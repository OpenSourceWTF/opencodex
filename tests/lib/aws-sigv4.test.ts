import { describe, expect, test } from "bun:test";
import { amzDate, canonicalQuery, canonicalUri, rfc3986Encode, sha256Hex, signAwsRequest } from "../../src/lib/aws-sigv4";

// AWS Signature Version 4 test suite credentials and instant (aws-sig-v4-test-suite).
const SUITE_CREDENTIALS = { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" };
const SUITE_INSTANT = new Date("2015-08-30T12:36:00Z");

describe("aws sigv4 primitives", () => {
  test("x-amz-date formatting and the empty-payload hash", () => {
    expect(amzDate(SUITE_INSTANT)).toBe("20150830T123600Z");
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  test("RFC 3986 encoding covers the characters encodeURIComponent leaves bare", () => {
    expect(rfc3986Encode("a b*c'(d)!")).toBe("a%20b%2Ac%27%28d%29%21");
    expect(rfc3986Encode("us.anthropic.claude-opus-5-5")).toBe("us.anthropic.claude-opus-5-5");
  });

  test("the canonical URI double-encodes an already encoded path, keeping segment separators", () => {
    expect(canonicalUri("/")).toBe("/");
    expect(canonicalUri("")).toBe("/");
    expect(canonicalUri("/model/us.anthropic.claude-opus-5-5/invoke")).toBe("/model/us.anthropic.claude-opus-5-5/invoke");
    const arn = encodeURIComponent("arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-opus-5-5");
    expect(canonicalUri(`/model/${arn}/invoke`)).toBe(`/model/${arn.replace(/%/g, "%25")}/invoke`);
  });

  test("the canonical query sorts by name then value", () => {
    expect(canonicalQuery(new URLSearchParams("b=2&a=2&a=1&c=%20"))).toBe("a=1&a=2&b=2&c=%20");
    expect(canonicalQuery(new URLSearchParams(""))).toBe("");
  });
});

describe("aws sigv4 signing", () => {
  test("reproduces the AWS test-suite get-vanilla signature", () => {
    const signed = signAwsRequest({
      method: "GET",
      url: "https://example.amazonaws.com/",
      headers: {},
      body: "",
      region: "us-east-1",
      service: "service",
      credentials: SUITE_CREDENTIALS,
      now: SUITE_INSTANT,
      contentSha256Header: false,
    });
    expect(signed.canonicalRequest).toBe([
      "GET",
      "/",
      "",
      "host:example.amazonaws.com",
      "x-amz-date:20150830T123600Z",
      "",
      "host;x-amz-date",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ].join("\n"));
    expect(signed.stringToSign).toBe([
      "AWS4-HMAC-SHA256",
      "20150830T123600Z",
      "20150830/us-east-1/service/aws4_request",
      "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
    ].join("\n"));
    expect(signed.signature).toBe("5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    expect(signed.headers.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    );
  });

  test("a Bedrock POST signs content-type, the payload hash and the session token; other headers stay unsigned", () => {
    const body = JSON.stringify({ anthropic_version: "bedrock-2023-05-31", max_tokens: 1, messages: [] });
    const signed = signAwsRequest({
      method: "POST",
      url: "https://bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-opus-5-5/invoke-with-response-stream",
      headers: { "Content-Type": "application/json", Accept: "application/vnd.amazon.eventstream", "X-Trace": "abc" },
      body,
      region: "us-east-1",
      service: "bedrock",
      credentials: { ...SUITE_CREDENTIALS, sessionToken: "session-token-value" },
      now: SUITE_INSTANT,
    });
    expect(signed.headers.host).toBe("bedrock-runtime.us-east-1.amazonaws.com");
    expect(signed.headers["x-amz-date"]).toBe("20150830T123600Z");
    expect(signed.headers["x-amz-content-sha256"]).toBe(sha256Hex(body));
    expect(signed.headers["x-amz-security-token"]).toBe("session-token-value");
    expect(signed.headers["Content-Type"]).toBe("application/json");
    expect(signed.headers.Accept).toBe("application/vnd.amazon.eventstream");
    expect(signed.headers.authorization).toContain("Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request");
    expect(signed.headers.authorization).toContain("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token,");
    expect(signed.canonicalRequest).not.toContain("x-trace");
    expect(signed.canonicalRequest.split("\n")[0]).toBe("POST");
    // Any change to the body changes the signature: the signature binds the final bytes.
    const tampered = signAwsRequest({
      method: "POST",
      url: "https://bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-opus-5-5/invoke-with-response-stream",
      headers: { "Content-Type": "application/json" },
      body: body + " ",
      region: "us-east-1",
      service: "bedrock",
      credentials: { ...SUITE_CREDENTIALS, sessionToken: "session-token-value" },
      now: SUITE_INSTANT,
    });
    expect(tampered.signature).not.toBe(signed.signature);
  });

  test("a caller-supplied authorization or host header is replaced, never signed twice", () => {
    const signed = signAwsRequest({
      method: "GET",
      url: "https://example.amazonaws.com/",
      headers: { Authorization: "Bearer stale", Host: "evil.example" },
      body: "",
      region: "us-east-1",
      service: "service",
      credentials: SUITE_CREDENTIALS,
      now: SUITE_INSTANT,
      contentSha256Header: false,
    });
    expect(Object.keys(signed.headers).filter(name => name.toLowerCase() === "authorization")).toEqual(["authorization"]);
    expect(Object.keys(signed.headers).filter(name => name.toLowerCase() === "host")).toEqual(["host"]);
    expect(signed.headers.host).toBe("example.amazonaws.com");
    expect(signed.signature).toBe("5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
  });
});
