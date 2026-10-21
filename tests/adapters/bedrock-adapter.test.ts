import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createBedrockAdapter as createBedrockAdapterProduction } from "../../src/adapters/bedrock";
import {
  BEDROCK_ANTHROPIC_VERSION,
  bedrockEventStreamToSse,
  bedrockInferenceProfilePrefix,
  bedrockRuntimeOrigin,
  bedrockWireModelId,
  canonicalClaudeModelId,
  resolveBedrockRegion,
} from "../../src/adapters/bedrock";
import { encodeMessage } from "../../src/lib/eventstream-decoder";
import { __resetAwsCredentialCache } from "../../src/lib/aws-credentials";
import { sha256Hex } from "../../src/lib/aws-sigv4";
import { parseRequest } from "../../src/responses/parser";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { removeTreeWithRetry } from "../helpers/remove-tree";
import type { AdapterEvent, OcxProviderConfig } from "../../src/types";
import { withTestTranslatorBudget } from "../helpers/translator-budget";

const createBedrockAdapter = (...args: Parameters<typeof createBedrockAdapterProduction>) =>
  withTestTranslatorBudget(createBedrockAdapterProduction(...args));

function provider(overrides: Partial<OcxProviderConfig> = {}): OcxProviderConfig {
  return {
    adapter: "bedrock",
    baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
    authMode: "key",
    apiKey: "bedrock-test-key",
    region: "us-west-2",
    ...overrides,
  };
}

function request(model: string, stream = true) {
  return parseRequest({ model, stream, input: [{ role: "user", content: "Hello from test" }] });
}

const AWS_ENV = ["AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"] as const;
const origAwsEnv = Object.fromEntries(AWS_ENV.map(name => [name, process.env[name]])) as Record<typeof AWS_ENV[number], string | undefined>;

beforeEach(() => {
  for (const name of AWS_ENV) delete process.env[name];
});

afterEach(() => {
  for (const name of AWS_ENV) {
    if (origAwsEnv[name] === undefined) delete process.env[name]; else process.env[name] = origAwsEnv[name];
  }
});

describe("bedrock destination arithmetic", () => {
  test("region precedence: field, then concrete host, then env, then default", () => {
    expect(resolveBedrockRegion({ region: "eu-central-1", baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com" })).toBe("eu-central-1");
    expect(resolveBedrockRegion({ baseUrl: "https://bedrock-runtime.ap-southeast-2.amazonaws.com" })).toBe("ap-southeast-2");
    expect(resolveBedrockRegion({ baseUrl: "https://gateway.example/bedrock" }, { AWS_REGION: "eu-west-1" })).toBe("eu-west-1");
    expect(resolveBedrockRegion({ baseUrl: "https://gateway.example/bedrock" }, { AWS_DEFAULT_REGION: "us-east-2" })).toBe("us-east-2");
    expect(resolveBedrockRegion({ baseUrl: "https://gateway.example/bedrock" }, {})).toBe("us-east-1");
  });

  test("a configured region that is not an AWS label fails closed", () => {
    expect(() => resolveBedrockRegion({ region: "us-east-1.evil.example", baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com" }))
      .toThrow("region must be a single lowercase AWS region label");
    expect(() => resolveBedrockRegion({ region: "US-EAST-1", baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com" }))
      .toThrow("region must be a single lowercase AWS region label");
  });

  test("runtime origin follows the region on canonical hosts, keeps custom hosts, refuses leftovers", () => {
    expect(bedrockRuntimeOrigin("https://bedrock-runtime.us-east-1.amazonaws.com", "us-west-2"))
      .toBe("https://bedrock-runtime.us-west-2.amazonaws.com");
    expect(bedrockRuntimeOrigin("https://bedrock-runtime-fips.us-east-1.amazonaws.com/", "us-gov-west-1"))
      .toBe("https://bedrock-runtime-fips.us-gov-west-1.amazonaws.com");
    expect(bedrockRuntimeOrigin("https://bedrock-runtime.{region}.amazonaws.com", "us-west-2"))
      .toBe("https://bedrock-runtime.us-west-2.amazonaws.com");
    expect(bedrockRuntimeOrigin("https://gateway.example/bedrock/", "us-west-2")).toBe("https://gateway.example/bedrock");
    expect(() => bedrockRuntimeOrigin("https://{account}.example/{region}", "us-west-2")).toThrow("unresolved {account}");
    expect(() => bedrockRuntimeOrigin("not a url", "us-west-2")).toThrow("malformed baseUrl");
  });

  test("inference profile prefix follows the source geography", () => {
    expect(bedrockInferenceProfilePrefix("us-east-1")).toBe("us.");
    expect(bedrockInferenceProfilePrefix("us-gov-west-1")).toBe("us-gov.");
    expect(bedrockInferenceProfilePrefix("eu-central-1")).toBe("eu.");
    expect(bedrockInferenceProfilePrefix("ap-northeast-1")).toBe("jp.");
    expect(bedrockInferenceProfilePrefix("ap-southeast-2")).toBe("au.");
    expect(bedrockInferenceProfilePrefix("ap-south-1")).toBe("apac.");
    expect(bedrockInferenceProfilePrefix("sa-east-1")).toBe("");
  });

  test("canonical ids map onto the profile with Bedrock's own suffixes; Bedrock ids and ARNs pass through", () => {
    expect(bedrockWireModelId("claude-opus-5-5", "us-east-1")).toBe("us.anthropic.claude-opus-5-5");
    expect(bedrockWireModelId("claude-fable-5-1", "us-east-1")).toBe("us.anthropic.claude-fable-5-1");
    // Older generations are served under dated/versioned ids; the metadata bundle supplies them.
    expect(bedrockWireModelId("claude-haiku-4-5", "us-east-1")).toBe("us.anthropic.claude-haiku-4-5-20251001-v1:0");
    expect(bedrockWireModelId("claude-opus-4-6", "eu-central-1")).toBe("eu.anthropic.claude-opus-4-6-v1");
    expect(bedrockWireModelId("claude-sonnet-4-5", "us-east-1")).toBe("us.anthropic.claude-sonnet-4-5-20250929-v1:0");
    expect(bedrockWireModelId("claude-haiku-4-5", "sa-east-1")).toBe("anthropic.claude-haiku-4-5-20251001-v1:0");
    // An id the bundle does not know is passed through under the vendor segment unchanged.
    expect(bedrockWireModelId("claude-future-9", "us-east-1")).toBe("us.anthropic.claude-future-9");
    expect(bedrockWireModelId("global.anthropic.claude-sonnet-5-5", "us-east-1")).toBe("global.anthropic.claude-sonnet-5-5");
    expect(bedrockWireModelId("anthropic.claude-haiku-4-5-20251001-v1:0", "eu-west-1")).toBe("anthropic.claude-haiku-4-5-20251001-v1:0");
    const arn = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-opus-5-5";
    expect(bedrockWireModelId(arn, "us-east-1")).toBe(arn);
  });

  test("the canonical Claude id is recovered from every Bedrock identifier shape", () => {
    expect(canonicalClaudeModelId("us.anthropic.claude-opus-5-5")).toBe("claude-opus-5-5");
    expect(canonicalClaudeModelId("anthropic.claude-haiku-4-5-20251001-v1:0")).toBe("claude-haiku-4-5-20251001-v1:0");
    expect(canonicalClaudeModelId("arn:aws:bedrock:us-east-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-5-5"))
      .toBe("claude-sonnet-5-5");
    expect(canonicalClaudeModelId("claude-fable-5-1")).toBe("claude-fable-5-1");
    expect(canonicalClaudeModelId("us.amazon.nova-pro-v1:0")).toBe("us.amazon.nova-pro-v1:0");
  });
});

describe("bedrock adapter buildRequest", () => {
  test("targets the regional invoke-with-response-stream route with a bearer key and the Bedrock body deltas", async () => {
    const req = await createBedrockAdapter(provider()).buildRequest(request("claude-opus-5-5"));

    expect(req.url).toBe("https://bedrock-runtime.us-west-2.amazonaws.com/model/us.anthropic.claude-opus-5-5/invoke-with-response-stream");
    expect(req.method).toBe("POST");
    expect(req.outboundModelId).toBe("us.anthropic.claude-opus-5-5");
    expect(req.headers["Authorization"]).toBe("Bearer bedrock-test-key");
    expect(req.headers["Accept"]).toBe("application/vnd.amazon.eventstream");
    expect(req.headers["Content-Type"]).toBe("application/json");
    expect(req.headers["x-api-key"]).toBeUndefined();
    expect(req.headers["anthropic-version"]).toBeUndefined();
    expect(req.headers["anthropic-beta"]).toBeUndefined();

    const body = JSON.parse(req.body) as Record<string, unknown>;
    expect(body.anthropic_version).toBe(BEDROCK_ANTHROPIC_VERSION);
    expect(body.model).toBeUndefined();
    expect(body.stream).toBeUndefined();
    expect(body.speed).toBeUndefined();
    expect(body.cache_control).toBeUndefined();
    expect(body.max_tokens).toBeGreaterThan(0);
    // The explicit prompt-cache breakpoint survives; Bedrock accepts it. The 1h ttl never appears.
    expect(body.messages).toEqual([{ role: "user", content: [{ type: "text", text: "Hello from test", cache_control: { type: "ephemeral" } }] }]);
  });

  test("long cache retention is clamped to the 5-minute breakpoint Bedrock accepts", async () => {
    const req = await withTestTranslatorBudget(createBedrockAdapterProduction(provider(), { cacheRetention: "long" }))
      .buildRequest(request("claude-opus-5-5"));
    expect(req.body).not.toContain("\"ttl\"");
    expect(req.body).toContain("\"cache_control\":{\"type\":\"ephemeral\"}");
  });

  test("the wrapped Anthropic contract reads the canonical family even behind a Bedrock id", async () => {
    // Opus 5.5 is an adaptive-thinking family: `thinking.type: "enabled"` would 400 on Bedrock
    // exactly as it does on api.anthropic.com, so the family rule has to survive the id prefix.
    for (const model of ["claude-opus-5-5", "us.anthropic.claude-opus-5-5"]) {
      const req = await createBedrockAdapter(provider()).buildRequest(parseRequest({
        model, stream: true, reasoning: { effort: "high" }, input: [{ role: "user", content: "think" }],
      }));
      const body = JSON.parse(req.body) as { thinking?: { type?: string }; output_config?: { effort?: string } };
      expect(body.thinking?.type, model).toBe("adaptive");
      expect(body.output_config?.effort, model).toBe("high");
      expect(req.url).toContain("/model/us.anthropic.claude-opus-5-5/");
    }
  });

  test("a non-streaming request uses /invoke and asks for JSON", async () => {
    const req = await createBedrockAdapter(provider()).buildRequest(request("claude-haiku-4-5", false));
    expect(req.url).toBe("https://bedrock-runtime.us-west-2.amazonaws.com/model/us.anthropic.claude-haiku-4-5-20251001-v1%3A0/invoke");
    expect(req.outboundModelId).toBe("us.anthropic.claude-haiku-4-5-20251001-v1:0");
    expect(req.headers["Accept"]).toBe("application/json");
  });

  test("a full Bedrock id or ARN is sent verbatim, path-encoded", async () => {
    const arn = "arn:aws:bedrock:us-west-2:123456789012:inference-profile/global.anthropic.claude-sonnet-5-5";
    const req = await createBedrockAdapter(provider()).buildRequest(request(arn));
    expect(req.url).toBe(`https://bedrock-runtime.us-west-2.amazonaws.com/model/${encodeURIComponent(arn)}/invoke-with-response-stream`);
    expect(req.outboundModelId).toBe(arn);
  });

  test("the region embedded in a concrete baseUrl is honored when `region` is absent", async () => {
    const req = await createBedrockAdapter(provider({
      region: undefined,
      baseUrl: "https://bedrock-runtime.eu-central-1.amazonaws.com",
    })).buildRequest(request("claude-sonnet-5-5"));
    expect(req.url).toBe("https://bedrock-runtime.eu-central-1.amazonaws.com/model/eu.anthropic.claude-sonnet-5-5/invoke-with-response-stream");
  });

  test("operator anthropic-beta headers become the body's anthropic_beta list; other headers pass", async () => {
    const req = await createBedrockAdapter(provider({
      headers: { "anthropic-beta": "context-1m-2025-08-07, interleaved-thinking-2025-05-14", "x-trace": "abc" },
    })).buildRequest(request("claude-sonnet-5-5"));
    const body = JSON.parse(req.body) as { anthropic_beta?: string[] };
    expect(body.anthropic_beta).toEqual(["context-1m-2025-08-07", "interleaved-thinking-2025-05-14"]);
    expect(req.headers["x-trace"]).toBe("abc");
    expect(req.headers["anthropic-beta"]).toBeUndefined();
  });

  test("reserved headers cannot be overridden and a bad region fails closed", async () => {
    await expect(createBedrockAdapter(provider({ headers: { Authorization: "Bearer other" } })).buildRequest(request("claude-sonnet-5-5")))
      .rejects.toThrow('Reserved header "Authorization"');
    await expect(createBedrockAdapter(provider({ region: "bogus" })).buildRequest(request("claude-sonnet-5-5")))
      .rejects.toThrow("region must be a single lowercase AWS region label");
  });

  test("without an API key the request is SigV4-signed with AWS credentials and carries no bearer", async () => {
    __resetAwsCredentialCache();
    process.env.AWS_ACCESS_KEY_ID = "AKIATEST";
    process.env.AWS_SECRET_ACCESS_KEY = "test-secret";
    process.env.AWS_SESSION_TOKEN = "test-session";
    try {
      const req = await createBedrockAdapter(provider({ apiKey: undefined, region: "eu-west-1" })).buildRequest(request("claude-sonnet-5-5"));
      expect(req.url).toBe("https://bedrock-runtime.eu-west-1.amazonaws.com/model/eu.anthropic.claude-sonnet-5-5/invoke-with-response-stream");
      expect(req.headers.authorization).toStartWith("AWS4-HMAC-SHA256 Credential=AKIATEST/");
      expect(req.headers.authorization).toContain("/eu-west-1/bedrock/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=");
      expect(req.headers["x-amz-security-token"]).toBe("test-session");
      expect(req.headers.host).toBe("bedrock-runtime.eu-west-1.amazonaws.com");
      expect(req.headers["x-amz-content-sha256"]).toBe(sha256Hex(req.body));
      expect(req.headers["Accept"]).toBe("application/vnd.amazon.eventstream");
      expect(Object.keys(req.headers).filter(h => h.toLowerCase() === "authorization")).toHaveLength(1);
      const body = JSON.parse(req.body) as Record<string, unknown>;
      expect(body.anthropic_version).toBe(BEDROCK_ANTHROPIC_VERSION);
    } finally {
      delete process.env.AWS_ACCESS_KEY_ID;
      delete process.env.AWS_SECRET_ACCESS_KEY;
      delete process.env.AWS_SESSION_TOKEN;
      __resetAwsCredentialCache();
    }
  });

  test("without an API key or any AWS credentials the error names the profile and the login path", async () => {
    __resetAwsCredentialCache();
    const home = mkdtempSync(join(tmpdir(), "bedrock-nohome-"));
    const origHome = process.env.HOME;
    process.env.HOME = home;
    delete process.env.AWS_PROFILE;
    try {
      await expect(createBedrockAdapter(provider({ apiKey: undefined, awsProfile: "missing" })).buildRequest(request("claude-sonnet-5-5")))
        .rejects.toThrow(/no API key and AWS credentials could not be resolved: AWS profile "missing" was not found/);
    } finally {
      if (origHome === undefined) delete process.env.HOME; else process.env.HOME = origHome;
      __resetAwsCredentialCache();
      await removeTreeWithRetry(home);
    }
  });
});

const enc = new TextEncoder();

function chunkFrame(event: Record<string, unknown>): Uint8Array {
  const bytes = Buffer.from(JSON.stringify(event), "utf8").toString("base64");
  return encodeMessage(
    { ":message-type": "event", ":event-type": "chunk", ":content-type": "application/json" },
    enc.encode(JSON.stringify({ bytes })),
  );
}

function exceptionFrame(type: string, message: string): Uint8Array {
  return encodeMessage(
    { ":message-type": "exception", ":exception-type": type, ":content-type": "application/json" },
    enc.encode(JSON.stringify({ message })),
  );
}

const happyFrames = [
  chunkFrame({ type: "message_start", message: { id: "msg_1", type: "message", role: "assistant", model: "claude-opus-5-5", content: [], usage: { input_tokens: 12, output_tokens: 1 } } }),
  chunkFrame({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }),
  chunkFrame({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "Hel" } }),
  chunkFrame({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "lo" } }),
  chunkFrame({ type: "content_block_stop", index: 0 }),
  chunkFrame({ type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 7 } }),
  chunkFrame({
    type: "message_stop",
    "amazon-bedrock-invocationMetrics": { inputTokenCount: 12, outputTokenCount: 7, invocationLatency: 500, firstByteLatency: 100 },
  }),
];

function eventStreamResponse(frames: Uint8Array[], cutEvery?: number): Response {
  const bytes = Buffer.concat(frames.map(f => Buffer.from(f)));
  return new Response(new ReadableStream<Uint8Array>({
    start(controller) {
      if (!cutEvery) {
        controller.enqueue(new Uint8Array(bytes));
      } else {
        for (let offset = 0; offset < bytes.length; offset += cutEvery) {
          controller.enqueue(new Uint8Array(bytes.subarray(offset, Math.min(offset + cutEvery, bytes.length))));
        }
      }
      controller.close();
    },
  }), { status: 200, headers: { "content-type": "application/vnd.amazon.eventstream" } });
}

async function collect(response: Response): Promise<AdapterEvent[]> {
  const events: AdapterEvent[] = [];
  for await (const event of createBedrockAdapter(provider()).parseStream(response)) events.push(event);
  return events;
}

describe("bedrock adapter parseStream", () => {
  test("decodes chunk frames into the Anthropic event sequence, across arbitrary chunk boundaries", async () => {
    for (const cut of [undefined, 1, 7, 64]) {
      const events = await collect(eventStreamResponse(happyFrames, cut));
      const text = events.filter(e => e.type === "text_delta").map(e => (e as { text: string }).text).join("");
      expect(text, `cut=${cut}`).toBe("Hello");
      const done = events.at(-1);
      expect(done?.type, `cut=${cut}`).toBe("done");
      expect((done as { stopReason?: string }).stopReason).toBe("end_turn");
      expect((done as { usage?: { inputTokens?: number; outputTokens?: number } }).usage).toMatchObject({ inputTokens: 12, outputTokens: 7 });
    }
  });

  test("a throttling exception frame becomes a 429 error event so failover can hop", async () => {
    const events = await collect(eventStreamResponse([
      happyFrames[0]!,
      exceptionFrame("throttlingException", "Too many requests, please wait before trying again."),
    ]));
    const error = events.find(e => e.type === "error") as { status?: number; errorType?: string; message: string } | undefined;
    expect(error).toBeDefined();
    expect(error?.status).toBe(429);
    expect(error?.errorType).toBe("rate_limit_error");
    expect(error?.message).toContain("throttlingException: Too many requests");
    expect(events.filter(e => e.type === "done")).toHaveLength(0);
  });

  test("a validation exception becomes a 400 and a stream cut before message_stop is a truncation error", async () => {
    const validation = await collect(eventStreamResponse([exceptionFrame("validationException", "max_tokens: too large")]));
    expect((validation.find(e => e.type === "error") as { status?: number } | undefined)?.status).toBe(400);

    const truncated = await collect(eventStreamResponse(happyFrames.slice(0, 4)));
    const error = truncated.find(e => e.type === "error") as { message: string } | undefined;
    expect(error?.message).toContain("ended before message_stop");
  });

  test("a corrupt frame surfaces one terminal error instead of throwing out of the generator", async () => {
    const corrupt = Buffer.from(happyFrames[1]!);
    corrupt[corrupt.length - 1] ^= 0xff; // break the message CRC
    const events = await collect(eventStreamResponse([happyFrames[0]!, new Uint8Array(corrupt)]));
    const error = events.find(e => e.type === "error") as { status?: number; message: string } | undefined;
    expect(error?.status).toBe(502);
    expect(error?.message).toContain("decode failed");
  });

  test("re-encoded SSE carries one data record per chunk", async () => {
    const sse = await new Response(bedrockEventStreamToSse(eventStreamResponse(happyFrames).body!)).text();
    const records = sse.split("\n\n").filter(Boolean);
    expect(records).toHaveLength(happyFrames.length);
    expect(records[0]).toStartWith('data: {"type":"message_start"');
  });

  test("an upstream that already speaks SSE is parsed as-is", async () => {
    const sse = [
      'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":1,"output_tokens":0}}}',
      'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
      'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"gateway"}}',
      'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}',
      'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}',
      'event: message_stop\ndata: {"type":"message_stop"}',
    ].join("\n\n") + "\n\n";
    const events = await collect(new Response(sse, { headers: { "content-type": "text/event-stream" } }));
    expect(events.some(e => e.type === "text_delta" && e.text === "gateway")).toBe(true);
    expect(events.at(-1)?.type).toBe("done");
  });
});

describe("bedrock adapter buffered and error surfaces", () => {
  test("parseResponse reads the plain Messages JSON document from /invoke", async () => {
    const adapter = createBedrockAdapter(provider());
    const events = await adapter.parseResponse!(new Response(JSON.stringify({
      id: "msg_2", type: "message", role: "assistant", model: "claude-haiku-4-5",
      content: [{ type: "text", text: "buffered" }],
      stop_reason: "end_turn", usage: { input_tokens: 3, output_tokens: 2 },
    }), { headers: { "content-type": "application/json" } }));
    expect(events).toEqual([
      { type: "text_delta", text: "buffered" },
      { type: "done", usage: expect.objectContaining({ inputTokens: 3, outputTokens: 2 }), stopReason: "end_turn" },
    ]);
  });

  test("formatErrorBody names the AWS error type and message", () => {
    const adapter = createBedrockAdapterProduction(provider());
    const headers = new Headers({ "x-amzn-errortype": "ThrottlingException:http://internal.amazon.com/coral/com.amazon.bedrock/" });
    expect(adapter.formatErrorBody!(429, headers, JSON.stringify({ message: "Too many tokens per minute." })))
      .toBe("ThrottlingException: Too many tokens per minute.");
    expect(adapter.formatErrorBody!(403, new Headers({ "x-amzn-errortype": "AccessDeniedException" }), "")).toBe("AccessDeniedException (HTTP 403)");
    // Without an AWS header the Anthropic envelope formatter still applies.
    expect(adapter.formatErrorBody!(400, new Headers(), JSON.stringify({ type: "error", error: { type: "invalid_request_error", message: "bad" } })))
      .toContain("bad");
  });
});
