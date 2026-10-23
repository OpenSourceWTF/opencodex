import { createHash, createHmac } from "node:crypto";

/**
 * AWS Signature Version 4 request signing, with no `@aws-sdk/*` dependency.
 *
 * Only what a Bedrock Messages call needs: a single-chunk body, headers in the signature, no
 * query signing beyond canonicalization, no S3 path rules. The canonical path is double-encoded
 * (every non-S3 service encodes the already-encoded path once more), which is what makes an
 * inference-profile ARN in the Bedrock route sign correctly.
 */

export interface AwsSigningCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface AwsSignRequestInput {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | Uint8Array;
  region: string;
  service: string;
  credentials: AwsSigningCredentials;
  /** Signing instant; defaults to now. Tests pin it for known-answer vectors. */
  now?: Date;
  /** Send `x-amz-content-sha256` beside the signature (default true). */
  contentSha256Header?: boolean;
}

export interface AwsSignedRequest {
  headers: Record<string, string>;
  /** The canonical request string, for diagnostics and tests. */
  canonicalRequest: string;
  stringToSign: string;
  signature: string;
}

const AWS4_ALGORITHM = "AWS4-HMAC-SHA256";

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}

/** `YYYYMMDDTHHMMSSZ`, the x-amz-date form. */
export function amzDate(date: Date): string {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, "");
}

/** RFC 3986 percent-encoding: `encodeURIComponent` plus the characters it leaves bare. */
export function rfc3986Encode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/**
 * The canonical URI: the already-encoded path, encoded once more per segment. `/` stays a
 * separator, an empty path is `/`.
 */
export function canonicalUri(pathname: string): string {
  if (!pathname || pathname === "/") return "/";
  return pathname.split("/").map(segment => rfc3986Encode(segment)).join("/");
}

/** Query parameters sorted by name then value, each RFC 3986 encoded. */
export function canonicalQuery(search: URLSearchParams): string {
  const pairs: Array<[string, string]> = [];
  for (const [name, value] of search) pairs.push([rfc3986Encode(name), rfc3986Encode(value)]);
  pairs.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1));
  return pairs.map(([name, value]) => `${name}=${value}`).join("&");
}

function canonicalHeaderValue(value: string): string {
  return value.trim().replace(/\s+/g, " ");
}

/** Headers that take part in the signature: host, content-type and every `x-amz-*` header. */
function isSignedHeader(name: string): boolean {
  return name === "host" || name === "content-type" || name.startsWith("x-amz-");
}

export function signingKey(secretAccessKey: string, date: string, region: string, service: string): Buffer {
  const kDate = hmac(`AWS4${secretAccessKey}`, date);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

/**
 * Sign a request. Returns the input headers plus `host`, `x-amz-date`, `x-amz-content-sha256`
 * (unless disabled), `x-amz-security-token` for session credentials, and `authorization`.
 * Header names in the result keep the caller's casing; signing is case-insensitive as required.
 */
export function signAwsRequest(input: AwsSignRequestInput): AwsSignedRequest {
  const url = new URL(input.url);
  const now = input.now ?? new Date();
  const dateTime = amzDate(now);
  const date = dateTime.slice(0, 8);
  const payloadHash = sha256Hex(input.body);

  const headers: Record<string, string> = { ...input.headers };
  const setHeader = (name: string, value: string) => {
    for (const existing of Object.keys(headers)) {
      if (existing.toLowerCase() === name) delete headers[existing];
    }
    headers[name] = value;
  };
  setHeader("host", url.host);
  setHeader("x-amz-date", dateTime);
  if (input.contentSha256Header !== false) setHeader("x-amz-content-sha256", payloadHash);
  if (input.credentials.sessionToken) setHeader("x-amz-security-token", input.credentials.sessionToken);
  for (const existing of Object.keys(headers)) {
    if (existing.toLowerCase() === "authorization") delete headers[existing];
  }

  const signed = Object.entries(headers)
    .map(([name, value]) => [name.toLowerCase(), canonicalHeaderValue(value)] as const)
    .filter(([name]) => isSignedHeader(name))
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const signedHeaderNames = signed.map(([name]) => name).join(";");
  const canonicalHeaders = signed.map(([name, value]) => `${name}:${value}\n`).join("");

  const canonicalRequest = [
    input.method.toUpperCase(),
    canonicalUri(url.pathname),
    canonicalQuery(url.searchParams),
    canonicalHeaders,
    signedHeaderNames,
    payloadHash,
  ].join("\n");

  const scope = `${date}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = [AWS4_ALGORITHM, dateTime, scope, sha256Hex(canonicalRequest)].join("\n");
  const signature = hmac(signingKey(input.credentials.secretAccessKey, date, input.region, input.service), stringToSign).toString("hex");

  headers["authorization"] = `${AWS4_ALGORITHM} Credential=${input.credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaderNames}, Signature=${signature}`;
  return { headers, canonicalRequest, stringToSign, signature };
}
