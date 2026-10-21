import type { AdapterRequest, IncomingMeta, ProviderAdapter } from "./base";
import { createAnthropicAdapter } from "./anthropic";
import type { AdapterFactoryContext } from "./registry";
import type { AdapterEvent, OcxParsedRequest, OcxProviderConfig } from "../types";
import type { TranslatorBudget } from "../lib/translator-budget";
import type { AdapterTierMetadata } from "../providers/fastwire";
import { decodeEventStream, type EventStreamMessage } from "../lib/eventstream-decoder";
import {
  BEDROCK_ANTHROPIC_VERSION,
  bedrockModelUrl,
  bedrockRuntimeOrigin,
  bedrockWireModelId,
  canonicalClaudeModelId,
  resolveBedrockRegion,
} from "../providers/bedrock-destination";
import { AwsCredentialError, resolveAwsCredentials } from "../lib/aws-credentials";
import { signAwsRequest } from "../lib/aws-sigv4";

export {
  BEDROCK_ANTHROPIC_VERSION,
  bedrockInferenceProfilePrefix,
  bedrockModelUrl,
  bedrockRuntimeOrigin,
  bedrockWireModelId,
  canonicalClaudeModelId,
  resolveBedrockRegion,
} from "../providers/bedrock-destination";

/**
 * Amazon Bedrock, Anthropic Messages wire.
 *
 * Wraps the anthropic adapter: the Messages body, thinking/effort rules, tool lowering and the
 * SSE event parser are all reused. Bedrock differs in four places and this module owns exactly
 * those:
 *
 * - URL: `/model/{modelId}/invoke-with-response-stream` (or `/invoke`) on the regional runtime
 *   host, with canonical `claude-*` ids mapped onto the region's inference profile.
 * - Body: no `model`, no `stream`, `anthropic_version: "bedrock-2023-05-31"`, and betas moved
 *   from the `anthropic-beta` header into an `anthropic_beta` array. Anthropic-only fields
 *   (`speed`, `service_tier`, top-level automatic `cache_control`, the 1h cache `ttl`) are dropped.
 * - Auth: a Bedrock API key as `Authorization: Bearer` when one is configured; otherwise AWS
 *   SigV4 with credentials from the AWS profile (`awsProfile`, `AWS_PROFILE`, `default`): env
 *   keys, shared credentials, or an IAM Identity Center (SSO) session (`src/lib/aws-credentials.ts`).
 * - Stream: `application/vnd.amazon.eventstream` frames whose `chunk` payload carries the
 *   base64 Anthropic event. Frames are re-encoded as SSE and handed to the anthropic parser, so
 *   every Messages event rule (refusals, `error` stop reasons, truncation) applies unchanged.
 */

/** Headers the adapter owns; an operator header with one of these names is refused. */
export const BEDROCK_RESERVED_HEADERS = new Set([
  "authorization",
  "x-api-key",
  "anthropic-version",
  "host",
  "x-amz-security-token",
  "x-amz-date",
  "x-amz-content-sha256",
]);

/** Fields of the Messages body that Bedrock rejects or that only api.anthropic.com honors. */
const BEDROCK_DROPPED_BODY_FIELDS = ["model", "stream", "speed", "service_tier", "cache_control"] as const;

type BedrockExceptionMapping = { status: number; errorType: string };

/**
 * Smithy exception names Bedrock raises on the Messages route, mapped onto the HTTP status the
 * same failure carries when it happens before the stream opens. The status is what the combo
 * selector and key failover branch on, so a mid-stream throttle has to look like a 429.
 */
const BEDROCK_EXCEPTIONS: Record<string, BedrockExceptionMapping> = {
  throttlingexception: { status: 429, errorType: "rate_limit_error" },
  validationexception: { status: 400, errorType: "invalid_request_error" },
  accessdeniedexception: { status: 403, errorType: "permission_error" },
  resourcenotfoundexception: { status: 404, errorType: "not_found_error" },
  modelnotreadyexception: { status: 503, errorType: "overloaded_error" },
  serviceunavailableexception: { status: 503, errorType: "overloaded_error" },
  modelstreamerrorexception: { status: 502, errorType: "api_error" },
  modeltimeoutexception: { status: 504, errorType: "api_error" },
  internalserverexception: { status: 500, errorType: "api_error" },
};

function classifyBedrockException(name: string | undefined): BedrockExceptionMapping {
  const key = (name ?? "").split(":")[0]!.trim().toLowerCase();
  return BEDROCK_EXCEPTIONS[key] ?? { status: 502, errorType: "api_error" };
}

function bedrockExceptionMessage(payloadText: string): string | undefined {
  try {
    const parsed: unknown = JSON.parse(payloadText);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const record = parsed as Record<string, unknown>;
      const message = record.message ?? record.Message;
      if (typeof message === "string" && message.trim()) return message.trim();
    }
  } catch {
    /* not JSON — fall through */
  }
  const trimmed = payloadText.trim();
  return trimmed || undefined;
}

/** Collapse an AWS error-type header (`ThrottlingException:http://...`) to its bare name. */
function bedrockErrorTypeName(headers: Headers): string | undefined {
  const raw = headers.get("x-amzn-errortype") ?? headers.get("x-amzn-ErrorType");
  const name = raw?.split(":")[0]?.trim();
  return name && /^[A-Za-z]+$/.test(name) ? name : undefined;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function sseFrame(event: string | undefined, data: string): Uint8Array {
  return textEncoder.encode(event ? `event: ${event}\ndata: ${data}\n\n` : `data: ${data}\n\n`);
}

function sseErrorFrame(mapping: BedrockExceptionMapping, message: string): Uint8Array {
  return sseFrame("error", JSON.stringify({
    type: "error",
    error: { type: mapping.errorType, message, status: mapping.status },
  }));
}

/**
 * The Anthropic event carried by one `chunk` frame, or undefined when the frame is not a chunk
 * (Bedrock defines no other event type on this route; anything else is skipped, not fatal).
 */
function chunkEventJson(message: EventStreamMessage): string | undefined {
  if (message.headers[":event-type"] !== "chunk") return undefined;
  const envelope: unknown = JSON.parse(textDecoder.decode(message.payload));
  const bytes = envelope && typeof envelope === "object" && !Array.isArray(envelope)
    ? (envelope as { bytes?: unknown }).bytes
    : undefined;
  if (typeof bytes !== "string") throw new Error("bedrock chunk frame has no base64 `bytes` payload");
  return Buffer.from(bytes, "base64").toString("utf8");
}

/**
 * Re-encode a Bedrock eventstream body as Anthropic SSE. Pull-driven, so a slow consumer applies
 * backpressure to the upstream body instead of buffering the whole response. An exception frame
 * or a framing error becomes a terminal SSE `error` record; the anthropic parser turns that into
 * the one terminal `error` event the bridge expects.
 */
export function bedrockEventStreamToSse(body: ReadableStream<Uint8Array>): ReadableStream<Uint8Array> {
  const frames = decodeEventStream(body)[Symbol.asyncIterator]();
  let finished = false;
  const finish = (controller: ReadableStreamDefaultController<Uint8Array>, frame?: Uint8Array) => {
    finished = true;
    if (frame) controller.enqueue(frame);
    controller.close();
  };
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (finished) return;
      let next: IteratorResult<EventStreamMessage>;
      try {
        next = await frames.next();
      } catch (error) {
        finish(controller, sseErrorFrame(
          { status: 502, errorType: "upstream_error" },
          `bedrock event stream decode failed: ${error instanceof Error ? error.message : String(error)}`,
        ));
        return;
      }
      if (next.done) {
        finish(controller);
        return;
      }
      const message = next.value;
      const messageType = message.headers[":message-type"];
      if (messageType === "exception" || messageType === "error") {
        const mapping = classifyBedrockException(message.headers[":exception-type"] ?? message.headers[":error-code"]);
        const detail = bedrockExceptionMessage(textDecoder.decode(message.payload))
          ?? message.headers[":error-message"]
          ?? "Amazon Bedrock stream exception";
        const name = message.headers[":exception-type"] ?? message.headers[":error-code"];
        finish(controller, sseErrorFrame(mapping, name ? `${name}: ${detail}` : detail));
        await frames.return?.(undefined);
        return;
      }
      if (messageType !== "event") {
        finish(controller, sseErrorFrame(
          { status: 502, errorType: "upstream_error" },
          `bedrock response protocol error: unsupported Smithy message type ${JSON.stringify(messageType ?? "missing")}`,
        ));
        await frames.return?.(undefined);
        return;
      }
      let json: string | undefined;
      try {
        json = chunkEventJson(message);
      } catch (error) {
        finish(controller, sseErrorFrame(
          { status: 502, errorType: "upstream_error" },
          error instanceof Error ? error.message : String(error),
        ));
        await frames.return?.(undefined);
        return;
      }
      if (json !== undefined) controller.enqueue(sseFrame(undefined, json));
    },
    async cancel() {
      finished = true;
      await frames.return?.(undefined);
    },
  });
}

/** Bedrock accepts `cache_control: {type: "ephemeral"}` breakpoints but not the extended `ttl`. */
function stripCacheTtl(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) stripCacheTtl(item);
    return;
  }
  if (!value || typeof value !== "object") return;
  const record = value as Record<string, unknown>;
  const cc = record.cache_control;
  if (cc && typeof cc === "object" && !Array.isArray(cc)) delete (cc as Record<string, unknown>).ttl;
  for (const key of ["system", "messages", "content", "tools"]) {
    if (key in record) stripCacheTtl(record[key]);
  }
}

function isSseResponse(response: Response): boolean {
  return (response.headers.get("content-type") ?? "").toLowerCase().includes("text/event-stream");
}

/** Fold a comma-separated `anthropic-beta` header value into the body's `anthropic_beta` list. */
function collectBetas(...values: Array<string | undefined>): string[] {
  const out: string[] = [];
  for (const value of values) {
    for (const beta of (value ?? "").split(",")) {
      const trimmed = beta.trim();
      if (trimmed && !out.includes(trimmed)) out.push(trimmed);
    }
  }
  return out;
}

function headerValue(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) return value;
  }
  return undefined;
}

export function createBedrockAdapter(
  provider: OcxProviderConfig,
  context: AdapterFactoryContext = {},
): ProviderAdapter {
  // The Messages body builder reads `baseUrl` only to decide whether api.anthropic.com-only
  // features apply (server tools, automatic caching), so any non-Anthropic host is correct here.
  // Constructed lazily: region and URL errors belong to the request, not to adapter construction.
  let base: ProviderAdapter | undefined;
  const baseAdapter = (origin: string): ProviderAdapter => {
    base ??= createAnthropicAdapter({
      ...provider,
      authMode: "key",
      apiKeyTransport: "bearer",
      // The wrapped builder requires a key only to place a header this adapter discards; SigV4 and
      // bearer auth are both applied below on the rebuilt header set.
      apiKey: typeof provider.apiKey === "string" && provider.apiKey.trim() ? provider.apiKey : "bedrock-sigv4",
      baseUrl: origin,
      headers: undefined,
      // Bedrock has no fast lane and no service tier; keep the wrapped adapter from emitting them.
      fastWire: undefined,
      modelSupportsServiceTier: undefined,
      // Bedrock prompt caching is the 5-minute `ephemeral` breakpoint only; a 1h `ttl` is rejected.
    }, context.cacheRetention === "none" ? "none" : "short");
    return base;
  };
  // Parsing a stream never needs a destination; a fixed placeholder keeps the parser available.
  const parser = (): ProviderAdapter => baseAdapter("https://bedrock-runtime.invalid");

  return {
    name: "bedrock",

    formatErrorBody(status: number, headers: Headers, payloadText: string): string {
      const name = bedrockErrorTypeName(headers);
      const message = bedrockExceptionMessage(payloadText);
      if (name && message) return `${name}: ${message}`;
      if (name) return `${name} (HTTP ${status})`;
      return parser().formatErrorBody?.(status, headers, payloadText) ?? payloadText;
    },

    async buildRequest(parsed: OcxParsedRequest, incoming: IncomingMeta): Promise<AdapterRequest> {
      const key = typeof provider.apiKey === "string" ? provider.apiKey.trim() : "";
      if (provider.headers) {
        for (const name of Object.keys(provider.headers)) {
          if (BEDROCK_RESERVED_HEADERS.has(name.toLowerCase())) {
            throw new Error(`Reserved header "${name}" cannot be overridden in amazon-bedrock provider configuration`);
          }
        }
      }
      const region = resolveBedrockRegion(provider);
      const origin = bedrockRuntimeOrigin(provider.baseUrl, region);
      const wireModelId = bedrockWireModelId(parsed.modelId, region);
      const canonicalModelId = canonicalClaudeModelId(parsed.modelId);

      const inner = await baseAdapter(origin).buildRequest({ ...parsed, modelId: canonicalModelId }, incoming);

      const body = JSON.parse(inner.body) as Record<string, unknown>;
      for (const field of BEDROCK_DROPPED_BODY_FIELDS) delete body[field];
      stripCacheTtl(body);
      body.anthropic_version = BEDROCK_ANTHROPIC_VERSION;
      const betas = collectBetas(
        headerValue(inner.headers, "anthropic-beta"),
        provider.headers ? headerValue(provider.headers, "anthropic-beta") : undefined,
      );
      if (betas.length > 0) body.anthropic_beta = betas;

      let headers: Record<string, string> = {
        "Content-Type": "application/json",
        "Accept": parsed.stream ? "application/vnd.amazon.eventstream" : "application/json",
      };
      if (provider.headers) {
        for (const [name, value] of Object.entries(provider.headers)) {
          if (name.toLowerCase() === "anthropic-beta" || typeof value !== "string") continue;
          headers[name] = value;
        }
      }
      const url = bedrockModelUrl(origin, wireModelId, parsed.stream);
      const serialized = JSON.stringify(body);
      if (key) {
        headers["Authorization"] = `Bearer ${key}`;
      } else {
        // No API key: sign with AWS credentials. The signature covers the final bytes, so this is
        // the last step; a retry re-sends the same signed request inside SigV4's 15-minute window.
        let credentials;
        try {
          credentials = await resolveAwsCredentials({ profile: provider.awsProfile, signal: incoming?.abortSignal });
        } catch (error) {
          if (error instanceof AwsCredentialError) {
            throw new Error(`amazon-bedrock has no API key and AWS credentials could not be resolved: ${error.message}`);
          }
          throw error;
        }
        headers = signAwsRequest({
          method: "POST",
          url,
          headers,
          body: serialized,
          region,
          service: "bedrock",
          credentials,
        }).headers;
      }

      return {
        ...inner,
        url,
        headers,
        body: serialized,
        outboundModelId: wireModelId,
      };
    },

    async *parseStream(
      response: Response,
      budget: TranslatorBudget,
      tierMetadata?: AdapterTierMetadata,
    ): AsyncGenerator<AdapterEvent> {
      if (!response.body) {
        yield { type: "error", message: "No response body" };
        return;
      }
      // A gateway in front of Bedrock may already speak SSE; only the native eventstream is re-encoded.
      const upstream = isSseResponse(response)
        ? response
        : new Response(bedrockEventStreamToSse(response.body), {
          status: response.status,
          headers: { "content-type": "text/event-stream" },
        });
      yield* parser().parseStream(upstream, budget, tierMetadata);
    },

    parseResponse(
      response: Response,
      budget: TranslatorBudget,
      tierMetadata?: AdapterTierMetadata,
    ): Promise<AdapterEvent[]> {
      // `/invoke` answers with the plain Messages JSON document.
      return parser().parseResponse!(response, budget, tierMetadata);
    },
  };
}
