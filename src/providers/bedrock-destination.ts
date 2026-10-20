import type { OcxProviderConfig } from "../types";

/**
 * Amazon Bedrock destination resolution for the `bedrock` adapter.
 *
 * Bedrock serves the Anthropic Messages wire through
 * `POST https://bedrock-runtime.{region}.amazonaws.com/model/{modelId}/invoke-with-response-stream`
 * (or `/invoke` when the caller did not ask for a stream). The body is the ordinary Messages body
 * minus `model`, plus `anthropic_version`; betas travel in an `anthropic_beta` array instead of
 * a header. This module owns the region, host and model-id arithmetic so the adapter and config
 * validation read the same rules.
 */

/** The only `anthropic_version` Bedrock accepts for the Messages wire. */
export const BEDROCK_ANTHROPIC_VERSION = "bedrock-2023-05-31";
export const BEDROCK_DEFAULT_REGION = "us-east-1";
/**
 * Registry seed. A canonical runtime host follows `provider.region` at request time (the region
 * label inside the host is replaced), so this default never pins a user to us-east-1. A custom
 * `baseUrl` on another host (a gateway or VPC endpoint) is used verbatim.
 */
export const BEDROCK_DEFAULT_RUNTIME_BASE_URL = `https://bedrock-runtime.${BEDROCK_DEFAULT_REGION}.amazonaws.com`;

/** `us-east-1`, `us-gov-west-1`, `ap-southeast-2`, `eu-central-1`, ... one lowercase AWS region label. */
const AWS_REGION_LABEL = /^[a-z]{2}(?:-[a-z]+){1,2}-\d$/;
const BEDROCK_RUNTIME_HOST = /^(bedrock-runtime(?:-fips)?)\.([a-z0-9-]+)(\.amazonaws\.com(?:\.cn)?)$/i;

export function bedrockRegionConfigError(region: unknown): string | null {
  if (typeof region !== "string" || !AWS_REGION_LABEL.test(region)) {
    return "Amazon Bedrock region must be a single lowercase AWS region label (for example, us-east-1 or eu-central-1)";
  }
  return null;
}

/**
 * Region precedence: the provider's `region`, the region embedded in a concrete Bedrock runtime
 * `baseUrl`, then `AWS_REGION` / `AWS_DEFAULT_REGION`, then the registry default. A configured
 * value that is not a region label fails closed rather than becoming part of a request host.
 */
export function resolveBedrockRegion(
  provider: Pick<OcxProviderConfig, "region" | "baseUrl">,
  env: Record<string, string | undefined> = process.env,
): string {
  if (provider.region !== undefined) {
    const error = bedrockRegionConfigError(provider.region);
    if (error) throw new Error(`amazon-bedrock provider ${error}`);
    return provider.region;
  }
  const fromHost = regionFromBaseUrl(provider.baseUrl);
  if (fromHost) return fromHost;
  for (const name of ["AWS_REGION", "AWS_DEFAULT_REGION"] as const) {
    const value = env[name]?.trim();
    if (value && AWS_REGION_LABEL.test(value)) return value;
  }
  return BEDROCK_DEFAULT_REGION;
}

function regionFromBaseUrl(baseUrl: string | undefined): string | undefined {
  if (typeof baseUrl !== "string" || baseUrl.includes("{")) return undefined;
  try {
    const match = BEDROCK_RUNTIME_HOST.exec(new URL(baseUrl).hostname);
    const region = match?.[2]?.toLowerCase();
    return region && AWS_REGION_LABEL.test(region) ? region : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The request origin, plus any fixed path prefix for a gateway. A canonical Bedrock runtime host
 * is rebuilt for `region`, so one row serves every region through its `region` field; any other
 * host is the operator's and is used verbatim. A literal `{region}` placeholder is also
 * substituted. Refuses a malformed URL or any other unresolved `{placeholder}` so a typo never
 * reaches the wire.
 */
export function bedrockRuntimeOrigin(baseUrl: string, region: string): string {
  const substituted = baseUrl.trim().split("{region}").join(region).replace(/\/+$/, "");
  // indexOf instead of a regex: \{[^}]*\} is quadratic on brace-only input (CodeQL js/polynomial-redos).
  const openBrace = substituted.indexOf("{");
  const closeBrace = openBrace === -1 ? -1 : substituted.indexOf("}", openBrace);
  if (closeBrace !== -1) {
    throw new Error(`amazon-bedrock baseUrl contains unresolved ${substituted.slice(openBrace, closeBrace + 1)}`);
  }
  let url: URL;
  try {
    url = new URL(substituted);
  } catch {
    throw new Error(`amazon-bedrock provider has malformed baseUrl: ${baseUrl}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`amazon-bedrock provider baseUrl must be http(s): ${baseUrl}`);
  }
  const canonical = BEDROCK_RUNTIME_HOST.exec(url.hostname);
  if (canonical) url.hostname = `${canonical[1]!.toLowerCase()}.${region}${canonical[3]!.toLowerCase()}`;
  const path = url.pathname.replace(/\/+$/, "");
  return `${url.origin}${path === "/" ? "" : path}`;
}

/**
 * Cross-region inference profile prefix for a source region. Claude's current generations are
 * served through geography-scoped profiles (`us.`, `eu.`, `apac.`, `jp.`, `au.`, `us-gov.`); an
 * unknown geography gets the in-region id (no prefix). Name a full Bedrock id to pick another
 * profile, for example `global.anthropic.claude-sonnet-5-5`.
 */
export function bedrockInferenceProfilePrefix(region: string): string {
  if (region.startsWith("us-gov-")) return "us-gov.";
  if (region.startsWith("us-")) return "us.";
  if (region.startsWith("eu-")) return "eu.";
  if (region === "ap-northeast-1" || region === "ap-northeast-3") return "jp.";
  if (region === "ap-southeast-2") return "au.";
  if (region.startsWith("ap-")) return "apac.";
  return "";
}

/** A Bedrock model id, inference-profile id or ARN, as opposed to a canonical `claude-*` id. */
export function isBedrockModelIdentifier(modelId: string): boolean {
  return /^arn:/i.test(modelId) || /(?:^|\.)anthropic\./i.test(modelId);
}

/** The id placed in the request path: canonical `claude-*` ids map onto the region's profile. */
export function bedrockWireModelId(modelId: string, region: string): string {
  if (isBedrockModelIdentifier(modelId)) return modelId;
  if (/^claude-/i.test(modelId)) return `${bedrockInferenceProfilePrefix(region)}anthropic.${modelId}`;
  return modelId;
}

/**
 * The canonical Claude id inside a Bedrock identifier, so the Anthropic adapter's per-family
 * contract (adaptive thinking, sampling rules, output ceilings) reads the family it knows.
 * `us.anthropic.claude-opus-5-5` -> `claude-opus-5-5`; an id without a Claude segment is unchanged.
 */
export function canonicalClaudeModelId(modelId: string): string {
  const match = /(?:^|[./:])(claude-[a-z0-9.-]+(?::\d+)?)$/i.exec(modelId);
  return match?.[1] ?? modelId;
}

export function bedrockModelUrl(origin: string, wireModelId: string, stream: boolean): string {
  const operation = stream ? "invoke-with-response-stream" : "invoke";
  return `${origin}/model/${encodeURIComponent(wireModelId)}/${operation}`;
}
