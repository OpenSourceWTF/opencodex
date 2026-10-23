import { afterAll, beforeEach, describe, expect, mock, test } from "bun:test";

// `mock.module` outlives this file in a shared process; keep the real module and put it back.
const realDns = { ...(await import("node:dns/promises")) };
afterAll(() => {
  mock.module("node:dns/promises", () => realDns);
});

// Mock DNS before importing destination-policy — it binds `lookup` at load time. Every name under
// `.internal.test` answers with a private address; anything else is public.
const lookups: string[] = [];
const lookupMock = mock(async (hostname: string): Promise<{ address: string; family: number }[]> => {
  lookups.push(hostname);
  return [{ address: hostname.endsWith(".internal.test") ? "10.0.0.7" : "93.184.216.34", family: 4 }];
});
mock.module("node:dns/promises", () => ({ lookup: lookupMock }));

const { providerDestinationConfigError, providerDestinationResolvedError } = await import("../../src/lib/destination-policy");
const { configSchema } = await import("../../src/config/schema/config-schema");
const { providerManagementConfigError } = await import("../../src/server/auth-cors");

type Row = { adapter: string; baseUrl: string; authMode: "key"; region?: string; allowPrivateNetwork?: boolean };
const row = (baseUrl: string, overrides: Partial<Row> = {}): Row => ({ adapter: "bedrock", baseUrl, authMode: "key", region: "eu-west-1", ...overrides });

beforeEach(() => {
  lookups.length = 0;
});

const configWith = (bedrock: Record<string, unknown>) => ({ port: 0, defaultProvider: "amazon-bedrock", providers: { "amazon-bedrock": bedrock } });

describe("bedrock destinations are checked as the adapter addresses them", () => {
  test("a {region} placeholder host is resolved after substitution, so private DNS answers are refused", async () => {
    const error = await providerDestinationResolvedError("my-bedrock", row("https://bedrock.{region}.internal.test"));
    expect(lookups).toEqual(["bedrock.eu-west-1.internal.test"]);
    expect(error).toContain("resolves to a private-network address (10.0.0.7)");
    // The explicit opt-in still admits an intentionally private gateway.
    expect(await providerDestinationResolvedError("my-bedrock", row("https://bedrock.{region}.internal.test", { allowPrivateNetwork: true }))).toBeNull();
  });

  test("without a configured region the substitution uses the same fallback the adapter uses", async () => {
    await providerDestinationResolvedError("my-bedrock", row("https://bedrock.{region}.internal.test", { region: undefined }));
    expect(lookups).toEqual([`bedrock.${process.env.AWS_REGION?.trim() || process.env.AWS_DEFAULT_REGION?.trim() || "us-east-1"}.internal.test`]);
  });

  test("a canonical runtime host is checked for the configured region, and stays public", async () => {
    expect(await providerDestinationResolvedError("amazon-bedrock", row("https://bedrock-runtime.us-east-1.amazonaws.com"))).toBeNull();
    expect(lookups).toEqual(["bedrock-runtime.eu-west-1.amazonaws.com"]);
  });

  test("a literal private host behind the placeholder is refused synchronously too", () => {
    expect(providerDestinationConfigError("my-bedrock", row("https://{region}.localhost"))).toContain("localhost");
  });

  test("other adapters keep checking the baseUrl as written", async () => {
    await providerDestinationResolvedError("custom", { ...row("https://bedrock.{region}.internal.test"), adapter: "anthropic" });
    expect(lookups).toEqual(["bedrock.{region}.internal.test"]);
  });
});

describe("bedrock AWS hosts require https", () => {
  test("refused at write time (management and config load), allowed for an operator gateway", () => {
    for (const baseUrl of ["http://bedrock-runtime.us-east-1.amazonaws.com", "http://bedrock-runtime.{region}.amazonaws.com"]) {
      expect(providerDestinationConfigError("amazon-bedrock", row(baseUrl)), baseUrl).toContain("must use https for an AWS host");
      expect(providerManagementConfigError("amazon-bedrock", { ...row(baseUrl), apiKey: "k" }), baseUrl).toContain("must use https for an AWS host");
    }
    expect(providerDestinationConfigError("my-bedrock", row("http://gateway.example/bedrock"))).toBeNull();
    const config = (baseUrl: string) => configWith(row(baseUrl));
    expect(configSchema.safeParse(config("http://bedrock-runtime.us-east-1.amazonaws.com")).success).toBe(false);
    expect(configSchema.safeParse(config("https://bedrock-runtime.us-east-1.amazonaws.com")).success).toBe(true);
  });
});

describe("awsSsoAutoLogin accepts only a boolean", () => {
  test("config load degrades a non-boolean to absent (off); the management write rejects it", () => {
    const parsed = configSchema.safeParse(configWith({ ...row("https://bedrock-runtime.us-east-1.amazonaws.com"), awsSsoAutoLogin: "false" }));
    expect(parsed.success).toBe(true);
    expect(parsed.data?.providers["amazon-bedrock"]?.awsSsoAutoLogin).toBeUndefined();
    const kept = configSchema.safeParse(configWith({ ...row("https://bedrock-runtime.us-east-1.amazonaws.com"), awsSsoAutoLogin: true }));
    expect(kept.data?.providers["amazon-bedrock"]?.awsSsoAutoLogin).toBe(true);
    const base = { ...row("https://bedrock-runtime.us-east-1.amazonaws.com"), apiKey: "k" };
    expect(providerManagementConfigError("amazon-bedrock", { ...base, awsSsoAutoLogin: "false" as unknown as boolean }))
      .toContain("awsSsoAutoLogin must be a boolean");
    expect(providerManagementConfigError("amazon-bedrock", { ...base, awsSsoAutoLogin: true })).toBeNull();
  });
});
