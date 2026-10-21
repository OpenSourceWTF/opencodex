import { describe, expect, test } from "bun:test";
import { effectiveAdapterContract, getAdapterDefinition } from "../../src/adapters/registry";
import { deriveKeyLoginMap, providerConfigSeed } from "../../src/providers/derive";
import { getProviderRegistryEntry } from "../../src/providers/registry";
import { ANTHROPIC_MODELS } from "../../src/providers/registry/model-seeds";
import { routedProviderConfig } from "../../src/providers/routed-config";
import { providerManagementConfigError } from "../../src/server/auth-cors";
import type { OcxProviderConfig } from "../../src/types";

const entry = getProviderRegistryEntry("amazon-bedrock");

describe("amazon-bedrock provider registry row", () => {
  test("is a key-auth Claude roster on the bedrock adapter with a templated regional host", () => {
    expect(entry).toBeDefined();
    expect(entry?.adapter).toBe("bedrock");
    expect(entry?.authKind).toBe("key");
    expect(entry?.baseUrl).toBe("https://bedrock-runtime.us-east-1.amazonaws.com");
    expect(entry?.allowBaseUrlOverride).toBe(true);
    expect(entry?.region).toBe("us-east-1");
    expect(entry?.models).toEqual([...ANTHROPIC_MODELS]);
    expect(entry?.liveModels).toBe(false);
    expect(entry?.jawcodeBundle).toBe("amazon-bedrock");
    // No `/models` endpoint exists on the runtime host; the key flow must not fake a verdict.
    expect(entry?.apiKeyValidation).toBe("unknown");
    // A key is one of two credentials: without it the adapter signs with the AWS profile.
    expect(entry?.keyOptional).toBe(true);
  });

  test("inherits the anthropic wire contract through the adapter registry", () => {
    expect(getAdapterDefinition("bedrock")?.contractParent).toBe("anthropic");
    expect(effectiveAdapterContract("bedrock").wire).toBe("anthropic");
  });

  test("seeds region, static roster and the Anthropic model metadata into config", () => {
    const seed = providerConfigSeed(entry!);
    expect(seed.adapter).toBe("bedrock");
    expect(seed.authMode).toBe("key");
    expect(seed.region).toBe("us-east-1");
    expect(seed.liveModels).toBe(false);
    expect(seed.defaultModel).toBe("claude-sonnet-5-5");
    expect(seed.models).toEqual([...ANTHROPIC_MODELS]);
    expect(seed.modelContextWindows?.["claude-opus-5-5"]).toBe(1_000_000);
    expect(seed.modelMaxOutputTokens?.["claude-opus-5-5"]).toBe(128_000);
    expect(seed.modelReasoningEfforts?.["claude-opus-5-5"]).toEqual(["low", "medium", "high", "xhigh", "max"]);
    // apiKeyTransport is an anthropic-adapter-only config field; the bedrock adapter owns its bearer.
    expect(seed.apiKeyTransport).toBeUndefined();
  });

  test("is exported to the key-login map with an unknown validation policy", () => {
    const login = deriveKeyLoginMap()["amazon-bedrock"];
    expect(login).toBeDefined();
    expect(login?.adapter).toBe("bedrock");
    expect(login?.apiKeyValidation).toBe("unknown");
  });

  test("a minimal user row is backfilled with the registry region at route time", () => {
    const routed = routedProviderConfig("amazon-bedrock", {
      adapter: "bedrock",
      baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
      authMode: "key",
      apiKey: "bedrock-key",
    });
    expect(routed.region).toBe("us-east-1");
    const explicit = routedProviderConfig("amazon-bedrock", {
      adapter: "bedrock",
      baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
      authMode: "key",
      apiKey: "bedrock-key",
      region: "eu-west-1",
    });
    expect(explicit.region).toBe("eu-west-1");
  });
});

describe("amazon-bedrock management validation", () => {
  const row = (overrides: Partial<OcxProviderConfig> = {}): OcxProviderConfig => ({
    adapter: "bedrock",
    baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
    authMode: "key",
    apiKey: "bedrock-key",
    region: "us-east-1",
    ...overrides,
  });

  test("accepts a well-formed Bedrock row and rejects a malformed region", () => {
    expect(providerManagementConfigError("amazon-bedrock", row())).toBeNull();
    expect(providerManagementConfigError("amazon-bedrock", row({ region: "us-east-1/evil" })))
      .toContain("region must be a single lowercase AWS region label");
    expect(providerManagementConfigError("amazon-bedrock", row({ awsProfile: "bedrock" }))).toBeNull();
    expect(providerManagementConfigError("amazon-bedrock", row({ apiKey: undefined, awsProfile: "bedrock" }))).toBeNull();
    expect(providerManagementConfigError("amazon-bedrock", row({ awsProfile: "has space" })))
      .toContain("awsProfile must be");
    // The region rule is scoped to the bedrock adapter; other adapters ignore the field.
    expect(providerManagementConfigError("custom-anthropic", {
      adapter: "anthropic", baseUrl: "https://api.anthropic.com", authMode: "key", apiKey: "k", region: "whatever",
    } as OcxProviderConfig)).toBeNull();
  });
});
