import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createBedrockAdapter as createBedrockAdapterProduction } from "../../src/adapters/bedrock";
import { __resetAwsCredentialCache, AWS_SSO_LOGIN_GUIDANCE } from "../../src/lib/aws-credentials";
import { __resetAwsSsoLoginForTests } from "../../src/lib/aws-sso-login";
import { runWithRequestAdmission, type RequestAdmissionKind } from "../../src/lib/request-admission-scope";
import { parseRequest } from "../../src/responses/parser";
import type { OcxProviderConfig } from "../../src/types";
import { removeTreeWithRetry } from "../helpers/remove-tree";
import { withTestTranslatorBudget } from "../helpers/translator-budget";

// The browser SSO login spends the user's AWS identity on the proxy host. It runs only when the
// operator opted in AND the request was loopback-admitted on a loopback bind; every other combination must fail
// with the guidance and never start the CLI. A fake `aws` first on PATH records each invocation,
// so a regression could never reach a real CLI on the test machine. The shared config comes from
// AWS_CONFIG_FILE (os.homedir() does not follow a HOME change at runtime); the SSO session name is
// unique per run, so no token cache can exist for it.

const ENV = ["HOME", "PATH", "AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"] as const;
const saved = Object.fromEntries(ENV.map(name => [name, process.env[name]])) as Record<typeof ENV[number], string | undefined>;
let home: string;
let marker: string;
const SESSION = `my-sso-${crypto.randomUUID()}`;

const SSO_CONFIG = `
[profile personal]
sso_session = ${SESSION}
sso_account_id = 123456789012
sso_role_name = BedrockUser
region = us-east-1

[sso-session ${SESSION}]
sso_start_url = https://d-example.awsapps.com/start
sso_region = us-east-1
`;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "bedrock-sso-gate-"));
  marker = join(home, "aws-invocations");
  const bin = join(home, "bin");
  mkdirSync(bin, { recursive: true });
  mkdirSync(join(home, ".aws"), { recursive: true });
  writeFileSync(join(home, ".aws", "config"), SSO_CONFIG);
  // Exits 1 without touching the token cache: the login "fails", which also arms the backoff.
  writeFileSync(join(bin, "aws"), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${marker}'\nexit 1\n`, { mode: 0o755 });
  for (const name of ENV) delete process.env[name];
  process.env.HOME = home;
  process.env.PATH = bin;
  process.env.AWS_CONFIG_FILE = join(home, ".aws", "config");
  process.env.AWS_SHARED_CREDENTIALS_FILE = join(home, ".aws", "credentials");
  __resetAwsCredentialCache();
  __resetAwsSsoLoginForTests();
});

afterEach(async () => {
  for (const name of ENV) {
    if (saved[name] === undefined) delete process.env[name]; else process.env[name] = saved[name];
  }
  __resetAwsCredentialCache();
  __resetAwsSsoLoginForTests();
  await removeTreeWithRetry(home);
});

function provider(overrides: Partial<OcxProviderConfig> = {}): OcxProviderConfig {
  return {
    adapter: "bedrock",
    baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
    authMode: "key",
    region: "us-east-1",
    awsProfile: "personal",
    ...overrides,
  };
}

async function build(config: OcxProviderConfig, kind: RequestAdmissionKind | undefined, publicBind = false): Promise<Error> {
  const adapter = withTestTranslatorBudget(createBedrockAdapterProduction(config));
  const request = parseRequest({ model: "claude-sonnet-5-5", stream: true, input: [{ role: "user", content: "hi" }] });
  return runWithRequestAdmission(kind, publicBind, () => adapter.buildRequest(request)).then(
    () => { throw new Error("buildRequest unexpectedly succeeded"); },
    (error: Error) => error,
  );
}

const invocations = (): string[] => existsSync(marker) ? readFileSync(marker, "utf8").split("\n").filter(Boolean) : [];
const GUIDANCE_ERROR = "amazon-bedrock has no API key and AWS credentials could not be resolved: "
  + `no AWS SSO session is cached for the configured profile; ${AWS_SSO_LOGIN_GUIDANCE}`;

describe("bedrock browser SSO login gate", () => {
  test("default off: even a loopback request gets the guidance and never starts the CLI", async () => {
    const warn = spyOn(console, "warn").mockImplementation(() => {});
    try {
      const error = await build(provider(), "loopback");
      expect(error.message).toBe(GUIDANCE_ERROR);
      expect(error.message).not.toContain("personal");
      expect(invocations()).toEqual([]);
      // The operator's service log names the provider, not the profile or the home directory.
      const lines = warn.mock.calls.map(call => String(call[0]));
      expect(lines.some(line => line.startsWith("[bedrock] amazon-bedrock: AWS credentials could not be resolved:"))).toBe(true);
      for (const line of lines) {
        expect(line).not.toContain("personal");
        expect(line).not.toContain(home);
      }
    } finally {
      warn.mockRestore();
    }
  });

  test("a hand-edited string \"true\" does not arm it", async () => {
    const error = await build(provider({ awsSsoAutoLogin: "true" as unknown as boolean }), "loopback");
    expect(error.message).toBe(GUIDANCE_ERROR);
    expect(invocations()).toEqual([]);
  });

  test.each(["configured", "environment", undefined] as const)(
    "opted in, but a %s admission never opens a browser on the host",
    async kind => {
      const error = await build(provider({ awsSsoAutoLogin: true }), kind);
      expect(error.message).toBe(GUIDANCE_ERROR);
      expect(invocations()).toEqual([]);
    },
  );

  test("opted in, but loopback on a hub or LAN bind (the secondary loopback listener) does not qualify", async () => {
    const error = await build(provider({ awsSsoAutoLogin: true }), "loopback", true);
    expect(error.message).toBe(GUIDANCE_ERROR);
    expect(invocations()).toEqual([]);
  });

  test.skipIf(process.platform === "win32")(
    "opted in and loopback: the fixed command runs once, then the backoff fails fast",
    async () => {
      const first = await build(provider({ awsSsoAutoLogin: true }), "loopback");
      expect(first.message).toBe(GUIDANCE_ERROR);
      expect(invocations()).toEqual(["sso login --profile=personal"]);
      const second = await build(provider({ awsSsoAutoLogin: true }), "loopback");
      expect(second.message).toBe(GUIDANCE_ERROR);
      expect(invocations()).toEqual(["sso login --profile=personal"]);
    },
  );
});
