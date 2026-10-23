import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { saveConfig } from "../../src/config";
import { __resetAwsCredentialCache } from "../../src/lib/aws-credentials";
import { __resetAwsSsoLoginForTests } from "../../src/lib/aws-sso-login";
import { startServer } from "../../src/server";
import { clearRequestLogsForTests } from "../../src/server/request-log";
import type { OcxConfig } from "../../src/types";
import { installIsolatedCodexHome, type IsolatedCodexHome } from "../helpers/isolated-codex-home";
import { removeTreeWithRetry } from "../helpers/remove-tree";

// Hooked-up check for the SSO login gate: the admission scope set by runAdmittedHttpTurn must
// reach the bedrock adapter through the real HTTP path. The adapter-level gate (opt-in, kinds,
// public binds) is covered in tests/adapters/bedrock-sso-login-gate.test.ts; this proves a
// loopback request on a loopback bind is the one that may start it. A fake `aws` first on PATH
// records the invocation and exits 1, so no real CLI or browser is ever involved.

const ENV = ["OPENCODEX_HOME", "PATH", "AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"] as const;
const saved = Object.fromEntries(ENV.map(name => [name, process.env[name]])) as Record<typeof ENV[number], string | undefined>;
const SESSION = `my-sso-${crypto.randomUUID()}`;
let dir = "";
let marker = "";
let isolatedCodexHome: IsolatedCodexHome | null = null;

beforeEach(() => {
  isolatedCodexHome = installIsolatedCodexHome("ocx-bedrock-wiring-codex-");
  dir = mkdtempSync(join(tmpdir(), "ocx-bedrock-wiring-"));
  marker = join(dir, "aws-invocations");
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, "aws"), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${marker}'\nexit 1\n`, { mode: 0o755 });
  writeFileSync(join(dir, "aws-config"), [
    "[profile personal]", `sso_session = ${SESSION}`, "sso_account_id = 123456789012", "sso_role_name = BedrockUser",
    `[sso-session ${SESSION}]`, "sso_start_url = https://d-example.awsapps.com/start", "sso_region = us-east-1", "",
  ].join("\n"));
  for (const name of ENV) delete process.env[name];
  process.env.OPENCODEX_HOME = join(dir, "home");
  process.env.PATH = `${bin}:/usr/bin:/bin`;
  process.env.AWS_CONFIG_FILE = join(dir, "aws-config");
  process.env.AWS_SHARED_CREDENTIALS_FILE = join(dir, "aws-credentials");
  __resetAwsCredentialCache();
  __resetAwsSsoLoginForTests();
  clearRequestLogsForTests();
});

afterEach(async () => {
  clearRequestLogsForTests();
  for (const name of ENV) {
    if (saved[name] === undefined) delete process.env[name]; else process.env[name] = saved[name];
  }
  __resetAwsCredentialCache();
  __resetAwsSsoLoginForTests();
  isolatedCodexHome?.restore();
  isolatedCodexHome = null;
  if (dir) await removeTreeWithRetry(dir);
});

function config(awsSsoAutoLogin: boolean | undefined): OcxConfig {
  return {
    port: 0,
    hostname: "127.0.0.1",
    defaultProvider: "my-bedrock",
    providers: {
      "my-bedrock": {
        adapter: "bedrock",
        baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
        authMode: "key",
        region: "us-east-1",
        awsProfile: "personal",
        models: ["claude-sonnet-5-5"],
        defaultModel: "claude-sonnet-5-5",
        ...(awsSsoAutoLogin === undefined ? {} : { awsSsoAutoLogin }),
      },
    },
  } as OcxConfig;
}

async function postMessages(cfg: OcxConfig): Promise<{ status: number; body: string }> {
  saveConfig(cfg);
  const proxy = startServer(0);
  try {
    const response = await fetch(new URL("/v1/messages", proxy.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "my-bedrock/claude-sonnet-5-5", max_tokens: 16, stream: false, messages: [{ role: "user", content: "hi" }] }),
    });
    return { status: response.status, body: await response.text() };
  } finally {
    await proxy.stop(true);
  }
}

const invocations = (): string[] => existsSync(marker) ? readFileSync(marker, "utf8").split("\n").filter(Boolean) : [];

describe("bedrock SSO login through the HTTP data plane", () => {
  test.skipIf(process.platform === "win32")("an opted-in loopback request reaches the login, once; the client sees only guidance", async () => {
    const first = await postMessages(config(true));
    expect(first.status).toBeGreaterThanOrEqual(400);
    expect(first.body).toContain("aws sso login --profile <name>");
    expect(first.body).not.toContain("personal");
    expect(invocations()).toEqual(["sso login --profile=personal"]);
  });

  test("without the opt-in the same loopback request never starts it", async () => {
    const result = await postMessages(config(undefined));
    expect(result.status).toBeGreaterThanOrEqual(400);
    expect(result.body).toContain("aws sso login --profile <name>");
    expect(invocations()).toEqual([]);
  });
});
