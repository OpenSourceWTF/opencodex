import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { __resetAwsCredentialCache, AwsCredentialError, resolveAwsCredentials } from "../../src/lib/aws-credentials";
import { __resetAwsSsoLoginForTests, AwsSsoLoginError, resolveAwsCliExecutable, runAwsSsoLogin } from "../../src/lib/aws-sso-login";
import { removeTreeWithRetry } from "../helpers/remove-tree";

let home: string;
let binDir: string;
const NOW = Date.parse("2026-10-20T20:00:00Z");

const SSO_CONFIG = `
[profile bedrock]
sso_session = my-sso
sso_account_id = 123456789012
sso_role_name = BedrockUser
region = us-east-1

[sso-session my-sso]
sso_start_url = https://d-example.awsapps.com/start
sso_region = us-east-1
`;

function ssoCacheFile(key: string): string {
  const dir = join(home, ".aws", "sso", "cache");
  mkdirSync(dir, { recursive: true });
  return join(dir, `${createHash("sha1").update(key).digest("hex")}.json`);
}

function portalFetch(): typeof fetch {
  return (async () => new Response(JSON.stringify({
    roleCredentials: { accessKeyId: "ASIAEXAMPLE", secretAccessKey: "s", sessionToken: "t", expiration: NOW + 3_600_000 },
  }), { status: 200 })) as typeof fetch;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "aws-sso-login-"));
  binDir = join(home, "bin");
  mkdirSync(join(home, ".aws"), { recursive: true });
  mkdirSync(binDir, { recursive: true });
  writeFileSync(join(home, ".aws", "config"), SSO_CONFIG);
  // A fake `aws` on PATH so executable resolution succeeds without the real CLI.
  writeFileSync(join(binDir, "aws"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  __resetAwsCredentialCache();
  __resetAwsSsoLoginForTests();
});

afterEach(async () => {
  __resetAwsCredentialCache();
  __resetAwsSsoLoginForTests();
  await removeTreeWithRetry(home);
});

describe("aws sso login runner", () => {
  test("resolves the CLI from PATH and rejects an invalid profile before spawning", async () => {
    expect(resolveAwsCliExecutable({ PATH: binDir })).toBe(join(binDir, "aws"));
    await expect(runAwsSsoLogin("bad name", { env: { PATH: binDir } })).rejects.toBeInstanceOf(AwsSsoLoginError);
  });

  test("a missing CLI is reported with guidance instead of a spawn error", async () => {
    const empty = join(home, "empty");
    mkdirSync(empty);
    const error = await runAwsSsoLogin("bedrock", { env: { PATH: empty }, cliFallbackPaths: [] }).catch(e => e);
    expect(error).toBeInstanceOf(AwsSsoLoginError);
    expect(error.message).toContain("was not found on PATH");
  });

  test("concurrent logins for one profile share a single spawn; a non-zero exit surfaces the CLI's last line", async () => {
    let spawns = 0;
    const spawn = async () => { spawns += 1; await new Promise(r => setTimeout(r, 20)); return { exitCode: 0, stderr: "" }; };
    await Promise.all([
      runAwsSsoLogin("bedrock", { env: { PATH: binDir }, spawn }),
      runAwsSsoLogin("bedrock", { env: { PATH: binDir }, spawn }),
      runAwsSsoLogin("bedrock", { env: { PATH: binDir }, spawn }),
    ]);
    expect(spawns).toBe(1);

    const failing = async () => ({ exitCode: 255, stderr: "Attempting to open browser\nError: The SSO session has expired or is invalid.\n" });
    const error = await runAwsSsoLogin("bedrock", { env: { PATH: binDir }, spawn: failing }).catch(e => e);
    expect(error.message).toBe("`aws sso login --profile bedrock` exited with code 255: Error: The SSO session has expired or is invalid.");
  });
});

describe("credential resolution with automatic SSO login", () => {
  test("an expired session triggers the login, then the refreshed cache is used", async () => {
    const cachePath = ssoCacheFile("my-sso");
    writeFileSync(cachePath, JSON.stringify({ accessToken: "stale", expiresAt: new Date(NOW - 60_000).toISOString() }));
    const spawn = async (executable: string, profile: string) => {
      expect(executable).toBe(join(binDir, "aws"));
      expect(profile).toBe("bedrock");
      // What `aws sso login` does: writes a fresh token into the cache.
      writeFileSync(cachePath, JSON.stringify({ accessToken: "fresh", expiresAt: new Date(NOW + 8 * 3_600_000).toISOString() }));
      return { exitCode: 0, stderr: "" };
    };
    const creds = await resolveAwsCredentials({
      profile: "bedrock", homeDir: home, env: { PATH: binDir }, fetch: portalFetch(), now: () => NOW,
      ssoLogin: { enabled: true, spawn },
    });
    expect(creds.source).toBe("sso:bedrock");
    expect(creds.accessKeyId).toBe("ASIAEXAMPLE");
  });

  test("a missing session also triggers the login; with auto-login off the error names the command", async () => {
    let spawned = false;
    const cachePath = ssoCacheFile("my-sso");
    const spawn = async () => {
      spawned = true;
      writeFileSync(cachePath, JSON.stringify({ accessToken: "fresh", expiresAt: new Date(NOW + 3_600_000).toISOString() }));
      return { exitCode: 0, stderr: "" };
    };
    const off = await resolveAwsCredentials({
      profile: "bedrock", homeDir: home, env: { PATH: binDir }, fetch: portalFetch(), now: () => NOW,
      ssoLogin: { enabled: false, spawn },
    }).catch(e => e);
    expect(off).toBeInstanceOf(AwsCredentialError);
    expect(off.loginRequired).toBe(true);
    expect(off.message).toContain("aws sso login --profile bedrock");
    expect(spawned).toBe(false);

    const creds = await resolveAwsCredentials({
      profile: "bedrock", homeDir: home, env: { PATH: binDir }, fetch: portalFetch(), now: () => NOW,
      ssoLogin: { enabled: true, spawn },
    });
    expect(spawned).toBe(true);
    expect(creds.source).toBe("sso:bedrock");
  });

  test("a failed login keeps the original diagnosis and appends why the login failed", async () => {
    const spawn = async () => ({ exitCode: 1, stderr: "browser could not be opened\n" });
    const error = await resolveAwsCredentials({
      profile: "bedrock", homeDir: home, env: { PATH: binDir }, fetch: portalFetch(), now: () => NOW,
      ssoLogin: { enabled: true, spawn },
    }).catch(e => e);
    expect(error).toBeInstanceOf(AwsCredentialError);
    expect(error.message).toContain("No AWS SSO session is cached");
    expect(error.message).toContain("automatic login failed");
    expect(error.message).toContain("browser could not be opened");
  });

  test("a cancelled request stops waiting without killing the login; the next request finds the token", async () => {
    const cachePath = ssoCacheFile("my-sso");
    let finishLogin: () => void = () => {};
    const spawn = async () => {
      await new Promise<void>(resolve => { finishLogin = resolve; });
      writeFileSync(cachePath, JSON.stringify({ accessToken: "fresh", expiresAt: new Date(NOW + 3_600_000).toISOString() }));
      return { exitCode: 0, stderr: "" };
    };
    const controller = new AbortController();
    const pending = resolveAwsCredentials({
      profile: "bedrock", homeDir: home, env: { PATH: binDir }, fetch: portalFetch(), now: () => NOW,
      signal: controller.signal, ssoLogin: { enabled: true, spawn },
    }).catch(e => e);
    await new Promise(r => setTimeout(r, 10));
    controller.abort();
    const cancelled = await pending;
    expect(cancelled).toBeInstanceOf(AwsCredentialError);
    expect(cancelled.message).toContain("cancelled while the browser login was pending");

    finishLogin();
    await new Promise(r => setTimeout(r, 10));
    // The login was still running and wrote the cache; a fresh request resolves without another spawn.
    let spawnedAgain = false;
    const creds = await resolveAwsCredentials({
      profile: "bedrock", homeDir: home, env: { PATH: binDir }, fetch: portalFetch(), now: () => NOW,
      ssoLogin: { enabled: true, spawn: async () => { spawnedAgain = true; return { exitCode: 0, stderr: "" }; } },
    });
    expect(creds.source).toBe("sso:bedrock");
    expect(spawnedAgain).toBe(false);
  });

  test("static-key and non-SSO failures never start a login", async () => {
    writeFileSync(join(home, ".aws", "config"), "[profile proc]\ncredential_process = /usr/bin/false\n");
    let spawned = false;
    const spawn = async () => { spawned = true; return { exitCode: 0, stderr: "" }; };
    await expect(resolveAwsCredentials({ profile: "proc", homeDir: home, env: { PATH: binDir }, now: () => NOW, ssoLogin: { enabled: true, spawn } }))
      .rejects.toThrow("credential_process");
    expect(spawned).toBe(false);
  });
});
