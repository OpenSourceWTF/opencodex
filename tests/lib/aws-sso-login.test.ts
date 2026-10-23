import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { __resetAwsCredentialCache, AWS_SSO_LOGIN_GUIDANCE, AwsCredentialError, resolveAwsCredentials } from "../../src/lib/aws-credentials";
import {
  __resetAwsSsoLoginForTests,
  AWS_SSO_LOGIN_BACKOFF_MS,
  AwsSsoLoginError,
  awsSsoLoginArgv,
  awsSsoLoginSuppressed,
  resolveAwsCliExecutable,
  runAwsSsoLogin,
} from "../../src/lib/aws-sso-login";
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
    expect(error.message).toBe("`aws sso login` exited with code 255: Error: The SSO session has expired or is invalid.");
  });

  test("the profile travels as one --profile=<name> argument, so a leading dash is never a flag", async () => {
    expect(awsSsoLoginArgv("personal")).toEqual(["sso", "login", "--profile=personal"]);
    expect(awsSsoLoginArgv("-dash")).toEqual(["sso", "login", "--profile=-dash"]);
    const seen: Array<readonly string[]> = [];
    await runAwsSsoLogin("-dash", { env: { PATH: binDir }, spawn: async (_exe, argv) => { seen.push(argv); return { exitCode: 0, stderr: "" }; } });
    expect(seen).toEqual([["sso", "login", "--profile=-dash"]]);
  });

  test("the CLI's sign-in URL and code reach the local log; the start-URL line does not", async () => {
    const logged: string[] = [];
    const spawn = async (_exe: string, _argv: readonly string[], log: (line: string) => void) => {
      log("Please visit the following URL:");
      log("https://device.sso.us-east-1.amazonaws.com/");
      log("Then enter the code:");
      log("ABCD-EFGH\u001b[0m");
      log("Successfully logged into Start URL: https://d-example.awsapps.com/start");
      return { exitCode: 0, stderr: "" };
    };
    await runAwsSsoLogin("personal", { env: { PATH: binDir }, spawn, log: line => logged.push(line) });
    expect(logged).toEqual([
      "[bedrock] aws sso login: Please visit the following URL:",
      "[bedrock] aws sso login: https://device.sso.us-east-1.amazonaws.com/",
      "[bedrock] aws sso login: Then enter the code:",
      "[bedrock] aws sso login: ABCD-EFGH[0m",
    ]);
  });

  test("a failed, timed-out or CLI-less login suppresses new attempts for the backoff window", async () => {
    let now = NOW;
    let spawns = 0;
    const failing = async () => { spawns += 1; return { exitCode: 1, stderr: "" }; };
    await expect(runAwsSsoLogin("personal", { env: { PATH: binDir }, spawn: failing, now: () => now })).rejects.toThrow("exited with code 1");
    expect(awsSsoLoginSuppressed("personal", now)).toBe(true);
    // Inside the window: fail fast, no spawn.
    now += AWS_SSO_LOGIN_BACKOFF_MS - 1;
    await expect(runAwsSsoLogin("personal", { env: { PATH: binDir }, spawn: failing, now: () => now })).rejects.toThrow("automatic attempts resume");
    expect(spawns).toBe(1);
    // Another profile is unaffected.
    await runAwsSsoLogin("other", { env: { PATH: binDir }, spawn: async () => ({ exitCode: 0, stderr: "" }), now: () => now });
    // After the window the next attempt spawns again; a timeout counts as a failure too.
    now += 1;
    const timeout = async () => { spawns += 1; return { exitCode: null, stderr: "", timedOut: true }; };
    await expect(runAwsSsoLogin("personal", { env: { PATH: binDir }, spawn: timeout, now: () => now })).rejects.toThrow("was not approved within");
    expect(spawns).toBe(2);
    expect(awsSsoLoginSuppressed("personal", now)).toBe(true);
    // A missing CLI is a failure as well.
    const empty = join(home, "empty");
    mkdirSync(empty);
    await expect(runAwsSsoLogin("fresh", { env: { PATH: empty }, cliFallbackPaths: [], now: () => now })).rejects.toThrow("was not found on PATH");
    expect(awsSsoLoginSuppressed("fresh", now)).toBe(true);
  });
});

describe("credential resolution with automatic SSO login", () => {
  test("an expired session triggers the login, then the refreshed cache is used", async () => {
    const cachePath = ssoCacheFile("my-sso");
    writeFileSync(cachePath, JSON.stringify({ accessToken: "stale", expiresAt: new Date(NOW - 60_000).toISOString() }));
    const spawn = async (executable: string, argv: readonly string[]) => {
      expect(executable).toBe(join(binDir, "aws"));
      expect(argv).toEqual(["sso", "login", "--profile=bedrock"]);
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

  test("a missing session also triggers the login; with auto-login off the error gives the command without the profile", async () => {
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
    expect(off.message).toBe(`no AWS SSO session is cached for the configured profile; ${AWS_SSO_LOGIN_GUIDANCE}`);
    expect(off.message).toContain("aws sso login --profile <name>");
    expect(off.message).not.toContain("bedrock");
    expect(spawned).toBe(false);

    const creds = await resolveAwsCredentials({
      profile: "bedrock", homeDir: home, env: { PATH: binDir }, fetch: portalFetch(), now: () => NOW,
      ssoLogin: { enabled: true, spawn },
    });
    expect(spawned).toBe(true);
    expect(creds.source).toBe("sso:bedrock");
  });

  test("a failed login keeps the diagnosis and guidance for the client; why it failed goes to the detail", async () => {
    const spawn = async () => ({ exitCode: 1, stderr: "browser could not be opened\n" });
    const error = await resolveAwsCredentials({
      profile: "bedrock", homeDir: home, env: { PATH: binDir }, fetch: portalFetch(), now: () => NOW,
      ssoLogin: { enabled: true, spawn },
    }).catch(e => e);
    expect(error).toBeInstanceOf(AwsCredentialError);
    expect(error.message).toBe(`no AWS SSO session is cached for the configured profile; ${AWS_SSO_LOGIN_GUIDANCE}`);
    expect(error.detail).toContain("automatic login did not complete");
    expect(error.detail).toContain("browser could not be opened");
  });

  test("a login that exits 0 but leaves the session unusable backs off; requests in the window fail fast", async () => {
    let now = NOW;
    let spawns = 0;
    const useless = async () => { spawns += 1; return { exitCode: 0, stderr: "" }; };
    const resolve = () => resolveAwsCredentials({
      profile: "bedrock", homeDir: home, env: { PATH: binDir }, fetch: portalFetch(), now: () => now,
      ssoLogin: { enabled: true, spawn: useless },
    }).catch(e => e);
    const first = await resolve();
    expect(first.message).toBe(`no AWS SSO session is cached for the configured profile; ${AWS_SSO_LOGIN_GUIDANCE}`);
    expect(first.detail).toContain("still unusable");
    expect(spawns).toBe(1);
    const second = await resolve();
    expect(second.message).toBe(first.message);
    expect(second.detail).toContain("automatic attempts resume");
    expect(spawns).toBe(1);
    now += AWS_SSO_LOGIN_BACKOFF_MS;
    await resolve();
    expect(spawns).toBe(2);
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
