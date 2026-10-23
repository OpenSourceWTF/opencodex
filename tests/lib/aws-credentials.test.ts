import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  __resetAwsCredentialCache,
  AWS_SSO_LOGIN_GUIDANCE,
  AwsCredentialError,
  awsProfileConfigError,
  parseAwsIni,
  reconcileAwsCredentials,
  resolveAwsCredentials,
  sweepExpiredAwsCredentials,
} from "../../src/lib/aws-credentials";
import { removeTreeWithRetry } from "../helpers/remove-tree";

let home: string;
const NOW = Date.parse("2026-10-20T20:00:00Z");

function writeAws(name: "config" | "credentials", text: string): void {
  mkdirSync(join(home, ".aws"), { recursive: true });
  writeFileSync(join(home, ".aws", name), text, { mode: 0o600 });
}

function ssoCacheFile(key: string): string {
  const dir = join(home, ".aws", "sso", "cache");
  mkdirSync(dir, { recursive: true });
  return join(dir, `${createHash("sha1").update(key).digest("hex")}.json`);
}

const SSO_CONFIG = `
[profile bedrock]
sso_session = my-sso
sso_account_id = 123456789012
sso_role_name = BedrockUser
region = us-east-1

[sso-session my-sso]
sso_start_url = https://d-example.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access
`;

type FetchCall = { url: string; init?: RequestInit };

function fakeFetch(routes: Record<string, (call: FetchCall) => Response>): { fetch: typeof fetch; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const call = { url, init };
    calls.push(call);
    const route = Object.entries(routes).find(([prefix]) => url.startsWith(prefix));
    if (!route) throw new Error(`unexpected fetch ${url}`);
    return route[1](call);
  }) as typeof fetch;
  return { fetch: impl, calls };
}

const portalOk = () => new Response(JSON.stringify({
  roleCredentials: {
    accessKeyId: "ASIAEXAMPLE",
    secretAccessKey: "sso-secret",
    sessionToken: "sso-session-token",
    expiration: NOW + 60 * 60_000,
  },
}), { status: 200, headers: { "content-type": "application/json" } });

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "aws-creds-"));
  __resetAwsCredentialCache();
});

afterEach(async () => {
  __resetAwsCredentialCache();
  await removeTreeWithRetry(home);
});

describe("aws shared-config parsing", () => {
  test("reads sections, trims values and strips trailing comments", () => {
    const ini = parseAwsIni("[default]\nregion = us-east-2 # home\n\n[profile personal]\n  output=json\n; comment\n[sso-session x]\nsso_region = us-east-1\n");
    expect(ini.get("default")).toEqual({ region: "us-east-2" });
    expect(ini.get("profile personal")).toEqual({ output: "json" });
    expect(ini.get("sso-session x")).toEqual({ sso_region: "us-east-1" });
  });

  test("profile names follow the shared-config character set", () => {
    expect(awsProfileConfigError("bedrock")).toBeNull();
    expect(awsProfileConfigError("team.dev@acme+1")).toBeNull();
    expect(awsProfileConfigError("bad name")).toContain("awsProfile must be");
    expect(awsProfileConfigError("")).toContain("awsProfile must be");
    expect(awsProfileConfigError(42)).toContain("awsProfile must be");
  });
});

describe("resolveAwsCredentials", () => {
  test("environment keys win when no profile is configured", async () => {
    const creds = await resolveAwsCredentials({
      homeDir: home,
      env: { AWS_ACCESS_KEY_ID: "AKIAENV", AWS_SECRET_ACCESS_KEY: "env-secret", AWS_SESSION_TOKEN: "env-token" },
      now: () => NOW,
    });
    expect(creds).toEqual({ accessKeyId: "AKIAENV", secretAccessKey: "env-secret", sessionToken: "env-token", source: "env" });
  });

  test("an explicit profile beats environment keys and reads the shared credentials file", async () => {
    writeAws("credentials", "[personal]\naws_access_key_id = AKIAPERSONAL\naws_secret_access_key = personal-secret\n");
    const creds = await resolveAwsCredentials({
      profile: "personal",
      homeDir: home,
      env: { AWS_ACCESS_KEY_ID: "AKIAENV", AWS_SECRET_ACCESS_KEY: "env-secret" },
      now: () => NOW,
    });
    expect(creds).toEqual({ accessKeyId: "AKIAPERSONAL", secretAccessKey: "personal-secret", source: "credentials-file:personal" });
  });

  test("AWS_PROFILE selects the profile when none is configured", async () => {
    writeAws("credentials", "[work]\naws_access_key_id = AKIAWORK\naws_secret_access_key = work-secret\n");
    const creds = await resolveAwsCredentials({ homeDir: home, env: { AWS_PROFILE: "work" }, now: () => NOW });
    expect(creds.source).toBe("credentials-file:work");
  });

  test("an SSO profile exchanges the cached access token at the portal and caches the role credentials", async () => {
    writeAws("config", SSO_CONFIG);
    writeFileSync(ssoCacheFile("my-sso"), JSON.stringify({
      startUrl: "https://d-example.awsapps.com/start",
      region: "us-east-1",
      accessToken: "cached-access-token",
      expiresAt: new Date(NOW + 3 * 60 * 60_000).toISOString(),
    }));
    const net = fakeFetch({ "https://portal.sso.us-east-1.amazonaws.com/federation/credentials?": portalOk });

    const creds = await resolveAwsCredentials({ profile: "bedrock", homeDir: home, env: {}, fetch: net.fetch, now: () => NOW });
    expect(creds).toEqual({
      accessKeyId: "ASIAEXAMPLE",
      secretAccessKey: "sso-secret",
      sessionToken: "sso-session-token",
      expiresAtMs: NOW + 60 * 60_000,
      source: "sso:bedrock",
    });
    expect(net.calls).toHaveLength(1);
    const portal = new URL(net.calls[0]!.url);
    expect(portal.searchParams.get("account_id")).toBe("123456789012");
    expect(portal.searchParams.get("role_name")).toBe("BedrockUser");
    expect(new Headers(net.calls[0]!.init?.headers).get("x-amz-sso_bearer_token")).toBe("cached-access-token");

    // Second resolution is served from memory; no second portal call.
    await resolveAwsCredentials({ profile: "bedrock", homeDir: home, env: {}, fetch: net.fetch, now: () => NOW });
    expect(net.calls).toHaveLength(1);
    // Within five minutes of expiry the cache is bypassed and the portal is asked again.
    await resolveAwsCredentials({ profile: "bedrock", homeDir: home, env: {}, fetch: net.fetch, now: () => NOW + 56 * 60_000 });
    expect(net.calls).toHaveLength(2);
  });

  test("an expired SSO token with a refresh token is refreshed through SSO-OIDC and written back", async () => {
    writeAws("config", SSO_CONFIG);
    const cachePath = ssoCacheFile("my-sso");
    writeFileSync(cachePath, JSON.stringify({
      startUrl: "https://d-example.awsapps.com/start",
      region: "us-east-1",
      accessToken: "stale-access-token",
      expiresAt: new Date(NOW - 60_000).toISOString(),
      refreshToken: "refresh-1",
      clientId: "client-id",
      clientSecret: "client-secret",
    }));
    const net = fakeFetch({
      "https://oidc.us-east-1.amazonaws.com/token": call => {
        const body = JSON.parse(String(call.init?.body)) as Record<string, string>;
        expect(body).toEqual({ clientId: "client-id", clientSecret: "client-secret", grantType: "refresh_token", refreshToken: "refresh-1" });
        return new Response(JSON.stringify({ accessToken: "fresh-access-token", expiresIn: 28_800, refreshToken: "refresh-2" }), { status: 200 });
      },
      "https://portal.sso.us-east-1.amazonaws.com/federation/credentials?": call => {
        expect(new Headers(call.init?.headers).get("x-amz-sso_bearer_token")).toBe("fresh-access-token");
        return portalOk();
      },
    });

    const creds = await resolveAwsCredentials({ profile: "bedrock", homeDir: home, env: {}, fetch: net.fetch, now: () => NOW });
    expect(creds.accessKeyId).toBe("ASIAEXAMPLE");
    expect(net.calls.map(c => new URL(c.url).hostname)).toEqual(["oidc.us-east-1.amazonaws.com", "portal.sso.us-east-1.amazonaws.com"]);
    const rewritten = JSON.parse(readFileSync(cachePath, "utf8")) as Record<string, string>;
    expect(rewritten.accessToken).toBe("fresh-access-token");
    expect(rewritten.refreshToken).toBe("refresh-2");
    expect(Date.parse(rewritten.expiresAt!)).toBeGreaterThan(NOW);
  });

  test("an expired SSO token without a refresh token gives the login command, not the profile", async () => {
    writeAws("config", SSO_CONFIG);
    writeFileSync(ssoCacheFile("my-sso"), JSON.stringify({
      accessToken: "stale", expiresAt: new Date(NOW - 60_000).toISOString(),
    }));
    const net = fakeFetch({});
    const error = await resolveAwsCredentials({ profile: "bedrock", homeDir: home, env: {}, fetch: net.fetch, now: () => NOW }).catch(e => e);
    expect(error).toBeInstanceOf(AwsCredentialError);
    expect(error.message).toBe(`the AWS SSO session for the configured profile has expired; ${AWS_SSO_LOGIN_GUIDANCE}`);
    expect(net.calls).toHaveLength(0);
  });

  test("a rejected SSO token at the portal, a missing session and a legacy start-url cache key are all handled", async () => {
    writeAws("config", SSO_CONFIG);
    const missing = await resolveAwsCredentials({ profile: "bedrock", homeDir: home, env: {}, fetch: fakeFetch({}).fetch, now: () => NOW }).catch(e => e);
    expect(missing.message).toContain("no AWS SSO session is cached");

    writeFileSync(ssoCacheFile("my-sso"), JSON.stringify({ accessToken: "revoked", expiresAt: new Date(NOW + 3_600_000).toISOString() }));
    const rejected = fakeFetch({ "https://portal.sso.us-east-1.amazonaws.com/federation/credentials?": () => new Response("{}", { status: 401 }) });
    const error = await resolveAwsCredentials({ profile: "bedrock", homeDir: home, env: {}, fetch: rejected.fetch, now: () => NOW }).catch(e => e);
    expect(error.message).toContain("rejected the cached session for the configured profile (HTTP 401)");
    expect(error.message).toContain(AWS_SSO_LOGIN_GUIDANCE);

    // Legacy profiles without sso_session key their cache on the start URL.
    writeAws("config", "[profile legacy]\nsso_start_url = https://d-legacyexample.awsapps.com/start\nsso_region = us-east-1\nsso_account_id = 123456789012\nsso_role_name = Dev\n");
    writeFileSync(ssoCacheFile("https://d-legacyexample.awsapps.com/start"), JSON.stringify({ accessToken: "legacy-token", expiresAt: new Date(NOW + 3_600_000).toISOString() }));
    const legacy = fakeFetch({ "https://portal.sso.us-east-1.amazonaws.com/federation/credentials?": portalOk });
    const creds = await resolveAwsCredentials({ profile: "legacy", homeDir: home, env: {}, fetch: legacy.fetch, now: () => NOW });
    expect(creds.source).toBe("sso:legacy");
  });

  test("unsupported profile shapes and unknown profiles fail with a named reason", async () => {
    writeAws("config", "[profile proc]\ncredential_process = /usr/bin/false\n[profile chained]\nrole_arn = arn:aws:iam::123456789012:role/x\nsource_profile = default\n");
    await expect(resolveAwsCredentials({ profile: "proc", homeDir: home, env: {}, now: () => NOW })).rejects.toThrow("credential_process");
    await expect(resolveAwsCredentials({ profile: "chained", homeDir: home, env: {}, now: () => NOW })).rejects.toThrow("role_arn");
    await expect(resolveAwsCredentials({ profile: "nope", homeDir: home, env: {}, now: () => NOW })).rejects.toThrow("the configured AWS profile was not found in the AWS config");
    await expect(resolveAwsCredentials({ profile: "bad name", homeDir: home, env: {}, now: () => NOW })).rejects.toThrow("the configured AWS profile name is not valid");
  });

  test("client-facing messages never carry the profile name or the home path; the detail keeps the path redacted", async () => {
    // `aws configure sso` suggests names like <Role>-<AccountId>; none of it may reach a client.
    const profile = "BedrockUser-123456789012";
    const notFound = await resolveAwsCredentials({ profile, homeDir: home, env: {}, now: () => NOW }).catch(e => e);
    expect(notFound).toBeInstanceOf(AwsCredentialError);
    expect(notFound.message).toBe("the configured AWS profile was not found in the AWS config");
    expect(notFound.detail).toContain("profile from the provider's awsProfile");
    expect(notFound.detail).toContain(".aws/config");
    writeAws("config", "[profile other]\nregion = us-east-1\n");
    const named = await resolveAwsCredentials({ profile, homeDir: home, env: {}, now: () => NOW }).catch(e => e);
    const viaEnv = await resolveAwsCredentials({ homeDir: home, env: { AWS_PROFILE: profile }, now: () => NOW }).catch(e => e);
    expect(viaEnv.detail).toContain("profile from AWS_PROFILE");
    writeAws("config", `[profile ${profile}]\nsso_session = missing\n[profile half]\nsso_start_url = https://d-example.awsapps.com/start\n`);
    const badSession = await resolveAwsCredentials({ profile, homeDir: home, env: {}, now: () => NOW }).catch(e => e);
    const incomplete = await resolveAwsCredentials({ profile: "half", homeDir: home, env: {}, now: () => NOW }).catch(e => e);
    for (const error of [notFound, named, viaEnv, badSession, incomplete]) {
      expect(error).toBeInstanceOf(AwsCredentialError);
      expect(error.message).not.toContain(profile);
      expect(error.message).not.toContain("123456789012");
      expect(error.message).not.toContain(home);
      expect(error.message).not.toContain("half");
      expect(error.detail ?? "").not.toContain(profile);
      expect(error.detail ?? "").not.toMatch(/\/(Users|home)\/(?!\[USER\])/);
    }
  });

  test("sweep drops expiring entries and a config generation clears the cache", async () => {
    writeAws("config", SSO_CONFIG);
    writeFileSync(ssoCacheFile("my-sso"), JSON.stringify({ accessToken: "t", expiresAt: new Date(NOW + 3_600_000).toISOString() }));
    const net = fakeFetch({ "https://portal.sso.us-east-1.amazonaws.com/federation/credentials?": portalOk });
    await resolveAwsCredentials({ profile: "bedrock", homeDir: home, env: {}, fetch: net.fetch, now: () => NOW });
    expect(sweepExpiredAwsCredentials(NOW)).toBe(0);
    expect(sweepExpiredAwsCredentials(NOW + 56 * 60_000)).toBe(1);
    await resolveAwsCredentials({ profile: "bedrock", homeDir: home, env: {}, fetch: net.fetch, now: () => NOW });
    expect(reconcileAwsCredentials({ generation: 1 } as never)).toBe(1);
    expect(reconcileAwsCredentials({ generation: 1 } as never)).toBe(0);
  });
});
