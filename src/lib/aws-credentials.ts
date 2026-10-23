import { createHash } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { GenerationContext } from "./state-store-sweeper";
import { recordAwsSsoLoginFailure, runAwsSsoLogin, type RunAwsSsoLoginOptions } from "./aws-sso-login";
import { redactUserPath } from "./redact";

/**
 * AWS credential resolution for the `bedrock` adapter, with no `@aws-sdk/*` dependency.
 *
 * Order, matching what the AWS CLI does for the same inputs:
 *
 * 1. With no profile configured: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
 *    (+ `AWS_SESSION_TOKEN`) from the environment.
 * 2. The profile — `awsProfile`, else `AWS_PROFILE`, else `default` — in
 *    `~/.aws/credentials` (static keys) or `~/.aws/config`.
 * 3. An IAM Identity Center (SSO) profile: the access token `aws sso login` cached under
 *    `~/.aws/sso/cache/<sha1>.json`, refreshed through SSO-OIDC when it has expired and carries a
 *    refresh token, exchanged for role credentials at the SSO portal.
 *
 * `role_arn`/`source_profile` chaining and `credential_process` are not implemented; a profile
 * that needs them fails with a message that names the field. Resolved credentials are cached in
 * memory until shortly before they expire.
 *
 * When an SSO session is missing, expired beyond refresh, or rejected, and `ssoLogin` is enabled,
 * the interactive `aws sso login --profile=<name>` is run once (it opens the browser) and the
 * profile is resolved again — the same recovery Claude Code's own `awsAuthRefresh` performs. The
 * caller decides `enabled`: the bedrock adapter sets it only for an opted-in provider serving a
 * loopback-admitted request. Otherwise the error carries {@link AWS_SSO_LOGIN_GUIDANCE}.
 *
 * Error messages reach the client (the adapter's build failure is a 400), so they never name the
 * profile, a file path, or the account: `aws configure sso` suggests profile names such as
 * `<Role>-<AccountId>`. What an operator needs to diagnose further is in `detail`, for the local
 * service log only.
 */

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  /** Epoch milliseconds; absent for static keys. */
  expiresAtMs?: number;
  /** Where the credentials came from, for diagnostics. Never carries secret material. */
  source: string;
}

export type FetchImpl = typeof fetch;

export interface ResolveAwsCredentialsOptions {
  /** Named profile. Omitted: `AWS_PROFILE`, then `default`; env keys win when no profile is set. */
  profile?: string;
  env?: Record<string, string | undefined>;
  homeDir?: string;
  fetch?: FetchImpl;
  now?: () => number;
  signal?: AbortSignal;
  /** Run the interactive SSO login when the session is unusable, then retry once. */
  ssoLogin?: { enabled: boolean } & RunAwsSsoLoginOptions;
}

/** Shared-config profile names: the AWS CLI accepts these characters. */
const AWS_PROFILE_NAME = /^[A-Za-z0-9_.@+=,-]{1,128}$/;
const AWS_REGION_LABEL = /^[a-z]{2}(?:-[a-z]+){1,2}-\d$/;
const AWS_ACCOUNT_ID = /^\d{12}$/;
const AWS_ROLE_NAME = /^[\w+=,.@-]{1,64}$/;
const SSO_TOKEN_SKEW_MS = 60_000;
const CREDENTIAL_REFRESH_SKEW_MS = 5 * 60_000;
const SSO_HTTP_TIMEOUT_MS = 10_000;

export function awsProfileConfigError(value: unknown): string | null {
  if (typeof value !== "string" || !AWS_PROFILE_NAME.test(value)) {
    return "awsProfile must be an AWS shared-config profile name (letters, digits, and _ . @ + = , -)";
  }
  return null;
}

/** Appended to every "the session needs a login" error that did not (or could not) run one. */
export const AWS_SSO_LOGIN_GUIDANCE = "sign in on the proxy host with `aws sso login --profile <name>`, where <name> is this provider's "
  + "awsProfile, or enable awsSsoAutoLogin to open that login automatically for requests from this machine";

export class AwsCredentialError extends Error {
  constructor(
    /** Client-safe: no profile name, path, or account. */
    message: string,
    readonly profile: string | undefined,
    /** An interactive `aws sso login` for `profile` would fix this. */
    readonly loginRequired = false,
    /** Local service log only: no home path and no secret material, but it may quote the AWS CLI. */
    readonly detail?: string,
  ) {
    super(message);
    this.name = "AwsCredentialError";
  }
}

function withLoginGuidance(error: AwsCredentialError, detail?: string): AwsCredentialError {
  const details = [error.detail, detail].filter(Boolean).join("; ");
  return new AwsCredentialError(`${error.message}; ${AWS_SSO_LOGIN_GUIDANCE}`, error.profile, true, details || undefined);
}

type IniSections = Map<string, Record<string, string>>;

/** Minimal INI reader for the AWS shared files: `[section]` headers and `key = value` lines. */
export function parseAwsIni(text: string): IniSections {
  const sections: IniSections = new Map();
  let current: Record<string, string> | undefined;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+[#;].*$/, "").trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const header = /^\[\s*(.+?)\s*\]$/.exec(line);
    if (header) {
      current = {};
      sections.set(header[1]!, current);
      continue;
    }
    if (!current) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    current[line.slice(0, eq).trim().toLowerCase()] = line.slice(eq + 1).trim();
  }
  return sections;
}

function readIni(path: string): IniSections {
  try {
    return parseAwsIni(readFileSync(path, "utf8"));
  } catch {
    return new Map();
  }
}

function awsDir(env: Record<string, string | undefined>, homeDir: string): string {
  return join(homeDir, ".aws");
}

function credentialsPath(env: Record<string, string | undefined>, homeDir: string): string {
  return env.AWS_SHARED_CREDENTIALS_FILE?.trim() || join(awsDir(env, homeDir), "credentials");
}

function configPath(env: Record<string, string | undefined>, homeDir: string): string {
  return env.AWS_CONFIG_FILE?.trim() || join(awsDir(env, homeDir), "config");
}

function configSection(config: IniSections, profile: string): Record<string, string> | undefined {
  return config.get(profile === "default" ? "default" : `profile ${profile}`) ?? config.get(profile);
}

interface SsoCacheEntry {
  accessToken?: string;
  expiresAt?: string;
  refreshToken?: string;
  clientId?: string;
  clientSecret?: string;
  region?: string;
  startUrl?: string;
}

function ssoCachePath(homeDir: string, env: Record<string, string | undefined>, cacheKey: string): string {
  return join(awsDir(env, homeDir), "sso", "cache", `${createHash("sha1").update(cacheKey, "utf8").digest("hex")}.json`);
}

function readSsoCache(path: string): SsoCacheEntry | undefined {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as SsoCacheEntry : undefined;
  } catch {
    return undefined;
  }
}

function writeSsoCache(path: string, entry: SsoCacheEntry): void {
  // Best effort, like the SDKs: the refreshed token also serves the next `aws` CLI call. A read-only
  // cache directory just means the next proxy start refreshes again.
  try {
    writeFileSync(path, JSON.stringify(entry, null, 2), { mode: 0o600 });
    chmodSync(path, 0o600);
  } catch {
    /* ignore */
  }
}

function timeoutSignal(parent: AbortSignal | undefined): AbortSignal {
  const timeout = AbortSignal.timeout(SSO_HTTP_TIMEOUT_MS);
  return parent ? AbortSignal.any([parent, timeout]) : timeout;
}

async function readJsonResponse(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  try {
    const parsed: unknown = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

async function refreshSsoToken(
  entry: SsoCacheEntry,
  ssoRegion: string,
  fetchImpl: FetchImpl,
  signal: AbortSignal | undefined,
): Promise<SsoCacheEntry | undefined> {
  if (!entry.refreshToken || !entry.clientId || !entry.clientSecret) return undefined;
  const response = await fetchImpl(`https://oidc.${ssoRegion}.amazonaws.com/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      clientId: entry.clientId,
      clientSecret: entry.clientSecret,
      grantType: "refresh_token",
      refreshToken: entry.refreshToken,
    }),
    redirect: "error",
    signal: timeoutSignal(signal),
  });
  if (!response.ok) return undefined;
  const body = await readJsonResponse(response);
  if (typeof body.accessToken !== "string" || typeof body.expiresIn !== "number") return undefined;
  return {
    ...entry,
    accessToken: body.accessToken,
    expiresAt: new Date(Date.now() + body.expiresIn * 1000).toISOString(),
    ...(typeof body.refreshToken === "string" ? { refreshToken: body.refreshToken } : {}),
  };
}

async function resolveSsoProfile(
  profile: string,
  section: Record<string, string>,
  config: IniSections,
  options: Required<Pick<ResolveAwsCredentialsOptions, "env" | "homeDir" | "fetch" | "now">> & Pick<ResolveAwsCredentialsOptions, "signal">,
): Promise<AwsCredentials> {
  const sessionName = section.sso_session;
  const session = sessionName ? config.get(`sso-session ${sessionName}`) : undefined;
  if (sessionName && !session) {
    throw new AwsCredentialError("the configured AWS profile names an sso_session that the AWS config does not define", profile);
  }
  const startUrl = session?.sso_start_url ?? section.sso_start_url;
  const ssoRegion = session?.sso_region ?? section.sso_region;
  const accountId = section.sso_account_id;
  const roleName = section.sso_role_name;
  if (!startUrl || !ssoRegion || !accountId || !roleName) {
    throw new AwsCredentialError("the configured AWS profile is an incomplete SSO profile (needs sso_start_url, sso_region, sso_account_id, sso_role_name)", profile);
  }
  if (!AWS_REGION_LABEL.test(ssoRegion)) throw new AwsCredentialError("the configured AWS profile has an invalid sso_region", profile);
  if (!AWS_ACCOUNT_ID.test(accountId)) throw new AwsCredentialError("the configured AWS profile has an invalid sso_account_id", profile);
  if (!AWS_ROLE_NAME.test(roleName)) throw new AwsCredentialError("the configured AWS profile has an invalid sso_role_name", profile);

  const cachePath = ssoCachePath(options.homeDir, options.env, sessionName ?? startUrl);
  let entry = readSsoCache(cachePath);
  if (!entry?.accessToken) {
    throw new AwsCredentialError("no AWS SSO session is cached for the configured profile", profile, true);
  }
  const expiresAtMs = entry.expiresAt ? Date.parse(entry.expiresAt) : Number.NaN;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs - SSO_TOKEN_SKEW_MS <= options.now()) {
    const refreshed = await refreshSsoToken(entry, ssoRegion, options.fetch, options.signal);
    if (!refreshed) {
      throw new AwsCredentialError("the AWS SSO session for the configured profile has expired", profile, true);
    }
    entry = refreshed;
    writeSsoCache(cachePath, entry);
  }

  const portal = new URL(`https://portal.sso.${ssoRegion}.amazonaws.com/federation/credentials`);
  portal.searchParams.set("account_id", accountId);
  portal.searchParams.set("role_name", roleName);
  const response = await options.fetch(portal, {
    headers: { "x-amz-sso_bearer_token": entry.accessToken! },
    redirect: "error",
    signal: timeoutSignal(options.signal),
  });
  if (response.status === 401 || response.status === 403) {
    throw new AwsCredentialError(`AWS SSO rejected the cached session for the configured profile (HTTP ${response.status})`, profile, true);
  }
  if (!response.ok) {
    throw new AwsCredentialError(`the AWS SSO portal returned HTTP ${response.status}`, profile);
  }
  const body = await readJsonResponse(response);
  const role = body.roleCredentials;
  const creds = role && typeof role === "object" ? role as Record<string, unknown> : undefined;
  if (!creds || typeof creds.accessKeyId !== "string" || typeof creds.secretAccessKey !== "string") {
    throw new AwsCredentialError("the AWS SSO portal returned no role credentials", profile);
  }
  return {
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    ...(typeof creds.sessionToken === "string" ? { sessionToken: creds.sessionToken } : {}),
    ...(typeof creds.expiration === "number" ? { expiresAtMs: creds.expiration } : {}),
    source: `sso:${profile}`,
  };
}

function staticFromSection(section: Record<string, string> | undefined, source: string): AwsCredentials | undefined {
  const accessKeyId = section?.aws_access_key_id;
  const secretAccessKey = section?.aws_secret_access_key;
  if (!accessKeyId || !secretAccessKey) return undefined;
  return {
    accessKeyId,
    secretAccessKey,
    ...(section?.aws_session_token ? { sessionToken: section.aws_session_token } : {}),
    source,
  };
}

async function resolveUncached(
  profile: string | undefined,
  options: Required<Pick<ResolveAwsCredentialsOptions, "env" | "homeDir" | "fetch" | "now">> & Pick<ResolveAwsCredentialsOptions, "signal">,
): Promise<AwsCredentials> {
  const { env, homeDir } = options;
  if (profile === undefined) {
    const accessKeyId = env.AWS_ACCESS_KEY_ID?.trim();
    const secretAccessKey = env.AWS_SECRET_ACCESS_KEY?.trim();
    if (accessKeyId && secretAccessKey) {
      const sessionToken = env.AWS_SESSION_TOKEN?.trim();
      return { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}), source: "env" };
    }
  }
  const name = profile ?? (env.AWS_PROFILE?.trim() || "default");
  const origin = profile !== undefined ? "the provider's awsProfile" : env.AWS_PROFILE?.trim() ? "AWS_PROFILE" : "the default profile";
  const error = awsProfileConfigError(name);
  if (error) throw new AwsCredentialError("the configured AWS profile name is not valid", name, false, `profile from ${origin}`);

  const credentials = readIni(credentialsPath(env, homeDir));
  const config = readIni(configPath(env, homeDir));
  const fromCredentials = staticFromSection(credentials.get(name), `credentials-file:${name}`);
  if (fromCredentials) return fromCredentials;
  const section = configSection(config, name);
  const fromConfig = staticFromSection(section, `config-file:${name}`);
  if (fromConfig) return fromConfig;
  if (section && (section.sso_session || section.sso_start_url)) {
    return resolveSsoProfile(name, section, config, options);
  }
  if (section?.credential_process) {
    throw new AwsCredentialError("the configured AWS profile uses credential_process, which the bedrock adapter does not run; paste a Bedrock API key or use a static or SSO profile", name);
  }
  if (section?.role_arn) {
    throw new AwsCredentialError("the configured AWS profile assumes role_arn, which the bedrock adapter does not chain; paste a Bedrock API key or use a static or SSO profile", name);
  }
  if (!section && !credentials.has(name)) {
    const file = configPath(env, homeDir);
    const where = existsSync(file) ? `not in ${redactUserPath(file)}` : `no AWS config file at ${redactUserPath(file)}`;
    throw new AwsCredentialError("the configured AWS profile was not found in the AWS config", name, false, `profile from ${origin}, ${where}`);
  }
  throw new AwsCredentialError("the configured AWS profile has no usable credentials (static keys or an SSO session)", name);
}

const cache = new Map<string, AwsCredentials>();
const inflight = new Map<string, Promise<AwsCredentials>>();
let lastReconciledGeneration = 0;

function cacheKey(profile: string | undefined, env: Record<string, string | undefined>, homeDir: string): string {
  return `${homeDir}\0${profile ?? `$${env.AWS_PROFILE ?? ""}`}`;
}

/** Resolve credentials for the bedrock adapter, cached until five minutes before they expire. */
export async function resolveAwsCredentials(options: ResolveAwsCredentialsOptions = {}): Promise<AwsCredentials> {
  const env = options.env ?? process.env;
  const homeDir = options.homeDir ?? homedir();
  const now = options.now ?? Date.now;
  const key = cacheKey(options.profile, env, homeDir);
  const cached = cache.get(key);
  if (cached && (cached.expiresAtMs === undefined || cached.expiresAtMs - CREDENTIAL_REFRESH_SKEW_MS > now())) return cached;
  cache.delete(key);
  const pending = inflight.get(key);
  if (pending) return pending;
  const resolveOptions = { env, homeDir, fetch: options.fetch ?? fetch, now, signal: options.signal };
  const ssoLogin = options.ssoLogin;
  const run = resolveUncached(options.profile, resolveOptions)
    .catch(async (error: unknown) => {
      if (!(error instanceof AwsCredentialError) || !error.loginRequired || !error.profile) throw error;
      if (!ssoLogin?.enabled) throw withLoginGuidance(error);
      const profile = error.profile;
      // The browser login is the operator's action; the request waits for it, and a caller that
      // gives up (abort) stops waiting without killing the login — the next request finds the token.
      await Promise.race([
        runAwsSsoLogin(profile, { env, now, ...ssoLogin }).catch(loginError => {
          throw withLoginGuidance(error, `automatic login did not complete: ${loginError instanceof Error ? loginError.message : String(loginError)}`);
        }),
        new Promise<never>((_, reject) => {
          options.signal?.addEventListener("abort", () => reject(new AwsCredentialError(`${error.message} (the request was cancelled while the browser login was pending)`, profile, true)), { once: true });
        }),
      ]);
      try {
        return await resolveUncached(options.profile, resolveOptions);
      } catch (retryError) {
        if (!(retryError instanceof AwsCredentialError) || !retryError.loginRequired) throw retryError;
        // The CLI exited 0 yet the session is still unusable: a second login would end the same way.
        recordAwsSsoLoginFailure(profile, now());
        throw withLoginGuidance(retryError, "automatic login finished but the session is still unusable");
      }
    })
    .then(creds => {
      // Static keys never expire on their own; re-read them each start, not each request.
      cache.set(key, creds);
      return creds;
    })
    .finally(() => inflight.delete(key));
  inflight.set(key, run);
  return run;
}

export function sweepExpiredAwsCredentials(now = Date.now()): number {
  let removed = 0;
  for (const [key, creds] of cache) {
    if (creds.expiresAtMs === undefined || creds.expiresAtMs - CREDENTIAL_REFRESH_SKEW_MS > now) continue;
    cache.delete(key);
    removed += 1;
  }
  return removed;
}

/** A config generation change may rename or retarget profiles; drop everything and re-resolve lazily. */
export function reconcileAwsCredentials(context: GenerationContext): number {
  if (context.generation <= lastReconciledGeneration) return 0;
  const removed = cache.size;
  cache.clear();
  lastReconciledGeneration = context.generation;
  return removed;
}

export function __resetAwsCredentialCache(): void {
  cache.clear();
  inflight.clear();
  lastReconciledGeneration = 0;
}
