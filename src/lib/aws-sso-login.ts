import { existsSync } from "node:fs";
import { sanitizeLogMetadataString } from "./redact";

/**
 * Interactive AWS SSO login for the `bedrock` adapter, matching Claude Code's own
 * `awsAuthRefresh` behavior: when the IAM Identity Center session behind an AWS profile is
 * missing or expired, run `aws sso login --profile=<name>` (which opens the browser), wait for
 * the operator to approve, then let the caller re-read the refreshed token cache.
 *
 * It is opt-in (`awsSsoAutoLogin: true`) and the caller starts it only for the host's own operator
 * (`requestFromLocalOperator` in `src/lib/request-admission-scope.ts`). The command is fixed, not configurable: the
 * only operator input is the profile name, which is validated against the shared-config
 * character set and passed as one `--profile=<name>` argument, so a name cannot become a flag.
 * One login runs per profile at a time; concurrent requests wait on the same one.
 *
 * A login that fails (non-zero exit, timeout, missing CLI) or leaves the session unusable
 * suppresses new attempts for that profile for a backoff window, so a host with nobody at the
 * browser does not start a login on every request. The CLI's stdout carries the sign-in URL and,
 * for the device flow, the code; each line goes to the local service log (never to a client), so
 * an operator on a host whose browser cannot open can still finish the login by hand.
 */

const LOGIN_TIMEOUT_MS = 180_000;
/** How long a failed or useless login suppresses the next automatic attempt for the profile. */
export const AWS_SSO_LOGIN_BACKOFF_MS = 5 * 60_000;
/** Homebrew, the AWS installer bundle, and the Linux default, tried only after `PATH` misses. */
const AWS_CLI_FALLBACK_PATHS = ["/opt/homebrew/bin/aws", "/usr/local/bin/aws", "/usr/bin/aws"];
const AWS_PROFILE_NAME = /^[A-Za-z0-9_.@+=,-]{1,128}$/;
/** The success line names the organization's start URL; the sign-in instructions never need it. */
const STDOUT_LINE_WITHHELD = /start url/i;
const LOG_LINE_MAX = 2048;

export class AwsSsoLoginError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AwsSsoLoginError";
  }
}

export function resolveAwsCliExecutable(
  env: Record<string, string | undefined> = process.env,
  fallbackPaths: readonly string[] = AWS_CLI_FALLBACK_PATHS,
): string | undefined {
  const fromPath = Bun.which("aws", { PATH: env.PATH ?? "" });
  if (fromPath) return fromPath;
  return fallbackPaths.find(candidate => existsSync(candidate));
}

const inflight = new Map<string, Promise<void>>();
const suppressedUntil = new Map<string, number>();

export interface AwsSsoLoginResult {
  exitCode: number | null;
  stderr: string;
  timedOut?: boolean;
}

export interface RunAwsSsoLoginOptions {
  env?: Record<string, string | undefined>;
  /** Replaces the real spawn in tests; `log` receives what the CLI prints to stdout. */
  spawn?: (executable: string, argv: readonly string[], log: (line: string) => void) => Promise<AwsSsoLoginResult>;
  timeoutMs?: number;
  /** Install locations tried after PATH; tests pass `[]` so a developer's real CLI is never run. */
  cliFallbackPaths?: readonly string[];
  /** Local service log sink. Defaults to `console.warn`. */
  log?: (line: string) => void;
  now?: () => number;
}

/** The fixed argv after the executable. One argument carries the profile, so it is never a flag. */
export function awsSsoLoginArgv(profile: string): string[] {
  return ["sso", "login", `--profile=${profile}`];
}

/** Forward one line of CLI output to the local log: control characters stripped, secrets redacted, bounded. */
function logCliLine(log: (line: string) => void, line: string): void {
  if (STDOUT_LINE_WITHHELD.test(line)) return;
  const safe = sanitizeLogMetadataString(line, LOG_LINE_MAX);
  if (safe) log(`[bedrock] aws sso login: ${safe}`);
}

async function forwardLines(stream: ReadableStream<Uint8Array>, onLine: (line: string) => void): Promise<void> {
  const decoder = new TextDecoder();
  let pending = "";
  for await (const chunk of stream) {
    pending += decoder.decode(chunk, { stream: true });
    let newline = pending.indexOf("\n");
    while (newline !== -1) {
      onLine(pending.slice(0, newline));
      pending = pending.slice(newline + 1);
      newline = pending.indexOf("\n");
    }
  }
  pending += decoder.decode();
  if (pending) onLine(pending);
}

async function spawnAwsSsoLogin(
  executable: string,
  argv: readonly string[],
  log: (line: string) => void,
  env: Record<string, string | undefined>,
  timeoutMs: number,
): Promise<AwsSsoLoginResult> {
  const proc = Bun.spawn([executable, ...argv], {
    env: { ...env, AWS_PAGER: "" } as Record<string, string>,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; proc.kill(); }, timeoutMs);
  try {
    const [exitCode, stderr] = await Promise.all([
      proc.exited,
      new Response(proc.stderr).text(),
      forwardLines(proc.stdout, log),
    ]);
    return { exitCode, stderr, timedOut };
  } finally {
    clearTimeout(timer);
  }
}

/** Whether a recent failure for `profile` still suppresses an automatic login. */
export function awsSsoLoginSuppressed(profile: string, now: number = Date.now()): boolean {
  const until = suppressedUntil.get(profile);
  if (until === undefined) return false;
  if (until > now) return true;
  suppressedUntil.delete(profile);
  return false;
}

/** Record a login that failed or left the session unusable; the next attempt waits out the backoff. */
export function recordAwsSsoLoginFailure(profile: string, now: number = Date.now()): void {
  suppressedUntil.set(profile, now + AWS_SSO_LOGIN_BACKOFF_MS);
}

/**
 * Run the browser login for `profile`, once per profile at a time. Resolves when the CLI exits 0;
 * rejects with an AwsSsoLoginError otherwise. The message is for the local log: it folds in the
 * CLI's last stderr line, which may echo the profile, so callers keep it away from clients.
 */
export function runAwsSsoLogin(profile: string, options: RunAwsSsoLoginOptions = {}): Promise<void> {
  if (!AWS_PROFILE_NAME.test(profile)) {
    return Promise.reject(new AwsSsoLoginError("the AWS profile name is not valid"));
  }
  const pending = inflight.get(profile);
  if (pending) return pending;
  const now = options.now ?? Date.now;
  if (awsSsoLoginSuppressed(profile, now())) {
    return Promise.reject(new AwsSsoLoginError(
      `a recent automatic \`aws sso login\` for this profile failed; automatic attempts resume ${AWS_SSO_LOGIN_BACKOFF_MS / 60_000} minutes after it`,
    ));
  }
  const env = options.env ?? process.env;
  const log = options.log ?? console.warn;
  const run = (async () => {
    const executable = resolveAwsCliExecutable(env, options.cliFallbackPaths);
    if (!executable) {
      throw new AwsSsoLoginError("the AWS CLI (`aws`) was not found on PATH, so the SSO login could not be started");
    }
    const argv = awsSsoLoginArgv(profile);
    const onLine = (line: string) => logCliLine(log, line);
    const result = options.spawn
      ? await options.spawn(executable, argv, onLine)
      : await spawnAwsSsoLogin(executable, argv, onLine, env, options.timeoutMs ?? LOGIN_TIMEOUT_MS);
    if (result.timedOut) {
      throw new AwsSsoLoginError(`\`aws sso login\` was not approved within ${(options.timeoutMs ?? LOGIN_TIMEOUT_MS) / 1000}s`);
    }
    if (result.exitCode !== 0) {
      const detail = result.stderr.trim().split("\n").filter(Boolean).at(-1);
      throw new AwsSsoLoginError(`\`aws sso login\` exited with code ${result.exitCode}${detail ? `: ${detail}` : ""}`);
    }
  })()
    .catch((error: unknown) => {
      recordAwsSsoLoginFailure(profile, now());
      throw error;
    })
    .finally(() => inflight.delete(profile));
  inflight.set(profile, run);
  return run;
}

export function __resetAwsSsoLoginForTests(): void {
  inflight.clear();
  suppressedUntil.clear();
}
