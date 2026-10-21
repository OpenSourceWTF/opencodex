import { existsSync } from "node:fs";

/**
 * Interactive AWS SSO login for the `bedrock` adapter, matching Claude Code's own
 * `awsAuthRefresh` behavior: when the IAM Identity Center session behind an AWS profile is
 * missing or expired, run `aws sso login --profile <name>` (which opens the browser), wait for
 * the operator to approve, then let the caller re-read the refreshed token cache.
 *
 * The command is fixed, not configurable: the only operator inputs are the profile name, which
 * is validated against the shared-config character set before it reaches the argv, and the
 * on/off switch. One login runs per profile at a time; concurrent requests wait on the same one.
 */

const LOGIN_TIMEOUT_MS = 180_000;
/** Homebrew, the AWS installer bundle, and the Linux default, tried only after `PATH` misses. */
const AWS_CLI_FALLBACK_PATHS = ["/opt/homebrew/bin/aws", "/usr/local/bin/aws", "/usr/bin/aws"];
const AWS_PROFILE_NAME = /^[A-Za-z0-9_.@+=,-]{1,128}$/;

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

export interface RunAwsSsoLoginOptions {
  env?: Record<string, string | undefined>;
  /** Replaces the real spawn in tests. */
  spawn?: (executable: string, profile: string) => Promise<{ exitCode: number; stderr: string }>;
  timeoutMs?: number;
  /** Install locations tried after PATH; tests pass `[]` so a developer's real CLI is never run. */
  cliFallbackPaths?: readonly string[];
}

async function spawnAwsSsoLogin(executable: string, profile: string, env: Record<string, string | undefined>, timeoutMs: number): Promise<{ exitCode: number; stderr: string }> {
  const proc = Bun.spawn([executable, "sso", "login", "--profile", profile], {
    env: { ...env, AWS_PAGER: "" } as Record<string, string>,
    stdin: "ignore",
    stdout: "ignore",
    stderr: "pipe",
  });
  const timer = setTimeout(() => proc.kill(), timeoutMs);
  try {
    const [exitCode, stderr] = await Promise.all([proc.exited, new Response(proc.stderr).text()]);
    return { exitCode, stderr };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Run the browser login for `profile`, once per profile at a time. Resolves when the CLI exits 0;
 * rejects with an operator-readable message otherwise. The CLI's own stderr is folded into the
 * message with secrets impossible by construction (it prints URLs and codes, never tokens).
 */
export function runAwsSsoLogin(profile: string, options: RunAwsSsoLoginOptions = {}): Promise<void> {
  if (!AWS_PROFILE_NAME.test(profile)) {
    return Promise.reject(new AwsSsoLoginError(`AWS profile "${profile}" is not a valid profile name`));
  }
  const pending = inflight.get(profile);
  if (pending) return pending;
  const env = options.env ?? process.env;
  const run = (async () => {
    const executable = resolveAwsCliExecutable(env, options.cliFallbackPaths);
    if (!executable) {
      throw new AwsSsoLoginError("the AWS CLI (`aws`) was not found on PATH, so the SSO login could not be started — install it or run `aws sso login` yourself");
    }
    const timeoutMs = options.timeoutMs ?? LOGIN_TIMEOUT_MS;
    const result = options.spawn
      ? await options.spawn(executable, profile)
      : await spawnAwsSsoLogin(executable, profile, env, timeoutMs);
    if (result.exitCode !== 0) {
      const detail = result.stderr.trim().split("\n").filter(Boolean).at(-1);
      throw new AwsSsoLoginError(`\`aws sso login --profile ${profile}\` exited with code ${result.exitCode}${detail ? `: ${detail}` : ""}`);
    }
  })().finally(() => inflight.delete(profile));
  inflight.set(profile, run);
  return run;
}

export function __resetAwsSsoLoginForTests(): void {
  inflight.clear();
}
