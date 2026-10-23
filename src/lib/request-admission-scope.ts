import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Who the data-plane request served by the current async context was admitted as.
 *
 * The server resolves admission once per request (`resolveApiAuth` and its siblings in
 * `src/server/auth-cors.ts`) and records the kind in the request log as `admissionKind`. Most
 * code never needs it again, but an action that runs on the proxy host on a caller's behalf does:
 * the bedrock adapter's browser SSO login may start only for the host's own operator, so a remote
 * API-key holder in hub or LAN mode can never open a browser on the host.
 *
 * Scoped through AsyncLocalStorage rather than threaded through every adapter call site, the way
 * `src/lib/request-execution-budget.ts` scopes its physical-send reporter. Absent means "not a
 * data-plane request" (management routes, background work started outside a request), which
 * every consumer must treat as not local.
 */
export type RequestAdmissionKind = "configured" | "environment" | "loopback";

interface RequestAdmissionScope {
  readonly kind: RequestAdmissionKind;
  /** The proxy's main listener requires API keys (a hub or LAN bind). */
  readonly publicBind: boolean;
}

const scope = new AsyncLocalStorage<RequestAdmissionScope>();

export function runWithRequestAdmission<T>(kind: RequestAdmissionKind | undefined, publicBind: boolean, work: () => T): T {
  return kind === undefined ? work() : scope.run({ kind, publicBind }, work);
}

/**
 * Whether the current request comes from the host's own operator: admitted on loopback by a proxy
 * whose main listener is itself loopback. A hub's or LAN bind's secondary loopback listener does
 * not qualify, which is the rule `admissionMayUseMeteredComboTargets` applies to operator consent
 * in `src/server/admission-model-scope.ts`.
 */
export function requestFromLocalOperator(): boolean {
  const current = scope.getStore();
  return current?.kind === "loopback" && !current.publicBind;
}
