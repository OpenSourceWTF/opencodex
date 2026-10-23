import type { OcxProviderConfig } from "../../types";

/**
 * Management fields of the `bedrock` adapter: `region` and `awsProfile` (a blank string clears),
 * and `awsSsoAutoLogin` (`true` opts in to the host browser login, `false` or `null` leaves it off).
 * Kept beside provider-routes.ts so the route file stays under its size cap; the value rules
 * themselves are validated again by providerManagementConfigError before anything is written.
 */
export const BEDROCK_PROVIDER_FIELDS = ["region", "awsProfile", "awsSsoAutoLogin"] as const;

export function applyBedrockProviderPatchFields(
  rawBody: Record<string, unknown>,
  next: OcxProviderConfig,
): { error: string } | { touched: boolean } {
  let touched = false;
  for (const field of ["region", "awsProfile"] as const) {
    if (!Object.hasOwn(rawBody, field)) continue;
    const value = rawBody[field];
    if (typeof value !== "string") return { error: `${field} must be a string` };
    const trimmed = value.trim();
    if (trimmed) next[field] = trimmed;
    else delete next[field];
    touched = true;
  }
  if (Object.hasOwn(rawBody, "awsSsoAutoLogin")) {
    if (rawBody.awsSsoAutoLogin === null) {
      delete next.awsSsoAutoLogin;
    } else if (typeof rawBody.awsSsoAutoLogin === "boolean") {
      next.awsSsoAutoLogin = rawBody.awsSsoAutoLogin;
    } else {
      return { error: "awsSsoAutoLogin must be a boolean or null to clear" };
    }
    touched = true;
  }
  return { touched };
}

/** The same fields as the provider list reports them: as configured, never defaulted. */
export function bedrockProviderListFields(provider: OcxProviderConfig): Pick<OcxProviderConfig, typeof BEDROCK_PROVIDER_FIELDS[number]> {
  return { region: provider.region, awsProfile: provider.awsProfile, awsSsoAutoLogin: provider.awsSsoAutoLogin };
}
