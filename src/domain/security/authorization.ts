import { err, ok, type Result } from "../result.js";
import type { AuthorizationScope } from "./assessment.js";

export interface AuthorizationError {
  readonly code:
    | "TARGET_NOT_AUTHORIZED"
    | "TARGET_EXPLICITLY_DENIED"
    | "AUTHORIZATION_EXPIRED"
    | "ACTIVE_VERIFICATION_DISALLOWED";
  readonly target: string;
  readonly message: string;
}

/**
 * Normalize target string for uniform comparison.
 */
const normalizeTarget = (target: string): string => {
  return target.trim().toLowerCase().replaceAll("\\", "/");
};

/**
 * Check if candidate target matches an allowed/denied pattern.
 * Supports exact matching, directory prefix matching, and wildcard domain matching.
 */
const matchesPattern = (target: string, pattern: string): boolean => {
  const normTarget = normalizeTarget(target);
  const normPattern = normalizeTarget(pattern);

  if (normTarget === normPattern) {
    return true;
  }

  // Path prefix match (e.g. pattern="/opt/firmware" matches "/opt/firmware/squashfs-root/bin/busybox")
  if (
    normPattern.endsWith("/") &&
    normTarget.startsWith(normPattern)
  ) {
    return true;
  }
  if (normTarget.startsWith(`${normPattern}/`)) {
    return true;
  }

  // Domain wildcard match (e.g. pattern="*.internal.corp" matches "api.internal.corp")
  if (normPattern.startsWith("*.")) {
    const domainSuffix = normPattern.slice(1); // ".internal.corp"
    if (normTarget.endsWith(domainSuffix)) {
      return true;
    }
  }

  return false;
};

/**
 * Validate that a target operation strictly falls within the declared authorization scope.
 * Fails closed if any ambiguity exists or authorization has expired.
 */
export const validateTargetAuthorization = (
  target: string,
  scope: AuthorizationScope,
  now?: string,
): Result<void, AuthorizationError> => {
  const currentTimestamp = now ?? new Date().toISOString();

  // 1. Check expiration
  if (currentTimestamp > scope.valid_until) {
    return err({
      code: "AUTHORIZATION_EXPIRED",
      target,
      message: `Authorization scope expired at ${scope.valid_until} (current: ${currentTimestamp}).`,
    });
  }

  // 2. Check explicit denials first (Deny-overrides)
  for (const denied of scope.denied_targets) {
    if (matchesPattern(target, denied)) {
      return err({
        code: "TARGET_EXPLICITLY_DENIED",
        target,
        message: `Target '${target}' matches explicitly denied scope pattern '${denied}'.`,
      });
    }
  }

  // 3. Check allowed targets
  let isAllowed = false;
  for (const allowed of scope.allowed_targets) {
    if (matchesPattern(target, allowed)) {
      isAllowed = true;
      break;
    }
  }

  if (!isAllowed) {
    return err({
      code: "TARGET_NOT_AUTHORIZED",
      target,
      message: `Target '${target}' is not covered by any allowed target in authorization scope.`,
    });
  }

  return ok(undefined);
};

/**
 * Validate whether active execution / exploitation verification is permitted.
 */
export const validateActiveVerificationPermission = (
  scope: AuthorizationScope,
): Result<void, AuthorizationError> => {
  if (!scope.allow_active_verification) {
    return err({
      code: "ACTIVE_VERIFICATION_DISALLOWED",
      target: "active_verification",
      message:
        "Active vulnerability verification is disabled in the current authorization scope.",
    });
  }
  return ok(undefined);
};
