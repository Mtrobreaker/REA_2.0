import { posix } from "node:path";
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
 * Detect any raw '..' path traversal segment or NUL byte before normalization.
 */
const hasPathTraversalSegment = (raw: string): boolean => {
  if (raw.includes("\0")) return true;
  const unified = raw.trim().replaceAll("\\", "/");
  const segments = unified.split("/");
  return segments.some((seg) => seg === "..");
};

/**
 * Normalize target string for uniform comparison (POSIX-normalized, lowercased, slash-unified).
 */
const normalizeTarget = (target: string): string => {
  const unified = target.trim().toLowerCase().replaceAll("\\", "/");
  if (unified.startsWith("*.")) {
    return unified;
  }
  const normalized = posix.normalize(unified);
  if (normalized.length > 1 && normalized.endsWith("/")) {
    return normalized.slice(0, -1);
  }
  return normalized;
};

/**
 * Check if candidate target matches an allowed/denied pattern.
 * Supports exact matching, directory prefix matching, and wildcard domain matching.
 */
const matchesPattern = (target: string, pattern: string): boolean => {
  if (hasPathTraversalSegment(target)) {
    return false;
  }

  const normTarget = normalizeTarget(target);
  const normPattern = normalizeTarget(pattern);

  if (normTarget === normPattern) {
    return true;
  }

  // Path prefix match (e.g. pattern="/opt/firmware" matches "/opt/firmware/squashfs-root/bin/busybox")
  if (normPattern === "/") {
    return normTarget.startsWith("/");
  }
  if (normTarget.startsWith(`${normPattern}/`)) {
    return true;
  }

  // Domain wildcard match (e.g. pattern="*.internal.corp" matches "api.internal.corp")
  if (normPattern.startsWith("*.")) {
    const domainSuffix = normPattern.slice(1); // ".internal.corp"
    if (normTarget.endsWith(domainSuffix) && !normTarget.includes("/")) {
      return true;
    }
  }

  return false;
};

/**
 * Validate that a target operation strictly falls within the declared authorization scope.
 * Fails closed if any ambiguity or path traversal exists or authorization has expired.
 */
export const validateTargetAuthorization = (
  target: string,
  scope: AuthorizationScope,
  now?: string,
): Result<void, AuthorizationError> => {
  const currentTimestamp = now ?? new Date().toISOString();

  // 0. Reject any path traversal attempt ('..') or NUL byte immediately (fail-closed)
  if (hasPathTraversalSegment(target)) {
    return err({
      code: "TARGET_NOT_AUTHORIZED",
      target,
      message: `Target '${target}' contains disallowed path traversal segments ('..') or NUL bytes.`,
    });
  }

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
        message: `Target '${target}' matches explicit denial pattern '${denied}'.`,
      });
    }
  }

  // 3. Check allowed targets
  const isAllowed = scope.allowed_targets.some((allowed) =>
    matchesPattern(target, allowed),
  );

  if (!isAllowed) {
    return err({
      code: "TARGET_NOT_AUTHORIZED",
      target,
      message: `Target '${target}' is outside the authorized engagement scope.`,
    });
  }

  return ok(undefined);
};

/**
 * Validate that active dynamic verification is explicitly authorized for the target.
 */
export const validateActiveVerificationAuthorization = (
  target: string,
  scope: AuthorizationScope,
  now?: string,
): Result<void, AuthorizationError> => {
  const baseAuth = validateTargetAuthorization(target, scope, now);
  if (!baseAuth.ok) {
    return baseAuth;
  }

  if (!scope.allow_active_verification) {
    return err({
      code: "ACTIVE_VERIFICATION_DISALLOWED",
      target,
      message: `Active verification is disabled in authorization scope '${scope.authorization_reference}'.`,
    });
  }

  return ok(undefined);
};

export const validateActiveVerificationPermission = (
  scope: AuthorizationScope,
): Result<void, AuthorizationError> => {
  if (!scope.allow_active_verification) {
    return err({
      code: "ACTIVE_VERIFICATION_DISALLOWED",
      target: scope.authorization_reference,
      message: `Active verification is disabled in authorization scope '${scope.authorization_reference}'.`,
    });
  }
  return ok(undefined);
};
