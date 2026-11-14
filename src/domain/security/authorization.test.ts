import { describe, expect, it } from "vitest";
import type { AuthorizationScope } from "./assessment.js";
import {
  validateActiveVerificationPermission,
  validateTargetAuthorization,
} from "./authorization.js";

describe("Security Authorization & Scope Gate", () => {
  const baseScope: AuthorizationScope = {
    allowed_targets: [
      "/var/firmware/target_root",
      "192.168.1.1",
      "*.internal.corp",
      "https://git.internal.corp/repo.git",
    ],
    denied_targets: [
      "/var/firmware/target_root/etc/shadow",
      "192.168.1.254",
      "prod.internal.corp",
    ],
    authorized_by: "CISO Office",
    authorization_reference: "AUTH-2026-X9",
    valid_until: "2026-12-31T23:59:59.000Z",
    allow_active_verification: true,
  };

  it("permits targets strictly within allowed scope", () => {
    const validTargets = [
      "/var/firmware/target_root/bin/busybox",
      "192.168.1.1",
      "dev.internal.corp",
      "api.internal.corp",
      "https://git.internal.corp/repo.git",
    ];

    for (const target of validTargets) {
      const result = validateTargetAuthorization(
        target,
        baseScope,
        "2026-11-05T12:00:00.000Z",
      );
      expect(result.ok).toBe(true);
    }
  });

  it("rejects targets outside of allowed scope", () => {
    const unauthorizedTargets = [
      "/etc/passwd",
      "8.8.8.8",
      "external.com",
      "https://github.com/unauthorized/repo",
    ];

    for (const target of unauthorizedTargets) {
      const result = validateTargetAuthorization(
        target,
        baseScope,
        "2026-11-05T12:00:00.000Z",
      );
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("TARGET_NOT_AUTHORIZED");
      }
    }
  });

  it("enforces explicit deny overrides", () => {
    const denied = [
      "/var/firmware/target_root/etc/shadow",
      "192.168.1.254",
      "prod.internal.corp",
    ];

    for (const target of denied) {
      const result = validateTargetAuthorization(
        target,
        baseScope,
        "2026-11-05T12:00:00.000Z",
      );
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("TARGET_EXPLICITLY_DENIED");
      }
    }
  });

  it("rejects expired authorization scopes", () => {
    const result = validateTargetAuthorization(
      "192.168.1.1",
      baseScope,
      "2027-01-01T00:00:00.000Z", // Past 2026-12-31
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("AUTHORIZATION_EXPIRED");
    }
  });

  it("checks active verification permission", () => {
    expect(validateActiveVerificationPermission(baseScope).ok).toBe(true);

    const restrictedScope: AuthorizationScope = {
      ...baseScope,
      allow_active_verification: false,
    };
    const res = validateActiveVerificationPermission(restrictedScope);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error.code).toBe("ACTIVE_VERIFICATION_DISALLOWED");
    }
  });
});
