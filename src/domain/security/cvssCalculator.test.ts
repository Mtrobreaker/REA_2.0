import { describe, expect, it } from "vitest";
import {
  calculateCvss31BaseScore,
  calculateCvss31FromVector,
  cvssRoundUp,
  formatCvss31Vector,
  parseCvss31Vector,
} from "./cvssCalculator.js";

describe("CVSS v3.1 Calculator", () => {
  describe("Roundup Function (Section 7.4)", () => {
    it("matches official specification examples", () => {
      expect(cvssRoundUp(4.0)).toBe(4.0);
      expect(cvssRoundUp(4.01)).toBe(4.1);
      expect(cvssRoundUp(4.0001)).toBe(4.1);
      expect(cvssRoundUp(0.0)).toBe(0.0);
      expect(cvssRoundUp(9.8)).toBe(9.8);
      expect(cvssRoundUp(9.80001)).toBe(9.9);
    });
  });

  describe("Vector Parsing and Formatting", () => {
    it("round-trips standard vector strings", () => {
      const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      const parsed = parseCvss31Vector(vector);
      expect(parsed.ok).toBe(true);
      if (parsed.ok) {
        expect(parsed.value.attack_vector).toBe("N");
        expect(parsed.value.confidentiality_impact).toBe("H");
        expect(formatCvss31Vector(parsed.value)).toBe(vector);
      }
    });

    it("rejects invalid vectors", () => {
      expect(parseCvss31Vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").ok).toBe(false);
      expect(parseCvss31Vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").ok).toBe(false);
      expect(parseCvss31Vector("CVSS:3.1/AV:N/AC:L").ok).toBe(false);
      expect(parseCvss31Vector("not_a_vector").ok).toBe(false);
    });
  });

  describe("NIST / FIRST Reference Benchmark Vectors", () => {
    // 1. Log4Shell / Critical RCE (CVE-2021-44228)
    it("scores Log4Shell (9.8 Critical)", () => {
      const result = calculateCvss31FromVector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.score).toBe(9.8);
        expect(result.value.severity).toBe("CRITICAL");
        expect(result.value.exploitability_subscore).toBe(3.9);
        expect(result.value.impact_subscore).toBe(5.9);
      }
    });

    // 2. Maximum Possible Score (10.0 Critical with Scope Changed)
    it("scores Maximum Critical (10.0 Critical)", () => {
      const result = calculateCvss31FromVector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.score).toBe(10.0);
        expect(result.value.severity).toBe("CRITICAL");
      }
    });

    // 3. Reflected Cross-Site Scripting (6.1 Medium with Scope Changed)
    it("scores Reflected XSS (6.1 Medium)", () => {
      const result = calculateCvss31FromVector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.score).toBe(6.1);
        expect(result.value.severity).toBe("MEDIUM");
      }
    });

    // 4. Local Privilege Escalation (7.8 High)
    it("scores Local Privilege Escalation (7.8 High)", () => {
      const result = calculateCvss31FromVector(
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.score).toBe(7.8);
        expect(result.value.severity).toBe("HIGH");
      }
    });

    // 5. High-Privilege Network RCE (7.2 High)
    it("scores High-Privilege Network RCE (7.2 High)", () => {
      const result = calculateCvss31FromVector(
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.score).toBe(7.2);
        expect(result.value.severity).toBe("HIGH");
      }
    });

    // 6. Adjacent Network Exploit (8.8 High)
    it("scores Adjacent Network Exploit (8.8 High)", () => {
      const result = calculateCvss31FromVector(
        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.score).toBe(8.8);
        expect(result.value.severity).toBe("HIGH");
      }
    });

    // 7. Physical Attack Vector (6.8 Medium)
    it("scores Physical Attack Vector (6.8 Medium)", () => {
      const result = calculateCvss31FromVector(
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.score).toBe(6.8);
        expect(result.value.severity).toBe("MEDIUM");
      }
    });

    // 8. Low Severity Information Leak (3.1 Low)
    it("scores Low Severity Information Leak (3.1 Low)", () => {
      const result = calculateCvss31FromVector(
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.score).toBe(3.1);
        expect(result.value.severity).toBe("LOW");
      }
    });

    // 9. Zero Impact (0.0 Informational)
    it("scores Zero Impact (0.0 Informational)", () => {
      const result = calculateCvss31FromVector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.score).toBe(0.0);
        expect(result.value.severity).toBe("INFORMATIONAL");
      }
    });
  });
});

