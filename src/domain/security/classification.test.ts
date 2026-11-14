import { describe, expect, it } from "vitest";
import {
  capecIdSchema,
  cveIdSchema,
  cweIdSchema,
  isCapecId,
  isCveId,
  isCweId,
  isMitreAttackTechniqueId,
  mitreAttackTechniqueSchema,
  owaspWeb2021CategorySchema,
  securityClassificationSchema,
  securitySeverityLevelSchema,
} from "./classification.js";

describe("Security Classification Domain", () => {
  describe("CVE Identifiers", () => {
    it("accepts valid CVE identifiers", () => {
      const valid = ["CVE-2024-1234", "CVE-2021-44228", "CVE-1999-0001", "CVE-2026-9999999"];
      for (const id of valid) {
        expect(isCveId(id)).toBe(true);
        expect(cveIdSchema.parse(id)).toBe(id);
      }
    });

    it("rejects malformed CVE identifiers", () => {
      const invalid = ["cve-2024-1234", "CVE-24-1234", "CVE-2024-1", "NOT-A-CVE", "CVE-ABCD-1234"];
      for (const id of invalid) {
        expect(isCveId(id)).toBe(false);
        expect(() => cveIdSchema.parse(id)).toThrow();
      }
    });
  });

  describe("CWE Identifiers", () => {
    it("accepts valid CWE identifiers", () => {
      const valid = ["CWE-79", "CWE-89", "CWE-119", "CWE-12345"];
      for (const id of valid) {
        expect(isCweId(id)).toBe(true);
        expect(cweIdSchema.parse(id)).toBe(id);
      }
    });

    it("rejects malformed CWE identifiers", () => {
      const invalid = ["cwe-79", "CWE-", "CWE", "CWE-abc", "79"];
      for (const id of invalid) {
        expect(isCweId(id)).toBe(false);
        expect(() => cweIdSchema.parse(id)).toThrow();
      }
    });
  });

  describe("CAPEC Identifiers", () => {
    it("accepts valid CAPEC identifiers", () => {
      const valid = ["CAPEC-100", "CAPEC-66", "CAPEC-1"];
      for (const id of valid) {
        expect(isCapecId(id)).toBe(true);
        expect(capecIdSchema.parse(id)).toBe(id);
      }
    });

    it("rejects malformed CAPEC identifiers", () => {
      expect(isCapecId("capec-100")).toBe(false);
      expect(isCapecId("CAPEC-")).toBe(false);
    });
  });

  describe("MITRE ATT&CK Techniques", () => {
    it("accepts valid techniques and sub-techniques", () => {
      const valid = ["T1059", "T1059.001", "T1078", "T1566.002"];
      for (const id of valid) {
        expect(isMitreAttackTechniqueId(id)).toBe(true);
        expect(mitreAttackTechniqueSchema.parse(id)).toBe(id);
      }
    });

    it("rejects malformed techniques", () => {
      const invalid = ["T105", "1059", "T1059.01", "T1059.1", "T-1059"];
      for (const id of invalid) {
        expect(isMitreAttackTechniqueId(id)).toBe(false);
        expect(() => mitreAttackTechniqueSchema.parse(id)).toThrow();
      }
    });
  });

  describe("OWASP & Severity Taxonomies", () => {
    it("validates OWASP Top 10 Web categories", () => {
      expect(
        owaspWeb2021CategorySchema.parse("A01:2021-Broken Access Control"),
      ).toBe("A01:2021-Broken Access Control");
      expect(() =>
        owaspWeb2021CategorySchema.parse("A99:Invalid Category"),
      ).toThrow();
    });

    it("validates standard severity levels", () => {
      expect(securitySeverityLevelSchema.parse("CRITICAL")).toBe("CRITICAL");
      expect(securitySeverityLevelSchema.parse("HIGH")).toBe("HIGH");
      expect(securitySeverityLevelSchema.parse("MEDIUM")).toBe("MEDIUM");
      expect(securitySeverityLevelSchema.parse("LOW")).toBe("LOW");
      expect(securitySeverityLevelSchema.parse("INFORMATIONAL")).toBe("INFORMATIONAL");
      expect(() => securitySeverityLevelSchema.parse("URGENT")).toThrow();
    });

    it("parses an aggregated SecurityClassification object", () => {
      const classification = securityClassificationSchema.parse({
        cve: ["CVE-2024-1234"],
        cwe: ["CWE-89"],
        capec: ["CAPEC-66"],
        mitre_attack: ["T1059.001"],
        owasp: ["A03:2021-Injection"],
      });
      expect(classification.cve).toEqual(["CVE-2024-1234"]);
      expect(classification.cwe).toEqual(["CWE-89"]);
      expect(classification.mitre_attack).toEqual(["T1059.001"]);
    });
  });
});

