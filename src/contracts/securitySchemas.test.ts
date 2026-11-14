import { describe, expect, it } from "vitest";
import {
  calculateCvssSchema,
  deepFirmwareInspectionSchema,
  deviceInspectionSchema,
  embeddedOsAuditSchema,
  generateSecurityReportSchema,
  getSecurityAssessmentStateSchema,
  hardwareRtlInspectionSchema,
  recordSecurityFindingSchema,
  registerSecurityAssetSchema,
  runMultiAgentAssessmentSchema,
  scanSecurityTargetSchema,
  startSecurityAssessmentSchema,
  verifySecurityFindingSchema,
} from "./securitySchemas.js";

describe("Security Contracts & Schemas", () => {
  it("validates StartSecurityAssessment input schema", () => {
    const valid = {
      title: "Quarterly Penetration Test",
      allowed_targets: ["/app/source", "10.0.0.1/24"],
      denied_targets: ["10.0.0.254"],
      authorized_by: "Security Operations",
      authorization_reference: "SEC-TICKET-4412",
      valid_until: "2026-12-31T23:59:59.000Z",
      allow_active_verification: true,
      target_technologies: ["nodejs", "docker"],
      compliance_frameworks: ["SOC2", "OWASP_TOP_10"],
      depth: "exhaustive",
    };

    const parsed = startSecurityAssessmentSchema.parse(valid);
    expect(parsed.title).toBe("Quarterly Penetration Test");
    expect(parsed.depth).toBe("exhaustive");

    expect(() =>
      startSecurityAssessmentSchema.parse({
        ...valid,
        allowed_targets: [], // must have at least 1
      }),
    ).toThrow();
  });

  it("validates GetSecurityAssessmentState schema", () => {
    const validId =
      "asm_1111111111111111111111111111111111111111111111111111111111111111";
    expect(
      getSecurityAssessmentStateSchema.parse({ assessment_id: validId }),
    ).toEqual({ assessment_id: validId });

    expect(() =>
      getSecurityAssessmentStateSchema.parse({ assessment_id: "invalid_id" }),
    ).toThrow();
  });

  it("validates CalculateCvss schema", () => {
    const validVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    expect(
      calculateCvssSchema.parse({ vector_string: validVector }),
    ).toEqual({ vector_string: validVector });

    expect(() =>
      calculateCvssSchema.parse({ vector_string: "CVSS:2.0/..." }),
    ).toThrow();
  });

  it("validates GenerateSecurityReport schema", () => {
    const validId =
      "asm_1111111111111111111111111111111111111111111111111111111111111111";
    const reportOptions = generateSecurityReportSchema.parse({
      assessment_id: validId,
      format: "sarif",
      include_remediation_diffs: true,
    });

    expect(reportOptions.format).toBe("sarif");
    expect(reportOptions.include_remediation_diffs).toBe(true);

    expect(() =>
      generateSecurityReportSchema.parse({
        assessment_id: validId,
        format: "unsupported_format",
      }),
    ).toThrow();
  });

  it("validates new Phase 4 and Phase 5 schemas", () => {
    // 1. Scan target
    const scanParsed = scanSecurityTargetSchema.parse({
      path: "/srv/code",
    });
    expect(scanParsed.path).toBe("/srv/code");
    expect(scanParsed.authorized_by).toBe("mcp-caller");

    // 2. Deep firmware inspection
    const fwParsed = deepFirmwareInspectionSchema.parse({
      path: "/opt/firmware.bin",
    });
    expect(fwParsed.path).toBe("/opt/firmware.bin");

    // 3. Device interface & OS inspection
    const devParsed = deviceInspectionSchema.parse({
      target: "/dev/ttyUSB0",
      interface_type: "UART_SERIAL",
    });
    expect(devParsed.target).toBe("/dev/ttyUSB0");

    const osParsed = embeddedOsAuditSchema.parse({
      path: "/opt/rootfs",
    });
    expect(osParsed.path).toBe("/opt/rootfs");

    // 4. Multi-agent assessment
    const maParsed = runMultiAgentAssessmentSchema.parse({
      target_path: "/workspace/repo",
      title: "Full SOC Audit",
    });
    expect(maParsed.title).toBe("Full SOC Audit");
    expect(maParsed.depth).toBe("standard");
  });
});

