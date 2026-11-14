import { describe, expect, it } from "vitest";
import { computeAssetId } from "./asset.js";
import {
  computeFindingId,
  isFindingId,
  securityFindingSchema,
  type SecurityFinding,
} from "./finding.js";

describe("Security Finding Domain", () => {
  const assetId = computeAssetId({
    name: "upnpd",
    type: "compiled_binary",
  });

  const baseFindingInput = {
    asset_id: assetId,
    name: "Stack Buffer Overflow in SOAP Header Parsing",
    location: {
      file: "src/soap.c",
      function: "parse_soap_action",
      line: 142,
      column: 12,
      end_line: 150,
      module: "upnp_core",
      component: "soap_handler",
      address: "0x00401120",
      offset: 4384,
    },
    root_cause:
      "Unbounded strcpy() copies HTTP SOAPAction header into 256-byte stack buffer.",
  };

  it("computes deterministic finding IDs", () => {
    const id1 = computeFindingId(baseFindingInput);
    const id2 = computeFindingId(baseFindingInput);

    expect(id1).toBe(id2);
    expect(isFindingId(id1)).toBe(true);
    expect(id1).toMatch(/^fnd_[a-f0-9]{64}$/u);
  });

  it("produces distinct finding IDs when location or root cause varies", () => {
    const id1 = computeFindingId(baseFindingInput);
    const id2 = computeFindingId({
      ...baseFindingInput,
      location: {
        ...baseFindingInput.location,
        line: 199,
      },
    });

    expect(id1).not.toBe(id2);
  });

  it("validates full 15-field SecurityFinding schema", () => {
    const findingId = computeFindingId(baseFindingInput);
    const finding: SecurityFinding = {
      id: findingId,
      name: baseFindingInput.name,
      affected_asset: {
        id: assetId,
        name: "upnpd",
        type: "compiled_binary",
      },
      location: baseFindingInput.location,
      technical_description:
        "The UPnP daemon handles incoming SOAP requests without verifying the Content-Length or string length of the SOAPAction header, resulting in stack memory corruption.",
      root_cause: baseFindingInput.root_cause,
      evidence_ids: [
        "ev_8f9a2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6",
      ],
      reproduction_steps: [
        "Send HTTP POST to TCP port 49152 with a 512-byte SOAPAction header.",
        "Observe process crash with SIGSEGV at return instruction.",
      ],
      impact: {
        description: "Remote code execution with root privileges.",
        attack_prerequisites: ["Direct network line of sight to port 49152"],
        exploitability: "PROVEN",
      },
      severity: {
        level: "CRITICAL",
        cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score: 9.8,
        justification: "Unauthenticated remote code execution on default port.",
      },
      confidence: {
        level: "CONFIRMED",
        false_positive_considerations: [
          "Compiler stack canaries are absent in binary.",
        ],
        verification_method: "Dynamic test in QEMU sandbox.",
      },
      remediation: {
        description: "Replace strcpy() with strlcpy() and enforce buffer bounds.",
        code_diff: "--- soap.c\n+++ soap.c\n@@ -142,1 +142,1 @@\n- strcpy(buf, header);\n+ strlcpy(buf, header, sizeof(buf));",
        config_example: null,
        priority: "IMMEDIATE",
        validation_procedure: "Run test case with 512-byte payload; verify 400 Bad Request returned.",
      },
      classification: {
        cve: [],
        cwe: [],
        capec: [],
        mitre_attack: [],
        owasp: ["A03:2021-Injection"],
      },
      verification_status: "VERIFIED",
      provenance: {
        discovered_by: "BinaryAnalysisAgent",
        discovered_at: "2026-11-05T12:00:00.000Z",
        verified_by: "VulnerabilityVerificationAgent",
        verified_at: "2026-11-05T12:15:00.000Z",
      },
    };

    const parsed = securityFindingSchema.parse(finding);
    expect(parsed.id).toBe(findingId);
    expect(parsed.severity.level).toBe("CRITICAL");
    expect(parsed.verification_status).toBe("VERIFIED");
  });
});

