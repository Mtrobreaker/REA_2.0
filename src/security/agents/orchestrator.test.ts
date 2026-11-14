import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createAssessmentState } from "../../domain/security/assessment.js";
import { ChiefSecurityOrchestrator } from "./orchestrator.js";

describe("ChiefSecurityOrchestrator & Multi-Agent Team", () => {
  let tempDir: string;
  let orchestrator: ChiefSecurityOrchestrator;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-multiagent-test-"));
    orchestrator = new ChiefSecurityOrchestrator();
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("orchestrates multi-agent assessment across RTL, firmware, binary, and source assets", async () => {
    // 1. Create mock assets inside authorized temp dir
    // Hardware device interface asset
    const hwFile = join(tempDir, "serial_console.tty");
    await writeFile(
      hwFile,
      "Linux (none) 5.10.0-8-armmp\nBusyBox v1.33.1 (ash)\n# ",
      "utf8",
    );

    // Firmware image with embedded key
    const fwFile = join(tempDir, "router_firmware.bin");
    const fakeKey =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0mockkey...\n-----END RSA PRIVATE KEY-----\n";
    await writeFile(fwFile, Buffer.from(fakeKey, "latin1"));

    // Compiled binary with dangerous symbol
    const binFile = join(tempDir, "auth_daemon.elf");
    const fakeElf = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46]), // ELF magic
      Buffer.from("\0gets\0strcpy\0system\0", "latin1"),
    ]);
    await writeFile(binFile, fakeElf);

    // 2. Set up initial assessment state
    const initialState = createAssessmentState({
      objective: {
        title: "Full-Stack Hardware/Firmware/Binary Audit",
        target_technologies: ["Hardware Interfaces", "Embedded Linux", "C"],
        compliance_frameworks: ["NIST SP 800-193", "OWASP Top 10"],
        focus_areas: ["Silicon Root-of-Trust", "Firmware Secrets", "Native Mitigations"],
        depth: "exhaustive",
      },
      scope: {
        allowed_targets: [tempDir],
        denied_targets: [],
        authorized_by: "Chief Information Security Officer",
        authorization_reference: "AUTH-CYBER-2026-999",
        valid_until: "2026-12-31T23:59:59Z",
        allow_active_verification: false,
      },
    });

    // 3. Execute orchestration pipeline
    const result = await orchestrator.runAssessment(initialState);

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const { assessment, message_history, agent_logs } = result.value;

    // Verify Phase completed
    expect(assessment.phase).toBe("completed");
    expect(assessment.completed_at).not.toBeNull();

    // Verify Reconnaissance identified assets
    expect(assessment.assets.length).toBeGreaterThanOrEqual(4); // directory + rtl + bin + fw
    expect(agent_logs.reconnaissance.length).toBeGreaterThan(0);

    // Verify Hardware Security Agent discovered device interface weaknesses
    const hwFindings = assessment.findings.filter(
      (f) => f.provenance.discovered_by === "device-interface-agent" || f.provenance.discovered_by === "hardware-security-agent",
    );
    expect(hwFindings.length).toBeGreaterThanOrEqual(1);
    expect(
      hwFindings.some((f) => f.name.includes("Unauthenticated Root Shell on UART Serial Console")),
    ).toBe(true);

    // Verify Firmware Security Agent discovered embedded key
    const fwFindings = assessment.findings.filter(
      (f) => f.provenance.discovered_by === "firmware-security-agent",
    );
    expect(fwFindings.length).toBeGreaterThanOrEqual(1);
    expect(fwFindings[0]!.name).toContain("Embedded Cryptographic RSA Private Key");
    expect(fwFindings[0]!.severity.level).toBe("CRITICAL");

    // Verify Binary Analysis Agent discovered dangerous C symbols
    const binFindings = assessment.findings.filter(
      (f) => f.provenance.discovered_by === "binary-analysis-agent",
    );
    expect(binFindings.length).toBeGreaterThanOrEqual(2); // gets, strcpy, system
    expect(binFindings.some((f) => f.name.includes("gets"))).toBe(true);

    // Verify Verification Agent validated findings
    for (const f of assessment.findings) {
      expect(["VERIFIED", "FALSE_POSITIVE", "UNVERIFIED", "INCONCLUSIVE", "CANDIDATE"]).toContain(
        f.verification_status,
      );
    }

    // Verify Remediation Agent assigned proper priorities
    const critFindings = assessment.findings.filter((f) => f.severity.level === "CRITICAL");
    for (const cf of critFindings) {
      expect(cf.remediation.priority).toBe("IMMEDIATE");
    }

    // Verify Message History
    expect(message_history.length).toBeGreaterThan(5);
    for (const msg of message_history) {
      expect(msg.message_id).toMatch(/^msg_[a-f0-9]{64}$/);
      expect(msg.timestamp).toBeDefined();
    }

    // Verify Attack Paths synthesized
    expect(result.value.attack_paths.length).toBeGreaterThanOrEqual(1);
    expect(result.value.attack_paths[0]!.title).toContain("Composite Exploit Chain");
  });

  it("fails closed when target path violates authorization scope", async () => {
    const initialState = createAssessmentState({
      objective: {
        title: "Unauthorized Assessment Attempt",
        target_technologies: [],
        compliance_frameworks: [],
        focus_areas: [],
        depth: "surface",
      },
      scope: {
        allowed_targets: [tempDir],
        denied_targets: [tempDir], // explicitly denied
        authorized_by: "Operator",
        authorization_reference: "DENIED-TEST",
        valid_until: "2026-12-31T23:59:59Z",
        allow_active_verification: false,
      },
    });

    const result = await orchestrator.runAssessment(initialState);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.failing_agent).toBe("reconnaissance");
      expect(result.error.message).toContain("failed authorization check");
      expect((result.error.details as any)?.code).toBe("TARGET_UNAUTHORIZED");
    }
  });

  it("respects abort signal and halts gracefully", async () => {
    const initialState = createAssessmentState({
      objective: {
        title: "Canceled Assessment",
        target_technologies: [],
        compliance_frameworks: [],
        focus_areas: [],
        depth: "standard",
      },
      scope: {
        allowed_targets: [tempDir],
        denied_targets: [],
        authorized_by: "Operator",
        authorization_reference: "CANCEL-TEST",
        valid_until: "2026-12-31T23:59:59Z",
        allow_active_verification: false,
      },
    });

    const controller = new AbortController();
    controller.abort(); // already aborted

    const result = await orchestrator.runAssessment(initialState, controller.signal);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.message).toContain("aborted by operator cancellation signal");
    }
  });
});
