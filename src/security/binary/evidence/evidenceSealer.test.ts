import { appendFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import { createEvidence } from "../../../domain/evidence.js";
import { EvidenceSealer } from "./EvidenceSealer.js";

const testAssessmentId = "asm_sealer_test_00000000000000000000000000000000000000000000000000001" as AssessmentId;
const testSecret = "sealer_test_secret_32_bytes_long_key_xyz";

describe("Phase 7E: Evidence Ledger Recording & Sealing Verification", () => {
  let tempDir: string;
  let journalPath: string;
  let sealer: EvidenceSealer;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-sealer-test-"));
    journalPath = join(tempDir, "audit-journal.jsonl");
    sealer = new EvidenceSealer({
      journalPath,
      secret: testSecret,
      assessmentId: testAssessmentId,
    });
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it("records stages, binary hashes, and adjudication transitions with HMAC chaining", () => {
    const stageRes = sealer.recordStage({
      stage: "cfg_reachability",
      provider: "ReaControlFlowEngine",
      version: "1.0.0",
      timestamp: Date.now(),
      details: { pathsCount: 2 },
    });
    expect(stageRes.ok).toBe(true);

    const binRes = sealer.recordBinary("gateway_daemon", "a".repeat(64), { arch: "ARM" });
    expect(binRes.ok).toBe(true);

    const adjRes = sealer.recordAdjudication(
      "fnd_001",
      "CANDIDATE",
      "VERIFIED",
      "L5 Witness verified",
      "d".repeat(64),
    );
    expect(adjRes.ok).toBe(true);

    // Verify HMAC journal integrity
    const verifyRes = sealer.getJournal().verifyIntegrity();
    expect(verifyRes.ok).toBe(true);
    if (!verifyRes.ok) return;

    expect(verifyRes.value.totalRecords).toBe(3);
  });

  it("seals investigation manifest and verifies tamper-evident HMAC signature", () => {
    sealer.recordBinary("router_fw", "b".repeat(64));
    sealer.recordAdjudication("fnd_002", "CANDIDATE", "MITIGATED", "Dominating guard confirmed");

    const sealRes = sealer.sealInvestigation();
    expect(sealRes.ok).toBe(true);
    if (!sealRes.ok) return;

    const manifest = sealRes.value;
    expect(manifest.assessmentId).toBe(testAssessmentId);
    expect(manifest.binariesEvaluated.length).toBe(1);
    expect(manifest.findingsAdjudicated.length).toBe(1);
    expect(manifest.manifestDigest.length).toBe(64);
    expect(manifest.manifestHmacSignature.length).toBe(64);

    // Verify manifest
    const checkRes = sealer.verifyManifest(manifest);
    expect(checkRes.ok).toBe(true);
  });
});

describe("Phase 7E: Fail-Closed Tamper Detection & Integrity Violation", () => {
  let tempDir: string;
  let journalPath: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-sealer-tamper-"));
    journalPath = join(tempDir, "audit-journal.jsonl");
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it("fails closed when audit journal entries are tampered with before sealing", () => {
    const sealer = new EvidenceSealer({
      journalPath,
      secret: testSecret,
      assessmentId: testAssessmentId,
    });

    sealer.recordBinary("firmware.bin", "c".repeat(64));
    sealer.recordAdjudication("fnd_003", "CANDIDATE", "VERIFIED", "Witness verified");

    // Tamper with journal file on disk by appending corrupted record
    appendFileSync(journalPath, JSON.stringify({ index: 999, action: "FORGED_ACTION", entry_hash: "bad_hash" }) + "\n");

    // Sealing MUST fail closed
    const sealRes = sealer.sealInvestigation();
    expect(sealRes.ok).toBe(false);
    if (sealRes.ok) return;

    expect(sealRes.error.code).toBe("INTEGRITY_COMPROMISED");
    expect(sealRes.error.message).toContain("integrity verification failed");
  });

  it("rejects manifest verification if manifest digest or signature is altered", () => {
    const sealer = new EvidenceSealer({
      journalPath,
      secret: testSecret,
      assessmentId: testAssessmentId,
    });

    sealer.recordBinary("target_bin", "e".repeat(64));
    const sealRes = sealer.sealInvestigation();
    expect(sealRes.ok).toBe(true);
    if (!sealRes.ok) return;

    const tamperedManifest = {
      ...sealRes.value,
      totalAuditEntries: 9999, // Tampered count
    };

    const verifyRes = sealer.verifyManifest(tamperedManifest);
    expect(verifyRes.ok).toBe(false);
    if (verifyRes.ok) return;

    expect(verifyRes.error.code).toBe("VERIFICATION_FAILED");
  });
});

describe("Phase 7E: Artifact Integrity, Evidence Ledger Binding & Tamper Detection", () => {
  let tempDir: string;
  let journalPath: string;
  let artifactPath: string;
  let sealer: EvidenceSealer;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-artifact-tamper-"));
    journalPath = join(tempDir, "audit-journal.jsonl");
    artifactPath = join(tempDir, "reachability_trace.json");
    appendFileSync(artifactPath, JSON.stringify({ trace: [0x1000, 0x1004, 0x1008] }));

    sealer = new EvidenceSealer({
      journalPath,
      secret: testSecret,
      assessmentId: testAssessmentId,
    });
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it("cryptographically binds registered artifacts and stores evidence records in EvidenceLedger", () => {
    const artRes = sealer.recordArtifact("trace_dump", artifactPath);
    expect(artRes.ok).toBe(true);

    const testEv = createEvidence(
      undefined,
      { id: "rea_tracer", name: "ReaTracer", version: "1.0.0" },
      {
        operation: "trace_path",
        parameters: {},
        result: { call_path: ["main", "system"] },
      },
    );

    const evRes = sealer.recordEvidence(testEv, artifactPath);
    expect(evRes.ok).toBe(true);

    // Verify EvidenceLedger stores the record
    const ledger = sealer.getLedger();
    const stored = ledger.get(testEv.evidence_id);
    expect(stored).toBeDefined();

    const sealRes = sealer.sealInvestigation();
    expect(sealRes.ok).toBe(true);
    if (!sealRes.ok) return;

    const manifest = sealRes.value;
    expect(manifest.artifacts.length).toBeGreaterThanOrEqual(1);
    const boundArt = manifest.artifacts.find((a) => a.name === "trace_dump");
    expect(boundArt).toBeDefined();
    expect(boundArt?.sha256.length).toBe(64);

    const verifyRes = sealer.verifyManifest(manifest);
    expect(verifyRes.ok).toBe(true);
  });

  it("fails closed when a registered artifact is modified on disk prior to verification", () => {
    sealer.recordArtifact("trace_dump", artifactPath);
    const sealRes = sealer.sealInvestigation();
    expect(sealRes.ok).toBe(true);
    if (!sealRes.ok) return;

    // Tamper with artifact on disk
    appendFileSync(artifactPath, "TAMPERED_BYTES");

    const verifyRes = sealer.verifyManifest(sealRes.value);
    expect(verifyRes.ok).toBe(false);
    if (verifyRes.ok) return;

    expect(verifyRes.error.code).toBe("VERIFICATION_FAILED");
    expect(verifyRes.error.message).toContain("content modified on disk");
  });

  it("fails closed when a registered artifact is deleted from disk prior to verification", () => {
    sealer.recordArtifact("trace_dump", artifactPath);
    const sealRes = sealer.sealInvestigation();
    expect(sealRes.ok).toBe(true);
    if (!sealRes.ok) return;

    // Delete artifact on disk
    rmSync(artifactPath, { force: true });

    const verifyRes = sealer.verifyManifest(sealRes.value);
    expect(verifyRes.ok).toBe(false);
    if (verifyRes.ok) return;

    expect(verifyRes.error.code).toBe("VERIFICATION_FAILED");
    expect(verifyRes.error.message).toContain("missing from disk");
  });

  it("rejects artifact registration and fails verification on wrong secret or expected hash", () => {
    const badReg = sealer.recordArtifact("bad_art", artifactPath, "0".repeat(64));
    expect(badReg.ok).toBe(false);
    if (!badReg.ok) {
      expect(badReg.error.code).toBe("INTEGRITY_COMPROMISED");
    }

    sealer.recordArtifact("valid_art", artifactPath);
    const sealRes = sealer.sealInvestigation();
    expect(sealRes.ok).toBe(true);
    if (!sealRes.ok) return;

    const wrongSealer = new EvidenceSealer({
      journalPath,
      secret: "completely_wrong_secret_key_32_bytes_!",
      assessmentId: testAssessmentId,
    });

    const verifyRes = wrongSealer.verifyManifest(sealRes.value);
    expect(verifyRes.ok).toBe(false);
    if (!verifyRes.ok) {
      expect(verifyRes.error.code).toBe("VERIFICATION_FAILED");
    }
  });
});
