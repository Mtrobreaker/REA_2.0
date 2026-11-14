import { createHash, createHmac } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import canonicalize from "canonicalize";
import { err, ok, type Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { Evidence } from "../../../domain/evidence.js";
import { EvidenceLedger } from "../../../application/investigation/EvidenceLedger.js";
import {
  appendAuditRecord,
  verifyAuditJournal,
  GENESIS_HASH,
  type AuditRecord,
} from "../../packboard/HmacAuditJournal.js";
import type {
  AnalysisStageRecord,
  EvidenceArtifactRecord,
  SealedInvestigationManifest,
  SealingError,
} from "./types.js";

export class HmacAuditJournalWrapper {
  constructor(
    private readonly journalPath: string,
    private readonly secret: string,
  ) {}

  public appendEntry(
    action: string,
    leadId: string,
    assessmentId: string,
    payload: unknown,
  ): Result<AuditRecord, Error> {
    return appendAuditRecord(
      this.journalPath,
      this.secret,
      action,
      leadId,
      assessmentId,
      payload,
    );
  }

  public verifyIntegrity(): Result<
    { totalRecords: number; finalHash: string },
    { message: string; details?: unknown }
  > {
    const res = verifyAuditJournal(this.journalPath, this.secret);
    if (!res.ok) {
      return err({
        message: `Audit chain corrupted at line ${res.error.line}: ${res.error.reason}`,
        details: res.error,
      });
    }

    if (!existsSync(this.journalPath)) {
      return ok({ totalRecords: 0, finalHash: GENESIS_HASH });
    }

    const content = readFileSync(this.journalPath, "utf8").trim();
    if (content.length === 0) {
      return ok({ totalRecords: 0, finalHash: GENESIS_HASH });
    }

    const lines = content.split("\n").filter((l) => l.trim().length > 0);
    const lastLine = lines[lines.length - 1];
    let finalHash = GENESIS_HASH;
    if (lastLine) {
      try {
        const parsed = JSON.parse(lastLine) as AuditRecord;
        finalHash = parsed.entry_hash;
      } catch {
        return err({ message: "Failed to parse last journal entry" });
      }
    }

    return ok({ totalRecords: lines.length, finalHash });
  }

  public getJournalPath(): string {
    return this.journalPath;
  }
}

export interface EvidenceSealerOptions {
  readonly journalPath: string;
  readonly secret: string;
  readonly assessmentId: AssessmentId;
  readonly ledger?: EvidenceLedger;
}

export class EvidenceSealer {
  private readonly journal: HmacAuditJournalWrapper;
  private readonly ledger: EvidenceLedger;
  private readonly secret: string;
  private readonly assessmentId: AssessmentId;
  private readonly binaryRecords: Map<string, string> = new Map();
  private readonly adjudicationRecords: Map<string, { state: string; witnessDigest?: string }> = new Map();
  private readonly artifactRecords: Map<string, { path: string; expectedSha256?: string }> = new Map();

  constructor(options: EvidenceSealerOptions) {
    this.secret = options.secret;
    this.assessmentId = options.assessmentId;
    this.journal = new HmacAuditJournalWrapper(
      options.journalPath,
      options.secret,
    );
    this.ledger = options.ledger ?? new EvidenceLedger();
  }

  public getLedger(): EvidenceLedger {
    return this.ledger;
  }

  public getJournal(): HmacAuditJournalWrapper {
    return this.journal;
  }

  /**
   * Record an investigation stage execution and provider provenance into the HMAC journal.
   */
  public recordStage(stage: AnalysisStageRecord): Result<void, SealingError> {
    const res = this.journal.appendEntry(
      "ANALYSIS_STAGE",
      `stage_${stage.stage}`,
      this.assessmentId,
      stage,
    );

    if (!res.ok) {
      return err({
        code: "STORAGE_ERROR",
        message: `Failed to record analysis stage: ${res.error.message}`,
        details: res.error,
      });
    }

    return ok(undefined);
  }

  /**
   * Record binary SHA-256 integrity and metadata.
   */
  public recordBinary(name: string, sha256: string, metadata: Record<string, unknown> = {}): Result<void, SealingError> {
    this.binaryRecords.set(name, sha256);
    const res = this.journal.appendEntry(
      "BINARY_REGISTERED",
      `bin_${name}`,
      this.assessmentId,
      { name, sha256, metadata },
    );

    if (!res.ok) {
      return err({
        code: "STORAGE_ERROR",
        message: `Failed to record binary integrity: ${res.error.message}`,
        details: res.error,
      });
    }

    return ok(undefined);
  }

  /**
   * Record an adjudication transition for a finding.
   */
  public recordAdjudication(
    findingId: string,
    fromState: string,
    toState: string,
    reasoning: string,
    witnessDigest?: string,
  ): Result<void, SealingError> {
    this.adjudicationRecords.set(findingId, {
      state: toState,
      ...(witnessDigest !== undefined ? { witnessDigest } : {}),
    });
    const res = this.journal.appendEntry(
      "ADJUDICATION_TRANSITION",
      findingId,
      this.assessmentId,
      {
        findingId,
        fromState,
        toState,
        reasoning,
        ...(witnessDigest !== undefined ? { witnessDigest } : {}),
      },
    );

    if (!res.ok) {
      return err({
        code: "STORAGE_ERROR",
        message: `Failed to record adjudication transition: ${res.error.message}`,
        details: res.error,
      });
    }

    return ok(undefined);
  }

  /**
   * Register a physical evidence artifact and verify its existence and optional expected hash.
   */
  public recordArtifact(name: string, filePath: string, expectedSha256?: string): Result<void, SealingError> {
    if (!existsSync(filePath)) {
      return err({
        code: "STORAGE_ERROR",
        message: `Artifact file '${name}' does not exist at path: ${filePath}`,
      });
    }

    try {
      const fileBytes = readFileSync(filePath);
      const computedSha256 = createHash("sha256").update(fileBytes).digest("hex");

      if (expectedSha256 !== undefined && expectedSha256 !== computedSha256) {
        return err({
          code: "INTEGRITY_COMPROMISED",
          message: `Artifact '${name}' hash mismatch: expected ${expectedSha256}, got ${computedSha256}`,
        });
      }

      this.artifactRecords.set(name, {
        path: filePath,
        ...(expectedSha256 !== undefined ? { expectedSha256 } : {}),
      });

      const res = this.journal.appendEntry(
        "ARTIFACT_REGISTERED",
        `art_${name}`,
        this.assessmentId,
        { name, path: filePath, sha256: computedSha256, size: fileBytes.length },
      );

      if (!res.ok) {
        return err({
          code: "STORAGE_ERROR",
          message: `Failed to record artifact in journal: ${res.error.message}`,
          details: res.error,
        });
      }

      return ok(undefined);
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        message: `Failed to read artifact '${name}' from disk: ${cause instanceof Error ? cause.message : String(cause)}`,
        details: cause,
      });
    }
  }

  /**
   * Record domain evidence in the EvidenceLedger and optionally bind its file artifact.
   */
  public recordEvidence(evidence: Evidence, artifactPath?: string): Result<void, SealingError> {
    const ledgerRes = this.ledger.record(evidence);
    if (!ledgerRes.ok) {
      return err({
        code: "INTEGRITY_COMPROMISED",
        message: `Failed to record evidence in ledger: ${ledgerRes.error.message}`,
        details: ledgerRes.error,
      });
    }

    if (artifactPath) {
      const artRes = this.recordArtifact(evidence.evidence_id, artifactPath);
      if (!artRes.ok) {
        return artRes;
      }
    }

    const res = this.journal.appendEntry(
      "EVIDENCE_RECORDED",
      evidence.evidence_id,
      this.assessmentId,
      { evidenceId: evidence.evidence_id, operation: evidence.operation, predicateType: evidence.predicate_type, artifactPath },
    );

    if (!res.ok) {
      return err({
        code: "STORAGE_ERROR",
        message: `Failed to record evidence entry in journal: ${res.error.message}`,
        details: res.error,
      });
    }

    return ok(undefined);
  }

  /**
   * Seal the investigation: Verifies cryptographic HMAC integrity of the journal,
   * cryptographically binds registered artifacts via SHA-256 hashes, fails closed if
   * any file is missing or corrupted, and produces a tamper-evident signed manifest.
   */
  public sealInvestigation(): Result<SealedInvestigationManifest, SealingError> {
    // 1. Mandatory Integrity Gate: Verify entire HMAC hash chain
    const verifyRes = this.journal.verifyIntegrity();
    if (!verifyRes.ok) {
      return err({
        code: "INTEGRITY_COMPROMISED",
        message: `Fail closed: Audit journal integrity verification failed: ${verifyRes.error.message}`,
        details: verifyRes.error,
      });
    }

    const { totalRecords, finalHash } = verifyRes.value;

    const binariesEvaluated = Array.from(this.binaryRecords.entries()).map(([name, sha256]) => ({
      name,
      sha256,
    }));

    const findingsAdjudicated = Array.from(this.adjudicationRecords.entries()).map(
      ([findingId, { state, witnessDigest }]) => ({
        findingId,
        finalState: state,
        ...(witnessDigest ? { witnessDigest } : {}),
      }),
    );

    // 2. Cryptographically bind all registered physical artifacts
    const artifacts: EvidenceArtifactRecord[] = [];
    for (const [name, rec] of this.artifactRecords.entries()) {
      if (!existsSync(rec.path)) {
        return err({
          code: "INTEGRITY_COMPROMISED",
          message: `Fail closed: Registered artifact '${name}' is missing from disk at ${rec.path}`,
        });
      }

      try {
        const fileBytes = readFileSync(rec.path);
        const computedSha256 = createHash("sha256").update(fileBytes).digest("hex");
        if (rec.expectedSha256 !== undefined && rec.expectedSha256 !== computedSha256) {
          return err({
            code: "INTEGRITY_COMPROMISED",
            message: `Fail closed: Artifact '${name}' was modified before sealing: expected ${rec.expectedSha256}, got ${computedSha256}`,
          });
        }
        artifacts.push({
          name,
          path: rec.path,
          sha256: computedSha256,
          size: fileBytes.length,
        });
      } catch (cause) {
        return err({
          code: "INTEGRITY_COMPROMISED",
          message: `Fail closed: Failed to hash artifact '${name}': ${cause instanceof Error ? cause.message : String(cause)}`,
          details: cause,
        });
      }
    }

    const sealedAt = new Date().toISOString();

    const manifestBody = {
      assessmentId: this.assessmentId,
      totalAuditEntries: totalRecords,
      finalEntryHash: finalHash,
      binariesEvaluated,
      findingsAdjudicated,
      artifacts,
      sealedAt,
    };

    const canonicalJson = canonicalize(manifestBody) ?? JSON.stringify(manifestBody);
    const manifestDigest = createHash("sha256").update(canonicalJson).digest("hex");
    const manifestHmacSignature = createHmac("sha256", this.secret).update(manifestDigest).digest("hex");

    // Log the seal event itself into the journal
    this.journal.appendEntry("INVESTIGATION_SEALED", "manifest_seal", this.assessmentId, {
      manifestDigest,
      manifestHmacSignature,
      sealedAt,
    });

    return ok({
      assessmentId: this.assessmentId,
      totalAuditEntries: totalRecords,
      genesisHash: "0".repeat(64),
      finalEntryHash: finalHash,
      binariesEvaluated,
      findingsAdjudicated,
      artifacts,
      manifestDigest,
      manifestHmacSignature,
      sealedAt,
    });
  }

  /**
   * Verify an existing sealed investigation manifest against secret, journal, and artifacts on disk.
   */
  public verifyManifest(
    manifest: SealedInvestigationManifest,
    options?: { verifyArtifactsOnDisk?: boolean },
  ): Result<boolean, SealingError> {
    const manifestBody = {
      assessmentId: manifest.assessmentId,
      totalAuditEntries: manifest.totalAuditEntries,
      finalEntryHash: manifest.finalEntryHash,
      binariesEvaluated: manifest.binariesEvaluated,
      findingsAdjudicated: manifest.findingsAdjudicated,
      artifacts: manifest.artifacts,
      sealedAt: manifest.sealedAt,
    };

    const canonicalJson = canonicalize(manifestBody) ?? JSON.stringify(manifestBody);
    const computedDigest = createHash("sha256").update(canonicalJson).digest("hex");

    if (computedDigest !== manifest.manifestDigest) {
      return err({
        code: "VERIFICATION_FAILED",
        message: "Manifest content digest does not match computed digest (tampering detected)",
      });
    }

    const expectedSignature = createHmac("sha256", this.secret).update(computedDigest).digest("hex");
    if (expectedSignature !== manifest.manifestHmacSignature) {
      return err({
        code: "VERIFICATION_FAILED",
        message: "Manifest HMAC signature verification failed (invalid secret or signature)",
      });
    }

    // Verify physical evidence artifacts on disk
    if (options?.verifyArtifactsOnDisk !== false && manifest.artifacts) {
      for (const art of manifest.artifacts) {
        if (!existsSync(art.path)) {
          return err({
            code: "VERIFICATION_FAILED",
            message: `Artifact '${art.name}' missing from disk at ${art.path}`,
          });
        }
        try {
          const fileBytes = readFileSync(art.path);
          const computed = createHash("sha256").update(fileBytes).digest("hex");
          if (computed !== art.sha256) {
            return err({
              code: "VERIFICATION_FAILED",
              message: `Artifact '${art.name}' content modified on disk (expected ${art.sha256}, got ${computed})`,
            });
          }
        } catch (cause) {
          return err({
            code: "VERIFICATION_FAILED",
            message: `Failed to read artifact '${art.name}' on disk: ${cause instanceof Error ? cause.message : String(cause)}`,
            details: cause,
          });
        }
      }
    }

    return ok(true);
  }
}
