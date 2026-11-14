import { readFile, rm, mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { BinaryWorkerSupervisor } from "../../../src/security/binary/supervisor/BinaryWorkerSupervisor.js";
import { ParentEvidenceValidator } from "../../../src/security/binary/evidence/ParentEvidenceValidator.js";
import { TrustedEvidenceAuthority } from "../../../src/security/binary/evidence/TrustedAnalysisEvidence.js";
import { KeyringManager } from "../../../src/security/packboard/secureKeyring.js";
import { SqliteBlackboardStorage } from "../../../src/security/blackboard/SqliteBlackboardStorage.js";
import type { AssessmentId } from "../../../src/domain/security/assessment.js";
import type { AssetId } from "../../../src/domain/security/asset.js";

async function main() {
  console.log("================================================================================");
  printHeader("REA Milestone 4.3 — Phase 2: Supervised Child-Process Pipeline Verification");
  console.log("Target: usr/sbin/dropbear from OpenWrt 23.05.0 SquashFS");
  console.log("================================================================================\n");

  const tempDir = await mkdtemp(join(tmpdir(), "rea-supervised-eval-"));
  const dbPath = join(tempDir, "blackboard.db");
  const journalPath = join(tempDir, "journal.db");

  const assessmentId = "asm_openwrt_capstone_eval" as AssessmentId;
  const assetId = "ast_dropbear_mips32" as AssetId;
  const taskId = "tsk_dropbear_analysis_01";
  const fencingToken = 1;
  const binarySha256 = "d7fc7e4ee7ea59ecb4b333890483ea3a428b5ace6a737876cea2aac169832661";

  const storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });
  const keyring = KeyringManager.createEphemeral(assessmentId);
  const authority = new TrustedEvidenceAuthority({ keyringManager: keyring, db: storage.getDatabase() });
  const validator = new ParentEvidenceValidator();

  const binaryPath = "evaluation/corpus/openwrt/usr_sbin_dropbear";
  const binaryBytes = await readFile(binaryPath);

  storage.getDatabase().prepare(`
    INSERT INTO assessments (
      id, name, status, objective_json, authorization_json, metrics_json, created_at, updated_at
    ) VALUES (?, 'OpenWrt Capstone Eval Assessment', 'active', '{}', '{}', '{}', ?, ?)
  `).run(assessmentId, Date.now(), Date.now());

  storage.getDatabase().prepare(`
    INSERT INTO assets (
      id, assessment_id, name, type, sha256, path, metadata_json, created_at
    ) VALUES (?, ?, 'usr_sbin_dropbear', 'binary', ?, '/usr/sbin/dropbear', ?, ?)
  `).run(
    assetId,
    assessmentId,
    binarySha256,
    JSON.stringify({ architecture: "MIPS", buffer: { type: "Buffer", data: [] } }),
    Date.now(),
  );

  console.log("[1] Initializing BinaryWorkerSupervisor with child worker isolation...");
  const supervisor = new BinaryWorkerSupervisor({
    workerId: "wkr_capstone_real_01",
    allowedRoot: process.cwd(),
  });

  await supervisor.start();
  console.log(`    - Supervisor state: ${supervisor.getState()}`);
  console.log(`    - Supervised worker ID: ${supervisor.workerId}`);

  const runManager = authority.getRunManager();
  const run = runManager.startRun(assessmentId, assetId, binarySha256);

  console.log("[2] Dispatching DECODE task over IPC to isolated worker process...");
  const decodeRequest: any = {
    protocolVersion: "1.0.0",
    kind: "ANALYZE_REQUEST",
    messageId: randomUUID(),
    taskId,
    assessmentId,
    assetId,
    binarySha256,
    runId: run.runId,
    fencingToken,
    workerId: supervisor.workerId,
    requestedStage: "DECODE",
    binaryInput: {
      type: "inline_buffer",
      expected_sha256: binarySha256,
      byte_size: binaryBytes.length,
      data_base64: binaryBytes.toString("base64"),
      read_only: true,
    },
    analysisConfiguration: {
      architecture: "MIPS_BE",
      entryPoints: ["_start"],
      targetFunctions: [],
      maxInstructions: 50000,
      maxCfgBlocks: 10000,
      maxPaths: 5,
    },
    deadline: Date.now() + 30000,
  };

  const startTime = Date.now();
  const workerRes = await supervisor.executeTask(decodeRequest);
  const elapsedMs = Date.now() - startTime;

  if (!workerRes.ok) {
    console.error("Worker task execution failed:", workerRes.error);
    await supervisor.shutdown(500);
    process.exit(1);
  }

  const untrustedDto = workerRes.value;
  console.log(`    - Worker task completed in ${elapsedMs}ms`);
  console.log(`    - Execution status: ${untrustedDto.executionStatus}`);
  console.log(`    - Decoded instructions: ${untrustedDto.resultPayload.decoder?.instructions.length}`);
  console.log(`    - Provider declared: ${untrustedDto.resultPayload.decoder?.provider}`);
  console.log(`    - Worker resultDigest: ${untrustedDto.resultDigest}`);

  console.log("[3] Parent process evidence validation (ParentEvidenceValidator)...");
  const parentCtx = {
    assessmentId,
    assetId,
    binarySha256,
    runId: run.runId,
    taskId,
    fencingToken,
    workerId: supervisor.workerId,
    requestedStage: "DECODE" as const,
    architecture: "MIPS",
    binaryInputBytes: binaryBytes,
  };

  const valRes = validator.validateWorkerResponse(untrustedDto, parentCtx);
  if (!valRes.ok) {
    console.error("Parent validation rejected worker response:", valRes.error);
    await supervisor.shutdown(500);
    process.exit(1);
  }
  console.log(`    - Parent validation passed: keys=${Object.keys(valRes.value)}`);
  console.log(`    - decoderPayload present: ${!!valRes.value.decoderPayload}`);
  if (valRes.value.decoderPayload) {
    console.log(`    - decoderPayload instructions: ${valRes.value.decoderPayload.instructions.length}`);
  }

  console.log("[4] HMAC Evidence Sealing (TrustedEvidenceAuthority)...");
  const sealRes = validator.sealValidatedEvidence(valRes.value, authority, parentCtx);
  if (!sealRes.ok) {
    console.error("HMAC evidence sealing failed:", sealRes.error);
    await supervisor.shutdown(500);
    process.exit(1);
  }

  const sealedEvidence = sealRes.value;
  console.log("    - Sealed Evidence Bundle Keys:", Object.keys(sealedEvidence));
  if (sealedEvidence.decoderEvidence) {
    console.log("    - Decoder Evidence:", JSON.stringify(sealedEvidence.decoderEvidence, null, 2));
  }

  console.log("[5] Dispatching CFG task over IPC to isolated worker process...");
  const cfgRequest = {
    ...decodeRequest,
    messageId: randomUUID(),
    requestedStage: "CFG",
  };

  const cfgWorkerRes = await supervisor.executeTask(cfgRequest);
  if (!cfgWorkerRes.ok) {
    console.error("CFG execution failed:", cfgWorkerRes.error);
    await supervisor.shutdown(500);
    process.exit(1);
  }

  const cfgDto = cfgWorkerRes.value;
  console.log(`    - CFG Basic Blocks recovered: ${cfgDto.resultPayload.cfg?.blocks.length}`);
  console.log(`    - CFG Edges recovered: ${cfgDto.resultPayload.cfg?.edges.length}`);
  console.log(`    - CFG Hash: ${cfgDto.resultPayload.cfg?.cfgHash}`);

  console.log("[6] Clean shutdown of supervisor and worker child process...");
  await supervisor.shutdown(500);
  storage.close();
  await rm(tempDir, { recursive: true, force: true });
  console.log("\n[SUCCESS] Production pipeline successfully executed, verified, and sealed real OpenWrt binary via Capstone!\n");
}

function printHeader(text: string) {
  console.log(text);
}

main().catch(err => {
  console.error("Error:", err);
  process.exit(1);
});
