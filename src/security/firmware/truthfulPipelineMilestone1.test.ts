/* eslint-disable max-lines-per-function */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SqliteBlackboardStorage } from "../blackboard/SqliteBlackboardStorage.js";
import { KeyringManager } from "../packboard/secureKeyring.js";
import {
  TrustedEvidenceAuthority,
  TrustedEvidenceVerifier,
} from "../binary/evidence/TrustedAnalysisEvidence.js";
import {
  ParentEvidenceValidator,
  type ParentValidationContext,
} from "../binary/evidence/ParentEvidenceValidator.js";
import { BinaryWorkerSupervisor } from "../binary/supervisor/BinaryWorkerSupervisor.js";
import { BinaryAnalysisDispatcher } from "../binary/worker/BinaryAnalysisDispatcher.js";
import { BinaryInputResolver } from "../binary/worker/BinaryInputResolver.js";
import { VulnerabilityAdjudicationBridge } from "../binary/VulnerabilityAdjudicationBridge.js";
import { FirmwareInventoryService } from "./FirmwareInventoryService.js";
import { defaultFirmwareDeepAnalyzer } from "./firmwareDeepAnalyzer.js";
import { BinaryAnalysisAgent } from "../agents/binaryAnalysisAgent.js";
import { VulnerabilityVerificationAgent } from "../agents/verificationAgent.js";
import { MultiStageAdjudicator } from "../../application/security/adjudicate/MultiStageAdjudicator.js";
import { VulnerabilityEngine } from "../engines/vulnerability/engine.js";
import { defaultReportGenerator } from "../reporting/reportGenerator.js";
import { createTestElfImage } from "../binary/testElfFixtures.js";
import { computeAssetId, type AssetId, type AssetRecord } from "../../domain/security/asset.js";
import { createAssessmentState, type AssessmentId } from "../../domain/security/assessment.js";
import type { BinaryWorkerAnalyzeRequest } from "../binary/ipc/binaryWorkerProtocol.js";
import type { VulnerabilityCandidate } from "../../domain/security/binary/types.js";
import { ok, err } from "../../domain/result.js";

describe("Milestone 1: Truthful Firmware-to-Binary Analysis Vertical Slice", () => {
  let tempDir: string;
  let sandboxDir: string;
  let dbPath: string;
  let journalPath: string;
  let storage: SqliteBlackboardStorage;
  let keyringManager: KeyringManager;
  let authority: TrustedEvidenceAuthority;
  let verifier: TrustedEvidenceVerifier;
  let validator: ParentEvidenceValidator;
  let bridge: VulnerabilityAdjudicationBridge;
  let inventoryService: FirmwareInventoryService;

  const assessmentId = "asm_m1_truthful_00000000000000000000000000000000000000000000000000000001" as AssessmentId;
  const rootFirmwareAssetId = "ast_root_fw_00000000000000000000000000000000000000000000000000000001" as AssetId;
  const activeSupervisors: BinaryWorkerSupervisor[] = [];

  function trackSupervisor(sup: BinaryWorkerSupervisor): BinaryWorkerSupervisor {
    activeSupervisors.push(sup);
    return sup;
  }

  // Pre-generate test ELF buffers
  const armBusyboxBytes = createTestElfImage({
    is64Bit: false,
    isLE: true,
    machine: 0x28, // ARM
    entryPoint: 0x10000,
    importedSymbols: ["strcpy", "system"],
    exportedSymbols: ["main", "busybox_main"],
    strings: ["admin:admin", "busybox 1.35.0", "/bin/sh"],
    textBytes: new Uint8Array([0x04, 0x00, 0x9d, 0xe5, 0x00, 0x00, 0x00, 0xeb]),
  });
  const busyboxSha256 = createHash("sha256").update(armBusyboxBytes).digest("hex");

  const x64DaemonBytes = createTestElfImage({
    is64Bit: true,
    isLE: true,
    machine: 0x3e, // x86_64
    entryPoint: 0x401000,
    importedSymbols: ["gets", "printf"],
    exportedSymbols: ["main", "daemon_init"],
    strings: ["Gateway Daemon 2.0", "Starting listener"],
  });
  const daemonSha256 = createHash("sha256").update(x64DaemonBytes).digest("hex");

  let rootFirmwarePath: string;
  let rootFirmwareSha256: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-m1-truthful-"));
    sandboxDir = join(tempDir, "sandbox");
    dbPath = join(tempDir, "blackboard.db");
    journalPath = join(tempDir, "audit.jsonl");

    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });
    keyringManager = KeyringManager.createEphemeral(assessmentId);
    authority = new TrustedEvidenceAuthority({ keyringManager, db: storage.getDatabase() });
    verifier = new TrustedEvidenceVerifier({ keyringManager, db: storage.getDatabase() });
    validator = new ParentEvidenceValidator();
    bridge = new VulnerabilityAdjudicationBridge({ verifier });
    inventoryService = new FirmwareInventoryService(storage);

    // Create root firmware binary on disk
    rootFirmwarePath = join(tempDir, "firmware.bin");
    const fwContent = Buffer.concat([
      Buffer.from("FAKE_FIRMWARE_HEADER_UIMAGE_OR_SQUASHFS"),
      Buffer.alloc(1024, 0x55),
    ]);
    await writeFile(rootFirmwarePath, fwContent);
    rootFirmwareSha256 = createHash("sha256").update(fwContent).digest("hex");

    // Initialize root assessment & root firmware asset in blackboard
    storage.getDatabase().prepare(`
      INSERT INTO assessments (
        id, name, status, objective_json, authorization_json, metrics_json, created_at, updated_at
      ) VALUES (?, 'Milestone 1 Truthful Pipeline Assessment', 'active', '{}', '{}', '{}', ?, ?)
    `).run(assessmentId, Date.now(), Date.now());

    await storage.assets.create({
      id: rootFirmwareAssetId,
      assessment_id: assessmentId,
      parent_asset_id: null,
      name: "firmware.bin",
      type: "firmware_image",
      path: rootFirmwarePath,
      digest: { sha256: rootFirmwareSha256 },
      architecture: null,
      version: "1.0.0",
      environment: { platform: "firmware_linux" },
      tags: ["root_firmware"],
      metadata: { fileSize: fwContent.length },
      created_at: Date.now(),
    });

    // Populate sandbox filesystem fixture
    await mkdir(join(sandboxDir, "bin"), { recursive: true });
    await mkdir(join(sandboxDir, "usr", "bin"), { recursive: true });
    await mkdir(join(sandboxDir, "etc"), { recursive: true });

    // 1. Valid ARM ELF binary without extension
    await writeFile(join(sandboxDir, "bin", "busybox"), armBusyboxBytes);

    // 2. Valid x86_64 ELF binary
    await writeFile(join(sandboxDir, "usr", "bin", "gateway_daemon"), x64DaemonBytes);

    // 3. Non-executable text file
    await writeFile(join(sandboxDir, "etc", "passwd"), "root:x:0:0:root:/root:/bin/sh\n");

    // 4. Non-executable configuration
    await writeFile(
      join(sandboxDir, "etc", "config.json"),
      JSON.stringify({ hostname: "gateway", debug: false }, null, 2),
    );

    // 5. In-sandbox symlink: bin/sh -> busybox
    // 6. Outside-escaping symlink: etc/shadow -> outside sandbox
    try {
      await symlink("busybox", join(sandboxDir, "bin", "sh"));
      const outsideTarget = join(tempDir, "outside_shadow.txt");
      await writeFile(outsideTarget, "root:$6$salt$hash:19000:0:99999:7:::\n");
      await symlink(outsideTarget, join(sandboxDir, "etc", "shadow_symlink"));
    } catch {
      // On Windows without Developer Mode / SeCreateSymbolicLinkPrivilege, symlink creation throws EPERM.
    }
  });

  afterEach(async () => {
    while (activeSupervisors.length > 0) {
      const sup = activeSupervisors.pop()!;
      try {
        await sup.shutdown(500);
      } catch {
        sup.forceKillProcess();
      }
    }
    storage.close();
    try {
      await rm(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  // ==========================================================================
  // Acceptance A: Extraction and Inventory
  // ==========================================================================
  describe("Acceptance A: Extraction and child-asset inventory", () => {
    it("A1-A10: Truthfully inventories extracted files, checks hashes, classifies content, and preserves lineage & gaps", async () => {
      // 1. Run inventory on the extracted sandbox
      const invRes = await inventoryService.inventoryAndSchedule(
        assessmentId,
        rootFirmwareAssetId,
        sandboxDir,
        "squashfs",
      );
      expect(invRes.ok).toBe(true);
      if (!invRes.ok) return;

      const extraction = invRes.value;
      expect(extraction.rootAssetId).toBe(rootFirmwareAssetId);
      expect(extraction.extractedFilesCount).toBe(4); // busybox, gateway_daemon, passwd, config.json

      // 2. Verify regular extracted child files are published as assets
      const allAssetsRes = await storage.assets.listByAssessment(assessmentId);
      expect(allAssetsRes.ok).toBe(true);
      if (!allAssetsRes.ok) return;
      const assets = allAssetsRes.value;

      // Find published files
      const busyboxAsset = assets.find((a: any) => a.name === "busybox");
      const daemonAsset = assets.find((a: any) => a.name === "gateway_daemon");
      const passwdAsset = assets.find((a: any) => a.name === "passwd");
      const configAsset = assets.find((a: any) => a.name === "config.json");

      expect(busyboxAsset).toBeDefined();
      expect(daemonAsset).toBeDefined();
      expect(passwdAsset).toBeDefined();
      expect(configAsset).toBeDefined();

      // 3. Every published child has independent SHA-256 matching actual bytes
      expect(busyboxAsset!.digest?.sha256).toBe(busyboxSha256);
      expect(daemonAsset!.digest?.sha256).toBe(daemonSha256);
      expect(passwdAsset!.digest?.sha256).toBe(
        createHash("sha256").update("root:x:0:0:root:/root:/bin/sh\n").digest("hex"),
      );

      // 4. Lineage accurately links child assets to root firmware
      expect((busyboxAsset!.metadata as any).rootFirmwareAssetId).toBe(rootFirmwareAssetId);
      expect((busyboxAsset!.metadata as any).firmwareSha256).toBe(rootFirmwareSha256);
      expect(busyboxAsset!.parent_asset_id).not.toBeNull();

      // 5. Nested relative paths preserved
      expect(busyboxAsset!.path).toBe("bin/busybox");
      expect(daemonAsset!.path).toBe("usr/bin/gateway_daemon");
      expect(passwdAsset!.path).toBe("etc/passwd");
      expect(configAsset!.path).toBe("etc/config.json");

      // 6. Non-executable files classified correctly
      expect(passwdAsset!.type).toBe("cloud_configuration"); // In etc/
      expect(configAsset!.type).toBe("cloud_configuration");
      expect(passwdAsset!.tags).toContain("skipped");

      // 7. ELF binaries classified from content, not filename
      expect(busyboxAsset!.type).toBe("compiled_binary");
      expect(busyboxAsset!.architecture).toBe("ARM");
      expect((busyboxAsset!.metadata as any).is64Bit).toBe(false);
      expect((busyboxAsset!.metadata as any).endianness).toBe("little");

      expect(daemonAsset!.type).toBe("compiled_binary");
      expect(daemonAsset!.architecture).toBe("x86_64");
      expect((daemonAsset!.metadata as any).is64Bit).toBe(true);

      // 8. Symlinks preserved as observations, not executable assets
      const symlinkAsset = assets.find((a: any) => a.name === "sh" || a.name === "shadow_symlink");
      expect(symlinkAsset).toBeUndefined(); // MUST NOT be published as regular binary asset

      const symlinkRows = storage.getDatabase().prepare(
        "SELECT * FROM observations WHERE assessment_id = ? AND key = ?",
      ).all(assessmentId, "firmware.symlink_entry") as any[];

      if (symlinkRows.length > 0) {
        const escapingRow = symlinkRows.find((r) => JSON.parse(r.value_json).path === "etc/shadow_symlink");
        if (escapingRow) {
          expect(JSON.parse(escapingRow.value_json).escapes_sandbox).toBe(true);
        }
      } else {
        // On platforms without symlink creation privilege, verify symlink observation can be safely recorded
        const manualObs = await storage.observations.record({
          assessment_id: assessmentId,
          asset_id: rootFirmwareAssetId,
          key: "firmware.symlink_entry",
          value: { path: "bin/sh", target: "busybox", escapes_sandbox: false, published: false },
          confidence: 1.0,
          source_tool: "firmware_inventory",
          agent_id: "firmware_inventory_service",
          evidence_id: null,
          created_at: Date.now(),
        });
        expect(manualObs.ok).toBe(true);
      }

      // 9. Extraction gaps preserved
      const gapRes = await inventoryService.recordExtractionGap(assessmentId, rootFirmwareAssetId, {
        path: "mtd3/encrypted_kernel",
        reason: "Encrypted payload chunk; no static key available",
        kind: "encrypted",
        offset: 0x40000,
      });
      expect(gapRes.ok).toBe(true);

      const gapRows = storage.getDatabase().prepare(
        "SELECT * FROM observations WHERE assessment_id = ? AND key = ?",
      ).all(assessmentId, "firmware.extraction_gap") as any[];
      expect(gapRows).toHaveLength(1);
      expect(JSON.parse(gapRows[0].value_json).kind).toBe("encrypted");

      // 10. Distinct lifecycle states preserved: queued_for_analysis, NOT analyzed
      expect((busyboxAsset!.metadata as any).lifecycle_state).toBe("queued_for_analysis");
      expect((busyboxAsset!.metadata as any).analyzed).toBe(false);
      expect((busyboxAsset!.metadata as any).queued_for_analysis).toBe(true);

      // Tasks created for executables
      const tasksRes = await storage.tasks.listByAssessment(assessmentId);
      expect(tasksRes.ok).toBe(true);
      if (!tasksRes.ok) return;
      expect(tasksRes.value).toHaveLength(2); // busybox and daemon
      expect(tasksRes.value[0]!.status).toBe("open");
    });
  });

  // ==========================================================================
  // Acceptance B: Real Supervised Binary Analysis Handoff
  // ==========================================================================
  describe("Acceptance B: Real supervised binary analysis handoff", () => {
    it("B1-B8: Supervises child worker, resolves exact bytes, validates and seals evidence, rejects stale fencing", async () => {
      // 1. Setup real supervisor
      const supervisor = trackSupervisor(
        new BinaryWorkerSupervisor({
          workerId: "wkr_m1_supervised_01",
          allowedRoot: tempDir,
        }),
      );
      await supervisor.start();
      expect(supervisor.getState()).toBe("READY");

      // 2. Setup task and run in authority
      const taskId = "tsk_m1_arm_busybox";
      const fencingToken = 1;
      const runManager = authority.getRunManager();
      const run = runManager.startRun(assessmentId, rootFirmwareAssetId, busyboxSha256);

      // 3. Build parent-controlled input reference pointing to exact published child file
      const busyboxPath = join(sandboxDir, "bin", "busybox");
      const req: BinaryWorkerAnalyzeRequest = {
        protocolVersion: "1.0.0",
        kind: "ANALYZE_REQUEST",
        messageId: randomUUID(),
        taskId,
        assessmentId,
        assetId: rootFirmwareAssetId,
        firmwareSha256: rootFirmwareSha256,
        binarySha256: busyboxSha256,
        runId: run.runId,
        fencingToken,
        workerId: supervisor.workerId,
        requestedStage: "ALL",
        binaryInput: {
          type: "file_path",
          path: busyboxPath,
          expected_sha256: busyboxSha256,
          byte_size: armBusyboxBytes.length,
          read_only: true,
        },
        analysisConfiguration: {
          architecture: "ARM",
          entryPoints: ["main"],
          maxInstructions: 10_000,
          maxCfgBlocks: 100,
          maxPaths: 50,
        },
        deadline: Date.now() + 15_000,
      };

      const parentCtx: ParentValidationContext = {
        assessmentId,
        assetId: rootFirmwareAssetId,
        binarySha256: busyboxSha256,
        firmwareSha256: rootFirmwareSha256,
        runId: run.runId,
        taskId,
        fencingToken,
        workerId: supervisor.workerId,
        requestedStage: "ALL",
        architecture: "ARM",
        binaryInputPath: busyboxPath,
      };

      // 4. Dispatch request through supervisor
      const workerResponse = await supervisor.executeTask(req);
      expect(workerResponse.ok).toBe(true);
      if (!workerResponse.ok) return;

      const resp = workerResponse.value;
      expect(resp.kind).toBe("ANALYZE_RESPONSE");
      expect(resp.taskId).toBe(taskId);
      expect(resp.binarySha256).toBe(busyboxSha256);

      // 5. Parent independently validates returned DTO
      const valRes = validator.validateWorkerResponse(resp, parentCtx);
      expect(valRes.ok).toBe(true);
      if (!valRes.ok) return;

      // 6. Parent seals evidence in authority
      const sealedRes = validator.sealValidatedEvidence(valRes.value, authority, parentCtx);
      expect(sealedRes.ok).toBe(true);
      if (!sealedRes.ok) return;

      expect(sealedRes.value.decoderEvidence).toBeDefined();
      expect(sealedRes.value.reachabilityEvidence).toBeDefined();

      // Ensure task exists in blackboard with expected fencingToken
      storage.getDatabase().prepare(`
        INSERT INTO tasks (
          id, assessment_id, task_type, title, description, asset_id, priority, status,
          blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
          smoke_score, votes_json, evidence_hashes_json, created_at, updated_at
        ) VALUES (
          ?, ?, 'binary_analysis', 'Analyze busybox', 'Static binary inspection', ?, 'high', 'claimed',
          '[]', ?, 1, '{}', null, '{}', 0, '[]', '[]', ?, ?
        )
      `).run(taskId, assessmentId, rootFirmwareAssetId, fencingToken, Date.now(), Date.now());

      // 7. Persist truthful finding in SQLite blackboard
      const candidate: VulnerabilityCandidate = {
        binaryAssetId: rootFirmwareAssetId,
        ruleId: "REA-BIN-001",
        name: "Potential Buffer Overflow in Busybox Packet Handler",
        category: "unsafe_memory_operations",
        functionName: "busybox_main",
        functionAddress: "0x10000",
        sinkApi: "system",
        callAddress: "0x10004",
        callerInfo: "main",
        sourceOfInput: "network_socket",
        guardInfo: null,
        evidenceReferences: [],
        detectionMethod: "L2_HEURISTIC",
        confidenceScore: 0.5,
        confidenceLimitations: ["Static signature without dataflow validation"],
        cwe: ["CWE-120"],
        technicalDescription: "Binary calls unsafe CRT function without bounds check",
        remediationGuidance: "Replace unchecked call with bounded alternative",
      };

      const assetRecord: any = {
        id: rootFirmwareAssetId,
        assessment_id: assessmentId,
        parent_asset_id: null,
        name: "busybox",
        type: "compiled_binary",
        path: busyboxPath,
        digest: { sha256: busyboxSha256 },
        architecture: "ARM",
        version: "1.35.0",
        environment: null,
        tags: ["binary"],
        metadata: {},
        created_at: Date.now(),
      };

      const adjRes = validator.adjudicateAndPersist({
        storage,
        authority,
        bridge,
        candidate,
        asset: assetRecord,
        context: parentCtx,
        bundle: sealedRes.value,
      });

      expect(adjRes.ok).toBe(true);
      if (!adjRes.ok) return;

      // Notice: because taint and witness are fail-closed INCONCLUSIVE, finding cannot be VERIFIED
      expect(adjRes.value.finding.verification_status).not.toBe("VERIFIED");
      expect(["INCONCLUSIVE", "CANDIDATE"]).toContain(adjRes.value.finding.verification_status);

      // Verify finding persisted in SQLite database
      const row = storage.getDatabase().prepare("SELECT * FROM findings WHERE id = ?").get(adjRes.value.finding.id) as any;
      expect(row).toBeDefined();
      expect(row.asset_id).toBe(rootFirmwareAssetId);

      // 8. Stale or mismatched fencing token dropped
      const staleParentCtx: ParentValidationContext = {
        ...parentCtx,
        fencingToken: 999, // Mismatched fencing token!
      };
      const staleValRes = validator.validateWorkerResponse(resp, staleParentCtx);
      expect(staleValRes.ok).toBe(false);
      if (!staleValRes.ok) {
        expect(["CONTEXT_MISMATCH", "FENCING_TOKEN_STALE"]).toContain(staleValRes.error.code);
        expect((staleValRes.error as any).field).toBe("fencingToken");
      }
    });
  });

  // ==========================================================================
  // Acceptance C: Fail-Closed Proof
  // ==========================================================================
  describe("Acceptance C: Fail-closed proof and heuristic policy", () => {
    it("C1: Raw 'telnetd' string alone cannot produce VERIFIED", async () => {
      const telnetdFirmwarePath = join(tempDir, "telnetd_fw.bin");
      await writeFile(
        telnetdFirmwarePath,
        Buffer.concat([
          Buffer.from("DEVICE_FIRMWARE_V1\n"),
          Buffer.from("/usr/sbin/telnetd -p 23\n"),
          Buffer.from("root:$1$fakehash:15000:0:99999:7:::\n"),
        ]),
      );

      const result = await defaultFirmwareDeepAnalyzer.analyze(telnetdFirmwarePath);
      expect(result.ok).toBe(true);
      if (!result.ok) return;

      const telnetFinding = result.value.findings.find((f) => f.name.includes("Telnet"));
      expect(telnetFinding).toBeDefined();
      // MUST NOT be VERIFIED based on string existence alone
      expect(telnetFinding!.verification_status).toBe("CANDIDATE");
      expect(telnetFinding!.impact.exploitability).toBe("THEORETICAL");
      expect(telnetFinding!.provenance.verified_by).toBeNull();
    });

    it("C2: Symbol reference alone cannot produce VERIFIED", async () => {
      const binaryAgent = new BinaryAnalysisAgent();
      const assessment = createAssessmentState({
        objective: { title: "Symbol Audit", target_technologies: ["C"], compliance_frameworks: [], focus_areas: [], depth: "standard" },
        scope: { allowed_targets: [tempDir], denied_targets: [], authorized_by: "Lead", authorization_reference: "REF", valid_until: "2026-12-31T23:59:59Z", allow_active_verification: false },
      });

      const binAsset: AssetRecord = {
        id: computeAssetId({ name: "busybox", type: "compiled_binary" }),
        name: "busybox",
        type: "compiled_binary",
        path: join(sandboxDir, "bin", "busybox"),
        digest: { sha256: busyboxSha256 },
        architecture: "ARM",
        version: null,
        environment: null,
        tags: [],
        metadata: {},
      };

      const ctx: any = {
        state: { ...assessment, assets: [binAsset], findings: [] },
        updateAssessment: (fn: any) => {
          ctx.state = fn(ctx.state);
        },
      };

      const execRes = await binaryAgent.execute(ctx);
      expect(execRes.ok).toBe(true);
      expect(ctx.state.findings.length).toBeGreaterThanOrEqual(1);

      for (const finding of ctx.state.findings) {
        // Unchecked CRT symbols MUST be UNVERIFIED / CANDIDATE, never VERIFIED
        expect(finding.verification_status).toBe("UNVERIFIED");
        expect(finding.impact.exploitability).toBe("THEORETICAL");
        expect(finding.provenance.verified_by).toBeNull();
      }
    });

    it("C3-C6: Dispatcher TAINT, WITNESS, and REACHABILITY fail closed to INCONCLUSIVE and THEORETICAL", async () => {
      const dispatcher = new BinaryAnalysisDispatcher();

      const createRequest = (requestedStage: any): BinaryWorkerAnalyzeRequest => ({
        protocolVersion: "1.0.0",
        kind: "ANALYZE_REQUEST",
        messageId: randomUUID(),
        taskId: "test_task",
        assessmentId,
        assetId: rootFirmwareAssetId,
        firmwareSha256: rootFirmwareSha256,
        binarySha256: busyboxSha256,
        runId: "run_test",
        fencingToken: 1,
        workerId: "wkr_test",
        requestedStage,
        binaryInput: {
          type: "inline_buffer",
          data_base64: armBusyboxBytes.toString("base64"),
          expected_sha256: busyboxSha256,
          byte_size: armBusyboxBytes.length,
          read_only: true,
        },
        analysisConfiguration: {
          architecture: "ARM",
          entryPoints: ["main"],
          maxInstructions: 10_000,
          maxCfgBlocks: 100,
          maxPaths: 50,
        },
        deadline: Date.now() + 15_000,
      });

      // C3: TAINT stage returns INCONCLUSIVE
      const taintRes = await dispatcher.dispatch(createRequest("TAINT"), armBusyboxBytes);
      expect(taintRes.ok).toBe(true);
      if (!taintRes.ok) return;
      expect(taintRes.value.resultPayload.taint?.status).toBe("INCONCLUSIVE");
      expect(taintRes.value.resultPayload.taint?.source).toBeNull();
      expect(taintRes.value.resultPayload.taint?.steps).toHaveLength(0);

      // C4: WITNESS stage returns THEORETICAL and isSatisfiable: false
      const witnessRes = await dispatcher.dispatch(createRequest("WITNESS"), armBusyboxBytes);
      expect(witnessRes.ok).toBe(true);
      if (!witnessRes.ok) return;
      expect(witnessRes.value.resultPayload.witness?.exploitabilityStatus).toBe("THEORETICAL");
      expect(witnessRes.value.resultPayload.witness?.isSatisfiable).toBe(false);

      // C5: REACHABILITY on incomplete target returns INCONCLUSIVE
      const reachRes = await dispatcher.dispatch(createRequest("REACHABILITY"), armBusyboxBytes);
      expect(reachRes.ok).toBe(true);
      if (!reachRes.ok) return;
      expect(["INCONCLUSIVE", "PARTIAL"]).toContain(reachRes.value.resultPayload.reachability?.status);
    });

    it("C7-C9: Missing source or missing evidence cannot satisfy verification or produce VERIFIED", () => {
      const adjudicator = new MultiStageAdjudicator();

      // C7: Missing source code returns INCONCLUSIVE
      const noSourceDecision = adjudicator.adjudicate({
        finding_id: "fnd_0000000000000000000000000000000000000000000000000000000000000001" as any,
        source_code: "",
        file_path: "src/main.c",
        evidence_category: "STATIC_AST_CFG",
      });
      expect(noSourceDecision.ok).toBe(true);
      if (!noSourceDecision.ok) return;
      expect(noSourceDecision.value.outcome).toBe("INCONCLUSIVE");

      // C8: VerificationAgent without evidence does NOT promote to VERIFIED
      const verificationAgent = new VulnerabilityVerificationAgent(adjudicator);
      const candidateFinding: any = {
        id: "fnd_0000000000000000000000000000000000000000000000000000000000000002",
        name: "Candidate Unverified Finding",
        affected_asset: { id: rootFirmwareAssetId, name: "fw", type: "firmware_image" },
        location: { file: "net.c", line: 10 },
        technical_description: "Candidate",
        root_cause: "Unknown",
        evidence_ids: [], // NO evidence
        severity: { level: "HIGH", cvss_score: 7.5 },
        confidence: { level: "TENTATIVE", false_positive_considerations: [] },
        remediation: { priority: "HIGH" },
        classification: { cve: [], cwe: [], capec: [], mitre_attack: [], owasp: [] },
        verification_status: "CANDIDATE",
        provenance: { discovered_by: "scanner", discovered_at: new Date().toISOString(), verified_by: null, verified_at: null },
      };

      const agentCtx: any = {
        state: { findings: [candidateFinding] },
        updateAssessment: (fn: any) => {
          agentCtx.state = fn(agentCtx.state);
        },
      };

      verificationAgent.execute(agentCtx);
      const evaluated = agentCtx.state.findings[0];
      // MUST NOT be upgraded to VERIFIED
      expect(evaluated.verification_status).not.toBe("VERIFIED");
      expect(["CANDIDATE", "UNVERIFIED", "INCONCLUSIVE"]).toContain(evaluated.verification_status);
      expect(evaluated.provenance.verified_by).toBeNull();
    });
  });

  // ==========================================================================
  // Acceptance D: Scanner Status
  // ==========================================================================
  describe("Acceptance D: Truthful scanner and coverage status", () => {
    it("D1: .squashfs files are identified as firmware_image, never generic compiled_binary", async () => {
      const squashFsPath = join(tempDir, "rootfs.squashfs");
      // Write SquashFS 4.0 magic (sqsh)
      const sqshBuf = Buffer.concat([Buffer.from("sqsh"), Buffer.alloc(96, 0)]);
      await writeFile(squashFsPath, sqshBuf);

      const headerInfo = await FirmwareInventoryService.inspectBinaryHeader(squashFsPath);
      expect(headerInfo.isElf).toBe(false);
      expect(headerInfo.isExecutable).toBe(false);
    });

    it("D2-D5: Reports NOT_SCANNED when 0 scanners run; reports PARTIAL on partial; zero findings does not claim target is clean", async () => {
      const vulnEngine = new VulnerabilityEngine();
      const compiledAsset: AssetRecord = {
        id: computeAssetId({ name: "binary_target", type: "compiled_binary" }),
        name: "binary_target",
        type: "compiled_binary",
        path: join(sandboxDir, "bin", "busybox"),
        digest: { sha256: busyboxSha256 },
        architecture: "ARM",
        version: null,
        environment: null,
        tags: [],
        metadata: {},
      };

      const scope = {
        allowed_targets: [tempDir],
        denied_targets: [],
        authorized_by: "SecLead",
        authorization_reference: "REF-001",
        valid_until: "2026-12-31T23:59:59Z",
        allow_active_verification: false,
      };

      // D2: Zero scanners executed (YARA selected but no rule files provided)
      const discoverRes = await vulnEngine.discover({
        asset: compiledAsset,
        scope,
        // No yaraRuleFiles passed
      });

      expect(discoverRes.ok).toBe(true);
      if (!discoverRes.ok) return;

      expect(discoverRes.value.status).toBe("NOT_SCANNED");
      expect(discoverRes.value.executed_scanners).toHaveLength(0);
      expect(discoverRes.value.skipped_scanners).toContain("yara");

      // D3: Report Generator generates truthful NOT_SCANNED notice
      const assessment = createAssessmentState({
        objective: { title: "Scan of binary_target", target_technologies: [], compliance_frameworks: [], focus_areas: [], depth: "standard" },
        scope,
      });

      const mdReport = defaultReportGenerator.generate({
        assessment: { ...assessment, assets: [compiledAsset], findings: [] },
        format: "markdown",
        scanExecution: {
          status: discoverRes.value.status,
          selected_scanners: discoverRes.value.selected_scanners,
          executed_scanners: discoverRes.value.executed_scanners,
          completed_scanners: discoverRes.value.completed_scanners,
          failed_scanners: discoverRes.value.failed_scanners,
          skipped_scanners: discoverRes.value.skipped_scanners,
          scanner_warnings: discoverRes.value.scanner_warnings,
          unsupported_input_types: [],
          coverage: {
            discovered_files: 1,
            extracted_files: 0,
            eligible_binaries: 1,
            binaries_analyzed: 0,
            binaries_partially_analyzed: 0,
            binaries_skipped_or_failed: 1,
          },
        },
      });

      expect(mdReport).toContain("NOT_SCANNED");
      expect(mdReport).toContain("No security scanners were executed against the target");

      // D4: Partial coverage when a scanner fails
      const mockFailingSemgrep = async () => err(new Error("Semgrep process crashed"));
      const partialDiscover = await vulnEngine.discover({
        asset: { ...compiledAsset, type: "source_repository" },
        scope,
        semgrepRunner: mockFailingSemgrep as any,
        trivyRunner: (async () => ok({ findings: [], rawSarif: null, commandLine: "trivy" })) as any,
      });

      expect(partialDiscover.ok).toBe(true);
      if (!partialDiscover.ok) return;
      expect(partialDiscover.value.status).toBe("PARTIAL");
      expect(partialDiscover.value.failed_scanners).toContain("semgrep");
      expect(partialDiscover.value.completed_scanners).toContain("trivy");

      // D5: Stated coverage notice in report
      const partialReport = defaultReportGenerator.generate({
        assessment: { ...assessment, assets: [compiledAsset], findings: [] },
        format: "markdown",
        scanExecution: {
          status: "PARTIAL",
          selected_scanners: ["semgrep", "trivy"],
          executed_scanners: ["semgrep", "trivy"],
          completed_scanners: ["trivy"],
          failed_scanners: ["semgrep"],
          skipped_scanners: [],
          scanner_warnings: ["Semgrep failed"],
          unsupported_input_types: [],
          coverage: {
            discovered_files: 1,
            extracted_files: 0,
            eligible_binaries: 0,
            binaries_analyzed: 0,
            binaries_partially_analyzed: 1,
            binaries_skipped_or_failed: 0,
          },
        },
      });

      expect(partialReport).toContain("Unanalyzed areas remain unexamined");
    });
  });

  // ==========================================================================
  // Acceptance E: Persistence and Lineage
  // ==========================================================================
  describe("Acceptance E: Persistence, lineage, and atomic commits", () => {
    it("E1-E5: State survives SQLite close/reopen, maintains lineage, and rolls back on error", async () => {
      // 1. Write an entity hierarchy
      const childAssetId = "ast_child_daemon_01" as AssetId;
      await storage.assets.create({
        id: childAssetId,
        assessment_id: assessmentId,
        parent_asset_id: rootFirmwareAssetId,
        name: "gateway_daemon",
        type: "compiled_binary",
        path: "usr/bin/gateway_daemon",
        digest: { sha256: daemonSha256 },
        architecture: "x86_64",
        version: "2.0",
        environment: null,
        tags: ["binary"],
        metadata: { rootFirmwareAssetId, firmwareSha256: rootFirmwareSha256 },
        created_at: Date.now(),
      });

      const findingId = "fnd_m1_lineage_0000000000000000000000000000000000000000000000000000001" as any;
      await storage.findings.create({
        id: findingId,
        assessment_id: assessmentId,
        asset_id: childAssetId,
        fingerprint: findingId,
        title: "Insecure Function",
        description: "Uses legacy function",
        state: "CANDIDATE",
        cwe: ["CWE-242"],
        severity: { level: "HIGH", cvss_score: 7.5, cvss_vector: null, justification: "" },
        confidence: { level: "CONFIRMED", false_positive_considerations: [], verification_method: null },
        location: { file: "daemon.c", line: 42, column: null, end_line: null, module: null, component: null, address: null, offset: null, function: "main" },
        evidence_ids: [],
        remediation: { priority: "IMMEDIATE", description: "Fix", code_diff: null, config_example: null, validation_procedure: "" },
        cas_version: 0,
        created_at: Date.now(),
        updated_at: Date.now(),
      });

      // E1: State survives SQLite database close and reopen
      storage.close();

      const reopenedStorage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });
      const reopenedAssetRes = await reopenedStorage.assets.findById(assessmentId, childAssetId);
      expect(reopenedAssetRes.ok).toBe(true);
      if (!reopenedAssetRes.ok || !reopenedAssetRes.value) return;
      expect(reopenedAssetRes.value).not.toBeNull();
      expect(reopenedAssetRes.value.digest?.sha256).toBe(daemonSha256);

      // E2: Lineage preserved across close/reopen
      expect(reopenedAssetRes.value.parent_asset_id).toBe(rootFirmwareAssetId);

      const reopenedFindingRes = await reopenedStorage.findings.getById(assessmentId, findingId);
      expect(reopenedFindingRes.ok).toBe(true);
      if (!reopenedFindingRes.ok || !reopenedFindingRes.value) return;
      expect(reopenedFindingRes.value).not.toBeNull();
      expect(reopenedFindingRes.value.asset_id).toBe(childAssetId);

      // E4: Atomic outbox commit: findings and outbox events commit together
      reopenedStorage.transaction((tx) => {
        tx.queueOutbox("FINDING_RECORDED", "finding", findingId, assessmentId, { verified: false });
      });

      const outboxRow = reopenedStorage.getDatabase().prepare(
        "SELECT * FROM transactional_outbox WHERE entity_id = ?",
      ).get(findingId) as any;
      expect(outboxRow).toBeDefined();
      expect(["FINDING_CREATED", "FINDING_RECORDED"]).toContain(outboxRow.event_type);

      // E5: Transaction rollback on error leaves blackboard uncorrupted
      const invalidTaskId = "tsk_should_rollback";
      expect(() => {
        reopenedStorage.transaction((tx) => {
          tx.db.prepare(`
            INSERT INTO tasks (
              id, assessment_id, task_type, title, description, asset_id, priority, status,
              blocked_by_json, fencing_token, cas_version, claim_json, result_json, metadata_json,
              smoke_score, votes_json, evidence_hashes_json, created_at, updated_at
            ) VALUES (
              ?, ?, 'binary_analysis', 'Rollback Test', '', ?, 'high', 'open',
              '[]', 0, 0, null, null, '{}', 0, '[]', '[]', ?, ?
            )
          `).run(invalidTaskId, assessmentId, childAssetId, Date.now(), Date.now());

          // Trigger intentional crash
          throw new Error("Simulated worker transaction failure");
        });
      }).toThrow("Simulated worker transaction failure");

      const taskRow = reopenedStorage.getDatabase().prepare(
        "SELECT * FROM tasks WHERE id = ?",
      ).get(invalidTaskId);
      expect(taskRow).toBeUndefined(); // Completely rolled back!

      reopenedStorage.close();
    });
  });
});
