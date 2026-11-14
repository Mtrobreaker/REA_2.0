import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import { computeAssetId } from "../../../domain/security/asset.js";
import type {
  BlackboardAssetRecord,
  TaskRecord,
} from "../../../domain/security/blackboard/types.js";
import { ContextProjector } from "../blackboard/ContextProjector.js";
import { SqliteBlackboardStorage } from "../../../security/blackboard/SqliteBlackboardStorage.js";
import { createTestElfImage } from "../../../security/binary/testElfFixtures.js";
import { BinaryAnalysisWorker } from "./BinaryAnalysisWorker.js";

const assessmentId = "asm_bin_worker_0000000000000000000000000000000000000000000000000000000000" as AssessmentId;
const assessment = {
  id: assessmentId,
  name: "Binary Worker Assessment",
  status: "active" as const,
  objective: {
    title: "Binary Analysis",
    target_technologies: ["Linux", "ARM"],
    compliance_frameworks: [],
    focus_areas: ["Vulnerabilities"],
    depth: "standard" as const,
  },
  authorization: {
    allowed_targets: ["target_daemon"],
    denied_targets: [],
    authorized_by: "Security Team",
    authorization_reference: "AUTH-BIN-01",
    valid_until: new Date(Date.now() + 86400000).toISOString(),
    allow_active_verification: false,
  },
  metrics: {
    total_assets: 0,
    total_findings: 0,
    critical_findings: 0,
    high_findings: 0,
    medium_findings: 0,
    low_findings: 0,
    info_findings: 0,
    verified_findings: 0,
  },
  created_at: Date.now(),
  updated_at: Date.now(),
};

describe("BinaryAnalysisWorker Task Execution & Blackboard Persistence", () => {
  let dbDir: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;

  beforeEach(async () => {
    dbDir = await mkdtemp(join(tmpdir(), "rea-binworker-test-"));
    const dbPath = join(dbDir, "blackboard.db");
    const journalPath = join(dbDir, "packboard-audit.jsonl");
    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });
    projector = new ContextProjector({ blackboard: storage });
    await storage.assessments.create(assessment);
    await storage.assessments.create(assessment);
  });

  afterEach(async () => {
    storage.close();
    try {
      await rm(dbDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("executes binary_analysis task, extracts facts, and records findings in blackboard", async () => {
    const elfBuf = createTestElfImage({
      is64Bit: false,
      isLE: true,
      machine: 0x28, // ARM
      entryPoint: 0x10000,
      importedSymbols: ["strcpy", "system"],
      exportedSymbols: ["main", "process_request"],
      strings: ["admin:admin", "/bin/sh"],
    });

    const assetId = computeAssetId({
      name: "target_daemon",
      type: "compiled_binary",
      architecture: "ARM",
    });

    const asset: BlackboardAssetRecord = {
      id: assetId,
      assessment_id: assessmentId,
      parent_asset_id: null,
      name: "target_daemon",
      type: "compiled_binary",
      path: "/usr/sbin/target_daemon",
      digest: { sha256: "c".repeat(64) },
      architecture: "ARM",
      version: "1.0",
      environment: null,
      tags: ["executable", "elf"],
      metadata: {
        buffer: elfBuf,
        isExecutable: true,
      },
      created_at: Date.now(),
    };
    await storage.assets.create(asset);

    const taskId = "task_bin_001";
    const task: TaskRecord = {
      id: taskId,
      assessment_id: assessmentId,
      task_type: "binary_analysis",
      title: "Analyze target_daemon",
      description: "Static analysis and vulnerability detection",
      asset_id: assetId,
      priority: "high",
      status: "open",
      blocked_by: [],
      fencing_token: 0,
      cas_version: 0,
      claim: null,
      result: null,
      metadata: {
        buffer: elfBuf,
        required_capabilities: ["binary_decompilation"],
      },
      created_at: Date.now(),
      updated_at: Date.now(),
    };
    await storage.tasks.create(task);

    const workerInstance = new BinaryAnalysisWorker(assessmentId, storage, projector, {
      workerConfig: { agentId: "test_bin_agent", pollIntervalMs: 20 },
    });
    await workerInstance.start();

    // Run pollOnce to claim and execute the task
    const polled = await workerInstance.worker.pollOnce();
    expect(polled).toBe(true);

    // Wait for asynchronous task completion
    let completed = false;
    let lastErr: any = null;
    for (let i = 0; i < 50; i++) {
      const t = await storage.tasks.getById(assessmentId, taskId);
      if (t.ok && t.value?.status === "completed") {
        completed = true;
        break;
      }
      if (t.ok && t.value?.status === "failed") {
        lastErr = t.value.result;
        break;
      }
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(lastErr).toBeNull();
    expect(completed).toBe(true);

    // Verify findings were recorded in blackboard
    const findingsRes = await storage.findings.listByAssessment(assessmentId);
    expect(findingsRes.ok).toBe(true);
    if (findingsRes.ok) {
      expect(findingsRes.value.length).toBeGreaterThanOrEqual(2);
      const names = findingsRes.value.map((f) => f.title);
      expect(names.some((n) => n.includes("strcpy"))).toBe(true);
      expect(names.some((n) => n.includes("system"))).toBe(true);

      // Verify L1/L2 lifecycle is CANDIDATE
      for (const f of findingsRes.value) {
        expect(f.state).toBe("CANDIDATE");
      }
    }

    // Verify observations in blackboard
    const obsRes = await storage.observations.listByAsset(assessmentId, assetId);
    expect(obsRes.ok).toBe(true);
    if (obsRes.ok) {
      const keys = obsRes.value.map((o) => o.key);
      expect(keys).toContain("binary.metadata");
      expect(keys).toContain("binary.symbols");
      expect(keys).toContain("binary.analysis_report");
    }

    await workerInstance.stop();
  });
});

describe("BinaryAnalysisWorker Isolation & Idempotency", () => {
  let dbDir: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;

  const assessmentId = "asm_bin_worker_0000000000000000000000000000000000000000000000000000000000" as AssessmentId;

  beforeEach(async () => {
    dbDir = await mkdtemp(join(tmpdir(), "rea-binworker-idem-"));
    const dbPath = join(dbDir, "blackboard.db");
    const journalPath = join(dbDir, "packboard-audit.jsonl");
    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });
    projector = new ContextProjector({ blackboard: storage });
    await storage.assessments.create(assessment);
  });

  afterEach(async () => {
    storage.close();
    try {
      await rm(dbDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("enforces assessment isolation and rejects tasks from different assessments", async () => {
    const otherAssessmentId = "asm_foreign_00000000000000000000000000000000000000000000000000000000" as AssessmentId;
    const workerInstance = new BinaryAnalysisWorker(assessmentId, storage, projector);

    const foreignTask: TaskRecord = {
      id: "foreign_task",
      assessment_id: otherAssessmentId,
      task_type: "binary_analysis",
      title: "Foreign Task",
      description: "Illegal task",
      asset_id: "ast_foreign" as any,
      priority: "high",
      status: "open",
      blocked_by: [],
      fencing_token: 0,
      cas_version: 0,
      claim: null,
      result: null,
      metadata: {},
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    await expect(
      workerInstance.handleBinaryAnalysisTask(foreignTask, null),
    ).rejects.toThrow("Assessment isolation violation");

    await workerInstance.stop();
  });

  it("is idempotent: re-executing task on same asset returns cached report without duplicating findings", async () => {
    const elfBuf = createTestElfImage({
      importedSymbols: ["strcpy"],
      exportedSymbols: ["main"],
    });

    const assetId = computeAssetId({
      name: "idempotent_bin",
      type: "compiled_binary",
    });

    await storage.assets.create({
      id: assetId,
      assessment_id: assessmentId,
      parent_asset_id: null,
      name: "idempotent_bin",
      type: "compiled_binary",
      path: "/bin/idempotent_bin",
      digest: { sha256: "d".repeat(64) },
      architecture: "x86_64",
      version: null,
      environment: null,
      tags: ["executable"],
      metadata: { buffer: elfBuf },
      created_at: Date.now(),
    });

    const task: TaskRecord = {
      id: "task_idem_1",
      assessment_id: assessmentId,
      task_type: "binary_analysis",
      title: "Idempotent task",
      description: "Testing idempotency",
      asset_id: assetId,
      priority: "high",
      status: "open",
      blocked_by: [],
      fencing_token: 1,
      cas_version: 0,
      claim: null,
      result: null,
      metadata: { buffer: elfBuf },
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    const workerInstance = new BinaryAnalysisWorker(assessmentId, storage, projector);

    // Pass 1: Initial execution
    const res1 = await workerInstance.handleBinaryAnalysisTask(task, null);
    const initialFindings = await storage.findings.listByAssessment(assessmentId);
    expect(initialFindings.ok).toBe(true);
    const count1 = initialFindings.ok ? initialFindings.value.length : 0;
    expect(count1).toBeGreaterThanOrEqual(1);

    // Pass 2: Re-execution returns cached execution result
    const res2 = await workerInstance.handleBinaryAnalysisTask(task, null);
    expect(res2.assetId).toBe(res1.assetId);

    const pass2Findings = await storage.findings.listByAssessment(assessmentId);
    expect(pass2Findings.ok).toBe(true);
    if (pass2Findings.ok) {
      expect(pass2Findings.value.length).toBe(count1); // No duplicate findings added
    }

    await workerInstance.stop();
  });

  it("aborts execution immediately when AbortSignal is cancelled", async () => {
    const workerInstance = new BinaryAnalysisWorker(assessmentId, storage, projector);
    const abortCtrl = new AbortController();
    abortCtrl.abort(); // Cancel before execution

    const task: TaskRecord = {
      id: "cancelled_task",
      assessment_id: assessmentId,
      task_type: "binary_analysis",
      title: "Cancelled task",
      description: "Testing cancellation",
      asset_id: "ast_dummy" as any,
      priority: "high",
      status: "open",
      blocked_by: [],
      fencing_token: 1,
      cas_version: 0,
      claim: null,
      result: null,
      metadata: {},
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    await expect(
      workerInstance.handleBinaryAnalysisTask(task, null, abortCtrl.signal),
    ).rejects.toThrow("aborted");

    await workerInstance.stop();
  });
});
