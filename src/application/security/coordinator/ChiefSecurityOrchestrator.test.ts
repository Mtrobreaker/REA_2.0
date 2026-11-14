import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteBlackboardStorage } from "../../../security/blackboard/SqliteBlackboardStorage.js";
import { ContextProjector } from "../blackboard/ContextProjector.js";
import { ChiefSecurityOrchestrator } from "./ChiefSecurityOrchestrator.js";
import { AgentWorker } from "./AgentWorker.js";
import type { TaskRecord, AssessmentRecord, AssetRecord } from "../../../domain/security/blackboard/types.js";

function setupTempDir(): string {
  return mkdtempSync(join(tmpdir(), "rea-orchestrator-test-"));
}

async function initAssessment(storage: SqliteBlackboardStorage, assessmentId: string, assetId: string) {
  const assessment: AssessmentRecord = {
    id: assessmentId as any,
    name: "Orchestrator Assessment",
    status: "active",
    objective: {
      title: "Orchestration Test",
      target_technologies: ["Linux"],
      compliance_frameworks: [],
      focus_areas: [],
      depth: "standard",
    },
    authorization: {
      allowed_targets: ["target.bin"],
      denied_targets: [],
      authorized_by: "secops",
      authorization_reference: "AUTH-1",
      valid_until: new Date(Date.now() + 100000).toISOString(),
      allow_active_verification: false,
    },
    metrics: {
      total_assets: 1,
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
  await storage.assessments.create(assessment);

  const asset: AssetRecord = {
    id: assetId as any,
    assessment_id: assessmentId as any,
    parent_asset_id: null,
    name: "target.bin",
    type: "compiled_binary",
    path: "/bin/target.bin",
    digest: { sha256: "sha256-target" },
    architecture: "ARMv7",
    version: "1.0",
    environment: { platform: "arm-linux" },
    tags: ["binary"],
    metadata: {},
    created_at: Date.now(),
  };
  await storage.assets.create(asset);
}

function createTask(id: string, assessmentId: string, assetId: string, taskType: string, blockedBy: string[] = []): TaskRecord {
  return {
    id,
    assessment_id: assessmentId as any,
    task_type: taskType,
    title: `Task ${id}`,
    description: `Desc ${id}`,
    asset_id: assetId as any,
    priority: "normal",
    status: blockedBy.length > 0 ? "blocked" : "open",
    blocked_by: blockedBy,
    fencing_token: 1,
    cas_version: 1,
    claim: null,
    result: null,
    metadata: {},
    created_at: Date.now(),
    updated_at: Date.now(),
  };
}

describe("ChiefSecurityOrchestrator: Concurrency Bounds & Worker Pool", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentId = "asm_orch_conc" as any;
  const assetId = "ast_orch_asset" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    projector = new ContextProjector({ blackboard: storage });
    await initAssessment(storage, assessmentId, assetId);
  });

  afterEach(() => {
    storage.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("enforces worker concurrency ceiling and rejects registrations exceeding maxConcurrency", () => {
    const orchestrator = new ChiefSecurityOrchestrator(storage, { maxConcurrency: 2 });

    const w1 = new AgentWorker({ agentId: "w1", assessmentId, capabilities: ["scan"] }, storage, projector, async () => ({}));
    const w2 = new AgentWorker({ agentId: "w2", assessmentId, capabilities: ["scan"] }, storage, projector, async () => ({}));
    const w3 = new AgentWorker({ agentId: "w3", assessmentId, capabilities: ["scan"] }, storage, projector, async () => ({}));

    expect(orchestrator.registerWorker(w1).ok).toBe(true);
    expect(orchestrator.registerWorker(w2).ok).toBe(true);

    // 3rd worker registration exceeds ceiling of 2
    const res3 = orchestrator.registerWorker(w3);
    expect(res3.ok).toBe(false);
    if (!res3.ok) {
      expect(res3.error.code).toBe("MAX_CONCURRENCY_EXCEEDED");
    }
  });
});

describe("ChiefSecurityOrchestrator: Task Dependencies & Observation Sharing", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentId = "asm_orch_flow" as any;
  const assetId = "ast_orch_flow_asset" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    projector = new ContextProjector({ blackboard: storage });
    await initAssessment(storage, assessmentId, assetId);
  });

  afterEach(() => {
    storage.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("T14 & T18: schedules dependent tasks upon completion and shares observations across workers", async () => {
    const orchestrator = new ChiefSecurityOrchestrator(storage, { maxConcurrency: 4 });

    // Task A: string extraction -> publishes observation
    // Task B: decompile -> blocked by Task A
    await orchestrator.submitTask(createTask("task_extract", assessmentId, assetId, "string_extraction"));
    await orchestrator.submitTask(createTask("task_decompile", assessmentId, assetId, "decompile", ["task_extract"]));

    let taskBReceivedObservation = false;

    // Worker 1: handles string_extraction and posts observation
    const worker1 = new AgentWorker(
      { agentId: "extractor", assessmentId, capabilities: ["string_extraction"], pollIntervalMs: 20 },
      storage,
      projector,
      async (task) => {
        // Publish observation through orchestrator/blackboard
        await orchestrator.publishObservation({
          assessment_id: assessmentId,
          asset_id: assetId,
          key: "dangerous_function",
          value: { name: "system", offset: "0x1040" },
          confidence: 0.95,
          source_tool: "strings",
          agent_id: "extractor",
          evidence_id: "ev_strings_1",
          created_at: Date.now(),
        });
        return { extracted: 1 };
      },
    );

    // Worker 2: handles decompile, expects to see observation from Task A
    const worker2 = new AgentWorker(
      { agentId: "decompiler", assessmentId, capabilities: ["decompile"], pollIntervalMs: 20 },
      storage,
      projector,
      async (task, context) => {
        // Verify observation from Worker 1 is present in Worker 2's context projection!
        const foundObs = context.relevant_observations.find((o) => o.key === "dangerous_function");
        if (foundObs) {
          taskBReceivedObservation = true;
        }
        return { decompiled: true };
      },
    );

    orchestrator.registerWorker(worker1);
    orchestrator.registerWorker(worker2);

    await orchestrator.start(assessmentId);

    // Poll until both tasks complete
    for (let i = 0; i < 20; i++) {
      await worker1.pollOnce();
      await worker2.pollOnce();
      await new Promise((r) => setTimeout(r, 40));

      const taskB = await storage.tasks.getById(assessmentId, "task_decompile");
      if (taskB.ok && taskB.value?.status === "completed") {
        break;
      }
    }

    expect(taskBReceivedObservation).toBe(true);

    const taskAFinal = await storage.tasks.getById(assessmentId, "task_extract");
    const taskBFinal = await storage.tasks.getById(assessmentId, "task_decompile");
    expect(taskAFinal.ok && taskAFinal.value?.status).toBe("completed");
    expect(taskBFinal.ok && taskBFinal.value?.status).toBe("completed");

    await orchestrator.shutdown();
  });
});

describe("ChiefSecurityOrchestrator: Assessment Isolation & Observability Snapshot", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentAlpha = "asm_orch_alpha" as any;
  const assessmentBeta = "asm_orch_beta" as any;
  const assetAlpha = "ast_alpha" as any;
  const assetBeta = "ast_beta" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    projector = new ContextProjector({ blackboard: storage });
    await initAssessment(storage, assessmentAlpha, assetAlpha);
    await initAssessment(storage, assessmentBeta, assetBeta);
  });

  afterEach(() => {
    storage.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("strictly enforces assessment isolation between autonomous worker pools", async () => {
    const orchestratorAlpha = new ChiefSecurityOrchestrator(storage);

    // Create a task only in Beta
    await storage.tasks.create(createTask("task_beta_only", assessmentBeta, assetBeta, "secret_task"));

    let workerAlphaClaimedBetaTask = false;
    const workerAlpha = new AgentWorker(
      { agentId: "worker_alpha", assessmentId: assessmentAlpha, capabilities: ["secret_task"], pollIntervalMs: 20 },
      storage,
      projector,
      async (task) => {
        if (task.id === "task_beta_only") {
          workerAlphaClaimedBetaTask = true;
        }
        return {};
      },
    );

    orchestratorAlpha.registerWorker(workerAlpha);
    await orchestratorAlpha.start(assessmentAlpha);

    const claimed = await workerAlpha.pollOnce();
    expect(claimed).toBe(false);
    expect(workerAlphaClaimedBetaTask).toBe(false);

    // Beta task remains open and unclaimed
    const betaTask = await storage.tasks.getById(assessmentBeta, "task_beta_only");
    expect(betaTask.ok && betaTask.value?.status).toBe("open");

    await orchestratorAlpha.shutdown();
  });

  it("generates accurate structured observability snapshot", async () => {
    const orchestrator = new ChiefSecurityOrchestrator(storage);
    const worker = new AgentWorker(
      { agentId: "monitor_worker", assessmentId: assessmentAlpha, capabilities: ["task_type_x"], pollIntervalMs: 50 },
      storage,
      projector,
      async () => ({ done: true }),
    );
    orchestrator.registerWorker(worker);
    await orchestrator.start(assessmentAlpha);

    await storage.tasks.create(createTask("task_snap_1", assessmentAlpha, assetAlpha, "task_type_x"));
    await storage.tasks.create(createTask("task_snap_2", assessmentAlpha, assetAlpha, "task_type_y"));

    const snapshotRes = await orchestrator.getObservabilitySnapshot(assessmentAlpha);
    expect(snapshotRes.ok).toBe(true);
    if (!snapshotRes.ok) return;

    const snap = snapshotRes.value;
    expect(snap.assessment_id).toBe(assessmentAlpha);
    expect(snap.registered_agents).toBeGreaterThanOrEqual(1);
    expect(snap.pending_tasks).toBe(2);
    expect(snap.completed_tasks).toBe(0);
    expect(snap.agent_health.length).toBeGreaterThanOrEqual(1);
    expect(snap.agent_health.some((a) => a.agent_id === "monitor_worker")).toBe(true);

    await orchestrator.shutdown();
  });
});

