import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { SqliteBlackboardStorage } from "../../../security/blackboard/SqliteBlackboardStorage.js";
import { ContextProjector } from "../blackboard/ContextProjector.js";
import { AgentWorker } from "./AgentWorker.js";
import { ChiefSecurityOrchestrator } from "./ChiefSecurityOrchestrator.js";
import type { TaskRecord, AssessmentRecord, AssetRecord } from "../../../domain/security/blackboard/types.js";

function setupTempDir(): string {
  return mkdtempSync(join(tmpdir(), "rea-phase4-checks-"));
}

async function initAssessment(storage: SqliteBlackboardStorage, assessmentId: string, assetId: string) {
  const assessment: AssessmentRecord = {
    id: assessmentId as any,
    name: "Phase 4 Integration Assessment",
    status: "active",
    objective: {
      title: "Integration Check",
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

function makeTask(id: string, assessmentId: string, assetId: string, taskType: string): TaskRecord {
  return {
    id,
    assessment_id: assessmentId as any,
    task_type: taskType,
    title: `Task ${id}`,
    description: `Desc ${id}`,
    asset_id: assetId as any,
    priority: "normal",
    status: "open",
    blocked_by: [],
    fencing_token: 1,
    cas_version: 1,
    claim: null,
    result: null,
    metadata: {},
    created_at: Date.now(),
    updated_at: Date.now(),
  };
}

describe("Phase 4 Focused Check 1: Subprocess Termination on Task Timeout", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentId = "asm_timeout_check" as any;
  const assetId = "ast_timeout_asset" as any;

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

  it("propagates task execution timeout through AbortSignal and aborts subprocess", async () => {
    await storage.tasks.create(makeTask("task_subproc_timeout", assessmentId, assetId, "hang_test"));

    let subprocessAborted = false;

    const worker = new AgentWorker(
      {
        agentId: "subproc_worker",
        assessmentId,
        capabilities: ["hang_test"],
        taskTimeoutMs: 60, // Short timeout
        pollIntervalMs: 20,
      },
      storage,
      projector,
      async (task, context, signal) => {
        // Simulates a long-running OwnedCommand / subprocess listening to signal
        return new Promise((resolve, reject) => {
          signal.addEventListener("abort", () => {
            subprocessAborted = true;
            reject(new Error("Subprocess aborted by supervisor deadline"));
          });
          // Intentionally do not resolve to trigger timeout
        });
      },
    );

    await worker.start();
    await worker.pollOnce();

    // Wait for timeout to fire
    await new Promise((r) => setTimeout(r, 120));

    expect(subprocessAborted).toBe(true);

    await worker.stop();
  });
});

describe("Phase 4 Focused Check 2: Actual OS-Process Crash Recovery", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentId = "asm_os_crash" as any;
  const assetId = "ast_os_asset" as any;

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

  it("spawns real OS child process, kills it with SIGKILL, coordinator reaps lease and 2nd worker completes task", async () => {
    const orchestrator = new ChiefSecurityOrchestrator(storage, { maxConcurrency: 4, reapIntervalMs: 50 });
    await storage.tasks.create(makeTask("t_os_crash_1", assessmentId, assetId, "os_proc_task"));

    // Spawn an actual OS process (Node.js) that runs and holds open handles
    const child = spawn(process.execPath, [
      "-e",
      "setInterval(() => {}, 1000);",
    ]);

    expect(child.pid).toBeDefined();
    const childPid = child.pid!;

    // Claim task on behalf of the real child process
    const now = Date.now();
    const claimRes = await storage.tasks.claimTask(
      assessmentId,
      "t_os_crash_1",
      {
        agent_id: "os_proc_worker_1",
        host_id: "host-os",
        pid: childPid,
        process_start_time: now,
        rea_run_id: "run-os-1",
        claimed_at: now,
        lease_until: now + 50, // 50ms lease
      },
      1,
    );
    expect(claimRes.ok).toBe(true);

    // Hard kill the real OS process
    child.kill("SIGKILL");

    // Wait for lease to expire
    await new Promise((r) => setTimeout(r, 70));

    // Orchestrator reaps the crashed worker's expired lease
    const reaped = await orchestrator.reapStaleWorkers(assessmentId);
    expect(reaped).toBe(1);

    // Another healthy worker spins up, claims and finishes the task
    let healthyCompleted = false;
    const worker2 = new AgentWorker(
      { agentId: "healthy_os_worker_2", assessmentId, capabilities: ["os_proc_task"], pollIntervalMs: 20 },
      storage,
      projector,
      async () => {
        healthyCompleted = true;
        return { recovered: true };
      },
    );

    orchestrator.registerWorker(worker2);
    await worker2.start();
    await worker2.pollOnce();

    await new Promise((r) => setTimeout(r, 60));
    expect(healthyCompleted).toBe(true);

    const completed = await storage.tasks.getById(assessmentId, "t_os_crash_1");
    expect(completed.ok && completed.value?.status).toBe("completed");

    await orchestrator.shutdown();
  });
});

describe("Phase 4 Focused Check 3: State Persistence Across Application Restart", () => {
  let tempDir: string;
  let dbPath: string;
  const assessmentId = "asm_restart_persist" as any;
  const assetId = "ast_restart_asset" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    const storage = new SqliteBlackboardStorage({ dbPath });
    await initAssessment(storage, assessmentId, assetId);
    storage.close();
  });

  afterEach(() => {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("persists retry counts, dead-letter status, and fencing tokens across restart", async () => {
    // 1. Session A: create task, retry multiple times to dead-letter, advance fencing token
    let storage = new SqliteBlackboardStorage({ dbPath });
    const task = makeTask("t_persist_1", assessmentId, assetId, "persist_task");
    await storage.tasks.create(task);

    // Retry 1
    await storage.tasks.retryTask(assessmentId, "t_persist_1", "error 1", 2);
    // Retry 2
    await storage.tasks.retryTask(assessmentId, "t_persist_1", "error 2", 2);
    // Retry 3 (exceeds maxRetries 2 -> dead-lettered)
    const deadLetterRes = await storage.tasks.retryTask(assessmentId, "t_persist_1", "error 3", 2);
    expect(deadLetterRes.ok && deadLetterRes.value.deadLetter).toBe(true);

    const taskBeforeRestart = await storage.tasks.getById(assessmentId, "t_persist_1");
    expect(taskBeforeRestart.ok && taskBeforeRestart.value?.status).toBe("failed");
    const fencingTokenBefore = taskBeforeRestart.ok ? taskBeforeRestart.value!.fencing_token : 0;
    const retryCountBefore = taskBeforeRestart.ok ? taskBeforeRestart.value!.metadata.retry_count : 0;

    // Simulate process shutdown
    storage.close();

    // 2. Session B: restart application and open database
    storage = new SqliteBlackboardStorage({ dbPath });
    const taskAfterRestart = await storage.tasks.getById(assessmentId, "t_persist_1");
    expect(taskAfterRestart.ok).toBe(true);
    if (taskAfterRestart.ok && taskAfterRestart.value) {
      expect(taskAfterRestart.value.status).toBe("failed");
      expect(taskAfterRestart.value.metadata.dead_letter).toBe(true);
      expect(taskAfterRestart.value.metadata.retry_count).toBe(retryCountBefore);
      expect(taskAfterRestart.value.fencing_token).toBe(fencingTokenBefore);
      expect((taskAfterRestart.value.result as any)?.retries_exhausted).toBe(true);
    }

    // Verify fresh orchestrator starts with 0 active workers (no concurrency leakage)
    const orchestrator = new ChiefSecurityOrchestrator(storage, { maxConcurrency: 4 });
    const snapshot = await orchestrator.getObservabilitySnapshot(assessmentId);
    expect(snapshot.ok).toBe(true);
    if (snapshot.ok) {
      expect(snapshot.value.active_workers).toBe(0);
      expect(snapshot.value.dead_letter_tasks).toBe(1);
    }

    storage.close();
  });
});

