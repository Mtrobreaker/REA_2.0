import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteBlackboardStorage } from "../../../security/blackboard/SqliteBlackboardStorage.js";
import { ContextProjector } from "../blackboard/ContextProjector.js";
import { AgentWorker } from "./AgentWorker.js";
import type { TaskRecord, AssessmentRecord, AssetRecord } from "../../../domain/security/blackboard/types.js";

function setupTempDir(): string {
  return mkdtempSync(join(tmpdir(), "rea-worker-test-"));
}

async function initAssessmentAndAsset(storage: SqliteBlackboardStorage, assessmentId: string, assetId: string) {
  const assessment: AssessmentRecord = {
    id: assessmentId as any,
    name: "Worker Assessment",
    status: "active",
    objective: {
      title: "Worker Test",
      target_technologies: ["Linux"],
      compliance_frameworks: [],
      focus_areas: [],
      depth: "standard",
    },
    authorization: {
      allowed_targets: ["test.bin"],
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
    name: "test.bin",
    type: "compiled_binary",
    path: "/bin/test.bin",
    digest: { sha256: "sha256-test" },
    architecture: "ARMv7",
    version: "1.0",
    environment: { platform: "arm-linux" },
    tags: ["binary"],
    metadata: {},
    created_at: Date.now(),
  };
  await storage.assets.create(asset);
}

function makeTask(id: string, assessmentId: string, assetId: string, taskType: string, priority: "normal" | "high" | "critical" = "normal"): TaskRecord {
  return {
    id,
    assessment_id: assessmentId as any,
    task_type: taskType,
    title: `Task ${id}`,
    description: `Desc ${id}`,
    asset_id: assetId as any,
    priority,
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

describe("AgentWorker: Registration & Capability-based Discovery", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentId = "asm_worker_reg" as any;
  const assetId = "ast_worker_asset" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    projector = new ContextProjector({ blackboard: storage });
    await initAssessmentAndAsset(storage, assessmentId, assetId);
  });

  afterEach(() => {
    storage.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("registers worker with capabilities and discovers matching tasks", async () => {
    const executedTasks: string[] = [];
    const worker = new AgentWorker(
      {
        agentId: "binary_analyst_1",
        assessmentId,
        capabilities: ["binary_decompilation"],
        pollIntervalMs: 20,
      },
      storage,
      projector,
      async (task) => {
        executedTasks.push(task.id);
        return { disassembled: true };
      },
    );

    await worker.start();

    // Verify registration in AgentRegistryRepository
    const agent = await storage.agents.get(assessmentId, "binary_analyst_1");
    expect(agent.ok).toBe(true);
    expect(agent.ok && agent.value?.capabilities).toContain("binary_decompilation");

    // Submit non-matching task and matching task
    await storage.tasks.create(makeTask("t_extract", assessmentId, assetId, "firmware_extraction"));
    await storage.tasks.create(makeTask("t_decompile", assessmentId, assetId, "binary_decompilation"));

    // Trigger poll
    const claimed = await worker.pollOnce();
    expect(claimed).toBe(true);

    // Wait for async execution
    await new Promise((r) => setTimeout(r, 80));

    expect(executedTasks).toContain("t_decompile");
    expect(executedTasks).not.toContain("t_extract");

    // Verify task state in database is completed
    const completedTask = await storage.tasks.getById(assessmentId, "t_decompile");
    expect(completedTask.ok && completedTask.value?.status).toBe("completed");

    await worker.stop();
  });
});

describe("AgentWorker: Atomic CAS Contention & Stale Worker Recovery", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentId = "asm_cas_race" as any;
  const assetId = "ast_cas_asset" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    projector = new ContextProjector({ blackboard: storage });
    await initAssessmentAndAsset(storage, assessmentId, assetId);
  });

  afterEach(() => {
    storage.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("two competing workers race for the same task; exactly one claims it atomically", async () => {
    const task = makeTask("t_race_1", assessmentId, assetId, "static_scan");
    await storage.tasks.create(task);

    const winners: string[] = [];

    const workerA = new AgentWorker(
      { agentId: "agent_A", assessmentId, capabilities: ["static_scan"], pollIntervalMs: 50 },
      storage,
      projector,
      async (t) => {
        winners.push("agent_A");
        return { agent: "A" };
      },
    );

    const workerB = new AgentWorker(
      { agentId: "agent_B", assessmentId, capabilities: ["static_scan"], pollIntervalMs: 50 },
      storage,
      projector,
      async (t) => {
        winners.push("agent_B");
        return { agent: "B" };
      },
    );

    await workerA.start();
    await workerB.start();

    // Both workers attempt poll simultaneously
    const [resA, resB] = await Promise.all([workerA.pollOnce(), workerB.pollOnce()]);

    // Exactly one worker must succeed in claiming
    expect(Number(resA) + Number(resB)).toBe(1);

    await new Promise((r) => setTimeout(r, 100));
    expect(winners.length).toBe(1);

    await workerA.stop();
    await workerB.stop();
  });

  it("reaps expired leases, increments fencing token, and rejects stale worker submission", async () => {
    const task = makeTask("t_stale_1", assessmentId, assetId, "deep_decompilation");
    await storage.tasks.create(task);

    // Worker claims task with short 100ms lease
    const claimRes = await storage.tasks.claimTask(
      assessmentId,
      "t_stale_1",
      {
        agent_id: "slow_worker",
        host_id: "host",
        pid: 1234,
        process_start_time: 1000,
        rea_run_id: "run1",
        claimed_at: Date.now(),
        lease_until: Date.now() + 50, // Short lease
      },
      1,
    );
    expect(claimRes.ok).toBe(true);
    const staleFencingToken = claimRes.ok ? claimRes.value.fencing_token : 0;

    // Simulate time passing beyond lease expiry
    await new Promise((r) => setTimeout(r, 70));

    // Reaper reclaims the expired task
    const reapedCount = await storage.tasks.reapExpiredLeases(assessmentId, Date.now());
    expect(reapedCount.ok && reapedCount.value).toBe(1);

    // Verify task is re-opened and fencing token incremented
    const reapedTask = await storage.tasks.getById(assessmentId, "t_stale_1");
    expect(reapedTask.ok && reapedTask.value?.status).toBe("open");
    expect(reapedTask.ok && reapedTask.value?.fencing_token).toBeGreaterThan(staleFencingToken);

    // Now zombie worker attempts to submit with the old fencing token
    const staleSubmission = await storage.tasks.completeTask(
      assessmentId,
      "t_stale_1",
      staleFencingToken,
      { output: "zombie data" },
    );
    expect(staleSubmission.ok).toBe(false);
    if (!staleSubmission.ok) {
      expect(staleSubmission.error.code).toBe("STALE_FENCING_TOKEN");
    }
  });
});

describe("AgentWorker: Bounded Retries & Dead-Letter Queue", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentId = "asm_retry_test" as any;
  const assetId = "ast_retry_asset" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    projector = new ContextProjector({ blackboard: storage });
    await initAssessmentAndAsset(storage, assessmentId, assetId);
  });

  afterEach(() => {
    storage.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("retries failed tasks with backoff and moves to dead letter queue upon exhausting retries", async () => {
    const task = makeTask("t_flaky", assessmentId, assetId, "flaky_task");
    await storage.tasks.create(task);

    let attempts = 0;
    const worker = new AgentWorker(
      {
        agentId: "flaky_worker",
        assessmentId,
        capabilities: ["flaky_task"],
        maxRetries: 2, // Max 2 retries
        pollIntervalMs: 20,
      },
      storage,
      projector,
      async () => {
        attempts++;
        throw new Error("Simulated flaky parser crash");
      },
    );

    await worker.start();

    // 1st attempt
    await worker.pollOnce();
    await new Promise((r) => setTimeout(r, 60));

    // 2nd attempt (1st retry)
    await worker.pollOnce();
    await new Promise((r) => setTimeout(r, 60));

    // 3rd attempt (2nd retry -> exhaustion)
    await worker.pollOnce();
    await new Promise((r) => setTimeout(r, 60));

    const finalTask = await storage.tasks.getById(assessmentId, "t_flaky");
    expect(finalTask.ok).toBe(true);
    if (finalTask.ok && finalTask.value) {
      expect(finalTask.value.status).toBe("failed");
      expect(finalTask.value.metadata.dead_letter).toBe(true);
      expect((finalTask.value.result as any)?.retries_exhausted).toBe(true);
    }

    await worker.stop();
  });
});

