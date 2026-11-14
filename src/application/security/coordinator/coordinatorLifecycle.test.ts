import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteBlackboardStorage } from "../../../security/blackboard/SqliteBlackboardStorage.js";
import { ContextProjector } from "../blackboard/ContextProjector.js";
import { AgentWorker } from "./AgentWorker.js";
import { ChiefSecurityOrchestrator } from "./ChiefSecurityOrchestrator.js";
import type { TaskRecord, AssessmentRecord, AssetRecord } from "../../../domain/security/blackboard/types.js";

function setupTempDir(): string {
  return mkdtempSync(join(tmpdir(), "rea-lifecycle-test-"));
}

async function initAssessment(storage: SqliteBlackboardStorage, assessmentId: string, assetId: string) {
  const assessment: AssessmentRecord = {
    id: assessmentId as any,
    name: "Lifecycle Assessment",
    status: "active",
    objective: {
      title: "Lifecycle Test",
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

describe("Coordinator Lifecycle: Lease Renewal & Maximum 5-Renewal Ceiling", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  const assessmentId = "asm_renew_ceil" as any;
  const assetId = "ast_renew_asset" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    await initAssessment(storage, assessmentId, assetId);
  });

  afterEach(() => {
    storage.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("extends lease on renewal and rejects 6th renewal exceeding the 5-renewal ceiling", async () => {
    await storage.tasks.create(makeTask("t_renew_ceil", assessmentId, assetId, "long_task"));

    const claimRes = await storage.tasks.claimTask(
      assessmentId,
      "t_renew_ceil",
      {
        agent_id: "long_agent",
        host_id: "host",
        pid: 9999,
        process_start_time: 1000,
        rea_run_id: "run-long",
        claimed_at: Date.now(),
        lease_until: Date.now() + 5000,
      },
      1,
    );
    expect(claimRes.ok).toBe(true);
    const token = claimRes.ok ? claimRes.value.fencing_token : 0;

    // Renew 5 times successfully
    for (let i = 1; i <= 5; i++) {
      const renewRes = await storage.tasks.renewLease(assessmentId, "t_renew_ceil", "long_agent", token, 5000, 5);
      expect(renewRes.ok).toBe(true);
      if (renewRes.ok) {
        expect(renewRes.value.metadata.renewal_count).toBe(i);
      }
    }

    // 6th renewal attempt must be rejected per blueprint ceiling
    const overflowRenew = await storage.tasks.renewLease(assessmentId, "t_renew_ceil", "long_agent", token, 5000, 5);
    expect(overflowRenew.ok).toBe(false);
    if (!overflowRenew.ok) {
      expect(overflowRenew.error.code).toBe("LEASE_RENEWAL_EXCEEDED");
    }
  });
});

describe("Coordinator Lifecycle: Worker Crash & Task Recovery", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentId = "asm_crash_rec" as any;
  const assetId = "ast_crash_asset" as any;

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

  it("recovers crashed worker task, allows 2nd worker to claim and complete, rejects zombie", async () => {
    const orchestrator = new ChiefSecurityOrchestrator(storage, { maxConcurrency: 4, reapIntervalMs: 50 });
    await storage.tasks.create(makeTask("t_crash_rec", assessmentId, assetId, "crash_task"));

    // 1. Simulate Worker 1 process claiming task, then abruptly terminating (hard crash)
    const now = Date.now();
    const claimRes = await storage.tasks.claimTask(
      assessmentId,
      "t_crash_rec",
      {
        agent_id: "crashed_worker_1",
        host_id: "host-1",
        pid: 88888, // Dead worker process PID
        process_start_time: 1000,
        rea_run_id: "run-crash",
        claimed_at: now,
        lease_until: now + 50, // Short 50ms lease
      },
      1,
    );
    expect(claimRes.ok).toBe(true);
    const worker1FencingToken = claimRes.ok ? claimRes.value.fencing_token : 0;

    // Verify task is claimed
    const inFlight = await storage.tasks.getById(assessmentId, "t_crash_rec");
    expect(inFlight.ok && inFlight.value?.status).toBe("claimed");

    // 2. Wait for lease to expire
    await new Promise((r) => setTimeout(r, 70));

    // 3. Orchestrator reaps expired lease
    const reaped = await orchestrator.reapStaleWorkers(assessmentId);
    expect(reaped).toBe(1);

    // 4. Worker 2 spins up and claims the recovered task
    let worker2Executed = false;
    const worker2 = new AgentWorker(
      { agentId: "healthy_worker_2", assessmentId, capabilities: ["crash_task"], pollIntervalMs: 20 },
      storage,
      projector,
      async (t) => {
        worker2Executed = true;
        return { recoveredBy: "worker_2" };
      },
    );
    orchestrator.registerWorker(worker2);
    await worker2.start();
    await worker2.pollOnce();

    await new Promise((r) => setTimeout(r, 60));
    expect(worker2Executed).toBe(true);

    const completed = await storage.tasks.getById(assessmentId, "t_crash_rec");
    expect(completed.ok && completed.value?.status).toBe("completed");
    expect(completed.ok && (completed.value?.result as any)?.recoveredBy).toBe("worker_2");

    // 5. Late zombie submission from Worker 1 is rejected
    const zombieSub = await storage.tasks.completeTask(assessmentId, "t_crash_rec", worker1FencingToken, { data: "zombie" });
    expect(zombieSub.ok).toBe(false);
    if (!zombieSub.ok) {
      expect(zombieSub.error.code).toBe("STALE_FENCING_TOKEN");
    }

    await orchestrator.shutdown();
  });
});
