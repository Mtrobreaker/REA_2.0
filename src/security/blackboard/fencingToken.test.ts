import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteBlackboardStorage } from "./SqliteBlackboardStorage.js";
import type { AssessmentId } from "../../domain/security/assessment.js";
import type { AssetId } from "../../domain/security/asset.js";
import type { TaskRecord, TaskClaim, AssessmentRecord } from "../../domain/security/blackboard/types.js";

describe("Fencing-Token Lease Recovery & Stale Worker Rejection (T22)", () => {
  let tempDir: string;
  let storage: SqliteBlackboardStorage;

  const assessmentId = "asm_fencing_0000000000000000000000000000000000000000000000000000000" as AssessmentId;
  const assetId = "ast_target_00000000000000000000000000000000000000000000000000000000" as AssetId;

  beforeEach(async () => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-fencing-test-"));
    const dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath, assessmentId });

    const asm: AssessmentRecord = {
      id: assessmentId,
      name: "Fencing Test Assessment",
      status: "active",
      objective: { title: "Test", target_technologies: [], compliance_frameworks: [], focus_areas: [], depth: "standard" },
      authorization: { allowed_targets: ["target.bin"], denied_targets: [], authorized_by: "Test", authorization_reference: "REF", valid_until: new Date().toISOString(), allow_active_verification: false },
      metrics: { total_assets: 1, total_findings: 0, critical_findings: 0, high_findings: 0, medium_findings: 0, low_findings: 0, info_findings: 0, verified_findings: 0 },
      created_at: Date.now(),
      updated_at: Date.now(),
    };
    await storage.assessments.create(asm);
  });

  afterEach(() => {
    storage.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("T22: rejects stale worker attempting to submit task result with expired fencing token", async () => {
    const taskId = "task_fencing_contention_001";
    const initialTask: TaskRecord = {
      id: taskId,
      assessment_id: assessmentId,
      task_type: "deep_decompilation",
      title: "Analyze Crypto Routine",
      description: "Decompile AES decryption key schedule",
      asset_id: assetId,
      priority: "high",
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

    await storage.tasks.create(initialTask);

    // 1. Worker 1 claims task with short lease
    const now = Date.now();
    const claim1: TaskClaim = {
      agent_id: "worker_1_lagging",
      host_id: "host_worker_1",
      pid: 1111,
      process_start_time: now,
      rea_run_id: "run_worker_1",
      claimed_at: now,
      lease_until: now + 50, // Expires in 50ms
    };

    const claim1Res = await storage.tasks.claimTask(assessmentId, taskId, claim1, 1);
    expect(claim1Res.ok).toBe(true);
    if (!claim1Res.ok) return;

    const worker1FencingToken = claim1Res.value.fencing_token;
    expect(worker1FencingToken).toBe(2);

    // 2. Simulate Worker 1 hanging / GC pause past lease expiration
    await new Promise((resolve) => setTimeout(resolve, 80));

    // 3. Supervisor reaps expired lease
    const reapRes = await storage.tasks.reapExpiredLeases(assessmentId, Date.now());
    expect(reapRes.ok).toBe(true);
    if (!reapRes.ok) return;
    expect(reapRes.value).toBe(1);

    // Inspect task after reap: status is open, fencing_token incremented to 3
    const reapedTask = await storage.tasks.getById(assessmentId, taskId);
    expect(reapedTask.ok).toBe(true);
    if (!reapedTask.ok) return;
    expect(reapedTask.value?.status).toBe("open");
    expect(reapedTask.value?.fencing_token).toBe(3);

    // 4. Worker 2 claims the task
    const claim2: TaskClaim = {
      agent_id: "worker_2_healthy",
      host_id: "host_worker_2",
      pid: 2222,
      process_start_time: Date.now(),
      rea_run_id: "run_worker_2",
      claimed_at: Date.now(),
      lease_until: Date.now() + 60000,
    };

    const claim2Res = await storage.tasks.claimTask(assessmentId, taskId, claim2, reapedTask.value!.cas_version);
    expect(claim2Res.ok).toBe(true);
    if (!claim2Res.ok) return;

    const worker2FencingToken = claim2Res.value.fencing_token;
    expect(worker2FencingToken).toBe(4);
    expect(claim2Res.value.claim?.agent_id).toBe("worker_2_healthy");

    // 5. Worker 1 wakes up and attempts to submit result with stale token (2)
    // MUST BE STRICTLY REJECTED WITH STALE_FENCING_TOKEN
    const staleSubmitRes = await storage.tasks.completeTask(
      assessmentId,
      taskId,
      worker1FencingToken, // Stale token 2!
      { decompiled_bytes: "stale data from lagging worker" },
    );

    expect(staleSubmitRes.ok).toBe(false);
    if (staleSubmitRes.ok) return;
    expect(staleSubmitRes.error.code).toBe("STALE_FENCING_TOKEN");
    if (staleSubmitRes.error.code === "STALE_FENCING_TOKEN") {
      expect(staleSubmitRes.error.submittedToken).toBe(worker1FencingToken);
      expect(staleSubmitRes.error.expectedToken).toBe(worker2FencingToken);
    }

    // Verify task is STILL claimed by Worker 2, not overwritten by Worker 1
    const taskStillWorker2 = await storage.tasks.getById(assessmentId, taskId);
    expect(taskStillWorker2.ok).toBe(true);
    if (!taskStillWorker2.ok) return;
    expect(taskStillWorker2.value?.status).toBe("claimed");
    expect(taskStillWorker2.value?.claim?.agent_id).toBe("worker_2_healthy");
    expect(taskStillWorker2.value?.result).toBeNull();

    // 6. Worker 2 submits result with valid token 4: SUCCEEDS
    const validSubmitRes = await storage.tasks.completeTask(
      assessmentId,
      taskId,
      worker2FencingToken,
      { decompiled_bytes: "valid verified disassembly from worker 2" },
    );

    expect(validSubmitRes.ok).toBe(true);
    if (!validSubmitRes.ok) return;
    expect(validSubmitRes.value.status).toBe("completed");
    expect((validSubmitRes.value.result as any).decompiled_bytes).toContain("worker 2");
  });
});

