import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteBlackboardStorage } from "./SqliteBlackboardStorage.js";
import type { AssessmentId } from "../../domain/security/assessment.js";
import type { AssetId } from "../../domain/security/asset.js";
import type { TaskRecord, TaskClaim, AssessmentRecord } from "../../domain/security/blackboard/types.js";

describe("Task Dependencies & Automated Unblocking (T14)", () => {
  let tempDir: string;
  let storage: SqliteBlackboardStorage;

  const assessmentId = "asm_deps_0000000000000000000000000000000000000000000000000000000000" as AssessmentId;
  const assetId = "ast_target_00000000000000000000000000000000000000000000000000000000" as AssetId;

  beforeEach(async () => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-task-deps-"));
    const dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath, assessmentId });

    const asm: AssessmentRecord = {
      id: assessmentId,
      name: "Dependency Test Assessment",
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

  it("T14: blocks downstream task claims until upstream tasks complete, then unblocks automatically", async () => {
    // 1. Task A: Extraction
    const taskA: TaskRecord = {
      id: "task_A_extraction",
      assessment_id: assessmentId,
      task_type: "firmware_extraction",
      title: "Extract Firmware Image",
      description: "Extract rootfs filesystem",
      asset_id: assetId,
      priority: "critical",
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

    // 2. Task B: Decompilation (Blocked by Task A)
    const taskB: TaskRecord = {
      id: "task_B_decompilation",
      assessment_id: assessmentId,
      task_type: "binary_analysis",
      title: "Decompile Kernel Binary",
      description: "Decompile /bin/busybox",
      asset_id: assetId,
      priority: "high",
      status: "open", // Will be created as 'blocked' because task_A is not completed
      blocked_by: ["task_A_extraction"],
      fencing_token: 1,
      cas_version: 1,
      claim: null,
      result: null,
      metadata: {},
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    await storage.tasks.create(taskA);
    const createdB = await storage.tasks.create(taskB);
    expect(createdB.ok).toBe(true);
    if (!createdB.ok) return;
    expect(createdB.value.status).toBe("blocked");

    // 3. Worker tries to claim Task B while Task A is open: MUST FAIL
    const workerClaim: TaskClaim = {
      agent_id: "worker_ghidra_01",
      host_id: "host_local",
      pid: 2000,
      process_start_time: Date.now(),
      rea_run_id: "run_001",
      claimed_at: Date.now(),
      lease_until: Date.now() + 60000,
    };

    const claimBBeforeA = await storage.tasks.claimTask(assessmentId, "task_B_decompilation", workerClaim, 1);
    expect(claimBBeforeA.ok).toBe(false);
    if (claimBBeforeA.ok) return;
    expect(claimBBeforeA.error.code).toBe("TASK_BLOCKED");
    if (claimBBeforeA.error.code === "TASK_BLOCKED") {
      expect(claimBBeforeA.error.unresolvedDependencies).toContain("task_A_extraction");
    }

    // 4. Worker claims and completes Task A
    const claimARes = await storage.tasks.claimTask(assessmentId, "task_A_extraction", workerClaim, 1);
    expect(claimARes.ok).toBe(true);
    if (!claimARes.ok) return;
    const tokenA = claimARes.value.fencing_token;

    const completeARes = await storage.tasks.completeTask(
      assessmentId,
      "task_A_extraction",
      tokenA,
      { extracted_files: ["/bin/busybox", "/etc/passwd"] },
    );
    expect(completeARes.ok).toBe(true);

    // 5. Verify Task B is automatically unblocked!
    const checkB = await storage.tasks.getById(assessmentId, "task_B_decompilation");
    expect(checkB.ok).toBe(true);
    if (!checkB.ok) return;
    expect(checkB.value?.status).toBe("open");

    // 6. Worker can now claim Task B successfully
    const claimBAfterA = await storage.tasks.claimTask(assessmentId, "task_B_decompilation", workerClaim, checkB.value!.cas_version);
    expect(claimBAfterA.ok).toBe(true);
    if (!claimBAfterA.ok) return;
    expect(claimBAfterA.value.status).toBe("claimed");
    expect(claimBAfterA.value.claim?.agent_id).toBe("worker_ghidra_01");
  });
});

