import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { computeAssetId } from "../../../src/domain/security/asset.js";
import type { AssessmentId } from "../../../src/domain/security/assessment.js";
import { SqliteBlackboardStorage } from "../../../src/security/blackboard/SqliteBlackboardStorage.js";
import { SandboxedExtractor } from "../../../src/security/firmware/SandboxedExtractor.js";
import { FirmwareInventoryService } from "../../../src/security/firmware/FirmwareInventoryService.js";

async function main() {
  const sampleWinPath = "C:\\Users\\acer\\REA-EVALUATION-LAB\\firmware-corpus\\openwrt-23.05.0-ath79-generic-rootfs.squashfs";
  console.log(`[INVENTORY] Starting real OpenWrt inventory and task scheduling test...`);

  const workDir = await mkdtemp(join(tmpdir(), "rea-openwrt-inv-"));
  const dbPath = join(workDir, "blackboard.db");
  const journalPath = join(workDir, "blackboard-journal.jsonl");

  const assessmentId = "asm_openwrt_test_00000000000000000000000000000000000000000000000000000" as AssessmentId;
  const storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });

  await storage.assessments.create({
    id: assessmentId,
    name: "OpenWrt Real Firmware Assessment",
    status: "in_progress",
    objective: {
      title: "Real SquashFS Evaluation",
      target_technologies: ["Linux", "MIPS", "SquashFS"],
      compliance_frameworks: [],
      focus_areas: ["Firmware"],
      depth: "standard",
    },
    authorization: {
      allowed_targets: ["openwrt-rootfs.squashfs"],
      denied_targets: [],
      authorized_by: "Benchmark Auditor",
      authorization_reference: "AUTH-EVAL-01",
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
  });

  const rootAssetId = computeAssetId({
    name: "openwrt-23.05.0-ath79-generic-rootfs.squashfs",
    type: "firmware_image",
  });

  await storage.assets.create({
    id: rootAssetId,
    assessment_id: assessmentId,
    parent_asset_id: null,
    name: "openwrt-23.05.0-ath79-generic-rootfs.squashfs",
    type: "firmware_image",
    path: sampleWinPath,
    digest: { sha256: "b".repeat(64) },
    architecture: null,
    version: "23.05.0",
    environment: null,
    tags: ["firmware", "squashfs", "mips"],
    metadata: {},
    created_at: Date.now(),
  });

  console.log(`[EXTRACT] Extracting real firmware image with SandboxedExtractor...`);
  const extractor = new SandboxedExtractor();
  const extractRes = await extractor.extract(sampleWinPath);
  if (!extractRes.ok) {
    console.error("Extraction failed:", extractRes.error);
    process.exit(1);
  }

  const summary = extractRes.value;
  console.log(`[EXTRACT DONE] ${summary.entries.length} validated entries.`);

  console.log(`[INVENTORY] Ingesting into FirmwareInventoryService...`);
  const invService = new FirmwareInventoryService(storage);
  const invRes = await invService.inventoryAndSchedule(
    assessmentId,
    rootAssetId,
    summary.sandboxDir,
    summary.format,
  );

  if (!invRes.ok) {
    console.error("Inventory failed:", invRes.error);
    process.exit(1);
  }

  const invSummary = invRes.value;
  console.log("\n================ INVENTORY SUMMARY ================");
  console.log(`Total Assets Created:       ${invSummary.assetsCreated.length}`);
  console.log(`Files Processed:            ${invSummary.extractedFilesCount}`);
  console.log(`Total Bytes Extracted:      ${invSummary.totalBytesExtracted}`);
  console.log(`Tasks Created:              ${invSummary.tasksCreated.length}`);
  console.log(`Observations Created:       ${invSummary.observationsCreated.length}`);
  console.log("===================================================\n");

  // Inspect tasks scheduled
  const allTasksRes = await storage.tasks.listByAssessment(assessmentId);
  if (!allTasksRes.ok) {
    console.error("Failed to list tasks:", allTasksRes.error);
    process.exit(1);
  }

  const tasks = allTasksRes.value;
  console.log(`Total Tasks in Blackboard: ${tasks.length}`);
  const typeCounts = new Map<string, number>();
  for (const t of tasks) {
    typeCounts.set(t.task_type, (typeCounts.get(t.task_type) ?? 0) + 1);
  }
  for (const [t, c] of typeCounts) {
    console.log(`- Task [${t}]: ${c}`);
  }

  // Verify asset reference integrity for all 374 tasks
  let validAssetReferences = 0;
  for (const t of tasks) {
    const assetRes = await storage.assets.findById(assessmentId, t.asset_id);
    if (!assetRes.ok || !assetRes.value) {
      console.error(`Task ${t.id} references non-existent asset: ${t.asset_id}`);
      process.exit(1);
    }
    validAssetReferences++;
  }
  console.log(`Verified ${validAssetReferences}/${tasks.length} task asset references exist in Blackboard.`);

  if (tasks.length !== 374 || validAssetReferences !== 374) {
    console.error(`Expected exactly 374 binary analysis tasks, found ${tasks.length}`);
    process.exit(1);
  }

  storage.close();
  await extractor.cleanupSandbox(summary.sandboxDir);
  await rm(workDir, { recursive: true, force: true });
  console.log(`[PASS] Inventory, asset ingestion, and task scheduling verified!`);
}

main().catch((e) => {
  console.error("Unhandled error:", e);
  process.exit(1);
});
