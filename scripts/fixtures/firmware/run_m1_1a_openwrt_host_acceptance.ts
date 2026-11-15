/* eslint-disable max-lines-per-function */
/**
 * REA M1.1A — Corrected Final OpenWrt 23.05.0 Acceptance Runner
 *
 * Enforces all Step 1 through Step 5 acceptance criteria strictly and fail-closed:
 * 1. Exact target verification (existence, 3,670,016 bytes, SHA-256 91300ba95fd0558097ccd7acb09bb128da2a72543281780807c34c2d5142a4a0).
 * 2. Mandatory reference manifest validation (fails closed if any reference manifest is missing or empty).
 * 3. Full 990 regular-file SHA-256 reconciliation + byte size verification.
 * 4. Full 202 symlink path & target reconciliation + escaping symlink neutralization verification.
 * 5. Full 112 directory + 1 special character device (dev/console) reconciliation + zero unexpected entries check.
 * 6. Full SecurityAssessmentService execution with 15-ELF task budget, verifying ONLY ELF files are scheduled
 *    (0 shell scripts/configs scheduled) and all skipped ELF binaries are truthfully reported.
 * 7. Supervised child worker execution, parent evidence validation, HMAC sealing, and 11 negative security boundary checks.
 * 8. Genuine SQLite cold-restart reconstruction and full parity verification across assets, lineage, hashes, tasks, findings, and coverage.
 * 9. Markdown, JSON, and SARIF report parity verification against persisted SQLite state.
 * 10. All mandatory criteria participate in the final ACCEPTED / NOT ACCEPTED gate decision.
 */
import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { SecurityAssessmentService } from "../../../src/application/security/assessment/SecurityAssessmentService.js";
import { SqliteBlackboardStorage } from "../../../src/security/blackboard/SqliteBlackboardStorage.js";
import { KeyringManager } from "../../../src/security/packboard/secureKeyring.js";
import { SandboxedExtractor } from "../../../src/security/firmware/SandboxedExtractor.js";
import { SquashFsParser } from "../../../src/security/firmware/SquashFsParser.js";
import { BinaryWorkerSupervisor } from "../../../src/security/binary/supervisor/BinaryWorkerSupervisor.js";
import {
  TrustedEvidenceAuthority,
  TrustedEvidenceVerifier,
} from "../../../src/security/binary/evidence/TrustedAnalysisEvidence.js";
import {
  ParentEvidenceValidator,
  type ParentValidationContext,
} from "../../../src/security/binary/evidence/ParentEvidenceValidator.js";
import { VulnerabilityAdjudicationBridge } from "../../../src/security/binary/VulnerabilityAdjudicationBridge.js";
import { computeAssetId } from "../../../src/domain/security/asset.js";
import type { AssessmentId } from "../../../src/domain/security/assessment.js";
import type { BinaryWorkerAnalyzeRequest } from "../../../src/security/binary/ipc/binaryWorkerProtocol.js";
import type { VulnerabilityCandidate } from "../../../src/domain/security/binary/types.js";
import type { BlackboardAssetRecord } from "../../../src/domain/security/blackboard/types.js";

const DEFAULT_OPENWRT_PATH =
  "/tmp/rea_eval_lab/firmware-corpus/openwrt-23.05.0-ath79-generic-rootfs.squashfs";
const EXPECTED_OPENWRT_SHA256 =
  "91300ba95fd0558097ccd7acb09bb128da2a72543281780807c34c2d5142a4a0";
const EXPECTED_OPENWRT_BYTE_SIZE = 3_670_016;
const ELF_TASK_BUDGET = 15;

interface InventoryGroundTruth {
  readonly directories: Set<string>;
  readonly regularFiles: Map<string, number>; // relPath -> byteSize
  readonly symlinks: Map<string, string>; // relPath -> target
  readonly specialFiles: Array<{ path: string; rawLine: string }>;
}

function computeFileSha256Sync(filePath: string): string {
  const buf = readFileSync(filePath);
  return createHash("sha256").update(buf).digest("hex");
}

function loadMandatorySha256Manifest(
  manifestPath: string,
): Map<string, string> {
  if (!existsSync(manifestPath)) {
    throw new Error(
      `FAIL_CLOSED: Mandatory SHA-256 reference manifest missing at ${manifestPath}`,
    );
  }
  const content = readFileSync(manifestPath, "utf8").trim();
  if (!content) {
    throw new Error(
      `FAIL_CLOSED: Mandatory SHA-256 reference manifest is empty at ${manifestPath}`,
    );
  }
  const map = new Map<string, string>();
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const match = trimmed.match(/^([a-fA-F0-9]{64})\s+(.+)$/);
    if (!match || !match[1] || !match[2]) {
      throw new Error(
        `FAIL_CLOSED: Malformed line in SHA-256 manifest: '${trimmed}'`,
      );
    }
    const hash = match[1].toLowerCase();
    const rel = match[2]
      .trim()
      .replace(/^\.\/+/u, "")
      .replace(/^squashfs-root\/?/u, "")
      .replace(/\\/g, "/");
    map.set(rel, hash);
  }
  if (map.size === 0) {
    throw new Error(
      `FAIL_CLOSED: Zero SHA-256 entries parsed from ${manifestPath}`,
    );
  }
  return map;
}

function loadMandatorySymlinkManifest(
  manifestPath: string,
): Map<string, string> {
  if (!existsSync(manifestPath)) {
    throw new Error(
      `FAIL_CLOSED: Mandatory symlink reference manifest missing at ${manifestPath}`,
    );
  }
  const content = readFileSync(manifestPath, "utf8").trim();
  if (!content) {
    throw new Error(
      `FAIL_CLOSED: Mandatory symlink reference manifest is empty at ${manifestPath}`,
    );
  }
  const map = new Map<string, string>();
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const match = trimmed.match(/squashfs-root\/(.+?)\s+->\s+(.+)$/);
    if (!match || !match[1] || !match[2]) {
      throw new Error(
        `FAIL_CLOSED: Malformed symlink line in reference manifest: '${trimmed}'`,
      );
    }
    map.set(match[1].trim().replace(/\\/g, "/"), match[2].trim());
  }
  if (map.size === 0) {
    throw new Error(
      `FAIL_CLOSED: Zero symlink entries parsed from ${manifestPath}`,
    );
  }
  return map;
}

function loadMandatoryUnsquashfsInventory(
  inventoryPath: string,
): InventoryGroundTruth {
  if (!existsSync(inventoryPath)) {
    throw new Error(
      `FAIL_CLOSED: Mandatory unsquashfs inventory missing at ${inventoryPath}`,
    );
  }
  const content = readFileSync(inventoryPath, "utf8").trim();
  if (!content) {
    throw new Error(
      `FAIL_CLOSED: Mandatory unsquashfs inventory is empty at ${inventoryPath}`,
    );
  }

  const directories = new Set<string>();
  const regularFiles = new Map<string, number>();
  const symlinks = new Map<string, string>();
  const specialFiles: Array<{ path: string; rawLine: string }> = [];

  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const typeChar = trimmed[0];

    if (typeChar === "l") {
      const symMatch = trimmed.match(/squashfs-root\/(.+?)\s+->\s+(.+)$/);
      if (!symMatch || !symMatch[1] || !symMatch[2]) {
        throw new Error(
          `FAIL_CLOSED: Malformed symlink entry in inventory: '${trimmed}'`,
        );
      }
      symlinks.set(symMatch[1].trim().replace(/\\/g, "/"), symMatch[2].trim());
    } else if (typeChar === "d") {
      if (trimmed.endsWith("squashfs-root")) {
        continue; // Root directory entry
      }
      const dirMatch = trimmed.match(/squashfs-root\/(.+)$/);
      if (!dirMatch || !dirMatch[1]) {
        throw new Error(
          `FAIL_CLOSED: Malformed directory entry in inventory: '${trimmed}'`,
        );
      }
      directories.add(dirMatch[1].trim().replace(/\\/g, "/"));
    } else if (typeChar === "-") {
      const fileMatch = trimmed.match(
        /^-\S+\s+\S+\s+(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+squashfs-root\/(.+)$/,
      );
      if (!fileMatch || !fileMatch[1] || !fileMatch[2]) {
        throw new Error(
          `FAIL_CLOSED: Malformed file entry in inventory: '${trimmed}'`,
        );
      }
      regularFiles.set(
        fileMatch[2].trim().replace(/\\/g, "/"),
        Number(fileMatch[1]),
      );
    } else {
      const specMatch = trimmed.match(/squashfs-root\/(.+)$/);
      const rel =
        specMatch && specMatch[1]
          ? specMatch[1].trim().replace(/\\/g, "/")
          : trimmed;
      specialFiles.push({ path: rel, rawLine: trimmed });
    }
  }

  if (
    regularFiles.size === 0 ||
    symlinks.size === 0 ||
    directories.size === 0
  ) {
    throw new Error(
      `FAIL_CLOSED: Incomplete unsquashfs inventory parsed from ${inventoryPath}`,
    );
  }

  return { directories, regularFiles, symlinks, specialFiles };
}

async function main(): Promise<void> {
  const targetPath =
    process.argv[2] ??
    process.env.REA_OPENWRT_CORPUS_PATH ??
    DEFAULT_OPENWRT_PATH;

  const refSha256Path = resolve(
    "evaluation/reference-results/unsquashfs-openwrt-sha256.txt",
  );
  const refSymlinksPath = resolve(
    "evaluation/reference-results/unsquashfs-openwrt-symlinks.txt",
  );
  const refInventoryPath =
    process.env.REA_OPENWRT_INVENTORY_PATH ??
    "/tmp/rea_eval_lab/ground-truth/openwrt_unsquashfs_inventory.txt";

  const outputJsonPath =
    process.env.REA_M1_1A_JSON_OUT ??
    resolve("evaluation/reports/m1_1a_openwrt_host_validation_result.json");

  console.log(
    "================================================================================",
  );
  console.log("REA M1.1A — Final Real OpenWrt 23.05.0 Acceptance Runner");
  console.log(
    "================================================================================",
  );
  console.log(`Target Firmware  : ${targetPath}`);
  console.log(`Expected Size    : ${EXPECTED_OPENWRT_BYTE_SIZE} bytes`);
  console.log(`Expected SHA-256 : ${EXPECTED_OPENWRT_SHA256}`);
  console.log(
    `Runtime Host     : ${process.platform} (${process.arch}), Node ${process.version}`,
  );
  console.log(
    "--------------------------------------------------------------------------------",
  );

  // ==========================================================================
  // STEP 1: Verify Actual Target (Existence, Exact Size, Exact SHA-256)
  // ==========================================================================
  if (!existsSync(targetPath)) {
    throw new Error(
      `STOP [NOT ACCEPTED]: Target firmware file does not exist at ${targetPath}`,
    );
  }
  const targetStat = statSync(targetPath);
  const actualSha256 = computeFileSha256Sync(targetPath);

  console.log(`[STEP 1] Target exists     : true`);
  console.log(
    `[STEP 1] Actual byte size  : ${targetStat.size} (expected ${EXPECTED_OPENWRT_BYTE_SIZE})`,
  );
  console.log(`[STEP 1] Actual SHA-256    : ${actualSha256}`);

  if (targetStat.size !== EXPECTED_OPENWRT_BYTE_SIZE) {
    throw new Error(
      `STOP [NOT ACCEPTED]: Target size mismatch: expected ${EXPECTED_OPENWRT_BYTE_SIZE}, got ${targetStat.size}`,
    );
  }
  if (actualSha256.toLowerCase() !== EXPECTED_OPENWRT_SHA256.toLowerCase()) {
    throw new Error(
      `STOP [NOT ACCEPTED]: Target SHA-256 mismatch: expected ${EXPECTED_OPENWRT_SHA256}, got ${actualSha256}`,
    );
  }
  console.log(
    `[STEP 1 PASS] Firmware file existence, byte size, and SHA-256 verified.`,
  );

  // ==========================================================================
  // STEP 2: Audit & Load Mandatory Reference Manifests (Fail Closed if Missing)
  // ==========================================================================
  const refSha256Map = loadMandatorySha256Manifest(refSha256Path);
  const refSymlinkMap = loadMandatorySymlinkManifest(refSymlinksPath);
  const refInventory = loadMandatoryUnsquashfsInventory(refInventoryPath);

  console.log(
    `[STEP 2] Loaded unsquashfs-openwrt-sha256.txt     : ${refSha256Map.size} file SHA-256 hashes`,
  );
  console.log(
    `[STEP 2] Loaded unsquashfs-openwrt-symlinks.txt   : ${refSymlinkMap.size} symlinks`,
  );
  console.log(
    `[STEP 2] Loaded openwrt_unsquashfs_inventory.txt  : ${refInventory.directories.size} subdirectories (113 incl. root), ` +
      `${refInventory.regularFiles.size} regular files, ${refInventory.symlinks.size} symlinks, ${refInventory.specialFiles.length} special file(s)`,
  );

  // Cross-check the two reference sources against each other
  if (refSha256Map.size !== refInventory.regularFiles.size) {
    throw new Error(
      `STOP [NOT ACCEPTED]: Reference manifest file count mismatch: sha256 manifest has ${refSha256Map.size}, inventory has ${refInventory.regularFiles.size}`,
    );
  }
  if (refSymlinkMap.size !== refInventory.symlinks.size) {
    throw new Error(
      `STOP [NOT ACCEPTED]: Reference manifest symlink count mismatch: symlink manifest has ${refSymlinkMap.size}, inventory has ${refInventory.symlinks.size}`,
    );
  }
  for (const [symPath, symTarget] of refSymlinkMap.entries()) {
    if (refInventory.symlinks.get(symPath) !== symTarget) {
      throw new Error(
        `STOP [NOT ACCEPTED]: Reference symlink disagreement on ${symPath}`,
      );
    }
  }
  console.log(`[STEP 2 PASS] Reference manifests audited and cross-verified.`);

  // ==========================================================================
  // STEP 3: Independent Extraction & Full Structure/Hash Reconciliation
  // ==========================================================================
  const rawFwBytes = readFileSync(targetPath);
  const sqfsParseStart = Date.now();
  const parsedSqfs = SquashFsParser.parseEntries(rawFwBytes, 0);
  const sqfsParseMs = Date.now() - sqfsParseStart;
  if (!parsedSqfs.ok) {
    throw new Error(
      `STOP [NOT ACCEPTED]: SquashFsParser.parseEntries failed: ${parsedSqfs.error.code} - ${parsedSqfs.error.message}`,
    );
  }
  const rawEntries = parsedSqfs.value;
  const rawSpecialEntries = rawEntries.filter(
    (e) => e.kind === "device" || e.kind === "special",
  );

  const extractor = new SandboxedExtractor();
  const extStart = Date.now();
  const extRes = await extractor.extract(targetPath);
  const directExtractionMs = Date.now() - extStart;
  if (!extRes.ok) {
    throw new Error(
      `STOP [NOT ACCEPTED]: SandboxedExtractor.extract failed: ${extRes.error.code} - ${extRes.error.message}`,
    );
  }

  const extSummary = extRes.value;
  const reaRegularFiles = new Map<string, { size: number; sha256: string }>();
  const reaSymlinks = new Map<
    string,
    { target: string; isPlaceholder: boolean }
  >();
  const reaDirectories = new Set<string>();
  const unexpectedEntries: string[] = [];

  try {
    for (const entry of extSummary.entries) {
      const rel = entry.relativePath.replace(/\\/g, "/");
      if (entry.kind === "file") {
        const bytes = readFileSync(entry.destinationPath);
        const sha256 = createHash("sha256").update(bytes).digest("hex");
        reaRegularFiles.set(rel, { size: bytes.length, sha256 });
      } else if (entry.kind === "symlink") {
        const isPlaceholder = existsSync(`${entry.destinationPath}.symlink`);
        reaSymlinks.set(rel, {
          target: entry.linkTarget ?? "",
          isPlaceholder,
        });
      } else if (entry.kind === "directory") {
        if (rel && rel !== ".") {
          reaDirectories.add(rel);
        }
      } else {
        unexpectedEntries.push(`${entry.kind}:${rel}`);
      }
    }

    // 3.1 Reconcile all 990 regular file SHA-256 digests and byte sizes
    let exactHashMatches = 0;
    let exactSizeMatches = 0;
    const missingFiles: string[] = [];
    const extraFiles: string[] = [];
    const hashMismatches: Array<{
      path: string;
      expected: string;
      actual: string;
    }> = [];
    const sizeMismatches: Array<{
      path: string;
      expected: number;
      actual: number;
    }> = [];

    for (const [relPath, expectedHash] of refSha256Map.entries()) {
      const reaFile = reaRegularFiles.get(relPath);
      if (!reaFile) {
        missingFiles.push(relPath);
        continue;
      }
      if (reaFile.sha256 === expectedHash) {
        exactHashMatches++;
      } else {
        hashMismatches.push({
          path: relPath,
          expected: expectedHash,
          actual: reaFile.sha256,
        });
      }
      const expectedSize = refInventory.regularFiles.get(relPath);
      if (expectedSize !== undefined && reaFile.size === expectedSize) {
        exactSizeMatches++;
      } else if (expectedSize !== undefined) {
        sizeMismatches.push({
          path: relPath,
          expected: expectedSize,
          actual: reaFile.size,
        });
      }
    }
    for (const relPath of reaRegularFiles.keys()) {
      if (!refSha256Map.has(relPath)) {
        extraFiles.push(relPath);
      }
    }

    // 3.2 Reconcile all 202 symlink paths and exact targets
    let exactSymlinkMatches = 0;
    let placeholderSymlinksCount = 0;
    const missingSymlinks: string[] = [];
    const extraSymlinks: string[] = [];
    const symlinkTargetMismatches: Array<{
      path: string;
      expected: string;
      actual: string;
    }> = [];

    for (const [symPath, expectedTarget] of refSymlinkMap.entries()) {
      const reaSym = reaSymlinks.get(symPath);
      if (!reaSym) {
        missingSymlinks.push(symPath);
        continue;
      }
      if (reaSym.isPlaceholder) {
        placeholderSymlinksCount++;
      }
      if (reaSym.target === expectedTarget) {
        exactSymlinkMatches++;
      } else {
        symlinkTargetMismatches.push({
          path: symPath,
          expected: expectedTarget,
          actual: reaSym.target,
        });
      }
    }
    for (const symPath of reaSymlinks.keys()) {
      if (!refSymlinkMap.has(symPath)) {
        extraSymlinks.push(symPath);
      }
    }

    // 3.3 Reconcile all 112 subdirectories
    let exactDirectoryMatches = 0;
    const missingDirectories: string[] = [];
    const extraDirectories: string[] = [];
    for (const dirPath of refInventory.directories) {
      if (reaDirectories.has(dirPath)) {
        exactDirectoryMatches++;
      } else {
        missingDirectories.push(dirPath);
      }
    }
    for (const dirPath of reaDirectories) {
      if (!refInventory.directories.has(dirPath)) {
        extraDirectories.push(dirPath);
      }
    }

    // 3.4 Verify special device node neutralization (dev/console must NOT exist on host disk)
    const devConsoleCreatedOnDisk = existsSync(
      join(extSummary.sandboxDir, "dev/console"),
    );
    const specialFilesNeutralizedCorrectly =
      rawSpecialEntries.length === refInventory.specialFiles.length &&
      rawSpecialEntries.length === 1 &&
      rawSpecialEntries[0]?.path === "dev/console" &&
      !devConsoleCreatedOnDisk;

    console.log(
      `[STEP 3] Regular file SHA-256 matches : ${exactHashMatches}/${refSha256Map.size} ` +
        `(missing=${missingFiles.length}, extra=${extraFiles.length}, hashMismatches=${hashMismatches.length}, sizeMismatches=${sizeMismatches.length})`,
    );
    console.log(
      `[STEP 3] Symlink target matches       : ${exactSymlinkMatches}/${refSymlinkMap.size} ` +
        `(missing=${missingSymlinks.length}, extra=${extraSymlinks.length}, mismatches=${symlinkTargetMismatches.length}, placeholders=${placeholderSymlinksCount})`,
    );
    console.log(
      `[STEP 3] Directory matches            : ${exactDirectoryMatches}/${refInventory.directories.size} ` +
        `(missing=${missingDirectories.length}, extra=${extraDirectories.length})`,
    );
    console.log(
      `[STEP 3] Special nodes neutralized    : ${rawSpecialEntries.length}/${refInventory.specialFiles.length} ` +
        `(dev/console on disk: ${devConsoleCreatedOnDisk})`,
    );

    // ========================================================================
    // STEP 4: Execute Full Shared SecurityAssessmentService Pipeline
    // ========================================================================
    const workDir = mkdtempSync(join(tmpdir(), "rea-openwrt-m1-1a-db-"));
    const dbPath = join(workDir, "blackboard.db");
    const journalPath = join(workDir, "packboard.jsonl");
    const assessmentId = ("asm_" + "a".repeat(64)) as AssessmentId;
    const keyring = KeyringManager.createEphemeral(assessmentId);

    try {
      console.log(
        `\n[STEP 4] Running SecurityAssessmentService.runAssessment (budget=${ELF_TASK_BUDGET} ELFs)...`,
      );
      const service1 = new SecurityAssessmentService({
        dbPath,
        journalPath,
        keyringManager: keyring,
      });

      const runRes = await service1.runAssessment({
        assessmentId,
        targetPath,
        title:
          "M1.1A Final Real OpenWrt 23.05.0 ath79 RootFS Acceptance Assessment",
        authorizedBy: "Principal Security Auditor",
        authorizationReference: "AUTH-M1.1A-OPENWRT-FINAL",
        depth: "standard",
        format: "markdown",
        maxBinariesToAnalyze: ELF_TASK_BUDGET,
        taskTimeoutMs: 60_000,
        runExternalScanners: false,
      });

      if (!runRes.ok) {
        throw new Error(
          `STOP [NOT ACCEPTED]: SecurityAssessmentService.runAssessment failed: ${runRes.error.code} - ${runRes.error.message}`,
        );
      }

      const preRestart = runRes.value;
      const classCounts = preRestart.extractionSummary?.classificationCounts;
      const totalElfFiles =
        (classCounts?.elf_executable ?? 0) +
        (classCounts?.elf_shared_library ?? 0);

      // Verify in SQLite tasks table that ONLY ELF files were scheduled as binary_analysis tasks
      const storageInspect = new SqliteBlackboardStorage({
        dbPath,
        journalPath,
        keyringManager: keyring,
        assessmentId,
      });

      let allTasksInDbCount = 0;
      let nonElfTasksScheduledCount = 0;
      let completedTasksInDbCount = 0;
      let openTasksInDbCount = 0;
      let totalAssetsInDbCount = 0;
      let validParentLineageCount = 0;

      try {
        const tasksRes =
          await storageInspect.tasks.listByAssessment(assessmentId);
        const tasks = tasksRes.ok ? tasksRes.value : [];
        allTasksInDbCount = tasks.length;
        completedTasksInDbCount = tasks.filter(
          (t) => t.status === "completed",
        ).length;
        openTasksInDbCount = tasks.filter((t) => t.status === "open").length;

        const assetsRes =
          await storageInspect.assets.listByAssessment(assessmentId);
        const assets = assetsRes.ok ? assetsRes.value : [];
        totalAssetsInDbCount = assets.length;
        const assetById = new Map<string, BlackboardAssetRecord>();
        for (const a of assets) {
          assetById.set(a.id, a);
        }
        for (const a of assets) {
          if (a.parent_asset_id === null || assetById.has(a.parent_asset_id)) {
            validParentLineageCount++;
          }
        }

        for (const t of tasks) {
          const a = assetById.get(t.asset_id);
          const cls = a?.metadata?.fileClassification;
          if (cls !== "elf_executable" && cls !== "elf_shared_library") {
            nonElfTasksScheduledCount++;
          }
        }
      } finally {
        storageInspect.close();
      }

      const analyzedMetrics = preRestart.binaryMetrics.filter(
        (m) => m.status === "PARTIAL" || m.status === "COMPLETED",
      );
      const skippedMetrics = preRestart.binaryMetrics.filter(
        (m) => m.status === "SKIPPED",
      );
      const failedMetrics = preRestart.binaryMetrics.filter(
        (m) => m.status === "FAILED",
      );

      console.log(
        `[STEP 4] Assessment status            : ${preRestart.status}`,
      );
      console.log(
        `[STEP 4] Classification counts        : ${JSON.stringify(classCounts)}`,
      );
      console.log(
        `[STEP 4] Eligible ELF binaries        : ${preRestart.scanExecution.coverage.eligible_binaries} (totalElfFiles=${totalElfFiles})`,
      );
      console.log(
        `[STEP 4] Non-ELF tasks scheduled      : ${nonElfTasksScheduledCount}`,
      );
      console.log(
        `[STEP 4] Analyzed ELF binaries        : ${analyzedMetrics.length} (budget=${ELF_TASK_BUDGET})`,
      );
      console.log(
        `[STEP 4] Skipped ELF binaries         : ${skippedMetrics.length}`,
      );
      console.log(
        `[STEP 4] Failed ELF binaries          : ${failedMetrics.length}`,
      );
      for (const fm of failedMetrics) {
        console.log(
          `  [FAILED ELF] ${fm.relativePath} (${fm.byteSize} B): ${fm.error} (${fm.durationMs}ms)`,
        );
      }
      for (const am of analyzedMetrics) {
        console.log(
          `  [ANALYZED ELF] ${am.relativePath} (${am.byteSize} B): instrs=${am.instructionsDecoded}, decodedBytes=${am.decodedBytes}/${am.totalCodeBytes}, cfg=${am.cfgBlocksCount}/${am.cfgEdgesCount}, cands=${am.candidatesDetected}, findings=${am.findingsPersisted} (${am.durationMs}ms)`,
        );
      }
      console.log(
        `[STEP 4] Total findings persisted     : ${preRestart.assessment.findings.length}`,
      );

      // ======================================================================
      // STEP 4B: Negative Security Boundary Checks on Real OpenWrt Binary
      // ======================================================================
      console.log(
        `\n[STEP 4B] Executing 12 negative security boundary checks...`,
      );
      const negDir = mkdtempSync(join(workDir, "neg-tests-"));
      const negDbPath = join(negDir, "neg.db");
      const negAssessmentId = ("asm_" + "b".repeat(64)) as AssessmentId;
      const negKeyring = KeyringManager.createEphemeral(negAssessmentId);
      const negStorage = new SqliteBlackboardStorage({
        dbPath: negDbPath,
        keyringManager: negKeyring,
        assessmentId: negAssessmentId,
      });

      // Extract one real OpenWrt ELF binary (bin/busybox) into negDir for boundary testing
      const busyboxEntry = extSummary.entries.find(
        (e) =>
          e.kind === "file" &&
          e.relativePath.replace(/\\/g, "/") === "usr/sbin/uhttpd",
      );
      if (!busyboxEntry) {
        throw new Error(
          "STOP [NOT ACCEPTED]: bin/busybox not found in extracted OpenWrt entries",
        );
      }
      const busyboxBytes = readFileSync(busyboxEntry.destinationPath);
      const busyboxSha256 = createHash("sha256")
        .update(busyboxBytes)
        .digest("hex");
      const allowedBinDir = join(negDir, "allowed");
      const outsideBinDir = join(negDir, "outside");
      mkdirSync(allowedBinDir, { recursive: true });
      mkdirSync(outsideBinDir, { recursive: true });
      const insideBusyboxPath = join(allowedBinDir, "busybox");
      const outsideBusyboxPath = join(outsideBinDir, "busybox");
      writeFileSync(insideBusyboxPath, busyboxBytes);
      writeFileSync(outsideBusyboxPath, busyboxBytes);

      const negAssetId = computeAssetId({
        name: "busybox",
        type: "compiled_binary",
        digest: { sha256: busyboxSha256 },
        architecture: "MIPS",
      });

      negStorage
        .getDatabase()
        .prepare(`
        INSERT INTO assessments (
          id, name, status, objective_json, authorization_json, metrics_json, created_at, updated_at
        ) VALUES (?, 'Negative Boundary Assessment', 'in_progress', '{}', '{}', '{}', ?, ?)
      `)
        .run(negAssessmentId, Date.now(), Date.now());

      const negAssetRecord: BlackboardAssetRecord = {
        id: negAssetId,
        assessment_id: negAssessmentId,
        parent_asset_id: null,
        name: "busybox",
        type: "compiled_binary",
        path: insideBusyboxPath,
        digest: { sha256: busyboxSha256 },
        architecture: "MIPS",
        version: null,
        environment: null,
        tags: [],
        metadata: {},
        created_at: Date.now(),
      };
      await negStorage.assets.create(negAssetRecord);

      const negSupervisor = new BinaryWorkerSupervisor({
        workerId: "wkr_neg_openwrt_01",
        allowedRoot: allowedBinDir,
        defaultTaskTimeoutMs: 10_000,
      });
      await negSupervisor.start();

      const negativeBoundaryResults: Record<string, boolean> = {};
      try {
        const negAuthority = new TrustedEvidenceAuthority({
          keyringManager: negKeyring,
          db: negStorage.getDatabase(),
        });
        const negVerifier = new TrustedEvidenceVerifier({
          keyringManager: negKeyring,
          db: negStorage.getDatabase(),
        });
        const negBridge = new VulnerabilityAdjudicationBridge({
          verifier: negVerifier,
        });
        const negValidator = new ParentEvidenceValidator();

        const run1 = negAuthority
          .getRunManager()
          .startRun(negAssessmentId, negAssetId, busyboxSha256);
        const baseReq: BinaryWorkerAnalyzeRequest = {
          protocolVersion: "1.0.0",
          kind: "ANALYZE_REQUEST",
          messageId: randomUUID(),
          taskId: "tsk_neg_openwrt_01",
          assessmentId: negAssessmentId,
          assetId: negAssetId,
          firmwareSha256: actualSha256,
          binarySha256: busyboxSha256,
          runId: run1.runId,
          fencingToken: 7,
          workerId: "wkr_neg_openwrt_01",
          requestedStage: "ALL",
          binaryInput: {
            type: "file_path",
            path: insideBusyboxPath,
            expected_sha256: busyboxSha256,
            byte_size: busyboxBytes.length,
            read_only: true,
          },
          analysisConfiguration: {
            architecture: "MIPS_BE",
            entryPoints: ["main"],
            targetFunctions: ["strcpy"],
            targetSinkApi: "strcpy",
            candidateRuleId: "REA-BIN-001",
            candidateCategory: "unsafe_memory_operations",
            maxInstructions: 50_000,
            maxCfgBlocks: 5_000,
            maxPaths: 100,
          },
          deadline: Date.now() + 10_000,
        };

        const resp1 = await negSupervisor.executeTask(baseReq);
        if (!resp1.ok) {
          throw new Error(
            `Negative baseline worker execution failed: ${resp1.error.message}`,
          );
        }
        const ctx1: ParentValidationContext = {
          assessmentId: negAssessmentId,
          assetId: negAssetId,
          binarySha256: busyboxSha256,
          firmwareSha256: actualSha256,
          runId: run1.runId,
          taskId: "tsk_neg_openwrt_01",
          fencingToken: 7,
          workerId: "wkr_neg_openwrt_01",
          requestedStage: "ALL",
          architecture: "MIPS_BE",
          binaryInputPath: insideBusyboxPath,
        };
        const val1 = negValidator.validateWorkerResponse(resp1.value, ctx1);
        if (!val1.ok) {
          throw new Error(
            `Negative baseline validation failed: ${val1.error.message}`,
          );
        }
        const seal1 = negValidator.sealValidatedEvidence(
          val1.value,
          negAuthority,
          ctx1,
        );
        if (!seal1.ok) {
          throw new Error(
            `Negative baseline sealing failed: ${seal1.error.message}`,
          );
        }
        const bundle1 = seal1.value;

        const cand: VulnerabilityCandidate = {
          binaryAssetId: negAssetId,
          ruleId: "REA-BIN-001",
          name: "Candidate strcpy in busybox",
          category: "unsafe_memory_operations",
          functionName: "<symbol_table_import>",
          functionAddress: null,
          sinkApi: "strcpy",
          callAddress: null,
          callerInfo: "<symbol_table_import>",
          sourceOfInput: "unknown_external_input",
          guardInfo: null,
          evidenceReferences: ["import:strcpy"],
          detectionMethod: "L1_SYMBOL_TABLE",
          confidenceScore: 0.45,
          confidenceLimitations: ["Symbol import only"],
          cwe: ["CWE-120"],
          technicalDescription: "Unresolved import strcpy",
          remediationGuidance: "Use bounded copy",
        };

        // 1. Missing evidence
        const rMissing = negBridge.adjudicateCandidate(
          negAssessmentId,
          negAssetRecord,
          cand,
          {
            runId: run1.runId,
            firmwareSha256: actualSha256,
          },
        );
        negativeBoundaryResults.missingEvidenceRejected =
          rMissing.ok &&
          rMissing.value.finding.verification_status !== "VERIFIED";

        // 2. Modified evidence
        const tamperedRch = {
          ...bundle1.reachabilityEvidence!,
          claims: {
            ...bundle1.reachabilityEvidence!.claims,
            payload: {
              ...bundle1.reachabilityEvidence!.claims.payload,
              status: "REACHABLE" as const,
              isComplete: true,
            },
          },
        };
        const rModified = negBridge.adjudicateCandidate(
          negAssessmentId,
          negAssetRecord,
          cand,
          {
            trustedReachability: tamperedRch,
            trustedTaint: bundle1.taintEvidence,
            trustedWitness: bundle1.witnessEvidence,
            runId: run1.runId,
            firmwareSha256: actualSha256,
          },
        );
        negativeBoundaryResults.modifiedEvidenceRejected =
          rModified.ok &&
          rModified.value.finding.verification_status !== "VERIFIED";

        // 3. Wrong asset binding
        const wrongAsset: BlackboardAssetRecord = {
          ...negAssetRecord,
          id: ("ast_" + "9".repeat(64)) as any,
        };
        const rWrongAsset = negBridge.adjudicateCandidate(
          negAssessmentId,
          wrongAsset,
          cand,
          {
            trustedReachability: bundle1.reachabilityEvidence,
            trustedTaint: bundle1.taintEvidence,
            trustedWitness: bundle1.witnessEvidence,
            runId: run1.runId,
            firmwareSha256: actualSha256,
          },
        );
        negativeBoundaryResults.wrongAssetBindingRejected =
          rWrongAsset.ok &&
          rWrongAsset.value.finding.verification_status !== "VERIFIED";

        // 4. Wrong assessment binding
        const rWrongAss = negBridge.adjudicateCandidate(
          ("asm_" + "1".repeat(64)) as AssessmentId,
          negAssetRecord,
          cand,
          {
            trustedReachability: bundle1.reachabilityEvidence,
            trustedTaint: bundle1.taintEvidence,
            trustedWitness: bundle1.witnessEvidence,
            runId: run1.runId,
            firmwareSha256: actualSha256,
          },
        );
        negativeBoundaryResults.wrongAssessmentBindingRejected =
          rWrongAss.ok &&
          rWrongAss.value.finding.verification_status !== "VERIFIED";

        // 5. Replayed evidence across a different runId
        const runOther = negAuthority
          .getRunManager()
          .startRun(negAssessmentId, negAssetId, busyboxSha256);
        const rReplayed = negBridge.adjudicateCandidate(
          negAssessmentId,
          negAssetRecord,
          cand,
          {
            trustedReachability: bundle1.reachabilityEvidence,
            trustedTaint: bundle1.taintEvidence,
            trustedWitness: bundle1.witnessEvidence,
            runId: runOther.runId,
            firmwareSha256: actualSha256,
          },
        );
        negativeBoundaryResults.replayedEvidenceRejected =
          rReplayed.ok &&
          rReplayed.value.finding.verification_status !== "VERIFIED";

        // 6, 7, 8. Incomplete CFG + NOT_ATTEMPTED taint + NOT_ATTEMPTED witness on active run1
        const rIncomplete = negBridge.adjudicateCandidate(
          negAssessmentId,
          negAssetRecord,
          cand,
          {
            trustedReachability: bundle1.reachabilityEvidence,
            trustedTaint: bundle1.taintEvidence,
            trustedWitness: bundle1.witnessEvidence,
            runId: run1.runId,
            firmwareSha256: actualSha256,
          },
        );
        const isNotVerifiedAndNotFalsePositive =
          rIncomplete.ok &&
          rIncomplete.value.finding.verification_status !== "VERIFIED" &&
          rIncomplete.value.finding.verification_status !==
            "REJECTED_FALSE_POSITIVE" &&
          rIncomplete.value.finding.impact.exploitability === "THEORETICAL";
        negativeBoundaryResults.incompleteCfgCannotProduceVerified =
          isNotVerifiedAndNotFalsePositive;
        negativeBoundaryResults.notAttemptedTaintCannotProduceVerified =
          isNotVerifiedAndNotFalsePositive &&
          bundle1.taintEvidence?.payload.stageStatus === "NOT_ATTEMPTED";
        negativeBoundaryResults.notAttemptedWitnessCannotProduceVerified =
          isNotVerifiedAndNotFalsePositive &&
          bundle1.witnessEvidence?.payload.stageStatus === "NOT_ATTEMPTED";

        // 9. Revoked analysis run
        negAuthority.getRunManager().revokeRun(run1.runId);
        const rRevoked = negBridge.adjudicateCandidate(
          negAssessmentId,
          negAssetRecord,
          cand,
          {
            trustedReachability: bundle1.reachabilityEvidence,
            trustedTaint: bundle1.taintEvidence,
            trustedWitness: bundle1.witnessEvidence,
            runId: run1.runId,
            firmwareSha256: actualSha256,
          },
        );
        negativeBoundaryResults.revokedRunRejected =
          rRevoked.ok &&
          rRevoked.value.finding.verification_status !== "VERIFIED";

        // 10. Stale fencing token
        const staleVal = negValidator.validateWorkerResponse(resp1.value, {
          ...ctx1,
          fencingToken: 999,
        });
        negativeBoundaryResults.staleFencingTokenRejected = !staleVal.ok;

        // 11. Access outside allowedRoot
        const outsideResp = await negSupervisor.executeTask({
          ...baseReq,
          messageId: randomUUID(),
          taskId: "tsk_neg_outside_02",
          binaryInput: {
            type: "file_path",
            path: outsideBusyboxPath,
            expected_sha256: busyboxSha256,
            byte_size: busyboxBytes.length,
            read_only: true,
          },
        });
        negativeBoundaryResults.accessOutsideAllowedRootBlocked =
          outsideResp.ok &&
          outsideResp.value.executionStatus === "FAILED" &&
          Boolean(
            outsideResp.value.decodeCompleteness.haltReason?.includes(
              "escapes allowed root",
            ),
          );

        // 12. Worker timeout kill
        const timeoutSup = new BinaryWorkerSupervisor({
          workerId: "wkr_neg_timeout_03",
          allowedRoot: allowedBinDir,
          defaultTaskTimeoutMs: 50,
          cancelGraceMs: 50,
        });
        await timeoutSup.start();
        const hungPid = timeoutSup.getChildPid()!;
        process.kill(hungPid, "SIGSTOP");
        const hungRes = await timeoutSup.executeTask({
          ...baseReq,
          messageId: randomUUID(),
          taskId: "tsk_neg_hung_03",
          workerId: "wkr_neg_timeout_03",
          deadline: Date.now() + 40,
        });
        negativeBoundaryResults.workerTimeoutHandledCleanly =
          !hungRes.ok && timeoutSup.getState() === "TERMINATED";
        await timeoutSup.shutdown(100);
      } finally {
        await negSupervisor.shutdown(500);
        negStorage.close();
      }

      console.log(
        `[STEP 4B] Negative boundary results   : ${JSON.stringify(negativeBoundaryResults)}`,
      );

      // ======================================================================
      // STEP 5: Validate Persistence, Cold Restart & Report Parity
      // ======================================================================
      console.log(
        `\n[STEP 5] Performing cold restart reconstruction from ${dbPath}...`,
      );
      const service2 = new SecurityAssessmentService({
        dbPath,
        journalPath,
        keyringManager: keyring,
      });

      const postMdRes = await service2.generateReportFromPersisted(
        assessmentId,
        "markdown",
      );
      const postJsonRes = await service2.generateReportFromPersisted(
        assessmentId,
        "json",
      );
      const postSarifRes = await service2.generateReportFromPersisted(
        assessmentId,
        "sarif",
      );

      if (!postMdRes.ok || !postJsonRes.ok || !postSarifRes.ok) {
        throw new Error(
          "STOP [NOT ACCEPTED]: Cold restart report generation failed",
        );
      }

      const postRestart = postMdRes.value;
      const parsedJsonReport = JSON.parse(postJsonRes.value.report);
      const parsedSarifReport = JSON.parse(postSarifRes.value.report);

      // Compare pre-restart and post-restart assets, hashes, lineage, findings, coverage, warnings, status
      const preAssetsSorted = preRestart.assessment.assets
        .map((a) => `${a.id}|${a.name}|${a.type}|${a.digest?.sha256 ?? "null"}`)
        .sort();
      const postAssetsSorted = postRestart.assessment.assets
        .map((a) => `${a.id}|${a.name}|${a.type}|${a.digest?.sha256 ?? "null"}`)
        .sort();
      const assetsAndHashesMatch =
        preAssetsSorted.length === postAssetsSorted.length &&
        JSON.stringify(preAssetsSorted) === JSON.stringify(postAssetsSorted);

      const preFindingsSorted = preRestart.assessment.findings
        .map(
          (f) =>
            `${f.id}|${f.verification_status}|${f.severity.level}|${f.evidence_ids.join(",")}`,
        )
        .sort();
      const postFindingsSorted = postRestart.assessment.findings
        .map(
          (f) =>
            `${f.id}|${f.verification_status}|${f.severity.level}|${f.evidence_ids.join(",")}`,
        )
        .sort();
      const findingsAndStatusesMatch =
        preFindingsSorted.length === postFindingsSorted.length &&
        JSON.stringify(preFindingsSorted) ===
          JSON.stringify(postFindingsSorted);

      const coverageMatches =
        JSON.stringify(preRestart.scanExecution.coverage) ===
        JSON.stringify(postRestart.scanExecution.coverage);

      const warningsMatch =
        JSON.stringify(preRestart.scanExecution.scanner_warnings) ===
        JSON.stringify(postRestart.scanExecution.scanner_warnings);

      const normalizeTimestamps = (md: string) =>
        md.replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z/g, "<ISO_TS>");
      const markdownReportMatches =
        normalizeTimestamps(postMdRes.value.report) ===
          normalizeTimestamps(preRestart.report) &&
        postMdRes.value.report.includes("PARTIAL") &&
        !postMdRes.value.report.includes("Status: CLEAN");

      const jsonReportMatches =
        parsedJsonReport.assessment_id === assessmentId &&
        parsedJsonReport.scan_execution?.status === "PARTIAL" &&
        parsedJsonReport.findings?.length ===
          preRestart.assessment.findings.length &&
        parsedJsonReport.assets?.length === preRestart.assessment.assets.length;

      const sarifReportMatches =
        parsedSarifReport.version === "2.1.0" &&
        parsedSarifReport.runs?.[0]?.results?.length ===
          preRestart.assessment.findings.length;

      const verifiedFindingsCount = preRestart.assessment.findings.filter(
        (f) => f.verification_status === "VERIFIED",
      ).length;

      // ======================================================================
      // STEP 6: Evaluate All 10 Mandatory Acceptance Criteria
      // ======================================================================
      const criteria = {
        criterion1_exactTargetVerified:
          targetStat.size === EXPECTED_OPENWRT_BYTE_SIZE &&
          actualSha256.toLowerCase() === EXPECTED_OPENWRT_SHA256.toLowerCase(),
        criterion2_referenceManifestsValidAndComplete:
          refSha256Map.size === 990 &&
          refSymlinkMap.size === 202 &&
          refInventory.directories.size === 112 &&
          refInventory.specialFiles.length === 1,
        criterion3_all990RegularFileHashesMatch:
          exactHashMatches === 990 &&
          exactSizeMatches === 990 &&
          missingFiles.length === 0 &&
          extraFiles.length === 0 &&
          hashMismatches.length === 0 &&
          sizeMismatches.length === 0,
        criterion4_all202SymlinksReconciled:
          exactSymlinkMatches === 202 &&
          missingSymlinks.length === 0 &&
          extraSymlinks.length === 0 &&
          symlinkTargetMismatches.length === 0,
        criterion5_directoriesSpecialFilesAndNoUnexpectedEntries:
          exactDirectoryMatches === 112 &&
          missingDirectories.length === 0 &&
          extraDirectories.length === 0 &&
          specialFilesNeutralizedCorrectly &&
          unexpectedEntries.length === 0,
        criterion6_elfBudgetEnforcedAndOnlyElfsScheduled:
          nonElfTasksScheduledCount === 0 &&
          preRestart.scanExecution.coverage.eligible_binaries ===
            totalElfFiles &&
          totalElfFiles > ELF_TASK_BUDGET &&
          analyzedMetrics.length === ELF_TASK_BUDGET &&
          skippedMetrics.length === totalElfFiles - ELF_TASK_BUDGET &&
          failedMetrics.length === 0,
        criterion7_supervisedWorkersAndEvidenceValidationPass:
          analyzedMetrics.length === ELF_TASK_BUDGET &&
          analyzedMetrics.every(
            (m) =>
              m.evidenceIds.length === 5 &&
              m.taintStageStatus === "NOT_ATTEMPTED" &&
              m.witnessStageStatus === "NOT_ATTEMPTED" &&
              m.status === "PARTIAL",
          ),
        criterion8_negativeSecurityBoundariesAndZeroVerifiedFindings:
          verifiedFindingsCount === 0 &&
          Object.values(negativeBoundaryResults).every((v) => v === true),
        criterion9_coldRestartPersistenceAndLineageMatch:
          assetsAndHashesMatch &&
          validParentLineageCount === totalAssetsInDbCount &&
          findingsAndStatusesMatch &&
          coverageMatches &&
          warningsMatch &&
          postRestart.status === "PARTIAL",
        criterion10_markdownJsonSarifReportsMatchPersistedState:
          markdownReportMatches && jsonReportMatches && sarifReportMatches,
      };

      const allCriteriaPass = Object.values(criteria).every((v) => v === true);
      const finalDecision = allCriteriaPass ? "ACCEPTED" : "NOT ACCEPTED";

      const resultPayload = {
        milestone: "M1.1A",
        testSuite: "Final Real OpenWrt 23.05.0 Acceptance Run",
        repositoryCommit: "a9ed7435927b9e1806cfbdb6790022378db18d42",
        timestamp: new Date().toISOString(),
        environment: {
          platform: process.platform,
          arch: process.arch,
          nodeVersion: process.version,
        },
        step1_targetVerification: {
          targetPath,
          exists: true,
          expectedByteSize: EXPECTED_OPENWRT_BYTE_SIZE,
          actualByteSize: targetStat.size,
          expectedSha256: EXPECTED_OPENWRT_SHA256,
          actualSha256,
          exactMatch: criteria.criterion1_exactTargetVerified,
        },
        step2_referenceManifestAudit: {
          sha256ManifestPath: refSha256Path,
          sha256EntriesCount: refSha256Map.size,
          symlinkManifestPath: refSymlinksPath,
          symlinkEntriesCount: refSymlinkMap.size,
          unsquashfsInventoryPath: refInventoryPath,
          inventorySubdirectoriesCount: refInventory.directories.size,
          inventoryRegularFilesCount: refInventory.regularFiles.size,
          inventorySymlinksCount: refInventory.symlinks.size,
          inventorySpecialFiles: refInventory.specialFiles,
        },
        step3_extractionReconciliation: {
          squashFsParseMs: sqfsParseMs,
          directExtractionMs,
          rawSquashFsEntriesParsed: rawEntries.length,
          regularFilesExpected: refSha256Map.size,
          regularFilesExtracted: reaRegularFiles.size,
          exactSha256Matches: exactHashMatches,
          exactByteSizeMatches: exactSizeMatches,
          missingFilesCount: missingFiles.length,
          extraFilesCount: extraFiles.length,
          hashMismatchesCount: hashMismatches.length,
          sizeMismatchesCount: sizeMismatches.length,
          symlinksExpected: refSymlinkMap.size,
          symlinksExtracted: reaSymlinks.size,
          exactSymlinkTargetMatches: exactSymlinkMatches,
          neutralizedPlaceholderSymlinksCount: placeholderSymlinksCount,
          missingSymlinksCount: missingSymlinks.length,
          extraSymlinksCount: extraSymlinks.length,
          symlinkTargetMismatchesCount: symlinkTargetMismatches.length,
          directoriesExpected: refInventory.directories.size,
          directoriesExtracted: reaDirectories.size,
          exactDirectoryMatches,
          missingDirectoriesCount: missingDirectories.length,
          extraDirectoriesCount: extraDirectories.length,
          specialFilesExpected: refInventory.specialFiles.length,
          specialFilesNeutralized: rawSpecialEntries.length,
          devConsoleCreatedOnHostDisk: devConsoleCreatedOnDisk,
          unexpectedEntriesCount: unexpectedEntries.length,
        },
        step4_assessmentExecution: {
          assessmentId: preRestart.assessmentId,
          status: preRestart.status,
          classificationCounts: classCounts,
          coverage: preRestart.scanExecution.coverage,
          scannerWarnings: preRestart.scanExecution.scanner_warnings,
          stageTimingsMs: preRestart.stageTimingsMs,
          sqlTasksVerification: {
            totalTasksInDb: allTasksInDbCount,
            completedTasksInDb: completedTasksInDbCount,
            openTasksInDb: openTasksInDbCount,
            nonElfTasksScheduled: nonElfTasksScheduledCount,
          },
          findingsSummary: {
            totalFindings: preRestart.assessment.findings.length,
            verifiedFindingsCount,
            byVerificationStatus: preRestart.assessment.findings.reduce(
              (acc, f) => {
                acc[f.verification_status] =
                  (acc[f.verification_status] ?? 0) + 1;
                return acc;
              },
              {} as Record<string, number>,
            ),
            bySeverity: preRestart.assessment.findings.reduce(
              (acc, f) => {
                acc[f.severity.level] = (acc[f.severity.level] ?? 0) + 1;
                return acc;
              },
              {} as Record<string, number>,
            ),
          },
          analyzedBinariesMetrics: analyzedMetrics,
          skippedBinariesCount: skippedMetrics.length,
          skippedBinariesSample: skippedMetrics.slice(0, 15).map((m) => ({
            relativePath: m.relativePath,
            sha256: m.sha256,
            byteSize: m.byteSize,
            architecture: m.architecture,
            status: m.status,
            reason: m.selectionPriorityReason,
          })),
        },
        step4b_negativeSecurityBoundaries: negativeBoundaryResults,
        step5_coldRestartAndReportParity: {
          preRestartAssetsCount: preRestart.assessment.assets.length,
          postRestartAssetsCount: postRestart.assessment.assets.length,
          assetsAndHashesMatch,
          validParentLineageCount,
          totalAssetsInDbCount,
          preRestartFindingsCount: preRestart.assessment.findings.length,
          postRestartFindingsCount: postRestart.assessment.findings.length,
          findingsAndStatusesMatch,
          coverageMatches,
          warningsMatch,
          markdownReportMatches,
          jsonReportMatches,
          sarifReportMatches,
        },
        mandatoryCriteriaStatus: criteria,
        finalDecision,
      };

      mkdirSync(dirname(outputJsonPath), { recursive: true });
      writeFileSync(
        outputJsonPath,
        JSON.stringify(resultPayload, null, 2),
        "utf8",
      );

      console.log(
        "\n================================================================================",
      );
      console.log("MANDATORY ACCEPTANCE CRITERIA SUMMARY");
      console.log(
        "================================================================================",
      );
      for (const [k, v] of Object.entries(criteria)) {
        console.log(`  [${v ? "PASS" : "FAIL"}] ${k}`);
      }
      console.log(
        "--------------------------------------------------------------------------------",
      );
      console.log(`FINAL MILESTONE M1.1A GATE DECISION: ${finalDecision}`);
      console.log(`Machine-readable JSON written to   : ${outputJsonPath}`);
      console.log(
        "================================================================================",
      );

      if (!allCriteriaPass) {
        process.exitCode = 1;
      }
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  } finally {
    await extractor.cleanupSandbox(extSummary.sandboxDir);
  }
}

main().catch((err) => {
  console.error("[FATAL ACCEPTANCE ERROR]", err);
  process.exit(1);
});
