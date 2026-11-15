#!/usr/bin/env node
/**
 * REA — M1.1B Supported Node.js Runtime Confirmation Runner (Before M1.1C)
 *
 * Verifies that the M1.1B public CLI (`rea security-scan` and `rea security-report`)
 * works end-to-end using a project-supported Node.js runtime (`^22.19.0 || ^24.11.0 || >=26.0.0`)
 * and the native built-in `import { DatabaseSync } from "node:sqlite"` WITHOUT using any
 * custom Node 18 SQLite N-API addon (`sqlite_napi.node`) or custom ESM compatibility loader.
 *
 * Safety & Fail-Closed Guarantees:
 * 1. Authoritative Firmware Target Path (`FAIL_TARGET_MISSING`):
 *    - If `--firmware-path` is supplied, uses ONLY that exact path (never falls back to
 *      `/tmp/rea_eval_lab`, default Windows paths, or any other copy).
 *    - If the resolved target file does not exist, returns `FAIL_TARGET_MISSING` and stops.
 *    - Records the exact canonical path (`realpathSync`) in the final JSON output.
 * 2. Mandatory Reference Manifests (`FAIL_REFERENCE_MISSING`):
 *    - Requires both `unsquashfs-openwrt-sha256.txt` (990 entries) and
 *      `unsquashfs-openwrt-symlinks.txt` (202 entries).
 *    - If either manifest is missing, returns `FAIL_REFERENCE_MISSING` and stops.
 *    - Validates both the entry counts AND the per-file SHA-256 digests (990/990) and
 *      per-symlink targets (202/202) against the extracted/persisted firmware state.
 * 3. Supported Node.js Runtime (`BLOCKED_UNSUPPORTED_NODE_RUNTIME`):
 *    - Refuses to fall back to Node 18 custom N-API SQLite shims or ESM loaders.
 * 4. Strict Gate:
 *    - Final decision (`overall_status: "PASSED"`, `ready_for_m1_1c: true`) requires all 12
 *      mandatory checks (IDs 1..12) to have `executed === true` AND `passed === true`.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";

const DEFAULT_HOST_FIRMWARE_PATH =
  "C:\\Users\\acer\\REA-EVALUATION-LAB\\firmware-corpus\\openwrt-23.05.0-ath79-generic-rootfs.squashfs";
const EXPECTED_OPENWRT_SHA256 =
  "91300ba95fd0558097ccd7acb09bb128da2a72543281780807c34c2d5142a4a0";
const EXPECTED_OPENWRT_SIZE_BYTES = 3_670_016;

// Authoritative OpenWrt 23.05.0 SquashFS Inventory & Coverage Constants
const EXPECTED_DISCOVERED_ENTRIES = 1_305;
const EXPECTED_REGULAR_FILES = 990;
const EXPECTED_SYMLINKS = 202;
const EXPECTED_DIRECTORIES = 112;
const EXPECTED_SPECIAL_FILES = 1;
const EXPECTED_ELF_EXECUTABLES = 43;
const EXPECTED_ELF_SHARED_LIBS = 104;
const EXPECTED_SHELL_SCRIPTS = 252;
const EXPECTED_CONFIG_FILES = 122;
const EXPECTED_OTHER_REGULAR_FILES = 469;
const EXPECTED_ELIGIBLE_ELF_BINARIES = 147; // 43 + 104
const EXPECTED_ANALYZED_BINARIES = 15; // default standard depth maxBinaries = 15
const EXPECTED_PARTIALLY_ANALYZED_BINARIES = 15;
const EXPECTED_SKIPPED_BINARIES = 132; // 147 - 15
const EXPECTED_PERSISTED_ASSETS = 1_086;
const EXPECTED_SEALED_EVIDENCE_RECORDS = 75; // 15 binaries * 5 stages
const EXPECTED_FINDINGS_COUNT = 6;
const EXPECTED_VERIFIED_FINDINGS_COUNT = 0;

const REQUIRED_CHECK_IDS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

function parseCliArgs(argv) {
  let firmwarePathArg = null;
  let outputDirArg = null;
  let refDirArg = null;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--firmware-path=")) {
      firmwarePathArg = arg.slice("--firmware-path=".length);
    } else if (arg === "--firmware-path" && argv[i + 1]) {
      firmwarePathArg = argv[++i];
    } else if (arg.startsWith("--output-dir=")) {
      outputDirArg = arg.slice("--output-dir=".length);
    } else if (arg === "--output-dir" && argv[i + 1]) {
      outputDirArg = argv[++i];
    } else if (arg.startsWith("--ref-dir=")) {
      refDirArg = arg.slice("--ref-dir=".length);
    } else if (arg === "--ref-dir" && argv[i + 1]) {
      refDirArg = argv[++i];
    } else if (!arg.startsWith("-") && !firmwarePathArg) {
      firmwarePathArg = arg;
    }
  }
  return { firmwarePathArg, outputDirArg, refDirArg };
}

function parseNodeVersion(versionStr) {
  const clean = versionStr.replace(/^v/, "");
  const parts = clean.split(".").map((n) => Number.parseInt(n, 10));
  return {
    raw: versionStr,
    major: parts[0] ?? 0,
    minor: parts[1] ?? 0,
    patch: parts[2] ?? 0,
  };
}

function isSupportedNodeVersion(v) {
  if (v.major === 22) return v.minor > 19 || (v.minor === 19 && v.patch >= 0);
  if (v.major === 24) return v.minor > 11 || (v.minor === 11 && v.patch >= 0);
  if (v.major >= 26) return true;
  return false;
}

/**
 * Correction 1: Authoritative firmware path resolution with zero silent fallbacks.
 * - If `--firmware-path` is supplied, uses ONLY that path.
 * - Otherwise, if `REA_OPENWRT_FIRMWARE_PATH` is set, uses ONLY that path.
 * - Otherwise, uses `DEFAULT_HOST_FIRMWARE_PATH` without searching fallback paths.
 */
function resolveAuthoritativeFirmwareTarget(cliFirmwarePath) {
  const hasExplicitCli =
    typeof cliFirmwarePath === "string" && cliFirmwarePath.trim().length > 0;
  const hasExplicitEnv =
    !hasExplicitCli &&
    typeof process.env.REA_OPENWRT_FIRMWARE_PATH === "string" &&
    process.env.REA_OPENWRT_FIRMWARE_PATH.trim().length > 0;

  const selectionSource = hasExplicitCli
    ? "cli_--firmware-path"
    : hasExplicitEnv
      ? "env_REA_OPENWRT_FIRMWARE_PATH"
      : "default_host_path";

  const suppliedPath = hasExplicitCli
    ? cliFirmwarePath.trim()
    : hasExplicitEnv
      ? process.env.REA_OPENWRT_FIRMWARE_PATH.trim()
      : DEFAULT_HOST_FIRMWARE_PATH;

  const resolvedPath = resolve(suppliedPath);
  const exists = existsSync(resolvedPath);
  let canonicalPath = null;
  if (exists) {
    try {
      canonicalPath = realpathSync(resolvedPath);
    } catch {
      canonicalPath = resolvedPath;
    }
  }

  return {
    selectionSource,
    suppliedPath,
    resolvedPath,
    canonicalPath,
    exists,
  };
}

/**
 * Correction 2: Mandatory reference manifest resolution and content parsing with zero silent fallbacks.
 * Requires both `unsquashfs-openwrt-sha256.txt` and `unsquashfs-openwrt-symlinks.txt`.
 */
function resolveMandatoryReferenceManifests(cliRefDir, repoRoot) {
  const hasExplicitCli =
    typeof cliRefDir === "string" && cliRefDir.trim().length > 0;
  const hasExplicitEnv =
    !hasExplicitCli &&
    typeof process.env.REA_OPENWRT_REFERENCE_DIR === "string" &&
    process.env.REA_OPENWRT_REFERENCE_DIR.trim().length > 0;

  const selectionSource = hasExplicitCli
    ? "cli_--ref-dir"
    : hasExplicitEnv
      ? "env_REA_OPENWRT_REFERENCE_DIR"
      : "default_evaluation_reference_results";

  const suppliedDir = hasExplicitCli
    ? cliRefDir.trim()
    : hasExplicitEnv
      ? process.env.REA_OPENWRT_REFERENCE_DIR.trim()
      : resolve(repoRoot, "evaluation/reference-results");

  const resolvedDir = resolve(suppliedDir);
  const sha256ManifestPath = resolve(
    resolvedDir,
    "unsquashfs-openwrt-sha256.txt",
  );
  const symlinksManifestPath = resolve(
    resolvedDir,
    "unsquashfs-openwrt-symlinks.txt",
  );
  const sha256Exists = existsSync(sha256ManifestPath);
  const symlinksExists = existsSync(symlinksManifestPath);

  return {
    selectionSource,
    suppliedDir,
    resolvedDir,
    sha256ManifestPath,
    symlinksManifestPath,
    sha256CanonicalPath: sha256Exists ? realpathSync(sha256ManifestPath) : null,
    symlinksCanonicalPath: symlinksExists
      ? realpathSync(symlinksManifestPath)
      : null,
    sha256Exists,
    symlinksExists,
    bothExist: sha256Exists && symlinksExists,
  };
}

function parseMandatoryReferenceManifestContents(refInfo) {
  const shaContent = readFileSync(refInfo.sha256CanonicalPath, "utf8").trim();
  if (!shaContent) {
    throw new Error(
      `FAIL_REFERENCE_MISSING: SHA-256 reference manifest is empty at ${refInfo.sha256CanonicalPath}`,
    );
  }
  const sha256Map = new Map();
  for (const line of shaContent.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const match = trimmed.match(/^([a-fA-F0-9]{64})\s+(.+)$/);
    if (!match || !match[1] || !match[2]) {
      throw new Error(
        `FAIL_REFERENCE_MISSING: Malformed SHA-256 manifest line in ${refInfo.sha256CanonicalPath}: '${trimmed}'`,
      );
    }
    const digest = match[1].toLowerCase();
    const relPath = match[2]
      .trim()
      .replace(/^\.\/+/u, "")
      .replace(/^squashfs-root\/?/u, "")
      .replace(/\\/g, "/");
    sha256Map.set(relPath, digest);
  }

  const symContent = readFileSync(refInfo.symlinksCanonicalPath, "utf8").trim();
  if (!symContent) {
    throw new Error(
      `FAIL_REFERENCE_MISSING: Symlinks reference manifest is empty at ${refInfo.symlinksCanonicalPath}`,
    );
  }
  const symlinkMap = new Map();
  for (const line of symContent.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const match = trimmed.match(/squashfs-root\/(.+?)\s+->\s+(.+)$/);
    if (!match || !match[1] || !match[2]) {
      throw new Error(
        `FAIL_REFERENCE_MISSING: Malformed symlink manifest line in ${refInfo.symlinksCanonicalPath}: '${trimmed}'`,
      );
    }
    const relPath = match[1].trim().replace(/\\/g, "/");
    const target = match[2].trim();
    symlinkMap.set(relPath, target);
  }

  return {
    sha256Map,
    symlinkMap,
    regularFilesCount: sha256Map.size,
    symlinksCount: symlinkMap.size,
    countsMatchAuthoritative:
      sha256Map.size === EXPECTED_REGULAR_FILES &&
      symlinkMap.size === EXPECTED_SYMLINKS,
  };
}

function parseJsonFromStdout(stdout) {
  const trimmed = (stdout ?? "").trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    const start = trimmed.indexOf("{");
    const end = trimmed.lastIndexOf("}");
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(trimmed.slice(start, end + 1));
      } catch {
        return null;
      }
    }
    return null;
  }
}

function buildUnexecutedChecksList(startId, statusCode, reason) {
  const definitions = [
    [
      1,
      "Use Node.js 22.19+ or 24.11+ (package.json engines: ^22.19.0 || ^24.11.0 || >=26.0.0)",
    ],
    [2, "Verify process.version and process.execPath"],
    [3, 'Verify native import { DatabaseSync } from "node:sqlite" works'],
    [
      4,
      "Do not use custom Node 18 SQLite N-API addon or ESM compatibility loader",
    ],
    [5, "Execute a real OpenWrt rea security-scan"],
    [
      6,
      "Verify target SHA-256 (91300ba95fd0558097ccd7acb09bb128da2a72543281780807c34c2d5142a4a0)",
    ],
    [7, "Verify the assessment is persisted in SQLite"],
    [8, "Exit the scan process completely"],
    [9, "Retrieve the report from a fresh process using rea security-report"],
    [
      10,
      "Verify PARTIAL status, findings (6 total, 0 verified), coverage (1,305 discovered, 990 extracted, 147 eligible ELFs, 15 analyzed, 132 skipped) and reference manifest reconciliation",
    ],
    [
      11,
      "Confirm SQLite cold-restart persistence (1,086 assets, 147 tasks, 75 sealed evidence records, 6 findings) and full 990-file/202-symlink manifest content parity",
    ],
    [
      12,
      "Run relevant CLI regression tests (src/cli/securityCommands.test.ts)",
    ],
  ];
  return definitions
    .filter(([id]) => id >= startId)
    .map(([id, name]) => ({
      id,
      name,
      executed: false,
      passed: false,
      status: statusCode,
      details: { reason },
    }));
}

async function main() {
  const startedAt = new Date().toISOString();
  const repoRoot = process.cwd();
  const { firmwarePathArg, outputDirArg, refDirArg } = parseCliArgs(
    process.argv.slice(2),
  );

  const outputDir = outputDirArg
    ? resolve(outputDirArg)
    : process.env.REA_RUNTIME_CONFIRMATION_OUTPUT_DIR
      ? resolve(process.env.REA_RUNTIME_CONFIRMATION_OUTPUT_DIR)
      : resolve(repoRoot, "evaluation/m1_1b_runtime_confirmation");
  mkdirSync(outputDir, { recursive: true });

  const jsonOutPath = resolve(
    outputDir,
    "m1_1b_runtime_confirmation_result.json",
  );
  const logOutPath = resolve(outputDir, "m1_1b_runtime_confirmation_raw.log");

  const logLines = [];
  function log(msg) {
    const line = `[${new Date().toISOString()}] ${msg}`;
    logLines.push(line);
    process.stdout.write(`${line}\n`);
  }

  log("=== REA M1.1B Runtime Confirmation Before M1.1C ===");

  // -------------------------------------------------------------------------
  // Pre-Flight Gate 1 (Correction 1): Authoritative Target Path Verification
  // -------------------------------------------------------------------------
  const targetInfo = resolveAuthoritativeFirmwareTarget(firmwarePathArg);
  log(
    `[Target Resolution] source=${targetInfo.selectionSource}, supplied=${targetInfo.suppliedPath}, resolved=${targetInfo.resolvedPath}, canonical=${targetInfo.canonicalPath ?? "MISSING"}`,
  );

  const refInfo = resolveMandatoryReferenceManifests(refDirArg, repoRoot);
  log(
    `[Reference Resolution] source=${refInfo.selectionSource}, dir=${refInfo.resolvedDir}, sha256Manifest=${refInfo.sha256Exists ? "FOUND" : "MISSING"}, symlinksManifest=${refInfo.symlinksExists ? "FOUND" : "MISSING"}`,
  );

  if (!targetInfo.exists || !targetInfo.canonicalPath) {
    const errorMsg = `FAIL_TARGET_MISSING: Authoritative firmware path (${targetInfo.selectionSource}) does not exist at '${targetInfo.resolvedPath}' (supplied: '${targetInfo.suppliedPath}'). Refusing to fall back to any other path.`;
    log(`[STOP — FAIL_TARGET_MISSING] ${errorMsg}`);

    const resultPayload = {
      milestone: "M1.1B_RUNTIME_CONFIRMATION",
      overall_status: "FAIL_TARGET_MISSING",
      ready_for_m1_1c: false,
      all_mandatory_checks_executed: false,
      all_mandatory_checks_passed: false,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      configured_target: {
        selection_source: targetInfo.selectionSource,
        supplied_firmware_path: targetInfo.suppliedPath,
        resolved_firmware_path: targetInfo.resolvedPath,
        canonical_firmware_path: null,
        target_exists: false,
        expected_sha256: EXPECTED_OPENWRT_SHA256,
        expected_size_bytes: EXPECTED_OPENWRT_SIZE_BYTES,
      },
      reference_manifests: {
        selection_source: refInfo.selectionSource,
        resolved_reference_dir: refInfo.resolvedDir,
        sha256_manifest_path: refInfo.sha256ManifestPath,
        sha256_manifest_canonical_path: refInfo.sha256CanonicalPath,
        sha256_manifest_exists: refInfo.sha256Exists,
        symlinks_manifest_path: refInfo.symlinksManifestPath,
        symlinks_manifest_canonical_path: refInfo.symlinksCanonicalPath,
        symlinks_manifest_exists: refInfo.symlinksExists,
      },
      blocker: {
        code: "FAIL_TARGET_MISSING",
        message: errorMsg,
      },
      checks: buildUnexecutedChecksList(1, "FAIL_TARGET_MISSING", errorMsg),
    };

    writeFileSync(
      jsonOutPath,
      JSON.stringify(resultPayload, null, 2) + "\n",
      "utf8",
    );
    writeFileSync(logOutPath, logLines.join("\n") + "\n", "utf8");
    process.exitCode = 1;
    return;
  }

  // -------------------------------------------------------------------------
  // Pre-Flight Gate 2 (Correction 2): Mandatory Reference Manifest Verification
  // -------------------------------------------------------------------------
  if (!refInfo.bothExist) {
    const missingFiles = [];
    if (!refInfo.sha256Exists) missingFiles.push(refInfo.sha256ManifestPath);
    if (!refInfo.symlinksExists)
      missingFiles.push(refInfo.symlinksManifestPath);
    const errorMsg = `FAIL_REFERENCE_MISSING: Mandatory OpenWrt reference manifest(s) missing (${missingFiles.join(", ")}). Both unsquashfs-openwrt-sha256.txt and unsquashfs-openwrt-symlinks.txt are strictly required.`;
    log(`[STOP — FAIL_REFERENCE_MISSING] ${errorMsg}`);

    const resultPayload = {
      milestone: "M1.1B_RUNTIME_CONFIRMATION",
      overall_status: "FAIL_REFERENCE_MISSING",
      ready_for_m1_1c: false,
      all_mandatory_checks_executed: false,
      all_mandatory_checks_passed: false,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      configured_target: {
        selection_source: targetInfo.selectionSource,
        supplied_firmware_path: targetInfo.suppliedPath,
        resolved_firmware_path: targetInfo.resolvedPath,
        canonical_firmware_path: targetInfo.canonicalPath,
        target_exists: true,
        expected_sha256: EXPECTED_OPENWRT_SHA256,
        expected_size_bytes: EXPECTED_OPENWRT_SIZE_BYTES,
      },
      reference_manifests: {
        selection_source: refInfo.selectionSource,
        resolved_reference_dir: refInfo.resolvedDir,
        sha256_manifest_path: refInfo.sha256ManifestPath,
        sha256_manifest_canonical_path: refInfo.sha256CanonicalPath,
        sha256_manifest_exists: refInfo.sha256Exists,
        symlinks_manifest_path: refInfo.symlinksManifestPath,
        symlinks_manifest_canonical_path: refInfo.symlinksCanonicalPath,
        symlinks_manifest_exists: refInfo.symlinksExists,
      },
      blocker: {
        code: "FAIL_REFERENCE_MISSING",
        message: errorMsg,
      },
      checks: buildUnexecutedChecksList(1, "FAIL_REFERENCE_MISSING", errorMsg),
    };

    writeFileSync(
      jsonOutPath,
      JSON.stringify(resultPayload, null, 2) + "\n",
      "utf8",
    );
    writeFileSync(logOutPath, logLines.join("\n") + "\n", "utf8");
    process.exitCode = 1;
    return;
  }

  let parsedManifests;
  try {
    parsedManifests = parseMandatoryReferenceManifestContents(refInfo);
    if (!parsedManifests.countsMatchAuthoritative) {
      throw new Error(
        `FAIL_REFERENCE_MISSING: Reference manifest entry counts (${parsedManifests.regularFilesCount} regular files, ${parsedManifests.symlinksCount} symlinks) do not match authoritative OpenWrt 23.05.0 ground truth (${EXPECTED_REGULAR_FILES} regular files, ${EXPECTED_SYMLINKS} symlinks).`,
      );
    }
    log(
      `[Reference Manifests Loaded] regularFiles=${parsedManifests.regularFilesCount} (from ${refInfo.sha256CanonicalPath}), symlinks=${parsedManifests.symlinksCount} (from ${refInfo.symlinksCanonicalPath})`,
    );
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    log(`[STOP — FAIL_REFERENCE_MISSING] ${errorMsg}`);
    const resultPayload = {
      milestone: "M1.1B_RUNTIME_CONFIRMATION",
      overall_status: "FAIL_REFERENCE_MISSING",
      ready_for_m1_1c: false,
      all_mandatory_checks_executed: false,
      all_mandatory_checks_passed: false,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      configured_target: {
        selection_source: targetInfo.selectionSource,
        supplied_firmware_path: targetInfo.suppliedPath,
        resolved_firmware_path: targetInfo.resolvedPath,
        canonical_firmware_path: targetInfo.canonicalPath,
        target_exists: true,
        expected_sha256: EXPECTED_OPENWRT_SHA256,
        expected_size_bytes: EXPECTED_OPENWRT_SIZE_BYTES,
      },
      reference_manifests: {
        selection_source: refInfo.selectionSource,
        resolved_reference_dir: refInfo.resolvedDir,
        sha256_manifest_path: refInfo.sha256ManifestPath,
        sha256_manifest_canonical_path: refInfo.sha256CanonicalPath,
        sha256_manifest_exists: refInfo.sha256Exists,
        symlinks_manifest_path: refInfo.symlinksManifestPath,
        symlinks_manifest_canonical_path: refInfo.symlinksCanonicalPath,
        symlinks_manifest_exists: refInfo.symlinksExists,
      },
      blocker: {
        code: "FAIL_REFERENCE_MISSING",
        message: errorMsg,
      },
      checks: buildUnexecutedChecksList(1, "FAIL_REFERENCE_MISSING", errorMsg),
    };
    writeFileSync(
      jsonOutPath,
      JSON.stringify(resultPayload, null, 2) + "\n",
      "utf8",
    );
    writeFileSync(logOutPath, logLines.join("\n") + "\n", "utf8");
    process.exitCode = 1;
    return;
  }

  const checks = [];

  // -------------------------------------------------------------------------
  // Check 1: Use Node.js 22.19+ or 24.11+
  // -------------------------------------------------------------------------
  const parsedVersion = parseNodeVersion(process.version);
  const versionSupported = isSupportedNodeVersion(parsedVersion);
  checks.push({
    id: 1,
    name: "Use Node.js 22.19+ or 24.11+ (package.json engines: ^22.19.0 || ^24.11.0 || >=26.0.0)",
    executed: true,
    passed: versionSupported,
    details: {
      detected_version: process.version,
      required_range: "^22.19.0 || ^24.11.0 || >=26.0.0",
      nvmrc_target: "24.18.0",
    },
  });
  log(
    `[Check 1] Node.js version check: detected=${process.version}, required='^22.19.0 || ^24.11.0 || >=26.0.0' -> ${
      versionSupported ? "PASS" : "FAIL (UNSUPPORTED_NODE_RUNTIME)"
    }`,
  );

  // -------------------------------------------------------------------------
  // Check 2: Verify process.version and process.execPath
  // -------------------------------------------------------------------------
  const execPathExists = existsSync(process.execPath);
  checks.push({
    id: 2,
    name: "Verify process.version and process.execPath",
    executed: true,
    passed: Boolean(process.version && process.execPath && execPathExists),
    details: {
      process_version: process.version,
      process_execPath: process.execPath,
      platform: process.platform,
      arch: process.arch,
      execPath_exists: execPathExists,
    },
  });
  log(
    `[Check 2] Runtime binary identity: process.version=${process.version}, process.execPath=${process.execPath} (${process.platform}/${process.arch}) -> PASS`,
  );

  // -------------------------------------------------------------------------
  // Check 4 (evaluated before Check 3 to ensure Check 3 is unshimmed):
  // Do not use the custom Node 18 SQLite N-API addon or ESM compatibility loader
  // -------------------------------------------------------------------------
  const nodeOptions = process.env.NODE_OPTIONS ?? "";
  const execArgvJoined = process.execArgv.join(" ");
  const hasCustomLoader =
    nodeOptions.includes("ts-loader") ||
    execArgvJoined.includes("ts-loader") ||
    nodeOptions.includes("sqlite_napi") ||
    execArgvJoined.includes("sqlite_napi") ||
    nodeOptions.includes("--loader") ||
    execArgvJoined.includes("--loader");
  const check4Passed = !hasCustomLoader;
  checks.push({
    id: 4,
    name: "Do not use custom Node 18 SQLite N-API addon or ESM compatibility loader",
    executed: true,
    passed: check4Passed,
    details: {
      process_execArgv: process.execArgv,
      env_NODE_OPTIONS: nodeOptions || null,
      custom_shim_detected: hasCustomLoader,
    },
  });
  log(
    `[Check 4] Zero custom Node 18 shims/loaders: execArgv=${JSON.stringify(
      process.execArgv,
    )}, NODE_OPTIONS=${JSON.stringify(nodeOptions)} -> ${check4Passed ? "PASS" : "FAIL"}`,
  );

  // -------------------------------------------------------------------------
  // Check 3: Verify native import { DatabaseSync } from "node:sqlite" works
  // -------------------------------------------------------------------------
  let nativeSqliteWorked = false;
  let nativeSqliteDetails = {};
  let NativeDatabaseSync = null;
  try {
    const sqliteMod = await import("node:sqlite");
    NativeDatabaseSync = sqliteMod.DatabaseSync;
    if (typeof NativeDatabaseSync === "function") {
      const memDb = new NativeDatabaseSync(":memory:");
      memDb.exec(
        "CREATE TABLE runtime_probe (id INTEGER PRIMARY KEY, label TEXT NOT NULL);",
      );
      memDb
        .prepare("INSERT INTO runtime_probe (id, label) VALUES (?, ?);")
        .run(1, "native_node_sqlite_ok");
      const row = memDb
        .prepare("SELECT id, label FROM runtime_probe WHERE id = ?;")
        .get(1);
      memDb.close();
      nativeSqliteWorked =
        row?.id === 1 && row?.label === "native_node_sqlite_ok";
      nativeSqliteDetails = {
        module_specifier: "node:sqlite",
        databaseSync_type: typeof NativeDatabaseSync,
        probe_row: row,
      };
    }
  } catch (err) {
    nativeSqliteWorked = false;
    nativeSqliteDetails = {
      module_specifier: "node:sqlite",
      error_code: err?.code ?? "UNKNOWN_ERROR",
      error_message: err instanceof Error ? err.message : String(err),
    };
  }
  checks.push({
    id: 3,
    name: 'Verify native import { DatabaseSync } from "node:sqlite" works',
    executed: true,
    passed: nativeSqliteWorked,
    details: nativeSqliteDetails,
  });
  log(
    `[Check 3] Native import("node:sqlite") probe: ${
      nativeSqliteWorked
        ? "PASS (DatabaseSync in-memory round-trip succeeded)"
        : `FAIL (${nativeSqliteDetails.error_code}: ${nativeSqliteDetails.error_message})`
    }`,
  );

  checks.sort((a, b) => a.id - b.id);

  // -------------------------------------------------------------------------
  // Fail-Closed Gate if Supported Runtime / Native node:sqlite is Unavailable
  // -------------------------------------------------------------------------
  if (!versionSupported || !nativeSqliteWorked || !check4Passed) {
    const blockerReason = !versionSupported
      ? `Current environment only provides Node.js ${process.version} at ${process.execPath} (requires ^22.19.0 || ^24.11.0 || >=26.0.0) and lacks built-in node:sqlite.`
      : !nativeSqliteWorked
        ? `Built-in module "node:sqlite" failed to load natively: ${nativeSqliteDetails.error_message}`
        : "Custom compatibility loader or N-API shim was detected in process arguments.";

    log(`[STOP — FAIL-CLOSED] ${blockerReason}`);
    log(
      "[STOP — FAIL-CLOSED] Refusing to fall back to Node 18 custom N-API SQLite shim or ESM loader per M1.1B runtime confirmation rules.",
    );

    checks.push(
      ...buildUnexecutedChecksList(
        5,
        "BLOCKED_BY_UNSUPPORTED_HOST_RUNTIME",
        blockerReason,
      ),
    );

    const resultPayload = {
      milestone: "M1.1B_RUNTIME_CONFIRMATION",
      overall_status: "BLOCKED_UNSUPPORTED_NODE_RUNTIME",
      ready_for_m1_1c: false,
      all_mandatory_checks_executed: false,
      all_mandatory_checks_passed: false,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      configured_target: {
        selection_source: targetInfo.selectionSource,
        supplied_firmware_path: targetInfo.suppliedPath,
        resolved_firmware_path: targetInfo.resolvedPath,
        canonical_firmware_path: targetInfo.canonicalPath,
        target_exists: true,
        expected_sha256: EXPECTED_OPENWRT_SHA256,
        expected_size_bytes: EXPECTED_OPENWRT_SIZE_BYTES,
      },
      reference_manifests: {
        selection_source: refInfo.selectionSource,
        resolved_reference_dir: refInfo.resolvedDir,
        sha256_manifest_path: refInfo.sha256ManifestPath,
        sha256_manifest_canonical_path: refInfo.sha256CanonicalPath,
        sha256_manifest_exists: refInfo.sha256Exists,
        sha256_manifest_entry_count: parsedManifests.regularFilesCount,
        symlinks_manifest_path: refInfo.symlinksManifestPath,
        symlinks_manifest_canonical_path: refInfo.symlinksCanonicalPath,
        symlinks_manifest_exists: refInfo.symlinksExists,
        symlinks_manifest_entry_count: parsedManifests.symlinksCount,
        counts_match_authoritative: parsedManifests.countsMatchAuthoritative,
      },
      expected_openwrt_inventory: {
        discovered_entries: EXPECTED_DISCOVERED_ENTRIES,
        regular_files_extracted: EXPECTED_REGULAR_FILES,
        symlinks: EXPECTED_SYMLINKS,
        directories: EXPECTED_DIRECTORIES,
        special_files_neutralized: EXPECTED_SPECIAL_FILES,
        classification_counts: {
          elf_executable: EXPECTED_ELF_EXECUTABLES,
          elf_shared_library: EXPECTED_ELF_SHARED_LIBS,
          shell_script: EXPECTED_SHELL_SCRIPTS,
          configuration_file: EXPECTED_CONFIG_FILES,
          regular_file: EXPECTED_OTHER_REGULAR_FILES,
        },
        eligible_elf_binaries: EXPECTED_ELIGIBLE_ELF_BINARIES,
        binaries_analyzed: EXPECTED_ANALYZED_BINARIES,
        binaries_partially_analyzed: EXPECTED_PARTIALLY_ANALYZED_BINARIES,
        binaries_skipped_or_failed: EXPECTED_SKIPPED_BINARIES,
        persisted_assets_in_db: EXPECTED_PERSISTED_ASSETS,
        sealed_evidence_records_in_db: EXPECTED_SEALED_EVIDENCE_RECORDS,
        findings_count: EXPECTED_FINDINGS_COUNT,
        verified_findings_count: EXPECTED_VERIFIED_FINDINGS_COUNT,
      },
      runtime: {
        process_version: process.version,
        process_execPath: process.execPath,
        platform: process.platform,
        arch: process.arch,
        package_engines_node: "^22.19.0 || ^24.11.0 || >=26.0.0",
        nvmrc: "24.18.0",
        native_node_sqlite_available: nativeSqliteWorked,
        custom_shims_used: false,
      },
      blocker: {
        code: "ERR_UNSUPPORTED_NODE_RUNTIME",
        message: blockerReason,
        sqlite_probe_error: nativeSqliteDetails,
      },
      checks,
    };

    writeFileSync(
      jsonOutPath,
      JSON.stringify(resultPayload, null, 2) + "\n",
      "utf8",
    );
    writeFileSync(logOutPath, logLines.join("\n") + "\n", "utf8");

    process.exitCode = 1;
    return;
  }

  // -------------------------------------------------------------------------
  // Checks 5–12: Full Supported-Runtime Execution on Node 22.19+ / 24.11+
  // -------------------------------------------------------------------------
  const canonicalFirmwarePath = targetInfo.canonicalPath;
  const fwBuffer = readFileSync(canonicalFirmwarePath);
  const fwSha256 = createHash("sha256").update(fwBuffer).digest("hex");
  const fwSize = fwBuffer.byteLength;

  if (
    fwSize !== EXPECTED_OPENWRT_SIZE_BYTES ||
    fwSha256 !== EXPECTED_OPENWRT_SHA256
  ) {
    throw new Error(
      `NOT ACCEPTED: Target firmware mismatch at ${canonicalFirmwarePath}. Expected ${EXPECTED_OPENWRT_SIZE_BYTES} bytes and SHA-256 ${EXPECTED_OPENWRT_SHA256}, got ${fwSize} bytes and ${fwSha256}.`,
    );
  }

  const dbPath = resolve(
    outputDir,
    "m1_1b_supported_runtime_blackboard.sqlite",
  );
  rmSync(dbPath, { force: true });

  // Clean environment with zero custom loaders
  const cleanEnv = { ...process.env };
  delete cleanEnv.NODE_OPTIONS;

  const cliScriptPath = resolve(repoRoot, "scripts/rea-cli.ts");

  // -------------------------------------------------------------------------
  // Check 5: Execute a real OpenWrt rea security-scan
  // -------------------------------------------------------------------------
  log(
    `[Check 5] Launching 'rea security-scan' on ${canonicalFirmwarePath} using ${process.execPath}...`,
  );
  const scanStartMs = Date.now();
  const scanProc = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      cliScriptPath,
      "security-scan",
      canonicalFirmwarePath,
      "--format=json",
      `--db-path=${dbPath}`,
      "--authorized-by=M1.1B-Supported-Runtime-Validator",
      "--reference=REA-M1.1B-RUNTIME-CONFIRMATION",
    ],
    {
      cwd: repoRoot,
      env: cleanEnv,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  const scanDurationMs = Date.now() - scanStartMs;

  if (scanProc.stderr && scanProc.stderr.trim()) {
    log(`[Check 5 stderr] ${scanProc.stderr.trim()}`);
  }

  const scanOut = parseJsonFromStdout(scanProc.stdout);
  if (!scanOut && scanProc.stdout) {
    log(`[Check 5 stdout preview] ${scanProc.stdout.slice(0, 500)}`);
  }
  const assessmentId = scanOut?.assessment_id ?? null;

  const check5Passed =
    scanProc.status === 0 &&
    scanOut !== null &&
    scanOut.status === "PARTIAL" &&
    typeof assessmentId === "string" &&
    /^asm_[a-f0-9]{64}$/.test(assessmentId);

  checks.push({
    id: 5,
    name: "Execute a real OpenWrt rea security-scan",
    executed: true,
    passed: check5Passed,
    details: {
      pid: scanProc.pid,
      exit_code: scanProc.status,
      duration_ms: scanDurationMs,
      canonical_firmware_path: canonicalFirmwarePath,
      assessment_id: assessmentId,
      status: scanOut?.status ?? null,
    },
  });
  log(
    `[Check 5] rea security-scan exit=${scanProc.status}, assessment_id=${assessmentId}, status=${scanOut?.status} -> ${
      check5Passed ? "PASS" : "FAIL"
    }`,
  );

  // -------------------------------------------------------------------------
  // Check 6: Verify target SHA-256
  // -------------------------------------------------------------------------
  const check6Passed =
    fwSha256 === EXPECTED_OPENWRT_SHA256 &&
    fwSize === EXPECTED_OPENWRT_SIZE_BYTES &&
    scanOut?.sha256 === EXPECTED_OPENWRT_SHA256 &&
    scanOut?.extraction_summary?.rootFirmwareSha256 === EXPECTED_OPENWRT_SHA256;

  checks.push({
    id: 6,
    name: "Verify target SHA-256",
    executed: true,
    passed: check6Passed,
    details: {
      canonical_firmware_path: canonicalFirmwarePath,
      expected_sha256: EXPECTED_OPENWRT_SHA256,
      actual_file_sha256: fwSha256,
      cli_reported_sha256: scanOut?.sha256 ?? null,
      extraction_summary_sha256:
        scanOut?.extraction_summary?.rootFirmwareSha256 ?? null,
      file_size_bytes: fwSize,
    },
  });
  log(
    `[Check 6] Target SHA-256=${fwSha256} (size=${fwSize}) -> ${check6Passed ? "PASS" : "FAIL"}`,
  );

  // -------------------------------------------------------------------------
  // Check 7: Verify the assessment is persisted
  // -------------------------------------------------------------------------
  const dbExistsAfterScan = existsSync(dbPath) && statSync(dbPath).size > 0;
  const check7Passed =
    dbExistsAfterScan &&
    typeof assessmentId === "string" &&
    /^asm_[a-f0-9]{64}$/.test(assessmentId);

  checks.push({
    id: 7,
    name: "Verify the assessment is persisted",
    executed: true,
    passed: check7Passed,
    details: {
      db_path: dbPath,
      db_exists: dbExistsAfterScan,
      db_size_bytes: dbExistsAfterScan ? statSync(dbPath).size : 0,
      assessment_id: assessmentId,
    },
  });
  log(
    `[Check 7] SQLite file persisted (${dbExistsAfterScan ? statSync(dbPath).size : 0} bytes) -> ${
      check7Passed ? "PASS" : "FAIL"
    }`,
  );

  // -------------------------------------------------------------------------
  // Check 8: Exit the scan process completely
  // -------------------------------------------------------------------------
  let scanProcessTerminated = true;
  if (typeof scanProc.pid === "number") {
    try {
      process.kill(scanProc.pid, 0);
      scanProcessTerminated = false;
    } catch {
      scanProcessTerminated = true;
    }
  }
  const check8Passed =
    scanProc.status === 0 &&
    scanProc.signal === null &&
    typeof scanProc.pid === "number" &&
    scanProcessTerminated;

  checks.push({
    id: 8,
    name: "Exit the scan process completely",
    executed: true,
    passed: check8Passed,
    details: {
      scan_pid: scanProc.pid,
      scan_exit_code: scanProc.status,
      scan_signal: scanProc.signal,
      process_terminated: scanProcessTerminated,
    },
  });
  log(
    `[Check 8] Scan process PID ${scanProc.pid} exited completely (terminated=${scanProcessTerminated}) -> ${
      check8Passed ? "PASS" : "FAIL"
    }`,
  );

  // -------------------------------------------------------------------------
  // Check 9: Retrieve the report from a fresh process using rea security-report
  // -------------------------------------------------------------------------
  const targetAssessmentId = assessmentId ?? "missing_assessment_id";
  const reportMdProc = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      cliScriptPath,
      "security-report",
      targetAssessmentId,
      "--format=markdown",
      `--db-path=${dbPath}`,
    ],
    {
      cwd: repoRoot,
      env: cleanEnv,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  const reportJsonProc = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      cliScriptPath,
      "security-report",
      targetAssessmentId,
      "--format=json",
      `--db-path=${dbPath}`,
    ],
    {
      cwd: repoRoot,
      env: cleanEnv,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  const reportSarifProc = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      cliScriptPath,
      "security-report",
      targetAssessmentId,
      "--format=sarif",
      `--db-path=${dbPath}`,
    ],
    {
      cwd: repoRoot,
      env: cleanEnv,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    },
  );

  const mdOut = parseJsonFromStdout(reportMdProc.stdout);
  const jsonOut = parseJsonFromStdout(reportJsonProc.stdout);
  const sarifOut = parseJsonFromStdout(reportSarifProc.stdout);

  const mdText = typeof mdOut?.report === "string" ? mdOut.report : "";
  const reconstructedJsonReport =
    typeof jsonOut?.report === "string"
      ? parseJsonFromStdout(jsonOut.report)
      : null;
  const reconstructedSarifReport =
    typeof sarifOut?.report === "string"
      ? parseJsonFromStdout(sarifOut.report)
      : null;

  const check9Passed =
    reportMdProc.status === 0 &&
    reportJsonProc.status === 0 &&
    reportSarifProc.status === 0 &&
    reportMdProc.pid !== scanProc.pid &&
    reportJsonProc.pid !== scanProc.pid &&
    reportSarifProc.pid !== scanProc.pid &&
    mdOut?.status === "SUCCESS" &&
    jsonOut?.status === "SUCCESS" &&
    sarifOut?.status === "SUCCESS" &&
    mdOut?.assessment_id === targetAssessmentId &&
    reconstructedJsonReport?.assessment_id === targetAssessmentId;

  checks.push({
    id: 9,
    name: "Retrieve the report from a fresh process using rea security-report",
    executed: true,
    passed: check9Passed,
    details: {
      scan_pid: scanProc.pid,
      markdown_report_pid: reportMdProc.pid,
      json_report_pid: reportJsonProc.pid,
      sarif_report_pid: reportSarifProc.pid,
      distinct_os_processes:
        reportMdProc.pid !== scanProc.pid &&
        reportJsonProc.pid !== scanProc.pid &&
        reportSarifProc.pid !== scanProc.pid,
      markdown_exit_code: reportMdProc.status,
      json_exit_code: reportJsonProc.status,
      sarif_exit_code: reportSarifProc.status,
      assessment_id: mdOut?.assessment_id ?? null,
    },
  });
  log(
    `[Check 9] Fresh process report retrieval (scan PID=${scanProc.pid}, report PIDs=${reportMdProc.pid}/${reportJsonProc.pid}/${reportSarifProc.pid}) -> ${
      check9Passed ? "PASS" : "FAIL"
    }`,
  );

  // -------------------------------------------------------------------------
  // Check 10 & Check 11: Reconcile Persisted SQLite Data & Mandatory Manifest Contents
  // -------------------------------------------------------------------------
  const coldDb = new NativeDatabaseSync(dbPath, { open: true });
  const assessmentRow = coldDb
    .prepare("SELECT id, name, status FROM assessments WHERE id = ?;")
    .get(targetAssessmentId);
  const rootAssetRow = coldDb
    .prepare(
      "SELECT id, name, type, sha256 FROM assets WHERE assessment_id = ? AND parent_asset_id IS NULL;",
    )
    .get(targetAssessmentId);
  const totalAssetsCount = Number(
    coldDb
      .prepare("SELECT COUNT(*) AS cnt FROM assets WHERE assessment_id = ?;")
      .get(targetAssessmentId)?.cnt ?? 0,
  );
  const skippedBudgetAssetsCount = Number(
    coldDb
      .prepare(
        "SELECT COUNT(*) AS cnt FROM assets WHERE assessment_id = ? AND json_extract(metadata_json, '$.lifecycle_state') = 'skipped_budget';",
      )
      .get(targetAssessmentId)?.cnt ?? 0,
  );
  const totalTasksCount = Number(
    coldDb
      .prepare("SELECT COUNT(*) AS cnt FROM tasks WHERE assessment_id = ?;")
      .get(targetAssessmentId)?.cnt ?? 0,
  );
  const completedTasksCount = Number(
    coldDb
      .prepare(
        "SELECT COUNT(*) AS cnt FROM tasks WHERE assessment_id = ? AND status = 'completed';",
      )
      .get(targetAssessmentId)?.cnt ?? 0,
  );
  const openTasksCount = Number(
    coldDb
      .prepare(
        "SELECT COUNT(*) AS cnt FROM tasks WHERE assessment_id = ? AND status = 'open';",
      )
      .get(targetAssessmentId)?.cnt ?? 0,
  );
  const nonBinaryTasksCount = Number(
    coldDb
      .prepare(
        "SELECT COUNT(*) AS cnt FROM tasks WHERE assessment_id = ? AND task_type != 'binary_analysis';",
      )
      .get(targetAssessmentId)?.cnt ?? 0,
  );
  const sealedEvidenceCount = Number(
    coldDb
      .prepare(
        "SELECT COUNT(*) AS cnt FROM analysis_evidence_records WHERE assessment_id = ?;",
      )
      .get(targetAssessmentId)?.cnt ?? 0,
  );
  const persistedFindingsCount = Number(
    coldDb
      .prepare("SELECT COUNT(*) AS cnt FROM findings WHERE assessment_id = ?;")
      .get(targetAssessmentId)?.cnt ?? 0,
  );
  const verifiedFindingsCount = Number(
    coldDb
      .prepare(
        "SELECT COUNT(*) AS cnt FROM findings WHERE assessment_id = ? AND state = 'VERIFIED';",
      )
      .get(targetAssessmentId)?.cnt ?? 0,
  );
  const scanExecObsRow = coldDb
    .prepare(
      "SELECT value_json FROM observations WHERE assessment_id = ? AND key = 'assessment.scan_execution' ORDER BY created_at DESC LIMIT 1;",
    )
    .get(targetAssessmentId);

  // Content validation against mandatory reference manifests (990 regular files + 202 symlinks)
  const extractedFileRows = coldDb
    .prepare(
      "SELECT path, sha256 FROM assets WHERE assessment_id = ? AND parent_asset_id IS NOT NULL AND path IS NOT NULL AND sha256 IS NOT NULL;",
    )
    .all(targetAssessmentId);
  const symlinkObsRows = coldDb
    .prepare(
      "SELECT value_json FROM observations WHERE assessment_id = ? AND key = 'firmware.symlink_entry';",
    )
    .all(targetAssessmentId);
  coldDb.close();

  const persistedRegularFilesMap = new Map();
  for (const row of extractedFileRows) {
    if (typeof row.path === "string" && typeof row.sha256 === "string") {
      persistedRegularFilesMap.set(
        row.path.replace(/\\/g, "/"),
        row.sha256.toLowerCase(),
      );
    }
  }

  let exactRegularFileHashMatches = 0;
  const missingRegularFiles = [];
  const extraRegularFiles = [];
  const regularFileHashMismatches = [];

  for (const [relPath, expectedHash] of parsedManifests.sha256Map.entries()) {
    const actualHash = persistedRegularFilesMap.get(relPath);
    if (!actualHash) {
      missingRegularFiles.push(relPath);
    } else if (actualHash === expectedHash) {
      exactRegularFileHashMatches++;
    } else {
      regularFileHashMismatches.push({
        path: relPath,
        expected: expectedHash,
        actual: actualHash,
      });
    }
  }
  for (const relPath of persistedRegularFilesMap.keys()) {
    if (!parsedManifests.sha256Map.has(relPath)) {
      extraRegularFiles.push(relPath);
    }
  }

  const persistedSymlinksMap = new Map();
  for (const row of symlinkObsRows) {
    try {
      const val = JSON.parse(row.value_json);
      if (typeof val?.path === "string" && typeof val?.target === "string") {
        persistedSymlinksMap.set(
          val.path.replace(/\\/g, "/"),
          val.target.replace(/\\/g, "/"),
        );
      }
    } catch {
      // ignore malformed JSON
    }
  }

  let exactSymlinkTargetMatches = 0;
  const missingSymlinks = [];
  const extraSymlinks = [];
  const symlinkTargetMismatches = [];

  for (const [
    relPath,
    expectedTarget,
  ] of parsedManifests.symlinkMap.entries()) {
    const actualTarget = persistedSymlinksMap.get(relPath);
    if (actualTarget === undefined) {
      missingSymlinks.push(relPath);
    } else if (actualTarget === expectedTarget) {
      exactSymlinkTargetMatches++;
    } else {
      symlinkTargetMismatches.push({
        path: relPath,
        expected: expectedTarget,
        actual: actualTarget,
      });
    }
  }
  for (const relPath of persistedSymlinksMap.keys()) {
    if (!parsedManifests.symlinkMap.has(relPath)) {
      extraSymlinks.push(relPath);
    }
  }

  const manifestContentsReconciled =
    parsedManifests.countsMatchAuthoritative &&
    exactRegularFileHashMatches === EXPECTED_REGULAR_FILES &&
    missingRegularFiles.length === 0 &&
    extraRegularFiles.length === 0 &&
    regularFileHashMismatches.length === 0 &&
    exactSymlinkTargetMatches === EXPECTED_SYMLINKS &&
    missingSymlinks.length === 0 &&
    extraSymlinks.length === 0 &&
    symlinkTargetMismatches.length === 0;

  // Evaluate Check 10
  const extSummary = scanOut?.extraction_summary;
  const classCounts = extSummary?.classificationCounts;
  const scanCov = scanOut?.scan_execution?.coverage;
  const reportCov = mdOut?.scan_execution?.coverage;

  const extractionCountsMatch =
    extSummary?.totalDiscoveredEntries === EXPECTED_DISCOVERED_ENTRIES &&
    extSummary?.regularFilesExtracted === EXPECTED_REGULAR_FILES &&
    extSummary?.symlinksCount === EXPECTED_SYMLINKS &&
    extSummary?.directoriesCount === EXPECTED_DIRECTORIES &&
    extSummary?.specialFilesNeutralized === EXPECTED_SPECIAL_FILES &&
    classCounts?.elf_executable === EXPECTED_ELF_EXECUTABLES &&
    classCounts?.elf_shared_library === EXPECTED_ELF_SHARED_LIBS &&
    classCounts?.shell_script === EXPECTED_SHELL_SCRIPTS &&
    classCounts?.configuration_file === EXPECTED_CONFIG_FILES &&
    classCounts?.regular_file === EXPECTED_OTHER_REGULAR_FILES &&
    manifestContentsReconciled;

  const coverageCountsMatch =
    scanCov?.discovered_files === EXPECTED_DISCOVERED_ENTRIES &&
    scanCov?.extracted_files === EXPECTED_REGULAR_FILES &&
    scanCov?.eligible_binaries === EXPECTED_ELIGIBLE_ELF_BINARIES &&
    scanCov?.binaries_analyzed === EXPECTED_ANALYZED_BINARIES &&
    scanCov?.binaries_partially_analyzed ===
      EXPECTED_PARTIALLY_ANALYZED_BINARIES &&
    scanCov?.binaries_skipped_or_failed === EXPECTED_SKIPPED_BINARIES &&
    reportCov?.discovered_files === EXPECTED_DISCOVERED_ENTRIES &&
    reportCov?.extracted_files === EXPECTED_REGULAR_FILES &&
    reportCov?.eligible_binaries === EXPECTED_ELIGIBLE_ELF_BINARIES &&
    reportCov?.binaries_analyzed === EXPECTED_ANALYZED_BINARIES &&
    reportCov?.binaries_partially_analyzed ===
      EXPECTED_PARTIALLY_ANALYZED_BINARIES &&
    reportCov?.binaries_skipped_or_failed === EXPECTED_SKIPPED_BINARIES;

  const mdContainsPartialAndSkipped =
    mdText.includes("**Scan Execution Status:** `PARTIAL`") &&
    mdText.includes("PARTIAL Analysis Coverage Notice") &&
    mdText.includes(
      "### 3.1. ELF Binary Analysis & Skipped Binary Inventory",
    ) &&
    mdText.includes(
      `Skipped / Unanalyzed ELF Binaries (${EXPECTED_SKIPPED_BINARIES}):`,
    );

  const jsonContainsPartialAndSkipped =
    reconstructedJsonReport?.scan_status === "PARTIAL" &&
    reconstructedJsonReport?.scan_execution?.status === "PARTIAL" &&
    Array.isArray(reconstructedJsonReport?.analyzed_binaries) &&
    reconstructedJsonReport.analyzed_binaries.length ===
      EXPECTED_ANALYZED_BINARIES &&
    Array.isArray(reconstructedJsonReport?.skipped_binaries) &&
    reconstructedJsonReport.skipped_binaries.length ===
      EXPECTED_SKIPPED_BINARIES &&
    reconstructedJsonReport?.assets?.length === EXPECTED_PERSISTED_ASSETS &&
    reconstructedJsonReport?.findings?.length === EXPECTED_FINDINGS_COUNT;

  const sarifContainsPartialAndSkipped =
    reconstructedSarifReport?.version === "2.1.0" &&
    reconstructedSarifReport?.runs?.[0]?.results?.length ===
      EXPECTED_FINDINGS_COUNT &&
    reconstructedSarifReport?.runs?.[0]?.properties?.scan_status ===
      "PARTIAL" &&
    reconstructedSarifReport?.runs?.[0]?.properties?.skipped_binaries_count ===
      EXPECTED_SKIPPED_BINARIES;

  const findingsMatch =
    scanOut?.findings_count === EXPECTED_FINDINGS_COUNT &&
    scanOut?.verified_findings_count === EXPECTED_VERIFIED_FINDINGS_COUNT &&
    mdOut?.findings_count === EXPECTED_FINDINGS_COUNT &&
    mdOut?.verified_findings_count === EXPECTED_VERIFIED_FINDINGS_COUNT;

  const check10Passed =
    mdOut?.assessment_status === "PARTIAL" &&
    jsonOut?.assessment_status === "PARTIAL" &&
    sarifOut?.assessment_status === "PARTIAL" &&
    extractionCountsMatch &&
    coverageCountsMatch &&
    mdContainsPartialAndSkipped &&
    jsonContainsPartialAndSkipped &&
    sarifContainsPartialAndSkipped &&
    findingsMatch;

  checks.push({
    id: 10,
    name: "Verify PARTIAL status, findings, coverage, skipped binaries, and reference manifest content reconciliation",
    executed: true,
    passed: check10Passed,
    details: {
      assessment_status: mdOut?.assessment_status ?? null,
      extraction_summary: {
        totalDiscoveredEntries: extSummary?.totalDiscoveredEntries ?? null,
        regularFilesExtracted: extSummary?.regularFilesExtracted ?? null,
        symlinksCount: extSummary?.symlinksCount ?? null,
        directoriesCount: extSummary?.directoriesCount ?? null,
        specialFilesNeutralized: extSummary?.specialFilesNeutralized ?? null,
        classificationCounts: classCounts ?? null,
      },
      reference_manifest_reconciliation: {
        sha256_manifest_canonical_path: refInfo.sha256CanonicalPath,
        symlinks_manifest_canonical_path: refInfo.symlinksCanonicalPath,
        expected_regular_files: EXPECTED_REGULAR_FILES,
        exact_regular_file_hash_matches: exactRegularFileHashMatches,
        missing_regular_files_count: missingRegularFiles.length,
        extra_regular_files_count: extraRegularFiles.length,
        regular_file_hash_mismatches_count: regularFileHashMismatches.length,
        expected_symlinks: EXPECTED_SYMLINKS,
        exact_symlink_target_matches: exactSymlinkTargetMatches,
        missing_symlinks_count: missingSymlinks.length,
        extra_symlinks_count: extraSymlinks.length,
        symlink_target_mismatches_count: symlinkTargetMismatches.length,
        all_manifest_contents_reconciled: manifestContentsReconciled,
      },
      coverage: reportCov ?? null,
      findings: {
        total: mdOut?.findings_count ?? null,
        verified: mdOut?.verified_findings_count ?? null,
      },
      reconstructed_json_counts: {
        assets: reconstructedJsonReport?.assets?.length ?? null,
        analyzed_binaries:
          reconstructedJsonReport?.analyzed_binaries?.length ?? null,
        skipped_binaries:
          reconstructedJsonReport?.skipped_binaries?.length ?? null,
        findings: reconstructedJsonReport?.findings?.length ?? null,
      },
      markdown_verified: mdContainsPartialAndSkipped,
      sarif_verified: sarifContainsPartialAndSkipped,
    },
  });
  log(
    `[Check 10] PARTIAL status, findings (${mdOut?.findings_count}), coverage (1305/990/147/15/132), skipped (${reconstructedJsonReport?.skipped_binaries?.length}), manifest content matches (${exactRegularFileHashMatches}/990 hashes, ${exactSymlinkTargetMatches}/202 symlinks) -> ${
      check10Passed ? "PASS" : "FAIL"
    }`,
  );

  // Evaluate Check 11
  const persistedScanExec = scanExecObsRow?.value_json
    ? JSON.parse(scanExecObsRow.value_json)
    : null;

  const check11Passed =
    assessmentRow?.id === targetAssessmentId &&
    rootAssetRow?.sha256 === EXPECTED_OPENWRT_SHA256 &&
    persistedScanExec?.status === "PARTIAL" &&
    totalAssetsCount === EXPECTED_PERSISTED_ASSETS &&
    skippedBudgetAssetsCount === EXPECTED_SKIPPED_BINARIES &&
    totalTasksCount === EXPECTED_ELIGIBLE_ELF_BINARIES &&
    completedTasksCount === EXPECTED_ANALYZED_BINARIES &&
    openTasksCount === EXPECTED_SKIPPED_BINARIES &&
    nonBinaryTasksCount === 0 &&
    sealedEvidenceCount === EXPECTED_SEALED_EVIDENCE_RECORDS &&
    persistedFindingsCount === EXPECTED_FINDINGS_COUNT &&
    verifiedFindingsCount === EXPECTED_VERIFIED_FINDINGS_COUNT &&
    manifestContentsReconciled;

  checks.push({
    id: 11,
    name: "Confirm SQLite cold-restart persistence and manifest content parity",
    executed: true,
    passed: check11Passed,
    details: {
      assessment_row: assessmentRow,
      root_asset_row: rootAssetRow,
      persisted_scan_execution_status: persistedScanExec?.status ?? null,
      total_assets_in_db: totalAssetsCount,
      skipped_budget_assets_in_db: skippedBudgetAssetsCount,
      total_tasks_in_db: totalTasksCount,
      completed_tasks_in_db: completedTasksCount,
      open_tasks_in_db: openTasksCount,
      non_elf_tasks_scheduled: nonBinaryTasksCount,
      sealed_evidence_records_in_db: sealedEvidenceCount,
      persisted_findings_in_db: persistedFindingsCount,
      verified_findings_in_db: verifiedFindingsCount,
      manifest_contents_reconciled: manifestContentsReconciled,
    },
  });
  log(
    `[Check 11] Native node:sqlite cold-restart inspection (assets=${totalAssetsCount}, tasks=${totalTasksCount} [${completedTasksCount} completed, ${openTasksCount} open], evidence=${sealedEvidenceCount}, findings=${persistedFindingsCount}, manifestReconciled=${manifestContentsReconciled}) -> ${
      check11Passed ? "PASS" : "FAIL"
    }`,
  );

  // -------------------------------------------------------------------------
  // Check 12: Run relevant CLI regression tests
  // -------------------------------------------------------------------------
  const vitestCliPath = resolve(repoRoot, "node_modules/vitest/vitest.mjs");
  const testProc = spawnSync(
    process.execPath,
    [vitestCliPath, "run", "src/cli/securityCommands.test.ts"],
    {
      cwd: repoRoot,
      env: cleanEnv,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  const check12Passed = testProc.status === 0;
  checks.push({
    id: 12,
    name: "Run relevant CLI regression tests (src/cli/securityCommands.test.ts)",
    executed: true,
    passed: check12Passed,
    details: {
      exit_code: testProc.status,
      stdout_tail: (testProc.stdout ?? "").slice(-1200),
    },
  });
  log(
    `[Check 12] CLI regression tests (src/cli/securityCommands.test.ts) -> ${
      check12Passed ? "PASS" : "FAIL"
    }`,
  );

  // Strict gate: Every required check ID (1..12) must have been executed AND passed
  const allMandatoryChecksExecuted =
    checks.length === REQUIRED_CHECK_IDS.length &&
    REQUIRED_CHECK_IDS.every((reqId) =>
      checks.some((c) => c.id === reqId && c.executed === true),
    );
  const allMandatoryChecksPassed =
    allMandatoryChecksExecuted &&
    REQUIRED_CHECK_IDS.every((reqId) =>
      checks.some(
        (c) => c.id === reqId && c.executed === true && c.passed === true,
      ),
    );

  const resultPayload = {
    milestone: "M1.1B_RUNTIME_CONFIRMATION",
    overall_status: allMandatoryChecksPassed ? "PASSED" : "FAILED",
    ready_for_m1_1c: allMandatoryChecksPassed,
    all_mandatory_checks_executed: allMandatoryChecksExecuted,
    all_mandatory_checks_passed: allMandatoryChecksPassed,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    configured_target: {
      selection_source: targetInfo.selectionSource,
      supplied_firmware_path: targetInfo.suppliedPath,
      resolved_firmware_path: targetInfo.resolvedPath,
      canonical_firmware_path: canonicalFirmwarePath,
      target_exists: true,
      expected_sha256: EXPECTED_OPENWRT_SHA256,
      expected_size_bytes: EXPECTED_OPENWRT_SIZE_BYTES,
    },
    reference_manifests: {
      selection_source: refInfo.selectionSource,
      resolved_reference_dir: refInfo.resolvedDir,
      sha256_manifest_path: refInfo.sha256ManifestPath,
      sha256_manifest_canonical_path: refInfo.sha256CanonicalPath,
      sha256_manifest_exists: refInfo.sha256Exists,
      sha256_manifest_entry_count: parsedManifests.regularFilesCount,
      symlinks_manifest_path: refInfo.symlinksManifestPath,
      symlinks_manifest_canonical_path: refInfo.symlinksCanonicalPath,
      symlinks_manifest_exists: refInfo.symlinksExists,
      symlinks_manifest_entry_count: parsedManifests.symlinksCount,
      counts_match_authoritative: parsedManifests.countsMatchAuthoritative,
      all_manifest_contents_reconciled: manifestContentsReconciled,
    },
    expected_openwrt_inventory: {
      discovered_entries: EXPECTED_DISCOVERED_ENTRIES,
      regular_files_extracted: EXPECTED_REGULAR_FILES,
      symlinks: EXPECTED_SYMLINKS,
      directories: EXPECTED_DIRECTORIES,
      special_files_neutralized: EXPECTED_SPECIAL_FILES,
      classification_counts: {
        elf_executable: EXPECTED_ELF_EXECUTABLES,
        elf_shared_library: EXPECTED_ELF_SHARED_LIBS,
        shell_script: EXPECTED_SHELL_SCRIPTS,
        configuration_file: EXPECTED_CONFIG_FILES,
        regular_file: EXPECTED_OTHER_REGULAR_FILES,
      },
      eligible_elf_binaries: EXPECTED_ELIGIBLE_ELF_BINARIES,
      binaries_analyzed: EXPECTED_ANALYZED_BINARIES,
      binaries_partially_analyzed: EXPECTED_PARTIALLY_ANALYZED_BINARIES,
      binaries_skipped_or_failed: EXPECTED_SKIPPED_BINARIES,
      persisted_assets_in_db: EXPECTED_PERSISTED_ASSETS,
      sealed_evidence_records_in_db: EXPECTED_SEALED_EVIDENCE_RECORDS,
      findings_count: EXPECTED_FINDINGS_COUNT,
      verified_findings_count: EXPECTED_VERIFIED_FINDINGS_COUNT,
    },
    runtime: {
      process_version: process.version,
      process_execPath: process.execPath,
      platform: process.platform,
      arch: process.arch,
      package_engines_node: "^22.19.0 || ^24.11.0 || >=26.0.0",
      nvmrc: "24.18.0",
      native_node_sqlite_available: true,
      custom_shims_used: false,
    },
    checks,
  };

  writeFileSync(
    jsonOutPath,
    JSON.stringify(resultPayload, null, 2) + "\n",
    "utf8",
  );
  writeFileSync(logOutPath, logLines.join("\n") + "\n", "utf8");

  if (!allMandatoryChecksPassed) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(
    `Fatal error in runtime confirmation runner: ${err instanceof Error ? err.stack : String(err)}\n`,
  );
  process.exitCode = 1;
});
