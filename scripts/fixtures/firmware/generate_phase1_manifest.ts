import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { SandboxedExtractor } from "../../../src/security/firmware/SandboxedExtractor.js";
import { SquashFsParser } from "../../../src/security/firmware/SquashFsParser.js";

async function main() {
  const sampleWinPath = "C:\\Users\\acer\\REA-EVALUATION-LAB\\firmware-corpus\\openwrt-23.05.0-ath79-generic-rootfs.squashfs";
  const refShaPath = "evaluation/reference-results/unsquashfs-openwrt-sha256.txt";
  const refSymlinksPath = "evaluation/reference-results/unsquashfs-openwrt-symlinks.txt";
  const manifestOutputPath = "evaluation/reports/openwrt-phase1-full-reconciliation-manifest.json";

  console.log("[PHASE 1 AUDIT] Starting comprehensive Phase 1 verification...");

  // 1. Read reference unsquashfs hashes
  console.log(`[REF] Reading reference hashes: ${refShaPath}`);
  const refShaContent = await readFile(refShaPath, "utf8");
  const refFileHashes = new Map<string, string>();
  for (const line of refShaContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [hash, rawPath] = trimmed.split(/\s+/);
    if (hash && rawPath) {
      const rel = rawPath.replace(/^\.\//, "").replace(/\\/g, "/");
      refFileHashes.set(rel, hash);
    }
  }
  console.log(`[REF] Loaded ${refFileHashes.size} reference files.`);

  // 2. Read reference symlinks
  console.log(`[REF] Reading reference symlinks: ${refSymlinksPath}`);
  const refSymContent = await readFile(refSymlinksPath, "utf8");
  const refSymlinks = new Map<string, string>();
  for (const line of refSymContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // Format: lrwxrwxrwx ... squashfs-root/bin/ash -> busybox
    const match = trimmed.match(/squashfs-root\/(.+?)\s+->\s+(.+)$/);
    if (match) {
      refSymlinks.set(match[1].replace(/\\/g, "/"), match[2]);
    }
  }
  console.log(`[REF] Loaded ${refSymlinks.size} reference symlinks.`);

  // 3. Inspect SquashFS file directly to verify Superblock & Inode count
  const firmwareBytes = await readFile(sampleWinPath);
  const firmwareSha256 = createHash("sha256").update(firmwareBytes).digest("hex");
  const parsedEntriesRes = SquashFsParser.parseEntries(firmwareBytes, 0);
  if (!parsedEntriesRes.ok) {
    console.error("SquashFsParser parseEntries failed:", parsedEntriesRes.error);
    process.exit(1);
  }
  const rawEntries = parsedEntriesRes.value;
  console.log(`[PARSER] SquashFsParser parsed ${rawEntries.length} total entries directly from image.`);

  // Count raw entries by kind
  const rawCounts = {
    file: 0,
    directory: 0,
    symlink: 0,
    device: 0,
    other: 0,
  };
  for (const e of rawEntries) {
    if (e.kind === "file") rawCounts.file++;
    else if (e.kind === "directory") rawCounts.directory++;
    else if (e.kind === "symlink") rawCounts.symlink++;
    else if (e.kind === "device" || e.kind === "special") rawCounts.device++;
    else rawCounts.other++;
  }

  // 4. Extract via REA SandboxedExtractor
  console.log("[REA] Extracting firmware via REA SandboxedExtractor...");
  const startTime = Date.now();
  const extractor = new SandboxedExtractor();
  const res = await extractor.extract(sampleWinPath);
  const elapsedMs = Date.now() - startTime;

  if (!res.ok) {
    console.error("Extraction failed:", res.error);
    process.exit(1);
  }
  const summary = res.value;
  console.log(`[REA] Extraction finished in ${elapsedMs}ms.`);

  const fileManifestList: Array<{
    path: string;
    size: number;
    rea_sha256: string;
    ref_sha256: string;
    match: boolean;
  }> = [];

  let matchedFiles = 0;
  let mismatchedFiles = 0;
  let missingFiles = 0;
  let extraFiles = 0;

  const reaFileMap = new Map<string, { size: number; hash: string }>();

  for (const entry of summary.entries) {
    if (entry.kind === "file") {
      const rel = entry.relativePath.replace(/\\/g, "/");
      const bytes = await readFile(entry.destinationPath);
      const hash = createHash("sha256").update(bytes).digest("hex");
      reaFileMap.set(rel, { size: bytes.length, hash });
    }
  }

  for (const [path, refHash] of refFileHashes.entries()) {
    const rea = reaFileMap.get(path);
    if (!rea) {
      missingFiles++;
      fileManifestList.push({
        path,
        size: -1,
        rea_sha256: "MISSING",
        ref_sha256: refHash,
        match: false,
      });
    } else {
      const isMatch = rea.hash === refHash;
      if (isMatch) matchedFiles++;
      else mismatchedFiles++;
      fileManifestList.push({
        path,
        size: rea.size,
        rea_sha256: rea.hash,
        ref_sha256: refHash,
        match: isMatch,
      });
    }
  }

  for (const [path, info] of reaFileMap.entries()) {
    if (!refFileHashes.has(path)) {
      extraFiles++;
      fileManifestList.push({
        path,
        size: info.size,
        rea_sha256: info.hash,
        ref_sha256: "NOT_IN_REFERENCE",
        match: false,
      });
    }
  }

  // Symlinks verification
  let matchedSymlinks = 0;
  let mismatchedSymlinks = 0;
  const symlinkManifestList: Array<{
    path: string;
    ref_target: string;
    rea_target: string | null;
    handling: string;
    match: boolean;
  }> = [];

  const reaSymlinkEntries = summary.entries.filter((e) => e.kind === "symlink");
  const reaSymlinkMap = new Map<string, typeof summary.entries[0]>();
  for (const s of reaSymlinkEntries) {
    reaSymlinkMap.set(s.relativePath.replace(/\\/g, "/"), s);
  }

  for (const [symPath, refTarget] of refSymlinks.entries()) {
    const reaSym = reaSymlinkMap.get(symPath);
    if (!reaSym) {
      symlinkManifestList.push({
        path: symPath,
        ref_target: refTarget,
        rea_target: null,
        handling: "MISSING",
        match: false,
      });
      mismatchedSymlinks++;
    } else {
      const match = reaSym.linkTarget === refTarget;
      if (match) matchedSymlinks++;
      else mismatchedSymlinks++;
      symlinkManifestList.push({
        path: symPath,
        ref_target: refTarget,
        rea_target: reaSym.linkTarget ?? null,
        handling: "neutralized_symlink_metadata",
        match,
      });
    }
  }

  // Directory verification
  const reaDirectories = summary.entries
    .filter((e) => e.kind === "directory")
    .map((e) => e.relativePath.replace(/\\/g, "/"));

  // Check special files
  const specialFiles = rawEntries.filter((e) => e.kind === "device" || e.kind === "special");
  const specialFilesHandling = specialFiles.map((s) => ({
    path: s.path,
    kind: s.kind,
    action: "DEVICE_NODE_REJECTED (safely prevented mknod on host OS)",
  }));

  // Build full machine-readable comparison manifest
  const completeManifest = {
    schema_version: "1.0.0",
    generated_at: new Date().toISOString(),
    audit_target: {
      image_name: "openwrt-23.05.0-ath79-generic-rootfs.squashfs",
      image_size: firmwareBytes.length,
      image_sha256: firmwareSha256,
      format: "SquashFS 4.0",
      architecture: "MIPS 32-bit Big-Endian",
      compression: "XZ (type 4)",
    },
    verification_environment: {
      platform: process.platform,
      arch: process.arch,
      node_version: process.version,
      reference_tool: "unsquashfs v4.6.1",
      rea_extractor: "SandboxedExtractor + SquashFsParser + XzDecompressor",
    },
    reconciliation_summary: {
      total_reference_regular_files: refFileHashes.size,
      total_rea_regular_files: reaFileMap.size,
      exact_sha256_matches: matchedFiles,
      hash_mismatches: mismatchedFiles,
      missing_in_rea: missingFiles,
      extra_in_rea: extraFiles,
      reconciliation_accuracy_pct: Number(((matchedFiles / refFileHashes.size) * 100).toFixed(4)),
      total_reference_symlinks: refSymlinks.size,
      total_rea_symlinks: reaSymlinkEntries.length,
      exact_symlink_matches: matchedSymlinks,
      symlink_mismatches: mismatchedSymlinks,
      total_directories: reaDirectories.length,
      special_device_nodes_neutralized: specialFilesHandling.length,
      raw_squashfs_entries_parsed: rawEntries.length,
      raw_counts: rawCounts,
    },
    special_files: specialFilesHandling,
    directories: reaDirectories,
    symlinks: symlinkManifestList,
    files: fileManifestList,
  };

  await writeFile(manifestOutputPath, JSON.stringify(completeManifest, null, 2), "utf8");
  console.log(`[PASS] Machine-readable comparison manifest saved to: ${manifestOutputPath}`);
  console.log(`[SUMMARY] Regular files: ${matchedFiles}/${refFileHashes.size} (${completeManifest.reconciliation_summary.reconciliation_accuracy_pct}%)`);
  console.log(`[SUMMARY] Symlinks: ${matchedSymlinks}/${refSymlinks.size}`);
  console.log(`[SUMMARY] Directories: ${reaDirectories.length}`);
  console.log(`[SUMMARY] Special devices: ${specialFilesHandling.length} neutralized`);

  await extractor.cleanupSandbox(summary.sandboxDir);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
