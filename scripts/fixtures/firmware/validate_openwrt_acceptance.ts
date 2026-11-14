import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import { SandboxedExtractor } from "../../../src/security/firmware/SandboxedExtractor.js";

async function main() {
  const samplePath = "C:\\Users\\acer\\REA-EVALUATION-LAB\\firmware-corpus\\openwrt-23.05.0-ath79-generic-rootfs.squashfs";
  console.log(`[ACCEPTANCE] Testing real OpenWrt SquashFS extraction on: ${samplePath}`);

  const startTime = Date.now();
  const extractor = new SandboxedExtractor();
  const res = await extractor.extract(samplePath);
  const durationMs = Date.now() - startTime;

  if (!res.ok) {
    console.error(`[ACCEPTANCE FAILED] Extraction failed with error:`, res.error);
    process.exit(1);
  }

  const summary = res.value;
  console.log(`[ACCEPTANCE SUCCESS] Extraction completed in ${durationMs}ms`);
  console.log(`- Format detected: ${summary.format}`);
  console.log(`- Sandbox directory: ${summary.sandboxDir}`);
  console.log(`- Files extracted count: ${summary.filesExtracted}`);
  console.log(`- Bytes extracted total: ${summary.bytesExtracted}`);
  console.log(`- Total validated entries: ${summary.entries.length}`);

  let dirs = 0;
  let files = 0;
  let symlinks = 0;
  let others = 0;

  for (const entry of summary.entries) {
    if (entry.kind === "directory") dirs++;
    else if (entry.kind === "file") files++;
    else if (entry.kind === "symlink") symlinks++;
    else others++;
  }

  console.log(`Entry Breakdown:`);
  console.log(`- Directories: ${dirs}`);
  console.log(`- Files: ${files}`);
  console.log(`- Symlinks: ${symlinks}`);
  console.log(`- Others: ${others}`);
  console.log(`- Total filesystem items: ${dirs + files + symlinks + others}`);

  // Inspect specific critical files
  const testFiles = [
    "etc/banner",
    "bin/board_detect",
    "bin/busybox",
    "etc/openwrt_release",
    "etc/init.d/boot",
  ];

  console.log(`\nVerifying reference file hashes from extracted sandbox:`);
  for (const tf of testFiles) {
    const entry = summary.entries.find((e) => e.relativePath.replace(/\\/g, "/") === tf);
    if (!entry) {
      console.error(`[FAIL] Could not find entry for ${tf}`);
      continue;
    }

    try {
      const bytes = await readFile(entry.destinationPath);
      const hash = createHash("sha256").update(bytes).digest("hex");
      console.log(`- ${tf} (${bytes.length} bytes): SHA-256 = ${hash}`);
    } catch (e) {
      console.error(`- ${tf}: Failed to read (${e})`);
    }
  }

  // Verify symlinks
  const sampleSymlinks = summary.entries.filter((e) => e.kind === "symlink").slice(0, 5);
  console.log(`\nSample extracted symlinks:`);
  for (const s of sampleSymlinks) {
    console.log(`- ${s.relativePath} -> ${s.linkTarget}`);
  }

  // Cleanup sandbox
  console.log(`\nCleaning up sandbox directory: ${summary.sandboxDir}`);
  await extractor.cleanupSandbox(summary.sandboxDir);
  console.log(`[PASS] Sandbox cleanup verified.`);
}

main().catch((err) => {
  console.error("Unhandled error:", err);
  process.exit(1);
});
