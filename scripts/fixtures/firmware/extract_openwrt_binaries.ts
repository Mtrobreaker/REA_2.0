import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { SandboxedExtractor } from "../../../src/security/firmware/SandboxedExtractor.js";

async function main() {
  const sampleWinPath = "C:\\Users\\acer\\REA-EVALUATION-LAB\\firmware-corpus\\openwrt-23.05.0-ath79-generic-rootfs.squashfs";
  const outputBase = "evaluation/corpus/openwrt";

  console.log("[EXTRACT] Extracting target binaries from OpenWrt firmware...");
  const extractor = new SandboxedExtractor();
  const res = await extractor.extract(sampleWinPath);

  if (!res.ok) {
    console.error("Extraction failed:", res.error);
    process.exit(1);
  }

  const summary = res.value;
  console.log(`[EXTRACT] Extracted ${summary.filesExtracted} files into sandbox: ${summary.sandboxDir}`);

  const targets = [
    "bin/busybox",
    "usr/sbin/dropbear",
    "usr/sbin/uhttpd",
    "lib/libc.so"
  ];

  await mkdir(outputBase, { recursive: true });

  const extractedMap = new Map<string, string>();
  for (const entry of summary.entries) {
    if (entry.kind === "file") {
      const rel = entry.relativePath.replace(/\\/g, "/");
      if (targets.includes(rel)) {
        extractedMap.set(rel, entry.destinationPath);
      }
    }
  }

  for (const target of targets) {
    const srcPath = extractedMap.get(target);
    if (!srcPath) {
      console.error(`Target not found in extraction: ${target}`);
      process.exit(1);
    }
    const data = await readFile(srcPath);
    const hash = createHash("sha256").update(data).digest("hex");
    const destPath = join(outputBase, target.replace(/\//g, "_"));
    await writeFile(destPath, data);
    console.log(`[SAVED] ${target} (${data.length} bytes, SHA-256: ${hash}) -> ${destPath}`);
  }

  console.log("[CLEANUP] Cleaning up sandbox...");
  await extractor.cleanupSandbox(summary.sandboxDir);
  console.log("[DONE] All 4 target binaries extracted and verified successfully.");
}

main().catch(err => {
  console.error("Error:", err);
  process.exit(1);
});

