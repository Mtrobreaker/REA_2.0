import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { SandboxedExtractor } from "../../../src/security/firmware/SandboxedExtractor.js";

async function main() {
  const sampleWinPath = "C:\\Users\\acer\\REA-EVALUATION-LAB\\firmware-corpus\\openwrt-23.05.0-ath79-generic-rootfs.squashfs";
  const refFilePath = "evaluation/reference-results/unsquashfs-openwrt-sha256.txt";

  console.log("[AUDIT] Starting full 990-file SHA-256 reconciliation audit...");

  // 1. Read reference unsquashfs hashes
  console.log(`[REF] Reading reference hashes from: ${refFilePath}`);
  const refContent = await readFile(refFilePath, "utf8");
  const refFileHashes = new Map<string, string>();

  for (const line of refContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [hash, rawPath] = trimmed.split(/\s+/);
    if (hash && rawPath) {
      const rel = rawPath.replace(/^\.\//, "").replace(/\\/g, "/");
      refFileHashes.set(rel, hash);
    }
  }
  console.log(`[REF] Loaded ${refFileHashes.size} reference file hashes.`);

  // 2. Extract via REA SandboxedExtractor
  console.log("[REA] Extracting firmware via REA SandboxedExtractor...");
  const startTime = Date.now();
  const extractor = new SandboxedExtractor();
  const res = await extractor.extract(sampleWinPath);
  const elapsedMs = Date.now() - startTime;

  if (!res.ok) {
    console.error("REA extraction failed:", res.error);
    process.exit(1);
  }
  const summary = res.value;
  console.log(`[REA] Extraction finished in ${elapsedMs}ms.`);

  // Compute REA file hashes
  const reaFileHashes = new Map<string, { size: number; hash: string }>();
  for (const entry of summary.entries) {
    if (entry.kind === "file") {
      const rel = entry.relativePath.replace(/\\/g, "/");
      const bytes = await readFile(entry.destinationPath);
      const hash = createHash("sha256").update(bytes).digest("hex");
      reaFileHashes.set(rel, { size: bytes.length, hash });
    }
  }
  console.log(`[REA] Extracted ${reaFileHashes.size} regular files.`);

  // 3. Reconcile both sets
  let matched = 0;
  let mismatched = 0;
  let missingInRea = 0;
  let extraInRea = 0;

  for (const [path, refHash] of refFileHashes.entries()) {
    const rea = reaFileHashes.get(path);
    if (!rea) {
      console.error(`[MISSING IN REA] ${path}`);
      missingInRea++;
    } else if (rea.hash !== refHash) {
      console.error(`[HASH MISMATCH] ${path}: REA=${rea.hash} REF=${refHash}`);
      mismatched++;
    } else {
      matched++;
    }
  }

  for (const path of reaFileHashes.keys()) {
    if (!refFileHashes.has(path)) {
      console.error(`[EXTRA IN REA] ${path}`);
      extraInRea++;
    }
  }

  console.log("\n================ RECONCILIATION SUMMARY ================");
  console.log(`Total Reference Regular Files: ${refFileHashes.size}`);
  console.log(`Total REA Regular Files:       ${reaFileHashes.size}`);
  console.log(`Exact SHA-256 Matches:         ${matched}`);
  console.log(`Hash Mismatches:               ${mismatched}`);
  console.log(`Missing in REA:                ${missingInRea}`);
  console.log(`Extra in REA:                  ${extraInRea}`);
  console.log(`Match Accuracy:                ${((matched / refFileHashes.size) * 100).toFixed(2)}%`);
  console.log("========================================================\n");

  await extractor.cleanupSandbox(summary.sandboxDir);

  if (mismatched > 0 || missingInRea > 0 || extraInRea > 0) {
    process.exit(1);
  }
}

main().catch((e) => {
  console.error("Audit error:", e);
  process.exit(1);
});
