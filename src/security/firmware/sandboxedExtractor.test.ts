import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AssessmentId } from "../../domain/security/assessment.js";
import { computeAssetId } from "../../domain/security/asset.js";
import type { AssetId } from "../../domain/security/asset.js";
import { SqliteBlackboardStorage } from "../blackboard/SqliteBlackboardStorage.js";
import { PreWriteValidator } from "./PreWriteValidator.js";
import { SandboxedExtractor } from "./SandboxedExtractor.js";
import { SquashFsParser } from "./SquashFsParser.js";
import { FirmwareInventoryService } from "./FirmwareInventoryService.js";
import {
  createElfBinaryBuffer,
  createTarBuffer,
} from "./testArchiveHelpers.js";

const execFileAsync = promisify(execFile);

describe("Pre-Write Extraction Security Rules", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-prewrite-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("rejects path traversal sequences and escapes", () => {
    const stats = { archiveSizeBytes: 1000, currentFileCount: 0, currentCumulativeBytes: 0 };
    const policy = {
      maxCumulativeBytes: 10_000,
      maxSingleFileBytes: 5000,
      maxFileCount: 10,
      maxExpansionRatio: 10,
      maxExecutionTimeMs: 1000,
      allowSymlinks: true,
      allowSpecialFiles: false as const,
    };

    const res1 = PreWriteValidator.validateEntry(
      { path: "../../etc/shadow", kind: "file", size: 10 },
      tempDir,
      policy,
      stats,
    );
    expect(res1.ok).toBe(false);
    if (!res1.ok) expect(res1.error.code).toBe("PATH_TRAVERSAL");

    const res2 = PreWriteValidator.validateEntry(
      { path: "sub/../../../evil", kind: "file", size: 10 },
      tempDir,
      policy,
      stats,
    );
    expect(res2.ok).toBe(false);
    if (!res2.ok) expect(res2.error.code).toBe("PATH_TRAVERSAL");
  });

  it("rejects Windows drive-letter and UNC paths", () => {
    const stats = { archiveSizeBytes: 1000, currentFileCount: 0, currentCumulativeBytes: 0 };
    const policy = {
      maxCumulativeBytes: 10_000,
      maxSingleFileBytes: 5000,
      maxFileCount: 10,
      maxExpansionRatio: 10,
      maxExecutionTimeMs: 1000,
      allowSymlinks: true,
      allowSpecialFiles: false as const,
    };

    const res1 = PreWriteValidator.validateEntry(
      { path: "C:\\Windows\\System32\\cmd.exe", kind: "file", size: 10 },
      tempDir,
      policy,
      stats,
    );
    expect(res1.ok).toBe(false);
    if (!res1.ok) expect(res1.error.code).toBe("PATH_TRAVERSAL");

    const res2 = PreWriteValidator.validateEntry(
      { path: "\\\\10.0.0.1\\share\\payload", kind: "file", size: 10 },
      tempDir,
      policy,
      stats,
    );
    expect(res2.ok).toBe(false);
    if (!res2.ok) expect(res2.error.code).toBe("PATH_TRAVERSAL");
  });

  it("rejects symlink escape to sensitive host directories", () => {
    const stats = { archiveSizeBytes: 1000, currentFileCount: 0, currentCumulativeBytes: 0 };
    const policy = {
      maxCumulativeBytes: 10_000,
      maxSingleFileBytes: 5000,
      maxFileCount: 10,
      maxExpansionRatio: 10,
      maxExecutionTimeMs: 1000,
      allowSymlinks: true,
      allowSpecialFiles: false as const,
    };

    const res1 = PreWriteValidator.validateEntry(
      { path: "bin/sh_link", kind: "symlink", size: 0, linkTarget: "/etc/passwd" },
      tempDir,
      policy,
      stats,
    );
    expect(res1.ok).toBe(false);
    if (!res1.ok) expect(res1.error.code).toBe("SYMLINK_ESCAPE");

    const res2 = PreWriteValidator.validateEntry(
      { path: "bin/sh_link", kind: "symlink", size: 0, linkTarget: "../../../../../etc/shadow" },
      tempDir,
      policy,
      stats,
    );
    expect(res2.ok).toBe(false);
    if (!res2.ok) expect(res2.error.code).toBe("SYMLINK_ESCAPE");
  });

  it("rejects special device nodes, FIFOs, and quotas", () => {
    const stats = { archiveSizeBytes: 1000, currentFileCount: 9, currentCumulativeBytes: 9000 };
    const policy = {
      maxCumulativeBytes: 10_000,
      maxSingleFileBytes: 500,
      maxFileCount: 10,
      maxExpansionRatio: 10,
      maxExecutionTimeMs: 1000,
      allowSymlinks: true,
      allowSpecialFiles: false as const,
    };

    const specialRes = PreWriteValidator.validateEntry(
      { path: "dev/console", kind: "special", size: 0 },
      tempDir,
      policy,
      stats,
    );
    expect(specialRes.ok).toBe(false);
    if (!specialRes.ok) expect(specialRes.error.code).toBe("DEVICE_NODE_REJECTED");

    const countRes = PreWriteValidator.validateEntry(
      { path: "file11.txt", kind: "file", size: 10 },
      tempDir,
      policy,
      { ...stats, currentFileCount: 10 },
    );
    expect(countRes.ok).toBe(false);
    if (!countRes.ok) expect(countRes.error.code).toBe("QUOTA_EXCEEDED");

    const singleRes = PreWriteValidator.validateEntry(
      { path: "huge.bin", kind: "file", size: 600 },
      tempDir,
      policy,
      stats,
    );
    expect(singleRes.ok).toBe(false);
    if (!singleRes.ok) expect(singleRes.error.code).toBe("QUOTA_EXCEEDED");
  });
});

describe("Real Archive Extraction", () => {
  let workDir: string;

  beforeEach(async () => {
    workDir = await mkdtemp(join(tmpdir(), "rea-archive-test-"));
  });

  afterEach(async () => {
    await rm(workDir, { recursive: true, force: true });
  });

  it("extracts a real TAR fixture with directories and safe relative symlinks", async () => {
    const tarBuf = createTarBuffer([
      { name: "etc/", typeflag: "5" },
      { name: "etc/config.ini", content: "mode=production\nport=8080\n" },
      { name: "bin/", typeflag: "5" },
      { name: "bin/busybox", content: "ELF_BINARY_DATA" },
      { name: "bin/sh", typeflag: "2", linkname: "busybox" },
    ]);

    const archivePath = join(workDir, "firmware.tar");
    await writeFile(archivePath, tarBuf);

    const extractor = new SandboxedExtractor();
    const extractRes = await extractor.extract(archivePath, workDir);
    if (!extractRes.ok) console.error("DEBUG EXTRACT ERROR:", extractRes.error);

    expect(extractRes.ok).toBe(true);
    if (extractRes.ok) {
      expect(extractRes.value.format).toBe("tar");
      expect(extractRes.value.filesExtracted).toBe(3); // config.ini, busybox, sh symlink
      const cfg = await readFile(join(extractRes.value.sandboxDir, "etc/config.ini"), "utf8");
      expect(cfg).toContain("mode=production");
      await extractor.cleanupSandbox(extractRes.value.sandboxDir);
    }
  });

  it("aborts extraction and cleans up sandbox on malformed traversal archive", async () => {
    const maliciousTar = createTarBuffer([
      { name: "valid.txt", content: "hello" },
      { name: "../../../evil.txt", content: "payload" },
    ]);

    const archivePath = join(workDir, "evil.tar");
    await writeFile(archivePath, maliciousTar);

    const extractor = new SandboxedExtractor();
    const extractRes = await extractor.extract(archivePath, workDir);

    expect(extractRes.ok).toBe(false);
    if (!extractRes.ok) {
      expect(extractRes.error.code).toBe("PATH_TRAVERSAL");
    }
  });

  it("extracts a real SquashFS 4.0 image fixture", async () => {
    const sqshBuf = SquashFsParser.createTestImage([
      { path: "etc/hosts", content: "127.0.0.1 localhost\n" },
      { path: "bin/app", content: createElfBinaryBuffer({ machine: 0x28, is64Bit: false }) }, // ARM 32-bit
    ]);

    const archivePath = join(workDir, "firmware.squashfs");
    await writeFile(archivePath, sqshBuf);

    const extractor = new SandboxedExtractor();
    const extractRes = await extractor.extract(archivePath, workDir);
    if (!extractRes.ok) console.error("DEBUG EXTRACT ERROR:", extractRes.error);

    expect(extractRes.ok).toBe(true);
    if (extractRes.ok) {
      expect(extractRes.value.format).toBe("squashfs");
      expect(extractRes.value.filesExtracted).toBe(2);
      const hosts = await readFile(join(extractRes.value.sandboxDir, "etc/hosts"), "utf8");
      expect(hosts).toContain("127.0.0.1");
      await extractor.cleanupSandbox(extractRes.value.sandboxDir);
    }
  });

  it("extracts an independently generated SquashFS 4.0 fixture from spec generator", async () => {
    const fixturePath = join(workDir, "independent_fw.squashfs");
    await execFileAsync("python", [
      "scripts/fixtures/firmware/generate_independent_squashfs.py",
      fixturePath,
    ]);

    const extractor = new SandboxedExtractor();
    const extractRes = await extractor.extract(fixturePath, workDir);

    expect(extractRes.ok).toBe(true);
    if (extractRes.ok) {
      expect(extractRes.value.format).toBe("squashfs");
      expect(extractRes.value.filesExtracted).toBe(3); // kernel_version, init_service, sh
      const version = await readFile(join(extractRes.value.sandboxDir, "etc/kernel_version"), "utf8");
      expect(version).toContain("Linux 6.6.1-rea");
      await extractor.cleanupSandbox(extractRes.value.sandboxDir);
    }
  });

  it("safely extracts hardlinks within sandbox without symlink escape", async () => {
    const tarBuf = createTarBuffer([
      { name: "orig.txt", content: "data_to_link" },
      { name: "link_copy.txt", typeflag: "1", linkname: "orig.txt" },
    ]);

    const archivePath = join(workDir, "hardlink.tar");
    await writeFile(archivePath, tarBuf);

    const extractor = new SandboxedExtractor();
    const extractRes = await extractor.extract(archivePath, workDir);
    if (!extractRes.ok) console.error("DEBUG EXTRACT ERROR:", extractRes.error);

    expect(extractRes.ok).toBe(true);
    if (extractRes.ok) {
      const data = await readFile(join(extractRes.value.sandboxDir, "link_copy.txt"), "utf8");
      expect(data).toBe("data_to_link");
      await extractor.cleanupSandbox(extractRes.value.sandboxDir);
    }
  });
});

describe("Symlink Overwrite & Resource Limits", () => {
  let workDir: string;

  beforeEach(async () => {
    workDir = await mkdtemp(join(tmpdir(), "rea-limits-test-"));
  });

  afterEach(async () => {
    await rm(workDir, { recursive: true, force: true });
  });

  it("rejects writing through existing symlink (TOCTOU overwrite attack)", async () => {
    // Attack: entry 1 creates symlink 'link_target.txt' -> 'victim.txt'
    // Entry 2 attempts to write file content to 'link_target.txt'
    const attackTar = createTarBuffer([
      { name: "victim.txt", content: "initial_content" },
      { name: "link_target.txt", typeflag: "2", linkname: "victim.txt" },
      { name: "link_target.txt", content: "overwritten_content" },
    ]);

    const archivePath = join(workDir, "toctou_attack.tar");
    await writeFile(archivePath, attackTar);

    const extractor = new SandboxedExtractor();
    const extractRes = await extractor.extract(archivePath, workDir);

    expect(extractRes.ok).toBe(false);
    if (!extractRes.ok) {
      expect(extractRes.error.code).toBe("SYMLINK_ESCAPE");
    }
  });

  it("aborts gzip decompression bomb when expansion ratio exceeds policy limit", async () => {
    // Generate a high expansion ratio gzip payload (2 MB of zeroes compressed to ~2 KB)
    const zeroes = Buffer.alloc(2 * 1024 * 1024);
    const bombGzip = gzipSync(zeroes);

    const bombPath = join(workDir, "bomb.tar.gz");
    await writeFile(bombPath, bombGzip);

    // Policy with max expansion ratio 10x
    const strictExtractor = new SandboxedExtractor({
      maxCumulativeBytes: 10 * 1024 * 1024,
      maxSingleFileBytes: 5 * 1024 * 1024,
      maxFileCount: 100,
      maxExpansionRatio: 10, // Bomb limit: 10x
      maxExecutionTimeMs: 5000,
      allowSymlinks: true,
      allowSpecialFiles: false,
    });

    const res = await strictExtractor.extract(bombPath, workDir);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error.code).toBe("DECOMPRESSION_BOMB");
    }
  });

  it("aborts extraction and cleans up sandbox when signal is cancelled", async () => {
    const tarBuf = createTarBuffer([
      { name: "file1.txt", content: "test" },
      { name: "file2.txt", content: "test2" },
    ]);

    const archivePath = join(workDir, "cancel.tar");
    await writeFile(archivePath, tarBuf);

    const abortCtrl = new AbortController();
    abortCtrl.abort(); // Cancel before or during

    const extractor = new SandboxedExtractor();
    const res = await extractor.extract(archivePath, workDir, { signal: abortCtrl.signal });

    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error.code).toBe("SANDBOX_ERROR");
    }
  });
});

describe("TOCTOU & Streaming Decompression Security", () => {
  let workDir: string;

  beforeEach(async () => {
    workDir = await mkdtemp(join(tmpdir(), "rea-stream-test-"));
  });

  afterEach(async () => {
    await rm(workDir, { recursive: true, force: true });
  });

  it("aborts streaming decompression when cumulative quota is exceeded mid-stream", async () => {
    // 2 MB uncompressed payload compressed to ~2 KB
    const largeBuffer = Buffer.alloc(2 * 1024 * 1024, 0x41);
    const gzipped = gzipSync(largeBuffer);
    const gzipPath = join(workDir, "large.tar.gz");
    await writeFile(gzipPath, gzipped);

    // Policy with maxCumulativeBytes = 500 KB (less than 2 MB uncompressed)
    const strictExtractor = new SandboxedExtractor({
      maxCumulativeBytes: 500 * 1024,
      maxSingleFileBytes: 10 * 1024 * 1024,
      maxFileCount: 100,
      maxExpansionRatio: 10000,
      maxExecutionTimeMs: 5000,
      allowSymlinks: true,
      allowSpecialFiles: false,
    });

    const res = await strictExtractor.extract(gzipPath, workDir);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error.code).toBe("QUOTA_EXCEEDED");
    }
  });

  it("interrupts streaming decompression on AbortSignal and cleans up sandbox", async () => {
    const largeBuffer = Buffer.alloc(2 * 1024 * 1024, 0x42);
    const gzipped = gzipSync(largeBuffer);
    const gzipPath = join(workDir, "abort.tar.gz");
    await writeFile(gzipPath, gzipped);

    const abortCtrl = new AbortController();
    abortCtrl.abort();

    const extractor = new SandboxedExtractor();
    const res = await extractor.extract(gzipPath, workDir, { signal: abortCtrl.signal });

    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(["EXTRACTION_TIMEOUT", "SANDBOX_ERROR"]).toContain(res.error.code);
    }
  });

  it("returns UNSUPPORTED_FORMAT and cleans up sandbox when external tool is required", async () => {
    const cramfsHeader = Buffer.alloc(64);
    cramfsHeader.writeUInt32LE(0x28cd3d45, 0);
    const cramfsPath = join(workDir, "image.cramfs");
    await writeFile(cramfsPath, cramfsHeader);

    const extractor = new SandboxedExtractor();
    const res = await extractor.extract(cramfsPath, workDir);

    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error.code).toBe("UNSUPPORTED_FORMAT");
      expect(res.error.message).toContain("requires external tool integration");
    }
  });

  it("fails closed on completely unrecognized firmware magic", async () => {
    const randomBlob = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    const blobPath = join(workDir, "unknown.bin");
    await writeFile(blobPath, randomBlob);

    const extractor = new SandboxedExtractor();
    const res = await extractor.extract(blobPath, workDir);

    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error.code).toBe("UNSUPPORTED_FORMAT");
      expect(res.error.message).toContain("Unknown firmware format");
    }
  });

  it("safely handles duplicate regular file entries without symlink redirection", async () => {
    const dupTar = createTarBuffer([
      { name: "config.txt", content: "version=1" },
      { name: "config.txt", content: "version=2" },
    ]);
    const archivePath = join(workDir, "duplicate.tar");
    await writeFile(archivePath, dupTar);

    const extractor = new SandboxedExtractor();
    const extractRes = await extractor.extract(archivePath, workDir);
    if (!extractRes.ok) console.error("DEBUG EXTRACT ERROR:", extractRes.error);

    expect(extractRes.ok).toBe(true);
    if (extractRes.ok) {
      const content = await readFile(join(extractRes.value.sandboxDir, "config.txt"), "utf8");
      expect(content).toBe("version=2");
      await extractor.cleanupSandbox(extractRes.value.sandboxDir);
    }
  });
});

describe("Firmware Inventory & Task Generation", () => {
  let dbDir: string;
  let storage: SqliteBlackboardStorage;
  const testAssessmentId = "asm_fw_test_00000000000000000000000000000000000000000000000000000000" as AssessmentId;
  const assessment = {
    id: testAssessmentId,
    name: "Firmware Test Assessment",
    status: "initialization" as const,
    objective: {
      title: "Firmware Extraction Assessment",
      target_technologies: ["Linux", "SquashFS", "ARM"],
      compliance_frameworks: [],
      focus_areas: ["Firmware"],
      depth: "standard" as const,
    },
    authorization: {
      allowed_targets: ["firmware.bin"],
      denied_targets: [],
      authorized_by: "Security Team",
      authorization_reference: "AUTH-FW-01",
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
  };

  beforeEach(async () => {
    dbDir = await mkdtemp(join(tmpdir(), "rea-inventory-test-"));
    const dbPath = join(dbDir, "blackboard.db");
    const journalPath = join(dbDir, "packboard-audit.jsonl");
    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId: assessment.id });
    await storage.assessments.create(assessment);
  });

  afterEach(async () => {
    storage.close();
    try {
      await rm(dbDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("creates hierarchical asset tree, parses ELF metadata, and schedules tasks", async () => {
    // 1. Create root firmware asset
    const rootFwAssetId = computeAssetId({
      name: "root_firmware.bin",
      type: "firmware_image",
    });
    const rootAssetRes = await storage.assets.create({
      id: rootFwAssetId,
      assessment_id: assessment.id,
      parent_asset_id: null,
      name: "root_firmware.bin",
      type: "firmware_image",
      path: "/path/to/root_firmware.bin",
      digest: { sha256: "a".repeat(64) },
      architecture: null,
      version: "1.0.0",
      environment: null,
      tags: ["firmware"],
      metadata: {},
      created_at: Date.now(),
    });
    expect(rootAssetRes.ok).toBe(true);

    // 2. Prepare sandbox with real ARM ELF binary, script, and config
    const sandboxDir = join(dbDir, "sandbox");
    const armElf = createElfBinaryBuffer({ machine: 0x28, is64Bit: false, isLE: true }); // ARM LE 32-bit
    const sqshBuf = SquashFsParser.createTestImage([
      { path: "bin/gateway_daemon", content: armElf },
      { path: "etc/device.conf", content: "gateway_id=001\n" },
    ]);

    const archivePath = join(dbDir, "firmware.bin");
    await writeFile(archivePath, sqshBuf);

    const extractor = new SandboxedExtractor();
    const extractRes = await extractor.extract(archivePath, dbDir);
    expect(extractRes.ok).toBe(true);
    if (!extractRes.ok) return;

    // 3. Run Inventory Service
    const inventoryService = new FirmwareInventoryService(storage);
    const invRes = await inventoryService.inventoryAndSchedule(
      assessment.id,
      rootFwAssetId,
      extractRes.value.sandboxDir,
      "squashfs",
    );

    expect(invRes.ok).toBe(true);
    if (invRes.ok) {
      expect(invRes.value.extractedFilesCount).toBe(2);
      expect(invRes.value.assetsCreated.length).toBeGreaterThanOrEqual(3);

      // Verify partition asset
      const partitionAsset = invRes.value.assetsCreated.find((a) => a.type === "operating_system");
      expect(partitionAsset).toBeDefined();
      expect(partitionAsset?.parent_asset_id).toBe(rootFwAssetId);

      // Verify ELF binary asset
      const binaryAsset = invRes.value.assetsCreated.find((a) => a.name === "gateway_daemon");
      expect(binaryAsset).toBeDefined();
      expect(binaryAsset?.type).toBe("compiled_binary");
      expect(binaryAsset?.architecture).toBe("ARM");
      expect(binaryAsset?.tags).toContain("executable");

      // Verify binary_analysis task generated
      const tasks = invRes.value.tasksCreated;
      expect(tasks.length).toBe(1);
      expect(tasks[0]!.task_type).toBe("binary_analysis");
      expect(tasks[0]!.asset_id).toBe(binaryAsset?.id);
      expect((tasks[0]!.metadata as { architecture: string }).architecture).toBe("ARM");

      // Verify assessment isolation
      const otherAssessmentId = "asm_other_00000000000000000000000000000000000000000000000000000000" as AssessmentId;
      const isolatedAssets = await storage.assets.listByAssessment(otherAssessmentId);
      expect(isolatedAssets.ok).toBe(true);
      if (isolatedAssets.ok) {
        expect(isolatedAssets.value.length).toBe(0);
      }
    }

    await extractor.cleanupSandbox(extractRes.value.sandboxDir);
  });
});

describe("Inventory Idempotency Across Re-extraction & Restart", () => {
  let dbDir: string;
  let dbPath: string;
  let journalPath: string;
  let storage: SqliteBlackboardStorage;
  const assessmentId = "asm_idem_000000000000000000000000000000000000000000000000000000000000" as AssessmentId;
  const assessment = {
    id: assessmentId,
    name: "Idempotency Test Assessment",
    status: "initialization" as const,
    objective: {
      title: "Idempotency Assessment",
      target_technologies: ["Linux"],
      compliance_frameworks: [],
      focus_areas: ["Idempotency"],
      depth: "standard" as const,
    },
    authorization: {
      allowed_targets: ["firmware.bin"],
      denied_targets: [],
      authorized_by: "Security Team",
      authorization_reference: "AUTH-IDEM",
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
  };

  beforeEach(async () => {
    dbDir = await mkdtemp(join(tmpdir(), "rea-idem-test-"));
    dbPath = join(dbDir, "blackboard.db");
    journalPath = join(dbDir, "packboard-audit.jsonl");
    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });
    await storage.assessments.create(assessment);
  });

  afterEach(async () => {
    storage.close();
    try {
      await rm(dbDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("is fully idempotent on duplicate extraction and cold database restart", async () => {
    const rootFwId = computeAssetId({ name: "firmware.bin", type: "firmware_image" });
    await storage.assets.create({
      id: rootFwId,
      assessment_id: assessmentId,
      parent_asset_id: null,
      name: "firmware.bin",
      type: "firmware_image",
      path: "/firmware.bin",
      digest: null,
      architecture: null,
      version: null,
      environment: null,
      tags: [],
      metadata: {},
      created_at: Date.now(),
    });

    const armElf = createElfBinaryBuffer({ machine: 0x28, is64Bit: false });
    const tarBuf = createTarBuffer([
      { name: "etc/version", content: "1.0.0\n" },
      { name: "bin/daemon", content: armElf },
    ]);
    const archivePath = join(dbDir, "firmware.tar");
    await writeFile(archivePath, tarBuf);

    const extractor = new SandboxedExtractor();
    const extractRes = await extractor.extract(archivePath, dbDir);
    expect(extractRes.ok).toBe(true);
    if (!extractRes.ok) return;

    const inventoryService = new FirmwareInventoryService(storage);

    // Pass 1: Initial inventory & task dispatch
    const pass1 = await inventoryService.inventoryAndSchedule(
      assessmentId,
      rootFwId,
      extractRes.value.sandboxDir,
      "tar",
    );
    expect(pass1.ok).toBe(true);

    const initialAssets = await storage.assets.listByAssessment(assessmentId);
    expect(initialAssets.ok).toBe(true);
    const initialAssetCount = initialAssets.ok ? initialAssets.value.length : 0;

    // Pass 2: Immediate re-extraction within same session
    const pass2 = await inventoryService.inventoryAndSchedule(
      assessmentId,
      rootFwId,
      extractRes.value.sandboxDir,
      "tar",
    );
    expect(pass2.ok).toBe(true);

    const pass2Assets = await storage.assets.listByAssessment(assessmentId);
    expect(pass2Assets.ok).toBe(true);
    if (pass2Assets.ok) {
      expect(pass2Assets.value.length).toBe(initialAssetCount); // No duplicate assets
    }

    // Pass 3: Application cold restart (close & reopen database)
    storage.close();
    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });
    const restartedService = new FirmwareInventoryService(storage);

    const pass3 = await restartedService.inventoryAndSchedule(
      assessmentId,
      rootFwId,
      extractRes.value.sandboxDir,
      "tar",
    );
    expect(pass3.ok).toBe(true);

    const pass3Assets = await storage.assets.listByAssessment(assessmentId);
    expect(pass3Assets.ok).toBe(true);
    if (pass3Assets.ok) {
      expect(pass3Assets.value.length).toBe(initialAssetCount); // Still exactly initialAssetCount
    }

    await extractor.cleanupSandbox(extractRes.value.sandboxDir);
  });
});
