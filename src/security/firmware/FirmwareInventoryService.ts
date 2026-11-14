import { createHash, randomUUID } from "node:crypto";
import { open, readdir, readlink, realpath, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative } from "node:path";
import { err, ok, type Result } from "../../domain/result.js";
import type { AssessmentId } from "../../domain/security/assessment.js";
import {
  computeAssetId,
  type AssetId,
  type AssetType,
} from "../../domain/security/asset.js";
import type { BlackboardError } from "../../domain/security/blackboard/errors.js";
import type {
  BlackboardAssetRecord,
  IAssetRepository,
  IObservationRepository,
  ITaskRepository,
  ObservationRecord,
  TaskRecord,
} from "../../domain/security/blackboard/types.js";
import type {
  ExtractionResult,
  FirmwareFormat,
} from "../../domain/security/firmware/types.js";

export interface BlackboardContext {
  readonly assets: IAssetRepository;
  readonly observations: IObservationRepository;
  readonly tasks: ITaskRepository;
}

export interface ElfMetadata {
  readonly isElf: boolean;
  readonly is64Bit?: boolean;
  readonly endianness?: "little" | "big";
  readonly architecture?: string;
  readonly isExecutable: boolean;
}

export class FirmwareInventoryService {
  constructor(private readonly blackboard: BlackboardContext) {}

  /**
   * Statically inspect an executable / script header without execution.
   */
  public static async inspectBinaryHeader(filePath: string): Promise<ElfMetadata> {
    let handle;
    try {
      handle = await open(filePath, "r");
      const buffer = Buffer.alloc(64);
      const { bytesRead } = await handle.read(buffer, 0, 64, 0);
      await handle.close();

      if (bytesRead < 4) {
        return { isElf: false, isExecutable: false };
      }

      // Check SquashFS magic: sqsh (0x73 0x71 0x73 0x68) or hsqs (0x68 0x73 0x71 0x73)
      const magic4 = buffer.subarray(0, 4).toString("utf8");
      if (magic4 === "sqsh" || magic4 === "hsqs") {
        return { isElf: false, isExecutable: false };
      }

      // 1. ELF Magic: 0x7F 0x45 0x4C 0x46 (\x7fELF)
      if (
        buffer[0] === 0x7f &&
        buffer[1] === 0x45 &&
        buffer[2] === 0x4c &&
        buffer[3] === 0x46
      ) {
        const is64Bit = buffer[4] === 2;
        const isLE = buffer[5] === 1;
        const endianness = isLE ? "little" : "big";

        let architecture = "unknown";
        if (bytesRead >= 20) {
          const machine = isLE ? buffer.readUInt16LE(18) : buffer.readUInt16BE(18);
          switch (machine) {
            case 0x03:
              architecture = "x86";
              break;
            case 0x3e:
              architecture = "x86_64";
              break;
            case 0x28:
              architecture = "ARM";
              break;
            case 0xb7:
              architecture = "AArch64";
              break;
            case 0x08:
              architecture = "MIPS";
              break;
            case 0xf3:
              architecture = "RISC-V";
              break;
            case 0x14:
              architecture = "PowerPC";
              break;
            default:
              architecture = `machine_0x${machine.toString(16)}`;
          }
        }

        return {
          isElf: true,
          is64Bit,
          endianness,
          architecture,
          isExecutable: true,
        };
      }

      // 2. Shebang / script check (#! = 0x23 0x21)
      if (buffer[0] === 0x23 && buffer[1] === 0x21) {
        return {
          isElf: false,
          isExecutable: true,
        };
      }

      return { isElf: false, isExecutable: false };
    } catch {
      if (handle) {
        try {
          await handle.close();
        } catch {
          // Ignore close failure
        }
      }
      return { isElf: false, isExecutable: false };
    }
  }

  /**
   * Walk the extracted sandbox hierarchy, create hierarchical blackboard assets,
   * record observations, and generate binary-analysis tasks for executables.
   */
  public async inventoryAndSchedule(
    assessmentId: AssessmentId,
    rootFirmwareAssetId: AssetId,
    sandboxDir: string,
    format: FirmwareFormat,
  ): Promise<Result<ExtractionResult, BlackboardError>> {
    const assetsCreated: BlackboardAssetRecord[] = [];
    const tasksCreated: TaskRecord[] = [];
    const observationsCreated: ObservationRecord[] = [];
    let totalBytesExtracted = 0;
    let extractedFilesCount = 0;

    // 0. Resolve root firmware asset to preserve root firmware SHA-256 and lineage
    let rootFirmwareSha256: string = "0".repeat(64);
    const rootAssetRes = await this.blackboard.assets.findById(assessmentId, rootFirmwareAssetId);
    if (rootAssetRes.ok && rootAssetRes.value) {
      rootFirmwareSha256 = rootAssetRes.value.digest?.sha256 ?? rootFirmwareSha256;
    }

    // 1. Create partition / filesystem asset
    const fsName = `${format.toUpperCase()} Filesystem`;
    const fsAssetId = computeAssetId({
      name: fsName,
      type: "operating_system",
    });

    const now = Date.now();
    const fsAsset: BlackboardAssetRecord = {
      id: fsAssetId,
      assessment_id: assessmentId,
      parent_asset_id: rootFirmwareAssetId,
      name: fsName,
      type: "operating_system",
      path: null,
      digest: null,
      architecture: null,
      version: null,
      environment: { platform: "firmware_linux" },
      tags: ["partition", "filesystem", format],
      metadata: { format, sandbox_root: sandboxDir, firmwareSha256: rootFirmwareSha256, rootFirmwareAssetId },
      created_at: now,
    };

    let fsRecord: BlackboardAssetRecord;
    const existingFs = await this.blackboard.assets.findById(assessmentId, fsAssetId);
    if (existingFs.ok && existingFs.value) {
      fsRecord = existingFs.value;
    } else {
      const fsSaveRes = await this.blackboard.assets.create(fsAsset);
      if (!fsSaveRes.ok) return fsSaveRes;
      fsRecord = fsSaveRes.value;
    }
    assetsCreated.push(fsRecord);

    // Map relative directory paths to their parent asset ID
    const dirAssetMap = new Map<string, AssetId>();
    dirAssetMap.set("", fsAssetId);
    dirAssetMap.set(".", fsAssetId);

    // 2. Recursive filesystem traversal
    const walk = async (currentDir: string): Promise<Result<void, BlackboardError>> => {
      let entries;
      try {
        entries = await readdir(currentDir, { withFileTypes: true });
      } catch (e: unknown) {
        return ok(undefined); // Skip unreadable directory
      }

      for (const entry of entries) {
        const fullPath = join(currentDir, entry.name);
        const relPath = relative(sandboxDir, fullPath).replace(/\\/g, "/");
        const relDir = dirname(relPath).replace(/\\/g, "/");
        const parentId = dirAssetMap.get(relDir === "." ? "" : relDir) ?? fsAssetId;

        if (entry.isSymbolicLink()) {
          // Detect symlink: inspect target and ensure it does not escape sandbox
          let linkTarget: string | null = null;
          let escapes = false;
          try {
            linkTarget = await readlink(fullPath);
            const resolvedPath = await realpath(fullPath);
            const relToSandbox = relative(sandboxDir, resolvedPath);
            if (relToSandbox.startsWith("..") || isAbsolute(relToSandbox)) {
              escapes = true;
            }
          } catch {
            escapes = true;
          }

          // Record symlink observation; do not follow outside or publish as regular binary asset
          const obsRes = await this.blackboard.observations.record({
            assessment_id: assessmentId,
            asset_id: parentId,
            key: "firmware.symlink_entry",
            value: {
              path: relPath,
              target: linkTarget,
              escapes_sandbox: escapes,
              published: false,
            },
            confidence: 1.0,
            source_tool: "firmware_inventory",
            agent_id: "firmware_inventory_service",
            evidence_id: null,
            created_at: Date.now(),
          });
          if (obsRes.ok) observationsCreated.push(obsRes.value);
          continue;
        }

        if (
          entry.isCharacterDevice?.() ||
          entry.isBlockDevice?.() ||
          entry.isFIFO?.() ||
          entry.isSocket?.()
        ) {
          const deviceType = entry.isCharacterDevice?.()
            ? "character_device"
            : entry.isBlockDevice?.()
              ? "block_device"
              : entry.isFIFO?.()
                ? "fifo"
                : "socket";
          const obsRes = await this.blackboard.observations.record({
            assessment_id: assessmentId,
            asset_id: parentId,
            key: "firmware.special_entry",
            value: {
              path: relPath,
              type: deviceType,
              published: false,
            },
            confidence: 1.0,
            source_tool: "firmware_inventory",
            agent_id: "firmware_inventory_service",
            evidence_id: null,
            created_at: Date.now(),
          });
          if (obsRes.ok) observationsCreated.push(obsRes.value);
          continue;
        }

        if (entry.isDirectory()) {
          const dirAssetId = computeAssetId({
            name: entry.name,
            type: "source_repository",
          });

          const dirAsset: BlackboardAssetRecord = {
            id: dirAssetId,
            assessment_id: assessmentId,
            parent_asset_id: parentId,
            name: entry.name,
            type: "source_repository",
            path: relPath,
            digest: null,
            architecture: null,
            version: null,
            environment: null,
            tags: ["directory"],
            metadata: { relativePath: relPath },
            created_at: Date.now(),
          };

          let dirRecord: BlackboardAssetRecord;
          const existingDir = await this.blackboard.assets.findById(assessmentId, dirAssetId);
          if (existingDir.ok && existingDir.value) {
            dirRecord = existingDir.value;
          } else {
            const dRes = await this.blackboard.assets.create(dirAsset);
            if (!dRes.ok) return dRes;
            dirRecord = dRes.value;
          }
          assetsCreated.push(dirRecord);
          dirAssetMap.set(relPath, dirAssetId);

          const subWalk = await walk(fullPath);
          if (!subWalk.ok) return subWalk;
        } else if (entry.isFile()) {
          extractedFilesCount++;
          let fileSize = 0;
          try {
            const st = await stat(fullPath);
            fileSize = st.size;
          } catch {
            fileSize = 0;
          }
          totalBytesExtracted += fileSize;

          // Compute SHA-256
          const sha256 = await this.computeSha256(fullPath);

          // Statically inspect header (NO EXECUTION)
          const headerInfo = await FirmwareInventoryService.inspectBinaryHeader(fullPath);

          let assetType: AssetType = "source_repository";
          if (headerInfo.isElf) {
            assetType = "compiled_binary";
          } else if (
            relPath.startsWith("etc/") ||
            /\.(conf|cfg|ini|json|xml|yaml|yml)$/i.test(entry.name)
          ) {
            assetType = "cloud_configuration";
          } else if (
            entry.name.endsWith(".squashfs") ||
            entry.name.endsWith(".img") ||
            entry.name.endsWith(".bin")
          ) {
            assetType = "firmware_image";
          }

          const fileAssetId = computeAssetId({
            name: entry.name,
            type: assetType,
            digest: { sha256 },
            architecture: headerInfo.architecture ?? null,
          });

          const fileAsset: BlackboardAssetRecord = {
            id: fileAssetId,
            assessment_id: assessmentId,
            parent_asset_id: parentId,
            name: entry.name,
            type: assetType,
            path: relPath,
            digest: { sha256 },
            architecture: headerInfo.architecture ?? null,
            version: null,
            environment: null,
            tags: [
              "extracted",
              "published",
              "classified",
              ...(headerInfo.isExecutable ? ["queued_for_analysis", "executable"] : ["skipped"]),
              ...(headerInfo.isElf ? ["elf"] : []),
            ],
            metadata: {
              relativePath: relPath,
              fullPath,
              size: fileSize,
              endianness: headerInfo.endianness,
              is64Bit: headerInfo.is64Bit,
              firmwareSha256: rootFirmwareSha256,
              rootFirmwareAssetId,
              lifecycle_state: headerInfo.isExecutable ? "queued_for_analysis" : "classified",
              discovered: true,
              extracted: true,
              published: true,
              classified: true,
              queued_for_analysis: headerInfo.isExecutable,
              analyzed: false,
              failed: false,
              skipped: !headerInfo.isExecutable,
            },
            created_at: Date.now(),
          };

          let fileRecord: BlackboardAssetRecord;
          const existingFile = await this.blackboard.assets.findById(assessmentId, fileAssetId);
          if (existingFile.ok && existingFile.value) {
            fileRecord = existingFile.value;
          } else {
            const fRes = await this.blackboard.assets.create(fileAsset);
            if (!fRes.ok) return fRes;
            fileRecord = fRes.value;
          }
          assetsCreated.push(fileRecord);

          // Record observation (idempotent lookup)
          const existingObs = await this.blackboard.observations.listByAsset(
            assessmentId,
            fileAssetId,
            "firmware.extracted_file",
          );
          if (existingObs.ok && existingObs.value.length === 0) {
            const obsRes = await this.blackboard.observations.record({
              assessment_id: assessmentId,
              asset_id: fileAssetId,
              key: "firmware.extracted_file",
              value: {
                path: relPath,
                size: fileSize,
                sha256,
                isExecutable: headerInfo.isExecutable,
                architecture: headerInfo.architecture,
              },
              confidence: 1.0,
              source_tool: "firmware_extractor",
              agent_id: "firmware_extractor_agent",
              evidence_id: null,
              created_at: Date.now(),
            });
            if (obsRes.ok) {
              observationsCreated.push(obsRes.value);
            }
          } else if (existingObs.ok && existingObs.value.length > 0) {
            observationsCreated.push(existingObs.value[0]!);
          }

          // Generate binary-analysis task for executables (idempotent)
          if (headerInfo.isExecutable) {
            const taskId = `task_fw_${fileAssetId.replace(/^ast_/u, "").slice(0, 32)}`;
            const existingTask = await this.blackboard.tasks.getById(assessmentId, taskId);
            if (existingTask.ok && existingTask.value) {
              tasksCreated.push(existingTask.value);
            } else {
              const taskRecord: TaskRecord = {
                id: taskId,
                assessment_id: assessmentId,
                task_type: "binary_analysis",
                title: `Audit binary: ${relPath}`,
                description: `Perform static disassembly and vulnerability analysis for ${relPath} (arch: ${headerInfo.architecture ?? "unknown"})`,
                asset_id: fileAssetId,
                priority: "high",
                status: "open",
                blocked_by: [],
                fencing_token: 0,
                cas_version: 0,
                claim: null,
                result: null,
                metadata: {
                  required_capabilities: ["binary_decompilation"],
                  architecture: headerInfo.architecture,
                  endianness: headerInfo.endianness,
                  relativePath: relPath,
                  fullPath,
                  is_executable: true,
                  firmwareSha256: rootFirmwareSha256,
                  rootFirmwareAssetId,
                  task_state: "queued_for_analysis",
                },
                created_at: Date.now(),
                updated_at: Date.now(),
              };

              const tRes = await this.blackboard.tasks.create(taskRecord);
              if (tRes.ok) {
                tasksCreated.push(tRes.value);
              }
            }
          }
        }
      }

      return ok(undefined);
    };

    const walkRes = await walk(sandboxDir);
    if (!walkRes.ok) return walkRes;

    // Record high-level extraction observation (idempotent)
    const existingSummary = await this.blackboard.observations.listByAsset(
      assessmentId,
      rootFirmwareAssetId,
      "firmware.extraction_summary",
    );
    if (existingSummary.ok && existingSummary.value.length === 0) {
      const summaryObs = await this.blackboard.observations.record({
        assessment_id: assessmentId,
        asset_id: rootFirmwareAssetId,
        key: "firmware.extraction_summary",
        value: {
          format,
          filesExtracted: extractedFilesCount,
          totalBytesExtracted,
          assetsCreatedCount: assetsCreated.length,
          tasksCreatedCount: tasksCreated.length,
        },
        confidence: 1.0,
        source_tool: "firmware_extractor",
        agent_id: "firmware_extractor_agent",
        evidence_id: null,
        created_at: Date.now(),
      });
      if (summaryObs.ok) {
        observationsCreated.push(summaryObs.value);
      }
    } else if (existingSummary.ok && existingSummary.value.length > 0) {
      observationsCreated.push(existingSummary.value[0]!);
    }

    return ok({
      assessmentId,
      rootAssetId: rootFirmwareAssetId,
      format,
      sandboxDir,
      extractedFilesCount,
      totalBytesExtracted,
      assetsCreated,
      tasksCreated,
      observationsCreated,
      securityViolations: [],
    });
  }

  private async computeSha256(filePath: string): Promise<string> {
    try {
      const handle = await open(filePath, "r");
      const hash = createHash("sha256");
      const buffer = Buffer.alloc(64 * 1024);
      let bytesRead = 0;
      let pos = 0;

      while ((bytesRead = (await handle.read(buffer, 0, buffer.length, pos)).bytesRead) > 0) {
        hash.update(buffer.subarray(0, bytesRead));
        pos += bytesRead;
      }
      await handle.close();
      return hash.digest("hex");
    } catch {
      return "0".repeat(64);
    }
  }

  /**
   * Preserve unknown, encrypted, depth-limited, unsupported, and failed extraction regions as explicit coverage gaps.
   */
  public async recordExtractionGap(
    assessmentId: AssessmentId,
    rootFirmwareAssetId: AssetId,
    gap: {
      readonly path: string;
      readonly reason: string;
      readonly kind: "unknown-chunk" | "encrypted" | "depth-limited" | "unsupported" | "failed";
      readonly offset?: number;
    },
  ): Promise<Result<ObservationRecord, BlackboardError>> {
    return this.blackboard.observations.record({
      assessment_id: assessmentId,
      asset_id: rootFirmwareAssetId,
      key: "firmware.extraction_gap",
      value: {
        path: gap.path,
        reason: gap.reason,
        kind: gap.kind,
        offset: gap.offset ?? null,
      },
      confidence: 1.0,
      source_tool: "firmware_inventory",
      agent_id: "firmware_inventory_service",
      evidence_id: null,
      created_at: Date.now(),
    });
  }
}

