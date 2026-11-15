/* eslint-disable max-lines-per-function */
import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { access, constants, open, readFile, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { err, ok, type Result } from "../../../domain/result.js";
import {
  calculateAssessmentMetrics,
  createAssessmentState,
  type AssessmentDepth,
  type AssessmentId,
  type AssessmentState,
  type AuthorizationScope,
} from "../../../domain/security/assessment.js";
import {
  computeAssetId,
  type AssetId,
  type AssetRecord,
  type AssetType,
} from "../../../domain/security/asset.js";
import { validateTargetAuthorization } from "../../../domain/security/authorization.js";
import type { SecurityFinding } from "../../../domain/security/finding.js";
import type {
  BlackboardAssetRecord,
  FindingRecord,
  TaskRecord,
} from "../../../domain/security/blackboard/types.js";
import { detectFirmwareFormat } from "../../../domain/security/firmware/detector.js";
import { SqliteBlackboardStorage } from "../../../security/blackboard/SqliteBlackboardStorage.js";
import { KeyringManager } from "../../../security/packboard/secureKeyring.js";
import { SandboxedExtractor } from "../../../security/firmware/SandboxedExtractor.js";
import { SquashFsParser } from "../../../security/firmware/SquashFsParser.js";
import {
  FirmwareInventoryService,
  type ExtractedFileClassification,
} from "../../../security/firmware/FirmwareInventoryService.js";
import {
  defaultFirmwareDeepAnalyzer,
  type FirmwareDeepAnalyzer,
  type FirmwarePartitionInfo,
} from "../../../security/firmware/firmwareDeepAnalyzer.js";
import {
  defaultEmbeddedOsAnalyzer,
  type EmbeddedOsAnalyzer,
} from "../../../security/os/embeddedOsAnalyzer.js";
import {
  VulnerabilityEngine,
  type ScanExecutionStatus,
} from "../../../security/engines/vulnerability/engine.js";
import {
  TrustedEvidenceAuthority,
  TrustedEvidenceVerifier,
} from "../../../security/binary/evidence/TrustedAnalysisEvidence.js";
import {
  ParentEvidenceValidator,
  type ParentValidationContext,
} from "../../../security/binary/evidence/ParentEvidenceValidator.js";
import { BinaryWorkerSupervisor } from "../../../security/binary/supervisor/BinaryWorkerSupervisor.js";
import { BinaryAnalysisBridge } from "../../../security/binary/BinaryAnalysisBridge.js";
import { VulnerabilityCandidateDetector } from "../../../security/binary/VulnerabilityCandidateDetector.js";
import { VulnerabilityAdjudicationBridge } from "../../../security/binary/VulnerabilityAdjudicationBridge.js";
import type { BinaryWorkerAnalyzeRequest } from "../../../security/binary/ipc/binaryWorkerProtocol.js";
import { ChiefSecurityOrchestrator as DomainAgentOrchestrator } from "../../../security/agents/orchestrator.js";
import {
  defaultReportGenerator,
  type ReportFormat,
  type ScanExecutionMetadata,
  type SecurityReportGenerator,
} from "../../../security/reporting/reportGenerator.js";
import { SarifExporter } from "../reporting/SarifExporter.js";

export interface SecurityAssessmentServiceDependencies {
  readonly storage?: SqliteBlackboardStorage | undefined;
  readonly dbPath?: string | undefined;
  readonly journalPath?: string | undefined;
  readonly keyringManager?: KeyringManager | undefined;
  readonly extractor?: SandboxedExtractor | undefined;
  readonly firmwareDeepAnalyzer?: FirmwareDeepAnalyzer | undefined;
  readonly embeddedOsAnalyzer?: EmbeddedOsAnalyzer | undefined;
  readonly vulnerabilityEngine?: VulnerabilityEngine | undefined;
  readonly binaryBridge?: BinaryAnalysisBridge | undefined;
  readonly candidateDetector?: VulnerabilityCandidateDetector | undefined;
  readonly parentValidator?: ParentEvidenceValidator | undefined;
  readonly reportGenerator?: SecurityReportGenerator | undefined;
  readonly supervisorFactory?: (options: {
    readonly workerId: string;
    readonly allowedRoot: string;
    readonly defaultTaskTimeoutMs: number;
    readonly maxOldSpaceSizeMb: number;
  }) => BinaryWorkerSupervisor;
}

export interface SecurityAssessmentRequest {
  readonly assessmentId?: AssessmentId | undefined;
  readonly targetPath: string;
  readonly title?: string | undefined;
  readonly authorizedBy: string;
  readonly authorizationReference: string;
  readonly validUntil?: string | undefined;
  readonly allowActiveVerification?: boolean | undefined;
  readonly allowedTargets?: readonly string[] | undefined;
  readonly deniedTargets?: readonly string[] | undefined;
  readonly depth?: AssessmentDepth | undefined;
  readonly format?: ReportFormat | undefined;
  readonly maxBinariesToAnalyze?: number | undefined;
  readonly taskTimeoutMs?: number | undefined;
  readonly maxWorkerHeapMb?: number | undefined;
  readonly yaraRuleFiles?: readonly string[] | undefined;
  readonly semgrepRules?: readonly string[] | undefined;
  readonly runExternalScanners?: boolean | undefined;
  readonly keepExtractedSandbox?: boolean | undefined;
  readonly signal?: AbortSignal | undefined;
}

export interface FirmwareExtractionSummaryRecord {
  readonly rootAssetId: AssetId;
  readonly rootFirmwareSha256: string;
  readonly format: string;
  readonly sandboxDir: string | null;
  readonly totalDiscoveredEntries: number;
  readonly regularFilesExtracted: number;
  readonly directoriesCount: number;
  readonly symlinksCount: number;
  readonly specialFilesNeutralized: number;
  readonly totalBytesExtracted: number;
  readonly classificationCounts: Readonly<
    Record<ExtractedFileClassification, number>
  >;
  readonly extractionGaps: ReadonlyArray<{
    readonly path: string;
    readonly reason: string;
    readonly kind: string;
  }>;
  readonly extractionWarnings: readonly string[];
}

export interface BinaryExecutionMetricRecord {
  readonly assetId: AssetId;
  readonly name: string;
  readonly relativePath: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly architecture: string;
  readonly endianness: string;
  readonly elfClass: string;
  readonly selectionPriorityReason: string;
  readonly status: "COMPLETED" | "PARTIAL" | "FAILED" | "SKIPPED";
  readonly decoderProvider: string;
  readonly instructionsDecoded: number;
  readonly decodedBytes: number;
  readonly totalCodeBytes: number;
  readonly unsupportedBytes: number;
  readonly decoderOutcome: string;
  readonly decoderComplete: boolean;
  readonly cfgBlocksCount: number;
  readonly cfgEdgesCount: number;
  readonly cfgComplete: boolean;
  readonly functionsRecoveredCount: number;
  readonly callRelationshipsCount: number;
  readonly unresolvedSensitiveImports: readonly string[];
  readonly reachabilityStatus: string;
  readonly taintStageStatus: string;
  readonly witnessStageStatus: string;
  readonly witnessSatisfiabilityStatus: string;
  readonly candidatesDetected: number;
  readonly findingsPersisted: number;
  readonly evidenceIds: readonly string[];
  readonly durationMs: number;
  readonly error?: string | undefined;
}

export interface StageTimingsRecord {
  readonly validationAndHashingMs: number;
  readonly extractionMs: number;
  readonly inventoryMs: number;
  readonly binaryAnalysisMs: number;
  readonly externalScannersMs: number;
  readonly persistenceAndReportingMs: number;
  readonly totalDurationMs: number;
}

export interface SecurityAssessmentExecutionOutput {
  readonly assessmentId: AssessmentId;
  readonly status: ScanExecutionStatus;
  readonly assessment: AssessmentState;
  readonly scanExecution: ScanExecutionMetadata;
  readonly extractionSummary?: FirmwareExtractionSummaryRecord | undefined;
  readonly binaryMetrics: readonly BinaryExecutionMetricRecord[];
  readonly stageTimingsMs: StageTimingsRecord;
  readonly report: string;
}

export interface FirmwareInspectionExecutionOutput {
  readonly assessmentId: AssessmentId;
  readonly status: ScanExecutionStatus;
  readonly target_path: string;
  readonly sha256: string;
  readonly architecture: string;
  readonly endianness: string;
  readonly detected_partitions: readonly FirmwarePartitionInfo[];
  readonly extraction_summary: FirmwareExtractionSummaryRecord;
  readonly binary_metrics: readonly BinaryExecutionMetricRecord[];
  readonly scan_execution: ScanExecutionMetadata;
  readonly findings: readonly SecurityFinding[];
  readonly risk_score: number;
  readonly summary: string;
  readonly stage_timings_ms: StageTimingsRecord;
}

export interface PersistedAssessmentReportOutput {
  readonly assessmentId: AssessmentId;
  readonly status: ScanExecutionStatus;
  readonly assessment: AssessmentState;
  readonly scanExecution: ScanExecutionMetadata;
  readonly extractionSummary?: FirmwareExtractionSummaryRecord | undefined;
  readonly binaryMetrics: readonly BinaryExecutionMetricRecord[];
  readonly format: ReportFormat;
  readonly report: string;
}

export interface SecurityAssessmentServiceError {
  readonly code:
    | "AUTHORIZATION_DENIED"
    | "INVALID_TARGET"
    | "ASSESSMENT_NOT_FOUND"
    | "STORAGE_ERROR"
    | "EXECUTION_ABORTED"
    | "INTERNAL_ERROR";
  readonly message: string;
  readonly details?: unknown;
}

const PRIORITY_DAEMON_NAMES = new Set([
  "dropbear",
  "uhttpd",
  "dnsmasq",
  "wpa_supplicant",
  "hostapd",
  "pppd",
  "telnetd",
  "sshd",
  "httpd",
  "ntpd",
  "odhcpd",
  "openvpn",
]);

const PRIORITY_CORE_NAMES = new Set([
  "busybox",
  "ubus",
  "ubusd",
  "rpcd",
  "netifd",
  "procd",
  "uci",
  "ustream-ssl",
  "fw3",
  "nft",
  "iptables",
]);

export class SecurityAssessmentService {
  private readonly injectedStorage?: SqliteBlackboardStorage | undefined;
  private readonly dbPath?: string | undefined;
  private readonly journalPath?: string | undefined;
  private readonly keyringManager?: KeyringManager | undefined;
  private readonly extractor: SandboxedExtractor;
  private readonly firmwareDeepAnalyzer: FirmwareDeepAnalyzer;
  private readonly embeddedOsAnalyzer: EmbeddedOsAnalyzer;
  private readonly vulnerabilityEngine: VulnerabilityEngine;
  private readonly binaryBridge: BinaryAnalysisBridge;
  private readonly candidateDetector: VulnerabilityCandidateDetector;
  private readonly parentValidator: ParentEvidenceValidator;
  private readonly reportGenerator: SecurityReportGenerator;
  private readonly supervisorFactory: NonNullable<
    SecurityAssessmentServiceDependencies["supervisorFactory"]
  >;

  constructor(deps?: SecurityAssessmentServiceDependencies) {
    this.injectedStorage = deps?.storage;
    this.dbPath = deps?.dbPath;
    this.journalPath = deps?.journalPath;
    this.keyringManager = deps?.keyringManager;
    this.extractor = deps?.extractor ?? new SandboxedExtractor();
    this.firmwareDeepAnalyzer =
      deps?.firmwareDeepAnalyzer ?? defaultFirmwareDeepAnalyzer;
    this.embeddedOsAnalyzer =
      deps?.embeddedOsAnalyzer ?? defaultEmbeddedOsAnalyzer;
    this.vulnerabilityEngine =
      deps?.vulnerabilityEngine ?? new VulnerabilityEngine();
    this.binaryBridge = deps?.binaryBridge ?? new BinaryAnalysisBridge();
    this.candidateDetector =
      deps?.candidateDetector ?? new VulnerabilityCandidateDetector();
    this.parentValidator =
      deps?.parentValidator ?? new ParentEvidenceValidator();
    this.reportGenerator = deps?.reportGenerator ?? defaultReportGenerator;
    this.supervisorFactory =
      deps?.supervisorFactory ??
      ((opts) =>
        new BinaryWorkerSupervisor({
          workerId: opts.workerId,
          allowedRoot: opts.allowedRoot,
          defaultTaskTimeoutMs: opts.defaultTaskTimeoutMs,
          maxOldSpaceSizeMb: opts.maxOldSpaceSizeMb,
        }));
  }

  public async runAssessment(
    request: SecurityAssessmentRequest,
  ): Promise<
    Result<SecurityAssessmentExecutionOutput, SecurityAssessmentServiceError>
  > {
    const totalStart = Date.now();
    let validationAndHashingMs = 0;
    let extractionMs = 0;
    let inventoryMs = 0;
    let binaryAnalysisMs = 0;
    let externalScannersMs = 0;

    if (request.signal?.aborted) {
      return err({
        code: "EXECUTION_ABORTED",
        message: "Security assessment cancelled before startup",
      });
    }

    const stage1Start = Date.now();
    const depth: AssessmentDepth = request.depth ?? "standard";
    const format: ReportFormat = request.format ?? "markdown";
    const validUntil =
      request.validUntil ?? new Date(Date.now() + 86_400_000).toISOString();

    if (
      !request.targetPath ||
      request.targetPath.trim().length === 0 ||
      request.targetPath.includes("\0")
    ) {
      return err({
        code: "INVALID_TARGET",
        message: "Target path must be a non-empty valid filesystem path.",
      });
    }

    const scope: AuthorizationScope = {
      allowed_targets:
        request.allowedTargets && request.allowedTargets.length > 0
          ? [...request.allowedTargets]
          : [request.targetPath],
      denied_targets: [...(request.deniedTargets ?? [])],
      authorized_by: request.authorizedBy,
      authorization_reference: request.authorizationReference,
      valid_until: validUntil,
      allow_active_verification: request.allowActiveVerification ?? false,
    };

    const authCheck = validateTargetAuthorization(request.targetPath, scope);
    if (!authCheck.ok) {
      return err({
        code: "AUTHORIZATION_DENIED",
        message: authCheck.error.message,
        details: authCheck.error,
      });
    }

    const resolvedTargetPath = resolve(request.targetPath);
    const resolvedAuthCheck = validateTargetAuthorization(
      resolvedTargetPath,
      scope,
    );
    if (!resolvedAuthCheck.ok) {
      return err({
        code: "AUTHORIZATION_DENIED",
        message: resolvedAuthCheck.error.message,
        details: resolvedAuthCheck.error,
      });
    }

    let targetStats;
    try {
      targetStats = await stat(resolvedTargetPath);
    } catch (cause) {
      const code = (cause as NodeJS.ErrnoException)?.code;
      if (code === "EACCES" || code === "EPERM") {
        return err({
          code: "AUTHORIZATION_DENIED",
          message: `Insufficient permissions to stat target '${resolvedTargetPath}': ${cause instanceof Error ? cause.message : String(cause)}`,
          details: cause,
        });
      }
      return err({
        code: "INVALID_TARGET",
        message: `Target path '${resolvedTargetPath}' does not exist or is unreadable: ${cause instanceof Error ? cause.message : String(cause)}`,
        details: cause,
      });
    }

    try {
      await access(resolvedTargetPath, constants.R_OK);
    } catch (cause) {
      return err({
        code: "AUTHORIZATION_DENIED",
        message: `Insufficient permissions to read target '${resolvedTargetPath}': ${cause instanceof Error ? cause.message : String(cause)}`,
        details: cause,
      });
    }

    let rootAssetType: AssetType = "source_repository";
    let rootSha256: string | null = null;
    let rootArchitecture: string | null = null;
    let rootFormat = "directory";

    if (targetStats.isFile()) {
      rootSha256 = await this.computeFileSha256(resolvedTargetPath);
      const headerInfo =
        await FirmwareInventoryService.inspectBinaryHeader(resolvedTargetPath);
      const headerBytes = await this.readFirstBytes(resolvedTargetPath, 8192);
      const fwDetection = detectFirmwareFormat(headerBytes);

      const lower = resolvedTargetPath.toLowerCase();
      if (headerInfo.isElf) {
        rootAssetType = "compiled_binary";
        rootArchitecture = headerInfo.architecture ?? null;
        rootFormat = "elf";
      } else if (
        fwDetection.format !== "unknown" ||
        headerInfo.isKernelOrBootloader ||
        lower.endsWith(".bin") ||
        lower.endsWith(".img") ||
        lower.endsWith(".rom") ||
        lower.endsWith(".fw") ||
        lower.endsWith(".squashfs") ||
        lower.endsWith(".trx") ||
        lower.endsWith(".tar") ||
        lower.endsWith(".gz") ||
        lower.endsWith(".xz")
      ) {
        rootAssetType = "firmware_image";
        rootFormat =
          fwDetection.format !== "unknown"
            ? fwDetection.format
            : "firmware_binary";
      } else {
        rootAssetType = "source_repository";
        rootFormat = "file";
      }
    }

    const rootAssetName = basename(resolvedTargetPath);
    const initialAssessment = createAssessmentState({
      objective: {
        title: request.title ?? `Security Assessment of ${rootAssetName}`,
        target_technologies: [
          rootAssetType,
          ...(rootArchitecture ? [rootArchitecture] : []),
        ],
        compliance_frameworks: ["OWASP IoT Top 10", "CWE Top 25"],
        focus_areas: [
          "Firmware Extraction",
          "ELF Binary Analysis",
          "Trusted Evidence Adjudication",
        ],
        depth,
      },
      scope: {
        ...scope,
        allowed_targets: [resolvedTargetPath],
      },
    });

    const assessmentId =
      request.assessmentId ?? initialAssessment.assessment_id;
    const rootAssetId = computeAssetId({
      name: rootAssetName,
      type: rootAssetType,
      digest: rootSha256 ? { sha256: rootSha256 } : null,
      architecture: rootArchitecture,
    });

    validationAndHashingMs = Date.now() - stage1Start;

    let acquired: { storage: SqliteBlackboardStorage; ownsStorage: boolean };
    try {
      acquired = this.acquireStorage(assessmentId);
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        message: `Failed to initialize SQLite blackboard storage: ${cause instanceof Error ? cause.message : String(cause)}`,
        details: cause,
      });
    }
    const { storage, ownsStorage } = acquired;
    let activeSandboxDir: string | null = null;
    let activeSupervisor: BinaryWorkerSupervisor | null = null;

    try {
      const keyring = this.keyringManager ?? storage.getKeyringManager();
      const authority = new TrustedEvidenceAuthority({
        keyringManager: keyring,
        db: storage.getDatabase(),
      });
      const verifier = new TrustedEvidenceVerifier({
        keyringManager: keyring,
        db: storage.getDatabase(),
      });
      const adjudicationBridge = new VulnerabilityAdjudicationBridge({
        verifier,
      });
      const inventoryService = new FirmwareInventoryService(storage);

      const existingAssessment =
        await storage.assessments.findById(assessmentId);
      if (!existingAssessment.ok) {
        return err({
          code: "STORAGE_ERROR",
          message: existingAssessment.error.message,
          details: existingAssessment.error,
        });
      }

      const nowMs = Date.now();
      if (!existingAssessment.value) {
        const createAssRes = await storage.assessments.create({
          id: assessmentId,
          name: initialAssessment.objective.title,
          status: "active",
          objective: initialAssessment.objective,
          authorization: initialAssessment.scope,
          metrics: initialAssessment.metrics,
          created_at: nowMs,
          updated_at: nowMs,
        });
        if (!createAssRes.ok) {
          return err({
            code: "STORAGE_ERROR",
            message: createAssRes.error.message,
            details: createAssRes.error,
          });
        }
      }

      const rootBlackboardAsset: BlackboardAssetRecord = {
        id: rootAssetId,
        assessment_id: assessmentId,
        parent_asset_id: null,
        name: rootAssetName,
        type: rootAssetType,
        path: resolvedTargetPath,
        digest: rootSha256 ? { sha256: rootSha256 } : null,
        architecture: rootArchitecture,
        version: null,
        environment: { platform: "embedded_linux" },
        tags: ["root_target", rootAssetType, rootFormat],
        metadata: {
          fullPath: resolvedTargetPath,
          size: targetStats.size,
          format: rootFormat,
          isDirectory: targetStats.isDirectory(),
          firmwareSha256: rootSha256 ?? "0".repeat(64),
          rootFirmwareAssetId: rootAssetId,
        },
        created_at: nowMs,
      };

      const existingRootAsset = await storage.assets.findById(
        assessmentId,
        rootAssetId,
      );
      if (!existingRootAsset.ok || !existingRootAsset.value) {
        const createAssetRes = await storage.assets.create(rootBlackboardAsset);
        if (!createAssetRes.ok) {
          return err({
            code: "STORAGE_ERROR",
            message: createAssetRes.error.message,
            details: createAssetRes.error,
          });
        }
      }

      const extractionGaps: Array<{
        path: string;
        reason: string;
        kind: string;
      }> = [];
      const extractionWarnings: string[] = [];
      const unsupportedInputTypes: string[] = [];
      const candidateFindingsToPersist: SecurityFinding[] = [];
      let extractionSummary: FirmwareExtractionSummaryRecord | undefined;

      if (rootAssetType === "firmware_image") {
        const extStart = Date.now();

        const deepRes = await this.firmwareDeepAnalyzer.analyze(
          resolvedTargetPath,
          this.toDomainAsset(rootBlackboardAsset),
        );
        if (deepRes.ok) {
          candidateFindingsToPersist.push(...deepRes.value.findings);
        }

        let specialNodesNeutralized = 0;
        let rawDirectoriesCount = 0;
        let rawSymlinksCount = 0;
        let rawTotalEntries = 0;

        try {
          const rawBuf = await readFile(resolvedTargetPath);
          const detection = detectFirmwareFormat(rawBuf);
          if (detection.format === "squashfs") {
            const parsedEntries = SquashFsParser.parseEntries(
              rawBuf,
              detection.offset,
            );
            if (parsedEntries.ok) {
              rawTotalEntries = parsedEntries.value.length;
              for (const entry of parsedEntries.value) {
                if (entry.kind === "special") {
                  specialNodesNeutralized++;
                } else if (entry.kind === "directory") {
                  rawDirectoriesCount++;
                } else if (entry.kind === "symlink") {
                  rawSymlinksCount++;
                }
              }
            }
          }
        } catch {
          // Handled by SandboxedExtractor below
        }

        const extractRes = await this.extractor.extract(
          resolvedTargetPath,
          undefined,
          request.signal ? { signal: request.signal } : undefined,
        );
        extractionMs = Date.now() - extStart;

        if (!extractRes.ok) {
          const gapKind =
            extractRes.error.code === "UNSUPPORTED_FORMAT"
              ? "unsupported"
              : "failed";
          const gapReason = `${extractRes.error.code}: ${extractRes.error.message}`;
          extractionGaps.push({
            path: rootAssetName,
            reason: gapReason,
            kind: gapKind,
          });
          extractionWarnings.push(gapReason);
          if (extractRes.error.code === "UNSUPPORTED_FORMAT") {
            unsupportedInputTypes.push(rootFormat);
          }
          await inventoryService.recordExtractionGap(
            assessmentId,
            rootAssetId,
            {
              path: rootAssetName,
              reason: gapReason,
              kind: gapKind,
              offset: 0,
            },
          );

          extractionSummary = {
            rootAssetId,
            rootFirmwareSha256: rootSha256 ?? "0".repeat(64),
            format: rootFormat,
            sandboxDir: null,
            totalDiscoveredEntries: 0,
            regularFilesExtracted: 0,
            directoriesCount: 0,
            symlinksCount: 0,
            specialFilesNeutralized: 0,
            totalBytesExtracted: 0,
            classificationCounts: {
              elf_executable: 0,
              elf_shared_library: 0,
              shell_script: 0,
              configuration_file: 0,
              kernel_or_bootloader_image: 0,
              unknown_binary: 0,
              regular_file: 0,
            },
            extractionGaps,
            extractionWarnings,
          };
        } else {
          activeSandboxDir = extractRes.value.sandboxDir;
          const invStart = Date.now();

          if (specialNodesNeutralized > 0) {
            await storage.observations.record({
              assessment_id: assessmentId,
              asset_id: rootAssetId,
              key: "firmware.special_entry",
              value: {
                path: "dev/console",
                type: "character_device",
                neutralized: true,
                count: specialNodesNeutralized,
                published: false,
              },
              confidence: 1.0,
              source_tool: "sandboxed_extractor",
              agent_id: "security_assessment_service",
              evidence_id: null,
              created_at: Date.now(),
            });
          }

          const invRes = await inventoryService.inventoryAndSchedule(
            assessmentId,
            rootAssetId,
            extractRes.value.sandboxDir,
            extractRes.value.format,
          );
          inventoryMs = Date.now() - invStart;

          if (!invRes.ok) {
            return err({
              code: "STORAGE_ERROR",
              message: `Firmware inventory failed: ${invRes.error.message}`,
              details: invRes.error,
            });
          }

          const osRes = await this.embeddedOsAnalyzer.analyze(
            extractRes.value.sandboxDir,
            this.toDomainAsset(rootBlackboardAsset),
          );
          if (osRes.ok) {
            candidateFindingsToPersist.push(...osRes.value.findings);
          }

          const classCounts: Record<ExtractedFileClassification, number> = {
            elf_executable: 0,
            elf_shared_library: 0,
            shell_script: 0,
            configuration_file: 0,
            kernel_or_bootloader_image: 0,
            unknown_binary: 0,
            regular_file: 0,
          };

          let dirCount = 0;
          for (const createdAsset of invRes.value.assetsCreated) {
            if (createdAsset.tags.includes("directory")) {
              dirCount++;
              continue;
            }
            if (createdAsset.tags.includes("partition")) {
              continue;
            }
            const cls =
              (createdAsset.metadata
                ?.fileClassification as ExtractedFileClassification) ??
              "regular_file";
            if (cls in classCounts) {
              classCounts[cls]++;
            }
          }

          const symlinkObs = invRes.value.observationsCreated.filter(
            (o) => o.key === "firmware.symlink_entry",
          );
          for (const sym of symlinkObs) {
            const val = sym.value as {
              path?: string;
              target?: string;
              escapes_sandbox?: boolean;
            };
            if (val.escapes_sandbox) {
              extractionWarnings.push(
                `Symlink '${val.path}' targeting '${val.target}' escapes sandbox and was neutralized`,
              );
            }
          }

          const effectiveDirs = Math.max(dirCount, rawDirectoriesCount);
          const effectiveSymlinks = Math.max(
            symlinkObs.length,
            rawSymlinksCount,
          );
          const totalEntries =
            rawTotalEntries > 0
              ? rawTotalEntries
              : invRes.value.extractedFilesCount +
                effectiveDirs +
                effectiveSymlinks +
                specialNodesNeutralized;

          extractionSummary = {
            rootAssetId,
            rootFirmwareSha256: rootSha256 ?? "0".repeat(64),
            format: extractRes.value.format,
            sandboxDir: request.keepExtractedSandbox
              ? extractRes.value.sandboxDir
              : null,
            totalDiscoveredEntries: totalEntries,
            regularFilesExtracted: invRes.value.extractedFilesCount,
            directoriesCount: effectiveDirs,
            symlinksCount: effectiveSymlinks,
            specialFilesNeutralized: specialNodesNeutralized,
            totalBytesExtracted: invRes.value.totalBytesExtracted,
            classificationCounts: classCounts,
            extractionGaps,
            extractionWarnings,
          };
        }
      } else if (rootAssetType === "compiled_binary") {
        const taskId = `task_bin_${rootAssetId.replace(/^ast_/u, "").slice(0, 32)}`;
        const existingTask = await storage.tasks.getById(assessmentId, taskId);
        if (!existingTask.ok || !existingTask.value) {
          const taskRecord: TaskRecord = {
            id: taskId,
            assessment_id: assessmentId,
            task_type: "binary_analysis",
            title: `Audit binary: ${rootAssetName}`,
            description: `Perform static disassembly and vulnerability analysis for ${rootAssetName}`,
            asset_id: rootAssetId,
            priority: "high",
            status: "open",
            blocked_by: [],
            fencing_token: 0,
            cas_version: 0,
            claim: null,
            result: null,
            metadata: {
              required_capabilities: ["binary_decompilation"],
              architecture: rootArchitecture ?? "x86_64",
              relativePath: rootAssetName,
              fullPath: resolvedTargetPath,
              is_executable: true,
              firmwareSha256: rootSha256 ?? "0".repeat(64),
              rootFirmwareAssetId: rootAssetId,
              task_state: "queued_for_analysis",
            },
            created_at: Date.now(),
            updated_at: Date.now(),
          };
          await storage.tasks.create(taskRecord);
        }
      }

      const binStart = Date.now();
      const allTasksRes = await storage.tasks.listByAssessment(assessmentId);
      const allTasks = allTasksRes.ok ? allTasksRes.value : [];
      const openBinaryTasks = allTasks.filter(
        (t) => t.task_type === "binary_analysis" && t.status === "open",
      );

      const defaultBudget =
        depth === "surface" ? 5 : depth === "standard" ? 15 : 100;
      const maxBinaries = request.maxBinariesToAnalyze ?? defaultBudget;

      const prioritizedTasks = [...openBinaryTasks].sort((a, b) => {
        const scoreA = this.computeBinarySelectionPriority(a).score;
        const scoreB = this.computeBinarySelectionPriority(b).score;
        if (scoreB !== scoreA) return scoreB - scoreA;
        const pathA = String(a.metadata?.relativePath ?? a.title);
        const pathB = String(b.metadata?.relativePath ?? b.title);
        return pathA.localeCompare(pathB);
      });

      const selectedTasks = prioritizedTasks.slice(0, maxBinaries);
      const skippedByBudgetTasks = prioritizedTasks.slice(maxBinaries);

      const binaryMetrics: BinaryExecutionMetricRecord[] = [];
      let binariesAnalyzedCount = 0;
      let binariesPartiallyAnalyzedCount = 0;
      let binariesSkippedOrFailedCount = skippedByBudgetTasks.length;

      for (const skippedTask of skippedByBudgetTasks) {
        const assetRes = await storage.assets.findById(
          assessmentId,
          skippedTask.asset_id,
        );
        const asset = assetRes.ok ? assetRes.value : null;
        const priorityInfo = this.computeBinarySelectionPriority(skippedTask);
        const skipReason = `Skipped: task budget limit (${maxBinaries}) reached (${priorityInfo.reason})`;

        if (asset) {
          this.updateAssetLifecycleMetadata(storage, asset.id, {
            ...asset.metadata,
            lifecycle_state: "skipped_budget",
            analyzed: false,
            partially_analyzed: false,
            failed: false,
            skipped: true,
            skipped_reason: skipReason,
          });
        }

        const skippedMetricRecord: BinaryExecutionMetricRecord = {
          assetId: skippedTask.asset_id,
          name: asset?.name ?? skippedTask.title,
          relativePath: String(
            skippedTask.metadata?.relativePath ?? asset?.path ?? "",
          ),
          sha256: asset?.digest?.sha256 ?? "0".repeat(64),
          byteSize: Number(asset?.metadata?.size ?? 0),
          architecture: String(
            asset?.architecture ??
              skippedTask.metadata?.architecture ??
              "unknown",
          ),
          endianness: String(asset?.metadata?.endianness ?? "unknown"),
          elfClass: asset?.metadata?.is64Bit ? "ELF64" : "ELF32",
          selectionPriorityReason: skipReason,
          status: "SKIPPED",
          decoderProvider: "NOT_ATTEMPTED",
          instructionsDecoded: 0,
          decodedBytes: 0,
          totalCodeBytes: 0,
          unsupportedBytes: 0,
          decoderOutcome: "NOT_ATTEMPTED",
          decoderComplete: false,
          cfgBlocksCount: 0,
          cfgEdgesCount: 0,
          cfgComplete: false,
          functionsRecoveredCount: 0,
          callRelationshipsCount: 0,
          unresolvedSensitiveImports: [],
          reachabilityStatus: "NOT_ATTEMPTED",
          taintStageStatus: "NOT_ATTEMPTED",
          witnessStageStatus: "NOT_ATTEMPTED",
          witnessSatisfiabilityStatus: "NOT_ATTEMPTED",
          candidatesDetected: 0,
          findingsPersisted: 0,
          evidenceIds: [],
          durationMs: 0,
        };
        binaryMetrics.push(skippedMetricRecord);

        await storage.observations.record({
          assessment_id: assessmentId,
          asset_id: skippedTask.asset_id,
          key: "binary.analysis_metrics",
          value: skippedMetricRecord,
          confidence: 1.0,
          source_tool: "security_assessment_service",
          agent_id: "security_assessment_service",
          evidence_id: null,
          created_at: Date.now(),
        });
      }

      if (selectedTasks.length > 0) {
        const commonAllowedRoot = activeSandboxDir
          ? dirname(activeSandboxDir)
          : dirname(resolvedTargetPath);
        const taskTimeoutMs = request.taskTimeoutMs ?? 15_000;
        const maxWorkerHeapMb = request.maxWorkerHeapMb ?? 512;

        const registerWorkerAgent = async (agentId: string) => {
          await storage.agents.register({
            agent_id: agentId,
            assessment_id: assessmentId,
            capabilities: ["binary_analysis", "binary_decompilation"],
            host_id: "localhost",
            pid: process.pid,
            status: "idle",
            heartbeat_at: Date.now(),
            registered_at: Date.now(),
          });
        };

        let workerAgentId = `wkr_sup_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
        await registerWorkerAgent(workerAgentId);

        activeSupervisor = this.supervisorFactory({
          workerId: workerAgentId,
          allowedRoot: commonAllowedRoot,
          defaultTaskTimeoutMs: taskTimeoutMs,
          maxOldSpaceSizeMb: maxWorkerHeapMb,
        });
        await activeSupervisor.start();

        for (const openTask of selectedTasks) {
          if (request.signal?.aborted) {
            break;
          }

          const taskStart = Date.now();
          const priorityInfo = this.computeBinarySelectionPriority(openTask);

          if (activeSupervisor.getState() !== "READY") {
            try {
              await activeSupervisor.shutdown(200);
            } catch {
              activeSupervisor.forceKillProcess();
            }
            workerAgentId = `wkr_sup_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
            await registerWorkerAgent(workerAgentId);
            activeSupervisor = this.supervisorFactory({
              workerId: workerAgentId,
              allowedRoot: commonAllowedRoot,
              defaultTaskTimeoutMs: taskTimeoutMs,
              maxOldSpaceSizeMb: maxWorkerHeapMb,
            });
            await activeSupervisor.start();
          }

          const claimedTask = await this.claimSpecificTask(
            storage,
            assessmentId,
            openTask.id,
            workerAgentId,
            taskTimeoutMs * 2,
          );

          const assetRes = await storage.assets.findById(
            assessmentId,
            openTask.asset_id,
          );
          if (!assetRes.ok || !assetRes.value || !claimedTask) {
            binariesSkippedOrFailedCount++;
            continue;
          }

          const asset = assetRes.value;
          const assetMeta = (asset.metadata ?? {}) as Record<string, unknown>;
          const binaryPath =
            (assetMeta.fullPath as string) ??
            (openTask.metadata?.fullPath as string) ??
            asset.path ??
            resolvedTargetPath;

          try {
            const bridgeRes = await this.binaryBridge.analyze(
              { path: binaryPath },
              request.signal ? { signal: request.signal } : undefined,
            );
            if (!bridgeRes.ok) {
              throw new Error(
                `BinaryAnalysisBridge failed: ${bridgeRes.error.message}`,
              );
            }

            const bridgeReport = bridgeRes.value;
            const candidates = this.candidateDetector.detectCandidates(
              asset.id,
              bridgeReport,
            );

            const binarySha256 =
              asset.digest?.sha256 ?? bridgeReport.metadata.sha256;
            const firmwareSha256 =
              (assetMeta.firmwareSha256 as string) ??
              rootSha256 ??
              binarySha256;
            const rawArch =
              asset.architecture ?? bridgeReport.metadata.architecture;
            const mappedArch =
              rawArch === "MIPS"
                ? bridgeReport.metadata.endianness === "big"
                  ? "MIPS_BE"
                  : "MIPS_LE"
                : rawArch === "x86_64" ||
                    rawArch === "ARM" ||
                    rawArch === "ARM32" ||
                    rawArch === "Thumb" ||
                    rawArch === "MIPS_BE" ||
                    rawArch === "MIPS_LE"
                  ? rawArch
                  : "ARM";

            const fileStat = await stat(binaryPath);
            const normalizedTaskId = claimedTask.id.startsWith("tsk_")
              ? claimedTask.id
              : `tsk_${claimedTask.id.replace(/[^a-zA-Z0-9_-]/g, "")}`;
            const fencingToken = Math.max(1, claimedTask.fencing_token);

            const runManager = authority.getRunManager();
            const firstCand = candidates[0];
            const run = runManager.startRun(
              assessmentId,
              asset.id,
              binarySha256,
            );

            const workerReq: BinaryWorkerAnalyzeRequest = {
              protocolVersion: "1.0.0",
              kind: "ANALYZE_REQUEST",
              messageId: randomUUID(),
              taskId: normalizedTaskId,
              assessmentId,
              assetId: asset.id,
              firmwareSha256,
              binarySha256,
              runId: run.runId,
              fencingToken,
              workerId: activeSupervisor.workerId,
              requestedStage: "ALL",
              binaryInput: {
                type: "file_path",
                path: binaryPath,
                expected_sha256: binarySha256,
                byte_size: Math.max(1, fileStat.size),
                read_only: true,
              },
              analysisConfiguration: {
                architecture: mappedArch as any,
                entryPoints: ["main"],
                targetFunctions: firstCand ? [firstCand.sinkApi] : ["strcpy"],
                targetSinkApi: firstCand?.sinkApi ?? "strcpy",
                candidateRuleId: firstCand?.ruleId ?? "REA-BIN-001",
                candidateCategory:
                  firstCand?.category ?? "unsafe_memory_operations",
                maxInstructions: 25_000,
                maxCfgBlocks: 10_000,
                maxPaths: 500,
              },
              deadline: Date.now() + taskTimeoutMs,
            };

            const workerResp = await activeSupervisor.executeTask(workerReq);
            if (!workerResp.ok) {
              throw new Error(
                `Supervised binary worker failed (${workerResp.error.code}): ${workerResp.error.message}`,
              );
            }

            const validateCtx: ParentValidationContext = {
              assessmentId,
              assetId: asset.id,
              binarySha256,
              firmwareSha256,
              runId: run.runId,
              taskId: normalizedTaskId,
              fencingToken,
              workerId: activeSupervisor.workerId,
              requestedStage: "ALL",
              architecture: mappedArch,
              binaryInputPath: binaryPath,
            };

            const valRes = this.parentValidator.validateWorkerResponse(
              workerResp.value,
              validateCtx,
            );
            if (!valRes.ok) {
              throw new Error(
                `ParentEvidenceValidator rejected worker response (${valRes.error.code}): ${valRes.error.message}`,
              );
            }

            const sealedRes = this.parentValidator.sealValidatedEvidence(
              valRes.value,
              authority,
              validateCtx,
            );
            if (!sealedRes.ok) {
              throw new Error(
                `TrustedEvidenceAuthority sealing failed (${sealedRes.error.code}): ${sealedRes.error.message}`,
              );
            }

            const bundle = sealedRes.value;
            const collectedEvidenceIds: string[] = [];
            if (bundle.decoderEvidence)
              collectedEvidenceIds.push(
                bundle.decoderEvidence.claims.evidenceId,
              );
            if (bundle.cfgEvidence)
              collectedEvidenceIds.push(bundle.cfgEvidence.claims.evidenceId);
            if (bundle.reachabilityEvidence)
              collectedEvidenceIds.push(
                bundle.reachabilityEvidence.claims.evidenceId,
              );
            if (bundle.taintEvidence)
              collectedEvidenceIds.push(bundle.taintEvidence.claims.evidenceId);
            if (bundle.witnessEvidence)
              collectedEvidenceIds.push(
                bundle.witnessEvidence.claims.evidenceId,
              );

            let findingsPersistedForBinary = 0;

            for (let idx = 0; idx < candidates.length; idx++) {
              const candidate = candidates[idx]!;
              let candidateBundle = bundle;
              let candidateRunId = run.runId;

              if (
                idx > 0 &&
                (candidate.sinkApi !== firstCand?.sinkApi ||
                  candidate.ruleId !== firstCand?.ruleId ||
                  candidate.category !== firstCand?.category)
              ) {
                const subRun = runManager.startRun(
                  assessmentId,
                  asset.id,
                  binarySha256,
                );
                candidateRunId = subRun.runId;
                const subReq: BinaryWorkerAnalyzeRequest = {
                  ...workerReq,
                  messageId: randomUUID(),
                  runId: subRun.runId,
                  analysisConfiguration: {
                    ...workerReq.analysisConfiguration,
                    targetFunctions: [candidate.sinkApi],
                    targetSinkApi: candidate.sinkApi,
                    candidateRuleId: candidate.ruleId,
                    candidateCategory: candidate.category,
                  },
                  deadline: Date.now() + taskTimeoutMs,
                };
                const subResp = await activeSupervisor.executeTask(subReq);
                if (subResp.ok) {
                  const subValCtx: ParentValidationContext = {
                    ...validateCtx,
                    runId: subRun.runId,
                  };
                  const subVal = this.parentValidator.validateWorkerResponse(
                    subResp.value,
                    subValCtx,
                  );
                  if (subVal.ok) {
                    const subSeal = this.parentValidator.sealValidatedEvidence(
                      subVal.value,
                      authority,
                      subValCtx,
                    );
                    if (subSeal.ok) {
                      candidateBundle = subSeal.value;
                    }
                  }
                }
              }

              const persistCtx: ParentValidationContext = {
                ...validateCtx,
                taskId: claimedTask.id,
                fencingToken: claimedTask.fencing_token,
                runId: candidateRunId,
              };

              const adjRes = this.parentValidator.adjudicateAndPersist({
                storage,
                authority,
                bridge: adjudicationBridge,
                candidate,
                asset,
                context: persistCtx,
                bundle: candidateBundle,
              });

              if (adjRes.ok) {
                findingsPersistedForBinary++;
              }
            }

            if (candidates.length === 0) {
              storage.transaction((tx) => {
                tx.db
                  .prepare(
                    `UPDATE tasks
                     SET status = 'completed', result_json = ?, cas_version = cas_version + 1, updated_at = ?
                     WHERE id = ? AND fencing_token = ?`,
                  )
                  .run(
                    JSON.stringify({
                      candidatesCount: 0,
                      evidenceIds: collectedEvidenceIds,
                    }),
                    Date.now(),
                    claimedTask.id,
                    claimedTask.fencing_token,
                  );
              });
            }

            const decPayload = valRes.value.decoderPayload;
            const cfgPayload = valRes.value.cfgPayload;
            const rchPayload = valRes.value.reachabilityPayload;
            const tntPayload = valRes.value.taintPayload;
            const witPayload = valRes.value.witnessPayload;

            const isDecodeAndCfgComplete =
              Boolean(decPayload && decPayload.outcome === "SUCCESS") &&
              Boolean(cfgPayload && cfgPayload.isComplete);
            const binaryStatus: "COMPLETED" | "PARTIAL" =
              isDecodeAndCfgComplete &&
              rchPayload?.isComplete === true &&
              tntPayload?.stageStatus !== "NOT_ATTEMPTED" &&
              tntPayload?.status !== "INCONCLUSIVE"
                ? "COMPLETED"
                : "PARTIAL";

            if (binaryStatus === "COMPLETED") {
              binariesAnalyzedCount++;
            } else {
              binariesAnalyzedCount++;
              binariesPartiallyAnalyzedCount++;
            }

            this.updateAssetLifecycleMetadata(storage, asset.id, {
              ...assetMeta,
              lifecycle_state: "analyzed",
              analyzed: true,
              partially_analyzed: binaryStatus === "PARTIAL",
              failed: false,
              skipped: false,
              evidenceIds: collectedEvidenceIds,
            });

            const totalCodeBytes = decPayload?.totalBytes ?? 0;
            const decodedBytes = decPayload?.decodedBytes ?? 0;
            const unsupportedBytes = Math.max(0, totalCodeBytes - decodedBytes);

            const metricRecord: BinaryExecutionMetricRecord = {
              assetId: asset.id,
              name: asset.name,
              relativePath: String(
                assetMeta.relativePath ?? asset.path ?? asset.name,
              ),
              sha256: binarySha256,
              byteSize: fileStat.size,
              architecture: bridgeReport.metadata.architecture,
              endianness: bridgeReport.metadata.endianness,
              elfClass: bridgeReport.metadata.elfClass,
              selectionPriorityReason: priorityInfo.reason,
              status: binaryStatus,
              decoderProvider:
                decPayload?.provenance.actualProvider ??
                "InProcessInstructionDecoder",
              instructionsDecoded: decPayload?.instructions.length ?? 0,
              decodedBytes,
              totalCodeBytes,
              unsupportedBytes,
              decoderOutcome: decPayload?.outcome ?? "FAILED",
              decoderComplete: decPayload?.outcome === "SUCCESS",
              cfgBlocksCount: cfgPayload?.blocks.length ?? 0,
              cfgEdgesCount: cfgPayload?.edges.length ?? 0,
              cfgComplete: cfgPayload?.isComplete ?? false,
              functionsRecoveredCount: bridgeReport.functions.length,
              callRelationshipsCount: bridgeReport.callRelationships.length,
              unresolvedSensitiveImports:
                bridgeReport.metadata.unresolvedSensitiveImports ?? [],
              reachabilityStatus: rchPayload?.status ?? "INCONCLUSIVE",
              taintStageStatus:
                tntPayload?.stageStatus ??
                tntPayload?.status ??
                "NOT_ATTEMPTED",
              witnessStageStatus: witPayload?.stageStatus ?? "NOT_ATTEMPTED",
              witnessSatisfiabilityStatus:
                witPayload?.satisfiabilityStatus ?? "NOT_ATTEMPTED",
              candidatesDetected: candidates.length,
              findingsPersisted: findingsPersistedForBinary,
              evidenceIds: collectedEvidenceIds,
              durationMs: Date.now() - taskStart,
            };

            binaryMetrics.push(metricRecord);

            await storage.observations.record({
              assessment_id: assessmentId,
              asset_id: asset.id,
              key: "binary.analysis_metrics",
              value: metricRecord,
              confidence: 1.0,
              source_tool: metricRecord.decoderProvider,
              agent_id: activeSupervisor.workerId,
              evidence_id: collectedEvidenceIds[0] ?? null,
              created_at: Date.now(),
            });
          } catch (taskErr) {
            binariesSkippedOrFailedCount++;
            const errMsg =
              taskErr instanceof Error ? taskErr.message : String(taskErr);
            extractionWarnings.push(
              `Binary analysis failed for '${asset.name}': ${errMsg}`,
            );

            storage.transaction((tx) => {
              tx.db
                .prepare(
                  `UPDATE tasks
                   SET status = 'failed', result_json = ?, metadata_json = ?, cas_version = cas_version + 1, updated_at = ?
                   WHERE id = ?`,
                )
                .run(
                  JSON.stringify({ error: errMsg }),
                  JSON.stringify({
                    ...claimedTask.metadata,
                    failed: true,
                    error: errMsg,
                  }),
                  Date.now(),
                  claimedTask.id,
                );
            });

            this.updateAssetLifecycleMetadata(storage, asset.id, {
              ...assetMeta,
              lifecycle_state: "failed",
              analyzed: false,
              failed: true,
              error: errMsg,
            });

            binaryMetrics.push({
              assetId: asset.id,
              name: asset.name,
              relativePath: String(
                assetMeta.relativePath ?? asset.path ?? asset.name,
              ),
              sha256: asset.digest?.sha256 ?? "0".repeat(64),
              byteSize: Number(assetMeta.size ?? 0),
              architecture: String(asset.architecture ?? "unknown"),
              endianness: String(assetMeta.endianness ?? "unknown"),
              elfClass: assetMeta.is64Bit ? "ELF64" : "ELF32",
              selectionPriorityReason: priorityInfo.reason,
              status: "FAILED",
              decoderProvider: "InProcessInstructionDecoder",
              instructionsDecoded: 0,
              decodedBytes: 0,
              totalCodeBytes: 0,
              unsupportedBytes: 0,
              decoderOutcome: "FAILED",
              decoderComplete: false,
              cfgBlocksCount: 0,
              cfgEdgesCount: 0,
              cfgComplete: false,
              functionsRecoveredCount: 0,
              callRelationshipsCount: 0,
              unresolvedSensitiveImports: [],
              reachabilityStatus: "INCONCLUSIVE",
              taintStageStatus: "NOT_ATTEMPTED",
              witnessStageStatus: "NOT_ATTEMPTED",
              witnessSatisfiabilityStatus: "NOT_ATTEMPTED",
              candidatesDetected: 0,
              findingsPersisted: 0,
              evidenceIds: [],
              durationMs: Date.now() - taskStart,
              error: errMsg,
            });
          }
        }
      }
      binaryAnalysisMs = Date.now() - binStart;

      const extScanStart = Date.now();
      let selectedScanners: string[] = [];
      let executedScanners: string[] = [];
      let completedScanners: string[] = [];
      let failedScanners: string[] = [];
      let skippedScanners: string[] = [];
      const scannerWarnings: string[] = [...extractionWarnings];

      if (request.runExternalScanners !== false) {
        const discoverRes = await this.vulnerabilityEngine.discover({
          asset: this.toDomainAsset(rootBlackboardAsset),
          scope: initialAssessment.scope,
          ...(request.yaraRuleFiles
            ? { yaraRuleFiles: request.yaraRuleFiles }
            : {}),
          ...(request.semgrepRules
            ? { semgrepRules: request.semgrepRules }
            : {}),
          ...(request.signal ? { signal: request.signal } : {}),
        });

        if (discoverRes.ok) {
          selectedScanners = [...discoverRes.value.selected_scanners];
          executedScanners = [...discoverRes.value.executed_scanners];
          completedScanners = [...discoverRes.value.completed_scanners];
          failedScanners = [...discoverRes.value.failed_scanners];
          skippedScanners = [...discoverRes.value.skipped_scanners];
          scannerWarnings.push(...discoverRes.value.scanner_warnings);
          candidateFindingsToPersist.push(...discoverRes.value.findings);
        }
      }
      externalScannersMs = Date.now() - extScanStart;

      const persistStart = Date.now();
      for (const candidateFinding of candidateFindingsToPersist) {
        const existingFinding = await storage.findings.getById(
          assessmentId,
          candidateFinding.id,
        );
        if (!existingFinding.ok || !existingFinding.value) {
          await storage.findings.create({
            id: candidateFinding.id,
            assessment_id: assessmentId,
            fingerprint: candidateFinding.id,
            asset_id: candidateFinding.affected_asset.id,
            title: candidateFinding.name,
            description: candidateFinding.technical_description,
            state:
              candidateFinding.verification_status === "VERIFIED"
                ? "CANDIDATE"
                : (candidateFinding.verification_status as any),
            cwe: [...candidateFinding.classification.cwe],
            severity: candidateFinding.severity,
            confidence: candidateFinding.confidence,
            location: candidateFinding.location,
            evidence_ids: [...candidateFinding.evidence_ids],
            remediation: candidateFinding.remediation,
            cas_version: 1,
            created_at: Date.now(),
            updated_at: Date.now(),
          });
        }
      }

      if (selectedTasks.length > 0) {
        if (!selectedScanners.includes("rea_supervised_binary_worker")) {
          selectedScanners.unshift("rea_supervised_binary_worker");
        }
        executedScanners.unshift("rea_supervised_binary_worker");
        if (binariesAnalyzedCount > 0) {
          completedScanners.unshift("rea_supervised_binary_worker");
        } else {
          failedScanners.unshift("rea_supervised_binary_worker");
        }
      }

      if (rootAssetType === "firmware_image") {
        selectedScanners.unshift("rea_sandboxed_extractor");
        executedScanners.unshift("rea_sandboxed_extractor");
        if (extractionSummary && extractionSummary.regularFilesExtracted > 0) {
          completedScanners.unshift("rea_sandboxed_extractor");
        } else {
          failedScanners.unshift("rea_sandboxed_extractor");
        }
      }

      const eligibleBinariesCount = openBinaryTasks.length;
      const extractedFilesCount = extractionSummary?.regularFilesExtracted ?? 0;
      const discoveredFilesCount =
        extractionSummary && extractionSummary.totalDiscoveredEntries > 0
          ? extractionSummary.totalDiscoveredEntries
          : 1;

      if (binariesPartiallyAnalyzedCount > 0) {
        scannerWarnings.push(
          `${binariesPartiallyAnalyzedCount}/${binariesAnalyzedCount} analyzed ELF binary(ies) had partial stage coverage (instruction-level TAINT and symbolic WITNESS are NOT_ATTEMPTED/INCONCLUSIVE).`,
        );
      }
      if (skippedByBudgetTasks.length > 0) {
        scannerWarnings.push(
          `${skippedByBudgetTasks.length} of ${eligibleBinariesCount} eligible ELF binaries were not analyzed due to task budget limit (${maxBinaries}).`,
        );
      }

      let overallStatus: ScanExecutionStatus = "COMPLETED";
      const nothingExecuted =
        executedScanners.length === 0 &&
        binariesAnalyzedCount === 0 &&
        extractedFilesCount === 0;

      if (nothingExecuted) {
        overallStatus = "NOT_SCANNED";
      } else if (
        rootAssetType === "firmware_image" &&
        extractedFilesCount === 0 &&
        binariesAnalyzedCount === 0 &&
        completedScanners.length === 0
      ) {
        overallStatus = "FAILED";
      } else if (
        extractionGaps.length > 0 ||
        binariesPartiallyAnalyzedCount > 0 ||
        binariesSkippedOrFailedCount > 0 ||
        failedScanners.length > 0 ||
        skippedScanners.length > 0 ||
        (eligibleBinariesCount > 0 &&
          binariesAnalyzedCount < eligibleBinariesCount)
      ) {
        overallStatus = "PARTIAL";
      } else {
        overallStatus = "COMPLETED";
      }

      const scanExecution: ScanExecutionMetadata = {
        status: overallStatus,
        selected_scanners: selectedScanners,
        executed_scanners: executedScanners,
        completed_scanners: completedScanners,
        failed_scanners: failedScanners,
        skipped_scanners: skippedScanners,
        scanner_warnings: scannerWarnings,
        unsupported_input_types: unsupportedInputTypes,
        extraction_gaps: extractionGaps.map((g) => ({
          path: g.path,
          reason: g.reason,
        })),
        coverage: {
          discovered_files: discoveredFilesCount,
          extracted_files: extractedFilesCount,
          eligible_binaries: eligibleBinariesCount,
          binaries_analyzed: binariesAnalyzedCount,
          binaries_partially_analyzed: binariesPartiallyAnalyzedCount,
          binaries_skipped_or_failed: binariesSkippedOrFailedCount,
        },
      };

      await storage.observations.record({
        assessment_id: assessmentId,
        asset_id: rootAssetId,
        key: "assessment.scan_execution",
        value: scanExecution,
        confidence: 1.0,
        source_tool: "security_assessment_service",
        agent_id: "security_assessment_service",
        evidence_id: null,
        created_at: Date.now(),
      });

      if (extractionSummary) {
        await storage.observations.record({
          assessment_id: assessmentId,
          asset_id: rootAssetId,
          key: "assessment.extraction_summary",
          value: extractionSummary,
          confidence: 1.0,
          source_tool: "security_assessment_service",
          agent_id: "security_assessment_service",
          evidence_id: null,
          created_at: Date.now(),
        });
      }

      const reconstructed = await this.buildAssessmentStateFromStorage(
        storage,
        assessmentId,
        scanExecution,
      );
      if (!reconstructed.ok) {
        return reconstructed;
      }

      const dbStatus = overallStatus === "FAILED" ? "failed" : "completed";
      await storage.assessments.updateStatus(
        assessmentId,
        dbStatus,
        reconstructed.value.metrics,
      );

      const report = this.renderReport(
        reconstructed.value,
        format,
        scanExecution,
      );
      const persistenceAndReportingMs = Date.now() - persistStart;
      const totalDurationMs = Date.now() - totalStart;

      const stageTimingsMs: StageTimingsRecord = {
        validationAndHashingMs,
        extractionMs,
        inventoryMs,
        binaryAnalysisMs,
        externalScannersMs,
        persistenceAndReportingMs,
        totalDurationMs,
      };

      await storage.observations.record({
        assessment_id: assessmentId,
        asset_id: rootAssetId,
        key: "assessment.stage_timings",
        value: stageTimingsMs,
        confidence: 1.0,
        source_tool: "security_assessment_service",
        agent_id: "security_assessment_service",
        evidence_id: null,
        created_at: Date.now(),
      });

      return ok({
        assessmentId,
        status: overallStatus,
        assessment: reconstructed.value,
        scanExecution,
        extractionSummary,
        binaryMetrics,
        stageTimingsMs,
        report,
      });
    } finally {
      if (activeSupervisor) {
        try {
          await activeSupervisor.shutdown(500);
        } catch {
          activeSupervisor.forceKillProcess();
        }
      }
      if (activeSandboxDir && !request.keepExtractedSandbox) {
        await this.extractor.cleanupSandbox(activeSandboxDir);
      }
      if (ownsStorage) {
        storage.close();
      }
    }
  }

  public async inspectFirmware(
    request: SecurityAssessmentRequest,
  ): Promise<
    Result<FirmwareInspectionExecutionOutput, SecurityAssessmentServiceError>
  > {
    const runRes = await this.runAssessment({
      ...request,
      format: request.format ?? "json",
    });
    if (!runRes.ok) {
      return runRes;
    }

    const out = runRes.value;
    const resolvedPath = resolve(request.targetPath);
    const deepRes = await this.firmwareDeepAnalyzer.analyze(resolvedPath);
    const partitions = deepRes.ok ? deepRes.value.detected_partitions : [];
    const arch =
      out.binaryMetrics[0]?.architecture ??
      (deepRes.ok ? deepRes.value.architecture : "UNKNOWN");
    const endianness =
      out.binaryMetrics[0]?.endianness ??
      (deepRes.ok ? deepRes.value.endianness : "unknown");

    let score = 0;
    for (const f of out.assessment.findings) {
      if (f.severity.level === "CRITICAL") score += 35;
      else if (f.severity.level === "HIGH") score += 20;
      else if (f.severity.level === "MEDIUM") score += 10;
      else if (f.severity.level === "LOW") score += 5;
    }
    const riskScore = Math.min(score, 100);

    const extSummary: FirmwareExtractionSummaryRecord =
      out.extractionSummary ?? {
        rootAssetId:
          out.assessment.assets[0]?.id ??
          (("ast_" + "0".repeat(64)) as AssetId),
        rootFirmwareSha256:
          out.assessment.assets[0]?.digest?.sha256 ?? "0".repeat(64),
        format: "unknown",
        sandboxDir: null,
        totalDiscoveredEntries: out.scanExecution.coverage.discovered_files,
        regularFilesExtracted: out.scanExecution.coverage.extracted_files,
        directoriesCount: 0,
        symlinksCount: 0,
        specialFilesNeutralized: 0,
        totalBytesExtracted: 0,
        classificationCounts: {
          elf_executable: 0,
          elf_shared_library: 0,
          shell_script: 0,
          configuration_file: 0,
          kernel_or_bootloader_image: 0,
          unknown_binary: 0,
          regular_file: 0,
        },
        extractionGaps: [],
        extractionWarnings: out.scanExecution.scanner_warnings,
      };

    const summary =
      `Firmware assessment [${out.status}] for '${basename(resolvedPath)}': ` +
      `extracted ${extSummary.regularFilesExtracted} files, identified ${out.scanExecution.coverage.eligible_binaries} ELF binaries ` +
      `(${out.scanExecution.coverage.binaries_analyzed} analyzed, ${out.scanExecution.coverage.binaries_skipped_or_failed} skipped/failed), ` +
      `and recorded ${out.assessment.findings.length} finding(s).`;

    return ok({
      assessmentId: out.assessmentId,
      status: out.status,
      target_path: resolvedPath,
      sha256: extSummary.rootFirmwareSha256,
      architecture: arch,
      endianness,
      detected_partitions: partitions,
      extraction_summary: extSummary,
      binary_metrics: out.binaryMetrics,
      scan_execution: out.scanExecution,
      findings: out.assessment.findings,
      risk_score: riskScore,
      summary,
      stage_timings_ms: out.stageTimingsMs,
    });
  }

  public async runMultiAgentAssessment(
    request: SecurityAssessmentRequest,
  ): Promise<
    Result<SecurityAssessmentExecutionOutput, SecurityAssessmentServiceError>
  > {
    const baseResult = await this.runAssessment(request);
    if (!baseResult.ok) {
      return baseResult;
    }

    const domainOrchestrator = new DomainAgentOrchestrator();
    const multiAgentRes = await domainOrchestrator.runAssessment(
      baseResult.value.assessment,
      request.signal,
    );

    if (!multiAgentRes.ok) {
      return baseResult;
    }

    const { storage, ownsStorage } = this.acquireStorage(
      baseResult.value.assessmentId,
    );
    try {
      for (const f of multiAgentRes.value.assessment.findings) {
        const existing = await storage.findings.getById(
          baseResult.value.assessmentId,
          f.id,
        );
        if (!existing.ok || !existing.value) {
          await storage.findings.create({
            id: f.id,
            assessment_id: baseResult.value.assessmentId,
            fingerprint: f.id,
            asset_id: f.affected_asset.id,
            title: f.name,
            description: f.technical_description,
            state:
              f.verification_status === "VERIFIED"
                ? "CANDIDATE"
                : (f.verification_status as any),
            cwe: [...f.classification.cwe],
            severity: f.severity,
            confidence: f.confidence,
            location: f.location,
            evidence_ids: [...f.evidence_ids],
            remediation: f.remediation,
            cas_version: 1,
            created_at: Date.now(),
            updated_at: Date.now(),
          });
        }
      }

      const rebuilt = await this.buildAssessmentStateFromStorage(
        storage,
        baseResult.value.assessmentId,
        baseResult.value.scanExecution,
      );
      if (!rebuilt.ok) {
        return rebuilt;
      }

      const format = request.format ?? "markdown";
      const report = this.renderReport(
        rebuilt.value,
        format,
        baseResult.value.scanExecution,
      );

      return ok({
        ...baseResult.value,
        assessment: rebuilt.value,
        report,
      });
    } finally {
      if (ownsStorage) {
        storage.close();
      }
    }
  }

  public async generateReportFromPersisted(
    assessmentId: AssessmentId,
    format: ReportFormat = "markdown",
  ): Promise<
    Result<PersistedAssessmentReportOutput, SecurityAssessmentServiceError>
  > {
    if (!/^asm_[a-f0-9]{64}$/.test(String(assessmentId ?? ""))) {
      return err({
        code: "INVALID_TARGET",
        message: `Invalid assessment ID '${String(assessmentId)}': expected format asm_<64 lowercase hex chars>.`,
      });
    }

    if (!this.injectedStorage) {
      const candidateDbPath =
        this.dbPath ??
        process.env.REA_SECURITY_DB_PATH ??
        join(tmpdir(), "rea-security-blackboard", "blackboard.db");
      if (candidateDbPath !== ":memory:") {
        if (!existsSync(candidateDbPath)) {
          return err({
            code: "ASSESSMENT_NOT_FOUND",
            message: `Persisted SQLite blackboard '${candidateDbPath}' does not exist for assessment '${assessmentId}'.`,
          });
        }
        try {
          await access(candidateDbPath, constants.R_OK);
        } catch (cause) {
          return err({
            code: "AUTHORIZATION_DENIED",
            message: `Insufficient permissions to read SQLite blackboard '${candidateDbPath}': ${cause instanceof Error ? cause.message : String(cause)}`,
            details: cause,
          });
        }
      }
    }

    let acquired: { storage: SqliteBlackboardStorage; ownsStorage: boolean };
    try {
      acquired = this.acquireStorage(assessmentId);
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        message: `Failed to open or verify SQLite blackboard storage for '${assessmentId}': ${cause instanceof Error ? cause.message : String(cause)}`,
        details: cause,
      });
    }
    const { storage, ownsStorage } = acquired;
    try {
      const assRes = await storage.assessments.findById(assessmentId);
      if (!assRes.ok) {
        return err({
          code: "STORAGE_ERROR",
          message: assRes.error.message,
          details: assRes.error,
        });
      }
      if (!assRes.value) {
        return err({
          code: "ASSESSMENT_NOT_FOUND",
          message: `Assessment '${assessmentId}' was not found in SQLite blackboard storage.`,
        });
      }

      const db = storage.getDatabase();
      const scanExecRow = db
        .prepare(
          `SELECT value_json FROM observations
           WHERE assessment_id = ? AND key = 'assessment.scan_execution'
           ORDER BY created_at DESC LIMIT 1`,
        )
        .get(assessmentId) as { value_json: string } | undefined;

      const extSummaryRow = db
        .prepare(
          `SELECT value_json FROM observations
           WHERE assessment_id = ? AND key = 'assessment.extraction_summary'
           ORDER BY created_at DESC LIMIT 1`,
        )
        .get(assessmentId) as { value_json: string } | undefined;

      const binMetricRows = db
        .prepare(
          `SELECT value_json FROM observations
           WHERE assessment_id = ? AND key = 'binary.analysis_metrics'
           ORDER BY created_at ASC`,
        )
        .all(assessmentId) as Array<{ value_json: string }>;

      const binaryMetrics: BinaryExecutionMetricRecord[] = binMetricRows.map(
        (r) => JSON.parse(r.value_json) as BinaryExecutionMetricRecord,
      );

      const extractionSummary: FirmwareExtractionSummaryRecord | undefined =
        extSummaryRow
          ? (JSON.parse(
              extSummaryRow.value_json,
            ) as FirmwareExtractionSummaryRecord)
          : undefined;

      let scanExecution: ScanExecutionMetadata;
      if (scanExecRow) {
        scanExecution = JSON.parse(
          scanExecRow.value_json,
        ) as ScanExecutionMetadata;
      } else {
        const tasksRes = await storage.tasks.listByAssessment(assessmentId);
        const tasks = tasksRes.ok ? tasksRes.value : [];
        const binTasks = tasks.filter((t) => t.task_type === "binary_analysis");
        const completedBin = binTasks.filter(
          (t) => t.status === "completed",
        ).length;
        const failedOrOpenBin = binTasks.filter(
          (t) => t.status !== "completed",
        ).length;

        scanExecution = {
          status:
            failedOrOpenBin > 0
              ? "PARTIAL"
              : completedBin > 0
                ? "COMPLETED"
                : "NOT_SCANNED",
          selected_scanners: ["rea_supervised_binary_worker"],
          executed_scanners:
            completedBin > 0 ? ["rea_supervised_binary_worker"] : [],
          completed_scanners:
            completedBin > 0 ? ["rea_supervised_binary_worker"] : [],
          failed_scanners: [],
          skipped_scanners: [],
          scanner_warnings: [],
          unsupported_input_types: [],
          coverage: {
            discovered_files: 1,
            extracted_files: extractionSummary?.regularFilesExtracted ?? 0,
            eligible_binaries: binTasks.length,
            binaries_analyzed: completedBin,
            binaries_partially_analyzed: completedBin,
            binaries_skipped_or_failed: failedOrOpenBin,
          },
        };
      }

      if (
        !scanExecution ||
        typeof scanExecution !== "object" ||
        !scanExecution.coverage ||
        typeof scanExecution.coverage.discovered_files !== "number"
      ) {
        return err({
          code: "STORAGE_ERROR",
          message: `Corrupted persisted scan_execution observation for assessment '${assessmentId}'.`,
        });
      }

      const stateRes = await this.buildAssessmentStateFromStorage(
        storage,
        assessmentId,
        scanExecution,
      );
      if (!stateRes.ok) {
        return stateRes;
      }

      if (stateRes.value.assets.length === 0) {
        return err({
          code: "STORAGE_ERROR",
          message: `Corrupted persisted assessment '${assessmentId}': zero asset records exist in SQLite storage.`,
        });
      }

      const report = this.renderReport(stateRes.value, format, scanExecution);

      return ok({
        assessmentId,
        status: scanExecution.status,
        assessment: stateRes.value,
        scanExecution,
        extractionSummary,
        binaryMetrics,
        format,
        report,
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        message: `Corrupted or unreadable persisted assessment '${assessmentId}': ${cause instanceof Error ? cause.message : String(cause)}`,
        details: cause,
      });
    } finally {
      if (ownsStorage) {
        storage.close();
      }
    }
  }

  private acquireStorage(assessmentId: AssessmentId): {
    storage: SqliteBlackboardStorage;
    ownsStorage: boolean;
  } {
    if (this.injectedStorage) {
      return { storage: this.injectedStorage, ownsStorage: false };
    }
    const resolvedDbPath =
      this.dbPath ??
      process.env.REA_SECURITY_DB_PATH ??
      join(tmpdir(), "rea-security-blackboard", "blackboard.db");
    const resolvedJournalPath =
      this.journalPath ??
      join(dirname(resolvedDbPath), "packboard-audit.jsonl");

    const storage = new SqliteBlackboardStorage({
      dbPath: resolvedDbPath,
      journalPath: resolvedJournalPath,
      keyringManager: this.keyringManager,
      assessmentId,
    });
    return { storage, ownsStorage: true };
  }

  private computeBinarySelectionPriority(task: TaskRecord): {
    score: number;
    reason: string;
  } {
    const relPath = String(
      task.metadata?.relativePath ?? task.title,
    ).toLowerCase();
    const base = basename(relPath);

    if (PRIORITY_DAEMON_NAMES.has(base)) {
      return { score: 100, reason: "Tier 1: Network/Authentication Daemon" };
    }
    if (PRIORITY_CORE_NAMES.has(base)) {
      return { score: 85, reason: "Tier 2: Core System Utility / IPC Bus" };
    }
    if (
      relPath.startsWith("usr/sbin/") ||
      relPath.startsWith("sbin/") ||
      relPath.startsWith("usr/bin/") ||
      relPath.startsWith("bin/")
    ) {
      return { score: 70, reason: "Tier 3: System ELF Executable" };
    }
    if (
      relPath.includes(".so") ||
      relPath.startsWith("lib/") ||
      relPath.startsWith("usr/lib/")
    ) {
      return { score: 40, reason: "Tier 4: Shared Library (.so)" };
    }
    return { score: 50, reason: "Tier 3: ELF Binary" };
  }

  private async claimSpecificTask(
    storage: SqliteBlackboardStorage,
    assessmentId: AssessmentId,
    taskId: string,
    agentId: string,
    leaseDurationMs: number,
  ): Promise<TaskRecord | null> {
    const now = Date.now();
    const claim = {
      agent_id: agentId,
      claimed_at: now,
      lease_expires_at: now + leaseDurationMs,
    };
    storage.transaction((tx) => {
      tx.db
        .prepare(
          `UPDATE tasks
           SET status = 'claimed',
               fencing_token = fencing_token + 1,
               cas_version = cas_version + 1,
               claim_json = ?,
               updated_at = ?
           WHERE id = ? AND assessment_id = ?`,
        )
        .run(JSON.stringify(claim), now, taskId, assessmentId);
    });
    const res = await storage.tasks.getById(assessmentId, taskId);
    return res.ok ? res.value : null;
  }

  private updateAssetLifecycleMetadata(
    storage: SqliteBlackboardStorage,
    assetId: AssetId,
    metadata: Record<string, unknown>,
    assessmentId?: AssessmentId,
  ): void {
    storage.transaction((tx) => {
      if (assessmentId) {
        tx.db
          .prepare(
            "UPDATE assets SET metadata_json = ? WHERE id = ? AND assessment_id = ?",
          )
          .run(JSON.stringify(metadata), assetId, assessmentId);
      } else {
        tx.db
          .prepare("UPDATE assets SET metadata_json = ? WHERE id = ?")
          .run(JSON.stringify(metadata), assetId);
      }
    });
  }

  private async buildAssessmentStateFromStorage(
    storage: SqliteBlackboardStorage,
    assessmentId: AssessmentId,
    scanExecution: ScanExecutionMetadata,
  ): Promise<Result<AssessmentState, SecurityAssessmentServiceError>> {
    const assRes = await storage.assessments.findById(assessmentId);
    if (!assRes.ok || !assRes.value) {
      return err({
        code: "ASSESSMENT_NOT_FOUND",
        message: `Assessment ${assessmentId} not found in blackboard`,
      });
    }

    const assetsRes = await storage.assets.listByAssessment(assessmentId);
    if (!assetsRes.ok) {
      return err({
        code: "STORAGE_ERROR",
        message: assetsRes.error.message,
      });
    }

    const findingsRes = await storage.findings.listByAssessment(assessmentId);
    if (!findingsRes.ok) {
      return err({
        code: "STORAGE_ERROR",
        message: findingsRes.error.message,
      });
    }

    const assetMap = new Map<string, BlackboardAssetRecord>();
    const domainAssets: AssetRecord[] = [];
    for (const a of assetsRes.value) {
      assetMap.set(a.id, a);
      domainAssets.push(this.toDomainAsset(a));
    }

    const domainFindings: SecurityFinding[] = findingsRes.value.map((f) =>
      this.toDomainFinding(f, assetMap.get(f.asset_id)),
    );

    const metrics = calculateAssessmentMetrics(domainAssets, domainFindings);
    const assRecord = assRes.value;

    const state: AssessmentState = {
      assessment_id: assessmentId,
      phase: scanExecution.status === "FAILED" ? "failed" : "completed",
      created_at: new Date(assRecord.created_at).toISOString(),
      updated_at: new Date(assRecord.updated_at).toISOString(),
      completed_at: new Date().toISOString(),
      objective: assRecord.objective,
      scope: assRecord.authorization,
      assets: domainAssets,
      findings: domainFindings,
      metrics,
    };

    return ok(state);
  }

  private toDomainAsset(a: BlackboardAssetRecord): AssetRecord {
    return {
      id: a.id,
      name: a.name,
      type: a.type,
      path: a.path,
      digest: a.digest,
      architecture: a.architecture,
      version: a.version,
      environment: a.environment,
      tags: [...a.tags],
      metadata: { ...a.metadata },
    };
  }

  private toDomainFinding(
    r: FindingRecord,
    asset?: BlackboardAssetRecord,
  ): SecurityFinding {
    const isVerified = r.state === "VERIFIED";
    return {
      id: r.id,
      name: r.title,
      affected_asset: {
        id: r.asset_id,
        name: asset?.name ?? r.location.module ?? r.asset_id,
        type: asset?.type ?? "compiled_binary",
      },
      location: r.location,
      technical_description: r.description,
      root_cause: r.description,
      evidence_ids: [...r.evidence_ids],
      reproduction_steps: [],
      impact: {
        description: r.description,
        attack_prerequisites: ["Authorized target access"],
        exploitability: isVerified ? "PROVEN" : "THEORETICAL",
      },
      severity: r.severity,
      confidence: r.confidence,
      remediation: r.remediation ?? {
        description: "Review and remediate identified weakness",
        code_diff: null,
        config_example: null,
        priority: "MEDIUM_TERM",
        validation_procedure: "Re-run security assessment after patching",
      },
      classification: {
        cve: [],
        cwe: (r.cwe ?? []) as any,
        capec: [],
        mitre_attack: [],
        owasp: [],
      },
      verification_status: r.state as any,
      provenance: {
        discovered_by: "SecurityAssessmentService",
        discovered_at: new Date(r.created_at).toISOString(),
        verified_by: isVerified ? "AdjudicationEngine" : null,
        verified_at: isVerified ? new Date(r.updated_at).toISOString() : null,
      },
    };
  }

  private renderReport(
    assessment: AssessmentState,
    format: ReportFormat,
    scanExecution: ScanExecutionMetadata,
  ): string {
    if (format === "sarif") {
      const sarifDoc = SarifExporter.exportFindings(assessment.findings, {
        assessmentId: assessment.assessment_id,
      });
      const enrichedRuns = sarifDoc.runs.map((run) => ({
        ...run,
        properties: {
          assessment_id: assessment.assessment_id,
          scan_status: scanExecution.status,
          scan_execution: scanExecution,
          skipped_binaries_count:
            scanExecution.coverage.binaries_skipped_or_failed,
        },
      }));
      return JSON.stringify({ ...sarifDoc, runs: enrichedRuns }, null, 2);
    }
    return this.reportGenerator.generate({
      assessment,
      format,
      scanExecution,
    });
  }

  private async computeFileSha256(filePath: string): Promise<string> {
    const handle = await open(filePath, "r");
    try {
      const hash = createHash("sha256");
      const buf = Buffer.alloc(64 * 1024);
      let pos = 0;
      let bytesRead = 0;
      while (
        (bytesRead = (await handle.read(buf, 0, buf.length, pos)).bytesRead) > 0
      ) {
        hash.update(buf.subarray(0, bytesRead));
        pos += bytesRead;
      }
      return hash.digest("hex");
    } finally {
      await handle.close();
    }
  }

  private async readFirstBytes(
    filePath: string,
    length: number,
  ): Promise<Buffer> {
    const handle = await open(filePath, "r");
    try {
      const buf = Buffer.alloc(length);
      const { bytesRead } = await handle.read(buf, 0, length, 0);
      return buf.subarray(0, bytesRead);
    } finally {
      await handle.close();
    }
  }
}
