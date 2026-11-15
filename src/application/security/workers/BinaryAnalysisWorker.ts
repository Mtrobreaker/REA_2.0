import { randomUUID } from "node:crypto";
import type { Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type {
  ICentralBlackboard,
  TaskRecord,
  BlackboardAssetRecord,
} from "../../../domain/security/blackboard/types.js";
import type { IContextProjector } from "../../../domain/security/blackboard/contextProjection.js";
import type { BlackboardError } from "../../../domain/security/blackboard/errors.js";
import { AgentWorker } from "../coordinator/AgentWorker.js";
import type {
  WorkerConfig,
  TaskExecutionHandler,
} from "../coordinator/coordinatorTypes.js";
import { BinaryAnalysisBridge } from "../../../security/binary/BinaryAnalysisBridge.js";
import { VulnerabilityCandidateDetector } from "../../../security/binary/VulnerabilityCandidateDetector.js";
import { VulnerabilityAdjudicationBridge } from "../../../security/binary/VulnerabilityAdjudicationBridge.js";
import type {
  BinaryAnalysisReport,
  SecurityFinding,
} from "../../../domain/security/binary/types.js";
import type { BinaryWorkerSupervisor } from "../../../security/binary/supervisor/BinaryWorkerSupervisor.js";
import type {
  ParentEvidenceValidator,
  ParentValidationContext,
} from "../../../security/binary/evidence/ParentEvidenceValidator.js";
import type { TrustedEvidenceAuthority } from "../../../security/binary/evidence/TrustedAnalysisEvidence.js";
import type { BinaryWorkerAnalyzeRequest } from "../../../security/binary/ipc/binaryWorkerProtocol.js";

export interface BinaryAnalysisWorkerOptions {
  readonly bridge?: BinaryAnalysisBridge;
  readonly detector?: VulnerabilityCandidateDetector;
  readonly adjudicator?: VulnerabilityAdjudicationBridge;
  readonly workerConfig?: Partial<WorkerConfig>;
  readonly supervisor?: BinaryWorkerSupervisor | undefined;
  readonly validator?: ParentEvidenceValidator | undefined;
  readonly authority?: TrustedEvidenceAuthority | undefined;
}

export interface BinaryAnalysisExecutionResult {
  readonly assetId: string;
  readonly sha256: string;
  readonly architecture: string;
  readonly endianness: string;
  readonly elfClass: string;
  readonly functionsCount: number;
  readonly candidatesCount: number;
  readonly findingsCreated: number;
  readonly findings: readonly SecurityFinding[];
}

export class BinaryAnalysisWorker {
  public readonly worker: AgentWorker;
  private readonly bridge: BinaryAnalysisBridge;
  private readonly detector: VulnerabilityCandidateDetector;
  private readonly adjudicator: VulnerabilityAdjudicationBridge;
  private readonly supervisor?: BinaryWorkerSupervisor | undefined;
  private readonly validator?: ParentEvidenceValidator | undefined;
  private readonly authority?: TrustedEvidenceAuthority | undefined;

  constructor(
    public readonly assessmentId: AssessmentId,
    private readonly blackboard: ICentralBlackboard,
    private readonly contextProjector: IContextProjector,
    options?: BinaryAnalysisWorkerOptions,
  ) {
    this.bridge = options?.bridge ?? new BinaryAnalysisBridge();
    this.detector = options?.detector ?? new VulnerabilityCandidateDetector();
    this.adjudicator =
      options?.adjudicator ?? new VulnerabilityAdjudicationBridge();
    this.supervisor = options?.supervisor;
    this.validator = options?.validator;
    this.authority = options?.authority;

    const config: WorkerConfig = {
      agentId: options?.workerConfig?.agentId ?? `worker_bin_${Date.now()}`,
      assessmentId,
      capabilities: ["binary_analysis", "binary_decompilation"],
      hostId: options?.workerConfig?.hostId,
      pollIntervalMs: options?.workerConfig?.pollIntervalMs ?? 50,
      leaseDurationMs: options?.workerConfig?.leaseDurationMs ?? 3000,
      heartbeatIntervalMs: options?.workerConfig?.heartbeatIntervalMs ?? 500,
      taskTimeoutMs: options?.workerConfig?.taskTimeoutMs ?? 10_000,
      maxTaskCeilingRenewals:
        options?.workerConfig?.maxTaskCeilingRenewals ?? 5,
      maxRetries: options?.workerConfig?.maxRetries ?? 3,
    };

    const handler: TaskExecutionHandler = (task, context, signal) =>
      this.handleBinaryAnalysisTask(task, context, signal);

    this.worker = new AgentWorker(
      config,
      blackboard,
      contextProjector,
      handler,
    );
  }

  public async start(): Promise<Result<void, BlackboardError>> {
    return this.worker.start();
  }

  public async stop(): Promise<void> {
    return this.worker.stop();
  }

  /**
   * Core task execution handler invoked by AgentWorker.
   */
  public async handleBinaryAnalysisTask(
    task: TaskRecord,
    _context: unknown,
    signal?: AbortSignal,
  ): Promise<BinaryAnalysisExecutionResult> {
    if (signal?.aborted) {
      throw new Error(`Task ${task.id} execution aborted before startup`);
    }

    // 1. Assessment Isolation Check
    if (task.assessment_id !== this.assessmentId) {
      throw new Error(
        `Assessment isolation violation: worker bound to ${this.assessmentId} cannot execute task for ${task.assessment_id}`,
      );
    }

    if (!task.asset_id) {
      throw new Error(`Task ${task.id} has no associated asset_id`);
    }

    // 2. Fetch Target Asset Record
    const assetRes = await this.blackboard.assets.findById(
      this.assessmentId,
      task.asset_id,
    );
    if (!assetRes.ok || !assetRes.value) {
      throw new Error(
        `Failed to locate asset ${task.asset_id} for task ${task.id}: ${assetRes.ok ? "not found" : assetRes.error.message}`,
      );
    }
    const asset: BlackboardAssetRecord = assetRes.value;

    // 3. Idempotency Check: Avoid duplicate analysis if already recorded
    const existingObs = await this.blackboard.observations.listByAsset(
      this.assessmentId,
      asset.id,
      "binary.analysis_report",
    );

    if (existingObs.ok && existingObs.value.length > 0) {
      const cached = existingObs.value[0]!
        .value as BinaryAnalysisExecutionResult;
      return cached;
    }

    // 4. Resolve Target Binary (Path or In-Memory Buffer)
    const metadata = asset.metadata as Record<string, unknown>;
    const taskMetadata = task.metadata as Record<string, unknown>;
    const targetPath =
      (metadata?.fullPath as string) ??
      (taskMetadata?.fullPath as string) ??
      asset.path;

    let rawBuffer = (taskMetadata?.buffer as any) ?? (metadata?.buffer as any);
    if (
      rawBuffer &&
      !Buffer.isBuffer(rawBuffer) &&
      Array.isArray(rawBuffer.data)
    ) {
      rawBuffer = Buffer.from(rawBuffer.data);
    }
    const targetBuffer = Buffer.isBuffer(rawBuffer) ? rawBuffer : undefined;

    // 5. Static Reverse Engineering Bridge (NO TARGET EXECUTION)
    const analysisRes = await this.bridge.analyze(
      { path: targetPath, ...(targetBuffer ? { buffer: targetBuffer } : {}) },
      signal ? { signal } : undefined,
    );

    if (!analysisRes.ok) {
      throw new Error(
        `Binary analysis bridge failed for asset ${asset.id}: ${analysisRes.error.message}`,
      );
    }
    const report: BinaryAnalysisReport = analysisRes.value;

    // 6. Vulnerability Candidate Detection across 7 Categories
    const candidates = this.detector.detectCandidates(asset.id, report);

    // 7. Multi-Stage Adjudication & 6-State Lifecycle Assignment
    const now = Date.now();
    const findingsCreated: SecurityFinding[] = [];

    if (this.supervisor && this.validator && this.authority) {
      // Execute analysis via isolated child worker supervisor
      const binarySha256 = (asset.digest?.sha256 ??
        report.metadata.sha256) as string;
      const firmwareSha256 =
        (metadata?.firmwareSha256 as string) ?? binarySha256;
      const rawArch =
        asset.architecture ??
        report.metadata.architecture ??
        (metadata?.architecture as string) ??
        "ARM";
      const mappedArch =
        rawArch === "MIPS"
          ? report.metadata.endianness === "big"
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

      const normalizedTaskId = task.id.startsWith("tsk_")
        ? task.id
        : `tsk_${task.id.replace(/[^a-zA-Z0-9_-]/g, "")}`;
      const effectiveFencingToken = Math.max(1, task.fencing_token);

      let binaryInput: BinaryWorkerAnalyzeRequest["binaryInput"];
      if (targetBuffer) {
        binaryInput = {
          type: "inline_buffer",
          data_base64: targetBuffer.toString("base64"),
          expected_sha256: binarySha256,
          byte_size: targetBuffer.length,
          read_only: true,
        };
      } else if (targetPath) {
        const byteSize =
          (metadata?.size as number) ?? (metadata?.byteSize as number) ?? 1024;
        binaryInput = {
          type: "file_path",
          path: targetPath,
          expected_sha256: binarySha256,
          byte_size: Math.max(1, byteSize),
          read_only: true,
        };
      } else {
        throw new Error(
          `Asset ${asset.id} has no valid path or buffer reference`,
        );
      }

      const runManager = this.authority.getRunManager();
      const firstCand = candidates[0];
      const run = runManager.startRun(
        this.assessmentId,
        asset.id,
        binarySha256,
      );

      const req: BinaryWorkerAnalyzeRequest = {
        protocolVersion: "1.0.0",
        kind: "ANALYZE_REQUEST",
        messageId: randomUUID(),
        taskId: normalizedTaskId,
        assessmentId: this.assessmentId,
        assetId: asset.id,
        firmwareSha256,
        binarySha256,
        runId: run.runId,
        fencingToken: effectiveFencingToken,
        workerId: this.supervisor.workerId,
        requestedStage: "ALL",
        binaryInput,
        analysisConfiguration: {
          architecture: mappedArch as any,
          entryPoints: ["main"],
          targetFunctions: firstCand ? [firstCand.sinkApi] : ["strcpy"],
          targetSinkApi: firstCand?.sinkApi ?? "strcpy",
          candidateRuleId: firstCand?.ruleId ?? "REA-BIN-001",
          candidateCategory: firstCand?.category ?? "unsafe_memory_operations",
          maxInstructions: 100_000,
          maxCfgBlocks: 10_000,
          maxPaths: 500,
        },
        deadline: Date.now() + 15_000,
      };

      const parentCtx: ParentValidationContext = {
        assessmentId: this.assessmentId,
        assetId: asset.id as any,
        binarySha256,
        firmwareSha256,
        runId: run.runId,
        taskId: task.id,
        fencingToken: task.fencing_token,
        workerId: this.supervisor.workerId,
        requestedStage: "ALL",
        architecture: mappedArch,
        binaryInputBytes: targetBuffer,
        binaryInputPath: targetBuffer ? undefined : targetPath,
      };

      const workerResponse = await this.supervisor.executeTask(req);
      if (!workerResponse.ok) {
        throw new Error(
          `Worker execution failed: ${workerResponse.error.message}`,
        );
      }

      // Align taskId/fencingToken in validation context with what was sent to worker
      const validateCtx: ParentValidationContext = {
        ...parentCtx,
        taskId: normalizedTaskId,
        fencingToken: effectiveFencingToken,
      };

      const valRes = this.validator.validateWorkerResponse(
        workerResponse.value,
        validateCtx,
      );
      if (!valRes.ok) {
        throw new Error(
          `Worker evidence validation failed: ${valRes.error.message} (${valRes.error.code})`,
        );
      }

      const sealedRes = this.validator.sealValidatedEvidence(
        valRes.value,
        this.authority,
        validateCtx,
      );
      if (!sealedRes.ok) {
        throw new Error(
          `Evidence sealing failed: ${sealedRes.error.message} (${sealedRes.error.code})`,
        );
      }

      const storage = this.blackboard as any;
      if (typeof storage.transaction === "function") {
        for (let idx = 0; idx < candidates.length; idx++) {
          const candidate = candidates[idx]!;
          if (signal?.aborted)
            throw new Error(
              `Task ${task.id} aborted during candidate adjudication`,
            );

          let candidateBundle = sealedRes.value;
          let candidateRunId = run.runId;

          if (
            idx > 0 &&
            (candidate.sinkApi !== firstCand?.sinkApi ||
              candidate.ruleId !== firstCand?.ruleId ||
              candidate.category !== firstCand?.category)
          ) {
            const subRun = runManager.startRun(
              this.assessmentId,
              asset.id,
              binarySha256,
            );
            candidateRunId = subRun.runId;
            const subReq: BinaryWorkerAnalyzeRequest = {
              ...req,
              messageId: randomUUID(),
              runId: subRun.runId,
              analysisConfiguration: {
                ...req.analysisConfiguration,
                targetFunctions: [candidate.sinkApi],
                targetSinkApi: candidate.sinkApi,
                candidateRuleId: candidate.ruleId,
                candidateCategory: candidate.category,
              },
            };
            const subResp = await this.supervisor.executeTask(subReq);
            if (subResp.ok) {
              const subValCtx: ParentValidationContext = {
                ...validateCtx,
                runId: subRun.runId,
              };
              const subVal = this.validator.validateWorkerResponse(
                subResp.value,
                subValCtx,
              );
              if (subVal.ok) {
                const subSeal = this.validator.sealValidatedEvidence(
                  subVal.value,
                  this.authority,
                  subValCtx,
                );
                if (subSeal.ok) {
                  candidateBundle = subSeal.value;
                }
              }
            }
          }

          const adjRes = this.validator.adjudicateAndPersist({
            storage,
            authority: this.authority,
            bridge: this.adjudicator,
            candidate,
            asset,
            context: { ...parentCtx, runId: candidateRunId },
            bundle: candidateBundle,
          });
          if (adjRes.ok) {
            findingsCreated.push(adjRes.value.finding);
          }
        }
      } else {
        for (const candidate of candidates) {
          if (signal?.aborted)
            throw new Error(
              `Task ${task.id} aborted during candidate adjudication`,
            );
          const adjResult = this.adjudicator.adjudicateCandidate(
            this.assessmentId,
            asset,
            candidate,
            {
              trustedReachability: sealedRes.value.reachabilityEvidence,
              trustedTaint: sealedRes.value.taintEvidence,
              trustedWitness: sealedRes.value.witnessEvidence,
              runId: run.runId,
            },
          );
          if (!adjResult.ok) continue;
          const finding = adjResult.value.finding;
          const saveRes = await this.blackboard.findings.create({
            id: finding.id,
            assessment_id: this.assessmentId,
            fingerprint: finding.id,
            asset_id: asset.id,
            title: finding.name,
            description: finding.technical_description,
            state: finding.verification_status as any,
            cwe: finding.classification.cwe as string[],
            severity: finding.severity,
            confidence: finding.confidence,
            location: finding.location,
            evidence_ids: finding.evidence_ids,
            remediation: finding.remediation,
            cas_version: 0,
            created_at: now,
            updated_at: now,
          });
          if (saveRes.ok) {
            findingsCreated.push(finding);
          }
        }
      }
    } else {
      for (const candidate of candidates) {
        if (signal?.aborted) {
          throw new Error(
            `Task ${task.id} aborted during candidate adjudication`,
          );
        }

        const adjResult = this.adjudicator.adjudicateCandidate(
          this.assessmentId,
          asset,
          candidate,
        );

        if (!adjResult.ok) continue;
        const finding = adjResult.value.finding;

        // Map to Blackboard FindingRecord
        const findingRecord = {
          id: finding.id,
          assessment_id: this.assessmentId,
          fingerprint: finding.id,
          asset_id: asset.id,
          title: finding.name,
          description: finding.technical_description,
          state: finding.verification_status as any,
          cwe: finding.classification.cwe as string[],
          severity: finding.severity,
          confidence: finding.confidence,
          location: finding.location,
          evidence_ids: finding.evidence_ids,
          remediation: finding.remediation,
          cas_version: 0,
          created_at: now,
          updated_at: now,
        };

        // Persist finding to blackboard (with assessment isolation)
        const saveRes = await this.blackboard.findings.create(findingRecord);
        if (saveRes.ok) {
          findingsCreated.push(finding);
        }
      }
    }

    // 8. Persist Structured Binary Facts to Blackboard Observations
    await this.blackboard.observations.record({
      assessment_id: this.assessmentId,
      asset_id: asset.id,
      key: "binary.metadata",
      value: {
        sha256: report.metadata.sha256,
        architecture: report.metadata.architecture,
        endianness: report.metadata.endianness,
        elfClass: report.metadata.elfClass,
        entryPoint: report.metadata.entryPoint,
        sectionsCount: report.metadata.sections.length,
        programHeadersCount: report.metadata.programHeaders.length,
        dynamicLibraries: report.metadata.dynamicLibraries,
        isExecutable: report.metadata.isExecutable,
      },
      confidence: 1.0,
      source_tool: report.provenance.provider,
      agent_id: this.worker.agentId,
      evidence_id: `ev_meta_${report.metadata.sha256.slice(0, 16)}`,
      created_at: now,
    });

    await this.blackboard.observations.record({
      assessment_id: this.assessmentId,
      asset_id: asset.id,
      key: "binary.symbols",
      value: {
        importedCount: report.metadata.importedSymbols.length,
        exportedCount: report.metadata.exportedSymbols.length,
        importedNames: report.metadata.importedSymbols.map((s) => s.name),
        exportedNames: report.metadata.exportedSymbols.map((s) => s.name),
      },
      confidence: 1.0,
      source_tool: report.provenance.provider,
      agent_id: this.worker.agentId,
      evidence_id: null,
      created_at: now,
    });

    const executionResult: BinaryAnalysisExecutionResult = {
      assetId: asset.id,
      sha256: report.metadata.sha256,
      architecture: report.metadata.architecture,
      endianness: report.metadata.endianness,
      elfClass: report.metadata.elfClass,
      functionsCount: report.functions.length,
      candidatesCount: candidates.length,
      findingsCreated: findingsCreated.length,
      findings: findingsCreated,
    };

    // Cache summary observation for idempotency
    await this.blackboard.observations.record({
      assessment_id: this.assessmentId,
      asset_id: asset.id,
      key: "binary.analysis_report",
      value: executionResult,
      confidence: 1.0,
      source_tool: report.provenance.provider,
      agent_id: this.worker.agentId,
      evidence_id: null,
      created_at: now,
    });

    return executionResult;
  }
}
