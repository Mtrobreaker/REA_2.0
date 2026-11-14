import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { ok, err, type Result } from "../../../domain/result.js";
import type { AssessmentId } from "../../../domain/security/assessment.js";
import type { AssetId } from "../../../domain/security/asset.js";
import type {
  ICentralBlackboard,
  AssetRecord,
  ObservationRecord,
} from "../../../domain/security/blackboard/types.js";
import type { BlackboardError } from "../../../domain/security/blackboard/errors.js";
import {
  type ContextBudgetConfig,
  type TargetAssetMetadata,
  type ParentFirmwareMetadata,
  type ProjectedObservation,
  type ContextMetrics,
  type TaskContextProjection,
  type ProjectContextOptions,
  type EvidenceRecord,
  type IContextProjector,
  DEFAULT_CONTEXT_BUDGET_CONFIG,
} from "../../../domain/security/blackboard/contextProjection.js";

export interface ContextProjectorOptions {
  readonly blackboard: ICentralBlackboard;
  readonly budgetConfig?: ContextBudgetConfig | undefined;
  readonly evidenceRootDir?: string | undefined;
}

const CRITICAL_SECURITY_KEYS = new Set([
  "vulnerability",
  "cwe",
  "cve",
  "dangerous_function",
  "sink",
  "guard",
  "architecture",
  "endianness",
  "canary",
  "aslr",
  "nx",
  "pie",
  "relro",
  "format_string",
  "buffer_overflow",
  "heap_corruption",
  "rop",
  "shellcode",
]);

interface PrioritizedObservationCandidate {
  readonly observation: ProjectedObservation;
  readonly priorityScore: number;
  readonly createdAt: number;
}

export class ContextProjector implements IContextProjector {
  private readonly blackboard: ICentralBlackboard;
  private readonly budgetConfig: ContextBudgetConfig;
  private readonly evidenceRootDir?: string | undefined;

  constructor(options: ContextProjectorOptions) {
    this.blackboard = options.blackboard;
    this.budgetConfig = options.budgetConfig ?? DEFAULT_CONTEXT_BUDGET_CONFIG;
    this.evidenceRootDir = options.evidenceRootDir;
  }

  public async projectTaskContext(
    assessmentId: AssessmentId,
    taskId: string,
    options?: ProjectContextOptions,
  ): Promise<Result<TaskContextProjection, BlackboardError>> {
    try {
      // 1. Validate assessment exists
      const assessmentRes = await this.blackboard.assessments.findById(assessmentId);
      if (!assessmentRes.ok) return assessmentRes;
      if (!assessmentRes.value) {
        return err({
          code: "ASSESSMENT_NOT_FOUND",
          assessmentId,
          message: `Assessment ${assessmentId} not found`,
        });
      }

      // 2. Load Task
      const taskRes = await this.blackboard.tasks.getById(assessmentId, taskId);
      if (!taskRes.ok) return taskRes;
      if (!taskRes.value) {
        return err({
          code: "TASK_NOT_FOUND",
          taskId,
          message: `Task ${taskId} not found in assessment ${assessmentId}`,
        });
      }
      const task = taskRes.value;

      // 3. Load Target Asset
      const assetRes = await this.blackboard.assets.findById(assessmentId, task.asset_id);
      if (!assetRes.ok) return assetRes;
      if (!assetRes.value) {
        return err({
          code: "ASSET_NOT_FOUND",
          assetId: task.asset_id,
          message: `Target asset ${task.asset_id} not found for task ${taskId}`,
        });
      }
      const targetAsset = assetRes.value;

      // 4. Resolve Target Asset & Parent Firmware Metadata
      const targetAssetMeta = this.extractTargetAssetMetadata(targetAsset);
      const parentFirmwareMeta = await this.resolveParentFirmwareMetadata(assessmentId, targetAsset);

      // 5. Fetch, Prioritize, and Bounded Observations
      const prioritizedObs = await this.fetchAndPrioritizeObservations(assessmentId, targetAsset);

      // 6. Enforce Strict Serialized Byte Budget
      const budget = this.resolveBudget(options?.byteBudget);
      const projection = this.buildBoundedProjection(
        task.id,
        task.task_type,
        task.fencing_token,
        assessmentId,
        targetAssetMeta,
        parentFirmwareMeta,
        prioritizedObs,
        budget,
      );

      return ok(projection);
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "ContextProjector.projectTaskContext",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  private resolveBudget(requested?: number): number {
    if (requested === undefined || requested <= 0) {
      return this.budgetConfig.default_byte_budget;
    }
    return Math.min(requested, this.budgetConfig.max_byte_budget);
  }

  private extractTargetAssetMetadata(asset: AssetRecord): TargetAssetMetadata {
    const env = (asset.environment ?? {}) as Record<string, unknown>;
    const meta = (asset.metadata ?? {}) as Record<string, unknown>;
    const endianness =
      env.endianness === "little" || env.endianness === "big"
        ? (env.endianness as "little" | "big")
        : meta.endianness === "little" || meta.endianness === "big"
          ? (meta.endianness as "little" | "big")
          : undefined;

    return {
      asset_id: asset.id,
      name: asset.name,
      path: asset.path ?? undefined,
      file_type: asset.type,
      sha256: asset.digest?.sha256 ?? (asset as any).sha256 ?? undefined,
      architecture: asset.architecture ?? undefined,
      endianness,
    };
  }

  private async resolveParentFirmwareMetadata(
    assessmentId: AssessmentId,
    asset: AssetRecord,
  ): Promise<ParentFirmwareMetadata> {
    if (!asset.parent_asset_id) {
      const env = (asset.environment ?? {}) as Record<string, unknown>;
      const meta = (asset.metadata ?? {}) as Record<string, unknown>;
      const osFlavor =
        typeof env.os === "string"
          ? env.os
          : typeof env.os_flavor === "string"
            ? env.os_flavor
            : typeof meta.os_flavor === "string"
              ? meta.os_flavor
              : undefined;
      return {
        root_name: asset.name,
        os_flavor: osFlavor,
      };
    }

    let current = asset;
    const visited = new Set<string>([asset.id]);

    while (current.parent_asset_id) {
      if (visited.has(current.parent_asset_id)) break;
      visited.add(current.parent_asset_id);

      const parentRes = await this.blackboard.assets.findById(assessmentId, current.parent_asset_id);
      if (!parentRes.ok || !parentRes.value) break;
      current = parentRes.value;
    }

    const env = (current.environment ?? {}) as Record<string, unknown>;
    const meta = (current.metadata ?? {}) as Record<string, unknown>;
    const osFlavor =
      typeof env.os === "string"
        ? env.os
        : typeof env.os_flavor === "string"
          ? env.os_flavor
          : typeof meta.os_flavor === "string"
            ? meta.os_flavor
            : undefined;
    return {
      root_name: current.name,
      os_flavor: osFlavor,
    };
  }

  private async fetchAndPrioritizeObservations(
    assessmentId: AssessmentId,
    targetAsset: AssetRecord,
  ): Promise<ReadonlyArray<ProjectedObservation>> {
    const targetObsRes = await this.blackboard.observations.listByAsset(assessmentId, targetAsset.id);
    const targetObs = targetObsRes.ok ? targetObsRes.value : [];

    let parentObs: ReadonlyArray<ObservationRecord> = [];
    if (targetAsset.parent_asset_id && targetAsset.parent_asset_id !== targetAsset.id) {
      const pRes = await this.blackboard.observations.listByAsset(assessmentId, targetAsset.parent_asset_id);
      if (pRes.ok) parentObs = pRes.value;
    }

    const conflictsRes = await this.blackboard.observations.getConflicts(assessmentId, targetAsset.id);
    const conflictKeys = new Set((conflictsRes.ok ? conflictsRes.value : []).map((c) => c.key));

    const candidates: PrioritizedObservationCandidate[] = [];

    for (const obs of targetObs) {
      const isConflict = Boolean(obs.is_conflict || conflictKeys.has(obs.key));
      const projected: ProjectedObservation = {
        key: obs.key,
        value: obs.value,
        confidence: obs.confidence,
        source_tool: obs.source_tool,
        evidence_id: obs.evidence_id,
        is_conflict: isConflict,
      };
      candidates.push({
        observation: projected,
        priorityScore: this.calculatePriorityScore(projected, true),
        createdAt: obs.created_at,
      });
    }

    for (const obs of parentObs) {
      const isConflict = Boolean(obs.is_conflict);
      const projected: ProjectedObservation = {
        key: obs.key,
        value: obs.value,
        confidence: obs.confidence,
        source_tool: obs.source_tool,
        evidence_id: obs.evidence_id,
        is_conflict: isConflict,
      };
      candidates.push({
        observation: projected,
        priorityScore: this.calculatePriorityScore(projected, false),
        createdAt: obs.created_at,
      });
    }

    candidates.sort((a, b) => {
      if (b.priorityScore !== a.priorityScore) {
        return b.priorityScore - a.priorityScore;
      }
      return b.createdAt - a.createdAt;
    });

    return candidates.map((c) => c.observation);
  }

  private calculatePriorityScore(obs: ProjectedObservation, isTargetAsset: boolean): number {
    let score = 0;
    if (isTargetAsset) score += 1000;
    if (obs.is_conflict) score += 500;

    const lower = obs.key.toLowerCase();
    if (CRITICAL_SECURITY_KEYS.has(lower) || Array.from(CRITICAL_SECURITY_KEYS).some((k) => lower.includes(k))) {
      score += 200;
    }

    score += Math.round(obs.confidence * 100);
    return score;
  }

  private buildBoundedProjection(
    taskId: string,
    taskType: string,
    fencingToken: number,
    assessmentId: string,
    targetAsset: TargetAssetMetadata,
    parentFirmware: ParentFirmwareMetadata,
    observations: ReadonlyArray<ProjectedObservation>,
    budget: number,
  ): TaskContextProjection {
    const mandatory = {
      task_id: taskId,
      task_type: taskType,
      fencing_token: fencingToken,
      assessment_id: assessmentId,
      target_asset: targetAsset,
      parent_firmware: parentFirmware,
    };

    const totalAvailable = observations.length;
    const included: ProjectedObservation[] = [];

    // Attempt to include prioritized observations one-by-one while strictly under budget
    for (const obs of observations) {
      const nextIncluded = [...included, obs];
      const testMetrics: ContextMetrics = {
        total_available_observations: totalAvailable,
        included_observations: nextIncluded.length,
        omitted_observations: totalAvailable - nextIncluded.length,
        serialized_bytes: budget,
        estimated_tokens: Math.ceil(budget / 4),
        truncated: nextIncluded.length < totalAvailable,
      };

      const testBytes = this.measureBytesExact(mandatory, nextIncluded, testMetrics);
      if (testBytes <= budget) {
        included.push(obs);
      } else {
        // Cannot fit without exceeding budget; preserve priority invariant by stopping
        break;
      }
    }

    let finalMetrics: ContextMetrics = {
      total_available_observations: totalAvailable,
      included_observations: included.length,
      omitted_observations: totalAvailable - included.length,
      serialized_bytes: 0,
      estimated_tokens: 0,
      truncated: included.length < totalAvailable,
    };

    let finalBytes = this.measureBytesExact(mandatory, included, finalMetrics);
    finalMetrics = {
      ...finalMetrics,
      serialized_bytes: finalBytes,
      estimated_tokens: Math.ceil(finalBytes / 4),
    };

    // Guarantee that final serialized bytes does not exceed budget if observations were included
    while (included.length > 0 && this.measureBytesExact(mandatory, included, finalMetrics) > budget) {
      included.pop();
      finalMetrics = {
        total_available_observations: totalAvailable,
        included_observations: included.length,
        omitted_observations: totalAvailable - included.length,
        serialized_bytes: 0,
        estimated_tokens: 0,
        truncated: true,
      };
      finalBytes = this.measureBytesExact(mandatory, included, finalMetrics);
      finalMetrics = {
        ...finalMetrics,
        serialized_bytes: finalBytes,
        estimated_tokens: Math.ceil(finalBytes / 4),
      };
    }

    if (finalBytes > budget) {
      finalMetrics = {
        ...finalMetrics,
        truncated: true,
      };
    }

    return {
      ...mandatory,
      relevant_observations: included,
      context_metrics: finalMetrics,
    };
  }

  private measureBytesExact(
    mandatory: any,
    observations: readonly ProjectedObservation[],
    metricsBase: ContextMetrics,
  ): number {
    let currentMetrics = { ...metricsBase };
    let json = JSON.stringify({
      ...mandatory,
      relevant_observations: observations,
      context_metrics: currentMetrics,
    });
    let bytes = Buffer.byteLength(json, "utf8");

    // Converge serialized_bytes field inside the JSON payload to its own byte length
    for (let iter = 0; iter < 3; iter++) {
      currentMetrics = {
        ...currentMetrics,
        serialized_bytes: bytes,
        estimated_tokens: Math.ceil(bytes / 4),
      };
      json = JSON.stringify({
        ...mandatory,
        relevant_observations: observations,
        context_metrics: currentMetrics,
      });
      const newBytes = Buffer.byteLength(json, "utf8");
      if (newBytes === bytes) {
        break;
      }
      bytes = newBytes;
    }

    return bytes;
  }

  // ==========================================
  // Pull-on-Demand Secondary Retrieval API
  // ==========================================

  public async getAsset(
    assessmentId: AssessmentId,
    assetId: AssetId,
  ): Promise<Result<AssetRecord, BlackboardError>> {
    try {
      const res = await this.blackboard.assets.findById(assessmentId, assetId);
      if (!res.ok) return res;
      if (!res.value) {
        return err({
          code: "ASSET_NOT_FOUND",
          assetId,
          message: `Asset ${assetId} not found in assessment ${assessmentId}`,
        });
      }
      if (res.value.assessment_id !== assessmentId) {
        return err({
          code: "ASSESSMENT_ISOLATION_VIOLATION",
          expectedAssessmentId: assessmentId,
          actualAssessmentId: res.value.assessment_id,
          entityId: assetId,
          message: `Access denied: asset ${assetId} belongs to another assessment`,
        });
      }
      return ok(res.value);
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "ContextProjector.getAsset",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async getObservation(
    assessmentId: AssessmentId,
    observationId: string,
  ): Promise<Result<ObservationRecord, BlackboardError>> {
    try {
      const res = await this.blackboard.observations.findById(assessmentId, observationId);
      if (!res.ok) return res;
      if (!res.value) {
        return err({
          code: "OBSERVATION_NOT_FOUND",
          observationId,
          message: `Observation ${observationId} not found in assessment ${assessmentId}`,
        });
      }
      if (res.value.assessment_id !== assessmentId) {
        return err({
          code: "ASSESSMENT_ISOLATION_VIOLATION",
          expectedAssessmentId: assessmentId,
          actualAssessmentId: res.value.assessment_id,
          entityId: observationId,
          message: `Access denied: observation ${observationId} belongs to another assessment`,
        });
      }
      return ok(res.value);
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "ContextProjector.getObservation",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }

  public async getEvidenceRecord(
    assessmentId: AssessmentId,
    evidenceId: string,
  ): Promise<Result<EvidenceRecord, BlackboardError>> {
    try {
      // 1. Check physical persisted evidence on disk if evidenceRootDir configured
      if (this.evidenceRootDir) {
        const assessmentEvidenceDir = resolve(this.evidenceRootDir, assessmentId, "evidence");
        const prefix = evidenceId.slice(0, 2);
        const physicalPath = resolve(assessmentEvidenceDir, prefix, `${evidenceId}.json`);

        // Fail closed against directory traversal: ensure physicalPath strictly starts with assessmentEvidenceDir
        if (!physicalPath.startsWith(assessmentEvidenceDir)) {
          return err({
            code: "ASSESSMENT_ISOLATION_VIOLATION",
            expectedAssessmentId: assessmentId,
            actualAssessmentId: "external_path",
            entityId: evidenceId,
            message: `Access denied: Evidence path traversal detected for ${evidenceId}`,
          });
        }

        if (existsSync(physicalPath)) {
          const content = readFileSync(physicalPath, "utf8");
          const parsed = JSON.parse(content);
          return ok({
            evidence_id: evidenceId,
            assessment_id: assessmentId,
            sha256: parsed.sha256 ?? evidenceId,
            content_type: parsed.content_type ?? "application/json",
            payload: parsed.payload ?? parsed,
            created_at: parsed.created_at ?? Date.now(),
          });
        }
      }

      // 2. Look up observation with matching evidence_id within this assessment
      const obsRes = await this.blackboard.observations.findById(assessmentId, evidenceId);
      if (obsRes.ok && obsRes.value && obsRes.value.assessment_id === assessmentId) {
        const obs = obsRes.value;
        return ok({
          evidence_id: evidenceId,
          assessment_id: assessmentId,
          sha256: obs.evidence_id ?? evidenceId,
          content_type: "application/json",
          payload: obs.value,
          created_at: obs.created_at,
        });
      }

      // 3. Check if evidence exists in tasks evidence_hashes
      const tasksRes = await this.blackboard.tasks.listByAssessment(assessmentId);
      if (tasksRes.ok) {
        for (const t of tasksRes.value) {
          if (t.evidence_hashes && t.evidence_hashes.includes(evidenceId)) {
            return ok({
              evidence_id: evidenceId,
              assessment_id: assessmentId,
              sha256: evidenceId,
              content_type: "application/json",
              payload: { taskId: t.id, title: t.title, result: t.result },
              created_at: t.created_at,
            });
          }
        }
      }

      return err({
        code: "EVIDENCE_NOT_FOUND",
        evidenceId,
        message: `Evidence record ${evidenceId} not found in assessment ${assessmentId}`,
      });
    } catch (cause) {
      return err({
        code: "STORAGE_ERROR",
        operation: "ContextProjector.getEvidenceRecord",
        message: cause instanceof Error ? cause.message : String(cause),
        cause,
      });
    }
  }
}
