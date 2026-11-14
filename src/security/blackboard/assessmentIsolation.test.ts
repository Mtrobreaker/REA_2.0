import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteBlackboardStorage } from "./SqliteBlackboardStorage.js";
import type { AssessmentId } from "../../domain/security/assessment.js";
import type { AssetId } from "../../domain/security/asset.js";
import type { FindingId } from "../../domain/security/finding.js";
import type {
  AssessmentRecord,
  BlackboardAssetRecord,
  TaskRecord,
  AgentRegistration,
  FindingRecord,
} from "../../domain/security/blackboard/types.js";

const assessmentAlpha = "asm_alpha_00000000000000000000000000000000000000000000000000000000" as AssessmentId;
const assessmentBeta = "asm_beta_000000000000000000000000000000000000000000000000000000000" as AssessmentId;
const assetAlpha = "ast_alpha_00000000000000000000000000000000000000000000000000000000" as AssetId;
const assetBeta = "ast_beta_000000000000000000000000000000000000000000000000000000000" as AssetId;

function createBaseAssessment(id: AssessmentId, name: string): AssessmentRecord {
  return {
    id,
    name,
    status: "active",
    objective: {
      title: name,
      target_technologies: [],
      compliance_frameworks: [],
      focus_areas: [],
      depth: "standard",
    },
    authorization: {
      allowed_targets: ["target.bin"],
      denied_targets: [],
      authorized_by: "Security Team",
      authorization_reference: "AUTH-01",
      valid_until: new Date(Date.now() + 86400000).toISOString(),
      allow_active_verification: false,
    },
    metrics: {
      total_assets: 1,
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
}

describe("Assessment Isolation: Assets & Observations (T20)", () => {
  let tempDir: string;
  let storage: SqliteBlackboardStorage;

  beforeEach(async () => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-isolation-a-"));
    const dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    await storage.assessments.create(createBaseAssessment(assessmentAlpha, "Assessment Alpha"));
    await storage.assessments.create(createBaseAssessment(assessmentBeta, "Assessment Beta"));
  });

  afterEach(() => {
    storage.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("strictly partitions assets across assessments", async () => {
    const assetA: BlackboardAssetRecord = {
      id: assetAlpha,
      assessment_id: assessmentAlpha,
      parent_asset_id: null,
      name: "Alpha Firmware",
      type: "firmware_image",
      path: "/opt/alpha.bin",
      digest: { sha256: "a".repeat(64) },
      architecture: "arm",
      version: "1.0",
      environment: null,
      tags: ["alpha"],
      metadata: {},
      created_at: Date.now(),
    };

    const assetB: BlackboardAssetRecord = {
      id: assetBeta,
      assessment_id: assessmentBeta,
      parent_asset_id: null,
      name: "Beta Firmware",
      type: "firmware_image",
      path: "/opt/beta.bin",
      digest: { sha256: "b".repeat(64) },
      architecture: "mips",
      version: "2.0",
      environment: null,
      tags: ["beta"],
      metadata: {},
      created_at: Date.now(),
    };

    await storage.assets.create(assetA);
    await storage.assets.create(assetB);

    const getAlphaInAlpha = await storage.assets.findById(assessmentAlpha, assetAlpha);
    expect(getAlphaInAlpha.ok).toBe(true);
    if (!getAlphaInAlpha.ok) return;
    expect(getAlphaInAlpha.value?.name).toBe("Alpha Firmware");

    const getAlphaInBeta = await storage.assets.findById(assessmentBeta, assetAlpha);
    expect(getAlphaInBeta.ok).toBe(true);
    if (!getAlphaInBeta.ok) return;
    expect(getAlphaInBeta.value).toBeNull();

    const listAlpha = await storage.assets.listByAssessment(assessmentAlpha);
    expect(listAlpha.ok).toBe(true);
    if (!listAlpha.ok) return;
    expect(listAlpha.value.length).toBe(1);
    expect(listAlpha.value[0]?.id).toBe(assetAlpha);
  });

  it("strictly partitions observations across assessments", async () => {
    await storage.observations.record({
      assessment_id: assessmentAlpha,
      asset_id: assetAlpha,
      key: "architecture",
      value: "ARM",
      confidence: 0.95,
      source_tool: "file_utility",
      agent_id: "agent_alpha",
      evidence_id: null,
      created_at: Date.now(),
    });

    await storage.observations.record({
      assessment_id: assessmentBeta,
      asset_id: assetBeta,
      key: "architecture",
      value: "MIPS",
      confidence: 0.90,
      source_tool: "readelf",
      agent_id: "agent_beta",
      evidence_id: null,
      created_at: Date.now(),
    });

    const alphaObs = await storage.observations.listByAsset(assessmentAlpha, assetAlpha);
    expect(alphaObs.ok).toBe(true);
    if (!alphaObs.ok) return;
    expect(alphaObs.value.length).toBe(1);
    expect(alphaObs.value[0]?.value).toBe("ARM");

    const crossObs = await storage.observations.listByAsset(assessmentBeta, assetAlpha);
    expect(crossObs.ok).toBe(true);
    if (!crossObs.ok) return;
    expect(crossObs.value.length).toBe(0);
  });
});

describe("Assessment Isolation: Tasks, Agents & Findings (T20)", () => {
  let tempDir: string;
  let storage: SqliteBlackboardStorage;

  beforeEach(async () => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-isolation-b-"));
    const dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    await storage.assessments.create(createBaseAssessment(assessmentAlpha, "Assessment Alpha"));
    await storage.assessments.create(createBaseAssessment(assessmentBeta, "Assessment Beta"));
  });

  afterEach(() => {
    storage.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("strictly partitions tasks across assessments", async () => {
    const taskA: TaskRecord = {
      id: "task_alpha_01",
      assessment_id: assessmentAlpha,
      task_type: "decompilation",
      title: "Decompile Alpha Binary",
      description: "Analyze main entrypoint",
      asset_id: assetAlpha,
      priority: "high",
      status: "open",
      blocked_by: [],
      fencing_token: 1,
      cas_version: 1,
      claim: null,
      result: null,
      metadata: {},
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    const taskB: TaskRecord = {
      id: "task_beta_01",
      assessment_id: assessmentBeta,
      task_type: "firmware_extraction",
      title: "Extract Beta Squashfs",
      description: "Extract rootfs partition",
      asset_id: assetBeta,
      priority: "critical",
      status: "open",
      blocked_by: [],
      fencing_token: 1,
      cas_version: 1,
      claim: null,
      result: null,
      metadata: {},
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    await storage.tasks.create(taskA);
    await storage.tasks.create(taskB);

    const getBetaInAlpha = await storage.tasks.getById(assessmentAlpha, "task_beta_01");
    expect(getBetaInAlpha.ok).toBe(true);
    if (!getBetaInAlpha.ok) return;
    expect(getBetaInAlpha.value).toBeNull();

    const alphaTasks = await storage.tasks.listByAssessment(assessmentAlpha);
    expect(alphaTasks.ok).toBe(true);
    if (!alphaTasks.ok) return;
    expect(alphaTasks.value.length).toBe(1);
    expect(alphaTasks.value[0]?.id).toBe("task_alpha_01");
  });

  it("strictly partitions registered agents and findings across assessments", async () => {
    const agentA: AgentRegistration = {
      agent_id: "agent_re_01",
      assessment_id: assessmentAlpha,
      capabilities: ["ghidra", "binary_analysis"],
      host_id: "host_1",
      pid: 1234,
      status: "active",
      heartbeat_at: Date.now(),
      registered_at: Date.now(),
    };

    const agentB: AgentRegistration = {
      agent_id: "agent_fw_01",
      assessment_id: assessmentBeta,
      capabilities: ["binwalk", "firmware_extraction"],
      host_id: "host_2",
      pid: 5678,
      status: "active",
      heartbeat_at: Date.now(),
      registered_at: Date.now(),
    };

    await storage.agents.register(agentA);
    await storage.agents.register(agentB);

    const alphaAgents = await storage.agents.listActive(assessmentAlpha);
    expect(alphaAgents.ok).toBe(true);
    if (!alphaAgents.ok) return;
    expect(alphaAgents.value.length).toBe(1);
    expect(alphaAgents.value[0]?.agent_id).toBe("agent_re_01");

    const findingA: FindingRecord = {
      id: "fnd_0000000000000000000000000000000000000000000000000000000000000001" as FindingId,
      assessment_id: assessmentAlpha,
      fingerprint: "fp_alpha_01",
      asset_id: assetAlpha,
      title: "Buffer Overflow in Alpha",
      description: "Unbounded strcpy",
      state: "CANDIDATE",
      cwe: ["CWE-120"],
      severity: { level: "HIGH", cvss_vector: null, cvss_score: 7.5, justification: "" },
      confidence: { level: "MEDIUM", false_positive_considerations: [], verification_method: null },
      location: {
        file: "main.c",
        function: "parse_args",
        line: 42,
        column: 5,
        end_line: 42,
        module: null,
        component: null,
        address: null,
        offset: null,
      },
      evidence_ids: [],
      remediation: null,
      cas_version: 1,
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    await storage.findings.create(findingA);

    const getInAlpha = await storage.findings.getById(assessmentAlpha, findingA.id);
    expect(getInAlpha.ok).toBe(true);
    if (!getInAlpha.ok) return;
    expect(getInAlpha.value?.title).toBe("Buffer Overflow in Alpha");

    const getInBeta = await storage.findings.getById(assessmentBeta, findingA.id);
    expect(getInBeta.ok).toBe(true);
    if (!getInBeta.ok) return;
    expect(getInBeta.value).toBeNull();
  });
});
