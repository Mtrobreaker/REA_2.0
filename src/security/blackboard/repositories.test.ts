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
  AgentRegistration,
  FindingRecord,
} from "../../domain/security/blackboard/types.js";

const assessmentId = "asm_repo_test_000000000000000000000000000000000000000000000000000000" as AssessmentId;
const rootAssetId = "ast_root_fw_00000000000000000000000000000000000000000000000000000000" as AssetId;
const childAssetId = "ast_child_bin_00000000000000000000000000000000000000000000000000000" as AssetId;

function createTestAssessment(): AssessmentRecord {
  return {
    id: assessmentId,
    name: "Typed Repository Test Assessment",
    status: "initialization",
    objective: {
      title: "Test Objective",
      target_technologies: ["Linux", "ARM"],
      compliance_frameworks: [],
      focus_areas: ["Kernel"],
      depth: "standard",
    },
    authorization: {
      allowed_targets: ["firmware.bin"],
      denied_targets: [],
      authorized_by: "QA Team",
      authorization_reference: "AUTH-TEST",
      valid_until: new Date(Date.now() + 86400000).toISOString(),
      allow_active_verification: true,
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
    created_at: 1000,
    updated_at: 1000,
  };
}

describe("Typed Repositories: Assessment & Asset CRUD", () => {
  let tempDir: string;
  let storage: SqliteBlackboardStorage;

  beforeEach(async () => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-repos-a-"));
    const dbPath = join(tempDir, "blackboard.db");
    const journalPath = join(tempDir, "packboard-audit.jsonl");
    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });
    await storage.assessments.create(createTestAssessment());
  });

  afterEach(() => {
    storage.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("AssessmentRepository: creates, queries, updates status, and lists assessments", async () => {
    const foundRes = await storage.assessments.findById(assessmentId);
    expect(foundRes.ok).toBe(true);
    if (!foundRes.ok) return;
    expect(foundRes.value?.name).toBe("Typed Repository Test Assessment");
    expect(foundRes.value?.status).toBe("initialization");

    const updateRes = await storage.assessments.updateStatus(assessmentId, "vulnerability_discovery", {
      total_assets: 2,
      critical_findings: 1,
    });
    expect(updateRes.ok).toBe(true);
    if (!updateRes.ok) return;
    expect(updateRes.value.status).toBe("vulnerability_discovery");
    expect(updateRes.value.metrics.total_assets).toBe(2);
    expect(updateRes.value.metrics.critical_findings).toBe(1);

    const listRes = await storage.assessments.list();
    expect(listRes.ok).toBe(true);
    if (!listRes.ok) return;
    expect(listRes.value.length).toBe(1);
    expect(listRes.value[0]?.id).toBe(assessmentId);
  });

  it("AssetRepository: creates hierarchy and queries by parent", async () => {
    const rootAsset: BlackboardAssetRecord = {
      id: rootAssetId,
      assessment_id: assessmentId,
      parent_asset_id: null,
      name: "firmware.bin",
      type: "firmware_image",
      path: "/images/firmware.bin",
      digest: { sha256: "1".repeat(64) },
      architecture: "arm",
      version: "1.0",
      environment: null,
      tags: ["root", "vendor_x"],
      metadata: { chip: "STM32F4" },
      created_at: 1000,
    };
    await storage.assets.create(rootAsset);

    const childAsset: BlackboardAssetRecord = {
      id: childAssetId,
      assessment_id: assessmentId,
      parent_asset_id: rootAssetId,
      name: "httpd",
      type: "compiled_binary",
      path: "/usr/sbin/httpd",
      digest: { sha256: "2".repeat(64) },
      architecture: "arm",
      version: "2.4",
      environment: null,
      tags: ["binary", "daemon"],
      metadata: { stripped: true },
      created_at: 2000,
    };
    await storage.assets.create(childAsset);

    const childrenRes = await storage.assets.findByParent(assessmentId, rootAssetId);
    expect(childrenRes.ok).toBe(true);
    if (!childrenRes.ok) return;
    expect(childrenRes.value.length).toBe(1);
    expect(childrenRes.value[0]?.name).toBe("httpd");

    const binaryListRes = await storage.assets.listByAssessment(assessmentId, { type: "compiled_binary" });
    expect(binaryListRes.ok).toBe(true);
    if (!binaryListRes.ok) return;
    expect(binaryListRes.value.length).toBe(1);
    expect(binaryListRes.value[0]?.id).toBe(childAssetId);
  });
});

describe("Typed Repositories: Agent Registry & Finding Transitions", () => {
  let tempDir: string;
  let storage: SqliteBlackboardStorage;

  beforeEach(async () => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-repos-b-"));
    const dbPath = join(tempDir, "blackboard.db");
    const journalPath = join(tempDir, "packboard-audit.jsonl");
    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId });
    await storage.assessments.create(createTestAssessment());
  });

  afterEach(() => {
    storage.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("AgentRegistryRepository: registers agents, updates heartbeats, and discovers active agents", async () => {
    const agent: AgentRegistration = {
      agent_id: "agent_binary_analyzer",
      assessment_id: assessmentId,
      capabilities: ["ghidra", "r2", "decompiler"],
      host_id: "worker_node_1",
      pid: 4321,
      status: "active",
      heartbeat_at: Date.now(),
      registered_at: Date.now(),
    };

    await storage.agents.register(agent);

    const getRes = await storage.agents.get(assessmentId, "agent_binary_analyzer");
    expect(getRes.ok).toBe(true);
    if (!getRes.ok) return;
    expect(getRes.value?.capabilities).toContain("ghidra");

    const newTimestamp = Date.now() + 5000;
    await storage.agents.heartbeat(assessmentId, "agent_binary_analyzer", newTimestamp);

    const updated = await storage.agents.get(assessmentId, "agent_binary_analyzer");
    expect(updated.ok).toBe(true);
    if (!updated.ok) return;
    expect(updated.value?.heartbeat_at).toBe(newTimestamp);

    const activeList = await storage.agents.listActive(assessmentId, 60000);
    expect(activeList.ok).toBe(true);
    if (!activeList.ok) return;
    expect(activeList.value.length).toBe(1);
  });

  it("FindingRepository: creates findings and enforces CAS version on state transitions", async () => {
    const findingId = "fnd_0000000000000000000000000000000000000000000000000000000000000099" as FindingId;
    const finding: FindingRecord = {
      id: findingId,
      assessment_id: assessmentId,
      fingerprint: "fp_auth_bypass_01",
      asset_id: childAssetId,
      title: "Hardcoded Admin Password",
      description: "Password found in binary string table",
      state: "CANDIDATE",
      cwe: ["CWE-798"],
      severity: { level: "CRITICAL", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss_score: 9.8, justification: "" },
      confidence: { level: "HIGH", false_positive_considerations: [], verification_method: "string_extractor" },
      location: {
        file: "auth.c",
        function: "check_password",
        line: 120,
        column: 10,
        end_line: 120,
        module: null,
        component: null,
        address: "0x00014020",
        offset: null,
      },
      evidence_ids: ["ev_hex_dump_001"],
      remediation: null,
      cas_version: 1,
      created_at: 1000,
      updated_at: 1000,
    };

    await storage.findings.create(finding);

    const fpRes = await storage.findings.getByFingerprint(assessmentId, "fp_auth_bypass_01");
    expect(fpRes.ok).toBe(true);
    if (!fpRes.ok) return;
    expect(fpRes.value?.id).toBe(findingId);

    const trans1Res = await storage.findings.transitionState(assessmentId, findingId, "INVESTIGATING", 1);
    expect(trans1Res.ok).toBe(true);
    if (!trans1Res.ok) return;
    expect(trans1Res.value.state).toBe("INVESTIGATING");
    expect(trans1Res.value.cas_version).toBe(2);

    const conflictRes = await storage.findings.transitionState(assessmentId, findingId, "VERIFIED", 1);
    expect(conflictRes.ok).toBe(false);

    const trans2Res = await storage.findings.transitionState(
      assessmentId,
      findingId,
      "VERIFIED",
      2,
      { evidence_ids: ["ev_dynamic_login_proof_002"] },
    );
    expect(trans2Res.ok).toBe(true);
    if (!trans2Res.ok) return;
    expect(trans2Res.value.state).toBe("VERIFIED");
    expect(trans2Res.value.cas_version).toBe(3);
    expect(trans2Res.value.evidence_ids).toContain("ev_hex_dump_001");
    expect(trans2Res.value.evidence_ids).toContain("ev_dynamic_login_proof_002");
  });
});
