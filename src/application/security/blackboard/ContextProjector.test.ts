import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteBlackboardStorage } from "../../../security/blackboard/SqliteBlackboardStorage.js";
import { ContextProjector } from "./ContextProjector.js";
import type {
  AssessmentRecord,
  AssetRecord,
  TaskRecord,
} from "../../../domain/security/blackboard/types.js";

function setupTempDir(): string {
  return mkdtempSync(join(tmpdir(), "rea-phase3-projector-"));
}

async function seedTestAssessment(storage: SqliteBlackboardStorage, assessmentId: string) {
  const assessment: AssessmentRecord = {
    id: assessmentId as any,
    name: "Firmware Assessment Alpha",
    status: "active",
    objective: {
      title: "Analyze firmware",
      target_technologies: ["ARM", "Linux"],
      compliance_frameworks: [],
      focus_areas: ["buffer_overflow"],
      depth: "standard",
    },
    authorization: {
      allowed_targets: ["firmware.bin"],
      denied_targets: [],
      authorized_by: "sec-ops",
      authorization_reference: "AUTH-001",
      valid_until: new Date(Date.now() + 100000).toISOString(),
      allow_active_verification: false,
    },
    metrics: {
      total_assets: 2,
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
  await storage.assessments.create(assessment);

  const rootAsset: AssetRecord = {
    id: "asset-root" as any,
    assessment_id: assessmentId as any,
    parent_asset_id: null,
    name: "firmware.bin",
    type: "firmware_image",
    path: "/images/firmware.bin",
    digest: { sha256: "root-sha256-hex" },
    architecture: "ARMv7",
    version: "1.0.0",
    environment: { platform: "arm-linux", os: "OpenWrt Linux 5.4" },
    tags: ["firmware", "root"],
    metadata: { endianness: "little" },
    created_at: Date.now(),
  };
  await storage.assets.create(rootAsset);

  const binaryAsset: AssetRecord = {
    id: "asset-httpd" as any,
    assessment_id: assessmentId as any,
    parent_asset_id: "asset-root" as any,
    name: "httpd",
    type: "compiled_binary",
    path: "/bin/httpd",
    digest: { sha256: "httpd-sha256-hex" },
    architecture: "ARMv7",
    version: "1.0.0",
    environment: { platform: "arm-linux" },
    tags: ["daemon", "network"],
    metadata: { endianness: "little" },
    created_at: Date.now(),
  };
  await storage.assets.create(binaryAsset);

  const task: TaskRecord = {
    id: "task-decompile-httpd",
    assessment_id: assessmentId as any,
    task_type: "binary_analysis",
    title: "Decompile HTTP daemon",
    description: "Analyze HTTP daemon for buffer overflows",
    asset_id: "asset-httpd" as any,
    priority: "high",
    status: "open",
    blocked_by: [],
    fencing_token: 42,
    cas_version: 1,
    claim: null,
    result: null,
    metadata: {},
    evidence_hashes: ["ev-hash-httpd-1"],
    created_at: Date.now(),
    updated_at: Date.now(),
  };
  await storage.tasks.create(task);
}

describe("Phase 3: Serialized Byte-Budget Enforcement & Metrics", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentId = "assess-budget-test" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    projector = new ContextProjector({ blackboard: storage });
    await seedTestAssessment(storage, assessmentId);
  });

  afterEach(() => {
    storage.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("strictly enforces default 4096-byte budget and computes accurate truncation metrics", async () => {
    // Seed 30 observations for asset-httpd
    for (let i = 0; i < 30; i++) {
      await storage.observations.record({
        assessment_id: assessmentId,
        asset_id: "asset-httpd" as any,
        key: `vulnerability_signal_${i}`,
        value: {
          function: `parse_header_${i}`,
          detail: "Potential stack buffer overflow due to unconstrained strcpy from network socket header parameter payload",
          iteration: i,
        },
        confidence: 0.85,
        source_tool: "ghidra_decompiler",
        agent_id: "static_analyzer",
        evidence_id: `ev-obs-${i}`,
        created_at: Date.now() + i,
      });
    }

    const res = await projector.projectTaskContext(assessmentId, "task-decompile-httpd");
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const proj = res.value;
    const actualBytes = Buffer.byteLength(JSON.stringify(proj), "utf8");

    expect(actualBytes).toBeLessThanOrEqual(4096);
    expect(proj.context_metrics.serialized_bytes).toBe(actualBytes);
    expect(proj.context_metrics.total_available_observations).toBe(30);
    expect(proj.context_metrics.included_observations).toBeGreaterThan(0);
    expect(proj.context_metrics.included_observations + proj.context_metrics.omitted_observations).toBe(30);
    expect(proj.context_metrics.truncated).toBe(true);
    expect(proj.context_metrics.estimated_tokens).toBe(Math.ceil(actualBytes / 4));
  });

  it("clamps budget to configured max_byte_budget (16384 bytes) when oversized budget requested", async () => {
    const res = await projector.projectTaskContext(assessmentId, "task-decompile-httpd", {
      byteBudget: 50000, // Exceeds 16384 cap
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const actualBytes = Buffer.byteLength(JSON.stringify(res.value), "utf8");
    expect(actualBytes).toBeLessThanOrEqual(16384);
  });

  it("enforces a tight custom byte budget (e.g. 1024 bytes)", async () => {
    for (let i = 0; i < 10; i++) {
      await storage.observations.record({
        assessment_id: assessmentId,
        asset_id: "asset-httpd" as any,
        key: `obs_${i}`,
        value: { info: "payload string ".repeat(5) },
        confidence: 0.8,
        source_tool: "scanner",
        agent_id: "agent",
        evidence_id: null,
        created_at: Date.now() + i,
      });
    }

    const res = await projector.projectTaskContext(assessmentId, "task-decompile-httpd", {
      byteBudget: 1024,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const actualBytes = Buffer.byteLength(JSON.stringify(res.value), "utf8");
    expect(actualBytes).toBeLessThanOrEqual(1024);
  });

  it("T13: Context Budget & Truncation - projects context with 500 observations against 2 KB budget", async () => {
    // Insert 500 observations
    for (let i = 0; i < 500; i++) {
      await storage.observations.record({
        assessment_id: assessmentId,
        asset_id: "asset-httpd" as any,
        key: `scale_obs_${i}`,
        value: { detail: `Observation payload data item ${i}`, score: i * 0.1 },
        confidence: 0.7,
        source_tool: "bulk_scanner",
        agent_id: "crawler",
        evidence_id: `ev-${i}`,
        created_at: Date.now() + i,
      });
    }

    const res = await projector.projectTaskContext(assessmentId, "task-decompile-httpd", {
      byteBudget: 2048,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const proj = res.value;
    const actualBytes = Buffer.byteLength(JSON.stringify(proj), "utf8");

    // Pass Criteria for T13: Output strictly <= 2048 bytes; truncation metrics reported
    expect(actualBytes).toBeLessThanOrEqual(2048);
    expect(proj.context_metrics.serialized_bytes).toBe(actualBytes);
    expect(proj.context_metrics.total_available_observations).toBe(500);
    expect(proj.context_metrics.truncated).toBe(true);
    expect(proj.context_metrics.omitted_observations).toBeGreaterThan(0);
    expect(proj.context_metrics.included_observations + proj.context_metrics.omitted_observations).toBe(500);
  });
});

describe("Phase 3: Mandatory Metadata Preservation", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentId = "assess-meta-test" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    projector = new ContextProjector({ blackboard: storage });
    await seedTestAssessment(storage, assessmentId);
  });

  afterEach(() => {
    storage.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("preserves task, asset, fencing token, and parent firmware metadata even under strict budget", async () => {
    const res = await projector.projectTaskContext(assessmentId, "task-decompile-httpd", {
      byteBudget: 200, // Intentionally tight budget below full payload
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const proj = res.value;
    expect(proj.task_id).toBe("task-decompile-httpd");
    expect(proj.task_type).toBe("binary_analysis");
    expect(proj.fencing_token).toBe(42);
    expect(proj.assessment_id).toBe(assessmentId);

    // Target asset
    expect(proj.target_asset.asset_id).toBe("asset-httpd");
    expect(proj.target_asset.name).toBe("httpd");
    expect(proj.target_asset.path).toBe("/bin/httpd");
    expect(proj.target_asset.file_type).toBe("compiled_binary");
    expect(proj.target_asset.architecture).toBe("ARMv7");
    expect(proj.target_asset.endianness).toBe("little");

    // Parent firmware metadata correctly resolved
    expect(proj.parent_firmware.root_name).toBe("firmware.bin");
    expect(proj.parent_firmware.os_flavor).toBe("OpenWrt Linux 5.4");
  });
});

describe("Phase 3: Observation Prioritization & Conflict Preservation", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentId = "assess-priority-test" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    projector = new ContextProjector({ blackboard: storage });
    await seedTestAssessment(storage, assessmentId);
  });

  afterEach(() => {
    storage.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("prioritizes security-critical keys, conflicting observations, and high-confidence facts", async () => {
    // 1. Generic observation (low priority)
    await storage.observations.record({
      assessment_id: assessmentId,
      asset_id: "asset-httpd" as any,
      key: "compiler_flag_verbose",
      value: { data: "gcc options debug enabled" },
      confidence: 0.5,
      source_tool: "strings",
      agent_id: "scout",
      evidence_id: null,
      created_at: 1000,
    });

    // 2. High confidence security-critical observation (high priority)
    await storage.observations.record({
      assessment_id: assessmentId,
      asset_id: "asset-httpd" as any,
      key: "dangerous_function",
      value: { name: "strcpy", caller: "parse_cookie", offset: "0x401200" },
      confidence: 0.95,
      source_tool: "ghidra",
      agent_id: "static_analyzer",
      evidence_id: "ev-strcpy-1",
      created_at: 2000,
    });

    // 3. Conflicting architecture observations
    await storage.observations.record({
      assessment_id: assessmentId,
      asset_id: "asset-httpd" as any,
      key: "architecture",
      value: "ARMv7-A",
      confidence: 0.9,
      source_tool: "readelf",
      agent_id: "agent-1",
      evidence_id: null,
      created_at: 3000,
    });
    await storage.observations.record({
      assessment_id: assessmentId,
      asset_id: "asset-httpd" as any,
      key: "architecture",
      value: "MIPS32",
      confidence: 0.8,
      source_tool: "binwalk",
      agent_id: "agent-2",
      evidence_id: null,
      created_at: 3001,
    });

    const res = await projector.projectTaskContext(assessmentId, "task-decompile-httpd", {
      byteBudget: 1500, // Bounded budget to force prioritization
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const keys = res.value.relevant_observations.map((o) => o.key);
    // Security critical and conflicting items must be included first
    expect(keys).toContain("dangerous_function");
    expect(keys).toContain("architecture");

    // Verify conflict flag is preserved on conflicting observation
    const archObs = res.value.relevant_observations.filter((o) => o.key === "architecture");
    expect(archObs.length).toBeGreaterThan(0);
    expect(archObs.some((o) => o.is_conflict === true)).toBe(true);
  });
});

describe("Phase 3: Pull-on-Demand Retrieval & Assessment Isolation", () => {
  let tempDir: string;
  let dbPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;
  const assessmentAlpha = "assess-alpha" as any;
  const assessmentBeta = "assess-beta" as any;

  beforeEach(async () => {
    tempDir = setupTempDir();
    dbPath = join(tempDir, "blackboard.db");
    storage = new SqliteBlackboardStorage({ dbPath });
    projector = new ContextProjector({ blackboard: storage });
    await seedTestAssessment(storage, assessmentAlpha);
  });

  afterEach(() => {
    storage.close();
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("retrieves full asset and observation on demand within the authorized assessment", async () => {
    const obsRes = await storage.observations.record({
      assessment_id: assessmentAlpha,
      asset_id: "asset-httpd" as any,
      key: "canary_check",
      value: { stack_canaries_present: false },
      confidence: 0.99,
      source_tool: "checksec",
      agent_id: "hardening_checker",
      evidence_id: "ev-canary-001",
      created_at: Date.now(),
    });
    expect(obsRes.ok).toBe(true);
    if (!obsRes.ok) return;

    // Pull-on-demand Asset
    const assetRes = await projector.getAsset(assessmentAlpha, "asset-httpd" as any);
    expect(assetRes.ok).toBe(true);
    if (assetRes.ok) {
      expect(assetRes.value.name).toBe("httpd");
      expect(assetRes.value.path).toBe("/bin/httpd");
    }

    // Pull-on-demand Observation
    const pullObsRes = await projector.getObservation(assessmentAlpha, obsRes.value.id);
    expect(pullObsRes.ok).toBe(true);
    if (pullObsRes.ok) {
      expect(pullObsRes.value.key).toBe("canary_check");
      expect(pullObsRes.value.evidence_id).toBe("ev-canary-001");
    }

    // Pull-on-demand Evidence Record
    const evRes = await projector.getEvidenceRecord(assessmentAlpha, obsRes.value.id);
    expect(evRes.ok).toBe(true);
    if (evRes.ok) {
      expect(evRes.value.evidence_id).toBe(obsRes.value.id);
      expect(evRes.value.assessment_id).toBe(assessmentAlpha);
    }
  });

  it("strictly rejects cross-assessment asset or observation retrieval", async () => {
    // Attempting to pull asset-httpd using assessmentBeta
    const crossAsset = await projector.getAsset(assessmentBeta, "asset-httpd" as any);
    expect(crossAsset.ok).toBe(false);

    // Attempting to project task context across assessment boundaries fails
    const crossProj = await projector.projectTaskContext(assessmentBeta, "task-decompile-httpd");
    expect(crossProj.ok).toBe(false);
  });

  it("handles empty observations correctly without error", async () => {
    const res = await projector.projectTaskContext(assessmentAlpha, "task-decompile-httpd");
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.relevant_observations).toEqual([]);
    expect(res.value.context_metrics.total_available_observations).toBe(0);
    expect(res.value.context_metrics.included_observations).toBe(0);
    expect(res.value.context_metrics.truncated).toBe(false);
  });
});
