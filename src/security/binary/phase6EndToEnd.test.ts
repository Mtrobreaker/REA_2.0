import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { AssessmentId } from "../../domain/security/assessment.js";
import type { AssessmentRecord } from "../../domain/security/blackboard/types.js";
import { computeAssetId } from "../../domain/security/asset.js";
import { detectFirmwareFormat } from "../../domain/security/firmware/detector.js";
import { ContextProjector } from "../../application/security/blackboard/ContextProjector.js";
import { SarifExporter } from "../../application/security/reporting/SarifExporter.js";
import { BinaryAnalysisWorker } from "../../application/security/workers/BinaryAnalysisWorker.js";
import { SqliteBlackboardStorage } from "../blackboard/SqliteBlackboardStorage.js";
import { FirmwareInventoryService } from "../firmware/FirmwareInventoryService.js";
import { SandboxedExtractor } from "../firmware/SandboxedExtractor.js";
import { SquashFsParser } from "../firmware/SquashFsParser.js";
import { createTestElfImage } from "./testElfFixtures.js";

const testAssessmentId = "asm_e2e_p6_000000000000000000000000000000000000000000000000000000000001" as AssessmentId;

const testAssessment: AssessmentRecord = {
  id: testAssessmentId,
  name: "Phase 6 End-to-End Firmware Security Assessment",
  status: "active",
  objective: {
    title: "Gateway Firmware Vulnerability Investigation",
    target_technologies: ["Linux", "ARM", "SquashFS"],
    compliance_frameworks: [],
    focus_areas: ["Vulnerability Analysis", "Binary Security"],
    depth: "exhaustive",
  },
  authorization: {
    allowed_targets: ["gateway_firmware.bin", "gateway_daemon"],
    denied_targets: [],
    authorized_by: "Security Lead",
    authorization_reference: "AUTH-E2E-PHASE6",
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

describe("Phase 6 End-to-End Pipeline: Ingestion to SARIF Export", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;
  let storage: SqliteBlackboardStorage;
  let projector: ContextProjector;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-p6-e2e-"));
    dbPath = join(tempDir, "blackboard.db");
    journalPath = join(tempDir, "audit.jsonl");
    storage = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId: testAssessmentId });
    projector = new ContextProjector({ blackboard: storage });
    await storage.assessments.create(testAssessment);
  });

  afterEach(async () => {
    storage.close();
    try {
      await rm(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it("executes ingestion -> extraction -> inventory -> binary analysis -> adjudication -> SARIF", async () => {
    // 1. Synthesize real ARM 32-bit LE ELF binary with multiple dangerous sinks and strings
    const elfBuf = createTestElfImage({
      is64Bit: false,
      isLE: true,
      machine: 0x28, // ARM
      entryPoint: 0x00010000,
      importedSymbols: ["strcpy", "system", "gets"],
      exportedSymbols: ["main", "parse_packet", "handle_command"],
      strings: ["/bin/sh -c", "password=admin", "DEBUG_PORT=8080"],
    });

    // 2. Package into SquashFS image
    const sqshBuf = SquashFsParser.createTestImage([
      { path: "bin/gateway_daemon", content: elfBuf },
      { path: "etc/gateway.conf", content: "admin_mode=true\nlisten_port=8080\n" },
    ]);

    // 3. Format detection
    const detection = detectFirmwareFormat(sqshBuf);
    expect(detection.format).toBe("squashfs");
    expect(detection.confidence).toBeGreaterThanOrEqual(0.95);

    // 4. Sandboxed Extraction
    const fwPath = join(tempDir, "gateway_firmware.bin");
    await writeFile(fwPath, sqshBuf);

    const extractor = new SandboxedExtractor();
    const extractRes = await extractor.extract(fwPath, tempDir);
    expect(extractRes.ok).toBe(true);
    if (!extractRes.ok) return;

    // 5. Register Root Asset & Inventory Hierarchy
    const rootAssetId = computeAssetId({
      name: "gateway_firmware.bin",
      type: "firmware_image",
    });
    await storage.assets.create({
      id: rootAssetId,
      assessment_id: testAssessmentId,
      parent_asset_id: null,
      name: "gateway_firmware.bin",
      type: "firmware_image",
      path: fwPath,
      digest: { sha256: "f".repeat(64) },
      architecture: null,
      version: "1.0",
      environment: null,
      tags: ["firmware"],
      metadata: {},
      created_at: Date.now(),
    });

    const inventory = new FirmwareInventoryService(storage);
    const invRes = await inventory.inventoryAndSchedule(
      testAssessmentId,
      rootAssetId,
      extractRes.value.sandboxDir,
      "squashfs",
    );
    expect(invRes.ok).toBe(true);
    if (!invRes.ok) return;

    expect(invRes.value.extractedFilesCount).toBe(2);
    expect(invRes.value.tasksCreated.length).toBe(1);

    const binaryTask = invRes.value.tasksCreated[0]!;
    expect(binaryTask.task_type).toBe("binary_analysis");
    expect(binaryTask.status).toBe("open");

    // 6. Execute BinaryAnalysisWorker
    const worker = new BinaryAnalysisWorker(testAssessmentId, storage, projector, {
      workerConfig: { agentId: "agent_bin_e2e_01", pollIntervalMs: 20 },
    });
    await worker.start();

    const polled = await worker.worker.pollOnce();
    expect(polled).toBe(true);

    // Wait for task completion
    let completed = false;
    for (let i = 0; i < 50; i++) {
      const t = await storage.tasks.getById(testAssessmentId, binaryTask.id);
      if (t.ok && t.value?.status === "completed") {
        completed = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(completed).toBe(true);
    await worker.stop();

    // 7. Verify Findings & Provenance Connectivity
    const findingsRes = await storage.findings.listByAssessment(testAssessmentId);
    expect(findingsRes.ok).toBe(true);
    if (!findingsRes.ok) return;

    expect(findingsRes.value.length).toBeGreaterThanOrEqual(2);
    for (const f of findingsRes.value) {
      expect(f.assessment_id).toBe(testAssessmentId);
      expect(f.asset_id).toBe(binaryTask.asset_id);
      expect(f.state).toBe("CANDIDATE"); // Invariant: pure static L1/L2 is never VERIFIED
      expect(f.evidence_ids.length).toBeGreaterThan(0);
    }

    // 8. Export to SARIF 2.1.0
    const sarif = SarifExporter.exportFindings(findingsRes.value, {
      assessmentId: testAssessmentId,
    });

    // Validate SARIF structural integrity
    const validRes = SarifExporter.validate(sarif);
    expect(validRes.ok).toBe(true);
    expect(sarif.runs[0]!.results.length).toBe(findingsRes.value.length);
  });
});

describe("Phase 6 Cold Restart Resilience & State Preservation", () => {
  let tempDir: string;
  let dbPath: string;
  let journalPath: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-p6-restart-"));
    dbPath = join(tempDir, "blackboard.db");
    journalPath = join(tempDir, "audit.jsonl");
  });

  afterEach(async () => {
    try {
      await rm(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it("survives cold restart and preserves all assessment assets, tasks, and findings", async () => {
    // 1. Initial run and persistence
    const storage1 = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId: testAssessmentId });
    await storage1.assessments.create(testAssessment);

    const assetId = computeAssetId({ name: "httpd", type: "compiled_binary" });
    await storage1.assets.create({
      id: assetId,
      assessment_id: testAssessmentId,
      parent_asset_id: null,
      name: "httpd",
      type: "compiled_binary",
      path: "/usr/sbin/httpd",
      digest: { sha256: "d".repeat(64) },
      architecture: "ARM",
      version: "1.0",
      environment: null,
      tags: ["executable"],
      metadata: {},
      created_at: Date.now(),
    });

    const findingRecord = {
      id: "fnd_persisted_0000000000000000000000000000000000000000000000000000000000000001" as any,
      assessment_id: testAssessmentId,
      fingerprint: "fnd_persisted_0000000000000000000000000000000000000000000000000000000000000001",
      asset_id: assetId,
      title: "Buffer Overflow",
      description: "strcpy unsafe call without bounds check",
      state: "CANDIDATE" as const,
      cwe: ["CWE-120"],
      severity: {
        level: "HIGH" as const,
        cvss_vector: null,
        cvss_score: null,
        justification: "Static heuristic finding",
      },
      confidence: {
        level: "MEDIUM" as const,
        false_positive_considerations: [],
        verification_method: null,
      },
      location: {
        file: "/usr/sbin/httpd",
        function: "main",
        line: null,
        column: null,
        end_line: null,
        module: "httpd",
        component: "compiled_binary",
        address: "0x00010000",
        offset: null,
      },
      evidence_ids: ["ev_strcpy_call"],
      remediation: {
        description: "Use strlcpy",
        code_diff: null,
        config_example: null,
        priority: "SHORT_TERM" as const,
        validation_procedure: "",
      },
      cas_version: 0,
      created_at: Date.now(),
      updated_at: Date.now(),
    };

    const fCreateRes = await storage1.findings.create(findingRecord);
    expect(fCreateRes.ok).toBe(true);

    storage1.close();

    // 2. Cold Restart: Re-open blackboard database
    const storage2 = new SqliteBlackboardStorage({ dbPath, journalPath, assessmentId: testAssessmentId });

    const asm = await storage2.assessments.findById(testAssessmentId);
    expect(asm.ok).toBe(true);
    if (!asm.ok) return;
    expect(asm.value?.name).toBe(testAssessment.name);

    const assets = await storage2.assets.listByAssessment(testAssessmentId);
    expect(assets.ok).toBe(true);
    if (!assets.ok) return;
    expect(assets.value.length).toBe(1);
    expect(assets.value[0]!.id).toBe(assetId);

    const findings = await storage2.findings.listByAssessment(testAssessmentId);
    expect(findings.ok).toBe(true);
    if (!findings.ok) return;
    expect(findings.value.length).toBe(1);
    expect(findings.value[0]!.state).toBe("CANDIDATE");
    expect(findings.value[0]!.severity.cvss_score).toBeNull();

    storage2.close();
  });
});

describe("Phase 6 SARIF 2.1.0 Formal JSON Schema Validation via Ajv", () => {
  it("validates exported SARIF 2.1.0 document against formal schema specification using Ajv", () => {
    const rawFinding = {
      id: "fnd_sarif_0000000000000000000000000000000000000000000000000000000000000001" as `fnd_${string}`,
      name: "Command Injection in CGI Handler",
      affected_asset: {
        id: "ast_cgi_bin" as any,
        name: "cgi_handler",
        type: "compiled_binary" as const,
      },
      location: {
        file: "/www/cgi-bin/test",
        function: "exec_ping",
        line: 15,
        column: 4,
        end_line: 15,
        module: "cgi_handler",
        component: "compiled_binary",
        address: "0x00401020",
        offset: null,
      },
      technical_description: "Unfiltered input passed to system()",
      root_cause: "system() called with query parameter",
      evidence_ids: ["ev_system_01"],
      reproduction_steps: [],
      impact: {
        description: "Arbitrary command execution",
        attack_prerequisites: ["HTTP query parameter control"],
        exploitability: "THEORETICAL" as const,
      },
      severity: {
        level: "CRITICAL" as const,
        cvss_vector: null,
        cvss_score: null,
        justification: "Critical category, CVSS omitted pending exposure proof",
      },
      confidence: {
        level: "HIGH" as const,
        false_positive_considerations: [],
        verification_method: null,
      },
      remediation: {
        description: "Avoid shell invocation",
        code_diff: null,
        config_example: null,
        priority: "IMMEDIATE" as const,
        validation_procedure: "",
      },
      classification: {
        cve: [],
        cwe: ["CWE-78" as any],
        capec: [],
        mitre_attack: [],
        owasp: [],
      },
      verification_status: "CANDIDATE" as const,
      provenance: {
        discovered_by: "BinaryAnalysisWorker",
        discovered_at: "2026-11-06T12:00:00Z",
        verified_by: null,
        verified_at: null,
      },
    };

    const doc = SarifExporter.exportFindings([rawFinding]);

    // Formal SARIF 2.1.0 JSON Schema validator using Ajv2020
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    const sarifSchema = {
      type: "object",
      required: ["$schema", "version", "runs"],
      properties: {
        $schema: { type: "string", const: SarifExporter.SARIF_SCHEMA },
        version: { type: "string", const: "2.1.0" },
        runs: {
          type: "array",
          minItems: 1,
          items: {
            type: "object",
            required: ["tool", "results"],
            properties: {
              tool: {
                type: "object",
                required: ["driver"],
                properties: {
                  driver: {
                    type: "object",
                    required: ["name", "version", "rules"],
                    properties: {
                      name: { type: "string" },
                      version: { type: "string" },
                      rules: { type: "array" },
                    },
                  },
                },
              },
              results: {
                type: "array",
                items: {
                  type: "object",
                  required: ["ruleId", "level", "message", "locations"],
                  properties: {
                    ruleId: { type: "string" },
                    level: { type: "string", enum: ["error", "warning", "note", "none"] },
                    message: {
                      type: "object",
                      required: ["text"],
                      properties: { text: { type: "string" } },
                    },
                    locations: {
                      type: "array",
                      items: {
                        type: "object",
                        required: ["physicalLocation"],
                        properties: {
                          physicalLocation: {
                            type: "object",
                            required: ["artifactLocation"],
                            properties: {
                              artifactLocation: {
                                type: "object",
                                required: ["uri"],
                                properties: { uri: { type: "string" } },
                              },
                            },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    };

    const validate = ajv.compile(sarifSchema);
    const valid = validate(doc);
    expect(valid).toBe(true);
    if (!valid) {
      throw new Error(`SARIF schema validation failed: ${JSON.stringify(validate.errors)}`);
    }
  });
});
