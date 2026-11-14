import { describe, expect, it } from "vitest";
import type { AssessmentId } from "../../domain/security/assessment.js";
import type { AssetId } from "../../domain/security/asset.js";
import type { BlackboardAssetRecord } from "../../domain/security/blackboard/types.js";
import type { VulnerabilityCandidate } from "../../domain/security/binary/types.js";
import { TestAdjudicationBridge } from "./testing/TestAdjudicationBridge.js";
import { WitnessValidator } from "./witness/WitnessValidator.js";
import { SandboxHarness } from "../verification/sandboxHarness.js";
import { InstructionDecoder } from "./cfg/InstructionDecoder.js";
import { ControlFlowGraphBuilder } from "./cfg/ControlFlowGraphBuilder.js";
import { TaintEngine } from "./taint/TaintEngine.js";
import type { InterproceduralCallGraph, ControlFlowGraph } from "./cfg/types.js";
import type { WitnessArtifact } from "./witness/types.js";

const section1Adjudicator = new TestAdjudicationBridge();
const section1Validator = new WitnessValidator();
const section1AssessmentId = "asm_audit_00000000000000000000000000000000000000000000000000000001" as AssessmentId;
const section1Asset: BlackboardAssetRecord = {
  id: "ast_audit_bin_00000000000000000000000000000000000000000000000000000001" as AssetId,
  assessment_id: section1AssessmentId,
  parent_asset_id: null,
  name: "audit_target",
  type: "compiled_binary",
  path: "/bin/audit_target",
  digest: { sha256: "a".repeat(64) },
  architecture: "x86_64",
  version: "1.0",
  environment: null,
  tags: ["audit"],
  metadata: {},
  created_at: Date.now(),
};

const section1BaseCandidate: VulnerabilityCandidate = {
  binaryAssetId: section1Asset.id,
  ruleId: "REA-AUDIT-001-CMD-INJECTION",
  category: "command_injection",
  name: "system() audit test",
  functionName: "target_func",
  functionAddress: "0x1000",
  sinkApi: "system",
  callAddress: "0x1020",
  callerInfo: "caller",
  sourceOfInput: "network",
  guardInfo: null,
  evidenceReferences: ["ev_audit"],
  detectionMethod: "L5_WITNESS",
  confidenceScore: 0.9,
  confidenceLimitations: [],
  cwe: ["CWE-78"],
  technicalDescription: "Audit test candidate",
  remediationGuidance: "Fix",
};

describe("Sprint 3A.2 Audit - Section 1: Vulnerability Adjudication Bypasses", () => {
  it("AUDIT-FIXED-1.1: verifiedWitness string alone cannot bypass reachability and taint requirements", () => {
    // When detectionMethod is L5_WITNESS and verifiedWitness string is passed without reachability,
    // VulnerabilityAdjudicationBridge fails closed to INCONCLUSIVE.
    const res = section1Adjudicator.adjudicateCandidate(section1AssessmentId, section1Asset, section1BaseCandidate, {
      verifiedWitness: "Arbitrary unverified witness string",
      // Reachability and taint omitted!
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(res.value.finding.confidence.verification_method).toContain(
      "Witness artifact or proof cannot establish exploitability without verified reachability",
    );
  });

  it("AUDIT-FIXED-1.2: empty bounds object {} cannot escalate THEORETICAL witness to PROVEN exploitability", () => {
    const witness: WitnessArtifact = {
      witnessId: "wit_empty_bounds",
      findingId: "fnd_001",
      ruleId: "REA-AUDIT-001",
      category: "command_injection",
      source: { api: "recv", functionName: "main", address: 0x1000 },
      sink: { api: "system", functionName: "main", address: 0x1050 },
      executionPathAddresses: [0x1000, 0x1050],
      preconditions: ["input reaches system"],
      constraints: [
        { parameter: "cmd", type: "min_length", expectedValue: 100, description: "Requires 100 bytes" },
      ],
      reproductionPayloadDescription: "Payload",
      environment: {
        architecture: "x86_64",
        endianness: "little",
        os: "linux",
        mode: "simulated_harness",
        configuration: {},
        runtimeVersion: "1.0",
      },
      artifactDigest: "0".repeat(64),
      generatedAt: new Date().toISOString(),
    };

    // Passing bounds: {} (empty bounds, no actual constraint enforcement)
    const valResult = section1Validator.validateWitness(witness, {});
    // Empty bounds must remain THEORETICAL and not reproducible!
    expect(valResult.isSatisfiable).toBe(true);
    expect(valResult.exploitabilityStatus).toBe("THEORETICAL");
    expect(valResult.isReproducible).toBe(false);
  });

  it("AUDIT-FIXED-1.3: character filter check correctly blocks multi-character sequences in character_present", () => {
    const witness: WitnessArtifact = {
      witnessId: "wit_char_filter",
      findingId: "fnd_002",
      ruleId: "REA-AUDIT-002",
      category: "path_traversal",
      source: { api: "recv", functionName: "main", address: 0x1000 },
      sink: { api: "fopen", functionName: "main", address: 0x1050 },
      executionPathAddresses: [0x1000, 0x1050],
      preconditions: ["traversal"],
      constraints: [
        // Expected value is multi-character string "../"
        { parameter: "path", type: "character_present", expectedValue: "../", description: "Directory traversal sequence" },
      ],
      reproductionPayloadDescription: "Payload",
      environment: {
        architecture: "x86_64",
        endianness: "little",
        os: "linux",
        mode: "simulated_harness",
        configuration: {},
        runtimeVersion: "1.0",
      },
      artifactDigest: "0".repeat(64),
      generatedAt: new Date().toISOString(),
    };

    // Environment blocks '/' and '.'
    const valResult = section1Validator.validateWitness(witness, {
      disallowedCharacters: [".", "/"],
    });

    // Both constituent characters and sequences are blocked!
    expect(valResult.isSatisfiable).toBe(false);
    expect(valResult.exploitabilityStatus).toBe("UNSATISFIABLE");
    expect(valResult.conflictingGuards.length).toBeGreaterThan(0);
  });
});

describe("Sprint 3A.2 Audit - Section 1: Mitigation, Evidence & Sandbox Invariants", () => {
  it("AUDIT-FIXED-1.4: MITIGATED rejected without established vulnerability and verified binary reachability", () => {
    const candidateWithGuard: VulnerabilityCandidate = {
      ...section1BaseCandidate,
      detectionMethod: "L2_HEURISTIC",
      guardInfo: {
        claimedGuard: "len < 100",
        isSound: true,
      },
    };

    // Call adjudication with NO reachability and NO taintFlow.
    // The candidate merely claims a guard `len < 100`.
    const res = section1Adjudicator.adjudicateCandidate(section1AssessmentId, section1Asset, candidateWithGuard);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    // Must NOT be marked MITIGATED without established reachability and CFG evidence!
    expect(res.value.lifecycleState).not.toBe("MITIGATED");
    expect(res.value.lifecycleState).toBe("CANDIDATE");
  });

  it("AUDIT-VERIFIED-1.5: empty witness constraints fail closed as UNSATISFIABLE", () => {
    const emptyWitness: WitnessArtifact = {
      witnessId: "wit_empty",
      findingId: "fnd_003",
      ruleId: "REA-AUDIT-003",
      category: "command_injection",
      source: { api: "recv", functionName: "main", address: 0x1000 },
      sink: { api: "system", functionName: "main", address: 0x1050 },
      executionPathAddresses: [0x1000, 0x1050],
      preconditions: [],
      constraints: [],
      reproductionPayloadDescription: "Empty witness",
      environment: {
        architecture: "x86_64",
        endianness: "little",
        os: "linux",
        mode: "simulated_harness",
        configuration: {},
        runtimeVersion: "1.0",
      },
      artifactDigest: "0".repeat(64),
      generatedAt: new Date().toISOString(),
    };

    const valResult = section1Validator.validateWitness(emptyWitness);
    expect(valResult.isSatisfiable).toBe(false);
    expect(valResult.exploitabilityStatus).toBe("UNSATISFIABLE");
  });

  it("AUDIT-FIXED-1.6: contradictory UNREACHABLE reachability with claimed witness fails closed to INCONCLUSIVE", () => {
    // If reachability is UNREACHABLE, but someone provided a verifiedWitness,
    // VulnerabilityAdjudicationBridge must fail closed to INCONCLUSIVE, not FALSE_POSITIVE.
    const res = section1Adjudicator.adjudicateCandidate(section1AssessmentId, section1Asset, section1BaseCandidate, {
      verifiedWitness: "Arbitrary verified witness",
      reachability: {
        status: "UNREACHABLE",
        paths: [],
        entryPoint: "main",
        target: "system",
        deadCodeFunctions: ["target_func"],
        reasoning: "Dead code",
        provider: "ReaControlFlowEngine",
      },
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(res.value.finding.confidence.verification_method).toContain("Contradictory analysis evidence");
  });

  it("AUDIT-VERIFIED-1.7: sandboxHarness requires expectedPattern oracle to establish VERIFIED", async () => {
    const harness = new SandboxHarness();
    const finding: any = {
      id: "fnd_0000000000000000000000000000000000000000000000000000000000000001",
      name: "test finding",
      affected_asset: {
        id: "ast_0000000000000000000000000000000000000000000000000000000000000001",
        name: "test-bin",
        type: "compiled_binary",
      },
      location: { file: null, function: null, line: null, column: null, end_line: null, module: null, component: null, address: null, offset: null },
      technical_description: "test",
      root_cause: "test",
      evidence_ids: [],
      reproduction_steps: [],
      impact: { description: "test", attack_prerequisites: [], exploitability: "THEORETICAL" },
      severity: { level: "HIGH", cvss_vector: null, cvss_score: null, justification: "test" },
      confidence: { level: "MEDIUM", false_positive_considerations: [], verification_method: null },
      remediation: { description: "test", code_diff: null, config_example: null, priority: "SHORT_TERM", validation_procedure: "test" },
      classification: { cve: [], cwe: [], capec: [], mitre_attack: [], owasp: [] },
      verification_status: "CANDIDATE",
      provenance: { discovered_by: "test", discovered_at: "", verified_by: null, verified_at: null },
    };

    const res = await harness.verifyFinding({
      finding,
      scope: {
        allowed_targets: ["*"],
        denied_targets: [],
        authorized_by: "Lead",
        authorization_reference: "REF-001",
        valid_until: "2026-12-31T23:59:59Z",
        allow_active_verification: true,
      },
      testCommand: "echo",
      testArgs: ["hello world"],
      policy: {
        commandRunner: async () => ({
          stdout: { text: "normal output\n", bytes: 14, observedBytes: 14 },
          stderr: { text: "", bytes: 0, observedBytes: 0 },
          exitCode: 0,
          signal: null,
        }),
      },
      // expectedPattern is NOT provided
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.status).toBe("UNVERIFIED");
  });
});

describe("Sprint 3A.2 Audit - Section 2: Instruction Decoding Conformance & Flaws", () => {
  const decoder = new InstructionDecoder();
  const cfgBuilder = new ControlFlowGraphBuilder();

  it("AUDIT-FIXED-2.1: x86_64 correctly parses immediate byte 0xE8 inside MOV without phantom CALL", () => {
    // Machine code for: mov $0x000000e8, %eax
    // Bytes: B8 E8 00 00 00
    // Byte 0: 0xB8 (MOV EAX, imm32)
    // Bytes 1..4: 0xE8 0x00 0x00 0x00 (immediate value 232)
    const code = new Uint8Array([0xb8, 0xe8, 0x00, 0x00, 0x00, 0xc3]);
    const insts = decoder.decode(code, 0x401000, { architecture: "x86_64" });

    // Now correctly decoded as MOV (size 5) + RET (size 1) => 2 instructions.
    expect(insts.length).toBe(2);
    expect(insts[0]!.mnemonic).toBe("mov");
    expect(insts[0]!.size).toBe(5);
    expect(insts[0]!.isCall).toBe(false);

    expect(insts[1]!.mnemonic).toBe("ret");
    expect(insts[1]!.size).toBe(1);
    expect(insts[1]!.isReturn).toBe(true);
  });

  it("AUDIT-FIXED-2.2: x86_64 ModR/M and SIB indirect call correctly calculates 3-byte size", () => {
    // ff 14 24 is: call *(%rsp)
    // 1 byte opcode (0xff) + 1 byte modrm (0x14) + 1 byte SIB (0x24) => total 3 bytes!
    const code = new Uint8Array([0xff, 0x14, 0x24, 0xc3]);
    const insts = decoder.decode(code, 0x401000, { architecture: "x86_64" });

    expect(insts.length).toBe(2);
    expect(insts[0]!.size).toBe(3);
    expect(insts[0]!.isCall).toBe(true);
    expect(insts[0]!.isIndirect).toBe(true);

    expect(insts[1]!.mnemonic).toBe("ret");
  });

  it("AUDIT-FIXED-2.3: x86_64 disp8/disp32 ModR/M indirect call correctly calculates 3-byte size", () => {
    // ff 50 10 is: call *0x10(%rax) (ModR/M with 8-bit displacement)
    // Total size: 3 bytes.
    const code = new Uint8Array([0xff, 0x50, 0x10, 0xc3]);
    const insts = decoder.decode(code, 0x401000, { architecture: "x86_64" });

    expect(insts.length).toBe(2);
    expect(insts[0]!.size).toBe(3);
    expect(insts[0]!.isCall).toBe(true);
    expect(insts[0]!.isIndirect).toBe(true);

    expect(insts[1]!.mnemonic).toBe("ret");
  });

  it("AUDIT-FIXED-2.4: x86_64 safe fallback on truncated CALL rel32", () => {
    // Truncated call rel32: 0xe8 followed by only 2 bytes instead of 4
    const truncatedCode = new Uint8Array([0xe8, 0x10, 0x20]);
    const insts = decoder.decode(truncatedCode, 0x401000, { architecture: "x86_64" });
    expect(insts[0]!.mnemonic).toBe("unsupported_instruction");
    expect(insts[0]!.isMalformed).toBe(true);
    expect(insts.some((i) => i.isCall)).toBe(false);
  });

  it("AUDIT-FIXED-2.5: ARM32 flags trailing 1-3 bytes as malformed rather than silently dropping", () => {
    // Buffer with 7 bytes: 1 valid ARM instruction (4 bytes) + 3 trailing bytes
    const code = new Uint8Array([0x0e, 0x00, 0x00, 0xeb, 0x11, 0x22, 0x33]);
    const insts = decoder.decode(code, 0x10000, { architecture: "ARM", isLittleEndian: true });

    // Count is Math.floor(7 / 4) = 1 plus 1 trailing malformed record
    expect(insts.length).toBe(2);
    expect(insts[1]!.isMalformed).toBe(true);
    expect(insts[1]!.mnemonic).toBe("malformed_unaligned");
  });

  it("AUDIT-DEFECT-2.6: MIPS branch delay slot in CFG construction with fallthrough edge", () => {
    // MIPS instructions:
    // 0x1000: beq $r1, $r2, 0x1008 (0x10220001)
    // 0x1004: nop (delay slot) (0x00000000)
    // 0x1008: jr $ra (0x03e00008)
    // 0x100c: nop (delay slot) (0x00000000)
    const buf = Buffer.alloc(16);
    buf.writeUInt32BE(0x10220001, 0); // beq target = 0x1000 + 4 + (1<<2) = 0x1008
    buf.writeUInt32BE(0x00000000, 4); // delay slot nop
    buf.writeUInt32BE(0x03e00008, 8); // jr $ra
    buf.writeUInt32BE(0x00000000, 12); // delay slot nop

    const insts = decoder.decode(buf, 0x1000, { architecture: "MIPS", isLittleEndian: false });
    expect(insts.length).toBe(4);

    const cfg = cfgBuilder.buildFunctionCfg(insts, {
      functionName: "mips_branch_func",
      entryAddress: 0x1000,
      architecture: "MIPS",
    });

    // Block 1 should contain beq AND its delay slot (nop)
    const block1 = cfg.blocks.get("bb_0x1000")!;
    expect(block1.instructions.length).toBe(2);
    expect(block1.terminatorType).toBe("conditional_branch");
  });
});

describe("Sprint 3A.2 Audit - Section 3: Taint-Analysis Independence & Adversarial Tests", () => {
  const taintEngine = new TaintEngine();

  it("AUDIT-DEFECT-3.1: call-graph connectivity labeled as PROVEN_TAINT when sensitive function receives constant", () => {
    // Adversarial scenario:
    // Call graph: main -> send_report -> system
    // main calls send_report.
    // send_report passes a hardcoded string "/usr/bin/clean_temp" to system().
    // Source is recv() in main.
    // But the argument received by system() in send_report is NOT tainted.
    const callGraph: InterproceduralCallGraph = {
      functions: ["main", "send_report"],
      edges: [
        {
          callerFunction: "main",
          callerAddress: 0x1010,
          calleeFunction: "send_report",
          calleeAddress: 0x2000,
          isIndirect: false,
        },
      ],
      entryPoints: ["main"],
    };

    const emptyCfgs: ReadonlyMap<string, ControlFlowGraph> = new Map();

    // Caller does NOT pass isConstantArgument: true (as a static analyzer analyzing instructions would have to determine)
    const res = taintEngine.analyzeTaintFlow({
      source: { kind: "network_socket", api: "recv", functionName: "main", address: 0x1000, targetParameterOrReturn: 1 },
      sink: { api: "system", functionName: "send_report", address: 0x2020, vulnerableParameterIndex: 0 },
      callGraph,
      cfgs: emptyCfgs,
      // No caller-injected isConstantArgument
    });

    // TaintEngine blindly labels this PROVEN_TAINT because a call path exists in the graph!
    expect(res.status).toBe("PROVEN_TAINT");
    // Steps contain hardcoded placeholder "arg0" with address 0!
    expect(res.steps[1]!.variableOrRegister).toBe("arg0");
    expect(res.steps[1]!.address).toBe(0);
  });

  it("AUDIT-DEFECT-3.2: cfgs parameter is completely ignored by TaintEngine", () => {
    // TaintEngine takes `cfgs: ReadonlyMap<string, ControlFlowGraph>`, but never reads from it!
    const source = { kind: "network_socket" as const, api: "recv", functionName: "main", address: 0x1000, targetParameterOrReturn: 1 };
    const sink = { api: "system", functionName: "main", address: 0x1050, vulnerableParameterIndex: 0 };
    const callGraph: InterproceduralCallGraph = { functions: ["main"], edges: [], entryPoints: ["main"] };

    // Pass completely empty cfgs map
    const resEmpty = taintEngine.analyzeTaintFlow({ source, sink, callGraph, cfgs: new Map() });

    // Now pass dummy cfgs map with arbitrary instructions
    const dummyCfgs = new Map<string, ControlFlowGraph>([
      ["main", {
        functionName: "main",
        entryBlockId: "bb_0x1000",
        blocks: new Map(),
        edges: [],
        architecture: "x86_64",
      }],
    ]);
    const resWithCfgs = taintEngine.analyzeTaintFlow({ source, sink, callGraph, cfgs: dummyCfgs });

    // Output is 100% identical because cfgs is never inspected
    expect(resEmpty.status).toBe(resWithCfgs.status);
    expect(resEmpty.reasoning).toBe(resWithCfgs.reasoning);
  });
});

