import { describe, expect, it } from "vitest";
import fs from "fs";
import { InProcessInstructionDecoder } from "./InProcessInstructionDecoder.js";
import { InstructionDecoder } from "./InstructionDecoder.js";
import { CapstoneDecoderProvider } from "./CapstoneDecoderProvider.js";
import { ControlFlowGraphBuilder } from "./ControlFlowGraphBuilder.js";
import { ReachabilityAnalyzer } from "./ReachabilityAnalyzer.js";
import { TestAdjudicationBridge } from "../testing/TestAdjudicationBridge.js";
import type {
  ControlFlowGraph,
  Instruction,
  ReachabilityAnalysisResult,
  DecodeResult,
} from "./types.js";

const testAsset = {
  id: "asset_phase23",
  projectId: "proj_phase23",
  name: "firmware.bin",
  type: "BINARY",
  uri: "file:///tmp/firmware.bin",
  digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  size: 2048,
  version: "1.0",
  environment: null,
  tags: ["executable"],
  metadata: {},
  created_at: Date.now(),
} as any;

const testCandidate = {
  binaryAssetId: testAsset.id,
  ruleId: "REA-VULN-001",
  category: "unsafe_memory_operations",
  name: "Buffer Overflow",
  functionName: "target_vuln",
  functionAddress: "0x1000",
  sinkApi: "strcpy",
  callAddress: "0x1004",
  callerInfo: null,
  sourceOfInput: "network",
  guardInfo: null,
  evidenceReferences: [],
  detectionMethod: "L1_PATTERN",
  confidenceScore: 0.8,
  confidenceLimitations: [],
  cwe: ["CWE-120"],
  technicalDescription: "Candidate",
  remediationGuidance: "Fix",
} as any;

describe("Phase 2.3 - Section 1: Reproduction of Original Phase 2.1 Defects", () => {
  const decoder = new InProcessInstructionDecoder();
  const facade = new InstructionDecoder();
  const builder = new ControlFlowGraphBuilder();
  const analyzer = new ReachabilityAnalyzer();
  const bridge = new TestAdjudicationBridge();

  it("DEFECT-2.1.1: Unsupported architecture fails closed to INCONCLUSIVE (not FALSE_POSITIVE)", () => {
    const rawBytes = new Uint8Array([0x90, 0x90]);
    const decodeRes = facade.decodeSafe(rawBytes, 0x1000, { architecture: "unknown_arch" as any });
    expect(decodeRes.ok).toBe(false);

    const cfg = builder.buildFunctionCfg([], {
      functionName: "target_vuln",
      entryAddress: 0x1000,
      architecture: "unknown_arch" as any,
    });
    expect(cfg.blocks.size).toBe(0);
    expect(cfg.decodeOutcome).toBe("FAILED");
    expect(cfg.isComplete).toBe(false);

    const callGraph = builder.buildCallGraph(new Map([["target_vuln", cfg]]), new Map());
    const reachability = analyzer.analyzeReachability("target_vuln", callGraph, new Map([["target_vuln", cfg]]));
    expect(reachability.status).toBe("INCONCLUSIVE");

    const adjudicationRes = bridge.adjudicateCandidate("asmt_1" as any, testAsset, testCandidate, { reachability });
    expect(adjudicationRes.ok).toBe(true);
    if (!adjudicationRes.ok) return;
    expect(adjudicationRes.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adjudicationRes.value.finding.verification_status).toBe("INCONCLUSIVE");
  });

  it("DEFECT-2.1.2: Immediate bytes inside unhandled x86-64 opcodes halt decode without phantom branches", () => {
    // 0x25 with immediate 0xE9 (JMP-like): [0x25, 0xe9, 0x00, 0x00, 0x00, 0x90]
    const stream = new Uint8Array([0x25, 0xe9, 0x00, 0x00, 0x00, 0x90]);
    const decodeRes = decoder.decode(stream, 0x401000, { architecture: "x86_64" });
    expect(decodeRes.ok).toBe(true);
    if (!decodeRes.ok) return;

    expect(decodeRes.value.length).toBe(1);
    expect(decodeRes.value[0]!.mnemonic).toBe("unsupported_instruction");
    expect(decodeRes.value[0]!.isMalformed).toBe(true);
    expect(decodeRes.value.some((i) => i.isBranch)).toBe(false);
    expect(decodeRes.value.some((i) => i.isCall)).toBe(false);
  });

  it("DEFECT-2.1.3: Unrecognized byte sequence sets isMalformed and produces halted CFG block without fallthrough", () => {
    const endbr = new Uint8Array([0x0f, 0x1e, 0xfa]);
    const decodeRes = decoder.decode(endbr, 0x401000, { architecture: "x86_64" });
    expect(decodeRes.ok).toBe(true);
    if (!decodeRes.ok) return;

    const cfg = builder.buildFunctionCfg(decodeRes.value, {
      functionName: "endbr_fn",
      entryAddress: 0x401000,
      architecture: "x86_64",
    });
    expect(cfg.isComplete).toBe(false);
    expect(cfg.decodeOutcome).toBe("MALFORMED");
    const block = cfg.blocks.get("bb_0x401000")!;
    expect(block.terminatorType).toBe("halt");
    expect(block.successorIds.length).toBe(0);
    expect(cfg.edges.length).toBe(0);
  });

  it("DEFECT-2.1.4: Caller-supplied CapstoneDecoderProvider string is rejected as unsupported provider", () => {
    const forgedReachability: ReachabilityAnalysisResult = {
      status: "REACHABLE",
      paths: [],
      entryPoint: "main",
      target: "target_vuln",
      deadCodeFunctions: [],
      reasoning: "Claimed reachability",
      provider: "CapstoneDecoderProvider",
    };

    const adjudicationRes = bridge.adjudicateCandidate("asmt_1" as any, testAsset, testCandidate, {
      reachability: forgedReachability,
    });
    expect(adjudicationRes.ok).toBe(true);
    if (!adjudicationRes.ok) return;
    expect(adjudicationRes.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adjudicationRes.value.finding.confidence.verification_method).toContain(
      "Unsupported reachability proof provider",
    );
  });

  it("DEFECT-2.1.5: CapstoneDecoderProvider isAvailable reports operational state and decode returns UNSUPPORTED", () => {
    const capstone = new CapstoneDecoderProvider({ forceAvailable: false });
    expect(capstone.isAvailable()).toBe(false);

    const decodeRes = capstone.decode(new Uint8Array([0x90]), 0x1000, { architecture: "x86_64" });
    expect(decodeRes.ok).toBe(false);
    if (!decodeRes.ok) {
      expect(decodeRes.error.outcome).toBe("UNSUPPORTED");
      expect(decodeRes.error.message).toContain("libcapstone");
    }
  });
});

describe("Phase 2.3 - Section 2: Complete Differential Audit Metrics vs LLVM Reference", () => {
  const corpusPath = "C:/Users/acer/.gemini/antigravity/brain/a5d5c0a2-11df-475b-a7af-fd0c88384a83/scratch/differential_corpus.json";
  const decoder = new InProcessInstructionDecoder();
  const builder = new ControlFlowGraphBuilder();

  it("calculates exact instruction and byte coverage, boundary precision/recall, and CFG completeness", () => {
    const corpus = JSON.parse(fs.readFileSync(corpusPath, "utf8"));
    const metrics: any[] = [];

    for (const entry of corpus) {
      const rawBytes = Buffer.from(entry.raw_hex, "hex");
      const decodeRes = decoder.decode(rawBytes, 0, {
        architecture: entry.rea_arch,
        isThumb: entry.isThumb,
        isLittleEndian: entry.isLE,
      });

      const reaInsts = decodeRes.ok ? decodeRes.value : [];
      const llvmInsts = entry.llvm_instructions;
      const llvmMap = new Map<number, any>();
      let refBytesTotal = 0;
      for (const inst of llvmInsts) {
        llvmMap.set(inst.address, inst);
        refBytesTotal += inst.size;
      }

      let correctlyDecodedCount = 0;
      let incorrectlyDecodedCount = 0;
      let unsupportedInReaCount = 0;
      let correctlyDecodedBytes = 0;
      let matchingBoundaries = 0;
      let phantomBranches = 0;
      let phantomCalls = 0;
      let phantomReturns = 0;

      for (const inst of reaInsts) {
        const isUnsupported =
          inst.mnemonic === "unsupported_instruction" ||
          inst.mnemonic.startsWith("db") ||
          inst.isMalformed;

        if (isUnsupported) {
          unsupportedInReaCount++;
        }

        const llvm = llvmMap.get(inst.address);
        if (llvm) {
          matchingBoundaries++;
          if (!isUnsupported && inst.size === llvm.size) {
            correctlyDecodedCount++;
            correctlyDecodedBytes += inst.size;
          } else if (!isUnsupported && inst.size !== llvm.size) {
            incorrectlyDecodedCount++;
          }
        } else {
          incorrectlyDecodedCount++;
        }

        if (inst.isBranch && (!llvm || !llvm.mnemonic.match(/^(j|b|cbz|cbnz)/i))) {
          phantomBranches++;
        }
        if (inst.isCall && (!llvm || !llvm.mnemonic.match(/^(call|bl|jal)/i))) {
          phantomCalls++;
        }
        if (
          inst.isReturn &&
          (!llvm ||
            !(
              llvm.mnemonic.match(/^(ret)/i) ||
              (llvm.mnemonic.match(/^(bx|jr)/i) && (llvm.operands?.match(/(lr|\$ra)/i) ?? false)) ||
              (llvm.mnemonic.match(/^(pop)/i) && (llvm.operands?.match(/(pc)/i) ?? false))
            ))
        ) {
          phantomReturns++;
        }
      }

      const refInstructionCount = llvmInsts.length;
      const unreachedRefInstructions = Math.max(
        0,
        refInstructionCount - correctlyDecodedCount - incorrectlyDecodedCount,
      );
      const totalUnsupportedCount = unsupportedInReaCount + unreachedRefInstructions;

      const instructionCoveragePct = (correctlyDecodedCount / refInstructionCount) * 100;
      const byteCoveragePct = (correctlyDecodedBytes / refBytesTotal) * 100;
      const boundaryPrecision = (matchingBoundaries / Math.max(1, reaInsts.length)) * 100;
      const boundaryRecall = (matchingBoundaries / refInstructionCount) * 100;

      const cfg = builder.buildFunctionCfg(reaInsts, {
        functionName: entry.name,
        entryAddress: 0,
        architecture: entry.rea_arch,
      });

      metrics.push({
        name: entry.name,
        arch: entry.arch,
        opt: entry.opt,
        refInstructionCount,
        reaInstructionCount: reaInsts.length,
        correctlyDecodedCount,
        incorrectlyDecodedCount,
        unsupportedInReaCount,
        totalUnsupportedCount,
        refBytesTotal,
        correctlyDecodedBytes,
        instructionCoveragePct: `${instructionCoveragePct.toFixed(1)}%`,
        byteCoveragePct: `${byteCoveragePct.toFixed(1)}%`,
        boundaryPrecision: `${boundaryPrecision.toFixed(1)}%`,
        boundaryRecall: `${boundaryRecall.toFixed(1)}%`,
        cfgIsComplete: cfg.isComplete,
        cfgOutcome: cfg.decodeOutcome,
        phantomBranches,
        phantomCalls,
        phantomReturns,
      });
    }

    fs.writeFileSync(
      "C:/Users/acer/.gemini/antigravity/brain/a5d5c0a2-11df-475b-a7af-fd0c88384a83/scratch/phase23_detailed_metrics.json",
      JSON.stringify(metrics, null, 2),
    );

    console.log("=== PHASE 2.3 RECALCULATED DIFFERENTIAL METRICS ===");
    console.table(metrics);

    // Verify x86_64 true coverage
    const x86O0 = metrics.find((m) => m.name === "x86_64-O0");
    expect(x86O0).toBeDefined();
    expect(x86O0.refInstructionCount).toBe(93);
    expect(x86O0.correctlyDecodedCount).toBe(3); // 3 valid (push, mov, sub); 4th is unsupported_instruction
    expect(x86O0.instructionCoveragePct).toBe("3.2%");
    expect(x86O0.cfgIsComplete).toBe(false);
    expect(x86O0.phantomBranches).toBe(0);
    expect(x86O0.phantomCalls).toBe(0);

    const x86O2 = metrics.find((m) => m.name === "x86_64-O2");
    expect(x86O2).toBeDefined();
    expect(x86O2.refInstructionCount).toBe(42);
    expect(x86O2.correctlyDecodedCount).toBe(1); // 1 valid (mov); 2nd is unsupported_instruction
    expect(x86O2.instructionCoveragePct).toBe("2.4%");
    expect(x86O2.cfgIsComplete).toBe(false);
    expect(x86O2.phantomBranches).toBe(0);

    // Verify ARM32, Thumb, MIPS: 100% boundary precision and zero phantoms
    for (const m of metrics) {
      expect(m.boundaryPrecision).toBe("100.0%");
      expect(m.phantomBranches).toBe(0);
      expect(m.phantomCalls).toBe(0);
      expect(m.phantomReturns).toBe(0);
    }
  });
});

describe("Phase 2.3 - Section 3: Provider Provenance Authenticity & Trust Boundary Audit", () => {
  const bridge = new TestAdjudicationBridge();

  const provenTaint = {
    status: "PROVEN_TAINT" as const,
    sourceApi: "recv",
    sinkApi: "strcpy",
    confidence: 1.0,
    path: [],
    sanitizers: [],
    reasoning: "Direct taint propagation",
  } as any;

  const provenWitness = {
    witnessId: "wit_prov",
    isSatisfiable: true,
    exploitabilityStatus: "PROVEN" as const,
    conflictingGuards: [],
    violatesBoundaries: false,
  } as any;

  it("AUDIT-PROV-1: Demonstrates caller can forge authorized InProcessInstructionDecoder provider string", () => {
    // Caller-constructed plain JavaScript object asserting InProcessInstructionDecoder
    const forgedReachability: ReachabilityAnalysisResult = {
      status: "REACHABLE",
      paths: [
        {
          source: "main",
          target: "target_vuln",
          steps: [],
          isDefinitive: true,
          unresolvedIndirectJumps: [],
        },
      ],
      entryPoint: "main",
      target: "target_vuln",
      deadCodeFunctions: [],
      reasoning: "Forged reachability object directly injected into adjudication",
      provider: "InProcessInstructionDecoder",
      analysisOutcome: "SUCCESS",
      isComplete: true,
    };

    const res = bridge.adjudicateCandidate("asmt_prov_1" as any, testAsset, testCandidate, {
      reachability: forgedReachability,
      taintFlow: provenTaint,
      witnessValidation: provenWitness,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    // Runtime bridge accepts the string without cryptographic attestation and promotes to VERIFIED
    expect(res.value.lifecycleState).toBe("VERIFIED");
  });

  it("AUDIT-PROV-2: Demonstrates caller can forge GhidraProvider and IdaProvider provider strings", () => {
    for (const forgedProvider of ["GhidraProvider", "IdaProvider"]) {
      const forgedReachability: ReachabilityAnalysisResult = {
        status: "REACHABLE",
        paths: [],
        entryPoint: "main",
        target: "target_vuln",
        deadCodeFunctions: [],
        reasoning: `Forged ${forgedProvider} object`,
        provider: forgedProvider,
        analysisOutcome: "SUCCESS",
        isComplete: true,
      };

      const res = bridge.adjudicateCandidate("asmt_prov_2" as any, testAsset, testCandidate, {
        reachability: forgedReachability,
        taintFlow: provenTaint,
        witnessValidation: provenWitness,
      });
      expect(res.ok).toBe(true);
      if (!res.ok) return;
      expect(res.value.lifecycleState).toBe("VERIFIED");
    }
  });

  it("AUDIT-PROV-3: Proves provenance object is mutable and lacks cryptographic sealing", () => {
    const facade = new InstructionDecoder({
      providers: [
        new CapstoneDecoderProvider({ forceAvailable: false }),
        new InProcessInstructionDecoder(),
      ],
    });
    const decodeRes = facade.decodeResult(new Uint8Array([0x90]), 0x1000, {
      architecture: "x86_64",
      preferredProvider: "CapstoneDecoderProvider",
    });

    expect(decodeRes.provenance.isFallback).toBe(true);
    expect(decodeRes.provenance.actualProvider).toBe("InProcessInstructionDecoder");

    // Attempt tampering with provenance after decoding:
    const mutableProv = decodeRes.provenance as any;
    mutableProv.isFallback = false;
    mutableProv.actualProvider = "CapstoneDecoderProvider";

    expect(decodeRes.provenance.isFallback).toBe(false);
    expect(decodeRes.provenance.actualProvider).toBe("CapstoneDecoderProvider");
    // Object lacks runtime immutability (Object.isFrozen is false)
    expect(Object.isFrozen(decodeRes.provenance)).toBe(false);
  });
});

describe("Phase 2.3 - Section 4: Reachability Soundness & Indirect Control-Flow Audit", () => {
  const decoder = new InstructionDecoder();
  const builder = new ControlFlowGraphBuilder();
  const analyzer = new ReachabilityAnalyzer();
  const bridge = new TestAdjudicationBridge();

  it("SCENARIO-4.1 (Direct Call): Definitive direct call path establishes REACHABLE", () => {
    // main calls foo at 0x100a; foo calls target_vuln at 0x2000
    // main: call 0x100a (0xE8 0x05 0x00 0x00 0x00), ret (0xC3)
    const mainDecode = decoder.decodeResult(new Uint8Array([0xe8, 0x05, 0x00, 0x00, 0x00, 0xc3]), 0x1000, {
      architecture: "x86_64",
    });
    // foo: call 0x2000 (0xE8 0xf1 0x0f 0x00 0x00), ret (0xC3). Rel32 = 0x2000 - 0x100f = 0x0FF1
    const fooDecode = decoder.decodeResult(new Uint8Array([0xe8, 0xf1, 0x0f, 0x00, 0x00, 0xc3]), 0x100a, {
      architecture: "x86_64",
    });
    // target_vuln: nop (0x90), ret (0xC3)
    const vulnDecode = decoder.decodeResult(new Uint8Array([0x90, 0xc3]), 0x2000, {
      architecture: "x86_64",
    });

    const cfgs = new Map([
      ["main", builder.buildFunctionCfg(mainDecode, { functionName: "main", entryAddress: 0x1000, architecture: "x86_64" })],
      ["foo", builder.buildFunctionCfg(fooDecode, { functionName: "foo", entryAddress: 0x100a, architecture: "x86_64" })],
      ["target_vuln", builder.buildFunctionCfg(vulnDecode, { functionName: "target_vuln", entryAddress: 0x2000, architecture: "x86_64" })],
    ]);

    const knownSymbols = new Map([
      [0x100a, "foo"],
      [0x2000, "target_vuln"],
    ]);

    const callGraph = builder.buildCallGraph(cfgs, knownSymbols, ["main"]);
    const reachability = analyzer.analyzeReachability("target_vuln", callGraph, cfgs, { entryPoints: ["main"] });

    expect(reachability.status).toBe("REACHABLE");
    expect(reachability.isComplete).toBe(true);
  });

  it("SCENARIO-4.2 (Indirect Call through Function Pointer): Unresolved indirect call fails closed to INCONCLUSIVE", () => {
    // main: call rax (0xFF 0xD0), ret (0xC3) -> unresolved indirect call!
    const mainDecode = decoder.decodeResult(new Uint8Array([0xff, 0xd0, 0xc3]), 0x1000, {
      architecture: "x86_64",
    });
    // target_vuln: nop (0x90), ret (0xC3)
    const vulnDecode = decoder.decodeResult(new Uint8Array([0x90, 0xc3]), 0x2000, {
      architecture: "x86_64",
    });

    const cfgs = new Map([
      ["main", builder.buildFunctionCfg(mainDecode, { functionName: "main", entryAddress: 0x1000, architecture: "x86_64" })],
      ["target_vuln", builder.buildFunctionCfg(vulnDecode, { functionName: "target_vuln", entryAddress: 0x2000, architecture: "x86_64" })],
    ]);

    const knownSymbols = new Map([[0x2000, "target_vuln"]]);
    const callGraph = builder.buildCallGraph(cfgs, knownSymbols, ["main"]);
    const reachability = analyzer.analyzeReachability("target_vuln", callGraph, cfgs, { entryPoints: ["main"] });

    // CRITICAL SOUNDNESS INVARIANT:
    // Because main contains an unresolved indirect call, reachability CANNOT be disproven!
    expect(reachability.status).toBe("INCONCLUSIVE");
    expect(reachability.isComplete).toBe(false);
    expect(reachability.reasoning).toContain("unresolved indirect calls");

    // Adjudication must NEVER mark FALSE_POSITIVE!
    const adjudicationRes = bridge.adjudicateCandidate("asmt_ind_1" as any, testAsset, testCandidate, { reachability });
    expect(adjudicationRes.ok).toBe(true);
    if (!adjudicationRes.ok) return;
    expect(adjudicationRes.value.lifecycleState).toBe("INCONCLUSIVE");
  });

  it("SCENARIO-4.3 (Switch Jump Table / Indirect Jump): Indirect jump fails closed to INCONCLUSIVE", () => {
    // main: jmp rax (0xFF 0xE0) -> indirect jump!
    const mainDecode = decoder.decodeResult(new Uint8Array([0xff, 0xe0]), 0x1000, {
      architecture: "x86_64",
    });
    const vulnDecode = decoder.decodeResult(new Uint8Array([0x90, 0xc3]), 0x2000, {
      architecture: "x86_64",
    });

    const cfgs = new Map([
      ["main", builder.buildFunctionCfg(mainDecode, { functionName: "main", entryAddress: 0x1000, architecture: "x86_64" })],
      ["target_vuln", builder.buildFunctionCfg(vulnDecode, { functionName: "target_vuln", entryAddress: 0x2000, architecture: "x86_64" })],
    ]);

    const callGraph = builder.buildCallGraph(cfgs, new Map([[0x2000, "target_vuln"]]), ["main"]);
    const reachability = analyzer.analyzeReachability("target_vuln", callGraph, cfgs, { entryPoints: ["main"] });

    expect(reachability.status).toBe("INCONCLUSIVE");
    expect(reachability.isComplete).toBe(false);

    const adjudicationRes = bridge.adjudicateCandidate("asmt_jmp_1" as any, testAsset, testCandidate, { reachability });
    expect(adjudicationRes.ok).toBe(true);
    if (!adjudicationRes.ok) return;
    expect(adjudicationRes.value.lifecycleState).toBe("INCONCLUSIVE");
  });

  it("SCENARIO-4.4 (Cross-Function Branch / Tail Call): Tail call is recognized as interprocedural edge", () => {
    // main: jmp 0x2000 (cross-function tail call to target_vuln at 0x2000)
    // 0xE9 0xfb 0x0f 0x00 0x00 (rel32 = 0x2000 - 0x1005 = 0x0FFB)
    const mainDecode = decoder.decodeResult(new Uint8Array([0xe9, 0xfb, 0x0f, 0x00, 0x00]), 0x1000, {
      architecture: "x86_64",
    });
    const vulnDecode = decoder.decodeResult(new Uint8Array([0x90, 0xc3]), 0x2000, {
      architecture: "x86_64",
    });

    const cfgs = new Map([
      ["main", builder.buildFunctionCfg(mainDecode, { functionName: "main", entryAddress: 0x1000, architecture: "x86_64" })],
      ["target_vuln", builder.buildFunctionCfg(vulnDecode, { functionName: "target_vuln", entryAddress: 0x2000, architecture: "x86_64" })],
    ]);

    const knownSymbols = new Map([[0x2000, "target_vuln"]]);
    const callGraph = builder.buildCallGraph(cfgs, knownSymbols, ["main"]);
    const reachability = analyzer.analyzeReachability("target_vuln", callGraph, cfgs, { entryPoints: ["main"] });

    // Tail call must be traversed as reaching!
    expect(reachability.status).toBe("REACHABLE");
    expect(reachability.isComplete).toBe(true);
  });

  it("SCENARIO-4.5 (Recursive Calls): Handles recursive cycles without infinite recursion", () => {
    // foo calls bar, bar calls foo
    const fooDecode = decoder.decodeResult(new Uint8Array([0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3]), 0x1000, {
      architecture: "x86_64",
    });
    const barDecode = decoder.decodeResult(new Uint8Array([0xe8, 0xe0, 0xff, 0xff, 0xff, 0xc3]), 0x1010, {
      architecture: "x86_64",
    });
    const uncalledDecode = decoder.decodeResult(new Uint8Array([0x90, 0xc3]), 0x3000, {
      architecture: "x86_64",
    });

    const cfgs = new Map([
      ["foo", builder.buildFunctionCfg(fooDecode, { functionName: "foo", entryAddress: 0x1000, architecture: "x86_64" })],
      ["bar", builder.buildFunctionCfg(barDecode, { functionName: "bar", entryAddress: 0x1010, architecture: "x86_64" })],
      ["uncalled", builder.buildFunctionCfg(uncalledDecode, { functionName: "uncalled", entryAddress: 0x3000, architecture: "x86_64" })],
    ]);

    const knownSymbols = new Map([
      [0x1010, "bar"],
      [0x1000, "foo"],
      [0x3000, "uncalled"],
    ]);

    const callGraph = builder.buildCallGraph(cfgs, knownSymbols, ["foo"]);
    const reachability = analyzer.analyzeReachability("uncalled", callGraph, cfgs, { entryPoints: ["foo"] });

    expect(reachability.status).toBe("UNREACHABLE");
    expect(reachability.isComplete).toBe(true);
  });

  it("SCENARIO-4.6 (External API Sink): External API sink without CFG is recognized via call graph", () => {
    // main calls system at 0x401050 (external PLT stub / imported API)
    const mainDecode = decoder.decodeResult(new Uint8Array([0xe8, 0x4b, 0x00, 0x00, 0x00, 0xc3]), 0x1000, {
      architecture: "x86_64",
    });

    const cfgs = new Map([
      ["main", builder.buildFunctionCfg(mainDecode, { functionName: "main", entryAddress: 0x1000, architecture: "x86_64" })],
    ]);

    const knownSymbols = new Map([[0x1050, "system"]]);
    const callGraph = builder.buildCallGraph(cfgs, knownSymbols, ["main"]);
    const reachability = analyzer.analyzeReachability("system", callGraph, cfgs, { entryPoints: ["main"] });

    expect(reachability.status).toBe("REACHABLE");
    expect(reachability.isComplete).toBe(true);
  });

  it("SCENARIO-4.7 (Missing Entry Points): Empty entry points fails closed to INCONCLUSIVE", () => {
    const mainDecode = decoder.decodeResult(new Uint8Array([0x90, 0xc3]), 0x1000, { architecture: "x86_64" });
    const cfgs = new Map([
      ["main", builder.buildFunctionCfg(mainDecode, { functionName: "main", entryAddress: 0x1000, architecture: "x86_64" })],
    ]);

    const callGraph = builder.buildCallGraph(cfgs, new Map(), []);
    const reachability = analyzer.analyzeReachability("main", callGraph, cfgs, { entryPoints: [] });

    expect(reachability.status).toBe("INCONCLUSIVE");
    expect(reachability.isComplete).toBe(false);
  });
});

describe("Phase 2.3 - Section 5: CFG Completeness Propagation Audit", () => {
  const decoder = new InstructionDecoder();
  const builder = new ControlFlowGraphBuilder();
  const analyzer = new ReachabilityAnalyzer();
  const bridge = new TestAdjudicationBridge();

  it("AUDIT-PROP-1: Decoder outcome PARTIAL propagates to CFG, reachability, and adjudication", () => {
    // Valid NOP followed by unhandled opcode 0x25
    const partialStream = new Uint8Array([0x90, 0x25, 0xe9, 0x00, 0x00, 0x00]);
    const decodeRes = decoder.decodeResult(partialStream, 0x1000, { architecture: "x86_64" });
    expect(decodeRes.outcome).toBe("PARTIAL");

    const cfg = builder.buildFunctionCfg(decodeRes, {
      functionName: "fn_partial",
      entryAddress: 0x1000,
      architecture: "x86_64",
    });
    expect(cfg.decodeOutcome).toBe("PARTIAL");
    expect(cfg.isComplete).toBe(false);

    const callGraph = builder.buildCallGraph(new Map([["fn_partial", cfg]]), new Map());
    const reachability = analyzer.analyzeReachability("fn_partial", callGraph, new Map([["fn_partial", cfg]]));
    expect(reachability.analysisOutcome).toBe("PARTIAL");
    expect(reachability.isComplete).toBe(false);
    expect(reachability.status).toBe("INCONCLUSIVE");

    const adjudicationRes = bridge.adjudicateCandidate("asmt_prop_1" as any, testAsset, testCandidate, { reachability });
    expect(adjudicationRes.ok).toBe(true);
    if (!adjudicationRes.ok) return;
    expect(adjudicationRes.value.lifecycleState).toBe("INCONCLUSIVE");
  });

  it("AUDIT-PROP-2: Halted CFG blocks are prevented from emitting call graph edges", () => {
    // Unsupported instruction 0x25 followed by immediate byte 0xE8 (CALL-like)
    const stream = new Uint8Array([0x25, 0xe8, 0x00, 0x00, 0x00, 0x90]);
    const decodeRes = decoder.decodeResult(stream, 0x1000, { architecture: "x86_64" });
    const cfg = builder.buildFunctionCfg(decodeRes, {
      functionName: "halted_fn",
      entryAddress: 0x1000,
      architecture: "x86_64",
    });

    const callGraph = builder.buildCallGraph(new Map([["halted_fn", cfg]]), new Map());
    expect(callGraph.edges.length).toBe(0);
  });
});

describe("Phase 2.3 - Section 6: Authoritative Adjudication Invariants (8-State Matrix)", () => {
  const bridge = new TestAdjudicationBridge();

  const provenTaint = {
    status: "PROVEN_TAINT" as const,
    sourceApi: "recv",
    sinkApi: "strcpy",
    confidence: 1.0,
    path: [],
    sanitizers: [],
    reasoning: "Direct taint propagation",
  } as any;

  const noTaint = {
    status: "NO_TAINT" as const,
    sourceApi: "recv",
    sinkApi: "strcpy",
    confidence: 1.0,
    path: [],
    sanitizers: [],
    reasoning: "No taint reaches sink",
  } as any;

  const provenWitness = {
    witnessId: "wit_prov",
    isSatisfiable: true,
    exploitabilityStatus: "PROVEN" as const,
    conflictingGuards: [],
    violatesBoundaries: false,
  } as any;

  const unsatisfiableWitness = {
    witnessId: "wit_unsat",
    isSatisfiable: false,
    exploitabilityStatus: "UNSATISFIABLE" as const,
    conflictingGuards: ["buf_len <= 10"],
    violatesBoundaries: false,
  } as any;

  const completeReachable: ReachabilityAnalysisResult = {
    status: "REACHABLE",
    paths: [{ source: "main", target: "target_vuln", steps: [], isDefinitive: true, unresolvedIndirectJumps: [] }],
    entryPoint: "main",
    target: "target_vuln",
    deadCodeFunctions: [],
    reasoning: "Definitive call chain",
    provider: "ReaControlFlowEngine",
    analysisOutcome: "SUCCESS",
    isComplete: true,
  };

  const completeUnreachable: ReachabilityAnalysisResult = {
    status: "UNREACHABLE",
    paths: [],
    entryPoint: "main",
    target: "target_vuln",
    deadCodeFunctions: ["target_vuln"],
    reasoning: "Dead code in complete graph",
    provider: "ReaControlFlowEngine",
    analysisOutcome: "SUCCESS",
    isComplete: true,
  };

  const incompleteReachability: ReachabilityAnalysisResult = {
    status: "INCONCLUSIVE",
    paths: [],
    entryPoint: "main",
    target: "target_vuln",
    deadCodeFunctions: [],
    reasoning: "Incomplete graph with unhandled opcodes",
    provider: "ReaControlFlowEngine",
    analysisOutcome: "PARTIAL",
    isComplete: false,
  };

  it("Matrix Case 1: REACHABLE + PROVEN_TAINT + PROVEN witness -> VERIFIED", () => {
    const res = bridge.adjudicateCandidate("asmt_m1" as any, testAsset, testCandidate, {
      reachability: completeReachable,
      taintFlow: provenTaint,
      witnessValidation: provenWitness,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.lifecycleState).toBe("VERIFIED");
  });

  it("Matrix Case 2: REACHABLE + PROVEN_TAINT + UNSATISFIABLE witness -> INCONCLUSIVE (contradiction)", () => {
    const res = bridge.adjudicateCandidate("asmt_m2" as any, testAsset, testCandidate, {
      reachability: completeReachable,
      taintFlow: provenTaint,
      witnessValidation: unsatisfiableWitness,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.lifecycleState).toBe("INCONCLUSIVE");
  });

  it("Matrix Case 3: REACHABLE + NO_TAINT + PROVEN witness -> INCONCLUSIVE (contradiction)", () => {
    const res = bridge.adjudicateCandidate("asmt_m3" as any, testAsset, testCandidate, {
      reachability: completeReachable,
      taintFlow: noTaint,
      witnessValidation: provenWitness,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.lifecycleState).toBe("INCONCLUSIVE");
  });

  it("Matrix Case 4: REACHABLE + NO_TAINT + UNSATISFIABLE witness -> FALSE_POSITIVE", () => {
    const res = bridge.adjudicateCandidate("asmt_m4" as any, testAsset, testCandidate, {
      reachability: completeReachable,
      taintFlow: noTaint,
      witnessValidation: unsatisfiableWitness,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.lifecycleState).toBe("FALSE_POSITIVE");
  });

  it("Matrix Case 5: UNREACHABLE + PROVEN_TAINT + PROVEN witness -> INCONCLUSIVE (contradiction)", () => {
    const res = bridge.adjudicateCandidate("asmt_m5" as any, testAsset, testCandidate, {
      reachability: completeUnreachable,
      taintFlow: provenTaint,
      witnessValidation: provenWitness,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.lifecycleState).toBe("INCONCLUSIVE");
  });

  it("Matrix Case 6: UNREACHABLE + PROVEN_TAINT + UNSATISFIABLE witness -> INCONCLUSIVE (contradiction)", () => {
    const res = bridge.adjudicateCandidate("asmt_m6" as any, testAsset, testCandidate, {
      reachability: completeUnreachable,
      taintFlow: provenTaint,
      witnessValidation: unsatisfiableWitness,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.lifecycleState).toBe("INCONCLUSIVE");
  });

  it("Matrix Case 7: UNREACHABLE + NO_TAINT + UNSATISFIABLE witness -> FALSE_POSITIVE", () => {
    const res = bridge.adjudicateCandidate("asmt_m7" as any, testAsset, testCandidate, {
      reachability: completeUnreachable,
      taintFlow: noTaint,
      witnessValidation: unsatisfiableWitness,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.lifecycleState).toBe("FALSE_POSITIVE");
  });

  it("Matrix Case 8: INCONCLUSIVE reachability + PROVEN_TAINT + PROVEN witness -> INCONCLUSIVE", () => {
    const res = bridge.adjudicateCandidate("asmt_m8" as any, testAsset, testCandidate, {
      reachability: incompleteReachability,
      taintFlow: provenTaint,
      witnessValidation: provenWitness,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.lifecycleState).toBe("INCONCLUSIVE");
  });
});

