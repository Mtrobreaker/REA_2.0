import { describe, expect, it } from "vitest";
import { ControlFlowGraphBuilder } from "./ControlFlowGraphBuilder.js";
import { InstructionDecoder } from "./InstructionDecoder.js";
import { InProcessInstructionDecoder } from "./InProcessInstructionDecoder.js";
import { CapstoneDecoderProvider } from "./CapstoneDecoderProvider.js";
import { ReachabilityAnalyzer } from "./ReachabilityAnalyzer.js";
import { TestAdjudicationBridge } from "../testing/TestAdjudicationBridge.js";
import type { Instruction, ReachabilityAnalysisResult } from "./types.js";
import {
  POSITIVE_FIXTURES,
  NEGATIVE_FIXTURES,
} from "./fixtures/instructionFixtures.js";

describe("Phase 7A: Multi-Architecture Instruction Decoding", () => {
  const decoder = new InstructionDecoder();

  it("decodes ARM32 branch, call, and return instructions accurately", () => {
    // 0x10000: B 0x10010 (offset +8 from PC+8 => +8 bytes => 0x10000 + 8 + 8 = 0x10018)
    // 0x10004: BL 0x10020
    // 0x10008: BX LR (0xe12fff1e)
    // 0x1000c: BLX R3 (0xe12fff33)
    const buf = Buffer.alloc(16);
    // B: 0xEA000002 (offset = 2 words = +8 bytes)
    buf.writeUInt32LE(0xea000002, 0);
    // BL: 0xEB000005 (offset = 5 words = +20 bytes)
    buf.writeUInt32LE(0xeb000005, 4);
    // BX LR: 0xE12FFF1E
    buf.writeUInt32LE(0xe12fff1e, 8);
    // BLX R3: 0xE12FFF33
    buf.writeUInt32LE(0xe12fff33, 12);

    const insts = decoder.decode(buf, 0x10000, { architecture: "ARM", isLittleEndian: true });
    expect(insts.length).toBe(4);

    expect(insts[0]!.isBranch).toBe(true);
    expect(insts[0]!.isCall).toBe(false);
    expect(insts[0]!.targetAddress).toBe(0x10000 + 8 + (2 << 2));

    expect(insts[1]!.isCall).toBe(true);
    expect(insts[1]!.targetAddress).toBe(0x10004 + 8 + (5 << 2));

    expect(insts[2]!.isReturn).toBe(true);
    expect(insts[2]!.mnemonic).toBe("bx lr");

    expect(insts[3]!.isCall).toBe(true);
    expect(insts[3]!.isIndirect).toBe(true);
  });

  it("decodes MIPS32 jumps, branch conditions, and return instructions", () => {
    const buf = Buffer.alloc(16);
    // J 0x00400100 (target index = 0x00100040)
    buf.writeUInt32BE(0x08100040, 0);
    // JAL 0x00400200
    buf.writeUInt32BE(0x0c100080, 4);
    // BEQ $r1, $r2, +4 words (0x10220004)
    buf.writeUInt32BE(0x10220004, 8);
    // JR $ra (0x03E00008)
    buf.writeUInt32BE(0x03e00008, 12);

    const insts = decoder.decode(buf, 0x00400000, { architecture: "MIPS", isLittleEndian: false });
    expect(insts.length).toBe(4);

    expect(insts[0]!.mnemonic).toBe("j");
    expect(insts[0]!.isBranch).toBe(true);

    expect(insts[1]!.mnemonic).toBe("jal");
    expect(insts[1]!.isCall).toBe(true);

    expect(insts[2]!.mnemonic).toBe("beq");
    expect(insts[2]!.isConditional).toBe(true);

    expect(insts[3]!.mnemonic).toBe("jr $ra");
    expect(insts[3]!.isReturn).toBe(true);
  });

  it("decodes x86_64 call, jmp, and ret instructions with variable lengths", () => {
    // 0xE8 0x10 0x00 0x00 0x00 (call +16)
    // 0xEB 0x05 (jmp short +5)
    // 0xC3 (ret)
    const buf = Buffer.from([0xe8, 0x10, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xc3]);
    const insts = decoder.decode(buf, 0x401000, { architecture: "x86_64" });
    expect(insts.length).toBe(3);

    expect(insts[0]!.mnemonic).toBe("call");
    expect(insts[0]!.size).toBe(5);
    expect(insts[0]!.targetAddress).toBe(0x401000 + 5 + 0x10);

    expect(insts[1]!.mnemonic).toBe("jmp");
    expect(insts[1]!.size).toBe(2);
    expect(insts[1]!.targetAddress).toBe(0x401005 + 2 + 5);

    expect(insts[2]!.mnemonic).toBe("ret");
    expect(insts[2]!.isReturn).toBe(true);
  });
});

describe("Phase 7A: CFG Construction & Inter-procedural Reachability", () => {
  const builder = new ControlFlowGraphBuilder();
  const analyzer = new ReachabilityAnalyzer();

  it("constructs intra-procedural CFG with leaders, conditional edges, and successors", () => {
    // Synthetic function with if-else branch:
    // 0x1000: cmp r0, #0
    // 0x1004: beq 0x1010
    // 0x1008: mov r1, #1
    // 0x100c: b 0x1014
    // 0x1010: mov r1, #2 (target of beq)
    // 0x1014: bx lr (join point & return)
    const instructions: Instruction[] = [
      { address: 0x1000, mnemonic: "cmp", operands: "r0, #0", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
      { address: 0x1004, mnemonic: "beq", operands: "0x1010", size: 4, rawBytes: new Uint8Array(4), isBranch: true, isConditional: true, isCall: false, isReturn: false, isIndirect: false, targetAddress: 0x1010 },
      { address: 0x1008, mnemonic: "mov", operands: "r1, #1", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
      { address: 0x100c, mnemonic: "b", operands: "0x1014", size: 4, rawBytes: new Uint8Array(4), isBranch: true, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: 0x1014 },
      { address: 0x1010, mnemonic: "mov", operands: "r1, #2", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
      { address: 0x1014, mnemonic: "bx lr", operands: "lr", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: true, isIndirect: false, targetAddress: null },
    ];

    const cfg = builder.buildFunctionCfg(instructions, {
      functionName: "parse_packet",
      entryAddress: 0x1000,
      architecture: "ARM",
    });

    expect(cfg.blocks.size).toBe(4);
    expect(cfg.entryBlockId).toBe("bb_0x1000");

    const entryBlock = cfg.blocks.get("bb_0x1000")!;
    expect(entryBlock.terminatorType).toBe("conditional_branch");
    expect(entryBlock.successorIds).toContain("bb_0x1010"); // true branch
    expect(entryBlock.successorIds).toContain("bb_0x1008"); // false branch
  });

  it("proves reachability from entry point to vulnerable sink via call chain", () => {
    // main -> handle_request -> exec_ping -> system
    const mainCfg = builder.buildFunctionCfg([
      { address: 0x1000, mnemonic: "bl", operands: "0x2000", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: true, isReturn: false, isIndirect: false, targetAddress: 0x2000 },
      { address: 0x1004, mnemonic: "bx lr", operands: "lr", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: true, isIndirect: false, targetAddress: null },
    ], { functionName: "main", entryAddress: 0x1000, architecture: "ARM" });

    const handleCfg = builder.buildFunctionCfg([
      { address: 0x2000, mnemonic: "bl", operands: "0x3000", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: true, isReturn: false, isIndirect: false, targetAddress: 0x3000 },
      { address: 0x2004, mnemonic: "bx lr", operands: "lr", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: true, isIndirect: false, targetAddress: null },
    ], { functionName: "handle_request", entryAddress: 0x2000, architecture: "ARM" });

    const pingCfg = builder.buildFunctionCfg([
      { address: 0x3000, mnemonic: "bl", operands: "0x4000", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: true, isReturn: false, isIndirect: false, targetAddress: 0x4000 },
      { address: 0x3004, mnemonic: "bx lr", operands: "lr", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: true, isIndirect: false, targetAddress: null },
    ], { functionName: "exec_ping", entryAddress: 0x3000, architecture: "ARM" });

    const functions = new Map([
      ["main", mainCfg],
      ["handle_request", handleCfg],
      ["exec_ping", pingCfg],
    ]);

    const symbols = new Map([
      [0x2000, "handle_request"],
      [0x3000, "exec_ping"],
      [0x4000, "system"],
    ]);

    const callGraph = builder.buildCallGraph(functions, symbols, ["main"]);
    const res = analyzer.analyzeReachability("system", callGraph, functions);

    expect(res.status).toBe("REACHABLE");
    expect(res.paths.length).toBe(1);
    expect(res.paths[0]!.isDefinitive).toBe(true);
    expect(res.paths[0]!.steps.length).toBe(4); // main -> handle_request -> exec_ping -> system
  });

  it("marks uncalled dead code functions as UNREACHABLE", () => {
    const mainCfg = builder.buildFunctionCfg([
      { address: 0x1000, mnemonic: "bx lr", operands: "lr", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: true, isIndirect: false, targetAddress: null },
    ], { functionName: "main", entryAddress: 0x1000, architecture: "ARM" });

    const deadCfg = builder.buildFunctionCfg([
      { address: 0x9000, mnemonic: "bl", operands: "0x4000", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: true, isReturn: false, isIndirect: false, targetAddress: 0x4000 },
      { address: 0x9004, mnemonic: "bx lr", operands: "lr", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: true, isIndirect: false, targetAddress: null },
    ], { functionName: "dead_handler", entryAddress: 0x9000, architecture: "ARM" });

    const functions = new Map([
      ["main", mainCfg],
      ["dead_handler", deadCfg],
    ]);

    const symbols = new Map([[0x4000, "system"]]);
    const callGraph = builder.buildCallGraph(functions, symbols, ["main"]);
    const res = analyzer.analyzeReachability("system", callGraph, functions);

    expect(res.status).toBe("UNREACHABLE");
    expect(res.deadCodeFunctions).toContain("dead_handler");
  });

  it("evaluates to INCONCLUSIVE when call path traverses an unresolved indirect branch", () => {
    // main -> dispatcher (indirect call via register) -> unknown
    const mainCfg = builder.buildFunctionCfg([
      { address: 0x1000, mnemonic: "bl", operands: "0x2000", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: true, isReturn: false, isIndirect: false, targetAddress: 0x2000 },
    ], { functionName: "main", entryAddress: 0x1000, architecture: "ARM" });

    const dispatchCfg = builder.buildFunctionCfg([
      { address: 0x2000, mnemonic: "blx", operands: "r3", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: true, isReturn: false, isIndirect: true, targetAddress: null },
    ], { functionName: "dispatcher", entryAddress: 0x2000, architecture: "ARM" });

    const functions = new Map([
      ["main", mainCfg],
      ["dispatcher", dispatchCfg],
    ]);

    const symbols = new Map([[0x2000, "dispatcher"]]);
    const callGraph = builder.buildCallGraph(functions, symbols, ["main"]);
    const res = analyzer.analyzeReachability("unknown_indirect", callGraph, functions);

    expect(res.status).toBe("INCONCLUSIVE");
    expect(res.paths[0]!.isDefinitive).toBe(false);
    expect(res.paths[0]!.unresolvedIndirectJumps.length).toBeGreaterThan(0);
  });
});

describe("Phase 7A: MIPS Branch Delay Slot CFG Semantics", () => {
  const builder = new ControlFlowGraphBuilder();

  it("includes delay slot in unconditional jump block and avoids phantom fallthrough", () => {
    // 0x1000: j 0x1010
    // 0x1004: addiu $v0, $v0, 1  (delay slot, executed before jump)
    // 0x1008: nop (not reached from jump)
    // 0x1010: jr $ra (target of jump)
    // 0x1014: nop (delay slot of return)
    const instructions: Instruction[] = [
      { address: 0x1000, mnemonic: "j", operands: "0x1010", size: 4, rawBytes: new Uint8Array(4), isBranch: true, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: 0x1010 },
      { address: 0x1004, mnemonic: "addiu", operands: "$v0, $v0, 1", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
      { address: 0x1008, mnemonic: "nop", operands: "", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
      { address: 0x1010, mnemonic: "jr $ra", operands: "$ra", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: true, isIndirect: false, targetAddress: null },
      { address: 0x1014, mnemonic: "nop", operands: "", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
    ];

    const cfg = builder.buildFunctionCfg(instructions, {
      functionName: "mips_jump_test",
      entryAddress: 0x1000,
      architecture: "MIPS",
    });

    // Block 1 should start at 0x1000 and contain BOTH j and its delay slot (0x1004)
    const entryBlock = cfg.blocks.get("bb_0x1000");
    expect(entryBlock).toBeDefined();
    if (!entryBlock) return;

    expect(entryBlock.instructions.length).toBe(2);
    expect(entryBlock.instructions[0]!.mnemonic).toBe("j");
    expect(entryBlock.instructions[1]!.mnemonic).toBe("addiu");
    expect(entryBlock.terminatorType).toBe("branch");

    // Successor should be ONLY target 0x1010 (no phantom fallthrough to 0x1008)
    expect(entryBlock.successorIds).toEqual(["bb_0x1010"]);
  });

  it("correctly branches and falls through past delay slot on conditional branch", () => {
    // 0x2000: beq $a0, $zero, 0x2010
    // 0x2004: addiu $v0, $zero, 0 (delay slot, executes regardless of branch outcome)
    // 0x2008: addiu $v0, $zero, 1 (false fallthrough branch at i+2)
    // 0x200c: jr $ra
    // 0x2010: jr $ra (true branch target)
    // 0x2014: nop (delay slot)
    const instructions: Instruction[] = [
      { address: 0x2000, mnemonic: "beq", operands: "$a0, $zero, 0x2010", size: 4, rawBytes: new Uint8Array(4), isBranch: true, isConditional: true, isCall: false, isReturn: false, isIndirect: false, targetAddress: 0x2010 },
      { address: 0x2004, mnemonic: "addiu", operands: "$v0, $zero, 0", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
      { address: 0x2008, mnemonic: "addiu", operands: "$v0, $zero, 1", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
      { address: 0x200c, mnemonic: "jr $ra", operands: "$ra", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: true, isIndirect: false, targetAddress: null },
      { address: 0x2010, mnemonic: "jr $ra", operands: "$ra", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: true, isIndirect: false, targetAddress: null },
      { address: 0x2014, mnemonic: "nop", operands: "", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
    ];

    const cfg = builder.buildFunctionCfg(instructions, {
      functionName: "mips_beq_test",
      entryAddress: 0x2000,
      architecture: "MIPS",
    });

    const branchBlock = cfg.blocks.get("bb_0x2000")!;
    expect(branchBlock.instructions.length).toBe(2);
    expect(branchBlock.instructions[1]!.address).toBe(0x2004); // Delay slot included
    expect(branchBlock.terminatorType).toBe("conditional_branch");

    // True branch goes to 0x2010, false branch falls through to 0x2008 (past delay slot)
    expect(branchBlock.successorIds).toContain("bb_0x2010");
    expect(branchBlock.successorIds).toContain("bb_0x2008");
  });

  it("includes delay slot in call (jal) and return (jr $ra) blocks", () => {
    // 0x3000: jal 0x4000
    // 0x3004: move $a0, $s0 (delay slot sets argument)
    // 0x3008: jr $ra
    // 0x300c: nop (delay slot)
    const instructions: Instruction[] = [
      { address: 0x3000, mnemonic: "jal", operands: "0x4000", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: true, isReturn: false, isIndirect: false, targetAddress: 0x4000 },
      { address: 0x3004, mnemonic: "move", operands: "$a0, $s0", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
      { address: 0x3008, mnemonic: "jr $ra", operands: "$ra", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: true, isIndirect: false, targetAddress: null },
      { address: 0x300c, mnemonic: "nop", operands: "", size: 4, rawBytes: new Uint8Array(4), isBranch: false, isConditional: false, isCall: false, isReturn: false, isIndirect: false, targetAddress: null },
    ];

    const cfg = builder.buildFunctionCfg(instructions, {
      functionName: "mips_call_ret_test",
      entryAddress: 0x3000,
      architecture: "MIPS",
    });

    const callBlock = cfg.blocks.get("bb_0x3000")!;
    expect(callBlock.instructions.length).toBe(2);
    expect(callBlock.terminatorType).toBe("call");
    expect(callBlock.successorIds).toEqual(["bb_0x3008"]); // Resumes after delay slot

    const retBlock = cfg.blocks.get("bb_0x3008")!;
    expect(retBlock.instructions.length).toBe(2);
    expect(retBlock.terminatorType).toBe("return");
    expect(retBlock.successorIds.length).toBe(0);
  });
});

describe("Phase 2: Decoder Provider Abstraction & Capstone Evaluation", () => {
  const capstone = new CapstoneDecoderProvider();
  const inProcess = new InProcessInstructionDecoder();
  const universal = new InstructionDecoder();

  it("evaluates Capstone provider contracts and architecture support", () => {
    expect(capstone.name).toBe("CapstoneDecoderProvider");
    expect(capstone.supportedArchitectures).toContain("x86_64");
    expect(capstone.supportedArchitectures).toContain("ARM");
    expect(capstone.supportedArchitectures).toContain("MIPS");
    // Standard environment without python-capstone reports clean availability status
    expect(typeof capstone.isAvailable()).toBe("boolean");
    expect(typeof capstone.getAvailabilityReason()).toBe("string");
  });

  it("evaluates InProcessInstructionDecoder conforming provider contracts", () => {
    expect(inProcess.name).toBe("InProcessInstructionDecoder");
    expect(inProcess.canDecode({ architecture: "x86_64" })).toBe(true);
    expect(inProcess.canDecode({ architecture: "ARM" })).toBe(true);
    expect(inProcess.canDecode({ architecture: "MIPS" })).toBe(true);
    expect(inProcess.canDecode({ architecture: "unknown" })).toBe(false);
  });

  it("dispatches transparently through universal decoder facade with fail-closed safety", () => {
    const providers = universal.getProviders();
    expect(providers.length).toBe(2);
    expect(providers[0]!.name).toBe("CapstoneDecoderProvider");
    expect(providers[1]!.name).toBe("InProcessInstructionDecoder");

    // Unsupported architecture fails closed to empty array via decode()
    const emptyInsts = universal.decode(new Uint8Array([0x90]), 0x1000, { architecture: "unknown" });
    expect(emptyInsts).toEqual([]);

    // Unsupported architecture returns explicit InstructionDecodeError via decodeSafe()
    const safeRes = universal.decodeSafe(new Uint8Array([0x90]), 0x1000, { architecture: "unknown" });
    expect(safeRes.ok).toBe(false);
    if (safeRes.ok) return;
    expect(safeRes.error.message).toContain("Unsupported architecture");
  });
});

describe("Phase 2: x86-64 Prefixes, ModR/M, SIB, and Displacement Handling", () => {
  const decoder = new InProcessInstructionDecoder();

  it("decodes 32-bit conditional branch (0x0F 0x84 JE rel32) with correct 6-byte boundary", () => {
    const vec = POSITIVE_FIXTURES.find((f) => f.name.includes("0x0F 0x84"))!;
    const res = decoder.decode(vec.bytes, vec.baseAddress, { architecture: vec.architecture });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.length).toBe(vec.expectedInstructionCount);
    const inst = res.value[0]!;
    expect(inst.mnemonic).toBe(vec.expectedFirstMnemonic);
    expect(inst.size).toBe(vec.expectedFirstSize);
    expect(inst.targetAddress).toBe(vec.expectedTargetAddress);
    expect(inst.isBranch).toBe(true);
    expect(inst.isConditional).toBe(true);
  });

  it("prevents false branch detection when 0xE9 appears inside immediate value (MOV EAX, 0x0000E990)", () => {
    const vec = POSITIVE_FIXTURES.find((f) => f.name.includes("MOV EAX, 0x0000E990"))!;
    const res = decoder.decode(vec.bytes, vec.baseAddress, { architecture: vec.architecture });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.length).toBe(2);
    const inst0 = res.value[0]!;
    expect(inst0.mnemonic).toBe("mov");
    expect(inst0.size).toBe(5);
    expect(inst0.isBranch).toBe(false);
    expect(inst0.targetAddress).toBeNull();

    const inst1 = res.value[1]!;
    expect(inst1.mnemonic).toBe("ret");
    expect(inst1.size).toBe(1);
    expect(inst1.isReturn).toBe(true);
  });

  it("decodes REX.W prefixed RIP-relative displacement (MOV RAX, [RIP + 0x20])", () => {
    const vec = POSITIVE_FIXTURES.find((f) => f.name.includes("REX.W prefixed RIP-relative"))!;
    const res = decoder.decode(vec.bytes, vec.baseAddress, { architecture: vec.architecture });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.length).toBe(1);
    const inst = res.value[0]!;
    expect(inst.mnemonic).toBe("mov");
    expect(inst.size).toBe(7);
    expect(inst.operands).toContain("[rip +");
    expect(inst.prefixes).toContain("rex.w");
  });

  it("decodes SIB addressing with scale, index, and base (MOV RDX, [RDI + RSI*4 + 0x10])", () => {
    const vec = POSITIVE_FIXTURES.find((f) => f.name.includes("SIB addressing"))!;
    const res = decoder.decode(vec.bytes, vec.baseAddress, { architecture: vec.architecture });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.length).toBe(1);
    const inst = res.value[0]!;
    expect(inst.mnemonic).toBe("mov");
    expect(inst.size).toBe(5);
    expect(inst.operands).toContain("*4");
  });

  it("decodes indirect call via ModR/M RIP-relative with computed target", () => {
    const vec = POSITIVE_FIXTURES.find((f) => f.name.includes("Indirect call via ModR/M"))!;
    const res = decoder.decode(vec.bytes, vec.baseAddress, { architecture: vec.architecture });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.length).toBe(1);
    const inst = res.value[0]!;
    expect(inst.isCall).toBe(true);
    expect(inst.isIndirect).toBe(true);
    expect(inst.targetAddress).toBe(0x402006);
  });
});

describe("Phase 2: ARM32, Thumb-2, and MIPS32 Reference Vector Parity", () => {
  const decoder = new InProcessInstructionDecoder();

  it("decodes ARM32 condition codes and stack return instructions", () => {
    const armBne = POSITIVE_FIXTURES.find((f) => f.name.includes("ARM32: Conditional branch BNE"))!;
    const resBne = decoder.decode(armBne.bytes, armBne.baseAddress, { architecture: armBne.architecture, isLittleEndian: true });
    expect(resBne.ok).toBe(true);
    if (!resBne.ok) return;
    expect(resBne.value[0]!.mnemonic).toBe("bne");
    expect(resBne.value[0]!.isConditional).toBe(true);
    expect(resBne.value[0]!.targetAddress).toBe(armBne.expectedTargetAddress);

    const armPop = POSITIVE_FIXTURES.find((f) => f.name.includes("ARM32: Return via stack POP"))!;
    const resPop = decoder.decode(armPop.bytes, armPop.baseAddress, { architecture: armPop.architecture, isLittleEndian: true });
    expect(resPop.ok).toBe(true);
    if (!resPop.ok) return;
    expect(resPop.value[0]!.mnemonic).toBe("pop {..., pc}");
    expect(resPop.value[0]!.isReturn).toBe(true);
  });

  it("decodes 32-bit Thumb-2 BL and 16-bit Thumb CBZ instructions", () => {
    const t2Bl = POSITIVE_FIXTURES.find((f) => f.name.includes("Thumb-2: 32-bit branch with link BL"))!;
    const resBl = decoder.decode(t2Bl.bytes, t2Bl.baseAddress, { architecture: "ARM", isThumb: true, isLittleEndian: true });
    expect(resBl.ok).toBe(true);
    if (!resBl.ok) return;
    expect(resBl.value[0]!.mnemonic).toBe("bl");
    expect(resBl.value[0]!.size).toBe(4);
    expect(resBl.value[0]!.isCall).toBe(true);
    expect(resBl.value[0]!.targetAddress).toBe(t2Bl.expectedTargetAddress);

    const tCbz = POSITIVE_FIXTURES.find((f) => f.name.includes("Thumb: 16-bit CBZ"))!;
    const resCbz = decoder.decode(tCbz.bytes, tCbz.baseAddress, { architecture: "ARM", isThumb: true, isLittleEndian: true });
    expect(resCbz.ok).toBe(true);
    if (!resCbz.ok) return;
    expect(resCbz.value[0]!.mnemonic).toBe("cbz");
    expect(resCbz.value[0]!.size).toBe(2);
    expect(resCbz.value[0]!.isBranch).toBe(true);
    expect(resCbz.value[0]!.isConditional).toBe(true);
    expect(resCbz.value[0]!.targetAddress).toBe(tCbz.expectedTargetAddress);
  });

  it("decodes MIPS32 Big-Endian and Little-Endian jumps and delay slots", () => {
    const mipsBe = POSITIVE_FIXTURES.find((f) => f.name.includes("MIPS32: JAL call with NOP"))!;
    const resBe = decoder.decode(mipsBe.bytes, mipsBe.baseAddress, { architecture: "MIPS", isLittleEndian: false });
    expect(resBe.ok).toBe(true);
    if (!resBe.ok) return;
    expect(resBe.value.length).toBe(2);
    expect(resBe.value[0]!.mnemonic).toBe("jal");
    expect(resBe.value[0]!.hasDelaySlot).toBe(true);
    expect(resBe.value[0]!.targetAddress).toBe(mipsBe.expectedTargetAddress);

    const mipsLe = POSITIVE_FIXTURES.find((f) => f.name.includes("MIPS32: JR $ra return"))!;
    const resLe = decoder.decode(mipsLe.bytes, mipsLe.baseAddress, { architecture: "MIPS", isLittleEndian: true });
    expect(resLe.ok).toBe(true);
    if (!resLe.ok) return;
    expect(resLe.value.length).toBe(2);
    expect(resLe.value[0]!.mnemonic).toBe("jr $ra");
    expect(resLe.value[0]!.isReturn).toBe(true);
    expect(resLe.value[0]!.hasDelaySlot).toBe(true);
  });
});

describe("Phase 2: Negative Fixtures & Fail-Closed Malformed Input Handling", () => {
  const decoder = new InProcessInstructionDecoder();
  const builder = new ControlFlowGraphBuilder();

  it("fails closed on truncated x86-64 prefix without opcode", () => {
    const fix = NEGATIVE_FIXTURES.find((f) => f.name.includes("Incomplete trailing REX prefix"))!;
    const res = decoder.decode(fix.bytes, fix.baseAddress, { architecture: fix.architecture });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value[0]!.isMalformed).toBe(true);
  });

  it("fails closed on truncated x86-64 SIB displacement", () => {
    const fix = NEGATIVE_FIXTURES.find((f) => f.name.includes("Truncated SIB displacement"))!;
    const res = decoder.decode(fix.bytes, fix.baseAddress, { architecture: fix.architecture });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    // SIB displacement truncated -> falls back to single raw bytes without hallucinating branch
    expect(res.value.some((i) => i.isBranch)).toBe(false);
  });

  it("fails closed on unaligned ARM32 stream and truncated Thumb-2 instruction", () => {
    const armFix = NEGATIVE_FIXTURES.find((f) => f.name.includes("ARM32: Truncated 3-byte"))!;
    const armRes = decoder.decode(armFix.bytes, armFix.baseAddress, { architecture: "ARM", isThumb: false });
    expect(armRes.ok).toBe(true);
    if (!armRes.ok) return;
    expect(armRes.value.some((i) => i.isMalformed)).toBe(true);

    const thumbFix = NEGATIVE_FIXTURES.find((f) => f.name.includes("Thumb-2: Truncated 32-bit"))!;
    const thumbRes = decoder.decode(thumbFix.bytes, thumbFix.baseAddress, { architecture: "ARM", isThumb: true });
    expect(thumbRes.ok).toBe(true);
    if (!thumbRes.ok) return;
    expect(thumbRes.value.some((i) => i.isMalformed)).toBe(true);
  });

  it("fails closed with explicit error on unsupported architecture", () => {
    const fix = NEGATIVE_FIXTURES.find((f) => f.name.includes("Unsupported architecture"))!;
    const res = decoder.decode(fix.bytes, fix.baseAddress, { architecture: fix.architecture });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error.message).toContain("Unsupported architecture");
  });

  it("halts CFG construction when a MIPS branch lacks its delay slot instruction", () => {
    // JAL at end of stream without delay slot
    const fix = NEGATIVE_FIXTURES.find((f) => f.name.includes("MIPS32: Truncated delay slot"))!;
    const res = decoder.decode(fix.bytes, fix.baseAddress, { architecture: "MIPS", isLittleEndian: false });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.length).toBe(1);

    const cfg = builder.buildFunctionCfg(res.value, {
      functionName: "mips_truncated_branch",
      entryAddress: fix.baseAddress,
      architecture: "MIPS",
    });

    const entryBlock = cfg.blocks.get(`bb_0x${fix.baseAddress.toString(16)}`)!;
    expect(entryBlock.terminatorType).toBe("halt");
    expect(entryBlock.successorIds.length).toBe(0);
  });
});

const remediationTestAsset = {
  id: "asset_test_bin",
  projectId: "proj_test",
  name: "firmware.bin",
  type: "BINARY",
  uri: "file:///tmp/firmware.bin",
  digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  size: 1024,
  version: "1.0",
  environment: null,
  tags: ["executable"],
  metadata: {},
  created_at: Date.now(),
} as any;

const remediationCandidate = {
  binaryAssetId: remediationTestAsset.id,
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

describe("Phase 2.2: Rule 1 - Fail-Closed Reachability and Adjudication", () => {
  const decoder = new InstructionDecoder();
  const builder = new ControlFlowGraphBuilder();
  const analyzer = new ReachabilityAnalyzer();
  const bridge = new TestAdjudicationBridge();
  const testAsset = remediationTestAsset;
  const candidate = remediationCandidate;

  // -------------------------------------------------------------------------
  // Rule 1: Fail-Closed Reachability and Adjudication
  // -------------------------------------------------------------------------

  it("REMEDIATED-2.1.1: unsupported architecture fails closed to INCONCLUSIVE in reachability and adjudication", () => {
    const rawBytes = new Uint8Array([0x90, 0x90]);
    const decodeRes = decoder.decodeSafe(rawBytes, 0x1000, { architecture: "unknown" });
    expect(decodeRes.ok).toBe(false);

    const cfg = builder.buildFunctionCfg([], {
      functionName: "target_vuln",
      entryAddress: 0x1000,
      architecture: "unknown",
    });
    expect(cfg.blocks.size).toBe(0);
    expect(cfg.decodeOutcome).toBe("FAILED");
    expect(cfg.isComplete).toBe(false);

    const callGraph = builder.buildCallGraph(new Map([["target_vuln", cfg]]), new Map());
    const reachability = analyzer.analyzeReachability("target_vuln", callGraph, new Map([["target_vuln", cfg]]));
    // Fail closed: must report INCONCLUSIVE, never UNREACHABLE!
    expect(reachability.status).toBe("INCONCLUSIVE");
    expect(reachability.isComplete).toBe(false);

    const adjudicationRes = bridge.adjudicateCandidate(
      "asmt_test_01" as any,
      testAsset,
      candidate,
      { reachability },
    );
    expect(adjudicationRes.ok).toBe(true);
    if (!adjudicationRes.ok) return;
    // Adjudication engine fails closed to INCONCLUSIVE, NEVER FALSE_POSITIVE!
    expect(adjudicationRes.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adjudicationRes.value.finding.verification_status).toBe("INCONCLUSIVE");
  });

  it("Rule 1: empty decode caused by failure fails closed to INCONCLUSIVE", () => {
    const emptyCfg = builder.buildFunctionCfg([], {
      functionName: "target_vuln",
      entryAddress: 0x2000,
      architecture: "x86_64",
    });
    expect(emptyCfg.decodeOutcome).toBe("FAILED");
    expect(emptyCfg.isComplete).toBe(false);

    const callGraph = builder.buildCallGraph(new Map([["target_vuln", emptyCfg]]), new Map());
    const reachability = analyzer.analyzeReachability("target_vuln", callGraph, new Map([["target_vuln", emptyCfg]]));
    expect(reachability.status).toBe("INCONCLUSIVE");

    const adjudicationRes = bridge.adjudicateCandidate("asmt_01" as any, testAsset, candidate, { reachability });
    expect(adjudicationRes.ok).toBe(true);
    if (!adjudicationRes.ok) return;
    expect(adjudicationRes.value.lifecycleState).toBe("INCONCLUSIVE");
  });

  it("Rule 1: malformed instruction in the middle of a function creates halted block and fails closed", () => {
    // Valid NOP, then unknown opcode 0x25 with payload, stopping decode
    const stream = new Uint8Array([0x90, 0x25, 0xe9, 0x00, 0x00, 0x00]);
    const decodeRes = decoder.decodeResult(stream, 0x1000, { architecture: "x86_64" });
    expect(decodeRes.outcome).toBe("PARTIAL");

    const cfg = builder.buildFunctionCfg(decodeRes, {
      functionName: "partially_valid_fn",
      entryAddress: 0x1000,
      architecture: "x86_64",
    });
    expect(cfg.isComplete).toBe(false);
    expect(cfg.decodeOutcome).toBe("PARTIAL");

    // The block containing the unsupported instruction is halted with 0 outgoing edges
    const blocks = Array.from(cfg.blocks.values());
    const haltedBlock = blocks.find((b) => b.terminatorType === "halt");
    expect(haltedBlock).toBeDefined();
    expect(haltedBlock?.successorIds.length).toBe(0);

    const callGraph = builder.buildCallGraph(new Map([["partially_valid_fn", cfg]]), new Map());
    const reachability = analyzer.analyzeReachability("partially_valid_fn", callGraph, new Map([["partially_valid_fn", cfg]]));
    expect(reachability.status).toBe("INCONCLUSIVE");
    expect(reachability.isComplete).toBe(false);
  });

  it("Rule 1: genuine completed analysis of uncalled function legitimately establishes UNREACHABLE and FALSE_POSITIVE", () => {
    // Valid complete main function: calls foo(), then returns
    // 0xE8 0x05 0x00 0x00 0x00 (call foo at 0x100a), 0xC3 (ret)
    const mainBytes = new Uint8Array([0xe8, 0x05, 0x00, 0x00, 0x00, 0xc3]);
    const mainDecode = decoder.decodeResult(mainBytes, 0x1000, { architecture: "x86_64" });
    expect(mainDecode.outcome).toBe("SUCCESS");

    // Valid complete foo function: NOP, ret
    const fooBytes = new Uint8Array([0x90, 0xc3]);
    const fooDecode = decoder.decodeResult(fooBytes, 0x100a, { architecture: "x86_64" });
    expect(fooDecode.outcome).toBe("SUCCESS");

    // Valid complete dead function (never called): NOP, ret
    const deadBytes = new Uint8Array([0x90, 0xc3]);
    const deadDecode = decoder.decodeResult(deadBytes, 0x2000, { architecture: "x86_64" });
    expect(deadDecode.outcome).toBe("SUCCESS");

    const mainCfg = builder.buildFunctionCfg(mainDecode, {
      functionName: "main",
      entryAddress: 0x1000,
      architecture: "x86_64",
    });
    const fooCfg = builder.buildFunctionCfg(fooDecode, {
      functionName: "foo",
      entryAddress: 0x100a,
      architecture: "x86_64",
    });
    const deadCfg = builder.buildFunctionCfg(deadDecode, {
      functionName: "dead_sink",
      entryAddress: 0x2000,
      architecture: "x86_64",
    });

    const cfgs = new Map([
      ["main", mainCfg],
      ["foo", fooCfg],
      ["dead_sink", deadCfg],
    ]);

    const knownSymbols = new Map([
      [0x100a, "foo"],
      [0x2000, "dead_sink"],
    ]);

    const callGraph = builder.buildCallGraph(cfgs, knownSymbols, ["main"]);
    const reachability = analyzer.analyzeReachability("dead_sink", callGraph, cfgs, { entryPoints: ["main"] });

    // Complete CFGs without failure correctly establish UNREACHABLE!
    expect(reachability.status).toBe("UNREACHABLE");
    expect(reachability.analysisOutcome).toBe("SUCCESS");
    expect(reachability.isComplete).toBe(true);

    const adjudicationRes = bridge.adjudicateCandidate(
      "asmt_01" as any,
      testAsset,
      { ...candidate, sinkApi: "dead_sink" },
      { reachability },
    );
    expect(adjudicationRes.ok).toBe(true);
    if (!adjudicationRes.ok) return;
    expect(adjudicationRes.value.lifecycleState).toBe("FALSE_POSITIVE");
  });
});

describe("Phase 2.2: Rule 2 - Eliminate x86-64 Desynchronization", () => {
  const decoder = new InstructionDecoder();
  const builder = new ControlFlowGraphBuilder();

  it("REMEDIATED-2.1.2: unrecognized x86_64 multi-byte instruction halts without phantom branch desynchronization", () => {
    // 0x25 is 'and eax, imm32'. With imm32 = 0x000000e9: [0x25, 0xe9, 0x00, 0x00, 0x00, 0x90]
    // Because 0x25 is unrecognized, it halts decoding immediately rather than stepping 1 byte.
    // 0xE9 is NEVER parsed as a phantom JMP!
    const bytes = new Uint8Array([0x25, 0xe9, 0x00, 0x00, 0x00, 0x90]);
    const res = decoder.decodeResult(bytes, 0x401000, { architecture: "x86_64" });
    expect(res.outcome).toBe("MALFORMED");
    expect(res.instructions.length).toBe(1);
    expect(res.instructions[0]!.mnemonic).toBe("unsupported_instruction");
    expect(res.instructions[0]!.isMalformed).toBe(true);
    expect(res.instructions.some((i) => i.isBranch)).toBe(false);
    expect(res.instructions.some((i) => i.isCall)).toBe(false);
  });

  it("Rule 2: exact 0x6B IMUL instruction halts cleanly and preserves preceding valid instructions", () => {
    // Clang IMUL 0x6B: [0x6b, 0x45, 0xfc, 0x03, 0x83, 0xc0, 0x01, 0x5d, 0xc3]
    // Preceded by valid instructions: push rbp (0x55), mov rbp, rsp (0x48 0x89 0xe5)
    const stream = new Uint8Array([
      0x55, 0x48, 0x89, 0xe5, // push rbp; mov rbp, rsp
      0x6b, 0x45, 0xfc, 0x03, // imull $0x3, -0x4(%rbp), %eax (unsupported)
      0x83, 0xc0, 0x01, 0x5d, 0xc3, // remaining bytes
    ]);

    const res = decoder.decodeResult(stream, 0x401000, { architecture: "x86_64" });
    expect(res.outcome).toBe("PARTIAL");
    // 2 valid instructions preserved:
    expect(res.instructions.length).toBe(3);
    expect(res.instructions[0]!.mnemonic).toBe("push");
    expect(res.instructions[0]!.address).toBe(0x401000);
    expect(res.instructions[1]!.mnemonic).toBe("mov");
    expect(res.instructions[1]!.address).toBe(0x401001);

    // 0x6B halted cleanly as unsupported_instruction:
    expect(res.instructions[2]!.mnemonic).toBe("unsupported_instruction");
    expect(res.instructions[2]!.address).toBe(0x401004);
    expect(res.instructions[2]!.isMalformed).toBe(true);

    // ZERO phantom branches, calls, or returns created from immediate bytes
    expect(res.instructions.some((i) => i.isBranch)).toBe(false);
    expect(res.instructions.some((i) => i.isCall)).toBe(false);
    expect(res.instructions.some((i) => i.isReturn)).toBe(false);
  });

  it("REMEDIATED-2.1.3: raw unrecognized bytes set isMalformed and create halted CFG block without fallthrough", () => {
    const endbr = new Uint8Array([0x0f, 0x1e, 0xfa]);
    const res = decoder.decodeResult(endbr, 0x401000, { architecture: "x86_64" });
    expect(res.instructions[0]!.isMalformed).toBe(true);

    const endbrCfg = builder.buildFunctionCfg(res, {
      functionName: "endbr_fn",
      entryAddress: 0x401000,
      architecture: "x86_64",
    });
    expect(endbrCfg.isComplete).toBe(false);
    expect(endbrCfg.decodeOutcome).toBe("MALFORMED");
    const block = endbrCfg.blocks.get("bb_0x401000")!;
    expect(block.terminatorType).toBe("halt");
    expect(block.successorIds.length).toBe(0);
    expect(endbrCfg.edges.length).toBe(0);
  });
});

describe("Phase 2.2: Rule 3 & 5 - Provider Provenance and Adjudication Matrix", () => {
  const decoder = new InstructionDecoder();
  const bridge = new TestAdjudicationBridge();
  const testAsset = remediationTestAsset;
  const candidate = remediationCandidate;

  it("REMEDIATED-2.1.4: caller-supplied CapstoneDecoderProvider string is rejected as unsupported provider", () => {
    const spoofedReachability: ReachabilityAnalysisResult = {
      status: "REACHABLE",
      paths: [
        {
          source: "main",
          target: "sink",
          steps: [],
          isDefinitive: true,
          unresolvedIndirectJumps: [],
        },
      ],
      entryPoint: "main",
      target: "sink",
      deadCodeFunctions: [],
      reasoning: "Spoofed claim without proof",
      provider: "CapstoneDecoderProvider",
    };

    const adjudicationRes = bridge.adjudicateCandidate(
      "asmt_test_01" as any,
      testAsset,
      candidate,
      { reachability: spoofedReachability },
    );
    expect(adjudicationRes.ok).toBe(true);
    if (!adjudicationRes.ok) return;
    expect(adjudicationRes.value.lifecycleState).toBe("INCONCLUSIVE");
    expect(adjudicationRes.value.finding.confidence.verification_method).toContain(
      "Unsupported reachability proof provider",
    );
  });

  it("REMEDIATED-2.1.5: CapstoneDecoderProvider returns UNSUPPORTED and decoder tracks fallback transparently", () => {
    const forcedCapstone = new CapstoneDecoderProvider({ forceAvailable: true, forceUnsupported: true });
    expect(forcedCapstone.isAvailable()).toBe(true);
    const decodeRes = forcedCapstone.decode(new Uint8Array([0x90]), 0x401000, { architecture: "x86_64" });
    expect(decodeRes.ok).toBe(false);
    if (!decodeRes.ok) {
      expect(decodeRes.error.outcome).toBe("UNSUPPORTED");
    }

    // Facade fallback transparently identifies InProcessInstructionDecoder with fallback telemetry
    const fallbackDecoder = new InstructionDecoder({
      providers: [
        new CapstoneDecoderProvider({ forceAvailable: false }),
        new InProcessInstructionDecoder(),
      ],
    });
    const fallbackRes = fallbackDecoder.decodeResult(new Uint8Array([0x90]), 0x401000, {
      architecture: "x86_64",
      preferredProvider: "CapstoneDecoderProvider",
    });
    expect(fallbackRes.provenance.actualProvider).toBe("InProcessInstructionDecoder");
    expect(fallbackRes.provenance.requestedProvider).toBe("CapstoneDecoderProvider");
    expect(fallbackRes.provenance.isFallback).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Rule 5: Adversarial Adjudication Verification Matrix
  // -------------------------------------------------------------------------

  it("Rule 5 Matrix: complete reachable CFG + proven taint + proven witness -> VERIFIED", () => {
    const reachability: ReachabilityAnalysisResult = {
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
      reasoning: "Definitive call chain from entry point",
      provider: "ReaControlFlowEngine",
      analysisOutcome: "SUCCESS",
      isComplete: true,
    };

    const taintFlow = {
      status: "PROVEN_TAINT" as const,
      path: [],
      sanitizers: [],
      sourceApi: "recv",
      sinkApi: "strcpy",
      confidence: 1.0,
      reasoning: "Taint propagates directly",
    } as any;

    const witnessValidation = {
      witnessId: "wit_123",
      isSatisfiable: true,
      exploitabilityStatus: "PROVEN" as const,
      conflictingGuards: [],
      violatesBoundaries: false,
    } as any;

    const res = bridge.adjudicateCandidate("asmt_01" as any, testAsset, candidate, {
      reachability,
      taintFlow,
      witnessValidation,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.lifecycleState).toBe("VERIFIED");
  });

  it("Rule 5 Matrix: incomplete reachability with claimed witness CANNOT establish VERIFIED or FALSE_POSITIVE", () => {
    const incompleteReachability: ReachabilityAnalysisResult = {
      status: "REACHABLE",
      paths: [],
      entryPoint: "main",
      target: "target_vuln",
      deadCodeFunctions: [],
      reasoning: "Incomplete reachability with unhandled instructions",
      provider: "ReaControlFlowEngine",
      analysisOutcome: "PARTIAL",
      isComplete: false,
    };

    const taintFlow = {
      status: "PROVEN_TAINT" as const,
      path: [],
      sanitizers: [],
      sourceApi: "recv",
      sinkApi: "strcpy",
      confidence: 1.0,
      reasoning: "Taint flow",
    } as any;

    const witnessValidation = {
      witnessId: "wit_123",
      isSatisfiable: true,
      exploitabilityStatus: "PROVEN" as const,
      conflictingGuards: [],
      violatesBoundaries: false,
    } as any;

    const res = bridge.adjudicateCandidate("asmt_01" as any, testAsset, candidate, {
      reachability: incompleteReachability,
      taintFlow,
      witnessValidation,
    });
    // Incomplete analysis fails closed: cannot be promoted to VERIFIED
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.lifecycleState).toBe("INCONCLUSIVE");
  });
});

