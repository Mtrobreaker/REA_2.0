import { describe, expect, it } from "vitest";
import { InProcessInstructionDecoder } from "./InProcessInstructionDecoder.js";
import { CapstoneDecoderProvider } from "./CapstoneDecoderProvider.js";
import { ControlFlowGraphBuilder } from "./ControlFlowGraphBuilder.js";
import { FunctionRecoveryEngine } from "./FunctionRecoveryEngine.js";

describe("Milestone 4.3.1: MIPS16, Function Recovery, and CFG Accuracy Suite", () => {
  const inProcessDecoder = new InProcessInstructionDecoder();
  const capstone = new CapstoneDecoderProvider();
  const cfgBuilder = new ControlFlowGraphBuilder();
  const recoveryEngine = new FunctionRecoveryEngine();

  it("1. Accurately decodes MIPS16 base control-flow, save/restore, and delay slot semantics", () => {
    // 64 c2: save $ra, 16  (save: bit 7 = 1)
    // 10 03: b +6 (target = 0x1002 + 6 = 0x1008)
    // e8 a0: jrc $ra (compact return, NO delay slot)
    // 64 42: restore $ra, 16 (restore: bit 7 = 0)
    // e8 20: jr $ra (return WITH delay slot)
    // 65 00: nop
    const bytes = Buffer.from("64c21003e8a06442e8206500", "hex");
    const res = inProcessDecoder.decode(bytes, 0x1000, {
      architecture: "MIPS",
      isMips16: true,
      isLittleEndian: false,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const insts = res.value.instructions;
    expect(insts.length).toBe(6);
    expect(insts[0]!.mnemonic).toBe("save");
    expect(insts[0]!.hasDelaySlot).toBe(false);
    expect(insts[0]!.isaMode).toBe("MIPS16");

    expect(insts[1]!.mnemonic).toBe("b");
    expect(insts[1]!.isBranch).toBe(true);
    expect(insts[1]!.hasDelaySlot).toBe(false);
    expect(insts[1]!.targetAddress).toBe(0x100a);

    expect(insts[2]!.mnemonic).toBe("jrc ra");
    expect(insts[2]!.isReturn).toBe(true);
    expect(insts[2]!.hasDelaySlot).toBe(false);

    expect(insts[3]!.mnemonic).toBe("restore");
    expect(insts[3]!.hasDelaySlot).toBe(false);

    expect(insts[4]!.mnemonic).toBe("jr ra");
    expect(insts[4]!.isReturn).toBe(true);
    expect(insts[4]!.hasDelaySlot).toBe(true);
  });

  it("2. Accurately decodes MIPS16 32-bit instructions (EXTEND prefix and JAL / JALX)", () => {
    // f0 01 64 c2: extend + save
    // 18 00 04 00: jal 0x1000 (target MIPS16, bit 0 set)
    // 1c 00 04 00: jalx 0x1000 (target MIPS32, bit 0 cleared)
    const bytes = Buffer.from("f00164c2180004001c000400", "hex");
    const res = inProcessDecoder.decode(bytes, 0x2000, {
      architecture: "MIPS",
      isMips16: true,
      isLittleEndian: false,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const insts = res.value.instructions;
    expect(insts.length).toBe(3);

    // Extended save
    expect(insts[0]!.mnemonic).toBe("save");
    expect(insts[0]!.size).toBe(4);
    expect(insts[0]!.isaMode).toBe("MIPS16");

    // JAL (call MIPS16)
    expect(insts[1]!.mnemonic).toBe("jal");
    expect(insts[1]!.isCall).toBe(true);
    expect(insts[1]!.size).toBe(4);
    expect(insts[1]!.hasDelaySlot).toBe(true);
    expect(insts[1]!.targetAddress! & 1).toBe(1);

    // JALX (call MIPS32 mode exchange)
    expect(insts[2]!.mnemonic).toBe("jalx");
    expect(insts[2]!.isCall).toBe(true);
    expect(insts[2]!.size).toBe(4);
    expect(insts[2]!.hasDelaySlot).toBe(true);
    expect(insts[2]!.targetAddress! & 1).toBe(0);
  });

  it("3. Validates Capstone fail-closed delegation on MIPS16", () => {
    expect(
      capstone.canDecode({
        architecture: "MIPS",
        isMips16: true,
      }),
    ).toBe(false);

    const bytes = Buffer.from("64c2e8a0", "hex");
    const decodeRes = capstone.decode(bytes, 0x1000, {
      architecture: "MIPS",
      isMips16: true,
    });
    expect(decodeRes.ok).toBe(false);
    if (!decodeRes.ok) {
      expect(decodeRes.error.outcome).toBe("UNSUPPORTED");
    }
  });

  it("4. Accurately partitions MIPS16 CFG basic blocks respecting non-delay branches", () => {
    // Block 1:
    // 0x1000: 64 c2  save
    // 0x1002: 10 01  b 0x1006 (compact unconditional branch, NO delay slot)
    // Block 2 (jump target):
    // 0x1006: e8 a0  jrc $ra (compact return)
    const bytes = Buffer.from("64c210016500e8a0", "hex");
    const res = inProcessDecoder.decode(bytes, 0x1000, {
      architecture: "MIPS",
      isMips16: true,
      isLittleEndian: false,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const cfg = cfgBuilder.buildFunctionCfg(res.value, {
      functionName: "test_mips16_fn",
      entryAddress: 0x1000,
      architecture: "MIPS",
    });

    expect(cfg.isComplete).toBe(true);
    // Block 1 should have 2 instructions (save, b) and not consume 0x1004 as delay slot
    const entryBlock = cfg.blocks.get("bb_0x1000");
    expect(entryBlock).toBeDefined();
    expect(entryBlock!.instructions.length).toBe(2);
    expect(entryBlock!.terminatorType).toBe("branch");
  });

  it("5. Recovers functions and marks boundaries with verified vs inferred status", () => {
    // Function 1 (MIPS16, verified by jrc $ra):
    // 0x1000: 64 c2  save
    // 0x1002: e8 a0  jrc $ra
    // Function 2 (MIPS32, verified by jr $ra + nop delay slot):
    // 0x1004: 27 bd ff f0  addiu $sp, $sp, -16
    // 0x1008: 03 e0 00 08  jr $ra
    // 0x100c: 00 00 00 00  nop
    const mips16Bytes = Buffer.from("64c2e8a0", "hex");
    const mips32Bytes = Buffer.from("27bdfff003e0000800000000", "hex");
    const combinedBytes = Buffer.concat([mips16Bytes, mips32Bytes]);

    const res = inProcessDecoder.decode(combinedBytes, 0x1000, {
      architecture: "MIPS",
      isLittleEndian: false,
      mips16Regions: [{ start: 0x1000, end: 0x1004 }],
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const insts = res.value.instructions;
    expect(insts.length).toBe(5);
    expect(insts[0]!.isaMode).toBe("MIPS16");
    expect(insts[2]!.isaMode).toBe("MIPS32");

    const result = recoveryEngine.recoverFunctions(insts, {
      architecture: "MIPS",
      baseAddress: 0x1000,
      totalCodeBytes: combinedBytes.length,
      symbols: [
        { name: "fn_mips16", address: 0x1001, isExport: true },
        { name: "fn_mips32", address: 0x1004, isExport: true },
      ],
    });

    expect(result.totalRecovered).toBe(2);
    expect(result.mips16FunctionsCount).toBe(1);
    expect(result.mips32FunctionsCount).toBe(1);
    expect(result.verifiedBoundariesCount).toBe(2);

    const fn1 = result.functions[0]!;
    expect(fn1.name).toBe("fn_mips16");
    expect(fn1.isaMode).toBe("MIPS16");
    expect(fn1.boundaryStatus).toBe("VERIFIED");
    expect(fn1.size).toBe(4);

    const fn2 = result.functions[1]!;
    expect(fn2.name).toBe("fn_mips32");
    expect(fn2.isaMode).toBe("MIPS32");
    expect(fn2.boundaryStatus).toBe("VERIFIED");
    expect(fn2.size).toBe(12);
  });
});
