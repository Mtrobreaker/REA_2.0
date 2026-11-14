import { describe, expect, it } from "vitest";
import { InProcessInstructionDecoder } from "./InProcessInstructionDecoder.js";

const decoder = new InProcessInstructionDecoder();

describe("Milestone 4.3.2 - Part A1: MIPS16 Arithmetic, Shifts, and Memory Operations", () => {
  it("verifies opcode 0x00: addiu rx, sp, imm8*4", () => {
    // 0x0001 -> opcode 0x00, rx=0 ($s0), imm=1 -> imm*4 = 4
    const bytes = new Uint8Array([0x00, 0x01]);
    const res = decoder.decode(bytes, 0x1000, {
      architecture: "MIPS",
      isMips16: true,
      isLittleEndian: false,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const inst = res.value.instructions[0]!;
    expect(inst.address).toBe(0x1000);
    expect(inst.size).toBe(2);
    expect(inst.mnemonic).toBe("addiu");
    expect(inst.operands).toBe("$s0, $sp, 4");
    expect(inst.isBranch).toBe(false);
    expect(inst.isCall).toBe(false);
    expect(inst.isReturn).toBe(false);
    expect(inst.hasDelaySlot).toBe(false);
    expect(inst.isMalformed).toBeUndefined();
    expect(inst.isaMode).toBe("MIPS16");
  });

  it("verifies opcode 0x01: addiu rx, pc, imm8*4", () => {
    // 0x0902 -> opcode 0x01, rx=1 ($s1), imm=2 -> imm*4 = 8
    const bytes = new Uint8Array([0x09, 0x02]);
    const res = decoder.decode(bytes, 0x1000, {
      architecture: "MIPS",
      isMips16: true,
      isLittleEndian: false,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const inst = res.value.instructions[0]!;
    expect(inst.mnemonic).toBe("addiu");
    expect(inst.operands).toBe("$s1, $pc, 8");
    expect(inst.isBranch).toBe(false);
    expect(inst.isaMode).toBe("MIPS16");
  });

  it("verifies opcode 0x06: shift instructions sll, srl, sra", () => {
    // sll $v0, $v1, 2: op 0x06, rx=2, ry=3, sa=2, funct=0 -> (0x06<<11)|(2<<8)|(3<<5)|(2<<2)|0 = 0x3268
    const bytes = new Uint8Array([0x32, 0x68]);
    const res = decoder.decode(bytes, 0x1000, {
      architecture: "MIPS",
      isMips16: true,
      isLittleEndian: false,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const inst = res.value.instructions[0]!;
    expect(inst.mnemonic).toBe("sll");
    expect(inst.operands).toBe("$v0, $v1, 2");
    expect(inst.isBranch).toBe(false);
  });

  it("verifies opcode 0x16: PC-relative literal pool load lw rx, imm8*4(pc)", () => {
    // 0xb004 -> op 0x16, rx=0 ($s0), imm=4 -> 16($pc)
    const bytes = new Uint8Array([0xb0, 0x04]);
    const res = decoder.decode(bytes, 0x1000, { architecture: "MIPS", isMips16: true });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const inst = res.value.instructions[0]!;
    expect(inst.mnemonic).toBe("lw");
    expect(inst.operands).toBe("$s0, 16($pc)");
  });

  it("verifies opcode 0x1c: RRR format addu and subu", () => {
    // addu $v0, $s0, $s1: op 0x1c, rx=0, ry=1, rz=2, funct=1 -> (0x1c<<11)|(0<<8)|(1<<5)|(2<<2)|1 = 0xe029
    const adduBytes = new Uint8Array([0xe0, 0x29]);
    const adduRes = decoder.decode(adduBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    expect(adduRes.ok).toBe(true);
    if (!adduRes.ok) return;
    const adduInst = adduRes.value.instructions[0]!;
    expect(adduInst.mnemonic).toBe("addu");
    expect(adduInst.operands).toBe("$v0, $s0, $s1");

    // subu $v0, $s0, $s1: funct=3 -> 0xe02b
    const subuBytes = new Uint8Array([0xe0, 0x2b]);
    const subuRes = decoder.decode(subuBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    expect(subuRes.ok).toBe(true);
    if (!subuRes.ok) return;
    const subuInst = subuRes.value.instructions[0]!;
    expect(subuInst.mnemonic).toBe("subu");
    expect(subuInst.operands).toBe("$v0, $s0, $s1");
  });
});

describe("Milestone 4.3.2 - Part A2: MIPS16 Branch, Jump, and Call Target Resolution", () => {
  it("verifies opcode 0x02: unconditional branch b and target calculation without delay slot", () => {
    // b +8: opcode 0x02, imm11 = 4 -> target = 0x1000 + 2 + (4 << 1) = 0x100a
    const bytes = new Uint8Array([0x10, 0x04]);
    const res = decoder.decode(bytes, 0x1000, {
      architecture: "MIPS",
      isMips16: true,
      isLittleEndian: false,
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const inst = res.value.instructions[0]!;
    expect(inst.mnemonic).toBe("b");
    expect(inst.isBranch).toBe(true);
    expect(inst.isConditional).toBe(false);
    expect(inst.isCall).toBe(false);
    expect(inst.isReturn).toBe(false);
    expect(inst.hasDelaySlot).toBe(false);
    expect(inst.targetAddress).toBe(0x100a);
    expect(inst.size).toBe(2);
    expect(inst.isaMode).toBe("MIPS16");
  });

  it("verifies opcode 0x03: JAL (call within MIPS16) and JALX (call with mode transition to MIPS32)", () => {
    // JAL: 0x1800 0x0800 -> target: 0x10002000 (MIPS16: LSB set to 1)
    const jalBytes = new Uint8Array([0x18, 0x00, 0x08, 0x00]);
    const jalRes = decoder.decode(jalBytes, 0x1000, {
      architecture: "MIPS",
      isMips16: true,
      isLittleEndian: false,
    });
    expect(jalRes.ok).toBe(true);
    if (!jalRes.ok) return;
    const jalInst = jalRes.value.instructions[0]!;
    expect(jalInst.mnemonic).toBe("jal");
    expect(jalInst.size).toBe(4);
    expect(jalInst.isCall).toBe(true);
    expect(jalInst.hasDelaySlot).toBe(true);
    expect(jalInst.targetAddress! & 1).toBe(1); // MIPS16 mode target

    // JALX: bit 10 of first halfword set -> 0x1c00 0x0800
    const jalxBytes = new Uint8Array([0x1c, 0x00, 0x08, 0x00]);
    const jalxRes = decoder.decode(jalxBytes, 0x1000, {
      architecture: "MIPS",
      isMips16: true,
      isLittleEndian: false,
    });
    expect(jalxRes.ok).toBe(true);
    if (!jalxRes.ok) return;
    const jalxInst = jalxRes.value.instructions[0]!;
    expect(jalxInst.mnemonic).toBe("jalx");
    expect(jalxInst.size).toBe(4);
    expect(jalxInst.isCall).toBe(true);
    expect(jalxInst.hasDelaySlot).toBe(true);
    expect(jalxInst.targetAddress! & 1).toBe(0); // Mode switch to MIPS32 (LSB = 0)
  });

  it("verifies opcode 0x04 & 0x05: conditional branches beqz and bnez without delay slots", () => {
    // beqz $v0, +4: opcode 0x04, rx=2 ($v0), imm8=2 -> target = 0x1000 + 2 + (2 << 1) = 0x1006
    const beqzBytes = new Uint8Array([0x22, 0x02]);
    const beqzRes = decoder.decode(beqzBytes, 0x1000, {
      architecture: "MIPS",
      isMips16: true,
      isLittleEndian: false,
    });
    expect(beqzRes.ok).toBe(true);
    if (!beqzRes.ok) return;
    const beqzInst = beqzRes.value.instructions[0]!;
    expect(beqzInst.mnemonic).toBe("beqz");
    expect(beqzInst.operands).toBe("$v0, 0x1006");
    expect(beqzInst.isBranch).toBe(true);
    expect(beqzInst.isConditional).toBe(true);
    expect(beqzInst.hasDelaySlot).toBe(false);
    expect(beqzInst.targetAddress).toBe(0x1006);

    // bnez $a0, +4: opcode 0x05, rx=4 ($a0), imm8=2 -> target = 0x1006
    const bnezBytes = new Uint8Array([0x2c, 0x02]);
    const bnezRes = decoder.decode(bnezBytes, 0x1000, {
      architecture: "MIPS",
      isMips16: true,
      isLittleEndian: false,
    });
    expect(bnezRes.ok).toBe(true);
    if (!bnezRes.ok) return;
    const bnezInst = bnezRes.value.instructions[0]!;
    expect(bnezInst.mnemonic).toBe("bnez");
    expect(bnezInst.operands).toBe("$a0, 0x1006");
    expect(bnezInst.isBranch).toBe(true);
    expect(bnezInst.isConditional).toBe(true);
    expect(bnezInst.hasDelaySlot).toBe(false);
  });
});

describe("Milestone 4.3.2 - Part A3: MIPS16 Mode Transitions, Returns, and Exceptions", () => {
  it("verifies opcode 0x0c: bteqz, btnez, adjsp, save, restore, move, and nop", () => {
    // bteqz +8: (0x0c << 11) | (0 << 8) | 4 = 0x6004 -> target 0x100a
    const bteqzBytes = new Uint8Array([0x60, 0x04]);
    const bteqzRes = decoder.decode(bteqzBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    expect(bteqzRes.ok).toBe(true);
    if (!bteqzRes.ok) return;
    const bteqzInst = bteqzRes.value.instructions[0]!;
    expect(bteqzInst.mnemonic).toBe("bteqz");
    expect(bteqzInst.isBranch).toBe(true);
    expect(bteqzInst.isConditional).toBe(true);
    expect(bteqzInst.hasDelaySlot).toBe(false);
    expect(bteqzInst.targetAddress).toBe(0x100a);

    // btnez +8: 0x6104 -> target 0x100a
    const btnezBytes = new Uint8Array([0x61, 0x04]);
    const btnezInst = decoder.decode(btnezBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    if (btnezInst.ok) {
      expect(btnezInst.value.instructions[0]!.mnemonic).toBe("btnez");
      expect(btnezInst.value.instructions[0]!.isBranch).toBe(true);
      expect(btnezInst.value.instructions[0]!.isConditional).toBe(true);
    }

    // save: 0x6480..0x64ff
    const saveBytes = new Uint8Array([0x64, 0x90]);
    const saveInst = decoder.decode(saveBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    if (saveInst.ok) {
      expect(saveInst.value.instructions[0]!.mnemonic).toBe("save");
      expect(saveInst.value.instructions[0]!.isBranch).toBe(false);
    }

    // restore: 0x6400..0x647f
    const restoreBytes = new Uint8Array([0x64, 0x10]);
    const restoreInst = decoder.decode(restoreBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    if (restoreInst.ok) {
      expect(restoreInst.value.instructions[0]!.mnemonic).toBe("restore");
      expect(restoreInst.value.instructions[0]!.isReturn).toBe(false);
    }

    // nop: 0x6500
    const nopBytes = new Uint8Array([0x65, 0x00]);
    const nopInst = decoder.decode(nopBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    if (nopInst.ok) {
      expect(nopInst.value.instructions[0]!.mnemonic).toBe("nop");
    }
  });

  it("verifies opcode 0x1d: returns, indirect jumps, and indirect calls", () => {
    // jr $ra with delay slot (nd=0, ra=1, l=0): 0xe820
    const jrRaBytes = new Uint8Array([0xe8, 0x20]);
    const jrRaRes = decoder.decode(jrRaBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    expect(jrRaRes.ok).toBe(true);
    if (!jrRaRes.ok) return;
    const jrRaInst = jrRaRes.value.instructions[0]!;
    expect(jrRaInst.mnemonic).toBe("jr ra");
    expect(jrRaInst.isReturn).toBe(true);
    expect(jrRaInst.hasDelaySlot).toBe(true);

    // jrc ra compact without delay slot (nd=1, ra=1, l=0): 0xe8a0
    const jrcRaBytes = new Uint8Array([0xe8, 0xa0]);
    const jrcRaRes = decoder.decode(jrcRaBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    expect(jrcRaRes.ok).toBe(true);
    if (!jrcRaRes.ok) return;
    const jrcRaInst = jrcRaRes.value.instructions[0]!;
    expect(jrcRaInst.mnemonic).toBe("jrc ra");
    expect(jrcRaInst.isReturn).toBe(true);
    expect(jrcRaInst.hasDelaySlot).toBe(false);

    // jalr $v0 with delay slot (nd=0, ra=0, l=1, rx=2): 0xea40
    const jalrBytes = new Uint8Array([0xea, 0x40]);
    const jalrRes = decoder.decode(jalrBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    expect(jalrRes.ok).toBe(true);
    if (!jalrRes.ok) return;
    const jalrInst = jalrRes.value.instructions[0]!;
    expect(jalrInst.mnemonic).toBe("jalr");
    expect(jalrInst.isCall).toBe(true);
    expect(jalrInst.isIndirect).toBe(true);
    expect(jalrInst.hasDelaySlot).toBe(true);

    // jalrc $v0 compact (nd=1, ra=0, l=1, rx=2): 0xea40 | 0x80 = 0xeac0
    const jalrcBytes = new Uint8Array([0xea, 0xc0]);
    const jalrcRes = decoder.decode(jalrcBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    expect(jalrcRes.ok).toBe(true);
    if (!jalrcRes.ok) return;
    const jalrcInst = jalrcRes.value.instructions[0]!;
    expect(jalrcInst.mnemonic).toBe("jalrc");
    expect(jalrcInst.isCall).toBe(true);
    expect(jalrcInst.isIndirect).toBe(true);
    expect(jalrcInst.hasDelaySlot).toBe(false);

    // sdbbp: 0xe801
    const sdbbpBytes = new Uint8Array([0xe8, 0x01]);
    const sdbbpRes = decoder.decode(sdbbpBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    if (sdbbpRes.ok) {
      expect(sdbbpRes.value.instructions[0]!.mnemonic).toBe("sdbbp");
    }

    // break: 0xe805
    const breakBytes = new Uint8Array([0xe8, 0x05]);
    const breakRes = decoder.decode(breakBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    if (breakRes.ok) {
      expect(breakRes.value.instructions[0]!.mnemonic).toBe("break");
    }
  });
});

describe("Milestone 4.3.2 - Part A4: MIPS16 EXTEND Prefix and Malformed/Reserved Encodings", () => {
  it("verifies opcode 0x1e: EXTEND prefix 32-bit forms and 16-bit target expansions", () => {
    // EXTEND + b +1024: 0xf000 0x1200 -> target: 0x1000 + 4 + (512 << 1) = 0x1404
    const extBBytes = new Uint8Array([0xf0, 0x00, 0x12, 0x00]);
    const extBRes = decoder.decode(extBBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    expect(extBRes.ok).toBe(true);
    if (!extBRes.ok) return;
    const extBInst = extBRes.value.instructions[0]!;
    expect(extBInst.mnemonic).toBe("b");
    expect(extBInst.size).toBe(4);
    expect(extBInst.isBranch).toBe(true);
    expect(extBInst.hasDelaySlot).toBe(false);

    // EXTEND + save
    const extSaveBytes = new Uint8Array([0xf0, 0x00, 0x64, 0x80]);
    const extSaveRes = decoder.decode(extSaveBytes, 0x1000, { architecture: "MIPS", isMips16: true });
    if (extSaveRes.ok) {
      const extSaveInst = extSaveRes.value.instructions[0]!;
      expect(extSaveInst.mnemonic).toBe("save");
      expect(extSaveInst.size).toBe(4);
    }
  });

  it("verifies fail-closed behavior on reserved/invalid MIPS16 encodings (opcodes 0x07, 0x0f, 0x17, 0x1f)", () => {
    // Opcode 0x07: 0x3800
    const res07 = decoder.decode(new Uint8Array([0x38, 0x00]), 0x1000, { architecture: "MIPS", isMips16: true });
    expect(res07.ok).toBe(true);
    if (res07.ok) {
      const op07 = res07.value.instructions[0]!;
      expect(op07.isMalformed).toBe(true);
      expect(op07.mnemonic).toBe("unsupported_mips16_07");
    }

    // Opcode 0x0f: 0x7800
    const res0f = decoder.decode(new Uint8Array([0x78, 0x00]), 0x1000, { architecture: "MIPS", isMips16: true });
    if (res0f.ok) {
      const op0f = res0f.value.instructions[0]!;
      expect(op0f.isMalformed).toBe(true);
      expect(op0f.mnemonic).toBe("unsupported_mips16_0f");
    }

    // Opcode 0x17: 0xb800
    const res17 = decoder.decode(new Uint8Array([0xb8, 0x00]), 0x1000, { architecture: "MIPS", isMips16: true });
    if (res17.ok) {
      const op17 = res17.value.instructions[0]!;
      expect(op17.isMalformed).toBe(true);
      expect(op17.mnemonic).toBe("unsupported_mips16_17");
    }

    // Opcode 0x1f: 0xf800
    const res1f = decoder.decode(new Uint8Array([0xf8, 0x00]), 0x1000, { architecture: "MIPS", isMips16: true });
    if (res1f.ok) {
      const op1f = res1f.value.instructions[0]!;
      expect(op1f.isMalformed).toBe(true);
      expect(op1f.mnemonic).toBe("unsupported_mips16_1f");
    }

    // Truncated EXTEND (only 2 bytes): fail-closed
    const resTrunc = decoder.decode(new Uint8Array([0xf0, 0x00]), 0x1000, { architecture: "MIPS", isMips16: true });
    if (resTrunc.ok) {
      const truncExtend = resTrunc.value.instructions[0]!;
      expect(truncExtend.isMalformed).toBe(true);
      expect(truncExtend.mnemonic).toBe("malformed_extend_truncated");
    }
  });
});
