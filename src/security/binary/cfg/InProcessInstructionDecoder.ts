import { err, ok, type Result } from "../../../domain/result.js";
import type {
  Architecture,
  DecodeOptions,
  DecodeOutcome,
  DecodeResult,
  Instruction,
  InstructionDecoderProvider,
} from "./types.js";
import { InstructionDecodeError } from "./types.js";

/**
 * Conforming In-Process Instruction Decoder.
 *
 * Implements high-fidelity, deterministic instruction boundary decoding,
 * prefix tracking, ModR/M & SIB calculation, RIP-relative addressing,
 * ARM A32 conditions, Thumb/Thumb-2 variable-width stepping, and MIPS32
 * (LE/BE) branch delay slot tracking.
 *
 * Designed to fail closed on malformed input or unsupported architectures.
 */
export class InProcessInstructionDecoder implements InstructionDecoderProvider {
  public readonly name = "InProcessInstructionDecoder";
  public readonly supportedArchitectures: readonly Architecture[] = ["ARM", "MIPS", "x86_64"];

  public canDecode(options: DecodeOptions): boolean {
    return this.supportedArchitectures.includes(options.architecture);
  }

  public decode(
    bytes: Uint8Array,
    baseAddress: number,
    options: DecodeOptions,
  ): Result<DecodeResult, InstructionDecodeError> {
    if (!this.supportedArchitectures.includes(options.architecture)) {
      return err(
        new InstructionDecodeError(
          `Unsupported architecture: '${options.architecture}'. Supported: ARM, MIPS, x86_64`,
          options.architecture,
          baseAddress,
          bytes,
          "UNSUPPORTED",
        ),
      );
    }

    if (bytes.byteLength === 0) {
      const emptyResult: any = [];
      emptyResult.outcome = "SUCCESS";
      emptyResult.instructions = [];
      emptyResult.architecture = options.architecture;
      emptyResult.baseAddress = baseAddress;
      emptyResult.totalBytes = 0;
      emptyResult.decodedBytes = 0;
      emptyResult.provenance = {
        actualProvider: "InProcessInstructionDecoder",
        isFallback: false,
        timestamp: Date.now(),
      };
      return ok(emptyResult as DecodeResult);
    }

    let instructions: Instruction[];
    switch (options.architecture) {
      case "x86_64":
        instructions = this.decodeX86_64(bytes, baseAddress);
        break;
      case "ARM":
        if (options.isThumb || (baseAddress & 1) === 1) {
          instructions = this.decodeThumb(bytes, baseAddress & ~1, options.isLittleEndian ?? true);
        } else {
          instructions = this.decodeArm(bytes, baseAddress, options.isLittleEndian ?? true);
        }
        break;
      case "MIPS":
        if (
          options.isMips16 ||
          (baseAddress & 1) === 1 ||
          (options.mips16Regions && options.mips16Regions.length > 0)
        ) {
          instructions = this.decodeMixedMips(
            bytes,
            baseAddress,
            options.isLittleEndian ?? false,
            options,
          );
        } else {
          instructions = this.decodeMips(bytes, baseAddress, options.isLittleEndian ?? false);
        }
        break;
      default:
        return err(
          new InstructionDecodeError(
            `Unhandled architecture: ${options.architecture}`,
            options.architecture,
            baseAddress,
            bytes,
            "UNSUPPORTED",
          ),
        );
    }

    const hasMalformed = instructions.some((i) => i.isMalformed === true);
    let decodedBytes = 0;
    for (const inst of instructions) {
      if (!inst.isMalformed) {
        decodedBytes += inst.size;
      }
    }

    let outcome: DecodeOutcome = "SUCCESS";
    if (hasMalformed) {
      outcome = decodedBytes > 0 ? "PARTIAL" : "MALFORMED";
    }

    const decodeResult: any = [...instructions];
    decodeResult.outcome = outcome;
    decodeResult.instructions = instructions;
    decodeResult.architecture = options.architecture;
    decodeResult.baseAddress = baseAddress;
    decodeResult.totalBytes = bytes.byteLength;
    decodeResult.decodedBytes = decodedBytes;
    decodeResult.provenance = {
      actualProvider: "InProcessInstructionDecoder",
      isFallback: false,
      timestamp: Date.now(),
    };
    if (hasMalformed) {
      decodeResult.haltReason = "Stream halted on malformed or unsupported instruction";
    }

    return ok(decodeResult as DecodeResult);
  }

  // =========================================================================
  // x86-64 Instruction Decoder
  // =========================================================================
  private decodeX86_64(bytes: Uint8Array, baseAddress: number): Instruction[] {
    const instructions: Instruction[] = [];
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 0;

    while (offset < bytes.byteLength) {
      const startOffset = offset;
      const addr = (baseAddress + offset) >>> 0;
      const prefixes: string[] = [];

      // 1. Parse Legacy & REX Prefixes
      let hasOperandSizeOverride = false;
      let rexW = false;
      let hasRex = false;

      while (offset < bytes.byteLength) {
        const b = bytes[offset]!;
        // Legacy group 1 (Lock & Repeat)
        if (b === 0xf0) { prefixes.push("lock"); offset++; }
        else if (b === 0xf2) { prefixes.push("repne"); offset++; }
        else if (b === 0xf3) { prefixes.push("repe"); offset++; }
        // Legacy group 2 (Segment overrides / branch hints)
        else if (b === 0x2e) { prefixes.push("cs"); offset++; }
        else if (b === 0x36) { prefixes.push("ss"); offset++; }
        else if (b === 0x3e) { prefixes.push("ds"); offset++; }
        else if (b === 0x26) { prefixes.push("es"); offset++; }
        else if (b === 0x64) { prefixes.push("fs"); offset++; }
        else if (b === 0x65) { prefixes.push("gs"); offset++; }
        // Legacy group 3 (Operand-size override)
        else if (b === 0x66) { hasOperandSizeOverride = true; prefixes.push("data16"); offset++; }
        // Legacy group 4 (Address-size override)
        else if (b === 0x67) { prefixes.push("addr32"); offset++; }
        // REX prefix (0x40 - 0x4F) in 64-bit mode
        else if (b >= 0x40 && b <= 0x4f) {
          hasRex = true;
          rexW = (b & 0x08) !== 0;
          prefixes.push(`rex${rexW ? ".w" : ""}`);
          offset++;
          // REX must immediately precede the opcode (can only be one REX prefix)
          break;
        } else {
          break;
        }
      }

      if (offset >= bytes.byteLength) {
        // Trailing prefix without opcode -> malformed instruction
        const rawBytes = bytes.slice(startOffset, bytes.byteLength);
        instructions.push({
          address: addr,
          mnemonic: "malformed_prefix",
          operands: "",
          size: rawBytes.byteLength,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          isMalformed: true,
          prefixes,
        });
        break;
      }

      const b0 = bytes[offset]!;

      // -------------------------------------------------------------
      // 2. Control-Flow Instructions
      // -------------------------------------------------------------

      // RET (0xC3, 0xCB)
      if (b0 === 0xc3 || b0 === 0xcb) {
        offset++;
        const size = offset - startOffset;
        instructions.push({
          address: addr,
          mnemonic: b0 === 0xcb ? "retf" : "ret",
          operands: "",
          size,
          rawBytes: bytes.slice(startOffset, offset),
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: true,
          isIndirect: false,
          targetAddress: null,
          prefixes,
        });
        continue;
      }

      // RET imm16 (0xC2, 0xCA)
      if ((b0 === 0xc2 || b0 === 0xca) && offset + 3 <= bytes.byteLength) {
        const imm16 = view.getUint16(offset + 1, true);
        offset += 3;
        const size = offset - startOffset;
        instructions.push({
          address: addr,
          mnemonic: b0 === 0xca ? "retf" : "ret",
          operands: `0x${imm16.toString(16)}`,
          size,
          rawBytes: bytes.slice(startOffset, offset),
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: true,
          isIndirect: false,
          targetAddress: null,
          prefixes,
        });
        continue;
      }

      // JMP rel8 (0xEB)
      if (b0 === 0xeb && offset + 2 <= bytes.byteLength) {
        const rel8 = view.getInt8(offset + 1);
        offset += 2;
        const size = offset - startOffset;
        const target = (addr + size + rel8) >>> 0;
        instructions.push({
          address: addr,
          mnemonic: "jmp",
          operands: `0x${target.toString(16)}`,
          size,
          rawBytes: bytes.slice(startOffset, offset),
          isBranch: true,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: target,
          prefixes,
        });
        continue;
      }

      // JMP rel32 (0xE9)
      if (b0 === 0xe9 && offset + 5 <= bytes.byteLength) {
        const rel32 = view.getInt32(offset + 1, true);
        offset += 5;
        const size = offset - startOffset;
        const target = (addr + size + rel32) >>> 0;
        instructions.push({
          address: addr,
          mnemonic: "jmp",
          operands: `0x${target.toString(16)}`,
          size,
          rawBytes: bytes.slice(startOffset, offset),
          isBranch: true,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: target,
          prefixes,
        });
        continue;
      }

      // CALL rel32 (0xE8)
      if (b0 === 0xe8 && offset + 5 <= bytes.byteLength) {
        const rel32 = view.getInt32(offset + 1, true);
        offset += 5;
        const size = offset - startOffset;
        const target = (addr + size + rel32) >>> 0;
        instructions.push({
          address: addr,
          mnemonic: "call",
          operands: `0x${target.toString(16)}`,
          size,
          rawBytes: bytes.slice(startOffset, offset),
          isBranch: false,
          isConditional: false,
          isCall: true,
          isReturn: false,
          isIndirect: false,
          targetAddress: target,
          prefixes,
        });
        continue;
      }

      // Jcc rel8 (0x70 - 0x7F)
      if (b0 >= 0x70 && b0 <= 0x7f && offset + 2 <= bytes.byteLength) {
        const rel8 = view.getInt8(offset + 1);
        const condition = this.getX86ConditionName(b0 & 0x0f);
        offset += 2;
        const size = offset - startOffset;
        const target = (addr + size + rel8) >>> 0;
        instructions.push({
          address: addr,
          mnemonic: `j${condition}`,
          operands: `0x${target.toString(16)}`,
          size,
          rawBytes: bytes.slice(startOffset, offset),
          isBranch: true,
          isConditional: true,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: target,
          prefixes,
        });
        continue;
      }

      // Two-byte opcode: 0x0F
      if (b0 === 0x0f && offset + 2 <= bytes.byteLength) {
        const b1 = bytes[offset + 1]!;

        // Jcc rel32 (0x0F 0x80 - 0x0F 0x8F)
        if (b1 >= 0x80 && b1 <= 0x8f && offset + 6 <= bytes.byteLength) {
          const rel32 = view.getInt32(offset + 2, true);
          const condition = this.getX86ConditionName(b1 & 0x0f);
          offset += 6;
          const size = offset - startOffset;
          const target = (addr + size + rel32) >>> 0;
          instructions.push({
            address: addr,
            mnemonic: `j${condition}`,
            operands: `0x${target.toString(16)}`,
            size,
            rawBytes: bytes.slice(startOffset, offset),
            isBranch: true,
            isConditional: true,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: target,
            prefixes,
          });
          continue;
        }

        // SYSCALL (0x0F 0x05)
        if (b1 === 0x05) {
          offset += 2;
          const size = offset - startOffset;
          instructions.push({
            address: addr,
            mnemonic: "syscall",
            operands: "",
            size,
            rawBytes: bytes.slice(startOffset, offset),
            isBranch: false,
            isConditional: false,
            isCall: true,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            prefixes,
          });
          continue;
        }

        // UD2 (0x0F 0x0B)
        if (b1 === 0x0b) {
          offset += 2;
          const size = offset - startOffset;
          instructions.push({
            address: addr,
            mnemonic: "ud2",
            operands: "",
            size,
            rawBytes: bytes.slice(startOffset, offset),
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            prefixes,
          });
          continue;
        }
      }

      // Group 5: Indirect CALL / JMP via ModR/M (0xFF /2 or /4)
      if (b0 === 0xff && offset + 2 <= bytes.byteLength) {
        const modrm = bytes[offset + 1]!;
        const regOp = (modrm >>> 3) & 0x07;
        if (regOp === 2 || regOp === 4) {
          const isCall = regOp === 2;
          const operandResult = this.parseModRm(bytes, offset + 1, addr + (offset - startOffset));
          if (operandResult) {
            offset += 1 + operandResult.totalModRmBytes;
            const size = offset - startOffset;
            instructions.push({
              address: addr,
              mnemonic: isCall ? "call (indirect)" : "jmp (indirect)",
              operands: operandResult.operandText,
              size,
              rawBytes: bytes.slice(startOffset, offset),
              isBranch: !isCall,
              isConditional: false,
              isCall,
              isReturn: false,
              isIndirect: true,
              targetAddress: operandResult.ripTargetAddress,
              prefixes,
            });
            continue;
          }
        }
      }

      // -------------------------------------------------------------
      // 3. Variable-Length Non-Branch Instructions (Boundary Preservation)
      // -------------------------------------------------------------

      // MOV reg, imm32 / imm64 (0xB8..0xBF)
      // This is critical: if imm32/imm64 contains 0xE9, 0xE8, or 0xC3,
      // it MUST NOT be misdecoded as a jump!
      if (b0 >= 0xb8 && b0 <= 0xbf) {
        const regIdx = b0 - 0xb8;
        const immSize = rexW ? 8 : (hasOperandSizeOverride ? 2 : 4);
        if (offset + 1 + immSize <= bytes.byteLength) {
          offset += 1 + immSize;
          const size = offset - startOffset;
          instructions.push({
            address: addr,
            mnemonic: "mov",
            operands: `r${regIdx}, imm${immSize * 8}`,
            size,
            rawBytes: bytes.slice(startOffset, offset),
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            prefixes,
          });
          continue;
        }
      }

      // Common ModR/M instructions: MOV, LEA, ADD, SUB, CMP, XOR, TEST
      // 0x88, 0x89 (MOV r/m, r), 0x8A, 0x8B (MOV r, r/m), 0x8D (LEA)
      if (
        (b0 >= 0x88 && b0 <= 0x8b) ||
        b0 === 0x8d ||
        b0 === 0x31 || b0 === 0x33 ||
        b0 === 0x01 || b0 === 0x03 ||
        b0 === 0x29 || b0 === 0x2b ||
        b0 === 0x85
      ) {
        if (offset + 2 <= bytes.byteLength) {
          const modrmParsed = this.parseModRm(bytes, offset + 1, addr + (offset - startOffset));
          if (modrmParsed) {
            const mnemonic = b0 === 0x8d ? "lea" : (b0 >= 0x88 && b0 <= 0x8b) ? "mov" : "alu_op";
            offset += 1 + modrmParsed.totalModRmBytes;
            const size = offset - startOffset;
            instructions.push({
              address: addr,
              mnemonic,
              operands: modrmParsed.operandText,
              size,
              rawBytes: bytes.slice(startOffset, offset),
              isBranch: false,
              isConditional: false,
              isCall: false,
              isReturn: false,
              isIndirect: false,
              targetAddress: null,
              prefixes,
            });
            continue;
          }
        }
      }

      // Immediate ALU operations with ModR/M: 0x80, 0x81, 0x83
      if ((b0 === 0x80 || b0 === 0x81 || b0 === 0x83) && offset + 2 <= bytes.byteLength) {
        const modrmParsed = this.parseModRm(bytes, offset + 1, addr + (offset - startOffset));
        if (modrmParsed) {
          const immSize = b0 === 0x81 ? (hasOperandSizeOverride ? 2 : 4) : 1;
          const fullInstLen = 1 + modrmParsed.totalModRmBytes + immSize;
          if (offset + fullInstLen <= bytes.byteLength) {
            offset += fullInstLen;
            const size = offset - startOffset;
            instructions.push({
              address: addr,
              mnemonic: "alu_imm",
              operands: `${modrmParsed.operandText}, imm${immSize * 8}`,
              size,
              rawBytes: bytes.slice(startOffset, offset),
              isBranch: false,
              isConditional: false,
              isCall: false,
              isReturn: false,
              isIndirect: false,
              targetAddress: null,
              prefixes,
            });
            continue;
          }
        }
      }

      // PUSH / POP r64 (0x50 - 0x5F)
      if (b0 >= 0x50 && b0 <= 0x5f) {
        offset++;
        const isPush = b0 <= 0x57;
        const size = offset - startOffset;
        instructions.push({
          address: addr,
          mnemonic: isPush ? "push" : "pop",
          operands: `r${b0 & 0x07}`,
          size,
          rawBytes: bytes.slice(startOffset, offset),
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          prefixes,
        });
        continue;
      }

      // NOP (0x90)
      if (b0 === 0x90) {
        offset++;
        const size = offset - startOffset;
        instructions.push({
          address: addr,
          mnemonic: "nop",
          operands: "",
          size,
          rawBytes: bytes.slice(startOffset, offset),
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          prefixes,
        });
        continue;
      }

      // INT3 (0xCC)
      if (b0 === 0xcc) {
        offset++;
        const size = offset - startOffset;
        instructions.push({
          address: addr,
          mnemonic: "int3",
          operands: "",
          size,
          rawBytes: bytes.slice(startOffset, offset),
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          prefixes,
        });
        continue;
      }

      // Cannot establish a reliable x86-64 instruction boundary.
      // STOP decoding the affected region to prevent stream desynchronization
      // and phantom branch generation. Do not advance 1 byte into instruction payloads!
      const unhandledBytes = bytes.slice(startOffset);
      instructions.push({
        address: addr,
        mnemonic: "unsupported_instruction",
        operands: `0x${b0.toString(16).padStart(2, "0")}`,
        size: unhandledBytes.byteLength,
        rawBytes: unhandledBytes,
        isBranch: false,
        isConditional: false,
        isCall: false,
        isReturn: false,
        isIndirect: false,
        targetAddress: null,
        isMalformed: true,
        prefixes,
      });
      break;
    }

    return instructions;
  }

  /**
   * Parse x86-64 ModR/M and SIB addressing.
   * Returns total bytes consumed by ModR/M + SIB + displacement,
   * formatted operand text, and RIP-relative target if applicable.
   */
  private parseModRm(
    bytes: Uint8Array,
    modrmOffset: number,
    instAddr: number,
  ): {
    readonly totalModRmBytes: number;
    readonly operandText: string;
    readonly ripTargetAddress: number | null;
  } | null {
    if (modrmOffset >= bytes.byteLength) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const modrm = bytes[modrmOffset]!;
    const mod = (modrm >>> 6) & 0x03;
    const reg = (modrm >>> 3) & 0x07;
    const rm = modrm & 0x07;

    let consumed = 1; // 1 byte for ModR/M
    let hasSib = false;
    let sibByte = 0;
    let ripTargetAddress: number | null = null;
    let operandText = `r${reg}`;

    if (mod !== 3 && rm === 4) {
      // SIB byte present
      if (modrmOffset + 1 >= bytes.byteLength) return null;
      hasSib = true;
      sibByte = bytes[modrmOffset + 1]!;
      consumed += 1;
    }

    // Displacement calculation
    let dispSize = 0;
    let dispValue = 0;

    if (mod === 0) {
      if (!hasSib && rm === 5) {
        // RIP-relative addressing [rip + disp32] in 64-bit mode
        dispSize = 4;
      } else if (hasSib && (sibByte & 0x07) === 5) {
        // SIB base = 5 with mod = 0 -> disp32 without base register
        dispSize = 4;
      }
    } else if (mod === 1) {
      dispSize = 1;
    } else if (mod === 2) {
      dispSize = 4;
    }

    if (modrmOffset + consumed + dispSize > bytes.byteLength) {
      return null;
    }

    if (dispSize === 1) {
      dispValue = view.getInt8(modrmOffset + consumed);
      consumed += 1;
    } else if (dispSize === 4) {
      dispValue = view.getInt32(modrmOffset + consumed, true);
      consumed += 4;
    }

    if (mod === 0 && !hasSib && rm === 5) {
      const nextInstAddr = instAddr + consumed + 1; // +1 for opcode
      ripTargetAddress = (nextInstAddr + dispValue) >>> 0;
      operandText = `[rip + 0x${dispValue.toString(16)}]`;
    } else if (hasSib) {
      const scale = 1 << ((sibByte >>> 6) & 0x03);
      const index = (sibByte >>> 3) & 0x07;
      const base = sibByte & 0x07;
      operandText = `[r${base} + r${index}*${scale}${dispSize > 0 ? ` + 0x${dispValue.toString(16)}` : ""}]`;
    } else if (mod === 3) {
      operandText = `r${rm}`;
    } else {
      operandText = `[r${rm}${dispSize > 0 ? ` + 0x${dispValue.toString(16)}` : ""}]`;
    }

    return {
      totalModRmBytes: consumed,
      operandText,
      ripTargetAddress,
    };
  }

  private getX86ConditionName(code: number): string {
    const conditions = [
      "o", "no", "b", "ae", "e", "ne", "be", "a",
      "s", "ns", "p", "np", "l", "ge", "le", "g",
    ];
    return conditions[code] ?? "c";
  }

  // =========================================================================
  // ARM32 (A32) Instruction Decoder
  // =========================================================================
  private decodeArm(
    bytes: Uint8Array,
    baseAddress: number,
    isLE: boolean,
  ): Instruction[] {
    const instructions: Instruction[] = [];
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const count = Math.floor(bytes.byteLength / 4);

    for (let i = 0; i < count; i++) {
      const offset = i * 4;
      const addr = (baseAddress + offset) >>> 0;
      const raw = view.getUint32(offset, isLE);
      const rawBytes = bytes.slice(offset, offset + 4);

      const cond = (raw >>> 28) & 0x0f;
      const isCond = cond !== 0x0e && cond !== 0x0f; // 0xE = AL (always)
      const condSuffix = this.getArmConditionSuffix(cond);

      // 1. Branch / Branch with Link (B / BL): bits 27..25 = 0b101
      if (((raw >>> 25) & 0x07) === 0x05) {
        const isLink = ((raw >>> 24) & 0x01) === 0x01;
        let imm24 = raw & 0x00ffffff;
        if (imm24 & 0x00800000) imm24 |= 0xff000000;
        const target = (addr + 8 + (imm24 << 2)) >>> 0;
        const mnemonic = isLink ? `bl${condSuffix}` : `b${condSuffix}`;

        instructions.push({
          address: addr,
          mnemonic,
          operands: `0x${target.toString(16)}`,
          size: 4,
          rawBytes,
          isBranch: !isLink,
          isConditional: isCond,
          isCall: isLink,
          isReturn: false,
          isIndirect: false,
          targetAddress: target,
        });
        continue;
      }

      // 2. Branch and Exchange (BX): bits 27..4 = 0x012FFF1
      if ((raw & 0x0ffffff0) === 0x012fff10) {
        const rm = raw & 0x0f;
        const isRet = rm === 0x0e; // r14 = lr

        instructions.push({
          address: addr,
          mnemonic: isRet ? "bx lr" : `bx${condSuffix} r${rm}`,
          operands: isRet ? "lr" : `r${rm}`,
          size: 4,
          rawBytes,
          isBranch: !isRet,
          isConditional: isCond,
          isCall: false,
          isReturn: isRet,
          isIndirect: !isRet,
          targetAddress: null,
        });
        continue;
      }

      // 3. Branch, Link and Exchange (BLX Rm): bits 27..4 = 0x012FFF3
      if ((raw & 0x0ffffff0) === 0x012fff30) {
        const rm = raw & 0x0f;
        instructions.push({
          address: addr,
          mnemonic: `blx${condSuffix}`,
          operands: `r${rm}`,
          size: 4,
          rawBytes,
          isBranch: false,
          isConditional: isCond,
          isCall: true,
          isReturn: false,
          isIndirect: true,
          targetAddress: null,
        });
        continue;
      }

      // 4. Return via POP {..., PC} or LDMIA SP!, {..., PC}
      // Bit 15 set (PC in reglist), bits 27..20 = 0x8B (LDMIA SP!) or 0x89
      if (((raw >>> 20) & 0xff) === 0x8b && (raw & 0x00008000) !== 0) {
        instructions.push({
          address: addr,
          mnemonic: `pop${condSuffix} {..., pc}`,
          operands: "pc",
          size: 4,
          rawBytes,
          isBranch: false,
          isConditional: isCond,
          isCall: false,
          isReturn: true,
          isIndirect: false,
          targetAddress: null,
        });
        continue;
      }

      // 5. Return via MOV PC, LR: bits 27..20 = 0x1A, Rd = 15, Rm = 14
      if ((raw & 0x0ffffff0) === 0x01a0f00e) {
        instructions.push({
          address: addr,
          mnemonic: `mov${condSuffix} pc, lr`,
          operands: "pc, lr",
          size: 4,
          rawBytes,
          isBranch: false,
          isConditional: isCond,
          isCall: false,
          isReturn: true,
          isIndirect: false,
          targetAddress: null,
        });
        continue;
      }

      // 6. LDR PC, [Rn, #offset] (Indirect branch / Jump Table)
      if (((raw >>> 20) & 0xfd) === 0x59 && ((raw >>> 12) & 0x0f) === 15) {
        const rn = (raw >>> 16) & 0x0f;
        instructions.push({
          address: addr,
          mnemonic: `ldr${condSuffix} pc, [r${rn}]`,
          operands: `pc, [r${rn}]`,
          size: 4,
          rawBytes,
          isBranch: true,
          isConditional: isCond,
          isCall: false,
          isReturn: false,
          isIndirect: true,
          targetAddress: null,
        });
        continue;
      }

      // Default generic ARM instruction
      instructions.push({
        address: addr,
        mnemonic: "arm_inst",
        operands: `0x${raw.toString(16).padStart(8, "0")}`,
        size: 4,
        rawBytes,
        isBranch: false,
        isConditional: isCond,
        isCall: false,
        isReturn: false,
        isIndirect: false,
        targetAddress: null,
      });
    }

    // Fail closed on unaligned trailing bytes
    if (bytes.byteLength % 4 !== 0) {
      const remainingOffset = count * 4;
      const rawBytes = bytes.slice(remainingOffset);
      instructions.push({
        address: (baseAddress + remainingOffset) >>> 0,
        mnemonic: "malformed_unaligned",
        operands: "",
        size: rawBytes.byteLength,
        rawBytes,
        isBranch: false,
        isConditional: false,
        isCall: false,
        isReturn: false,
        isIndirect: false,
        targetAddress: null,
        isMalformed: true,
      });
    }

    return instructions;
  }

  private getArmConditionSuffix(cond: number): string {
    const conds = [
      "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
      "hi", "ls", "ge", "lt", "gt", "le", "", "nv",
    ];
    return conds[cond] ?? "";
  }

  // =========================================================================
  // ARM Thumb & Thumb-2 Instruction Decoder
  // =========================================================================
  private decodeThumb(
    bytes: Uint8Array,
    baseAddress: number,
    isLE: boolean,
  ): Instruction[] {
    const instructions: Instruction[] = [];
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 0;

    while (offset < bytes.byteLength) {
      if (offset + 2 > bytes.byteLength) {
        // Fail closed on trailing unaligned single byte
        instructions.push({
          address: (baseAddress + offset) >>> 0,
          mnemonic: "raw_byte",
          operands: `0x${bytes[offset]!.toString(16).padStart(2, "0")}`,
          size: 1,
          rawBytes: bytes.slice(offset, offset + 1),
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          isMalformed: true,
        });
        break;
      }

      const addr = (baseAddress + offset) >>> 0;
      const raw16 = view.getUint16(offset, isLE);

      // -------------------------------------------------------------
      // 32-bit Thumb-2 Instructions (Prefixes: 0b11101, 0b11110, 0b11111)
      // -------------------------------------------------------------
      const prefix = (raw16 >>> 11) & 0x1f;
      if (prefix === 0x1d || prefix === 0x1e || prefix === 0x1f) {
        if (offset + 4 > bytes.byteLength) {
          // Truncated 32-bit Thumb instruction -> fail closed
          instructions.push({
            address: addr,
            mnemonic: "truncated_thumb32",
            operands: "",
            size: bytes.byteLength - offset,
            rawBytes: bytes.slice(offset),
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            isMalformed: true,
          });
          break;
        }

        const raw16_2 = view.getUint16(offset + 2, isLE);

        // BL / BLX (Thumb-2): 0b11110_S_imm10 ... 0b11_J1_1_J2_imm11
        const isBL = (raw16 >>> 12) === 0x0f && ((raw16_2 >>> 14) & 0x03) === 0x03;
        if (isBL) {
          const s = (raw16 >>> 10) & 1;
          const imm10 = raw16 & 0x03ff;
          const j1 = (raw16_2 >>> 13) & 1;
          const j2 = (raw16_2 >>> 11) & 1;
          const imm11 = raw16_2 & 0x07ff;
          const i1 = ~(j1 ^ s) & 1;
          const i2 = ~(j2 ^ s) & 1;
          let imm25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
          if (imm25 & 0x01000000) imm25 |= 0xfe000000;
          const target = (addr + 4 + imm25) >>> 0;

          instructions.push({
            address: addr,
            mnemonic: "bl",
            operands: `0x${target.toString(16)}`,
            size: 4,
            rawBytes: bytes.slice(offset, offset + 4),
            isBranch: false,
            isConditional: false,
            isCall: true,
            isReturn: false,
            isIndirect: false,
            targetAddress: target,
          });
          offset += 4;
          continue;
        }

        // B.W (32-bit unconditional branch): 0b11110_S_imm10 ... 0b10_J1_0_J2_imm11
        const isBW = (raw16 >>> 12) === 0x0f && ((raw16_2 >>> 14) & 0x03) === 0x02;
        if (isBW) {
          const s = (raw16 >>> 10) & 1;
          const imm10 = raw16 & 0x03ff;
          const j1 = (raw16_2 >>> 13) & 1;
          const j2 = (raw16_2 >>> 11) & 1;
          const imm11 = raw16_2 & 0x07ff;
          const i1 = ~(j1 ^ s) & 1;
          const i2 = ~(j2 ^ s) & 1;
          let imm25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
          if (imm25 & 0x01000000) imm25 |= 0xfe000000;
          const target = (addr + 4 + imm25) >>> 0;

          instructions.push({
            address: addr,
            mnemonic: "b.w",
            operands: `0x${target.toString(16)}`,
            size: 4,
            rawBytes: bytes.slice(offset, offset + 4),
            isBranch: true,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: target,
          });
          offset += 4;
          continue;
        }

        // Generic 32-bit Thumb-2 instruction
        instructions.push({
          address: addr,
          mnemonic: "thumb32_inst",
          operands: `0x${raw16.toString(16).padStart(4, "0")}${raw16_2.toString(16).padStart(4, "0")}`,
          size: 4,
          rawBytes: bytes.slice(offset, offset + 4),
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
        });
        offset += 4;
        continue;
      }

      // -------------------------------------------------------------
      // 16-bit Thumb Instructions (T16)
      // -------------------------------------------------------------

      // 1. BX / BLX Rm: 0b01000111_xxxx_xxxx (0x4700..0x4778)
      if ((raw16 & 0xff87) === 0x4700) {
        const rm = (raw16 >>> 3) & 0x0f;
        const isRet = rm === 14;
        const isLink = ((raw16 >>> 7) & 1) === 1;

        instructions.push({
          address: addr,
          mnemonic: isRet ? "bx lr" : isLink ? `blx r${rm}` : `bx r${rm}`,
          operands: isRet ? "lr" : `r${rm}`,
          size: 2,
          rawBytes: bytes.slice(offset, offset + 2),
          isBranch: !isRet && !isLink,
          isConditional: false,
          isCall: isLink,
          isReturn: isRet,
          isIndirect: !isRet,
          targetAddress: null,
        });
        offset += 2;
        continue;
      }

      // 2. POP {..., PC}: 0b1011110_1_xxxxxxxx (0xBD00..0xBDF8)
      if ((raw16 & 0xff00) === 0xbd00) {
        instructions.push({
          address: addr,
          mnemonic: "pop {..., pc}",
          operands: "pc",
          size: 2,
          rawBytes: bytes.slice(offset, offset + 2),
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: true,
          isIndirect: false,
          targetAddress: null,
        });
        offset += 2;
        continue;
      }

      // 3. Unconditional branch B imm11: 0b11100_xxxxxxxxxxx (0xE000..0xE7FF)
      if ((raw16 & 0xf800) === 0xe000) {
        let imm11 = raw16 & 0x07ff;
        if (imm11 & 0x0400) imm11 |= 0xfffff800;
        const target = (addr + 4 + (imm11 << 1)) >>> 0;

        instructions.push({
          address: addr,
          mnemonic: "b",
          operands: `0x${target.toString(16)}`,
          size: 2,
          rawBytes: bytes.slice(offset, offset + 2),
          isBranch: true,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: target,
        });
        offset += 2;
        continue;
      }

      // 4. Conditional branch B<cond> imm8: 0b1101_xxxx_xxxxxxxx (0xD000..0xDFFF)
      // Note: 0xDE00 is undefined and 0xDF00 is SVC
      if ((raw16 & 0xf000) === 0xd000 && (raw16 & 0x0e00) !== 0x0e00) {
        let imm8 = raw16 & 0x00ff;
        if (imm8 & 0x80) imm8 |= 0xffffff00;
        const target = (addr + 4 + (imm8 << 1)) >>> 0;
        const cond = (raw16 >>> 8) & 0x0f;
        const condSuffix = this.getArmConditionSuffix(cond);

        instructions.push({
          address: addr,
          mnemonic: `b${condSuffix}`,
          operands: `0x${target.toString(16)}`,
          size: 2,
          rawBytes: bytes.slice(offset, offset + 2),
          isBranch: true,
          isConditional: true,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: target,
        });
        offset += 2;
        continue;
      }

      // 5. CBZ / CBNZ Rn, imm (0xB100..0xB3FF / 0xB900..0xBBFF)
      if ((raw16 & 0xf500) === 0xb100) {
        const isCbnz = (raw16 & 0x0800) !== 0;
        const rn = raw16 & 0x07;
        const i = (raw16 >>> 9) & 1;
        const imm5 = (raw16 >>> 3) & 0x1f;
        const imm = (i << 6) | (imm5 << 1);
        const target = (addr + 4 + imm) >>> 0;

        instructions.push({
          address: addr,
          mnemonic: isCbnz ? "cbnz" : "cbz",
          operands: `r${rn}, 0x${target.toString(16)}`,
          size: 2,
          rawBytes: bytes.slice(offset, offset + 2),
          isBranch: true,
          isConditional: true,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: target,
        });
        offset += 2;
        continue;
      }

      // 6. IT (If-Then) block: 0xBF00..0xBFEE (mask != 0)
      if ((raw16 & 0xff00) === 0xbf00 && (raw16 & 0x000f) !== 0) {
        instructions.push({
          address: addr,
          mnemonic: "it",
          operands: `cond=0x${((raw16 >>> 4) & 0x0f).toString(16)}`,
          size: 2,
          rawBytes: bytes.slice(offset, offset + 2),
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
        });
        offset += 2;
        continue;
      }

      // Generic 16-bit Thumb instruction
      instructions.push({
        address: addr,
        mnemonic: "thumb16_inst",
        operands: `0x${raw16.toString(16).padStart(4, "0")}`,
        size: 2,
        rawBytes: bytes.slice(offset, offset + 2),
        isBranch: false,
        isConditional: false,
        isCall: false,
        isReturn: false,
        isIndirect: false,
        targetAddress: null,
      });
      offset += 2;
    }

    return instructions;
  }

  // =========================================================================
  // MIPS32 Instruction Decoder (LE and BE with Delay Slots)
  // =========================================================================
  private decodeMipsInstruction(
    raw: number,
    addr: number,
    rawBytes: Uint8Array,
  ): Instruction {
    const opcode = (raw >>> 26) & 0x3f;

    // J (Jump): opcode 0x02
    if (opcode === 0x02) {
      const target = (((addr + 4) & 0xf0000000) | ((raw & 0x03ffffff) << 2)) >>> 0;
      return {
        address: addr,
        mnemonic: "j",
        operands: `0x${target.toString(16)}`,
        size: 4,
        rawBytes,
        isBranch: true,
        isConditional: false,
        isCall: false,
        isReturn: false,
        isIndirect: false,
        targetAddress: target,
        hasDelaySlot: true,
        isaMode: "MIPS32",
      };
    }

    // JAL (Jump and Link / Call): opcode 0x03
    if (opcode === 0x03) {
      const target = (((addr + 4) & 0xf0000000) | ((raw & 0x03ffffff) << 2)) >>> 0;
      return {
        address: addr,
        mnemonic: "jal",
        operands: `0x${target.toString(16)}`,
        size: 4,
        rawBytes,
        isBranch: false,
        isConditional: false,
        isCall: true,
        isReturn: false,
        isIndirect: false,
        targetAddress: target,
        hasDelaySlot: true,
        isaMode: "MIPS32",
      };
    }

    // JALX (Jump and Link Exchange to MIPS16): opcode 0x1d
    if (opcode === 0x1d) {
      const target = ((((addr + 4) & 0xf0000000) | ((raw & 0x03ffffff) << 2)) | 1) >>> 0;
      return {
        address: addr,
        mnemonic: "jalx",
        operands: `0x${(target & ~1).toString(16)}`,
        size: 4,
        rawBytes,
        isBranch: false,
        isConditional: false,
        isCall: true,
        isReturn: false,
        isIndirect: false,
        targetAddress: target,
        hasDelaySlot: true,
        isaMode: "MIPS32",
      };
    }

    // SPECIAL opcodes (opcode 0x00)
    if (opcode === 0x00) {
      const funct = raw & 0x3f;
      const rs = (raw >>> 21) & 0x1f;

      // JR (Jump Register): funct 0x08
      if (funct === 0x08) {
        const isRet = rs === 31; // $ra
        return {
          address: addr,
          mnemonic: isRet ? "jr $ra" : `jr $r${rs}`,
          operands: isRet ? "$ra" : `$r${rs}`,
          size: 4,
          rawBytes,
          isBranch: !isRet,
          isConditional: false,
          isCall: false,
          isReturn: isRet,
          isIndirect: !isRet,
          targetAddress: null,
          hasDelaySlot: true,
          isaMode: "MIPS32",
        };
      }

      // JALR (Jump and Link Register): funct 0x09
      if (funct === 0x09) {
        return {
          address: addr,
          mnemonic: "jalr",
          operands: `$r${rs}`,
          size: 4,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: true,
          isReturn: false,
          isIndirect: true,
          targetAddress: null,
          hasDelaySlot: true,
          isaMode: "MIPS32",
        };
      }
    }

    // REGIMM branches (opcode 0x01): BLTZ (rt=0), BGEZ (rt=1), BLTZAL (rt=16), BGEZAL (rt=17)
    if (opcode === 0x01) {
      const rt = (raw >>> 16) & 0x1f;
      let imm16 = raw & 0xffff;
      if (imm16 & 0x8000) imm16 |= 0xffff0000;
      const target = (addr + 4 + (imm16 << 2)) >>> 0;
      const isCall = rt === 16 || rt === 17;
      const mnemonic =
        rt === 0
          ? "bltz"
          : rt === 1
            ? "bgez"
            : rt === 16
              ? "bltzal"
              : rt === 17
                ? "bgezal"
                : "regimm_branch";

      return {
        address: addr,
        mnemonic,
        operands: `0x${target.toString(16)}`,
        size: 4,
        rawBytes,
        isBranch: !isCall,
        isConditional: true,
        isCall,
        isReturn: false,
        isIndirect: false,
        targetAddress: target,
        hasDelaySlot: true,
        isaMode: "MIPS32",
      };
    }

    // Conditional branches: BEQ (0x04), BNE (0x05), BLEZ (0x06), BGTZ (0x07)
    if (opcode === 0x04 || opcode === 0x05 || opcode === 0x06 || opcode === 0x07) {
      let imm16 = raw & 0xffff;
      if (imm16 & 0x8000) imm16 |= 0xffff0000;
      const target = (addr + 4 + (imm16 << 2)) >>> 0;
      const mnemonic =
        opcode === 0x04 ? "beq" : opcode === 0x05 ? "bne" : opcode === 0x06 ? "blez" : "bgtz";

      return {
        address: addr,
        mnemonic,
        operands: `0x${target.toString(16)}`,
        size: 4,
        rawBytes,
        isBranch: true,
        isConditional: true,
        isCall: false,
        isReturn: false,
        isIndirect: false,
        targetAddress: target,
        hasDelaySlot: true,
        isaMode: "MIPS32",
      };
    }

    // Default generic MIPS32 instruction
    return {
      address: addr,
      mnemonic: "mips_inst",
      operands: `0x${raw.toString(16).padStart(8, "0")}`,
      size: 4,
      rawBytes,
      isBranch: false,
      isConditional: false,
      isCall: false,
      isReturn: false,
      isIndirect: false,
      targetAddress: null,
      isaMode: "MIPS32",
    };
  }

  private decodeMips(
    bytes: Uint8Array,
    baseAddress: number,
    isLE: boolean,
  ): Instruction[] {
    const instructions: Instruction[] = [];
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const count = Math.floor(bytes.byteLength / 4);

    for (let i = 0; i < count; i++) {
      const offset = i * 4;
      const addr = (baseAddress + offset) >>> 0;
      const raw = view.getUint32(offset, isLE);
      const rawBytes = bytes.slice(offset, offset + 4);
      instructions.push(this.decodeMipsInstruction(raw, addr, rawBytes));
    }

    // Fail closed on unaligned trailing bytes
    if (bytes.byteLength % 4 !== 0) {
      const remainingOffset = count * 4;
      const rawBytes = bytes.slice(remainingOffset);
      instructions.push({
        address: (baseAddress + remainingOffset) >>> 0,
        mnemonic: "malformed_unaligned",
        operands: "",
        size: rawBytes.byteLength,
        rawBytes,
        isBranch: false,
        isConditional: false,
        isCall: false,
        isReturn: false,
        isIndirect: false,
        targetAddress: null,
        isMalformed: true,
        isaMode: "MIPS32",
      });
    }

    return instructions;
  }

  // =========================================================================
  // MIPS16 Instruction Decoder (Variable-length 16-bit / 32-bit instructions)
  // =========================================================================
  private static readonly M16_REG_NAMES = ["$s0", "$s1", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3"];
  private static readonly M16_R32_NAMES = [
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
  ];

  private decodeMips16Instruction(
    view: DataView,
    offset: number,
    addr: number,
    isLE: boolean,
    bytes: Uint8Array,
  ): { inst: Instruction; bytesRead: number } {
    if (offset + 2 > bytes.byteLength) {
      const rawBytes = bytes.slice(offset);
      return {
        inst: {
          address: addr,
          mnemonic: "malformed_unaligned",
          operands: "",
          size: rawBytes.byteLength,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          isMalformed: true,
          isaMode: "MIPS16",
        },
        bytesRead: rawBytes.byteLength,
      };
    }

    const w16 = view.getUint16(offset, isLE);
    const opcode = (w16 >>> 11) & 0x1f;

    // =========================================================================
    // Case 1: EXTEND prefix (0xf000..0xf7ff, opcode 0x1e) - 32-bit instruction
    // =========================================================================
    if (opcode === 0x1e) {
      if (offset + 4 > bytes.byteLength) {
        const rawBytes = bytes.slice(offset);
        return {
          inst: {
            address: addr,
            mnemonic: "malformed_extend_truncated",
            operands: "",
            size: rawBytes.byteLength,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            isMalformed: true,
            isaMode: "MIPS16",
          },
          bytesRead: rawBytes.byteLength,
        };
      }

      const next16 = view.getUint16(offset + 2, isLE);
      const rawBytes = bytes.slice(offset, offset + 4);
      const nextOpcode = (next16 >>> 11) & 0x1f;

      // Extended save: next16 has (w & 0xff80) == 0x6480
      if ((next16 & 0xff80) === 0x6480) {
        return {
          inst: {
            address: addr,
            mnemonic: "save",
            operands: "",
            size: 4,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 4,
        };
      }

      // Extended restore: next16 has (w & 0xff80) == 0x6400
      if ((next16 & 0xff80) === 0x6400) {
        return {
          inst: {
            address: addr,
            mnemonic: "restore",
            operands: "",
            size: 4,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 4,
        };
      }

      // Extended b: opcode 0x02
      if (nextOpcode === 0x02) {
        let imm = ((w16 & 0x1f) << 11) | (next16 & 0x7ff);
        if (imm & 0x8000) imm |= 0xffff0000;
        const target = (addr + 4 + (imm << 1)) >>> 0;
        return {
          inst: {
            address: addr,
            mnemonic: "b",
            operands: `0x${target.toString(16)}`,
            size: 4,
            rawBytes,
            isBranch: true,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: target,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 4,
        };
      }

      // Extended beqz: opcode 0x04
      if (nextOpcode === 0x04) {
        const rx = (next16 >>> 8) & 0x7;
        let imm = ((w16 & 0x1f) << 11) | (next16 & 0xff);
        if (imm & 0x8000) imm |= 0xffff0000;
        const target = (addr + 4 + (imm << 1)) >>> 0;
        return {
          inst: {
            address: addr,
            mnemonic: "beqz",
            operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, 0x${target.toString(16)}`,
            size: 4,
            rawBytes,
            isBranch: true,
            isConditional: true,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: target,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 4,
        };
      }

      // Extended bnez: opcode 0x05
      if (nextOpcode === 0x05) {
        const rx = (next16 >>> 8) & 0x7;
        let imm = ((w16 & 0x1f) << 11) | (next16 & 0xff);
        if (imm & 0x8000) imm |= 0xffff0000;
        const target = (addr + 4 + (imm << 1)) >>> 0;
        return {
          inst: {
            address: addr,
            mnemonic: "bnez",
            operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, 0x${target.toString(16)}`,
            size: 4,
            rawBytes,
            isBranch: true,
            isConditional: true,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: target,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 4,
        };
      }

      // Extended bteqz: next16 & 0xff00 === 0x6000
      if ((next16 & 0xff00) === 0x6000) {
        let imm = ((w16 & 0x1f) << 11) | (next16 & 0xff);
        if (imm & 0x8000) imm |= 0xffff0000;
        const target = (addr + 4 + (imm << 1)) >>> 0;
        return {
          inst: {
            address: addr,
            mnemonic: "bteqz",
            operands: `0x${target.toString(16)}`,
            size: 4,
            rawBytes,
            isBranch: true,
            isConditional: true,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: target,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 4,
        };
      }

      // Extended btnez: next16 & 0xff00 === 0x6100
      if ((next16 & 0xff00) === 0x6100) {
        let imm = ((w16 & 0x1f) << 11) | (next16 & 0xff);
        if (imm & 0x8000) imm |= 0xffff0000;
        const target = (addr + 4 + (imm << 1)) >>> 0;
        return {
          inst: {
            address: addr,
            mnemonic: "btnez",
            operands: `0x${target.toString(16)}`,
            size: 4,
            rawBytes,
            isBranch: true,
            isConditional: true,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: target,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 4,
        };
      }

      // Reserved / invalid extended opcodes
      if (nextOpcode === 0x07 || nextOpcode === 0x0f || nextOpcode === 0x17 || nextOpcode === 0x1f) {
        return {
          inst: {
            address: addr,
            mnemonic: "unsupported_mips16_ext",
            operands: `0x${w16.toString(16).padStart(4, "0")}${next16.toString(16).padStart(4, "0")}`,
            size: 4,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            hasDelaySlot: false,
            isMalformed: true,
            isaMode: "MIPS16",
          },
          bytesRead: 4,
        };
      }

      // General extended instructions (ALU, load, store, shift, li)
      let extMnem = "addiu";
      let extOps = "";
      const rx = (next16 >>> 8) & 0x7;
      const ry = (next16 >>> 5) & 0x7;
      const imm16 = (((w16 & 0x1f) << 11) | (next16 & 0x7ff)) << 16 >> 16;

      switch (nextOpcode) {
        case 0x00:
          extMnem = "addiu";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, $sp, ${imm16}`;
          break;
        case 0x01:
          extMnem = "addiu";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, $pc, ${imm16}`;
          break;
        case 0x06:
          extMnem = (next16 & 0x3) === 0 ? "sll" : (next16 & 0x3) === 2 ? "srl" : "sra";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${(w16 & 0x1f)}`;
          break;
        case 0x08:
          extMnem = "addiu";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm16}`;
          break;
        case 0x09:
          extMnem = "addiu";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm16}`;
          break;
        case 0x0a:
          extMnem = "slti";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm16}`;
          break;
        case 0x0b:
          extMnem = "sltiu";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm16}`;
          break;
        case 0x0c:
          extMnem = "addiu";
          extOps = `$sp, ${imm16}`;
          break;
        case 0x0d:
          extMnem = "li";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm16}`;
          break;
        case 0x0e:
          extMnem = "cmpi";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm16}`;
          break;
        case 0x10:
          extMnem = "lb";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm16}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`;
          break;
        case 0x11:
          extMnem = "lh";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm16}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`;
          break;
        case 0x12:
          extMnem = "lw";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm16}($sp)`;
          break;
        case 0x13:
          extMnem = "lw";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm16}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`;
          break;
        case 0x14:
          extMnem = "lbu";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm16}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`;
          break;
        case 0x15:
          extMnem = "lhu";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm16}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`;
          break;
        case 0x18:
          extMnem = "sb";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm16}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`;
          break;
        case 0x19:
          extMnem = "sh";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm16}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`;
          break;
        case 0x1a:
          extMnem = "sw";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm16}($sp)`;
          break;
        case 0x1b:
          extMnem = "sw";
          extOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm16}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`;
          break;
        default:
          extMnem = "extended_alu";
          extOps = `0x${imm16.toString(16)}`;
          break;
      }

      return {
        inst: {
          address: addr,
          mnemonic: extMnem,
          operands: extOps,
          size: 4,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 4,
      };
    }

    // =========================================================================
    // Case 2: JAL / JALX (opcode 0x03: 0x1800..0x1fff) - 32-bit call instruction
    // =========================================================================
    if (opcode === 0x03) {
      if (offset + 4 > bytes.byteLength) {
        const rawBytes = bytes.slice(offset);
        return {
          inst: {
            address: addr,
            mnemonic: "malformed_jal_truncated",
            operands: "",
            size: rawBytes.byteLength,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            isMalformed: true,
            isaMode: "MIPS16",
          },
          bytesRead: rawBytes.byteLength,
        };
      }

      const w2 = view.getUint16(offset + 2, isLE);
      const rawBytes = bytes.slice(offset, offset + 4);
      const isJalx = ((w16 >>> 10) & 1) === 1;
      const tgt_2016 = (w16 >>> 5) & 0x1f;
      const tgt_2521 = w16 & 0x1f;
      const tgt_1500 = w2 & 0xffff;
      const target = (((addr + 4) & 0xf0000000) | (tgt_2521 << 23) | (tgt_2016 << 18) | (tgt_1500 << 2)) >>> 0;

      if (!isJalx) {
        // JAL calls MIPS16 function: LSB set to 1
        const mips16Target = (target | 1) >>> 0;
        return {
          inst: {
            address: addr,
            mnemonic: "jal",
            operands: `0x${(target & ~1).toString(16)}`,
            size: 4,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: true,
            isReturn: false,
            isIndirect: false,
            targetAddress: mips16Target,
            hasDelaySlot: true,
            isaMode: "MIPS16",
          },
          bytesRead: 4,
        };
      } else {
        // JALX switches to MIPS32 function: LSB cleared to 0
        const mips32Target = (target & ~1) >>> 0;
        return {
          inst: {
            address: addr,
            mnemonic: "jalx",
            operands: `0x${mips32Target.toString(16)}`,
            size: 4,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: true,
            isReturn: false,
            isIndirect: false,
            targetAddress: mips32Target,
            hasDelaySlot: true,
            isaMode: "MIPS16",
          },
          bytesRead: 4,
        };
      }
    }

    // =========================================================================
    // Case 3: 2-byte MIPS16 instructions
    // =========================================================================
    const rawBytes = bytes.slice(offset, offset + 2);
    const rx = (w16 >>> 8) & 0x7;
    const ry = (w16 >>> 5) & 0x7;
    const rz = (w16 >>> 2) & 0x7;

    // Opcode 0x00: addiu rx, sp, imm8*4
    if (opcode === 0x00) {
      const imm = (w16 & 0xff) * 4;
      return {
        inst: {
          address: addr,
          mnemonic: "addiu",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, $sp, ${imm}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x01: addiu rx, pc, imm8*4
    if (opcode === 0x01) {
      const imm = (w16 & 0xff) * 4;
      return {
        inst: {
          address: addr,
          mnemonic: "addiu",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, $pc, ${imm}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Unconditional branch: b (opcode 0x02: 0x1000..0x17ff)
    if (opcode === 0x02) {
      let imm11 = w16 & 0x7ff;
      if (imm11 & 0x400) imm11 |= 0xfffff800;
      const target = (addr + 2 + (imm11 << 1)) >>> 0;
      return {
        inst: {
          address: addr,
          mnemonic: "b",
          operands: `0x${target.toString(16)}`,
          size: 2,
          rawBytes,
          isBranch: true,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: target,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Conditional branch: beqz (opcode 0x04: 0x2000..0x27ff)
    if (opcode === 0x04) {
      let imm8 = w16 & 0xff;
      if (imm8 & 0x80) imm8 |= 0xffffff00;
      const target = (addr + 2 + (imm8 << 1)) >>> 0;
      return {
        inst: {
          address: addr,
          mnemonic: "beqz",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, 0x${target.toString(16)}`,
          size: 2,
          rawBytes,
          isBranch: true,
          isConditional: true,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: target,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Conditional branch: bnez (opcode 0x05: 0x2800..0x2fff)
    if (opcode === 0x05) {
      let imm8 = w16 & 0xff;
      if (imm8 & 0x80) imm8 |= 0xffffff00;
      const target = (addr + 2 + (imm8 << 1)) >>> 0;
      return {
        inst: {
          address: addr,
          mnemonic: "bnez",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, 0x${target.toString(16)}`,
          size: 2,
          rawBytes,
          isBranch: true,
          isConditional: true,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: target,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x06: SHIFT (sll, srl, sra)
    if (opcode === 0x06) {
      const sa = (w16 >>> 2) & 0x7;
      const funct = w16 & 0x3;
      const mnem = funct === 0 ? "sll" : funct === 2 ? "srl" : "sra";
      return {
        inst: {
          address: addr,
          mnemonic: mnem,
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${sa}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x07: Reserved encoding
    if (opcode === 0x07) {
      return {
        inst: {
          address: addr,
          mnemonic: "unsupported_mips16_07",
          operands: `0x${w16.toString(16).padStart(4, "0")}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isMalformed: true,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x08: addiu ry, rx, imm4
    if (opcode === 0x08) {
      const imm4 = w16 & 0xf;
      return {
        inst: {
          address: addr,
          mnemonic: "addiu",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm4}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x09: addiu rx, imm8
    if (opcode === 0x09) {
      let imm8 = w16 & 0xff;
      if (imm8 & 0x80) imm8 |= 0xffffff00;
      return {
        inst: {
          address: addr,
          mnemonic: "addiu",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm8}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x0a: slti rx, imm8
    if (opcode === 0x0a) {
      const imm8 = w16 & 0xff;
      return {
        inst: {
          address: addr,
          mnemonic: "slti",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm8}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x0b: sltiu rx, imm8
    if (opcode === 0x0b) {
      const imm8 = w16 & 0xff;
      return {
        inst: {
          address: addr,
          mnemonic: "sltiu",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm8}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x0c: I8 format (bteqz, btnez, adjsp, save, restore, move, nop)
    if (opcode === 0x0c) {
      const funct = (w16 >>> 8) & 0x7;

      // bteqz (funct 0b000: 0x6000..0x60ff)
      if (funct === 0) {
        let imm8 = w16 & 0xff;
        if (imm8 & 0x80) imm8 |= 0xffffff00;
        const target = (addr + 2 + (imm8 << 1)) >>> 0;
        return {
          inst: {
            address: addr,
            mnemonic: "bteqz",
            operands: `0x${target.toString(16)}`,
            size: 2,
            rawBytes,
            isBranch: true,
            isConditional: true,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: target,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 2,
        };
      }

      // btnez (funct 0b001: 0x6100..0x61ff)
      if (funct === 1) {
        let imm8 = w16 & 0xff;
        if (imm8 & 0x80) imm8 |= 0xffffff00;
        const target = (addr + 2 + (imm8 << 1)) >>> 0;
        return {
          inst: {
            address: addr,
            mnemonic: "btnez",
            operands: `0x${target.toString(16)}`,
            size: 2,
            rawBytes,
            isBranch: true,
            isConditional: true,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: target,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 2,
        };
      }

      // adjsp (funct 0b011: 0x6300..0x63ff)
      if (funct === 3) {
        let imm8 = w16 & 0xff;
        if (imm8 & 0x80) imm8 |= 0xffffff00;
        const imm = imm8 * 8;
        return {
          inst: {
            address: addr,
            mnemonic: "adjsp",
            operands: `$sp, ${imm}`,
            size: 2,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 2,
        };
      }

      // save (0x6480..0x64ff) / restore (0x6400..0x647f)
      if (funct === 4) {
        const isSave = (w16 & 0x80) === 0x80;
        return {
          inst: {
            address: addr,
            mnemonic: isSave ? "save" : "restore",
            operands: "",
            size: 2,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 2,
        };
      }

      // move r32, rz (funct 0b101: 0x6500..0x65ff)
      if (funct === 5) {
        const imm = w16 & 0xff;
        if (imm === 0 && rz === 0) {
          return {
            inst: {
              address: addr,
              mnemonic: "nop",
              operands: "",
              size: 2,
              rawBytes,
              isBranch: false,
              isConditional: false,
              isCall: false,
              isReturn: false,
              isIndirect: false,
              targetAddress: null,
              hasDelaySlot: false,
              isaMode: "MIPS16",
            },
            bytesRead: 2,
          };
        }
        const r32Idx = (w16 & 0x1f);
        return {
          inst: {
            address: addr,
            mnemonic: "move",
            operands: `${InProcessInstructionDecoder.M16_R32_NAMES[r32Idx]}, ${InProcessInstructionDecoder.M16_REG_NAMES[rz]}`,
            size: 2,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 2,
        };
      }

      // move ry, r32 (funct 0b111: 0x6700..0x67ff)
      if (funct === 7) {
        const r32Idx = w16 & 0x1f;
        return {
          inst: {
            address: addr,
            mnemonic: "move",
            operands: `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${InProcessInstructionDecoder.M16_R32_NAMES[r32Idx]}`,
            size: 2,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            hasDelaySlot: false,
            isaMode: "MIPS16",
          },
          bytesRead: 2,
        };
      }
    }

    // Opcode 0x0d: li rx, imm8
    if (opcode === 0x0d) {
      const imm8 = w16 & 0xff;
      return {
        inst: {
          address: addr,
          mnemonic: "li",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm8}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x0e: cmpi rx, imm8
    if (opcode === 0x0e) {
      const imm8 = w16 & 0xff;
      return {
        inst: {
          address: addr,
          mnemonic: "cmpi",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm8}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x0f: Reserved
    if (opcode === 0x0f) {
      return {
        inst: {
          address: addr,
          mnemonic: "unsupported_mips16_0f",
          operands: `0x${w16.toString(16).padStart(4, "0")}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isMalformed: true,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x10: lb ry, imm5(rx)
    if (opcode === 0x10) {
      const imm5 = w16 & 0x1f;
      return {
        inst: {
          address: addr,
          mnemonic: "lb",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm5}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x11: lh ry, imm5*2(rx)
    if (opcode === 0x11) {
      const imm = (w16 & 0x1f) * 2;
      return {
        inst: {
          address: addr,
          mnemonic: "lh",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x12: lw rx, imm8*4(sp)
    if (opcode === 0x12) {
      const imm = (w16 & 0xff) * 4;
      return {
        inst: {
          address: addr,
          mnemonic: "lw",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm}($sp)`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x13: lw ry, imm5*4(rx)
    if (opcode === 0x13) {
      const imm = (w16 & 0x1f) * 4;
      return {
        inst: {
          address: addr,
          mnemonic: "lw",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x14: lbu ry, imm5(rx)
    if (opcode === 0x14) {
      const imm5 = w16 & 0x1f;
      return {
        inst: {
          address: addr,
          mnemonic: "lbu",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm5}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x15: lhu ry, imm5*2(rx)
    if (opcode === 0x15) {
      const imm = (w16 & 0x1f) * 2;
      return {
        inst: {
          address: addr,
          mnemonic: "lhu",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x16: lw rx, imm8*4(pc) - Literal pool PC-relative load
    if (opcode === 0x16) {
      const imm = (w16 & 0xff) * 4;
      return {
        inst: {
          address: addr,
          mnemonic: "lw",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm}($pc)`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x17: Reserved
    if (opcode === 0x17) {
      return {
        inst: {
          address: addr,
          mnemonic: "unsupported_mips16_17",
          operands: `0x${w16.toString(16).padStart(4, "0")}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isMalformed: true,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x18: sb ry, imm5(rx)
    if (opcode === 0x18) {
      const imm5 = w16 & 0x1f;
      return {
        inst: {
          address: addr,
          mnemonic: "sb",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm5}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x19: sh ry, imm5*2(rx)
    if (opcode === 0x19) {
      const imm = (w16 & 0x1f) * 2;
      return {
        inst: {
          address: addr,
          mnemonic: "sh",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x1a: sw rx, imm8*4(sp)
    if (opcode === 0x1a) {
      const imm = (w16 & 0xff) * 4;
      return {
        inst: {
          address: addr,
          mnemonic: "sw",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${imm}($sp)`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x1b: sw ry, imm5*4(rx)
    if (opcode === 0x1b) {
      const imm = (w16 & 0x1f) * 4;
      return {
        inst: {
          address: addr,
          mnemonic: "sw",
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${imm}(${InProcessInstructionDecoder.M16_REG_NAMES[rx]})`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x1c: RRR format (addu, subu)
    if (opcode === 0x1c) {
      const funct = w16 & 0x3;
      const mnem = funct === 1 ? "addu" : funct === 3 ? "subu" : "addu";
      return {
        inst: {
          address: addr,
          mnemonic: mnem,
          operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rz]}, ${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${InProcessInstructionDecoder.M16_REG_NAMES[ry]}`,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x1d: RR format (jr, jalr, jrc, jalrc, cmp, and, or, xor, not, mult, div, etc.)
    if (opcode === 0x1d) {
      const funct = w16 & 0x1f;
      if (funct === 0) {
        const nd = (w16 >>> 7) & 1; // 0 = delay slot, 1 = compact (no delay slot)
        const l = (w16 >>> 6) & 1; // 0 = jump, 1 = link (call)
        const ra = (w16 >>> 5) & 1; // 0 = rx, 1 = $ra

        if (l === 0 && ra === 1) {
          const isCompact = nd === 1;
          return {
            inst: {
              address: addr,
              mnemonic: isCompact ? "jrc ra" : "jr ra",
              operands: "$ra",
              size: 2,
              rawBytes,
              isBranch: false,
              isConditional: false,
              isCall: false,
              isReturn: true,
              isIndirect: false,
              targetAddress: null,
              hasDelaySlot: !isCompact,
              isaMode: "MIPS16",
            },
            bytesRead: 2,
          };
        } else if (l === 0 && ra === 0) {
          const isCompact = nd === 1;
          return {
            inst: {
              address: addr,
              mnemonic: isCompact ? "jrc" : "jr",
              operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}`,
              size: 2,
              rawBytes,
              isBranch: true,
              isConditional: false,
              isCall: false,
              isReturn: false,
              isIndirect: true,
              targetAddress: null,
              hasDelaySlot: !isCompact,
              isaMode: "MIPS16",
            },
            bytesRead: 2,
          };
        } else if (l === 1) {
          const isCompact = nd === 1;
          return {
            inst: {
              address: addr,
              mnemonic: isCompact ? "jalrc" : "jalr",
              operands: `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}`,
              size: 2,
              rawBytes,
              isBranch: false,
              isConditional: false,
              isCall: true,
              isReturn: false,
              isIndirect: true,
              targetAddress: null,
              hasDelaySlot: !isCompact,
              isaMode: "MIPS16",
            },
            bytesRead: 2,
          };
        }
      }

      // Other RR opcodes
      let rrMnem = "unsupported_mips16_rr";
      let rrOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}, ${InProcessInstructionDecoder.M16_REG_NAMES[ry]}`;
      let isMalformed = false;

      switch (funct) {
        case 0x01: rrMnem = "sdbbp"; rrOps = ""; break;
        case 0x02: rrMnem = "slt"; break;
        case 0x03: rrMnem = "sltu"; break;
        case 0x04: rrMnem = "sllv"; rrOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${InProcessInstructionDecoder.M16_REG_NAMES[rx]}`; break;
        case 0x05: rrMnem = "break"; rrOps = ""; break;
        case 0x06: rrMnem = "srlv"; rrOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${InProcessInstructionDecoder.M16_REG_NAMES[rx]}`; break;
        case 0x07: rrMnem = "srav"; rrOps = `${InProcessInstructionDecoder.M16_REG_NAMES[ry]}, ${InProcessInstructionDecoder.M16_REG_NAMES[rx]}`; break;
        case 0x0a: rrMnem = "cmp"; break;
        case 0x0b: rrMnem = "neg"; break;
        case 0x0c: rrMnem = "and"; break;
        case 0x0d: rrMnem = "or"; break;
        case 0x0e: rrMnem = "xor"; break;
        case 0x0f: rrMnem = "not"; break;
        case 0x10: rrMnem = "mfhi"; rrOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}`; break;
        case 0x11: rrMnem = "seb"; rrOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}`; break;
        case 0x12: rrMnem = "mflo"; rrOps = `${InProcessInstructionDecoder.M16_REG_NAMES[rx]}`; break;
        case 0x18: rrMnem = "mult"; break;
        case 0x19: rrMnem = "multu"; break;
        case 0x1a: rrMnem = "div"; break;
        case 0x1b: rrMnem = "divu"; break;
        default:
          rrMnem = "unsupported_mips16_rr";
          isMalformed = true;
          break;
      }

      return {
        inst: {
          address: addr,
          mnemonic: rrMnem,
          operands: rrOps,
          size: 2,
          rawBytes,
          isBranch: false,
          isConditional: false,
          isCall: false,
          isReturn: false,
          isIndirect: false,
          targetAddress: null,
          hasDelaySlot: false,
          isMalformed,
          isaMode: "MIPS16",
        },
        bytesRead: 2,
      };
    }

    // Opcode 0x1f: Reserved
    return {
      inst: {
        address: addr,
        mnemonic: "unsupported_mips16_1f",
        operands: `0x${w16.toString(16).padStart(4, "0")}`,
        size: 2,
        rawBytes,
        isBranch: false,
        isConditional: false,
        isCall: false,
        isReturn: false,
        isIndirect: false,
        targetAddress: null,
        hasDelaySlot: false,
        isMalformed: true,
        isaMode: "MIPS16",
      },
      bytesRead: 2,
    };
  }

  // =========================================================================
  // Mixed MIPS16/MIPS32 Instruction Decoder
  // =========================================================================
  private decodeMixedMips(
    bytes: Uint8Array,
    baseAddress: number,
    isLE: boolean,
    options: DecodeOptions,
  ): Instruction[] {
    const instructions: Instruction[] = [];
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    // Initial ISA mode determination
    let currentMode: "MIPS32" | "MIPS16" =
      options.isMips16 || (baseAddress & 1) === 1 ? "MIPS16" : "MIPS32";

    const normalizedBase = (baseAddress & ~1) >>> 0;
    let offset = 0;

    const mips16Intervals = options.mips16Regions ?? [];

    while (offset < bytes.byteLength) {
      const curAddr = (normalizedBase + offset) >>> 0;

      // Check if explicit regions dictate the ISA mode at curAddr
      if (mips16Intervals.length > 0) {
        const inMips16 = mips16Intervals.some(
          (reg) => curAddr >= reg.start && curAddr < reg.end,
        );
        currentMode = inMips16 ? "MIPS16" : "MIPS32";
      }

      // Architecturally, MIPS32 instructions MUST be 4-byte aligned (curAddr % 4 === 0).
      // An unaligned address cannot execute MIPS32.
      if (currentMode === "MIPS32" && (curAddr % 4 !== 0)) {
        currentMode = "MIPS16";
      }

      if (currentMode === "MIPS16") {
        const { inst, bytesRead } = this.decodeMips16Instruction(
          view,
          offset,
          curAddr,
          isLE,
          bytes,
        );
        instructions.push(inst);
        offset += bytesRead;
      } else {
        // MIPS32 mode (requires 4-byte aligned instruction)
        if (offset + 4 <= bytes.byteLength) {
          const raw = view.getUint32(offset, isLE);
          const rawBytes = bytes.slice(offset, offset + 4);
          const inst = this.decodeMipsInstruction(raw, curAddr, rawBytes);
          instructions.push(inst);
          offset += 4;
        } else {
          // Unaligned trailing bytes
          const rawBytes = bytes.slice(offset);
          instructions.push({
            address: curAddr,
            mnemonic: "malformed_unaligned",
            operands: "",
            size: rawBytes.byteLength,
            rawBytes,
            isBranch: false,
            isConditional: false,
            isCall: false,
            isReturn: false,
            isIndirect: false,
            targetAddress: null,
            isMalformed: true,
            isaMode: "MIPS32",
          });
          offset += rawBytes.byteLength;
        }
      }
    }

    return instructions;
  }
}

