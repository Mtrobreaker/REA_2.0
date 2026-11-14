/**
 * Independently generated instruction-level test vectors for conformance testing.
 * Reference disassemblies derived from standard Capstone and GNU binutils specifications.
 */

export interface InstructionTestVector {
  readonly name: string;
  readonly architecture: "ARM" | "MIPS" | "x86_64";
  readonly isThumb?: boolean;
  readonly isLittleEndian?: boolean;
  readonly baseAddress: number;
  readonly bytes: Uint8Array;
  readonly expectedInstructionCount: number;
  readonly expectedFirstMnemonic: string;
  readonly expectedFirstSize: number;
  readonly expectedTargetAddress?: number | null;
  readonly expectedIsBranch?: boolean;
  readonly expectedIsConditional?: boolean;
  readonly expectedIsCall?: boolean;
  readonly expectedIsReturn?: boolean;
  readonly expectedIsIndirect?: boolean;
  readonly expectedHasDelaySlot?: boolean;
}

export const POSITIVE_FIXTURES: readonly InstructionTestVector[] = [
  // -------------------------------------------------------------
  // x86-64 Positive Fixtures
  // -------------------------------------------------------------
  {
    name: "x86_64: 32-bit conditional branch (0x0F 0x84 JZ/JE rel32)",
    architecture: "x86_64",
    baseAddress: 0x401000,
    // 0x0F 0x84 0x20 0x00 0x00 0x00 (je +0x20 -> target 0x401000 + 6 + 0x20 = 0x401026)
    bytes: new Uint8Array([0x0f, 0x84, 0x20, 0x00, 0x00, 0x00]),
    expectedInstructionCount: 1,
    expectedFirstMnemonic: "je",
    expectedFirstSize: 6,
    expectedTargetAddress: 0x401026,
    expectedIsBranch: true,
    expectedIsConditional: true,
    expectedIsCall: false,
    expectedIsReturn: false,
    expectedIsIndirect: false,
  },
  {
    name: "x86_64: Branch-like byte inside immediate value (MOV EAX, 0x0000E990)",
    architecture: "x86_64",
    baseAddress: 0x401000,
    // 0xB8 0x90 0xE9 0x00 0x00 (mov eax, 0xe990) followed by 0xC3 (ret)
    // 0xE9 inside immediate must NOT be misdecoded as JMP rel32!
    bytes: new Uint8Array([0xb8, 0x90, 0xe9, 0x00, 0x00, 0xc3]),
    expectedInstructionCount: 2,
    expectedFirstMnemonic: "mov",
    expectedFirstSize: 5,
    expectedTargetAddress: null,
    expectedIsBranch: false,
    expectedIsConditional: false,
    expectedIsCall: false,
    expectedIsReturn: false,
  },
  {
    name: "x86_64: REX.W prefixed RIP-relative addressing (MOV RAX, [RIP + 0x20])",
    architecture: "x86_64",
    baseAddress: 0x401000,
    // 0x48 (REX.W) 0x8B 0x05 0x20 0x00 0x00 0x00 (mov rax, [rip + 0x20])
    // Total 7 bytes. Target address = 0x401000 + 7 + 0x20 = 0x401027
    bytes: new Uint8Array([0x48, 0x8b, 0x05, 0x20, 0x00, 0x00, 0x00]),
    expectedInstructionCount: 1,
    expectedFirstMnemonic: "mov",
    expectedFirstSize: 7,
    expectedTargetAddress: null,
    expectedIsBranch: false,
  },
  {
    name: "x86_64: SIB addressing with displacement (MOV RDX, [RDI + RSI*4 + 0x10])",
    architecture: "x86_64",
    baseAddress: 0x401000,
    // 0x48 0x8B 0x54 0xB7 0x10
    bytes: new Uint8Array([0x48, 0x8b, 0x54, 0xb7, 0x10]),
    expectedInstructionCount: 1,
    expectedFirstMnemonic: "mov",
    expectedFirstSize: 5,
    expectedTargetAddress: null,
    expectedIsBranch: false,
  },
  {
    name: "x86_64: Indirect call via ModR/M RIP-relative (CALL [RIP + 0x1000])",
    architecture: "x86_64",
    baseAddress: 0x401000,
    // 0xFF 0x15 0x00 0x10 0x00 0x00 (call [rip + 0x1000])
    // Next inst addr = 0x401006 -> target address = 0x402006
    bytes: new Uint8Array([0xff, 0x15, 0x00, 0x10, 0x00, 0x00]),
    expectedInstructionCount: 1,
    expectedFirstMnemonic: "call (indirect)",
    expectedFirstSize: 6,
    expectedTargetAddress: 0x402006,
    expectedIsBranch: false,
    expectedIsCall: true,
    expectedIsIndirect: true,
  },

  // -------------------------------------------------------------
  // ARM32 (A32) Positive Fixtures
  // -------------------------------------------------------------
  {
    name: "ARM32: Conditional branch BNE (0x1A000004)",
    architecture: "ARM",
    isThumb: false,
    isLittleEndian: true,
    baseAddress: 0x10000,
    // BNE +4 words (+16 bytes): PC+8 + 16 = 0x10000 + 8 + 16 = 0x10018
    bytes: new Uint8Array([0x04, 0x00, 0x00, 0x1a]),
    expectedInstructionCount: 1,
    expectedFirstMnemonic: "bne",
    expectedFirstSize: 4,
    expectedTargetAddress: 0x10018,
    expectedIsBranch: true,
    expectedIsConditional: true,
    expectedIsCall: false,
    expectedIsReturn: false,
  },
  {
    name: "ARM32: Return via stack POP {R4, R5, PC} (0xE8BD8030)",
    architecture: "ARM",
    isThumb: false,
    isLittleEndian: true,
    baseAddress: 0x10000,
    // 0xE8BD8030 (pop {r4, r5, pc})
    bytes: new Uint8Array([0x30, 0x80, 0xbd, 0xe8]),
    expectedInstructionCount: 1,
    expectedFirstMnemonic: "pop {..., pc}",
    expectedFirstSize: 4,
    expectedIsReturn: true,
    expectedIsBranch: false,
  },

  // -------------------------------------------------------------
  // ARM Thumb / Thumb-2 Positive Fixtures
  // -------------------------------------------------------------
  {
    name: "Thumb-2: 32-bit branch with link BL (0xF000 0xF804)",
    architecture: "ARM",
    isThumb: true,
    isLittleEndian: true,
    baseAddress: 0x20000,
    // 0xF000 0xF804 (bl +8 bytes -> 0x20000 + 4 + 8 = 0x2000c)
    bytes: new Uint8Array([0x00, 0xf0, 0x04, 0xf8]),
    expectedInstructionCount: 1,
    expectedFirstMnemonic: "bl",
    expectedFirstSize: 4,
    expectedTargetAddress: 0x2000c,
    expectedIsCall: true,
    expectedIsBranch: false,
  },
  {
    name: "Thumb: 16-bit CBZ non-zero comparison (0xB110)",
    architecture: "ARM",
    isThumb: true,
    isLittleEndian: true,
    baseAddress: 0x20000,
    // CBZ r0, +4 bytes (target = 0x20000 + 4 + 4 = 0x20008)
    bytes: new Uint8Array([0x10, 0xb1]),
    expectedInstructionCount: 1,
    expectedFirstMnemonic: "cbz",
    expectedFirstSize: 2,
    expectedTargetAddress: 0x20008,
    expectedIsBranch: true,
    expectedIsConditional: true,
  },

  // -------------------------------------------------------------
  // MIPS32 Positive Fixtures
  // -------------------------------------------------------------
  {
    name: "MIPS32: JAL call with NOP branch delay slot (Big Endian)",
    architecture: "MIPS",
    isLittleEndian: false,
    baseAddress: 0x00400000,
    // JAL 0x00400080 (0x0C100020), delay slot NOP (0x00000000)
    bytes: new Uint8Array([0x0c, 0x10, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00]),
    expectedInstructionCount: 2,
    expectedFirstMnemonic: "jal",
    expectedFirstSize: 4,
    expectedTargetAddress: 0x00400080,
    expectedIsCall: true,
    expectedHasDelaySlot: true,
  },
  {
    name: "MIPS32: JR $ra return with delay slot (Little Endian)",
    architecture: "MIPS",
    isLittleEndian: true,
    baseAddress: 0x00400000,
    // JR $ra (0x03E00008 in LE: 0x08, 0x00, 0xE0, 0x03), delay slot NOP
    bytes: new Uint8Array([0x08, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x00, 0x00]),
    expectedInstructionCount: 2,
    expectedFirstMnemonic: "jr $ra",
    expectedFirstSize: 4,
    expectedIsReturn: true,
    expectedHasDelaySlot: true,
  },
];

export interface NegativeFixture {
  readonly name: string;
  readonly architecture: "ARM" | "MIPS" | "x86_64" | "unknown";
  readonly isThumb?: boolean;
  readonly isLittleEndian?: boolean;
  readonly baseAddress: number;
  readonly bytes: Uint8Array;
  readonly expectedErrorPattern?: string;
  readonly expectMalformedInstruction?: boolean;
}

export const NEGATIVE_FIXTURES: readonly NegativeFixture[] = [
  {
    name: "x86_64: Incomplete trailing REX prefix without opcode",
    architecture: "x86_64",
    baseAddress: 0x401000,
    bytes: new Uint8Array([0x48]), // REX.W alone
    expectMalformedInstruction: true,
  },
  {
    name: "x86_64: Truncated SIB displacement",
    architecture: "x86_64",
    baseAddress: 0x401000,
    // 0x48 0x8B 0x54 (ModR/M requiring SIB, but SIB byte missing)
    bytes: new Uint8Array([0x48, 0x8b, 0x54]),
    expectMalformedInstruction: true,
  },
  {
    name: "ARM32: Truncated 3-byte stream (unaligned)",
    architecture: "ARM",
    isThumb: false,
    baseAddress: 0x10000,
    bytes: new Uint8Array([0x01, 0x02, 0x03]),
    expectMalformedInstruction: true,
  },
  {
    name: "Thumb-2: Truncated 32-bit instruction (first 2 bytes of 4-byte prefix)",
    architecture: "ARM",
    isThumb: true,
    baseAddress: 0x20000,
    bytes: new Uint8Array([0x00, 0xf0]), // 32-bit prefix without second halfword
    expectMalformedInstruction: true,
  },
  {
    name: "MIPS32: Truncated delay slot (branch without delay slot instruction)",
    architecture: "MIPS",
    isLittleEndian: false,
    baseAddress: 0x00400000,
    // JAL 0x00400080 alone, without delay slot instruction
    bytes: new Uint8Array([0x0c, 0x10, 0x00, 0x20]),
    expectMalformedInstruction: false, // Disassembles JAL, but CFG builder marks missing delay slot as halt
  },
  {
    name: "Unsupported architecture: SPARC fails closed",
    architecture: "unknown",
    baseAddress: 0x1000,
    bytes: new Uint8Array([0x01, 0x00, 0x00, 0x00]),
    expectedErrorPattern: "Unsupported architecture",
  },
];

