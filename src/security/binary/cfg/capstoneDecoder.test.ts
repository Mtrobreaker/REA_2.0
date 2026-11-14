import { describe, expect, it } from "vitest";
import { CapstoneDecoderProvider } from "./CapstoneDecoderProvider.js";
import { InstructionDecoder } from "./InstructionDecoder.js";

describe("Phase 2: Capstone Native Decoder Integration Suite", () => {
  const capstone = new CapstoneDecoderProvider();
  const universal = new InstructionDecoder();

  it("1. Validates native library loading and project-local resolution without host PATH", () => {
    const libPath = CapstoneDecoderProvider.resolveLibraryPath();
    expect(libPath).toBeDefined();
    expect(typeof libPath).toBe("string");
    if (process.platform === "win32") {
      expect(libPath.toLowerCase()).toContain("tools\\capstone\\windows\\capstone.dll");
    } else {
      expect(libPath).toContain("tools/capstone/linux-wsl/libcapstone.so");
    }

    expect(capstone.isAvailable()).toBe(true);
    expect(capstone.getAvailabilityReason()).toContain("Capstone 5.0 native engine active");
    expect(capstone.supportedArchitectures).toEqual(["ARM", "MIPS", "x86_64"]);
  });

  it("2. Correctly decodes x86-64 instructions with precise boundaries and control-flow metadata", () => {
    // 55                push rbp
    // 48 89 e5          mov rbp, rsp
    // 48 83 ec 10       sub rsp, 0x10
    // e8 13 00 00 00    call 0x1020
    // c3                ret
    const bytes = Buffer.from("554889e54883ec10e813000000c3", "hex");
    const res = capstone.decode(bytes, 0x1000, {
      architecture: "x86_64",
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const result = res.value;
    expect(result.outcome).toBe("SUCCESS");
    expect(result.totalBytes).toBe(bytes.length);
    expect(result.decodedBytes).toBe(bytes.length);
    expect(result.instructions.length).toBe(5);

    expect(result.instructions[0]!.mnemonic).toBe("push");
    expect(result.instructions[0]!.size).toBe(1);

    expect(result.instructions[1]!.mnemonic).toBe("mov");
    expect(result.instructions[1]!.size).toBe(3);

    expect(result.instructions[2]!.mnemonic).toBe("sub");
    expect(result.instructions[2]!.size).toBe(4);

    expect(result.instructions[3]!.mnemonic).toBe("call");
    expect(result.instructions[3]!.isCall).toBe(true);
    expect(result.instructions[3]!.targetAddress).toBe(0x1020);

    expect(result.instructions[4]!.mnemonic).toBe("ret");
    expect(result.instructions[4]!.isReturn).toBe(true);

    expect(result.provenance.actualProvider).toBe("CapstoneDecoderProvider");
    expect(result.provenance.isFallback).toBe(false);
  });

  it("3. Correctly decodes ARM32 A32 instructions and maps conditions and returns", () => {
    // 00 48 2d e9    push {r11, lr}
    // 04 b0 8d e2    add r11, sp, #4
    // 06 00 00 eb    bl 0x1028
    // 00 88 bd e8    pop {r11, pc}
    const bytes = Buffer.from("00482de904b08de2060000eb0088bde8", "hex");
    const res = capstone.decode(bytes, 0x1000, {
      architecture: "ARM",
      isLittleEndian: true,
      isThumb: false,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const result = res.value;
    expect(result.outcome).toBe("SUCCESS");
    expect(result.instructions.length).toBe(4);

    // Call
    expect(result.instructions[2]!.mnemonic).toBe("bl");
    expect(result.instructions[2]!.isCall).toBe(true);
    expect(result.instructions[2]!.targetAddress).toBe(0x1028);

    // Return (pop with pc)
    expect(result.instructions[3]!.mnemonic).toBe("pop");
    expect(result.instructions[3]!.isReturn).toBe(true);
  });

  it("4. Correctly decodes ARM Thumb / Thumb-2 variable-width instructions", () => {
    // 80 b5       push {r7, lr}       (2 bytes)
    // 00 af       add r7, sp, #0      (2 bytes)
    // 00 f0 0e f8 bl 0x1024           (4 bytes Thumb-2 BL)
    // 80 bd       pop {r7, pc}        (2 bytes)
    const bytes = Buffer.from("80b500af00f00ef880bd", "hex");
    const res = capstone.decode(bytes, 0x1000, {
      architecture: "ARM",
      isLittleEndian: true,
      isThumb: true,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const result = res.value;
    expect(result.outcome).toBe("SUCCESS");
    expect(result.instructions.length).toBe(4);

    expect(result.instructions[0]!.size).toBe(2);
    expect(result.instructions[1]!.size).toBe(2);
    expect(result.instructions[2]!.size).toBe(4);
    expect(result.instructions[2]!.isCall).toBe(true);
    expect(result.instructions[2]!.targetAddress).toBe(0x1024);
    expect(result.instructions[3]!.size).toBe(2);
    expect(result.instructions[3]!.isReturn).toBe(true);
  });
});

describe("Phase 2: Capstone Native Decoder Integration Suite - MIPS and Robustness", () => {
  const capstone = new CapstoneDecoderProvider();
  const universal = new InstructionDecoder();

  it("5. Correctly decodes MIPS32 Big-Endian instructions with branch delay slots", () => {
    // 27 bd ff e0    addiu $sp, $sp, -32
    // af bf 00 1c    sw $ra, 28($sp)
    // 0c 10 00 10    jal 0x400040
    // 00 00 00 00    nop (delay slot)
    // 8f bf 00 1c    lw $ra, 28($sp)
    // 03 e0 00 08    jr $ra
    // 27 bd 00 20    addiu $sp, $sp, 32 (delay slot)
    const bytes = Buffer.from("27bdffe0afbf001c0c100010000000008fbf001c03e0000827bd0020", "hex");
    const res = capstone.decode(bytes, 0x400000, {
      architecture: "MIPS",
      isLittleEndian: false,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const result = res.value;
    expect(result.outcome).toBe("SUCCESS");
    expect(result.instructions.length).toBe(7);

    // jal has delay slot
    const jal = result.instructions[2]!;
    expect(jal.mnemonic).toBe("jal");
    expect(jal.isCall).toBe(true);
    expect(jal.hasDelaySlot).toBe(true);
    expect(jal.targetAddress).toBe(0x400040);

    // jr $ra has delay slot
    const jr = result.instructions[5]!;
    expect(jr.mnemonic).toBe("jr");
    expect(jr.isReturn).toBe(true);
    expect(jr.hasDelaySlot).toBe(true);
  });

  it("6. Correctly decodes MIPS32 Little-Endian instructions", () => {
    // In LE: jal 0x400040 is 10 00 10 0c
    // nop: 00 00 00 00
    // jr $ra: 08 00 e0 03
    // nop: 00 00 00 00
    const bytes = Buffer.from("1000100c000000000800e00300000000", "hex");
    const res = capstone.decode(bytes, 0x400000, {
      architecture: "MIPS",
      isLittleEndian: true,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const result = res.value;
    expect(result.outcome).toBe("SUCCESS");
    expect(result.instructions.length).toBe(4);
    expect(result.instructions[0]!.mnemonic).toBe("jal");
    expect(result.instructions[0]!.targetAddress).toBe(0x400040);
    expect(result.instructions[2]!.mnemonic).toBe("jr");
    expect(result.instructions[2]!.isReturn).toBe(true);
  });

  it("7. Handles invalid bytes and embedded data without inventing instructions (PARTIAL / MALFORMED)", () => {
    // Valid x86_64: 55 (push rbp) + ff ff (invalid) + c3 (ret)
    const partialBytes = Buffer.from("55ffffc3", "hex");
    const resPartial = capstone.decode(partialBytes, 0x1000, { architecture: "x86_64" });

    expect(resPartial.ok).toBe(true);
    if (!resPartial.ok) return;

    // Must NOT invent an instruction for ff ff or jump past it
    expect(resPartial.value.outcome).toBe("PARTIAL");
    expect(resPartial.value.instructions.length).toBe(1);
    expect(resPartial.value.instructions[0]!.mnemonic).toBe("push");
    expect(resPartial.value.decodedBytes).toBe(1);
    expect(resPartial.value.unhandledByteOffset).toBe(1);
    expect(resPartial.value.haltReason).toContain("Stream halted before EOF");

    // Pure invalid bytes from the start -> MALFORMED
    const malformedBytes = Buffer.from("ffffffff", "hex");
    const resMalformed = capstone.decode(malformedBytes, 0x1000, { architecture: "x86_64" });
    expect(resMalformed.ok).toBe(true);
    if (!resMalformed.ok) return;

    expect(resMalformed.value.outcome).toBe("MALFORMED");
    expect(resMalformed.value.instructions.length).toBe(0);
    expect(resMalformed.value.decodedBytes).toBe(0);
  });

  it("8. Rejects unsupported architecture with explicit UNSUPPORTED outcome", () => {
    const bytes = Buffer.from("9090", "hex");
    const res = capstone.decode(bytes, 0x1000, { architecture: "unknown" as any });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error.outcome).toBe("UNSUPPORTED");
  });

  it("9. Dispatches transparently through universal InstructionDecoder when requested", () => {
    const bytes = Buffer.from("554889e5c3", "hex"); // push rbp; mov rbp, rsp; ret
    const res = universal.decodeResult(bytes, 0x1000, {
      architecture: "x86_64",
      preferredProvider: "CapstoneDecoderProvider",
    });

    expect(res.outcome).toBe("SUCCESS");
    expect(res.instructions.length).toBe(3);
    expect(res.provenance.actualProvider).toBe("CapstoneDecoderProvider");
    expect(res.provenance.requestedProvider).toBe("CapstoneDecoderProvider");
    expect(res.provenance.isFallback).toBe(false);
  });
});
