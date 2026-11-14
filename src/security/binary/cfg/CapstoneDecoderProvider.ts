import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { err, ok, type Result } from "../../../domain/result.js";
import type {
  Architecture,
  DecodeOptions,
  DecodeOutcome,
  DecodeProvenance,
  DecodeResult,
  Instruction,
  InstructionDecoderProvider,
} from "./types.js";
import { InstructionDecodeError } from "./types.js";

// Capstone C API constants
const CS_ARCH_ARM = 0;
const CS_ARCH_ARM64 = 1;
const CS_ARCH_MIPS = 2;
const CS_ARCH_X86 = 3;

const CS_MODE_LITTLE_ENDIAN = 0;
const CS_MODE_ARM = 0;
const CS_MODE_16 = 2;
const CS_MODE_32 = 4;
const CS_MODE_64 = 8;
const CS_MODE_THUMB = 16;
const CS_MODE_MIPS32 = 4;
const CS_MODE_BIG_ENDIAN = 0x80000000;

interface NativeCapstoneInterface {
  readonly cs_open: (arch: number, mode: number, handlePtr: number[]) => number;
  readonly cs_close: (handlePtr: number[]) => number;
  readonly cs_disasm: (
    handle: number,
    code: Uint8Array | Buffer,
    codeSize: number,
    address: bigint,
    count: number,
    insnPtr: unknown[],
  ) => number;
  readonly cs_free: (insn: unknown, count: number) => void;
  readonly cs_strerror: (code: number) => string;
  readonly cs_version: (major: number[], minor: number[]) => number;
  readonly decodeInsns: (ptr: unknown, count: number) => any[];
}

export interface CapstoneDecoderProviderOptions {
  readonly forceAvailable?: boolean;
  readonly forceUnsupported?: boolean;
  readonly customLibPath?: string;
}

/**
 * Production Capstone Native Instruction Decoder Provider.
 *
 * Binds to project-local Capstone 5.0 native shared library (capstone.dll on Windows,
 * libcapstone.so on Linux/WSL) via Koffi C FFI without host PATH dependencies.
 *
 * Supports x86-64, ARM32 (A32), ARM Thumb/Thumb-2, and MIPS32 (Big-Endian & Little-Endian).
 * Strictly manages native memory (cs_free, cs_close) and preserves typed decoding outcomes
 * (SUCCESS, PARTIAL, MALFORMED, UNSUPPORTED, FAILED).
 */
export class CapstoneDecoderProvider implements InstructionDecoderProvider {
  public readonly name = "CapstoneDecoderProvider";
  public readonly supportedArchitectures: readonly Architecture[] = ["ARM", "MIPS", "x86_64"];

  private static cachedBinding: NativeCapstoneInterface | null = null;
  private static cachedAvailability: boolean | null = null;
  private static cachedAvailabilityReason: string | null = null;

  private readonly options: CapstoneDecoderProviderOptions;

  constructor(options?: CapstoneDecoderProviderOptions) {
    this.options = options ?? {};
  }

  /**
   * Resolve the project-local Capstone shared library path.
   */
  public static resolveLibraryPath(customPath?: string): string {
    if (customPath && existsSync(customPath)) {
      return customPath;
    }
    if (process.env.REA_CAPSTONE_PATH && existsSync(process.env.REA_CAPSTONE_PATH)) {
      return process.env.REA_CAPSTONE_PATH;
    }

    const currentDir = dirname(fileURLToPath(import.meta.url));
    const repoRoot = resolve(currentDir, "../../../..");

    const winCandidate = join(repoRoot, "tools", "capstone", "windows", "capstone.dll");
    const linuxCandidate = join(repoRoot, "tools", "capstone", "linux-wsl", "libcapstone.so");

    if (process.platform === "win32") {
      if (existsSync(winCandidate)) return winCandidate;
    } else {
      if (existsSync(linuxCandidate)) return linuxCandidate;
    }

    // Working directory fallbacks
    const cwdWin = resolve(process.cwd(), "tools/capstone/windows/capstone.dll");
    const cwdLinux = resolve(process.cwd(), "tools/capstone/linux-wsl/libcapstone.so");
    if (process.platform === "win32" && existsSync(cwdWin)) return cwdWin;
    if (process.platform !== "win32" && existsSync(cwdLinux)) return cwdLinux;

    throw new Error(
      `Project-local Capstone library not found at ${process.platform === "win32" ? winCandidate : linuxCandidate}. Ensure tools/capstone/ is provisioned.`,
    );
  }

  /**
   * Lazily load and bind native Capstone functions via Koffi FFI.
   */
  private static getOrInitNativeBinding(customPath?: string): NativeCapstoneInterface {
    if (this.cachedBinding) {
      return this.cachedBinding;
    }

    const libPath = this.resolveLibraryPath(customPath);
    const require = createRequire(import.meta.url);

    // Resolve Koffi module
    const currentDir = dirname(fileURLToPath(import.meta.url));
    const repoRoot = resolve(currentDir, "../../../..");
    const koffiDir = join(repoRoot, "tools", "capstone", "node_modules", "koffi");

    let koffi: any;
    try {
      koffi = require(koffiDir);
    } catch {
      try {
        koffi = require(resolve(process.cwd(), "tools/capstone/node_modules/koffi"));
      } catch (err: any) {
        throw new Error(`Failed to load Koffi FFI runtime: ${err?.message ?? String(err)}`);
      }
    }

    const lib = koffi.load(libPath);

    // cs_insn struct layout in Capstone 5.0
    const cs_insn_t = koffi.struct("cs_insn", {
      id: "uint32",
      address: "uint64",
      size: "uint16",
      bytes: koffi.array("uint8", 24),
      mnemonic: koffi.array("char", 32),
      op_str: koffi.array("char", 160),
      detail: "void *",
    });

    const cs_version = lib.func("unsigned int cs_version(_Out_ int *major, _Out_ int *minor)");
    const cs_open = lib.func("int cs_open(int arch, int mode, _Out_ size_t *handle)");
    const cs_close = lib.func("int cs_close(_Inout_ size_t *handle)");
    const cs_disasm = lib.func(
      "size_t cs_disasm(size_t handle, const uint8_t *code, size_t code_size, uint64_t address, size_t count, _Out_ cs_insn **insn)",
    );
    const cs_free = lib.func("void cs_free(cs_insn *insn, size_t count)");
    const cs_strerror = lib.func("const char *cs_strerror(int code)");

    const major = [0];
    const minor = [0];
    cs_version(major, minor);

    const binding: NativeCapstoneInterface = {
      cs_open,
      cs_close,
      cs_disasm,
      cs_free,
      cs_strerror,
      cs_version,
      decodeInsns: (ptr: unknown, count: number) => {
        const decoded = koffi.decode(ptr, cs_insn_t, count);
        return Array.isArray(decoded) ? decoded : [decoded];
      },
    };

    this.cachedBinding = binding;
    return binding;
  }

  /**
   * Determine whether Capstone is available in the current runtime environment.
   */
  public isAvailable(): boolean {
    if (this.options.forceAvailable !== undefined) {
      return this.options.forceAvailable;
    }

    if (CapstoneDecoderProvider.cachedAvailability !== null) {
      return CapstoneDecoderProvider.cachedAvailability;
    }

    try {
      CapstoneDecoderProvider.getOrInitNativeBinding(this.options.customLibPath);
      CapstoneDecoderProvider.cachedAvailability = true;
      CapstoneDecoderProvider.cachedAvailabilityReason = "Project-local Capstone 5.0 native engine active";
      return true;
    } catch (e: any) {
      CapstoneDecoderProvider.cachedAvailability = false;
      CapstoneDecoderProvider.cachedAvailabilityReason = `Capstone native library unavailable: ${e?.message ?? String(e)}`;
      return false;
    }
  }

  public getAvailabilityReason(): string {
    if (this.options.forceAvailable === false) {
      return "Capstone native library (libcapstone) is not installed in local environment";
    }
    if (CapstoneDecoderProvider.cachedAvailability === null) {
      this.isAvailable();
    }
    return (
      CapstoneDecoderProvider.cachedAvailabilityReason ??
      "Capstone native library (libcapstone) is not installed in local environment"
    );
  }

  public canDecode(options: DecodeOptions): boolean {
    if (this.options.forceUnsupported) {
      return false;
    }
    if (!this.supportedArchitectures.includes(options.architecture)) {
      return false;
    }
    // Capstone 5.0 lacks MIPS16 support; delegate MIPS16 to InProcessInstructionDecoder
    if (
      options.architecture === "MIPS" &&
      (options.isMips16 || (options.mips16Regions && options.mips16Regions.length > 0))
    ) {
      return false;
    }
    return this.isAvailable();
  }

  public decode(
    bytes: Uint8Array,
    baseAddress: number,
    options: DecodeOptions,
  ): Result<DecodeResult, InstructionDecodeError> {
    if (this.options.forceUnsupported) {
      return err(
        new InstructionDecodeError(
          "Capstone forced unsupported for verification",
          options.architecture,
          baseAddress,
          bytes,
          "UNSUPPORTED",
        ),
      );
    }

    if (!this.supportedArchitectures.includes(options.architecture)) {
      return err(
        new InstructionDecodeError(
          `Capstone does not support architecture: ${options.architecture}`,
          options.architecture,
          baseAddress,
          bytes,
          "UNSUPPORTED",
        ),
      );
    }

    if (!this.isAvailable()) {
      return err(
        new InstructionDecodeError(
          `CapstoneDecoderProvider is unavailable: ${this.getAvailabilityReason()}. Use InProcessInstructionDecoder.`,
          options.architecture,
          baseAddress,
          bytes,
          "UNSUPPORTED",
        ),
      );
    }

    // Handle empty byte slice cleanly
    if (bytes.byteLength === 0) {
      const emptyResult: any = [];
      emptyResult.outcome = "SUCCESS";
      emptyResult.instructions = [];
      emptyResult.architecture = options.architecture;
      emptyResult.baseAddress = baseAddress;
      emptyResult.totalBytes = 0;
      emptyResult.decodedBytes = 0;
      emptyResult.provenance = {
        actualProvider: this.name,
        requestedProvider: options.preferredProvider ?? this.name,
        isFallback: false,
        timestamp: Date.now(),
      };
      return ok(emptyResult as DecodeResult);
    }

    let binding: NativeCapstoneInterface;
    try {
      binding = CapstoneDecoderProvider.getOrInitNativeBinding(this.options.customLibPath);
    } catch (e: any) {
      return err(
        new InstructionDecodeError(
          `Capstone native binding failure: ${e?.message ?? String(e)}`,
          options.architecture,
          baseAddress,
          bytes,
          "FAILED",
        ),
      );
    }

    // Map Architecture, Endianness & Processor Mode
    let archConst: number;
    let modeConst: number;

    const isLittleEndian = options.isLittleEndian ?? (options.architecture !== "MIPS");

    switch (options.architecture) {
      case "x86_64":
        archConst = CS_ARCH_X86;
        modeConst = CS_MODE_64;
        break;

      case "ARM": {
        archConst = CS_ARCH_ARM;
        const endianFlag = isLittleEndian ? CS_MODE_LITTLE_ENDIAN : CS_MODE_BIG_ENDIAN;
        const isThumb = options.isThumb || (baseAddress & 1) === 1;
        modeConst = (isThumb ? CS_MODE_THUMB : CS_MODE_ARM) | endianFlag;
        break;
      }

      case "MIPS": {
        if (options.isMips16 || (options.mips16Regions && options.mips16Regions.length > 0)) {
          return err(
            new InstructionDecodeError(
              "Capstone does not support MIPS16 mode. Use InProcessInstructionDecoder.",
              options.architecture,
              baseAddress,
              bytes,
              "UNSUPPORTED",
            ),
          );
        }
        archConst = CS_ARCH_MIPS;
        const endianFlag = isLittleEndian ? CS_MODE_LITTLE_ENDIAN : CS_MODE_BIG_ENDIAN;
        modeConst = CS_MODE_MIPS32 | endianFlag;
        break;
      }

      default:
        return err(
          new InstructionDecodeError(
            `Unsupported architecture: ${options.architecture}`,
            options.architecture,
            baseAddress,
            bytes,
            "UNSUPPORTED",
          ),
        );
    }

    const handlePtr = [0];
    const openErr = binding.cs_open(archConst, modeConst, handlePtr);
    if (openErr !== 0) {
      return err(
        new InstructionDecodeError(
          `cs_open failed with error ${openErr} (${binding.cs_strerror(openErr)})`,
          options.architecture,
          baseAddress,
          bytes,
          "FAILED",
        ),
      );
    }

    const handle = handlePtr[0]!;
    const insnPtr = [null];
    const instructions: Instruction[] = [];
    let decodedBytes = 0;

    try {
      const count = binding.cs_disasm(
        handle,
        bytes,
        bytes.byteLength,
        BigInt(baseAddress >>> 0),
        0, // 0 = disassemble all until invalid byte or end
        insnPtr,
      );

      if (count > 0 && insnPtr[0]) {
        const rawInsns = binding.decodeInsns(insnPtr[0], count);
        let byteCursor = 0;

        for (let i = 0; i < count; i++) {
          const raw = rawInsns[i];
          const instAddress = Number(raw.address);
          const instSize = raw.size;
          const instMnemonic = (raw.mnemonic || "").trim();
          const instOperands = (raw.op_str || "").trim();

          const instRawBytes = bytes.slice(byteCursor, byteCursor + instSize);
          byteCursor += instSize;
          decodedBytes += instSize;

          const classified = this.classifyInstruction(
            options.architecture,
            instMnemonic,
            instOperands,
            instAddress,
          );

          instructions.push({
            address: instAddress,
            mnemonic: instMnemonic,
            operands: instOperands,
            size: instSize,
            rawBytes: instRawBytes,
            isBranch: classified.isBranch,
            isConditional: classified.isConditional,
            isCall: classified.isCall,
            isReturn: classified.isReturn,
            isIndirect: classified.isIndirect,
            targetAddress: classified.targetAddress,
            hasDelaySlot: classified.hasDelaySlot,
          });
        }

        // Strictly free native instruction memory
        binding.cs_free(insnPtr[0], count);
      }
    } catch (e: any) {
      return err(
        new InstructionDecodeError(
          `Capstone disassembly execution error: ${e?.message ?? String(e)}`,
          options.architecture,
          baseAddress,
          bytes,
          "FAILED",
        ),
      );
    } finally {
      // Strictly close handle
      binding.cs_close(handlePtr);
    }

    // Determine Typed Outcome
    let outcome: DecodeOutcome = "SUCCESS";
    let haltReason: string | undefined;

    if (decodedBytes === 0 && bytes.byteLength > 0) {
      outcome = "MALFORMED";
      haltReason = "Stream starts with invalid or malformed instruction bytes";
    } else if (decodedBytes < bytes.byteLength) {
      outcome = "PARTIAL";
      haltReason = "Stream halted before EOF (encountered invalid bytes, literal pool, or alignment boundary)";
    }

    const decodeResult: any = [...instructions];
    decodeResult.outcome = outcome;
    decodeResult.instructions = instructions;
    decodeResult.architecture = options.architecture;
    decodeResult.baseAddress = baseAddress;
    decodeResult.totalBytes = bytes.byteLength;
    decodeResult.decodedBytes = decodedBytes;
    decodeResult.provenance = {
      actualProvider: this.name,
      requestedProvider: options.preferredProvider ?? this.name,
      isFallback: false,
      timestamp: Date.now(),
    } as DecodeProvenance;

    if (outcome !== "SUCCESS") {
      decodeResult.haltReason = haltReason;
      decodeResult.unhandledByteOffset = decodedBytes;
    }

    return ok(decodeResult as DecodeResult);
  }

  /**
   * Classify control-flow characteristics from Capstone mnemonic and operands.
   */
  private classifyInstruction(
    arch: Architecture,
    mnemonic: string,
    operands: string,
    address: number,
  ): {
    isBranch: boolean;
    isConditional: boolean;
    isCall: boolean;
    isReturn: boolean;
    isIndirect: boolean;
    targetAddress: number | null;
    hasDelaySlot?: boolean | undefined;
  } {
    const m = mnemonic.toLowerCase();
    const ops = operands.toLowerCase();

    let isCall = false;
    let isReturn = false;
    let isBranch = false;
    let isConditional = false;
    let isIndirect = false;
    let targetAddress: number | null = null;
    let hasDelaySlot: boolean | undefined = undefined;

    switch (arch) {
      case "x86_64": {
        if (m === "call") {
          isCall = true;
          isIndirect = ops.includes("[") || /^(?:r[a-d]x|r[s|d]i|r[b|s]p|r[0-9]+|e[a-d]x)$/i.test(ops);
        } else if (m.startsWith("ret")) {
          isReturn = true;
        } else if (m.startsWith("j") || m.startsWith("loop")) {
          isBranch = true;
          isConditional = m !== "jmp";
          isIndirect = m === "jmp" && (ops.includes("[") || /^(?:r[a-d]x|r[s|d]i|r[b|s]p|r[0-9]+|e[a-d]x)$/i.test(ops));
        }

        if (!isIndirect && (isCall || isBranch)) {
          const match = ops.match(/0x[0-9a-fA-F]+/);
          if (match) {
            targetAddress = parseInt(match[0], 16);
          }
        }
        break;
      }

      case "ARM": {
        if (m === "bl" || m === "blx") {
          isCall = true;
          isIndirect = m === "blx" && !ops.includes("#") && !ops.startsWith("0x");
        } else if (
          (m === "bx" && ops === "lr") ||
          (m === "pop" && ops.includes("pc")) ||
          (m === "ldm" && ops.includes("pc")) ||
          (m === "mov" && ops.startsWith("pc, lr"))
        ) {
          isReturn = true;
        } else if (m.startsWith("b") || m.startsWith("cb")) {
          isBranch = true;
          isConditional = m !== "b" && m !== "bx";
          isIndirect = m === "bx" && ops !== "lr";
        }

        if (!isIndirect && (isCall || isBranch)) {
          const match = ops.match(/(?:#)?(0x[0-9a-fA-F]+)/);
          if (match && match[1]) {
            targetAddress = parseInt(match[1], 16);
          }
        }
        break;
      }

      case "MIPS": {
        hasDelaySlot = false;
        if (m === "jal" || m === "jalr" || m === "bal" || m === "jalx") {
          isCall = true;
          isIndirect = m === "jalr";
          hasDelaySlot = true;
        } else if (m === "jr" && (ops === "$ra" || ops === "$31")) {
          isReturn = true;
          hasDelaySlot = true;
        } else if (
          m === "b" ||
          m === "j" ||
          m === "jr" ||
          m.startsWith("b")
        ) {
          isBranch = true;
          isConditional = m !== "b" && m !== "j" && m !== "jr";
          isIndirect = m === "jr";
          hasDelaySlot = true;
        }

        if (!isIndirect && (isCall || isBranch)) {
          const match = ops.match(/0x[0-9a-fA-F]+/);
          if (match) {
            targetAddress = parseInt(match[0], 16);
          }
        }
        break;
      }
    }

    return {
      isBranch,
      isConditional,
      isCall,
      isReturn,
      isIndirect,
      targetAddress,
      hasDelaySlot,
    };
  }
}
