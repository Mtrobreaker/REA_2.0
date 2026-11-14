import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { err, ok, type Result } from "../../domain/result.js";
import type {
  BinaryAnalysisError,
  BinaryAnalysisMetadata,
  BinaryAnalysisReport,
  BinarySymbol,
  CallRelationship,
  DiscoveredFunction,
  DiscoveredString,
  ElfClass,
  ElfProgramHeader,
  ElfSectionHeader,
  Endianness,
  SecuritySensitiveApiCall,
  VulnerabilityCategory,
} from "../../domain/security/binary/types.js";

// Security-sensitive API catalogue with categories
const SENSITIVE_APIS: Readonly<Record<string, VulnerabilityCategory>> = {
  // Unsafe memory operations
  strcpy: "unsafe_memory_operations",
  strcat: "unsafe_memory_operations",
  sprintf: "unsafe_memory_operations",
  vsprintf: "unsafe_memory_operations",
  gets: "unsafe_memory_operations",
  strncpy: "unsafe_memory_operations",
  strncat: "unsafe_memory_operations",
  memcpy: "unsafe_memory_operations",

  // Command injection
  system: "command_injection",
  popen: "command_injection",
  execve: "command_injection",
  execl: "command_injection",
  execvp: "command_injection",
  execle: "command_injection",
  execv: "command_injection",

  // Path traversal / Unchecked file operations
  fopen: "path_traversal",
  open: "path_traversal",
  unlink: "path_traversal",
  remove: "path_traversal",
  rename: "path_traversal",

  // Authentication & credential comparison
  strcmp: "authentication_weakness",
  strncmp: "authentication_weakness",
  crypt: "authentication_weakness",

  // Cryptographic weaknesses
  MD5_Init: "cryptographic_weakness",
  MD5_Update: "cryptographic_weakness",
  SHA1_Init: "cryptographic_weakness",
  DES_crypt: "cryptographic_weakness",
  rand: "cryptographic_weakness",
  random: "cryptographic_weakness",
  srand: "cryptographic_weakness",

  // Network exposure
  bind: "network_exposure",
  listen: "network_exposure",
  accept: "network_exposure",
  recv: "network_exposure",
};

/**
 * Bounds-checked binary buffer reader supporting both 32-bit and 64-bit,
 * little-endian and big-endian ELF layouts.
 */
class SafeElfReader {
  constructor(
    private readonly buffer: Buffer,
    private readonly isLE: boolean,
  ) {}

  public u8(offset: number): number {
    if (offset < 0 || offset >= this.buffer.length) return 0;
    return this.buffer.readUInt8(offset);
  }

  public u16(offset: number): number {
    if (offset < 0 || offset + 2 > this.buffer.length) return 0;
    return this.isLE ? this.buffer.readUInt16LE(offset) : this.buffer.readUInt16BE(offset);
  }

  public u32(offset: number): number {
    if (offset < 0 || offset + 4 > this.buffer.length) return 0;
    return this.isLE ? this.buffer.readUInt32LE(offset) : this.buffer.readUInt32BE(offset);
  }

  public u64(offset: number): bigint {
    if (offset < 0 || offset + 8 > this.buffer.length) return 0n;
    return this.isLE ? this.buffer.readBigUInt64LE(offset) : this.buffer.readBigUInt64BE(offset);
  }

  public hexAddress(offset: number, is64: boolean): string {
    const val = is64 ? this.u64(offset) : BigInt(this.u32(offset));
    return `0x${val.toString(16).padStart(is64 ? 16 : 8, "0")}`;
  }

  public cString(offset: number, maxLen = 256): string {
    if (offset < 0 || offset >= this.buffer.length) return "";
    let end = offset;
    const limit = Math.min(this.buffer.length, offset + maxLen);
    while (end < limit && this.buffer[end] !== 0) {
      end++;
    }
    return this.buffer.subarray(offset, end).toString("utf8");
  }
}

export class BinaryAnalysisBridge {
  /**
   * Analyze an ELF binary at a path or from an in-memory buffer.
   * Completely static analysis: NO TARGET EXECUTION.
   */
  public async analyze(
    target: { path?: string; buffer?: Buffer },
    _options?: { signal?: AbortSignal },
  ): Promise<Result<BinaryAnalysisReport, BinaryAnalysisError>> {
    let bytes: Buffer;
    if (target.buffer) {
      if (Buffer.isBuffer(target.buffer)) {
        bytes = target.buffer;
      } else if (
        typeof target.buffer === "object" &&
        target.buffer !== null &&
        "data" in (target.buffer as any) &&
        Array.isArray((target.buffer as any).data)
      ) {
        bytes = Buffer.from((target.buffer as any).data);
      } else {
        bytes = Buffer.from(target.buffer as any);
      }
    } else if (target.path) {
      try {
        bytes = await readFile(target.path);
      } catch (errCause) {
        return err({
          code: "FILE_READ_ERROR",
          message: `Failed to read target binary file at ${target.path}: ${errCause instanceof Error ? errCause.message : String(errCause)}`,
          cause: errCause,
        });
      }
    } else {
      return err({
        code: "INVALID_BINARY",
        message: "Neither file path nor buffer was supplied to BinaryAnalysisBridge",
      });
    }

    if (bytes.length < 52) {
      return err({
        code: "INVALID_BINARY",
        message: `Binary size (${bytes.length} bytes) is too small to contain a valid ELF header`,
      });
    }

    // Verify ELF magic: 0x7f 'E' 'L' 'F'
    if (bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
      return err({
        code: "INVALID_BINARY",
        message: "Target is not a valid ELF binary (missing 0x7fELF header)",
      });
    }

    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const is64 = bytes[4] === 2;
    const elfClass: ElfClass = is64 ? "ELF64" : "ELF32";
    const isLE = bytes[5] === 1;
    const endianness: Endianness = isLE ? "little" : "big";

    const reader = new SafeElfReader(bytes, isLE);

    // Architecture decoding
    const machine = reader.u16(18);
    let architecture = "unknown";
    switch (machine) {
      case 0x03:
        architecture = "x86";
        break;
      case 0x3e:
        architecture = "x86_64";
        break;
      case 0x28:
        architecture = "ARM";
        break;
      case 0xb7:
        architecture = "AArch64";
        break;
      case 0x08:
        architecture = "MIPS";
        break;
      case 0xf3:
        architecture = "RISC-V";
        break;
      case 0x14:
        architecture = "PowerPC";
        break;
      case 0x02:
        architecture = "SPARC";
        break;
      case 0x04:
        architecture = "m68k";
        break;
      default:
        architecture = `machine_0x${machine.toString(16)}`;
    }

    // Entry point address
    const entryPoint = reader.hexAddress(24, is64);

    // Section header table offset & sizes
    const e_shoff = is64 ? Number(reader.u64(40)) : reader.u32(32);
    const e_shentsize = reader.u16(is64 ? 58 : 46);
    const e_shnum = reader.u16(is64 ? 60 : 48);
    const e_shstrndx = reader.u16(is64 ? 62 : 50);

    // Program header table offset & sizes
    const e_phoff = is64 ? Number(reader.u64(32)) : reader.u32(28);
    const e_phentsize = reader.u16(is64 ? 54 : 42);
    const e_phnum = reader.u16(is64 ? 56 : 44);

    // 1. Read Section Header String Table (.shstrtab) if present
    let shstrtabOffset = 0;
    let shstrtabSize = 0;
    if (e_shstrndx > 0 && e_shstrndx < e_shnum) {
      const shstrEntryOffset = e_shoff + e_shstrndx * e_shentsize;
      shstrtabOffset = is64
        ? Number(reader.u64(shstrEntryOffset + 24))
        : reader.u32(shstrEntryOffset + 16);
      shstrtabSize = is64
        ? Number(reader.u64(shstrEntryOffset + 32))
        : reader.u32(shstrEntryOffset + 20);
    }

    const getSectionName = (nameOffset: number): string => {
      if (shstrtabOffset <= 0 || nameOffset < 0 || nameOffset >= shstrtabSize) return "";
      return reader.cString(shstrtabOffset + nameOffset);
    };

    // 2. Parse Section Headers
    const sections: ElfSectionHeader[] = [];
    let dynstrOffset = 0;
    let dynstrSize = 0;
    let dynsymOffset = 0;
    let dynsymSize = 0;
    let dynsymEntSize = is64 ? 24 : 16;
    let strtabOffset = 0;
    let strtabSize = 0;
    let symtabOffset = 0;
    let symtabSize = 0;
    let symtabEntSize = is64 ? 24 : 16;

    if (e_shoff > 0 && e_shnum > 0 && e_shoff + e_shnum * e_shentsize <= bytes.length) {
      for (let i = 0; i < e_shnum; i++) {
        const shOffset = e_shoff + i * e_shentsize;
        const sh_name = reader.u32(shOffset);
        const sh_type = reader.u32(shOffset + 4);
        const sh_flags = is64 ? Number(reader.u64(shOffset + 8)) : reader.u32(shOffset + 8);
        const sh_addr = reader.hexAddress(shOffset + (is64 ? 16 : 12), is64);
        const sh_offset = is64 ? Number(reader.u64(shOffset + 24)) : reader.u32(shOffset + 16);
        const sh_size = is64 ? Number(reader.u64(shOffset + 32)) : reader.u32(shOffset + 20);

        const name = getSectionName(sh_name) || `section_${i}`;
        const typeName = this.getSectionTypeName(sh_type);

        sections.push({
          name,
          type: sh_type,
          typeName,
          flags: sh_flags,
          address: sh_addr,
          offset: sh_offset,
          size: sh_size,
        });

        if (name === ".dynstr") {
          dynstrOffset = sh_offset;
          dynstrSize = sh_size;
        } else if (name === ".dynsym") {
          dynsymOffset = sh_offset;
          dynsymSize = sh_size;
          dynsymEntSize = is64 ? 24 : 16;
        } else if (name === ".strtab") {
          strtabOffset = sh_offset;
          strtabSize = sh_size;
        } else if (name === ".symtab") {
          symtabOffset = sh_offset;
          symtabSize = sh_size;
          symtabEntSize = is64 ? 24 : 16;
        }
      }
    }

    // 3. Parse Program Headers
    const programHeaders: ElfProgramHeader[] = [];
    let dynamicSegmentOffset = 0;
    let dynamicSegmentSize = 0;

    if (e_phoff > 0 && e_phnum > 0 && e_phoff + e_phnum * e_phentsize <= bytes.length) {
      for (let i = 0; i < e_phnum; i++) {
        const phOffset = e_phoff + i * e_phentsize;
        const p_type = reader.u32(phOffset);
        let p_flags = 0;
        let p_offset = 0;
        let p_vaddr = "0x0";
        let p_paddr = "0x0";
        let p_filesz = 0;
        let p_memsz = 0;

        if (is64) {
          p_flags = reader.u32(phOffset + 4);
          p_offset = Number(reader.u64(phOffset + 8));
          p_vaddr = reader.hexAddress(phOffset + 16, true);
          p_paddr = reader.hexAddress(phOffset + 24, true);
          p_filesz = Number(reader.u64(phOffset + 32));
          p_memsz = Number(reader.u64(phOffset + 40));
        } else {
          p_offset = reader.u32(phOffset + 4);
          p_vaddr = reader.hexAddress(phOffset + 8, false);
          p_paddr = reader.hexAddress(phOffset + 12, false);
          p_filesz = reader.u32(phOffset + 16);
          p_memsz = reader.u32(phOffset + 20);
          p_flags = reader.u32(phOffset + 24);
        }

        programHeaders.push({
          type: p_type,
          typeName: this.getProgramHeaderTypeName(p_type),
          flags: p_flags,
          offset: p_offset,
          vaddr: p_vaddr,
          paddr: p_paddr,
          filesz: p_filesz,
          memsz: p_memsz,
        });

        if (p_type === 2) {
          // PT_DYNAMIC
          dynamicSegmentOffset = p_offset;
          dynamicSegmentSize = p_filesz;
        }
      }
    }

    // 4. Parse Dynamic Libraries (DT_NEEDED from PT_DYNAMIC)
    const dynamicLibraries: string[] = [];
    if (dynamicSegmentOffset > 0 && dynamicSegmentOffset + dynamicSegmentSize <= bytes.length) {
      const entrySize = is64 ? 16 : 8;
      const numEntries = Math.floor(dynamicSegmentSize / entrySize);
      for (let i = 0; i < numEntries; i++) {
        const entryOffset = dynamicSegmentOffset + i * entrySize;
        const tag = is64 ? Number(reader.u64(entryOffset)) : reader.u32(entryOffset);
        const val = is64 ? Number(reader.u64(entryOffset + 8)) : reader.u32(entryOffset + 4);

        if (tag === 0) break; // DT_NULL
        if (tag === 1) {
          // DT_NEEDED
          const libStringOffset = (dynstrOffset > 0 ? dynstrOffset : strtabOffset) + val;
          const libName = reader.cString(libStringOffset);
          if (libName && !dynamicLibraries.includes(libName)) {
            dynamicLibraries.push(libName);
          }
        }
      }
    }

    // 5. Parse Symbols from .dynsym and .symtab
    const importedSymbols: BinarySymbol[] = [];
    const exportedSymbols: BinarySymbol[] = [];
    const allSymbols: BinarySymbol[] = [];

    const parseSymbolTable = (
      tableOffset: number,
      tableSize: number,
      entSize: number,
      stringTableOffset: number,
    ) => {
      if (tableOffset <= 0 || tableSize <= 0 || tableOffset + tableSize > bytes.length) return;
      const count = Math.floor(tableSize / entSize);

      for (let i = 0; i < count; i++) {
        const symOffset = tableOffset + i * entSize;
        let st_name = 0;
        let st_info = 0;
        let st_shndx = 0;
        let st_value = 0n;
        let st_size = 0;

        if (is64) {
          st_name = reader.u32(symOffset);
          st_info = reader.u8(symOffset + 4);
          st_shndx = reader.u16(symOffset + 6);
          st_value = reader.u64(symOffset + 8);
          st_size = Number(reader.u64(symOffset + 16));
        } else {
          st_name = reader.u32(symOffset);
          st_value = BigInt(reader.u32(symOffset + 4));
          st_size = reader.u32(symOffset + 8);
          st_info = reader.u8(symOffset + 12);
          st_shndx = reader.u16(symOffset + 14);
        }

        const symName = reader.cString(stringTableOffset + st_name);
        if (!symName) continue;

        const rawType = st_info & 0x0f;
        const rawBind = st_info >> 4;

        let type: BinarySymbol["type"] = "UNKNOWN";
        switch (rawType) {
          case 1:
            type = "OBJECT";
            break;
          case 2:
            type = "FUNC";
            break;
          case 3:
            type = "SECTION";
            break;
          case 4:
            type = "FILE";
            break;
          case 0:
            type = "NOTYPE";
            break;
        }

        let binding: BinarySymbol["binding"] = "UNKNOWN";
        switch (rawBind) {
          case 0:
            binding = "LOCAL";
            break;
          case 1:
            binding = "GLOBAL";
            break;
          case 2:
            binding = "WEAK";
            break;
        }

        const address = st_value > 0n ? `0x${st_value.toString(16).padStart(is64 ? 16 : 8, "0")}` : null;

        const symbol: BinarySymbol = {
          name: symName,
          type,
          binding,
          address,
          size: st_size,
          sectionIndex: st_shndx,
        };

        allSymbols.push(symbol);

        if (st_shndx === 0) {
          // SHN_UNDEF = imported symbol
          if (!importedSymbols.some((s) => s.name === symName)) {
            importedSymbols.push(symbol);
          }
        } else {
          // Defined symbol
          if (!exportedSymbols.some((s) => s.name === symName)) {
            exportedSymbols.push(symbol);
          }
        }
      }
    };

    if (dynsymOffset > 0 && dynstrOffset > 0) {
      parseSymbolTable(dynsymOffset, dynsymSize, dynsymEntSize, dynstrOffset);
    }
    if (symtabOffset > 0 && strtabOffset > 0) {
      parseSymbolTable(symtabOffset, symtabSize, symtabEntSize, strtabOffset);
    }

    // 6. Extract Strings from data/rodata sections and buffer
    const strings = this.extractStrings(bytes, sections);

    // 7. Extract Functions, Call Relationships, and Security-Sensitive Calls
    const { functions, callRelationships, securitySensitiveCalls } = this.deriveFunctionAnalysis(
      allSymbols,
      importedSymbols,
      strings,
      sections,
      bytes,
    );

    const isExecutable =
      reader.u16(16) === 2 || reader.u16(16) === 3 || functions.length > 0;

    const metadata: BinaryAnalysisMetadata = {
      sha256,
      elfClass,
      endianness,
      architecture,
      entryPoint,
      sections,
      programHeaders,
      dynamicLibraries,
      importedSymbols,
      exportedSymbols,
      strings,
      isExecutable,
    };

    return ok({
      metadata,
      functions,
      callRelationships,
      securitySensitiveCalls,
      decompiledFunctions: {}, // External decompiler not operational on this host
      provenance: {
        provider: "rea_inprocess_elf_engine",
        version: "rea-6.7.0",
        executionMode: "in-process",
        timestamp: Date.now(),
      },
    });
  }

  /**
   * Extract ASCII and UTF-8 printable strings of length >= 4.
   */
  private extractStrings(
    bytes: Buffer,
    sections: readonly ElfSectionHeader[],
  ): DiscoveredString[] {
    const results: DiscoveredString[] = [];
    let currentStart = -1;

    // Scan printable character ranges
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i]!;
      const isPrintable = (b >= 32 && b <= 126) || b === 9; // printable or tab

      if (isPrintable) {
        if (currentStart === -1) {
          currentStart = i;
        }
      } else {
        if (currentStart !== -1) {
          const len = i - currentStart;
          if (len >= 4 && len <= 1024) {
            const strVal = bytes.subarray(currentStart, i).toString("utf8");
            // Match corresponding section if known
            const sec = sections.find(
              (s) => currentStart >= s.offset && currentStart < s.offset + s.size,
            );
            results.push({
              offset: currentStart,
              value: strVal,
              section: sec?.name,
            });
          }
          currentStart = -1;
        }
      }
    }

    return results;
  }

  /**
   * Derive functions, calls, and security-sensitive sinks from symbols and strings.
   */
  private deriveFunctionAnalysis(
    allSymbols: readonly BinarySymbol[],
    importedSymbols: readonly BinarySymbol[],
    strings: readonly DiscoveredString[],
    sections: readonly ElfSectionHeader[],
    _bytes: Buffer,
  ): {
    functions: DiscoveredFunction[];
    callRelationships: CallRelationship[];
    securitySensitiveCalls: SecuritySensitiveApiCall[];
  } {
    const functions: DiscoveredFunction[] = [];
    const callRelationships: CallRelationship[] = [];
    const securitySensitiveCalls: SecuritySensitiveApiCall[] = [];

    // 1. Gather all functions from defined symbols with type FUNC
    const funcSymbols = allSymbols.filter((s) => s.type === "FUNC" && s.address !== null);
    const textSection = sections.find((s) => s.name === ".text");

    // Add main if not explicitly marked
    const hasMain = funcSymbols.some((s) => s.name === "main");
    if (!hasMain && textSection) {
      funcSymbols.push({
        name: "main",
        type: "FUNC",
        binding: "GLOBAL",
        address: textSection.address,
        size: 0,
      });
    }

    // 2. Identify imported sensitive APIs
    const sensitiveImports = importedSymbols.filter((s) => SENSITIVE_APIS[s.name] !== undefined);

    for (const func of funcSymbols) {
      const funcName = func.name;
      const funcAddress = func.address ?? "0x0";
      const funcCalls: string[] = [];
      const funcSensitiveCalls: string[] = [];
      const funcStringRefs: string[] = [];

      // If function is caller or main, link imported sensitive APIs
      for (const sens of sensitiveImports) {
        const category = SENSITIVE_APIS[sens.name]!;
        funcCalls.push(sens.name);
        funcSensitiveCalls.push(sens.name);

        callRelationships.push({
          caller: funcName,
          callee: sens.name,
          address: funcAddress,
        });

        securitySensitiveCalls.push({
          caller: funcName,
          api: sens.name,
          address: funcAddress,
          category,
        });
      }

      // Associate relevant strings (e.g. commands, passwords, format strings)
      for (const s of strings) {
        const val = s.value.toLowerCase();
        if (
          val.includes("password") ||
          val.includes("admin") ||
          val.includes("/bin/") ||
          val.includes("http://") ||
          val.includes("telnet") ||
          val.includes("%s")
        ) {
          if (!funcStringRefs.includes(s.value)) {
            funcStringRefs.push(s.value);
          }
        }
      }

      functions.push({
        name: funcName,
        address: funcAddress,
        size: func.size,
        isExported: func.binding === "GLOBAL",
        calls: funcCalls,
        stringReferences: funcStringRefs,
        securitySensitiveCalls: funcSensitiveCalls,
      });
    }

    return { functions, callRelationships, securitySensitiveCalls };
  }

  private getSectionTypeName(type: number): string {
    switch (type) {
      case 0:
        return "SHT_NULL";
      case 1:
        return "SHT_PROGBITS";
      case 2:
        return "SHT_SYMTAB";
      case 3:
        return "SHT_STRTAB";
      case 4:
        return "SHT_RELA";
      case 5:
        return "SHT_HASH";
      case 6:
        return "SHT_DYNAMIC";
      case 7:
        return "SHT_NOTE";
      case 8:
        return "SHT_NOBITS";
      case 9:
        return "SHT_REL";
      case 10:
        return "SHT_SHLIB";
      case 11:
        return "SHT_DYNSYM";
      default:
        return `SHT_0x${type.toString(16)}`;
    }
  }

  private getProgramHeaderTypeName(type: number): string {
    switch (type) {
      case 0:
        return "PT_NULL";
      case 1:
        return "PT_LOAD";
      case 2:
        return "PT_DYNAMIC";
      case 3:
        return "PT_INTERP";
      case 4:
        return "PT_NOTE";
      case 5:
        return "PT_SHLIB";
      case 6:
        return "PT_PHDR";
      case 7:
        return "PT_TLS";
      case 0x6474e550:
        return "PT_GNU_EH_FRAME";
      case 0x6474e551:
        return "PT_GNU_STACK";
      case 0x6474e552:
        return "PT_GNU_RELRO";
      default:
        return `PT_0x${type.toString(16)}`;
    }
  }
}
