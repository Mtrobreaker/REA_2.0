export interface TestElfOptions {
  readonly is64Bit?: boolean;
  readonly isLE?: boolean;
  readonly machine?: number; // 0x3e = x86_64, 0x28 = ARM, 0x08 = MIPS
  readonly importedSymbols?: readonly string[];
  readonly exportedSymbols?: readonly string[];
  readonly strings?: readonly string[];
  readonly dynamicLibraries?: readonly string[];
  readonly entryPoint?: number;
  readonly textBytes?: Uint8Array;
}

/**
 * Generate a synthetically valid ELF32 / ELF64 binary with real section headers,
 * program headers, dynamic string table, dynamic symbol table, and rodata strings.
 */
export function createTestElfImage(options: TestElfOptions = {}): Buffer {
  const is64 = options.is64Bit ?? false;
  const isLE = options.isLE ?? true;
  const machine = options.machine ?? (is64 ? 0x3e : 0x28);
  const entryPoint = options.entryPoint ?? 0x10000;
  const imported = options.importedSymbols ?? ["strcpy", "system"];
  const exported = options.exportedSymbols ?? ["main", "process_request"];
  const userStrings = options.strings ?? ["Hello REA", "admin:admin", "/bin/sh -c"];
  const dylibs = options.dynamicLibraries ?? ["libc.so.0"];

  // 1. Build String Table (.dynstr)
  // Starts with \0
  const dynstrChunks: Buffer[] = [Buffer.from([0])];
  const stringOffsets = new Map<string, number>();
  let dynstrLength = 1;

  const addDynString = (str: string): number => {
    let offset = stringOffsets.get(str);
    if (offset !== undefined) return offset;
    offset = dynstrLength;
    const b = Buffer.from(str + "\0", "utf8");
    dynstrChunks.push(b);
    dynstrLength += b.length;
    stringOffsets.set(str, offset);
    return offset;
  };

  for (const lib of dylibs) addDynString(lib);
  for (const s of imported) addDynString(s);
  for (const s of exported) addDynString(s);

  const dynstrBuf = Buffer.concat(dynstrChunks);

  // 2. Build Symbol Table (.dynsym)
  // Entry 0: STN_UNDEF (all zeroes)
  const symEntrySize = is64 ? 24 : 16;
  const symEntries: Buffer[] = [Buffer.alloc(symEntrySize)];

  // Add imported symbols (st_shndx = 0, FUNC or NOTYPE)
  for (const s of imported) {
    const sym = Buffer.alloc(symEntrySize);
    const nameOff = addDynString(s);
    if (is64) {
      if (isLE) {
        sym.writeUInt32LE(nameOff, 0);
        sym.writeUInt8(0x12, 4); // STB_GLOBAL (1) | STT_FUNC (2)
        sym.writeUInt16LE(0, 6); // SHN_UNDEF = 0
        sym.writeBigUInt64LE(0n, 8); // value = 0
        sym.writeBigUInt64LE(0n, 16); // size = 0
      } else {
        sym.writeUInt32BE(nameOff, 0);
        sym.writeUInt8(0x12, 4);
        sym.writeUInt16BE(0, 6);
        sym.writeBigUInt64BE(0n, 8);
        sym.writeBigUInt64BE(0n, 16);
      }
    } else {
      if (isLE) {
        sym.writeUInt32LE(nameOff, 0);
        sym.writeUInt32LE(0, 4); // value = 0
        sym.writeUInt32LE(0, 8); // size = 0
        sym.writeUInt8(0x12, 12);
        sym.writeUInt16LE(0, 14); // SHN_UNDEF = 0
      } else {
        sym.writeUInt32BE(nameOff, 0);
        sym.writeUInt32BE(0, 4);
        sym.writeUInt32BE(0, 8);
        sym.writeUInt8(0x12, 12);
        sym.writeUInt16BE(0, 14);
      }
    }
    symEntries.push(sym);
  }

  // Add exported symbols (st_shndx = 1 (.text), st_value > 0)
  let funcAddr = entryPoint;
  for (const s of exported) {
    const sym = Buffer.alloc(symEntrySize);
    const nameOff = addDynString(s);
    if (is64) {
      if (isLE) {
        sym.writeUInt32LE(nameOff, 0);
        sym.writeUInt8(0x12, 4);
        sym.writeUInt16LE(1, 6); // Section 1 (.text)
        sym.writeBigUInt64LE(BigInt(funcAddr), 8);
        sym.writeBigUInt64LE(64n, 16); // size
      } else {
        sym.writeUInt32BE(nameOff, 0);
        sym.writeUInt8(0x12, 4);
        sym.writeUInt16BE(1, 6);
        sym.writeBigUInt64BE(BigInt(funcAddr), 8);
        sym.writeBigUInt64BE(64n, 16);
      }
    } else {
      if (isLE) {
        sym.writeUInt32LE(nameOff, 0);
        sym.writeUInt32LE(funcAddr, 4);
        sym.writeUInt32LE(64, 8);
        sym.writeUInt8(0x12, 12);
        sym.writeUInt16LE(1, 14);
      } else {
        sym.writeUInt32BE(nameOff, 0);
        sym.writeUInt32BE(funcAddr, 4);
        sym.writeUInt32BE(64, 8);
        sym.writeUInt8(0x12, 12);
        sym.writeUInt16BE(1, 14);
      }
    }
    funcAddr += 64;
    symEntries.push(sym);
  }

  const dynsymBuf = Buffer.concat(symEntries);

  // 3. Build .rodata section with user strings
  const rodataChunks: Buffer[] = [];
  for (const s of userStrings) {
    rodataChunks.push(Buffer.from(s + "\0", "utf8"));
  }
  const rodataBuf = Buffer.concat(rodataChunks);

  // 4. Build .text section (actual machine code if provided, otherwise NOP padding)
  const textBuf = options.textBytes ? Buffer.from(options.textBytes) : Buffer.alloc(256, 0x90);

  // 5. Build .dynamic section (DT_NEEDED entries, DT_STRTAB, DT_SYMTAB, DT_NULL)
  const dynEntrySize = is64 ? 16 : 8;
  const dynEntries: Buffer[] = [];

  for (const lib of dylibs) {
    const d = Buffer.alloc(dynEntrySize);
    const strOff = addDynString(lib);
    if (is64) {
      if (isLE) {
        d.writeBigUInt64LE(1n, 0); // DT_NEEDED
        d.writeBigUInt64LE(BigInt(strOff), 8);
      } else {
        d.writeBigUInt64BE(1n, 0);
        d.writeBigUInt64BE(BigInt(strOff), 8);
      }
    } else {
      if (isLE) {
        d.writeUInt32LE(1, 0);
        d.writeUInt32LE(strOff, 4);
      } else {
        d.writeUInt32BE(1, 0);
        d.writeUInt32BE(strOff, 4);
      }
    }
    dynEntries.push(d);
  }

  // DT_NULL terminating entry
  dynEntries.push(Buffer.alloc(dynEntrySize));
  const dynamicBuf = Buffer.concat(dynEntries);

  // 6. Build Section Header String Table (.shstrtab)
  const shstrList = ["", ".text", ".rodata", ".dynsym", ".dynstr", ".dynamic", ".shstrtab"];
  const shstrChunks: Buffer[] = [];
  const shstrOffsets: number[] = [];
  let shstrTotal = 0;
  for (const s of shstrList) {
    shstrOffsets.push(shstrTotal);
    const b = Buffer.from(s + "\0", "utf8");
    shstrChunks.push(b);
    shstrTotal += b.length;
  }
  const shstrtabBuf = Buffer.concat(shstrChunks);

  // Calculate layout offsets
  const elfHeaderSize = is64 ? 64 : 52;
  const phentSize = is64 ? 56 : 32;
  const phnum = 2; // PT_LOAD, PT_DYNAMIC
  const phoff = elfHeaderSize;

  const textOffset = phoff + phentSize * phnum;
  const rodataOffset = textOffset + textBuf.length;
  const dynstrOffset = rodataOffset + rodataBuf.length;
  const dynsymOffset = dynstrOffset + dynstrBuf.length;
  const dynamicOffset = dynsymOffset + dynsymBuf.length;
  const shstrtabOffset = dynamicOffset + dynamicBuf.length;

  const shentSize = is64 ? 64 : 40;
  const shnum = 7; // NULL, .text, .rodata, .dynsym, .dynstr, .dynamic, .shstrtab
  const shoff = shstrtabOffset + shstrtabBuf.length;

  const totalFileSize = shoff + shentSize * shnum;
  const totalBuf = Buffer.alloc(totalFileSize);

  // Write ELF Header
  totalBuf[0] = 0x7f;
  totalBuf[1] = 0x45;
  totalBuf[2] = 0x4c;
  totalBuf[3] = 0x46;
  totalBuf[4] = is64 ? 2 : 1;
  totalBuf[5] = isLE ? 1 : 2;
  totalBuf[6] = 1;

  if (isLE) {
    totalBuf.writeUInt16LE(2, 16); // e_type = ET_EXEC
    totalBuf.writeUInt16LE(machine, 18);
    totalBuf.writeUInt32LE(1, 20); // e_version = 1
    if (is64) {
      totalBuf.writeBigUInt64LE(BigInt(entryPoint), 24);
      totalBuf.writeBigUInt64LE(BigInt(phoff), 32);
      totalBuf.writeBigUInt64LE(BigInt(shoff), 40);
      totalBuf.writeUInt32LE(0, 48); // flags
      totalBuf.writeUInt16LE(elfHeaderSize, 52);
      totalBuf.writeUInt16LE(phentSize, 54);
      totalBuf.writeUInt16LE(phnum, 56);
      totalBuf.writeUInt16LE(shentSize, 58);
      totalBuf.writeUInt16LE(shnum, 60);
      totalBuf.writeUInt16LE(6, 62); // e_shstrndx = 6 (.shstrtab)
    } else {
      totalBuf.writeUInt32LE(entryPoint, 24);
      totalBuf.writeUInt32LE(phoff, 28);
      totalBuf.writeUInt32LE(shoff, 32);
      totalBuf.writeUInt32LE(0, 36);
      totalBuf.writeUInt16LE(elfHeaderSize, 40);
      totalBuf.writeUInt16LE(phentSize, 42);
      totalBuf.writeUInt16LE(phnum, 44);
      totalBuf.writeUInt16LE(shentSize, 46);
      totalBuf.writeUInt16LE(shnum, 48);
      totalBuf.writeUInt16LE(6, 50); // e_shstrndx = 6
    }
  } else {
    totalBuf.writeUInt16BE(2, 16);
    totalBuf.writeUInt16BE(machine, 18);
    totalBuf.writeUInt32BE(1, 20);
    if (is64) {
      totalBuf.writeBigUInt64BE(BigInt(entryPoint), 24);
      totalBuf.writeBigUInt64BE(BigInt(phoff), 32);
      totalBuf.writeBigUInt64BE(BigInt(shoff), 40);
      totalBuf.writeUInt32BE(0, 48);
      totalBuf.writeUInt16BE(elfHeaderSize, 52);
      totalBuf.writeUInt16BE(phentSize, 54);
      totalBuf.writeUInt16BE(phnum, 56);
      totalBuf.writeUInt16BE(shentSize, 58);
      totalBuf.writeUInt16BE(shnum, 60);
      totalBuf.writeUInt16BE(6, 62);
    } else {
      totalBuf.writeUInt32BE(entryPoint, 24);
      totalBuf.writeUInt32BE(phoff, 28);
      totalBuf.writeUInt32BE(shoff, 32);
      totalBuf.writeUInt32BE(0, 36);
      totalBuf.writeUInt16BE(elfHeaderSize, 40);
      totalBuf.writeUInt16BE(phentSize, 42);
      totalBuf.writeUInt16BE(phnum, 44);
      totalBuf.writeUInt16BE(shentSize, 46);
      totalBuf.writeUInt16BE(shnum, 48);
      totalBuf.writeUInt16BE(6, 50);
    }
  }

  // Write Program Header 1: PT_LOAD
  if (is64) {
    totalBuf.writeUInt32LE(1, phoff); // p_type = PT_LOAD
    totalBuf.writeUInt32LE(5, phoff + 4); // p_flags = R | X
    totalBuf.writeBigUInt64LE(BigInt(textOffset), phoff + 8);
    totalBuf.writeBigUInt64LE(BigInt(entryPoint), phoff + 16);
    totalBuf.writeBigUInt64LE(BigInt(entryPoint), phoff + 24);
    totalBuf.writeBigUInt64LE(BigInt(textBuf.length + rodataBuf.length), phoff + 32);
    totalBuf.writeBigUInt64LE(BigInt(textBuf.length + rodataBuf.length), phoff + 40);
  } else {
    totalBuf.writeUInt32LE(1, phoff);
    totalBuf.writeUInt32LE(textOffset, phoff + 4);
    totalBuf.writeUInt32LE(entryPoint, phoff + 8);
    totalBuf.writeUInt32LE(entryPoint, phoff + 12);
    totalBuf.writeUInt32LE(textBuf.length + rodataBuf.length, phoff + 16);
    totalBuf.writeUInt32LE(textBuf.length + rodataBuf.length, phoff + 20);
    totalBuf.writeUInt32LE(5, phoff + 24);
  }

  // Write Program Header 2: PT_DYNAMIC
  const ph2 = phoff + phentSize;
  if (is64) {
    totalBuf.writeUInt32LE(2, ph2); // PT_DYNAMIC
    totalBuf.writeUInt32LE(6, ph2 + 4); // R | W
    totalBuf.writeBigUInt64LE(BigInt(dynamicOffset), ph2 + 8);
    totalBuf.writeBigUInt64LE(BigInt(0x20000), ph2 + 16);
    totalBuf.writeBigUInt64LE(BigInt(0x20000), ph2 + 24);
    totalBuf.writeBigUInt64LE(BigInt(dynamicBuf.length), ph2 + 32);
    totalBuf.writeBigUInt64LE(BigInt(dynamicBuf.length), ph2 + 40);
  } else {
    totalBuf.writeUInt32LE(2, ph2);
    totalBuf.writeUInt32LE(dynamicOffset, ph2 + 4);
    totalBuf.writeUInt32LE(0x20000, ph2 + 8);
    totalBuf.writeUInt32LE(0x20000, ph2 + 12);
    totalBuf.writeUInt32LE(dynamicBuf.length, ph2 + 16);
    totalBuf.writeUInt32LE(dynamicBuf.length, ph2 + 20);
    totalBuf.writeUInt32LE(6, ph2 + 24);
  }

  // Copy Section Payloads
  textBuf.copy(totalBuf, textOffset);
  rodataBuf.copy(totalBuf, rodataOffset);
  dynstrBuf.copy(totalBuf, dynstrOffset);
  dynsymBuf.copy(totalBuf, dynsymOffset);
  dynamicBuf.copy(totalBuf, dynamicOffset);
  shstrtabBuf.copy(totalBuf, shstrtabOffset);

  // Write Section Headers
  const sectionsData = [
    { nameIdx: 0, type: 0, flags: 0, addr: 0, offset: 0, size: 0 }, // NULL
    { nameIdx: 1, type: 1, flags: 6, addr: entryPoint, offset: textOffset, size: textBuf.length }, // .text (SHT_PROGBITS, ALLOC|EXEC)
    { nameIdx: 2, type: 1, flags: 2, addr: entryPoint + 0x1000, offset: rodataOffset, size: rodataBuf.length }, // .rodata (ALLOC)
    { nameIdx: 3, type: 11, flags: 2, addr: 0, offset: dynsymOffset, size: dynsymBuf.length }, // .dynsym (SHT_DYNSYM)
    { nameIdx: 4, type: 3, flags: 2, addr: 0, offset: dynstrOffset, size: dynstrBuf.length }, // .dynstr (SHT_STRTAB)
    { nameIdx: 5, type: 6, flags: 3, addr: 0x20000, offset: dynamicOffset, size: dynamicBuf.length }, // .dynamic (SHT_DYNAMIC)
    { nameIdx: 6, type: 3, flags: 0, addr: 0, offset: shstrtabOffset, size: shstrtabBuf.length }, // .shstrtab (SHT_STRTAB)
  ];

  for (let i = 0; i < sectionsData.length; i++) {
    const s = sectionsData[i]!;
    const entry = shoff + i * shentSize;
    const nameOff = shstrOffsets[s.nameIdx] ?? 0;

    if (is64) {
      totalBuf.writeUInt32LE(nameOff, entry);
      totalBuf.writeUInt32LE(s.type, entry + 4);
      totalBuf.writeBigUInt64LE(BigInt(s.flags), entry + 8);
      totalBuf.writeBigUInt64LE(BigInt(s.addr), entry + 16);
      totalBuf.writeBigUInt64LE(BigInt(s.offset), entry + 24);
      totalBuf.writeBigUInt64LE(BigInt(s.size), entry + 32);
    } else {
      totalBuf.writeUInt32LE(nameOff, entry);
      totalBuf.writeUInt32LE(s.type, entry + 4);
      totalBuf.writeUInt32LE(s.flags, entry + 8);
      totalBuf.writeUInt32LE(s.addr, entry + 12);
      totalBuf.writeUInt32LE(s.offset, entry + 16);
      totalBuf.writeUInt32LE(s.size, entry + 20);
    }
  }

  return totalBuf;
}
