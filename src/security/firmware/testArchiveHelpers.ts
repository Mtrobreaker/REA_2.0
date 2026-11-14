/**
 * Test archive helper to generate valid and malformed TAR buffers.
 */
export interface TarTestEntry {
  readonly name: string;
  readonly content?: string | Buffer | undefined;
  readonly typeflag?: string | undefined;
  readonly linkname?: string | undefined;
  readonly overrideSize?: number | undefined;
}

export function createTarBuffer(entries: readonly TarTestEntry[]): Buffer {
  const blocks: Buffer[] = [];

  for (const entry of entries) {
    const header = Buffer.alloc(512);
    const content = Buffer.isBuffer(entry.content)
      ? entry.content
      : Buffer.from(entry.content ?? "", "utf8");
    const size = entry.overrideSize ?? (entry.typeflag === "5" ? 0 : content.length);

    // Name (0..100)
    header.write(entry.name, 0, Math.min(entry.name.length, 100), "utf8");

    // Mode (100..108)
    header.write("0000644\0", 100, 8, "ascii");

    // UID / GID
    header.write("0000000\0", 108, 8, "ascii");
    header.write("0000000\0", 116, 8, "ascii");

    // Size (124..136) in octal
    const sizeOctal = size.toString(8).padStart(11, "0") + " ";
    header.write(sizeOctal, 124, 12, "ascii");

    // Mtime (136..148)
    header.write("00000000000\0", 136, 12, "ascii");

    // Typeflag (156)
    header.write(entry.typeflag ?? "0", 156, 1, "ascii");

    // Linkname (157..257)
    if (entry.linkname) {
      header.write(entry.linkname, 157, Math.min(entry.linkname.length, 100), "utf8");
    }

    // Magic & version (257..265)
    header.write("ustar\0", 257, 6, "ascii");
    header.write("00", 263, 2, "ascii");

    // Compute checksum (148..156)
    // First fill chksum with spaces (8 spaces)
    header.fill(0x20, 148, 156);
    let chksum = 0;
    for (let i = 0; i < 512; i++) {
      chksum += header[i]!;
    }
    const chksumOctal = chksum.toString(8).padStart(6, "0") + "\0 ";
    header.write(chksumOctal, 148, 8, "ascii");

    blocks.push(header);

    if (content.length > 0) {
      const paddedSize = Math.ceil(content.length / 512) * 512;
      const paddedContent = Buffer.alloc(paddedSize);
      content.copy(paddedContent, 0);
      blocks.push(paddedContent);
    }
  }

  // End of archive: two 512-byte zero blocks
  blocks.push(Buffer.alloc(1024));

  return Buffer.concat(blocks);
}

/**
 * Generate a synthetic 32-bit or 64-bit ELF binary buffer.
 */
export function createElfBinaryBuffer(options: {
  readonly is64Bit?: boolean;
  readonly isLE?: boolean;
  readonly machine?: number; // 0x3e = x86_64, 0x28 = ARM, 0xb7 = AArch64, 0x08 = MIPS
}): Buffer {
  const is64 = options.is64Bit ?? true;
  const isLE = options.isLE ?? true;
  const machine = options.machine ?? 0x3e;

  const buf = Buffer.alloc(64);
  // Magic: \x7fELF
  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46;
  buf[4] = is64 ? 2 : 1; // EI_CLASS
  buf[5] = isLE ? 1 : 2; // EI_DATA
  buf[6] = 1; // EI_VERSION

  // e_type at 16 (2 = EXEC)
  if (isLE) {
    buf.writeUInt16LE(2, 16);
    buf.writeUInt16LE(machine, 18);
  } else {
    buf.writeUInt16BE(2, 16);
    buf.writeUInt16BE(machine, 18);
  }

  return buf;
}

