import type { FirmwareFormat, FirmwareFormatDetectionResult } from "./types.js";

export function detectFirmwareFormat(buffer: Buffer): FirmwareFormatDetectionResult {
  if (buffer.length < 4) {
    return {
      format: "unknown",
      confidence: 0,
      offset: 0,
      description: "Buffer too small to determine format",
    };
  }

  // 1. SquashFS (0x73717368 = sqsh LE, 0x68737173 = hsqs BE)
  const sqshLE = Buffer.from([0x73, 0x71, 0x73, 0x68]);
  const sqshBE = Buffer.from([0x68, 0x73, 0x71, 0x73]);
  const sqshOffsetLE = buffer.indexOf(sqshLE);
  if (sqshOffsetLE !== -1) {
    return {
      format: "squashfs",
      confidence: 0.99,
      offset: sqshOffsetLE,
      description: "SquashFS 4.0 filesystem (Little-Endian)",
      details: { endianness: "little" },
    };
  }
  const sqshOffsetBE = buffer.indexOf(sqshBE);
  if (sqshOffsetBE !== -1) {
    return {
      format: "squashfs",
      confidence: 0.99,
      offset: sqshOffsetBE,
      description: "SquashFS 4.0 filesystem (Big-Endian)",
      details: { endianness: "big" },
    };
  }

  // 2. CramFS (0x28cd3d45 = LE, 0x453dcd28 = BE)
  const cramfsLE = Buffer.from([0x45, 0x3d, 0xcd, 0x28]);
  const cramfsBE = Buffer.from([0x28, 0xcd, 0x3d, 0x45]);
  const cramfsOffset = buffer.indexOf(cramfsLE) !== -1 ? buffer.indexOf(cramfsLE) : buffer.indexOf(cramfsBE);
  if (cramfsOffset !== -1) {
    return {
      format: "cramfs",
      confidence: 0.95,
      offset: cramfsOffset,
      description: "CramFS compressed ROM filesystem",
    };
  }

  // 3. JFFS2 (0x1985 = LE [0x85, 0x19], BE [0x19, 0x85])
  const jffs2LE = Buffer.from([0x85, 0x19]);
  const jffs2BE = Buffer.from([0x19, 0x85]);
  const jffs2Offset = buffer.indexOf(jffs2LE) !== -1 ? buffer.indexOf(jffs2LE) : buffer.indexOf(jffs2BE);
  if (jffs2Offset !== -1) {
    return {
      format: "jffs2",
      confidence: 0.9,
      offset: jffs2Offset,
      description: "JFFS2 flash filesystem",
    };
  }

  // 4. UBIFS / UBI (magic 'UBI#' = 0x55 0x42 0x49 0x23, or UBIFS node 0x06101831)
  const ubiMagic = Buffer.from([0x55, 0x42, 0x49, 0x23]);
  const ubifsNode = Buffer.from([0x31, 0x18, 0x10, 0x06]);
  const ubiOffset = buffer.indexOf(ubiMagic) !== -1 ? buffer.indexOf(ubiMagic) : buffer.indexOf(ubifsNode);
  if (ubiOffset !== -1) {
    return {
      format: "ubifs",
      confidence: 0.95,
      offset: ubiOffset,
      description: "UBIFS / Unsorted Block Image",
    };
  }

  // 5. ext4 superblock at byte 1024, magic 0xef53 at 1080 (offset 1080 = 0x438)
  if (buffer.length >= 1082) {
    const extMagic = buffer.readUInt16LE(1080);
    if (extMagic === 0xef53) {
      return {
        format: "ext4",
        confidence: 0.98,
        offset: 0,
        description: "ext2/ext3/ext4 Linux filesystem image",
      };
    }
  }

  // 6. U-Boot Legacy Image (0x27051956)
  const uimage = Buffer.from([0x27, 0x05, 0x19, 0x56]);
  const uimageOffset = buffer.indexOf(uimage);
  if (uimageOffset !== -1) {
    return {
      format: "uimage",
      confidence: 0.99,
      offset: uimageOffset,
      description: "U-Boot legacy firmware image (uImage)",
    };
  }

  // 7. Flattened Device Tree / FIT image (0xd00dfeed)
  const fitMagic = Buffer.from([0xd0, 0x0d, 0xfe, 0xed]);
  const fitOffset = buffer.indexOf(fitMagic);
  if (fitOffset !== -1) {
    return {
      format: "fit",
      confidence: 0.99,
      offset: fitOffset,
      description: "Flattened Device Tree / FIT firmware image",
    };
  }

  // 8. TRX image (magic 'HDR0' = 0x48 0x44 0x52 0x30)
  const trx = Buffer.from([0x48, 0x44, 0x52, 0x30]);
  const trxOffset = buffer.indexOf(trx);
  if (trxOffset !== -1) {
    return {
      format: "trx",
      confidence: 0.99,
      offset: trxOffset,
      description: "Broadcom TRX embedded firmware image",
    };
  }

  // 9. Compressed Archives: GZIP, BZIP2, XZ
  if (buffer[0] === 0x1f && buffer[1] === 0x8b) {
    return {
      format: "gzip",
      confidence: 0.98,
      offset: 0,
      description: "Gzip compressed archive / tar.gz",
    };
  }
  if (buffer[0] === 0x42 && buffer[1] === 0x5a && buffer[2] === 0x68) {
    return {
      format: "bzip2",
      confidence: 0.98,
      offset: 0,
      description: "Bzip2 compressed archive / tar.bz2",
    };
  }
  if (buffer.subarray(0, 6).equals(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]))) {
    return {
      format: "xz",
      confidence: 0.98,
      offset: 0,
      description: "XZ compressed archive / tar.xz",
    };
  }

  // 10. TAR Archive (POSIX ustar magic at offset 257)
  if (buffer.length >= 512) {
    const magic = buffer.toString("ascii", 257, 263);
    if (magic.startsWith("ustar")) {
      return {
        format: "tar",
        confidence: 0.99,
        offset: 0,
        description: "POSIX TAR archive",
      };
    }
  }

  return {
    format: "unknown",
    confidence: 0.1,
    offset: 0,
    description: "Unknown raw binary image",
  };
}

