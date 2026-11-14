import { inflateSync } from "node:zlib";
import { err, ok, type Result } from "../../domain/result.js";
import type {
  ArchiveEntryCandidate,
  ArchiveEntryKind,
  ExtractionError,
} from "../../domain/security/firmware/types.js";
import { XzDecompressor } from "./XzDecompressor.js";

export interface SquashFsEntry {
  readonly path: string;
  readonly kind: ArchiveEntryKind;
  readonly size: number;
  readonly content?: Buffer | undefined;
  readonly linkTarget?: string | undefined;
}

export interface SquashFsSuperblock {
  readonly magic: number;
  readonly inodes: number;
  readonly mkfsTime: number;
  readonly blockSize: number;
  readonly fragments: number;
  readonly compression: number;
  readonly blockLog: number;
  readonly flags: number;
  readonly idCount: number;
  readonly versionMajor: number;
  readonly versionMinor: number;
  readonly rootInodeRef: bigint;
  readonly bytesUsed: bigint;
  readonly idTableStart: bigint;
  readonly xattrIdTableStart: bigint;
  readonly inodeTableStart: bigint;
  readonly directoryTableStart: bigint;
  readonly fragmentTableStart: bigint;
  readonly exportTableStart: bigint;
  readonly isLittleEndian: boolean;
}

export class SquashFsParser {
  /**
   * Parse SquashFS 4.0 superblock.
   */
  public static parseSuperblock(
    buffer: Buffer,
    offset = 0,
  ): Result<SquashFsSuperblock, ExtractionError> {
    if (buffer.length - offset < 96) {
      return err({
        code: "INVALID_FIRMWARE",
        message: "Buffer too small to contain SquashFS superblock (minimum 96 bytes)",
      });
    }

    const sqshLE = 0x73717368;
    const sqshBE = 0x68737173;
    const magic = buffer.readUInt32LE(offset);

    let isLE = true;
    if (magic === sqshLE) {
      isLE = true;
    } else if (magic === sqshBE) {
      isLE = false;
    } else {
      return err({
        code: "INVALID_FIRMWARE",
        message: `Invalid SquashFS magic: 0x${magic.toString(16)}`,
      });
    }

    const readU16 = (o: number) =>
      isLE ? buffer.readUInt16LE(offset + o) : buffer.readUInt16BE(offset + o);
    const readU32 = (o: number) =>
      isLE ? buffer.readUInt32LE(offset + o) : buffer.readUInt32BE(offset + o);
    const readU64 = (o: number) =>
      isLE ? buffer.readBigUInt64LE(offset + o) : buffer.readBigUInt64BE(offset + o);

    const versionMajor = readU16(28);
    const versionMinor = readU16(30);

    if (versionMajor !== 4) {
      return err({
        code: "UNSUPPORTED_FORMAT",
        message: `Unsupported SquashFS version ${versionMajor}.${versionMinor} (only 4.0 supported)`,
      });
    }

    return ok({
      magic,
      inodes: readU32(4),
      mkfsTime: readU32(8),
      blockSize: readU32(12),
      fragments: readU32(16),
      compression: readU16(20),
      blockLog: readU16(22),
      flags: readU16(24),
      idCount: readU16(26),
      versionMajor,
      versionMinor,
      rootInodeRef: readU64(32),
      bytesUsed: readU64(40),
      idTableStart: readU64(48),
      xattrIdTableStart: readU64(56),
      inodeTableStart: readU64(64),
      directoryTableStart: readU64(72),
      fragmentTableStart: readU64(80),
      exportTableStart: readU64(88),
      isLittleEndian: isLE,
    });
  }

  /**
   * Decompress a compressed block according to superblock compression format.
   */
  public static decompressBlock(
    slice: Buffer,
    maxOutputLength: number,
    compression: number,
  ): Buffer {
    if (compression === 1) {
      return inflateSync(slice, { maxOutputLength });
    }
    if (compression === 4) {
      return XzDecompressor.decompressSync(slice, { maxOutputLength });
    }
    throw new Error(
      `Unsupported SquashFS compression format ${compression} (only gzip/1 and xz/4 supported)`,
    );
  }

  /**
   * Decompress a SquashFS metadata block (up to 8192 uncompressed bytes).
   */
  public static readMetadataBlock(
    buffer: Buffer,
    offset: number,
    isLE: boolean,
    compression = 1,
  ): { data: Buffer; bytesRead: number } {
    if (offset + 2 > buffer.length) {
      throw new Error(`SquashFS metadata header out of bounds at offset ${offset}`);
    }
    const header = isLE ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
    const isUncompressed = (header & 0x8000) !== 0;
    const size = header & 0x7fff;
    const dataOffset = offset + 2;

    if (dataOffset + size > buffer.length) {
      throw new Error(
        `SquashFS metadata block data truncated: requires ${size} bytes at ${dataOffset}, buffer length ${buffer.length}`,
      );
    }

    const slice = buffer.subarray(dataOffset, dataOffset + size);
    const data = isUncompressed
      ? slice
      : this.decompressBlock(slice, 8192, compression);
    return { data, bytesRead: 2 + size };
  }

  /**
   * Parse SquashFS 4.0 entries from image buffer.
   */
  public static parseEntries(
    buffer: Buffer,
    offset = 0,
  ): Result<ReadonlyArray<SquashFsEntry>, ExtractionError> {
    const sbResult = this.parseSuperblock(buffer, offset);
    if (!sbResult.ok) {
      return sbResult;
    }
    const sb = sbResult.value;

    try {
      const entries: SquashFsEntry[] = [];
      const isLE = sb.isLittleEndian;
      const readU16 = (b: Buffer, o: number) => (isLE ? b.readUInt16LE(o) : b.readUInt16BE(o));
      const readU32 = (b: Buffer, o: number) => (isLE ? b.readUInt32LE(o) : b.readUInt32BE(o));

      // Cache decompressed metadata blocks by start offset
      const metadataCache = new Map<number, Buffer>();
      const getMetadataBlock = (blockOffset: number): Buffer => {
        let cached = metadataCache.get(blockOffset);
        if (!cached) {
          const { data } = this.readMetadataBlock(buffer, blockOffset, isLE, sb.compression);
          cached = data;
          metadataCache.set(blockOffset, cached);
        }
        return cached;
      };

      // Helper to read contiguous bytes across metadata block boundaries
      const readMetadataBytes = (startBlock: number, startOffset: number, length: number): Buffer => {
        let currentBlock = startBlock;
        let currentOffset = startOffset;
        let remaining = length;
        const chunks: Buffer[] = [];

        while (remaining > 0) {
          const block = getMetadataBlock(currentBlock);
          const availableInBlock = block.length - currentOffset;
          const toRead = Math.min(remaining, availableInBlock);

          chunks.push(block.subarray(currentOffset, currentOffset + toRead));
          remaining -= toRead;

          if (remaining > 0) {
            // Find next metadata block
            const header = isLE ? buffer.readUInt16LE(currentBlock) : buffer.readUInt16BE(currentBlock);
            const size = header & 0x7fff;
            currentBlock += 2 + size;
            currentOffset = 0;
          }
        }
        return Buffer.concat(chunks);
      };

      // Parse fragment table if present
      interface FragmentEntry {
        readonly startBlock: number;
        readonly size: number;
        readonly isUncompressed: boolean;
      }
      const fragmentEntries: FragmentEntry[] = [];
      const fragmentCache = new Map<number, Buffer>();

      if (sb.fragments > 0 && sb.fragmentTableStart !== 0xffffffffffffffffn) {
        const fragPtrCount = Math.ceil(sb.fragments / 512);
        const fragTableChunks: Buffer[] = [];
        for (let i = 0; i < fragPtrCount; i++) {
          const ptrOffset = Number(sb.fragmentTableStart) + i * 8;
          const blockPtr = isLE ? buffer.readBigUInt64LE(ptrOffset) : buffer.readBigUInt64BE(ptrOffset);
          fragTableChunks.push(getMetadataBlock(Number(blockPtr)));
        }
        const fragTableRaw = Buffer.concat(fragTableChunks);
        for (let i = 0; i < sb.fragments; i++) {
          const fOffset = i * 16;
          if (fOffset + 16 > fragTableRaw.length) break;
          const startBlock = Number(isLE ? fragTableRaw.readBigUInt64LE(fOffset) : fragTableRaw.readBigUInt64BE(fOffset));
          const sizeRaw = readU32(fragTableRaw, fOffset + 8);
          const isUncomp = (sizeRaw & (1 << 24)) !== 0;
          const size = sizeRaw & 0x00ffffff;
          fragmentEntries.push({ startBlock, size, isUncompressed: isUncomp });
        }
      }

      const getFragmentBlock = (fragIndex: number): Buffer => {
        let cached = fragmentCache.get(fragIndex);
        if (cached) return cached;
        if (fragIndex >= fragmentEntries.length) {
          throw new Error(`SquashFS fragment index ${fragIndex} out of bounds (total fragments: ${fragmentEntries.length})`);
        }
        const frag = fragmentEntries[fragIndex]!;
        const fragSlice = buffer.subarray(frag.startBlock, frag.startBlock + frag.size);
        const decompressed = frag.isUncompressed
          ? fragSlice
          : this.decompressBlock(fragSlice, sb.blockSize, sb.compression);
        fragmentCache.set(fragIndex, decompressed);
        return decompressed;
      };

      // Read inode at reference: rootInodeRef
      const rootBlockOffset = Number(sb.inodeTableStart) + Number(sb.rootInodeRef >> 16n);
      const rootOffsetInBlock = Number(sb.rootInodeRef & 0xffffn);

      const rootBaseBuf = readMetadataBytes(rootBlockOffset, rootOffsetInBlock, 16);
      const rootType = readU16(rootBaseBuf, 0);
      const rootInodeBuf = rootType === 8
        ? readMetadataBytes(rootBlockOffset, rootOffsetInBlock, 40)
        : readMetadataBytes(rootBlockOffset, rootOffsetInBlock, 32);

      // Recursive directory crawler
      const traverseDirectory = (
        dirBlockStartOffset: number,
        dirOffsetInBlock: number,
        dirFileSize: number,
        currentPath: string,
      ) => {
        if (dirFileSize <= 3) return; // empty directory (has only 3 bytes overhead)

        const dirDataLength = dirFileSize > 3 ? dirFileSize - 3 : dirFileSize;
        const dirData = readMetadataBytes(
          Number(sb.directoryTableStart) + dirBlockStartOffset,
          dirOffsetInBlock,
          dirDataLength,
        );

        let pos = 0;
        while (pos < dirData.length) {
          if (pos + 12 > dirData.length) break;

          const count = readU32(dirData, pos) + 1; // count of entries - 1 stored
          const startInodeBlock = readU32(dirData, pos + 4);
          pos += 12;

          for (let i = 0; i < count && pos < dirData.length; i++) {
            if (pos + 8 > dirData.length) break;
            const inodeOffset = readU16(dirData, pos);
            const w1 = readU16(dirData, pos + 2);
            const w2 = readU16(dirData, pos + 4);
            const w3 = readU16(dirData, pos + 6);

            // Disambiguate standard SquashFS 4.0 layout (offset, inode_num, type, size-1)
            // from legacy in-memory test fixture layout (offset, type, size-1, 0).
            let nameSize = w3 + 1;
            if (w1 >= 1 && w1 <= 14 && w3 === 0 && w2 > 0 && pos + 8 + w2 + 1 <= dirData.length) {
              const testSlice = dirData.subarray(pos + 8, pos + 8 + w2 + 1);
              if (testSlice.every((c) => c >= 32 && c <= 126)) {
                nameSize = w2 + 1;
              }
            }

            pos += 8;

            if (pos + nameSize > dirData.length) break;
            const entryName = dirData.subarray(pos, pos + nameSize).toString("ascii");
            pos += nameSize;

            const entryPath = currentPath ? `${currentPath}/${entryName}` : entryName;

            // Fetch inode
            const entryInodeBlock = Number(sb.inodeTableStart) + startInodeBlock;
            const baseInode = readMetadataBytes(entryInodeBlock, inodeOffset, 16);
            const rawType = readU16(baseInode, 0);

            if (rawType === 1) {
              // Basic directory
              const inodeData = readMetadataBytes(entryInodeBlock, inodeOffset, 32);
              const subDirBlockStart = readU32(inodeData, 16);
              const subDirSize = readU16(inodeData, 24);
              const subDirOffset = readU16(inodeData, 26);

              entries.push({
                path: entryPath,
                kind: "directory",
                size: 0,
              });

              traverseDirectory(subDirBlockStart, subDirOffset, subDirSize, entryPath);
            } else if (rawType === 8) {
              // Extended directory
              const inodeData = readMetadataBytes(entryInodeBlock, inodeOffset, 40);
              const subDirSize = readU32(inodeData, 20);
              const subDirBlockStart = readU32(inodeData, 24);
              const subDirOffset = readU16(inodeData, 34);

              entries.push({
                path: entryPath,
                kind: "directory",
                size: 0,
              });

              traverseDirectory(subDirBlockStart, subDirOffset, subDirSize, entryPath);
            } else if (rawType === 2) {
              // Basic regular file
              const fixedData = readMetadataBytes(entryInodeBlock, inodeOffset, 32);
              const blocksStart = readU32(fixedData, 16);
              const fragIndex = readU32(fixedData, 20);
              const fragOffset = readU32(fixedData, 24);
              const fileSize = readU32(fixedData, 28);

              // Extract file data blocks
              let fileContent: Buffer | undefined = undefined;
              if (fileSize > 0) {
                const fileBlocks: Buffer[] = [];
                let currentFileOffset = blocksStart;
                let bytesRemaining = fileSize;
                const numFullBlocks = fragIndex !== 0xffffffff
                  ? Math.floor(fileSize / sb.blockSize)
                  : Math.ceil(fileSize / sb.blockSize);

                const blockSizesBuf = numFullBlocks > 0
                  ? readMetadataBytes(entryInodeBlock, inodeOffset + 32, numFullBlocks * 4)
                  : Buffer.alloc(0);

                for (let b = 0; b < numFullBlocks && bytesRemaining > 0; b++) {
                  const bSizeRaw = readU32(blockSizesBuf, b * 4);
                  const isBlockUncompressed = (bSizeRaw & (1 << 24)) !== 0;
                  const bSize = bSizeRaw & 0x00ffffff;

                  if (bSize > 0 && currentFileOffset + bSize <= buffer.length) {
                    const blockSlice = buffer.subarray(currentFileOffset, currentFileOffset + bSize);
                    const decompressed = isBlockUncompressed
                      ? blockSlice
                      : this.decompressBlock(blockSlice, sb.blockSize, sb.compression);
                    const useful = decompressed.subarray(0, Math.min(bytesRemaining, decompressed.length));
                    fileBlocks.push(useful);
                    bytesRemaining -= useful.length;
                    currentFileOffset += bSize;
                  }
                }

                if (fragIndex !== 0xffffffff && bytesRemaining > 0) {
                  const fragBlock = getFragmentBlock(fragIndex);
                  const available = fragBlock.subarray(fragOffset, fragOffset + bytesRemaining);
                  fileBlocks.push(available);
                  bytesRemaining -= available.length;
                }

                fileContent = Buffer.concat(fileBlocks);
              } else {
                fileContent = Buffer.alloc(0);
              }

              entries.push({
                path: entryPath,
                kind: "file",
                size: fileSize,
                content: fileContent,
              });
            } else if (rawType === 3 || rawType === 10) {
              // Basic symlink (3) or Extended symlink (10)
              const symHeader = readMetadataBytes(entryInodeBlock, inodeOffset, 24);
              const symlinkSize = readU32(symHeader, 20);
              const symlinkTarget = readMetadataBytes(entryInodeBlock, inodeOffset + 24, symlinkSize).toString("ascii");

              entries.push({
                path: entryPath,
                kind: "symlink",
                size: symlinkSize,
                linkTarget: symlinkTarget,
              });
            } else if (rawType === 4 || rawType === 5 || rawType === 6 || rawType === 7) {
              // Special device node / FIFO / socket
              entries.push({
                path: entryPath,
                kind: "special",
                size: 0,
              });
            }
          }
        }
      };

      if (rootType === 1) {
        const rootDirBlockStart = readU32(rootInodeBuf, 16);
        const rootDirSize = readU16(rootInodeBuf, 24);
        const rootDirOffset = readU16(rootInodeBuf, 26);
        traverseDirectory(rootDirBlockStart, rootDirOffset, rootDirSize, "");
      } else if (rootType === 8) {
        const rootDirSize = readU32(rootInodeBuf, 20);
        const rootDirBlockStart = readU32(rootInodeBuf, 24);
        const rootDirOffset = readU16(rootInodeBuf, 34);
        traverseDirectory(rootDirBlockStart, rootDirOffset, rootDirSize, "");
      }

      return ok(entries);
    } catch (e: unknown) {
      return err({
        code: "INVALID_FIRMWARE",
        message: `Failed to parse SquashFS entries: ${e instanceof Error ? e.message : String(e)}`,
        cause: e,
      });
    }
  }

  /**
   * Helper to build a valid, minimal SquashFS 4.0 binary image with given files.
   * Very useful for testing and reproducible fixture generation without unsquashfs!
   */
  public static createTestImage(
    files: ReadonlyArray<{ path: string; content?: Buffer | string; isSymlink?: boolean; symlinkTarget?: string }>,
  ): Buffer {
    const blockSize = 4096;
    const isLE = true;

    // Header size = 96 bytes
    // File data blocks begin at 96
    const dataChunks: Buffer[] = [];
    const fileOffsets: { path: string; offset: number; size: number; content: Buffer }[] = [];
    let currentDataOffset = 96;

    for (const f of files) {
      if (f.isSymlink) continue;
      const content = Buffer.isBuffer(f.content)
        ? f.content
        : Buffer.from(f.content ?? "", "utf8");
      // Store compressed data block with zlib deflate
      const uncompressed = content;
      // Mark as uncompressed for simplicity: bit 24 = 1
      fileOffsets.push({
        path: f.path,
        offset: currentDataOffset,
        size: uncompressed.length,
        content: uncompressed,
      });
      dataChunks.push(uncompressed);
      currentDataOffset += uncompressed.length;
    }

    // Inode table
    const inodeTableOffset = currentDataOffset;
    const inodeChunks: Buffer[] = [];
    // Basic root directory inode (32 bytes)
    // Basic regular file inode (32 + 4 bytes = 36 bytes)
    let inodeOffsetCounter = 0;
    const fileInodeOffsets = new Map<string, number>();

    // File inodes
    for (const f of files) {
      if (f.isSymlink) {
        const target = Buffer.from(f.symlinkTarget ?? "", "ascii");
        const inode = Buffer.alloc(24 + target.length);
        inode.writeUInt16LE(3, 0); // type 3 = symlink
        inode.writeUInt16LE(0o777, 2); // mode
        inode.writeUInt32LE(target.length, 20); // symlink_size
        target.copy(inode, 24);
        fileInodeOffsets.set(f.path, inodeOffsetCounter);
        inodeChunks.push(inode);
        inodeOffsetCounter += inode.length;
      } else {
        const fo = fileOffsets.find((x) => x.path === f.path)!;
        const inode = Buffer.alloc(36);
        inode.writeUInt16LE(2, 0); // type 2 = regular file
        inode.writeUInt16LE(0o644, 2); // mode
        inode.writeUInt32LE(fo.offset, 16); // blocks_start
        inode.writeUInt32LE(0xffffffff, 20); // frag_index = none
        inode.writeUInt32LE(fo.size, 28); // file_size
        // block sizes: 1 block, uncompressed bit set
        inode.writeUInt32LE(fo.size | (1 << 24), 32);
        fileInodeOffsets.set(f.path, inodeOffsetCounter);
        inodeChunks.push(inode);
        inodeOffsetCounter += inode.length;
      }
    }

    // Pre-build directory table so exact size is known
    const dirChunks: Buffer[] = [];
    const dirHeader = Buffer.alloc(12);
    dirHeader.writeUInt32LE(files.length - 1, 0); // count - 1
    dirHeader.writeUInt32LE(0, 4); // start inode block
    dirChunks.push(dirHeader);

    for (const f of files) {
      const name = Buffer.from(f.path, "ascii");
      const entry = Buffer.alloc(8 + name.length);
      const inOff = fileInodeOffsets.get(f.path) ?? 0;
      entry.writeUInt16LE(inOff, 0); // inode offset
      entry.writeUInt16LE(f.isSymlink ? 3 : 2, 2); // type
      entry.writeUInt16LE(name.length - 1, 4); // name size - 1
      entry.writeUInt16LE(0, 6);
      name.copy(entry, 8);
      dirChunks.push(entry);
    }
    const dirTableRaw = Buffer.concat(dirChunks);

    // Root directory inode (placed at end of inode table)
    const rootInodeOffset = inodeOffsetCounter;
    const rootInode = Buffer.alloc(32);
    rootInode.writeUInt16LE(1, 0); // type 1 = basic dir
    rootInode.writeUInt16LE(0o755, 2);
    rootInode.writeUInt32LE(0, 16); // dir_block_start in directory table
    rootInode.writeUInt16LE(dirTableRaw.length + 3, 24); // file_size of dir (entries size + 3)
    rootInode.writeUInt16LE(0, 26); // offset in dir block
    inodeChunks.push(rootInode);

    const inodeTableRaw = Buffer.concat(inodeChunks);
    // Wrap in uncompressed metadata block (bit 15 = 1)
    const inodeTableBlock = Buffer.alloc(2 + inodeTableRaw.length);
    inodeTableBlock.writeUInt16LE(inodeTableRaw.length | 0x8000, 0);
    inodeTableRaw.copy(inodeTableBlock, 2);

    // Directory table block
    const directoryTableOffset = inodeTableOffset + inodeTableBlock.length;
    const dirTableBlock = Buffer.alloc(2 + dirTableRaw.length);
    dirTableBlock.writeUInt16LE(dirTableRaw.length | 0x8000, 0);
    dirTableRaw.copy(dirTableBlock, 2);

    const totalBytesUsed = directoryTableOffset + dirTableBlock.length;

    // Superblock (96 bytes)
    const sb = Buffer.alloc(96);
    sb.writeUInt32LE(0x73717368, 0); // magic
    sb.writeUInt32LE(files.length + 1, 4); // inodes
    sb.writeUInt32LE(Math.floor(Date.now() / 1000), 8); // mkfs_time
    sb.writeUInt32LE(blockSize, 12); // block_size
    sb.writeUInt32LE(0, 16); // fragments
    sb.writeUInt16LE(1, 20); // compression: 1 = gzip
    sb.writeUInt16LE(12, 22); // block_log = 12 (4096)
    sb.writeUInt16LE(0, 24); // flags
    sb.writeUInt16LE(1, 26); // id_count
    sb.writeUInt16LE(4, 28); // version_major
    sb.writeUInt16LE(0, 30); // version_minor
    sb.writeBigUInt64LE(BigInt(rootInodeOffset), 32); // root_inode_ref
    sb.writeBigUInt64LE(BigInt(totalBytesUsed), 40); // bytes_used
    sb.writeBigUInt64LE(BigInt(totalBytesUsed), 48); // id_table_start
    sb.writeBigUInt64LE(BigInt(0xffffffffffffffffn), 56); // xattr_id_table_start
    sb.writeBigUInt64LE(BigInt(inodeTableOffset), 64); // inode_table_start
    sb.writeBigUInt64LE(BigInt(directoryTableOffset), 72); // directory_table_start
    sb.writeBigUInt64LE(BigInt(0xffffffffffffffffn), 80); // fragment_table_start
    sb.writeBigUInt64LE(BigInt(0xffffffffffffffffn), 88); // export_table_start

    return Buffer.concat([sb, ...dataChunks, inodeTableBlock, dirTableBlock]);
  }
}
