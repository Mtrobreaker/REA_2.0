import { constants } from "node:fs";
import {
  link,
  lstat,
  mkdtemp,
  open,
  readFile,
  rm,
  symlink,
  unlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, normalize, resolve, sep } from "node:path";
import { Readable } from "node:stream";
import { createGunzip } from "node:zlib";
import { err, ok, type Result } from "../../domain/result.js";
import { detectFirmwareFormat } from "../../domain/security/firmware/detector.js";
import {
  DEFAULT_EXTRACTION_POLICY,
  type ArchiveEntryCandidate,
  type ArchiveEntryKind,
  type ExtractionError,
  type ExtractionSecurityPolicy,
  type FirmwareFormat,
} from "../../domain/security/firmware/types.js";
import {
  PreWriteValidator,
  type ExtractionStats,
  type ValidatedEntry,
} from "./PreWriteValidator.js";
import { SquashFsParser } from "./SquashFsParser.js";

export interface ExtractionSummary {
  readonly sandboxDir: string;
  readonly format: FirmwareFormat;
  readonly filesExtracted: number;
  readonly bytesExtracted: number;
  readonly entries: ReadonlyArray<ValidatedEntry>;
}

export class SandboxedExtractor {
  constructor(
    private readonly policy: ExtractionSecurityPolicy = DEFAULT_EXTRACTION_POLICY,
  ) {}

  /**
   * Safely delete the sandbox directory and all its contents.
   * Enforces strict path bounds checking to prevent accidental deletion outside the sandbox.
   */
  public async cleanupSandbox(sandboxDir: string): Promise<void> {
    try {
      const canonical = resolve(sandboxDir);
      const parent = resolve(tmpdir());
      const root = resolve(sep);
      if (
        canonical === root ||
        canonical === parent ||
        !canonical.includes("rea-fw-sandbox-")
      ) {
        return; // Refuse to delete unsafe path
      }
      await rm(canonical, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  }

  /**
   * Extract a firmware image or archive into an isolated, secure staging directory.
   */
  public async extract(
    sourcePath: string,
    sandboxParentDir?: string,
    options?: { signal?: AbortSignal },
  ): Promise<Result<ExtractionSummary, ExtractionError>> {
    let sourceBuffer: Buffer;
    try {
      sourceBuffer = await readFile(sourcePath);
    } catch (e: unknown) {
      return err({
        code: "INVALID_FIRMWARE",
        message: `Failed to read source firmware file at ${sourcePath}: ${e instanceof Error ? e.message : String(e)}`,
        cause: e,
      });
    }

    if (sourceBuffer.length > this.policy.maxCumulativeBytes) {
      return err({
        code: "QUOTA_EXCEEDED",
        message: `Source file size ${sourceBuffer.length} bytes exceeds maximum allowed limit of ${this.policy.maxCumulativeBytes} bytes`,
      });
    }

    // Combine caller signal with policy-enforced wall-clock timeout
    const timeoutSignal = AbortSignal.timeout(this.policy.maxExecutionTimeMs);
    const combinedSignal = options?.signal
      ? AbortSignal.any([options.signal, timeoutSignal])
      : timeoutSignal;

    // Detect format
    const detection = detectFirmwareFormat(sourceBuffer);
    if (detection.format === "unknown") {
      return err({
        code: "UNSUPPORTED_FORMAT",
        message: "Unknown firmware format or unrecognized archive structure",
      });
    }

    // Prepare sandbox
    const parent = sandboxParentDir ?? tmpdir();
    let sandboxDir: string;
    try {
      sandboxDir = await mkdtemp(join(parent, "rea-fw-sandbox-"));
    } catch (e: unknown) {
      return err({
        code: "SANDBOX_ERROR",
        message: `Failed to create sandbox temporary directory: ${e instanceof Error ? e.message : String(e)}`,
        cause: e,
      });
    }

    const stats: ExtractionStats = {
      archiveSizeBytes: sourceBuffer.length,
      currentFileCount: 0,
      currentCumulativeBytes: 0,
    };

    const validatedEntries: ValidatedEntry[] = [];

    try {
      if (combinedSignal.aborted) {
        throw new Error("Extraction cancelled before unpacking");
      }

      let formatToExtract = detection.format;
      let payloadBuffer = sourceBuffer;

      // Handle common firmware containers (e.g., uImage, TRX)
      if (formatToExtract === "uimage") {
        if (sourceBuffer.length > 64) {
          payloadBuffer = sourceBuffer.subarray(64);
          const innerDetection = detectFirmwareFormat(payloadBuffer);
          if (innerDetection.format !== "unknown") {
            formatToExtract = innerDetection.format;
          }
        }
      } else if (formatToExtract === "trx") {
        if (sourceBuffer.length > 28) {
          payloadBuffer = sourceBuffer.subarray(28);
          const innerDetection = detectFirmwareFormat(payloadBuffer);
          if (innerDetection.format !== "unknown") {
            formatToExtract = innerDetection.format;
          }
        }
      }

      // Handle GZIP decompression with bounded streaming, incremental quota & bomb guards
      if (formatToExtract === "gzip") {
        const decompressedRes = await this.decompressGzipStream(
          payloadBuffer,
          combinedSignal,
        );
        if (!decompressedRes.ok) {
          await this.cleanupSandbox(sandboxDir);
          return decompressedRes;
        }
        payloadBuffer = decompressedRes.value;
        const innerDetection = detectFirmwareFormat(payloadBuffer);
        formatToExtract = innerDetection.format === "unknown" ? "tar" : innerDetection.format;
      }

      // Extract based on format
      if (formatToExtract === "tar") {
        const tarResult = await this.extractTar(
          payloadBuffer,
          sandboxDir,
          stats,
          validatedEntries,
          combinedSignal,
        );
        if (!tarResult.ok) {
          await this.cleanupSandbox(sandboxDir);
          return tarResult;
        }
      } else if (formatToExtract === "squashfs") {
        const sqshResult = await this.extractSquashFs(
          payloadBuffer,
          detection.offset,
          sandboxDir,
          stats,
          validatedEntries,
          combinedSignal,
        );
        if (!sqshResult.ok) {
          await this.cleanupSandbox(sandboxDir);
          return sqshResult;
        }
      } else {
        await this.cleanupSandbox(sandboxDir);
        return err({
          code: "UNSUPPORTED_FORMAT",
          message: `Direct sandbox extraction for ${formatToExtract} requires external tool integration`,
        });
      }

      return ok({
        sandboxDir,
        format: formatToExtract,
        filesExtracted: stats.currentFileCount,
        bytesExtracted: stats.currentCumulativeBytes,
        entries: validatedEntries,
      });
    } catch (e: unknown) {
      await this.cleanupSandbox(sandboxDir);
      return err({
        code: "SANDBOX_ERROR",
        message: `Sandbox extraction failed: ${e instanceof Error ? e.message : String(e)}`,
        cause: e,
      });
    }
  }

  /**
   * Safe in-process streaming TAR extractor.
   */
  private async extractTar(
    buffer: Buffer,
    sandboxDir: string,
    stats: ExtractionStats,
    validatedEntries: ValidatedEntry[],
    signal?: AbortSignal,
  ): Promise<Result<void, ExtractionError>> {
    let offset = 0;
    let nextLongName: string | undefined = undefined;
    let nextLongLink: string | undefined = undefined;

    while (offset + 512 <= buffer.length) {
      if (signal?.aborted) {
        return err({ code: "EXTRACTION_TIMEOUT", message: "Extraction cancelled by signal" });
      }

      const header = buffer.subarray(offset, offset + 512);
      // Check for zero block (end of archive)
      let isZero = true;
      for (let i = 0; i < 512; i++) {
        if (header[i] !== 0) {
          isZero = false;
          break;
        }
      }
      if (isZero) {
        break; // End of archive
      }

      // Read header fields
      const readString = (start: number, length: number): string => {
        let end = start;
        while (end < start + length && (header[end] ?? 0) !== 0) {
          end++;
        }
        return header.subarray(start, end).toString("utf8");
      };

      const rawName = readString(0, 100);
      const prefix = readString(345, 155);
      const rawSizeStr = readString(124, 12).trim();
      const size = rawSizeStr ? parseInt(rawSizeStr, 8) : 0;
      const typeflag = String.fromCharCode(header[156] ?? 0);
      const rawLinkname = readString(157, 100);

      offset += 512;

      // Handle GNU long filename / linkname
      if (typeflag === "L") {
        nextLongName = buffer.subarray(offset, offset + size).toString("utf8").replace(/\0+$/u, "");
        const blocks = Math.ceil(size / 512);
        offset += blocks * 512;
        continue;
      }
      if (typeflag === "K") {
        nextLongLink = buffer.subarray(offset, offset + size).toString("utf8").replace(/\0+$/u, "");
        const blocks = Math.ceil(size / 512);
        offset += blocks * 512;
        continue;
      }

      const entryPath = nextLongName ?? (prefix ? `${prefix}/${rawName}` : rawName);
      const linkTarget = nextLongLink ?? (rawLinkname || undefined);
      nextLongName = undefined;
      nextLongLink = undefined;

      // Map entry kind
      let kind: ArchiveEntryKind = "file";
      if (typeflag === "5" || entryPath.endsWith("/")) {
        kind = "directory";
      } else if (typeflag === "2") {
        kind = "symlink";
      } else if (typeflag === "1") {
        kind = "hardlink";
      } else if (["3", "4", "6"].includes(typeflag)) {
        kind = "special";
      }

      const candidate: ArchiveEntryCandidate = {
        path: entryPath,
        kind,
        size: kind === "directory" ? 0 : size,
        linkTarget,
      };

      // 1. PRE-WRITE VALIDATION
      const valResult = PreWriteValidator.validateEntry(candidate, sandboxDir, this.policy, stats);
      if (!valResult.ok) {
        if (valResult.error.code === "DEVICE_NODE_REJECTED") {
          // Special files (device nodes, FIFOs, sockets) cannot and must not be created on host disk.
          // Safely skip disk creation while preserving sandbox security bounds.
          continue;
        }
        if (valResult.error.code === "SYMLINK_ESCAPE" && candidate.kind === "symlink") {
          // Neutralize absolute/forbidden host symlinks inside firmware (e.g. /proc/mounts, /etc/ssl/certs).
          // Creating raw host symlinks to these paths would be dangerous on host OS.
          // Safely write a non-executable metadata placeholder file to preserve the link record.
          const canonical = resolve(sandboxDir);
          const sanitized = normalize(candidate.path.replace(/\\/g, "/")).replace(/^\/+/u, "");
          const destPath = resolve(canonical, sanitized);
          if (destPath === canonical || !destPath.startsWith(canonical + sep)) {
            return valResult; // Path itself escapes sandbox
          }
          const dirRes = await PreWriteValidator.ensureSafeDirectory(dirname(destPath), sandboxDir);
          if (!dirRes.ok) return dirRes;

          const phRes = await this.writeEntryExclusive(
            `${destPath}.symlink`,
            Buffer.from(`symlink:${candidate.linkTarget ?? ""}`),
          );
          if (!phRes.ok) return phRes;

          (stats as { currentFileCount: number }).currentFileCount++;
          validatedEntries.push({
            destinationPath: destPath,
            relativePath: candidate.path,
            kind: "symlink",
            size: candidate.size,
            linkTarget: candidate.linkTarget ?? undefined,
          });
          continue;
        }
        return valResult;
      }
      const validated = valResult.value;

      // 2. WRITE ENTRY
      if (validated.kind === "directory") {
        const dirRes = await PreWriteValidator.ensureSafeDirectory(validated.destinationPath, sandboxDir);
        if (!dirRes.ok) return dirRes;
        validatedEntries.push(validated);
      } else if (validated.kind === "symlink") {
        const dirRes = await PreWriteValidator.ensureSafeDirectory(dirname(validated.destinationPath), sandboxDir);
        if (!dirRes.ok) return dirRes;

        const symCheck = await PreWriteValidator.validateNotSymlink(validated.destinationPath);
        if (!symCheck.ok) return symCheck;

        try {
          if (validated.linkTarget) {
            await symlink(validated.linkTarget, validated.destinationPath);
          }
        } catch {
          // On non-admin Windows, symlink may throw EPERM; fallback to link metadata file
          const phRes = await this.writeEntryExclusive(
            `${validated.destinationPath}.symlink`,
            Buffer.from(`symlink:${validated.linkTarget ?? ""}`),
          );
          if (!phRes.ok) return phRes;
        }
        (stats as { currentFileCount: number }).currentFileCount++;
        validatedEntries.push(validated);
      } else if (validated.kind === "hardlink") {
        const dirRes = await PreWriteValidator.ensureSafeDirectory(dirname(validated.destinationPath), sandboxDir);
        if (!dirRes.ok) return dirRes;

        const symCheck = await PreWriteValidator.validateNotSymlink(validated.destinationPath);
        if (!symCheck.ok) return symCheck;

        if (validated.linkTarget) {
          const resolvedTarget = resolve(sandboxDir, validated.linkTarget.replace(/^[/\\]+/u, ""));
          try {
            await link(resolvedTarget, validated.destinationPath);
          } catch {
            // Fallback to copying bytes if hardlink is not permitted
            try {
              const targetBytes = await readFile(resolvedTarget);
              const copyRes = await this.writeEntryExclusive(validated.destinationPath, targetBytes);
              if (!copyRes.ok) return copyRes;
            } catch {
              const linkPhRes = await this.writeEntryExclusive(
                `${validated.destinationPath}.link`,
                Buffer.from(`hardlink:${validated.linkTarget}`),
              );
              if (!linkPhRes.ok) return linkPhRes;
            }
          }
        }
        (stats as { currentFileCount: number }).currentFileCount++;
        validatedEntries.push(validated);
      } else if (validated.kind === "file") {
        const dirRes = await PreWriteValidator.ensureSafeDirectory(dirname(validated.destinationPath), sandboxDir);
        if (!dirRes.ok) return dirRes;

        const fileContent = buffer.subarray(offset, offset + size);
        const writeRes = await this.writeEntryExclusive(validated.destinationPath, fileContent);
        if (!writeRes.ok) return writeRes;

        (stats as { currentFileCount: number }).currentFileCount++;
        (stats as { currentCumulativeBytes: number }).currentCumulativeBytes += size;
        validatedEntries.push(validated);
      }

      const contentBlocks = Math.ceil(size / 512);
      offset += contentBlocks * 512;
    }

    return ok(undefined);
  }

  /**
   * Safe SquashFS extractor.
   */
  private async extractSquashFs(
    buffer: Buffer,
    offset: number,
    sandboxDir: string,
    stats: ExtractionStats,
    validatedEntries: ValidatedEntry[],
    signal?: AbortSignal,
  ): Promise<Result<void, ExtractionError>> {
    const entriesResult = SquashFsParser.parseEntries(buffer, offset);
    if (!entriesResult.ok) {
      return entriesResult;
    }

    for (const entry of entriesResult.value) {
      if (signal?.aborted) {
        return err({ code: "EXTRACTION_TIMEOUT", message: "Extraction cancelled by signal" });
      }

      const candidate: ArchiveEntryCandidate = {
        path: entry.path,
        kind: entry.kind,
        size: entry.size,
        linkTarget: entry.linkTarget,
      };

      // 1. PRE-WRITE VALIDATION
      const valResult = PreWriteValidator.validateEntry(candidate, sandboxDir, this.policy, stats);
      if (!valResult.ok) {
        if (valResult.error.code === "DEVICE_NODE_REJECTED") {
          // Special files (device nodes, FIFOs, sockets) cannot and must not be created on host disk.
          // Safely skip disk creation while preserving sandbox security bounds.
          continue;
        }
        if (valResult.error.code === "SYMLINK_ESCAPE" && candidate.kind === "symlink") {
          // Neutralize absolute/forbidden host symlinks inside firmware (e.g. /proc/mounts, /etc/ssl/certs).
          // Creating raw host symlinks to these paths would be dangerous on host OS.
          // Safely write a non-executable metadata placeholder file to preserve the link record.
          const canonical = resolve(sandboxDir);
          const sanitized = normalize(candidate.path.replace(/\\/g, "/")).replace(/^\/+/u, "");
          const destPath = resolve(canonical, sanitized);
          if (destPath === canonical || !destPath.startsWith(canonical + sep)) {
            return valResult; // Path itself escapes sandbox
          }
          const dirRes = await PreWriteValidator.ensureSafeDirectory(dirname(destPath), sandboxDir);
          if (!dirRes.ok) return dirRes;

          const phRes = await this.writeEntryExclusive(
            `${destPath}.symlink`,
            Buffer.from(`symlink:${candidate.linkTarget ?? ""}`),
          );
          if (!phRes.ok) return phRes;

          (stats as { currentFileCount: number }).currentFileCount++;
          validatedEntries.push({
            destinationPath: destPath,
            relativePath: candidate.path,
            kind: "symlink",
            size: candidate.size,
            linkTarget: candidate.linkTarget ?? undefined,
          });
          continue;
        }
        return valResult;
      }
      const validated = valResult.value;

      // 2. WRITE ENTRY
      if (validated.kind === "directory") {
        const dirRes = await PreWriteValidator.ensureSafeDirectory(validated.destinationPath, sandboxDir);
        if (!dirRes.ok) return dirRes;
        validatedEntries.push(validated);
      } else if (validated.kind === "symlink") {
        const dirRes = await PreWriteValidator.ensureSafeDirectory(dirname(validated.destinationPath), sandboxDir);
        if (!dirRes.ok) return dirRes;

        const symCheck = await PreWriteValidator.validateNotSymlink(validated.destinationPath);
        if (!symCheck.ok) return symCheck;

        try {
          if (validated.linkTarget) {
            await symlink(validated.linkTarget, validated.destinationPath);
          }
        } catch {
          const phRes = await this.writeEntryExclusive(
            `${validated.destinationPath}.symlink`,
            Buffer.from(`symlink:${validated.linkTarget ?? ""}`),
          );
          if (!phRes.ok) return phRes;
        }
        (stats as { currentFileCount: number }).currentFileCount++;
        validatedEntries.push(validated);
      } else if (validated.kind === "file") {
        const dirRes = await PreWriteValidator.ensureSafeDirectory(dirname(validated.destinationPath), sandboxDir);
        if (!dirRes.ok) return dirRes;

        const writeRes = await this.writeEntryExclusive(
          validated.destinationPath,
          entry.content ?? Buffer.alloc(0),
        );
        if (!writeRes.ok) return writeRes;

        (stats as { currentFileCount: number }).currentFileCount++;
        (stats as { currentCumulativeBytes: number }).currentCumulativeBytes += entry.size;
        validatedEntries.push(validated);
      }
    }

    return ok(undefined);
  }

  /**
   * Atomic and exclusive file creation with TOCTOU elimination.
   * Uses O_CREAT | O_EXCL ('wx') so that the kernel atomically aborts if
   * the path exists (or is a symlink) without traversing it.
   * Then verifies that the opened file descriptor is a regular file.
   */
  private async writeEntryExclusive(
    destinationPath: string,
    content: Buffer,
  ): Promise<Result<void, ExtractionError>> {
    // 1. Initial check for existing symlinks or Windows .symlink placeholders
    const symCheck = await PreWriteValidator.validateNotSymlink(destinationPath);
    if (!symCheck.ok) {
      return symCheck;
    }

    let handle;
    try {
      handle = await open(destinationPath, "wx");
    } catch (e: unknown) {
      const error = e as NodeJS.ErrnoException;
      if (error.code === "EEXIST") {
        // Path exists. Determine if it is a symlink or placeholder.
        const statResult = await lstat(destinationPath).catch(() => null);
        if (!statResult || statResult.isSymbolicLink()) {
          return err({
            code: "SYMLINK_ESCAPE",
            message: `Refusing to write to existing symbolic link at ${destinationPath}`,
            violationPath: destinationPath,
          });
        }
        const placeholder = await lstat(`${destinationPath}.symlink`).catch(() => null);
        if (placeholder) {
          return err({
            code: "SYMLINK_ESCAPE",
            message: `Refusing to write to existing symbolic link placeholder at ${destinationPath}`,
            violationPath: destinationPath,
          });
        }

        // Regular file already exists (e.g. duplicate archive entry).
        // Safely unlink and re-open exclusively.
        try {
          await unlink(destinationPath);
          handle = await open(destinationPath, "wx");
        } catch (retryErr: unknown) {
          return err({
            code: "SANDBOX_ERROR",
            message: `Failed to safely recreate existing file at ${destinationPath}: ${retryErr instanceof Error ? retryErr.message : String(retryErr)}`,
            violationPath: destinationPath,
          });
        }
      } else {
        return err({
          code: "SANDBOX_ERROR",
          message: `Failed to open destination file exclusively at ${destinationPath}: ${error.message}`,
          violationPath: destinationPath,
        });
      }
    }

    // 2. Descriptor inspection (fstat) to ensure opened handle is a regular file
    try {
      const handleStat = await handle.stat();
      if (!handleStat.isFile()) {
        return err({
          code: "DEVICE_NODE_REJECTED",
          message: `Opened destination is not a regular file: ${destinationPath}`,
          violationPath: destinationPath,
        });
      }
      await handle.writeFile(content);
    } finally {
      await handle.close();
    }

    return ok(undefined);
  }

  /**
   * Bounded streaming gzip decompression with chunk-by-chunk quota,
   * expansion-ratio bomb protection, and immediate AbortSignal interruption.
   */
  private async decompressGzipStream(
    compressedBuffer: Buffer,
    signal?: AbortSignal,
  ): Promise<Result<Buffer, ExtractionError>> {
    if (signal?.aborted) {
      return err({ code: "EXTRACTION_TIMEOUT", message: "Decompression cancelled by signal" });
    }

    return new Promise<Result<Buffer, ExtractionError>>((resolve) => {
      let isSettled = false;
      const chunks: Buffer[] = [];
      let bytesDecompressed = 0;
      const inputLength = compressedBuffer.length;
      const maxCumulative = this.policy.maxCumulativeBytes;
      const maxRatio = this.policy.maxExpansionRatio;

      const gunzip = createGunzip();
      const readable = Readable.from(compressedBuffer);

      const cleanup = () => {
        chunks.length = 0;
        signal?.removeEventListener("abort", onAbort);
      };

      const settle = (result: Result<Buffer, ExtractionError>) => {
        if (isSettled) return;
        isSettled = true;
        if (!result.ok) {
          gunzip.destroy();
          readable.destroy();
          cleanup();
        } else {
          signal?.removeEventListener("abort", onAbort);
        }
        resolve(result);
      };

      const onAbort = () => {
        settle(err({ code: "EXTRACTION_TIMEOUT", message: "Decompression cancelled by signal" }));
      };

      if (signal) {
        signal.addEventListener("abort", onAbort, { once: true });
      }

      gunzip.on("data", (chunk: Buffer) => {
        if (isSettled) return;

        bytesDecompressed += chunk.length;

        // 1. Enforce cumulative byte limit incrementally on every chunk
        if (bytesDecompressed > maxCumulative) {
          settle(err({
            code: "QUOTA_EXCEEDED",
            message: `Decompressed size (${bytesDecompressed} bytes) exceeds maximum allowed cumulative limit (${maxCumulative} bytes)`,
          }));
          return;
        }

        // 2. Enforce expansion ratio limit incrementally on every chunk (after initial 1 MB)
        if (inputLength > 0 && bytesDecompressed > 1024 * 1024) {
          const ratio = bytesDecompressed / inputLength;
          if (ratio > maxRatio) {
            settle(err({
              code: "DECOMPRESSION_BOMB",
              message: `Streaming decompression bomb detected: expansion ratio ${ratio.toFixed(1)}x exceeds maximum allowed ${maxRatio}x`,
            }));
            return;
          }
        }

        chunks.push(chunk);
      });

      gunzip.on("end", () => {
        if (isSettled) return;
        const totalBuffer = Buffer.concat(chunks, bytesDecompressed);
        chunks.length = 0;
        settle(ok(totalBuffer));
      });

      gunzip.on("error", (error: Error) => {
        settle(err({
          code: "INVALID_FIRMWARE",
          message: `Failed to decompress gzip stream: ${error.message}`,
          cause: error,
        }));
      });

      readable.on("error", (error: Error) => {
        settle(err({
          code: "INVALID_FIRMWARE",
          message: `Gzip stream read error: ${error.message}`,
          cause: error,
        }));
      });

      readable.pipe(gunzip);
    });
  }
}
