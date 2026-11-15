import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface XzDecompressorOptions {
  readonly maxOutputLength?: number;
  readonly timeoutMs?: number;
  readonly maxExpansionRatio?: number;
  readonly memlimitMb?: number;
  readonly signal?: AbortSignal;
}

export class XzDecompressor {
  private static cachedBinaryPath: string | null = null;

  /**
   * Resolve the project-local XZ executable path across Windows and Linux.
   */
  public static resolveXzBinary(): string {
    if (this.cachedBinaryPath && existsSync(this.cachedBinaryPath)) {
      return this.cachedBinaryPath;
    }

    // 1. Explicit environment override
    if (process.env.REA_XZ_PATH && existsSync(process.env.REA_XZ_PATH)) {
      this.cachedBinaryPath = process.env.REA_XZ_PATH;
      return this.cachedBinaryPath;
    }

    // 2. Resolve relative to this module
    const currentDir = dirname(fileURLToPath(import.meta.url));
    // src/security/firmware -> repo root is 3 levels up
    const repoRoot = resolve(currentDir, "../../..");

    const winCandidate = join(repoRoot, "tools", "xz", "windows", "xz.exe");
    const linuxCandidate = join(repoRoot, "tools", "xz", "linux-wsl", "xz");

    if (process.platform === "win32") {
      if (existsSync(winCandidate)) {
        this.cachedBinaryPath = winCandidate;
        return winCandidate;
      }
    } else {
      if (existsSync(linuxCandidate)) {
        this.cachedBinaryPath = linuxCandidate;
        return linuxCandidate;
      }
    }

    // Check cwd fallback
    const cwdWin = resolve(process.cwd(), "tools/xz/windows/xz.exe");
    const cwdLinux = resolve(process.cwd(), "tools/xz/linux-wsl/xz");
    if (process.platform === "win32" && existsSync(cwdWin)) {
      this.cachedBinaryPath = cwdWin;
      return cwdWin;
    }
    if (process.platform !== "win32" && existsSync(cwdLinux)) {
      this.cachedBinaryPath = cwdLinux;
      return cwdLinux;
    }
    if (process.platform !== "win32" && existsSync("/usr/bin/xz")) {
      this.cachedBinaryPath = "/usr/bin/xz";
      return "/usr/bin/xz";
    }

    throw new Error(
      `Project-local XZ executable not found. Expected at ${process.platform === "win32" ? winCandidate : linuxCandidate}. Ensure Task 2C toolchain is installed under tools/xz/.`,
    );
  }

  /**
   * Synchronously decompress an XZ-compressed byte buffer.
   */
  public static decompressSync(
    compressed: Buffer,
    options: XzDecompressorOptions = {},
  ): Buffer {
    if (compressed.length === 0) {
      return Buffer.alloc(0);
    }

    const xzPath = this.resolveXzBinary();
    const maxOutputLength = options.maxOutputLength ?? 16 * 1024 * 1024; // 16 MB default
    const timeoutMs = options.timeoutMs ?? 10_000; // 10s default
    const maxRatio = options.maxExpansionRatio ?? 100;
    const memlimit = options.memlimitMb ?? 128;

    const args = ["-d", "-c", `--memlimit=${memlimit}MB`, "--threads=1"];

    const res = spawnSync(xzPath, args, {
      input: compressed,
      maxBuffer: maxOutputLength,
      timeout: timeoutMs,
      shell: false,
      windowsHide: true,
    });

    if (res.error) {
      const errObj = res.error as { code?: string };
      if (errObj.code === "ETIMEDOUT") {
        throw new Error(
          `XZ decompression timed out after ${timeoutMs}ms (execution limit exceeded)`,
        );
      }
      if (errObj.code === "ENOBUFS") {
        throw new Error(
          `XZ decompression output exceeded maximum allowed size limit of ${maxOutputLength} bytes`,
        );
      }
      throw new Error(
        `XZ decompression process spawn failed: ${res.error.message}`,
      );
    }

    if (res.status !== 0) {
      const stderr = res.stderr ? res.stderr.toString().trim() : "";
      throw new Error(
        `XZ decompression failed with exit code ${res.status}: ${stderr || "corrupted or truncated input stream"}`,
      );
    }

    const decompressed = res.stdout;
    if (decompressed.length > maxOutputLength) {
      throw new Error(
        `XZ decompressed size (${decompressed.length} bytes) exceeds maximum limit of ${maxOutputLength} bytes`,
      );
    }

    if (compressed.length > 0) {
      const ratio = decompressed.length / compressed.length;
      if (ratio > maxRatio && decompressed.length > 1024 * 1024) {
        throw new Error(
          `XZ decompression bomb detected: expansion ratio ${ratio.toFixed(1)}x exceeds maximum allowed ${maxRatio}x`,
        );
      }
    }

    return decompressed;
  }
}
