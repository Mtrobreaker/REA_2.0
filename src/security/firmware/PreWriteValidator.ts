import { lstat, mkdir } from "node:fs/promises";
import { dirname, isAbsolute, normalize, resolve, sep } from "node:path";
import { err, ok, type Result } from "../../domain/result.js";
import type {
  ArchiveEntryCandidate,
  ArchiveEntryKind,
  ExtractionError,
  ExtractionSecurityPolicy,
} from "../../domain/security/firmware/types.js";

export interface ExtractionStats {
  readonly archiveSizeBytes: number;
  readonly currentFileCount: number;
  readonly currentCumulativeBytes: number;
}

export interface ValidatedEntry {
  readonly destinationPath: string;
  readonly relativePath: string;
  readonly kind: ArchiveEntryKind;
  readonly size: number;
  readonly linkTarget?: string | undefined;
}

const FORBIDDEN_HOST_TARGETS = [
  "/etc",
  "/proc",
  "/sys",
  "/dev",
  "/root",
  "/var/run",
  "/bin",
  "/sbin",
  "/usr/bin",
  "/usr/sbin",
  "c:\\windows",
  "c:\\program files",
  "c:\\program files (x86)",
  "c:\\users",
];

export class PreWriteValidator {
  /**
   * Validate an archive entry candidate against security policies before writing.
   */
  public static validateEntry(
    candidate: ArchiveEntryCandidate,
    sandboxRoot: string,
    policy: ExtractionSecurityPolicy,
    stats: ExtractionStats,
  ): Result<ValidatedEntry, ExtractionError> {
    const rawPath = candidate.path;

    // 1. Path traversal & malformed path validation
    if (!rawPath || typeof rawPath !== "string") {
      return err({
        code: "PATH_TRAVERSAL",
        message: "Archive entry path cannot be empty",
      });
    }

    if (rawPath.includes("\0")) {
      return err({
        code: "PATH_TRAVERSAL",
        message: "Archive entry path contains NUL character",
        violationPath: rawPath,
      });
    }

    // Windows drive-letter rejection (e.g. C:, D:)
    if (/^[a-zA-Z]:/u.test(rawPath)) {
      return err({
        code: "PATH_TRAVERSAL",
        message: `Absolute drive-letter path rejected: ${rawPath}`,
        violationPath: rawPath,
      });
    }

    // UNC path rejection (e.g. \\server\share or //server/share)
    if (rawPath.startsWith("\\\\") || rawPath.startsWith("//")) {
      return err({
        code: "PATH_TRAVERSAL",
        message: `UNC path rejected: ${rawPath}`,
        violationPath: rawPath,
      });
    }

    // Absolute Unix or root-relative path rejection
    if (rawPath.startsWith("/") || rawPath.startsWith("\\")) {
      return err({
        code: "PATH_TRAVERSAL",
        message: `Absolute path rejected: ${rawPath}`,
        violationPath: rawPath,
      });
    }

    // Segments check for traversal sequences
    const segments = rawPath.split(/[/\\]+/u);
    for (const segment of segments) {
      if (segment === "..") {
        return err({
          code: "PATH_TRAVERSAL",
          message: `Path traversal sequence '..' detected: ${rawPath}`,
          violationPath: rawPath,
        });
      }
    }

    // Canonical sandbox containment check
    const canonicalSandbox = resolve(sandboxRoot);
    const sanitizedRelative = normalize(rawPath.replace(/\\/g, "/")).replace(
      /^\/+/u,
      "",
    );
    const destinationPath = resolve(canonicalSandbox, sanitizedRelative);

    if (
      destinationPath !== canonicalSandbox &&
      !destinationPath.startsWith(canonicalSandbox + sep)
    ) {
      return err({
        code: "PATH_TRAVERSAL",
        message: `Target path escapes sandbox boundary: ${rawPath} -> ${destinationPath}`,
        violationPath: rawPath,
      });
    }

    // 2. Special-file and device-node rejection
    if (candidate.kind === "special") {
      return err({
        code: "DEVICE_NODE_REJECTED",
        message: `Special file / device node rejected (FIFOs, device nodes, and sockets are forbidden): ${rawPath}`,
        violationPath: rawPath,
      });
    }

    // 3. Symlink / Hardlink escape protection
    let validatedLinkTarget: string | undefined = undefined;
    if (candidate.kind === "symlink" || candidate.kind === "hardlink") {
      if (!policy.allowSymlinks) {
        return err({
          code: "SYMLINK_ESCAPE",
          message: `Symlinks / hardlinks are disabled by security policy: ${rawPath}`,
          violationPath: rawPath,
        });
      }

      const target = candidate.linkTarget;
      if (!target || typeof target !== "string" || target.trim().length === 0) {
        return err({
          code: "SYMLINK_ESCAPE",
          message: `Empty symlink target for: ${rawPath}`,
          violationPath: rawPath,
        });
      }

      // Check for forbidden host targets in target string
      const lowerTarget = target.toLowerCase();
      for (const forbidden of FORBIDDEN_HOST_TARGETS) {
        if (
          lowerTarget === forbidden ||
          lowerTarget.startsWith(`${forbidden}/`) ||
          lowerTarget.startsWith(`${forbidden}\\`)
        ) {
          return err({
            code: "SYMLINK_ESCAPE",
            message: `Symlink points to forbidden host path '${forbidden}': ${rawPath} -> ${target}`,
            violationPath: rawPath,
          });
        }
      }

      // Drive letter or UNC target rejection
      if (/^[a-zA-Z]:/u.test(target) || target.startsWith("\\\\") || target.startsWith("//")) {
        return err({
          code: "SYMLINK_ESCAPE",
          message: `Symlink target with drive letter or UNC rejected: ${rawPath} -> ${target}`,
          violationPath: rawPath,
        });
      }

      // Resolve destination of the symlink target
      let resolvedTarget: string;
      if (isAbsolute(target) || target.startsWith("/") || target.startsWith("\\")) {
        // Absolute symlinks inside an archive are intended relative to archive root
        const stripped = target.replace(/^[/\\]+/u, "");
        resolvedTarget = resolve(canonicalSandbox, stripped);
      } else {
        // Relative to candidate's parent directory
        resolvedTarget = resolve(dirname(destinationPath), target);
      }

      if (
        resolvedTarget !== canonicalSandbox &&
        !resolvedTarget.startsWith(canonicalSandbox + sep)
      ) {
        return err({
          code: "SYMLINK_ESCAPE",
          message: `Symlink target escapes sandbox boundary: ${rawPath} -> ${target}`,
          violationPath: rawPath,
        });
      }

      validatedLinkTarget = target;
    }

    // 4. Decompression bomb and quota enforcement
    if (candidate.size > policy.maxSingleFileBytes) {
      return err({
        code: "QUOTA_EXCEEDED",
        message: `File size ${candidate.size} bytes exceeds max single file limit of ${policy.maxSingleFileBytes} bytes`,
        violationPath: rawPath,
      });
    }

    if (stats.currentFileCount + 1 > policy.maxFileCount) {
      return err({
        code: "QUOTA_EXCEEDED",
        message: `Extraction file count ${stats.currentFileCount + 1} exceeds max file count ${policy.maxFileCount}`,
        violationPath: rawPath,
      });
    }

    const nextCumulativeBytes = stats.currentCumulativeBytes + candidate.size;
    if (nextCumulativeBytes > policy.maxCumulativeBytes) {
      return err({
        code: "QUOTA_EXCEEDED",
        message: `Cumulative extracted bytes ${nextCumulativeBytes} exceeds limit of ${policy.maxCumulativeBytes} bytes`,
        violationPath: rawPath,
      });
    }

    // Expansion ratio bomb check (ratio > maxExpansionRatio after minimum threshold)
    if (stats.archiveSizeBytes > 0 && nextCumulativeBytes > 1024 * 1024) {
      const ratio = nextCumulativeBytes / stats.archiveSizeBytes;
      if (ratio > policy.maxExpansionRatio) {
        return err({
          code: "DECOMPRESSION_BOMB",
          message: `Decompression bomb detected: expansion ratio ${ratio.toFixed(1)}x exceeds maximum allowed ${policy.maxExpansionRatio}x`,
          violationPath: rawPath,
        });
      }
    }

    return ok({
      destinationPath,
      relativePath: sanitizedRelative,
      kind: candidate.kind,
      size: candidate.size,
      ...(validatedLinkTarget !== undefined ? { linkTarget: validatedLinkTarget } : {}),
    });
  }

  /**
   * TOCTOU-safe directory creation: Verifies that no intermediate component
   * is a symlink before descending and creating subdirectories.
   */
  public static async ensureSafeDirectory(
    dirPath: string,
    sandboxRoot: string,
  ): Promise<Result<void, ExtractionError>> {
    const canonicalSandbox = resolve(sandboxRoot);
    const targetDir = resolve(dirPath);

    if (
      targetDir !== canonicalSandbox &&
      !targetDir.startsWith(canonicalSandbox + sep)
    ) {
      return err({
        code: "PATH_TRAVERSAL",
        message: `Directory path escapes sandbox: ${targetDir}`,
        violationPath: dirPath,
      });
    }

    const rel = targetDir.slice(canonicalSandbox.length).replace(/^[/\\]+/u, "");
    if (!rel) {
      return ok(undefined);
    }

    const parts = rel.split(/[/\\]+/u);
    let current = canonicalSandbox;

    for (const part of parts) {
      current = resolve(current, part);
      try {
        const s = await lstat(current);
        if (s.isSymbolicLink()) {
          return err({
            code: "SYMLINK_ESCAPE",
            message: `Intermediate directory component is a symbolic link: ${current}`,
            violationPath: current,
          });
        }
        if (!s.isDirectory()) {
          return err({
            code: "PATH_TRAVERSAL",
            message: `Intermediate component is not a directory: ${current}`,
            violationPath: current,
          });
        }
      } catch (e: unknown) {
        const error = e as NodeJS.ErrnoException;
        if (error.code === "ENOENT") {
          await mkdir(current);
        } else {
          return err({
            code: "SANDBOX_ERROR",
            message: `Failed to create safe directory: ${error.message}`,
            cause: error,
          });
        }
      }
    }

    return ok(undefined);
  }

  /**
   * Validate that destination path is not an existing symbolic link before writing.
   */
  public static async validateNotSymlink(
    destinationPath: string,
  ): Promise<Result<void, ExtractionError>> {
    try {
      const s = await lstat(destinationPath);
      if (s.isSymbolicLink()) {
        return err({
          code: "SYMLINK_ESCAPE",
          message: `Refusing to write through existing symbolic link at ${destinationPath}`,
          violationPath: destinationPath,
        });
      }
    } catch (e: unknown) {
      const error = e as NodeJS.ErrnoException;
      if (error.code !== "ENOENT") {
        return err({
          code: "SANDBOX_ERROR",
          message: `Failed to stat destination path: ${error.message}`,
          violationPath: destinationPath,
        });
      }
    }

    // Also check for symlink placeholder file on non-admin Windows hosts
    try {
      await lstat(`${destinationPath}.symlink`);
      return err({
        code: "SYMLINK_ESCAPE",
        message: `Refusing to write through existing symbolic link placeholder at ${destinationPath}`,
        violationPath: destinationPath,
      });
    } catch {
      // Normal: no placeholder exists
    }

    return ok(undefined);
  }
}

