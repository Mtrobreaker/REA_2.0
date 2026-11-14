import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative } from "node:path";
import { err, ok, type Result } from "../../../domain/result.js";
import {
  type BinaryInputReference,
  validateBinaryInputReference,
} from "../ipc/binaryWorkerProtocol.js";

export interface BinaryInputResolverOptions {
  /** Optional allowed root directory enclosing permitted target binaries. */
  readonly allowedRoot?: string | undefined;
}

export interface ResolvedBinaryInput {
  readonly buffer: Buffer;
  readonly sha256: string;
  readonly byteSize: number;
  readonly source: "file_path" | "inline_buffer";
}

export interface BinaryInputResolutionError {
  readonly code:
    | "INVALID_INPUT_REFERENCE"
    | "PATH_TRAVERSAL"
    | "DIGEST_MISMATCH"
    | "FILE_ACCESS_ERROR"
    | "SIZE_EXCEEDED";
  readonly message: string;
}

/**
 * Resolves a parent-issued BinaryInputReference into read-only binary bytes.
 *
 * Security Invariants:
 * 1. Rejects arbitrary, unvalidated filesystem paths.
 * 2. Blocks relative paths, directory traversal sequences ('..'), and root escapes.
 * 3. Enforces cryptographic digest binding: the actual SHA-256 of read bytes
 *    must match expected_sha256 exactly.
 * 4. The worker never sets executable file permissions (chmod +x) and never
 *    executes target binaries as processes.
 */
export class BinaryInputResolver {
  private readonly allowedRoot: string | undefined;

  constructor(options?: BinaryInputResolverOptions) {
    this.allowedRoot = options?.allowedRoot;
  }

  public async resolve(
    ref: BinaryInputReference,
  ): Promise<Result<ResolvedBinaryInput, BinaryInputResolutionError>> {
    if (ref.type === "inline_buffer") {
      return this.resolveInlineBuffer(ref);
    }

    if (ref.type === "file_path") {
      return this.resolveFilePath(ref);
    }

    return err({
      code: "INVALID_INPUT_REFERENCE",
      message: "Unsupported binary input reference type",
    });
  }

  private resolveInlineBuffer(
    ref: Extract<BinaryInputReference, { type: "inline_buffer" }>,
  ): Result<ResolvedBinaryInput, BinaryInputResolutionError> {
    let buf: Buffer;
    try {
      buf = Buffer.from(ref.data_base64, "base64");
    } catch {
      return err({
        code: "INVALID_INPUT_REFERENCE",
        message: "Failed to decode inline base64 binary buffer",
      });
    }

    if (buf.length !== ref.byte_size) {
      return err({
        code: "SIZE_EXCEEDED",
        message: `Inline buffer byte size mismatch: declared ${ref.byte_size}, decoded ${buf.length}`,
      });
    }

    const actualSha256 = createHash("sha256").update(buf).digest("hex");
    if (actualSha256.toLowerCase() !== ref.expected_sha256.toLowerCase()) {
      return err({
        code: "DIGEST_MISMATCH",
        message: `Inline buffer SHA-256 digest mismatch: expected ${ref.expected_sha256}, calculated ${actualSha256}`,
      });
    }

    return ok({
      buffer: buf,
      sha256: actualSha256,
      byteSize: buf.length,
      source: "inline_buffer",
    });
  }

  private async resolveFilePath(
    ref: Extract<BinaryInputReference, { type: "file_path" }>,
  ): Promise<Result<ResolvedBinaryInput, BinaryInputResolutionError>> {
    // 1. Strict traversal and allowed root containment check
    const pathValidation = validateBinaryInputReference(ref, this.allowedRoot);
    if (!pathValidation.ok) {
      return err({
        code: "PATH_TRAVERSAL",
        message: `Path traversal or root escape rejected: ${pathValidation.error.message}`,
      });
    }

    // 1b. Symlink resolution check if allowed root is configured
    if (this.allowedRoot) {
      try {
        const canonicalTarget = await realpath(ref.path);
        const canonicalRoot = await realpath(this.allowedRoot);
        const rel = relative(canonicalRoot, canonicalTarget);
        if (rel.startsWith("..") || isAbsolute(rel)) {
          return err({
            code: "PATH_TRAVERSAL",
            message: `Canonical target path '${canonicalTarget}' escapes allowed root '${canonicalRoot}' via symlink`,
          });
        }
      } catch (realpathErr) {
        return err({
          code: "FILE_ACCESS_ERROR",
          message: `Cannot resolve canonical binary path: ${realpathErr instanceof Error ? realpathErr.name : "read failure"}`,
        });
      }
    }

    // 2. Read bytes into memory strictly as data
    let buf: Buffer;
    try {
      buf = await readFile(ref.path);
    } catch (readErr) {
      // Do not leak internal system paths or full stack traces
      return err({
        code: "FILE_ACCESS_ERROR",
        message: `Cannot access target binary: ${readErr instanceof Error ? readErr.name : "read failure"}`,
      });
    }

    if (buf.length !== ref.byte_size) {
      return err({
        code: "SIZE_EXCEEDED",
        message: `Binary file size mismatch: declared ${ref.byte_size}, observed ${buf.length}`,
      });
    }

    // 3. Cryptographic digest verification
    const actualSha256 = createHash("sha256").update(buf).digest("hex");
    if (actualSha256.toLowerCase() !== ref.expected_sha256.toLowerCase()) {
      return err({
        code: "DIGEST_MISMATCH",
        message: `Target binary SHA-256 digest mismatch: expected ${ref.expected_sha256}, calculated ${actualSha256}`,
      });
    }

    return ok({
      buffer: buf,
      sha256: actualSha256,
      byteSize: buf.length,
      source: "file_path",
    });
  }
}
