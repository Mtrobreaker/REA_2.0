import type { AssetId, AssetType } from "../asset.js";
import type { AssessmentId } from "../assessment.js";
import type { BlackboardAssetRecord, TaskRecord, ObservationRecord } from "../blackboard/types.js";

export type FirmwareFormat =
  | "squashfs"
  | "cramfs"
  | "jffs2"
  | "ubifs"
  | "ext4"
  | "tar"
  | "gzip"
  | "bzip2"
  | "xz"
  | "uimage"
  | "fit"
  | "trx"
  | "unknown";

export interface FirmwareFormatDetectionResult {
  readonly format: FirmwareFormat;
  readonly confidence: number;
  readonly offset: number;
  readonly description: string;
  readonly details?: Readonly<Record<string, unknown>> | undefined;
}

export interface ExtractionSecurityPolicy {
  /** Maximum bytes permitted across all extracted files (default: 10 GB). */
  readonly maxCumulativeBytes: number;
  /** Maximum bytes permitted for any single extracted file (default: 2 GB). */
  readonly maxSingleFileBytes: number;
  /** Maximum total number of filesystem entries (default: 10,000). */
  readonly maxFileCount: number;
  /** Maximum expansion ratio before aborting as a decompression bomb (default: 100x). */
  readonly maxExpansionRatio: number;
  /** Execution timeout for extraction in milliseconds (default: 60,000 ms). */
  readonly maxExecutionTimeMs: number;
  /** Whether safe in-sandbox symlinks are permitted (default: true). */
  readonly allowSymlinks: boolean;
  /** Special files (device nodes, FIFOs, sockets) are strictly forbidden (always false). */
  readonly allowSpecialFiles: false;
}

export const DEFAULT_EXTRACTION_POLICY: ExtractionSecurityPolicy = {
  maxCumulativeBytes: 10 * 1024 * 1024 * 1024, // 10 GB
  maxSingleFileBytes: 2 * 1024 * 1024 * 1024,  // 2 GB
  maxFileCount: 10_000,
  maxExpansionRatio: 100,                      // 100x ratio
  maxExecutionTimeMs: 60_000,                  // 60 seconds
  allowSymlinks: true,
  allowSpecialFiles: false,
};

export type ArchiveEntryKind = "file" | "directory" | "symlink" | "hardlink" | "special";

export interface ArchiveEntryCandidate {
  readonly path: string;
  readonly kind: ArchiveEntryKind;
  readonly size: number;
  readonly linkTarget?: string | null | undefined;
}

export interface ExtractedAssetMetadata {
  readonly relativePath: string;
  readonly fullPath: string;
  readonly type: AssetType;
  readonly size: number;
  readonly sha256: string;
  readonly architecture?: string | undefined;
  readonly endianness?: "little" | "big" | undefined;
  readonly isExecutable: boolean;
}

export interface ExtractionResult {
  readonly assessmentId: AssessmentId;
  readonly rootAssetId: AssetId;
  readonly format: FirmwareFormat;
  readonly sandboxDir: string;
  readonly extractedFilesCount: number;
  readonly totalBytesExtracted: number;
  readonly assetsCreated: ReadonlyArray<BlackboardAssetRecord>;
  readonly tasksCreated: ReadonlyArray<TaskRecord>;
  readonly observationsCreated: ReadonlyArray<ObservationRecord>;
  readonly securityViolations: ReadonlyArray<string>;
}

export type ExtractionErrorCode =
  | "INVALID_FIRMWARE"
  | "UNSUPPORTED_FORMAT"
  | "PATH_TRAVERSAL"
  | "SYMLINK_ESCAPE"
  | "DEVICE_NODE_REJECTED"
  | "DECOMPRESSION_BOMB"
  | "QUOTA_EXCEEDED"
  | "EXTRACTION_TIMEOUT"
  | "SANDBOX_ERROR";

export interface ExtractionError {
  readonly code: ExtractionErrorCode;
  readonly message: string;
  readonly violationPath?: string | undefined;
  readonly cause?: unknown;
}

