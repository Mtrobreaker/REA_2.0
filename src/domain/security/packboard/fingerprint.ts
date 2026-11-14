import { createHash } from "node:crypto";
import type { AssetId } from "../asset.js";
import type { FindingLocation } from "../finding.js";
import type { SecurityClassification } from "../classification.js";

export interface FingerprintParams {
  readonly asset_id: AssetId;
  readonly location: FindingLocation;
  readonly classification: SecurityClassification;
  readonly sink_identifier?: string | null;
  readonly data_flow_hash?: string | null;
}

/**
 * Normalizes file path to lowercase forward slashes, stripping drive letters or relative dots.
 */
export function normalizeFilePath(filePath: string | null | undefined): string {
  if (!filePath) return "unknown_file";
  return filePath
    .replace(/\\/g, "/")
    .replace(/^[a-zA-Z]:/u, "")
    .replace(/^\.\//u, "")
    .toLowerCase();
}

/**
 * Generates a deterministic composite root-cause fingerprint for a security finding/lead.
 * Ensures that vulnerabilities with different root causes, sinks, or CWEs are never incorrectly merged,
 * even if they appear on adjacent or identical source lines.
 */
export function generateCompositeFingerprint(params: FingerprintParams): string {
  const normFile = normalizeFilePath(params.location.file);
  const funcName = params.location.function?.trim().toLowerCase() ?? "anonymous";
  const primaryCwe = params.classification.cwe[0] ?? "CWE-UNKNOWN";
  const sink = params.sink_identifier?.trim().toLowerCase() ?? "default_sink";
  const flowHash = params.data_flow_hash?.trim() ?? "no_flow_hash";

  const rawKey = [
    params.asset_id,
    normFile,
    funcName,
    primaryCwe,
    sink,
    flowHash,
  ].join("::");

  return createHash("sha256").update(rawKey, "utf8").digest("hex");
}

