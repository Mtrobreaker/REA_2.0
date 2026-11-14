import { err, ok, type Result } from "../../../domain/result.js";
import type { AssetRecord } from "../../../domain/security/asset.js";
import type { SecurityFinding } from "../../../domain/security/finding.js";
import { normalizeSarif } from "../../../domain/security/sarifNormalizer.js";
import { runOwnedCommand } from "../../../process/OwnedCommand.js";
import type {
  OwnedProviderProcessSpawnOptions,
  ProviderProcessSnapshot,
  SpawnedOwnedProviderProcess,
} from "../../../process/ProviderProcess.js";

export interface TrivyScanOptions {
  readonly target: string;
  readonly mode?: "fs" | "image" | "rootfs";
  readonly scanners?: readonly ("vuln" | "secret" | "misconfig")[];
  readonly severity?: readonly ("UNKNOWN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL")[];
  readonly timeoutMs?: number;
  readonly executablePath?: string;
  readonly signal?: AbortSignal;
  readonly asset: AssetRecord;
  readonly launcher?: (
    input: OwnedProviderProcessSpawnOptions,
  ) => Promise<SpawnedOwnedProviderProcess>;
  readonly commandRunner?: (
    spawn: OwnedProviderProcessSpawnOptions,
    limits: {
      readonly diagnosticBytes: number;
      readonly timeoutMs: number;
      readonly acceptNonZeroExit?: boolean;
    },
  ) => Promise<ProviderProcessSnapshot>;
}

export interface TrivyScanError {
  readonly code:
    | "TRIVY_NOT_INSTALLED"
    | "TRIVY_EXECUTION_FAILED"
    | "TRIVY_TIMEOUT"
    | "TRIVY_PARSE_ERROR";
  readonly message: string;
  readonly details?: unknown;
}

export interface TrivyScanResult {
  readonly findings: readonly SecurityFinding[];
  readonly rawSarif: unknown;
  readonly commandLine: string;
}

/**
 * Execute Trivy container, filesystem, or dependency scan and normalize into SecurityFindings.
 */
export const runTrivyScan = async (
  options: TrivyScanOptions,
): Promise<Result<TrivyScanResult, TrivyScanError>> => {
  const executable = options.executablePath ?? "trivy";
  const timeoutMs = options.timeoutMs ?? 180_000;
  const mode = options.mode ?? "fs";

  const args: string[] = [mode, "--format", "sarif", "--quiet"];

  if (options.scanners && options.scanners.length > 0) {
    args.push("--scanners", options.scanners.join(","));
  }

  if (options.severity && options.severity.length > 0) {
    args.push("--severity", options.severity.join(","));
  }

  args.push(options.target);

  const runId = `trivy_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  let snapshot: ProviderProcessSnapshot;

  try {
    if (options.commandRunner) {
      snapshot = await options.commandRunner(
        {
          command: executable,
          arguments: args,
          runId,
          ...(options.signal !== undefined ? { signal: options.signal } : {}),
        },
        {
          diagnosticBytes: 20 * 1024 * 1024, // Retain up to 20MB of SARIF output
          timeoutMs,
          acceptNonZeroExit: true,
        },
      );
    } else {
      snapshot = await runOwnedCommand(
        {
          command: executable,
          arguments: args,
          runId,
          ...(options.signal !== undefined ? { signal: options.signal } : {}),
        },
        {
          diagnosticBytes: 20 * 1024 * 1024,
          timeoutMs,
          acceptNonZeroExit: true,
        },
        {
          ...(options.signal !== undefined ? { signal: options.signal } : {}),
          ...(options.launcher !== undefined ? { launcher: options.launcher } : {}),
        },
      );
    }
  } catch (error: unknown) {
    const errorMsg = error instanceof Error ? error.message : String(error);

    if (errorMsg.includes("ENOENT") || errorMsg.includes("not found")) {
      return err({
        code: "TRIVY_NOT_INSTALLED",
        message:
          "Trivy binary was not found on PATH. Install it via 'brew install trivy' or official packages.",
        details: errorMsg,
      });
    }

    if (errorMsg.includes("timeout") || errorMsg.includes("deadline")) {
      return err({
        code: "TRIVY_TIMEOUT",
        message: `Trivy analysis timed out after ${timeoutMs}ms.`,
        details: errorMsg,
      });
    }

    return err({
      code: "TRIVY_EXECUTION_FAILED",
      message: `Failed to execute Trivy: ${errorMsg}`,
      details: error,
    });
  }

  const stdout = snapshot.stdout.text.trim();
  if (!stdout) {
    return ok({
      findings: [],
      rawSarif: null,
      commandLine: `${executable} ${args.join(" ")}`,
    });
  }

  let sarifJson: unknown;
  try {
    sarifJson = JSON.parse(stdout);
  } catch (parseError: unknown) {
    return err({
      code: "TRIVY_PARSE_ERROR",
      message: `Failed to parse Trivy output as JSON: ${parseError instanceof Error ? parseError.message : String(parseError)}`,
      details: stdout.slice(0, 500),
    });
  }

  const normalized = normalizeSarif(sarifJson, options.asset);
  if (!normalized.ok) {
    return err({
      code: "TRIVY_PARSE_ERROR",
      message: `Failed to normalize Trivy SARIF: ${normalized.error.message}`,
      details: normalized.error,
    });
  }

  return ok({
    findings: normalized.value,
    rawSarif: sarifJson,
    commandLine: `${executable} ${args.join(" ")}`,
  });
};
