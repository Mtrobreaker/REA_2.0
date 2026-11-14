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

export interface SemgrepScanOptions {
  readonly targets: readonly string[];
  readonly rules?: readonly string[];
  readonly configPath?: string;
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

export interface SemgrepScanError {
  readonly code:
    | "SEMGREP_NOT_INSTALLED"
    | "SEMGREP_EXECUTION_FAILED"
    | "SEMGREP_TIMEOUT"
    | "SEMGREP_PARSE_ERROR";
  readonly message: string;
  readonly details?: unknown;
}

export interface SemgrepScanResult {
  readonly findings: readonly SecurityFinding[];
  readonly rawSarif: unknown;
  readonly commandLine: string;
}

/**
 * Execute Semgrep static analysis and normalize SARIF output into SecurityFindings.
 */
export const runSemgrepScan = async (
  options: SemgrepScanOptions,
): Promise<Result<SemgrepScanResult, SemgrepScanError>> => {
  const executable = options.executablePath ?? "semgrep";
  const timeoutMs = options.timeoutMs ?? 120_000;

  const args: string[] = ["scan", "--sarif", "--quiet"];

  if (options.configPath) {
    args.push("--config", options.configPath);
  } else if (options.rules && options.rules.length > 0) {
    for (const rule of options.rules) {
      args.push("--config", rule);
    }
  } else {
    // Default to security audit ruleset
    args.push("--config", "p/security-audit");
  }

  for (const target of options.targets) {
    args.push(target);
  }

  const runId = `semgrep_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
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
          diagnosticBytes: 10 * 1024 * 1024,
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
          diagnosticBytes: 10 * 1024 * 1024, // Retain up to 10MB of SARIF output
          timeoutMs,
          acceptNonZeroExit: true, // Semgrep exits with 1 or 2 when findings are found
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
        code: "SEMGREP_NOT_INSTALLED",
        message:
          "Semgrep executable was not found on PATH. Install it via 'pip install semgrep' or 'brew install semgrep'.",
        details: errorMsg,
      });
    }

    if (errorMsg.includes("timeout") || errorMsg.includes("deadline")) {
      return err({
        code: "SEMGREP_TIMEOUT",
        message: `Semgrep analysis timed out after ${timeoutMs}ms.`,
        details: errorMsg,
      });
    }

    return err({
      code: "SEMGREP_EXECUTION_FAILED",
      message: `Failed to execute Semgrep: ${errorMsg}`,
      details: error,
    });
  }

  const stdout = snapshot.stdout.text.trim();
  if (!stdout) {
    // Check if stderr reported an error
    if (snapshot.stderr.text) {
      return err({
        code: "SEMGREP_EXECUTION_FAILED",
        message: `Semgrep stderr reported failure: ${snapshot.stderr.text}`,
        details: snapshot.stderr.text,
      });
    }

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
      code: "SEMGREP_PARSE_ERROR",
      message: `Failed to parse Semgrep output as JSON: ${parseError instanceof Error ? parseError.message : String(parseError)}`,
      details: stdout.slice(0, 500),
    });
  }

  const normalized = normalizeSarif(sarifJson, options.asset);
  if (!normalized.ok) {
    return err({
      code: "SEMGREP_PARSE_ERROR",
      message: `Failed to normalize Semgrep SARIF: ${normalized.error.message}`,
      details: normalized.error,
    });
  }

  return ok({
    findings: normalized.value,
    rawSarif: sarifJson,
    commandLine: `${executable} ${args.join(" ")}`,
  });
};
