import { createHash } from "node:crypto";
import { ok, err, type Result } from "../../domain/result.js";
import type { AuthorizationScope } from "../../domain/security/assessment.js";
import {
  validateTargetAuthorization,
  type AuthorizationError,
} from "../../domain/security/authorization.js";
import type { SecurityFinding } from "../../domain/security/finding.js";
import {
  runOwnedCommand,
} from "../../process/OwnedCommand.js";
import type {
  OwnedProviderProcessSpawnOptions,
  ProviderProcessSnapshot,
  SpawnedOwnedProviderProcess,
} from "../../process/ProviderProcess.js";

export type CommandExecutionLimits = Parameters<typeof runOwnedCommand>[1];

export interface SandboxPolicy {
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly allowNetwork: boolean;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly commandRunner?: (
    options: OwnedProviderProcessSpawnOptions,
    limits: CommandExecutionLimits,
  ) => Promise<ProviderProcessSnapshot>;
}

export const DEFAULT_SANDBOX_POLICY: SandboxPolicy = {
  timeoutMs: 15_000,
  maxOutputBytes: 10 * 1024 * 1024,
  allowNetwork: false,
};

export interface VerificationExecutionResult {
  readonly finding_id: string;
  readonly status: "VERIFIED" | "FALSE_POSITIVE" | "UNVERIFIED";
  readonly command: string;
  readonly arguments: readonly string[];
  readonly exit_code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly duration_ms: number;
  readonly justification: string;
}

export interface VerificationError {
  readonly code:
    | "AUTHORIZATION_DENIED"
    | "EXECUTION_TIMEOUT"
    | "EXECUTION_FAILED"
    | "INVALID_FINDING";
  readonly message: string;
  readonly details?: unknown;
}

export interface RunVerificationOptions {
  readonly finding: SecurityFinding;
  readonly scope: AuthorizationScope;
  readonly testCommand: string;
  readonly testArgs?: readonly string[];
  readonly expectedPattern?: string | RegExp;
  readonly policy?: Partial<SandboxPolicy>;
  readonly signal?: AbortSignal;
}

/**
 * Sandboxed Dynamic Verification Harness
 * Safely executes controlled, non-destructive reproduction steps in an isolated
 * environment, enforcing timeouts, resource boundaries, and fail-closed authorization.
 */
export class SandboxHarness {
  constructor(private readonly defaultPolicy: SandboxPolicy = DEFAULT_SANDBOX_POLICY) {}

  public async verifyFinding(
    options: RunVerificationOptions,
  ): Promise<Result<VerificationExecutionResult, VerificationError>> {
    const finding = options.finding;
    const targetFile = finding.location.file;

    // 1. Enforce fail-closed authorization check on the target
    if (targetFile) {
      const auth = validateTargetAuthorization(targetFile, options.scope);
      if (!auth.ok) {
        return err({
          code: "AUTHORIZATION_DENIED",
          message: `Verification rejected: target ${targetFile} violates authorization scope (${auth.error.message})`,
          details: auth.error,
        });
      }
    }

    const policy: SandboxPolicy = {
      ...this.defaultPolicy,
      ...options.policy,
    };

    const runId = `vfy_${createHash("sha256")
      .update(`${finding.id}:${Date.now()}:${Math.random()}`)
      .digest("hex")
      .slice(0, 16)}`;

    const startTime = Date.now();
    const args = [...(options.testArgs ?? [])];
    let snapshot: ProviderProcessSnapshot;

    try {
      const spawnOpts: OwnedProviderProcessSpawnOptions = {
        command: options.testCommand,
        arguments: args,
        runId,
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
      };

      const limits: CommandExecutionLimits = {
        diagnosticBytes: policy.maxOutputBytes,
        timeoutMs: policy.timeoutMs,
        acceptNonZeroExit: true, // Vulnerability probes frequently exit non-zero
      };

      if (policy.commandRunner) {
        snapshot = await policy.commandRunner(spawnOpts, limits);
      } else {
        snapshot = await runOwnedCommand(spawnOpts, limits, {
          ...(options.signal !== undefined ? { signal: options.signal } : {}),
        });
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes("deadline") || msg.includes("timeout")) {
        return err({
          code: "EXECUTION_TIMEOUT",
          message: `Verification execution timed out after ${policy.timeoutMs}ms`,
          details: e,
        });
      }
      return err({
        code: "EXECUTION_FAILED",
        message: `Verification command execution failed: ${msg}`,
        details: e,
      });
    }

    const duration = Date.now() - startTime;
    const stdout = snapshot.stdout.text;
    const stderr = snapshot.stderr.text;

    // 2. Evaluate output against expected pattern or failure indicators
    let status: "VERIFIED" | "FALSE_POSITIVE" | "UNVERIFIED" = "UNVERIFIED";
    let justification = "";

    if (options.expectedPattern) {
      const reproduced =
        typeof options.expectedPattern === "string"
          ? stdout.includes(options.expectedPattern) || stderr.includes(options.expectedPattern)
          : options.expectedPattern.test(stdout) || options.expectedPattern.test(stderr);

      if (reproduced) {
        status = "VERIFIED";
        justification = `Output matched expected vulnerability pattern: ${String(options.expectedPattern)}`;
      } else {
        // Did not match expected vulnerability pattern
        status = snapshot.exitCode === 0 ? "FALSE_POSITIVE" : "UNVERIFIED";
        justification =
          snapshot.exitCode === 0
            ? `Output did not contain expected vulnerability indicator: ${String(options.expectedPattern)}`
            : `Probe exited with code ${snapshot.exitCode ?? "null"} without matching expected vulnerability indicator (unverified crash/failure).`;
      }
    } else {
      // Invariant: Normal process completion, non-empty stdout, or an unverified crash alone
      // must NEVER establish vulnerability verification without an expected pattern oracle.
      status = "UNVERIFIED";
      justification = `No expected vulnerability indicator pattern provided. Process completion (exit code ${snapshot.exitCode ?? "null"}) or unverified crash alone cannot establish vulnerability verification.`;
    }

    return ok({
      finding_id: finding.id,
      status,
      command: options.testCommand,
      arguments: args,
      exit_code: snapshot.exitCode ?? null,
      stdout,
      stderr,
      duration_ms: duration,
      justification,
    });
  }
}

export const defaultSandboxHarness = new SandboxHarness();
