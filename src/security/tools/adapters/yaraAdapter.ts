import { err, ok, type Result } from "../../../domain/result.js";
import type { AssetRecord } from "../../../domain/security/asset.js";
import type { SecuritySeverityLevel } from "../../../domain/security/classification.js";
import {
  computeFindingId,
  type FindingLocation,
  type SecurityFinding,
} from "../../../domain/security/finding.js";
import { runOwnedCommand } from "../../../process/OwnedCommand.js";
import type {
  OwnedProviderProcessSpawnOptions,
  ProviderProcessSnapshot,
  SpawnedOwnedProviderProcess,
} from "../../../process/ProviderProcess.js";

export interface YaraScanOptions {
  readonly targets: readonly string[];
  readonly ruleFiles?: readonly string[];
  readonly ruleString?: string;
  readonly recursive?: boolean;
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

export interface YaraScanError {
  readonly code:
    | "YARA_NOT_INSTALLED"
    | "YARA_EXECUTION_FAILED"
    | "YARA_TIMEOUT"
    | "YARA_RULE_ERROR";
  readonly message: string;
  readonly details?: unknown;
}

export interface YaraMatch {
  readonly rule: string;
  readonly tags: readonly string[];
  readonly meta: Readonly<Record<string, string>>;
  readonly target: string;
  readonly strings: readonly {
    readonly identifier: string;
    readonly offset: number;
    readonly value: string;
  }[];
}

export interface YaraScanResult {
  readonly findings: readonly SecurityFinding[];
  readonly matches: readonly YaraMatch[];
  readonly commandLine: string;
}

/**
 * Parse output from `yara -m -s -g` format.
 */
export const parseYaraOutput = (rawOutput: string): YaraMatch[] => {
  const lines = rawOutput.split("\n");
  const matches: YaraMatch[] = [];
  let currentMatch: YaraMatch | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (!line) continue;

    // String match line: 0x1a4:$str: value
    const stringMatch = /^(0x[a-fA-F0-9]+):(\$[a-zA-Z0-9_]*):\s*(.*)$/u.exec(
      line.trimStart(),
    );
    if (stringMatch && currentMatch) {
      const offset = parseInt(stringMatch[1] ?? "0", 16);
      const identifier = stringMatch[2] ?? "$";
      const value = stringMatch[3] ?? "";
      (
        currentMatch.strings as {
          identifier: string;
          offset: number;
          value: string;
        }[]
      ).push({
        identifier,
        offset,
        value,
      });
      continue;
    }

    // New rule match header line
    // Format: rule_name [tag1,tag2] [key="val",key2="val2"] /path/to/target
    const ruleHeader = /^([a-zA-Z0-9_]+)\s*(?:\[([^\]]*)\])?\s*(?:\[([^\]]*)\])?\s+(.+)$/u.exec(
      line,
    );

    if (ruleHeader) {
      if (currentMatch) {
        matches.push(currentMatch);
      }

      const rule = ruleHeader[1] ?? "unknown_rule";
      const rawTags = ruleHeader[2] ?? "";
      const rawMeta = ruleHeader[3] ?? "";
      const target = ruleHeader[4] ?? "";

      const tags = rawTags
        ? rawTags
            .split(",")
            .map((t) => t.trim())
            .filter(Boolean)
        : [];

      const meta: Record<string, string> = {};
      if (rawMeta) {
        // Matches key="value" or key=value
        const metaRegex = /([a-zA-Z0-9_]+)=(?:"([^"]*)"|([^,\s]*))/gu;
        let m: RegExpExecArray | null;
        while ((m = metaRegex.exec(rawMeta)) !== null) {
          const key = m[1];
          const val = m[2] ?? m[3] ?? "";
          if (key) meta[key] = val;
        }
      }

      currentMatch = {
        rule,
        tags,
        meta,
        target,
        strings: [],
      };
    }
  }

  if (currentMatch) {
    matches.push(currentMatch);
  }

  return matches;
};

/**
 * Derive qualitative severity level from YARA tags and meta fields.
 */
const deriveYaraSeverity = (
  tags: readonly string[],
  meta: Readonly<Record<string, string>>,
): SecuritySeverityLevel => {
  const metaSev = meta["severity"]?.toUpperCase();
  if (metaSev === "CRITICAL") return "CRITICAL";
  if (metaSev === "HIGH") return "HIGH";
  if (metaSev === "MEDIUM") return "MEDIUM";
  if (metaSev === "LOW") return "LOW";
  if (metaSev === "INFORMATIONAL" || metaSev === "INFO") return "INFORMATIONAL";

  const lowerTags = tags.map((t) => t.toLowerCase());
  if (lowerTags.includes("malware") || lowerTags.includes("trojan") || lowerTags.includes("c2")) {
    return "CRITICAL";
  }
  if (lowerTags.includes("exploit") || lowerTags.includes("cve") || lowerTags.includes("backdoor")) {
    return "HIGH";
  }
  if (lowerTags.includes("suspicious") || lowerTags.includes("hacktool") || lowerTags.includes("packer")) {
    return "MEDIUM";
  }

  return "LOW";
};

/**
 * Execute YARA signature matching and normalize matches into SecurityFindings.
 */
export const runYaraScan = async (
  options: YaraScanOptions,
): Promise<Result<YaraScanResult, YaraScanError>> => {
  const executable = options.executablePath ?? "yara";
  const timeoutMs = options.timeoutMs ?? 60_000;

  const args: string[] = ["-m", "-s", "-g"];
  if (options.recursive) {
    args.push("-r");
  }

  // Add rule file
  const ruleFile = options.ruleFiles?.[0];
  if (!ruleFile) {
    return err({
      code: "YARA_RULE_ERROR",
      message: "At least one YARA rule file must be provided.",
    });
  }
  args.push(ruleFile);

  for (const target of options.targets) {
    args.push(target);
  }

  const runId = `yara_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
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
          diagnosticBytes: 5 * 1024 * 1024,
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
          diagnosticBytes: 5 * 1024 * 1024,
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
        code: "YARA_NOT_INSTALLED",
        message:
          "YARA binary was not found on PATH. Install it via 'brew install yara' or download official binary.",
        details: errorMsg,
      });
    }

    if (errorMsg.includes("timeout") || errorMsg.includes("deadline")) {
      return err({
        code: "YARA_TIMEOUT",
        message: `YARA scan timed out after ${timeoutMs}ms.`,
        details: errorMsg,
      });
    }

    return err({
      code: "YARA_EXECUTION_FAILED",
      message: `Failed to execute YARA: ${errorMsg}`,
      details: error,
    });
  }

  const matches = parseYaraOutput(snapshot.stdout.text);
  const now = new Date().toISOString();
  const findings: SecurityFinding[] = [];

  for (const match of matches) {
    const severity = deriveYaraSeverity(match.tags, match.meta);
    const ruleTitle =
      match.meta["description"] ??
      `YARA Signature Match: ${match.rule}`;

    const firstOffset = match.strings[0]?.offset ?? null;

    const location: FindingLocation = {
      file: match.target,
      function: null,
      line: null,
      column: null,
      end_line: null,
      module: null,
      component: null,
      address: null,
      offset: firstOffset,
    };

    const rootCause = `File matched YARA rule '${match.rule}' with ${match.strings.length} string patterns.`;

    const findingId = computeFindingId({
      asset_id: options.asset.id,
      name: ruleTitle,
      location,
      root_cause: rootCause,
    });

    findings.push({
      id: findingId,
      name: ruleTitle,
      affected_asset: {
        id: options.asset.id,
        name: options.asset.name,
        type: options.asset.type,
      },
      location,
      technical_description: `Target matched signature rule '${match.rule}'. Tags: [${match.tags.join(", ")}]. Matched strings: ${match.strings.map((s) => `${s.identifier} at 0x${s.offset.toString(16)}`).join(", ")}`,
      root_cause: rootCause,
      evidence_ids: [],
      reproduction_steps: [
        `Run: yara -m -s ${ruleFile} ${match.target}`,
      ],
      impact: {
        description: match.meta["impact"] ?? `Presence of malicious pattern: ${match.rule}`,
        attack_prerequisites: [],
        exploitability: "THEORETICAL",
      },
      severity: {
        level: severity,
        cvss_vector: null,
        cvss_score: severity === "CRITICAL" ? 9.0 : severity === "HIGH" ? 7.5 : 4.0,
        justification: `Derived from YARA rule metadata/tags for rule '${match.rule}'`,
      },
      confidence: {
        level: "CONFIRMED",
        false_positive_considerations: [
          "Verify rule specificity against clean baseline binaries.",
        ],
        verification_method: "Exact byte pattern matching via YARA engine.",
      },
      remediation: {
        description:
          match.meta["remediation"] ??
          "Quarantine or investigate file for unauthorized modifications.",
        code_diff: null,
        config_example: null,
        priority: severity === "CRITICAL" ? "IMMEDIATE" : "MEDIUM_TERM",
        validation_procedure: `Re-scan target with YARA rule ${match.rule}.`,
      },
      classification: {
        cve: match.meta["cve"] ? [match.meta["cve"] as any] : [],
        cwe: [],
        capec: [],
        mitre_attack: [],
        owasp: [],
      },
      verification_status: "CANDIDATE",
      provenance: {
        discovered_by: "YARA Engine",
        discovered_at: now,
        verified_by: null,
        verified_at: null,
      },
    });
  }

  return ok({
    findings,
    matches,
    commandLine: `${executable} ${args.join(" ")}`,
  });
};
