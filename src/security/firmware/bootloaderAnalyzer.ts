import { existsSync, readFileSync } from "node:fs";
import { ok, err, type Result } from "../../domain/result.js";
import {
  computeFindingId,
  type FindingLocation,
  type SecurityFinding,
} from "../../domain/security/finding.js";
import type { AssetId, AssetRecord } from "../../domain/security/asset.js";
import type { CweId, SecuritySeverityLevel } from "../../domain/security/classification.js";

export interface BootloaderAnalysisResult {
  readonly path: string;
  readonly bootloader_type: string;
  readonly findings: readonly SecurityFinding[];
  readonly raw_variables: Readonly<Record<string, string>>;
}

export class BootloaderAnalyzer {
  public async analyze(
    filePath: string,
    asset?: AssetRecord,
  ): Promise<Result<BootloaderAnalysisResult, Error>> {
    if (!existsSync(filePath)) {
      return err(new Error(`Bootloader environment file not found: ${filePath}`));
    }

    const content = readFileSync(filePath, "utf-8");
    const findings: SecurityFinding[] = [];
    const rawVariables: Record<string, string> = {};

    const defaultAsset: AssetRecord = asset ?? {
      id: "ast_0000000000000000000000000000000000000000000000000000000000000000" as AssetId,
      name: "Target Bootloader",
      type: "firmware_image",
      path: filePath,
      digest: null,
      architecture: null,
      version: null,
      environment: null,
      tags: [],
      metadata: {},
    };

    const makeFinding = (opts: {
      name: string;
      severity: SecuritySeverityLevel;
      cvssVector: string;
      cvssScore: number;
      cweId: CweId;
      line: number;
      technicalDescription: string;
      rootCause: string;
      remediationDesc: string;
    }): SecurityFinding => {
      const location: FindingLocation = {
        file: filePath,
        function: null,
        line: opts.line,
        column: null,
        end_line: null,
        module: "bootloader/env",
        component: "bootloader",
        address: null,
        offset: null,
      };

      const id = computeFindingId({
        asset_id: defaultAsset.id,
        name: opts.name,
        location,
        root_cause: opts.rootCause,
      });

      return {
        id,
        name: opts.name,
        affected_asset: {
          id: defaultAsset.id,
          name: defaultAsset.name,
          type: defaultAsset.type,
        },
        location,
        technical_description: opts.technicalDescription,
        root_cause: opts.rootCause,
        evidence_ids: [],
        reproduction_steps: [`Inspect line ${opts.line} in ${filePath}`],
        impact: {
          description: "Execution hijacking or physical shell access bypass.",
          attack_prerequisites: ["Serial console or adjacent network access"],
          exploitability: "PROVEN",
        },
        severity: {
          level: opts.severity,
          cvss_vector: opts.cvssVector,
          cvss_score: opts.cvssScore,
          justification: opts.technicalDescription,
        },
        confidence: {
          level: "CONFIRMED",
          false_positive_considerations: [],
          verification_method: "U-Boot environment variable parse",
        },
        remediation: {
          description: opts.remediationDesc,
          code_diff: null,
          config_example: null,
          priority: opts.severity === "CRITICAL" ? "IMMEDIATE" : "SHORT_TERM",
          validation_procedure: `Verify ${filePath} does not contain dangerous boot arguments.`,
        },
        classification: {
          cve: [],
          cwe: [opts.cweId],
          capec: [],
          mitre_attack: [],
          owasp: [],
        },
        verification_status: "UNVERIFIED",
        provenance: {
          discovered_by: "bootloader-analyzer",
          discovered_at: new Date().toISOString(),
          verified_by: null,
          verified_at: null,
        },
      };
    };

    // Parse KEY=VALUE lines
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i]?.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx > 0) {
        const key = trimmed.slice(0, eqIdx).trim();
        const value = trimmed.slice(eqIdx + 1).trim();
        rawVariables[key] = value;

        if (key === "bootargs") {
          if (value.includes("init=/bin/sh") || value.includes("init=/bin/bash")) {
            findings.push(
              makeFinding({
                name: "Insecure Bootloader Init Argument (init=/bin/sh)",
                severity: "CRITICAL",
                cvssVector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvssScore: 6.8,
                cweId: "CWE-250" as CweId,
                line: i + 1,
                technicalDescription:
                  "The bootloader bootargs contains 'init=/bin/sh', which forces the kernel to bypass user authentication and launch a root shell.",
                rootCause: "Development debug parameter retained in bootloader environment.",
                remediationDesc: "Remove 'init=/bin/sh' from bootargs and restore standard init daemon path.",
              }),
            );
          }
        }

        if (key === "bootcmd") {
          if (value.includes("tftp") && !value.includes("verify=yes")) {
            findings.push(
              makeFinding({
                name: "Insecure Unauthenticated Network Boot (TFTP) in Bootloader",
                severity: "HIGH",
                cvssVector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvssScore: 8.8,
                cweId: "CWE-306" as CweId,
                line: i + 1,
                technicalDescription:
                  "The bootloader executes network TFTP booting without image signature verification, allowing network attackers to boot malicious kernels.",
                rootCause: "Unverified TFTP network boot sequence in bootcmd.",
                remediationDesc: "Enforce cryptographic image verification (FIT image with signed hash) before booting network payloads.",
              }),
            );
          }
        }
      }
    }

    return ok({
      path: filePath,
      bootloader_type: "U_BOOT",
      findings,
      raw_variables: Object.freeze(rawVariables),
    });
  }
}

export const defaultBootloaderAnalyzer = new BootloaderAnalyzer();
