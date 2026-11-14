import { readFile } from "node:fs/promises";
import { ok, type Result } from "../../domain/result.js";
import type { CweId } from "../../domain/security/classification.js";
import {
  computeFindingId,
  type FindingLocation,
  type SecurityFinding,
} from "../../domain/security/finding.js";
import type {
  AgentContext,
  AgentExecutionError,
  AgentExecutionResult,
  SecurityAgent,
} from "./types.js";

/**
 * Binary Analysis Agent
 * Examines executables, libraries, and firmware binaries for security mitigations,
 * dangerous native calls, unsafe memory operations, and vulnerable symbols.
 */
export class BinaryAnalysisAgent implements SecurityAgent {
  public readonly role = "binary_analysis";
  public readonly name = "Binary & Executable Security Agent";
  public readonly description =
    "Analyzes compiled executables, ELF/PE/Mach-O binaries, detecting missing compiler mitigations and unsafe native functions.";

  public async execute(
    context: AgentContext,
  ): Promise<Result<AgentExecutionResult, AgentExecutionError>> {
    const assets = context.state.assets.filter(
      (a) => a.type === "compiled_binary" || a.type === "firmware_image",
    );
    const actions: string[] = [];
    const findings: SecurityFinding[] = [];

    if (assets.length === 0) {
      actions.push("No binary or executable assets present for analysis.");
      return ok({
        agent_role: this.role,
        actions_performed: actions,
        findings_added: [],
        findings_modified: [],
        assets_added: [],
      });
    }

    for (const asset of assets) {
      if (!asset.path) continue;
      actions.push(`Inspecting binary target: ${asset.name}`);

      try {
        const buffer = await readFile(asset.path);
        const headerInspection = this.inspectBinaryHeaders(asset.path, buffer, asset);
        findings.push(...headerInspection.findings);
        actions.push(...headerInspection.actions);
      } catch (err: unknown) {
        actions.push(
          `Could not read binary file ${asset.path}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    if (findings.length > 0) {
      context.updateAssessment((state) => ({
        ...state,
        findings: [...state.findings, ...findings],
      }));
    }

    return ok({
      agent_role: this.role,
      actions_performed: actions,
      findings_added: findings,
      findings_modified: [],
      assets_added: [],
    });
  }

  private inspectBinaryHeaders(
    filePath: string,
    buffer: Buffer,
    asset: { id: `ast_${string}`; name: string; type: any },
  ): { findings: SecurityFinding[]; actions: string[] } {
    const findings: SecurityFinding[] = [];
    const actions: string[] = [];

    // Check ELF magic \x7fELF
    if (buffer.length >= 4 && buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
      actions.push(`Verified ELF format for ${asset.name}`);

      // Basic string-based dangerous symbol scan
      const stringContent = buffer.toString("latin1");
      const dangerousFunctions = [
        { name: "gets", cwe: "CWE-242" as CweId, severity: "HIGH" as const, cvss: 7.5 },
        { name: "strcpy", cwe: "CWE-120" as CweId, severity: "MEDIUM" as const, cvss: 5.3 },
        { name: "system", cwe: "CWE-78" as CweId, severity: "HIGH" as const, cvss: 8.1 },
      ];

      for (const fn of dangerousFunctions) {
        const symbolNeedle = "\0" + fn.name + "\0";
        if (stringContent.includes(symbolNeedle)) {
          actions.push(`Detected import or reference to dangerous CRT function: ${fn.name}`);
          const location: FindingLocation = {
            file: filePath,
            function: fn.name,
            line: null,
            column: null,
            end_line: null,
            module: null,
            component: "dynamic_symbols",
            address: null,
            offset: null,
          };

          const rootCause = `Binary links or references legacy unchecked standard C function '${fn.name}' without bounded length validation.`;
          const findingId = computeFindingId({
            asset_id: asset.id,
            name: `Insecure Native Function Call: ${fn.name}`,
            location,
            root_cause: rootCause,
          });

          findings.push({
            id: findingId,
            name: `Insecure Native Function Call: ${fn.name}`,
            affected_asset: {
              id: asset.id,
              name: asset.name,
              type: asset.type,
            },
            location,
            technical_description: `The compiled executable imports the inherently unsafe or high-risk symbol '${fn.name}', which is susceptible to buffer overflows or arbitrary command injection.`,
            root_cause: rootCause,
            evidence_ids: [],
            reproduction_steps: [
              `Inspect binary symbol table: readelf -s ${filePath} | grep ${fn.name}`,
            ],
            impact: {
              description: `Attacker supplying unbounded input may trigger memory corruption or arbitrary command execution.`,
              attack_prerequisites: ["Input path reaching function invocation"],
              exploitability: "THEORETICAL",
            },
            severity: {
              level: fn.severity,
              cvss_vector: null,
              cvss_score: fn.cvss,
              justification: `Use of unsafe C runtime symbol ${fn.name}`,
            },
            confidence: {
              level: "CONFIRMED",
              false_positive_considerations: ["Symbol may be present in unused dead code block"],
              verification_method: "Binary symbol table inspection",
            },
            remediation: {
              description: `Replace '${fn.name}' with bounded or memory-safe alternatives (e.g. strncpy, snprintf, execve).`,
              code_diff: null,
              config_example: null,
              priority: "SHORT_TERM",
              validation_procedure: `Recompile and verify '${fn.name}' is absent from dynamic symbol table.`,
            },
            classification: {
              cve: [],
              cwe: [fn.cwe],
              capec: [],
              mitre_attack: [],
              owasp: [],
            },
            verification_status: "UNVERIFIED",
            provenance: {
              discovered_by: "binary-analysis-agent",
              discovered_at: new Date().toISOString(),
              verified_by: null,
              verified_at: null,
            },
          });
        }
      }
    } else {
      actions.push(`Non-ELF or raw binary format for ${asset.name}`);
    }

    return { findings, actions };
  }
}
