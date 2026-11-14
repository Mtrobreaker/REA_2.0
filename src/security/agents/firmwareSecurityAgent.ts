import { ok, type Result } from "../../domain/result.js";
import type { SecurityFinding } from "../../domain/security/finding.js";
import { defaultFirmwareDeepAnalyzer } from "../firmware/firmwareDeepAnalyzer.js";
import type {
  AgentContext,
  AgentExecutionError,
  AgentExecutionResult,
  SecurityAgent,
} from "./types.js";

/**
 * Firmware Security Agent
 * Examines firmware images, filesystems, bootloaders, update mechanisms,
 * and detects embedded credentials, certificates, and hardcoded encryption keys.
 */
export class FirmwareSecurityAgent implements SecurityAgent {
  public readonly role = "firmware_security";
  public readonly name = "Firmware & Embedded Systems Security Agent";
  public readonly description =
    "Analyzes firmware binaries, embedded filesystems, bootloader configurations, and identifies hardcoded keys and insecure update schemes.";

  public async execute(
    context: AgentContext,
  ): Promise<Result<AgentExecutionResult, AgentExecutionError>> {
    const firmwareAssets = context.state.assets.filter(
      (a) => a.type === "firmware_image",
    );
    const actions: string[] = [];
    const findings: SecurityFinding[] = [];

    if (firmwareAssets.length === 0) {
      actions.push("No firmware assets registered for evaluation.");
      return ok({
        agent_role: this.role,
        actions_performed: actions,
        findings_added: [],
        findings_modified: [],
        assets_added: [],
      });
    }

    for (const asset of firmwareAssets) {
      if (!asset.path) continue;
      actions.push(`Running deep firmware analysis on asset: ${asset.name}`);

      const result = await defaultFirmwareDeepAnalyzer.analyze(asset.path, asset);
      if (result.ok) {
        actions.push(result.value.summary);
        const mapped = result.value.findings.map((f) => ({
          ...f,
          provenance: {
            ...f.provenance,
            discovered_by: "firmware-security-agent",
          },
        }));
        findings.push(...mapped);
      } else {
        actions.push(`Firmware analysis failed for ${asset.name}: ${result.error.message}`);
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
}

