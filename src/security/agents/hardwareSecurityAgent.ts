import { ok, type Result } from "../../domain/result.js";
import type { SecurityFinding } from "../../domain/security/finding.js";
import { defaultDeviceInterfaceAnalyzer } from "../device/deviceInterfaceAnalyzer.js";
import type {
  AgentContext,
  AgentExecutionError,
  AgentExecutionResult,
  SecurityAgent,
} from "./types.js";

/**
 * Device Interface & Hardware-Software Security Agent
 * Evaluates physical communication interfaces (UART, JTAG/SWD, USB, ADB)
 * to detect unauthenticated root consoles, unlocked debug interfaces, and improper access controls.
 */
export class DeviceInterfaceSecurityAgent implements SecurityAgent {
  public readonly role = "hardware_security";
  public readonly name = "Device Interface & Hardware Security Agent";
  public readonly description =
    "Analyzes physical and logical device communication interfaces (UART serial, ADB, JTAG/SWD, USB) for insecure root consoles and unlocked debug access.";

  public async execute(
    context: AgentContext,
  ): Promise<Result<AgentExecutionResult, AgentExecutionError>> {
    const deviceAssets = context.state.assets.filter(
      (a) => a.type === "device_hardware",
    );
    const actions: string[] = [];
    const findings: SecurityFinding[] = [];

    if (deviceAssets.length === 0) {
      actions.push("No hardware device assets registered for evaluation.");
      return ok({
        agent_role: this.role,
        actions_performed: actions,
        findings_added: [],
        findings_modified: [],
        assets_added: [],
      });
    }

    for (const asset of deviceAssets) {
      if (!asset.path) continue;
      actions.push(
        `Running device interface security analysis on: ${asset.name}`,
      );

      const result = await defaultDeviceInterfaceAnalyzer.analyze({
        target: asset.path,
        asset,
      });

      if (result.ok) {
        actions.push(
          `Identified ${result.value.findings.length} findings on interface ${result.value.interface_type}`,
        );
        const mapped = result.value.findings.map((f) => ({
          ...f,
          provenance: {
            ...f.provenance,
            discovered_by: "device-interface-agent",
          },
        }));
        findings.push(...mapped);
      } else {
        actions.push(
          `Device interface analysis failed for ${asset.name}: ${result.error.message}`,
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
}

/**
 * Backwards compatibility alias.
 */
export const HardwareSecurityAgent = DeviceInterfaceSecurityAgent;
