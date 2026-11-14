import { ok, err, type Result } from "../../domain/result.js";
import {
  computeFindingId,
  type FindingLocation,
  type SecurityFinding,
} from "../../domain/security/finding.js";
import type { AssetId, AssetRecord } from "../../domain/security/asset.js";
import type { CweId, SecuritySeverityLevel } from "../../domain/security/classification.js";
import {
  defaultSerialUartAdapter,
  SerialUartAdapter,
} from "./adapters/serialAdapter.js";
import { defaultAdbAdapter, AdbAdapter } from "./adapters/adbAdapter.js";
import type { DeviceProbeOptions } from "./types.js";

export interface DeviceInterfaceAnalysisResult {
  readonly target: string;
  readonly interface_type: string;
  readonly findings: readonly SecurityFinding[];
  readonly raw_details: Readonly<Record<string, unknown>>;
}

export class DeviceInterfaceAnalyzer {
  public constructor(
    private readonly serialAdapter: SerialUartAdapter = defaultSerialUartAdapter,
    private readonly adbAdapter: AdbAdapter = defaultAdbAdapter,
  ) {}

  public async analyze(
    options: DeviceProbeOptions & {
      interface_type?: "UART_SERIAL" | "ADB" | "JTAG_SWD" | "USB";
      asset?: AssetRecord;
    },
  ): Promise<Result<DeviceInterfaceAnalysisResult, Error>> {
    const target = options.target;
    const ifaceType = options.interface_type ?? (target.startsWith("COM") || target.includes("tty") ? "UART_SERIAL" : "ADB");
    const findings: SecurityFinding[] = [];
    const rawDetails: Record<string, unknown> = {};

    const defaultAsset: AssetRecord = options.asset ?? {
      id: "ast_0000000000000000000000000000000000000000000000000000000000000000" as AssetId,
      name: `Device Interface (${ifaceType})`,
      type: "device_hardware",
      path: target,
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
      technicalDescription: string;
      rootCause: string;
      remediationDesc: string;
    }): SecurityFinding => {
      const location: FindingLocation = {
        file: target,
        function: null,
        line: 1,
        column: null,
        end_line: null,
        module: `interface/${ifaceType.toLowerCase()}`,
        component: "hardware_interface",
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
        reproduction_steps: [`Connect to ${ifaceType} interface at ${target} and inspect access level`],
        impact: {
          description: "Direct local or physical root-level device compromise.",
          attack_prerequisites: ["Physical or interface access to device pins/ports"],
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
          verification_method: "Direct device interface interrogation",
        },
        remediation: {
          description: opts.remediationDesc,
          code_diff: null,
          config_example: null,
          priority: opts.severity === "CRITICAL" ? "IMMEDIATE" : "SHORT_TERM",
          validation_procedure: `Verify ${target} requires strong authentication or is disabled in production.`,
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
          discovered_by: "device-interface-analyzer",
          discovered_at: new Date().toISOString(),
          verified_by: null,
          verified_at: null,
        },
      };
    };

    if (ifaceType === "UART_SERIAL") {
      const probeRes = await this.serialAdapter.probe(options);
      if (probeRes.ok) {
        rawDetails.status = probeRes.value.status;
        rawDetails.banner = probeRes.value.banner;

        if (probeRes.value.status.access_level === "ROOT_SHELL") {
          findings.push(
            makeFinding({
              name: "Unauthenticated Root Shell on UART Serial Console",
              severity: "CRITICAL",
              cvssVector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              cvssScore: 6.8,
              cweId: "CWE-1188" as CweId,
              technicalDescription:
                "The hardware serial UART console provides an interactive root shell without requiring password authentication or login verification.",
              rootCause: "Insecure default inittab/getty configuration on tty serial device.",
              remediationDesc:
                "Disable serial console autologin; enforce password authentication with /sbin/getty or /sbin/login.",
            }),
          );
        }
      }
    } else if (ifaceType === "ADB") {
      const probeRes = await this.adbAdapter.probe(options);
      if (probeRes.ok) {
        const raw = probeRes.value.raw_attributes;
        rawDetails.attributes = raw;

        if (raw.is_root) {
          findings.push(
            makeFinding({
              name: "Root Privileges Enabled by Default via ADB",
              severity: "CRITICAL",
              cvssVector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              cvssScore: 8.4,
              cweId: "CWE-250" as CweId,
              technicalDescription:
                "ADB daemon executes as root or ro.debuggable=1 allows direct adb root access without security controls.",
              rootCause: "Production build contains userdebug/eng debug build configuration.",
              remediationDesc: "Produce a user build with ro.debuggable=0 and ro.secure=1.",
            }),
          );
        }

        if (raw.selinux === "Permissive" || raw.selinux === "Disabled") {
          findings.push(
            makeFinding({
              name: `SELinux Enforcement Disabled (${String(raw.selinux)}) on Device`,
              severity: "HIGH",
              cvssVector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
              cvssScore: 7.7,
              cweId: "CWE-693" as CweId,
              technicalDescription:
                `SELinux is currently running in '${String(raw.selinux)}' mode, disabling mandatory access control (MAC) protection.`,
              rootCause: "Kernel command line contains androidboot.selinux=permissive.",
              remediationDesc: "Enforce SELinux in enforcing mode in production boot configuration.",
            }),
          );
        }
      }
    }

    return ok({
      target,
      interface_type: ifaceType,
      findings,
      raw_details: Object.freeze(rawDetails),
    });
  }
}

export const defaultDeviceInterfaceAnalyzer = new DeviceInterfaceAnalyzer();
