import { ok, err, type Result } from "../../../domain/result.js";
import type {
  ArchitectureType,
  DeviceInterfaceStatus,
} from "../../../domain/security/device.js";
import type {
  DeviceAdapterError,
  DeviceInterfaceAdapter,
  DeviceProbeOptions,
  DeviceProbeResult,
} from "../types.js";

export type AdbPropertyFetcher = (
  serial: string,
) => Promise<{
  properties: Readonly<Record<string, string>>;
  selinuxState: string;
  isRoot: boolean;
}>;

export class AdbAdapter implements DeviceInterfaceAdapter {
  public readonly interfaceType = "ADB" as const;

  public constructor(
    private readonly customFetcher?: AdbPropertyFetcher,
  ) {}

  public async probe(
    options: DeviceProbeOptions,
  ): Promise<Result<DeviceProbeResult, DeviceAdapterError>> {
    const serial = options.target;

    try {
      const data = this.customFetcher
        ? await this.customFetcher(serial)
        : {
            properties: {},
            selinuxState: "unknown",
            isRoot: false,
          };

      const props = data.properties;
      const model = props["ro.product.model"] ?? "Android Device";
      const manufacturer = props["ro.product.manufacturer"] ?? "Generic";
      const abi = props["ro.product.cpu.abi"] ?? "arm64-v8a";
      const release = props["ro.build.version.release"] ?? "Unknown";
      const patch = props["ro.build.version.security_patch"] ?? "Unknown";

      let arch: ArchitectureType = "AARCH64";
      if (abi.startsWith("arm64")) {
        arch = "AARCH64";
      } else if (abi.startsWith("armeabi")) {
        arch = "ARM";
      } else if (abi.startsWith("x86_64")) {
        arch = "X86_64";
      } else if (abi.startsWith("x86")) {
        arch = "X86";
      }

      const isRoot = data.isRoot || (props["ro.debuggable"] === "1" && props["ro.secure"] === "0");
      const isAccessible = Object.keys(props).length > 0;

      const status: DeviceInterfaceStatus = {
        type: "ADB",
        port_or_address: serial,
        is_accessible: isAccessible,
        auth_required: true,
        auth_status: isAccessible ? ("AUTHENTICATED" as const) : ("UNTESTED" as const),
        access_level: isRoot
          ? ("ROOT_SHELL" as const)
          : isAccessible
            ? ("SHELL_USER" as const)
            : ("NONE" as const),
        details: `${manufacturer} ${model} (Android ${release}, Patch: ${patch}, SELinux: ${data.selinuxState})`,
      };

      return ok({
        interface_type: "ADB",
        status,
        banner: `Android ${release} (${manufacturer} ${model})`,
        raw_attributes: {
          manufacturer,
          model,
          architecture: arch,
          release,
          security_patch: patch,
          selinux: data.selinuxState,
          is_root: isRoot,
          properties: props,
        },
      });
    } catch (e: unknown) {
      return err({
        code: "PROBE_FAILED",
        message: `ADB probe failed for device '${serial}': ${e instanceof Error ? e.message : String(e)}`,
        details: e,
      });
    }
  }
}

export const defaultAdbAdapter = new AdbAdapter();

