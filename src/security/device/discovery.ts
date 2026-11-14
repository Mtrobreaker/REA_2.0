import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { ok, err, type Result } from "../../domain/result.js";
import {
  createDeviceCapabilityProfile,
  type ArchitectureType,
  type DeviceCapabilityProfile,
  type DeviceCategory,
  type DeviceInterfaceStatus,
  type OperatingSystemType,
} from "../../domain/security/device.js";
import { defaultAdbAdapter, AdbAdapter } from "./adapters/adbAdapter.js";
import { defaultSerialUartAdapter, SerialUartAdapter } from "./adapters/serialAdapter.js";
import type { DeviceAdapterError, DeviceProbeOptions } from "./types.js";

export interface DiscoveryOptions extends DeviceProbeOptions {
  readonly preferredInterface?: string;
  readonly safetyLevel?: "PASSIVE_IDENTIFICATION" | "READ_ONLY_ACQUISITION";
}

export class DeviceDiscoveryEngine {
  public constructor(
    private readonly serialAdapter: SerialUartAdapter = defaultSerialUartAdapter,
    private readonly adbAdapter: AdbAdapter = defaultAdbAdapter,
  ) {}

  public async discover(
    options: DiscoveryOptions,
  ): Promise<Result<DeviceCapabilityProfile, DeviceAdapterError>> {
    const target = options.target;

    // 1. Check if target is a local extracted filesystem directory
    if (existsSync(target)) {
      return this.discoverFromLocalFilesystem(target);
    }

    // 2. Check if target matches ADB serial or requested as ADB
    if (options.preferredInterface === "ADB" || /^[a-zA-Z0-9]{8,}$/u.test(target)) {
      const probeRes = await this.adbAdapter.probe(options);
      if (probeRes.ok) {
        const raw = probeRes.value.raw_attributes;
        const profile = createDeviceCapabilityProfile({
          name: `${String(raw.manufacturer ?? "Android")} ${String(raw.model ?? "Device")}`,
          category: "ANDROID_MOBILE",
          architecture: (raw.architecture as ArchitectureType) ?? "AARCH64",
          operating_system: "ANDROID",
          vendor: String(raw.manufacturer ?? "Android"),
          model: String(raw.model ?? "Device"),
          firmware_version: `Android ${String(raw.release ?? "")} (Patch ${String(raw.security_patch ?? "")})`,
          available_interfaces: [probeRes.value.status],
          supported_acquisition_methods: ["adb_backup", "adb_pull_partitions"],
          recommended_workflow: "android_platform_deep_audit",
        });
        return ok(profile);
      }
    }

    // 3. Check if target matches UART serial port (COM* or /dev/tty*)
    if (
      options.preferredInterface === "UART_SERIAL" ||
      target.startsWith("COM") ||
      target.includes("tty")
    ) {
      const probeRes = await this.serialAdapter.probe(options);
      if (probeRes.ok) {
        const status = probeRes.value.status;
        const isRoot = status.access_level === "ROOT_SHELL";
        const profile = createDeviceCapabilityProfile({
          name: `Serial Device at ${target}`,
          category: "EMBEDDED_LINUX",
          architecture: "ARM", // Default inferred arch for embedded Linux UART
          operating_system: "EMBEDDED_LINUX",
          vendor: "Generic Hardware",
          model: "Serial Target",
          available_interfaces: [status],
          supported_acquisition_methods: isRoot
            ? ["serial_u-boot_dump", "serial_dd_read"]
            : ["serial_boot_log_capture"],
          recommended_workflow: "embedded_serial_console_audit",
        });
        return ok(profile);
      }
    }

    // 4. Fallback Generic Device Profile
    const fallbackStatus: DeviceInterfaceStatus = {
      type: "ETHERNET",
      port_or_address: target,
      is_accessible: false,
      auth_required: true,
      auth_status: "UNTESTED",
      access_level: "NONE",
      details: "Generic unprobed network target",
    };

    const fallback = createDeviceCapabilityProfile({
      name: `Device (${target})`,
      category: "GENERIC_EMBEDDED",
      architecture: "UNKNOWN",
      operating_system: "UNKNOWN",
      available_interfaces: [fallbackStatus],
      supported_acquisition_methods: ["passive_traffic_analysis"],
      recommended_workflow: "generic_device_surface_audit",
    });

    return ok(fallback);
  }

  private discoverFromLocalFilesystem(
    dirPath: string,
  ): Result<DeviceCapabilityProfile, DeviceAdapterError> {
    let category: DeviceCategory = "EMBEDDED_LINUX";
    let os: OperatingSystemType = "EMBEDDED_LINUX";
    let arch: ArchitectureType = "ARM";
    let vendor = "Generic";
    let model = "Extracted Image";
    let firmwareVersion = "Unknown";
    const supportedMethods = ["local_filesystem_analysis"];

    // Check /etc/os-release or /etc/openwrt_release
    const etcDir = join(dirPath, "etc");
    if (existsSync(etcDir)) {
      const osReleasePath = join(etcDir, "os-release");
      const openwrtPath = join(etcDir, "openwrt_release");

      if (existsSync(openwrtPath)) {
        category = "ROUTER_NETWORK";
        vendor = "OpenWrt";
        model = "Router";
        const content = readFileSync(openwrtPath, "utf-8");
        const match = /DISTRIB_DESCRIPTION='([^']+)'/u.exec(content);
        if (match?.[1]) {
          firmwareVersion = match[1];
        }
      } else if (existsSync(osReleasePath)) {
        const content = readFileSync(osReleasePath, "utf-8");
        if (content.includes("Android")) {
          category = "ANDROID_MOBILE";
          os = "ANDROID";
        } else if (content.includes("OpenWrt") || content.includes("LEDE")) {
          category = "ROUTER_NETWORK";
          vendor = "OpenWrt";
        }
      }
    }

    // Check for build.prop (Android indicator)
    const buildProp = join(dirPath, "build.prop");
    const systemBuildProp = join(dirPath, "system", "build.prop");
    if (existsSync(buildProp) || existsSync(systemBuildProp)) {
      category = "ANDROID_MOBILE";
      os = "ANDROID";
      vendor = "Android";
      model = "AOSP Image";
    }

    const ifaceStatus: DeviceInterfaceStatus = {
      type: "LOCAL_FILESYSTEM",
      port_or_address: dirPath,
      is_accessible: true,
      auth_required: false,
      auth_status: "NONE_REQUIRED",
      access_level: "ROOT_SHELL",
      details: "Direct offline filesystem access",
    };

    const profile = createDeviceCapabilityProfile({
      name: `${vendor} ${model}`,
      category,
      architecture: arch,
      operating_system: os,
      vendor,
      model,
      firmware_version: firmwareVersion,
      available_interfaces: [ifaceStatus],
      supported_acquisition_methods: supportedMethods,
      recommended_workflow:
        category === "ANDROID_MOBILE"
          ? "android_platform_deep_audit"
          : "embedded_linux_deep_audit",
    });

    return ok(profile);
  }
}

export const defaultDeviceDiscoveryEngine = new DeviceDiscoveryEngine();

