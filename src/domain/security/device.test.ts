import { describe, it, expect } from "vitest";
import {
  createDeviceCapabilityProfile,
  createDeviceId,
  deviceCapabilityProfileSchema,
  isDeviceId,
} from "./device.js";

describe("Device Domain Model", () => {
  it("generates deterministic DeviceId and validates with isDeviceId", () => {
    const id1 = createDeviceId("ROUTER_NETWORK", "Netgear_R7000", "00:14:22:01:23:45");
    const id2 = createDeviceId("ROUTER_NETWORK", "Netgear_R7000", "00:14:22:01:23:45");
    const id3 = createDeviceId("IOT_SMART_HOME", "Camera_X1", "00:14:22:01:23:46");

    expect(id1).toBe(id2);
    expect(id1).not.toBe(id3);
    expect(isDeviceId(id1)).toBe(true);
    expect(isDeviceId("dev_1234")).toBe(false);
  });

  it("creates a frozen DeviceCapabilityProfile validated by schema", () => {
    const profile = createDeviceCapabilityProfile({
      name: "SmartHub Gateway X",
      category: "IOT_SMART_HOME",
      architecture: "ARM",
      operating_system: "EMBEDDED_LINUX",
      vendor: "Acme IoT",
      model: "SH-200",
      firmware_version: "2.1.4-build8",
      available_interfaces: [
        {
          type: "UART_SERIAL",
          port_or_address: "/dev/ttyUSB0",
          is_accessible: true,
          auth_required: false,
          auth_status: "NONE_REQUIRED",
          access_level: "ROOT_SHELL",
          details: "Unauthenticated root shell at 115200 baud",
        },
        {
          type: "ETHERNET",
          port_or_address: "192.168.1.1:80",
          is_accessible: true,
          auth_required: true,
          auth_status: "UNTESTED",
          access_level: "RESTRICTED",
        },
      ],
      supported_acquisition_methods: ["uart_boot_dump", "network_backup_download"],
      recommended_workflow: "embedded_linux_deep_audit",
      safety_level: "PASSIVE_IDENTIFICATION",
    });

    const parsed = deviceCapabilityProfileSchema.parse(profile);
    expect(parsed.id).toMatch(/^dev_[a-f0-9]{64}$/u);
    expect(parsed.category).toBe("IOT_SMART_HOME");
    expect(parsed.architecture).toBe("ARM");
    expect(parsed.available_interfaces).toHaveLength(2);
    expect(Object.isFrozen(profile)).toBe(true);
  });
});

