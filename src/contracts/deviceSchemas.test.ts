import { describe, it, expect } from "vitest";
import {
  deviceDiscoveryInputSchema,
  deviceAcquisitionInputSchema,
  embeddedOsAuditInputSchema,
  bootloaderAuditInputSchema,
  deviceInterfaceAuditInputSchema,
} from "./deviceSchemas.js";

describe("Device & OS Contract Schemas", () => {
  it("validates deviceDiscoveryInputSchema with default values", () => {
    const input = {
      target: "/dev/ttyUSB0",
      preferred_interface: "UART_SERIAL",
    };
    const parsed = deviceDiscoveryInputSchema.parse(input);
    expect(parsed.target).toBe("/dev/ttyUSB0");
    expect(parsed.safety_level).toBe("PASSIVE_IDENTIFICATION");
    expect(parsed.timeout_ms).toBe(10_000);
  });

  it("validates deviceAcquisitionInputSchema", () => {
    const input = {
      device_id: "dev_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      interface_type: "ADB",
      source_path_or_partition: "/system",
      destination_path: "C:/targets/system_dump",
    };
    const parsed = deviceAcquisitionInputSchema.parse(input);
    expect(parsed.verify_integrity).toBe(true);
    expect(parsed.safety_level).toBe("READ_ONLY_ACQUISITION");
  });

  it("validates embeddedOsAuditInputSchema", () => {
    const input = {
      root_path: "C:/firmware/squashfs-root",
    };
    const parsed = embeddedOsAuditInputSchema.parse(input);
    expect(parsed.check_shadow).toBe(true);
    expect(parsed.check_permissions).toBe(true);
    expect(parsed.check_kernel_config).toBe(true);
    expect(parsed.check_services).toBe(true);
  });

  it("validates bootloaderAuditInputSchema", () => {
    const input = {
      boot_image_or_env_path: "C:/firmware/u-boot-env.bin",
      bootloader_type: "U_BOOT",
    };
    const parsed = bootloaderAuditInputSchema.parse(input);
    expect(parsed.bootloader_type).toBe("U_BOOT");
  });

  it("validates deviceInterfaceAuditInputSchema", () => {
    const input = {
      target: "COM3",
      interface_type: "UART_SERIAL",
      allow_active_probing: true,
    };
    const parsed = deviceInterfaceAuditInputSchema.parse(input);
    expect(parsed.allow_active_probing).toBe(true);
  });
});

