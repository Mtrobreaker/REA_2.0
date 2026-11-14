import { z } from "zod";
import { localPathStringSchema, nulFreeStringSchema } from "../domain/localPath.js";
import {
  acquisitionSafetyLevelSchema,
  deviceCategorySchema,
  physicalInterfaceTypeSchema,
} from "../domain/security/device.js";

/**
 * Input schema to probe and discover a connected or target hardware device.
 */
export const deviceDiscoveryInputSchema = z.strictObject({
  target: nulFreeStringSchema.describe(
    "Target address, COM/TTY port, USB device ID, or local filesystem image path",
  ),
  preferred_interface: physicalInterfaceTypeSchema.optional().describe(
    "Preferred physical/logical interface to prioritize (e.g. UART_SERIAL, ADB, USB)",
  ),
  safety_level: acquisitionSafetyLevelSchema
    .default("PASSIVE_IDENTIFICATION")
    .describe("Permitted safety level for discovery"),
  baud_rates: z
    .array(z.number().int().positive())
    .optional()
    .describe("Specific baud rates to test when probing UART serial interfaces"),
  timeout_ms: z
    .number()
    .int()
    .positive()
    .default(10_000)
    .describe("Probing timeout in milliseconds"),
});

export type DeviceDiscoveryInput = z.infer<typeof deviceDiscoveryInputSchema>;

/**
 * Input schema for read-only firmware or software component acquisition.
 */
export const deviceAcquisitionInputSchema = z.strictObject({
  device_id: nulFreeStringSchema.describe("Target Device ID (dev_<sha256>)"),
  interface_type: physicalInterfaceTypeSchema.describe("Interface to use for acquisition"),
  source_path_or_partition: nulFreeStringSchema.describe(
    "Source filesystem path, partition name, or SPI flash memory offset",
  ),
  destination_path: localPathStringSchema.describe(
    "Local destination directory or file path to store acquired image",
  ),
  verify_integrity: z
    .boolean()
    .default(true)
    .describe("Whether to compute and verify SHA-256 digests across multiple reads"),
  safety_level: acquisitionSafetyLevelSchema
    .default("READ_ONLY_ACQUISITION")
    .describe("Safety level (cannot exceed authorized scope)"),
});

export type DeviceAcquisitionInput = z.infer<typeof deviceAcquisitionInputSchema>;

/**
 * Input schema to audit embedded operating system and configuration files.
 */
export const embeddedOsAuditInputSchema = z.strictObject({
  root_path: localPathStringSchema.describe(
    "Extracted root filesystem directory path or mounted device path",
  ),
  check_shadow: z
    .boolean()
    .default(true)
    .describe("Audit /etc/shadow and /etc/passwd for weak/blank passwords and root accounts"),
  check_permissions: z
    .boolean()
    .default(true)
    .describe("Audit SUID/SGID binaries and world-writable sensitive paths"),
  check_kernel_config: z
    .boolean()
    .default(true)
    .describe("Audit Linux kernel configuration (e.g. /proc/config.gz, boot/config*) for hardening"),
  check_services: z
    .boolean()
    .default(true)
    .describe("Audit active daemons and init scripts (SysV, systemd, OpenWrt procd, Android init.rc)"),
});

export type EmbeddedOsAuditInput = z.infer<typeof embeddedOsAuditInputSchema>;

/**
 * Input schema to audit bootloader security (U-Boot, GRUB, Little Kernel).
 */
export const bootloaderAuditInputSchema = z.strictObject({
  boot_image_or_env_path: localPathStringSchema.describe(
    "Path to U-Boot environment file, boot script, or binary bootloader image",
  ),
  bootloader_type: z
    .enum(["U_BOOT", "GRUB", "LITTLE_KERNEL", "COREBOOT", "UEFI", "GENERIC"])
    .default("U_BOOT")
    .describe("Bootloader architecture class"),
});

export type BootloaderAuditInput = z.infer<typeof bootloaderAuditInputSchema>;

/**
 * Input schema for device interface security auditing (UART, JTAG, ADB).
 */
export const deviceInterfaceAuditInputSchema = z.strictObject({
  target: nulFreeStringSchema.describe(
    "Target port, USB device identifier, ADB device serial, or serial port",
  ),
  interface_type: physicalInterfaceTypeSchema.describe("Interface under audit"),
  allow_active_probing: z
    .boolean()
    .default(false)
    .describe("Explicit authorization flag to send non-destructive test input"),
});

export type DeviceInterfaceAuditInput = z.infer<typeof deviceInterfaceAuditInputSchema>;

