import { z } from "zod";
import { digestCanonicalValue } from "../canonicalDigest.js";
import { nulFreeStringSchema } from "../localPath.js";

/**
 * Branded identifier for a discovered or analyzed hardware device.
 * Follows the pattern: dev_<sha256>
 */
export type DeviceId = `dev_${string}`;

export const deviceIdPattern = /^dev_[a-f0-9]{64}$/u;

export const deviceIdSchema = z
  .string()
  .regex(deviceIdPattern, "Invalid Device ID (expected dev_<sha256>)")
  .transform((val) => val as DeviceId);

export const isDeviceId = (value: unknown): value is DeviceId =>
  typeof value === "string" && deviceIdPattern.test(value);

/**
 * Universal Hardware Device Categories.
 */
export const DEVICE_CATEGORIES = [
  "ROUTER_NETWORK",
  "IOT_SMART_HOME",
  "ANDROID_MOBILE",
  "EMBEDDED_LINUX",
  "HOST_COMPUTER",
  "USB_DEVICE",
  "INDUSTRIAL_CONTROLLER",
  "AUTOMOTIVE_ECU",
  "GENERIC_EMBEDDED",
] as const;

export type DeviceCategory = (typeof DEVICE_CATEGORIES)[number];
export const deviceCategorySchema = z.enum(DEVICE_CATEGORIES);

/**
 * Hardware CPU/Microcontroller Architecture Types.
 */
export const ARCHITECTURE_TYPES = [
  "ARM",
  "AARCH64",
  "MIPS_EB",
  "MIPS_EL",
  "X86",
  "X86_64",
  "RISCV",
  "POWERPC",
  "XTENSA",
  "TRICORE",
  "UNKNOWN",
] as const;

export type ArchitectureType = (typeof ARCHITECTURE_TYPES)[number];
export const architectureTypeSchema = z.enum(ARCHITECTURE_TYPES);

/**
 * Operating System / Firmware Runtime Classes.
 */
export const OPERATING_SYSTEM_TYPES = [
  "EMBEDDED_LINUX",
  "ANDROID",
  "WINDOWS",
  "MACOS",
  "RTOS_FREERTOS",
  "RTOS_ZEPHYR",
  "RTOS_VXWORKS",
  "AUTOSAR",
  "BARE_METAL",
  "UNKNOWN",
] as const;

export type OperatingSystemType = (typeof OPERATING_SYSTEM_TYPES)[number];
export const operatingSystemTypeSchema = z.enum(OPERATING_SYSTEM_TYPES);

/**
 * Physical and Logical Communication Interfaces.
 */
export const PHYSICAL_INTERFACE_TYPES = [
  "USB",
  "ADB",
  "FASTBOOT",
  "UART_SERIAL",
  "JTAG_SWD",
  "SPI_FLASH",
  "ETHERNET",
  "WIFI",
  "CAN_BUS",
  "SSH",
  "LOCAL_FILESYSTEM",
] as const;

export type PhysicalInterfaceType = (typeof PHYSICAL_INTERFACE_TYPES)[number];
export const physicalInterfaceTypeSchema = z.enum(PHYSICAL_INTERFACE_TYPES);

/**
 * 4-Tier Safety & Acquisition Levels.
 */
export const ACQUISITION_SAFETY_LEVELS = [
  "PASSIVE_IDENTIFICATION",
  "READ_ONLY_ACQUISITION",
  "ACTIVE_NON_DESTRUCTIVE_PROBING",
  "INTRUSIVE_MODIFICATION",
] as const;

export type AcquisitionSafetyLevel = (typeof ACQUISITION_SAFETY_LEVELS)[number];
export const acquisitionSafetyLevelSchema = z.enum(ACQUISITION_SAFETY_LEVELS);

/**
 * Status of an available hardware interface.
 */
export const deviceInterfaceStatusSchema = z.strictObject({
  type: physicalInterfaceTypeSchema,
  port_or_address: nulFreeStringSchema,
  is_accessible: z.boolean(),
  auth_required: z.boolean(),
  auth_status: z.enum(["NONE_REQUIRED", "AUTHENTICATED", "REJECTED", "UNTESTED"]),
  access_level: z.enum(["NONE", "RESTRICTED", "SHELL_USER", "ROOT_SHELL", "FLASH_RAW"]),
  details: z.string().optional(),
});

export type DeviceInterfaceStatus = z.infer<typeof deviceInterfaceStatusSchema>;

/**
 * Canonical Device Capability Profile schema.
 */
export const deviceCapabilityProfileSchema = z.strictObject({
  id: deviceIdSchema,
  name: nulFreeStringSchema,
  category: deviceCategorySchema,
  architecture: architectureTypeSchema,
  operating_system: operatingSystemTypeSchema,
  vendor: z.string().optional(),
  model: z.string().optional(),
  firmware_version: z.string().optional(),
  available_interfaces: z.array(deviceInterfaceStatusSchema).default([]),
  supported_acquisition_methods: z.array(z.string()).default([]),
  recommended_workflow: nulFreeStringSchema,
  safety_level: acquisitionSafetyLevelSchema.default("PASSIVE_IDENTIFICATION"),
  evidence_ids: z.array(z.string()).default([]),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

export type DeviceCapabilityProfile = z.infer<typeof deviceCapabilityProfileSchema>;

/**
 * Input type for creating a DeviceCapabilityProfile.
 */
export interface DeviceCapabilityProfileInput {
  readonly id?: DeviceId;
  readonly name: string;
  readonly category: DeviceCategory;
  readonly architecture: ArchitectureType;
  readonly operating_system: OperatingSystemType;
  readonly vendor?: string;
  readonly model?: string;
  readonly firmware_version?: string;
  readonly available_interfaces?: readonly DeviceInterfaceStatus[];
  readonly supported_acquisition_methods?: readonly string[];
  readonly recommended_workflow: string;
  readonly safety_level?: AcquisitionSafetyLevel;
  readonly evidence_ids?: readonly string[];
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/**
 * Computes a deterministic DeviceId from unique identity attributes.
 */
export const createDeviceId = (
  category: DeviceCategory,
  vendorOrModel: string,
  hardwareSerialOrAddress: string,
): DeviceId => {
  const digest = digestCanonicalValue({
    category,
    vendorOrModel,
    hardwareSerialOrAddress,
  });
  return `dev_${digest}` as DeviceId;
};

/**
 * Factory for creating a frozen DeviceCapabilityProfile.
 */
export const createDeviceCapabilityProfile = (
  input: DeviceCapabilityProfileInput,
): DeviceCapabilityProfile => {
  const id =
    input.id ??
    createDeviceId(
      input.category,
      `${input.vendor ?? "unknown"}_${input.model ?? "generic"}`,
      input.name,
    );

  const profile: DeviceCapabilityProfile = {
    id,
    name: input.name,
    category: input.category,
    architecture: input.architecture,
    operating_system: input.operating_system,
    ...(input.vendor !== undefined ? { vendor: input.vendor } : {}),
    ...(input.model !== undefined ? { model: input.model } : {}),
    ...(input.firmware_version !== undefined ? { firmware_version: input.firmware_version } : {}),
    available_interfaces: [...(input.available_interfaces ?? [])],
    supported_acquisition_methods: [...(input.supported_acquisition_methods ?? [])],
    recommended_workflow: input.recommended_workflow,
    safety_level: input.safety_level ?? "PASSIVE_IDENTIFICATION",
    evidence_ids: [...(input.evidence_ids ?? [])],
    metadata: { ...(input.metadata ?? {}) },
  };

  return Object.freeze(profile);
};
