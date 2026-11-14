import { z } from "zod";
import { assetIdSchema, type AssetId } from "./asset.js";

/**
 * Protocols and physical interfaces for attack surface entry points.
 */
export const ENTRY_POINT_PROTOCOLS = [
  "http",
  "https",
  "tcp",
  "udp",
  "grpc",
  "websocket",
  "file",
  "ipc",
  "jtag",
  "uart",
  "spi",
  "i2c",
  "can",
  "unknown",
] as const;

export type EntryPointProtocol = (typeof ENTRY_POINT_PROTOCOLS)[number];

export const entryPointProtocolSchema = z.enum(ENTRY_POINT_PROTOCOLS);

/**
 * Entry point representing an exposed interface, port, function, or pin.
 */
export const entryPointSchema = z.strictObject({
  id: z.string().min(1),
  name: z.string().min(1),
  protocol: entryPointProtocolSchema,
  target_port: z.number().int().min(1).max(65535).nullable().default(null),
  interface: z.string().nullable().default(null),
  exported_symbol: z.string().nullable().default(null),
  authentication_required: z.boolean().default(false),
  description: z.string().default(""),
});

export type EntryPoint = z.infer<typeof entryPointSchema>;

/**
 * Trust boundary representing crossing between privilege domains.
 */
export const trustBoundarySchema = z.strictObject({
  id: z.string().min(1),
  source_domain: z.string().min(1),
  target_domain: z.string().min(1),
  elevation_risk: z.boolean().default(false),
  description: z.string().default(""),
});

export type TrustBoundary = z.infer<typeof trustBoundarySchema>;

/**
 * Summary metrics of an attack surface.
 */
export const attackSurfaceMetricsSchema = z.strictObject({
  total_entry_points: z.number().int().nonnegative(),
  unauthenticated_entry_points: z.number().int().nonnegative(),
  network_exposed_entry_points: z.number().int().nonnegative(),
  hardware_interfaces: z.number().int().nonnegative(),
});

export type AttackSurfaceMetrics = z.infer<typeof attackSurfaceMetricsSchema>;

/**
 * Complete attack surface map for an asset.
 */
export const attackSurfaceMapSchema = z.strictObject({
  asset_id: assetIdSchema,
  entry_points: z.array(entryPointSchema).default([]),
  trust_boundaries: z.array(trustBoundarySchema).default([]),
  exposed_services: z.array(z.string()).default([]),
  metrics: attackSurfaceMetricsSchema,
});

export type AttackSurfaceMap = z.infer<typeof attackSurfaceMapSchema>;

/**
 * Calculate attack surface metrics for a set of entry points.
 */
export const calculateAttackSurfaceMetrics = (
  entryPoints: readonly EntryPoint[],
): AttackSurfaceMetrics => {
  let unauthenticated = 0;
  let networkExposed = 0;
  let hardwareInterfaces = 0;

  for (const ep of entryPoints) {
    if (!ep.authentication_required) {
      unauthenticated++;
    }
    if (
      ep.protocol === "http" ||
      ep.protocol === "https" ||
      ep.protocol === "tcp" ||
      ep.protocol === "udp" ||
      ep.protocol === "grpc" ||
      ep.protocol === "websocket"
    ) {
      networkExposed++;
    }
    if (
      ep.protocol === "jtag" ||
      ep.protocol === "uart" ||
      ep.protocol === "spi" ||
      ep.protocol === "i2c" ||
      ep.protocol === "can"
    ) {
      hardwareInterfaces++;
    }
  }

  return {
    total_entry_points: entryPoints.length,
    unauthenticated_entry_points: unauthenticated,
    network_exposed_entry_points: networkExposed,
    hardware_interfaces: hardwareInterfaces,
  };
};

/**
 * Factory to create an AttackSurfaceMap with automatic metrics derivation.
 */
export const createAttackSurfaceMap = (input: {
  asset_id: AssetId;
  entry_points?: EntryPoint[];
  trust_boundaries?: TrustBoundary[];
  exposed_services?: string[];
}): AttackSurfaceMap => {
  const entryPoints = input.entry_points ?? [];
  const trustBoundaries = input.trust_boundaries ?? [];
  const exposedServices = input.exposed_services ?? [];
  const metrics = calculateAttackSurfaceMetrics(entryPoints);

  return {
    asset_id: input.asset_id,
    entry_points: entryPoints,
    trust_boundaries: trustBoundaries,
    exposed_services: exposedServices,
    metrics,
  };
};

