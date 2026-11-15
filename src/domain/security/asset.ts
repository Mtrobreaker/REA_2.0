import { z } from "zod";
import { digestCanonicalValue } from "../canonicalDigest.js";
import { nulFreeStringSchema } from "../localPath.js";

/**
 * Branded identifier for an analyzed cybersecurity asset.
 * Follows the pattern: ast_<sha256>
 */
export type AssetId = `ast_${string}`;

export const assetIdPattern = /^ast_[a-f0-9]{64}$/u;

export const assetIdSchema = z
  .string()
  .regex(assetIdPattern, "Invalid Asset ID (expected ast_<sha256>)")
  .transform((val) => val as AssetId);

export const isAssetId = (value: unknown): value is AssetId =>
  typeof value === "string" && assetIdPattern.test(value);

/**
 * Supported asset technology types across the full stack.
 */
export const ASSET_TYPES = [
  "source_repository",
  "compiled_binary",
  "firmware_image",
  "device_hardware",
  "network_service",
  "operating_system",
  "web_application",
  "cloud_configuration",
] as const;

export type AssetType = (typeof ASSET_TYPES)[number];

export const assetTypeSchema = z.enum(ASSET_TYPES);

/**
 * Environment context for an asset.
 */
export const assetEnvironmentSchema = z.strictObject({
  platform: z.string().min(1),
  os: z.string().optional(),
  host: z.string().optional(),
  isolation: z.string().optional(),
});

export type AssetEnvironment = z.infer<typeof assetEnvironmentSchema>;

/**
 * Canonical Asset Record schema.
 */
export const assetRecordSchema = z.strictObject({
  id: assetIdSchema,
  name: nulFreeStringSchema,
  type: assetTypeSchema,
  path: nulFreeStringSchema.nullable().default(null),
  digest: z
    .strictObject({
      sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    })
    .nullable()
    .default(null),
  architecture: z.string().nullable().default(null),
  version: z.string().nullable().default(null),
  environment: assetEnvironmentSchema.nullable().default(null),
  tags: z.array(z.string()).default([]),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

export type AssetRecord = z.infer<typeof assetRecordSchema>;

/**
 * Deterministically compute an AssetId based on its immutable identity fields.
 */
export const computeAssetId = (input: {
  name: string;
  type: AssetType;
  digest?: { sha256: string } | null;
  architecture?: string | null;
  version?: string | null;
}): AssetId => {
  const identityPayload = {
    name: input.name,
    type: input.type,
    digest: input.digest?.sha256 ?? null,
    architecture: input.architecture ?? null,
    version: input.version ?? null,
  };
  const hash = digestCanonicalValue(identityPayload);
  return `ast_${hash}`;
};

/**
 * In-memory map and indexing collection for assets.
 */
export class AssetMap {
  private readonly assets = new Map<AssetId, AssetRecord>();

  constructor(initialAssets: readonly AssetRecord[] = []) {
    for (const asset of initialAssets) {
      this.assets.set(asset.id, asset);
    }
  }

  public set(asset: AssetRecord): void {
    this.assets.set(asset.id, asset);
  }

  public get(id: AssetId): AssetRecord | undefined {
    return this.assets.get(id);
  }

  public has(id: AssetId): boolean {
    return this.assets.has(id);
  }

  public delete(id: AssetId): boolean {
    return this.assets.delete(id);
  }

  public get size(): number {
    return this.assets.size;
  }

  public values(): AssetRecord[] {
    return Array.from(this.assets.values());
  }

  public filterByType(type: AssetType): AssetRecord[] {
    return this.values().filter((a) => a.type === type);
  }

  public toJSON(): AssetRecord[] {
    return this.values();
  }
}
