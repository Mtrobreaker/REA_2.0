import { describe, expect, it } from "vitest";
import {
  AssetMap,
  assetRecordSchema,
  computeAssetId,
  isAssetId,
} from "./asset.js";

describe("Asset Security Domain", () => {
  const baseAsset = {
    name: "gateway_firmware.bin",
    type: "firmware_image" as const,
    digest: {
      sha256:
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    architecture: "mips",
    version: "1.0.4",
  };

  it("computes deterministic asset IDs", () => {
    const id1 = computeAssetId(baseAsset);
    const id2 = computeAssetId(baseAsset);

    expect(id1).toBe(id2);
    expect(isAssetId(id1)).toBe(true);
    expect(id1).toMatch(/^ast_[a-f0-9]{64}$/u);
  });

  it("produces distinct IDs when identity attributes vary", () => {
    const id1 = computeAssetId(baseAsset);
    const id2 = computeAssetId({
      ...baseAsset,
      version: "1.0.5",
    });
    const id3 = computeAssetId({
      ...baseAsset,
      architecture: "arm",
    });

    expect(id1).not.toBe(id2);
    expect(id1).not.toBe(id3);
  });

  it("validates and parses AssetRecord schema", () => {
    const id = computeAssetId(baseAsset);
    const record = assetRecordSchema.parse({
      id,
      name: baseAsset.name,
      type: baseAsset.type,
      path: "/var/firmware/gateway_firmware.bin",
      digest: baseAsset.digest,
      architecture: baseAsset.architecture,
      version: baseAsset.version,
      environment: {
        platform: "embedded_linux",
        os: "Linux 4.1.2",
      },
      tags: ["iot", "mips", "gateway"],
      metadata: { vendor: "Acme" },
    });

    expect(record.id).toBe(id);
    expect(record.tags).toEqual(["iot", "mips", "gateway"]);
  });

  it("manages assets in AssetMap collection", () => {
    const id1 = computeAssetId(baseAsset);
    const id2 = computeAssetId({
      name: "auth_service",
      type: "network_service",
    });

    const asset1 = assetRecordSchema.parse({
      id: id1,
      name: baseAsset.name,
      type: baseAsset.type,
    });

    const asset2 = assetRecordSchema.parse({
      id: id2,
      name: "auth_service",
      type: "network_service",
    });

    const map = new AssetMap([asset1]);
    expect(map.size).toBe(1);
    expect(map.has(id1)).toBe(true);
    expect(map.get(id1)).toEqual(asset1);

    map.set(asset2);
    expect(map.size).toBe(2);
    expect(map.filterByType("network_service")).toEqual([asset2]);
    expect(map.filterByType("firmware_image")).toEqual([asset1]);

    expect(map.delete(id1)).toBe(true);
    expect(map.size).toBe(1);
    expect(map.has(id1)).toBe(false);
  });
});

