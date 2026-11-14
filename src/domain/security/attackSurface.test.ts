import { describe, expect, it } from "vitest";
import { computeAssetId } from "./asset.js";
import {
  attackSurfaceMapSchema,
  calculateAttackSurfaceMetrics,
  createAttackSurfaceMap,
  type EntryPoint,
} from "./attackSurface.js";

describe("Attack Surface Domain", () => {
  const assetId = computeAssetId({
    name: "iot_router",
    type: "firmware_image",
  });

  const entryPoints: EntryPoint[] = [
    {
      id: "ep_1",
      name: "HTTP Web Management",
      protocol: "http",
      target_port: 80,
      interface: "eth0",
      exported_symbol: null,
      authentication_required: false,
      description: "Default unauthenticated web setup wizard",
    },
    {
      id: "ep_2",
      name: "SSH Administration",
      protocol: "tcp",
      target_port: 22,
      interface: "eth0",
      exported_symbol: null,
      authentication_required: true,
      description: "Dropbear SSH daemon",
    },
    {
      id: "ep_3",
      name: "JTAG Debug Header",
      protocol: "jtag",
      target_port: null,
      interface: "header_j1",
      exported_symbol: null,
      authentication_required: false,
      description: "Hardware 10-pin JTAG header exposed on PCB",
    },
  ];

  it("calculates attack surface metrics correctly", () => {
    const metrics = calculateAttackSurfaceMetrics(entryPoints);
    expect(metrics.total_entry_points).toBe(3);
    expect(metrics.unauthenticated_entry_points).toBe(2);
    expect(metrics.network_exposed_entry_points).toBe(2);
    expect(metrics.hardware_interfaces).toBe(1);
  });

  it("creates AttackSurfaceMap with automatic metrics", () => {
    const map = createAttackSurfaceMap({
      asset_id: assetId,
      entry_points: entryPoints,
      trust_boundaries: [
        {
          id: "tb_1",
          source_domain: "unauthenticated_wan",
          target_domain: "root_daemon",
          elevation_risk: true,
          description: "WAN HTTP traffic routed directly to root httpd process",
        },
      ],
      exposed_services: ["lighttpd/1.4.35", "dropbear/2019.78"],
    });

    expect(map.asset_id).toBe(assetId);
    expect(map.entry_points).toHaveLength(3);
    expect(map.trust_boundaries).toHaveLength(1);
    expect(map.metrics.total_entry_points).toBe(3);
    expect(map.metrics.unauthenticated_entry_points).toBe(2);

    const parsed = attackSurfaceMapSchema.parse(map);
    expect(parsed.asset_id).toBe(assetId);
  });
});

