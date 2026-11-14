import { describe, it, expect } from "vitest";
import { DeviceInterfaceAnalyzer } from "./deviceInterfaceAnalyzer.js";
import { SerialUartAdapter } from "./adapters/serialAdapter.js";
import { AdbAdapter } from "./adapters/adbAdapter.js";

describe("DeviceInterfaceAnalyzer", () => {
  it("detects unauthenticated root shell on UART console", async () => {
    const mockSerial = new SerialUartAdapter(async (port) => {
      return "Linux (none) 5.10.0-8-armmp\n# ";
    });

    const analyzer = new DeviceInterfaceAnalyzer(mockSerial, undefined);
    const res = await analyzer.analyze({
      target: "/dev/ttyUSB0",
      interface_type: "UART_SERIAL",
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.findings).toHaveLength(1);
    expect(res.value.findings[0]?.name).toContain("Unauthenticated Root Shell on UART Serial Console");
    expect(res.value.findings[0]?.severity.level).toBe("CRITICAL");
  });

  it("detects root privileges and permissive SELinux on Android ADB target", async () => {
    const mockAdb = new AdbAdapter(async (serial) => ({
      properties: {
        "ro.product.model": "DevPhone",
        "ro.debuggable": "1",
        "ro.secure": "0",
      },
      selinuxState: "Permissive",
      isRoot: true,
    }));

    const analyzer = new DeviceInterfaceAnalyzer(undefined, mockAdb);
    const res = await analyzer.analyze({
      target: "device123",
      interface_type: "ADB",
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    expect(res.value.findings).toHaveLength(2);
    const names = res.value.findings.map((f) => f.name);
    expect(names.some((n) => n.includes("Root Privileges Enabled by Default via ADB"))).toBe(true);
    expect(names.some((n) => n.includes("SELinux Enforcement Disabled (Permissive)"))).toBe(true);
  });
});

