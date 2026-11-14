import { describe, it, expect } from "vitest";
import { DeviceDiscoveryEngine } from "./discovery.js";
import { SerialUartAdapter } from "./adapters/serialAdapter.js";
import { AdbAdapter } from "./adapters/adbAdapter.js";

describe("DeviceDiscoveryEngine", () => {
  it("discovers an Android device via simulated ADB adapter", async () => {
    const mockAdb = new AdbAdapter(async (serial) => ({
      properties: {
        "ro.product.model": "Pixel 7 Pro",
        "ro.product.manufacturer": "Google",
        "ro.product.cpu.abi": "arm64-v8a",
        "ro.build.version.release": "14",
        "ro.build.version.security_patch": "2024-05-01",
      },
      selinuxState: "Enforcing",
      isRoot: false,
    }));

    const engine = new DeviceDiscoveryEngine(undefined, mockAdb);
    const res = await engine.discover({
      target: "HT74A0200123",
      preferredInterface: "ADB",
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const profile = res.value;
    expect(profile.category).toBe("ANDROID_MOBILE");
    expect(profile.architecture).toBe("AARCH64");
    expect(profile.vendor).toBe("Google");
    expect(profile.model).toBe("Pixel 7 Pro");
    expect(profile.available_interfaces[0]?.access_level).toBe("SHELL_USER");
  });

  it("discovers an embedded device via simulated UART adapter with root shell", async () => {
    const mockSerial = new SerialUartAdapter(async (port, baud) => {
      return "BusyBox v1.33.1 (2022-01-15 08:32:10 UTC) built-in shell (ash)\n# ";
    });

    const engine = new DeviceDiscoveryEngine(mockSerial, undefined);
    const res = await engine.discover({
      target: "/dev/ttyUSB0",
      preferredInterface: "UART_SERIAL",
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const profile = res.value;
    expect(profile.category).toBe("EMBEDDED_LINUX");
    expect(profile.available_interfaces[0]?.access_level).toBe("ROOT_SHELL");
    expect(profile.supported_acquisition_methods).toContain("serial_u-boot_dump");
  });
});

