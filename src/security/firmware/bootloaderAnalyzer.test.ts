import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { BootloaderAnalyzer } from "./bootloaderAnalyzer.js";

describe("BootloaderAnalyzer", () => {
  let testEnvFile: string;

  beforeEach(() => {
    testEnvFile = join(tmpdir(), `u_boot_env_${Date.now()}_${Math.random().toString(36).slice(2)}.txt`);
  });

  afterEach(() => {
    try {
      rmSync(testEnvFile, { force: true });
    } catch {
      // Cleanup
    }
  });

  it("detects init=/bin/sh and unverified TFTP bootcmd in U-Boot environment", async () => {
    const envContent = `baudrate=115200
bootargs=console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=squashfs init=/bin/sh
bootcmd=tftp 0x80000000 uImage; bootm 0x80000000
ipaddr=192.168.1.1
serverip=192.168.1.100
`;
    writeFileSync(testEnvFile, envContent, "utf-8");

    const analyzer = new BootloaderAnalyzer();
    const res = await analyzer.analyze(testEnvFile);

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const result = res.value;
    expect(result.findings).toHaveLength(2);

    const names = result.findings.map((f) => f.name);
    expect(names.some((n) => n.includes("Insecure Bootloader Init Argument (init=/bin/sh)"))).toBe(true);
    expect(names.some((n) => n.includes("Insecure Unauthenticated Network Boot (TFTP)"))).toBe(true);
  });
});

