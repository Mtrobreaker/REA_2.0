import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultFirmwareDeepAnalyzer } from "./firmwareDeepAnalyzer.js";

describe("FirmwareDeepAnalyzer", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-firmware-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("detects ARM architecture, SquashFS partition, and embedded secrets", async () => {
    const fwPath = join(tempDir, "test_firmware.bin");

    // Build mock firmware image with:
    // 1. Fake ELF header for ARM (machine 0x28, little endian)
    const elfHeader = Buffer.alloc(52);
    elfHeader[0] = 0x7f;
    elfHeader[1] = 0x45;
    elfHeader[2] = 0x4c;
    elfHeader[3] = 0x46;
    elfHeader[4] = 1; // 32-bit
    elfHeader[5] = 1; // little-endian
    elfHeader.writeUInt16LE(0x28, 18); // ARM machine type

    // 2. SquashFS partition magic 'hsqs'
    const squashfsHeader = Buffer.from([0x68, 0x73, 0x71, 0x73]);

    // 3. Embedded PEM private key
    const pemKey = Buffer.from(
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0mockkey...\n-----END RSA PRIVATE KEY-----\n",
      "latin1",
    );

    // 4. Shadow file with MD5 crypt hash
    const shadowData = Buffer.from(
      "root:$1$abc$1234567890abcdef123456:19000:0:99999:7:::\n",
      "latin1",
    );

    // 5. Insecure bootargs
    const bootargs = Buffer.from("console=ttyS0,115200 init=/bin/sh root=/dev/mtdblock0\n", "latin1");

    // 6. Telnetd service
    const initScript = Buffer.from("#!/bin/sh\n/usr/sbin/telnetd -l /bin/sh\n", "latin1");

    const fullFirmware = Buffer.concat([
      elfHeader,
      Buffer.alloc(100),
      squashfsHeader,
      Buffer.alloc(100),
      pemKey,
      Buffer.alloc(100),
      shadowData,
      Buffer.alloc(100),
      bootargs,
      Buffer.alloc(100),
      initScript,
    ]);

    await writeFile(fwPath, fullFirmware);

    const result = await defaultFirmwareDeepAnalyzer.analyze(fwPath);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const data = result.value;
    expect(data.architecture).toBe("ARM");
    expect(data.endianness).toBe("little");
    expect(data.detected_partitions.length).toBeGreaterThanOrEqual(1);
    expect(data.detected_partitions[0]!.type).toBe("SquashFS");

    // Check findings
    expect(data.findings.length).toBeGreaterThanOrEqual(4);

    // 1. RSA Private key
    const rsaFinding = data.findings.find((f) =>
      f.name.includes("Embedded Cryptographic RSA Private Key"),
    );
    expect(rsaFinding).toBeDefined();
    expect(rsaFinding!.severity.level).toBe("CRITICAL");

    // 2. Hardcoded shadow hash
    const shadowFinding = data.findings.find((f) =>
      f.name.includes("Hardcoded Root Password Hash"),
    );
    expect(shadowFinding).toBeDefined();
    expect(shadowFinding!.severity.level).toBe("CRITICAL");

    // 3. Init shell bypass
    const initFinding = data.findings.find((f) =>
      f.name.includes("Insecure Bootloader Arguments"),
    );
    expect(initFinding).toBeDefined();
    expect(initFinding!.severity.level).toBe("HIGH");

    // 4. Telnetd
    const telnetFinding = data.findings.find((f) =>
      f.name.includes("Unencrypted Telnet Daemon Enabled"),
    );
    expect(telnetFinding).toBeDefined();
    expect(telnetFinding!.severity.level).toBe("HIGH");

    // Risk score should be high
    expect(data.risk_score).toBeGreaterThanOrEqual(80);
    expect(data.summary).toContain("ARM");
  });

  it("returns error for missing firmware file", async () => {
    const result = await defaultFirmwareDeepAnalyzer.analyze(
      join(tempDir, "non_existent_firmware.bin"),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("UNREADABLE_FIRMWARE");
    }
  });
});

