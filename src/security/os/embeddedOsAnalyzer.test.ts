import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { EmbeddedOsAnalyzer } from "./embeddedOsAnalyzer.js";

describe("EmbeddedOsAnalyzer", () => {
  let testRoot: string;

  beforeEach(() => {
    testRoot = join(tmpdir(), `rea_os_test_${Date.now()}_${Math.random().toString(36).slice(2)}`);
    mkdirSync(join(testRoot, "etc"), { recursive: true });
    mkdirSync(join(testRoot, "boot"), { recursive: true });
  });

  afterEach(() => {
    try {
      rmSync(testRoot, { recursive: true, force: true });
    } catch {
      // Cleanup
    }
  });

  it("identifies blank root password, weak MD5 hash, and backdoor UID 0 account", async () => {
    // Write /etc/passwd with root (UID 0) and backdoor user (UID 0)
    const passwdContent = `root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
backdoor_dev:x:0:0:debug account:/tmp:/bin/sh
user:x:1000:1000:user:/home/user:/bin/sh
`;
    writeFileSync(join(testRoot, "etc", "passwd"), passwdContent, "utf-8");

    // Write /etc/shadow with blank password on root and MD5 hash on user
    const shadowContent = `root::19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
backdoor_dev:!:19000:0:99999:7:::
user:$1$salt$1234567890abcdef:19000:0:99999:7:::
`;
    writeFileSync(join(testRoot, "etc", "shadow"), shadowContent, "utf-8");

    // Write kernel config missing KASLR and stack protector
    const kernelConfigContent = `# Linux kernel configuration
CONFIG_BINFMT_ELF=y
# CONFIG_RANDOMIZE_BASE is not set
# CONFIG_STACKPROTECTOR_STRONG is not set
`;
    writeFileSync(join(testRoot, "boot", "config"), kernelConfigContent, "utf-8");

    const analyzer = new EmbeddedOsAnalyzer();
    const res = await analyzer.analyze(testRoot);

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const result = res.value;
    expect(result.findings.length).toBeGreaterThanOrEqual(4);

    const names = result.findings.map((f) => f.name);
    expect(names.some((n) => n.includes("Blank Password on Privileged Account"))).toBe(true);
    expect(names.some((n) => n.includes("Backdoor UID 0 Superuser Account"))).toBe(true);
    expect(names.some((n) => n.includes("Cryptographically Weak Password Hash (MD5)"))).toBe(true);
    expect(names.some((n) => n.includes("Missing KASLR"))).toBe(true);
  });
});

