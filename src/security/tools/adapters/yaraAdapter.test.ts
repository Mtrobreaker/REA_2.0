import { describe, expect, it } from "vitest";
import { computeAssetId } from "../../../domain/security/asset.js";
import type { ProviderProcessSnapshot } from "../../../process/ProviderProcess.js";
import { parseYaraOutput, runYaraScan } from "./yaraAdapter.js";

describe("YARA Signature Adapter", () => {
  const asset = {
    id: computeAssetId({
      name: "target_binary.elf",
      type: "compiled_binary",
    }),
    name: "target_binary.elf",
    type: "compiled_binary" as const,
    path: "/bin/target_binary.elf",
    digest: null,
    architecture: "x86_64",
    version: null,
    environment: null,
    tags: [],
    metadata: {},
  };

  const sampleYaraOutput = `
apt_backdoor_beacon [malware,c2] [author="Analyst",description="Known C2 Beacon Payload",severity="CRITICAL"] /bin/target_binary.elf
0x1420:$c2_domain: evil-c2-server.com
0x18a0:$magic_header: BEACON_INIT_V2
`;

  it("parses standard YARA output with tags, metadata, and string offsets", () => {
    const matches = parseYaraOutput(sampleYaraOutput);
    expect(matches).toHaveLength(1);
    const m = matches[0];
    expect(m).toBeDefined();
    if (m) {
      expect(m.rule).toBe("apt_backdoor_beacon");
      expect(m.tags).toEqual(["malware", "c2"]);
      expect(m.meta["author"]).toBe("Analyst");
      expect(m.meta["description"]).toBe("Known C2 Beacon Payload");
      expect(m.meta["severity"]).toBe("CRITICAL");
      expect(m.target).toBe("/bin/target_binary.elf");
      expect(m.strings).toHaveLength(2);
      expect(m.strings[0]?.identifier).toBe("$c2_domain");
      expect(m.strings[0]?.offset).toBe(0x1420);
      expect(m.strings[0]?.value).toBe("evil-c2-server.com");
    }
  });

  it("runs YARA scan and normalizes output into SecurityFinding records", async () => {
    const mockRunner = async (): Promise<ProviderProcessSnapshot> => ({
      stdout: {
        text: sampleYaraOutput,
        bytes: sampleYaraOutput.length,
        observedBytes: sampleYaraOutput.length,
      },
      stderr: { text: "", bytes: 0, observedBytes: 0 },
      exitCode: 0,
      signal: null,
    });

    const result = await runYaraScan({
      targets: ["/bin/target_binary.elf"],
      ruleFiles: ["rules/malware.yar"],
      asset,
      commandRunner: mockRunner,
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.findings).toHaveLength(1);
      const finding = result.value.findings[0];
      expect(finding).toBeDefined();
      if (finding) {
        expect(finding.name).toBe("Known C2 Beacon Payload");
        expect(finding.severity.level).toBe("CRITICAL");
        expect(finding.location.file).toBe("/bin/target_binary.elf");
        expect(finding.location.offset).toBe(0x1420);
        expect(finding.verification_status).toBe("CANDIDATE");
        expect(finding.confidence.level).toBe("CONFIRMED");
      }
    }
  });

  it("handles missing YARA executable (YARA_NOT_INSTALLED)", async () => {
    const mockRunner = async (): Promise<ProviderProcessSnapshot> => {
      throw new Error("spawn yara ENOENT");
    };

    const result = await runYaraScan({
      targets: ["/bin/target_binary.elf"],
      ruleFiles: ["rules/malware.yar"],
      asset,
      commandRunner: mockRunner,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("YARA_NOT_INSTALLED");
    }
  });

  it("requires at least one rule file", async () => {
    const result = await runYaraScan({
      targets: ["/bin/target_binary.elf"],
      ruleFiles: [],
      asset,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("YARA_RULE_ERROR");
    }
  });
});
