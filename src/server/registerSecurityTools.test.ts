import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { registerSecurityTools } from "./registerSecurityTools.js";

describe("registerSecurityTools (MCP Server Integration)", () => {
  let tempDir: string;
  let tools: Map<string, { config: any; callback: any }>;
  const logger = pino({ enabled: false });

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "rea-mcp-sec-test-"));
    tools = new Map<string, { config: any; callback: any }>();

    const mockServer = {
      registerTool: (name: string, config: any, callback: any) => {
        tools.set(name, { config, callback });
      },
    } as unknown as EvidenceMcpServer;

    registerSecurityTools(mockServer, logger);
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("registers all cybersecurity MCP tools", () => {
    const expected = [
      "security_scan",
      "security_cvss",
      "security_report",
      "security_multiagent_assess",
      "security_firmware_inspect",
      "security_device_inspect",
      "security_os_audit",
    ];

    for (const name of expected) {
      expect(tools.has(name)).toBe(true);
      const tool = tools.get(name)!;
      expect(tool.config.description).toBeDefined();
      expect(tool.config.inputSchema).toBeDefined();
    }
  });

  it("executes security_device_inspect tool handler on serial target", async () => {
    const ttyPath = join(tempDir, "serial.tty");
    await writeFile(ttyPath, "BusyBox v1.33.1 (ash)\n# ", "utf8");

    const tool = tools.get("security_device_inspect")!;
    const response = await tool.callback({
      target: ttyPath,
      interface_type: "UART_SERIAL",
    });

    expect(response.content).toHaveLength(1);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.target).toBe(ttyPath);
    expect(parsed.findings.length).toBeGreaterThanOrEqual(1);
    expect(parsed.findings[0].name).toContain(
      "Unauthenticated Root Shell on UART Serial Console",
    );
  });

  it("executes security_os_audit tool handler on extracted filesystem", async () => {
    const rootPath = join(tempDir, "rootfs");
    const etcPath = join(rootPath, "etc");
    await mkdir(etcPath, { recursive: true });
    await writeFile(
      join(etcPath, "passwd"),
      "root:x:0:0:root:/root:/bin/sh\n",
      "utf8",
    );
    await writeFile(
      join(etcPath, "shadow"),
      "root::19000:0:99999:7:::\n",
      "utf8",
    );

    const tool = tools.get("security_os_audit")!;
    const response = await tool.callback({
      path: rootPath,
    });

    expect(response.content).toHaveLength(1);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.root_path).toBe(rootPath);
    expect(parsed.findings.length).toBeGreaterThanOrEqual(1);
  });

  it("executes security_cvss tool handler and returns CVSS score", async () => {
    const tool = tools.get("security_cvss")!;
    const response = await tool.callback({
      vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    });

    expect(response.content).toHaveLength(1);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.score).toBe(9.8);
    expect(parsed.severity).toBe("CRITICAL");
  });

  it("executes security_firmware_inspect tool handler on firmware binary", async () => {
    const fwPath = join(tempDir, "test.bin");
    const fakeKey =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0mock...\n-----END RSA PRIVATE KEY-----\n";
    await writeFile(fwPath, Buffer.from(fakeKey, "latin1"));

    const tool = tools.get("security_firmware_inspect")!;
    const response = await tool.callback({
      path: fwPath,
    });

    expect(response.content).toHaveLength(1);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.target_path).toBe(fwPath);
    expect(parsed.findings.length).toBeGreaterThanOrEqual(1);
    expect(parsed.risk_score).toBeGreaterThan(0);
  });

  it("executes security_multiagent_assess tool handler across targets", async () => {
    const tool = tools.get("security_multiagent_assess")!;
    const response = await tool.callback({
      target_path: tempDir,
      title: "MCP Multi-Agent Assessment",
      authorized_by: "Security Operations",
      authorization_reference: "MCP-TEST-001",
      depth: "surface",
      format: "markdown",
    });

    expect(response.content).toHaveLength(1);
    expect(response.content[0].text).toContain("Security Assessment Report");
    expect(response.content[0].text).toContain("MCP Multi-Agent Assessment");
  });

  it("executes security_scan tool handler", async () => {
    const tool = tools.get("security_scan")!;
    const response = await tool.callback({
      path: tempDir,
      authorized_by: "Lead Auditor",
      authorization_reference: "AUDIT-001",
      depth: "surface",
      format: "json",
    });

    expect(response.content).toHaveLength(1);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.assessment_id).toMatch(/^asm_[a-f0-9]{64}$/);
    expect(parsed.phase).toBe("completed");
  });

  it("executes security_report tool handler", async () => {
    const tool = tools.get("security_report")!;
    const response = await tool.callback({
      assessment_id:
        "asm_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      format: "markdown",
      include_remediation_diffs: true,
    });

    expect(response.content).toHaveLength(1);
    expect(response.content[0].text).toContain("Security Assessment Report");
  });
});
