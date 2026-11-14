import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { pbkdf2Sync, createCipheriv } from "node:crypto";
import {
  KeyringManager,
  resolveCurrentWindowsUserSid,
  DEFAULT_PBKDF2_ITERATIONS,
  type KeyringData,
  type EncryptedKeyringBundleV1,
} from "./secureKeyring.js";

describe("KeyringManager: Security & Key Lifecycle (T01, T02)", () => {
  let tempDir: string;
  const assessmentId = "asm_test_keyring_lifecycle_12345";

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-keyring-test-"));
    delete process.env.REA_ASSESSMENT_KEY;
  });

  afterEach(() => {
    delete process.env.REA_ASSESSMENT_KEY;
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  });

  it("T01: generates a 256-bit random key and enforces restricted file permissions", () => {
    const res = KeyringManager.resolveKeyring(tempDir, assessmentId);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const manager = res.value;
    const active = manager.getActiveKey();
    expect(active.version).toBe(1);
    expect(active.key_hex).toMatch(/^[0-9a-f]{64}$/); // 256 bits = 64 hex chars

    const keyringPath = join(tempDir, ".rea-keyring.json");
    expect(existsSync(keyringPath)).toBe(true);

    if (process.platform === "win32") {
      const aclOut = execFileSync("icacls", [keyringPath], { encoding: "utf8" });
      expect(aclOut).toContain("Successfully processed 1 files");
      expect(aclOut.toLowerCase()).not.toContain("everyone");
      expect(aclOut.toLowerCase()).not.toContain("builtin\\users");
    } else {
      const mode = statSync(keyringPath).mode & 0o777;
      expect(mode).toBe(0o600);
    }
  });

  it("T02: fails closed when explicit key conflicts with existing keyring", () => {
    const res1 = KeyringManager.resolveKeyring(tempDir, assessmentId);
    expect(res1.ok).toBe(true);

    const conflictingKey = "a".repeat(64);
    const res2 = KeyringManager.resolveKeyring(tempDir, assessmentId, {
      explicitKeyHex: conflictingKey,
    });
    expect(res2.ok).toBe(false);
    if (res2.ok) return;
    expect(res2.error.message).toContain("KEY_MISMATCH");
  });

  it("fails closed when REA_ASSESSMENT_KEY conflicts with existing keyring", () => {
    const res1 = KeyringManager.resolveKeyring(tempDir, assessmentId);
    expect(res1.ok).toBe(true);

    process.env.REA_ASSESSMENT_KEY = "b".repeat(64);
    const res2 = KeyringManager.resolveKeyring(tempDir, assessmentId);
    expect(res2.ok).toBe(false);
    if (res2.ok) return;
    expect(res2.error.message).toContain("KEY_CONFLICT");
  });

  it("honors REA_ASSESSMENT_KEY when creating a brand new keyring", () => {
    const envKey = "c".repeat(64);
    process.env.REA_ASSESSMENT_KEY = envKey;

    const res = KeyringManager.resolveKeyring(tempDir, assessmentId);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.value.getActiveKey().key_hex).toBe(envKey);
  });
});

describe("KeyringManager: Windows ACL & Fail-Closed Enforcement", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-acl-test-"));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it("resolves the authenticated Windows account SID and never substitutes Owner Rights (S-1-3-4)", () => {
    if (process.platform !== "win32") return;

    const sid = resolveCurrentWindowsUserSid();
    expect(sid).toMatch(/^S-1-5-(?:21-\d+-\d+-\d+-\d+|\d+)$/);
    expect(sid).not.toBe("S-1-3-4");
  });

  it("enforces restrictive permissions and verifies effective ACL on disk", () => {
    const testFile = join(tempDir, "sensitive.key");
    writeFileSync(testFile, "sensitive-key-material", "utf8");

    KeyringManager.enforceFilePermissions(testFile);

    if (process.platform === "win32") {
      const aclOut = execFileSync("icacls", [testFile], { encoding: "utf8" });
      expect(aclOut).toContain("Successfully processed 1 files");
      expect(aclOut.toLowerCase()).not.toContain("everyone");
      expect(aclOut.toLowerCase()).not.toContain("builtin\\users");
      expect(aclOut.toLowerCase()).not.toContain("authenticated users");
    } else {
      const mode = statSync(testFile).mode & 0o777;
      expect(mode).toBe(0o600);
    }
  });

  it("fails closed with an error when permissions cannot be established on non-existent file", () => {
    const nonExistent = join(tempDir, "does-not-exist.key");
    expect(() => {
      KeyringManager.enforceFilePermissions(nonExistent);
    }).toThrow(/FAIL_CLOSED/);
  });
});

describe("KeyringManager: Rotation & Encrypted Backup", () => {
  let tempDir: string;
  const assessmentId = "asm_test_keyring_rotation_12345";

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "rea-keyring-rot-test-"));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  });

  it("rotates key producing dual cryptographic proofs and preserves key history", () => {
    const res = KeyringManager.resolveKeyring(tempDir, assessmentId);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const manager = res.value;
    const v1Key = manager.getActiveKey().key_hex;

    const rotateRes = manager.rotateKey("rotation-evt-001");
    expect(rotateRes.ok).toBe(true);
    if (!rotateRes.ok) return;

    expect(rotateRes.value.old_version).toBe(1);
    expect(rotateRes.value.new_version).toBe(2);
    expect(rotateRes.value.new_key_hex).toMatch(/^[0-9a-f]{64}$/);
    expect(rotateRes.value.new_key_hex).not.toBe(v1Key);

    expect(manager.getActiveVersion()).toBe(2);
    expect(manager.getKeyForVersion(1)).toBe(v1Key);
    expect(manager.getKeyForVersion(2)).toBe(rotateRes.value.new_key_hex);

    // Verify persisted on disk
    const onDisk: KeyringData = JSON.parse(readFileSync(join(tempDir, ".rea-keyring.json"), "utf8"));
    expect(onDisk.active_version).toBe(2);
    expect(onDisk.keys.length).toBe(2);
  });

  it("exports and imports encrypted keyring bundle using PBKDF2-HMAC-SHA512 with 600,000 iterations (blueprint)", () => {
    const res = KeyringManager.resolveKeyring(tempDir, assessmentId);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const manager = res.value;
    manager.rotateKey("rot-evt-002");

    const passphrase = "correct-horse-battery-staple-passphrase";
    // Test with a smaller iteration in test to run fast, or default 600,000
    // Let's test default 600,000
    const bundle = manager.exportEncrypted(passphrase);
    expect(bundle.format).toBe("rea-encrypted-keyring-v2");
    expect(bundle.kdf).toBe("pbkdf2-hmac-sha512");
    expect(bundle.iterations).toBe(DEFAULT_PBKDF2_ITERATIONS);
    expect(bundle.iterations).toBe(600_000);
    expect(bundle.ciphertext_base64.length).toBeGreaterThan(0);

    const importPath = join(tempDir, "imported-keyring-v2.json");
    const importRes = KeyringManager.importEncrypted(bundle, passphrase, importPath);
    expect(importRes.ok).toBe(true);
    if (!importRes.ok) return;

    const imported = importRes.value;
    expect(imported.getActiveVersion()).toBe(2);
    expect(imported.getKeyForVersion(1)).toBe(manager.getKeyForVersion(1));
    expect(imported.getKeyForVersion(2)).toBe(manager.getKeyForVersion(2));

    // Wrong passphrase fails
    const wrongRes = KeyringManager.importEncrypted(bundle, "wrong-passphrase");
    expect(wrongRes.ok).toBe(false);
  });

  it("preserves backward compatibility for legacy V1 encrypted keyring backups (100,000 iterations)", () => {
    const res = KeyringManager.resolveKeyring(tempDir, assessmentId);
    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const manager = res.value;

    // Create a mock legacy V1 bundle with 100,000 iterations
    const passphrase = "legacy-v1-passphrase-test";
    const salt = Buffer.from("0123456789abcdef0123456789abcdef", "hex");
    const iv = Buffer.from("0123456789abcdef01234567", "hex");
    const iterations = 100_000;
    const key = pbkdf2Sync(passphrase, salt, iterations, 32, "sha512");
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const plaintext = Buffer.from(JSON.stringify(manager.toJSON()), "utf8");
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const legacyBundle: EncryptedKeyringBundleV1 = {
      format: "rea-encrypted-keyring-v1",
      ciphertext_base64: ciphertext.toString("base64"),
      salt_hex: salt.toString("hex"),
      iv_hex: iv.toString("hex"),
      auth_tag_hex: authTag.toString("hex"),
      iterations,
    };

    const importPath = join(tempDir, "imported-legacy-v1.json");
    const importRes = KeyringManager.importEncrypted(legacyBundle, passphrase, importPath);
    expect(importRes.ok).toBe(true);
    if (!importRes.ok) return;

    const imported = importRes.value;
    expect(imported.getAssessmentId()).toBe(manager.getAssessmentId());
    expect(imported.getActiveKey().key_hex).toBe(manager.getActiveKey().key_hex);
  });
});
