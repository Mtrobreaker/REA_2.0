import { randomBytes, createHmac, pbkdf2Sync, createCipheriv, createDecipheriv } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, chmodSync, statSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { ok, err, type Result } from "../../domain/result.js";

export interface KeyringKeyEntry {
  readonly version: number;
  readonly key_hex: string;
  readonly created_at: string;
  readonly rotation_event_id?: string | undefined;
}

export interface KeyringData {
  readonly assessment_id: string;
  readonly active_version: number;
  readonly keys: ReadonlyArray<KeyringKeyEntry>;
}

export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
export const LEGACY_PBKDF2_ITERATIONS = 100_000;

export interface EncryptedKeyringBundleV1 {
  readonly format: "rea-encrypted-keyring-v1";
  readonly ciphertext_base64: string;
  readonly salt_hex: string;
  readonly iv_hex: string;
  readonly auth_tag_hex: string;
  readonly iterations: number;
}

export interface EncryptedKeyringBundleV2 {
  readonly format: "rea-encrypted-keyring-v2";
  readonly kdf: "pbkdf2-hmac-sha512";
  readonly ciphertext_base64: string;
  readonly salt_hex: string;
  readonly iv_hex: string;
  readonly auth_tag_hex: string;
  readonly iterations: number;
}

export type EncryptedKeyringBundle = EncryptedKeyringBundleV1 | EncryptedKeyringBundleV2;

export interface KeyRotationProof {
  readonly old_version: number;
  readonly new_version: number;
  readonly new_key_hex: string;
  readonly rotation_event_id: string;
  readonly proof_old_key: string;
  readonly proof_new_key: string;
}

/**
 * Resolves the current Windows user's Account SID.
 * Disallows generic or unverified Owner Rights SID (S-1-3-4).
 * Fails closed if resolution cannot be authenticated.
 */
export function resolveCurrentWindowsUserSid(): string {
  try {
    const raw = execFileSync("whoami", ["/user", "/fo", "csv", "/nh"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    }).trim();

    const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
    for (const line of lines) {
      const match = line.match(/["'](S-1-[0-9-]+)["']/);
      if (match && match[1]) {
        const sid = match[1];
        if (sid === "S-1-3-4") {
          throw new Error("REJECTED_SID: Owner Rights SID (S-1-3-4) is not an authenticated account SID");
        }
        if (/^S-1-5-(?:21-\d+-\d+-\d+-\d+|\d+)$/.test(sid)) {
          return sid;
        }
      }
    }
  } catch (err: any) {
    if (err?.message?.includes("REJECTED_SID")) {
      throw err;
    }
  }

  try {
    const raw = execFileSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
      {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      },
    ).trim();

    if (raw === "S-1-3-4") {
      throw new Error("REJECTED_SID: Owner Rights SID (S-1-3-4) is not an authenticated account SID");
    }
    if (/^S-1-5-(?:21-\d+-\d+-\d+-\d+|\d+)$/.test(raw)) {
      return raw;
    }
  } catch (err: any) {
    if (err?.message?.includes("REJECTED_SID")) {
      throw err;
    }
  }

  throw new Error("FAIL_CLOSED: Unable to resolve current Windows user account SID; refusing to apply insecure fallback");
}

export class KeyringManager {
  private data: KeyringData;
  private readonly keyringPath?: string | undefined;

  constructor(data: KeyringData, keyringPath?: string | undefined) {
    this.data = data;
    this.keyringPath = keyringPath;
  }

  public getAssessmentId(): string {
    return this.data.assessment_id;
  }

  public getActiveVersion(): number {
    return this.data.active_version;
  }

  public getActiveKey(): { version: number; key_hex: string } {
    const entry = this.data.keys.find((k) => k.version === this.data.active_version);
    if (!entry) {
      throw new Error(`Corrupted keyring: active version ${this.data.active_version} not found in keys`);
    }
    return { version: entry.version, key_hex: entry.key_hex };
  }

  public getKeyForVersion(version: number): string | undefined {
    return this.data.keys.find((k) => k.version === version)?.key_hex;
  }

  public getAllKeys(): Map<number, string> {
    const map = new Map<number, string>();
    for (const entry of this.data.keys) {
      map.set(entry.version, entry.key_hex);
    }
    return map;
  }

  public getKeyResolver(): (version: number) => string | undefined {
    return (v: number) => this.getKeyForVersion(v);
  }

  public toJSON(): KeyringData {
    return {
      assessment_id: this.data.assessment_id,
      active_version: this.data.active_version,
      keys: [...this.data.keys],
    };
  }

  /**
   * Rotates the active key to a newly generated 256-bit random key.
   * Generates dual cryptographic proofs:
   * 1. proof_old_key: HMAC(old_key, challenge) authenticating rotation from old authority
   * 2. proof_new_key: HMAC(new_key, confirmation) proving possession of new authority
   */
  public rotateKey(rotationEventId: string): Result<KeyRotationProof, Error> {
    try {
      const active = this.getActiveKey();
      const newVersion = active.version + 1;
      const newKeyHex = randomBytes(32).toString("hex");

      const oldChallenge = `REA_KEY_ROTATION:${rotationEventId}:${newVersion}`;
      const proofOldKey = createHmac("sha256", active.key_hex).update(oldChallenge, "utf8").digest("hex");

      const newChallenge = `REA_KEY_ROTATION_CONFIRMATION:${rotationEventId}:${active.version}`;
      const proofNewKey = createHmac("sha256", newKeyHex).update(newChallenge, "utf8").digest("hex");

      const newEntry: KeyringKeyEntry = {
        version: newVersion,
        key_hex: newKeyHex,
        created_at: new Date().toISOString(),
        rotation_event_id: rotationEventId,
      };

      this.data = {
        assessment_id: this.data.assessment_id,
        active_version: newVersion,
        keys: [...this.data.keys, newEntry],
      };

      if (this.keyringPath) {
        this.saveToFile(this.keyringPath);
      }

      return ok({
        old_version: active.version,
        new_version: newVersion,
        new_key_hex: newKeyHex,
        rotation_event_id: rotationEventId,
        proof_old_key: proofOldKey,
        proof_new_key: proofNewKey,
      });
    } catch (cause) {
      return err(cause instanceof Error ? cause : new Error(String(cause)));
    }
  }

  public saveToFile(targetPath: string): void {
    const serialized = JSON.stringify(this.toJSON(), null, 2);
    writeFileSync(targetPath, serialized, "utf8");
    KeyringManager.enforceFilePermissions(targetPath);
  }

  /**
   * Exports an encrypted keyring bundle using PBKDF2-HMAC-SHA512 (600,000 iterations default)
   * and AES-256-GCM authenticated encryption.
   */
  public exportEncrypted(
    passphrase: string,
    options?: { readonly iterations?: number | undefined },
  ): EncryptedKeyringBundleV2 {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const iterations = options?.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
    const key = pbkdf2Sync(passphrase, salt, iterations, 32, "sha512");

    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const plaintext = Buffer.from(JSON.stringify(this.toJSON()), "utf8");
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      format: "rea-encrypted-keyring-v2",
      kdf: "pbkdf2-hmac-sha512",
      ciphertext_base64: ciphertext.toString("base64"),
      salt_hex: salt.toString("hex"),
      iv_hex: iv.toString("hex"),
      auth_tag_hex: authTag.toString("hex"),
      iterations,
    };
  }

  /**
   * Imports and restores an encrypted keyring bundle.
   * Backward compatible with both V1 (100k iterations) and V2 (600k iterations) bundles.
   */
  public static importEncrypted(
    bundle: EncryptedKeyringBundle,
    passphrase: string,
    keyringPath?: string | undefined,
  ): Result<KeyringManager, Error> {
    try {
      if (bundle.format !== "rea-encrypted-keyring-v1" && bundle.format !== "rea-encrypted-keyring-v2") {
        return err(new Error(`Unsupported encrypted keyring format: ${(bundle as any).format}`));
      }

      if (bundle.format === "rea-encrypted-keyring-v2" && bundle.kdf !== "pbkdf2-hmac-sha512") {
        return err(new Error(`Unsupported KDF algorithm: ${(bundle as any).kdf}`));
      }

      const salt = Buffer.from(bundle.salt_hex, "hex");
      const iv = Buffer.from(bundle.iv_hex, "hex");
      const authTag = Buffer.from(bundle.auth_tag_hex, "hex");
      const ciphertext = Buffer.from(bundle.ciphertext_base64, "base64");

      const key = pbkdf2Sync(passphrase, salt, bundle.iterations, 32, "sha512");
      const decipher = createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(authTag);

      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      const data = JSON.parse(decrypted.toString("utf8")) as KeyringData;

      const manager = new KeyringManager(data, keyringPath);
      if (keyringPath) {
        manager.saveToFile(keyringPath);
      }
      return ok(manager);
    } catch (cause) {
      return err(new Error(`Failed to decrypt keyring: ${cause instanceof Error ? cause.message : String(cause)}`));
    }
  }

  /**
   * Applies restrictive file permissions and verifies effective access.
   * Fails closed if permissions cannot be established or verified.
   */
  public static enforceFilePermissions(filePath: string): void {
    if (process.platform === "win32") {
      const sid = resolveCurrentWindowsUserSid();

      // 1. Apply restrictive ACL: remove inheritance and grant Full Control exclusively to user's SID
      try {
        execFileSync("icacls", [filePath, "/inheritance:r", "/grant:r", `*${sid}:(F)`], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
        });
      } catch (cause) {
        throw new Error(
          `FAIL_CLOSED: Failed to set restrictive Windows ACL on ${filePath}: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
      }

      // 2. Verify the effective ACL
      try {
        const verifyOutput = execFileSync("icacls", [filePath], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
        });

        if (!verifyOutput.includes("Successfully processed 1 files")) {
          throw new Error("icacls reported processing failure");
        }

        // Verify that broad access principals are not present
        const forbiddenPrincipals = [
          "Everyone",
          "BUILTIN\\Users",
          "NT AUTHORITY\\Authenticated Users",
          "ANONYMOUS LOGON",
        ];
        const lowerOut = verifyOutput.toLowerCase();
        for (const principal of forbiddenPrincipals) {
          if (lowerOut.includes(principal.toLowerCase())) {
            throw new Error(`Insecure principal found in effective ACL: ${principal}`);
          }
        }
      } catch (cause) {
        throw new Error(
          `FAIL_CLOSED: Effective Windows ACL verification failed for ${filePath}: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
      }
    } else {
      try {
        chmodSync(filePath, 0o600);
        const effectiveMode = statSync(filePath).mode & 0o777;
        if (effectiveMode !== 0o600) {
          throw new Error(
            `Expected mode 0600, got 0${effectiveMode.toString(8)}`,
          );
        }
      } catch (cause) {
        throw new Error(
          `FAIL_CLOSED: POSIX file permission enforcement failed on ${filePath}: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
      }
    }
  }

  /**
   * Resolves the assessment keyring adhering strictly to the 4-tier precedence rule:
   * 1. Explicit key in options
   * 2. Existing .rea-keyring.json on disk
   * 3. Environment variable REA_ASSESSMENT_KEY (for NEW assessment creation only)
   * 4. Cryptographically secure random 256-bit key generation
   */
  public static resolveKeyring(
    directory: string,
    assessmentId: string,
    options?: {
      readonly explicitKeyHex?: string | undefined;
      readonly allowEnvFallback?: boolean | undefined;
    },
  ): Result<KeyringManager, Error> {
    try {
      const keyringPath = join(directory, ".rea-keyring.json");
      const envKey = process.env.REA_ASSESSMENT_KEY?.trim();

      // Case 1: Keyring file already exists on disk
      if (existsSync(keyringPath)) {
        let existing: KeyringData;
        try {
          const content = readFileSync(keyringPath, "utf8");
          existing = JSON.parse(content) as KeyringData;
        } catch (e) {
          return err(new Error(`Corrupted keyring file at ${keyringPath}: ${String(e)}`));
        }

        const active = existing.keys.find((k) => k.version === existing.active_version);
        if (!active) {
          return err(new Error(`Keyring at ${keyringPath} has invalid active_version ${existing.active_version}`));
        }

        // Precedence check: Explicit key passed
        if (options?.explicitKeyHex && options.explicitKeyHex !== active.key_hex) {
          return err(
            new Error(
              `KEY_MISMATCH: Provided explicit key does not match active key in existing keyring at ${keyringPath}`,
            ),
          );
        }

        // Precedence check: Env variable passed when file exists
        if (envKey && envKey !== active.key_hex) {
          return err(
            new Error(
              `KEY_CONFLICT: Environment variable REA_ASSESSMENT_KEY conflicts with existing keyring at ${keyringPath}`,
            ),
          );
        }

        return ok(new KeyringManager(existing, keyringPath));
      }

      // Case 2: New assessment keyring creation
      let chosenKey: string;
      if (options?.explicitKeyHex) {
        if (!/^[0-9a-fA-F]{64}$/.test(options.explicitKeyHex)) {
          return err(new Error("Invalid explicit key format: must be 64-char (256-bit) hex"));
        }
        chosenKey = options.explicitKeyHex.toLowerCase();
      } else if (options?.allowEnvFallback !== false && envKey) {
        if (!/^[0-9a-fA-F]{64}$/.test(envKey)) {
          return err(new Error("Invalid REA_ASSESSMENT_KEY format: must be 64-char (256-bit) hex"));
        }
        chosenKey = envKey.toLowerCase();
      } else {
        // Fallback: Generate cryptographically random 256-bit key
        chosenKey = randomBytes(32).toString("hex");
      }

      const initialData: KeyringData = {
        assessment_id: assessmentId,
        active_version: 1,
        keys: [
          {
            version: 1,
            key_hex: chosenKey,
            created_at: new Date().toISOString(),
          },
        ],
      };

      const manager = new KeyringManager(initialData, keyringPath);
      manager.saveToFile(keyringPath);
      return ok(manager);
    } catch (cause) {
      return err(cause instanceof Error ? cause : new Error(String(cause)));
    }
  }

  /**
   * Creates an ephemeral, in-memory KeyringManager without writing to disk.
   */
  public static createEphemeral(assessmentId: string, explicitKeyHex?: string | undefined): KeyringManager {
    const key = explicitKeyHex ?? randomBytes(32).toString("hex");
    const data: KeyringData = {
      assessment_id: assessmentId,
      active_version: 1,
      keys: [
        {
          version: 1,
          key_hex: key,
          created_at: new Date().toISOString(),
        },
      ],
    };
    return new KeyringManager(data);
  }
}
