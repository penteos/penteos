import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Encryption of secrets at rest. AES-256-GCM with a workspace key kept
 * apart from the engagements: copying an engagement directory does not reveal its credentials.
 * (A passphrase or the OS keychain can wrap this key later without changing the format.)
 */

const PREFIX = "v1:";

export class Vault {
  constructor(private readonly key: Buffer) {
    if (key.length !== 32) throw new Error("vault key must be 32 bytes");
  }

  /** The workspace key, created on first use with owner-only permissions. */
  static forFile(path: string): Vault {
    if (!existsSync(path)) {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, randomBytes(32).toString("base64"), { mode: 0o600 });
    }
    chmodSync(path, 0o600);
    return new Vault(Buffer.from(readFileSync(path, "utf8").trim(), "base64"));
  }

  seal(plain: string): string {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.key, iv);
    const body = Buffer.concat([c.update(plain, "utf8"), c.final()]);
    return PREFIX + Buffer.concat([iv, c.getAuthTag(), body]).toString("base64");
  }

  open(sealed: string): string {
    if (!Vault.isSealed(sealed)) return sealed;
    const buf = Buffer.from(sealed.slice(PREFIX.length), "base64");
    const d = createDecipheriv("aes-256-gcm", this.key, buf.subarray(0, 12));
    d.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString("utf8");
  }

  static isSealed(value: string): boolean {
    return value.startsWith(PREFIX);
  }
}
