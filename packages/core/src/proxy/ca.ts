import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { createHash, randomBytes, webcrypto } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { createSecureContext, type SecureContext } from "node:tls";

/**
 * Penteos's own certificate authority, for the intercepting proxy: one per workspace, created
 * on first use (key 0600). The project browser trusts it only inside its own session, so
 * nothing is installed in the system. Leaf certificates are made per host on demand (ECDSA
 * P-256: a few milliseconds each) and cached.
 */

x509.cryptoProvider.set(webcrypto as unknown as Crypto);
const ALG = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;
type KeyPair = { privateKey: CryptoKey; publicKey: CryptoKey };

function pem(label: string, der: ArrayBuffer): string {
  const b64 = Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

function unpem(text: string): Buffer {
  return Buffer.from(text.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
}

const serial = () => {
  const b = randomBytes(16);
  b[0] = b[0]! & 0x7f; // positive
  return b.toString("hex");
};

export class CertificateAuthority {
  private readonly contexts = new Map<string, Promise<SecureContext>>();

  private constructor(
    readonly certPem: string,
    private readonly cert: x509.X509Certificate,
    private readonly keys: KeyPair,
    private readonly leafKeys: KeyPair,
    private readonly leafKeyPem: string,
  ) {}

  /** "sha256/<base64>" of the certificate (DER): how Electron reports fingerprints. */
  get fingerprint(): string {
    return `sha256/${createHash("sha256").update(Buffer.from(this.cert.rawData)).digest("base64")}`;
  }

  get derBase64(): string {
    return Buffer.from(this.cert.rawData).toString("base64");
  }

  static async load(dir: string): Promise<CertificateAuthority> {
    mkdirSync(dir, { recursive: true });
    const certFile = join(dir, "proxy-ca.pem");
    const keyFile = join(dir, "proxy-ca.key");
    let certPem: string;
    let keys: KeyPair;
    if (existsSync(certFile) && existsSync(keyFile)) {
      certPem = readFileSync(certFile, "utf8");
      const priv = await webcrypto.subtle.importKey("pkcs8", new Uint8Array(unpem(readFileSync(keyFile, "utf8"))), ALG, true, ["sign"]);
      const cert = new x509.X509Certificate(certPem);
      const pub = await cert.publicKey.export(ALG, ["verify"]);
      keys = { privateKey: priv as CryptoKey, publicKey: pub as CryptoKey };
    } else {
      keys = (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as unknown as KeyPair;
      const now = Date.now();
      const ca = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: serial(),
        name: `CN=Penteos CA (${hostname()}), O=Penteos`,
        notBefore: new Date(now - 86_400_000),
        notAfter: new Date(now + 10 * 365 * 86_400_000),
        keys,
        signingAlgorithm: ALG,
        extensions: [
          new x509.BasicConstraintsExtension(true, 0, true),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
          await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        ],
      });
      certPem = ca.toString("pem");
      writeFileSync(certFile, certPem, { mode: 0o644 });
      writeFileSync(keyFile, pem("PRIVATE KEY", await webcrypto.subtle.exportKey("pkcs8", keys.privateKey)), { mode: 0o600 });
    }
    chmodSync(keyFile, 0o600);
    // One key for every leaf: generating keys per host is the slow part, and it buys nothing here.
    const leafKeys = (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as unknown as KeyPair;
    const leafKeyPem = pem("PRIVATE KEY", await webcrypto.subtle.exportKey("pkcs8", leafKeys.privateKey));
    return new CertificateAuthority(certPem, new x509.X509Certificate(certPem), keys, leafKeys, leafKeyPem);
  }

  /** TLS context presenting a certificate for this host (DNS name or IP), signed by the CA. */
  contextFor(host: string): Promise<SecureContext> {
    const name = host.toLowerCase().replace(/^\[|\]$/g, "");
    let ctx = this.contexts.get(name);
    if (!ctx) {
      ctx = this.issue(name);
      this.contexts.set(name, ctx);
      // A failed issue must not stay cached.
      ctx.catch(() => this.contexts.delete(name));
    }
    return ctx;
  }

  private async issue(host: string): Promise<SecureContext> {
    const { cert, key } = await this.pemFor(host);
    return createSecureContext({ cert, key });
  }

  /** Certificate chain (leaf + CA) and key in PEM for a host. */
  async pemFor(host: string): Promise<{ cert: string; key: string }> {
    const isIp = /^[\d.]+$/.test(host) || host.includes(":");
    const now = Date.now();
    const leaf = await x509.X509CertificateGenerator.create({
      serialNumber: serial(),
      subject: `CN=${host.replace(/[,=+<>#;"\\]/g, "_")}`,
      issuer: this.cert.subject,
      notBefore: new Date(now - 86_400_000),
      // Browsers reject leaf certificates valid for more than 398 days.
      notAfter: new Date(now + 390 * 86_400_000),
      signingKey: this.keys.privateKey,
      publicKey: this.leafKeys.publicKey,
      signingAlgorithm: ALG,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        new x509.ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.1"]),
        new x509.SubjectAlternativeNameExtension([isIp ? { type: "ip", value: host } : { type: "dns", value: host }]),
        await x509.AuthorityKeyIdentifierExtension.create(this.keys.publicKey),
      ],
    });
    return { cert: `${leaf.toString("pem").trim()}\n${this.certPem.trim()}\n`, key: this.leafKeyPem };
  }
}
