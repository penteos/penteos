// JWT inspector: decodes and checks a token. Local only: node:crypto for HMAC, no network.
import { createHmac, timingSafeEqual } from "node:crypto";

const COMMON = [
  "secret", "secretkey", "secret-key", "secret_key", "jwt", "jwtsecret", "jwt-secret", "jwt_secret", "key", "private", "privatekey",
  "password", "passw0rd", "123456", "12345678", "changeme", "change-me", "changethis", "admin", "test", "testing", "dev", "development",
  "default", "token", "auth", "authentication", "your-256-bit-secret", "your-secret-key", "mysecret", "my-secret", "my_secret", "s3cr3t",
  "supersecret", "super-secret", "topsecret", "hmac", "signing-key", "app-secret", "api-secret", "qwerty", "letmein", "welcome",
  "shhhhh", "keyboard cat", "your_jwt_secret", "secret123", "jwt123", "access", "refresh", "production", "prod", "staging", "",
];
const HMAC = { HS256: "sha256", HS384: "sha384", HS512: "sha512" };

const b64urlDecode = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const json = (part, what) => {
  try {
    return JSON.parse(b64urlDecode(part).toString("utf8"));
  } catch {
    throw new Error(`the ${what} is not base64url JSON: is it a JWT?`);
  }
};

export function inspect(token, extra = []) {
  const parts = token.trim().replace(/^Bearer\s+/i, "").split(".");
  if (parts.length !== 3) throw new Error(`a JWT has 3 parts separated by dots; this one has ${parts.length}`);
  const header = json(parts[0], "header");
  const payload = json(parts[1], "payload");
  const issues = [];
  const add = (severity, title, detail, template) => issues.push({ severity, title, detail, ...(template ? { template } : {}) });
  const alg = String(header.alg ?? "");

  if (/^none$/i.test(alg)) add("critical", "alg none", "The header declares no signature: if the server accepts it, anyone can forge tokens.", "jwt-alg-none");
  else add("info", "alg none test", "Try the same payload with alg none (and None, NONE) and an empty signature: a server that accepts it does not verify.");

  let secret;
  if (HMAC[alg]) {
    const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
    const sig = b64urlDecode(parts[2]);
    for (const word of [...new Set([...extra, ...COMMON])]) {
      const mac = createHmac(HMAC[alg], word).update(signed).digest();
      if (mac.length === sig.length && timingSafeEqual(mac, sig)) {
        secret = word;
        break;
      }
    }
    if (secret !== undefined) add("high", "Weak HMAC secret", `The token is signed with "${secret}": anyone can sign tokens with any identity or role.`, "jwt-weak-hmac-secret");
    else add("info", "HMAC secret not in the list", `Not cracked with ${COMMON.length + extra.length} candidates; try hashcat -m 16500 with a larger list.`);
  } else if (/^(RS|PS|ES)\d{3}$/.test(alg)) {
    add("info", "Algorithm confusion test", `Asymmetric (${alg}): if the public key is reachable (/.well-known/jwks.json), try signing with HS256 using it as the secret.`);
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp === undefined) add("medium", "No expiry (exp)", "A leaked token stays valid until the secret changes.", "jwt-no-expiry");
  else if (typeof payload.exp === "number") {
    if (payload.exp < now) add("info", "Expired", `Expired ${new Date(payload.exp * 1000).toISOString()}: check the server rejects it.`);
    else if (payload.exp - (typeof payload.iat === "number" ? payload.iat : now) > 30 * 24 * 3600) add("low", "Long-lived", `Valid for ${Math.round((payload.exp - (payload.iat ?? now)) / 86400)} days.`, "jwt-no-expiry");
  }
  if (typeof payload.iat === "number" && payload.iat > now + 300) add("low", "Issued in the future", "iat is later than now: clocks or validation are off.");
  if (header.kid !== undefined) add("info", "kid header", `kid = ${JSON.stringify(header.kid).slice(0, 120)}: test path traversal (../../dev/null with an empty secret) and SQL injection in it.`);
  if (header.jku || header.x5u) add("medium", "jku / x5u header", "The token says where to fetch its key: test whether the server follows a URL you control (key injection, SSRF).");
  if (header.jwk) add("medium", "Embedded jwk", "The token carries its own key: test whether the server trusts it (sign with your own key).");
  const sensitive = Object.keys(payload).filter((k) => /role|admin|scope|perm|group|is_?staff|tenant|org/i.test(k));
  if (sensitive.length) add("info", "Authorization claims", `${sensitive.join(", ")}: change them in a forged or re-signed token to test privilege escalation.`);

  return { header, payload, alg, ...(secret !== undefined ? { secret } : {}), issues };
}

export async function activate(plugin) {
  plugin.operation("inspect", async (input) => {
    const words = String(input.words ?? "").split(/\r?\n/).map((w) => w.trim()).filter(Boolean).slice(0, 5000);
    return inspect(String(input.token ?? ""), words);
  });
}
