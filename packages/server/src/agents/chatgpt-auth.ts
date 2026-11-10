import { createHash, createPublicKey, type JsonWebKeyInput, randomBytes, randomUUID, verify as verifySignature } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import type { Vault } from "@penteos/core";

/**
 * "Sign in with ChatGPT" for open-source, locally hosted apps (developers.openai.com/siwc): the
 * operator authorizes Penteos in OpenAI's own page, and the agent's requests are billed to their
 * ChatGPT plan. OAuth 2.0 with PKCE through a 127.0.0.1 loopback; the first sign-in registers this
 * install as its own client (never Codex's). Tokens live sealed with the workspace key, refresh
 * before they expire (one refresh at a time: the refresh token rotates) and are revoked on sign-out.
 */

const ISSUER = "https://auth.openai.com";
export const CHATGPT_API = "https://api.openai.com/v1";
/** OpenAI's endpoints; tests point them at a local stand-in. */
export interface ChatGptEndpoints {
  issuer: string;
  api: string;
}
const OPENAI: ChatGptEndpoints = { issuer: ISSUER, api: CHATGPT_API };
const SCOPE = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const PLAN_SCOPE = "chatgpt.tokens.use.direct";
const APP_NAME = "Penteos";
const CALLBACK_PATH = "/auth/callback";
/** Refresh errors after which only a new sign-in helps. */
const TERMINAL_REFRESH = new Set(["invalid_grant", "invalid_refresh_token", "token_expired", "refresh_token_expired", "refresh_token_invalidated", "refresh_token_reused"]);

interface Stored {
  /** This install, for OpenAI's per-host attribution: opaque, made once. */
  hostId: string;
  /** The client OpenAI issued at the first sign-in (oaiapp_…), bound to one account. */
  clientId?: string;
  email?: string;
  subject?: string;
  idToken?: string;
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: number;
  scopes?: string[];
  /** The operator saw "You're using your ChatGPT plan" once. */
  welcomed?: boolean;
}

export interface ChatGptStatus {
  signedIn: boolean;
  /** Plan usage granted (the chatgpt.tokens.use.direct scope). */
  plan: boolean;
  email?: string;
  /** The first time it is ready: the interface shows the plan notice once. */
  welcome: boolean;
  pending: boolean;
}

/** A sign-in that only a new authorization can fix (revoked, expired, disconnected in ChatGPT). */
export class ChatGptSignedOut extends Error {}

const b64url = (b: Buffer) => b.toString("base64url");
type Jwk = JsonWebKeyInput["key"] & { kid?: string };
const SEALED = ["idToken", "accessToken", "refreshToken"] as const;

export class ChatGptAuth {
  private readonly file: string;
  private state: Stored;
  private refreshing?: Promise<string>;
  private pending?: { server: Server; timer: NodeJS.Timeout };
  private jwks?: { at: number; keys: Jwk[] };

  constructor(
    dataDir: string,
    private readonly vault: () => Vault,
    private readonly fetchImpl: typeof fetch = fetch,
    readonly endpoints: ChatGptEndpoints = OPENAI,
  ) {
    this.file = join(dataDir, "config", "chatgpt.json");
    this.state = this.load();
  }

  private load(): Stored {
    try {
      const raw = JSON.parse(readFileSync(this.file, "utf8")) as Stored;
      for (const k of SEALED) if (raw[k]) raw[k] = this.vault().open(raw[k]!);
      if (raw.hostId) return raw;
    } catch {
      /* none yet, or unreadable: a fresh host */
    }
    return { hostId: `urn:uuid:${randomUUID()}` };
  }

  private save(): void {
    mkdirSync(join(this.file, ".."), { recursive: true });
    const out: Stored = { ...this.state };
    for (const k of SEALED) if (out[k]) out[k] = this.vault().seal(out[k]!);
    const tmp = `${this.file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(out, null, 2), { mode: 0o600 });
    renameSync(tmp, this.file);
  }

  status(): ChatGptStatus {
    const signedIn = Boolean(this.state.refreshToken || this.state.accessToken);
    const plan = signedIn && (this.state.scopes ?? []).includes(PLAN_SCOPE);
    return { signedIn, plan, ...(this.state.email ? { email: this.state.email } : {}), welcome: plan && !this.state.welcomed, pending: Boolean(this.pending) };
  }

  acknowledgeWelcome(): void {
    this.state.welcomed = true;
    this.save();
  }

  /**
   * Starts a sign-in: a one-shot listener on 127.0.0.1, then the URL of OpenAI's page to open in
   * the browser. `done` hears how it ended. A new attempt replaces one still waiting.
   */
  async begin(done: (result: { ok: true } | { ok: false; error: string }) => void): Promise<{ url: string }> {
    this.cancel();
    const verifier = b64url(randomBytes(64));
    const challenge = b64url(createHash("sha256").update(verifier).digest());
    const stateToken = b64url(randomBytes(24));
    const nonce = b64url(randomBytes(24));
    const returning = this.state.clientId;
    const server = createServer();
    await new Promise<void>((ok, fail) => {
      server.once("error", fail);
      server.listen(0, "127.0.0.1", () => ok());
    });
    const port = (server.address() as { port: number }).port;
    const redirect = `http://127.0.0.1:${port}${CALLBACK_PATH}`;
    const finish = (result: { ok: true } | { ok: false; error: string }) => {
      this.cancel();
      done(result);
    };
    server.on("request", (req, res) => {
      const url = new URL(req.url ?? "/", redirect);
      if (url.pathname !== CALLBACK_PATH) {
        res.writeHead(404).end();
        return;
      }
      const page = (title: string, body: string) => {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(`<!doctype html><meta charset="utf-8"><title>Penteos</title><body style="font:15px system-ui;background:#0b0712;color:#ece6ff;display:grid;place-items:center;height:90vh"><div><h2>${title}</h2><p>${body}</p></div>`);
      };
      const error = url.searchParams.get("error");
      if (error) {
        page("Not connected", error === "access_denied" ? "Access was declined. You can close this tab." : "ChatGPT returned an error. You can close this tab and try again from Penteos.");
        finish({ ok: false, error });
        return;
      }
      if (url.searchParams.get("state") !== stateToken) {
        page("Not connected", "This answer does not belong to the sign-in Penteos started. Try again from Penteos.");
        finish({ ok: false, error: "state_mismatch" });
        return;
      }
      const issued = url.searchParams.get("client_id") ?? undefined;
      const clientId = returning ?? issued;
      if (!clientId || (returning && issued && issued !== returning)) {
        page("Not connected", "The registration did not complete. Try again from Penteos.");
        finish({ ok: false, error: "registration_incomplete" });
        return;
      }
      const code = url.searchParams.get("code") ?? "";
      this.exchange(clientId, code, verifier, redirect, nonce)
        .then(() => {
          page("Penteos is connected", "Your ChatGPT plan is ready. You can close this tab and go back to Penteos.");
          finish({ ok: true });
        })
        .catch((e: Error) => {
          page("Not connected", "The sign-in could not be completed. Try again from Penteos.");
          finish({ ok: false, error: e.message });
        });
    });
    // Nobody signs in for five minutes: the listener goes.
    const timer = setTimeout(() => finish({ ok: false, error: "timeout" }), 5 * 60_000);
    this.pending = { server, timer };
    const params = new URLSearchParams({
      client_id: returning ?? "dynamic_agent_client",
      ext_agent_host_id: this.state.hostId,
      response_type: "code",
      redirect_uri: redirect,
      scope: SCOPE,
      resource: OPENAI.api,
      state: stateToken,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    if (!returning) params.set("agent_name_hint", APP_NAME);
    if (returning && this.state.idToken) params.set("id_token_hint", this.state.idToken);
    if (returning && this.state.email) params.set("login_hint", this.state.email);
    return { url: `${this.endpoints.issuer}/api/accounts/authorize?${params}` };
  }

  cancel(): void {
    if (!this.pending) return;
    clearTimeout(this.pending.timer);
    this.pending.server.close();
    this.pending = undefined;
  }

  private async exchange(clientId: string, code: string, verifier: string, redirect: string, nonce: string): Promise<void> {
    const res = await this.fetchImpl(`${this.endpoints.issuer}/api/accounts/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, code, code_verifier: verifier, redirect_uri: redirect, resource: OPENAI.api }),
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) throw new Error(String(body.error ?? `token exchange failed (${res.status})`));
    const claims = await this.verifyIdToken(String(body.id_token ?? ""), clientId, nonce);
    // A returning registration belongs to one account: another account's tokens never replace it.
    if (this.state.subject && this.state.clientId === clientId && claims.sub !== this.state.subject) throw new Error("account_mismatch");
    this.state = {
      ...this.state,
      clientId,
      subject: String(claims.sub),
      ...(typeof claims.email === "string" ? { email: claims.email } : {}),
    };
    this.store(body);
  }

  /** Replaces the tokens together (the refresh token rotates on every refresh). */
  private store(body: Record<string, unknown>): void {
    this.state.accessToken = String(body.access_token ?? "");
    if (typeof body.refresh_token === "string") this.state.refreshToken = body.refresh_token;
    if (typeof body.id_token === "string") this.state.idToken = body.id_token;
    this.state.expiresAt = Date.now() + Number(body.expires_in ?? 3600) * 1000;
    if (typeof body.scope === "string") this.state.scopes = body.scope.split(/[\s+]+/).filter(Boolean);
    this.save();
  }

  /** RS256 against OpenAI's published keys, then issuer, audience, expiry and this attempt's nonce. */
  private async verifyIdToken(token: string, clientId: string, nonce: string): Promise<Record<string, unknown>> {
    const [h, p, s] = token.split(".");
    if (!h || !p || !s) throw new Error("id_token missing");
    const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8")) as { alg?: string; kid?: string };
    if (header.alg !== "RS256") throw new Error("id_token algorithm");
    const keys = await this.keys();
    const jwk = keys.find((k) => k.kid === header.kid) ?? (keys.length === 1 ? keys[0] : undefined);
    if (!jwk) throw new Error("id_token key unknown");
    const ok = verifySignature("RSA-SHA256", Buffer.from(`${h}.${p}`), createPublicKey({ key: jwk, format: "jwk" }), Buffer.from(s, "base64url"));
    if (!ok) throw new Error("id_token signature");
    const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as Record<string, unknown>;
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    const now = Date.now() / 1000;
    if (claims.iss !== this.endpoints.issuer || !aud.includes(clientId) || typeof claims.exp !== "number" || claims.exp < now - 60 || claims.nonce !== nonce || !claims.sub) throw new Error("id_token claims");
    return claims;
  }

  private async keys(): Promise<Jwk[]> {
    if (this.jwks && Date.now() - this.jwks.at < 3600_000) return this.jwks.keys;
    const res = await this.fetchImpl(`${this.endpoints.issuer}/.well-known/jwks.json`);
    const body = (await res.json()) as { keys?: Jwk[] };
    this.jwks = { at: Date.now(), keys: body.keys ?? [] };
    return this.jwks.keys;
  }

  /** A valid access token, refreshed when it is about to expire. */
  async token(): Promise<string> {
    if (!this.state.accessToken && !this.state.refreshToken) throw new ChatGptSignedOut("not signed in");
    if (this.state.accessToken && (this.state.expiresAt ?? 0) - Date.now() > 120_000) return this.state.accessToken;
    this.refreshing ??= this.refresh().finally(() => (this.refreshing = undefined));
    return this.refreshing;
  }

  private async refresh(): Promise<string> {
    if (!this.state.refreshToken || !this.state.clientId) {
      this.clearTokens();
      throw new ChatGptSignedOut("no refresh token");
    }
    const res = await this.fetchImpl(`${this.endpoints.issuer}/api/accounts/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", client_id: this.state.clientId, refresh_token: this.state.refreshToken, resource: OPENAI.api }),
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      const code = String(body.error ?? "");
      if (TERMINAL_REFRESH.has(code)) {
        this.clearTokens();
        throw new ChatGptSignedOut(code);
      }
      // A network or server problem keeps the sign-in: the next request tries again.
      throw new Error(`refresh failed (${res.status}${code ? ` ${code}` : ""})`);
    }
    this.store(body);
    return this.state.accessToken!;
  }

  private clearTokens(): void {
    delete this.state.accessToken;
    delete this.state.refreshToken;
    delete this.state.expiresAt;
    delete this.state.scopes;
    this.save();
  }

  /** Revokes at OpenAI (best effort, a few tries), then forgets the tokens. The registration and host stay. */
  async signOut(): Promise<{ revoked: boolean }> {
    this.cancel();
    let revoked = !this.state.refreshToken;
    for (let i = 0; i < 3 && !revoked && this.state.refreshToken && this.state.clientId; i++) {
      try {
        const res = await this.fetchImpl(`${this.endpoints.issuer}/api/accounts/oauth/revoke`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token: this.state.refreshToken, token_type_hint: "refresh_token", client_id: this.state.clientId }),
        });
        if (res.ok) revoked = true;
        else if (res.status < 500) break;
      } catch {
        /* network: try again */
      }
      if (!revoked) await new Promise((r) => setTimeout(r, 400 * (i + 1)));
    }
    this.clearTokens();
    delete this.state.idToken;
    this.save();
    return { revoked };
  }

  /** The models this account can use, in OpenAI's order. */
  async models(): Promise<Array<{ slug: string; name: string }>> {
    const res = await this.fetchImpl(`${this.endpoints.api}/models`, { headers: { authorization: `Bearer ${await this.token()}` }, signal: AbortSignal.timeout(5000) });
    if (!res.ok) return [];
    const body = (await res.json()) as { models?: Array<{ slug?: string; display_name?: string; visibility?: string }>; data?: Array<{ id: string }> };
    if (body.models) return body.models.filter((m) => m.slug && (m.visibility ?? "list") === "list").map((m) => ({ slug: m.slug!, name: m.display_name ?? m.slug! }));
    return (body.data ?? []).map((m) => ({ slug: m.id, name: m.id }));
  }

}
