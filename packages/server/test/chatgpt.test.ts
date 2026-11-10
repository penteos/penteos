import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type OperationContext, Vault } from "@penteos/core";
import { afterEach, beforeEach, expect, it } from "vitest";
import { ChatGptAuth } from "../src/agents/chatgpt-auth.js";
import { ChatGptPlanSession } from "../src/agents/providers/chatgpt.js";
import type { AgentEvent, TurnContext } from "../src/agents/types.js";

/**
 * Sign in with ChatGPT against a stand-in for OpenAI on 127.0.0.1: registration on the first
 * sign-in, PKCE, a signed ID token, rotating refresh, revocation, and the agent on the plan.
 */

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "k1", alg: "RS256", use: "sig" };

let dir: string;
let server: Server;
let base: string;
let auth: ChatGptAuth;
let seen: { challenge?: string; revoked?: string; responses: Array<Record<string, unknown>>; refreshTokens: string[] };
let responsesReply: (res: import("node:http").ServerResponse) => void;

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
function idToken(claims: Record<string, unknown>) {
  const head = b64({ alg: "RS256", kid: "k1", typ: "JWT" });
  const body = b64(claims);
  return `${head}.${body}.${sign("RSA-SHA256", Buffer.from(`${head}.${body}`), privateKey).toString("base64url")}`;
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-chatgpt-"));
  seen = { responses: [], refreshTokens: [] };
  let nonce = "";
  let refreshCount = 0;
  responsesReply = (res) => {
    res.writeHead(200, { "content-type": "text/event-stream" });
    const ev = (type: string, data: Record<string, unknown>) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`);
    ev("response.output_text.delta", { delta: "Hola", item_id: "m1", output_index: 0, content_index: 0, sequence_number: 1 });
    ev("response.completed", { response: { id: "r1", status: "completed", output: [] }, sequence_number: 2 });
    res.end();
  };
  server = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => (raw += String(d)));
    req.on("end", () => {
      const url = new URL(req.url ?? "/", "http://x");
      const form = new URLSearchParams(raw);
      const json = (status: number, body: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      };
      if (url.pathname === "/.well-known/jwks.json") return json(200, { keys: [jwk] });
      if (url.pathname === "/api/accounts/oauth/token") {
        if (form.get("grant_type") === "authorization_code") {
          const challenge = createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url");
          if (form.get("code") !== "good-code" || challenge !== seen.challenge || form.get("resource") !== "https://api.openai.com/v1") return json(400, { error: "invalid_grant" });
          const now = Math.floor(Date.now() / 1000);
          return json(200, {
            access_token: "at-1",
            refresh_token: "rt-1",
            id_token: idToken({ iss: base, aud: form.get("client_id"), sub: "user-1", email: "op@example.com", nonce, iat: now, exp: now + 3600 }),
            token_type: "Bearer",
            // Short-lived on purpose: the next token() refreshes.
            expires_in: 60,
            scope: "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct",
          });
        }
        seen.refreshTokens.push(form.get("refresh_token") ?? "");
        if (form.get("refresh_token") === "dead") return json(400, { error: "invalid_grant" });
        refreshCount++;
        return json(200, { access_token: `at-${refreshCount + 1}`, refresh_token: `rt-${refreshCount + 1}`, expires_in: 3600, token_type: "Bearer", scope: "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct" });
      }
      if (url.pathname === "/api/accounts/oauth/revoke") {
        seen.revoked = form.get("token") ?? "";
        res.writeHead(200).end();
        return;
      }
      if (url.pathname === "/v1/models") return json(200, { models: [{ slug: "gpt-test", display_name: "GPT Test", visibility: "list" }, { slug: "internal", visibility: "hide" }] });
      if (url.pathname === "/v1/responses") {
        seen.responses.push(JSON.parse(raw) as Record<string, unknown>);
        return responsesReply(res);
      }
      // The authorize page: the test reads the nonce from it the way the real page would carry it.
      if (url.pathname === "/api/accounts/authorize") {
        nonce = url.searchParams.get("nonce") ?? "";
        return json(200, {});
      }
      res.writeHead(404).end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const vault = new Vault(randomBytes(32));
  auth = new ChatGptAuth(dir, () => vault, fetch, { issuer: base, api: `${base}/v1` });
});

afterEach(async () => {
  auth.cancel();
  await new Promise((r) => server.close(r));
  rmSync(dir, { recursive: true, force: true });
});

/** Plays the browser: OpenAI's page, then its redirect back to Penteos's loopback. */
async function signIn(callback: (redirect: URL, state: string) => URL): Promise<{ ok: boolean; error?: string }> {
  let resolveDone!: (r: { ok: boolean; error?: string }) => void;
  const done = new Promise<{ ok: boolean; error?: string }>((r) => (resolveDone = r));
  const { url } = await auth.begin((r) => resolveDone(r));
  const authorize = new URL(url);
  seen.challenge = authorize.searchParams.get("code_challenge") ?? undefined;
  await fetch(url);
  const back = callback(new URL(authorize.searchParams.get("redirect_uri")!), authorize.searchParams.get("state")!);
  await fetch(back).catch(() => undefined);
  return done;
}

it("first sign-in registers this install, keeps the tokens sealed and enables the plan", async () => {
  const result = await signIn((redirect, state) => {
    redirect.search = new URLSearchParams({ code: "good-code", state, client_id: "oaiapp_123", scope: "openid chatgpt.tokens.use.direct" }).toString();
    return redirect;
  });
  expect(result).toEqual({ ok: true });
  expect(auth.status()).toMatchObject({ signedIn: true, plan: true, email: "op@example.com", welcome: true });
  const onDisk = readFileSync(join(dir, "config", "chatgpt.json"), "utf8");
  expect(onDisk).toContain("oaiapp_123");
  expect(onDisk).toMatch(/urn:uuid:/);
  for (const secret of ["at-1", "rt-1"]) expect(onDisk).not.toContain(secret);
  // Short-lived token: refreshed with the issued client and the rotating refresh token.
  expect(await auth.token()).toBe("at-2");
  expect(seen.refreshTokens).toEqual(["rt-1"]);
  expect((await auth.models()).map((m) => m.slug)).toEqual(["gpt-test"]);
  // Sign-out revokes the latest refresh token and forgets the tokens, not the registration.
  expect(await auth.signOut()).toEqual({ revoked: true });
  expect(seen.revoked).toBe("rt-2");
  expect(auth.status()).toMatchObject({ signedIn: false, plan: false });
  expect(readFileSync(join(dir, "config", "chatgpt.json"), "utf8")).toContain("oaiapp_123");
});

it("an answer that does not carry this attempt's state is refused", async () => {
  const result = await signIn((redirect) => {
    redirect.search = new URLSearchParams({ code: "good-code", state: "someone-else", client_id: "oaiapp_123" }).toString();
    return redirect;
  });
  expect(result).toEqual({ ok: false, error: "state_mismatch" });
  expect(auth.status().signedIn).toBe(false);
});

it("declining in ChatGPT's page leaves Penteos signed out", async () => {
  const result = await signIn((redirect, state) => {
    redirect.search = new URLSearchParams({ error: "access_denied", state }).toString();
    return redirect;
  });
  expect(result).toEqual({ ok: false, error: "access_denied" });
});

function turn(events: AgentEvent[]): TurnContext {
  return {
    system: "You are the Maestro.",
    ops: {} as OperationContext,
    caller: {} as TurnContext["caller"],
    settings: { model: "gpt-test" },
    workDir: dir,
    dataDir: dir,
    emit: (e) => events.push(e),
    signal: new AbortController().signal,
    lang: "en",
    allow: () => false,
  };
}

it("the agent runs on the plan: brief as instructions, nothing stored at OpenAI, streamed", async () => {
  await signIn((redirect, state) => {
    redirect.search = new URLSearchParams({ code: "good-code", state, client_id: "oaiapp_123" }).toString();
    return redirect;
  });
  const events: AgentEvent[] = [];
  const session = new ChatGptPlanSession(auth, undefined);
  await session.send("Map the scope", turn(events));
  expect(events.filter((e) => e.kind === "delta").map((e) => (e as { text: string }).text).join("")).toBe("Hola");
  expect(events.some((e) => e.kind === "error")).toBe(false);
  const body = seen.responses[0]!;
  expect(body).toMatchObject({ model: "gpt-test", instructions: "You are the Maestro.", store: false, stream: true });
  expect(body.input).toEqual([{ role: "user", content: "Map the scope" }]);
});

it("a plan limit is said plainly, with where to manage usage", async () => {
  await signIn((redirect, state) => {
    redirect.search = new URLSearchParams({ code: "good-code", state, client_id: "oaiapp_123" }).toString();
    return redirect;
  });
  responsesReply = (res) => {
    res.writeHead(429, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { code: "subscription_sharing_usage_limit_exceeded", message: "limit", type: "usage" } }));
  };
  const events: AgentEvent[] = [];
  await new ChatGptPlanSession(auth, undefined).send("go", turn(events));
  const error = events.find((e) => e.kind === "error") as { text: string } | undefined;
  expect(error?.text).toContain("chatgpt.com/settings/usage");
});
