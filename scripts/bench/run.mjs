// The detector bench: Penteos's own checks (no AI) against intentionally vulnerable applications
// whose flaws are documented, each result compared with what the checks are built to find. Runs on
// GitHub's machines (bench.yml), never on a developer's computer.
//   (from packages/server) node --conditions=penteos-source --import tsx ../../scripts/bench/run.mjs <juice-shop origin> <vampi origin> <out.md>
// A miss is a measurement (reported, not a failure); an error running a check fails the run.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { executeOperation, ToolRegistry, ToolRunner, Workspace } from "../../packages/core/src/index.ts";

const [juice = "http://127.0.0.1:3000", vampi = "http://127.0.0.1:5000", out = "bench.md"] = process.argv.slice(2);
const HUMAN = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
const dir = mkdtempSync(join(tmpdir(), "penteos-bench-"));
const ws = new Workspace(join(dir, "data"));
const rows = [];
let errors = 0;

function project(name, origins) {
  const eng = ws.create({ clientName: "Bench", name, mode: "web", maxRisk: "intrusive" }, HUMAN.actor);
  for (const o of origins) {
    const u = new URL(o);
    eng.addScopeRule({ effect: "include", target: { type: "ip", value: u.hostname }, ports: u.port || (u.protocol === "https:" ? "443" : "80") }, HUMAN.actor);
  }
  const runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  const ctx = { workspace: ws, caller: HUMAN, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner };
  return { eng, op: (name, input) => executeOperation(name, input, ctx) };
}

/** One expectation: what the check should find, and whether it did. */
async function expect(target, what, check, fn) {
  const started = Date.now();
  try {
    const { ok, detail } = await fn();
    rows.push({ target, what, check, result: ok ? "found" : "missed", detail, ms: Date.now() - started });
  } catch (e) {
    errors++;
    rows.push({ target, what, check, result: "error", detail: String(e.message ?? e).slice(0, 300), ms: Date.now() - started });
  }
}

const observations = (eng, re) => eng.query({ kind: "observation", limit: 5000 }).filter((o) => re.test(`${o.attributes.sourceRule} ${o.attributes.title}`));

// ---------------------------------------------------------------------------------------------
// OWASP Juice Shop (Angular single-page app with a REST API)
// ---------------------------------------------------------------------------------------------
{
  const { eng, op } = project("Juice Shop", [juice]);
  await expect("Juice Shop", "Its API surface read from the JavaScript (dozens of endpoints)", "web_harvest_scripts", async () => {
    await op("web.harvest_scripts", { url: `${juice}/` });
    const n = eng.query({ kind: "endpoint", limit: 5000 }).length;
    return { ok: n >= 30, detail: `${n} endpoint(s) in the graph` };
  });
  await expect("Juice Shop", "Missing browser defences (CSP, framing) reported", "web_check_transport", async () => {
    const r = await op("web.check_transport", { target: juice });
    const issues = (r.issues ?? []).join(" | ");
    return { ok: /Content-Security-Policy|framed/.test(issues), detail: issues.slice(0, 300) || "no issues" };
  });
  await expect("Juice Shop", "API endpoints answering without authentication", "web_probe_endpoints", async () => {
    await op("web.probe_endpoints", { origin: juice, fromOrigin: juice }).catch(() => op("web.probe_endpoints", { origin: juice, paths: ["/api/Users", "/api/Products", "/rest/user/whoami", "/api/Feedbacks", "/api/Challenges", "/rest/admin/application-configuration"] }));
    const hits = observations(eng, /apiprobe:no-auth/);
    return { ok: hits.length > 0, detail: hits.slice(0, 5).map((o) => o.attributes.title).join(" | ") || "none" };
  });
  await expect("Juice Shop", "Open redirect on /redirect?to= (allowlist checked by substring)", "web_probe_redirects", async () => {
    const r = await op("web.probe_redirects", { origin: juice, targets: [{ path: "/redirect", param: "to" }] });
    return { ok: (r.hits ?? []).length > 0, detail: (r.hits ?? []).join(" | ") || `tried ${r.tried}` };
  });
}

// ---------------------------------------------------------------------------------------------
// VAmPI (a deliberately vulnerable REST API: BOLA, a debug endpoint, mass assignment)
// ---------------------------------------------------------------------------------------------
{
  const { eng, op } = project("VAmPI", [vampi]);
  const post = async (path, body, token) => {
    const r = await fetch(`${vampi}${path}`, { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
    return r.json().catch(() => ({}));
  };
  await fetch(`${vampi}/createdb`).catch(() => undefined);
  const stamp = Date.now().toString(36);
  const users = {};
  for (const who of ["ana", "bob"]) {
    await post("/users/v1/register", { username: `${who}${stamp}`, password: `Pw-${stamp}-${who}`, email: `${who}${stamp}@bench.test` });
    users[who] = (await post("/users/v1/login", { username: `${who}${stamp}`, password: `Pw-${stamp}-${who}` })).auth_token;
  }
  await post("/books/v1", { book_title: `ana-secret-${stamp}`, secret: "ANA-PRIVATE" }, users.ana);
  await op("secret.save", { name: "account_a", kind: "token", value: `Bearer ${users.ana}` });
  await op("secret.save", { name: "account_b", kind: "token", value: `Bearer ${users.bob}` });

  await expect("VAmPI", "BOLA: one user reads another user's book secret", "web_cross_account", async () => {
    const r = await op("web.cross_account", { origin: vampi, accountA: "Authorization: {{secret:account_a}}", accountB: "Authorization: {{secret:account_b}}", raws: [`GET /books/v1/ana-secret-${stamp} HTTP/1.1\nAuthorization: {{secret:account_a}}`] });
    return { ok: (r.hits ?? []).some((h) => /reads account A's resource/.test(h)), detail: (r.hits ?? []).join(" | ") || "none" };
  });
  await expect("VAmPI", "The debug endpoint lists users with no session", "web_probe_endpoints", async () => {
    await op("web.probe_endpoints", { origin: vampi, paths: ["/users/v1/_debug", "/books/v1", "/users/v1", "/me", "/users/v1/me"] });
    const hits = observations(eng, /no-auth.*_debug|_debug.*no-auth/);
    return { ok: hits.length > 0, detail: observations(eng, /apiprobe/).map((o) => o.attributes.title).join(" | ") || "none" };
  });
  await expect("VAmPI", "Login rate limiting absent", "web_probe_rate_limit", async () => {
    const r = await op("web.probe_rate_limit", { origin: vampi, raw: `POST /users/v1/login HTTP/1.1\nContent-Type: application/json\n\n{"username":"nobody${stamp}","password":"x"}`, risk: "intrusive" });
    return { ok: r.verdict === "no_defence", detail: `verdict ${r.verdict}` };
  });
}

ws.close();
const found = rows.filter((r) => r.result === "found").length;
const md = [
  "# Penteos detector bench",
  "",
  `**${found} of ${rows.length}** expected issues found${errors ? ` · **${errors} error(s)**` : ""}.`,
  "",
  "| Target | Expected | Check | Result | Detail |",
  "|---|---|---|---|---|",
  ...rows.map((r) => `| ${r.target} | ${r.what} | \`${r.check}\` | ${r.result === "found" ? "✅ found" : r.result === "missed" ? "❌ missed" : "⚠️ error"} | ${String(r.detail).replace(/\|/g, "\\|").replace(/\n/g, " ").slice(0, 300)} |`),
  "",
].join("\n");
writeFileSync(out, md);
console.log(md);
process.exit(errors ? 1 : 0);
