/**
 * The demo project for screenshots: "Acme Corp - External web pentest", on reserved names
 * (*.acme-corp.test) and documentation addresses (203.0.113.0/24) that reach no one. Tools are the
 * stand-ins in scripts/demo/bin: the runs go through Penteos's real path (scope check, approvals,
 * runner, parsers), only the network is fake.
 */

/** Builds the project through the core's API. `api(op, input, token)`; `agent` is the Maestro's token. */
export async function seed({ api, agent }) {
  const AGENT = agent;
  await api("workspace.set_prefs", { onboarded: true, workStyle: "solo" });
  const eng = await api("engagement.create", { clientName: "Acme Corp", name: "External web pentest", mode: "web", language: "en" });
  const id = eng.id;
  const on = (input) => ({ engagementId: id, ...input });

  await api("engagement.update", on({ maxRisk: "exploitation", autonomy: "maestro" }));
  for (const rule of [
    { effect: "include", target: { type: "wildcard", value: "*.acme-corp.test" }, reason: "SOW §2: every Acme web property" },
    { effect: "include", target: { type: "cidr", value: "203.0.113.0/28" }, reason: "SOW §2: perimeter range" },
    { effect: "exclude", target: { type: "domain", value: "pay.acme-corp.test" }, reason: "Third-party payment provider: not authorized" },
  ]) {
    await api("scope.add_rule", on({ rule }));
  }

  // Recon and mapping, as the Maestro ran them.
  const run = async (argv, targets, risk) => {
    const r = await api("run.exec", on({ argv, targets, risk, wait: 20 }), AGENT);
    if (process.env.DEMO_STEP) console.log(argv[0], JSON.stringify(r).slice(0, 400));
    return r;
  };
  await run(["httpx", "-u", "www.acme-corp.test", "-u", "app.acme-corp.test", "-u", "api.acme-corp.test", "-u", "vpn.acme-corp.test", "-u", "staging.acme-corp.test", "-title", "-tech-detect", "-status-code"], ["www.acme-corp.test", "app.acme-corp.test", "api.acme-corp.test", "vpn.acme-corp.test", "staging.acme-corp.test"], "passive");
  await run(["nmap", "-sV", "-T3", "203.0.113.0/28"], ["203.0.113.0/28"], "active");
  await run(["katana", "-u", "https://app.acme-corp.test", "-d", "3", "-jc"], ["app.acme-corp.test"], "active");
  // The operator moves the work on, phase by phase, as they would after reviewing it.
  await api("phase.set", on({ phase: "mapping", summary: "Five web properties and their services mapped." }));
  await api("phase.set", on({ phase: "analysis", summary: "Application routes, roles and auth flows documented." }));
  await api("phase.set", on({ phase: "exploitation", summary: "Candidates: script console, orders id parameter, invoice ids." }));

  // Intrusive steps wait for the operator; here the operator approves them, as they would.
  const approved = async (argv, targets) => {
    const asked = await run(argv, targets, "intrusive");
    if (asked.status !== "pending_approval") return asked;
    await api("approval.approve", on({ approvalId: asked.approvalId }));
    for (let i = 0; i < 40; i++) {
      const runs = await api("run.list", on({ limit: 5 }));
      const done = (runs.runs ?? runs).find((r) => r.command?.startsWith(argv[0]) && r.status === "finished");
      if (done) return done;
      await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error(`${argv[0]} did not finish`);
  };
  const nuclei = await approved(["nuclei", "-u", "app.acme-corp.test", "-u", "staging.acme-corp.test", "-u", "vpn.acme-corp.test", "-severity", "low,medium,high,critical"], ["app.acme-corp.test", "staging.acme-corp.test", "vpn.acme-corp.test"]);
  const sqlmap = await approved(["sqlmap", "-u", "https://api.acme-corp.test/api/v2/orders?id=1042", "--batch", "--level", "2", "--risk", "1"], ["api.acme-corp.test"]);

  // The scope gate at work: the payment provider is linked from the checkout, and it is not ours.
  await run(["httpx", "-u", "pay.acme-corp.test", "-title"], ["pay.acme-corp.test"], "passive").catch(() => undefined);

  // What the Maestro wrote up, with the evidence from those runs.
  const rawOf = async (r) => {
    return (await api("run.get", on({ runId: r.runId ?? r.id }))).rawIds?.[0];
  };
  // Evidence is the part that shows it: with `line`, only the output line that contains it.
  const evidence = async (r, caption, line) => {
    const rawId = await rawOf(r);
    if (!rawId) return [];
    let range;
    if (line) {
      const got = await api("raw.get", on({ rawId }));
      const text = typeof got.content === "string" ? got.content : got.content?.content ?? "";
      const at = text.split("\n").findIndex((l) => l.includes(line));
      if (at >= 0) {
        const before = text.split("\n").slice(0, at).join("\n");
        const start = Buffer.byteLength(before) + (at > 0 ? 1 : 0);
        range = { start, end: start + Buffer.byteLength(text.split("\n")[at]) };
      }
    }
    return [(await api("evidence.from_raw", on({ rawId, caption, ...(range ? { range } : {}) }), AGENT)).id];
  };
  const entity = async (kind, text) => (await api("entity.query", on({ kind, text })))[0]?.id;
  const observations = await api("entity.query", on({ kind: "observation" }));
  const observationOf = (rule) => observations.find((o) => o.attributes.sourceRule === `nuclei:${rule}`)?.id;
  // Findings that came out of a scanner are promoted from its observation (linked, and it leaves
  // the "not yet assessed" list); the rest are written up directly.
  const finding = async (f, cvss, status, rule) => {
    const observationId = rule && observationOf(rule);
    const { instances: _i, ...text } = f;
    const made = observationId ? await api("observation.promote", on({ observationIds: [observationId], ...text }), AGENT) : await api("finding.create", on(f), AGENT);
    if (cvss) await api("finding.set_cvss", on({ id: made.id, vector: cvss }), AGENT);
    if (status) await api("finding.set_status", on({ id: made.id, status }));
    return made;
  };
  const jenkins = await entity("webapp", "staging.acme-corp.test");
  const apiApp = await entity("webapp", "api.acme-corp.test");
  const portal = await entity("webapp", "app.acme-corp.test");
  const vpn = await entity("domain", "vpn.acme-corp.test");
  const staging = await entity("domain", "staging.acme-corp.test");
  const www = await entity("webapp", "www.acme-corp.test");
  const at = (entityId, location) => (entityId ? [{ entityId, location }] : []);

  const jenkinsFinding = await finding(
    {
      title: "Unauthenticated Jenkins script console allows remote code execution",
      severity: "critical",
      description: "The Jenkins instance on the staging server exposes `/script` without authentication. The script console runs arbitrary Groovy code with the privileges of the Jenkins service.",
      impact: "Anyone on the internet can run commands on the staging server, read the build secrets it stores (deploy keys, cloud credentials) and use it to reach production pipelines.",
      remediation: "Take the instance off the internet or put it behind the VPN, enable authentication with matrix-based authorization, and rotate every credential stored in Jenkins.",
      instances: at(jenkins, "http://staging.acme-corp.test:8080/script"),
      evidenceIds: await evidence(nuclei, "nuclei: jenkins-script-console matched without credentials", "jenkins-script-console"),
      cwe: ["CWE-306"],
    },
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "approved",
    "jenkins-script-console",
  );
  const sqliFinding = await finding(
    {
      title: "SQL injection in the orders API (id parameter)",
      severity: "high",
      description: "`GET /api/v2/orders?id=` concatenates the parameter into a PostgreSQL query. Boolean-based blind and stacked-query payloads are both accepted.",
      impact: "Any signed-in customer can read every order and customer record in the database, and stacked queries allow modifying data.",
      remediation: "Use parameterized queries in the orders repository and validate `id` as an integer. Review the other `/api/v2` handlers built on the same helper.",
      instances: at(apiApp, "GET /api/v2/orders?id=1042"),
      evidenceIds: await evidence(sqlmap, "sqlmap confirms boolean-based blind injection on id (PostgreSQL 13)"),
      cwe: ["CWE-89"],
    },
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "approved",
  );
  // The two approved ones went through the whole review: demonstrated impact and an independent
  // verifier that reproduced them without the finder's history.
  const impact = {
    [jenkinsFinding.id]: {
      reach: "The console runs as the jenkins user, which owns /var/lib/jenkins: 14 pipelines and 31 stored credentials, listed with a read-only Groovy call.",
      exposed: "The credential store holds an AWS access key for the deploy role and the SSH key used to push to production web servers.",
      chain: "With the deploy key, the production web servers (www and app) are one step away: the same key is in their authorized_keys.",
    },
    [sqliFinding.id]: {
      reach: "The orders table holds 48,210 rows across 6,912 customers; counted with a boolean-blind COUNT, no rows were dumped.",
      exposed: "Customer names, shipping addresses and phone numbers; card data is not stored (tokenized by the payment provider).",
      chain: "Not chained: stacked queries work, but the database user cannot write outside the orders schema.",
    },
  };
  // What the answers stand on: a read-only call to each, kept as evidence.
  const jenkinsProbe = await run(["curl", "-s", "-i", "-X", "POST", "http://staging.acme-corp.test:8080/scriptText", "--data-urlencode", "script=println('id'.execute().text)"], ["staging.acme-corp.test"], "active");
  const ordersProbe = await run(["curl", "-s", "-i", "https://api.acme-corp.test/api/v2/orders?id=1042%20AND%20(SELECT%20COUNT(*)%20FROM%20orders)>0", "-H", "Authorization: Bearer <test-user>"], ["api.acme-corp.test"], "active");
  const proof = {
    [jenkinsFinding.id]: await evidence(jenkinsProbe, "Script console runs as jenkins and lists 14 jobs and 31 stored credentials (ids only)"),
    [sqliFinding.id]: await evidence(ordersProbe, "Boolean-blind COUNT: 48,210 orders across 6,912 customers; no rows dumped"),
  };
  for (const [findingId, answers] of Object.entries(impact)) {
    for (const [key, answer] of Object.entries(answers)) {
      const status = key === "chain" && findingId === sqliFinding.id ? "not_applicable" : "answered";
      await api("finding.answer_impact", on({ id: findingId, key, status, answer, ...(key === "chain" ? {} : { evidenceIds: proof[findingId] }) }), AGENT);
    }
  }
  // Verified by hand by the operator (the independent verifier needs a live model).
  await api("finding.verdict", on({ id: jenkinsFinding.id, verdict: "reproduced", summary: "Reproduced from a clean session: GET /script returns the console, and println(\"id\".execute().text) runs as uid=1000(jenkins)." }));
  await api("finding.verdict", on({ id: sqliFinding.id, verdict: "reproduced", summary: "Reproduced with a fresh token: id=1042 AND 1=1 returns the order, AND 1=2 returns 404; timing payloads confirm PostgreSQL." }));

  await finding(
    {
      title: "Invoices can be read across customer accounts (IDOR)",
      severity: "high",
      description: "`GET /api/v2/invoices/{id}` returns any invoice when the id is changed, regardless of the account that owns it.",
      impact: "A customer can download other customers' invoices: names, addresses, purchase history and tax ids.",
      remediation: "Check that the invoice belongs to the caller's account on the server, for every object returned by id.",
      instances: at(apiApp, "GET /api/v2/invoices/88231"),
      cwe: ["CWE-639"],
    },
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    undefined,
  );
  await finding(
    {
      title: "Anonymous FTP access on the staging server",
      severity: "medium",
      description: "vsftpd 3.0.3 on staging.acme-corp.test accepts the `anonymous` user and lists the `/pub/backups` directory.",
      impact: "Backups and build artifacts on the server can be downloaded by anyone.",
      remediation: "Disable anonymous login (`anonymous_enable=NO`) and close port 21 to the internet.",
      instances: at(staging, "staging.acme-corp.test:21"),
      cwe: ["CWE-284"],
    },
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    undefined,
    "ftp-anonymous-login",
  );
  await finding(
    {
      title: "Outdated nginx 1.18.0 (CVE-2021-23017)",
      severity: "medium",
      description: "The public web servers report nginx 1.18.0, affected by an off-by-one in the DNS resolver (CVE-2021-23017). Exploitability depends on the `resolver` directive being set: pending verification.",
      impact: "If the resolver is in use, a crafted DNS response may crash the worker process or, in rare cases, execute code.",
      remediation: "Upgrade nginx to 1.20.1 or later on www and app.",
      instances: [...at(www, "nginx/1.18.0"), ...at(portal, "nginx/1.18.0")],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
      cwe: ["CWE-193"],
    },
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
  );
  await finding(
    {
      title: "TLS 1.0 still negotiated on the VPN gateway",
      severity: "low",
      description: "vpn.acme-corp.test accepts TLS 1.0 connections.",
      impact: "Clients that fall back to TLS 1.0 are exposed to known protocol weaknesses.",
      remediation: "Allow only TLS 1.2 and 1.3 on the SSL VPN portal.",
      instances: at(vpn, "vpn.acme-corp.test:443"),
      cwe: ["CWE-327"],
    },
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    undefined,
    "deprecated-tls",
  );
  await finding({
    title: "Missing security headers on the customer portal",
    severity: "low",
    description: "`Content-Security-Policy` and `Strict-Transport-Security` are not set on app.acme-corp.test.",
    impact: "Weaker protection against cross-site scripting and protocol downgrade.",
    remediation: "Add a restrictive CSP and HSTS with `max-age=31536000; includeSubDomains`.",
    instances: at(portal, "https://app.acme-corp.test"),
    cwe: ["CWE-693"],
  }, undefined, undefined, "http-missing-security-headers");

  // Coverage of the two applications under test (OWASP WSTG categories).
  const coverage = [
    [portal, "INFO", "tested"], [portal, "CONF", "tested"], [portal, "IDNT", "tested"], [portal, "ATHN", "in_progress"], [portal, "SESS", "in_progress"], [portal, "INPV", "untested"], [portal, "CRYP", "tested"],
    [apiApp, "INFO", "tested"], [apiApp, "ATHZ", "vulnerable"], [apiApp, "INPV", "vulnerable"], [apiApp, "ATHN", "tested"], [apiApp, "BUSL", "untested"],
    [jenkins, "CONF", "vulnerable"], [jenkins, "ATHN", "vulnerable"],
  ];
  for (const [webappId, category, status] of coverage) {
    if (webappId) await api("webapp.set_coverage", on({ webappId, category, status }), AGENT);
  }

  // Where the work is now: the next intrusive step waits for the operator.
  await run(["sqlmap", "-u", "https://api.acme-corp.test/api/v2/invoices/88231", "--batch", "--level", "2", "--risk", "1"], ["api.acme-corp.test"], "intrusive");
  return { engagementId: id };
}

/**
 * The Maestro's side of the story, as its conversation file: what it said and which operations it
 * called. `approvalId` is the pending sqlmap request, shown as a card right after the call.
 */
export function conversation({ approvalId }) {
  const at = (min) => new Date(Date.now() - min * 60_000).toISOString();
  let n = 0;
  const tool = (name, input, summary, status = "ok", extra = {}) => ({ kind: "tool", id: `demo-${++n}`, name, input, status, summary, ...extra });
  const say = (text) => ({ kind: "text", text });
  const events = [
    { kind: "user", text: "Start with recon on the Acme perimeter. Stay strictly inside the SOW.", at: at(96) },
    say("Starting passive: I'll probe the five known hostnames, then run a service scan of 203.0.113.0/28. Both are covered by rules #1 and #2."),
    tool("run.exec", { intent: "Probe the five web properties", argv: ["httpx", "-u", "www.acme-corp.test", "…"] }, "5 web apps · nginx 1.18.0, Express, Jenkins 2.303.1"),
    tool("run.exec", { intent: "Service scan of the perimeter range", argv: ["nmap", "-sV", "203.0.113.0/28"] }, "5 hosts up · 9 open services"),
    tool("run.exec", { intent: "Check the payment page linked from checkout", argv: ["httpx", "-u", "pay.acme-corp.test"] }, "blocked by scope: pay.acme-corp.test is excluded (rule #3) - nothing was sent", "error"),
    say("**Staging stands out:** Jenkins 2.303.1 on :8080 and anonymous FTP on :21.\n\nThe checkout links to `pay.acme-corp.test`. It's excluded by rule #3 (third-party payment provider), so I left it alone and noted it as a limitation for the report."),
    { kind: "done", provider: "claude-code", at: at(90) },
    { kind: "user", text: "Good. You're cleared for exploitation on the API and staging.", at: at(41) },
    tool("run.exec", { intent: "Templates against the three exposed apps", argv: ["nuclei", "-u", "staging.acme-corp.test", "…"] }, "1 critical · 1 medium · 2 low"),
    tool("run.exec", { intent: "Confirm the orders id parameter", argv: ["sqlmap", "-u", "https://api.acme-corp.test/api/v2/orders?id=1042"] }, "id is injectable · PostgreSQL 13"),
    tool("finding.create", { intent: "Write up the SQL injection with sqlmap's output" }, "SQL injection in the orders API · high · CVSS 8.1"),
    tool("finding.create", { intent: "Write up the Jenkins script console" }, "Unauthenticated Jenkins script console · critical · CVSS 9.8"),
    say("Two confirmed, both with evidence attached:\n\n- **Jenkins script console** without authentication → remote code execution on staging (critical, 9.8).\n- **SQL injection** in `GET /api/v2/orders?id=` (high, 8.1)."),
    tool("run.exec", { intent: "Check whether invoice ids are injectable too", argv: ["sqlmap", "-u", "https://api.acme-corp.test/api/v2/invoices/88231"] }, "pending_approval", "ok", approvalId ? { approvalId } : {}),
    say("Next I'd like to test the invoice ids the same way. It's an exploitation-level step, so it's waiting for your approval above."),
    { kind: "done", provider: "claude-code", at: at(12) },
  ];
  return { version: 1, events, watchedApprovals: approvalId ? [approvalId] : [], watchedRuns: [], notices: [] };
}
