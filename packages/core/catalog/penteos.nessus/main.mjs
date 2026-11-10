// Nessus (.nessus v2) → Penteos ingest items. It only reads the text it is given: no network, no files.
const SEVERITY = { 1: "low", 2: "medium", 3: "high", 4: "critical" };
const MAX_ITEMS = 50000;

const unescape = (s) =>
  s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&amp;/g, "&");
const attrs = (s) => Object.fromEntries([...s.matchAll(/([\w:-]+)="([^"]*)"/g)].map((m) => [m[1], unescape(m[2])]));
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9a-f:]+$/i;
const isIp = (v) => IPV4.test(v) || (v.includes(":") && IPV6.test(v));
const isFqdn = (v) => /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(v);

function parse(text) {
  const items = [];
  const push = (item) => {
    if (items.length >= MAX_ITEMS) throw new Error(`more than ${MAX_ITEMS} items: split the report`);
    items.push(item);
  };
  let version;
  const policy = /<policyName>([\s\S]*?)<\/policyName>/.exec(text);
  for (const host of text.matchAll(/<ReportHost\b([^>]*)>([\s\S]*?)<\/ReportHost>/g)) {
    const name = attrs(host[1]).name ?? "";
    const props = Object.fromEntries([...host[2].matchAll(/<tag name="([^"]+)">([\s\S]*?)<\/tag>/g)].map((m) => [m[1], unescape(m[2]).trim()]));
    version ??= props["nessus-version"];
    const ip = props["host-ip"] || (isIp(name) ? name : undefined);
    if (!ip || !isIp(ip)) continue;
    const hostKey = { ip };
    const fqdn = (props["host-fqdn"] || (isFqdn(name) ? name : "")).toLowerCase();
    const os = (props["operating-system"] || "").split("\n")[0].trim();
    push({
      op: "upsert",
      kind: "host",
      key: hostKey,
      attributes: { status: "up", hostnames: [fqdn, props["netbios-name"]].filter(Boolean), ...(os ? { os: { name: os.slice(0, 200), confidence: 0.7 } } : {}) },
      confidence: 0.9,
    });
    if (fqdn && isFqdn(fqdn)) {
      push({ op: "upsert", kind: "domain", key: { fqdn } });
      push({ op: "relate", type: "resolves_to", from: { kind: "domain", key: { fqdn } }, to: { kind: "host", key: hostKey } });
    }
    const services = new Set();
    for (const item of host[2].matchAll(/<ReportItem\b([^>]*)>([\s\S]*?)<\/ReportItem>/g)) {
      const a = attrs(item[1]);
      const port = Number(a.port);
      const transport = a.protocol === "tcp" || a.protocol === "udp" ? a.protocol : undefined;
      const severity = Number(a.severity);
      const body = {};
      const cves = [];
      for (const m of item[2].matchAll(/<(description|solution|synopsis|plugin_output|risk_factor|cvss3_base_score|cve|see_also)>([\s\S]*?)<\/\1>/g)) {
        if (m[1] === "cve") cves.push(unescape(m[2]).trim());
        else body[m[1]] = unescape(m[2]).trim();
      }
      let target = { kind: "host", key: hostKey };
      if (transport && Number.isInteger(port) && port > 0 && port < 65536) {
        const serviceKey = { ip, transport, port };
        target = { kind: "service", key: serviceKey };
        if (!services.has(`${transport}/${port}`)) {
          services.add(`${transport}/${port}`);
          const svc = (a.svc_name || "").replace(/\?$/, "").replace(/^www$/, "http");
          push({ op: "upsert", kind: "service", key: serviceKey, attributes: { state: "open", ...(svc && svc !== "general" ? { protocol: svc } : {}) }, confidence: 0.8 });
          push({ op: "relate", type: "runs_on", from: { kind: "service", key: serviceKey }, to: { kind: "host", key: hostKey } });
        }
      }
      if (!(severity >= 1) || !a.pluginName) continue;
      const detail = [
        body.synopsis,
        body.description,
        cves.length ? `CVE: ${cves.join(", ")}` : "",
        body.cvss3_base_score ? `CVSS v3: ${body.cvss3_base_score}` : "",
        body.solution ? `Solution: ${body.solution}` : "",
        body.see_also ? `See also: ${body.see_also}` : "",
        body.plugin_output ? `Output:\n${body.plugin_output.slice(0, 1500)}` : "",
      ]
        .filter(Boolean)
        .join("\n\n")
        .slice(0, 6000);
      push({
        op: "observe",
        title: a.pluginName.slice(0, 300),
        sourceRule: `nessus:${a.pluginID ?? "unknown"}`,
        affects: [target],
        severityHint: SEVERITY[severity],
        ...(detail ? { detail } : {}),
      });
    }
  }
  return { items, tool: "nessus", ...(version ? { toolVersion: version } : {}), ...(policy ? { policy: unescape(policy[1]) } : {}) };
}

export async function activate(plugin) {
  plugin.operation("parse", async (input) => parse(String(input.text ?? "")));
}
