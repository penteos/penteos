import { Resolver } from "node:dns/promises";

/**
 * What a domain's DNS says about two classic risks, with lookups only (passive):
 *   - mail spoofing: SPF missing or permissive, DMARC missing or "none", no DKIM selector found;
 *   - subdomain takeover: a name whose CNAME points at a service someone else can claim (GitHub
 *     Pages, S3, Heroku, Azure…) or at a name that no longer exists.
 * The analysis is pure (tested with fixed records); `lookup` does the queries.
 */

export interface DnsIssue {
  key: string;
  severity: "info" | "low" | "medium" | "high";
  title: string;
  detail: string;
}

export interface MailRecords {
  domain: string;
  spf?: string;
  /** More than one SPF record (invalid: receivers treat it as no SPF). */
  spfCount: number;
  dmarc?: string;
  dkimSelectors: string[];
  mx: string[];
}

export function mailIssues(r: MailRecords): DnsIssue[] {
  const out: DnsIssue[] = [];
  const d = r.domain;
  const dmarcPolicy = r.dmarc ? (/\bp\s*=\s*(none|quarantine|reject)/i.exec(r.dmarc)?.[1]?.toLowerCase() ?? "none") : undefined;
  const enforced = dmarcPolicy === "quarantine" || dmarcPolicy === "reject";
  if (r.spfCount > 1) out.push({ key: "spf:multiple", severity: "medium", title: `${d} publishes ${r.spfCount} SPF records`, detail: "More than one v=spf1 record is a permanent error: receivers ignore SPF for the domain." });
  if (!r.spf) out.push({ key: "spf:missing", severity: enforced ? "low" : "medium", title: `No SPF record on ${d}`, detail: `Nothing says which servers may send mail as ${d}.${r.mx.length ? "" : " The domain has no MX either: if it never sends mail, publish \"v=spf1 -all\"."}` });
  else {
    const all = /([+?~-]?)all\b/i.exec(r.spf);
    const q = all ? all[1] || "+" : undefined;
    if (q === "+") out.push({ key: "spf:pass-all", severity: "high", title: `SPF on ${d} lets any server send as the domain (+all)`, detail: `SPF: ${r.spf}` });
    else if (q === "?" || !all) out.push({ key: "spf:neutral", severity: enforced ? "low" : "medium", title: `SPF on ${d} does not reject other senders (${all ? "?all" : "no all"})`, detail: `SPF: ${r.spf}` });
    else if (q === "~" && !enforced) out.push({ key: "spf:softfail", severity: "low", title: `SPF on ${d} only soft-fails other senders (~all) and DMARC does not enforce`, detail: `SPF: ${r.spf}. With ~all and no enforcing DMARC, forged mail from ${d} usually reaches the inbox.` });
  }
  if (!r.dmarc) out.push({ key: "dmarc:missing", severity: "medium", title: `No DMARC record on ${d}`, detail: `_dmarc.${d} has no policy: receivers are not told to reject mail that fails SPF/DKIM, and the owner gets no reports of spoofing.` });
  else {
    if (dmarcPolicy === "none") out.push({ key: "dmarc:none", severity: "medium", title: `DMARC on ${d} is p=none (monitoring only)`, detail: `DMARC: ${r.dmarc}. Forged mail as ${d} is delivered; combined with a non-strict SPF, the domain can be spoofed in phishing.` });
    const pct = Number(/\bpct\s*=\s*(\d+)/i.exec(r.dmarc)?.[1] ?? 100);
    if (enforced && pct < 100) out.push({ key: "dmarc:pct", severity: "low", title: `DMARC on ${d} applies to ${pct}% of mail`, detail: `DMARC: ${r.dmarc}` });
    if (!/\brua\s*=/i.test(r.dmarc)) out.push({ key: "dmarc:no-reports", severity: "info", title: `DMARC on ${d} asks for no aggregate reports (rua)`, detail: "Spoofing attempts go unnoticed." });
  }
  if (r.mx.length && !r.dkimSelectors.length) out.push({ key: "dkim:none-found", severity: "info", title: `No DKIM key found on ${d} under the common selectors`, detail: "Not proof there is none (selectors are arbitrary), but nothing common answered." });
  return out;
}

/** Services where a dangling name can be claimed, by the CNAME they use and what they answer. */
export const TAKEOVER_SERVICES: Array<{ service: string; cname: RegExp; body?: RegExp }> = [
  { service: "GitHub Pages", cname: /\.github\.io$/i, body: /There isn't a GitHub Pages site here/i },
  { service: "Amazon S3", cname: /\.s3[.-](?:website[.-])?(?:[a-z0-9-]+\.)?amazonaws\.com$/i, body: /NoSuchBucket|The specified bucket does not exist/i },
  { service: "Amazon CloudFront", cname: /\.cloudfront\.net$/i, body: /The request could not be satisfied.*Bad request|ERROR: The request could not be satisfied/is },
  { service: "Heroku", cname: /\.herokuapp\.com$|\.herokudns\.com$/i, body: /no-such-app|There's nothing here, yet/i },
  { service: "Azure", cname: /\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azureedge\.net|azurefd\.net)$/i, body: /404 Web Site not found|The resource you are looking for has been removed/i },
  { service: "Netlify", cname: /\.netlify\.(app|com)$/i, body: /Not Found - Request ID/i },
  { service: "Vercel", cname: /\.vercel(-dns)?\.(app|com)$/i, body: /DEPLOYMENT_NOT_FOUND|The deployment could not be found/i },
  { service: "Shopify", cname: /\.myshopify\.com$/i, body: /Sorry, this shop is currently unavailable/i },
  { service: "Zendesk", cname: /\.zendesk\.com$/i, body: /Help Center Closed/i },
  { service: "Fastly", cname: /\.fastly\.net$/i, body: /Fastly error: unknown domain/i },
  { service: "Pantheon", cname: /\.pantheonsite\.io$/i, body: /The gods are wise, but do not know of the site/i },
  { service: "Surge", cname: /\.surge\.sh$/i, body: /project not found/i },
  { service: "Bitbucket", cname: /\.bitbucket\.io$/i, body: /Repository not found/i },
  { service: "Ghost", cname: /\.ghost\.io$/i, body: /Domain error|The thing you were looking for is no longer here/i },
  { service: "Fly.io", cname: /\.fly\.dev$/i },
  { service: "Read the Docs", cname: /\.readthedocs\.io$/i, body: /unknown to Read the Docs/i },
];

export interface NameRecords {
  name: string;
  /** The CNAME chain, in order. */
  cnames: string[];
  /** Whether the end of the chain resolves to an address. */
  resolves: boolean;
  /** What the name answered over HTTP(S), when it was asked (in scope). */
  body?: string;
}

export function takeoverIssue(r: NameRecords): DnsIssue | undefined {
  const target = r.cnames[r.cnames.length - 1];
  if (!target) return undefined;
  const svc = TAKEOVER_SERVICES.find((s) => s.cname.test(target));
  const chain = [r.name, ...r.cnames].join(" → ");
  if (svc && (!r.resolves || (svc.body && r.body && svc.body.test(r.body)))) {
    return { key: `takeover:${svc.service}`, severity: "high", title: `${r.name} points at an unclaimed ${svc.service} resource (possible subdomain takeover)`, detail: `${chain}. ${!r.resolves ? "The target does not resolve" : `${svc.service} answers that the resource does not exist`}: whoever creates it on ${svc.service} serves content as ${r.name} (phishing, cookies of the parent domain). Confirm by checking the resource name is free, without claiming it.` };
  }
  if (!r.resolves) return { key: "dangling-cname", severity: "medium", title: `${r.name} has a CNAME to a name that does not exist (${target})`, detail: `${chain}. A dangling record: if that name (or its domain) can be registered or created, ${r.name} can be taken over.` };
  return undefined;
}

const COMMON_DKIM = ["default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim", "smtp", "mandrill", "mxvault", "zoho", "protonmail", "everlytickey1", "sendgrid", "amazonses", "pm", "mailjet"];

/** The records the checks need (failures read as "absent"). */
export async function lookupMail(domain: string, resolver = new Resolver({ timeout: 4000, tries: 2 })): Promise<MailRecords> {
  const txt = async (n: string) => (await resolver.resolveTxt(n).catch(() => [] as string[][])).map((parts) => parts.join(""));
  const root = await txt(domain);
  const spfs = root.filter((t) => /^v=spf1\b/i.test(t));
  const dmarc = (await txt(`_dmarc.${domain}`)).find((t) => /^v=DMARC1/i.test(t));
  const mx = (await resolver.resolveMx(domain).catch(() => [])).map((m) => m.exchange);
  const dkimSelectors: string[] = [];
  for (const sel of COMMON_DKIM) if ((await txt(`${sel}._domainkey.${domain}`)).some((t) => /p=/i.test(t))) dkimSelectors.push(sel);
  return { domain, ...(spfs[0] ? { spf: spfs[0] } : {}), spfCount: spfs.length, ...(dmarc ? { dmarc } : {}), dkimSelectors, mx };
}

export async function lookupName(name: string, resolver = new Resolver({ timeout: 4000, tries: 2 })): Promise<NameRecords> {
  const cnames: string[] = [];
  let current = name;
  for (let i = 0; i < 8; i++) {
    const next = (await resolver.resolveCname(current).catch(() => [] as string[]))[0];
    if (!next || cnames.includes(next)) break;
    cnames.push(next.replace(/\.$/, ""));
    current = next;
  }
  const resolves = (await resolver.resolve4(current).catch(() => [])).length > 0 || (await resolver.resolve6(current).catch(() => [])).length > 0;
  return { name, cnames, resolves };
}
