import { type IngestBatch, type IngestItem, INGEST_FORMAT, isIp, normalizeFqdn } from "@penteos/schema";
import { XMLParser } from "fast-xml-parser";

export const PARSER_ID = "nmap-xml@0.1.0";

export interface ParseOptions {
  rawIds: string[];
  runId?: string;
  networkContext?: string;
}

type Node = Record<string, unknown>;

const ARRAYS = new Set(["host", "port", "address", "hostname", "osmatch", "script"]);

const xml = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "",
  isArray: (name) => ARRAYS.has(name),
});

function list(value: unknown): Node[] {
  return Array.isArray(value) ? (value as Node[]) : [];
}

function node(value: unknown): Node | undefined {
  return value && typeof value === "object" ? (value as Node) : undefined;
}

function str(value: unknown): string | undefined {
  return value === undefined || value === null || value === "" ? undefined : String(value);
}

function epochToIso(value: unknown): string | undefined {
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds > 0 ? new Date(seconds * 1000).toISOString() : undefined;
}

/**
 * Parses nmap XML output (`-oX`) into an ingest batch. Deterministic: same XML, same batch.
 * Partial XML from an interrupted scan is accepted as long as it parses.
 */
export function parseNmapXml(content: string, options: ParseOptions): IngestBatch {
  const doc = node(xml.parse(content));
  const run = node(doc?.nmaprun);
  if (!run) throw new Error("not an nmap XML document (missing <nmaprun>)");

  const items: IngestItem[] = [];
  const startedAt = epochToIso(run.start) ?? new Date().toISOString();

  for (const host of list(run.host)) {
    const addresses = list(host.address);
    const ip = addresses.find((a) => a.addrtype === "ipv4" || a.addrtype === "ipv6")?.addr;
    if (typeof ip !== "string" || !isIp(ip)) continue;
    const mac = str(addresses.find((a) => a.addrtype === "mac")?.addr);
    const hostKey = { ip };

    const hostnames = list(node(host.hostnames)?.hostname);
    const names: string[] = [];
    for (const h of hostnames) {
      try {
        names.push(normalizeFqdn(String(h.name)));
      } catch {
        // nmap sometimes reports names that are not valid DNS (NetBIOS); keep them out of Domain.
      }
    }

    const osMatch = list(node(host.os)?.osmatch)[0];
    const state = str(node(host.status)?.state);

    items.push({
      op: "upsert",
      kind: "host",
      key: hostKey,
      attributes: {
        status: state === "up" ? "up" : state === "down" ? "down" : "unknown",
        hostnames: [...new Set(names)],
        ...(mac ? { mac } : {}),
        ...(osMatch
          ? { os: { name: String(osMatch.name), confidence: Math.min(1, Number(osMatch.accuracy ?? 0) / 100) } }
          : {}),
      },
      confidence: 1,
    });

    for (const h of hostnames) {
      let fqdn: string;
      try {
        fqdn = normalizeFqdn(String(h.name));
      } catch {
        continue;
      }
      items.push({ op: "upsert", kind: "domain", key: { fqdn } });
      // "user" = the name the operator scanned, which resolved to this IP. PTR names don't imply that.
      if (h.type === "user") {
        items.push({
          op: "relate",
          type: "resolves_to",
          from: { kind: "domain", key: { fqdn } },
          to: { kind: "host", key: hostKey },
        });
      }
    }

    for (const port of list(node(host.ports)?.port)) {
      const transport = port.protocol === "udp" ? "udp" : port.protocol === "tcp" ? "tcp" : undefined;
      const portNumber = Number(port.portid);
      if (!transport || !Number.isInteger(portNumber)) continue;

      const service = node(port.service);
      const tls = service?.tunnel === "ssl" || service?.name === "https" ? true : undefined;
      let protocol = str(service?.name);
      if (protocol === "https") protocol = "http";
      const product = str(service?.product);
      const version = [str(service?.version), str(service?.extrainfo) && `(${service?.extrainfo})`]
        .filter(Boolean)
        .join(" ");
      const conf = Number(service?.conf);
      // nmap's own CPE for the service (e.g. cpe:/a:openbsd:openssh:8.2p1): the precise key for
      // matching known vulnerabilities. Prefer the application CPE over the OS one.
      const cpes = (Array.isArray(service?.cpe) ? service!.cpe : service?.cpe !== undefined ? [service.cpe] : []).map((c) => String(c));
      const cpe = cpes.find((c) => c.startsWith("cpe:/a:") || c.startsWith("cpe:2.3:a:")) ?? cpes[0];

      const serviceKey = { ip, transport, port: portNumber };
      items.push({
        op: "upsert",
        kind: "service",
        key: serviceKey,
        attributes: {
          state: str(node(port.state)?.state) ?? "open",
          ...(protocol ? { protocol } : {}),
          ...(product ? { product } : {}),
          ...(version ? { version } : {}),
          ...(cpe ? { cpe } : {}),
          ...(tls ? { tls } : {}),
        },
        confidence: Number.isFinite(conf) && conf > 0 ? Math.min(1, conf / 10) : 0.8,
      });
      items.push({
        op: "relate",
        type: "runs_on",
        from: { kind: "service", key: serviceKey },
        to: { kind: "host", key: hostKey },
      });
    }
  }

  return {
    format: INGEST_FORMAT,
    source: { parser: PARSER_ID, tool: "nmap", ...(str(run.version) ? { toolVersion: String(run.version) } : {}) },
    ...(options.runId ? { runId: options.runId } : {}),
    rawIds: options.rawIds,
    ...(options.networkContext ? { networkContext: options.networkContext } : {}),
    observedAt: startedAt,
    items,
  };
}
