import type { RiskLevel } from "@penteos/schema";

/**
 * nmap adapter (level 1 tool): knows where the targets are in the
 * arguments and how risky a given invocation is.
 */

/** Options that take a separate value argument. */
const VALUE_OPTIONS = new Set([
  "-p", "-oX", "-oN", "-oG", "-oA", "-oS", "-oM", "-iL", "-iR", "-e", "-S", "-D", "-g",
  "--script", "--script-args", "--script-args-file", "--top-ports", "--port-ratio", "--min-rate", "--max-rate",
  "--exclude", "--excludefile", "--dns-servers", "--source-port", "--data-length", "--data", "--data-string",
  "--max-retries", "--host-timeout", "--scan-delay", "--max-scan-delay", "--min-hostgroup", "--max-hostgroup",
  "--min-parallelism", "--max-parallelism", "--min-rtt-timeout", "--max-rtt-timeout", "--initial-rtt-timeout",
  "--version-intensity", "--ttl", "--proxies", "--datadir", "--stylesheet", "--resume", "--spoof-mac", "--mtu",
  "--exclude-ports", "--servicedb", "--versiondb", "--stats-every", "--defeat-icmp-ratelimit",
]);

export const NMAP_PRESETS: Record<string, { args: string[]; risk: RiskLevel; title: string }> = {
  quick: { args: ["-sV", "--top-ports", "100", "-T4"], risk: "active", title: "Top 100 ports with versions" },
  "service-scan": { args: ["-sV", "-T4"], risk: "active", title: "Default ports with versions" },
  full: { args: ["-sV", "-p-", "-T4"], risk: "active", title: "All TCP ports with versions" },
  scripts: { args: ["-sV", "-sC", "-T4"], risk: "intrusive", title: "Versions and default NSE scripts" },
};

export interface NmapInvocation {
  targets: string[];
  /** Set when targets cannot be determined from the arguments. */
  unchecked?: string;
  risk: RiskLevel;
}

function expandPorts(spec: string): number[] | undefined {
  if (spec === "-" || spec.includes("*")) return undefined;
  const ports: number[] = [];
  for (const raw of spec.split(",")) {
    const part = raw.replace(/^[TUS]:/, "");
    const [a, b] = part.split("-").map(Number);
    if (a === undefined || Number.isNaN(a)) return undefined;
    const end = b === undefined ? a : Number.isNaN(b) ? 65535 : b;
    for (let p = a; p <= end; p++) {
      ports.push(p);
      if (ports.length > 20) return undefined; // too many to list: treat as "any port"
    }
  }
  return ports;
}

export function analyzeNmapArgs(argv: string[]): NmapInvocation {
  const hosts: string[] = [];
  let ports: number[] | undefined;
  let unchecked: string | undefined;
  let risk: RiskLevel = "active";

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg.startsWith("-")) {
      const [name, inline] = arg.startsWith("--") ? arg.split("=", 2) : [arg.length > 2 && arg.startsWith("-p") ? "-p" : arg, arg.startsWith("-p") && arg.length > 2 ? arg.slice(2) : undefined];
      const takesValue = VALUE_OPTIONS.has(name!);
      const value = takesValue ? (inline ?? argv[++i]) : inline;

      if (name === "-iL") unchecked = `targets read from file ${value ?? ""}`.trim();
      if (name === "-iR") unchecked = "random targets (-iR)";
      if (name === "-p" && value) ports = expandPorts(value);
      if (name === "-sC" || name === "-A" || name === "--script") risk = "intrusive";
      if (name === "-sL" && risk === "active") risk = "passive";
      continue;
    }
    hosts.push(arg);
  }

  if (hosts.length === 0 && !unchecked) unchecked = "no targets in the command line";
  const targets = ports
    ? hosts.flatMap((h) => (h.includes("/") ? [h] : ports!.map((p) => `${h.includes(":") ? `[${h}]` : h}:${p}`)))
    : hosts;
  return { targets, risk, ...(unchecked ? { unchecked } : {}) };
}
