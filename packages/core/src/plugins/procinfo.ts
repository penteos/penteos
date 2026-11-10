import { spawnSync } from "node:child_process";

/**
 * What a plugin's processes are doing, on macOS: there is no /proc, so the same facts come from
 * `ps` (the process tree, each command, CPU time and resident memory) and `lsof` (established TCP
 * connections). The parsers are pure and tested on any system with real macOS output; only the
 * two small runners below touch the machine.
 */

export interface ProcRow {
  pid: number;
  ppid: number;
  /** CPU time used so far, in ms. */
  cpuMs: number;
  /** Resident memory, in KB. */
  rssKb: number;
  command: string;
}

/** "0:00.12", "12:34.56", "1:02:03.45", "2-01:02:03" (ps TIME): milliseconds. */
export function parseCpuTime(text: string): number {
  const [days, rest] = text.includes("-") ? [Number(text.split("-")[0]), text.split("-")[1]!] : [0, text];
  const parts = rest.split(":").map(Number);
  if (parts.some((p) => !Number.isFinite(p))) return NaN;
  let seconds = 0;
  for (const p of parts) seconds = seconds * 60 + p;
  return Math.round((days * 86400 + seconds) * 1000);
}

/** `ps -axo pid=,ppid=,rss=,time=,command=` → rows (headers off, the command keeps its spaces). */
export function parsePs(text: string): ProcRow[] {
  const rows: ProcRow[] = [];
  for (const line of text.split("\n")) {
    const m = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/.exec(line);
    if (!m) continue;
    const cpuMs = parseCpuTime(m[4]!);
    if (!Number.isFinite(cpuMs)) continue;
    rows.push({ pid: Number(m[1]), ppid: Number(m[2]), rssKb: Number(m[3]), cpuMs, command: m[5]!.trim().slice(0, 300) });
  }
  return rows;
}

/** A process and everything under it, from a ps table (at most 64, like the Linux reader). */
export function treeOf(rows: ProcRow[], root: number): number[] {
  const out = [root];
  for (let i = 0; i < out.length && out.length < 64; i++) {
    for (const r of rows) if (r.ppid === out[i] && !out.includes(r.pid)) out.push(r.pid);
  }
  return out;
}

/** `lsof -Fn` lines: "n10.0.0.5:51234->203.0.113.9:443", "n[::1]:5000->[2001:db8::1]:443". Remote ends, loopback left out. */
export function parseLsof(text: string): Array<{ ip: string; port: number }> {
  const out = new Map<string, { ip: string; port: number }>();
  for (const line of text.split("\n")) {
    if (!line.startsWith("n") || !line.includes("->")) continue;
    const remote = line.slice(line.indexOf("->") + 2).trim();
    const m = /^\[([0-9a-fA-F:.]+)\]:(\d+)$/.exec(remote) ?? /^([0-9.]+):(\d+)$/.exec(remote);
    if (!m) continue;
    const ip = m[1]!.toLowerCase();
    if (ip.startsWith("127.") || ip === "::1" || ip === "0:0:0:0:0:0:0:1") continue;
    out.set(`${ip}:${m[2]}`, { ip, port: Number(m[2]) });
  }
  return [...out.values()];
}

let cached: { at: number; rows: ProcRow[] } | undefined;

/** The machine's process table (macOS), read at most every 200 ms: several readers share one ps. */
export function psTable(): ProcRow[] {
  if (cached && Date.now() - cached.at < 200) return cached.rows;
  const r = spawnSync("ps", ["-axo", "pid=,ppid=,rss=,time=,command="], { encoding: "utf8", timeout: 3000, maxBuffer: 16 * 1024 * 1024 });
  const rows = r.status === 0 ? parsePs(r.stdout) : [];
  cached = { at: Date.now(), rows };
  return rows;
}

/** Established TCP connections of these processes to other machines (macOS, lsof). */
export function lsofConnections(pids: number[]): Array<{ ip: string; port: number }> {
  if (!pids.length) return [];
  const r = spawnSync("lsof", ["-a", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-p", pids.join(","), "-Fn"], { encoding: "utf8", timeout: 3000 });
  // lsof exits 1 when it finds nothing: that is an answer, not an error.
  return r.stdout ? parseLsof(r.stdout) : [];
}
