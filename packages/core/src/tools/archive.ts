import { execFileSync } from "node:child_process";
import { gunzipSync, unzipSync } from "fflate";

/**
 * Reading the archives tools are published in: .zip, .tar.gz and
 * plain .tar, in memory. Only regular files come out; links, devices and anything whose path
 * escapes the archive are dropped, so an archive can never write outside the folder it goes to.
 */

export type ArchiveFormat = "zip" | "tar.gz" | "tar" | "raw" | "rpm";

export interface ArchiveFile {
  /** Path inside the archive, with "/" separators, never absolute and never with "..". */
  path: string;
  data: Uint8Array;
  /** Whether the archive marks it executable (tar mode bits; zip keeps no reliable mode). */
  executable: boolean;
}

export function formatOf(name: string): ArchiveFormat {
  if (/\.rpm$/i.test(name)) return "rpm";
  if (/\.zip$/i.test(name)) return "zip";
  if (/\.(tar\.gz|tgz)$/i.test(name)) return "tar.gz";
  if (/\.tar$/i.test(name)) return "tar";
  return "raw";
}

/** A path that stays inside the archive, or undefined. */
export function safePath(raw: string): string | undefined {
  const parts = raw.replace(/\\/g, "/").split("/").filter((p) => p && p !== ".");
  if (!parts.length || parts.some((p) => p === "..") || /^[a-zA-Z]:$/.test(parts[0]!)) return undefined;
  return parts.join("/");
}

export function readArchive(data: Uint8Array, format: ArchiveFormat, name = "file"): ArchiveFile[] {
  if (format === "raw") return [{ path: name, data, executable: true }];
  if (format === "rpm") return readCpio(rpmPayload(data));
  if (format === "zip") {
    const out: ArchiveFile[] = [];
    for (const [raw, content] of Object.entries(unzipSync(data))) {
      if (raw.endsWith("/")) continue;
      const path = safePath(raw);
      if (path) out.push({ path, data: content, executable: false });
    }
    return out;
  }
  return readTar(format === "tar.gz" ? gunzipSync(data) : data);
}

/** ustar, with GNU long names and pax path records (what Go release tools produce). */
export function readTar(buf: Uint8Array): ArchiveFile[] {
  const out: ArchiveFile[] = [];
  const text = (from: number, len: number) => {
    let end = from;
    while (end < from + len && buf[end] !== 0) end++;
    return new TextDecoder().decode(buf.subarray(from, end));
  };
  const octal = (from: number, len: number) => parseInt(text(from, len).trim() || "0", 8);
  let offset = 0;
  let longName: string | undefined;
  let paxPath: string | undefined;
  while (offset + 512 <= buf.length) {
    // Two zero blocks end the archive; one is enough to stop.
    if (buf.subarray(offset, offset + 512).every((b) => b === 0)) break;
    const size = octal(offset + 124, 12);
    const type = String.fromCharCode(buf[offset + 156] || 48);
    const mode = octal(offset + 100, 8);
    const prefix = text(offset + 345, 155);
    const base = text(offset, 100);
    const start = offset + 512;
    const body = buf.subarray(start, start + size);
    offset = start + Math.ceil(size / 512) * 512;
    if (type === "L") {
      longName = new TextDecoder().decode(body).replace(/\0+$/, "");
      continue;
    }
    if (type === "x") {
      const m = /\d+ path=([^\n]*)\n/.exec(new TextDecoder().decode(body));
      paxPath = m?.[1];
      continue;
    }
    if (type === "g") continue;
    const name = paxPath ?? longName ?? (prefix ? `${prefix}/${base}` : base);
    longName = undefined;
    paxPath = undefined;
    // Regular files only: no links, directories or devices.
    if (type !== "0" && type !== "\0" && type !== "7") continue;
    const path = safePath(name);
    if (path) out.push({ path, data: body, executable: (mode & 0o111) !== 0 });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// RPM (the official nmap.org package): read without rpm, the payload unpacked here.

/** The cpio payload of an RPM: past the lead and both headers, decompressed. */
export function rpmPayload(d: Uint8Array): Uint8Array {
  const view = new DataView(d.buffer, d.byteOffset, d.byteLength);
  if (view.getUint32(0) !== 0xedabeedb) throw new Error("not an RPM file");
  const header = (off: number) => {
    if (d[off] !== 0x8e || d[off + 1] !== 0xad || d[off + 2] !== 0xe8) throw new Error("bad RPM header");
    const count = view.getUint32(off + 8);
    const size = view.getUint32(off + 12);
    const store = off + 16 + 16 * count;
    const tags = new Map<number, { type: number; at: number; n: number }>();
    for (let i = 0; i < count; i++) {
      const at = off + 16 + 16 * i;
      tags.set(view.getUint32(at), { type: view.getUint32(at + 4), at: store + view.getUint32(at + 8), n: view.getUint32(at + 12) });
    }
    return { tags, end: store + size };
  };
  const sig = header(96);
  const main = header(Math.ceil(sig.end / 8) * 8);
  const str = (tag: number) => {
    const t = main.tags.get(tag);
    if (!t) return undefined;
    let e = t.at;
    while (d[e] !== 0) e++;
    return new TextDecoder().decode(d.subarray(t.at, e));
  };
  const payload = d.subarray(main.end);
  const compressor = str(1125) ?? "gzip";
  if (compressor === "gzip") return gunzipSync(payload);
  if (compressor === "xz" || compressor === "lzma") return xzDecompress(payload);
  throw new Error(`RPM payload compressed with ${compressor}, which Penteos cannot read`);
}

/**
 * XZ, which Node does not read: the system's xz (every distribution has it: its package manager
 * needs it), else Python's lzma module. Neither there: the caller falls back to the system package.
 */
export function xzDecompress(data: Uint8Array): Uint8Array {
  const attempts: Array<[string, string[]]> = [
    ["xz", ["-dc"]],
    ["python3", ["-c", "import sys,lzma; sys.stdout.buffer.write(lzma.decompress(sys.stdin.buffer.read()))"]],
  ];
  for (const [cmd, args] of attempts) {
    try {
      return new Uint8Array(execFileSync(cmd, args, { input: data, maxBuffer: 512 * 1024 * 1024, stdio: ["pipe", "pipe", "ignore"] }));
    } catch {
      /* next */
    }
  }
  throw new Error("this package is compressed with XZ and there is no xz or python3 on this system to unpack it");
}

/** cpio "newc" (what RPM uses): regular files only, paths kept inside the archive. */
export function readCpio(buf: Uint8Array): ArchiveFile[] {
  const out: ArchiveFile[] = [];
  const text = (from: number, len: number) => new TextDecoder().decode(buf.subarray(from, from + len));
  let off = 0;
  while (off + 110 <= buf.length) {
    const magic = text(off, 6);
    if (magic !== "070701" && magic !== "070702") throw new Error("bad cpio entry");
    const field = (i: number) => parseInt(text(off + 6 + i * 8, 8), 16);
    const mode = field(1);
    const size = field(6);
    const nameSize = field(11);
    const name = text(off + 110, nameSize - 1);
    const dataAt = Math.ceil((off + 110 + nameSize) / 4) * 4;
    off = Math.ceil((dataAt + size) / 4) * 4;
    if (name === "TRAILER!!!") break;
    // Regular files only (S_IFREG): no links, devices or directories.
    if ((mode & 0o170000) !== 0o100000) continue;
    const path = safePath(name);
    if (path) out.push({ path, data: buf.subarray(dataAt, dataAt + size), executable: (mode & 0o111) !== 0 });
  }
  return out;
}
