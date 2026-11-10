import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync, zipSync } from "fflate";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readArchive, safePath } from "../src/tools/archive.js";
import type { CatalogEntry } from "../src/tools/catalog.js";
import { versionAtLeast } from "../src/tools/catalog.js";
import { Toolbox, ToolboxError } from "../src/tools/toolbox.js";

/** A ustar archive with the given files (what Go release tools publish, gzipped). */
function tar(files: Array<{ name: string; body: string | Uint8Array; mode?: number; type?: string }>): Uint8Array {
  const blocks: Uint8Array[] = [];
  for (const f of files) {
    const body = typeof f.body === "string" ? new TextEncoder().encode(f.body) : f.body;
    const h = new Uint8Array(512);
    const put = (s: string, at: number) => h.set(new TextEncoder().encode(s), at);
    put(f.name, 0);
    put((f.mode ?? 0o755).toString(8).padStart(7, "0"), 100);
    put("0000000", 108);
    put("0000000", 116);
    put(body.length.toString(8).padStart(11, "0"), 124);
    put("00000000000", 136);
    put("        ", 148);
    put(f.type ?? "0", 156);
    put("ustar\u000000", 257);
    let sum = 0;
    for (const b of h) sum += b;
    put(sum.toString(8).padStart(6, "0") + "\u0000 ", 148);
    blocks.push(h, body, new Uint8Array((512 - (body.length % 512)) % 512));
  }
  blocks.push(new Uint8Array(1024));
  const out = new Uint8Array(blocks.reduce((n, b) => n + b.length, 0));
  let o = 0;
  for (const b of blocks) (out.set(b, o), (o += b.length));
  return out;
}

const script = (version: string) => `#!/bin/sh\necho "faketool version ${version}"\n`;
const sha = (d: Uint8Array) => createHash("sha256").update(d).digest("hex");

let dir: string;
let server: Server;
let base: string;
/** What the fake download server serves, and what it saw. */
let files: Map<string, Uint8Array>;
let seen: Array<{ url: string; range?: string }>;
/** Per path: cut the connection after this many bytes, this many times. */
let cuts: Map<string, { after: number; times: number }>;
let failAll = false;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-toolbox-"));
  files = new Map();
  seen = [];
  cuts = new Map();
  failAll = false;
  server = createServer((req, res) => {
    seen.push({ url: req.url!, ...(req.headers.range ? { range: String(req.headers.range) } : {}) });
    if (failAll) return void res.writeHead(503).end();
    if (req.url === "/redirect") return void res.writeHead(302, { location: "/tool.tar.gz" }).end();
    const data = files.get(req.url!);
    if (!data) return void res.writeHead(404).end();
    const m = /bytes=(\d+)-/.exec(String(req.headers.range ?? ""));
    const from = m ? Number(m[1]) : 0;
    const chunk = data.subarray(from);
    res.writeHead(m ? 206 : 200, { "content-length": String(chunk.length) });
    const cut = cuts.get(req.url!);
    if (cut && cut.times > 0) {
      cut.times--;
      res.write(chunk.subarray(0, cut.after));
      setTimeout(() => res.destroy(), 20);
      return;
    }
    res.end(chunk);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});

afterEach(async () => {
  await new Promise((r) => server.close(r));
  rmSync(dir, { recursive: true, force: true });
});

function publish(version: string, opts: { path?: string; corrupt?: boolean; format?: "tar.gz" | "zip"; body?: string } = {}): CatalogEntry {
  const path = opts.path ?? `/faketool-${version}.${opts.format ?? "tar.gz"}`;
  const body = opts.body ?? script(version);
  const data = opts.format === "zip" ? zipSync({ "faketool_dir/faketool": new TextEncoder().encode(body), "README.md": new TextEncoder().encode("hola") }) : gzipSync(tar([{ name: "faketool", body }, { name: "LICENSE", body: "MIT", mode: 0o644 }]));
  // A corrupted file: same size, one byte changed, so only the hash can tell.
  const served = opts.corrupt ? Uint8Array.from(data, (b, i) => (i === 40 ? b ^ 1 : b)) : data;
  files.set(path, served);
  return {
    name: "faketool",
    version,
    via: "release",
    homepage: "https://example.test",
    license: "MIT",
    binary: "faketool",
    assets: { "linux-x64": { url: `${base}${path}`, sha256: sha(data), size: data.length, format: opts.format ?? "tar.gz", bin: opts.format === "zip" ? "faketool_dir/faketool" : "faketool" } },
  };
}

const box = (catalog: CatalogEntry[], extra: Partial<ConstructorParameters<typeof Toolbox>[1]> = {}) =>
  new Toolbox(join(dir, "toolbox"), { catalog, platform: "linux-x64", allowHttp: true, retryDelayMs: 5, idleTimeoutMs: 2000, ...extra });
const verify = async (bin: string) => (execFileSync(bin, []).toString().includes("faketool version") ? undefined : "not faketool");

describe("tool box: verified installs without root", () => {
  it("downloads, verifies, unpacks and switches a tool on; it runs from bin/", async () => {
    const b = box([publish("1.0.0")]);
    const lines: string[] = [];
    const t = await b.install("faketool", { verify, onProgress: (l) => lines.push(l) });
    expect(t.version).toBe("1.0.0");
    expect(execFileSync(join(b.binDir, "faketool")).toString()).toContain("faketool version 1.0.0");
    expect(b.binaryPath("faketool")).toBeTruthy();
    expect(lines.join("\n")).toContain("SHA-256 verified");
    // Only the executable is kept; the partial download is gone.
    expect(readdirSync(join(dir, "toolbox", "pkgs", "faketool", "1.0.0"))).toEqual(["faketool"]);
    expect(readdirSync(join(dir, "toolbox", "downloads"))).toEqual([]);
  });

  it("follows redirects (GitHub sends downloads elsewhere) and reads zip archives", async () => {
    const e = publish("1.0.0", { format: "zip" });
    const b = box([e]);
    expect((await b.install("faketool", { verify })).version).toBe("1.0.0");
    const r = publish("1.0.1", { path: "/tool.tar.gz" });
    r.assets["linux-x64"]!.url = `${base}/redirect`;
    expect((await box([r]).install("faketool", { verify })).version).toBe("1.0.1");
  });

  it("never installs a file whose SHA-256 differs from the catalog, and deletes it", async () => {
    const b = box([publish("1.0.0", { corrupt: true })]);
    await expect(b.install("faketool", { verify })).rejects.toMatchObject({ code: "HASH_MISMATCH" });
    expect(b.get("faketool")).toBeUndefined();
    expect(existsSync(join(b.binDir, "faketool"))).toBe(false);
    expect(readdirSync(join(dir, "toolbox", "downloads"))).toEqual([]);
  });

  it("resumes a download cut in the middle instead of starting over", async () => {
    const e = publish("1.0.0");
    const path = new URL(e.assets["linux-x64"]!.url).pathname;
    cuts.set(path, { after: 100, times: 1 });
    const t = await box([e]).install("faketool", { verify });
    expect(t.version).toBe("1.0.0");
    expect(seen.filter((s) => s.url === path)).toEqual([{ url: path }, { url: path, range: "bytes=100-" }]);
  });

  it("gives up after its retries with a reason and what to do, and installs nothing", async () => {
    failAll = true;
    const b = box([publish("1.0.0")]);
    const err = (await b.install("faketool", { verify }).catch((e) => e)) as ToolboxError;
    expect(err.code).toBe("DOWNLOAD_FAILED");
    expect(err.hint).toMatch(/connection|proxy/i);
    expect(seen.length).toBe(5);
    expect(b.installed()).toEqual([]);
  });

  it("does not switch on a binary that does not run here", async () => {
    const b = box([publish("1.0.0", { body: "#!/bin/sh\necho something else\n" })]);
    await expect(b.install("faketool", { verify })).rejects.toMatchObject({ code: "IDENTITY_FAILED" });
    expect(b.get("faketool")).toBeUndefined();
    expect(existsSync(join(b.binDir, "faketool"))).toBe(false);
    expect(readdirSync(join(dir, "toolbox", "pkgs", "faketool"))).toEqual([]);
  });

  it("checks room and the box's limit before downloading anything", async () => {
    const e = publish("1.0.0");
    await expect(box([e], { freeSpace: () => 10 }).install("faketool")).rejects.toMatchObject({ code: "NO_SPACE" });
    await expect(box([e], { quotaBytes: 10 }).install("faketool")).rejects.toMatchObject({ code: "QUOTA" });
    expect(seen).toEqual([]);
  });

  it("refuses tools that are not in the catalog, or not for this system, and non-HTTPS URLs", async () => {
    const e = publish("1.0.0");
    await expect(box([e]).install("other")).rejects.toMatchObject({ code: "NOT_IN_CATALOG" });
    await expect(box([e], { platform: "linux-arm64" }).install("faketool")).rejects.toMatchObject({ code: "NO_ASSET" });
    await expect(box([e], { allowHttp: false }).install("faketool")).rejects.toMatchObject({ code: "DOWNLOAD_FAILED" });
  });

  it("two requests for the same tool share one download", async () => {
    const e = publish("1.0.0");
    const b = box([e]);
    const [x, y] = await Promise.all([b.install("faketool", { verify }), b.install("faketool", { verify })]);
    expect(x).toEqual(y);
    expect(seen.length).toBe(1);
  });

  it("an update keeps the previous version to go back to, and removing frees everything", async () => {
    const dirBox = join(dir, "toolbox");
    await box([publish("1.0.0")]).install("faketool", { verify });
    const b = box([publish("2.0.0")]);
    const t = await b.install("faketool", { verify });
    expect(t.previous?.version).toBe("1.0.0");
    expect(execFileSync(join(b.binDir, "faketool")).toString()).toContain("2.0.0");
    const back = b.rollback("faketool");
    expect(back.version).toBe("1.0.0");
    expect(execFileSync(join(b.binDir, "faketool")).toString()).toContain("1.0.0");
    // A third version: the oldest one goes (two at most).
    await box([publish("3.0.0")]).install("faketool", { verify });
    expect(readdirSync(join(dirBox, "pkgs", "faketool")).sort()).toEqual(["1.0.0", "3.0.0"]);
    const { freed } = b.remove("faketool");
    expect(freed).toBeGreaterThan(0);
    expect(b.get("faketool")).toBeUndefined();
    expect(existsSync(join(b.binDir, "faketool"))).toBe(false);
  });

  it("after a crash, leftovers go and a tool whose files vanished is no longer listed", async () => {
    const b = box([publish("1.0.0")]);
    await b.install("faketool", { verify });
    mkdirSync(join(dir, "toolbox", "pkgs", "faketool", ".tmp-abcd"), { recursive: true });
    writeFileSync(join(dir, "toolbox", "bin", ".tmp-faketool-1234"), "");
    rmSync(join(dir, "toolbox", "pkgs", "faketool", "1.0.0"), { recursive: true });
    const again = box([publish("1.0.0")]);
    expect(again.get("faketool")).toBeUndefined();
    expect(readdirSync(join(dir, "toolbox", "pkgs", "faketool"))).toEqual([]);
    expect(readdirSync(join(dir, "toolbox", "bin")).filter((f) => f.startsWith(".tmp-"))).toEqual([]);
  });
});

describe("diagnosis", () => {
  it("says what would keep installs from working here, and nothing when all is well", async () => {
    const ok = await box([], { freeSpace: () => 5e9, reach: async () => true }).diagnose();
    expect(ok.filter((c) => !c.ok)).toEqual([]);
    const bad = await box([], { freeSpace: () => 100e6, reach: async (u) => !u.includes("github") }).diagnose();
    expect(bad.filter((c) => !c.ok).map((c) => c.id)).toEqual(["space", "net.github"]);
  });
});

describe("a kit for networks without internet", () => {
  it("exports verified tools into one file; another box installs them with no network, checked against its own catalog", async () => {
    const entry = publish("1.0.0");
    const kit = join(dir, "herramientas.penteos-tools");
    const out = await box([entry]).exportKit(kit, { platform: "linux-x64" });
    expect(out.tools).toEqual([{ name: "faketool", version: "1.0.0", size: entry.assets["linux-x64"]!.size }]);
    // The client's network: no internet (the download server is gone).
    await new Promise((r) => server.close(r));
    server = createServer().listen(0);
    const offline = new Toolbox(join(dir, "offline"), { catalog: [entry], platform: "linux-x64", allowHttp: true, retryDelayMs: 5 });
    const r = await offline.importKit(kit, { verify });
    expect(r.installed.map((t) => t.version)).toEqual(["1.0.0"]);
    expect(execFileSync(join(offline.binDir, "faketool")).toString()).toContain("faketool version 1.0.0");
    // A box whose catalog does not have that exact file leaves it out and says so.
    const other = new Toolbox(join(dir, "other"), { catalog: [publish("2.0.0")], platform: "linux-x64", allowHttp: true });
    const r2 = await other.importKit(kit, { verify });
    expect(r2.installed).toEqual([]);
    expect(r2.skipped[0]!.reason).toMatch(/not in this Penteos's verified catalog/);
    // A kit for another platform is refused.
    await expect(new Toolbox(join(dir, "arm"), { catalog: [entry], platform: "linux-arm64" }).importKit(kit)).rejects.toMatchObject({ code: "NO_ASSET" });
  });
});

describe("archives", () => {
  it("drops links and paths that would escape the folder", () => {
    const data = tar([
      { name: "ok/tool", body: "x" },
      { name: "../evil", body: "x" },
      { name: "/etc/passwd", body: "x" },
      { name: "link", body: "", type: "2" },
    ]);
    expect(readArchive(data, "tar").map((f) => f.path)).toEqual(["ok/tool", "etc/passwd"]);
    expect(safePath("a/../../b")).toBeUndefined();
    expect(safePath("./a//b")).toBe("a/b");
  });

  it("compares versions by their numbers", () => {
    expect(versionAtLeast("1.6.10", "1.6.9")).toBe(true);
    expect(versionAtLeast("v2.0.0-dev", "2.0.0")).toBe(true);
    expect(versionAtLeast("1.5", "1.6.0")).toBe(false);
  });
});
