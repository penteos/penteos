import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { zipSync } from "fflate";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { installPackage, packPlugin } from "../src/index.js";

/** A plugin as one file: packed, and never trusted when unpacked. */

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-pack-"));
  mkdirSync(join(dir, "src", "acme.x"), { recursive: true });
  mkdirSync(join(dir, "plugins"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const manifest = { id: "acme.x", name: "X", version: "1.2.0", apiVersion: 1, level: "code", main: "main.mjs", author: { type: "human" }, permissions: [] };
const enc = (s: string) => new TextEncoder().encode(s);

describe("packing", () => {
  it("packs a valid folder and unpacks it as <id>/, the same files", () => {
    const src = join(dir, "src", "acme.x");
    writeFileSync(join(src, "plugin.json"), JSON.stringify(manifest));
    writeFileSync(join(src, "main.mjs"), "export async function activate() {}");
    mkdirSync(join(src, ".git"));
    writeFileSync(join(src, ".git", "HEAD"), "x");
    const packed = packPlugin(src);
    expect(packed.name).toBe("acme.x-1.2.0.penteos-plugin");
    expect(packed.files).toBe(2);
    expect(installPackage(packed.bytes, join(dir, "plugins")).id).toBe("acme.x");
    expect(readdirSync(join(dir, "plugins", "acme.x")).sort()).toEqual(["main.mjs", "plugin.json"]);
  });

  it("refuses to pack an invalid manifest, a missing main, or a link", () => {
    const src = join(dir, "src", "acme.x");
    writeFileSync(join(src, "plugin.json"), JSON.stringify({ ...manifest, permissions: ["bogus"] }));
    expect(() => packPlugin(src)).toThrow(/does not validate/);
    writeFileSync(join(src, "plugin.json"), JSON.stringify(manifest));
    expect(() => packPlugin(src)).toThrow(/main main.mjs is not in the folder/);
    writeFileSync(join(src, "main.mjs"), "x");
    symlinkSync("/etc/hostname", join(src, "link.txt"));
    expect(() => packPlugin(src)).toThrow(/is a link/);
  });
});

describe("unpacking someone else's file", () => {
  const zip = (files: Record<string, string>) => zipSync(Object.fromEntries(Object.entries(files).map(([k, v]) => [k, enc(v)])));

  it("refuses names that leave the folder", () => {
    for (const evil of ["../escape.txt", "/etc/evil", "a/../../escape.txt"]) {
      expect(() => installPackage(zip({ "plugin.json": JSON.stringify(manifest), "main.mjs": "x", [evil]: "x" }), join(dir, "plugins"))).toThrow(/unsafe file name/);
    }
    expect(existsSync(join(dir, "escape.txt"))).toBe(false);
  });

  it("refuses a zip bomb before expanding it, and too many files", () => {
    const bomb = zip({ "plugin.json": JSON.stringify(manifest), "main.mjs": "x", "big.txt": "0".repeat(4000) });
    expect(() => installPackage(bomb, join(dir, "plugins"), { files: 100, bytes: 1024 })).toThrow(/more than 1024 bytes once unpacked/);
    const many = zip(Object.fromEntries([["plugin.json", JSON.stringify(manifest)], ...Array.from({ length: 6 }, (_, i) => [`f${i}.txt`, "x"])]));
    expect(() => installPackage(many, join(dir, "plugins"), { files: 5, bytes: 1_000_000 })).toThrow(/more than 5 files/);
    expect(readdirSync(join(dir, "plugins"))).toEqual([]);
  });

  it("refuses garbage, a missing or invalid manifest, and leaves nothing behind", () => {
    expect(() => installPackage(enc("not a zip"), join(dir, "plugins"))).toThrow(/not a valid plugin package/);
    expect(() => installPackage(zip({ "main.mjs": "x" }), join(dir, "plugins"))).toThrow(/no plugin.json/);
    expect(() => installPackage(zip({ "plugin.json": "{nope" }), join(dir, "plugins"))).toThrow(/not valid JSON/);
    expect(() => installPackage(zip({ "plugin.json": JSON.stringify({ ...manifest, id: "Bad Id" }) }), join(dir, "plugins"))).toThrow(/does not validate/);
    expect(readdirSync(join(dir, "plugins"))).toEqual([]);
  });

  it("an update replaces the earlier copy", () => {
    installPackage(zip({ "plugin.json": JSON.stringify(manifest), "main.mjs": "v1", "old.txt": "x" }), join(dir, "plugins"));
    installPackage(zip({ "plugin.json": JSON.stringify({ ...manifest, version: "1.3.0" }), "main.mjs": "v2" }), join(dir, "plugins"));
    expect(readdirSync(join(dir, "plugins", "acme.x")).sort()).toEqual(["main.mjs", "plugin.json"]);
    expect(readFileSync(join(dir, "plugins", "acme.x", "main.mjs"), "utf8")).toBe("v2");
  });
});
