import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { adaptNmap, canAskPassword, captureState, forgetCaptureState, setcapCommand, systemInstallArgv } from "../src/tools/system.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  forgetCaptureState();
});

/** A stand-in nmap: with --privileged it either works (has the capability) or refuses. */
function fakeNmap(capability: boolean): string {
  const d = mkdtempSync(join(tmpdir(), "penteos-sys-"));
  dirs.push(d);
  const p = join(d, "nmap");
  writeFileSync(p, capability ? '#!/bin/sh\necho "Nmap done: 1 IP address"\n' : '#!/bin/sh\necho "Operation not permitted" >&2; exit 1\n', { mode: 0o755 });
  chmodSync(p, 0o755);
  return p;
}

describe("nmap without root", () => {
  it("without the capture permission: SYN becomes connect, -A keeps versions and scripts, raw-only options go, and it says so", () => {
    const r = adaptNmap(["-sS", "-A", "-O", "-sU", "-p", "80", "10.0.0.1"], "none");
    expect(r.argv).toEqual(["-sT", "-sV", "-sC", "-p", "80", "10.0.0.1"]);
    expect(r.changes).toEqual(["-sS → -sT", "-A → -sV -sC (no OS detection or traceroute)", "without -O", "without -sU"]);
  });

  it("with the permission it is told to use it (--privileged); as root nothing changes", () => {
    expect(adaptNmap(["-sS", "x"], "capability").argv).toEqual(["--privileged", "-sS", "x"]);
    expect(adaptNmap(["-sS", "x"], "root")).toEqual({ argv: ["-sS", "x"], changes: [] });
  });

  it("asks nmap itself whether the permission works (a nosuid folder answers 'none')", () => {
    if (process.getuid?.() === 0) return;
    expect(captureState(fakeNmap(true))).toBe("capability");
    expect(captureState(fakeNmap(false))).toBe("none");
  });

  it("never opens a password window unless the desktop app said a person is there", () => {
    const before = { flag: process.env.PENTEOS_PASSWORD_PROMPTS, display: process.env.DISPLAY };
    try {
      process.env.DISPLAY = ":0";
      delete process.env.PENTEOS_PASSWORD_PROMPTS;
      expect(canAskPassword()).toBe(false);
    } finally {
      if (before.flag === undefined) delete process.env.PENTEOS_PASSWORD_PROMPTS;
      else process.env.PENTEOS_PASSWORD_PROMPTS = before.flag;
      if (before.display === undefined) delete process.env.DISPLAY;
      else process.env.DISPLAY = before.display;
    }
  });

  it("the exact commands a person allows with their password", () => {
    expect(setcapCommand("/opt/x/nmap")).toEqual(["setcap", "cap_net_raw,cap_net_admin,cap_net_bind_service+eip", "/opt/x/nmap"]);
    expect(systemInstallArgv("apt", "nmap")).toEqual(["apt-get", "install", "-y", "nmap"]);
    expect(systemInstallArgv("pacman", "nmap")).toEqual(["pacman", "-S", "--needed", "--noconfirm", "nmap"]);
  });
});
