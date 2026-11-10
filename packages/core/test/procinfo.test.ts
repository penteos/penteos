import { describe, expect, it } from "vitest";
import { parseCpuTime, parseLsof, parsePs, treeOf } from "../src/plugins/procinfo.js";

/** macOS has no /proc: what a plugin's processes do comes from ps and lsof, read here as macOS prints them. */
const PS = [
  "    1     0  12345   3:01.27 /sbin/launchd",
  "  501     1 182400   0:02.10 /Applications/Penteos.app/Contents/MacOS/Penteos /Applications/Penteos.app/Contents/Resources/core/core.mjs --data-dir /Users/ana/Library/Application Support/Penteos",
  "  640   501  64000   0:00.85 /Applications/Penteos.app/Contents/MacOS/Penteos /Users/ana/Library/Application Support/Penteos/plugin-host/runner.mjs main.mjs",
  "  641   640   9800   0:00.03 /usr/bin/curl -s https://api.lab.test/ip",
  "  642   641   1200 1:02:03.50 sleep 30",
  "  700     1   5000   2-01:00:00 /usr/sbin/syslogd",
  "garbage line",
].join("\n");

describe("ps (macOS)", () => {
  it("reads CPU time in every format ps uses", () => {
    expect(parseCpuTime("0:00.12")).toBe(120);
    expect(parseCpuTime("12:34.56")).toBe(754560);
    expect(parseCpuTime("1:02:03.50")).toBe(3723500);
    expect(parseCpuTime("2-01:00:00")).toBe(176400000);
    expect(parseCpuTime("x:y")).toBeNaN();
  });

  it("reads the table, commands with their spaces, and the tree under a process", () => {
    const rows = parsePs(PS);
    expect(rows).toHaveLength(6);
    expect(rows[1]!.command).toContain("Application Support/Penteos");
    expect(rows.find((r) => r.pid === 640)).toMatchObject({ ppid: 501, rssKb: 64000, cpuMs: 850 });
    expect(treeOf(rows, 640)).toEqual([640, 641, 642]);
    expect(treeOf(rows, 999)).toEqual([999]);
  });
});

describe("lsof (macOS)", () => {
  it("keeps the remote end of established connections, leaving loopback out", () => {
    const out = parseLsof(["p641", "f5", "n10.0.0.5:51234->203.0.113.9:443", "f6", "n127.0.0.1:50000->127.0.0.1:8899", "f7", "n[2001:db8::5]:50001->[2001:DB8::1]:8443", "n[::1]:5000->[::1]:6000", "n*:5353"].join("\n"));
    expect(out).toEqual([
      { ip: "203.0.113.9", port: 443 },
      { ip: "2001:db8::1", port: 8443 },
    ]);
  });
});
