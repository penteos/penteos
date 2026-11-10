import { describe, expect, it } from "vitest";
import { argsForTool, manifestInvocation, targetForTool, validateManifest } from "../src/index.js";
import { BUILTIN_MANIFESTS } from "../src/tools/builtin-manifests.js";

/**
 * Tools that take a name (dnsx, subfinder, dig) get the host of a URL. A web test's scope is a
 * URL, and these tools given "https://…" fail or answer about nothing.
 */
const manifest = (name: string) => validateManifest(BUILTIN_MANIFESTS.find((m) => (m as { name: string }).name === name));

describe("targets in the form each tool takes", () => {
  it("name tools get the host of a URL", () => {
    const dnsx = manifest("dnsx");
    expect(targetForTool(dnsx, "https://pay.cliente.example")).toBe("pay.cliente.example");
    expect(targetForTool(dnsx, "https://Pay.Cliente.Example:8443/login?x=1")).toBe("pay.cliente.example");
    expect(targetForTool(dnsx, "pay.cliente.example")).toBe("pay.cliente.example");
    expect(manifestInvocation(dnsx, ["https://pay.cliente.example"])).toEqual(["-silent", "-a", "-aaaa", "-cname", "-resp", "-d", "pay.cliente.example"]);
    expect(manifestInvocation(manifest("subfinder"), ["https://cliente.example/"])).toEqual(["-silent", "-d", "cliente.example"]);
    expect(manifestInvocation(manifest("dig"), ["https://cliente.example"]).filter((a) => a.includes("cliente"))).toEqual(Array(6).fill("cliente.example"));
  });

  it("rewrites a command written by hand: flag values, inline values, lists and positionals", () => {
    expect(argsForTool(manifest("dnsx"), ["-silent", "-d", "https://a.cliente.example,https://b.cliente.example", "-json"])).toEqual(["-silent", "-d", "a.cliente.example,b.cliente.example", "-json"]);
    expect(argsForTool(manifest("subfinder"), ["-d=https://cliente.example", "-o", "https://not-a-target.example/out"])).toEqual(["-d=cliente.example", "-o", "https://not-a-target.example/out"]);
    expect(argsForTool(manifest("dig"), ["+noall", "+answer", "https://cliente.example", "A"])).toEqual(["+noall", "+answer", "cliente.example", "A"]);
  });

  it("leaves URL tools alone", () => {
    const httpx = manifest("httpx");
    expect(targetForTool(httpx, "https://pay.cliente.example")).toBe("https://pay.cliente.example");
    expect(argsForTool(httpx, ["-u", "https://pay.cliente.example"])).toEqual(["-u", "https://pay.cliente.example"]);
  });
});
