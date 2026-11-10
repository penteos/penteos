import { expect, it } from "vitest";
import { type AgentEvent, foldDelta } from "../src/agents/types.js";

it("a notice arriving mid-message does not cut the agent's text in two", () => {
  const events: AgentEvent[] = [{ kind: "text", text: "Aplicación: [@Northwind" }, { kind: "notice", text: "El operador aceptó pasar a la fase «Mapeo»." }];
  foldDelta(events, "](penteos:entity/01M5) - SPA de Vite");
  expect(events).toEqual([
    { kind: "text", text: "Aplicación: [@Northwind](penteos:entity/01M5) - SPA de Vite" },
    { kind: "notice", text: "El operador aceptó pasar a la fase «Mapeo»." },
  ]);
  // After a tool call the next text is a new message.
  events.push({ kind: "tool", id: "t", name: "x", input: {}, status: "ok" });
  foldDelta(events, "Otro");
  expect(events.at(-1)).toEqual({ kind: "text", text: "Otro" });
});
