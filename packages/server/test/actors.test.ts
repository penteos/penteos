import { Actor } from "@penteos/schema";
import { describe, expect, it } from "vitest";
import { AGENT, HUMAN, MAESTRO } from "../src/actors.js";

describe("built-in actors", () => {
  // Actors are stored inside entities (finding owner/reviewer), where their ids are validated.
  it.each([HUMAN, AGENT, MAESTRO])("$actor.id is a valid actor", (caller) => {
    expect(Actor.safeParse(caller.actor).success).toBe(true);
  });
});
