/**
 * The Maestro mascot: the hoplite guardian in the brand palette, as pixel art the operator drew.
 * Unlike the tiny code-drawn Helmet (crisp at 16px for avatars), this is the big, full-body
 * character for the empty state - and it changes pose with what the Maestro is doing: asleep when
 * parked, at the laptop when working, dashing when it runs a batch. It breathes (a slow bob) and,
 * while active, lifts with a warm glow. Reduced-motion keeps it still.
 */
import badgeUrl from "../assets/mascot/badge-helmet.png";
import heroUrl from "../assets/mascot/hero.png";
import hackUrl from "../assets/mascot/maestro-hack.png";
import idleUrl from "../assets/mascot/maestro-idle.png";
import runUrl from "../assets/mascot/maestro-run.png";
import workUrl from "../assets/mascot/maestro-work.png";

export type MascotState = "idle" | "work" | "run" | "hack" | "hero";

const SRC: Record<MascotState, string> = {
  idle: idleUrl,
  work: workUrl,
  run: runUrl,
  hack: hackUrl,
  hero: heroUrl,
};

/**
 * The Maestro's avatar: the guardian helmet in a round badge (from the operator's sprite sheet),
 * the identity mark that sits in the panel header and menu. Still - only a soft glow while active -
 * so the header stays calm. This is "the Maestro we built", not the code-drawn placeholder helmet.
 */
export function MaestroBadge({ size = 24, active = false, title }: { size?: number; active?: boolean; title?: string }) {
  return (
    <img
      src={badgeUrl}
      alt={title ?? ""}
      className={`maestro-badge${active ? " active" : ""}`}
      style={{ width: size, height: size, imageRendering: "pixelated", display: "block", borderRadius: "50%" }}
      draggable={false}
    />
  );
}

export function Mascot({ state = "idle", size = 96, active = false, title }: { state?: MascotState; size?: number; active?: boolean; title?: string }) {
  return (
    <img
      src={SRC[state]}
      alt={title ?? ""}
      className={`mascot${active ? " active" : ""}`}
      style={{ height: size, width: "auto", imageRendering: "pixelated", display: "block" }}
      draggable={false}
    />
  );
}
