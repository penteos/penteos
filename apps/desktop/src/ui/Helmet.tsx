import { useEffect, useRef } from "react";

/**
 * The Penteos mascot: a chunky pixel hoplite helmet whose visor is the prompt ">_". Drawn on a
 * canvas so it stays crisp at any size, and recoloured by role (the visor and crest carry the
 * colour). When `active` (the agent is thinking or working) the visor scans and the cursor blinks,
 * with a soft glow; at rest it is still. A placeholder for the final art - same shape and roles,
 * so it swaps cleanly later.
 */

export type HelmetRole = "maestro" | "verifier";

const ARM = { out: "#0b0712", armHi: "#a594f2", armMid: "#6f5bb8", armLow: "#3f2d6e", hi: "#fff6e8" };
const VIS: Record<HelmetRole, { vis: string; visSh: string }> = {
  maestro: { vis: "#f2c438", visSh: "#c08a12" },
  verifier: { vis: "#54e58a", visSh: "#2aa85c" },
};

// Helmet body: leftmost filled column per row (symmetric around 8|9, grid 18).
const SIL: Record<number, number> = { 2: 6, 3: 5, 4: 4, 5: 3, 6: 3, 7: 3, 8: 3, 9: 3, 10: 3, 11: 4, 12: 4, 13: 5, 14: 6, 15: 7 };

function paint(canvas: HTMLCanvasElement, role: HelmetRole, frame: number, active: boolean) {
  const N = 18;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.clearRect(0, 0, N, N);
  const P = { ...ARM, ...VIS[role] };
  const put = (x: number, y: number, c: string) => {
    if (x < 0 || x >= N || y < 0 || y >= N) return;
    ctx.fillStyle = c;
    ctx.fillRect(x, y, 1, 1);
  };
  const mir = (x: number) => N - 1 - x;
  const srow = (xL: number, xR: number, y: number, c: string) => {
    for (let x = xL; x <= xR; x++) {
      put(x, y, c);
      put(mir(x), y, c);
    }
  };
  const row = (x0: number, x1: number, y: number, c: string) => {
    for (let x = x0; x <= x1; x++) put(x, y, c);
  };

  for (const ys in SIL) srow(SIL[+ys]!, 8, +ys, P.out);
  for (let y = 3; y <= 14; y++) if (SIL[y] !== undefined) srow(SIL[y]! + 1, 8, y, P.armMid);
  for (let y = 3; y <= 5; y++) srow(SIL[y]! + 1, 8, y, P.armHi);
  for (let y = 12; y <= 14; y++) srow(SIL[y]! + 1, 8, y, P.armLow);
  srow(6, 8, 1, P.out);
  srow(6, 8, 2, P.vis);
  for (let y = 6; y <= 8; y++) srow(5, 8, y, P.vis);
  srow(5, 8, 8, P.visSh);
  for (const x of [4, mir(4)]) { put(x, 6, P.out); put(x, 7, P.out); put(x, 8, P.out); }
  row(5, 12, 5, P.out);
  row(5, 12, 9, P.out);
  // the prompt ">_" as the visor reflections
  put(5, 6, P.hi);
  put(6, 7, P.hi);
  put(5, 8, P.hi);
  const blinkOn = !active || Math.floor(frame / 32) % 2 === 0; // cursor blinks while thinking
  if (blinkOn) row(11, 12, 8, P.hi);
  if (active) {
    const sx = 5 + ((frame >> 2) % 8); // a bright point scanning across the visor
    put(sx, 7, P.hi);
  }
  // lower face: nasal guard + mouth
  srow(8, 8, 11, P.armMid);
  srow(8, 8, 12, P.armLow);
  row(6, 11, 11, P.out);
}

export function Helmet({ size = 24, role = "maestro", active = false, title }: { size?: number; role?: HelmetRole; active?: boolean; title?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    c.width = 18;
    c.height = 18;
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!active || reduce) {
      paint(c, role, 0, false);
      return;
    }
    let raf = 0;
    let frame = 0;
    const loop = () => {
      paint(c, role, frame++, true);
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, [role, active]);
  return <canvas ref={ref} width={18} height={18} className={`helmet${active ? " think" : ""}`} style={{ width: size, height: size, imageRendering: "pixelated", display: "block" }} role="img" aria-label={title} />;
}
