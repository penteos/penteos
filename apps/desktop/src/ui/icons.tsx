import * as L from "lucide-react";
import type { CSSProperties, ReactElement, SVGProps } from "react";
import badgeUrl from "../assets/app-badge.png";

/**
 * Penteos's own icons: angular, monoline, chamfered at 45° like the penteos in the mark - never
 * rounded. The most visible ones are drawn here; the rest come from Lucide redrawn with mitred
 * joins and square caps so they speak the same language. Same names and props as lucide-react,
 * so every screen imports from here instead.
 */

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "ref"> {
  size?: number | string;
  color?: string;
  strokeWidth?: number | string;
  className?: string;
  style?: CSSProperties;
}

type Icon = (props: IconProps) => ReactElement;

function draw(d: string, extra?: (p: IconProps) => ReactElement | null): Icon {
  const Comp = ({ size = 24, color = "currentColor", strokeWidth = 1.5, className, style, ...rest }: IconProps) => (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={strokeWidth}
      strokeLinejoin="miter"
      strokeLinecap="square"
      className={`bi ${className ?? ""}`}
      style={style}
      aria-hidden={rest["aria-label"] ? undefined : true}
      {...rest}
    >
      <path d={d} />
      {extra ? extra({ size, color, strokeWidth }) : null}
    </svg>
  );
  return Comp;
}

/** A Lucide icon in Penteos's language: mitred corners, square ends, a thinner line. */
function angular(I: L.LucideIcon): Icon {
  const Comp = ({ strokeWidth = 1.5, className, ...rest }: IconProps) => (
    <I strokeWidth={Number(strokeWidth)} strokeLinejoin="miter" strokeLinecap="square" className={`bi ${className ?? ""}`} {...(rest as L.LucideProps)} />
  );
  return Comp;
}

// The chamfered "circle" of this set: an octagon.
const O = "M8.5 3h7L21 8.5v7L15.5 21h-7L3 15.5v-7z";
const DOC = "M6 3h9l4 4v13l-1 1H6l-1-1V4z";
const BOX = "M5 4h14l1 1v14l-1 1H5l-1-1V5z";
const HEAD = "M9 4h6l1 1v4l-1 1H9L8 9V5z M4 21v-4l2-3h12l2 3v4";

// --- sections ------------------------------------------------------------------------------
export const House = draw("M4 21V11l8-7 8 7v10h-5.5v-5h-5v5z");
export const Shield = draw("M12 3l7.5 3v6.5L17 17l-5 4-5-4-2.5-4.5V6z");
export const ShieldCheck = draw("M12 3l7.5 3v6.5L17 17l-5 4-5-4-2.5-4.5V6z M8.5 12l2.5 2.5 4.5-5");
export const ShieldAlert = draw("M12 3l7.5 3v6.5L17 17l-5 4-5-4-2.5-4.5V6z M12 8v5 M12 15.5v.5");
export const ShieldOff = draw("M12 3l7.5 3v6.5L17 17l-5 4-5-4-2.5-4.5V6z M3 3l18 18");
export const AppWindow = draw("M6 4h12l2 2v12l-2 2H6l-2-2V6z M4 9h16");
export const Monitor = draw("M5 4h14l1 1v10l-1 1H5l-1-1V5z M9 20h6 M12 16v4");
export const Grid3x3 = draw("M6 4h12l2 2v12l-2 2H6l-2-2V6z M4 10h16 M4 15h16 M10 4v16 M15 4v16");
export const LayoutGrid = draw("M4 4h7v7H4z M13 4h7v7h-7z M4 13h7v7H4z M13 13h7v7h-7z");
export const Network = draw("M9 3h6v5H9z M4 16h5v5H4z M15 16h5v5h-5z M12 8v4 M6.5 12h11 M6.5 12v4 M17.5 12v4");
export const Globe = draw(`${O} M3 12h18 M12 3 9 7.5v9L12 21 M12 3l3 4.5v9L12 21`);
export const Radar = draw("M9 4h6l5 5v6l-5 5H9l-5-5V9z M11 9h2l2 2v2l-2 2h-2l-2-2v-2z");
export const Server = draw("M5 4h14l1 1v4l-1 1H5L4 9V5z M5 14h14l1 1v4l-1 1H5l-1-1v-4z M7.5 7h1 M7.5 17h1");
export const Database = draw("M5 5l2-2h10l2 2v14l-2 2H7l-2-2z M5 9l2 2h10l2-2 M5 14l2 2h10l2-2");
export const Bug = draw("M12 3l9 16-1 1H4l-1-1z M12 9v5 M12 16.5v.5");
export const AlertTriangle = Bug;
export const KeyRound = draw("M14 4h4l2 2v4l-2 2h-4l-2-2V6z M12.5 10.5 4 19v1h3v-2h2v-2h2l2.5-2.5");
export const KanbanSquare = draw(`${BOX} M9.5 4v16 M14.5 4v10`);
export const NotebookPen = draw(`${DOC} M9 11h6 M9 15h4`);
export const Brain = draw("M8 6h8l2 2v8l-2 2H8l-2-2V8z M10 3v3 M14 3v3 M10 18v3 M14 18v3 M3 10h3 M3 14h3 M18 10h3 M18 14h3");
export const Cpu = Brain;
export const FileText = draw(`${DOC} M9 12h6 M9 16h6`);
export const ScrollText = draw(`${DOC} M9 8h4 M9 12h6 M9 16h6`);
export const FileCheck2 = draw(`${DOC} M8.5 14l2.5 2.5 4.5-5`);
export const FileWarning = draw(`${DOC} M12 9v5 M12 16.5v.5`);
export const FileCode2 = draw(`${DOC} M10 11l-2 2 2 2 M14 11l2 2-2 2`);
export const Wrench = draw("M14 3h5l2 2v3l-3 3h-3l-8 8-3-3 8-8V5z");
export const Users = draw("M6 4h5l1 1v3l-1 1H6L5 8V5z M2 20v-4l2-3h9l2 3v4 M15 4h3l1 1v3l-1 1h-3 M17 13h2l2 3v4");
export const User = draw(HEAD);
export const UserRound = User;
export const UserPlus = draw(`${HEAD} M19 3v6 M16 6h6`);
export const UserCheck = draw(`${HEAD} M16 6l2 2 4-4`);
// The agent icon is the Penteos mark itself: a hoplite helmet whose visor is the prompt ">_".
export const Bot = draw("M6 19 L5 10 L9 5 H15 L19 10 L18 19 M11.5 5 L12 2.5 L12.5 5 M7 11 H17 M12 11 V18 M8 12.4 L9.3 13.1 L8 13.8 M14.5 13.5 H16.2");
export const Crown = draw("M4 18l2-10 4 4 2-6 2 6 4-4 2 10z M4 21h16");
export const Crosshair = draw(`${O} M12 3v5 M12 16v5 M3 12h5 M16 12h5`);
export const Route = draw("M6 19h7l2-2v-2l-2-2h-2L9 11V9l2-2h7 M3 17h4v4H3z M17 3h4v4h-4z");
export const GitCompareArrows = draw("M4 7h14 M15 4l3 3-3 3 M20 17H6 M9 14l-3 3 3 3");
export const GitBranch = draw("M6 3v18 M6 15l6-6h6 M15 6l3 3-3 3");
export const History = draw("M3 12V8.5L8.5 3h7L21 8.5v7L15.5 21h-7L5 17.5 M12 7v5l3 3 M3 4v5h5");
export const SquareTerminal = draw(`${BOX} M8 9l3 3-3 3 M13 15h4`);
export const TerminalSquare = SquareTerminal;
export const BookOpen = draw("M3 5h6l3 2 3-2h6v14h-6l-3 2-3-2H3z M12 7v14");
export const BookPlus = draw("M5 3h13l1 1v16l-1 1H5l-1-1V4z M12 8v6 M9 11h6");
export const Calculator = draw(`${BOX} M8 8h8 M8 12h.5 M12 12h.5 M16 12h.5 M8 16h.5 M12 16h.5 M16 16h.5`);

// --- actions -------------------------------------------------------------------------------
export const Check = draw("M5 12.5l4.5 4.5L19 7.5");
export const CheckCheck = draw("M2 12.5l4.5 4.5L16 7.5 M10 16l1 1 9.5-9.5");
export const X = draw("M6 6l12 12M18 6L6 18");
export const Plus = draw("M12 5v14M5 12h14");
export const Search = draw("M9 3h5l4 4v5l-4 4H9l-4-4V7z M16 16l5 5");
export const Send = draw("M3 11l18-8-6 18-3-7z M12 14l9-11");
export const Play = draw("M7 4l12 8-12 8z");
export const Pause = draw("M7 4h3v16H7z M14 4h3v16h-3z");
export const Square = draw("M6 6h12v12H6z");
export const FastForward = draw("M3 5l9 7-9 7z M12 5l9 7-9 7z");
export const OctagonX = draw(`${O} M9 9l6 6M15 9l-6 6`);
export const Ban = draw(`${O} M7 7l10 10`);
export const ChevronDown = draw("M6 9l6 6 6-6");
export const Activity = draw("M3 12h4l3-8 4 16 3-8h4");
export const Footprints = draw("M7 3c2 0 3 2 3 5s-1 5-3 5-3-2-3-5 1-5 3-5z M5 16h4v2a2 2 0 0 1-4 0z M17 7c2 0 3 2 3 5s-1 5-3 5-3-2-3-5 1-5 3-5z M15 20h4v1a2 2 0 0 1-4 0z");
export const MessageSquareQuote = draw("M4 5h16v11H9l-5 4z M8 9h2v2l-1 2 M13 9h2v2l-1 2");
export const ChevronRight = draw("M9 6l6 6-6 6");
export const ChevronLeft = draw("M15 6l-6 6 6 6");
export const ArrowRight = draw("M4 12h16M14 6l6 6-6 6");
export const ArrowLeft = draw("M20 12H4M10 6l-6 6 6 6");
export const ArrowUp = draw("M12 20V4M6 10l6-6 6 6");
export const ArrowDown = draw("M12 4v16M6 14l6 6 6-6");
export const ArrowUpRight = draw("M7 17L17 7M8 7h9v9");
export const ArrowDownLeft = draw("M17 7L7 17M16 17H7V8");
export const CornerUpLeft = draw("M20 20v-7l-3-3H4 M9 5l-5 5 5 5");
export const Trash2 = draw("M4 6h16 M9 6V3h6v3 M6 6l1 14 1 1h8l1-1 1-14 M10 10v7 M14 10v7");
export const Eraser = draw("M14 4l6 6-9 9H7l-3-3z M9 9l6 6 M10 20h10");
export const Upload = draw("M12 15V3M7 8l5-5 5 5 M4 15v5l1 1h14l1-1v-5");
export const Download = draw("M12 3v12M7 10l5 5 5-5 M4 15v5l1 1h14l1-1v-5");
export const Copy = draw("M9 9h10l1 1v10l-1 1H9l-1-1V10z M5 15H4l-1-1V4l1-1h10l1 1v1");
export const Eye = draw("M2 12l5-5h10l5 5-5 5H7z M10.5 10h3l1 1v2l-1 1h-3l-1-1v-2z");
export const EyeOff = draw("M2 12l5-5h10l5 5-5 5H7z M10.5 10h3l1 1v2l-1 1h-3l-1-1v-2z M3 3l18 18");
export const Pencil = draw("M15 4l5 5-11 11H4v-5z M13 6l5 5");
export const SquarePen = draw("M11 4H5l-1 1v14l1 1h14l1-1v-6 M17 3l4 4-9 9H8v-4z");
export const Lock = draw("M6 10h12l1 1v9l-1 1H6l-1-1v-9z M8 10V6l2-3h4l2 3v4");
export const Unlock = draw("M6 10h12l1 1v9l-1 1H6l-1-1v-9z M8 10V6l2-3h4l2 2");
export const Zap = draw("M13 2L4 14h7l-1 8 9-12h-7z");
export const Hand = draw("M8 13V5l1.5-1.5L11 5v6 M11 10V3.5L12.5 2 14 3.5V10 M14 10V4.5L15.5 3 17 4.5V12 M17 9l1.5-1.5L20 9v5l-3 6-2 1h-5l-3-3-3-5 1.5-1.5L8 13");
export const Bell = draw("M6 17v-7l2-4 2-2h4l2 2 2 4v7l2 2H4z M10 21h4");
export const PanelRight = draw(`${BOX} M15 4v16`);
export const PanelBottom = draw(`${BOX} M4 15h16`);
export const Settings2 = draw("M4 7h10 M18 7h2 M4 17h2 M10 17h10 M14 5h4v4h-4z M6 15h4v4H6z");
export const ExternalLink = draw("M14 4h6v6 M20 4l-9 9 M18 14v5l-1 1H5l-1-1V7l1-1h5");
export const Link2 = draw("M9 8H6L3 11v2l3 3h3 M15 8h3l3 3v2l-3 3h-3 M8 12h8");
export const Flag = draw("M5 21V4 M5 4h11l-2 4 2 4H5");
export const Milestone = draw("M12 21v-8 M5 5h12l3 4-3 4H5z");
export const Save = draw("M5 4h11l4 4v11l-1 1H5l-1-1V5z M8 4v5h7V4 M8 20v-6h8v6");
export const MessageSquare = draw("M5 4h14l1 1v10l-1 1H9l-5 4V5z");
export const Plug = draw("M9 3v5 M15 3v5 M6 8h12v4l-3 4H9l-3-4z M12 16v5");
export const PlugZap = draw("M9 3v5 M15 3v5 M6 8h12v4l-3 4H9l-3-4z M12 16v5 M12.5 10l-1.5 2.5h2L11.5 15");
export const Maximize2 = draw("M14 4h6v6 M20 4l-7 7 M10 20H4v-6 M4 20l7-7");
export const ListChecks = draw("M4 6l1.5 1.5L8 5 M4 12l1.5 1.5L8 11 M4 18l1.5 1.5L8 17 M11 6h9 M11 12h9 M11 18h9");
export const AtSign = draw(`M16 12V8.5L12.5 5h-1L8 8.5v7l3.5 3.5H16 M10 10h4v4h-4z M14 14l2 2h3l2-2V9.5L15.5 4h-7L4 8.5v7L8.5 20`);
export const Wand2 = draw("M4 20l12-12 M14 6l4 4 M18 3v3 M21 6h-3 M10 3v2 M20 13v2");
export const CalendarClock = draw("M5 5h14l1 1v13l-1 1H5l-1-1V6z M4 10h16 M8 3v4 M16 3v4 M12 13v3h3");
export const Lightbulb = draw("M9 18h6 M10 21h4 M8 15l-2-3V8l3-4h6l3 4v4l-2 3z");
export const Printer = draw("M7 9V3h10v6 M5 9h14l1 1v7l-1 1h-2 M7 18H5l-1-1v-7 M7 14h10v7H7z");
export const Camera = draw("M4 7h4l2-3h4l2 3h4l1 1v11l-1 1H4l-1-1V8z M10 11h4l1 1v3l-1 1h-4l-1-1v-3z");
export const FlaskConical = draw("M9 3h6 M10 3v6l-6 10 1 2h14l1-2-6-10V3 M7 15h10");

// --- states --------------------------------------------------------------------------------
export const CheckCircle2 = draw(`${O} M8 12.5l3 3 5-6`);
export const CircleCheck = CheckCircle2;
export const XCircle = draw(`${O} M9 9l6 6M15 9l-6 6`);
export const CircleX = XCircle;
export const CircleHelp = draw(`${O} M9.5 9.5L11 8h2l1.5 1.5V11L12 12.5V14 M12 16.5v.5`);
export const CircleAlert = draw(`${O} M12 7.5v6 M12 16v.5`);
/** Spins with className="spin": an open octagon. */
export const Loader2 = draw("M12 3h3.5L21 8.5v7L15.5 21");
export const RotateCcw = draw("M3 4v5h5 M4 9l4.5-6h7L21 8.5v7L15.5 21h-7L4 16.5");
export const RotateCw = draw("M21 4v5h-5 M20 9l-4.5-6h-7L3 8.5v7L8.5 21h7l4.5-4.5");
export const RefreshCw = draw("M21 4v5h-5 M20 9l-4.5-6h-7L3 8.5 M3 20v-5h5 M4 15l4.5 6h7L21 15.5");
export const Flame = draw("M12 21l-5-3-2-5 2-5 2 2 1-6 5 4 3 5-1 5-5 3z");
export const Skull = draw("M6 4l2-1h8l2 1 2 4v6l-3 2v4H7v-4l-3-2V8z M9 10h2v2H9z M13 10h2v2h-2z M10 20v-3 M14 20v-3");
export const Cpu2 = Brain;

// --- fallbacks: Lucide drawn in this set's language -----------------------------------------
export const Unknown = angular(L.Circle);
export const FolderOpen = angular(L.FolderOpen);

/** Penteos' mark: the app badge (the hoplite helmet on its rounded tile, build-resources/icon.png). */
export function Mark(props: { size?: number; className?: string; title?: string }) {
  const s = props.size ?? 22;
  return <img src={badgeUrl} width={s} height={s} className={props.className} alt={props.title ?? ""} aria-hidden={props.title ? undefined : true} draggable={false} style={{ display: "block", borderRadius: Math.round(s * 0.22) }} />;
}
export const Puzzle = angular(L.Puzzle);
export const Image = angular(L.Image);
export const BarChart3 = angular(L.ChartColumn);
export const Mail = angular(L.Mail);
