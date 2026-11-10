import { Check } from "./icons";
import { useEffect, useRef, useState } from "react";
import { keys } from "../i18n";

/** A classic application menu (Archivo, Editar, Ver…), drawn inside the window like VS Code on Linux. */

export type MenuItem =
  | { label: string; shortcut?: string; onClick: () => void; disabled?: boolean; checked?: boolean }
  | { header: string }
  | "sep";

export interface Menu {
  label: string;
  items: MenuItem[];
}

export function MenuBar(props: { menus: Menu[] }) {
  const [open, setOpen] = useState<number>();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (open === undefined) return;
    const close = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(undefined);
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(undefined);
      if (e.key === "ArrowRight") setOpen((o) => ((o ?? 0) + 1) % props.menus.length);
      if (e.key === "ArrowLeft") setOpen((o) => ((o ?? 0) - 1 + props.menus.length) % props.menus.length);
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", key);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", key);
    };
  }, [open, props.menus.length]);

  return (
    <div className="menubar" ref={ref}>
      {props.menus.map((m, i) => (
        <div key={m.label} className="menu-root">
          <button
            className={`menu-title ${open === i ? "on" : ""}`}
            // Keep focus where it was (the terminal, an input): Edit → Copy acts on it.
            onMouseDown={(e) => {
              e.preventDefault();
              setOpen(open === i ? undefined : i);
            }}
            onMouseEnter={() => open !== undefined && setOpen(i)}
          >
            {m.label}
          </button>
          {open === i ? (
            <div className="menu-pop">
              {m.items.map((it, j) =>
                it === "sep" ? (
                  <div key={j} className="menu-sep" />
                ) : "header" in it ? (
                  <div key={j} className="menu-header">{it.header}</div>
                ) : (
                  <button
                    key={j}
                    className="menu-item"
                    disabled={it.disabled}
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => {
                      setOpen(undefined);
                      it.onClick();
                    }}
                  >
                    <span className="mi-check">{it.checked ? <Check size={12} /> : null}</span>
                    <span className="mi-label">{it.label}</span>
                    {it.shortcut ? <span className="mi-key">{keys(it.shortcut)}</span> : null}
                  </button>
                ),
              )}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}
