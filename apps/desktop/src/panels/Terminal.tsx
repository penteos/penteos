import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import { useEffect, useRef } from "react";
import { useApp } from "../state";
import { t } from "../i18n";

const THEME = {
  background: "#110e16",
  foreground: "#e3e0ea",
  cursor: "#9d8cff",
  cursorAccent: "#110e16",
  selectionBackground: "rgba(157, 140, 255, 0.28)",
  black: "#2d2738",
  red: "#e5717d",
  green: "#6cc69a",
  yellow: "#d6b26e",
  blue: "#8fa8d8",
  magenta: "#b4a6ff",
  cyan: "#7fc4c9",
  white: "#c3bfcd",
  brightBlack: "#615b6d",
  brightRed: "#ef949d",
  brightGreen: "#8fd6b3",
  brightYellow: "#e3c891",
  brightBlue: "#adc0e4",
  brightMagenta: "#cbc1ff",
  brightCyan: "#a2d6da",
  brightWhite: "#ffffff",
};

/**
 * A real shell running in the core process. Integrated tools (nmap) are wrapped: their targets
 * are checked against the scope before they run, and their output lands in the graph.
 */
export function TerminalPanel() {
  const { client } = useApp();
  const host = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const term = new Terminal({
      theme: THEME,
      fontFamily: '"JetBrains Mono Variable", ui-monospace, monospace',
      fontSize: 12.5,
      lineHeight: 1.25,
      cursorBlink: true,
      cursorStyle: "bar",
      allowProposedApi: true,
      scrollback: 10_000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host.current!);
    fit.fit();

    let termId: string | undefined;
    let disposed = false;
    client
      .openTerminal(term.cols, term.rows, {
        data: (d) => term.write(d),
        exit: () => term.write(`\r\n\x1b[2m${t("data.terminal.ended")}\x1b[0m\r\n`),
      })
      .then((id) => {
        if (!id) {
          // Team server: no shell on the server for remote operators.
          term.write(`\x1b[38;5;245m${client.termDenied ?? t("data.terminal.unavailable")}\x1b[0m\r\n`);
          return;
        }
        if (disposed) client.termClose(id);
        termId = id;
      });
    const input = term.onData((d) => termId && client.termInput(termId, d));
    const observer = new ResizeObserver(() => {
      try {
        fit.fit();
        if (termId) client.termResize(termId, term.cols, term.rows);
      } catch {
        /* hidden panel */
      }
    });
    observer.observe(host.current!);
    (window as any).__penteosTerm = (text: string) => termId && client.termInput(termId, text);

    return () => {
      disposed = true;
      observer.disconnect();
      input.dispose();
      if (termId) client.termClose(termId);
      term.dispose();
    };
  }, [client]);

  return (
    <div className="panel">
      <div className="term-host" ref={host} />
    </div>
  );
}
