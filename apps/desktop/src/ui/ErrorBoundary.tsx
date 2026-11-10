import { Component, type ReactNode } from "react";
import { AlertTriangle, RotateCcw } from "./icons";
import { t } from "../i18n";
import { reportError } from "./reportError";

/**
 * A section that fails shows what happened and a way to retry, instead of taking the whole
 * workbench down (React unmounts everything on an unhandled render error: a black window).
 */
export class ErrorBoundary extends Component<{ children: ReactNode; area?: string }, { error?: Error }> {
  state: { error?: Error } = {};

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error(`[penteos] ${this.props.area ?? "section"} failed:`, error);
    reportError(`section:${this.props.area ?? "?"}`, error);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="panel error-boundary">
        <div className="eb-box">
          <div className="eb-head"><AlertTriangle size={14} /> {t("shell.error.title")}</div>
          <div className="eb-text">{t("shell.error.body")}</div>
          <pre className="eb-detail mono">{this.state.error.message}</pre>
          <button className="btn sm primary" onClick={() => this.setState({ error: undefined })}><RotateCcw size={12} /> {t("common.retry")}</button>
        </div>
      </div>
    );
  }
}
