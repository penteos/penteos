import ReactMarkdown, { defaultUrlTransform } from "react-markdown";
import remarkGfm from "remark-gfm";
import { useAppOptional } from "../state";

/**
 * Markdown from agents and notes: GitHub flavor (tables, lists, code). Raw HTML is never
 * rendered. Links to entities ([@label](penteos:entity/<id>)) open them in the workbench; other
 * links open in the system browser.
 */
export function Markdown(props: { text: string }) {
  // Outside the workbench (the report document is rendered on its own) mentions are plain text.
  const workbench = useAppOptional()?.workbench;
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      urlTransform={(url) => (url.startsWith("penteos:") ? url : defaultUrlTransform(url))}
      components={{
        a: ({ href, children }) => {
          const m = /^penteos:entity\/(\w+)$/.exec(href ?? "");
          if (m && !workbench) return <span className="mention">{children}</span>;
          if (m && workbench) {
            return (
              <a
                className="mention"
                href="#"
                onClick={(e) => {
                  e.preventDefault();
                  workbench.openEntity(m[1]!, String(Array.isArray(children) ? children.join("") : (children ?? "")).replace(/^@/, ""));
                }}
              >
                {children}
              </a>
            );
          }
          return (
            <a href={href} target="_blank" rel="noreferrer">
              {children}
            </a>
          );
        },
        table: ({ children }) => (
          <div className="md-table">
            <table>{children}</table>
          </div>
        ),
      }}
    >
      {props.text}
    </ReactMarkdown>
  );
}
