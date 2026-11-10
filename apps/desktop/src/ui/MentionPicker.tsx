import { AtSign } from "./icons";
import { useEffect, useRef, useState } from "react";
import { type Entity, useApp } from "../state";
import { t as tr } from "../i18n";

/** Finds an entity by text and returns a mention link: [@label](penteos:entity/<id>). */
export function entityLabel(e: Entity): string {
  const a = e.attributes;
  return String(a.title ?? a.displayName ?? a.origin ?? a.fqdn ?? a.ip ?? a.pathTemplate ?? e.naturalKey ?? e.id);
}

export function MentionPicker(props: { onPick: (markdown: string) => void }) {
  const { client } = useApp();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [items, setItems] = useState<Entity[]>([]);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const t = setTimeout(() => {
      client.call<Entity[]>("entity.query", { text: q || undefined, limit: 12 }).then((r) => setItems(r.filter((e) => !["scope_rule", "memory"].includes(e.kind))), () => setItems([]));
    }, 150);
    return () => clearTimeout(t);
  }, [open, q, client]);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, [open]);
  return (
    <div className="mention-picker" ref={ref}>
      <button className="btn sm ghost" title={tr("data.mention.title")} onClick={() => setOpen((v) => !v)}>
        <AtSign size={12} /> {tr("data.mention.button")}
      </button>
      {open ? (
        <div className="menu-pop" style={{ top: 28, minWidth: 320 }}>
          <input className="input sm" autoFocus placeholder={tr("data.mention.placeholder")} value={q} onChange={(e) => setQ(e.target.value)} style={{ width: "100%", marginBottom: 4 }} />
          {items.map((e) => (
            <button
              key={e.id}
              className="menu-item"
              onClick={() => {
                props.onPick(`[@${entityLabel(e)}](penteos:entity/${e.id})`);
                setOpen(false);
                setQ("");
              }}
            >
              <span className="mi-check" />
              <span className="mi-label">{entityLabel(e)}</span>
              <span className="mi-key">{e.kind}</span>
            </button>
          ))}
          {items.length === 0 ? <div className="menu-header">{tr("data.mention.empty")}</div> : null}
        </div>
      ) : null}
    </div>
  );
}
