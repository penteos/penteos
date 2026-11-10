/// <reference lib="dom" />
/**
 * Functions that run inside the page of the agents' browser (sent as source with
 * Runtime.evaluate). They only touch the page's own DOM, so they are typed against it.
 */

/** Runs inside the page: what a person would see and could act on. */
export function pageState(): unknown {
  const selectorOf = (el: Element): string => {
    if (el.id) return `#${CSS.escape(el.id)}`;
    const name = el.getAttribute("name");
    if (name) return `${el.tagName.toLowerCase()}[name="${name}"]`;
    const parent = el.parentElement;
    if (!parent) return el.tagName.toLowerCase();
    const same = Array.from(parent.children).filter((c) => c.tagName === el.tagName);
    return `${selectorOf(parent)} > ${el.tagName.toLowerCase()}${same.length > 1 ? `:nth-of-type(${same.indexOf(el) + 1})` : ""}`;
  };
  const shown = (el: Element) => {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  const clean = (s: string | null | undefined) => (s ?? "").replace(/\s+/g, " ").trim();
  return {
    url: location.href,
    title: document.title,
    text: clean(document.body?.innerText).slice(0, 4000),
    links: Array.from(document.querySelectorAll("a[href]"))
      .filter(shown)
      .slice(0, 80)
      .map((a) => ({ text: clean(a.textContent).slice(0, 80), href: (a as HTMLAnchorElement).href })),
    forms: Array.from(document.querySelectorAll("form"))
      .slice(0, 10)
      .map((f) => ({
        action: (f as HTMLFormElement).action,
        method: ((f as HTMLFormElement).method || "get").toUpperCase(),
        fields: Array.from(f.querySelectorAll("input, select, textarea"))
          .filter((i) => (i as HTMLInputElement).type !== "hidden")
          .slice(0, 30)
          .map((i) => ({ name: i.getAttribute("name") ?? "", type: (i as HTMLInputElement).type || i.tagName.toLowerCase(), selector: selectorOf(i) })),
      })),
    buttons: Array.from(document.querySelectorAll("button, [role=button], input[type=submit], input[type=button]"))
      .filter(shown)
      .slice(0, 40)
      .map((b) => ({ text: clean(b.textContent || (b as HTMLInputElement).value).slice(0, 60), selector: selectorOf(b) })),
  };
}

/** Runs inside the page: click an element by selector, or the first clickable one with that text. */
export function clickIn(selector: string | null, text: string | null): string {
  let el: Element | null = selector ? document.querySelector(selector) : null;
  if (!el && text) {
    const want = text.toLowerCase();
    el =
      Array.from(document.querySelectorAll("a, button, [role=button], input[type=submit], input[type=button], label")).find((e) =>
        (e.textContent || (e as HTMLInputElement).value || "").toLowerCase().includes(want),
      ) ?? null;
  }
  if (!el) return "not_found";
  (el as HTMLElement).scrollIntoView({ block: "center" });
  (el as HTMLElement).click();
  return "clicked";
}

/** Runs inside the page: type into a field the way a person would (frameworks see the change). */
export function fillIn(selector: string, value: string, submit: boolean): string {
  const el = document.querySelector(selector) as HTMLInputElement | HTMLTextAreaElement | null;
  if (!el) return "not_found";
  el.focus();
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")?.set?.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  if (submit) {
    const form = el.closest("form");
    if (form) form.requestSubmit();
    else el.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  }
  return "filled";
}

