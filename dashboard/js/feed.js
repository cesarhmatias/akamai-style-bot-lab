// Live feed: rows with action, segment, endpoint class and badges; selecting a row opens the inspector.
import { $, h, state, label, fmtTime, scoreClass, actionChip, segChip, tag, caseOf, MAX_ROWS, ACTION_ORDER, ACTIONS } from "./util.js";
import { renderDetail } from "./inspector.js";

const passes = (r) => !state.feedFilter || (r.action || (r.blocked ? "deny" : "allow")) === state.feedFilter;

export function rowEl(r) {
  const sel = state.selected && state.selected.id === r.id;
  const L = r.layers || {};
  return h("div", { class: "feed-row" + (sel ? " sel" : ""), role: "option", "aria-selected": String(!!sel), tabindex: "-1", "data-id": r.id, onclick: () => select(r) },
    h("span", { class: "t mono" }, fmtTime(r.ts)),
    h("span", {}, h("span", { class: "chip c-" + label(r).replace(/\W/g, "_") }, label(r))),
    h("span", { class: "req" },
      h("span", { class: "path mono", title: r.method + " " + r.path }, h("b", {}, r.method), " ", r.path),
      h("span", { class: "sub" },
        r.endpoint_class ? h("span", {}, r.endpoint_class) : null, r.telemetry_type ? h("span", {}, r.telemetry_type) : null,
        r.is_human ? tag("human", "Bot Score 0", "human") : null, r.is_safeguard ? tag("safeguard", "Challenge waived to protect a human", "safe") : null,
        L.applicable && L.agree === false ? tag("layers ✕", "Cross-layer version disagreement", "blk") : null,
        r.reference ? tag("ref", "Deny reference " + r.reference, "ref") : null, r.canary ? tag("canary", "Carries canary " + r.canary, "ref") : null)),
    h("span", {}, actionChip(r.action || (r.blocked ? "deny" : "allow"))),
    h("span", {}, segChip(r.segment)),
    h("span", {}, h("span", { class: "pill " + scoreClass(r.score) }, r.score)));
}
export function renderFeed() {
  const f = $("feed");
  const list = state.reports.filter(passes);
  if (!state.reports.length) { f.replaceChildren(h("p", { class: "empty" }, "No requests yet. Click Test on a case or run the client matrix.")); return; }
  f.replaceChildren(...(list.length ? list.map(rowEl) : [h("p", { class: "empty" }, "No request with that action yet.")]));
}
export function prependRow(r) {
  if (!passes(r)) return;
  const f = $("feed");
  if (f.querySelector(".empty")) f.replaceChildren();
  f.prepend(rowEl(r));
  while (f.children.length > MAX_ROWS) f.lastChild.remove();
}
export function select(r) {
  state.selected = r;
  document.querySelectorAll(".feed-row").forEach((e) => { const on = e.dataset.id === r.id; e.classList.toggle("sel", on); e.setAttribute("aria-selected", String(on)); });
  renderDetail();
}
export function mountFeedControls() {
  const sel = $("feed-filter");
  const seen = new Set(ACTION_ORDER);
  const opts = ["", ...ACTION_ORDER];
  sel.replaceChildren(...opts.map((a) => h("option", { value: a }, a || "all actions")));
  sel.addEventListener("change", (e) => { state.feedFilter = e.target.value; renderFeed(); });
  // actions the API reports that we do not know get added on the fly
  return (a) => { if (a && !seen.has(a)) { seen.add(a); sel.append(h("option", { value: a }, a)); } };
}
$("feed").addEventListener("keydown", (e) => {
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  e.preventDefault();
  const list = state.reports.filter(passes);
  const i = list.findIndex((r) => state.selected && r.id === state.selected.id) + (e.key === "ArrowDown" ? 1 : -1);
  const r = list[Math.max(0, Math.min(list.length - 1, i))];
  if (r) { select(r); $("feed").querySelector(".sel")?.scrollIntoView({ block: "nearest" }); }
});
