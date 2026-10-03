// Browser vs scraper comparison: latest report per client for one case, with action, segment and tri-state verdicts.
import { $, h, state, label, sigFor, scoreClass, actionChip, segChip, LABELS, safeCls } from "./util.js";

const SEV = { block: 0, fail: 1, warn: 2, pass: 3, skip: 4 };
const outcome = (r, slug) => (slug !== "all" && sigFor(r, slug) ? sigFor(r, slug).verdict : r.blocked ? "fail" : "pass");

export function renderCmpSelect() {
  const sel = $("cmp-case");
  const slugs = ["all", ...state.modules.map((m) => m.slug)];
  if (!state.cmpCase || !slugs.includes(state.cmpCase)) state.cmpCase = slugs[1] || "all";
  sel.replaceChildren(...slugs.map((s) => h("option", { value: s, selected: s === state.cmpCase }, s)));
  renderCmp();
}
export function renderCmp() {
  const slug = state.cmpCase, box = $("cmp");
  if (!slug) return;
  const path = "/protected/" + slug;
  const latest = {};
  for (const r of state.reports) if ((r.path || "").split("?")[0] === path && !latest[label(r)]) latest[label(r)] = r; // newest first
  const labels = [...LABELS, ...Object.keys(latest).filter((l) => !LABELS.includes(l))];
  const have = Object.keys(latest);
  const all = slug === "all";
  const mods = all ? [...new Set(Object.values(latest).flatMap((r) => (r.signals || []).map((s) => s.module)))] : [slug];
  const verdicts = (m) => Object.values(latest).map((r) => sigFor(r, m)?.verdict ?? "-");
  const diffMods = new Set(mods.filter((m) => new Set(verdicts(m)).size > 1));
  // in "all" mode only modules that differ or are not pass/skip stay visible; the rest is summarised
  const interesting = (m) => diffMods.has(m) || verdicts(m).some((v) => v !== "pass" && v !== "skip" && v !== "-");
  const shown = all ? mods.filter(interesting).sort((a, b) => Math.min(...verdicts(a).map((v) => SEV[v] ?? 5)) - Math.min(...verdicts(b).map((v) => SEV[v] ?? 5))) : mods;
  const hidden = mods.length - shown.length;
  const cols = labels.map((l) => {
    const r = latest[l];
    const cc = "chip c-" + safeCls(l);
    if (!r) return h("div", { class: "col none" }, h("span", { class: cc }, l), h("p", { class: "meta" }, "No request yet."));
    const act = r.action || (r.blocked ? "deny" : "allow");
    return h("div", { class: "col" },
      h("div", { class: "row" }, h("span", { class: cc }, l), h("span", { class: "pill " + scoreClass(r.score) }, r.score)),
      h("div", { class: "tags" }, actionChip(act), segChip(r.segment), r.endpoint_class ? h("span", { class: "tag ep" }, r.endpoint_class) : null),
      shown.map((m) => {
        const s = sigFor(r, m);
        if (!s) return null;
        return h("div", { class: "sig-line v-" + safeCls(s.verdict) + (diffMods.has(m) ? " diff" : "") },
          h("span", { class: "badge v-" + safeCls(s.verdict) }, s.verdict), " ", all ? h("b", {}, m + " ") : null, h("div", { class: "meta" }, s.reason));
      }),
      all && hidden ? h("p", { class: "meta" }, `${hidden} other module${hidden > 1 ? "s" : ""} passed or were skipped for every client.`) : null);
  });
  const why = [];
  const out = Object.fromEntries(have.map((l) => [l, outcome(latest[l], slug)]));
  const ok = have.filter((l) => ["pass", "skip"].includes(out[l])), bad = have.filter((l) => ["fail", "block"].includes(out[l])), warn = have.filter((l) => out[l] === "warn");
  const acts = new Set(have.map((l) => latest[l].action));
  if (ok.length && (bad.length || warn.length)) {
    why.push(h("p", {}, h("b", {}, "Why the difference: "), `${ok.join(", ")} passed while ${[...bad, ...warn].join(", ")} ${bad.length ? "failed" : "raised a warning"}.`));
    const items = [];
    for (const m of mods) for (const f of [...bad, ...warn]) {
      const s = sigFor(latest[f], m);
      if (s && ["fail", "warn", "block"].includes(s.verdict)) items.push(h("li", {}, h("b", {}, f), ` / ${m}: ${s.reason}`));
    }
    why.push(h("ul", {}, items.slice(0, 8)));
  } else if (have.length) why.push(h("p", { class: "meta" }, "All observed clients got the same verdict for this case; highlighted rows would mark per-signal differences."));
  if (have.length > 1 && acts.size > 1) why.push(h("p", { class: "meta" }, "Actions differ per client: the segment the aggregate score lands in decides the action, not the single module verdict."));
  box.replaceChildren(h("div", { class: "cmp-grid" }, cols), why.length ? h("div", { class: "why" }, why) : null);
}
