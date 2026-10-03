// Case cards: confidence tiers, endpoint classes, challenge providers, filtering and compact mode.
import { $, h, state, api, sendJson, toast, pref, label, sigFor, STORE, CONF, CONF_ORDER, confChip, tag, UNVERIFIED } from "./util.js";
import { focusFlag } from "./flags.js";
import { renderCmpSelect } from "./compare.js";

const ep = { page: "GET /", protected: "GET /protected/*", transactional: "POST /api/login, /api/checkout", mobile: "/mobile/api/*" };
const ui = { q: "", cats: new Set(), confs: new Set(), compact: pref.get("compact", false) };
let firstCases = true;

const verdictOf = (r, slug) => {
  const s = sigFor(r, slug);
  return s ? s.verdict : r.blocked ? "block" : "pass";
};

function legend() {
  return h("div", { class: "legend", role: "group", "aria-label": "Confidence tiers" },
    CONF_ORDER.map((k) => h("div", { class: "legend-item" }, confChip(k, CONF[k].name), h("span", {}, CONF[k].desc))),
    h("p", { class: "meta legend-note" }, "Tiers come from the audit's source grading. ", h("b", {}, "LOW"), " behaviours are flag-gated and unverified: treat a result that depends on them as a hypothesis, not as how Akamai behaves."));
}

function toolbar(cats, total, shown) {
  const toggle = (set, v) => () => { set.has(v) ? set.delete(v) : set.add(v); renderCases(); };
  const chip = (set, v, text, cls) => h("button", { class: "fchip " + (cls || ""), "aria-pressed": String(set.has(v)), onclick: toggle(set, v) }, text);
  return h("div", { class: "toolbar" },
    h("input", { type: "search", id: "case-q", placeholder: "Filter cases…", "aria-label": "Filter cases by name or description", value: ui.q,
      oninput: (e) => { ui.q = e.target.value; renderCases(true); } }),
    h("div", { class: "fgroup", role: "group", "aria-label": "Category" }, cats.map((c) => chip(ui.cats, c, c))),
    h("div", { class: "fgroup", role: "group", "aria-label": "Confidence" }, CONF_ORDER.map((c) => chip(ui.confs, c, c, "c-" + c))),
    h("label", { class: "inline-switch" }, h("button", { class: "switch", role: "switch", "aria-checked": String(ui.compact), "aria-label": "Compact mode",
      onclick: () => { ui.compact = !ui.compact; pref.set("compact", ui.compact); renderCases(true); } }), "Compact"),
    h("span", { class: "meta", "aria-live": "polite" }, shown === total ? `${total} cases` : `${shown} of ${total} cases`));
}

function card(m, i) {
  const last = state.lastByCase[m.slug];
  const lv = m.last_verdict;
  const v = last ? verdictOf(last, m.slug) : lv && lv.verdict ? lv.verdict : "none";
  const flags = m.flags || [];
  const flagOn = flags.filter((f) => (state.flags.find((x) => x.name === f) || {}).value);
  const low = m.confidence === "low";
  const applies = m.applies_to || [];
  const flagChips = flags.map((f) => {
    const on = !!(state.flags.find((x) => x.name === f) || {}).value;
    return h("button", { class: "tag flag" + (on ? " on" : ""), title: `Feature flag ${f} (${on ? "on" : "off"}). Click to jump to it.`, onclick: () => focusFlag(f) }, "⚑ " + f);
  });
  return h("article", { class: "card" + (m.enabled ? "" : " disabled") + (low ? " low" : ""), style: firstCases ? `animation-delay:${i * 25}ms` : "animation:none", id: "case-" + m.slug },
    h("div", { class: "row" }, h("h3", {}, m.title || m.slug), h("span", { class: "chip", title: "Category" }, m.category || "")),
    h("div", { class: "tags" },
      confChip(m.confidence || "", (m.confidence || "?")),
      applies.length ? applies.map((c) => tag(c, "Evaluated on " + c + " requests (" + (ep[c] || c) + ") when all enabled modules run", "ep")) : tag("no class", "Not evaluated by the 'all modules' runs; only GET /protected/" + m.slug, "ep none"),
      (m.challenge_providers || []).map((p) => tag("challenge: " + p, "Serves the '" + p + "' challenge provider", "prov"))),
    ui.compact ? null : h("p", {}, m.description || ""),
    low && !ui.compact ? h("p", { class: "unverified" }, UNVERIFIED + ": behaviour is flag-gated" + (flags.length ? (flagOn.length ? ` (${flagOn.length}/${flags.length} flags on).` : " (all flags off, so mostly inactive).") : ".")) : null,
    ui.compact ? null : flagChips.length ? h("div", { class: "tags" }, flagChips) : null,
    h("div", { class: "row" },
      h("span", { class: "badge v-" + v, title: last ? "Last verdict from " + label(last) : lv ? "Last verdict recorded by the API" : "No request yet" }, v === "none" ? "no data" : v),
      h("div", { class: "row" },
        h("a", { class: "btn sm", href: `${STORE}/protected/${encodeURIComponent(m.slug)}`, target: "_blank", rel: "noopener",
          title: "Opens in your real browser (so JS challenges run). The dashboard cannot probe it cross-origin because of the self-signed certificate." }, "Test ↗"),
        h("button", { class: "switch", role: "switch", "aria-checked": String(!!m.enabled), "aria-label": "Enable " + (m.title || m.slug), onclick: () => toggle(m) }))));
}

export function renderCases(keepFocus = false) {
  const box = $("cases"), bar = $("cases-bar");
  const all = state.modules;
  const cats = [...new Set(all.map((m) => m.category).filter(Boolean))].sort();
  const q = ui.q.trim().toLowerCase();
  const list = all.filter((m) =>
    (!ui.cats.size || ui.cats.has(m.category)) && (!ui.confs.size || ui.confs.has(m.confidence)) &&
    (!q || `${m.slug} ${m.title} ${m.description} ${m.category}`.toLowerCase().includes(q)));
  box.classList.toggle("compact", ui.compact);
  if (!all.length) {
    bar.replaceChildren();
    box.replaceChildren(h("p", { class: "empty" }, state.modulesError ? "Cannot load cases: the API is unreachable. Retrying when the live feed reconnects." : "No cases reported by the API."));
    return;
  }
  const hadFocus = keepFocus && document.activeElement && document.activeElement.id === "case-q";
  const sel = hadFocus ? document.activeElement.selectionStart : 0;
  bar.replaceChildren(toolbar(cats, all.length, list.length));
  if (hadFocus) { const i = $("case-q"); i.focus(); i.setSelectionRange(sel, sel); }
  box.replaceChildren(...(list.length ? list.map(card) : [h("p", { class: "empty" }, "No case matches the filters.")]));
  firstCases = false;
  renderCmpSelect();
}

async function toggle(m) {
  const enabled = !m.enabled;
  try {
    await sendJson("PUT", "/api/modules/" + encodeURIComponent(m.slug), { enabled });
    m.enabled = enabled; renderCases();
  } catch (e) { toast("Could not toggle " + m.slug + ": " + e.message, "error"); }
}

export async function loadModules() {
  try {
    const d = await api("/api/modules");
    state.modules = Array.isArray(d) ? d : d.modules || [];
    state.modulesError = false;
  } catch (e) { state.modulesError = true; throw e; } finally { renderCases(); }
}
export function mountCases() { $("legend").replaceChildren(legend()); renderCases(); }
