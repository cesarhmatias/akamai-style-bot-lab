// Response policy panel: Bot Score bands per telemetry type, segment -> action per endpoint class, action params.
// GET/PUT/DELETE /api/policy. PUT deep-merges, so only the edited cells are sent.
import { $, h, state, api, sendJson, toast, errorLines, actionChip, safeCls, ACTIONS, SEGMENT_DESC } from "./util.js";

const EP_DESC = { page: "GET /", protected: "GET /protected/*", transactional: "POST /api/login, /api/checkout", mobile: "/mobile/api/*" };
const TEL_DESC = { standard: "Browser telemetry (sensor posts)", inline: "Telemetry on transactional requests", native: "Mobile SDK telemetry (lab-chosen band)" };
const SEGS = ["cautious", "strict", "aggressive"];
// [key, label, hint, kind]; kind: "num" | "int" | "provider"
const PARAM_GROUPS = [
  ["delay", "Delay", [["delay_seconds", "delay_seconds", "pause before the real response", "num"]]],
  ["slow", "Slow", [["slow_seconds", "slow_seconds", "total streaming time", "num"], ["slow_chunks", "slow_chunks", "1-50 chunks", "int"]]],
  ["tarpit", "Tarpit", [["tarpit_seconds", "tarpit_seconds", "hold time before the 403", "num"]]],
  ["safeguard", "Safeguard", [["safeguard_failures", "safeguard_failures", "challenges issued before the waiver", "int"], ["safeguard_window_seconds", "safeguard_window_seconds", "sliding window", "int"]]],
  ["challenge", "Challenge", [["challenge_provider", "challenge_provider", "which provider serves the challenge", "provider"],
    ["chlg_duration", "chlg_duration", "min. seconds between issue and solve (0-120)", "num"], ["challenge_interval", "challenge_interval", "seconds a solve stays valid (1-7200)", "int"],
    ["challenge_timeout", "challenge_timeout", "seconds to submit a solution", "int"], ["adaptive_count", "adaptive_count", "solutions required by adaptive (1-10)", "int"],
    ["norechallenge_seconds", "norechallenge_seconds", "interactive: no re-challenge window", "int"]]],
];
const clone = (o) => JSON.parse(JSON.stringify(o));
let draft = null;
let status = { kind: "", lines: [] };

const base = () => (state.policy ? { bands: state.policy.bands || {}, actions: state.policy.actions || {}, params: state.policy.params || {} } : null);
const choices = () => (state.policy && state.policy.choices) || {};

// ---- diff: draft vs server -> deep-merge patch ----
function diff() {
  const cur = base();
  const patch = { bands: {}, actions: {}, params: {} };
  let n = 0;
  for (const t of Object.keys(draft.bands)) for (const s of Object.keys(draft.bands[t])) {
    const a = draft.bands[t][s], b = ((cur.bands[t] || {})[s]) || [];
    if (a[0] !== b[0] || a[1] !== b[1]) { (patch.bands[t] ||= {})[s] = a; n++; }
  }
  for (const c of Object.keys(draft.actions)) for (const s of Object.keys(draft.actions[c])) {
    if (draft.actions[c][s] !== ((cur.actions[c] || {})[s])) { (patch.actions[c] ||= {})[s] = draft.actions[c][s]; n++; }
  }
  for (const k of Object.keys(draft.params)) if (draft.params[k] !== cur.params[k]) { patch.params[k] = draft.params[k]; n++; }
  return { patch, n };
}

// ---- band strip: score 1..100 coloured by segment, gaps/overlaps flagged ----
function coverage(bands) {
  const owner = [];
  const overlap = [];
  for (let sc = 1; sc <= 100; sc++) {
    const hits = SEGS.filter((s) => bands[s] && bands[s][0] <= sc && sc <= bands[s][1]);
    owner[sc] = hits[0] || null;
    if (hits.length > 1) overlap.push(sc);
  }
  const ranges = (arr) => { const out = []; let s = null; for (let i = 1; i <= 101; i++) { if (arr.includes(i) && s == null) s = i; if (!arr.includes(i) && s != null) { out.push(s === i - 1 ? String(s) : `${s}-${i - 1}`); s = null; } } return out; };
  const gaps = ranges(owner.map((o, i) => (o ? 0 : i)).filter(Boolean));
  return { owner, gaps, overlap: ranges(overlap) };
}
function strip(bands) {
  const { owner, gaps, overlap } = coverage(bands);
  const cells = [];
  for (let sc = 1; sc <= 100; sc++) cells.push(h("i", { class: "s-" + (owner[sc] || "none"), title: `${sc}: ${owner[sc] || "no band"}` }));
  return h("div", { class: "strip-wrap" },
    h("div", { class: "strip", role: "img", "aria-label": "Score 1 to 100 coloured by segment" }, h("i", { class: "s-human", title: "0: human" }), cells),
    h("div", { class: "strip-axis mono" }, h("span", {}, "0 human"), h("span", {}, "25"), h("span", {}, "50"), h("span", {}, "75"), h("span", {}, "100")),
    gaps.length ? h("p", { class: "warnline" }, `Scores ${gaps.join(", ")} are in no band; the lab falls back to aggressive.`) : null,
    overlap.length ? h("p", { class: "warnline" }, `Scores ${overlap.join(", ")} sit in overlapping bands; the earlier segment wins.`) : null);
}

function numInput(value, onchange, attrs = {}) {
  return h("input", { type: "number", class: "num", value: value ?? "", step: attrs.step || "1", min: attrs.min, max: attrs.max, "aria-label": attrs["aria-label"],
    onchange: (e) => { const v = e.target.value === "" ? NaN : Number(e.target.value); onchange(v); renderPolicy(); } });
}

function bandsSection() {
  const defs = (state.policy.defaults && state.policy.defaults.bands) || {};
  const types = Object.keys(draft.bands);
  return h("div", {}, h("h3", { class: "sub" }, "Bot Score bands"),
    h("p", { class: "hint" }, "Each telemetry type buckets the 0-100 aggregate score into segments. Score 0 is always ", h("b", {}, "human"), ". Standard and inline use the example values from the Akamai brief; native is lab-chosen."),
    types.map((t) => {
      const edited = SEGS.some((s) => { const d = (defs[t] || {})[s], v = draft.bands[t][s]; return d && v && (d[0] !== v[0] || d[1] !== v[1]); });
      return h("div", { class: "band-row" },
        h("div", { class: "band-title" }, h("b", {}, t), edited ? h("span", { class: "tag chg", title: "Differs from the defaults" }, "edited") : null, h("span", { class: "meta" }, TEL_DESC[t] || "")),
        strip(draft.bands[t]),
        h("div", { class: "band-inputs" }, SEGS.filter((s) => draft.bands[t][s]).map((s) => h("fieldset", { class: "band" },
          h("legend", {}, h("span", { class: "schip s-" + s, title: SEGMENT_DESC[s] }, s)),
          numInput(draft.bands[t][s][0], (v) => { draft.bands[t][s][0] = v; }, { min: 1, max: 100, "aria-label": `${t} ${s} low` }),
          h("span", { "aria-hidden": "true" }, "to"),
          numInput(draft.bands[t][s][1], (v) => { draft.bands[t][s][1] = v; }, { min: 1, max: 100, "aria-label": `${t} ${s} high` })))));
    }));
}

function actionSelect(cls, seg) {
  const cur = draft.actions[cls][seg];
  const orig = (base().actions[cls] || {})[seg];
  const opts = [...new Set([...(choices().actions || Object.keys(ACTIONS)), cur].filter(Boolean))];
  return h("select", { class: "act a-" + safeCls(cur) + (cur !== orig ? " dirty" : ""), "aria-label": `${cls} / ${seg} action`,
    onchange: (e) => { draft.actions[cls][seg] = e.target.value; renderPolicy(); } },
    opts.map((a) => h("option", { value: a, selected: a === cur }, (ACTIONS[a] ? ACTIONS[a].glyph + " " : "") + a)));
}
function actionsSection() {
  const classes = Object.keys(draft.actions);
  const segs = (choices().segments || ["human", ...SEGS]);
  return h("div", {}, h("h3", { class: "sub" }, "Segment to action"),
    h("p", { class: "hint" }, "What the lab does per endpoint class. Defaults are lab choices, not Akamai's. ", h("b", {}, "blocked"), " in reports means deny, tarpit or challenge; everything else returns a normal 2xx."),
    h("div", { class: "table-scroll" }, h("table", { class: "act-table" },
      h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Endpoint class"), segs.map((s) => h("th", { scope: "col" }, h("span", { class: "schip s-" + safeCls(s), title: SEGMENT_DESC[s] || "" }, s))))),
      h("tbody", {}, classes.map((c) => h("tr", {}, h("th", { scope: "row" }, h("b", {}, c), h("div", { class: "meta mono" }, EP_DESC[c] || "")),
        segs.map((s) => h("td", {}, draft.actions[c][s] !== undefined ? actionSelect(c, s) : h("span", { class: "meta" }, "unset")))))))));
}

function paramsSection() {
  const known = new Set(PARAM_GROUPS.flatMap(([, , items]) => items.map((i) => i[0])));
  const extra = Object.keys(draft.params).filter((k) => !known.has(k) && typeof draft.params[k] === "number").map((k) => [k, k, "", "num"]);
  const groups = extra.length ? [...PARAM_GROUPS, ["other", "Other", extra]] : PARAM_GROUPS;
  const field = ([key, name, hint, kind]) => {
    if (!(key in draft.params)) return null;
    const orig = base().params[key];
    const dirty = draft.params[key] !== orig;
    let ctl;
    if (kind === "provider") {
      const opts = [...new Set([...(choices().challenge_providers || []), draft.params[key]].filter(Boolean))];
      ctl = h("select", { "aria-label": name, class: dirty ? "dirty" : "", onchange: (e) => { draft.params[key] = e.target.value; renderPolicy(); } }, opts.map((o) => h("option", { value: o, selected: o === draft.params[key] }, o)));
    } else {
      const lim = { slow_chunks: [1, 50], chlg_duration: [0, 120], challenge_interval: [1, 7200], adaptive_count: [1, 10] }[key] || [0, undefined];
      ctl = numInput(draft.params[key], (v) => { draft.params[key] = v; }, { step: kind === "int" ? "1" : "0.1", min: lim[0], max: lim[1], "aria-label": name });
      if (dirty) ctl.classList.add("dirty");
    }
    return h("label", { class: "param" }, h("span", { class: "mono" }, name), ctl, hint ? h("span", { class: "meta" }, hint) : null);
  };
  return h("div", {}, h("h3", { class: "sub" }, "Action parameters"),
    h("div", { class: "param-groups" }, groups.map(([k, title, items]) => {
      const fields = items.map(field).filter(Boolean);
      return fields.length ? h("fieldset", { class: "pgroup" + (k === "challenge" ? " wide" : "") }, h("legend", {}, k === "challenge" || k === "other" ? title : actionChip(k)), fields) : null;
    })));
}

function statusBox() {
  if (!status.lines.length) return h("div", { id: "policy-status", class: "pstatus", role: "status", "aria-live": "polite" });
  return h("div", { id: "policy-status", class: "pstatus " + status.kind, role: status.kind === "error" ? "alert" : "status", "aria-live": "polite" },
    status.kind === "error" ? h("b", {}, "Rejected (422). Nothing was saved.") : null,
    h("ul", {}, status.lines.map((l) => h("li", {}, l))));
}

export function renderPolicy() {
  const box = $("policy");
  if (state.policyError || !state.policy) {
    box.replaceChildren(h("div", { class: "empty" }, "Policy unavailable (", state.policyError || "not loaded", "). ", h("button", { class: "btn sm", onclick: () => loadPolicy().catch(() => {}) }, "Retry")));
    return;
  }
  if (!draft) draft = clone(base());
  const { n } = diff();
  box.replaceChildren(
    h("div", { class: "policy-actions" },
      h("button", { class: "btn primary", disabled: n === 0, onclick: apply }, n ? `Apply ${n} change${n > 1 ? "s" : ""}` : "No changes"),
      h("button", { class: "btn", disabled: n === 0, onclick: () => { draft = clone(base()); status = { kind: "", lines: [] }; renderPolicy(); } }, "Discard"),
      h("button", { class: "btn danger", onclick: resetDefaults, title: "DELETE /api/policy" }, "Reset to defaults"),
      h("span", { class: "meta" }, "Applies to new requests. Past reports keep the action they got. POST /api/reset keeps the policy.")),
    statusBox(), bandsSection(), actionsSection(), paramsSection());
}

async function apply() {
  const { patch, n } = diff();
  if (!n) return;
  for (const k of Object.keys(patch)) if (!Object.keys(patch[k]).length) delete patch[k];
  try {
    await sendJson("PUT", "/api/policy", patch);
    draft = null;
    await loadPolicy();
    status = { kind: "ok", lines: ["Saved. The next requests use the new policy."] };
    renderPolicy();
  } catch (e) {
    status = { kind: "error", lines: errorLines(e) };
    renderPolicy();
  }
}
async function resetDefaults() {
  if (!confirm("Reset bands, actions and parameters to the lab defaults?")) return;
  try {
    await api("/api/policy", { method: "DELETE" });
    draft = null;
    await loadPolicy();
    status = { kind: "ok", lines: ["Policy reset to defaults."] };
    renderPolicy();
  } catch (e) { toast("Reset failed: " + errorLines(e).join("; "), "error"); }
}

export async function loadPolicy() {
  try {
    state.policy = await api("/api/policy");
    state.policyError = "";
    if (!draft || diff().n === 0) draft = clone(base());
  } catch (e) {
    state.policyError = e.status === 404 ? "this API version has no /api/policy" : e.message;
    throw e;
  } finally { renderPolicy(); }
}
