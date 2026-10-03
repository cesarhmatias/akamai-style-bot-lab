// Feature flags panel: GET /api/flags, PUT /api/flags/{name}. LOW-tier flags are unverified (vendor-sourced).
import { $, h, state, api, sendJson, toast, confChip, CONF_ORDER, UNVERIFIED, errorLines } from "./util.js";

const ui = { q: "", tiers: new Set(), changed: false };
const listeners = [];
export const onFlagsChange = (cb) => listeners.push(cb);
const moduleOf = (name) => (state.modules.find((m) => (m.flags || []).includes(name)) || {}).slug || "";

function row(f) {
  const low = f.confidence === "low";
  const mod = moduleOf(f.name);
  const changed = typeof f.default === "boolean" && f.value !== f.default;
  return h("div", { class: "flag-row" + (low ? " low" : "") + (changed ? " changed" : ""), id: "flag-" + f.name },
    h("div", { class: "flag-main" },
      h("div", { class: "row-wrap" },
        h("code", {}, f.name),
        confChip(f.confidence, f.confidence || "?"),
        low ? h("span", { class: "tag unv", title: "Only vendor sources describe this behaviour; the lab cannot confirm Akamai does it." }, UNVERIFIED) : null,
        mod ? h("a", { class: "tag ep", href: "#case-" + mod, title: "Declared by module " + mod }, mod) : null,
        changed ? h("span", { class: "tag chg", title: "Differs from the default" }, "changed") : null),
      h("p", {}, f.description || ""),
      h("p", { class: "meta" }, "default ", h("b", {}, f.default ? "on" : "off"), f.source ? " · source: " + f.source : "")),
    h("div", { class: "flag-ctl" },
      h("span", { class: "meta mono" }, f.value ? "on" : "off"),
      h("button", { class: "switch", role: "switch", "aria-checked": String(!!f.value), "aria-label": `${f.name}: ${f.value ? "on" : "off"}`, onclick: () => toggle(f) })));
}

export function renderFlags() {
  const box = $("flags"), bar = $("flags-bar");
  const all = state.flags;
  if (state.flagsError) {
    bar.replaceChildren();
    box.replaceChildren(h("div", { class: "empty" }, "Flags unavailable (", state.flagsError, "). ", h("button", { class: "btn sm", onclick: () => loadFlags().catch(() => {}) }, "Retry")));
    $("flags-count").textContent = "";
    return;
  }
  const q = ui.q.trim().toLowerCase();
  const list = all.filter((f) => (!ui.tiers.size || ui.tiers.has(f.confidence)) && (!ui.changed || f.value !== f.default) &&
    (!q || `${f.name} ${f.description} ${f.source}`.toLowerCase().includes(q)));
  const low = all.filter((f) => f.confidence === "low");
  $("flags-count").textContent = all.length ? `${all.length} flags · ${all.filter((f) => f.value).length} on · ${low.length} unverified` : "";
  const focused = document.activeElement && document.activeElement.id === "flag-q";
  bar.replaceChildren(h("div", { class: "toolbar" },
    h("input", { type: "search", id: "flag-q", placeholder: "Filter flags…", "aria-label": "Filter flags", value: ui.q, oninput: (e) => { ui.q = e.target.value; renderFlags(); } }),
    h("div", { class: "fgroup", role: "group", "aria-label": "Tier" }, CONF_ORDER.map((c) =>
      h("button", { class: "fchip c-" + c, "aria-pressed": String(ui.tiers.has(c)), onclick: () => { ui.tiers.has(c) ? ui.tiers.delete(c) : ui.tiers.add(c); renderFlags(); } }, c))),
    h("button", { class: "fchip", "aria-pressed": String(ui.changed), onclick: () => { ui.changed = !ui.changed; renderFlags(); } }, "changed from default"),
    h("span", { class: "meta" }, list.length === all.length ? "" : `${list.length} shown`)));
  if (focused) { const i = $("flag-q"); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }
  box.replaceChildren(...(list.length ? list.map(row) : [h("p", { class: "empty" }, all.length ? "No flag matches the filters." : "No flags declared.")]));
}

async function toggle(f) {
  const value = !f.value;
  try {
    await sendJson("PUT", "/api/flags/" + encodeURIComponent(f.name), { value });
    f.value = value; renderFlags(); listeners.forEach((cb) => cb());
    toast(`${f.name} ${value ? "enabled" : "disabled"}` + (f.confidence === "low" ? " (unverified behaviour)" : ""));
  } catch (e) { toast("Could not set " + f.name + ": " + errorLines(e).join("; "), "error"); }
}

export async function loadFlags() {
  try {
    const d = await api("/api/flags");
    state.flags = Array.isArray(d) ? d : [];
    state.flagsError = "";
  } catch (e) {
    state.flagsError = e.status === 404 ? "this API version has no /api/flags" : e.message;
    throw e;
  } finally { renderFlags(); listeners.forEach((cb) => cb()); }
}

// Jump from a case card to its flag row.
export function focusFlag(name) {
  const panel = $("sec-flags");
  if (panel) panel.open = true;
  ui.q = ""; ui.tiers.clear(); ui.changed = false; renderFlags();
  const el = $("flag-" + name);
  if (!el) return;
  el.scrollIntoView({ block: "center", behavior: "smooth" });
  el.classList.add("hit"); setTimeout(() => el.classList.remove("hit"), 1800);
  el.querySelector(".switch")?.focus({ preventScroll: true });
}
