// Shared helpers, constants and state for the dashboard. Plain ES module, no dependencies.
export const STORE = "https://localhost:8443";
export const LABELS = ["browser", "naive", "curl_cffi", "playwright"];
export const MAX_ROWS = 300;

export const state = {
  modules: [], flags: [], policy: null, reports: [], selected: null, tab: "headers", lastByCase: {},
  cmpCase: null, feedFilter: "",
};

export const $ = (id) => document.getElementById(id);

export function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}

export class ApiError extends Error {
  constructor(path, status, data) { super(`${path} ${status}`); this.status = status; this.data = data; }
}
export async function api(path, opts) {
  const r = await fetch(path, opts);
  let data = null;
  try { data = await r.json(); } catch { /* empty or non-JSON body */ }
  if (!r.ok) throw new ApiError(path, r.status, data);
  return data;
}
export const sendJson = (method, path, body) =>
  api(path, { method, headers: { "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });

// Pydantic 422 payloads: {detail: [{loc, msg, ...}]} or {detail: "text"}.
export function errorLines(e) {
  const d = e && e.data && e.data.detail;
  if (Array.isArray(d)) return d.map((x) => `${(x.loc || []).filter((p) => p !== "body").join(".") || "policy"}: ${x.msg || JSON.stringify(x)}`);
  if (typeof d === "string") return [d];
  return [e && e.message ? e.message : "request failed"];
}

export const label = (r) => r.client_label || "browser";
export const caseOf = (r) => { const m = /^\/protected\/([\w-]+)/.exec(r.path || ""); return m ? m[1] : null; };
export const sigFor = (r, slug) => (r.signals || []).find((s) => s.module === slug);
export const scoreClass = (s) => (s >= 50 ? "v-fail" : s >= 25 ? "v-warn" : "v-pass");
export const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
export const json = (o) => { try { return JSON.stringify(o, null, 2); } catch { return String(o); } };
export const safeCls = (s) => String(s || "unknown").replace(/[^\w-]/g, "_");

// Persisted UI preferences; storage can be blocked, so never rely on it.
export const pref = {
  get(k, d) { try { const v = localStorage.getItem("lab." + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("lab." + k, JSON.stringify(v)); } catch { /* ignore */ } },
};

export function toast(msg, kind = "info") {
  const box = $("toasts");
  if (!box) return;
  const t = h("div", { class: "toast " + kind }, msg);
  box.append(t);
  setTimeout(() => t.remove(), kind === "error" ? 6000 : 2800);
}

// ---------- actions ----------
// Everything the lab can do with a request (contract.Action). Unknown values fall back to a neutral style.
export const ACTIONS = {
  allow: { glyph: "✓", desc: "Real response, nothing recorded against the client (Bot Score 0 is treated as human)." },
  monitor: { glyph: "◉", desc: "Real response; the verdict is only recorded." },
  delay: { glyph: "◔", desc: "Real response after a fixed pause." },
  slow: { glyph: "≈", desc: "Real response streamed slowly in chunks." },
  challenge: { glyph: "?", desc: "Client got a challenge (428 JSON for XHR, an interstitial for navigations) instead of the resource." },
  tarpit: { glyph: "◍", desc: "Connection held, then a minimal 403." },
  serve_alternate: { glyph: "⇄", desc: "HTTP 200 with subtly wrong data and a hidden canary token (silent degradation)." },
  safeguard: { glyph: "◈", desc: "A challenge that was waived so a human is not trapped (isSafeguardResponse analogue)." },
  deny: { glyph: "✕", desc: "Deny page / 403 with an Akamai-style reference." },
};
export const ACTION_ORDER = ["deny", "tarpit", "challenge", "serve_alternate", "slow", "delay", "safeguard", "monitor", "allow"];
export const actionChip = (a, extra = "") => {
  const m = ACTIONS[a] || { glyph: "·", desc: "Unknown action reported by the API." };
  return h("span", { class: "achip a-" + safeCls(a) + (extra ? " " + extra : ""), title: m.desc }, h("i", { "aria-hidden": "true" }, m.glyph), a || "unknown");
};

export const SEGMENT_DESC = {
  human: "Bot Score 0: no detection fired.", cautious: "Low Bot Score band.", strict: "Middle Bot Score band.", aggressive: "High Bot Score band.",
};
export const segChip = (s) => (s ? h("span", { class: "schip s-" + safeCls(s), title: SEGMENT_DESC[s] || "Bot Score segment" }, s) : null);
export const tag = (text, title, cls = "") => h("span", { class: "tag " + cls, title }, text);

// ---------- confidence tiers ----------
export const CONF = {
  high: { name: "High", desc: "Backed by several public sources. Real lab behaviour, on by default." },
  medium: { name: "Medium", desc: "Implemented as a documented approximation of what Akamai is believed to do." },
  low: { name: "Low", desc: "Vendor-sourced and unverified. Active only behind a feature flag (default off)." },
  lab: { name: "Lab", desc: "Teaching device with no known Akamai analogue." },
};
export const CONF_ORDER = ["high", "medium", "low", "lab"];
export const confChip = (c, text) => {
  if (!c) return null;
  const m = CONF[c];
  return h("span", { class: "cchip c-" + safeCls(c), title: (m ? m.name + ": " + m.desc : "Unknown tier") }, text || c);
};
export const UNVERIFIED = "unverified (vendor-sourced)";
