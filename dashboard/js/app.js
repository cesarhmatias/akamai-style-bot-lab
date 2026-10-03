// Bot Detection Lab dashboard. Plain ES module, no build step, no dependencies.
const STORE = "https://localhost:8443";
const LABELS = ["browser", "naive", "curl_cffi", "playwright"];
const MAX_ROWS = 300;
const state = { modules: [], reports: [], selected: null, tab: "headers", lastByCase: {}, total: 0, blocked: 0, scoreSum: 0, cmpCase: null };
const $ = (id) => document.getElementById(id);

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
const label = (r) => r.client_label || "browser";
const caseOf = (r) => { const m = /^\/protected\/([\w-]+)/.exec(r.path || ""); return m ? m[1] : null; };
const sigFor = (r, slug) => (r.signals || []).find((s) => s.module === slug);
const verdictOf = (r, slug) => {
  if (slug && slug !== "all") { const s = sigFor(r, slug); if (s) return s.verdict; }
  return r.blocked ? "block" : "pass";
};
const scoreClass = (s) => (s >= 50 ? "v-fail" : s >= 25 ? "v-warn" : "v-pass");
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
const json = (o) => { try { return JSON.stringify(o, null, 2); } catch { return String(o); } };

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(path + " " + r.status);
  return r.json();
}

// ---------- header ----------
function renderStats() {
  $("st-total").textContent = state.total;
  $("st-blocked").textContent = (state.total ? Math.round((state.blocked / state.total) * 100) : 0) + "%";
  $("st-avg").textContent = state.total ? Math.round(state.scoreSum / state.total) : 0;
}
function recount() {
  state.total = state.reports.length;
  state.blocked = state.reports.filter((r) => r.blocked).length;
  state.scoreSum = state.reports.reduce((a, r) => a + (r.score || 0), 0);
}
function setConn(on) {
  const c = $("conn");
  c.className = "conn " + (on ? "on" : "off");
  c.querySelector("b").textContent = on ? "live" : "reconnecting";
  $("banner").hidden = on;
}

// ---------- cases ----------
let firstCases = true;
function renderCases() {
  const box = $("cases");
  box.replaceChildren(...state.modules.map((m, i) => {
    const last = state.lastByCase[m.slug];
    const v = last ? verdictOf(last, m.slug) : "none";
    return h("article", { class: "card" + (m.enabled ? "" : " disabled"), style: firstCases ? `animation-delay:${i * 30}ms` : "animation:none" },
      h("div", { class: "row" }, h("h3", {}, m.title || m.slug), h("span", { class: "chip" }, m.category || "")),
      h("p", {}, m.description || ""),
      h("div", { class: "row" },
        h("span", { class: "badge v-" + v, title: last ? "Last verdict from " + label(last) : "No request yet" }, v === "none" ? "no data" : v),
        h("div", { class: "row" },
          h("a", { class: "btn", href: `${STORE}/protected/${encodeURIComponent(m.slug)}`, target: "_blank", rel: "noopener",
            title: "Opens in your real browser (so JS challenges run). The dashboard cannot probe it cross-origin because of the self-signed certificate." }, "Test ↗"),
          h("button", { class: "switch", role: "switch", "aria-checked": String(!!m.enabled), "aria-label": "Enable " + (m.title || m.slug),
            onclick: () => toggle(m) }))));
  }));
  if (state.modules.length) firstCases = false;
  renderCmpSelect();
}
async function toggle(m) {
  const enabled = !m.enabled;
  try {
    await api("/api/modules/" + encodeURIComponent(m.slug), { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled }) });
    m.enabled = enabled; renderCases();
  } catch (e) { setConn(false); }
}
async function loadModules() {
  const d = await api("/api/modules");
  state.modules = Array.isArray(d) ? d : d.modules || [];
  renderCases();
}

// ---------- feed ----------
function rowEl(r) {
  const sel = state.selected && state.selected.id === r.id;
  const el = h("div", { class: "feed-row" + (sel ? " sel" : ""), role: "option", "aria-selected": String(!!sel), tabindex: "-1", "data-id": r.id,
    onclick: () => select(r) },
    h("span", { class: "t mono" }, fmtTime(r.ts)),
    h("span", {}, h("span", { class: "chip c-" + label(r) }, label(r))),
    h("span", { class: "mono" }, r.method),
    h("span", { class: "path mono", title: r.path }, r.path),
    h("span", {}, h("span", { class: "pill " + scoreClass(r.score) }, r.score)),
    h("span", { class: "blk" }, r.blocked ? "BLOCK" : ""));
  return el;
}
function renderFeed() {
  const f = $("feed");
  if (!state.reports.length) { f.replaceChildren(h("p", { class: "empty" }, "No requests yet. Click Test on a case or run the client matrix.")); return; }
  f.replaceChildren(...state.reports.map(rowEl));
}
function ingest(r, live = true) {
  if (!r || !r.id || state.reports.some((x) => x.id === r.id)) return;
  state.reports.unshift(r);
  if (state.reports.length > MAX_ROWS) state.reports.length = MAX_ROWS;
  const c = caseOf(r);
  if (c && (!state.lastByCase[c] || state.lastByCase[c].ts <= r.ts)) state.lastByCase[c] = r;
  if (live) {
    recount(); renderStats(); renderCases(); renderCmp();
    const f = $("feed");
    if (f.querySelector(".empty")) f.replaceChildren();
    f.prepend(rowEl(r));
    while (f.children.length > MAX_ROWS) f.lastChild.remove();
    if (!state.selected) select(r);
  }
}
async function backfill() {
  const d = await api("/api/requests?limit=100");
  const list = (Array.isArray(d) ? d : d.requests || []).slice().sort((a, b) => a.ts - b.ts);
  state.reports = []; state.lastByCase = {};
  list.forEach((r) => ingest(r, false));
  recount(); renderStats(); renderFeed(); renderCases(); renderCmp();
  if (!state.selected && state.reports[0]) select(state.reports[0]);
}
let es, retry = 1000;
function connect() {
  if (es) es.close();
  es = new EventSource("/api/feed");
  es.onopen = () => { retry = 1000; setConn(true); backfill().then(loadModules).catch(() => {}); };
  es.addEventListener("report", (ev) => { try { ingest(JSON.parse(ev.data)); } catch {} });
  es.onerror = () => {
    setConn(false); es.close();
    setTimeout(connect, retry); retry = Math.min(retry * 1.7, 10000);
  };
}

// ---------- gauge ----------
function gauge(score, blocked) {
  const R = 52, C = 2 * Math.PI * R, ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 140 140"); svg.setAttribute("width", "150"); svg.setAttribute("height", "150");
  svg.setAttribute("class", "gauge"); svg.setAttribute("role", "img"); svg.setAttribute("aria-label", `Score ${score} of 100${blocked ? ", blocked" : ""}`);
  const col = blocked ? "var(--block)" : score >= 50 ? "var(--fail)" : score >= 25 ? "var(--warn)" : "var(--pass)";
  svg.innerHTML = `<g transform="rotate(135 70 70)"><circle cx="70" cy="70" r="${R}" fill="none" stroke="#1a2540" stroke-width="12" stroke-linecap="round" stroke-dasharray="${C * 0.75} ${C}"/>
  <circle class="arc" cx="70" cy="70" r="${R}" fill="none" stroke="${col}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${C * 0.75} ${C}" stroke-dashoffset="${C * 0.75}"/></g>
  <text x="70" y="72" text-anchor="middle" font-size="30" font-weight="700">${score}</text>
  <text x="70" y="92" text-anchor="middle" font-size="10" fill="#8b9ab8" style="fill:#8b9ab8">${blocked ? "BLOCKED" : "ALLOWED"}</text>`;
  const arc = svg.querySelector(".arc");
  requestAnimationFrame(() => requestAnimationFrame(() => arc.setAttribute("stroke-dashoffset", String(C * 0.75 * (1 - Math.min(score, 100) / 100)))));
  return svg;
}

// ---------- detail ----------
const ICON = { pass: "✓", warn: "!", fail: "✕", block: "■", skip: "–" };
function signalEl(s) {
  const v = s.verdict || "skip";
  return h("details", { class: "sig v-" + v },
    h("summary", {},
      h("span", { class: "ico" }, ICON[v] || "?"),
      h("b", {}, s.module),
      h("div", { class: "bar", title: s.score + "/100" }, h("i", { style: `width:${Math.min(100, s.score || 0)}%` })),
      h("span", { class: "mono" }, s.score)),
    h("div", { class: "reason" }, s.reason || ""),
    s.details && Object.keys(s.details).length ? h("pre", {}, json(s.details)) : null);
}
function select(r) {
  state.selected = r;
  document.querySelectorAll(".feed-row").forEach((e) => { const on = e.dataset.id === r.id; e.classList.toggle("sel", on); e.setAttribute("aria-selected", String(on)); });
  renderDetail();
}
function fp(r, ...names) {
  const f = r.fingerprint || {};
  for (const k of Object.keys(f)) { const kk = k.toLowerCase().replace(/^x-/, "").replace(/[-_]/g, ""); if (names.includes(kk)) return f[k]; }
  return "";
}
const H2_SETTINGS = { 1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE" };
function parseH2(s) {
  const out = {};
  for (const m of String(s).matchAll(/(S|WU|PS|P)\[([^\]]*)\]/g)) out[m[1]] = m[2];
  if (!Object.keys(out).length && s) { const [a, b, c, d] = s.split("|"); Object.assign(out, { S: a, WU: b, P: c, PS: d }); }
  return out;
}
function h2View(r) {
  const raw = fp(r, "h2fingerprint", "h2", "http2");
  if (!raw) return h("p", { class: "empty" }, "No HTTP/2 fingerprint (connection was HTTP/1.1 or the field is absent).");
  const p = parseH2(raw);
  const settings = (p.S || "").split(/[;,]/).filter(Boolean).map((kv) => { const [k, v] = kv.split(":"); return h("tr", {}, h("th", {}, `${k} ${H2_SETTINGS[k] || ""}`), h("td", { class: "mono" }, v)); });
  const pseudo = (p.PS || "").split(",").filter(Boolean).map((x) => ({ m: ":method", a: ":authority", s: ":scheme", p: ":path" })[x] || x).join("  ");
  return h("div", {}, h("p", { class: "mono meta" }, raw),
    h("h2", {}, "SETTINGS"), h("table", {}, settings),
    h("dl", { class: "kv" },
      h("dt", {}, "WINDOW_UPDATE"), h("dd", { class: "mono" }, p.WU ?? "-"),
      h("dt", {}, "PRIORITY"), h("dd", { class: "mono" }, p.P ?? "-"),
      h("dt", {}, "Pseudo-header order"), h("dd", { class: "mono" }, pseudo || "-")));
}
function kvTable(rows) {
  if (!rows.length) return h("p", { class: "empty" }, "Nothing recorded.");
  return h("table", {}, rows.map(([k, v]) => h("tr", {}, h("th", { class: "mono" }, k), h("td", { class: "mono" }, v))));
}
function tabBody(r) {
  switch (state.tab) {
    case "headers": {
      const order = fp(r, "headerorder");
      const names = order ? order.split(",").map((s) => s.trim()).filter(Boolean) : [];
      const hs = (r.headers || []).map((p) => [p[0], p[1]]);
      return h("div", {}, names.length ? h("p", { class: "meta" }, "Wire order: ", h("span", { class: "mono" }, names.join(" → "))) : null, kvTable(hs));
    }
    case "tls": return kvTable([["JA3", fp(r, "ja3")], ["JA3 hash", fp(r, "ja3hash")], ["JA4", fp(r, "ja4")]].filter((x) => x[1]).concat(
      Object.entries(r.fingerprint || {}).filter(([k]) => !/ja3|ja4|h2|order/i.test(k))));
    case "h2": return h2View(r);
    default: return kvTable(Object.entries(r.cookies || {}));
  }
}
function renderDetail() {
  const r = state.selected, box = $("detail");
  if (!r) return;
  const tabs = [["headers", "Headers"], ["tls", "TLS"], ["h2", "HTTP/2"], ["cookies", "Cookies"]];
  const tablist = h("div", { class: "tabs", role: "tablist" }, tabs.map(([k, t]) => h("button", { class: "tab", role: "tab", "aria-selected": String(state.tab === k),
    onclick: () => { state.tab = k; renderDetail(); },
    onkeydown: (e) => { if (e.key === "ArrowRight" || e.key === "ArrowLeft") { const i = tabs.findIndex((x) => x[0] === state.tab) + (e.key === "ArrowRight" ? 1 : -1); state.tab = tabs[(i + 4) % 4][0]; renderDetail(); box.querySelector('[aria-selected=true]').focus(); } } }, t)));
  box.replaceChildren(
    h("div", { class: "gauge-wrap" }, gauge(r.score, r.blocked), h("div", {},
      h("div", { class: "mono" }, r.method + " " + r.path),
      h("div", { class: "meta" }, `${r.client_ip} · ${label(r)} · ${fmtTime(r.ts)}`),
      h("div", { class: "meta" }, r.user_agent))),
    h("div", { class: "signals" }, (r.signals || []).map(signalEl)),
    tablist, h("div", { role: "tabpanel", style: "padding-top:8px;max-height:320px;overflow:auto" }, tabBody(r)));
}

// ---------- comparison ----------
function renderCmpSelect() {
  const sel = $("cmp-case");
  const slugs = ["all", ...state.modules.map((m) => m.slug)];
  if (!state.cmpCase || !slugs.includes(state.cmpCase)) state.cmpCase = slugs[1] || "all";
  sel.replaceChildren(...slugs.map((s) => h("option", { value: s, selected: s === state.cmpCase }, s)));
  renderCmp();
}
function renderCmp() {
  const slug = state.cmpCase, box = $("cmp");
  if (!slug) return;
  const path = "/protected/" + slug;
  const latest = {};
  for (const r of state.reports) if ((r.path || "").split("?")[0] === path && !latest[label(r)]) latest[label(r)] = r; // reports are newest-first
  const labels = [...LABELS, ...Object.keys(latest).filter((l) => !LABELS.includes(l))];
  const mods = slug === "all" ? [...new Set(Object.values(latest).flatMap((r) => (r.signals || []).map((s) => s.module)))] : [slug];
  const diffMods = new Set(mods.filter((m) => new Set(Object.values(latest).map((r) => sigFor(r, m)?.verdict ?? "-")).size > 1));
  const cols = labels.map((l) => {
    const r = latest[l];
    if (!r) return h("div", { class: "col none" }, h("span", { class: "chip c-" + l }, l), h("p", { class: "meta" }, "No request yet."));
    return h("div", { class: "col" },
      h("div", { class: "row" }, h("span", { class: "chip c-" + l }, l), h("span", { class: "pill " + scoreClass(r.score) }, r.score)),
      h("div", { class: "meta" }, r.blocked ? "Blocked" : "Allowed"),
      mods.map((m) => { const s = sigFor(r, m); if (!s) return null; return h("div", { class: "sig-line v-" + s.verdict + (diffMods.has(m) ? " diff" : "") },
        h("span", { class: "badge v-" + s.verdict }, s.verdict), " ", slug === "all" ? h("b", {}, m + " ") : null, h("div", { class: "meta" }, s.reason)); }));
  });
  const have = Object.keys(latest);
  const why = [];
  const passed = have.filter((l) => !latest[l].blocked), failed = have.filter((l) => latest[l].blocked);
  if (passed.length && failed.length) {
    why.push(h("p", {}, h("b", {}, "Why the difference: "), `${passed.join(", ")} passed while ${failed.join(", ")} did not.`));
    const items = [];
    for (const m of mods) for (const f of failed) {
      const s = sigFor(latest[f], m);
      if (s && ["fail", "warn", "block"].includes(s.verdict)) items.push(h("li", {}, h("b", {}, f), ` / ${m}: ${s.reason}`));
    }
    why.push(h("ul", {}, items.slice(0, 8)));
  } else if (have.length) why.push(h("p", { class: "meta" }, "All observed clients got the same outcome for this case; highlighted rows would mark per-signal differences."));
  box.replaceChildren(h("div", { class: "cmp-grid" }, cols), why.length ? h("div", { class: "why" }, why) : null);
}

// ---------- boot ----------
$("cmp-case").addEventListener("change", (e) => { state.cmpCase = e.target.value; renderCmp(); });
$("reset").addEventListener("click", async () => {
  if (!confirm("Clear all lab state and the feed?")) return;
  try { await api("/api/reset", { method: "POST" }); } catch { setConn(false); return; }
  state.reports = []; state.lastByCase = {}; state.selected = null; recount(); renderStats(); renderFeed(); renderCases(); renderCmp();
  $("detail").replaceChildren(h("p", { class: "empty" }, "Select a request from the feed."));
});
$("feed").addEventListener("keydown", (e) => {
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  e.preventDefault();
  const i = state.reports.findIndex((r) => state.selected && r.id === state.selected.id) + (e.key === "ArrowDown" ? 1 : -1);
  const r = state.reports[Math.max(0, Math.min(state.reports.length - 1, i))];
  if (r) { select(r); $("feed").querySelector(".sel")?.scrollIntoView({ block: "nearest" }); }
});
renderFeed();
loadModules().catch(() => setConn(false));
connect();
