// Request inspector: action/segment chips, cross-layer agreement, per-signal confidence, fingerprint decoding.
import { $, h, state, json, label, fmtTime, safeCls, actionChip, segChip, confChip, tag, ACTIONS } from "./util.js";

const hdr = (r, name) => { const p = (r.headers || []).find((x) => String(x[0]).toLowerCase() === name); return p ? String(p[1]) : ""; };
const isEdge = (k) => /^x-(tls|h2|ja3)-/i.test(k);
const num = (v) => typeof v === "number" && Number.isFinite(v);

// ---------- gauge ----------
export function gauge(score, blocked, action) {
  const R = 52, C = 2 * Math.PI * R, ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  const text = (action || (blocked ? "blocked" : "allowed")).replace("_", " ").toUpperCase();
  svg.setAttribute("viewBox", "0 0 140 140"); svg.setAttribute("width", "150"); svg.setAttribute("height", "150");
  svg.setAttribute("class", "gauge a-" + safeCls(action || (blocked ? "deny" : "allow"))); svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `Bot score ${score} of 100, action ${text.toLowerCase()}`);
  svg.innerHTML = `<g transform="rotate(135 70 70)"><circle cx="70" cy="70" r="${R}" fill="none" stroke="#1a2540" stroke-width="12" stroke-linecap="round" stroke-dasharray="${C * 0.75} ${C}"/>
  <circle class="arc" cx="70" cy="70" r="${R}" fill="none" style="stroke:var(--c)" stroke-width="12" stroke-linecap="round" stroke-dasharray="${C * 0.75} ${C}" stroke-dashoffset="${C * 0.75}"/></g>
  <text x="70" y="72" text-anchor="middle" font-size="30" font-weight="700">${Number(score) || 0}</text>
  <text x="70" y="92" text-anchor="middle" font-size="${text.length > 9 ? 8 : 10}" style="fill:var(--c)" font-weight="700">${text.replace(/[<>&]/g, "")}</text>`;
  const arc = svg.querySelector(".arc");
  requestAnimationFrame(() => requestAnimationFrame(() => arc.setAttribute("stroke-dashoffset", String(C * 0.75 * (1 - Math.min(score || 0, 100) / 100)))));
  return svg;
}

// ---------- cross-layer agreement (version_consistency -> report.layers) ----------
function windowText(lo, hi) {
  if (!num(lo) && !num(hi)) return "no marker seen";
  if (num(lo) && num(hi)) return lo === hi ? `exactly ${lo}` : `${lo} to ${hi}`;
  return num(lo) ? `${lo} or newer` : `${hi} or older`;
}
function layerViz(L) {
  const lo = Math.max(...[L.tls_min, L.hdr_min].filter(num), -Infinity);
  const hi = num(L.tls_max) ? L.tls_max : Infinity;
  const claims = [["User-Agent", L.ua_major], ["sec-ch-ua", L.sech_major], ["JS userAgentData", L.js_major]].filter((c) => num(c[1]));
  const nums = [...claims.map((c) => c[1]), ...[lo, hi].filter(Number.isFinite)];
  if (!nums.length) return null;
  const dmin = Math.min(...nums) - 2, dmax = Math.max(...nums) + 2, span = dmax - dmin;
  const pos = (v) => ((v - dmin) / span) * 100;
  const wl = Number.isFinite(lo) ? pos(lo) : 0, wr = Number.isFinite(hi) ? pos(hi) : 100;
  const groups = new Map();
  for (const [name, v] of claims) groups.set(v, [...(groups.get(v) || []), name]);
  const marks = [...groups].sort((a, b) => a[0] - b[0]).map(([v, names], i) => {
    const ok = v >= lo && v <= hi;
    return h("div", { class: "lay-mark " + (ok ? "ok" : "bad") + (i % 2 ? " lower" : ""), style: `left:${pos(v)}%` },
      h("b", {}, v + (ok ? "" : " ✕")), h("span", {}, names.join(" + ")));
  });
  const wtxt = Number.isFinite(lo) || Number.isFinite(hi) ? `transport window: ${windowText(Number.isFinite(lo) ? lo : null, Number.isFinite(hi) ? hi : null)}` : "";
  return h("div", { class: "lay-viz", role: "img", "aria-label": `Claimed Chrome majors ${claims.map((c) => c[0] + " " + c[1]).join(", ")}; ${wtxt}` },
    h("div", { class: "lay-axis" },
      wtxt ? h("div", { class: "lay-win" + (Number.isFinite(hi) ? "" : " open"), style: `left:${wl}%;width:${Math.max(wr - wl, 1)}%`, title: wtxt }) : null,
      marks),
    wtxt ? h("div", { class: "meta lay-cap" }, wtxt) : null);
}
export function layersCard(r) {
  const L = r.layers && typeof r.layers === "object" ? r.layers : {};
  const sig = (r.signals || []).find((s) => s.module === "version_consistency");
  const has = Object.keys(L).length > 0;
  let state_ = "na", word = "N/A", why = "";
  if (!has) why = sig ? "version_consistency reported no layer data." : "version_consistency did not run for this request (module disabled, or an older report).";
  else if (L.applicable === false) why = (sig && sig.reason) || "Not a Chromium user agent: Chrome era markers do not apply.";
  else { state_ = L.agree === false ? "bad" : "ok"; word = L.agree === false ? "DISAGREE" : "AGREE"; why = sig && sig.reason ? sig.reason : ""; }
  const head = h("div", { class: "lay-head" },
    h("div", {}, h("h4", {}, "Cross-layer agreement"), h("p", { class: "meta" }, "Does the client's story agree across layers? TLS, headers and JavaScript must all describe the same browser release.")),
    h("span", { class: "verdict-big l-" + state_, role: "status" }, h("i", { "aria-hidden": "true" }, state_ === "ok" ? "✓" : state_ === "bad" ? "✕" : "–"), word));
  if (!has || L.applicable === false) return h("section", { class: "layers l-" + state_, "aria-label": "Cross-layer agreement" }, head, h("p", { class: "meta" }, why));
  const dis = Array.isArray(L.disagreements) ? L.disagreements : [];
  const ev = Array.isArray(L.evidence) ? L.evidence : [];
  const row = (k, v, note) => [h("dt", {}, k), h("dd", { class: "mono" }, v, note ? h("span", { class: "meta" }, " " + note) : null)];
  return h("section", { class: "layers l-" + state_, "aria-label": "Cross-layer agreement" }, head,
    layerViz(L),
    h("dl", { class: "kv lay-kv" },
      row("User-Agent major", num(L.ua_major) ? String(L.ua_major) : "-"),
      row("sec-ch-ua major", num(L.sech_major) ? String(L.sech_major) : "-", num(L.sech_major) ? "" : "(header absent)"),
      row("JS userAgentData major", num(L.js_major) ? String(L.js_major) : "-", num(L.js_major) ? "" : "(no sensor posted yet)"),
      row("TLS-implied version", windowText(L.tls_min, L.tls_max), L.tls_family ? `(${L.tls_family}-shaped hello)` : ""),
      row("Header-implied minimum", num(L.hdr_min) ? `${L.hdr_min} or newer` : "none", "(zstd, priority)")),
    dis.length ? h("div", { class: "lay-list bad" }, h("b", {}, "Disagreements"), h("ul", {}, dis.map((d) => h("li", {}, d)))) : null,
    ev.length ? h("div", { class: "lay-list" }, h("b", {}, "Evidence"), h("ul", {}, ev.map((d) => h("li", {}, d)))) : null,
    why && !dis.length ? h("p", { class: "meta" }, why) : null);
}

// ---------- signals ----------
const ICON = { pass: "✓", warn: "!", fail: "✕", block: "■", skip: "–" };
function signalEl(s) {
  const v = s.verdict || "skip";
  return h("details", { class: "sig v-" + safeCls(v) },
    h("summary", {},
      h("span", { class: "ico" }, ICON[v] || "?"),
      h("span", { class: "sig-name" }, h("b", {}, s.module), confChip(s.confidence, s.confidence)),
      h("div", { class: "bar", title: s.score + "/100" }, h("i", { style: `width:${Math.min(100, s.score || 0)}%` })),
      h("span", { class: "mono" }, s.score)),
    h("div", { class: "reason" }, s.reason || ""),
    s.details && Object.keys(s.details).length ? h("pre", {}, json(s.details)) : null);
}
function signalsBlock(r) {
  const order = { block: 0, fail: 1, warn: 2, pass: 3, skip: 4 };
  const sigs = (r.signals || []).slice().sort((a, b) => (order[a.verdict] ?? 5) - (order[b.verdict] ?? 5) || (b.score || 0) - (a.score || 0));
  const active = sigs.filter((s) => s.verdict !== "skip"), skipped = sigs.filter((s) => s.verdict === "skip");
  return h("div", { class: "signals" },
    active.map(signalEl),
    skipped.length ? h("details", { class: "skipped" }, h("summary", {}, `${skipped.length} skipped module${skipped.length > 1 ? "s" : ""} (not applicable to this request)`), skipped.map(signalEl)) : null);
}

// ---------- fingerprint decoding ----------
const GROUPS = { 23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448", 256: "ffdhe2048", 257: "ffdhe3072", 4587: "SecP256r1MLKEM768", 4588: "X25519MLKEM768", 4589: "SecP384r1MLKEM1024", 25497: "X25519Kyber768Draft00" };
const GROUP_NOTE = { 4588: "Chrome 131+ (hybrid ML-KEM replaced the Kyber draft)", 25497: "Chrome 130 or older (Kyber draft)" };
const SIGALGS = { "0401": "rsa_pkcs1_sha256", "0501": "rsa_pkcs1_sha384", "0601": "rsa_pkcs1_sha512", "0201": "rsa_pkcs1_sha1", "0403": "ecdsa_secp256r1_sha256", "0503": "ecdsa_secp384r1_sha384", "0603": "ecdsa_secp521r1_sha512", "0203": "ecdsa_sha1",
  "0804": "rsa_pss_rsae_sha256", "0805": "rsa_pss_rsae_sha384", "0806": "rsa_pss_rsae_sha512", "0807": "ed25519", "0808": "ed448", "0809": "rsa_pss_pss_sha256", "080a": "rsa_pss_pss_sha384", "080b": "rsa_pss_pss_sha512",
  "0904": "ML-DSA-44", "0905": "ML-DSA-65", "0906": "ML-DSA-87" };
const split = (s) => String(s || "").split(",").map((x) => x.trim()).filter(Boolean);

function chipList(items) { return h("span", { class: "chiplist" }, items.map(([t, title, cls]) => h("span", { class: "tag " + (cls || ""), title: title || null }, t))); }
function edgeRows(r) {
  const rows = [];
  const add = (name, val, view, note) => { if (val !== "") rows.push(h("tr", {}, h("th", { class: "mono" }, name), h("td", {}, h("div", { class: "mono" }, val), view || null, h("div", { class: "meta" }, note)))); };
  const groups = hdr(r, "x-tls-groups");
  add("x-tls-groups", groups, chipList(split(groups).map((g) => {
    const name = g === "grease" ? "GREASE" : GROUPS[g] || "unknown";
    return [`${g} ${name}`, GROUP_NOTE[g] || null, GROUP_NOTE[g] ? "era" : ""];
  })), "supported_groups in wire order. 4588 = X25519MLKEM768 means Chrome 131+; 25497 = the older Kyber draft means 130 or older.");
  const sig = hdr(r, "x-tls-sigalgs");
  add("x-tls-sigalgs", sig, chipList(split(sig).map((a) => {
    const low = a.toLowerCase(), ml = ["0904", "0905", "0906"].includes(low);
    return [`${low} ${a === "grease" ? "GREASE" : SIGALGS[low] || "unknown"}`, ml ? "Chrome 150+ marker (MEDIUM confidence: Go 1.27 also advertises ML-DSA)" : null, ml ? "era" : ""];
  })), "signature_algorithms, 4-digit hex. ML-DSA (0904 to 0906) in a Chrome-shaped hello suggests Chrome 150+ (medium confidence).");
  add("x-tls-alpn", hdr(r, "x-tls-alpn"), null, "Protocols offered. Real browsers offer h2 and http/1.1.");
  const alps = hdr(r, "x-tls-alps");
  add("x-tls-alps", alps, alps ? chipList([[alps === "17613" ? "17613 new ALPS codepoint" : alps === "17513" ? "17513 legacy ALPS codepoint" : "no ALPS", alps === "17613" ? "Chrome 133+" : alps === "17513" ? "Chrome 132 or older" : null, alps === "none" ? "" : "era"]]) : null,
    "ALPS (application_settings) extension. 17613 = new codepoint, Chrome 133+. 17513 = legacy codepoint, Chrome 132 or older (curl_cffi profiles often still send it).");
  add("x-tls-conn", hdr(r, "x-tls-conn"), null, "Opaque per-connection id (hash of the client random). Same value = same connection. Chrome shuffles extension order on every connection, so an identical order across many connections is a bot hint.");
  add("x-tls-exts", hdr(r, "x-tls-exts"), null, "Raw extension order as sent (shuffled by real Chrome 110+).");
  add("x-ja3-grease", hdr(r, "x-ja3-grease"), null, "GREASE placeholders seen in the hello (JA3 strips them).");
  const hp = hdr(r, "x-h2-headers-priority");
  add("x-h2-headers-priority", hp, null, "Priority carried by the first HEADERS frame (exclusive:dependency:weight) or none. Outside the Akamai string; shown, not scored.");
  return rows;
}

const H2_SETTINGS = { 1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE", 8: "ENABLE_CONNECT_PROTOCOL", 9: "NO_RFC7540_PRIORITIES" };
const PSEUDO = { m: ":method", a: ":authority", s: ":scheme", p: ":path" };
function parseH2(s) {
  s = String(s || "");
  const out = {};
  if (s.includes("[")) { for (const m of s.matchAll(/(S|WU|PS|P)\[([^\]]*)\]/g)) out[m[1]] = m[2]; return out; }
  const [a, b, c, d] = s.split("|");
  return { S: a, WU: b, P: c, PS: d };
}
function h2Section(r) {
  const paper = (r.fingerprint || {}).h2 || "";
  const labeled = hdr(r, "x-h2-fingerprint-labeled");
  const proto = (r.fingerprint || {}).proto || hdr(r, "x-http-proto");
  const raw = paper || labeled;
  if (!raw) return h("p", { class: "empty" }, "No HTTP/2 fingerprint" + (proto ? ` (connection was ${proto})` : " (field absent)") + ".");
  const p = parseH2(raw);
  const settings = (p.S || "").split(";").filter(Boolean).map((kv) => { const [k, v] = kv.split(":"); return h("tr", {}, h("th", { class: "mono" }, `${k} ${H2_SETTINGS[k] || "unknown"}`), h("td", { class: "mono" }, v)); });
  const wu = p.WU == null || p.WU === "" ? "-" : /^0+$/.test(p.WU) ? "absent (no WINDOW_UPDATE frame)" : p.WU;
  const prio = !p.P || p.P === "0" ? ["none"] : p.P.split(",").map((t) => { const [st, ex, dep, w] = t.split(":"); return w === undefined ? t : `stream ${st}, ${ex === "1" ? "exclusive" : "shared"}, dep ${dep}, weight ${w}`; });
  const pseudo = (p.PS || "").split(",").filter(Boolean).map((x) => PSEUDO[x] || x).join("  ");
  return h("div", {},
    h("dl", { class: "kv" },
      h("dt", {}, "Akamai paper format"), h("dd", { class: "mono" }, paper || "-", h("div", { class: "meta" }, "S|WU|P|PS as in the Akamai HTTP/2 fingerprinting paper (this is the canonical string the module scores).")),
      labeled ? [h("dt", {}, "Lab notation"), h("dd", { class: "mono" }, labeled, h("div", { class: "meta" }, "Same data with labelled brackets, for reading only. The brackets are not Akamai's format."))] : null),
    h("h5", {}, "SETTINGS"), h("table", {}, settings.length ? settings : h("tr", {}, h("td", { class: "meta" }, "none"))),
    h("dl", { class: "kv" },
      h("dt", {}, "WINDOW_UPDATE"), h("dd", { class: "mono" }, wu),
      h("dt", {}, "PRIORITY frames"), h("dd", { class: "mono" }, prio.map((x) => h("div", {}, x))),
      h("dt", {}, "Pseudo-header order"), h("dd", { class: "mono" }, pseudo || "-")));
}

function tlsSection(r) {
  const f = r.fingerprint || {};
  const basic = [["JA3", f.ja3, "Full JA3 string (GREASE removed)."], ["JA3 hash", f.ja3_hash, "md5 of the JA3 string."], ["JA4", f.ja4, "FoxIO JA4: stable under Chrome's extension shuffling."], ["Protocol", f.proto, ""]].filter((x) => x[1]);
  const rows = edgeRows(r);
  const extra = Object.entries(f).filter(([k, v]) => v && !/^(ja3|ja3_hash|ja4|h2|header_order|proto)$/.test(k));
  return h("div", {},
    basic.length ? h("table", {}, basic.map(([k, v, n]) => h("tr", {}, h("th", {}, k), h("td", {}, h("div", { class: "mono" }, v), n ? h("div", { class: "meta" }, n) : null)))) : h("p", { class: "empty" }, "No TLS fingerprint recorded."),
    h("h5", {}, "Edge TLS and HTTP/2 headers"),
    rows.length ? h("table", { class: "edge-table" }, rows) : h("p", { class: "empty" }, "None present (older edge, or the request did not come through the edge on :8443)."),
    extra.length ? h("table", {}, extra.map(([k, v]) => h("tr", {}, h("th", { class: "mono" }, k), h("td", { class: "mono" }, v)))) : null);
}

function kvTable(rows) {
  if (!rows.length) return h("p", { class: "empty" }, "Nothing recorded.");
  return h("table", {}, rows.map(([k, v]) => h("tr", {}, h("th", { class: "mono" }, k), h("td", { class: "mono" }, v))));
}
function originTab(r) {
  const o = r.origin_headers && typeof r.origin_headers === "object" ? r.origin_headers : {};
  const keys = Object.keys(o);
  const note = h("p", { class: "meta note" }, "What an origin would receive. There is no real origin in the lab: these are recorded, never forwarded.");
  if (!keys.length) return h("div", {}, note, h("p", { class: "empty" }, "No origin headers on this report."));
  return h("div", {}, note, h("table", {}, keys.map((k) => {
    let extra = null;
    if (/^akamai-user-risk$/i.test(k)) extra = h("dl", { class: "kv risk" }, String(o[k]).split(";").filter(Boolean).flatMap((kv) => { const i = kv.indexOf("="); return [h("dt", {}, kv.slice(0, i)), h("dd", { class: "mono" }, kv.slice(i + 1) || "-")]; }));
    return h("tr", {}, h("th", { class: "mono" }, k), h("td", {}, h("div", { class: "mono" }, o[k]), extra));
  })));
}
function tabBody(r) {
  switch (state.tab) {
    case "fingerprint": return h("div", {}, h("h5", {}, "TLS"), tlsSection(r), h("h5", {}, "HTTP/2"), h2Section(r));
    case "origin": return originTab(r);
    case "cookies": return kvTable(Object.entries(r.cookies || {}));
    case "json": return h("pre", { class: "tall" }, json(r));
    default: {
      const order = (r.fingerprint || {}).header_order || "";
      const names = order ? order.split(",").map((s) => s.trim()).filter(Boolean) : [];
      const hs = (r.headers || []).filter((p) => !isEdge(String(p[0]))).map((p) => [p[0], p[1]]);
      return h("div", {}, names.length ? h("p", { class: "meta" }, "Wire order: ", h("span", { class: "mono" }, names.join(" → "))) : null, kvTable(hs),
        (r.headers || []).some((p) => isEdge(String(p[0]))) ? h("p", { class: "meta" }, "Edge-injected TLS/HTTP/2 headers are on the Fingerprint tab.") : null);
    }
  }
}

// ---------- detail ----------
const TABS = [["headers", "Headers"], ["fingerprint", "Fingerprint"], ["cookies", "Cookies"], ["origin", "Origin headers"], ["json", "JSON"]];
export function renderDetail() {
  const r = state.selected, box = $("detail");
  if (!r) return;
  const action = r.action || (r.blocked ? "deny" : "allow");
  const tabs = h("div", { class: "tabs", role: "tablist" }, TABS.map(([k, t]) => h("button", { class: "tab", role: "tab", id: "tab-" + k, "aria-selected": String(state.tab === k), tabindex: state.tab === k ? "0" : "-1",
    onclick: () => { state.tab = k; renderDetail(); },
    onkeydown: (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      const i = TABS.findIndex((x) => x[0] === state.tab) + (e.key === "ArrowRight" ? 1 : -1);
      state.tab = TABS[(i + TABS.length) % TABS.length][0]; renderDetail(); $("tab-" + state.tab).focus();
    } }, t)));
  const chips = h("div", { class: "tags big" },
    actionChip(action), segChip(r.segment),
    r.endpoint_class ? tag(r.endpoint_class, "Endpoint class", "ep") : null,
    r.telemetry_type ? tag(r.telemetry_type + " telemetry", "Telemetry type picks the Bot Score band table", "ep") : null,
    r.is_human ? tag("human", "Bot Score 0: no detection fired (isHuman() analogue)", "human") : null,
    r.is_safeguard ? tag("safeguard", "A challenge was waived so a human is not trapped (isSafeguardResponse analogue)", "safe") : null,
    r.challenge_provider ? tag("provider: " + r.challenge_provider, "Challenge provider that was served", "prov") : null,
    r.blocked ? tag("blocked", "The client did not receive the real resource", "blk") : null);
  const special = [];
  if (r.reference) special.push(h("div", { class: "special deny" }, h("b", {}, "Deny reference "),
    h("a", { class: "mono", href: "/api/reference/" + encodeURIComponent(r.reference).replace(/%2F/g, "/"), target: "_blank", rel: "noopener", title: "GET /api/reference/{ref}: the report this deny page maps to" }, "Reference #" + r.reference),
    h("span", { class: "meta" }, " · what a blocked client sees on the deny page; the lab maps it back to this report.")));
  if (r.canary) special.push(h("div", { class: "special alt" }, h("b", {}, "Canary "),
    h("a", { class: "mono", href: "/api/canary/" + encodeURIComponent(r.canary), target: "_blank", rel: "noopener", title: "GET /api/canary/{token}" }, r.canary),
    h("span", { class: "meta" }, " · hidden token planted in the perturbed 200 response. If it shows up later, that client scraped degraded data.")));
  box.replaceChildren(
    h("div", { class: "gauge-wrap" }, gauge(r.score, r.blocked, action), h("div", { class: "gauge-meta" },
      h("div", { class: "mono" }, r.method + " " + r.path),
      h("div", { class: "meta" }, `${r.client_ip} · ${label(r)} · ${fmtTime(r.ts)}`),
      h("div", { class: "meta" }, r.user_agent), chips)),
    ...special,
    layersCard(r),
    signalsBlock(r),
    tabs, h("div", { role: "tabpanel", "aria-labelledby": "tab-" + state.tab, class: "tabpanel" }, tabBody(r)));
}
