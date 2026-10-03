// Bot Detection Lab dashboard. Plain ES modules, no build step, no dependencies.
import { $, h, state, api, sendJson, caseOf, MAX_ROWS, ACTION_ORDER, ACTIONS, safeCls, actionChip } from "./util.js";
import { mountCases, loadModules, renderCases } from "./cases.js";
import { loadFlags, renderFlags, onFlagsChange } from "./flags.js";
import { loadPolicy } from "./policy.js";
import { renderFeed, prependRow, select, mountFeedControls } from "./feed.js";
import { renderDetail } from "./inspector.js";
import { renderCmp } from "./compare.js";

let total = 0, blocked = 0, scoreSum = 0;
const dist = {};
const actionOf = (r) => r.action || (r.blocked ? "deny" : "allow");

// ---------- header stats ----------
function recount() {
  total = state.reports.length;
  blocked = state.reports.filter((r) => r.blocked).length;
  scoreSum = state.reports.reduce((a, r) => a + (r.score || 0), 0);
  for (const k of Object.keys(dist)) delete dist[k];
  for (const r of state.reports) dist[actionOf(r)] = (dist[actionOf(r)] || 0) + 1;
}
function renderStats() {
  $("st-total").textContent = total;
  $("st-blocked").textContent = (total ? Math.round((blocked / total) * 100) : 0) + "%";
  $("st-avg").textContent = total ? Math.round(scoreSum / total) : 0;
  const keys = [...ACTION_ORDER, ...Object.keys(dist).filter((k) => !ACTION_ORDER.includes(k))].filter((k) => dist[k]);
  const bar = $("st-dist-bar"), legend = $("st-dist-legend");
  bar.setAttribute("aria-label", total ? "Action distribution: " + keys.map((k) => `${k} ${dist[k]}`).join(", ") : "No requests yet");
  bar.replaceChildren(...keys.map((k) => h("i", { class: "a-" + safeCls(k), style: `flex:${dist[k]}`, title: `${k}: ${dist[k]} (${Math.round((dist[k] / total) * 100)}%)` })));
  legend.replaceChildren(...keys.map((k) => h("span", { class: "dl a-" + safeCls(k), title: (ACTIONS[k] || {}).desc || "" }, h("i", { "aria-hidden": "true" }), `${k} ${dist[k]}`)));
}
function setConn(on) {
  const c = $("conn");
  c.className = "conn " + (on ? "on" : "off");
  c.querySelector("b").textContent = on ? "live" : "reconnecting";
  $("banner").hidden = on;
}

// ---------- feed ingestion ----------
let noteAction = () => {};
function ingest(r, live = true) {
  if (!r || !r.id || state.reports.some((x) => x.id === r.id)) return;
  noteAction(r.action);
  state.reports.unshift(r);
  if (state.reports.length > MAX_ROWS) state.reports.length = MAX_ROWS;
  const c = caseOf(r);
  if (c && (!state.lastByCase[c] || state.lastByCase[c].ts <= r.ts)) state.lastByCase[c] = r;
  if (live) {
    recount(); renderStats(); renderCases(true); renderCmp();
    prependRow(r);
    if (!state.selected) select(r);
  }
}
async function backfill() {
  const d = await api("/api/requests?limit=100");
  const list = (Array.isArray(d) ? d : d.requests || []).slice().sort((a, b) => a.ts - b.ts);
  state.reports = []; state.lastByCase = {};
  list.forEach((r) => ingest(r, false));
  recount(); renderStats(); renderFeed(); renderCases(true); renderCmp();
  if (!state.selected && state.reports[0]) select(state.reports[0]);
}
// control-plane data is (re)loaded whenever the stream (re)connects; one failing panel must not block the others
async function refreshControlPlane() {
  await Promise.allSettled([backfill()]);
  await Promise.allSettled([loadModules(), loadFlags(), loadPolicy()]);
  renderFlags(); // module -> flag mapping needs both lists
}
let es, retry = 1000;
function connect() {
  if (es) es.close();
  es = new EventSource("/api/feed");
  es.onopen = () => { retry = 1000; setConn(true); refreshControlPlane(); };
  es.addEventListener("report", (ev) => { try { ingest(JSON.parse(ev.data)); } catch { /* ignore malformed event */ } });
  es.onerror = () => {
    setConn(false); es.close();
    setTimeout(connect, retry); retry = Math.min(retry * 1.7, 10000);
  };
}

// ---------- boot ----------
$("cmp-case").addEventListener("change", (e) => { state.cmpCase = e.target.value; renderCmp(); });
$("reset").addEventListener("click", async () => {
  if (!confirm("Clear all lab state and the feed? (Flags and policy are kept.)")) return;
  try { await sendJson("POST", "/api/reset"); } catch { setConn(false); return; }
  state.reports = []; state.lastByCase = {}; state.selected = null;
  recount(); renderStats(); renderFeed(); renderCases(true); renderCmp();
  $("detail").replaceChildren(h("p", { class: "empty" }, "Select a request from the feed."));
});
noteAction = mountFeedControls();
onFlagsChange(() => renderCases(true));
mountCases();
renderStats(); renderFeed(); renderDetail();
refreshControlPlane();
connect();
