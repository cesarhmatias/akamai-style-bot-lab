# ruff: noqa: E501
"""Run lab page scripts in node against a minimal browser stub (test helper, no network).

``run_js(scripts, driver)`` evaluates the scripts (sensor, pixel, inline telemetry, ...) in a
``vm`` context whose ``window`` imitates a stock Chrome closely enough for the lab's probes
(native-looking Navigator getters, ``window.chrome``), then evaluates ``driver`` (JS that may
use ``ev(type, props)``, ``drain()``, ``calls`` and must assign ``result``). Skips the test when
no node binary exists (PATH, else the one bundled with Playwright).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const cfg = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const t0 = Number(process.hrtime.bigint()) / 1e6;
const timers = [];
const listeners = {};
const calls = [];
const sandbox = {
  console: { debug() {}, log() {} },
  setTimeout: (fn, ms) => { timers.push([fn, ms]); return timers.length; },
  setInterval: () => 0,
  now: () => Number(process.hrtime.bigint()) / 1e6 - t0,
  nodeBtoa: (s) => Buffer.from(s, 'latin1').toString('base64'),
  nodeAtob: (s) => Buffer.from(s, 'base64').toString('latin1'),
  URL, mode: cfg.mode, cookie: cfg.cookie, listeners, calls, timers, result: null,
  crypto: { getRandomValues: (a) => { for (let i = 0; i < a.length; i++) a[i] = (i * 37 + 11) & 255; return a; } },
};
vm.createContext(sandbox);
const boot = `
var Navigator = function Navigator() {};
function nativeGetter(key, val) {
  var f = (function () { return val; }).bind(null);
  Object.defineProperty(f, 'name', { value: 'get ' + key });
  Object.defineProperty(Navigator.prototype, key, { get: f, configurable: true, enumerable: true });
}
var UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
nativeGetter('webdriver', false);
nativeGetter('userAgent', UA);
nativeGetter('platform', 'Linux x86_64');
nativeGetter('languages', ['en-US']);
nativeGetter('hardwareConcurrency', 8);
nativeGetter('plugins', { length: 5 });
var navigator = Object.create(Navigator.prototype);
navigator.language = 'en-US';
navigator.userAgentData = { mobile: false, brands: [{ brand: 'Google Chrome', version: '131' }, { brand: 'Chromium', version: '131' }, { brand: 'Not_A Brand', version: '24' }] };
if (mode === 'playwright') {
  Object.defineProperty(Navigator.prototype, 'webdriver', { get: function () { return false; } });
}
function Headers(init) {
  this.m = {};
  if (init instanceof Headers) { Object.assign(this.m, init.m); }
  else if (init) { for (var k in init) { this.m[k.toLowerCase()] = init[k]; } }
}
Headers.prototype.set = function (k, v) { this.m[k.toLowerCase()] = v; };
Headers.prototype.get = function (k) { return this.m[k.toLowerCase()]; };
function XMLHttpRequest() { this.headers = {}; }
XMLHttpRequest.prototype.open = function () {};
XMLHttpRequest.prototype.setRequestHeader = function (k, v) { this.headers[k.toLowerCase()] = v; };
XMLHttpRequest.prototype.send = function (body) { calls.push({ xhr: this, body: body }); };
var window = {
  Function: Function, Object: Object, Navigator: Navigator, navigator: navigator, JSON: JSON,
  Intl: Intl, Math: Math, console: console, Headers: Headers, XMLHttpRequest: XMLHttpRequest,
  crypto: crypto, location: { href: 'https://localhost:8443/' },
  performance: { now: now, timing: { navigationStart: 1, domContentLoadedEventEnd: 5, loadEventEnd: 9, responseEnd: 4, requestStart: 2 },
    getEntriesByType: function () { return []; } },
  screen: { width: 1920, height: 1080, availWidth: 1920, colorDepth: 24 },
  devicePixelRatio: 1,
  document: {
    cookie: cookie, hasFocus: function () { return true; }, visibilityState: 'visible',
    createElement: function () { return { getContext: function () { return { fillRect() {}, fillText() {}, arc() {}, stroke() {} }; }, toDataURL: function () { return 'data:image/png;base64,AAAA'; } }; },
    querySelectorAll: function () { return window.__inputs || []; } },
  addEventListener: function (t, fn) { (listeners[t] = listeners[t] || []).push(fn); },
  setTimeout: setTimeout, setInterval: setInterval, unescape: unescape,
  encodeURIComponent: encodeURIComponent, btoa: nodeBtoa, atob: nodeAtob,
  CustomEvent: function (n, o) { this.type = n; this.detail = o && o.detail; },
  dispatchEvent: function (e) { window.__events = (window.__events || []).concat(e.type); },
  fetch: function (input, init) {
    calls.push({ fetch: true, input: input, init: init });
    return { then: function (ok) {
      ok({ ok: true, json: function () { return { then: function (f) { f({ success: true, more: window.__more || 0 }); } }; } });
    } };
  },
};
if (mode !== 'no-chrome') { window.chrome = { app: {}, csi: function () {}, loadTimes: function () {} }; }
window.window = window;
var atob = nodeAtob;
var btoa = nodeBtoa;
var document = window.document;
var CustomEvent = window.CustomEvent;
var fetch = function () { return window.fetch.apply(window, arguments); };
var Date_now = Date.now;
function ev(type, props) {
  (listeners[type] || []).forEach(function (fn) {
    fn(Object.assign({ timeStamp: now(), target: null }, props));
  });
}
function drain() {
  var guard = 0;
  while (timers.length && guard++ < 500) { var t = timers.shift(); t[0](); }
}
`;
vm.runInContext(boot, sandbox);
for (const p of cfg.scripts) vm.runInContext(fs.readFileSync(p, 'utf8'), sandbox, { filename: p });
vm.runInContext(cfg.driver, sandbox);
process.stdout.write(JSON.stringify(sandbox.result));
"""


def find_node() -> str | None:
    node = shutil.which("node")
    if node:
        return node
    try:
        import playwright

        cand = Path(playwright.__file__).parent / "driver" / "node"
        return str(cand) if cand.exists() else None
    except ImportError:
        return None


def run_js(
    tmp_path: Path,
    scripts: list[str],
    driver: str,
    *,
    mode: str = "native",
    cookie: str = "",
) -> Any:
    node = find_node()
    if not node:
        pytest.skip("node not available")
    files = []
    for i, text in enumerate(scripts):
        f = tmp_path / f"script{i}.js"
        f.write_text(text, encoding="utf-8")
        files.append(str(f))
    (tmp_path / "harness.js").write_text(HARNESS, encoding="utf-8")
    (tmp_path / "cfg.json").write_text(
        json.dumps({"scripts": files, "driver": driver, "mode": mode, "cookie": cookie})
    )
    res = subprocess.run(
        [node, str(tmp_path / "harness.js"), str(tmp_path / "cfg.json")],
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


MOUSE_DRIVER = """
var x = 100, y = 200;
for (var i = 0; i < 20; i++) { x += 7 + (i % 3); y += 3 + (i % 5); ev('mousemove', {clientX: x, clientY: y}); }
drain();
result = {
  posts: calls.filter(function (c) { return c.fetch; }).map(function (c) { return {url: c.input, body: c.init.body}; }),
  events: window.__events || [], done: window.__akSensorDone, flush: typeof window.__akSensorFlush
};
"""
