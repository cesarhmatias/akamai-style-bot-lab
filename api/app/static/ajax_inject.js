/* Lab-written AJAX challenge injection helper (audit 2.4, Akamai "injectJavaScript" concept;
 * NOT Akamai code). Wraps same-origin fetch and XMLHttpRequest: when a call comes back
 * 428 Precondition Required with a challenge body it renders the challenge in an overlay
 * (iframe id=sec-cpt-if), solves it, and retries the original request once. */
(function () {
  'use strict';
  if (window.__secCptInjected) return;
  window.__secCptInjected = true;
  var nativeFetch = window.fetch ? window.fetch.bind(window) : null;
  var NativeXHR = window.XMLHttpRequest;
  var pending = null;

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function hex(buf) {
    var a = new Uint8Array(buf), s = '';
    for (var i = 0; i < a.length; i++) s += (a[i] < 16 ? '0' : '') + a[i].toString(16);
    return s;
  }
  async function solve(nonce, difficulty) {
    var prefix = '0'.repeat(difficulty), enc = new TextEncoder(), start = 0, B = 256;
    for (;;) {
      var jobs = [];
      for (var i = 0; i < B; i++) jobs.push(crypto.subtle.digest('SHA-256', enc.encode(nonce + (start + i))));
      var res = await Promise.all(jobs);
      for (var k = 0; k < B; k++) if (hex(res[k]).indexOf(prefix) === 0) return start + k;
      start += B;
    }
  }
  function isChallenge(status, j) { return status === 428 && j && j.provider && j.token; }

  function overlay(ch) {
    var box = document.createElement('div');
    box.id = 'sec-cpt-overlay';
    box.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(255,255,255,.92);' +
      'display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif';
    var f = document.createElement('iframe');
    f.id = 'sec-cpt-if';
    f.setAttribute('provider', ch.provider);
    f.setAttribute('challenge', btoa(JSON.stringify(ch)));
    f.setAttribute('data-duration', String(ch.chlg_duration || 0));
    f.style.cssText = 'border:0;width:min(420px,92vw);height:' + (ch.provider === 'interactive' ? '440px' : '140px');
    f.src = ch.provider === 'interactive' && ch.challenge_url
      ? ch.challenge_url : '/_sec/cp_challenge/message.htm?provider=' + ch.provider;
    box.appendChild(f);
    (document.body || document.documentElement).appendChild(box);
    return box;
  }

  function waitInteractive() {
    return new Promise(function (resolve) {
      function onMsg(e) {
        if (e.data && e.data.secCpt === 'interactive') {
          window.removeEventListener('message', onMsg);
          resolve(!!e.data.ok);
        }
      }
      window.addEventListener('message', onMsg);
    });
  }

  async function solveInline(ch) {
    var t0 = Date.now(), answers = [];
    if (ch.provider !== 'behavioral') {
      var n = ch.count || 1;
      for (var i = 0; i < n; i++) answers.push(await solve(n > 1 ? ch.nonce + '.' + i : ch.nonce, ch.difficulty));
    }
    var wait = (ch.chlg_duration || 0) * 1000 + 300 - (Date.now() - t0);
    if (wait > 0) await sleep(wait);
    if (ch.provider !== 'crypto') {
      for (var w = 0; w < 40 && window.__akSensorDone !== true; w++) await sleep(250);
    }
    var r = await nativeFetch('/_sec/verify?provider=' + ch.provider, {
      method: 'POST', credentials: 'include', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: ch.token, answers: answers})
    });
    return r.ok;
  }

  function runChallenge(ch) {
    if (pending) return pending;  // concurrent 428s share one challenge
    pending = (async function () {
      var box = overlay(ch), ok = false;
      try { ok = ch.provider === 'interactive' ? await waitInteractive() : await solveInline(ch); }
      catch (e) { ok = false; }
      box.remove();
      pending = null;
      return ok;
    })();
    return pending;
  }

  function sameOrigin(url) {
    try { return new URL(url, location.href).origin === location.origin; } catch (e) { return false; }
  }

  if (nativeFetch) {
    window.fetch = function (input, init) {
      var first, retry;
      try { first = new Request(input, init); retry = first.clone(); }
      catch (e) { return nativeFetch(input, init); }
      if (!sameOrigin(first.url)) return nativeFetch(first);
      return nativeFetch(first).then(function (resp) {
        if (resp.status !== 428) return resp;
        return resp.clone().json().then(function (j) {
          if (!isChallenge(resp.status, j)) return resp;
          return runChallenge(j).then(function (ok) { return ok ? nativeFetch(retry) : resp; });
        }, function () { return resp; });
      });
    };
  }

  if (NativeXHR) {
    var EVENTS = ['readystatechange', 'loadstart', 'progress', 'load', 'loadend', 'error', 'abort', 'timeout'];
    var LabXHR = function () {
      var self = this;
      self._listeners = {};
      self._args = null; self._headers = []; self._retried = false; self._held = false;
      self._props = {responseType: '', timeout: 0, withCredentials: false};
      self._wire(new NativeXHR());
      EVENTS.forEach(function (n) {
        Object.defineProperty(self, 'on' + n, {
          get: function () { return self._listeners['on' + n] || null; },
          set: function (fn) { self._listeners['on' + n] = fn; }, configurable: true
        });
      });
    };
    LabXHR.prototype._wire = function (x) {
      var self = this;
      self._x = x;
      EVENTS.forEach(function (n) {
        x.addEventListener(n, function (ev) { self._onInner(n, ev, x); });
      });
    };
    LabXHR.prototype._emit = function (n, ev) {
      var ls = (this._listeners[n] || []).slice();
      var h = this._listeners['on' + n];
      if (h) h.call(this, ev);
      ls.forEach(function (fn) { fn.call(this, ev); }, this);
    };
    LabXHR.prototype._onInner = function (n, ev, x) {
      if (x !== this._x || this._held) return;
      if (n === 'readystatechange' && x.readyState === 4 && x.status === 428 &&
          !this._retried && this._args && sameOrigin(this._args[1])) {
        var j = null, self = this;
        try { j = JSON.parse(x.responseText); } catch (e) { j = null; }
        if (isChallenge(428, j)) {  // hold every event until the challenge is solved
          this._held = true;
          runChallenge(j).then(function (ok) { self._release(ok, ev); });
          return;
        }
      }
      this._emit(n, ev);
    };
    LabXHR.prototype._release = function (ok, ev) {
      this._held = false;
      if (!ok) {  // challenge failed: surface the original 428 response
        this._emit('readystatechange', ev); this._emit('load', ev); this._emit('loadend', ev);
        return;
      }
      this._retried = true;
      var x = new NativeXHR();
      this._wire(x);
      x.open.apply(x, this._args);
      Object.keys(this._props).forEach(function (k) { x[k] = this._props[k]; }, this);
      this._headers.forEach(function (h) { x.setRequestHeader(h[0], h[1]); });
      x.send(this._body);
    };
    ['readyState', 'status', 'statusText', 'responseText', 'response', 'responseURL', 'responseXML', 'upload'].forEach(function (p) {
      Object.defineProperty(LabXHR.prototype, p, {get: function () { return this._x[p]; }});
    });
    ['responseType', 'timeout', 'withCredentials'].forEach(function (p) {
      Object.defineProperty(LabXHR.prototype, p, {
        get: function () { return this._x[p]; },
        set: function (v) { this._props[p] = v; this._x[p] = v; }
      });
    });
    LabXHR.prototype.open = function () {
      this._args = Array.prototype.slice.call(arguments); this._retried = false;
      return this._x.open.apply(this._x, arguments);
    };
    LabXHR.prototype.setRequestHeader = function (k, v) {
      this._headers.push([k, v]); return this._x.setRequestHeader(k, v);
    };
    LabXHR.prototype.send = function (body) { this._body = body; return this._x.send(body); };
    ['abort', 'getAllResponseHeaders', 'getResponseHeader', 'overrideMimeType'].forEach(function (m) {
      LabXHR.prototype[m] = function () { return this._x[m].apply(this._x, arguments); };
    });
    LabXHR.prototype.addEventListener = function (n, fn) {
      (this._listeners[n] = this._listeners[n] || []).push(fn);
    };
    LabXHR.prototype.removeEventListener = function (n, fn) {
      this._listeners[n] = (this._listeners[n] || []).filter(function (f) { return f !== fn; });
    };
    LabXHR.prototype.dispatchEvent = function (ev) { this._emit(ev.type, ev); return true; };
    LabXHR.UNSENT = 0; LabXHR.OPENED = 1; LabXHR.HEADERS_RECEIVED = 2; LabXHR.LOADING = 3; LabXHR.DONE = 4;
    window.XMLHttpRequest = LabXHR;
  }
})();
