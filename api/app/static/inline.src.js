/* Lab inline-telemetry client (audit report 2.5). LAB-DEFINED header format; the header name
 * 'akamai-bm-telemetry' and the '&&&'-separated segments are vendor-observed only.
 * Concatenated after labcrypto.js. Configuration comes from the page markup:
 *   window.__akInline = {k: <per-session mac key>, v: 'lab1', p: [<paths>], s: <server ms>}
 * Wraps fetch and XMLHttpRequest for the listed paths and attaches, per request:
 *   a=<ver>&&&t=<ts ms>&&&n=<nonce>&&&h=<request hash>&&&e=<mac>&&&sensor_data=<payload>
 * where h = sha256(METHOD + ' ' + path + LF + sha256(body)),
 *       e = hmac_sha256(k, ver LF t LF n LF h LF payload),
 *       payload = base64url(json: keystroke/mouse/touch/scroll telemetry captured so far).
 * Only string bodies are supported. Key identities are never recorded, only timings. */
(function () {
  var W = window;
  var cfg = W.__akInline;
  if (!cfg || W.__akInlineInstalled) { return; }
  W.__akInlineInstalled = true;
  var P = W.performance;
  var HEADER = 'akamai-bm-telemetry';
  var offset = cfg.s ? cfg.s - Date.now() : 0;
  var buf = {mouse: [], keys: [], touch: [], scroll: []};
  var cnt = {mouse: 0, key: 0, touch: 0, scroll: 0, click: 0, paste: 0, input: 0};
  var down = {};
  var first = 0;

  function keep(list, item, max) {
    list.push(item);
    if (list.length > max) { list.shift(); }
  }
  function r1(v) { return Math.round(v * 10) / 10; }
  function seen() { if (!first) { first = P.now(); } }
  function on(type, fn) { W.addEventListener(type, fn, true); }

  on('mousemove', function (e) {
    cnt.mouse++;
    seen();
    keep(buf.mouse, [Math.round(e.clientX), Math.round(e.clientY), r1(e.timeStamp)], 80);
  });
  on('keydown', function (e) {
    cnt.key++;
    seen();
    if (!e.repeat) { down[e.code] = e.timeStamp; }
  });
  on('keyup', function (e) {
    var t0 = down[e.code];
    if (t0 === undefined) { return; }
    down[e.code] = undefined;
    keep(buf.keys, [r1(t0), r1(e.timeStamp - t0)], 60);
  });
  function touchEv(kind) {
    return function (e) {
      cnt.touch++;
      seen();
      var l = e.changedTouches || e.touches;
      if (l && l.length) {
        keep(buf.touch, [kind, Math.round(l[0].clientX), Math.round(l[0].clientY),
          r1(e.timeStamp)], 40);
      }
    };
  }
  on('touchstart', touchEv(0));
  on('touchmove', touchEv(1));
  on('touchend', touchEv(2));
  function scrolled(e) { cnt.scroll++; seen(); keep(buf.scroll, r1(e.timeStamp), 20); }
  on('scroll', scrolled);
  on('wheel', scrolled);
  on('click', function () { cnt.click++; seen(); });
  on('paste', function () { cnt.paste++; seen(); });
  on('input', function () { cnt.input++; });

  function chars() {
    var n = 0;
    var els = document.querySelectorAll('input,textarea');
    for (var i = 0; i < els.length; i++) {
      var t = (els[i].type || '').toLowerCase();
      if (t === 'hidden' || t === 'checkbox' || t === 'radio' || t === 'submit' ||
          t === 'button') { continue; }
      n += (els[i].value || '').length;
    }
    return n;
  }
  function b64url(s) {
    return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_')
      .replace(/=+$/, '');
  }
  function nonce() {
    var a = new Uint8Array(8);
    if (W.crypto && W.crypto.getRandomValues) {
      W.crypto.getRandomValues(a);
    } else {
      for (var i = 0; i < 8; i++) { a[i] = Math.floor(Math.random() * 256); }
    }
    var s = '';
    for (var j = 0; j < 8; j++) { s += (a[j] + 256).toString(16).slice(1); }
    return s;
  }
  function payload() {
    var p = {v: 1, t0: first ? r1(first) : 0, t1: r1(P.now())};
    p.mouse = buf.mouse;
    p.keys = buf.keys;
    p.touch = buf.touch;
    p.scroll = buf.scroll;
    p.counts = cnt;
    p.fill = {chars: chars(), inputs: cnt.input};
    p.focus = {has: document.hasFocus()};
    return p;
  }
  function header(method, path, body) {
    var h = labCrypto.sha256Hex(method + ' ' + path + '\n' + labCrypto.sha256Hex(body));
    var ts = String(Date.now() + offset);
    var n = nonce();
    var sd = b64url(JSON.stringify(payload()));
    var e = labCrypto.hmacHex(cfg.k, [cfg.v, ts, n, h, sd].join('\n'));
    return 'a=' + cfg.v + '&&&t=' + ts + '&&&n=' + n + '&&&h=' + h + '&&&e=' + e +
      '&&&sensor_data=' + sd;
  }
  function pathOf(url) {
    try { return new URL(String(url), W.location.href).pathname; } catch (e) { return ''; }
  }
  function isTarget(path) { return cfg.p.indexOf(path) >= 0; }

  var nativeFetch = W.fetch;
  if (nativeFetch) {
    W.fetch = function (input, init) {
      try {
        var url = typeof input === 'string' || !input || !input.url ? input : input.url;
        var method = String((init && init.method) || (input && input.method) || 'GET')
          .toUpperCase();
        var path = pathOf(url);
        if (method !== 'GET' && isTarget(path)) {
          var opts = init ? Object.assign({}, init) : {};
          var hdrs = new Headers(opts.headers || (input && input.headers) || undefined);
          var body = typeof opts.body === 'string' ? opts.body : String(opts.body || '');
          hdrs.set(HEADER, header(method, path, body));
          opts.headers = hdrs;
          init = opts;
        }
      } catch (e) { /* never break the page */ }
      return nativeFetch.call(this, input, init);
    };
  }
  var X = W.XMLHttpRequest;
  if (X && X.prototype) {
    var nativeOpen = X.prototype.open;
    var nativeSend = X.prototype.send;
    X.prototype.open = function (method, url) {
      this.__akm = String(method || 'GET').toUpperCase();
      this.__akp = pathOf(url);
      return nativeOpen.apply(this, arguments);
    };
    X.prototype.send = function (body) {
      try {
        if (this.__akm !== 'GET' && isTarget(this.__akp)) {
          this.setRequestHeader(HEADER, header(this.__akm, this.__akp,
            typeof body === 'string' ? body : String(body || '')));
        }
      } catch (e) { /* never break the page */ }
      return nativeSend.apply(this, arguments);
    };
  }
})();
