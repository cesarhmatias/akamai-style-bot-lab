/* Readable source of the lab sensor. Served obfuscated by app/modules/sensor_data.py.
 * LAB-DEFINED encoding and probes: this is not Akamai code and does not reproduce any real
 * Akamai payload format; it only imitates the SHAPE described in the audit report.
 * Authoring rules (the Python obfuscator relies on them):
 *  - only single-quoted string literals, no escapes, no quotes or double slashes inside
 *  - property access via brackets with string literals: obj['name']
 *  - local identifiers start with a dollar sign and are renamed to hex names
 *  - no quoted keys inside object literals (use assignments)
 *  - no dollar sign directly followed by a letter inside regex literals (none are used)
 *  - placeholders replaced per session at serve time: @KEY@ (xor key), @HASH@ (payload
 *    prefix hash), @PATH@ (same-origin POST path), @CDP@ (1 when the cdp_probes flag is on)
 */
(function () {
  var $K = '@KEY@';
  var $H = '@HASH@';
  var $PATH = '@PATH@';
  var $CDP = '@CDP@' === '1';
  var $W = window;
  var $N = $W['navigator'];
  var $P = $W['performance'];
  var $FTS = $W['Function']['prototype']['toString'];
  var $mouse = [];
  var $keys = [];
  var $touch = [];
  var $scroll = [];
  var $down = {};
  var $cnt = {};
  var $mot = {};
  var $foc = {};
  var $posts = 0;
  var $busy = false;
  var $finished = false;
  var $armed = false;
  var $lastEv = 0;
  var $lastPostTotal = 0;
  var $MAXN = 300;
  var $MAXK = 200;
  var $MAXT = 200;
  var $MAXS = 100;
  var $MAXPOSTS = 3;
  var $WINDOW = 2000;
  var $IDLE = 4000;
  var $started = $P['now']();
  $cnt['key'] = 0;
  $cnt['scroll'] = 0;
  $cnt['touch'] = 0;
  $cnt['click'] = 0;
  $cnt['mouse'] = 0;
  $cnt['paste'] = 0;
  $mot['n'] = 0;
  $mot['o'] = 0;
  $mot['min'] = 0;
  $mot['max'] = 0;
  $foc['blur'] = 0;
  $foc['focus'] = 0;
  $foc['vis'] = 0;

  function $r(v, d) {
    var m = Math['pow'](10, d);
    return Math['round'](v * m) / m;
  }
  function $on(type, fn) {
    $W['addEventListener'](type, fn, true);
  }
  function $safe(fn, dflt) {
    try { return fn(); } catch (e) { return dflt; }
  }
  function $total() {
    return $cnt['key'] + $cnt['scroll'] + $cnt['touch'] + $cnt['click'] + $cnt['mouse'];
  }
  function $touched() {
    $lastEv = $P['now']();
  }
  function $arm() {
    if ($armed || $posts > 0) { return; }
    $armed = true;
    $W['setTimeout']($send, $WINDOW);
  }
  function $count(type, name) {
    $on(type, function () { $cnt[name]++; $touched(); });
  }

  // ---- interaction capture (timings only: key identities are never recorded) ----
  $count('scroll', 'scroll');
  $count('wheel', 'scroll');
  $count('click', 'click');
  $count('paste', 'paste');
  $on('scroll', function (e) {
    if ($scroll['length'] < $MAXS) { $scroll['push']($r(e['timeStamp'], 1)); }
  });
  $on('wheel', function (e) {
    if ($scroll['length'] < $MAXS) { $scroll['push']($r(e['timeStamp'], 1)); }
  });
  $on('keydown', function (e) {
    $cnt['key']++;
    $touched();
    if (!e['repeat']) { $down[e['code']] = e['timeStamp']; }
    $arm();
  });
  $on('keyup', function (e) {
    var t0 = $down[e['code']];
    if (t0 === undefined || $keys['length'] >= $MAXK) { return; }
    $down[e['code']] = undefined;
    $keys['push']([$r(t0, 1), $r(e['timeStamp'] - t0, 1)]);
  });
  function $touchEv(kind) {
    return function (e) {
      $cnt['touch']++;
      $touched();
      var list = e['changedTouches'] || e['touches'];
      var t = list && list['length'] ? list[0] : null;
      if (t && $touch['length'] < $MAXT) {
        $touch['push']([kind, t['clientX'], t['clientY'], $r(e['timeStamp'], 1)]);
      }
      $arm();
    };
  }
  $on('touchstart', $touchEv(0));
  $on('touchmove', $touchEv(1));
  $on('touchend', $touchEv(2));
  $on('mousemove', function (e) {
    $cnt['mouse']++;
    $touched();
    $arm();
    if ($mouse['length'] < $MAXN) {
      $mouse['push']([e['clientX'], e['clientY'], $r(e['timeStamp'], 2)]);
      if ($mouse['length'] >= $MAXN) { $send(); }
    }
  });
  $on('devicemotion', function (e) {
    $mot['n']++;
    var a = e['accelerationIncludingGravity'];
    if (a && a['x'] !== null) {
      var m = Math['sqrt'](a['x'] * a['x'] + a['y'] * a['y'] + a['z'] * a['z']);
      if ($mot['n'] === 1 || m < $mot['min']) { $mot['min'] = $r(m, 3); }
      if ($mot['n'] === 1 || m > $mot['max']) { $mot['max'] = $r(m, 3); }
    }
  });
  $on('deviceorientation', function () { $mot['o']++; });
  $on('blur', function (e) { if (e['target'] === $W) { $foc['blur']++; } });
  $on('focus', function (e) { if (e['target'] === $W) { $foc['focus']++; } });
  $on('visibilitychange', function () { $foc['vis']++; });
  $W['setTimeout'](function () {
    if ($total() === 0) { $send(); }
  }, $IDLE);

  // ---- fingerprint helpers ----
  function $hash(s) {
    var h = 2166136261;
    for (var i = 0; i < s['length']; i++) {
      h ^= s['charCodeAt'](i);
      h = Math['imul'](h, 16777619) >>> 0;
    }
    return h['toString'](16);
  }
  function $canvas() {
    var c = $W['document']['createElement']('canvas');
    c['width'] = 200;
    c['height'] = 50;
    var g = c['getContext']('2d');
    g['textBaseline'] = 'top';
    g['font'] = '14px Arial';
    g['fillStyle'] = '#f60';
    g['fillRect'](10, 5, 80, 30);
    g['fillStyle'] = '#069';
    g['fillText']('akamai-lab 123', 4, 15);
    g['strokeStyle'] = 'rgba(102,204,0,0.7)';
    g['arc'](120, 25, 18, 0, Math['PI'] * 1.7);
    g['stroke']();
    return $hash(c['toDataURL']());
  }
  function $navTiming() {
    var o = {};
    var t = $P['timing'];
    if (t) {
      o['ns'] = t['navigationStart'];
      o['dcl'] = t['domContentLoadedEventEnd'] - t['navigationStart'];
      o['load'] = t['loadEventEnd'] - t['navigationStart'];
      o['resp'] = t['responseEnd'] - t['requestStart'];
    }
    var e = $safe(function () { return $P['getEntriesByType']('navigation')[0]; }, null);
    if (e) {
      o['di'] = $r(e['domInteractive'], 2);
      o['dur'] = $r(e['duration'], 2);
      o['type'] = e['type'];
    }
    return o;
  }

  // ---- JS integrity probes (audit report 2.3; HIGH concept, lab-defined details) ----
  function $isNative(fn) {
    return $safe(function () {
      return typeof fn === 'function' && $FTS['call'](fn)['indexOf']('[native code]') >= 0;
    }, false);
  }
  function $getterInfo(key) {
    var o = {};
    var proto = $W['Navigator'] ? $W['Navigator']['prototype'] : null;
    var own = $safe(function () {
      return Object['getOwnPropertyDescriptor']($N, key);
    }, null);
    var onProto = proto ? $safe(function () {
      return Object['getOwnPropertyDescriptor'](proto, key);
    }, null) : null;
    var d = own || onProto;
    o['where'] = own ? 'own' : (onProto ? 'proto' : 'none');
    o['accessor'] = !!(d && d['get']);
    o['native'] = !!(d && d['get']) && $isNative(d['get']);
    o['name_ok'] = !!(d && d['get']) && d['get']['name'] === 'get ' + key;
    return o;
  }
  function $globals() {
    var pre = ['__playwright', '__pw', '__puppeteer', 'puppeteer', 'cdc_', '__selenium',
      '_selenium', '__webdriver', '__driver', '__nightmare', '__fxdriver', 'domAutomation'];
    var exact = ['_phantom', 'callPhantom', 'phantom', 'domAutomationController'];
    var names = $safe(function () { return Object['getOwnPropertyNames']($W); }, []);
    var dn = $safe(function () {
      return Object['getOwnPropertyNames']($W['document']);
    }, []);
    names = names['concat'](dn);
    var found = [];
    for (var i = 0; i < names['length'] && found['length'] < 10; i++) {
      var nm = names[i];
      var hit = exact['indexOf'](nm) >= 0;
      for (var j = 0; j < pre['length'] && !hit; j++) {
        var at = nm['indexOf'](pre[j]);
        hit = at === 0 || (at === 1 && nm['charAt'](0) === String['fromCharCode'](36));
      }
      if (hit) { found['push'](nm); }
    }
    return found;
  }
  function $chrome() {
    var o = {};
    var c = $W['chrome'];
    o['present'] = typeof c === 'object' && c !== null;
    var keys = [];
    var want = ['app', 'csi', 'loadTimes', 'runtime'];
    for (var i = 0; i < want['length']; i++) {
      var k = want[i];
      if (o['present'] && $safe(function () { return k in c; }, false)) { keys['push'](k); }
    }
    o['keys'] = keys;
    return o;
  }
  function $cdp() {
    var hit = false;
    var err = new Error('x');
    Object['defineProperty'](err, 'stack', { get: function () { hit = true; return ''; } });
    $safe(function () { $W['console']['debug'](err); }, 0);
    return hit;
  }
  function $integrity() {
    var o = {};
    var nav = {};
    var keys = ['webdriver', 'userAgent', 'platform', 'languages', 'hardwareConcurrency',
      'plugins'];
    for (var i = 0; i < keys['length']; i++) { nav[keys[i]] = $getterInfo(keys[i]); }
    o['nav'] = nav;
    o['fts_native'] = $isNative($FTS);
    o['globals'] = $safe($globals, []);
    o['chrome'] = $safe($chrome, {});
    if ($CDP) { o['cdp'] = $safe($cdp, false); }
    return o;
  }

  function $build(ticks) {
    var s = $W['screen'];
    var p = {};
    p['v'] = 2;
    p['t0'] = $r($started, 2);
    p['t1'] = $r($P['now'](), 2);
    p['mouse'] = $mouse;
    p['keys'] = $keys;
    p['touch'] = $touch;
    p['scroll'] = $scroll;
    p['counts'] = $cnt;
    var motion = {};
    motion['dm'] = $W['DeviceMotionEvent'] !== undefined;
    motion['do'] = $W['DeviceOrientationEvent'] !== undefined;
    motion['perm'] = $safe(function () {
      return typeof $W['DeviceMotionEvent']['requestPermission'] === 'function';
    }, false);
    motion['n'] = $mot['n'];
    motion['o'] = $mot['o'];
    motion['spread'] = $r($mot['max'] - $mot['min'], 3);
    p['motion'] = motion;
    var fc = {};
    fc['blur'] = $foc['blur'];
    fc['focus'] = $foc['focus'];
    fc['vis'] = $foc['vis'];
    fc['has'] = $safe(function () { return $W['document']['hasFocus'](); }, null);
    fc['state'] = $safe(function () { return $W['document']['visibilityState']; }, '');
    p['focus'] = fc;
    var deltas = [];
    for (var i = 1; i < ticks['length']; i++) { deltas['push']($r(ticks[i] - ticks[i - 1], 3)); }
    var tm = {};
    tm['deltas'] = deltas;
    tm['nav'] = $navTiming();
    p['timing'] = tm;
    var sc = {};
    sc['width'] = s['width'];
    sc['height'] = s['height'];
    sc['availWidth'] = s['availWidth'];
    sc['colorDepth'] = s['colorDepth'];
    sc['pixelRatio'] = $W['devicePixelRatio'];
    p['screen'] = sc;
    var nv = {};
    nv['userAgent'] = $N['userAgent'];
    nv['platform'] = $N['platform'];
    nv['language'] = $N['language'];
    nv['languages'] = $safe(function () { return $N['languages']['slice'](); }, []);
    nv['hardwareConcurrency'] = $N['hardwareConcurrency'];
    nv['deviceMemory'] = $N['deviceMemory'];
    nv['maxTouchPoints'] = $N['maxTouchPoints'];
    nv['webdriver'] = $N['webdriver'] === true;
    nv['plugins'] = $N['plugins'] ? $N['plugins']['length'] : -1;
    nv['brands'] = $safe(function () {
      return $N['userAgentData']['brands']['map'](function (b) {
        return b['brand'] + '/' + b['version'];
      });
    }, []);
    nv['mobile'] = $safe(function () { return $N['userAgentData']['mobile'] === true; }, null);
    p['navigator'] = nv;
    p['integrity'] = $safe($integrity, {});
    p['tz'] = $safe(function () {
      return $W['Intl']['DateTimeFormat']()['resolvedOptions']()['timeZone'];
    }, '');
    p['tzo'] = new Date()['getTimezoneOffset']();
    p['canvas'] = $safe($canvas, '');
    return p;
  }

  // ---- lab-defined payload: 'lab3;0;1;<post index>;<hash8>;<base64(xor(json, key))>' ----
  function $encode(obj, idx) {
    var raw = $W['unescape']($W['encodeURIComponent']($W['JSON']['stringify'](obj)));
    var out = '';
    for (var i = 0; i < raw['length']; i++) {
      out += String['fromCharCode'](raw['charCodeAt'](i) ^ $K['charCodeAt'](i % $K['length']));
    }
    return 'lab3;0;1;' + idx + ';' + $H + ';' + $W['btoa'](out);
  }
  function $finish(ok) {
    if ($finished) { return; }
    $finished = true;
    $W['__akSensorDone'] = true;
    $W['__akSensorOk'] = ok;
    var detail = {};
    detail['success'] = ok;
    $W['dispatchEvent'](new $W['CustomEvent']('ak:sensor', { detail: detail }));
  }
  function $after(ok, j) {
    $busy = false;
    if (ok) {
      $posts++;
      if (j && j['more'] > 0 && $posts < $MAXPOSTS) {
        $W['setTimeout']($post, 1200);
        return;
      }
    }
    $finish(ok);
  }
  function $post() {
    if ($busy || $posts >= $MAXPOSTS) { return; }
    $busy = true;
    $lastPostTotal = $total();
    var ticks = [];
    var n = 0;
    (function $step() {
      ticks['push']($P['now']());
      if (++n < 12) { $W['setTimeout']($step, 0); } else { $submit($build(ticks)); }
    })();
  }
  function $submit(payload) {
    var body = {};
    body['sensor_data'] = $encode(payload, $posts);
    var hdr = {};
    hdr['Content-Type'] = 'application/json';
    $W['fetch']($PATH, {
      method: 'POST',
      headers: hdr,
      body: $W['JSON']['stringify'](body),
      credentials: 'same-origin'
    })['then'](function (r) {
      return r['json']()['then'](function (j) {
        $after(r['ok'] && j['success'] === true, j);
      }, function () { $after(false, null); });
    }, function () { $after(false, null); });
  }
  function $send() {
    if ($posts > 0 || $busy) { return; }
    $post();
  }
  // later posts (up to three per session) carry the interaction that followed the first one
  $W['setInterval'](function () {
    if (!$finished || $busy || $posts === 0 || $posts >= $MAXPOSTS) { return; }
    if ($total() - $lastPostTotal >= 6 && $P['now']() - $lastEv >= 1500) { $post(); }
  }, 1000);
  $W['__akSensorFlush'] = $send;
})();
