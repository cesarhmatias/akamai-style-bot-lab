/* Readable source of the lab sensor. Served obfuscated by app/modules/sensor_data.py.
 * Authoring rules (the Python obfuscator relies on them):
 *  - only single-quoted string literals, no escapes, no quotes or double slashes inside
 *  - property access via brackets with string literals: obj['name']
 *  - local identifiers start with a dollar sign and are renamed to hex names
 *  - no quoted keys inside object literals (use assignments)
 *  - '@KEY@' is replaced by the per-session XOR key
 */
(function () {
  var $K = '@KEY@';
  var $W = window;
  var $N = $W['navigator'];
  var $P = $W['performance'];
  var $mouse = [];
  var $cnt = {};
  var $sent = false;
  var $MAXN = 300;
  var $WINDOW = 2000;
  var $IDLE = 4000;
  var $started = $P['now']();
  $cnt['key'] = 0;
  $cnt['scroll'] = 0;
  $cnt['touch'] = 0;
  $cnt['click'] = 0;
  $cnt['mouse'] = 0;

  function $r(v, d) {
    var m = Math['pow'](10, d);
    return Math['round'](v * m) / m;
  }
  function $on(type, fn) {
    $W['addEventListener'](type, fn, true);
  }
  function $count(type, name) {
    $on(type, function () { $cnt[name]++; });
  }
  function $safe(fn, dflt) {
    try { return fn(); } catch (e) { return dflt; }
  }

  $count('keydown', 'key');
  $count('scroll', 'scroll');
  $count('wheel', 'scroll');
  $count('touchstart', 'touch');
  $count('touchmove', 'touch');
  $count('click', 'click');
  $on('mousemove', function (e) {
    $cnt['mouse']++;
    if ($mouse['length'] === 0) {
      $W['setTimeout']($send, $WINDOW);
    }
    if ($mouse['length'] < $MAXN) {
      $mouse['push']([e['clientX'], e['clientY'], $r(e['timeStamp'], 2)]);
      if ($mouse['length'] >= $MAXN) { $send(); }
    }
  });
  $W['setTimeout'](function () {
    if ($mouse['length'] === 0) { $send(); }
  }, $IDLE);

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
    g['fillText']('akamai-lab éü 123', 4, 15);
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
  function $build(ticks) {
    var s = $W['screen'];
    var p = {};
    p['v'] = 1;
    p['t0'] = $r($started, 2);
    p['t1'] = $r($P['now'](), 2);
    p['mouse'] = $mouse;
    p['counts'] = $cnt;
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
    nv['webdriver'] = $N['webdriver'] === true;
    nv['plugins'] = $N['plugins'] ? $N['plugins']['length'] : -1;
    nv['brands'] = $safe(function () {
      return $N['userAgentData']['brands']['map'](function (b) {
        return b['brand'] + '/' + b['version'];
      });
    }, []);
    p['navigator'] = nv;
    p['tz'] = $safe(function () {
      return $W['Intl']['DateTimeFormat']()['resolvedOptions']()['timeZone'];
    }, '');
    p['tzo'] = new Date()['getTimezoneOffset']();
    p['canvas'] = $safe($canvas, '');
    return p;
  }
  function $encode(obj) {
    var raw = $W['unescape']($W['encodeURIComponent']($W['JSON']['stringify'](obj)));
    var out = '';
    for (var i = 0; i < raw['length']; i++) {
      out += String['fromCharCode'](raw['charCodeAt'](i) ^ $K['charCodeAt'](i % $K['length']));
    }
    return $W['btoa'](out);
  }
  function $finish(ok) {
    $W['__akSensorDone'] = true;
    $W['__akSensorOk'] = ok;
    var detail = {};
    detail['success'] = ok;
    $W['dispatchEvent'](new $W['CustomEvent']('ak:sensor', { detail: detail }));
  }
  function $post(payload) {
    var body = {};
    body['sensor_data'] = $encode(payload);
    var hdr = {};
    hdr['Content-Type'] = 'application/json';
    $W['fetch']('/akam/sensor_data/sensor', {
      method: 'POST',
      headers: hdr,
      body: $W['JSON']['stringify'](body),
      credentials: 'same-origin'
    }).then(function (r) { $finish(r['ok']); }, function () { $finish(false); });
  }
  function $send() {
    if ($sent) { return; }
    $sent = true;
    var ticks = [];
    var n = 0;
    (function $step() {
      ticks['push']($P['now']());
      if (++n < 12) { $W['setTimeout']($step, 0); } else { $post($build(ticks)); }
    })();
  }
  $W['__akSensorFlush'] = $send;
})();
