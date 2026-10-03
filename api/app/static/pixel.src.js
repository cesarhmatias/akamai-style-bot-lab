/* Lab pixel script, served at /akam/<n>/<hex>. LAB-DEFINED pixel data (the real pixel POST
 * body is unverified, audit report 3.2 item 7). Concatenated after labcrypto.js.
 * Placeholders: @HEX@ (per-session hex), @N@ (path number). */
(function () {
  var W = window;
  function finish(ok) {
    W.__akPixelOk = ok;
    W.__akPixelDone = true;
    W.dispatchEvent(new CustomEvent('ak:pixel'));
  }
  function cookie(name) {
    var parts = document.cookie.split('; ');
    for (var i = 0; i < parts.length; i++) {
      var at = parts[i].indexOf('=');
      if (parts[i].slice(0, at) === name) { return parts[i].slice(at + 1).replace(/^"|"$/g, ''); }
    }
    return '';
  }
  try {
    var value = String(W.bazadebezolkohpepadr);
    var ts = Date.now();
    var digest = labCrypto.sha256Hex(value + '.@HEX@.' + ts + '.' + cookie('bm_sz'));
    fetch('/akam/@N@/pixel_@HEX@', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'p=' + encodeURIComponent(ts + '.' + digest.slice(0, 32))
    }).then(function (r) { finish(r.ok); }, function () { finish(false); });
  } catch (e) { finish(false); }
})();
