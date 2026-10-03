/* Lab-written tile-grid behavioral challenge client (NOT Akamai code).
 * Records pointer and key telemetry while the visitor clicks the highlighted tiles in the
 * order shown, posts it to the lab verifier and then reloads the original request (or tells
 * the parent page when it runs inside the AJAX-injection overlay iframe). */
(function () {
  'use strict';
  var root = document.querySelector('.sec-bc-tile-parent');
  if (!root) return;
  var token = root.getAttribute('data-token');
  var need = +root.getAttribute('data-need');
  var verify = root.getAttribute('data-verify');
  var t0 = performance.now();
  var moves = [], keys = [], clicks = [], sent = false;
  function now() { return Math.round(performance.now() - t0); }
  document.addEventListener('pointermove', function (e) {
    if (moves.length < 300) moves.push([Math.round(e.clientX), Math.round(e.clientY), now()]);
  });
  document.addEventListener('keydown', function (e) {
    // only the key CLASS and timing are kept, never the characters
    if (keys.length < 100) keys.push([e.key && e.key.length === 1 ? 'char' : e.key, now()]);
  });
  function done(ok) {
    if (window.parent !== window) {
      window.parent.postMessage({secCpt: 'interactive', ok: ok}, '*');
      return;
    }
    var tries = +(sessionStorage.getItem('sec_bc_tries') || 0);
    if (ok || tries < 3) {
      sessionStorage.setItem('sec_bc_tries', ok ? 0 : tries + 1);
      location.reload();  // re-issues the ORIGINAL request; a new tile challenge if it failed
    }
  }
  function submit() {
    if (sent) return;
    sent = true;
    fetch(verify, {
      method: 'POST', credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: token, clicks: clicks, moves: moves, keys: keys, total: now()})
    }).then(function (r) { return r.json(); })
      .then(function (j) { done(!!j.ok); })
      .catch(function () { done(false); });
  }
  root.addEventListener('click', function (e) {
    var tile = e.target.closest ? e.target.closest('[data-i]') : null;
    if (!tile || sent) return;
    tile.classList.add('sec-bc-picked');
    var r = tile.getBoundingClientRect();
    clicks.push({
      i: +tile.getAttribute('data-i'), t: now(), x: Math.round(e.clientX), y: Math.round(e.clientY),
      trusted: e.isTrusted === true, detail: e.detail,
      inside: e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom
    });
    if (clicks.length >= need) submit();
  });
})();
