# `js_integrity`: JavaScript integrity and automation-artifact probes

Category: js · Module: `api/app/modules/js_integrity.py` · Protected URL: `/protected/js_integrity`
· Default: on · Module tier: **HIGH** (the `cdp_probes` extra is LOW, flag-gated, off)

## What it is

The sensor reads properties that automation frameworks change and sends the results inside the payload: whether
`navigator.webdriver` is a native getter, whether the UA or client hints say `HeadlessChrome`, automation-injected
globals, and the shape of `window.chrome`.

## How real Akamai uses it

Integrity probes inside the sensor are described by community analyses ([V]/[S]); a 2026 measurement of 7,944 sites found
`navigator.webdriver` read on 34% of them, `HeadlessChrome` brands in client hints as a strong headless tell, and
automation honeypot properties checked on 46% ([S], Gundelach et al., 2026-06-12; report §2.3). The results travel inside
the payload, so nothing is visible to the client except the properties the script reads. Akamai-specific CDP and
headless probes are vendor claims only (report §3.1 LOW).

## Confidence

| Sub-feature | Tier | Flag (default) |
|---|---|---|
| Native-getter checks on Navigator, `webdriver` descriptor, `HeadlessChrome`, framework globals, `window.chrome` shape | HIGH (concept) | none |
| Error.stack getter trap for CDP / DevTools serialisation | LOW: unverified, vendor-sourced | `cdp_probes` (off) |

Probe weights are lab-defined; each probe records its own confidence in `details["probes"]`.

## How the lab simulates it

`static/sensor.src.js` records the probes under `integrity` (plus `navigator.brands` and `navigator.webdriver`);
`sensor_data` stores them and this module scores them from `sensor:{sid}` (or `sensor:integrity:{sid}` when the sensor was
rejected, so the reason is still explainable). Probe weights:

| Probe | Weight |
|---|---|
| `navigator.webdriver` is true | 100 |
| `webdriver` getter missing from the report | 80 |
| `webdriver` not an accessor on `Navigator.prototype`, or the getter is not native (script function) | 70 |
| other Navigator getters tampered (`userAgent`, `platform`, `languages`, `hardwareConcurrency`, `plugins`) | 55 |
| `Function.prototype.toString` patched | 50 |
| `HeadlessChrome` in the UA or `userAgentData.brands` | 85 |
| automation globals present | 90 |
| `window.chrome` absent in a desktop Chrome UA (warn) / atypical shape (warn) | 25 / 15 |
| Chrome >= 90 UA with empty `userAgentData.brands` (warn) | 15 |
| `cdp_probes` on and the Error.stack trap fired | 60 |

`score = min(100, round(max + 0.5 * sum(others)))`. 50 and above fails, 20-49 warns, below 20 passes. No sensor at all is
fail 90 ("no sensor posted (no integrity probes)"; "no usable sensor (<reason>)" if it was rejected). Applies to page,
protected and transactional requests.

## How a scraper passes it

By not tampering: a stock (headful, or patched-at-source) browser reports native getters and no automation globals.
`Object.defineProperty(Navigator.prototype, 'webdriver', {get: () => false})` leaves the descriptor in place but swaps in
a script function (its `toString` shows source and its name is `get`), which is flagged. A client that fabricates
native-shaped results without running the script passes: the data is client-supplied, and the lab does not claim to
match Akamai's rotated, obfuscated probes.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 90, "no sensor posted (no integrity probes)" |
| curl_cffi | fail | fail 90, same reason |
| Playwright (default recipe) | fail | fail 100, "navigator.webdriver getter is not native (overridden by script); HeadlessChrome in UA or client hints; window.chrome is absent in a Chrome UA" |

`clients/results_notes.md` records how Playwright would pass (the full browser, `--disable-blink-features=
AutomationControlled`, no JS override, a CDP user-agent override with matching `userAgentMetadata`).

## Limits and caveats

- `window.chrome.runtime` is optional (it exists only on some pages); the expected set is `app`, `csi`, `loadTimes`.
- Akamai-specific CDP probes are unverified ([KNOWN_GAPS](../KNOWN_GAPS.md) low-confidence list).
