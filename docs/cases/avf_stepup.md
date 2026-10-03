# `avf_stepup`: Advanced Validation Framework style step-up collection

Category: js · Module: `api/app/modules/avf_stepup.py` · Protected URL: `/protected/avf_stepup` · Default: on
· Module tier: **MEDIUM** (concept MEDIUM-HIGH; the probe set is a lab approximation)

## What it is

When a detection lacks enough information for a confident decision, ask the device for more data on demand instead of
always collecting it. Only gray-zone clients ever see the extra script.

## How real Akamai uses it

Akamai's 2026-03-10 blog says "If a detection method lacks sufficient information to make a confident decision, the new
AVF dynamically requests additional data from the device" ([P], report §2.6). What it asks for, and how the answer is
scored, is not public. The probe set here (WebGL vendor and renderer, an audio-context hash, a font count) is the report's
suggestion, not a documented Akamai list.

## Confidence

Tier **MEDIUM** (report §2.6): the on-demand concept is public; the probes, scoring and thresholds are an approximation. No
flag.

## How the lab simulates it

- `after_score`: when a request lands in the `strict` segment and no step-up data exists for the session, the session is
  marked `avf:need:{sid}` (900 s).
- `page_snippets` then adds `/akam/avf_stepup/stepup.js` to every lab HTML page for that session only. The script posts
  `{webgl: {vendor, renderer}, audio, fonts}` to `POST /akam/avf_stepup/data` (403 `not_requested` if nothing was
  requested). The data is stored at `avf:data:{sid}` (3600 s) and the response returns the step-up score.
- Scoring of the data (higher is more bot-like): no WebGL renderer 25; a software renderer (SwiftShader, llvmpipe,
  softpipe, mesa offscreen) 35; a renderer contradicting the UA platform 30; a missing or degenerate audio hash 20; fewer
  than 3 fonts 25 (capped at 100).
- `evaluate()`: SKIP when no step-up was requested; WARN 30 when requested but no data arrived; otherwise the data score
  (0 passes, 1-49 warns, 50 and above fails). The next request is re-scored with that signal.
- The report's alternative (route the strict segment to the tile challenge) is available by setting `challenge_provider`
  to `interactive` in the policy.

## How a scraper passes it

Run the script in a real browser with a real GPU or a believable software stack. A pure-HTTP client never sees the script's
output and keeps the WARN.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | warn | warn 30, "step-up data requested but not received" (challenge/strict) |
| curl_cffi | warn | warn 30, same (monitor/strict) |
| Playwright | pass | skip 0, "no step-up requested for this session" (it was never pushed into the strict segment in this run) |

The case depends on session history by design and the matrix runs cases in a fixed order so the result is deterministic.

## Limits and caveats

- Lab heuristics; headless Chromium reports SwiftShader and would score as suspicious if it were asked.
- What Akamai asks for and how it scores it is unverified.
