# `visitor_prioritization`: waiting room (a gate, off by default)

Category: network · Module: `api/app/modules/visitor_prioritization.py` · Default: **off** (`default_enabled = False`)
· Module tier: **LOW** · It is an access gate, not a detection: `evaluate()` is always SKIP and `applies_to` is empty

## What it is

Under load, admit only part of the **new** visitors and park the rest on a waiting page. An admitted visitor carries an
"allowed user" cookie; a parked visitor carries a short-lived waiting-room cookie and is let in after the wait.

## How real Akamai uses it

Akamai's Visitor Prioritization cloudlet issues an allowed-user cookie (the instance label changes its name) and a
waiting-room cookie ([P], TechDocs 2026-06-23, report §2.15). The cookie is commonly seen as `akavpau_<label>`, from a
single search snippet ([S, weak]). The lab's storefront is a "limited sneaker drop", the textbook use case.

## Confidence

Tier **LOW** overall (report §2.15, §3.1: "`akavpau_` cookie prefix: Low, search snippet only"). Unverified, vendor-sourced
detail; the module is disabled by default. Flag `akavpau_cookie_name` (default off) switches the allowed-user cookie to the
vendor-style name.

## How the lab simulates it

When enabled, a `pre_request` gate runs on page and protected requests before scoring:

- A session is **new** until it has an admission record (`vp:allowed:{sid}`, 3600 s). Admission is a deterministic hash of the
  session id: the same session always lands in the same bucket, and `admit_percent` of the 100 buckets (default 50,
  `LAB_VP_ADMIT_PERCENT`) are admitted at once.
- Everyone else is parked (`vp:parked:{sid}`): an HTML page for navigations (HTTP 200, `Retry-After`, a meta refresh) or a 503
  JSON `{error: "waiting_room", retry_after}` for API callers, plus a `lab_vp_waiting` cookie. The session is admitted once
  `wait_seconds` (default 30, `LAB_VP_WAIT_SECONDS`) have elapsed.
- Admission queues the allowed-user cookie (`lab_vp_allowed`, or `akavpau_<label>` with the flag on; label from `LAB_VP_LABEL`,
  default `lab`), which `finalize_cookies` issues.
- The waiting page still carries the sensor and pixel snippets.

## How a scraper passes it

Keep the cookies and wait; a parked client simply polls until admitted.

## Observed results

Not in the matrix ("a waiting-room gate, not a detection"; listed under "Off by default (LOW confidence)" in `RESULTS.md`).
Behaviour is covered by `api/tests/test_visitor_prioritization.py`.

## Limits and caveats

- No real queue, capacity or position: the wait estimate is a lab number.
- The cookie names and lifetimes are unverified ([KNOWN_GAPS](../KNOWN_GAPS.md) item 2).
