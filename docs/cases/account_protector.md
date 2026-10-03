# `account_protector`: login risk against a per-account profile

Category: behavioral · Module: `api/app/modules/account_protector.py` · Protected URL: `/protected/account_protector`
(the matrix exercises `POST /api/login`) · Default: on · Module tier: **MEDIUM** (an approximation; weights are lab-defined)

## What it is

Judge a **login** by comparing it with what is already known about that account: the devices, networks, locations and
active hours it was seen with before, plus properties of the identifier itself (disposable email domains). A familiar login
is low risk; a new device on a new network minutes after a login from far away is high risk.

## How real Akamai uses it

Akamai's Account Protector brief (09/2024, [P], report §2.10) lists user behavioral profiles ("previously observed
locations, networks, devices, IP addresses, and activity time"), population profiles, source reputation, risk/trust/general
indicators, email address and domain intelligence including disposable domains, and actions that include a cryptographic and
behavioral challenge and serve alternate content. Scores come from "user behavior profiling, population profiling, and
reputation data" ([P], Terraform docs). The origin receives an `Akamai-User-Risk` header, observed as
`uuid=...;requestid=...;status=4;score=0;general=...;risk=;trust=udbp:...|udfp:...|udop:...|ugp:FR|unp:12322|utp:weekday_3;allow=0;action=monitor`
([S], an integrator write-up 2025 and Auth0). The scoring model and the meaning of the codes are not public.

## Confidence

Tier **MEDIUM** (report §2.10, §3.1: "`Akamai-User-Risk` format: Medium"). Concept HIGH; the lab's factors, weights, code
names and the header's field contents are lab-defined. No flag.

## How the lab simulates it

- Applies to `POST /api/login` only (every other transactional path is SKIP; so is a body without a `username`).
- Per-username profile in the store (`ap:profile:<sha256 of the username>[:24]`, 30 days): seen /24 networks, UA families,
  JA4 families, active hours, last /16 and time. The lab has no ASN or geo database, so the IP prefix stands in for both.
- Risk factors (points, summed and capped at 100): disposable email domain 35 (a small built-in list), new device (UA family)
  25, new network (/24) 20, new JA4 family 10, impossible travel (different /16 within 300 s) 40, unusual hour (after 5
  recorded hours) 10. With no profile yet (`gnew_user`) only the disposable-domain factor can apply.
- Verdict: score 0 passes ("login consistent with the profile"); 1-49 warns; 50 and above fails.
- `after_score` learns the login into the profile only when the engine let it through (not deny, tarpit, challenge or
  serve_alternate) and the risk was below 40, so an attacker cannot poison a profile.
- The signal carries `details["user_risk"]`; the engine renders it as the `Akamai-User-Risk` origin header
  (`uuid;requestid;status;score;general;risk;trust;allow;action`). It is only recorded in `ScoreReport.origin_headers`.

## How a scraper passes it

Log in from the account's usual device and network, with a real email domain.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | pass | pass 0, "login consistent with the profile (gnew_user)" |
| curl_cffi | pass | pass 0, same |
| Playwright | pass | pass 0, same |

A single clean login has no history to contradict, so every client passes this cell even though the same login request is
denied (`deny/aggressive`) because other modules fire on the transactional endpoint. The risk factors are covered by unit
tests.

## Limits and caveats

- No population profiles, no source-reputation feed, no real geo or ASN data.
- The `status`, `general`, `risk` and `trust` codes are loosely modelled on the observed example, not Akamai's.
