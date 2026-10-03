# Known gaps

This lab simulates the *observable* behaviour of Akamai Bot Manager, calibrated from public sources (see
[`docs/research/akamai-audit-2026-10.md`](research/akamai-audit-2026-10.md)). It is **not a replica of the product** and is not
affiliated with Akamai. Three kinds of gap follow: things that could not be verified from public material, behaviour that is
implemented but rests on weak sources (and is therefore gated or labelled), and features that are deliberately not built.
Each case doc in [`docs/cases/`](cases/) says which of these applies to it.

## 1. Could not verify (audit §3.2)

Each of these needs a captured session to settle. Where the lab implements one, it does so behind a feature flag (default
off) or labels the behaviour as an approximation, and the case doc says which.

1. **`_abck` state transitions on a current site.** Whether `~0~` appears at all, after how many sensor POSTs, and what the
   trailing fields look like today.
2. **`Set-Cookie` attributes** (HttpOnly, Secure, SameSite, Max-Age, Domain) for `_abck`, `bm_sz`, `ak_bmsc`, `bm_sv`, `bm_mi`,
   `bm_so`, `bm_s`, `bm_ss`, `bm_lso`, `sbsd_o` and `sec_cpt`.
3. **The sensor payload's current version prefix**, and whether a given site uses standard or inline telemetry (look for
   `akamai-bm-telemetry` on XHR).
4. **SBSD:** the script URL, the body shape, the cookies, and passive versus blocking behaviour.
5. **sec-cpt:** 428 versus 200, the provider, `chlg_duration` values, and the verify path. For the `bm-verify` interstitial,
   whether the verify response ever carries a JSON `location`, and whether the 5-second meta-refresh wait is enforced by
   the server (see section 4).
6. **The behavioral challenge's DOM** and the events it records.
7. **The pixel POST body**, and which cookie changes afterwards.
8. **Deny responses:** the `Server` header, `Mime-Version`, and the reference format. Tarpit and serve-alternate are hard to
   observe by design.
9. **Whether a non-permuted extension order, a stale Chrome version, missing ML-DSA signature schemes or a missing Chrome
   152 GREASE signature algorithm get flagged in practice.**
10. **Safari 26's current TLS and HTTP/2 values.** The lab's Safari profiles come from Safari 18 captures.

## 2. Implemented on weak sources: flag-gated or labelled

Findings the audit rates Low (§3.1) never run by default. The lab keeps them behind a flag, off, and calls them "unverified,
vendor-sourced". Medium findings run by default and are documented as approximations. LAB marks teaching devices with no
Akamai analogue.

| Claim (audit §3.1, Low) | What the lab does | Flag (default) |
|---|---|---|
| `~0~` in `_abck` marks validity | cookie flips to `~0~` on validation; a forged `~0~` is a BLOCK | `abck_tilde0_mode` (off) |
| 3 sensor posts when `~0~` never appears | validity needs N posts (default 3) | `abck_n_posts` (off) |
| SBSD artifacts, passive and blocking modes, vendor cookies | the vendor-described flow; the default is the LAB op-chain device | `sbsd_vendor_flow` (off) |
| Pixel result is tied to `ak_bmsc` | a solved pixel re-issues `ak_bmsc` and scoring requires it | `pixel_ties_ak_bmsc` (off) |
| `ak_bmsc` is HttpOnly | the cookie is issued HttpOnly | `ak_bmsc_httponly` (off) |
| `bm_sv` / `bm_mi` purposes and lifetimes | cookies issued and `bm_sv` required on XHR | `bm_sv_cookies` (off) |
| Akamai-specific CDP / headless probes | an `Error.stack` getter trap probe | `cdp_probes` (off) |
| Hosting-ASN penalty | the built-in datacenter CIDR table adds WARN 40 | `hosting_asn_penalty` (off) |
| Botnet clustering / network effect | fingerprint clusters inherit a bad flag | `botnet_cluster` (off; module also off) |
| Current Akamai use of TCP/IP fingerprints | not implemented (stub, see below) | `tcp_fingerprint` (off; module also off) |
| `akavpau_` allowed-user cookie prefix | the allowed-user cookie takes that name | `akavpau_cookie_name` (off; module also off) |
| Penalties for old but genuine browser versions | **nothing**: the lab does not penalise a consistent old profile | none |
| HTTP/3 fingerprinting by Akamai | **nothing** (see deferred features) | none |
| Detection names "Cookie Integrity Failed", "Session Validation", "Browser Validation" | not used as names; `session_validation` is a lab approximation | none |
| SBSD is part of Content Protector | speculation; not modelled | none |
| JSON `location` in the interstitial verify response (audit §3.1, Low) | the verify reply carries the challenged path, same-origin only; clients must not depend on it (see section 4) | `interstitial_location` (off) |

## 3. Deferred features (deliberately not built)

| Feature | Why it is not built |
|---|---|
| **HTTP/3 and QUIC fingerprints** (audit §2.16) | Chrome's H3 SETTINGS and QUIC parameters can be fingerprinted, but the audit found **no evidence that Akamai Bot Manager scores them**, and the Go edge has no QUIC listener. Low value for Akamai fidelity. |
| **TCP/IP (p0f-style) passive fingerprint** (audit §2.12) | `tcp_fingerprint` is a documented stub that always returns SKIP. The SYN is invisible to the Go edge (`net` and `crypto/tls` hand over an established stream), so it needs raw capture with `NET_RAW` (AF_PACKET, libpcap or eBPF; the project uses no cgo). Docker's bridge NAT also re-originates the connection and rewrites the TTL, so a captured "initial TTL" would describe Docker, not the client. A real capture needs `network_mode: host` or a client-side vantage point. |
| **Pixel `<noscript><img>` fallback** (audit §1.2 case 7) | Seen only in search snippets: the audit "did not fetch a page that confirms it". Not built (`pixel_challenge` docstring). |
| **EdgeWorkers runtime** (`onBotSegmentAvailable`, `isHuman()`, `isSafeguardResponse()`) | There is no EdgeWorkers sandbox. The equivalents are `ScoreReport.is_human`, `is_safeguard` and `segment`. |
| **A real origin** behind the API | Origin verdict headers (`Akamai-Bot`, `Akamai-User-Risk`, `ja4-fingerprint`) are recorded in `ScoreReport.origin_headers` and shown in the inspector, but never forwarded to an upstream. |
| **Reverse-DNS verification and remote key directories** for known bots | The lab is offline; `known_bots` checks configured source ranges and a LAB Ed25519 key directory, and never fetches a remote `Signature-Agent` directory. |
| **Population profiles, source reputation feeds, real geo or ASN data** | Akamai derives these from its whole network. `account_protector` and `ip_reputation` use only local counters, with the IP prefix standing in for network and location. |
| **Other rate-control identifiers and client lists** (`api-key`, `cookie:<name>`, `request-header:<name>`, `query-string:<name>`; GEO, ASN, FILE_HASH, USER_ID, DOMAIN lists; `region_aggregated` counters) | Only `ip`, `ip-useragent` and `tls-fingerprint` identifiers and an IP list (`LAB_BAD_CIDRS`) exist. The rest add no new teaching value for a single-process lab. |
| **Challenge-action options** (`GOOGLE_RECAPTCHA`, `allowFullCpuUtilization`, custom branding, a real `AKAMAI_MOBILE_CRYPTO` SDK flow) | Only crypto, behavioral, adaptive, interactive and interstitial providers exist; the mobile class reuses the JSON provider. The real SDK documentation is login-gated. |
| **Five interactive mini-game types** | One tile-grid game is built (audit §2.4). |
| **High-entropy client-hint negotiation** (`Accept-CH`, `Critical-CH`) | The lab does not request hints; `header_order` and `version_consistency` use what the browser sends by default. |
| **HEADERS-frame priority scoring** | The edge records `x-h2-headers-priority` and `h2_fingerprint` echoes it in `details`, but it is outside Akamai's string and not scored. |
| **Real Akamai payload, cookie and script encodings** | Never copied: artifact *shapes* are modelled, encodings are lab-defined. |

## 4. Interstitial (`bm-verify`) specifics

- **`location` in the verify response is unconfirmed.** Published sources show the interstitial clearing the session by
  reloading the page, or by a `<meta http-equiv="refresh">` that carries a single-use `bm-verify` token. None shows a JSON
  `location` field in the `/_sec/verify?provider=interstitial` response. The lab returns one only with the Low flag
  `interstitial_location` (off); clients should not depend on it, and any client that follows it must reject
  cross-origin targets.
- **Cookie timing is approximated.** In the bershka capture the interstitial page sets only the site's own session cookies
  and the verify response sets `_abck`, `bm_sz` and `ak_bmsc`. The lab issues all three with the page, because it binds the
  token to `bm_sz`. Cookie presence therefore proves nothing in the lab: the gate clears only on server-side state (a solved
  interstitial, a valid `sec_cpt` or a validated `_abck`).
- **The meta-refresh wait is enforced by the lab.** The page refreshes after 5 seconds with the token, and the lab admits
  that one navigation only after the 5 seconds have passed. The brief says Bot Manager "enforces a time penalty" on clients
  that do not run JavaScript; that the server checks this particular wait is an inference.
- **`i` is read as the issue time.** The observed `var i = 1789910678` is 2026-09-20 13:24 UTC, inside the capture window, so
  the lab uses the issuing Unix time. One sample cannot prove it.

## How to close a gap without leaving the project's boundaries

Record a HAR in your everyday browser during an ordinary manual visit to a site you use anyway (DevTools → Network →
"Preserve log" → export HAR), or put an Akamai trial property in front of a site you own. Diff the capture against the lab's
live feed. Don't script captures against third-party sites, and scrub cookies and tokens from HARs before committing them.
