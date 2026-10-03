# `known_bots`: known-bot verification and impersonators

Category: passive · Module: `api/app/modules/known_bots.py` · Protected URL: `/protected/known_bots`
· Default: on · Module tier: **MEDIUM** (an approximation)

## What it is

Well-known crawlers announce themselves in the User-Agent, which anyone can forge. A genuine one is verifiable out of
band: by its source network (published IP ranges, or reverse DNS plus forward confirmation) or by a cryptographic
identity: HTTP Message Signatures (RFC 9421), profiled by the Web Bot Auth drafts (`Signature`, `Signature-Input`,
`Signature-Agent` and a key directory at `/.well-known/http-message-signatures-directory`).

## How real Akamai uses it

Bot Manager has a known-bot directory (about 1,750 bots in 2023, [P]) and an "Impersonators of Known Bots" detection
([P], report §2.11). On 2026-09-03 Akamai split AI bots into AI training crawlers, AI search crawlers, and AI fetchers
and agents ([P]); since late 2025 it verifies Web Bot Auth signatures ([P]). Directory contents, category membership
and the verification internals are not public. The `Akamai-Bot` origin header observed in the wild reads
`Akamai-Categorized Bot (amazonbot):monitor:Web Search Engine Bots` ([S]).

## Confidence

Tier **MEDIUM** (report §2.11, §3.1): the behaviour is an approximation. Sub-features:

| Sub-feature | Tier |
|---|---|
| Impersonator detection, AI category split, signature verification (concept) | HIGH (Akamai blogs 2025-2026) |
| Lab-local bot table, built-in IP ranges (Googlebot, Bingbot, Applebot), category labels | MEDIUM (approximation; ranges are an illustrative snapshot that goes stale) |
| Web Bot Auth header details (`/.well-known/...` directory) | MEDIUM (drafts not fetched by the audit) |

No flag. The Web Bot Auth path and the `Akamai-Bot` header are always on.

## How the lab simulates it

- `BOTS` is a lab table of UA patterns with a category: Web Search Engine Bots (googlebot, bingbot, applebot,
  amazonbot, duckduckbot, yandexbot, baiduspider), AI Training Crawlers (gptbot, claudebot, ccbot, bytespider,
  meta-externalagent), AI Search Crawlers (oai-searchbot, claude-searchbot, perplexitybot, duckassistbot), AI Fetchers
  and Agents (chatgpt-user, claude-user, perplexity-user) and Link Preview Bots. AI bots have no built-in range.
  Extend ranges with `LAB_KNOWN_BOT_RANGES="googlebot=66.249.64.0/19;gptbot=203.0.113.0/28"`. Reverse DNS is not
  performed (the lab is offline) and says so in `details["rdns"]`.
- A UA claiming a known bot passes when the client IP is in the bot's ranges, or when the request carries a valid
  RFC 9421 signature from a key in the lab directory whose bot name matches: covered `@authority`, `created` within
  300 s, `tag="web-bot-auth"`, optional `nonce` replay protection (store key `botsig:nonce:{keyid}:{nonce}`), and
  covered `signature-agent` when that header is present. Otherwise: FAIL 85 "Impersonator of known bot".
- A valid signature from a lab key is accepted with a non-bot UA too ("signed agent": pass 0). A signature that does
  not verify, with no bot UA, is WARN 20. A non-bot UA without a signature is SKIP.
- Lab keys are Ed25519 (pure-Python RFC 8032, lab use only), derived from `LAB_BOT_KEY_SEED` (hex) or random per
  process, and published as a JWKS at `GET /.well-known/http-message-signatures-directory`. `lab_sign_headers()`
  signs requests for tests and demos.
- The pass result carries `bot_name`, `bot_category`, `bot_class` and `verified_by`; the engine turns them into the
  `Akamai-Bot` origin header (`Akamai-Categorized Bot (<name>):<action>:<category>`).

## How a scraper passes it

Do not claim to be a bot: a normal scraper gets SKIP. To be treated as a verified crawler you must come from the
bot's published ranges, or sign requests with a key the site trusts.

## Observed results

All three harness clients are SKIP ("Not a known-bot User-Agent"), shown as pass in the matrix: no client claims a
crawler UA. The row exists so the harness fails when the module disappears, not because the clients are tested on it.

## Limits and caveats

- The directory trusts only lab keys; remote `Signature-Agent` directories are never fetched, and the header is treated
  as an opaque value in the signature base.
- Category membership is the lab's labelling. Real Akamai's directory is not public.
- Ed25519 in pure Python is slow-ish and not production cryptography.
