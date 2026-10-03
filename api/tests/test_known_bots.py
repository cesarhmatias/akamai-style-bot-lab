import asyncio

import app.modules.known_bots as kb
import pytest
from app.contract import EndpointClass, RequestContext, Verdict
from app.store import MemoryStore

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
GPTBOT_UA = (
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; "
    "+https://openai.com/gptbot"
)
CLAUDEBOT_UA = "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/153.0.0.0 Safari/537.36"
)
NOW = 1_800_000_000


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    monkeypatch.setattr(kb, "_clock", lambda: NOW)
    monkeypatch.delenv("LAB_KNOWN_BOT_RANGES", raising=False)


def ctx(ua, ip="203.0.113.7", headers=None, store=None, path="/protected/known_bots"):
    hs = [("host", "lab.local:8443"), *(headers or [])]
    return RequestContext(
        method="GET", path=path, client_ip=ip, headers=hs, header_order=[], cookies={},
        user_agent=ua, store=store or MemoryStore(),
    )


def run(c):
    return asyncio.run(kb.KnownBotsModule().evaluate(c))


def signed(bot, **kw):
    h = kb.lab_sign_headers(bot, "lab.local:8443", created=NOW, **kw)
    return [(k.lower(), v) for k, v in h.items()]


# --- Ed25519 against RFC 8032 test vectors -------------------------------------------------


def test_ed25519_rfc8032_vector_1_empty_message():
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39"
        "701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert kb.ed25519_public_key(seed) == pub
    assert kb.ed25519_sign(seed, b"") == sig
    assert kb.ed25519_verify(pub, b"", sig)


def test_ed25519_rfc8032_vector_2_one_byte():
    seed = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    pub = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    sig = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f36"
        "13d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    assert kb.ed25519_public_key(seed) == pub
    assert kb.ed25519_sign(seed, b"\x72") == sig
    assert kb.ed25519_verify(pub, b"\x72", sig)


def test_ed25519_rejects_tampering():
    seed = b"\x01" * 32
    pub = kb.ed25519_public_key(seed)
    sig = kb.ed25519_sign(seed, b"hello")
    assert not kb.ed25519_verify(pub, b"hellp", sig)
    assert not kb.ed25519_verify(pub, b"hello", sig[:-1] + bytes([sig[-1] ^ 1]))
    assert not kb.ed25519_verify(pub[:-1], b"hello", sig)
    assert not kb.ed25519_verify(kb.ed25519_public_key(b"\x02" * 32), b"hello", sig)


# --- classification --------------------------------------------------------------------------


def test_module_metadata():
    m = kb.KnownBotsModule()
    assert m.confidence.value == "medium" and m.default_enabled
    assert m.applies_to == frozenset(EndpointClass)


@pytest.mark.parametrize(
    ("ua", "name", "cls"),
    [
        (GOOGLEBOT_UA, "googlebot", "search_engine"),
        (GPTBOT_UA, "gptbot", "ai_training"),
        (CLAUDEBOT_UA, "claudebot", "ai_training"),
        ("Mozilla/5.0 (compatible; OAI-SearchBot/1.0)", "oai-searchbot", "ai_search"),
        ("Mozilla/5.0 ... ChatGPT-User/1.0", "chatgpt-user", "ai_fetcher_agent"),
        ("Mozilla/5.0 (compatible; PerplexityBot/1.0)", "perplexitybot", "ai_search"),
        ("Mozilla/5.0 (compatible; Perplexity-User/1.0)", "perplexity-user", "ai_fetcher_agent"),
        ("Mozilla/5.0 (compatible; bingbot/2.0)", "bingbot", "search_engine"),
        ("Mozilla/5.0 (compatible; Applebot/0.1)", "applebot", "search_engine"),
    ],
)
def test_identify_bot(ua, name, cls):
    bot = kb.identify_bot(ua)
    assert bot is not None and (bot.name, bot.bot_class) == (name, cls)


def test_ai_split_has_three_categories():
    cats = {b.category for b in kb.BOTS}
    assert {kb.CAT_AI_TRAIN, kb.CAT_AI_SEARCH, kb.CAT_AI_AGENT} <= cats


def test_browsers_are_not_bots():
    assert kb.identify_bot(CHROME_UA) is None
    assert run(ctx(CHROME_UA)).verdict == Verdict.SKIP


# --- impersonation / IP ranges ---------------------------------------------------------------


def test_googlebot_from_random_ip_is_impersonator():
    s = run(ctx(GOOGLEBOT_UA))
    assert s.verdict == Verdict.FAIL and s.score == 85
    assert "Impersonator of known bot" in s.reason
    assert s.details["impersonator"] is True and s.details["bot_name"] == "googlebot"


def test_googlebot_from_published_range_passes():
    s = run(ctx(GOOGLEBOT_UA, ip="66.249.66.1"))
    assert s.verdict == Verdict.PASS
    d = s.details
    assert d["verified_by"] == "ip-range" and d["bot_category"] == kb.CAT_SEARCH
    assert "not performed" in d["rdns"]


def test_env_range_verifies_ai_bot(monkeypatch):
    assert run(ctx(GPTBOT_UA, ip="198.51.100.20")).verdict == Verdict.FAIL
    monkeypatch.setenv("LAB_KNOWN_BOT_RANGES", "gptbot=198.51.100.0/28,198.51.100.16/28")
    s = run(ctx(GPTBOT_UA, ip="198.51.100.20"))
    assert s.verdict == Verdict.PASS and s.details["bot_category"] == kb.CAT_AI_TRAIN
    assert s.details["bot_class"] == "ai_training"


def test_range_for_one_bot_does_not_verify_another(monkeypatch):
    monkeypatch.setenv("LAB_KNOWN_BOT_RANGES", "gptbot=198.51.100.0/24")
    assert run(ctx(CLAUDEBOT_UA, ip="198.51.100.20")).verdict == Verdict.FAIL


# --- RFC 9421 signatures ---------------------------------------------------------------------


def test_valid_signature_verifies_claimed_bot():
    s = run(ctx(CLAUDEBOT_UA, headers=signed("claudebot")))
    assert s.verdict == Verdict.PASS and s.details["verified_by"] == "http-message-signature"
    assert s.details["bot_category"] == kb.CAT_AI_TRAIN and s.details["keyid"]


def test_signature_from_other_bots_key_is_impersonation():
    s = run(ctx(CLAUDEBOT_UA, headers=signed("gptbot")))
    assert s.verdict == Verdict.FAIL and "belongs to gptbot" in s.details["signature_error"]


def test_signature_for_other_authority_fails():
    h = kb.lab_sign_headers("claudebot", "other.example", created=NOW)
    s = run(ctx(CLAUDEBOT_UA, headers=[(k.lower(), v) for k, v in h.items()]))
    assert s.verdict == Verdict.FAIL and "does not verify" in s.details["signature_error"]


def test_stale_signature_fails():
    h = kb.lab_sign_headers("claudebot", "lab.local:8443", created=NOW - 3600)
    s = run(ctx(CLAUDEBOT_UA, headers=[(k.lower(), v) for k, v in h.items()]))
    assert s.verdict == Verdict.FAIL and "away from now" in s.details["signature_error"]


def test_tampered_signature_fails():
    hs = signed("claudebot")
    hs = [(k, v[:-3] + "AA:" if k == "signature" else v) for k, v in hs]
    s = run(ctx(CLAUDEBOT_UA, headers=hs))
    assert s.verdict == Verdict.FAIL


def test_unknown_keyid_fails():
    hs = signed("claudebot")
    hs = [(k, v.replace('keyid="', 'keyid="zz') if k == "signature-input" else v) for k, v in hs]
    s = run(ctx(CLAUDEBOT_UA, headers=hs))
    assert s.verdict == Verdict.FAIL and "unknown keyid" in s.details["signature_error"]


def test_missing_tag_fails():
    hs = signed("claudebot")
    hs = [
        (k, v.replace(';tag="web-bot-auth"', "") if k == "signature-input" else v) for k, v in hs
    ]
    s = run(ctx(CLAUDEBOT_UA, headers=hs))
    assert s.verdict == Verdict.FAIL and "web-bot-auth" in s.details["signature_error"]


def test_nonce_replay_is_rejected():
    store = MemoryStore()
    hs = signed("claudebot", nonce="n-1")
    assert run(ctx(CLAUDEBOT_UA, headers=hs, store=store)).verdict == Verdict.PASS
    again = run(ctx(CLAUDEBOT_UA, headers=hs, store=store))
    assert again.verdict == Verdict.FAIL and "nonce replayed" in again.details["signature_error"]


def test_signature_wins_over_wrong_ip_and_ip_wins_over_bad_signature():
    by_sig = run(ctx(GOOGLEBOT_UA, ip="10.9.9.9", headers=signed("googlebot")))
    assert by_sig.verdict == Verdict.PASS
    bad = [("signature", "sig1=:AAAA:"), ("signature-input", signed("googlebot")[1][1])]
    s = run(ctx(GOOGLEBOT_UA, ip="66.249.66.1", headers=bad))
    assert s.verdict == Verdict.PASS and s.details["verified_by"] == "ip-range"
    assert "signature_error" in s.details


def test_signed_agent_with_browser_ua_is_accepted_and_categorised():
    s = run(ctx(CHROME_UA, headers=signed("chatgpt-user")))
    assert s.verdict == Verdict.PASS
    assert s.details["bot_category"] == kb.CAT_AI_AGENT and "Signed agent" in s.reason


def test_failed_signature_on_non_bot_ua_is_low_warn_not_fail():
    hs = signed("claudebot")
    hs = [(k, v[:-3] + "AA:" if k == "signature" else v) for k, v in hs]
    s = run(ctx(CHROME_UA, headers=hs))
    assert s.verdict == Verdict.WARN and s.score == 20


def test_signature_agent_must_be_covered_when_present():
    hs = signed("claudebot")
    hs = [(k, v.replace(' "signature-agent"', "") if k == "signature-input" else v) for k, v in hs]
    s = run(ctx(CLAUDEBOT_UA, headers=hs))
    assert s.verdict == Verdict.FAIL  # the signed base no longer matches either


def test_parse_signature_input_multiple_labels():
    raw = (
        'sig1=("@authority");created=1;keyid="a";tag="x", '
        'sig2=("@authority" "signature-agent");created=2;keyid="b"'
    )
    parsed = kb.parse_signature_input(raw)
    assert set(parsed) == {"sig1", "sig2"}
    assert parsed["sig2"][0] == ["@authority", "signature-agent"]
    assert parsed["sig1"][1] == {"created": "1", "keyid": "a", "tag": "x"}
    assert kb.parse_signatures("sig1=:QUJD:, bad=xyz") == {"sig1": b"ABC"}


# --- key directory ---------------------------------------------------------------------------


def test_directory_jwks_lists_lab_keys_with_thumbprint_kids():
    jwks = kb.directory_jwks()
    keys = {k["lab_bot"]: k for k in jwks["keys"]}
    assert set(keys) == set(kb.BOT_BY_NAME)
    pub = kb.lab_key("gptbot").public
    assert keys["gptbot"]["kid"] == kb.thumbprint(pub)
    assert keys["gptbot"]["kty"] == "OKP" and keys["gptbot"]["crv"] == "Ed25519"


async def test_well_known_directory_is_served(client):
    r = await client.get("/.well-known/http-message-signatures-directory")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/http-message-signatures-directory")
    assert any(k["lab_bot"] == "googlebot" for k in r.json()["keys"])
