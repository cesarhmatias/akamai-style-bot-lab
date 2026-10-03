"""Bot Score segments, the response policy document and the safeguard bookkeeping."""

from collections.abc import Callable

import pytest
from app.contract import Action, EndpointClass, RequestContext, Signal, Verdict
from app.engine import Engine, telemetry_type_for
from app.policy import (
    HUMAN,
    Policy,
    PolicyParams,
    PolicyStore,
    clear_challenge_failures,
    decide_challenge,
)
from app.registry import Registry
from app.store import MemoryStore
from test_engine import make


@pytest.mark.parametrize(
    ("ttype", "score", "segment"),
    [
        ("standard", 0, HUMAN),
        ("standard", 1, "cautious"),
        ("standard", 20, "cautious"),
        ("standard", 21, "strict"),
        ("standard", 60, "strict"),
        ("standard", 61, "aggressive"),
        ("standard", 100, "aggressive"),
        ("inline", 28, "cautious"),
        ("inline", 29, "strict"),
        ("inline", 80, "strict"),
        ("inline", 81, "aggressive"),
        ("native", 25, "cautious"),
        ("native", 26, "strict"),
        ("native", 70, "strict"),
        ("native", 71, "aggressive"),
        ("bogus", 40, "strict"),  # unknown telemetry types use the standard bands
    ],
)
def test_segment_bands(ttype: str, score: int, segment: str) -> None:
    assert Policy().segment_for(score, ttype) == segment


def test_default_actions() -> None:
    p = Policy()
    assert p.action_for(EndpointClass.PROTECTED, HUMAN) == Action.ALLOW
    assert p.action_for(EndpointClass.PROTECTED, "cautious") == Action.MONITOR
    assert p.action_for(EndpointClass.PROTECTED, "strict") == Action.CHALLENGE
    assert p.action_for(EndpointClass.PROTECTED, "aggressive") == Action.DENY
    assert p.action_for(EndpointClass.TRANSACTIONAL, "strict") == Action.SERVE_ALTERNATE
    assert p.action_for(EndpointClass.PAGE, "aggressive") == Action.MONITOR  # landing stays up


async def test_policy_store_roundtrip_merge_and_validation(memory_store: MemoryStore) -> None:
    ps = PolicyStore(memory_store)
    assert (await ps.get()).params.challenge_provider == "crypto"
    p = await ps.update(
        {"actions": {"protected": {"strict": "tarpit"}}, "params": {"delay_seconds": 0.1}}
    )
    assert p.actions["protected"]["strict"] == Action.TARPIT
    assert p.actions["protected"]["aggressive"] == Action.DENY  # merged, not replaced
    assert (await ps.get()).params.delay_seconds == 0.1
    with pytest.raises(ValueError, match="band"):
        await ps.update({"bands": {"standard": {"strict": [50, 10]}}})
    with pytest.raises(ValueError, match="unknown endpoint class"):
        await ps.update({"actions": {"nope": {"strict": "deny"}}})
    with pytest.raises(ValueError, match="challenge_provider"):
        await ps.update({"params": {"challenge_provider": "bogus"}})
    assert (await ps.reset()).actions["protected"]["strict"] == Action.CHALLENGE


def test_telemetry_type_resolution(make_ctx: Callable[..., RequestContext]) -> None:
    plain = [Signal(module="m", verdict=Verdict.PASS, score=0, reason="r")]
    inline = [
        Signal(
            module="i",
            verdict=Verdict.PASS,
            score=0,
            reason="r",
            details={"telemetry_type": "inline"},
        )
    ]
    assert telemetry_type_for(make_ctx(), plain) == "standard"
    assert telemetry_type_for(make_ctx(), inline) == "inline"
    assert telemetry_type_for(make_ctx(endpoint_class=EndpointClass.MOBILE), plain) == "native"


async def test_engine_report_fields(
    memory_store: MemoryStore, make_ctx: Callable[..., RequestContext]
) -> None:
    eng = Engine(Registry(memory_store, [make("a", 70)]), memory_store)
    rep = await eng.evaluate(make_ctx())
    assert rep.segment == "aggressive" and rep.action == Action.DENY and rep.blocked
    assert rep.reference.startswith("18.") and eng.by_reference("#" + rep.reference) is rep
    assert not rep.is_human
    ok = Engine(Registry(memory_store, [make("a", 0, Verdict.PASS)]), memory_store)
    rep = await ok.evaluate(make_ctx())
    assert rep.is_human and rep.segment == HUMAN and rep.action == Action.ALLOW and not rep.blocked


async def test_block_verdict_forces_deny(
    memory_store: MemoryStore, make_ctx: Callable[..., RequestContext]
) -> None:
    eng = Engine(Registry(memory_store, [make("a", 5, Verdict.BLOCK)]), memory_store)
    rep = await eng.evaluate(make_ctx())
    assert rep.segment == "cautious" and rep.action == Action.DENY and rep.blocked


async def test_serve_alternate_gets_canary(
    memory_store: MemoryStore, make_ctx: Callable[..., RequestContext]
) -> None:
    eng = Engine(Registry(memory_store, [make("a", 40)]), memory_store)
    await eng.policy.update({"actions": {"protected": {"strict": "serve_alternate"}}})
    rep = await eng.evaluate(make_ctx())
    assert rep.action == Action.SERVE_ALTERNATE and not rep.blocked
    assert (
        rep.canary.startswith("cnry-") and await memory_store.get(f"canary:{rep.canary}") == rep.id
    )


async def test_layers_and_origin_headers(
    memory_store: MemoryStore, make_ctx: Callable[..., RequestContext]
) -> None:
    class Rich(type(make("v", 0))):  # type: ignore[misc]
        async def evaluate(self, ctx: RequestContext) -> Signal:
            return Signal(
                module="v",
                verdict=Verdict.PASS,
                score=0,
                reason="r",
                details={
                    "layers": {"ua": 131},
                    "bot_name": "amazonbot",
                    "bot_category": "Web Search Engine Bots",
                    "user_risk": {"uuid": "u1", "score": 7, "risk": ["unew_net"], "allow": 0},
                },
            )

    Rich.slug = "v"  # type: ignore[misc]
    eng = Engine(Registry(memory_store, [Rich()]), memory_store)
    rep = await eng.evaluate(make_ctx(ja4="t13d1516h2_x_y"))
    assert rep.layers == {"ua": 131}
    h = rep.origin_headers
    assert h["Akamai-Bot"] == "Akamai-Categorized Bot (amazonbot):allow:Web Search Engine Bots"
    assert h["Akamai-User-Risk"].startswith("uuid=u1;requestid=" + rep.id + ";status=0;score=7;")
    assert h["Akamai-User-Risk"].endswith("risk=unew_net;trust=;allow=0;action=allow")
    assert h["ja4-fingerprint"] == "t13d1516h2_x_y"


async def test_unclassified_and_human_bot_header(
    memory_store: MemoryStore, make_ctx: Callable[..., RequestContext]
) -> None:
    eng = Engine(Registry(memory_store, [make("a", 30)]), memory_store)
    rep = await eng.evaluate(make_ctx())
    assert (
        rep.origin_headers["Akamai-Bot"] == "Akamai-Unclassified Bot (lab-defined):challenge:strict"
    )
    assert (
        "Akamai-User-Risk" not in rep.origin_headers and "ja4-fingerprint" not in rep.origin_headers
    )


async def test_safeguard_after_k_failed_challenges(memory_store: MemoryStore) -> None:
    params = PolicyParams(safeguard_failures=2, safeguard_window_seconds=60)
    assert await decide_challenge(memory_store, "s", params, 0) == (Action.CHALLENGE, False)
    assert await decide_challenge(memory_store, "s", params, 1) == (Action.CHALLENGE, False)
    assert await decide_challenge(memory_store, "s", params, 2) == (Action.SAFEGUARD, True)
    assert await decide_challenge(memory_store, "s", params, 3) == (Action.SAFEGUARD, True)
    await clear_challenge_failures(memory_store, "s")
    assert await decide_challenge(memory_store, "s", params, 4) == (Action.CHALLENGE, False)


async def test_engine_safeguard_and_reset_keeps_policy(
    memory_store: MemoryStore, make_ctx: Callable[..., RequestContext]
) -> None:
    reg = Registry(memory_store, [make("a", 30)])
    eng = Engine(reg, memory_store)
    await eng.policy.update({"params": {"safeguard_failures": 2, "tarpit_seconds": 0.01}})
    await reg.set_flag("akamai_ghost_server_header", False)
    ctx = make_ctx(session_id="sid-1")
    acts = [(await eng.evaluate(ctx)).action for _ in range(4)]
    assert acts == [Action.CHALLENGE, Action.CHALLENGE, Action.SAFEGUARD, Action.SAFEGUARD]
    last = await eng.evaluate(ctx)
    assert last.is_safeguard and not last.blocked
    await eng.reset()
    assert (await eng.policy.get()).params.tarpit_seconds == 0.01
    assert not await reg.flag_value(reg.flag_specs()["akamai_ghost_server_header"])
    assert (await eng.evaluate(ctx)).action == Action.CHALLENGE  # counters were cleared
