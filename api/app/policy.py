"""Bot Score segments and the per-endpoint response policy (audit §2.1, confidence HIGH).

Mechanism
    Every detection contributes to ONE aggregate Bot Score (0-100, see ``engine.aggregate``).
    The score is bucketed into a *response segment* and each segment is mapped to an *action*.
    Score 0 means "no detection fired" and is treated as human (``isHuman``).

How real Akamai uses it (report §2.1, tier HIGH)
    Akamai's Bot Manager UI example sets, for standard telemetry, Cautious 1-20 (Monitor),
    Strict 21-60 (Crypto challenge) and Aggressive 61-100 (Deny); for inline telemetry the
    bands are 1-28, 29-80 and 81-100; native mobile apps have their own row. Actions include
    monitor, allow, deny, delay, slow, tarpit, serve alternate content and challenge.
    EdgeWorkers exposes ``isHuman()`` and ``isSafeguardResponse()``. Often nothing obvious
    shows on the wire: a response is slower, content is subtly different, or a challenge
    appears; a 403 is only one possible outcome.

How the lab simulates it
    * standard and inline bands are the report's example numbers.
    * the ``native`` band (1-25 / 26-70 / 71-100) is LAB-CHOSEN: the report only says native
      apps have "a separate row" without numbers.
    * the segment -> action mapping per endpoint class and the action parameters (delay,
      slow, tarpit duration, safeguard thresholds, challenge settings) are lab defaults, not
      Akamai defaults. They are persisted in the store (``policy:doc``) and edited at
      ``GET/PUT /api/policy``; ``POST /api/reset`` keeps them.
    * ``safeguard``: after ``safeguard_failures`` challenges issued to one session inside
      ``safeguard_window_seconds`` without a solve, the next challenge becomes a pass under
      monitoring so a human is never trapped forever (isSafeguardResponse analogue).

``blocked`` in a report means the client did NOT receive the real resource: action in
``deny``, ``tarpit`` or ``challenge`` (``contract.BLOCKING_ACTIONS``). ``delay``, ``slow``,
``serve_alternate``, ``safeguard``, ``monitor`` and ``allow`` all answer with a normal 2xx.

Limits: the aggregate is a single number; Akamai does not publish how it combines
detections, so the lab keeps its own documented formula.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field, field_validator

from .contract import Action, EndpointClass, SessionStore
from .store import window_add, window_count

HUMAN = "human"
SEGMENTS = ("cautious", "strict", "aggressive")
TELEMETRY_TYPES = ("standard", "inline", "native")
CHALLENGE_PROVIDERS = ("crypto", "behavioral", "adaptive", "interactive", "interstitial")

POLICY_KEY = "policy:doc"

Bands = dict[str, dict[str, tuple[int, int]]]

# Band tables: telemetry type -> segment -> (low, high), inclusive. Standard and inline are
# the example values from the Akamai Bot Manager brief (report §2.1); native is lab-chosen.
DEFAULT_BANDS: Bands = {
    "standard": {"cautious": (1, 20), "strict": (21, 60), "aggressive": (61, 100)},
    "inline": {"cautious": (1, 28), "strict": (29, 80), "aggressive": (81, 100)},
    "native": {"cautious": (1, 25), "strict": (26, 70), "aggressive": (71, 100)},
}

# endpoint class -> segment -> action. Lab defaults chosen to keep the harness meaningful and
# fast: protected resources use the report's example (cautious=monitor, strict=challenge,
# aggressive=deny); the landing page is always served so challenge scripts can load;
# transactional endpoints are stricter and use silent degradation (serve_alternate).
DEFAULT_ACTIONS: dict[str, dict[str, Action]] = {
    EndpointClass.PAGE: {
        HUMAN: Action.ALLOW,
        "cautious": Action.MONITOR,
        "strict": Action.MONITOR,
        "aggressive": Action.MONITOR,
    },
    EndpointClass.PROTECTED: {
        HUMAN: Action.ALLOW,
        "cautious": Action.MONITOR,
        "strict": Action.CHALLENGE,
        "aggressive": Action.DENY,
    },
    EndpointClass.TRANSACTIONAL: {
        HUMAN: Action.ALLOW,
        "cautious": Action.DELAY,
        "strict": Action.SERVE_ALTERNATE,
        "aggressive": Action.DENY,
    },
    EndpointClass.MOBILE: {
        HUMAN: Action.ALLOW,
        "cautious": Action.MONITOR,
        "strict": Action.CHALLENGE,
        "aggressive": Action.DENY,
    },
}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


class PolicyParams(BaseModel):
    """Tunable action parameters. Defaults can be set with ``LAB_*`` environment variables."""

    delay_seconds: float = Field(default_factory=lambda: _env_float("LAB_DELAY_SECONDS", 1.5), ge=0)
    slow_seconds: float = Field(default_factory=lambda: _env_float("LAB_SLOW_SECONDS", 3.0), ge=0)
    slow_chunks: int = Field(default=6, ge=1, le=50)
    tarpit_seconds: float = Field(
        default_factory=lambda: _env_float("LAB_TARPIT_SECONDS", 5.0), ge=0
    )
    safeguard_failures: int = Field(default=3, ge=1)
    safeguard_window_seconds: int = Field(default=600, ge=1)
    challenge_provider: str = "crypto"
    # Minimum wall-clock seconds between issuing and solving a challenge (Akamai allows up to
    # 120 via cryptoChallengeDurationInSeconds; the lab default is small to keep runs fast).
    chlg_duration: float = Field(
        default_factory=lambda: _env_float("LAB_CHLG_DURATION", 2.0), ge=0, le=120
    )
    # Seconds a solved challenge stays valid (challengeIntervalInSeconds, API range 1-7200).
    challenge_interval: int = Field(
        default_factory=lambda: int(_env_float("LAB_CHALLENGE_INTERVAL", 600)), ge=1, le=7200
    )
    challenge_timeout: int = Field(default=60, ge=1)  # seconds to submit a solution
    adaptive_count: int = Field(default=3, ge=1, le=10)  # solutions required by "adaptive"
    norechallenge_seconds: int = Field(default=3000, ge=1)  # interactive challenge: 50 minutes

    @field_validator("challenge_provider")
    @classmethod
    def _provider(cls, v: str) -> str:
        if v not in CHALLENGE_PROVIDERS:
            raise ValueError(f"challenge_provider must be one of {CHALLENGE_PROVIDERS}")
        return v


class Policy(BaseModel):
    bands: Bands = Field(default_factory=lambda: {k: dict(v) for k, v in DEFAULT_BANDS.items()})
    actions: dict[str, dict[str, Action]] = Field(
        default_factory=lambda: {k: dict(v) for k, v in DEFAULT_ACTIONS.items()}
    )
    params: PolicyParams = Field(default_factory=PolicyParams)

    @field_validator("bands")
    @classmethod
    def _bands(
        cls, v: dict[str, dict[str, tuple[int, int]]]
    ) -> dict[str, dict[str, tuple[int, int]]]:
        for ttype, segs in v.items():
            if ttype not in TELEMETRY_TYPES:
                raise ValueError(f"unknown telemetry type {ttype}")
            for seg, (lo, hi) in segs.items():
                if seg not in SEGMENTS:
                    raise ValueError(f"unknown segment {seg}")
                if not 1 <= lo <= hi <= 100:
                    raise ValueError(f"bad band {ttype}.{seg}: need 1 <= low <= high <= 100")
        return v

    @field_validator("actions")
    @classmethod
    def _actions(cls, v: dict[str, dict[str, Action]]) -> dict[str, dict[str, Action]]:
        classes = {str(c) for c in EndpointClass}
        for cls_name, segs in v.items():
            if cls_name not in classes:
                raise ValueError(f"unknown endpoint class {cls_name}")
            for seg in segs:
                if seg != HUMAN and seg not in SEGMENTS:
                    raise ValueError(f"unknown segment {seg}")
        return v

    def segment_for(self, score: int, telemetry_type: str) -> str:
        """Segment name for a 0-100 score; ``human`` for 0."""
        if score <= 0:
            return HUMAN
        table = self.bands.get(telemetry_type) or self.bands["standard"]
        for seg in SEGMENTS:
            lo, hi = table.get(seg, (0, -1))
            if lo <= score <= hi:
                return seg
        return SEGMENTS[-1] if score > 0 else HUMAN

    def action_for(self, endpoint_class: EndpointClass | str, segment: str) -> Action:
        row = self.actions.get(str(endpoint_class), {})
        return row.get(segment, Action.MONITOR if segment != HUMAN else Action.ALLOW)


def segment_for(score: int, telemetry_type: str = "standard", policy: Policy | None = None) -> str:
    return (policy or Policy()).segment_for(score, telemetry_type)


def _merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class PolicyStore:
    """Loads and saves the policy document (store key ``policy:doc``)."""

    def __init__(self, store: SessionStore) -> None:
        self.store = store

    async def get(self) -> Policy:
        raw = await self.store.get(POLICY_KEY)
        if raw:
            try:
                return Policy.model_validate_json(raw)
            except ValueError:
                pass
        return Policy()

    async def put(self, policy: Policy) -> None:
        await self.store.set(POLICY_KEY, policy.model_dump_json())

    async def update(self, patch: dict[str, Any]) -> Policy:
        """Deep-merge ``patch`` into the current policy, validate, persist, return it."""
        current = (await self.get()).model_dump(mode="json")
        policy = Policy.model_validate(_merge(current, patch))
        await self.put(policy)
        return policy

    async def reset(self) -> Policy:
        policy = Policy()
        await self.put(policy)
        return policy


# --- safeguard bookkeeping -----------------------------------------------------------------


def _fail_key(sid: str) -> str:
    return f"chlg:fail:{sid}"


def _safe_key(sid: str) -> str:
    return f"safeguard:{sid}"


async def decide_challenge(
    store: SessionStore, sid: str, params: PolicyParams, now: float | None = None
) -> tuple[Action, bool]:
    """Resolve a ``challenge`` action for a session: (CHALLENGE|SAFEGUARD, is_safeguard).

    Every challenge issued is recorded in a sliding window. Once ``safeguard_failures``
    challenges were already issued inside ``safeguard_window_seconds`` with no solve, the
    session is let through under monitoring (and stays so for the same window)."""
    if not sid:
        return Action.CHALLENGE, False
    window = params.safeguard_window_seconds
    if await store.get(_safe_key(sid)):
        return Action.SAFEGUARD, True
    if await window_count(store, _fail_key(sid), window, now) >= params.safeguard_failures:
        await store.set(_safe_key(sid), "1", ttl=window)
        await store.delete(_fail_key(sid))
        return Action.SAFEGUARD, True
    await window_add(store, _fail_key(sid), window, now)
    return Action.CHALLENGE, False


async def clear_challenge_failures(store: SessionStore, sid: str) -> None:
    """Called by challenge providers on a successful solve."""
    if sid:
        await store.delete(_fail_key(sid))
        await store.delete(_safe_key(sid))
