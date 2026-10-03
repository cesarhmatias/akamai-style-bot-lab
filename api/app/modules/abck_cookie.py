"""Case 4 - ``abck_cookie``: the ``_abck`` cookie must be present AND validated server-side.

Mechanism
---------
``_abck`` is the cookie Akamai's sensor flow upgrades once it accepts a client's telemetry.
Public captures show the shape ``HEX32~<flag>~YAAQ<base64>~-1~-1~-1`` (report §1.2 case 4,
tier MEDIUM: two public captures, 2022 and 2026). Akamai frames cookie and JavaScript checks as
active detection that "employs an interaction to confirm the request is coming from a web
browser" (report §1.2, [P]).

How real Akamai uses it (and what is unverified)
------------------------------------------------
* MEDIUM: id + state flag + opaque blob, refreshed by ``Set-Cookie`` on sensor POST responses.
* LOW (vendor-only, report §3.1): "valid once it contains ``~0~``", and "on sites that never
  show ``~0~`` the client must post exactly 3 sensors". A 2026 write-up calls ``~0~`` "a
  convention, not a guarantee". The lab therefore models validity in three modes.
* MEDIUM (approximation): binding the validated state to fingerprint continuity. The report
  says "Akamai's exact binding rules are not public"; the lab stores JA4 family + User-Agent +
  /24 (IPv6 /48) at validation time and treats a validated cookie presented with a different
  binding as replay or tampering.

Modes (this module)
-------------------
``default``          Server-side truth only: the store key ``abck:{session_id}`` decides. The
                     cookie's flag field is NOT trusted (a forged ``~0~`` simply is not
                     validated). Cookie flag stays ``-1``.
``abck_tilde0_mode`` (LOW flag, default off) The cookie flips to ``~0~`` on validation, and a
                     ``~0~`` cookie that the server never validated is a BLOCK (forgery).
``abck_n_posts``     (LOW flag, default off) Vendor "3-post rule": validity requires N valid
                     sensor posts (``sensor:n:{sid}``, N = 3, env ``LAB_ABCK_REQUIRED_POSTS``)
                     and ``~0~`` never appears.

How the lab simulates / how a client passes
-------------------------------------------
No JS of its own: ``sensor_data`` validates posts, then calls ``mark_abck_validated`` with the
fingerprint binding and refreshes the cookie. A client passes by running the sensor flow in
the same browser (same TLS stack, UA and /24) and keeping the cookies it is handed.

Limits
------
Lab thresholds and the binding components are the lab's own. A UA or JA4-family change is a
BLOCK; an IP-prefix-only change is a FAIL (NAT and mobile roaming legitimately move clients).
"""

from __future__ import annotations

import os
from typing import ClassVar

from app.contract import (
    Confidence,
    DetectionModule,
    FlagSpec,
    RequestContext,
    Signal,
    Verdict,
)
from app.session import (
    abck_binding,
    binding_from_ctx,
    binding_mismatch,
    is_abck_validated,
    parse_abck,
)

DEFAULT_REQUIRED_POSTS = 3


def required_posts() -> int:
    """Sensor posts needed in ``abck_n_posts`` mode (default 3, env ``LAB_ABCK_REQUIRED_POSTS``)."""
    try:
        return max(1, int(os.environ.get("LAB_ABCK_REQUIRED_POSTS", DEFAULT_REQUIRED_POSTS)))
    except ValueError:
        return DEFAULT_REQUIRED_POSTS


class AbckCookieModule(DetectionModule):
    slug: ClassVar[str] = "abck_cookie"
    title: ClassVar[str] = "_abck cookie validation"
    description: ClassVar[str] = (
        "Requires a persisted _abck cookie whose session the sensor flow validated server-side, "
        "presented by the same client (JA4 family, User-Agent, /24) that validated it."
    )
    category: ClassVar[str] = "cookie"
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    flags: ClassVar[list[FlagSpec]] = [
        FlagSpec(
            name="abck_tilde0_mode",
            description="Cookie flips to ~0~ on validation; a forged ~0~ is a BLOCK.",
            confidence=Confidence.LOW,
            source="report §1.2 case 4, §3.1 (~0~ semantics: vendors only)",
        ),
        FlagSpec(
            name="abck_n_posts",
            description="Validity needs N valid sensor posts (default 3); ~0~ never appears.",
            confidence=Confidence.LOW,
            source="report §1.2 case 4, §3.1 (3-post rule: vendors only)",
        ),
    ]

    async def evaluate(self, ctx: RequestContext) -> Signal:
        value = ctx.cookies.get("_abck")
        if not value:
            return self.signal(Verdict.FAIL, 95, "no _abck (first visit / cookies not persisted)")
        store, sid = ctx.store, ctx.session_id
        tilde0, n_posts = ctx.flag("abck_tilde0_mode"), ctx.flag("abck_n_posts")
        parsed = parse_abck(value)
        mode = "n_posts" if n_posts else "tilde0" if tilde0 else "default"
        truth = store is not None and bool(sid) and await is_abck_validated(store, sid)
        if n_posts and truth:
            posts = int(await store.get(f"sensor:n:{sid}") or 0)
            truth = posts >= required_posts()
        if tilde0 and not n_posts and parsed and parsed[1] == 0 and not truth:
            return self.signal(
                Verdict.BLOCK,
                100,
                "_abck claims ~0~ but server never validated it (forged)",
                mode=mode,
            )
        if parsed is None:
            return self.signal(Verdict.FAIL, 85, "_abck is malformed", mode=mode)
        if not truth:
            reason = "_abck not validated"
            if n_posts:
                reason += f" (needs {required_posts()} valid sensor posts)"
            return self.signal(Verdict.FAIL, 85, reason, server_validated=False, mode=mode)
        bound = await abck_binding(store, sid)
        if bound is not None:
            diff = binding_mismatch(bound, binding_from_ctx(ctx))
            if diff and diff != ["net"]:
                return self.signal(
                    Verdict.BLOCK,
                    100,
                    f"validated _abck presented by a different client ({', '.join(diff)} changed): "
                    "replay/tamper",
                    mode=mode,
                    binding_diff=diff,
                )
            if diff:
                return self.signal(
                    Verdict.FAIL,
                    70,
                    "validated _abck presented from a different network prefix",
                    mode=mode,
                    binding_diff=diff,
                )
        return self.signal(Verdict.PASS, 0, "_abck validated", mode=mode, server_validated=True)
