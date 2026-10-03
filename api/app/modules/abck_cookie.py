"""Case 4 - ``abck_cookie``: the ``_abck`` cookie must be present AND validated.

Real Akamai lifecycle:
1. First visit: the edge sets ``_abck=<hex>~-1~<blob>~-1~-1`` (``~-1~`` = not yet
   validated) together with ``bm_sz``/``ak_bmsc``.
2. The page's obfuscated sensor script POSTs ``sensor_data``; if Akamai judges it
   human-like, the response carries a new ``_abck`` containing ``~0~`` (validated).
3. Subsequent requests presenting a ``~0~`` cookie are let through; a ``~-1~`` cookie
   (or none) is challenged. Forging ``~0~`` locally is detected because the server
   remembers the truth (store key ``abck:{session_id}``).

This module has no JS of its own; it relies on the ``sensor_data`` flow.
"""

from __future__ import annotations

from typing import ClassVar

from app.contract import DetectionModule, RequestContext, Signal, Verdict
from app.session import is_abck_validated


class AbckCookieModule(DetectionModule):
    slug: ClassVar[str] = "abck_cookie"
    title: ClassVar[str] = "_abck cookie validation"
    description: ClassVar[str] = (
        "Requires a persisted _abck cookie that the sensor flow upgraded to the validated form."
    )
    category: ClassVar[str] = "cookie"

    async def evaluate(self, ctx: RequestContext) -> Signal:
        value = ctx.cookies.get("_abck")
        if not value:
            return self.signal(Verdict.FAIL, 95, "no _abck (first visit / cookies not persisted)")
        claims_valid = "~0~" in value
        truth = (
            ctx.store is not None
            and bool(ctx.session_id)
            and await is_abck_validated(ctx.store, ctx.session_id)
        )
        if claims_valid and not truth:
            return self.signal(
                Verdict.BLOCK, 100, "_abck claims ~0~ but server never validated it (forged)"
            )
        if not claims_valid:
            return self.signal(Verdict.FAIL, 85, "_abck not validated", server_validated=truth)
        return self.signal(Verdict.PASS, 0, "_abck validated")
