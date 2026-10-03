"""Response builders for the policy actions (audit §2.1 and §2.13).

* Deny page (§2.13, text and reference format tier HIGH, ``Server: AkamaiGHost`` MEDIUM):
  ``Access Denied`` / ``You don't have permission to access "<url>" on this server.`` /
  ``Reference #18.<hex>.<unix ts>.<hex>``. Real Akamai pages can also carry an
  ``errors.edgesuite.net`` link. In a 2026 measurement 103 of 110 blocked Akamai sites showed
  no vendor branding at all, so the page is deliberately plain.
* ``serve_alternate`` (§2.1, tier HIGH): silent degradation. A 200 response whose data is
  subtly wrong (price, stock, totals) and carries a hidden canary token recorded in
  ``ScoreReport.canary``. Nothing in the body says the client was classified; only the
  lab-only ``X-Lab-Report-Id`` header and ``GET /api/canary/<token>`` reveal it.
* ``slow`` streams the body in chunks over a configurable duration.

None of the shapes here are Akamai code; they are lab-written markup that mimics what a
client can observe.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi import Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

PRODUCT: dict[str, Any] = {
    "sku": "SNK-DROP-01",
    "name": "Limited sneaker drop",
    "price": 199.0,
    "currency": "USD",
    "stock": 3,
}


def wants_html(request: Request) -> bool:
    """True for browser navigations; XHR/fetch/API callers get JSON."""
    accept = request.headers.get("accept", "")
    if "text/html" not in accept or "application/json" in accept:
        return False
    if request.headers.get("x-requested-with", "").lower() == "xmlhttprequest":
        return False
    return request.headers.get("sec-fetch-dest", "") != "empty"


def _entity(text: str) -> str:
    """HTML-entity encode like Akamai's error pages (``:`` -> ``&#58;``, ``/`` -> ``&#47;``)."""
    return "".join(f"&#{ord(c)};" if c in ":/.# " else html.escape(c) for c in text)


def deny_html(url: str, reference: str) -> str:
    ref = f"Reference #{reference}"
    return (
        "<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD><BODY>\n<H1>Access Denied</H1>\n \n"
        f'You don\'t have permission to access "{_entity(url)}" on this server.<P>\n'
        f"{_entity(ref)}\n<P>https{_entity('://errors.edgesuite.net/' + reference)}\n"
        "</BODY>\n</HTML>\n"
    )


def deny_response(request: Request, reference: str, *, ghost: bool) -> Response:
    resp = HTMLResponse(deny_html(str(request.url), reference), status_code=403)
    if ghost:
        resp.headers["Server"] = "AkamaiGHost"  # MEDIUM: vendor-cited, widely observed
    return resp


def _bits(canary: str, n: int = 4) -> list[int]:
    digest = hashlib.sha256(canary.encode()).digest()
    return list(digest[:n])


def alt_product(canary: str) -> dict[str, Any]:
    """The product with a plausible but wrong price/stock and the hidden canary."""
    a, b, *_ = _bits(canary)
    price = round(PRODUCT["price"] * (1.06 + (a % 15) / 100), 2)
    stock = 1 + b % 2  # 1 or 2, never the real 3
    return {**PRODUCT, "price": price, "stock": stock, "ref": canary}


def hidden_canary_html(canary: str) -> str:
    """A hidden element a scraper that copies raw HTML would carry along."""
    return (
        f'<span hidden aria-hidden="true" data-ref="{html.escape(canary)}" '
        f'style="display:none">{html.escape(canary)}</span>'
    )


def alt_order(order: dict[str, Any], canary: str) -> dict[str, Any]:
    a, _b, *_ = _bits(canary)
    total = round(float(order["total"]) * (1.05 + (a % 10) / 100), 2)
    return {
        **order,
        "total": total,
        "order_id": f"{order['order_id']}-{canary[-4:]}",
        "ref": canary,
    }


def _copy_headers(src: Response, dst: Response) -> None:
    """Copy every header except the body-derived ones, keeping repeated Set-Cookie lines."""
    for k, v in src.raw_headers:
        if k.lower() not in {b"content-length", b"content-type"}:
            dst.raw_headers.append((k, v))


def merge_json(resp: Response, extra: dict[str, Any]) -> Response:
    """Return a JSONResponse equal to ``resp`` with ``extra`` keys added (challenge JSON)."""
    try:
        body = json.loads(bytes(resp.body))
    except (ValueError, AttributeError):
        return resp
    out = JSONResponse({**extra, **body}, status_code=resp.status_code)
    _copy_headers(resp, out)
    return out


def inject_before_body_end(resp: Response, markup: str) -> Response:
    if not markup:
        return resp
    text = bytes(resp.body).decode("utf-8", "replace")
    idx = text.lower().rfind("</body>")
    text = text[:idx] + markup + text[idx:] if idx >= 0 else text + markup
    out = HTMLResponse(text, status_code=resp.status_code)
    _copy_headers(resp, out)
    return out


def slowed(resp: Response, seconds: float, chunks: int) -> Response:
    """Re-emit ``resp`` as a stream spread over ``seconds`` (the ``slow`` action)."""
    body = bytes(resp.body)
    n = max(1, min(chunks, len(body) or 1))
    size = -(-len(body) // n)
    parts = [body[i : i + size] for i in range(0, len(body), size)] or [b""]

    async def gen() -> AsyncIterator[bytes]:
        for i, part in enumerate(parts):
            if i:
                await asyncio.sleep(seconds / max(1, len(parts) - 1))
            yield part

    out = StreamingResponse(gen(), status_code=resp.status_code, media_type=resp.media_type)
    for k, v in resp.headers.items():
        if k.lower() not in {"content-length"}:
            out.headers[k] = v
    return out
