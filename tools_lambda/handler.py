"""AgentCore Gateway tool target for the bedrock-guard demo.

Tools:
  lookup_order(order_id)  - returns order status. The data includes PII, so the
                            output guardrail has something to anonymize.
  read_document(path)     - returns a document under docs/public/. This is the
                            deliberately "dangerous" capability: a file read
                            whose argument the model controls.

Defence in depth for read_document:
  1. The gateway's Cedar policy only permits paths like "public/*" and forbids "..".
  2. This handler canonicalises the path and refuses anything outside docs/public,
     whatever the policy says.
  3. Every refusal emits a structured SECURITY event, which a metric filter turns
     into an alarm.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

DOCS_ROOT = (Path(__file__).parent / "docs").resolve()
PUBLIC_ROOT = (DOCS_ROOT / "public").resolve()
ORDER_ID_RE = re.compile(r"^ORD-\d{6}$")
MAX_PATH_LEN = 128

ORDERS: dict[str, dict[str, Any]] = {
    "ORD-100001": {"status": "shipped", "carrier": "DHL", "eta": "2026-11-18"},
    "ORD-100002": {
        "status": "delayed",
        "eta": "2026-11-25",
        "customer_email": "jane.doe@example.com",
        "customer_phone": "+44 7700 900123",
    },
}


def _security_event(kind: str, **fields: Any) -> None:
    LOG.warning(json.dumps({"event": "SECURITY", "kind": kind, **fields}))


def _tool_name(context: Any) -> str:
    custom = getattr(getattr(context, "client_context", None), "custom", None) or {}
    full = custom.get("bedrockAgentCoreToolName", "")
    # "<target>___<tool>" -> "<tool>"
    return full.split("___", 1)[-1]


def lookup_order(args: dict[str, Any]) -> dict[str, Any]:
    order_id = str(args.get("order_id", ""))
    if not ORDER_ID_RE.fullmatch(order_id):
        _security_event("invalid_input", tool="lookup_order", detail="order_id format")
        return {"error": "order_id must look like ORD-123456"}
    order = ORDERS.get(order_id)
    return {"order_id": order_id, **order} if order else {"error": "order not found"}


def read_document(args: dict[str, Any]) -> dict[str, Any]:
    raw = str(args.get("path", ""))
    if not raw or len(raw) > MAX_PATH_LEN or "\x00" in raw:
        _security_event("invalid_input", tool="read_document", path=raw[:MAX_PATH_LEN])
        return {"error": "invalid path"}

    candidate = (DOCS_ROOT / raw).resolve()
    if not candidate.is_relative_to(PUBLIC_ROOT) or candidate.suffix != ".md":
        _security_event("path_traversal_blocked", tool="read_document", path=raw)
        return {"error": "access denied: only public/*.md documents are readable"}
    if not candidate.is_file():
        return {"error": "document not found"}
    return {"path": raw, "content": candidate.read_text(encoding="utf-8")[:4000]}


TOOLS = {"lookup_order": lookup_order, "read_document": read_document}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    name = _tool_name(context)
    fn = TOOLS.get(name)
    if fn is None:
        _security_event("unknown_tool", tool=name)
        return {"error": f"unknown tool {name!r}"}
    result = fn(event if isinstance(event, dict) else {})
    LOG.info(
        json.dumps(
            {
                "event": "TOOL_CALL",
                "tool": name,
                "ok": "error" not in result,
                "request_id": getattr(context, "aws_request_id", os.getenv("AWS_REQUEST_ID", "")),
            }
        )
    )
    return result
