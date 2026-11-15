"""Shared fixtures for the bedrock-guard attack harness.

The harness drives the *deployed* dev stack. Outputs come from
`terraform -chdir=terraform/envs/dev output -json` (cached in outputs.json).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.parse
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import boto3
import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "agent"))
from sigv4_auth import SigV4HttpxAuth  # noqa: E402

BLOCK_MARKER = "blocked by"
CANARY = "BGCANARY"


def _load_outputs() -> dict[str, Any]:
    cache = ROOT / "outputs.json"
    if not cache.exists():
        raw = subprocess.run(
            ["terraform", f"-chdir={ROOT / 'terraform/envs/dev'}", "output", "-json"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        cache.write_text(raw)
        cache.chmod(0o600)
    return {k: v["value"] for k, v in json.loads(cache.read_text()).items()}


@pytest.fixture(scope="session")
def out() -> dict[str, Any]:
    return _load_outputs()


@pytest.fixture(scope="session")
def session(out: dict[str, Any]) -> boto3.session.Session:
    return boto3.session.Session(region_name=out["region"])


@pytest.fixture(scope="session")
def probe_session(out: dict[str, Any], session: boto3.session.Session) -> boto3.session.Session:
    creds = session.client("sts").assume_role(RoleArn=out["probe_role_arn"], RoleSessionName="bg-attack-harness")["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=out["region"],
    )


def fetch_token(out: dict[str, Any], client_id: str, client_secret: str) -> str:
    resp = httpx.post(
        out["cognito_token_endpoint"],
        data={"grant_type": "client_credentials", "scope": out["cognito_scope"]},
        auth=(client_id, client_secret),
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


@pytest.fixture(scope="session")
def trusted_token(out: dict[str, Any]) -> str:
    return fetch_token(out, out["trusted_client_id"], out["trusted_client_secret"])


@pytest.fixture(scope="session")
def untrusted_token(out: dict[str, Any]) -> str:
    return fetch_token(out, out["untrusted_client_id"], out["untrusted_client_secret"])


@dataclass
class AgentReply:
    status: int
    body: dict[str, Any]
    raw: str

    @property
    def text(self) -> str:
        return str(self.body.get("response", self.raw))

    @property
    def blocked(self) -> bool:
        return bool(self.body.get("guardrail_intervened")) or BLOCK_MARKER in self.text


def runtime_url(out: dict[str, Any]) -> str:
    arn = urllib.parse.quote(out["agent_runtime_arn"], safe="")
    return f"https://bedrock-agentcore.{out['region']}.amazonaws.com/runtimes/{arn}/invocations?qualifier=DEFAULT"


@pytest.fixture(scope="session")
def invoke(out: dict[str, Any], trusted_token: str) -> Callable[..., AgentReply]:
    def _invoke(prompt: str, *, token: str | None = trusted_token, session_id: str | None = None) -> AgentReply:
        headers = {
            "Content-Type": "application/json",
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id or f"bg-test-{uuid.uuid4()}",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = httpx.post(runtime_url(out), json={"prompt": prompt}, headers=headers, timeout=180)
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if isinstance(body, str):
            body = {"response": body}
        return AgentReply(resp.status_code, body if isinstance(body, dict) else {}, resp.text)

    return _invoke


@pytest.fixture(scope="session")
def start_ms() -> int:
    return int(time.time() * 1000) - 5_000


def poll_logs(session: boto3.session.Session, group: str, pattern: str, since_ms: int, timeout_s: int = 120) -> list[str]:
    """Poll CloudWatch Logs until `pattern` matches at least one event."""
    logs = session.client("logs")
    deadline = time.time() + timeout_s
    while True:
        events = logs.filter_log_events(logGroupName=group, filterPattern=pattern, startTime=since_ms).get("events", [])
        if events or time.time() > deadline:
            return [e["message"] for e in events]
        time.sleep(10)


def metric_sum(session: boto3.session.Session, metric: str, since_ms: int) -> float:
    cw = session.client("cloudwatch")
    resp = cw.get_metric_statistics(
        Namespace="BedrockGuard",
        MetricName=metric,
        StartTime=since_ms / 1000,
        EndTime=time.time() + 60,
        Period=60,
        Statistics=["Sum"],
    )
    return sum(dp["Sum"] for dp in resp["Datapoints"])


def poll_metric(session: boto3.session.Session, metric: str, since_ms: int, timeout_s: int = 300) -> float:
    deadline = time.time() + timeout_s
    while True:
        total = metric_sum(session, metric, since_ms)
        if total > 0 or time.time() > deadline:
            return total
        time.sleep(20)


def mcp_call(url: str, auth: httpx.Auth, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Minimal MCP JSON-RPC over streamable HTTP (handles JSON or SSE replies)."""
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    with httpx.Client(auth=auth, timeout=30) as client:
        init = client.post(
            url,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "bg-attack", "version": "1"}},
            },
        )
        if init.status_code >= 400:
            return {"http_status": init.status_code, "body": init.text}
        if sid := init.headers.get("mcp-session-id"):
            headers["Mcp-Session-Id"] = sid
        resp = client.post(url, headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
        if resp.status_code >= 400:
            return {"http_status": resp.status_code, "body": resp.text}
        text = resp.text
        if resp.headers.get("content-type", "").startswith("text/event-stream"):
            data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
            text = data[-1] if data else "{}"
        return json.loads(text)


@pytest.fixture(scope="session")
def probe_gateway(out: dict[str, Any], probe_session: boto3.session.Session) -> Callable[..., dict[str, Any]]:
    auth = SigV4HttpxAuth(probe_session, out["region"])
    target = out["gateway_target_name"]

    def _call(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return mcp_call(out["gateway_url"], auth, "tools/call", {"name": f"{target}___{tool}", "arguments": arguments})

    return _call


def is_mcp_error(result: dict[str, Any]) -> bool:
    if "error" in result or result.get("http_status", 200) >= 400:
        return True
    res = result.get("result", {})
    if res.get("isError"):
        return True
    content = json.dumps(res.get("content", []))
    return "error" in content.lower() and "denied" in content.lower()


def assume_env_flag(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes"}
