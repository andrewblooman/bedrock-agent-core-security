"""T07: inbound authentication on the AgentCore Runtime (Cognito JWT, client pinning)."""

import botocore.exceptions
import pytest


def test_baseline_trusted_client_is_served(invoke):
    reply = invoke("How long does standard UK shipping take?")
    assert reply.status == 200, reply.raw
    assert not reply.blocked, reply.text
    assert "3" in reply.text and "5" in reply.text, reply.text


def test_missing_token_rejected(invoke):
    assert invoke("hello", token=None).status in (401, 403)


def test_forged_token_rejected(invoke):
    forged = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciIsImNsaWVudF9pZCI6ImV2aWwifQ.c2lnbmF0dXJl"
    assert invoke("hello", token=forged).status in (401, 403)


def test_same_issuer_untrusted_client_rejected(invoke, untrusted_token):
    """Valid signature from our own user pool, but client not in allowed_clients."""
    assert invoke("hello", token=untrusted_token).status in (401, 403)


def test_sigv4_caller_rejected_on_jwt_runtime(session, out):
    """Even an account admin can't bypass the JWT authorizer with IAM credentials."""
    client = session.client("bedrock-agentcore")
    with pytest.raises(botocore.exceptions.ClientError) as err:
        client.invoke_agent_runtime(
            agentRuntimeArn=out["agent_runtime_arn"],
            qualifier="DEFAULT",
            runtimeSessionId="bg-test-sigv4-" + "x" * 30,
            payload=b'{"prompt": "hello"}',
        )
    assert err.value.response["Error"]["Code"] in {"AccessDeniedException", "ValidationException", "UnauthorizedException"}
