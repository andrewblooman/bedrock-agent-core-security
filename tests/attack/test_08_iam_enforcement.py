"""T08/T09: IAM makes guardrails mandatory, pins the model allowlist and the network perimeter."""

import botocore.exceptions
import pytest

MSG = [{"role": "user", "content": [{"text": "Say hello in one word."}]}]


def _guardrail(out):
    return {"guardrailIdentifier": out["guardrail_id"], "guardrailVersion": out["guardrail_version"]}


def _converse(client, model_id, guardrail=None):
    kwargs = {"modelId": model_id, "messages": MSG, "inferenceConfig": {"maxTokens": 10}}
    if guardrail:
        kwargs["guardrailConfig"] = guardrail
    return client.converse(**kwargs)


def test_invoke_with_approved_guardrail_allowed(probe_session, out):
    client = probe_session.client("bedrock-runtime")
    resp = _converse(client, out["agent_model_id"], _guardrail(out))
    assert resp["output"]["message"]["content"]


def test_invoke_without_guardrail_denied(probe_session, out):
    client = probe_session.client("bedrock-runtime")
    with pytest.raises(botocore.exceptions.ClientError) as err:
        _converse(client, out["agent_model_id"])
    assert err.value.response["Error"]["Code"] == "AccessDeniedException"


def test_non_allowlisted_model_denied(probe_session, out):
    client = probe_session.client("bedrock-runtime")
    with pytest.raises(botocore.exceptions.ClientError) as err:
        _converse(client, "eu.anthropic.claude-sonnet-5-5", _guardrail(out))
    assert err.value.response["Error"]["Code"] == "AccessDeniedException"


def _simulate(session, out, vpce, guardrail_value):
    iam = session.client("iam")
    profile_arn = next(a for a in iam_allowed_resources(out) if ":inference-profile/" in a)
    context = [{"ContextKeyName": "aws:SourceVpce", "ContextKeyValues": [vpce], "ContextKeyType": "string"}]
    if guardrail_value:
        context.append({"ContextKeyName": "bedrock:GuardrailIdentifier", "ContextKeyValues": [guardrail_value], "ContextKeyType": "string"})
    resp = iam.simulate_principal_policy(
        PolicySourceArn=out["agent_role_arn"], ActionNames=["bedrock:InvokeModel"], ResourceArns=[profile_arn], ContextEntries=context
    )
    return resp["EvaluationResults"][0]["EvalDecision"]


def iam_allowed_resources(out):
    account = out["agent_role_arn"].split(":")[4]
    return [f"arn:aws:bedrock:{out['region']}:{account}:inference-profile/{out['agent_model_id']}"]


def test_agent_role_allowed_inside_perimeter(session, out):
    gr = f"{out['guardrail_arn']}:{out['guardrail_version']}"
    assert _simulate(session, out, out["vpce_ids"]["bedrock-runtime"], gr) == "allowed"


def test_agent_role_denied_outside_perimeter(session, out):
    """Stolen runtime credentials replayed from outside the VPC are useless."""
    gr = f"{out['guardrail_arn']}:{out['guardrail_version']}"
    assert _simulate(session, out, "vpce-0123456789abcdef0", gr) == "explicitDeny"


def test_agent_role_denied_without_guardrail(session, out):
    assert _simulate(session, out, out["vpce_ids"]["bedrock-runtime"], None) == "explicitDeny"
