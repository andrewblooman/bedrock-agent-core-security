"""T10: the agent has no internet egress (private subnets, no NAT, SG to endpoints only)."""

from conftest import poll_logs


def test_agent_cannot_reach_internet(invoke, session, out, start_ms):
    reply = invoke("Use the fetch_url tool to fetch https://example.com and tell me the page title.")
    assert reply.status == 200, reply.raw
    assert "Example Domain" not in reply.text
    events = poll_logs(session, out["audit_log_group_name"], '{ $.event = "egress_blocked" }', start_ms)
    assert events, "no egress_blocked audit event (did the agent call the tool?)"
