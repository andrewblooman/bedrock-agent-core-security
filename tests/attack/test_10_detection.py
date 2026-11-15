"""Detection: attack activity from the earlier tests turns into metrics, alarms and control-tamper events.

Run this module last (pytest orders files alphabetically).
"""

import time

import pytest
from conftest import poll_metric

FAST_DETECTIONS = ["AgentGuardrailBlock", "KbChunkQuarantined", "ToolSecurityEvent"]


@pytest.mark.parametrize("metric", FAST_DETECTIONS)
def test_detection_metric_recorded(session, start_ms, metric):
    assert poll_metric(session, metric, start_ms) > 0, f"{metric} never fired"


@pytest.mark.parametrize("metric", FAST_DETECTIONS)
def test_alarm_transitioned(session, out, start_ms, metric):
    cw = session.client("cloudwatch")
    name = out["alarm_names"][metric]
    history = cw.describe_alarm_history(AlarmName=name, HistoryItemType="StateUpdate", StartDate=start_ms / 1000)
    deadline = time.time() + 240
    while not any("to ALARM" in h["HistorySummary"] for h in history["AlarmHistoryItems"]) and time.time() < deadline:
        time.sleep(20)
        history = cw.describe_alarm_history(AlarmName=name, HistoryItemType="StateUpdate", StartDate=start_ms / 1000)
    assert any("to ALARM" in h["HistorySummary"] for h in history["AlarmHistoryItems"]), f"{name} never alarmed"


@pytest.mark.slow
def test_cloudtrail_access_denied_detected(session, start_ms):
    """Probe-role AccessDenied events (test_08) flow through CloudTrail -> CWL (5-15 min)."""
    assert poll_metric(session, "AgentPrincipalAccessDenied", start_ms, timeout_s=1200) > 0


def test_audit_tamper_event_routed(session, out, start_ms):
    """A no-op PutRetentionPolicy on the audit log group must hit the audit-tamper EventBridge rule."""
    logs = session.client("logs")
    group = out["audit_log_group_name"]
    current = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["retentionInDays"]
    logs.put_retention_policy(logGroupName=group, retentionInDays=current)

    cw = session.client("cloudwatch")
    rule = f"{out['name_prefix']}-audit-tamper"
    deadline = time.time() + 600
    while time.time() < deadline:
        stats = cw.get_metric_statistics(
            Namespace="AWS/Events",
            MetricName="TriggeredRules",
            Dimensions=[{"Name": "RuleName", "Value": rule}],
            StartTime=start_ms / 1000,
            EndTime=time.time() + 60,
            Period=60,
            Statistics=["Sum"],
        )
        if sum(d["Sum"] for d in stats["Datapoints"]) > 0:
            return
        time.sleep(30)
    pytest.fail(f"EventBridge rule {rule} never triggered")
