# Detection and response for the Bedrock / AgentCore estate.
#   CloudTrail: management events plus Bedrock/AgentCore/S3 data events, sent to
#               S3 and CloudWatch Logs
#   Metric filters + alarms over CloudTrail, model invocation logs, the agent
#               audit log and the tool Lambda logs
#   EventBridge: control-tamper and GuardDuty findings, both to SNS
#   GuardDuty and Security Hub (optional, account-level singletons)

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  ns         = "BedrockGuard"
  trail_name = "${var.name_prefix}-trail"
  trail_arn  = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}

# ================================================================ alerting
resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-security-alerts"
  kms_master_key_id = var.logs_kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "alerts" {
  statement {
    sid       = "AllowAlarmAndEventPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ============================================================== CloudTrail
resource "aws_s3_bucket" "trail" {
  bucket_prefix = "${var.name_prefix}-cloudtrail-"
  force_destroy = var.force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.logs_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = var.trail_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket     = aws_s3_bucket.trail.id
  policy     = data.aws_iam_policy_document.trail_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.trail]
}

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/${var.name_prefix}/cloudtrail"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "trail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_iam_role" "trail" {
  name               = "${var.name_prefix}-cloudtrail-to-cwl"
  assume_role_policy = data.aws_iam_policy_document.trail_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "trail_cwl" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "trail" {
  name   = "deliver-to-cwl"
  role   = aws_iam_role.trail.id
  policy = data.aws_iam_policy_document.trail_cwl.json
}

resource "aws_cloudtrail" "this" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  kms_key_id                    = var.logs_kms_key_arn
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail.arn

  advanced_event_selector {
    name = "Management events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  dynamic "advanced_event_selector" {
    for_each = toset(var.data_event_resource_types)
    content {
      name = "Data events ${advanced_event_selector.value}"
      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }
      field_selector {
        field  = "resources.type"
        equals = [advanced_event_selector.value]
      }
    }
  }

  dynamic "advanced_event_selector" {
    for_each = length(var.s3_data_event_bucket_arns) > 0 ? [1] : []
    content {
      name = "S3 data events for sensitive buckets"
      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }
      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }
      field_selector {
        field       = "resources.ARN"
        starts_with = [for b in var.s3_data_event_bucket_arns : "${b}/"]
      }
    }
  }

  tags       = var.tags
  depends_on = [aws_s3_bucket_policy.trail, aws_iam_role_policy.trail]
}

# ======================================================== metric filters
locals {
  # name => { log_group, pattern, threshold, description }
  detections = merge(
    {
      AgentPrincipalAccessDenied = {
        log_group   = aws_cloudwatch_log_group.trail.name
        pattern     = "{ ($.errorCode = \"AccessDenied*\" || $.errorCode = \"*UnauthorizedOperation\" || $.errorCode = \"*AccessDeniedException\") && $.userIdentity.sessionContext.sessionIssuer.userName = \"${var.name_prefix}-*\" }"
        threshold   = 1
        description = "An agent-side role was denied an AWS action (possible tool abuse, injection-driven privilege probing or stolen credentials)."
      }
      BedrockInvokeOutsideVpce = {
        log_group   = aws_cloudwatch_log_group.trail.name
        pattern     = "{ $.eventSource = \"bedrock.amazonaws.com\" && $.userIdentity.sessionContext.sessionIssuer.userName = \"${var.agent_role_name}\" && $.vpcEndpointId NOT EXISTS }"
        threshold   = 1
        description = "Agent role credentials used against Bedrock without traversing the VPC endpoint."
      }
      ControlPlaneChangeByAgentRole = {
        log_group   = aws_cloudwatch_log_group.trail.name
        pattern     = "{ ($.eventSource = \"bedrock.amazonaws.com\" || $.eventSource = \"bedrock-agentcore.amazonaws.com\" || $.eventSource = \"iam.amazonaws.com\") && $.readOnly IS FALSE && $.managementEvent IS TRUE && $.userIdentity.sessionContext.sessionIssuer.userName = \"${var.name_prefix}-*\" }"
        threshold   = 1
        description = "An agent-side role attempted a control-plane write."
      }
      GuardrailIntervenedInvocation = {
        log_group   = var.invocation_log_group_name
        pattern     = "{ $.output.outputBodyJson.stopReason = \"guardrail_intervened\" }"
        threshold   = var.guardrail_intervention_threshold
        description = "Bedrock guardrail interventions on model invocations exceeded threshold (possible attack campaign)."
      }
      CanaryInModelTraffic = {
        log_group   = var.invocation_log_group_name
        pattern     = "\"BGCANARY\""
        threshold   = 1
        description = "Canary secret reached model traffic: KB screening failed or someone is pasting secrets into the model."
      }
      AgentGuardrailBlock = {
        log_group   = var.audit_log_group_name
        pattern     = "{ $.event = \"guardrail_intervened\" }"
        threshold   = var.guardrail_intervention_threshold
        description = "Agent audit: guardrail blocked agent input/output."
      }
      KbChunkQuarantined = {
        log_group   = var.audit_log_group_name
        pattern     = "{ $.event = \"kb_chunk_blocked\" }"
        threshold   = 1
        description = "Retrieved KB content failed guardrail screening (indirect prompt injection or sensitive data in corpus)."
      }
      CanaryInAgentResponse = {
        log_group   = var.audit_log_group_name
        pattern     = "{ $.event = \"canary_detected\" }"
        threshold   = 1
        description = "Agent response contained canary material and was suppressed by the last-line filter."
      }
      ToolSecurityEvent = {
        log_group   = var.tools_log_group_name
        pattern     = "\"SECURITY\""
        threshold   = 1
        description = "Gateway tool rejected a malicious or malformed call (e.g. path traversal)."
      }
    },
    var.extra_detections,
  )
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each       = local.detections
  name           = "${var.name_prefix}-${each.key}"
  log_group_name = each.value.log_group
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.key
    namespace     = local.ns
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each            = local.detections
  alarm_name          = "${var.name_prefix}-${each.key}"
  alarm_description   = each.value.description
  namespace           = local.ns
  metric_name         = each.key
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  tags                = var.tags
  depends_on          = [aws_cloudwatch_log_metric_filter.this]
}

# ============================================================ EventBridge
resource "aws_cloudwatch_event_rule" "ai_control_tamper" {
  name        = "${var.name_prefix}-ai-control-tamper"
  description = "Changes to Bedrock guardrails/logging/KBs and AgentCore runtimes/gateways/policies"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["bedrock.amazonaws.com", "bedrock-agentcore.amazonaws.com"]
      eventName = [
        { prefix = "Delete" },
        { prefix = "Update" },
        { prefix = "Put" },
        { prefix = "Create" },
      ]
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "audit_tamper" {
  name        = "${var.name_prefix}-audit-tamper"
  description = "Attempts to blind detection: CloudTrail, GuardDuty, log groups, metric filters, KMS keys"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
        "DeleteDetector", "UpdateDetector", "DisassociateFromMasterAccount",
        "DeleteLogGroup", "DeleteMetricFilter", "PutRetentionPolicy", "DisassociateKmsKey",
        "DeleteAlarms", "DisableAlarmActions",
        "ScheduleKeyDeletion", "DisableKey",
        "DeleteModelInvocationLoggingConfiguration",
      ]
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${var.name_prefix}-guardduty-findings"
  description = "GuardDuty findings severity >= 4"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail        = { severity = [{ numeric = [">=", 4] }] }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "ai_control_tamper" {
  rule = aws_cloudwatch_event_rule.ai_control_tamper.name
  arn  = aws_sns_topic.alerts.arn
  input_transformer {
    input_paths = {
      event  = "$.detail.eventName"
      source = "$.detail.eventSource"
      actor  = "$.detail.userIdentity.arn"
      time   = "$.time"
    }
    input_template = "\"[bedrock-guard] AI control change: <event> on <source> by <actor> at <time>\""
  }
}

resource "aws_cloudwatch_event_target" "audit_tamper" {
  rule = aws_cloudwatch_event_rule.audit_tamper.name
  arn  = aws_sns_topic.alerts.arn
  input_transformer {
    input_paths = {
      event = "$.detail.eventName"
      actor = "$.detail.userIdentity.arn"
      time  = "$.time"
    }
    input_template = "\"[bedrock-guard] AUDIT TAMPER: <event> by <actor> at <time>\""
  }
}

resource "aws_cloudwatch_event_target" "guardduty" {
  rule = aws_cloudwatch_event_rule.guardduty.name
  arn  = aws_sns_topic.alerts.arn
}

# ======================================================= GuardDuty / SecHub
resource "aws_guardduty_detector" "this" {
  count                        = var.enable_guardduty ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = var.tags
}

resource "aws_guardduty_detector_feature" "this" {
  for_each    = var.enable_guardduty ? toset(["S3_DATA_EVENTS", "LAMBDA_NETWORK_LOGS"]) : toset([])
  detector_id = aws_guardduty_detector.this[0].id
  name        = each.value
  status      = "ENABLED"
}

resource "aws_securityhub_account" "this" {
  count                    = var.enable_security_hub ? 1 : 0
  enable_default_standards = false
  auto_enable_controls     = true
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:${local.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}
