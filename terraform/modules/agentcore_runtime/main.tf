# AgentCore Runtime hosting the Strands agent (direct code deployment, Python 3.14).
#   - VPC network mode: ENIs sit in private subnets with no internet route.
#   - Inbound auth: Cognito JWT pinned to one client ID. SigV4 callers are rejected.
#   - Execution role: least privilege, permissions boundary, a guardrail-required
#     IAM deny and a VPC-endpoint network perimeter.
#   - Code artifact: SSE-KMS bucket, versioned, readable only by the deployer
#     and the runtime role.
#   - Security audit events: written by the agent to a dedicated KMS-encrypted
#     log group that the detection module watches.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  role_name  = "${var.name_prefix}-agent-runtime"
  code_key   = "agent/${filemd5(var.agent_zip_path)}.zip"
}

# ------------------------------------------------------------ audit log group
resource "aws_cloudwatch_log_group" "audit" {
  name              = "/${var.name_prefix}/agent-audit"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags
}

# ------------------------------------------------------------- code bucket
resource "aws_s3_bucket" "code" {
  bucket_prefix = "${var.name_prefix}-agent-code-"
  force_destroy = var.force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "code" {
  bucket                  = aws_s3_bucket.code.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "code" {
  bucket = aws_s3_bucket.code.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "code" {
  bucket = aws_s3_bucket.code.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "code" {
  bucket = aws_s3_bucket.code.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.data_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "code_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.code.arn, "${aws_s3_bucket.code.arn}/*"]
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
  # Integrity: only deployers may write agent code.
  statement {
    sid       = "DenyWriteExceptDeployers"
    effect    = "Deny"
    actions   = ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.code.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = var.admin_principal_arns
    }
  }
}

resource "aws_s3_bucket_policy" "code" {
  bucket     = aws_s3_bucket.code.id
  policy     = data.aws_iam_policy_document.code_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.code]
}

resource "aws_s3_object" "agent" {
  bucket      = aws_s3_bucket.code.id
  key         = local.code_key
  source      = var.agent_zip_path
  source_hash = filemd5(var.agent_zip_path)
  depends_on  = [aws_s3_bucket_server_side_encryption_configuration.code, aws_s3_bucket_policy.code]
}

# --------------------------------------------------------- execution role
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:bedrock-agentcore:${local.region}:${local.account_id}:*"]
    }
  }
}

resource "aws_iam_role" "runtime" {
  name                 = local.role_name
  assume_role_policy   = data.aws_iam_policy_document.assume.json
  permissions_boundary = var.permissions_boundary_arn
  max_session_duration = 3600
  tags                 = var.tags
}

data "aws_iam_policy_document" "runtime" {
  statement {
    sid       = "InvokeAllowlistedModels"
    actions   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
    resources = var.allowed_model_resources
  }
  statement {
    sid       = "ApplyGuardrail"
    actions   = ["bedrock:ApplyGuardrail"]
    resources = [var.guardrail_arn, "${var.guardrail_arn}:*", "arn:${local.partition}:bedrock:*:${local.account_id}:guardrail-profile/*"]
  }
  statement {
    sid       = "RetrieveFromKnowledgeBase"
    actions   = ["bedrock:Retrieve"]
    resources = [var.knowledge_base_arn]
  }
  statement {
    sid       = "ShortTermMemory"
    actions   = ["bedrock-agentcore:CreateEvent", "bedrock-agentcore:ListEvents", "bedrock-agentcore:GetEvent"]
    resources = [var.memory_arn]
  }
  statement {
    sid     = "WorkloadIdentity"
    actions = ["bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetWorkloadAccessTokenForJWT", "bedrock-agentcore:GetWorkloadAccessTokenForUserId"]
    resources = [
      "arn:${local.partition}:bedrock-agentcore:${local.region}:${local.account_id}:workload-identity-directory/default",
      "arn:${local.partition}:bedrock-agentcore:${local.region}:${local.account_id}:workload-identity-directory/default/workload-identity/*",
    ]
  }
  statement {
    sid       = "RuntimeLogs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/bedrock-agentcore/runtimes/*"]
  }
  statement {
    sid       = "AuditLog"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.audit.arn}:*"]
  }
  statement {
    sid       = "DescribeLogGroups"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:*"]
  }
  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
    resources = ["*"]
  }
  statement {
    sid       = "Metrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["bedrock-agentcore"]
    }
  }
  statement {
    sid       = "DataKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.data_kms_key_arn]
  }
}

resource "aws_iam_role_policy" "runtime" {
  name   = "agent-least-privilege"
  role   = aws_iam_role.runtime.id
  policy = data.aws_iam_policy_document.runtime.json
}

resource "aws_iam_role_policy_attachment" "guardrail_enforcement" {
  role       = aws_iam_role.runtime.name
  policy_arn = var.guardrail_enforcement_policy_arn
}

resource "aws_iam_role_policy_attachment" "network_perimeter" {
  count      = var.enforce_network_perimeter ? 1 : 0
  role       = aws_iam_role.runtime.name
  policy_arn = var.network_perimeter_policy_arn
}

# ------------------------------------------------------------------ runtime
resource "aws_bedrockagentcore_agent_runtime" "this" {
  agent_runtime_name = replace("${var.name_prefix}_agent", "-", "_")
  description        = "bedrock-guard Strands support agent"
  role_arn           = aws_iam_role.runtime.arn

  agent_runtime_artifact {
    code_configuration {
      entry_point = ["app.py"]
      runtime     = "PYTHON_3_14"
      code {
        s3 {
          bucket     = aws_s3_bucket.code.id
          prefix     = aws_s3_object.agent.key
          version_id = aws_s3_object.agent.version_id
        }
      }
    }
  }

  network_configuration {
    network_mode = "VPC"
    network_mode_config {
      subnets         = var.subnet_ids
      security_groups = [var.security_group_id]
    }
  }

  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url   = var.jwt_discovery_url
      allowed_clients = var.jwt_allowed_clients
    }
  }

  request_header_configuration {
    request_header_allowlist = ["Authorization"]
  }

  protocol_configuration {
    server_protocol = "HTTP"
  }

  lifecycle_configuration = [{
    idle_runtime_session_timeout = 300
    max_lifetime                 = 3600
  }]

  environment_variables = merge({
    BG_REGION            = local.region
    BG_MODEL_ID          = var.model_id
    BG_GUARDRAIL_ID      = var.guardrail_id
    BG_GUARDRAIL_VERSION = var.guardrail_version
    BG_KB_ID             = var.knowledge_base_id
    BG_MEMORY_ID         = var.memory_id
    BG_GATEWAY_URL       = var.gateway_url
    BG_AUDIT_LOG_GROUP   = aws_cloudwatch_log_group.audit.name
  }, var.extra_environment)

  tags = var.tags
  depends_on = [
    aws_iam_role_policy.runtime,
    aws_iam_role_policy_attachment.guardrail_enforcement,
    aws_iam_role_policy_attachment.network_perimeter,
  ]
}
