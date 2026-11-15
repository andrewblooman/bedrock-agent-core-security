# Preventive IAM controls for Bedrock model access:
#   1. guardrail_enforcement: deny model invocation unless the request carries
#      our guardrail (bedrock:GuardrailIdentifier), and deny any model outside the
#      allowlist. Attach to every principal that calls models on behalf of users.
#   2. network_perimeter: deny agent data-plane calls that don't arrive through
#      our VPC endpoints, so credentials stolen from the runtime are useless outside it.
#   3. workload_boundary: permissions boundary for every agent-side role; agents
#      can never touch IAM, assume other roles, or change the controls that watch them.
#   4. scp_json: the same guardrail rule as an Organizations SCP, for use outside this account.
#   5. probe role: a test-only role with the enforcement policy attached, which the
#      attack harness assumes to prove the IAM denies work.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition

  invoke_actions = [
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:Converse",
    "bedrock:ConverseStream",
  ]

  # Inference profiles + the foundation models they route to (any region).
  allowed_model_resources = flatten([
    for m in var.allowed_model_ids : startswith(m, "arn:") ? [m] : (
      can(regex("^(eu|us|apac|global|jp|au|ca)\\.", m)) ? [
        "arn:${local.partition}:bedrock:${local.region}:${local.account_id}:inference-profile/${m}",
        "arn:${local.partition}:bedrock:*::foundation-model/${replace(m, "/^[a-z]+\\./", "")}",
        ] : [
        "arn:${local.partition}:bedrock:*::foundation-model/${m}",
      ]
    )
  ])

  guardrail_values = [var.guardrail_arn, "${var.guardrail_arn}:*"]
}

# ---------------------------------------------------------------- 1. guardrail
data "aws_iam_policy_document" "guardrail_enforcement" {
  statement {
    sid       = "DenyInvokeWithoutApprovedGuardrail"
    effect    = "Deny"
    actions   = local.invoke_actions
    resources = ["*"]
    condition {
      test     = "StringNotLike"
      variable = "bedrock:GuardrailIdentifier"
      values   = local.guardrail_values
    }
  }

  statement {
    sid           = "DenyNonAllowlistedModels"
    effect        = "Deny"
    actions       = local.invoke_actions
    not_resources = local.allowed_model_resources
  }

  statement {
    sid    = "DenyGuardrailTampering"
    effect = "Deny"
    actions = [
      "bedrock:CreateGuardrail*",
      "bedrock:UpdateGuardrail",
      "bedrock:DeleteGuardrail",
      "bedrock:PutModelInvocationLoggingConfiguration",
      "bedrock:DeleteModelInvocationLoggingConfiguration",
      "bedrock:PutEnforcedGuardrailConfiguration",
      "bedrock:DeleteEnforcedGuardrailConfiguration",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "guardrail_enforcement" {
  name        = "${var.name_prefix}-bedrock-guardrail-enforcement"
  description = "Deny Bedrock model invocation without the approved guardrail or outside the model allowlist"
  policy      = data.aws_iam_policy_document.guardrail_enforcement.json
  tags        = var.tags
}

# --------------------------------------------------------- 2. network perimeter
data "aws_iam_policy_document" "network_perimeter" {
  statement {
    sid    = "DenyAgentDataPlaneOutsideVpce"
    effect = "Deny"
    actions = concat(local.invoke_actions, [
      "bedrock:ApplyGuardrail",
      "bedrock:Retrieve",
      "bedrock:RetrieveAndGenerate",
      "bedrock-agentcore:InvokeGateway",
      "bedrock-agentcore:CreateEvent",
      "bedrock-agentcore:ListEvents",
      "bedrock-agentcore:GetEvent",
      "bedrock-agentcore:RetrieveMemoryRecords",
    ])
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpce"
      values   = var.allowed_vpce_ids
    }
    condition {
      test     = "BoolIfExists"
      variable = "aws:ViaAWSService"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "network_perimeter" {
  name        = "${var.name_prefix}-agent-network-perimeter"
  description = "Deny agent data-plane calls that do not traverse the bedrock-guard VPC endpoints"
  policy      = data.aws_iam_policy_document.network_perimeter.json
  tags        = var.tags
}

# ------------------------------------------------------- 3. permissions boundary
data "aws_iam_policy_document" "boundary" {
  statement {
    sid    = "AllowedServiceSurface"
    effect = "Allow"
    actions = [
      "bedrock:*",
      "bedrock-agentcore:*",
      "s3vectors:*",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:ListBucket",
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
      "logs:DescribeLogGroups",
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
      "xray:GetSamplingRules",
      "xray:GetSamplingTargets",
      "cloudwatch:PutMetricData",
      "lambda:InvokeFunction",
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcs",
      "ec2:DeleteNetworkInterface",
      "ec2:AssignPrivateIpAddresses",
      "ec2:UnassignPrivateIpAddresses",
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "NoIdentityOrOrgChanges"
    effect    = "Deny"
    actions   = ["iam:*", "organizations:*", "account:*", "sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:GetFederationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "NoControlTampering"
    effect = "Deny"
    actions = [
      "bedrock:CreateGuardrail*",
      "bedrock:UpdateGuardrail",
      "bedrock:DeleteGuardrail",
      "bedrock:PutModelInvocationLoggingConfiguration",
      "bedrock:DeleteModelInvocationLoggingConfiguration",
      "bedrock:DeleteKnowledgeBase",
      "bedrock:UpdateKnowledgeBase",
      "bedrock-agentcore:CreateAgentRuntime*",
      "bedrock-agentcore:UpdateAgentRuntime*",
      "bedrock-agentcore:DeleteAgentRuntime*",
      "bedrock-agentcore:CreateGateway*",
      "bedrock-agentcore:UpdateGateway*",
      "bedrock-agentcore:DeleteGateway*",
      "bedrock-agentcore:CreatePolicy*",
      "bedrock-agentcore:UpdatePolicy*",
      "bedrock-agentcore:DeletePolicy*",
      "bedrock-agentcore:CreateMemory",
      "bedrock-agentcore:UpdateMemory",
      "bedrock-agentcore:DeleteMemory",
      "bedrock-agentcore:PutResourcePolicy",
      "bedrock-agentcore:DeleteResourcePolicy",
      "logs:DeleteLogGroup",
      "logs:DeleteLogStream",
      "logs:PutRetentionPolicy",
      "logs:DeleteMetricFilter",
      "logs:DisassociateKmsKey",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "boundary" {
  name        = "${var.name_prefix}-agent-workload-boundary"
  description = "Permissions boundary for all bedrock-guard agent-side roles"
  policy      = data.aws_iam_policy_document.boundary.json
  tags        = var.tags
}

# ------------------------------------------------------------------- 4. SCP
data "aws_iam_policy_document" "scp" {
  statement {
    sid       = "DenyBedrockInvokeWithoutGuardrail"
    effect    = "Deny"
    actions   = local.invoke_actions
    resources = ["*"]
    condition {
      test     = "StringNotLike"
      variable = "bedrock:GuardrailIdentifier"
      values   = ["arn:${local.partition}:bedrock:*:*:guardrail/*"]
    }
    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:${local.partition}:iam::*:role/${var.scp_breakglass_role_name}"]
    }
  }
}

# ----------------------------------------------------------------- 5. probe
data "aws_iam_policy_document" "probe_assume" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.arn]
    }
  }
}

resource "aws_iam_role" "probe" {
  name                 = "${var.name_prefix}-control-probe"
  description          = "TEST ONLY: assumed by tests/attack to verify IAM and Cedar denies"
  assume_role_policy   = data.aws_iam_policy_document.probe_assume.json
  permissions_boundary = aws_iam_policy.boundary.arn
  max_session_duration = 3600
  tags                 = var.tags
}

data "aws_iam_policy_document" "probe" {
  # Deliberately broad allow so that only the enforcement policy's denies decide.
  statement {
    actions   = concat(local.invoke_actions, ["bedrock:ApplyGuardrail", "bedrock:GetGuardrail"])
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "probe" {
  name   = "broad-invoke"
  role   = aws_iam_role.probe.id
  policy = data.aws_iam_policy_document.probe.json
}

resource "aws_iam_role_policy_attachment" "probe_enforcement" {
  role       = aws_iam_role.probe.name
  policy_arn = aws_iam_policy.guardrail_enforcement.arn
}
