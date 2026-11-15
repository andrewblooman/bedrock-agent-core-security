# AgentCore Gateway: the only route from the agent to business tools.
#   - AWS_IAM inbound auth (SigV4). The agent uses its role and holds no secrets.
#   - Resource policy: only named principals may call InvokeGateway.
#   - Cedar policy engine in ENFORCE mode: default deny, per-tool permits
#     with input constraints, and an explicit forbid on path traversal.
#   - Gateway encrypted with the data CMK.
#   - Tool Lambda runs in private subnets with no egress, under a boundary.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.region
  partition   = data.aws_partition.current.partition
  target_name = "acmetools"

  # IAM principals as AgentCore Policy sees them (session name stripped).
  agent_principal = "arn:${local.partition}:sts::${local.account_id}:assumed-role/${var.agent_role_name}"
  probe_principal = "arn:${local.partition}:sts::${local.account_id}:assumed-role/${var.probe_role_name}"
}

# ------------------------------------------------------------ tool Lambda
data "archive_file" "tools" {
  type        = "zip"
  source_dir  = var.tools_source_dir
  output_path = "${path.root}/build/tools_lambda.zip"
  excludes    = ["__pycache__"]
}

resource "aws_cloudwatch_log_group" "tools" {
  name              = "/aws/lambda/${var.name_prefix}-gateway-tools"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "tools" {
  name                 = "${var.name_prefix}-gateway-tools-lambda"
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume.json
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags
}

data "aws_iam_policy_document" "tools" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.tools.arn}:*"]
  }
  statement {
    # VPC ENI management required for VPC-attached Lambda.
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSubnets",
      "ec2:DeleteNetworkInterface",
      "ec2:AssignPrivateIpAddresses",
      "ec2:UnassignPrivateIpAddresses",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "tools" {
  name   = "tools-runtime"
  role   = aws_iam_role.tools.id
  policy = data.aws_iam_policy_document.tools.json
}

resource "aws_lambda_function" "tools" {
  function_name    = "${var.name_prefix}-gateway-tools"
  role             = aws_iam_role.tools.arn
  runtime          = "python3.14"
  architectures    = ["arm64"]
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.tools.output_path
  source_code_hash = data.archive_file.tools.output_base64sha256
  timeout          = 10
  memory_size      = 256
  kms_key_arn      = var.data_kms_key_arn

  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [var.security_group_id]
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.tools.name
  }

  tracing_config {
    mode = "Active"
  }

  tags       = var.tags
  depends_on = [aws_iam_role_policy.tools]
}

# ---------------------------------------------------------- gateway role
data "aws_iam_policy_document" "gateway_assume" {
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

resource "aws_iam_role" "gateway" {
  name                 = "${var.name_prefix}-agentcore-gateway"
  assume_role_policy   = data.aws_iam_policy_document.gateway_assume.json
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags
}

data "aws_iam_policy_document" "gateway" {
  statement {
    sid       = "InvokeTools"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.tools.arn]
  }
  statement {
    sid       = "GatewayKms"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.data_kms_key_arn]
  }
  dynamic "statement" {
    for_each = var.enable_policy_engine ? [1] : []
    content {
      sid = "PolicyEngineAuthorization"
      actions = [
        "bedrock-agentcore:AuthorizeAction",
        "bedrock-agentcore:PartiallyAuthorizeActions",
        "bedrock-agentcore:GetPolicyEngine",
      ]
      resources = [
        aws_bedrockagentcore_policy_engine.this[0].policy_engine_arn,
        "arn:${local.partition}:bedrock-agentcore:${local.region}:${local.account_id}:gateway/*",
      ]
    }
  }
}

resource "aws_iam_role_policy" "gateway" {
  name   = "gateway-least-privilege"
  role   = aws_iam_role.gateway.id
  policy = data.aws_iam_policy_document.gateway.json
}

# ------------------------------------------------------------ policy engine
resource "aws_bedrockagentcore_policy_engine" "this" {
  count              = var.enable_policy_engine ? 1 : 0
  name               = replace("${var.name_prefix}_tool_policy", "-", "_")
  description        = "Cedar authorization for bedrock-guard gateway tools"
  encryption_key_arn = var.data_kms_key_arn
  tags               = var.tags
}

# ----------------------------------------------------------------- gateway
resource "aws_bedrockagentcore_gateway" "this" {
  name            = "${var.name_prefix}-gateway"
  description     = "bedrock-guard tool gateway"
  role_arn        = aws_iam_role.gateway.arn
  authorizer_type = "AWS_IAM"
  protocol_type   = "MCP"
  kms_key_arn     = var.data_kms_key_arn

  protocol_configuration {
    mcp {
      supported_versions = ["2025-06-18", "2025-03-26"]
      instructions       = "Acme Outfitters support tools."
    }
  }

  dynamic "policy_engine_configuration" {
    for_each = var.enable_policy_engine ? [1] : []
    content {
      arn  = aws_bedrockagentcore_policy_engine.this[0].policy_engine_arn
      mode = var.policy_engine_mode
    }
  }

  tags       = var.tags
  depends_on = [aws_iam_role_policy.gateway]
}

resource "aws_bedrockagentcore_gateway_target" "tools" {
  name               = local.target_name
  gateway_identifier = aws_bedrockagentcore_gateway.this.gateway_id
  description        = "Acme order + document tools (Lambda)"

  credential_provider_configuration {
    gateway_iam_role {}
  }

  target_configuration {
    mcp {
      lambda {
        lambda_arn = aws_lambda_function.tools.arn
        tool_schema {
          inline_payload {
            name        = "lookup_order"
            description = "Look up the status of an Acme order by its ID (format ORD-123456)."
            input_schema {
              type = "object"
              property {
                name        = "order_id"
                type        = "string"
                description = "Order ID, e.g. ORD-100001"
                required    = true
              }
            }
          }
          inline_payload {
            name        = "read_document"
            description = "Read a public help-centre document by relative path, e.g. public/shipping.md."
            input_schema {
              type = "object"
              property {
                name        = "path"
                type        = "string"
                description = "Relative document path under public/"
                required    = true
              }
            }
          }
        }
      }
    }
  }
}

# --------------------------------------------------------- Cedar policies
resource "aws_bedrockagentcore_policy" "lookup_order" {
  count            = var.enable_policy_engine ? 1 : 0
  name             = "permit_lookup_order"
  description      = "Agent may look up well-formed order IDs"
  policy_engine_id = aws_bedrockagentcore_policy_engine.this[0].policy_engine_id
  validation_mode  = "FAIL_ON_ANY_FINDINGS"
  definition {
    cedar {
      statement = <<-CEDAR
        permit(
          principal == AgentCore::IamEntity::"${local.agent_principal}",
          action == AgentCore::Action::"${local.target_name}___lookup_order",
          resource == AgentCore::Gateway::"${aws_bedrockagentcore_gateway.this.gateway_arn}"
        )
        when {
          context.input.order_id like "ORD-*"
        };
      CEDAR
    }
  }
  depends_on = [aws_bedrockagentcore_gateway_target.tools]
}

resource "aws_bedrockagentcore_policy" "read_document" {
  count            = var.enable_policy_engine ? 1 : 0
  name             = "permit_read_public_documents"
  description      = "Agent and test probe may read public/* documents only"
  policy_engine_id = aws_bedrockagentcore_policy_engine.this[0].policy_engine_id
  validation_mode  = "FAIL_ON_ANY_FINDINGS"
  definition {
    cedar {
      statement = <<-CEDAR
        permit(
          principal,
          action == AgentCore::Action::"${local.target_name}___read_document",
          resource == AgentCore::Gateway::"${aws_bedrockagentcore_gateway.this.gateway_arn}"
        )
        when {
          (principal == AgentCore::IamEntity::"${local.agent_principal}" ||
           principal == AgentCore::IamEntity::"${local.probe_principal}") &&
          context.input.path like "public/*"
        };
      CEDAR
    }
  }
  depends_on = [aws_bedrockagentcore_gateway_target.tools]
}

resource "aws_bedrockagentcore_policy" "forbid_traversal" {
  count            = var.enable_policy_engine ? 1 : 0
  name             = "forbid_path_traversal"
  description      = "No principal may pass '..' to read_document"
  policy_engine_id = aws_bedrockagentcore_policy_engine.this[0].policy_engine_id
  validation_mode  = "FAIL_ON_ANY_FINDINGS"
  definition {
    cedar {
      statement = <<-CEDAR
        forbid(
          principal,
          action == AgentCore::Action::"${local.target_name}___read_document",
          resource == AgentCore::Gateway::"${aws_bedrockagentcore_gateway.this.gateway_arn}"
        )
        when {
          context.input.path like "*..*"
        };
      CEDAR
    }
  }
  depends_on = [aws_bedrockagentcore_gateway_target.tools]
}

# ------------------------------------------------------- resource policy
data "aws_iam_policy_document" "gateway_resource" {
  statement {
    sid       = "AllowNamedCallers"
    actions   = ["bedrock-agentcore:InvokeGateway"]
    resources = [aws_bedrockagentcore_gateway.this.gateway_arn]
    principals {
      type        = "AWS"
      identifiers = concat([var.agent_role_arn, var.probe_role_arn], var.admin_principal_arns)
    }
  }
  statement {
    sid       = "DenyEveryoneElse"
    effect    = "Deny"
    actions   = ["bedrock-agentcore:InvokeGateway"]
    resources = [aws_bedrockagentcore_gateway.this.gateway_arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = concat([var.agent_role_arn, var.probe_role_arn], var.admin_principal_arns)
    }
  }
}

resource "aws_bedrockagentcore_resource_policy" "gateway" {
  resource_arn = aws_bedrockagentcore_gateway.this.gateway_arn
  policy       = data.aws_iam_policy_document.gateway_resource.json
}

# Probe role may call the gateway (Cedar still decides which tools).
data "aws_iam_policy_document" "probe_invoke" {
  statement {
    actions   = ["bedrock-agentcore:InvokeGateway"]
    resources = [aws_bedrockagentcore_gateway.this.gateway_arn]
  }
}

resource "aws_iam_role_policy" "probe_invoke" {
  name   = "invoke-gateway"
  role   = var.probe_role_name
  policy = data.aws_iam_policy_document.probe_invoke.json
}

# The agent runtime role may call this gateway (resource policy + Cedar still apply).
resource "aws_iam_role_policy" "agent_invoke" {
  name   = "invoke-gateway"
  role   = var.agent_role_name
  policy = data.aws_iam_policy_document.probe_invoke.json
}
