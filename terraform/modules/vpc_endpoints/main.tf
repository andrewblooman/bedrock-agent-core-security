# Private connectivity to every AWS API the agent needs. Each endpoint policy
# allows only principals from this account (data-perimeter "identity"
# control), so stolen credentials from another account cannot exfiltrate
# through our endpoints. The bedrock-runtime policy also limits the actions
# that can be called through it.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region

  # service suffix => list of allowed actions (["*"] = any action, still account-scoped)
  interface_endpoints = {
    "bedrock-runtime" = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream",
      "bedrock:Converse",
      "bedrock:ConverseStream",
      "bedrock:ApplyGuardrail",
      "bedrock:CountTokens",
    ]
    "bedrock-agent-runtime"     = ["bedrock:Retrieve"]
    "bedrock-agentcore"         = ["*"]
    "bedrock-agentcore.gateway" = ["*"]
    "logs"                      = ["*"]
    "sts"                       = ["*"]
  }
  endpoint_subnet_ids = slice(var.subnet_ids, 0, min(var.endpoint_az_count, length(var.subnet_ids)))
}

data "aws_iam_policy_document" "interface" {
  for_each = local.interface_endpoints

  statement {
    sid       = "AccountPrincipalsOnly"
    actions   = each.value
    resources = ["*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${local.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = local.endpoint_subnet_ids
  security_group_ids  = [var.endpoint_security_group_id]
  policy              = data.aws_iam_policy_document.interface[each.key].json
  tags                = merge(var.tags, { Name = "${var.name_prefix}-${each.key}" })
}

# S3 gateway endpoint: only buckets owned by this account are reachable.
data "aws_iam_policy_document" "s3" {
  statement {
    sid       = "OwnAccountBucketsOnly"
    actions   = ["s3:*"]
    resources = ["*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${local.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [var.private_route_table_id]
  policy            = data.aws_iam_policy_document.s3.json
  tags              = merge(var.tags, { Name = "${var.name_prefix}-s3" })
}
