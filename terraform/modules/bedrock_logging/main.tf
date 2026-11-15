# Account/region-wide Bedrock model invocation logging: full prompts and
# completions go to CloudWatch Logs (for detection) and S3 (for long-term
# evidence). Both are encrypted with the logs CMK. These logs contain
# sensitive prompt data, so read access should be restricted to the
# security team.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  source_arn = "arn:${local.partition}:bedrock:${local.region}:${local.account_id}:*"
}

resource "aws_s3_bucket" "logs" {
  bucket_prefix       = "${var.name_prefix}-invocation-logs-"
  force_destroy       = var.force_destroy
  object_lock_enabled = var.object_lock_days > 0
  tags                = var.tags
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.logs_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "logs" {
  count  = var.object_lock_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.logs.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_days
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = var.s3_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
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
    sid       = "BedrockLogDelivery"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/${var.s3_key_prefix}/AWSLogs/${local.account_id}/BedrockModelInvocationLogs/*"]
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [local.source_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket     = aws_s3_bucket.logs.id
  policy     = data.aws_iam_policy_document.bucket.json
  depends_on = [aws_s3_bucket_public_access_block.logs]
}

resource "aws_cloudwatch_log_group" "invocations" {
  name              = "/${var.name_prefix}/bedrock/model-invocations"
  retention_in_days = var.cw_retention_days
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [local.source_arn]
    }
  }
}

resource "aws_iam_role" "logging" {
  name               = "${var.name_prefix}-bedrock-invocation-logging"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "logging" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.invocations.arn}:log-stream:aws/bedrock/modelinvocations"]
  }
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/${var.s3_key_prefix}/large-data/*"]
  }
}

resource "aws_iam_role_policy" "logging" {
  name   = "deliver-invocation-logs"
  role   = aws_iam_role.logging.id
  policy = data.aws_iam_policy_document.logging.json
}

resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  logging_config {
    text_data_delivery_enabled      = true
    image_data_delivery_enabled     = true
    embedding_data_delivery_enabled = false
    video_data_delivery_enabled     = false

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.invocations.name
      role_arn       = aws_iam_role.logging.arn
      large_data_delivery_s3_config {
        bucket_name = aws_s3_bucket.logs.id
        key_prefix  = "${var.s3_key_prefix}/large-data"
      }
    }

    s3_config {
      bucket_name = aws_s3_bucket.logs.id
      key_prefix  = var.s3_key_prefix
    }
  }

  depends_on = [aws_s3_bucket_policy.logs, aws_iam_role_policy.logging]
}
