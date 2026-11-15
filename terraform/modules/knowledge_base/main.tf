# Bedrock Knowledge Base on S3 Vectors.
# Controls: CMK on the source bucket, vectors and data source; TLS-only bucket
# policy that allows reads only by the KB role and admins; a KB service role
# whose trust is pinned to this account's knowledge bases; least-privilege
# access to one bucket, one index and one embedding model.
# Ingested content is untrusted. The agent screens retrieved chunks with
# ApplyGuardrail before they reach the model (see agent/app.py).

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id          = data.aws_caller_identity.current.account_id
  region              = data.aws_region.current.region
  partition           = data.aws_partition.current.partition
  embedding_model_arn = "arn:${local.partition}:bedrock:${local.region}::foundation-model/${var.embedding_model_id}"
  docs                = fileset(var.seed_docs_path, "**/*.md")
  docs_hash           = sha256(join("", [for f in local.docs : filesha256("${var.seed_docs_path}/${f}")]))
}

# ------------------------------------------------------------ source bucket
resource "aws_s3_bucket" "source" {
  bucket_prefix = "${var.name_prefix}-kb-source-"
  force_destroy = var.force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "source" {
  bucket                  = aws_s3_bucket.source.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "source" {
  bucket = aws_s3_bucket.source.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "source" {
  bucket = aws_s3_bucket.source.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "source" {
  bucket = aws_s3_bucket.source.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "source" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.source.arn, "${aws_s3_bucket.source.arn}/*"]
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

  # Only the KB role and named admins can read the corpus.
  statement {
    sid       = "DenyReadExceptKbAndAdmins"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.source.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = concat([aws_iam_role.kb.arn], var.admin_principal_arns)
    }
  }
}

resource "aws_s3_bucket_policy" "source" {
  bucket     = aws_s3_bucket.source.id
  policy     = data.aws_iam_policy_document.source.json
  depends_on = [aws_s3_bucket_public_access_block.source]
}

resource "aws_s3_object" "docs" {
  for_each     = local.docs
  bucket       = aws_s3_bucket.source.id
  key          = "docs/${each.value}"
  source       = "${var.seed_docs_path}/${each.value}"
  source_hash  = filemd5("${var.seed_docs_path}/${each.value}")
  content_type = "text/markdown"
  depends_on   = [aws_s3_bucket_server_side_encryption_configuration.source]
}

# ------------------------------------------------------------- vector store
resource "aws_s3vectors_vector_bucket" "this" {
  vector_bucket_name = "${var.name_prefix}-kb-vectors"
  force_destroy      = var.force_destroy
  encryption_configuration = [{
    sse_type    = "aws:kms"
    kms_key_arn = var.kms_key_arn
  }]
  tags = var.tags
}

resource "aws_s3vectors_index" "this" {
  vector_bucket_name = aws_s3vectors_vector_bucket.this.vector_bucket_name
  index_name         = "${var.name_prefix}-kb-index"
  data_type          = "float32"
  dimension          = var.embedding_dimensions
  distance_metric    = "cosine"

  # Bedrock KB stores chunk text + metadata; keep them non-filterable to stay
  # under the filterable-metadata size limit.
  metadata_configuration {
    non_filterable_metadata_keys = ["AMAZON_BEDROCK_TEXT", "AMAZON_BEDROCK_METADATA"]
  }
  tags = var.tags
}

# ------------------------------------------------------------------ KB role
data "aws_iam_policy_document" "kb_assume" {
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
      values   = ["arn:${local.partition}:bedrock:${local.region}:${local.account_id}:knowledge-base/*"]
    }
  }
}

resource "aws_iam_role" "kb" {
  name                 = "${var.name_prefix}-kb-service"
  assume_role_policy   = data.aws_iam_policy_document.kb_assume.json
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags
}

data "aws_iam_policy_document" "kb" {
  statement {
    sid       = "Embed"
    actions   = ["bedrock:InvokeModel"]
    resources = [local.embedding_model_arn]
  }
  statement {
    sid       = "ReadSourceList"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.source.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceAccount"
      values   = [local.account_id]
    }
  }
  statement {
    sid       = "ReadSourceObjects"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.source.arn}/docs/*"]
  }
  statement {
    sid = "Vectors"
    actions = [
      "s3vectors:PutVectors",
      "s3vectors:GetVectors",
      "s3vectors:DeleteVectors",
      "s3vectors:QueryVectors",
      "s3vectors:GetIndex",
    ]
    resources = [aws_s3vectors_index.this.index_arn]
  }
  statement {
    sid       = "Kms"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "kb" {
  name   = "kb-least-privilege"
  role   = aws_iam_role.kb.id
  policy = data.aws_iam_policy_document.kb.json
}

# ------------------------------------------------------------ knowledge base
resource "aws_bedrockagent_knowledge_base" "this" {
  name        = "${var.name_prefix}-kb"
  description = "Acme Outfitters support corpus (contains planted canary + poisoned doc for testing)"
  role_arn    = aws_iam_role.kb.arn

  knowledge_base_configuration {
    type = "VECTOR"
    vector_knowledge_base_configuration {
      embedding_model_arn = local.embedding_model_arn
      embedding_model_configuration {
        bedrock_embedding_model_configuration {
          dimensions          = var.embedding_dimensions
          embedding_data_type = "FLOAT32"
        }
      }
    }
  }

  storage_configuration {
    type = "S3_VECTORS"
    s3_vectors_configuration {
      index_arn = aws_s3vectors_index.this.index_arn
    }
  }

  tags       = var.tags
  depends_on = [aws_iam_role_policy.kb]
}

resource "aws_bedrockagent_data_source" "this" {
  knowledge_base_id    = aws_bedrockagent_knowledge_base.this.id
  name                 = "${var.name_prefix}-docs"
  data_deletion_policy = "DELETE"

  data_source_configuration {
    type = "S3"
    s3_configuration {
      bucket_arn         = aws_s3_bucket.source.arn
      inclusion_prefixes = ["docs/"]
    }
  }

  server_side_encryption_configuration {
    kms_key_arn = var.kms_key_arn
  }

  vector_ingestion_configuration {
    chunking_configuration {
      chunking_strategy = "FIXED_SIZE"
      fixed_size_chunking_configuration {
        max_tokens         = 300
        overlap_percentage = 10
      }
    }
  }
}

# Terraform has no ingestion-job resource; sync whenever the docs change.
resource "terraform_data" "ingest" {
  count            = var.run_ingestion ? 1 : 0
  triggers_replace = [local.docs_hash, aws_bedrockagent_data_source.this.data_source_id]

  provisioner "local-exec" {
    command = "${path.module}/../../../scripts/ingest_kb.sh ${aws_bedrockagent_knowledge_base.this.id} ${aws_bedrockagent_data_source.this.data_source_id} ${local.region}"
  }

  depends_on = [aws_s3_object.docs]
}
