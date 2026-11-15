variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "KMS key for log group and bucket."
  type        = string
}

variable "s3_key_prefix" {
  description = "Prefix inside the bucket for invocation logs."
  type        = string
  default     = "bedrock"
}

variable "cw_retention_days" {
  description = "CloudWatch retention for invocation logs."
  type        = number
  default     = 30
}

variable "s3_retention_days" {
  description = "S3 retention for invocation logs."
  type        = number
  default     = 365
}

variable "object_lock_days" {
  description = "Governance-mode Object Lock retention (0 disables). Enable in prod for tamper-evident evidence."
  type        = number
  default     = 0
}

variable "force_destroy" {
  description = "Allow destroying a non-empty bucket (dev only)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
