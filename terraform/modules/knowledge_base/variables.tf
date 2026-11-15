variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "kms_key_arn" {
  description = "Data CMK."
  type        = string
}

variable "embedding_model_id" {
  description = "Embedding model ID."
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
}

variable "embedding_dimensions" {
  description = "Embedding dimensions."
  type        = number
  default     = 1024
}

variable "seed_docs_path" {
  description = "Local directory of markdown docs to ingest."
  type        = string
}

variable "admin_principal_arns" {
  description = "Principals (besides the KB role) allowed to read the source corpus."
  type        = list(string)
}

variable "permissions_boundary_arn" {
  description = "Permissions boundary for the KB role."
  type        = string
}

variable "run_ingestion" {
  description = "Start an ingestion job when docs change."
  type        = bool
  default     = true
}

variable "force_destroy" {
  description = "Allow destroying non-empty buckets (dev only)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
