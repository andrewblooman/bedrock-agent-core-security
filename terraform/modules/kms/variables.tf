variable "name_prefix" {
  description = "Prefix for resource names, e.g. bg-dev."
  type        = string
}

variable "deletion_window_in_days" {
  description = "KMS key deletion waiting period."
  type        = number
  default     = 7
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
