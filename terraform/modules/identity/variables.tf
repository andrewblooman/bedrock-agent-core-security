variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "deletion_protection" {
  description = "Cognito deletion protection."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
