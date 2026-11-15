variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "kms_key_arn" {
  description = "Data CMK."
  type        = string
}

variable "event_expiry_days" {
  description = "Days before memory events expire (7-365)."
  type        = number
  default     = 7
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
