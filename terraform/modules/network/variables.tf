variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "cidr_block" {
  description = "VPC CIDR."
  type        = string
  default     = "10.40.0.0/16"
}

variable "az_count" {
  description = "Number of AZs for private subnets."
  type        = number
  default     = 2
}

variable "enable_internet_egress" {
  description = "Create IGW + NAT so private workloads can reach the internet. Off by default (strongest egress control)."
  type        = bool
  default     = false
}

variable "logs_kms_key_arn" {
  description = "KMS key for the flow-log group."
  type        = string
}

variable "log_retention_days" {
  description = "Flow log retention."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
