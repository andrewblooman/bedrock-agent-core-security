variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "tools_source_dir" {
  description = "Directory containing the tool Lambda source."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnets for the tool Lambda."
  type        = list(string)
}

variable "security_group_id" {
  description = "Workload SG for the tool Lambda."
  type        = string
}

variable "data_kms_key_arn" {
  description = "Data CMK."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "Logs CMK."
  type        = string
}

variable "log_retention_days" {
  description = "Tool Lambda log retention."
  type        = number
  default     = 90
}

variable "permissions_boundary_arn" {
  description = "Boundary for gateway and Lambda roles."
  type        = string
}

variable "agent_role_name" {
  description = "Name of the agent runtime role (Cedar principal)."
  type        = string
}

variable "agent_role_arn" {
  description = "ARN of the agent runtime role."
  type        = string
}

variable "probe_role_name" {
  description = "Name of the test probe role."
  type        = string
}

variable "probe_role_arn" {
  description = "ARN of the test probe role."
  type        = string
}

variable "admin_principal_arns" {
  description = "Admin principals allowed to call InvokeGateway (Cedar still applies)."
  type        = list(string)
  default     = []
}

variable "enable_policy_engine" {
  description = "Attach a Cedar policy engine to the gateway."
  type        = bool
  default     = true
}

variable "policy_engine_mode" {
  description = "ENFORCE or LOG_ONLY."
  type        = string
  default     = "ENFORCE"
  validation {
    condition     = contains(["ENFORCE", "LOG_ONLY"], var.policy_engine_mode)
    error_message = "policy_engine_mode must be ENFORCE or LOG_ONLY."
  }
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
