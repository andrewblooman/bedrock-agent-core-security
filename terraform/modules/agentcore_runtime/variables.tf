variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "agent_zip_path" {
  description = "Path to the built agent deployment zip (scripts/build_agent.sh)."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnets for runtime ENIs."
  type        = list(string)
}

variable "security_group_id" {
  description = "Workload SG."
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
  description = "Audit log retention."
  type        = number
  default     = 90
}

variable "permissions_boundary_arn" {
  description = "Permissions boundary."
  type        = string
}

variable "guardrail_enforcement_policy_arn" {
  description = "Managed policy requiring the approved guardrail."
  type        = string
}

variable "network_perimeter_policy_arn" {
  description = "Managed policy denying data-plane calls outside the VPC endpoints."
  type        = string
}

variable "enforce_network_perimeter" {
  description = "Attach the VPC-endpoint network perimeter policy."
  type        = bool
  default     = true
}

variable "allowed_model_resources" {
  description = "Model ARNs the agent may invoke."
  type        = list(string)
}

variable "model_id" {
  description = "Model / inference profile ID used by the agent."
  type        = string
}

variable "guardrail_id" {
  description = "Guardrail ID."
  type        = string
}

variable "guardrail_arn" {
  description = "Guardrail ARN."
  type        = string
}

variable "guardrail_version" {
  description = "Guardrail version."
  type        = string
}

variable "knowledge_base_id" {
  description = "KB ID."
  type        = string
}

variable "knowledge_base_arn" {
  description = "KB ARN."
  type        = string
}

variable "memory_id" {
  description = "AgentCore memory ID."
  type        = string
}

variable "memory_arn" {
  description = "AgentCore memory ARN."
  type        = string
}

variable "gateway_url" {
  description = "AgentCore gateway MCP URL."
  type        = string
}

variable "jwt_discovery_url" {
  description = "OIDC discovery URL."
  type        = string
}

variable "jwt_allowed_clients" {
  description = "Allowed OAuth client IDs."
  type        = list(string)
}

variable "admin_principal_arns" {
  description = "Principals allowed to write agent code."
  type        = list(string)
}

variable "extra_environment" {
  description = "Additional environment variables."
  type        = map(string)
  default     = {}
}

variable "force_destroy" {
  description = "Allow destroying non-empty code bucket (dev only)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
