variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "guardrail_arn" {
  description = "ARN of the approved guardrail."
  type        = string
}

variable "allowed_model_ids" {
  description = "Model IDs / inference profile IDs / ARNs that may be invoked."
  type        = list(string)
}

variable "allowed_vpce_ids" {
  description = "VPC endpoint IDs that agent data-plane calls must traverse."
  type        = list(string)
}

variable "scp_breakglass_role_name" {
  description = "Role name exempted in the generated SCP."
  type        = string
  default     = "BedrockBreakGlass"
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
