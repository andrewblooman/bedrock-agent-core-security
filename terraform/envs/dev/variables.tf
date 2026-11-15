variable "region" {
  description = "AWS region."
  type        = string
  default     = "eu-west-1"
}

variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
  default     = "bg-dev"
}

variable "agent_model_id" {
  description = "Inference profile used by the agent."
  type        = string
  default     = "eu.anthropic.claude-haiku-5-5"
}

variable "allowed_model_ids" {
  description = "Model allowlist enforced by IAM (must include agent_model_id)."
  type        = list(string)
  default     = ["eu.anthropic.claude-haiku-5-5"]
}

variable "alert_email" {
  description = "Optional email for security alerts (requires confirming the SNS subscription)."
  type        = string
  default     = ""
}

variable "enable_internet_egress" {
  description = "Add NAT egress to the workload subnets (weakens the egress control)."
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "Create GuardDuty detector."
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub."
  type        = bool
  default     = true
}

variable "enforce_guardrail_account_wide" {
  description = "Bedrock account-level enforced guardrail (affects ALL workloads in the account)."
  type        = bool
  default     = false
}

variable "enforce_network_perimeter" {
  description = "Deny agent data-plane calls not traversing the VPC endpoints."
  type        = bool
  default     = true
}

variable "policy_engine_mode" {
  description = "AgentCore gateway Cedar policy mode."
  type        = string
  default     = "ENFORCE"
}
