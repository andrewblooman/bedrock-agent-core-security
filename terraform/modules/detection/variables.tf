variable "name_prefix" {
  description = "Prefix for resource names (also used to match agent-side role names)."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "Logs CMK."
  type        = string
}

variable "alert_email" {
  description = "Optional email subscribed to the alert topic."
  type        = string
  default     = ""
}

variable "agent_role_name" {
  description = "Agent runtime role name."
  type        = string
}

variable "invocation_log_group_name" {
  description = "Bedrock model invocation log group."
  type        = string
}

variable "audit_log_group_name" {
  description = "Agent security audit log group."
  type        = string
}

variable "tools_log_group_name" {
  description = "Gateway tool Lambda log group."
  type        = string
}

variable "guardrail_intervention_threshold" {
  description = "Interventions per minute that trigger the alarm."
  type        = number
  default     = 1
}

variable "data_event_resource_types" {
  description = "CloudTrail data-event resource types to record."
  type        = list(string)
  default = [
    "AWS::Bedrock::KnowledgeBase",
    "AWS::Bedrock::Guardrail",
    "AWS::BedrockAgentCore::Runtime",
    "AWS::BedrockAgentCore::Gateway",
    "AWS::BedrockAgentCore::Memory",
    "AWS::BedrockAgentCore::WorkloadIdentity",
  ]
}

variable "s3_data_event_bucket_arns" {
  description = "Buckets whose object-level access is recorded (KB corpus, agent code)."
  type        = list(string)
  default     = []
}

variable "extra_detections" {
  description = "Additional metric-filter detections: name => {log_group, pattern, threshold, description}."
  type = map(object({
    log_group   = string
    pattern     = string
    threshold   = number
    description = string
  }))
  default = {}
}

variable "enable_guardduty" {
  description = "Create a GuardDuty detector (account singleton)."
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub + FSBP (account singleton)."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudTrail CWL retention."
  type        = number
  default     = 90
}

variable "trail_retention_days" {
  description = "CloudTrail S3 retention."
  type        = number
  default     = 365
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
