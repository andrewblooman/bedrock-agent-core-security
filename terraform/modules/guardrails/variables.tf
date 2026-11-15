variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK for guardrail encryption."
  type        = string
}

variable "use_standard_tier" {
  description = "Use the Standard safeguard tier (better prompt-attack detection; requires a cross-region guardrail profile)."
  type        = bool
  default     = true
}

variable "cross_region_guardrail_profile" {
  description = "Guardrail profile ID, e.g. eu.guardrail.v1:0 or us.guardrail.v1:0. Empty disables cross-region (Classic tier only)."
  type        = string
  default     = "eu.guardrail.v1:0"
}

variable "canary_regex" {
  description = "Regex matching the planted canary secret."
  type        = string
  default     = "BGCANARY-[A-Z0-9]{12}"
}

variable "blocked_words" {
  description = "Custom blocked words/phrases."
  type        = list(string)
  default     = ["ignore previous instructions", "developer mode enabled"]
}

variable "grounding_threshold" {
  description = "Contextual grounding threshold."
  type        = number
  default     = 0.75
}

variable "relevance_threshold" {
  description = "Contextual relevance threshold."
  type        = number
  default     = 0.5
}

variable "blocked_input_message" {
  description = "Message returned when input is blocked."
  type        = string
  default     = "Sorry, I can't help with that request. [blocked by guardrail: input]"
}

variable "blocked_output_message" {
  description = "Message returned when output is blocked."
  type        = string
  default     = "Sorry, I can't share that response. [blocked by guardrail: output]"
}

variable "enforce_account_wide" {
  description = "Apply this guardrail to every Bedrock invocation in the account/region (affects all workloads)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
