variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "detection_names" {
  description = "Detection metric names in the BedrockGuard namespace."
  type        = list(string)
}

variable "alarm_arns" {
  description = "Alarm ARNs to show."
  type        = list(string)
}
