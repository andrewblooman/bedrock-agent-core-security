variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnets for interface endpoint ENIs."
  type        = list(string)
}

variable "endpoint_az_count" {
  description = "How many of subnet_ids get endpoint ENIs. 1 halves cost in dev; use 2+ for production resilience."
  type        = number
  default     = 1
}

variable "private_route_table_id" {
  description = "Route table for the S3 gateway endpoint."
  type        = string
}

variable "endpoint_security_group_id" {
  description = "SG attached to interface endpoints."
  type        = string
}

variable "tags" {
  description = "Tags."
  type        = map(string)
  default     = {}
}
