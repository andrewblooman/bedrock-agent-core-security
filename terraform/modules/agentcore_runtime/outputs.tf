output "role_arn" {
  description = "Runtime execution role ARN."
  value       = aws_iam_role.runtime.arn
}

output "role_name" {
  description = "Runtime execution role name."
  value       = aws_iam_role.runtime.name
}

output "agent_runtime_arn" {
  description = "Agent runtime ARN."
  value       = aws_bedrockagentcore_agent_runtime.this.agent_runtime_arn
}

output "agent_runtime_id" {
  description = "Agent runtime ID."
  value       = aws_bedrockagentcore_agent_runtime.this.agent_runtime_id
}

output "audit_log_group_name" {
  description = "Agent security audit log group."
  value       = aws_cloudwatch_log_group.audit.name
}

output "code_bucket_arn" {
  description = "Agent code bucket ARN."
  value       = aws_s3_bucket.code.arn
}
