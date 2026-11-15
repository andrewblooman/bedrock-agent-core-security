output "gateway_id" {
  description = "Gateway ID."
  value       = aws_bedrockagentcore_gateway.this.gateway_id
}

output "gateway_arn" {
  description = "Gateway ARN."
  value       = aws_bedrockagentcore_gateway.this.gateway_arn
}

output "gateway_url" {
  description = "Gateway MCP URL."
  value       = aws_bedrockagentcore_gateway.this.gateway_url
}

output "target_name" {
  description = "Gateway target name (tool prefix)."
  value       = local.target_name
}

output "tools_lambda_name" {
  description = "Tool Lambda function name."
  value       = aws_lambda_function.tools.function_name
}

output "tools_log_group_name" {
  description = "Tool Lambda log group."
  value       = aws_cloudwatch_log_group.tools.name
}
