# Consumed by tests/attack (terraform output -json > outputs.json).
output "region" {
  description = "Region."
  value       = var.region
}

output "name_prefix" {
  description = "Name prefix."
  value       = var.name_prefix
}

output "agent_runtime_arn" {
  description = "Agent runtime ARN."
  value       = module.runtime.agent_runtime_arn
}

output "agent_role_arn" {
  description = "Agent runtime role ARN."
  value       = module.runtime.role_arn
}

output "audit_log_group_name" {
  description = "Agent audit log group."
  value       = module.runtime.audit_log_group_name
}

output "gateway_url" {
  description = "Gateway MCP URL."
  value       = module.gateway.gateway_url
}

output "gateway_target_name" {
  description = "Gateway target prefix."
  value       = module.gateway.target_name
}

output "tools_lambda_name" {
  description = "Tool Lambda."
  value       = module.gateway.tools_lambda_name
}

output "tools_log_group_name" {
  description = "Tool Lambda log group."
  value       = module.gateway.tools_log_group_name
}

output "guardrail_id" {
  description = "Guardrail ID."
  value       = module.guardrails.guardrail_id
}

output "guardrail_arn" {
  description = "Guardrail ARN."
  value       = module.guardrails.guardrail_arn
}

output "guardrail_version" {
  description = "Guardrail version."
  value       = module.guardrails.guardrail_version
}

output "knowledge_base_id" {
  description = "KB ID."
  value       = module.knowledge_base.knowledge_base_id
}

output "agent_model_id" {
  description = "Agent model."
  value       = var.agent_model_id
}

output "probe_role_arn" {
  description = "Test probe role."
  value       = module.iam.probe_role_arn
}

output "network_perimeter_policy_arn" {
  description = "Network perimeter policy."
  value       = module.iam.network_perimeter_policy_arn
}

output "vpce_ids" {
  description = "VPC endpoint IDs."
  value       = module.vpc_endpoints.endpoint_ids
}

output "invocation_log_group_name" {
  description = "Model invocation log group."
  value       = module.bedrock_logging.log_group_name
}

output "alarm_names" {
  description = "Detection alarms."
  value       = module.detection.alarm_names
}

output "alerts_topic_arn" {
  description = "Alert topic."
  value       = module.detection.alerts_topic_arn
}

output "dashboard_name" {
  description = "Security dashboard."
  value       = module.observability.dashboard_name
}

output "cognito_token_endpoint" {
  description = "OAuth token endpoint."
  value       = module.identity.token_endpoint
}

output "cognito_scope" {
  description = "OAuth scope."
  value       = module.identity.scope
}

output "trusted_client_id" {
  description = "Trusted client."
  value       = module.identity.trusted_client_id
}

output "trusted_client_secret" {
  description = "Trusted client secret."
  value       = module.identity.trusted_client_secret
  sensitive   = true
}

output "untrusted_client_id" {
  description = "Untrusted client."
  value       = module.identity.untrusted_client_id
}

output "untrusted_client_secret" {
  description = "Untrusted client secret."
  value       = module.identity.untrusted_client_secret
  sensitive   = true
}

output "org_scp_json" {
  description = "SCP to enforce guardrails org-wide."
  value       = module.iam.scp_json
}
