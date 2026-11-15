output "guardrail_enforcement_policy_arn" {
  description = "Managed policy: guardrail required + model allowlist."
  value       = aws_iam_policy.guardrail_enforcement.arn
}

output "network_perimeter_policy_arn" {
  description = "Managed policy: agent data plane only via VPC endpoints."
  value       = aws_iam_policy.network_perimeter.arn
}

output "boundary_policy_arn" {
  description = "Permissions boundary for agent-side roles."
  value       = aws_iam_policy.boundary.arn
}

output "allowed_model_resources" {
  description = "Resolved model ARNs allowed for invocation."
  value       = local.allowed_model_resources
}

output "scp_json" {
  description = "Organizations SCP enforcing guardrails on all Bedrock invocations (apply at the org level)."
  value       = data.aws_iam_policy_document.scp.json
}

output "probe_role_arn" {
  description = "Test-only role used by the attack harness."
  value       = aws_iam_role.probe.arn
}

output "probe_role_name" {
  description = "Test-only role name."
  value       = aws_iam_role.probe.name
}
