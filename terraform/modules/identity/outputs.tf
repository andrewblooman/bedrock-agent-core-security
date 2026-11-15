output "discovery_url" {
  description = "OIDC discovery URL for the JWT authorizer."
  value       = "https://cognito-idp.${data.aws_region.current.region}.amazonaws.com/${aws_cognito_user_pool.this.id}/.well-known/openid-configuration"
}

output "token_endpoint" {
  description = "OAuth2 token endpoint."
  value       = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${data.aws_region.current.region}.amazoncognito.com/oauth2/token"
}

output "scope" {
  description = "OAuth scope required to invoke the agent."
  value       = "${aws_cognito_resource_server.agent.identifier}/invoke"
}

output "trusted_client_id" {
  description = "Allowed client ID."
  value       = aws_cognito_user_pool_client.trusted.id
}

output "trusted_client_secret" {
  description = "Allowed client secret."
  value       = aws_cognito_user_pool_client.trusted.client_secret
  sensitive   = true
}

output "untrusted_client_id" {
  description = "Same-issuer client that must be rejected."
  value       = aws_cognito_user_pool_client.untrusted.id
}

output "untrusted_client_secret" {
  description = "Untrusted client secret."
  value       = aws_cognito_user_pool_client.untrusted.client_secret
  sensitive   = true
}

output "user_pool_id" {
  description = "User pool ID."
  value       = aws_cognito_user_pool.this.id
}
