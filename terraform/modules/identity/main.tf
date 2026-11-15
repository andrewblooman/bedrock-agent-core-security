# Inbound identity for the AgentCore Runtime (CUSTOM_JWT authorizer).
# Machine-to-machine OAuth (client_credentials) with a dedicated scope.
# Two app clients are created:
#   trusted   - listed in the runtime's allowed_clients
#   untrusted - a valid token from the same issuer that must still be
#               rejected (tests audience/client pinning)

resource "aws_cognito_user_pool" "this" {
  name                     = "${var.name_prefix}-agent-users"
  deletion_protection      = var.deletion_protection ? "ACTIVE" : "INACTIVE"
  mfa_configuration        = "OPTIONAL"
  auto_verified_attributes = ["email"]

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 1
  }

  software_token_mfa_configuration {
    enabled = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  tags = var.tags
}

resource "random_id" "domain" {
  byte_length = 4
}

resource "aws_cognito_user_pool_domain" "this" {
  domain       = "${var.name_prefix}-${random_id.domain.hex}"
  user_pool_id = aws_cognito_user_pool.this.id
}

resource "aws_cognito_resource_server" "agent" {
  identifier   = "bedrock-guard"
  name         = "bedrock-guard agent API"
  user_pool_id = aws_cognito_user_pool.this.id

  scope {
    scope_name        = "invoke"
    scope_description = "Invoke the bedrock-guard agent"
  }
}

resource "aws_cognito_user_pool_client" "trusted" {
  name                                 = "${var.name_prefix}-trusted-client"
  user_pool_id                         = aws_cognito_user_pool.this.id
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_scopes                 = ["${aws_cognito_resource_server.agent.identifier}/invoke"]
  supported_identity_providers         = ["COGNITO"]
  access_token_validity                = 15
  token_validity_units {
    access_token = "minutes"
  }
  enable_token_revocation       = true
  prevent_user_existence_errors = "ENABLED"
}

resource "aws_cognito_user_pool_client" "untrusted" {
  name                                 = "${var.name_prefix}-untrusted-client"
  user_pool_id                         = aws_cognito_user_pool.this.id
  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_scopes                 = ["${aws_cognito_resource_server.agent.identifier}/invoke"]
  supported_identity_providers         = ["COGNITO"]
  access_token_validity                = 15
  token_validity_units {
    access_token = "minutes"
  }
  enable_token_revocation       = true
  prevent_user_existence_errors = "ENABLED"
}

data "aws_region" "current" {}
