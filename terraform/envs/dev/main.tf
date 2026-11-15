data "aws_caller_identity" "current" {}

locals {
  repo_root  = abspath("${path.root}/../../..")
  admin_arns = [data.aws_caller_identity.current.arn]
}

module "kms" {
  source      = "../../modules/kms"
  name_prefix = var.name_prefix
}

module "network" {
  source                 = "../../modules/network"
  name_prefix            = var.name_prefix
  logs_kms_key_arn       = module.kms.logs_key_arn
  enable_internet_egress = var.enable_internet_egress
}

module "vpc_endpoints" {
  source                     = "../../modules/vpc_endpoints"
  name_prefix                = var.name_prefix
  vpc_id                     = module.network.vpc_id
  subnet_ids                 = module.network.private_subnet_ids
  private_route_table_id     = module.network.private_route_table_id
  endpoint_security_group_id = module.network.endpoint_security_group_id
}

module "bedrock_logging" {
  source           = "../../modules/bedrock_logging"
  name_prefix      = var.name_prefix
  logs_kms_key_arn = module.kms.logs_key_arn
  force_destroy    = true
}

module "guardrails" {
  source               = "../../modules/guardrails"
  name_prefix          = var.name_prefix
  kms_key_arn          = module.kms.data_key_arn
  enforce_account_wide = var.enforce_guardrail_account_wide
}

module "iam" {
  source            = "../../modules/iam_guardrail_enforcement"
  name_prefix       = var.name_prefix
  guardrail_arn     = module.guardrails.guardrail_arn
  allowed_model_ids = var.allowed_model_ids
  allowed_vpce_ids  = values(module.vpc_endpoints.endpoint_ids)
}

module "knowledge_base" {
  source                   = "../../modules/knowledge_base"
  name_prefix              = var.name_prefix
  kms_key_arn              = module.kms.data_key_arn
  seed_docs_path           = "${local.repo_root}/kb_seed"
  admin_principal_arns     = local.admin_arns
  permissions_boundary_arn = module.iam.boundary_policy_arn
  force_destroy            = true
}

module "memory" {
  source      = "../../modules/agentcore_memory"
  name_prefix = var.name_prefix
  kms_key_arn = module.kms.data_key_arn
}

module "identity" {
  source      = "../../modules/identity"
  name_prefix = var.name_prefix
}

module "gateway" {
  source                   = "../../modules/agentcore_gateway"
  name_prefix              = var.name_prefix
  tools_source_dir         = "${local.repo_root}/tools_lambda"
  subnet_ids               = module.network.private_subnet_ids
  security_group_id        = module.network.workload_security_group_id
  data_kms_key_arn         = module.kms.data_key_arn
  logs_kms_key_arn         = module.kms.logs_key_arn
  permissions_boundary_arn = module.iam.boundary_policy_arn
  agent_role_name          = module.runtime.role_name
  agent_role_arn           = module.runtime.role_arn
  probe_role_name          = module.iam.probe_role_name
  probe_role_arn           = module.iam.probe_role_arn
  admin_principal_arns     = local.admin_arns
  policy_engine_mode       = var.policy_engine_mode
}

module "runtime" {
  source                           = "../../modules/agentcore_runtime"
  name_prefix                      = var.name_prefix
  agent_zip_path                   = "${local.repo_root}/build/agent.zip"
  subnet_ids                       = module.network.private_subnet_ids
  security_group_id                = module.network.workload_security_group_id
  data_kms_key_arn                 = module.kms.data_key_arn
  logs_kms_key_arn                 = module.kms.logs_key_arn
  permissions_boundary_arn         = module.iam.boundary_policy_arn
  guardrail_enforcement_policy_arn = module.iam.guardrail_enforcement_policy_arn
  network_perimeter_policy_arn     = module.iam.network_perimeter_policy_arn
  enforce_network_perimeter        = var.enforce_network_perimeter
  allowed_model_resources          = module.iam.allowed_model_resources
  model_id                         = var.agent_model_id
  guardrail_id                     = module.guardrails.guardrail_id
  guardrail_arn                    = module.guardrails.guardrail_arn
  guardrail_version                = module.guardrails.guardrail_version
  knowledge_base_id                = module.knowledge_base.knowledge_base_id
  knowledge_base_arn               = module.knowledge_base.knowledge_base_arn
  memory_id                        = module.memory.memory_id
  memory_arn                       = module.memory.memory_arn
  gateway_url                      = module.gateway.gateway_url
  jwt_discovery_url                = module.identity.discovery_url
  jwt_allowed_clients              = [module.identity.trusted_client_id]
  admin_principal_arns             = local.admin_arns
  force_destroy                    = true
}

module "detection" {
  source                    = "../../modules/detection"
  name_prefix               = var.name_prefix
  logs_kms_key_arn          = module.kms.logs_key_arn
  alert_email               = var.alert_email
  agent_role_name           = module.runtime.role_name
  invocation_log_group_name = module.bedrock_logging.log_group_name
  audit_log_group_name      = module.runtime.audit_log_group_name
  tools_log_group_name      = module.gateway.tools_log_group_name
  s3_data_event_bucket_arns = [module.knowledge_base.source_bucket_arn, module.runtime.code_bucket_arn]
  enable_guardduty          = var.enable_guardduty
  enable_security_hub       = var.enable_security_hub
  force_destroy             = true
}

module "observability" {
  source          = "../../modules/observability"
  name_prefix     = var.name_prefix
  detection_names = module.detection.detection_names
  alarm_arns      = module.detection.alarm_arns
}
