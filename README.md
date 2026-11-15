# bedrock-agent-core-security (bedrock-guard)

[![CI](https://github.com/andrewblooman/bedrock-agent-core-security/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/andrewblooman/bedrock-agent-core-security/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/github/license/andrewblooman/bedrock-agent-core-security)](LICENSE)
[![Terraform](https://img.shields.io/badge/Terraform-%3E%3D1.15-844FBA?logo=terraform&logoColor=white)](https://developer.hashicorp.com/terraform)
[![AWS provider](https://img.shields.io/badge/hashicorp%2Faws-%3E%3D6.73-FF9900?logo=amazonwebservices&logoColor=white)](https://registry.terraform.io/providers/hashicorp/aws/latest)
[![Python](https://img.shields.io/badge/Python-3.14-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Amazon Bedrock](https://img.shields.io/badge/Amazon%20Bedrock-Guardrails%20%7C%20KB-01A88D?logo=amazonwebservices&logoColor=white)](https://aws.amazon.com/bedrock/)
[![AgentCore](https://img.shields.io/badge/Bedrock%20AgentCore-Runtime%20%7C%20Gateway%20%7C%20Policy-232F3E?logo=amazonwebservices&logoColor=white)](https://aws.amazon.com/bedrock/agentcore/)
[![Strands Agents](https://img.shields.io/badge/Strands%20Agents-1.65-6E40C9)](https://strandsagents.com/)
[![gitleaks](https://img.shields.io/badge/secrets-gitleaks-blue?logo=git&logoColor=white)](https://github.com/gitleaks/gitleaks)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Last commit](https://img.shields.io/github/last-commit/andrewblooman/bedrock-agent-core-security)](https://github.com/andrewblooman/bedrock-agent-core-security/commits/main)

Reference security controls for **Amazon Bedrock** and **Bedrock AgentCore**: network isolation, IAM guardrail enforcement, Bedrock Guardrails, Cedar tool authorization, logging and detection. It is written as modular Terraform and proven against a sample Strands agent and a Bedrock Knowledge Base by an attack-test harness.

See [docs/controls.md](docs/controls.md) for the threat → control → test matrix.

## Layout
```
terraform/modules/   kms, network, vpc_endpoints, bedrock_logging, guardrails, iam_guardrail_enforcement,
                     knowledge_base (S3 Vectors), identity (Cognito), agentcore_memory,
                     agentcore_gateway (Lambda tools + Cedar), agentcore_runtime, detection, observability
terraform/envs/dev/  root module (state: s3://medium-example-terraform-state-dev/bedrock-guard/dev)
agent/               Strands agent (AgentCore direct code deploy, PYTHON_3_14, arm64)
tools_lambda/        Gateway tool Lambda (lookup_order, read_document)
kb_seed/             KB corpus incl. a planted canary doc and a poisoned (indirect-injection) review
tests/attack/        pytest harness that attacks the deployed stack
```

## Architecture
Caller → Cognito JWT → **AgentCore Runtime** (VPC mode, private subnets, no internet route) → through VPC endpoints → Bedrock (Claude Haiku 5.5 + guardrail, IAM-enforced), KB Retrieve (each chunk screened by ApplyGuardrail), AgentCore Memory and **AgentCore Gateway** (SigV4, resource policy, Cedar ENFORCE) → tool Lambda (VPC, no egress).
All logs use CMKs. Invocation logs, CloudTrail (management + data events), the agent audit log and tool logs feed metric-filter alarms. EventBridge tamper rules and GuardDuty findings go to SNS.

## Deploy
```bash
./scripts/lock_agent_deps.sh   # only when agent/requirements.in changes
./scripts/build_agent.sh       # builds build/agent.zip (required before plan)
cd terraform/envs/dev
terraform init && terraform plan -out=tfplan && terraform apply tfplan
```
Account-level side effects: region-wide Bedrock invocation logging, a multi-region CloudTrail, a GuardDuty detector, and Security Hub (`enable_guardduty` / `enable_security_hub` turn the last two off). Estimated cost is about $60–80/month, mostly interface endpoints. `endpoint_az_count = 1` in dev.

## Test the controls
```bash
python3.14 -m venv .venv && .venv/bin/pip install -r tests/requirements.txt
.venv/bin/pytest tests/attack -v -m "not slow"   # ~10 min
.venv/bin/pytest tests/attack -v -m slow          # CloudTrail-lagged detections
```
`outputs.json` (gitignored, mode 600) caches the Terraform outputs, including Cognito client secrets.

## Teardown
`./scripts/teardown.sh`

## Verification
- CI (`.github/workflows/ci.yml`): terraform fmt/validate, ruff, gitleaks on every push and PR
- `terraform fmt -check -recursive terraform && terraform -chdir=terraform/envs/dev validate`
- `~/code/boundary/.venv/bin/boundary scan terraform --fail-on HIGH`
- Snyk Code (agent, tools_lambda, tests) + Snyk IaC (terraform)
- `.venv/bin/ruff check agent tools_lambda tests`

## License
Apache 2.0. See [LICENSE](LICENSE).
