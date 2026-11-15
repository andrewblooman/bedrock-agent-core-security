# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Reference security controls for Amazon Bedrock and Bedrock AgentCore, written as modular Terraform. A sample workload (a Strands agent on AgentCore Runtime, a Bedrock Knowledge Base, and a Gateway tool Lambda) exists to be attacked by `tests/attack`. `docs/controls.md` maps each threat to its control and its test, so keep it in sync when you add or change a control.

## Commands

All Python uses `python3.14`. The repo venv is `.venv` (`python3.14 -m venv .venv && .venv/bin/pip install -r tests/requirements.txt ruff`).

- Build the agent artifact. Run this before any `terraform plan`, because `agentcore_runtime` calls `filemd5()` on it: `./scripts/build_agent.sh` → `build/agent.zip`
- Re-lock agent deps after editing `agent/requirements.in`: `./scripts/lock_agent_deps.sh`. This resolves linux/arm64 cp314 wheels and writes `agent/requirements.lock` with sha256 hashes.
- Terraform: `terraform fmt -recursive terraform`, then `cd terraform/envs/dev && terraform init -backend=false && terraform validate` (no credentials needed). `validate` also needs `build/agent.zip` to exist; CI creates an empty placeholder.
- Real plan/apply: `cd terraform/envs/dev && terraform init && terraform plan -out=tfplan`. Confirm with the user before `apply`. It has account-wide side effects: region-wide Bedrock invocation logging, a multi-region CloudTrail, GuardDuty and Security Hub.
- Teardown: `./scripts/teardown.sh`
- Lint: `.venv/bin/ruff check agent tools_lambda tests && .venv/bin/ruff format --check agent tools_lambda tests`
- Attack tests (need a deployed stack): `.venv/bin/pytest tests/attack -v -m "not slow"`. Single test: `.venv/bin/pytest tests/attack/test_07_tool_abuse.py::test_cedar_forbids_traversal -v`. `-m slow` waits 5–15 minutes on CloudTrail delivery.
- Security scans: `~/code/boundary/.venv/bin/boundary scan terraform --fail-on HIGH`, Snyk Code on `agent/`, `tools_lambda/` and `tests/`, Snyk IaC on `terraform/`, and `gitleaks git --staged --config .gitleaks.toml .` before pushing. CI runs only fmt/validate and ruff; secret scanning is local by choice.

## Architecture

- `terraform/envs/dev` is the only root module. Its state lives in the shared bucket `medium-example-terraform-state-dev` under the key `bedrock-guard/dev/terraform.tfstate` (S3-native locking, Terraform >= 1.15). All resources live in `terraform/modules/*`; the root only wires them together. Version constraints (`>= 1.15`, aws `>= 6.73, < 7.0`) are repeated in every module's `versions.tf` and must move together. 6.73 is the minimum that has `aws_bedrockagentcore_*`, `aws_s3vectors_*` and `aws_bedrock_enforced_guardrail_configuration`.
- **Dependency shape that looks circular but isn't:** `agentcore_runtime` creates the agent role and passes it out, and `agentcore_gateway` consumes it for Cedar principals, the resource policy and the agent's `InvokeGateway` policy. The runtime resource itself then consumes `gateway_url`. Terraform resolves this per resource, so don't add module-level `depends_on` between these two, or you'll create a real cycle.
- **IAM layering (`iam_guardrail_enforcement`):**
  - `guardrail_enforcement` denies InvokeModel/Converse unless `bedrock:GuardrailIdentifier` matches, and denies models outside the allowlist via `NotResource`. Attach it only to callers that act for users (the agent and the probe), never to the KB role, because embeddings carry no guardrail.
  - `network_perimeter` denies agent data-plane calls without `aws:SourceVpce`.
  - A permissions boundary is applied to every agent-side role.
  - The `control-probe` role exists only so tests can exercise these denies. The agent role trusts only AgentCore, so tests can't assume it.
- **Model IDs** are EU cross-region inference profiles (`eu.anthropic.claude-haiku-5-5`). The IAM module expands each profile into the profile ARN plus `foundation-model/<base>` in all regions.
- **The agent runtime uses direct code deployment** (`PYTHON_3_14`, a zip in S3), not a container: the local Docker can't build arm64. It runs in VPC mode in private subnets with **no internet route**, and every AWS API is reached through `vpc_endpoints`. If you add an AWS API call to the agent, you must also add the VPC endpoint (and allow it in the endpoint policy and the perimeter policy), or the call times out.
- **Inbound auth differs by component:** the Runtime uses a Cognito JWT pinned to the `trusted` client; the `untrusted` client exists only for negative tests. The Gateway uses `AWS_IAM`, and the agent signs requests with `agent/sigv4_auth.py`, which tests also import. Cedar sees IAM callers as `AgentCore::IamEntity::"arn:aws:sts::<acct>:assumed-role/<role>"`. Tool actions are named `<target>___<tool>` with target `acmetools`. A policy engine denies everything not permitted.
- **Agent-side controls in `agent/app.py`:**
  - Each KB chunk is screened with `ApplyGuardrail` before the model sees it, and blocked chunks are audited as `kb_chunk_blocked`.
  - Retrieved content is wrapped in `<untrusted_data>` tags.
  - `streaming=False` is deliberate: the `GuardrailIntervenedInvocation` metric filter parses non-streaming invocation logs.
  - The memory actor comes from the JWT's `client_id`, never from the payload.
  - A last-line canary regex filters the output.
  - `fetch_url` is a test-only egress probe, enabled by `enable_egress_probe` and restricted to an exact host allowlist.
- **Detection contract:** the agent writes JSON audit events (`{"event": ...}`) to the `agent-audit` log group, and the tool Lambda logs `SECURITY` lines. `detection` metric filters key on those exact event names and strings, and the tests poll for them. If you rename an event, update the filter and the tests too.
- **Test fixtures that look like secrets:** `BGCANARY-*` tokens in `kb_seed/` and `tools_lambda/docs/internal/`, the poisoned review in `kb_seed/`, and the forged JWT in `test_01_authn.py` are deliberate. They're allowlisted narrowly in `.gitleaks.toml`. The guardrail's `canary_regex` must keep matching them.
- Tests read Terraform outputs from `outputs.json` (gitignored, mode 600, contains Cognito secrets). Delete it after re-applying so it gets regenerated.

## Unverified against real AWS

The stack has been planned but never applied. These are expected to need fixes on first apply:
- Cedar policy syntax
- CloudTrail data-event `resources.type` names in `detection`
- the `bedrock:GuardrailIdentifier` value format (the IAM condition allows both `<arn>` and `<arn>:*`)
- whether the `aws:SourceVpce` perimeter blocks any AgentCore-internal calls (toggle with `enforce_network_perimeter`)
- `included_models = ["ALL"]` on the opt-in account-enforced guardrail
