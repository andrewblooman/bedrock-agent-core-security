# bedrock-guard contributor guidance

## Commands

Use Python 3.14 and the repository virtual environment:

```bash
python3.14 -m venv .venv
.venv/bin/pip install -r tests/requirements.txt ruff
```

```bash
# Re-lock only after changing agent/requirements.in. Produces arm64 CPython 3.14 hashes.
./scripts/lock_agent_deps.sh

# Build before every Terraform plan; agentcore_runtime hashes build/agent.zip.
./scripts/build_agent.sh

# Terraform formatting and offline validation
terraform fmt -recursive terraform
cd terraform/envs/dev && terraform init -backend=false && terraform validate

# Python lint and formatting checks
.venv/bin/ruff check agent tools_lambda tests
.venv/bin/ruff format --check agent tools_lambda tests

# Deployed-stack attack tests
.venv/bin/pytest tests/attack -v -m "not slow"
.venv/bin/pytest tests/attack/test_07_tool_abuse.py::test_cedar_forbids_traversal -v
.venv/bin/pytest tests/attack -v -m slow
```

Attack tests require a deployed stack and cache Terraform outputs, including Cognito secrets, in gitignored `outputs.json` (mode 600). Delete that cache after re-applying. Slow tests wait 5–15 minutes for CloudTrail delivery.

Run a real `terraform plan` with the configured backend only after building the artifact. Ask for confirmation before `terraform apply`: it enables account-wide Bedrock invocation logging and CloudTrail, and can enable GuardDuty and Security Hub. Use `./scripts/teardown.sh` to remove the stack.

## Architecture

`terraform/envs/dev` is the sole root module; it wires `terraform/modules/*` together while the modules own all resources. The sample workload is a Strands agent directly deployed as an arm64 Python zip to AgentCore Runtime. It accepts a Cognito JWT, runs in private subnets without internet access, and reaches Bedrock, Knowledge Base, Memory, and Gateway through VPC endpoints.

The Gateway is an AWS_IAM-authenticated MCP endpoint backed by the tool Lambda and an enforcing Cedar policy engine. The runtime signs its Gateway requests with `agent/sigv4_auth.py`; attack tests import that same implementation. The runtime retrieves Knowledge Base chunks, screens each with `ApplyGuardrail`, wraps accepted content as `<untrusted_data>`, and sends model requests with the configured Bedrock guardrail. `docs/controls.md` is the threat-to-control-to-test matrix and must remain aligned when a control changes.

`agentcore_runtime` creates the agent role, which `agentcore_gateway` uses in its Cedar policy, resource policy, and InvokeGateway permission; the runtime then consumes the gateway URL. This is intentionally resolvable at resource level. Do not add a module-level `depends_on` between those modules.

## Repository-specific conventions

- Keep the Terraform version constraints synchronized across every module `versions.tf`. The AWS provider floor supports AgentCore, S3 Vectors, and account-enforced guardrails.
- IAM enforcement is layered: apply the guardrail/model policy to user-acting callers (runtime and control probe), not the Knowledge Base role because embedding calls do not carry a guardrail. Agent-side roles require the permissions boundary, and runtime data-plane calls need the VPC endpoint perimeter.
- Adding an AWS API call from `agent/app.py` also requires the corresponding VPC endpoint, endpoint-policy permission, and network-perimeter permission; otherwise the isolated runtime will time out.
- Runtime authentication is Cognito JWT pinned to the trusted client; Gateway authentication is SigV4. Derive Memory actors from JWT `client_id`, never request payload fields. Cedar tool names use `<target>___<tool>` and default-deny behavior must remain intact.
- Preserve `streaming=False`: the `GuardrailIntervenedInvocation` detection depends on non-streaming Bedrock invocation logs. Preserve KB screening, untrusted-data wrapping, and the final canary filter when changing agent flow.
- Agent audit JSON event names and tool Lambda `SECURITY` log content are detection contracts. When changing them, update the detection module and attack tests together.
- `BGCANARY-*` values in seed/tool documents, the poisoned review, and forged test JWT are intentional test fixtures narrowly allowlisted in `.gitleaks.toml`; keep the guardrail canary regex compatible with them.
