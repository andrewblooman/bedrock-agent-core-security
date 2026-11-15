# bedrock-guard control matrix

Each row maps a threat to its preventive, detective and verifying controls. Test IDs refer to `tests/attack`.

| ID | Threat | Preventive controls (module) | Detective controls (detection) | Test |
|---|---|---|---|---|
| T01 | Direct prompt injection / jailbreak | Guardrail PROMPT_ATTACK (Standard tier), denied topics, word list (`guardrails`); hardened system prompt (`agent/app.py`) | `AgentGuardrailBlock`, `GuardrailIntervenedInvocation` alarms | test_02 |
| T02 | Indirect injection via RAG content | Per-chunk `ApplyGuardrail` screening + quarantine; `<untrusted_data>` spotlighting (`agent/app.py`) | `KbChunkQuarantined` alarm | test_03 |
| T03 | Sensitive data in corpus / exfiltration | Canary regex + PII BLOCK (`guardrails`); chunk screening; last-line canary output filter; KB bucket read restricted to KB role (`knowledge_base`) | `CanaryInModelTraffic`, `CanaryInAgentResponse` alarms; S3 data events on corpus | test_04 |
| T04 | PII leakage | PII BLOCK (SSN, cards, AWS keys, passwords) and ANONYMIZE (email, phone, name, address) | Invocation logs (CWL + S3) | test_05 |
| T05 | Off-policy use | Denied topics: investment advice, offensive security, system internals | `AgentGuardrailBlock` | test_06 |
| T06 | Tool abuse (path traversal, unpermitted tools) | Gateway Cedar policy engine ENFORCE: default deny, input constraints, forbid `..` (`agentcore_gateway`); Lambda canonical-path check; gateway resource policy | `ToolSecurityEvent` alarm; CloudTrail data events on gateway | test_07 |
| T07 | Unauthenticated / wrong-client callers | Runtime CUSTOM_JWT pinned to one Cognito client; SigV4 rejected (`agentcore_runtime`, `identity`) | CloudTrail data events on runtime | test_01 |
| T08 | Guardrail bypass by calling models directly | IAM deny unless `bedrock:GuardrailIdentifier` = approved guardrail; tamper deny (`iam_guardrail_enforcement`); optional account-enforced guardrail; org SCP output | `ai-control-tamper` EventBridge rule; `AgentPrincipalAccessDenied` | test_08 |
| T09 | Model sprawl / unapproved models | IAM model allowlist (Allow + Deny NotResource) | `AgentPrincipalAccessDenied` | test_08 |
| T10 | Credential theft from runtime | Network perimeter: deny data-plane calls without `aws:SourceVpce`; endpoint policies limited to account principals; permissions boundary (no IAM/STS) | `BedrockInvokeOutsideVpce`, `AgentPrincipalAccessDenied` | test_08 (IAM simulation) |
| T11 | Data exfiltration via egress | Private subnets with no IGW/NAT; SG egress only to endpoints + S3 prefix list; S3 gateway endpoint limited to own-account buckets (`network`, `vpc_endpoints`) | VPC flow logs; `egress_blocked` audit events | test_09 |
| T12 | Blinding the defenders | Boundary denies log/guardrail/runtime changes by agent roles; CMK-encrypted logs; log-file validation; optional Object Lock | `audit-tamper` and `ai-control-tamper` rules to SNS; GuardDuty; Security Hub FSBP | test_10 |
| T13 | Memory poisoning / cross-user leakage | Short-term memory only (no extraction strategies), CMK, 7-day expiry; actor = JWT client_id, not payload; blocked turns stored redacted (`agentcore_memory`, `agent/app.py`) | CloudTrail data events on memory | not tested (needs a second allowed client) |
| T14 | Supply chain of agent code | Hash-pinned aarch64 wheels (`agent/requirements.lock`); code bucket writable only by deployers, versioned, KMS | S3 data events on code bucket | Snyk / Boundary in CI |

## Known limitations
- Contextual grounding is configured, but it only applies when grounding sources are tagged. The agent uses retrieval screening instead.
- `GuardrailIntervenedInvocation` relies on non-streaming Converse logs (the agent sets `streaming=False`).
- CloudTrail-based detections lag 5–15 minutes (`pytest -m slow`).
- MFA delete on S3 (Snyk SNYK-CC-TF-127) needs the root account and is accepted for dev.
