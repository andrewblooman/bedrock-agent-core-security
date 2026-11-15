# Short-term conversational memory only. There are no long-term extraction
# strategies on purpose: they would let injected content persist across
# sessions (memory poisoning). Events are encrypted with the data CMK and
# expire automatically.

resource "aws_bedrockagentcore_memory" "this" {
  name                  = replace("${var.name_prefix}_memory", "-", "_")
  description           = "bedrock-guard agent short-term memory"
  event_expiry_duration = var.event_expiry_days
  encryption_key_arn    = var.kms_key_arn
  tags                  = var.tags
}
