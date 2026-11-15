# High-level security dashboard: alarm status, single-value tiles for each
# detection, and Bedrock usage gauges.

data "aws_region" "current" {}

locals {
  region = data.aws_region.current.region
  tiles  = [for name in var.detection_names : ["BedrockGuard", name, { stat = "Sum", period = 86400, label = name }]]
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = "${var.name_prefix}-security"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "alarm", x = 0, y = 0, width = 24, height = 4
        properties = {
          title  = "Detection alarms"
          alarms = var.alarm_arns
        }
      },
      {
        type = "metric", x = 0, y = 4, width = 24, height = 6
        properties = {
          title   = "Security events (24h)"
          view    = "singleValue"
          region  = local.region
          metrics = local.tiles
          stat    = "Sum"
          period  = 86400
        }
      },
      {
        type = "metric", x = 0, y = 10, width = 8, height = 6
        properties = {
          title  = "Guardrail interventions vs invocations (1h)"
          view   = "gauge"
          region = local.region
          metrics = [
            ["BedrockGuard", "GuardrailIntervenedInvocation", { stat = "Sum", period = 3600, label = "intervened" }],
          ]
          yAxis = { left = { min = 0, max = 50 } }
        }
      },
      {
        type = "metric", x = 8, y = 10, width = 16, height = 6
        properties = {
          title  = "Bedrock model invocations"
          view   = "timeSeries"
          region = local.region
          metrics = [
            ["AWS/Bedrock", "Invocations", { stat = "Sum", period = 300 }],
            ["AWS/Bedrock", "InvocationClientErrors", { stat = "Sum", period = 300 }],
            ["AWS/Bedrock", "InvocationThrottles", { stat = "Sum", period = 300 }],
          ]
        }
      },
    ]
  })
}
