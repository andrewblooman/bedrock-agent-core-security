output "alerts_topic_arn" {
  description = "SNS topic for security alerts."
  value       = aws_sns_topic.alerts.arn
}

output "trail_log_group_name" {
  description = "CloudTrail log group."
  value       = aws_cloudwatch_log_group.trail.name
}

output "alarm_names" {
  description = "Map of detection => alarm name."
  value       = { for k, v in aws_cloudwatch_metric_alarm.this : k => v.alarm_name }
}

output "metric_namespace" {
  description = "Custom metric namespace."
  value       = local.ns
}

output "alarm_arns" {
  description = "Alarm ARNs."
  value       = [for v in aws_cloudwatch_metric_alarm.this : v.arn]
}

output "detection_names" {
  description = "Detection metric names."
  value       = keys(local.detections)
}
