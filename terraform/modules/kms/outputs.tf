output "logs_key_arn" {
  description = "ARN of the logs CMK."
  value       = aws_kms_key.logs.arn
}

output "data_key_arn" {
  description = "ARN of the data CMK."
  value       = aws_kms_key.data.arn
}
