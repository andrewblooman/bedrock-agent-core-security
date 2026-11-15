output "log_group_name" {
  description = "CloudWatch log group receiving model invocation logs."
  value       = aws_cloudwatch_log_group.invocations.name
}

output "bucket_name" {
  description = "S3 bucket receiving model invocation logs."
  value       = aws_s3_bucket.logs.id
}
