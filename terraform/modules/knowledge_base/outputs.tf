output "knowledge_base_id" {
  description = "Knowledge base ID."
  value       = aws_bedrockagent_knowledge_base.this.id
}

output "knowledge_base_arn" {
  description = "Knowledge base ARN."
  value       = aws_bedrockagent_knowledge_base.this.arn
}

output "data_source_id" {
  description = "Data source ID."
  value       = aws_bedrockagent_data_source.this.data_source_id
}

output "source_bucket_name" {
  description = "KB source bucket."
  value       = aws_s3_bucket.source.id
}

output "source_bucket_arn" {
  description = "KB source bucket ARN."
  value       = aws_s3_bucket.source.arn
}
