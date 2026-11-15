output "endpoint_ids" {
  description = "Map of service => VPC endpoint ID (interface + s3)."
  value       = merge({ for k, v in aws_vpc_endpoint.interface : k => v.id }, { s3 = aws_vpc_endpoint.s3.id })
}

output "bedrock_runtime_endpoint_id" {
  description = "bedrock-runtime VPC endpoint ID (used by aws:SourceVpce perimeter policy)."
  value       = aws_vpc_endpoint.interface["bedrock-runtime"].id
}
