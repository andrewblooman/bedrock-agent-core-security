output "vpc_id" {
  description = "VPC ID."
  value       = aws_vpc.this.id
}

output "vpc_cidr" {
  description = "VPC CIDR."
  value       = aws_vpc.this.cidr_block
}

output "private_subnet_ids" {
  description = "Private subnet IDs."
  value       = aws_subnet.private[*].id
}

output "private_route_table_id" {
  description = "Private route table ID."
  value       = aws_route_table.private.id
}

output "endpoint_security_group_id" {
  description = "SG for interface endpoints."
  value       = aws_security_group.endpoints.id
}

output "workload_security_group_id" {
  description = "SG for agent runtime and tool Lambdas."
  value       = aws_security_group.workload.id
}

output "flow_log_group_name" {
  description = "VPC flow log group."
  value       = aws_cloudwatch_log_group.flow.name
}
