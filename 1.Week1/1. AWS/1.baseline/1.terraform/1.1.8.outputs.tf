# ============================================================
# outputs.tf - Output Values
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Prints important resource information after
#           terraform apply completes successfully
# ============================================================

# VPC ID
output "vpc_id" {
  description = "ID of the main VPC"
  value       = aws_vpc.main.id
}

# Public Subnet ID
output "public_subnet_id" {
  description = "ID of the public subnet (web tier)"
  value       = aws_subnet.public.id
}

# Private Subnet ID
output "private_subnet_id" {
  description = "ID of the private subnet (database tier)"
  value       = aws_subnet.private.id
}

# EC2 Public IP - open this in browser to see Apache page
output "web_public_ip" {
  description = "Public IP of the web server - open in browser"
  value       = aws_instance.web.public_ip
}

# S3 Bucket Name
output "s3_bucket_name" {
  description = "Name of the S3 data bucket"
  value       = aws_s3_bucket.data.bucket
}

# RDS Endpoint
output "rds_endpoint" {
  description = "RDS MySQL endpoint"
  value       = aws_db_instance.main.endpoint
}

# Security Group IDs
output "web_security_group_id" {
  description = "ID of the web security group"
  value       = aws_security_group.web_sg.id
}

output "rds_security_group_id" {
  description = "ID of the RDS security group"
  value       = aws_security_group.rds_sg.id
}
