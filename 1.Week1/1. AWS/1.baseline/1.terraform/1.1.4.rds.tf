# ============================================================
# rds.tf - Database Tier
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Creates MySQL RDS instance in private subnet
#           Baseline: encrypted, private, not publicly accessible
# ============================================================

# DB Subnet Group - RDS requires subnets in at least 2 AZs
resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-db-subnet"
  subnet_ids = [aws_subnet.public.id, aws_subnet.private.id]
  tags       = { Name = "${var.project}-db-subnet" }
}

# RDS MySQL Instance - Baseline secure configuration
resource "aws_db_instance" "main" {
  identifier        = "${var.project}-db"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  db_name           = "appdb"
  username          = "admin"
  password          = var.db_password

  # Network configuration - uses dedicated RDS security group
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  # Baseline secure settings
  storage_encrypted   = true   # Encryption at rest enabled
  publicly_accessible = false  # Not exposed to internet
  skip_final_snapshot = true

  tags = { Name = "${var.project}-db" }
}
