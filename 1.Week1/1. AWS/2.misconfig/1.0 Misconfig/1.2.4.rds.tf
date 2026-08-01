# ============================================================
# rds.tf - Database Tier
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Creates MySQL RDS instance in private subnet
#
# MISCONFIGURATIONS INTRODUCED:
#   [M08] RDS publicly_accessible = true
#   [M09] RDS storage_encrypted = false
#   [M12] RDS backup_retention_period = 0 (backups disabled)
# ============================================================

# DB Subnet Group - RDS requires subnets in at least 2 AZs
resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-db-subnet"
  subnet_ids = [aws_subnet.public.id, aws_subnet.private.id]
  tags       = { Name = "${var.project}-db-subnet-v2" }
}

# ---------------------------------------------------------------
# RDS MySQL Instance - MISCONFIGURED STATE
# ---------------------------------------------------------------
resource "aws_db_instance" "main" {
  identifier        = "${var.project}-db"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  db_name           = "appdb"
  username          = "admin"
  password          = var.db_password

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  # ---------------------------------------------------------------
  # [M08] MISCONFIGURATION - RDS exposed to internet
  #  Baseline:  publicly_accessible = false   (SECURE)
  #  Misconfig: publicly_accessible = true    (INSECURE)
  #
  #  Risk: RDS gets a public DNS endpoint reachable from internet
  #        Even if SG rules restrict traffic, public endpoint itself
  #        is a compliance violation (PCI-DSS 6.4, ISO 27001 A.13)
  #  Fix: Set back to false
  # ---------------------------------------------------------------
  publicly_accessible = true    # INSECURE: database has public internet endpoint

  # ---------------------------------------------------------------
  # [M09] MISCONFIGURATION - RDS encryption disabled
  #  Baseline:  storage_encrypted = true    (SECURE)
  #  Misconfig: storage_encrypted = false   (INSECURE)
  #
  #  Risk: Database files stored in plaintext on EBS volumes
  #        Snapshot theft, physical disk access = full data exposure
  #  Fix: Set back to true (NOTE: requires recreating the instance)
  # ---------------------------------------------------------------
  storage_encrypted = false     # INSECURE: data at rest is unencrypted

  # ---------------------------------------------------------------
  # [M12] MISCONFIGURATION - Automated backups disabled
  #  Baseline:  backup_retention_period not set (defaults to 1 day)
  #  Misconfig: backup_retention_period = 0   (backups DISABLED)
  #
  #  Risk: No automated backups = zero recovery point objective
  #        Also disables Point-in-Time Recovery (PITR)
  #        Ransomware attack = permanent data loss
  #  Fix: Set to 7 or more days
  # ---------------------------------------------------------------
  backup_retention_period = 0   # INSECURE: automated backups completely disabled

  skip_final_snapshot = true

  tags = { Name = "${var.project}-db" }
}
