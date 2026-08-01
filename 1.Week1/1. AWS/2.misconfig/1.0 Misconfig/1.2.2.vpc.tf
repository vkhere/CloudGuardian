# ============================================================
# vpc.tf - Network Infrastructure
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Creates VPC, Public Subnet, Private Subnet,
#           Internet Gateway, Route Table and Security Groups
#
# MISCONFIGURATIONS INTRODUCED:
#   [M06] SSH port 22 open to 0.0.0.0/0 in web_sg
#   [M07] RDS port 3306 open to 0.0.0.0/0 in rds_sg
# ============================================================

# Main VPC - contains all resources
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "${var.project}-vpc" }
}

# Public Subnet - Web tier lives here (ap-south-1a)
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "ap-south-1a"
  tags = { Name = "${var.project}-public" }
}

# Private Subnet - Database lives here (ap-south-1b)
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "ap-south-1b"
  tags = { Name = "${var.project}-private" }
}

# Internet Gateway - allows internet access for public subnet
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-igw" }
}

# Route Table - routes internet traffic through IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${var.project}-public-rt" }
}

# Route Table Association - links public subnet to route table
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ----------------------------------------------------------------
# Security Group - Web Tier
# [M06] MISCONFIGURATION: SSH (port 22) open to entire internet
#        Baseline had only HTTP/HTTPS (80/443) open
#        Risk: Brute-force, credential stuffing from any IP
# ----------------------------------------------------------------
resource "aws_security_group" "web_sg" {
  name   = "${var.project}-web-sg"
  vpc_id = aws_vpc.main.id

  # Allow HTTP traffic from anywhere (baseline - OK)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow HTTPS traffic from anywhere (baseline - OK)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # [M06] MISCONFIGURATION - SSH open to world
  # Baseline: This rule did NOT exist
  # Fix: Remove this block OR restrict to known admin IP
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # INSECURE: should be your IP only e.g. ["203.0.113.5/32"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-web-sg" }
}

# ----------------------------------------------------------------
# Security Group - RDS Tier
# [M07] MISCONFIGURATION: MySQL port 3306 open to 0.0.0.0/0
#        Baseline: Only allowed MySQL from web_sg (internal)
#        Risk: Database directly reachable from internet
# ----------------------------------------------------------------
resource "aws_security_group" "rds_sg" {
  name   = "${var.project}-rds-sg"
  vpc_id = aws_vpc.main.id

  # [M07] MISCONFIGURATION - RDS open to world
  # Baseline was: security_groups = [aws_security_group.web_sg.id]
  # Fix: Change cidr_blocks back to security_groups reference
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # INSECURE: entire internet can reach DB
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-rds-sg" }
}
