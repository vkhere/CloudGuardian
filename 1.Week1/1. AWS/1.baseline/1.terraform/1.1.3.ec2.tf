# ============================================================
# ec2.tf - Web Tier
# Project : CloudGuardian - CAP-CSE-3W
# Purpose : Creates EC2 instance as web server with Apache
#           Baseline: IMDSv2 enforced, placed in public subnet
# ============================================================

resource "aws_instance" "web" {
  ami                    = "ami-0f58b397bc5c1f2e8"  # Amazon Linux 2 - ap-south-1
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.web_profile.name

  # IMDSv2 enforced - baseline secure (prevents SSRF attacks)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  # User data - installs and starts Apache web server
  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y httpd
    systemctl start httpd
    systemctl enable httpd
    echo "<html>
      <head><title>CloudGuardian</title></head>
      <body>
        <h1>CloudGuardian Web Server</h1>
        <p>3-Tier Reference Workload - Week 1 Baseline</p>
      </body>
    </html>" > /var/www/html/index.html
  EOF

  tags = { Name = "${var.project}-web" }
}
