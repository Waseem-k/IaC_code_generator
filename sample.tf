# Sample Terraform Configuration with Security Vulnerabilities
# This file intentionally contains security issues for testing the IaC Security Policy Generator

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# 1. VULNERABILITY: Public S3 Bucket with public-read ACL
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-vulnerable-public-bucket-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_acl" "vulnerable_bucket_acl" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  acl    = "public-read"  # SECURITY ISSUE: Public read access
}

# Additional S3 vulnerability - no public access block
resource "aws_s3_bucket" "another_vulnerable_bucket" {
  bucket = "another-vulnerable-bucket-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_public_access_block" "vulnerable_pab" {
  bucket = aws_s3_bucket.another_vulnerable_bucket.id

  block_public_acls       = false  # SECURITY ISSUE: Should be true
  block_public_policy     = false  # SECURITY ISSUE: Should be true
  ignore_public_acls      = false  # SECURITY ISSUE: Should be true
  restrict_public_buckets = false  # SECURITY ISSUE: Should be true
}

# 2. VULNERABILITY: Unencrypted EBS Volume
resource "aws_ebs_volume" "unencrypted_volume" {
  availability_zone = "us-west-2a"
  size              = 20
  type              = "gp3"
  # SECURITY ISSUE: Missing encryption configuration
  # encrypted = true should be added
}

# 3. VULNERABILITY: EC2 Instance with unencrypted EBS block device
resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t3.micro"
  key_name      = aws_key_pair.vulnerable_key.key_name

  ebs_block_device {
    device_name = "/dev/sdf"
    volume_size = 10
    volume_type = "gp3"
    # SECURITY ISSUE: Missing encrypted = true
  }

  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]
  subnet_id             = aws_subnet.public_subnet.id

  tags = {
    Name = "VulnerableInstance"
  }
}

# 4. VULNERABILITY: Security Group with open inbound rules
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-security-group"
  description = "Security group with vulnerable rules"
  vpc_id      = aws_vpc.main.id

  # SECURITY ISSUE: SSH access from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # SECURITY ISSUE: Open to the world
  }

  # SECURITY ISSUE: HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # SECURITY ISSUE: Open to the world
  }

  # SECURITY ISSUE: All ports open
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # SECURITY ISSUE: All ports open to world
  }

  # SECURITY ISSUE: All protocols allowed
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # SECURITY ISSUE: All protocols from anywhere
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "VulnerableSecurityGroup"
  }
}

# 5. VULNERABILITY: RDS Instance without encryption
resource "aws_db_instance" "vulnerable_db" {
  identifier = "vulnerable-database"
  
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  
  db_name  = "vulnerabledb"
  username = "admin"
  password = "password123"  # SECURITY ISSUE: Hardcoded password
  
  # SECURITY ISSUE: No encryption enabled
  # storage_encrypted = true should be added
  
  # SECURITY ISSUE: No backup retention
  backup_retention_period = 0  # SECURITY ISSUE: No backups
  
  # SECURITY ISSUE: Database is publicly accessible
  publicly_accessible = true  # SECURITY ISSUE: Public access
  
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  skip_final_snapshot = true
  
  tags = {
    Name = "VulnerableDatabase"
  }
}

# Database security group with issues
resource "aws_security_group" "db_sg" {
  name        = "database-sg"
  description = "Database security group"
  vpc_id      = aws_vpc.main.id

  # SECURITY ISSUE: Database port open to world
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # SECURITY ISSUE: MySQL open to world
  }

  tags = {
    Name = "DatabaseSecurityGroup"
  }
}

# 6. VULNERABILITY: IAM Policy with wildcard permissions
resource "aws_iam_policy" "vulnerable_policy" {
  name        = "VulnerablePolicy"
  description = "Policy with excessive permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"        # SECURITY ISSUE: Wildcard action
        Resource = "*"      # SECURITY ISSUE: Wildcard resource
      }
    ]
  })
}

# IAM user with vulnerable policy
resource "aws_iam_user" "vulnerable_user" {
  name = "vulnerable-user"
}

resource "aws_iam_user_policy_attachment" "vulnerable_attachment" {
  user       = aws_iam_user.vulnerable_user.name
  policy_arn = aws_iam_policy.vulnerable_policy.arn
}

# 7. VULNERABILITY: SSH Key Pair (should use AWS Systems Manager Session Manager instead)
resource "aws_key_pair" "vulnerable_key" {
  key_name   = "vulnerable-key"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7S5..."  # Truncated for brevity
}

# 8. Network Infrastructure (some with default/vulnerable configurations)
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "MainVPC"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "MainIGW"
  }
}

# SECURITY ISSUE: Using default VPC reference (commented out but shows pattern)
# resource "aws_instance" "default_vpc_instance" {
#   ami           = "ami-0c02fb55956c7d316"
#   instance_type = "t3.micro"
#   vpc_id        = "default"  # SECURITY ISSUE: Using default VPC
# }

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true  # Makes instances get public IPs

  tags = {
    Name = "PublicSubnet"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-west-2b"

  tags = {
    Name = "PrivateSubnet"
  }
}

resource "aws_db_subnet_group" "main" {
  name       = "main-db-subnet-group"
  subnet_ids = [aws_subnet.public_subnet.id, aws_subnet.private_subnet.id]

  tags = {
    Name = "Main DB subnet group"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "PublicRouteTable"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public.id
}

# 9. CloudTrail without proper configuration (commented to avoid costs)
# resource "aws_cloudtrail" "vulnerable_trail" {
#   name           = "vulnerable-trail"
#   s3_bucket_name = aws_s3_bucket.vulnerable_bucket.bucket
#   
#   # SECURITY ISSUE: No log file encryption
#   # kms_key_id = aws_kms_key.cloudtrail.arn should be added
#   
#   # SECURITY ISSUE: No log file validation
#   # enable_log_file_validation = true should be added
# }

# 10. Random ID for unique resource naming
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Outputs
output "vulnerable_bucket_name" {
  value       = aws_s3_bucket.vulnerable_bucket.bucket
  description = "Name of the vulnerable S3 bucket"
}

output "vulnerable_instance_id" {
  value       = aws_instance.vulnerable_instance.id
  description = "ID of the vulnerable EC2 instance"
}

output "vulnerable_db_endpoint" {
  value       = aws_db_instance.vulnerable_db.endpoint
  description = "Endpoint of the vulnerable RDS instance"
  sensitive   = true
}

output "security_group_id" {
  value       = aws_security_group.vulnerable_sg.id
  description = "ID of the vulnerable security group"
}

# Additional vulnerable configurations for comprehensive testing

# 11. VULNERABILITY: ALB without proper security configuration
resource "aws_lb" "vulnerable_alb" {
  name               = "vulnerable-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.vulnerable_sg.id]
  subnets           = [aws_subnet.public_subnet.id, aws_subnet.private_subnet.id]

  # SECURITY ISSUE: No access logs enabled
  # access_logs {
  #   bucket  = aws_s3_bucket.lb_logs.bucket
  #   enabled = true
  # }

  tags = {
    Name = "VulnerableALB"
  }
}

# 12. VULNERABILITY: Lambda function with overly permissive execution role
resource "aws_iam_role" "lambda_role" {
  name = "vulnerable-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# SECURITY ISSUE: Lambda role with admin access
resource "aws_iam_role_policy_attachment" "lambda_admin_policy" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # SECURITY ISSUE: Too permissive
}

# 13. VULNERABILITY: API Gateway without proper authentication
resource "aws_api_gateway_rest_api" "vulnerable_api" {
  name        = "vulnerable-api"
  description = "API Gateway without proper security"

  # SECURITY ISSUE: No authentication/authorization configured
}

resource "aws_api_gateway_resource" "vulnerable_resource" {
  rest_api_id = aws_api_gateway_rest_api.vulnerable_api.id
  parent_id   = aws_api_gateway_rest_api.vulnerable_api.root_resource_id
  path_part   = "vulnerable"
}

resource "aws_api_gateway_method" "vulnerable_method" {
  rest_api_id   = aws_api_gateway_rest_api.vulnerable_api.id
  resource_id   = aws_api_gateway_resource.vulnerable_resource.id
  http_method   = "GET"
  authorization = "NONE"  # SECURITY ISSUE: No authorization required
}