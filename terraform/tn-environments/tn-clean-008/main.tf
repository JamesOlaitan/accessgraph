provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

locals {
  tags = {
    Project     = "accessgraph-benchmark"
    ManagedBy   = "terraform"
    Environment = var.environment_name
  }
}

# IAM users

resource "aws_iam_user" "user_1" {
  name = "${var.environment_name}-user-1"
  tags = local.tags
}

resource "aws_iam_user" "user_2" {
  name = "${var.environment_name}-user-2"
  tags = local.tags
}

resource "aws_iam_user" "user_3" {
  name = "${var.environment_name}-user-3"
  tags = local.tags
}

resource "aws_iam_user" "user_4" {
  name = "${var.environment_name}-user-4"
  tags = local.tags
}

# Policy attachments
# user_1: CloudWatch read-only
resource "aws_iam_user_policy_attachment" "user_1_cw" {
  user       = aws_iam_user.user_1.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

# user_2: RDS read-only
resource "aws_iam_user_policy_attachment" "user_2_rds" {
  user       = aws_iam_user.user_2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess"
}

# user_3: CloudWatch + RDS read-only (two policies, one user)
resource "aws_iam_user_policy_attachment" "user_3_cw" {
  user       = aws_iam_user.user_3.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

resource "aws_iam_user_policy_attachment" "user_3_rds" {
  user       = aws_iam_user.user_3.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess"
}

# user_4: EC2 read-only
resource "aws_iam_user_policy_attachment" "user_4_ec2" {
  user       = aws_iam_user.user_4.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

# Lambda role (conditional trust — restricts to current account via aws:SourceAccount)
resource "aws_iam_role" "lambda_role" {
  name = "${var.environment_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = local.tags
}

# S3 bucket (side resource — varies environment shape)
resource "aws_s3_bucket" "side" {
  bucket = "${var.environment_name}-${data.aws_caller_identity.current.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "side" {
  bucket                  = aws_s3_bucket.side.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
