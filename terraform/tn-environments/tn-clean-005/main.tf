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

resource "aws_iam_user" "user_5" {
  name = "${var.environment_name}-user-5"
  tags = local.tags
}

# Policy attachments
# user_1: RDS read-only
resource "aws_iam_user_policy_attachment" "user_1_rds" {
  user       = aws_iam_user.user_1.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess"
}

# user_2: S3 read-only
resource "aws_iam_user_policy_attachment" "user_2_s3" {
  user       = aws_iam_user.user_2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# user_3: RDS + S3 read-only (two policies, one user)
resource "aws_iam_user_policy_attachment" "user_3_rds" {
  user       = aws_iam_user.user_3.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess"
}

resource "aws_iam_user_policy_attachment" "user_3_s3" {
  user       = aws_iam_user.user_3.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# user_4: CloudWatch read-only
resource "aws_iam_user_policy_attachment" "user_4_cw" {
  user       = aws_iam_user.user_4.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

# user_5: EC2 read-only
resource "aws_iam_user_policy_attachment" "user_5_ec2" {
  user       = aws_iam_user.user_5.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

# Lambda role (bare trust — no Condition block)
resource "aws_iam_role" "lambda_role" {
  name = "${var.environment_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
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
