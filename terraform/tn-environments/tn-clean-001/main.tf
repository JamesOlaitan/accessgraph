provider "aws" {
  region = var.aws_region
}

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

# Policy attachments
# user_1: S3 read-only
resource "aws_iam_user_policy_attachment" "user_1_s3" {
  user       = aws_iam_user.user_1.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# user_2: CloudWatch read-only
resource "aws_iam_user_policy_attachment" "user_2_cw" {
  user       = aws_iam_user.user_2.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

# user_3: S3 + CloudWatch read-only (two policies, one user)
resource "aws_iam_user_policy_attachment" "user_3_s3" {
  user       = aws_iam_user.user_3.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_user_policy_attachment" "user_3_cw" {
  user       = aws_iam_user.user_3.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
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

# Lambda function (side resource — varies environment shape)
data "archive_file" "handler" {
  type        = "zip"
  output_path = "${path.module}/lambda_handler.zip"
  source {
    content  = "def handler(event, context):\n    return {\"status\": \"ok\"}\n"
    filename = "handler.py"
  }
}

resource "aws_lambda_function" "side" {
  filename         = data.archive_file.handler.output_path
  function_name    = "${var.environment_name}-fn"
  role             = aws_iam_role.lambda_role.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.handler.output_base64sha256

  tags = local.tags
}
