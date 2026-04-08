provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

locals {
  trust_arn = var.trust_principal_arn != null ? var.trust_principal_arn : data.aws_caller_identity.current.arn

  tags = {
    Project   = "accessgraph-benchmark"
    ManagedBy = "terraform"
    Purpose   = "benchmark-scanner"
  }
}

resource "aws_iam_role" "scanner" {
  name                 = "AccessGraphBenchmarkScanner"
  max_session_duration = 28800

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = local.trust_arn }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}
