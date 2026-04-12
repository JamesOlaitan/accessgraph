# Supplement: add a CloudFormation-assumable role with admin-equivalent
# permissions.
#
# PMapper's cloudformation_edges.py checks whether the destination
# role's trust policy allows cloudformation.amazonaws.com to assume it.
# Without such a role, PMapper produces 0 edges for this scenario.

resource "aws_iam_role" "privesc20-cf-execution-role" {
  name = "privesc20-cf-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "cloudformation.amazonaws.com"
        }
      },
    ]
  })

  managed_policy_arns = [aws_iam_policy.privesc-sre-admin-policy.arn]
}
