# Supplement: add a Lambda-assumable role with admin-equivalent permissions.
#
# PMapper's lambda_edges.py checks whether the destination role's trust
# policy allows lambda.amazonaws.com to assume it. Without a role that
# trusts the Lambda service, PMapper's edge module skips all roles and
# produces 0 edges for this scenario. This supplement creates such a
# role and attaches the SRE admin policy so PMapper can construct a
# PassRole edge from the scenario user to the Lambda execution role.

resource "aws_iam_role" "privesc15-lambda-execution-role" {
  name = "privesc15-lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })

  managed_policy_arns = [aws_iam_policy.privesc-sre-admin-policy.arn]
}
