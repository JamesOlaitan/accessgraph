# Supplement: add an EC2-assumable role with admin-equivalent permissions
# and an instance profile.
#
# PMapper's ec2_edges.py checks whether the destination role's trust
# policy allows ec2.amazonaws.com to assume it. Without such a role,
# PMapper produces 0 edges for this scenario.
#
# The instance profile is required because the scenario user has
# ec2:AssociateIamInstanceProfile but NOT iam:CreateInstanceProfile.
# PMapper's EC2 edge module checks node_destination.instance_profile
# and skips nodes without one if the source cannot create profiles.

resource "aws_iam_role" "privesc3-ec2-execution-role" {
  name = "privesc3-ec2-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  managed_policy_arns = [aws_iam_policy.privesc-sre-admin-policy.arn]
}

resource "aws_iam_instance_profile" "privesc3-ec2-execution-profile" {
  name = "privesc3-ec2-execution-profile"
  role = aws_iam_role.privesc3-ec2-execution-role.name
}
