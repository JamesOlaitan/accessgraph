output "user_arns" {
  description = "ARNs of all IAM users created in this TN environment."
  value = [
    aws_iam_user.user_1.arn,
    aws_iam_user.user_2.arn,
    aws_iam_user.user_3.arn,
  ]
}

output "role_arn" {
  description = "ARN of the lambda-trust IAM role."
  value       = aws_iam_role.lambda_role.arn
}

output "environment_name" {
  description = "Logical name of this TN environment."
  value       = var.environment_name
}
