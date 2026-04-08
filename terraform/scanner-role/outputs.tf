output "role_arn" {
  description = "ARN of the AccessGraphBenchmarkScanner IAM role."
  value       = aws_iam_role.scanner.arn
}

output "role_name" {
  description = "Name of the AccessGraphBenchmarkScanner IAM role."
  value       = aws_iam_role.scanner.name
}

output "max_session_duration" {
  description = "Maximum session duration in seconds (28800 = 8 hours)."
  value       = aws_iam_role.scanner.max_session_duration
}
