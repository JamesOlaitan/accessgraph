variable "trust_principal_arn" {
  description = "ARN of the IAM principal allowed to assume the scanner role. When null, the trust policy grants access to the principal running Terraform (resolved via aws_caller_identity)."
  type        = string
  default     = null
}

variable "aws_region" {
  description = "AWS region for the provider configuration. IAM is global; this only affects regional API endpoints."
  type        = string
  default     = "us-east-1"
}
