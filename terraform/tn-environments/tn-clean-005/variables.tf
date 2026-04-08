variable "aws_region" {
  description = "AWS region for the provider configuration."
  type        = string
  default     = "us-east-1"
}

variable "environment_name" {
  description = "Logical name for this TN environment. Used in resource names and tags."
  type        = string
  default     = "tn-clean-005"
}
