variable "aws_region" {
  type = string
}

variable "state_bucket_name" {
  description = "Globally unique name for the CloudSentinel Terraform state bucket."
  type        = string
}
