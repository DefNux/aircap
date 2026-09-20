variable "account_id" {
  description = "AWS account id. A variable rather than aws_caller_identity so plan needs no credentials."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be exactly 12 digits."
  }
}

variable "region" {
  description = "Region for the Bedrock workload and its telemetry."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name, used in tags and resource names."
  type        = string
  default     = "lab"

  validation {
    condition     = contains(["lab", "dev", "stage", "prod"], var.environment)
    error_message = "environment must be one of: lab, dev, stage, prod."
  }
}

variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
  default     = "aircap"
}

variable "log_retention_days" {
  description = "Retention for CloudWatch log groups. 365 is the shortest window that still covers an annual audit."
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days >= 90
    error_message = "Retention under 90 days is below the window most AI incidents are discovered in."
  }
}

variable "invocation_log_expiry_days" {
  description = <<-EOT
    Days before Bedrock invocation logs expire. These records contain full prompts and
    completions, so they are among the most sensitive objects in the account: long
    enough to investigate, short enough to limit exposure.
  EOT
  type        = number
  default     = 180
}

variable "application_role_name" {
  description = "Name of the role the AI application assumes. Only this principal should invoke the model."
  type        = string
  default     = "aircap-app-role"
}

variable "allowed_model_ids" {
  description = "Foundation models the application may invoke. An allowlist, not a wildcard."
  type        = list(string)
  default = [
    "anthropic.claude-sonnet-4-5-20250929-v1:0",
    "anthropic.claude-haiku-4-5-20251001-v1:0",
  ]
}

variable "alert_email" {
  description = "Optional address for detection alerts. Empty disables the subscription."
  type        = string
  default     = ""
}

variable "enable_security_hub" {
  description = "Whether to enable Security Hub. Off by default because it bills per finding."
  type        = bool
  default     = false
}

variable "offline_plan" {
  description = <<-EOT
    Skip the provider's STS credential checks so `terraform plan` runs with no AWS
    credentials and no cost. Verification only - never set true for an apply, which
    is why it defaults to false.
  EOT
  type        = bool
  default     = false
}
