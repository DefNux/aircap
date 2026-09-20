terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.6"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

# No data sources requiring live API calls (no aws_caller_identity, no aws_region).
# Account id and region arrive as variables instead, which keeps `terraform plan`
# runnable with no credentials and therefore at zero cost - the constraint this whole
# project is built under.
provider "aws" {
  region = var.region

  # The AWS provider calls STS GetCallerIdentity at plan time, so a plan normally
  # needs live credentials. Under this project's zero-spend constraint that is not
  # available, so offline verification skips those checks explicitly. Default is
  # false: real deployments must validate credentials.
  skip_credentials_validation = var.offline_plan
  skip_requesting_account_id  = var.offline_plan
  skip_metadata_api_check     = var.offline_plan

  default_tags {
    tags = {
      Project     = "AIRCAP"
      ManagedBy   = "terraform"
      Purpose     = "AI workload incident response telemetry and controls"
      Environment = var.environment
    }
  }
}
