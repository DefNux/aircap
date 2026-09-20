output "invocation_log_bucket" {
  description = "S3 bucket holding Bedrock prompts and completions."
  value       = aws_s3_bucket.invocation_logs.id
}

output "cloudtrail_bucket" {
  description = "S3 bucket holding CloudTrail data events for bedrock:InvokeModel."
  value       = aws_s3_bucket.cloudtrail.id
}

output "athena_workgroup" {
  description = "Workgroup to run detections/sql/*.sql against."
  value       = aws_athena_workgroup.detections.name
}

output "glue_database" {
  description = "Glue database holding the telemetry tables."
  value       = aws_glue_catalog_database.telemetry.name
}

output "guardrail_id" {
  description = "Guardrail id required by the mandatory-guardrail IAM condition."
  value       = aws_bedrock_guardrail.baseline.guardrail_id
}

output "application_role_arn" {
  description = "The only principal expected to invoke the model. Detection D004 alerts on anything else."
  value       = aws_iam_role.application.arn
}

output "alert_topic_arn" {
  description = "SNS topic detections publish to."
  value       = aws_sns_topic.alerts.arn
}

output "scp_document_path" {
  description = "Generated SCP to attach at the organisation or OU level. Terraform does not attach it - that is an org-level action taken deliberately."
  value       = local_file.scp_mandatory_guardrail.filename
}
