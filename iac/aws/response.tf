# ---------------------------------------------------------------------------
# Detection -> alert path. EventBridge to Lambda to SNS.
#
# No automated containment. See lambda/handler.py for why: a containment action
# inherits the false positives of the detection that triggered it, and this project
# has already seen a runbook quarantine two legitimate documents.
# ---------------------------------------------------------------------------

data "archive_file" "responder" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/generated/responder.zip"
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-detections"
  kms_master_key_id = aws_kms_key.telemetry.arn
}

resource "aws_sns_topic_subscription" "email" {
  count = var.alert_email == "" ? 0 : 1

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_iam_role" "responder" {
  name = "${var.name_prefix}-responder"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
  })
}

resource "aws_cloudwatch_log_group" "responder" {
  name              = "/aws/lambda/${var.name_prefix}-responder"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.telemetry.arn
}

resource "aws_iam_role_policy" "responder" {
  name = "publish-and-log"
  role = aws_iam_role.responder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.responder.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.telemetry.arn
      },
      {
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.responder_dlq.arn
      },
      {
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "responder" {
  # checkov:skip=CKV_AWS_117:The function reaches only SNS and CloudWatch Logs. Putting it in
  #   a VPC would require NAT or interface endpoints - real cost, no security gain, and it
  #   would add a failure mode to the alerting path.
  # checkov:skip=CKV_AWS_272:Code signing needs a Signer profile and a publishing pipeline.
  #   Worth adding when this is deployed from CI; premature while the artifact is built by
  #   the archive provider from a single local file.
  function_name    = "${var.name_prefix}-responder"
  role             = aws_iam_role.responder.arn
  handler          = "handler.handler"
  runtime          = "python3.13"
  filename         = data.archive_file.responder.output_path
  source_code_hash = data.archive_file.responder.output_base64sha256
  timeout          = 30
  memory_size      = 256
  kms_key_arn      = aws_kms_key.telemetry.arn

  # A runaway detection loop must not be able to consume the account's whole
  # concurrency budget and take unrelated functions down with it.
  reserved_concurrent_executions = 5

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.responder_dlq.arn
  }

  environment {
    variables = {
      ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
      CONTAIN_DRY_RUN = "true"
    }
  }

  # Without this, the first invocation races log-group creation and Lambda creates an
  # unencrypted group with infinite retention.
  depends_on = [
    aws_cloudwatch_log_group.responder,
    aws_iam_role_policy.responder,
  ]
}

resource "aws_cloudwatch_event_rule" "detections" {
  name        = "${var.name_prefix}-detections"
  description = "Routes AIRCAP detection findings to the responder"

  event_pattern = jsonencode({
    source      = ["aircap.detections"]
    detail-type = ["AI Workload Detection"]
    detail = {
      severity = ["critical", "high"]
    }
  })
}

resource "aws_cloudwatch_event_target" "responder" {
  rule      = aws_cloudwatch_event_rule.detections.name
  target_id = "responder"
  arn       = aws_lambda_function.responder.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detections.arn
}

# Cost-attack alarm. This is the preventive half of residual risk A08, which the lab
# could only detect: nothing in the application stops a sub-ceiling token flood.
resource "aws_cloudwatch_metric_alarm" "invocation_volume" {
  alarm_name          = "${var.name_prefix}-invocation-volume"
  alarm_description   = "Sustained Bedrock invocation volume - maps to detection D012"
  namespace           = "AWS/Bedrock"
  metric_name         = "Invocations"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 500
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "guardrail_intervention_rate" {
  alarm_name          = "${var.name_prefix}-guardrail-interventions"
  alarm_description   = "Spike in guardrail interventions - probing or a prompt-injection campaign"
  namespace           = "AWS/Bedrock"
  metric_name         = "InvocationsIntervened"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_securityhub_account" "main" {
  count = var.enable_security_hub ? 1 : 0
}
