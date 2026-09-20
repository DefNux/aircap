# ---------------------------------------------------------------------------
# S3 access logging for the telemetry buckets.
#
# Thematically the most important bucket here: reading Bedrock invocation logs means
# reading every prompt and completion the application ever saw. Who does that should
# itself be audited, which is why this exists rather than being suppressed as
# "logging the logs".
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "access_logs" {
  # checkov:skip=CKV_AWS_18:This IS the access-log target; logging its own reads would recurse.
  # checkov:skip=CKV_AWS_145:S3 server access logging cannot deliver to an SSE-KMS bucket -
  #   an AWS platform constraint, not a choice. SSE-S3 with bucket keys is the strongest
  #   option available for this specific bucket.
  # checkov:skip=CKV_AWS_144:Cross-region replication of access logs doubles cost for no investigative gain.
  # checkov:skip=CKV2_AWS_62:Detection reads these via Athena, not S3 event notifications.
  bucket = "${var.name_prefix}-access-logs-${var.account_id}-${var.region}"
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      # S3 server access logging cannot write to an SSE-KMS bucket, so this one uses
      # SSE-S3. A real constraint, not an oversight.
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.access_logs.arn,
          "${aws_s3_bucket.access_logs.arn}/*",
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "AllowS3ServerAccessLogging"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.access_logs.arn}/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.account_id }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_logging" "invocation_logs" {
  bucket        = aws_s3_bucket.invocation_logs.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "invocation-logs/"
}

resource "aws_s3_bucket_logging" "cloudtrail" {
  bucket        = aws_s3_bucket.cloudtrail.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "cloudtrail/"
}

resource "aws_s3_bucket_logging" "athena_results" {
  bucket        = aws_s3_bucket.athena_results.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "athena-results/"
}

# --- CloudTrail to CloudWatch Logs -----------------------------------------
# S3 delivery is batched every few minutes; CloudWatch Logs is near-real-time. For
# detection D004 (unauthorized principal invoking the model) that latency difference
# is the gap between catching a stolen credential and reading about it later.

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.name_prefix}-bedrock"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.telemetry.arn
}

resource "aws_iam_role" "cloudtrail_logs" {
  name = "${var.name_prefix}-cloudtrail-to-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name = "write-to-log-group"
  role = aws_iam_role.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

# --- Lambda hardening -------------------------------------------------------

resource "aws_sqs_queue" "responder_dlq" {
  name                              = "${var.name_prefix}-responder-dlq"
  kms_master_key_id                 = aws_kms_key.telemetry.arn
  kms_data_key_reuse_period_seconds = 300
  message_retention_seconds         = 1209600
}

resource "aws_sqs_queue_policy" "responder_dlq" {
  queue_url = aws_sqs_queue.responder_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "sqs:*"
      Resource  = aws_sqs_queue.responder_dlq.arn
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
