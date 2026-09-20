# ---------------------------------------------------------------------------
# Telemetry plane: the two streams the AIRCAP detections consume.
#
#   Bedrock model invocation logging -> prompts and completions (what was said)
#   CloudTrail data events           -> who called the model (never the bodies)
#
# The lab's DuckDB views read exactly these schemas, so detections/sql/*.sql runs
# against the Athena tables below with no change beyond the FROM clause.
# ---------------------------------------------------------------------------

resource "aws_kms_key" "telemetry" {
  description             = "AIRCAP telemetry encryption - prompts, completions and control-plane logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  # Written as a policy document rather than relying on the default key policy, so
  # CloudTrail and Bedrock can encrypt without granting either service broad access.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountRootManagesKey"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringLike = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${var.account_id}:trail/*" }
        }
      },
      {
        Sid       = "BedrockLoggingEncrypt"
        Effect    = "Allow"
        Principal = { Service = "bedrock.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.account_id }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "telemetry" {
  name          = "alias/${var.name_prefix}-telemetry"
  target_key_id = aws_kms_key.telemetry.key_id
}

# --- invocation logs (prompts + completions) --------------------------------

resource "aws_s3_bucket" "invocation_logs" {
  # checkov:skip=CKV_AWS_144:Cross-region replication would copy every prompt and completion
  #   into a second region. That doubles storage cost AND doubles the blast radius of the
  #   most sensitive objects in the account. Durability here is not worth that exposure.
  # checkov:skip=CKV2_AWS_62:Detections read this bucket through Athena on a schedule, not
  #   via S3 event notifications. Adding them would create an unused notification path.
  bucket = "${var.name_prefix}-bedrock-invocation-logs-${var.account_id}-${var.region}"
}

resource "aws_s3_bucket_public_access_block" "invocation_logs" {
  bucket                  = aws_s3_bucket.invocation_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "invocation_logs" {
  bucket = aws_s3_bucket.invocation_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.telemetry.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "invocation_logs" {
  bucket = aws_s3_bucket.invocation_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "invocation_logs" {
  bucket = aws_s3_bucket.invocation_logs.id

  rule {
    id     = "expire-prompt-bodies"
    status = "Enabled"

    filter {}

    # Prompts and completions are the highest-sensitivity objects here. Investigation
    # needs weeks, not years.
    expiration {
      days = var.invocation_log_expiry_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Deny any unencrypted-in-transit access. Without this the bucket policy is silent
# on TLS, and "we assumed HTTPS" is not a control.
resource "aws_s3_bucket_policy" "invocation_logs" {
  bucket = aws_s3_bucket.invocation_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.invocation_logs.arn,
          "${aws_s3_bucket.invocation_logs.arn}/*",
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "AllowBedrockLogDelivery"
        Effect    = "Allow"
        Principal = { Service = "bedrock.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.invocation_logs.arn}/AWSLogs/${var.account_id}/BedrockModelInvocationLogs/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.account_id }
          ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock:${var.region}:${var.account_id}:*" }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "invocation_logs" {
  name              = "/aws/bedrock/${var.name_prefix}/invocations"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.telemetry.arn
}

resource "aws_iam_role" "bedrock_logging" {
  name = "${var.name_prefix}-bedrock-logging"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
  })
}

resource "aws_iam_role_policy" "bedrock_logging" {
  name = "write-invocation-logs"
  role = aws_iam_role.bedrock_logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.invocation_logs.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.invocation_logs.arn}/*"
      }
    ]
  })
}

# This is the resource that makes prompt-level detection possible at all. Without it
# CloudTrail proves a model was called and nothing proves what it was asked to do.
resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = false
    image_data_delivery_enabled     = false
    text_data_delivery_enabled      = true
    video_data_delivery_enabled     = false

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.invocation_logs.name
      role_arn       = aws_iam_role.bedrock_logging.arn

      large_data_delivery_s3_config {
        bucket_name = aws_s3_bucket.invocation_logs.id
        key_prefix  = "large-data"
      }
    }

    s3_config {
      bucket_name = aws_s3_bucket.invocation_logs.id
      key_prefix  = "AWSLogs/${var.account_id}/BedrockModelInvocationLogs"
    }
  }

  depends_on = [
    aws_s3_bucket_policy.invocation_logs,
    aws_iam_role_policy.bedrock_logging,
  ]
}

# --- CloudTrail data events (who called the model) --------------------------

resource "aws_s3_bucket" "cloudtrail" {
  # checkov:skip=CKV_AWS_144:See invocation_logs - replication widens exposure of audit data.
  # checkov:skip=CKV2_AWS_62:CloudTrail delivery is consumed via Athena and CloudWatch Logs.
  bucket = "${var.name_prefix}-cloudtrail-${var.account_id}-${var.region}"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.telemetry.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*",
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = { "aws:SourceArn" = "arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/${var.name_prefix}-bedrock" }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${var.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/${var.name_prefix}-bedrock"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "bedrock" {
  name                          = "${var.name_prefix}-bedrock"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  kms_key_id                    = aws_kms_key.telemetry.arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  # Near-real-time delivery alongside the S3 archive. S3 batches every few minutes;
  # for detection D004 that latency is the difference between catching a stolen
  # credential in use and reading about it afterwards.
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_logs.arn
  sns_topic_name             = aws_sns_topic.alerts.name

  # Data events for Bedrock are what detections D003 and D004 read. They are NOT on by
  # default and are billed per event, which is why so many accounts have no record of
  # who invoked a model.
  advanced_event_selector {
    name = "bedrock-model-invocation-data-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::Bedrock::Model"]
    }
  }

  advanced_event_selector {
    name = "management-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_iam_role_policy.cloudtrail_logs,
  ]
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "expire-trail-logs"
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
