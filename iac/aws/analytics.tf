# ---------------------------------------------------------------------------
# Athena: the production home of detections/sql/*.sql.
#
# The lab's DuckDB views and these Athena tables expose identical column names, so a
# detection moves between them by changing only the FROM clause.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "athena_results" {
  # checkov:skip=CKV_AWS_144:Query results are a derived, 30-day copy of data that already
  #   exists in the source bucket. Replicating them protects nothing.
  # checkov:skip=CKV2_AWS_62:Nothing consumes Athena results via S3 events.
  bucket = "${var.name_prefix}-athena-results-${var.account_id}-${var.region}"
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.telemetry.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-query-results"
    status = "Enabled"
    filter {}

    # Query results contain prompt excerpts. They are a copy of sensitive data with a
    # shorter useful life than the source.
    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_versioning" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_athena_workgroup" "detections" {
  name        = "${var.name_prefix}-detections"
  description = "Runs the AIRCAP detection library against Bedrock and CloudTrail telemetry"

  configuration {
    enforce_workgroup_configuration         = true
    publish_cloudwatch_metrics_enabled      = true
    enable_minimum_encryption_configuration = true

    # A scan ceiling is the only thing standing between a careless SELECT * and a
    # surprising bill. $5/TB means an unbounded query over months of logs is real money.
    bytes_scanned_cutoff_per_query = 10 * 1024 * 1024 * 1024

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.id}/results/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.telemetry.arn
      }
    }
  }
}

resource "aws_glue_catalog_database" "telemetry" {
  name        = replace("${var.name_prefix}_telemetry", "-", "_")
  description = "AIRCAP AI workload telemetry"
}

# Partition projection rather than a crawler: the key layout is known and fixed, so
# paying a crawler to rediscover it every hour is waste.
resource "aws_glue_catalog_table" "bedrock_invocations" {
  name          = "bedrock_invocations"
  database_name = aws_glue_catalog_database.telemetry.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification"              = "json"
    "projection.enabled"          = "true"
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy/MM/dd/HH"
    "projection.dt.range"         = "2026/01/01/00,NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "HOURS"
    "storage.location.template"   = "s3://${aws_s3_bucket.invocation_logs.id}/AWSLogs/${var.account_id}/BedrockModelInvocationLogs/${var.region}/$${dt}"
    "EXTERNAL"                    = "TRUE"
  }

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.invocation_logs.id}/AWSLogs/${var.account_id}/BedrockModelInvocationLogs/${var.region}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters            = { "ignore.malformed.json" = "true" }
    }

    columns {
      name = "timestamp"
      type = "string"
    }
    columns {
      name = "accountid"
      type = "string"
    }
    columns {
      name = "region"
      type = "string"
    }
    columns {
      name = "requestid"
      type = "string"
    }
    columns {
      name = "operation"
      type = "string"
    }
    columns {
      name = "modelid"
      type = "string"
    }
    columns {
      name = "identity"
      type = "struct<arn:string>"
    }
    columns {
      name = "input"
      type = "struct<inputcontenttype:string,inputbodyjson:string,inputtokencount:int>"
    }
    columns {
      name = "output"
      type = "struct<outputcontenttype:string,outputbodyjson:string,outputtokencount:int>"
    }
    columns {
      name = "guardrailid"
      type = "string"
    }
    columns {
      name = "guardrailaction"
      type = "string"
    }
  }
}
