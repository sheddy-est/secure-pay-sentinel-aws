data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  name_prefix          = lower(replace(var.project_name, "_", "-"))
  bucket_name          = substr("${local.name_prefix}-${data.aws_caller_identity.current.account_id}-${var.aws_region}-tx", 0, 63)
  lambda_function_name = "${local.name_prefix}-processor"
  dynamodb_table_name  = "${local.name_prefix}-transactions"
  sns_topic_name       = "${local.name_prefix}-alerts"
  waf_ipv4_name        = "${local.name_prefix}-blocked-ipv4"
  waf_ipv6_name        = "${local.name_prefix}-blocked-ipv6"
  waf_web_acl_name     = "${local.name_prefix}-web-acl"
  waf_api_region       = var.waf_scope == "CLOUDFRONT" ? "us-east-1" : var.aws_region
  bedrock_is_inference_profile = length([
    for prefix in ["global.", "us.", "eu.", "au.", "apac."] : prefix
    if startswith(var.bedrock_model_id, prefix)
  ]) > 0
  bedrock_foundation_model_id = local.bedrock_is_inference_profile ? trimprefix(
    trimprefix(
      trimprefix(
        trimprefix(
          trimprefix(var.bedrock_model_id, "global."),
          "us.",
        ),
        "eu.",
      ),
      "au.",
    ),
    "apac.",
  ) : var.bedrock_model_id
  bedrock_model_arn             = "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}::foundation-model/${var.bedrock_model_id}"
  bedrock_inference_profile_arn = "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:inference-profile/${var.bedrock_model_id}"
  bedrock_profile_foundation_model_arns = [
    for region in distinct(concat([var.aws_region], var.bedrock_inference_profile_regions)) :
    "arn:${data.aws_partition.current.partition}:bedrock:${region}::foundation-model/${local.bedrock_foundation_model_id}"
  ]
  bedrock_invoke_resources = local.bedrock_is_inference_profile ? concat(
    [local.bedrock_inference_profile_arn],
    local.bedrock_profile_foundation_model_arns
  ) : [local.bedrock_model_arn]

  common_tags = merge(
    {
      Application = "Secure-Pay Sentinel"
      ManagedBy   = "Terraform"
      Project     = var.project_name
    },
    var.tags
  )
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/secure-pay-sentinel-lambda.zip"
  excludes    = ["__pycache__", "__pycache__/*", "*.pyc"]
}

resource "aws_s3_bucket" "transactions" {
  bucket        = local.bucket_name
  force_destroy = var.force_destroy_bucket
  tags          = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "transactions" {
  bucket = aws_s3_bucket.transactions.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "transactions" {
  bucket = aws_s3_bucket.transactions.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "transactions" {
  bucket = aws_s3_bucket.transactions.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_dynamodb_table" "transactions" {
  name         = local.dynamodb_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "transaction_id"
  range_key    = "ingested_at"

  attribute {
    name = "transaction_id"
    type = "S"
  }

  attribute {
    name = "ingested_at"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  ttl {
    attribute_name = "ttl_epoch"
    enabled        = true
  }

  tags = local.common_tags
}

resource "aws_sns_topic" "alerts" {
  name = local.sns_topic_name
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_wafv2_ip_set" "blocked_ipv4_regional" {
  count = var.waf_scope == "REGIONAL" ? 1 : 0

  name               = local.waf_ipv4_name
  description        = "Secure-Pay Sentinel IPv4 block list."
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []
  tags               = local.common_tags
}

resource "aws_wafv2_ip_set" "blocked_ipv6_regional" {
  count = var.waf_scope == "REGIONAL" ? 1 : 0

  name               = local.waf_ipv6_name
  description        = "Secure-Pay Sentinel IPv6 block list."
  scope              = "REGIONAL"
  ip_address_version = "IPV6"
  addresses          = []
  tags               = local.common_tags
}

resource "aws_wafv2_web_acl" "regional" {
  count = var.waf_scope == "REGIONAL" ? 1 : 0

  name        = local.waf_web_acl_name
  description = "Web ACL managed by Secure-Pay Sentinel."
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "BlockHighRiskIPv4"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked_ipv4_regional[0].arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-ipv4-blocks"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "BlockHighRiskIPv6"
    priority = 2

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked_ipv6_regional[0].arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-ipv6-blocks"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-web-acl"
    sampled_requests_enabled   = true
  }

  tags = local.common_tags
}

resource "aws_wafv2_ip_set" "blocked_ipv4_cloudfront" {
  count    = var.waf_scope == "CLOUDFRONT" ? 1 : 0
  provider = aws.us_east_1

  name               = local.waf_ipv4_name
  description        = "Secure-Pay Sentinel IPv4 block list."
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = []
  tags               = local.common_tags
}

resource "aws_wafv2_ip_set" "blocked_ipv6_cloudfront" {
  count    = var.waf_scope == "CLOUDFRONT" ? 1 : 0
  provider = aws.us_east_1

  name               = local.waf_ipv6_name
  description        = "Secure-Pay Sentinel IPv6 block list."
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV6"
  addresses          = []
  tags               = local.common_tags
}

resource "aws_wafv2_web_acl" "cloudfront" {
  count    = var.waf_scope == "CLOUDFRONT" ? 1 : 0
  provider = aws.us_east_1

  name        = local.waf_web_acl_name
  description = "Web ACL managed by Secure-Pay Sentinel."
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "BlockHighRiskIPv4"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked_ipv4_cloudfront[0].arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-ipv4-blocks"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "BlockHighRiskIPv6"
    priority = 2

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked_ipv6_cloudfront[0].arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-ipv6-blocks"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-web-acl"
    sampled_requests_enabled   = true
  }

  tags = local.common_tags
}

locals {
  active_waf_ipv4_name = var.waf_scope == "REGIONAL" ? aws_wafv2_ip_set.blocked_ipv4_regional[0].name : aws_wafv2_ip_set.blocked_ipv4_cloudfront[0].name
  active_waf_ipv4_id   = var.waf_scope == "REGIONAL" ? aws_wafv2_ip_set.blocked_ipv4_regional[0].id : aws_wafv2_ip_set.blocked_ipv4_cloudfront[0].id
  active_waf_ipv4_arn  = var.waf_scope == "REGIONAL" ? aws_wafv2_ip_set.blocked_ipv4_regional[0].arn : aws_wafv2_ip_set.blocked_ipv4_cloudfront[0].arn

  active_waf_ipv6_name = var.waf_scope == "REGIONAL" ? aws_wafv2_ip_set.blocked_ipv6_regional[0].name : aws_wafv2_ip_set.blocked_ipv6_cloudfront[0].name
  active_waf_ipv6_id   = var.waf_scope == "REGIONAL" ? aws_wafv2_ip_set.blocked_ipv6_regional[0].id : aws_wafv2_ip_set.blocked_ipv6_cloudfront[0].id
  active_waf_ipv6_arn  = var.waf_scope == "REGIONAL" ? aws_wafv2_ip_set.blocked_ipv6_regional[0].arn : aws_wafv2_ip_set.blocked_ipv6_cloudfront[0].arn

  active_waf_web_acl_arn = var.waf_scope == "REGIONAL" ? aws_wafv2_web_acl.regional[0].arn : aws_wafv2_web_acl.cloudfront[0].arn
}

resource "aws_wafv2_web_acl_association" "regional_target" {
  count = var.waf_scope == "REGIONAL" && var.protected_resource_arn != "" ? 1 : 0

  resource_arn = var.protected_resource_arn
  web_acl_arn  = local.active_waf_web_acl_arn
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.lambda_function_name}"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_iam_role" "lambda_execution" {
  name = "${local.name_prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "lambda_execution" {
  name = "${local.name_prefix}-lambda-policy"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadTransactionsFromS3"
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.transactions.arn}/${var.ingestion_prefix}*"
      },
      {
        Sid    = "WriteToTransactionTable"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
        ]
        Resource = aws_dynamodb_table.transactions.arn
      },
      {
        Sid    = "PublishIncidentAlerts"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid    = "InvokeConfiguredBedrockModel"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel"
        ]
        Resource = local.bedrock_invoke_resources
      },
      {
        Sid    = "ManageDedicatedWafIpSets"
        Effect = "Allow"
        Action = [
          "wafv2:GetIPSet",
          "wafv2:UpdateIPSet"
        ]
        Resource = [
          local.active_waf_ipv4_arn,
          local.active_waf_ipv6_arn
        ]
      },
      {
        Sid    = "WriteLambdaLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda.arn}:*"
      }
    ]
  })
}

resource "aws_lambda_function" "transaction_processor" {
  function_name = local.lambda_function_name
  role          = aws_iam_role.lambda_execution.arn
  runtime       = "python3.13"
  handler       = "handler.lambda_handler"
  filename      = data.archive_file.lambda_zip.output_path

  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout
  architectures    = [var.lambda_architecture]

  environment {
    variables = {
      BEDROCK_MODEL_ID  = var.bedrock_model_id
      LOG_LEVEL         = "INFO"
      RISK_THRESHOLD    = tostring(var.risk_threshold)
      RETENTION_DAYS    = tostring(var.retention_days)
      SNS_TOPIC_ARN     = aws_sns_topic.alerts.arn
      TABLE_NAME        = aws_dynamodb_table.transactions.name
      WAF_IPV4_SET_ID   = local.active_waf_ipv4_id
      WAF_IPV4_SET_NAME = local.active_waf_ipv4_name
      WAF_IPV6_SET_ID   = local.active_waf_ipv6_id
      WAF_IPV6_SET_NAME = local.active_waf_ipv6_name
      WAF_REGION        = local.waf_api_region
      WAF_SCOPE         = var.waf_scope
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda_execution
  ]

  tags = local.common_tags
}

resource "aws_lambda_permission" "allow_s3" {
  statement_id   = "AllowExecutionFromS3"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.transaction_processor.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.transactions.arn
  source_account = data.aws_caller_identity.current.account_id
}

resource "aws_s3_bucket_notification" "transactions" {
  bucket = aws_s3_bucket.transactions.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.transaction_processor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = var.ingestion_prefix
    filter_suffix       = ".json"
  }

  depends_on = [aws_lambda_permission.allow_s3]
}
