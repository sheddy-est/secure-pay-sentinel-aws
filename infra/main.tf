provider "aws" {
  region = "us-east-1"
}

# 1. Ingestion Layer: S3 Bucket
resource "aws_s3_bucket" "transaction_ingest" {
  bucket = "secure-pay-sentinel-ingest-${random_id.suffix.hex}"
}

resource "random_id" "suffix" {
  byte_length = 4
}

# 2. Persistence: DynamoDB Table
resource "aws_dynamodb_table" "transactions" {
  name           = "SecurePayTransactions"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "transaction_id"
  
  attribute {
    name = "transaction_id"
    type = "S"
  }
}

# 3. Notification: SNS Topic
resource "aws_sns_topic" "alerts" {
  name = "secure-pay-high-risk-alerts"
}

# (Add an email subscription via AWS Console or CLI manually to confirm the endpoint)

# 4. Active Defense: WAFv2 IP Set
resource "aws_wafv2_ip_set" "blocked_ips" {
  name               = "SecurePayBlockedIPs"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = [] # Starts empty
}

# 5. IAM Role & Least Privilege Policy
resource "aws_iam_role" "lambda_exec" {
  name = "secure_pay_lambda_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "secure_pay_lambda_policy"
  role = aws_iam_role.lambda_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow" # Basic logging
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow" # S3 Read
        Action = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.transaction_ingest.arn}/*"
      },
      {
        Effect = "Allow" # Bedrock Invoke
        Action = ["bedrock:InvokeModel"]
        Resource = "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-sonnet-20240620-v1:0"
      },
      {
        Effect = "Allow" # DynamoDB Write
        Action = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.transactions.arn
      },
      {
        Effect = "Allow" # SNS Publish
        Action = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect = "Allow" # WAF Update
        Action = ["wafv2:GetIPSet", "wafv2:UpdateIPSet"]
        Resource = aws_wafv2_ip_set.blocked_ips.arn
      }
    ]
  })
}

# 6. Lambda Function
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "../src"
  output_path = "lambda_function.zip"
}

resource "aws_lambda_function" "sentinel_processor" {
  filename         = "lambda_function.zip"
  function_name    = "SecurePayAnalyzer"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "app.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.transactions.name
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
      WAF_IPSET_NAME = aws_wafv2_ip_set.blocked_ips.name
      WAF_IPSET_ID   = aws_wafv2_ip_set.blocked_ips.id
      WAF_SCOPE      = "REGIONAL"
    }
  }
}

# 7. S3 Event Trigger for Lambda
resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sentinel_processor.arn
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.transaction_ingest.arn
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.transaction_ingest.id
  lambda_function {
    lambda_function_arn = aws_lambda_function.sentinel_processor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".json"
  }
  depends_on = [aws_lambda_permission.allow_s3]
}
