output "transaction_bucket_name" {
  description = "S3 bucket that receives transaction uploads."
  value       = aws_s3_bucket.transactions.bucket
}

output "lambda_function_name" {
  description = "Lambda transaction processor function name."
  value       = aws_lambda_function.transaction_processor.function_name
}

output "dynamodb_table_name" {
  description = "DynamoDB table used to store transaction analysis."
  value       = aws_dynamodb_table.transactions.name
}

output "sns_topic_arn" {
  description = "SNS topic ARN used for proactive incident alerts."
  value       = aws_sns_topic.alerts.arn
}

output "web_acl_arn" {
  description = "WAF web ACL ARN managed by Secure-Pay Sentinel."
  value       = local.active_waf_web_acl_arn
}

output "waf_api_region" {
  description = "Region that must be used for WAF API calls."
  value       = local.waf_api_region
}

output "waf_ipv4_ip_set_name" {
  description = "IPv4 WAF IP set name."
  value       = local.active_waf_ipv4_name
}

output "waf_ipv4_ip_set_id" {
  description = "IPv4 WAF IP set ID."
  value       = local.active_waf_ipv4_id
}

output "waf_ipv6_ip_set_name" {
  description = "IPv6 WAF IP set name."
  value       = local.active_waf_ipv6_name
}

output "waf_ipv6_ip_set_id" {
  description = "IPv6 WAF IP set ID."
  value       = local.active_waf_ipv6_id
}
