# Secure-pay Sentinel

A serverless pipeline that ingests transaction logs, uses AI to identify fraudulent patterns, and automatically updates AWS WAF rules to block malicious IP addresses.

# Technical Highlights

- Security-First Design: Implemented NACLs, Security Groups, and WAF to protect the transaction perimeter.
- FinOps focus: Built on a pay-as-you-go serverless model, ensuring cost optimization while maintaining 99.9% availability.
- Event-Driven Automation: Reduced remediation time from minutes to milliseconds by automating WAF rule updates via Lambda
  
# AWS Services Used
- Amazon Bedrock
- AWS Lambda
- S3 Bucket
- DynamoDB
- AWS WAF
- IAM
- Amazon SNS
- Terraform (Open Source IaC)
