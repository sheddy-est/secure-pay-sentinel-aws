import json
import boto3
import os
import urllib.parse
from datetime import datetime

# Initialize AWS clients
s3 = boto3.client('s3')
bedrock = boto3.client('bedrock-runtime')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')
wafv2 = boto3.client('wafv2')

# Environment Variables
DDB_TABLE = os.environ['DYNAMODB_TABLE']
SNS_TOPIC = os.environ['SNS_TOPIC_ARN']
WAF_NAME = os.environ['WAF_IPSET_NAME']
WAF_ID = os.environ['WAF_IPSET_ID']
WAF_SCOPE = os.environ['WAF_SCOPE']

def lambda_handler(event, context):
    table = dynamodb.Table(DDB_TABLE)
    
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(record['s3']['object']['key'])
        
        try:
            # 1. Ingestion: Fetch the transaction file
            response = s3.get_object(Bucket=bucket, Key=key)
            transaction_data = json.loads(response['Body'].read().decode('utf-8'))
            
            tx_id = transaction_data.get('transaction_id', 'unknown')
            source_ip = transaction_data.get('source_ip')
            
            # 2. Intelligence: Analyze with Bedrock (Claude 3.5 Sonnet)
            prompt = f"""
            Analyze this fintech transaction for signs of 'Man-in-the-Middle' or 'SQL Injection' attacks based on the payload. 
            Return ONLY a valid JSON object with two keys: "risk_score" (integer 1-10) and "reasoning" (string). 
            Transaction Payload: {json.dumps(transaction_data)}
            """
            
            bedrock_payload = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 512,
                "messages": [{"role": "user", "content": prompt}]
            }
            
            bedrock_response = bedrock.invoke_model(
                modelId='anthropic.claude-3-5-sonnet-20240620-v1:0',
                contentType='application/json',
                accept='application/json',
                body=json.dumps(bedrock_payload)
            )
            
            response_body = json.loads(bedrock_response['body'].read())
            ai_output = response_body['content'][0]['text']
            
            # Parse AI output
            analysis = json.loads(ai_output)
            risk_score = analysis.get('risk_score', 0)
            reasoning = analysis.get('reasoning', '')
            
            print(f"Transaction {tx_id} | Risk Score: {risk_score}")
            
            # 3. Persistence: Store in DynamoDB
            table.put_item(Item={
                'transaction_id': tx_id,
                'timestamp': datetime.utcnow().isoformat(),
                'source_ip': source_ip,
                'risk_score': risk_score,
                'reasoning': reasoning,
                'raw_payload': json.dumps(transaction_data)
            })
            
            # 4. Active Defense & Notification
            if risk_score > 8:
                # Trigger SNS
                sns.publish(
                    TopicArn=SNS_TOPIC,
                    Subject=f"CRITICAL: High Risk Transaction Detected ({tx_id})",
                    Message=f"Risk Score: {risk_score}\nReasoning: {reasoning}\nSource IP: {source_ip}"
                )
                
                # Update WAF IP Set to block the IP
                if source_ip:
                    block_ip_in_waf(source_ip)
                    
        except Exception as e:
            print(f"Error processing object {key} from bucket {bucket}. Error: {str(e)}")
            raise e

def block_ip_in_waf(ip_address):
    # WAF requires IPs in CIDR notation (e.g., /32 for a single IP)
    cidr_ip = f"{ip_address}/32"
    
    try:
        # First, get the current IP set and its LockToken (required for updates)
        response = wafv2.get_ip_set(
            Name=WAF_NAME,
            Scope=WAF_SCOPE,
            Id=WAF_ID
        )
        
        lock_token = response['LockToken']
        current_addresses = response['IPSet']['Addresses']
        
        if cidr_ip not in current_addresses:
            current_addresses.append(cidr_ip)
            
            # Update the IP set
            wafv2.update_ip_set(
                Name=WAF_NAME,
                Scope=WAF_SCOPE,
                Id=WAF_ID,
                Addresses=current_addresses,
                LockToken=lock_token
            )
            print(f"Successfully added {cidr_ip} to WAF blocklist.")
        else:
            print(f"IP {cidr_ip} is already in the WAF blocklist.")
            
    except Exception as e:
        print(f"Failed to update WAF: {str(e)}")
