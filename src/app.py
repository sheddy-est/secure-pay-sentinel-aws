import ipaddress
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
from typing import Any
from urllib.parse import unquote_plus

import boto3
from botocore.exceptions import ClientError


LOGGER = logging.getLogger()
LOGGER.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

TABLE_NAME = os.environ["TABLE_NAME"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
BEDROCK_MODEL_ID = os.environ["BEDROCK_MODEL_ID"]
RISK_THRESHOLD = int(os.getenv("RISK_THRESHOLD", "8"))
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))
WAF_SCOPE = os.getenv("WAF_SCOPE", "REGIONAL")
WAF_REGION = os.getenv("WAF_REGION", "us-east-1")

WAF_IP_SETS = {
    4: {
        "name": os.getenv("WAF_IPV4_SET_NAME", ""),
        "id": os.getenv("WAF_IPV4_SET_ID", ""),
    },
    6: {
        "name": os.getenv("WAF_IPV6_SET_NAME", ""),
        "id": os.getenv("WAF_IPV6_SET_ID", ""),
    },
}

SYSTEM_PROMPT = (
    "You are Secure-Pay Sentinel, a fintech transaction security analyst. "
    "Review the provided transaction for signs of SQL injection, man-in-the-middle, "
    "payload tampering, header anomalies, replay indicators, or suspicious routing. "
    "Return only valid JSON with these keys: "
    "risk_score, risk_level, detected_attack_types, recommended_action, summary, evidence. "
    "risk_score must be an integer from 1 to 10. "
    "risk_level must be LOW, MEDIUM, HIGH, or CRITICAL. "
    "recommended_action must be allow, monitor, or block. "
    "detected_attack_types and evidence must be arrays of strings."
)

SQLI_PATTERNS = [
    r"(?i)\bunion\s+select\b",
    r"(?i)\bor\s+1=1\b",
    r"(?i)\bdrop\s+table\b",
    r"(?i)\bsleep\s*\(",
    r"(?i)--",
]

MITM_PATTERNS = [
    r"(?i)certificate[-_\s]?mismatch",
    r"(?i)tls1\.0",
    r"(?i)sslstrip",
    r"(?i)replay",
    r"(?i)proxy",
    r"(?i)session[-_\s]?integrity",
]

s3_client = boto3.client("s3")
sns_client = boto3.client("sns")
bedrock_client = boto3.client("bedrock-runtime")
waf_client = boto3.client("wafv2", region_name=WAF_REGION)
dynamodb_resource = boto3.resource("dynamodb")
table = dynamodb_resource.Table(TABLE_NAME)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context

    summary = {
        "files_processed": 0,
        "transactions_processed": 0,
        "alerts_sent": 0,
        "blocked_ips": 0,
        "errors": [],
        "results": [],
    }

    for record in event.get("Records", []):
        if record.get("eventSource") != "aws:s3":
            continue

        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])
        summary["files_processed"] += 1

        try:
            transactions = _load_transactions(bucket, key)
        except Exception as exc:
            LOGGER.exception("Failed to load transactions from s3://%s/%s", bucket, key)
            summary["errors"].append(
                {
                    "bucket": bucket,
                    "key": key,
                    "error": str(exc),
                }
            )
            continue

        for position, transaction in enumerate(transactions):
            try:
                result = _process_transaction(transaction, bucket, key, position)
                summary["transactions_processed"] += 1
                summary["alerts_sent"] += int(result["alert_sent"])
                summary["blocked_ips"] += int(result["waf_block_applied"])
                summary["results"].append(result)
            except Exception as exc:
                LOGGER.exception(
                    "Transaction processing failed for s3://%s/%s position=%s",
                    bucket,
                    key,
                    position,
                )
                summary["errors"].append(
                    {
                        "bucket": bucket,
                        "key": key,
                        "position": position,
                        "error": str(exc),
                    }
                )

    LOGGER.info("Processing summary: %s", json.dumps(summary, default=_json_default))
    return summary


def _load_transactions(bucket: str, key: str) -> list[dict[str, Any]]:
    response = s3_client.get_object(Bucket=bucket, Key=key)
    body = response["Body"].read().decode("utf-8")
    payload = json.loads(body, parse_float=Decimal)

    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict) and isinstance(payload.get("transactions"), list):
        records = payload["transactions"]
    else:
        records = [payload]

    normalized: list[dict[str, Any]] = []
    for record in records:
        if isinstance(record, dict):
            normalized.append(record)
        else:
            normalized.append({"raw_record": record})

    return normalized


def _process_transaction(
    transaction: dict[str, Any],
    bucket: str,
    key: str,
    position: int,
) -> dict[str, Any]:
    ingested_at = _utc_now().isoformat()
    transaction_id = _resolve_transaction_id(transaction, bucket, key, position)
    source_ip = _extract_source_ip(transaction)

    analysis = _analyze_transaction(transaction)
    risk_score = _clamp_int(analysis["risk_score"], minimum=1, maximum=10)

    alert_required = risk_score > RISK_THRESHOLD
    alert_sent = False
    alert_error = None

    waf_block_applied = False
    blocked_cidr = None
    waf_error = None

    if alert_required:
        try:
            _publish_alert(transaction_id, source_ip, risk_score, analysis, bucket, key)
            alert_sent = True
        except ClientError as exc:
            alert_error = _format_client_error(exc)
            LOGGER.exception("SNS publish failed for transaction %s", transaction_id)

        if source_ip:
            try:
                waf_result = _update_waf_ip_set(source_ip)
                waf_block_applied = waf_result["updated"]
                blocked_cidr = waf_result["cidr"]
            except Exception as exc:
                waf_error = str(exc)
                LOGGER.exception("WAF update failed for transaction %s", transaction_id)

    item = {
        "transaction_id": transaction_id,
        "ingested_at": ingested_at,
        "ttl_epoch": int((_utc_now() + timedelta(days=RETENTION_DAYS)).timestamp()),
        "s3_bucket": bucket,
        "s3_key": key,
        "record_position": position,
        "source_ip": source_ip or "unknown",
        "risk_score": Decimal(str(risk_score)),
        "risk_level": analysis["risk_level"],
        "recommended_action": analysis["recommended_action"],
        "detected_attack_types": analysis["detected_attack_types"],
        "summary": analysis["summary"],
        "evidence": analysis["evidence"],
        "analysis_provider": analysis["analysis_provider"],
        "alert_required": alert_required,
        "alert_sent": alert_sent,
        "alert_error": alert_error,
        "waf_block_applied": waf_block_applied,
        "blocked_cidr": blocked_cidr,
        "waf_error": waf_error,
        "transaction": _to_dynamodb_value(transaction),
    }

    table.put_item(Item=_strip_none(item))

    return {
        "transaction_id": transaction_id,
        "risk_score": risk_score,
        "source_ip": source_ip,
        "alert_sent": alert_sent,
        "waf_block_applied": waf_block_applied,
    }


def _analyze_transaction(transaction: dict[str, Any]) -> dict[str, Any]:
    user_prompt = (
        "Analyze this fintech transaction for signs of Man-in-the-Middle or SQL Injection "
        "attacks based on the payload. Return a risk score 1-10.\n\n"
        "Transaction JSON:\n"
        f"{json.dumps(transaction, default=_json_default, sort_keys=True)}"
    )

    try:
        response = bedrock_client.converse(
            modelId=BEDROCK_MODEL_ID,
            system=[{"text": SYSTEM_PROMPT}],
            messages=[
                {
                    "role": "user",
                    "content": [{"text": user_prompt}],
                }
            ],
            inferenceConfig={
                "maxTokens": 500,
                "temperature": 0,
            },
        )
        response_text = _extract_bedrock_text(response)
        parsed = _extract_json_object(response_text)
        normalized = _normalize_analysis(parsed)
        normalized["analysis_provider"] = "bedrock"
        return normalized
    except Exception as exc:
        LOGGER.exception("Bedrock analysis failed, using heuristic fallback")
        fallback = _heuristic_fallback(transaction)
        fallback["analysis_provider"] = "heuristic-fallback"
        fallback["evidence"].append(f"Bedrock fallback reason: {str(exc)}")
        return fallback


def _extract_bedrock_text(response: dict[str, Any]) -> str:
    content = response["output"]["message"]["content"]
    parts = []
    for block in content:
        text = block.get("text")
        if text:
            parts.append(text)

    if not parts:
        raise ValueError("Bedrock response did not contain a text block.")

    return "\n".join(parts).strip()


def _extract_json_object(text: str) -> dict[str, Any]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        parsed = json.loads(text[start : end + 1])

    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object from Bedrock.")

    return parsed


def _normalize_analysis(raw: dict[str, Any]) -> dict[str, Any]:
    risk_score = _clamp_int(raw.get("risk_score", 1), minimum=1, maximum=10)
    risk_level = str(raw.get("risk_level") or _risk_level_from_score(risk_score)).upper()

    if risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        risk_level = _risk_level_from_score(risk_score)

    recommended_action = str(
        raw.get("recommended_action") or _action_from_score(risk_score)
    ).lower()

    if recommended_action not in {"allow", "monitor", "block"}:
        recommended_action = _action_from_score(risk_score)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "recommended_action": recommended_action,
        "detected_attack_types": _string_list(raw.get("detected_attack_types")),
        "summary": str(raw.get("summary") or "No summary returned by model."),
        "evidence": _string_list(raw.get("evidence")),
    }


def _heuristic_fallback(transaction: dict[str, Any]) -> dict[str, Any]:
    serialized = json.dumps(transaction, default=_json_default, sort_keys=True)
    lowered = serialized.lower()

    evidence = []
    attack_types = []
    risk_score = 2

    if any(re.search(pattern, lowered) for pattern in SQLI_PATTERNS):
        evidence.append("Static signature matched SQL injection indicators.")
        attack_types.append("SQL_INJECTION")
        risk_score = max(risk_score, 9)

    if any(re.search(pattern, lowered) for pattern in MITM_PATTERNS):
        evidence.append("Static signature matched man-in-the-middle indicators.")
        attack_types.append("MAN_IN_THE_MIDDLE")
        risk_score = max(risk_score, 8)

    if not evidence:
        evidence.append("No static attack indicators matched.")

    return {
        "risk_score": risk_score,
        "risk_level": _risk_level_from_score(risk_score),
        "recommended_action": _action_from_score(risk_score),
        "detected_attack_types": attack_types,
        "summary": "Heuristic fallback analysis used because Bedrock response handling failed.",
        "evidence": evidence,
    }


def _publish_alert(
    transaction_id: str,
    source_ip: str | None,
    risk_score: int,
    analysis: dict[str, Any],
    bucket: str,
    key: str,
) -> None:
    message = {
        "project": "Secure-Pay Sentinel",
        "transaction_id": transaction_id,
        "risk_score": risk_score,
        "source_ip": source_ip,
        "risk_level": analysis["risk_level"],
        "recommended_action": analysis["recommended_action"],
        "detected_attack_types": analysis["detected_attack_types"],
        "summary": analysis["summary"],
        "evidence": analysis["evidence"],
        "s3_bucket": bucket,
        "s3_key": key,
        "waf_scope": WAF_SCOPE,
    }

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"Secure-Pay Sentinel Alert: {transaction_id}",
        Message=json.dumps(message, indent=2),
    )


def _update_waf_ip_set(source_ip: str) -> dict[str, Any]:
    ip_obj = ipaddress.ip_address(source_ip)
    cidr = f"{ip_obj.compressed}/{32 if ip_obj.version == 4 else 128}"
    target = WAF_IP_SETS[ip_obj.version]

    if not target["name"] or not target["id"]:
        raise ValueError(f"WAF IP set configuration is missing for IPv{ip_obj.version}.")

    last_error: Exception | None = None
    for _ in range(3):
        response = waf_client.get_ip_set(
            Name=target["name"],
            Scope=WAF_SCOPE,
            Id=target["id"],
        )
        addresses = set(response["IPSet"]["Addresses"])

        if cidr in addresses:
            return {"updated": False, "cidr": cidr}

        addresses.add(cidr)

        try:
            waf_client.update_ip_set(
                Name=target["name"],
                Scope=WAF_SCOPE,
                Id=target["id"],
                Addresses=sorted(addresses),
                LockToken=response["LockToken"],
            )
            return {"updated": True, "cidr": cidr}
        except waf_client.exceptions.WAFOptimisticLockException as exc:
            last_error = exc
            continue

    if last_error:
        raise last_error

    raise RuntimeError("Unable to update WAF IP set.")


def _resolve_transaction_id(
    transaction: dict[str, Any],
    bucket: str,
    key: str,
    position: int,
) -> str:
    for field in ("transaction_id", "id", "payment_id"):
        value = transaction.get(field)
        if value:
            return str(value)

    digest_input = json.dumps(transaction, default=_json_default, sort_keys=True)
    digest = sha256(f"{bucket}:{key}:{position}:{digest_input}".encode("utf-8")).hexdigest()
    return f"generated-{digest[:16]}"


def _extract_source_ip(transaction: dict[str, Any]) -> str | None:
    candidates: list[Any] = [
        transaction.get("source_ip"),
        transaction.get("ip_address"),
        transaction.get("origin_ip"),
    ]

    payload = transaction.get("payload")
    if isinstance(payload, dict):
        headers = payload.get("headers")
        if isinstance(headers, dict):
            candidates.extend(
                [
                    headers.get("x-forwarded-for"),
                    headers.get("x-real-ip"),
                    headers.get("cf-connecting-ip"),
                ]
            )

    for value in candidates:
        if not value:
            continue

        if isinstance(value, str):
            candidate = value.split(",")[0].strip()
        else:
            continue

        try:
            return ipaddress.ip_address(candidate).compressed
        except ValueError:
            continue

    return None


def _risk_level_from_score(score: int) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def _action_from_score(score: int) -> str:
    if score >= 9:
        return "block"
    if score >= 5:
        return "monitor"
    return "allow"


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _strip_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_none(v) for v in value if v is not None]
    return value


def _to_dynamodb_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _to_dynamodb_value(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_to_dynamodb_value(v) for v in value if v is not None]
    if isinstance(value, float):
        return Decimal(str(value))
    return value


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _clamp_int(value: Any, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = minimum
    return max(minimum, min(maximum, number))


def _format_client_error(exc: ClientError) -> str:
    error = exc.response.get("Error", {})
    return f"{error.get('Code', 'ClientError')}: {error.get('Message', str(exc))}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
