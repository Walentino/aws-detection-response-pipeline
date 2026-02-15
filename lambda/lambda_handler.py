"""
AWS IAM Access Key Detection & Auto-Remediation Lambda

Processes EventBridge events from CloudTrail, evaluates detection logic,
executes remediation actions, and sends structured alerts.

Environment Variables:
    SNS_TOPIC_ARN     - ARN of the SNS topic for security alerts
    DYNAMODB_TABLE    - Name of the DynamoDB state table
    SLACK_WEBHOOK_URL - Slack incoming webhook URL
    DRY_RUN           - "true" to log without remediating (default: "true")
    ALLOWED_IPS       - Comma-separated CIDR ranges for allowlisted IPs
    ALLOWED_ROLES     - Comma-separated ARN patterns for allowlisted roles
"""

import json
import os
import logging
import hashlib
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from urllib.request import Request, urlopen
from urllib.error import URLError

import boto3
from botocore.exceptions import ClientError

# ── Configuration ──────────────────────────────────────────────

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC_ARN     = os.environ.get("SNS_TOPIC_ARN", "")
DYNAMODB_TABLE    = os.environ.get("DYNAMODB_TABLE", "SecurityPipelineState")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
DRY_RUN           = os.environ.get("DRY_RUN", "true").lower() == "true"
ALLOWED_IPS       = os.environ.get("ALLOWED_IPS", "").split(",") if os.environ.get("ALLOWED_IPS") else []
ALLOWED_ROLES     = os.environ.get("ALLOWED_ROLES", "").split(",") if os.environ.get("ALLOWED_ROLES") else []

iam_client = boto3.client("iam")
sns_client = boto3.client("sns")
ddb_client = boto3.resource("dynamodb").Table(DYNAMODB_TABLE)


# ── Helper: Extract Event Context ──────────────────────────────

def extract_event_context(event: dict) -> dict:
    """
    Parse the EventBridge/CloudTrail event into a clean context dict.
    Handles nested userIdentity structures (IAM user, assumed role, federated).

    Uses 'or {}' pattern throughout because CloudTrail explicitly sets
    fields to null (e.g. "responseElements": null) for failed API calls.
    dict.get("key", {}) does NOT handle this -- it only returns the default
    when the key is missing, not when the value is None.
    """
    detail = event.get("detail") or {}
    user_identity = detail.get("userIdentity") or {}

    # Resolve principal ARN across identity types
    principal_arn = user_identity.get("arn", "")
    identity_type = user_identity.get("type", "Unknown")
    account_id = user_identity.get("accountId", "")

    # For assumed roles, get the session issuer (the actual role)
    session_context = user_identity.get("sessionContext") or {}
    session_issuer = session_context.get("sessionIssuer") or {}
    role_arn = session_issuer.get("arn", "")

    # Extract access key ID if present (from the requestor, not the created key)
    access_key_id = user_identity.get("accessKeyId", "")

    # FIX: responseElements is null for failed/denied API calls
    response = detail.get("responseElements") or {}
    new_key_info = response.get("accessKey") or {}
    created_key_id = new_key_info.get("accessKeyId", "")

    # FIX: requestParameters can also be null
    request_params = detail.get("requestParameters") or {}
    target_username = request_params.get("userName", "")

    return {
        "event_name": detail.get("eventName", ""),
        "event_source": detail.get("eventSource", ""),
        "event_time": detail.get("eventTime", ""),
        "source_ip": detail.get("sourceIPAddress", ""),
        "user_agent": detail.get("userAgent", ""),
        "principal_arn": principal_arn,
        "identity_type": identity_type,
        "account_id": account_id,
        "role_arn": role_arn,
        "access_key_id": access_key_id,
        "error_code": detail.get("errorCode", ""),
        "error_message": detail.get("errorMessage", ""),
        "aws_region": detail.get("awsRegion", ""),
        # CreateAccessKey specific
        "created_key_id": created_key_id,
        "target_username": target_username or new_key_info.get("userName", ""),
        # Raw detail for audit
        "raw_event_id": detail.get("eventID", ""),
    }


# ── Helper: Check Allowlists ────────────────────────────────────

def is_ip_allowed(source_ip: str) -> bool:
    """Check if the source IP is in the allowlist (CIDR match)."""
    if not ALLOWED_IPS or not source_ip:
        return False
    try:
        ip = ip_address(source_ip)
        return any(ip in ip_network(cidr.strip(), strict=False)
                   for cidr in ALLOWED_IPS if cidr.strip())
    except ValueError:
        # sourceIPAddress can be a service name like "iam.amazonaws.com"
        return source_ip.endswith(".amazonaws.com")


def is_role_allowed(principal_arn: str) -> bool:
    """Check if the principal ARN matches any allowlisted role pattern."""
    if not ALLOWED_ROLES or not principal_arn:
        return False
    return any(pattern.strip() in principal_arn
               for pattern in ALLOWED_ROLES if pattern.strip())


def check_dynamodb_allowlist(ctx: dict) -> bool:
    """
    Check DynamoDB for dynamic allowlist entries.

    FIX: Guards against empty string sort keys, which DynamoDB rejects
    with ValidationException. This happens when events have no source_ip
    or principal_arn (e.g. scheduled events, malformed CloudTrail events).
    """
    try:
        # Skip if we don't have values to look up
        if not ctx.get("source_ip") and not ctx.get("principal_arn"):
            return False

        # Check IP allowlist
        if ctx["source_ip"]:
            resp = ddb_client.get_item(Key={"PK": "ALLOWLIST#IP", "SK": ctx["source_ip"]})
            if "Item" in resp:
                logger.info(f"IP {ctx['source_ip']} found in DynamoDB allowlist")
                return True

        # Check principal allowlist
        if ctx["principal_arn"]:
            resp = ddb_client.get_item(Key={"PK": "ALLOWLIST#PRINCIPAL", "SK": ctx["principal_arn"]})
            if "Item" in resp:
                logger.info(f"Principal {ctx['principal_arn']} found in DynamoDB allowlist")
                return True
    except ClientError as e:
        logger.warning(f"DynamoDB allowlist check failed: {e}")
    return False


# ── Detection Logic ─────────────────────────────────────────────

def evaluate_event(ctx: dict) -> dict:
    """
    Core detection logic. Returns a verdict dict:
      {"alert": bool, "severity": str, "reason": str,
       "remediate": bool, "action": str}
    """
    event_name = ctx["event_name"]

    # Skip events with no event name (e.g. scheduled test events)
    if not event_name:
        return {"alert": False, "severity": "none", "reason": "No event name",
                "remediate": False, "action": "none"}

    # ── Check allowlists first (fast path) ──
    if is_ip_allowed(ctx["source_ip"]):
        logger.info(f"Allowed IP: {ctx['source_ip']} for {event_name}")
        return {"alert": False, "severity": "none", "reason": "Allowed IP",
                "remediate": False, "action": "none"}

    if is_role_allowed(ctx["principal_arn"]):
        logger.info(f"Allowed role: {ctx['principal_arn']} for {event_name}")
        return {"alert": False, "severity": "none", "reason": "Allowed role",
                "remediate": False, "action": "none"}

    if check_dynamodb_allowlist(ctx):
        return {"alert": False, "severity": "none", "reason": "DynamoDB allowlist",
                "remediate": False, "action": "none"}

    # ── Signal 1: Access Key Creation ──
    if event_name == "CreateAccessKey":
        return {
            "alert": True,
            "severity": "HIGH",
            "reason": (f"IAM access key created for user '{ctx['target_username']}' "
                       f"by {ctx['principal_arn']} from {ctx['source_ip']}"),
            "remediate": True,
            "action": "disable_created_key",
        }

    # ── Signal 2: Recon API Calls ──
    recon_apis = {"GetCallerIdentity", "GetSessionToken", "ListUsers",
                  "ListRoles", "ListAttachedUserPolicies", "ListBuckets", "GetBucketAcl"}
    if event_name in recon_apis:
        return {
            "alert": True,
            "severity": "MEDIUM",
            "reason": (f"Reconnaissance API call '{event_name}' from "
                       f"{ctx['principal_arn']} at {ctx['source_ip']}"),
            "remediate": False,  # Alert only for recon; no auto-disable
            "action": "alert_only",
        }

    # ── Signal 3: AccessDenied Errors ──
    if ctx["error_code"] in ("AccessDenied", "Client.UnauthorizedAccess", "AccessDeniedException"):
        return {
            "alert": True,
            "severity": "MEDIUM",
            "reason": (f"AccessDenied on '{event_name}' for "
                       f"{ctx['principal_arn']} from {ctx['source_ip']}. "
                       f"Error: {ctx['error_message']}"),
            "remediate": False,
            "action": "alert_only",
        }

    # Default: no action
    return {"alert": False, "severity": "none", "reason": "No detection match",
            "remediate": False, "action": "none"}


# ── Remediation Actions ─────────────────────────────────────────

def disable_access_key(access_key_id: str, username: str) -> dict:
    """
    Disable a specific IAM access key.
    Returns: {"success": bool, "message": str}
    """
    if not access_key_id:
        return {"success": False, "message": "No access key ID to disable"}

    if DRY_RUN:
        msg = f"[DRY RUN] Would disable key {access_key_id} for user {username}"
        logger.info(msg)
        return {"success": True, "message": msg}

    try:
        iam_client.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status="Inactive"
        )
        msg = f"Disabled access key {access_key_id} for user {username}"
        logger.info(msg)
        return {"success": True, "message": msg}
    except ClientError as e:
        msg = f"Failed to disable key {access_key_id}: {e.response['Error']['Message']}"
        logger.error(msg)
        return {"success": False, "message": msg}


def attach_deny_all_policy(username: str) -> dict:
    """
    Attach an inline deny-all policy to quarantine a compromised user.
    This is a stronger containment than just disabling one key.
    """
    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyAllAutoRemediation",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }]
    })

    if DRY_RUN:
        msg = f"[DRY RUN] Would attach deny-all policy to user {username}"
        logger.info(msg)
        return {"success": True, "message": msg}

    try:
        iam_client.put_user_policy(
            UserName=username,
            PolicyName="AutoRemediation-DenyAll",
            PolicyDocument=deny_policy
        )
        msg = f"Attached deny-all inline policy to user {username}"
        logger.info(msg)
        return {"success": True, "message": msg}
    except ClientError as e:
        msg = f"Failed to attach deny-all policy: {e.response['Error']['Message']}"
        logger.error(msg)
        return {"success": False, "message": msg}


def execute_remediation(ctx: dict, verdict: dict) -> list:
    """
    Execute the appropriate remediation based on the verdict.
    Returns a list of action results.
    """
    results = []
    action = verdict.get("action", "none")

    if action == "disable_created_key" and ctx.get("created_key_id"):
        # Disable the newly created key
        r1 = disable_access_key(ctx["created_key_id"], ctx["target_username"])
        results.append(r1)

        # Also quarantine the target user if severity is HIGH
        if verdict["severity"] == "HIGH":
            r2 = attach_deny_all_policy(ctx["target_username"])
            results.append(r2)

    return results


# ── Alerting ─────────────────────────────────────────────────────

def build_alert_message(ctx: dict, verdict: dict, remediation_results: list) -> dict:
    """Build a structured alert message for SNS and Slack."""
    dry_run_tag = " [DRY RUN]" if DRY_RUN else ""

    alert = {
        "title": f"{verdict['severity']} Security Alert{dry_run_tag}: {ctx['event_name']}",
        "severity": verdict["severity"],
        "detection_reason": verdict["reason"],
        "event_details": {
            "event_name": ctx["event_name"],
            "event_source": ctx["event_source"],
            "event_time": ctx["event_time"],
            "source_ip": ctx["source_ip"],
            "user_agent": ctx["user_agent"],
            "principal_arn": ctx["principal_arn"],
            "aws_region": ctx["aws_region"],
            "event_id": ctx["raw_event_id"],
        },
        "remediation": {
            "dry_run": DRY_RUN,
            "actions_taken": [r["message"] for r in remediation_results],
            "all_succeeded": all(r["success"] for r in remediation_results)
                             if remediation_results else None,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return alert


def send_sns_alert(alert: dict) -> None:
    """Publish alert to SNS topic."""
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not configured; skipping SNS alert")
        return

    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=alert["title"][:100],  # SNS subject max 100 chars
            Message=json.dumps(alert, indent=2),
        )
        logger.info(f"SNS alert published: {alert['title']}")
    except ClientError as e:
        logger.error(f"SNS publish failed: {e}")


def send_slack_alert(alert: dict) -> None:
    """Send formatted alert to Slack via incoming webhook."""
    if not SLACK_WEBHOOK_URL:
        logger.warning("SLACK_WEBHOOK_URL not configured; skipping Slack alert")
        return

    severity_emoji = {"HIGH": ":rotating_light:", "MEDIUM": ":warning:",
                      "LOW": ":information_source:"}.get(alert["severity"], ":grey_question:")

    remediation_text = "No auto-remediation taken."
    if alert["remediation"]["actions_taken"]:
        actions = "\n".join(f"  \u2022 {a}" for a in alert["remediation"]["actions_taken"])
        remediation_text = f"*Actions:*\n{actions}"

    slack_msg = {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text",
             "text": f"{severity_emoji} {alert['title']}"}},
            {"type": "section", "text": {"type": "mrkdwn",
             "text": f"*Detection:* {alert['detection_reason']}"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Event:* `{alert['event_details']['event_name']}`"},
                {"type": "mrkdwn", "text": f"*Source IP:* `{alert['event_details']['source_ip']}`"},
                {"type": "mrkdwn", "text": f"*Principal:* `{alert['event_details']['principal_arn']}`"},
                {"type": "mrkdwn", "text": f"*Region:* `{alert['event_details']['aws_region']}`"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn",
             "text": f"*Remediation:*\n{remediation_text}"}},
            {"type": "context", "elements": [
                {"type": "mrkdwn",
                 "text": f"Event ID: `{alert['event_details']['event_id']}`"},
            ]},
        ]
    }

    try:
        req = Request(SLACK_WEBHOOK_URL, data=json.dumps(slack_msg).encode("utf-8"),
                      headers={"Content-Type": "application/json"})
        urlopen(req, timeout=5)
        logger.info("Slack alert sent successfully")
    except URLError as e:
        logger.error(f"Slack webhook failed: {e}")


# ── Audit Logging ────────────────────────────────────────────────

def log_to_dynamodb(ctx: dict, verdict: dict, remediation_results: list) -> None:
    """Write an audit record to DynamoDB."""
    try:
        event_hash = hashlib.sha256(
            f"{ctx['raw_event_id']}{ctx['event_time']}".encode()).hexdigest()[:12]

        # Build sort key -- guard against empty values
        sk_value = f"{ctx['event_time']}#{event_hash}" if ctx["event_time"] else f"unknown#{event_hash}"

        ddb_client.put_item(Item={
            "PK": f"DETECTION#{ctx['event_name'] or 'Unknown'}",
            "SK": sk_value,
            "event_name": ctx["event_name"],
            "principal_arn": ctx["principal_arn"],
            "source_ip": ctx["source_ip"],
            "severity": verdict["severity"],
            "reason": verdict["reason"],
            "dry_run": DRY_RUN,
            "remediation_actions": json.dumps(
                [r["message"] for r in remediation_results]),
            "event_id": ctx["raw_event_id"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ttl": int(datetime.now(timezone.utc).timestamp()) + (90 * 86400),  # 90-day TTL
        })
        logger.info("Audit record written to DynamoDB")
    except ClientError as e:
        logger.error(f"DynamoDB write failed: {e}")


# ── Main Handler ─────────────────────────────────────────────────

def lambda_handler(event, context):
    """
    Main entry point. Processes an EventBridge event through the
    detection pipeline: extract -> evaluate -> remediate -> alert -> audit.
    """
    logger.info(f"Event received: {json.dumps(event)[:500]}")

    try:
        # 1. Extract context
        ctx = extract_event_context(event)
        logger.info(f"Processing {ctx['event_name']} from {ctx['source_ip']} "
                     f"by {ctx['principal_arn']}")

        # 2. Evaluate detection logic
        verdict = evaluate_event(ctx)
        logger.info(f"Verdict: alert={verdict['alert']}, "
                     f"severity={verdict['severity']}, action={verdict['action']}")

        if not verdict["alert"]:
            logger.info("No alert triggered. Exiting.")
            return {"statusCode": 200, "body": "No alert"}

        # 3. Execute remediation (if applicable)
        remediation_results = []
        if verdict["remediate"]:
            remediation_results = execute_remediation(ctx, verdict)

        # 4. Build and send alerts
        alert = build_alert_message(ctx, verdict, remediation_results)
        send_sns_alert(alert)
        send_slack_alert(alert)

        # 5. Audit log
        log_to_dynamodb(ctx, verdict, remediation_results)

        return {"statusCode": 200, "body": json.dumps(alert)}

    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        # Best-effort alert on pipeline failure
        try:
            send_sns_alert({
                "title": "PIPELINE ERROR: Detection Lambda Failed",
                "severity": "HIGH",
                "detection_reason": f"Lambda execution error: {str(e)}",
                "event_details": {"raw_input": json.dumps(event)[:1000]},
                "remediation": {"dry_run": DRY_RUN, "actions_taken": [],
                                "all_succeeded": False},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass  # Don't let alert failure mask the original error
        raise  # Re-raise so Lambda runtime records the failure
