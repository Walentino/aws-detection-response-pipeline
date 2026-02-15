"""
Step Functions Task Handlers for the Incident Response Workflow.

Each function corresponds to a Task state in the state machine.
They are designed as small, single-responsibility functions that
the state machine orchestrates.

Deploy as separate Lambda functions, or as a single Lambda with
a router pattern (shown at the bottom of this file).
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

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── Clients ──────────────────────────────────────────────────────

iam_client = boto3.client("iam")
sns_client = boto3.client("sns")
ddb_resource = boto3.resource("dynamodb")
sfn_client = boto3.client("stepfunctions")

SNS_TOPIC_ARN  = os.environ.get("SNS_TOPIC_ARN", "")
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "SecurityPipelineState")
DRY_RUN        = os.environ.get("DRY_RUN", "true").lower() == "true"
ALLOWED_IPS    = [x.strip() for x in os.environ.get("ALLOWED_IPS", "").split(",") if x.strip()]
ALLOWED_ROLES  = [x.strip() for x in os.environ.get("ALLOWED_ROLES", "").split(",") if x.strip()]

ddb_table = ddb_resource.Table(DYNAMODB_TABLE)


# ═══════════════════════════════════════════════════════════════════
# TASK 1: Extract Event Context
# ═══════════════════════════════════════════════════════════════════

def extract_context_handler(event, context):
    """
    Parse raw EventBridge/CloudTrail event into a clean context dict.
    Determines severity based on detection signal type.
    """
    detail = event.get("detail") or {}
    user_identity = detail.get("userIdentity") or {}
    session_context = user_identity.get("sessionContext") or {}
    session_issuer = session_context.get("sessionIssuer") or {}

    response = detail.get("responseElements") or {}
    new_key_info = response.get("accessKey") or {}
    request_params = detail.get("requestParameters") or {}

    event_name = detail.get("eventName", "")
    error_code = detail.get("errorCode", "")

    # Determine severity
    if event_name == "CreateAccessKey":
        severity = "HIGH"
        signal = "key_creation"
    elif event_name in ("GetCallerIdentity", "GetSessionToken", "ListUsers",
                        "ListRoles", "ListAttachedUserPolicies", "ListBuckets", "GetBucketAcl"):
        severity = "MEDIUM"
        signal = "reconnaissance"
    elif error_code in ("AccessDenied", "Client.UnauthorizedAccess", "AccessDeniedException"):
        severity = "MEDIUM"
        signal = "access_denied"
    else:
        severity = "LOW"
        signal = "unknown"

    target_username = request_params.get("userName", "") or new_key_info.get("userName", "")

    ctx = {
        "event_name": event_name,
        "event_source": detail.get("eventSource", ""),
        "event_time": detail.get("eventTime", ""),
        "source_ip": detail.get("sourceIPAddress", ""),
        "user_agent": detail.get("userAgent", ""),
        "principal_arn": user_identity.get("arn", ""),
        "identity_type": user_identity.get("type", "Unknown"),
        "account_id": user_identity.get("accountId", ""),
        "role_arn": session_issuer.get("arn", ""),
        "access_key_id": user_identity.get("accessKeyId", ""),
        "error_code": error_code,
        "error_message": detail.get("errorMessage", ""),
        "aws_region": detail.get("awsRegion", ""),
        "created_key_id": new_key_info.get("accessKeyId", ""),
        "target_username": target_username,
        "raw_event_id": detail.get("eventID", ""),
        "severity": severity,
        "signal": signal,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(f"Extracted context: {event_name} | {severity} | {ctx['source_ip']} | {ctx['principal_arn']}")
    return ctx


# ═══════════════════════════════════════════════════════════════════
# TASK 2: Check Allowlist
# ═══════════════════════════════════════════════════════════════════

def check_allowlist_handler(event, context):
    """
    Check all allowlist layers. Returns {allowed: bool, reason: str}.
    """
    ctx = event.get("context", event)
    source_ip = ctx.get("source_ip", "")
    principal_arn = ctx.get("principal_arn", "")

    # Layer 1: IP allowlist (env var)
    if source_ip and ALLOWED_IPS:
        try:
            ip = ip_address(source_ip)
            for cidr in ALLOWED_IPS:
                if ip in ip_network(cidr, strict=False):
                    return {"allowed": True, "reason": f"IP {source_ip} in CIDR allowlist {cidr}"}
        except ValueError:
            if source_ip.endswith(".amazonaws.com"):
                return {"allowed": True, "reason": f"AWS service IP: {source_ip}"}

    # Layer 2: Role allowlist (env var)
    if principal_arn and ALLOWED_ROLES:
        for pattern in ALLOWED_ROLES:
            if pattern in principal_arn:
                return {"allowed": True, "reason": f"Principal matches allowlist pattern: {pattern}"}

    # Layer 3: DynamoDB dynamic allowlist
    try:
        if source_ip:
            resp = ddb_table.get_item(Key={"PK": "ALLOWLIST#IP", "SK": source_ip})
            if "Item" in resp:
                return {"allowed": True, "reason": f"IP {source_ip} in DynamoDB allowlist"}
        if principal_arn:
            resp = ddb_table.get_item(Key={"PK": "ALLOWLIST#PRINCIPAL", "SK": principal_arn})
            if "Item" in resp:
                return {"allowed": True, "reason": f"Principal {principal_arn} in DynamoDB allowlist"}
    except ClientError as e:
        logger.warning(f"DynamoDB allowlist check failed: {e}")

    return {"allowed": False, "reason": "No allowlist match"}


# ═══════════════════════════════════════════════════════════════════
# TASK 3: Immediate Containment
# ═══════════════════════════════════════════════════════════════════

def containment_handler(event, context):
    """
    Disable the compromised access key and attach a deny-all policy.
    This is the speed-critical function — contain first, investigate later.
    """
    ctx = event.get("context", {})
    actions = event.get("actions", [])
    results = []

    key_id = ctx.get("created_key_id") or ctx.get("access_key_id", "")
    username = ctx.get("target_username", "")

    if not username:
        return {"success": False, "results": [], "message": "No target username to contain"}

    if "disable_key" in actions and key_id:
        if DRY_RUN:
            results.append({"action": "disable_key", "success": True,
                          "message": f"[DRY RUN] Would disable key {key_id} for {username}"})
        else:
            try:
                iam_client.update_access_key(
                    UserName=username, AccessKeyId=key_id, Status="Inactive")
                results.append({"action": "disable_key", "success": True,
                              "message": f"Disabled key {key_id} for {username}"})
            except ClientError as e:
                results.append({"action": "disable_key", "success": False,
                              "message": f"Failed: {e.response['Error']['Message']}"})

    if "attach_deny_policy" in actions:
        deny_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Sid": "DenyAllAutoRemediation",
                          "Effect": "Deny", "Action": "*", "Resource": "*"}]
        })
        if DRY_RUN:
            results.append({"action": "attach_deny_policy", "success": True,
                          "message": f"[DRY RUN] Would attach deny-all to {username}"})
        else:
            try:
                iam_client.put_user_policy(
                    UserName=username, PolicyName="AutoRemediation-DenyAll",
                    PolicyDocument=deny_policy)
                results.append({"action": "attach_deny_policy", "success": True,
                              "message": f"Attached deny-all policy to {username}"})
            except ClientError as e:
                results.append({"action": "attach_deny_policy", "success": False,
                              "message": f"Failed: {e.response['Error']['Message']}"})

    all_succeeded = all(r["success"] for r in results) if results else False
    logger.info(f"Containment results: {json.dumps(results)}")

    return {"success": all_succeeded, "results": results, "dry_run": DRY_RUN}


# ═══════════════════════════════════════════════════════════════════
# TASK 4: Permanent Remediation (post-approval)
# ═══════════════════════════════════════════════════════════════════

def permanent_remediation_handler(event, context):
    """
    Analyst approved. Delete the access key permanently and
    remove the deny-all policy.
    """
    ctx = event.get("context", {})
    actions = event.get("actions", [])
    results = []

    key_id = ctx.get("created_key_id") or ctx.get("access_key_id", "")
    username = ctx.get("target_username", "")

    if "delete_key" in actions and key_id and username:
        if DRY_RUN:
            results.append({"action": "delete_key", "success": True,
                          "message": f"[DRY RUN] Would delete key {key_id}"})
        else:
            try:
                iam_client.delete_access_key(UserName=username, AccessKeyId=key_id)
                results.append({"action": "delete_key", "success": True,
                              "message": f"Deleted key {key_id} for {username}"})
            except ClientError as e:
                results.append({"action": "delete_key", "success": False,
                              "message": f"Failed: {e.response['Error']['Message']}"})

    if "remove_deny_policy" in actions and username:
        if DRY_RUN:
            results.append({"action": "remove_deny_policy", "success": True,
                          "message": f"[DRY RUN] Would remove deny-all from {username}"})
        else:
            try:
                iam_client.delete_user_policy(
                    UserName=username, PolicyName="AutoRemediation-DenyAll")
                results.append({"action": "remove_deny_policy", "success": True,
                              "message": f"Removed deny-all policy from {username}"})
            except ClientError as e:
                results.append({"action": "remove_deny_policy", "success": False,
                              "message": f"Failed: {e.response['Error']['Message']}"})

    logger.info(f"Permanent remediation results: {json.dumps(results)}")
    return {"success": all(r["success"] for r in results), "results": results}


# ═══════════════════════════════════════════════════════════════════
# TASK 5: Rollback Containment (analyst denied — false positive)
# ═══════════════════════════════════════════════════════════════════

def rollback_handler(event, context):
    """
    Analyst denied the remediation (false positive).
    Re-enable the access key and remove the deny-all policy.
    """
    ctx = event.get("context", {})
    actions = event.get("actions", [])
    results = []

    key_id = ctx.get("created_key_id") or ctx.get("access_key_id", "")
    username = ctx.get("target_username", "")

    if "enable_key" in actions and key_id and username:
        if DRY_RUN:
            results.append({"action": "enable_key", "success": True,
                          "message": f"[DRY RUN] Would re-enable key {key_id}"})
        else:
            try:
                iam_client.update_access_key(
                    UserName=username, AccessKeyId=key_id, Status="Active")
                results.append({"action": "enable_key", "success": True,
                              "message": f"Re-enabled key {key_id} for {username}"})
            except ClientError as e:
                results.append({"action": "enable_key", "success": False,
                              "message": f"Failed: {e.response['Error']['Message']}"})

    if "remove_deny_policy" in actions and username:
        if DRY_RUN:
            results.append({"action": "remove_deny_policy", "success": True,
                          "message": f"[DRY RUN] Would remove deny-all from {username}"})
        else:
            try:
                iam_client.delete_user_policy(
                    UserName=username, PolicyName="AutoRemediation-DenyAll")
                results.append({"action": "remove_deny_policy", "success": True,
                              "message": f"Removed deny-all policy from {username}"})
            except ClientError as e:
                results.append({"action": "remove_deny_policy", "success": False,
                              "message": f"Failed: {e.response['Error']['Message']}"})

    logger.info(f"Rollback results: {json.dumps(results)}")
    return {"success": all(r["success"] for r in results), "results": results}


# ═══════════════════════════════════════════════════════════════════
# TASK 6: Send Alert
# ═══════════════════════════════════════════════════════════════════

def send_alert_handler(event, context):
    """
    Send structured alert to SNS. Adapts message based on severity
    and workflow stage.
    """
    ctx = event.get("context", {})
    severity = event.get("severity", "INFO")
    message = event.get("message", "")
    channel = event.get("channel", "sns")
    containment_result = event.get("containmentResult", {})

    dry_run_tag = " [DRY RUN]" if DRY_RUN else ""

    alert = {
        "title": f"{severity} Security Alert{dry_run_tag}: {ctx.get('event_name', 'Unknown')}",
        "severity": severity,
        "message": message,
        "event_details": {
            "event_name": ctx.get("event_name", ""),
            "source_ip": ctx.get("source_ip", ""),
            "principal_arn": ctx.get("principal_arn", ""),
            "aws_region": ctx.get("aws_region", ""),
            "event_id": ctx.get("raw_event_id", ""),
        },
        "containment": containment_result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "workflow": "step-functions",
    }

    if channel == "sns" and SNS_TOPIC_ARN:
        try:
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=alert["title"][:100],
                Message=json.dumps(alert, indent=2),
            )
            logger.info(f"SNS alert sent: {alert['title']}")
        except ClientError as e:
            logger.error(f"SNS publish failed: {e}")

    return {"sent": True, "title": alert["title"]}


# ═══════════════════════════════════════════════════════════════════
# TASK 7: Audit Log
# ═══════════════════════════════════════════════════════════════════

def audit_log_handler(event, context):
    """
    Write an audit record to DynamoDB.
    """
    ctx = event.get("context", {})
    action = event.get("action", "unknown")
    reason = event.get("reason", "")

    event_id = ctx.get("raw_event_id", "none")
    event_time = ctx.get("event_time", "")
    event_hash = hashlib.sha256(f"{event_id}{event_time}".encode()).hexdigest()[:12]

    sk_value = f"{event_time}#{event_hash}" if event_time else f"unknown#{event_hash}"

    try:
        ddb_table.put_item(Item={
            "PK": f"WORKFLOW#{ctx.get('event_name', 'Unknown')}",
            "SK": sk_value,
            "event_name": ctx.get("event_name", ""),
            "principal_arn": ctx.get("principal_arn", ""),
            "source_ip": ctx.get("source_ip", ""),
            "severity": ctx.get("severity", ""),
            "action": action,
            "reason": reason,
            "dry_run": DRY_RUN,
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ttl": int(datetime.now(timezone.utc).timestamp()) + (90 * 86400),
        })
        logger.info(f"Audit record written: {action}")
    except ClientError as e:
        logger.error(f"DynamoDB write failed: {e}")

    return {"logged": True, "action": action}


# ═══════════════════════════════════════════════════════════════════
# TASK 8: Analyst Approval Handler
# ═══════════════════════════════════════════════════════════════════

def approval_handler(event, context):
    """
    Called by an analyst (via API Gateway, CLI, or a simple approval page)
    to approve or deny a pending remediation.

    Expected input:
    {
        "task_token": "...",
        "decision": "approve" | "deny",
        "analyst": "analyst-name",
        "notes": "optional notes"
    }

    This function calls StepFunctions SendTaskSuccess or SendTaskFailure
    to resume the paused workflow.
    """
    task_token = event.get("task_token", "")
    decision = event.get("decision", "deny")
    analyst = event.get("analyst", "unknown")
    notes = event.get("notes", "")

    if not task_token:
        return {"error": "No task_token provided"}

    output = {
        "decision": decision,
        "analyst": analyst,
        "notes": notes,
        "decided_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        if decision == "approve":
            sfn_client.send_task_success(
                taskToken=task_token,
                output=json.dumps(output)
            )
            logger.info(f"Approval granted by {analyst}")
        else:
            sfn_client.send_task_failure(
                taskToken=task_token,
                error="AnalystDenied",
                cause=f"Denied by {analyst}: {notes}"
            )
            logger.info(f"Approval denied by {analyst}: {notes}")
    except ClientError as e:
        logger.error(f"Failed to send task result: {e}")
        return {"error": str(e)}

    return {"decision": decision, "analyst": analyst}


# ═══════════════════════════════════════════════════════════════════
# ROUTER PATTERN (single Lambda deployment option)
# ═══════════════════════════════════════════════════════════════════

HANDLERS = {
    "extract_context": extract_context_handler,
    "check_allowlist": check_allowlist_handler,
    "containment": containment_handler,
    "permanent_remediation": permanent_remediation_handler,
    "rollback": rollback_handler,
    "send_alert": send_alert_handler,
    "audit_log": audit_log_handler,
    "approval": approval_handler,
}


def router_handler(event, context):
    """
    Single-Lambda router. Deploy one Lambda and use the 'task' field
    in the Step Functions input to route to the correct handler.

    In the state machine, set each Task's Parameters to include:
      "task": "extract_context"  (or whichever handler)

    This reduces the number of Lambda functions from 8 to 1.
    """
    task = event.get("task", "")
    handler = HANDLERS.get(task)

    if not handler:
        raise ValueError(f"Unknown task: {task}. Valid tasks: {list(HANDLERS.keys())}")

    return handler(event, context)
