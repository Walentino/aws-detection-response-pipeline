# AWS Automated Detection & Response Pipeline

Serverless security pipeline that detects IAM access key compromise in near-real-time and auto-remediates — built on CloudTrail, EventBridge, Lambda, SNS, and DynamoDB.

```
CloudTrail → EventBridge → Lambda → SNS/Slack + DynamoDB
                                  ↓
                          Auto-Remediation
                    (disable key, quarantine user)
```

## Why This Exists

Exposed IAM access keys are the #1 initial access vector in AWS compromises. GuardDuty catches some of this, but with a detection delay and limited customization. This pipeline gives you sub-minute detection with rules you control, auto-remediation you can tune, and an audit trail you own.

This project operationalizes the detection rules from [`aws-cloudtrail-detection-rules`](https://github.com/Walentino/aws-cloudtrail-detection-rules) into a live, automated pipeline. The infrastructure patterns follow the same secure-by-default philosophy as [`terraform-aws-security-modules`](https://github.com/Walentino/terraform-aws-security-modules).

## What It Detects

| Signal | Severity | CloudTrail Events | Auto-Remediation |
|--------|----------|-------------------|------------------|
| IAM access key created outside normal process | HIGH | `CreateAccessKey` | Disable key + quarantine user |
| Reconnaissance API calls from unknown source | MEDIUM | `GetCallerIdentity`, `ListUsers`, `ListRoles`, `ListBuckets`, `GetSessionToken` | Alert only |
| AccessDenied error spike (permission enumeration) | MEDIUM | Any API call with `errorCode: AccessDenied` | Alert only |

### MITRE ATT&CK Mapping

- **T1078.004** — Valid Accounts: Cloud Accounts (Initial Access)
- **T1098.001** — Account Manipulation: Additional Cloud Credentials (Persistence)
- **T1580** — Cloud Infrastructure Discovery (Discovery)
- **T1087.004** — Account Discovery: Cloud Account (Discovery)

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌───────────────────┐
│  CloudTrail  │────▶│  EventBridge  │────▶│  Lambda           │
│  (all mgmt   │     │  (3 rules)   │     │  (detection +     │
│   events)    │     │              │     │   remediation)    │
└──────────────┘     └──────────────┘     └─────┬─────────────┘
                                                │
                           ┌────────────────────┼────────────────────┐
                           ▼                    ▼                    ▼
                    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
                    │  SNS         │     │  Slack       │     │  DynamoDB    │
                    │  (email)     │     │  (webhook)   │     │  (audit log  │
                    │              │     │              │     │   + allowlist)│
                    └──────────────┘     └──────────────┘     └──────────────┘
```

### Components

| Service | Role | Cost |
|---------|------|------|
| CloudTrail | Logs all API calls as structured JSON events | Free (1 management trail) |
| EventBridge | Filters security-relevant events via pattern matching | Free (custom rules) |
| Lambda | Detection logic, context enrichment, remediation execution | Free (well within 1M requests/month) |
| SNS | Fan-out alerts to email, SMS, or other Lambda functions | Free (1K emails/month) |
| DynamoDB | Stores allowlists, remediation audit trail, pipeline config | Free (25GB, on-demand) |
| Slack | Real-time alert delivery via incoming webhook | Free |

**Total estimated cost: $0.00/month** for a single-account deployment.

## How It Works

### Detection Flow

1. **Every API call** in the AWS account generates a CloudTrail management event
2. **EventBridge rules** pattern-match against specific API actions and error codes
3. **Lambda evaluates** the matched event against detection logic:
   - Is the source IP in the allowlist? → Skip
   - Is the principal an approved admin/CI role? → Skip
   - Is the principal in the DynamoDB dynamic allowlist? → Skip
   - Otherwise → Generate alert, execute remediation if applicable
4. **Alerts** publish to SNS (email) and Slack (webhook) with structured event details
5. **Audit records** are written to DynamoDB with a 90-day TTL

### Remediation Actions (HIGH severity only)

When `DRY_RUN=false` and a HIGH severity event fires:

1. **Disable the access key** — `iam:UpdateAccessKey` sets the key to `Inactive`
2. **Quarantine the user** — Attaches a `Deny *` inline policy (`AutoRemediation-DenyAll`)

Both actions are logged to DynamoDB for audit. In `DRY_RUN=true` mode (the default), the Lambda logs what it *would* do without taking action.

### False Positive Tuning

The pipeline supports three layers of allowlisting:

- **Environment variables** — `ALLOWED_IPS` (CIDR ranges) and `ALLOWED_ROLES` (ARN patterns) for static allowlists. No redeployment needed — just update the Lambda config.
- **DynamoDB dynamic allowlist** — Add/remove entries without touching Lambda. Supports IP and principal allowlists with expiration timestamps.
- **AWS service filtering** — Automatically skips events where `sourceIPAddress` ends in `.amazonaws.com` (AWS internal operations).

#### Tuning Workflow

1. Deploy with `DRY_RUN=true`
2. Run for 1–2 weeks; review alerts in CloudWatch Logs and DynamoDB
3. Add false positive sources to allowlists
4. Set `DRY_RUN=false` for HIGH-confidence rules (CreateAccessKey)
5. Keep MEDIUM rules (recon, AccessDenied) in alert-only mode

## Quickstart

### Prerequisites

- AWS account with CloudTrail enabled (management events)
- AWS CLI configured with appropriate permissions
- Python 3.12 runtime for Lambda

### Deploy

```bash
# 1. Create SNS topic and subscribe your email
aws sns create-topic --name security-alerts
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:ACCOUNT_ID:security-alerts \
  --protocol email \
  --notification-endpoint your-email@example.com

# 2. Create DynamoDB state table
aws dynamodb create-table \
  --table-name SecurityPipelineState \
  --attribute-definitions \
    AttributeName=PK,AttributeType=S \
    AttributeName=SK,AttributeType=S \
  --key-schema \
    AttributeName=PK,KeyType=HASH \
    AttributeName=SK,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST

# 3. Package and deploy Lambda
cd lambda/
zip -r ../detection-lambda.zip lambda_handler.py
aws lambda create-function \
  --function-name iam-key-detection-response \
  --runtime python3.12 \
  --handler lambda_handler.lambda_handler \
  --zip-file fileb://../detection-lambda.zip \
  --role arn:aws:iam::ACCOUNT_ID:role/DetectionPipelineLambdaRole \
  --timeout 60 \
  --memory-size 256 \
  --environment Variables="{
    SNS_TOPIC_ARN=arn:aws:sns:us-east-1:ACCOUNT_ID:security-alerts,
    DYNAMODB_TABLE=SecurityPipelineState,
    DRY_RUN=true
  }"

# 4. Create EventBridge rules
aws events put-rule \
  --name detect-iam-key-creation \
  --event-pattern '{"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["iam.amazonaws.com"],"eventName":["CreateAccessKey"]}}'

aws events put-rule \
  --name detect-recon-api-calls \
  --event-pattern '{"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventName":["GetCallerIdentity","GetSessionToken","ListUsers","ListRoles","ListAttachedUserPolicies","ListBuckets","GetBucketAcl"]}}'

aws events put-rule \
  --name detect-access-denied-spike \
  --event-pattern '{"detail-type":["AWS API Call via CloudTrail"],"detail":{"errorCode":["AccessDenied","Client.UnauthorizedAccess","AccessDeniedException"]}}'

# 5. Wire EventBridge rules to Lambda
for RULE in detect-iam-key-creation detect-recon-api-calls detect-access-denied-spike; do
  aws events put-targets --rule $RULE \
    --targets "Id=lambda-target,Arn=arn:aws:lambda:us-east-1:ACCOUNT_ID:function:iam-key-detection-response"
  aws lambda add-permission \
    --function-name iam-key-detection-response \
    --statement-id "${RULE}-invoke" \
    --action lambda:InvokeFunction \
    --principal events.amazonaws.com \
    --source-arn $(aws events describe-rule --name $RULE --query 'Arn' --output text)
done
```

### Test

```bash
# Create a test user and access key (triggers Signal 1)
aws iam create-user --user-name test-detection-user
aws iam create-access-key --user-name test-detection-user

# Use the test credentials for recon (triggers Signal 2)
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>
aws sts get-caller-identity
aws iam list-users 2>&1 || true
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# Check Lambda logs after 5-15 minutes
aws logs tail /aws/lambda/iam-key-detection-response --since 30m
```

## Repository Structure

```
aws-detection-response-pipeline/
├── README.md
├── lambda/
│   ├── lambda_handler.py          # Detection engine + remediation + alerting
│   └── test_event.json            # Sample EventBridge payload for direct invoke testing
├── terraform/                     # IaC for all pipeline resources
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── eventbridge.tf
│   ├── lambda.tf
│   ├── sns.tf
│   └── dynamodb.tf
├── docs/
│   ├── architecture.md
│   ├── detection-logic.md
│   ├── false-positive-tuning.md
│   └── cost-analysis.md
└── tests/
    ├── test_detection_logic.py
    └── simulate_attack.sh
```

## Relationship to Other Projects

This project is part of a three-repo AWS security portfolio:

| Repository | Role | How They Connect |
|------------|------|------------------|
| [`aws-cloudtrail-detection-rules`](https://github.com/Walentino/aws-cloudtrail-detection-rules) | Detection rule library | Provides the EventBridge patterns and CloudWatch metric filters that this pipeline operationalizes |
| [`terraform-aws-security-modules`](https://github.com/Walentino/terraform-aws-security-modules) | Secure infrastructure modules | Provides the `cloudtrail-baseline` module that feeds this pipeline, plus IaC patterns used in `terraform/` |
| **`aws-detection-response-pipeline`** (this repo) | Automated detection & response | Operationalizes the detection rules into a live pipeline with auto-remediation and alerting |

### How they fit together

The **detection rules** repo defines *what* to look for — the specific CloudTrail API calls, error patterns, and behavioral signals that indicate compromise. This pipeline repo turns those rules into a *running system* that matches events in real-time, evaluates context, and takes action.

The **Terraform modules** repo defines *how to build secure infrastructure* — including the CloudTrail baseline that generates the telemetry this pipeline consumes. The `cloudtrail-baseline` module ensures multi-region logging, log validation, and KMS encryption are enabled by default, so the detection pipeline has reliable, tamper-resistant input data.

Together, the three repos demonstrate the full security lifecycle: **prevent** (Terraform guardrails) → **detect** (CloudTrail rules) → **respond** (this pipeline).

## Design Decisions

### Why EventBridge over CloudWatch Metric Filters?

EventBridge provides native JSON pattern matching against CloudTrail event structure, supports multiple rules per event bus without log group dependencies, and routes directly to Lambda without intermediate metric/alarm steps. CloudWatch Metric Filters are better for aggregate counting (e.g., "more than 10 AccessDenied in 5 minutes") but require more infrastructure for single-event detection.

### Why Lambda-only over Step Functions?

For single-action remediation (disable key → alert), Lambda is simpler, faster to deploy, and cheaper. Step Functions add value for multi-step workflows with human approval gates, retry logic, and parallel execution — which is the planned Phase 2 enhancement for full incident lifecycle management.

### Why DynamoDB for state?

DynamoDB on-demand mode stays within Free Tier for low-throughput security events, supports TTL for automatic cleanup of audit records, and provides a single-table design (PK/SK) that handles allowlists, remediation logs, and configuration in one table.

### Why `DRY_RUN=true` as default?

Auto-remediation that disables access keys can cause outages if it fires on legitimate activity. Starting in dry-run mode lets you validate detection logic and tune false positives before enabling destructive actions. This is standard practice in production detection engineering.

## Lessons Learned During Implementation

- **CloudTrail sets `responseElements` and `requestParameters` to explicit `null`** (not missing) for failed API calls. Python's `dict.get("key", {})` doesn't handle this — you need `detail.get("key") or {}` to catch both missing keys and `None` values.
- **CloudTrail-to-EventBridge delivery requires explicit event selector configuration** on some account types. If EventBridge rules aren't matching, run `aws cloudtrail put-event-selectors` to ensure management events are enabled.
- **DynamoDB rejects empty strings as key attributes.** Guard all DynamoDB lookups against empty `source_ip` or `principal_arn` values before querying.
- **EventBridge `errorCode` varies by service.** IAM returns `AccessDenied`, but other services return `AccessDeniedException`. Match both in your rule patterns.

## Roadmap

- [x] Core pipeline: CloudTrail → EventBridge → Lambda → SNS
- [x] Detection signals: key creation, recon API calls, AccessDenied errors
- [x] Auto-remediation: disable key + quarantine user
- [x] DynamoDB audit trail and dynamic allowlists
- [x] Dry-run mode
- [ ] Slack webhook integration
- [x] Step Functions workflow for multi-step incident response with analyst approval
- [ ] Additional detection signals: `ConsoleLogin` without MFA, `AssumeRole` from unknown accounts, `PutBucketPolicy` making S3 public
- [ ] Terraform module for full pipeline deployment
- [ ] Unit tests for detection logic

## Author

Built by [Adewale Odeja](https://linkedin.com/in/adewaleodeja) — cloud security engineer focused on AWS detection and response automation. ACRTP-certified. Organizer of the GTA Pwned Labs study group.

## License

MIT
