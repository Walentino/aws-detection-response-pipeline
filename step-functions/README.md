# Step Functions: Incident Response Workflow

Phase 2 enhancement to the detection pipeline. Adds multi-step orchestration with a human-in-the-loop approval gate for HIGH severity incidents.

## Why Step Functions?

The Lambda-only pipeline handles immediate containment well, but production incident response needs more:

- **Analyst approval** before permanent actions (deleting keys vs. just disabling them)
- **Rollback capability** when containment hits a false positive
- **Visual execution history** for audit and post-incident review
- **Built-in retry and error handling** at each workflow step
- **Parallel execution** (alert + log + approval happen simultaneously)

## Workflow

```
                    ┌─────────────────┐
                    │  Extract Event  │
                    │  Context        │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Check          │
                    │  Allowlist      │
                    └────────┬────────┘
                             │
                   ┌─────────┴──────────┐
                   │                    │
              Allowlisted          Not Allowlisted
                   │                    │
              Log & Exit       ┌────────▼────────┐
                               │  Evaluate       │
                               │  Severity       │
                               └────────┬────────┘
                                        │
                          ┌─────────────┴─────────────┐
                          │                           │
                       MEDIUM                       HIGH
                          │                           │
                   ┌──────▼──────┐           ┌────────▼────────┐
                   │ Alert Only  │           │  Immediate      │
                   │ (SNS + log) │           │  Containment    │
                   └─────────────┘           │  (disable key + │
                                             │   deny policy)  │
                                             └────────┬────────┘
                                                      │
                                        ┌─────────────┼──────────────┐
                                        │             │              │
                                   Send Alert    Write Audit   ┌────▼─────┐
                                                    Log        │  Wait    │
                                                               │  for     │
                                                               │  Analyst │
                                                               │  (≤24h)  │
                                                               └────┬─────┘
                                                                    │
                                                       ┌────────────┴───────────┐
                                                       │                        │
                                                  APPROVE                    DENY
                                                       │                        │
                                              ┌────────▼────────┐     ┌─────────▼────────┐
                                              │  Delete Key     │     │  Re-enable Key   │
                                              │  Permanently    │     │  Remove Deny     │
                                              └────────┬────────┘     │  Policy          │
                                                       │              └─────────┬────────┘
                                                       │                        │
                                                       └────────────┬───────────┘
                                                                    │
                                                           ┌────────▼────────┐
                                                           │  Final Alert +  │
                                                           │  Audit Log      │
                                                           └─────────────────┘
```

## How the Approval Gate Works

The workflow uses the Step Functions **callback pattern** (`waitForTaskToken`):

1. After containment, the state machine sends a message to an SQS queue containing a **task token** and incident details
2. The workflow **pauses** and waits (up to 24 hours)
3. An analyst reviews the incident and calls the approval Lambda with the task token and their decision
4. The workflow **resumes** and routes to either permanent remediation (approve) or rollback (deny)

### Approving or Denying from the CLI

```bash
# Get the pending approval message from SQS
aws sqs receive-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/security-incident-approval \
  --max-number-of-messages 1

# Approve (extract the taskToken from the message body)
aws lambda invoke \
  --function-name security-incident-approval-handler \
  --payload '{"task_token":"TOKEN_FROM_SQS","decision":"approve","analyst":"your-name"}' \
  response.json

# Or deny (false positive)
aws lambda invoke \
  --function-name security-incident-approval-handler \
  --payload '{"task_token":"TOKEN_FROM_SQS","decision":"deny","analyst":"your-name","notes":"False positive - CI/CD key rotation"}' \
  response.json
```

## Files

| File | Purpose |
|------|---------|
| `state-machine.asl.json` | State machine definition (Amazon States Language) |
| `sfn_handlers.py` | All task handler functions (router pattern — single Lambda) |
| `terraform/sfn.tf` | Terraform config for Step Functions, SQS, IAM, EventBridge |

## Architecture Decisions

**Single Lambda with router pattern** — Instead of deploying 8 separate Lambda functions (one per task), we deploy one Lambda and use a `task` field to route to the correct handler. This reduces deployment complexity and cold starts while keeping the code logically separated.

**SQS for approval queue** — SQS provides durable message storage for the task token while the analyst reviews. Messages are retained for 4 days, giving analysts a window to respond even if they're not immediately available.

**24-hour approval timeout** — The `HeartbeatSeconds: 86400` gives analysts a full day to review. If no response arrives, the workflow times out and the containment remains in place (fail-safe).

**Parallel execution** — After containment, alerting, audit logging, and approval requests happen simultaneously. This ensures the analyst is notified as fast as possible, not waiting for sequential log writes.
