# ═══════════════════════════════════════════════════════════════════
# Step Functions Incident Response Workflow — Terraform Configuration
# ═══════════════════════════════════════════════════════════════════
#
# Deploys:
#   - Step Functions state machine
#   - SQS queue for analyst approval (callback pattern)
#   - IAM roles for Step Functions and Lambda
#   - EventBridge rule to trigger the workflow (for HIGH severity)
#
# Usage:
#   This supplements the existing Lambda-only pipeline. The Lambda
#   handles MEDIUM severity (alert-only). HIGH severity events route
#   to Step Functions for the full containment → approval → resolution
#   workflow.
# ═══════════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ── Variables ────────────────────────────────────────────────────

variable "aws_region" {
  default = "us-east-1"
}

variable "sns_topic_arn" {
  description = "ARN of the existing SNS security-alerts topic"
  type        = string
}

variable "dynamodb_table_name" {
  description = "Name of the existing DynamoDB state table"
  default     = "SecurityPipelineState"
}

variable "existing_lambda_role_arn" {
  description = "ARN of the existing Lambda execution role (from the core pipeline)"
  type        = string
}

variable "dry_run" {
  description = "Enable dry-run mode (log without remediating)"
  default     = "true"
}

variable "allowed_ips" {
  description = "Comma-separated CIDR allowlist"
  default     = ""
}

variable "allowed_roles" {
  description = "Comma-separated role ARN patterns for allowlist"
  default     = ""
}

# ── Data Sources ─────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ── SQS Queue for Analyst Approval ──────────────────────────────

resource "aws_sqs_queue" "approval_queue" {
  name                       = "security-incident-approval"
  visibility_timeout_seconds = 90000  # > HeartbeatSeconds (86400)
  message_retention_seconds  = 345600 # 4 days
  receive_wait_time_seconds  = 20     # Long polling

  tags = {
    Project = "DetectionPipeline"
    Phase   = "StepFunctions"
  }
}

# ── Lambda Function (router pattern — single function) ───────────

data "archive_file" "sfn_lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/sfn_handlers.py"
  output_path = "${path.module}/.build/sfn_handlers.zip"
}

resource "aws_lambda_function" "sfn_handler" {
  function_name = "security-incident-workflow-handler"
  runtime       = "python3.12"
  handler       = "sfn_handlers.router_handler"
  role          = var.existing_lambda_role_arn
  filename      = data.archive_file.sfn_lambda_zip.output_path
  timeout       = 60
  memory_size   = 256

  source_code_hash = data.archive_file.sfn_lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN  = var.sns_topic_arn
      DYNAMODB_TABLE = var.dynamodb_table_name
      DRY_RUN        = var.dry_run
      ALLOWED_IPS    = var.allowed_ips
      ALLOWED_ROLES  = var.allowed_roles
    }
  }

  tags = {
    Project = "DetectionPipeline"
    Phase   = "StepFunctions"
  }
}

# ── Lambda for Analyst Approval (API-triggered) ──────────────────

resource "aws_lambda_function" "approval_handler" {
  function_name = "security-incident-approval-handler"
  runtime       = "python3.12"
  handler       = "sfn_handlers.approval_handler"
  role          = var.existing_lambda_role_arn
  filename      = data.archive_file.sfn_lambda_zip.output_path
  timeout       = 30
  memory_size   = 128

  source_code_hash = data.archive_file.sfn_lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN  = var.sns_topic_arn
      DYNAMODB_TABLE = var.dynamodb_table_name
      DRY_RUN        = var.dry_run
    }
  }

  tags = {
    Project = "DetectionPipeline"
    Phase   = "StepFunctions"
  }
}

# ── Step Functions IAM Role ──────────────────────────────────────

resource "aws_iam_role" "sfn_role" {
  name = "security-incident-workflow-sfn-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "states.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "sfn_policy" {
  name = "security-incident-workflow-sfn-permissions"
  role = aws_iam_role.sfn_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeLambda"
        Effect = "Allow"
        Action = ["lambda:InvokeFunction"]
        Resource = [
          aws_lambda_function.sfn_handler.arn,
          aws_lambda_function.approval_handler.arn
        ]
      },
      {
        Sid    = "SQSSendMessage"
        Effect = "Allow"
        Action = ["sqs:SendMessage"]
        Resource = [aws_sqs_queue.approval_queue.arn]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      }
    ]
  })
}

# ── Step Functions State Machine ─────────────────────────────────

resource "aws_sfn_state_machine" "incident_response" {
  name     = "security-incident-response-workflow"
  role_arn = aws_iam_role.sfn_role.arn

  definition = templatefile("${path.module}/../step-functions/state-machine.asl.json", {
    ExtractContextFunctionArn       = aws_lambda_function.sfn_handler.arn
    CheckAllowlistFunctionArn       = aws_lambda_function.sfn_handler.arn
    AuditLogFunctionArn             = aws_lambda_function.sfn_handler.arn
    ContainmentFunctionArn          = aws_lambda_function.sfn_handler.arn
    SendAlertFunctionArn            = aws_lambda_function.sfn_handler.arn
    PermanentRemediationFunctionArn = aws_lambda_function.sfn_handler.arn
    RollbackFunctionArn             = aws_lambda_function.sfn_handler.arn
    ApprovalQueueUrl                = aws_sqs_queue.approval_queue.url
  })

  tags = {
    Project = "DetectionPipeline"
    Phase   = "StepFunctions"
  }
}

# ── EventBridge Rule: Route HIGH Severity to Step Functions ──────

resource "aws_cloudwatch_event_rule" "high_severity_to_sfn" {
  name        = "detect-iam-key-creation-sfn"
  description = "Route CreateAccessKey events to Step Functions workflow"

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["CreateAccessKey"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sfn_target" {
  rule     = aws_cloudwatch_event_rule.high_severity_to_sfn.name
  arn      = aws_sfn_state_machine.incident_response.arn
  role_arn = aws_iam_role.eventbridge_sfn_role.arn
}

resource "aws_iam_role" "eventbridge_sfn_role" {
  name = "eventbridge-start-sfn-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "events.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge_sfn_policy" {
  name = "eventbridge-start-sfn-execution"
  role = aws_iam_role.eventbridge_sfn_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["states:StartExecution"]
      Resource = [aws_sfn_state_machine.incident_response.arn]
    }]
  })
}

# ── Outputs ──────────────────────────────────────────────────────

output "state_machine_arn" {
  value = aws_sfn_state_machine.incident_response.arn
}

output "approval_queue_url" {
  value = aws_sqs_queue.approval_queue.url
}

output "sfn_handler_function_name" {
  value = aws_lambda_function.sfn_handler.function_name
}

output "approval_handler_function_name" {
  value = aws_lambda_function.approval_handler.function_name
}
