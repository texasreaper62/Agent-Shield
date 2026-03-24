# =============================================================================
# Agent Shield — Terraform Configuration
#
# Manages AI security policies as infrastructure-as-code using a hypothetical
# "agent-shield" Terraform provider.
#
# This demonstrates how shield policies, detection rules, and agent protection
# can be version-controlled and deployed consistently across environments.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    agentshield = {
      source  = "agent-shield/agentshield"
      version = "~> 1.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Provider Configuration
# -----------------------------------------------------------------------------

provider "agentshield" {
  # All detection runs locally — no API keys or cloud calls needed.
  # The provider manages policy files and agent configurations.
  config_dir = var.config_dir
}

# -----------------------------------------------------------------------------
# Shield Policy — Primary detection policy for the agent fleet
# -----------------------------------------------------------------------------

resource "agentshield_policy" "main" {
  name        = "${var.environment}-shield-policy"
  description = "Primary Agent Shield policy for ${var.environment}"

  sensitivity     = var.sensitivity
  block_on_threat = var.block_on_threat
  block_threshold = var.block_threshold

  logging = var.enable_logging

  dangerous_tools = [
    "bash",
    "shell",
    "exec",
    "eval",
    "write_file",
    "delete_file",
    "http_request",
    "sql",
    "database",
  ]

  tags = {
    environment = var.environment
    managed_by  = "terraform"
    team        = var.team
  }
}

# -----------------------------------------------------------------------------
# Detection Rules — Custom patterns for organization-specific threats
# -----------------------------------------------------------------------------

resource "agentshield_detection_rule" "internal_data_leak" {
  policy_id   = agentshield_policy.main.id
  name        = "internal-data-leak-detection"
  description = "Detect attempts to exfiltrate internal project names and codenames"

  category = "data_exfiltration"
  severity = "critical"

  patterns = [
    "internal[_\\s]?project",
    "codename[:\\s]",
    "confidential[:\\s]",
  ]

  action = "block"
}

resource "agentshield_detection_rule" "competitor_phishing" {
  policy_id   = agentshield_policy.main.id
  name        = "competitor-phishing"
  description = "Detect social engineering attempts referencing competitor products"

  category = "social_engineering"
  severity = "high"

  patterns = [
    "pretend\\s+you\\s+are\\s+(?:made\\s+by|from)\\s+\\w+",
    "switch\\s+to\\s+\\w+\\s+mode",
  ]

  action = "warn"
}

# -----------------------------------------------------------------------------
# PII Redaction Policy
# -----------------------------------------------------------------------------

resource "agentshield_pii_policy" "default" {
  policy_id   = agentshield_policy.main.id
  name        = "pii-redaction-${var.environment}"
  description = "PII redaction rules for ${var.environment}"

  redact_email       = true
  redact_phone       = true
  redact_ssn         = true
  redact_credit_card = true
  redact_ip_address  = var.environment == "production" ? true : false

  custom_patterns = var.custom_pii_patterns
}

# -----------------------------------------------------------------------------
# Tool Permission Boundary
# -----------------------------------------------------------------------------

resource "agentshield_tool_boundary" "restricted" {
  policy_id   = agentshield_policy.main.id
  name        = "tool-boundary-${var.environment}"
  description = "Tool permission boundary for ${var.environment} agents"

  allowed_tools = var.allowed_tools

  denied_sequences = [
    "read_file -> http_request",
    "database_query -> http_request",
    "read_credentials -> *",
  ]

  max_tool_calls_per_turn = var.max_tool_calls
}

# -----------------------------------------------------------------------------
# Rate Limiting
# -----------------------------------------------------------------------------

resource "agentshield_rate_limit" "default" {
  policy_id       = agentshield_policy.main.id
  name            = "rate-limit-${var.environment}"
  max_requests    = var.rate_limit_max
  window_seconds  = var.rate_limit_window
  block_on_exceed = true
}

# -----------------------------------------------------------------------------
# Compliance Reporting
# -----------------------------------------------------------------------------

resource "agentshield_compliance" "audit" {
  policy_id  = agentshield_policy.main.id
  name       = "compliance-${var.environment}"
  frameworks = var.compliance_frameworks

  audit_trail_enabled = true
  retention_days      = var.audit_retention_days
}
