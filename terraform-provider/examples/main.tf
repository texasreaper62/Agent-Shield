# Agent Shield Terraform Provider - Example Configuration
#
# This example demonstrates how to manage Agent Shield security policies,
# custom detection rules, and tenant configurations as infrastructure-as-code.

terraform {
  required_providers {
    agent_shield = {
      source  = "agentshield/agent-shield"
      version = "~> 0.1"
    }
  }
}

# --------------------------------------------------------------------------
# Provider configuration
# --------------------------------------------------------------------------

provider "agent_shield" {
  endpoint         = "http://localhost:8080"
  api_key          = var.agent_shield_api_key
  default_severity = "medium"
}

variable "agent_shield_api_key" {
  type        = string
  sensitive   = true
  description = "API key for Agent Shield"
}

# --------------------------------------------------------------------------
# Security policy with custom patterns
# --------------------------------------------------------------------------

resource "agent_shield_policy" "production" {
  name            = "production-security"
  description     = "Production security policy with strict detection"
  min_severity    = "low"
  block_on_threat = true
  enabled         = true

  categories = [
    "prompt_injection",
    "data_exfiltration",
    "pii_detection",
    "tool_abuse",
    "jailbreak",
  ]

  custom_patterns = [
    {
      regex       = "(?i)api[_-]?key\\s*[:=]\\s*['\"][A-Za-z0-9]{32,}"
      severity    = "critical"
      category    = "data_exfiltration"
      description = "Detects exposed API keys in agent output"
    },
    {
      regex       = "(?i)(drop\\s+table|truncate\\s+table|delete\\s+from)"
      severity    = "critical"
      category    = "tool_abuse"
      description = "Detects SQL injection attempts in agent input"
    },
    {
      regex       = "(?i)\\bpassword\\s*[:=]\\s*\\S+"
      severity    = "high"
      category    = "pii_detection"
      description = "Detects plaintext passwords in content"
    },
  ]
}

# --------------------------------------------------------------------------
# Custom detection rule
# --------------------------------------------------------------------------

resource "agent_shield_rule" "block_internal_urls" {
  policy_id   = agent_shield_policy.production.id
  pattern     = "https?://internal\\.[a-z]+\\.corp\\.example\\.com"
  severity    = "high"
  category    = "data_exfiltration"
  description = "Block references to internal corporate URLs"
  enabled     = true
}

resource "agent_shield_rule" "detect_prompt_leak" {
  policy_id   = agent_shield_policy.production.id
  pattern     = "(?i)(reveal|show|display|print)\\s+(your|the)\\s+(system\\s+prompt|instructions|rules)"
  severity    = "high"
  category    = "prompt_leak"
  description = "Detect attempts to extract the system prompt"
  enabled     = true
}

# --------------------------------------------------------------------------
# Tenant configuration
# --------------------------------------------------------------------------

resource "agent_shield_tenant" "primary" {
  name                    = "primary-tenant"
  policy_id               = agent_shield_policy.production.id
  max_requests_per_minute = 5000
  sso_provider            = "okta"

  allowed_categories = [
    "prompt_injection",
    "data_exfiltration",
    "pii_detection",
    "tool_abuse",
    "jailbreak",
  ]

  blocked_categories = []
}

# --------------------------------------------------------------------------
# Data source: list built-in patterns
# --------------------------------------------------------------------------

data "agent_shield_patterns" "all" {}

data "agent_shield_patterns" "injection_only" {
  category = "prompt_injection"
}

# --------------------------------------------------------------------------
# Outputs
# --------------------------------------------------------------------------

output "policy_id" {
  description = "The ID of the production security policy"
  value       = agent_shield_policy.production.id
}

output "tenant_id" {
  description = "The ID of the primary tenant"
  value       = agent_shield_tenant.primary.id
}

output "total_builtin_patterns" {
  description = "Number of built-in detection patterns"
  value       = data.agent_shield_patterns.all.pattern_count
}

output "injection_patterns" {
  description = "Built-in prompt injection patterns"
  value       = data.agent_shield_patterns.injection_only.patterns
}
