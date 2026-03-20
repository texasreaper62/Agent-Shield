# Agent Shield Terraform Provider - Multi-Tenant Configuration
#
# This example demonstrates managing multiple tenants with different
# security policies using variable-driven configuration.

terraform {
  required_providers {
    agent_shield = {
      source  = "agentshield/agent-shield"
      version = "~> 0.1"
    }
  }
}

# --------------------------------------------------------------------------
# Variables
# --------------------------------------------------------------------------

variable "api_key" {
  type        = string
  sensitive   = true
  description = "Agent Shield API key"
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Deployment environment (production, staging, development)"
}

variable "tenants" {
  type = map(object({
    policy_tier             = string
    max_requests_per_minute = number
    sso_provider            = optional(string)
    blocked_categories      = optional(list(string), [])
  }))
  default = {
    "acme-corp" = {
      policy_tier             = "strict"
      max_requests_per_minute = 10000
      sso_provider            = "okta"
      blocked_categories      = []
    }
    "startup-inc" = {
      policy_tier             = "standard"
      max_requests_per_minute = 2000
      sso_provider            = "google"
      blocked_categories      = ["steganography"]
    }
    "dev-team" = {
      policy_tier             = "permissive"
      max_requests_per_minute = 500
      sso_provider            = null
      blocked_categories      = ["pii_detection", "steganography"]
    }
  }
  description = "Map of tenant configurations"
}

# --------------------------------------------------------------------------
# Provider
# --------------------------------------------------------------------------

provider "agent_shield" {
  endpoint         = "http://localhost:8080"
  api_key          = var.api_key
  default_severity = var.environment == "production" ? "low" : "medium"
}

# --------------------------------------------------------------------------
# Policies by tier
# --------------------------------------------------------------------------

resource "agent_shield_policy" "strict" {
  name            = "${var.environment}-strict"
  description     = "Strict security policy — blocks all threat levels"
  min_severity    = "low"
  block_on_threat = true
  enabled         = true

  categories = [
    "prompt_injection",
    "data_exfiltration",
    "pii_detection",
    "tool_abuse",
    "encoding_attack",
    "jailbreak",
    "indirect_injection",
    "prompt_leak",
  ]

  custom_patterns = [
    {
      regex       = "(?i)Bearer\\s+[A-Za-z0-9\\-._~+/]+=*"
      severity    = "critical"
      category    = "data_exfiltration"
      description = "Detect leaked Bearer tokens"
    },
  ]
}

resource "agent_shield_policy" "standard" {
  name            = "${var.environment}-standard"
  description     = "Standard security policy — blocks high and critical threats"
  min_severity    = "high"
  block_on_threat = true
  enabled         = true

  categories = [
    "prompt_injection",
    "data_exfiltration",
    "pii_detection",
    "tool_abuse",
    "jailbreak",
  ]
}

resource "agent_shield_policy" "permissive" {
  name            = "${var.environment}-permissive"
  description     = "Permissive policy — logs threats but does not block"
  min_severity    = "medium"
  block_on_threat = false
  enabled         = true

  categories = [
    "prompt_injection",
    "data_exfiltration",
    "tool_abuse",
  ]
}

# --------------------------------------------------------------------------
# Policy tier lookup
# --------------------------------------------------------------------------

locals {
  policy_map = {
    strict     = agent_shield_policy.strict.id
    standard   = agent_shield_policy.standard.id
    permissive = agent_shield_policy.permissive.id
  }
}

# --------------------------------------------------------------------------
# Tenants (created from the variable map)
# --------------------------------------------------------------------------

resource "agent_shield_tenant" "tenants" {
  for_each = var.tenants

  name                    = each.key
  policy_id               = local.policy_map[each.value.policy_tier]
  max_requests_per_minute = each.value.max_requests_per_minute
  sso_provider            = each.value.sso_provider
  blocked_categories      = each.value.blocked_categories
}

# --------------------------------------------------------------------------
# Shared rule applied to the strict policy
# --------------------------------------------------------------------------

resource "agent_shield_rule" "block_internal_domains" {
  policy_id   = agent_shield_policy.strict.id
  pattern     = "(?i)https?://[^/]*\\.internal\\.(example|corp)\\.com"
  severity    = "critical"
  category    = "data_exfiltration"
  description = "Block all references to internal domains"
  enabled     = true
}

# --------------------------------------------------------------------------
# Outputs
# --------------------------------------------------------------------------

output "tenant_ids" {
  description = "Map of tenant name to tenant ID"
  value       = { for k, t in agent_shield_tenant.tenants : k => t.id }
}

output "policy_ids" {
  description = "Map of policy tier to policy ID"
  value       = local.policy_map
}
