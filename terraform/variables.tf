# =============================================================================
# Agent Shield — Terraform Variables
# =============================================================================

variable "environment" {
  description = "Deployment environment (e.g. development, staging, production)"
  type        = string
  default     = "development"

  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "config_dir" {
  description = "Path to the Agent Shield configuration directory"
  type        = string
  default     = "./agent-shield-config"
}

variable "sensitivity" {
  description = "Detection sensitivity level: low, medium, or high"
  type        = string
  default     = "high"

  validation {
    condition     = contains(["low", "medium", "high"], var.sensitivity)
    error_message = "Sensitivity must be one of: low, medium, high."
  }
}

variable "block_on_threat" {
  description = "Whether to block requests when threats are detected"
  type        = bool
  default     = true
}

variable "block_threshold" {
  description = "Minimum severity to trigger a block: low, medium, high, or critical"
  type        = string
  default     = "high"

  validation {
    condition     = contains(["low", "medium", "high", "critical"], var.block_threshold)
    error_message = "Block threshold must be one of: low, medium, high, critical."
  }
}

variable "enable_logging" {
  description = "Enable scan result logging"
  type        = bool
  default     = true
}

variable "team" {
  description = "Team name for resource tagging"
  type        = string
  default     = "platform"
}

variable "allowed_tools" {
  description = "List of tools agents are allowed to use"
  type        = list(string)
  default     = ["search", "read_file", "calculator", "web_browse"]
}

variable "max_tool_calls" {
  description = "Maximum tool calls allowed per agent turn"
  type        = number
  default     = 10
}

variable "rate_limit_max" {
  description = "Maximum requests per rate limit window"
  type        = number
  default     = 100
}

variable "rate_limit_window" {
  description = "Rate limit window in seconds"
  type        = number
  default     = 60
}

variable "compliance_frameworks" {
  description = "Compliance frameworks to report against"
  type        = list(string)
  default     = ["SOC2", "GDPR"]
}

variable "audit_retention_days" {
  description = "Number of days to retain audit trail records"
  type        = number
  default     = 90
}

variable "custom_pii_patterns" {
  description = "Custom PII patterns to add to the redaction policy"
  type        = list(string)
  default     = []
}
