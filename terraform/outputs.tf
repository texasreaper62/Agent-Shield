# =============================================================================
# Agent Shield — Terraform Outputs
# =============================================================================

output "policy_id" {
  description = "The ID of the created Agent Shield policy"
  value       = agentshield_policy.main.id
}

output "policy_name" {
  description = "The name of the created Agent Shield policy"
  value       = agentshield_policy.main.name
}

output "environment" {
  description = "The deployment environment"
  value       = var.environment
}

output "sensitivity" {
  description = "The configured detection sensitivity"
  value       = var.sensitivity
}

output "block_on_threat" {
  description = "Whether blocking is enabled"
  value       = var.block_on_threat
}

output "compliance_frameworks" {
  description = "Active compliance frameworks"
  value       = var.compliance_frameworks
}

output "detection_rules" {
  description = "List of custom detection rule names"
  value = [
    agentshield_detection_rule.internal_data_leak.name,
    agentshield_detection_rule.competitor_phishing.name,
  ]
}

output "summary" {
  description = "Human-readable summary of the deployed shield configuration"
  value       = <<-EOT
    Agent Shield Policy: ${agentshield_policy.main.name}
    Environment:         ${var.environment}
    Sensitivity:         ${var.sensitivity}
    Blocking:            ${var.block_on_threat ? "enabled" : "disabled"}
    Block Threshold:     ${var.block_threshold}
    Compliance:          ${join(", ", var.compliance_frameworks)}
    Allowed Tools:       ${join(", ", var.allowed_tools)}
    Rate Limit:          ${var.rate_limit_max} req / ${var.rate_limit_window}s
  EOT
}
