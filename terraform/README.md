# Agent Shield — Terraform Configuration

Manage Agent Shield security policies as infrastructure-as-code using a hypothetical `agentshield` Terraform provider.

## Concept

This directory demonstrates how AI agent security policies can be:

- **Version-controlled** alongside your application code
- **Reviewed** through standard pull request workflows
- **Deployed consistently** across development, staging, and production
- **Audited** with Terraform state and plan diffs

## Files

| File | Description |
|------|-------------|
| `main.tf` | Provider config, shield policy, detection rules, PII redaction, tool boundaries, rate limits, compliance |
| `variables.tf` | Input variables with defaults and validation |
| `outputs.tf` | Output values for downstream consumption |

## Usage

```bash
# Initialize the provider
terraform init

# Preview changes
terraform plan -var="environment=production" -var="sensitivity=high"

# Apply the configuration
terraform apply -var="environment=production"

# Destroy (remove policies)
terraform destroy
```

## Environment Examples

```bash
# Development — permissive, logging only
terraform apply -var="environment=development" -var="block_on_threat=false"

# Staging — mirrors production with blocking enabled
terraform apply -var="environment=staging" -var="block_on_threat=true"

# Production — strict, full compliance
terraform apply \
  -var="environment=production" \
  -var="sensitivity=high" \
  -var="block_on_threat=true" \
  -var="block_threshold=medium" \
  -var='compliance_frameworks=["SOC2","HIPAA","GDPR"]' \
  -var="audit_retention_days=365"
```

## Note

The `agentshield` provider is hypothetical. These files illustrate the concept of managing AI security policies as IaC. The HCL syntax is valid and follows Terraform best practices.
