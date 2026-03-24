# Agent Shield Terraform Provider

Manage [Agent Shield](https://github.com/agentshield/agent-shield) security policies as infrastructure-as-code with Terraform.

## Provider Configuration

```hcl
provider "agent_shield" {
  endpoint         = "http://localhost:8080"   # Agent Shield API endpoint
  api_key          = var.api_key               # API key (sensitive)
  default_severity = "medium"                  # Default severity threshold
}
```

| Attribute          | Type   | Required | Default                  | Description                                                        |
|--------------------|--------|----------|--------------------------|--------------------------------------------------------------------|
| `endpoint`         | string | No       | `http://localhost:8080`  | Agent Shield API endpoint URL.                                     |
| `api_key`          | string | No       | —                        | API key for authentication. Can also use `AGENT_SHIELD_API_KEY`.   |
| `default_severity` | string | No       | `medium`                 | Default minimum severity (`critical`, `high`, `medium`, `low`).    |

## Resources

### agent_shield_policy

Manages a security policy that defines detection rules, severity thresholds, and categories.

```hcl
resource "agent_shield_policy" "example" {
  name            = "production-security"
  description     = "Strict detection for production agents"
  min_severity    = "low"
  block_on_threat = true
  enabled         = true

  categories = [
    "prompt_injection",
    "data_exfiltration",
    "pii_detection",
  ]

  custom_patterns = [
    {
      regex       = "(?i)api[_-]?key\\s*[:=]\\s*[A-Za-z0-9]{32,}"
      severity    = "critical"
      category    = "data_exfiltration"
      description = "Detect exposed API keys"
    },
  ]
}
```

| Attribute         | Type         | Required | Default    | Description                                     |
|-------------------|--------------|----------|------------|-------------------------------------------------|
| `name`            | string       | Yes      | —          | Policy name.                                    |
| `description`     | string       | No       | —          | Policy description.                             |
| `min_severity`    | string       | No       | `medium`   | Minimum severity to trigger detection.          |
| `block_on_threat` | bool         | No       | `true`     | Block requests when a threat is detected.       |
| `categories`      | list(string) | No       | —          | Detection categories to enable.                 |
| `custom_patterns` | list(object) | No       | —          | Custom patterns (regex, severity, category, description). |
| `enabled`         | bool         | No       | `true`     | Whether the policy is active.                   |

**Read-only attributes:** `id`, `created_at`, `updated_at`

### agent_shield_rule

Manages an individual detection rule within a policy.

```hcl
resource "agent_shield_rule" "example" {
  policy_id   = agent_shield_policy.example.id
  pattern     = "(?i)(drop|truncate)\\s+table"
  severity    = "critical"
  category    = "tool_abuse"
  description = "Detect SQL injection attempts"
  enabled     = true
}
```

| Attribute     | Type   | Required | Default | Description                                  |
|---------------|--------|----------|---------|----------------------------------------------|
| `policy_id`   | string | Yes      | —       | ID of the parent policy.                     |
| `pattern`     | string | Yes      | —       | Regex pattern for threat detection.          |
| `severity`    | string | Yes      | —       | Severity level (`critical`, `high`, `medium`, `low`). |
| `category`    | string | Yes      | —       | Detection category (e.g., `prompt_injection`). |
| `description` | string | No       | —       | What this rule detects.                      |
| `enabled`     | bool   | No       | `true`  | Whether the rule is active.                  |

**Read-only attributes:** `id`, `created_at`, `updated_at`

### agent_shield_tenant

Manages a tenant in a multi-tenant Agent Shield deployment.

```hcl
resource "agent_shield_tenant" "example" {
  name                    = "acme-corp"
  policy_id               = agent_shield_policy.example.id
  max_requests_per_minute = 5000
  sso_provider            = "okta"

  allowed_categories = ["prompt_injection", "data_exfiltration"]
  blocked_categories = []
}
```

| Attribute                 | Type         | Required | Default | Description                                       |
|---------------------------|--------------|----------|---------|---------------------------------------------------|
| `name`                    | string       | Yes      | —       | Tenant name.                                      |
| `policy_id`               | string       | Yes      | —       | ID of the assigned security policy.               |
| `max_requests_per_minute` | int          | No       | `1000`  | Rate limit for scan requests.                     |
| `allowed_categories`      | list(string) | No       | —       | Categories to enable (allowlist).                 |
| `blocked_categories`      | list(string) | No       | —       | Categories to disable (blocklist).                |
| `sso_provider`            | string       | No       | —       | SSO provider (`okta`, `azure_ad`, `google`, `onelogin`, `auth0`, `custom`). |

**Read-only attributes:** `id`, `created_at`, `updated_at`

## Data Sources

### agent_shield_patterns

Read-only access to the built-in detection patterns and categories.

```hcl
data "agent_shield_patterns" "all" {}

data "agent_shield_patterns" "injection" {
  category = "prompt_injection"
}

output "pattern_count" {
  value = data.agent_shield_patterns.all.pattern_count
}
```

| Attribute  | Type   | Required | Description                         |
|------------|--------|----------|-------------------------------------|
| `category` | string | No       | Filter patterns by category.        |

**Read-only attributes:**

| Attribute       | Type         | Description                          |
|-----------------|--------------|--------------------------------------|
| `patterns`      | list(object) | List of patterns (name, regex, severity, category, description). |
| `categories`    | list(string) | All available detection categories.  |
| `pattern_count` | int          | Number of patterns returned.         |

## Examples

See the [`examples/`](examples/) directory:

- **[`main.tf`](examples/main.tf)** — Single-tenant setup with custom patterns and rules.
- **[`multi-tenant.tf`](examples/multi-tenant.tf)** — Variable-driven multi-tenant deployment with tiered policies.

## Import

Existing resources can be imported using their ID:

```bash
# Import a policy
terraform import agent_shield_policy.example policy-a1b2c3d4e5f67890

# Import a rule
terraform import agent_shield_rule.example rule-a1b2c3d4e5f67890

# Import a tenant
terraform import agent_shield_tenant.example tenant-a1b2c3d4e5f67890
```

## Building

```bash
cd terraform-provider
go build -o terraform-provider-agent-shield .
```

Move the binary into your Terraform plugins directory:

```bash
mkdir -p ~/.terraform.d/plugins/agentshield/agent-shield/0.1.0/linux_amd64/
mv terraform-provider-agent-shield ~/.terraform.d/plugins/agentshield/agent-shield/0.1.0/linux_amd64/
```
