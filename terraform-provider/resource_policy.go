package main

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"
)

// PolicyResource manages Agent Shield security policies. A policy defines
// a collection of detection rules, severity thresholds, and categories
// that control how the shield evaluates agent input and output.
type PolicyResource struct {
	provider *Provider
}

// NewPolicyResource creates a Terraform resource definition for agent_shield_policy.
func NewPolicyResource(p *Provider) *Resource {
	pr := &PolicyResource{provider: p}
	return &Resource{
		Schema: Schema{
			"id": {
				Type:        "string",
				Description: "Unique identifier for the policy (generated).",
			},
			"name": {
				Type:        "string",
				Required:    true,
				Description: "Human-readable name for the policy.",
			},
			"description": {
				Type:        "string",
				Optional:    true,
				Description: "Description of the policy's purpose.",
			},
			"min_severity": {
				Type:        "string",
				Optional:    true,
				Default:     "medium",
				Description: "Minimum severity level that triggers detection (critical, high, medium, low).",
			},
			"block_on_threat": {
				Type:        "bool",
				Optional:    true,
				Default:     true,
				Description: "Whether to block requests when a threat is detected.",
			},
			"categories": {
				Type:        "list",
				Optional:    true,
				Description: "List of detection category names to enable.",
			},
			"custom_patterns": {
				Type:        "list_object",
				Optional:    true,
				Description: "List of custom detection patterns, each with regex, severity, category, and description.",
				Fields:      []string{"regex", "severity", "category", "description"},
			},
			"enabled": {
				Type:        "bool",
				Optional:    true,
				Default:     true,
				Description: "Whether the policy is active.",
			},
			"created_at": {
				Type:        "string",
				Description: "Timestamp when the policy was created (ISO 8601).",
			},
			"updated_at": {
				Type:        "string",
				Description: "Timestamp when the policy was last updated (ISO 8601).",
			},
		},
		Create: pr.Create,
		Read:   pr.Read,
		Update: pr.Update,
		Delete: pr.Delete,
	}
}

// Create provisions a new policy from the given data map and returns the
// resulting state including the generated ID and timestamps.
func (pr *PolicyResource) Create(data map[string]interface{}) (map[string]interface{}, error) {
	if err := pr.provider.isConfigured(); err != nil {
		return nil, err
	}

	// Validate required fields
	name, ok := data["name"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("name is required and must be a non-empty string")
	}

	// Apply defaults
	if _, ok := data["min_severity"]; !ok {
		data["min_severity"] = pr.provider.DefaultSeverity
	}
	if severity, ok := data["min_severity"].(string); ok {
		if !isValidSeverity(strings.ToLower(severity)) {
			return nil, fmt.Errorf("min_severity must be one of: %s", strings.Join(validSeverities, ", "))
		}
		data["min_severity"] = strings.ToLower(severity)
	}
	if _, ok := data["block_on_threat"]; !ok {
		data["block_on_threat"] = true
	}
	if _, ok := data["enabled"]; !ok {
		data["enabled"] = true
	}

	// Validate custom patterns if provided
	if patterns, ok := data["custom_patterns"].([]interface{}); ok {
		for i, p := range patterns {
			pm, ok := p.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("custom_patterns[%d] must be an object", i)
			}
			if _, ok := pm["regex"].(string); !ok {
				return nil, fmt.Errorf("custom_patterns[%d].regex is required", i)
			}
			if sev, ok := pm["severity"].(string); ok {
				if !isValidSeverity(strings.ToLower(sev)) {
					return nil, fmt.Errorf("custom_patterns[%d].severity must be one of: %s", i, strings.Join(validSeverities, ", "))
				}
			}
		}
	}

	// Generate ID and timestamps
	id := generateID("policy")
	now := time.Now().UTC().Format(time.RFC3339)

	state := copyMap(data)
	state["id"] = id
	state["created_at"] = now
	state["updated_at"] = now

	// Store state
	pr.provider.policyStore[id] = state
	return state, nil
}

// Read retrieves the current state of a policy by its ID.
func (pr *PolicyResource) Read(id string) (map[string]interface{}, error) {
	if err := pr.provider.isConfigured(); err != nil {
		return nil, err
	}

	state, ok := pr.provider.policyStore[id]
	if !ok {
		return nil, fmt.Errorf("policy %s not found", id)
	}

	return copyMap(state), nil
}

// Update modifies an existing policy. The ID cannot be changed.
func (pr *PolicyResource) Update(id string, data map[string]interface{}) (map[string]interface{}, error) {
	if err := pr.provider.isConfigured(); err != nil {
		return nil, err
	}

	existing, ok := pr.provider.policyStore[id]
	if !ok {
		return nil, fmt.Errorf("policy %s not found", id)
	}

	// Merge updates into existing state
	state := copyMap(existing)
	for k, v := range data {
		if k == "id" || k == "created_at" {
			continue // immutable fields
		}
		state[k] = v
	}

	// Validate severity if changed
	if severity, ok := state["min_severity"].(string); ok {
		if !isValidSeverity(strings.ToLower(severity)) {
			return nil, fmt.Errorf("min_severity must be one of: %s", strings.Join(validSeverities, ", "))
		}
		state["min_severity"] = strings.ToLower(severity)
	}

	state["updated_at"] = time.Now().UTC().Format(time.RFC3339)

	pr.provider.policyStore[id] = state
	return state, nil
}

// Delete removes a policy by its ID. Returns an error if the policy
// does not exist.
func (pr *PolicyResource) Delete(id string) error {
	if err := pr.provider.isConfigured(); err != nil {
		return err
	}

	if _, ok := pr.provider.policyStore[id]; !ok {
		return fmt.Errorf("policy %s not found", id)
	}

	delete(pr.provider.policyStore, id)
	return nil
}

// generateID creates a random prefixed identifier.
func generateID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%x", prefix, b)
}

// copyMap returns a shallow copy of the given map.
func copyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{}, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
