package main

import (
	"fmt"
	"strings"
	"time"
)

// RuleResource manages individual detection rules within an Agent Shield
// policy. Each rule defines a regex pattern, severity level, and category
// that the shield uses to identify threats.
type RuleResource struct {
	provider *Provider
}

// NewRuleResource creates a Terraform resource definition for agent_shield_rule.
func NewRuleResource(p *Provider) *Resource {
	rr := &RuleResource{provider: p}
	return &Resource{
		Schema: Schema{
			"id": {
				Type:        "string",
				Description: "Unique identifier for the rule (generated).",
			},
			"policy_id": {
				Type:        "string",
				Required:    true,
				Description: "ID of the parent policy this rule belongs to.",
			},
			"pattern": {
				Type:        "string",
				Required:    true,
				Description: "Regular expression pattern used for threat detection.",
			},
			"severity": {
				Type:        "string",
				Required:    true,
				Description: "Severity level of threats matching this rule (critical, high, medium, low).",
			},
			"category": {
				Type:        "string",
				Required:    true,
				Description: "Detection category for this rule (e.g., prompt_injection, data_exfiltration).",
			},
			"description": {
				Type:        "string",
				Optional:    true,
				Description: "Human-readable description of what this rule detects.",
			},
			"enabled": {
				Type:        "bool",
				Optional:    true,
				Default:     true,
				Description: "Whether the rule is active.",
			},
			"created_at": {
				Type:        "string",
				Description: "Timestamp when the rule was created (ISO 8601).",
			},
			"updated_at": {
				Type:        "string",
				Description: "Timestamp when the rule was last updated (ISO 8601).",
			},
		},
		Create: rr.Create,
		Read:   rr.Read,
		Update: rr.Update,
		Delete: rr.Delete,
	}
}

// Create provisions a new detection rule and associates it with the
// specified policy. Returns the full state including generated ID.
func (rr *RuleResource) Create(data map[string]interface{}) (map[string]interface{}, error) {
	if err := rr.provider.isConfigured(); err != nil {
		return nil, err
	}

	// Validate required fields
	policyID, ok := data["policy_id"].(string)
	if !ok || strings.TrimSpace(policyID) == "" {
		return nil, fmt.Errorf("policy_id is required and must be a non-empty string")
	}

	// Verify the referenced policy exists
	if _, exists := rr.provider.policyStore[policyID]; !exists {
		return nil, fmt.Errorf("policy %s not found; create the policy before adding rules", policyID)
	}

	pattern, ok := data["pattern"].(string)
	if !ok || strings.TrimSpace(pattern) == "" {
		return nil, fmt.Errorf("pattern is required and must be a non-empty regex string")
	}

	severity, ok := data["severity"].(string)
	if !ok || strings.TrimSpace(severity) == "" {
		return nil, fmt.Errorf("severity is required")
	}
	severity = strings.ToLower(strings.TrimSpace(severity))
	if !isValidSeverity(severity) {
		return nil, fmt.Errorf("severity must be one of: %s", strings.Join(validSeverities, ", "))
	}

	category, ok := data["category"].(string)
	if !ok || strings.TrimSpace(category) == "" {
		return nil, fmt.Errorf("category is required and must be a non-empty string")
	}

	// Apply defaults
	if _, ok := data["enabled"]; !ok {
		data["enabled"] = true
	}

	// Generate ID and timestamps
	id := generateID("rule")
	now := time.Now().UTC().Format(time.RFC3339)

	state := copyMap(data)
	state["id"] = id
	state["severity"] = severity
	state["pattern"] = pattern
	state["category"] = strings.TrimSpace(category)
	state["created_at"] = now
	state["updated_at"] = now

	rr.provider.ruleStore[id] = state
	return state, nil
}

// Read retrieves the current state of a rule by its ID.
func (rr *RuleResource) Read(id string) (map[string]interface{}, error) {
	if err := rr.provider.isConfigured(); err != nil {
		return nil, err
	}

	state, ok := rr.provider.ruleStore[id]
	if !ok {
		return nil, fmt.Errorf("rule %s not found", id)
	}

	return copyMap(state), nil
}

// Update modifies an existing rule. The ID and policy_id cannot be changed.
func (rr *RuleResource) Update(id string, data map[string]interface{}) (map[string]interface{}, error) {
	if err := rr.provider.isConfigured(); err != nil {
		return nil, err
	}

	existing, ok := rr.provider.ruleStore[id]
	if !ok {
		return nil, fmt.Errorf("rule %s not found", id)
	}

	state := copyMap(existing)
	for k, v := range data {
		if k == "id" || k == "created_at" || k == "policy_id" {
			continue // immutable fields
		}
		state[k] = v
	}

	// Validate severity if changed
	if severity, ok := state["severity"].(string); ok {
		severity = strings.ToLower(strings.TrimSpace(severity))
		if !isValidSeverity(severity) {
			return nil, fmt.Errorf("severity must be one of: %s", strings.Join(validSeverities, ", "))
		}
		state["severity"] = severity
	}

	state["updated_at"] = time.Now().UTC().Format(time.RFC3339)

	rr.provider.ruleStore[id] = state
	return state, nil
}

// Delete removes a rule by its ID.
func (rr *RuleResource) Delete(id string) error {
	if err := rr.provider.isConfigured(); err != nil {
		return err
	}

	if _, ok := rr.provider.ruleStore[id]; !ok {
		return fmt.Errorf("rule %s not found", id)
	}

	delete(rr.provider.ruleStore, id)
	return nil
}
