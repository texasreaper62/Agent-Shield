package main

import (
	"fmt"
	"strings"
	"time"
)

// TenantResource manages multi-tenant configurations for Agent Shield.
// Each tenant can have its own policy assignment, rate limits, category
// filters, and SSO integration.
type TenantResource struct {
	provider *Provider
}

// NewTenantResource creates a Terraform resource definition for agent_shield_tenant.
func NewTenantResource(p *Provider) *Resource {
	tr := &TenantResource{provider: p}
	return &Resource{
		Schema: Schema{
			"id": {
				Type:        "string",
				Description: "Unique identifier for the tenant (generated).",
			},
			"name": {
				Type:        "string",
				Required:    true,
				Description: "Human-readable name for the tenant.",
			},
			"policy_id": {
				Type:        "string",
				Required:    true,
				Description: "ID of the security policy assigned to this tenant.",
			},
			"max_requests_per_minute": {
				Type:        "int",
				Optional:    true,
				Default:     1000,
				Description: "Maximum number of scan requests allowed per minute for this tenant.",
			},
			"allowed_categories": {
				Type:        "list",
				Optional:    true,
				Description: "List of detection categories explicitly allowed for this tenant. If set, only these categories are active.",
			},
			"blocked_categories": {
				Type:        "list",
				Optional:    true,
				Description: "List of detection categories to disable for this tenant.",
			},
			"sso_provider": {
				Type:        "string",
				Optional:    true,
				Description: "SSO provider identifier for tenant authentication (e.g., okta, azure_ad, google).",
			},
			"created_at": {
				Type:        "string",
				Description: "Timestamp when the tenant was created (ISO 8601).",
			},
			"updated_at": {
				Type:        "string",
				Description: "Timestamp when the tenant was last updated (ISO 8601).",
			},
		},
		Create: tr.Create,
		Read:   tr.Read,
		Update: tr.Update,
		Delete: tr.Delete,
	}
}

// Create provisions a new tenant with the given configuration.
func (tr *TenantResource) Create(data map[string]interface{}) (map[string]interface{}, error) {
	if err := tr.provider.isConfigured(); err != nil {
		return nil, err
	}

	// Validate required fields
	name, ok := data["name"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("name is required and must be a non-empty string")
	}

	policyID, ok := data["policy_id"].(string)
	if !ok || strings.TrimSpace(policyID) == "" {
		return nil, fmt.Errorf("policy_id is required and must be a non-empty string")
	}

	// Verify the referenced policy exists
	if _, exists := tr.provider.policyStore[policyID]; !exists {
		return nil, fmt.Errorf("policy %s not found; create the policy before creating tenants", policyID)
	}

	// Apply defaults
	if _, ok := data["max_requests_per_minute"]; !ok {
		data["max_requests_per_minute"] = 1000
	}

	// Validate max_requests_per_minute is positive
	if rpm, ok := data["max_requests_per_minute"].(int); ok {
		if rpm <= 0 {
			return nil, fmt.Errorf("max_requests_per_minute must be a positive integer")
		}
	}

	// Validate SSO provider if set
	if sso, ok := data["sso_provider"].(string); ok {
		validSSO := []string{"okta", "azure_ad", "google", "onelogin", "auth0", "custom"}
		sso = strings.ToLower(strings.TrimSpace(sso))
		found := false
		for _, v := range validSSO {
			if v == sso {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("sso_provider must be one of: %s", strings.Join(validSSO, ", "))
		}
		data["sso_provider"] = sso
	}

	// Generate ID and timestamps
	id := generateID("tenant")
	now := time.Now().UTC().Format(time.RFC3339)

	state := copyMap(data)
	state["id"] = id
	state["created_at"] = now
	state["updated_at"] = now

	tr.provider.tenantStore[id] = state
	return state, nil
}

// Read retrieves the current state of a tenant by its ID.
func (tr *TenantResource) Read(id string) (map[string]interface{}, error) {
	if err := tr.provider.isConfigured(); err != nil {
		return nil, err
	}

	state, ok := tr.provider.tenantStore[id]
	if !ok {
		return nil, fmt.Errorf("tenant %s not found", id)
	}

	return copyMap(state), nil
}

// Update modifies an existing tenant configuration. The ID cannot be changed.
func (tr *TenantResource) Update(id string, data map[string]interface{}) (map[string]interface{}, error) {
	if err := tr.provider.isConfigured(); err != nil {
		return nil, err
	}

	existing, ok := tr.provider.tenantStore[id]
	if !ok {
		return nil, fmt.Errorf("tenant %s not found", id)
	}

	state := copyMap(existing)
	for k, v := range data {
		if k == "id" || k == "created_at" {
			continue // immutable fields
		}
		state[k] = v
	}

	// Re-validate policy reference if changed
	if policyID, ok := state["policy_id"].(string); ok {
		if _, exists := tr.provider.policyStore[policyID]; !exists {
			return nil, fmt.Errorf("policy %s not found", policyID)
		}
	}

	// Validate max_requests_per_minute if changed
	if rpm, ok := state["max_requests_per_minute"].(int); ok {
		if rpm <= 0 {
			return nil, fmt.Errorf("max_requests_per_minute must be a positive integer")
		}
	}

	state["updated_at"] = time.Now().UTC().Format(time.RFC3339)

	tr.provider.tenantStore[id] = state
	return state, nil
}

// Delete removes a tenant by its ID.
func (tr *TenantResource) Delete(id string) error {
	if err := tr.provider.isConfigured(); err != nil {
		return err
	}

	if _, ok := tr.provider.tenantStore[id]; !ok {
		return fmt.Errorf("tenant %s not found", id)
	}

	delete(tr.provider.tenantStore, id)
	return nil
}
