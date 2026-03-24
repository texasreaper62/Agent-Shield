package main

import (
	"fmt"
	"strings"
)

// Provider implements the Agent Shield Terraform provider. It holds
// configuration state and exposes the set of managed resources and
// read-only data sources available to Terraform plans.
type Provider struct {
	// Endpoint is the Agent Shield API endpoint URL.
	Endpoint string

	// APIKey is the authentication key for the Agent Shield API.
	APIKey string

	// DefaultSeverity is the minimum severity level for threat detection.
	DefaultSeverity string

	// configured tracks whether Configure has been called successfully.
	configured bool

	// stores hold in-memory state for each resource type, simulating
	// a backend API or state store.
	policyStore map[string]map[string]interface{}
	ruleStore   map[string]map[string]interface{}
	tenantStore map[string]map[string]interface{}
}

// validSeverities lists the accepted severity level values.
var validSeverities = []string{"critical", "high", "medium", "low"}

// NewProvider creates a new unconfigured Provider instance with
// initialized internal stores.
func NewProvider() *Provider {
	return &Provider{
		policyStore: make(map[string]map[string]interface{}),
		ruleStore:   make(map[string]map[string]interface{}),
		tenantStore: make(map[string]map[string]interface{}),
	}
}

// Configure applies the given configuration map to the provider.
// It validates required fields and sets defaults where appropriate.
//
// Accepted configuration keys:
//   - endpoint: string (default "http://localhost:8080")
//   - api_key: string (optional, sensitive)
//   - default_severity: string (default "medium", one of critical|high|medium|low)
func (p *Provider) Configure(config map[string]interface{}) error {
	// Endpoint
	if v, ok := config["endpoint"]; ok {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("endpoint must be a string")
		}
		p.Endpoint = s
	} else {
		p.Endpoint = "http://localhost:8080"
	}

	// API Key
	if v, ok := config["api_key"]; ok {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("api_key must be a string")
		}
		p.APIKey = s
	}

	// Default Severity
	if v, ok := config["default_severity"]; ok {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("default_severity must be a string")
		}
		s = strings.ToLower(strings.TrimSpace(s))
		if !isValidSeverity(s) {
			return fmt.Errorf("default_severity must be one of: %s", strings.Join(validSeverities, ", "))
		}
		p.DefaultSeverity = s
	} else {
		p.DefaultSeverity = "medium"
	}

	p.configured = true
	return nil
}

// Resources returns the full map of managed resource types supported by
// this provider. Each key is a Terraform resource type name.
func (p *Provider) Resources() map[string]*Resource {
	return map[string]*Resource{
		"agent_shield_policy": NewPolicyResource(p),
		"agent_shield_rule":   NewRuleResource(p),
		"agent_shield_tenant": NewTenantResource(p),
	}
}

// DataSources returns the map of data sources supported by this provider.
// Data sources are read-only and do not create or manage infrastructure.
func (p *Provider) DataSources() map[string]*DataSource {
	return map[string]*DataSource{
		"agent_shield_patterns": NewPatternsDataSource(p),
	}
}

// isValidSeverity checks whether the given string is a recognized severity level.
func isValidSeverity(s string) bool {
	for _, v := range validSeverities {
		if v == s {
			return true
		}
	}
	return false
}

// isConfigured returns an error if the provider has not been configured.
func (p *Provider) isConfigured() error {
	if !p.configured {
		return fmt.Errorf("provider has not been configured; call Configure first")
	}
	return nil
}
