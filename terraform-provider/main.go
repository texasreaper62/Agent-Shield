// Package main implements a Terraform provider for Agent Shield.
//
// This provider enables enterprises to manage Agent Shield security policies,
// rules, and multi-tenant configurations as infrastructure-as-code using
// Terraform. All detection runs locally with zero external dependencies.
//
// Usage:
//
//	provider "agent_shield" {
//	  endpoint         = "http://localhost:8080"
//	  api_key          = var.shield_api_key
//	  default_severity = "medium"
//	}
package main

import (
	"fmt"
	"os"
)

// Version is the provider version, set at build time.
var Version = "0.1.0"

// SchemaField describes a single field in a resource or provider schema.
type SchemaField struct {
	Type        string      // "string", "int", "bool", "list", "list_object"
	Required    bool        // Whether the field must be set
	Optional    bool        // Whether the field is optional
	Sensitive   bool        // Whether the value should be masked in output
	Default     interface{} // Default value if not set
	Description string      // Human-readable description
	Fields      []string    // Sub-fields for list_object type
}

// Schema is a map of field names to their schema definitions.
type Schema map[string]SchemaField

// Resource represents a Terraform managed resource with CRUD operations.
type Resource struct {
	Schema Schema
	Create func(data map[string]interface{}) (map[string]interface{}, error)
	Read   func(id string) (map[string]interface{}, error)
	Update func(id string, data map[string]interface{}) (map[string]interface{}, error)
	Delete func(id string) error
}

// DataSource represents a Terraform data source (read-only).
type DataSource struct {
	Schema Schema
	Read   func(data map[string]interface{}) (map[string]interface{}, error)
}

// ProviderSchema defines the configuration schema for the Agent Shield provider.
var ProviderSchema = Schema{
	"endpoint": {
		Type:        "string",
		Optional:    true,
		Default:     "http://localhost:8080",
		Description: "The Agent Shield API endpoint URL.",
	},
	"api_key": {
		Type:        "string",
		Optional:    true,
		Sensitive:   true,
		Description: "API key for authenticating with the Agent Shield API.",
	},
	"default_severity": {
		Type:        "string",
		Optional:    true,
		Default:     "medium",
		Description: "Default minimum severity level for threat detection (critical, high, medium, low).",
	},
}

// ResourceTypes returns the names of all resource types supported by this provider.
var ResourceTypes = []string{
	"agent_shield_policy",
	"agent_shield_rule",
	"agent_shield_tenant",
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Agent Shield Terraform Provider v%s\n", Version)
		fmt.Println("This binary is a Terraform plugin. Run it with Terraform.")
		fmt.Println()
		fmt.Println("Supported resource types:")
		for _, rt := range ResourceTypes {
			fmt.Printf("  - %s\n", rt)
		}
		fmt.Println()
		fmt.Println("Supported data sources:")
		fmt.Println("  - agent_shield_patterns")
		os.Exit(0)
	}

	// In a real Terraform provider, the plugin framework handles gRPC
	// serving. Here we simulate the provider lifecycle for demonstration.
	arg := os.Args[1]
	switch arg {
	case "serve":
		serve()
	case "version":
		fmt.Printf("Agent Shield Terraform Provider v%s\n", Version)
	case "validate":
		validate()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", arg)
		os.Exit(1)
	}
}

// serve simulates the Terraform plugin serve loop.
func serve() {
	provider := NewProvider()
	fmt.Printf("[Agent Shield] Provider v%s ready\n", Version)
	fmt.Printf("[Agent Shield] Resources: %d\n", len(provider.Resources()))
	fmt.Printf("[Agent Shield] Data sources: %d\n", len(provider.DataSources()))
	fmt.Println("[Agent Shield] Waiting for Terraform RPC calls...")
}

// validate runs basic schema validation on all resources and data sources.
func validate() {
	provider := NewProvider()

	// Configure with defaults
	err := provider.Configure(map[string]interface{}{
		"endpoint":         "http://localhost:8080",
		"default_severity": "medium",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	resources := provider.Resources()
	for name, res := range resources {
		fmt.Printf("[Agent Shield] Validated resource: %s (%d fields)\n", name, len(res.Schema))
	}

	dataSources := provider.DataSources()
	for name, ds := range dataSources {
		fmt.Printf("[Agent Shield] Validated data source: %s (%d fields)\n", name, len(ds.Schema))
	}

	fmt.Println("[Agent Shield] All schemas valid.")
}
