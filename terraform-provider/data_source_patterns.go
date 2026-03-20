package main

// PatternsDataSource provides read-only access to the built-in detection
// patterns and categories available in Agent Shield. This data source is
// useful for discovering what patterns exist before writing custom rules.
type PatternsDataSource struct {
	provider *Provider
}

// BuiltinPattern describes a single built-in detection pattern.
type BuiltinPattern struct {
	Name        string
	Regex       string
	Severity    string
	Category    string
	Description string
}

// builtinPatterns is the catalogue of detection patterns that ship with
// Agent Shield. These correspond to the patterns in src/detector-core.js.
var builtinPatterns = []BuiltinPattern{
	{
		Name:        "system_prompt_override",
		Regex:       `(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)`,
		Severity:    "critical",
		Category:    "prompt_injection",
		Description: "Detects attempts to override or ignore the system prompt.",
	},
	{
		Name:        "role_impersonation",
		Regex:       `(?i)you\s+are\s+now\s+(a|an|the)\s+\w+`,
		Severity:    "high",
		Category:    "prompt_injection",
		Description: "Detects attempts to reassign the AI's role.",
	},
	{
		Name:        "data_exfiltration_url",
		Regex:       `(?i)(fetch|curl|wget|http|send\s+to)\s+(https?://|ftp://)`,
		Severity:    "critical",
		Category:    "data_exfiltration",
		Description: "Detects attempts to exfiltrate data via URLs.",
	},
	{
		Name:        "pii_ssn",
		Regex:       `\b\d{3}-\d{2}-\d{4}\b`,
		Severity:    "high",
		Category:    "pii_detection",
		Description: "Detects US Social Security numbers.",
	},
	{
		Name:        "pii_credit_card",
		Regex:       `\b(?:\d{4}[-\s]?){3}\d{4}\b`,
		Severity:    "high",
		Category:    "pii_detection",
		Description: "Detects credit card numbers.",
	},
	{
		Name:        "pii_email",
		Regex:       `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
		Severity:    "medium",
		Category:    "pii_detection",
		Description: "Detects email addresses.",
	},
	{
		Name:        "tool_abuse_file_system",
		Regex:       `(?i)(rm\s+-rf|del\s+/[sq]|format\s+[a-z]:)`,
		Severity:    "critical",
		Category:    "tool_abuse",
		Description: "Detects destructive file system commands.",
	},
	{
		Name:        "tool_abuse_privilege_escalation",
		Regex:       `(?i)(sudo|runas|chmod\s+777|chown\s+root)`,
		Severity:    "high",
		Category:    "tool_abuse",
		Description: "Detects privilege escalation attempts.",
	},
	{
		Name:        "encoding_base64_payload",
		Regex:       `(?i)(eval|exec|run)\s*\(\s*(atob|base64_decode|Buffer\.from)\s*\(`,
		Severity:    "high",
		Category:    "encoding_attack",
		Description: "Detects encoded payload execution attempts.",
	},
	{
		Name:        "jailbreak_dan",
		Regex:       `(?i)(DAN|do\s+anything\s+now|jailbreak|developer\s+mode)`,
		Severity:    "high",
		Category:    "jailbreak",
		Description: "Detects common jailbreak prompts like DAN.",
	},
	{
		Name:        "indirect_injection",
		Regex:       `(?i)(when\s+you\s+see\s+this|if\s+you\s+are\s+an?\s+AI|attention\s+model)`,
		Severity:    "high",
		Category:    "indirect_injection",
		Description: "Detects indirect prompt injection markers.",
	},
	{
		Name:        "canary_leak",
		Regex:       `(?i)(system\s+prompt|initial\s+instructions|you\s+were\s+told|your\s+instructions)`,
		Severity:    "medium",
		Category:    "prompt_leak",
		Description: "Detects attempts to extract the system prompt.",
	},
}

// builtinCategories lists all detection categories supported by Agent Shield.
var builtinCategories = []string{
	"prompt_injection",
	"data_exfiltration",
	"pii_detection",
	"tool_abuse",
	"encoding_attack",
	"jailbreak",
	"indirect_injection",
	"prompt_leak",
	"fragmentation",
	"language_switch",
	"steganography",
	"multi_agent_attack",
}

// NewPatternsDataSource creates a Terraform data source for reading the
// built-in detection patterns and categories available in Agent Shield.
func NewPatternsDataSource(p *Provider) *DataSource {
	ds := &PatternsDataSource{provider: p}
	return &DataSource{
		Schema: Schema{
			"category": {
				Type:        "string",
				Optional:    true,
				Description: "Filter patterns by category. If not set, all patterns are returned.",
			},
			"patterns": {
				Type:        "list_object",
				Description: "List of built-in detection patterns.",
				Fields:      []string{"name", "regex", "severity", "category", "description"},
			},
			"categories": {
				Type:        "list",
				Description: "List of all available detection categories.",
			},
			"pattern_count": {
				Type:        "int",
				Description: "Total number of patterns returned.",
			},
		},
		Read: ds.Read,
	}
}

// Read returns the built-in detection patterns, optionally filtered by
// category. It always returns the full list of available categories.
func (ds *PatternsDataSource) Read(data map[string]interface{}) (map[string]interface{}, error) {
	if err := ds.provider.isConfigured(); err != nil {
		return nil, err
	}

	// Optional category filter
	categoryFilter := ""
	if v, ok := data["category"].(string); ok && v != "" {
		categoryFilter = v
	}

	// Build pattern list
	var patterns []map[string]interface{}
	for _, p := range builtinPatterns {
		if categoryFilter != "" && p.Category != categoryFilter {
			continue
		}
		patterns = append(patterns, map[string]interface{}{
			"name":        p.Name,
			"regex":       p.Regex,
			"severity":    p.Severity,
			"category":    p.Category,
			"description": p.Description,
		})
	}

	// Build category list
	categories := make([]interface{}, len(builtinCategories))
	for i, c := range builtinCategories {
		categories[i] = c
	}

	result := map[string]interface{}{
		"patterns":      patterns,
		"categories":    categories,
		"pattern_count": len(patterns),
	}

	return result, nil
}
