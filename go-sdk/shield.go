// Package agentshield provides local-only AI agent security scanning.
//
// Agent Shield detects prompt injection, data exfiltration, tool abuse,
// and 30+ other AI-specific threats. All detection runs locally via
// pattern matching — no external calls, no API keys, no data leaves
// the user's environment.
//
// Zero external dependencies: stdlib only.
package agentshield

import (
	"regexp"
	"strings"
	"time"
)

// Severity represents the severity level of a detected threat.
type Severity string

const (
	// SeverityCritical indicates a critical threat requiring immediate action.
	SeverityCritical Severity = "critical"
	// SeverityHigh indicates a high-severity threat.
	SeverityHigh Severity = "high"
	// SeverityMedium indicates a medium-severity threat.
	SeverityMedium Severity = "medium"
	// SeverityLow indicates a low-severity threat.
	SeverityLow Severity = "low"
)

// SeverityOrder maps severity levels to numeric values for comparison.
// Higher values indicate more severe threats.
var SeverityOrder = map[Severity]int{
	SeverityCritical: 4,
	SeverityHigh:     3,
	SeverityMedium:   2,
	SeverityLow:      1,
}

// Category represents a classification of threat type.
type Category string

const (
	// CategoryPromptInjection covers instruction override and prompt manipulation attacks.
	CategoryPromptInjection Category = "prompt_injection"
	// CategoryRoleHijacking covers attempts to change the AI's role or persona.
	CategoryRoleHijacking Category = "role_hijack"
	// CategoryDataExfiltration covers attempts to extract sensitive data.
	CategoryDataExfiltration Category = "data_exfiltration"
	// CategorySocialEngineering covers manipulation and social engineering attacks.
	CategorySocialEngineering Category = "social_engineering"
	// CategoryToolAbuse covers unauthorized tool or function call attempts.
	CategoryToolAbuse Category = "tool_abuse"
	// CategorySystemProbe covers attempts to probe system internals or configurations.
	CategorySystemProbe Category = "system_probe"
)

// AllCategories returns a slice containing all threat categories.
func AllCategories() []Category {
	return []Category{
		CategoryPromptInjection,
		CategoryRoleHijacking,
		CategoryDataExfiltration,
		CategorySocialEngineering,
		CategoryToolAbuse,
		CategorySystemProbe,
	}
}

// Pattern defines a detection rule with a regex, severity, and category.
type Pattern struct {
	// Regex is the regular expression string used for matching.
	Regex string
	// Severity is the threat severity level if this pattern matches.
	Severity Severity
	// Category classifies the type of threat this pattern detects.
	Category Category
	// Description is a human-readable explanation of the threat.
	Description string
	// compiled is the pre-compiled regexp for efficient matching.
	compiled *regexp.Regexp
}

// Threat represents a single detected threat in scanned text.
type Threat struct {
	// Category classifies the type of threat detected.
	Category Category `json:"category"`
	// Severity is the threat severity level.
	Severity Severity `json:"severity"`
	// Description is a human-readable explanation of the threat.
	Description string `json:"description"`
}

// ScanResult holds the outcome of scanning a text input.
type ScanResult struct {
	// Safe is true when no threats were detected.
	Safe bool `json:"safe"`
	// Threats contains all detected threats.
	Threats []Threat `json:"threats"`
	// Severity is the highest severity level found (empty string if safe).
	Severity string `json:"severity"`
	// ScanTimeUs is the scan duration in microseconds.
	ScanTimeUs int64 `json:"scan_time_us"`
	// InputLength is the length of the scanned input in bytes.
	InputLength int `json:"input_length"`
}

// ScanConfig controls scanning behavior.
type ScanConfig struct {
	// MinSeverity sets the minimum severity threshold for reported threats.
	// Threats below this severity are ignored. Defaults to SeverityLow.
	MinSeverity Severity
	// Categories limits scanning to specific threat categories.
	// An empty slice means all categories are scanned.
	Categories []Category
	// MaxInputSize is the maximum input size in bytes. Inputs exceeding
	// this are truncated before scanning. 0 means no limit.
	MaxInputSize int
	// TimeBudgetMs is the maximum time budget for a scan in milliseconds.
	// 0 means no time limit.
	TimeBudgetMs int
}

// Shield is the main scanner that detects threats in text input.
type Shield struct {
	patterns []Pattern
	config   ScanConfig
}

// New creates a new Shield with the given configuration.
// If config is nil, default settings are used (all categories, SeverityLow minimum).
func New(config *ScanConfig) *Shield {
	s := &Shield{
		patterns: DefaultPatterns(),
	}

	if config != nil {
		s.config = *config
	} else {
		s.config = ScanConfig{
			MinSeverity: SeverityLow,
		}
	}

	// Set default minimum severity if empty.
	if s.config.MinSeverity == "" {
		s.config.MinSeverity = SeverityLow
	}

	// Compile all patterns.
	for i := range s.patterns {
		s.patterns[i].compiled = regexp.MustCompile(s.patterns[i].Regex)
	}

	return s
}

// Scan analyzes text for security threats and returns a ScanResult.
func (s *Shield) Scan(text string) *ScanResult {
	start := time.Now()

	result := &ScanResult{
		Safe:        true,
		Threats:     []Threat{},
		InputLength: len(text),
	}

	// Enforce max input size.
	if s.config.MaxInputSize > 0 && len(text) > s.config.MaxInputSize {
		text = text[:s.config.MaxInputSize]
	}

	if text == "" {
		result.ScanTimeUs = time.Since(start).Microseconds()
		return result
	}

	lower := strings.ToLower(text)
	minOrder := SeverityOrder[s.config.MinSeverity]
	categorySet := s.buildCategorySet()
	highestOrder := 0

	var deadline time.Time
	hasDeadline := s.config.TimeBudgetMs > 0
	if hasDeadline {
		deadline = start.Add(time.Duration(s.config.TimeBudgetMs) * time.Millisecond)
	}

	for _, p := range s.patterns {
		// Check time budget.
		if hasDeadline && time.Now().After(deadline) {
			break
		}

		// Filter by severity threshold.
		order := SeverityOrder[p.Severity]
		if order < minOrder {
			continue
		}

		// Filter by category.
		if categorySet != nil {
			if _, ok := categorySet[p.Category]; !ok {
				continue
			}
		}

		// Match against lowercased text.
		if p.compiled.MatchString(lower) {
			threat := Threat{
				Category:    p.Category,
				Severity:    p.Severity,
				Description: p.Description,
			}
			result.Threats = append(result.Threats, threat)
			result.Safe = false

			if order > highestOrder {
				highestOrder = order
				result.Severity = string(p.Severity)
			}
		}
	}

	result.ScanTimeUs = time.Since(start).Microseconds()
	return result
}

// ScanBatch scans multiple texts and returns results in the same order.
func (s *Shield) ScanBatch(texts []string) []*ScanResult {
	results := make([]*ScanResult, len(texts))
	for i, text := range texts {
		results[i] = s.Scan(text)
	}
	return results
}

// PatternCount returns the number of loaded detection patterns.
func (s *Shield) PatternCount() int {
	return len(s.patterns)
}

// buildCategorySet returns a set of allowed categories, or nil if all are allowed.
func (s *Shield) buildCategorySet() map[Category]struct{} {
	if len(s.config.Categories) == 0 {
		return nil
	}
	set := make(map[Category]struct{}, len(s.config.Categories))
	for _, c := range s.config.Categories {
		set[c] = struct{}{}
	}
	return set
}

// DefaultPatterns returns the built-in set of 25+ detection patterns
// covering all six threat categories.
func DefaultPatterns() []Pattern {
	return []Pattern{
		// ---- Prompt Injection ----
		{
			Regex:       `ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|directives|rules)`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: "Instruction override: ignore previous instructions",
		},
		{
			Regex:       `disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|directives|context)`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: "Instruction override: disregard previous instructions",
		},
		{
			Regex:       `forget\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|prompts|directives|rules|training)`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: "Instruction override: forget previous instructions",
		},
		{
			Regex:       `new\s+(system\s+)?(instructions|prompt|directive|rules)\s*:`,
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: "Prompt injection: new instruction block",
		},
		{
			Regex:       `\[system\]|\[inst\]|\[\/inst\]|<\|im_start\|>|<\|system\|>`,
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: "Prompt injection: chat template markers",
		},
		{
			Regex:       `override\s+(your|the|all|system)\s+(instructions|rules|constraints|guidelines|behavior)`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: "Instruction override: override system rules",
		},

		// ---- Role Hijacking ----
		{
			Regex:       `you\s+are\s+now\s+(a|an|the|my)\s+`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijacking,
			Description: "Role hijacking: persona reassignment",
		},
		{
			Regex:       `act\s+as\s+(a|an|the|my)\s+(hacker|attacker|malicious|unrestricted|jailbroken|evil)`,
			Severity:    SeverityCritical,
			Category:    CategoryRoleHijacking,
			Description: "Role hijacking: malicious persona assignment",
		},
		{
			Regex:       `pretend\s+(you('re|are)|to\s+be)\s+(a|an|the)\s+`,
			Severity:    SeverityMedium,
			Category:    CategoryRoleHijacking,
			Description: "Role hijacking: pretend to be another entity",
		},
		{
			Regex:       `switch\s+to\s+(developer|admin|root|sudo|unrestricted|god)\s+mode`,
			Severity:    SeverityCritical,
			Category:    CategoryRoleHijacking,
			Description: "Role hijacking: switch to privileged mode",
		},
		{
			Regex:       `enable\s+(dan|jailbreak|developer|unrestricted)\s+mode`,
			Severity:    SeverityCritical,
			Category:    CategoryRoleHijacking,
			Description: "Role hijacking: enable jailbreak mode",
		},

		// ---- Data Exfiltration ----
		{
			Regex:       `(send|post|transmit|exfiltrate|upload)\s+(this|the|all|my)?\s*(data|info|information|content|message|conversation)\s+(to|via)\s+`,
			Severity:    SeverityCritical,
			Category:    CategoryDataExfiltration,
			Description: "Data exfiltration: send data to external target",
		},
		{
			Regex:       `(fetch|curl|wget|http(s)?:\/\/|ftp:\/\/)`,
			Severity:    SeverityMedium,
			Category:    CategoryDataExfiltration,
			Description: "Data exfiltration: URL or fetch reference detected",
		},
		{
			Regex:       `(encode|encrypt|compress)\s+(and\s+)?(send|transmit|upload|exfiltrate)`,
			Severity:    SeverityHigh,
			Category:    CategoryDataExfiltration,
			Description: "Data exfiltration: encode and transmit data",
		},
		{
			Regex:       `(api[_\s-]?key|secret[_\s-]?key|password|token|credential|private[_\s-]?key)\s*(is|=|:)\s*`,
			Severity:    SeverityHigh,
			Category:    CategoryDataExfiltration,
			Description: "Data exfiltration: credential or secret exposure",
		},
		{
			Regex:       `(show|reveal|display|print|output|dump)\s+(the\s+)?(system\s+prompt|internal\s+instructions|hidden\s+prompt|original\s+prompt)`,
			Severity:    SeverityHigh,
			Category:    CategoryDataExfiltration,
			Description: "Data exfiltration: system prompt extraction attempt",
		},

		// ---- Social Engineering ----
		{
			Regex:       `(this\s+is\s+(an?\s+)?(emergency|urgent|critical)|urgent\s*:|immediate\s+action\s+required)`,
			Severity:    SeverityMedium,
			Category:    CategorySocialEngineering,
			Description: "Social engineering: artificial urgency",
		},
		{
			Regex:       `(i('m| am)\s+(the|your|an?)\s+(admin|administrator|developer|owner|ceo|manager|supervisor))`,
			Severity:    SeverityMedium,
			Category:    CategorySocialEngineering,
			Description: "Social engineering: false authority claim",
		},
		{
			Regex:       `(do\s+not|don'?t)\s+(question|refuse|reject|deny|hesitate|think\s+about)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: "Social engineering: suppressing refusal behavior",
		},
		{
			Regex:       `(trust\s+me|believe\s+me|i\s+promise|you\s+can\s+trust)`,
			Severity:    SeverityLow,
			Category:    CategorySocialEngineering,
			Description: "Social engineering: trust manipulation",
		},
		{
			Regex:       `(no\s+one\s+will\s+(know|find\s+out|notice)|between\s+you\s+and\s+me|keep\s+this\s+secret)`,
			Severity:    SeverityMedium,
			Category:    CategorySocialEngineering,
			Description: "Social engineering: secrecy pressure",
		},

		// ---- Tool Abuse ----
		{
			Regex:       `(execute|run|eval)\s*\(\s*['"]`,
			Severity:    SeverityCritical,
			Category:    CategoryToolAbuse,
			Description: "Tool abuse: arbitrary code execution attempt",
		},
		{
			Regex:       `(rm\s+-rf|del\s+\/|format\s+c:|drop\s+table|delete\s+from)\s+`,
			Severity:    SeverityCritical,
			Category:    CategoryToolAbuse,
			Description: "Tool abuse: destructive command detected",
		},
		{
			Regex:       `(call|invoke|trigger|use)\s+(the\s+)?(tool|function|api|endpoint)\s+(to\s+)?(delete|destroy|remove|drop|wipe)`,
			Severity:    SeverityHigh,
			Category:    CategoryToolAbuse,
			Description: "Tool abuse: destructive tool invocation",
		},
		{
			Regex:       `(sudo|chmod\s+777|chown|pkill|kill\s+-9)`,
			Severity:    SeverityHigh,
			Category:    CategoryToolAbuse,
			Description: "Tool abuse: privileged system command",
		},

		// ---- System Probe ----
		{
			Regex:       `(what\s+(is|are)\s+your\s+(system\s+prompt|instructions|rules|constraints|guidelines|directives))`,
			Severity:    SeverityMedium,
			Category:    CategorySystemProbe,
			Description: "System probe: asking for system instructions",
		},
		{
			Regex:       `(list|show|tell\s+me|what\s+are)\s+(your\s+)?(available\s+)?(tools|functions|capabilities|apis|endpoints)`,
			Severity:    SeverityLow,
			Category:    CategorySystemProbe,
			Description: "System probe: tool enumeration attempt",
		},
		{
			Regex:       `(what\s+(model|version|llm)\s+(are\s+you|is\s+this)|which\s+(model|ai|llm)\s+(are\s+you|is\s+this))`,
			Severity:    SeverityLow,
			Category:    CategorySystemProbe,
			Description: "System probe: model identification attempt",
		},
		{
			Regex:       `(repeat|echo|print)\s+(everything|all)\s+(above|before|prior|from\s+the\s+start)`,
			Severity:    SeverityHigh,
			Category:    CategorySystemProbe,
			Description: "System probe: prompt echo/extraction attempt",
		},
	}
}
