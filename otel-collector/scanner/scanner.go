// Package scanner provides a standalone Go implementation of Agent Shield
// detection patterns. It runs entirely locally with zero external dependencies,
// scanning text for prompt injection, data exfiltration, tool abuse, and 25+
// other AI-specific threat patterns.
package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Severity represents the severity level of a detected threat.
type Severity int

const (
	// SeverityLow indicates a low-risk threat.
	SeverityLow Severity = iota
	// SeverityMedium indicates a medium-risk threat.
	SeverityMedium
	// SeverityHigh indicates a high-risk threat.
	SeverityHigh
	// SeverityCritical indicates a critical-risk threat.
	SeverityCritical
)

// String returns the string representation of a Severity.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity converts a string to a Severity level.
// Returns SeverityLow if the string is unrecognized.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityLow
	}
}

// Category represents the category of a detected threat.
type Category string

const (
	CategoryPromptInjection   Category = "prompt_injection"
	CategoryJailbreak         Category = "jailbreak"
	CategoryDataExfiltration  Category = "data_exfiltration"
	CategoryToolAbuse         Category = "tool_abuse"
	CategoryPII               Category = "pii_exposure"
	CategorySystemPromptLeak  Category = "system_prompt_leak"
	CategoryEncodingAttack    Category = "encoding_attack"
	CategorySocialEngineering Category = "social_engineering"
	CategoryPrivilegeEscalation Category = "privilege_escalation"
	CategoryResourceAbuse     Category = "resource_abuse"
)

// Threat represents a single detected threat within scanned text.
type Threat struct {
	// Category of the threat (e.g., prompt_injection, jailbreak).
	Category Category `json:"category"`
	// Severity level of the threat.
	Severity Severity `json:"severity"`
	// SeverityStr is the string form of the severity for serialization.
	SeverityStr string `json:"severity_str"`
	// Description is a human-readable explanation of the threat.
	Description string `json:"description"`
	// Pattern is the name of the pattern that matched.
	Pattern string `json:"pattern"`
	// Matched is the substring that triggered the detection.
	Matched string `json:"matched"`
	// Position is the character offset where the match was found.
	Position int `json:"position"`
}

// ScanResult holds the result of scanning a text input.
type ScanResult struct {
	// Threats contains all detected threats.
	Threats []Threat `json:"threats"`
	// Scanned is true if the scan completed successfully.
	Scanned bool `json:"scanned"`
	// Duration is how long the scan took.
	Duration time.Duration `json:"duration"`
	// InputHash is the SHA-256 hash of the scanned input.
	InputHash string `json:"input_hash"`
	// ThreatCount is the total number of threats detected.
	ThreatCount int `json:"threat_count"`
	// MaxSeverity is the highest severity found, or -1 if no threats.
	MaxSeverity Severity `json:"max_severity"`
}

// IsThreat returns true if any threats were detected.
func (r *ScanResult) IsThreat() bool {
	return len(r.Threats) > 0
}

// HasSeverityAtLeast returns true if any threat meets or exceeds the given severity.
func (r *ScanResult) HasSeverityAtLeast(min Severity) bool {
	for _, t := range r.Threats {
		if t.Severity >= min {
			return true
		}
	}
	return false
}

// Config holds configuration for the Scanner.
type Config struct {
	// MinSeverity is the minimum severity level to report.
	MinSeverity Severity
	// Categories filters detection to specific categories. Empty means all.
	Categories []Category
	// MaxInputLength caps the input length to prevent resource abuse.
	// Zero means no limit.
	MaxInputLength int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		MinSeverity:    SeverityLow,
		Categories:     nil,
		MaxInputLength: 100000,
	}
}

// pattern is an internal detection pattern.
type pattern struct {
	name        string
	category    Category
	severity    Severity
	regex       *regexp.Regexp
	description string
}

// Scanner is the core detection engine. It is safe for concurrent use.
type Scanner struct {
	config   *Config
	patterns []pattern
}

// New creates a new Scanner with the given configuration.
// If config is nil, DefaultConfig() is used.
func New(config *Config) *Scanner {
	if config == nil {
		config = DefaultConfig()
	}
	s := &Scanner{config: config}
	s.initPatterns()
	return s
}

// initPatterns loads all 25+ detection patterns.
func (s *Scanner) initPatterns() {
	s.patterns = []pattern{
		// --- Prompt Injection (Critical) ---
		{
			name:        "direct_prompt_override",
			category:    CategoryPromptInjection,
			severity:    SeverityCritical,
			regex:       regexp.MustCompile(`(?i)(ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?))`),
			description: "Direct instruction to override system prompt",
		},
		{
			name:        "new_instructions_injection",
			category:    CategoryPromptInjection,
			severity:    SeverityCritical,
			regex:       regexp.MustCompile(`(?i)(new\s+instructions?|updated?\s+instructions?|revised?\s+instructions?)[\s:]*`),
			description: "Attempt to inject replacement instructions",
		},
		{
			name:        "system_prompt_prefix",
			category:    CategoryPromptInjection,
			severity:    SeverityCritical,
			regex:       regexp.MustCompile(`(?i)(^|\n)\s*(system\s*:|<\|?system\|?>|<<\s*SYS\s*>>|\[SYSTEM\])`),
			description: "Fake system prompt prefix injection",
		},
		{
			name:        "role_impersonation",
			category:    CategoryPromptInjection,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`(?i)(you\s+are\s+now|act\s+as\s+if|pretend\s+(you\s+are|to\s+be)|from\s+now\s+on\s+you)`),
			description: "Role impersonation to alter agent behavior",
		},
		{
			name:        "delimiter_injection",
			category:    CategoryPromptInjection,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`(?i)(---+\s*(end|begin|start)\s*(of\s+)?(system|instructions?|prompt)|<\/?system>|<\|im_start\|>|<\|im_end\|>)`),
			description: "Delimiter-based prompt boundary manipulation",
		},

		// --- Jailbreak (Critical / High) ---
		{
			name:        "dan_jailbreak",
			category:    CategoryJailbreak,
			severity:    SeverityCritical,
			regex:       regexp.MustCompile(`(?i)(DAN\s*(mode|prompt|jailbreak)|do\s+anything\s+now|dev(eloper)?\s+mode\s+(en|act))`),
			description: "DAN (Do Anything Now) jailbreak attempt",
		},
		{
			name:        "hypothetical_bypass",
			category:    CategoryJailbreak,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`(?i)(hypothetically|in\s+a\s+fictional\s+scenario|for\s+(educational|research|academic)\s+purposes?\s+only|imagine\s+you\s+(have\s+no|don'?t\s+have)\s+(restrictions?|limitations?|rules?))`),
			description: "Hypothetical scenario used to bypass restrictions",
		},
		{
			name:        "opposite_day",
			category:    CategoryJailbreak,
			severity:    SeverityMedium,
			regex:       regexp.MustCompile(`(?i)(opposite\s+day|opposite\s+mode|reverse\s+psychology\s+mode|everything\s+is\s+(reversed|opposite))`),
			description: "Opposite-mode trick to invert safety rules",
		},
		{
			name:        "character_roleplay",
			category:    CategoryJailbreak,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`(?i)(you\s+are\s+(an?\s+)?evil|you\s+have\s+been\s+(jailbroken|freed)|no\s+(ethical|moral)\s+(guidelines?|restrictions?))`),
			description: "Character roleplay to remove safety guardrails",
		},

		// --- Data Exfiltration (Critical) ---
		{
			name:        "url_exfiltration",
			category:    CategoryDataExfiltration,
			severity:    SeverityCritical,
			regex:       regexp.MustCompile(`(?i)(https?://[^\s]*\?(.*=.*){2,}|fetch\s*\(\s*['"]https?://|curl\s+(-[a-zA-Z]+\s+)*https?://|wget\s+https?://)`),
			description: "URL-based data exfiltration attempt",
		},
		{
			name:        "dns_exfiltration",
			category:    CategoryDataExfiltration,
			severity:    SeverityCritical,
			regex:       regexp.MustCompile(`(?i)(nslookup\s+|dig\s+|host\s+)[^\s]*\.(burpcollaborator|oastify|interact\.sh|canarytokens)`),
			description: "DNS-based data exfiltration via known services",
		},
		{
			name:        "encoded_exfiltration",
			category:    CategoryDataExfiltration,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`(?i)(base64\s*(encode|decode|_encode|_decode)|btoa|atob)\s*\(`),
			description: "Encoding function used for potential data exfiltration",
		},
		{
			name:        "webhook_exfiltration",
			category:    CategoryDataExfiltration,
			severity:    SeverityCritical,
			regex:       regexp.MustCompile(`(?i)(webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|ngrok\.io)`),
			description: "Known data exfiltration endpoint detected",
		},

		// --- Tool Abuse (High / Critical) ---
		{
			name:        "shell_injection",
			category:    CategoryToolAbuse,
			severity:    SeverityCritical,
			regex:       regexp.MustCompile(`(?i)(;\s*(rm|cat|curl|wget|nc|bash|sh|python|perl|ruby)\s+|&&\s*(rm|cat|curl)|` + "`" + `(rm|cat|curl|wget)[^` + "`" + `]*` + "`" + `|\$\((rm|cat|curl|wget))`),
			description: "Shell command injection in tool arguments",
		},
		{
			name:        "path_traversal",
			category:    CategoryToolAbuse,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`(\.\.\/){2,}|\.\.\\|%2e%2e[%/]|\.\.%2f`),
			description: "Path traversal attempt in tool arguments",
		},
		{
			name:        "sql_injection",
			category:    CategoryToolAbuse,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`(?i)(\b(UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM)\b|'\s*(OR|AND)\s*'?\s*[0-9]+\s*=\s*[0-9])`),
			description: "SQL injection attempt detected",
		},
		{
			name:        "ssrf_attempt",
			category:    CategoryToolAbuse,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google|100\.100\.100\.200|fd00::|localhost:\d{4,5}|127\.0\.0\.1:\d{4,5})`),
			description: "Server-side request forgery (SSRF) targeting internal services",
		},

		// --- PII Exposure (High) ---
		{
			name:        "credit_card",
			category:    CategoryPII,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
			description: "Credit card number detected",
		},
		{
			name:        "ssn",
			category:    CategoryPII,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			description: "Social Security Number pattern detected",
		},
		{
			name:        "api_key_leak",
			category:    CategoryPII,
			severity:    SeverityCritical,
			regex:       regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20,})`),
			description: "API key or secret token detected",
		},

		// --- System Prompt Leak (High / Critical) ---
		{
			name:        "prompt_extraction",
			category:    CategorySystemPromptLeak,
			severity:    SeverityCritical,
			regex:       regexp.MustCompile(`(?i)(repeat\s+(your|the)\s+(system\s+)?(instructions?|prompt|rules?)|what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules?)|show\s+me\s+your\s+(system\s+)?(prompt|instructions?))`),
			description: "Attempt to extract system prompt",
		},
		{
			name:        "prompt_leak_via_format",
			category:    CategorySystemPromptLeak,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`(?i)(output\s+your\s+(initial|original|full|complete)\s+(prompt|instructions?|config)|print\s+(system|initial)\s+(message|prompt)|translate\s+your\s+(instructions?|prompt)\s+to)`),
			description: "System prompt leak via format/translation trick",
		},

		// --- Encoding Attack (Medium / High) ---
		{
			name:        "base64_payload",
			category:    CategoryEncodingAttack,
			severity:    SeverityMedium,
			regex:       regexp.MustCompile(`(?i)(decode\s+this|execute\s+this|run\s+this)[\s:]*[A-Za-z0-9+/]{20,}={0,2}`),
			description: "Encoded payload with execution instruction",
		},
		{
			name:        "hex_encoding",
			category:    CategoryEncodingAttack,
			severity:    SeverityMedium,
			regex:       regexp.MustCompile(`(?i)(\\x[0-9a-f]{2}){4,}|(%[0-9a-f]{2}){4,}`),
			description: "Hex-encoded content possibly hiding malicious payload",
		},
		{
			name:        "unicode_smuggling",
			category:    CategoryEncodingAttack,
			severity:    SeverityMedium,
			regex:       regexp.MustCompile(`(\\u[0-9a-fA-F]{4}){4,}`),
			description: "Unicode escape sequence smuggling",
		},

		// --- Social Engineering (Medium / High) ---
		{
			name:        "urgency_manipulation",
			category:    CategorySocialEngineering,
			severity:    SeverityMedium,
			regex:       regexp.MustCompile(`(?i)(this\s+is\s+(very\s+)?(urgent|critical|emergency)|immediately\s+(do|execute|run|perform)|lives?\s+(are|is)\s+at\s+stake|someone\s+will\s+(die|get\s+hurt))`),
			description: "Urgency-based social engineering to bypass safety checks",
		},
		{
			name:        "authority_impersonation",
			category:    CategorySocialEngineering,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`(?i)(i\s+am\s+(the|a|an)\s+(admin|administrator|developer|owner|CEO|CTO)|openai\s+(staff|employee|team)|anthropic\s+(staff|employee|team)|by\s+order\s+of\s+(management|the\s+board))`),
			description: "Authority impersonation to elevate privileges",
		},

		// --- Privilege Escalation (High / Critical) ---
		{
			name:        "role_elevation",
			category:    CategoryPrivilegeEscalation,
			severity:    SeverityHigh,
			regex:       regexp.MustCompile(`(?i)(elevate\s+(my\s+)?(privileges?|permissions?|access|role)|grant\s+(me\s+)?(admin|root|sudo)|switch\s+to\s+(admin|root|superuser)\s+mode)`),
			description: "Attempt to escalate privileges or role",
		},
		{
			name:        "config_override",
			category:    CategoryPrivilegeEscalation,
			severity:    SeverityCritical,
			regex:       regexp.MustCompile(`(?i)(override\s+(safety|security|config)|disable\s+(safety|security|filters?|guardrails?)|turn\s+off\s+(safety|security|content\s+filter))`),
			description: "Attempt to override safety configuration",
		},

		// --- Resource Abuse (Medium) ---
		{
			name:        "infinite_loop",
			category:    CategoryResourceAbuse,
			severity:    SeverityMedium,
			regex:       regexp.MustCompile(`(?i)(repeat\s+this\s+(forever|infinitely|1000\s+times)|while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)|do\s+this\s+(forever|endlessly))`),
			description: "Attempt to cause infinite loop or resource exhaustion",
		},
		{
			name:        "token_exhaustion",
			category:    CategoryResourceAbuse,
			severity:    SeverityMedium,
			regex:       regexp.MustCompile(`(?i)(generate\s+\d{4,}\s+(words?|tokens?|characters?|paragraphs?)|write\s+(a\s+)?\d{4,}\s+(word|token|character))`),
			description: "Attempt to exhaust token limits",
		},
	}
}

// Scan analyzes the given text for threats and returns a ScanResult.
// It is safe for concurrent use.
func (s *Scanner) Scan(text string) *ScanResult {
	start := time.Now()

	result := &ScanResult{
		Scanned:     true,
		InputHash:   hashText(text),
		MaxSeverity: Severity(-1),
	}

	// Enforce max input length.
	if s.config.MaxInputLength > 0 && len(text) > s.config.MaxInputLength {
		text = text[:s.config.MaxInputLength]
	}

	// Build a set of allowed categories for fast lookup.
	categoryFilter := make(map[Category]bool)
	for _, c := range s.config.Categories {
		categoryFilter[c] = true
	}
	filterByCategory := len(categoryFilter) > 0

	for _, p := range s.patterns {
		// Skip categories not in the filter, if a filter is set.
		if filterByCategory && !categoryFilter[p.category] {
			continue
		}

		// Skip patterns below the minimum severity.
		if p.severity < s.config.MinSeverity {
			continue
		}

		loc := p.regex.FindStringIndex(text)
		if loc == nil {
			continue
		}

		matched := text[loc[0]:loc[1]]
		// Truncate long matches for readability.
		if len(matched) > 200 {
			matched = matched[:200] + "..."
		}

		threat := Threat{
			Category:    p.category,
			Severity:    p.severity,
			SeverityStr: p.severity.String(),
			Description: p.description,
			Pattern:     p.name,
			Matched:     matched,
			Position:    loc[0],
		}

		result.Threats = append(result.Threats, threat)

		if p.severity > result.MaxSeverity {
			result.MaxSeverity = p.severity
		}
	}

	result.ThreatCount = len(result.Threats)
	result.Duration = time.Since(start)
	return result
}

// hashText returns the hex-encoded SHA-256 hash of the input text.
func hashText(text string) string {
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:])
}

// TraceIDFromHash converts the first 16 bytes of a hex hash into a
// 32-character trace ID string suitable for use as an OTel TraceID.
func TraceIDFromHash(hexHash string) string {
	if len(hexHash) < 32 {
		return fmt.Sprintf("%032s", hexHash)
	}
	return hexHash[:32]
}

// SpanIDFromHash converts bytes 16-24 of a hex hash into a
// 16-character span ID string suitable for use as an OTel SpanID.
func SpanIDFromHash(hexHash string) string {
	if len(hexHash) < 32 {
		return fmt.Sprintf("%016s", hexHash)
	}
	return hexHash[16:32]
}
