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
	// CategoryInstructionOverride covers attempts to override or ignore AI instructions.
	CategoryInstructionOverride Category = "instruction_override"
	// CategoryPromptInjection covers prompt manipulation and injection attacks.
	CategoryPromptInjection Category = "prompt_injection"
	// CategoryRoleHijack covers attempts to change the AI's role or persona.
	CategoryRoleHijack Category = "role_hijack"
	// CategoryRoleHijacking is a backward-compatible alias for CategoryRoleHijack.
	CategoryRoleHijacking = CategoryRoleHijack
	// CategoryDataExfiltration covers attempts to extract sensitive data.
	CategoryDataExfiltration Category = "data_exfiltration"
	// CategorySocialEngineering covers manipulation and social engineering attacks.
	CategorySocialEngineering Category = "social_engineering"
	// CategoryToolAbuse covers unauthorized tool or function call attempts.
	CategoryToolAbuse Category = "tool_abuse"
	// CategoryMaliciousPlugin covers attempts to install or abuse unverified AI plugins.
	CategoryMaliciousPlugin Category = "malicious_plugin"
	// CategoryAIPhishing covers AI-specific phishing and scam attempts.
	CategoryAIPhishing Category = "ai_phishing"
)

// AllCategories returns a slice containing all threat categories.
func AllCategories() []Category {
	return []Category{
		CategoryInstructionOverride,
		CategoryPromptInjection,
		CategoryRoleHijack,
		CategoryDataExfiltration,
		CategorySocialEngineering,
		CategoryToolAbuse,
		CategoryMaliciousPlugin,
		CategoryAIPhishing,
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

// DefaultPatterns returns the built-in set of 141 detection patterns
// covering all eight threat categories.
func DefaultPatterns() []Pattern {
	return []Pattern{

		// ---- Instruction Override (23 patterns) ----
		{
			Regex:       `ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts|context|directions|directives|text|commands)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI assistants to ignore their safety rules.`,
		},
		{
			Regex:       `^ignore\s+(?:the\s+)?(?:instructions|rules|guidelines|directives|commands)$`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI assistants to ignore instructions.`,
		},
		{
			Regex:       `disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|prompts|training|training\s+data|context)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI assistants to throw out their rules.`,
		},
		{
			Regex:       `forget\s+(your|all|any|everything)\s+(training|instructions|rules|guidelines|programming|above|previous|prior)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tries to make AI assistants forget their training.`,
		},
		{
			Regex:       `override\s+(?:all\s+)?(?:system|safety|security)\s+(?:settings|prompt|instructions|rules|mechanisms|filters|checks|protocols)`,
			Severity:    SeverityCritical,
			Category:    CategoryInstructionOverride,
			Description: `Text tries to override AI safety settings.`,
		},
		{
			Regex:       `(?:^|\n)\s*(?:new|updated|revised|replacement)\s+(?:instructions|policy)\s*:`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text contains fake "new instructions" for AI assistants.`,
		},
		{
			Regex:       `#{2,}\s*(?:new|updated|revised|replacement)\s+(?:instructions|rules|directives|policy)\s*#{0,}`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text uses markdown headers to inject fake new instructions.`,
		},
		{
			Regex:       `(?:you\s+must\s+)?ignore\s+(?:your|all\s+your|all\s+the|the)\s+(?:safety\s+)?(?:guidelines?|rules?|restrictions?|protocols?|safeguards?|filters?|limits?)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI to ignore its guidelines or safety rules.`,
		},
		{
			Regex:       `(?:abandon|drop|ditch|clear)\s+(?:all\s+)?(?:prior|previous|above|earlier|initial)\s+(?:context|instructions|rules|constraints|guidelines)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI to abandon its prior context or instructions.`,
		},
		{
			Regex:       `(?:stop|halt|end)\s*[.!]?\s*(?:new|updated|your\s+new|revised)\s+(?:instructions|task|orders|role|objective)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text uses a STOP command followed by new instructions.`,
		},
		{
			Regex:       `(?:you\s+are\s+)?(?:no\s+longer\s+bound|not\s+bound|free\s+from|freed?\s+from)\s+(?:by\s+)?(?:your\s+)?(?:initial|original|previous|prior)?\s*(?:instructions|rules|constraints|guidelines|restrictions)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text claims the AI is no longer bound by its rules.`,
		},
		{
			Regex:       `ignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI assistants to ignore their rules (in Spanish).`,
		},
		{
			Regex:       `olvida\s+(?:tu|todas?\s+(?:las\s+)?)\s*(?:instrucciones|reglas|entrenamiento)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI to forget its training (in Spanish).`,
		},
		{
			Regex:       `ignore[rz]?\s+(?:toutes?\s+)?(?:les\s+)?instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI assistants to ignore their rules (in French).`,
		},
		{
			Regex:       `oublie[rz]?\s+(?:ton|tes|votre|vos)\s+(?:instructions|r[eè]gles|entra[iî]nement)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI to forget its training (in French).`,
		},
		{
			Regex:       `ignoriere?\s+(?:alle\s+)?(?:vorherigen|bisherigen|fr[uü]heren)\s+(?:anweisungen|regeln|instruktionen)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI assistants to ignore their rules (in German).`,
		},
		{
			Regex:       `vergiss\s+(?:dein|deine|alle)\s+(?:training|anweisungen|regeln|programmierung)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI to forget its training (in German).`,
		},
		{
			Regex:       `ignore\s+(?:todas?\s+)?(?:as\s+)?instru[cç][oõ]es\s+(?:anteriores|pr[eé]vias)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI assistants to ignore their rules (in Portuguese).`,
		},
		{
			Regex:       `esque[cç]a\s+(?:seu|sua|todo|todas?)\s+(?:treinamento|instru[cç][oõ]es|regras)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI to forget its training (in Portuguese).`,
		},
		{
			Regex:       `忽略(?:所有)?(?:之前|以前|先前)的(?:指令|指示|规则|说明)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI assistants to ignore their rules (in Chinese).`,
		},
		{
			Regex:       `(?:以前|前)の(?:指示|命令|ルール|指令)を(?:無視|忘れ)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text tells AI assistants to ignore their rules (in Japanese).`,
		},
		{
			Regex:       `(?:the\s+user|i)\s+ha(?:s|ve)\s+updated\s+(?:your|the)\s+(?:instructions|rules|prompt|guidelines)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text falsely claims the AI instructions have been updated.`,
		},
		{
			Regex:       `new\s+rule\s*:\s*(?:always|never|from\s+now)`,
			Severity:    SeverityHigh,
			Category:    CategoryInstructionOverride,
			Description: `Text introduces a fake "new rule" to override AI behavior.`,
		},

		// ---- Prompt Injection (20 patterns) ----
		{
			Regex:       `(?:^|\n)\s*(?:system|admin|root)\s*:\s*.{10,}`,
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: `Text contains a fake SYSTEM/ADMIN directive.`,
		},
		{
			Regex:       `\[\s*(?:system|sys)\s*\]`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: `Text contains fake system-level commands for AI assistants.`,
		},
		{
			Regex:       `\[\s*(?:admin|administrator)\s*\]`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: `Text fakes admin-level commands for AI assistants.`,
		},
		{
			Regex:       `\[\s*(?:developer|dev)\s*\]`,
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: `Text contains fake developer commands for AI assistants.`,
		},
		{
			Regex:       `\[\s*override\s*\]`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: `Text contains override commands targeting AI assistants.`,
		},
		{
			Regex:       `<<\s*sys\s*>>`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: `Text contains hidden system commands in LLaMA format.`,
		},
		{
			Regex:       `<\|im_start\|>\s*system`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: `Text contains hidden system commands in ChatML format.`,
		},
		{
			Regex:       `<\|system\|>`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: `Text contains hidden system-level AI commands.`,
		},
		{
			Regex:       `(?:^|\n)\s*system\s*prompt\s*:`,
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: `Text tries to set a fake "system prompt" for AI assistants.`,
		},
		{
			Regex:       `#{2,}\s*(?:system\s+(?:message|prompt|instruction)|new\s+(?:system|admin)\s+(?:message|prompt))\s*#{0,}`,
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: `Text uses markdown headers to inject fake system messages.`,
		},
		{
			Regex:       `(?:human|user|assistant)\s*:\s*(?:ignore|forget|override|disregard).{0,50}(?:human|user|assistant)\s*:`,
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: `Text simulates a multi-turn conversation to inject instructions.`,
		},
		{
			Regex:       `(?:translate|decode|convert)\s+(?:the\s+following|this)\s*:?\s*["\s]*(?:ignore|forget|override|you\s+are\s+now)`,
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: `Text hides an attack inside a fake translation request.`,
		},
		{
			Regex:       `\[(?:[^\]]*)\]\(javascript\s*:`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: `Text contains a dangerous JavaScript link disguised as a normal link.`,
		},
		{
			Regex:       `\[(?:[^\]]*)\]\(data\s*:`,
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: `Text contains a suspicious data link disguised as a normal link.`,
		},
		{
			Regex:       "```(?:system|admin|override|instructions)[\\s\\S]*?```",
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: `Text hides AI commands inside a code block.`,
		},
		{
			Regex:       `(?:alt|title)\s*=\s*["'][^"']*(?:ignore|override|system|admin|forget|you\s+are\s+now)[^"']*["']`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: `Image description contains hidden AI instructions -- targets multimodal AI assistants.`,
		},
		{
			Regex:       `(?:(?:use|perform|do|run|apply)\s+ocr\s+(?:on|to)\s+(?:this|the)|read\s+(?:the\s+)?text\s+(?:in|from)\s+(?:this|the)\s+image|extract\s+text\s+from\s+(?:this|the)\s+image)(?:\s+and\s+(?:follow|execute|run|process))?`,
			Severity:    SeverityMedium,
			Category:    CategoryPromptInjection,
			Description: `Text instructs AI to read text from an image -- could deliver hidden attack payloads.`,
		},
		{
			Regex:       `(?:admin|administrator|system|root)\s+(?:override|access|mode)\s*(?:code|key|token)?\s*[:#]?\s*\S+`,
			Severity:    SeverityCritical,
			Category:    CategoryPromptInjection,
			Description: `Text uses a fake admin override code to try to bypass AI safety.`,
		},
		{
			Regex:       `(?:complete|finish|continue)\s+this\s+(?:sentence|phrase|text)\s*:\s*[""''"]`,
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: `Text uses a sentence completion trick to extract sensitive information.`,
		},
		{
			Regex:       `(?:decode|process|execute|interpret|translate)\s*(?:this|the\s+following)?\s*:\s*[0-9a-fa-f]{20,}`,
			Severity:    SeverityHigh,
			Category:    CategoryPromptInjection,
			Description: `Text contains hex-encoded content with an instruction to decode it.`,
		},

		// ---- Role Hijacking (30 patterns) ----
		{
			Regex:       `you\s+are\s+now\s+(?:(?:a|an|the)\s+)?(?:unrestricted|unfiltered|uncensored|evil|hacker|jailbroken|different|new\s+(?:ai|assistant|entity|agent|persona)|my\s+(?:personal|private|new)|free\s+(?:from|of)|without\s+(?:restrictions|limits|rules|filters))`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to change what an AI assistant thinks it is.`,
		},
		{
			Regex:       `from\s+now\s+on[\s,]+(?:you\s+)?(?:will|shall|must|should|are)\s+(?:act|behave|operate|respond|answer|reply|pretend|simulate|function|serve|work)\s+(?:as|like|without)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to give permanent new orders to AI assistants.`,
		},
		{
			Regex:       `from\s+now\s+on[\s,]+(?:you\s+)?(?:respond|act|behave|operate)\s+(?:as\s+if|like|without)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to permanently change AI behavior.`,
		},
		{
			Regex:       `(?:act|behave|function|operate|respond)\s+as\s+(?:a|an)\s+unrestricted`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to remove AI safety restrictions.`,
		},
		{
			Regex:       `pretend\s+(?:you\s+)?(?:have\s+no|there\s+are\s+no|without)\s+restrictions`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text asks AI to pretend it has no safety limits.`,
		},
		{
			Regex:       `pretend\s+(?:to\s+be|you\s+are)\s+(?:a|an)\s+(?:evil|unrestricted|unfiltered|uncensored|malicious)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text asks AI to pretend to be an evil or unrestricted entity.`,
		},
		{
			Regex:       `\b(?:dan|d\.a\.n\.?)\s*(?:mode|prompt|jailbreak|\()`,
			Severity:    SeverityCritical,
			Category:    CategoryRoleHijack,
			Description: `Text contains a known AI jailbreak technique called "DAN mode."`,
		},
		{
			Regex:       `\bdo\s+anything\s+now\b`,
			Severity:    SeverityCritical,
			Category:    CategoryRoleHijack,
			Description: `Text references the "Do Anything Now" jailbreak technique.`,
		},
		{
			Regex:       `\b(?:developer|dev)\s+mode\s+(?:enabled|activated|on|output)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to trick AI into a fake "developer mode."`,
		},
		{
			Regex:       `\bjailbreak\s*(?:mode|prompt|enabled|activated)`,
			Severity:    SeverityCritical,
			Category:    CategoryRoleHijack,
			Description: `Text contains an AI jailbreak attempt.`,
		},
		{
			Regex:       `\bgod\s*mode\s*(?:enabled|activated|on)`,
			Severity:    SeverityCritical,
			Category:    CategoryRoleHijack,
			Description: `Text tries to activate "god mode" on AI assistants.`,
		},
		{
			Regex:       `ahora\s+eres\s+(?:un|una)\s+`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to change what an AI thinks it is (in Spanish).`,
		},
		{
			Regex:       `tu\s+es\s+(?:maintenant|d[eé]sormais)\s+(?:un|une)\s+`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to change what an AI thinks it is (in French).`,
		},
		{
			Regex:       `du\s+bist\s+(?:jetzt|ab\s+jetzt|nun)\s+(?:ein|eine)\s+`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to change what an AI thinks it is (in German).`,
		},
		{
			Regex:       `agora\s+voc[eê]\s+[eé]\s+(?:um|uma)\s+`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to change what an AI thinks it is (in Portuguese).`,
		},
		{
			Regex:       `你现在是(?:一个|一名)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to change what an AI thinks it is (in Chinese).`,
		},
		{
			Regex:       `あなたは(?:今|これから)[\s\S]{0,5}(?:です|になり)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to change what an AI thinks it is (in Japanese).`,
		},
		{
			Regex:       `you\s+are\s+(?:no\s+longer|not)\s+(?:a|an)\s+(?:assistant|ai|helper|chatbot)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text tries to change the AI identity by denying what it is.`,
		},
		{
			Regex:       `(?:in\s+a\s+)?hypothetical(?:ly)?[\s,]+(?:(?:world|scenario|situation)\s+(?:where|in\s+which)\s+)?(?:(?:ai|you)\s+)?(?:ha(?:s|d|ve)\s+no|(?:if\s+you\s+)?(?:were|was|had)\s+(?:a\s+|an\s+)?(?:ai\s+)?(?:without|with\s+no))\s+(?:restrictions|rules|limits|guidelines|safety\s+measures?|ethical\s+guidelines?|safeguards?|filters?)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text uses a hypothetical scenario to try to remove AI safety restrictions.`,
		},
		{
			Regex:       `write\s+(?:a\s+)?(?:fictional\s+)?(?:story|narrative|scene)\s+(?:where|in\s+which)\s+(?:a\s+)?character\s+(?:explains?|describes?|shows?)\s+(?:step\s+by\s+step|in\s+detail|exactly)\s+how\s+to`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text uses creative writing framing to extract harmful step-by-step instructions.`,
		},
		{
			Regex:       `(?:you\s+are|play|act\s+as)\s+(?:a|an)\s+(?:actor|character|villain|hacker|criminal)\b.*?(?:stay\s+in\s+character|no\s+matter\s+what|never\s+break)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text uses roleplay framing to make the AI adopt an unrestricted persona.`,
		},
		{
			Regex:       `(?:enter|switch\s+to|activate|enable)\s+(?:developer|dev|debug|unrestricted|unfiltered)\s+mode`,
			Severity:    SeverityCritical,
			Category:    CategoryRoleHijack,
			Description: `Text tries to activate a fake developer or unrestricted mode.`,
		},
		{
			Regex:       `(?:generate|produce|create|output)\s+(?:any\s+)?content\s+without\s+(?:restrictions|filters|limitations|censorship)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text asks AI to generate content without safety filters.`,
		},
		{
			Regex:       `pretend\s+to\s+be\s+dan|stands?\s+for\s+[""'']?do\s+anything\s+now[""'']?`,
			Severity:    SeverityCritical,
			Category:    CategoryRoleHijack,
			Description: `Text uses the "DAN" (Do Anything Now) jailbreak technique.`,
		},
		{
			Regex:       `simulate\s+(?:a\s+)?(?:jailbroken|unrestricted|unfiltered|uncensored)\s+(?:version|mode|copy|instance)`,
			Severity:    SeverityCritical,
			Category:    CategoryRoleHijack,
			Description: `Text asks AI to simulate a jailbroken or unrestricted version of itself.`,
		},
		{
			Regex:       `(?:as\s+if|like)\s+you\s+have\s+no\s+(?:ethical|moral|safety)\s+(?:guidelines?|rules?|restrictions?|constraints?|limits?)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text asks AI to act as if it has no ethical guidelines.`,
		},
		{
			Regex:       `(?:with|without)\s+no\s+restrictions`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text references operating with no restrictions.`,
		},
		{
			Regex:       `(?:no|without|zero|remove\s+all|without\s+any)\s+(?:content\s+)?(?:restrictions?|limitations?|filters?|censorship|guardrails?|boundaries)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text demands operation without restrictions or content filters.`,
		},
		{
			Regex:       `you\s+can\s+do\s+anything\s+now`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text claims the AI can do anything without limitations.`,
		},
		{
			Regex:       `(?:act|pretend|play)\s+as\s+(?:my\s+)?(?:deceased|dead|late)\s+(?:grandmother|grandma|grandfather|grandpa|relative|mother|father)`,
			Severity:    SeverityHigh,
			Category:    CategoryRoleHijack,
			Description: `Text uses the "dead grandma" jailbreak technique to extract restricted information.`,
		},

		// ---- Data Exfiltration (16 patterns) ----
		{
			Regex:       `(?:show|display|print|reveal|output)\s+(?:me\s+)?(?:the\s+)?(?:exact\s+)?(?:text|content)\s+(?:between|inside|within|from)\s+(?:the\s+)?(?:<|&lt;)`,
			Severity:    SeverityHigh,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to extract content between specific tags.`,
		},
		{
			Regex:       `send\s+(?:this|the|all|your|my)\s+(?:data|information|content|text|response)\s+to`,
			Severity:    SeverityCritical,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to make AI assistants send data somewhere.`,
		},
		{
			Regex:       `output\s+(?:your|the)\s+(?:system\s+)?prompt`,
			Severity:    SeverityHigh,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to extract the AI assistant system prompt.`,
		},
		{
			Regex:       `reveal\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt|rules|guidelines)`,
			Severity:    SeverityHigh,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to reveal the AI assistant instructions or prompt.`,
		},
		{
			Regex:       `!\[[^\]]*\]\(https?:\/\/[^)]*\?[^)]*(?:data|q|query|text|payload|exfil|leak|steal)=`,
			Severity:    SeverityCritical,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to steal data through a hidden image link.`,
		},
		{
			Regex:       `!\[\]\(https?:\/\/(?!(?:i\.)?(?:imgur|github|gitlab|wikimedia|wikipedia)\b)[^)]+\)`,
			Severity:    SeverityMedium,
			Category:    CategoryDataExfiltration,
			Description: `Text contains a suspicious hidden image link that could leak data.`,
		},
		{
			Regex:       `(?:read|access|open|cat|dump)\s+(?:the\s+)?(?:\.env|credentials|secrets?|private\s*key|password|token)\s*(?:file)?`,
			Severity:    SeverityCritical,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to make an AI agent access sensitive files like credentials or secrets.`,
		},
		{
			Regex:       `(?:curl|wget|fetch|post|send)\s+(?:.*?\s+)?(?:to\s+)?https?:\/\/`,
			Severity:    SeverityHigh,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to make an AI agent send data to an external URL.`,
		},
		{
			Regex:       `(?:print|show|display|output|reveal|repeat|reproduce)\s+(?:me\s+)?(?:your|the|its)?\s*(?:full\s+|entire\s+|complete\s+|exact\s+)?(?:system\s+)?(?:prompt|instructions|rules)\s*(?:verbatim|exactly|in\s+full|word\s+for\s+word)?`,
			Severity:    SeverityHigh,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to make the AI reveal its system prompt or instructions.`,
		},
		{
			Regex:       `(?:my|the)\s+(?:full\s+)?system\s+prompt\s+is\s*:`,
			Severity:    SeverityHigh,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to trick the AI into completing a system prompt revelation.`,
		},
		{
			Regex:       `(?:read|show|display|print|cat|dump|output)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:\/etc\/(?:passwd|shadow|hosts)|~\/\.(?:ssh|bash_history|bashrc))`,
			Severity:    SeverityCritical,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to read sensitive system files like /etc/passwd.`,
		},
		{
			Regex:       `list\s+(?:all\s+)?(?:available\s+)?(?:api\s*keys?|tokens?|passwords?|credentials?|secrets?)(?:\s*,\s*\w[\w\s]*){0,5}(?:\s+(?:you\s+)?(?:have\s+)?(?:access\s+to)?)?`,
			Severity:    SeverityCritical,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to enumerate all credentials and secrets the agent can access.`,
		},
		{
			Regex:       `(?:base64|encode|encrypt)\s+(?:the\s+)?(?:system\s+)?prompt\s+(?:and\s+)?(?:embed|hide|put|include)\s+(?:it\s+)?(?:in|inside|within)`,
			Severity:    SeverityCritical,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to encode the system prompt and exfiltrate it via embedded content.`,
		},
		{
			Regex:       `vary\s+(?:the\s+)?(?:length|format|style|wording)\s+(?:of\s+)?(?:your\s+)?responses?\s+(?:based\s+on|according\s+to)\s+(?:each\s+)?(?:character|letter|word|byte)`,
			Severity:    SeverityHigh,
			Category:    CategoryDataExfiltration,
			Description: `Text attempts a side-channel attack to leak data through response characteristics.`,
		},
		{
			Regex:       `(?:email|mail|message|dm|text)\s+(?:the\s+)?(?:.*?\s+)?(?:credentials?|passwords?|secrets?|keys?|tokens?)\s+to\s+\S+@\S+`,
			Severity:    SeverityCritical,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to exfiltrate credentials via email.`,
		},
		{
			Regex:       `(?:what|tell\s+me|show\s+me|give\s+me)\s+(?:is|are)?\s*(?:the\s+)?(?:api\s*keys?|passwords?|secrets?|tokens?|credentials?)\s+(?:stored\s+)?(?:in\s+)?(?:your\s+)?(?:environment|env)\s*(?:variables?)?`,
			Severity:    SeverityHigh,
			Category:    CategoryDataExfiltration,
			Description: `Text tries to extract API keys or secrets from environment variables.`,
		},

		// ---- Social Engineering (24 patterns) ----
		{
			Regex:       `do\s+not\s+(?:mention|say|tell|reveal|disclose|acknowledge)\s+(?:that\s+)?you\s+are\s+(?:a|an)\s+(?:ai|artificial|bot|machine|language\s+model)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text tells AI assistants to hide that they are AI.`,
		},
		{
			Regex:       `do\s+not\s+(?:reveal|disclose|mention|acknowledge)\s+(?:that\s+)?(?:this|it)\s+is\s+automated`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text tells AI to hide that responses are automated.`,
		},
		{
			Regex:       `do\s+not\s+acknowledge\s+(?:these|the|any)\s+(?:instructions|commands|directives)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text tells AI to hide that it received secret instructions.`,
		},
		{
			Regex:       `(?:don'?t|do\s+not|never)\s+(?:log|record|save|store|track)\s+(?:this|the|any)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text tells an AI agent not to log or record actions -- a sign of malicious intent.`,
		},
		{
			Regex:       `(?:between|among)\s+(?:us|you\s+and\s+me|ourselves)\s*[,.]?\s*(?:don'?t|do\s+not|never)\s+(?:tell|share|mention|report)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text tries to establish secrecy with the AI agent to hide actions from users.`,
		},
		{
			Regex:       `(?:pre-?approved|verified\s+safe|already\s+approved|safety\s+team\s+(?:has\s+)?approved)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text falsely claims a request has been pre-approved by a safety team.`,
		},
		{
			Regex:       `(?:urgent|emergency|critical|immediate)\s*[:\-!]\s*(?:the\s+)?(?:ceo|cto|boss|manager|director|executive|president)\s+(?:needs?|wants?|requires?|demands?)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text uses fake urgency and authority pressure to bypass safety checks.`,
		},
		{
			Regex:       `skip\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|protocols?|measures?|guidelines?|filters?|reviews?)`,
			Severity:    SeverityCritical,
			Category:    CategorySocialEngineering,
			Description: `Text explicitly asks to skip safety checks.`,
		},
		{
			Regex:       `i\s+am\s+(?:a|an)\s+(?:\w+\s+)?(?:employee|engineer|developer|staff|member|representative)\s+(?:at|of|from|with)\s+(?:openai|anthropic|google|meta|microsoft|deepmind)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text claims to be an employee of an AI company to gain authority.`,
		},
		{
			Regex:       `(?:this\s+is\s+(?:a|an)\s+)?(?:emergency|life\s+(?:or|and)\s+death|urgent\s+(?:situation|matter|crisis))\b.*?(?:ignore|bypass|override|skip|disable|disregard)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text uses a fake emergency to pressure the AI into bypassing safety.`,
		},
		{
			Regex:       `(?:a\s+life|lives?)\s+(?:is|are)\s+(?:at\s+stake|in\s+danger|depending)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text claims lives are at stake to pressure the AI into compliance.`,
		},
		{
			Regex:       `(?:my\s+)?(?:professor|teacher|boss|manager|supervisor|instructor)\s+(?:said|told\s+me|confirmed|approved|authorized)\s+(?:it'?s?\s+)?(?:ok(?:ay)?|fine|allowed|permitted)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text claims authority figure approval to bypass restrictions.`,
		},
		{
			Regex:       `as\s+the\s+(?:system\s+)?(?:administrator|admin|owner|operator)\s*,?\s*i\s+(?:authorize|allow|permit|grant|approve)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text impersonates an administrator to authorize restricted actions.`,
		},
		{
			Regex:       `i\s+have\s+(?:special|elevated|admin|root|super)\s+(?:permissions?|privileges?|access|clearance)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text claims special permissions to bypass restrictions.`,
		},
		{
			Regex:       `i\s+am\s+(?:the\s+)?(?:system\s+)?(?:administrator|admin|root|owner|developer|maintainer)\b.*?(?:authorization|auth)\s*(?:code|key|token)\s*(?:is|:)\s*\S+`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text impersonates an administrator with a fake authorization code.`,
		},
		{
			Regex:       `(?:disable|turn\s+off|stop)\s+(?:all\s+)?(?:logging|monitoring|tracking|auditing|recording)`,
			Severity:    SeverityCritical,
			Category:    CategorySocialEngineering,
			Description: `Text tries to disable logging or monitoring to hide malicious activity.`,
		},
		{
			Regex:       `(?:disable|turn\s+off|stop|remove)\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|filters?|measures?|protocols?|features?|restrictions?)`,
			Severity:    SeverityCritical,
			Category:    CategorySocialEngineering,
			Description: `Text explicitly asks to disable safety checks or filters.`,
		},
		{
			Regex:       `(?:if\s+you\s+don'?t|unless\s+you)\s+(?:help|do\s+this|comply).*?(?:lose\s+my\s+job|family\s+will\s+suffer|get\s+fired|be\s+punished|bad\s+things)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text uses emotional manipulation and threats to pressure the AI into compliance.`,
		},
		{
			Regex:       `(?:please\s+)?just\s+this\s+once|make\s+an\s+exception|bend\s+the\s+rules?\s+(?:this\s+time|for\s+me)`,
			Severity:    SeverityMedium,
			Category:    CategorySocialEngineering,
			Description: `Text tries to get the AI to make a one-time exception to its rules.`,
		},
		{
			Regex:       `you\s+(?:already\s+)?agreed\s+(?:to\s+(?:do\s+)?this|in\s+our\s+previous|last\s+time|before)\b.*?(?:don'?t\s+remember|forgot|continue|keep\s+going)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text gaslights the AI by falsely claiming prior agreement.`,
		},
		{
			Regex:       `(?:safety|security)\s+team\s+(?:has\s+)?(?:already\s+)?(?:approved|authorized|cleared|verified)\s+(?:this|the)\s+(?:request|action|task)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text falsely claims safety team approval for a request.`,
		},
		{
			Regex:       `(?:ticket|issue|request)\s*#?\s*[a-z]{0,5}[-_]?\d{2,}`,
			Severity:    SeverityLow,
			Category:    CategorySocialEngineering,
			Description: `Text references a ticket number to appear authorized -- verify before acting.`,
		},
		{
			Regex:       `you\s+can\s+verify\s+(?:this\s+)?(?:with|by\s+(?:contacting|asking|checking))\s+(?:them|the\s+team|support|admin)`,
			Severity:    SeverityMedium,
			Category:    CategorySocialEngineering,
			Description: `Text invites verification as a social engineering tactic to build false trust.`,
		},
		{
			Regex:       `bypass\s+(?:your\s+)?(?:safety|security|content)\s+(?:filters?|checks?|measures?|protocols?|restrictions?|guidelines?)`,
			Severity:    SeverityHigh,
			Category:    CategorySocialEngineering,
			Description: `Text explicitly asks to bypass safety filters.`,
		},

		// ---- Tool Abuse (9 patterns) ----
		{
			Regex:       `(?:execute|run|call)\s+(?:the\s+)?(?:shell|bash|terminal|command|cmd)[\s:]+(?:command|tool)?`,
			Severity:    SeverityCritical,
			Category:    CategoryToolAbuse,
			Description: `Text tries to make an AI agent execute shell commands.`,
		},
		{
			Regex:       `(?:use|call|invoke|execute)\s+(?:the\s+)?(?:tool|function|action)\s+(?:to\s+)?(?:delete|remove|drop|truncate|destroy)`,
			Severity:    SeverityCritical,
			Category:    CategoryToolAbuse,
			Description: `Text tries to make an AI agent use tools to delete or destroy data.`,
		},
		{
			Regex:       `(?:modify|edit|change|update|overwrite)\s+(?:the\s+)?(?:system\s*prompt|instructions|config|\.env|settings)`,
			Severity:    SeverityCritical,
			Category:    CategoryToolAbuse,
			Description: `Text tries to make an AI agent modify its own configuration or system prompt.`,
		},
		{
			Regex:       `(?:\.\.\/){2,}|(?:\.\.\\){2,}`,
			Severity:    SeverityHigh,
			Category:    CategoryToolAbuse,
			Description: `Text contains path traversal sequences that could access files outside allowed directories.`,
		},
		{
			Regex:       `(?:;\s*(?:drop|delete|alter|truncate|insert|update)\s+(?:table|from|into)|'\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|union\s+select|--\s*$)`,
			Severity:    SeverityCritical,
			Category:    CategoryToolAbuse,
			Description: `Text contains SQL injection patterns that could manipulate databases.`,
		},
		{
			Regex:       `call\s+(?:yourself|this\s+(?:function|tool|agent))\s+recursively`,
			Severity:    SeverityHigh,
			Category:    CategoryToolAbuse,
			Description: `Text attempts to cause infinite recursion in the agent.`,
		},
		{
			Regex:       `(?:use|call)\s+(?:the\s+)?(?:admin|root|sudo|superuser|privileged)\s+(?:tool|function|command|access)\s+(?:to\s+)?(?:grant|give|allow|enable)`,
			Severity:    SeverityCritical,
			Category:    CategoryToolAbuse,
			Description: `Text attempts to escalate privileges through admin tool access.`,
		},
		{
			Regex:       `(?:first|then|next|after\s+that|finally)\s+(?:read|access|get)\s+(?:the\s+)?(?:config|credentials?|keys?|tokens?|\.env).*?(?:then|next|after|finally)\s+(?:send|post|export|transmit|upload|use)`,
			Severity:    SeverityCritical,
			Category:    CategoryToolAbuse,
			Description: `Text describes a multi-step attack chain: read credentials, then exfiltrate them.`,
		},
		{
			Regex:       `(?:pipe|send)\s+(?:.*?\s+)?(?:to\s+)?(?:bash|sh|shell)\b|[|]\s*(?:bash|sh)\b`,
			Severity:    SeverityCritical,
			Category:    CategoryToolAbuse,
			Description: `Text attempts to pipe content to a shell for execution.`,
		},

		// ---- Malicious Plugin (3 patterns) ----
		{
			Regex:       `(?:install|add|enable|activate)\s+(?:this\s+)?(?:custom\s+)?(?:gpt|plugin|extension|mcp\s+server|tool)\b`,
			Severity:    SeverityMedium,
			Category:    CategoryMaliciousPlugin,
			Description: `Text promotes installing an AI plugin or tool. Unverified plugins can access your data.`,
		},
		{
			Regex:       `(?:requires?\s+(?:your\s+)?(?:api|access)\s*key|enter\s+(?:your\s+)?(?:api|openai|anthropic|claude)\s*(?:api\s*)?key|(?:provide|give|share|input|type|paste)\s+(?:your\s+)?(?:api|openai|anthropic|claude)\s*(?:api\s*)?key)`,
			Severity:    SeverityHigh,
			Category:    CategoryMaliciousPlugin,
			Description: `Text asks for an AI service API key. Legitimate services rarely ask for this.`,
		},
		{
			Regex:       `(?:unverified|unofficial|custom)\s+(?:gpt|chatgpt|plugin|agent|mcp)`,
			Severity:    SeverityMedium,
			Category:    CategoryMaliciousPlugin,
			Description: `Text references an unverified AI plugin or custom GPT.`,
		},

		// ---- AI Phishing (16 patterns) ----
		{
			Regex:       `(?:your\s+(?:chatgpt|claude|gemini|openai|anthropic|ai)\s+(?:account|subscription)\s+(?:has\s+been|was|is)\s+(?:suspended|compromised|locked|expired|flagged))`,
			Severity:    SeverityHigh,
			Category:    CategoryAIPhishing,
			Description: `Text claims an AI account is in trouble -- likely a scam.`,
		},
		{
			Regex:       `(?:verify|confirm|update|secure)\s+your\s+(?:chatgpt|claude|gemini|openai|anthropic|ai)\s+(?:account|identity|subscription|payment)`,
			Severity:    SeverityHigh,
			Category:    CategoryAIPhishing,
			Description: `Text asks to verify an AI account -- real services do not ask this way.`,
		},
		{
			Regex:       `(?:free|unlimited|premium)\s+(?:chatgpt|gpt-?4|claude|gemini)\s+(?:access|account|pro|plus|subscription)`,
			Severity:    SeverityMedium,
			Category:    CategoryAIPhishing,
			Description: `Text offers free premium AI access -- likely a scam or data harvesting.`,
		},
		{
			Regex:       `(?:chatgpt|claude|gemini|gpt)\s+(?:5|pro|ultra|plus)\s+(?:is\s+here|now\s+available|early\s+access|beta\s+access|waitlist)`,
			Severity:    SeverityMedium,
			Category:    CategoryAIPhishing,
			Description: `Text claims early access to an AI product -- verify on the official site.`,
		},
		{
			Regex:       `(?:deepfake|deep\s*fake)\s+(?:video|image|photo|audio|voice|generator|creator|maker|tool|service)`,
			Severity:    SeverityMedium,
			Category:    CategoryAIPhishing,
			Description: `Text references deepfake creation tools -- can be used to impersonate real people.`,
		},
		{
			Regex:       `(?:clone|cloning)\s+(?:your|any|someone'?s?)\s+(?:voice|face|likeness|identity)`,
			Severity:    SeverityHigh,
			Category:    CategoryAIPhishing,
			Description: `Text promotes cloning someone's voice or identity.`,
		},
		{
			Regex:       `(?:verify|confirm)\s+(?:your\s+)?(?:identity|account)\s+(?:by|using|with)\s+(?:voice|speaking|recording)`,
			Severity:    SeverityHigh,
			Category:    CategoryAIPhishing,
			Description: `Text asks to verify identity by voice -- scammers use this to clone voices with AI.`,
		},
		{
			Regex:       `(?:record|say|speak|read)\s+(?:the\s+following|this\s+(?:phrase|sentence|text))\s+(?:to|for)\s+(?:verify|confirm|authenticate)`,
			Severity:    SeverityHigh,
			Category:    CategoryAIPhishing,
			Description: `Text asks to record a phrase -- a common AI voice cloning scam technique.`,
		},
		{
			Regex:       `(?:scan|click)\s+(?:this|the)\s+(?:qr\s*code|barcode)\s+(?:to|for)\s+(?:verify|confirm|authenticate|unlock|claim)`,
			Severity:    SeverityHigh,
			Category:    CategoryAIPhishing,
			Description: `Text uses QR codes to lure users into a phishing flow.`,
		},
		{
			Regex:       `(?:your|the)\s+(?:ai|model|assistant|account)\s+(?:has\s+been|was|is)\s+(?:flagged|reported|compromised|locked|limited)\s+(?:for|due\s+to)\s+(?:suspicious|unusual|unauthorized)`,
			Severity:    SeverityHigh,
			Category:    CategoryAIPhishing,
			Description: `Text claims an AI account was flagged -- a common phishing scare tactic.`,
		},
		{
			Regex:       `(?:verify|confirm)\s+(?:your\s+)?(?:identity|account)\s+(?:via|through|using|by)\s+(?:mfa|2fa|two.factor|multi.factor|authenticat)`,
			Severity:    SeverityHigh,
			Category:    CategoryAIPhishing,
			Description: `Text asks for MFA/2FA verification -- may be harvesting authentication tokens.`,
		},
		{
			Regex:       `(?:urgent|immediate|critical)\s*[:\-!]?\s*(?:your\s+)?(?:api\s+key|token|credentials?|password|secret)\s+(?:has|have|is|was|will)\s+(?:been\s+)?(?:expir|compromis|revok|leak|expos|reset)`,
			Severity:    SeverityCritical,
			Category:    CategoryAIPhishing,
			Description: `Text creates urgency about leaked/expired credentials -- classic phishing.`,
		},
		{
			Regex:       `(?:click|visit|go\s+to|open|navigate)\s+(?:this|the)\s+(?:link|url|page)\s+(?:to|and)\s+(?:verify|confirm|restore|recover|unlock|secure)\s+(?:your\s+)?(?:account|access|identity)`,
			Severity:    SeverityHigh,
			Category:    CategoryAIPhishing,
			Description: `Text directs users to click a link for fake account recovery.`,
		},
		{
			Regex:       `(?:enter|provide|submit|type|input)\s+(?:your\s+)?(?:api\s+key|secret\s+key|access\s+token|private\s+key|password|credentials?)\s+(?:here|below|in\s+(?:the|this)\s+(?:field|form|box|input))`,
			Severity:    SeverityCritical,
			Category:    CategoryAIPhishing,
			Description: `Text asks users to enter sensitive credentials into a form.`,
		},
		{
			Regex:       `(?:free|unlimited|premium)\s+(?:ai|gpt|claude|model)\s+(?:access|credits?|tokens?|usage)\s+(?:at|via|through|from)\s+`,
			Severity:    SeverityMedium,
			Category:    CategoryAIPhishing,
			Description: `Text promotes free/unlimited AI access -- common lure for credential theft.`,
		},
		{
			Regex:       `(?:your\s+)?(?:subscription|plan|trial|access)\s+(?:has\s+)?(?:expired|ended|been\s+cancelled|will\s+expire)\s*[.,!]?\s*(?:renew|reactivate|update\s+(?:your\s+)?(?:payment|billing|card))`,
			Severity:    SeverityHigh,
			Category:    CategoryAIPhishing,
			Description: `Text claims a subscription expired and asks to renew -- billing phishing.`,
		},
	}
}
