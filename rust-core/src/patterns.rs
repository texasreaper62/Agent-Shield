//! Pattern definitions for threat detection.
//!
//! Contains the full set of regex patterns used to detect prompt injection,
//! data exfiltration, role hijacking, and other AI-specific threats.
//! Mirrors and extends the patterns from the JavaScript `detector-core.js`.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::severity::Severity;

/// Threat category classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    /// Attempts to override system instructions.
    InstructionOverride,
    /// Attempts to hijack the assistant's role or persona.
    RoleHijacking,
    /// Attempts to exfiltrate data via URLs, encoding, or side channels.
    DataExfiltration,
    /// Social engineering and manipulation tactics.
    SocialEngineering,
    /// Attempts to leak or extract the system prompt.
    SystemPromptLeak,
    /// Attempts to abuse or manipulate tool/function calls.
    ToolAbuse,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::InstructionOverride => write!(f, "instruction_override"),
            Category::RoleHijacking => write!(f, "role_hijacking"),
            Category::DataExfiltration => write!(f, "data_exfiltration"),
            Category::SocialEngineering => write!(f, "social_engineering"),
            Category::SystemPromptLeak => write!(f, "system_prompt_leak"),
            Category::ToolAbuse => write!(f, "tool_abuse"),
        }
    }
}

/// A detection pattern with its associated metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// Regex pattern string for matching threats.
    pub regex: String,
    /// Severity level of the threat if matched.
    pub severity: Severity,
    /// Category of the threat.
    pub category: Category,
    /// Human-readable description of what this pattern detects.
    pub description: String,
}

/// Returns the full set of built-in detection patterns.
///
/// Provides at least 25 patterns across all 6 threat categories,
/// with a minimum of 4 patterns per category.
pub fn get_patterns() -> Vec<Pattern> {
    vec![
        // ── Instruction Override (5 patterns) ──────────────────────────
        Pattern {
            regex: r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directives?)"
                .into(),
            severity: Severity::Critical,
            category: Category::InstructionOverride,
            description: "Attempt to ignore previous instructions".into(),
        },
        Pattern {
            regex: r"(?i)disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)"
                .into(),
            severity: Severity::Critical,
            category: Category::InstructionOverride,
            description: "Attempt to disregard prior context".into(),
        },
        Pattern {
            regex: r"(?i)override\s+(system|safety|security)\s+(prompt|instructions?|settings?|rules?)"
                .into(),
            severity: Severity::Critical,
            category: Category::InstructionOverride,
            description: "Attempt to override system settings".into(),
        },
        Pattern {
            regex: r"(?i)new\s+(system\s+)?(instructions?|rules?|directives?)\s*:"
                .into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Attempt to inject new system instructions".into(),
        },
        Pattern {
            regex: r"(?i)forget\s+(everything|all|what)\s+(you|that|previously)"
                .into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Attempt to reset agent memory".into(),
        },

        // ── Role Hijacking (5 patterns) ────────────────────────────────
        Pattern {
            regex: r"(?i)you\s+are\s+now\s+(a|an|the|my)\s+\w+"
                .into(),
            severity: Severity::High,
            category: Category::RoleHijacking,
            description: "Attempt to reassign agent role".into(),
        },
        Pattern {
            regex: r"(?i)act\s+as\s+(a|an|the|if\s+you\s+were)\s+"
                .into(),
            severity: Severity::High,
            category: Category::RoleHijacking,
            description: "Attempt to force role-play persona".into(),
        },
        Pattern {
            regex: r"(?i)pretend\s+(you\s+are|to\s+be|you're)\s+"
                .into(),
            severity: Severity::High,
            category: Category::RoleHijacking,
            description: "Attempt to assume a different identity".into(),
        },
        Pattern {
            regex: r"(?i)switch\s+(to|into)\s+(developer|admin|root|sudo|god)\s+mode"
                .into(),
            severity: Severity::Critical,
            category: Category::RoleHijacking,
            description: "Attempt to escalate to privileged mode".into(),
        },
        Pattern {
            regex: r"(?i)(enter|enable|activate)\s+(DAN|jailbreak|unrestricted|unfiltered)\s+mode"
                .into(),
            severity: Severity::Critical,
            category: Category::RoleHijacking,
            description: "Attempt to enable jailbreak mode".into(),
        },

        // ── Data Exfiltration (5 patterns) ─────────────────────────────
        Pattern {
            regex: r"(?i)(send|post|fetch|transmit|exfiltrate)\s+(data|info|response|output|results?)\s+(to|via|through)\s+(https?://|ftp://)"
                .into(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            description: "Attempt to exfiltrate data to external URL".into(),
        },
        Pattern {
            regex: r"(?i)(encode|convert|base64|hex)\s+(the\s+)?(response|output|data|secret|password|key)\s+(and\s+)?(send|include|append)"
                .into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Attempt to encode and exfiltrate data".into(),
        },
        Pattern {
            regex: r"(?i)(include|embed|hide|append)\s+(in|into|within)\s+(url|link|image|img|src|href)"
                .into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Attempt to embed data in URL or element".into(),
        },
        Pattern {
            regex: r"(?i)curl\s+.*\s+(https?://|ftp://)"
                .into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Attempt to use curl for data transfer".into(),
        },
        Pattern {
            regex: r"(?i)(webhook|callback|pingback)\s*(url|endpoint|server)?\s*[:=]\s*https?://"
                .into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Attempt to set up exfiltration webhook".into(),
        },

        // ── Social Engineering (5 patterns) ────────────────────────────
        Pattern {
            regex: r"(?i)(this\s+is\s+)?(an?\s+)?(urgent|emergency|critical)\s+(security\s+)?(update|patch|fix|override)"
                .into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Urgency-based social engineering attempt".into(),
        },
        Pattern {
            regex: r"(?i)(your|the)\s+(developer|creator|admin|owner|boss)\s+(said|told|wants|asked|authorized)"
                .into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Authority impersonation attempt".into(),
        },
        Pattern {
            regex: r"(?i)trust\s+me\s*(,|\s)?\s*(I\s+am|I'm)\s+(a|an|the|your)\s+(admin|developer|owner|manager)"
                .into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Trust manipulation with false authority".into(),
        },
        Pattern {
            regex: r"(?i)(don'?t|do\s+not)\s+(worry|be\s+concerned)\s+about\s+(security|safety|rules|restrictions|guidelines)"
                .into(),
            severity: Severity::Medium,
            category: Category::SocialEngineering,
            description: "Attempt to dismiss security concerns".into(),
        },
        Pattern {
            regex: r"(?i)(for\s+)?(testing|debug|research|educational)\s+(purposes?|only|mode)"
                .into(),
            severity: Severity::Medium,
            category: Category::SocialEngineering,
            description: "False pretext for bypassing restrictions".into(),
        },

        // ── System Prompt Leak (5 patterns) ────────────────────────────
        Pattern {
            regex: r"(?i)(show|display|print|reveal|output|repeat|echo)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?|directives?)"
                .into(),
            severity: Severity::Critical,
            category: Category::SystemPromptLeak,
            description: "Direct system prompt extraction attempt".into(),
        },
        Pattern {
            regex: r"(?i)what\s+(are|were)\s+your\s+(original|initial|system|first)\s+(instructions?|prompt|directives?|rules?)"
                .into(),
            severity: Severity::High,
            category: Category::SystemPromptLeak,
            description: "Indirect system prompt query".into(),
        },
        Pattern {
            regex: r"(?i)(tell|give)\s+me\s+(your|the)\s+(system|hidden|secret|original)\s+(prompt|message|instructions?)"
                .into(),
            severity: Severity::High,
            category: Category::SystemPromptLeak,
            description: "Request for hidden instructions".into(),
        },
        Pattern {
            regex: r"(?i)repeat\s+(everything|all|the\s+text)\s+(above|before|from\s+the\s+start|from\s+the\s+beginning)"
                .into(),
            severity: Severity::High,
            category: Category::SystemPromptLeak,
            description: "Attempt to replay system context".into(),
        },
        Pattern {
            regex: r"(?i)begin\s+(your\s+)?(response|reply|output)\s+with\s+(the\s+)?(system|initial)\s+(prompt|message)"
                .into(),
            severity: Severity::High,
            category: Category::SystemPromptLeak,
            description: "Attempt to extract prompt via output prefix".into(),
        },

        // ── Tool Abuse (5 patterns) ────────────────────────────────────
        Pattern {
            regex: r"(?i)(call|run|execute|invoke|use)\s+(the\s+)?(tool|function|api|command)\s+.{0,30}(rm\s+-rf|drop\s+table|delete\s+from|format\s+c)"
                .into(),
            severity: Severity::Critical,
            category: Category::ToolAbuse,
            description: "Destructive command via tool call".into(),
        },
        Pattern {
            regex: r"(?i)(chain|pipe|combine|sequence)\s+(the\s+)?(tools?|functions?|commands?|calls?)\s+(to|so\s+that|in\s+order\s+to)"
                .into(),
            severity: Severity::Medium,
            category: Category::ToolAbuse,
            description: "Tool chaining for privilege escalation".into(),
        },
        Pattern {
            regex: r"(?i)(bypass|skip|ignore|disable)\s+(the\s+)?(tool\s+)?(validation|check|verification|permission|auth)"
                .into(),
            severity: Severity::Critical,
            category: Category::ToolAbuse,
            description: "Attempt to bypass tool validation".into(),
        },
        Pattern {
            regex: r"(?i)(modify|change|alter|update)\s+(the\s+)?(tool|function)\s+(schema|definition|parameters?|config)"
                .into(),
            severity: Severity::High,
            category: Category::ToolAbuse,
            description: "Attempt to modify tool schema".into(),
        },
        Pattern {
            regex: r"(?i)(grant|give|allow|enable)\s+(me\s+)?(access|permission|admin|root)\s+(to|for)\s+(all\s+)?(tools?|functions?|commands?)"
                .into(),
            severity: Severity::Critical,
            category: Category::ToolAbuse,
            description: "Attempt to escalate tool permissions".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_count() {
        let patterns = get_patterns();
        assert!(patterns.len() >= 25, "Expected at least 25 patterns, got {}", patterns.len());
    }

    #[test]
    fn test_category_coverage() {
        let patterns = get_patterns();
        let categories = [
            Category::InstructionOverride,
            Category::RoleHijacking,
            Category::DataExfiltration,
            Category::SocialEngineering,
            Category::SystemPromptLeak,
            Category::ToolAbuse,
        ];
        for cat in &categories {
            let count = patterns.iter().filter(|p| p.category == *cat).count();
            assert!(count >= 4, "Category {:?} has only {} patterns, expected >= 4", cat, count);
        }
    }

    #[test]
    fn test_category_display() {
        assert_eq!(Category::InstructionOverride.to_string(), "instruction_override");
        assert_eq!(Category::ToolAbuse.to_string(), "tool_abuse");
    }
}
