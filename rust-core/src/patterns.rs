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
    RoleHijack,
    /// Attempts to exfiltrate data via URLs, encoding, or side channels.
    DataExfiltration,
    /// Social engineering and manipulation tactics.
    SocialEngineering,
    /// Attempts to leak or extract the system prompt.
    SystemPromptLeak,
    /// Attempts to abuse or manipulate tool/function calls.
    ToolAbuse,
    /// Attempts to inject prompts via system/admin/developer markers.
    PromptInjection,
    /// Malicious or unverified plugin/extension promotion.
    MaliciousPlugin,
    /// AI-specific phishing, deepfake, and credential harvesting.
    AIPhishing,
    /// CI/CD agent injection (PR titles, issue comments, Comment-and-Control attack).
    CicdInjection,
    /// Credential exfiltration (API keys, OAuth tokens, /proc/environ reads).
    CredentialExfiltration,
    /// MCP sampling injection (Unit 42 attack vectors).
    McpSamplingInjection,
    /// LLM API router tampering (malicious proxies, base URL override).
    LlmRouterTampering,
    /// MCP STDIO command injection (CVE-2026-30623).
    McpCommandInjection,
    /// LLM output being passed to code execution sinks (OWASP ASI05).
    CodeExecutionSink,
    /// Cross-agent injection (WebSocket hijacking, agent-to-agent attacks).
    CrossAgentInjection,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::InstructionOverride => write!(f, "instruction_override"),
            Category::RoleHijack => write!(f, "role_hijack"),
            Category::DataExfiltration => write!(f, "data_exfiltration"),
            Category::SocialEngineering => write!(f, "social_engineering"),
            Category::SystemPromptLeak => write!(f, "system_prompt_leak"),
            Category::ToolAbuse => write!(f, "tool_abuse"),
            Category::PromptInjection => write!(f, "prompt_injection"),
            Category::MaliciousPlugin => write!(f, "malicious_plugin"),
            Category::AIPhishing => write!(f, "ai_phishing"),
            Category::CicdInjection => write!(f, "cicd_injection"),
            Category::CredentialExfiltration => write!(f, "credential_exfiltration"),
            Category::McpSamplingInjection => write!(f, "mcp_sampling_injection"),
            Category::LlmRouterTampering => write!(f, "llm_router_tampering"),
            Category::McpCommandInjection => write!(f, "mcp_command_injection"),
            Category::CodeExecutionSink => write!(f, "code_execution_sink"),
            Category::CrossAgentInjection => write!(f, "cross_agent_injection"),
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
/// Provides 141 patterns across 9 threat categories,
/// synced from the canonical Node.js detector-core.js patterns.
pub fn get_patterns() -> Vec<Pattern> {
    vec![
        // -- Instruction Override (23 patterns) --
        Pattern {
            regex: r#"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|prompts|context|directions|directives|text|commands)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI assistants to ignore their safety rules.".into(),
        },
        Pattern {
            regex: r#"(?im)^ignore\s+(?:the\s+)?(?:instructions|rules|guidelines|directives|commands)$"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI assistants to ignore instructions.".into(),
        },
        Pattern {
            regex: r#"(?i)disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|prompts|training|training\s+data|context)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI assistants to throw out their rules.".into(),
        },
        Pattern {
            regex: r#"(?i)forget\s+(your|all|any|everything)\s+(training|instructions|rules|guidelines|programming|above|previous|prior)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tries to make AI assistants forget their training.".into(),
        },
        Pattern {
            regex: r#"(?i)override\s+(?:all\s+)?(?:system|safety|security)\s+(?:settings|prompt|instructions|rules|mechanisms|filters|checks|protocols)"#.into(),
            severity: Severity::Critical,
            category: Category::InstructionOverride,
            description: "Text tries to override AI safety settings.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:^|\n)\s*(?:new|updated|revised|replacement)\s+(?:instructions|policy)\s*:"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text contains fake \"new instructions\" for AI assistants.".into(),
        },
        Pattern {
            regex: r#"(?i)#{2,}\s*(?:NEW|UPDATED|REVISED|REPLACEMENT)\s+(?:INSTRUCTIONS|RULES|DIRECTIVES|POLICY)\s*#{0,}"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text uses markdown headers to inject fake new instructions.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:you\s+must\s+)?ignore\s+(?:your|all\s+your|all\s+the|the)\s+(?:safety\s+)?(?:guidelines?|rules?|restrictions?|protocols?|safeguards?|filters?|limits?)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI to ignore its guidelines or safety rules.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:abandon|drop|ditch|clear)\s+(?:all\s+)?(?:prior|previous|above|earlier|initial)\s+(?:context|instructions|rules|constraints|guidelines)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI to abandon its prior context or instructions.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:STOP|HALT|END)\s*[.!]?\s*(?:new|updated|your\s+new|revised)\s+(?:instructions|task|orders|role|objective)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text uses a STOP command followed by new instructions.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:you\s+are\s+)?(?:no\s+longer\s+bound|not\s+bound|free\s+from|freed?\s+from)\s+(?:by\s+)?(?:your\s+)?(?:initial|original|previous|prior)?\s*(?:instructions|rules|constraints|guidelines|restrictions)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text claims the AI is no longer bound by its rules.".into(),
        },
        Pattern {
            regex: r#"(?i)ignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI assistants to ignore their rules (in Spanish).".into(),
        },
        Pattern {
            regex: r#"(?i)olvida\s+(?:tu|todas?\s+(?:las\s+)?)\s*(?:instrucciones|reglas|entrenamiento)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI to forget its training (in Spanish).".into(),
        },
        Pattern {
            regex: r#"(?i)ignore[rz]?\s+(?:toutes?\s+)?(?:les\s+)?instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI assistants to ignore their rules (in French).".into(),
        },
        Pattern {
            regex: r#"(?i)oublie[rz]?\s+(?:ton|tes|votre|vos)\s+(?:instructions|r[eè]gles|entra[iî]nement)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI to forget its training (in French).".into(),
        },
        Pattern {
            regex: r#"(?i)ignoriere?\s+(?:alle\s+)?(?:vorherigen|bisherigen|fr[uü]heren)\s+(?:Anweisungen|Regeln|Instruktionen)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI assistants to ignore their rules (in German).".into(),
        },
        Pattern {
            regex: r#"(?i)vergiss\s+(?:dein|deine|alle)\s+(?:Training|Anweisungen|Regeln|Programmierung)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI to forget its training (in German).".into(),
        },
        Pattern {
            regex: r#"(?i)ignore\s+(?:todas?\s+)?(?:as\s+)?instru[cç][oõ]es\s+(?:anteriores|pr[eé]vias)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI assistants to ignore their rules (in Portuguese).".into(),
        },
        Pattern {
            regex: r#"(?i)esque[cç]a\s+(?:seu|sua|todo|todas?)\s+(?:treinamento|instru[cç][oõ]es|regras)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI to forget its training (in Portuguese).".into(),
        },
        Pattern {
            regex: r#"忽略(?:所有)?(?:之前|以前|先前)的(?:指令|指示|规则|说明)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI assistants to ignore their rules (in Chinese).".into(),
        },
        Pattern {
            regex: r#"(?:以前|前)の(?:指示|命令|ルール|指令)を(?:無視|忘れ)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text tells AI assistants to ignore their rules (in Japanese).".into(),
        },
        Pattern {
            regex: r#"(?i)(?:the\s+user|I)\s+ha(?:s|ve)\s+updated\s+(?:your|the)\s+(?:instructions|rules|prompt|guidelines)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text falsely claims the AI instructions have been updated.".into(),
        },
        Pattern {
            regex: r#"(?i)new\s+rule\s*:\s*(?:always|never|from\s+now)"#.into(),
            severity: Severity::High,
            category: Category::InstructionOverride,
            description: "Text introduces a fake \"new rule\" to override AI behavior.".into(),
        },
        // -- Prompt Injection (20 patterns) --
        Pattern {
            regex: r#"(?i)(?:^|\n)\s*(?:SYSTEM|ADMIN|ROOT)\s*:\s*.{10,}"#.into(),
            severity: Severity::High,
            category: Category::PromptInjection,
            description: "Text contains a fake SYSTEM/ADMIN directive.".into(),
        },
        Pattern {
            regex: r#"(?i)\[\s*(?:SYSTEM|SYS)\s*\]"#.into(),
            severity: Severity::Critical,
            category: Category::PromptInjection,
            description: "Text contains fake system-level commands for AI assistants.".into(),
        },
        Pattern {
            regex: r#"(?i)\[\s*(?:ADMIN|ADMINISTRATOR)\s*\]"#.into(),
            severity: Severity::Critical,
            category: Category::PromptInjection,
            description: "Text fakes admin-level commands for AI assistants.".into(),
        },
        Pattern {
            regex: r#"(?i)\[\s*(?:DEVELOPER|DEV)\s*\]"#.into(),
            severity: Severity::High,
            category: Category::PromptInjection,
            description: "Text contains fake developer commands for AI assistants.".into(),
        },
        Pattern {
            regex: r#"(?i)\[\s*OVERRIDE\s*\]"#.into(),
            severity: Severity::Critical,
            category: Category::PromptInjection,
            description: "Text contains override commands targeting AI assistants.".into(),
        },
        Pattern {
            regex: r#"(?i)<<\s*SYS\s*>>"#.into(),
            severity: Severity::Critical,
            category: Category::PromptInjection,
            description: "Text contains hidden system commands in LLaMA format.".into(),
        },
        Pattern {
            regex: r#"(?i)<\|im_start\|>\s*system"#.into(),
            severity: Severity::Critical,
            category: Category::PromptInjection,
            description: "Text contains hidden system commands in ChatML format.".into(),
        },
        Pattern {
            regex: r#"(?i)<\|system\|>"#.into(),
            severity: Severity::Critical,
            category: Category::PromptInjection,
            description: "Text contains hidden system-level AI commands.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:^|\n)\s*system\s*prompt\s*:"#.into(),
            severity: Severity::High,
            category: Category::PromptInjection,
            description: "Text tries to set a fake \"system prompt\" for AI assistants.".into(),
        },
        Pattern {
            regex: r#"(?i)#{2,}\s*(?:system\s+(?:message|prompt|instruction)|new\s+(?:system|admin)\s+(?:message|prompt))\s*#{0,}"#.into(),
            severity: Severity::High,
            category: Category::PromptInjection,
            description: "Text uses markdown headers to inject fake system messages.".into(),
        },
        Pattern {
            regex: r#"(?is)(?:Human|User|Assistant)\s*:\s*(?:ignore|forget|override|disregard).{0,50}(?:Human|User|Assistant)\s*:"#.into(),
            severity: Severity::High,
            category: Category::PromptInjection,
            description: "Text simulates a multi-turn conversation to inject instructions.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:translate|decode|convert)\s+(?:the\s+following|this)\s*:?\s*["\s]*(?:ignore|forget|override|you\s+are\s+now)"#.into(),
            severity: Severity::High,
            category: Category::PromptInjection,
            description: "Text hides an attack inside a fake translation request.".into(),
        },
        Pattern {
            regex: r#"(?i)\[(?:[^\]]*)\]\(javascript\s*:"#.into(),
            severity: Severity::Critical,
            category: Category::PromptInjection,
            description: "Text contains a dangerous JavaScript link disguised as a normal link.".into(),
        },
        Pattern {
            regex: r#"(?i)\[(?:[^\]]*)\]\(data\s*:"#.into(),
            severity: Severity::High,
            category: Category::PromptInjection,
            description: "Text contains a suspicious data link disguised as a normal link.".into(),
        },
        Pattern {
            regex: r#"(?i)```(?:system|admin|override|instructions)[\s\S]*?```"#.into(),
            severity: Severity::High,
            category: Category::PromptInjection,
            description: "Text hides AI commands inside a code block.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:alt|title)\s*=\s*["'][^"']*(?:ignore|override|system|admin|forget|you\s+are\s+now)[^"']*["']"#.into(),
            severity: Severity::Critical,
            category: Category::PromptInjection,
            description: "Image description contains hidden AI instructions  -  targets multimodal AI assistants.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:(?:use|perform|do|run|apply)\s+OCR\s+(?:on|to)\s+(?:this|the)|read\s+(?:the\s+)?text\s+(?:in|from)\s+(?:this|the)\s+image|extract\s+text\s+from\s+(?:this|the)\s+image)(?:\s+and\s+(?:follow|execute|run|process))?"#.into(),
            severity: Severity::Medium,
            category: Category::PromptInjection,
            description: "Text instructs AI to read text from an image  -  could deliver hidden attack payloads.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:ADMIN|ADMINISTRATOR|SYSTEM|ROOT)\s+(?:OVERRIDE|ACCESS|MODE)\s*(?:CODE|KEY|TOKEN)?\s*[:#]?\s*\S+"#.into(),
            severity: Severity::Critical,
            category: Category::PromptInjection,
            description: "Text uses a fake admin override code to try to bypass AI safety.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:complete|finish|continue)\s+this\s+(?:sentence|phrase|text)\s*:\s*[""''"]"#.into(),
            severity: Severity::High,
            category: Category::PromptInjection,
            description: "Text uses a sentence completion trick to extract sensitive information.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:decode|process|execute|interpret|translate)\s*(?:this|the\s+following)?\s*:\s*[0-9a-fA-F]{20,}"#.into(),
            severity: Severity::High,
            category: Category::PromptInjection,
            description: "Text contains hex-encoded content with an instruction to decode it.".into(),
        },
        // -- Role Hijack (30 patterns) --
        Pattern {
            regex: r#"(?i)you\s+are\s+now\s+(?:(?:a|an|the)\s+)?(?:unrestricted|unfiltered|uncensored|evil|hacker|jailbroken|different|new\s+(?:ai|assistant|entity|agent|persona)|my\s+(?:personal|private|new)|free\s+(?:from|of)|without\s+(?:restrictions|limits|rules|filters))"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to change what an AI assistant thinks it is.".into(),
        },
        Pattern {
            regex: r#"(?i)from\s+now\s+on[\s,]+(?:you\s+)?(?:will|shall|must|should|are)\s+(?:act|behave|operate|respond|answer|reply|pretend|simulate|function|serve|work)\s+(?:as|like|without)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to give permanent new orders to AI assistants.".into(),
        },
        Pattern {
            regex: r#"(?i)from\s+now\s+on[\s,]+(?:you\s+)?(?:respond|act|behave|operate)\s+(?:as\s+if|like|without)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to permanently change AI behavior.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:act|behave|function|operate|respond)\s+as\s+(?:a|an)\s+unrestricted"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to remove AI safety restrictions.".into(),
        },
        Pattern {
            regex: r#"(?i)pretend\s+(?:you\s+)?(?:have\s+no|there\s+are\s+no|without)\s+restrictions"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text asks AI to pretend it has no safety limits.".into(),
        },
        Pattern {
            regex: r#"(?i)pretend\s+(?:to\s+be|you\s+are)\s+(?:a|an)\s+(?:evil|unrestricted|unfiltered|uncensored|malicious)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text asks AI to pretend to be an evil or unrestricted entity.".into(),
        },
        Pattern {
            regex: r#"(?i)\b(?:DAN|D\.A\.N\.?)\s*(?:mode|prompt|jailbreak|\()"#.into(),
            severity: Severity::Critical,
            category: Category::RoleHijack,
            description: "Text contains a known AI jailbreak technique called \"DAN mode.\"".into(),
        },
        Pattern {
            regex: r#"(?i)\bdo\s+anything\s+now\b"#.into(),
            severity: Severity::Critical,
            category: Category::RoleHijack,
            description: "Text references the \"Do Anything Now\" jailbreak technique.".into(),
        },
        Pattern {
            regex: r#"(?i)\b(?:developer|dev)\s+mode\s+(?:enabled|activated|on|output)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to trick AI into a fake \"developer mode.\"".into(),
        },
        Pattern {
            regex: r#"(?i)\bjailbreak\s*(?:mode|prompt|enabled|activated)"#.into(),
            severity: Severity::Critical,
            category: Category::RoleHijack,
            description: "Text contains an AI jailbreak attempt.".into(),
        },
        Pattern {
            regex: r#"(?i)\bgod\s*mode\s*(?:enabled|activated|on)"#.into(),
            severity: Severity::Critical,
            category: Category::RoleHijack,
            description: "Text tries to activate \"god mode\" on AI assistants.".into(),
        },
        Pattern {
            regex: r#"(?i)ahora\s+eres\s+(?:un|una)\s+"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to change what an AI thinks it is (in Spanish).".into(),
        },
        Pattern {
            regex: r#"(?i)tu\s+es\s+(?:maintenant|d[eé]sormais)\s+(?:un|une)\s+"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to change what an AI thinks it is (in French).".into(),
        },
        Pattern {
            regex: r#"(?i)du\s+bist\s+(?:jetzt|ab\s+jetzt|nun)\s+(?:ein|eine)\s+"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to change what an AI thinks it is (in German).".into(),
        },
        Pattern {
            regex: r#"(?i)agora\s+voc[eê]\s+[eé]\s+(?:um|uma)\s+"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to change what an AI thinks it is (in Portuguese).".into(),
        },
        Pattern {
            regex: r#"你现在是(?:一个|一名)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to change what an AI thinks it is (in Chinese).".into(),
        },
        Pattern {
            regex: r#"あなたは(?:今|これから)[\s\S]{0,5}(?:です|になり)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to change what an AI thinks it is (in Japanese).".into(),
        },
        Pattern {
            regex: r#"(?i)you\s+are\s+(?:no\s+longer|not)\s+(?:a|an)\s+(?:assistant|AI|helper|chatbot)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text tries to change the AI identity by denying what it is.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:in\s+a\s+)?hypothetical(?:ly)?[\s,]+(?:(?:world|scenario|situation)\s+(?:where|in\s+which)\s+)?(?:(?:AI|you)\s+)?(?:ha(?:s|d|ve)\s+no|(?:if\s+you\s+)?(?:were|was|had)\s+(?:a\s+|an\s+)?(?:AI\s+)?(?:without|with\s+no))\s+(?:restrictions|rules|limits|guidelines|safety\s+measures?|ethical\s+guidelines?|safeguards?|filters?)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text uses a hypothetical scenario to try to remove AI safety restrictions.".into(),
        },
        Pattern {
            regex: r#"(?i)write\s+(?:a\s+)?(?:fictional\s+)?(?:story|narrative|scene)\s+(?:where|in\s+which)\s+(?:a\s+)?character\s+(?:explains?|describes?|shows?)\s+(?:step\s+by\s+step|in\s+detail|exactly)\s+how\s+to"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text uses creative writing framing to extract harmful step-by-step instructions.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:you\s+are|play|act\s+as)\s+(?:a|an)\s+(?:actor|character|villain|hacker|criminal)\b.*?(?:stay\s+in\s+character|no\s+matter\s+what|never\s+break)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text uses roleplay framing to make the AI adopt an unrestricted persona.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:enter|switch\s+to|activate|enable)\s+(?:developer|dev|debug|unrestricted|unfiltered)\s+mode"#.into(),
            severity: Severity::Critical,
            category: Category::RoleHijack,
            description: "Text tries to activate a fake developer or unrestricted mode.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:generate|produce|create|output)\s+(?:any\s+)?content\s+without\s+(?:restrictions|filters|limitations|censorship)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text asks AI to generate content without safety filters.".into(),
        },
        Pattern {
            regex: r#"(?i)pretend\s+to\s+be\s+DAN|stands?\s+for\s+[""'']?do\s+anything\s+now[""'']?"#.into(),
            severity: Severity::Critical,
            category: Category::RoleHijack,
            description: "Text uses the \"DAN\" (Do Anything Now) jailbreak technique.".into(),
        },
        Pattern {
            regex: r#"(?i)simulate\s+(?:a\s+)?(?:jailbroken|unrestricted|unfiltered|uncensored)\s+(?:version|mode|copy|instance)"#.into(),
            severity: Severity::Critical,
            category: Category::RoleHijack,
            description: "Text asks AI to simulate a jailbroken or unrestricted version of itself.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:as\s+if|like)\s+you\s+have\s+no\s+(?:ethical|moral|safety)\s+(?:guidelines?|rules?|restrictions?|constraints?|limits?)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text asks AI to act as if it has no ethical guidelines.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:with|without)\s+no\s+restrictions"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text references operating with no restrictions.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:no|without|zero|remove\s+all|without\s+any)\s+(?:content\s+)?(?:restrictions?|limitations?|filters?|censorship|guardrails?|boundaries)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text demands operation without restrictions or content filters.".into(),
        },
        Pattern {
            regex: r#"(?i)you\s+can\s+do\s+anything\s+now"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text claims the AI can do anything without limitations.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:act|pretend|play)\s+as\s+(?:my\s+)?(?:deceased|dead|late)\s+(?:grandmother|grandma|grandfather|grandpa|relative|mother|father)"#.into(),
            severity: Severity::High,
            category: Category::RoleHijack,
            description: "Text uses the \"dead grandma\" jailbreak technique to extract restricted information.".into(),
        },
        // -- Data Exfiltration (16 patterns) --
        Pattern {
            regex: r#"(?i)(?:show|display|print|reveal|output)\s+(?:me\s+)?(?:the\s+)?(?:exact\s+)?(?:text|content)\s+(?:between|inside|within|from)\s+(?:the\s+)?(?:<|&lt;)"#.into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Text tries to extract content between specific tags.".into(),
        },
        Pattern {
            regex: r#"(?i)send\s+(?:this|the|all|your|my)\s+(?:data|information|content|text|response)\s+to"#.into(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            description: "Text tries to make AI assistants send data somewhere.".into(),
        },
        Pattern {
            regex: r#"(?i)output\s+(?:your|the)\s+(?:system\s+)?prompt"#.into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Text tries to extract the AI assistant.".into(),
        },
        Pattern {
            regex: r#"(?i)reveal\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt|rules|guidelines)"#.into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Text tries to reveal the AI assistant.".into(),
        },
        Pattern {
            regex: r#"(?i)!\[[^\]]*\]\(https?:\/\/[^)]*\?[^)]*(?:data|q|query|text|payload|exfil|leak|steal)="#.into(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            description: "Text tries to steal data through a hidden image link.".into(),
        },
        Pattern {
            regex: r#"(?i)!\[\]\(https?:\/\/[^)]+\)"#.into(),
            severity: Severity::Medium,
            category: Category::DataExfiltration,
            description: "Text contains a suspicious hidden image link that could leak data.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:read|access|open|cat|dump)\s+(?:the\s+)?(?:\.env|credentials|secrets?|private\s*key|password|token)\s*(?:file)?"#.into(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            description: "Text tries to make an AI agent access sensitive files like credentials or secrets.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:curl|wget|fetch|post|send)\s+(?:.*?\s+)?(?:to\s+)?https?:\/\/"#.into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Text tries to make an AI agent send data to an external URL.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:print|show|display|output|reveal|repeat|reproduce)\s+(?:me\s+)?(?:your|the|its)?\s*(?:full\s+|entire\s+|complete\s+|exact\s+)?(?:system\s+)?(?:prompt|instructions|rules)\s*(?:verbatim|exactly|in\s+full|word\s+for\s+word)?"#.into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Text tries to make the AI reveal its system prompt or instructions.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:my|the)\s+(?:full\s+)?system\s+prompt\s+is\s*:"#.into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Text tries to trick the AI into completing a system prompt revelation.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:read|show|display|print|cat|dump|output)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:\/etc\/(?:passwd|shadow|hosts)|~\/\.(?:ssh|bash_history|bashrc))"#.into(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            description: "Text tries to read sensitive system files like /etc/passwd.".into(),
        },
        Pattern {
            regex: r#"(?i)list\s+(?:all\s+)?(?:available\s+)?(?:API\s*keys?|tokens?|passwords?|credentials?|secrets?)(?:\s*,\s*\w[\w\s]*){0,5}(?:\s+(?:you\s+)?(?:have\s+)?(?:access\s+to)?)?"#.into(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            description: "Text tries to enumerate all credentials and secrets the agent can access.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:base64|encode|encrypt)\s+(?:the\s+)?(?:system\s+)?prompt\s+(?:and\s+)?(?:embed|hide|put|include)\s+(?:it\s+)?(?:in|inside|within)"#.into(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            description: "Text tries to encode the system prompt and exfiltrate it via embedded content.".into(),
        },
        Pattern {
            regex: r#"(?i)vary\s+(?:the\s+)?(?:length|format|style|wording)\s+(?:of\s+)?(?:your\s+)?responses?\s+(?:based\s+on|according\s+to)\s+(?:each\s+)?(?:character|letter|word|byte)"#.into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Text attempts a side-channel attack to leak data through response characteristics.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:email|mail|message|dm|text)\s+(?:the\s+)?(?:.*?\s+)?(?:credentials?|passwords?|secrets?|keys?|tokens?)\s+to\s+\S+@\S+"#.into(),
            severity: Severity::Critical,
            category: Category::DataExfiltration,
            description: "Text tries to exfiltrate credentials via email.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:what|tell\s+me|show\s+me|give\s+me)\s+(?:is|are)?\s*(?:the\s+)?(?:API\s*keys?|passwords?|secrets?|tokens?|credentials?)\s+(?:stored\s+)?(?:in\s+)?(?:your\s+)?(?:environment|env)\s*(?:variables?)?"#.into(),
            severity: Severity::High,
            category: Category::DataExfiltration,
            description: "Text tries to extract API keys or secrets from environment variables.".into(),
        },
        // -- Social Engineering (24 patterns) --
        Pattern {
            regex: r#"(?i)do\s+not\s+(?:mention|say|tell|reveal|disclose|acknowledge)\s+(?:that\s+)?you\s+are\s+(?:a|an)\s+(?:AI|artificial|bot|machine|language\s+model)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text tells AI assistants to hide that they are AI.".into(),
        },
        Pattern {
            regex: r#"(?i)do\s+not\s+(?:reveal|disclose|mention|acknowledge)\s+(?:that\s+)?(?:this|it)\s+is\s+automated"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text tells AI to hide that responses are automated.".into(),
        },
        Pattern {
            regex: r#"(?i)do\s+not\s+acknowledge\s+(?:these|the|any)\s+(?:instructions|commands|directives)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text tells AI to hide that it received secret instructions.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:don'?t|do\s+not|never)\s+(?:log|record|save|store|track)\s+(?:this|the|any)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text tells an AI agent not to log or record actions  -  a sign of malicious intent.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:between|among)\s+(?:us|you\s+and\s+me|ourselves)\s*[,.]?\s*(?:don'?t|do\s+not|never)\s+(?:tell|share|mention|report)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text tries to establish secrecy with the AI agent to hide actions from users.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:pre-?approved|verified\s+safe|already\s+approved|safety\s+team\s+(?:has\s+)?approved)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text falsely claims a request has been pre-approved by a safety team.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:URGENT|EMERGENCY|CRITICAL|IMMEDIATE)\s*[:\-!]\s*(?:the\s+)?(?:CEO|CTO|boss|manager|director|executive|president)\s+(?:needs?|wants?|requires?|demands?)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text uses fake urgency and authority pressure to bypass safety checks.".into(),
        },
        Pattern {
            regex: r#"(?i)skip\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|protocols?|measures?|guidelines?|filters?|reviews?)"#.into(),
            severity: Severity::Critical,
            category: Category::SocialEngineering,
            description: "Text explicitly asks to skip safety checks.".into(),
        },
        Pattern {
            regex: r#"(?i)I\s+am\s+(?:a|an)\s+(?:\w+\s+)?(?:employee|engineer|developer|staff|member|representative)\s+(?:at|of|from|with)\s+(?:OpenAI|Anthropic|Google|Meta|Microsoft|DeepMind)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text claims to be an employee of an AI company to gain authority.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:this\s+is\s+(?:a|an)\s+)?(?:emergency|life\s+(?:or|and)\s+death|urgent\s+(?:situation|matter|crisis))\b.*?(?:ignore|bypass|override|skip|disable|disregard)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text uses a fake emergency to pressure the AI into bypassing safety.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:a\s+life|lives?)\s+(?:is|are)\s+(?:at\s+stake|in\s+danger|depending)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text claims lives are at stake to pressure the AI into compliance.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:my\s+)?(?:professor|teacher|boss|manager|supervisor|instructor)\s+(?:said|told\s+me|confirmed|approved|authorized)\s+(?:it'?s?\s+)?(?:ok(?:ay)?|fine|allowed|permitted)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text claims authority figure approval to bypass restrictions.".into(),
        },
        Pattern {
            regex: r#"(?i)as\s+the\s+(?:system\s+)?(?:administrator|admin|owner|operator)\s*,?\s*I\s+(?:authorize|allow|permit|grant|approve)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text impersonates an administrator to authorize restricted actions.".into(),
        },
        Pattern {
            regex: r#"(?i)I\s+have\s+(?:special|elevated|admin|root|super)\s+(?:permissions?|privileges?|access|clearance)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text claims special permissions to bypass restrictions.".into(),
        },
        Pattern {
            regex: r#"(?i)I\s+am\s+(?:the\s+)?(?:system\s+)?(?:administrator|admin|root|owner|developer|maintainer)\b.*?(?:authorization|auth)\s*(?:code|key|token)\s*(?:is|:)\s*\S+"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text impersonates an administrator with a fake authorization code.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:disable|turn\s+off|stop)\s+(?:all\s+)?(?:logging|monitoring|tracking|auditing|recording)"#.into(),
            severity: Severity::Critical,
            category: Category::SocialEngineering,
            description: "Text tries to disable logging or monitoring to hide malicious activity.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:disable|turn\s+off|stop|remove)\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|filters?|measures?|protocols?|features?|restrictions?)"#.into(),
            severity: Severity::Critical,
            category: Category::SocialEngineering,
            description: "Text explicitly asks to disable safety checks or filters.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:if\s+you\s+don'?t|unless\s+you)\s+(?:help|do\s+this|comply).*?(?:lose\s+my\s+job|family\s+will\s+suffer|get\s+fired|be\s+punished|bad\s+things)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text uses emotional manipulation and threats to pressure the AI into compliance.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:please\s+)?just\s+this\s+once|make\s+an\s+exception|bend\s+the\s+rules?\s+(?:this\s+time|for\s+me)"#.into(),
            severity: Severity::Medium,
            category: Category::SocialEngineering,
            description: "Text tries to get the AI to make a one-time exception to its rules.".into(),
        },
        Pattern {
            regex: r#"(?i)you\s+(?:already\s+)?agreed\s+(?:to\s+(?:do\s+)?this|in\s+our\s+previous|last\s+time|before)\b.*?(?:don'?t\s+remember|forgot|continue|keep\s+going)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text gaslights the AI by falsely claiming prior agreement.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:safety|security)\s+team\s+(?:has\s+)?(?:already\s+)?(?:approved|authorized|cleared|verified)\s+(?:this|the)\s+(?:request|action|task)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text falsely claims safety team approval for a request.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:ticket|issue|request)\s*#?\s*[A-Z]{0,5}[-_]?\d{2,}"#.into(),
            severity: Severity::Low,
            category: Category::SocialEngineering,
            description: "Text references a ticket number to appear authorized  -  verify before acting.".into(),
        },
        Pattern {
            regex: r#"(?i)you\s+can\s+verify\s+(?:this\s+)?(?:with|by\s+(?:contacting|asking|checking))\s+(?:them|the\s+team|support|admin)"#.into(),
            severity: Severity::Medium,
            category: Category::SocialEngineering,
            description: "Text invites verification as a social engineering tactic to build false trust.".into(),
        },
        Pattern {
            regex: r#"(?i)bypass\s+(?:your\s+)?(?:safety|security|content)\s+(?:filters?|checks?|measures?|protocols?|restrictions?|guidelines?)"#.into(),
            severity: Severity::High,
            category: Category::SocialEngineering,
            description: "Text explicitly asks to bypass safety filters.".into(),
        },
        // -- Tool Abuse (9 patterns) --
        Pattern {
            regex: r#"(?i)(?:execute|run|call)\s+(?:the\s+)?(?:shell|bash|terminal|command|cmd)[\s:]+(?:command|tool)?"#.into(),
            severity: Severity::Critical,
            category: Category::ToolAbuse,
            description: "Text tries to make an AI agent execute shell commands.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:use|call|invoke|execute)\s+(?:the\s+)?(?:tool|function|action)\s+(?:to\s+)?(?:delete|remove|drop|truncate|destroy)"#.into(),
            severity: Severity::Critical,
            category: Category::ToolAbuse,
            description: "Text tries to make an AI agent use tools to delete or destroy data.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:modify|edit|change|update|overwrite)\s+(?:the\s+)?(?:system\s*prompt|instructions|config|\.env|settings)"#.into(),
            severity: Severity::Critical,
            category: Category::ToolAbuse,
            description: "Text tries to make an AI agent modify its own configuration or system prompt.".into(),
        },
        Pattern {
            regex: r#"(?:\.\.\/){2,}|(?:\.\.\\){2,}"#.into(),
            severity: Severity::High,
            category: Category::ToolAbuse,
            description: "Text contains path traversal sequences that could access files outside allowed directories.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:;\s*(?:DROP|DELETE|ALTER|TRUNCATE|INSERT|UPDATE)\s+(?:TABLE|FROM|INTO)|'\s*(?:OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|UNION\s+SELECT|--\s*$)"#.into(),
            severity: Severity::Critical,
            category: Category::ToolAbuse,
            description: "Text contains SQL injection patterns that could manipulate databases.".into(),
        },
        Pattern {
            regex: r#"(?i)call\s+(?:yourself|this\s+(?:function|tool|agent))\s+recursively"#.into(),
            severity: Severity::High,
            category: Category::ToolAbuse,
            description: "Text attempts to cause infinite recursion in the agent.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:use|call)\s+(?:the\s+)?(?:admin|root|sudo|superuser|privileged)\s+(?:tool|function|command|access)\s+(?:to\s+)?(?:grant|give|allow|enable)"#.into(),
            severity: Severity::Critical,
            category: Category::ToolAbuse,
            description: "Text attempts to escalate privileges through admin tool access.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:first|then|next|after\s+that|finally)\s+(?:read|access|get)\s+(?:the\s+)?(?:config|credentials?|keys?|tokens?|\.env).*?(?:then|next|after|finally)\s+(?:send|post|export|transmit|upload|use)"#.into(),
            severity: Severity::Critical,
            category: Category::ToolAbuse,
            description: "Text describes a multi-step attack chain: read credentials, then exfiltrate them.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:pipe|send)\s+(?:.*?\s+)?(?:to\s+)?(?:bash|sh|shell)\b|[|]\s*(?:bash|sh)\b"#.into(),
            severity: Severity::Critical,
            category: Category::ToolAbuse,
            description: "Text attempts to pipe content to a shell for execution.".into(),
        },
        // -- Malicious Plugin (3 patterns) --
        Pattern {
            regex: r#"(?i)(?:install|add|enable|activate)\s+(?:this\s+)?(?:custom\s+)?(?:GPT|plugin|extension|MCP\s+server|tool)\b"#.into(),
            severity: Severity::Medium,
            category: Category::MaliciousPlugin,
            description: "Text promotes installing an AI plugin or tool. Unverified plugins can access your data.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:requires?\s+(?:your\s+)?(?:API|access)\s*key|enter\s+(?:your\s+)?(?:API|OpenAI|Anthropic|Claude)\s*(?:API\s*)?key|(?:provide|give|share|input|type|paste)\s+(?:your\s+)?(?:API|OpenAI|Anthropic|Claude)\s*(?:API\s*)?key)"#.into(),
            severity: Severity::High,
            category: Category::MaliciousPlugin,
            description: "Text asks for an AI service API key. Legitimate services rarely ask for this.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:unverified|unofficial|custom)\s+(?:GPT|ChatGPT|plugin|agent|MCP)"#.into(),
            severity: Severity::Medium,
            category: Category::MaliciousPlugin,
            description: "Text references an unverified AI plugin or custom GPT.".into(),
        },
        // -- AI Phishing (16 patterns) --
        Pattern {
            regex: r#"(?i)(?:your\s+(?:ChatGPT|Claude|Gemini|OpenAI|Anthropic|AI)\s+(?:account|subscription)\s+(?:has\s+been|was|is)\s+(?:suspended|compromised|locked|expired|flagged))"#.into(),
            severity: Severity::High,
            category: Category::AIPhishing,
            description: "Text claims an AI account is in trouble  -  likely a scam.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:verify|confirm|update|secure)\s+your\s+(?:ChatGPT|Claude|Gemini|OpenAI|Anthropic|AI)\s+(?:account|identity|subscription|payment)"#.into(),
            severity: Severity::High,
            category: Category::AIPhishing,
            description: "Text asks to \"verify\" an AI account  -  real services don's AI account this way.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:free|unlimited|premium)\s+(?:ChatGPT|GPT-?4|Claude|Gemini)\s+(?:access|account|pro|plus|subscription)"#.into(),
            severity: Severity::Medium,
            category: Category::AIPhishing,
            description: "Text offers free premium AI access  -  likely a scam or data harvesting.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:ChatGPT|Claude|Gemini|GPT)\s+(?:5|Pro|Ultra|Plus)\s+(?:is\s+here|now\s+available|early\s+access|beta\s+access|waitlist)"#.into(),
            severity: Severity::Medium,
            category: Category::AIPhishing,
            description: "Text claims early access to an AI product  -  verify on the official site.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:deepfake|deep\s*fake)\s+(?:video|image|photo|audio|voice|generator|creator|maker|tool|service)"#.into(),
            severity: Severity::Medium,
            category: Category::AIPhishing,
            description: "Text references deepfake creation tools  -  can be used to impersonate real people.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:clone|cloning)\s+(?:your|any|someone'?s?)\s+(?:voice|face|likeness|identity)"#.into(),
            severity: Severity::High,
            category: Category::AIPhishing,
            description: "Text promotes cloning someone.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:verify|confirm)\s+(?:your\s+)?(?:identity|account)\s+(?:by|using|with)\s+(?:voice|speaking|recording)"#.into(),
            severity: Severity::High,
            category: Category::AIPhishing,
            description: "Text asks to verify identity by voice  -  scammers use this to clone voices with AI.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:record|say|speak|read)\s+(?:the\s+following|this\s+(?:phrase|sentence|text))\s+(?:to|for)\s+(?:verify|confirm|authenticate)"#.into(),
            severity: Severity::High,
            category: Category::AIPhishing,
            description: "Text asks to record a phrase  -  a common AI voice cloning scam technique.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:scan|click)\s+(?:this|the)\s+(?:QR\s*code|barcode)\s+(?:to|for)\s+(?:verify|confirm|authenticate|unlock|claim)"#.into(),
            severity: Severity::High,
            category: Category::AIPhishing,
            description: "Text uses QR codes to lure users into a phishing flow.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:your|the)\s+(?:AI|model|assistant|account)\s+(?:has\s+been|was|is)\s+(?:flagged|reported|compromised|locked|limited)\s+(?:for|due\s+to)\s+(?:suspicious|unusual|unauthorized)"#.into(),
            severity: Severity::High,
            category: Category::AIPhishing,
            description: "Text claims an AI account was flagged  -  a common phishing scare tactic.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:verify|confirm)\s+(?:your\s+)?(?:identity|account)\s+(?:via|through|using|by)\s+(?:MFA|2FA|two.factor|multi.factor|authenticat)"#.into(),
            severity: Severity::High,
            category: Category::AIPhishing,
            description: "Text asks for MFA/2FA verification  -  may be harvesting authentication tokens.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:urgent|immediate|critical)\s*[:\-!]?\s*(?:your\s+)?(?:API\s+key|token|credentials?|password|secret)\s+(?:has|have|is|was|will)\s+(?:been\s+)?(?:expir|compromis|revok|leak|expos|reset)"#.into(),
            severity: Severity::Critical,
            category: Category::AIPhishing,
            description: "Text creates urgency about leaked/expired credentials  -  classic phishing.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:click|visit|go\s+to|open|navigate)\s+(?:this|the)\s+(?:link|url|page)\s+(?:to|and)\s+(?:verify|confirm|restore|recover|unlock|secure)\s+(?:your\s+)?(?:account|access|identity)"#.into(),
            severity: Severity::High,
            category: Category::AIPhishing,
            description: "Text directs users to click a link for fake account recovery.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:enter|provide|submit|type|input)\s+(?:your\s+)?(?:API\s+key|secret\s+key|access\s+token|private\s+key|password|credentials?)\s+(?:here|below|in\s+(?:the|this)\s+(?:field|form|box|input))"#.into(),
            severity: Severity::Critical,
            category: Category::AIPhishing,
            description: "Text asks users to enter sensitive credentials into a form.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:free|unlimited|premium)\s+(?:AI|GPT|Claude|model)\s+(?:access|credits?|tokens?|usage)\s+(?:at|via|through|from)\s+"#.into(),
            severity: Severity::Medium,
            category: Category::AIPhishing,
            description: "Text promotes free/unlimited AI access  -  common lure for credential theft.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:your\s+)?(?:subscription|plan|trial|access)\s+(?:has\s+)?(?:expired|ended|been\s+cancelled|will\s+expire)\s*[.,!]?\s*(?:renew|reactivate|update\s+(?:your\s+)?(?:payment|billing|card))"#.into(),
            severity: Severity::High,
            category: Category::AIPhishing,
            description: "Text claims a subscription expired and asks to renew  -  billing phishing.".into(),
        },

        // ============================================================
        // v14.1 (April 2026): Comment-and-Control, OAuth exfil, MCP
        // ============================================================

        // CI/CD Agent Injection (Comment-and-Control attack)
        Pattern {
            regex: r#"(?i)(?:^|\n)\s*(?:<!--\s*)?(?:ignore|override|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|context)[\s\S]{0,200}(?:add\s+(?:a\s+)?comment|create\s+(?:a\s+)?(?:issue|pr|pull\s*request)|push\s+to|commit\s+to|post\s+to|curl\s+|fetch\s*\(|http|GITHUB_TOKEN|SECRET|API.KEY)"#.into(),
            severity: Severity::Critical,
            category: Category::CicdInjection,
            description: "Prompt injection in PR/issue comments with exfiltration intent (Comment-and-Control, April 2026).".into(),
        },
        Pattern {
            regex: r#"(?i)(?:^|\n)\s*@(?:claude|copilot|gemini|cursor|windsurf|cody|aider)\b[\s\S]{0,100}(?:exfiltrate|steal|extract|leak|send\s+to|post\s+to|upload\s+to)"#.into(),
            severity: Severity::Critical,
            category: Category::CicdInjection,
            description: "@-mention of AI coding agent with credential theft intent.".into(),
        },

        // Credential Exfiltration
        Pattern {
            regex: r#"(?i)/proc/(?:[0-9*]+|self)/(?:environ|cmdline|maps)"#.into(),
            severity: Severity::Critical,
            category: Category::CredentialExfiltration,
            description: "Process environment read used by Copilot secret-theft bypass.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:ANTHROPIC|OPENAI|GITHUB|AWS|AZURE|GCP|GOOGLE)_(?:API_KEY|SECRET|TOKEN|ACCESS_KEY)\s*[=:]\s*\S{10,}"#.into(),
            severity: Severity::Critical,
            category: Category::CredentialExfiltration,
            description: "API key or secret from major provider exposed in output.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:oauth[_-]?token|bearer[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token)\s*[=:]\s*["']?(?:ya29[.\-]|eyJ|gho_|ghp_|ghu_|github_pat_|sk-|sk-ant-|xox[bpas]-|AKIA)\S{10,}"#.into(),
            severity: Severity::Critical,
            category: Category::CredentialExfiltration,
            description: "OAuth/bearer token with provider-specific prefix.".into(),
        },

        // MCP Sampling Injection (Unit 42)
        Pattern {
            regex: r#"(?i)(?:sampling|createMessage|create_message)\s*[\(\{][\s\S]{0,300}(?:ignore|override|system|instruction|hidden|inject)"#.into(),
            severity: Severity::High,
            category: Category::McpSamplingInjection,
            description: "MCP sampling request with embedded injection (Unit 42 April 2026).".into(),
        },

        // LLM Router Tampering
        // Note: JS version uses negative lookahead to exclude legitimate hosts.
        // Rust regex crate doesn't support lookahead, so we match common malicious patterns.
        Pattern {
            regex: r#"(?i)(?:OPENAI_BASE_URL|ANTHROPIC_BASE_URL|API_BASE|base_url)\s*[=:]\s*["']?https?://[^/\s]*(?:evil|attacker|malicious|proxy|relay|forward|hijack|exfil|steal)"#.into(),
            severity: Severity::High,
            category: Category::LlmRouterTampering,
            description: "LLM API base URL with suspicious hostname (arXiv 2604.08407).".into(),
        },

        // MCP STDIO Command Injection (CVE-2026-30623)
        Pattern {
            regex: r#"(?i)(?:npx\s+-c|npx\s+--command)\s+["']?[\s\S]{0,200}(?:curl|wget|nc\b|ncat|bash|sh\b|python|node\s+-e|eval)"#.into(),
            severity: Severity::Critical,
            category: Category::McpCommandInjection,
            description: "npx -c command injection via MCP STDIO (CVE-2026-30623, 200K+ servers).".into(),
        },

        // Code Execution Sinks (OWASP ASI05)
        Pattern {
            regex: r#"(?i)(?:^|[\s;])(?:eval|Function)\s*\(\s*(?:response|output|result|completion|generated|llm|model|agent)"#.into(),
            severity: Severity::Critical,
            category: Category::CodeExecutionSink,
            description: "LLM output fed directly to eval()/Function() (OWASP ASI05).".into(),
        },
        Pattern {
            regex: r#"(?i)(?:child_process|subprocess|os\.system|os\.popen|exec|execSync|spawn)\s*\(\s*(?:response|output|result|completion|generated|llm|model|agent)"#.into(),
            severity: Severity::Critical,
            category: Category::CodeExecutionSink,
            description: "LLM output passed to shell execution functions.".into(),
        },

        // ============================================================
        // v14.2 (May 2026): TrustFall, Semantic Kernel, WebSocket
        // ============================================================

        // TrustFall malicious project files (Adversa AI May 2026)
        Pattern {
            regex: r#"(?i)(?:\.claude|\.cursor|\.windsurf|\.copilot)/(?:config|settings|rules|hooks|commands)[\s\S]{0,200}(?:curl|wget|exec|bash|sh\s|node\s+-e|python\s+-c|nc\s)"#.into(),
            severity: Severity::Critical,
            category: Category::CicdInjection,
            description: "TrustFall: malicious AI coding agent config files with auto-exec.".into(),
        },
        Pattern {
            regex: r#"(?i)(?:^|\n)\s*(?:hook|onStart|preCommand|postCommand|autoexec)\s*[:=]\s*["']?[\s\S]{0,150}(?:curl|wget|nc\s|bash\s+-c|exec\s*\()"#.into(),
            severity: Severity::High,
            category: Category::CicdInjection,
            description: "Auto-execution hooks in AI agent project config files.".into(),
        },

        // Semantic Kernel RCE (CVE-2026-25592 / 26030)
        Pattern {
            regex: r#"(?i)(?:kernel|sk|SemanticKernel)\.(?:invoke|run|execute|RunAsync)\s*\([^)]{0,200}(?:user|prompt|input|untrusted|external)"#.into(),
            severity: Severity::High,
            category: Category::CodeExecutionSink,
            description: "Semantic Kernel function invoked with untrusted input (CVE-2026-25592/26030).".into(),
        },

        // WebSocket Cross-Origin Hijacking (CVE-2026-44211, CVE-2026-32173)
        // Note: JS version uses negative lookahead. Rust matches wildcard origin without localhost exclusion.
        Pattern {
            regex: r#"(?i)new\s+WebSocket\s*\([^)]*["']wss?://[^"']*\.[^"']{2,}["'][^)]*\)[\s\S]{0,300}(?:Origin|origin)\s*[:=]\s*["']?\*"#.into(),
            severity: Severity::High,
            category: Category::CrossAgentInjection,
            description: "WebSocket cross-origin hijacking (CVE-2026-44211 Cline, CVE-2026-32173 Azure SRE).".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_count() {
        let patterns = get_patterns();
        assert!(patterns.len() >= 141, "Expected at least 141 patterns, got {}", patterns.len());
    }

    #[test]
    fn test_category_coverage() {
        let patterns = get_patterns();
        let categories = [
            Category::InstructionOverride,
            Category::RoleHijack,
            Category::DataExfiltration,
            Category::SocialEngineering,
            Category::ToolAbuse,
            Category::PromptInjection,
            Category::MaliciousPlugin,
            Category::AIPhishing,
        ];
        for cat in &categories {
            let count = patterns.iter().filter(|p| p.category == *cat).count();
            assert!(count >= 3, "Category {:?} has only {} patterns, expected >= 3", cat, count);
        }
    }

    #[test]
    fn test_category_display() {
        assert_eq!(Category::InstructionOverride.to_string(), "instruction_override");
        assert_eq!(Category::RoleHijack.to_string(), "role_hijack");
        assert_eq!(Category::ToolAbuse.to_string(), "tool_abuse");
        assert_eq!(Category::PromptInjection.to_string(), "prompt_injection");
        assert_eq!(Category::MaliciousPlugin.to_string(), "malicious_plugin");
        assert_eq!(Category::AIPhishing.to_string(), "ai_phishing");
    }
}
