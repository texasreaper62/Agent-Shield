//! Severity levels for threat classification.
//!
//! Provides a four-tier severity model matching the JavaScript Agent Shield SDK:
//! Critical > High > Medium > Low.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Threat severity level.
///
/// Ordered from least to most severe. Supports comparison via `PartialOrd`/`Ord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum Severity {
    /// Low-risk indicator, likely benign but worth noting.
    Low = 1,
    /// Medium-risk indicator, warrants review.
    Medium = 2,
    /// High-risk threat, likely malicious.
    High = 3,
    /// Critical threat requiring immediate blocking.
    Critical = 4,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!("unknown severity: {}", other)),
        }
    }
}

/// Returns the numeric order of a severity level (1-4).
pub fn severity_order(s: &Severity) -> u8 {
    *s as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::Low.to_string(), "low");
    }

    #[test]
    fn test_from_str() {
        assert_eq!(Severity::from_str("HIGH").unwrap(), Severity::High);
        assert!(Severity::from_str("unknown").is_err());
    }

    #[test]
    fn test_severity_order() {
        assert_eq!(severity_order(&Severity::Low), 1);
        assert_eq!(severity_order(&Severity::Critical), 4);
    }
}
