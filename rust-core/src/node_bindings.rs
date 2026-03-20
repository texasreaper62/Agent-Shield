//! Node.js NAPI bindings.
//!
//! Exposes the scanning engine as a native Node.js addon via NAPI-RS.

use napi_derive::napi;

use crate::scanner::Scanner;

/// Scans a text string for threats.
///
/// Returns a JSON string containing the `ScanResult`.
#[napi]
pub fn scan_text(text: String) -> napi::Result<String> {
    let scanner = Scanner::new(None);
    let result = scanner.scan(&text);
    serde_json::to_string(&result)
        .map_err(|e| napi::Error::from_reason(format!("serialization failed: {}", e)))
}

/// Scans multiple text strings for threats in a single call.
///
/// Returns a JSON string containing a `Vec<ScanResult>`.
#[napi]
pub fn scan_batch(texts: Vec<String>) -> napi::Result<String> {
    let scanner = Scanner::new(None);
    let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
    let results = scanner.scan_batch(&refs);
    serde_json::to_string(&results)
        .map_err(|e| napi::Error::from_reason(format!("serialization failed: {}", e)))
}

/// Returns a JSON string containing all built-in patterns.
#[napi]
pub fn get_patterns() -> napi::Result<String> {
    let patterns = crate::patterns::get_patterns();
    serde_json::to_string(&patterns)
        .map_err(|e| napi::Error::from_reason(format!("serialization failed: {}", e)))
}
