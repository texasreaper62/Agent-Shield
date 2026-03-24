//! WebAssembly bindings via `wasm-bindgen`.
//!
//! Exposes the scanning engine to JavaScript/TypeScript running in browsers
//! or any WASM runtime.

use wasm_bindgen::prelude::*;

use crate::scanner::{ScanConfig, Scanner};
use crate::severity::Severity;

/// Scans a text string for threats and returns a JSON-serialized `ScanResult`.
///
/// # Arguments
///
/// * `text` - The input text to scan.
///
/// # Returns
///
/// A `JsValue` containing the JSON representation of the scan result.
#[wasm_bindgen]
pub fn scan_text(text: &str) -> JsValue {
    let scanner = Scanner::new(None);
    let result = scanner.scan(text);
    let json = serde_json::to_string(&result).unwrap_or_else(|e| {
        format!(r#"{{"error":"serialization failed: {}"}}"#, e)
    });
    JsValue::from_str(&json)
}

/// Returns the number of built-in detection patterns.
#[wasm_bindgen]
pub fn get_pattern_count() -> usize {
    let scanner = Scanner::new(None);
    scanner.pattern_count()
}

/// Scans text with a custom configuration provided as a JSON string.
///
/// # Arguments
///
/// * `text` - The input text to scan.
/// * `config_json` - JSON string representing a `ScanConfig`.
///
/// # Config JSON Format
///
/// ```json
/// {
///   "min_severity": "Medium",
///   "categories": null,
///   "max_input_size": 1000000,
///   "time_budget_us": 0
/// }
/// ```
#[wasm_bindgen]
pub fn scan_text_with_config(text: &str, config_json: &str) -> JsValue {
    let config: ScanConfig = match serde_json::from_str(config_json) {
        Ok(c) => c,
        Err(e) => {
            let err = format!(r#"{{"error":"invalid config: {}"}}"#, e);
            return JsValue::from_str(&err);
        }
    };
    let scanner = Scanner::new(Some(config));
    let result = scanner.scan(text);
    let json = serde_json::to_string(&result).unwrap_or_else(|e| {
        format!(r#"{{"error":"serialization failed: {}"}}"#, e)
    });
    JsValue::from_str(&json)
}
