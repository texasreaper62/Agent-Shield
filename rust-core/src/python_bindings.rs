//! Python bindings via PyO3.
//!
//! Exposes the scanning engine as a native Python extension module.

use pyo3::prelude::*;

use crate::scanner::Scanner;

/// Scans a text string for threats.
///
/// Returns a JSON string containing the scan result.
#[pyfunction]
fn scan_text(text: &str) -> PyResult<String> {
    let scanner = Scanner::new(None);
    let result = scanner.scan(text);
    serde_json::to_string(&result)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("serialization failed: {}", e)))
}

/// Scans multiple text strings for threats in a single call.
///
/// Returns a JSON string containing a list of scan results.
#[pyfunction]
fn scan_batch(texts: Vec<String>) -> PyResult<String> {
    let scanner = Scanner::new(None);
    let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
    let results = scanner.scan_batch(&refs);
    serde_json::to_string(&results)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("serialization failed: {}", e)))
}

/// Agent Shield Core — Python module for high-performance threat detection.
#[pymodule]
fn agent_shield_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_text, m)?)?;
    m.add_function(wrap_pyfunction!(scan_batch, m)?)?;
    Ok(())
}
