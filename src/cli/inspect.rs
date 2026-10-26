//! Bounded offline inspection, sharing the proxy's existing scanner.
//!
//! Input is stdin only. Output never includes findings, offsets, snippets,
//! filenames, a content hash or any caller-supplied string. A successful report
//! means the bounded pattern scan ran, not that arbitrary content is safe.
use std::collections::BTreeSet;
use std::io::{Read, Write};

use crate::dlp::{DlpScanner, patterns::RegexScanner};
use serde::Serialize;
use zeroize::Zeroizing;

pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("inspection_failed")]
pub struct InspectionError;

#[derive(Serialize)]
struct Report {
    version: u8,
    bytes: usize,
    categories: BTreeSet<String>,
}

/// Read at most limit+1 bytes, reject over-limit/failed reads, and return one
/// deterministic category-only report. The caller must enforce an I/O deadline
/// and close stdin: no library can infer EOF from a producer holding its pipe.
pub fn run(input: impl Read, mut output: impl Write) -> Result<(), InspectionError> {
    let mut payload = Zeroizing::new(Vec::new());
    input
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut payload)
        .map_err(|_| InspectionError)?;
    if payload.len() > MAX_INPUT_BYTES {
        return Err(InspectionError);
    }
    let categories = RegexScanner::new()
        .scan(&payload)
        .into_iter()
        .map(|finding| finding.pattern_name)
        .collect();
    let report = Report {
        version: 1,
        bytes: payload.len(),
        categories,
    };
    // Serialize only the fixed projection, never DlpFinding or the raw input.
    let mut encoded = serde_json::to_vec(&report).map_err(|_| InspectionError)?;
    encoded.push(b'\n');
    output.write_all(&encoded).map_err(|_| InspectionError)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn errors_never_produce_a_success_report_or_echo_io_messages() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("synthetic-private-value"))
            }
        }
        let mut out = Vec::new();
        let error = run(Broken, &mut out).unwrap_err();
        assert!(out.is_empty());
        assert_eq!(error.to_string(), "inspection_failed");
        assert!(run(&vec![b'x'; MAX_INPUT_BYTES + 1][..], &mut out).is_err());
        assert!(out.is_empty());
    }
    #[test]
    fn empty_and_maximum_input_are_supported() {
        for input in [Vec::new(), vec![b'!'; MAX_INPUT_BYTES]] {
            let mut out = Vec::new();
            run(&input[..], &mut out).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(
                value,
                serde_json::json!({"version":1,"bytes":input.len(),"categories":[]})
            );
        }
    }
}
