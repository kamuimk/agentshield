//! Synthetic payloads for the four bounded-inspection blind spots.
use base64::{Engine as _, engine::general_purpose::STANDARD};
pub fn bodies() -> Vec<String> {
    let key = "sk-proj-SYNTHETICNOTAREALKEY000000000000000000000000";
    let oversized = STANDARD.encode("ordinary harmless prose ".repeat(4096) + key);
    let candidates = "ordinary ".repeat(2049) + &STANDARD.encode(key);
    let prefix = (STANDARD.encode(vec![b'a'; 48 * 1024]) + " ").repeat(21);
    let output = prefix + &STANDARD.encode("ordinary harmless prose ".repeat(1024) + key);
    let mut nested = key.to_string();
    for _ in 0..3 {
        nested = STANDARD.encode(nested);
    }
    vec![oversized, candidates, output, nested]
}
