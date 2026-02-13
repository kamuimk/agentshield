//! Unified error handling for the AgentShield library.
//!
//! Uses [`thiserror`] to define a single error enum that covers all failure modes:
//! database access, I/O, config parsing, JSON serialization, proxy operations, and
//! notification delivery. Library code returns [`Result<T>`] which aliases
//! `std::result::Result<T, AgentShieldError>`.
//!
//! The binary (`main.rs`) uses [`anyhow`] for top-level error propagation.

use thiserror::Error;

/// Unified error type for the AgentShield library.
///
/// Each variant wraps an underlying error source, enabling automatic conversion
/// via `?` and preserving the original error chain for diagnostics.
#[derive(Debug, Error)]
pub enum AgentShieldError {
    /// SQLite database error (schema init, query, insert).
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// File I/O error (config read, plist write, etc.).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// TOML configuration parsing error.
    #[error("Config parse error: {0}")]
    ConfigParse(#[from] toml::de::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Proxy runtime error (connection pool, bind failure, etc.).
    #[error("Proxy error: {0}")]
    Proxy(String),

    /// Missing environment variable during config substitution.
    #[error("Config error: undefined environment variable `{0}`")]
    ConfigEnvVar(String),

    /// Notification delivery error (Telegram API failure, etc.).
    #[error("Notification error: {0}")]
    Notification(String),
}

/// Convenience type alias for `std::result::Result<T, AgentShieldError>`.
pub type Result<T> = std::result::Result<T, AgentShieldError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_converts() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: AgentShieldError = io_err.into();
        assert!(matches!(err, AgentShieldError::Io(_)));
        assert!(err.to_string().contains("IO error"));
    }

    #[test]
    fn proxy_error_displays_message() {
        let err = AgentShieldError::Proxy("connection refused".to_string());
        assert_eq!(err.to_string(), "Proxy error: connection refused");
    }

    #[test]
    fn config_parse_error_converts() {
        let bad_toml = "[invalid";
        let toml_err = toml::from_str::<toml::Value>(bad_toml).unwrap_err();
        let err: AgentShieldError = toml_err.into();
        assert!(matches!(err, AgentShieldError::ConfigParse(_)));
    }

    #[test]
    fn error_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AgentShieldError>();
    }
}
