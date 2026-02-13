use thiserror::Error;

/// Unified error type for the AgentShield library.
#[derive(Debug, Error)]
pub enum AgentShieldError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Config parse error: {0}")]
    ConfigParse(#[from] toml::de::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("Notification error: {0}")]
    Notification(String),
}

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
