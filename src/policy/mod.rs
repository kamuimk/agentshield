//! Policy engine for AgentShield.
//!
//! This module provides the TOML-based configuration system ([`config`]) and
//! the rule evaluation engine ([`evaluator`]) that determines whether each
//! outbound request should be allowed, denied, or prompted for approval.

pub mod config;
pub mod evaluator;
