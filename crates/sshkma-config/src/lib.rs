//! TOML configuration models and validation for sshkma client and server.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ConfigError {
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("serialization error: {0}")]
    Serialize(String),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthStorage {
    #[default]
    Keyring,
    Toml,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VaultConfig {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub storage: AuthStorage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshPathsConfig {
    #[serde(default = "default_config_dir")]
    pub config_dir: String,
    #[serde(default = "default_managed_dir")]
    pub managed_dir: String,
    #[serde(default = "default_keys_dir")]
    pub keys_dir: String,
}

fn default_config_dir() -> String {
    "~/.ssh".into()
}
fn default_managed_dir() -> String {
    "~/.ssh/managed".into()
}
fn default_keys_dir() -> String {
    "~/.ssh/keys".into()
}

impl Default for SshPathsConfig {
    fn default() -> Self {
        Self {
            config_dir: default_config_dir(),
            managed_dir: default_managed_dir(),
            keys_dir: default_keys_dir(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub vault: VaultConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub ssh: SshPathsConfig,
}

fn default_version() -> u32 {
    1
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            version: 1,
            vault: VaultConfig::default(),
            auth: AuthConfig::default(),
            ssh: SshPathsConfig::default(),
        }
    }
}

impl ClientConfig {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }
    pub fn from_toml_str(s: &str) -> Result<Self> {
        Self::from_str(s)
    }
    pub fn parse(s: &str) -> Result<Self> {
        Self::from_str(s)
    }
    pub fn to_string_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::Serialize(e.to_string()))
    }
    pub fn to_toml_string(&self) -> Result<String> {
        self.to_string_toml()
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(ConfigError::Invalid("version must be 1".into()));
        }
        if let Some(url) = &self.vault.url {
            if !(url.starts_with("https://")
                || url.starts_with("http://localhost")
                || url.starts_with("http://127.0.0.1"))
            {
                return Err(ConfigError::Invalid("vault url must use https".into()));
            }
        }
        if self.ssh.config_dir.is_empty()
            || self.ssh.managed_dir.is_empty()
            || self.ssh.keys_dir.is_empty()
        {
            return Err(ConfigError::Invalid("ssh paths must not be empty".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSection {
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_listen")]
    pub listen_address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_public_url")]
    pub public_url: String,
}

fn default_public_url() -> String {
    "https://localhost:8080".into()
}

fn default_hostname() -> String {
    "localhost".into()
}
fn default_listen() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8080
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            hostname: default_hostname(),
            listen_address: default_listen(),
            port: default_port(),
            public_url: default_public_url(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSection {
    #[serde(default = "default_storage_root")]
    pub root: String,
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            root: default_storage_root(),
        }
    }
}

fn default_storage_root() -> String {
    "/var/lib/sshkmad".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSection {
    #[serde(default = "default_access_ttl")]
    pub access_ttl: String,
    #[serde(default = "default_refresh_ttl")]
    pub refresh_ttl: String,
    #[serde(default = "default_secret_file")]
    pub secret_file: String,
}

fn default_access_ttl() -> String {
    "15m".into()
}
fn default_refresh_ttl() -> String {
    "720h".into()
}
fn default_secret_file() -> String {
    "/etc/sshkma/secrets/session.key".into()
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            access_ttl: default_access_ttl(),
            refresh_ttl: default_refresh_ttl(),
            secret_file: default_secret_file(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_file")]
    pub file: String,
    #[serde(default = "default_security_file")]
    pub security_file: String,
    #[serde(default = "default_rotation")]
    pub rotation: String,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
}

fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "logfmt".into()
}
fn default_log_file() -> String {
    "/var/log/sshkmad/sshkmad.log".into()
}
fn default_security_file() -> String {
    "/var/log/sshkmad/security.log".into()
}
fn default_rotation() -> String {
    "daily".into()
}
fn default_retention() -> u32 {
    30
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            file: default_log_file(),
            security_file: default_security_file(),
            rotation: default_rotation(),
            retention_days: default_retention(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecuritySection {
    #[serde(default = "default_require_https")]
    pub require_https: bool,
    #[serde(default = "default_max_login")]
    pub max_login_attempts: u32,
}

fn default_require_https() -> bool {
    true
}
fn default_max_login() -> u32 {
    5
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            require_https: default_require_https(),
            max_login_attempts: default_max_login(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServerConfig {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub storage: StorageSection,
    #[serde(default)]
    pub auth: AuthSection,
    #[serde(default)]
    pub logging: LoggingSection,
    #[serde(default)]
    pub security: SecuritySection,
}

impl ServerConfig {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }
    pub fn from_toml_str(s: &str) -> Result<Self> {
        Self::from_str(s)
    }
    pub fn parse(s: &str) -> Result<Self> {
        Self::from_str(s)
    }
    pub fn to_string_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::Serialize(e.to_string()))
    }
    pub fn to_toml_string(&self) -> Result<String> {
        self.to_string_toml()
    }
    pub fn validate(&self) -> Result<()> {
        if self.server.public_url.is_empty() {
            return Err(ConfigError::Invalid("public_url must not be empty".into()));
        }
        if self.security.require_https && self.server.public_url.starts_with("http://") {
            let host = self
                .server
                .public_url
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("");
            let host = host.split(':').next().unwrap_or("");
            if host != "localhost" && host != "127.0.0.1" {
                return Err(ConfigError::Invalid(
                    "require_https forbids http public_url".into(),
                ));
            }
        }
        if self.storage.root.is_empty() {
            return Err(ConfigError::Invalid(
                "storage root must not be empty".into(),
            ));
        }
        Ok(())
    }
}

pub fn default_client_config_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("sshkma").join("config.toml"));
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return Some(
                home.join("Library")
                    .join("Application Support")
                    .join("sshkma")
                    .join("config.toml"),
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = dirs::config_dir() {
            return Some(appdata.join("sshkma").join("config.toml"));
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Some(home) = dirs::home_dir() {
            return Some(home.join(".config").join("sshkma").join("config.toml"));
        }
    }
    dirs::config_dir().map(|d| d.join("sshkma").join("config.toml"))
}

pub fn default_server_config_path() -> PathBuf {
    PathBuf::from("/etc/sshkma/sshkmad.toml")
}
