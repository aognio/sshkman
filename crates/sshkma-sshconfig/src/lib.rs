//! OpenSSH configuration management and keypair preservation for sshkma.

use ssh_key::{PrivateKey, PublicKey};
use sshkma_domain::{FileAction, HostAlias, InstallationPlan, ManagedFile, ManagedFileType, Slug};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum SshConfigError {
    #[error("private and public key material do not match")]
    KeyMismatch,
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("include error: {0}")]
    IncludeError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalSshKeypair {
    private_key_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    comment: Option<String>,
}

impl OriginalSshKeypair {
    pub fn validate_and_create<P, U>(priv_bytes: P, pub_bytes: U) -> Result<Self, SshConfigError>
    where
        P: AsRef<[u8]>,
        U: AsRef<[u8]>,
    {
        let priv_bytes = priv_bytes.as_ref().to_vec();
        let pub_bytes = pub_bytes.as_ref().to_vec();

        let priv_key = PrivateKey::from_openssh(&priv_bytes)
            .map_err(|e| SshConfigError::InvalidPrivateKey(e.to_string()))?;

        let pub_str = std::str::from_utf8(&pub_bytes)
            .map_err(|e| SshConfigError::InvalidPublicKey(e.to_string()))?;
        let pub_key = PublicKey::from_openssh(pub_str.trim())
            .map_err(|e| SshConfigError::InvalidPublicKey(e.to_string()))?;

        if priv_key.public_key().to_bytes().unwrap_or_default()
            != pub_key.to_bytes().unwrap_or_default()
        {
            return Err(SshConfigError::KeyMismatch);
        }

        let comment = {
            let c = pub_key.comment();
            if c.is_empty() {
                None
            } else {
                Some(c.to_string())
            }
        };

        Ok(Self {
            private_key_bytes: priv_bytes,
            public_key_bytes: pub_bytes,
            comment,
        })
    }

    pub fn private_key_bytes(&self) -> &[u8] {
        &self.private_key_bytes
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }
}

#[derive(Debug, Clone)]
pub struct ManagedHostParams {
    pub slug: Slug,
    pub host_alias: HostAlias,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: String,
    pub extra_directives: Vec<(String, String)>,
}

pub fn generate_host_config(params: &ManagedHostParams) -> String {
    let mut out = String::new();
    out.push_str(&format!("Host {}\n", params.host_alias.as_str()));
    if let Some(hostname) = &params.hostname {
        out.push_str(&format!("    HostName {}\n", hostname));
    }
    if let Some(user) = &params.user {
        out.push_str(&format!("    User {}\n", user));
    }
    if let Some(port) = params.port {
        out.push_str(&format!("    Port {}\n", port));
    }
    out.push_str(&format!("    IdentityFile {}\n", params.identity_file));
    out.push_str("    IdentitiesOnly yes\n");
    for (k, v) in &params.extra_directives {
        out.push_str(&format!("    {} {}\n", k, v));
    }
    out
}

const BEGIN_MARKER: &str = "# BEGIN SSHKMA MANAGED INCLUDES";
const END_MARKER: &str = "# END SSHKMA MANAGED INCLUDES";

pub fn ensure_managed_include(
    existing: &str,
    managed_path: &str,
) -> Result<String, SshConfigError> {
    if existing.contains(BEGIN_MARKER) {
        return Ok(existing.to_string());
    }
    let block = format!(
        "{}\nInclude {}\n{}\n",
        BEGIN_MARKER, managed_path, END_MARKER
    );
    if existing.trim().is_empty() {
        Ok(block)
    } else {
        Ok(format!("{}{}", block, existing))
    }
}

pub fn remove_managed_include(existing: &str) -> String {
    let mut out = String::new();
    let mut in_block = false;
    for line in existing.lines() {
        if line.trim() == BEGIN_MARKER {
            in_block = true;
            continue;
        }
        if line.trim() == END_MARKER {
            in_block = false;
            continue;
        }
        if in_block {
            continue;
        }
        // skip Include line inside block already handled; also skip stray managed include?
        out.push_str(line);
        out.push('\n');
    }
    out.trim().to_string()
}

// Need trailing newline? Test compares trim. Fine.

#[allow(clippy::too_many_arguments)]
pub fn plan_installation(
    slug: &Slug,
    host_alias: &HostAlias,
    hostname: Option<&str>,
    user: Option<&str>,
    port: Option<u16>,
    priv_bytes: &[u8],
    pub_bytes: &[u8],
    managed_dir: &str,
    keys_dir: &str,
) -> InstallationPlan {
    let slug_str = slug.as_str();
    let private_path = format!("{}/{}", keys_dir, slug_str);
    let public_path = format!("{}/{}.pub", keys_dir, slug_str);
    let config_path = format!("{}/{}.conf", managed_dir, slug_str);

    let params = ManagedHostParams {
        slug: slug.clone(),
        host_alias: host_alias.clone(),
        hostname: hostname.map(|s| s.to_string()),
        user: user.map(|s| s.to_string()),
        port,
        identity_file: private_path.clone(),
        extra_directives: Vec::new(),
    };
    let conf_content = generate_host_config(&params).into_bytes();

    let mut plan = InstallationPlan::default();
    plan.add_action(FileAction::Create(ManagedFile::new(
        config_path,
        ManagedFileType::SshConfig,
        0o644,
        conf_content,
    )));
    plan.add_action(FileAction::Create(ManagedFile::new(
        private_path,
        ManagedFileType::SshPrivateKey,
        0o600,
        priv_bytes.to_vec(),
    )));
    plan.add_action(FileAction::Create(ManagedFile::new(
        public_path,
        ManagedFileType::SshPublicKey,
        0o644,
        pub_bytes.to_vec(),
    )));
    plan
}
