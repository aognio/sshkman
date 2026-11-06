//! HTTP client adapter, token storage, and OpenSSH installer helpers for sshkma.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sshkma_crypto::{GrantWrappedKeyEnvelope, WrappedKeyEnvelope};

#[derive(Debug, Clone)]
pub struct ClientError(pub String);
impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ClientError {}

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResult {
    pub user_id: String,
    pub session_id: String,
    pub device_id: String,
    pub access_token: String,
    pub refresh_token: String,
}

pub struct VaultClient {
    pub base_url: String,
    pub access_token: Option<String>,
    http: reqwest::Client,
}

impl VaultClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: None,
            http: reqwest::Client::new(),
        }
    }

    pub fn set_token(&mut self, token: String) {
        self.access_token = Some(token);
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub async fn login(&mut self, username: &str, password: &str) -> Result<LoginResult> {
        let body = serde_json::json!({"username": username, "password": password});
        let resp = self
            .http
            .post(self.url("/api/v1/auth/login"))
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!("login failed: {}", resp.status())));
        }
        let lr: LoginResult = resp.json().await.map_err(|e| ClientError(e.to_string()))?;
        self.access_token = Some(lr.access_token.clone());
        Ok(lr)
    }

    pub async fn refresh(&mut self, refresh_token: &str) -> Result<(String, String)> {
        let body = serde_json::json!({"refresh_token": refresh_token});
        let resp = self
            .http
            .post(self.url("/api/v1/auth/refresh"))
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!("refresh failed: {}", resp.status())));
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| ClientError(e.to_string()))?;
        let a = v["access_token"].as_str().unwrap_or("").to_string();
        let r = v["refresh_token"].as_str().unwrap_or("").to_string();
        self.access_token = Some(a.clone());
        Ok((a, r))
    }

    pub async fn logout(&self, all_devices: bool) -> Result<()> {
        let token = self.access_token.clone().unwrap_or_default();
        let body = serde_json::json!({"all_devices": all_devices});
        let resp = self
            .http
            .post(self.url("/api/v1/auth/logout"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(ClientError(format!("logout failed: {}", resp.status())));
        }
        Ok(())
    }

    pub async fn vault_init(
        &self,
        wrapped_key: WrappedKeyEnvelope,
        recovery_key: WrappedKeyEnvelope,
        salt: Option<String>,
    ) -> Result<()> {
        let token = self.access_token.clone().unwrap_or_default();
        let body = serde_json::json!({
            "wrapped_key": wrapped_key,
            "recovery_key": recovery_key,
            "salt": salt,
        });
        let resp = self
            .http
            .post(self.url("/api/v1/vault/init"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(ClientError(format!("vault_init failed: {}", resp.status())));
        }
        Ok(())
    }

    pub async fn get_wrapped_key(&self) -> Result<serde_json::Value> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .get(self.url("/api/v1/vault/wrapped-key"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "get_wrapped_key failed: {}",
                resp.status()
            )));
        }
        resp.json().await.map_err(|e| ClientError(e.to_string()))
    }

    pub async fn get_manifest(&self) -> Result<(Vec<u8>, u64)> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .get(self.url("/api/v1/vault/manifest"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "get_manifest failed: {}",
                resp.status()
            )));
        }
        let rev = resp
            .headers()
            .get("x-vault-revision")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ClientError(e.to_string()))?
            .to_vec();
        Ok((bytes, rev))
    }

    pub async fn put_manifest(&self, bytes: &[u8], expected_rev: u64) -> Result<()> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .put(self.url("/api/v1/vault/manifest"))
            .bearer_auth(token)
            .header("x-vault-revision", expected_rev.to_string())
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(ClientError(format!(
                "put_manifest failed: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn list_identities(&self) -> Result<Vec<String>> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .get(self.url("/api/v1/vault/identities"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "list_identities failed: {}",
                resp.status()
            )));
        }
        resp.json().await.map_err(|e| ClientError(e.to_string()))
    }

    pub async fn upload_identity(&self, identity_id: &str, ciphertext: &[u8]) -> Result<()> {
        let token = self.access_token.clone().unwrap_or_default();
        let body = serde_json::json!({
            "identity_id": identity_id,
            "ciphertext": B64.encode(ciphertext),
        });
        let resp = self
            .http
            .post(self.url("/api/v1/vault/identities"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(ClientError(format!(
                "upload_identity failed: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn download_identity(&self, identity_id: &str) -> Result<Vec<u8>> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .get(self.url(&format!("/api/v1/vault/identities/{}", identity_id)))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "download_identity failed: {}",
                resp.status()
            )));
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| ClientError(e.to_string()))?;
        let b64 = v["ciphertext"].as_str().unwrap_or("");
        B64.decode(b64).map_err(|e| ClientError(e.to_string()))
    }

    pub async fn delete_identity(&self, identity_id: &str) -> Result<()> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .delete(self.url(&format!("/api/v1/vault/identities/{}", identity_id)))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(ClientError(format!(
                "delete_identity failed: {}",
                resp.status()
            )));
        }
        Ok(())
    }
    pub async fn set_grant_key(&self, public_key: &str) -> Result<()> {
        let token = self.access_token.clone().unwrap_or_default();
        let body = serde_json::json!({"public_key": public_key});
        let resp = self
            .http
            .put(self.url("/api/v1/account/grant-key"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(ClientError(format!(
                "set_grant_key failed: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn get_grant_key(&self, username: &str) -> Result<String> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .get(self.url(&format!("/api/v1/users/{}/grant-key", username)))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "get_grant_key failed: {}",
                resp.status()
            )));
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| ClientError(e.to_string()))?;
        Ok(v["public_key"].as_str().unwrap_or("").to_string())
    }

    pub async fn create_grant(
        &self,
        grantee_username: &str,
        permissions: Vec<String>,
        wrapped_key: GrantWrappedKeyEnvelope,
        grantee_public_key: Option<String>,
        expires_at: Option<u64>,
    ) -> Result<String> {
        let token = self.access_token.clone().unwrap_or_default();
        let body = serde_json::json!({
            "grantee_username": grantee_username,
            "permissions": permissions,
            "wrapped_key": wrapped_key,
            "grantee_public_key": grantee_public_key,
            "expires_at": expires_at,
        });
        let resp = self
            .http
            .post(self.url("/api/v1/grants"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "create_grant failed: {}",
                resp.status()
            )));
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| ClientError(e.to_string()))?;
        Ok(v["grant_id"].as_str().unwrap_or("").to_string())
    }

    pub async fn list_grants(&self) -> Result<Vec<serde_json::Value>> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .get(self.url("/api/v1/grants"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "list_grants failed: {}",
                resp.status()
            )));
        }
        resp.json().await.map_err(|e| ClientError(e.to_string()))
    }

    pub async fn revoke_grant(&self, grant_id: &str) -> Result<()> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .delete(self.url(&format!("/api/v1/grants/{}", grant_id)))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(ClientError(format!(
                "revoke_grant failed: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn get_grant_wrapped_key(&self, grant_id: &str) -> Result<serde_json::Value> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .get(self.url(&format!("/api/v1/grants/{}/wrapped-key", grant_id)))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "get_grant_wrapped_key failed: {}",
                resp.status()
            )));
        }
        resp.json().await.map_err(|e| ClientError(e.to_string()))
    }
    pub async fn register(
        &self,
        invite_code: &str,
        username: &str,
        password: &str,
    ) -> Result<String> {
        let body = serde_json::json!({
            "invite_code": invite_code,
            "username": username,
            "password": password,
        });
        let resp = self
            .http
            .post(self.url("/api/v1/auth/register"))
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!("register failed: {}", resp.status())));
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| ClientError(e.to_string()))?;
        Ok(v["user_id"].as_str().unwrap_or("").to_string())
    }

    pub async fn create_invite(
        &self,
        ttl_secs: u64,
        role: Option<String>,
    ) -> Result<(String, u64)> {
        let token = self.access_token.clone().unwrap_or_default();
        let body = serde_json::json!({"ttl_secs": ttl_secs, "role": role});
        let resp = self
            .http
            .post(self.url("/api/v1/invites"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "create_invite failed: {}",
                resp.status()
            )));
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| ClientError(e.to_string()))?;
        Ok((
            v["code"].as_str().unwrap_or("").to_string(),
            v["expires_at"].as_u64().unwrap_or(0),
        ))
    }

    pub async fn list_invites(&self) -> Result<Vec<serde_json::Value>> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .get(self.url("/api/v1/invites"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "list_invites failed: {}",
                resp.status()
            )));
        }
        resp.json().await.map_err(|e| ClientError(e.to_string()))
    }

    pub async fn revoke_invite(&self, code: &str) -> Result<()> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .delete(self.url(&format!("/api/v1/invites/{}", code.replace('-', ""))))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(ClientError(format!(
                "revoke_invite failed: {}",
                resp.status()
            )));
        }
        Ok(())
    }
    pub async fn admin_users_list(&self) -> Result<Vec<serde_json::Value>> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .get(self.url("/api/v1/admin/users"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "admin_users_list failed: {}",
                resp.status()
            )));
        }
        resp.json().await.map_err(|e| ClientError(e.to_string()))
    }

    pub async fn admin_overview(&self) -> Result<serde_json::Value> {
        let token = self.access_token.clone().unwrap_or_default();
        let resp = self
            .http
            .get(self.url("/api/v1/admin/overview"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ClientError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ClientError(format!(
                "admin_overview failed: {}",
                resp.status()
            )));
        }
        resp.json().await.map_err(|e| ClientError(e.to_string()))
    }
}

// Token storage helpers (TOML fallback)
#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub struct TokenStore {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

pub fn save_token_store(path: &std::path::Path, store: &TokenStore) -> Result<()> {
    let s = toml::to_string_pretty(store).map_err(|e| ClientError(e.to_string()))?;
    sshkma_storage::atomic_write(path, s.as_bytes()).map_err(|e| ClientError(e.to_string()))?;
    Ok(())
}

pub fn load_token_store(path: &std::path::Path) -> Result<TokenStore> {
    if !path.exists() {
        return Ok(TokenStore::default());
    }
    let s = std::fs::read_to_string(path).map_err(|e| ClientError(e.to_string()))?;
    toml::from_str(&s).map_err(|e| ClientError(e.to_string()))
}

// Re-export storage
pub use sshkma_storage;
