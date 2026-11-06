//! Axum HTTP API and server-side application services for sshkmad.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sshkma_auth::{generate_token, hash_password, hash_token, verify_password};
use sshkma_crypto::WrappedKeyEnvelope;
use sshkma_domain::{IdentityId, UserId};
use sshkma_storage::{atomic_write, ensure_dir, read_file};
use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct AppState {
    pub storage_root: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io error: {0}")]
    Io(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("auth error: {0}")]
    Auth(String),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            ServerError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ServerError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            ServerError::Conflict(m) => (StatusCode::CONFLICT, m),
            ServerError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ServerError::Auth(m) => (StatusCode::UNAUTHORIZED, m),
            ServerError::Io(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(serde_json::json!({"error": msg}))).into_response()
    }
}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        ServerError::Io(e.to_string())
    }
}

// ---------- Filesystem layout helpers ----------

fn users_dir(root: &Path) -> PathBuf {
    root.join("users")
}
fn user_dir(root: &Path, user_id: &str) -> PathBuf {
    users_dir(root).join(user_id)
}
fn account_path(root: &Path, user_id: &str) -> PathBuf {
    user_dir(root, user_id).join("account.toml")
}
fn vault_path(root: &Path, user_id: &str) -> PathBuf {
    user_dir(root, user_id).join("vault.toml")
}
fn identities_dir(root: &Path, user_id: &str) -> PathBuf {
    user_dir(root, user_id).join("identities")
}

fn grants_dir(root: &Path, user_id: &str) -> PathBuf {
    user_dir(root, user_id).join("grants")
}
fn grant_path(root: &Path, grantee_user_id: &str, grant_id: &str) -> PathBuf {
    grants_dir(root, grantee_user_id).join(format!("{}.toml", grant_id))
}

pub fn load_account(root: &Path, user_id: &str) -> Result<AccountRecord, ServerError> {
    let s = fs::read_to_string(account_path(root, user_id))?;
    toml::from_str(&s).map_err(|e| ServerError::Io(e.to_string()))
}

pub fn save_account(root: &Path, user_id: &str, acc: &AccountRecord) -> Result<(), ServerError> {
    let toml_str = toml::to_string_pretty(acc).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&account_path(root, user_id), toml_str.as_bytes())
        .map_err(|e| ServerError::Io(e.to_string()))
}

pub fn list_grants(root: &Path, grantee_user_id: &str) -> Result<Vec<VaultGrant>, ServerError> {
    let dir = grants_dir(root, grantee_user_id);
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(&dir).map_err(|e| ServerError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| ServerError::Io(e.to_string()))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            if let Ok(s) = fs::read_to_string(&path) {
                if let Ok(g) = toml::from_str::<VaultGrant>(&s) {
                    out.push(g);
                }
            }
        }
    }
    Ok(out)
}

pub fn save_grant(root: &Path, grant: &VaultGrant) -> Result<(), ServerError> {
    let dir = grants_dir(root, &grant.grantee_user_id);
    ensure_dir(&dir).map_err(|e| ServerError::Io(e.to_string()))?;
    let toml_str = toml::to_string_pretty(grant).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(
        &grant_path(root, &grant.grantee_user_id, &grant.grant_id),
        toml_str.as_bytes(),
    )
    .map_err(|e| ServerError::Io(e.to_string()))
}

pub fn revoke_grant(root: &Path, grantee_user_id: &str, grant_id: &str) -> Result<(), ServerError> {
    let p = grant_path(root, grantee_user_id, grant_id);
    if !p.exists() {
        return Err(ServerError::NotFound("grant".into()));
    }
    let s = fs::read_to_string(&p)?;
    let mut g: VaultGrant = toml::from_str(&s).map_err(|e| ServerError::Io(e.to_string()))?;
    g.revoked = true;
    let toml_str = toml::to_string_pretty(&g).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&p, toml_str.as_bytes()).map_err(|e| ServerError::Io(e.to_string()))
}
fn identity_path(root: &Path, user_id: &str, id: &str) -> PathBuf {
    identities_dir(root, user_id).join(format!("{}.enc", id))
}
fn manifest_path(root: &Path, user_id: &str) -> PathBuf {
    user_dir(root, user_id).join("manifest.enc")
}
fn devices_dir(root: &Path) -> PathBuf {
    root.join("devices")
}
fn device_path(root: &Path, device_id: &str) -> PathBuf {
    devices_dir(root).join(format!("{}.toml", device_id))
}
fn sessions_dir(root: &Path) -> PathBuf {
    root.join("sessions")
}
fn session_path(root: &Path, session_id: &str) -> PathBuf {
    sessions_dir(root).join(format!("{}.toml", session_id))
}
fn index_path(root: &Path) -> PathBuf {
    users_dir(root).join("_index.toml")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------- Records ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[default]
    Reader,
    Admin,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Reader => write!(f, "reader"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AccountRecord {
    pub user_id: String,
    pub username: String,
    pub password_hash: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub role: Role,
    #[serde(default)]
    pub grant_public_key: Option<String>, // hex X25519 public key
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultGrant {
    pub grant_id: String,
    pub grantor_user_id: String,
    pub grantee_user_id: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub wrapped_vmk: sshkma_crypto::GrantWrappedKeyEnvelope,
    #[serde(default)]
    pub grantee_public_key: Option<String>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Serialize)]
pub struct AdminUserView {
    pub username: String,
    pub user_id: String,
    pub role: String,
    pub disabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InviteRecord {
    pub code: String,
    pub created_by: String,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub used_by: Option<String>,
    #[serde(default)]
    pub used_at: Option<u64>,
    #[serde(default)]
    pub role: Role,
}

fn invites_dir(root: &Path) -> PathBuf {
    root.join("invites")
}
fn invite_path(root: &Path, code: &str) -> PathBuf {
    let safe = code.replace('-', "");
    invites_dir(root).join(format!("{}.toml", safe))
}

pub fn generate_invite_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let a: u32 = rng.gen_range(0..10000);
    let b: u32 = rng.gen_range(0..10000);
    format!("{:04}-{:04}", a, b)
}

pub fn create_invite(
    root: &Path,
    created_by: &str,
    ttl_secs: u64,
    role: Role,
) -> Result<InviteRecord, ServerError> {
    ensure_dir(&invites_dir(root)).map_err(|e| ServerError::Io(e.to_string()))?;
    let code = generate_invite_code();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let inv = InviteRecord {
        code: code.clone(),
        created_by: created_by.to_string(),
        created_at: now,
        expires_at: now + ttl_secs,
        used_by: None,
        used_at: None,
        role,
    };
    let toml_str = toml::to_string_pretty(&inv).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&invite_path(root, &code), toml_str.as_bytes())
        .map_err(|e| ServerError::Io(e.to_string()))?;
    Ok(inv)
}

pub fn redeem_invite(
    root: &Path,
    code: &str,
    username: &str,
    password: &str,
) -> Result<UserId, ServerError> {
    let path = invite_path(root, code);
    if !path.exists() {
        return Err(ServerError::NotFound("invite".into()));
    }
    let s = fs::read_to_string(&path).map_err(|e| ServerError::Io(e.to_string()))?;
    let mut inv: InviteRecord = toml::from_str(&s).map_err(|e| ServerError::Io(e.to_string()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now > inv.expires_at {
        return Err(ServerError::BadRequest("invite expired".into()));
    }
    if inv.used_by.is_some() {
        return Err(ServerError::Conflict("invite already used".into()));
    }
    // create user with role
    ensure_dir(&users_dir(root)).map_err(|e| ServerError::Io(e.to_string()))?;
    let mut idx = load_index(root);
    if idx.contains_key(username) {
        return Err(ServerError::Conflict("username exists".into()));
    }
    let user_id = UserId::new();
    let hash = hash_password(&secrecy::SecretString::from(password.to_string()))
        .map_err(|e| ServerError::Auth(e.to_string()))?;
    let account = AccountRecord {
        user_id: user_id.as_str().to_string(),
        username: username.to_string(),
        password_hash: hash,
        disabled: false,
        role: inv.role,
        grant_public_key: None,
    };
    let dir = user_dir(root, user_id.as_str());
    ensure_dir(&dir).map_err(|e| ServerError::Io(e.to_string()))?;
    ensure_dir(&identities_dir(root, user_id.as_str()))
        .map_err(|e| ServerError::Io(e.to_string()))?;
    let toml_str = toml::to_string_pretty(&account).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&account_path(root, user_id.as_str()), toml_str.as_bytes())
        .map_err(|e| ServerError::Io(e.to_string()))?;
    let vault = VaultRecord::default();
    let vstr = toml::to_string_pretty(&vault).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&vault_path(root, user_id.as_str()), vstr.as_bytes())
        .map_err(|e| ServerError::Io(e.to_string()))?;
    idx.insert(username.to_string(), user_id.as_str().to_string());
    save_index(root, &idx)?;
    // mark used
    inv.used_by = Some(user_id.as_str().to_string());
    inv.used_at = Some(now);
    let toml_str = toml::to_string_pretty(&inv).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&path, toml_str.as_bytes()).map_err(|e| ServerError::Io(e.to_string()))?;
    Ok(user_id)
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VaultRecord {
    pub wrapped_key: Option<WrappedKeyEnvelope>,
    pub recovery_key: Option<WrappedKeyEnvelope>,
    pub salt: Option<String>,
    pub revision: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceRecord {
    pub device_id: String,
    pub user_id: String,
    pub name: String,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionRecord {
    pub session_id: String,
    pub user_id: String,
    pub device_id: String,
    pub access_token_hash: String,
    pub refresh_token_hash: String,
    pub access_expires_at: u64,
    pub refresh_expires_at: u64,
    pub revoked: bool,
}

// ---------- Index ----------

fn load_index(root: &Path) -> BTreeMap<String, String> {
    let p = index_path(root);
    if !p.exists() {
        return BTreeMap::new();
    }
    fs::read_to_string(&p)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_index(root: &Path, idx: &BTreeMap<String, String>) -> Result<(), ServerError> {
    ensure_dir(&users_dir(root)).map_err(|e| ServerError::Io(e.to_string()))?;
    let s = toml::to_string_pretty(idx).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&index_path(root), s.as_bytes()).map_err(|e| ServerError::Io(e.to_string()))?;
    Ok(())
}

// ---------- Public admin helpers ----------

pub fn create_user(root: &Path, username: &str, password: &str) -> Result<UserId, ServerError> {
    ensure_dir(&users_dir(root)).map_err(|e| ServerError::Io(e.to_string()))?;
    let mut idx = load_index(root);
    if idx.contains_key(username) {
        return Err(ServerError::Conflict("username exists".into()));
    }
    let user_id = UserId::new();
    let hash = hash_password(&secrecy::SecretString::from(password.to_string()))
        .map_err(|e| ServerError::Auth(e.to_string()))?;
    let account = AccountRecord {
        user_id: user_id.as_str().to_string(),
        username: username.to_string(),
        password_hash: hash,
        disabled: false,
        role: Role::Admin,
        grant_public_key: None,
    };
    let dir = user_dir(root, user_id.as_str());
    ensure_dir(&dir).map_err(|e| ServerError::Io(e.to_string()))?;
    ensure_dir(&identities_dir(root, user_id.as_str()))
        .map_err(|e| ServerError::Io(e.to_string()))?;
    let toml_str = toml::to_string_pretty(&account).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&account_path(root, user_id.as_str()), toml_str.as_bytes())
        .map_err(|e| ServerError::Io(e.to_string()))?;
    let vault = VaultRecord::default();
    let vstr = toml::to_string_pretty(&vault).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&vault_path(root, user_id.as_str()), vstr.as_bytes())
        .map_err(|e| ServerError::Io(e.to_string()))?;
    idx.insert(username.to_string(), user_id.as_str().to_string());
    save_index(root, &idx)?;
    Ok(user_id)
}

fn find_user_by_username(root: &Path, username: &str) -> Result<AccountRecord, ServerError> {
    let idx = load_index(root);
    let uid = idx
        .get(username)
        .ok_or(ServerError::NotFound("user".into()))?;
    let s = fs::read_to_string(account_path(root, uid))?;
    let acc: AccountRecord = toml::from_str(&s).map_err(|e| ServerError::Io(e.to_string()))?;
    Ok(acc)
}

fn load_vault(root: &Path, user_id: &str) -> Result<VaultRecord, ServerError> {
    let p = vault_path(root, user_id);
    if !p.exists() {
        return Ok(VaultRecord::default());
    }
    let s = fs::read_to_string(&p)?;
    toml::from_str(&s).map_err(|e| ServerError::Io(e.to_string()))
}

fn save_vault(root: &Path, user_id: &str, v: &VaultRecord) -> Result<(), ServerError> {
    let s = toml::to_string_pretty(v).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&vault_path(root, user_id), s.as_bytes())
        .map_err(|e| ServerError::Io(e.to_string()))?;
    Ok(())
}

fn authenticate(root: &Path, token: &str) -> Result<SessionRecord, ServerError> {
    let token_hash = hash_token(token);
    // scan sessions
    let dir = sessions_dir(root);
    if !dir.exists() {
        return Err(ServerError::Unauthorized);
    }
    for entry in fs::read_dir(&dir).map_err(|e| ServerError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| ServerError::Io(e.to_string()))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let s = fs::read_to_string(&path).map_err(|e| ServerError::Io(e.to_string()))?;
        let sess: SessionRecord = match toml::from_str(&s) {
            Ok(x) => x,
            Err(_) => continue,
        };
        if sess.access_token_hash == token_hash && !sess.revoked {
            if sess.access_expires_at < now_secs() {
                return Err(ServerError::Unauthorized);
            }
            return Ok(sess);
        }
    }
    Err(ServerError::Unauthorized)
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get("authorization")?.to_str().ok()?;
    let v = v.trim();
    v.strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
        .map(|rest| rest.to_string())
}

// ---------- Request/Response types ----------

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
    #[serde(default)]
    device_name: Option<String>,
}

#[derive(Serialize)]
struct LoginResp {
    user_id: String,
    session_id: String,
    device_id: String,
    access_token: String,
    refresh_token: String,
}

#[derive(Deserialize)]
struct RefreshReq {
    refresh_token: String,
}

#[derive(Deserialize)]
struct LogoutReq {
    #[serde(default)]
    all_devices: bool,
}

#[derive(Deserialize)]
struct RegisterReq {
    invite_code: String,
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct InviteCreateReq {
    #[serde(default = "default_ttl")]
    ttl_secs: u64,
    #[serde(default)]
    role: Option<String>,
}
fn default_ttl() -> u64 {
    3600
}

#[derive(Deserialize)]
struct GrantKeyReq {
    public_key: String,
}

#[derive(Deserialize)]
struct GrantCreateReq {
    grantee_username: String,
    #[serde(default)]
    permissions: Vec<String>,
    wrapped_key: sshkma_crypto::GrantWrappedKeyEnvelope,
    #[serde(default)]
    grantee_public_key: Option<String>,
    #[serde(default)]
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct VaultInitReq {
    wrapped_key: WrappedKeyEnvelope,
    recovery_key: WrappedKeyEnvelope,
    #[serde(default)]
    salt: Option<String>,
}

#[derive(Deserialize)]
struct IdentityUploadReq {
    identity_id: String,
    ciphertext: String, // base64
}

// ---------- Handlers ----------

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}
async fn ready() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ready"}))
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginReq>,
) -> Result<Json<LoginResp>, ServerError> {
    let root = &state.storage_root;
    let account = find_user_by_username(root, &req.username)?;
    if account.disabled {
        return Err(ServerError::Auth("account disabled".into()));
    }
    let ok = verify_password(
        &secrecy::SecretString::from(req.password.clone()),
        &account.password_hash,
    )
    .map_err(|e| ServerError::Auth(e.to_string()))?;
    if !ok {
        return Err(ServerError::Auth("invalid credentials".into()));
    }

    ensure_dir(&devices_dir(root)).map_err(|e| ServerError::Io(e.to_string()))?;
    ensure_dir(&sessions_dir(root)).map_err(|e| ServerError::Io(e.to_string()))?;

    let device_id = sshkma_domain::DeviceId::new();
    let device = DeviceRecord {
        device_id: device_id.as_str().to_string(),
        user_id: account.user_id.clone(),
        name: req.device_name.clone().unwrap_or_else(|| "device".into()),
        created_at: now_secs(),
    };
    let dtoml = toml::to_string_pretty(&device).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&device_path(root, device_id.as_str()), dtoml.as_bytes())
        .map_err(|e| ServerError::Io(e.to_string()))?;

    let session_id = sshkma_domain::SessionId::new();
    let access_token = generate_token();
    let refresh_token = generate_token();
    let sess = SessionRecord {
        session_id: session_id.as_str().to_string(),
        user_id: account.user_id.clone(),
        device_id: device_id.as_str().to_string(),
        access_token_hash: hash_token(&access_token),
        refresh_token_hash: hash_token(&refresh_token),
        access_expires_at: now_secs() + 15 * 60,
        refresh_expires_at: now_secs() + 30 * 24 * 60 * 60,
        revoked: false,
    };
    let stoml = toml::to_string_pretty(&sess).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(&session_path(root, session_id.as_str()), stoml.as_bytes())
        .map_err(|e| ServerError::Io(e.to_string()))?;

    Ok(Json(LoginResp {
        user_id: account.user_id,
        session_id: session_id.as_str().to_string(),
        device_id: device_id.as_str().to_string(),
        access_token,
        refresh_token,
    }))
}

async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshReq>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let root = &state.storage_root;
    let refresh_hash = hash_token(&req.refresh_token);
    // find session
    let dir = sessions_dir(root);
    let mut found: Option<SessionRecord> = None;
    let mut found_path: Option<PathBuf> = None;
    if dir.exists() {
        for entry in fs::read_dir(&dir).map_err(|e| ServerError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| ServerError::Io(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let s = fs::read_to_string(&path).map_err(|e| ServerError::Io(e.to_string()))?;
            let sess: SessionRecord = match toml::from_str(&s) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if sess.refresh_token_hash == refresh_hash && !sess.revoked {
                found = Some(sess);
                found_path = Some(path);
                break;
            }
        }
    }
    let mut sess = found.ok_or(ServerError::Unauthorized)?;
    if sess.refresh_expires_at < now_secs() {
        return Err(ServerError::Unauthorized);
    }
    // rotate
    let new_access = generate_token();
    let new_refresh = generate_token();
    sess.access_token_hash = hash_token(&new_access);
    sess.refresh_token_hash = hash_token(&new_refresh);
    sess.access_expires_at = now_secs() + 15 * 60;
    sess.refresh_expires_at = now_secs() + 30 * 24 * 60 * 60;
    let stoml = toml::to_string_pretty(&sess).map_err(|e| ServerError::Io(e.to_string()))?;
    if let Some(p) = found_path {
        atomic_write(&p, stoml.as_bytes()).map_err(|e| ServerError::Io(e.to_string()))?;
    }
    Ok(Json(serde_json::json!({
        "access_token": new_access,
        "refresh_token": new_refresh,
    })))
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LogoutReq>,
) -> Result<StatusCode, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let uid = sess.user_id.clone();
    // revoke session(s)
    let dir = sessions_dir(root);
    if dir.exists() {
        for entry in fs::read_dir(&dir).map_err(|e| ServerError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| ServerError::Io(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let s = fs::read_to_string(&path).map_err(|e| ServerError::Io(e.to_string()))?;
            let mut srec: SessionRecord = match toml::from_str(&s) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if srec.user_id != uid {
                continue;
            }
            if req.all_devices || srec.session_id == sess.session_id {
                srec.revoked = true;
                let stoml =
                    toml::to_string_pretty(&srec).map_err(|e| ServerError::Io(e.to_string()))?;
                atomic_write(&path, stoml.as_bytes())
                    .map_err(|e| ServerError::Io(e.to_string()))?;
            }
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn vault_init(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VaultInitReq>,
) -> Result<StatusCode, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let mut v = load_vault(root, &sess.user_id)?;
    if v.wrapped_key.is_some() {
        return Err(ServerError::Conflict("vault exists".into()));
    }
    v.wrapped_key = Some(req.wrapped_key);
    v.recovery_key = Some(req.recovery_key);
    v.salt = req.salt;
    v.revision = 0;
    save_vault(root, &sess.user_id, &v)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn vault_wrapped_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let v = load_vault(root, &sess.user_id)?;
    Ok(Json(serde_json::json!({
        "wrapped_key": v.wrapped_key,
        "recovery_key": v.recovery_key,
        "salt": v.salt,
        "revision": v.revision,
    })))
}

async fn manifest_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let p = manifest_path(root, &sess.user_id);
    if !p.exists() {
        return Err(ServerError::NotFound("manifest".into()));
    }
    let bytes = read_file(&p).map_err(|e| ServerError::Io(e.to_string()))?;
    let v = load_vault(root, &sess.user_id)?;
    let mut h = HeaderMap::new();
    h.insert("x-vault-revision", v.revision.to_string().parse().unwrap());
    Ok((h, bytes))
}

async fn manifest_put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let expected: u64 = headers
        .get("x-vault-revision")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut v = load_vault(root, &sess.user_id)?;
    if v.revision != expected {
        return Err(ServerError::Conflict(format!(
            "expected {}, found {}",
            expected, v.revision
        )));
    }
    // new revision = expected + 1 (client should send next)
    let new_rev = expected + 1;
    v.revision = new_rev;
    save_vault(root, &sess.user_id, &v)?;
    atomic_write(&manifest_path(root, &sess.user_id), &body)
        .map_err(|e| ServerError::Io(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn identities_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<String>>, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let dir = identities_dir(root, &sess.user_id);
    let mut ids = Vec::new();
    if dir.exists() {
        for entry in fs::read_dir(&dir).map_err(|e| ServerError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| ServerError::Io(e.to_string()))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(stem) = name.strip_suffix(".enc") {
                ids.push(stem.to_string());
            }
        }
    }
    Ok(Json(ids))
}

async fn identity_upload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<IdentityUploadReq>,
) -> Result<StatusCode, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let acc = load_account(root, &sess.user_id)?;
    if acc.role != Role::Admin {
        return Err(ServerError::Unauthorized);
    }
    // validate identity id parse
    let _id = IdentityId::parse(&req.identity_id)
        .map_err(|_| ServerError::BadRequest("bad id".into()))?;
    let bytes = B64
        .decode(&req.ciphertext)
        .map_err(|_| ServerError::BadRequest("bad b64".into()))?;
    ensure_dir(&identities_dir(root, &sess.user_id)).map_err(|e| ServerError::Io(e.to_string()))?;
    atomic_write(
        &identity_path(root, &sess.user_id, &req.identity_id),
        &bytes,
    )
    .map_err(|e| ServerError::Io(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn identity_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let p = identity_path(root, &sess.user_id, &id);
    if !p.exists() {
        return Err(ServerError::NotFound("identity".into()));
    }
    let bytes = read_file(&p).map_err(|e| ServerError::Io(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "identity_id": id,
        "ciphertext": B64.encode(&bytes),
    })))
}

async fn identity_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<StatusCode, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let acc = load_account(root, &sess.user_id)?;
    if acc.role != Role::Admin {
        return Err(ServerError::Unauthorized);
    }
    let p = identity_path(root, &sess.user_id, &id);
    if p.exists() {
        let _ = fs::remove_file(&p);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn grant_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<GrantCreateReq>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let acc = load_account(root, &sess.user_id)?;
    if acc.role != Role::Admin {
        return Err(ServerError::Unauthorized);
    }
    // find grantee
    let idx = load_index(root);
    let grantee_uid = idx
        .get(&req.grantee_username)
        .ok_or(ServerError::NotFound("grantee".into()))?
        .clone();
    let grant_id = uuid::Uuid::new_v4().to_string();
    let perms = if req.permissions.is_empty() {
        vec!["read".into(), "install".into()]
    } else {
        req.permissions
    };
    let grant = VaultGrant {
        grant_id: grant_id.clone(),
        grantor_user_id: sess.user_id.clone(),
        grantee_user_id: grantee_uid.clone(),
        permissions: perms,
        wrapped_vmk: req.wrapped_key,
        grantee_public_key: req.grantee_public_key,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        expires_at: req.expires_at,
        revoked: false,
    };
    save_grant(root, &grant)?;
    Ok(Json(serde_json::json!({"grant_id": grant_id})))
}

async fn grants_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<VaultGrant>>, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    // received grants
    let mut out = list_grants(root, &sess.user_id)?;
    // also grants created by this user (stored under grantees; scan all users)
    // best-effort: scan users dir
    let users_dir = users_dir(root);
    if users_dir.exists() {
        for entry in fs::read_dir(&users_dir).map_err(|e| ServerError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| ServerError::Io(e.to_string()))?;
            let uid = entry.file_name().to_string_lossy().to_string();
            if uid.starts_with('_') {
                continue;
            }
            if let Ok(gs) = list_grants(root, &uid) {
                for g in gs {
                    if g.grantor_user_id == sess.user_id
                        && !out.iter().any(|x| x.grant_id == g.grant_id)
                    {
                        out.push(g);
                    }
                }
            }
        }
    }
    Ok(Json(out))
}

async fn grant_revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<StatusCode, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let acc = load_account(root, &sess.user_id)?;
    if acc.role != Role::Admin {
        return Err(ServerError::Unauthorized);
    }
    // find grantee
    let users_dir = users_dir(root);
    if users_dir.exists() {
        for entry in fs::read_dir(&users_dir).map_err(|e| ServerError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| ServerError::Io(e.to_string()))?;
            let uid = entry.file_name().to_string_lossy().to_string();
            if uid.starts_with('_') {
                continue;
            }
            let p = grant_path(root, &uid, &id);
            if p.exists() {
                revoke_grant(root, &uid, &id)?;
                return Ok(StatusCode::NO_CONTENT);
            }
        }
    }
    Err(ServerError::NotFound("grant".into()))
}

async fn grant_wrapped_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    // find grant
    let users_dir = users_dir(root);
    if users_dir.exists() {
        for entry in fs::read_dir(&users_dir).map_err(|e| ServerError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| ServerError::Io(e.to_string()))?;
            let uid = entry.file_name().to_string_lossy().to_string();
            if uid.starts_with('_') {
                continue;
            }
            if uid != sess.user_id {
                continue;
            }
            let p = grant_path(root, &uid, &id);
            if p.exists() {
                let s = fs::read_to_string(&p).map_err(|e| ServerError::Io(e.to_string()))?;
                let g: VaultGrant =
                    toml::from_str(&s).map_err(|e| ServerError::Io(e.to_string()))?;
                if g.revoked {
                    return Err(ServerError::Unauthorized);
                }
                // check expiry
                if let Some(exp) = g.expires_at {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    if now > exp {
                        return Err(ServerError::Unauthorized);
                    }
                }
                return Ok(Json(serde_json::json!({
                    "grant_id": g.grant_id,
                    "wrapped_key": g.wrapped_vmk,
                    "grantor_user_id": g.grantor_user_id,
                    "permissions": g.permissions,
                })));
            }
        }
    }
    Err(ServerError::NotFound("grant".into()))
}

async fn account_set_grant_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<GrantKeyReq>,
) -> Result<StatusCode, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let mut acc = load_account(root, &sess.user_id)?;
    acc.grant_public_key = Some(req.public_key);
    save_account(root, &sess.user_id, &acc)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn account_get_grant_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let _sess = authenticate(root, &token)?;
    let idx = load_index(root);
    let uid = idx
        .get(&username)
        .ok_or(ServerError::NotFound("user".into()))?;
    let acc = load_account(root, uid)?;
    Ok(Json(
        serde_json::json!({"public_key": acc.grant_public_key}),
    ))
}

async fn auth_register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let root = &state.storage_root;
    let uid = redeem_invite(root, &req.invite_code, &req.username, &req.password)?;
    Ok(Json(serde_json::json!({"user_id": uid.as_str()})))
}

async fn invite_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<InviteCreateReq>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let acc = load_account(root, &sess.user_id)?;
    if acc.role != Role::Admin {
        return Err(ServerError::Unauthorized);
    }
    let role = match req.role.as_deref() {
        Some("admin") => Role::Admin,
        _ => Role::Reader,
    };
    let inv = create_invite(root, &sess.user_id, req.ttl_secs, role)?;
    Ok(Json(
        serde_json::json!({"code": inv.code, "expires_at": inv.expires_at}),
    ))
}

async fn invite_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<InviteRecord>>, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let acc = load_account(root, &sess.user_id)?;
    if acc.role != Role::Admin {
        return Err(ServerError::Unauthorized);
    }
    let dir = invites_dir(root);
    let mut out = Vec::new();
    if dir.exists() {
        for entry in fs::read_dir(&dir).map_err(|e| ServerError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| ServerError::Io(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                if let Ok(s) = fs::read_to_string(&path) {
                    if let Ok(inv) = toml::from_str::<InviteRecord>(&s) {
                        out.push(inv);
                    }
                }
            }
        }
    }
    Ok(Json(out))
}

async fn invite_revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(code): axum::extract::Path<String>,
) -> Result<StatusCode, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let acc = load_account(root, &sess.user_id)?;
    if acc.role != Role::Admin {
        return Err(ServerError::Unauthorized);
    }
    let path = invite_path(root, &code);
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_users_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminUserView>>, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let acc = load_account(root, &sess.user_id)?;
    if acc.role != Role::Admin {
        return Err(ServerError::Unauthorized);
    }
    let idx = load_index(root);
    let mut out = Vec::new();
    for (name, uid) in &idx {
        let a = load_account(root, uid).unwrap_or_default();
        out.push(AdminUserView {
            username: name.clone(),
            user_id: uid.clone(),
            role: a.role.to_string(),
            disabled: a.disabled,
        });
    }
    Ok(Json(out))
}

async fn admin_overview(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ServerError> {
    let root = &state.storage_root;
    let token = extract_bearer(&headers).ok_or(ServerError::Unauthorized)?;
    let sess = authenticate(root, &token)?;
    let acc = load_account(root, &sess.user_id)?;
    if acc.role != Role::Admin {
        return Err(ServerError::Unauthorized);
    }
    let idx = load_index(root);
    let mut users = Vec::new();
    for (name, uid) in &idx {
        let a = load_account(root, uid).unwrap_or_default();
        users.push(serde_json::json!({
            "username": name,
            "user_id": uid,
            "role": a.role.to_string(),
            "disabled": a.disabled,
        }));
    }
    let dir = invites_dir(root);
    let mut invites = Vec::new();
    if dir.exists() {
        for entry in fs::read_dir(&dir).map_err(|e| ServerError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| ServerError::Io(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                if let Ok(s) = fs::read_to_string(&path) {
                    if let Ok(inv) = toml::from_str::<InviteRecord>(&s) {
                        invites.push(serde_json::json!({
                            "code": inv.code,
                            "expires_at": inv.expires_at,
                            "used_by": inv.used_by,
                        }));
                    }
                }
            }
        }
    }
    Ok(Json(
        serde_json::json!({"users": users, "invites": invites}),
    ))
}

// ---------- Router ----------

pub fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/register", post(auth_register))
        .route("/api/v1/auth/refresh", post(refresh))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/invites", post(invite_create).get(invite_list))
        .route("/api/v1/invites/{code}", delete(invite_revoke))
        .route("/api/v1/admin/users", get(admin_users_list))
        .route("/api/v1/admin/overview", get(admin_overview))
        .route("/api/v1/vault/init", post(vault_init))
        .route("/api/v1/vault/wrapped-key", get(vault_wrapped_key))
        .route(
            "/api/v1/vault/manifest",
            get(manifest_get).put(manifest_put),
        )
        .route(
            "/api/v1/vault/identities",
            get(identities_list).post(identity_upload),
        )
        .route(
            "/api/v1/vault/identities/{id}",
            get(identity_download).delete(identity_delete),
        )
        .route("/api/v1/grants", post(grant_create).get(grants_list))
        .route("/api/v1/grants/{id}", delete(grant_revoke))
        .route("/api/v1/grants/{id}/wrapped-key", get(grant_wrapped_key))
        .route("/api/v1/account/grant-key", put(account_set_grant_key))
        .route(
            "/api/v1/users/{username}/grant-key",
            get(account_get_grant_key),
        )
        .with_state(state)
}

pub async fn serve(
    addr: SocketAddr,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_app(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------- Convenience for apps ----------

pub fn create_app_state(root: PathBuf) -> Arc<AppState> {
    Arc::new(AppState { storage_root: root })
}

// Re-export WrappedKeyEnvelope already from crypto; nothing else.

pub fn escape_logfmt_value(value: &str) -> String {
    let needs_quoting = value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\\' || c == '=');
    if !needs_quoting {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn unescape_logfmt_value(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if !trimmed.starts_with('"') {
        if trimmed.contains(char::is_whitespace) {
            return Err("invalid logfmt value".to_string());
        }
        return Ok(trimmed.to_string());
    }
    if trimmed.len() < 2 || !trimmed.ends_with('"') {
        return Err("invalid logfmt value".to_string());
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                _ => return Err("invalid logfmt value".to_string()),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}
