use clap::{Parser, Subcommand};
use secrecy::SecretString;
use sshkma_client::{load_token_store, save_token_store, TokenStore, VaultClient};
use sshkma_config::{default_client_config_path, AuthStorage, ClientConfig};
use sshkma_crypto::{derive_kek, unwrap_vmk, Argon2Params};
use sshkma_domain::{HostAlias, IdentityId, Slug};
use sshkma_sshconfig::{ensure_managed_include, plan_installation, OriginalSshKeypair};
use sshkma_storage::atomic_write;
use sshkma_vault::{
    decrypt_identity_record, encrypt_identity_record, encrypt_manifest, EncryptedIdentityRecord,
    PlaintextIdentityRecord, VaultManifest,
};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "sshkma", version, about = "sshkma client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Login {
        url: String,
        #[arg(long)]
        username: Option<String>,
    },
    Logout {
        #[arg(long)]
        all_devices: bool,
    },
    Unlock,
    Lock,
    Status,
    List,
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    Install {
        slug: String,
        #[arg(long)]
        dry_run: bool,
    },
    Remove {
        slug: String,
        #[arg(long)]
        dry_run: bool,
    },
    Sync {
        #[arg(long)]
        dry_run: bool,
    },
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    Doctor,
    Version,
}

#[derive(Subcommand)]
enum KeysAction {
    BulkRemove {
        #[arg(long)]
        glob: Option<String>,
        #[arg(long)]
        remote: bool,
        #[arg(long)]
        local: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        yes: bool,
    },
    BulkImport {
        #[arg(long)]
        config: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        glob: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    Add {
        slug: String,
        #[arg(long)]
        private: Option<String>,
        #[arg(long)]
        public: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    Show {
        slug: String,
    },
    Remove {
        slug: String,
        #[arg(long)]
        remote: bool,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    Show,
    Check,
}

fn config_path() -> PathBuf {
    default_client_config_path().unwrap_or_else(|| PathBuf::from("config.toml"))
}

fn load_config() -> ClientConfig {
    let p = config_path();
    if p.exists() {
        fs::read_to_string(&p)
            .ok()
            .and_then(|s| ClientConfig::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        ClientConfig::default()
    }
}

fn save_config(cfg: &ClientConfig) {
    let p = config_path();
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(s) = cfg.to_string_toml() {
        let _ = atomic_write(&p, s.as_bytes());
    }
}

fn token_store_path() -> PathBuf {
    config_path()
        .parent()
        .unwrap_or(Path::new("."))
        .join("tokens.toml")
}

fn prompt_line(prompt: &str) -> String {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    line.trim().to_string()
}

fn prompt_secret(env_name: &str, prompt: &str) -> String {
    if let Ok(v) = std::env::var(env_name) {
        if !v.is_empty() {
            return v;
        }
    }
    prompt_line(prompt)
}

fn expand_path(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(p)
}

fn load_tokens(cfg: &ClientConfig) -> TokenStore {
    match cfg.auth.storage {
        AuthStorage::Toml => load_token_store(&token_store_path()).unwrap_or_default(),
        AuthStorage::Keyring => {
            if let Some(username) = &cfg.vault.username {
                if let Ok(entry) = keyring::Entry::new("sshkma", username) {
                    if let Ok(secret) = entry.get_password() {
                        if let Ok(ts) = toml::from_str::<TokenStore>(&secret) {
                            return ts;
                        }
                    }
                }
            }
            load_token_store(&token_store_path()).unwrap_or_default()
        }
    }
}

fn save_tokens(cfg: &ClientConfig, ts: &TokenStore) {
    match cfg.auth.storage {
        AuthStorage::Toml => {
            let _ = save_token_store(&token_store_path(), ts);
        }
        AuthStorage::Keyring => {
            if let Some(username) = &cfg.vault.username {
                if let Ok(entry) = keyring::Entry::new("sshkma", username) {
                    if let Ok(s) = toml::to_string_pretty(ts) {
                        let _ = entry.set_password(&s);
                        return;
                    }
                }
            }
            let _ = save_token_store(&token_store_path(), ts);
        }
    }
}

fn clear_tokens(cfg: &ClientConfig) {
    match cfg.auth.storage {
        AuthStorage::Toml => {
            let _ = fs::remove_file(token_store_path());
        }
        AuthStorage::Keyring => {
            if let Some(username) = &cfg.vault.username {
                if let Ok(entry) = keyring::Entry::new("sshkma", username) {
                    let _ = entry.delete_credential();
                }
            }
            let _ = fs::remove_file(token_store_path());
        }
    }
}

fn make_client(cfg: &ClientConfig, ts: &TokenStore) -> VaultClient {
    let url = cfg.vault.url.clone().unwrap_or_default();
    let mut c = VaultClient::new(url);
    if let Some(t) = &ts.access_token {
        c.set_token(t.clone());
    }
    c
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Version => println!("{}", env!("CARGO_PKG_VERSION")),
        Commands::Status => {
            let cfg = load_config();
            let ts = load_tokens(&cfg);
            println!(
                "authenticated={} vault_url={:?}",
                ts.access_token.is_some(),
                cfg.vault.url
            );
        }
        Commands::Lock => println!("locked"),
        Commands::Config { action } => match action {
            ConfigAction::Show => {
                let cfg = load_config();
                println!("{}", cfg.to_string_toml().unwrap_or_default());
            }
            ConfigAction::Check => {
                let cfg = load_config();
                match cfg.validate() {
                    Ok(()) => println!("config ok"),
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Doctor => {
            let cfg = load_config();
            println!("config_path={}", config_path().display());
            println!("config_valid={}", cfg.validate().is_ok());
            println!("ssh_config_dir={}", cfg.ssh.config_dir);
        }
        Commands::Login { url, username } => {
            let mut cfg = load_config();
            cfg.vault.url = Some(url.clone());
            let username = username.unwrap_or_else(|| prompt_line("Username: "));
            cfg.vault.username = Some(username.clone());
            save_config(&cfg);
            let password = prompt_secret("SSHKMA_PASSWORD", "Password: ");
            let mut client = VaultClient::new(url.clone());
            match client.login(&username, &password).await {
                Ok(lr) => {
                    let ts = TokenStore {
                        access_token: Some(lr.access_token),
                        refresh_token: Some(lr.refresh_token),
                    };
                    save_tokens(&cfg, &ts);
                    println!("logged in as {}", username);
                }
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Logout { all_devices } => {
            let cfg = load_config();
            let ts = load_tokens(&cfg);
            let client = make_client(&cfg, &ts);
            let _ = client.logout(all_devices).await;
            clear_tokens(&cfg);
            println!("logged out");
        }
        Commands::Unlock => {
            let cfg = load_config();
            let ts = load_tokens(&cfg);
            let client = make_client(&cfg, &ts);
            let password = prompt_secret("SSHKMA_VAULT_PASSWORD", "Vault password: ");
            match unlock_vmk(
                &client,
                &password,
                cfg.vault.username.as_deref().unwrap_or(""),
            )
            .await
            {
                Ok(_) => println!("vault unlocked"),
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::List => {
            let cfg = load_config();
            let ts = load_tokens(&cfg);
            let client = make_client(&cfg, &ts);
            let password = prompt_secret("SSHKMA_VAULT_PASSWORD", "Vault password: ");
            // need user id; require env SSHKMA_USER_ID
            let user_id_str = std::env::var("SSHKMA_USER_ID").unwrap_or_default();
            let user_id = match sshkma_domain::UserId::parse(&user_id_str) {
                Ok(u) => u,
                Err(_) => {
                    eprintln!("set SSHKMA_USER_ID");
                    std::process::exit(1);
                }
            };
            match fetch_identities(&client, &password, &user_id).await {
                Ok(items) => {
                    #[derive(tabled::Tabled)]
                    struct IdentityRow {
                        #[tabled(rename = "Slug")]
                        slug: String,
                        #[tabled(rename = "Host")]
                        host: String,
                        #[tabled(rename = "Hostname")]
                        hostname: String,
                        #[tabled(rename = "User")]
                        user: String,
                        #[tabled(rename = "Port")]
                        port: String,
                    }
                    let rows: Vec<IdentityRow> = items
                        .into_iter()
                        .map(|(slug, host, hostname, user, port)| IdentityRow {
                            slug,
                            host,
                            hostname: hostname.unwrap_or_default(),
                            user: user.unwrap_or_default(),
                            port: port.map(|p| p.to_string()).unwrap_or_default(),
                        })
                        .collect();
                    let table = tabled::Table::new(rows);
                    println!("{}", table);
                }
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Keys { action } => match action {
            KeysAction::Add {
                slug,
                private,
                public,
                host,
                hostname,
                user,
                port,
            } => {
                let cfg = load_config();
                let ts = load_tokens(&cfg);
                let client = make_client(&cfg, &ts);
                // Resolve key paths (and host details) from ~/.ssh/config when not provided.
                let mut private = private;
                let mut public = public;
                let mut hostname = hostname;
                let mut user = user;
                let mut port = port;
                if private.is_none() || public.is_none() {
                    let lookup_host = host.clone().unwrap_or_else(|| slug.clone());
                    let ssh_config_path = expand_path(&cfg.ssh.config_dir).join("config");
                    let text = fs::read_to_string(&ssh_config_path).unwrap_or_default();
                    if let Some(r) = resolve_ssh_host(&text, &lookup_host, &cfg.ssh.config_dir) {
                        if private.is_none() {
                            private = r.identity_file;
                        }
                        if public.is_none() {
                            if let Some(p) = &private {
                                public = Some(format!("{}.pub", p));
                            }
                        }
                        if hostname.is_none() {
                            hostname = r.hostname;
                        }
                        if user.is_none() {
                            user = r.user;
                        }
                        if port.is_none() {
                            port = r.port;
                        }
                    }
                }
                let private = match private {
                    Some(p) if !p.is_empty() => p,
                    _ => {
                        eprintln!("could not resolve key paths; provide --private/--public");
                        std::process::exit(1);
                    }
                };
                let public = match public {
                    Some(p) if !p.is_empty() => p,
                    _ => {
                        eprintln!("could not resolve public key path; provide --public");
                        std::process::exit(1);
                    }
                };
                let priv_bytes = fs::read(expand_path(&private)).unwrap();
                let pub_bytes = fs::read(expand_path(&public)).unwrap();
                let kp = match OriginalSshKeypair::validate_and_create(&priv_bytes, &pub_bytes) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                };
                let slug = Slug::parse(&slug).unwrap();
                let host_alias =
                    HostAlias::parse(&host.clone().unwrap_or_else(|| slug.as_str().to_string()))
                        .unwrap();
                let identity_id = IdentityId::new();
                let record = PlaintextIdentityRecord {
                    slug: slug.as_str().to_string(),
                    host_alias: host_alias.as_str().to_string(),
                    hostname,
                    user,
                    port,
                    private_key_openssh: String::from_utf8(priv_bytes.clone()).unwrap(),
                    public_key_openssh: String::from_utf8(pub_bytes.clone()).unwrap(),
                    extra_ssh_directives: vec![],
                    created_at: now(),
                    updated_at: now(),
                };
                let password = prompt_secret("SSHKMA_VAULT_PASSWORD", "Vault password: ");
                let user_id_str = std::env::var("SSHKMA_USER_ID").unwrap_or_default();
                let user_id = match sshkma_domain::UserId::parse(&user_id_str) {
                    Ok(u) => u,
                    Err(_) => {
                        eprintln!("set SSHKMA_USER_ID");
                        std::process::exit(1);
                    }
                };
                let vmk = match unlock_vmk(&client, &password, "").await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                };
                let enc = encrypt_identity_record(&record, &vmk, &user_id, &identity_id).unwrap();
                if client
                    .upload_identity(identity_id.as_str(), &enc.ciphertext)
                    .await
                    .is_err()
                {
                    eprintln!("upload failed");
                    std::process::exit(1);
                }
                // update manifest
                let _ = update_manifest_add(&client, &vmk, &user_id, identity_id.clone()).await;
                println!("imported {} ({})", slug, identity_id);
                let _ = kp;
            }
            KeysAction::BulkRemove {
                glob,
                remote,
                local,
                dry_run,
                yes,
            } => {
                let cfg = load_config();
                let do_remote = remote || (!remote && !local);
                let do_local = local || (!remote && !local);

                let mut remote_records: Vec<(String, String)> = Vec::new();
                if do_remote {
                    let ts = load_tokens(&cfg);
                    let client = make_client(&cfg, &ts);
                    let password = prompt_secret("SSHKMA_VAULT_PASSWORD", "Vault password: ");
                    let user_id_str = std::env::var("SSHKMA_USER_ID").unwrap_or_default();
                    let user_id = match sshkma_domain::UserId::parse(&user_id_str) {
                        Ok(u) => u,
                        Err(_) => {
                            eprintln!("set SSHKMA_USER_ID");
                            std::process::exit(1);
                        }
                    };
                    let vmk_for_fetch =
                        unlock_vmk(&client, &password, "")
                            .await
                            .unwrap_or_else(|e| {
                                eprintln!("{}", e);
                                std::process::exit(1);
                            });
                    let recs = fetch_records(&client, &vmk_for_fetch, &user_id)
                        .await
                        .unwrap_or_else(|e| {
                            eprintln!("{}", e);
                            std::process::exit(1);
                        });
                    for (id, rec) in recs {
                        if let Some(g) = &glob {
                            if !glob_match(g.as_bytes(), rec.slug.as_bytes()) {
                                continue;
                            }
                        }
                        remote_records.push((id, rec.slug));
                    }

                    if dry_run {
                        println!("Remote candidates: {}", remote_records.len());
                        for (id, slug) in &remote_records {
                            println!("  {} ({})", slug, id);
                        }
                    } else if !remote_records.is_empty() && !yes {
                        println!("Remove {} remote identit(ies)? [y/N]", remote_records.len());
                        let mut line = String::new();
                        let _ = std::io::stdin().read_line(&mut line);
                        if !line.trim().eq_ignore_ascii_case("y") {
                            println!("aborted");
                            std::process::exit(0);
                        }
                    }

                    if !dry_run {
                        let vmk = unlock_vmk(&client, &password, "")
                            .await
                            .unwrap_or_else(|e| {
                                eprintln!("{}", e);
                                std::process::exit(1);
                            });
                        for (id, slug) in &remote_records {
                            let identity_id = match sshkma_domain::IdentityId::parse(id) {
                                Ok(i) => i,
                                Err(_) => continue,
                            };
                            if client.delete_identity(id).await.is_ok() {
                                let _ =
                                    update_manifest_remove(&client, &vmk, &user_id, identity_id)
                                        .await;
                                println!("removed (vault) {}", slug);
                            } else {
                                eprintln!("failed to remove {} from vault", slug);
                            }
                        }
                    }
                }

                if do_local {
                    let managed_dir = expand_path(&cfg.ssh.managed_dir);
                    let keys_dir = expand_path(&cfg.ssh.keys_dir);
                    let mut local_slugs: Vec<String> = Vec::new();
                    if let Ok(entries) = fs::read_dir(&managed_dir) {
                        for entry in entries.flatten() {
                            let p = entry.path();
                            if p.extension().and_then(|s| s.to_str()) == Some("conf") {
                                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                                    if let Some(g) = &glob {
                                        if !glob_match(g.as_bytes(), stem.as_bytes()) {
                                            continue;
                                        }
                                    }
                                    local_slugs.push(stem.to_string());
                                }
                            }
                        }
                    }
                    if dry_run {
                        println!("Local candidates: {}", local_slugs.len());
                        for s in &local_slugs {
                            println!("  {}", s);
                        }
                    } else if !local_slugs.is_empty() && !yes && !do_remote {
                        println!("Remove {} local identit(ies)? [y/N]", local_slugs.len());
                        let mut line = String::new();
                        let _ = std::io::stdin().read_line(&mut line);
                        if !line.trim().eq_ignore_ascii_case("y") {
                            println!("aborted");
                            std::process::exit(0);
                        }
                    }
                    if !dry_run {
                        for s in &local_slugs {
                            let _ = fs::remove_file(managed_dir.join(format!("{}.conf", s)));
                            let _ = fs::remove_file(keys_dir.join(s));
                            let _ = fs::remove_file(keys_dir.join(format!("{}.pub", s)));
                            println!("removed (local) {}", s);
                        }
                    }
                }
            }
            KeysAction::BulkImport {
                config,
                dry_run,
                glob,
                yes,
            } => {
                let cfg = load_config();
                let ts = load_tokens(&cfg);
                let client = make_client(&cfg, &ts);
                let config_path = match config {
                    Some(p) => expand_path(&p),
                    None => expand_path(&cfg.ssh.config_dir).join("config"),
                };
                let text = fs::read_to_string(&config_path).unwrap_or_default();
                use ssh2_config::{ParseRule, SshConfig};
                use std::io::Cursor;
                let mut reader = Cursor::new(text.as_bytes());
                let parsed = match SshConfig::default().parse(
                    &mut reader,
                    ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("failed to parse ssh config: {}", e);
                        std::process::exit(1);
                    }
                };

                // collect candidates
                #[derive(Clone)]
                struct Candidate {
                    alias: String,
                    slug: String,
                    private: String,
                    public: String,
                    hostname: Option<String>,
                    user: Option<String>,
                    port: Option<u16>,
                }
                let mut candidates: Vec<Candidate> = Vec::new();
                let mut used_slugs: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                for host in parsed.get_hosts() {
                    for clause in &host.pattern {
                        if clause.negated {
                            continue;
                        }
                        let alias = clause.pattern.clone();
                        if alias.contains('*') || alias.contains('?') {
                            continue;
                        }
                        if let Some(g) = &glob {
                            if !glob_match(g.as_bytes(), alias.as_bytes()) {
                                continue;
                            }
                        }
                        let params = &host.params;
                        let id_file = match params.identity_file.as_ref().and_then(|v| v.first()) {
                            Some(p) => p.to_string_lossy().to_string(),
                            None => continue,
                        };
                        let private = if id_file.starts_with("~/") {
                            expand_path(&id_file).to_string_lossy().to_string()
                        } else if std::path::Path::new(&id_file).is_absolute() {
                            id_file.clone()
                        } else {
                            expand_path(&cfg.ssh.config_dir)
                                .join(&id_file)
                                .to_string_lossy()
                                .to_string()
                        };
                        let public = format!("{}.pub", private);
                        if !std::path::Path::new(&private).exists()
                            || !std::path::Path::new(&public).exists()
                        {
                            continue;
                        }
                        // slug derivation
                        let mut slug = sanitize_slug(&alias);
                        if slug.is_empty() {
                            slug = "host".to_string();
                        }
                        let mut final_slug = slug.clone();
                        let mut n = 2;
                        while used_slugs.contains(&final_slug) {
                            final_slug = format!("{}-{}", slug, n);
                            n += 1;
                        }
                        used_slugs.insert(final_slug.clone());
                        candidates.push(Candidate {
                            alias: alias.clone(),
                            slug: final_slug,
                            private,
                            public,
                            hostname: params.host_name.clone(),
                            user: params.user.clone(),
                            port: params.port,
                        });
                    }
                }

                if dry_run {
                    for c in &candidates {
                        println!(
                            "would import {} -> slug={} key={}",
                            c.alias, c.slug, c.private
                        );
                    }
                    println!("total {}", candidates.len());
                    return;
                }

                if !candidates.is_empty() && !yes {
                    println!("Found {} key(s) to import:", candidates.len());
                    for c in &candidates {
                        println!("  {} -> slug={} key={}", c.alias, c.slug, c.private);
                    }
                    println!("Proceed? [y/N]");
                    let mut line = String::new();
                    let _ = std::io::stdin().read_line(&mut line);
                    if !line.trim().eq_ignore_ascii_case("y") {
                        println!("aborted");
                        return;
                    }
                }

                let password = prompt_secret("SSHKMA_VAULT_PASSWORD", "Vault password: ");
                let user_id_str = std::env::var("SSHKMA_USER_ID").unwrap_or_default();
                let user_id = match sshkma_domain::UserId::parse(&user_id_str) {
                    Ok(u) => u,
                    Err(_) => {
                        eprintln!("set SSHKMA_USER_ID");
                        std::process::exit(1);
                    }
                };
                let vmk = match unlock_vmk(&client, &password, "").await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                };

                let mut ok = 0usize;
                let mut fail = 0usize;
                for c in &candidates {
                    let priv_bytes = match fs::read(&c.private) {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("{}: read error {}", c.alias, e);
                            fail += 1;
                            continue;
                        }
                    };
                    let pub_bytes = match fs::read(&c.public) {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("{}: read error {}", c.alias, e);
                            fail += 1;
                            continue;
                        }
                    };
                    if OriginalSshKeypair::validate_and_create(&priv_bytes, &pub_bytes).is_err() {
                        eprintln!("{}: invalid keypair", c.alias);
                        fail += 1;
                        continue;
                    }
                    let slug = match Slug::parse(&c.slug) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("{}: bad slug {}: {}", c.alias, c.slug, e);
                            fail += 1;
                            continue;
                        }
                    };
                    let host_alias = match HostAlias::parse(&c.alias) {
                        Ok(h) => h,
                        Err(_) => match HostAlias::parse(&c.slug) {
                            Ok(h) => h,
                            Err(e) => {
                                eprintln!("{}: bad host alias: {}", c.alias, e);
                                fail += 1;
                                continue;
                            }
                        },
                    };
                    let identity_id = IdentityId::new();
                    let record = PlaintextIdentityRecord {
                        slug: slug.as_str().to_string(),
                        host_alias: host_alias.as_str().to_string(),
                        hostname: c.hostname.clone(),
                        user: c.user.clone(),
                        port: c.port,
                        private_key_openssh: String::from_utf8(priv_bytes.clone())
                            .unwrap_or_default(),
                        public_key_openssh: String::from_utf8(pub_bytes.clone())
                            .unwrap_or_default(),
                        extra_ssh_directives: vec![],
                        created_at: now(),
                        updated_at: now(),
                    };
                    let enc = match encrypt_identity_record(&record, &vmk, &user_id, &identity_id) {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("{}: encrypt error {}", c.alias, e);
                            fail += 1;
                            continue;
                        }
                    };
                    if client
                        .upload_identity(identity_id.as_str(), &enc.ciphertext)
                        .await
                        .is_err()
                    {
                        eprintln!("{}: upload failed", c.alias);
                        fail += 1;
                        continue;
                    }
                    let _ = update_manifest_add(&client, &vmk, &user_id, identity_id.clone()).await;
                    println!("imported {} ({})", c.slug, identity_id);
                    ok += 1;
                }
                println!("done: {} imported, {} failed", ok, fail);
            }
            KeysAction::Show { slug } => {
                let cfg = load_config();
                let ts = load_tokens(&cfg);
                let client = make_client(&cfg, &ts);
                let password = prompt_secret("SSHKMA_VAULT_PASSWORD", "Vault password: ");
                let user_id_str = std::env::var("SSHKMA_USER_ID").unwrap_or_default();
                let user_id = sshkma_domain::UserId::parse(&user_id_str).unwrap();
                let vmk = unlock_vmk(&client, &password, "").await.unwrap();
                let _items = fetch_identities(&client, &password, &user_id)
                    .await
                    .unwrap();
                // find by slug via direct fetch all records
                let recs = fetch_records(&client, &vmk, &user_id).await.unwrap();
                if let Some(r) = recs.iter().find(|r| r.1.slug == slug) {
                    println!("{}", r.1.private_key_openssh);
                    println!("{}", r.1.public_key_openssh);
                } else {
                    eprintln!("not found");
                    std::process::exit(1);
                }
            }
            KeysAction::Remove { slug, remote } => {
                if !remote {
                    println!("local remove not supported; use remove command");
                    return;
                }
                let cfg = load_config();
                let ts = load_tokens(&cfg);
                let client = make_client(&cfg, &ts);
                let password = prompt_secret("SSHKMA_VAULT_PASSWORD", "Vault password: ");
                let user_id_str = std::env::var("SSHKMA_USER_ID").unwrap_or_default();
                let user_id = sshkma_domain::UserId::parse(&user_id_str).unwrap();
                let vmk = unlock_vmk(&client, &password, "").await.unwrap();
                let recs = fetch_records(&client, &vmk, &user_id).await.unwrap();
                if let Some((id, _)) = recs
                    .iter()
                    .find(|r| r.1.slug == slug)
                    .map(|r| (r.0.clone(), ()))
                {
                    let _ = client.delete_identity(&id).await;
                    let _ = update_manifest_remove(
                        &client,
                        &vmk,
                        &user_id,
                        sshkma_domain::IdentityId::parse(&id).unwrap(),
                    )
                    .await;
                    println!("removed {}", slug);
                } else {
                    eprintln!("not found");
                    std::process::exit(1);
                }
            }
        },
        Commands::Install { slug, dry_run } => {
            let cfg = load_config();
            let ts = load_tokens(&cfg);
            let client = make_client(&cfg, &ts);
            let password = prompt_secret("SSHKMA_VAULT_PASSWORD", "Vault password: ");
            let user_id_str = std::env::var("SSHKMA_USER_ID").unwrap_or_default();
            let user_id = sshkma_domain::UserId::parse(&user_id_str).unwrap();
            let vmk = unlock_vmk(&client, &password, "").await.unwrap();
            let recs = fetch_records(&client, &vmk, &user_id).await.unwrap();
            let rec = recs
                .iter()
                .find(|r| r.1.slug == slug)
                .map(|r| r.1.clone())
                .unwrap();
            let priv_bytes = rec.private_key_openssh.into_bytes();
            let pub_bytes = rec.public_key_openssh.into_bytes();
            let slug = Slug::parse(&rec.slug).unwrap();
            let host_alias = HostAlias::parse(&rec.host_alias).unwrap();
            let managed_dir = expand_path(&cfg.ssh.managed_dir);
            let keys_dir = expand_path(&cfg.ssh.keys_dir);
            let plan = plan_installation(
                &slug,
                &host_alias,
                rec.hostname.as_deref(),
                rec.user.as_deref(),
                rec.port,
                &priv_bytes,
                &pub_bytes,
                &managed_dir.to_string_lossy(),
                &keys_dir.to_string_lossy(),
            );
            if dry_run {
                println!("{:?}", plan);
                return;
            }
            // apply
            for action in plan.actions() {
                if let sshkma_domain::FileAction::Create(f) = action {
                    let p = PathBuf::from(&f.path);
                    if let Some(parent) = p.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::write(&p, &f.content);
                }
            }
            // ensure include
            let main_config = expand_path(&cfg.ssh.config_dir).join("config");
            let existing = fs::read_to_string(&main_config).unwrap_or_default();
            let managed_path = format!("{}/*.conf", managed_dir.display());
            let updated = ensure_managed_include(&existing, &managed_path).unwrap();
            if updated != existing {
                let _ = atomic_write(&main_config, updated.as_bytes());
            }
            println!("installed {}", slug);
        }
        Commands::Remove { slug, dry_run } => {
            let cfg = load_config();
            let managed_dir = expand_path(&cfg.ssh.managed_dir);
            let keys_dir = expand_path(&cfg.ssh.keys_dir);
            if dry_run {
                println!("would remove {}", slug);
                return;
            }
            let _ = fs::remove_file(managed_dir.join(format!("{}.conf", slug)));
            let _ = fs::remove_file(keys_dir.join(&slug));
            let _ = fs::remove_file(keys_dir.join(format!("{}.pub", slug)));
            println!("removed {}", slug);
        }
        Commands::Sync { dry_run } => {
            let cfg = load_config();
            let ts = load_tokens(&cfg);
            let client = make_client(&cfg, &ts);
            let password = prompt_secret("SSHKMA_VAULT_PASSWORD", "Vault password: ");
            let user_id_str = std::env::var("SSHKMA_USER_ID").unwrap_or_default();
            let user_id = sshkma_domain::UserId::parse(&user_id_str).unwrap();
            let vmk = unlock_vmk(&client, &password, "").await.unwrap();
            let recs = fetch_records(&client, &vmk, &user_id).await.unwrap();
            let managed_dir = expand_path(&cfg.ssh.managed_dir);
            let keys_dir = expand_path(&cfg.ssh.keys_dir);
            for (_, rec) in &recs {
                let slug = Slug::parse(&rec.slug).unwrap();
                let host_alias = HostAlias::parse(&rec.host_alias).unwrap();
                let priv_bytes = rec.private_key_openssh.as_bytes();
                let pub_bytes = rec.public_key_openssh.as_bytes();
                let plan = plan_installation(
                    &slug,
                    &host_alias,
                    rec.hostname.as_deref(),
                    rec.user.as_deref(),
                    rec.port,
                    priv_bytes,
                    pub_bytes,
                    &managed_dir.to_string_lossy(),
                    &keys_dir.to_string_lossy(),
                );
                if dry_run {
                    println!("{:?}", plan);
                } else {
                    for action in plan.actions() {
                        if let sshkma_domain::FileAction::Create(f) = action {
                            let p = PathBuf::from(&f.path);
                            if let Some(parent) = p.parent() {
                                let _ = fs::create_dir_all(parent);
                            }
                            let _ = fs::write(&p, &f.content);
                        }
                    }
                }
            }
            if !dry_run {
                let main_config = expand_path(&cfg.ssh.config_dir).join("config");
                let existing = fs::read_to_string(&main_config).unwrap_or_default();
                let managed_path = format!("{}/*.conf", managed_dir.display());
                let updated = ensure_managed_include(&existing, &managed_path).unwrap();
                if updated != existing {
                    let _ = atomic_write(&main_config, updated.as_bytes());
                }
                println!("synced {} identities", recs.len());
            }
        }
    }
}

fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    match pattern[0] {
        b'*' => {
            if pattern.len() == 1 {
                return true;
            }
            for i in 0..=text.len() {
                if glob_match(&pattern[1..], &text[i..]) {
                    return true;
                }
            }
            false
        }
        b'?' => !text.is_empty() && glob_match(&pattern[1..], &text[1..]),
        c => !text.is_empty() && c == text[0] && glob_match(&pattern[1..], &text[1..]),
    }
}

fn sanitize_slug(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let out = out.trim_matches('-').to_string();
    if out.len() > 64 {
        out[..64].to_string()
    } else {
        out
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn unlock_vmk(
    client: &VaultClient,
    password: &str,
    _user: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let wk = client.get_wrapped_key().await.map_err(|e| e.to_string())?;
    let wrapped_env: sshkma_crypto::WrappedKeyEnvelope =
        serde_json::from_value(wk["wrapped_key"].clone()).map_err(|e| e.to_string())?;
    let salt_hex = wk["salt"].as_str().unwrap_or("");
    let salt_bytes: [u8; 16] = if salt_hex.len() == 32 {
        let v = hex::decode(salt_hex).map_err(|e| e.to_string())?;
        let mut a = [0u8; 16];
        a.copy_from_slice(&v);
        a
    } else {
        [0u8; 16]
    };
    let kek = derive_kek(
        &SecretString::from(password.to_string()),
        &salt_bytes,
        &Argon2Params::interactive(),
    )
    .map_err(|e| e.to_string())?;
    let aad = format!("sshkma:vmk:v1:{}", ""); // best effort
    unwrap_vmk(&wrapped_env, &kek, aad.as_bytes()).map_err(|e| e.to_string())
}

async fn fetch_records(
    client: &VaultClient,
    vmk: &zeroize::Zeroizing<[u8; 32]>,
    user_id: &sshkma_domain::UserId,
) -> Result<Vec<(String, PlaintextIdentityRecord)>, String> {
    let ids = client.list_identities().await.map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for id in ids {
        let ct = client
            .download_identity(&id)
            .await
            .map_err(|e| e.to_string())?;
        let enc = EncryptedIdentityRecord {
            identity_id: sshkma_domain::IdentityId::parse(&id).unwrap(),
            user_id: user_id.clone(),
            revision: 0,
            ciphertext: ct,
        };
        let rec = decrypt_identity_record(&enc, vmk).map_err(|e| e.to_string())?;
        out.push((id, rec));
    }
    Ok(out)
}

async fn fetch_identities(
    client: &VaultClient,
    password: &str,
    user_id: &sshkma_domain::UserId,
) -> Result<Vec<(String, String, Option<String>, Option<String>, Option<u16>)>, String> {
    let vmk = unlock_vmk(client, password, "").await?;
    let recs = fetch_records(client, &vmk, user_id).await?;
    Ok(recs
        .into_iter()
        .map(|(_, r)| (r.slug, r.host_alias, r.hostname, r.user, r.port))
        .collect())
}

async fn update_manifest_add(
    client: &VaultClient,
    vmk: &zeroize::Zeroizing<[u8; 32]>,
    user_id: &sshkma_domain::UserId,
    identity_id: IdentityId,
) -> Result<(), String> {
    let (bytes, rev) = client.get_manifest().await.unwrap_or_default();
    let mut manifest = if bytes.is_empty() {
        VaultManifest::new()
    } else {
        sshkma_vault::decrypt_manifest(&bytes, vmk, user_id).unwrap_or_default()
    };
    if !manifest.identity_ids.contains(&identity_id) {
        manifest.identity_ids.push(identity_id);
    }
    manifest.revision = rev + 1;
    let new_bytes = encrypt_manifest(&manifest, vmk, user_id).map_err(|e| e.to_string())?;
    client
        .put_manifest(&new_bytes, rev)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn update_manifest_remove(
    client: &VaultClient,
    vmk: &zeroize::Zeroizing<[u8; 32]>,
    user_id: &sshkma_domain::UserId,
    identity_id: IdentityId,
) -> Result<(), String> {
    let (bytes, rev) = match client.get_manifest().await {
        Ok(x) => x,
        Err(_) => return Ok(()),
    };
    let mut manifest = sshkma_vault::decrypt_manifest(&bytes, vmk, user_id).unwrap_or_default();
    manifest.identity_ids.retain(|x| x != &identity_id);
    manifest.revision = rev + 1;
    let new_bytes = encrypt_manifest(&manifest, vmk, user_id).map_err(|e| e.to_string())?;
    client
        .put_manifest(&new_bytes, rev)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug, Clone)]
struct ResolvedSshHost {
    identity_file: Option<String>,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
}

fn resolve_ssh_host(text: &str, target: &str, config_dir: &str) -> Option<ResolvedSshHost> {
    use ssh2_config::{ParseRule, SshConfig};
    use std::io::Cursor;
    let mut reader = Cursor::new(text.as_bytes());
    let config = SshConfig::default()
        .parse(
            &mut reader,
            ParseRule::ALLOW_UNKNOWN_FIELDS | ParseRule::ALLOW_UNSUPPORTED_FIELDS,
        )
        .ok()?;
    let params = config.query(target);
    let id_file = params
        .identity_file
        .as_ref()
        .and_then(|v| v.first())
        .map(|p| p.to_string_lossy().to_string())?;
    let expanded = if id_file.starts_with("~/") {
        expand_path(&id_file).to_string_lossy().to_string()
    } else if std::path::Path::new(&id_file).is_absolute() {
        id_file
    } else {
        expand_path(config_dir)
            .join(&id_file)
            .to_string_lossy()
            .to_string()
    };
    Some(ResolvedSshHost {
        identity_file: Some(expanded),
        hostname: params.host_name.clone(),
        user: params.user.clone(),
        port: params.port,
    })
}
