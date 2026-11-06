use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sshkma_config::ServerConfig;
use sshkma_server::create_user;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "sshkmad",
    version,
    about = "sshkmad server daemon and admin CLI",
    long_about = "sshkmad is the server daemon and administrative CLI for a self-hosted, zero-knowledge SSH identity vault.\n\nIt stores only encrypted vault content and opaque identifiers on the filesystem.",
    after_help = "Examples:\n  sshkmad init --config /etc/sshkma/sshkmad.toml\n  sshkmad config check\n  sshkmad users add --username alice --password 'change-me'\n  sshkmad serve\n  sshkmad overview\n  sshkmad invites create --ttl 3600\n\nEnvironment/paths:\n  Default config: /etc/sshkma/sshkmad.toml (override with --config)\n  Storage root: /var/lib/sshkmad"
)]
struct Cli {
    #[arg(long, default_value = "/etc/sshkma/sshkmad.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Serve,
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    Users {
        #[command(subcommand)]
        action: UsersAction,
    },
    Invites {
        #[command(subcommand)]
        action: InvitesAction,
    },
    Devices {
        #[command(subcommand)]
        action: DevicesAction,
    },
    Sessions {
        #[command(subcommand)]
        action: SessionsAction,
    },
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    Stats,
    Doctor,
    Overview,
    Version,
}

#[derive(Subcommand)]
enum ConfigAction {
    Check,
}

#[derive(Subcommand)]
enum UsersAction {
    Add {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    List,
    Disable {
        username: String,
    },
}

#[derive(Subcommand)]
enum InvitesAction {
    Create {
        #[arg(long, default_value = "3600")]
        ttl: u64,
        #[arg(long)]
        role: Option<String>,
    },
    List,
    Revoke {
        code: String,
    },
}

#[derive(Subcommand)]
enum DevicesAction {
    List,
    Revoke { device_id: String },
}

#[derive(Subcommand)]
enum SessionsAction {
    List,
    Revoke { session_id: String },
}

#[derive(Subcommand)]
enum KeysAction {
    List,
    Show {
        id: String,
        #[arg(long)]
        user: String,
    },
    Remove {
        id: String,
        #[arg(long)]
        user: String,
    },
    Import {
        id: String,
        #[arg(long)]
        file: String,
        #[arg(long)]
        user: String,
    },
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
struct AccountRecord {
    user_id: String,
    username: String,
    password_hash: String,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    role: String,
    #[serde(default)]
    grant_public_key: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct DeviceRecord {
    device_id: String,
    user_id: String,
    name: String,
    created_at: u64,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct SessionRecord {
    session_id: String,
    user_id: String,
    device_id: String,
    access_token_hash: String,
    refresh_token_hash: String,
    access_expires_at: u64,
    refresh_expires_at: u64,
    revoked: bool,
}

fn load_cfg(cli_config: &PathBuf) -> ServerConfig {
    if cli_config.exists() {
        fs::read_to_string(cli_config)
            .ok()
            .and_then(|s| ServerConfig::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        ServerConfig::default()
    }
}

fn root_of(cfg: &ServerConfig) -> PathBuf {
    PathBuf::from(&cfg.storage.root)
}

fn users_index_path(root: &Path) -> PathBuf {
    root.join("users").join("_index.toml")
}

fn load_index(root: &Path) -> std::collections::BTreeMap<String, String> {
    let p = users_index_path(root);
    if !p.exists() {
        return std::collections::BTreeMap::new();
    }
    fs::read_to_string(&p)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => {
            let cfg = ServerConfig::default();
            if let Some(parent) = cli.config.parent() {
                let _ = fs::create_dir_all(parent);
            }
            match cfg.to_string_toml() {
                Ok(s) => {
                    if fs::write(&cli.config, s).is_ok() {
                        println!("initialized {}", cli.config.display());
                    } else {
                        eprintln!("failed to write config");
                    }
                }
                Err(e) => eprintln!("{}", e),
            }
        }
        Commands::Serve => {
            let cfg = load_cfg(&cli.config);
            if let Err(e) = cfg.validate() {
                eprintln!("config error: {}", e);
                return;
            }
            let addr = format!("{}:{}", cfg.server.listen_address, cfg.server.port)
                .parse()
                .unwrap();
            println!("serving on {}", addr);
            let state = sshkma_server::create_app_state(root_of(&cfg));
            if let Err(e) = sshkma_server::serve(addr, state).await {
                eprintln!("serve error: {}", e);
            }
        }
        Commands::Config { action } => match action {
            ConfigAction::Check => {
                let s = fs::read_to_string(&cli.config).unwrap_or_default();
                match ServerConfig::from_str(&s) {
                    Ok(cfg) => match cfg.validate() {
                        Ok(()) => println!("config ok"),
                        Err(e) => {
                            eprintln!("{}", e);
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Users { action } => {
            let cfg = load_cfg(&cli.config);
            let root = root_of(&cfg);
            match action {
                UsersAction::Add { username, password } => {
                    match create_user(&root, &username, &password) {
                        Ok(id) => println!("created user {} ({})", username, id),
                        Err(e) => {
                            eprintln!("{}", e);
                            std::process::exit(1);
                        }
                    }
                }
                UsersAction::List => {
                    let idx = load_index(&root);
                    for (name, uid) in &idx {
                        let ap = root.join("users").join(uid).join("account.toml");
                        let disabled = fs::read_to_string(&ap)
                            .ok()
                            .and_then(|s| toml::from_str::<AccountRecord>(&s).ok())
                            .map(|a| a.disabled)
                            .unwrap_or(false);
                        println!("{} {} disabled={}", name, uid, disabled);
                    }
                }
                UsersAction::Disable { username } => {
                    let idx = load_index(&root);
                    if let Some(uid) = idx.get(&username) {
                        let ap = root.join("users").join(uid).join("account.toml");
                        if let Ok(s) = fs::read_to_string(&ap) {
                            if let Ok(mut acc) = toml::from_str::<AccountRecord>(&s) {
                                acc.disabled = true;
                                if let Ok(out) = toml::to_string_pretty(&acc) {
                                    let _ = fs::write(&ap, out);
                                    println!("disabled {}", username);
                                }
                            }
                        }
                    } else {
                        eprintln!("user not found");
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Invites { action } => {
            let cfg = load_cfg(&cli.config);
            let root = root_of(&cfg);
            match action {
                InvitesAction::Create { ttl, role } => {
                    let r = match role.as_deref() {
                        Some("admin") => sshkma_server::Role::Admin,
                        _ => sshkma_server::Role::Reader,
                    };
                    match sshkma_server::create_invite(&root, "admin", ttl, r) {
                        Ok(inv) => {
                            let base = cfg.server.public_url.trim_end_matches('/').to_string();
                            print!(
                                "{}",
                                sshkma_config::render_invite_text(&base, &inv.code, inv.expires_at)
                            );
                        }
                        Err(e) => {
                            eprintln!("{}", e);
                            std::process::exit(1);
                        }
                    }
                }
                InvitesAction::List => {
                    let dir = root.join("invites");
                    if dir.exists() {
                        for entry in fs::read_dir(&dir).unwrap() {
                            let entry = entry.unwrap();
                            let path = entry.path();
                            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                                if let Ok(s) = fs::read_to_string(&path) {
                                    if let Ok(inv) =
                                        toml::from_str::<sshkma_server::InviteRecord>(&s)
                                    {
                                        println!(
                                            "{} expires={} used={}",
                                            inv.code,
                                            inv.expires_at,
                                            inv.used_by.as_deref().unwrap_or("-")
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                InvitesAction::Revoke { code } => {
                    let path = root
                        .join("invites")
                        .join(format!("{}.toml", code.replace('-', "")));
                    if path.exists() {
                        let _ = fs::remove_file(&path);
                        println!("revoked {}", code);
                    } else {
                        eprintln!("not found");
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Devices { action } => {
            let cfg = load_cfg(&cli.config);
            let root = root_of(&cfg);
            let dev_dir = root.join("devices");
            match action {
                DevicesAction::List => {
                    if dev_dir.exists() {
                        for entry in fs::read_dir(&dev_dir).unwrap() {
                            let entry = entry.unwrap();
                            let path = entry.path();
                            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                                if let Ok(s) = fs::read_to_string(&path) {
                                    if let Ok(d) = toml::from_str::<DeviceRecord>(&s) {
                                        println!(
                                            "{} user={} name={} created={}",
                                            d.device_id, d.user_id, d.name, d.created_at
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                DevicesAction::Revoke { device_id } => {
                    let dp = dev_dir.join(format!("{}.toml", device_id));
                    // revoke sessions for this device
                    let sess_dir = root.join("sessions");
                    if sess_dir.exists() {
                        for entry in fs::read_dir(&sess_dir).unwrap() {
                            let entry = entry.unwrap();
                            let path = entry.path();
                            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                                if let Ok(s) = fs::read_to_string(&path) {
                                    if let Ok(mut sess) = toml::from_str::<SessionRecord>(&s) {
                                        if sess.device_id == device_id {
                                            sess.revoked = true;
                                            if let Ok(out) = toml::to_string_pretty(&sess) {
                                                let _ = fs::write(&path, out);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    let _ = fs::remove_file(&dp);
                    println!("revoked device {}", device_id);
                }
            }
        }
        Commands::Sessions { action } => {
            let cfg = load_cfg(&cli.config);
            let root = root_of(&cfg);
            let sess_dir = root.join("sessions");
            match action {
                SessionsAction::List => {
                    if sess_dir.exists() {
                        for entry in fs::read_dir(&sess_dir).unwrap() {
                            let entry = entry.unwrap();
                            let path = entry.path();
                            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                                if let Ok(s) = fs::read_to_string(&path) {
                                    if let Ok(sess) = toml::from_str::<SessionRecord>(&s) {
                                        println!(
                                            "{} user={} device={} access_exp={} revoked={}",
                                            sess.session_id,
                                            sess.user_id,
                                            sess.device_id,
                                            sess.access_expires_at,
                                            sess.revoked
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                SessionsAction::Revoke { session_id } => {
                    let sp = sess_dir.join(format!("{}.toml", session_id));
                    if let Ok(s) = fs::read_to_string(&sp) {
                        if let Ok(mut sess) = toml::from_str::<SessionRecord>(&s) {
                            sess.revoked = true;
                            if let Ok(out) = toml::to_string_pretty(&sess) {
                                let _ = fs::write(&sp, out);
                                println!("revoked session {}", session_id);
                            }
                        }
                    } else {
                        eprintln!("session not found");
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Keys { action } => {
            let cfg = load_cfg(&cli.config);
            let root = root_of(&cfg);
            match action {
                KeysAction::List => {
                    let idx = load_index(&root);
                    for uid in idx.values() {
                        let idir = root.join("users").join(uid).join("identities");
                        if idir.exists() {
                            for entry in fs::read_dir(&idir).unwrap() {
                                let entry = entry.unwrap();
                                let path = entry.path();
                                if path.extension().and_then(|s| s.to_str()) == Some("enc") {
                                    let stem = path.file_stem().unwrap().to_string_lossy();
                                    let bytes = fs::read(&path).map(|b| b.len()).unwrap_or(0);
                                    println!("user={} identity={} bytes={}", uid, stem, bytes);
                                }
                            }
                        }
                    }
                }
                KeysAction::Show { id, user } => {
                    let p = root
                        .join("users")
                        .join(&user)
                        .join("identities")
                        .join(format!("{}.enc", id));
                    if !p.exists() {
                        eprintln!("not found");
                        std::process::exit(1);
                    }
                    let bytes = fs::read(&p).unwrap();
                    println!("user={} identity={} bytes={}", user, id, bytes.len());
                }
                KeysAction::Remove { id, user } => {
                    let p = root
                        .join("users")
                        .join(&user)
                        .join("identities")
                        .join(format!("{}.enc", id));
                    if p.exists() {
                        let _ = fs::remove_file(&p);
                        println!("removed {}", id);
                    } else {
                        eprintln!("not found");
                        std::process::exit(1);
                    }
                }
                KeysAction::Import { id, file, user } => {
                    // validate id
                    if sshkma_domain::IdentityId::parse(&id).is_err() {
                        eprintln!("invalid identity id");
                        std::process::exit(1);
                    }
                    let data = fs::read(&file).unwrap();
                    let dir = root.join("users").join(&user).join("identities");
                    let _ = fs::create_dir_all(&dir);
                    let p = dir.join(format!("{}.enc", id));
                    if fs::write(&p, data).is_ok() {
                        println!("imported {} for {}", id, user);
                    } else {
                        eprintln!("write failed");
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Stats => {
            let cfg = load_cfg(&cli.config);
            let root = root_of(&cfg);
            let users = load_index(&root).len();
            let devices = count_files(&root.join("devices"), "toml");
            let sessions = count_files(&root.join("sessions"), "toml");
            let mut identities = 0usize;
            let mut bytes = 0u64;
            let users_dir = root.join("users");
            if users_dir.exists() {
                for entry in fs::read_dir(&users_dir).unwrap() {
                    let entry = entry.unwrap();
                    let idir = entry.path().join("identities");
                    if idir.exists() {
                        for ie in fs::read_dir(&idir).unwrap() {
                            let ie = ie.unwrap();
                            identities += 1;
                            bytes += ie.metadata().map(|m| m.len()).unwrap_or(0);
                        }
                    }
                }
            }
            println!(
                "users={} devices={} sessions={} identities={} identity_bytes={}",
                users, devices, sessions, identities, bytes
            );
        }
        Commands::Doctor => {
            let cfg = load_cfg(&cli.config);
            let root = root_of(&cfg);
            println!("config: {}", cli.config.display());
            println!("storage_root: {} exists={}", root.display(), root.exists());
            println!("doctor: ok");
        }
        Commands::Overview => {
            let cfg = load_cfg(&cli.config);
            let root = root_of(&cfg);
            println!("Users:");
            let idx = load_index(&root);
            for (name, uid) in &idx {
                let ap = root.join("users").join(uid).join("account.toml");
                let (disabled, role) = fs::read_to_string(&ap)
                    .ok()
                    .and_then(|s| toml::from_str::<AccountRecord>(&s).ok())
                    .map(|a| (a.disabled, a.role))
                    .unwrap_or((false, String::new()));
                println!("  {} {} disabled={} role={}", name, uid, disabled, role);
            }
            println!("Pending invites:");
            let dir = root.join("invites");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if dir.exists() {
                for entry in fs::read_dir(&dir).unwrap() {
                    let entry = entry.unwrap();
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                        if let Ok(s) = fs::read_to_string(&path) {
                            if let Ok(inv) = toml::from_str::<sshkma_server::InviteRecord>(&s) {
                                let status = if inv.used_by.is_some() {
                                    "used"
                                } else if now > inv.expires_at {
                                    "expired"
                                } else {
                                    "pending"
                                };
                                if status == "pending" {
                                    println!(
                                        "  {} expires={} role={}",
                                        inv.code, inv.expires_at, inv.role
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        Commands::Version => println!("{}", env!("CARGO_PKG_VERSION")),
    }
}

fn count_files(dir: &Path, ext: &str) -> usize {
    if !dir.exists() {
        return 0;
    }
    fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some(ext))
                .count()
        })
        .unwrap_or(0)
}
