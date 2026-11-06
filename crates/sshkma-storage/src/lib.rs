//! Filesystem-only storage helpers: atomic writes, containment checks, locking.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(String),
    #[error("path traversal or containment violation: {0}")]
    Containment(String),
    #[error("symlink not allowed: {0}")]
    Symlink(String),
    #[error("lock error: {0}")]
    Lock(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

fn io_err(e: std::io::Error) -> StorageError {
    StorageError::Io(e.to_string())
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(io_err)
}

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(io_err)
}

pub fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    atomic_write(path, data)
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir(parent)?;
    let tmp_path = parent.join(format!(
        ".{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(io_err)?;
        f.write_all(data).map_err(io_err)?;
        f.sync_all().map_err(io_err)?;
    }
    fs::rename(&tmp_path, path).map_err(io_err)?;
    // fsync parent best-effort
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.is_empty() {
        return Ok(root.to_path_buf());
    }
    let rel = Path::new(relative);
    for comp in rel.components() {
        match comp {
            Component::Normal(_) => {}
            _ => {
                return Err(StorageError::Containment(format!(
                    "unsafe path component in {}",
                    relative
                )))
            }
        }
    }
    // reject symlink traversal in existing components
    let mut current = root.to_path_buf();
    for comp in rel.components() {
        current.push(comp);
        if let Ok(meta) = fs::symlink_metadata(&current) {
            if meta.file_type().is_symlink() {
                return Err(StorageError::Symlink(current.display().to_string()));
            }
        }
    }
    Ok(root.join(rel))
}

pub fn contains_path(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}

pub fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

pub struct AdvisoryLock {
    file: File,
}

impl AdvisoryLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        ensure_dir(path.parent().unwrap_or_else(|| Path::new(".")))?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(io_err)?;
        file.lock().map_err(|e| StorageError::Lock(e.to_string()))?;
        Ok(Self { file })
    }

    pub fn release(self) -> Result<()> {
        self.file
            .unlock()
            .map_err(|e| StorageError::Lock(e.to_string()))?;
        Ok(())
    }
}

pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn read(&self, relative: &str) -> Result<Vec<u8>> {
        let path = safe_join(&self.root, relative)?;
        read_file(&path)
    }

    pub fn write(&self, relative: &str, data: &[u8]) -> Result<()> {
        let path = safe_join(&self.root, relative)?;
        atomic_write(&path, data)
    }

    pub fn exists(&self, relative: &str) -> bool {
        safe_join(&self.root, relative)
            .map(|p| p.exists())
            .unwrap_or(false)
    }
}

// Aliases
pub fn safe_path(root: &Path, relative: &str) -> Result<PathBuf> {
    safe_join(root, relative)
}

pub fn atomic_write_file(path: &Path, data: &[u8]) -> Result<()> {
    atomic_write(path, data)
}
