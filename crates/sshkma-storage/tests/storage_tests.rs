use sshkma_storage::{atomic_write, safe_join, FileStore};
use tempfile::TempDir;

#[test]
fn atomic_write_and_read() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("file.txt");
    atomic_write(&path, b"hello").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"hello");
}

#[test]
fn path_containment() {
    let dir = TempDir::new().unwrap();
    assert!(safe_join(dir.path(), "../evil").is_err());
    assert!(safe_join(dir.path(), "a/b").is_ok());
}

#[test]
fn file_store_roundtrip() {
    let dir = TempDir::new().unwrap();
    let store = FileStore::new(dir.path().to_path_buf());
    store.write("sub/data.txt", b"xyz").unwrap();
    assert_eq!(store.read("sub/data.txt").unwrap(), b"xyz");
    assert!(store.exists("sub/data.txt"));
}

#[test]
fn symlink_rejected() {
    #[cfg(unix)]
    {
        let dir = TempDir::new().unwrap();
        let link = dir.path().join("link");
        let _ = std::os::unix::fs::symlink("/etc", &link);
        assert!(safe_join(dir.path(), "link/secret").is_err());
    }
}
