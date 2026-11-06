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

use sshkma_storage::{safe_path, AdvisoryLock};

#[test]
fn safe_join_rejects_traversal() {
    let root = std::path::PathBuf::from("/tmp/scratchpad/root");
    assert!(safe_join(&root, "../evil").is_err());
    assert!(safe_join(&root, "a/../b").is_err());
    assert!(safe_join(&root, "/abs").is_err());
    let ok = safe_join(&root, "a/b.txt").unwrap();
    assert_eq!(ok, root.join("a/b.txt"));
}

#[test]
fn filestore_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = FileStore::new(tmp.path().to_path_buf());
    store.write("sub/file.txt", b"hello").unwrap();
    assert!(store.exists("sub/file.txt"));
    assert_eq!(store.read("sub/file.txt").unwrap(), b"hello");
    assert!(!store.exists("nope.txt"));
}

#[test]
fn advisory_lock_acquire_release() {
    let tmp = tempfile::TempDir::new().unwrap();
    let lockpath = tmp.path().join("lock");
    let lock = AdvisoryLock::acquire(&lockpath).unwrap();
    lock.release().unwrap();
}

#[test]
fn is_symlink_false_for_regular() {
    let tmp = tempfile::TempDir::new().unwrap();
    let p = tmp.path().join("f");
    std::fs::write(&p, b"x").unwrap();
    assert!(!sshkma_storage::is_symlink(&p));
}

#[test]
fn safe_path_alias() {
    let root = std::path::PathBuf::from("/r");
    assert_eq!(safe_path(&root, "a").unwrap(), root.join("a"));
}
