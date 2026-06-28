//! The dotprot commands: setup, lock, unlock, and the bare-toggle dispatcher.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::op::OpBackend;
use crate::prot::{self, ProtData};

pub const VAULT_NAME: &str = ".prot";
const PROT_FILE: &str = ".prot";
const VAULT_DESCRIPTION: &str = "Managed by dotprot — protected .env and config files.";

fn prot_path(cwd: &Path) -> PathBuf {
    cwd.join(PROT_FILE)
}

/// Expand the user's patterns against the working dir into concrete relative
/// file paths. The `.prot` file itself is always excluded. Globs only match
/// files that exist on disk (used by lock). Results are sorted and de-duped.
fn expand_patterns(cwd: &Path, patterns: &[String]) -> Result<Vec<String>> {
    let mut matches: BTreeSet<String> = BTreeSet::new();

    for pattern in patterns {
        // Resolve the glob relative to cwd, then store the path back as a
        // cwd-relative string so document titles and .prot keys stay stable.
        let abs_pattern = cwd.join(pattern);
        let abs_pattern = abs_pattern.to_string_lossy();
        for entry in glob::glob(&abs_pattern)? {
            let path = match entry {
                Ok(p) => p,
                Err(e) => {
                    // An entry we couldn't read (e.g. a permission error while
                    // walking). Don't abort the whole lock over one bad entry,
                    // but never swallow it silently: a file the user meant to
                    // protect could otherwise be skipped while they believe it
                    // was handled, leaving a secret in plaintext on disk.
                    eprintln!("  warning: could not read {} — skipped", e.path().display());
                    continue;
                }
            };
            if !path.is_file() {
                continue;
            }
            if let Ok(rel) = path.strip_prefix(cwd) {
                let rel = rel.to_string_lossy().to_string();
                if rel != PROT_FILE {
                    matches.insert(rel);
                }
            }
        }
    }

    Ok(matches.into_iter().collect())
}

/// A 1Password title that's unique per absolute file path.
fn document_title(cwd: &Path, rel_file: &str) -> String {
    cwd.join(rel_file).to_string_lossy().to_string()
}

/// Whether a protected file is present on disk.
///
/// Uses `try_exists` rather than `exists` so a "couldn't determine" (e.g. a
/// permission error) is not silently read as "absent". An indeterminate result
/// is treated as **present**, which is the safe bias for every caller: unlock
/// then declines to overwrite a file it can't read, and toggle steers away from
/// a destructive restore when it can't be sure the original is gone.
fn file_exists(p: &Path) -> bool {
    p.try_exists().unwrap_or(true)
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

pub fn setup(op: &impl OpBackend) -> Result<()> {
    op.assert_signed_in()?;

    if let Some(id) = op.find_vault(VAULT_NAME)? {
        println!("Vault \"{VAULT_NAME}\" already exists ({id}).");
        return Ok(());
    }

    let id = op.create_vault(VAULT_NAME, VAULT_DESCRIPTION)?;
    println!("Created vault \"{VAULT_NAME}\" ({id}).");
    Ok(())
}

/// Resolve the vault ID, finding it if not already cached in `prot`. If the
/// vault doesn't exist in 1Password yet, create it (a one-time action) and
/// announce it clearly so the user knows a vault was made in their account.
fn ensure_vault(op: &impl OpBackend, prot: &mut ProtData) -> Result<String> {
    if let Some(v) = &prot.vault {
        return Ok(v.clone());
    }
    let id = match op.find_vault(VAULT_NAME)? {
        Some(found) => found,
        None => {
            let created = op.create_vault(VAULT_NAME, VAULT_DESCRIPTION)?;
            println!("Created 1Password vault \"{VAULT_NAME}\" ({created}).");
            println!("(one-time setup — future runs reuse it)");
            created
        }
    };
    prot.vault = Some(id.clone());
    Ok(id)
}

// ---------------------------------------------------------------------------
// lock
// ---------------------------------------------------------------------------

/// Lock the protected files into 1Password.
///
/// With `keep = true`, files are uploaded and verified but NOT deleted from
/// disk — useful for confirming the vault copy yourself before trusting
/// dotprot to remove anything.
pub fn lock(op: &impl OpBackend, cwd: &Path, keep: bool) -> Result<()> {
    op.assert_signed_in()?;

    let file = prot_path(cwd);
    let mut prot = match prot::read(&file)? {
        Some(p) => p,
        None => {
            // Auto-create on first lock, defaulting to .env*.
            let p = ProtData::empty();
            prot::write(&file, &p)?;
            println!("Created {PROT_FILE} (protecting: {}).", p.patterns.join(", "));
            p
        }
    };

    let vault = ensure_vault(op, &mut prot)?;
    let files = expand_patterns(cwd, &prot.patterns)?;

    if files.is_empty() {
        bail!(
            "No files match the patterns in {PROT_FILE} ({}).\n\
             Either the files are already locked, or no matching files exist.",
            prot.patterns.join(", ")
        );
    }

    let mut locked = 0;
    for rel_file in &files {
        let abs_file = cwd.join(rel_file);
        let content = fs::read(&abs_file)?;
        let title = document_title(cwd, rel_file);
        let file_name = Path::new(rel_file)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| rel_file.clone());

        // op rejects empty stdin/empty files; a zero-byte file can't be stored
        // as a document. Skip it rather than fail.
        if content.is_empty() {
            println!("  skip {rel_file} (empty file — nothing to protect)");
            continue;
        }

        // Re-lock if we already have a doc id for this pattern entry; otherwise
        // create a fresh document.
        let id = match prot.document_id(rel_file) {
            Some(existing) => {
                let existing = existing.to_string();
                op.edit_document(&vault, &existing, &title, &file_name, &content)?;
                existing
            }
            None => op.create_document(&vault, &title, &file_name, &content)?,
        };

        // Verify-then-delete: read the document back and byte-compare before we
        // ever remove the original from disk.
        let round_trip = op.get_document(&vault, &id)?;
        if round_trip != content {
            bail!(
                "Verification failed for {rel_file}: the copy in 1Password does not \
                 match the file on disk. Left {rel_file} in place; nothing deleted."
            );
        }

        prot.set_document(rel_file, &id);
        // Persist the document id (and vault) immediately, before deleting the
        // file. If a later file fails, everything locked so far is recorded in
        // .prot and recoverable.
        prot::write(&file, &prot)?;
        if keep {
            println!("  uploaded {rel_file} -> 1Password (kept on disk)");
        } else {
            fs::remove_file(&abs_file)?;
            println!("  locked {rel_file} -> 1Password");
        }
        locked += 1;
    }

    if keep {
        println!(
            "Uploaded {locked} file(s) to vault \"{VAULT_NAME}\". \
             Originals kept on disk (--keep); run `dotprot lock` to remove them."
        );
    } else {
        println!("Locked {locked} file(s) into vault \"{VAULT_NAME}\".");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// unlock
// ---------------------------------------------------------------------------

pub fn unlock(op: &impl OpBackend, cwd: &Path) -> Result<()> {
    op.assert_signed_in()?;

    let file = prot_path(cwd);
    let mut prot = match prot::read(&file)? {
        Some(p) => p,
        None => bail!("No {PROT_FILE} found in {}. Nothing to unlock.", cwd.display()),
    };
    if prot.documents.is_empty() {
        bail!("{PROT_FILE} has no locked documents recorded. Nothing to unlock.");
    }

    let vault = ensure_vault(op, &mut prot)?;

    let mut unlocked = 0;
    for (rel_file, id) in &prot.documents {
        let abs_file = cwd.join(rel_file);
        if file_exists(&abs_file) {
            println!("  skip {rel_file} (already present on disk)");
            continue;
        }
        let content = op.get_document(&vault, id)?;
        write_owner_only(&abs_file, &content)?;
        unlocked += 1;
        println!("  unlocked {rel_file} <- 1Password");
    }

    // Documents are intentionally kept in 1Password so the directory can
    // re-lock later. We leave prot.documents intact.
    println!("Unlocked {unlocked} file(s) from vault \"{VAULT_NAME}\".");
    Ok(())
}

/// Write a restored file with owner-only (0600) permissions on Unix.
fn write_owner_only(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(content)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// bare `dotprot` — infer lock vs unlock from current state
// ---------------------------------------------------------------------------

pub fn toggle(op: &impl OpBackend, cwd: &Path, keep: bool) -> Result<()> {
    let file = prot_path(cwd);
    let prot = prot::read(&file)?;

    // No .prot at all (or nothing recorded) -> first run -> lock.
    let prot = match prot {
        Some(p) if !p.documents.is_empty() => p,
        _ => return lock(op, cwd, keep),
    };

    // Compare recorded documents against what's on disk.
    let mut present: Vec<&str> = Vec::new();
    let mut absent: Vec<&str> = Vec::new();
    for (rel_file, _) in &prot.documents {
        if file_exists(&cwd.join(rel_file)) {
            present.push(rel_file);
        } else {
            absent.push(rel_file);
        }
    }

    if !present.is_empty() && !absent.is_empty() {
        bail!(
            "Mixed state: some recorded files are present on disk and others are missing, \
             so it's unclear whether you mean to lock or unlock.\n\
             \x20 present: {}\n\
             \x20 missing: {}\n\
             Use `dotprot lock` or `dotprot unlock` explicitly to resolve the ambiguity.",
            present.join(", "),
            absent.join(", "),
        );
    }

    if !absent.is_empty() {
        // Everything recorded is missing -> restore. (--keep is a no-op here.)
        unlock(op, cwd)
    } else {
        // Everything recorded is present -> re-lock.
        lock(op, cwd, keep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::OpBackend;
    use std::cell::RefCell;

    /// A fake [`OpBackend`] that records each call and stores "uploaded"
    /// document bytes in memory, so tests can drive lock/unlock without a live
    /// vault and assert the verify-then-delete ordering.
    struct MockOp {
        /// Ordered log of operations, for asserting sequencing.
        calls: RefCell<Vec<String>>,
        /// id -> bytes, as if stored in 1Password.
        docs: RefCell<Vec<(String, Vec<u8>)>>,
        /// When true, `get_document` returns bytes that differ from what was
        /// uploaded — simulating a corrupted or partial upload on read-back.
        corrupt_readback: bool,
    }

    impl MockOp {
        fn new() -> Self {
            MockOp {
                calls: RefCell::new(Vec::new()),
                docs: RefCell::new(Vec::new()),
                corrupt_readback: false,
            }
        }

        fn corrupting() -> Self {
            let mut m = Self::new();
            m.corrupt_readback = true;
            m
        }

        fn store(&self, id: &str, content: &[u8]) {
            let mut docs = self.docs.borrow_mut();
            if let Some(entry) = docs.iter_mut().find(|(i, _)| i == id) {
                entry.1 = content.to_vec();
            } else {
                docs.push((id.to_string(), content.to_vec()));
            }
        }
    }

    impl OpBackend for MockOp {
        fn assert_signed_in(&self) -> Result<()> {
            self.calls.borrow_mut().push("assert_signed_in".into());
            Ok(())
        }
        fn find_vault(&self, _name: &str) -> Result<Option<String>> {
            Ok(Some("VAULT".into()))
        }
        fn create_vault(&self, _name: &str, _description: &str) -> Result<String> {
            Ok("VAULT".into())
        }
        fn create_document(
            &self,
            _vault: &str,
            _title: &str,
            _file_name: &str,
            content: &[u8],
        ) -> Result<String> {
            self.calls.borrow_mut().push("create_document".into());
            let id = format!("DOC{}", self.docs.borrow().len());
            self.store(&id, content);
            Ok(id)
        }
        fn edit_document(
            &self,
            _vault: &str,
            id: &str,
            _title: &str,
            _file_name: &str,
            content: &[u8],
        ) -> Result<()> {
            self.calls.borrow_mut().push("edit_document".into());
            self.store(id, content);
            Ok(())
        }
        fn get_document(&self, _vault: &str, id: &str) -> Result<Vec<u8>> {
            self.calls.borrow_mut().push("get_document".into());
            let bytes = self
                .docs
                .borrow()
                .iter()
                .find(|(i, _)| i == id)
                .map(|(_, b)| b.clone())
                .unwrap_or_default();
            if self.corrupt_readback {
                // Return something that won't match what's on disk.
                Ok(b"CORRUPTED".to_vec())
            } else {
                Ok(bytes)
            }
        }
    }

    /// Write a `.prot` with a single `.env` pattern and a real `.env` file.
    fn setup_dir(secret: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), secret).unwrap();
        let mut prot = ProtData::empty();
        prot.vault = Some("VAULT".to_string());
        prot::write(&dir.path().join(PROT_FILE), &prot).unwrap();
        dir
    }

    #[test]
    fn lock_deletes_only_after_successful_readback() {
        let dir = setup_dir(b"SECRET=1\n");
        let op = MockOp::new();

        lock(&op, dir.path(), false).unwrap();

        // File is gone, but only because the round-trip matched.
        assert!(!dir.path().join(".env").exists(), ".env should be deleted");

        // The read-back (get_document) must precede nothing destructive on disk,
        // and must come after the upload. Verify the upload->verify ordering.
        let calls = op.calls.borrow();
        let upload = calls.iter().position(|c| c == "create_document").unwrap();
        let verify = calls.iter().position(|c| c == "get_document").unwrap();
        assert!(
            upload < verify,
            "upload must happen before read-back verify"
        );

        // The document id was persisted to .prot.
        let prot = prot::read(&dir.path().join(PROT_FILE)).unwrap().unwrap();
        assert_eq!(prot.document_id(".env"), Some("DOC0"));
    }

    #[test]
    fn lock_keeps_file_when_readback_mismatches() {
        let dir = setup_dir(b"SECRET=1\n");
        let op = MockOp::corrupting();

        // The cardinal rule: a mismatched read-back must NOT delete the file.
        let err = lock(&op, dir.path(), false).unwrap_err();

        assert!(
            dir.path().join(".env").exists(),
            ".env must survive a failed verification"
        );
        assert!(
            err.to_string().contains("Verification failed"),
            "expected a verification-failed error, got: {err}"
        );
        // And we never recorded a (bogus) success in .prot.
        let prot = prot::read(&dir.path().join(PROT_FILE)).unwrap().unwrap();
        assert_eq!(prot.document_id(".env"), None);
    }

    #[test]
    fn lock_with_keep_uploads_and_verifies_but_does_not_delete() {
        let dir = setup_dir(b"SECRET=1\n");
        let op = MockOp::new();

        lock(&op, dir.path(), true).unwrap();

        assert!(
            dir.path().join(".env").exists(),
            "--keep must leave the file on disk"
        );
        // It was still uploaded and verified (id recorded), so the user can
        // confirm the vault copy before trusting deletion.
        let calls = op.calls.borrow();
        assert!(calls.iter().any(|c| c == "get_document"), "must verify");
        let prot = prot::read(&dir.path().join(PROT_FILE)).unwrap().unwrap();
        assert_eq!(prot.document_id(".env"), Some("DOC0"));
    }

    #[test]
    fn unlock_restores_file_with_owner_only_mode() {
        let dir = setup_dir(b"SECRET=restored\n");
        let op = MockOp::new();

        // Lock first (file gets deleted), then unlock to restore it.
        lock(&op, dir.path(), false).unwrap();
        assert!(!dir.path().join(".env").exists());

        unlock(&op, dir.path()).unwrap();

        let restored = fs::read(dir.path().join(".env")).unwrap();
        assert_eq!(restored, b"SECRET=restored\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(".env"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "restored file must be 0600");
        }
    }
}
