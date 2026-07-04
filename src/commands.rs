//! The dotprot commands: setup, lock, unlock, and the bare-toggle dispatcher.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::op::OpBackend;
use crate::prot::{self, ProtData};

pub const VAULT_NAME: &str = ".prot";
const PROT_FILE: &str = ".prot";
const VAULT_DESCRIPTION: &str = "Managed by dotprot — protected .env and config files.";

/// Ensure the user is signed in to 1Password before running a command.
///
/// The default entry point used by the commands; it asks the user via an
/// interactive terminal prompt. See [`ensure_signed_in_with`] for the testable
/// core that takes the confirmation decision as a parameter.
fn ensure_signed_in(op: &impl OpBackend) -> Result<()> {
    ensure_signed_in_with(op, || {
        prompt_yes_no("You are not signed in to 1Password. Sign in now?")
    })
}

/// Core of [`ensure_signed_in`], with the "should we sign in?" decision injected
/// so it can be exercised without a real terminal.
///
/// If already signed in, returns immediately. Otherwise `confirm` decides
/// whether to run `op signin`; the production path makes that an interactive
/// prompt that is itself a no (false) in non-interactive contexts, so CI and
/// pipes never hang — they fall back to the same clear error as before.
fn ensure_signed_in_with(
    op: &impl OpBackend,
    confirm: impl FnOnce() -> Result<bool>,
) -> Result<()> {
    if op.is_signed_in()? {
        return Ok(());
    }

    if !confirm()? {
        bail!("You are not signed in to 1Password. Run `op signin` first.");
    }

    op.sign_in()?;

    // `op signin` reported success; confirm the session is actually usable
    // before we proceed to touch any protected files.
    if op.is_signed_in()? {
        Ok(())
    } else {
        bail!("Still not signed in to 1Password after `op signin`. Aborting.");
    }
}

/// Ask a yes/no question on the terminal, defaulting to "no".
///
/// Returns `Ok(false)` without prompting when stdin/stdout isn't an interactive
/// terminal, so non-interactive runs (CI, pipes) fail fast with a clear error
/// rather than blocking on input that will never arrive.
fn prompt_yes_no(question: &str) -> Result<bool> {
    use std::io::{IsTerminal, Write};

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Ok(false);
    }

    print!("{question} [y/N] ");
    std::io::stdout().flush().ok();

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

fn prot_path(cwd: &Path) -> PathBuf {
    cwd.join(PROT_FILE)
}

/// Expand the user's patterns against the working dir into concrete relative
/// file paths. The `.prot` file itself is always excluded. Globs only match
/// files that exist on disk (used by lock). Results are sorted and de-duped.
fn expand_patterns(cwd: &Path, patterns: &[String]) -> Result<Vec<String>> {
    let mut matches: BTreeSet<String> = BTreeSet::new();

    // The working directory becomes the literal prefix of every glob, so any
    // metacharacters in it (`[`, `?`, `*` — brackets in directory names are
    // real) must be escaped or matching silently fails.
    let escaped_cwd = glob::Pattern::escape(&cwd.to_string_lossy());

    for pattern in patterns {
        // Resolve the glob relative to cwd, then store the path back as a
        // cwd-relative string so document titles and .prot keys stay stable.
        // A rooted/absolute pattern stands alone (Path::join semantics — the
        // base is replaced): gluing it onto cwd would silently re-anchor
        // `/shared/x.env` at `<cwd>/shared/x.env`, a different file that
        // could then be locked and deleted.
        let abs_pattern = if Path::new(pattern).has_root() {
            cwd.join(pattern).to_string_lossy().into_owned()
        } else {
            format!("{escaped_cwd}{}{pattern}", std::path::MAIN_SEPARATOR)
        };
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
            // A pattern like `../shared/.env` can match outside the working
            // directory. strip_prefix is lexical — `cwd/../x` still "strips" —
            // so any remaining `..` component also means the file is outside.
            // dotprot only protects files under cwd; say so loudly, or the
            // user will believe the file is locked while it sits in plaintext.
            let rel = path.strip_prefix(cwd).ok().filter(|rel| {
                !rel.components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            });
            let Some(rel) = rel else {
                eprintln!(
                    "  warning: {} is outside {} — skipped (dotprot only \
                     protects files inside the working directory)",
                    path.display(),
                    cwd.display()
                );
                continue;
            };
            let rel = rel.to_string_lossy().to_string();
            if rel.chars().any(|c| c.is_control()) || rel != rel.trim() {
                // .prot is a line-oriented format whose parser trims each
                // recorded key: a control character (e.g. a newline) would
                // corrupt the line, and leading/trailing whitespace (a file
                // named `.env `) would round-trip to a different key — either
                // way the document id is unrecoverable from .prot after the
                // original file is already deleted.
                eprintln!(
                    "  warning: {rel:?} has control characters or leading/\
                     trailing whitespace in its name — skipped (unsupported \
                     in {PROT_FILE})"
                );
                continue;
            }
            if rel != PROT_FILE {
                matches.insert(rel);
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
    ensure_signed_in(op)?;

    if let Some(id) = op.find_vault(VAULT_NAME)? {
        println!("Vault \"{VAULT_NAME}\" already exists ({id}).");
        return Ok(());
    }

    let id = op.create_vault(VAULT_NAME, VAULT_DESCRIPTION)?;
    println!("Created vault \"{VAULT_NAME}\" ({id}).");
    Ok(())
}

/// Resolve the 1Password vault ID to use for this run.
///
/// If `.prot` records a vault ID, verify it still refers to a vault actually
/// named ".prot" before using it. The ID is user-editable (and often committed
/// to version control), so trusting it blindly would let a tampered or
/// copy-pasted value silently point dotprot's document writes at some other
/// vault in the account.
///
/// Otherwise look the vault up by name. `create_if_missing` decides whether a
/// missing vault is created (lock — a one-time action, announced clearly) or
/// an error (unlock — a fresh empty vault could never contain the recorded
/// documents, so creating one only muddies the account).
fn resolve_vault(
    op: &impl OpBackend,
    prot: &mut ProtData,
    create_if_missing: bool,
) -> Result<String> {
    if let Some(id) = &prot.vault {
        return match op.vault_name(id)? {
            Some(name) if name == VAULT_NAME => Ok(id.clone()),
            Some(name) => bail!(
                "The vault recorded in {PROT_FILE} ({id}) is named \"{name}\", not \
                 \"{VAULT_NAME}\". Refusing to touch it. If that vault was renamed, \
                 rename it back; if the ID is stale, remove the `vault:` line from \
                 {PROT_FILE} and rerun."
            ),
            None => bail!(
                "The vault recorded in {PROT_FILE} ({id}) was not found in your \
                 1Password account. If it was deleted, remove the `vault:` line \
                 from {PROT_FILE} and rerun."
            ),
        };
    }
    let id = match op.find_vault(VAULT_NAME)? {
        Some(found) => found,
        None if create_if_missing => {
            let created = op.create_vault(VAULT_NAME, VAULT_DESCRIPTION)?;
            println!("Created 1Password vault \"{VAULT_NAME}\" ({created}).");
            println!("(one-time setup — future runs reuse it)");
            created
        }
        None => bail!(
            "No \"{VAULT_NAME}\" vault found in your 1Password account, but \
             {PROT_FILE} has documents recorded. Nothing to restore from."
        ),
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
    ensure_signed_in(op)?;

    let file = prot_path(cwd);
    let mut prot = match prot::read(&file)? {
        Some(p) => p,
        None => {
            // Auto-create on first lock, defaulting to .env*.
            let p = ProtData::empty();
            prot::write(&file, &p)?;
            println!(
                "Created {PROT_FILE} (protecting: {}).",
                p.patterns.join(", ")
            );
            p
        }
    };

    let vault = resolve_vault(op, &mut prot, true)?;
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
            // The upload and read-back take real time (network round-trips);
            // the file may have been modified meanwhile, in which case the
            // verified vault copy is already stale and deleting would destroy
            // bytes that were never uploaded. Re-read and only delete if the
            // file is still exactly what we stored.
            let current = fs::read(&abs_file)
                .with_context(|| format!("re-reading {rel_file} before delete"))?;
            if current != content {
                bail!(
                    "{rel_file} changed on disk while it was being uploaded, so the \
                     copy in 1Password is already stale. Left {rel_file} in place — \
                     run `dotprot lock` again to store the new contents."
                );
            }
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
    ensure_signed_in(op)?;

    let file = prot_path(cwd);
    let mut prot = match prot::read(&file)? {
        Some(p) => p,
        None => bail!(
            "No {PROT_FILE} found in {}. Nothing to unlock.",
            cwd.display()
        ),
    };
    if prot.documents.is_empty() {
        bail!("{PROT_FILE} has no locked documents recorded. Nothing to unlock.");
    }

    // Validate every recorded path before restoring anything, so a tampered
    // entry aborts the run atomically instead of after a partial restore.
    for (rel_file, _) in &prot.documents {
        validate_restore_path(rel_file)?;
    }

    let vault = resolve_vault(op, &mut prot, false)?;

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
///
/// Opens with `create_new` (O_CREAT|O_EXCL): the open fails if anything —
/// including a dangling symlink, which `file_exists` reads as "absent" —
/// already sits at the path. A plain `create(true)` would follow such a
/// symlink and write the secret to wherever it points.
fn write_owner_only(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| {
        format!(
            "refusing to write {} — something already exists at that path \
             (possibly a symlink); remove it and run `dotprot unlock` again",
            path.display()
        )
    })?;
    f.write_all(content)?;
    Ok(())
}

/// Reject recorded file paths that could escape the working directory.
///
/// Lock only ever records cwd-relative paths, but `.prot` is user-editable and
/// often committed to version control, so unlock must not trust it: an entry
/// like `doc ../../.bashrc: <id>` would otherwise restore vault content to an
/// arbitrary path outside the project.
///
/// This is an allowlist — every component must be a plain name — because a
/// blocklist under-enumerates: a rooted-but-driveless Windows path like
/// `\Users\x` is not absolute and has no `Prefix` or `ParentDir` component,
/// yet `cwd.join()` replaces everything except the drive letter with it.
fn validate_restore_path(rel_file: &str) -> Result<()> {
    use std::path::Component;
    let path = Path::new(rel_file);
    if path.components().next().is_none()
        || !path.components().all(|c| matches!(c, Component::Normal(_)))
    {
        bail!(
            "Refusing to restore \"{rel_file}\": {PROT_FILE} entries must be \
             plain relative paths inside this directory (no absolute or rooted \
             paths, no `..`)."
        );
    }
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

    // The recorded paths are untrusted input here too: they steer the
    // lock-vs-unlock decision and are echoed in the mixed-state message, so a
    // tampered entry could otherwise probe paths outside the project.
    for (rel_file, _) in &prot.documents {
        validate_restore_path(rel_file)?;
    }

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
        /// Current sign-in state. `sign_in()` flips it to true, modelling a
        /// successful `op signin`.
        signed_in: RefCell<bool>,
        /// When true, `sign_in()` does NOT flip `signed_in` — modelling a user
        /// who cancels the auth or whose session still isn't usable afterward.
        signin_fails: bool,
        /// When set, `get_document` rewrites this (path, bytes) on disk —
        /// simulating the protected file being modified by something else
        /// during the upload/verify round-trip.
        rewrite_on_get: Option<(PathBuf, Vec<u8>)>,
        /// What `vault_name` reports for any ID: the vault's current name, or
        /// `None` for a vault that no longer exists.
        vault_name_response: Option<String>,
        /// What `find_vault` reports: the vault's ID, or `None` when no vault
        /// named ".prot" exists in the account.
        find_vault_response: Option<String>,
    }

    impl MockOp {
        fn new() -> Self {
            MockOp {
                calls: RefCell::new(Vec::new()),
                docs: RefCell::new(Vec::new()),
                corrupt_readback: false,
                signed_in: RefCell::new(true),
                signin_fails: false,
                rewrite_on_get: None,
                vault_name_response: Some(VAULT_NAME.to_string()),
                find_vault_response: Some("VAULT".to_string()),
            }
        }

        fn corrupting() -> Self {
            let mut m = Self::new();
            m.corrupt_readback = true;
            m
        }

        /// A backend that starts signed out. `sign_in()` will flip it to
        /// signed-in unless `signin_fails` is also set.
        fn signed_out() -> Self {
            let m = Self::new();
            *m.signed_in.borrow_mut() = false;
            m
        }

        fn called(&self, name: &str) -> bool {
            self.calls.borrow().iter().any(|c| c == name)
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
        fn is_signed_in(&self) -> Result<bool> {
            self.calls.borrow_mut().push("is_signed_in".into());
            Ok(*self.signed_in.borrow())
        }
        fn sign_in(&self) -> Result<()> {
            self.calls.borrow_mut().push("sign_in".into());
            if !self.signin_fails {
                *self.signed_in.borrow_mut() = true;
            }
            Ok(())
        }
        fn find_vault(&self, _name: &str) -> Result<Option<String>> {
            self.calls.borrow_mut().push("find_vault".into());
            Ok(self.find_vault_response.clone())
        }
        fn vault_name(&self, _id: &str) -> Result<Option<String>> {
            self.calls.borrow_mut().push("vault_name".into());
            Ok(self.vault_name_response.clone())
        }
        fn create_vault(&self, _name: &str, _description: &str) -> Result<String> {
            self.calls.borrow_mut().push("create_vault".into());
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
            if let Some((path, bytes)) = &self.rewrite_on_get {
                fs::write(path, bytes).unwrap();
            }
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

    #[test]
    fn lock_keeps_file_that_changed_during_upload() {
        let dir = setup_dir(b"SECRET=1\n");
        let mut op = MockOp::new();
        // The vault copy round-trips fine, but the file on disk is rewritten
        // during the verify step — deleting it would lose the new contents.
        op.rewrite_on_get = Some((dir.path().join(".env"), b"SECRET=2\n".to_vec()));

        let err = lock(&op, dir.path(), false).unwrap_err();

        assert!(
            err.to_string().contains("changed on disk"),
            "expected a changed-on-disk error, got: {err}"
        );
        assert_eq!(
            fs::read(dir.path().join(".env")).unwrap(),
            b"SECRET=2\n",
            "the modified file must survive untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unlock_refuses_to_write_through_dangling_symlink() {
        let dir = setup_dir(b"SECRET=1\n");
        let op = MockOp::new();
        lock(&op, dir.path(), false).unwrap();

        // Plant a dangling symlink where .env used to be. `file_exists` reads
        // it as absent (try_exists follows links), so unlock proceeds — but the
        // open must refuse to write through the link.
        let target = dir.path().join("attacker-target");
        std::os::unix::fs::symlink(&target, dir.path().join(".env")).unwrap();

        let err = unlock(&op, dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("refusing to write"),
            "expected a refusal error, got: {err:#}"
        );
        assert!(
            !target.exists(),
            "secret must not be written through the symlink"
        );
    }

    #[test]
    fn unlock_rejects_paths_that_escape_the_directory() {
        let dir = setup_dir(b"SECRET=1\n");
        let op = MockOp::new();
        lock(&op, dir.path(), false).unwrap();

        // Simulate a tampered .prot: rewrite the recorded entry to a traversal
        // path pointing outside the working directory.
        let mut prot = prot::read(&dir.path().join(PROT_FILE)).unwrap().unwrap();
        let id = prot.document_id(".env").unwrap().to_string();
        prot.documents = vec![("../escaped.env".to_string(), id)];
        prot::write(&dir.path().join(PROT_FILE), &prot).unwrap();

        let err = unlock(&op, dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("Refusing to restore"),
            "expected a traversal refusal, got: {err}"
        );
        assert!(
            !dir.path().join("../escaped.env").exists(),
            "nothing may be written outside the working directory"
        );
    }

    #[test]
    fn validate_restore_path_allows_only_plain_relative_paths() {
        assert!(validate_restore_path(".env").is_ok());
        assert!(validate_restore_path("nested/dir/.env").is_ok());
        assert!(validate_restore_path("../up.env").is_err());
        assert!(validate_restore_path("/abs/path.env").is_err());
        assert!(validate_restore_path("a/../b.env").is_err());
        assert!(validate_restore_path("").is_err());
    }

    /// On Windows, `\Users\x` is rooted but NOT absolute and has no Prefix or
    /// ParentDir component — `cwd.join()` would replace everything except the
    /// drive letter with it. The allowlist must reject it. (Runs on the
    /// windows-latest CI job; on Unix a backslash is an ordinary filename
    /// character, so this shape isn't parseable the same way.)
    #[cfg(windows)]
    #[test]
    fn validate_restore_path_rejects_rooted_driveless_windows_paths() {
        assert!(validate_restore_path(r"\Users\victim\startup.bat").is_err());
        assert!(validate_restore_path(r"C:\Users\victim\x").is_err());
        assert!(validate_restore_path(r"C:relative.env").is_err());
    }

    #[test]
    fn unlock_validates_all_paths_before_restoring_anything() {
        let dir = setup_dir(b"SECRET=1\n");
        let op = MockOp::new();
        lock(&op, dir.path(), false).unwrap();

        // Tamper: a good entry first, a traversal entry second. Unlock must
        // fail atomically — the good file must NOT be restored first.
        let mut prot = prot::read(&dir.path().join(PROT_FILE)).unwrap().unwrap();
        let id = prot.document_id(".env").unwrap().to_string();
        prot.documents = vec![
            (".env".to_string(), id.clone()),
            ("../evil".to_string(), id),
        ];
        prot::write(&dir.path().join(PROT_FILE), &prot).unwrap();

        let err = unlock(&op, dir.path()).unwrap_err();

        assert!(err.to_string().contains("Refusing to restore"));
        assert!(
            !dir.path().join(".env").exists(),
            "a tampered .prot must abort before any file is restored"
        );
    }

    #[test]
    fn toggle_rejects_tampered_document_paths() {
        let dir = setup_dir(b"SECRET=1\n");
        let op = MockOp::new();
        lock(&op, dir.path(), false).unwrap();

        // A tampered absolute entry must not let toggle probe (and echo the
        // existence of) paths outside the project.
        let mut prot = prot::read(&dir.path().join(PROT_FILE)).unwrap().unwrap();
        let id = prot.document_id(".env").unwrap().to_string();
        prot.documents.push(("/etc/hosts".to_string(), id));
        prot::write(&dir.path().join(PROT_FILE), &prot).unwrap();

        let err = toggle(&op, dir.path(), false).unwrap_err();
        assert!(
            err.to_string().contains("Refusing to restore"),
            "expected toggle to reject the tampered path, got: {err}"
        );
    }

    // --- pattern expansion --------------------------------------------------

    #[test]
    fn lock_works_in_directory_with_glob_metacharacters() {
        let outer = tempfile::tempdir().unwrap();
        let dir = outer.path().join("we[i]rd dir");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join(".env"), b"SECRET=1\n").unwrap();
        let mut prot = ProtData::empty();
        prot.vault = Some("VAULT".to_string());
        prot::write(&dir.join(PROT_FILE), &prot).unwrap();

        let op = MockOp::new();
        lock(&op, &dir, false).unwrap();

        assert!(
            !dir.join(".env").exists(),
            ".env must lock even when the project path contains [ ] metacharacters"
        );
    }

    #[test]
    fn expand_patterns_skips_matches_outside_the_working_directory() {
        let outer = tempfile::tempdir().unwrap();
        let dir = outer.path().join("project");
        fs::create_dir(&dir).unwrap();
        fs::write(outer.path().join("outside.env"), b"SECRET=1\n").unwrap();

        let matches = expand_patterns(&dir, &["../outside.env".to_string()]).unwrap();

        assert!(
            matches.is_empty(),
            "files outside cwd must not be treated as protectable: {matches:?}"
        );
    }

    #[test]
    fn expand_patterns_does_not_reanchor_absolute_patterns_under_cwd() {
        // Regression test: an absolute pattern must keep Path::join semantics
        // (the pattern stands alone). Concatenating it onto cwd would make
        // `/shared/x.env` match `<cwd>/shared/x.env` — a different file that
        // lock would then upload and DELETE.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("shared")).unwrap();
        fs::write(dir.path().join("shared/x.env"), b"SECRET=1\n").unwrap();

        let matches = expand_patterns(dir.path(), &["/shared/x.env".to_string()]).unwrap();

        assert!(
            matches.is_empty(),
            "an absolute pattern must not match a cwd-relative file: {matches:?}"
        );
    }

    #[test]
    fn expand_patterns_matches_absolute_pattern_inside_cwd() {
        // An absolute pattern that names a file inside the project worked
        // before the glob-escaping change and must keep working.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), b"SECRET=1\n").unwrap();
        let abs = dir.path().join(".env").to_string_lossy().to_string();

        let matches = expand_patterns(dir.path(), &[abs]).unwrap();

        assert_eq!(matches, vec![".env".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn expand_patterns_skips_filenames_with_control_characters() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env\nx"), b"SECRET=1\n").unwrap();
        fs::write(dir.path().join(".env"), b"SECRET=1\n").unwrap();

        let matches = expand_patterns(dir.path(), &[".env*".to_string()]).unwrap();

        assert_eq!(
            matches,
            vec![".env".to_string()],
            "a newline in a filename would corrupt the .prot line format"
        );
    }

    #[cfg(unix)]
    #[test]
    fn expand_patterns_skips_filenames_with_edge_whitespace() {
        // prot::parse trims each recorded key, so a file named `.env ` would
        // be locked and deleted but recorded under the trimmed key `.env` —
        // its mapping lost. Such names must be skipped before upload.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env "), b"SECRET=1\n").unwrap();
        fs::write(dir.path().join(".env"), b"SECRET=1\n").unwrap();

        let matches = expand_patterns(dir.path(), &[".env*".to_string()]).unwrap();

        assert_eq!(
            matches,
            vec![".env".to_string()],
            "edge whitespace is trimmed by the .prot parser and must be refused"
        );
    }

    // --- vault resolution ---------------------------------------------------

    #[test]
    fn lock_refuses_vault_id_that_is_not_the_prot_vault() {
        let dir = setup_dir(b"SECRET=1\n");
        let mut op = MockOp::new();
        // The recorded vault ID resolves to some other vault in the account
        // (tampered or copy-pasted .prot).
        op.vault_name_response = Some("Personal".to_string());

        let err = lock(&op, dir.path(), false).unwrap_err();

        assert!(
            err.to_string().contains("is named \"Personal\""),
            "expected a wrong-vault refusal, got: {err}"
        );
        assert!(
            !op.called("create_document") && !op.called("edit_document"),
            "must not write documents into a vault that isn't \".prot\""
        );
        assert!(dir.path().join(".env").exists(), ".env must be untouched");
    }

    #[test]
    fn lock_refuses_vault_id_that_no_longer_exists() {
        let dir = setup_dir(b"SECRET=1\n");
        let mut op = MockOp::new();
        op.vault_name_response = None; // recorded vault ID resolves to nothing

        let err = lock(&op, dir.path(), false).unwrap_err();

        assert!(
            err.to_string().contains("was not found"),
            "expected a vault-not-found error, got: {err}"
        );
        assert!(dir.path().join(".env").exists(), ".env must be untouched");
    }

    #[test]
    fn unlock_errors_instead_of_creating_a_missing_vault() {
        let dir = setup_dir(b"SECRET=1\n");
        let op = MockOp::new();
        lock(&op, dir.path(), false).unwrap();

        // Simulate a .prot with documents recorded but no usable vault: drop
        // the cached ID and make the by-name lookup come up empty.
        let mut prot = prot::read(&dir.path().join(PROT_FILE)).unwrap().unwrap();
        prot.vault = None;
        prot::write(&dir.path().join(PROT_FILE), &prot).unwrap();
        let mut op = MockOp::new();
        op.find_vault_response = None;

        let err = unlock(&op, dir.path()).unwrap_err();

        assert!(
            err.to_string().contains("No \".prot\" vault found"),
            "expected a missing-vault error, got: {err}"
        );
        assert!(
            !op.called("create_vault"),
            "unlock must never create a vault — the recorded documents \
             couldn't be in a fresh one"
        );
    }

    // --- sign-in orchestration --------------------------------------------

    #[test]
    fn ensure_signed_in_is_noop_when_already_signed_in() {
        let op = MockOp::new(); // starts signed in
        ensure_signed_in_with(&op, || panic!("must not prompt when already signed in")).unwrap();
        assert!(
            !op.called("sign_in"),
            "must not sign in when already signed in"
        );
    }

    #[test]
    fn ensure_signed_in_signs_in_when_user_confirms() {
        let op = MockOp::signed_out();
        // User says yes.
        ensure_signed_in_with(&op, || Ok(true)).unwrap();
        assert!(op.called("sign_in"), "should have run sign_in on confirm");
    }

    #[test]
    fn ensure_signed_in_errors_and_skips_signin_when_user_declines() {
        let op = MockOp::signed_out();
        // User says no (this is also the non-interactive fallback: confirm = false).
        let err = ensure_signed_in_with(&op, || Ok(false)).unwrap_err();
        assert!(
            err.to_string().contains("not signed in"),
            "expected a not-signed-in error, got: {err}"
        );
        assert!(
            !op.called("sign_in"),
            "must not sign in when the user declines / non-interactive"
        );
    }

    #[test]
    fn ensure_signed_in_errors_when_signin_does_not_take() {
        let mut op = MockOp::signed_out();
        op.signin_fails = true; // op signin "succeeds" but session still unusable
        let err = ensure_signed_in_with(&op, || Ok(true)).unwrap_err();
        assert!(
            err.to_string().contains("Still not signed in"),
            "expected a post-signin failure, got: {err}"
        );
    }

    #[test]
    fn lock_aborts_without_touching_files_when_not_signed_in() {
        let dir = setup_dir(b"SECRET=1\n");
        // Signed out; non-interactive test harness means the prompt resolves to
        // "no", so lock must bail before uploading or deleting anything.
        let op = MockOp::signed_out();

        let err = lock(&op, dir.path(), false).unwrap_err();

        assert!(err.to_string().contains("not signed in"));
        assert!(
            dir.path().join(".env").exists(),
            ".env must be untouched when not signed in"
        );
        assert!(
            !op.called("create_document"),
            "must not upload when signed out"
        );
    }
}
