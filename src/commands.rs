//! The dotprot commands: setup, lock, unlock, and the bare-toggle dispatcher.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::op;
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

fn file_exists(p: &Path) -> bool {
    p.exists()
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

pub fn setup() -> Result<()> {
    op::assert_signed_in()?;

    if let Some(id) = op::find_vault(VAULT_NAME)? {
        println!("Vault \"{VAULT_NAME}\" already exists ({id}).");
        return Ok(());
    }

    let id = op::create_vault(VAULT_NAME, VAULT_DESCRIPTION)?;
    println!("Created vault \"{VAULT_NAME}\" ({id}).");
    Ok(())
}

/// Resolve the vault ID, finding it if not already cached in `prot`. If the
/// vault doesn't exist in 1Password yet, create it (a one-time action) and
/// announce it clearly so the user knows a vault was made in their account.
fn ensure_vault(prot: &mut ProtData) -> Result<String> {
    if let Some(v) = &prot.vault {
        return Ok(v.clone());
    }
    let id = match op::find_vault(VAULT_NAME)? {
        Some(found) => found,
        None => {
            let created = op::create_vault(VAULT_NAME, VAULT_DESCRIPTION)?;
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
pub fn lock(cwd: &Path, keep: bool) -> Result<()> {
    op::assert_signed_in()?;

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

    let vault = ensure_vault(&mut prot)?;
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
                op::edit_document(&vault, &existing, &file_name, &content)?;
                existing
            }
            None => op::create_document(&vault, &title, &file_name, &content)?,
        };

        // Verify-then-delete: read the document back and byte-compare before we
        // ever remove the original from disk.
        let round_trip = op::get_document(&vault, &id)?;
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

pub fn unlock(cwd: &Path) -> Result<()> {
    op::assert_signed_in()?;

    let file = prot_path(cwd);
    let mut prot = match prot::read(&file)? {
        Some(p) => p,
        None => bail!("No {PROT_FILE} found in {}. Nothing to unlock.", cwd.display()),
    };
    if prot.documents.is_empty() {
        bail!("{PROT_FILE} has no locked documents recorded. Nothing to unlock.");
    }

    let vault = ensure_vault(&mut prot)?;

    let mut unlocked = 0;
    for (rel_file, id) in &prot.documents {
        let abs_file = cwd.join(rel_file);
        if file_exists(&abs_file) {
            println!("  skip {rel_file} (already present on disk)");
            continue;
        }
        let content = op::get_document(&vault, id)?;
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

pub fn toggle(cwd: &Path, keep: bool) -> Result<()> {
    let file = prot_path(cwd);
    let prot = prot::read(&file)?;

    // No .prot at all (or nothing recorded) -> first run -> lock.
    let prot = match prot {
        Some(p) if !p.documents.is_empty() => p,
        _ => return lock(cwd, keep),
    };

    // Compare recorded documents against what's on disk.
    let mut present = 0;
    let mut absent = 0;
    for (rel_file, _) in &prot.documents {
        if file_exists(&cwd.join(rel_file)) {
            present += 1;
        } else {
            absent += 1;
        }
    }

    if present > 0 && absent > 0 {
        bail!(
            "Mixed state: {present} recorded file(s) are present and {absent} are missing. \
             Use `dotprot lock` or `dotprot unlock` explicitly to resolve the ambiguity."
        );
    }

    if absent > 0 {
        // Everything recorded is missing -> restore. (--keep is a no-op here.)
        unlock(cwd)
    } else {
        // Everything recorded is present -> re-lock.
        lock(cwd, keep)
    }
}
