//! Thin wrapper around the 1Password `op` CLI.
//!
//! dotprot never handles credentials itself — it shells out to `op`, which
//! manages auth. We surface op's stderr verbatim so the user sees real errors
//! (e.g. "you are not currently signed in").

use std::io::Write;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use tempfile::TempDir;

/// Run `op` with the given args, returning raw stdout bytes on success.
///
/// On a non-zero exit we return an error carrying op's stderr verbatim.
fn run_op(args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("op").args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow!(
                "The 1Password CLI (`op`) was not found on your PATH.\n\
                 Install it: https://developer.1password.com/docs/cli/get-started/"
            )
        } else {
            anyhow!("failed to run op: {e}")
        }
    })?;

    if output.status.success() {
        Ok(output.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(OpFailure {
            stderr: stderr.trim().to_string(),
        }
        .into())
    }
}

/// Error type carrying op's stderr, so callers can inspect it (e.g. to detect
/// "not signed in") while still rendering a clean message.
#[derive(Debug)]
pub struct OpFailure {
    pub stderr: String,
}

impl std::fmt::Display for OpFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.stderr)
    }
}

impl std::error::Error for OpFailure {}

/// Pull the item/vault identifier out of an `op ... --format=json` response.
///
/// op is inconsistent across subcommands: `document create` returns `uuid`,
/// while other commands use `id`. Accept either so we never depend on the
/// wrong one.
#[derive(Deserialize)]
struct IdEnvelope {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
}

fn parse_id(stdout: &[u8]) -> Result<String> {
    let env: IdEnvelope = serde_json::from_slice(stdout).with_context(|| {
        format!(
            "could not parse op JSON response: {}",
            String::from_utf8_lossy(stdout).trim()
        )
    })?;
    env.uuid.or(env.id).ok_or_else(|| {
        anyhow!(
            "could not find an id/uuid in op's response: {}",
            String::from_utf8_lossy(stdout).trim()
        )
    })
}

/// The 1Password operations dotprot performs, behind a trait so the
/// safety-critical lock/unlock flow can be exercised against a mock.
///
/// The real implementation ([`RealOp`]) shells out to `op`; tests substitute a
/// fake to assert ordering guarantees (e.g. that a file is never deleted when
/// the read-back doesn't match) without touching a live vault.
pub trait OpBackend {
    /// Whether the user is currently signed in (no prompting).
    fn is_signed_in(&self) -> Result<bool>;
    /// Run `op signin` interactively.
    fn sign_in(&self) -> Result<()>;
    fn find_vault(&self, name: &str) -> Result<Option<String>>;
    /// Look up a vault by ID and return its current name, or `None` if no such
    /// vault exists.
    fn vault_name(&self, id: &str) -> Result<Option<String>>;
    fn create_vault(&self, name: &str, description: &str) -> Result<String>;
    fn create_document(
        &self,
        vault: &str,
        title: &str,
        file_name: &str,
        content: &[u8],
    ) -> Result<String>;
    fn edit_document(
        &self,
        vault: &str,
        id: &str,
        title: &str,
        file_name: &str,
        content: &[u8],
    ) -> Result<()>;
    fn get_document(&self, vault: &str, id: &str) -> Result<Vec<u8>>;
}

/// The production [`OpBackend`]: every call shells out to the `op` CLI.
pub struct RealOp;

impl OpBackend for RealOp {
    fn is_signed_in(&self) -> Result<bool> {
        is_signed_in()
    }
    fn sign_in(&self) -> Result<()> {
        sign_in()
    }
    fn find_vault(&self, name: &str) -> Result<Option<String>> {
        find_vault(name)
    }
    fn vault_name(&self, id: &str) -> Result<Option<String>> {
        vault_name(id)
    }
    fn create_vault(&self, name: &str, description: &str) -> Result<String> {
        create_vault(name, description)
    }
    fn create_document(
        &self,
        vault: &str,
        title: &str,
        file_name: &str,
        content: &[u8],
    ) -> Result<String> {
        create_document(vault, title, file_name, content)
    }
    fn edit_document(
        &self,
        vault: &str,
        id: &str,
        title: &str,
        file_name: &str,
        content: &[u8],
    ) -> Result<()> {
        edit_document(vault, id, title, file_name, content)
    }
    fn get_document(&self, vault: &str, id: &str) -> Result<Vec<u8>> {
        get_document(vault, id)
    }
}

/// Whether the user is currently signed in to 1Password.
///
/// Returns `Ok(true)`/`Ok(false)` for the signed-in / not-signed-in cases, and
/// `Err` only for an unexpected failure (e.g. `op` not installed, or an error
/// that isn't recognizably "not signed in"). Splitting this out from
/// [`assert_signed_in`] lets the command layer decide whether to prompt for an
/// interactive sign-in rather than just erroring.
pub fn is_signed_in() -> Result<bool> {
    // `op whoami` exits non-zero (and prints to stderr) when not signed in.
    match run_op(&["whoami"]) {
        Ok(_) => Ok(true),
        Err(e) => {
            if let Some(f) = e.downcast_ref::<OpFailure>() {
                if f.stderr.to_lowercase().contains("not signed in") {
                    return Ok(false);
                }
            }
            Err(e)
        }
    }
}

/// Run `op signin` interactively, inheriting the terminal so the user can
/// complete authentication (Touch ID, desktop-app approval, or account/password
/// prompts). Unlike [`run_op`], this does not capture stdio — `op` needs direct
/// access to the terminal to prompt.
pub fn sign_in() -> Result<()> {
    let status = Command::new("op").arg("signin").status().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow!(
                "The 1Password CLI (`op`) was not found on your PATH.\n\
                 Install it: https://developer.1password.com/docs/cli/get-started/"
            )
        } else {
            anyhow!("failed to run op signin: {e}")
        }
    })?;
    if status.success() {
        Ok(())
    } else {
        bail!("`op signin` did not complete successfully. Not signed in.");
    }
}

/// Whether an `op vault get` failure means "no such vault", as opposed to any
/// other failure (network, auth, or an ambiguous name matching several vaults).
///
/// Only a genuine not-found may be treated as `None`: 1Password allows
/// duplicate vault names, so misreading a transient error as "missing" would
/// lead the caller to create a second `.prot` vault and silently split storage
/// across the two. The current CLI says `"<name>" isn't a vault in this
/// account.`; the extra patterns cover older/newer phrasings.
fn vault_not_found(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("isn't a vault") || s.contains("is not a vault") || s.contains("vault not found")
}

/// Find a vault by name. Returns its ID, or `None` if it doesn't exist.
pub fn find_vault(name: &str) -> Result<Option<String>> {
    match run_op(&["vault", "get", name, "--format=json"]) {
        Ok(stdout) => Ok(Some(parse_id(&stdout)?)),
        Err(e) => match e.downcast_ref::<OpFailure>() {
            Some(f) if vault_not_found(&f.stderr) => Ok(None),
            _ => Err(e),
        },
    }
}

/// Envelope for pulling the vault's name out of `op vault get --format=json`.
#[derive(Deserialize)]
struct VaultEnvelope {
    #[serde(default)]
    name: Option<String>,
}

/// Look up a vault by ID and return its current name, or `None` if no vault
/// with that ID exists. Lets callers confirm a stored vault ID still refers to
/// the vault they think it does before writing anything into it.
pub fn vault_name(id: &str) -> Result<Option<String>> {
    match run_op(&["vault", "get", id, "--format=json"]) {
        Ok(stdout) => {
            let env: VaultEnvelope = serde_json::from_slice(&stdout).with_context(|| {
                format!(
                    "could not parse op JSON response: {}",
                    String::from_utf8_lossy(&stdout).trim()
                )
            })?;
            let name = env
                .name
                .ok_or_else(|| anyhow!("op's response for vault {id} did not include a name"))?;
            Ok(Some(name))
        }
        Err(e) => match e.downcast_ref::<OpFailure>() {
            Some(f) if vault_not_found(&f.stderr) => Ok(None),
            _ => Err(e),
        },
    }
}

/// Create a vault and return its ID.
pub fn create_vault(name: &str, description: &str) -> Result<String> {
    let stdout = run_op(&[
        "vault",
        "create",
        name,
        "--description",
        description,
        "--format=json",
    ])?;
    parse_id(&stdout)
}

/// Write `content` to a 0600 temp file inside a fresh temp dir and run `fn`
/// with its path. The dir (and file) are removed when the returned guard drops.
///
/// We'd prefer to pipe bytes via stdin, but `op document create -` does not
/// reliably read piped stdin across platforms/versions ("expected data on
/// stdin but none found"), so a real file path is the only dependable input.
fn temp_file_with(file_name: &str, content: &[u8]) -> Result<(TempDir, std::path::PathBuf)> {
    let dir = tempfile::Builder::new()
        .prefix("dotprot-")
        .tempdir()
        .context("creating temp dir for op document")?;
    let path = dir.path().join(file_name);
    let mut f = open_owner_only(&path)?;
    f.write_all(content)
        .context("writing secret to temp file")?;
    f.flush().ok();
    Ok((dir, path))
}

/// Open a file for writing with owner-only (0600) permissions on Unix.
fn open_owner_only(path: &std::path::Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).context("opening temp file")
}

/// Create a document from raw bytes. Returns the new document item's ID.
pub fn create_document(
    vault: &str,
    title: &str,
    file_name: &str,
    content: &[u8],
) -> Result<String> {
    let (_dir, path) = temp_file_with(file_name, content)?;
    let path_str = path.to_string_lossy();
    let stdout = run_op(&[
        "document",
        "create",
        &path_str,
        "--vault",
        vault,
        "--title",
        title,
        "--file-name",
        file_name,
        "--format=json",
    ])?;
    parse_id(&stdout)
}

/// Replace an existing document's contents from raw bytes, keeping its title in
/// sync (the title is the file's absolute path, which can change if the file is
/// moved between locks).
pub fn edit_document(
    vault: &str,
    id: &str,
    title: &str,
    file_name: &str,
    content: &[u8],
) -> Result<()> {
    let (_dir, path) = temp_file_with(file_name, content)?;
    let path_str = path.to_string_lossy();
    run_op(&[
        "document",
        "edit",
        id,
        &path_str,
        "--vault",
        vault,
        "--title",
        title,
        "--file-name",
        file_name,
    ])?;
    Ok(())
}

/// Download a document's raw bytes by ID.
pub fn get_document(vault: &str, id: &str) -> Result<Vec<u8>> {
    run_op(&["document", "get", id, "--vault", vault, "--force"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_id_prefers_uuid() {
        let out = br#"{"uuid":"U123","id":"I456"}"#;
        assert_eq!(parse_id(out).unwrap(), "U123");
    }

    #[test]
    fn parse_id_falls_back_to_id() {
        let out = br#"{"id":"I456"}"#;
        assert_eq!(parse_id(out).unwrap(), "I456");
    }

    #[test]
    fn parse_id_errors_when_neither_present() {
        let out = br#"{"createdAt":"now"}"#;
        assert!(parse_id(out).is_err());
    }

    #[test]
    fn vault_not_found_matches_real_op_message() {
        // Captured verbatim from `op vault get <nonexistent> --format=json`.
        assert!(vault_not_found(
            r#"[ERROR] 2026/07/04 10:49:55 "zzz" isn't a vault in this account. Specify the vault with its ID or name."#
        ));
    }

    #[test]
    fn vault_not_found_rejects_other_failures() {
        // Transient/auth/ambiguity failures must propagate as errors, never be
        // read as "vault missing" (which would trigger creating a duplicate).
        assert!(!vault_not_found("network error: dial tcp: i/o timeout"));
        assert!(!vault_not_found("you are not currently signed in"));
        assert!(!vault_not_found(r#"More than one vault matches ".prot""#));
    }
}
