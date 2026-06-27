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

/// Verify `op` is installed and the user is signed in. Returns a friendly
/// error otherwise.
pub fn assert_signed_in() -> Result<()> {
    // `op whoami` exits non-zero (and prints to stderr) when not signed in.
    match run_op(&["whoami"]) {
        Ok(_) => Ok(()),
        Err(e) => {
            if let Some(f) = e.downcast_ref::<OpFailure>() {
                if f.stderr.to_lowercase().contains("not signed in") {
                    bail!("You are not signed in to 1Password. Run `op signin` first.");
                }
            }
            Err(e)
        }
    }
}

/// Find a vault by name. Returns its ID, or `None` if it doesn't exist.
pub fn find_vault(name: &str) -> Result<Option<String>> {
    match run_op(&["vault", "get", name, "--format=json"]) {
        Ok(stdout) => Ok(Some(parse_id(&stdout)?)),
        Err(e) => {
            // `vault get` errors if the vault doesn't exist — treat that as
            // "not found" rather than a hard failure.
            if e.downcast_ref::<OpFailure>().is_some() {
                Ok(None)
            } else {
                Err(e)
            }
        }
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

/// Replace an existing document's contents from raw bytes.
pub fn edit_document(vault: &str, id: &str, file_name: &str, content: &[u8]) -> Result<()> {
    let (_dir, path) = temp_file_with(file_name, content)?;
    let path_str = path.to_string_lossy();
    run_op(&[
        "document",
        "edit",
        id,
        &path_str,
        "--vault",
        vault,
        "--file-name",
        file_name,
    ])?;
    Ok(())
}

/// Download a document's raw bytes by ID.
pub fn get_document(vault: &str, id: &str) -> Result<Vec<u8>> {
    run_op(&["document", "get", id, "--vault", vault, "--force"])
}

/// Delete a document by ID.
#[allow(dead_code)]
pub fn delete_document(vault: &str, id: &str) -> Result<()> {
    run_op(&["document", "delete", id, "--vault", vault])?;
    Ok(())
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
}
