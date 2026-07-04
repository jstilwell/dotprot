//! Local backups of `.prot` files under the user's home directory.
//!
//! Every time dotprot writes a project's `.prot`, it mirrors the write to
//! `~/.prot/backups/<absolute project path>/.prot`, so `dotprot restore` can
//! bring the file back if it's ever lost. Like `.prot` itself, backups hold
//! no secrets — only vault/document IDs and the user's patterns — but they
//! are the map back to the 1Password documents, which is exactly what hurts
//! to lose.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

use crate::prot::{self, ProtData};

/// Where the backup of `cwd`'s `.prot` lives under `home`.
///
/// The project's absolute path is mirrored as subdirectories below
/// `<home>/.prot/backups/`, so the tree is human-browsable and two projects
/// can never collide. Windows path prefixes (`C:`, `\\server\share`) become
/// plain directory names (`C`, `server_share`); the root separator carries no
/// name and is dropped.
pub fn backup_file(home: &Path, cwd: &Path) -> PathBuf {
    let mut path = home.join(".prot").join("backups");
    for comp in cwd.components() {
        match comp {
            Component::Normal(name) => path.push(name),
            Component::Prefix(prefix) => {
                let name = sanitize_prefix(&prefix.as_os_str().to_string_lossy());
                if !name.is_empty() {
                    path.push(name);
                }
            }
            // RootDir has no name; CurDir/ParentDir don't appear in the
            // absolute paths `env::current_dir()` returns.
            _ => {}
        }
    }
    path.join(crate::commands::PROT_FILE)
}

/// Turn a Windows path prefix (`C:`, `\\server\share`, `\\?\C:`) into a valid
/// directory name. Drive-letter forms all collapse to the bare letter, so the
/// verbatim and non-verbatim spellings of the same drive share one backup.
fn sanitize_prefix(prefix: &str) -> String {
    prefix
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                Some(c)
            } else if c == ':' {
                None
            } else {
                Some('_')
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

/// Write `data` to the backup location for `cwd`, creating directories as
/// needed. Returns the backup file's path. Callers decide the failure policy
/// (lock warns and carries on; a backup must never abort a lock).
pub fn save(home: &Path, cwd: &Path, data: &ProtData) -> Result<PathBuf> {
    let file = backup_file(home, cwd);
    let dir = file
        .parent()
        .expect("backup path always ends in .prot under a directory");
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating backup directory {}", dir.display()))?;
    prot::write(&file, data)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_path_mirrors_the_project_path() {
        let home = Path::new("/home/user");
        let file = backup_file(home, Path::new("/code/my proj"));
        assert_eq!(
            file,
            Path::new("/home/user/.prot/backups/code/my proj/.prot")
        );
    }

    #[test]
    fn distinct_projects_get_distinct_backups() {
        let home = Path::new("/home/user");
        assert_ne!(
            backup_file(home, Path::new("/code/a")),
            backup_file(home, Path::new("/code/b"))
        );
    }

    #[test]
    fn windows_prefixes_become_plain_names() {
        assert_eq!(sanitize_prefix("C:"), "C");
        assert_eq!(sanitize_prefix(r"\\?\C:"), "C");
        assert_eq!(sanitize_prefix(r"\\server\share"), "server_share");
    }

    #[test]
    fn save_round_trips_through_the_backup() {
        let home = tempfile::tempdir().unwrap();
        let mut data = ProtData::empty();
        data.vault = Some("VAULT".to_string());
        data.set_document(".env", "DOC0");

        let file = save(home.path(), Path::new("/code/proj"), &data).unwrap();

        let restored = prot::read(&file).unwrap().unwrap();
        assert_eq!(restored.vault.as_deref(), Some("VAULT"));
        assert_eq!(restored.document_id(".env"), Some("DOC0"));
        assert_eq!(restored.patterns, data.patterns);
    }
}
