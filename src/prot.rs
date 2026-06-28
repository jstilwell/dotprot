//! Read/write the `.prot` file.
//!
//! Layout — a managed header block, a sentinel line, then the user's list of
//! file patterns (one per line). dotprot owns everything above the sentinel and
//! rewrites it freely; everything below it belongs to the user.
//!
//! ```text
//! # dotprot — managed below, do not edit
//! vault: abcd1234...
//! doc .env: wxyz5678...
//! doc config/secrets.json: efgh9012...
//! # ---- your files (edit below) ----
//! .env*
//! config/secrets.json
//! ```

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

const SENTINEL: &str = "# ---- your files (edit below) ----";
const HEADER_NOTE: &str = "# dotprot — managed below, do not edit";

/// Parsed contents of a `.prot` file.
#[derive(Debug, Default, Clone)]
pub struct ProtData {
    /// Vault ID, once setup/lock has run.
    pub vault: Option<String>,
    /// (file pattern as written by the user) -> 1Password document ID.
    /// A Vec rather than a map to keep insertion order stable on round-trip.
    pub documents: Vec<(String, String)>,
    /// User-maintained glob patterns of files to protect.
    pub patterns: Vec<String>,
}

impl ProtData {
    /// Default contents written when `.prot` doesn't exist yet.
    pub fn empty() -> Self {
        ProtData {
            vault: None,
            documents: Vec::new(),
            patterns: vec![".env*".to_string()],
        }
    }

    /// Look up a recorded document ID for a pattern entry.
    pub fn document_id(&self, pattern: &str) -> Option<&str> {
        self.documents
            .iter()
            .find(|(p, _)| p == pattern)
            .map(|(_, id)| id.as_str())
    }

    /// Insert or update the document ID for a pattern entry.
    pub fn set_document(&mut self, pattern: &str, id: &str) {
        if let Some(entry) = self.documents.iter_mut().find(|(p, _)| p == pattern) {
            entry.1 = id.to_string();
        } else {
            self.documents
                .push((pattern.to_string(), id.to_string()));
        }
    }
}

pub fn parse(text: &str) -> ProtData {
    let mut data = ProtData::default();

    let (header_text, body_text) = match text.find(SENTINEL) {
        Some(idx) => (&text[..idx], &text[idx + SENTINEL.len()..]),
        None => ("", text),
    };

    for raw in header_text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("vault:") {
            let v = rest.trim();
            data.vault = if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            };
        } else if let Some(rest) = line.strip_prefix("doc ") {
            // "doc <pattern>: <id>" — split on the LAST colon so patterns may
            // themselves contain colons.
            if let Some(sep) = rest.rfind(':') {
                let pattern = rest[..sep].trim();
                let id = rest[sep + 1..].trim();
                if !pattern.is_empty() && !id.is_empty() {
                    data.documents
                        .push((pattern.to_string(), id.to_string()));
                }
            }
        }
    }

    for raw in body_text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        data.patterns.push(line.to_string());
    }

    data
}

pub fn serialize(data: &ProtData) -> String {
    let mut lines: Vec<String> = vec![HEADER_NOTE.to_string()];
    lines.push(format!("vault: {}", data.vault.as_deref().unwrap_or("")));
    for (pattern, id) in &data.documents {
        lines.push(format!("doc {pattern}: {id}"));
    }
    lines.push(String::new());
    lines.push(SENTINEL.to_string());
    for pattern in &data.patterns {
        lines.push(pattern.clone());
    }
    lines.push(String::new());
    lines.join("\n")
}

/// Read and parse `.prot`. Returns `None` if the file doesn't exist.
pub fn read(path: &Path) -> Result<Option<ProtData>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(parse(&text))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Serialize and write `.prot` with owner-only (`0600`) permissions on Unix.
///
/// `.prot` holds no secrets — only vault and document IDs — but it is a precise
/// map of which 1Password documents hold this project's secrets, so we keep it
/// as locked down as every other file dotprot writes.
pub fn write(path: &Path, data: &ProtData) -> Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(serialize(data).as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_defaults_to_env_glob() {
        let p = ProtData::empty();
        assert_eq!(p.vault, None);
        assert!(p.documents.is_empty());
        assert_eq!(p.patterns, vec![".env*".to_string()]);
    }

    #[test]
    fn parse_reads_vault_documents_and_patterns() {
        let text = "# dotprot — managed below, do not edit\n\
                    vault: VAULT123\n\
                    doc .env: DOC_ENV\n\
                    doc config/secrets.json: DOC_SECRETS\n\
                    \n\
                    # ---- your files (edit below) ----\n\
                    .env\n\
                    config/secrets.json\n";
        let p = parse(text);
        assert_eq!(p.vault.as_deref(), Some("VAULT123"));
        assert_eq!(p.document_id(".env"), Some("DOC_ENV"));
        assert_eq!(p.document_id("config/secrets.json"), Some("DOC_SECRETS"));
        assert_eq!(
            p.patterns,
            vec![".env".to_string(), "config/secrets.json".to_string()]
        );
    }

    #[test]
    fn serialize_then_parse_round_trips() {
        let mut original = ProtData {
            vault: Some("V".to_string()),
            documents: vec![],
            patterns: vec![".env*".to_string(), "secrets/*.json".to_string()],
        };
        original.set_document(".env", "D1");
        original.set_document(".env.local", "D2");

        let round = parse(&serialize(&original));
        assert_eq!(round.vault, original.vault);
        assert_eq!(round.documents, original.documents);
        assert_eq!(round.patterns, original.patterns);
    }

    #[test]
    fn empty_vault_round_trips_as_none() {
        let p = ProtData::empty();
        let round = parse(&serialize(&p));
        assert_eq!(round.vault, None);
    }

    #[test]
    fn pattern_with_colon_survives_round_trip() {
        let mut p = ProtData {
            vault: Some("V".to_string()),
            documents: vec![],
            patterns: vec!["weird:name.env".to_string()],
        };
        p.set_document("weird:name.env", "DOC");
        let round = parse(&serialize(&p));
        assert_eq!(round.document_id("weird:name.env"), Some("DOC"));
    }

    #[test]
    fn comments_and_blanks_in_user_section_ignored() {
        let text = "# ---- your files (edit below) ----\n\
                    # my secrets\n\
                    .env\n\
                    \n\
                    \x20\x20\n\
                    .env.production\n";
        let p = parse(text);
        assert_eq!(
            p.patterns,
            vec![".env".to_string(), ".env.production".to_string()]
        );
    }

    #[test]
    fn no_sentinel_treats_all_lines_as_patterns() {
        let p = parse(".env\n.env.local\n");
        assert_eq!(
            p.patterns,
            vec![".env".to_string(), ".env.local".to_string()]
        );
        assert_eq!(p.vault, None);
    }

    #[cfg(unix)]
    #[test]
    fn write_creates_prot_with_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".prot");
        write(&path, &ProtData::empty()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        // Only the low 9 permission bits matter here.
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }
}
