use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VaultId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub exclude_globs: Vec<String>,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            exclude_globs: vec![
                "**/.git/**".into(),
                "**/node_modules/**".into(),
                "**/.next/**".into(),
                "**/target/**".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub id: VaultId,
    pub name: String,
    pub root_path: String, // store as UTF-8 string; normalize at boundaries
    pub created_at_ns: i64,
    pub config: VaultConfig,
}

/// App data root: %APPDATA%\Cupola  (Windows)
pub fn app_data_root() -> Result<PathBuf> {
    let appdata =
        std::env::var_os("APPDATA").ok_or_else(|| anyhow::anyhow!("APPDATA env var missing"))?;
    Ok(PathBuf::from(appdata).join("Cupola"))
}

pub fn vault_dir(app_root: &Path, vault_id: &VaultId) -> PathBuf {
    app_root.join("vaults").join(vault_id.0.to_string())
}

pub fn vault_db_path(app_root: &Path, vault_id: &VaultId) -> PathBuf {
    vault_dir(app_root, vault_id).join("db.sqlite")
}

pub fn vault_cas_root(app_root: &Path, vault_id: &VaultId) -> PathBuf {
    vault_dir(app_root, vault_id).join("cas")
}

pub fn vault_indexes_root(app_root: &Path, vault_id: &VaultId) -> PathBuf {
    vault_dir(app_root, vault_id).join("indexes")
}

pub fn now_ns() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    (d.as_secs() as i64) * 1_000_000_000 + (d.subsec_nanos() as i64)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestV0 {
    pub vault_id: String,
    pub root: String,
    pub created_at: i64,
    pub artifacts: Vec<ManifestArtifactV0>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestArtifactV0 {
    pub rel_path: String,
    pub raw_blob_id: String,
    pub mtime_ns: i64,
    pub file_size: i64,
    pub file_type: String,
    pub artifact_version_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerifyDiffKind {
    Modified,
    Missing,
    Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyDiff {
    pub kind: VerifyDiffKind,
    pub rel_path: String,
    pub expected_raw_blob_id: Option<String>,
    pub actual_raw_blob_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub vault_id: String,
    pub root: String,
    pub created_at: i64,
    pub artifact_count: usize,
    pub mismatches: Vec<VerifyDiff>,
    pub ok: bool,
}

pub fn deterministic_vault_id_from_root_path(root_path: &str) -> VaultId {
    let mut h = blake3::Hasher::new();
    h.update(b"cupola:vault:v1\0");
    h.update(root_path.as_bytes());
    let out = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&out.as_bytes()[0..16]);
    b[6] = (b[6] & 0x0f) | 0x40; // version
    b[8] = (b[8] & 0x3f) | 0x80; // variant
    VaultId(Uuid::from_bytes(b))
}

fn is_excluded(rel: &str) -> bool {
    rel.starts_with(".git/")
        || rel.contains("/.git/")
        || rel.starts_with("node_modules/")
        || rel.contains("/node_modules/")
        || rel.starts_with("target/")
        || rel.contains("/target/")
        || rel.starts_with(".next/")
        || rel.contains("/.next/")
        || rel.starts_with(".cupola_app/")
        || rel.contains("/.cupola_app/")
}

fn crawl_sorted_for_verify(root: &Path) -> Result<Vec<(String, PathBuf)>> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let abs = entry.path();
            if abs.is_dir() {
                walk(root, &abs, out)?;
                continue;
            }
            if !abs.is_file() {
                continue;
            }
            let rel = abs
                .strip_prefix(root)
                .unwrap_or(abs.as_path())
                .to_string_lossy()
                .replace('\\', "/");
            if is_excluded(&rel) {
                continue;
            }
            out.push((rel, abs));
        }
        Ok(())
    }

    let mut items = Vec::new();
    walk(root, root, &mut items)?;
    items.sort_by(|a, b| {
        a.0.to_ascii_lowercase()
            .cmp(&b.0.to_ascii_lowercase())
            .then_with(|| a.0.cmp(&b.0))
    });
    Ok(items)
}

pub async fn verify_manifest(vault_root: &Path, manifest_path: &Path) -> Result<VerifyReport> {
    let vault_root = vault_root.canonicalize()?;
    let root_s = vault_root.to_string_lossy().to_string();

    let manifest_bytes = tokio::fs::read(manifest_path).await?;
    let manifest: ManifestV0 = serde_json::from_slice(&manifest_bytes)?;

    let expected_vault_id = deterministic_vault_id_from_root_path(&root_s).0.to_string();
    if manifest.vault_id != expected_vault_id {
        anyhow::bail!(
            "manifest vault_id mismatch: expected {}, got {}",
            expected_vault_id,
            manifest.vault_id
        );
    }

    let mut current_hashes: BTreeMap<String, String> = BTreeMap::new();
    for (rel_path, abs_path) in crawl_sorted_for_verify(&vault_root)? {
        let bytes = tokio::fs::read(abs_path).await?;
        current_hashes.insert(rel_path, blake3::hash(&bytes).to_hex().to_string());
    }

    let mut mismatches: Vec<VerifyDiff> = Vec::new();
    let mut manifest_paths: BTreeSet<String> = BTreeSet::new();
    for a in &manifest.artifacts {
        manifest_paths.insert(a.rel_path.clone());
        match current_hashes.get(&a.rel_path) {
            Some(raw_blob_id) if raw_blob_id == &a.raw_blob_id => {}
            Some(raw_blob_id) => mismatches.push(VerifyDiff {
                kind: VerifyDiffKind::Modified,
                rel_path: a.rel_path.clone(),
                expected_raw_blob_id: Some(a.raw_blob_id.clone()),
                actual_raw_blob_id: Some(raw_blob_id.clone()),
            }),
            None => mismatches.push(VerifyDiff {
                kind: VerifyDiffKind::Missing,
                rel_path: a.rel_path.clone(),
                expected_raw_blob_id: Some(a.raw_blob_id.clone()),
                actual_raw_blob_id: None,
            }),
        }
    }

    for rel_path in current_hashes.keys() {
        if !manifest_paths.contains(rel_path) {
            mismatches.push(VerifyDiff {
                kind: VerifyDiffKind::Extra,
                rel_path: rel_path.clone(),
                expected_raw_blob_id: None,
                actual_raw_blob_id: current_hashes.get(rel_path).cloned(),
            });
        }
    }

    Ok(VerifyReport {
        vault_id: manifest.vault_id,
        root: manifest.root,
        created_at: manifest.created_at,
        artifact_count: manifest.artifacts.len(),
        ok: mismatches.is_empty(),
        mismatches,
    })
}

/// Minimal VaultManager (in-memory for now; DB persistence comes next PR)
pub struct VaultManager {
    app_root: PathBuf,
}
fn derive_vault_id(root_path: &str) -> VaultId {
    // Normalize for stability across runs (Windows-safe).
    // - remove \\?\ prefix if present
    // - lowercase
    // - unify separators to '/'
    let s = root_path.trim();
    let s = s.strip_prefix(r"\\?\").unwrap_or(s);
    let s = s.replace('\\', "/").to_lowercase();

    VaultId(Uuid::new_v5(&Uuid::NAMESPACE_URL, s.as_bytes()))
}
impl VaultManager {
    pub fn new(app_root: PathBuf) -> Self {
        Self { app_root }
    }

    pub fn app_root(&self) -> &Path {
        &self.app_root
    }

    pub async fn ensure_layout(&self, vault_id: &VaultId) -> Result<()> {
        let vdir = vault_dir(&self.app_root, vault_id);
        tokio::fs::create_dir_all(vdir.join("cas")).await?;
        tokio::fs::create_dir_all(vdir.join("indexes")).await?;
        tokio::fs::create_dir_all(self.app_root.join("logs")).await?;
        Ok(())
    }

    pub async fn create_vault(&self, name: &str, root_path: &str) -> Result<Vault> {
        let id = derive_vault_id(root_path);
        self.ensure_layout(&id).await?;
        Ok(Vault {
            id,
            name: name.to_string(),
            root_path: root_path.to_string(),
            created_at_ns: now_ns(),
            config: VaultConfig::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn vault_layout_is_created() {
        let td = TempDir::new().unwrap();
        let mgr = VaultManager::new(td.path().to_path_buf());
        let v = mgr.create_vault("Test", r"C:\tmp").await.unwrap();

        let vdir = vault_dir(mgr.app_root(), &v.id);
        assert!(vdir.join("cas").exists());
        assert!(vdir.join("indexes").exists());
    }
    #[tokio::test]
    async fn vault_id_is_deterministic_from_root_path() {
        let td = TempDir::new().unwrap();
        let mgr = VaultManager::new(td.path().to_path_buf());

        let v1 = mgr.create_vault("A", r"\\?\C:\TMP\Vault").await.unwrap();
        let v2 = mgr.create_vault("B", r"c:/tmp/vault").await.unwrap();

        assert_eq!(v1.id.0, v2.id.0);
    }
}
