use anyhow::Result;
use serde::{Deserialize, Serialize};
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

/// Minimal VaultManager (in-memory for now; DB persistence comes next PR)
pub struct VaultManager {
    app_root: PathBuf,
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
        let id = VaultId(Uuid::new_v4());
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
        let v = mgr.create_vault("Test", "C:\\tmp").await.unwrap();

        let vdir = vault_dir(mgr.app_root(), &v.id);
        assert!(vdir.join("cas").exists());
        assert!(vdir.join("indexes").exists());
    }
}
