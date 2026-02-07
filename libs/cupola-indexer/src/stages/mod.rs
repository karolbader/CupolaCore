pub mod hash;
pub mod parse;
use anyhow::Result;
use std::path::PathBuf;

/// Minimal event the pipeline will ingest (v0).
#[derive(Debug, Clone)]
pub struct ArtifactEvent {
    pub abs_path: PathBuf,
}

/// Pipeline stage trait (v0 scaffold).
#[async_trait::async_trait]
pub trait Stage: Send + Sync {
    async fn handle(&self, evt: ArtifactEvent) -> Result<()>;
}
