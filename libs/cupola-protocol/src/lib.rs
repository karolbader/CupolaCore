use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PingDTO {
    pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchHitDTO {
    pub chunk_id: String,
    pub rel_path: String,
    pub file_type: String,
    pub mtime_ns: i64,
    pub raw_blob_id: String,
    pub chunk_blob_id: String,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
    pub excerpt: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolInfoDTO {
    pub name: String,
    pub version: Option<String>,
    pub build: String,
    pub platform: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultInfoDTO {
    pub vault_path: String,
    pub vault_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnvelopeDTO {
    pub schema_version: String,
    pub tool: ToolInfoDTO,
    pub generated_at: String,
    pub vault: VaultInfoDTO,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResponseDTO {
    #[serde(flatten)]
    pub env: EnvelopeDTO,
    pub query: String,
    pub limit: u32,
    pub hits: Vec<SearchHitDTO>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReplayCheckDTO {
    pub name: String,
    pub ok: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReplayReportDTO {
    pub ok: bool,
    pub vault_path: String,
    pub manifest_path: String,
    pub checks: Vec<ReplayCheckDTO>,
    pub errors: Vec<String>,
}
