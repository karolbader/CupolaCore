use anyhow::Result;

pub mod pipeline;

pub mod journal;
pub mod stages;
use std::path::{Path, PathBuf};
use unicase::UniCase;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct CrawlItem {
    pub rel_path: String,
    pub abs_path: PathBuf,
}

/// Deterministic crawler (v0 skeleton):
/// - Walks files
/// - Sorts by rel path (case-insensitive stable order)
/// - Returns list
pub fn crawl_sorted(root: &Path) -> Result<Vec<CrawlItem>> {
    let mut items: Vec<CrawlItem> = vec![];

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let abs = entry.path().to_path_buf();
        let rel = abs
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");

        // super-basic exclusions for now (real globbing later)
        // IMPORTANT: handle root-level dirs too (e.g. "node_modules/x.txt" has no leading '/')
        if rel.starts_with(".git/")
            || rel.contains("/.git/")
            || rel.starts_with("node_modules/")
            || rel.contains("/node_modules/")
            || rel.starts_with("target/")
            || rel.contains("/target/")
            || rel.starts_with(".next/")
            || rel.contains("/.next/")
        {
            continue;
        }

        items.push(CrawlItem {
            rel_path: rel,
            abs_path: abs,
        });
    }

    items.sort_by(|a, b| {
        let aa = UniCase::new(a.rel_path.as_str());
        let bb = UniCase::new(b.rel_path.as_str());
        aa.cmp(&bb).then_with(|| a.rel_path.cmp(&b.rel_path))
    });

    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn crawl_is_sorted_and_excludes_common_dirs() {
        let td = TempDir::new().unwrap();
        std::fs::create_dir_all(td.path().join("a")).unwrap();
        std::fs::create_dir_all(td.path().join("node_modules")).unwrap();

        let mut f1 = std::fs::File::create(td.path().join("a").join("Z.txt")).unwrap();
        writeln!(f1, "hi").unwrap();
        let mut f2 = std::fs::File::create(td.path().join("a").join("b.txt")).unwrap();
        writeln!(f2, "hi").unwrap();
        let mut f3 = std::fs::File::create(td.path().join("node_modules").join("x.txt")).unwrap();
        writeln!(f3, "nope").unwrap();

        let out = crawl_sorted(td.path()).unwrap();
        let rels: Vec<_> = out.iter().map(|x| x.rel_path.as_str()).collect();

        assert!(rels.iter().all(|p| !p.contains("node_modules")));
        assert_eq!(rels, vec!["a/b.txt", "a/Z.txt"]);
    }
}
