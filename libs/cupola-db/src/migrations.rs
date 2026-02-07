use anyhow::Result;
use sqlx::SqlitePool;

pub async fn run(pool: &SqlitePool) -> Result<()> {
    // NOTE: sqlx::migrate! requires a string literal.
    // This path is relative to the cupola-db crate root (libs/cupola-db).
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}
