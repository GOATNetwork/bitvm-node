mod goat;
mod graph;
mod instance;
mod node;
mod stats;
mod swap;
#[cfg(test)]
mod tests;

use sqlx::migrate::Migrator;
use sqlx::pool::PoolConnection;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::{Sqlite, SqliteConnection, SqlitePool, Transaction, migrate::MigrateDatabase};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use graph::{GraphQuery, GraphRuntimeUpdate};
pub use instance::{InstanceQuery, InstanceUpdate};
pub use node::NodeQuery;
pub use swap::{SwapEscrowQuery, SwapEscrowUpdate};

pub(super) fn get_current_timestamp_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

#[derive(Clone, Debug)]
pub struct LocalDB {
    pub path: String,
    pub is_mem: bool,
    pub conn: SqlitePool,
}

#[derive(Debug)]
pub enum ConnectionHolder<'a> {
    Pooled(PoolConnection<Sqlite>),
    Direct(SqliteConnection),
    Transaction(Transaction<'a, Sqlite>),
}

#[derive(Debug)]
pub struct StorageProcessor<'a> {
    pub conn: ConnectionHolder<'a>,
    pub in_transaction: bool,
}

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
/// sqlx's own default, made explicit: how long a statement waits for SQLite's
/// write lock before failing with "database is locked".
pub const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

impl LocalDB {
    pub async fn new(path: &str, is_mem: bool) -> LocalDB {
        Self::new_with_busy_timeout(path, is_mem, DEFAULT_BUSY_TIMEOUT).await
    }

    /// `busy_timeout` must cover the longest write transaction the process
    /// holds (the engine's apply), or every other writer fails while it runs.
    pub async fn new_with_busy_timeout(
        path: &str,
        is_mem: bool,
        busy_timeout: Duration,
    ) -> LocalDB {
        if !Sqlite::database_exists(path).await.unwrap_or(false) {
            tracing::info!("Creating database {}", path);
            match Sqlite::create_database(path).await {
                Ok(_) => tracing::info!(
                    event = "database_lifecycle",
                    outcome = "created",
                    "local database created"
                ),
                Err(error) => panic!("error: {error}"),
            }
        } else {
            tracing::info!("Database already exists");
        }

        let mut options = SqliteConnectOptions::from_str(path)
            .unwrap()
            .create_if_missing(true)
            .busy_timeout(busy_timeout);
        if !is_mem {
            // File-backed nodes run event watchers, P2P handlers, and maintenance tasks
            // concurrently. WAL allows their readers to proceed while a short write commits.
            options = options.journal_mode(SqliteJournalMode::Wal);
        }
        let conn = SqlitePool::connect_with(options).await.unwrap();
        Self { path: path.to_string(), is_mem, conn }
    }

    pub async fn migrate(&self) {
        match MIGRATOR.run(&self.conn).await {
            Ok(_) => tracing::info!("Migration success"),
            Err(error) => {
                panic!("error: {error:?}");
            }
        }
    }

    pub async fn acquire<'a>(&self) -> anyhow::Result<StorageProcessor<'a>> {
        Ok(StorageProcessor {
            conn: ConnectionHolder::Pooled(self.conn.acquire().await?),
            in_transaction: false,
        })
    }
    pub async fn start_transaction<'a>(&self) -> anyhow::Result<StorageProcessor<'a>> {
        Ok(StorageProcessor {
            conn: ConnectionHolder::Transaction(self.conn.begin().await?),
            in_transaction: true,
        })
    }

    /// Start a short write transaction before reading state that will be
    /// immediately reconciled. This prevents a stale snapshot from dropping
    /// a concurrent update between the read and the conditional write.
    pub async fn start_immediate_transaction<'a>(&self) -> anyhow::Result<StorageProcessor<'a>> {
        Ok(StorageProcessor {
            conn: ConnectionHolder::Transaction(self.conn.begin_with("BEGIN IMMEDIATE").await?),
            in_transaction: true,
        })
    }
}

impl StorageProcessor<'_> {
    pub fn conn(&mut self) -> &mut SqliteConnection {
        match &mut self.conn {
            ConnectionHolder::Pooled(conn) => conn,
            ConnectionHolder::Direct(conn) => conn,
            ConnectionHolder::Transaction(conn) => conn,
        }
    }

    pub async fn commit(self) -> anyhow::Result<()> {
        if let ConnectionHolder::Transaction(transaction) = self.conn {
            transaction.commit().await?;
            Ok(())
        } else {
            panic!(
                "StorageProcessor::commit can only be invoked after calling StorageProcessor::begin_transaction"
            );
        }
    }
}

pub async fn create_local_db(db_path: &str) -> LocalDB {
    create_local_db_with_busy_timeout(db_path, DEFAULT_BUSY_TIMEOUT).await
}

pub async fn create_local_db_with_busy_timeout(db_path: &str, busy_timeout: Duration) -> LocalDB {
    // Only in-memory databases skip WAL; a file-backed node needs its readers
    // to proceed while the engine holds the write lock.
    let is_mem = db_path.contains(":memory:");
    let local_db = LocalDB::new_with_busy_timeout(db_path, is_mem, busy_timeout).await;
    local_db.migrate().await;
    local_db
}
