use crate::metrics::{Metric, Timestamp};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// SQLite storage for buffering metrics when API is unavailable
#[derive(Clone)]
pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

impl Storage {
    /// Create a new storage instance
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY,
                metric_type TEXT NOT NULL,
                data TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                sent INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_metrics_sent ON metrics(sent, created_at)",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS last_poll_times (
                equipment_id TEXT PRIMARY KEY,
                last_poll_time TEXT NOT NULL
            )",
            [],
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Store a metric in the buffer
    pub fn store_metric(&self, metric: &Metric) -> Result<()> {
        let data = serde_json::to_string(metric)?;
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO metrics (metric_type, data, timestamp) VALUES (?1, ?2, ?3)",
            params![metric.metric_type(), data, metric.timestamp().to_rfc3339()],
        )?;

        Ok(())
    }

    /// Get pending metrics that haven't been sent yet
    pub fn get_pending_metrics(&self, limit: usize) -> Result<Vec<(i64, Metric)>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT id, data FROM metrics WHERE sent = 0 ORDER BY created_at LIMIT ?1")?;

        let metrics = stmt
            .query_map([limit], |row| {
                let id: i64 = row.get(0)?;
                let data: String = row.get(1)?;
                Ok((id, data))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id, data)| {
                serde_json::from_str::<Metric>(&data)
                    .ok()
                    .map(|metric| (id, metric))
            })
            .collect();

        Ok(metrics)
    }

    /// Mark metrics as sent
    pub fn mark_metrics_sent(&self, ids: &[i64]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }

        let conn = self.conn.lock().unwrap();
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let query = format!("UPDATE metrics SET sent = 1 WHERE id IN ({})", placeholders);

        let params: Vec<_> = ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
        conn.execute(&query, params.as_slice())?;

        Ok(())
    }

    /// Clean up old metrics that have been sent
    pub fn cleanup_old_metrics(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "DELETE FROM metrics WHERE sent = 1 AND created_at < datetime('now', '-24 hours')",
            [],
        )?;

        Ok(())
    }

    /// Get the last poll time for equipment
    #[allow(dead_code)] // Used in full SNMP implementation
    pub fn get_last_poll_time(&self, equipment_id: &str) -> Result<Option<Timestamp>> {
        let conn = self.conn.lock().unwrap();

        let result: std::result::Result<String, _> = conn.query_row(
            "SELECT last_poll_time FROM last_poll_times WHERE equipment_id = ?1",
            params![equipment_id],
            |row| row.get(0),
        );

        match result {
            Ok(_timestamp_str) => {
                // Return a Timestamp - parsing from string not implemented yet
                // For now just return None since this function isn't used yet
                Ok(None)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update the last poll time for equipment
    pub fn update_last_poll_time(&self, equipment_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Timestamp::now().to_rfc3339();

        conn.execute(
            "INSERT OR REPLACE INTO last_poll_times (equipment_id, last_poll_time) VALUES (?1, ?2)",
            params![equipment_id, now],
        )?;

        Ok(())
    }

    /// Get all last poll times
    pub fn get_all_last_poll_times(&self) -> Result<std::collections::HashMap<String, Timestamp>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare("SELECT equipment_id, last_poll_time FROM last_poll_times")?;

        let times: std::collections::HashMap<String, Timestamp> = stmt
            .query_map([], |row| {
                let equipment_id: String = row.get(0)?;
                let _timestamp_str: String = row.get(1)?;
                Ok(equipment_id)
            })?
            .filter_map(|r| r.ok())
            .map(|id| (id, Timestamp::now())) // Simplified - not parsing timestamps yet
            .collect();

        Ok(times)
    }
}
