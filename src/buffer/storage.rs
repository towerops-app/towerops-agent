use crate::metrics::Metric;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// SQLite storage for buffering metrics when API is unavailable
#[derive(Clone)]
pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

impl Storage {
    /// Create a new storage instance
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path).context("Failed to open database")?;

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
        )
        .context("Failed to create metrics table")?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_metrics_sent ON metrics(sent, created_at)",
            [],
        )
        .context("Failed to create index")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS last_poll_times (
                equipment_id TEXT PRIMARY KEY,
                last_poll_time TEXT NOT NULL
            )",
            [],
        )
        .context("Failed to create last_poll_times table")?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Store a metric in the buffer
    pub fn store_metric(&self, metric: &Metric) -> Result<()> {
        let data = serde_json::to_string(metric).context("Failed to serialize metric")?;
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO metrics (metric_type, data, timestamp) VALUES (?1, ?2, ?3)",
            params![
                metric.metric_type(),
                data,
                metric.timestamp().to_rfc3339()
            ],
        )
        .context("Failed to insert metric")?;

        Ok(())
    }

    /// Get pending metrics that haven't been sent yet
    pub fn get_pending_metrics(&self, limit: usize) -> Result<Vec<(i64, Metric)>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT id, data FROM metrics WHERE sent = 0 ORDER BY created_at LIMIT ?1")
            .context("Failed to prepare statement")?;

        let metrics = stmt
            .query_map([limit], |row| {
                let id: i64 = row.get(0)?;
                let data: String = row.get(1)?;
                Ok((id, data))
            })
            .context("Failed to query metrics")?
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
        conn.execute(&query, params.as_slice())
            .context("Failed to mark metrics as sent")?;

        Ok(())
    }

    /// Clean up old metrics that have been sent
    pub fn cleanup_old_metrics(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "DELETE FROM metrics WHERE sent = 1 AND created_at < datetime('now', '-24 hours')",
            [],
        )
        .context("Failed to cleanup old metrics")?;

        Ok(())
    }

    /// Get the last poll time for equipment
    pub fn get_last_poll_time(&self, equipment_id: &str) -> Result<Option<DateTime<Utc>>> {
        let conn = self.conn.lock().unwrap();

        let result: Result<String, _> = conn.query_row(
            "SELECT last_poll_time FROM last_poll_times WHERE equipment_id = ?1",
            params![equipment_id],
            |row| row.get(0),
        );

        match result {
            Ok(timestamp_str) => {
                let dt = DateTime::parse_from_rfc3339(&timestamp_str)
                    .context("Failed to parse timestamp")?
                    .with_timezone(&Utc);
                Ok(Some(dt))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e).context("Failed to query last poll time"),
        }
    }

    /// Update the last poll time for equipment
    pub fn update_last_poll_time(&self, equipment_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT OR REPLACE INTO last_poll_times (equipment_id, last_poll_time) VALUES (?1, ?2)",
            params![equipment_id, now],
        )
        .context("Failed to update last poll time")?;

        Ok(())
    }

    /// Get all last poll times
    pub fn get_all_last_poll_times(&self) -> Result<HashMap<String, DateTime<Utc>>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT equipment_id, last_poll_time FROM last_poll_times")
            .context("Failed to prepare statement")?;

        let times: HashMap<String, DateTime<Utc>> = stmt
            .query_map([], |row| {
                let equipment_id: String = row.get(0)?;
                let timestamp_str: String = row.get(1)?;
                Ok((equipment_id, timestamp_str))
            })
            .context("Failed to query poll times")?
            .filter_map(|r| r.ok())
            .filter_map(|(id, ts)| {
                DateTime::parse_from_rfc3339(&ts)
                    .ok()
                    .map(|dt| (id, dt.with_timezone(&Utc)))
            })
            .collect();

        Ok(times)
    }
}
