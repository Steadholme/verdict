//! Relation-tuple storage.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring the
//! keystone/inkwell/cellar seam: handlers (and the [`crate::check`] engine) depend only on the
//! trait, so a FusionDB-backed store can drop in later. The PostgreSQL layer uses ONLY portable
//! standard SQL (TEXT/BIGINT, PK/UNIQUE/NOT NULL, parameterized queries, `INSERT .. ON CONFLICT`,
//! `CREATE INDEX`) and runtime queries (no compile-time macros), so the build needs NO database and
//! the same statements later run unchanged on FusionDB over pgwire.
//!
//! The methods are `async`: the axum handlers `.await` them directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge, so a
//! DB round-trip never blocks a worker thread.
//!
//! A tuple is the Zanzibar `(object, relation, subject)` triple. The `subject` may be a concrete
//! principal (`user:w33d`) OR a *userset* (`group:eng#member`) — the latter models indirection: it
//! means "every subject that has the `member` relation on `group:eng`".

use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::LIST_LIMIT;

/// A relation tuple (maps 1:1 to a `tuples` row).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tuple {
    pub id: String,
    pub object: String,
    pub relation: String,
    pub subject: String,
    pub created_at: i64,
}

/// Storage failure surfaced to the handler layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Backend I/O failure (mapped to a 500).
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable relation-tuple store. The reverse-index reads (`subjects_for` /
/// `objects_with_relation`) are exactly what the [`crate::check`] expansion needs.
#[async_trait]
pub trait Store: Send + Sync {
    /// All tuples, newest-first (`created_at` DESC), capped at [`LIST_LIMIT`]. Drives the console
    /// browse view.
    async fn list_tuples(&self) -> Vec<Tuple>;

    /// The subjects granted `(object, relation)` — both concrete principals and usersets. This is
    /// the single read the check engine fans out over.
    async fn subjects_for(&self, object: &str, relation: &str) -> Vec<String>;

    /// Every distinct object that has at least one tuple with this `relation`. Backs
    /// `list-objects` (the engine then checks each candidate).
    async fn objects_with_relation(&self, relation: &str) -> Vec<String>;

    /// Insert a tuple. Idempotent on the `UNIQUE(object, relation, subject)` triple: returns
    /// `true` when a new row was created, `false` when the tuple already existed.
    async fn add_tuple(&self, tuple: &Tuple) -> Result<bool, StoreError>;

    /// Delete a tuple by its `(object, relation, subject)` triple. Returns `true` when a row was
    /// removed, `false` when none matched.
    async fn delete_tuple(
        &self,
        object: &str,
        relation: &str,
        subject: &str,
    ) -> Result<bool, StoreError>;
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    tuples: Mutex<Vec<Tuple>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no `.await`
    // inside), so a guard is never held across a yield point.
    async fn list_tuples(&self) -> Vec<Tuple> {
        let tuples = self.tuples.lock().expect("tuples lock poisoned");
        let mut v: Vec<Tuple> = tuples.clone();
        // Newest-first; ties broken by id so output is stable.
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.id.cmp(&a.id)));
        v.truncate(LIST_LIMIT);
        v
    }

    async fn subjects_for(&self, object: &str, relation: &str) -> Vec<String> {
        self.tuples
            .lock()
            .expect("tuples lock poisoned")
            .iter()
            .filter(|t| t.object == object && t.relation == relation)
            .map(|t| t.subject.clone())
            .collect()
    }

    async fn objects_with_relation(&self, relation: &str) -> Vec<String> {
        let tuples = self.tuples.lock().expect("tuples lock poisoned");
        let mut v: Vec<String> = tuples
            .iter()
            .filter(|t| t.relation == relation)
            .map(|t| t.object.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    async fn add_tuple(&self, tuple: &Tuple) -> Result<bool, StoreError> {
        let mut tuples = self.tuples.lock().expect("tuples lock poisoned");
        if tuples
            .iter()
            .any(|t| t.object == tuple.object && t.relation == tuple.relation && t.subject == tuple.subject)
        {
            return Ok(false);
        }
        tuples.push(tuple.clone());
        Ok(true)
    }

    async fn delete_tuple(
        &self,
        object: &str,
        relation: &str,
        subject: &str,
    ) -> Result<bool, StoreError> {
        let mut tuples = self.tuples.lock().expect("tuples lock poisoned");
        let before = tuples.len();
        tuples.retain(|t| !(t.object == object && t.relation == relation && t.subject == subject));
        Ok(tuples.len() != before)
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `VERDICT_STORE=postgres`. Each method drives sqlx natively and the
// handlers `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. The DB
// enforces the UNIQUE(object,relation,subject) constraint and `INSERT .. ON CONFLICT DO NOTHING`
// makes a write idempotent, so no in-process write serializer is needed.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds just a `PgPool`.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tuples (\
                 id TEXT PRIMARY KEY, \
                 object TEXT NOT NULL, \
                 relation TEXT NOT NULL, \
                 subject TEXT NOT NULL, \
                 created_at BIGINT NOT NULL, \
                 UNIQUE(object, relation, subject)\
             )",
        )
        .execute(&self.pool)
        .await?;
        // Backs the forward check read (subjects granted an object+relation).
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_tuples_obj_rel ON tuples (object, relation)")
            .execute(&self.pool)
            .await?;
        // Backs reverse lookups by subject.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_tuples_subject ON tuples (subject)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn tuple_from_row(row: &sqlx::postgres::PgRow) -> Result<Tuple, sqlx::Error> {
        Ok(Tuple {
            id: row.try_get("id")?,
            object: row.try_get("object")?,
            relation: row.try_get("relation")?,
            subject: row.try_get("subject")?,
            created_at: row.try_get("created_at")?,
        })
    }

    async fn list_tuples_async(&self) -> Result<Vec<Tuple>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, object, relation, subject, created_at \
             FROM tuples ORDER BY created_at DESC, id DESC LIMIT $1",
        )
        .bind(LIST_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::tuple_from_row).collect()
    }

    async fn subjects_for_async(
        &self,
        object: &str,
        relation: &str,
    ) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT subject FROM tuples WHERE object = $1 AND relation = $2",
        )
        .bind(object)
        .bind(relation)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| r.try_get("subject")).collect()
    }

    async fn objects_with_relation_async(&self, relation: &str) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT DISTINCT object FROM tuples WHERE relation = $1 ORDER BY object",
        )
        .bind(relation)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| r.try_get("object")).collect()
    }

    async fn add_tuple_async(&self, t: &Tuple) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO tuples (id, object, relation, subject, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (object, relation, subject) DO NOTHING",
        )
        .bind(&t.id)
        .bind(&t.object)
        .bind(&t.relation)
        .bind(&t.subject)
        .bind(t.created_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_tuple_async(
        &self,
        object: &str,
        relation: &str,
        subject: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM tuples WHERE object = $1 AND relation = $2 AND subject = $3",
        )
        .bind(object)
        .bind(relation)
        .bind(subject)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl Store for PgStore {
    async fn list_tuples(&self) -> Vec<Tuple> {
        self.list_tuples_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_tuples failed");
            Vec::new()
        })
    }

    async fn subjects_for(&self, object: &str, relation: &str) -> Vec<String> {
        self.subjects_for_async(object, relation)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg subjects_for failed");
                Vec::new()
            })
    }

    async fn objects_with_relation(&self, relation: &str) -> Vec<String> {
        self.objects_with_relation_async(relation)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg objects_with_relation failed");
                Vec::new()
            })
    }

    async fn add_tuple(&self, tuple: &Tuple) -> Result<bool, StoreError> {
        self.add_tuple_async(tuple)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn delete_tuple(
        &self,
        object: &str,
        relation: &str,
        subject: &str,
    ) -> Result<bool, StoreError> {
        self.delete_tuple_async(object, relation, subject)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tup(object: &str, relation: &str, subject: &str) -> Tuple {
        Tuple {
            id: format!("tup_{object}_{relation}_{subject}"),
            object: object.to_string(),
            relation: relation.to_string(),
            subject: subject.to_string(),
            created_at: 1,
        }
    }

    #[tokio::test]
    async fn add_is_idempotent_on_triple() {
        let s = InMemoryStore::new();
        assert!(s.add_tuple(&tup("doc:a", "viewer", "user:w33d")).await.unwrap());
        // Same triple again -> not newly inserted.
        assert!(!s.add_tuple(&tup("doc:a", "viewer", "user:w33d")).await.unwrap());
        assert_eq!(s.list_tuples().await.len(), 1);
    }

    #[tokio::test]
    async fn reverse_reads_filter_correctly() {
        let s = InMemoryStore::new();
        s.add_tuple(&tup("doc:a", "viewer", "user:w33d")).await.unwrap();
        s.add_tuple(&tup("doc:a", "viewer", "group:eng#member")).await.unwrap();
        s.add_tuple(&tup("doc:b", "editor", "user:zed")).await.unwrap();

        let mut subs = s.subjects_for("doc:a", "viewer").await;
        subs.sort();
        assert_eq!(subs, vec!["group:eng#member", "user:w33d"]);

        assert_eq!(s.objects_with_relation("viewer").await, vec!["doc:a"]);
        assert_eq!(s.objects_with_relation("editor").await, vec!["doc:b"]);
    }

    #[tokio::test]
    async fn delete_reports_whether_removed() {
        let s = InMemoryStore::new();
        s.add_tuple(&tup("doc:a", "viewer", "user:w33d")).await.unwrap();
        assert!(s.delete_tuple("doc:a", "viewer", "user:w33d").await.unwrap());
        assert!(!s.delete_tuple("doc:a", "viewer", "user:w33d").await.unwrap());
    }
}
