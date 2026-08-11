use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::{Executor, Row};

use crate::policy::{Effect, Membership, PolicyEdge, PolicySnapshot, ProjectionEdge};
use crate::policy::{SubjectAccessState, SubjectAccessStatus};

const MIGRATION_V2: &str = include_str!("../migrations/0002_policy_v2.sql");
const MIGRATION_V3: &str = include_str!("../migrations/0003_projection_source_fencing.sql");
const MIGRATION_V4: &str = include_str!("../migrations/0004_subject_access_status.sql");

#[derive(Debug, thiserror::Error)]
pub enum PolicyStoreError {
    #[error("policy backend unavailable")]
    Backend,
    #[error("policy state is inconsistent")]
    Inconsistent,
    #[error("policy projection conflicts with existing evidence")]
    Conflict,
    #[error("policy projection source version is stale")]
    StaleVersion,
}

#[derive(Clone, Debug)]
struct ProjectionSource {
    source_version: i64,
    payload_hash: String,
    projection_epoch: i64,
}

pub fn projection_payload_hash(edges: &[ProjectionEdge]) -> Result<String, PolicyStoreError> {
    let payload = serde_json::to_vec(edges).map_err(|_| PolicyStoreError::Inconsistent)?;
    Ok(hex::encode(Sha256::digest(payload)))
}

#[async_trait]
pub trait PolicyStore: Send + Sync {
    async fn snapshot(
        &self,
        permission: &str,
        subject: &str,
    ) -> Result<PolicySnapshot, PolicyStoreError>;
    async fn replace_projection(
        &self,
        source_grant_id: &str,
        source_version: i64,
        payload_hash: &str,
        edges: Vec<ProjectionEdge>,
        now: i64,
    ) -> Result<i64, PolicyStoreError>;
    async fn bump_epoch(&self, now: i64) -> Result<i64, PolicyStoreError>;
    async fn set_subject_status(
        &self,
        subject: &str,
        state: SubjectAccessState,
        source_event_id: &str,
        source_version: i64,
        now: i64,
    ) -> Result<(i64, bool), PolicyStoreError>;
}

#[derive(Default)]
struct MemoryState {
    epoch: i64,
    edges: Vec<PolicyEdge>,
    memberships: Vec<Membership>,
    projection_sources: HashMap<String, ProjectionSource>,
    subject_statuses: HashMap<String, SubjectAccessStatus>,
}

#[derive(Default)]
pub struct InMemoryPolicyStore {
    state: Mutex<MemoryState>,
}

impl InMemoryPolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_membership(&self, membership: Membership) {
        self.state
            .lock()
            .expect("policy store lock poisoned")
            .memberships
            .push(membership);
    }
}

#[async_trait]
impl PolicyStore for InMemoryPolicyStore {
    async fn snapshot(
        &self,
        permission: &str,
        subject: &str,
    ) -> Result<PolicySnapshot, PolicyStoreError> {
        let state = self.state.lock().expect("policy store lock poisoned");
        let object = format!("permission:{permission}");
        let edges = state
            .edges
            .iter()
            .filter(|edge| edge.object == object && edge.relation == "grantee" && edge.active)
            .cloned()
            .collect();
        Ok(PolicySnapshot {
            epoch: state.epoch,
            edges,
            memberships: state.memberships.clone(),
            subject_status: state.subject_statuses.get(subject).cloned(),
        })
    }

    async fn replace_projection(
        &self,
        source_grant_id: &str,
        source_version: i64,
        payload_hash: &str,
        edges: Vec<ProjectionEdge>,
        now: i64,
    ) -> Result<i64, PolicyStoreError> {
        if source_version <= 0
            || projection_payload_hash(&edges)? != payload_hash
            || edges.iter().any(|edge| edge.version != source_version)
        {
            return Err(PolicyStoreError::Conflict);
        }
        let mut state = self.state.lock().expect("policy store lock poisoned");
        if let Some(existing) = state.projection_sources.get(source_grant_id) {
            if source_version < existing.source_version {
                return Err(PolicyStoreError::StaleVersion);
            }
            if source_version == existing.source_version {
                return if payload_hash == existing.payload_hash {
                    Ok(existing.projection_epoch)
                } else {
                    Err(PolicyStoreError::Conflict)
                };
            }
        }
        let retained_edge_ids: HashSet<_> = state
            .edges
            .iter()
            .filter(|edge| edge.source_grant_id != source_grant_id)
            .map(|edge| edge.edge_id.as_str())
            .collect();
        let retained_projection_keys: HashSet<_> = state
            .edges
            .iter()
            .filter(|edge| edge.source_grant_id != source_grant_id)
            .map(|edge| edge.projection_key.as_str())
            .collect();
        let mut input_edge_ids = HashSet::new();
        let mut input_projection_keys = HashSet::new();
        if edges.iter().any(|edge| {
            retained_edge_ids.contains(edge.edge_id.as_str())
                || retained_projection_keys.contains(edge.projection_key.as_str())
                || !input_edge_ids.insert(edge.edge_id.as_str())
                || !input_projection_keys.insert(edge.projection_key.as_str())
        }) {
            return Err(PolicyStoreError::Conflict);
        }
        let epoch = state
            .epoch
            .checked_add(1)
            .ok_or(PolicyStoreError::Inconsistent)?;
        state
            .edges
            .retain(|edge| edge.source_grant_id != source_grant_id);
        state.edges.extend(
            edges
                .into_iter()
                .map(|edge| edge.into_policy_edge(source_grant_id, epoch, now)),
        );
        state.epoch = epoch;
        state.projection_sources.insert(
            source_grant_id.to_string(),
            ProjectionSource {
                source_version,
                payload_hash: payload_hash.to_string(),
                projection_epoch: epoch,
            },
        );
        Ok(epoch)
    }

    async fn bump_epoch(&self, _now: i64) -> Result<i64, PolicyStoreError> {
        let mut state = self.state.lock().expect("policy store lock poisoned");
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(PolicyStoreError::Inconsistent)?;
        Ok(state.epoch)
    }

    async fn set_subject_status(
        &self,
        subject: &str,
        access_state: SubjectAccessState,
        source_event_id: &str,
        source_version: i64,
        now: i64,
    ) -> Result<(i64, bool), PolicyStoreError> {
        if source_version <= 0 {
            return Err(PolicyStoreError::Conflict);
        }
        let mut state = self.state.lock().expect("policy store lock poisoned");
        if let Some(existing) = state.subject_statuses.get(subject) {
            if source_version < existing.source_version {
                return Err(PolicyStoreError::StaleVersion);
            }
            if source_version == existing.source_version {
                return if existing.state == access_state
                    && existing.source_event_id == source_event_id
                {
                    Ok((existing.policy_epoch, true))
                } else {
                    Err(PolicyStoreError::Conflict)
                };
            }
        }
        let epoch = state
            .epoch
            .checked_add(1)
            .ok_or(PolicyStoreError::Inconsistent)?;
        state.epoch = epoch;
        state.subject_statuses.insert(
            subject.to_string(),
            SubjectAccessStatus {
                subject: subject.to_string(),
                state: access_state,
                source_event_id: source_event_id.to_string(),
                source_version,
                policy_epoch: epoch,
                updated_at: now,
            },
        );
        Ok((epoch, false))
    }
}

pub struct PgPolicyStore {
    pool: PgPool,
}

impl PgPolicyStore {
    pub async fn connect(database_url: &str) -> Result<Self, PolicyStoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await
            .map_err(|_| PolicyStoreError::Backend)?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<(), PolicyStoreError> {
        for migration in [MIGRATION_V2, MIGRATION_V3, MIGRATION_V4] {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| PolicyStoreError::Backend)?;
            sqlx::raw_sql(migration)
                .execute(&mut *transaction)
                .await
                .map_err(|_| PolicyStoreError::Backend)?;
            transaction
                .commit()
                .await
                .map_err(|_| PolicyStoreError::Backend)?;
        }
        Ok(())
    }

    fn edge(row: &PgRow) -> Result<PolicyEdge, PolicyStoreError> {
        Ok(PolicyEdge {
            edge_id: get(row, "edge_id")?,
            projection_key: get(row, "projection_key")?,
            source_grant_id: get(row, "source_grant_id")?,
            object: get(row, "object")?,
            relation: get(row, "relation")?,
            subject: get(row, "subject")?,
            effect: match get::<String>(row, "effect")?.as_str() {
                "allow" => Effect::Allow,
                "deny" => Effect::Deny,
                _ => return Err(PolicyStoreError::Inconsistent),
            },
            resource_selector: get(row, "resource_selector")?,
            condition: get(row, "condition")?,
            not_before: get(row, "not_before")?,
            expires_at: get(row, "expires_at")?,
            active: get(row, "active")?,
            version: get(row, "version")?,
            projection_epoch: get(row, "projection_epoch")?,
            created_at: get(row, "created_at")?,
            updated_at: get(row, "updated_at")?,
        })
    }

    fn subject_status(row: &PgRow) -> Result<SubjectAccessStatus, PolicyStoreError> {
        Ok(SubjectAccessStatus {
            subject: get(row, "subject")?,
            state: match get::<String>(row, "state")?.as_str() {
                "active" => SubjectAccessState::Active,
                "frozen" => SubjectAccessState::Frozen,
                "terminated" => SubjectAccessState::Terminated,
                _ => return Err(PolicyStoreError::Inconsistent),
            },
            source_event_id: get(row, "source_event_id")?,
            source_version: get(row, "source_version")?,
            policy_epoch: get(row, "policy_epoch")?,
            updated_at: get(row, "updated_at")?,
        })
    }
}

#[async_trait]
impl PolicyStore for PgPolicyStore {
    async fn snapshot(
        &self,
        permission: &str,
        subject: &str,
    ) -> Result<PolicySnapshot, PolicyStoreError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PolicyStoreError::Backend)?;
        transaction
            .execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .await
            .map_err(|_| PolicyStoreError::Backend)?;
        let epoch: i64 = sqlx::query("SELECT epoch FROM policy_state WHERE id=1")
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| PolicyStoreError::Backend)?
            .ok_or(PolicyStoreError::Inconsistent)?
            .try_get("epoch")
            .map_err(|_| PolicyStoreError::Inconsistent)?;
        let object = format!("permission:{permission}");
        let rows = sqlx::query(
            "SELECT * FROM policy_edges_v2 \
             WHERE object=$1 AND relation='grantee' AND active=TRUE \
             ORDER BY edge_id ASC",
        )
        .bind(object)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PolicyStoreError::Backend)?;
        let edges: Vec<_> = rows.iter().map(Self::edge).collect::<Result<_, _>>()?;
        if edges.iter().any(|edge| edge.projection_epoch > epoch) {
            return Err(PolicyStoreError::Inconsistent);
        }
        let memberships = sqlx::query(
            "SELECT object,relation,subject FROM tuples WHERE relation='member' ORDER BY object,subject",
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PolicyStoreError::Backend)?
        .iter()
        .map(|row| {
            Ok(Membership {
                object: get(row, "object")?,
                relation: get(row, "relation")?,
                subject: get(row, "subject")?,
            })
        })
        .collect::<Result<Vec<_>, PolicyStoreError>>()?;
        let subject_status = sqlx::query(
            "SELECT subject,state,source_event_id,source_version,policy_epoch,updated_at \
             FROM policy_subject_status WHERE subject=$1",
        )
        .bind(subject)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PolicyStoreError::Backend)?
        .as_ref()
        .map(Self::subject_status)
        .transpose()?;
        if subject_status
            .as_ref()
            .is_some_and(|status| status.policy_epoch <= 0 || status.policy_epoch > epoch)
        {
            return Err(PolicyStoreError::Inconsistent);
        }
        transaction
            .commit()
            .await
            .map_err(|_| PolicyStoreError::Backend)?;
        Ok(PolicySnapshot {
            epoch,
            edges,
            memberships,
            subject_status,
        })
    }

    async fn replace_projection(
        &self,
        source_grant_id: &str,
        source_version: i64,
        payload_hash: &str,
        edges: Vec<ProjectionEdge>,
        now: i64,
    ) -> Result<i64, PolicyStoreError> {
        if source_version <= 0
            || projection_payload_hash(&edges)? != payload_hash
            || edges.iter().any(|edge| edge.version != source_version)
        {
            return Err(PolicyStoreError::Conflict);
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PolicyStoreError::Backend)?;
        let current_epoch: i64 =
            sqlx::query("SELECT epoch FROM policy_state WHERE id=1 FOR UPDATE")
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| PolicyStoreError::Backend)?
                .ok_or(PolicyStoreError::Inconsistent)?
                .try_get("epoch")
                .map_err(|_| PolicyStoreError::Inconsistent)?;
        if let Some(row) = sqlx::query(
            "SELECT source_version,payload_hash,projection_epoch \
             FROM policy_projection_source WHERE source_grant_id=$1",
        )
        .bind(source_grant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PolicyStoreError::Backend)?
        {
            let existing_version: i64 = get(&row, "source_version")?;
            let existing_hash: String = get(&row, "payload_hash")?;
            let existing_epoch: i64 = get(&row, "projection_epoch")?;
            if existing_epoch <= 0 || existing_epoch > current_epoch {
                return Err(PolicyStoreError::Inconsistent);
            }
            if source_version < existing_version {
                return Err(PolicyStoreError::StaleVersion);
            }
            if source_version == existing_version {
                if payload_hash != existing_hash {
                    return Err(PolicyStoreError::Conflict);
                }
                transaction
                    .commit()
                    .await
                    .map_err(|_| PolicyStoreError::Backend)?;
                return Ok(existing_epoch);
            }
        }
        let epoch = current_epoch
            .checked_add(1)
            .ok_or(PolicyStoreError::Inconsistent)?;
        let updated =
            sqlx::query("UPDATE policy_state SET epoch=$1,updated_at=$2 WHERE id=1 AND epoch=$3")
                .bind(epoch)
                .bind(now)
                .bind(current_epoch)
                .execute(&mut *transaction)
                .await
                .map_err(|_| PolicyStoreError::Backend)?;
        if updated.rows_affected() != 1 {
            return Err(PolicyStoreError::Inconsistent);
        }
        sqlx::query("DELETE FROM policy_edges_v2 WHERE source_grant_id=$1")
            .bind(source_grant_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| PolicyStoreError::Backend)?;
        for edge in edges {
            let edge = edge.into_policy_edge(source_grant_id, epoch, now);
            let result = sqlx::query(
                "INSERT INTO policy_edges_v2 \
                 (edge_id,projection_key,source_grant_id,object,relation,subject,effect,resource_selector,condition,not_before,expires_at,active,version,projection_epoch,created_at,updated_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
            )
            .bind(edge.edge_id)
            .bind(edge.projection_key)
            .bind(edge.source_grant_id)
            .bind(edge.object)
            .bind(edge.relation)
            .bind(edge.subject)
            .bind(edge.effect.as_str())
            .bind(edge.resource_selector)
            .bind(edge.condition)
            .bind(edge.not_before)
            .bind(edge.expires_at)
            .bind(edge.active)
            .bind(edge.version)
            .bind(edge.projection_epoch)
            .bind(edge.created_at)
            .bind(edge.updated_at)
            .execute(&mut *transaction)
            .await;
            if let Err(error) = result {
                if has_sqlstate(&error, "23505") {
                    return Err(PolicyStoreError::Conflict);
                }
                return Err(PolicyStoreError::Backend);
            }
        }
        sqlx::query(
            "INSERT INTO policy_projection_source \
             (source_grant_id,source_version,payload_hash,projection_epoch,updated_at) \
             VALUES ($1,$2,$3,$4,$5) \
             ON CONFLICT (source_grant_id) DO UPDATE SET source_version=EXCLUDED.source_version, \
                 payload_hash=EXCLUDED.payload_hash,projection_epoch=EXCLUDED.projection_epoch, \
                 updated_at=EXCLUDED.updated_at",
        )
        .bind(source_grant_id)
        .bind(source_version)
        .bind(payload_hash)
        .bind(epoch)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PolicyStoreError::Backend)?;
        transaction
            .commit()
            .await
            .map_err(|_| PolicyStoreError::Backend)?;
        Ok(epoch)
    }

    async fn bump_epoch(&self, now: i64) -> Result<i64, PolicyStoreError> {
        sqlx::query(
            "UPDATE policy_state SET epoch=epoch+1,updated_at=$1 WHERE id=1 RETURNING epoch",
        )
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PolicyStoreError::Backend)?
        .ok_or(PolicyStoreError::Inconsistent)?
        .try_get("epoch")
        .map_err(|_| PolicyStoreError::Inconsistent)
    }

    async fn set_subject_status(
        &self,
        subject: &str,
        access_state: SubjectAccessState,
        source_event_id: &str,
        source_version: i64,
        now: i64,
    ) -> Result<(i64, bool), PolicyStoreError> {
        if source_version <= 0 {
            return Err(PolicyStoreError::Conflict);
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| PolicyStoreError::Backend)?;
        let current_epoch: i64 =
            sqlx::query("SELECT epoch FROM policy_state WHERE id=1 FOR UPDATE")
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| PolicyStoreError::Backend)?
                .ok_or(PolicyStoreError::Inconsistent)?
                .try_get("epoch")
                .map_err(|_| PolicyStoreError::Inconsistent)?;
        if let Some(row) = sqlx::query(
            "SELECT state,source_event_id,source_version,policy_epoch \
             FROM policy_subject_status WHERE subject=$1 FOR UPDATE",
        )
        .bind(subject)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PolicyStoreError::Backend)?
        {
            let existing_version: i64 = get(&row, "source_version")?;
            if source_version < existing_version {
                return Err(PolicyStoreError::StaleVersion);
            }
            if source_version == existing_version {
                let existing_state: String = get(&row, "state")?;
                let existing_event: String = get(&row, "source_event_id")?;
                let existing_epoch: i64 = get(&row, "policy_epoch")?;
                if existing_epoch <= 0 || existing_epoch > current_epoch {
                    return Err(PolicyStoreError::Inconsistent);
                }
                if existing_state != access_state.as_str() || existing_event != source_event_id {
                    return Err(PolicyStoreError::Conflict);
                }
                transaction
                    .commit()
                    .await
                    .map_err(|_| PolicyStoreError::Backend)?;
                return Ok((existing_epoch, true));
            }
        }
        let epoch = current_epoch
            .checked_add(1)
            .ok_or(PolicyStoreError::Inconsistent)?;
        let updated =
            sqlx::query("UPDATE policy_state SET epoch=$1,updated_at=$2 WHERE id=1 AND epoch=$3")
                .bind(epoch)
                .bind(now)
                .bind(current_epoch)
                .execute(&mut *transaction)
                .await
                .map_err(|_| PolicyStoreError::Backend)?;
        if updated.rows_affected() != 1 {
            return Err(PolicyStoreError::Inconsistent);
        }
        sqlx::query(
            "INSERT INTO policy_subject_status \
             (subject,state,source_event_id,source_version,policy_epoch,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6) \
             ON CONFLICT (subject) DO UPDATE SET state=EXCLUDED.state, \
                 source_event_id=EXCLUDED.source_event_id,source_version=EXCLUDED.source_version, \
                 policy_epoch=EXCLUDED.policy_epoch,updated_at=EXCLUDED.updated_at",
        )
        .bind(subject)
        .bind(access_state.as_str())
        .bind(source_event_id)
        .bind(source_version)
        .bind(epoch)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            if has_sqlstate(&error, "23505") || has_sqlstate(&error, "23514") {
                PolicyStoreError::Conflict
            } else {
                PolicyStoreError::Backend
            }
        })?;
        transaction
            .commit()
            .await
            .map_err(|_| PolicyStoreError::Backend)?;
        Ok((epoch, false))
    }
}

fn get<T>(row: &PgRow, column: &str) -> Result<T, PolicyStoreError>
where
    for<'r> T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send + Unpin,
{
    row.try_get(column)
        .map_err(|_| PolicyStoreError::Inconsistent)
}

fn has_sqlstate(error: &sqlx::Error, expected: &str) -> bool {
    error
        .as_database_error()
        .and_then(|database| database.code())
        .is_some_and(|code| code == expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::any_resource_selector;

    fn edge(id: &str, source_permission: &str) -> ProjectionEdge {
        ProjectionEdge {
            edge_id: id.to_string(),
            projection_key: format!("projection:{id}"),
            subject: "user:alice".to_string(),
            permission: source_permission.to_string(),
            effect: Effect::Allow,
            resource_selector: any_resource_selector(),
            condition: None,
            not_before: None,
            expires_at: None,
            active: true,
            version: 1,
        }
    }

    async fn replace(
        store: &InMemoryPolicyStore,
        source_grant_id: &str,
        source_version: i64,
        edges: Vec<ProjectionEdge>,
        now: i64,
    ) -> Result<i64, PolicyStoreError> {
        let payload_hash = projection_payload_hash(&edges).unwrap();
        store
            .replace_projection(source_grant_id, source_version, &payload_hash, edges, now)
            .await
    }

    #[tokio::test]
    async fn projection_replace_bumps_epoch_and_preserves_other_evidence() {
        let store = InMemoryPolicyStore::new();
        assert_eq!(
            replace(
                &store,
                "grant:a",
                1,
                vec![edge("edge:a", "cpa.console.enter")],
                1,
            )
            .await
            .unwrap(),
            1
        );
        replace(
            &store,
            "grant:b",
            1,
            vec![edge("edge:b", "cpa.console.enter")],
            2,
        )
        .await
        .unwrap();
        replace(&store, "grant:a", 2, vec![], 3).await.unwrap();
        let snapshot = store
            .snapshot("cpa.console.enter", "user:alice")
            .await
            .unwrap();
        assert_eq!(snapshot.epoch, 3);
        assert_eq!(snapshot.edges.len(), 1);
        assert_eq!(snapshot.edges[0].source_grant_id, "grant:b");
    }

    #[tokio::test]
    async fn projection_source_version_is_monotonic_and_idempotent() {
        let store = InMemoryPolicyStore::new();
        let allow = vec![edge("edge:allow", "cpa.console.enter")];
        let first_epoch = replace(&store, "grant:source", 1, allow.clone(), 1)
            .await
            .unwrap();
        let revoked_epoch = replace(&store, "grant:source", 2, vec![], 2).await.unwrap();
        assert!(revoked_epoch > first_epoch);
        assert_eq!(
            replace(&store, "grant:source", 2, vec![], 3).await.unwrap(),
            revoked_epoch,
            "same version and payload is an epoch-stable replay"
        );
        assert!(matches!(
            replace(&store, "grant:source", 1, allow.clone(), 4).await,
            Err(PolicyStoreError::StaleVersion)
        ));
        let mut conflicting = allow;
        conflicting[0].version = 2;
        assert!(matches!(
            replace(&store, "grant:source", 2, conflicting, 5).await,
            Err(PolicyStoreError::Conflict)
        ));
        assert!(store
            .snapshot("cpa.console.enter", "user:alice")
            .await
            .unwrap()
            .edges
            .is_empty());
    }
}
