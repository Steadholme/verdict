use verdict::policy::{any_resource_selector, Effect, ProjectionEdge, SubjectAccessState};
use verdict::policy_store::{
    projection_payload_hash, PgPolicyStore, PolicyStore, PolicyStoreError,
};
use verdict::store::PgStore;

fn allow_edge(suffix: &str, version: i64) -> ProjectionEdge {
    ProjectionEdge {
        edge_id: format!("edge:projection-fence:{suffix}"),
        projection_key: format!("projection:fence:{suffix}"),
        subject: "user:alice".to_string(),
        permission: "cpa.console.enter".to_string(),
        effect: Effect::Allow,
        resource_selector: any_resource_selector(),
        condition: None,
        not_before: None,
        expires_at: None,
        active: true,
        version,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_projection_source_fence_rejects_late_allow() {
    let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping policy projection PG test");
        return;
    };
    let tuple_store = PgStore::connect(&database_url).await.unwrap();
    tuple_store.migrate().await.unwrap();
    let store = PgPolicyStore::connect(&database_url).await.unwrap();
    store.migrate().await.unwrap();
    store
        .migrate()
        .await
        .expect("policy migrations are idempotent");

    let suffix = verdict::now_nanos().to_string();
    let source = format!("grant:projection-fence:{suffix}");
    let allow_v1 = vec![allow_edge(&suffix, 1)];
    let allow_v1_hash = projection_payload_hash(&allow_v1).unwrap();
    let first_epoch = store
        .replace_projection(&source, 1, &allow_v1_hash, allow_v1.clone(), 1)
        .await
        .unwrap();

    let empty = Vec::<ProjectionEdge>::new();
    let empty_hash = projection_payload_hash(&empty).unwrap();
    let revoke_epoch = store
        .replace_projection(&source, 2, &empty_hash, empty.clone(), 2)
        .await
        .unwrap();
    assert!(revoke_epoch > first_epoch);
    assert_eq!(
        store
            .replace_projection(&source, 2, &empty_hash, empty, 3)
            .await
            .unwrap(),
        revoke_epoch
    );
    assert!(matches!(
        store
            .replace_projection(&source, 1, &allow_v1_hash, allow_v1, 4)
            .await,
        Err(PolicyStoreError::StaleVersion)
    ));

    let allow_v2 = vec![allow_edge(&suffix, 2)];
    let allow_v2_hash = projection_payload_hash(&allow_v2).unwrap();
    assert!(matches!(
        store
            .replace_projection(&source, 2, &allow_v2_hash, allow_v2, 5)
            .await,
        Err(PolicyStoreError::Conflict)
    ));

    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let edge_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM policy_edges_v2 WHERE source_grant_id=$1")
            .bind(&source)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(edge_count, 0, "the late allow cannot resurrect the edge");

    let subject = format!("user:jml-{suffix}");
    let (frozen_epoch, replayed) = store
        .set_subject_status(
            &subject,
            SubjectAccessState::Terminated,
            &format!("event:{suffix}"),
            7,
            6,
        )
        .await
        .unwrap();
    assert!(!replayed);
    assert_eq!(
        store
            .set_subject_status(
                &subject,
                SubjectAccessState::Terminated,
                &format!("event:{suffix}"),
                7,
                7,
            )
            .await
            .unwrap(),
        (frozen_epoch, true)
    );
    assert!(matches!(
        store
            .set_subject_status(
                &subject,
                SubjectAccessState::Active,
                &format!("event:stale:{suffix}"),
                6,
                8,
            )
            .await,
        Err(PolicyStoreError::StaleVersion)
    ));
    let snapshot = store.snapshot("cpa.console.enter", &subject).await.unwrap();
    let status = snapshot.subject_status.expect("durable subject status");
    assert_eq!(status.state, SubjectAccessState::Terminated);
    assert_eq!(status.policy_epoch, frozen_epoch);

    sqlx::query("DELETE FROM policy_projection_source WHERE source_grant_id=$1")
        .bind(&source)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM policy_subject_status WHERE subject=$1")
        .bind(&subject)
        .execute(&pool)
        .await
        .unwrap();
}
