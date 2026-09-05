use verdict::policy::{ApplicationSubjectState, ApplicationSubjectStatus};
use verdict::policy_store::{InMemoryPolicyStore, PgPolicyStore, PolicyStore, PolicyStoreError};

async fn verify_same_state_updates(store: &dyn PolicyStore) {
    use ApplicationSubjectState::{Active, Expired, Pending, Revoked, Suspended};
    for state in [Pending, Active, Suspended, Revoked, Expired] {
        let mut status = ApplicationSubjectStatus {
            application_sub: format!(
                "application:versions_{}_{}",
                state.as_str(),
                verdict::now_nanos()
            ),
            state,
            source_event_id: "event_initial_version".to_string(),
            subject_version: 1,
            policy_epoch: 2,
            revocation_epoch: 3,
            updated_at: 1,
        };
        assert!(!store
            .set_application_subject_status(status.clone())
            .await
            .unwrap());
        let original = status.clone();
        status.subject_version += 1;
        status.revocation_epoch += 1;
        status.source_event_id = "event_credential_revoked".to_string();
        status.updated_at += 1;
        assert!(!store
            .set_application_subject_status(status.clone())
            .await
            .unwrap());
        assert!(store
            .set_application_subject_status(status.clone())
            .await
            .unwrap());

        assert!(matches!(
            store.set_application_subject_status(original).await,
            Err(PolicyStoreError::StaleVersion)
        ));
        let mut conflicting = status.clone();
        conflicting.source_event_id = "event_conflicting_same_version".to_string();
        assert!(matches!(
            store.set_application_subject_status(conflicting).await,
            Err(PolicyStoreError::Conflict)
        ));
        for field in ["policy", "revocation"] {
            let mut stale = status.clone();
            stale.subject_version += 1;
            if field == "policy" {
                stale.policy_epoch -= 1;
            } else {
                stale.revocation_epoch -= 1;
            }
            assert!(matches!(
                store.set_application_subject_status(stale).await,
                Err(PolicyStoreError::StaleVersion)
            ));
        }
        let mut candidate = status.clone();
        candidate.subject_version += 1;
        candidate.source_event_id = "event_illegal_state_change".to_string();
        for to in [Pending, Active, Suspended, Revoked, Expired] {
            if (matches!(state, Revoked | Expired) && to != state)
                || (matches!(state, Active | Suspended) && to == Pending)
            {
                candidate.state = to;
                assert!(matches!(
                    store
                        .set_application_subject_status(candidate.clone())
                        .await,
                    Err(PolicyStoreError::Conflict)
                ));
            }
        }
        let stored = store
            .application_subject_status(&status.application_sub)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.state, state);
        assert_eq!(stored.subject_version, status.subject_version);
        assert_eq!(stored.policy_epoch, status.policy_epoch);
        assert_eq!(stored.revocation_epoch, status.revocation_epoch);
    }
}

#[tokio::test]
async fn memory_accepts_same_state_versions_without_rollback_or_revival() {
    verify_same_state_updates(&InMemoryPolicyStore::new()).await;
}

#[tokio::test]
async fn postgres_accepts_same_state_versions_without_rollback_or_revival() {
    let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; PostgreSQL lifecycle test not exercised");
        return;
    };
    let store = PgPolicyStore::connect(&database_url).await.unwrap();
    store.migrate().await.unwrap();
    verify_same_state_updates(&store).await;
}
