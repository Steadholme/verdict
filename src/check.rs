//! The decision engine: a bounded recursive expansion of relation tuples over the [`Store`] reads.
//!
//! Zanzibar semantics, v1 subset. `check(object, relation, subject)` is true when EITHER:
//!   1. a direct tuple `(object, relation, subject)` exists, OR
//!   2. some tuple `(object, relation, US)` grants the relation to a *userset* `US = "ns:id#rel"`,
//!      and the subject is (recursively) a member of that userset — `check(ns:id, rel, subject)`.
//!
//! The recursion is bounded by [`MAX_DEPTH`]: at most five levels of userset indirection are
//! followed, which both matches the spec and guarantees termination even on cyclic group graphs
//! (a cycle simply hits the depth ceiling and yields "not a member"). The resolution path is
//! returned alongside the boolean so callers (and the console tester) can see HOW a grant was
//! reached.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;

use serde::Serialize;

use crate::store::Store;

/// Maximum levels of userset indirection followed during expansion.
pub const MAX_DEPTH: usize = 5;

/// Outcome of a [`check`]: the boolean plus the resolution path (empty when denied). Each path step
/// is a tuple in `object#relation@subject` notation, from the queried object down to the direct
/// grant that satisfied it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    pub allowed: bool,
    pub via: Vec<String>,
}

/// Render a tuple in the canonical `object#relation@subject` notation used throughout the UI/API.
pub fn tuple_label(object: &str, relation: &str, subject: &str) -> String {
    format!("{object}#{relation}@{subject}")
}

/// Split a userset subject `"ns:id#rel"` into its `(object, relation)`. Returns `None` for a
/// concrete principal (no `#`).
pub fn parse_userset(subject: &str) -> Option<(&str, &str)> {
    subject.split_once('#')
}

/// `true` when `subject` is a userset reference (`group:eng#member`) rather than a concrete
/// principal (`user:w33d`).
pub fn is_userset(subject: &str) -> bool {
    subject.contains('#')
}

/// Decide `check(object, relation, subject)` with the bounded expansion above.
pub async fn check(store: &dyn Store, object: &str, relation: &str, subject: &str) -> CheckOutcome {
    match check_rec(
        store,
        object.to_string(),
        relation.to_string(),
        subject.to_string(),
        0,
    )
    .await
    {
        Some(via) => CheckOutcome { allowed: true, via },
        None => CheckOutcome {
            allowed: false,
            via: Vec::new(),
        },
    }
}

/// Recursive core. Owns its `String` arguments so the boxed future has no borrow entanglement with
/// the per-level `subjects` vector. Returns `Some(path)` on a grant, `None` otherwise.
fn check_rec<'a>(
    store: &'a dyn Store,
    object: String,
    relation: String,
    subject: String,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Option<Vec<String>>> + Send + 'a>> {
    Box::pin(async move {
        let subjects = store.subjects_for(&object, &relation).await;

        // (1) Direct grant.
        if subjects.iter().any(|s| s == &subject) {
            return Some(vec![tuple_label(&object, &relation, &subject)]);
        }

        // Depth ceiling: do not follow further userset indirection.
        if depth >= MAX_DEPTH {
            return None;
        }

        // (2) Userset indirection: follow each `ns:id#rel` grant one level down.
        for s in &subjects {
            if let Some((us_obj, us_rel)) = parse_userset(s) {
                if let Some(mut sub_path) = check_rec(
                    store,
                    us_obj.to_string(),
                    us_rel.to_string(),
                    subject.clone(),
                    depth + 1,
                )
                .await
                {
                    let mut path = vec![tuple_label(&object, &relation, s)];
                    path.append(&mut sub_path);
                    return Some(path);
                }
            }
        }

        None
    })
}

/// `list-objects`: every object on which `subject` holds `relation`. Enumerates the candidate
/// objects carrying that relation, then runs the full [`check`] on each (so userset indirection is
/// honored). Returned sorted + de-duplicated.
pub async fn list_objects(store: &dyn Store, relation: &str, subject: &str) -> Vec<String> {
    let candidates = store.objects_with_relation(relation).await;
    let mut out: Vec<String> = Vec::new();
    for object in candidates {
        if check(store, &object, relation, subject).await.allowed {
            out.push(object);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Result of an [`expand`]: the raw subjects directly granted the relation (usersets included),
/// the fully-resolved set of concrete principals (usersets flattened up to [`MAX_DEPTH`]), plus a
/// tree preserving the userset hops for the console's "who-can-access" view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expansion {
    pub direct: Vec<String>,
    pub members: Vec<String>,
    pub tree: Vec<ExpansionNode>,
}

/// One node in an [`Expansion`] tree. `subject` is the tuple subject shown at this level; userset
/// subjects carry children resolved from their referenced `(object, relation)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExpansionNode {
    pub subject: String,
    pub userset: bool,
    pub children: Vec<ExpansionNode>,
}

/// `expand`: who holds `relation` on `object`. Returns the direct grants and the flattened set of
/// concrete principals reached by following usersets breadth-first (bounded by [`MAX_DEPTH`], with
/// a visited set so a cyclic group graph terminates without re-walking).
pub async fn expand(store: &dyn Store, object: &str, relation: &str) -> Expansion {
    let direct = store.subjects_for(object, relation).await;

    let mut members: BTreeSet<String> = BTreeSet::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut queue: VecDeque<(String, String, usize)> = VecDeque::new();
    let mut tree = Vec::new();

    for s in &direct {
        match parse_userset(s) {
            Some((o, r)) => queue.push_back((o.to_string(), r.to_string(), 1)),
            None => {
                members.insert(s.clone());
            }
        }
        tree.push(expansion_node(store, s.clone(), 1, &mut HashSet::new()).await);
    }

    while let Some((o, r, depth)) = queue.pop_front() {
        if depth > MAX_DEPTH {
            continue;
        }
        if !seen.insert((o.clone(), r.clone())) {
            continue;
        }
        for s in store.subjects_for(&o, &r).await {
            match parse_userset(&s) {
                Some((no, nr)) => queue.push_back((no.to_string(), nr.to_string(), depth + 1)),
                None => {
                    members.insert(s);
                }
            }
        }
    }

    Expansion {
        direct,
        members: members.into_iter().collect(),
        tree,
    }
}

fn expansion_node<'a>(
    store: &'a dyn Store,
    subject: String,
    depth: usize,
    seen: &'a mut HashSet<(String, String)>,
) -> Pin<Box<dyn Future<Output = ExpansionNode> + Send + 'a>> {
    Box::pin(async move {
        let Some((object, relation)) = parse_userset(&subject) else {
            return ExpansionNode {
                subject,
                userset: false,
                children: Vec::new(),
            };
        };

        let mut node = ExpansionNode {
            subject: subject.clone(),
            userset: true,
            children: Vec::new(),
        };
        if depth > MAX_DEPTH {
            return node;
        }

        let key = (object.to_string(), relation.to_string());
        if !seen.insert(key.clone()) {
            return node;
        }

        for child in store.subjects_for(object, relation).await {
            node.children
                .push(expansion_node(store, child, depth + 1, seen).await);
        }
        seen.remove(&key);
        node
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{InMemoryStore, Tuple};

    fn t(object: &str, relation: &str, subject: &str) -> Tuple {
        Tuple {
            id: format!("tup_{object}_{relation}_{subject}"),
            object: object.to_string(),
            relation: relation.to_string(),
            subject: subject.to_string(),
            created_at: 1,
        }
    }

    async fn seeded() -> InMemoryStore {
        let s = InMemoryStore::new();
        s.add_tuple(&t("doc:readme", "viewer", "user:w33d"))
            .await
            .unwrap();
        s.add_tuple(&t("group:eng", "member", "user:w33d"))
            .await
            .unwrap();
        s.add_tuple(&t("doc:secret", "viewer", "group:eng#member"))
            .await
            .unwrap();
        s
    }

    #[tokio::test]
    async fn direct_grant_is_allowed() {
        let s = seeded().await;
        let r = check(&s, "doc:readme", "viewer", "user:w33d").await;
        assert!(r.allowed);
        assert_eq!(r.via, vec!["doc:readme#viewer@user:w33d"]);
    }

    #[tokio::test]
    async fn indirection_through_userset_is_allowed() {
        let s = seeded().await;
        let r = check(&s, "doc:secret", "viewer", "user:w33d").await;
        assert!(r.allowed);
        assert_eq!(
            r.via,
            vec![
                "doc:secret#viewer@group:eng#member",
                "group:eng#member@user:w33d",
            ]
        );
    }

    #[tokio::test]
    async fn unrelated_subject_is_denied() {
        let s = seeded().await;
        let r = check(&s, "doc:secret", "viewer", "user:intruder").await;
        assert!(!r.allowed);
        assert!(r.via.is_empty());
    }

    #[tokio::test]
    async fn cyclic_group_graph_terminates_and_denies() {
        let s = InMemoryStore::new();
        // group:a member <- group:b#member ; group:b member <- group:a#member (a cycle).
        s.add_tuple(&t("group:a", "member", "group:b#member"))
            .await
            .unwrap();
        s.add_tuple(&t("group:b", "member", "group:a#member"))
            .await
            .unwrap();
        let r = check(&s, "group:a", "member", "user:nobody").await;
        assert!(!r.allowed);
    }

    #[tokio::test]
    async fn depth_ceiling_blocks_beyond_five_levels() {
        let s = InMemoryStore::new();
        // Chain g0 <- g1#m <- g2#m <- ... <- g6#m, with user:deep a direct member of g6.
        for i in 0..6 {
            s.add_tuple(&t(&format!("g{i}"), "m", &format!("g{}#m", i + 1)))
                .await
                .unwrap();
        }
        s.add_tuple(&t("g6", "m", "user:deep")).await.unwrap();
        // g1 is reachable from g0 at depth 1; user:deep sits 6 hops below g0 -> beyond the ceiling.
        let r = check(&s, "g0", "m", "user:deep").await;
        assert!(!r.allowed, "a 6-level chain must exceed MAX_DEPTH=5");
        // But starting one level in (g1), the same user is exactly 5 hops away -> allowed.
        let r2 = check(&s, "g1", "m", "user:deep").await;
        assert!(r2.allowed);
    }

    #[tokio::test]
    async fn list_objects_includes_indirect_grants() {
        let s = seeded().await;
        let objs = list_objects(&s, "viewer", "user:w33d").await;
        assert_eq!(objs, vec!["doc:readme", "doc:secret"]);
    }

    #[tokio::test]
    async fn expand_flattens_usersets_to_concrete_members() {
        let s = seeded().await;
        let e = expand(&s, "doc:secret", "viewer").await;
        assert_eq!(e.direct, vec!["group:eng#member"]);
        assert_eq!(e.members, vec!["user:w33d"]);
        assert_eq!(e.tree.len(), 1);
        assert_eq!(e.tree[0].subject, "group:eng#member");
        assert!(e.tree[0].userset);
        assert_eq!(e.tree[0].children[0].subject, "user:w33d");
        assert!(!e.tree[0].children[0].userset);
    }
}
