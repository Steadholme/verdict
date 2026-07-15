# Verdict — policy decision point (Steadholme)

Zanzibar-style ReBAC/ABAC authorization for the Steadholme estate: relation tuples plus a `check`
API every backend service can consult. v1 implements relation tuples + recursive group/role
expansion via SQL reads (no external OpenFGA/SpiceDB).

## Model

A tuple is the triple `object#relation@subject`:

- `doc:readme#viewer@user:w33d` — a direct grant.
- `group:eng#member@user:w33d` — group membership.
- `doc:secret#viewer@group:eng#member` — a grant to a **userset**, which models indirection: it
  means "everyone with `member` on `group:eng` is a `viewer` of `doc:secret`".

`check(object, relation, subject)` is true when a direct tuple exists OR when the subject is reached
through userset indirection, expanded recursively up to **5 levels** deep (cycles terminate at the
depth ceiling). The resolution path is returned so callers can see *how* a grant was reached.

## Surfaces (route-split, one subdomain `authz.w33d.xyz`)

- **`/` admin console — gateway `auth=sso`.** Browse/add/delete tuples, a live check tester, an
  expand view (who holds a relation), and a list-objects view (what a subject can do). The gateway
  injects the verified `X-Auth-*`; Verdict trusts it (internal-only). Console POSTs carry a
  double-submit `__Host-csrf` token.
- **`/api/*` decision API — gateway `auth=public`, Verdict's OWN service-token auth.** Other
  backends call it over the network; the gateway passes `Authorization` through and Verdict checks
  `Bearer <VERDICT_SERVICE_TOKEN>` itself.

| Method + path             | Auth   | Body / result |
|---------------------------|--------|---------------|
| `GET  /healthz`           | none   | `200 ok` |
| `GET  /`                  | sso    | console HTML |
| `POST /`                  | sso    | add tuple (CSRF) |
| `POST /delete`            | sso    | delete tuple (CSRF) |
| `POST /api/check`         | bearer | `{object,relation,subject}` → `{allowed,via}` |
| `POST /api/tuples`        | bearer | write a tuple → `{ok,written}` |
| `POST /api/tuples/delete` | bearer | delete a tuple → `{ok,deleted}` |
| `POST /api/list-objects`  | bearer | `{relation,subject}` → `{objects}` |
| `POST /api/expand`        | bearer | `{object,relation}` → `{direct,members}` |

## Configuration (zero-config by default)

| Env | Default | Meaning |
|-----|---------|---------|
| `BIND_ADDR` | `0.0.0.0:9140` | listen address |
| `VERDICT_STORE` | `memory` | `memory` \| `postgres` |
| `DATABASE_URL` | — | required when `VERDICT_STORE=postgres` (db `verdict`) |
| `VERDICT_SERVICE_TOKEN` | — | enforced `/api/*` bearer; empty disables `/api/*` auth (dev) |
| `AUDIT_ENABLED` | `false` | enable the Watchtower audit emitter |
| `WATCHTOWER_URL` | — | e.g. `http://watchtower:8500` |
| `AUDIT_INGEST_TOKEN` | — | bearer for Watchtower ingest |

On an empty store the documented example tuple set is seeded so the console tester demonstrates
indirection on first run. Audit events: `verdict.tuple.write` (writes/deletes) and
`verdict.check.deny` (a denied `/api/check`).

## Build / test

```sh
CARGO_BUILD_JOBS=2 cargo check --all-targets
cargo test                  # in-memory, no database, no network
# Postgres integration (optional):
#   TEST_DATABASE_URL=postgres://… cargo test --test pg_store -- --nocapture
```
