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
- **`/api/*` service APIs — gateway `auth=public`, Verdict's scoped credential auth.** The gateway
  passes `Authorization` through and each handler accepts exactly one independent credential:
  decision, desired-state projection, or JML lifecycle. A credential valid for one scope is `401`
  on every endpoint in the other two scopes.

| Method + path | Auth scope | Body / result |
|---|---|---|
| `GET  /healthz` | none | `200 ok` |
| `GET  /` | SSO | console HTML |
| `POST /` | SSO | add tuple (CSRF) |
| `POST /delete` | SSO | delete tuple (CSRF) |
| `POST /api/check` | decision | `{object,relation,subject}` → `{allowed,via}` |
| `POST /api/v2/check` | decision | typed permission/resource/context decision with epoch + evidence |
| `POST /api/list-objects` | decision | `{relation,subject}` → `{objects}` |
| `POST /api/expand` | decision | `{object,relation}` → `{direct,members}` |
| `POST /api/v2/projections` | projection | fenced desired-state replacement for one Access Governance grant |
| `POST /api/tuples` | projection | legacy tuple write → `{ok,written}` |
| `POST /api/tuples/delete` | projection | legacy tuple delete → `{ok,deleted}` |
| `POST /api/tuples/import` | projection | legacy tuple bulk import |
| `POST /api/tuples/export` | projection | legacy tuple export |
| `POST /api/v2/subject-status` | lifecycle | fenced JML `active`/`frozen`/`terminated` state for one exact `user:` subject |

## Configuration (zero-config by default)

| Env | Default | Meaning |
|-----|---------|---------|
| `BIND_ADDR` | `0.0.0.0:9140` | listen address |
| `VERDICT_STORE` | `memory` | `memory` \| `postgres` |
| `DATABASE_URL` | — | required when `VERDICT_STORE=postgres` (db `verdict`) |
| `VERDICT_DECISION_TOKEN` | — | Bearer for decision/read endpoints only |
| `VERDICT_PROJECTION_TOKEN` | — | Bearer for desired-state projection and legacy tuple administration only |
| `VERDICT_LIFECYCLE_TOKEN` | — | Bearer for JML subject lifecycle only |
| `AUDIT_ENABLED` | `false` | enable the Watchtower audit emitter |
| `WATCHTOWER_URL` | — | e.g. `http://watchtower:8500` |
| `AUDIT_INGEST_TOKEN` | — | bearer for Watchtower ingest |

The three service tokens must each contain 32–512 visible ASCII bytes and must be pairwise
distinct. `VERDICT_STORE=postgres` fails startup unless all three are valid. The memory store may
run without service authentication only when all three variables are empty; partial configuration
always fails startup. `VERDICT_SERVICE_TOKEN` is retired and is never a fallback master token: a
non-empty legacy variable causes an explicit startup error.

Client integration is intentionally narrow:

- PDP/PEP decision clients use `VERDICT_DECISION_TOKEN`.
- Access Governance's projection worker uses `VERDICT_PROJECTION_TOKEN`.
- Access Governance's JML consequence worker uses `VERDICT_LIFECYCLE_TOKEN`.
- Any retained legacy tuple administration client uses `VERDICT_PROJECTION_TOKEN`.

Every client sends its credential as `Authorization: Bearer <token>`. Generate three independent
random values; do not reuse or derive one from another. Audit actors contain only the redacted
scope labels `service:decision`, `service:projection`, or `service:lifecycle`.

On an empty store the documented example tuple set is seeded so the console tester demonstrates
indirection on first run. Audit events include `verdict.tuple.write` (writes/deletes) and
`verdict.check.deny` (a denied `/api/check`).

The v2 evaluator applies subject status before any permission edge. `frozen` and
`terminated` therefore deny every permission at the central PDP, including permissions
added after the JML event. Replays with the same `source_version` and payload are epoch-stable;
older or conflicting updates return `409`.

## Build / test

```sh
CARGO_BUILD_JOBS=2 cargo check --all-targets
cargo test                  # in-memory, no database, no network
# Postgres integration (optional):
#   TEST_DATABASE_URL=postgres://… cargo test --test pg_store -- --nocapture
```

## 前端 v2（2026-09-08）

控制台按 Figma 文件 `iS3iDUEUHMzGvXmOipjAbO`（Verdict，wine accent）重做，拆成四个页面，
应用栏用同一组导航药丸串起来：

| 路由 | 页面 |
|---|---|
| `/` | Relation tuples 表（搜索 / 类型筛选 / 分页）、Add tuple、Import·export，右栏 Check tester + Expand + List objects |
| `/decisions` | v2 决策检查器：请求表单（subject / permission / resource / context / risk）→ 判定横幅、决策事实表、证据行、响应 JSON |
| `/expand` | 整页展开：访问树、直接授予、展平成员、展开事实 |
| `/list-objects` | 主体可达对象，标出经由哪个 userset |
| `/subjects` | JML 生命周期记录与围栏写入表单 |
| `/api` | 端点表（每条带凭据 scope）、两段 curl 示例、三个凭据 |

一条关系元组在任何位置都渲染成三枚定型 chip（蓝 object · 酒红 relation · 灰 subject，
userset 为紫色虚线），删除走独立确认页 `GET /delete`（POST 仍带 CSRF），无需 JavaScript。

**凭据只显示指纹。** `/api` 页面给出每个 token 的名字、长度与 `sha256` 前 16 位，
**不渲染 token 值** —— 控制台读者不应能从页面上取走服务凭据（设计稿里的 Reveal 按钮据此去掉，
`tests/verdict_flow.rs::api_page_shows_fingerprints_not_token_values` 固定这条）。

样式在 `static/service.css`，与 Odyssey 基底层叠后由 `/assets/verdict-20260908.css` 以不可变
缓存提供；改样式时同步提升该路径里的日期（测试会断言路径）。
