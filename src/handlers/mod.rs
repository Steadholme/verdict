//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `console` carries the SSO admin UI (browse /
//! add / delete tuples, a live check tester, and an expand view); `api` carries the
//! service-token-authed JSON decision API every other Steadholme service consults.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and served from one versioned,
//! immutable stylesheet, matching the Steadholme enterprise brand without repeating the payload
//! in every HTML response.

pub mod api;
pub mod api_v2;
pub mod console;
pub mod health;
pub mod pages;
pub mod ui;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use std::sync::OnceLock;

/// Verdict-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");

/// Versioned stylesheet URL. Change the date whenever the embedded CSS changes.
pub const APP_CSS_PATH: &str = "/assets/verdict-20260908.css";

static APP_CSS: OnceLock<String> = OnceLock::new();

/// Embedded design system (Odyssey canonical + Verdict service CSS), assembled once per process.
pub fn app_css() -> &'static str {
    APP_CSS
        .get_or_init(|| {
            let mut css = String::with_capacity(odyssey::APP_CSS.len() + SERVICE_CSS.len());
            css.push_str(odyssey::APP_CSS);
            css.push_str(SERVICE_CSS);
            css
        })
        .as_str()
}

/// Identity-independent stylesheet with an immutable one-year cache policy.
pub async fn app_css_asset() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
        ],
        app_css(),
    )
}

/// Cross-subdomain gateway logout (Verdict lives at authz.w33d.xyz; the IdP is at id.w33d.xyz).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Minimal HTML escaping for text/attribute interpolation (defense-in-depth on every field).
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Icons used across the console chrome (inline so no asset request is needed).
pub const ICON_MARK: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v18"/><path d="M5 7h14"/><path d="M5 7 2 14h6L5 7Z"/><path d="M19 7l-3 7h6l-3-7Z"/><path d="M8 21h8"/></svg>"##;
pub const ICON_GRID: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"##;
pub const ICON_SEARCH: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>"##;
pub const ICON_PLUS: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>"##;
pub const ICON_PLAY: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 4 14 8-14 8V4Z"/></svg>"##;
pub const ICON_DOWNLOAD: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12"/><path d="m7 11 5 5 5-5"/><path d="M4 20h16"/></svg>"##;
pub const ICON_UPLOAD: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20V8"/><path d="m7 12 5-5 5 5"/><path d="M4 4h16"/></svg>"##;
pub const ICON_BRANCH: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="6" cy="5" r="2.5"/><circle cx="6" cy="19" r="2.5"/><circle cx="18" cy="12" r="2.5"/><path d="M6 7.5v9"/><path d="M8.5 5H13a2.5 2.5 0 0 1 2.5 2.5V10"/></svg>"##;
pub const ICON_LIST: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 6h13M8 12h13M8 18h13"/><path d="M3 6h.01M3 12h.01M3 18h.01"/></svg>"##;
pub const ICON_SNOW: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v18M4.5 7.5l15 9M19.5 7.5l-15 9"/></svg>"##;
pub const ICON_CHECK: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 12 5 5L20 6"/></svg>"##;
pub const ICON_X: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>"##;
pub const ICON_USER_X: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="9" cy="8" r="3.5"/><path d="M3 20c0-3.3 2.7-6 6-6h1"/><path d="m16 14 5 5M21 14l-5 5"/></svg>"##;
pub const ICON_USER_CHECK: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="9" cy="8" r="3.5"/><path d="M3 20c0-3.3 2.7-6 6-6h1"/><path d="m15 16 2 2 4-4"/></svg>"##;
pub const ICON_LOCK: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>"##;
pub const ICON_KEY: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="8" r="4"/><path d="m11 11 9 9"/><path d="m17 17 2-2M20 20l2-2"/></svg>"##;
pub const ICON_ARROW_LEFT: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 12H5"/><path d="m11 6-6 6 6 6"/></svg>"##;
pub const ICON_TRASH: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 7h16"/><path d="M9 7V5h6v2"/><path d="M6 7l1 13h10l1-13"/></svg>"##;

/// The four console pages, in app-bar order.
pub const NAV: [(&str, &str); 4] = [
    ("/", "Console"),
    ("/decisions", "Decisions"),
    ("/subjects", "Subjects"),
    ("/api", "API"),
];

/// Render the app bar: brand lockup + host + the four page pills on the left, epoch, All apps,
/// identity and Log out on the right. `active` is the href of the current page.
pub fn app_bar(active: &str, email: &str, epoch: i64) -> String {
    let mut pills = String::new();
    for (href, label) in NAV {
        let class = if href == active {
            "surf surf--nav is-active"
        } else {
            "surf surf--nav"
        };
        pills.push_str(&format!(
            r#"<a class="{class}" href="{href}">{label}</a>"#,
            class = class,
            href = href,
            label = label,
        ));
    }
    let chip = if email.is_empty() || email == "—" {
        r#"<span class="user-email user-email--none">— (no gateway session)</span>"#.to_string()
    } else {
        let initial = email
            .chars()
            .next()
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "S".to_string());
        format!(
            r#"<span class="userchip"><span class="userchip__avatar" aria-hidden="true">{initial}</span><span class="user-email">{email}</span></span>"#,
            initial = esc(&initial),
            email = esc(email),
        )
    };
    format!(
        r#"<header class="suitebar">
  <a class="suitebar__brand" href="/">
    <span class="brand-tile" aria-hidden="true">{mark}</span>
    <span class="suitebar__name"><b>Steadholme</b><span>Verdict · authorization</span></span>
  </a>
  <span class="suitebar__host">authz.w33d.xyz</span>
  <nav class="surfaces" aria-label="Verdict pages">{pills}</nav>
  <span class="suitebar__spacer"></span>
  <div class="suitebar__right">
    <span class="epoch">epoch {epoch}</span>
    <a class="allapps" href="https://w33d.xyz">{grid}<span>All apps</span></a>
    {chip}
    <a class="btn btn-ghost btn-sm" href="{logout}">Log out</a>
  </div>
</header>"#,
        mark = ICON_MARK,
        pills = pills,
        epoch = epoch,
        grid = ICON_GRID,
        chip = chip,
        logout = LOGOUT_URL,
    )
}

/// The shared page footer.
pub const FOOTER: &str = r##"<footer class="v2-foot">
  <span class="v2-foot__lead">Steadholme Verdict · authz.w33d.xyz · v1 tuples + v2 policy</span>
  <a href="https://access.w33d.xyz">Access</a>
  <a href="https://id.w33d.xyz">Keystone</a>
  <a href="https://audit.w33d.xyz">Watchtower</a>
  <a href="https://status.w33d.xyz">Status</a>
  <a href="https://w33d.xyz">All apps</a>
</footer>"##;

/// Fill a page template's chrome placeholders: theme attributes, stylesheet, app bar, footer.
pub fn shell(template: &str, headers: &HeaderMap, active: &str, email: &str, epoch: i64) -> String {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok());
    let theme = odyssey::resolve_theme(cookie);
    template
        .replace("{{THEME_ATTR}}", odyssey::html_theme_attr(theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(theme))
        .replace("{{CSS_PATH}}", APP_CSS_PATH)
        .replace("{{APPBAR}}", &app_bar(active, email, epoch))
        .replace("{{FOOTER}}", FOOTER)
}

/// Format epoch seconds as a compact UTC `Mon D, YYYY` (e.g. `Jun 30, 2026`). std `time` only.
pub fn fmt_date(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!("{} {}, {}", month_abbr(dt.month()), dt.day(), dt.year()),
        Err(_) => secs.to_string(),
    }
}

/// Format epoch seconds as `2026-09-08 10:12:41 UTC` — the decision inspector needs the second,
/// not just the day.
pub fn fmt_datetime(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            dt.year(),
            u8::from(dt.month()),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        Err(_) => secs.to_string(),
    }
}

fn month_abbr(m: time::Month) -> &'static str {
    use time::Month::*;
    match m {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    }
}

/// A branded HTML error document: one status tile with the code, the reason and the message.
pub fn error_page(status: StatusCode, message: &str) -> String {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error");
    let template = format!(
        r#"<!DOCTYPE html>
<html lang="en"{{{{THEME_ATTR}}}}>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="{{{{COLOR_SCHEME}}}}">
  <title>{code} {reason} · Verdict</title>
  <link rel="stylesheet" href="{{{{CSS_PATH}}}}">
</head>
<body class="page-v2">
{{{{APPBAR}}}}
<main class="v2-page">
  <div class="status-wrap">
    <div class="status-tile">
      <div class="status-tile__code">{code}</div>
      <h1 class="status-tile__heading">{reason}</h1>
      <p class="status-tile__detail">{msg}</p>
      <div class="tags">
        <a class="btn btn-primary" href="/">{back}Back to the console</a>
        <a class="btn btn-secondary" href="https://w33d.xyz">All apps</a>
      </div>
    </div>
  </div>
  {{{{FOOTER}}}}
</main>
</body>
</html>"#,
        code = code,
        reason = esc(reason),
        msg = esc(message),
        back = ICON_ARROW_LEFT,
    );
    shell(&template, &HeaderMap::new(), "/", "—", 0)
}
