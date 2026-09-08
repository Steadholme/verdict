//! Shared server-render fragments for the v2 console surface.
//!
//! The visual vocabulary comes from the Figma file `iS3iDUEUHMzGvXmOipjAbO`: a relation tuple is
//! always rendered as three typed chips (blue object · wine relation · slate subject, dashed
//! violet when the subject is a userset), so the same shape reads the same way in the table, the
//! resolution path, the access tree and every result panel.

use crate::check;
use crate::handlers::esc;

/// One typed tuple chip. `part` is `object`, `relation`, `subject` or `userset`.
pub fn chip(part: &str, label: &str, small: bool) -> String {
    format!(
        r#"<span class="tc tc--{part}{sm}">{label}</span>"#,
        part = part,
        sm = if small { " tc--sm" } else { "" },
        label = esc(label),
    )
}

/// A subject chip that picks the userset variant when the subject carries `#`.
pub fn subject_chip(subject: &str, small: bool) -> String {
    if check::is_userset(subject) {
        chip("userset", subject, small)
    } else {
        chip("subject", subject, small)
    }
}

/// The full `object # relation @ subject` line as chips with mono separators.
pub fn tuple_line(object: &str, relation: &str, subject: &str, small: bool) -> String {
    format!(
        r#"{o}<span class="tsep">#</span>{r}<span class="tsep">@</span>{s}"#,
        o = chip("object", object, small),
        r = chip("relation", relation, small),
        s = subject_chip(subject, small),
    )
}

/// A row of subject chips, or an empty note when the list is empty.
pub fn chip_row(items: &[String], empty: &str) -> String {
    if items.is_empty() {
        return format!(r#"<p class="note">{}</p>"#, esc(empty));
    }
    let mut out = String::from(r#"<div class="chips">"#);
    for item in items {
        out.push_str(&subject_chip(item, true));
    }
    out.push_str("</div>");
    out
}

/// The access tree: nested lists of subject chips with a member count on every userset.
pub fn access_tree(nodes: &[check::ExpansionNode]) -> String {
    if nodes.is_empty() {
        return r#"<p class="note">no grants</p>"#.to_string();
    }
    let mut out = String::from(r#"<ul class="tree">"#);
    for node in nodes {
        tree_node(node, &mut out);
    }
    out.push_str("</ul>");
    out
}

fn tree_node(node: &check::ExpansionNode, out: &mut String) {
    out.push_str(r#"<li><span class="tree__row">"#);
    out.push_str(&subject_chip(&node.subject, true));
    if !node.children.is_empty() {
        out.push_str(&format!(
            r#"<span class="tree__count">{}</span>"#,
            plural(node.children.len(), "member", "members"),
        ));
    }
    out.push_str("</span>");
    if !node.children.is_empty() {
        out.push_str(r#"<ul class="tree">"#);
        for child in &node.children {
            tree_node(child, out);
        }
        out.push_str("</ul>");
    }
    out.push_str("</li>");
}

/// Count every node in an expansion tree (the card's node count).
pub fn tree_size(nodes: &[check::ExpansionNode]) -> usize {
    nodes.iter().map(|node| 1 + tree_size(&node.children)).sum()
}

/// The deepest level reached in an expansion tree (1 = direct grants only).
pub fn tree_depth(nodes: &[check::ExpansionNode]) -> usize {
    nodes
        .iter()
        .map(|node| 1 + tree_depth(&node.children))
        .max()
        .unwrap_or(0)
}

/// A definitions card body from `(term, value)` pairs. `mono` marks values rendered in the mono
/// face (identifiers, hashes, tokens).
pub fn defs(rows: &[(&str, String, bool)]) -> String {
    let mut out = String::from(r#"<div class="defs">"#);
    for (term, value, mono) in rows {
        out.push_str(&format!(
            r#"<div class="defs__row"><span class="defs__term">{term}</span><span class="defs__value{mono}">{value}</span></div>"#,
            term = esc(term),
            mono = if *mono { " mono" } else { "" },
            value = value,
        ));
    }
    out.push_str("</div>");
    out
}

/// A dark code block with a title bar. `body` is already escaped and may carry `<span class="k">`
/// highlight markers.
pub fn code_block(title: &str, body: String) -> String {
    format!(
        r#"<div class="code"><div class="code__head"><span class="code__title">{title}</span></div><pre class="code__body">{body}</pre></div>"#,
        title = esc(title),
        body = body,
    )
}

/// Colour a JSON document: keys, strings and numbers get their own class.
pub fn highlight_json(json: &str) -> String {
    let mut out = String::new();
    let mut chars = json.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            out.push_str(&esc(&c.to_string()));
            continue;
        }
        let mut literal = String::from("\"");
        for c in chars.by_ref() {
            literal.push(c);
            if c == '"' {
                break;
            }
        }
        let key = matches!(chars.peek(), Some(':'));
        out.push_str(&format!(
            r#"<span class="{class}">{text}</span>"#,
            class = if key { "k" } else { "s" },
            text = esc(&literal),
        ));
    }
    out
}

/// `1 284` — thousands separated by a thin space so long counts stay readable in the mono face.
pub fn fmt_count(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// `1 tuple` / `2 tuples`.
pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}
