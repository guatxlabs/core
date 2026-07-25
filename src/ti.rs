//! Threat-Intelligence core — PURE, injection-safe translation of STIX 2.1 `indicator`
//! objects into Plume IOC rows, plus IOC value normalization. Mirrors the discipline of the Sigma
//! importer (daemon side): a construct that cannot be translated FAITHFULLY is SKIPPED WITH A
//! REASON (never emitted as an IOC that would over- or under-match silently).
//!
//! DESIGN — vendor-agnostic & shared. This module is `serde_json`-only (zero rusqlite, zero I/O), so
//! both Plume (blue SOC) and the Forge console can consume the same STIX front-end. The daemon owns the
//! IOC STORE (SQLCipher `ioc` table) and the match-on-ingest cache; this crate owns only the *pure*
//! parse + normalize. Nothing here touches SQL: values become `Ioc` structs that the daemon binds via
//! parametrized statements -> INJECTION IMPOSSIBLE by construction (no string is ever interpolated).
//!
//! SUPPORTED STIX patterns (the common, unambiguous subset):
//!   `[ipv4-addr:value = '1.2.3.4']`            -> ip
//!   `[ipv6-addr:value = '2001:db8::1']`        -> ip
//!   `[domain-name:value = 'evil.example']`     -> domain
//!   `[url:value = 'http://evil.example/x']`    -> url
//!   `[email-addr:value = 'a@evil.example']`    -> email
//!   `[file:hashes.'SHA-256' = '<64hex>']`      -> hash_sha256 (MD5/SHA-1/SHA-256)
//!   OR-combinations of the above inside one observation (`[a = 'x' OR b = 'y']`) -> several IOCs.
//! UNSUPPORTED (skip-with-reason, never a silent miss): AND-combined comparisons (would require BOTH to
//! match -> reducing to one field over-matches), multi-observation operators (FOLLOWEDBY / WITHIN /
//! REPEATS), non-equality operators (`!=`, `<`, `>`, LIKE, MATCHES, IN, ISSUBSET/ISSUPERSET),
//! unsupported object paths / hash algorithms, and non-`stix` pattern types.

use serde_json::Value;

/// Canonical IOC type vocabulary (mirrors the daemon `ioc.type` CHECK-free contract).
pub const IOC_TYPES: &[&str] = &[
    "ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email",
];

/// A parsed indicator ready to become an `ioc` row. `value` is ALREADY normalized. No SQL, no I/O.
#[derive(Debug, Clone, PartialEq)]
pub struct Ioc {
    pub kind: String,
    pub value: String,
    pub stix_id: Option<String>,
    pub confidence: Option<i64>,
    /// STIX `valid_until` (ISO8601) -> the daemon maps it to `ioc.expires`.
    pub valid_until: Option<String>,
    pub labels: Vec<String>,
}

/// A STIX object that was NOT turned into IOC(s), with a human-readable reason (never a silent drop).
#[derive(Debug, Clone, PartialEq)]
pub struct StixSkip {
    pub id: String,
    pub reason: String,
}

/// Outcome of importing a bundle: the IOCs that translated + the objects skipped with reasons.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StixImport {
    pub iocs: Vec<Ioc>,
    pub skipped: Vec<StixSkip>,
}

/// Normalize a raw IOC value for a given `kind`. Returns `None` if empty/invalid for that kind.
/// Normalization is what makes match-on-ingest reliable: BOTH the stored IOC and the incoming event
/// value pass through the same canonical form (lowercase domains/urls/hashes/emails, trimmed IPs).
pub fn normalize_ioc(kind: &str, raw: &str) -> Option<String> {
    let v = raw.trim();
    if v.is_empty() {
        return None;
    }
    match kind {
        "ip" => {
            // Light canonical form: trim + lowercase (IPv6 hex). We validate the charset only (no full
            // RFC parse) — a value with only hex digits, '.', ':' and at least one '.'/':'. Strips a
            // trailing zone/prefix would over-reach; keep conservative.
            let s = v.to_ascii_lowercase();
            let ok = s.len() >= 2
                && s.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
                && s.chars().any(|c| c == '.' || c == ':');
            ok.then_some(s)
        }
        "domain" => {
            let mut s = v.to_ascii_lowercase();
            while s.ends_with('.') {
                s.pop();
            }
            // strip a leading wildcard label ("*.evil.example" -> "evil.example") so a host event matches.
            if let Some(rest) = s.strip_prefix("*.") {
                s = rest.to_string();
            }
            let ok = s.len() >= 3
                && s.contains('.')
                && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
            ok.then_some(s)
        }
        "url" => {
            // URLs are compared case-insensitively end-to-end (both sides lowercased identically). This
            // loses path case-sensitivity but keeps IOC<->event matching symmetric and predictable.
            Some(v.to_ascii_lowercase())
        }
        "email" => {
            let s = v.to_ascii_lowercase();
            (s.contains('@') && s.len() >= 3).then_some(s)
        }
        "hash_md5" => norm_hex(v, 32),
        "hash_sha1" => norm_hex(v, 40),
        "hash_sha256" => norm_hex(v, 64),
        _ => None,
    }
}

/// Lowercase + validate an exact-length hex string (hash). Returns None on any non-hex char / bad length.
fn norm_hex(v: &str, len: usize) -> Option<String> {
    let s = v.trim().to_ascii_lowercase();
    (s.len() == len && s.chars().all(|c| c.is_ascii_hexdigit())).then_some(s)
}

/// Map a STIX object-path (comparison LHS, e.g. `ipv4-addr:value`, `file:hashes.'SHA-256'`) to an IOC
/// kind. Returns `Err(reason)` for a path we do not translate (so the caller skips with that reason).
fn stix_path_to_kind(lhs: &str) -> Result<&'static str, String> {
    let lhs = lhs.trim();
    match lhs {
        "ipv4-addr:value" | "ipv6-addr:value" => Ok("ip"),
        "domain-name:value" => Ok("domain"),
        "url:value" => Ok("url"),
        "email-addr:value" => Ok("email"),
        _ => {
            // file:hashes.<ALG> — ALG may be quoted ('SHA-256', "MD5") or bare (MD5). Normalize: strip
            // quotes, uppercase, drop '-' -> MD5 / SHA1 / SHA256.
            if let Some(alg_raw) = lhs.strip_prefix("file:hashes.") {
                let alg: String = alg_raw
                    .trim_matches(|c| c == '\'' || c == '"')
                    .to_ascii_uppercase()
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .collect();
                return match alg.as_str() {
                    "MD5" => Ok("hash_md5"),
                    "SHA1" => Ok("hash_sha1"),
                    "SHA256" => Ok("hash_sha256"),
                    other => Err(format!("unsupported hash algorithm '{other}' (MD5/SHA-1/SHA-256 only)")),
                };
            }
            Err(format!("unsupported STIX object path '{lhs}'"))
        }
    }
}

/// Parse a STIX 2.1 pattern into `(kind, raw_value)` pairs, or `Err(reason)` if it uses a construct we
/// cannot translate faithfully. Only conjunction-free, equality-only, single-observation patterns are
/// accepted (optionally OR-combined). The values returned are NOT yet normalized (caller normalizes).
pub fn parse_stix_pattern(pattern: &str) -> Result<Vec<(&'static str, String)>, String> {
    let p = pattern.trim();
    if p.is_empty() {
        return Err("empty pattern".into());
    }
    // Reject qualifiers / multi-observation operators outright (case-insensitive word check).
    let up = p.to_ascii_uppercase();
    for bad in ["FOLLOWEDBY", "REPEATS", "WITHIN", "LIKE", "MATCHES", "ISSUBSET", "ISSUPERSET", " IN ", " IN(", "!=", "<=", ">=", "<", ">"] {
        if up.contains(bad) {
            return Err(format!("unsupported pattern operator/qualifier ({})", bad.trim()));
        }
    }
    // Single observation only: must be exactly one [...] group. Extract the innermost content.
    let open = p.find('[').ok_or("pattern is not a STIX observation ([...])")?;
    let close = p.rfind(']').ok_or("pattern is not a STIX observation ([...])")?;
    if close <= open {
        return Err("malformed observation brackets".into());
    }
    // A second observation group -> multi-observation, unsupported.
    if p[open + 1..close].contains('[') {
        return Err("multi-observation pattern (unsupported)".into());
    }
    let inner = p[open + 1..close].trim();
    // AND-combined comparisons cannot be reduced to independent IOCs without over-matching -> reject.
    if split_top(inner, " AND ").len() > 1 {
        return Err("AND-combined comparisons (unsupported — would over-match)".into());
    }
    let mut out: Vec<(&'static str, String)> = Vec::new();
    for term in split_top(inner, " OR ") {
        let term = term.trim().trim_matches(|c| c == '(' || c == ')').trim();
        if term.is_empty() {
            continue;
        }
        // Split on the FIRST '=' (equality only; '!='/'<='/'>=' already rejected above).
        let eq = term.find('=').ok_or_else(|| format!("comparison without '=' : '{term}'"))?;
        let lhs = term[..eq].trim();
        let rhs_raw = term[eq + 1..].trim();
        let kind = stix_path_to_kind(lhs)?;
        let value = unquote_stix(rhs_raw)?;
        out.push((kind, value));
    }
    if out.is_empty() {
        return Err("no comparison found in observation".into());
    }
    Ok(out)
}

/// Split `s` on a case-insensitive separator, but ONLY at bracket/paren depth 0 and outside single
/// quotes. Keeps `'a OR b'` string literals and `(...)` groups intact. Separator must be surrounded by
/// the given form (already includes spaces, e.g. " OR ").
fn split_top(s: &str, sep: &str) -> Vec<String> {
    let up = s.to_ascii_uppercase();
    let sep_up = sep.to_ascii_uppercase();
    let sb = sep_up.as_bytes();
    let bytes = up.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    let mut in_q = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '\'' => in_q = !in_q,
            '(' | '[' if !in_q => depth += 1,
            ')' | ']' if !in_q => depth -= 1,
            _ => {}
        }
        if !in_q && depth == 0 && i + sb.len() <= bytes.len() && &bytes[i..i + sb.len()] == sb {
            parts.push(s[start..i].to_string());
            i += sb.len();
            start = i;
            continue;
        }
        i += 1;
    }
    parts.push(s[start..].to_string());
    parts
}

/// Strip the surrounding single quotes of a STIX string literal and decode `\'` and `\\`. Errors if the
/// literal is not single-quoted (we only translate quoted string comparisons).
fn unquote_stix(rhs: &str) -> Result<String, String> {
    let r = rhs.trim();
    let inner = r
        .strip_prefix('\'')
        .and_then(|x| x.strip_suffix('\''))
        .ok_or_else(|| format!("value is not a quoted string literal: {r}"))?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\'') => out.push('\''),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// Translate a STIX 2.1 bundle (or a single indicator object, or an array of objects) into IOC rows.
/// PURE: no SQL, no I/O. Non-indicator objects are ignored (not "skipped" — they simply are not
/// indicators). Every indicator that cannot translate is recorded in `skipped` with a reason.
pub fn stix_bundle_to_iocs(bundle: &Value) -> StixImport {
    let mut import = StixImport::default();
    let objects: Vec<&Value> = match bundle {
        Value::Object(_) => {
            if bundle.get("type").and_then(|t| t.as_str()) == Some("bundle") {
                bundle
                    .get("objects")
                    .and_then(|o| o.as_array())
                    .map(|a| a.iter().collect())
                    .unwrap_or_default()
            } else {
                vec![bundle]
            }
        }
        Value::Array(a) => a.iter().collect(),
        _ => Vec::new(),
    };
    for obj in objects {
        if obj.get("type").and_then(|t| t.as_str()) != Some("indicator") {
            continue; // not an indicator SDO — silently ignore (relationships, malware, etc.)
        }
        let id = obj.get("id").and_then(|x| x.as_str()).unwrap_or("indicator--?").to_string();
        // pattern_type defaults to "stix" when absent (STIX 2.1). Anything else -> skip with reason.
        let ptype = obj.get("pattern_type").and_then(|x| x.as_str()).unwrap_or("stix");
        if ptype != "stix" {
            import.skipped.push(StixSkip { id, reason: format!("pattern_type='{ptype}' (only 'stix' supported)") });
            continue;
        }
        let pattern = match obj.get("pattern").and_then(|x| x.as_str()) {
            Some(p) => p,
            None => {
                import.skipped.push(StixSkip { id, reason: "indicator has no 'pattern'".into() });
                continue;
            }
        };
        let pairs = match parse_stix_pattern(pattern) {
            Ok(p) => p,
            Err(e) => {
                import.skipped.push(StixSkip { id, reason: e });
                continue;
            }
        };
        let confidence = obj.get("confidence").and_then(|x| x.as_i64());
        let valid_until = obj.get("valid_until").and_then(|x| x.as_str()).map(|s| s.to_string());
        let labels: Vec<String> = obj
            .get("labels")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|l| l.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        let mut produced = 0usize;
        for (kind, raw) in pairs {
            match normalize_ioc(kind, &raw) {
                Some(value) => {
                    import.iocs.push(Ioc {
                        kind: kind.to_string(),
                        value,
                        stix_id: Some(id.clone()),
                        confidence,
                        valid_until: valid_until.clone(),
                        labels: labels.clone(),
                    });
                    produced += 1;
                }
                None => import.skipped.push(StixSkip {
                    id: id.clone(),
                    reason: format!("value for {kind} failed normalization: '{raw}'"),
                }),
            }
        }
        if produced == 0 && import.skipped.iter().all(|s| s.id != id) {
            import.skipped.push(StixSkip { id, reason: "no usable comparison produced an IOC".into() });
        }
    }
    import
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_each_type() {
        assert_eq!(normalize_ioc("ip", " 1.2.3.4 ").as_deref(), Some("1.2.3.4"));
        assert_eq!(normalize_ioc("ip", "2001:DB8::1").as_deref(), Some("2001:db8::1"));
        assert_eq!(normalize_ioc("ip", "not-an-ip"), None);
        assert_eq!(normalize_ioc("domain", "EVIL.Example.").as_deref(), Some("evil.example"));
        assert_eq!(normalize_ioc("domain", "*.bad.example").as_deref(), Some("bad.example"));
        assert_eq!(normalize_ioc("domain", "nodot"), None);
        assert_eq!(normalize_ioc("url", "HTTP://Bad.Example/Path").as_deref(), Some("http://bad.example/path"));
        assert_eq!(normalize_ioc("email", "AB@Bad.Example").as_deref(), Some("ab@bad.example"));
        assert_eq!(normalize_ioc("hash_md5", &"A".repeat(32)).as_deref(), Some("a".repeat(32).as_str()));
        assert_eq!(normalize_ioc("hash_sha1", &"b".repeat(40)).unwrap().len(), 40);
        assert_eq!(normalize_ioc("hash_sha256", &"c".repeat(64)).unwrap().len(), 64);
        assert_eq!(normalize_ioc("hash_md5", "xyz"), None); // bad length/charset
        assert_eq!(normalize_ioc("bogus", "x"), None);
    }

    #[test]
    fn parse_each_supported_pattern() {
        assert_eq!(parse_stix_pattern("[ipv4-addr:value = '1.2.3.4']").unwrap(), vec![("ip", "1.2.3.4".into())]);
        assert_eq!(parse_stix_pattern("[domain-name:value='evil.example']").unwrap(), vec![("domain", "evil.example".into())]);
        assert_eq!(parse_stix_pattern("[url:value = 'http://x/y']").unwrap(), vec![("url", "http://x/y".into())]);
        assert_eq!(parse_stix_pattern("[email-addr:value = 'a@b.com']").unwrap(), vec![("email", "a@b.com".into())]);
        assert_eq!(parse_stix_pattern("[file:hashes.'SHA-256' = 'DEAD']").unwrap(), vec![("hash_sha256", "DEAD".into())]);
        assert_eq!(parse_stix_pattern("[file:hashes.MD5 = 'beef']").unwrap(), vec![("hash_md5", "beef".into())]);
    }

    #[test]
    fn parse_or_combination_yields_multiple() {
        let got = parse_stix_pattern("[file:hashes.MD5 = 'aa' OR file:hashes.'SHA-256' = 'bb']").unwrap();
        assert_eq!(got, vec![("hash_md5", "aa".into()), ("hash_sha256", "bb".into())]);
    }

    #[test]
    fn parse_unsupported_skips_with_reason() {
        assert!(parse_stix_pattern("[network-traffic:dst_port = '445']").is_err()); // unsupported path
        assert!(parse_stix_pattern("[file:name LIKE '%.exe']").is_err()); // LIKE
        assert!(parse_stix_pattern("[file:hashes.SSDEEP = 'x']").is_err()); // unsupported algo
        assert!(parse_stix_pattern("[a:value = 'x'] FOLLOWEDBY [b:value = 'y']").is_err()); // multi-obs
        assert!(parse_stix_pattern("[domain-name:value = 'a.com' AND url:value = 'http://a']").is_err()); // AND
        assert!(parse_stix_pattern("[ipv4-addr:value != '1.2.3.4']").is_err()); // non-equality
    }

    #[test]
    fn bundle_import_mix_supported_and_skipped() {
        let bundle = json!({
            "type": "bundle", "id": "bundle--1",
            "objects": [
                {"type":"indicator","id":"indicator--a","pattern":"[ipv4-addr:value = '9.9.9.9']","pattern_type":"stix","confidence":80,"valid_until":"2027-01-01T00:00:00Z","labels":["malicious-activity"]},
                {"type":"indicator","id":"indicator--b","pattern":"[file:name LIKE '%.exe']","pattern_type":"stix"},
                {"type":"indicator","id":"indicator--c","pattern":"[domain-name:value = 'EVIL.Example']"},
                {"type":"indicator","id":"indicator--d","pattern_type":"pcre","pattern":"/x/"},
                {"type":"malware","id":"malware--x","name":"z"}
            ]
        });
        let imp = stix_bundle_to_iocs(&bundle);
        assert_eq!(imp.iocs.len(), 2);
        let ip = imp.iocs.iter().find(|i| i.kind == "ip").unwrap();
        assert_eq!(ip.value, "9.9.9.9");
        assert_eq!(ip.confidence, Some(80));
        assert_eq!(ip.valid_until.as_deref(), Some("2027-01-01T00:00:00Z"));
        assert_eq!(ip.stix_id.as_deref(), Some("indicator--a"));
        // domain normalized to lowercase
        assert!(imp.iocs.iter().any(|i| i.kind == "domain" && i.value == "evil.example"));
        // b (LIKE) and d (pcre) skipped-with-reason; malware ignored (not skipped)
        assert_eq!(imp.skipped.len(), 2);
        assert!(imp.skipped.iter().any(|s| s.id == "indicator--b"));
        assert!(imp.skipped.iter().any(|s| s.id == "indicator--d"));
    }

    #[test]
    fn injection_safe_values_are_inert_data() {
        // A quoted value with an embedded escaped quote decodes to a plain literal — still just DATA
        // (the daemon binds it as a parameter; it is never interpolated into SQL/SOQL).
        let got = parse_stix_pattern(r#"[url:value = 'http://x/?q=1\'2']"#).unwrap();
        assert_eq!(got[0].1, "http://x/?q=1'2");
        // A domain value carrying a SQL metacharacter fails NORMALIZATION (charset guard) -> skipped,
        // never emitted; proof the pure layer cannot smuggle a hostile identifier into a row.
        let bundle = json!({"type":"indicator","id":"indicator--x",
            "pattern":"[domain-name:value = 'a.com; DROP TABLE ioc']","pattern_type":"stix"});
        let imp = stix_bundle_to_iocs(&bundle);
        assert!(imp.iocs.is_empty());
        assert_eq!(imp.skipped.len(), 1);
    }
}
