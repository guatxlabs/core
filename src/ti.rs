//! Threat-Intelligence core — PURE, injection-safe translation of STIX 2.1 `indicator`
//! objects into Plume IOC rows, plus IOC value normalization. Mirrors the discipline of the Sigma
//! importer (daemon side): a construct that cannot be translated FAITHFULLY is SKIPPED WITH A
//! REASON, so that it is not emitted as an IOC that would over- or under-match silently.
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
//!
//! ONE OBSERVATION, AND NOTHING AROUND IT. Refusing an observation qualifier is NOT done by listing
//! qualifier names. `parse_stix_pattern` locates the single `[...]` group on the structural view and
//! then requires the rest of the pattern to be EMPTY; whatever is left — before or after — is refused
//! and quoted verbatim in the reason. That check is written ONCE (`translate_observation`, the
//! `before`/`after` test); the operator list is read once more, by `name_known_operator`, but only to
//! rewrite the TEXT of an `Err` — it is handed no `Ok` and cannot produce one, so nothing but that one
//! test turns what surrounds the observation into a verdict. A qualifier this module has never heard
//! of therefore falls on the refuse side by default rather than by enumeration. WHAT THAT CHANGED,
//! MEASURED (probe compiled against `git archive` exports of 48035b9 and 742efe7, input verbatim):
//!   `[url:value='x'] START t'2020-01-01T00:00:00Z' STOP t'2021-01-01T00:00:00Z'`
//!                                    48035b9 OK [(url,x)]   742efe7 OK [(url,x)]   now ERR
//!   `[url:value='x'] WITHIN60 SECONDS`   48035b9 ERR         742efe7 OK [(url,x)]   now ERR
//!   `[url:value='x'] REPEATS3 TIMES`     48035b9 ERR         742efe7 OK [(url,x)]   now ERR
//!   `[url:value='x'] ISSUBSET42`         48035b9 ERR         742efe7 OK [(url,x)]   now ERR
//!   `[url:value='x'] ; DROP TABLE ioc`   48035b9 OK          742efe7 OK             now ERR
//!   `GARBAGE [url:value='x']`            48035b9 OK          742efe7 OK             now ERR
//! The `START ... STOP ...` line is the KNOWN GAP the previous revision documented and left open; it
//! is now closed BY REFUSAL, not by honouring the window: `Ioc` has no field for an observation
//! window (only `valid_until`, which comes from the SDO, not from the pattern), so an indicator that
//! declares one is skipped with a reason. That is a deliberate trade — an indicator a TI feed would
//! previously have imported window-less is now not imported at all — and it is the module's stated
//! discipline: over-matching outside a declared window is exactly the "silent over-match" the header
//! forbids. `qualifier_tails_are_never_dropped_in_silence` re-measures the class in CI.

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
                // The key is read AS WRITTEN: at most ONE surrounding quote pair is removed, and every
                // remaining character must be one a hash-algorithm key can contain. The previous
                // reading DELETED every non-alphanumeric character before matching, so a key nobody
                // wrote was coerced into a supported one — MEASURED identical on 48035b9 and 742efe7:
                //   `[file:hashes.MD5#$%^ = '<32 hex>']` -> OK [(hash_md5, …)]
                //   `[file:hashes.MD 5    = '<32 hex>']` -> OK [(hash_md5, …)]
                // Both are refused now. This is also what lets the operator list stop being a gate:
                // with the lenient reading restored and the reason layer removed, the sole decision
                // site ACCEPTS `[file:hashes.MD5<= 'dead']`, `[file:hashes.MD5 >= 'dead']` and
                // `[file:hashes.MD5! = 'dead']` as MD5 equalities (measured on a mutated copy) — the
                // deleted `<`/`>`/`!` is what the operator list used to be catching for it. Frozen by
                // `stix_corpus_verdicts_are_frozen`, section E.
                let key = strip_one_quote_pair(alg_raw);
                if key.is_empty()
                    || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    return Err(format!(
                        "unsupported hash algorithm '{key}' (MD5/SHA-1/SHA-256 only)"
                    ));
                }
                // `-`/`_` are separators inside the registered spellings (`SHA-256`) -> dropped; case
                // is folded. Nothing else is removed.
                let alg: String = key
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
    // ONE DECISION SITE. `translate_observation` is the only function here that decides whether a
    // pattern translates; `name_known_operator` is handed an `Err` and can only REPLACE ITS TEXT, so
    // no entry of the operator list can accept a refused pattern or refuse an accepted one. That is
    // not a claim about the list's contents — it is the shape of this `match`, and
    // `operator_list_is_a_reason_layer_not_a_gate` re-measures it over the whole corpus in CI.
    // It matters because the list USED to be the gate: it ran first and returned early, which is how
    // `[url:value='x'] WITHIN60 SECONDS` (a MALFORMED qualifier: no name boundary before its
    // argument) went from refused on 48035b9 — by an accidental substring match — to accepted on
    // 742efe7, IOC emitted with its observation window dropped in silence.
    match translate_observation(p) {
        Ok(v) => Ok(v),
        Err(e) => Err(name_known_operator(p, e)),
    }
}

/// The ONLY accept/reject decision of this module. Everything it needs about the pattern's shape is
/// read from ONE structural view (`pattern_structure`), never from the raw text.
fn translate_observation(p: &str) -> Result<Vec<(&'static str, String)>, String> {
    if p.is_empty() {
        return Err("empty pattern".into());
    }
    // ONE structural view feeds EVERY structural check below — observation brackets, AND/OR split,
    // equality split, string-literal check. `pattern_structure` blanks the CONTENT of each
    // single-quoted STIX string literal (keeping its quotes) with the same `\'` / `\\` escaping as
    // `unquote_stix`, and is BYTE-ALIGNED with `p`, so every offset it yields slices `p` correctly.
    // Reading a VALUE as if it were structure is what threw valid IOCs away:
    // `[url:value='http://[2001:db8::1]:8080/a']` was refused as a multi-observation pattern because
    // `find('[')`/`rfind(']')`/`contains('[')` still ran on the RAW pattern — exactly the silent
    // detection blind spot this module's header promises to avoid. Deriving the split points from
    // the same view also keeps them from disagreeing with `unquote_stix` about where a literal ends.
    let (structure, unterminated) = pattern_structure(p);
    if unterminated {
        return Err("unterminated string literal in pattern".into());
    }
    // A STIX observation expression may be wrapped in balanced parentheses (`([url:value='x'])`,
    // accepted on 48035b9 and 742efe7 — measured). Peel those wrappers on BOTH views in lockstep;
    // a paren whose partner is not the last character is not a wrapper and is left where it is.
    let (text, view) = strip_balanced_parens(p, &structure);
    let open = view
        .find('[')
        .ok_or("pattern is not a STIX observation ([...])")?;
    let close = matching_bracket(view, open).ok_or("malformed observation brackets")?;
    // *** THE decision on what may surround the observation, and the only one. *** It admits exactly
    // one thing: nothing. An operator, an observation qualifier (well-formed or not, listed below or
    // not), a second observation, or plain text all land here — the module does not need to know
    // their names, only that they are not the observation. The offending text is quoted back so it
    // can never be discarded "without a word".
    let before = text[..open].trim();
    let after = text[close + 1..].trim();
    if !before.is_empty() || !after.is_empty() {
        return Err(outside_the_observation(before, after));
    }
    // A second bracket group NESTED in this one -> multi-observation, unsupported.
    if view[open + 1..close].contains('[') {
        return Err("multi-observation pattern (unsupported)".into());
    }
    let (inner, inner_st) = trim_pair(&text[open + 1..close], &view[open + 1..close], false);
    // AND-combined comparisons cannot be reduced to independent IOCs without over-matching -> reject.
    if split_top(inner, inner_st, " AND ").len() > 1 {
        return Err("AND-combined comparisons (unsupported — would over-match)".into());
    }
    let mut out: Vec<(&'static str, String)> = Vec::new();
    for (raw_term, raw_term_st) in split_top(inner, inner_st, " OR ") {
        let (term, term_st) = trim_pair(&raw_term, &raw_term_st, true);
        if term.is_empty() {
            continue;
        }
        // Split on the FIRST '=' OF THE STRUCTURE (equality only), so a '=' inside a value or a
        // quoted path key cannot move the boundary. A comparison written with `!=`/`<=`/`>=` leaves
        // its `!`/`<`/`>` glued to the left-hand side, where `stix_path_to_kind` refuses it.
        let eq = term_st.find('=').ok_or_else(|| format!("comparison without '=' : '{term}'"))?;
        let lhs = term[..eq].trim();
        let (rhs, rhs_st) = trim_pair(&term[eq + 1..], &term_st[eq + 1..], false);
        let kind = stix_path_to_kind(lhs)?;
        let value = unquote_stix(rhs, rhs_st)?;
        out.push((kind, value));
    }
    if out.is_empty() {
        return Err("no comparison found in observation".into());
    }
    Ok(out)
}

/// Named/symbolic operators this module does not translate. PURELY a reason layer: see
/// `name_known_operator`, which is only ever applied to an `Err`.
///
/// MEASURED on a copy with this layer removed — the decision site alone already refuses all 13, each
/// with a reason of its own, so no entry of these two lists is holding anything up:
///   `!=` / `>=`     -> "unsupported STIX object path 'ipv4-addr:value !'" (the `!`/`>` stays glued
///                      to the left-hand side, where the path allowlist rejects it)
///   `<` LIKE IN MATCHES ISSUBSET ISSUPERSET -> "comparison without '='"
///   WITHIN / REPEATS / FOLLOWEDBY           -> "text outside the observation is not translated: …"
const NAMED_OPERATORS: [&str; 8] = [
    "FOLLOWEDBY",
    "REPEATS",
    "WITHIN",
    "LIKE",
    "MATCHES",
    "ISSUBSET",
    "ISSUPERSET",
    "IN",
];
const SYMBOLIC_OPERATORS: [&str; 5] = ["!=", "<=", ">=", "<", ">"];

/// Replace the text of an already-decided `Err` with the name of the operator that most likely
/// explains it. CANNOT change a verdict: it never sees the `Ok` branch (`parse_stix_pattern`).
///
/// A NAMED operator is matched as a TOKEN of the structure, not as a substring: a STIX 2.1 type name
/// may legally contain one (`x-within-obj`, `x-in-house`, `file:hashes.WITHIN256`), and naming an
/// operator its author never wrote sends the analyst hunting for the wrong thing. What separates a
/// real named operator from a name — whitespace, bracket, paren, quote — is never a name character.
/// Symbolic operators are punctuation: no identifier contains one, so no token rule is needed.
fn name_known_operator(p: &str, reason: String) -> String {
    let up = pattern_structure(p).0.to_ascii_uppercase();
    for bad in NAMED_OPERATORS {
        if contains_token(&up, bad) {
            return format!("unsupported pattern operator/qualifier ({bad})");
        }
    }
    for bad in SYMBOLIC_OPERATORS {
        if up.contains(bad) {
            return format!("unsupported pattern operator/qualifier ({bad})");
        }
    }
    reason
}

/// Reason for text found outside the single observation. Quotes the offending text VERBATIM (clipped
/// to `CLIP_CHARS` CHARACTERS — not bytes — so a multi-byte value cannot split a char boundary or
/// make the message unbounded; see `outside_reason_quotes_the_text_and_is_clipped`).
fn outside_the_observation(before: &str, after: &str) -> String {
    let what = match (before.is_empty(), after.is_empty()) {
        (false, false) => format!(
            "'{}' before it and '{}' after it",
            clip(before),
            clip(after)
        ),
        (false, true) => format!("'{}' before it", clip(before)),
        _ => format!("'{}' after it", clip(after)),
    };
    format!(
        "text outside the observation is not translated: {what} \
         (a pattern must be exactly ONE [...] observation, optionally in balanced parentheses)"
    )
}

const CLIP_CHARS: usize = 60;

fn clip(s: &str) -> String {
    if s.chars().count() <= CLIP_CHARS {
        return s.to_string();
    }
    let head: String = s.chars().take(CLIP_CHARS).collect();
    format!("{head}…")
}

/// Byte offset of the `]` that closes the `[` at `open`, scanning the structural view (where brackets
/// inside a string literal are already blanked). `None` if the group is never closed.
fn matching_bracket(view: &str, open: usize) -> Option<usize> {
    let b = view.as_bytes();
    let mut depth = 0i32;
    for (i, c) in b.iter().enumerate().skip(open) {
        match c {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Peel `(` … `)` wrappers off `(text, view)` in LOCKSTEP, only when the leading paren's partner IS
/// the trailing one — so `([a]) OR ([b])` keeps its parens (and is then refused as text outside the
/// observation) while `(( [a] ))` unwraps.
fn strip_balanced_parens<'a>(text: &'a str, view: &'a str) -> (&'a str, &'a str) {
    debug_assert_eq!(text.len(), view.len());
    let (mut lo, mut hi) = (0usize, view.len());
    loop {
        trim_ws_range(view, &mut lo, &mut hi);
        let inner = &view[lo..hi];
        if !(inner.starts_with('(') && inner.ends_with(')')) {
            break;
        }
        match matching_paren(inner) {
            Some(m) if m == inner.len() - 1 => {
                lo += 1;
                hi -= 1;
            }
            _ => break,
        }
    }
    (&text[lo..hi], &view[lo..hi])
}

/// Byte offset of the `)` that closes the `(` at index 0 of `view`, or `None`.
fn matching_paren(view: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in view.as_bytes().iter().enumerate() {
        match c {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Advance `lo` / retreat `hi` past UNICODE whitespace of `view`. Unicode, not ASCII: `lhs.trim()`
/// downstream is Unicode, and a view that trimmed less than its text made the two disagree.
fn trim_ws_range(view: &str, lo: &mut usize, hi: &mut usize) {
    while *lo < *hi {
        let c = view[*lo..*hi].chars().next().unwrap_or('x');
        if c.is_whitespace() {
            *lo += c.len_utf8();
        } else {
            break;
        }
    }
    while *lo < *hi {
        let c = view[*lo..*hi].chars().next_back().unwrap_or('x');
        if c.is_whitespace() {
            *hi -= c.len_utf8();
        } else {
            break;
        }
    }
}

/// Remove at most ONE matching surrounding quote pair (`'…'` or `"…"`). Unlike a `trim_matches`, it
/// never eats a quote that has no partner, and never eats two layers.
fn strip_one_quote_pair(s: &str) -> &str {
    for q in ['\'', '"'] {
        if s.len() >= 2 && s.starts_with(q) && s.ends_with(q) {
            return &s[q.len_utf8()..s.len() - q.len_utf8()];
        }
    }
    s
}

/// Characters that can be part of a STIX object path or type name (`x-my-type:value`,
/// `file:hashes.MD5`). Used to tell a named operator apart from a name that merely CONTAINS one.
fn is_stix_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':')
}

/// True if `needle` occurs in `hay` as a whole TOKEN — not glued to a longer STIX name on either
/// side. Both must already be uppercase; `needle` must be non-empty ASCII.
fn contains_token(hay: &str, needle: &str) -> bool {
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(needle) {
        let at = from + rel;
        let left_free = hay[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !is_stix_name_char(c));
        let right_free = hay[at + needle.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_stix_name_char(c));
        if left_free && right_free {
            return true;
        }
        from = at + 1;
    }
    false
}

/// Return a same-shape view of `s` in which the CONTENT of every single-quoted STIX string literal is
/// replaced by spaces (the quotes themselves are kept), plus a flag telling whether a literal was left
/// OPEN at the end of `s`. Used to scan the pattern's STRUCTURE — object paths, operators, qualifiers,
/// brackets, separators — without ever looking inside a VALUE. `\'` and `\\` inside a literal do not
/// close it (same escaping as `unquote_stix`).
///
/// BYTE-ALIGNED: a blanked character is replaced by as many spaces as it occupies bytes, so
/// `view.len() == s.len()` and any offset found in the view slices `s` at the same place. Offsets are
/// only ever taken at characters copied VERBATIM (brackets, separators, `=`), which are ASCII and thus
/// always land on a character boundary of `s`.
fn pattern_structure(s: &str) -> (String, bool) {
    let mut out = String::with_capacity(s.len());
    let (mut in_q, mut esc) = (false, false);
    let blank = |out: &mut String, c: char| {
        for _ in 0..c.len_utf8() {
            out.push(' ');
        }
    };
    for c in s.chars() {
        if !in_q {
            if c == '\'' {
                in_q = true;
            }
            out.push(c);
        } else if esc {
            esc = false;
            blank(&mut out, c);
        } else {
            match c {
                '\\' => {
                    esc = true;
                    blank(&mut out, c);
                }
                '\'' => {
                    in_q = false;
                    out.push('\'');
                }
                _ => blank(&mut out, c),
            }
        }
    }
    (out, in_q)
}

/// Trim `(text, view)` in LOCKSTEP: the whitespace (and, with `parens`, the surrounding `(`/`)` layer)
/// is located on the byte-aligned structural VIEW, and the SAME byte range is applied to both, so the
/// two can never disagree on where a term starts and ends. A literal's blanked content is spaces, but
/// its quotes are not, so trimming stops at the quote and never reaches inside a value.
fn trim_pair<'a>(text: &'a str, view: &'a str, parens: bool) -> (&'a str, &'a str) {
    debug_assert_eq!(text.len(), view.len());
    let b = view.as_bytes();
    let (mut lo, mut hi) = (0usize, view.len());
    trim_ws_range(view, &mut lo, &mut hi);
    if parens {
        while lo < hi && (b[lo] == b'(' || b[lo] == b')') {
            lo += 1;
        }
        while hi > lo && (b[hi - 1] == b'(' || b[hi - 1] == b')') {
            hi -= 1;
        }
        trim_ws_range(view, &mut lo, &mut hi);
    }
    (&text[lo..hi], &view[lo..hi])
}

/// Split `(s, view)` on a case-insensitive separator, but ONLY at bracket/paren depth 0 and outside
/// string literals. Keeps `'a OR b'` string literals and `(...)` groups intact. Separator must be
/// surrounded by the given form (already includes spaces, e.g. " OR ").
///
/// The scan runs on the byte-aligned structural VIEW, where a literal's content is already blanked
/// with the same `\'` / `\\` escaping as `unquote_stix`; both halves are returned so the caller keeps
/// the pair aligned. Scanning the RAW string instead made this splitter and `unquote_stix` disagree
/// about where a literal ends: `[url:value='a\' OR domain-name:value=\'evil.com']` was cut INSIDE the
/// value and refused with a reason that named a fragment the author never wrote.
fn split_top(s: &str, view: &str, sep: &str) -> Vec<(String, String)> {
    debug_assert_eq!(s.len(), view.len());
    let up = view.to_ascii_uppercase();
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
            parts.push((s[start..i].to_string(), view[start..i].to_string()));
            i += sb.len();
            start = i;
            continue;
        }
        i += 1;
    }
    parts.push((s[start..].to_string(), view[start..].to_string()));
    parts
}

/// Strip the surrounding single quotes of a STIX string literal and decode `\'` and `\\`. Errors if the
/// right-hand side is not EXACTLY ONE single-quoted literal.
///
/// "Exactly one" is decided on the byte-aligned structural `view`, where a literal keeps its quotes
/// and loses its content: a quote left in the middle means the RHS spans more than one literal.
/// `strip_prefix('\'')` + `strip_suffix('\'')` on the RAW text could not tell the two apart and let
/// a glued `AND` be folded INTO the value — MEASURED identical on 48035b9 and 742efe7:
///   `[url:value='http://a'AND url:value='http://b']`
///     -> OK [(url, "http://a'AND url:value='http://b")]   — an IOC value nobody wrote, which then
///        matches nothing (under-match) while the AND it carries is never reported.
/// Refused now, with the reason below.
fn unquote_stix(rhs: &str, view: &str) -> Result<String, String> {
    debug_assert_eq!(rhs.len(), view.len());
    let one_literal = view.len() >= 2
        && view.starts_with('\'')
        && view.ends_with('\'')
        && !view[1..view.len() - 1].contains('\'');
    if !one_literal {
        return Err(format!("value is not a quoted string literal: {rhs}"));
    }
    let inner = &rhs[1..rhs.len() - 1];
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

    // S3 — la denylist d'opérateurs doit porter sur la STRUCTURE du motif, JAMAIS sur le contenu des
    // valeurs : un IOC valide dont la valeur contient « likely-bad », « within », « matches », «
    // repeats » ou « < » est courant sur un flux TI public, et le jeter avec un motif faux
    // (« unsupported operator ») est exactement l'angle mort de détection que l'en-tête du module
    // promet d'éviter (« never a silent miss »).
    #[test]
    fn parse_operator_substring_inside_value_is_not_an_operator() {
        for (pattern, kind, value) in [
            ("[url:value='http://x/likely-bad']", "url", "http://x/likely-bad"),
            ("[domain-name:value='within.example.com']", "domain", "within.example.com"),
            ("[domain-name:value='matches-evil.example']", "domain", "matches-evil.example"),
            ("[url:value='http://x/repeats']", "url", "http://x/repeats"),
            ("[url:value='http://x/?a=1<2']", "url", "http://x/?a=1<2"),
        ] {
            let got = parse_stix_pattern(pattern)
                .unwrap_or_else(|e| panic!("IOC valide rejeté : {pattern} -> {e}"));
            assert_eq!(got, vec![(kind, value.to_string())], "{pattern}");
        }
    }

    // S3-bis — TOUS les contrôles de structure (crochets d'observation, découpe AND/OR, découpe de
    // l'égalité, denylist) doivent lire la MÊME vue structurelle, avec la MÊME règle d'échappement.
    // Un IOC rejeté à tort est un ANGLE MORT DE DÉTECTION, pas un détail cosmétique : ces motifs
    // sont valides et ordinaires sur un flux TI public.
    #[test]
    fn parse_valid_ioc_corpus_is_never_rejected() {
        for (pattern, kind, value) in [
            // les 5 cas déjà mesurés par la revue
            (
                "[url:value='http://x/likely-bad']",
                "url",
                "http://x/likely-bad",
            ),
            (
                "[domain-name:value='within.example.com']",
                "domain",
                "within.example.com",
            ),
            (
                "[domain-name:value='matches-evil.example']",
                "domain",
                "matches-evil.example",
            ),
            ("[url:value='http://x/repeats']", "url", "http://x/repeats"),
            ("[url:value='http://x/?a=1<2']", "url", "http://x/?a=1<2"),
            // URL à littéral IPv6 : les crochets sont DANS la valeur, pas une 2e observation
            (
                "[url:value='http://[2001:db8::1]:8080/a']",
                "url",
                "http://[2001:db8::1]:8080/a",
            ),
            // crochets dans le CHEMIN de l'URL
            ("[url:value='http://x/a[0]']", "url", "http://x/a[0]"),
            // valeur contenant une quote ÉCHAPPÉE suivie de « OR » : la découpe ne doit pas couper
            // à l'intérieur du littéral (les deux vues doivent s'accorder sur sa fin)
            (
                r"[url:value='a\' OR domain-name:value=\'evil.com']",
                "url",
                r"a' OR domain-name:value='evil.com",
            ),
            // nom d'opérateur DANS la valeur, collé à des crochets
            (
                "[url:value='http://x/[within]/[repeats]']",
                "url",
                "http://x/[within]/[repeats]",
            ),
            // valeur NON-ASCII + crochet : la vue structurelle doit préserver les OFFSETS D'OCTETS
            ("[url:value='http://x/café[1]']", "url", "http://x/café[1]"),
        ] {
            let got = parse_stix_pattern(pattern)
                .unwrap_or_else(|e| panic!("IOC valide rejeté : {pattern} -> {e}"));
            assert_eq!(got, vec![(kind, value.to_string())], "{pattern}");
        }
    }

    // Un motif REFUSÉ doit l'être avec la VRAIE raison : une raison fausse envoie l'analyste
    // chercher un opérateur qu'il n'a jamais écrit.
    #[test]
    fn parse_rejection_gives_the_true_reason() {
        for (pattern, expected) in [
            // type d'objet custom `x-...` : LÉGAL en STIX 2.1, simplement non traduit ici. La raison
            // est le chemin d'objet, PAS le qualificateur WITHIN.
            (
                "[x-within-obj:value='1.2.3.4']",
                "unsupported STIX object path",
            ),
            (
                "[x-in-house:value='1.2.3.4']",
                "unsupported STIX object path",
            ),
            // valeur en DOUBLE quotes : la vraie raison est le littéral, pas l'opérateur LIKE.
            (
                "[url:value=\"http://x/likely-bad\"]",
                "not a quoted string literal",
            ),
            // algorithme de hachage dont le nom contient un opérateur : raison = algorithme.
            (
                "[file:hashes.WITHIN256 = 'dead']",
                "unsupported hash algorithm",
            ),
        ] {
            let e = parse_stix_pattern(pattern).unwrap_err();
            assert!(
                e.contains(expected),
                "raison trompeuse pour {pattern} : {e}"
            );
        }
    }

    // Direction INVERSE : un VRAI opérateur/qualificateur, hors littéral, reste refusé — y compris
    // collé à un crochet ou à une parenthèse, où la règle de jeton doit encore mordre.
    #[test]
    fn parse_real_operator_token_is_still_rejected() {
        for (pattern, needle) in [
            ("[a:value='x']WITHIN 60 SECONDS", "WITHIN"),
            ("[a:value='x'](WITHIN 60 SECONDS)", "WITHIN"),
            ("[a:value='x']REPEATS 3 TIMES", "REPEATS"),
            ("[a:value='x']FOLLOWEDBY [b:value='y']", "FOLLOWEDBY"),
            ("[file:name  LIKE  '%.exe']", "LIKE"),
            ("[file:name\tLIKE\t'%.exe']", "LIKE"),
            ("[file:name\nLIKE\n'%.exe']", "LIKE"),
            ("[file:name like '%.exe']", "LIKE"),
            ("[url:value LIKE'x']", "LIKE"),
            ("[domain-name:value IN('a.com','b.com')]", "IN"),
            ("[domain-name:value in ('a.com')]", "IN"),
            ("[domain-name:value NOT IN ('a.com')]", "IN"),
            ("[domain-name:value ISSUBSET 'a.com']", "ISSUBSET"),
            ("[domain-name:value ISSUPERSET 'a.com']", "ISSUPERSET"),
            ("[file:name MATCHES 'evil']", "MATCHES"),
            ("[ipv4-addr:value!='1.2.3.4']", "!="),
            ("[network-traffic:dst_port>='1024']", ">="),
        ] {
            let e = match parse_stix_pattern(pattern) {
                Err(e) => e,
                Ok(ok) => panic!("doit rester refusé : {pattern} -> {ok:?}"),
            };
            assert!(
                e.contains(needle),
                "raison attendue {needle} pour {pattern} : {e}"
            );
        }
    }

    #[test]
    fn parse_operator_in_structure_is_still_rejected() {
        // Contre-preuve : un VRAI opérateur (hors littéral) reste refusé avec sa raison.
        for pattern in [
            "[file:name LIKE '%.exe']",
            "[file:name MATCHES 'evil']",
            "[ipv4-addr:value != '1.2.3.4']",
            "[network-traffic:dst_port > '1024']",
            "[domain-name:value IN ('a.com','b.com')]",
            "[a:value = 'x'] REPEATS 3 TIMES",
            "[a:value = 'x'] WITHIN 60 SECONDS",
        ] {
            assert!(parse_stix_pattern(pattern).is_err(), "doit rester refusé : {pattern}");
        }
    }

    /// One row of the frozen corpus: the pattern, then either the pairs it MUST yield, or the
    /// substring its refusal reason MUST contain.
    type Row = (
        &'static str,
        Option<&'static [(&'static str, &'static str)]>,
        &'static str,
    );

    /// CORPUS ANTI-DÉRIVE — motifs STIX représentatifs, valides ET invalides, chacun avec le VERDICT
    /// attendu (pas seulement « ne panique pas »). Il contient délibérément des formes qu'aucune
    /// ligne du module ne traite nommément — écriture multi-ligne, tabulation, espace insécable,
    /// valeur non-ASCII, types custom `x-`, parenthèses imbriquées, littéral collé — pour que les
    /// gardes soient exercées sur leur CLASSE et pas sur les seuls cas qui les ont motivées.
    ///
    /// Les commentaires `48035b9:` / `742efe7:` sont des MESURES, faites hors dépôt sur les exports
    /// `git archive` de ces deux commits, avec la même entrée octet pour octet.
    fn corpus() -> Vec<Row> {
        vec![
            // ---- A. le sous-ensemble supporté, tel qu'un flux TI public l'écrit ----
            ("[ipv4-addr:value = '185.220.101.5']", Some(&[("ip", "185.220.101.5")]), ""),
            ("[ipv6-addr:value = '2a00:1450:4007:80f::200e']", Some(&[("ip", "2a00:1450:4007:80f::200e")]), ""),
            ("[domain-name:value = 'c2.badguy.tld']", Some(&[("domain", "c2.badguy.tld")]), ""),
            ("[domain-name:value = 'xn--80ak6aa92e.com']", Some(&[("domain", "xn--80ak6aa92e.com")]), ""),
            ("[domain-name:value='*.phish.example']", Some(&[("domain", "*.phish.example")]), ""),
            ("[url:value = 'http://185.220.101.5/gate.php']", Some(&[("url", "http://185.220.101.5/gate.php")]), ""),
            ("[url:value = 'https://example.com/path?a=1&b=2#frag']", Some(&[("url", "https://example.com/path?a=1&b=2#frag")]), ""),
            ("[url:value = 'http://192.168.0.1:8080/a%20b']", Some(&[("url", "http://192.168.0.1:8080/a%20b")]), ""),
            ("[email-addr:value = 'phish@mail.example']", Some(&[("email", "phish@mail.example")]), ""),
            ("[file:hashes.MD5 = 'dead']", Some(&[("hash_md5", "dead")]), ""),
            ("[file:hashes.'SHA-1' = 'dead']", Some(&[("hash_sha1", "dead")]), ""),
            ("[file:hashes.'SHA-256' = 'dead']", Some(&[("hash_sha256", "dead")]), ""),
            ("[file:hashes.\"MD5\" = 'dead']", Some(&[("hash_md5", "dead")]), ""),
            ("[file:hashes.sha256 = 'dead']", Some(&[("hash_sha256", "dead")]), ""),
            ("[file:hashes.SHA_256 = 'dead']", Some(&[("hash_sha256", "dead")]), ""),
            (
                "[file:hashes.MD5 = 'aa' OR file:hashes.'SHA-1' = 'bb' OR file:hashes.'SHA-256' = 'cc']",
                Some(&[("hash_md5", "aa"), ("hash_sha1", "bb"), ("hash_sha256", "cc")]),
                "",
            ),
            // écriture : espaces, tabulation, RETOUR À LA LIGNE dans le motif, espace insécable
            ("[ url:value = 'http://x/y' ]", Some(&[("url", "http://x/y")]), ""),
            ("[url:value\t=\t'http://x/tab']", Some(&[("url", "http://x/tab")]), ""),
            ("[url:value =\n   'http://x/multiline']", Some(&[("url", "http://x/multiline")]), ""),
            ("  \t[url:value='http://x/pad']\n  ", Some(&[("url", "http://x/pad")]), ""),
            ("[url:value\u{a0}= 'http://x/nbsp']", Some(&[("url", "http://x/nbsp")]), ""),
            // NBSP autour de la VALEUR : la vue structurelle doit rogner l'espace UNICODE comme le
            // fait `.trim()` en aval, sinon la valeur ne commence plus par sa quote et un IOC
            // parfaitement ordinaire est refusé (mesuré : accepté sur 48035b9 et 742efe7).
            ("[url:value =\u{a0}'http://x/nbsp-rhs']", Some(&[("url", "http://x/nbsp-rhs")]), ""),
            ("[url:value=\u{a0}'http://x/nbsp2'\u{a0}]", Some(&[("url", "http://x/nbsp2")]), ""),
            // expression d'observation parenthésée (acceptée sur 48035b9 ET 742efe7 — mesuré)
            ("([url:value='http://x/paren'])", Some(&[("url", "http://x/paren")]), ""),
            ("(  [url:value='http://x/paren2']  )", Some(&[("url", "http://x/paren2")]), ""),
            ("((([url:value='http://x/deep'])))", Some(&[("url", "http://x/deep")]), ""),
            ("[(url:value='http://x/inner-paren')]", Some(&[("url", "http://x/inner-paren")]), ""),
            // ---- B. valeurs qui RESSEMBLENT à de la structure : doivent rester des VALEURS ----
            ("[url:value='http://[2001:db8::1]:8080/a']", Some(&[("url", "http://[2001:db8::1]:8080/a")]), ""),
            ("[url:value='http://x/a[0]']", Some(&[("url", "http://x/a[0]")]), ""),
            ("[url:value='http://x/café[1]']", Some(&[("url", "http://x/café[1]")]), ""),
            ("[url:value='http://x/[within]/[repeats]']", Some(&[("url", "http://x/[within]/[repeats]")]), ""),
            ("[url:value='http://x/likely-bad']", Some(&[("url", "http://x/likely-bad")]), ""),
            ("[domain-name:value='within.example.com']", Some(&[("domain", "within.example.com")]), ""),
            ("[domain-name:value='matches-evil.example']", Some(&[("domain", "matches-evil.example")]), ""),
            ("[url:value='http://x/repeats']", Some(&[("url", "http://x/repeats")]), ""),
            ("[url:value='http://x/?a=1<2']", Some(&[("url", "http://x/?a=1<2")]), ""),
            (r"[url:value='a\' OR domain-name:value=\'evil.com']", Some(&[("url", r"a' OR domain-name:value='evil.com")]), ""),
            (r"[url:value = 'http://x/?q=1\'2']", Some(&[("url", "http://x/?q=1'2")]), ""),
            (r"[url:value='c:\\windows\\x']", Some(&[("url", r"c:\windows\x")]), ""),
            // ---- C. opérateurs / chemins réellement non traduits : refus, VRAIE raison ----
            ("[network-traffic:dst_port = '445']", None, "unsupported STIX object path"),
            ("[x-within-obj:value='1.2.3.4']", None, "unsupported STIX object path"),
            ("[x-in-house:value='1.2.3.4']", None, "unsupported STIX object path"),
            ("[x-repeats-tracker:value='a.com']", None, "unsupported STIX object path"),
            ("[x-likely-bad:value='a.com']", None, "unsupported STIX object path"),
            ("[file:hashes.SSDEEP = 'x']", None, "unsupported hash algorithm"),
            ("[file:hashes.WITHIN256 = 'dead']", None, "unsupported hash algorithm"),
            ("[url:value=\"http://x/likely-bad\"]", None, "not a quoted string literal"),
            ("[file:name LIKE '%.exe']", None, "(LIKE)"),
            ("[file:name MATCHES 'evil']", None, "(MATCHES)"),
            ("[domain-name:value IN ('a.com','b.com')]", None, "(IN)"),
            ("[domain-name:value ISSUBSET 'a.com']", None, "(ISSUBSET)"),
            ("[domain-name:value ISSUPERSET 'a.com']", None, "(ISSUPERSET)"),
            ("[ipv4-addr:value != '1.2.3.4']", None, "(!=)"),
            ("[network-traffic:dst_port >= '1024']", None, "(>=)"),
            ("[domain-name:value='a.com' AND url:value='http://a']", None, "AND-combined"),
            ("", None, "empty pattern"),
            ("[]", None, "no comparison found"),
            ("ipv4-addr:value = '1.2.3.4'", None, "not a STIX observation"),
            // ---- D. le littéral doit être UN littéral, entier ----
            // 48035b9 & 742efe7 : OK [(url,"x'")] — la 2e quote, orpheline, était avalée en silence.
            ("[url:value='x'']", None, "unterminated string literal"),
            ("[url:value='http://x/o'brien']", None, "unterminated string literal"),
            ("[url:value='x]", None, "unterminated string literal"),
            // 48035b9 & 742efe7 : OK [(url,"http://a'AND url:value='http://b")] — le AND replié DANS
            // la valeur, IOC émis avec une valeur que personne n'a écrite.
            ("[url:value='http://a'AND url:value='http://b']", None, "not a quoted string literal"),
            ("[url:value='a'foo'b']", None, "not a quoted string literal"),
            // ---- E. clé d'algorithme lue TELLE QU'ÉCRITE ----
            // 48035b9 & 742efe7 : les trois -> OK [(hash_md5, …)], caractères supprimés en silence.
            ("[file:hashes.MD5#$%^ = 'dead']", None, "unsupported hash algorithm"),
            ("[file:hashes.MD 5 = 'dead']", None, "unsupported hash algorithm"),
            ("[file:hashes.MD5! = 'dead']", None, "unsupported hash algorithm"),
            ("[file:hashes.'SHA-256'x = 'dead']", None, "unsupported hash algorithm"),
            ("[file:hashes.M-D-5 = 'dead']", Some(&[("hash_md5", "dead")]), ""), // inchangé vs 48035b9
            // ---- F. hors de l'observation : rien n'est toléré ----
            // 48035b9 & 742efe7 : les cinq premiers -> OK, le texte hors crochets jeté sans un mot.
            ("[url:value='x'] START t'2020-01-01T00:00:00Z' STOP t'2021-01-01T00:00:00Z'", None, "outside the observation"),
            ("[url:value='x'] EN DEHORS DE TOUT", None, "outside the observation"),
            ("[url:value='x'] ; DROP TABLE ioc", None, "outside the observation"),
            ("GARBAGE [url:value='x']", None, "outside the observation"),
            ("[url:value='x']\u{a0}Ω", None, "outside the observation"),
            // 742efe7 : OK — qualificateur MALFORMÉ (pas de frontière avant son argument).
            ("[url:value='x'] WITHIN60 SECONDS", None, "outside the observation"),
            ("[url:value='x'] REPEATS3 TIMES", None, "outside the observation"),
            ("[url:value='x'] ISSUBSET42", None, "outside the observation"),
            // qualificateur BIEN formé : la couche de raison le nomme (le verdict, lui, vient du
            // même contrôle « hors observation » — cf. operator_list_is_a_reason_layer_not_a_gate)
            ("[url:value='x'] WITHIN 60 SECONDS", None, "(WITHIN)"),
            ("[url:value='x']REPEATS 3 TIMES", None, "(REPEATS)"),
            ("[a:value='x'] FOLLOWEDBY [b:value='y']", None, "(FOLLOWEDBY)"),
            ("[a:value='x'][b:value='y']", None, "outside the observation"),
            ("([url:value='a']) OR ([url:value='b'])", None, "outside the observation"),
        ]
    }

    #[test]
    fn stix_corpus_verdicts_are_frozen() {
        for (pattern, want_ok, want_err) in corpus() {
            match (parse_stix_pattern(pattern), want_ok) {
                (Ok(got), Some(exp)) => {
                    let exp: Vec<(&str, String)> =
                        exp.iter().map(|(k, v)| (*k, (*v).to_string())).collect();
                    assert_eq!(got, exp, "verdict changé pour {pattern:?}");
                }
                (Err(e), None) => assert!(
                    e.contains(want_err),
                    "raison changée pour {pattern:?} : attendu ~{want_err:?}, obtenu {e:?}"
                ),
                (Ok(got), None) => panic!("{pattern:?} devait être REFUSÉ, obtenu {got:?}"),
                (Err(e), Some(_)) => panic!("{pattern:?} devait être ACCEPTÉ, obtenu {e:?}"),
            }
        }
    }

    /// LA CLASSE, PAS LE CAS. Le mode d'échec fermé ici n'est pas « le mot WITHIN » mais « du texte
    /// hors de l'observation est jeté en silence ». On l'exerce donc par PRODUIT séparateur × queue,
    /// avec des séparateurs et des queues dont AUCUN n'apparaît dans le code du module : espace
    /// insécable, retour chariot seul, écriture multi-ligne, ponctuation, unicode, chiffres nus.
    /// Aucun n'est traité nommément ; tous doivent tomber du côté du refus, avec une raison NON VIDE.
    ///
    /// MESURE de référence (sondes hors dépôt, mêmes 202 formes) : 48035b9 en acceptait 106,
    /// 742efe7 en acceptait 177, la révision courante 0.
    #[test]
    fn qualifier_tails_are_never_dropped_in_silence() {
        let seps = [
            " ", "\t", "\n", "\r", "\u{a0}", "", "  ", " \n ", "/", ";", "-", "+", "|",
        ];
        let tails = [
            "WITHIN 60 SECONDS",
            "WITHIN60 SECONDS",
            "within60 seconds",
            "WiThIn60",
            "REPEATS3 TIMES",
            "ISSUBSET42",
            "FOLLOWEDBY60 [b:value='y']",
            "START t'2020-01-01T00:00:00Z' STOP t'2021-01-01T00:00:00Z'",
            "STARTt'2020-01-01T00:00:00Z'",
            "ZZZ",
            "Ω",
            "1",
            "%",
            "--commentaire",
        ];
        let mut checked = 0usize;
        for s in seps {
            for t in tails {
                let p = format!("[url:value='x']{s}{t}");
                let e = match parse_stix_pattern(&p) {
                    Err(e) => e,
                    Ok(v) => panic!("queue jetée en silence : {p:?} -> {v:?}"),
                };
                assert!(!e.trim().is_empty(), "refus sans raison pour {p:?}");
                checked += 1;
            }
        }
        for s in [" ", "\t", "\n", "\u{a0}", ""] {
            for h in ["GARBAGE", "WITHIN60", "Ω", "OBJECT"] {
                let p = format!("{h}{s}[url:value='x']");
                if let Ok(v) = parse_stix_pattern(&p) {
                    panic!("tête jetée en silence : {p:?} -> {v:?}");
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 202, "le produit mesuré doit rester le même");
    }

    /// La décision n'est prise qu'à UN endroit : `parse_stix_pattern` ne produit un `Ok` que par
    /// `translate_observation`, et `name_known_operator` ne reçoit qu'un `Err` dont il réécrit le
    /// TEXTE — cet argument-là est la FORME du `match`, pas ce test.
    ///
    /// CE QUE CE TEST MESURE, exactement : sur le corpus et sur des motifs choisis pour porter un
    /// opérateur, le verdict (et la valeur produite) sont IDENTIQUES avec et sans la couche de
    /// raison — donc aucune entrée de `NAMED_OPERATORS` / `SYMBOLIC_OPERATORS` ne porte aujourd'hui
    /// une décision. CE QU'IL NE MESURE PAS : replacer la liste en garde AVANT le `match` ne le fait
    /// PAS tomber (vérifié sur une copie mutée : 16/16 verts), parce qu'une telle garde serait
    /// aujourd'hui redondante. Il tombe le jour où une entrée refuserait un motif que le site de
    /// décision accepte — c'est la régression qu'il garde, pas la forme du code.
    #[test]
    fn operator_list_is_a_reason_layer_not_a_gate() {
        let mut patterns: Vec<String> = corpus().iter().map(|(p, _, _)| (*p).to_string()).collect();
        for s in [" ", "", "\t", "\n"] {
            for t in [
                "WITHIN 60 SECONDS",
                "LIKE 'x'",
                "IN ('a')",
                "ZZZ",
                "ISSUBSET42",
            ] {
                patterns.push(format!("[url:value='x']{s}{t}"));
            }
        }
        for p in [
            "[file:hashes.MD5<= 'dead']",
            "[file:hashes.MD5 >= 'dead']",
            "[file:name LIKE '%.exe']",
            "[domain-name:value IN ('a.com')]",
            "[ipv4-addr:value != '1.2.3.4']",
            "[url:value LIKE'x']",
        ] {
            patterns.push(p.to_string());
        }
        for p in &patterns {
            let with = parse_stix_pattern(p);
            let without = translate_observation(p.trim());
            assert_eq!(
                with.is_ok(),
                without.is_ok(),
                "la liste d'opérateurs a changé un VERDICT pour {p:?} : {with:?} vs {without:?}"
            );
            if let (Ok(a), Ok(b)) = (&with, &without) {
                assert_eq!(a, b, "sortie divergente pour {p:?}");
            }
        }
    }

    /// La raison rend le texte REFUSÉ tel qu'il a été écrit — sinon « jeté en silence » redevient
    /// vrai à l'échelle du message. Bornée en CARACTÈRES (pas en octets) : une queue multi-octets ne
    /// peut ni couper une frontière de caractère ni faire enfler le message sans limite.
    #[test]
    fn outside_reason_quotes_the_text_and_is_clipped() {
        let e = parse_stix_pattern("[url:value='x'] ; DROP TABLE ioc").unwrap_err();
        assert!(e.contains("; DROP TABLE ioc"), "{e}");
        let long = "Ω".repeat(500);
        let e = parse_stix_pattern(&format!("[url:value='x'] {long}")).unwrap_err();
        assert!(e.contains(&"Ω".repeat(CLIP_CHARS)), "{e}");
        assert!(!e.contains(&"Ω".repeat(CLIP_CHARS + 1)), "non borné : {e}");
        assert!(e.contains('…'), "troncature non signalée : {e}");
        // les DEUX côtés sont rendus quand les deux existent
        let e = parse_stix_pattern("AVANT [url:value='x'] APRÈS").unwrap_err();
        assert!(e.contains("AVANT") && e.contains("APRÈS"), "{e}");
    }

    /// Au niveau PRODUIT : un indicateur dont le motif porte un qualificateur ne disparaît pas, il
    /// ressort dans `skipped` AVEC sa raison — c'est le contrat de l'en-tête du module.
    #[test]
    fn bundle_reports_a_dropped_qualifier_instead_of_importing_a_bare_ioc() {
        let bundle = json!({"type":"bundle","id":"bundle--q","objects":[
            {"type":"indicator","id":"indicator--win","pattern_type":"stix",
             "pattern":"[url:value='http://evil/x'] START t'2020-01-01T00:00:00Z' STOP t'2021-01-01T00:00:00Z'"},
            {"type":"indicator","id":"indicator--mal","pattern_type":"stix",
             "pattern":"[url:value='http://evil/y'] WITHIN60 SECONDS"},
            {"type":"indicator","id":"indicator--ok","pattern_type":"stix",
             "pattern":"[url:value='http://evil/z']"}
        ]});
        let imp = stix_bundle_to_iocs(&bundle);
        assert_eq!(imp.iocs.len(), 1, "{:?}", imp.iocs);
        assert_eq!(imp.iocs[0].value, "http://evil/z");
        assert_eq!(imp.skipped.len(), 2);
        for id in ["indicator--win", "indicator--mal"] {
            let s = imp.skipped.iter().find(|s| s.id == id).expect(id);
            assert!(!s.reason.trim().is_empty(), "skip sans raison : {s:?}");
        }
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
