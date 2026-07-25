//! BANC DIFFÉRENTIEL — gate de la migration du compilo SOQL de Plume vers `core`.
//!
//! PROUVE que `guatx_core::soql::compile_with_time(q, from, to, &Schema::events())` est un
//! SUR-ENSEMBLE STRICT du compilo legacy de Plume : pour tout le corpus, le SQL émis, le statut
//! ok/erreur et les colonnes de sortie sont IDENTIQUES. Tant que ce test est vert, basculer le
//! compilo de Plume vers core NE CHANGE PAS le SQL généré (donc PAS les détections).
//!
//! RÉFÉRENCE « Plume » (module `plume_ref` ci-dessous) = MIROIR FIGÉ du compilo legacy du daemon
//! Plume (`soql_compile` + helpers). ATTENTION : le compilo legacy `soql_compile` ayant été RETIRÉ
//! (le daemon délègue désormais à `guatx_core::soql`), ce miroir n'est plus une capture « verbatim »
//! d'un compilo legacy vivant — pour les OPS POST-MIGRATION (`values`/`list`, `in`/`not in` + glue, `rename`,
//! `lookup`, `mvexpand`, rollup ATT&CK) il est synchronisé À LA MAIN sur core. Sa valeur reste ENTIÈRE :
//! c'est une RÉIMPLÉMENTATION INDÉPENDANTE (fragments `format!` codés séparément), donc toute édition
//! UNILATÉRALE de core (le cas courant d'une régression) fait diverger le banc. Seule une édition
//! SIMULTANÉE core+miroir passerait le différentiel — d'où les GOLDENS littéraux ci-dessous en filet
//! secondaire. Figée en CONFIGURATION DE RÉFÉRENCE DU BANC :
//!   - `PLUME_FTS_FIELDS` OFF  -> terme libre = `message LIKE '%tok%'` (jamais la branche FTS5).
//!   - `PLUME_AUTOINDEX` OFF   -> `AUTOINDEX_SET` vide -> `field_is_indexed == HOT_FIELDS.contains`.
//!   - instrumentation de chaleur (`autoindex_note*`) = effets de bord SANS impact SQL -> omise.
//! C'est exactement le SQL que `/api/query` renvoie dans `compiled_sql` via `soql_to_sql`
//! (= `soql_compile`), hors interception rollup-route (optimisation Plume-only conservée côté daemon).
//!
//! REJOUABLE hors-ligne : `cargo test -p guatx-core --test plume_parity -- --nocapture`.
//! Corpus dans `tests/corpus_soql_coverage.txt`.

use guatx_core::soql::{compile, compile_with_time, Dialect, Schema, SqliteDialect};

// =================================================================================================
// RÉFÉRENCE PLUME (verbatim, configuration de référence). NE PAS « améliorer » : doit rester le miroir EXACT du
// compilo legacy. Toute divergence volontaire de core est portée DANS core, pas ici.
// =================================================================================================
#[allow(dead_code)]
mod plume_ref {
    fn soql_tokenize(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut inq = false;
        for c in s.chars() {
            match c {
                '"' => inq = !inq,
                c if c.is_whitespace() && !inq => {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                }
                c => cur.push(c),
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }

    fn soql_ident_ok(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
    fn soql_esc(s: &str) -> String {
        s.replace('\'', "''")
    }
    fn soql_qid(s: &str) -> String {
        format!("\"{}\"", s.replace('"', "\"\""))
    }
    fn soql_num(s: &str) -> bool {
        let s = s.strip_prefix('-').unwrap_or(s);
        let mut parts = s.split('.');
        let int = parts.next().unwrap_or("");
        let frac = parts.next();
        parts.next().is_none()
            && !int.is_empty() && int.bytes().all(|b| b.is_ascii_digit())
            && frac.map_or(true, |f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
    }
    fn soql_agg(tok: &str, cols: &[String]) -> Result<(String, String), String> {
        if tok == "count" {
            return Ok(("COUNT(*)".to_string(), "count".to_string()));
        }
        if let Some(o) = tok.find('(') {
            if tok.ends_with(')') {
                let func = &tok[..o];
                let field = &tok[o + 1..tok.len() - 1];
                if !soql_ident_ok(field) {
                    return Err(format!("champ invalide : {field}"));
                }
                let qf = soql_field(field, cols);
                let sql = match func {
                    "count" => format!("COUNT({qf})"),
                    "sum" => format!("SUM({qf})"),
                    "avg" => format!("AVG({qf})"),
                    "min" => format!("MIN({qf})"),
                    "max" => format!("MAX({qf})"),
                    "dc" => format!("COUNT(DISTINCT {qf})"),
                    // Agrégats-liste bornés (OP 1) : miroir INDÉPENDANT du `group_concat_bounded` du
                    // Dialect (cap 4096) — sans cela le banc différentiel n'exerçait JAMAIS cette méthode.
                    "values" => format!("substr(GROUP_CONCAT(DISTINCT {qf}),1,4096)"),
                    "list" => format!("substr(GROUP_CONCAT({qf}),1,4096)"),
                    _ => return Err(format!("fonction stats inconnue : {func}")),
                };
                return Ok((sql, func.to_string()));
            }
        }
        Err(format!("stats : syntaxe invalide '{tok}' (count | sum(f) | avg(f) | min(f) | max(f) | dc(f))"))
    }
    fn soql_dur(s: &str) -> Result<i64, String> {
        let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (num, unit) = s.split_at(split);
        let n: i64 = num.parse().map_err(|_| "span invalide".to_string())?;
        let mult = match unit {
            "" | "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86400,
            _ => return Err(format!("unité span inconnue : {unit}")),
        };
        Ok(n * mult)
    }
    fn soql_expr_sql(expr: &str) -> Result<String, String> {
        const FNS: &[&str] = &[
            "if", "coalesce", "ifnull", "nullif", "lower", "upper", "length", "len", "abs", "round",
            "min", "max", "substr", "replace", "trim",
        ];
        const DENY_KW: &[&str] = &[
            "select", "from", "where", "union", "intersect", "except", "join", "using", "on", "by",
            "group", "order", "having", "limit", "offset", "with", "as", "into", "values", "exists",
            "pragma", "attach", "detach", "insert", "update", "delete", "drop", "alter", "create",
            "replace", "returning", "vacuum", "reindex", "analyze", "over", "partition", "window", "cast",
        ];
        let chars: Vec<char> = expr.chars().collect();
        let mut i = 0;
        let mut out = String::new();
        while i < chars.len() {
            let c = chars[i];
            if c.is_whitespace() {
                out.push(' ');
                i += 1;
                continue;
            }
            if c == '\'' || c == '"' {
                let q = c;
                i += 1;
                let mut s = String::new();
                while i < chars.len() && chars[i] != q {
                    s.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("eval : chaîne non terminée".into());
                }
                i += 1;
                out.push('\'');
                out.push_str(&s.replace('\'', "''"));
                out.push('\'');
                continue;
            }
            if c.is_ascii_digit() || (c == '.' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit()) {
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    out.push(chars[i]);
                    i += 1;
                }
                continue;
            }
            if c.is_ascii_alphabetic() || c == '_' {
                let mut id = String::new();
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    id.push(chars[i]);
                    i += 1;
                }
                let mut j = i;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                let is_fn = j < chars.len() && chars[j] == '(';
                let low = id.to_lowercase();
                if matches!(low.as_str(), "and" | "or" | "not" | "in" | "like" | "between" | "is" | "glob" | "null" | "true" | "false") {
                    out.push_str(&low);
                } else if is_fn {
                    if !FNS.contains(&low.as_str()) {
                        return Err(format!("eval : fonction non autorisée : {id}"));
                    }
                    out.push_str(match low.as_str() {
                        "len" => "length",
                        "if" => "iif",
                        _ => low.as_str(),
                    });
                } else if DENY_KW.contains(&low.as_str()) {
                    return Err(format!("eval : mot-clé SQL non autorisé : {id}"));
                } else if soql_ident_ok(&id) {
                    out.push_str(&id);
                } else {
                    return Err(format!("eval : identifiant invalide : {id}"));
                }
                continue;
            }
            let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
            match two.as_str() {
                "==" => {
                    out.push('=');
                    i += 2;
                    continue;
                }
                "!=" | "<>" | "<=" | ">=" => {
                    out.push_str(&two);
                    i += 2;
                    continue;
                }
                _ => {}
            }
            match c {
                '+' | '-' | '*' | '/' | '%' | '(' | ')' | ',' | '<' | '>' | '=' => {
                    out.push(c);
                    i += 1;
                }
                '.' => {
                    out.push_str(" || ");
                    i += 1;
                }
                _ => return Err(format!("eval : caractère non autorisé : '{c}'")),
            }
        }
        Ok(out)
    }

    // Défaut produit : PLUME_AUTOINDEX OFF -> AUTOINDEX_SET vide -> field_is_indexed = HOT_FIELDS.contains.
    const HOT_FIELDS: &[&str] = &[
        "action", "user", "owner", "kind", "ns", "role", "scope",
        "verb", "resource", "operation",
    ];
    fn field_is_indexed(name: &str) -> bool {
        HOT_FIELDS.contains(&name)
    }

    fn soql_field(name: &str, cols: &[String]) -> String {
        if cols.iter().any(|c| c == name) {
            soql_qid(name)
        } else if cols.iter().any(|c| c == "fields") {
            format!("json_extract(fields,'$.{name}')")
        } else {
            soql_qid(name)
        }
    }

    const EVENT_COLS: &[&str] = &["ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields", "dedup", "id"];
    fn soql_filter_field(name: &str, numeric: bool) -> String {
        if EVENT_COLS.contains(&name) {
            soql_qid(name)
        } else if numeric && !field_is_indexed(name) {
            format!("CAST(json_extract(fields,'$.{name}') AS REAL)")
        } else {
            format!("json_extract(fields,'$.{name}')")
        }
    }

    fn soql_split_pipes(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut depth = 0i32;
        let mut cur = String::new();
        for c in s.chars() {
            match c {
                '[' => { depth += 1; cur.push(c); }
                ']' => { depth -= 1; cur.push(c); }
                '|' if depth == 0 => { out.push(cur.trim().to_string()); cur.clear(); }
                _ => cur.push(c),
            }
        }
        if !cur.trim().is_empty() { out.push(cur.trim().to_string()); }
        out.into_iter().filter(|s| !s.is_empty()).collect()
    }

    fn soql_bracket(stage: &str) -> Result<String, String> {
        let start = stage.find('[').ok_or_else(|| "crochet '[' manquant (ex: append [search ...])".to_string())?;
        let end = stage.rfind(']').ok_or_else(|| "crochet ']' manquant".to_string())?;
        if end <= start + 1 {
            return Err("sous-recherche vide".into());
        }
        Ok(stage[start + 1..end].trim().to_string())
    }

    fn soql_proj(target: &[String], have: &[String]) -> String {
        let items: Vec<String> = target
            .iter()
            .map(|c| if have.iter().any(|h| h == c) { soql_qid(c) } else { format!("NULL AS {}", soql_qid(c)) })
            .collect();
        format!("SELECT {}", items.join(", "))
    }

    fn metric_base(spec: &str, from: i64, to: i64) -> Result<(String, Vec<String>), String> {
        let toks: Vec<&str> = spec.split_whitespace().collect();
        let name = match toks.get(1) {
            Some(n) => *n,
            None => return Err("metric : nom de métrique requis (ex: metric node_load1)".into()),
        };
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b':') {
            return Err(format!("metric : nom invalide : {name}"));
        }
        let mut conds = vec![format!("name='{}'", soql_esc(name))];
        let mut value_cond: Option<String> = None;
        let mut value_cond_roll: Option<String> = None;
        let mut bylabels: Vec<String> = Vec::new();
        let mut i = 2;
        while i < toks.len() {
            if toks[i] == "by" {
                bylabels = toks[i + 1..].join(" ").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                break;
            }
            if let Some((op, num)) = parse_value_filter(toks[i]) {
                value_cond = Some(format!("value {op} {num}"));
                value_cond_roll = Some(format!("avg {op} {num}"));
            } else if let Some((k, v)) = toks[i].split_once('=') {
                if soql_ident_ok(k) {
                    conds.push(format!("json_extract(labels,'$.{}')='{}'", k, soql_esc(v)));
                }
            }
            i += 1;
        }
        if from > 0 { conds.push(format!("ts >= {from}")); }
        if to > 0 { conds.push(format!("ts <= {to}")); }
        let mut sel = "ts,host,value".to_string();
        let mut selr = "ts,host,avg AS value".to_string();
        let mut ocols: Vec<String> = vec!["ts".into(), "host".into(), "value".into()];
        for l in &bylabels {
            if soql_ident_ok(l) {
                sel.push_str(&format!(",json_extract(labels,'$.{l}') AS {}", soql_qid(l)));
                selr.push_str(&format!(",json_extract(labels,'$.{l}') AS {}", soql_qid(l)));
                ocols.push(l.clone());
            }
        }
        let mut raw_conds = conds.clone();
        let mut roll_conds = conds;
        if let Some(vc) = value_cond { raw_conds.push(vc); }
        if let Some(vc) = value_cond_roll { roll_conds.push(vc); }
        let cond = raw_conds.join(" AND ");
        let cond_roll = roll_conds.join(" AND ");
        let sql = format!("SELECT {sel} FROM metric WHERE {cond} UNION ALL SELECT {selr} FROM metric_rollup WHERE {cond_roll} ORDER BY ts");
        Ok((sql, ocols))
    }

    fn parse_value_filter(tok: &str) -> Option<(&'static str, f64)> {
        let rest = tok.strip_prefix("value")?;
        for (pat, sqlop) in [(">=", ">="), ("<=", "<="), ("!=", "<>"), ("=", "="), (">", ">"), ("<", "<")] {
            if let Some(num) = rest.strip_prefix(pat) {
                if let Ok(f) = num.trim().parse::<f64>() {
                    return Some((sqlop, f));
                }
            }
        }
        None
    }

    // OP 2 (`in` / `not in`) + re-collage des opérateurs espacés — miroir INDÉPENDANT du pré-pass de
    // core (`soql_in_*` / `soql_glue_spaced_ops`). Sans eux le banc ne comparait AUCUNE clause `in`/`not
    // in` ni forme `champ = "x"` espacée (elles n'étaient couvertes que par des goldens auto-cohérents).
    fn soql_glue_spaced_ops(tokens: Vec<String>) -> Vec<String> {
        fn is_op(c: char) -> bool { matches!(c, '=' | ':' | '!' | '<' | '>' | '~') }
        let mut out: Vec<String> = Vec::new();
        let mut i = 0;
        while i < tokens.len() {
            let mut t = tokens[i].clone();
            i += 1;
            let bare = !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if bare && i < tokens.len() && tokens[i].starts_with(is_op) { t.push_str(&tokens[i]); i += 1; }
            if t.ends_with(is_op) && i < tokens.len() { t.push_str(&tokens[i]); i += 1; }
            out.push(t);
        }
        out
    }
    fn soql_in_re() -> &'static regex::Regex {
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"(?i)\b([A-Za-z_][A-Za-z0-9_]*)\s+(not\s+)?in\s*\(([^()]*)\)").unwrap())
    }
    fn soql_in_values(inner: &str) -> Vec<String> {
        inner.split(',').map(|v| v.trim().trim_matches('"').trim().to_string()).filter(|v| !v.is_empty()).collect()
    }
    fn soql_in_cond(field: &str, negate: bool, vals: &[String]) -> String {
        let numeric = vals.iter().all(|v| soql_num(v));
        let fexpr = soql_filter_field(field, numeric);
        let list = if numeric {
            vals.join(",")
        } else {
            vals.iter().map(|v| format!("'{}'", soql_esc(v))).collect::<Vec<_>>().join(",")
        };
        // MIROIR synchronisé sur core : `in(...)` textuel positif = COLLATE NOCASE (casse-insensible),
        // numérique/négation = BINARY. Édition SIMULTANÉE core+miroir -> différentiel reste vert.
        let collate = if numeric || negate { "" } else { " COLLATE NOCASE" };
        format!("{fexpr}{collate} {} ({list})", if negate { "NOT IN" } else { "IN" })
    }
    fn soql_in_collect(first: &str, conds: &mut Vec<String>) -> String {
        soql_in_re().replace_all(first, |caps: &regex::Captures| {
            let vals = soql_in_values(&caps[3]);
            if vals.is_empty() { return String::from(" "); }
            conds.push(soql_in_cond(&caps[1], caps.get(2).is_some(), &vals));
            String::from(" ")
        }).into_owned()
    }
    fn soql_parse_in(expr: &str) -> Option<(String, bool, Vec<String>)> {
        let e = expr.trim();
        let caps = soql_in_re().captures(e)?;
        let m = caps.get(0)?;
        if m.start() != 0 || m.end() != e.len() { return None; }
        let vals = soql_in_values(caps.get(3)?.as_str());
        if vals.is_empty() { return None; }
        Some((caps.get(1)?.as_str().to_string(), caps.get(2).is_some(), vals))
    }

    pub fn soql_compile(soql: &str, from: i64, to: i64, depth: u32) -> Result<(String, Vec<String>), String> {
        if depth > 3 {
            return Err("sous-recherches trop imbriquées (max 3)".into());
        }
        let stages = soql_split_pipes(soql);
        if stages.is_empty() {
            return Err("soql vide".into());
        }
        let f0 = stages[0].trim();
        let (mut sql, mut ocols): (String, Vec<String>) = if f0 == "metric" || f0.starts_with("metric ") {
            metric_base(f0, from, to)?
        } else {
            let mut first: &str = stages[0].as_str();
            if let Some(r) = first.strip_prefix("search ") {
                first = r.trim();
            } else if first == "search" {
                first = "";
            }
            let mut conds: Vec<String> = Vec::new();
            // OP 2 : pré-pass `in`/`not in` (extrait AVANT glue/tokenize, comme core `soql_in_collect`).
            let cleaned;
            let first = if first.contains('(') {
                cleaned = soql_in_collect(first, &mut conds);
                cleaned.as_str()
            } else {
                first
            };
            for tk in soql_glue_spaced_ops(soql_tokenize(first)) {
                let mut matched = false;
                for op in ["=~", ">=", "<=", "!=", "=", ":", ">", "<"] {
                    if let Some(pos) = tk.find(op) {
                        let field = &tk[..pos];
                        let val = &tk[pos + op.len()..];
                        if soql_ident_ok(field) {
                            let fstr = soql_filter_field(field, false);
                            if op == "=~" {
                                conds.push(format!("{fstr} REGEXP '{}'", soql_esc(val)));
                                matched = true;
                                break;
                            }
                            let sqlop = match op { "!=" => "<>", ":" => "=", _ => op };
                            if matches!(op, ":" | "=") && val.starts_with('~') {
                                conds.push(format!("{fstr} REGEXP '{}'", soql_esc(&val[1..])));
                            } else if matches!(op, ":" | "=" | "!=") && val.contains('*') {
                                let like = soql_esc(val).replace('*', "%");
                                let likeop = if op == "!=" { "NOT LIKE" } else { "LIKE" };
                                conds.push(format!("{fstr} {likeop} '{like}'"));
                            } else if soql_num(val) {
                                conds.push(format!("{} {sqlop} {val}", soql_filter_field(field, true)));
                            } else {
                                conds.push(format!("{fstr} {sqlop} '{}'", soql_esc(val)));
                            }
                            matched = true;
                            break;
                        }
                    }
                }
                if !matched {
                    // Défaut produit : PLUME_FTS_FIELDS OFF -> toujours la branche message LIKE.
                    conds.push(format!("message LIKE '%{}%'", soql_esc(&tk)));
                }
            }
            if from > 0 {
                conds.push(format!("ts >= {from}"));
            }
            if to > 0 {
                conds.push(format!("ts <= {to}"));
            }
            let wc = if conds.is_empty() { String::new() } else { format!(" WHERE {}", conds.join(" AND ")) };
            (
                format!("SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event{wc}"),
                ["ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields"].iter().map(|s| s.to_string()).collect(),
            )
        };

        for stage in &stages[1..] {
            let toks: Vec<&str> = stage.split_whitespace().collect();
            match toks.first().copied().unwrap_or("") {
                "stats" => {
                    let (aggsql, alias) = soql_agg(toks.get(1).copied().unwrap_or("count"), &ocols)?;
                    if let Some(bi) = toks.iter().position(|w| *w == "by") {
                        let fields: Vec<String> = toks[bi + 1..].join(" ").split(',')
                            .map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                        for f in &fields {
                            if !soql_ident_ok(f) {
                                return Err(format!("champ invalide : {f}"));
                            }
                        }
                        let sel: Vec<String> = fields.iter().map(|f| format!("{} AS {}", soql_field(f, &ocols), soql_qid(f))).collect();
                        let gcols = fields.iter().map(|f| soql_qid(f)).collect::<Vec<_>>().join(",");
                        sql = format!("SELECT {},{aggsql} AS {} FROM ({sql}) GROUP BY {gcols}", sel.join(","), soql_qid(&alias));
                        ocols = fields;
                        ocols.push(alias.to_string());
                    } else {
                        sql = format!("SELECT {aggsql} AS {} FROM ({sql})", soql_qid(&alias));
                        ocols = vec![alias.to_string()];
                    }
                }
                "timechart" => {
                    let byi = toks.iter().position(|w| *w == "by");
                    let head_end = byi.unwrap_or(toks.len());
                    let mut span = 0i64;
                    let mut aggtok = "count";
                    for t in &toks[1..head_end] {
                        if let Some(s) = t.strip_prefix("span=") {
                            span = soql_dur(s)?;
                        } else if !t.contains('=') {
                            aggtok = t;
                        }
                    }
                    if span <= 0 {
                        let range = if to > from && from > 0 { to - from } else { 86400 };
                        let raw = (range / 120).max(60);
                        let steps = [60i64, 300, 900, 1800, 3600, 7200, 14400, 43200, 86400, 604800];
                        span = *steps.iter().find(|&&s| s >= raw).unwrap_or(&604800);
                    }
                    let (aggsql, alias) = soql_agg(aggtok, &ocols)?;
                    let by: Vec<String> = byi
                        .map(|bi| toks[bi + 1..].join(" ").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                        .unwrap_or_default();
                    for f in &by {
                        if !soql_ident_ok(f) {
                            return Err(format!("timechart : champ invalide : {f}"));
                        }
                    }
                    if by.is_empty() {
                        sql = format!("SELECT (ts/{span})*{span} AS bucket,{aggsql} AS {} FROM ({sql}) GROUP BY bucket ORDER BY bucket", soql_qid(&alias));
                        ocols = vec!["bucket".to_string(), alias.to_string()];
                    } else {
                        let sel: Vec<String> = by.iter().map(|f| format!("{} AS {}", soql_field(f, &ocols), soql_qid(f))).collect();
                        let bc = by.iter().map(|f| soql_qid(f)).collect::<Vec<_>>().join(",");
                        sql = format!("SELECT (ts/{span})*{span} AS bucket,{},{aggsql} AS {} FROM ({sql}) GROUP BY bucket,{bc} ORDER BY bucket", sel.join(","), soql_qid(&alias));
                        ocols = std::iter::once("bucket".to_string()).chain(by).chain(std::iter::once(alias.to_string())).collect();
                    }
                }
                "where" => {
                    let expr = toks[1..].join(" ");
                    if let Some((field, negate, vals)) = soql_parse_in(&expr) {
                        if !soql_ident_ok(&field) {
                            return Err(format!("where : champ invalide : {field}"));
                        }
                        let numeric = vals.iter().all(|v| soql_num(v));
                        let mut fexpr = soql_field(&field, &ocols);
                        let list = if numeric {
                            if fexpr.starts_with("json_extract") { fexpr = format!("CAST({fexpr} AS REAL)"); }
                            vals.join(",")
                        } else {
                            vals.iter().map(|v| format!("'{}'", soql_esc(v))).collect::<Vec<_>>().join(",")
                        };
                        sql = format!("SELECT * FROM ({sql}) WHERE {fexpr} {} ({list})", if negate { "NOT IN" } else { "IN" });
                        continue;
                    }
                    let mut split: Option<(&str, &str, &str)> = None;
                    for op in ["=~", ">=", "<=", "!=", "=", ">", "<"] {
                        if let Some(pos) = expr.find(op) {
                            split = Some((expr[..pos].trim(), op, expr[pos + op.len()..].trim()));
                            break;
                        }
                    }
                    let (field, op, valraw) = match split {
                        Some(x) => x,
                        None => return Err("where : 'champ op valeur' attendu (ex: count > 5 ou src_ip =~ \"^90\\.\")".into()),
                    };
                    let sqlop = match op {
                        "=" => "=", "!=" => "<>", ">" => ">", "<" => "<", ">=" => ">=", "<=" => "<=", "=~" => "REGEXP",
                        o => return Err(format!("where : opérateur invalide : {o}")),
                    };
                    let val = valraw.trim_matches('"');
                    if !soql_ident_ok(field) {
                        return Err(format!("where : champ invalide : {field}"));
                    }
                    let mut fexpr = soql_field(field, &ocols);
                    let cond = if soql_num(val) && sqlop != "REGEXP" {
                        if fexpr.starts_with("json_extract") { fexpr = format!("CAST({fexpr} AS REAL)"); }
                        format!("{fexpr} {sqlop} {val}")
                    } else {
                        format!("{fexpr} {sqlop} '{}'", soql_esc(val))
                    };
                    sql = format!("SELECT * FROM ({sql}) WHERE {cond}");
                }
                "sort" => {
                    let f = toks.get(1).copied().unwrap_or("");
                    let (field, dir) = match f.strip_prefix('-') {
                        Some(x) => (x, "DESC"),
                        None => (f, "ASC"),
                    };
                    if !soql_ident_ok(field) {
                        return Err(format!("sort : champ invalide : {field}"));
                    }
                    sql = format!("SELECT * FROM ({sql}) ORDER BY {} {dir}", soql_field(field, &ocols));
                }
                "head" | "limit" => {
                    let n: i64 = toks.get(1).copied().unwrap_or("20").parse().map_err(|_| "head/limit : nombre attendu".to_string())?;
                    sql = format!("SELECT * FROM ({sql}) LIMIT {n}");
                }
                "rex" => {
                    if toks.len() < 3 { return Err("rex : 'rex <champ> \"<motif à groupes nommés>\"' attendu".into()); }
                    let field = toks[1];
                    if !soql_ident_ok(field) { return Err(format!("rex : champ invalide : {field}")); }
                    let pat = toks[2..].join(" ");
                    let pat = pat.trim().trim_matches('"').trim_matches('\'');
                    if pat.is_empty() { return Err("rex : motif vide".into()); }
                    let gre = regex::Regex::new(r"\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>").unwrap();
                    let mut names: Vec<String> = Vec::new();
                    for c in gre.captures_iter(pat) {
                        let nm = c[1].to_string();
                        if soql_ident_ok(&nm) && !names.contains(&nm) { names.push(nm); }
                    }
                    if names.is_empty() { return Err("rex : aucun groupe nommé (?<nom>…) dans le motif".into()); }
                    let fexpr = soql_field(field, &ocols);
                    let pesc = soql_esc(pat);
                    let adds: Vec<String> = names.iter().map(|n| format!("re_cap({fexpr},'{pesc}','{n}') AS {}", soql_qid(n))).collect();
                    sql = format!("SELECT *,{} FROM ({sql})", adds.join(","));
                    for n in names { if !ocols.contains(&n) { ocols.push(n); } }
                }
                "fields" => {
                    let fields: Vec<String> = toks[1..].join(" ").split(',')
                        .map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                    for f in &fields {
                        if !soql_ident_ok(f) {
                            return Err(format!("fields : champ invalide : {f}"));
                        }
                    }
                    let sel: Vec<String> = fields.iter().map(|f| format!("{} AS {}", soql_field(f, &ocols), soql_qid(f))).collect();
                    sql = format!("SELECT {} FROM ({sql})", sel.join(","));
                    ocols = fields;
                }
                "table" => {
                    let raw = toks[1..].join(" ");
                    if raw.trim() != "*" {
                        let fields: Vec<String> = raw
                            .split(|c| c == ',' || c == ' ')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        for f in &fields {
                            if !soql_ident_ok(f) {
                                return Err(format!("table : champ invalide : {f}"));
                            }
                        }
                        if !fields.is_empty() {
                            let sel: Vec<String> = fields.iter().map(|f| format!("{} AS {}", soql_field(f, &ocols), soql_qid(f))).collect();
                            sql = format!("SELECT {} FROM ({sql})", sel.join(","));
                            ocols = fields;
                        }
                    }
                }
                "dedup" => {
                    let fields: Vec<String> = toks[1..].join(" ").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                    if fields.is_empty() {
                        return Err("dedup : champ(s) requis".into());
                    }
                    for f in &fields {
                        if !soql_ident_ok(f) {
                            return Err(format!("dedup : champ invalide : {f}"));
                        }
                    }
                    let gb: Vec<String> = fields.iter().map(|f| soql_field(f, &ocols)).collect();
                    sql = format!("SELECT * FROM ({sql}) GROUP BY {}", gb.join(","));
                }
                "top" | "rare" => {
                    let mut idx = 1;
                    let mut n = 10i64;
                    if let Some(t) = toks.get(1) {
                        if let Ok(v) = t.parse::<i64>() {
                            n = v;
                            idx = 2;
                        }
                    }
                    let field = toks.get(idx).copied().unwrap_or("");
                    if !soql_ident_ok(field) {
                        return Err(format!("{} : champ invalide : {field}", toks[0]));
                    }
                    let dir = if toks[0] == "top" { "DESC" } else { "ASC" };
                    let fexpr = soql_field(field, &ocols);
                    let qfield = soql_qid(field);
                    sql = format!("SELECT {fexpr} AS {qfield},COUNT(*) AS count FROM ({sql}) GROUP BY {qfield} ORDER BY count {dir} LIMIT {n}");
                    ocols = vec![field.to_string(), "count".to_string()];
                }
                "eventstats" => {
                    let (aggsql, alias) = soql_agg(toks.get(1).copied().unwrap_or("count"), &ocols)?;
                    let part = if let Some(bi) = toks.iter().position(|w| *w == "by") {
                        let fields: Vec<String> = toks[bi + 1..].join(" ").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                        for f in &fields {
                            if !soql_ident_ok(f) {
                                return Err(format!("eventstats : champ invalide : {f}"));
                            }
                        }
                        let pcols: Vec<String> = fields.iter().map(|f| soql_field(f, &ocols)).collect();
                        format!("PARTITION BY {}", pcols.join(","))
                    } else {
                        String::new()
                    };
                    sql = format!("SELECT *, {aggsql} OVER ({part}) AS {} FROM ({sql})", soql_qid(&alias));
                    ocols.push(alias.to_string());
                }
                "rate" => {
                    let partcols: Vec<String> = ocols.iter().filter(|c| *c != "ts" && *c != "value").map(|c| soql_qid(c)).collect();
                    let win = if partcols.is_empty() {
                        "ORDER BY ts".to_string()
                    } else {
                        format!("PARTITION BY {} ORDER BY ts", partcols.join(","))
                    };
                    sql = format!(
                        "SELECT *, CASE WHEN (value - LAG(value) OVER w) >= 0 AND (ts - LAG(ts) OVER w) > 0 \
                         THEN (value - LAG(value) OVER w)*1.0/(ts - LAG(ts) OVER w) ELSE NULL END AS rate \
                         FROM ({sql}) WINDOW w AS ({win})"
                    );
                    if !ocols.iter().any(|c| c == "rate") {
                        ocols.push("rate".to_string());
                    }
                }
                "eval" => {
                    let rest = stage.strip_prefix("eval").unwrap_or("").trim();
                    let (name, expr) = rest
                        .split_once('=')
                        .ok_or_else(|| "eval : 'eval champ = expression' attendu".to_string())?;
                    let name = name.trim();
                    if !soql_ident_ok(name) {
                        return Err(format!("eval : nom de champ invalide : {name}"));
                    }
                    let expr_sql = soql_expr_sql(expr.trim())?;
                    if expr_sql.trim().is_empty() {
                        return Err("eval : expression vide".into());
                    }
                    sql = format!("SELECT *, ({expr_sql}) AS {} FROM ({sql})", soql_qid(name));
                    if !ocols.iter().any(|c| c == name) {
                        ocols.push(name.to_string());
                    }
                }
                "append" => {
                    let inner = soql_bracket(stage)?;
                    let (sub_sql, sub_cols) = soql_compile(&inner, from, to, depth + 1)?;
                    let mut ucols = ocols.clone();
                    for c in &sub_cols {
                        if !ucols.iter().any(|x| x == c) {
                            ucols.push(c.clone());
                        }
                    }
                    let left = soql_proj(&ucols, &ocols);
                    let right = soql_proj(&ucols, &sub_cols);
                    sql = format!("{left} FROM ({sql}) UNION ALL {right} FROM ({sub_sql})");
                    ocols = ucols;
                }
                "join" => {
                    let after = stage.strip_prefix("join").unwrap_or("").trim_start();
                    let field = after.split(|c: char| c.is_whitespace() || c == '[').next().unwrap_or("").trim();
                    if !soql_ident_ok(field) {
                        return Err(format!("join : champ invalide : {field}"));
                    }
                    let inner = soql_bracket(stage)?;
                    let (sub_sql, sub_cols) = soql_compile(&inner, from, to, depth + 1)?;
                    if !ocols.iter().any(|c| c == field) || !sub_cols.iter().any(|c| c == field) {
                        return Err(format!("join : le champ '{field}' doit exister des deux côtés"));
                    }
                    sql = format!("SELECT * FROM ({sql}) LEFT JOIN ({sub_sql}) USING({})", soql_qid(field));
                    for c in sub_cols {
                        if !ocols.iter().any(|x| *x == c) {
                            ocols.push(c);
                        }
                    }
                }
                "mvexpand" => {
                    // OP 2.1 (PARSER PHASE 2) — miroir READ-ONLY de soql_compile (main.rs).
                    // NB : main.rs ayant été retiré, ce miroir est synchronisé sur le correctif core
                    // (garde json_valid : scalaire non-JSON -> '[]' -> 0 ligne, pas « malformed JSON »).
                    let field = toks.get(1).copied().unwrap_or("");
                    if !soql_ident_ok(field) {
                        return Err(format!("mvexpand : champ invalide : {field}"));
                    }
                    let arrexpr = soql_field(field, &ocols);
                    let mut sel: Vec<String> = Vec::new();
                    let mut new_ocols: Vec<String> = Vec::new();
                    let mut had = false;
                    for c in &ocols {
                        if c == field {
                            sel.push(format!("je.value AS {}", soql_qid(field)));
                            had = true;
                        } else {
                            sel.push(soql_qid(c));
                        }
                        new_ocols.push(c.clone());
                    }
                    if !had {
                        sel.push(format!("je.value AS {}", soql_qid(field)));
                        new_ocols.push(field.to_string());
                    }
                    sql = format!("SELECT {} FROM ({sql}), json_each(CASE WHEN json_valid({arrexpr}) THEN {arrexpr} ELSE '[]' END) je", sel.join(","));
                    ocols = new_ocols;
                }
                "rename" => {
                    // OP 3 — miroir INDÉPENDANT du `rename` de core (aucune couverture différentielle avant).
                    let raw = toks[1..].join(" ");
                    let mut pairs: Vec<(String, String)> = Vec::new();
                    for seg in raw.split(',') {
                        let parts: Vec<&str> = seg.split_whitespace().collect();
                        let (old, new) = match parts.as_slice() {
                            [o, kw, n] if kw.eq_ignore_ascii_case("as") => (*o, *n),
                            _ => return Err(format!("rename : 'a AS b' attendu, reçu : '{}'", seg.trim())),
                        };
                        if !soql_ident_ok(old) || !soql_ident_ok(new) {
                            return Err(format!("rename : identifiant invalide : {old} AS {new}"));
                        }
                        pairs.push((old.to_string(), new.to_string()));
                    }
                    if pairs.is_empty() {
                        return Err("rename : au moins une paire 'a AS b' requise".into());
                    }
                    let proj: Vec<String> = pairs.iter().map(|(o, n)| format!("{} AS {}", soql_field(o, &ocols), soql_qid(n))).collect();
                    sql = format!("SELECT *, {} FROM ({sql})", proj.join(", "));
                    for (_, n) in &pairs {
                        if !ocols.iter().any(|c| c == n) { ocols.push(n.clone()); }
                    }
                }
                "lookup" => {
                    // OP lookup — miroir INDÉPENDANT (les DEUX branches : avec/sans OUTPUT).
                    let name = toks.get(1).copied().unwrap_or("");
                    if !soql_ident_ok(name) {
                        return Err(format!("lookup : nom de table invalide : {name}"));
                    }
                    let keyfield = toks.get(2).copied().unwrap_or("");
                    if !soql_ident_ok(keyfield) {
                        return Err(format!("lookup : champ-clé invalide : {keyfield}"));
                    }
                    let out_cols: Vec<String> = match toks.iter().position(|w| w.eq_ignore_ascii_case("output")) {
                        Some(oi) => toks[oi + 1..]
                            .join(" ")
                            .split(|c| c == ',' || c == ' ')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect(),
                        None => Vec::new(),
                    };
                    for c in &out_cols {
                        if !soql_ident_ok(c) {
                            return Err(format!("lookup : colonne OUTPUT invalide : {c}"));
                        }
                    }
                    let keyexpr = soql_field(keyfield, &ocols);
                    let nameesc = soql_esc(name);
                    if out_cols.is_empty() {
                        sql = format!(
                            "SELECT base.*, lk.val AS {} FROM ({sql}) base LEFT JOIN lookup_kv lk ON lk.name='{nameesc}' AND lk.\"key\"={keyexpr}",
                            soql_qid(name)
                        );
                        if !ocols.iter().any(|c| c == name) {
                            ocols.push(name.to_string());
                        }
                    } else {
                        let adds: Vec<String> = out_cols
                            .iter()
                            .map(|c| format!("CASE WHEN json_valid(lk.val) THEN json_extract(lk.val,'$.{c}') END AS {}", soql_qid(c)))
                            .collect();
                        sql = format!(
                            "SELECT base.*, {} FROM ({sql}) base LEFT JOIN lookup_kv lk ON lk.name='{nameesc}' AND lk.\"key\"={keyexpr}",
                            adds.join(", ")
                        );
                        for c in out_cols {
                            if !ocols.iter().any(|x| *x == c) {
                                ocols.push(c);
                            }
                        }
                    }
                }
                other => return Err(format!("commande soql inconnue : '{other}'")),
            }
        }
        Ok((sql, ocols))
    }
}

// =================================================================================================
// LE BANC
// =================================================================================================

// from/to identiques des deux côtés -> les bornes `ts >= F`/`ts <= T` sont émises à l'identique
// (le banc isole les DIVERGENCES de résolution de champ/quoting/cast, pas le calage temporel).
const FROM: i64 = 1_719_000_000;
const TO: i64 = 1_719_500_000;

fn corpus() -> Vec<String> {
    let raw = include_str!("corpus_soql_coverage.txt");
    raw.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Résultat normalisé d'un compilo pour une requête : Ok(sql, colonnes) ou Err.
type Out = Result<(String, Vec<String>), String>;

fn plume_out(q: &str) -> Out {
    plume_ref::soql_compile(q, FROM, TO, 0)
}
fn core_out(q: &str) -> Out {
    compile_with_time(q, FROM, TO, &Schema::events()).map(|c| (c.sql, c.columns))
}

#[test]
fn differential_zero_unexpected_diff() {
    let corpus = corpus();
    let mut total = 0usize;
    let mut ok_match = 0usize;       // ok des 2 côtés, SQL + colonnes identiques
    let mut err_match = 0usize;      // err des 2 côtés (rejet symétrique)
    let mut unexpected: Vec<(String, String)> = Vec::new(); // (requête, raison)

    for q in &corpus {
        total += 1;
        let pr = plume_out(q);
        let cr = core_out(q);
        match (&pr, &cr) {
            (Ok((ps, pc)), Ok((cs, cc))) => {
                if ps != cs {
                    unexpected.push((q.clone(), format!("SQL diffère\n      PLUME: {ps}\n      CORE : {cs}")));
                } else if pc != cc {
                    unexpected.push((q.clone(), format!("colonnes diffèrent: plume={pc:?} core={cc:?}")));
                } else {
                    ok_match += 1;
                }
            }
            (Err(_), Err(_)) => err_match += 1,
            (Ok(_), Err(e)) => unexpected.push((q.clone(), format!("Plume OK mais core ERR: {e}"))),
            (Err(e), Ok(_)) => unexpected.push((q.clone(), format!("Plume ERR ({e}) mais core OK"))),
        }
    }

    eprintln!("\n==================== BANC DIFFÉRENTIEL SOQL (core[events] vs Plume) ====================");
    eprintln!("corpus            : {total} requêtes (panels + règles livrés + purple/blindspot + couverture)");
    eprintln!("ok identiques     : {ok_match}");
    eprintln!("err symétriques   : {err_match}");
    eprintln!("diffs INTENTIONNELS whitelistés : 0  (join-mitre GATÉ off pour events ; quoting/json-agg/no-cast = parité, pas un écart)");
    eprintln!("diffs INATTENDUS  : {}  (doit être 0 pour basculer)", unexpected.len());
    if !unexpected.is_empty() {
        eprintln!("\n--- DIFFS INATTENDUS (BLOQUANTS) ---");
        for (q, why) in &unexpected {
            eprintln!("  [{q}]\n    -> {why}");
        }
    }
    eprintln!("=======================================================================================\n");

    assert!(
        unexpected.is_empty(),
        "{} diff(s) inattendu(s) -> NE PAS BASCULER (cf. rapport ci-dessus)",
        unexpected.len()
    );
}

/// Échantillon lisible : imprime le SQL Plume vs core sur 3 requêtes clés (toujours vert tant que
/// `differential_zero_unexpected_diff` l'est ; sert de preuve visuelle dans le rapport).
#[test]
fn sample_key_queries_print() {
    let keys = [
        "search source=cloudflare | stats dc(vhost) by src_ip | where dc > 3 | stats count",
        "search source=ufw | stats dc(dport) by src_ip | where dc > 15 | stats count",
        "search source=rbac-audit | where severity>=3 | sort -severity | table subject,kind,role,scope,ns,risk",
    ];
    for q in keys {
        let p = plume_out(q).unwrap().0;
        let c = core_out(q).unwrap().0;
        eprintln!("\nREQUÊTE: {q}\n  PLUME: {p}\n  CORE : {c}\n  ÉGAL : {}", p == c);
        assert_eq!(p, c, "écart sur requête clé : {q}");
    }
}

/// DIVERGENCE 4 (gate) : la spécialisation purple `join mitre` EXISTE mais est OPT-IN par le schéma.
/// Sur `events` -> `USING(mitre)` (= Plume). Sur un schéma à `mitre_rollup_join=true` (Forge/purple)
/// -> rollup parent `ON CASE ...`. C'est l'unique divergence INTENTIONNELLE, gatée, donc absente du
/// chemin prod events (0 diff dans le banc) et démontrée ici comme atteignable hors-events.
#[test]
fn join_mitre_divergence_is_gated_opt_in() {
    let q = "search | stats count by mitre | join mitre [search source=x | stats count by mitre]";

    // events : parité Plume (USING brut), AUCUN rollup.
    let ev = compile_with_time(q, FROM, TO, &Schema::events()).unwrap().sql;
    assert!(ev.contains("USING(\"mitre\")"), "events doit rester USING : {ev}");
    assert!(!ev.contains("instr(l.mitre"), "events ne doit PAS rouler le rollup : {ev}");
    assert_eq!(ev, plume_out(q).unwrap().0, "events doit être byte-identique à Plume");

    // schéma purple (mitre_rollup_join=true) : rollup parent activé -> divergence intentionnelle visible.
    let mut purple = Schema::events();
    purple.mitre_rollup_join = true;
    let pu = compile_with_time(q, FROM, TO, &purple).unwrap().sql;
    assert!(pu.contains("instr(l.mitre,'.')"), "purple doit rouler le rollup gauche : {pu}");
    assert!(pu.contains("instr(r.mitre,'.')"), "purple doit rouler le rollup droit : {pu}");
    assert!(!pu.contains("USING(\"mitre\")"), "purple ne doit PAS faire un USING brut : {pu}");
    // ANCRAGE EXACT de l'assemblage rollup (Dialect::mitre_parent + gluing `{l}={r}`). Le chemin
    // rollup ATT&CK est GATÉ off pour `events()` -> INATTEIGNABLE par le banc différentiel (corpus
    // events-only) ; on le fige ICI en littéral pour qu'une évolution symétrique du fragment
    // `mitre_parent` (nouveau backend / « amélioration ») casse ce test avant de dériver en silence.
    assert!(pu.starts_with("SELECT l.*,r.* FROM ("), "forme de jointure purple dérivée : {pu}");
    assert!(pu.ends_with(
        ") l LEFT JOIN (SELECT json_extract(fields,'$.mitre') AS \"mitre\",COUNT(*) AS \"count\" \
         FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event \
         WHERE \"source\" = 'x' AND ts >= 1719000000 AND ts <= 1719500000) GROUP BY \"mitre\") r \
         ON CASE WHEN instr(l.mitre,'.')>0 THEN UPPER(substr(l.mitre,1,instr(l.mitre,'.')-1)) ELSE UPPER(l.mitre) END\
         =CASE WHEN instr(r.mitre,'.')>0 THEN UPPER(substr(r.mitre,1,instr(r.mitre,'.')-1)) ELSE UPPER(r.mitre) END"
    ), "assemblage rollup purple dérivé du golden : {pu}");
}

// =================================================================================================
// GATE DU DIALECT (readiness pivot « pluggable store »).
//
// Le compilateur soql émet désormais ses FRAGMENTS SQL variables (accès JSON, cast, bucketing, agrégat-
// liste, rollup ATT&CK, LIKE de terme libre) via `Schema.dialect` (`SqliteDialect`, unique backend). Ces
// deux tests figent la sortie du Dialect en CHAÎNES GOLDEN LITTÉRALES pré-refactor.
//
// PORTÉE DE LA GARANTIE (à lire honnêtement) : pour tout FRAGMENT ATTEIGNABLE par le corpus events, le
// banc `differential_zero_unexpected_diff` (core-via-Dialect == miroir INDÉPENDANT `plume_ref`, byte-à-
// byte) est l'oracle FORT — il attrape toute édition unilatérale de core. Le corpus exerce désormais AUSSI
// les fragments jadis hors-banc : `group_concat_bounded` (values/list), `json_extract(labels,…)` des
// métriques, `like_contains`, in/not-in+glue, formes substituées `__OPERATOR_EXCL__`/`__SELF_EXCL__`
// (`<>`/`NOT LIKE`), `rename`, `lookup` (2 branches). Le SEUL fragment INATTEIGNABLE par le corpus reste le
// rollup ATT&CK parent (`mitre_parent`), GATÉ off pour `events()` : il est ancré par un GOLDEN littéral
// (fragment figé dans `sqlite_dialect_fragments_are_frozen` + assemblage figé dans
// `join_mitre_divergence_is_gated_opt_in`), pas par le différentiel. C'est le différentiel (oracle
// indépendant) qui ferme ce trou pour tout ce que le corpus atteint. Ensemble, ils
// prouvent que le Dialect n'a rien changé au SQL émis SUR CES SURFACES, et cassent AVANT une détection prod.
// =================================================================================================

#[test]
fn sqlite_dialect_fragments_are_frozen() {
    // Chaque méthode du SPI renvoie EXACTEMENT le fragment SQL legacy (golden littéral pré-refactor).
    let d = SqliteDialect;
    assert_eq!(d.json_extract("fields", "user"), "json_extract(fields,'$.user')");
    assert_eq!(d.json_extract("labels", "job"), "json_extract(labels,'$.job')");
    assert_eq!(d.json_extract("lk.val", "country"), "json_extract(lk.val,'$.country')");
    assert_eq!(
        d.cast_real("json_extract(fields,'$.dport')"),
        "CAST(json_extract(fields,'$.dport') AS REAL)"
    );
    assert_eq!(d.time_bucket("ts", 3600), "(ts/3600)*3600");
    assert_eq!(d.time_bucket("ts", 86400), "(ts/86400)*86400");
    assert_eq!(
        d.group_concat_bounded("json_extract(fields,'$.user')", true, 4096),
        "substr(GROUP_CONCAT(DISTINCT json_extract(fields,'$.user')),1,4096)"
    );
    assert_eq!(
        d.group_concat_bounded("\"title\"", false, 4096),
        "substr(GROUP_CONCAT(\"title\"),1,4096)"
    );
    assert_eq!(
        d.mitre_parent("l.mitre"),
        "CASE WHEN instr(l.mitre,'.')>0 THEN UPPER(substr(l.mitre,1,instr(l.mitre,'.')-1)) ELSE UPPER(l.mitre) END"
    );
    assert_eq!(d.like_contains("message", "brute"), "message LIKE '%brute%'");
    // Quoting / échappement : le SPI expose ces primitives ; SqliteDialect délègue à soql_qid / soql_esc.
    assert_eq!(d.quote_ident("order"), "\"order\"");
    assert_eq!(d.escape_literal("O'Brien"), "O''Brien");
}

#[test]
fn dialect_emits_golden_full_sql() {
    // SQL compilé COMPLET figé pour un large éventail de requêtes (from/to = 0 -> pas de borne ts, goldens
    // lisibles). Ces chaînes sont la RÉFÉRENCE PRÉ-REFACTOR ; elles exercent chaque fragment du Dialect.
    let cases: &[(&str, &str)] = &[
        // filtre colonne réelle (quoting)
        ("search source=sshd",
         "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE \"source\" = 'sshd'"),
        // champ JSON numérique NON indexé -> CAST REAL (Dialect::cast_real + json_extract)
        ("search dport=443",
         "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE CAST(json_extract(fields,'$.dport') AS REAL) = 443"),
        // champ JSON INDEXÉ (HOT_FIELDS) -> forme canonique SANS cast
        ("search verb=5",
         "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE json_extract(fields,'$.verb') = 5"),
        // stats dc(champ JSON) by colonne réelle
        ("search source=cloudflare | stats dc(vhost) by src_ip",
         "SELECT \"src_ip\" AS \"src_ip\",COUNT(DISTINCT json_extract(fields,'$.vhost')) AS \"dc\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE \"source\" = 'cloudflare') GROUP BY \"src_ip\""),
        // agrégat-liste borné DISTINCT (Dialect::group_concat_bounded, distinct=true)
        ("search | stats values(user) by src_ip",
         "SELECT \"src_ip\" AS \"src_ip\",substr(GROUP_CONCAT(DISTINCT json_extract(fields,'$.user')),1,4096) AS \"values\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY \"src_ip\""),
        // agrégat-liste borné NON distinct (distinct=false)
        ("search | stats list(user) by src_ip",
         "SELECT \"src_ip\" AS \"src_ip\",substr(GROUP_CONCAT(json_extract(fields,'$.user')),1,4096) AS \"list\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY \"src_ip\""),
        // timechart : bucket temporel (Dialect::time_bucket)
        ("search | timechart span=1h count by source",
         "SELECT (ts/3600)*3600 AS bucket,\"source\" AS \"source\",COUNT(*) AS \"count\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY bucket,\"source\" ORDER BY bucket"),
        // NOT IN sur champ JSON textuel
        ("search user not in (root,ubuntu)",
         "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE json_extract(fields,'$.user') NOT IN ('root','ubuntu')"),
        // IN numérique sur champ JSON non indexé -> CAST REAL
        ("search dport in (80,443)",
         "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE CAST(json_extract(fields,'$.dport') AS REAL) IN (80,443)"),
        // termes libres -> message LIKE '%..%' (Dialect::like_contains)
        ("search brute force login",
         "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%brute%' AND message LIKE '%force%' AND message LIKE '%login%'"),
        // mvexpand : json_each + garde json_valid (arrexpr résolu via Dialect::json_extract)
        ("search source=cloudflare | mvexpand ips",
         "SELECT \"ts\",\"host\",\"source\",\"category\",\"severity\",\"src_ip\",\"dst_ip\",\"url\",\"xff\",\"message\",\"fields\",je.value AS \"ips\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE \"source\" = 'cloudflare'), json_each(CASE WHEN json_valid(json_extract(fields,'$.ips')) THEN json_extract(fields,'$.ips') ELSE '[]' END) je"),
        // lookup : LEFT JOIN + colonnes OUTPUT via Dialect::json_extract('lk.val', c)
        ("search source=web | lookup geoip src_ip OUTPUT country,asn",
         "SELECT base.*, CASE WHEN json_valid(lk.val) THEN json_extract(lk.val,'$.country') END AS \"country\", CASE WHEN json_valid(lk.val) THEN json_extract(lk.val,'$.asn') END AS \"asn\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE \"source\" = 'web') base LEFT JOIN lookup_kv lk ON lk.name='geoip' AND lk.\"key\"=\"src_ip\""),
        // join mitre sur events -> USING brut (parité Plume : rollup parent GATÉ off)
        ("search | stats count by mitre | join mitre [search source=x | stats count by mitre]",
         "SELECT * FROM (SELECT json_extract(fields,'$.mitre') AS \"mitre\",COUNT(*) AS \"count\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY \"mitre\") LEFT JOIN (SELECT json_extract(fields,'$.mitre') AS \"mitre\",COUNT(*) AS \"count\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE \"source\" = 'x') GROUP BY \"mitre\") USING(\"mitre\")"),
        // where numérique sur champ JSON -> CAST REAL (Dialect::cast_real)
        ("search | where dport>=443",
         "SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) WHERE CAST(json_extract(fields,'$.dport') AS REAL) >= 443"),
        // rename : colonne réelle -> alias (OP 3 — AUCUN golden avant ce lot)
        ("search source=web | rename src_ip AS client",
         "SELECT *, \"src_ip\" AS \"client\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE \"source\" = 'web')"),
        // rename : multi-paires dont champ JSON (json_extract) -> alias
        ("search source=web | rename vhost AS host_header, ua AS agent",
         "SELECT *, json_extract(fields,'$.vhost') AS \"host_header\", json_extract(fields,'$.ua') AS \"agent\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE \"source\" = 'web')"),
        // lookup : branche SANS OUTPUT (val JSON entier sous alias = nom du lookup) — non figée avant
        ("search source=web | lookup geoip src_ip",
         "SELECT base.*, lk.val AS \"geoip\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE \"source\" = 'web') base LEFT JOIN lookup_kv lk ON lk.name='geoip' AND lk.\"key\"=\"src_ip\""),
        // métrique AVEC labels : filtre `label=val` + `by <label>` via Dialect::json_extract(labels,…) — 0 couverture avant
        ("metric http_requests_total job=api by code",
         "SELECT ts,host,value,json_extract(labels,'$.code') AS \"code\" FROM metric WHERE name='http_requests_total' AND json_extract(labels,'$.job')='api' UNION ALL SELECT ts,host,avg AS value,json_extract(labels,'$.code') AS \"code\" FROM metric_rollup WHERE name='http_requests_total' AND json_extract(labels,'$.job')='api' ORDER BY ts"),
        // mvexpand : champ RÉEL remplacé IN PLACE + garde json_valid sur scalaire (variante du cas JSON)
        ("search source=web | mvexpand src_ip",
         "SELECT \"ts\",\"host\",\"source\",\"category\",\"severity\",je.value AS \"src_ip\",\"dst_ip\",\"url\",\"xff\",\"message\",\"fields\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE \"source\" = 'web'), json_each(CASE WHEN json_valid(\"src_ip\") THEN \"src_ip\" ELSE '[]' END) je"),
    ];
    for (q, golden) in cases {
        let got = compile(q, &Schema::events()).unwrap().sql;
        assert_eq!(&got, golden, "\nDialect a dérivé du golden pour: {q}\n  GOLDEN: {golden}\n  ÉMIS  : {got}");
    }
}
