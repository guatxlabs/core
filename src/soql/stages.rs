//! Compilateurs PAR ÉTAPE — chaque `compile_<stage>` porte VERBATIM l'ancien bras de `match`.
//!
//! Extrait mécaniquement de `soql.rs` (découpage en sous-modules) : PUR DÉPLACEMENT, aucune
//! ligne de logique/SQL modifiée — seules des visibilités privées ont été relevées à `pub(crate)`
//! pour rester joignables depuis le module parent. Comportement byte-identique (cf. `tests/plume_parity.rs`).

use super::*;

// ---------------------------------------------------------------------------------------------
// Compilateurs PAR ÉTAPE. Chaque `compile_<stage>` porte VERBATIM le corps de l'ancien bras de
// `match` de `compile_depth` : il reçoit le `sql`/`ocols` courants PAR VALEUR et renvoie la paire
// mise à jour. `compile_depth` (plus bas) n'est plus qu'un DISPATCHER sur le nom d'étape. Aucune
// émission n'a changé (invariant prouvé par `tests/plume_parity.rs`).
// ---------------------------------------------------------------------------------------------

pub(crate) fn compile_stats(toks: &[&str], mut sql: String, mut ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    let (aggsql, alias) = soql_agg(toks.get(1).copied().unwrap_or("count"), &ocols, jf, d)?;
    if let Some(bi) = toks.iter().position(|w| *w == "by") {
        let (fields, sel, gcols) = by_fields(&toks[bi + 1..].join(" "), "", &ocols, jf, d)?;
        sql = format!("SELECT {},{aggsql} AS {} FROM ({sql}) GROUP BY {gcols}", sel.join(","), soql_qid(&alias));
        ocols = fields;
        ocols.push(alias.to_string());
    } else {
        sql = format!("SELECT {aggsql} AS {} FROM ({sql})", soql_qid(&alias));
        ocols = vec![alias.to_string()];
    }
    Ok((sql, ocols))
}

pub(crate) fn compile_timechart(toks: &[&str], mut sql: String, mut ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect, from: i64, to: i64) -> Result<(String, Vec<String>), String> {
    let byi = toks.iter().position(|w| *w == "by");
    let head_end = byi.unwrap_or(toks.len());
    let mut span = 0i64;
    let mut aggtok = "count";
    for t in &toks[1..head_end] {
        if let Some(s) = t.strip_prefix("span=") {
            span = soql_dur(s)?;
        } else if t.contains('=') {
            // S1 — FAIL-CLOSED. Seul le préfixe EXACT `span=` était reconnu ; tout autre jeton CONTENANT
            // `=` était ignoré sans un mot, puis `if span <= 0` substituait le bucket automatique — la
            // requête ne mesurait alors PAS la fenêtre demandée. Mesuré : `spans=…`, `SPAN=1h`,
            // `span =1h` compilaient tous les trois avec `(ts/900)*900`. C'est la substitution
            // silencieuse que S1 dit fermer, atteignable sans aucun débordement ; on refuse, comme
            // `metric` refuse un jeton `k=v` inconnu.
            return Err(format!(
                "timechart : option inconnue : {t} (seul `span=<durée>` est supporté, ex: span=1h)"
            ));
        } else {
            aggtok = t;
        }
    }
    if span <= 0 {
        let range = if to > from && from > 0 { to - from } else { 86400 };
        let raw = (range / 120).max(60);
        let steps = [60i64, 300, 900, 1800, 3600, 7200, 14400, 43200, 86400, 604800];
        span = *steps.iter().find(|&&s| s >= raw).unwrap_or(&604800);
    }
    let (aggsql, alias) = soql_agg(aggtok, &ocols, jf, d)?;
    let (by, sel, bc) = match byi {
        Some(bi) => by_fields(&toks[bi + 1..].join(" "), "timechart : ", &ocols, jf, d)?,
        None => (Vec::new(), Vec::new(), String::new()),
    };
    let bucket = d.time_bucket("ts", span); // (ts/span)*span — troncature au bucket (Dialect)
    if by.is_empty() {
        sql = format!("SELECT {bucket} AS bucket,{aggsql} AS {} FROM ({sql}) GROUP BY bucket ORDER BY bucket", soql_qid(&alias));
        ocols = vec!["bucket".to_string(), alias.to_string()];
    } else {
        sql = format!("SELECT {bucket} AS bucket,{},{aggsql} AS {} FROM ({sql}) GROUP BY bucket,{bc} ORDER BY bucket", sel.join(","), soql_qid(&alias));
        ocols = std::iter::once("bucket".to_string()).chain(by).chain(std::iter::once(alias.to_string())).collect();
    }
    Ok((sql, ocols))
}

pub(crate) fn compile_where(toks: &[&str], mut sql: String, ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    let expr = toks[1..].join(" ");
    // OP 2 (`in` / `not in`) dans `where` : résout le champ via `soql_field` (colonne réelle /
    // alias de stage / json_extract), CAST REAL si liste numérique sur champ JSON (même règle
    // que le `where` scalaire). Échappe les valeurs textuelles.
    if let Some((field, negate, vals)) = in_clause_whole(expr.trim()) {
        if !soql_ident_ok(&field) {
            return Err(format!("where : champ invalide : {field}"));
        }
        let numeric = vals.iter().all(|v| soql_num(v));
        let mut fexpr = soql_field(&field, &ocols, jf, d);
        let list = if numeric {
            if fexpr.starts_with("json_extract") { fexpr = d.cast_real(&fexpr); }
            vals.join(",")
        } else {
            vals.iter().map(|v| format!("'{}'", d.escape_literal(v))).collect::<Vec<_>>().join(",")
        };
        sql = format!("SELECT * FROM ({sql}) WHERE {fexpr} {} ({list})", if negate { "NOT IN" } else { "IN" });
        return Ok((sql, ocols));
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
    let mut fexpr = soql_field(field, &ocols, jf, d);
    let cond = if soql_num(val) && sqlop != "REGEXP" {
        if fexpr.starts_with("json_extract") { fexpr = d.cast_real(&fexpr); }
        format!("{fexpr} {sqlop} {val}")
    } else {
        format!("{fexpr} {sqlop} '{}'", d.escape_literal(val))
    };
    sql = format!("SELECT * FROM ({sql}) WHERE {cond}");
    Ok((sql, ocols))
}

pub(crate) fn compile_sort(toks: &[&str], mut sql: String, ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    let f = toks.get(1).copied().unwrap_or("");
    let (field, dir) = match f.strip_prefix('-') {
        Some(x) => (x, "DESC"),
        None => (f, "ASC"),
    };
    if !soql_ident_ok(field) {
        return Err(format!("sort : champ invalide : {field}"));
    }
    sql = format!("SELECT * FROM ({sql}) ORDER BY {} {dir}", soql_field(field, &ocols, jf, d));
    Ok((sql, ocols))
}

pub(crate) fn compile_head(toks: &[&str], mut sql: String, ocols: Vec<String>) -> Result<(String, Vec<String>), String> {
    let n: i64 = toks.get(1).copied().unwrap_or("20").parse().map_err(|_| "head/limit : nombre attendu".to_string())?;
    // CORE-3 : `LIMIT -N` -> SQLite interprète un LIMIT NÉGATIF comme ILLIMITÉ (aucune borne) -> un `head -5`
    // renverrait TOUTES les lignes au lieu d'en tronquer. On REJETTE le négatif (`head`/`limit` négatif n'a
    // pas de sens). `0` reste valide (`LIMIT 0` = 0 ligne, déjà sûr).
    if n < 0 {
        return Err(format!("head/limit : nombre négatif interdit : {n}"));
    }
    sql = format!("SELECT * FROM ({sql}) LIMIT {n}");
    Ok((sql, ocols))
}

pub(crate) fn compile_rex(toks: &[&str], mut sql: String, mut ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
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
    let fexpr = soql_field(field, &ocols, jf, d);
    let pesc = d.escape_literal(pat);
    let adds: Vec<String> = names.iter().map(|n| format!("re_cap({fexpr},'{pesc}','{n}') AS {}", soql_qid(n))).collect();
    sql = format!("SELECT *,{} FROM ({sql})", adds.join(","));
    for n in names { if !ocols.contains(&n) { ocols.push(n); } }
    Ok((sql, ocols))
}

pub(crate) fn compile_fields(toks: &[&str], mut sql: String, mut ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    // MÊME PORTE que `by`/`dedup` : liste séparée par des virgules seules, aucune entrée jetée.
    // Mesuré avant : `search | fields` et `search | fields ,` émettaient `SELECT  FROM (…)` — du SQL
    // syntaxiquement invalide envoyé au store — et `fields ,src_ip` jetait l'entrée vide sans un mot.
    let fields: Vec<String> = FieldList::commas(&toks[1..].join(" "))
        .map_err(|bad| format!("fields : champ invalide : {bad}"))?
        .into_vec();
    let sel: Vec<String> = fields.iter().map(|f| format!("{} AS {}", soql_field(f, &ocols, jf, d), soql_qid(f))).collect();
    sql = format!("SELECT {} FROM ({sql})", sel.join(","));
    ocols = fields;
    Ok((sql, ocols))
}

pub(crate) fn compile_table(toks: &[&str], mut sql: String, mut ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    let raw = toks[1..].join(" ");
    // `table *` ET `table` NU sont des PASSE-PLAT DÉLIBÉRÉS (contrat existant, épinglé par
    // `phaseb_table_star_and_bare_are_not_narrowing` : ils ne restreignent pas la projection, donc
    // l'élagage de `message` ne s'applique pas). Ils ne passent pas par la porte : il n'y a pas de
    // liste à valider. Tout le reste y passe.
    if !raw.trim().is_empty() && raw.trim() != "*" {
        // MÊME PORTE, AUTRE GRAMMAIRE : ici le BLANC est un séparateur (`table a b` est légitime,
        // mesuré), donc une suite de séparateurs est indiscernable d'un seul et se réduit. Ce que la
        // porte ferme quand même : une liste qui ne contient QUE des séparateurs (`table ,`) ne peut
        // plus s'évaporer en silence — elle est refusée, comme partout ailleurs.
        let fields: Vec<String> = FieldList::commas_or_blanks(&raw)
            .map_err(|bad| format!("table : champ invalide : {bad}"))?
            .into_vec();
        let sel: Vec<String> = fields.iter().map(|f| format!("{} AS {}", soql_field(f, &ocols, jf, d), soql_qid(f))).collect();
        sql = format!("SELECT {} FROM ({sql})", sel.join(","));
        ocols = fields;
    }
    Ok((sql, ocols))
}

pub(crate) fn compile_rename(toks: &[&str], mut sql: String, mut ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    // OP 3 : `rename a AS b[, c AS d]` -> `SELECT *, <a> AS "b", <c> AS "d" FROM (sql)`.
    // ADDITIF (le `*` conserve les colonnes existantes ; on AJOUTE les alias). `a` est résolu
    // via `soql_field` (colonne réelle / alias de stage -> quoté ; champ JSON -> json_extract)
    // pour qu'un renommage de clé JSON soit valide. Utile pour aligner les clés avant join.
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
    let proj: Vec<String> = pairs.iter().map(|(o, n)| format!("{} AS {}", soql_field(o, &ocols, jf, d), soql_qid(n))).collect();
    sql = format!("SELECT *, {} FROM ({sql})", proj.join(", "));
    for (_, n) in &pairs {
        if !ocols.iter().any(|c| c == n) { ocols.push(n.clone()); }
    }
    Ok((sql, ocols))
}

pub(crate) fn compile_dedup(toks: &[&str], mut sql: String, ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    // MÊME PORTE que `by`/`fields` (mesuré avant : `dedup ,src_ip` jetait l'entrée vide en silence ;
    // la liste vide était déjà refusée ici, elle l'est maintenant par la porte, comme partout).
    let fields: Vec<String> = FieldList::commas(&toks[1..].join(" "))
        .map_err(|bad| format!("dedup : champ invalide : {bad}"))?
        .into_vec();
    let gb: Vec<String> = fields.iter().map(|f| soql_field(f, &ocols, jf, d)).collect();
    sql = format!("SELECT * FROM ({sql}) GROUP BY {}", gb.join(","));
    Ok((sql, ocols))
}

pub(crate) fn compile_top(toks: &[&str], mut sql: String, mut ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
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
    let fexpr = soql_field(field, &ocols, jf, d);
    let qfield = soql_qid(field);
    sql = format!("SELECT {fexpr} AS {qfield},COUNT(*) AS count FROM ({sql}) GROUP BY {qfield} ORDER BY count {dir} LIMIT {n}");
    ocols = vec![field.to_string(), "count".to_string()];
    Ok((sql, ocols))
}

pub(crate) fn compile_eventstats(toks: &[&str], mut sql: String, mut ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    let (aggsql, alias) = soql_agg(toks.get(1).copied().unwrap_or("count"), &ocols, jf, d)?;
    // Parse+validation `by` partagé (préfixe d'erreur « eventstats : ») -> noms de champ de partition.
    let fields: Vec<String> = if let Some(bi) = toks.iter().position(|w| *w == "by") {
        by_fields(&toks[bi + 1..].join(" "), "eventstats : ", &ocols, jf, d)?.0
    } else {
        Vec::new()
    };
    // CORE-2 : `values`/`list` compilent en `substr(GROUP_CONCAT(...),1,4096)` — INEMPLOYABLE en fonction
    // fenêtre (SQLite : « substr() may not be used as a window function » ; et `GROUP_CONCAT(DISTINCT …) OVER`
    // est refusé : « DISTINCT is not supported for window functions »). Le chemin `OVER (...)` produisait donc
    // du SQL INVALIDE -> règle MUETTE. On émet à la place une SOUS-REQUÊTE CORRÉLÉE par partition (sémantique
    // eventstats fidèle : l'agrégat de la partition est rattaché à CHAQUE ligne, sans replier les lignes). Les
    // agrégats fenêtrables (count/sum/avg/min/max/dc) gardent le chemin `OVER (...)` INCHANGÉ (parité stricte).
    if matches!(alias.as_str(), "values" | "list") {
        let where_c = if fields.is_empty() {
            // Pas de `by` : agrégat GLOBAL diffusé sur toutes les lignes (eventstats sans partition).
            String::new()
        } else {
            let conds: Vec<String> = fields
                .iter()
                .map(|f| {
                    let pi = soql_field_qual(f, &ocols, jf, d, "i");
                    let po = soql_field_qual(f, &ocols, jf, d, "o");
                    format!("{pi} IS {po}") // `IS` = égalité null-safe (partition NULL groupée, comme OVER)
                })
                .collect();
            format!(" WHERE {}", conds.join(" AND "))
        };
        sql = format!(
            "SELECT o.*, (SELECT {aggsql} FROM ({sql}) AS i{where_c}) AS {} FROM ({sql}) AS o",
            soql_qid(&alias)
        );
    } else {
        // eventstats construit un PARTITION BY à partir des `soql_field` (pas d'alias).
        let part = if fields.is_empty() {
            String::new()
        } else {
            let pcols: Vec<String> = fields.iter().map(|f| soql_field(f, &ocols, jf, d)).collect();
            format!("PARTITION BY {}", pcols.join(","))
        };
        sql = format!("SELECT *, {aggsql} OVER ({part}) AS {} FROM ({sql})", soql_qid(&alias));
    }
    ocols.push(alias.to_string());
    Ok((sql, ocols))
}

pub(crate) fn compile_rate(mut sql: String, mut ocols: Vec<String>) -> Result<(String, Vec<String>), String> {
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
    Ok((sql, ocols))
}

pub(crate) fn compile_eval(stage: &str, mut sql: String, mut ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    let rest = stage.strip_prefix("eval").unwrap_or("").trim();
    let (name, expr) = rest
        .split_once('=')
        .ok_or_else(|| "eval : 'eval champ = expression' attendu".to_string())?;
    let name = name.trim();
    if !soql_ident_ok(name) {
        return Err(format!("eval : nom de champ invalide : {name}"));
    }
    // FIELD FILTERS : passe `jf` + les colonnes vivantes (ocols AVANT l'ajout de l'alias) au compilateur d'expression
    // pour qu'une référence au SAC JSON (`fields`) soit caviardée (choke-point du masque), au lieu de copier
    // le blob brut dans la colonne aliasée.
    let expr_sql = soql_expr_sql(expr.trim(), jf, &ocols, d)?;
    if expr_sql.trim().is_empty() {
        return Err("eval : expression vide".into());
    }
    sql = format!("SELECT *, ({expr_sql}) AS {} FROM ({sql})", soql_qid(name));
    if !ocols.iter().any(|c| c == name) {
        ocols.push(name.to_string());
    }
    Ok((sql, ocols))
}

pub(crate) fn compile_append(stage: &str, mut sql: String, mut ocols: Vec<String>, from: i64, to: i64, depth: u32, schema: &Schema) -> Result<(String, Vec<String>), String> {
    let inner = soql_bracket(stage)?;
    let (sub_sql, sub_cols) = compile_depth(&inner, from, to, depth + 1, schema)?;
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
    Ok((sql, ocols))
}

pub(crate) fn compile_join(stage: &str, mut sql: String, mut ocols: Vec<String>, from: i64, to: i64, depth: u32, schema: &Schema) -> Result<(String, Vec<String>), String> {
    let d = schema.dialect;
    let after = stage.strip_prefix("join").unwrap_or("").trim_start();
    let field = after.split(|c: char| c.is_whitespace() || c == '[').next().unwrap_or("").trim();
    if !soql_ident_ok(field) {
        return Err(format!("join : champ invalide : {field}"));
    }
    let inner = soql_bracket(stage)?;
    let (sub_sql, sub_cols) = compile_depth(&inner, from, to, depth + 1, schema)?;
    if !ocols.iter().any(|c| c == field) || !sub_cols.iter().any(|c| c == field) {
        return Err(format!("join : le champ '{field}' doit exister des deux côtés"));
    }
    if field == PURPLE_JOIN_FIELD && schema.mitre_rollup_join {
        // DIVERGENCE 4 (gatée par `schema.mitre_rollup_join`). Contrat purple : la corrélation
        // ATT&CK se fait au niveau de la technique PARENTE. On JOINT sur le rollup des DEUX côtés
        // (sous-technique -> parente). PLUME (`events()`) garde `USING` (parité stricte) : ce bloc
        // n'est atteint qu'en mode purple opt-in.
        let l = d.mitre_parent(&format!("l.{field}"));
        let r = d.mitre_parent(&format!("r.{field}"));
        sql = format!(
            "SELECT l.*,r.* FROM ({sql}) l LEFT JOIN ({sub_sql}) r ON {l}={r}"
        );
    } else {
        sql = format!("SELECT * FROM ({sql}) LEFT JOIN ({sub_sql}) USING({})", soql_qid(field));
    }
    for c in sub_cols {
        if !ocols.iter().any(|x| *x == c) {
            ocols.push(c);
        }
    }
    Ok((sql, ocols))
}

pub(crate) fn compile_mvexpand(toks: &[&str], mut sql: String, mut ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    // OP 2.1 : `mvexpand f` éclate un TABLEAU JSON du champ `f` en UNE ligne par élément via
    // json_each ; garde `json_valid(...) ELSE '[]'` -> un champ absent/scalaire non-JSON donne
    // ZÉRO ligne au lieu d'une erreur SQLite qui avorterait la requête. `f` validé `soql_ident_ok`.
    let field = toks.get(1).copied().unwrap_or("");
    if !soql_ident_ok(field) {
        return Err(format!("mvexpand : champ invalide : {field}"));
    }
    let arrexpr = soql_field(field, &ocols, jf, d); // champ réel quoté OU json_extract(jf,'$.f')
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
    Ok((sql, ocols))
}

pub(crate) fn compile_lookup(toks: &[&str], mut sql: String, mut ocols: Vec<String>, jf: Option<&str>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    // OP : ENRICHISSEMENT par table de référence `lookup_kv`. `lookup <name> <keyfield> [OUTPUT
    // col1,col2]` -> LEFT JOIN pour AJOUTER des colonnes extraites du JSON `val`. Garde `json_valid`
    // -> `val` malformé/NULL donne NULL et non une erreur. `name`/`keyfield`/OUTPUT validés `soql_ident_ok`.
    let name = toks.get(1).copied().unwrap_or("");
    if !soql_ident_ok(name) {
        return Err(format!("lookup : nom de table invalide : {name}"));
    }
    let keyfield = toks.get(2).copied().unwrap_or("");
    if !soql_ident_ok(keyfield) {
        return Err(format!("lookup : champ-clé invalide : {keyfield}"));
    }
    // OUTPUT col1,col2 (OPTIONNEL — mais une fois TAPÉ, c'est une DEMANDE EXPLICITE). MÊME PORTE que
    // `by`/`fields`/`dedup`/`table`, et MÊME GRAMMAIRE que `table` : le BLANC y est aussi séparateur
    // (`OUTPUT a b` == `OUTPUT a,b`, mesuré) -> `commas_or_blanks`. Mesuré AVANT (identique de v0.2.0 à
    // 08a6593) : `OUTPUT` nu et `OUTPUT ,` retombaient sur la branche « OUTPUT absent » et la projection
    // DEMANDÉE s'évaporait sans un mot ; `OUTPUT ,a` jetait l'entrée vide en silence. La porte valide
    // aussi chaque entrée (`soql_ident_ok`), donc il n'y a plus de 2e contrôle à écrire ici.
    // `lookup` SANS `OUTPUT` reste le passe-plat documenté (expose `val` brut) : rien n'a été demandé.
    let out_cols: Vec<String> = match toks.iter().position(|w| w.eq_ignore_ascii_case("output")) {
        Some(oi) => FieldList::commas_or_blanks(&toks[oi + 1..].join(" "))
            .map_err(|bad| format!("lookup : colonne OUTPUT invalide : {bad}"))?
            .into_vec(),
        None => Vec::new(),
    };
    let keyexpr = soql_field(keyfield, &ocols, jf, d);
    let nameesc = d.escape_literal(name);
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
            .map(|c| format!("CASE WHEN json_valid(lk.val) THEN {} END AS {}", d.json_extract("lk.val", c), soql_qid(c)))
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
    Ok((sql, ocols))
}
