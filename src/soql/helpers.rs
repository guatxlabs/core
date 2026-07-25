//! Helpers d'émission SOQL (schéma-indépendants — portés verbatim de Plume).
//!
//! Extrait mécaniquement de `soql.rs` (découpage en sous-modules) : PUR DÉPLACEMENT, aucune
//! ligne de logique/SQL modifiée — seules des visibilités privées ont été relevées à `pub(crate)`
//! pour rester joignables depuis le module parent. Comportement byte-identique (cf. `tests/plume_parity.rs`).

use super::*;

// ---------------------------------------------------------------------------------------------
// Helpers (schéma-indépendants — portés verbatim de Plume).
// ---------------------------------------------------------------------------------------------

/// Découpe un texte en jetons (espaces = séparateurs, sauf entre guillemets `"`). PUBLIC : la
/// route-rollup de Plume (`try_rollup_route`, qui reste côté daemon à la bascule) en dépend.
/// Sortie STRICTEMENT identique à l'historique : `soql_tokenize_marked` en est la source unique,
/// on n'en retire que le marqueur de guillemets.
pub fn soql_tokenize(s: &str) -> Vec<String> {
    let marked = soql_tokenize_marked(s);
    marked.into_iter().map(|(t, _)| t).collect()
}

/// Comme `soql_tokenize`, mais CONSERVE pour chaque jeton s'il a été construit avec des guillemets
/// (`true` dès qu'un `"` a été consommé pendant sa construction).
///
/// POURQUOI : `soql_tokenize` JETTE les guillemets, donc l'aval ne peut plus distinguer
/// `search "user-agent=curl"` (une PHRASE que l'analyste veut chercher telle quelle) de
/// `search user-agent=curl` (un nom de champ mal écrit). C'est la cause racine des refus abusifs
/// mesurés sur des phrases quotées légitimes. Le marqueur sert UNIQUEMENT à EXEMPTER un jeton quoté
/// de la garde de nom de champ (cf. `table_conds`) : il n'ouvre aucun chemin nouveau et ne change
/// aucune émission SQL.
pub(crate) fn soql_tokenize_marked(s: &str) -> Vec<(String, bool)> {
    let (mut out, mut cur, mut inq, mut quoted) = (Vec::new(), String::new(), false, false);
    for c in s.chars() {
        match c {
            '"' => {
                inq = !inq;
                quoted = true;
            }
            c if c.is_whitespace() && !inq => {
                if !cur.is_empty() {
                    out.push((std::mem::take(&mut cur), quoted));
                }
                quoted = false;
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push((cur, quoted));
    }
    out
}

pub(crate) fn soql_ident_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// TRUE si `s` a la FORME d'un nom de champ, c'est-à-dire si un jeton `s<op>valeur` PRÉTEND filtrer un
/// champ : commence par une lettre ASCII ou `_`, et ne contient que `[A-Za-z0-9_.-]`. Sert UNIQUEMENT à
/// distinguer un nom de champ MAL ÉCRIT (`x-forwarded-for`, `http.status` -> erreur explicite, cf.
/// `table_conds`) d'un VRAI terme libre (phrase quotée, horodatage `10:00:00`, chemin/URL) qui garde le
/// scan plein-texte. Un identifiant VALIDE (`soql_ident_ok`) est un sous-ensemble de cette forme.
pub(crate) fn soql_fieldish(s: &str) -> bool {
    let mut cs = s.chars();
    matches!(cs.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Échappe une valeur pour un littéral chaîne SQL (doublage des `'`). PUBLIC (cf. `soql_tokenize`).
pub fn soql_esc(s: &str) -> String {
    s.replace('\'', "''")
}

/// Quoting d'identifiant style SQLite : double-quote + doublage des `"` internes. PORTÉ DE PLUME
/// (DIVERGENCE 2). Indispensable pour les alias/identifiants GÉNÉRÉS (`AS X`, `GROUP BY X`,
/// `ORDER BY X`, `USING(X)`) : `soql_ident_ok` autorise des MOTS RÉSERVÉS SQLite (`order`, `group`,
/// `where`, `from`, `select`...) qui, en position d'identifiant NU, déclenchent `near "X": syntax
/// error`. Les noms passent déjà `soql_ident_ok` (pas de `"` réel) ; le doublage reste correct par
/// sécurité. PUBLIC : la route-rollup de Plume en dépend à la bascule.
pub fn soql_qid(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub(crate) fn soql_num(s: &str) -> bool {
    let s = s.strip_prefix('-').unwrap_or(s);
    let mut parts = s.split('.');
    let int = parts.next().unwrap_or("");
    let frac = parts.next();
    parts.next().is_none()
        && !int.is_empty() && int.bytes().all(|b| b.is_ascii_digit())
        && frac.map_or(true, |f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
}

/// count | count(f) | sum(f) | avg(f) | min(f) | max(f) | dc(f)  -> (expr SQL, alias).
/// DIVERGENCE 1 (parité Plume) : la réf de champ agrégée passe par `soql_field` -> un champ JSON
/// devient `COUNT(json_extract(fields,'$.X'))` / `COUNT(DISTINCT json_extract(...))` et NON `COUNT(X)`
/// nu (colonne inexistante -> erreur SQL -> `eval_value=0` -> RÈGLE MUETTE). Rend `stats dc(vhost)
/// by src_ip` fonctionnel (recon multi-vhost, T1595). Une colonne réelle / un alias de stage est
/// quoté via `soql_field` (gère les mots réservés).
pub(crate) fn soql_agg(tok: &str, cols: &[String], json_field: Option<&str>, d: &dyn Dialect) -> Result<(String, String), String> {
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
            let qf = soql_field(field, cols, json_field, d);
            let sql = match func {
                "count" => format!("COUNT({qf})"),
                "sum" => format!("SUM({qf})"),
                "avg" => format!("AVG({qf})"),
                "min" => format!("MIN({qf})"),
                "max" => format!("MAX({qf})"),
                "dc" => format!("COUNT(DISTINCT {qf})"),
                // OP 1 : agrégats LISTE (recon multi-valeur). `values` = valeurs DISTINCTES groupées,
                // `list` = toutes (avec doublons). Anti-explosion mémoire (budget 2 Go) : la string
                // concaténée est BORNÉE à 4096 c. par `substr(...,1,4096)` (un GROUP_CONCAT non borné
                // sur un champ à forte cardinalité gonflerait la ligne agrégée sans limite).
                "values" => d.group_concat_bounded(&qf, true, 4096),
                "list" => d.group_concat_bounded(&qf, false, 4096),
                _ => return Err(format!("fonction stats inconnue : {func}")),
            };
            return Ok((sql, func.to_string()));
        }
    }
    Err(format!("stats : syntaxe invalide '{tok}' (count | sum(f) | avg(f) | min(f) | max(f) | dc(f) | values(f) | list(f))"))
}

// ---------------------------------------------------------------------------------------------
// BORNES D'EXPLOITATION DE LA COMPILATION — le texte de requête est une ENTRÉE NON FIABLE
// (CONTRIBUTING.md), et la compilation a lieu AVANT tout budget d'exécution du store : elle doit
// donc porter ses propres bornes. Chacune a un DÉFAUT SÛR et se règle par l'environnement (choix
// d'exploitation). Au DÉPASSEMENT : une ERREUR CLAIRE est rendue à l'appelant — jamais un panic,
// jamais une valeur substituée en silence.
//
//   GUATX_SOQL_MAX_SPAN_SECS  défaut 315360000 (10 ans)  bucket `timechart span=` (secondes)
//   GUATX_SOQL_MAX_STAGES     défaut 64                  nombre d'étapes de pipe d'un pipeline
//   GUATX_SOQL_MAX_SQL_BYTES  défaut 1048576 (1 Mio)      taille du SQL émis, vérifiée APRÈS chaque étape
//   GUATX_SOQL_MAX_TEXT_BYTES défaut 1048576 (1 Mio)      taille du TEXTE de requête accepté
//
// PORTÉE EXACTE de la borne de SQL : elle est vérifiée APRÈS chaque étape (base, champs calculés,
// lookups automatiques, puis chaque étape de pipe). Le pic TRANSITOIRE d'UNE étape n'est donc pas
// borné par elle : c'est la borne du TEXTE d'entrée qui le contient. Mesure du couple : 400 006
// octets de texte -> 4 600 089 octets de SQL (amplification ×11,5) AVANT refus.
//
// Une variable PRÉSENTE mais illisible (non numérique, ≤ 0, au-dessus du PLAFOND) est une ERREUR de
// configuration rendue à l'appelant, PAS un retour muet au défaut : une borne que l'opérateur croit
// avoir posée ne doit jamais être ignorée en silence. Conséquence assumée : tant que la variable est
// illisible, TOUTE requête qui consulte cette borne échoue (fail-closed), et le message le dit —
// c'est une erreur de CONFIGURATION SERVEUR, pas une erreur de la requête de l'utilisateur.
//
// PLAFOND DE SÛRETÉ : chaque borne a un `hard_max`. Une borne de sécurité doit pouvoir être BAISSÉE,
// jamais RETIRÉE — sans plafond, `GUATX_SOQL_MAX_SQL_BYTES=99999999999999` (valeur d'apparence
// plausible, mesurée comme acceptée) désactivait la protection anti-OOM.
//
// CACHE : seule une valeur VALIDE est mise en cache (lecture unique par processus). Un refus n'est
// PAS verrouillé -> corriger la variable ne demande pas de redémarrer le service. Symétriquement, une
// valeur valide déjà lue reste figée pour la vie du processus.
// ---------------------------------------------------------------------------------------------

/// Plafonds de sûreté (cf. bandeau) : `(défaut, plafond)`. Le plafond du span vaut son défaut — cette
/// borne-là ne peut donc qu'être BAISSÉE.
const LIM_SPAN_SECS: (i64, i64) = (315_360_000, 315_360_000);
const LIM_STAGES: (i64, i64) = (64, 1_024);
const LIM_SQL_BYTES: (i64, i64) = (1_048_576, 16_777_216);
const LIM_TEXT_BYTES: (i64, i64) = (1_048_576, 16_777_216);

/// Analyse d'une borne. FONCTION PURE (la valeur brute est un ARGUMENT, pas une lecture d'environnement)
/// -> testable in-process, contrairement à la lecture cachée. `raw = None` = variable absente = défaut.
pub(crate) fn parse_limit(
    var: &str,
    raw: Option<&str>,
    default: i64,
    hard_max: i64,
) -> Result<i64, String> {
    match raw {
        None => Ok(default),
        Some(v) => match v.trim().parse::<i64>() {
            Ok(n) if n > 0 && n <= hard_max => Ok(n),
            _ => Err(format!(
                "configuration serveur invalide (ce n'est pas votre requête) : la borne de compilation {var} doit être un entier entre 1 et {hard_max}"
            )),
        },
    }
}

/// Lecture d'une borne d'environnement, avec MISE EN CACHE DE LA SEULE VALEUR VALIDE (cf. bandeau).
fn env_limit(
    cell: &'static std::sync::OnceLock<i64>,
    var: &str,
    lim: (i64, i64),
) -> Result<i64, String> {
    if let Some(v) = cell.get() {
        return Ok(*v);
    }
    let v = parse_limit(var, std::env::var(var).ok().as_deref(), lim.0, lim.1)?;
    let _ = cell.set(v);
    Ok(v)
}

/// Borne haute du bucket `timechart span=` (secondes). Cf. bandeau BORNES D'EXPLOITATION.
pub(crate) fn soql_max_span_secs() -> Result<i64, String> {
    static C: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    env_limit(&C, "GUATX_SOQL_MAX_SPAN_SECS", LIM_SPAN_SECS)
}

/// Borne du nombre d'étapes de pipe d'un pipeline. Cf. bandeau BORNES D'EXPLOITATION.
pub(crate) fn soql_max_stages() -> Result<i64, String> {
    static C: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    env_limit(&C, "GUATX_SOQL_MAX_STAGES", LIM_STAGES)
}

/// Borne de la taille (octets) du SQL émis, vérifiée APRÈS CHAQUE étape. Cf. bandeau ci-dessus.
pub(crate) fn soql_max_sql_bytes() -> Result<i64, String> {
    static C: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    env_limit(&C, "GUATX_SOQL_MAX_SQL_BYTES", LIM_SQL_BYTES)
}

/// Borne de la taille (octets) du TEXTE DE REQUÊTE accepté. Cf. bandeau ci-dessus.
pub(crate) fn soql_max_text_bytes() -> Result<i64, String> {
    static C: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    env_limit(&C, "GUATX_SOQL_MAX_TEXT_BYTES", LIM_TEXT_BYTES)
}

pub(crate) fn soql_dur(s: &str) -> Result<i64, String> {
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
    // S1 — ARITHMÉTIQUE BORNÉE. `n * mult` débordait i64 depuis du texte de requête : PANIC du thread
    // de compilation (profils avec overflow-checks) ou WRAP NÉGATIF rattrapé par le `if span <= 0` de
    // `compile_timechart`, qui SUBSTITUAIT alors le bucket auto au bucket DEMANDÉ (la requête ne mesure
    // plus ce qu'elle croit mesurer). Les deux faces sont fermées ici : erreur claire, jamais de
    // substitution. Le `<= 0` couvre aussi `span=0` explicite (0 n'est pas un bucket : on refuse au
    // lieu de retomber en silence sur le bucket automatique ; `timechart` SANS `span=` est inchangé).
    let max = soql_max_span_secs()?;
    let secs = n.checked_mul(mult).ok_or_else(|| format!("span hors bornes : {s}"))?;
    if secs <= 0 || secs > max {
        return Err(format!("span hors bornes : {s} (attendu entre 1 s et {max} s)"));
    }
    Ok(secs)
}

pub(crate) fn soql_expr_sql(expr: &str, json_field: Option<&str>, cols: &[String], d: &dyn Dialect) -> Result<String, String> {
    // Allowlist des fonctions d'eval = la const de complétion EXPOSÉE (source unique de vérité) : la
    // complétion propose EXACTEMENT ce que ce chemin accepte -> aucune dérive possible (cf. SOQL_EVAL_FUNCTIONS).
    const FNS: &[&str] = SOQL_EVAL_FUNCTIONS;
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
            // Échappement du littéral `eval` via le DIALECT (`escape_literal`),
            // plus le doublage-quote EN DUR : SQLite/DuckDB émettent byte-identique (soql_esc), mais ClickHouse
            // échappe AUSSI le backslash (`a\` -> `'a\\'`) — sans quoi un backslash final romprait la borne du
            // littéral (injection). Cohérent avec tous les autres chemins de valeur du compilateur.
            out.push('\'');
            out.push_str(&d.escape_literal(&s));
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
                // FIELD FILTERS — CHOKE-POINT DU MASQUE dans `eval`. Résolution d'identifiant CALQUÉE
                // sur `soql_field` (sémantique UNIQUE : eval et projection résolvent un identifiant à
                // l'identique), avec garde stricte de parité mode 0 :
                //  - SAC JSON (`fields`, TOUTE CASSE) : gardé BRUT à la base (source d'extraction des clés)
                //    -> `eval x = fields` le COPIERAIT EN CLAIR dans une colonne aliasée, contournant
                //    `mask_output_bag`. On route par `bag_wrap` (RETIRE les clés masquées du blob, fail-
                //    closed). Comparaison INSENSIBLE À LA CASSE : SQLite plie la casse des noms de colonne,
                //    donc `FIELDS`/`FiElDs`/`substr(FIELDS,…)` se résoudraient QUAND MÊME vers la colonne
                //    brute `fields` — un match sensible à la casse (CVE mask-bypass) les laisserait fuir.
                //    VIDE -> `bag_wrap` = None -> identifiant nu (byte-identique au legacy).
                //  - COLONNE RÉELLE (`src_ip`, …) : DÉJÀ masquée à la projection de BASE (`base_proj_col`)
                //    -> émise BRUTE ici (pas de re-masquage : un hash de hash serait faux). Mode 0 identique.
                //  - IDENTIFIANT INCONNU (clé JSON pure, variante de casse, champ absent) : au lieu d'un
                //    ÉCHO SQL BRUT (qui pouvait se résoudre vers une colonne masquée brute — CLASSE entière
                //    du bypass, pas juste `fields`), on l'extrait du sac comme `soql_field` :
                //    `d.json_extract(jf,'$.<id>')` + masque éventuel (NULL pour une clé absente : bénin).
                //    STRICTEMENT NO-OP EN MODE 0 : gardé par `mask_active()` — sans aucun masque actif on
                //    émet l'identifiant nu legacy (byte-identique ; parité différentielle intacte). Le
                //    json_extract ne s'ACTIVE que lorsqu'un masque existe, donc jamais en mode 0.
                match json_field {
                    Some(jf) if id.eq_ignore_ascii_case(jf) && cols.iter().any(|c| c.eq_ignore_ascii_case(jf)) => {
                        out.push_str(&bag_wrap(&soql_qid(jf), cols).unwrap_or_else(|| id.clone()));
                    }
                    _ if cols.iter().any(|c| *c == id) => out.push_str(&id),
                    Some(jf) if mask_active() && cols.iter().any(|c| c == jf) => {
                        let base = d.json_extract(jf, &id);
                        out.push_str(&mask_wrap(&base, &id).unwrap_or(base));
                    }
                    _ => out.push_str(&id),
                }
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

/// Découpe sur les pipes de PREMIER niveau (ignore les `|` dans les crochets `[ ... ]`). PUBLIC :
/// la route-rollup de Plume (`try_rollup_route`) en dépend à la bascule.
pub fn soql_split_pipes(s: &str) -> Vec<String> {
    let (mut out, mut depth, mut cur) = (Vec::new(), 0i32, String::new());
    for c in s.chars() {
        match c {
            '[' => { depth += 1; cur.push(c); }
            ']' => { depth -= 1; cur.push(c); }
            '|' if depth == 0 => { out.push(cur.trim().to_string()); cur.clear(); }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

pub(crate) fn soql_bracket(stage: &str) -> Result<String, String> {
    let start = stage.find('[').ok_or_else(|| "crochet '[' manquant (ex: append [search ...])".to_string())?;
    let end = stage.rfind(']').ok_or_else(|| "crochet ']' manquant".to_string())?;
    if end <= start + 1 {
        return Err("sous-recherche vide".into());
    }
    Ok(stage[start + 1..end].trim().to_string())
}

pub(crate) fn soql_proj(target: &[String], have: &[String]) -> String {
    let items: Vec<String> = target
        .iter()
        .map(|c| if have.iter().any(|h| h == c) { soql_qid(c) } else { format!("NULL AS {}", soql_qid(c)) })
        .collect();
    format!("SELECT {}", items.join(", "))
}

pub(crate) fn parse_value_filter(tok: &str) -> Option<(&'static str, f64)> {
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
