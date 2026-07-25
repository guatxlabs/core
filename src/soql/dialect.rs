use super::{mitre_parent_sql, soql_esc, soql_qid};

// ---------------------------------------------------------------------------------------------
// DIALECT — SPI d'ÉMISSION SQL (readiness pivot « pluggable store »).
//
// Le compilateur soql traduit un PIPELINE en SQL. Toute la STRUCTURE (étapes, ordre, colonnes de
// sortie, quoting/échappement, gardes de sûreté) est schéma-neutre ET backend-neutre : elle reste
// dans `compile_depth`. Ce qui VARIE d'un backend à l'autre, ce sont quelques FRAGMENTS de texte SQL
// (accès à un sous-champ JSON, coercition numérique, troncature temporelle, agrégat-liste borné,
// rollup ATT&CK, `LIKE` de terme libre). Avant ce pivot ils étaient des `format!` codés en dur dans
// `soql_field`/`soql_filter_field`/`soql_agg`/le stage timechart/`mitre_parent_sql`. Ils sont désormais
// émis PAR le `Dialect` porté par le `Schema`.
//
// INVARIANT ABSOLU (prouvé par `tests/plume_parity.rs`) : `SqliteDialect` est le SEUL Dialect ; ses
// méthodes renvoient EXACTEMENT les mêmes chaînes que les `format!` legacy -> la sortie SQL est
// BYTE-IDENTIQUE. Le Dialect n'est PAS un point d'extension actif ici : c'est la COUTURE qui rendra un
// jour possible un backend DuckDB/ClickHouse (émission JSON / bucketing / cast différents) SANS
// toucher au compilateur. `Send + Sync` + objets-sûrs -> `&'static dyn Dialect` portable partout.
//
// NB quoting/échappement : `quote_ident`/`escape_literal` figurent dans le SPI (surface complète),
// mais le compilateur continue d'appeler les fonctions PUBLIQUES `soql_qid`/`soql_esc` (dont dépend la
// route-rollup de Plume) — `SqliteDialect` s'y délègue, source unique de vérité. Idem `mitre_parent`
// (délègue à `mitre_parent_sql`, conservé pour la couverture de test existante).
pub trait Dialect: Send + Sync {
    /// Accès à un sous-champ JSON : `json_extract(container,'$.field')`. `field` est déjà validé
    /// (`soql_ident_ok`) par l'appelant -> pas d'injection dans le chemin JSON.
    fn json_extract(&self, container: &str, field: &str) -> String;
    /// Coercition numérique d'une expression textuelle : `CAST(expr AS REAL)`.
    fn cast_real(&self, expr: &str) -> String;
    /// Troncature d'un timestamp au bucket `span` (secondes) : `(ts_col/span)*span` (timechart).
    fn time_bucket(&self, ts_col: &str, span: i64) -> String;
    /// Agrégat-liste BORNÉ (anti-explosion mémoire) : `substr(GROUP_CONCAT([DISTINCT ]expr),1,cap)`.
    fn group_concat_bounded(&self, expr: &str, distinct: bool, cap: usize) -> String;
    /// Rollup ATT&CK d'un champ vers sa technique PARENTE (sous-technique -> parente, casse uniformisée).
    fn mitre_parent(&self, col: &str) -> String;
    /// Terme libre : `col LIKE '%pat%'` — `pat` est DÉJÀ échappé (`soql_esc`) par l'appelant.
    fn like_contains(&self, col: &str, escaped_pat: &str) -> String;
    /// Quoting d'identifiant (mots réservés SQLite). Délègue à la fonction publique `soql_qid`.
    fn quote_ident(&self, ident: &str) -> String;
    /// Échappement d'un littéral chaîne. Délègue à la fonction publique `soql_esc`.
    fn escape_literal(&self, s: &str) -> String;
}

/// L'UNIQUE implémentation : émet exactement le SQL SQLite/SQLCipher historique de Plume (parité stricte).
#[derive(Clone, Copy, Debug, Default)]
pub struct SqliteDialect;

impl Dialect for SqliteDialect {
    fn json_extract(&self, container: &str, field: &str) -> String {
        format!("json_extract({container},'$.{field}')")
    }
    fn cast_real(&self, expr: &str) -> String {
        format!("CAST({expr} AS REAL)")
    }
    fn time_bucket(&self, ts_col: &str, span: i64) -> String {
        format!("({ts_col}/{span})*{span}")
    }
    fn group_concat_bounded(&self, expr: &str, distinct: bool, cap: usize) -> String {
        let d = if distinct { "DISTINCT " } else { "" };
        format!("substr(GROUP_CONCAT({d}{expr}),1,{cap})")
    }
    fn mitre_parent(&self, col: &str) -> String {
        mitre_parent_sql(col)
    }
    fn like_contains(&self, col: &str, escaped_pat: &str) -> String {
        format!("{col} LIKE '%{escaped_pat}%'")
    }
    fn quote_ident(&self, ident: &str) -> String {
        soql_qid(ident)
    }
    fn escape_literal(&self, s: &str) -> String {
        soql_esc(s)
    }
}

/// Instance `'static` de l'unique Dialect — référencée par `Schema.dialect` (défaut de tous les schémas).
pub static SQLITE_DIALECT: SqliteDialect = SqliteDialect;

// ---------------------------------------------------------------------------------------------
// DUCKDB DIALECT (tier WARM analytique) — émission SOQL -> SQL DuckDB.
//
// PUR TEXTE, ZÉRO dépendance : `DuckDbDialect` ne fait qu'émettre des FRAGMENTS SQL DuckDB (pas de
// dépendance à la crate `duckdb`, qui vit — feature-gated — dans le daemon). Il n'est SÉLECTIONNÉ que
// si un `Schema` le porte (`with_dialect(&DUCKDB_DIALECT)` / `events_duckdb()`) ; les schémas par défaut
// restent sur `SqliteDialect` -> `differential_zero_unexpected_diff` (parité mode 0) INCHANGÉ. Le
// COMPILATEUR (`compile_depth`) est réutilisé VERBATIM : seuls ces fragments changent (tableau ci-dessous).
//
// Correspondances (delta d'émission SQLite -> DuckDB) :
//   json_extract  : `json_extract_string(c,'$.f')` (DuckDB rend le texte du sous-champ JSON) ;
//   cast_real     : `TRY_CAST(e AS DOUBLE)` (DuckDB est STRICT ; `TRY_CAST` -> NULL sur échec, comme la
//                   coercition indulgente de SQLite `CAST AS REAL` ; cf. `toFloat64OrNull` côté CH) ;
//   time_bucket   : `(ts // span)*span` (`//` = division ENTIÈRE DuckDB ; `/` y est flottant — même
//                   arithmétique de grain que SQLite, indispensable pour aligner les rollups) ;
//   group_concat  : `substr(string_agg([DISTINCT ]e,','),1,cap)` (DuckDB = `string_agg`, séparateur
//                   EXPLICITE ; le `,` reproduit le défaut de `GROUP_CONCAT` SQLite) ;
//   mitre_parent  : IDENTIQUE (DuckDB a `instr`/`substr`/`UPPER`) -> délègue à `mitre_parent_sql` ;
//   like_contains : `col ILIKE '%pat%'` — `LIKE` SQLite est CASE-INSENSITIVE (ASCII) par défaut, `LIKE`
//                   DuckDB est CASE-SENSITIVE ; `ILIKE` restaure la sémantique (cf. `positionCaseInsensitive`
//                   côté CH) ;
//   quote_ident / escape_literal : identiques à SQLite (double-quote / doublage `'`) -> délèguent.
/// Dialect d'émission DuckDB (tier WARM). Émission pure texte (aucune dép `duckdb`). Sélectionné
/// via `Schema::with_dialect(&DUCKDB_DIALECT)` / `Schema::events_duckdb()` ; jamais par défaut.
#[derive(Clone, Copy, Debug, Default)]
pub struct DuckDbDialect;

impl Dialect for DuckDbDialect {
    fn json_extract(&self, container: &str, field: &str) -> String {
        format!("json_extract_string({container},'$.{field}')")
    }
    fn cast_real(&self, expr: &str) -> String {
        format!("TRY_CAST({expr} AS DOUBLE)")
    }
    fn time_bucket(&self, ts_col: &str, span: i64) -> String {
        format!("({ts_col} // {span})*{span}")
    }
    fn group_concat_bounded(&self, expr: &str, distinct: bool, cap: usize) -> String {
        let d = if distinct { "DISTINCT " } else { "" };
        format!("substr(string_agg({d}{expr},','),1,{cap})")
    }
    fn mitre_parent(&self, col: &str) -> String {
        // `instr`/`substr`/`UPPER` existent à l'identique en DuckDB -> même expression que SQLite.
        mitre_parent_sql(col)
    }
    fn like_contains(&self, col: &str, escaped_pat: &str) -> String {
        // ILIKE : reproduit l'insensibilité à la casse du `LIKE` SQLite (le `LIKE` DuckDB est sensible).
        format!("{col} ILIKE '%{escaped_pat}%'")
    }
    fn quote_ident(&self, ident: &str) -> String {
        soql_qid(ident)
    }
    fn escape_literal(&self, s: &str) -> String {
        soql_esc(s)
    }
}

/// Instance `'static` du Dialect DuckDB — sélectionnable par `Schema.dialect` (jamais le défaut).
pub static DUCKDB_DIALECT: DuckDbDialect = DuckDbDialect;

// ---------------------------------------------------------------------------------------------
// CLICKHOUSE DIALECT (tier COLD/scale) — émission SOQL -> SQL ClickHouse.
//
// PUR TEXTE, ZÉRO dépendance (comme `DuckDbDialect`) : `ClickHouseDialect` n'émet que des FRAGMENTS
// SQL ClickHouse ; la crate `clickhouse` (réseau/async) vit — feature-gated — dans le daemon, JAMAIS
// dans le cœur. Sélectionné UNIQUEMENT si un `Schema` le porte (`with_dialect(&CLICKHOUSE_DIALECT)` /
// `events_clickhouse()`) ; les schémas par défaut restent sur `SqliteDialect` -> parité mode 0
// (`differential_zero_unexpected_diff`) INCHANGÉE. Le COMPILATEUR (`compile_depth`) est réutilisé
// VERBATIM (tableau de mapping des fragments ci-dessous) :
// seuls ces fragments changent — chaque règle/panel/RBA/Sigma écrit en SOQL tient sans réécriture.
//
// Correspondances (delta d'émission SQLite -> ClickHouse) :
//   json_extract  : `JSONExtractString(c,'f')` (ClickHouse extrait le texte du sous-champ ; la clé est
//                   le NOM nu, pas un chemin `$.f`) ;
//   cast_real     : `toFloat64OrNull(e)` (ClickHouse est STRICT ; `*OrNull` -> NULL sur échec, comme la
//                   coercition indulgente de SQLite `CAST AS REAL` / du DuckDB `TRY_CAST`) ;
//   time_bucket   : `intDiv(ts,span)*span` (division ENTIÈRE explicite — MÊME arithmétique de grain que
//                   `(ts/span)*span` SQLite ; on NE bascule PAS vers `toStartOfInterval` : le grain des
//                   rollups doit rester identique entre tiers) ;
//   group_concat  : `substring(arrayStringConcat(groupUniqArray|groupArray(e),','),1,cap)` — ClickHouse
//                   agrège en TABLEAU (`groupArray` = tout, `groupUniqArray` = DISTINCT) puis join avec
//                   `arrayStringConcat` (séparateur explicite `,`, reproduit le défaut `GROUP_CONCAT`) ;
//   mitre_parent  : réécrit en fns ClickHouse (`position`/`substring`/`upper` — ClickHouse n'a PAS
//                   `instr`) ; MÊME sémantique (index 1-based, 0 si absent) que `mitre_parent_sql` ;
//   like_contains : `positionCaseInsensitive(col,'pat') > 0` — reproduit l'insensibilité à la casse du
//                   `LIKE` SQLite (le `LIKE` ClickHouse est CASE-SENSITIVE), sans wildcards `%` ;
//   quote_ident / escape_literal : DÉLÈGUENT à `soql_qid`/`soql_esc` (double-quote / doublage `'`). Ces
//                   formes sont AUSSI valides en ClickHouse (identifiants double-quotés + `''` accepté
//                   dans un littéral). Le quoting d'IDENTIFIANT que le compilateur émet en direct passe
//                   par `soql_qid` (jamais `d.quote_ident`) -> déléguer `quote_ident` à `soql_qid` garde
//                   les deux cohérents. L'ÉCHAPPEMENT DE LITTÉRAL, lui, est désormais ROUTÉ par le
//                   compilateur via `d.escape_literal` (le backslash final doit être doublé en
//                   ClickHouse pour borner le littéral ; SQLite/DuckDB le laissent inerte) -> le dialect
//                   GOUVERNE réellement l'échappement des valeurs. Déléguer garde donc le quoting/
//                   échappement de TOUTE la requête ClickHouse cohérent et légal (une variante backtick
//                   divergerait de ce que le compilateur émet réellement).
/// Dialect d'émission ClickHouse (tier COLD/scale). Émission pure texte (aucune dép `clickhouse`).
/// Sélectionné via `Schema::with_dialect(&CLICKHOUSE_DIALECT)` / `Schema::events_clickhouse()` ; jamais
/// par défaut. Le compilateur est réutilisé verbatim -> parité mode 0 SQLite intacte.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClickHouseDialect;

impl Dialect for ClickHouseDialect {
    fn json_extract(&self, container: &str, field: &str) -> String {
        // ClickHouse : la clé JSON est le NOM nu (pas de chemin `$.field`).
        format!("JSONExtractString({container},'{field}')")
    }
    fn cast_real(&self, expr: &str) -> String {
        format!("toFloat64OrNull({expr})")
    }
    fn time_bucket(&self, ts_col: &str, span: i64) -> String {
        // `intDiv` = division entière ClickHouse -> même grain que `(ts/span)*span` SQLite.
        format!("intDiv({ts_col},{span})*{span}")
    }
    fn group_concat_bounded(&self, expr: &str, distinct: bool, cap: usize) -> String {
        // ClickHouse agrège en tableau (`groupUniqArray`=distinct / `groupArray`=tout) puis join.
        let agg = if distinct { "groupUniqArray" } else { "groupArray" };
        format!("substring(arrayStringConcat({agg}({expr}),','),1,{cap})")
    }
    fn mitre_parent(&self, col: &str) -> String {
        // ClickHouse n'a PAS `instr` -> `position(haystack,needle)` (1-based, 0 si absent) ; `substring`
        // 1-based comme `substr` SQLite ; `upper` aligne la casse. Sémantique identique à `mitre_parent_sql`.
        format!(
            "CASE WHEN position({col},'.')>0 THEN upper(substring({col},1,position({col},'.')-1)) ELSE upper({col}) END"
        )
    }
    fn like_contains(&self, col: &str, escaped_pat: &str) -> String {
        // `positionCaseInsensitive` restaure l'insensibilité à la casse du `LIKE` SQLite (le `LIKE`
        // ClickHouse est sensible). Recherche de sous-chaîne -> pas de wildcards `%`.
        format!("positionCaseInsensitive({col},'{escaped_pat}') > 0")
    }
    fn quote_ident(&self, ident: &str) -> String {
        soql_qid(ident)
    }
    fn escape_literal(&self, s: &str) -> String {
        // ClickHouse traite les ÉCHAPPEMENTS C-style (`\'`, `\\`, …) À L'INTÉRIEUR d'un littéral
        // simple-quote — contrairement à SQLite/DuckDB. Doubler seulement les `'` (`soql_esc`) est donc
        // INSUFFISANT ici : une valeur à backslash final (`a\`) émise `'a\'` verrait `\'` interprété comme
        // une quote ÉCHAPPÉE -> le littéral ne se ferme jamais -> rupture de borne -> injection SQL. On
        // échappe donc le BACKSLASH D'ABORD (`\` -> `\\`), PUIS on double les quotes (`'` -> `''`, forme
        // acceptée par ClickHouse dans un littéral). L'ordre importe : traiter le backslash en premier évite
        // de ré-échapper des backslashes que le doublage de quote n'introduit de toute façon pas.
        // SQLite/DuckDB gardent `soql_esc` (ils ne traitent PAS `\`) -> leur émission reste byte-identique.
        s.replace('\\', "\\\\").replace('\'', "''")
    }
}

/// Instance `'static` du Dialect ClickHouse — sélectionnable par `Schema.dialect` (jamais le défaut).
pub static CLICKHOUSE_DIALECT: ClickHouseDialect = ClickHouseDialect;
