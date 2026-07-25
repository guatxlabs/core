//! soql — langage de requête type-SPL (Splunk-lite) compilé en SQL read-only.
//!
//! PROMOTION INTÉGRALE du compilateur de Plume (daemon), rendu **schéma-générique** : la
//! même implémentation sert `event`/`metric` (Plume, bleu) ET `finding`/`runrecord` (Forge, rouge).
//! Un `Schema` décrit la (les) table(s) de base, les colonnes réelles, le champ JSON optionnel et
//! le champ de recherche libre — c'est le SEUL paramètre ; toute la logique des étapes est commune.
//!
//! Étapes : `search`/`metric`/`<alt>` (base) | stats | timechart | where | sort | head/limit | rex
//!          | fields | table | dedup | top/rare | eventstats | rate | eval | append [..] | join f [..].
//!
//! Sûreté (identique à Plume) : identifiants validés (`soql_ident_ok`), valeurs échappées
//! (`soql_esc`, quotes doublées) et inlinées, mots-clés SQL interdits dans `eval`, littéraux
//! numériques stricts, un seul SELECT, récursion bornée (≤3). Le SELECT s'exécute ensuite sur une
//! connexion SQLITE_OPEN_READ_ONLY côté consommateur. Les UDF `regexp`/`re_cap` (pour `=~`/`rex`)
//! sont enregistrées par le consommateur sur sa connexion.

// ---------------------------------------------------------------------------------------------
// CONTRAT ATT&CK partagé (boucle purple : Forge tire T ─► Plume détecte T ?).
//
// La corrélation purple est une ÉGALITÉ du champ `mitre`. Mais Forge tire parfois une
// sous-technique (`T1059.001`) là où Plume détecte la technique parente (`T1059`), ou
// l'inverse. Sans canonicalisation, l'égalité brute manquerait la corrélation et le
// dashboard de couverture afficherait un faux « trou de détection » (missed) — exactement
// l'erreur de mesure défensive qu'on veut éviter. Le contrat impose donc :
//
//   1. `normalize_technique(s) -> Option<String>` : MAJUSCULES, valide `T\d{4}(\.\d{3})?`,
//      ROLLUP sous-technique -> technique parente (`T1059.001` -> `T1059`). `None` si l'entrée
//      n'est pas un ID ATT&CK de technique valide (bruit, vide, format faux).
//   2. La JOINTURE purple se fait au niveau de la technique PARENTE : les deux côtés (Forge
//      run-record, Plume détection) normalisent leur `mitre` AVANT l'égalité. Une détection de
//      sous-technique compte donc bien pour la couverture de la technique parente tirée, et
//      réciproquement — pas de faux missed dû à la granularité.
//   3. `PURPLE_EXCHANGE_COLS` : les colonnes d'échange que les deux produits partagent pour la
//      mesure (`mitre` = clé de jointure ; `ts` = horodatage pour le MTTD ; `target` = périmètre).
//
// Schéma-neutre, pur `std`, zéro effet de bord — une seule implémentation auditée des deux côtés.
// ---------------------------------------------------------------------------------------------

/// Colonnes d'échange de la boucle purple, partagées par `Schema::forge()` (run-record rouge)
/// et `Schema::events()` (détection bleue). `mitre` est la clé de jointure (normalisée au niveau
/// technique parente), `ts` l'horodatage qui alimente le MTTD, `target` le périmètre corrélé.
///
/// Ces trois colonnes existent des deux côtés du contrat : c'est ce qui rend la mesure
/// detected/missed/MTTD possible par une simple requête soql `join mitre [...]`.
pub const PURPLE_EXCHANGE_COLS: &[&str] = &["mitre", "ts", "target"];

/// Canonicalise un identifiant de technique MITRE ATT&CK pour la corrélation purple.
///
/// - Met en MAJUSCULES et retire les espaces de bordure.
/// - Valide la forme `T\d{4}` (technique) ou `T\d{4}.\d{3}` (sous-technique).
/// - ROLLUP : une sous-technique est réduite à sa technique parente (`T1059.001` -> `T1059`),
///   de sorte que la jointure purple se fasse toujours au niveau PARENT (pas de faux « missed »
///   quand Forge tire `T1059.001` et que Plume détecte `T1059`, ou l'inverse).
/// - Renvoie `None` si l'entrée n'est pas un ID de technique valide (vide, bruit, format faux,
///   numéro de chiffres erroné). `None` = « pas une technique » : à exclure de la corrélation.
///
/// # Exemples
/// ```
/// use guatx_core::soql::normalize_technique;
/// assert_eq!(normalize_technique("t1059.001").as_deref(), Some("T1059"));
/// assert_eq!(normalize_technique("  T1190 ").as_deref(), Some("T1190"));
/// assert_eq!(normalize_technique("T1059.001.002"), None); // pas une forme valide
/// assert_eq!(normalize_technique("TA0001"), None);        // tactique, pas technique
/// assert_eq!(normalize_technique(""), None);
/// ```
pub fn normalize_technique(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_uppercase();
    // Sépare une éventuelle sous-technique : on ne garde que la technique parente (rollup).
    let (tech, sub) = match s.split_once('.') {
        Some((t, sub)) => (t, Some(sub)),
        None => (s.as_str(), None),
    };
    // Technique : 'T' suivi d'EXACTEMENT 4 chiffres.
    let digits = tech.strip_prefix('T')?;
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Sous-technique (si présente) : EXACTEMENT 3 chiffres, et pas d'autre point ('.001.002' rejeté).
    if let Some(sub) = sub {
        if sub.len() != 3 || !sub.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    // Rollup : on renvoie la technique parente seule.
    Some(tech.to_string())
}

/// Nom du champ de corrélation ATT&CK partagé par les deux produits (clé de jointure purple).
pub const PURPLE_JOIN_FIELD: &str = "mitre";

/// Expression SQL qui ROLLUP un champ technique ATT&CK vers sa technique PARENTE, à la volée,
/// SANS UDF (pur SQLite `std`). `T1059.001` -> `T1059`, `T1059` -> `T1059`, casse uniformisée.
/// Utilisée par l'étape `join mitre [...]` pour corréler au niveau parent (cf. contrat purple).
///
/// La forme : si la valeur contient un `.`, on garde la partie avant le premier `.` ; sinon la
/// valeur entière. `UPPER(...)` aligne la casse des deux côtés de l'égalité.
pub(crate) fn mitre_parent_sql(col: &str) -> String {
    format!(
        "CASE WHEN instr({col},'.')>0 THEN UPPER(substr({col},1,instr({col},'.')-1)) ELSE UPPER({col}) END"
    )
}

// ---------------------------------------------------------------------------------------------
// DIALECT — SPI d'ÉMISSION SQL (trait `Dialect` + impls Sqlite/DuckDb/ClickHouse) : extrait VERBATIM
// dans le sous-module `dialect` (pur déplacement — aucun changement de comportement).
// Le re-export ci-dessous préserve À L'IDENTIQUE les chemins publics `soql::Dialect`,
// `soql::SqliteDialect`, `soql::SQLITE_DIALECT`, `soql::DUCKDB_DIALECT`, `soql::CLICKHOUSE_DIALECT`, …
mod dialect;
pub use dialect::*;

// ---------------------------------------------------------------------------------------------
// DÉCOUPAGE EN SOUS-MODULES — PUR DÉPLACEMENT, comportement byte-identique.
// Le corps du compilateur est réparti en sous-modules cohésifs alongside `dialect`. Les re-exports
// glob ci-dessous préservent À L'IDENTIQUE les chemins publics `soql::<name>` (API consommée par le
// daemon Plume) et rendent les items `pub(crate)` déplacés joignables depuis ce module parent.
//   mask      — FIELD FILTERS : MaskAction/FieldMaskSet, MaskGuard, mask_wrap, mask_output_bag…
//   knowledge — KNOWLEDGE OBJECTS + MACROS : KnowledgeSet/MacroDef/AutoLookup, expand_macros…
//   helpers   — helpers d'émission : soql_tokenize/esc/qid/split_pipes, soql_agg, soql_expr_sql…
//   stages    — compilateurs PAR ÉTAPE : compile_stats/where/join/… (bras de dispatch de compile_depth).
mod mask;
mod knowledge;
mod helpers;
mod stages;
pub use mask::*;
pub use knowledge::*;
pub use helpers::*;
pub(crate) use stages::*;

// ---------------------------------------------------------------------------------------------
// VOCABULAIRE DE COMPLÉTION (IDE-like) — SOURCE UNIQUE DE VÉRITÉ, exposée pour la complétion.
//
// Ces consts DÉCRIVENT la surface grammaticale que le compilateur fermé ci-dessous ACCEPTE. Elles
// existent pour que la complétion côté produit (endpoint daemon + client JS) NE PUISSE JAMAIS suggérer
// un token que `to_sql` rejetterait — la complétion est un SOUS-ENSEMBLE STRICT de ce qui compile.
//
// ANTI-DÉRIVE (double garde) :
//   1. `SOQL_EVAL_FUNCTIONS` est RÉFÉRENCÉE DIRECTEMENT par `soql_expr_sql` (l'allowlist de fonctions
//      d'`eval` EST cette const — pas une copie) -> les fonctions d'eval ne peuvent pas diverger.
//   2. Pour les commandes / fonctions stats / opérateurs (dont le dispatch est un `match` à bras
//      littéraux qui ne peut pas référencer une const), un TEST (`completion_vocab_*`) compile une
//      requête minimale par entrée via `to_sql` et exige `Ok(..)` -> retirer un bras du compilateur
//      fait ÉCHOUER le test. La complétion reste donc prouvée ⊆ grammaire.
//
// Zéro effet runtime : ce sont des `&[&str]` statiques (aucun code émis, binaire inchangé).
// ---------------------------------------------------------------------------------------------

/// Mots-clés de BASE (étape 0) du schéma Plume `events()` : `search` (défaut) et `metric` (obs).
/// Les bases alternatives de Forge (`runs`) ne font PAS partie de ce schéma -> hors complétion Plume.
pub const SOQL_BASE_KEYWORDS: &[&str] = &["search", "metric"];

/// Commandes de PIPE acceptées par `compile_depth` (miroir EXACT du `match` de dispatch d'étapes).
/// Un test compile `search | <cmd> ...` pour chacune et exige `Ok` (anti-dérive vs le match littéral).
pub const SOQL_PIPE_COMMANDS: &[&str] = &[
    "stats", "timechart", "where", "sort", "head", "limit", "rex", "fields", "table", "rename",
    "dedup", "top", "rare", "eventstats", "rate", "eval", "append", "join", "mvexpand", "lookup",
];

/// Fonctions d'agrégation acceptées par `soql_agg` (`stats`/`eventstats`/`timechart`). `count` est nu ;
/// les autres prennent un champ `f(champ)`. Un test compile `search | stats <fn>(source)` par entrée.
pub const SOQL_STATS_FUNCTIONS: &[&str] = &["count", "sum", "avg", "min", "max", "dc", "values", "list"];

/// Fonctions autorisées dans une expression `eval` — RÉFÉRENCÉE DIRECTEMENT par `soql_expr_sql` (c'est
/// l'allowlist elle-même, pas une copie) -> la complétion des fonctions d'eval ne peut pas dériver.
pub const SOQL_EVAL_FUNCTIONS: &[&str] = &[
    "if", "coalesce", "ifnull", "nullif", "lower", "upper", "length", "len", "abs", "round",
    "min", "max", "substr", "replace", "trim",
];

/// Opérateurs de comparaison de filtre (base `search`/`where`). `=~` = REGEXP ; `:` = alias de `=`.
/// Modificateurs de valeur (non listés ici car ce ne sont pas des opérateurs) : `*` glob (LIKE), `~`
/// préfixe regex, `in (…)` / `not in`. Un test compile `search field <op> valeur` par entrée.
pub const SOQL_FILTER_OPERATORS: &[&str] = &["=", "!=", ">", ">=", "<", "<=", ":", "=~"];

/// Mots-clés structurants (ni commande ni fonction) reconnus par les étapes : `by` (groupe stats/
/// timechart), `span=` (bucket timechart), `as` (rename), `OUTPUT` (colonnes de lookup).
pub const SOQL_KEYWORDS: &[&str] = &["by", "span=", "as", "OUTPUT"];

// ---------------------------------------------------------------------------------------------
// Schéma : ce qui paramètre le compilateur pour un produit donné.
// ---------------------------------------------------------------------------------------------

/// Champs JSON (sous le `json_field` de base) couverts par un INDEX EXPRESSION figé côté Plume
/// (miroir de `HOT_FIELDS`/`field_is_indexed` du daemon). Cardinalité bornée, tous TEXTUELS. Pour
/// ces champs, le filtre numérique émet la forme CANONIQUE `json_extract(fields,'$.X')` SANS
/// `CAST(... AS REAL)` : le planner SQLite n'utilise `CREATE INDEX ... ON event(json_extract(
/// fields,'$.X'))` QUE si la requête émet EXACTEMENT la même expression texte. Un `CAST` change
/// l'expression -> l'index expression n'est pas retenu par le planner (dégradation de performance
/// sur de gros volumes).
pub const HOT_FIELDS: &[&str] = &[
    "action", "user", "owner", "kind", "ns", "role", "scope",
    "verb", "resource", "operation",
];

#[derive(Clone)]
pub struct BaseDef {
    pub keyword: String,             // mot-clé de base : "search", "runs"...
    pub table: String,               // table SQL : "event", "finding", "runrecord"
    pub select_cols: Vec<String>,    // colonnes du SELECT de base (= ocols initiales)
    pub real_cols: Vec<String>,      // colonnes RÉELLES (le reste -> json_field si présent)
    pub json_field: Option<String>,  // colonne JSON de sous-champs ("fields") ou None
    pub freetext_col: Option<String>,// colonne ciblée par un terme nu (LIKE) ou None
    /// Champs JSON (sous `json_field`) couverts par un index expression (DIVERGENCE 3, parité Plume).
    /// Pour eux, `soql_filter_field` NE met PAS le `CAST(... AS REAL)` en comparaison numérique afin
    /// de conserver la forme canonique qui matche l'index. Vide = aucun index expression (Forge).
    pub indexed_fields: Vec<String>,
    /// FILTRE ENVIRONNEMENT : cette base porte-t-elle la colonne `env_id` (axe intra-tenant) ?
    /// `true` -> quand le schéma a un `env_filter` actif (mode 1), `table_base` ajoute
    /// `env_id = '<env>'` au WHERE. `false` (Forge finding/runrecord — pas d'env_id) -> jamais.
    pub has_env_id: bool,
}

/// FILTRE DE LIGNES OBLIGATOIRE (H1 — isolation tenant). Contrainte `<column> IN (<ids>)` INJECTÉE par le
/// compilateur dans le WHERE de CHAQUE base compilée (finding ET runrecord), au niveau AST/atome — JAMAIS
/// du texte ajouté que la SoQL de l'appelant pourrait rompre. NON CONTOURNABLE : c'est un atome booléen
/// (parenthésé) AND-joint AU SOMMET du WHERE de base, appliqué à la FEUILLE (`table_base`, l'unique accès
/// physique aux tables) -> aucun `WHERE`/`OR`/sous-requête/`UNION`/commentaire de l'utilisateur ne peut y
/// échapper (les étages en aval enveloppent une base DÉJÀ filtrée ; append/join recompilent leur base avec
/// le MÊME schéma -> même filtre). Liste d'ids VIDE -> atome qui ne matche RIEN (`1=0`, fail-closed : un
/// grant vide renvoie ZÉRO ligne, jamais toutes).
#[derive(Clone, Debug)]
pub struct RowFilter {
    /// Nom de colonne RÉELLE sur laquelle contraindre (ex : `engagement_id`). Validé `soql_ident_ok` à
    /// l'émission (un nom invalide -> fail-closed `1=0`, jamais un élargissement d'accès).
    pub column: String,
    /// Ids AUTORISÉS. VIDE -> `1=0` (matche rien, fail-closed). Non vide -> `<col> IN (id1,id2,…)` (i64
    /// inlinés — non injectables).
    pub ids: Vec<i64>,
}

impl RowFilter {
    /// Émet l'ATOME WHERE self-contained et non contournable : `(<col> IN (id,…))`, ou `1=0` si la liste
    /// d'ids est vide (fail-closed : un grant vide ne matche RIEN, jamais tout). La colonne est validée
    /// (`soql_ident_ok`) ; un nom invalide -> fail-closed `1=0` (un filtre malformé ne peut JAMAIS élargir
    /// l'accès). Les ids sont des i64 -> inlinés sans risque d'injection. Parenthésé -> un seul atome
    /// booléen sous n'importe quel AND-join (précédence stable, non contournable).
    fn cond_sql(&self) -> String {
        if self.ids.is_empty() || !soql_ident_ok(&self.column) {
            return "1=0".to_string(); // fail-closed : matche rien (grant vide ou colonne invalide)
        }
        let list = self.ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        format!("({} IN ({list}))", soql_qid(&self.column))
    }
}

#[derive(Clone)]
pub struct Schema {
    pub default: BaseDef,            // base par défaut (mot-clé "search")
    pub alts: Vec<BaseDef>,          // bases alternatives (ex: "runs" -> runrecord)
    pub metric: bool,                // true -> active la base `metric` (Plume/OBS)
    /// Spécialisation purple de `join mitre` (DIVERGENCE 4, gatée). `true` -> la jointure ATT&CK
    /// roule au niveau technique PARENTE des deux côtés (`ON <rollup>=<rollup>`, contrat purple) ;
    /// `false` -> jointure historique `USING(mitre)` (égalité brute). Plume (`events()`) reste sur
    /// `USING` pour la PARITÉ STRICTE avec le compilo legacy ; Forge (`forge()`) active le rollup
    /// (boucle de couverture detected/missed). Divergence INTENTIONNELLE, opt-in par le schéma.
    pub mitre_rollup_join: bool,
    /// FILTRE ENVIRONNEMENT : `Some("<env>")` -> injecte `env_id = '<env>'` dans le WHERE des
    /// bases qui portent la colonne (`BaseDef.has_env_id`). `None` (DÉFAUT, mode 0 / env unique) ->
    /// AUCUNE condition ajoutée : la sortie SQL est BYTE-IDENTIQUE au compilo legacy (parité stricte
    /// préservée — invariant absolu mode 0). Posé par le daemon via `Schema::with_env` d'après
    /// l'en-tête `X-Plume-Env` (valeur validée en amont, ré-échappée ici via `soql_esc`).
    pub env_filter: Option<String>,
    /// DIALECT d'émission SQL (readiness pivot « pluggable store »). `&SQLITE_DIALECT` pour tous les
    /// schémas actuels : c'est l'unique backend. Porté PAR le `Schema` pour qu'un futur backend
    /// (DuckDB/ClickHouse) se sélectionne SANS toucher au compilateur. Sortie BYTE-IDENTIQUE au legacy
    /// tant que le Dialect est `SqliteDialect` (invariant prouvé par `tests/plume_parity.rs`).
    pub dialect: &'static dyn Dialect,
    /// FIELD FILTERS — masques AU NIVEAU CHAMP effectifs pour l'appelant courant (rôle/tenant/env
    /// déjà résolus par le daemon). VIDE par DÉFAUT -> `soql_field`/`soql_filter`/`eval` émettent l'expression
    /// legacy À L'IDENTIQUE (mode 0 byte-identique, invariant absolu). Non vide -> chaque référence de champ
    /// masqué émet l'expression de masque (CASE/`plume_fmask_hash`/NULL) AU MOMENT DE LA COMPILATION, donc
    /// AVANT toute agrégation (`values`/`stats`/`top`) ou renommage (`rename`/`rex`/`eval`) -> impossible de
    /// contourner par agrégation ou aliasing (le masque est dans l'expression de base, pas dans le nom).
    pub field_masks: FieldMaskSet,
    /// KNOWLEDGE OBJECTS — objets de savoir PERSISTÉS, auto-appliqués À LA COMPILATION : alias de
    /// champ (canonique -> source), champs calculés (`new = <eval>`), event types (nom -> filtre SOQL) et
    /// tags (label -> paires champ=valeur). VIDE par DÉFAUT -> le compilateur émet le SQL legacy À
    /// L'IDENTIQUE (mode 0 byte-identique, invariant absolu, prouvé par `tests/plume_parity.rs`). Non vide
    /// -> chaque objet se COMPOSE sur le compilateur (alias résolu dans `soql_field`/`soql_filter_field`,
    /// calc injecté comme `eval` implicite au-dessus de la base, `eventtype=`/`tag=` détendus en conditions
    /// via le MÊME chemin de filtre) -> tout search (Explore, panels, règles, export) en hérite. Ils passent
    /// par `soql_field`/`soql_filter_field` -> HÉRITENT du masquage de champ (un calc/eventtype sur un champ
    /// masqué ne peut PAS récupérer la valeur : alias résolu AVANT le masque, filtre sur champ masqué REJETÉ).
    pub field_knowledge: KnowledgeSet,
    /// PHASE B — ÉLAGAGE DE PROJECTION (`message`). `false` par DÉFAUT (invariant absolu mode 0 : SQL
    /// BYTE-IDENTIQUE au legacy — c'est ce que gèle `tests/plume_parity.rs`). `true` -> le compilateur
    /// RETIRE la colonne grasse `message` du SELECT de BASE (`SELECT ts,host,…,fields FROM event`) UNIQUEMENT
    /// quand elle est PROUVÉE inutile en aval (voir `message_prunable`) : borne la matérialisation RAM d'un
    /// b-tree intermédiaire (`temp_store=MEMORY`) sur grande fenêtre SANS changer AUCUNE ligne de résultat
    /// (message absent de la sortie ET jamais référencé => l'ôter du SELECT interne ne modifie aucune valeur
    /// projetée). Gate CONSERVATRICE (défaut = garder) : au moindre doute, `message` est conservé. Posé par
    /// le daemon (`with_message_pruning`) sur les chemins lourds (run_due_rules, Explore hors rollup-route).
    pub prune_message_projection: bool,
    /// FILTRE DE LIGNES OBLIGATOIRE (H1 — isolation tenant). `None` par DÉFAUT -> AUCUNE contrainte injectée
    /// -> émission SQL BYTE-IDENTIQUE au legacy (invariant absolu mode 0 : `events()` et Forge community
    /// intacts). `Some(RowFilter{column, ids})` (posé via `with_row_filter`) -> le compilateur AND-joint
    /// `<column> IN (<ids>)` (ou `1=0` si ids vide, fail-closed) dans le WHERE de CHAQUE base compilée
    /// (finding ET runrecord, à toute profondeur : append/join recompilent avec le MÊME schéma). Non
    /// contournable : atome ajouté à la FEUILLE `table_base`, pas en texte que la SoQL de l'appelant
    /// pourrait rompre. Posé par la console Forge d'après le jeu d'engagements accordés à l'appelant.
    pub row_filter: Option<RowFilter>,
    /// KEYSET PAGINATION — PROJECTION de la clé de tri stable `id` dans le SELECT de base. `false`
    /// par DÉFAUT -> `id` ABSENT de la projection (mode 0 byte-identique, invariant absolu : `events()` et
    /// Forge intacts). `true` (posé via `with_cursor_id`, chemin browse Explore UNIQUEMENT) -> le compilateur
    /// AJOUTE `id` en fin de projection des bases qui portent RÉELLEMENT la colonne (`event` : `id` ∈ real_cols) ;
    /// une base sans `id` réel (Forge finding/runrecord) -> no-op. Permet au daemon de paginer par CURSEUR
    /// `(ts,id)` — `WHERE (ts,id) < curseur ORDER BY ts DESC,id DESC LIMIT n` — au lieu de `LIMIT/OFFSET`
    /// plafonné : parcours de la TOTALITÉ du match-set (millions de lignes) en O(page), sans plafond qui
    /// cacherait des événements. Se COMPOSE avec `prune_message_projection` (les deux ne touchent que la
    /// liste de projection de base).
    pub cursor_id: bool,
}

impl Schema {
    fn cols(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Schéma Plume (bleu) : event + metric. Reproduit le comportement actuel du daemon (parité).
    pub fn events() -> Schema {
        let ev = &["ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields", "dedup", "id"];
        let sel = &["ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields"];
        Schema {
            default: BaseDef {
                keyword: "search".into(),
                table: "event".into(),
                select_cols: Self::cols(sel),
                real_cols: Self::cols(ev),
                json_field: Some("fields".into()),
                freetext_col: Some("message".into()),
                indexed_fields: HOT_FIELDS.iter().map(|s| s.to_string()).collect(),
                has_env_id: true, // event.env_id -> scopable par environnement
            },
            alts: vec![],
            metric: true,
            // PARITÉ Plume : la jointure `mitre` historique du daemon est un `USING(mitre)` brut.
            mitre_rollup_join: false,
            env_filter: None, // mode 0 : pas de filtre env -> SQL byte-identique au legacy
            dialect: &SQLITE_DIALECT, // unique backend ; émission byte-identique au compilo legacy
            field_masks: FieldMaskSet::new(), // FIELD FILTERS : VIDE -> aucun masque -> émission legacy (mode 0)
            field_knowledge: KnowledgeSet::new(), // KNOWLEDGE OBJECTS : VIDE -> aucun KO -> émission legacy (mode 0)
            prune_message_projection: false, // Phase B : OFF -> SELECT de base inchangé (mode 0 byte-identique)
            row_filter: None, // H1 : Plume n'utilise pas le row-filter -> émission byte-identique (mode 0)
            cursor_id: false, // Keyset : OFF -> `id` hors projection (mode 0 byte-identique) ; posé par le daemon sur le browse
        }
    }

    /// Schéma Forge (rouge) : finding (search) + runrecord (runs). Pas de metric, pas de champ JSON.
    ///
    /// GATE `forge` (défaut OFF) : ce schéma est SPÉCIFIQUE au produit Forge — il est le SEUL point du
    /// cœur qui déclare la colonne `engagement_id` (row-filter H1) et la base `runrecord`. Plume ne le
    /// référence jamais (uniquement `events()`/`events_duckdb()`/`events_clickhouse()`), donc son
    /// retrait du build Plume est BYTE-IDENTIQUE (aucun autre item n'en dépend). Le compilateur SOQL,
    /// `Schema`, `RowFilter`/`with_row_filter` et le champ `mitre_rollup_join` restent GÉNÉRIQUES
    /// (non gatés) : une seule implémentation partagée, jamais de fork.
    #[cfg(feature = "forge")]
    pub fn forge() -> Schema {
        // Colonnes de PROJECTION (SELECT de base) — la forme de sortie de `/api/query`. INCHANGÉE.
        let fcols = &["ts", "campaign", "target", "title", "severity", "category", "mitre", "status", "evidence", "tool", "poc"];
        let rcols = &["ts", "campaign", "target", "kind", "mitre", "fired", "detail"];
        // Colonnes RÉELLES (filtrables) : = projection + `engagement_id`. `engagement_id` est une colonne
        // physique NOT NULL DEFAULT 1 de finding/runrecord (héritée du tenant via l'engagement) ; on la
        // déclare filtrable pour que le compilateur la reconnaisse dans un WHERE et que le row-filter
        // OBLIGATOIRE (`with_row_filter`, H1) puisse la contraindre — SANS l'ajouter à `select_cols`, donc
        // la forme du résultat de `/api/query` reste identique pour les appelants existants.
        let fcols_real = &["ts", "campaign", "target", "title", "severity", "category", "mitre", "status", "evidence", "tool", "poc", "engagement_id"];
        let rcols_real = &["ts", "campaign", "target", "kind", "mitre", "fired", "detail", "engagement_id"];
        Schema {
            default: BaseDef {
                keyword: "search".into(),
                table: "finding".into(),
                select_cols: Self::cols(fcols),
                real_cols: Self::cols(fcols_real),
                json_field: None,
                freetext_col: Some("title".into()),
                indexed_fields: vec![],
                has_env_id: false, // Forge : finding n'a pas d'env_id (axe env = Plume)
            },
            alts: vec![BaseDef {
                keyword: "runs".into(),
                table: "runrecord".into(),
                select_cols: Self::cols(rcols),
                real_cols: Self::cols(rcols_real),
                json_field: None,
                freetext_col: Some("detail".into()),
                indexed_fields: vec![],
                has_env_id: false, // Forge : runrecord n'a pas d'env_id
            }],
            metric: false,
            // Forge active le rollup purple : corrélation au niveau technique parente (opt-in).
            mitre_rollup_join: true,
            env_filter: None, // Forge n'utilise pas l'axe environnement (axe Plume)
            dialect: &SQLITE_DIALECT, // même backend SQLite/SQLCipher que Plume
            field_masks: FieldMaskSet::new(), // FIELD FILTERS : Forge n'injecte jamais de masque (émission legacy)
            field_knowledge: KnowledgeSet::new(), // KNOWLEDGE OBJECTS : Forge n'utilise pas les KO (émission legacy)
            prune_message_projection: false, // Phase B : OFF (Forge finding/runrecord n'ont pas de colonne `message`)
            row_filter: None, // H1 : DÉFAUT community = pas de filtre (byte-identique) ; la console pose `with_row_filter` en enterprise
            cursor_id: false, // Keyset : OFF ; finding/runrecord n'ont pas de colonne `id` réelle -> no-op de toute façon
        }
    }

    /// FILTRE ENVIRONNEMENT : renvoie une COPIE du schéma avec `env_filter` posé (ou effacé).
    /// Appelé par le daemon Plume à partir de l'en-tête `X-Plume-Env` (validé `env_slug_ok`). `None`
    /// ou `Some("")` -> pas de filtre (mode 0 / env unique / sélecteur « tous ») -> SQL inchangé.
    pub fn with_env(mut self, env: Option<&str>) -> Schema {
        self.env_filter = env.filter(|e| !e.is_empty()).map(|e| e.to_string());
        self
    }

    /// Sélectionne le DIALECT d'émission (readiness pivot multi-tier). Renvoie une COPIE avec `dialect`
    /// remplacé — le compilateur (`compile_depth`) est INCHANGÉ, seuls les fragments SQL varient. Le
    /// défaut de tous les schémas reste `&SQLITE_DIALECT` (mode 0 byte-identique) ; un backend WARM/COLD
    /// pose `&DUCKDB_DIALECT` / `&CLICKHOUSE_DIALECT` ICI sans toucher au compilateur.
    pub fn with_dialect(mut self, dialect: &'static dyn Dialect) -> Schema {
        self.dialect = dialect;
        self
    }

    /// Schéma Plume tier WARM DuckDB : `events()` avec le `DuckDbDialect`. Émission SOQL -> SQL
    /// DuckDB (le compilateur est réutilisé). Utilisé par `DuckDbStore` (daemon, feature `duckdb`).
    pub fn events_duckdb() -> Schema {
        Schema::events().with_dialect(&DUCKDB_DIALECT)
    }

    /// Schéma Plume tier COLD/scale ClickHouse : `events()` avec le `ClickHouseDialect`. Émission
    /// SOQL -> SQL ClickHouse (le compilateur est réutilisé). Utilisé par `ClickHouseStore` (daemon,
    /// feature `clickhouse`). Jamais le défaut -> parité mode 0 SQLite intacte.
    pub fn events_clickhouse() -> Schema {
        Schema::events().with_dialect(&CLICKHOUSE_DIALECT)
    }

    /// FIELD FILTERS : renvoie une COPIE du schéma avec le jeu de masques posé. `FieldMaskSet` VIDE
    /// (défaut) -> émission SQL BYTE-IDENTIQUE au legacy (mode 0). Posé par le daemon d'après les règles
    /// `field_filter` résolues pour le RÔLE/tenant/env de l'appelant (le cœur reste rôle-agnostique).
    pub fn with_masks(mut self, masks: FieldMaskSet) -> Schema {
        self.field_masks = masks;
        self
    }

    /// KNOWLEDGE OBJECTS : renvoie une COPIE du schéma avec le jeu de KO posé. `KnowledgeSet` VIDE
    /// (défaut) -> émission SQL BYTE-IDENTIQUE au legacy (mode 0). Posé par le daemon d'après les tables
    /// `knowledge_*` du tenant (alias/calc/eventtype/tag), tenant-wide (comme les règles de détection) :
    /// le cœur reste rôle-agnostique. Se COMPOSE avec `with_masks` (les KO passent par le chemin masqué).
    pub fn with_knowledge(mut self, ko: KnowledgeSet) -> Schema {
        self.field_knowledge = ko;
        self
    }

    /// PHASE B — ÉLAGAGE DE PROJECTION : renvoie une COPIE du schéma avec l'élagage de `message` posé.
    /// `false` (défaut) -> SELECT de base INCHANGÉ (mode 0 byte-identique, invariant absolu). `true` ->
    /// autorise le compilateur à retirer `message` du SELECT de base QUAND il est prouvé inutile en aval
    /// (`message_prunable`) ; sinon `message` est CONSERVÉ (défaut conservateur). Posé par le daemon sur
    /// les chemins lourds (détection périodique, Explore) — jamais un changement de résultat, seulement de RAM.
    pub fn with_message_pruning(mut self, on: bool) -> Schema {
        self.prune_message_projection = on;
        self
    }

    /// KEYSET PAGINATION : renvoie une COPIE du schéma avec la projection de `id` posée. `false`
    /// (défaut) -> `id` HORS du SELECT de base (mode 0 byte-identique, invariant absolu). `true` -> le
    /// compilateur ajoute `id` en FIN de projection des bases qui portent réellement la colonne (`event`),
    /// pour que le daemon pagine par curseur `(ts,id)` (parcours total sans plafond, cf. champ `cursor_id`).
    /// Posé par le daemon Plume sur le SEUL chemin browse Explore (search nu) — jamais un changement de
    /// résultat au-delà de la colonne `id` supplémentaire, seulement l'ajout de la clé de tri stable.
    pub fn with_cursor_id(mut self, on: bool) -> Schema {
        self.cursor_id = on;
        self
    }

    /// FILTRE DE LIGNES OBLIGATOIRE (H1 — isolation tenant) : renvoie une COPIE du schéma avec la contrainte
    /// `<column> IN (<ids>)` posée. Le compilateur l'AND-joint alors dans le WHERE de CHAQUE base compilée
    /// (finding ET runrecord, à toute profondeur) comme un ATOME booléen NON CONTOURNABLE. Liste d'ids VIDE
    /// -> `1=0` (fail-closed : matche RIEN, jamais tout — un grant vide renvoie zéro ligne). Non appelé
    /// (défaut `None`) -> émission SQL BYTE-IDENTIQUE au legacy (community / `events()` intacts). Posé par la
    /// console Forge d'après le jeu d'engagements accordés à l'appelant (`engagement_id`).
    pub fn with_row_filter(mut self, column: &str, ids: &[i64]) -> Schema {
        self.row_filter = Some(RowFilter { column: column.to_string(), ids: ids.to_vec() });
        self
    }
}

// FIELD FILTERS — déplacé dans le sous-module `mask` (voir en tête de fichier).

// KNOWLEDGE OBJECTS + MACROS — déplacés dans le sous-module `knowledge`.

// Helpers d'émission SOQL — déplacés dans le sous-module `helpers`.

// ---------------------------------------------------------------------------------------------
// Résolution de champs (paramétrée par json_field / real_cols).
// ---------------------------------------------------------------------------------------------

/// Résout un nom de champ en SQL : colonne réelle (ou alias d'un stage précédent, présent dans
/// `cols`) -> identifiant QUOTÉ (`soql_qid`, DIVERGENCE 2 : gère les mots réservés) ; sinon, si le
/// champ JSON de base est encore en portée (présent dans `cols`) -> `json_extract(jf,'$.<nom>')` ;
/// sinon -> identifiant quoté. `name` est déjà validé par `soql_ident_ok` (injection impossible).
fn soql_field(name: &str, cols: &[String], json_field: Option<&str>, d: &dyn Dialect) -> String {
    // KNOWLEDGE OBJECTS — ALIAS `canonical -> source`, résolu AVANT toute autre logique. On NE résout
    // QUE si `name` n'est pas déjà une colonne/alias VIVANT (un champ réel ou un alias de stage L'EMPORTE
    // sur un alias KO, sémantique Splunk). Le nom SOURCE traverse ensuite la résolution normale ET le masque
    // field-filters -> masquer la source couvre l'alias (pas de contournement). Scope KO vide -> `None` -> mode 0.
    let aliased = if cols.iter().any(|c| c == name) { None } else { ko_alias(name) };
    let name = aliased.as_deref().unwrap_or(name);
    // FIELD FILTERS : projection du SAC JSON ENTIER (`| table fields`) -> retire les clés masquées du
    // blob (fail-closed). VIDE -> blob inchangé (mode 0). Placé AVANT la résolution normale (fields est une
    // colonne réelle -> serait sinon renvoyé nu).
    if let Some(jf) = json_field {
        if name == jf && cols.iter().any(|c| c == jf) {
            let base = soql_qid(name);
            return bag_wrap(&base, cols).unwrap_or(base);
        }
    }
    if cols.iter().any(|c| c == name) {
        // COLONNE RÉELLE : déjà masquée à la projection de BASE (`base_proj_col`) une seule fois -> renvoyée
        // BRUTE ici (pas de re-masquage : évite le double-hachage ; les agrégats `values(col)` opèrent donc
        // sur la valeur déjà masquée de la sous-requête). Mode 0 -> identique (base brute).
        soql_qid(name)
    } else if let Some(jf) = json_field {
        if cols.iter().any(|c| c == jf) {
            // CLÉ DU SAC JSON : extraite du blob BRUT de base -> masquée ICI (une seule fois). Toute étape qui
            // passe par `soql_field` (projection/agrégat/rename/rex/sort/mvexpand/join-key) hérite du masque
            // AVANT agrégation. VIDE -> json_extract nu (mode 0 byte-identique).
            let base = d.json_extract(jf, name);
            mask_wrap(&base, name).unwrap_or(base)
        } else {
            soql_qid(name)
        }
    } else {
        soql_qid(name)
    }
}

/// CORE-2 : comme `soql_field`, mais QUALIFIE la référence de base (colonne réelle ou container JSON) par
/// l'alias de table `qual`. Utilisé UNIQUEMENT par `eventstats values/list` (sous-requête corrélée) : la
/// valeur de partition doit être comparée entre la ligne courante (`o`) et l'agrégat (`i`) SANS ambiguïté de
/// colonne (les deux sous-requêtes exposent `fields`/`src_ip`). Réplique EXACTEMENT la logique de résolution
/// et le masque de champ de `soql_field` — seule la RÉFÉRENCE de base est préfixée `qual.` (jamais le nom de champ
/// JSON, déjà validé `soql_ident_ok`). N'affecte aucun autre opérateur (mode 0 : chemin non emprunté).
fn soql_field_qual(name: &str, cols: &[String], json_field: Option<&str>, d: &dyn Dialect, qual: &str) -> String {
    let aliased = if cols.iter().any(|c| c == name) { None } else { ko_alias(name) };
    let name = aliased.as_deref().unwrap_or(name);
    if cols.iter().any(|c| c == name) {
        format!("{qual}.{}", soql_qid(name))
    } else if let Some(jf) = json_field {
        if cols.iter().any(|c| c == jf) {
            let base = d.json_extract(&format!("{qual}.{jf}"), name);
            mask_wrap(&base, name).unwrap_or(base)
        } else {
            format!("{qual}.{}", soql_qid(name))
        }
    } else {
        format!("{qual}.{}", soql_qid(name))
    }
}

/// Expr SQL pour FILTRER sur un champ au niveau base : colonne réelle -> identifiant QUOTÉ
/// (DIVERGENCE 2) ; sinon `json_extract(jf,'$.<nom>')`, avec `CAST(... AS REAL)` SI comparé à un
/// nombre — SAUF pour un champ INDEXÉ (`base.indexed_fields`, DIVERGENCE 3) où l'on garde la forme
/// canonique SANS cast pour matcher l'index expression. Pas de champ JSON (Forge) -> identifiant
/// quoté. `name` validé par `soql_ident_ok`.
fn soql_filter_field(name: &str, numeric: bool, base: &BaseDef, d: &dyn Dialect) -> Result<String, String> {
    // KNOWLEDGE OBJECTS — ALIAS `canonical -> source`, résolu AVANT le masque : filtrer sur un alias
    // dont la SOURCE est masquée est donc rejeté comme un filtre direct sur la source (pas de contournement
    // du masque de champ par alias). On NE résout que si `name` n'est pas une colonne réelle (le réel l'emporte).
    let aliased = if base.real_cols.iter().any(|c| c == name) { None } else { ko_alias(name) };
    let name = aliased.as_deref().unwrap_or(name);
    // FIELD FILTERS — ORACLE DE FILTRE : filtrer AU NIVEAU BASE sur un champ MASQUÉ pour l'appelant
    // permettrait d'extraire la valeur bit-à-bit via le NOMBRE DE LIGNES (`pan=41111* | stats count`,
    // `pan=~"^4[01]"`, wildcard, `in (...)`) — contournant Mask/Partial/Hash/Redact ET Deny (chaque
    // comparaison est un oracle). On REJETTE donc tout prédicat de base référençant un champ masqué
    // (comportement Splunk field-filters : un rôle qui ne peut pas VOIR un champ ne doit pas pouvoir le
    // SONDER). VIDE (mode 0 / champ non masqué) -> aucune erreur -> WHERE byte-identique au legacy.
    if mask_for(name).is_some() {
        return Err(format!("filtrage interdit sur le champ masqué « {name} » (field-filter actif pour votre rôle : un champ que vous ne pouvez pas voir ne peut pas être filtré)"));
    }
    Ok(if base.real_cols.iter().any(|c| c == name) {
        soql_qid(name)
    } else if let Some(jf) = &base.json_field {
        let indexed = base.indexed_fields.iter().any(|f| f == name);
        if numeric && !indexed {
            d.cast_real(&d.json_extract(jf, name))
        } else {
            d.json_extract(jf, name)
        }
    } else {
        soql_qid(name)
    })
}

// Base MÉTRIQUE (Plume/OBS) — verbatim, n'est atteinte que si schema.metric.
// `row_filter` (H1 — isolation tenant) : IDENTIQUE à `table_base`. `Some` -> AND-joint l'atome OBLIGATOIRE
// `(<col> IN (<ids>))` (ou `1=0` fail-closed si ids vide) via `RowFilter::cond_sql` (le MÊME helper que la
// feuille principale) dans le WHERE des DEUX accès physiques (`FROM metric` ET `FROM metric_rollup`) — ce
// sont les feuilles de la base métrique, aucun étage aval ne peut échapper au filtre. `None`
// (community/Plume/Forge) -> aucune condition ajoutée -> SQL byte-identique au legacy (invariant absolu).
fn metric_base(spec: &str, from: i64, to: i64, row_filter: Option<&RowFilter>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    let toks: Vec<&str> = spec.split_whitespace().collect();
    let name = match toks.get(1) {
        Some(n) => *n,
        None => return Err("metric : nom de métrique requis (ex: metric node_load1)".into()),
    };
    if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b':') {
        return Err(format!("metric : nom invalide : {name}"));
    }
    let mut conds = vec![format!("name='{}'", d.escape_literal(name))];
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
                conds.push(format!("{}='{}'", d.json_extract("labels", k), d.escape_literal(v)));
            }
        }
        i += 1;
    }
    if from > 0 { conds.push(format!("ts >= {from}")); }
    if to > 0 { conds.push(format!("ts <= {to}")); }
    // FILTRE DE LIGNES OBLIGATOIRE : AND-joint l'atome parenthésé au SOMMET du WHERE, AVANT le split
    // raw/roll -> les DEUX feuilles physiques (`metric` et `metric_rollup`) l'héritent à l'identique. Réutilise
    // `RowFilter::cond_sql` (helper de la feuille principale) -> injection-safe (ids i64 inlinés), fail-closed
    // (`1=0` si ids vide ou colonne invalide), sémantique AND-join identique. `None` -> aucun push -> byte-identique.
    if let Some(rf) = row_filter {
        conds.push(rf.cond_sql());
    }
    let mut sel = "ts,host,value".to_string();
    let mut selr = "ts,host,avg AS value".to_string();
    let mut ocols: Vec<String> = vec!["ts".into(), "host".into(), "value".into()];
    for l in &bylabels {
        if soql_ident_ok(l) {
            sel.push_str(&format!(",{} AS {}", d.json_extract("labels", l), soql_qid(l)));
            selr.push_str(&format!(",{} AS {}", d.json_extract("labels", l), soql_qid(l)));
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

/// Re-colle un filtre `champ op valeur` éclaté par des espaces (`source = "x"` -> `source="x"`),
/// pour tolérer la syntaxe SQL habituelle. Fusionne `<ident> <op…>` et tout jeton finissant par un
/// opérateur (= : ! < > ~) avec le jeton suivant. Un terme libre sans opérateur reste intact.
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

/// OP 2 (`in` / `not in`) — regex (compilée une fois) qui reconnaît une clause `field [not] in (...)`.
/// La liste `(a,b,c)` contient des virgules/espaces que `soql_tokenize` casserait : on l'extrait AVANT
/// le glue/tokenize via un PRÉ-PASS dédié au niveau STRING (cf. `soql_in_collect`). Bornée : la liste
/// interne `[^()]*` interdit toute parenthèse imbriquée (motif fini, pas de ReDoS).
fn soql_in_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?i)\b([A-Za-z_][A-Za-z0-9_]*)\s+(not\s+)?in\s*\(([^()]*)\)").unwrap())
}

/// CORE-1 : TRUE si l'octet `pos` de `s` tombe À L'INTÉRIEUR d'un littéral entre guillemets (nombre de `"`
/// AVANT `pos` impair). Même sémantique de guillemet que `soql_tokenize` (`"` bascule l'état, pas d'échappement).
/// `"` étant ASCII, compter les octets `"` == compter les caractères `"` (jamais un octet de continuation UTF-8) ;
/// `pos` provenant d'un match regex est une frontière de caractère valide -> `s[..pos]` est sûr.
fn soql_pos_quoted(s: &str, pos: usize) -> bool {
    s[..pos].bytes().filter(|&b| b == b'"').count() % 2 == 1
}

/// Parse les valeurs d'une liste `in (...)` : split sur `,`, trim, retire les guillemets, drop les vides.
fn soql_in_values(inner: &str) -> Vec<String> {
    inner.split(',').map(|v| v.trim().trim_matches('"').trim().to_string()).filter(|v| !v.is_empty()).collect()
}

/// Émet la condition SQL `IN (...)` / `NOT IN (...)` pour un champ FILTRÉ au niveau base. Liste 100 %
/// numérique -> passe par le chemin `numeric` de `soql_filter_field` (CAST REAL ou forme indexée) et
/// valeurs INLINE non quotées ; sinon valeurs ÉCHAPPÉES (single-quote, comme les autres filtres).
fn soql_in_cond(field: &str, negate: bool, vals: &[String], base: &BaseDef, d: &dyn Dialect) -> Result<String, String> {
    let numeric = vals.iter().all(|v| soql_num(v));
    let fexpr = soql_filter_field(field, numeric, base, d)?; // FIELD FILTERS : rejet si champ masqué (oracle in-clause)
    let list = if numeric {
        vals.join(",")
    } else {
        vals.iter().map(|v| format!("'{}'", d.escape_literal(v))).collect::<Vec<_>>().join(",")
    };
    // Une liste OU d'ÉGALITÉS textuelles est comparée CASSE-INSENSIBLE (`COLLATE NOCASE`) : aligne
    // `field in (a,b)` sur le défaut Sigma / l'égalité scalaire `(?i)` (sur-match, jamais un sous-match
    // silencieux sur des membres à casse variable). Numérique -> pas de casse. NÉGATION laissée BINARY :
    // un `not in` casse-sensible sur-INCLUT (jamais un angle mort). N'affecte PAS l'ingest (compilo de
    // requête uniquement) et aucune détection existante n'utilise un `in` textuel positif.
    let collate = if numeric || negate { "" } else { " COLLATE NOCASE" };
    Ok(format!("{fexpr}{collate} {} ({list})", if negate { "NOT IN" } else { "IN" }))
}

/// PRÉ-PASS `in`/`not in` (cf. `soql_in_re`) : extrait chaque clause `field [not] in (...)` de la chaîne
/// de filtres, pousse sa condition SQL dans `conds`, et renvoie la chaîne PRIVÉE de ces spans (le reste
/// suit le chemin de filtre normal : glue + tokenize + split d'opérateurs).
fn soql_in_collect(first: &str, base: &BaseDef, conds: &mut Vec<String>, d: &dyn Dialect) -> Result<String, String> {
    // FIELD FILTERS : `soql_in_cond` -> `soql_filter_field` REJETTE un `in (...)` sur un champ masqué (oracle). La
    // closure de `replace_all` ne peut pas court-circuiter -> on capture la 1re erreur et on la propage après.
    let mut err: Option<String> = None;
    let out = soql_in_re().replace_all(first, |caps: &regex::Captures| {
        if err.is_some() { return String::from(" "); }
        // CORE-1 : le pré-pass court AVANT le tokenize/quote-handling. Si l'IDENTIFIANT capturé (grp 1)
        // débute À L'INTÉRIEUR d'un littéral quoté, ce n'est PAS une vraie clause `in` : c'est le SUBSTRING
        // `<x> in (…)` d'une VALEUR quotée (ex. `message="user in (a,b)"`). On laisse le span INTACT -> le
        // tokenizer le traitera comme l'égalité `message = 'user in (a,b)'`. La borne `in`/`(`/`)` reste alors
        // au niveau quote 0 (aucun guillemet entre `field` et `(` : `\s+(not\s+)?in\s*\(` n'admet que blancs),
        // donc un vrai `foo in (a,b,c)` — même avec des VALEURS quotées `("a","b")` — matche toujours.
        let field_start = caps.get(1).map(|m| m.start()).unwrap_or(0);
        if soql_pos_quoted(first, field_start) {
            return caps[0].to_string(); // span verbatim : pas une clause `in`
        }
        let negate = caps.get(2).is_some();
        let vals = soql_in_values(&caps[3]);
        if vals.is_empty() {
            // CORE-4 : liste VIDE (`in ()` / `in (,,)`). SQLite refuse `x IN ()` (erreur de parse) -> on ne
            // peut pas l'émettre littéralement. Une liste vide = ensemble d'appartenance vide : `in` -> FAUX
            // partout (`1=0`), `not in` -> VRAI partout (`1=1`). JAMAIS un filtre ÉVANOUI (qui renverrait tout).
            conds.push(if negate { "1=1".to_string() } else { "1=0".to_string() });
            return String::from(" ");
        }
        match soql_in_cond(&caps[1], negate, &vals, base, d) {
            Ok(c) => conds.push(c),
            Err(e) => err = Some(e),
        }
        String::from(" ")
    }).into_owned();
    match err {
        Some(e) => Err(e),
        None => Ok(out),
    }
}

/// Parse une clause `in`/`not in` couvrant l'INTÉGRALITÉ de `expr` (pour l'étape `where`). Renvoie
/// `(field, negate, vals)` si tout `expr` est exactement une telle clause, sinon `None` (-> chemin
/// `where` normal `champ op valeur`).
fn soql_parse_in(expr: &str) -> Option<(String, bool, Vec<String>)> {
    let e = expr.trim();
    let caps = soql_in_re().captures(e)?;
    let m = caps.get(0)?;
    if m.start() != 0 || m.end() != e.len() { return None; } // match partiel -> pas une clause `in` pure
    let vals = soql_in_values(caps.get(3)?.as_str());
    if vals.is_empty() { return None; }
    Some((caps.get(1)?.as_str().to_string(), caps.get(2).is_some(), vals))
}

/// Construit la LISTE des conditions WHERE d'un FILTRE de base (pré-pass `in`/`not in`, glue/tokenize, boucle
/// d'opérateurs, terme libre). Extrait VERBATIM de `table_base` (parité stricte) + ajoute l'interception KO
/// `eventtype=`/`tag=` EN TÊTE de chaque jeton — no-op quand aucun eventtype/tag n'est défini (mode 0
/// byte-identique). `ko_depth` borne la récursion des eventtypes (un eventtype référençant un autre).
/// Réutilisé par `ko_special_token` pour détendre un filtre d'eventtype par le MÊME chemin (masque de champ inclus).
fn table_conds(first: &str, base: &BaseDef, d: &dyn Dialect, ko_depth: u32) -> Result<Vec<String>, String> {
    let mut conds: Vec<String> = Vec::new();
    // OP 2 (`in` / `not in`) : pré-pass dédié AVANT glue/tokenize. La liste `(a,b,c)` porte virgules/
    // espaces que `soql_tokenize` éclaterait ; on l'extrait au niveau string (gate `(` = perf, évite
    // la regex quand aucune liste possible). Les conditions IN sont poussées en TÊTE de `conds`.
    let cleaned;
    let first = if first.contains('(') {
        cleaned = soql_in_collect(first, base, &mut conds, d)?;
        cleaned.as_str()
    } else {
        first
    };
    for tk in soql_glue_spaced_ops(soql_tokenize(first)) {
        // KNOWLEDGE OBJECTS : `eventtype=NOM` / `tag=LABEL` DÉTENDUS ici (précèdent field=value). Scope
        // KO sans eventtype/tag -> `None` -> jeton traité normalement (mode 0 byte-identique).
        if let Some(cond) = ko_special_token(&tk, base, d, ko_depth)? {
            conds.push(cond);
            continue;
        }
        // `*` SEUL = joker « tous les événements » (convention SIEM/Splunk) -> AUCUN filtre (match-all),
        // et NON un terme libre `message LIKE '%*%'` (scan plein-texte lent qui ne matchait QUE les events
        // contenant littéralement « * »). N'affecte PAS les globs de valeur `champ=val*` (interceptés plus
        // haut par le branch `val.contains('*')`) ni un `*` quoté. Identité dans un AND (`search * source=x`).
        if tk == "*" {
            continue;
        }
        let mut matched = false;
        for op in ["=~", ">=", "<=", "!=", "=", ":", ">", "<"] {
            if let Some(pos) = tk.find(op) {
                let field = &tk[..pos];
                let val = &tk[pos + op.len()..];
                if soql_ident_ok(field) {
                    let fstr = soql_filter_field(field, false, base, d)?; // FIELD FILTERS : rejet si champ masqué (oracle)
                    if op == "=~" {
                        conds.push(format!("{fstr} REGEXP '{}'", d.escape_literal(val)));
                        matched = true;
                        break;
                    }
                    let sqlop = match op { "!=" => "<>", ":" => "=", _ => op };
                    if matches!(op, ":" | "=") && val.starts_with('~') {
                        conds.push(format!("{fstr} REGEXP '{}'", d.escape_literal(&val[1..])));
                    } else if matches!(op, ":" | "=" | "!=") && val.contains('*') {
                        let like = d.escape_literal(val).replace('*', "%");
                        let likeop = if op == "!=" { "NOT LIKE" } else { "LIKE" };
                        conds.push(format!("{fstr} {likeop} '{like}'"));
                    } else if soql_num(val) {
                        conds.push(format!("{} {sqlop} {val}", soql_filter_field(field, true, base, d)?));
                    } else {
                        conds.push(format!("{fstr} {sqlop} '{}'", d.escape_literal(val)));
                    }
                    matched = true;
                    break;
                }
            }
        }
        if !matched {
            match &base.freetext_col {
                // FIELD FILTERS : un terme LIBRE scanne la colonne plein-texte (message) via LIKE -> si CE champ est
                // masqué pour l'appelant, la recherche libre est un ORACLE sur sa valeur -> REJET fail-closed.
                Some(col) if mask_for(col).is_some() => {
                    return Err(format!("recherche plein-texte interdite : le champ « {col} » est masqué pour votre rôle"));
                }
                Some(col) => conds.push(d.like_contains(col, &d.escape_literal(&tk))),
                None => return Err(format!("terme libre non supporté ici : '{tk}'")),
            }
        }
    }
    Ok(conds)
}

// ---------------------------------------------------------------------------------------------
// PHASE B — ÉLAGAGE DE PROJECTION (`message`). Gate CONSERVATRICE : ne retire `message` du SELECT de
// BASE que quand il est PROUVÉ inutile en aval. Défaut (gate false) = comportement actuel (garder).
// ---------------------------------------------------------------------------------------------

/// Cherche l'identifiant `needle` (déjà minuscule) comme MOT COMPLET (bornes = non `[A-Za-z0-9_]`) dans
/// `hay`, insensible à la casse. Sur-approxime une RÉFÉRENCE de champ : « message » collé à un opérateur
/// (`message=`, `by message`, `values(message)`, `message,`) matche ; un AUTRE identifiant qui CONTIENT la
/// sous-chaîne (`error_message`, `a_message`) NE matche PAS (borne `_` = mot). Une référence à la VRAIE
/// colonne `message` s'écrit EXACTEMENT `message` bornée par un opérateur/espace/`(`/`,` -> toujours captée.
/// (Comparer les octets de la version minuscule : `to_ascii_lowercase` préserve les positions d'octets.)
fn contains_ident_word(hay: &str, needle: &str) -> bool {
    let h = hay.to_ascii_lowercase();
    let hb = h.as_bytes();
    let nlen = needle.len();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut from = 0usize;
    while let Some(off) = h[from..].find(needle) {
        let start = from + off;
        let end = start + nlen;
        let before_ok = start == 0 || !is_word(hb[start - 1]);
        let after_ok = end == hb.len() || !is_word(hb[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Une étape (par son 1er token + son texte brut) REPROJETTE-t-elle la sortie sur un jeu de colonnes FIXE
/// qui exclut le flux courant (donc élimine `message` de la sortie s'il n'y est pas re-nommé) ?
///  - `stats`/`timechart`/`top`/`rare` : agrègent/repliquent -> sortie = clés `by`/bucket + alias d'agrégat.
///  - `fields <liste>` / `table <liste>` : projection EXPLICITE (sauf `table *` / `table` nu = passe-plat).
/// Les autres étapes (`where`/`sort`/`head`/`eval`/`rex`/`rename`/`dedup`/`eventstats`/`rate`/`mvexpand`/
/// `lookup`/`append`/`join`) conservent `*` -> `message` reste vivant -> NON réductrices.
fn stage_is_narrowing(first: &str, stage: &str) -> bool {
    match first {
        "stats" | "timechart" | "top" | "rare" => true,
        "fields" => {
            // au moins un champ nommé (sinon SQL dégénéré : on ne compte pas comme réduction fiable).
            stage.split_whitespace().nth(1).is_some()
        }
        "table" => {
            let raw = stage.strip_prefix("table").unwrap_or("").trim();
            !raw.is_empty() && raw != "*"
        }
        _ => false,
    }
}

/// PROUVE qu'il est SÛR de retirer `message` du SELECT de base. VRAI (élaguer) SEULEMENT si les TROIS
/// conditions tiennent — sinon on GARDE `message` (défaut conservateur = comportement actuel) :
///
///  (1) AUCUN objet de savoir posé (`field_knowledge` vide). Écarte tout confond INDIRECT : un alias
///      `x -> message` ferait référencer la colonne SANS le token « message » ; un champ calculé/auto-lookup
///      injecté au-dessus de la base pourrait la lire ; une macro pourrait l'introduire. Scope KO vide ⇒ la
///      SEULE façon de référencer la colonne `message` est le token littéral `message` dans le texte -> capté.
///      (Les MASQUES de champ ne confondent PAS : ils enveloppent des références, n'en créent aucune d'indirecte.)
///  (2) Le token `message` (mot complet) N'APPARAÎT NULLE PART : ni dans le spec de base `f0` (terme libre,
///      `field=…`), ni dans AUCUNE étape pipe (texte BRUT, sous-requêtes `[...]` comprises). Sur-approxime
///      « message est référencé/re-projeté/re-nommé » : sa présence -> on garde. Son ABSENCE prouve qu'aucune
///      étape ne lit la colonne `message`, ne la nomme dans `table`/`fields`, ni ne la recrée (`eval message=…`,
///      `rename … AS message`, `rex … message`) — toutes ces formes contiennent le token.
///  (3) AU MOINS une étape RÉDUCTRICE (`stage_is_narrowing`) existe. Sans elle, la sortie = événements bruts
///      (`search` nu / `where` / `sort` / `head` / `eval` …) qui PROPAGENT `message` via `*` -> il est AFFICHÉ
///      -> on garde. Avec elle, `message` (jamais re-nommé, cf. (2)) est éliminé de la sortie et ne peut
///      revenir (toute ré-introduction par NOM contient le token, exclu par (2)).
///
/// Conjonction : `message` n'est NI référencé par aucune étape (2)+(1) NI présent dans la sortie (3)+(2) ->
/// l'ôter du SELECT interne ne change AUCUNE valeur d'AUCUNE ligne. (Une sous-requête `append`/`join`
/// décide SON propre élagage récursivement ; sa colonne `message` éventuelle est indépendante de celle,
/// déjà éliminée, de la ligne principale.)
fn message_prunable(f0: &str, pipe_stages: &[String], schema: &Schema) -> bool {
    // (1) aucun objet de savoir -> aucun confond indirect (alias/calc/eventtype/tag/macro/auto-lookup).
    if !schema.field_knowledge.is_empty() {
        return false;
    }
    // (2) token `message` absent partout (base + toutes les étapes, sous-requêtes incluses).
    if contains_ident_word(f0, "message") {
        return false;
    }
    if pipe_stages.iter().any(|s| contains_ident_word(s, "message")) {
        return false;
    }
    // (3) au moins une étape réductrice qui élimine `message` de la sortie.
    pipe_stages.iter().any(|s| {
        let first = s.split_whitespace().next().unwrap_or("");
        stage_is_narrowing(first, s)
    })
}

/// Renvoie une COPIE de `base` sans la colonne `message` dans `select_cols` (no-op si absente : bases Forge
/// finding/runrecord n'en portent pas). N'altère RIEN d'autre (json_field, freetext_col, real_cols, WHERE
/// intacts) : le filtre plein-texte `message LIKE …` et la résolution de champ restent inchangés — seule la
/// LISTE DE PROJECTION de base rétrécit. Appelé UNIQUEMENT quand `message_prunable` a prouvé la sûreté.
fn prune_message_col(base: &BaseDef) -> BaseDef {
    let mut b = base.clone();
    b.select_cols.retain(|c| c != "message");
    b
}

/// KEYSET PAGINATION — renvoie une COPIE de `base` avec la clé de tri stable `id` AJOUTÉE en FIN de
/// projection, UNIQUEMENT si la base porte RÉELLEMENT la colonne (`id` ∈ `real_cols`, cas `event`) et qu'elle
/// n'y figure pas déjà. Base sans `id` réel (Forge finding/runrecord) ou déjà présente -> no-op (base rendue
/// telle quelle). N'altère RIEN d'autre (json_field, freetext_col, real_cols, WHERE intacts) : seule la LISTE
/// DE PROJECTION s'allonge de `id`. Se compose après `prune_message_col` (les deux ne touchent que la projection).
fn append_cursor_id_col(mut base: BaseDef) -> BaseDef {
    if base.real_cols.iter().any(|c| c == "id") && !base.select_cols.iter().any(|c| c == "id") {
        base.select_cols.push("id".to_string());
    }
    base
}

// Base TABLE (search/runs) : filtres -> WHERE, puis SELECT <select_cols> FROM <table>.
// `env`  : Some("<env>") ET base.has_env_id -> ajoute `env_id = '<env>'` au WHERE (filtre
// environnement intra-tenant). None -> aucune condition (mode 0 / env unique) : SQL byte-identique.
// `row_filter` (H1 — isolation tenant) : Some -> AND-joint l'atome OBLIGATOIRE `(<col> IN (<ids>))` (ou
// `1=0` fail-closed si ids vide) DANS le WHERE de CETTE base. C'est la FEUILLE — l'unique accès physique à
// la table — donc aucun étage/sous-requête/UNION en aval ne peut y échapper (ils enveloppent une base déjà
// filtrée). None (community/Plume) -> aucune condition -> SQL byte-identique au legacy.
fn table_base(spec: &str, base: &BaseDef, from: i64, to: i64, env: Option<&str>, row_filter: Option<&RowFilter>, d: &dyn Dialect) -> Result<(String, Vec<String>), String> {
    let kw_sp = format!("{} ", base.keyword);
    let first = if let Some(r) = spec.strip_prefix(&kw_sp) {
        r.trim()
    } else if spec == base.keyword {
        ""
    } else {
        spec
    };
    let mut conds: Vec<String> = table_conds(first, base, d, 0)?;
    if from > 0 { conds.push(format!("ts >= {from}")); }
    if to > 0 { conds.push(format!("ts <= {to}")); }
    // FILTRE ENVIRONNEMENT : uniquement si la base porte `env_id` (event) ET qu'un env est
    // demandé (mode 1). Valeur validée en amont (env_slug_ok) + ré-échappée (soql_esc) -> pas
    // d'injection. Mode 0 / env absent -> conds inchangées -> parité SQL stricte.
    if base.has_env_id {
        if let Some(e) = env.filter(|e| !e.is_empty()) {
            conds.push(format!("env_id = '{}'", d.escape_literal(e)));
        }
    }
    // FILTRE DE LIGNES OBLIGATOIRE (H1 — isolation tenant) : posé DERNIER, AND-joint comme un ATOME
    // parenthésé au SOMMET du WHERE de base. Tous les autres `conds` sont eux-mêmes des atomes (égalité/
    // LIKE/REGEXP/IN, ou `(...)` pour eventtype/tag) -> l'AND-join ne peut pas les faire déborder de cet
    // atome. C'est la FEUILLE (unique `FROM <table>` physique) : chaque ligne qui remonte a DÉJÀ passé ce
    // filtre, donc aucun `WHERE`/`OR`/sous-requête/`UNION`/commentaire de la SoQL utilisateur (qui
    // enveloppe cette base ou recompile une base avec le MÊME schéma) ne peut lire une ligne hors-scope.
    // ids vide -> `1=0` (fail-closed : zéro ligne, jamais toutes). None -> rien -> SQL byte-identique.
    if let Some(rf) = row_filter {
        conds.push(rf.cond_sql());
    }
    let wc = if conds.is_empty() { String::new() } else { format!(" WHERE {}", conds.join(" AND ")) };
    // FIELD FILTERS : la projection de base est MASK-AWARE (cf. `base_proj_col`). VIDE (mode 0) ->
    // chaque colonne reste BRUTE non quotée -> SQL byte-identique au legacy. Ainsi un `search` NU (sans pipe)
    // — qui renvoie directement les colonnes de base — est déjà masqué (une colonne masquée n'est JAMAIS
    // servie brute), et un `| table fields` ne peut pas dumper une clé JSON masquée (retirée du blob).
    let jf = base.json_field.as_deref();
    let proj: Vec<String> = base.select_cols.iter().map(|c| base_proj_col(c, jf, &base.select_cols)).collect();
    Ok((
        format!("SELECT {} FROM {}{wc}", proj.join(","), base.table),
        base.select_cols.clone(),
    ))
}

// ---------------------------------------------------------------------------------------------
// Compilation du pipeline.
// ---------------------------------------------------------------------------------------------

pub struct Compiled {
    pub sql: String,
    pub columns: Vec<String>,
}

/// Convenance : compile -> SQL seule.
pub fn to_sql(soql: &str, from: i64, to: i64, schema: &Schema) -> Result<String, String> {
    compile_depth(soql, from, to, 0, schema).map(|(sql, _)| sql)
}

/// API publique : compile un pipeline soql en SQL read-only + colonnes de sortie.
pub fn compile(soql: &str, schema: &Schema) -> Result<Compiled, String> {
    compile_with_time(soql, 0, 0, schema)
}

/// Variante avec bornes temporelles (epoch) — `ts >= from`, `ts <= to` (0 = pas de borne).
pub fn compile_with_time(soql: &str, from: i64, to: i64, schema: &Schema) -> Result<Compiled, String> {
    let (sql, columns) = compile_depth(soql, from, to, 0, schema)?;
    Ok(Compiled { sql, columns })
}

/// Parse une liste `by <f1,f2,...>` (déjà jointe en une chaîne), valide chaque identifiant
/// (`soql_ident_ok`, préfixe d'erreur `label`) et construit les fragments d'émission PARTAGÉS par
/// `stats`/`timechart` (et le parse+validation de `eventstats`) :
/// - `fields` : les noms validés (deviennent des colonnes de sortie / clés GROUP BY) ;
/// - `sel`    : `["<soql_field> AS <qid>", ...]` (projection des champs de groupe) ;
/// - `gcols`  : les identifiants quotés joints par `,` (clause GROUP BY).
/// VERBATIM : mêmes appels `soql_field`/`soql_qid` et même ordre qu'avant l'extraction (parité stricte).
fn by_fields(raw: &str, label: &str, ocols: &[String], jf: Option<&str>, d: &dyn Dialect) -> Result<(Vec<String>, Vec<String>, String), String> {
    let fields: Vec<String> = raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    for f in &fields {
        if !soql_ident_ok(f) {
            return Err(format!("{label}champ invalide : {f}"));
        }
    }
    let sel: Vec<String> = fields.iter().map(|f| format!("{} AS {}", soql_field(f, ocols, jf, d), soql_qid(f))).collect();
    let gcols = fields.iter().map(|f| soql_qid(f)).collect::<Vec<_>>().join(",");
    Ok((fields, sel, gcols))
}
// Compilateurs PAR ÉTAPE — déplacés dans le sous-module `stages`. `compile_depth` (le DISPATCHER) reste ici.

fn compile_depth(soql: &str, from: i64, to: i64, depth: u32, schema: &Schema) -> Result<(String, Vec<String>), String> {
    if depth > 3 {
        return Err("sous-recherches trop imbriquées (max 3)".into());
    }
    // FIELD FILTERS : au depth 0, installe le jeu de masques du schéma dans le thread-local pour toute
    // la durée de la compilation (sous-recherches incluses : même thread, déjà couvert). VIDE -> no-op ->
    // parité stricte. RAII : restauré au Drop même en erreur/`?`. Les depths > 0 héritent du scope du parent.
    let _mask_guard = if depth == 0 {
        Some(MaskGuard::enter(&schema.field_masks))
    } else {
        None
    };
    // KNOWLEDGE OBJECTS : même mécanique que les field-filters — au depth 0, installe le jeu de KO du schéma dans son
    // thread-local pour toute la compilation (sous-recherches incluses). VIDE -> tous les hooks no-op -> parité
    // stricte. Les alias (`soql_field`/`soql_filter_field`) et `eventtype=`/`tag=` (`table_conds`) le lisent ;
    // les champs calculés sont injectés ci-dessous directement depuis `schema.field_knowledge`.
    let _ko_guard = if depth == 0 {
        Some(KnowGuard::enter(&schema.field_knowledge))
    } else {
        None
    };
    // MACROS : au DEPTH 0 uniquement, détend les appels `name(args)` en fragments SOQL AVANT le
    // découpage en étapes -> le texte détendu est parsé/compilé par CE MÊME compilateur fermé (jamais de SQL
    // brut, jamais de commande hors-enum). Les sous-recherches (`append`/`join`), déjà présentes dans la
    // chaîne depth-0, sont donc détendues UNE fois ici et recompilées telles quelles au depth > 0 (pas de
    // double expansion). Mode 0 (pas de backtick / aucune macro) -> chaîne inchangée -> parité stricte.
    let expanded = if depth == 0 {
        expand_macros(soql, &schema.field_knowledge)?
    } else {
        soql.to_string()
    };
    let stages = soql_split_pipes(&expanded);
    if stages.is_empty() {
        return Err("soql vide".into());
    }
    // S2 (a) — BORNE DU NOMBRE D'ÉTAPES. Rien ne bornait la LONGUEUR du pipeline (`depth > 3` ne borne que
    // l'imbrication des sous-recherches, `MACRO_MAX_LEN` que l'expansion de macros) : une requête de viewer
    // pouvait empiler des milliers d'étages, chacun enveloppant le SQL accumulé. Refus EXPLICITE au-delà de
    // la borne (cf. bandeau BORNES D'EXPLOITATION, `GUATX_SOQL_MAX_STAGES`) — jamais un pipeline tronqué.
    let max_stages = soql_max_stages()?;
    if stages.len() as i64 > max_stages {
        return Err(format!("pipeline trop long : {} étapes (maximum {max_stages})", stages.len()));
    }
    // S2 (b) — BORNE DE TAILLE DU SQL ÉMIS, vérifiée APRÈS CHAQUE étape (plus bas). `eventstats
    // values`/`list` interpole le SQL courant DEUX FOIS par étage -> croissance en 4^k : ~700 caractères de
    // requête suffisaient à produire des centaines de Mo de SQL (OOM PENDANT LA COMPILATION, donc avant tout
    // budget d'exécution du store). La borne coupe la croissance avec une erreur claire.
    let max_sql = soql_max_sql_bytes()?;
    let f0 = stages[0].trim();

    // FILTRE ENVIRONNEMENT : propagé aux bases qui portent `env_id` (cf. table_base). None en
    // mode 0 -> aucune injection -> parité SQL stricte.
    let env = schema.env_filter.as_deref();
    // FILTRE DE LIGNES OBLIGATOIRE : propagé À TOUTE PROFONDEUR aux bases (finding/runrecord) via
    // `table_base`. None (community/Plume) -> aucune injection -> parité SQL stricte. Comme le schéma est
    // passé tel quel aux sous-compilations (append/join), leurs bases héritent du MÊME filtre.
    let rf = schema.row_filter.as_ref();
    // DIALECT d'émission (readiness pivot) : porté par le schéma, `SqliteDialect` pour tous les schémas
    // actuels -> émission BYTE-IDENTIQUE au legacy. Passé aux helpers d'émission et aux étapes ci-dessous.
    let d = schema.dialect;
    // PHASE B — ÉLAGAGE `message` : décidé AVANT la base. `prune_message_projection` off (défaut) -> `false`
    // sans même analyser -> SELECT de base INCHANGÉ (mode 0 byte-identique). Sinon `message_prunable` PROUVE
    // la sûreté (aucune référence, réduction terminale, aucun KO). Décidé PAR APPEL `compile_depth` -> chaque
    // sous-requête (`append`/`join`) tranche son propre élagage. La copie élaguée (`owned`) ne vit QUE le temps
    // de l'appel `table_base` (référence empruntée) ; sans élagage, aucune copie n'est faite -> zéro overhead.
    let prune_msg = schema.prune_message_projection && message_prunable(f0, &stages[1..], schema);
    let (mut sql, mut ocols, json_field, is_table_base): (String, Vec<String>, Option<String>, bool) =
        if schema.metric && (f0 == "metric" || f0.starts_with("metric ")) {
            let (s, c) = metric_base(f0, from, to, rf, d)?;
            (s, c, None, false)
        } else if let Some(alt) = schema.alts.iter().find(|a| f0 == a.keyword || f0.starts_with(&format!("{} ", a.keyword))) {
            let owned;
            let base: &BaseDef = if prune_msg || schema.cursor_id {
                let b = if prune_msg { prune_message_col(alt) } else { alt.clone() };
                owned = if schema.cursor_id { append_cursor_id_col(b) } else { b };
                &owned
            } else {
                alt
            };
            let (s, c) = table_base(f0, base, from, to, env, rf, d)?;
            (s, c, alt.json_field.clone(), true)
        } else {
            let owned;
            let base: &BaseDef = if prune_msg || schema.cursor_id {
                let b = if prune_msg { prune_message_col(&schema.default) } else { schema.default.clone() };
                owned = if schema.cursor_id { append_cursor_id_col(b) } else { b };
                &owned
            } else {
                &schema.default
            };
            let (s, c) = table_base(f0, base, from, to, env, rf, d)?;
            (s, c, schema.default.json_field.clone(), true)
        };
    let jf = json_field.as_deref();

    // KNOWLEDGE OBJECTS — CHAMPS CALCULÉS : injectés comme des étapes `eval` IMPLICITES juste au-dessus
    // de la base (donc AVANT toute étape utilisateur -> disponibles partout en aval, et dans la projection
    // finale d'un `search` nu). RÉUTILISE `compile_eval` (chemin `eval` déjà injection-safe : l'expr traverse
    // `soql_expr_sql`, jamais de SQL brut). L'`eval` lit les colonnes de la base DÉJÀ masquée -> un calc
    // sur un champ masqué expose la VALEUR MASQUÉE, pas la valeur brute. VIDE (mode 0) / base métrique -> aucune
    // injection -> SQL byte-identique. (Base métrique exclue : ses colonnes (ts,host,value) ne portent pas les
    // champs événement qu'un calc référence.)
    if is_table_base {
        for (name, expr) in schema.field_knowledge.calcs() {
            let (ns, no) = compile_eval(&format!("eval {name} = {expr}"), sql, ocols, jf, d)?;
            sql = ns;
            ocols = no;
        }
        // AUTOMATIC LOOKUPS — injectés JUSTE au-dessus de la base (après les calc, comme un `| lookup`
        // implicite) : réutilise `compile_lookup` -> la clé passe par `soql_field` -> HÉRITE du masque de champ (une
        // clé masquée -> jointure sur valeur masquée -> pas d'enrichissement d'un champ que le rôle ne voit pas).
        // Inerte si `lookup_kv` est vide pour ce nom (LEFT JOIN -> NULL). VIDE (mode 0) -> aucune injection ->
        // SQL byte-identique. GeoIP = un auto-lookup dont la table est peuplée depuis une base BYO (config).
        for al in schema.field_knowledge.auto_lookups() {
            let mut toks: Vec<&str> = vec!["lookup", al.name.as_str(), al.key_field.as_str()];
            if !al.out_cols.is_empty() {
                toks.push("OUTPUT");
                for c in &al.out_cols {
                    toks.push(c.as_str());
                }
            }
            let (ns, no) = compile_lookup(&toks, sql, ocols, jf, d)?;
            sql = ns;
            ocols = no;
        }
    }

    for stage in &stages[1..] {
        let toks: Vec<&str> = stage.split_whitespace().collect();
        let (ns, no) = match toks.first().copied().unwrap_or("") {
            "stats" => compile_stats(&toks, sql, ocols, jf, d)?,
            "timechart" => compile_timechart(&toks, sql, ocols, jf, d, from, to)?,
            "where" => compile_where(&toks, sql, ocols, jf, d)?,
            "sort" => compile_sort(&toks, sql, ocols, jf, d)?,
            "head" | "limit" => compile_head(&toks, sql, ocols)?,
            "rex" => compile_rex(&toks, sql, ocols, jf, d)?,
            "fields" => compile_fields(&toks, sql, ocols, jf, d)?,
            "table" => compile_table(&toks, sql, ocols, jf, d)?,
            "rename" => compile_rename(&toks, sql, ocols, jf, d)?,
            "dedup" => compile_dedup(&toks, sql, ocols, jf, d)?,
            "top" | "rare" => compile_top(&toks, sql, ocols, jf, d)?,
            "eventstats" => compile_eventstats(&toks, sql, ocols, jf, d)?,
            "rate" => compile_rate(sql, ocols)?,
            "eval" => compile_eval(stage, sql, ocols, jf, d)?,
            "append" => compile_append(stage, sql, ocols, from, to, depth, schema)?,
            "join" => compile_join(stage, sql, ocols, from, to, depth, schema)?,
            "mvexpand" => compile_mvexpand(&toks, sql, ocols, jf, d)?,
            "lookup" => compile_lookup(&toks, sql, ocols, jf, d)?,
            other => return Err(format!("commande soql inconnue : '{other}'")),
        };
        sql = ns;
        ocols = no;
        // S2 (b) — la taille du SQL accumulé est vérifiée ICI, à chaque étage : une étape qui imbrique la
        // requête plusieurs fois (`eventstats values/list`) est arrêtée dès le franchissement de la borne,
        // avant que l'étage suivant ne la multiplie encore.
        if sql.len() as i64 > max_sql {
            return Err(format!(
                "requête trop complexe : le SQL généré dépasse {max_sql} octets — réduisez le nombre d'étapes (en particulier `eventstats values`/`list`, qui imbrique la requête)"
            ));
        }
    }
    // FIELD FILTERS : caviarde le SAC JSON s'il apparaît dans les colonnes FINALES (search nu / head /
    // sort / where qui ne re-projettent pas) -> aucune clé masquée ne fuit via le blob brut. VIDE -> no-op
    // (mode 0 byte-identique).
    let (sql, ocols) = mask_output_bag(sql, ocols, schema);
    Ok((sql, ocols))
}

#[cfg(test)]
#[path = "../soql_tests.rs"]
mod tests;
