//! FIELD FILTERS — masquage/contrôle d'accès AU NIVEAU CHAMP, appliqué À LA COMPILATION SOQL.
//!
//! Extrait mécaniquement de `soql.rs` (découpage en sous-modules) : PUR DÉPLACEMENT, aucune
//! ligne de logique/SQL modifiée — seules des visibilités privées ont été relevées à `pub(crate)`
//! pour rester joignables depuis le module parent. Comportement byte-identique (cf. `tests/plume_parity.rs`).
//!
//! LE SAC PEUT PORTER UNE VALEUR MASQUÉE dès que le jeu de masques de la compilation n'est pas vide
//! (`bag_may_carry_masked_value`, seule décision du compilateur pour tout ce qui protège le sac : refus du
//! prédicat de base, caviardage, clé de groupe, partition, taux, jointure, variantes de casse). Pourquoi :
//! le sac est écrit tel que le producteur de l'événement le fournit, rien n'en retire une clé qui porte le
//! nom d'une colonne réelle ; un sac peut donc porter `src_ip` avec la valeur même que le masque de la
//! colonne cache. Tout nom du jeu de masques est une clé à retirer du sac, colonne réelle ou non, vivante
//! dans la portée ou non (retirer une clé absente ne change rien). Le mode 0 est le jeu VIDE, et lui seul.
//! COÛT : un appelant dont le jeu de masques n'est pas vide ne peut plus filtrer sur le texte brut du sac
//! (il filtre par nom de clé, `search <clé>=…`), y compris tout appelant quand une règle de déni vaut pour
//! tous les rôles.

use super::*;

// =============================================================================================
// FIELD FILTERS — masquage/contrôle d'accès AU NIVEAU CHAMP, appliqué À LA COMPILATION SOQL.
//
// POURQUOI ICI (choke-point de provenance) : `soql_field` est l'UNIQUE fonction qui transforme un NOM de
// champ CIM en expression SQL de base (colonne réelle quotée OU `json_extract(fields,'$.<champ>')`). TOUTES
// les étapes qui exposent une valeur de champ passent par elle : projection (`table`/`fields`), agrégats
// (`stats`/`values`/`list`/`top`/`rare`/`dc`/`timechart`/`eventstats` via `soql_agg`), `rename`, `rex`,
// `sort`, `mvexpand`, clé de `join`/`lookup`. En enveloppant l'expression de base AU MOMENT DE LA
// COMPILATION, l'agrégat opère sur la valeur DÉJÀ masquée (`values(src_user)` -> GROUP_CONCAT du masque)
// et un `HASH` préserve la corrélation À L'INTÉRIEUR de l'agrégat -> impossible de fuir par agrégation ou
// aliasing. Le seul chemin qui court-circuite `soql_field` est l'identifiant BRUT d'`eval` (colonnes
// réelles) : il est masqué séparément dans `soql_expr_sql`.
//
// MODE 0 BYTE-IDENTIQUE : le jeu de masques est porté par le `Schema` et installé dans un thread-local le
// temps d'UNE compilation (thread-local car `soql_field` est une fonction libre appelée depuis ~15 sites ;
// la compilation d'une requête est synchrone sur UN thread). VIDE -> `mask_wrap` renvoie `None` -> l'appelant
// garde l'expression legacy telle quelle -> parité SQL stricte (prouvée par `tests/plume_parity.rs`).
// =============================================================================================

/// Action de masquage appliquée à la VALEUR d'un champ (jamais au nom de colonne, jamais interpolée dans du
/// SQL). Le daemon résout les règles `field_filter` (rôle/tenant/env) en ces actions AVANT la compilation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaskAction {
    /// Remplace toute valeur non-NULL par `***` (NULL reste NULL -> une ligne sans le champ reste vide).
    Mask,
    /// `***` + les 4 derniers caractères (« last-4 » stable, ex : PAN de carte). NULL reste NULL.
    MaskPartial,
    /// Hachage DÉTERMINISTE salé (`plume_fmask_hash`) : corrélation préservée, valeur non réversible.
    Hash,
    /// Supprime la valeur (colonne présente mais toujours NULL).
    Redact,
    /// Déni dur (classe PCI, comme la denylist de secrets) : NULL pour TOUS les rôles, admin compris.
    Deny,
}

/// Jeu de masques EFFECTIFS pour un appelant : nom de champ CIM -> action. VIDE = aucun masque -> émission
/// SQL byte-identique au legacy (mode 0). Résolu par le daemon (rôle/tenant/env) ; le cœur l'applique sans
/// connaître les rôles.
#[derive(Clone, Debug, Default)]
pub struct FieldMaskSet {
    map: std::collections::HashMap<String, MaskAction>,
}
impl FieldMaskSet {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    /// Enregistre (ou remplace) l'action de masque pour un champ.
    pub fn insert(&mut self, field: impl Into<String>, action: MaskAction) {
        self.map.insert(field.into(), action);
    }
    /// Action de masque pour `field`, ou `None` (champ non masqué).
    pub fn get(&self, field: &str) -> Option<MaskAction> {
        self.map.get(field).copied()
    }
    /// Noms des champs masqués (pour les gardes des surfaces non-SOQL, ex : /api/search qui doit refuser un
    /// filtre plein-texte/`fields:` probant une clé JSON masquée).
    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.map.keys().map(|s| s.as_str())
    }
}

thread_local! {
    // Jeu de masques ACTIF pour la compilation en cours sur CE thread. Vide hors compilation masquée ->
    // `mask_wrap` no-op -> parité stricte. Installé/retiré par `MaskGuard` (RAII) au depth 0 de compile_depth.
    static MASK_SCOPE: std::cell::RefCell<FieldMaskSet> = std::cell::RefCell::new(FieldMaskSet::new());
}

/// Garde RAII : installe le jeu de masques du schéma pour la durée d'UNE compilation (depth 0) et RESTAURE
/// le précédent au Drop (ré-entrance-safe : une compilation imbriquée qui repasserait par depth 0 ne
/// laisserait pas fuir son jeu, et une erreur/`?` en cours de compilation nettoie quand même le thread-local).
pub(crate) struct MaskGuard(FieldMaskSet);
impl MaskGuard {
    pub(crate) fn enter(m: &FieldMaskSet) -> Self {
        let prev = MASK_SCOPE.with(|c| c.replace(m.clone()));
        MaskGuard(prev)
    }
}
impl Drop for MaskGuard {
    fn drop(&mut self) {
        let restore = std::mem::take(&mut self.0);
        MASK_SCOPE.with(|c| *c.borrow_mut() = restore);
    }
}

/// Action de masque active pour `field` dans la compilation courante (thread-local). `None` -> pas de masque.
pub(crate) fn mask_for(field: &str) -> Option<MaskAction> {
    MASK_SCOPE.with(|c| c.borrow().get(field))
}

/// TRUE si un masque est actif dans la portée courante (scope non vide). GARDE de parité mode 0 : le
/// repli `json_extract` de `soql_expr_sql` (eval) ne diverge du legacy (identifiant nu) QUE lorsqu'un
/// masque existe -> le fix est strictement no-op quand rien n'est masqué (parité différentielle intacte).
pub(crate) fn mask_active() -> bool {
    MASK_SCOPE.with(|c| !c.borrow().is_empty())
}

/// Enveloppe l'expression SQL de BASE d'un champ (colonne réelle quotée, `json_extract`, ou identifiant eval)
/// selon l'action de masque active. `None` -> champ NON masqué : l'appelant garde la base à l'IDENTIQUE
/// (parité mode 0). Le masque agit sur la VALEUR, jamais sur le nom de colonne (pas d'injection : `base` est
/// déjà une expression sûre construite par le compilateur, `field` déjà validé par `soql_ident_ok`).
pub(crate) fn mask_wrap(base: &str, field: &str) -> Option<String> {
    let action = mask_for(field)?;
    Some(match action {
        // NULL préservé -> une ligne qui n'a PAS le champ reste vide (pas un faux `***`).
        MaskAction::Mask => format!("(CASE WHEN ({base}) IS NULL THEN NULL ELSE '***' END)"),
        MaskAction::MaskPartial => {
            format!("(CASE WHEN ({base}) IS NULL THEN NULL ELSE '***'||substr(CAST(({base}) AS TEXT),-4) END)")
        }
        // Hachage salé déterministe : la fonction scalaire est enregistrée par le consommateur sur sa
        // connexion read-only (comme `regexp`/`re_cap`). Sel par-base (jamais réversible sans le sel).
        MaskAction::Hash => format!("plume_fmask_hash({base})"),
        // REDACT et DENY caviardent la valeur à NULL dans la sortie. (DENY sur COLONNE RÉELLE est EN PLUS
        // bloqué au prepare() par l'authorizer SQLite côté daemon, même en SQL brut admin.)
        MaskAction::Redact | MaskAction::Deny => "NULL".to_string(),
    })
}

/// Chemins JSON (`'$.<clé>'`) de TOUS les noms du jeu de masques de la compilation courante. Sert à
/// CAVIARDER le sac `fields` (`search` nu, `| table fields`, et tout ce qui le lit) : sans ça, un rôle
/// restreint lirait la valeur masquée en clair dans le blob brut. Aucun nom n'est écarté, ni parce qu'il est
/// une colonne réelle, ni parce qu'il est vivant dans la portée : le sac peut porter une clé de ce nom (cf.
/// en-tête). Clés déjà validées `soql_ident_ok` -> pas d'injection dans le chemin JSON.
fn scope_json_key_paths() -> Vec<String> {
    MASK_SCOPE.with(|c| c.borrow().map.keys().map(|k| format!("'$.{k}'")).collect())
}

/// TRUE si le sac peut porter une valeur masquée : le jeu de masques courant n'est pas vide (cf. en-tête du
/// module). Faux en mode 0 (jeu vide : aucune émission ne change). Seule garde des comportements qui
/// protègent le sac.
pub(crate) fn bag_may_carry_masked_value() -> bool {
    mask_active()
}

/// Expression CAVIARDÉE du sac quand `name` désigne la colonne du sac vivante dans `cols` : le sac lui-même,
/// ou un alias d'étape qui n'en diffère que par la CASSE (`eval FIELDS = 1`) — SQLite résout les noms de
/// colonne sans tenir compte de la casse, et un tel alias se résout vers la PREMIÈRE colonne de ce nom,
/// c'est-à-dire le sac brut de la base. `qual` préfixe la référence (`i."fields"`, sous-requête corrélée).
/// `None` : ce n'est pas le sac, ou le jeu de masques est vide (`bag_may_carry_masked_value`) ->
/// l'appelant garde son émission historique à l'octet (mode 0).
pub(crate) fn bag_ref(name: &str, cols: &[String], json_field: Option<&str>, qual: Option<&str>) -> Option<String> {
    let jf = json_field?;
    if !bag_may_carry_masked_value() || !name.eq_ignore_ascii_case(jf) || !cols.iter().any(|c| c == jf) {
        return None;
    }
    if name != jf && !cols.iter().any(|c| c == name) {
        return None; // variante de casse NON vivante : c'est une clé du sac, résolue par `json_extract`
    }
    let base = match qual {
        Some(q) => format!("{q}.{}", soql_qid(jf)),
        None => soql_qid(jf),
    };
    bag_wrap(&base)
}

/// Clé de GROUP BY d'un champ de groupe `name` projeté par `fexpr` (sa `soql_field`), quand `name` ne
/// diffère du sac que par la CASSE (ou l'est). Dans un GROUP BY, SQLite résout un identifiant vers la colonne
/// d'ENTRÉE avant l'alias de sortie, et sans tenir compte de la casse : `GROUP BY "FIELDS"` groupe sur le sac
/// BRUT, que `FIELDS` soit le sac, un alias de savoir, ou une clé du sac lue par `json_extract`. Dès que le
/// jeu de masques n'est pas vide, on groupe donc sur l'expression projetée elle-même. `None` : nom sans
/// rapport avec le sac, ou jeu de masques vide -> l'appelant garde le nom quoté, à l'octet (mode 0).
pub(crate) fn bag_group_key(name: &str, fexpr: &str, cols: &[String], json_field: Option<&str>) -> Option<String> {
    let jf = json_field?;
    if !bag_may_carry_masked_value() || !name.eq_ignore_ascii_case(jf) || !cols.iter().any(|c| c == jf) {
        return None;
    }
    Some(fexpr.to_string())
}

/// Enveloppe la projection du SAC JSON ENTIER (`fields`) : retire du blob TOUS les noms masqués (fail-closed
/// — on RETIRE la clé plutôt que de la masquer, plus strict et sûr). JSON invalide -> NULL (jamais un blob
/// brut illisible qui contiendrait la clé en texte). `None` si le jeu de masques est vide -> blob inchangé
/// (mode 0 byte-identique).
pub(crate) fn bag_wrap(base: &str) -> Option<String> {
    let paths = scope_json_key_paths();
    if paths.is_empty() {
        return None;
    }
    Some(format!("(CASE WHEN json_valid({base}) THEN json_remove({base},{}) ELSE NULL END)", paths.join(",")))
}

/// Projection de base MASK-AWARE d'une COLONNE RÉELLE : DENY -> `NULL AS "col"` (aucune LECTURE brute ->
/// l'authorizer SQLite ne se déclenche PAS sur le SOQL compilé, mais TOUJOURS sur un `SELECT col` brut) ;
/// MASK/HASH/REDACT -> expression de masque `AS "col"` ; sinon la colonne BRUTE non quotée (parité mode 0
/// stricte). Le SAC JSON (`fields`) reste TOUJOURS BRUT ici : c'est la SOURCE d'extraction des clés en aval
/// (`| table src_user`) ; sa fuite en SORTIE (`search` nu, `| table fields`) est traitée par `soql_field`
/// (projection du blob) et `mask_output_bag` (colonnes finales). Masquer une colonne réelle UNE FOIS à la
/// base garantit que les agrégats/`| table col` héritent SANS double-masquage (le hash d'un hash serait faux).
pub(crate) fn base_proj_col(col: &str, json_field: Option<&str>, _cols: &[String]) -> String {
    if json_field == Some(col) {
        return col.to_string(); // sac JSON brut (source d'extraction) ; caviardé à la SORTIE
    }
    match mask_wrap(&soql_qid(col), col) {
        Some(w) => format!("{w} AS {}", soql_qid(col)),
        None => col.to_string(),
    }
}

/// FIELD FILTERS — caviardage du SAC JSON en SORTIE. Si les colonnes finales `ocols` contiennent le sac
/// (`fields`) — cas `search` NU, `| head`, `| sort`, `| where` qui ne re-projettent pas via `soql_field` — et
/// que le jeu de masques n'est pas vide, on RE-PROJETTE en retirant du blob tous les noms masqués. Les
/// autres colonnes passent BRUTES (déjà masquées à la base / par `soql_field`) -> aucun double-masquage.
/// VIDE / pas de sac en sortie -> `sql`/`ocols` INCHANGÉS (mode 0 byte-identique). Appliqué à chaque `compile_depth` (sous-requêtes
/// comprises) -> le blob brut ne fuit à aucune profondeur.
pub(crate) fn mask_output_bag(sql: String, ocols: Vec<String>, schema: &Schema) -> (String, Vec<String>) {
    let jf = match schema.default.json_field.as_deref() {
        Some(j) => j,
        None => return (sql, ocols),
    };
    if !ocols.iter().any(|c| c == jf) {
        return (sql, ocols);
    }
    let w = match bag_wrap(&soql_qid(jf)) {
        Some(w) => w,
        None => return (sql, ocols), // jeu de masques vide -> blob inchangé
    };
    // Une colonne de sortie qui ne diffère du sac que par la CASSE (alias `FIELDS`) se résout, dans SQLite,
    // vers le sac BRUT (première colonne de ce nom) : elle est caviardée comme le sac.
    let proj: Vec<String> = ocols
        .iter()
        .map(|c| if c.eq_ignore_ascii_case(jf) { format!("{w} AS {}", soql_qid(c)) } else { soql_qid(c) })
        .collect();
    (format!("SELECT {} FROM ({sql})", proj.join(",")), ocols)
}
