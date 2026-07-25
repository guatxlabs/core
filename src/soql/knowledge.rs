//! KNOWLEDGE OBJECTS + MACROS — objets de savoir persistés & expansion de macros.
//!
//! Extrait mécaniquement de `soql.rs` (découpage en sous-modules) : PUR DÉPLACEMENT, aucune
//! ligne de logique/SQL modifiée — seules des visibilités privées ont été relevées à `pub(crate)`
//! pour rester joignables depuis le module parent. Comportement byte-identique (cf. `tests/plume_parity.rs`).

use super::*;

// =============================================================================================
// KNOWLEDGE OBJECTS — objets de savoir PERSISTÉS, auto-appliqués À LA COMPILATION SOQL.
//
// QUATRE types, tous portés par le `Schema` (VIDE -> mode 0 byte-identique) et posés par le daemon depuis
// des tables versionnées (parité Splunk : ce qui rend un contenu SOC PORTABLE) :
//   1. ALIAS de champ (`canonical -> source`) : une recherche sur le nom CANONIQUE résout le champ SOURCE.
//      Résolu au CHOKE-POINT `soql_field`/`soql_filter_field`, AVANT la résolution normale ET le masque de champ
//      -> masquer la SOURCE couvre AUTOMATIQUEMENT tous ses alias (impossible d'échapper au masque via alias).
//   2. CHAMPS CALCULÉS (`new = <eval>`) : injectés comme des étapes `eval` IMPLICITES au-dessus de la base
//      (RÉUTILISE le compilateur `eval` déjà injection-safe ; l'expr ne construit JAMAIS de SQL brut). Comme
//      l'`eval` inline, ils lisent les colonnes de la sous-requête DÉJÀ masquée -> pas de fuite.
//   3. EVENT TYPES (`nom -> filtre SOQL`) : `eventtype=NOM` se détend en le filtre stocké, compilé par le
//      MÊME chemin de filtre de base (donc masque de champ : un filtre sur champ masqué est REJETÉ).
//   4. TAGS (`label -> [(champ,valeur)]`) : `tag=LABEL` se détend en `(champ1=val1 OR champ2=val2 ...)` via
//      `soql_filter_field` (donc masque de champ respecté).
//
// INVARIANT MODE 0 : `KnowledgeSet` VIDE -> `ko_alias`/`ko_eventtype`/`ko_tag` renvoient `None`, la boucle de
// calc ne s'exécute pas, `ko_special_token` renvoie `None` -> le compilateur émet le SQL legacy À L'IDENTIQUE.
// Comme les masques de champ, le jeu est installé dans un thread-local le temps d'UNE compilation (depth 0).
// =============================================================================================

/// Jeu de KNOWLEDGE OBJECTS effectif pour la compilation courante. VIDE = aucun KO -> émission SQL
/// byte-identique au legacy (mode 0). Résolu par le daemon (tables `knowledge_*` du tenant) ; le cœur
/// l'applique sans connaître les rôles (les KO sont tenant-wide, comme les règles de détection).
/// MACRO — fragment SOQL nommé et paramétré, détendu TEXTUELLEMENT dans la requête AVANT le
/// découpage en étapes, PUIS compilé par le MÊME compilateur fermé (jamais de SQL brut, jamais de
/// commande hors-enum). `params` = noms de placeholders `$nom$` du corps (idents validés). Le corps
/// est authoré par un editor+ ; les ARGUMENTS d'appel sont, eux, validés à l'expansion (anti-injection).
#[derive(Clone, Debug)]
pub struct MacroDef {
    /// Noms des paramètres (placeholders `$nom$` dans `body`), dans l'ordre d'appel positionnel.
    pub params: Vec<String>,
    /// Corps SOQL du fragment (peut contenir des `$nom$`), stocké verbatim, JAMAIS interpolé en SQL brut.
    pub body: String,
}

/// AUTOMATIC LOOKUP — enrichissement de référence AUTO-APPLIQUÉ juste au-dessus de la base (comme
/// un `| lookup` implicite), SANS que l'utilisateur l'écrive. Réutilise `compile_lookup` -> la clé passe
/// par `soql_field` -> HÉRITE du masque de champ. GeoIP = un auto-lookup dont la table `lookup_kv` est peuplée
/// depuis une base BYO (MaxMind exporté), inerte si vide (LEFT JOIN -> NULL).
#[derive(Clone, Debug)]
pub struct AutoLookup {
    /// Nom de la table de référence (`lookup_kv.name`), ident validé.
    pub name: String,
    /// Champ-clé de l'événement sur lequel joindre (ident validé ; résolu via `soql_field` -> masqué).
    pub key_field: String,
    /// Colonnes de sortie à exposer depuis le JSON `val` (idents validés ; vide -> expose `val` brut).
    pub out_cols: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct KnowledgeSet {
    /// ALIAS : nom CANONIQUE recherché -> champ SOURCE réellement présent dans l'événement.
    aliases: std::collections::HashMap<String, String>,
    /// CHAMPS CALCULÉS : `(nouveau_champ, expression eval)`, ORDONNÉS (un calc peut réutiliser un précédent).
    calcs: Vec<(String, String)>,
    /// EVENT TYPES : nom -> chaîne de filtre SOQL (la classification sauvegardée).
    eventtypes: std::collections::HashMap<String, String>,
    /// TAGS : label -> liste de paires `(champ, valeur)` (un label peut couvrir plusieurs paires -> OR).
    tags: std::collections::HashMap<String, Vec<(String, String)>>,
    /// MACROS : nom -> définition (params + corps). Détendues À LA COMPILATION (depth 0), avant split.
    macros: std::collections::HashMap<String, MacroDef>,
    /// AUTO-LOOKUPS : enrichissements auto-appliqués au-dessus de la base (ordre stable = ordre d'ajout).
    auto_lookups: Vec<AutoLookup>,
}
impl KnowledgeSet {
    pub fn new() -> Self {
        Self::default()
    }
    /// VIDE -> émission legacy (mode 0). Court-circuite l'installation du scope et tous les hooks.
    pub fn is_empty(&self) -> bool {
        self.aliases.is_empty() && self.calcs.is_empty() && self.eventtypes.is_empty() && self.tags.is_empty()
            && self.macros.is_empty() && self.auto_lookups.is_empty()
    }
    /// Ajoute un ALIAS `canonical -> source`. Idents validés (`soql_ident_ok`, anti-injection de nom) ;
    /// une paire invalide/auto-référentielle est IGNORÉE (fail-closed : un KO malformé ne s'applique pas).
    pub fn add_alias(&mut self, canonical: impl Into<String>, source: impl Into<String>) {
        let (c, s) = (canonical.into(), source.into());
        if soql_ident_ok(&c) && soql_ident_ok(&s) && c != s {
            self.aliases.insert(c, s);
        }
    }
    /// Ajoute un CHAMP CALCULÉ `new_field = <expr eval>`. L'expr est compilée par le chemin `eval` (déjà
    /// injection-safe) AU MOMENT de la recherche ; stockée verbatim, JAMAIS interpolée en SQL brut ici.
    pub fn add_calc(&mut self, new_field: impl Into<String>, expr: impl Into<String>) {
        let n = new_field.into();
        if soql_ident_ok(&n) {
            self.calcs.push((n, expr.into()));
        }
    }
    /// Ajoute un EVENT TYPE `name` = filtre SOQL. `eventtype=name` compilera ce filtre.
    pub fn add_eventtype(&mut self, name: impl Into<String>, filter: impl Into<String>) {
        let n = name.into();
        if soql_ident_ok(&n) {
            self.eventtypes.insert(n, filter.into());
        }
    }
    /// Ajoute une paire `field=value` sous le TAG `label`. `tag=label` détend l'OR de toutes ses paires.
    pub fn add_tag(&mut self, label: impl Into<String>, field: impl Into<String>, value: impl Into<String>) {
        let (l, f, v) = (label.into(), field.into(), value.into());
        if soql_ident_ok(&l) && soql_ident_ok(&f) {
            self.tags.entry(l).or_default().push((f, v));
        }
    }
    pub fn alias(&self, canonical: &str) -> Option<&str> {
        self.aliases.get(canonical).map(|s| s.as_str())
    }
    pub fn eventtype(&self, name: &str) -> Option<&str> {
        self.eventtypes.get(name).map(|s| s.as_str())
    }
    pub fn tag(&self, label: &str) -> Option<&[(String, String)]> {
        self.tags.get(label).map(|v| v.as_slice())
    }
    pub fn has_eventtypes(&self) -> bool {
        !self.eventtypes.is_empty()
    }
    pub fn has_tags(&self) -> bool {
        !self.tags.is_empty()
    }
    pub fn calcs(&self) -> &[(String, String)] {
        &self.calcs
    }
    /// Ajoute une MACRO `name(params) = body`. Nom + chaque paramètre validés `soql_ident_ok` (anti-injection
    /// de nom) ; une macro malformée est IGNORÉE (fail-closed : elle ne s'installe pas). Le CORPS est stocké
    /// verbatim (jamais compilé ici) ; il ne sera jamais émis en SQL brut — l'expansion produit du SOQL parsé
    /// par le compilateur fermé. `params` avec doublons ou noms invalides -> macro rejetée.
    pub fn add_macro(&mut self, name: impl Into<String>, params: Vec<String>, body: impl Into<String>) {
        let n = name.into();
        if !soql_ident_ok(&n) {
            return;
        }
        if params.iter().any(|p| !soql_ident_ok(p)) {
            return; // un placeholder au nom non-ident casserait la substitution -> rejet
        }
        // doublon de param -> ambiguïté de substitution -> rejet (fail-closed).
        let mut seen = std::collections::HashSet::new();
        if params.iter().any(|p| !seen.insert(p.clone())) {
            return;
        }
        self.macros.insert(n, MacroDef { params, body: body.into() });
    }
    pub fn macro_def(&self, name: &str) -> Option<&MacroDef> {
        self.macros.get(name)
    }
    pub fn has_macros(&self) -> bool {
        !self.macros.is_empty()
    }
    /// Ajoute un AUTO-LOOKUP. Nom de table + champ-clé + colonnes de sortie validés `soql_ident_ok`
    /// (anti-injection de nom) ; un auto-lookup malformé est IGNORÉ (fail-closed). L'injection réutilise
    /// `compile_lookup` (mask-aware) -> jamais de SQL brut.
    pub fn add_auto_lookup(&mut self, name: impl Into<String>, key_field: impl Into<String>, out_cols: Vec<String>) {
        let (n, k) = (name.into(), key_field.into());
        if !soql_ident_ok(&n) || !soql_ident_ok(&k) {
            return;
        }
        if out_cols.iter().any(|c| !soql_ident_ok(c)) {
            return;
        }
        self.auto_lookups.push(AutoLookup { name: n, key_field: k, out_cols });
    }
    pub fn auto_lookups(&self) -> &[AutoLookup] {
        &self.auto_lookups
    }
}

// =============================================================================================
// MACROS — EXPANSION TEXTUELLE puis compilation par le MÊME compilateur fermé.
//
// SÛRETÉ (le seam macro->compilateur, cible d'audit) :
//   - L'expansion ne produit QUE du texte SOQL, ré-parsé/compilé par `compile_depth` (enum de commandes
//     FERMÉE, `soql_field`/`soql_filter_field` = choke-points de masque de champ). AUCUN chemin SQL brut, aucune
//     nouvelle commande, aucun accès à un champ masqué non-masqué : tout ce que produit une macro RE-TRAVERSE
//     le compilateur comme si l'utilisateur l'avait tapé.
//   - RÉCURSION BORNÉE : la boucle d'expansion est plafonnée (`MACRO_MAX_EXPANSIONS`) ET la longueur totale
//     bornée (`MACRO_MAX_LEN`) -> une macro qui s'appelle elle-même (ou une bombe exponentielle) est REJETÉE,
//     jamais bouclante/OOM.
//   - ARGUMENTS anti-injection : un argument d'appel est une VALEUR scalaire (`validate_macro_arg`) ; tout
//     caractère de rupture (backtick, `|`, `[`, `]`, `'`, `"`, `$`, `(`, `)`, virgule, espace/contrôle) est
//     REJETÉ -> un argument ne peut pas sortir du fragment prévu (ni injecter une commande/sous-recherche/
//     macro imbriquée/placeholder). Un placeholder `$x$` non résolu (param inconnu) -> REJET (fail-closed).
// MODE 0 : aucune macro définie ET aucun backtick dans la requête -> chaîne renvoyée INCHANGÉE (parité).
// =============================================================================================

const MACRO_MAX_EXPANSIONS: usize = 64;
const MACRO_MAX_LEN: usize = 65536;

/// Un argument d'appel de macro est-il une valeur scalaire SÛRE ? Charset FERMÉ (valeurs IP/CIDR/glob/
/// chemin/identité) ; tout le reste (rupture de fragment) est rejeté -> injection impossible par argument.
fn validate_macro_arg(a: &str) -> Result<(), String> {
    if a.is_empty() {
        return Err("argument de macro vide".into());
    }
    if a.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '*' | '@')) {
        Ok(())
    } else {
        Err(format!("argument de macro invalide (caractère interdit) : {a}"))
    }
}

/// Parse le contenu ENTRE backticks : `name` ou `name(a, b, ...)`. Nom validé `soql_ident_ok`, chaque
/// argument validé `validate_macro_arg` (anti-injection).
fn parse_macro_call(call: &str) -> Result<(String, Vec<String>), String> {
    let call = call.trim();
    if call.is_empty() {
        return Err("appel de macro vide (``)".into());
    }
    if let Some(p) = call.find('(') {
        if !call.ends_with(')') {
            return Err(format!("appel de macro mal formé : {call}"));
        }
        let name = call[..p].trim().to_string();
        if !soql_ident_ok(&name) {
            return Err(format!("nom de macro invalide : {name}"));
        }
        let inner = &call[p + 1..call.len() - 1];
        let args: Vec<String> = if inner.trim().is_empty() {
            Vec::new()
        } else {
            inner.split(',').map(|a| a.trim().to_string()).collect()
        };
        for a in &args {
            validate_macro_arg(a)?;
        }
        Ok((name, args))
    } else {
        if !soql_ident_ok(call) {
            return Err(format!("nom de macro invalide : {call}"));
        }
        Ok((call.to_string(), Vec::new()))
    }
}

/// Substitue les `$param$` du corps par les arguments (déjà validés). Un `$` RÉSIDUEL (placeholder de
/// paramètre inconnu, ou `$` parasite) -> REJET (fail-closed : le SOQL n'utilise jamais `$`).
pub(crate) fn substitute_macro(body: &str, params: &[String], args: &[String]) -> Result<String, String> {
    let mut out = body.to_string();
    for (pnam, aval) in params.iter().zip(args.iter()) {
        out = out.replace(&format!("${pnam}$"), aval);
    }
    if let Some(i) = out.find('$') {
        // Snippet char-safe : `&out[i..i+16]` PANIQUE si un char UTF-8 multi-octets chevauche l'offset i+16
        // (corps forgé `$` + 14 ASCII + `é`). On prend 16 CHARS à partir de `i` -> jamais de coupe intra-char.
        let snippet: String = out[i..].chars().take(16).collect();
        return Err(format!("placeholder de macro non résolu : {snippet}"));
    }
    Ok(out)
}

/// Détend les appels `` `name` `` / `` `name(args)` `` de `soql` via les macros de `ks`. Textuel-puis-parsé :
/// le résultat est du SOQL compilé par le compilateur fermé. Récursion + longueur BORNÉES. Mode 0 (aucun
/// backtick / aucune macro) -> chaîne inchangée.
pub fn expand_macros(soql: &str, ks: &KnowledgeSet) -> Result<String, String> {
    if !soql.contains('`') {
        return Ok(soql.to_string()); // FAST-PATH mode 0 : pas de sigil macro -> texte inchangé (parité)
    }
    if ks.macros.is_empty() {
        return Err("backtick de macro trouvé mais aucune macro n'est définie".into());
    }
    let mut cur = soql.to_string();
    let mut budget = MACRO_MAX_EXPANSIONS;
    loop {
        let open = match cur.find('`') {
            Some(i) => i,
            None => return Ok(cur), // plus aucun appel -> terminé
        };
        let rest = &cur[open + 1..];
        let close_rel = rest.find('`').ok_or("backtick de macro non fermé")?;
        let close = open + 1 + close_rel;
        let call = cur[open + 1..close].to_string();
        let (name, args) = parse_macro_call(&call)?;
        let def = ks
            .macros
            .get(&name)
            .ok_or_else(|| format!("macro inconnue : {name}"))?;
        if args.len() != def.params.len() {
            return Err(format!(
                "macro {name} : {} argument(s) attendu(s), {} fourni(s)",
                def.params.len(),
                args.len()
            ));
        }
        let expansion = substitute_macro(&def.body, &def.params, &args)?;
        cur.replace_range(open..=close, &expansion);
        if budget == 0 || cur.len() > MACRO_MAX_LEN {
            return Err("expansion de macro trop grande ou récursive (borne dépassée)".into());
        }
        budget -= 1;
    }
}

thread_local! {
    // Jeu de KO ACTIF pour la compilation en cours sur CE thread. VIDE hors compilation KO -> tous les hooks
    // no-op -> parité stricte. Installé/retiré par `KnowGuard` (RAII) au depth 0 de compile_depth (comme le
    // scope de masques). Les depths > 0 (sous-recherches) héritent du scope du parent (même thread).
    static KO_SCOPE: std::cell::RefCell<KnowledgeSet> = std::cell::RefCell::new(KnowledgeSet::new());
}

/// Garde RAII : installe le jeu de KO du schéma pour la durée d'UNE compilation (depth 0) et RESTAURE le
/// précédent au Drop (ré-entrance-safe + nettoyage sur `?`/erreur), exactement comme `MaskGuard` pour les field-filters.
pub(crate) struct KnowGuard(KnowledgeSet);
impl KnowGuard {
    pub(crate) fn enter(k: &KnowledgeSet) -> Self {
        let prev = KO_SCOPE.with(|c| c.replace(k.clone()));
        KnowGuard(prev)
    }
}
impl Drop for KnowGuard {
    fn drop(&mut self) {
        let restore = std::mem::take(&mut self.0);
        KO_SCOPE.with(|c| *c.borrow_mut() = restore);
    }
}

/// Résout un ALIAS `canonical -> source` dans le scope KO courant. `None` (scope vide / pas un alias) ->
/// l'appelant garde le nom d'origine -> mode 0 byte-identique.
pub(crate) fn ko_alias(canonical: &str) -> Option<String> {
    KO_SCOPE.with(|c| c.borrow().alias(canonical).map(|s| s.to_string()))
}
/// Filtre SOQL stocké d'un EVENT TYPE (ou `None`).
fn ko_eventtype(name: &str) -> Option<String> {
    KO_SCOPE.with(|c| c.borrow().eventtype(name).map(|s| s.to_string()))
}
/// Paires `(champ,valeur)` d'un TAG (ou `None`).
fn ko_tag(label: &str) -> Option<Vec<(String, String)>> {
    KO_SCOPE.with(|c| c.borrow().tag(label).map(|v| v.to_vec()))
}
fn ko_has_eventtypes() -> bool {
    KO_SCOPE.with(|c| c.borrow().has_eventtypes())
}
fn ko_has_tags() -> bool {
    KO_SCOPE.with(|c| c.borrow().has_tags())
}

/// KNOWLEDGE OBJECTS — INTERCEPTION `eventtype=NOM` / `tag=LABEL` dans un jeton de FILTRE de base.
/// Renvoie `Some(condition SQL)` si le jeton est un eventtype/tag CONNU du scope KO courant, sinon `None`
/// (le jeton suit le chemin de filtre NORMAL -> mode 0 byte-identique quand aucun KO n'est défini).
///
/// - `eventtype=NOM` : détend le filtre SOQL stocké via le MÊME `table_conds` (donc masque de champ, échappement,
///   allowlist d'idents) et AND-joint ses conditions. Récursion bornée (`ko_depth`) contre un eventtype qui
///   en référencerait un autre en boucle.
/// - `tag=LABEL` : OR des paires `champ=valeur` via `soql_filter_field` (donc filtre sur champ masqué REJETÉ).
///
/// Le NOM/label n'est JAMAIS interpolé en SQL (clé de HashMap uniquement) ; seules les valeurs stockées le
/// sont, échappées (`soql_esc`) — injection impossible.
pub(crate) fn ko_special_token(tk: &str, base: &BaseDef, d: &dyn Dialect, ko_depth: u32) -> Result<Option<String>, String> {
    // Fast-path scope vide : aucun eventtype/tag -> jamais d'interception (mode 0 strict).
    if !ko_has_eventtypes() && !ko_has_tags() {
        return Ok(None);
    }
    let pos = match tk.find(|c| c == '=' || c == ':') {
        Some(p) => p,
        None => return Ok(None),
    };
    let field = &tk[..pos];
    let name = &tk[pos + 1..];
    if name.is_empty() {
        return Ok(None);
    }
    match field {
        "eventtype" if ko_has_eventtypes() => {
            if ko_depth >= 4 {
                return Err("eventtype : imbrication trop profonde (max 4)".into());
            }
            let filter = ko_eventtype(name).ok_or_else(|| format!("eventtype inconnu : {name}"))?;
            let sub = table_conds(&filter, base, d, ko_depth + 1)?;
            if sub.is_empty() {
                return Ok(Some("1=1".to_string())); // filtre vide -> classification universelle
            }
            Ok(Some(format!("({})", sub.join(" AND "))))
        }
        "tag" if ko_has_tags() => {
            let pairs = ko_tag(name).ok_or_else(|| format!("tag inconnu : {name}"))?;
            let mut ors: Vec<String> = Vec::new();
            for (f, v) in &pairs {
                let numeric = soql_num(v);
                // knowledge-objects/field-filters : `soql_filter_field` REJETTE un champ masqué (oracle) -> tag sur champ masqué = erreur.
                let fexpr = soql_filter_field(f, numeric, base, d)?;
                if numeric {
                    ors.push(format!("{fexpr} = {v}"));
                } else {
                    ors.push(format!("{fexpr} = '{}'", d.escape_literal(v)));
                }
            }
            if ors.is_empty() {
                return Ok(None);
            }
            Ok(Some(format!("({})", ors.join(" OR "))))
        }
        _ => Ok(None),
    }
}
