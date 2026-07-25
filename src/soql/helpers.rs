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
    soql_tokenize_marked(s)
        .into_iter()
        .map(|t| t.text)
        .collect()
}

/// Un jeton, avec DE QUOI DÉCIDER SI SA PARTIE GAUCHE EST DU TEXTE QUE L'UTILISATEUR A QUOTÉ.
///
/// POURQUOI CETTE STRUCTURE : `soql_tokenize` JETTE les guillemets, donc l'aval ne peut plus
/// distinguer `search "user-agent=curl"` (une PHRASE que l'analyste cherche telle quelle) de
/// `search user-agent=curl` (un nom de champ mal écrit). Un simple booléen « ce jeton contenait un
/// guillemet » NE SUFFIT PAS, et c'est la cause racine MESURÉE du contournement : dans
/// `x-forwarded-for="10.0.0.1"` les guillemets n'entourent que la VALEUR, la partie gauche reste un
/// nom de champ nu — un booléen de jeton exemptait pourtant le jeton ENTIER. On conserve donc la
/// position réelle de la quotation, pas sa simple présence.
#[derive(Clone)]
pub(crate) struct SoqlTok {
    /// Texte du jeton, guillemets RETIRÉS (strictement ce que rendait l'historique `soql_tokenize`).
    pub(crate) text: String,
    /// Bornes OCTETS du jeton dans le texte qui a été tokenisé, GUILLEMETS COMPRIS : `&src[beg..end]`
    /// rend exactement les octets que l'utilisateur a tapés pour ce jeton (cf. `soql_bad_field_msg`,
    /// qui suggère ce texte-là et non une reconstruction).
    pub(crate) beg: usize,
    pub(crate) end: usize,
    /// Nombre d'OCTETS DE TÊTE de `text` qui ont été produits À L'INTÉRIEUR de guillemets.
    lead: usize,
    /// Un guillemet est resté OUVERT à la fin du texte : la quotation n'est pas close.
    open: bool,
}

impl SoqlTok {
    /// LA décision, prise ICI ET NULLE PART AILLEURS : « les `n` premiers octets de ce jeton
    /// sont-ils du texte que l'utilisateur a lui-même mis entre guillemets ? »
    ///
    /// C'est le SEUL prédicat d'exemption de la garde de nom de champ, et il porte sur un PRÉFIXE
    /// (la partie gauche d'un opérateur), jamais sur le jeton entier :
    /// dans `"user-agent=curl"` tout le jeton vient des guillemets, donc sa partie gauche aussi : c'est
    /// une PHRASE ; dans `x-forwarded-for="1"` seule la VALEUR en vient, la partie gauche reste nue :
    /// c'est un FILTRE, et la garde s'applique.
    ///
    /// Une quotation NON CLOSE n'exempte rien (`open`) : sinon un seul `"` égaré suffirait à faire
    /// passer n'importe quel jeton pour une phrase.
    pub(crate) fn quoted_prefix(&self, n: usize) -> bool {
        !self.open && self.lead >= n
    }

    /// Recolle `other` à la fin de ce jeton (cf. `soql_glue_spaced_ops`) : le TEXTE se concatène, les
    /// bornes source s'étendent jusqu'à celles d'`other` (le fragment fusionné couvre donc les octets
    /// SOURCE des deux, séparateurs compris), la quotation de tête reste celle du PREMIER fragment, et
    /// une quotation non close de l'un contamine le tout.
    pub(crate) fn absorb(&mut self, other: &SoqlTok) {
        self.text.push_str(&other.text);
        self.end = other.end;
        self.open |= other.open;
    }

    /// Les octets SOURCE dont ce jeton provient, guillemets RETIRÉS. C'est ce texte-là qui est
    /// suggéré à l'utilisateur (cf. `soql_bad_field_msg`) plutôt qu'une reconstruction depuis le
    /// jeton, laquelle perdait les espaces et la ponctuation qu'il avait tapés.
    ///
    /// Les guillemets sont RETIRÉS parce que ce sont des DÉLIMITEURS que le tokenizer ne conserve
    /// jamais : un terme qui en contient ne peut pas être re-quoté tel quel (SOQL n'a pas
    /// d'échappement). Que re-jouer la suggestion rende bien un plein-texte SUR CE TEXTE est MESURÉ
    /// (`s11_error_suggestion_is_the_users_own_text`), pas déduit.
    ///
    /// PORTÉE EXACTE, MESURÉE ET NON UNIVERSELLE (contre-exemples relevés sur 400 suggestions tirées
    /// d'un corpus adverse, IDENTIQUES sur le tag public v0.2.0 — limite pré-existante, pas une
    /// conséquence de la garde) : 389 rendent bien `message LIKE '%<ce texte>%'` ; les 11 autres
    /// rendent une ÉGALITÉ/COMPARAISON, parce que le texte suggéré commence lui-même par un
    /// identifiant VALIDE suivi d'un opérateur (`b: not in ()` -> `$.b = ' not in ()'`,
    /// `source=web … In ()` -> `"source" = 'web … In ()'`). Le texte reste celui de l'utilisateur ;
    /// c'est sa RELECTURE qui diffère, et elle suit le chemin quoté historique à l'octet près.
    pub(crate) fn source_unquoted(&self, src: &str) -> String {
        src[self.beg..self.end].replace('"', "")
    }
}

/// Comme `soql_tokenize`, mais rend des `SoqlTok` (position de la quotation + bornes source) au lieu
/// de simples `String`. La CONSTRUCTION DU TEXTE du jeton est inchangée ligne pour ligne : mêmes
/// jetons, même découpe, même retrait des guillemets — `soql_tokenize` n'en est plus qu'une projection.
pub(crate) fn soql_tokenize_marked(s: &str) -> Vec<SoqlTok> {
    let mut out: Vec<SoqlTok> = Vec::new();
    let mut cur = String::new();
    let (mut inq, mut lead, mut in_lead, mut beg, mut started) =
        (false, 0usize, true, 0usize, false);
    for (i, c) in s.char_indices() {
        match c {
            '"' => {
                if !started {
                    beg = i;
                    started = true;
                }
                inq = !inq;
            }
            c if c.is_whitespace() && !inq => {
                if !cur.is_empty() {
                    out.push(SoqlTok {
                        text: std::mem::take(&mut cur),
                        beg,
                        end: i,
                        lead,
                        open: false,
                    });
                }
                started = false;
                lead = 0;
                in_lead = true;
            }
            c => {
                if !started {
                    beg = i;
                    started = true;
                }
                // Le préfixe quoté s'arrête au PREMIER caractère produit hors guillemets.
                if in_lead {
                    if inq {
                        lead += c.len_utf8();
                    } else {
                        in_lead = false;
                    }
                }
                cur.push(c);
            }
        }
    }
    if !cur.is_empty() {
        out.push(SoqlTok {
            text: cur,
            beg,
            end: s.len(),
            lead,
            open: inq,
        });
    }
    out
}

pub(crate) fn soql_ident_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// TRUE si `s` a la FORME d'un nom de champ, c'est-à-dire si un jeton `s<op>valeur` PRÉTEND filtrer un
/// champ : commence par une lettre ASCII ou `_`, et ne contient que `[A-Za-z0-9_.-]`. Sert à distinguer
/// un nom de champ MAL ÉCRIT (`x-forwarded-for`, `http.status` -> erreur explicite) d'un terme dont la
/// partie gauche ne prétend pas nommer un champ (horodatage `10:00:00`, chemin/URL), qui garde le scan
/// plein-texte. Un identifiant VALIDE (`soql_ident_ok`) est un sous-ensemble de cette forme.
/// DEUX APPELANTS, tous deux dans `mod.rs` : le recollage `soql_glue_spaced_ops` (pour que la forme
/// espacée `foo-bar = 1` redevienne UN jeton) et la garde de `table_conds`. Cette fonction NE SAIT
/// RIEN des guillemets : l'exemption d'un texte quoté est tranchée par `SoqlTok::quoted_prefix`.
pub(crate) fn soql_fieldish(s: &str) -> bool {
    let mut cs = s.chars();
    matches!(cs.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

// ---------------------------------------------------------------------------------------------
// CLAUSE `champ [not] in (…)` — LE SEUL ENDROIT OÙ SON NOM DE CHAMP EST OBTENU.
//
// POURQUOI UN TYPE, ET PAS UNE REGEX PARTAGÉE. Deux étapes reconnaissent cette clause (le pré-pass
// du filtre de base, l'étape `where`). Tant que chacune lisait le groupe 1 d'une regex commune, la
// question « quel champ cette clause réclame-t-elle ? » se posait EN DEHORS de la définition de la
// clause, et un troisième appelant l'aurait posée à sa façon. Ici la regex et ses groupes sont
// PRIVÉS au module : un appelant reçoit un `InClause` dont TOUS les champs sont privés, et le seul
// accès au nom est `InClause::field()`, qui décide. Poser la question autrement ne compile pas.
// ---------------------------------------------------------------------------------------------

/// Grammaire de la clause. Groupe 1 = le JETON qui précède `in` — `[^\s]+`, c'est-à-dire jusqu'au
/// BLANC : la frontière de jeton que `soql_tokenize_marked` applique, et la seule de ce langage.
/// AUCUN caractère n'est déclaré « autorisé au milieu d'un nom » ni exclu du jeton. Groupe 2 =
/// `not ` optionnel ; groupe 3 = le mot-clé `in` (sa POSITION sert au test de quotation) ; groupe 4
/// = le DÉLIMITEUR OUVRANT de la liste ; groupe 5 = l'intérieur de la liste. `[^()]*` interdit
/// l'imbrication (motif fini, pas de ReDoS).
fn in_clause_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?i)([^\s]+)\s+(not\s+)?(in)\s*(\()([^()]*)\)").unwrap())
}

/// TRUE si l'octet `pos` de `s` tombe À L'INTÉRIEUR d'un littéral entre guillemets (nombre de `"`
/// AVANT `pos` impair). Même sémantique de guillemet que `soql_tokenize_marked` (`"` bascule l'état,
/// pas d'échappement). `"` étant ASCII, compter les octets `"` == compter les caractères `"` (jamais
/// un octet de continuation UTF-8) ; `pos` provient d'un match regex, donc c'est une frontière de
/// caractère valide -> `s[..pos]` est sûr.
fn quote_level_odd(s: &str, pos: usize) -> bool {
    s[..pos].bytes().filter(|&b| b == b'"').count() % 2 == 1
}

/// UNE clause `champ [not] in (…)` reconnue dans un texte de filtre. Champs PRIVÉS (cf. bandeau).
pub(crate) struct InClause<'a> {
    /// Le texte complet de la clause, tel qu'il a été tapé (préfixe de groupement compris).
    text: &'a str,
    /// Le JETON qui précède `in`, tel qu'il a été tapé.
    token: &'a str,
    /// Le préfixe de GROUPEMENT retiré de la tête du jeton (cf. `field`).
    grouping: &'a str,
    /// Le nom RÉCLAMÉ : le jeton MOINS son préfixe de groupement. Validé par `field()`, jamais lu ailleurs.
    claimed: &'a str,
    /// Les deux bouts de la clause dont le NIVEAU DE QUOTATION décide qu'elle est réelle (cf. `quoted_end`).
    token_start: usize,
    kw_start: usize,
    negate: bool,
    /// L'intérieur de la liste, brut.
    list: &'a str,
}

impl<'a> InClause<'a> {
    /// Construit la clause à partir d'un match. LE NOM EST DÉRIVÉ ICI, EN DEUX TEMPS :
    ///  1. LA FRONTIÈRE — le jeton va jusqu'au blanc (groupe 1), donc le nom réclamé est TOUT le
    ///     jeton. Rien n'est énuméré comme « autorisé au milieu d'un nom ».
    ///  2. LE GROUPEMENT — une répétition du délimiteur OUVRANT DE LA LISTE DE CETTE CLAUSE
    ///     (groupe 4, LU dans le match, pas écrit ici) en TÊTE du jeton n'appartient à aucun nom :
    ///     c'est du groupement. Elle est retirée EN TÊTE seulement, jamais au milieu, et réémise
    ///     verbatim par l'appelant (`grouping()`), donc rien du texte de l'utilisateur ne disparaît.
    ///
    /// Le reste doit être un identifiant ENTIER (`soql_ident_ok`, cf. `field`).
    fn from_caps(caps: &regex::Captures<'a>) -> InClause<'a> {
        let token = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let open = caps.get(4).map(|m| m.as_str()).unwrap_or("");
        let mut cut = 0usize;
        while !open.is_empty() && token[cut..].starts_with(open) {
            cut += open.len();
        }
        InClause {
            text: caps.get(0).map(|m| m.as_str()).unwrap_or(""),
            token,
            grouping: &token[..cut],
            claimed: &token[cut..],
            token_start: caps.get(1).map(|m| m.start()).unwrap_or(0),
            kw_start: caps.get(3).map(|m| m.start()).unwrap_or(0),
            negate: caps.get(2).is_some(),
            list: caps.get(5).map(|m| m.as_str()).unwrap_or(""),
        }
    }

    /// LE NOM DE CHAMP QUE CETTE CLAUSE RÉCLAME, ou le texte à REFUSER EN LE NOMMANT EN ENTIER.
    ///
    /// C'est le seul accès au nom : les champs sont privés, donc aucun appelant — présent ou futur —
    /// ne peut prendre un fragment du jeton pour un nom de champ. Conséquence dérivée : tout
    /// caractère situé ailleurs qu'en tête de groupement rend le jeton non identifiant et REFUSE la
    /// clause, y compris un caractère que ce code ne nomme nulle part. La seule erreur possible par
    /// omission est donc un REFUS, jamais un filtre sur un champ que l'utilisateur n'a pas nommé.
    pub(crate) fn field(&self) -> Result<&'a str, &'a str> {
        if soql_ident_ok(self.claimed) {
            Ok(self.claimed)
        } else if self.claimed.is_empty() {
            Err(self.token) // rien après le groupement : on nomme ce qui a été tapé
        } else {
            Err(self.claimed)
        }
    }

    /// Le préfixe de GROUPEMENT du jeton. L'appelant le RÉÉMET dans le texte résiduel : il n'est pas
    /// consommé par la clause, il appartient au reste du filtre.
    pub(crate) fn grouping(&self) -> &'a str {
        self.grouping
    }

    /// Le texte de la clause, tel qu'il a été tapé (échappatoire suggérée à l'utilisateur).
    pub(crate) fn text(&self) -> &'a str {
        self.text
    }

    pub(crate) fn negate(&self) -> bool {
        self.negate
    }

    /// Valeurs de la liste : split sur `,`, trim, retrait des guillemets, vides jetées.
    pub(crate) fn values(&self) -> Vec<String> {
        self.list.split(',').map(|v| v.trim().trim_matches('"').trim().to_string()).filter(|v| !v.is_empty()).collect()
    }

    /// CORE-1 : une clause n'est RÉELLE que si SES DEUX BOUTS — le début du jeton ET le mot-clé `in` —
    /// sont au niveau de quotation 0 dans `src`. Les deux tests sont nécessaires, chacun couvre un cas
    /// mesuré que l'autre laisse passer :
    ///  - `message="user in (a,b)"` : le jeton commence hors quotes (`message="user`) mais le mot-clé
    ///    est DANS le littéral -> pas une clause : le tokenizer en fait l'égalité `message = '…'`.
    ///  - `"abc def" in (1,2)` : le mot-clé est hors quotes mais le jeton (`def"`) commence DEDANS ->
    ///    pas une clause non plus : c'est une PHRASE quotée suivie de texte libre.
    pub(crate) fn quoted_end(&self, src: &str) -> bool {
        quote_level_odd(src, self.token_start) || quote_level_odd(src, self.kw_start)
    }
}

/// Reconnaît chaque clause `in` de `src` et remplace son texte par ce que rend `f`. La regex et ses
/// groupes ne sortent JAMAIS d'ici : `f` ne reçoit qu'un `InClause`.
pub(crate) fn in_clauses_replace(src: &str, mut f: impl FnMut(InClause<'_>) -> String) -> String {
    in_clause_re()
        .replace_all(src, |caps: &regex::Captures| f(InClause::from_caps(caps)))
        .into_owned()
}

/// La clause qui couvre `expr` EN ENTIER, groupement compris — pour l'étape `where`, qui n'a pas de
/// grammaire de groupement (mesuré : `where (count > 5)` est refusé, et l'était déjà). Un préfixe de
/// groupement signifie donc qu'il reste de la structure que `where` ne sait pas lire : ce n'est pas
/// une clause pure, et l'expression repart sur le chemin `champ op valeur`. Une liste VIDE non plus
/// (`in ()`) : le `where` scalaire la traite comme avant.
pub(crate) fn in_clause_whole(expr: &str) -> Option<(String, bool, Vec<String>)> {
    let caps = in_clause_re().captures(expr)?;
    let m = caps.get(0)?;
    if m.start() != 0 || m.end() != expr.len() {
        return None;
    }
    let c = InClause::from_caps(&caps);
    if !c.grouping().is_empty() {
        return None;
    }
    let vals = c.values();
    if vals.is_empty() {
        return None;
    }
    // `where` valide lui-même le nom (libellé propre, sans suggestion) : on lui rend le nom RÉCLAMÉ,
    // valide ou non, et jamais un fragment de jeton.
    let field = match c.field() {
        Ok(f) => f,
        Err(bad) => bad,
    };
    Some((field.to_string(), c.negate(), vals))
}

// ---------------------------------------------------------------------------------------------
// LISTE DE LABELS D'UN `by` — UN SEUL ENDROIT DÉCIDE DE SA VALIDITÉ.
//
// Quatre étapes prennent un `by` (`stats`, `timechart`, `eventstats` via `by_fields` ; `metric` via
// `metric_base`). Tant que chacune découpait la chaîne elle-même, la correction d'un `by` corrigeait
// UNE étape : le `.filter(|s| !s.is_empty())` retiré de `metric_base` est resté dans `by_fields`, et
// les trois étapes qui en dépendent ont continué à JETER les labels vides — `stats count by` émettait
// `SELECT ,COUNT(*) … GROUP BY ` (SQL invalide) et `timechart … by ,` perdait le regroupement demandé
// sans un mot. Le champ est PRIVÉ : la seule façon d'obtenir une liste de labels est `ByLabels::parse`.
// ---------------------------------------------------------------------------------------------

/// Le label qui a fait refuser un `by`. `Display` rend `(vide)` pour un label vide : un message qui
/// nomme le vide par une chaîne vide ne dit rien à l'utilisateur.
pub(crate) struct BadByLabel(String);

impl std::fmt::Display for BadByLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() { "(vide)" } else { self.0.as_str() })
    }
}

/// Les labels d'un `by`, VALIDÉS. Champ privé : impossible d'en fabriquer une hors de `parse`.
pub(crate) struct ByLabels(Vec<String>);

impl ByLabels {
    /// `raw` = tout ce qui suit `by`, jetons joints par un espace. AUCUN LABEL N'EST JETÉ : la liste
    /// est rendue telle quelle à `soql_ident_ok`, qui tranche — et lui seul. `by` NU donne
    /// `"".split(',')` = UN label vide, refusé comme les autres : aucun cas particulier à écrire, et
    /// aucun `by` demandé ne peut s'évaporer en silence.
    pub(crate) fn parse(raw: &str) -> Result<ByLabels, BadByLabel> {
        let labels: Vec<String> = raw.split(',').map(|s| s.trim().to_string()).collect();
        match labels.iter().find(|l| !soql_ident_ok(l)) {
            Some(bad) => Err(BadByLabel(bad.clone())),
            None => Ok(ByLabels(labels)),
        }
    }

    pub(crate) fn into_vec(self) -> Vec<String> {
        self.0
    }
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
                // LIMITE ASSUMÉE ET MESURÉE — la garde de nom de champ de `table_conds` n'a PAS
                // d'équivalent ici, et ne peut pas en avoir : dans une EXPRESSION, `-` est l'opérateur
                // de soustraction. `search | eval x = foo-bar` rend `(foo-bar)` et
                // `eval x = foo - bar` rend `(foo - bar)` : ces deux SQL ne sont PAS identiques à
                // l'octet (ils ne diffèrent QUE par des blancs — mesuré, cf.
                // `eval_is_the_documented_blind_spot_of_the_field_name_guard`), mais SQLite les compile
                // en le MÊME programme (mesuré : `EXPLAIN SELECT (foo-bar) FROM t` et
                // `EXPLAIN SELECT (foo - bar) FROM t` rendent un bytecode identique, sqlite 3.53.3).
                // L'entrée ne porte donc AUCUNE information qui
                // distingue « nom de champ mal écrit » de « soustraction de deux champs » (`severity-1`
                // est légitime et s'écrit sans blancs). Refuser `a-b` casserait l'arithmétique ; refuser
                // un identifiant inconnu casserait `eval x = dport * 2` sur une clé JSON, qui n'est pas
                // énumérable. Conséquence : un nom de champ mal écrit dans `eval` échoue à l'EXÉCUTION
                // (colonne inexistante) et non à la compilation. Les 16 autres étapes, elles, refusent
                // (cf. `eval_is_the_documented_blind_spot_of_the_field_name_guard`).
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
