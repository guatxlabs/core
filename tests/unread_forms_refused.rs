//! CE QUI N'EST PAS LU EST REFUSÉ : barre verticale entre guillemets, structure booléenne de `search`,
//! jeton d'agrégat ou d'option en trop.
//!
//! Trois formes de requête rendaient un résultat faux sans rien dire (mesuré sur v0.2.5, e143c7c) :
//!  - A. le découpage en étapes coupait sur une barre verticale ENTRE GUILLEMETS : `search
//!    message="error | where host=h1"` devenait une recherche `message='error'` suivie d'un `where` ;
//!  - B. `search` relie ses termes par ET et ne connaît ni `OR`, ni `AND`, ni `NOT`, ni groupement : ils
//!    tombaient en terme libre (`message LIKE '%OR%'`), et la recherche rendait zéro ligne, ou pire,
//!    seulement les événements dont le message contient une parenthèse ;
//!  - C. une étape jetait les jetons qu'elle ne lit pas : `stats count dc(user) by host` rendait le seul
//!    `count`, `timechart count dc(user)` le dernier agrégat, `sort ts desc` un tri ascendant.
//!
//! MÉTHODE — PAR EXÉCUTION. Chaque requête est compilée, puis son SQL EXÉCUTÉ sur une base SQLite en
//! mémoire (`python3` et son module `sqlite3`, qui enregistre `regexp` et `re_cap` comme le consommateur ;
//! `GUATX_CORE_PYTHON3` en donne le chemin). Attendu : les LIGNES rendues, ou un REFUS nommé à la
//! compilation. Sans moteur, la suite ÉCHOUE ; `GUATX_CORE_DIFFERENTIEL_FACULTATIF=1` l'autorise
//! explicitement (seuls les refus et le SQL de référence sont alors vérifiés).
//!
//! Chaque cas de A, B et C échoue sur e143c7c (ce qu'il y rendait est écrit en regard). Les TÉMOINS
//! restent admis et rendent le SQL produit par e143c7c, à l'octet (`REFERENCE_E143C7C`).

use guatx_core::soql::{compile, soql_split_pipes, Schema};
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Clone, Copy, Debug)]
enum Attendu {
    /// La compilation réussit ; l'exécution rend ces lignes (triées, `|` entre colonnes, NULL vide).
    Lignes(&'static str),
    /// La compilation refuse, par une erreur qui contient ce texte.
    Refus(&'static str),
    /// La compilation réussit ; l'EXÉCUTION échoue, par une erreur qui contient ce texte.
    ErreurSql(&'static str),
}
use Attendu::*;

struct Cas {
    q: &'static str,
    attendu: Attendu,
}

const fn c(q: &'static str, attendu: Attendu) -> Cas {
    Cas { q, attendu }
}

/// Données : (ts, host, url, message, user du sac JSON).
const LIGNES: &[(i64, &str, &str, &str, &str)] = &[
    (1, "h1", "/a", "x|y", "u1"),
    (2, "h2", "/b", "OR door", "u2"),
    (3, "h1", "/c", "(root) login", "u1"),
    (4, "h3", "/d", "a]b", "u3"),
    (5, "h1", "/e", "error | where host=h1", "u2"),
];

// ---------------------------------------------------------------------------------------------
// A — LE DÉCOUPAGE RESPECTE LES GUILLEMETS. Sur e143c7c :
//   A1, A2, A3, A4, A7 et A9 : erreur de compilation (`commande GXQL inconnue : '/b"'`, `'y"'`…) ;
//   A5 : zéro ligne, sans erreur (`message = 'error'` puis `where host = 'h1'`) ;
//   A6 : zéro ligne, sans erreur (le `]` entre guillemets décrémentait la profondeur de crochets, la
//        barre suivante ne coupait plus : `stats` et `count` devenaient des termes libres) ;
//   A8 : `0`, sans erreur (le guillemet non fermé s'arrêtait à la barre : `message = 'x'` puis `stats`) ;
//   A10 : erreur de compilation (`table : champ invalide : ts]`, le `]` entre guillemets fermait le
//        crochet) ; il tient aussi le saut des guillemets du refus de deux sous-recherches (C).
// ÉTAPE `rex` — son motif est lu BRUT, `\"` y est un guillemet du motif, qui ne ferme pas :
//   A11 : erreur (`commande GXQL inconnue : 'y)"'`, la barre du motif coupait l'étape) ;
//   A12 et A13 (guillemet échappé ET barre dans le même motif, au premier niveau puis dans une
//        sous-recherche) : erreur (`commande GXQL inconnue : 'u3)\"."'`) ;
//   A14 : un guillemet RÉELLEMENT non fermé dans `rex` : refusé aussi, mais par `rex : aucun groupe
//        nommé (?<nom>…) dans le motif` (le motif s'arrêtait à la barre : `abc`) ;
//   A15 : HORS `rex`, la barre oblique inverse n'échappe rien : trois guillemets, dont un non fermé ;
//        sur e143c7c, `0` sans erreur (`"message" = 'a\b'`, le texte après le 2e `"` jeté).
// ---------------------------------------------------------------------------------------------
const A_GUILLEMETS: &[Cas] = &[
    c(r#"search url=~"/a|/b" | stats count"#, Lignes("2")),
    c(r#"search message="x|y" | table ts"#, Lignes("1")),
    c(r#"search "x|y" | table ts"#, Lignes("1")),
    c(r#"search host=h1 | where url=~"/a|/c" | table ts"#, Lignes("1\n3")),
    c(r#"search message="error | where host=h1" | table ts"#, Lignes("5")),
    c(r#"search message="a]b" | stats count"#, Lignes("1")),
    c(r#"search host=h2 | table ts | append [search message="x|y" | table ts]"#, Lignes("1\n2")),
    c(r#"search message="x | stats count"#, Refus("guillemet non fermé")),
    c(r#"search message="x|y"#, Refus("guillemet non fermé")),
    c(r#"search host=h2 | table ts | append [search message="a]b" | table ts]"#, Lignes("2\n4")),
    c(r#"search | rex message "(?<a>x|y)" | table a"#, Lignes("\n\n\n\nx")),
    c(r#"search | rex fields "user.:\"(?<u>u1|u3)\"." | table ts,u"#, Lignes("1|u1\n2|\n3|u1\n4|u3\n5|")),
    c(r#"search host=h2 | table ts,u | append [search | rex fields "user.:\"(?<u>u1|u3)\"." | where u="u3" | table ts,u]"#, Lignes("2|\n4|u3")),
    c(r#"search | rex message "abc | table x"#, Refus("guillemet non fermé")),
    c(r#"search message="a\"b" | stats count"#, Refus("guillemet non fermé")),
];

// ---------------------------------------------------------------------------------------------
// B — `search` NE LIT NI `OR`, NI `AND`, NI `NOT`, NI GROUPEMENT. Sur e143c7c, tous compilaient :
//   B1 à B5 : zéro ligne (`message LIKE '%OR%'`, `'%NOT%'`, `'%AND%'`, `'%(host=h1%'`, `'%(%'`) ;
//   B6 : la ligne 3 seule — la seule dont le message contient des parenthèses — au lieu de 1,3,4,5 ;
//   B7 : zéro ligne (`host = '(h1' AND message LIKE '%h2)%'`) : la `)` de queue, qui ne ferme rien
//        dans son jeton, est la seule trace du groupement ;
//   B8, B9 : zéro ligne (`host = '(h1' AND message LIKE '%f(x))%'`, `message LIKE '%f(x))%'`) : la
//        `)` de trop SUIT une paire équilibrée, qui doit être refermée avant de la compter.
// Une paire équilibrée DANS le jeton n'est pas un groupement : `sleep(5)`, `foo(bar)`, `f()` restent
// cherchés tels quels (témoins).
// ---------------------------------------------------------------------------------------------
const B_SEARCH: &[Cas] = &[
    c("search host=h1 OR host=h2 | table ts", Refus("opérateur non lu : « OR »")),
    c("search NOT host=h1 | table ts", Refus("opérateur non lu : « NOT »")),
    c("search host=h1 AND url=/a | table ts", Refus("opérateur non lu : « AND »")),
    c("search (host=h1 url=/a) | table ts", Refus("parenthèse de groupement non lue")),
    c("search ( host=h2 ) | table ts", Refus("parenthèse de groupement non lue")),
    c("search (host in (h1,h3)) | table ts", Refus("parenthèse de groupement non lue")),
    c("search host=(h1 h2) | table ts", Refus("parenthèse de groupement non lue : « h2) »")),
    c("search host=(h1 f(x)) | table ts", Refus("parenthèse de groupement non lue : « f(x)) »")),
    c("search f(x)) | table ts", Refus("parenthèse de groupement non lue : « f(x)) »")),
];

// ---------------------------------------------------------------------------------------------
// C — UN JETON NON LU EST REFUSÉ. Sur e143c7c, sauf C4 et C5 (déjà refusés), tous compilaient :
//   C1 `h1|3, h2|1, h3|1` (le `dc(user)` disparaissait) ; C2 `3` (le `count` disparaissait) ;
//   C3 `5` dans une colonne `count` (l'alias disparaissait) ; C6 `0|3` (le DERNIER agrégat, `dc`) ;
//   C7 `0|5` (le DERNIER `span=`, 1d) ; C8 le seul `count` par hôte ; C9 `h1|3` (top global, `by url`
//   jeté) ; C10 `1` (tri ASCENDANT, `desc` jeté) ; C11 `1` (`2` jeté) ; C12 aucune ligne (`extra`
//   jeté) ; C13 la jointure sur `host` (`extra` jeté) ; C14 une erreur SQL à l'EXÉCUTION seulement
//   (`host` jeté) ; C15 et C16 `2, 4` (`foo` jeté) ; C17 la jointure (`max=0` jeté) ; C18 `1` (`url`
//   jeté) ; C19 un top 10 (`5` jeté) ; C20 les 5 lignes (`extra` jeté) ; C21 la jointure (`foo` jeté) ;
//   C22 déjà refusé, par « stats : syntaxe invalide 'n' » (le cas tient le message d'alias) ; C23 `5`
//   (`BY host` jeté : total global) ; C24 `5` sur chaque ligne (partition jetée) ; C25 déjà refusé,
//   par « syntaxe invalide 'host' » ; C26 et C27 compilaient la seconde sous-recherche DANS la première
//   (`host = 'h3]' AND message LIKE '%[search%' AND …`).
// ---------------------------------------------------------------------------------------------
const C_ETAPES: &[Cas] = &[
    c("search | stats count dc(user) by host", Refus("un seul agrégat est lu")),
    c("search | stats dc(user) count", Refus("un seul agrégat est lu")),
    c("search | stats count as n", Refus("un alias n'est pas lu")),
    c("search | stats count, dc(user)", Refus("syntaxe invalide 'count,'")),
    c("search | stats count,dc(user)", Refus("fonction stats inconnue")),
    c("search | timechart span=1h count dc(user)", Refus("un seul agrégat est lu")),
    c("search | timechart span=1h span=1d count", Refus("un seul `span=` est lu")),
    c("search | eventstats count dc(user) by host | table ts,count", Refus("un seul agrégat est lu")),
    c("search | top 1 host by url", Refus("top : jeton non lu : « by url »")),
    c("search | sort ts desc | head 1 | table ts", Refus("sort : jeton non lu : « desc »")),
    c("search | head 1 2 | table ts", Refus("head : jeton non lu : « 2 »")),
    c("search | mvexpand user extra", Refus("mvexpand : jeton non lu : « extra »")),
    c("search | lookup lk host extra OUTPUT v | table ts,v", Refus("lookup : jeton non lu : « extra »")),
    c("search | rate host", Refus("rate : jeton non lu : « host »")),
    c("search host=h2 | table ts | append foo [search host=h3 | table ts]", Refus("append : jeton non lu : « foo »")),
    c("search host=h2 | table ts | append [search host=h3 | table ts] foo", Refus("append : jeton non lu : « foo »")),
    c("search | join host max=0 [search host=h1 | stats count by host] | table ts", Refus("join : jeton non lu : « max=0 »")),
    c("search | sort ts url | head 1 | table ts", Refus("sort : jeton non lu : « url »")),
    c("search | top host 5", Refus("top : jeton non lu : « 5 »")),
    c("search | lookup lk host extra | table ts", Refus("lookup : jeton non lu : « extra »")),
    c("search | join host [search host=h1 | stats count by host] foo | table ts", Refus("join : jeton non lu : « foo »")),
    c("search | timechart count as n", Refus("timechart : jeton non lu : « as n » (un alias n'est pas lu")),
    c("search | stats count BY host", Refus("le regroupement s'écrit `by` en minuscules, « BY » n'est pas lu")),
    c("search | eventstats count BY host | table ts,count", Refus("le regroupement s'écrit `by` en minuscules")),
    c("search | timechart span=1h count BY host", Refus("le regroupement s'écrit `by` en minuscules")),
    c("search host=h2 | table ts | append [search host=h3] [search host=h1]", Refus("append : une seule sous-recherche est lue : « [search host=h1 »")),
    c("search | join host [search host=h1] [search host=h2] | table ts", Refus("join : une seule sous-recherche est lue : « [search host=h2 »")),
];

// ---------------------------------------------------------------------------------------------
// TÉMOINS — RESTENT ADMIS, mêmes lignes et même SQL que sur e143c7c. Ils couvrent ce que les refus ne
// doivent pas toucher : barre NON guillemetée, listes `in`/`not in`, valeur de champ qui porte des
// parenthèses, terme entre guillemets, minuscules `or`/`not` en terme libre, `or` dans `eval`, et la
// forme lue de chaque étape gardée.
// Puis : une `)` ENTRE GUILLEMETS n'est pas un groupement (`"h2)"`, la forme que conseille le refus) ;
// un motif `rex` qui porte un guillemet échappé `\"` (au premier niveau, et dans une sous-recherche)
// est lu comme sur e143c7c ; HORS `rex`, une valeur qui finit par une barre oblique inverse
// (`"C:\dir\"`) aussi. La forme `"…\"(?<u>[^\"]+)\""` émet le SQL de e143c7c, qui échoue À
// L'EXÉCUTION : `compile_rex` retire TOUS les guillemets de queue (`trim_matches('"')`), celui de `\"`
// compris, et le motif finit par une barre oblique inverse seule. Défaut de `compile_rex`, hors du
// découpage, laissé tel quel ; la forme qui ne finit pas par `\""` (`…\"."`) rend ses lignes.
// ---------------------------------------------------------------------------------------------
const TEMOINS: &[Cas] = &[
    c("search host=h1 | stats count", Lignes("3")),
    c("search host in (h1, h3) | table ts", Lignes("1\n3\n4\n5")),
    c("search host not in (h1) | table ts", Lignes("2\n4")),
    c("search url=~(?i)^/A$ | table ts", Lignes("1")),
    c("search url=/a) | table ts", Lignes("")),
    c(r#"search "OR" | table ts"#, Lignes("2\n5")),
    c(r#"search "(root)" | table ts"#, Lignes("3")),
    c("search or | table ts", Lignes("2\n5")),
    c("search not | table ts", Lignes("")),
    c("search host(in | table ts", Lignes("")),
    c("search sleep(5) | table ts", Lignes("")),
    c("search foo(bar) | table ts", Lignes("")),
    c("search f() | table ts", Lignes("")),
    c(r#"search | eval z = if(host="h1" or host="h2", 1, 0) | stats sum(z)"#, Lignes("4")),
    c("search | where host in (h1, h2) | stats count", Lignes("4")),
    c("search | stats count by host", Lignes("h1|3\nh2|1\nh3|1")),
    c("search | stats count", Lignes("5")),
    c("search | timechart span=1h dc(user)", Lignes("0|3")),
    c("search | eventstats count by host | table ts,count", Lignes("1|3\n2|1\n3|3\n4|1\n5|3")),
    c("search | top 1 host", Lignes("h1|3")),
    c("search | sort -ts | head 1 | table ts", Lignes("5")),
    c("search | lookup lk host OUTPUT v | table ts,v", Lignes("1|V1\n2|\n3|V1\n4|\n5|V1")),
    c("search host=h2 | table ts | append [search host=h3 | table ts]", Lignes("2\n4")),
    c("search | join host [search host=h1 | stats count by host] | table ts,count", Lignes("1|3\n2|\n3|3\n4|\n5|3")),
    c(r#"search "h2)" | table ts"#, Lignes("")),
    c(r#"search "root)" | table ts"#, Lignes("3")),
    c(r#"search | rex message "a\"b(?<x>.*)" | table x"#, Lignes("\n\n\n\n")),
    c(r#"search | rex fields "user.:\"(?<u>[^\"]+)\"." | table ts,u"#, Lignes("1|u1\n2|u2\n3|u1\n4|u3\n5|u2")),
    c(r#"search host=h2 | table ts,u | append [search host=h3 | rex fields "user.:\"(?<u>[^\"]+)\"." | table ts,u]"#, Lignes("2|\n4|u3")),
    c(r#"search | rex fields "user.:\"(?<u>[^\"]+)\"" | table ts,u"#, ErreurSql("user-defined function raised exception")),
    c(r#"search message="C:\dir\" | stats count"#, Lignes("0")),
];

// ---------------------------------------------------------------------------------------------
// Moteur d'exécution.
// ---------------------------------------------------------------------------------------------

const PY_SQLITE: &str = r#"
import re, sqlite3, sys
setup, q = sys.stdin.read().split("\n-- REQUETE\n", 1)
con = sqlite3.connect(":memory:")
con.create_function("regexp", 2, lambda p, s: None if p is None or s is None else int(re.search(p, str(s)) is not None), deterministic=True)
def re_cap(s, p, g):
    # `(?<nom>…)` (syntaxe du moteur `regex` du consommateur) s'écrit `(?P<nom>…)` en Python.
    if s is None or p is None:
        return None
    m = re.search(re.sub(r"\(\?<(?=[A-Za-z_])", "(?P<", p), str(s))
    return None if m is None else m.group(g)
con.create_function("re_cap", 3, re_cap, deterministic=True)
try:
    con.executescript(setup)
    rows = con.execute(q.strip().rstrip(";")).fetchall()
except sqlite3.Error as e:
    sys.stderr.write("Error: %s\n" % e)
    sys.exit(1)
for r in rows:
    sys.stdout.write("|".join("" if v is None else str(v) for v in r) + "\n")
"#;

/// Le moteur, ou `None` si aucun et que le différentiel est déclaré facultatif ; sinon la suite échoue.
fn moteur() -> Option<String> {
    let py = std::env::var("GUATX_CORE_PYTHON3").unwrap_or_else(|_| "python3".to_string());
    let ok = Command::new(&py).args(["-I", "-c", "import sqlite3"]).output().map(|o| o.status.success()).unwrap_or(false);
    match (ok, std::env::var("GUATX_CORE_DIFFERENTIEL_FACULTATIF").is_ok()) {
        (true, _) => Some(py),
        (false, true) => None,
        (false, false) => panic!(
            "exécution impossible : `{py}` (module sqlite3) absent ; l'installer, ou poser \
             GUATX_CORE_DIFFERENTIEL_FACULTATIF=1 pour ne vérifier que les refus et le SQL de référence"
        ),
    }
}

/// Exécute `sql` sur la base des `LIGNES` ; rend les lignes TRIÉES, ou l'erreur SQLite.
fn executer(py: &str, sql: &str) -> Result<String, String> {
    let esc = |v: &str| format!("'{}'", v.replace('\'', "''"));
    let mut script = String::from(
        "CREATE TABLE event(ts INTEGER, host TEXT, source TEXT, category TEXT, severity INTEGER, src_ip TEXT, dst_ip TEXT, url TEXT, xff TEXT, message TEXT, fields TEXT, dedup TEXT, id INTEGER, env_id TEXT);\n\
         CREATE TABLE lookup_kv(name TEXT, \"key\" TEXT, val TEXT);\n\
         INSERT INTO lookup_kv VALUES('lk','h1','{\"v\":\"V1\"}');\n",
    );
    for (ts, host, url, message, user) in LIGNES {
        script.push_str(&format!(
            "INSERT INTO event VALUES({ts},{},'web','auth',3,'10.0.0.1','10.0.0.2',{},'',{},{},NULL,{ts},NULL);\n",
            esc(host),
            esc(url),
            esc(message),
            esc(&format!(r#"{{"user":"{user}"}}"#)),
        ));
    }
    script.push_str("\n-- REQUETE\n");
    script.push_str(sql);
    let mut p = Command::new(py)
        .args(["-I", "-c", PY_SQLITE])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("lancement du moteur SQLite");
    p.stdin.take().expect("stdin").write_all(script.as_bytes()).expect("écriture du script");
    let out = p.wait_with_output().expect("sortie du moteur SQLite");
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let mut lignes: Vec<String> = String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect();
    lignes.sort();
    Ok(lignes.join("\n"))
}

/// Compile et exécute chaque cas ; IMPRIME ce que rend chaque requête (`--nocapture`), puis échoue en
/// listant chaque écart. Les écarts sont tous collectés : sur l'ancien code, la sortie est la mesure.
fn verifier(cas: &[Cas]) {
    let py = moteur();
    let mut ecarts = Vec::new();
    for cs in cas {
        let rendu = compile(cs.q, &Schema::events());
        let vu = match &rendu {
            Err(e) => format!("REFUS {e}"),
            Ok(cmp) => match &py {
                Some(py) => match executer(py, &cmp.sql) {
                    Ok(l) => format!("LIGNES {l:?}  (SQL {})", cmp.sql),
                    Err(e) => format!("ERREUR SQL {e}  (SQL {})", cmp.sql),
                },
                None => format!("COMPILE (non exécuté)  (SQL {})", cmp.sql),
            },
        };
        eprintln!("`{}`\n    -> {vu}", cs.q);
        let bon = match (cs.attendu, &rendu) {
            (Refus(m), Err(e)) => e.contains(m),
            (ErreurSql(m), Ok(cmp)) => match &py {
                Some(py) => executer(py, &cmp.sql).is_err_and(|e| e.contains(m)),
                None => true,
            },
            (Lignes(l), Ok(cmp)) => match &py {
                Some(py) => executer(py, &cmp.sql).as_deref() == Ok(l),
                None => true,
            },
            _ => false,
        };
        if !bon {
            ecarts.push(format!("`{}`\n    attendu {:?}\n    obtenu  {vu}", cs.q, cs.attendu));
        }
    }
    assert!(ecarts.is_empty(), "{} écart(s) sur {} :\n{}", ecarts.len(), cas.len(), ecarts.join("\n"));
}

#[test]
fn a_une_barre_entre_guillemets_n_est_pas_une_frontiere_d_etape() {
    verifier(A_GUILLEMETS);
}

#[test]
fn b_search_refuse_or_and_not_et_le_groupement() {
    verifier(B_SEARCH);
}

#[test]
fn c_un_jeton_qu_une_etape_ne_lit_pas_est_refuse() {
    verifier(C_ETAPES);
}

#[test]
fn temoins_les_formes_lues_rendent_les_memes_lignes() {
    verifier(TEMOINS);
}

// ---------------------------------------------------------------------------------------------
// LE DÉCOUPEUR PUBLIC (`soql_split_pipes`, appelé par Plume).
// ---------------------------------------------------------------------------------------------

/// Le découpeur de e143c7c, copié tel quel : la référence de toute entrée SANS guillemet.
fn decoupe_e143c7c(s: &str) -> Vec<String> {
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

#[test]
fn decoupeur_public_sans_guillemet_identique_a_e143c7c() {
    // TOUTES les entrées de longueur <= 8 sur un alphabet qui porte chaque caractère que le découpeur
    // lit (barre, deux crochets, blanc) plus une lettre : aucune entrée choisie à la main.
    const ALPHA: [char; 5] = ['a', ' ', '|', '[', ']'];
    let mut vues = 0u64;
    let mut buf = String::new();
    for len in 0..=8u32 {
        for mut idx in 0..(ALPHA.len() as u64).pow(len) {
            buf.clear();
            for _ in 0..len {
                buf.push(ALPHA[(idx % ALPHA.len() as u64) as usize]);
                idx /= ALPHA.len() as u64;
            }
            assert_eq!(soql_split_pipes(&buf), decoupe_e143c7c(&buf), "découpage changé sans guillemet : {buf:?}");
            vues += 1;
        }
    }
    assert_eq!(vues, 488_281, "l'alphabet ou la longueur ont changé sans le dire");
}

#[test]
fn decoupeur_public_respecte_les_guillemets() {
    let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    for (q, attendu) in [
        (r#"search url=~"a|b" | stats count"#, v(&[r#"search url=~"a|b""#, "stats count"])),
        (r#"search message="x|y""#, v(&[r#"search message="x|y""#])),
        (r#"search message="a]b" | stats count"#, v(&[r#"search message="a]b""#, "stats count"])),
        (r#"search message="a[b" | stats count"#, v(&[r#"search message="a[b""#, "stats count"])),
        (r#"search a | append [search m="x|y" | table ts] | head 1"#, v(&["search a", r#"append [search m="x|y" | table ts]"#, "head 1"])),
        (r#"search a | append [search m="x]" | table ts] | head 1"#, v(&["search a", r#"append [search m="x]" | table ts]"#, "head 1"])),
        // Une barre NON guillemetée reste une frontière, entre deux textes guillemetés aussi.
        (r#"search a="1" | where b="2""#, v(&[r#"search a="1""#, r#"where b="2""#])),
        // Guillemet NON FERMÉ : le reste appartient à l'étape où il s'ouvre ; aucune étape fantôme.
        (r#"search message="x | stats count"#, v(&[r#"search message="x | stats count"#])),
        (r#"search a | where m="x | stats count"#, v(&["search a", r#"where m="x | stats count"#])),
        // ÉTAPE `rex` : son motif est une expression régulière, où `\"` est un guillemet du motif et `\\`
        // une barre oblique inverse. Le découpage lit ses guillemets comme `rex` : `\"` ne ferme pas.
        (r#"search | rex m "a\"b|c" | table x"#, v(&["search", r#"rex m "a\"b|c""#, "table x"])),
        (r#"search | rex m "a\\" | table x"#, v(&["search", r#"rex m "a\\""#, "table x"])),
        (r#"search a | append [search | rex m "a\"|b" | table x] | head 1"#, v(&["search a", r#"append [search | rex m "a\"|b" | table x]"#, "head 1"])),
        (r#"search a | append [search | rex m "a\"]" | table x] | head 1"#, v(&["search a", r#"append [search | rex m "a\"]" | table x]"#, "head 1"])),
        // HORS `rex`, la barre oblique inverse n'échappe rien (même bascule que le tokenizer) : la valeur
        // de `m="C:\dir\"` finit par une barre oblique inverse, et `where m="a\"|b"` se ferme au 2e `"`.
        (r#"search m="C:\dir\" | stats count"#, v(&[r#"search m="C:\dir\""#, "stats count"])),
        (r#"search | where m="a\"|b" | stats count"#, v(&["search", r#"where m="a\""#, r#"b" | stats count"#])),
        // Le mot de commande se reconnaît comme à la compilation : `REX` n'est pas `rex`.
        (r#"search | REX m "a\" | table x"#, v(&["search", r#"REX m "a\""#, "table x"])),
        // La première étape non vide d'un niveau est la base, même derrière une barre de tête : jamais `rex`.
        (r#"| rex m "a\" | table x"#, v(&[r#"rex m "a\""#, "table x"])),
        (r#"search a | append [ | rex m "a\" | table x] | head 1"#, v(&["search a", r#"append [ | rex m "a\" | table x]"#, "head 1"])),
    ] {
        assert_eq!(soql_split_pipes(q), attendu, "{q}");
    }
}

// ---------------------------------------------------------------------------------------------
// D — LES TÉMOINS ÉMETTENT LE SQL DE e143c7c, À L'OCTET.
// ---------------------------------------------------------------------------------------------

fn sql_de(q: &str) -> String {
    match compile(q, &Schema::events()) {
        Ok(c) => c.sql,
        Err(e) => format!("ERR {e}"),
    }
}

/// Imprime la référence (`cargo test --test unread_forms_refused -- --ignored --nocapture`).
#[test]
#[ignore]
fn imprimer_la_reference() {
    for cs in TEMOINS {
        println!("    (\n        {:?},\n        r##\"{}\"##,\n    ),", cs.q, sql_de(cs.q));
    }
}

#[test]
fn temoins_sql_identique_a_e143c7c() {
    let mut ecarts = Vec::new();
    for cs in TEMOINS {
        let (_, attendu) = REFERENCE_E143C7C
            .iter()
            .find(|(q, _)| *q == cs.q)
            .unwrap_or_else(|| panic!("requête absente de la référence : {}", cs.q));
        let obtenu = sql_de(cs.q);
        if obtenu != *attendu {
            ecarts.push(format!("`{}`\n  attendu {attendu}\n  obtenu  {obtenu}", cs.q));
        }
    }
    assert_eq!(TEMOINS.len(), REFERENCE_E143C7C.len(), "la référence porte des requêtes hors mesure");
    assert!(ecarts.is_empty(), "{} écart(s) :\n{}", ecarts.len(), ecarts.join("\n"));
}

/// `(requête, SQL)` — produit par e143c7c (v0.2.5) avec `imprimer_la_reference`.
const REFERENCE_E143C7C: &[(&str, &str)] = &[
    (
        "search host=h1 | stats count",
        r##"SELECT COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "host" = 'h1')"##,
    ),
    (
        "search host in (h1, h3) | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "host" COLLATE NOCASE IN ('h1','h3'))"##,
    ),
    (
        "search host not in (h1) | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "host" NOT IN ('h1'))"##,
    ),
    (
        "search url=~(?i)^/A$ | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "url" REGEXP '(?i)^/A$')"##,
    ),
    (
        "search url=/a) | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "url" = '/a)')"##,
    ),
    (
        "search \"OR\" | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%OR%')"##,
    ),
    (
        "search \"(root)\" | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%(root)%')"##,
    ),
    (
        "search or | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%or%')"##,
    ),
    (
        "search not | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%not%')"##,
    ),
    (
        "search host(in | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%host(in%')"##,
    ),
    (
        "search sleep(5) | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%sleep(5)%')"##,
    ),
    (
        "search foo(bar) | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%foo(bar)%')"##,
    ),
    (
        "search f() | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%f()%')"##,
    ),
    (
        "search | eval z = if(host=\"h1\" or host=\"h2\", 1, 0) | stats sum(z)",
        r##"SELECT SUM("z") AS "sum" FROM (SELECT *, (iif(host='h1' or host='h2', 1, 0)) AS "z" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | where host in (h1, h2) | stats count",
        r##"SELECT COUNT(*) AS "count" FROM (SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) WHERE "host" IN ('h1','h2'))"##,
    ),
    (
        "search | stats count by host",
        r##"SELECT "host" AS "host",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "host""##,
    ),
    (
        "search | stats count",
        r##"SELECT COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)"##,
    ),
    (
        "search | timechart span=1h dc(user)",
        r##"SELECT (ts/3600)*3600 AS bucket,COUNT(DISTINCT json_extract(fields,'$.user')) AS "dc" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY bucket ORDER BY bucket"##,
    ),
    (
        "search | eventstats count by host | table ts,count",
        r##"SELECT "ts" AS "ts","count" AS "count" FROM (SELECT *, COUNT(*) OVER (PARTITION BY "host") AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | top 1 host",
        r##"SELECT "host" AS "host",COUNT(*) AS count FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "host" ORDER BY count DESC LIMIT 1"##,
    ),
    (
        "search | sort -ts | head 1 | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT * FROM (SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) ORDER BY "ts" DESC) LIMIT 1)"##,
    ),
    (
        "search | lookup lk host OUTPUT v | table ts,v",
        r##"SELECT "ts" AS "ts","v" AS "v" FROM (SELECT base.*, CASE WHEN json_valid(lk.val) THEN json_extract(lk.val,'$.v') END AS "v" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) base LEFT JOIN lookup_kv lk ON lk.name='lk' AND lk."key"="host")"##,
    ),
    (
        "search host=h2 | table ts | append [search host=h3 | table ts]",
        r##"SELECT "ts" FROM (SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "host" = 'h2')) UNION ALL SELECT "ts" FROM (SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "host" = 'h3'))"##,
    ),
    (
        "search | join host [search host=h1 | stats count by host] | table ts,count",
        r##"SELECT "ts" AS "ts","count" AS "count" FROM (SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) LEFT JOIN (SELECT "host" AS "host",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "host" = 'h1') GROUP BY "host") USING("host"))"##,
    ),
    (
        "search \"h2)\" | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%h2)%')"##,
    ),
    (
        "search \"root)\" | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%root)%')"##,
    ),
    (
        "search | rex message \"a\\\"b(?<x>.*)\" | table x",
        r##"SELECT "x" AS "x" FROM (SELECT *,re_cap("message",'a\"b(?<x>.*)','x') AS "x" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | rex fields \"user.:\\\"(?<u>[^\\\"]+)\\\".\" | table ts,u",
        r##"SELECT "ts" AS "ts","u" AS "u" FROM (SELECT *,re_cap("fields",'user.:\"(?<u>[^\"]+)\".','u') AS "u" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search host=h2 | table ts,u | append [search host=h3 | rex fields \"user.:\\\"(?<u>[^\\\"]+)\\\".\" | table ts,u]",
        r##"SELECT "ts", "u" FROM (SELECT "ts" AS "ts",json_extract(fields,'$.u') AS "u" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "host" = 'h2')) UNION ALL SELECT "ts", "u" FROM (SELECT "ts" AS "ts","u" AS "u" FROM (SELECT *,re_cap("fields",'user.:\"(?<u>[^\"]+)\".','u') AS "u" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "host" = 'h3')))"##,
    ),
    (
        "search | rex fields \"user.:\\\"(?<u>[^\\\"]+)\\\"\" | table ts,u",
        r##"SELECT "ts" AS "ts","u" AS "u" FROM (SELECT *,re_cap("fields",'user.:\"(?<u>[^\"]+)\','u') AS "u" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search message=\"C:\\dir\\\" | stats count",
        r##"SELECT COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "message" = 'C:\dir\')"##,
    ),
];
