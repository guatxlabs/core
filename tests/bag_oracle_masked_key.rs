//! LE SAC JSON PEUT PORTER UNE VALEUR MASQUÉE : AUCUNE VOIE NE LIT SON TEXTE BRUT.
//!
//! Le masquage de champ se décide à la compilation. Le SAC (`fields`) est écrit tel que le producteur de
//! l'événement le fournit : il peut porter une clé masquée pour l'appelant, y compris une clé au nom d'une
//! colonne réelle masquée (`src_ip`, `message`…) avec la valeur même que le masque de la colonne cache.
//! Le sac est une colonne réelle : toute voie qui le lit BRUT relit cette valeur en clair et en fait un
//! oracle (nombre de lignes, groupes, valeur rendue). Dès que le jeu de masques n'est pas vide, le sac
//! est donc caviardé de TOUS les noms masqués, ou la voie est refusée.
//!
//! MÉTHODE — DIFFÉRENTIELLE, PAR EXÉCUTION. Chaque requête est compilée avec un jeu de masques, puis
//! EXÉCUTÉE (SQLite en mémoire) sur plusieurs jeux de données qui ne diffèrent QUE par la valeur (ou la
//! présence) de la clé masquée dans le sac. Une voie fuit si son résultat change d'un jeu à l'autre, ou
//! si la valeur apparaît dans une sortie. Attendu pour chaque voie : REFUS nommé à la compilation, ou
//! résultat IDENTIQUE — sans erreur SQL et sans la valeur — sur tous les jeux (une requête en erreur
//! partout serait « identique » sans rien prouver). Configurations : une clé du sac `secret` ; un jeu
//! mixte ; et une colonne réelle masquée dont le sac porte une clé du même nom (`src_ip`, vivante ou
//! retirée par `table`, `message` avec élagage de projection, `id`, `dedup`).
//!
//! MOTEUR : le binaire `sqlite3` (`GUATX_CORE_SQLITE3` en donne le chemin), à défaut `python3` et son
//! module `sqlite3` (`GUATX_CORE_PYTHON3`), qui enregistre `regexp` comme le fait le consommateur. Sans
//! aucun des deux, la suite ÉCHOUE : un différentiel sauté laisserait passer toute fuite en vert.
//! `GUATX_CORE_DIFFERENTIEL_FACULTATIF=1` l'autorise explicitement (seuls les refus sont alors vérifiés).
//!
//! MODE 0 = JEU DE MASQUES VIDE, et lui seul : `mode0_sql_identique_a_la_reference` fige le SQL émis
//! sans masque pour TOUTES les requêtes de la mesure. La référence a été produite par le compilateur
//! d'avant la garde (v0.2.4). Avec un jeu non vide, le SQL change par construction.

use guatx_core::soql::{compile, FieldMaskSet, KnowledgeSet, MaskAction, Schema};
use std::io::Write;
use std::process::{Command, Stdio};

/// Marqueur du refus nommé : un prédicat qui lirait le sac BRUT alors qu'un masque de champ est actif.
const REFUS_SAC: &str = "peut porter une valeur masquée";

/// Jeux de données : `(ts, valeur de la clé masquée dans le sac)` ; `None` = clé absente du sac.
const JEUX: &[(&str, &[(i64, Option<&str>)])] = &[
    ("abc,abc", &[(1, Some("abc")), (2, Some("abc"))]),
    ("abc,xyz", &[(1, Some("abc")), (2, Some("xyz"))]),
    ("xyz,xyz", &[(1, Some("xyz")), (2, Some("xyz"))]),
    ("absente,abc", &[(1, None), (2, Some("abc"))]),
];

#[derive(Clone, Copy, PartialEq, Debug)]
enum Attendu {
    /// La compilation refuse, par l'erreur nommée `REFUS_SAC`.
    Refus,
    /// La compilation réussit et le résultat est identique sur tous les jeux.
    Identique,
    /// La compilation réussit ; le SQL appelle une fonction que seul le consommateur enregistre
    /// (`re_cap`) : pas d'exécution ici, la forme est vérifiée par les tests du compilateur.
    CompileSansExecution,
}
use Attendu::*;

#[derive(Clone, Copy)]
struct Cas {
    voie: &'static str,
    q: &'static str,
    /// Pose les objets de savoir de `savoir()` (alias, eventtype, tag qui visent le sac).
    ko: bool,
    attendu: Attendu,
}

const fn c(voie: &'static str, q: &'static str, attendu: Attendu) -> Cas {
    Cas { voie, q, ko: false, attendu }
}
const fn k(voie: &'static str, q: &'static str, attendu: Attendu) -> Cas {
    Cas { voie, q, ko: true, attendu }
}

const VOIE1: &[Cas] = &[
    c("1 regex", r#"search fields=~"abc""#, Refus),
    c("1 regex (:~)", "search fields:~abc", Refus),
    c("1 joker", "search fields=*abc*", Refus),
    c("1 joker négatif", "search fields!=*abc*", Refus),
    c("1 in", r#"search fields in ({"secret":"abc"})"#, Refus),
    c("1 not in", r#"search fields not in ({"secret":"abc"})"#, Refus),
    c("1 égalité", "search fields=abc", Refus),
    c("1 différent", "search fields!=abc", Refus),
    c("1 comparaison", "search fields>{", Refus),
    c("1 comparaison numérique", "search fields>5", Refus),
    c("1 in numérique", "search fields in (1, 2)", Refus),
    c("1 joker + stats", "search fields=*abc* | stats count", Refus),
];

const VOIE2: &[Cas] = &[
    c("2 where regex", r#"search | where fields=~"abc""#, Identique),
    c("2 where in", r#"search | where fields in ({"secret":"abc"})"#, Identique),
    c("2 where différent", r#"search | where fields!="{}""#, Identique),
    c("2 eval identifiant", "search | eval x = fields | table x", Identique),
    c("2 eval substr", "search | eval x = substr(fields, 1, 14) | table x", Identique),
    c("2 eval len", "search | eval x = len(fields) | table x", Identique),
    c("2 eval like", "search | eval x = if(fields like '%abc%', 1, 0) | table x", Identique),
    c("2 eval replace", "search | eval x = replace(fields, 'abc', 'Z') | table x", Identique),
    c("2 eval casse", "search | eval x = lower(FIELDS) | table x", Identique),
];

const VOIE3: &[Cas] = &[
    c("3 search nu", "search", Identique),
    c("3 table fields", "search | table fields", Identique),
    c("3 sort", "search | sort fields | table ts", Identique),
    c("3 dedup", "search | dedup fields | stats count", Identique),
    c("3 stats by", "search | stats count by fields", Identique),
    c("3 stats by (2 clés)", "search | stats count by host, fields", Identique),
    c("3 values", "search | stats values(fields)", Identique),
    c("3 dc", "search | stats dc(fields)", Identique),
    c("3 min", "search | stats min(fields)", Identique),
    c("3 top", "search | top fields", Identique),
    c("3 rare", "search | rare fields", Identique),
    c("3 timechart by", "search | timechart span=1h count by fields", Identique),
    c("3 eventstats count by", "search | eventstats count by fields | table ts, count", Identique),
    c("3 eventstats values by", "search | eventstats values(ts) by fields | table ts, values", Identique),
    c("3 mvexpand", "search | mvexpand fields | table ts, fields", Identique),
    c("3 lookup clé", "search | lookup lk fields OUTPUT v | table ts, v", Identique),
    c("3 join clé", "search | join fields [search]", Refus),
    c("3 rex", r#"search | rex fields "(?<x>abc)""#, CompileSansExecution),
];

const VOIE4: &[Cas] = &[
    k("4 alias KO, prédicat de base", "search sac=*abc*", Refus),
    k("4 alias KO, where", r#"search | where sac=~"abc""#, Identique),
    k("4 alias KO, table", "search | table sac", Identique),
    k("4 eventtype", "search eventtype=et_sac", Refus),
    k("4 tag", "search tag=t_sac", Refus),
    c("4 rename puis where", r#"search | rename fields AS b | where b=~"abc""#, Identique),
    c("4 rename puis table", "search | rename fields AS b | table b", Identique),
    c("4 sous-recherche append", "search | append [search fields=*abc*]", Refus),
    c("4 sous-recherche join", "search | join host [search fields=*abc* | stats count by host]", Refus),
    c("4 profondeur 3", "search | append [search | append [search | append [search fields=*abc*]]]", Refus),
    c("4 sous-recherche stats by", "search | append [search | stats count by fields]", Identique),
];

const VOIE5: &[Cas] = &[
    c("5 alias nommé comme la clé, sortie", "search | eval secret = 1", Identique),
    c("5 alias nommé comme la clé, table", "search | eval secret = 1 | table fields", Identique),
    c("5 rename vers la clé, where", r#"search | rename host AS secret | where fields=~"abc""#, Identique),
    c("5 lookup OUTPUT la clé", "search | lookup lk host OUTPUT secret | table fields", Identique),
    c("5 alias casse, sortie", "search | eval FIELDS = 1", Identique),
    c("5 alias casse, where", r#"search | eval FIELDS = 1 | where FIELDS=~"abc""#, Identique),
    c("5 alias casse, table", "search | eval FIELDS = 1 | table FIELDS", Identique),
    c("5 alias casse, stats by", "search | eval Fields = 1 | stats count by Fields", Identique),
    c("5 rate (partition)", "search | eval value = ts | rate | table ts, rate", Identique),
];

/// Un nom de groupe qui ne diffère du sac que par la CASSE, sans être vivant : SQLite résout un GROUP BY
/// vers la colonne d'ENTRÉE avant l'alias, sans tenir compte de la casse — donc vers le sac BRUT.
const VOIE6: &[Cas] = &[
    c("6 stats by casse non vivante", "search | stats count by FIELDS", Identique),
    c("6 stats by casse non vivante (2 clés)", "search | stats count by host, Fields", Identique),
    c("6 top casse non vivante", "search | top FIELDS", Identique),
    c("6 rare casse non vivante", "search | rare fIELDS", Identique),
    c("6 timechart by casse non vivante", "search | timechart span=1h count by FIELDS", Identique),
    c("6 sous-recherche stats casse", "search | append [search | stats count by FIELDS]", Identique),
    c("6 eventstats count casse", "search | eventstats count by FIELDS | table ts, count", Identique),
    c("6 eventstats values casse", "search | eventstats values(ts) by FIELDS | table ts, values", Identique),
    c("6 dedup casse", "search | dedup FIELDS | stats count", Identique),
    c("6 rename vers casse puis stats", "search | rename fields AS FIELDS | stats count by FIELDS", Identique),
    k("6 alias KO casse vers le sac, stats", "search | stats dc(ts) by FIELDS", Identique),
    k("6 alias KO casse vers le sac, top", "search | top 5 FIELDS", Identique),
    k("6 alias KO casse vers une colonne, stats", "search | stats count by Fields", Identique),
    k("6 alias KO casse vers une colonne, rare", "search | rare Fields", Identique),
];

/// Les requêtes de la sonde de vérification qui ne figurent pas déjà plus haut : le sac après un `table`
/// qui retire les autres colonnes, partitions, jointure, alias de casse projeté.
const VOIE7: &[Cas] = &[
    c("7 table puis stats by", "search | table ts, fields | stats count by fields", Identique),
    c("7 table puis top", "search | table ts, fields | top fields", Identique),
    c("7 rate sans table", "search | eval value = ts | rate", Identique),
    c("7 table puis rate", "search | table ts, value, fields | rate", Identique),
    c("7 eventstats values by", "search | eventstats values(ts) by fields", Identique),
    c("7 table puis eventstats", "search | table ts, fields | eventstats values(ts) by fields", Identique),
    c("7 table puis join", "search | table host, fields | join fields [search]", Refus),
    c("7 table puis alias casse", "search | table ts, fields | eval FIELDS = 1", Identique),
    c("7 alias casse projeté", "search | eval FIELDS = 1 | table ts, FIELDS", Identique),
];

fn masques() -> FieldMaskSet {
    let mut m = FieldMaskSet::new();
    m.insert("secret", MaskAction::Redact);
    m
}

/// Jeu MIXTE : une clé du sac ET une colonne réelle.
fn masques_mixtes() -> FieldMaskSet {
    let mut m = masques();
    m.insert("src_ip", MaskAction::Mask);
    m
}

fn masque_reel(champ: &str, action: MaskAction) -> FieldMaskSet {
    let mut m = FieldMaskSet::new();
    m.insert(champ, action);
    m
}
fn masque_src_ip() -> FieldMaskSet {
    masque_reel("src_ip", MaskAction::Mask)
}
fn masque_message() -> FieldMaskSet {
    masque_reel("message", MaskAction::Mask)
}
fn masque_id() -> FieldMaskSet {
    masque_reel("id", MaskAction::Mask)
}
fn masque_dedup() -> FieldMaskSet {
    masque_reel("dedup", MaskAction::Redact)
}

/// Une configuration de mesure : la clé que porte le sac, le jeu de masques, l'élagage de `message`, et
/// la colonne réelle qui porte la même valeur que la clé du sac (`None` : aucune).
#[derive(Clone, Copy)]
struct Conf {
    nom: &'static str,
    cle: &'static str,
    masques: fn() -> FieldMaskSet,
    elagage: bool,
    miroir: Option<&'static str>,
}

const CLE_DU_SAC: Conf = Conf { nom: "clé du sac secret", cle: "secret", masques, elagage: false, miroir: None };
const JEU_MIXTE: Conf = Conf { nom: "jeu mixte secret + src_ip", cle: "secret", masques: masques_mixtes, elagage: false, miroir: None };
const SRC_IP: Conf = Conf { nom: "src_ip masqué, sac qui porte src_ip", cle: "src_ip", masques: masque_src_ip, elagage: false, miroir: Some("src_ip") };
const MESSAGE: Conf = Conf { nom: "message masqué + élagage, sac qui porte message", cle: "message", masques: masque_message, elagage: true, miroir: Some("message") };
const ID: Conf = Conf { nom: "id masqué, sac qui porte id", cle: "id", masques: masque_id, elagage: false, miroir: Some("id") };
const DEDUP: Conf = Conf { nom: "dedup caviardé, sac qui porte dedup", cle: "dedup", masques: masque_dedup, elagage: false, miroir: Some("dedup") };

fn savoir() -> KnowledgeSet {
    let mut k = KnowledgeSet::new();
    k.add_alias("sac", "fields");
    k.add_alias("FIELDS", "fields");
    k.add_alias("Fields", "host");
    k.add_eventtype("et_sac", "fields=*abc*");
    k.add_tag("t_sac", "fields", r#"{"secret":"abc"}"#);
    k
}

fn schema(cas: &Cas, m: FieldMaskSet, elagage: bool) -> Schema {
    let s = Schema::events().with_masks(m).with_message_pruning(elagage);
    if cas.ko {
        s.with_knowledge(savoir())
    } else {
        s
    }
}

fn sac(cle: &str, valeur: Option<&str>) -> String {
    match valeur {
        Some(v) => format!(r#"{{"{cle}":"{v}"}}"#),
        None => "{}".to_string(),
    }
}

/// Moteur d'exécution du différentiel.
#[derive(Clone, Debug)]
enum Moteur {
    /// Binaire `sqlite3` (chemin).
    Cli(String),
    /// `python3` (chemin) et son module `sqlite3`, piloté par `PY_SQLITE`.
    Python(String),
}

/// Séparateur entre le peuplement et la requête dans le script envoyé au moteur (commentaire SQL).
const SEP_REQUETE: &str = "\n-- REQUETE\n";

/// Programme Python : peuple la base en mémoire, exécute la requête, imprime les lignes comme `sqlite3
/// -batch` (`|` entre colonnes, NULL vide). `regexp(motif, valeur)` est enregistré comme chez le
/// consommateur : sans lui, toute requête REGEXP serait en erreur sur tous les jeux.
const PY_SQLITE: &str = r#"
import re, sqlite3, sys
setup, q = sys.stdin.read().split("\n-- REQUETE\n", 1)
con = sqlite3.connect(":memory:")
con.create_function("regexp", 2, lambda p, s: None if p is None or s is None else int(re.search(p, str(s)) is not None), deterministic=True)
try:
    con.executescript(setup)
    rows = con.execute(q.strip().rstrip(";")).fetchall()
except sqlite3.Error as e:
    sys.stderr.write("Error: %s\n" % e)
    sys.exit(1)
for r in rows:
    sys.stdout.write("|".join("" if v is None else str(v) for v in r) + "\n")
"#;

/// Premier moteur disponible : le binaire `cli`, à défaut `py` avec son module `sqlite3`.
fn moteur_dispo(cli: &str, py: &str) -> Option<Moteur> {
    if Command::new(cli).arg("-version").output().map(|o| o.status.success()).unwrap_or(false) {
        return Some(Moteur::Cli(cli.to_string()));
    }
    if Command::new(py).args(["-I", "-c", "import sqlite3"]).output().map(|o| o.status.success()).unwrap_or(false) {
        return Some(Moteur::Python(py.to_string()));
    }
    None
}

/// Choix du moteur : aucun moteur et différentiel non déclaré facultatif -> `Err` (la suite échoue).
fn choisir_moteur(cli: &str, py: &str, facultatif: bool) -> Result<Option<Moteur>, String> {
    match moteur_dispo(cli, py) {
        Some(m) => Ok(Some(m)),
        None if facultatif => Ok(None),
        None => Err(format!(
            "différentiel impossible : ni `{cli}` ni `{py}` (module sqlite3) ; installer l'un des deux, \
             ou poser GUATX_CORE_DIFFERENTIEL_FACULTATIF=1 pour ne vérifier que les refus"
        )),
    }
}

/// Le moteur du différentiel. Aucun moteur : ÉCHEC, sauf `GUATX_CORE_DIFFERENTIEL_FACULTATIF` posé.
fn sqlite3() -> Option<Moteur> {
    let cli = std::env::var("GUATX_CORE_SQLITE3").unwrap_or_else(|_| "sqlite3".to_string());
    let py = std::env::var("GUATX_CORE_PYTHON3").unwrap_or_else(|_| "python3".to_string());
    choisir_moteur(&cli, &py, std::env::var("GUATX_CORE_DIFFERENTIEL_FACULTATIF").is_ok()).unwrap_or_else(|e| panic!("{e}"))
}

/// Exécute `sql` sur une base en mémoire peuplée par `lignes` : la clé `conf.cle` du sac porte la valeur
/// de chaque ligne, et la colonne `conf.miroir` la même valeur (une valeur fixe quand la clé est absente :
/// la présence de la colonne n'est pas l'objet de la mesure). Rend la sortie, ou l'erreur SQLite.
fn executer(moteur: &Moteur, sql: &str, lignes: &[(i64, Option<&str>)], conf: &Conf) -> Result<String, String> {
    let esc = |v: &str| format!("'{}'", v.replace('\'', "''"));
    let mut script = String::from(
        "CREATE TABLE event(ts INTEGER, host TEXT, source TEXT, category TEXT, severity INTEGER, src_ip TEXT, dst_ip TEXT, url TEXT, xff TEXT, message TEXT, fields TEXT, dedup TEXT, id INTEGER, env_id TEXT);\n\
         CREATE TABLE lookup_kv(name TEXT, \"key\" TEXT, val TEXT);\n",
    );
    script.push_str(&format!("INSERT INTO lookup_kv VALUES('lk',{},'{{\"v\":\"trouvé\"}}');\n", esc(&sac(conf.cle, Some("abc")))));
    for (i, (ts, v)) in lignes.iter().enumerate() {
        let mut cols: Vec<(&str, String)> = vec![
            ("ts", ts.to_string()),
            ("host", esc("h")),
            ("source", esc("web")),
            ("category", esc("auth")),
            ("severity", "3".into()),
            ("src_ip", esc("10.0.0.1")),
            ("dst_ip", esc("10.0.0.2")),
            ("url", esc("/")),
            ("xff", esc("")),
            ("message", esc("m")),
            ("fields", esc(&sac(conf.cle, *v))),
            ("dedup", "NULL".into()),
            ("id", (i + 1).to_string()),
            ("env_id", "NULL".into()),
        ];
        if let Some(col) = conf.miroir {
            let c = cols.iter_mut().find(|(n, _)| *n == col).expect("colonne miroir");
            c.1 = esc(v.unwrap_or("zz-fixe"));
        }
        let noms: Vec<&str> = cols.iter().map(|(n, _)| *n).collect();
        let vals: Vec<&str> = cols.iter().map(|(_, v)| v.as_str()).collect();
        script.push_str(&format!("INSERT INTO event({}) VALUES({});\n", noms.join(","), vals.join(",")));
    }
    script.push_str(SEP_REQUETE);
    script.push_str(sql);
    script.push_str(";\n");
    let mut cmd = match moteur {
        Moteur::Cli(bin) => {
            let mut c = Command::new(bin);
            c.args(["-batch", "-bail", ":memory:"]);
            c
        }
        Moteur::Python(py) => {
            let mut c = Command::new(py);
            c.args(["-I", "-c", PY_SQLITE]);
            c
        }
    };
    let mut p = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("lancement du moteur SQLite");
    p.stdin.take().expect("stdin").write_all(script.as_bytes()).expect("écriture du script");
    let out = p.wait_with_output().expect("sortie du moteur SQLite");
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// Différentiel : `None` si le résultat est identique sur tous les jeux, sans erreur SQL, et ne contient
/// aucune valeur de la clé masquée ; sinon le détail par jeu (une erreur partout ne prouverait rien : elle
/// est rendue comme un écart).
fn differentiel(moteur: &Moteur, sql: &str, conf: &Conf) -> Option<String> {
    let res: Vec<(&str, Result<String, String>)> = JEUX.iter().map(|(n, l)| (*n, executer(moteur, sql, l, conf))).collect();
    let valeur_en_sortie = res.iter().any(|(_, r)| r.as_ref().is_ok_and(|o| VALEURS.iter().any(|v| o.contains(v))));
    if !valeur_en_sortie && res.iter().all(|(_, r)| r.is_ok() && *r == res[0].1) {
        None
    } else {
        Some(res.iter().map(|(n, r)| format!("      [{n}] {r:?}")).collect::<Vec<_>>().join("\n"))
    }
}

/// Valeurs que prend la clé masquée dans `JEUX` : aucune ne doit apparaître dans une sortie.
const VALEURS: &[&str] = &["abc", "xyz"];

fn verifier(cas: &[Cas]) {
    verifier_avec(cas, &CLE_DU_SAC)
}

fn verifier_avec(cas: &[Cas], conf: &Conf) {
    let bin = sqlite3();
    match &bin {
        Some(m) => eprintln!("moteur du différentiel : {m:?} ; configuration : {}", conf.nom),
        None => eprintln!("GUATX_CORE_DIFFERENTIEL_FACULTATIF : différentiel NON joué, seuls les refus sont vérifiés"),
    }
    let mut echecs: Vec<String> = Vec::new();
    let (mut fuites, mut refus, mut sures) = (0, 0, 0);
    for cs in cas {
        let r = compile(cs.q, &schema(cs, (conf.masques)(), conf.elagage));
        let verdict = match (&r, cs.attendu) {
            (Err(e), Refus) if e.contains(REFUS_SAC) => {
                refus += 1;
                "refus nommé".to_string()
            }
            (Err(e), _) => {
                echecs.push(format!("[{}] `{}` : erreur inattendue : {e}", cs.voie, cs.q));
                format!("ERREUR {e}")
            }
            (Ok(_), CompileSansExecution) => "compile (non exécuté)".to_string(),
            (Ok(comp), att) => {
                let diff = bin.as_ref().and_then(|b| differentiel(b, &comp.sql, conf));
                if att == Refus {
                    echecs.push(format!(
                        "[{}] `{}` : compilée alors qu'elle lit le sac brut ({})\n    SQL : {}{}",
                        cs.voie,
                        cs.q,
                        if diff.is_some() { "FUIT" } else { "pas de différence mesurée" },
                        comp.sql,
                        diff.as_deref().map(|d| format!("\n{d}")).unwrap_or_default()
                    ));
                }
                match diff {
                    Some(d) => {
                        fuites += 1;
                        if att == Identique {
                            echecs.push(format!("[{}] `{}` : FUIT\n    SQL : {}\n{d}", cs.voie, cs.q, comp.sql));
                        }
                        "FUIT".to_string()
                    }
                    None if bin.is_some() => {
                        sures += 1;
                        "identique".to_string()
                    }
                    None => "compile (différentiel non joué)".to_string(),
                }
            }
        };
        eprintln!("  {:<40} {:<70} {verdict}", cs.voie, cs.q);
    }
    eprintln!("BILAN|{}|{} requêtes|fuites={fuites}|refus={refus}|identiques={sures}|écarts={}", conf.nom, cas.len(), echecs.len());
    assert!(echecs.is_empty(), "{} : {} voie(s) en défaut :\n{}", conf.nom, echecs.len(), echecs.join("\n"));
}

fn toutes() -> impl Iterator<Item = &'static Cas> {
    VOIE1.iter().chain(VOIE2).chain(VOIE3).chain(VOIE4).chain(VOIE5).chain(VOIE6).chain(VOIE7)
}

#[test]
fn voie1_predicat_de_base_sur_le_sac() {
    verifier(VOIE1);
}

#[test]
fn voie2_le_sac_dans_where_et_eval() {
    verifier(VOIE2);
}

#[test]
fn voie3_etapes_qui_nomment_le_sac() {
    verifier(VOIE3);
}

#[test]
fn voie4_alias_rename_eventtype_tag_sous_recherches() {
    verifier(VOIE4);
}

#[test]
fn voie5_alias_qui_masquent_le_sac_et_rate() {
    verifier(VOIE5);
}

#[test]
fn voie6_nom_de_groupe_qui_ne_differe_du_sac_que_par_la_casse() {
    verifier(VOIE6);
}

#[test]
fn voie7_sac_apres_table_partitions_jointure() {
    verifier(VOIE7);
}

/// Toutes les voies, avec un jeu qui masque une clé du sac ET une colonne réelle.
#[test]
fn toutes_les_voies_avec_un_jeu_mixte() {
    let cas: Vec<Cas> = toutes().copied().collect();
    verifier_avec(&cas, &JEU_MIXTE);
}

// ---------------------------------------------------------------------------------------------
// COLONNE RÉELLE MASQUÉE, SAC QUI PORTE UNE CLÉ DU MÊME NOM. Le sac est écrit par le producteur :
// rien n'en retire `src_ip`. Toutes les voies, colonne vivante ou non dans la portée (VOIE7 la
// retire par `table`), avec élagage de `message`, et sur des colonnes jamais projetées (`id`,
// `dedup`) : la valeur ne sort par aucune voie.
// ---------------------------------------------------------------------------------------------

fn toutes_avec(conf: &Conf) {
    let cas: Vec<Cas> = toutes().copied().collect();
    verifier_avec(&cas, conf);
}

#[test]
fn colonne_reelle_src_ip_la_valeur_du_sac_ne_sort_pas() {
    toutes_avec(&SRC_IP);
}

#[test]
fn colonne_reelle_message_elague_la_valeur_du_sac_ne_sort_pas() {
    toutes_avec(&MESSAGE);
}

#[test]
fn colonne_reelle_id_la_valeur_du_sac_ne_sort_pas() {
    toutes_avec(&ID);
}

#[test]
fn colonne_reelle_dedup_la_valeur_du_sac_ne_sort_pas() {
    toutes_avec(&DEDUP);
}

/// Le différentiel sait voir une fuite : la clé masquée lue par un prédicat SANS masque change le
/// résultat, et une valeur rendue est vue. Sans ce témoin, un différentiel aveugle (base vide, requête
/// en erreur partout) rendrait toutes les voies « identiques ».
#[test]
fn le_differentiel_voit_une_fuite() {
    let Some(bin) = sqlite3() else {
        eprintln!("GUATX_CORE_DIFFERENTIEL_FACULTATIF : témoin du différentiel NON joué");
        return;
    };
    let sql = compile("search fields=*abc* | stats count", &Schema::events()).unwrap().sql;
    assert!(differentiel(&bin, &sql, &CLE_DU_SAC).is_some(), "le différentiel doit distinguer les jeux sans masque : {sql}");
    assert_eq!(executer(&bin, &sql, JEUX[0].1, &CLE_DU_SAC).unwrap().trim(), "2");
    // REGEXP est exécutable : sans lui, une voie REGEXP serait « identique » parce qu'en erreur partout.
    let sql = compile(r#"search fields=~"abc" | stats count"#, &Schema::events()).unwrap().sql;
    assert_eq!(executer(&bin, &sql, JEUX[1].1, &CLE_DU_SAC).unwrap().trim(), "1", "{sql}");
    // Une requête en erreur sur tous les jeux n'est pas « identique ».
    assert!(differentiel(&bin, "SELECT nulle_part FROM event", &CLE_DU_SAC).is_some());
    // Une valeur rendue est vue même quand elle est la même sur tous les jeux.
    assert!(differentiel(&bin, "SELECT 'abc' FROM event", &CLE_DU_SAC).is_some());
    // La colonne miroir porte la valeur : lue brute, elle se voit.
    assert!(differentiel(&bin, "SELECT src_ip FROM event", &SRC_IP).is_some());
}

/// Sans aucun moteur, le différentiel ne se saute pas en silence : la suite échoue, sauf choix explicite.
#[test]
fn sans_moteur_le_differentiel_echoue() {
    let absent = "/chemin/absent/guatx-core-moteur";
    assert!(choisir_moteur(absent, absent, false).is_err());
    assert!(matches!(choisir_moteur(absent, absent, true), Ok(None)));
}

// ---------------------------------------------------------------------------------------------
// MODE 0 — JEU DE MASQUES VIDE : SQL figé, produit par v0.2.4.
// ---------------------------------------------------------------------------------------------

fn rendu_sans_masque(cs: &Cas) -> String {
    match compile(cs.q, &schema(cs, FieldMaskSet::new(), false)) {
        Ok(c) => c.sql,
        Err(e) => format!("ERR {e}"),
    }
}

/// Imprime la référence (`cargo test --test bag_oracle_masked_key -- --ignored --nocapture`).
#[test]
#[ignore]
fn mode0_imprimer_la_reference() {
    for cs in toutes() {
        println!("    (\n        {:?},\n        r##\"{}\"##,\n    ),", cs.q, rendu_sans_masque(cs));
    }
}

#[test]
fn mode0_sql_identique_a_la_reference() {
    let mut ecarts = Vec::new();
    let mut vues = 0;
    for cs in toutes() {
        let (_, attendu) = REFERENCE_MODE0
            .iter()
            .find(|(q, _)| *q == cs.q)
            .unwrap_or_else(|| panic!("requête absente de la référence : {}", cs.q));
        vues += 1;
        let obtenu = rendu_sans_masque(cs);
        if obtenu != *attendu {
            ecarts.push(format!("`{}`\n  attendu {attendu}\n  obtenu  {obtenu}", cs.q));
        }
    }
    assert_eq!(vues, REFERENCE_MODE0.len(), "la référence porte des requêtes hors mesure");
    assert!(ecarts.is_empty(), "{} écart(s) sur {vues} :\n{}", ecarts.len(), ecarts.join("\n"));
}

/// `(requête, SQL sans masque)` — produit par v0.2.4.
const REFERENCE_MODE0: &[(&str, &str)] = &[
    (
        "search fields=~\"abc\"",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" REGEXP 'abc'"##,
    ),
    (
        "search fields:~abc",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" REGEXP 'abc'"##,
    ),
    (
        "search fields=*abc*",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" LIKE '%abc%'"##,
    ),
    (
        "search fields!=*abc*",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" NOT LIKE '%abc%'"##,
    ),
    (
        "search fields in ({\"secret\":\"abc\"})",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" COLLATE NOCASE IN ('{"secret":"abc"}')"##,
    ),
    (
        "search fields not in ({\"secret\":\"abc\"})",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" NOT IN ('{"secret":"abc"}')"##,
    ),
    (
        "search fields=abc",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" = 'abc'"##,
    ),
    (
        "search fields!=abc",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" <> 'abc'"##,
    ),
    (
        "search fields>{",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" > '{'"##,
    ),
    (
        "search fields>5",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" > 5"##,
    ),
    (
        "search fields in (1, 2)",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" IN (1,2)"##,
    ),
    (
        "search fields=*abc* | stats count",
        r##"SELECT COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" LIKE '%abc%')"##,
    ),
    (
        "search | where fields=~\"abc\"",
        r##"SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) WHERE "fields" REGEXP 'abc'"##,
    ),
    (
        "search | where fields in ({\"secret\":\"abc\"})",
        r##"SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) WHERE "fields" IN ('{"secret":"abc"}')"##,
    ),
    (
        "search | where fields!=\"{}\"",
        r##"SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) WHERE "fields" <> '{}'"##,
    ),
    (
        "search | eval x = fields | table x",
        r##"SELECT "x" AS "x" FROM (SELECT *, (fields) AS "x" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | eval x = substr(fields, 1, 14) | table x",
        r##"SELECT "x" AS "x" FROM (SELECT *, (substr(fields, 1, 14)) AS "x" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | eval x = len(fields) | table x",
        r##"SELECT "x" AS "x" FROM (SELECT *, (length(fields)) AS "x" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | eval x = if(fields like '%abc%', 1, 0) | table x",
        r##"SELECT "x" AS "x" FROM (SELECT *, (iif(fields like '%abc%', 1, 0)) AS "x" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | eval x = replace(fields, 'abc', 'Z') | table x",
        r##"SELECT "x" AS "x" FROM (SELECT *, (replace(fields, 'abc', 'Z')) AS "x" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | eval x = lower(FIELDS) | table x",
        r##"SELECT "x" AS "x" FROM (SELECT *, (lower(FIELDS)) AS "x" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event"##,
    ),
    (
        "search | table fields",
        r##"SELECT "fields" AS "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)"##,
    ),
    (
        "search | sort fields | table ts",
        r##"SELECT "ts" AS "ts" FROM (SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) ORDER BY "fields" ASC)"##,
    ),
    (
        "search | dedup fields | stats count",
        r##"SELECT COUNT(*) AS "count" FROM (SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "fields")"##,
    ),
    (
        "search | stats count by fields",
        r##"SELECT "fields" AS "fields",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "fields""##,
    ),
    (
        "search | stats count by host, fields",
        r##"SELECT "host" AS "host","fields" AS "fields",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "host","fields""##,
    ),
    (
        "search | stats values(fields)",
        r##"SELECT substr(GROUP_CONCAT(DISTINCT "fields"),1,4096) AS "values" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)"##,
    ),
    (
        "search | stats dc(fields)",
        r##"SELECT COUNT(DISTINCT "fields") AS "dc" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)"##,
    ),
    (
        "search | stats min(fields)",
        r##"SELECT MIN("fields") AS "min" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)"##,
    ),
    (
        "search | top fields",
        r##"SELECT "fields" AS "fields",COUNT(*) AS count FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "fields" ORDER BY count DESC LIMIT 10"##,
    ),
    (
        "search | rare fields",
        r##"SELECT "fields" AS "fields",COUNT(*) AS count FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "fields" ORDER BY count ASC LIMIT 10"##,
    ),
    (
        "search | timechart span=1h count by fields",
        r##"SELECT (ts/3600)*3600 AS bucket,"fields" AS "fields",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY bucket,"fields" ORDER BY bucket"##,
    ),
    (
        "search | eventstats count by fields | table ts, count",
        r##"SELECT "ts" AS "ts","count" AS "count" FROM (SELECT *, COUNT(*) OVER (PARTITION BY "fields") AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | eventstats values(ts) by fields | table ts, values",
        r##"SELECT "ts" AS "ts","values" AS "values" FROM (SELECT o.*, (SELECT substr(GROUP_CONCAT(DISTINCT "ts"),1,4096) FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) AS i WHERE i."fields" IS o."fields") AS "values" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) AS o)"##,
    ),
    (
        "search | mvexpand fields | table ts, fields",
        r##"SELECT "ts" AS "ts","fields" AS "fields" FROM (SELECT "ts","host","source","category","severity","src_ip","dst_ip","url","xff","message",je.value AS "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event), json_each(CASE WHEN json_valid("fields") THEN "fields" ELSE '[]' END) je)"##,
    ),
    (
        "search | lookup lk fields OUTPUT v | table ts, v",
        r##"SELECT "ts" AS "ts","v" AS "v" FROM (SELECT base.*, CASE WHEN json_valid(lk.val) THEN json_extract(lk.val,'$.v') END AS "v" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) base LEFT JOIN lookup_kv lk ON lk.name='lk' AND lk."key"="fields")"##,
    ),
    (
        "search | join fields [search]",
        r##"SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) LEFT JOIN (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) USING("fields")"##,
    ),
    (
        "search | rex fields \"(?<x>abc)\"",
        r##"SELECT *,re_cap("fields",'(?<x>abc)','x') AS "x" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)"##,
    ),
    (
        "search sac=*abc*",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" LIKE '%abc%'"##,
    ),
    (
        "search | where sac=~\"abc\"",
        r##"SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) WHERE "fields" REGEXP 'abc'"##,
    ),
    (
        "search | table sac",
        r##"SELECT "fields" AS "sac" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)"##,
    ),
    (
        "search eventtype=et_sac",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE ("fields" LIKE '%abc%')"##,
    ),
    (
        "search tag=t_sac",
        r##"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE ("fields" = '{"secret":"abc"}')"##,
    ),
    (
        "search | rename fields AS b | where b=~\"abc\"",
        r##"SELECT * FROM (SELECT *, "fields" AS "b" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) WHERE "b" REGEXP 'abc'"##,
    ),
    (
        "search | rename fields AS b | table b",
        r##"SELECT "b" AS "b" FROM (SELECT *, "fields" AS "b" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | append [search fields=*abc*]",
        r##"SELECT "ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) UNION ALL SELECT "ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" LIKE '%abc%')"##,
    ),
    (
        "search | join host [search fields=*abc* | stats count by host]",
        r##"SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) LEFT JOIN (SELECT "host" AS "host",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" LIKE '%abc%') GROUP BY "host") USING("host")"##,
    ),
    (
        "search | append [search | append [search | append [search fields=*abc*]]]",
        r##"SELECT "ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) UNION ALL SELECT "ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields" FROM (SELECT "ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) UNION ALL SELECT "ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields" FROM (SELECT "ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) UNION ALL SELECT "ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "fields" LIKE '%abc%')))"##,
    ),
    (
        "search | append [search | stats count by fields]",
        r##"SELECT "ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields", NULL AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) UNION ALL SELECT NULL AS "ts", NULL AS "host", NULL AS "source", NULL AS "category", NULL AS "severity", NULL AS "src_ip", NULL AS "dst_ip", NULL AS "url", NULL AS "xff", NULL AS "message", "fields", "count" FROM (SELECT "fields" AS "fields",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "fields")"##,
    ),
    (
        "search | eval secret = 1",
        r##"SELECT *, (1) AS "secret" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)"##,
    ),
    (
        "search | eval secret = 1 | table fields",
        r##"SELECT "fields" AS "fields" FROM (SELECT *, (1) AS "secret" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | rename host AS secret | where fields=~\"abc\"",
        r##"SELECT * FROM (SELECT *, "host" AS "secret" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) WHERE "fields" REGEXP 'abc'"##,
    ),
    (
        "search | lookup lk host OUTPUT secret | table fields",
        r##"SELECT "fields" AS "fields" FROM (SELECT base.*, CASE WHEN json_valid(lk.val) THEN json_extract(lk.val,'$.secret') END AS "secret" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) base LEFT JOIN lookup_kv lk ON lk.name='lk' AND lk."key"="host")"##,
    ),
    (
        "search | eval FIELDS = 1",
        r##"SELECT *, (1) AS "FIELDS" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)"##,
    ),
    (
        "search | eval FIELDS = 1 | where FIELDS=~\"abc\"",
        r##"SELECT * FROM (SELECT *, (1) AS "FIELDS" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) WHERE "FIELDS" REGEXP 'abc'"##,
    ),
    (
        "search | eval FIELDS = 1 | table FIELDS",
        r##"SELECT "FIELDS" AS "FIELDS" FROM (SELECT *, (1) AS "FIELDS" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | eval Fields = 1 | stats count by Fields",
        r##"SELECT "Fields" AS "Fields",COUNT(*) AS "count" FROM (SELECT *, (1) AS "Fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) GROUP BY "Fields""##,
    ),
    (
        "search | eval value = ts | rate | table ts, rate",
        r##"SELECT "ts" AS "ts","rate" AS "rate" FROM (SELECT *, CASE WHEN (value - LAG(value) OVER w) >= 0 AND (ts - LAG(ts) OVER w) > 0 THEN (value - LAG(value) OVER w)*1.0/(ts - LAG(ts) OVER w) ELSE NULL END AS rate FROM (SELECT *, (ts) AS "value" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) WINDOW w AS (PARTITION BY "host","source","category","severity","src_ip","dst_ip","url","xff","message","fields" ORDER BY ts))"##,
    ),
    (
        "search | stats count by FIELDS",
        r##"SELECT json_extract(fields,'$.FIELDS') AS "FIELDS",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "FIELDS""##,
    ),
    (
        "search | stats count by host, Fields",
        r##"SELECT "host" AS "host",json_extract(fields,'$.Fields') AS "Fields",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "host","Fields""##,
    ),
    (
        "search | top FIELDS",
        r##"SELECT json_extract(fields,'$.FIELDS') AS "FIELDS",COUNT(*) AS count FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "FIELDS" ORDER BY count DESC LIMIT 10"##,
    ),
    (
        "search | rare fIELDS",
        r##"SELECT json_extract(fields,'$.fIELDS') AS "fIELDS",COUNT(*) AS count FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "fIELDS" ORDER BY count ASC LIMIT 10"##,
    ),
    (
        "search | timechart span=1h count by FIELDS",
        r##"SELECT (ts/3600)*3600 AS bucket,json_extract(fields,'$.FIELDS') AS "FIELDS",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY bucket,"FIELDS" ORDER BY bucket"##,
    ),
    (
        "search | append [search | stats count by FIELDS]",
        r##"SELECT "ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields", NULL AS "FIELDS", NULL AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) UNION ALL SELECT NULL AS "ts", NULL AS "host", NULL AS "source", NULL AS "category", NULL AS "severity", NULL AS "src_ip", NULL AS "dst_ip", NULL AS "url", NULL AS "xff", NULL AS "message", NULL AS "fields", "FIELDS", "count" FROM (SELECT json_extract(fields,'$.FIELDS') AS "FIELDS",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "FIELDS")"##,
    ),
    (
        "search | eventstats count by FIELDS | table ts, count",
        r##"SELECT "ts" AS "ts","count" AS "count" FROM (SELECT *, COUNT(*) OVER (PARTITION BY json_extract(fields,'$.FIELDS')) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | eventstats values(ts) by FIELDS | table ts, values",
        r##"SELECT "ts" AS "ts","values" AS "values" FROM (SELECT o.*, (SELECT substr(GROUP_CONCAT(DISTINCT "ts"),1,4096) FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) AS i WHERE json_extract(i.fields,'$.FIELDS') IS json_extract(o.fields,'$.FIELDS')) AS "values" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) AS o)"##,
    ),
    (
        "search | dedup FIELDS | stats count",
        r##"SELECT COUNT(*) AS "count" FROM (SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY json_extract(fields,'$.FIELDS'))"##,
    ),
    (
        "search | rename fields AS FIELDS | stats count by FIELDS",
        r##"SELECT "FIELDS" AS "FIELDS",COUNT(*) AS "count" FROM (SELECT *, "fields" AS "FIELDS" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) GROUP BY "FIELDS""##,
    ),
    (
        "search | stats dc(ts) by FIELDS",
        r##"SELECT "fields" AS "FIELDS",COUNT(DISTINCT "ts") AS "dc" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "FIELDS""##,
    ),
    (
        "search | top 5 FIELDS",
        r##"SELECT "fields" AS "FIELDS",COUNT(*) AS count FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "FIELDS" ORDER BY count DESC LIMIT 5"##,
    ),
    (
        "search | stats count by Fields",
        r##"SELECT "host" AS "Fields",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "Fields""##,
    ),
    (
        "search | rare Fields",
        r##"SELECT "host" AS "Fields",COUNT(*) AS count FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) GROUP BY "Fields" ORDER BY count ASC LIMIT 10"##,
    ),
    (
        "search | table ts, fields | stats count by fields",
        r##"SELECT "fields" AS "fields",COUNT(*) AS "count" FROM (SELECT "ts" AS "ts","fields" AS "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) GROUP BY "fields""##,
    ),
    (
        "search | table ts, fields | top fields",
        r##"SELECT "fields" AS "fields",COUNT(*) AS count FROM (SELECT "ts" AS "ts","fields" AS "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) GROUP BY "fields" ORDER BY count DESC LIMIT 10"##,
    ),
    (
        "search | eval value = ts | rate",
        r##"SELECT *, CASE WHEN (value - LAG(value) OVER w) >= 0 AND (ts - LAG(ts) OVER w) > 0 THEN (value - LAG(value) OVER w)*1.0/(ts - LAG(ts) OVER w) ELSE NULL END AS rate FROM (SELECT *, (ts) AS "value" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) WINDOW w AS (PARTITION BY "host","source","category","severity","src_ip","dst_ip","url","xff","message","fields" ORDER BY ts)"##,
    ),
    (
        "search | table ts, value, fields | rate",
        r##"SELECT *, CASE WHEN (value - LAG(value) OVER w) >= 0 AND (ts - LAG(ts) OVER w) > 0 THEN (value - LAG(value) OVER w)*1.0/(ts - LAG(ts) OVER w) ELSE NULL END AS rate FROM (SELECT "ts" AS "ts",json_extract(fields,'$.value') AS "value","fields" AS "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) WINDOW w AS (PARTITION BY "fields" ORDER BY ts)"##,
    ),
    (
        "search | eventstats values(ts) by fields",
        r##"SELECT o.*, (SELECT substr(GROUP_CONCAT(DISTINCT "ts"),1,4096) FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) AS i WHERE i."fields" IS o."fields") AS "values" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) AS o"##,
    ),
    (
        "search | table ts, fields | eventstats values(ts) by fields",
        r##"SELECT o.*, (SELECT substr(GROUP_CONCAT(DISTINCT "ts"),1,4096) FROM (SELECT "ts" AS "ts","fields" AS "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) AS i WHERE i."fields" IS o."fields") AS "values" FROM (SELECT "ts" AS "ts","fields" AS "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) AS o"##,
    ),
    (
        "search | table host, fields | join fields [search]",
        r##"SELECT * FROM (SELECT "host" AS "host","fields" AS "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event)) LEFT JOIN (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event) USING("fields")"##,
    ),
    (
        "search | table ts, fields | eval FIELDS = 1",
        r##"SELECT *, (1) AS "FIELDS" FROM (SELECT "ts" AS "ts","fields" AS "fields" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
    (
        "search | eval FIELDS = 1 | table ts, FIELDS",
        r##"SELECT "ts" AS "ts","FIELDS" AS "FIELDS" FROM (SELECT *, (1) AS "FIELDS" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event))"##,
    ),
];
