//! store — DTO PLAINS du data-plane partagé.
//!
//! Ces types sont les STRUCTURES DE DONNÉES pures du store data-plane de Plume : les DTO d'insertion
//! (`EventRow`/`MetricRow`/`SnapshotRow`) et la vue de lecture typée (`QueryStats`/`Rows`). Ils ne
//! portent AUCUN couplage `rusqlite` : le `trait EventStore` et son unique impl `SqlcipherStore`
//! (qui, eux, dépendent de `rusqlite::Connection`) restent DANS le daemon — le cœur ne doit jamais
//! gagner de dépendance rusqlite/SQLCipher. Seuls les DTO purs remontent ici pour que le contrat de
//! données du store soit partageable (et, plus tard, réutilisable par un autre backend).

use serde_json::Value;

/// DTO d'insertion d'un event — SUR-ENSEMBLE canonique (élargit `NormEvent`). Les conventions encodent
/// les DÉFAUTS de colonne pour que la ligne stockée soit BYTE-IDENTIQUE quel que soit le producteur :
/// `dedup=None` -> NULL (pas de clé anti-doublon) ; `engagement_id`/`origin` "" == DEFAULT de colonne ;
/// `env_id=None` -> lié à 'prod' (DEFAULT `NOT NULL` de la colonne — on lie 'prod', jamais NULL).
#[derive(Debug, Clone, Default)]
pub struct EventRow {
    pub ts: i64,
    pub source: String,
    pub category: String,
    pub severity: i64,
    pub message: String,
    pub host: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub url: Option<String>,
    pub dedup: Option<String>,
    pub fields: Option<String>,
    pub engagement_id: String,
    pub origin: String,
    pub env_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MetricRow {
    pub ts: i64,
    pub name: String,
    pub labels: Option<String>,
    pub value: f64,
    pub host: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SnapshotRow {
    pub ts: i64,
    pub kind: String,
    pub hash: String,
    pub data: String,
    pub host: Option<String>,
}

/// Résultat de lecture normalisé (miroir DTO de la forme JSON `{columns, rows, stats}` que renvoie
/// `run_query_ex`). Fait partie de la surface du SPI ; le chemin LIVE conserve `serde_json::Value`
/// (byte-identique), `Rows::from_query_json` offre la vue typée (exercée par les tests du store).
#[derive(Debug, Clone, Default)]
pub struct QueryStats {
    pub elapsed_ms: f64,
    pub rows: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Rows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub stats: QueryStats,
}

impl Rows {
    /// Vue typée d'un résultat `run_query_ex`/`query_soql` (`{columns, rows, stats}`). `None` si la forme
    /// n'est pas celle attendue (ex. erreur amont). Sert de pont vers le DTO du SPI sans changer le chemin live.
    pub fn from_query_json(v: &Value) -> Option<Rows> {
        let columns = v.get("columns")?.as_array()?.iter().filter_map(|c| c.as_str().map(|s| s.to_string())).collect();
        let rows = v.get("rows")?.as_array()?.iter()
            .map(|r| r.as_array().cloned().unwrap_or_default())
            .collect();
        let st = v.get("stats");
        let stats = QueryStats {
            elapsed_ms: st.and_then(|s| s.get("elapsed_ms")).and_then(|x| x.as_f64()).unwrap_or(0.0),
            rows: st.and_then(|s| s.get("rows")).and_then(|x| x.as_u64()).unwrap_or(0) as usize,
            truncated: st.and_then(|s| s.get("truncated")).and_then(|x| x.as_bool()).unwrap_or(false),
        };
        Some(Rows { columns, rows, stats })
    }
}

// ====================================================================================================
// DÉCOUPLAGE DE LA SPI `EventStore` DU TYPE `rusqlite` (readiness pivot « pluggable store »).
//
// La couture data-plane (`trait EventStore`) a été taillée à l'origine CONTRE le modèle d'exécution
// SQLite : les `insert_*` prenaient un `&rusqlite::Connection` et renvoyaient un `rusqlite::Result`.
// CE TYPE EST LE COUPLAGE : un backend non-SQLite (DuckDB tier WARM, ClickHouse tier COLD) n'a ni
// `rusqlite::Connection` ni `rusqlite::Error`. LE DÉCOUPLAGE neutralise donc la SPI en l'exprimant
// sur des types NEUTRES définis ICI (le cœur ne gagne AUCUNE
// dépendance backend — ni rusqlite ni duckdb : cf. l'en-tête du module) :
//   - `StoreError`  : erreur neutre (l'impl mappe son erreur native vers `Backend`) ;
//   - `StoreHandle` : la connexion writer TYPE-EFFACÉE (`&dyn Any`) passée PAR APPEL — le cœur ignore
//                     le type concret ; l'impl la re-caste (`downcast`) vers SA connexion ;
//   - `trait EventStore` : la SPI backend-neutre que `SqlcipherStore` (byte-identique) ET `DuckDbStore`
//                     (tier WARM, feature-gated) implémentent.
//
// APPROCHE ADDITIVE (byte-identité mode 0 = invariant absolu). Les ~82 call-sites/handlers du daemon
// restent SUR le chemin rusqlite direct (le trait interne `SqlcipherEventStore` côté daemon, dont l'impl
// émet le SQL byte-identique historique). Cette SPI neutre est une COUCHE devant : `SqlcipherStore`
// l'implémente en re-castant `StoreHandle::Sqlite(&Connection)` puis en déléguant au chemin rusqlite ->
// mode 0 STRICTEMENT inchangé. La migration COMPLÈTE des call-sites vers la SPI neutre est un
// FOLLOW-UP volontairement différé pour ne pas risquer la parité en un seul pass.
// ====================================================================================================

/// Erreur neutre de la SPI store : découple la couture de `rusqlite::Error`. Le cœur ne porte
/// AUCUNE dépendance backend -> toute erreur native (exécution SQL, I/O, protocole réseau) est rendue en
/// texte ici ; l'impl concrète (`SqlcipherStore`/`DuckDbStore`) mappe son type d'erreur vers `Backend`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Échec natif du backend (exécution SQL, I/O, protocole), rendu en texte.
    Backend(String),
    /// L'émission SOQL -> SQL (compilation) a échoué AVANT toute exécution.
    Emit(String),
    /// Le `StoreHandle` transmis à l'impl ne correspond pas au backend qu'elle pilote (mauvais routage /
    /// erreur de programmation) : ex. un `DuckDbStore` reçoit un handle `Sqlite`.
    WrongHandle { expected: &'static str, got: &'static str },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Backend(m) => write!(f, "store backend error: {m}"),
            StoreError::Emit(m) => write!(f, "GXQL emission error: {m}"),
            StoreError::WrongHandle { expected, got } => {
                write!(f, "wrong store handle: impl expects `{expected}`, got `{got}`")
            }
        }
    }
}
impl std::error::Error for StoreError {}

/// Handle de connexion writer BACKEND-NEUTRE, passé PAR APPEL au chemin d'écriture. Le cœur ne
/// possède AUCUN type de connexion backend (pas de dép rusqlite/duckdb — délibéré), donc la connexion
/// vivante voyage TYPE-EFFACÉE derrière `&dyn Any` ; l'impl concrète la re-caste vers son propre type
/// (`downcast`). Le tag de variante NOMME le tier (diagnostic + `WrongHandle`) — ce n'est PAS une
/// dépendance backend (il n'enveloppe que `&dyn Any`). Le routing par-tenant est PRÉSERVÉ : l'appelant
/// résout la connexion writer du tenant et l'enveloppe ici à chaque appel (le store reste sans état).
pub enum StoreHandle<'a> {
    /// Connexion SQLite/SQLCipher (`&rusqlite::Connection`), effacée. `SqlcipherStore` la re-caste.
    Sqlite(&'a dyn std::any::Any),
    /// Connexion DuckDB (`&duckdb::Connection`), effacée. `DuckDbStore` la re-caste (feature `duckdb`).
    DuckDb(&'a dyn std::any::Any),
    /// Coordonnée ClickHouse (client/tenant, ex. `&clickhouse::Client`), effacée. `ClickHouseStore` la
    /// re-caste (feature `clickhouse`, tier COLD). Variante NON gatée ici (elle n'enveloppe que `&dyn Any` —
    /// AUCUNE dépendance `clickhouse` dans le cœur), exactement comme la variante `DuckDb`.
    ClickHouse(&'a dyn std::any::Any),
    /// Coordonnée du tier COLD PARQUET (Phase 1), effacée. Le writer Parquet (côté daemon, feature
    /// `cold_tier`) la re-caste vers sa coordonnée d'écriture concrète. Gatée `cold_tier` : sans la feature
    /// la variante n'existe PAS -> l'enum `StoreHandle` du build DÉFAUT est byte-identique. Comme `DuckDb`/
    /// `ClickHouse`, elle n'enveloppe qu'un `&dyn Any` -> AUCUNE dépendance `parquet` ne remonte au cœur.
    #[cfg(feature = "cold_tier")]
    Parquet(&'a dyn std::any::Any),
}

impl<'a> StoreHandle<'a> {
    /// Nom du tier porté par ce handle (diagnostic + message `WrongHandle`).
    pub fn tag(&self) -> &'static str {
        match self {
            StoreHandle::Sqlite(_) => "sqlite",
            StoreHandle::DuckDb(_) => "duckdb",
            StoreHandle::ClickHouse(_) => "clickhouse",
            #[cfg(feature = "cold_tier")]
            StoreHandle::Parquet(_) => "parquet",
        }
    }
    /// Re-caste le handle effacé vers le type de connexion concret `T` attendu par l'impl. Renvoie
    /// `WrongHandle` si le tier ne correspond pas (mauvais routage) — jamais un panic.
    pub fn downcast<T: std::any::Any>(&self, expected: &'static str) -> Result<&'a T, StoreError> {
        let any: &'a dyn std::any::Any = match self {
            StoreHandle::Sqlite(c) => *c,
            StoreHandle::DuckDb(c) => *c,
            StoreHandle::ClickHouse(c) => *c,
            #[cfg(feature = "cold_tier")]
            StoreHandle::Parquet(c) => *c,
        };
        any.downcast_ref::<T>()
            .ok_or(StoreError::WrongHandle { expected, got: self.tag() })
    }
}

/// SPI data-plane BACKEND-NEUTRE : la couture `EventStore` exprimée sur `StoreHandle`/`StoreError`
/// (et PLUS sur `rusqlite`). C'est le contrat qu'un backend non-SQLite implémente (`DuckDbStore` tier WARM,
/// futur `ClickHouseStore` tier COLD). `SqlcipherStore` l'implémente en re-castant `StoreHandle::Sqlite` vers
/// `&rusqlite::Connection` et en déléguant à son chemin rusqlite byte-identique -> mode 0 inchangé
/// (les handlers legacy continuent d'appeler le trait interne rusqlite directement ; cette couche neutre
/// est ADDITIVE — l'ENABLER d'un second backend, pas une réécriture des call-sites).
///
/// Object-safe (`&dyn EventStore`) : le seam d'ingest stateless (`ingest_batch`) route à travers `&dyn`.
pub trait EventStore {
    /// INSERT canonique d'un event (dédup côté backend). Ordre/valeurs figés (byte-identique côté SQLite).
    fn insert_event(&self, h: StoreHandle, row: &EventRow) -> Result<usize, StoreError>;
    /// INSERT d'une métrique (série temporelle).
    fn insert_metric(&self, h: StoreHandle, m: &MetricRow) -> Result<usize, StoreError>;
    /// INSERT d'un snapshot point-in-time.
    fn insert_snapshot(&self, h: StoreHandle, s: &SnapshotRow) -> Result<usize, StoreError>;
    /// INSERT par LOT : primitive d'écriture du tier d'ingest — un FRONT d'ingest stateless
    /// flush N lignes à travers la SPI sans aller-retour par ligne. `SqlcipherStore` = boucle à statement
    /// PRÉPARÉ (lignes byte-identiques) ; un backend analytique bufferise (async-insert ClickHouse).
    fn insert_events(&self, h: StoreHandle, rows: &[EventRow]) -> Result<usize, StoreError>;
    /// Texte SQL canonique de l'INSERT event (source unique de vérité), SYMÉTRIQUE de `metric_insert_sql`
    /// — pour les boucles à statement préparé / l'ingest batché.
    fn event_insert_sql(&self) -> &'static str;
    /// Texte SQL canonique de l'INSERT métrique (boucles à statement préparé).
    fn metric_insert_sql(&self) -> &'static str;
    /// ÉMISSION SOQL -> SQL du backend (émission possédée par le store via son `Dialect`). VARIANTE
    /// TENANT-WIDE / NON masquée : détection (règles tenant-wide, sans appelant) et rollups. Un chemin
    /// RÔLE-SCOPÉ (query/export/panels) NE DOIT JAMAIS appeler cette variante : il passe par `soql_to_sql_masked`.
    fn soql_to_sql(&self, soql: &str, from: i64, to: i64, env: Option<&str>) -> Result<String, StoreError>;
    /// FIELD FILTERS — ÉMISSION SOQL -> SQL AVEC masques de champ EFFECTIFS (résolus par le daemon pour
    /// le RÔLE/tenant/env de l'appelant), pour TOUT chemin de lecture ROLE-SCOPÉ sur CE backend (y compris les
    /// tiers WARM/COLD DuckDB/ClickHouse). VIDE -> STRICTEMENT identique à `soql_to_sql` (mode 0 byte-identique).
    /// DÉFAUT = FAIL-CLOSED : un backend qui n'implémente pas le masquage REFUSE toute compilation masquée ->
    /// jamais de SQL NON masqué servi à un rôle restreint (protège plutôt que fuir). Les tiers qui SAVENT émettre
    /// le masque via leur `Dialect` (`Schema::events_*().with_masks(...)`) l'OVERRIDENT. Miroir EXACT du
    /// fail-closed déjà éprouvé sur le trait chaud interne (`SqlcipherEventStore::soql_to_sql_masked`).
    fn soql_to_sql_masked(&self, soql: &str, from: i64, to: i64, env: Option<&str>, masks: &crate::soql::FieldMaskSet) -> Result<String, StoreError> {
        if masks.is_empty() {
            return self.soql_to_sql(soql, from, to, env);
        }
        Err(StoreError::Emit("field-filters non supportés sur ce backend de stockage (tier WARM/COLD) — lecture role-scopée refusée par sécurité".into()))
    }
    /// LECTURE SOQL de bout en bout : compile PUIS exécute contre `db_path` (chemin fichier pour SQLite ET
    /// DuckDB), borné par `budget_ms` + annulable via `qid`. Renvoie la forme JSON live `{columns,rows,stats}`.
    /// VARIANTE TENANT-WIDE / NON masquée (cf. `soql_to_sql`).
    fn query_soql(&self, db_path: &str, soql: &str, from: i64, to: i64, env: Option<&str>, budget_ms: u64, qid: Option<&str>) -> Result<Value, StoreError>;
    /// FIELD FILTERS — LECTURE SOQL ROLE-SCOPÉE de bout en bout AVEC masques (cf. `soql_to_sql_masked`).
    /// DÉFAUT = FAIL-CLOSED (refuse un masque non vide) ; les backends qui savent masquer l'OVERRIDENT.
    fn query_soql_masked(&self, db_path: &str, soql: &str, from: i64, to: i64, env: Option<&str>, budget_ms: u64, qid: Option<&str>, masks: &crate::soql::FieldMaskSet) -> Result<Value, StoreError> {
        if masks.is_empty() {
            return self.query_soql(db_path, soql, from, to, env, budget_ms, qid);
        }
        Err(StoreError::Emit("field-filters non supportés sur ce backend de stockage (tier WARM/COLD) — lecture role-scopée refusée par sécurité".into()))
    }
}

/// SEAM D'INGEST STATELESS (prérequis HA du tier COLD). Un front d'ingest/HEC n'a PAS besoin de savoir
/// quel backend il vise ni s'il existe un état SQLCipher local : il remet des lignes normalisées + un
/// `StoreHandle` résolu à `ingest_batch`, qui écrit à travers la SPI `EventStore` (`insert_events`).
/// C'est LA couture qui permet au tier d'ingest de tourner en N réplicas STATELESS devant un store
/// PARTAGÉ (la durabilité vit dans le store, pas dans le pod). L'impl horizontale complète (LB + rejeu
/// de spool durable + async) est différée à une phase ultérieure du tier COLD ; ici on POSE la couture + le design.
pub fn ingest_batch(store: &dyn EventStore, handle: StoreHandle, rows: &[EventRow]) -> Result<usize, StoreError> {
    store.insert_events(handle, rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    // Backend NON-rusqlite (mémoire pure) qui monte la SPI neutre `EventStore` : PREUVE que la
    // couture ne dépend plus d'un type backend concret (aucun rusqlite/duckdb ici). Il ignore le
    // `StoreHandle` (pas de connexion) -> démontre qu'un store sans `rusqlite::Connection` ride la SPI.
    #[derive(Default)]
    struct MemStore {
        events: RefCell<Vec<EventRow>>,
    }
    impl EventStore for MemStore {
        fn insert_event(&self, _h: StoreHandle, row: &EventRow) -> Result<usize, StoreError> {
            self.events.borrow_mut().push(row.clone());
            Ok(1)
        }
        fn insert_metric(&self, _h: StoreHandle, _m: &MetricRow) -> Result<usize, StoreError> { Ok(1) }
        fn insert_snapshot(&self, _h: StoreHandle, _s: &SnapshotRow) -> Result<usize, StoreError> { Ok(1) }
        fn insert_events(&self, _h: StoreHandle, rows: &[EventRow]) -> Result<usize, StoreError> {
            self.events.borrow_mut().extend(rows.iter().cloned());
            Ok(rows.len())
        }
        fn event_insert_sql(&self) -> &'static str { "INSERT INTO event(...) VALUES(...)" }
        fn metric_insert_sql(&self) -> &'static str { "INSERT INTO metric(...) VALUES(...)" }
        fn soql_to_sql(&self, soql: &str, _f: i64, _t: i64, _e: Option<&str>) -> Result<String, StoreError> {
            Ok(format!("-- compiled: {soql}"))
        }
        fn query_soql(&self, _p: &str, _s: &str, _f: i64, _t: i64, _e: Option<&str>, _b: u64, _q: Option<&str>) -> Result<Value, StoreError> {
            Ok(serde_json::json!({"columns":[],"rows":[],"stats":{"elapsed_ms":0.0,"rows":0,"truncated":false}}))
        }
    }

    // Le seam d'ingest stateless route un lot à travers `&dyn EventStore` — sans connaître le backend.
    #[test]
    fn stateless_ingest_seam_routes_batch_through_neutral_spi() {
        let store = MemStore::default();
        let unit = ();
        let rows = vec![
            EventRow { ts: 1, source: "a".into(), category: "log".into(), ..Default::default() },
            EventRow { ts: 2, source: "b".into(), category: "log".into(), ..Default::default() },
        ];
        let n = ingest_batch(&store, StoreHandle::Sqlite(&unit), &rows).unwrap();
        assert_eq!(n, 2);
        assert_eq!(store.events.borrow().len(), 2);
    }

    // La variante masquée du SPI neutre est FAIL-CLOSED par défaut. Un backend (ici `MemStore`) qui
    // n'override PAS `soql_to_sql_masked` REFUSE toute compilation avec masques NON vides -> jamais de SQL non
    // masqué servi à un rôle restreint. Masques VIDES -> délègue à `soql_to_sql` (mode 0 inchangé).
    #[test]
    fn masked_spi_fail_closed_by_default() {
        use crate::soql::{FieldMaskSet, MaskAction};
        let store = MemStore::default();
        // Masques VIDES -> passe (délégué au chemin non masqué).
        assert!(store.soql_to_sql_masked("search", 0, 0, None, &FieldMaskSet::new()).is_ok());
        assert!(store.query_soql_masked("p", "search", 0, 0, None, 0, None, &FieldMaskSet::new()).is_ok());
        // Masques NON vides sur un backend sans override -> REFUS (fail-closed), pas d'émission non masquée.
        let mut m = FieldMaskSet::new();
        m.insert("pan", MaskAction::Mask);
        assert!(matches!(store.soql_to_sql_masked("search", 0, 0, None, &m), Err(StoreError::Emit(_))),
            "backend non masquant DOIT refuser une lecture masquée (fail-closed)");
        assert!(matches!(store.query_soql_masked("p", "search", 0, 0, None, 0, None, &m), Err(StoreError::Emit(_))),
            "query masquée sur backend non masquant DOIT refuser (fail-closed)");
    }

    // `StoreHandle::downcast` re-caste le handle effacé et rejette proprement un mauvais tier.
    #[test]
    fn store_handle_downcast_and_wrong_handle() {
        let n: i64 = 42;
        let h = StoreHandle::Sqlite(&n);
        assert_eq!(*h.downcast::<i64>("sqlite").unwrap(), 42);
        // mauvais type concret -> WrongHandle (jamais un panic).
        match h.downcast::<String>("sqlite-string") {
            Err(StoreError::WrongHandle { expected, got }) => {
                assert_eq!(expected, "sqlite-string");
                assert_eq!(got, "sqlite");
            }
            other => panic!("attendu WrongHandle, obtenu {other:?}"),
        }
    }
}
