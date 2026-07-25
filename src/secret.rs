//! SECRET-PROVIDER SPI (Phase 2) — UNE seule abstraction pour les secrets de Plume : un `trait
//! SecretProvider`, une grammaire `SecretRef` (`scheme:rest`) et des providers PURS (aucun rusqlite,
//! unit-testables) qui unifient les trois résolveurs parallèles historiques du daemon.
//!
//! INVARIANT — RÉTROCOMPAT BYTE-IDENTIQUE : `FileProvider` porte les OCTETS EXACTS de l'ancien
//! `read_secret_file`/`read_secret_file_setup_safe`/`db_key_from_file` (lecture VERBATIM, aucun strip,
//! 0 octet -> `NotFound`, non-UTF8 -> `Malformed`, absent -> `NotFound`, illisible -> `Unreadable`).
//! Le MÊME Secret k8s alimente et l'ancien env (via `env::var`, qui ne retire rien) et le fichier
//! (projection brute, byte-pour-byte) -> `file == env` par construction. Retirer un `\n` fabriquerait
//! une divergence file≠env au cutover (SQLCipher décrypte alors avec une clé différente = outage).
//!
//! SÉPARATION PROVIDER / POLITIQUE : les providers renvoient un `SecretOutcome`/`SecretError` NEUTRE
//! (schéma-behavior uniquement). C'est l'ADAPTATEUR APPELANT (côté daemon) qui applique SA politique
//! (fail-closed `exit(78)` strict, setup-safe `""`, `Ok(None)` clair, reject-cleartext…). On PRÉSERVE
//! ainsi la sémantique PROPRE à chaque appelant sans l'homogénéiser.
//!
//! JAMAIS DE SECRET DANS UN LOG : `SecretError` ne porte QUE chemin/schéma/nature ; `SecretValue` est
//! `Debug`-rédigé et zeroizé au drop (`secrecy::SecretString`).

use secrecy::{ExposeSecret, SecretString};

/// Valeur de secret résolue. Enveloppe `secrecy::SecretString` : `Debug` rédigé, zéroïsée au drop.
/// N'expose la matière qu'explicitement via `expose()`/`into_string()` (chemins de cutover verbatim).
#[derive(Clone)]
pub struct SecretValue(SecretString);

impl SecretValue {
    /// Construit depuis une `String` déjà lue VERBATIM (aucun strip appliqué ici).
    pub fn new(s: String) -> Self {
        SecretValue(SecretString::from(s))
    }
    /// Emprunte la matière (pour l'appliquer, ex. `PRAGMA key`). NE PAS journaliser.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
    /// Consomme et rend la `String` (pour les appelants qui ont besoin d'une `String` possédée,
    /// ex. rétrocompat `cfg_secret -> String`). NE PAS journaliser.
    pub fn into_string(self) -> String {
        self.0.expose_secret().to_string()
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // JAMAIS la matière (défense en profondeur : `secrecy` rédige déjà, on le rend explicite).
        f.write_str("SecretValue(REDACTED)")
    }
}

/// Issue NON-ERREUR d'une résolution. `NotFound` = la source n'a PAS de valeur (fichier absent/vide,
/// var d'env absente/vide) — état LÉGITIME que l'appelant interprète (clair / setup / repli). `Present`
/// = valeur lue.
#[derive(Debug)]
pub enum SecretOutcome {
    /// Aucune valeur (absent ou vide). L'appelant décide : `""`/clair/setup, ou fail-closed.
    NotFound,
    /// Valeur présente (VERBATIM sauf provider explicitement trimmant).
    Present(SecretValue),
}

/// Échec d'une source CONFIGURÉE — TOUJOURS fail-closed côté appelant (jamais avalé en `""`). Ne porte
/// JAMAIS la matière : chemin/schéma/nature seulement.
#[derive(Debug)]
pub enum SecretError {
    /// Source présente mais illisible (permission / I/O autre que « absent »).
    Unreadable(String),
    /// Source présente mais non conforme (contenu non-UTF8, `literal:` vide…).
    Malformed(String),
    /// Backend distant en échec (Vault non configuré / injoignable / champ absent).
    Backend(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::Unreadable(s) => write!(f, "illisible ({s})"),
            SecretError::Malformed(s) => write!(f, "malformé ({s})"),
            SecretError::Backend(s) => write!(f, "backend ({s})"),
        }
    }
}

/// SPI de résolution d'un secret depuis UNE source (un schéma). Les impls sont PURES (providers core)
/// ou fines (VaultProvider HTTP côté daemon). `Send + Sync` : partageables derrière un `dyn`.
pub trait SecretProvider: Send + Sync {
    /// Schéma géré (`"file"`, `"env"`, `"literal"`, `"vault"`…).
    fn scheme(&self) -> &'static str;
    /// Résout `r` (dont `r.scheme()` DOIT == `self.scheme()`). Renvoie l'issue neutre / l'erreur.
    fn get(&self, r: &SecretRef) -> Result<SecretOutcome, SecretError>;
}

/// Grammaire `scheme:rest`. Schémas RECONNUS : `file` / `env` / `literal` / `vault`. Une chaîne SANS
/// préfixe de schéma reconnu -> `scheme == ""` (« unscheme ») : l'APPELANT décide (chemin nu -> `file:`
/// pour la rétrocompat `{KEY}_FILE`/`{KEY}_REF` ; ou reject-cleartext pour un overlay committé en git).
/// `vault:` : `rest == "MOUNT/path#field"` (le `#field` généralise l'ancien `data.data.key` codé en dur).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    scheme: String,
    rest: String,
}

const KNOWN_SCHEMES: &[&str] = &["file", "env", "literal", "vault"];

impl SecretRef {
    /// Classe `s` en `(scheme, rest)`. Si `s` commence par un schéma RECONNU suivi de `:`, on scinde ;
    /// sinon `scheme == ""` (unscheme) et `rest == s` (chaîne brute — chemin nu OU cleartext, à la
    /// discrétion de l'appelant). NE trim RIEN (le trim est une politique d'appelant, cf. overlays).
    pub fn parse(s: &str) -> SecretRef {
        if let Some(idx) = s.find(':') {
            let pfx = &s[..idx];
            if KNOWN_SCHEMES.contains(&pfx) {
                return SecretRef {
                    scheme: pfx.to_string(),
                    rest: s[idx + 1..].to_string(),
                };
            }
        }
        SecretRef {
            scheme: String::new(),
            rest: s.to_string(),
        }
    }

    /// Construit explicitement un `file:` (ex. `{KEY}_FILE` = chemin nu -> file: rétrocompat).
    pub fn file(path: &str) -> SecretRef {
        SecretRef { scheme: "file".to_string(), rest: path.to_string() }
    }
    /// Construit explicitement un `env:`.
    pub fn env(name: &str) -> SecretRef {
        SecretRef { scheme: "env".to_string(), rest: name.to_string() }
    }
    /// Construit explicitement un `literal:`.
    pub fn literal(value: &str) -> SecretRef {
        SecretRef { scheme: "literal".to_string(), rest: value.to_string() }
    }

    /// Schéma reconnu, ou `""` (unscheme).
    pub fn scheme(&self) -> &str {
        &self.scheme
    }
    /// Corps après `scheme:` (ou la chaîne brute si unscheme).
    pub fn rest(&self) -> &str {
        &self.rest
    }

    /// Décompose un `rest` de `vault:` en `(path, field)`. `MOUNT/p#field` -> (`MOUNT/p`, `field`) ;
    /// sans `#`, le champ par défaut est `key` (rétrocompat EXACTE de l'ancien `data.data.key`).
    pub fn vault_path_field(&self) -> (&str, &str) {
        match self.rest.split_once('#') {
            Some((p, fld)) if !fld.is_empty() => (p, fld),
            Some((p, _)) => (p, "key"),
            None => (self.rest.as_str(), "key"),
        }
    }
}

// =====================================================================================================
// PROVIDERS PURS (core). Comportement SCHÉMA uniquement ; la politique fail-closed/setup/clair est côté
// appelant (daemon). Aucun rusqlite, aucun réseau -> unit-testables in-process.
// =====================================================================================================

/// `file:/chemin` — lecture VERBATIM (byte-exact) d'un secret monté RO. PORTE LES OCTETS EXACTS de
/// l'ancien `read_secret_file`/`read_secret_file_setup_safe`/`db_key_from_file` :
///   - absent (`NotFound` I/O) ......... `Ok(NotFound)`   (l'appelant : setup légitime OU fail-closed)
///   - vide (0 octet) .................. `Ok(NotFound)`   (miroir de `env::var(..).filter(!is_empty)`)
///   - présent lisible non-vide ........ `Ok(Present(v))` (VERBATIM — AUCUN strip)
///   - présent non-UTF8 ................ `Err(Malformed)` (fail-closed — PAS de retour setup)
///   - présent illisible (perm/I/O) .... `Err(Unreadable)`(fail-closed)
/// La distinction ABSENT vs PRÉSENT-MAIS-CASSÉ (triple-guard PASS_HASH) est PORTÉE ICI : `NotFound`
/// (absent/vide) ≠ `Err` (cassé). Collapser les deux = contournement de re-bootstrap d'auth CRITIQUE.
pub struct FileProvider;

impl SecretProvider for FileProvider {
    fn scheme(&self) -> &'static str {
        "file"
    }
    fn get(&self, r: &SecretRef) -> Result<SecretOutcome, SecretError> {
        let path = r.rest();
        match std::fs::read(path) {
            Ok(bytes) if bytes.is_empty() => Ok(SecretOutcome::NotFound), // 0 octet -> pas de valeur
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) if s.is_empty() => Ok(SecretOutcome::NotFound), // défensif (bytes non-vide -> s non-vide)
                Ok(s) => Ok(SecretOutcome::Present(SecretValue::new(s))), // VERBATIM — aucun strip
                Err(_) => Err(SecretError::Malformed("contenu non-UTF8".to_string())),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SecretOutcome::NotFound), // ABSENT
            Err(e) => Err(SecretError::Unreadable(format!("{e}"))), // perm / autre I/O -> fail-closed
        }
    }
}

/// `env:NAME` — variable d'environnement. ATTEIGNABLE UNIQUEMENT via un `env:` EXPLICITE (jamais un
/// défaut silencieux -> le secret ne fuit pas dans /proc/environ par accident). FILTRE-VIDE : var
/// absente OU vide -> `NotFound` (miroir EXACT de `env::var(..).ok().filter(|k| !k.is_empty())` de
/// `db_key()`/`resolve_tenant_key`). Renvoie la valeur VERBATIM (aucun trim).
pub struct EnvProvider;

impl SecretProvider for EnvProvider {
    fn scheme(&self) -> &'static str {
        "env"
    }
    fn get(&self, r: &SecretRef) -> Result<SecretOutcome, SecretError> {
        match std::env::var(r.rest()) {
            Ok(v) if v.is_empty() => Ok(SecretOutcome::NotFound), // vide -> pas de valeur (filter-empty)
            Ok(v) => Ok(SecretOutcome::Present(SecretValue::new(v))), // VERBATIM
            Err(_) => Ok(SecretOutcome::NotFound), // absente -> pas de valeur
        }
    }
}

/// `literal:VALUE` — valeur directe (onboarding local / tests). VALUE vide -> `Err(Malformed)` (une
/// clé littérale vide n'a pas de sens ; miroir de l'ancien `resolve_tenant_key` `literal:` vide -> Err).
pub struct LiteralProvider;

impl SecretProvider for LiteralProvider {
    fn scheme(&self) -> &'static str {
        "literal"
    }
    fn get(&self, r: &SecretRef) -> Result<SecretOutcome, SecretError> {
        let v = r.rest();
        if v.is_empty() {
            return Err(SecretError::Malformed("literal: vide".to_string()));
        }
        Ok(SecretOutcome::Present(SecretValue::new(v.to_string())))
    }
}

// =====================================================================================================
// POINTS D'EXTENSION DISTANTS — NON IMPLÉMENTÉS (documentés). Un déploiement cloud fournirait une impl
// de `SecretProvider` pour son backend et l'enregistrerait dans le dispatch (ChainResolver côté daemon),
// EXACTEMENT comme `VaultProvider` (HTTP KV-v2, côté daemon). Bring-your-own-vendor :
// aucun hardcode, la SPI est le seul contrat. Volontairement absents ici (pas de dépendance SDK cloud
// dans le cœur 2 Go ; `Backend` porte l'échec fail-closed).
//
//   - `aws:secretsmanager/<id>#<field>`  -> AWS Secrets Manager (SDK `aws-sdk-secretsmanager`).
//   - `gcp:<project>/<secret>/<version>` -> GCP Secret Manager (SDK `google-cloud-secretmanager`).
//   - `k8s:<namespace>/<secret>#<key>`   -> lecture directe d'un Secret via l'API-server (in-cluster SA).
//
// Chaque impl : `scheme()` = le préfixe, `get()` = fetch fail-closed (absent -> `NotFound`, backend KO
// -> `Backend`, jamais de secret en clair dans l'erreur). AUCUNE n'est construite en Phase 2.

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("guatx-core-secret-{}-{}.tmp", std::process::id(), name));
        p.to_string_lossy().to_string()
    }

    #[test]
    fn secretref_parse_classifies_schemes_and_bare_paths() {
        assert_eq!(SecretRef::parse("file:/a/b").scheme(), "file");
        assert_eq!(SecretRef::parse("file:/a/b").rest(), "/a/b");
        assert_eq!(SecretRef::parse("env:PLUME_X").scheme(), "env");
        assert_eq!(SecretRef::parse("literal:abc").scheme(), "literal");
        assert_eq!(SecretRef::parse("vault:secret/data/db#key").scheme(), "vault");
        // chemin nu (pas de ':') -> unscheme, rest = brut (l'appelant décide file: ou reject).
        assert_eq!(SecretRef::parse("/data/plume/db.key").scheme(), "");
        assert_eq!(SecretRef::parse("/data/plume/db.key").rest(), "/data/plume/db.key");
        // schéma inconnu (préfixe:) -> unscheme (l'appelant reject en cleartext / préfixe inconnu).
        assert_eq!(SecretRef::parse("http://x").scheme(), "");
        // literal avec ':' dans la valeur -> split sur le PREMIER ':'.
        assert_eq!(SecretRef::parse("literal:a:b:c").rest(), "a:b:c");
    }

    #[test]
    fn vault_path_field_defaults_to_key() {
        assert_eq!(SecretRef::parse("vault:secret/data/db").vault_path_field(), ("secret/data/db", "key"));
        assert_eq!(SecretRef::parse("vault:secret/data/db#pass").vault_path_field(), ("secret/data/db", "pass"));
        // '#' vide -> défaut key (rétrocompat).
        assert_eq!(SecretRef::parse("vault:secret/data/db#").vault_path_field(), ("secret/data/db", "key"));
    }

    #[test]
    fn file_provider_verbatim_notfound_and_errors() {
        let f = FileProvider;
        // (a) VERBATIM : newline final CONSERVÉ (= byte-identique à env, anti-divergence cutover).
        let p = tmp("fp-ok");
        std::fs::write(&p, b"sso-secret\n").unwrap();
        match f.get(&SecretRef::file(&p)).unwrap() {
            SecretOutcome::Present(v) => assert_eq!(v.expose(), "sso-secret\n", "VERBATIM (newline conservé)"),
            _ => panic!("présent+lisible+non-vide -> Present"),
        }
        // (b) absent -> NotFound (l'appelant : setup OU fail-closed).
        assert!(matches!(f.get(&SecretRef::file(&tmp("fp-absent"))).unwrap(), SecretOutcome::NotFound));
        // (c) vide (0 octet) -> NotFound (miroir filter-empty).
        std::fs::write(&p, b"").unwrap();
        assert!(matches!(f.get(&SecretRef::file(&p)).unwrap(), SecretOutcome::NotFound));
        // (d) « \n » seul -> Present("\n") (non-vide, VERBATIM ; PAS strippé à vide).
        std::fs::write(&p, b"\n").unwrap();
        match f.get(&SecretRef::file(&p)).unwrap() {
            SecretOutcome::Present(v) => assert_eq!(v.expose(), "\n"),
            _ => panic!("« \\n » seul -> Present"),
        }
        // (e) non-UTF8 -> Malformed (fail-closed ; PAS NotFound -> triple-guard PASS_HASH préservé).
        std::fs::write(&p, [0xff, 0xfe, 0x00, 0x80]).unwrap();
        assert!(matches!(f.get(&SecretRef::file(&p)), Err(SecretError::Malformed(_))));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn env_provider_filter_empty_explicit_only() {
        let e = EnvProvider;
        let name = format!("PLUME_CORE_SECRET_ENVTEST_{}", std::process::id());
        // absente -> NotFound.
        std::env::remove_var(&name);
        assert!(matches!(e.get(&SecretRef::env(&name)).unwrap(), SecretOutcome::NotFound));
        // vide -> NotFound (filter-empty, miroir db_key/tenant).
        std::env::set_var(&name, "");
        assert!(matches!(e.get(&SecretRef::env(&name)).unwrap(), SecretOutcome::NotFound));
        // non-vide -> Present VERBATIM.
        std::env::set_var(&name, "val\n");
        match e.get(&SecretRef::env(&name)).unwrap() {
            SecretOutcome::Present(v) => assert_eq!(v.expose(), "val\n", "env VERBATIM (aucun trim)"),
            _ => panic!("env non-vide -> Present"),
        }
        std::env::remove_var(&name);
    }

    #[test]
    fn literal_provider_present_and_empty_malformed() {
        let l = LiteralProvider;
        match l.get(&SecretRef::literal("abc")).unwrap() {
            SecretOutcome::Present(v) => assert_eq!(v.expose(), "abc"),
            _ => panic!("literal non-vide -> Present"),
        }
        assert!(matches!(l.get(&SecretRef::literal("")), Err(SecretError::Malformed(_))));
    }

    #[test]
    fn secret_value_debug_is_redacted() {
        let v = SecretValue::new("topsecret".to_string());
        let dbg = format!("{v:?}");
        assert!(!dbg.contains("topsecret"), "Debug NE DOIT JAMAIS révéler la matière");
        assert_eq!(dbg, "SecretValue(REDACTED)");
    }
}
