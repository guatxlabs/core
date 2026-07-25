//! cim — contrat CIM (Common Information Model) partagé.
//!
//! Le CIM est le vocabulaire NEUTRE, inter-vendeur, sur lequel composent les détections : taxonomie
//! `category` (`CIM_CATEGORIES`), champs CŒUR (`CIM_CORE_FIELDS`), vocabulaire d'outcome `action`
//! (`CIM_ACTION_VOCAB`) et version du contrat (`CIM_VERSION`). Ce sont des CONSTANTES PURES + un
//! validateur pur (`cim_category_ok`) — AUCUN couplage rusqlite ni FS. Ils remontent dans le cœur
//! partagé pour être une source unique de vérité côté Plume ET Forge. Le PARSER de DSL d'ingest
//! (spécifique ingest) reste au daemon ; seul le contrat de vocabulaire est ici.

/// Version du contrat CIM (SemVer `majeur.mineur`). Majeur = rupture de taxonomie/champs.
/// v1.1 — additif : catégories `posture` (config-assessment / SCA-CIS) et `inventory`
/// (télémétrie d'inventaire endpoint : paquets/ports/processus). Bump MINEUR (ajout pur).
/// v1.2 — additif : catégorie `trace` (télémétrie OpenTelemetry : spans distribués, corrélables
/// aux logs par `trace_id`). Bump MINEUR (ajout pur, aucune category existante déplacée).
/// v1.3 — additif : homes CANONIQUES pour des catégories additionnelles émises par les
/// collecteurs — `exec` (exécution de processus), `secrets` (audit d'accès aux secrets),
/// `account` (gestion de comptes), `recon` (énumération) et les sous-étapes du collecteur mail
/// (`postscreen`/`reject`/`mailflow`/`mail-phishing`/`mail-url`). Ajouter une valeur à l'allow-list ne
/// réécrit AUCUNE ligne : les events déjà stockés deviennent conformes RÉTROACTIVEMENT, zéro migration.
/// Bump MINEUR (ajout pur, aucune category existante déplacée/renommée).
pub const CIM_VERSION: &str = "1.3";

/// TAXONOMIE CIM v1 — vocabulaire NEUTRE et closed-ish de `category` (l'axe de composition
/// inter-vendeur des détections). DEUX namespaces (le runtime les traite à L'IDENTIQUE ; la scission
/// est une GUIDANCE, cf. la documentation CIM du produit) : SÉCURITÉ (signal d'attaque, où composent
/// les règles `category=…`) et OPÉRATIONNEL/PLATEFORME (télémétrie collecteur, config, audit —
/// alimente santé/couverture/whitelists). Toute valeur ici est DÉJÀ émise par un parseur de
/// collecteur (syslog, pare-feu, endpoint…) ou consommée par une règle livrée. Étendre = bump
/// CIM_VERSION + màj de la documentation CIM + du miroir machine de la taxonomie côté daemon
/// (le test garde la parité).
pub const CIM_CATEGORIES: &[&str] = &[
    // — Sécurité (27) — l'axe de composition des détections.
    "firewall", "ids", "alert", "web", "malware", "auth", "dns", "mail", "dlp", "vpn",
    "application", "endpoint", "network", "data", "tamper", "vuln", "utm", "posture",
    // v1.3 — homes canoniques RÉTROACTIFS des catégories déjà émises par des collecteurs
    // (audit système, secrets, mail) ; ajout pur à l'allow-list, aucune ligne existante réécrite.
    "exec", "secrets", "account", "recon",
    "postscreen", "reject", "mailflow", "mail-phishing", "mail-url",
    // — Opérationnel / plateforme (13) — télémétrie, config, audit (pas un signal primaire).
    "health", "config", "audit", "system", "update", "container", "k8s", "ebpf", "ban",
    "integrity", "syslog", "inventory", "trace",
];

/// Jeu de champs CŒUR du CIM = les colonnes promues de `EventRow` (première classe,
/// indexées/filtrables directement). Miroir-de-contrat ; la définition qui FAIT FOI reste la
/// struct `EventRow` + `EVENT_INSERT_SQL`. (`fields` = sac JSON des champs ÉTENDUS.)
pub const CIM_CORE_FIELDS: &[&str] = &[
    "ts", "source", "category", "severity", "message", "host", "src_ip", "dst_ip", "url",
    "dedup", "fields", "engagement_id", "origin", "env_id",
];

/// Vocabulaire NEUTRE de `fields.action` (outcome normalisé CIM, dimension chaude de
/// rollup — cf. HOT_FIELDS). Valeurs cross-source produites par les collecteurs/parsers
/// (journal_action, fgt, web…). Guidance de mapping : réutiliser ces verbes neutres.
pub const CIM_ACTION_VOCAB: &[&str] = &[
    "success", "failure", "allowed", "blocked", "ban", "read", "modify", "delete",
    "sudo", "session_open", "session_close",
];

/// La `category` déclarée est-elle dans la taxonomie CIM v1 ? Validation PARSE/MAP — JAMAIS
/// un drop : l'appelant AVERTIT sur `false`, il ne rejette pas l'event (cf. anti-angle-mort).
pub fn cim_category_ok(category: &str) -> bool {
    CIM_CATEGORIES.contains(&category)
}

/// VOCABULAIRE DE CADRES DE CONFORMITÉ — jeu NEUTRE et canonique des cadres réglementaires
/// sur lesquels un contrôle de posture (SCA/CIS) ou une règle de détection peut être MAPPÉ. Les IDs
/// sont NORMALISÉS (minuscule, `_` séparateur) et alignés sur les clés que Wazuh émet dans
/// `data.sca.check.compliance.*` (cf. `ingest/endpoint.rs::flatten_compliance` -> `posture_framework`/
/// `posture_compliance`), pour que la posture ingérée et le tag de règle JOIGNENT sur le MÊME token.
/// CLOSED-ISH mais EXTENSIBLE : ce const est le socle par DÉFAUT ; le daemon l'UNIONNE avec une liste
/// additionnelle de CONFIG (`PLUME_COMPLIANCE_FRAMEWORKS`, CSV) -> ajouter un cadre client (ex `soc2`,
/// `dora`) ne demande PAS de rebuild (même philosophie vendor-agnostic que `endpoint_sources`). Le
/// CONTRÔLE (`control id`) reste LIBRE (ex `8.7`, `164.312(a)`, `AU-2`) — seule la FRAMEWORK est bornée.
pub const COMPLIANCE_FRAMEWORKS: &[&str] = &[
    "pci_dss", "hipaa", "nist_800_53", "gdpr", "tsc", "iso_27001", "cis",
];

/// Le cadre de conformité déclaré est-il dans le vocabulaire canonique CIM ? Validation PARSE/MAP pure
/// (comme `cim_category_ok`). Le daemon ÉTEND ce socle via config avant d'appeler sa propre validation ;
/// ceci reste la source de vérité des cadres BUILT-IN. Casse/vide/hors-vocab -> false.
pub fn compliance_framework_ok(fw: &str) -> bool {
    COMPLIANCE_FRAMEWORKS.contains(&fw)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CONTRAT CIM auto-cohérent (la moitié PURE de l'ancien test daemon, déplacée avec les consts) :
    /// `cim_category_ok` accepte toutes les catégories réellement émises/consommées, rejette casse/vide/
    /// hors-taxonomie, et la taxonomie est sans doublon. La PARITÉ avec le miroir machine de la
    /// taxonomie (côté daemon) reste testée CÔTÉ DAEMON via `include_str!`.
    #[test]
    fn cim_contract_is_self_consistent() {
        // 1. cim_category_ok : les categories RÉELLEMENT émises/consommées passent…
        for c in [
            "firewall", "ids", "alert", "web", "malware", "auth", "dns", "mail", "dlp",
            "vpn", "application", "endpoint", "network", "data", "tamper", "vuln", "utm",
            "posture",
            // v1.3 — catégories rendues canoniques (rétroactif).
            "exec", "secrets", "account", "recon",
            "postscreen", "reject", "mailflow", "mail-phishing", "mail-url",
            "health", "config", "audit", "system", "update", "container", "k8s", "ebpf",
            "ban", "integrity", "syslog", "inventory", "trace",
        ] {
            assert!(cim_category_ok(c), "category CIM connue rejetée: {c}");
        }
        // …et une valeur hors-taxonomie (ou casse/vide) ne passe pas.
        for c in ["", "nope", "Firewall", "http", "attack", "syslog "] {
            assert!(!cim_category_ok(c), "category hors-taxonomie acceptée à tort: {c:?}");
        }
        // 2. pas de doublon dans la taxonomie.
        let mut seen = std::collections::HashSet::new();
        for c in CIM_CATEGORIES {
            assert!(seen.insert(*c), "doublon dans CIM_CATEGORIES: {c}");
        }
    }

    /// CONTRAT CONFORMITÉ : le vocabulaire de cadres est cohérent (les cadres majeurs passent,
    /// casse/vide/hors-vocab échoue, pas de doublon). Les IDs sont alignés Wazuh (`pci_dss`, `hipaa`,
    /// `nist_800_53`, `gdpr`, `tsc`, `cis`) pour joindre la posture ingérée.
    #[test]
    fn compliance_framework_vocab_is_consistent() {
        for fw in ["pci_dss", "hipaa", "nist_800_53", "gdpr", "tsc", "iso_27001", "cis"] {
            assert!(compliance_framework_ok(fw), "cadre de conformité connu rejeté: {fw}");
        }
        for fw in ["", "nope", "PCI_DSS", "pci-dss", "hipaa "] {
            assert!(!compliance_framework_ok(fw), "cadre hors-vocab accepté à tort: {fw:?}");
        }
        let mut seen = std::collections::HashSet::new();
        for fw in COMPLIANCE_FRAMEWORKS {
            assert!(seen.insert(*fw), "doublon dans COMPLIANCE_FRAMEWORKS: {fw}");
        }
    }
}
