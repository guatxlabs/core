//! MITRE ATT&CK technique -> tactic mapping (Enterprise). PURE (`std`-only, zéro dépendance, zéro I/O),
//! comme `ti`/`soql` : partagé Plume (SOC bleu) ↔ Forge (rouge). Sert la RBA : le rollup de risque
//! compte des TACTIQUES distinctes (kill-chain breadth) et non des techniques — deux techniques de la MÊME
//! tactique ne « comptent » qu'une fois (un attaquant qui multiplie les techniques d'une seule phase est
//! moins avancé qu'un attaquant qui touche plusieurs phases). Sans ce mapping, la fondation RBA comptait des
//! techniques distinctes (proxy grossier ; cf. commentaire `rollup_risk`).
//!
//! DESIGN — table CURÉE (pas de préfixe magique : les IDs ATT&CK `T####` sont séquentiels, PAS groupés par
//! tactique -> aucun mapping par préfixe possible). On expose la tactique CANONIQUE (shortname ATT&CK) d'une
//! technique. Une technique ATT&CK peut relever de PLUSIEURS tactiques ; on retient la tactique PRIMAIRE
//! (celle du contexte SOC le plus courant) — suffisant pour la « largeur de kill-chain » de la RBA. Une
//! SOUS-technique (`T1110.001`) hérite de la tactique de sa technique PARENTE (`T1110`) : on tronque au `.`.
//! Table VALIDÉE contre l'ATT&CK Enterprise (v14+) pour toutes les techniques utilisées par les règles
//! seedées de Plume + un sur-ensemble des techniques SOC courantes (bring-your-own-vendor : un client peut
//! taguer ses règles avec n'importe quelle technique ATT&CK et obtenir la bonne tactique).

/// Les 14 tactiques ATT&CK Enterprise (shortname canonique, kebab-case — identique au champ `x_mitre`
/// `shortname` d'ATT&CK). Exposées pour l'UI / la validation.
pub const TACTICS: &[&str] = &[
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
];

/// Normalise un identifiant de technique en sa TECHNIQUE PARENTE canonique `T####` (majuscules, sans la
/// sous-technique). `"t1110.001"` -> `"T1110"`. Renvoie `None` si ce n'est pas un `T` suivi de chiffres.
pub fn parent_technique(tid: &str) -> Option<String> {
    let t = tid.trim();
    let base = t.split('.').next().unwrap_or(t).trim().to_ascii_uppercase();
    let digits = base.strip_prefix('T')?;
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        Some(base)
    } else {
        None
    }
}

/// Tactique PRIMAIRE (shortname ATT&CK) d'une technique/sous-technique, ou `None` si inconnue (technique non
/// curée ou identifiant hors format `T####`). Les sous-techniques héritent de leur parente.
pub fn tactic_for_technique(tid: &str) -> Option<&'static str> {
    let base = parent_technique(tid)?;
    let t = match base.as_str() {
        // --- Reconnaissance (TA0043) ---
        "T1595" | "T1592" | "T1589" | "T1590" | "T1591" | "T1598" | "T1597" | "T1596" | "T1593"
        | "T1594" => "reconnaissance",
        // --- Resource Development (TA0042) ---
        "T1583" | "T1586" | "T1584" | "T1587" | "T1588" | "T1608" | "T1585" | "T1650" => {
            "resource-development"
        }
        // --- Initial Access (TA0001) ---
        "T1189" | "T1190" | "T1133" | "T1200" | "T1566" | "T1091" | "T1195" | "T1199" | "T1078" => {
            "initial-access"
        }
        // --- Execution (TA0002) ---
        "T1059" | "T1203" | "T1204" | "T1559" | "T1053" | "T1129" | "T1106" | "T1072" | "T1569"
        | "T1610" | "T1648" | "T1651" => "execution",
        // --- Persistence (TA0003) ---
        "T1098" | "T1197" | "T1547" | "T1037" | "T1543" | "T1546" | "T1136" | "T1554" | "T1525"
        | "T1556" | "T1137" | "T1542" | "T1505" | "T1205" | "T1176" => "persistence",
        // --- Privilege Escalation (TA0004) ---
        "T1548" | "T1134" | "T1484" | "T1611" | "T1055" | "T1068" | "T1574" => {
            "privilege-escalation"
        }
        // --- Defense Evasion (TA0005) ---
        "T1562" | "T1070" | "T1036" | "T1027" | "T1218" | "T1140" | "T1112" | "T1497" | "T1620"
        | "T1211" | "T1222" | "T1564" | "T1553" | "T1656" | "T1006" | "T1014" | "T1202" | "T1207"
        | "T1216" | "T1221" | "T1480" | "T1600" | "T1601" => "defense-evasion",
        // --- Credential Access (TA0006) ---
        "T1110" | "T1552" | "T1555" | "T1003" | "T1056" | "T1558" | "T1557" | "T1212" | "T1187"
        | "T1539" | "T1606" | "T1621" | "T1649" | "T1040" => "credential-access",
        // --- Discovery (TA0007) ---
        "T1046" | "T1087" | "T1082" | "T1083" | "T1057" | "T1018" | "T1016" | "T1049" | "T1033"
        | "T1069" | "T1518" | "T1201" | "T1007" | "T1010" | "T1124" | "T1120" | "T1135" | "T1613"
        | "T1580" | "T1526" | "T1538" | "T1619" | "T1622" => "discovery",
        // --- Lateral Movement (TA0008) ---
        "T1021" | "T1210" | "T1550" | "T1080" | "T1563" | "T1570" | "T1534" => "lateral-movement",
        // --- Collection (TA0009) ---
        "T1560" | "T1213" | "T1005" | "T1039" | "T1025" | "T1074" | "T1114" | "T1115" | "T1119"
        | "T1123" | "T1125" | "T1113" | "T1602" | "T1530" | "T1185" => "collection",
        // --- Command and Control (TA0011) ---
        "T1071" | "T1105" | "T1573" | "T1090" | "T1095" | "T1132" | "T1568" | "T1571" | "T1102"
        | "T1104" | "T1008" | "T1092" | "T1219" | "T1572" | "T1001" | "T1659" => {
            "command-and-control"
        }
        // --- Exfiltration (TA0010) ---
        "T1041" | "T1048" | "T1567" | "T1029" | "T1030" | "T1011" | "T1052" | "T1020" | "T1537" => {
            "exfiltration"
        }
        // --- Impact (TA0040) ---
        "T1485" | "T1486" | "T1490" | "T1489" | "T1498" | "T1499" | "T1491" | "T1561" | "T1565"
        | "T1529" | "T1496" | "T1531" | "T1495" | "T1657" | "T1488" => "impact",
        _ => return None,
    };
    Some(t)
}

/// Catalogue CURÉ des techniques ATT&CK (technique parente `T####` -> tactique primaire), MÊME donnée que
/// `tactic_for_technique` mais ÉNUMÉRABLE : permet à un consommateur (matrice de couverture « navigator
/// global » de Plume) de balayer TOUTE la matrice et donc de surfacer les techniques SANS règle
/// (blind-spots) — impossible avec la seule fonction de lookup. Ordre = tactiques d'ATT&CK (kill-chain).
/// INVARIANT (test `catalog_agrees_with_lookup`) : chaque paire ici DOIT correspondre à
/// `tactic_for_technique` -> les deux ne peuvent pas diverger silencieusement.
pub const CATALOG: &[(&str, &str)] = &[
    // Reconnaissance
    ("T1595", "reconnaissance"), ("T1592", "reconnaissance"), ("T1589", "reconnaissance"),
    ("T1590", "reconnaissance"), ("T1591", "reconnaissance"), ("T1598", "reconnaissance"),
    ("T1597", "reconnaissance"), ("T1596", "reconnaissance"), ("T1593", "reconnaissance"),
    ("T1594", "reconnaissance"),
    // Resource Development
    ("T1583", "resource-development"), ("T1586", "resource-development"), ("T1584", "resource-development"),
    ("T1587", "resource-development"), ("T1588", "resource-development"), ("T1608", "resource-development"),
    ("T1585", "resource-development"), ("T1650", "resource-development"),
    // Initial Access
    ("T1189", "initial-access"), ("T1190", "initial-access"), ("T1133", "initial-access"),
    ("T1200", "initial-access"), ("T1566", "initial-access"), ("T1091", "initial-access"),
    ("T1195", "initial-access"), ("T1199", "initial-access"), ("T1078", "initial-access"),
    // Execution
    ("T1059", "execution"), ("T1203", "execution"), ("T1204", "execution"), ("T1559", "execution"),
    ("T1053", "execution"), ("T1129", "execution"), ("T1106", "execution"), ("T1072", "execution"),
    ("T1569", "execution"), ("T1610", "execution"), ("T1648", "execution"), ("T1651", "execution"),
    // Persistence
    ("T1098", "persistence"), ("T1197", "persistence"), ("T1547", "persistence"), ("T1037", "persistence"),
    ("T1543", "persistence"), ("T1546", "persistence"), ("T1136", "persistence"), ("T1554", "persistence"),
    ("T1525", "persistence"), ("T1556", "persistence"), ("T1137", "persistence"), ("T1542", "persistence"),
    ("T1505", "persistence"), ("T1205", "persistence"), ("T1176", "persistence"),
    // Privilege Escalation
    ("T1548", "privilege-escalation"), ("T1134", "privilege-escalation"), ("T1484", "privilege-escalation"),
    ("T1611", "privilege-escalation"), ("T1055", "privilege-escalation"), ("T1068", "privilege-escalation"),
    ("T1574", "privilege-escalation"),
    // Defense Evasion
    ("T1562", "defense-evasion"), ("T1070", "defense-evasion"), ("T1036", "defense-evasion"),
    ("T1027", "defense-evasion"), ("T1218", "defense-evasion"), ("T1140", "defense-evasion"),
    ("T1112", "defense-evasion"), ("T1497", "defense-evasion"), ("T1620", "defense-evasion"),
    ("T1211", "defense-evasion"), ("T1222", "defense-evasion"), ("T1564", "defense-evasion"),
    ("T1553", "defense-evasion"), ("T1656", "defense-evasion"), ("T1006", "defense-evasion"),
    ("T1014", "defense-evasion"), ("T1202", "defense-evasion"), ("T1207", "defense-evasion"),
    ("T1216", "defense-evasion"), ("T1221", "defense-evasion"), ("T1480", "defense-evasion"),
    ("T1600", "defense-evasion"), ("T1601", "defense-evasion"),
    // Credential Access
    ("T1110", "credential-access"), ("T1552", "credential-access"), ("T1555", "credential-access"),
    ("T1003", "credential-access"), ("T1056", "credential-access"), ("T1558", "credential-access"),
    ("T1557", "credential-access"), ("T1212", "credential-access"), ("T1187", "credential-access"),
    ("T1539", "credential-access"), ("T1606", "credential-access"), ("T1621", "credential-access"),
    ("T1649", "credential-access"), ("T1040", "credential-access"),
    // Discovery
    ("T1046", "discovery"), ("T1087", "discovery"), ("T1082", "discovery"), ("T1083", "discovery"),
    ("T1057", "discovery"), ("T1018", "discovery"), ("T1016", "discovery"), ("T1049", "discovery"),
    ("T1033", "discovery"), ("T1069", "discovery"), ("T1518", "discovery"), ("T1201", "discovery"),
    ("T1007", "discovery"), ("T1010", "discovery"), ("T1124", "discovery"), ("T1120", "discovery"),
    ("T1135", "discovery"), ("T1613", "discovery"), ("T1580", "discovery"), ("T1526", "discovery"),
    ("T1538", "discovery"), ("T1619", "discovery"), ("T1622", "discovery"),
    // Lateral Movement
    ("T1021", "lateral-movement"), ("T1210", "lateral-movement"), ("T1550", "lateral-movement"),
    ("T1080", "lateral-movement"), ("T1563", "lateral-movement"), ("T1570", "lateral-movement"),
    ("T1534", "lateral-movement"),
    // Collection
    ("T1560", "collection"), ("T1213", "collection"), ("T1005", "collection"), ("T1039", "collection"),
    ("T1025", "collection"), ("T1074", "collection"), ("T1114", "collection"), ("T1115", "collection"),
    ("T1119", "collection"), ("T1123", "collection"), ("T1125", "collection"), ("T1113", "collection"),
    ("T1602", "collection"), ("T1530", "collection"), ("T1185", "collection"),
    // Command and Control
    ("T1071", "command-and-control"), ("T1105", "command-and-control"), ("T1573", "command-and-control"),
    ("T1090", "command-and-control"), ("T1095", "command-and-control"), ("T1132", "command-and-control"),
    ("T1568", "command-and-control"), ("T1571", "command-and-control"), ("T1102", "command-and-control"),
    ("T1104", "command-and-control"), ("T1008", "command-and-control"), ("T1092", "command-and-control"),
    ("T1219", "command-and-control"), ("T1572", "command-and-control"), ("T1001", "command-and-control"),
    ("T1659", "command-and-control"),
    // Exfiltration
    ("T1041", "exfiltration"), ("T1048", "exfiltration"), ("T1567", "exfiltration"), ("T1029", "exfiltration"),
    ("T1030", "exfiltration"), ("T1011", "exfiltration"), ("T1052", "exfiltration"), ("T1020", "exfiltration"),
    ("T1537", "exfiltration"),
    // Impact
    ("T1485", "impact"), ("T1486", "impact"), ("T1490", "impact"), ("T1489", "impact"), ("T1498", "impact"),
    ("T1499", "impact"), ("T1491", "impact"), ("T1561", "impact"), ("T1565", "impact"), ("T1529", "impact"),
    ("T1496", "impact"), ("T1531", "impact"), ("T1495", "impact"), ("T1657", "impact"), ("T1488", "impact"),
];

/// Techniques curées (parentes `T####`) d'une tactique donnée, dans l'ordre du `CATALOG`. Vide si la
/// tactique est inconnue. Permet à la matrice de couverture d'énumérer la colonne d'une tactique.
pub fn techniques_for_tactic(tactic: &str) -> Vec<&'static str> {
    CATALOG.iter().filter(|(_, t)| *t == tactic).map(|(tid, _)| *tid).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plume_seeded_techniques_map_to_expected_tactics() {
        // Toutes les techniques taguées par les règles seedées de Plume DOIVENT être mappées.
        assert_eq!(tactic_for_technique("T1110"), Some("credential-access")); // Brute Force
        assert_eq!(tactic_for_technique("T1046"), Some("discovery")); // Network Service Discovery
        assert_eq!(tactic_for_technique("T1595"), Some("reconnaissance")); // Active Scanning
        assert_eq!(tactic_for_technique("T1595.002"), Some("reconnaissance")); // sous-technique -> parent
        assert_eq!(tactic_for_technique("T1190"), Some("initial-access")); // Exploit Public-Facing App
        assert_eq!(tactic_for_technique("T1498"), Some("impact")); // Network DoS
        assert_eq!(tactic_for_technique("T1490"), Some("impact")); // Inhibit System Recovery
        assert_eq!(tactic_for_technique("T1565"), Some("impact")); // Data Manipulation
        assert_eq!(tactic_for_technique("T1554"), Some("persistence")); // Compromise Host Software Binary
        assert_eq!(tactic_for_technique("T1543"), Some("persistence")); // Create/Modify System Process
        assert_eq!(tactic_for_technique("T1071"), Some("command-and-control")); // App Layer Protocol
        assert_eq!(tactic_for_technique("T1552"), Some("credential-access")); // Unsecured Credentials
        assert_eq!(tactic_for_technique("T1204"), Some("execution")); // User Execution
        assert_eq!(tactic_for_technique("T1562"), Some("defense-evasion")); // Impair Defenses
        assert_eq!(tactic_for_technique("T1562.001"), Some("defense-evasion")); // Disable/Modify Tools
    }

    #[test]
    fn distinct_tactics_collapses_same_tactic_techniques() {
        // Le point : deux techniques de la MÊME tactique -> UNE tactique distincte.
        let a = tactic_for_technique("T1110").unwrap(); // credential-access
        let b = tactic_for_technique("T1552").unwrap(); // credential-access
        assert_eq!(a, b, "T1110 et T1552 relèvent toutes deux de credential-access");
        // Trois techniques de tactiques distinctes.
        let set: std::collections::HashSet<_> =
            ["T1110", "T1046", "T1190"].iter().map(|t| tactic_for_technique(t).unwrap()).collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn normalization_and_unknowns() {
        assert_eq!(parent_technique("t1110.001").as_deref(), Some("T1110"));
        assert_eq!(parent_technique(" T1046 ").as_deref(), Some("T1046"));
        assert_eq!(parent_technique("bogus"), None);
        assert_eq!(parent_technique(""), None);
        assert_eq!(parent_technique("T"), None);
        // Technique hors table curée -> None (l'appelant SQL retombe alors sur l'ID technique brut).
        assert_eq!(tactic_for_technique("T9999"), None);
        assert_eq!(tactic_for_technique("not-a-technique"), None);
    }

    #[test]
    fn catalog_agrees_with_lookup() {
        // INVARIANT anti-drift : chaque (technique, tactique) du CATALOG énumérable correspond EXACTEMENT à
        // la fonction de lookup shippée -> les deux sources ne peuvent pas diverger sans casser un test.
        for (tid, tac) in CATALOG {
            assert_eq!(tactic_for_technique(tid), Some(*tac), "CATALOG {tid} désaccord avec tactic_for_technique");
            assert!(TACTICS.contains(tac), "CATALOG {tid} -> tactique non canonique {tac}");
        }
    }

    #[test]
    fn catalog_has_no_duplicate_techniques() {
        let mut seen = std::collections::HashSet::new();
        for (tid, _) in CATALOG {
            assert!(seen.insert(*tid), "technique dupliquée dans CATALOG : {tid}");
        }
        // Chaque tactique canonique possède au moins une technique curée (aucune colonne vide inattendue).
        for tac in TACTICS {
            assert!(!techniques_for_tactic(tac).is_empty(), "tactique {tac} sans technique curée");
        }
    }

    #[test]
    fn techniques_for_tactic_filters_correctly() {
        let cred = techniques_for_tactic("credential-access");
        assert!(cred.contains(&"T1110") && cred.contains(&"T1552"));
        assert!(!cred.contains(&"T1046")); // discovery, pas credential-access
        assert!(techniques_for_tactic("bogus-tactic").is_empty());
    }

    #[test]
    fn every_mapped_tactic_is_canonical() {
        // Toute tactique renvoyée appartient à la taxonomie des 14 tactiques Enterprise.
        for t in ["T1595", "T1190", "T1059", "T1547", "T1548", "T1562", "T1110", "T1046", "T1021",
                  "T1560", "T1071", "T1041", "T1486", "T1583"] {
            let tac = tactic_for_technique(t).unwrap();
            assert!(TACTICS.contains(&tac), "{tac} doit être une tactique canonique");
        }
    }
}
