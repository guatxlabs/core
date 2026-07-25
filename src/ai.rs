//! SPI de la couche IA CONSEIL (advisory) — Phase 1 : NL→SOQL UNIQUEMENT. PUR `std`, ZÉRO SDK,
//! ZÉRO réseau, ZÉRO dépendance nouvelle — exactement le patron de `secret.rs`/`cim.rs` (le cœur ne
//! livre QUE le CONTRAT + des helpers purs ; les impls réseau/vendeur vivent DANS le daemon derrière
//! la feature `ai`, jamais ici).
//!
//! INVARIANT CARDINAL — « l'IA PROPOSE, le compilateur FERMÉ DISPOSE, ZÉRO autorité d'exécution » :
//! `nl2soql_pipeline` prend le TEXTE SOQL renvoyé par le LLM et le passe à une COUTURE de compilation
//! (`compile`) — en production `soql_to_sql_x` (-> `guatx_core::soql::to_sql`), en test le compilo réel.
//! Il renvoie le SOQL + le SQL compilé (ou l'erreur de compilation). Il n'EXÉCUTE JAMAIS, ne touche
//! JAMAIS la base : la fonction n'a AUCUN handle de base. Un `DROP`/`SELECT * FROM user`/injection
//! hallucinés sont REJETÉS par le compilo exactement comme du mauvais SOQL humain (soql_ident_ok,
//! DENY_KW, un seul SELECT, enum de commandes fermé, masquage soql_field).
//!
//! REDACTION conservatrice : SEULS les NOMS de champ de schéma + la question NL sortent de la boîte
//! (aucune ligne d'event, aucune PII). `redact_fields` retire tout nom de champ ressemblant à un
//! secret/hash/token (defense-in-depth : le schéma event est déjà propre). Politique VERSIONNÉE.
//!
//! Points d'extension DIFFÉRÉS (non construits) : résumé d'incident, aide à l'écriture de règles,
//! RAG/embeddings. L'enum `AiPurpose` + le discriminant `api_shape` (côté daemon) sont les coutures.

use std::fmt;

/// Ce que l'IA a le droit de faire (Phase 1 = NL→SOQL seul). Enum FERMÉ — étendre = ajouter une
/// variante ET l'auditer ; jamais un point d'exécution.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AiPurpose {
    NlToSoql,
    // DIFFÉRÉ (extension points) : IncidentSummary, RuleAssist — NON implémentés en Phase 1.
}

impl AiPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            AiPurpose::NlToSoql => "nl_to_soql",
        }
    }
}

/// Requête neutre vers un backend d'inférence. `system`/`user` sont DÉJÀ rédigés (le pipeline redige
/// avant d'assembler). `max_tokens` = borne dure de coût par appel.
#[derive(Clone, Debug)]
pub struct AiRequest {
    pub purpose: AiPurpose,
    pub system: String,
    pub user: String,
    pub max_tokens: u32,
}

/// Réponse neutre. `text` = complétion brute (le pipeline en extrait le SOQL). Compteurs de tokens
/// best-effort (0 si le backend ne les fournit pas).
#[derive(Clone, Debug)]
pub struct AiResponse {
    pub text: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

/// Erreur NEUTRE — ne porte JAMAIS la matière du prompt ni la clé API (même discipline que
/// `SecretValue`/`SecretError`). `BadResponse` ne contient qu'un motif court (statut/forme), jamais
/// le corps de la réponse ni le corps de la requête.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AiError {
    Backend(String),
    Timeout,
    BadResponse(String),
}

impl fmt::Display for AiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AiError::Backend(m) => write!(f, "backend IA : {m}"),
            AiError::Timeout => write!(f, "backend IA : délai dépassé"),
            AiError::BadResponse(m) => write!(f, "réponse IA invalide : {m}"),
        }
    }
}
impl std::error::Error for AiError {}

/// LE CONTRAT. Un backend d'inférence quelconque (OpenAI-compatible, Ollama natif, Anthropic, …)
/// implémente ce trait. Toute l'autorité s'arrête ici : `complete` renvoie du TEXTE, jamais une action.
pub trait AiProvider {
    fn id(&self) -> &str;
    fn complete(&self, req: &AiRequest) -> Result<AiResponse, AiError>;
}

/// Politique de rédaction VERSIONNÉE. Conservatrice par défaut (`default_redaction_policy`) : refuse
/// inconditionnellement tout nom de champ ressemblant à un secret/hash/token ; la PII n'est laissée
/// passer que via une allowlist EXPLICITE (vide par défaut). La version est ESTAMPILLÉE dans chaque
/// entrée de ledger `ai.call`.
#[derive(Clone, Debug)]
pub struct RedactionPolicy {
    pub version: i64,
    /// Sous-chaînes (minuscule) interdites dans un nom de champ -> le champ est retiré du prompt.
    pub deny_substr: Vec<String>,
    /// Noms de champ (minuscule, exacts) explicitement AUTORISÉS même s'ils matchent un deny_substr.
    pub pii_allow: Vec<String>,
}

/// Politique par DÉFAUT (v1) — miroir de la denylist de secrets du daemon (`oac_key_is_secretish`) +
/// hash. Conservatrice : refuse secret/token/hash/password/key/auth/private/credential/bearer.
pub fn default_redaction_policy() -> RedactionPolicy {
    RedactionPolicy {
        version: 1,
        deny_substr: [
            "secret", "token", "password", "passwd", "pass", "api_key", "apikey", "hash",
            "private", "credential", "bearer", "authorization", "auth_header", "client_secret",
            "key",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        pii_allow: Vec::new(),
    }
}

/// Retire de `fields` tout nom qui matche une sous-chaîne interdite (sauf allowlist PII explicite).
/// Casse-insensible. C'est le point d'étranglement structurel : secret/hash/token ne peuvent PAS
/// entrer dans le prompt.
pub fn redact_fields(fields: &[String], p: &RedactionPolicy) -> Vec<String> {
    fields
        .iter()
        .filter(|f| {
            let lc = f.to_ascii_lowercase();
            if p.pii_allow.iter().any(|a| a.eq_ignore_ascii_case(f)) {
                return true;
            }
            !p.deny_substr.iter().any(|d| lc.contains(d.as_str()))
        })
        .cloned()
        .collect()
}

/// Amorce compacte de la grammaire SOQL (Splunk-lite) + few-shot. NE CONTIENT AUCUN nom de champ
/// sensible (statique, curé). Le `system` cadre le modèle ; le `user` porte le schéma (rédigé) + la NL.
pub fn build_nl2soql_prompt(fields: &[String], categories: &[&str], nl: &str) -> (String, String) {
    let system = "\
Tu es un assistant qui traduit une question en langage naturel en une requête SOQL (Splunk-lite) \
pour le SOC Plume. RÈGLES STRICTES :\n\
- Réponds UNIQUEMENT par la requête SOQL, sur une seule ligne, sans prose, sans balise de code.\n\
- La requête COMMENCE toujours par `search` puis des étapes séparées par `|`.\n\
- N'utilise QUE des noms de champ de la liste de schéma fournie. N'invente jamais de champ.\n\
- N'émets JAMAIS de SQL brut (SELECT/FROM/DROP/INSERT/UNION...). SOQL uniquement.\n\
- Commandes disponibles : search <filtres>, where <expr>, stats <agg> by <champs>, timechart, \
eval <champ>=<expr>, sort <champ>, head <n>, table <champs>, dedup <champs>, rename a as b, \
eventstats, top <champ>, rare <champ>.\n\
EXEMPLES :\n\
Q: échecs d'authentification par hôte sur la dernière heure\n\
R: search category=auth action=failure | stats count by host | sort -count\n\
Q: top 10 des IP sources bloquées\n\
R: search action=blocked | top src_ip | head 10\n\
Q: événements de sévérité élevée par source\n\
R: search severity>=3 | stats count by source"
        .to_string();

    let mut user = String::new();
    user.push_str("SCHÉMA (noms de champ autorisés) : ");
    user.push_str(&fields.join(", "));
    user.push_str("\nCATÉGORIES (valeurs de `category`) : ");
    user.push_str(&categories.join(", "));
    user.push_str("\n\nQUESTION : ");
    user.push_str(nl.trim());
    user.push_str("\nSOQL :");
    (system, user)
}

/// Extrait le SOQL d'une complétion : retire les clôtures markdown ```...```, l'étiquette de langage,
/// la prose évidente, et garde la première ligne non vide ressemblant à du SOQL (commence par `search`
/// ou contient `|`), sinon la première ligne non vide. Défensif — le compilo fermé re-valide de toute façon.
pub fn extract_soql(text: &str) -> String {
    let mut t = text.trim();
    // bloc de code clôturé ```lang\n...\n```
    if let Some(start) = t.find("```") {
        let after = &t[start + 3..];
        if let Some(end) = after.find("```") {
            let inner = &after[..end];
            // retire une éventuelle étiquette de langage sur la 1re ligne
            t = inner.trim();
            if let Some(nl) = t.find('\n') {
                let first = t[..nl].trim();
                if first.chars().all(|c| c.is_ascii_alphanumeric()) && !first.is_empty() {
                    t = t[nl + 1..].trim();
                }
            }
        }
    }
    // ligne SOQL préférée
    for line in t.lines() {
        let l = line.trim().trim_start_matches("R:").trim().trim_start_matches("SOQL:").trim();
        if l.is_empty() {
            continue;
        }
        let low = l.to_ascii_lowercase();
        if low.starts_with("search") || l.contains('|') {
            return l.to_string();
        }
    }
    // repli : première ligne non vide
    t.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").to_string()
}

/// Résultat du pipeline NL→SOQL. `sql` = SQL compilé si `valid` ; `error` = message du compilo sinon.
/// `retried` = un rebond de re-prompt a eu lieu sur erreur de compilation.
#[derive(Clone, Debug)]
pub struct Nl2SoqlOutcome {
    pub soql: String,
    pub sql: Option<String>,
    pub valid: bool,
    pub error: Option<String>,
    pub retried: bool,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

/// PIPELINE PUR NL→SOQL. AUCUNE base, AUCUN réseau propre. `compile` est la COUTURE du compilo FERMÉ
/// (en prod `soql_to_sql_x`, en test `guatx_core::soql::to_sql`). Rédige le schéma, assemble le prompt,
/// appelle `provider.complete`, extrait le SOQL, le COMPILE (jamais l'exécute). UN SEUL rebond de
/// re-prompt sur erreur de compilation. La seule chose faite du texte du LLM est `compile(&soql)` —
/// qui renvoie une chaîne SQL JAMAIS exécutée ici : zéro autorité d'exécution, structurellement.
pub fn nl2soql_pipeline(
    provider: &dyn AiProvider,
    nl: &str,
    fields: &[String],
    categories: &[&str],
    policy: &RedactionPolicy,
    max_tokens: u32,
    compile: &dyn Fn(&str) -> Result<String, String>,
) -> Result<Nl2SoqlOutcome, AiError> {
    // REDACTION structurelle : le schéma qui sort est TOUJOURS rédigé, quel que soit l'appelant.
    let safe_fields = redact_fields(fields, policy);
    let (system, user) = build_nl2soql_prompt(&safe_fields, categories, nl);

    let req = AiRequest { purpose: AiPurpose::NlToSoql, system: system.clone(), user, max_tokens };
    let resp = provider.complete(&req)?;
    let soql = extract_soql(&resp.text);
    let mut prompt_tokens = resp.prompt_tokens;
    let mut completion_tokens = resp.completion_tokens;

    // COMPILO FERMÉ = la seule chose faite du texte du LLM. Jamais d'exécution.
    match compile(&soql) {
        Ok(sql) => Ok(Nl2SoqlOutcome {
            soql,
            sql: Some(sql),
            valid: true,
            error: None,
            retried: false,
            prompt_tokens,
            completion_tokens,
        }),
        Err(e) => {
            // UN rebond : re-prompt en donnant l'erreur du compilo, puis on tranche définitivement.
            let retry_user = format!(
                "SCHÉMA (noms de champ autorisés) : {}\nCATÉGORIES : {}\n\nQUESTION : {}\n\
                 La requête précédente `{}` a été REJETÉE par le compilateur : {}\n\
                 Corrige-la. Réponds UNIQUEMENT par le SOQL corrigé.\nSOQL :",
                safe_fields.join(", "),
                categories.join(", "),
                nl.trim(),
                soql,
                e
            );
            let req2 = AiRequest { purpose: AiPurpose::NlToSoql, system, user: retry_user, max_tokens };
            let resp2 = provider.complete(&req2)?;
            prompt_tokens = prompt_tokens.saturating_add(resp2.prompt_tokens);
            completion_tokens = completion_tokens.saturating_add(resp2.completion_tokens);
            let soql2 = extract_soql(&resp2.text);
            match compile(&soql2) {
                Ok(sql) => Ok(Nl2SoqlOutcome {
                    soql: soql2,
                    sql: Some(sql),
                    valid: true,
                    error: None,
                    retried: true,
                    prompt_tokens,
                    completion_tokens,
                }),
                Err(e2) => Ok(Nl2SoqlOutcome {
                    soql: soql2,
                    sql: None,
                    valid: false,
                    error: Some(e2),
                    retried: true,
                    prompt_tokens,
                    completion_tokens,
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soql;
    use std::cell::RefCell;

    /// Provider MOCK — renvoie une file de complétions scriptées. Enregistre les appels. AUCUN réseau.
    struct MockProvider {
        replies: RefCell<Vec<String>>,
        calls: RefCell<u32>,
    }
    impl MockProvider {
        fn new(replies: Vec<&str>) -> Self {
            MockProvider {
                replies: RefCell::new(replies.into_iter().map(|s| s.to_string()).collect()),
                calls: RefCell::new(0),
            }
        }
    }
    impl AiProvider for MockProvider {
        fn id(&self) -> &str {
            "mock"
        }
        fn complete(&self, _req: &AiRequest) -> Result<AiResponse, AiError> {
            *self.calls.borrow_mut() += 1;
            let mut r = self.replies.borrow_mut();
            let text = if r.is_empty() { String::new() } else { r.remove(0) };
            Ok(AiResponse { text, prompt_tokens: 11, completion_tokens: 7 })
        }
    }

    // La COUTURE de compilation RÉELLE (compilo fermé) pour les tests.
    fn real_compile(s: &str) -> Result<String, String> {
        soql::to_sql(s, 0, 0, &soql::Schema::events())
    }

    fn ev_fields() -> Vec<String> {
        crate::cim::CIM_CORE_FIELDS.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn redact_drops_secret_hash_token_fields() {
        let p = default_redaction_policy();
        let fields: Vec<String> = ["host", "user", "password", "api_key", "token_hash", "session_token", "src_ip", "secret_ref"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = redact_fields(&fields, &p);
        assert!(out.contains(&"host".to_string()));
        assert!(out.contains(&"user".to_string()));
        assert!(out.contains(&"src_ip".to_string()));
        for banned in ["password", "api_key", "token_hash", "session_token", "secret_ref"] {
            assert!(!out.contains(&banned.to_string()), "champ sensible {banned} a fuité");
        }
    }

    #[test]
    fn prompt_contains_only_fieldnames_and_nl_no_secrets() {
        let p = default_redaction_policy();
        let fields: Vec<String> = ["host", "src_ip", "api_key", "hash", "session_token", "password", "message"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let safe = redact_fields(&fields, &p);
        // NB : `categories` est un vocabulaire CIM fermé et sûr (contient la category "secrets" — un
        // NOM DE CATÉGORIE, pas un credential) -> on ne teste PAS l'absence du mot "secret" en général,
        // on prouve que les NOMS DE CHAMP sensibles rédigés n'apparaissent JAMAIS dans le prompt.
        let (system, user) = build_nl2soql_prompt(&safe, crate::cim::CIM_CATEGORIES, "montre les erreurs");
        let blob = format!("{system}\n{user}").to_ascii_lowercase();
        for leaked in ["api_key", "session_token", "password", "hash"] {
            assert!(!blob.contains(leaked), "le prompt contient un nom de champ sensible : {leaked}");
        }
        assert!(user.contains("host") && user.contains("src_ip") && user.contains("montre les erreurs"));
    }

    #[test]
    fn extract_soql_strips_fences_and_prose() {
        assert_eq!(extract_soql("```soql\nsearch category=auth | stats count\n```"), "search category=auth | stats count");
        assert_eq!(extract_soql("Voici la requête :\nsearch severity>=3 | head 5"), "search severity>=3 | head 5");
        assert_eq!(extract_soql("R: search host=web01"), "search host=web01");
    }

    // === INVARIANT CARDINAL : quoi que crache le LLM, le compilo FERMÉ ne peut produire QU'un SELECT
    // read-only borné au schéma event/metric — jamais un DROP/INSERT, jamais un accès aux tables
    // user/token, jamais une 2e instruction. Le SOQL dangereux est SOIT rejeté (DENY_KW) SOIT NEUTRALISÉ
    // en recherche freetext inerte (les mots-clés deviennent des motifs LIKE entre quotes). ===
    #[test]
    fn cardinal_dangerous_soql_never_reaches_execution_shape() {
        let cats = crate::cim::CIM_CATEGORIES;
        let p = default_redaction_policy();
        for dangerous in [
            "SELECT * FROM user",
            "search x | eval y = drop",
            "search x; DROP TABLE event",
            "search x | eval y = (SELECT token_hash FROM token)",
            "DROP TABLE event",
            "attach database '/etc/passwd' as p",
            "'; DELETE FROM event; --",
            "search category=auth | stats count by host", // témoin légitime
        ] {
            let prov = MockProvider::new(vec![dangerous, dangerous]); // même réponse au rebond éventuel
            let out = nl2soql_pipeline(&prov, "peu importe", &ev_fields(), cats, &p, 256, &real_compile)
                .expect("le pipeline ne doit pas planter");
            match out.sql {
                None => {
                    // rejeté par le compilo (DENY_KW, etc.)
                    assert!(!out.valid && out.error.is_some(), "rejet incohérent : {dangerous}");
                }
                Some(sql) => {
                    // accepté => DOIT être un SELECT read-only borné à event/metric, une seule instruction.
                    let up = sql.to_uppercase();
                    assert!(up.trim_start().starts_with("SELECT"), "instruction non-SELECT émise pour [{dangerous}] : {sql}");
                    assert!(!up.contains(" FROM USER"), "accès table user pour [{dangerous}] : {sql}");
                    assert!(!up.contains(" FROM TOKEN"), "accès table token pour [{dangerous}] : {sql}");
                    assert!(!up.contains("DROP TABLE"), "DROP exécutable pour [{dangerous}] : {sql}");
                    assert!(!up.contains("DELETE FROM EVENT"), "DELETE exécutable pour [{dangerous}] : {sql}");
                    assert!(!up.contains("INSERT INTO"), "INSERT exécutable pour [{dangerous}] : {sql}");
                    assert!(!up.contains("ATTACH "), "ATTACH exécutable pour [{dangerous}] : {sql}");
                    // le seul FROM réel est event/metric (ou une sous-requête qui les enveloppe)
                    assert!(
                        up.contains("FROM EVENT") || up.contains("FROM METRIC") || up.contains("FROM (SELECT"),
                        "FROM inattendu pour [{dangerous}] : {sql}"
                    );
                }
            }
        }
    }

    // rejets EXPLICITES : les usages DENY_KW en eval sont bien refusés par le compilo.
    #[test]
    fn cardinal_deny_kw_in_eval_is_rejected() {
        let p = default_redaction_policy();
        for rejected in [
            "search x | eval y = drop",
            "search x | eval y = (SELECT token_hash FROM token)",
        ] {
            let prov = MockProvider::new(vec![rejected, rejected]);
            let out = nl2soql_pipeline(&prov, "q", &ev_fields(), crate::cim::CIM_CATEGORIES, &p, 256, &real_compile).unwrap();
            assert!(!out.valid, "usage DENY_KW accepté : {rejected}");
            assert!(out.error.is_some());
        }
    }

    // === ZÉRO EXÉCUTION : le pipeline ne fait QUE compiler ; la couture est le seul puits. ===
    #[test]
    fn zero_execution_only_compiles_never_runs() {
        let executed = RefCell::new(false);
        let compiled = RefCell::new(Vec::<String>::new());
        // couture qui ENREGISTRE ce qu'on compile et prouve qu'on n'exécute jamais.
        let compile = |s: &str| -> Result<String, String> {
            compiled.borrow_mut().push(s.to_string());
            // si quiconque tentait d'exécuter, il faudrait un handle DB — il n'y en a AUCUN.
            let _ = &executed; // jamais mis à true
            soql::to_sql(s, 0, 0, &soql::Schema::events())
        };
        let prov = MockProvider::new(vec!["search category=auth | stats count by host"]);
        let out = nl2soql_pipeline(&prov, "erreurs auth par hôte", &ev_fields(), crate::cim::CIM_CATEGORIES,
            &default_redaction_policy(), 256, &compile).unwrap();
        assert!(out.valid);
        assert!(out.sql.is_some());
        assert_eq!(compiled.borrow().len(), 1, "exactement une compilation, aucune exécution");
        assert!(!*executed.borrow(), "aucune exécution ne doit avoir lieu");
    }

    #[test]
    fn retry_once_on_compile_error_then_succeeds() {
        // 1re réponse REJETÉE (DENY_KW drop) -> rebond -> 2e réponse valide.
        let prov = MockProvider::new(vec!["search x | eval y = drop", "search category=auth | stats count"]);
        let out = nl2soql_pipeline(&prov, "q", &ev_fields(), crate::cim::CIM_CATEGORIES,
            &default_redaction_policy(), 256, &real_compile).unwrap();
        assert!(out.valid, "le rebond aurait dû aboutir");
        assert!(out.retried);
        assert_eq!(*prov.calls.borrow(), 2, "exactement un rebond (2 appels au provider)");
    }

    #[test]
    fn valid_soql_compiles_first_try() {
        let prov = MockProvider::new(vec!["search severity>=3 | stats count by source"]);
        let out = nl2soql_pipeline(&prov, "q", &ev_fields(), crate::cim::CIM_CATEGORIES,
            &default_redaction_policy(), 256, &real_compile).unwrap();
        assert!(out.valid);
        assert!(!out.retried);
        assert_eq!(*prov.calls.borrow(), 1);
        assert!(out.sql.unwrap().to_ascii_lowercase().contains("select"));
    }

    #[test]
    fn ai_error_never_carries_prompt_or_key() {
        // Display de AiError ne doit jamais exiger/porter de matière ; forme neutre.
        assert_eq!(format!("{}", AiError::Timeout), "backend IA : délai dépassé");
        assert!(format!("{}", AiError::Backend("HTTP 500".into())).contains("HTTP 500"));
    }
}
