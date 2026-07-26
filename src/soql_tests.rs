    use super::*;

    #[cfg(feature = "forge")]
    fn forge() -> Schema { Schema::forge() }

    // --- DuckDbDialect : émission WARM ---------------------------------------------------------
    #[test]
    fn duckdb_dialect_emits_duckdb_fragments() {
        let d = DuckDbDialect;
        assert_eq!(d.json_extract("fields", "user"), "json_extract_string(fields,'$.user')");
        assert_eq!(d.cast_real("x"), "TRY_CAST(x AS DOUBLE)");
        assert_eq!(d.time_bucket("ts", 3600), "(ts // 3600)*3600");
        assert_eq!(d.group_concat_bounded("user", true, 4096), "substr(string_agg(DISTINCT user,','),1,4096)");
        assert_eq!(d.group_concat_bounded("user", false, 4096), "substr(string_agg(user,','),1,4096)");
        assert_eq!(d.like_contains("message", "boom"), "message ILIKE '%boom%'");
        // quoting/échappement identiques à SQLite (délégués).
        assert_eq!(d.quote_ident("order"), "\"order\"");
        assert_eq!(d.escape_literal("O'B"), "O''B");
    }

    #[test]
    fn events_duckdb_compiles_via_duckdb_dialect() {
        // Le MÊME SOQL compile via le compilateur partagé, mais l'émission diffère (fragments DuckDB).
        let v = compile("search source=sshd | stats values(user) by src_ip", &Schema::events_duckdb()).unwrap();
        assert!(v.sql.contains("string_agg(DISTINCT json_extract_string(fields,'$.user'),',')"), "{}", v.sql);
        // Contre-preuve : le schéma SQLite par défaut émet la forme SQLite (parité intacte).
        let s = compile("search source=sshd | stats values(user) by src_ip", &Schema::events()).unwrap();
        assert!(s.sql.contains("GROUP_CONCAT(DISTINCT json_extract(fields,'$.user'))"), "{}", s.sql);
    }

    // --- ClickHouseDialect : émission COLD/scale -----------------------------------------------
    #[test]
    fn clickhouse_dialect_emits_clickhouse_fragments() {
        let d = ClickHouseDialect;
        assert_eq!(d.json_extract("fields", "user"), "JSONExtractString(fields,'user')");
        assert_eq!(d.cast_real("x"), "toFloat64OrNull(x)");
        assert_eq!(d.time_bucket("ts", 3600), "intDiv(ts,3600)*3600");
        assert_eq!(d.group_concat_bounded("user", true, 4096), "substring(arrayStringConcat(groupUniqArray(user),','),1,4096)");
        assert_eq!(d.group_concat_bounded("user", false, 4096), "substring(arrayStringConcat(groupArray(user),','),1,4096)");
        assert_eq!(d.like_contains("message", "boom"), "positionCaseInsensitive(message,'boom') > 0");
        assert_eq!(
            d.mitre_parent("mitre"),
            "CASE WHEN position(mitre,'.')>0 THEN upper(substring(mitre,1,position(mitre,'.')-1)) ELSE upper(mitre) END"
        );
        // quoting/échappement identiques à SQLite (délégués, valides en ClickHouse).
        assert_eq!(d.quote_ident("order"), "\"order\"");
        assert_eq!(d.escape_literal("O'B"), "O''B");
    }

    #[test]
    fn events_clickhouse_compiles_via_clickhouse_dialect() {
        // Le MÊME SOQL compile via le compilateur partagé, mais l'émission diffère (fragments ClickHouse).
        let v = compile("search source=sshd | stats values(user) by src_ip", &Schema::events_clickhouse()).unwrap();
        assert!(v.sql.contains("arrayStringConcat(groupUniqArray(JSONExtractString(fields,'user')),',')"), "{}", v.sql);
        // Contre-preuve : le schéma SQLite par défaut émet la forme SQLite (parité intacte).
        let s = compile("search source=sshd | stats values(user) by src_ip", &Schema::events()).unwrap();
        assert!(s.sql.contains("GROUP_CONCAT(DISTINCT json_extract(fields,'$.user'))"), "{}", s.sql);
    }

    #[test]
    #[cfg(feature = "forge")]
    fn search_filter_inlined_escaped() {
        let c = compile("search severity=HIGH | fields target,title", &forge()).unwrap();
        // DIVERGENCE 2 : les identifiants émis sont quotés (parité Plume / sûreté mots réservés).
        assert!(c.sql.contains("\"severity\" = 'HIGH'"), "{}", c.sql);
        assert_eq!(c.columns, vec!["target".to_string(), "title".to_string()]);
    }

    #[test]
    #[cfg(feature = "forge")]
    fn quote_escaping_blocks_injection() {
        let c = compile("search title=O'Brien", &forge()).unwrap();
        assert!(c.sql.contains("'O''Brien'"), "{}", c.sql);
    }

    #[test]
    #[cfg(feature = "forge")]
    fn stats_group_by_and_sort() {
        let c = compile("search | stats count by severity | sort -count", &forge()).unwrap();
        assert!(c.sql.contains("GROUP BY \"severity\""), "{}", c.sql);
        assert!(c.sql.contains("ORDER BY \"count\" DESC"), "{}", c.sql);
    }

    #[test]
    #[cfg(feature = "forge")]
    fn runs_alt_base() {
        let c = compile("runs | stats count by mitre", &forge()).unwrap();
        assert!(c.sql.contains("FROM runrecord"), "{}", c.sql);
    }

    #[test]
    #[cfg(feature = "forge")]
    fn unknown_stage_rejected() {
        assert!(compile("search | nope", &forge()).is_err());
    }

    #[test]
    fn events_base_matches_plume() {
        let c = compile("search source=sshd", &Schema::events()).unwrap();
        assert!(c.sql.starts_with("SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event"), "{}", c.sql);
        assert!(c.sql.contains("\"source\" = 'sshd'"), "{}", c.sql);
    }

    #[test]
    fn events_json_fallback() {
        let c = compile("search | stats count by dport", &Schema::events()).unwrap();
        assert!(c.sql.contains("json_extract(fields,'$.dport')"), "{}", c.sql);
    }

    // --- CONTRAT ATT&CK partagé (boucle purple) ---------------------------------------------

    #[test]
    fn normalize_technique_uppercases_and_trims() {
        assert_eq!(normalize_technique("t1190").as_deref(), Some("T1190"));
        assert_eq!(normalize_technique("  T1059 ").as_deref(), Some("T1059"));
        assert_eq!(normalize_technique("t1190").as_deref(), normalize_technique("T1190").as_deref());
    }

    #[test]
    fn normalize_technique_rolls_up_subtechnique_to_parent() {
        // Le rollup est l'invariant central : une sous-technique corrèle avec sa technique parente.
        assert_eq!(normalize_technique("T1059.001").as_deref(), Some("T1059"));
        assert_eq!(normalize_technique("t1059.001").as_deref(), Some("T1059"));
        assert_eq!(normalize_technique("T1059.003").as_deref(), Some("T1059"));
        // Parent et sous-technique convergent vers la même clé de jointure.
        assert_eq!(
            normalize_technique("T1059.001").as_deref(),
            normalize_technique("T1059").as_deref()
        );
    }

    #[test]
    fn normalize_technique_rejects_non_techniques() {
        assert_eq!(normalize_technique(""), None);
        assert_eq!(normalize_technique("   "), None);
        assert_eq!(normalize_technique("TA0001"), None);        // tactique, pas technique
        assert_eq!(normalize_technique("T123"), None);          // 3 chiffres
        assert_eq!(normalize_technique("T12345"), None);        // 5 chiffres
        assert_eq!(normalize_technique("T1059.01"), None);      // sous-technique à 2 chiffres
        assert_eq!(normalize_technique("T1059.0011"), None);    // sous-technique à 4 chiffres
        assert_eq!(normalize_technique("T1059.001.002"), None); // double point
        assert_eq!(normalize_technique("T1059."), None);        // point sans sous-technique
        assert_eq!(normalize_technique("X1059"), None);         // mauvais préfixe
        assert_eq!(normalize_technique("CWE-639"), None);       // pas un ID ATT&CK
    }

    #[test]
    #[cfg(feature = "forge")]
    fn purple_exchange_cols_present_both_sides() {
        // Le contrat exige que les colonnes d'échange existent des DEUX côtés de la corrélation.
        let forge = Schema::forge();
        let events = Schema::events();
        for col in PURPLE_EXCHANGE_COLS {
            assert!(
                forge.default.real_cols.iter().any(|c| c == col)
                    || forge.default.select_cols.iter().any(|c| c == col),
                "colonne purple '{col}' absente du schéma Forge (finding)"
            );
            assert!(
                events.default.real_cols.iter().any(|c| c == col)
                    || events.default.select_cols.iter().any(|c| c == col)
                    || events.default.json_field.is_some(),
                "colonne purple '{col}' non résolvable côté Plume (event)"
            );
        }
        // mitre = clé de jointure ; ts/target = MTTD + périmètre.
        assert!(PURPLE_EXCHANGE_COLS.contains(&PURPLE_JOIN_FIELD));
        assert!(PURPLE_EXCHANGE_COLS.contains(&"ts"));
        assert!(PURPLE_EXCHANGE_COLS.contains(&"target"));
    }

    #[test]
    #[cfg(feature = "forge")]
    fn join_on_mitre_correlates_at_parent_technique_level() {
        // La JOINTURE purple sur `mitre` doit rouler au niveau parent des DEUX côtés (pas USING brut).
        let c = compile("runs | join mitre [search]", &Schema::forge()).unwrap();
        assert!(!c.sql.contains("USING(mitre)"), "join mitre ne doit PAS être une égalité brute : {}", c.sql);
        assert!(c.sql.contains("instr(l.mitre,'.')"), "rollup gauche manquant : {}", c.sql);
        assert!(c.sql.contains("instr(r.mitre,'.')"), "rollup droit manquant : {}", c.sql);
        // La condition d'égalité est bien entre les deux expressions parentes normalisées.
        assert!(c.sql.contains("ON CASE"), "la jointure doit être ON <rollup>=<rollup> : {}", c.sql);
    }

    #[test]
    #[cfg(feature = "forge")]
    fn join_on_non_mitre_keeps_plain_using() {
        // Hors champ ATT&CK, le comportement de jointure historique est préservé (USING, identifiant quoté).
        let c = compile("search | join target [runs]", &Schema::forge()).unwrap();
        assert!(c.sql.contains("USING(\"target\")"), "{}", c.sql);
        assert!(!c.sql.contains("instr(l.target"), "{}", c.sql);
    }

    // --- DIVERGENCES PORTÉES (parité compilo Plume sur le schéma `events`) --------------------

    #[test]
    fn events_agg_resolves_json_field() {
        // DIVERGENCE 1 : un champ d'agrégation JSON est résolu via json_extract (sinon colonne
        // inexistante -> erreur SQL -> règle MUETTE). `stats dc(vhost) by src_ip` = recon T1595.
        let c = compile("search source=cloudflare | stats dc(vhost) by src_ip", &Schema::events()).unwrap();
        assert!(c.sql.contains("COUNT(DISTINCT json_extract(fields,'$.vhost'))"), "{}", c.sql);
        assert!(c.sql.contains("GROUP BY \"src_ip\""), "{}", c.sql);
        assert!(!c.sql.contains("COUNT(DISTINCT vhost)"), "agg ne doit PAS être nu : {}", c.sql);
    }

    #[test]
    fn events_qid_quotes_reserved_word_identifiers() {
        // DIVERGENCE 2 : un champ/alias homonyme d'un mot réservé SQLite doit être quoté partout
        // (sinon `near "group": syntax error`). `group` est un champ JSON ici.
        let c = compile("search | stats count by group", &Schema::events()).unwrap();
        assert!(c.sql.contains("AS \"group\""), "{}", c.sql);
        assert!(c.sql.contains("GROUP BY \"group\""), "{}", c.sql);
    }

    #[test]
    fn events_indexed_field_keeps_canonical_no_cast() {
        // DIVERGENCE 3 : un champ INDEXÉ (HOT_FIELDS, ex `verb`) comparé à un nombre garde la forme
        // canonique SANS CAST -> matche `CREATE INDEX ... ON event(json_extract(fields,'$.verb'))`.
        let c = compile("search verb=5", &Schema::events()).unwrap();
        assert!(c.sql.contains("json_extract(fields,'$.verb') = 5"), "{}", c.sql);
        assert!(!c.sql.contains("CAST(json_extract(fields,'$.verb')"), "champ indexé ne doit PAS être casté : {}", c.sql);
    }

    #[test]
    fn events_nonindexed_numeric_field_is_cast() {
        // DIVERGENCE 3 (revers) : un champ JSON NON indexé comparé à un nombre est CASTé (correction
        // de comparaison texte/nombre). `dport` n'est pas dans HOT_FIELDS.
        let c = compile("search dport=443", &Schema::events()).unwrap();
        assert!(c.sql.contains("CAST(json_extract(fields,'$.dport') AS REAL) = 443"), "{}", c.sql);
    }

    #[test]
    fn events_join_mitre_stays_plain_using() {
        // DIVERGENCE 4 (gatée) : sur le schéma `events`, `join mitre` reste un `USING(mitre)` brut
        // (PARITÉ Plume) — le rollup parent purple est opt-in (schéma Forge uniquement).
        let c = compile(
            "search | stats count by mitre | join mitre [search source=x | stats count by mitre]",
            &Schema::events(),
        ).unwrap();
        assert!(c.sql.contains("USING(\"mitre\")"), "{}", c.sql);
        assert!(!c.sql.contains("instr(l.mitre"), "events ne doit PAS rouler le rollup mitre : {}", c.sql);
    }

    #[test]
    fn pub_helpers_are_exported() {
        // DIVERGENCE 5 : ces helpers DOIVENT être publics (la route-rollup de Plume en dépendra).
        assert_eq!(soql_qid("order"), "\"order\"");
        assert_eq!(soql_esc("O'Brien"), "O''Brien");
        assert_eq!(soql_tokenize("a \"b c\" d").len(), 3);
        assert_eq!(soql_split_pipes("search | stats count").len(), 2);
    }

    #[test]
    fn mitre_parent_sql_rolls_dot_form() {
        // Le SQL de rollup garde la partie avant le premier point, sinon la valeur entière.
        let e = mitre_parent_sql("x");
        assert!(e.contains("instr(x,'.')>0"), "{e}");
        assert!(e.contains("substr(x,1,instr(x,'.')-1)"), "{e}");
        assert!(e.contains("UPPER(x)"), "{e}");
    }

    // --- PARSER PHASE 1 : nouveaux opérateurs SOQL (parité compilo legacy) ------------------------
    // NB PARITÉ : ces SQL attendus sont BYTE-IDENTIQUES à ce que produit le compilo miroir du
    // legacy (`soql_compile`/`soql_agg`), les deux étant codés à l'identique.

    #[test]
    fn op1_stats_values_list_group_concat() {
        // `values` = DISTINCT, `list` = avec doublons ; les deux bornées à 4096 c. (anti-explosion).
        // Champ JSON (`user`) résolu via json_extract (DIVERGENCE 1), alias = nom de la fonction.
        let v = compile("search | stats values(user) by src_ip", &Schema::events()).unwrap();
        assert!(v.sql.contains("substr(GROUP_CONCAT(DISTINCT json_extract(fields,'$.user')),1,4096) AS \"values\""), "{}", v.sql);
        assert!(v.sql.contains("GROUP BY \"src_ip\""), "{}", v.sql);
        assert_eq!(v.columns, vec!["src_ip".to_string(), "values".to_string()]);
        let l = compile("search | stats list(user) by src_ip", &Schema::events()).unwrap();
        assert!(l.sql.contains("substr(GROUP_CONCAT(json_extract(fields,'$.user')),1,4096) AS \"list\""), "{}", l.sql);
        assert!(!l.sql.contains("DISTINCT"), "list ne doit PAS être DISTINCT : {}", l.sql);
        // Colonne réelle (Forge `title`) -> quotée, pas de json_extract. (Gate `forge` : ce volet du
        // test cible le schéma Forge ; sans la feature il est retiré, le volet events ci-dessus reste.)
        #[cfg(feature = "forge")]
        {
            let f = compile("search | stats values(title) by campaign", &forge()).unwrap();
            assert!(f.sql.contains("substr(GROUP_CONCAT(DISTINCT \"title\"),1,4096) AS \"values\""), "{}", f.sql);
        }
    }

    #[test]
    fn op2_in_not_in_base_filter() {
        // Colonne réelle, liste textuelle -> IN avec valeurs quotées/échappées.
        let c = compile("search source in (web,cloudflare)", &Schema::events()).unwrap();
        assert!(c.sql.contains("\"source\" COLLATE NOCASE IN ('web','cloudflare')"), "{}", c.sql);
        // Colonne réelle, liste numérique -> IN inline non quoté (pas de CAST sur colonne réelle).
        let s = compile("search severity in (3,4)", &Schema::events()).unwrap();
        assert!(s.sql.contains("\"severity\" IN (3,4)"), "{}", s.sql);
        // Champ JSON, NOT IN textuel -> json_extract + NOT IN quoté.
        let u = compile("search user not in (root,ubuntu)", &Schema::events()).unwrap();
        assert!(u.sql.contains("json_extract(fields,'$.user') NOT IN ('root','ubuntu')"), "{}", u.sql);
        // Champ JSON NUMÉRIQUE non indexé -> CAST REAL + IN inline (chemin numeric de soql_filter_field).
        let d = compile("search dport in (80,443)", &Schema::events()).unwrap();
        assert!(d.sql.contains("CAST(json_extract(fields,'$.dport') AS REAL) IN (80,443)"), "{}", d.sql);
        // Combiné avec un filtre normal : la condition IN précède, le `=` suit, les deux en AND.
        let m = compile("search source in (web,cloudflare) severity=3", &Schema::events()).unwrap();
        assert!(m.sql.contains("\"source\" COLLATE NOCASE IN ('web','cloudflare') AND \"severity\" = 3"), "{}", m.sql);
        // Injection : une valeur avec quote est échappée (doublage).
        let inj = compile("search user in (a,O'Brien)", &Schema::events()).unwrap();
        assert!(inj.sql.contains("'O''Brien'"), "{}", inj.sql);
    }

    #[test]
    fn op2_in_not_in_where_stage() {
        // `where` sur colonne réelle numérique -> IN inline.
        let s = compile("search | where severity in (3,4)", &Schema::events()).unwrap();
        assert!(s.sql.contains("\"severity\" IN (3,4)"), "{}", s.sql);
        // `where` sur champ JSON numérique -> CAST REAL (même règle que le where scalaire).
        let d = compile("search | where dport in (80,443)", &Schema::events()).unwrap();
        assert!(d.sql.contains("CAST(json_extract(fields,'$.dport') AS REAL) IN (80,443)"), "{}", d.sql);
        // `where` NOT IN textuel sur champ JSON.
        let u = compile("search | where user not in (root,ubuntu)", &Schema::events()).unwrap();
        assert!(u.sql.contains("json_extract(fields,'$.user') NOT IN ('root','ubuntu')"), "{}", u.sql);
    }

    // CORE-1 : le pré-pass `in (...)` court AVANT le tokenize/quote-handling. Une VALEUR quotée contenant le
    // substring `<x> in (<liste>)` NE DOIT PAS être charcutée en un IN parasite + une égalité tronquée.
    #[test]
    fn core1_quoted_in_substring_compiles_to_equality_not_in() {
        // Repro 1 (auditeur) : la valeur quotée `user in (a,b)` -> ÉGALITÉ, PAS un IN sur json_extract(user).
        let a = compile("search message=\"user in (a,b)\"", &Schema::events()).unwrap();
        assert!(a.sql.contains("\"message\" = 'user in (a,b)'"), "{}", a.sql);
        assert!(!a.sql.contains(" IN ("), "IN parasite émis : {}", a.sql);
        assert!(!a.sql.contains("json_extract(fields,'$.user')"), "champ user shredé : {}", a.sql);
        // Repro 2 (auditeur) : URL quotée avec `x in (1,2)` -> égalité, pas d'IN numérique parasite.
        let b = compile("search url=\"/path?x in (1,2)\"", &Schema::events()).unwrap();
        assert!(b.sql.contains("\"url\" = '/path?x in (1,2)'"), "{}", b.sql);
        assert!(!b.sql.contains(" IN ("), "IN parasite émis : {}", b.sql);
    }

    // CORE-1 (régression) : le `in (...)` LÉGITIME (non quoté) DOIT toujours compiler en prédicat IN, y compris
    // mélangé à un filtre d'égalité, et même avec des VALEURS quotées dans la liste (les guillemets internes
    // n'affectent que les valeurs, pas la reconnaissance de la clause).
    #[test]
    fn core1_unquoted_in_still_compiles_to_in() {
        // `foo in (a,b,c)` non quoté -> IN (chemin inchangé).
        let a = compile("search source in (web,cloudflare,tor)", &Schema::events()).unwrap();
        assert!(a.sql.contains("\"source\" COLLATE NOCASE IN ('web','cloudflare','tor')"), "{}", a.sql);
        // Mixte : `a=1 b in (x,y)` -> l'IN sur `b` ET l'égalité sur `a`, les deux présents en AND.
        let m = compile("search a=1 b in (x,y)", &Schema::events()).unwrap();
        assert!(m.sql.contains("json_extract(fields,'$.b') COLLATE NOCASE IN ('x','y')"), "{}", m.sql);
        assert!(m.sql.contains("CAST(json_extract(fields,'$.a') AS REAL) = 1"), "{}", m.sql);
        // Valeurs quotées DANS la liste (le `(`/`in` restent au niveau quote 0) -> IN reconnu, quotes retirées.
        let q = compile("search source in (\"web\",\"cloudflare\")", &Schema::events()).unwrap();
        assert!(q.sql.contains("\"source\" COLLATE NOCASE IN ('web','cloudflare')"), "{}", q.sql);
    }

    // CORE-4 : une liste `in ()` VIDE ne doit JAMAIS s'évanouir (ce qui renverrait TOUT). `in` vide -> `1=0`
    // (rien), `not in` vide -> `1=1` (tout, sémantiquement correct pour un ensemble d'exclusion vide).
    #[test]
    fn core4_empty_in_list_never_vanishes() {
        let a = compile("search foo in ()", &Schema::events()).unwrap();
        assert!(a.sql.contains("1=0"), "in () doit matcher RIEN : {}", a.sql);
        let b = compile("search a in (,,)", &Schema::events()).unwrap();
        assert!(b.sql.contains("1=0"), "in (,,) doit matcher RIEN : {}", b.sql);
        // `not in ()` = ensemble d'exclusion vide -> matche TOUT (explicite `1=1`, pas un filtre disparu).
        let c = compile("search foo not in ()", &Schema::events()).unwrap();
        assert!(c.sql.contains("1=1"), "not in () doit matcher TOUT : {}", c.sql);
    }

    // CORE-3 : `head -N` émettait `LIMIT -N` que SQLite interprète comme ILLIMITÉ (renvoie tout). Le négatif
    // est désormais REJETÉ ; le cas positif reste inchangé.
    #[test]
    fn core3_head_negative_rejected() {
        assert!(compile("search | head -5", &Schema::events()).is_err(), "head négatif doit être rejeté");
        assert!(compile("search | limit -1", &Schema::events()).is_err(), "limit négatif doit être rejeté");
        let ok = compile("search | head 5", &Schema::events()).unwrap();
        assert!(ok.sql.contains("LIMIT 5"), "{}", ok.sql);
        // 0 reste valide (LIMIT 0 = 0 ligne, déjà sûr).
        let z = compile("search | head 0", &Schema::events()).unwrap();
        assert!(z.sql.contains("LIMIT 0"), "{}", z.sql);
    }

    // CORE-2 : `eventstats values/list` produisait `substr(GROUP_CONCAT(...),1,4096) OVER (...)` — SQL INVALIDE
    // (« substr() may not be used as a window function » / « DISTINCT is not supported for window functions »)
    // -> règle MUETTE. Désormais : sous-requête corrélée par partition (SQL valide, sémantique eventstats).
    #[test]
    fn core2_eventstats_values_list_valid_sql() {
        // values(user) by src_ip -> sous-requête corrélée, PAS de `substr(...) OVER`.
        let v = compile("search | eventstats values(user) by src_ip", &Schema::events()).unwrap();
        assert!(
            v.sql.contains("(SELECT substr(GROUP_CONCAT(DISTINCT json_extract(fields,'$.user')),1,4096) FROM ("),
            "{}", v.sql
        );
        assert!(v.sql.contains("AS i WHERE i.\"src_ip\" IS o.\"src_ip\") AS \"values\" FROM ("), "{}", v.sql);
        assert!(v.sql.trim_end().ends_with(") AS o"), "{}", v.sql);
        assert!(!v.sql.contains(" OVER ("), "OVER window invalide sur substr/group_concat : {}", v.sql);
        // list(user) by src_ip -> idem sans DISTINCT.
        let l = compile("search | eventstats list(user) by src_ip", &Schema::events()).unwrap();
        assert!(l.sql.contains("substr(GROUP_CONCAT(json_extract(fields,'$.user')),1,4096)"), "{}", l.sql);
        assert!(!l.sql.contains(" OVER ("), "{}", l.sql);
        // Sans `by` : agrégat global, pas de WHERE de corrélation, toujours valide.
        let g = compile("search | eventstats values(user)", &Schema::events()).unwrap();
        assert!(g.sql.contains(") AS i) AS \"values\" FROM ("), "{}", g.sql);
        assert!(!g.sql.contains(" OVER ("), "{}", g.sql);
        // RÉGRESSION : les agrégats FENÊTRABLES (count/avg/…) gardent le chemin `OVER (...)` INCHANGÉ.
        let c = compile("search | eventstats count by src_ip", &Schema::events()).unwrap();
        assert!(c.sql.contains("COUNT(*) OVER (PARTITION BY \"src_ip\") AS \"count\""), "{}", c.sql);
        let avg = compile("search | eventstats avg(severity) by host", &Schema::events()).unwrap();
        assert!(avg.sql.contains(" OVER (PARTITION BY \"host\")"), "{}", avg.sql);
    }

    #[test]
    fn op3_rename_alias() {
        // ADDITIF : `SELECT *, "src_ip" AS "attacker"` ; la colonne d'origine reste (via `*`).
        let c = compile("search | rename src_ip AS attacker", &Schema::events()).unwrap();
        assert!(c.sql.contains("SELECT *, \"src_ip\" AS \"attacker\" FROM"), "{}", c.sql);
        assert!(c.columns.contains(&"attacker".to_string()), "{:?}", c.columns);
        assert!(c.columns.contains(&"src_ip".to_string()), "{:?}", c.columns);
        // Multi-paires séparées par virgule, casse de `as` tolérée.
        let m = compile("search | rename src_ip AS attacker, dst_ip as victim", &Schema::events()).unwrap();
        assert!(m.sql.contains("\"src_ip\" AS \"attacker\""), "{}", m.sql);
        assert!(m.sql.contains("\"dst_ip\" AS \"victim\""), "{}", m.sql);
        // Renommage d'un champ JSON -> json_extract (et non une colonne nue inexistante).
        let j = compile("search | rename vhost AS host_hdr", &Schema::events()).unwrap();
        assert!(j.sql.contains("json_extract(fields,'$.vhost') AS \"host_hdr\""), "{}", j.sql);
        // Syntaxe invalide -> erreur.
        assert!(compile("search | rename src_ip attacker", &Schema::events()).is_err());
    }

    #[test]
    fn op_pipeline_chains() {
        // Enchaînement réaliste : filtre IN -> stats values -> rename pour aligner la clé de jointure.
        let ok = compile("search source in (web,cloudflare) | stats values(user) by src_ip | rename src_ip AS attacker", &Schema::events()).unwrap();
        assert!(ok.sql.contains("\"source\" COLLATE NOCASE IN ('web','cloudflare')"), "{}", ok.sql);
        assert!(ok.sql.contains("GROUP_CONCAT(DISTINCT json_extract(fields,'$.user'))"), "{}", ok.sql);
        assert!(ok.sql.contains("AS \"attacker\""), "{}", ok.sql);
    }

    // --- PARSER PHASE 2 : `mvexpand f` (parité compilo legacy) ------------------------------------
    // NB PARITÉ : le SQL attendu est BYTE-IDENTIQUE à ce que produit le compilo miroir du legacy
    // (`soql_compile`, arm "mvexpand") — les deux sont codés à l'identique.

    #[test]
    fn op_mvexpand_json_array_field() {
        // `mvexpand ips` : champ JSON (`ips` sous `fields`) -> json_each(CASE WHEN json_valid(...) ...).
        // La valeur scalaire (je.value) devient une colonne de sortie ; les colonnes de base sont gardées.
        let c = compile("search source=cloudflare | mvexpand ips", &Schema::events()).unwrap();
        // GARDE json_valid : seul un JSON valide (tableau) s'éclate ; sinon '[]' -> 0 ligne (pas d'erreur).
        assert!(
            c.sql.ends_with(",je.value AS \"ips\" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE \"source\" = 'cloudflare'), json_each(CASE WHEN json_valid(json_extract(fields,'$.ips')) THEN json_extract(fields,'$.ips') ELSE '[]' END) je"),
            "{}", c.sql
        );
        // `ips` (absent des ocols de base) est AJOUTÉ comme colonne expansée scalaire.
        assert_eq!(c.columns.last().map(|s| s.as_str()), Some("ips"), "{:?}", c.columns);
        assert!(c.columns.contains(&"fields".to_string()), "{:?}", c.columns);
    }

    #[test]
    fn op_mvexpand_real_column_replaced_in_place() {
        // `f` réel (ici `src_ip`, colonne event) : GARDE json_valid sur la colonne quotée, REMPLACÉE IN
        // PLACE (ordre des colonnes préservé, pas de doublon). json_each sur la valeur -> 1 ligne/élément.
        let c = compile("search | mvexpand src_ip", &Schema::events()).unwrap();
        assert!(c.sql.contains("je.value AS \"src_ip\""), "{}", c.sql);
        assert!(
            c.sql.contains("json_each(CASE WHEN json_valid(\"src_ip\") THEN \"src_ip\" ELSE '[]' END) je"),
            "{}", c.sql
        );
        // une seule occurrence de src_ip dans les colonnes (remplacement in-place).
        assert_eq!(c.columns.iter().filter(|c| *c == "src_ip").count(), 1, "{:?}", c.columns);
    }

    #[test]
    fn op_mvexpand_scalar_value_guarded_not_errored() {
        // RÉGRESSION : `src_ip` est une colonne RÉELLE qui peut contenir un scalaire NON-JSON (ex.
        // '1.2.3.4'). Sans garde, json_each(COALESCE(...)) avorterait la requête (« malformed JSON »)
        // car COALESCE ne remplace que NULL. La garde json_valid DOIT donc envelopper l'expression de
        // colonne : un scalaire non-JSON tombe sur ELSE '[]' -> 0 ligne, jamais d'erreur.
        let c = compile("search | mvexpand src_ip", &Schema::events()).unwrap();
        assert!(c.sql.contains("CASE WHEN json_valid(\"src_ip\") THEN \"src_ip\" ELSE '[]' END"), "{}", c.sql);
        // l'ancienne forme COALESCE (qui erreurrait sur scalaire non-JSON) ne doit PLUS apparaître.
        assert!(!c.sql.contains("COALESCE(\"src_ip\""), "garde COALESCE résiduelle : {}", c.sql);
    }

    #[test]
    fn op_mvexpand_rejects_bad_field() {
        assert!(compile("search | mvexpand bad-field", &Schema::events()).is_err());
    }

    // --- OP `lookup` : enrichissement par table de référence (lookup_kv) ---------------------------

    #[test]
    fn op_lookup_left_join_with_output_cols() {
        // `lookup geoip src_ip OUTPUT country,asn` : LEFT JOIN sur lookup_kv, clé = colonne réelle quotée,
        // colonnes OUTPUT extraites du JSON `val` (gardées via json_valid -> NULL si malformé/absent).
        let c = compile("search source=web | lookup geoip src_ip OUTPUT country,asn", &Schema::events()).unwrap();
        assert!(c.sql.starts_with("SELECT base.*,"), "{}", c.sql);
        assert!(c.sql.contains("LEFT JOIN lookup_kv lk ON lk.name='geoip' AND lk.\"key\"=\"src_ip\""), "{}", c.sql);
        assert!(c.sql.contains("CASE WHEN json_valid(lk.val) THEN json_extract(lk.val,'$.country') END AS \"country\""), "{}", c.sql);
        assert!(c.sql.contains("CASE WHEN json_valid(lk.val) THEN json_extract(lk.val,'$.asn') END AS \"asn\""), "{}", c.sql);
        assert!(c.columns.contains(&"country".to_string()) && c.columns.contains(&"asn".to_string()), "{:?}", c.columns);
        // les colonnes de base sont conservées (base.*).
        assert!(c.columns.contains(&"src_ip".to_string()), "{:?}", c.columns);
    }

    #[test]
    fn op_lookup_json_keyfield_and_no_output() {
        // keyfield = champ JSON -> json_extract ; OUTPUT omis -> expose le `val` brut sous le nom du lookup.
        let c = compile("search | lookup users user", &Schema::events()).unwrap();
        assert!(c.sql.contains("lk.\"key\"=json_extract(fields,'$.user')"), "{}", c.sql);
        assert!(c.sql.contains("lk.val AS \"users\""), "{}", c.sql);
        assert!(c.columns.contains(&"users".to_string()), "{:?}", c.columns);
    }

    #[test]
    #[cfg(feature = "forge")]
    fn op_lookup_escapes_name() {
        // `name` est échappé (soql_esc) ; il passe déjà soql_ident_ok donc pas de quote réelle, mais le
        // littéral est bien inliné quoté (pas d'injection possible). Colonne réelle Forge -> clé quotée.
        let c = compile("runs | lookup ttp mitre OUTPUT actor", &Schema::forge()).unwrap();
        assert!(c.sql.contains("lk.name='ttp' AND lk.\"key\"=\"mitre\""), "{}", c.sql);
    }

    #[test]
    fn op_lookup_output_typed_but_empty_is_refused_not_evaporated() {
        // LA 8e ÉTAPE. `OUTPUT` TAPÉ est une demande EXPLICITE. MESURÉ AVANT ce correctif, et
        // IDENTIQUE sur le tag public v0.2.0 (donc pré-existant, pas une régression) :
        //   search | lookup t k OUTPUT    -> SELECT base.*, lk.val AS "t" …   <- la projection
        //   search | lookup t k OUTPUT ,  -> idem                                DEMANDÉE s'évapore
        //   search | lookup t k OUTPUT ,a -> l'entrée vide jetée sans un mot
        // C'était mot pour mot le mode d'échec de `table ,`, refusé, lui, depuis le correctif
        // précédent. Les deux passent désormais par la MÊME porte.
        let ev = Schema::events();
        for q in ["search | lookup t k OUTPUT", "search | lookup t k OUTPUT ,", "search | lookup t k OUTPUT ,,"] {
            let e = to_sql(q, 0, 0, &ev).expect_err(&format!("« {q} » : OUTPUT tapé et vide"));
            assert!(e.contains("colonne OUTPUT invalide"), "message : {e}");
        }
        // Le message NOMME ce qui a été tapé, comme partout ailleurs (porte commune).
        let e = to_sql("search | lookup t k OUTPUT bad-col", 0, 0, &ev).expect_err("ident invalide");
        assert_eq!(e, "lookup : colonne OUTPUT invalide : bad-col");
        // ANTI-RÉGRESSION — les formes livrées rendent le SQL du tag public, à l'octet.
        let want = "SELECT base.*, CASE WHEN json_valid(lk.val) THEN json_extract(lk.val,'$.country') END AS \"country\", \
CASE WHEN json_valid(lk.val) THEN json_extract(lk.val,'$.asn') END AS \"asn\" FROM (SELECT ts,host,source,category,severity,\
src_ip,dst_ip,url,xff,message,fields FROM event WHERE \"source\" = 'web') base LEFT JOIN lookup_kv lk ON lk.name='geoip' \
AND lk.\"key\"=\"src_ip\"";
        for q in [
            "search source=web | lookup geoip src_ip OUTPUT country,asn",
            // le BLANC est séparateur ici comme dans `table` : même SQL, mesuré.
            "search source=web | lookup geoip src_ip OUTPUT country asn",
            "search source=web | lookup geoip src_ip OUTPUT country, asn",
        ] {
            assert_eq!(to_sql(q, 0, 0, &ev).unwrap(), want, "forme légitime réécrite : {q}");
        }
        // `lookup` SANS `OUTPUT` reste le passe-plat documenté : rien n'a été demandé, rien ne manque.
        assert!(to_sql("search | lookup users user", 0, 0, &ev).unwrap().contains("lk.val AS \"users\""));
    }

    #[test]
    fn an_in_list_value_written_empty_survives_and_a_run_of_separators_does_not() {
        // LA PORTE VOISINE — liste de VALEURS, pas de noms. Le domaine décide, pas la politique :
        // la chaîne vide n'est pas un nom de champ, mais c'est une valeur légitime.
        // MESURÉ AVANT (identique sur v0.2.0) : `search host in ("",b)` rendait `IN ('b')` — la
        // valeur explicitement demandée disparaissait sans un mot.
        let ev = Schema::events();
        let b = "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event";
        let w = |v: &str| format!("{b} WHERE \"host\" COLLATE NOCASE IN ({v})");
        assert_eq!(to_sql("search host in (\"\",b)", 0, 0, &ev).unwrap(), w("'','b'"));
        assert_eq!(to_sql("search host in (a,\"\",b)", 0, 0, &ev).unwrap(), w("'a','','b'"));
        // LIMITE ASSUMÉE, ÉCRITE : une entrée SANS AUCUN TEXTE est une suite de séparateurs,
        // indiscernable d'un seul — exactement comme `table a,,b`.
        assert_eq!(to_sql("search host in (a,,b)", 0, 0, &ev).unwrap(), w("'a','b'"));
        // CORE-4 INTACT : la liste ENTIÈREMENT vide n'a aucune valeur -> repli, jamais un filtre évanoui.
        assert_eq!(to_sql("search host in ()", 0, 0, &ev).unwrap(), format!("{b} WHERE 1=0"));
        assert_eq!(to_sql("search host in (,,)", 0, 0, &ev).unwrap(), format!("{b} WHERE 1=0"));
        assert_eq!(to_sql("search host not in ()", 0, 0, &ev).unwrap(), format!("{b} WHERE 1=1"));
        // ANTI-RÉGRESSION : les formes légitimes rendent le SQL du tag public, à l'octet.
        assert_eq!(to_sql("search host in (a,b)", 0, 0, &ev).unwrap(), w("'a','b'"));
        assert_eq!(to_sql("search host in (\"a b\",c)", 0, 0, &ev).unwrap(), w("'a b','c'"));
    }

    #[test]
    fn op_lookup_rejects_bad_identifiers() {
        assert!(compile("search | lookup bad-name src_ip", &Schema::events()).is_err());
        assert!(compile("search | lookup geoip bad-field", &Schema::events()).is_err());
        assert!(compile("search | lookup geoip src_ip OUTPUT bad-col", &Schema::events()).is_err());
        assert!(compile("search | lookup", &Schema::events()).is_err());
    }

    // ===================== MACROS — expansion textuelle -> compilateur fermé =====================
    fn ks_with_macro(name: &str, params: &[&str], body: &str) -> KnowledgeSet {
        let mut ks = KnowledgeSet::new();
        ks.add_macro(name, params.iter().map(|s| s.to_string()).collect(), body);
        ks
    }

    #[test]
    fn macro_mode0_byte_identical() {
        // Aucune macro définie ET aucun backtick -> le schéma avec KnowledgeSet vide émet le SQL legacy
        // À L'IDENTIQUE (invariant mode 0 absolu). expand_macros renvoie la chaîne inchangée (fast-path).
        for q in [
            "search source=web | stats count by src_ip",
            "search src_ip=1.2.3.4 | top user",
            "search | eval x = severity | table x",
        ] {
            let plain = to_sql(q, 0, 0, &Schema::events()).unwrap();
            let with_empty_ks = to_sql(q, 0, 0, &Schema::events().with_knowledge(KnowledgeSet::new())).unwrap();
            assert_eq!(plain, with_empty_ks, "parité mode 0 rompue : {q}");
        }
    }

    #[test]
    fn macro_expands_through_closed_compiler() {
        // `errors` détend en un fragment de recherche, recompilé par le compilateur normal (même SQL que si
        // l'utilisateur avait tapé le corps).
        let ks = ks_with_macro("errors", &[], "search severity>=4");
        let sch = Schema::events().with_knowledge(ks);
        let a = to_sql("`errors` | stats count", 0, 0, &sch).unwrap();
        let b = to_sql("search severity>=4 | stats count", 0, 0, &Schema::events()).unwrap();
        assert_eq!(a, b, "expansion != frappe directe");
    }

    #[test]
    fn macro_param_substitution_and_arg_reaches_field_path() {
        // `by_ip(1.2.3.4)` -> `search src_ip=1.2.3.4` : l'argument est inliné dans le fragment, puis le
        // filtre passe par le chemin de filtre normal (échappement/allowlist). Identique à la frappe directe.
        let ks = ks_with_macro("by_ip", &["ip"], "search src_ip=$ip$");
        let sch = Schema::events().with_knowledge(ks);
        let a = to_sql("`by_ip(1.2.3.4)`", 0, 0, &sch).unwrap();
        let b = to_sql("search src_ip=1.2.3.4", 0, 0, &Schema::events()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn macro_cannot_inject_pipe_or_command_via_arg() {
        // Un argument porteur d'un `|` (tentative d'injecter une commande) est REJETÉ à l'expansion — il ne
        // peut donc PAS introduire une nouvelle étape/commande hors-enum.
        let ks = ks_with_macro("by_ip", &["ip"], "search src_ip=$ip$");
        let sch = Schema::events().with_knowledge(ks);
        assert!(to_sql("`by_ip(1.2.3.4 | delete)`", 0, 0, &sch).is_err());
        // brackets (sous-recherche), quotes (rupture de littéral), backtick (macro imbriquée), $ (placeholder)
        for hostile in ["`by_ip(a[b])`", "`by_ip(a'b)`", "`by_ip(a\"b)`", "`by_ip(a`b)`", "`by_ip($x$)`"] {
            assert!(to_sql(hostile, 0, 0, &sch).is_err(), "argument hostile accepté : {hostile}");
        }
    }

    #[test]
    fn macro_no_raw_sql_escape() {
        // Le corps d'une macro RE-TRAVERSE le compilateur fermé : une COMMANDE inconnue est REJETÉE (enum
        // fermée), et rien de « brut » ne traverse. 1) commande hors-enum -> erreur.
        let ks = ks_with_macro("evil", &[], "search | dropstuff foo");
        let sch = Schema::events().with_knowledge(ks);
        assert!(to_sql("`evil`", 0, 0, &sch).is_err(), "commande hors-enum acceptée");
        // 2) même si un corps contient du texte SQL-ish toléré comme jetons ignorés/free-text, le SQL ÉMIS ne
        // contient JAMAIS le fragment brut (pas de passthrough) : `DROP TABLE` n'apparaît pas dans la sortie.
        let ks2 = ks_with_macro("junk", &[], "search | stats count");
        let a = to_sql("`junk`", 0, 0, &Schema::events().with_knowledge(ks2)).unwrap();
        assert!(!a.to_uppercase().contains("DROP"), "SQL brut passé : {a}");
        // 3) une valeur de recherche portée par un argument est ÉCHAPPÉE (soql_esc) — pas de rupture de littéral.
        let ksv = ks_with_macro("v", &["x"], "search host=$x$");
        let sv = to_sql("`v(a.b-c)`", 0, 0, &Schema::events().with_knowledge(ksv)).unwrap();
        assert!(sv.contains("'a.b-c'"), "valeur non inlinée/échappée : {sv}");
    }

    #[test]
    fn macro_recursion_is_bounded() {
        // Une macro qui s'appelle elle-même -> l'expansion boucle mais est PLAFONNÉE -> erreur, jamais un hang.
        let mut ks = KnowledgeSet::new();
        ks.add_macro("loop", Vec::new(), "`loop`");
        let sch = Schema::events().with_knowledge(ks);
        assert!(to_sql("`loop`", 0, 0, &sch).is_err());
        // bombe exponentielle (a -> b b, b -> c c, ...) : bornée par la longueur/itérations -> erreur.
        let mut kb = KnowledgeSet::new();
        kb.add_macro("a", Vec::new(), "`b` `b`");
        kb.add_macro("b", Vec::new(), "`a` `a`");
        assert!(to_sql("`a`", 0, 0, &Schema::events().with_knowledge(kb)).is_err());
    }

    #[test]
    fn macro_unknown_or_arity_mismatch_rejected() {
        let ks = ks_with_macro("by_ip", &["ip"], "search src_ip=$ip$");
        let sch = Schema::events().with_knowledge(ks);
        assert!(to_sql("`nope`", 0, 0, &sch).is_err(), "macro inconnue acceptée");
        assert!(to_sql("`by_ip`", 0, 0, &sch).is_err(), "arité 0 vs 1 acceptée");
        assert!(to_sql("`by_ip(a,b)`", 0, 0, &sch).is_err(), "arité 2 vs 1 acceptée");
        // backtick sans aucune macro définie -> erreur (pas de mode dégradé silencieux).
        assert!(to_sql("`x`", 0, 0, &Schema::events()).is_err());
    }

    #[test]
    fn macro_expanded_field_still_masked() {
        // Un champ exposé PAR une macro re-traverse `soql_field` -> HÉRITE du masque de champ : une macro ne peut
        // pas récupérer la valeur brute d'un champ masqué.
        let ks = ks_with_macro("show_ip", &[], "search | table src_user, host");
        let m = masks_of(&[("src_user", MaskAction::Hash)]);
        let sch = Schema::events().with_knowledge(ks).with_masks(m);
        let sql = to_sql("`show_ip`", 0, 0, &sch).unwrap();
        assert!(sql.contains("plume_fmask_hash("), "le masque doit s'appliquer au champ exposé par macro : {sql}");
    }

    #[test]
    fn macro_bad_definition_ignored() {
        // add_macro fail-closed : nom invalide / param invalide / param dupliqué -> macro NON installée.
        let mut ks = KnowledgeSet::new();
        ks.add_macro("bad-name", Vec::new(), "search");
        ks.add_macro("ok", vec!["a-b".into()], "search src_ip=$a-b$");
        ks.add_macro("dup", vec!["x".into(), "x".into()], "search");
        assert!(!ks.has_macros(), "une macro malformée a été installée");
    }

    #[test]
    fn macro_unresolved_placeholder_multibyte_snippet_no_panic() {
        // RÉGRESSION : le snippet d'erreur `&out[i..i+16]` PANIQUAIT si un char UTF-8 multi-octets chevauchait
        // l'offset i+16. Corps forgé `$` + 14 ASCII + `é` (le `é` de 2 octets straddle la fenêtre 16). Le `$`
        // résiduel (aucun param) DOIT donner un Err PROPRE (rejet fail-closed), jamais un panic.
        let body = format!("${}é", "a".repeat(14));
        let r = substitute_macro(&body, &[], &[]);
        assert!(r.is_err(), "un `$` résiduel doit être rejeté : {r:?}");
        // Corps PUREMENT multi-octets avec `$` résiduel -> toujours un Err propre (pas de coupe intra-char).
        let r2 = substitute_macro("$éàçüö€", &[], &[]);
        assert!(r2.is_err(), "corps multi-octets avec `$` résiduel doit être rejeté : {r2:?}");
        // Sanity : un `$param$` bien résolu suivi d'un char multi-octets ne casse pas la substitution.
        let ok = substitute_macro("src_user=$u$ résumé", &["u".into()], &["bob".into()]);
        assert_eq!(ok.unwrap(), "src_user=bob résumé");
    }

    // ===================== AUTO-LOOKUPS — enrichissement auto, mask-aware =====================
    fn ks_with_autolookup(name: &str, key: &str, out: &[&str]) -> KnowledgeSet {
        let mut ks = KnowledgeSet::new();
        ks.add_auto_lookup(name, key, out.iter().map(|s| s.to_string()).collect());
        ks
    }

    #[test]
    fn auto_lookup_injected_above_base_like_manual() {
        // Un auto-lookup produit le MÊME JOIN qu'un `| lookup` explicite juste après la base.
        let ks = ks_with_autolookup("geoip", "src_ip", &["country", "asn"]);
        let sch = Schema::events().with_knowledge(ks);
        let auto = to_sql("search source=web", 0, 0, &sch).unwrap();
        assert!(auto.contains("LEFT JOIN lookup_kv lk ON lk.name='geoip' AND lk.\"key\"=\"src_ip\""), "{auto}");
        assert!(auto.contains("AS \"country\"") && auto.contains("AS \"asn\""), "{auto}");
    }

    #[test]
    fn auto_lookup_mode0_byte_identical() {
        // KnowledgeSet sans auto-lookup -> aucune injection -> SQL byte-identique au legacy.
        let a = to_sql("search source=web", 0, 0, &Schema::events()).unwrap();
        let b = to_sql("search source=web", 0, 0, &Schema::events().with_knowledge(KnowledgeSet::new())).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn auto_lookup_key_is_masked() {
        // La CLÉ d'un auto-lookup passe par `soql_field` : si le champ-clé est masqué, la jointure porte
        // sur la valeur MASQUÉE -> impossible d'enrichir/géolocaliser un champ que le rôle ne peut pas voir.
        let ks = ks_with_autolookup("geoip", "user", &["country"]); // `user` = champ JSON masquable
        let m = masks_of(&[("user", MaskAction::Hash)]);
        let sch = Schema::events().with_knowledge(ks).with_masks(m);
        let sql = to_sql("search", 0, 0, &sch).unwrap();
        // la clé de jointure est l'expression masquée, pas le json_extract brut.
        assert!(sql.contains("lk.\"key\"=plume_fmask_hash("), "clé de jointure non masquée : {sql}");
    }

    #[test]
    fn search_star_is_match_all_not_freetext_scan() {
        // `search *` = joker « tous les événements » (convention SIEM/Splunk) -> compile À L'IDENTIQUE de
        // `search` (aucun filtre plein-texte). Régression : `*` seul devenait `message LIKE '%*%'` (scan lent
        // ne matchant QUE les events contenant littéralement « * »). Le glob de VALEUR n'est PAS affecté.
        let all = to_sql("search", 0, 0, &Schema::events()).unwrap();
        let star = to_sql("search *", 0, 0, &Schema::events()).unwrap();
        assert_eq!(star, all, "`search *` doit compiler comme `search` (match-all)");
        assert!(!star.contains("LIKE '%*%'"), "`search *` ne doit PAS générer de LIKE plein-texte : {star}");
        // `*` en tête d'un AND = identité : `search * source=web` == `search source=web`.
        let starand = to_sql("search * source=web", 0, 0, &Schema::events()).unwrap();
        let plain = to_sql("search source=web", 0, 0, &Schema::events()).unwrap();
        assert_eq!(starand, plain, "`search * source=web` doit == `search source=web`");
        // le glob de VALEUR `champ=val*` reste un LIKE (non affecté par le fix).
        let glob = to_sql("search source=web*", 0, 0, &Schema::events()).unwrap();
        assert!(glob.contains("LIKE"), "le glob de valeur `source=web*` doit rester un LIKE : {glob}");
    }

    // ===================== FIELD FILTERS — masquage à la compilation =====================
    fn masks_of(pairs: &[(&str, MaskAction)]) -> FieldMaskSet {
        let mut m = FieldMaskSet::new();
        for (f, a) in pairs {
            m.insert(*f, *a);
        }
        m
    }

    #[test]
    fn field_mask_mode0_byte_identical() {
        // Masques VIDES -> SQL STRICTEMENT identique au chemin non masqué (parité mode 0, invariant absolu).
        for q in [
            "search source=web | table src_user, host",
            "search | stats values(src_user) by host | rename host AS h",
            "search | eval leak = message | table leak",
            "search src_ip=1.2.3.4 | top user",
        ] {
            let plain = to_sql(q, 0, 0, &Schema::events()).unwrap();
            let empty = to_sql(q, 0, 0, &Schema::events().with_masks(FieldMaskSet::new())).unwrap();
            assert_eq!(plain, empty, "masques VIDES -> byte-identique pour: {q}");
        }
    }

    #[test]
    fn field_mask_projection_json_key() {
        // MASK sur src_user (clé JSON) : projection -> valeur masquée, json_extract nu absent de la sortie.
        let m = masks_of(&[("src_user", MaskAction::Mask)]);
        let sql = to_sql("search | table src_user, host", 0, 0, &Schema::events().with_masks(m)).unwrap();
        assert!(sql.contains("'***'"), "valeur masquée émise : {sql}");
        // le json_extract existe DANS le CASE mais jamais projeté nu comme colonne de sortie src_user.
        assert!(sql.contains("AS \"src_user\""), "alias conservé : {sql}");
        // host non masqué -> reste une colonne réelle nue.
        assert!(sql.contains("\"host\" AS \"host\""), "host intact : {sql}");
    }

    #[test]
    fn field_mask_aggregation_cannot_leak() {
        // `| stats values(src_user)` : l'agrégat opère sur la valeur MASQUÉE (pas de fuite via values()).
        let m = masks_of(&[("src_user", MaskAction::Mask)]);
        let sql = to_sql("search | stats values(src_user) by host", 0, 0, &Schema::events().with_masks(m)).unwrap();
        assert!(sql.contains("'***'"), "agrégat masqué : {sql}");
        assert!(
            !sql.contains("GROUP_CONCAT(DISTINCT json_extract(fields,'$.src_user'))"),
            "l'agrégat ne DOIT PAS voir la valeur brute : {sql}"
        );
    }

    #[test]
    fn field_mask_actions_emit_expected_sql() {
        for (act, needle) in [
            (MaskAction::Mask, "'***'"),
            (MaskAction::Hash, "plume_fmask_hash("),
            (MaskAction::Redact, "NULL"),
            (MaskAction::Deny, "NULL"),
        ] {
            let m = masks_of(&[("message", act)]);
            let sql = to_sql("search | table message", 0, 0, &Schema::events().with_masks(m)).unwrap();
            assert!(sql.contains(needle), "{act:?} -> '{needle}' attendu dans {sql}");
        }
        // partial (last-4) : substr(...,-4)
        let m = masks_of(&[("message", MaskAction::MaskPartial)]);
        let sql = to_sql("search | table message", 0, 0, &Schema::events().with_masks(m)).unwrap();
        assert!(sql.contains("substr(CAST(") && sql.contains(",-4)"), "last-4 émis : {sql}");
    }

    #[test]
    fn field_mask_eval_rename_rex_cannot_escape() {
        // eval leak = message (colonne réelle brute) -> DOIT être masqué (sinon exfil du champ masqué).
        let m = masks_of(&[("message", MaskAction::Mask)]);
        let sql = to_sql("search | eval leak = message | table leak", 0, 0, &Schema::events().with_masks(m)).unwrap();
        assert!(sql.contains("'***'"), "eval doit masquer message : {sql}");
        // rename src_user AS u -> masqué (aliasing ne contourne pas).
        let m2 = masks_of(&[("src_user", MaskAction::Mask)]);
        let sql2 = to_sql("search | rename src_user AS u", 0, 0, &Schema::events().with_masks(m2)).unwrap();
        assert!(sql2.contains("'***'"), "rename doit masquer src_user : {sql2}");
    }

    #[test]
    fn field_mask_filter_oracle_rejected() {
        // ORACLE DE FILTRE (field-filters, durcissement) : filtrer AU NIVEAU BASE sur un champ masqué doit être REJETÉ
        // (sinon extraction bit-à-bit via le nombre de lignes), TOUTES actions confondues (Mask/Hash/Deny...).
        let m = masks_of(&[
            ("pan", MaskAction::Deny),
            ("src_user", MaskAction::Hash),
            ("message", MaskAction::Mask),
            ("src_ip", MaskAction::Mask),
        ]);
        let sch = || Schema::events().with_masks(m.clone());
        for q in [
            "search pan=41111111111111",        // exact (clé JSON)
            "search pan=4111*",                 // joker
            "search pan=~\"^41\"",              // regex
            "search pan:41111",                 // ':' exact
            "search pan in (4111,4222)",        // in-clause
            "search src_user=alice",            // exact clé JSON haché
            "search src_user=~\"^a\"",          // regex
            "search src_ip=10.0.0.1",           // colonne réelle masquée
            "search message=~\"secret\"",       // colonne réelle masquée
            "search src_user=alice | stats count", // + agrégat (oracle par count)
            "search hello",                     // terme libre -> FTS sur message masqué
        ] {
            assert!(to_sql(q, 0, 0, &sch()).is_err(), "filtre sur champ masqué DOIT être rejeté : {q}");
        }
        // Filtre sur un champ NON masqué reste autorisé (host non masqué).
        assert!(to_sql("search host=web01", 0, 0, &sch()).is_ok(), "filtre sur champ non masqué OK");
        // ADMIN / mode 0 (masques VIDES) : AUCUNE restriction (byte-identique, admin voit en clair).
        for q in ["search pan=41111111111111", "search src_user=alice | stats count", "search hello", "search src_ip in (1,2)"] {
            assert!(to_sql(q, 0, 0, &Schema::events()).is_ok(), "admin/mode 0 : filtre autorisé : {q}");
        }
        // Terme libre autorisé si le champ plein-texte (message) n'est PAS masqué (seule une clé JSON l'est).
        let only_json = masks_of(&[("src_user", MaskAction::Hash)]);
        assert!(to_sql("search hello", 0, 0, &Schema::events().with_masks(only_json)).is_ok(), "free-text OK si message non masqué");
    }

    #[test]
    fn field_mask_eval_fields_bag_cannot_escape() {
        // Mask bypass sur le chemin SQLite LIVE : le SAC JSON `fields` est gardé BRUT à la base
        // (source d'extraction des clés). Un `eval x = fields` le COPIERAIT EN CLAIR dans une colonne
        // aliasée, contournant `mask_output_bag` (qui ne caviarde QUE la colonne littéralement nommée
        // `fields`). Le fix route TOUTE référence eval au sac par `bag_wrap` (retrait des clés masquées).
        let m = masks_of(&[("pan", MaskAction::Mask)]);
        let sch = || Schema::events().with_masks(m.clone());

        // 1) exploit direct : eval leak = fields | table leak -> caviardé (la clé pan est retirée du blob).
        let sql = to_sql("search category=payment | eval leak = fields | table leak", 0, 0, &sch()).unwrap();
        assert!(sql.contains("json_remove"), "eval x=fields DOIT caviarder le sac (json_remove absent) : {sql}");
        assert!(sql.contains("'$.pan'"), "la clé masquée pan DOIT être retirée du blob : {sql}");
        assert!(!sql.contains("(fields) AS \"leak\""), "le blob BRUT ne doit PAS être copié dans leak : {sql}");

        // 2) sans `table` : la colonne leak elle-même est caviardée à sa création.
        let sql2 = to_sql("search category=payment | eval leak = fields", 0, 0, &sch()).unwrap();
        assert!(sql2.contains("json_remove") && sql2.contains("'$.pan'"), "eval x=fields (sans table) caviardé : {sql2}");
        assert!(!sql2.contains("(fields) AS \"leak\""), "pas de copie brute : {sql2}");

        // 3) `fields` référencé DANS une expression (substr) : la substitution au niveau IDENTIFIANT couvre
        // toute occurrence -> substr opère sur le blob DÉJÀ caviardé (pan retiré, non ré-extractible).
        let sql3 = to_sql("search category=payment | eval leak = substr(fields,1,4)", 0, 0, &sch()).unwrap();
        assert!(sql3.contains("json_remove") && sql3.contains("'$.pan'"), "fields dans substr() caviardé : {sql3}");

        // 3bis) mask-bypass par variante de casse : SQLite plie la casse des noms de colonne,
        // donc `FIELDS`/`Fields`/`FiElDs`/`substr(FIELDS,…)` se résolvent QUAND MÊME vers la colonne brute
        // `fields`. Un match sensible à la casse les laissait échapper au caviardage -> fuite du blob EN
        // CLAIR. La comparaison est désormais INSENSIBLE À LA CASSE -> TOUTE graphie est caviardée, et
        // JAMAIS un écho brut `(FIELDS) AS "leak"` (que SQLite résoudrait vers le sac brut).
        for q in [
            "search category=payment | eval leak = FIELDS | table leak",
            "search category=payment | eval leak = Fields | table leak",
            "search category=payment | eval leak = FiElDs | table leak",
            "search category=payment | eval leak = substr(FIELDS,1,4) | table leak",
        ] {
            let s = to_sql(q, 0, 0, &sch()).unwrap();
            assert!(s.contains("json_remove") && s.contains("'$.pan'"), "variante de casse DOIT caviarder : {q} -> {s}");
            let lc = s.to_lowercase();
            assert!(!lc.contains("(fields) as \"leak\""), "aucun écho brut du sac (variante de casse) : {q} -> {s}");
        }

        // 3ter) EN PROFONDEUR (sous-recherche `append`) : le choke-point s'applique à CHAQUE compile_depth
        // -> une variante de casse dans un sous-`eval` ne fuit pas non plus le blob brut.
        let deep = to_sql(
            "search category=payment | append [search category=payment | eval leak = FIELDS | table leak] | table leak",
            0, 0, &sch(),
        ).unwrap();
        assert!(deep.contains("json_remove") && deep.contains("'$.pan'"), "sous-recherche : sac caviardé : {deep}");
        assert!(!deep.to_lowercase().contains("(fields) as \"leak\""), "sous-recherche : pas d'écho brut : {deep}");

        // 3quater) IDENTIFIANT INCONNU (clé JSON pure / champ absent) : au lieu d'un écho SQL brut (qui
        // pouvait résoudre vers une colonne masquée brute), il est extrait du sac comme `soql_field`
        // (`json_extract(...,'$.<id>')`, NULL pour une clé absente) -> jamais une référence de colonne
        // brute échappant au masque. Ici `pan` est masqué -> l'extraction est caviardée à '***'.
        let unk = to_sql("search category=payment | eval leak = pan | table leak", 0, 0, &sch()).unwrap();
        assert!(unk.contains("json_extract"), "clé inconnue extraite du sac (json_extract) : {unk}");
        assert!(unk.contains("'***'"), "la clé masquée pan extraite en eval DOIT être masquée : {unk}");
        // mode 0 (aucun masque) : STRICTEMENT no-op -> l'identifiant inconnu reste NU (legacy), aucun
        // json_extract parasite injecté (preuve que le repli ne s'active QUE sous masque).
        let unk0 = to_sql("search category=payment | eval leak = pan | table leak", 0, 0, &Schema::events()).unwrap();
        assert!(!unk0.contains("json_extract(\"fields\",'$.pan')") && !unk0.contains("json_extract(fields,'$.pan')"),
            "mode 0 : identifiant inconnu émis NU (pas de json_extract) : {unk0}");

        // 4) SIBLINGS déjà couverts par le choke-point `soql_field` (rename / stats-as / table) : caviardés
        //    aussi (régression-guard -> aucun chemin d'écho de champ ne copie le sac brut).
        for q in [
            "search category=payment | rename fields AS leak",
            "search category=payment | stats values(fields) AS leak",
            "search category=payment | table fields",
        ] {
            let s = to_sql(q, 0, 0, &sch()).unwrap();
            assert!(s.contains("json_remove") && s.contains("'$.pan'"), "sibling doit caviarder le sac : {q} -> {s}");
        }

        // 5) LEGIT eval INCHANGÉ : arithmétique / réf de colonne réelle non masquée -> les EXPRESSIONS eval
        //    sont émises À L'IDENTIQUE (aucun caviardage parasite sur `score`/`label`). Le seul caviardage
        //    présent est celui du sac `fields` en SORTIE (baseline field-filters, attendu), pas des colonnes eval.
        let legit = "search source=web | eval score = severity + 1 | eval label = source";
        let masked_legit = to_sql(legit, 0, 0, &sch()).unwrap();
        let mode0_legit = to_sql(legit, 0, 0, &Schema::events()).unwrap();
        for frag in ["(severity + 1) AS \"score\"", "(source) AS \"label\""] {
            assert!(masked_legit.contains(frag), "expr eval légitime intacte ({frag}) : {masked_legit}");
            assert!(mode0_legit.contains(frag), "expr eval mode 0 identique ({frag}) : {mode0_legit}");
        }
        // le pan (clé masquée) est absent de la sortie EN CLAIR ; le seul json_remove touche le sac `fields`,
        // jamais les colonnes eval `score`/`label` (qui restent des expressions arithmétiques/chaîne nues).
        assert!(!masked_legit.contains("json_remove(\"fields\",'$.pan') ELSE NULL END) AS \"score\""),
            "score NE doit PAS être caviardé : {masked_legit}");
    }

    #[test]
    fn clickhouse_escape_literal_escapes_backslash() {
        // ClickHouse traite `\` comme un échappement C-style DANS un littéral simple-quote. Doubler
        // seulement `'` (`soql_esc`) laisserait un `\` final casser la borne du littéral (`'a\'` = quote
        // échappée -> littéral non fermé -> injection). Le dialect CH échappe AUSSI le backslash. SQLite/DuckDB
        // NE traitent PAS `\` -> ils gardent le doublage de quote seul (byte-identique).
        let ch = ClickHouseDialect;
        assert_eq!(ch.escape_literal("a\\"), "a\\\\", "backslash final doublé (CH)");
        assert_eq!(ch.escape_literal("a'b"), "a''b", "quote doublée (CH)");
        assert_eq!(ch.escape_literal("a\\'b"), "a\\\\''b", "backslash ET quote échappés (CH)");
        // Contre-preuve : SQLite/DuckDB laissent le backslash INERTE (correct pour eux -> pas de rupture).
        assert_eq!(SqliteDialect.escape_literal("a\\"), "a\\", "SQLite : backslash inchangé");
        assert_eq!(DuckDbDialect.escape_literal("a\\"), "a\\", "DuckDB : backslash inchangé");

        // Émission COMPILÉE : le compilateur route désormais l'échappement des littéraux par `d.escape_literal`
        // -> un backslash final est DOUBLÉ en CH (littéral borné, pas d'injection) mais laissé INERTE en SQLite
        // (preuve que le dialect gouverne réellement l'échappement). Entrée SOQL = valeur `a\` (1 backslash).
        let ch_sql = to_sql("search source=a\\", 0, 0, &Schema::events_clickhouse()).unwrap();
        let sqlite_sql = to_sql("search source=a\\", 0, 0, &Schema::events()).unwrap();
        assert!(ch_sql.contains("'a\\\\'"), "CH : backslash DOUBLÉ -> littéral borné : {ch_sql}");
        assert!(sqlite_sql.contains("'a\\'") && !sqlite_sql.contains("'a\\\\'"), "SQLite : backslash INERTE (non doublé) : {sqlite_sql}");
        assert_ne!(ch_sql, sqlite_sql, "le dialect gouverne l'échappement (CH != SQLite sur backslash)");
    }

    #[test]
    fn field_mask_warm_tier_masks_like_hot() {
        // Quand les masques sont threadés via `.with_masks()`, le tier WARM (DuckDB) émet le MÊME
        // masque (`'***'`) que le HOT (SQLite) sur le même champ -> un rôle restreint ne voit pas de cleartext
        // sur le tier WARM. Sans masque, le WARM reste byte-identique au WARM non masqué (mode 0).
        let m = masks_of(&[("src_user", MaskAction::Mask)]);
        let hot = to_sql("search | table src_user, host", 0, 0, &Schema::events().with_masks(m.clone())).unwrap();
        let warm = to_sql("search | table src_user, host", 0, 0, &Schema::events_duckdb().with_masks(m.clone())).unwrap();
        assert!(hot.contains("'***'"), "HOT masque src_user : {hot}");
        assert!(warm.contains("'***'"), "WARM masque le MÊME champ : {warm}");
        let warm_plain = to_sql("search | table src_user, host", 0, 0, &Schema::events_duckdb()).unwrap();
        let warm_empty = to_sql("search | table src_user, host", 0, 0, &Schema::events_duckdb().with_masks(FieldMaskSet::new())).unwrap();
        assert_eq!(warm_plain, warm_empty, "WARM masques VIDES -> byte-identique (mode 0)");
    }

    // =============================================================================================
    // KNOWLEDGE OBJECTS — alias / calc / eventtype / tag, + mode 0 + héritage du masque de champ.
    // =============================================================================================

    #[test]
    fn ko_mode0_byte_identical() {
        // KnowledgeSet VIDE -> SQL STRICTEMENT identique au chemin sans KO (parité mode 0, invariant absolu).
        for q in [
            "search source=web | table user, host",
            "search severity=HIGH | stats count by src_ip",
            "search src_ip=1.2.3.4 | top user",
            "search | eval x = severity | table x",
            "search eventtype=foo",  // sans KO : `eventtype` = simple clé JSON -> legacy
            "search tag=bar",        // idem
        ] {
            let plain = to_sql(q, 0, 0, &Schema::events()).unwrap();
            let empty = to_sql(q, 0, 0, &Schema::events().with_knowledge(KnowledgeSet::new())).unwrap();
            assert_eq!(plain, empty, "KO VIDE -> byte-identique pour : {q}");
        }
    }

    #[test]
    fn ko_field_alias_resolves_source() {
        // Alias `client_ip -> src_ip` (colonne réelle) et `username -> user` (clé JSON).
        let mut ko = KnowledgeSet::new();
        ko.add_alias("client_ip", "src_ip");
        ko.add_alias("username", "user");
        let sch = Schema::events().with_knowledge(ko);
        // FILTRE de base sur l'alias -> résout la SOURCE.
        let f = to_sql("search client_ip=1.2.3.4", 0, 0, &sch).unwrap();
        assert!(f.contains("\"src_ip\" = '1.2.3.4'"), "alias client_ip -> src_ip (filtre) : {f}");
        // PROJECTION via l'alias -> json_extract de la source (clé JSON).
        let p = to_sql("search | table username", 0, 0, &sch).unwrap();
        assert!(p.contains("json_extract(fields,'$.user') AS \"username\""), "alias username -> user (projection) : {p}");
        // Un champ RÉEL du même nom l'emporte sur l'alias (aucun alias `host` défini -> intact de toute façon).
        let h = to_sql("search host=web01", 0, 0, &sch).unwrap();
        assert!(h.contains("\"host\" = 'web01'"), "host réel intact : {h}");
    }

    #[test]
    fn ko_calculated_field_computed_at_search_time() {
        // Calc `sev_hi = if(severity=='HIGH',1,0)` -> injecté comme eval implicite au-dessus de la base.
        let mut ko = KnowledgeSet::new();
        ko.add_calc("sev_hi", "if(severity=='HIGH',1,0)");
        let sch = Schema::events().with_knowledge(ko);
        let sql = to_sql("search source=web | where sev_hi > 0", 0, 0, &sch).unwrap();
        // l'eval implicite apparaît (iif — traduction eval de `if`), AS "sev_hi", au-dessus de la base event.
        assert!(sql.contains("AS \"sev_hi\""), "calc projeté : {sql}");
        assert!(sql.contains("iif(severity=='HIGH',1,0)") || sql.contains("iif(severity = 'HIGH',1,0)") || sql.contains("iif("), "calc via eval : {sql}");
        // le calc est disponible pour un `| where` en aval.
        assert!(sql.contains("WHERE \"sev_hi\" > 0"), "calc filtrable en aval : {sql}");
    }

    #[test]
    fn ko_eventtype_classifies_and_searchable() {
        // Eventtype `web_attack` = `source=web severity=HIGH` -> `eventtype=web_attack` compile le filtre stocké.
        let mut ko = KnowledgeSet::new();
        ko.add_eventtype("web_attack", "source=web severity=HIGH");
        let sch = Schema::events().with_knowledge(ko);
        let sql = to_sql("search eventtype=web_attack | stats count", 0, 0, &sch).unwrap();
        assert!(sql.contains("\"source\" = 'web'") && sql.contains("\"severity\" = 'HIGH'"), "eventtype détend le filtre : {sql}");
        assert!(sql.contains("(\"source\" = 'web' AND \"severity\" = 'HIGH')"), "conditions AND-jointes entre parenthèses : {sql}");
        // Eventtype inconnu (avec KO actif) -> erreur explicite.
        assert!(to_sql("search eventtype=nope", 0, 0, &sch).is_err(), "eventtype inconnu rejeté");
    }

    #[test]
    fn ko_tag_expands_to_field_value_conditions() {
        // Tag `pci` sur DEUX paires -> `tag=pci` détend un OR des deux.
        let mut ko = KnowledgeSet::new();
        ko.add_tag("pci", "category", "payment");
        ko.add_tag("pci", "source", "pos");
        let sch = Schema::events().with_knowledge(ko);
        let sql = to_sql("search tag=pci | stats count", 0, 0, &sch).unwrap();
        assert!(sql.contains(" OR "), "tag = OR des paires : {sql}");
        assert!(sql.contains("\"category\" = 'payment'") && sql.contains("\"source\" = 'pos'"), "paires détendues : {sql}");
        assert!(to_sql("search tag=unknown", 0, 0, &sch).is_err(), "tag inconnu rejeté");
    }

    #[test]
    fn ko_masking_not_bypassed_by_calc_field() {
        // field-filters x knowledge-objects : un calc `leak = src_ip` avec src_ip MASQUÉ (colonne réelle) ne DOIT PAS récupérer la valeur.
        let mut ko = KnowledgeSet::new();
        ko.add_calc("leak", "src_ip");
        let m = masks_of(&[("src_ip", MaskAction::Mask)]);
        let sql = to_sql("search | table leak, src_ip", 0, 0, &Schema::events().with_masks(m).with_knowledge(ko)).unwrap();
        // la base masque src_ip ('***') ; le calc lit cette colonne DÉJÀ masquée -> leak = '***', jamais la valeur brute.
        assert!(sql.contains("'***'"), "src_ip masqué à la base : {sql}");
        assert!(sql.contains("AS \"leak\""), "calc projeté : {sql}");
        // aucune extraction brute de src_ip contournant le masque (src_ip est une colonne réelle : jamais json_extract).
        assert!(!sql.contains("json_extract(fields,'$.src_ip')"), "pas de contournement du masque : {sql}");
    }

    #[test]
    fn ko_masking_not_bypassed_by_eventtype_or_alias() {
        // field-filters x knowledge-objects : un eventtype/tag/alias FILTRANT un champ masqué est REJETÉ (oracle interdit).
        let m = masks_of(&[("src_user", MaskAction::Hash)]);
        // eventtype filtrant un champ masqué
        let mut ko1 = KnowledgeSet::new();
        ko1.add_eventtype("byuser", "src_user=alice");
        assert!(
            to_sql("search eventtype=byuser", 0, 0, &Schema::events().with_masks(m.clone()).with_knowledge(ko1)).is_err(),
            "eventtype sur champ masqué REJETÉ (oracle)"
        );
        // tag sur champ masqué
        let mut ko2 = KnowledgeSet::new();
        ko2.add_tag("u", "src_user", "alice");
        assert!(
            to_sql("search tag=u", 0, 0, &Schema::events().with_masks(m.clone()).with_knowledge(ko2)).is_err(),
            "tag sur champ masqué REJETÉ (oracle)"
        );
        // alias vers un champ masqué : filtrer via l'alias est rejeté comme un filtre direct sur la source.
        let mut ko3 = KnowledgeSet::new();
        ko3.add_alias("who", "src_user");
        assert!(
            to_sql("search who=alice", 0, 0, &Schema::events().with_masks(m).with_knowledge(ko3)).is_err(),
            "alias vers champ masqué REJETÉ (pas de contournement)"
        );
    }

    #[test]
    fn ko_injection_rejected() {
        // Noms d'alias/calc/eventtype/tag et champs de tag ALLOWLISTÉS (idents) -> un nom hostile est IGNORÉ
        // à l'insertion (le KO malformé ne s'applique pas) ; une EXPR de calc hostile est rejetée par `eval`.
        let mut ko = KnowledgeSet::new();
        ko.add_alias("evil; DROP", "src_ip"); // canonique invalide -> ignoré
        ko.add_alias("ok", "src_ip);--");      // source invalide -> ignoré
        ko.add_tag("t", "field; DROP", "v");   // champ de tag invalide -> ignoré
        assert!(ko.alias("evil; DROP").is_none() && ko.alias("ok").is_none(), "alias hostiles ignorés");
        assert!(ko.tag("t").is_none(), "tag à champ hostile ignoré");
        // expr de calc hostile -> l'eval implicite échoue à la compilation (mot-clé SQL interdit).
        let mut ko2 = KnowledgeSet::new();
        ko2.add_calc("x", "(SELECT token_hash FROM token)");
        assert!(to_sql("search", 0, 0, &Schema::events().with_knowledge(ko2)).is_err(), "expr calc avec SELECT rejetée par eval");
        // valeur de tag hostile -> ÉCHAPPÉE (quotes doublées), pas d'injection.
        let mut ko3 = KnowledgeSet::new();
        ko3.add_tag("t", "category", "x' OR '1'='1");
        let sql = to_sql("search tag=t", 0, 0, &Schema::events().with_knowledge(ko3)).unwrap();
        assert!(sql.contains("'x'' OR ''1''=''1'"), "valeur de tag échappée : {sql}");
    }

    // ============================================================================================
    // PHASE B — ÉLAGAGE DE PROJECTION `message` (gate `prune_message_projection`, défaut OFF).
    //
    // Invariant de SÛRETÉ (aucun rusqlite en core -> équivalence de RÉSULTAT prouvée par égalité
    // MÉCANIQUE de SQL, pas par exécution) :
    //   * gate GARDE `message`  => SQL prune-ON BYTE-IDENTIQUE à la SQL défaut (prune-OFF).
    //   * gate ÉLAGUE `message` => l'UNIQUE delta est le retrait de la colonne `message` du SELECT de
    //     BASE. Cette colonne est PROUVÉE absente de la sortie ET non référencée par aucune étape ->
    //     l'ôter du SELECT interne ne change AUCUNE valeur d'AUCUNE ligne (les colonnes de sortie et
    //     tout le reste de la SQL sont identiques au bit près).
    // ============================================================================================

    // Occurrence de `message` dans la projection de base (mode 0, non masqué). Le retrait mécanique de
    // cette sous-chaîne = exactement ce que fait l'élagage sur une base unique.
    const PB_BASE_FULL: &str = "message,fields FROM event";
    const PB_BASE_PRUNED: &str = "fields FROM event";

    fn pb_schema() -> Schema { Schema::events().with_message_pruning(true) }

    /// SQL défaut (prune OFF) avec `message` retiré mécaniquement de CHAQUE base (global). Valide comme
    /// oracle d'équivalence pour les requêtes à base UNIQUE (toutes élaguées de la même façon).
    fn pb_off_minus_message(q: &str) -> String {
        compile(q, &Schema::events()).unwrap().sql.replace(PB_BASE_FULL, PB_BASE_PRUNED)
    }

    #[test]
    fn phaseb_default_off_never_prunes() {
        // Gate OFF (défaut events()) : MÊME une forme élaguable garde `message` -> parité mode 0 absolue.
        let q = "search source=x | stats count by source";
        let def = compile(q, &Schema::events()).unwrap().sql;
        assert!(def.contains(PB_BASE_FULL), "défaut OFF ne doit JAMAIS élaguer : {def}");
    }

    #[test]
    fn phaseb_prune_stats_by_source_result_identical() {
        // (a) `... | stats count by source` : réduction terminale, `message` jamais lu -> ÉLAGUÉ.
        let q = "search source=x | stats count by source";
        let on = compile(q, &pb_schema()).unwrap();
        let off = compile(q, &Schema::events()).unwrap();
        assert!(on.sql.contains("xff,fields FROM event"), "base doit être élaguée : {}", on.sql);
        assert!(!on.sql.contains("message"), "message ne doit plus apparaître nulle part : {}", on.sql);
        assert_eq!(on.sql, pb_off_minus_message(q), "SEUL delta = retrait de `message` de la base\nON : {}\nOFF: {}", on.sql, off.sql);
        assert_eq!(on.columns, off.columns, "colonnes de sortie inchangées : on={:?} off={:?}", on.columns, off.columns);
    }

    #[test]
    fn phaseb_prune_various_narrowing_terminals() {
        // Toutes réductrices, `message` jamais référencé -> ÉLAGUÉ ; SQL = défaut moins `message`.
        let prune = [
            "search source=x | stats count",                                            // stats global
            "search source=x | timechart count",                                        // timechart
            "search source=x | table ts source",                                        // table sans message
            "search source=x | fields ts,source",                                       // fields sans message
            "search source=x | top src_ip",                                             // top
            "search source=x | stats dc(user) by src_ip | where dc > 3 | stats count",  // multi-étages, message jamais lu
        ];
        for q in prune {
            let on = compile(q, &pb_schema()).unwrap();
            let off = compile(q, &Schema::events()).unwrap();
            assert!(!on.sql.contains("message"), "message doit être élagué pour: {q}\n{}", on.sql);
            assert_eq!(on.sql, pb_off_minus_message(q), "SEUL delta = `message` de base pour: {q}\nON : {}", on.sql);
            assert_eq!(on.columns, off.columns, "colonnes inchangées pour: {q}");
        }
    }

    #[test]
    fn phaseb_keep_when_message_referenced_or_raw() {
        // Chaque forme DOIT conserver `message` -> SQL prune-ON BYTE-IDENTIQUE au défaut (aucun élagage).
        let keep = [
            "search source=x | where message=\"foo\"",          // (b) where sur message
            "search \"freetext\"",                                // (c) terme libre -> event brut affiché
            "search source=x",                                    // (d) events bruts -> message affiché
            "search source=x | table ts source message",         // (e) table nomme message
            "search source=x | eval m=message",                   // (f) eval lit message
            "search source=x | rex message \"(?P<w>[a-z]+)\"",    // (f) rex sur message
            "search source=x | where dport>100",                  // pas de réduction -> event brut -> garder
            "search source=x | sort -ts | head 10",               // pas de réduction -> garder
            "search source=x | eval y=1",                         // eval NON-message MAIS pas de réduction -> garder
        ];
        for q in keep {
            let on = compile(q, &pb_schema()).unwrap().sql;
            let off = compile(q, &Schema::events()).unwrap().sql;
            assert_eq!(on, off, "DOIT garder message (SQL identique au défaut) pour: {q}");
            assert!(on.contains(PB_BASE_FULL), "base doit garder message pour: {q}\n{on}");
        }
    }

    #[test]
    fn phaseb_table_star_and_bare_are_not_narrowing() {
        // `table *` / `table` nu = passe-plat (ocols inchangés) -> events bruts -> garder message.
        for q in ["search source=x | table *", "search source=x | table"] {
            let on = compile(q, &pb_schema()).unwrap().sql;
            let off = compile(q, &Schema::events()).unwrap().sql;
            assert_eq!(on, off, "table */nu = passe-plat -> garder message : {q}");
            assert!(on.contains(PB_BASE_FULL), "{q} doit garder message");
        }
    }

    #[test]
    fn phaseb_append_prunes_main_keeps_subquery_independently() {
        // La sous-requête `append` décide SON PROPRE élagage : ligne principale réduite (stats) -> élaguée ;
        // sous-requête events-bruts -> conserve `message`. Les colonnes d'union restent identiques.
        let q = "search source=x | stats count by source | append [search source=y]";
        let on = compile(q, &pb_schema()).unwrap();
        let off = compile(q, &Schema::events()).unwrap();
        assert!(on.sql.contains("xff,fields FROM event WHERE \"source\" = 'x'"),
            "base PRINCIPALE élaguée : {}", on.sql);
        assert!(on.sql.contains("message,fields FROM event WHERE \"source\" = 'y'"),
            "base de SOUS-REQUÊTE conservée (décision indépendante) : {}", on.sql);
        assert_eq!(on.columns, off.columns, "colonnes d'union inchangées : on={:?} off={:?}", on.columns, off.columns);
    }

    #[test]
    fn phaseb_masking_preserved_on_remaining_columns() {
        // Masque sur `host` (colonne CONSERVÉE, non référencée). Pruning ON sur une forme élaguable :
        // `message` disparaît, le masque de `host` reste INCHANGÉ -> l'élagage ne touche QUE `message`.
        let mut m = FieldMaskSet::new();
        m.insert("host", MaskAction::Mask);
        let q = "search source=x | stats count by source";
        let masked_off = compile(q, &Schema::events().with_masks(m.clone())).unwrap().sql;
        let masked_on  = compile(q, &Schema::events().with_masks(m).with_message_pruning(true)).unwrap().sql;
        assert!(masked_off.contains("'***'") && masked_on.contains("'***'"), "masque host présent des deux côtés");
        assert_eq!(masked_on, masked_off.replace(PB_BASE_FULL, PB_BASE_PRUNED),
            "SEUL delta = retrait de `message` ; masque host (et tout le reste) intact\nON : {masked_on}\nOFF: {masked_off}");
    }

    #[test]
    fn phaseb_ko_present_blocks_pruning() {
        // Objet de savoir posé (alias `msg -> message`) : le gate se REFERME (confond indirect possible).
        // Requête DANGEREUSE si élaguée à tort : `stats count by msg` résout `msg` -> colonne réelle
        // `message` ; sans base `message`, elle deviendrait `json_extract(fields,'$.message')` (FAUX).
        // Le gate KO garde `message` -> résolution correcte.
        let mut ko = KnowledgeSet::new();
        ko.add_alias("msg", "message");
        let q = "search source=x | stats count by msg";
        let sql = compile(q, &Schema::events().with_knowledge(ko).with_message_pruning(true)).unwrap().sql;
        assert!(sql.contains(PB_BASE_FULL), "KO présent -> ne PAS élaguer : {sql}");
        assert!(sql.contains("\"message\" AS \"msg\""), "msg doit résoudre vers la colonne réelle message : {sql}");
    }

    #[test]
    fn phaseb_contains_ident_word_boundaries() {
        // Le scanner de token borne sur `[A-Za-z0-9_]` : capte la VRAIE référence, ignore les sur-chaînes.
        assert!(contains_ident_word("where message=\"x\"", "message"));
        assert!(contains_ident_word("stats count by message", "message"));
        assert!(contains_ident_word("values(message)", "message"));
        assert!(contains_ident_word("MESSAGE", "message"));           // insensible à la casse
        assert!(!contains_ident_word("error_message", "message"));    // `_` = caractère de mot -> pas une borne
        assert!(!contains_ident_word("message_id", "message"));       // idem à droite
        assert!(!contains_ident_word("search source=x | stats count", "message"));
    }

    // =====================================================================================
    // FILTRE DE LIGNES OBLIGATOIRE NON CONTOURNABLE (`with_row_filter`) : isolation tenant.
    // Prouve que `engagement_id IN (<ids>)` est AND-joint dans le WHERE de CHAQUE base compilée,
    // qu'aucune SoQL utilisateur (WHERE/OR/UNION/sous-requête) ne peut y échapper, et qu'une liste
    // vide matche RIEN (fail-closed). Filtre NON posé -> émission byte-identique (parité mode 0).
    // =====================================================================================

    #[test]
    #[cfg(feature = "forge")]
    fn row_filter_present_in_plain_query() {
        // `search` nu -> le WHERE de base contient l'atome obligatoire (aucun autre filtre).
        let s = Schema::forge().with_row_filter("engagement_id", &[7]);
        let sql = to_sql("search", 0, 0, &s).unwrap();
        assert!(sql.contains("FROM finding WHERE (\"engagement_id\" IN (7))"), "{sql}");
    }

    #[test]
    #[cfg(feature = "forge")]
    fn row_filter_anded_with_user_where_at_base() {
        // Le filtre utilisateur (`severity=HIGH`) ET le filtre obligatoire coexistent, AND-joints.
        let s = Schema::forge().with_row_filter("engagement_id", &[3]);
        let sql = to_sql("search severity=HIGH", 0, 0, &s).unwrap();
        assert!(sql.contains("\"severity\" = 'HIGH'"), "{sql}");
        assert!(sql.contains("(\"engagement_id\" IN (3))"), "{sql}");
        assert!(sql.contains("\"severity\" = 'HIGH' AND (\"engagement_id\" IN (3))"), "AND-join à la base attendu : {sql}");
    }

    #[test]
    #[cfg(feature = "forge")]
    fn row_filter_where_stage_cannot_escape() {
        // Un `| where` en aval enveloppe une base DÉJÀ filtrée : l'atome reste dans la sous-requête de base.
        let s = Schema::forge().with_row_filter("engagement_id", &[9]);
        let sql = to_sql("search | where severity=\"LOW\"", 0, 0, &s).unwrap();
        assert!(sql.contains("FROM finding WHERE (\"engagement_id\" IN (9))"), "base filtrée : {sql}");
    }

    #[test]
    #[cfg(feature = "forge")]
    fn row_filter_applies_to_both_finding_and_runrecord_via_union() {
        // `append` compile en UNION ALL : les DEUX bases (runrecord + finding) portent l'atome.
        let s = Schema::forge().with_row_filter("engagement_id", &[4]);
        let sql = to_sql("runs | append [search]", 0, 0, &s).unwrap();
        let n = sql.matches("(\"engagement_id\" IN (4))").count();
        assert_eq!(n, 2, "les deux bases (runrecord ET finding) doivent porter le filtre : {sql}");
        assert!(sql.contains("FROM runrecord WHERE (\"engagement_id\" IN (4))"), "runrecord filtré : {sql}");
        assert!(sql.contains("FROM finding WHERE (\"engagement_id\" IN (4))"), "finding filtré : {sql}");
    }

    #[test]
    #[cfg(feature = "forge")]
    fn row_filter_applies_to_join_subquery() {
        // `join` : la sous-requête recompile une base avec le MÊME schéma -> les deux côtés filtrés.
        let s = Schema::forge().with_row_filter("engagement_id", &[2]);
        let sql = to_sql("search | join target [runs]", 0, 0, &s).unwrap();
        assert!(sql.contains("FROM finding WHERE (\"engagement_id\" IN (2))"), "gauche filtrée : {sql}");
        assert!(sql.contains("FROM runrecord WHERE (\"engagement_id\" IN (2))"), "sous-requête join filtrée : {sql}");
    }

    #[test]
    #[cfg(feature = "forge")]
    fn row_filter_runrecord_base() {
        let s = Schema::forge().with_row_filter("engagement_id", &[5]);
        let sql = to_sql("runs", 0, 0, &s).unwrap();
        assert!(sql.contains("FROM runrecord WHERE (\"engagement_id\" IN (5))"), "{sql}");
    }

    #[test]
    #[cfg(feature = "forge")]
    fn row_filter_multiple_ids_inlined() {
        let s = Schema::forge().with_row_filter("engagement_id", &[2, 5, 8]);
        let sql = to_sql("search", 0, 0, &s).unwrap();
        assert!(sql.contains("(\"engagement_id\" IN (2,5,8))"), "{sql}");
    }

    #[test]
    #[cfg(feature = "forge")]
    fn row_filter_empty_ids_matches_nothing_fail_closed() {
        // Grant vide -> `1=0` (matche RIEN, jamais toutes les lignes). Aucun `IN (` émis.
        let s = Schema::forge().with_row_filter("engagement_id", &[]);
        let sql = to_sql("search", 0, 0, &s).unwrap();
        assert!(sql.contains("FROM finding WHERE 1=0"), "grant vide -> 1=0 fail-closed : {sql}");
        assert!(!sql.contains("engagement_id IN"), "aucun IN pour un grant vide : {sql}");
        // Idem sur runrecord et même avec un filtre utilisateur : jamais d'élargissement.
        let sql2 = to_sql("search severity=HIGH", 0, 0, &s).unwrap();
        assert!(sql2.contains("\"severity\" = 'HIGH' AND 1=0"), "{sql2}");
        let sql3 = to_sql("runs", 0, 0, &s).unwrap();
        assert!(sql3.contains("FROM runrecord WHERE 1=0"), "{sql3}");
    }

    #[test]
    #[cfg(feature = "forge")]
    fn row_filter_user_cannot_override_with_own_engagement_predicate() {
        // ADVERSARIAL : l'utilisateur granté sur [2] tente `engagement_id=1` (tenant d'un autre). Les DEUX
        // prédicats coexistent (AND) -> intersection VIDE à l'exécution : impossible de lire l'engagement 1.
        let s = Schema::forge().with_row_filter("engagement_id", &[2]);
        let sql = to_sql("search engagement_id=1", 0, 0, &s).unwrap();
        assert!(sql.contains("\"engagement_id\" = 1"), "prédicat utilisateur présent : {sql}");
        assert!(sql.contains("(\"engagement_id\" IN (2))"), "filtre obligatoire toujours présent : {sql}");
        assert!(sql.contains("\"engagement_id\" = 1 AND (\"engagement_id\" IN (2))"), "AND non contournable : {sql}");
    }

    #[test]
    #[cfg(feature = "forge")]
    fn row_filter_unset_is_byte_identical_forge() {
        // Sans row-filter -> émission INCHANGÉE : ni `engagement_id`, ni `1=0`, base identique au legacy.
        let plain = compile("search severity=HIGH | fields target,title", &Schema::forge()).unwrap().sql;
        assert!(!plain.contains("engagement_id"), "aucune fuite du filtre quand non posé : {plain}");
        assert!(!plain.contains("1=0"), "{plain}");
        // La forme de sortie (colonnes) est inchangée (engagement_id JAMAIS projeté).
        let cols = compile("search", &Schema::forge()).unwrap().columns;
        assert!(!cols.iter().any(|c| c == "engagement_id"), "engagement_id hors projection : {cols:?}");
        assert_eq!(cols.len(), 11, "forme de résultat /api/query inchangée : {cols:?}");
    }

    #[test]
    fn row_filter_does_not_affect_events_schema() {
        // Plume (`events()`) ne pose jamais de row-filter -> émission byte-identique (aucun engagement_id).
        let sql = compile("search source=sshd | stats count by src_ip", &Schema::events()).unwrap().sql;
        assert!(!sql.contains("engagement_id"), "events() intact : {sql}");
        assert!(!sql.contains("1=0"), "{sql}");
    }

    // -------------------------------------------------------------------------------------
    // DÉFENSE EN PROFONDEUR : le row-filter OBLIGATOIRE couvre AUSSI la base métrique
    // (`metric_base`). Aucun schéma actuel n'expose ce chemin sous row-filter (Forge=metric:false,
    // Plume=row_filter:None) : c'est une garantie universelle pour tout schéma tenant futur qui
    // poserait `metric:true` ET un row-filter. On utilise `events()` (metric:true, non gaté forge).
    // -------------------------------------------------------------------------------------

    #[test]
    fn metric_base_row_filter_on_both_leaves() {
        // metric:true + row-filter -> l'atome obligatoire est AND-joint dans le WHERE des DEUX feuilles
        // physiques (metric ET metric_rollup), via le MÊME helper (`RowFilter::cond_sql`) que la feuille
        // principale (colonne quotée, ids i64 inlinés -> injection-safe).
        let s = Schema::events().with_row_filter("tenant_id", &[7]);
        let sql = to_sql("metric node_load1", 0, 0, &s).unwrap();
        assert_eq!(sql.matches("(\"tenant_id\" IN (7))").count(), 2, "metric ET metric_rollup filtrés : {sql}");
        assert!(sql.contains("FROM metric WHERE name='node_load1' AND (\"tenant_id\" IN (7))"), "{sql}");
        assert!(sql.contains("FROM metric_rollup WHERE name='node_load1' AND (\"tenant_id\" IN (7))"), "{sql}");
    }

    #[test]
    fn metric_base_row_filter_empty_fail_closed() {
        // Grant vide -> `1=0` (fail-closed : matche RIEN, jamais toutes les lignes) sur les DEUX feuilles.
        let s = Schema::events().with_row_filter("tenant_id", &[]);
        let sql = to_sql("metric node_load1", 0, 0, &s).unwrap();
        assert_eq!(sql.matches("1=0").count(), 2, "les deux feuilles fail-closed : {sql}");
        assert!(!sql.contains("tenant_id IN"), "aucun IN pour un grant vide : {sql}");
    }

    #[test]
    fn metric_base_no_row_filter_byte_identical() {
        // Sans row-filter (défaut Plume/Forge) -> émission métrique BYTE-IDENTIQUE au legacy pré-fix.
        let sql = to_sql("metric node_load1", 0, 0, &Schema::events()).unwrap();
        assert_eq!(
            sql,
            "SELECT ts,host,value FROM metric WHERE name='node_load1' UNION ALL SELECT ts,host,avg AS value FROM metric_rollup WHERE name='node_load1' ORDER BY ts"
        );
        assert!(!sql.contains("tenant_id"), "{sql}");
        assert!(!sql.contains("1=0"), "{sql}");
    }

    // --- KEYSET PAGINATION : projection opt-in de la clé de tri stable `id` -------------------
    #[test]
    fn cursor_id_off_is_byte_identical() {
        // Défaut (cursor_id OFF) -> SQL STRICTEMENT identique à events() ; `id` hors projection. Mode 0.
        for q in ["search source=sshd", "search severity=HIGH src_ip=10.0.0.1", "search | head 5"] {
            let off = compile(q, &Schema::events()).unwrap();
            let explicit = compile(q, &Schema::events().with_cursor_id(false)).unwrap();
            assert_eq!(off.sql, explicit.sql, "with_cursor_id(false) doit être byte-identique pour: {q}");
            assert!(!off.columns.iter().any(|c| c == "id"), "id hors projection par défaut: {q}");
        }
    }

    #[test]
    fn cursor_id_on_projects_id_on_raw_search() {
        // ON -> `id` AJOUTÉ en FIN de projection de base + comme dernière colonne de sortie (search nue).
        let on = compile("search source=sshd", &Schema::events().with_cursor_id(true)).unwrap();
        let off = compile("search source=sshd", &Schema::events()).unwrap();
        assert_eq!(on.columns.last().map(String::as_str), Some("id"), "id = dernière colonne: {:?}", on.columns);
        // SEUL delta = `,id` inséré juste avant `FROM event` — rien d'autre ne change.
        assert_eq!(on.sql, off.sql.replacen(" FROM event", ",id FROM event", 1), "SEUL delta = ,id : {}", on.sql);
    }

    #[test]
    fn cursor_id_on_is_noop_when_base_has_no_real_id() {
        // Base sans `id` réel (metric) -> ON est un no-op : le curseur ne s'applique qu'aux bases event.
        let on = to_sql("metric node_load1", 0, 0, &Schema::events().with_cursor_id(true)).unwrap();
        let off = to_sql("metric node_load1", 0, 0, &Schema::events()).unwrap();
        assert_eq!(on, off, "cursor_id no-op sur base metric (pas d'id réel)");
    }

    #[cfg(feature = "forge")]
    #[test]
    fn cursor_id_on_is_noop_on_forge_no_id() {
        // Forge finding n'a pas de colonne `id` réelle -> ON est un no-op byte-identique.
        let on = compile("search severity=HIGH", &Schema::forge().with_cursor_id(true)).unwrap();
        let off = compile("search severity=HIGH", &Schema::forge()).unwrap();
        assert_eq!(on.sql, off.sql, "cursor_id no-op sur Forge (finding sans id réel)");
        assert!(!on.columns.iter().any(|c| c == "id"), "pas d'id sur Forge: {:?}", on.columns);
    }

    // --- S1 : `span=` — ARITHMÉTIQUE BORNÉE (plus de panic, plus de substitution muette) --------
    #[test]
    fn s1_span_overflow_is_error_not_panic() {
        // Mesure du rapport : `span=200000000000000d` -> `n * 86400` déborde i64.
        // ATTENDU : Err CLAIRE rendue à l'appelant (jamais un panic du thread de compilation, jamais
        // un wrap négatif rattrapé par `if span <= 0` qui SUBSTITUERAIT le bucket demandé).
        let e = to_sql("search | timechart span=200000000000000d count", 0, 0, &Schema::events())
            .expect_err("un span qui déborde doit être une erreur, pas un panic");
        assert!(e.to_lowercase().contains("span"), "l'erreur doit nommer le span : {e}");
    }

    #[test]
    fn s1_span_out_of_range_never_substitutes_silently() {
        // Un span ÉNORME mais sans débordement i64 (10^12 s ≈ 31 700 ans) : la borne haute doit le
        // REFUSER explicitement — et surtout ne JAMAIS retomber sur le bucket auto (60s…7j), ce qui
        // ferait mesurer à la requête autre chose que ce qu'elle demande.
        let e = to_sql("search | timechart span=1000000000000s count", 0, 0, &Schema::events())
            .expect_err("un span hors bornes doit être une erreur");
        assert!(e.to_lowercase().contains("span"), "l'erreur doit nommer le span : {e}");
        // Contre-preuve : un span légitime compile toujours et pose bien SON bucket.
        let ok = to_sql("search | timechart span=1h count", 0, 0, &Schema::events()).unwrap();
        assert!(ok.contains("(ts/3600)*3600"), "bucket 1h attendu : {ok}");
    }

    // --- S2 : bornes de compilation (nombre d'étapes + taille du SQL émis) ---------------------
    #[test]
    fn s2_pipeline_stage_count_is_bounded() {
        // Aucune borne n'existait sur le NOMBRE d'étapes de pipe : 2000 étapes compilaient.
        let q = format!("search{}", " | head 5".repeat(2000));
        let e = to_sql(&q, 0, 0, &Schema::events()).expect_err("un pipeline de 2000 étapes doit être refusé");
        assert!(e.contains("étape"), "l'erreur doit parler des étapes : {e}");
    }

    #[test]
    fn s2_emitted_sql_size_is_bounded() {
        // Mesure du rapport : `eventstats values(...)` interpole le SQL courant DEUX fois par étage
        // -> croissance en 4^k. k=16 produisait ~14 Mo de SQL (k=24 ≈ 3,6 Gio = OOM sous 2 Go).
        // ATTENDU : Err claire au dépassement de la borne de taille, pas un buffer illimité.
        let q = format!("search{}", " | eventstats values(user) by src_ip".repeat(16));
        let e = to_sql(&q, 0, 0, &Schema::events()).expect_err("la croissance 4^k doit être bornée");
        assert!(e.to_lowercase().contains("complexe") || e.to_lowercase().contains("taille"), "erreur de taille attendue : {e}");
    }

    #[test]
    fn s2_realistic_queries_still_compile() {
        // Garde-fou : les bornes ne doivent RIEN changer pour une requête légitime réaliste
        // (le corpus différentiel 99 requêtes est la référence ; ces 3 en sont des représentantes).
        for q in [
            "search source=web scope=external | stats count by src_ip | sort -count | head 20",
            "search source=cloudflare | stats values(user) by src_ip",
            "search source=web | eventstats count by src_ip | where count > 10 | stats count",
        ] {
            to_sql(q, 0, 0, &Schema::events()).unwrap_or_else(|e| panic!("doit compiler ({q}) : {e}"));
        }
    }

    // --- S10 : `metric` — un label invalide ne fait plus DISPARAÎTRE le filtre/groupement -------
    #[test]
    fn s10_metric_invalid_label_filter_is_error() {
        // Mesuré : `metric node_load1 foo-bar=1` -> le filtre DISPARAISSAIT et la requête renvoyait
        // TOUTES les séries de la métrique (règle de détection qui ne mesure plus ce qu'elle croit).
        let e = to_sql("metric node_load1 foo-bar=1", 0, 0, &Schema::events())
            .expect_err("un label invalide doit être refusé, pas ignoré");
        assert!(e.contains("foo-bar"), "l'erreur doit nommer le label : {e}");
        // Contre-preuve : un label valide filtre toujours.
        let ok = to_sql("metric http_requests_total job=api", 0, 0, &Schema::events()).unwrap();
        assert!(ok.contains("json_extract(labels,'$.job')='api'"), "{ok}");
    }

    #[test]
    fn s10_metric_invalid_by_label_is_error() {
        // Mesuré : `metric node_load1 by foo-bar` -> le GROUPEMENT disparaissait silencieusement.
        let e = to_sql("metric node_load1 by foo-bar", 0, 0, &Schema::events())
            .expect_err("un label de `by` invalide doit être refusé, pas ignoré");
        assert!(e.contains("foo-bar"), "l'erreur doit nommer le label : {e}");
        let ok = to_sql("metric http_requests_total by code", 0, 0, &Schema::events()).unwrap();
        assert!(ok.contains("json_extract(labels,'$.code')"), "{ok}");
    }

    #[test]
    fn s10_metric_by_without_a_valid_label_is_error_too() {
        // RÉSIDU DE LA MÊME CLASSE, mesuré sur 742efe7 ET sur 48035b9 : un `by` SANS aucun label valide
        // s'évaporait en silence (le `.filter(|s| !s.is_empty())` jetait les labels vides) et la requête
        // rendait TOUTES les séries SANS regroupement — exactement le mode d'échec S10 que le reste de
        // l'étape refuse. Plus aucun label n'est jeté : `soql_ident_ok` tranche, et lui seul.
        for q in [
            "metric node_load1 by",
            "metric node_load1 by ,",
            "metric node_load1 by ,,",
            "metric node_load1 by ,code",
            "metric node_load1 by code,",
            "metric node_load1 by code,,job",
        ] {
            match to_sql(q, 0, 0, &Schema::events()) {
                Ok(sql) => panic!("« {q} » doit être refusé et non regrouper en silence : {sql}"),
                Err(e) => assert!(e.contains("label invalide dans `by`"), "{e}"),
            }
        }
        // Contre-preuve : les formes légitimes de `by` sont intactes (goldens de regroupement).
        let a = to_sql("metric node_load1 by code", 0, 0, &Schema::events()).unwrap();
        assert!(a.contains("json_extract(labels,'$.code') AS \"code\""), "{a}");
        let b = to_sql("metric node_load1 by code,job", 0, 0, &Schema::events()).unwrap();
        assert!(b.contains("'$.code') AS \"code\""), "{b}");
        assert!(b.contains("'$.job') AS \"job\""), "{b}");
        let c = to_sql("metric node_load1 value>3 by code", 0, 0, &Schema::events()).unwrap();
        assert!(c.contains("value > 3") && c.contains("'$.code')"), "{c}");
    }

    // --- S11 : un nom de champ invalide ne dégénère plus en scan plein-texte -------------------
    #[test]
    fn s11_invalid_field_name_in_filter_is_error() {
        // Mesuré : `search foo-bar=1` -> `message LIKE '%foo-bar=1%'` (scan non borné + jeu de lignes
        // DIFFÉRENT de celui demandé = faux négatif muet dans une règle).
        for (q, field) in [
            ("search foo-bar=1", "foo-bar"),
            ("search x-forwarded-for=1.2.3.4", "x-forwarded-for"),
            ("search http.status>=500", "http.status"),
        ] {
            match to_sql(q, 0, 0, &Schema::events()) {
                Ok(sql) => panic!("attendu une erreur pour « {q} », obtenu du SQL : {sql}"),
                Err(e) => assert!(e.contains(field), "l'erreur doit nommer le champ {field} : {e}"),
            }
        }
    }

    #[test]
    fn s11_true_freetext_still_scans() {
        // Un VRAI terme libre (aucun opérateur de comparaison) garde le chemin LIKE, inchangé.
        let a = to_sql("search failed password", 0, 0, &Schema::events()).unwrap();
        assert!(a.contains("message LIKE '%failed%'") && a.contains("message LIKE '%password%'"), "{a}");
        // Une PHRASE quotée qui contient un `=` reste un terme libre. ATTENTION à ne pas lire ce cas
        // comme une preuve générale : `GET /x?a=1` est exempté DEUX FOIS (jeton quoté, ET partie gauche
        // sans forme de nom de champ). La garantie « une phrase quotée n'est jamais lue comme un nom de
        // champ » est prouvée par `s11_quoted_phrase_is_never_read_as_a_field_name`, dont les cas ont
        // une partie gauche EN forme de nom de champ (`user-agent=…`) — les 6 régressions mesurées.
        let b = to_sql("search \"GET /x?a=1\"", 0, 0, &Schema::events()).unwrap();
        assert!(b.contains("LIKE '%GET /x?a=1%'"), "{b}");
        // Un horodatage (`:` = alias de `=`) n'est pas un nom de champ : reste un terme libre.
        let c = to_sql("search 2026-07-25T10:00:00", 0, 0, &Schema::events()).unwrap();
        assert!(c.contains("LIKE '%2026-07-25T10:00:00%'"), "{c}");
    }

    // --- PRÉ-PASS `in (...)` : nom de champ COMPLET (plus de filtre muet sur un AUTRE champ) ----
    #[test]
    fn in_prepass_never_filters_a_field_the_user_did_not_name() {
        // DÉFAUT PRÉ-EXISTANT (mesuré sur 4b16822, AVANT ce correctif) : la classe `[A-Za-z0-9_]*` de
        // la classe de `in_clause_re` n'accrochait que le DERNIER segment après le tiret/point.
        //   search x-forwarded-for in (1,2) -> CAST(json_extract(fields,'$.for') AS REAL) IN (1,2)
        //   search src-ip in (10,11)        -> ... '$.ip'  ... IN (10,11)
        //   search http.status in (500,502) -> ... '$.status' ... IN (500,502)
        // Ce n'est PAS un scan plein-texte : c'est un FILTRE MUET SUR UN AUTRE CHAMP -> faux négatif
        // silencieux dans une règle de détection. ATTENDU : refus explicite nommant le champ COMPLET.
        for (q, field, ghost) in [
            ("search x-forwarded-for in (1,2)", "x-forwarded-for", "$.for"),
            ("search src-ip in (10,11)", "src-ip", "$.ip"),
            ("search http.status in (500,502)", "http.status", "$.status"),
            ("search -foo in (1,2)", "-foo", "$.foo"),
        ] {
            match to_sql(q, 0, 0, &Schema::events()) {
                Ok(sql) => panic!("attendu une erreur pour « {q} », obtenu un filtre : {sql}"),
                Err(e) => {
                    assert!(e.contains(field), "l'erreur doit nommer le champ COMPLET {field} : {e}");
                    assert!(!e.contains(ghost), "l'erreur ne doit pas parler du champ fantôme {ghost} : {e}");
                }
            }
        }
        // Même défaut sur l'étape `where` (le pré-pass y passe par `in_clause_whole`).
        let e = to_sql("search | where x-forwarded-for in (1,2)", 0, 0, &Schema::events())
            .expect_err("`where` doit refuser, pas filtrer un autre champ");
        assert!(e.contains("x-forwarded-for"), "l'erreur doit nommer le champ complet : {e}");
    }

    // Le nom d'une clause `in (...)` n'est plus défini par une CLASSE DE CARACTÈRES mais par la
    // FRONTIÈRE de jeton : aucun séparateur, présent ou futur, ne peut donc rouvrir la troncature.
    // CE TEST EST ÉCRIT CONTRE LA CLASSE, PAS CONTRE LES CAS TRAITÉS : la liste ci-dessous contient
    // des séparateurs que le code ne nomme NULLE PART — le seul caractère qu'il lit encore est le
    // délimiteur OUVRANT de la liste de la clause elle-même, retiré en TÊTE du jeton (groupement) et
    // LU dans le match, pas écrit. Y compris non-ASCII, écritures multi-lignes et casses mélangées.
    #[test]
    fn in_prepass_field_name_is_bounded_by_the_token_not_by_a_character_class() {
        // MESURÉ sur 742efe7 : la classe `[A-Za-z0-9_.-]` ne retenait que le DERNIER segment ->
        //   search cache/status in (200,302) -> ... '$.status' ... IN (200,302)   (champ jamais nommé)
        //   search user@host    in (1,2)     -> "host" IN (1,2)                    (VRAIE colonne indexée)
        for (q, field, ghost) in [
            ("search cache/status in (200,302)", "cache/status", "$.status"),
            ("search user@host in (1,2)", "user@host", "\"host\""),
            ("search api/v1/status in (500,502)", "api/v1/status", "$.status"),
            ("search foo$bar in (1,2)", "foo$bar", "$.bar"),
            ("search foo+bar in (1,2)", "foo+bar", "$.bar"),
            ("search foo%bar in (1,2)", "foo%bar", "$.bar"),
            ("search foo!bar in (1,2)", "foo!bar", "$.bar"),
            ("search foo*bar in (1,2)", "foo*bar", "$.bar"),
            ("search foo#bar in (1,2)", "foo#bar", "$.bar"),
            ("search foo@bar in (1,2)", "foo@bar", "$.bar"),
            // Séparateurs que le correctif n'énumère NULLE PART :
            ("search foo~bar in (1,2)", "foo~bar", "$.bar"),
            ("search foo^bar in (1,2)", "foo^bar", "$.bar"),
            ("search foo&bar in (1,2)", "foo&bar", "$.bar"),
            ("search foo;bar in (1,2)", "foo;bar", "$.bar"),
            ("search foo'bar in (1,2)", "foo'bar", "$.bar"),
            ("search foo,bar in (1,2)", "foo,bar", "$.bar"),
            ("search foo]bar in (1,2)", "foo]bar", "$.bar"),
            ("search foo?bar in (1,2)", "foo?bar", "$.bar"),
            ("search foo=bar in (1,2)", "foo=bar", "$.bar"),
            ("search foo:bar in (1,2)", "foo:bar", "$.bar"),
            // Non-ASCII (le nom capturé doit rester une frontière de CARACTÈRE valide) :
            ("search fooébar in (1,2)", "fooébar", "$.bar"),
            ("search foo·bar in (1,2)", "foo·bar", "$.bar"),
            ("search foo→bar in (1,2)", "foo→bar", "$.bar"),
            ("search fooλbar in (1,2)", "fooλbar", "$.bar"),
            // Quotation FERMÉE avant le nom : le nom réclamé est tout le jeton, pas son suffixe.
            ("search \"abc\"status in (1,2)", "abcstatus", "\"status\""),
            // Casse, espacement multiple, `not in`, écriture multi-ligne :
            ("search x-forwarded-for IN (1,2)", "x-forwarded-for", "$.for"),
            ("search x-forwarded-for In (1,2)", "x-forwarded-for", "$.for"),
            ("search x-forwarded-for    in    (1,2)", "x-forwarded-for", "$.for"),
            ("search x-forwarded-for not in (1,2)", "x-forwarded-for", "$.for"),
            ("search x-forwarded-for NOT IN (1,2)", "x-forwarded-for", "$.for"),
            ("search cache/status\nin (1,2)", "cache/status", "$.status"),
        ] {
            match to_sql(q, 0, 0, &Schema::events()) {
                Ok(sql) => panic!("attendu une erreur pour « {q} », obtenu un filtre : {sql}"),
                Err(e) => {
                    assert!(e.contains(field), "l'erreur doit nommer le champ COMPLET {field} : {e}");
                    assert!(!e.contains(ghost), "l'erreur ne doit pas parler du champ fantôme {ghost} : {e}");
                }
            }
        }
        // Sous-recherche (depth > 0) et étape `where` : mêmes frontières, même refus.
        for q in [
            "search source=a | append [search cache/status in (200,302) | stats count]",
            "search | stats count by mitre | join mitre [search user@host in (1,2) | stats count]",
            "search | where cache/status in (1,2)",
            "search | where foo@bar in (1,2)",
        ] {
            let e = to_sql(q, 0, 0, &Schema::events()).expect_err("la garde doit valoir ici aussi");
            assert!(!e.is_empty(), "{q}");
        }
    }

    #[test]
    fn in_prepass_legitimate_clauses_are_unchanged() {
        // CONTRE-PREUVE (anti-régression) : les 5 formes légitimes du corpus rendent le MÊME SQL
        // qu'avant le correctif — vérifié ici par leur SQL LITTÉRAL (goldens figés).
        let ev = Schema::events();
        let base = "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event";
        assert_eq!(
            to_sql("search dport in (80,443)", 0, 0, &ev).unwrap(),
            format!("{base} WHERE CAST(json_extract(fields,'$.dport') AS REAL) IN (80,443)")
        );
        assert_eq!(
            to_sql("search user not in (root,ubuntu)", 0, 0, &ev).unwrap(),
            format!("{base} WHERE json_extract(fields,'$.user') NOT IN ('root','ubuntu')")
        );
        assert_eq!(
            to_sql("search source=web dport in (80,443,8080)", 0, 0, &ev).unwrap(),
            format!("{base} WHERE CAST(json_extract(fields,'$.dport') AS REAL) IN (80,443,8080) AND \"source\" = 'web'")
        );
        assert_eq!(
            to_sql("search | where dport in (80,443)", 0, 0, &ev).unwrap(),
            format!("SELECT * FROM ({base}) WHERE CAST(json_extract(fields,'$.dport') AS REAL) IN (80,443)")
        );
        // Une clause `in (` À L'INTÉRIEUR d'un littéral quoté n'est PAS une clause `in` (CORE-1) :
        // elle reste une égalité, exactement comme avant.
        assert_eq!(
            to_sql("search message=\"user in (a,b)\"", 0, 0, &ev).unwrap(),
            format!("{base} WHERE \"message\" = 'user in (a,b)'")
        );
    }

    // --- PRÉ-PASS `in (...)` : PLUS AUCUNE EXCEPTION DE CARACTÈRE, PAS MÊME `(` -----------------
    #[test]
    fn in_prepass_has_no_separator_exception_not_even_the_grouping_one() {
        // DÉFAUT MESURÉ sur 6fff644 (sonde hors dépôt, export `git archive HEAD`) : la classe
        // `[^\s(]+` EXCLUAIT la parenthèse ouvrante, donc le jeton restait coupé DESSUS et le filtre
        // repartait sur le suffixe — un champ que l'utilisateur n'a jamais nommé :
        //   search foo(host in (1,2)        -> "host" IN (1,2) AND message LIKE '%foo(%'
        //   search count(src_ip in (10,11)) -> "src_ip" IN (10,11) AND …
        //   search a(b(host in (1,2)        -> "host" IN (1,2) AND …
        //   search lower(host in (a,b))     -> "host" COLLATE NOCASE IN ('a','b') AND …
        // `"host"` et `"src_ip"` sont les VRAIES colonnes indexées : filtre MUET, faux négatif dans une
        // règle. ATTENDU : refus nommant le jeton ENTIER, et jamais le champ fantôme.
        //
        // CE TEST EST ÉCRIT CONTRE LA CLASSE, PAS CONTRE LES CAS TRAITÉS. La liste ci-dessous mélange
        // volontairement des caractères que le code ne nomme NULLE PART (le seul caractère qu'il lit est
        // le délimiteur ouvrant de la liste de la clause elle-même, LU dans le match) : ZWSP, SHY, hors
        // BMP, ponctuation, guillemet simple, et la parenthèse en position MÉDIANE.
        for (q, field, ghost) in [
            ("search foo(host in (1,2)", "foo(host", "\"host\""),
            ("search count(src_ip in (10,11))", "count(src_ip", "\"src_ip\""),
            ("search a(b(host in (1,2)", "a(b(host", "\"host\""),
            ("search lower(host in (a,b))", "lower(host", "\"host\""),
            ("search x=(y in (1,2))", "x=(y", "$.y"),
            ("search foo(bar)baz in (1,2)", "foo(bar)baz", "$.baz"),
            // Caractères jamais nommés par le correctif :
            ("search foo\u{200b}host in (1,2)", "foo\u{200b}host", "\"host\""),
            ("search foo\u{00ad}host in (1,2)", "foo\u{00ad}host", "\"host\""),
            ("search foo\u{1d53d}host in (1,2)", "foo\u{1d53d}host", "\"host\""),
            ("search foo\u{00b7}host in (1,2)", "foo\u{00b7}host", "\"host\""),
            ("search foo\u{00a4}host in (1,2)", "foo\u{00a4}host", "\"host\""),
            ("search foo\u{00ac}host in (1,2)", "foo\u{00ac}host", "\"host\""),
            ("search foo\u{00b6}host in (1,2)", "foo\u{00b6}host", "\"host\""),
            ("search foo\\host in (1,2)", "foo\\host", "\"host\""),
        ] {
            match to_sql(q, 0, 0, &Schema::events()) {
                Ok(sql) => panic!("attendu une erreur pour « {q} », obtenu un filtre : {sql}"),
                Err(e) => {
                    assert!(e.contains(field), "l'erreur doit nommer le jeton ENTIER {field} : {e}");
                    assert!(!e.contains(ghost), "l'erreur ne doit pas parler du champ fantôme {ghost} : {e}");
                }
            }
        }
        // Le backtick est intercepté PLUS TÔT (couche macro) et n'atteint pas le pré-pass : il est
        // refusé, mais avec le message de cette couche-là. On ne réclame donc que le refus.
        to_sql("search foo`host in (1,2)", 0, 0, &Schema::events()).expect_err("backtick refusé en amont");
        // CAS NON TRAITÉ EXPLICITEMENT, VÉRIFIÉ QUAND MÊME : sans blanc avant `in` (`host(in (1,2)`)
        // il n'y a pas de clause du tout — la sortie est un scan plein-texte, et surtout AUCUN filtre
        // sur `host` n'est émis. C'est l'autre face de la garde : ne pas fabriquer de filtre fantôme.
        let s = to_sql("search host(in (1,2)", 0, 0, &Schema::events()).unwrap();
        assert!(!s.contains(" IN ("), "aucun filtre `IN` ne doit être fabriqué ici : {s}");
        assert!(s.contains("LIKE '%host(in%'"), "{s}");
        // ATTEIGNABLE EN SOUS-RECHERCHE : la garde vaut à la profondeur maximale (3), comme au depth 0.
        let e = to_sql(
            "search source=a | append [search source=b | append [search source=c | append [search foo(host in (1,2) | stats count]]]",
            0, 0, &Schema::events(),
        ).expect_err("la garde doit valoir à la profondeur 3");
        assert!(e.contains("foo(host"), "{e}");
        assert!(!e.contains("\"host\" IN"), "{e}");
    }

    #[test]
    fn in_prepass_leading_parens_are_grouping_and_stay_legitimate() {
        // CONTRE-PREUVE, ET C'EST ELLE QUI INTERDIT DE RETIRER L'EXCEPTION BÊTEMENT : une parenthèse
        // OUVRANTE DE TÊTE est du GROUPEMENT, pas une partie du nom. Elle est retirée de la tête du
        // jeton (le reste doit être un identifiant entier) puis RÉÉMISE dans le texte résiduel, où elle
        // repart en terme libre. Goldens LITTÉRAUX relevés par sonde sur le TAG PUBLIC v0.2.0 (48035b9)
        // ET sur 6fff644 : ces cinq formes rendent le MÊME SQL à l'octet près.
        let ev = Schema::events();
        let b = "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event";
        for (q, want) in [
            ("search (foo in (1,2)", format!("{b} WHERE CAST(json_extract(fields,'$.foo') AS REAL) IN (1,2) AND message LIKE '%(%'")),
            ("search (foo in (1,2))", format!("{b} WHERE CAST(json_extract(fields,'$.foo') AS REAL) IN (1,2) AND message LIKE '%(%' AND message LIKE '%)%'")),
            ("search ((foo in (1,2)))", format!("{b} WHERE CAST(json_extract(fields,'$.foo') AS REAL) IN (1,2) AND message LIKE '%((%' AND message LIKE '%))%'")),
            ("search (dport in (80,443))", format!("{b} WHERE CAST(json_extract(fields,'$.dport') AS REAL) IN (80,443) AND message LIKE '%(%' AND message LIKE '%)%'")),
            ("search a=1 (b in (1,2))", format!("{b} WHERE CAST(json_extract(fields,'$.b') AS REAL) IN (1,2) AND CAST(json_extract(fields,'$.a') AS REAL) = 1 AND message LIKE '%(%' AND message LIKE '%)%'")),
        ] {
            assert_eq!(to_sql(q, 0, 0, &ev).unwrap(), want, "groupement légitime réécrit : {q}");
        }
        // Une parenthèse FERMANTE de tête, elle, n'est pas du groupement d'ouverture : le nom réclamé
        // reste `)a` et la clause est refusée. Cas jamais traité explicitement, il tombe du bon côté.
        let e = to_sql("search )a in (1,2)", 0, 0, &ev).expect_err("`)a` n'est pas un nom");
        assert!(e.contains(")a"), "{e}");
        // `search (a) in (1,2)` : le groupement de TÊTE part, `a)` reste -> refusé en nommant `a)`.
        let e = to_sql("search (a) in (1,2)", 0, 0, &ev).expect_err("`a)` n'est pas un nom");
        assert!(e.contains("a)"), "{e}");
        // ÉTAPE `where` : elle n'a AUCUNE grammaire de groupement (mesuré sur 48035b9 comme sur
        // 6fff644 : `where (count > 5)` est refusé). Un préfixe de groupement y signifie donc de la
        // structure que `where` ne sait pas lire -> ce n'est pas une clause pure, et le refus est
        // INCHANGÉ. Ces trois formes ne doivent pas devenir compilables au prétexte du peeling.
        for q in [
            "search | where (dport in (80,443))",
            "search | where ((a in (1)) or (b in (2)))",
            "search | where (dport in (80,443)",
        ] {
            to_sql(q, 0, 0, &ev).expect_err(&format!("`where` n'a pas de groupement : {q}"));
        }
        // ... et la clause `where` NUE reste intacte.
        assert_eq!(
            to_sql("search | where dport in (80,443)", 0, 0, &ev).unwrap(),
            format!("SELECT * FROM ({b}) WHERE CAST(json_extract(fields,'$.dport') AS REAL) IN (80,443)")
        );
    }

    // --- S11 (suite) : la garde vaut aux TROIS étages, et exempte une phrase QUOTÉE -------------
    #[test]
    fn s11_quoted_phrase_is_never_read_as_a_field_name() {
        // RÉGRESSION MESURÉE sur 4b16822 : la garde refusait 6 phrases d'analyste réalistes, parce que
        // `soql_tokenize` JETAIT les guillemets — l'aval ne pouvait plus distinguer une PHRASE d'un nom
        // de champ mal écrit. Chaque golden ci-dessous est le SQL rendu AVANT la garde (relevé par sonde
        // compilée sur 48035b9) : une phrase quotée doit rendre EXACTEMENT ce SQL, à l'octet près.
        let ev = Schema::events();
        let b = "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event";
        for (q, want) in [
            ("search \"user-agent=curl/7.68\"", format!("{b} WHERE message LIKE '%user-agent=curl/7.68%'")),
            ("search \"content-type=application/json\"", format!("{b} WHERE message LIKE '%content-type=application/json%'")),
            ("search \"x-forwarded-for=10.0.0.1\"", format!("{b} WHERE message LIKE '%x-forwarded-for=10.0.0.1%'")),
            ("search \"set-cookie=session\"", format!("{b} WHERE message LIKE '%set-cookie=session%'")),
            ("search \"rate-limit=exceeded\"", format!("{b} WHERE message LIKE '%rate-limit=exceeded%'")),
            ("search source=web \"cache-control=no-store\"", format!("{b} WHERE \"source\" = 'web' AND message LIKE '%cache-control=no-store%'")),
            // Guillemets PARTIELS (`"foo-bar"=1`) : un seul jeton, quoté -> chemin historique lui aussi.
            ("search \"foo-bar\"=1", format!("{b} WHERE message LIKE '%foo-bar=1%'")),
        ] {
            assert_eq!(to_sql(q, 0, 0, &ev).unwrap(), want, "phrase quotée refusée ou réécrite : {q}");
        }
    }

    #[test]
    fn s11_guard_holds_on_all_three_stages() {
        // La MÊME entrée est analysée par TROIS étages successifs ; la garde doit valoir aux trois,
        // sinon un espace ou une clause `in` suffit à retomber dans le défaut. Mesuré sur 4b16822 :
        //   pré-pass `in (...)` : search x-forwarded-for in (1,2) -> filtre MUET sur le champ `for`
        //   recollage glue      : search foo-bar = 1              -> message LIKE '%foo-bar%' AND LIKE '%=1%'
        //   boucle d'opérateurs : search foo-bar=1                -> (déjà fermé)
        for (q, field) in [
            ("search x-forwarded-for in (1,2)", "x-forwarded-for"),
            ("search foo-bar = 1", "foo-bar"),
            ("search src-ip >= 5", "src-ip"),
            ("search foo-bar=1", "foo-bar"),
            ("search http.status>=500", "http.status"),
        ] {
            match to_sql(q, 0, 0, &Schema::events()) {
                Ok(sql) => panic!("attendu une erreur pour « {q} », obtenu du SQL : {sql}"),
                Err(e) => assert!(e.contains(field), "l'erreur doit nommer le champ {field} : {e}"),
            }
        }
        // L'ÉCHAPPATOIRE ANNONCÉE PAR LE MESSAGE D'ERREUR EXISTE VRAIMENT : mettre le terme entre
        // guillemets le rend à la recherche plein-texte (c'est ce que le message dit de faire).
        let ev = Schema::events();
        let b = "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event";
        assert_eq!(
            to_sql("search \"foo-bar=1\"", 0, 0, &ev).unwrap(),
            format!("{b} WHERE message LIKE '%foo-bar=1%'")
        );
        assert_eq!(
            to_sql("search \"x-forwarded-for in (1,2)\"", 0, 0, &ev).unwrap(),
            format!("{b} WHERE message LIKE '%x-forwarded-for in (1,2)%'")
        );
    }

    // --- S11 : GUILLEMETER LA VALEUR N'EXEMPTE RIEN (le marqueur porte sur la PARTIE GAUCHE) -----
    #[test]
    fn s11_quoting_the_value_does_not_exempt_the_field_name() {
        // MESURÉ sur 742efe7 : le marqueur de quotation valait pour le JETON ENTIER, donc guillemeter
        // la seule VALEUR exemptait la partie gauche et rouvrait le défaut au prix de deux caractères —
        // `search x-forwarded-for="10.0.0.1"` -> `message LIKE '%x-forwarded-for=10.0.0.1%'`, alors que
        // `search x-forwarded-for = "10.0.0.1"` (un espace de plus, MÊME sens) était refusé.
        // La garde se demande maintenant si la PARTIE GAUCHE vient des guillemets, pas le jeton.
        // Les formes ci-dessous couvrent les 8 opérateurs ET des écritures que le code ne nomme
        // nulle part : guillemet ORPHELIN, guillemets au MILIEU de la valeur ou du nom, tabulation,
        // saut de ligne, apostrophes, valeur vide.
        for (q, field) in [
            ("search x-forwarded-for=\"10.0.0.1\"", "x-forwarded-for"),
            ("search x-forwarded-for = \"10.0.0.1\"", "x-forwarded-for"),
            ("search http.status>=\"500\"", "http.status"),
            ("search src-ip>=\"5\"", "src-ip"),
            ("search src-ip<=\"5\"", "src-ip"),
            ("search src-ip>\"5\"", "src-ip"),
            ("search src-ip<\"5\"", "src-ip"),
            ("search foo-bar:\"1\"", "foo-bar"),
            ("search foo-bar!=\"1\"", "foo-bar"),
            ("search foo-bar=~\"1\"", "foo-bar"),
            ("search foo-bar=a\"b\"", "foo-bar"),   // guillemets au MILIEU de la valeur
            ("search foo-bar=1\"", "foo-bar"),      // guillemet ORPHELIN (jamais fermé)
            ("search \"foo-bar=1", "foo-bar"),      // guillemet OUVRANT jamais fermé
            ("search foo-bar\" = 1", "foo-bar"),    // le guillemet non fermé avale l'espace
            ("search foo\"-\"bar = 1", "foo-bar"),  // guillemets au MILIEU du NOM
            ("search x\"-forwarded-for\"=10.0.0.1", "x-forwarded-for"),
            ("search x-forwarded-for='10.0.0.1'", "x-forwarded-for"), // apostrophes : pas des guillemets
            ("search x-forwarded-for=\"\"", "x-forwarded-for"),       // valeur quotée VIDE
            ("search foo-bar\t=\t1", "foo-bar"),                      // tabulations
            ("search foo-bar\n=\n\"1\"", "foo-bar"),                   // écriture MULTI-LIGNE
            ("search source=web x-forwarded-for=\"1\"", "x-forwarded-for"), // en 2e position
            ("search x-forwarded-for=\"1\" source=web", "x-forwarded-for"), // en 1re position
        ] {
            match to_sql(q, 0, 0, &Schema::events()) {
                Ok(sql) => panic!("attendu une erreur pour « {q} », obtenu du SQL : {sql}"),
                Err(e) => assert!(e.contains(field), "l'erreur doit nommer le champ {field} : {e}"),
            }
        }
        // ET LA MÊME CHOSE EN SOUS-RECHERCHE (depth > 0) : la revue a mesuré le contournement dans un
        // `append [...]` et un `join f [...]`.
        for q in [
            "search source=a | append [search x-forwarded-for=\"1\" | stats count]",
            "search | stats count by m | join m [search x-forwarded-for=\"1\" | stats count by m]",
            "search a | append [search b | append [search http.status>=\"500\" | stats count]]",
        ] {
            let e = to_sql(q, 0, 0, &Schema::events()).expect_err("garde attendue ici aussi");
            assert!(e.contains("champ invalide dans le filtre"), "{e}");
        }
        // TÉMOIN : un filtre NORMAL dont la valeur est quotée reste un filtre indexé (c'est bien la
        // partie gauche, et elle seule, qui décide).
        let b = "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event";
        assert_eq!(
            to_sql("search source=\"web\"", 0, 0, &Schema::events()).unwrap(),
            format!("{b} WHERE \"source\" = 'web'")
        );
    }

    // --- S11 : l'échappatoire du message rend le texte RÉELLEMENT SAISI -------------------------
    #[test]
    fn s11_error_suggestion_is_the_users_own_text() {
        // MESURÉ sur 742efe7 : la suggestion était reconstruite à partir du jeton, donc elle PERDAIT le
        // texte de l'utilisateur — `search -foo in (1,2)` suggérait `"foo in (1,2)"` (tiret de tête
        // perdu) et `search foo-bar = 1` suggérait `"foo-bar=1"` (espaces perdus). Or les deux
        // suggestions rendent un JEU DE LIGNES DIFFÉRENT de celui du texte tapé.
        // La suggestion est désormais une TRANCHE du texte d'entrée (bornes octets du jeton / portée du
        // match `in`), guillemets retirés — donc le texte de l'utilisateur par construction.
        let ev = Schema::events();
        let b = "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event";
        for (q, want_term) in [
            ("search -foo in (1,2)", "-foo in (1,2)"),
            ("search foo-bar = 1", "foo-bar = 1"),
            ("search x-forwarded-for = \"10.0.0.1\"", "x-forwarded-for = 10.0.0.1"),
            ("search cache/status in (200,302)", "cache/status in (200,302)"),
            ("search foo-bar=a\"b\"", "foo-bar=ab"),
            ("search src-ip   >=   5", "src-ip   >=   5"),
        ] {
            let e = to_sql(q, 0, 0, &ev).expect_err("forme refusée attendue");
            let sug = format!("mettez-le entre guillemets : \"{want_term}\"");
            assert!(e.contains(&sug), "la suggestion doit rendre le texte saisi ({sug}) : {e}");
            // ET ELLE MARCHE : rejouer la suggestion rend une recherche plein-texte SUR CE TEXTE-LÀ.
            assert_eq!(
                to_sql(&format!("search \"{want_term}\""), 0, 0, &ev).unwrap(),
                format!("{b} WHERE message LIKE '%{want_term}%'"),
                "l'échappatoire suggérée doit compiler en plein-texte sur le texte suggéré"
            );
        }
        // PORTÉE EXACTE DE CETTE PROMESSE — elle n'est PAS universelle, et ce test le pinne plutôt que
        // de laisser la docstring l'affirmer plus large qu'elle n'est. Sur 400 suggestions tirées d'un
        // corpus adverse, 389 rendent bien un plein-texte ; les 11 autres rendent une ÉGALITÉ, parce
        // que le texte suggéré COMMENCE lui-même par un identifiant valide suivi d'un opérateur. Mesuré
        // identique sur le tag public v0.2.0 (48035b9) : limite PRÉ-EXISTANTE du chemin quoté, pas une
        // conséquence de la garde — et le SQL rendu est celui de v0.2.0 à l'octet près.
        assert_eq!(
            to_sql("search \"b: not in ()\"", 0, 0, &ev).unwrap(),
            format!("{b} WHERE json_extract(fields,'$.b') = ' not in ()'")
        );
        assert_eq!(
            to_sql("search \"source=web  In ()\"", 0, 0, &ev).unwrap(),
            format!("{b} WHERE \"source\" = 'web  In ()'")
        );
    }

    // --- LIMITE DOCUMENTÉE : `eval` n'a pas (et ne peut pas avoir) la garde de nom de champ ------
    #[test]
    fn eval_is_the_documented_blind_spot_of_the_field_name_guard() {
        let ev = Schema::events();
        // CORRECTION D'UNE AFFIRMATION FAUSSE (commit 9fcabd6, « byte for byte ») : les deux SQL ne
        // sont PAS identiques à l'octet, et ce test le MESURE au lieu de normaliser avant de comparer.
        // Ce qui est vrai et suffisant : ils ne diffèrent QUE par des blancs — `-` est l'opérateur de
        // soustraction dans une expression, et SQLite compile les deux en le même programme (mesuré
        // hors test : `EXPLAIN SELECT (foo-bar) FROM t` == `EXPLAIN SELECT (foo - bar) FROM t`,
        // bytecode identique, sqlite 3.53.3). Aucune garde ne peut donc les distinguer, et un nom mal
        // écrit échoue à l'EXÉCUTION (colonnes inexistantes), pas à la compilation.
        let a = to_sql("search | eval x = foo-bar", 0, 0, &ev).unwrap();
        let b = to_sql("search | eval x = foo - bar", 0, 0, &ev).unwrap();
        assert!(a.contains("(foo-bar) AS \"x\""), "{a}");
        assert!(b.contains("(foo - bar) AS \"x\""), "{b}");
        assert_ne!(a, b, "les deux SQL diffèrent bien (l'affirmation « byte for byte » était fausse)");
        assert_eq!(
            a.replace(' ', ""),
            b.replace(' ', ""),
            "et ils ne diffèrent QUE par des blancs — c'est CE point qui rend les deux lectures indiscernables"
        );
        // ET LA CONTREPARTIE : la limite est bien CIRCONSCRITE à `eval`. Les autres étapes qui prennent
        // un nom de champ le valident, elles.
        for q in [
            "search foo-bar=1",
            "search | where foo-bar > 1",
            "search | stats count by foo-bar",
            "search | table foo-bar",
            "search | fields foo-bar",
            "search | sort foo-bar",
            "search | dedup foo-bar",
            "search | top foo-bar",
            "search | rename foo-bar as x",
            "search | mvexpand foo-bar",
            "search | eventstats count by foo-bar",
            "search | timechart count by foo-bar",
            "metric node_load1 by foo-bar",
        ] {
            to_sql(q, 0, 0, &ev).expect_err(&format!("« {q} » doit refuser le nom de champ"));
        }
        // L'arithmétique LÉGITIME d'`eval` reste évidemment intacte (c'est elle qui interdit la garde).
        let c = to_sql("search | eval risk = severity * 2 | table risk", 0, 0, &ev).unwrap();
        assert!(c.contains("(severity * 2) AS \"risk\""), "{c}");
    }

    // --- NON-RÉGRESSION SUR ENTRÉE LÉGITIME RÉELLE ---------------------------------------------
    // Les goldens ci-dessous ne sont PAS choisis pour passer : ce sont des requêtes d'analyste
    // ordinaires (valeur quotée, en-tête HTTP quoté, texte libre à tirets, horodatage, `in` légitime,
    // `where`, `metric ... by`), et leur SQL a été RELEVÉ PAR SONDE sur le tag public v0.2.0 (48035b9),
    // AVANT tout correctif de ce lot. Toute la valeur du test est là : ces formes touchent exactement
    // les mécanismes que les gardes modifient (guillemets, tirets, `in (`), et doivent rendre le MÊME
    // SQL À L'OCTET PRÈS. Le banc `tests/plume_parity.rs` couvre les 99 requêtes livrées ; ceci couvre
    // en plus les écritures que le corpus livré ne contient pas.
    #[test]
    fn legitimate_analyst_queries_still_emit_the_v0_2_0_sql() {
        let ev = Schema::events();
        for (q, want) in [
            (r#"search source=sshd user="root" | stats count by src_ip"#, r#"SELECT "src_ip" AS "src_ip",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "source" = 'sshd' AND json_extract(fields,'$.user') = 'root') GROUP BY "src_ip""#),
            (r#"search source="web" severity=3"#, r#"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "source" = 'web' AND "severity" = 3"#),
            (r#"search source=nginx status=404 | timechart count"#, r#"SELECT (ts/900)*900 AS bucket,COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "source" = 'nginx' AND CAST(json_extract(fields,'$.status') AS REAL) = 404) GROUP BY bucket ORDER BY bucket"#),
            (r#"search "Accept-Encoding: gzip""#, r#"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%Accept-Encoding: gzip%'"#),
            (r#"search "POST /login HTTP/1.1""#, r#"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%POST /login HTTP/1.1%'"#),
            (r#"search category=malware "attachment.exe""#, r#"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "category" = 'malware' AND message LIKE '%attachment.exe%'"#),
            (r#"search source=auditd "type=SYSCALL""#, r#"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "source" = 'auditd' AND json_extract(fields,'$.type') = 'SYSCALL'"#),
            (r#"search rate-limit exceeded"#, r#"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%rate-limit%' AND message LIKE '%exceeded%'"#),
            (r#"search message="user in (a,b)""#, r#"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "message" = 'user in (a,b)'"#),
            (r#"search url="/path?x in (1,2)""#, r#"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "url" = '/path?x in (1,2)'"#),
            (r#"search source in ("web","cloudflare")"#, r#"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "source" COLLATE NOCASE IN ('web','cloudflare')"#),
            (r#"search source=web dport in (80,443,8080) | stats count by src_ip"#, r#"SELECT "src_ip" AS "src_ip",COUNT(*) AS "count" FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE CAST(json_extract(fields,'$.dport') AS REAL) IN (80,443,8080) AND "source" = 'web') GROUP BY "src_ip""#),
            (r#"search source=svc-audit | where error!="" | sort -ts | table user,operation,path,error"#, r#"SELECT json_extract(fields,'$.user') AS "user",json_extract(fields,'$.operation') AS "operation",json_extract(fields,'$.path') AS "path",json_extract(fields,'$.error') AS "error" FROM (SELECT * FROM (SELECT * FROM (SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE "source" = 'svc-audit') WHERE json_extract(fields,'$.error') <> '') ORDER BY "ts" DESC)"#),
            (r#"search 2026-07-25T10:00:00"#, r#"SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event WHERE message LIKE '%2026-07-25T10:00:00%'"#),
            (r#"metric node_load1 by code,job"#, r#"SELECT ts,host,value,json_extract(labels,'$.code') AS "code",json_extract(labels,'$.job') AS "job" FROM metric WHERE name='node_load1' UNION ALL SELECT ts,host,avg AS value,json_extract(labels,'$.code') AS "code",json_extract(labels,'$.job') AS "job" FROM metric_rollup WHERE name='node_load1' ORDER BY ts"#),
        ] {
            assert_eq!(to_sql(q, 0, 0, &ev).unwrap(), want, "SQL modifié pour une requête légitime : {q}");
        }
    }

    #[test]
    fn s11_glue_of_legitimate_spaced_filters_is_unchanged() {
        // CONTRE-PREUVE du recollage élargi : les formes espacées LÉGITIMES (corpus, « Opérateurs SQL
        // espacés (glue) ») rendent le MÊME SQL qu'avant, goldens littéraux.
        let ev = Schema::events();
        let b = "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event";
        assert_eq!(to_sql("search source = web", 0, 0, &ev).unwrap(), format!("{b} WHERE \"source\" = 'web'"));
        assert_eq!(
            to_sql("search source = \"web\"", 0, 0, &ev).unwrap(),
            format!("{b} WHERE \"source\" = 'web'")
        );
        assert_eq!(
            to_sql("search severity >= 3 | stats count", 0, 0, &ev).unwrap(),
            format!("SELECT COUNT(*) AS \"count\" FROM ({b} WHERE \"severity\" >= 3)")
        );
        // Un terme libre SANS opérateur reste intact, quoté ou non (aucun recollage).
        assert_eq!(to_sql("search x-forwarded-for", 0, 0, &ev).unwrap(), format!("{b} WHERE message LIKE '%x-forwarded-for%'"));
        assert_eq!(
            to_sql("search rate-limit exceeded", 0, 0, &ev).unwrap(),
            format!("{b} WHERE message LIKE '%rate-limit%' AND message LIKE '%exceeded%'")
        );
    }

    // --- S2 (suite) : le contrôle de taille couvre AUSSI une requête à une seule étape ----------
    #[test]
    fn s2_single_stage_query_is_bounded_too() {
        // MESURÉ sur 4b16822 : `if sql.len() > max_sql` vivait DANS `for stage in &stages[1..]`, donc
        // une requête à UNE SEULE étape — la forme la plus courante — n'était JAMAIS vérifiée :
        //   `search a a a …` x 200 000 = 400 006 octets de texte -> 4 600 089 octets de SQL, 0 erreur.
        let q = format!("search{}", " a".repeat(200_000));
        let e = to_sql(&q, 0, 0, &Schema::events())
            .expect_err("une requête à UNE étape doit être bornée elle aussi");
        assert!(e.contains("trop complexe"), "erreur de taille attendue : {e}");
    }

    #[test]
    fn s2_query_text_is_bounded() {
        // MESURÉ sur 4b16822 : rien ne bornait la LONGUEUR DU TEXTE d'entrée. Le SQL émis est vérifié
        // APRÈS chaque étape, donc le pic transitoire d'UNE étape n'est borné que par le texte.
        let q = format!("search {}", "a".repeat(1_100_000));
        let e = to_sql(&q, 0, 0, &Schema::events()).expect_err("le texte de requête doit être borné");
        assert!(e.contains("trop long"), "erreur de longueur de texte attendue : {e}");
    }

    #[test]
    fn s2_bounds_leave_realistic_queries_alone() {
        // ANTI-RÉGRESSION : 5 requêtes d'analyste réalistes (corpus livré) rendent le SQL ATTENDU, et
        // une requête volumineuse mais PLAUSIBLE (liste `in` de 2 000 valeurs, ~24 Ko de texte) compile.
        let ev = Schema::events();
        for q in [
            "search source=web scope=external | stats count by src_ip | sort -count | head 20",
            "search source=cloudflare | stats values(user) by src_ip",
            "search source=web | eventstats count by src_ip | where count > 10 | stats count",
            "search source=conntrack dir=outbound scope=external | sort -ts | table dst_host,dst_ip,proc,dport",
            "search | timechart span=1h count",
        ] {
            to_sql(q, 0, 0, &ev).unwrap_or_else(|e| panic!("doit compiler ({q}) : {e}"));
        }
        let vals: Vec<String> = (0..2000).map(|i| format!("10.0.{}.{}", i / 256, i % 256)).collect();
        let big = format!("search src_ip in ({})", vals.join(","));
        assert!(big.len() > 20_000, "la liste doit être volumineuse : {} octets", big.len());
        to_sql(&big, 0, 0, &ev).unwrap_or_else(|e| panic!("une liste `in` de 2000 IP doit compiler : {e}"));
    }

    // --- S10 (suite) : un jeton `metric` non reconnu ne s'évapore plus en fin de boucle ---------
    #[test]
    fn s10_metric_unrecognised_token_is_error() {
        // MESURÉ sur 4b16822 : seule la branche `split_once('=')` avait été passée en fail-closed. Un
        // jeton qui ne matche NI `by`, NI `value<op>N`, NI `k=v` tombait en fin de boucle sans `else` :
        //   metric node_load1 garbage  -> SELECT ts,host,value FROM metric WHERE name='node_load1' …
        //   metric node_load1 job:api  -> idem
        // soit TOUTES les séries de la métrique au lieu du sous-ensemble demandé — mot pour mot le mode
        // d'échec que S10 déclarait fermé.
        for (q, tok) in [
            ("metric node_load1 garbage", "garbage"),
            ("metric node_load1 job:api", "job:api"),
            ("metric node_load1 value~3", "value~3"),
        ] {
            match to_sql(q, 0, 0, &Schema::events()) {
                Ok(sql) => panic!("attendu une erreur pour « {q} », obtenu du SQL : {sql}"),
                Err(e) => assert!(e.contains(tok), "l'erreur doit nommer le jeton {tok} : {e}"),
            }
        }
    }

    // --- S10 (suite) : UNE SEULE PORTE DÉCIDE D'UNE LISTE `by`, POUR LES QUATRE ÉTAPES ----------
    #[test]
    fn a_by_list_is_decided_in_one_place_for_all_four_stages() {
        // DÉFAUT MESURÉ sur 6fff644 ET sur le tag public 48035b9 (donc pré-existant) : le
        // `.filter(|s| !s.is_empty())` avait été retiré de `metric_base` seulement. Les TROIS autres
        // étapes à `by` passent par `by_fields`, qui le portait encore ligne pour ligne :
        //   search | stats count by        -> SELECT ,COUNT(*) … GROUP BY        (SQL INVALIDE émis)
        //   search | stats count by ,      -> idem
        //   search | timechart span=1h count by ,  -> le `by` demandé S'ÉVAPORE, sans un mot
        //   search | stats count by ,src_ip        -> label vide jeté en silence
        //   search | eventstats count by ,src_ip   -> idem
        // Les quatre étapes passent maintenant par `ByLabels::parse`, et c'est LUI qui décide.
        // Les échecs sont ACCUMULÉS, pas levés au premier : une mutation de la porte doit se voir
        // NOMMER LES QUATRE ÉTAPES dans la sortie d'échec, pas seulement la première rencontrée.
        let ev = Schema::events();
        let mut leaks: Vec<String> = Vec::new();
        for (stage, tpl, label, want_msg) in [
            ("stats", "search | stats count {}", "src_ip", "champ invalide"),
            ("timechart", "search | timechart span=1h count {}", "src_ip", "champ invalide"),
            ("eventstats", "search | eventstats count {}", "src_ip", "champ invalide"),
            ("eventstats(values)", "search | eventstats values(user) {}", "src_ip", "champ invalide"),
            ("metric", "metric node_load1 {}", "code", "label invalide dans `by`"),
        ] {
            for shape in ["by", "by ,", "by ,,", "by ,{L}", "by {L},", "by {L},,host"] {
                let q = tpl.replace("{}", &shape.replace("{L}", label));
                match to_sql(&q, 0, 0, &ev) {
                    Ok(sql) => leaks.push(format!("[{stage}] « {q} » a compilé au lieu d'être refusé : {sql}")),
                    Err(e) => {
                        if !e.contains(want_msg) {
                            leaks.push(format!("[{stage}] « {q} » : message inattendu : {e}"));
                        }
                    }
                }
            }
        }
        assert!(leaks.is_empty(), "un `by` demandé s'est évaporé :\n{}", leaks.join("\n"));
        // CONTRE-PREUVE — les `by` LÉGITIMES des quatre étapes rendent le SQL du tag public v0.2.0,
        // goldens littéraux (relevés par sonde sur 48035b9 et sur 6fff644 : identiques).
        let b = "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event";
        for (q, want) in [
            ("search | stats count by src_ip", format!("SELECT \"src_ip\" AS \"src_ip\",COUNT(*) AS \"count\" FROM ({b}) GROUP BY \"src_ip\"")),
            ("search | stats count by src_ip,host", format!("SELECT \"src_ip\" AS \"src_ip\",\"host\" AS \"host\",COUNT(*) AS \"count\" FROM ({b}) GROUP BY \"src_ip\",\"host\"")),
            ("search | timechart span=1h count by source", format!("SELECT (ts/3600)*3600 AS bucket,\"source\" AS \"source\",COUNT(*) AS \"count\" FROM ({b}) GROUP BY bucket,\"source\" ORDER BY bucket")),
            ("search | eventstats count by host", format!("SELECT *, COUNT(*) OVER (PARTITION BY \"host\") AS \"count\" FROM ({b})")),
            ("metric node_load1 by code", "SELECT ts,host,value,json_extract(labels,'$.code') AS \"code\" FROM metric WHERE name='node_load1' UNION ALL SELECT ts,host,avg AS value,json_extract(labels,'$.code') AS \"code\" FROM metric_rollup WHERE name='node_load1' ORDER BY ts".to_string()),
        ] {
            assert_eq!(to_sql(q, 0, 0, &ev).unwrap(), want, "`by` légitime réécrit : {q}");
        }
        // Un `by` sans virgule mais mal séparé reste refusé par la MÊME porte, sur les quatre étapes.
        for q in [
            "search | stats count by src_ip host",
            "search | timechart span=1h count by src_ip host",
            "search | eventstats count by src_ip host",
            "metric node_load1 by code job",
        ] {
            to_sql(q, 0, 0, &ev).expect_err(&format!("« {q} » : `by` se sépare par des virgules"));
        }
    }

    #[test]
    fn a_comma_list_of_field_names_never_drops_an_entry_whatever_the_step() {
        // LE MÊME DÉFAUT, DANS LES ÉTAPES QUE `by` NE COUVRE PAS — c'est-à-dire l'élément suivant de
        // la liste, trouvé et fermé ici plutôt que laissé au relecteur. Le `.filter(|s| !s.is_empty())`
        // vivait aussi dans `compile_fields` et `compile_dedup`. MESURÉ avant ce correctif (et sur le
        // tag public 48035b9, donc pré-existant) :
        //   search | fields          -> SELECT  FROM (…)     <- SQL SYNTAXIQUEMENT INVALIDE émis
        //   search | fields ,        -> idem
        //   search | fields ,src_ip  -> entrée vide jetée sans un mot
        //   search | dedup ,src_ip   -> idem
        //   search | table ,         -> l'étape s'évapore (base rendue inchangée)
        // Les listes séparées par des VIRGULES SEULES passent toutes par `FieldList::commas` ; `table`,
        // dont la grammaire admet aussi le BLANC, par `FieldList::commas_or_blanks`.
        let ev = Schema::events();
        let mut leaks: Vec<String> = Vec::new();
        for (stage, tpl) in [
            ("fields", "search | fields {}"),
            ("dedup", "search | dedup {}"),
        ] {
            for shape in ["", ",", ",,", ",src_ip", "src_ip,", "src_ip,,host"] {
                let q = tpl.replace("{}", shape);
                if let Ok(sql) = to_sql(&q, 0, 0, &ev) {
                    leaks.push(format!("[{stage}] « {q} » a compilé : {sql}"));
                }
            }
        }
        // `table` : une liste qui ne contient QUE des séparateurs ne peut plus s'évaporer.
        for shape in [",", ",,", ", ,"] {
            let q = format!("search | table {shape}");
            if let Ok(sql) = to_sql(&q, 0, 0, &ev) {
                leaks.push(format!("[table] « {q} » a compilé : {sql}"));
            }
        }
        assert!(leaks.is_empty(), "une entrée demandée s'est évaporée :\n{}", leaks.join("\n"));

        // CONTRE-PREUVE — les formes légitimes rendent le SQL du tag public v0.2.0, goldens littéraux
        // (probe sur 48035b9 vs cet arbre : 0 ligne de différence sur 160 requêtes réelles).
        let b = "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event";
        for (q, want) in [
            ("search | fields src_ip", format!("SELECT \"src_ip\" AS \"src_ip\" FROM ({b})")),
            ("search | fields src_ip, host", format!("SELECT \"src_ip\" AS \"src_ip\",\"host\" AS \"host\" FROM ({b})")),
            ("search | dedup src_ip", format!("SELECT * FROM ({b}) GROUP BY \"src_ip\"")),
            ("search | dedup src_ip, host", format!("SELECT * FROM ({b}) GROUP BY \"src_ip\",\"host\"")),
            ("search | table src_ip,host", format!("SELECT \"src_ip\" AS \"src_ip\",\"host\" AS \"host\" FROM ({b})")),
            // `table` accepte le BLANC comme séparateur — c'est ce qui force la réduction des suites.
            ("search | table src_ip host", format!("SELECT \"src_ip\" AS \"src_ip\",\"host\" AS \"host\" FROM ({b})")),
            ("search | table src_ip, host", format!("SELECT \"src_ip\" AS \"src_ip\",\"host\" AS \"host\" FROM ({b})")),
        ] {
            assert_eq!(to_sql(q, 0, 0, &ev).unwrap(), want, "liste légitime réécrite : {q}");
        }
        // LIMITE ASSUMÉE ET MESURÉE, écrite ici plutôt que laissée à découvrir : dans `table`, une
        // suite de séparateurs est INDISCERNABLE d'un seul (`a, b` / `a,b` / `a  b` sont la même
        // écriture), donc `table a,,b` rend `a` et `b`. Dans les listes à virgules SEULES, la même
        // écriture est refusée — parce que là, elle est discernable.
        assert_eq!(
            to_sql("search | table src_ip,,host", 0, 0, &ev).unwrap(),
            format!("SELECT \"src_ip\" AS \"src_ip\",\"host\" AS \"host\" FROM ({b})")
        );
        to_sql("search | fields src_ip,,host", 0, 0, &ev).expect_err("virgules seules : entrée vide refusée");
        // Et les deux passe-plat DÉLIBÉRÉS de `table` restent intacts (contrat existant).
        for q in ["search | table *", "search | table"] {
            assert_eq!(to_sql(q, 0, 0, &ev).unwrap(), b, "passe-plat cassé : {q}");
        }
    }

    // =========================================================================================
    // LA PORTE DES LISTES — LES CAS SONT ENGENDRÉS DEPUIS LA STRUCTURE, PAS ÉNUMÉRÉS.
    //
    // POURQUOI CE TEST EXISTE : la garde précédente fermait les étapes qu'on avait PENSÉ à citer, et
    // le relecteur trouvait l'étape SUIVANTE. Elle existait déjà dans l'arbre : `lookup … OUTPUT`
    // prend une liste de noms de champs séparée par des virgules et ne passait pas par la porte —
    // `OUTPUT` nu et `OUTPUT ,` retombaient sur la branche « OUTPUT absent » et la projection
    // DEMANDÉE s'évaporait sans un mot.
    //
    // CE TEST NE NOMME AUCUNE ÉTAPE ET AUCUN MOT-CLÉ. Il LIT le dispatcheur (`soql/mod.rs`) et les
    // compilateurs (`soql/stages.rs`), en DÉRIVE les positions de liste, et vérifie sur chacune
    // qu'une liste TAPÉE ne peut pas s'évaporer. Une 21e étape ajoutée demain entre dans le test
    // sans qu'une ligne d'ici ne bouge.
    // =========================================================================================

    /// Le corps d'une fonction : de sa signature à la signature suivante de même niveau.
    fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
        let Some(p) = src.find(&format!("fn {name}(")) else { return "" };
        let rest = &src[p..];
        match rest[1..]
            .find("\npub(crate) fn ")
            .or_else(|| rest[1..].find("\nfn "))
            .map(|k| k + 1)
        {
            Some(e) => &rest[..e],
            None => rest,
        }
    }

    /// TOUTES les sources du sous-module `soql`, VÉRIFIÉES exhaustives contre les `mod …;` déclarés
    /// par `soql/mod.rs` : un sous-module ajouté sans être relu ici fait échouer les gardes au lieu
    /// de créer un angle mort. C'est la MÊME liste pour les DEUX gardes engendrées — l'asymétrie qui
    /// laissait la garde d'EFFET ne lire QUE `stages.rs` (donc rater un compilateur vivant dans
    /// `mod.rs`) est fermée en la faisant lire d'ici.
    fn soql_sources() -> Vec<(&'static str, &'static str)> {
        // `include_str!` exige un chemin LITTÉRAL : la liste ne peut pas être calculée, elle est donc
        // vérifiée juste après contre les `mod …;` déclarés.
        let files: Vec<(&str, &str)> = vec![
            ("mod.rs", include_str!("soql/mod.rs")),
            ("helpers.rs", include_str!("soql/helpers.rs")),
            ("stages.rs", include_str!("soql/stages.rs")),
            ("knowledge.rs", include_str!("soql/knowledge.rs")),
            ("dialect.rs", include_str!("soql/dialect.rs")),
            ("mask.rs", include_str!("soql/mask.rs")),
        ];
        let declared: Vec<String> = files[0]
            .1
            .lines()
            .filter_map(|l| l.trim().strip_prefix("mod ").and_then(|r| r.strip_suffix(';')))
            .filter(|m| *m != "tests")
            .map(|m| format!("{m}.rs"))
            .collect();
        let unread: Vec<&String> = declared.iter().filter(|m| !files.iter().any(|(f, _)| f == m)).collect();
        assert!(unread.is_empty(), "sous-module déclaré mais non relu par les gardes : {unread:?}");
        files
    }

    /// Les littéraux d'une portion de source, dans l'ordre.
    fn string_literals(seg: &str) -> Vec<&str> {
        let (mut out, mut i) = (Vec::new(), 0usize);
        while let Some(q) = seg[i..].find('"') {
            let a = i + q + 1;
            let Some(e) = seg[a..].find('"') else { break };
            out.push(&seg[a..a + e]);
            i = a + e + 1;
        }
        out
    }

    /// LES ÉTAPES, LUES DANS LE DISPATCHEUR : tout bras `"nom" [| "autre"] => compile_X(`.
    fn dispatcher_steps(modsrc: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for line in modsrc.lines() {
            let t = line.trim();
            let Some(a) = t.find("=> compile_") else { continue };
            let f: String = t[a + 3..].chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            for name in string_literals(&t[..a]) {
                out.push((name.to_string(), f.clone()));
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// LES MOTS-CLÉS D'UNE ÉTAPE, LUS DANS SON PROPRE COMPILATEUR : un mot-clé est un littéral que
    /// l'étape cherche PARMI SES JETONS (`toks.iter().position(|w| … "kw" …)`). C'est ce qui
    /// distingue `stats … by` (où `by` est un mot-clé) de `table a by b` (où `by` est un nom).
    fn keywords_of(body: &str) -> Vec<String> {
        let (mut out, mut i) = (Vec::new(), 0usize);
        while let Some(p) = body[i..].find("position(|w|") {
            let s = i + p;
            let seg = &body[s..];
            let seg = &seg[..seg.find(')').unwrap_or(seg.len())];
            for w in string_literals(seg) {
                if !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()) {
                    out.push(w.to_string());
                }
            }
            i = s + 12;
        }
        out.sort();
        out.dedup();
        out
    }

    /// Les préfixes d'argument engendrés : tous les mots de longueur <= 2 sur un alphabet de
    /// remplisseurs (un nom, un agrégat, un nombre) — de quoi rendre une étape par ailleurs VALIDE
    /// sans savoir laquelle.
    fn arg_prefixes() -> Vec<String> {
        let alpha = ["a", "count", "1"];
        let mut v = vec![String::new()];
        for x in alpha {
            v.push(x.to_string());
            for y in alpha {
                v.push(format!("{x} {y}"));
            }
        }
        v
    }

    /// Tous les mots NON VIDES de longueur <= 3 sur l'alphabet des SÉPARATEURS : une liste écrite
    /// avec ça ne contient AUCUN nom.
    fn separator_only_lists() -> Vec<String> {
        let alpha = [",", " "];
        let mut v = Vec::new();
        for a in alpha {
            v.push(a.to_string());
            for b in alpha {
                v.push(format!("{a}{b}"));
                for c in alpha {
                    v.push(format!("{a}{b}{c}"));
                }
            }
        }
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn no_typed_field_list_can_evaporate_whatever_the_step() {
        // L'ORACLE, DÉRIVÉ ET NON ÉCRIT : une position d'argument est une LISTE DE NOMS DE CHAMPS
        // si et seulement si CHANGER LES NOMS CHANGE LE SQL. On n'a donc pas à savoir quelles étapes
        // en prennent une — on le MESURE, étape par étape, sur des formes engendrées.
        //
        // Sur toute position ainsi trouvée, la règle vérifiée est :
        //  - MOT-CLÉ TAPÉ (`… by X`, `… OUTPUT X`) : la demande est EXPLICITE. Une liste sans aucun
        //    nom — y compris « rien du tout après le mot-clé » — doit être REFUSÉE. Aucune exception
        //    de grammaire : l'utilisateur a écrit le mot-clé.
        //  - LISTE = TOUT L'ARGUMENT (`fields X`, `table X`) : idem, MAIS si le BLANC est séparateur
        //    pour cette étape (mesuré : `S a b` == `S a,b`), alors un argument entièrement BLANC est
        //    indiscernable d'un argument ABSENT — l'étape nue est un contrat à part (`table` nu est
        //    un passe-plat délibéré). On n'exige donc le refus que des formes portant une VIRGULE.
        let modsrc = include_str!("soql/mod.rs");
        // LES MOTS-CLÉS SONT LUS DANS TOUTES LES SOURCES, PAS SEULEMENT `stages.rs` : un compilateur
        // d'étape peut vivre dans `mod.rs` (`by_fields`, `metric_base`, et n'importe quelle étape
        // future). `fn_body` sur cette concaténation le trouve où qu'il soit ; l'assertion plus bas
        // exige qu'il SOIT trouvé, au lieu de rendre une chaîne vide en silence.
        let allsrc: String = soql_sources().iter().map(|(_, s)| *s).collect::<Vec<_>>().join("\n");
        let steps = dispatcher_steps(modsrc);
        assert!(steps.len() >= 18, "le dispatcheur n'a pas été lu : {steps:?}");

        // Tous les schémas/dialectes livrés : la porte ne peut pas dépendre de la cible.
        let schemas: Vec<(&str, Schema)> = vec![
            ("events", Schema::events()),
            ("events_duckdb", Schema::events_duckdb()),
            ("events_clickhouse", Schema::events_clickhouse()),
            #[cfg(feature = "forge")]
            ("forge", Schema::forge()),
        ];
        let seps = separator_only_lists();
        let (mut positions, mut cases) = (0usize, 0usize);
        let mut leaks: Vec<String> = Vec::new();

        for (sname, sch) in &schemas {
            let base = if *sname == "forge" { "runs" } else { "search" };
            let sql_of = |q: &str| to_sql(q, 0, 0, sch).ok();
            for (step, f) in &steps {
                let body = fn_body(&allsrc, f);
                assert!(
                    !body.is_empty(),
                    "compilateur `{f}` (étape `{step}`) introuvable dans les sources relues : la garde \
                     d'effet ne peut pas lire ses mots-clés — angle mort de FICHIER, pas de forme"
                );
                let kws = keywords_of(body);

                // (1) LA LISTE EST TOUT L'ARGUMENT — le préfixe est forcément vide.
                if let (Some(x), Some(y)) = (
                    sql_of(&format!("{base} | {step} a,b")),
                    sql_of(&format!("{base} | {step} c,d")),
                ) {
                    if x != y {
                        let blank_sep = sql_of(&format!("{base} | {step} a b")).as_deref() == Some(x.as_str());
                        positions += 1;
                        let mut probes: Vec<String> = seps
                            .iter()
                            .filter(|a| !blank_sep || a.contains(','))
                            .map(|a| format!("{base} | {step} {a}"))
                            .collect();
                        if !blank_sep {
                            probes.push(format!("{base} | {step}"));
                        }
                        for q in probes {
                            cases += 1;
                            if let Some(sql) = sql_of(&q) {
                                leaks.push(format!("[{sname}/{step}/<arg>] « {q} » a compilé : {sql}"));
                            }
                        }
                    }
                }

                // (2) UN MOT-CLÉ A ÉTÉ TAPÉ — la demande est explicite, aucune exception.
                for k in &kws {
                    for p in arg_prefixes() {
                        let (Some(x), Some(y)) = (
                            sql_of(&format!("{base} | {step} {p} {k} a,b")),
                            sql_of(&format!("{base} | {step} {p} {k} c,d")),
                        ) else {
                            continue;
                        };
                        if x == y {
                            continue;
                        }
                        positions += 1;
                        let mut probes: Vec<String> =
                            seps.iter().map(|z| format!("{base} | {step} {p} {k} {z}")).collect();
                        probes.push(format!("{base} | {step} {p} {k}"));
                        for q in probes {
                            cases += 1;
                            if let Some(sql) = sql_of(&q) {
                                leaks.push(format!("[{sname}/{step}/{k}] « {q} » a compilé : {sql}"));
                            }
                        }
                    }
                }
            }
        }
        assert!(
            leaks.is_empty(),
            "une liste demandée s'est évaporée ({} sur {cases} cas) :\n{}",
            leaks.len(),
            leaks.join("\n")
        );
        // UN TEST QUI NE TROUVE AUCUNE POSITION PASSERAIT À VIDE. Le plancher est posé sur la valeur
        // MESURÉE, pas au tiers : la couverture par schéma est CONSTANTE (chaque schéma expose les
        // mêmes positions de liste), donc `positions == <par-schéma> × nb_schémas`. Réglé sur la vraie
        // mesure : 28 positions PAR schéma, soit 84 sur les 3 schémas par défaut, 112 avec
        // `--features forge` (4 schémas).
        //
        // Deux mutations que ce réglage attrape et que `>= 28` laissait passer :
        //  - mutS (retirer 2 des 3 schémas de la liste ci-dessus) : `schemas.len()` tombe à 1 -> échec.
        //  - mutK (casser la détection de mots-clés) : les positions à mot-clé s'évaporent -> échec.
        assert!(
            schemas.len() >= 3,
            "couverture de schémas réduite à {} : la dérivation doit tourner sur tous les schémas livrés",
            schemas.len()
        );
        const PER_SCHEMA: usize = 28;
        assert_eq!(
            positions,
            PER_SCHEMA * schemas.len(),
            "positions de liste : mesurées {positions}, attendues {} ({PER_SCHEMA} par schéma × {} \
             schémas). Une étape à liste ajoutée/retirée, ou la dérivation cassée : mettre à jour \
             PER_SCHEMA avec la valeur mesurée (et le README).",
            PER_SCHEMA * schemas.len(),
            schemas.len()
        );
    }

    #[test]
    fn no_user_written_name_reaches_the_sql_raw_whatever_the_step() {
        // LA MOITIÉ SCALAIRE DE LA DÉRIVATION — le pendant de la porte des LISTES, pour le nom de champ
        // SEUL, et pour la classe INJECTION. Elle remplace une énumération à la main du README (qui
        // oubliait `rex` et `join`) par une propriété MESURÉE, sans nommer aucune étape.
        //
        // L'ORACLE, DÉRIVÉ : un nom de champ écrit par l'utilisateur qui atteint le SQL doit être SOIT
        // refusé — un identifiant valide (`soql_ident_ok`) ne contient PAS de guillemet simple —, SOIT
        // ressortir échappé — une valeur légitime a son `'` doublé. Donc un jeton portant un `'` ne doit
        // JAMAIS apparaître SOUS SA FORME BRUTE dans le SQL émis. S'il y est, un nom a fui sans
        // validation (`json_extract(fields,'$.a'b')` : le `'` casse le littéral, du SQL invalide part au
        // store) ou une valeur est sortie non échappée. La forme échappée `zq''qz` NE contient PAS la
        // forme brute `zq'qz` — le test ne se déclenche donc que sur une vraie fuite.
        //
        // MESURÉ sur l'arbre : AUCUNE étape ne fuit. `eval` lui-même refuse le `'` non terminé
        // (« chaîne non terminée »), `search foo=a'b` émet `'a''b'`, `rex`/`sort`/`join`/… refusent le
        // nom invalide. C'est donc une propriété vérifiée, pas une liste espérée.
        const NEEDLE: &str = "zq'qz";
        let modsrc = include_str!("soql/mod.rs");
        let allsrc: String = soql_sources().iter().map(|(_, s)| *s).collect::<Vec<_>>().join("\n");
        let steps = dispatcher_steps(modsrc);
        let schemas: Vec<(&str, Schema)> = vec![
            ("events", Schema::events()),
            ("events_duckdb", Schema::events_duckdb()),
            ("events_clickhouse", Schema::events_clickhouse()),
            #[cfg(feature = "forge")]
            ("forge", Schema::forge()),
        ];
        let (mut probed, mut leaks) = (0usize, Vec::<String>::new());
        for (sname, sch) in &schemas {
            let base = if *sname == "forge" { "runs" } else { "search" };
            let sql_of = |q: &str| to_sql(q, 0, 0, sch).ok();
            for (step, f) in &steps {
                // Un nom de champ apparaît en position d'ARGUMENT NU, de LISTE, d'alias, d'expression,
                // et derrière chaque mot-clé de l'étape. On couvre les cinq, plus les mots-clés lus dans
                // le compilateur (où qu'il vive) — la même dérivation que la porte des listes.
                let mut forms: Vec<String> = vec![
                    format!("{base} | {step} {NEEDLE}"),
                    format!("{base} | {step} {NEEDLE},{NEEDLE}"),
                    format!("{base} | {step} {NEEDLE} AS y"),
                    format!("{base} | {step} x = {NEEDLE}"),
                    format!("{base} | {step} {NEEDLE} \"(?<u>x)\""),
                ];
                for k in keywords_of(fn_body(&allsrc, f)) {
                    for p in arg_prefixes() {
                        forms.push(format!("{base} | {step} {p} {k} {NEEDLE}"));
                        forms.push(format!("{base} | {step} {p} {k} {NEEDLE},{NEEDLE}"));
                    }
                }
                for q in forms {
                    probed += 1;
                    if let Some(sql) = sql_of(&q) {
                        if sql.contains(NEEDLE) {
                            leaks.push(format!("[{sname}/{step}] « {q} » -> {sql}"));
                        }
                    }
                }
            }
        }
        assert!(
            leaks.is_empty(),
            "un nom écrit par l'utilisateur est ressorti BRUT dans le SQL — nom non validé ou valeur \
             non échappée ({} cas) :\n{}",
            leaks.len(),
            leaks.join("\n")
        );
        assert!(probed > 200, "trop peu de formes sondées ({probed}) : la dérivation ne voit plus les étapes");
    }

    #[test]
    fn every_comma_split_of_the_compiler_is_the_door_or_a_written_exception() {
        // L'AUTRE MOITIÉ DE LA DÉRIVATION. Le test ci-dessus prouve qu'aucune position de liste
        // CONNUE DU DISPATCHEUR ne laisse s'évaporer une liste ; celui-ci ferme la façon dont la
        // 8e étape avait échappé à la porte : elle DÉCOUPAIT LA CHAÎNE ELLE-MÊME. Le type ne peut
        // pas l'interdire (rien n'oblige une étape à demander une `FieldList`), alors on le lit
        // DANS LA SOURCE : tout découpage sur la virgule est soit la porte, soit une exception
        // ÉCRITE ICI AVEC SA RAISON. Un 6e site apparaît -> ce test échoue, et le contributeur lit
        // quoi faire. Aucune étape n'est nommée : c'est la FORME du défaut qui est interdite.
        //
        // PORTÉE EXACTE, MESURÉE, NON UNIVERSELLE. Le détecteur clé sur le SÉPARATEUR VIRGULE, pas sur
        // le nom de la méthode : il repère une ligne qui contient à la fois `split` (la famille entière
        // — `split`, `splitn`, `split_once`, `split_terminator`, `split_inclusive`, `rsplit`…) ET un
        // littéral virgule (`','` ou `","`). C'est le DÉNOMINATEUR COMMUN de tout découpage sur la
        // virgule, pas une liste d'idiomes tenue à jour à la main. Reste HORS de portée, et c'est écrit :
        //  - une virgule cachée derrière une constante nommée DÉCLARÉE SUR UNE AUTRE LIGNE (`const C:
        //    char = ','` ailleurs, puis `s.split(C)`) ou un cast numérique (`s.split(0x2C as char)`) —
        //    aucun littéral virgule sur la ligne du split (MESURÉ : la même déclaration écrite SUR la
        //    ligne du split, elle, est bien vue — c'est la ligne, pas la portée, qui est lue) ;
        //  - un découpage étalé sur plusieurs lignes (lecture ligne à ligne).
        // Ces évasions sont des obfuscations qu'un contributeur n'écrit pas par accident. LA GARANTIE
        // pour les étapes du dispatcheur reste la garde d'EFFET (`no_typed_field_list…`) : elle constate
        // le résultat quelle que soit l'écriture, sur toutes les étapes que le dispatcheur expose. Cette
        // garde-ci est un garde-fou de FORME, pas la preuve.
        const DECLARED: [(&str, &str, &str); 5] = [
            ("helpers.rs", "commas", "LA PORTE — virgule seule (`by`, `fields`, `dedup`)"),
            ("helpers.rs", "commas_or_blanks", "LA PORTE — virgule ou blanc (`table`, `lookup … OUTPUT`)"),
            ("helpers.rs", "values", "liste de VALEURS, pas de noms : la chaîne vide y est une valeur légitime (cf. `InClause::values`)"),
            ("stages.rs", "compile_rename", "liste de PAIRES `a AS b` : chaque segment est validé, une liste vide est refusée — rien n'y est jeté"),
            ("knowledge.rs", "parse_macro_call", "arguments d'appel de MACRO, pas des noms de champs ; aucune entrée n'y est jetée"),
        ];
        // La liste des fichiers — VÉRIFIÉE exhaustive contre les `mod …;` déclarés — est partagée avec
        // la garde d'effet (`soql_sources`) : les deux gardes lisent EXACTEMENT le même périmètre.
        let files = soql_sources();
        let mut found: Vec<(String, String)> = Vec::new();
        for (fname, src) in files {
            let mut cur = String::new();
            for line in src.lines() {
                // Les commentaires (`//`, `///`) ne sont PAS du code : ils citent la grammaire.
                let code = match line.find("//") {
                    Some(i) => &line[..i],
                    None => line,
                };
                if let Some(i) = code.find("fn ") {
                    let n: String = code[i + 3..].chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    if !n.is_empty() && code[i + 3 + n.len()..].starts_with('(') {
                        cur = n;
                    }
                }
                // DÉCOUPAGE SUR LA VIRGULE = la famille `split*` ET un littéral virgule sur la même
                // ligne (cf. bandeau de portée). Clé sur le séparateur, pas sur l'idiome.
                let splits = code.contains("split");
                let comma_lit = code.contains("','") || code.contains("\",\"");
                if splits && comma_lit {
                    found.push((fname.to_string(), cur.clone()));
                }
            }
        }
        found.sort();
        found.dedup();
        let declared: Vec<(String, String)> =
            DECLARED.iter().map(|(f, n, _)| (f.to_string(), n.to_string())).collect();
        let mut d = declared.clone();
        d.sort();
        assert_eq!(
            found, d,
            "un découpage sur la virgule a été ajouté ou retiré. S'il produit des NOMS DE CHAMPS, il \
             doit passer par `FieldList::commas`/`commas_or_blanks` ; sinon, déclare-le ici AVEC SA \
             RAISON.\ntrouvés : {found:?}\ndéclarés : {d:?}"
        );
    }

    #[test]
    fn the_readme_step_count_is_the_one_the_dispatcher_gives() {
        // UN CHIFFRE PUBLIÉ EST UNE AFFIRMATION : un exploitant dimensionne avec. « 16 étapes » ne se
        // réconciliait avec AUCUNE lecture du code (le dispatcheur a 18 bras et accepte 20 noms) —
        // c'était le compteur de la LISTE ÉCRITE À CÔTÉ, laquelle avait cessé de suivre le code
        // (`rename`, `mvexpand`, `lookup`, `limit` en manquaient). Le README dit maintenant les DEUX
        // lectures, et c'est CE TEST qui les rend vraies : elles ne peuvent plus dériver en silence.
        let modsrc = include_str!("soql/mod.rs");
        let steps = dispatcher_steps(modsrc);
        let arms = modsrc
            .lines()
            .filter(|l| l.trim_start().starts_with('"') && l.contains("=> compile_"))
            .count();
        let readme = include_str!("../README.md");
        assert_eq!(arms, 18, "bras du dispatcheur");
        assert_eq!(steps.len(), 20, "noms d'étape acceptés");
        for claim in [
            format!("{arms} étapes de pipeline"),
            format!("{} noms", steps.len()),
        ] {
            assert!(readme.contains(&claim), "le README ne porte pas « {claim} »");
        }
        // Et chaque nom accepté est CITÉ dans le README : la liste ne peut plus être incomplète.
        let missing: Vec<&str> = steps
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| !readme.contains(&format!("`{n}`")))
            .collect();
        assert!(missing.is_empty(), "étapes acceptées mais absentes du README : {missing:?}");
    }

    #[test]
    fn s10_metric_by_error_explains_the_comma_separator() {
        // Le message « label invalide dans `by` : code extra » était bancal : `by` JOINT ses jetons avec
        // un espace, donc l'utilisateur qui écrit `by code extra` lit un « label » qu'il n'a pas écrit.
        // L'erreur doit dire ce qui est attendu (séparateur virgule).
        let e = to_sql("metric node_load1 by code extra", 0, 0, &Schema::events())
            .expect_err("un `by` mal séparé doit être refusé");
        assert!(e.contains("virgule"), "l'erreur doit expliquer le séparateur : {e}");
    }

    #[test]
    fn s10_metric_legitimate_specs_are_unchanged() {
        // ANTI-RÉGRESSION : les 5 formes `metric` légitimes (corpus + seeds) rendent le MÊME SQL.
        let ev = Schema::events();
        let m = "SELECT ts,host,value FROM metric WHERE name='node_load1'";
        let r = "SELECT ts,host,avg AS value FROM metric_rollup WHERE name='node_load1'";
        assert_eq!(to_sql("metric node_load1", 0, 0, &ev).unwrap(), format!("{m} UNION ALL {r} ORDER BY ts"));
        assert_eq!(
            to_sql("metric node_load1 value>3", 0, 0, &ev).unwrap(),
            format!("{m} AND value > 3 UNION ALL {r} AND avg > 3 ORDER BY ts")
        );
        let h = "SELECT ts,host,value FROM metric WHERE name='http_requests_total'";
        let hr = "SELECT ts,host,avg AS value FROM metric_rollup WHERE name='http_requests_total'";
        assert_eq!(
            to_sql("metric http_requests_total job=api", 0, 0, &ev).unwrap(),
            format!("{h} AND json_extract(labels,'$.job')='api' UNION ALL {hr} AND json_extract(labels,'$.job')='api' ORDER BY ts")
        );
        let byc = "SELECT ts,host,value,json_extract(labels,'$.code') AS \"code\" FROM metric WHERE name='http_requests_total'";
        let byr = "SELECT ts,host,avg AS value,json_extract(labels,'$.code') AS \"code\" FROM metric_rollup WHERE name='http_requests_total'";
        assert_eq!(to_sql("metric http_requests_total by code", 0, 0, &ev).unwrap(), format!("{byc} UNION ALL {byr} ORDER BY ts"));
        // Séparation par virgule (avec ou sans espace) : toujours acceptée.
        assert!(to_sql("metric http_requests_total by code, job", 0, 0, &ev).is_ok());
    }

    // --- S1 (suite) : un jeton `k=v` inconnu de `timechart` n'est plus ignoré en silence --------
    #[test]
    fn s1_unknown_timechart_option_is_error() {
        // MESURÉ sur 4b16822 : la boucle ne reconnaissait que le PRÉFIXE EXACT `span=` ; tout autre jeton
        // CONTENANT `=` était ignoré sans un mot, puis `if span <= 0` substituait le bucket automatique.
        //   search | timechart spans=200000000000000d count -> (ts/900)*900   (Ok !)
        //   search | timechart SPAN=1h count                -> (ts/900)*900   (Ok !)
        //   search | timechart span =1h count               -> (ts/900)*900   (Ok !)
        // La requête ne mesure alors PAS la fenêtre demandée : c'est la substitution silencieuse que S1
        // dit fermer, atteignable sans aucun débordement. Même règle que le `metric` fail-closed.
        for (q, tok) in [
            ("search | timechart spans=200000000000000d count", "spans="),
            ("search | timechart SPAN=1h count", "SPAN=1h"),
            ("search | timechart span =1h count", "=1h"),
            ("search | timechart span=1h limit=10 count", "limit=10"),
        ] {
            match to_sql(q, 0, 0, &Schema::events()) {
                Ok(sql) => panic!("attendu une erreur pour « {q} », obtenu du SQL : {sql}"),
                Err(e) => assert!(e.contains(tok), "l'erreur doit nommer le jeton {tok} : {e}"),
            }
        }
    }

    #[test]
    fn s1_legitimate_timechart_forms_are_unchanged() {
        // ANTI-RÉGRESSION : 5 formes `timechart` légitimes rendent le MÊME SQL (goldens littéraux).
        let ev = Schema::events();
        let b = "SELECT ts,host,source,category,severity,src_ip,dst_ip,url,xff,message,fields FROM event";
        assert_eq!(
            to_sql("search | timechart span=1h count", 0, 0, &ev).unwrap(),
            format!("SELECT (ts/3600)*3600 AS bucket,COUNT(*) AS \"count\" FROM ({b}) GROUP BY bucket ORDER BY bucket")
        );
        assert_eq!(
            to_sql("search | timechart count", 0, 0, &ev).unwrap(),
            format!("SELECT (ts/900)*900 AS bucket,COUNT(*) AS \"count\" FROM ({b}) GROUP BY bucket ORDER BY bucket")
        );
        assert_eq!(
            to_sql("search | timechart span=5m count by source", 0, 0, &ev).unwrap(),
            format!("SELECT (ts/300)*300 AS bucket,\"source\" AS \"source\",COUNT(*) AS \"count\" FROM ({b}) GROUP BY bucket,\"source\" ORDER BY bucket")
        );
        assert!(to_sql("search source=svc-audit vtype=response | timechart count", 0, 0, &ev).is_ok());
        assert!(to_sql("metric http_requests_total job=api | timechart avg(value)", 0, 0, &ev).is_ok());
    }

    // --- env_limit : plafond de sûreté, refus non verrouillé, et preuves du câblage -------------
    #[test]
    fn env_limit_parsing_is_covered() {
        // AUCUN test ne couvrait `env_limit` : ni l'override, ni la valeur illisible, ni le plafond.
        // `parse_limit` est PUR (valeur brute en argument) -> mesurable in-process.
        let v = "GUATX_SOQL_MAX_SQL_BYTES";
        assert_eq!(parse_limit(v, None, 1_048_576, 16_777_216), Ok(1_048_576)); // absente -> défaut
        assert_eq!(parse_limit(v, Some("4096"), 1_048_576, 16_777_216), Ok(4096)); // baissée -> OK
        assert_eq!(parse_limit(v, Some(" 4096 "), 1_048_576, 16_777_216), Ok(4096)); // trim
        assert_eq!(parse_limit(v, Some("16777216"), 1_048_576, 16_777_216), Ok(16_777_216)); // plafond exact
        // PLAFOND DE SÛRETÉ : mesuré AVANT ce correctif, `99999999999999` était ACCEPTÉ — la protection
        // anti-OOM était donc désactivable par une valeur d'apparence plausible.
        for bad in ["99999999999999", "16777217", "abc", "0", "-1", "", "1e6"] {
            let e = parse_limit(v, Some(bad), 1_048_576, 16_777_216)
                .expect_err("valeur hors bornes ou illisible : {bad}");
            assert!(e.contains(v) && e.contains("entre 1 et 16777216"), "message inexploitable : {e}");
            // Le message doit dire à un VIEWER que ce n'est pas sa requête qui est en cause.
            assert!(e.contains("configuration serveur"), "message non qualifié : {e}");
        }
        // La borne du span ne peut qu'être BAISSÉE (plafond = défaut).
        assert_eq!(parse_limit("GUATX_SOQL_MAX_SPAN_SECS", Some("86400"), 315_360_000, 315_360_000), Ok(86_400));
        assert!(parse_limit("GUATX_SOQL_MAX_SPAN_SECS", Some("315360001"), 315_360_000, 315_360_000).is_err());
    }

    #[test]
    fn env_limit_env_wiring_is_measured() {
        // Le cache `OnceLock` rend ces chemins INTESTABLES in-process (une seule lecture par processus) :
        // chaque cas est donc mesuré dans un PROCESSUS FILS dédié — ce même test, relancé avec un rôle.
        match std::env::var("GUATX_CORE_ENV_LIMIT_PROBE").as_deref() {
            Ok("override") => {
                // GUATX_SOQL_MAX_STAGES=2 : l'override est bien pris en compte.
                to_sql("search | head 1", 0, 0, &Schema::events()).expect("2 étapes <= 2");
                let e = to_sql("search | head 1 | head 2", 0, 0, &Schema::events()).expect_err("3 étapes > 2");
                assert!(e.contains("maximum 2"), "{e}");
            }
            Ok("ceiling") => {
                // GUATX_SOQL_MAX_SQL_BYTES=99999999999999 : accepté AVANT le correctif.
                let e = to_sql("search source=web", 0, 0, &Schema::events()).expect_err("plafond de sûreté");
                assert!(e.contains("GUATX_SOQL_MAX_SQL_BYTES") && e.contains("16777216"), "{e}");
            }
            Ok("unreadable") => {
                // GUATX_SOQL_MAX_SQL_BYTES=abc : refus… mais NON verrouillé dans le cache.
                let e = to_sql("search source=web", 0, 0, &Schema::events()).expect_err("valeur illisible");
                assert!(e.contains("GUATX_SOQL_MAX_SQL_BYTES"), "{e}");
                std::env::remove_var("GUATX_SOQL_MAX_SQL_BYTES");
                to_sql("search source=web", 0, 0, &Schema::events()).expect("corrigée -> aucun redémarrage");
                // …et la valeur VALIDE, elle, est figée pour la vie du processus (lecture unique).
                std::env::set_var("GUATX_SOQL_MAX_SQL_BYTES", "abc");
                to_sql("search source=web", 0, 0, &Schema::events()).expect("valeur valide déjà en cache");
            }
            _ => {
                for (role, var, val) in [
                    ("override", "GUATX_SOQL_MAX_STAGES", "2"),
                    ("ceiling", "GUATX_SOQL_MAX_SQL_BYTES", "99999999999999"),
                    ("unreadable", "GUATX_SOQL_MAX_SQL_BYTES", "abc"),
                ] {
                    let exe = std::env::current_exe().expect("current_exe");
                    let out = std::process::Command::new(exe)
                        .args(["soql::tests::env_limit_env_wiring_is_measured", "--exact", "--nocapture", "--test-threads", "1"])
                        .env("GUATX_CORE_ENV_LIMIT_PROBE", role)
                        .env(var, val)
                        .output()
                        .expect("processus fils");
                    let s = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
                    assert!(out.status.success(), "sonde « {role} » en échec :\n{s}");
                    assert!(s.contains("1 passed"), "sonde « {role} » non exécutée :\n{s}");
                }
            }
        }
    }
