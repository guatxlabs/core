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
        // Une PHRASE quotée qui contient un `=` reste un terme libre (elle ne prétend pas nommer un
        // champ : sa partie gauche n'a pas la forme d'un identifiant).
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
        // `soql_in_re` n'accrochait que le DERNIER segment après le tiret/point.
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
        // Même défaut sur l'étape `where` (le pré-pass y passe par `soql_parse_in`).
        let e = to_sql("search | where x-forwarded-for in (1,2)", 0, 0, &Schema::events())
            .expect_err("`where` doit refuser, pas filtrer un autre champ");
        assert!(e.contains("x-forwarded-for"), "l'erreur doit nommer le champ complet : {e}");
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
