# guatx-core

**Cœur partagé GuatX — neutre, public.** Le ~70 % commun à Plume (SOC bleu, publication à venir) et à la console
Forge (rouge), extrait pour n'avoir **qu'une seule implémentation** des primitives critiques.

*Rust · lib · dépendances minimales : `regex`, `serde_json`, `secrecy`, `zeroize` (4 crates, toutes déjà
présentes dans l'arbre des consommateurs — aucune crate native/compilée nouvelle).*

Licensed under LGPL-3.0-or-later, see [COPYING.LESSER](COPYING.LESSER).

## Pourquoi
- **Source unique de vérité** : un bug corrigé / une feature ajoutée une fois profite aux deux produits.
- **Cohérence sécurité** : les garde-fous (compilation read-only, allowlist anti-injection, auth) sont
  **critiques** → une seule implémentation auditée vaut mieux que deux qui divergent.

## Contenu
- `soql` — le compilateur **type-SPL complet de Plume**, promu ici et rendu **schéma-générique**
  (`Schema::events()` pour Plume · `Schema::forge()` pour Forge). 16 étapes : search/metric/`<alt>`
  (base) · stats · timechart · where · sort · head · rex · fields · table · dedup · top/rare ·
  eventstats · rate · eval · append[..] · join f[..]. SQL **read-only**, valeurs **échappées+inlinées**
  (`soql_esc`, quotes doublées), idents validés, mots-clés SQL interdits dans `eval`, récursion ≤3.
  Les UDF `regexp`/`re_cap` (pour `=~`/`rex`) sont enregistrées par le consommateur sur sa connexion.

À venir : auth (argon2 + host-guard anti-rebinding), exécution read-only, helpers de packaging.

## Règle d'or
**Rien d'offensif ici.** Modules d'attaque, évasion WAF/CF, logique ROE → restent dans **Forge**, dépôt
séparé qui dépend de ce cœur. `guatx-core` ne contient que de l'infra générique (requête, auth, stockage).

## Usage
```rust
use guatx_core::soql::{compile, Schema};
let c = compile("search severity=HIGH | stats count by mitre | sort -count", &Schema::events())?;
// c.sql = SQL read-only prêt à exécuter ; c.columns = colonnes de sortie.
// NB : le compilateur ÉCHAPPE et INLINE les valeurs (pas de paramètres liés) — l'échappement est
// délégué au `Dialect` de la cible (SQLite/DuckDB/ClickHouse), c'est le point d'étranglement unique.
```
```sh
cargo test                   # 154 tests (148 unitaires + 5 parité différentielle + 1 doctest)
cargo test --features forge  # 174 tests (schéma + tests Forge activés)
cargo test --all-features    # 183 tests (+ modules `ai` et `cold_tier`)
```

### Nom de champ et recherche plein-texte
Un nom de champ n'accepte que **lettres, chiffres et `_`**.

**Ce qui est refusé.** Dans un filtre de base (`search …`) ou un `where`, un terme dont la **partie
gauche** a la *forme* d'un nom de champ sans en être un valide est **refusé**, avec un message qui
nomme cette partie gauche. Sont concernées les deux syntaxes de filtre :

| Syntaxe | Ce qui décide du nom | Refusé |
|---|---|---|
| jeton `nom<op>valeur` (`=` `:` `!=` `>=` `<=` `>` `<` `=~`), collé ou espacé | la partie gauche de l'opérateur, blancs délimiteurs retirés | `x-forwarded-for=1.2.3.4` · `http.status>=500` · `foo-bar = 1` · `x-forwarded-for="10.0.0.1"` (guillemeter la *valeur* n'exempte pas) |
| clause `nom [not] in (…)` | tout ce qui précède `in` jusqu'à la frontière du jeton (le **blanc**, la seule de ce langage), **moins** les parenthèses ouvrantes de tête, qui sont du groupement — **pas** une classe de caractères | `src-ip in (10,11)` · `cache/status in (200,302)` · `user@host in (1,2)` · `-foo in (1,2)` · `foo(host in (1,2)` · `count(src_ip in (10,11))` |

Le laisser filer donnerait un scan plein-texte non borné — ou, pour `in (…)`, un filtre sur un *autre*
champ que celui écrit (le suffixe après le séparateur) : dans les deux cas un jeu de lignes différent
de celui demandé, sans un mot. La garde vaut aux mêmes conditions dans une sous-recherche
(`append […]`, `join f […]`), à toute profondeur.

**Ce qui n'est PAS refusé.** Une parenthèse ouvrante **de tête** est du **groupement**, pas une partie
du nom : elle est retirée de la tête du jeton, remise dans le texte du filtre, et le reste doit être un
identifiant entier. Mesuré : `search (dport in (80,443))` et `search ((foo in (1,2)))` rendent le SQL
de v0.2.0 à l'octet près, tandis que `search foo(host in (1,2)` est refusé. Le peeling n'a lieu qu'**en
tête** : `search (a) in (1,2)` réclame `a)` et est refusé.

Une **phrase quotée** reste une recherche plein-texte, inchangée :
`search "user-agent=curl/7.68"`, `search "x-forwarded-for in (1,2)"`, `search "foo-bar"=1`. La
quotation compte pour ce qu'elle couvre à **gauche de l'opérateur**, pas pour le fait qu'il y ait un
guillemet quelque part : `search source="web"` reste le filtre indexé `"source" = 'web'`, et
`search x-forwarded-for="10.0.0.1"` est refusé. Une quotation **non close** n'exempte rien.

**L'échappatoire.** Dans un **filtre de base**, le message d'erreur suggère votre propre texte entre
guillemets — c'est une tranche du texte que vous avez tapé, espaces et ponctuation compris. Mesuré :
`search foo-bar = 1` suggère `"foo-bar = 1"`, et `search "foo-bar = 1"` compile en
`message LIKE '%foo-bar = 1%'`. Les guillemets étant des **délimiteurs** (le tokenizer ne les conserve
jamais), le texte suggéré est le vôtre *sans ses guillemets internes* : `search foo-bar=a"b"` suggère
`"foo-bar=ab"`. L'étape `where` refuse elle aussi un nom invalide, mais avec son libellé propre et
**sans** suggestion (`where : champ invalide : foo-bar` — mesuré) : `where` n'a pas de recherche
plein-texte vers laquelle se rabattre.

**Limite mesurée, non fermée :** cette garde n'existe pas dans `eval`, et ne peut pas y exister — dans
une expression, `-` est l'opérateur de soustraction. `search | eval x = foo-bar` émet `(foo-bar)` et
`eval x = foo - bar` émet `(foo - bar)` : **ces deux SQL ne sont pas identiques à l'octet** — ils ne
diffèrent que par des blancs (mesuré par le test ci-dessous), et SQLite les compile en le **même
programme** (mesuré : `EXPLAIN SELECT (foo-bar) FROM t` et `EXPLAIN SELECT (foo - bar) FROM t` rendent
un bytecode identique, sqlite 3.53.3). Rien dans l'entrée ne sépare donc les deux lectures ; un nom mal
écrit y échoue à l'**exécution** (colonne inexistante) et non à la compilation. Les autres étapes qui
prennent un nom de champ (`where`, `stats by`, `table`, `fields`, `sort`, `dedup`, `top`, `rename`,
`mvexpand`, `eventstats`, `timechart by`, `metric by`) le valident (test
`eval_is_the_documented_blind_spot_of_the_field_name_guard`).

**Une liste de champs séparée par des virgules est décidée à un seul endroit** (`FieldList`), pour
toutes les étapes qui en prennent une : `stats by`, `timechart by`, `eventstats by`, `metric by`,
`fields`, `dedup` et `table`. Aucune entrée n'y est jetée, donc une liste demandée ne peut pas
s'évaporer en silence ni émettre du SQL invalide. Mesuré, refusé partout où le séparateur est la
**virgule seule** : `by`, `by ,`, `by ,src_ip`, `by src_ip,`, `by src_ip,,host`, `fields`, `fields ,`,
`fields ,src_ip`, `dedup ,src_ip`.

`table` a une grammaire différente — le **blanc** y est aussi un séparateur (`table a b` est légitime,
mesuré) — donc une *suite* de séparateurs y est indiscernable d'un seul et se réduit : `table a,,b`
rend `a` et `b` (limite assumée, mesurée). Ce qui reste fermé : `table ,` est refusé au lieu de
disparaître. `table *` et `table` nu restent des **passe-plat délibérés** (ils ne restreignent pas la
projection), inchangés.

### Bornes de compilation (le texte de requête est une entrée NON FIABLE)
La compilation a lieu **avant** tout budget d'exécution du store : elle porte donc ses propres bornes.
Chacune a un défaut sûr et se règle par l'environnement. **Au dépassement, une erreur claire est rendue
à l'appelant** — jamais un panic, jamais une valeur substituée en silence.

| Variable | Défaut | Plafond | Ce qu'elle borne |
|---|---|---|---|
| `GUATX_SOQL_MAX_SPAN_SECS` | `315360000` (10 ans) | `315360000` | le bucket `timechart span=` (secondes) |
| `GUATX_SOQL_MAX_STAGES` | `64` | `1024` | le nombre d'étapes de pipe d'un pipeline |
| `GUATX_SOQL_MAX_SQL_BYTES` | `1048576` (1 Mio) | `16777216` | la taille du SQL émis, vérifiée après chaque étape |
| `GUATX_SOQL_MAX_TEXT_BYTES` | `1048576` (1 Mio) | `16777216` | la taille du texte de requête accepté |

Une borne de sécurité peut être **baissée, pas retirée** : au-dessus du plafond la valeur est refusée
(la borne du span, dont le plafond vaut le défaut, ne peut donc qu'être baissée).

Portée exacte de la borne de SQL : elle est vérifiée **après** chaque étape émettrice (la base, chaque
champ calculé, chaque lookup automatique, puis chaque étape de pipe). Le pic **transitoire** d'une
étape n'est donc pas borné par elle : c'est la borne du **texte d'entrée** qui le contient. Ordre de
grandeur mesuré du couple : 400 006 octets de texte produisent 4 600 089 octets de SQL (×11,5) — donc
refus, la borne de SQL étant franchie dès la première étape.

Une variable **présente mais illisible** (non numérique, ≤ 0, au-dessus du plafond) est signalée comme
une erreur de configuration, et non ramenée en silence au défaut : une borne que l'opérateur croit avoir
posée ne doit jamais être ignorée sans le dire. Conséquence assumée, à connaître avant de déployer :
tant que la variable est illisible, **toute requête qui consulte cette borne échoue** (fail-closed), et
le message le dit — c'est une erreur de configuration *serveur*, pas une erreur de la requête. Seule une
valeur **valide** est mise en cache (lecture unique par processus) : corriger une variable illisible ne
demande **pas** de redémarrer le service ; en revanche une valeur valide déjà lue reste figée jusqu'au
redémarrage.

## Statut
- ✅ Compilateur de Plume **promu + généralisé** ici (16 étapes, schéma-générique). Suite complète : 154 tests (174 avec `--features forge`).
- ✅ Consommé par la console Forge et par Plume via une **git-dep épinglée par tag** :
  `guatx-core = { git = "https://github.com/guatxlabs/core", tag = "v0.2.0" }` — un clone autonome de
  l'un ou l'autre produit compile sans avoir ce dépôt en voisin.
- ✅ **Adoption par Plume terminée** : harnais de parité différentielle sur le corpus des requêtes
  livrées avec le produit (banc `tests/plume_parity.rs`, 0 divergence inattendue), bascule du daemon, puis suppression
  du compilateur interne. Aucune fonctionnalité perdue — ce cœur est désormais l'unique implémentation.
