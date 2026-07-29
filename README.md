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
- `soql` — le compilateur **GXQL** (*GuatX Query Language* ; **anciennement appelé « SOQL »** — même
  langage, même syntaxe, seul le nom change : `SOQL` était le nom du langage de requête de Salesforce).
  Le **module Rust reste `soql`** : le renommage porte sur le **nom du langage**, pas sur l'API — les
  identifiants publics (`guatx_core::soql::*`, `soql_esc`, `GUATX_SOQL_MAX_*`) sont **inchangés**, la
  lib est taguée v0.2.1 et consommée telle quelle par Plume et Forge.
  Le compilateur **type-SPL complet de Plume**, promu ici et rendu **schéma-générique**
  (`Schema::events()` pour Plume · `Schema::forge()` pour Forge). Une base (`search` / `metric` /
  `<alt>`) puis **18 étapes de pipeline**, sous **20 noms** (`head`/`limit` et `top`/`rare` sont deux
  paires d'alias) : `stats` · `timechart` · `where` · `sort` · `head`/`limit` · `rex` · `fields` ·
  `table` · `rename` · `dedup` · `top`/`rare` · `eventstats` · `rate` · `eval` · `mvexpand` ·
  `lookup` · `append`[..] · `join` f[..]. Ces deux chiffres sont ceux du **dispatcheur**, et un test
  les y compare (`the_readme_step_count_is_the_one_the_dispatcher_gives`) — la liste ci-dessus ne
  peut donc plus cesser de suivre le code, ce qui est exactement ce qui était arrivé au « 16 » qu'elle
  annonçait. SQL **read-only**, valeurs **échappées+inlinées**
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
cargo test                   # 161 tests (155 unitaires + 5 parité différentielle + 1 doctest)
cargo test --features forge  # 181 tests (schéma + tests Forge activés)
cargo test --all-features    # 190 tests (+ modules `ai` et `cold_tier`)
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
écrit y échoue à l'**exécution** (colonne inexistante) et non à la compilation ; même là, un `'` isolé
est rejeté (`eval : chaîne non terminée`), pas inliné brut.

**Aucun nom écrit ne ressort brut dans le SQL — propriété dérivée, non énumérée.** Un nom de champ qui
atteint le SQL doit être soit **refusé** (un identifiant valide ne contient pas de guillemet simple),
soit ressortir **échappé** (une valeur légitime a son `'` doublé). Le test
`no_user_written_name_reaches_the_sql_raw_whatever_the_step` engendre depuis le dispatcheur — sans
nommer d'étape — un jeton portant un `'` dans chaque position d'argument de chaque étape, sur les 4
schémas, et vérifie que sa **forme brute** n'apparaît jamais dans le SQL émis : sinon un nom aurait fui
sans validation (`json_extract(fields,'$.a'b')`, littéral cassé) ou une valeur serait sortie non
échappée. C'est ce qui remplace l'ancienne énumération à la main (qui prétendait lister « les autres
étapes » et oubliait `rex` et `join`, tous deux mesurés comme validant) — `eval` reste la seule
exception documentée ci-dessus, et elle refuse quand même le `'` non terminé.

**Une liste de champs séparée par des virgules est décidée à un seul endroit** (`FieldList`) : `stats
by`, `timechart by`, `eventstats by`, `metric by`, `fields`, `dedup`, `table` et `lookup … OUTPUT`.
Aucune entrée n'y est jetée, donc une liste demandée ne peut pas s'évaporer en silence ni émettre du
SQL invalide. Mesuré, refusé partout où le séparateur est la **virgule seule** : `by`, `by ,`,
`by ,src_ip`, `by src_ip,`, `by src_ip,,host`, `fields`, `fields ,`, `fields ,src_ip`, `dedup ,src_ip`.

**Ce n'est pas une liste d'étapes, c'est une propriété vérifiée sur celles que le code déclare.** Une
énumération écrite à la main avait déjà manqué une étape : `lookup … OUTPUT` découpait la chaîne
elle-même, si bien que `lookup t k OUTPUT` et `lookup t k OUTPUT ,` compilaient en retombant sur la
branche « OUTPUT absent » — la projection demandée disparaissait sans un mot. Deux tests remplacent
l'énumération, et ils ne nomment aucune étape :
- `no_typed_field_list_can_evaporate_whatever_the_step` **lit le dispatcheur** et le compilateur de
  chaque étape, en dérive les positions de liste (*une position est une liste de noms si changer les
  noms change le SQL*) et vérifie sur chacune, sur les 4 schémas livrés, qu'une liste sans aucun nom
  est refusée. Deux modes, de portée différente et c'est écrit : quand la liste est **tout
  l'argument** (`fields X`, `table X`), la détection est purement comportementale, indépendante de la
  façon dont l'étape découpe ; quand un **mot-clé** l'introduit (`by`, `OUTPUT`), ce mot-clé est lu
  dans le compilateur de l'étape — les mots-clés des étapes livrées le sont, une étape *future* qui
  introduirait une liste par un mot-clé que ce test ne détecte pas y échapperait. Cette limite reste
  une affaire de *projection perdue*, jamais de sécurité : l'invariant « aucun nom non valide n'atteint
  le SQL » est tenu à part et **universellement**, pour toute étape présente ou future, par
  `no_user_written_name_reaches_the_sql_raw` (il plante un nom porteur d'un guillemet dans chaque
  position d'argument de chaque étape et vérifie qu'il n'atteint jamais le SQL émis) ;
- `every_comma_split_of_the_compiler_is_the_door_or_a_written_exception` **lit la source** : tout
  découpage sur la virgule est soit la porte, soit une exception déclarée avec sa raison (valeurs de
  `in`, paires de `rename`, arguments de macro). Le détecteur clé sur le **séparateur virgule** (une
  ligne portant `split` — toute la famille, `split`/`splitn`/`split_once`/`split_terminator`/
  `split_inclusive`/`rsplit` — **et** un littéral virgule `','` ou `","`), donc un nouveau découpage à
  la main le fait échouer quelle que soit la méthode. **Hors de portée, et c'est écrit dans le test :**
  une virgule cachée derrière une constante nommée ou un cast numérique, ou un split étalé sur
  plusieurs lignes — obfuscations qu'on n'écrit pas par accident. La **garantie** pour les étapes du
  dispatcheur reste la garde d'EFFET ci-dessus, qui constate le résultat quelle que soit l'écriture ;
  celle-ci est un garde-fou de forme.

`table` et `lookup … OUTPUT` ont une grammaire différente — le **blanc** y est aussi un séparateur
(`table a b` et `OUTPUT a b` sont légitimes, mesuré) — donc une *suite* de séparateurs y est
indiscernable d'un seul et se réduit : `table a,,b` rend `a` et `b` (limite assumée, mesurée). Ce qui
reste fermé : `table ,` et `lookup t k OUTPUT ,` sont refusés au lieu de disparaître. `table *` et
`table` nu restent des **passe-plat délibérés** (ils ne restreignent pas la projection), inchangés,
comme `lookup` **sans** `OUTPUT` (rien n'a été demandé) — la différence tient à ce que l'utilisateur a
écrit : le mot-clé `OUTPUT` **tapé** est une demande explicite, l'absence de mot-clé n'en est pas une.

**La liste de *valeurs* d'un `champ in (…)` est la porte voisine, et sa frontière est ici.** Ce n'est
pas une liste de noms, et les deux ne peuvent pas décider pareil parce que leurs **domaines** diffèrent :
la chaîne vide n'est pas un nom de champ (refus), mais c'est une **valeur** légitime (un événement peut
porter `host=''`). Ce qui est donc testé est le **texte écrit**, avant retrait des guillemets :
`in ("",b)` rend `IN ('','b')` — la chaîne vide **demandée** survit (elle disparaissait avant, mesuré :
`IN ('b')`) ; une entrée sans aucun texte est une **suite de séparateurs**, indiscernable d'un seul
comme dans `table`, donc `in (a,,b)` rend `IN ('a','b')` (limite assumée, mesurée) ; et la liste
**entièrement** vide (`in ()`, `in (,,)`) ne rend aucune valeur — SQLite n'ayant pas de `IN ()`, elle
se replie sur `1=0` (`in`) / `1=1` (`not in`), jamais sur un filtre évanoui.

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
- ✅ Compilateur de Plume **promu + généralisé** ici (18 étapes de pipeline, schéma-générique). Suite complète : 161 tests (181 avec `--features forge`).
- ✅ Consommé par la console Forge et par Plume via une **git-dep épinglée par tag** :
  `guatx-core = { git = "https://github.com/guatxlabs/core", tag = "v0.2.1" }` — un clone autonome de
  l'un ou l'autre produit compile sans avoir ce dépôt en voisin. **Épinglez `v0.2.1` ou plus récent** :
  `v0.2.0` émettait, sur une entrée non fiable, des filtres portant sur une colonne que l'utilisateur
  n'avait jamais nommée (faux négatif silencieux dans une règle de détection) — cf. les notes du tag `v0.2.1`.
- ✅ **Adoption par Plume terminée** : harnais de parité différentielle sur le corpus des requêtes
  livrées avec le produit (banc `tests/plume_parity.rs`, 0 divergence inattendue), bascule du daemon, puis suppression
  du compilateur interne. Aucune fonctionnalité perdue — ce cœur est désormais l'unique implémentation.
