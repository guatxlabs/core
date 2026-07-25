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
cargo test                   # 121 tests (115 unitaires + 5 parité différentielle + 1 doctest)
cargo test --features forge  # 141 tests (schéma + tests Forge activés)
cargo test --all-features    # 150 tests (+ modules `ai` et `cold_tier`)
```

### Bornes de compilation (le texte de requête est une entrée NON FIABLE)
La compilation a lieu **avant** tout budget d'exécution du store : elle porte donc ses propres bornes.
Chacune a un défaut sûr et se règle par l'environnement. **Au dépassement, une erreur claire est rendue
à l'appelant** — jamais un panic, jamais une valeur substituée en silence.

| Variable | Défaut | Ce qu'elle borne |
|---|---|---|
| `GUATX_SOQL_MAX_SPAN_SECS` | `315360000` (10 ans) | le bucket `timechart span=` (secondes) |
| `GUATX_SOQL_MAX_STAGES` | `64` | le nombre d'étapes de pipe d'un pipeline |
| `GUATX_SOQL_MAX_SQL_BYTES` | `1048576` (1 Mio) | la taille du SQL émis, vérifiée après chaque étape |
| `GUATX_SOQL_MAX_TEXT_BYTES` | `1048576` (1 Mio) | la taille du texte de requête accepté |

Portée exacte de la borne de SQL : elle est vérifiée **après** chaque étape émettrice (la base, chaque
champ calculé, chaque lookup automatique, puis chaque étape de pipe). Le pic **transitoire** d'une
étape n'est donc pas borné par elle : c'est la borne du **texte d'entrée** qui le contient. Ordre de
grandeur mesuré du couple : 400 006 octets de texte produisent 4 600 089 octets de SQL (×11,5) — donc
refus, la borne de SQL étant franchie dès la première étape.

Une variable **présente mais illisible** (non numérique, ≤ 0) est signalée comme une erreur de
configuration, et non ramenée en silence au défaut : une borne que l'opérateur croit avoir posée ne doit
jamais être ignorée sans le dire.

## Statut
- ✅ Compilateur de Plume **promu + généralisé** ici (16 étapes, schéma-générique). Suite complète : 121 tests (141 avec `--features forge`).
- ✅ Consommé par la console Forge et par Plume via une **git-dep épinglée par tag** :
  `guatx-core = { git = "https://github.com/guatxlabs/core", tag = "v0.2.0" }` — un clone autonome de
  l'un ou l'autre produit compile sans avoir ce dépôt en voisin.
- ✅ **Adoption par Plume terminée** : harnais de parité différentielle sur le corpus des requêtes
  livrées avec le produit (banc `tests/plume_parity.rs`, 0 divergence inattendue), bascule du daemon, puis suppression
  du compilateur interne. Aucune fonctionnalité perdue — ce cœur est désormais l'unique implémentation.
