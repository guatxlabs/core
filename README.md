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
cargo test                   # 110 tests (104 unitaires + 5 parité différentielle + 1 doctest)
cargo test --features forge  # 130 tests (schéma + tests Forge activés)
cargo test --all-features    # 139 tests (+ modules `ai` et `cold_tier`)
```

## Statut
- ✅ Compilateur de Plume **promu + généralisé** ici (16 étapes, schéma-générique). Suite complète : 110 tests (130 avec `--features forge`).
- ✅ Consommé par la console Forge et par Plume via une **git-dep épinglée par tag** :
  `guatx-core = { git = "https://github.com/guatxlabs/core", tag = "v0.2.0" }` — un clone autonome de
  l'un ou l'autre produit compile sans avoir ce dépôt en voisin.
- ✅ **Adoption par Plume terminée** : harnais de parité différentielle sur le corpus des requêtes
  livrées avec le produit (banc `tests/plume_parity.rs`, 0 divergence inattendue), bascule du daemon, puis suppression
  du compilateur interne. Aucune fonctionnalité perdue — ce cœur est désormais l'unique implémentation.
