# Contribuer à guatx-core

[English](CONTRIBUTING.md) | [Français](CONTRIBUTING.fr.md)

Merci de votre intérêt pour guatx-core — le cœur partagé de GuatX, critique pour la sécurité (le
compilateur GXQL + la couche de masquage/périmètre dont dépendent Plume et la console Forge). Les
contributions sont bienvenues, sous quelques règles qui existent parce que cette crate est **critique
pour la sûreté** : un bug ici casse un contrôle dans *les deux* produits à la fois.

En contribuant, vous acceptez que votre contribution soit sous licence **LGPL-3.0-or-later** (la
licence du projet), et vous certifiez le [Developer Certificate of Origin](https://developercertificate.org/)
en signant vos commits (`git commit -s` → ajoute `Signed-off-by:`).

## Non négociable : les invariants du cœur

Une pull request qui affaiblit l'un d'eux sera **refusée**, si utile que soit la fonctionnalité :

- **Un seul compilateur GXQL — ne jamais le forker.** Le compilateur est le point d'étranglement unique
  du masquage/périmètre qui sert à la fois Plume (`Schema::events()`) et Forge (`Schema::forge()`).
  Corrigez-le et étendez-le *en place*. Ne le copiez pas, ne traitez pas un appelant à part, n'ajoutez
  pas un second chemin de code qui émet du SQL — un fork est un contrôle qui se désynchronise et
  finit par diverger de celui qui a été audité.
- **Le masquage / DENY s'applique par construction, jamais réimplémenté par appelant.** `soql_field`
  est l'UNIQUE fonction qui transforme un nom de colonne en SQL émis, et c'est là que les
  `field_masks` de compilation (`Deny` / hash) s'appliquent. Aucun appelant ne peut résoudre ni émettre
  une valeur de colonne de son côté ; tout passe par `soql_field`, pour que le masquage ne puisse pas
  être oublié.
- **Le compilateur reste en lecture seule, valeurs échappées + inlinées.** Aucun chemin ne peut émettre
  une mutation, une instruction empilée ou une valeur non échappée. Le texte de requête est une entrée
  non fiable.
- **Le périmètre de lignes tient.** Un `RowFilter` posé par `with_row_filter` doit rester joint par AND
  à la requête compilée ; n'ajoutez pas de chemin qui le retire, l'affaiblit ou le contourne.
- **Les secrets sont caviardés et mis à zéro.** Un `SecretValue` ne doit jamais atteindre en clair une
  sortie `Debug`, une erreur, une requête compilée ou un journal.
- **Les chaînes de référence (golden) se relisent, jamais rafraîchies en silence.** Certains fragments
  SQL sont épinglés par des chaînes de référence littérales plutôt que par le banc différentiel.
  Mettre à jour une chaîne de référence avec le code qu'elle épingle exige une relecture explicite d'un
  mainteneur : dites dans la PR pourquoi le SQL émis devait changer.
- **Un changement du compilateur générique est un changement de chaque dépendant.** Si vous touchez la
  mécanique partagée — `RowFilter`, `Schema::events()`, le chemin de masquage, tout ce qui n'est pas
  derrière la feature `forge` — cela touche **à la fois** Plume et Forge. Dites-le dans la PR et
  prévenez les mainteneurs ; les tests de parité différentielle doivent toujours passer.

Dans le doute, ajoutez un test qui prouve que l'invariant tient toujours.

## Compiler et tester

guatx-core est une **bibliothèque Rust autonome** (`Cargo.toml` à la racine du dépôt, dépendances
minimales). Ni Python, ni base de données, ni dépôt voisin — un simple clone compile et passe les tests.

```sh
cargo test                        # build par défaut : feature OFF (~70% partagé, aucune feature produit)
cargo test --features forge       # + le schéma Forge (Schema::forge()) et ses tests
cargo test --all-features         # + les modules `ai` et `cold_tier` (la CI joue aussi cette passe)
cargo clippy --all-targets --all-features   # lint indicatif — ne pas AUGMENTER le nombre d'avertissements
```

Tout doit être **vert** et **hors ligne** — les tests ne doivent pas toucher le réseau. Le build par
défaut (feature OFF) est le build partagé et doit rester compatible à l'octet : `--features forge`
ne fait qu'*ajouter* le schéma rouge et ses tests, il ne change jamais le compilateur partagé.

## Style de code

- **Sans `openssl`, dépendances minimales.** Le cœur ne tire que `regex`, `serde_json`, `secrecy`,
  `zeroize` (toutes déjà présentes dans l'arbre des deux consommateurs — aucune crate native/compilée
  nouvelle). N'ajoutez pas de dépendance sans en discuter d'abord.
- **Le code propre à un produit vit derrière une feature.** Tout ce qui est propre à Forge va derrière
  la feature `forge` (OFF par défaut) ; le compilateur partagé reste indépendant des produits.
- **Les secrets passent par la SPI.** Le matériel secret circule par `secret::SecretValue` / la SPI de
  fournisseur — jamais une `String` nue qui pourrait être journalisée.

## Pull requests

1. Ouvrez d'abord une issue pour tout ce qui n'est pas trivial, afin que nous nous accordions sur
   l'approche.
2. Un changement logique par PR. Gardez le diff ciblé.
3. Incluez des tests. Préservez ou améliorez la couverture.
4. Lancez `cargo test`, `cargo test --features forge`, `cargo test --all-features` et
   `cargo clippy --all-targets --all-features`. Les trois passes de test doivent être vertes (clippy
   est indicatif : l'arbre émet aujourd'hui un socle connu d'avertissements — n'augmentez pas ce nombre).
5. Signez vos commits (`-s`).
6. **Les problèmes de sécurité ne vont pas ici** — voir [`SECURITY.md`](SECURITY.fr.md).

## Un mot sur l'intention

guatx-core existe pour que les primitives critiques — compilation en lecture seule, masquage,
périmètre de lignes — aient **une seule** implémentation auditée, partagée par les deux produits. Les
contributions qui donneraient à un appelant un moyen de contourner ces contrôles, ou qui les
scinderaient en un second chemin divergent, sont hors du périmètre de ce projet.

## Écrire pour le public

Ce dépôt est public. Tout ce qui y est écrit — messages de commit, documentation,
commentaires de code — s'adresse au **lecteur futur du code**, pas à une personne ni à une
conversation.

**Un message de commit dit CE QUI CHANGE et POURQUOI.** Il n'a pas à raconter le
déroulement du travail. À proscrire :

- nommer une personne, ou citer un échange privé ;
- le récit à la première personne (« j'ai essayé », « ma première version ») ;
- les repères de session (« hier », « ce matin », « la quatrième fois aujourd'hui ») ;
- un chemin machine (`/home/<compte>`), un pseudo personnel, une adresse tierce.

Ce qui a de la valeur et doit rester : la **mesure** (chiffres et date), ce qui a été
**réfuté**, et la **raison** d'un choix de conception. Le journal de travail, lui, a sa
place dans un dépôt interne — pas dans l'historique public.

**Identité.** Tous les commits sont signés `guatxlabs <noreply@guatx.com>`. À poser dans
chaque clone, car un clone frais hérite de la configuration globale de la machine :

```sh
git config user.name  "guatxlabs"
git config user.email "noreply@guatx.com"
git config core.hooksPath .githooks   # arme les gardes ci-dessous
```

**Deux gardes versionnées** appliquent le mécanisable : `pre-commit` refuse un commit dont
l'auteur n'est pas le canonique ; `commit-msg` refuse un message portant un chemin machine,
un pseudo personnel ou une adresse tierce. Le STYLE, lui, n'est pas mécanisé : une garde
qui prétendrait en juger produirait du bruit et finirait désarmée. Il se tient à la
relecture.
