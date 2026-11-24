# Politique de sécurité

[English](SECURITY.md) | [Français](SECURITY.fr.md)

guatx-core est le **cœur partagé de GuatX, critique pour la sécurité** : une implémentation unique et
auditée du compilateur de requêtes GXQL et de la couche de masquage de champs / périmètre de lignes
dont dépendent Plume (SOC bleu) et la console Forge (rouge). Une faille ici met en échec un contrôle
dans *les deux* produits à la fois : nous voulons donc en entendre parler.

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique pour une vulnérabilité de sécurité.**

Signalez-la en privé via les **GitHub Security Advisories** — le bouton « Report a vulnerability » de
l'onglet **Security** de ce dépôt. Le signalement, la discussion et le correctif restent ainsi
coordonnés et privés, et nous pouvons vous créditer lors de la divulgation. C'est le seul canal que
nous surveillons : utilisez-le plutôt qu'une issue publique, une pull request ou un message direct.

Indiquez : la version/le commit concerné, une description, les étapes de reproduction ou une preuve de
concept, et l'impact. Les GitHub Security Advisories sont privées de bout en bout : aucun chiffrement
supplémentaire n'est nécessaire.

Nous visons un **accusé de réception sous 3 jours ouvrés** et à convenir avec vous d'un calendrier de
correction. Nous pratiquons la **divulgation coordonnée** et vous créditerons (sauf si vous préférez
rester anonyme) une fois un correctif publié.

## Ce qui est dans le périmètre

Le rôle de guatx-core est de compiler un texte de requête non fiable en SQL **en lecture seule** tout en
appliquant masquage et périmètre *par construction*. Un bug de sécurité est tout ce qui met cela en
échec. En particulier :

- **Contournement du point d'étranglement de masquage / DENY** — exfiltration d'une colonne masquée :
  obtenir en clair une valeur que `soql_field` aurait dû envelopper dans son expression de masque
  (hash) ou de `Deny`. `soql_field` est le point d'étranglement unique de provenance ; tout chemin qui
  atteint une valeur de colonne sans passer par lui (en contournant les `field_masks` de compilation)
  est dans le périmètre.
- **Injection GXQL / évasion du compilateur** — un texte de requête forgé qui échappe à la mise entre
  quotes/l'inlining des valeurs et injecte du SQL, ou qui fait émettre au compilateur autre chose que
  la requête en lecture seule voulue (mutation, sous-requête vers une table non prévue, instruction
  empilée).
- **Contournement du RowFilter / de l'autoriseur** — lire des lignes hors du périmètre de l'appelant :
  mettre en échec un `RowFilter` (`with_row_filter`) de sorte que le prédicat joint par AND soit
  retiré, affaibli ou contourné, ou tout autre accès à des lignes d'un autre périmètre / d'un autre
  tenant au travers de la requête compilée.
- **Fuite de secret** — un `SecretValue` / du matériel secret qui échappe au caviardage (vers une sortie
  `Debug`, une erreur, ou une requête compilée/un journal) au lieu d'être mis à zéro et `REDACTED`.

## Ce qui n'est PAS une vulnérabilité

- **Un mauvais usage de la bibliothèque dans votre propre application.** guatx-core applique le
  masquage, la compilation en lecture seule et le périmètre de lignes *aux requêtes qu'il compile* ;
  il ne peut pas sécuriser des chemins de code qui le contournent entièrement. Si votre application lit
  la base directement, remet au compilateur un schéma/un jeu de masques qui accorde l'accès, ou confie
  des secrets à autre chose que `SecretValue`, c'est un bug d'intégration de votre application, pas une
  faille du cœur.
- **Une demande de fonctionnalité pour un défaut plus strict.** Signalez la *mise en échec* d'un
  contrôle existant, pas l'absence d'un contrôle que nous ne revendiquons pas.

## Versions prises en charge

guatx-core est antérieur à la 1.0. Les correctifs de sécurité arrivent sur `main` et dans la dernière
release taguée. Les tags plus anciens ne sont pas maintenus : mettez à jour.

| Version | Prise en charge |
|---------|-----------|
| `main` / dernière release | ✅ |
| tags plus anciens | ❌ |

## Durcissement & audits

Les contrôles de sûreté du cœur — le compilateur GXQL unique, le point d'étranglement de masquage
`soql_field`, les masques `Deny` / hash appliqués à la compilation, le périmètre de lignes `RowFilter`,
et le caviardage/la mise à zéro des secrets — sont couverts par des tests (dont un banc de parité
différentielle contre le compilateur d'origine de Plume) et par une chaîne de CI qui joue
`cargo audit` et un scan de secrets à chaque push.
