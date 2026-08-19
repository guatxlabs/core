# Règles pour tout agent ou contributeur travaillant sur ce dépôt

Ce dépôt est **public**. Ce fichier existe parce que les règles ci-dessous ont déjà été
enfreintes, et que la mémoire d'une session ne survit ni à un changement d'agent, ni à une
perte de contexte. Ce qui suit est donc **appliqué par des gardes**, pas seulement écrit.

## 1. Identité — `guatxlabs <noreply@guatx.com>`, sans exception

La configuration git **globale** d'une station peut valoir autre chose ; tout clone frais en
hérite. Poser l'identité **localement**, dans chaque clone :

```sh
git config user.name  "guatxlabs"
git config user.email "noreply@guatx.com"
git config core.hooksPath .githooks     # arme les gardes
```

`.githooks/pre-commit` refuse un commit dont l'auteur n'est pas celui-là.

**AUCUN TRAILER `Co-Authored-By`.** GitHub ne construit pas la page Contributors a partir du
seul auteur : il compte aussi ces trailers sur la branche par defaut, et il apparie par
ADRESSE. Un seul trailer suffit a faire figurer un compte de plus comme contributeur du
projet. Ce depot n'affiche qu'une identite, celle qui engage sa responsabilite sur le code.
Le verificateur refuse le trailer, et il lit le FICHIER du message et non le corps nettoye —
ce corps retire deja ces lignes, donc une garde qui le lirait ne pourrait jamais rien
trouver et rendrait vert en etant aveugle.

## 2. Écrire pour le lecteur du code — jamais pour une personne

Un message de commit dit **ce qui change et pourquoi**. Il ne raconte pas le déroulement du
travail. Sont **refusés** par `.githooks/commit-msg` et par la CI :

| Famille | Exemple refusé |
|---|---|
| récit à la première personne | « j'ai corrigé », « je pensais que » |
| possessif renvoyant à l'auteur | « ma faute », « mon correctif », « mes deux verdicts » |
| repère de session | « hier », « à ce jour » au sens temporel, « 4e fois de la session » |
| adressé à une personne, ou citant un échange | « demandé par X », « X m'a dit » |
| chemin machine | `/home/<compte>` |
| compte personnel, adresse hors `@guatx.com` | — |

**Ce qui a de la valeur et doit rester** : la mesure (un chiffre **avec sa date**), ce qui a
été **réfuté**, et la **raison** d'un choix de conception. Le journal de travail — qui a
essayé quoi, dans quel ordre, en combien de tentatives — appartient à un dépôt interne.

Même règle pour la **documentation** et les **commentaires de code** : ils s'adressent au
lecteur, pas à un interlocuteur.

## 3. Comment la règle est tenue

```
.github/scripts/verifier-message-de-commit.sh   la règle, écrite UNE fois
.githooks/commit-msg                            boucle de retour locale (contournable)
.github/workflows/message-public.yml            application qui LIE, sur la plage poussée
```

Le hook **délègue** au script de la CI : une règle écrite deux fois finit par diverger. Le
hook se contourne (`--no-verify`) et se perd à chaque clone ; la CI, non. Pour vérifier un
message avant de committer :

```sh
git log -1 --format=%B > /tmp/m && ./.github/scripts/verifier-message-de-commit.sh /tmp/m
```

## 4. Ce que la garde ne fait pas

Elle ne juge que des familles **objectives**. Elle ne peut pas décider si une phrase
« s'adresse au public » : une garde qui prétendrait le faire produirait du bruit et
finirait désarmée. Cette part-là tient à la relecture — et la règle écrite ci-dessus est ce
qui la rend possible.
