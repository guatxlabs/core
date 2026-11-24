# Rules for any agent or contributor working on this repository

[English](AGENTS.md) | [Français](AGENTS.fr.md)

This repository is **public**. This file exists because the rules below have already been
broken, and because a session's memory survives neither a change of agent nor a loss of
context. What follows is therefore **enforced by guards**, not merely written down.

## 1. Identity — `guatxlabs <noreply@guatx.com>`, without exception

A workstation's **global** git configuration may say something else; every fresh clone
inherits it. Set the identity **locally**, in each clone:

```sh
git config user.name  "guatxlabs"
git config user.email "noreply@guatx.com"
git config core.hooksPath .githooks     # arms the guards
```

`.githooks/pre-commit` refuses a commit whose author is not that one.

**NO `Co-Authored-By` TRAILER.** GitHub does not build the Contributors page from the
author alone: it also counts these trailers on the default branch, and it matches by
ADDRESS. A single trailer is enough to list one more account as a contributor to the
project. This repository shows only one identity, the one that takes responsibility for the code.
The verifier refuses the trailer, and it reads the message FILE and not the cleaned body —
that body already strips these lines, so a guard that read it could never find anything
and would pass green while being blind.

## 2. Writing for the reader of the code — never for a person

A commit message says **what changes and why**. It does not tell the story of how the
work went. The following are **refused** by `.githooks/commit-msg` and by the CI:

| Family | Refused example |
|---|---|
| first-person narrative | « j'ai corrigé » ("I fixed"), « je pensais que » ("I thought that") |
| possessive referring to the author | « ma faute » ("my fault"), « mon correctif » ("my fix"), « mes deux verdicts » ("my two verdicts") |
| session marker | « hier » ("yesterday"), « à ce jour » ("to date") in the temporal sense, « 4e fois de la session » ("4th time this session") |
| addressed to a person, or quoting an exchange | « demandé par X » ("requested by X"), « X m'a dit » ("X told me") |
| machine path | `/home/<compte>` |
| personal account, address outside `@guatx.com` | — |

**What has value and must stay**: the measurement (a figure **with its date**), what was
**refuted**, and the **reason** for a design choice. The work log — who tried what, in what
order, in how many attempts — belongs in an internal repository.

The same rule applies to **documentation** and **code comments**: they are addressed to the
reader, not to an interlocutor.

## 3. How the rule is upheld

```
.github/scripts/verifier-message-de-commit.sh   la règle, écrite UNE fois
.githooks/commit-msg                            boucle de retour locale (contournable)
.github/workflows/message-public.yml            application qui LIE, sur la plage poussée
```

The hook **delegates** to the CI script: a rule written twice ends up diverging. The
hook can be bypassed (`--no-verify`) and is lost with every clone; the CI cannot. To check a
message before committing:

```sh
git log -1 --format=%B > /tmp/m && ./.github/scripts/verifier-message-de-commit.sh /tmp/m
```

## 4. What the guard does not do

It only judges **objective** families. It cannot decide whether a sentence
"is addressed to the public": a guard that claimed to do so would produce noise and would
end up disarmed. That part rests on review — and the rule written above is what
makes it possible.
