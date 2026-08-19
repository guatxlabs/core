#!/usr/bin/env bash
# Verifie qu'un message de commit s'adresse au LECTEUR DU CODE et non a une personne.
# Utilise par le hook `commit-msg` (local) ET par la CI (non contournable).
# Argument : un fichier contenant le message. Sortie 1 = refus, avec la raison.
set -uo pipefail
f="${1:?usage: verifier-message.sh <fichier>}"
corps="$(grep -v '^Co-Authored-By:' "$f" | grep -v '^#')"
fautes=""
ajoute() { fautes="$fautes
  - $1"; }

# ── STYLE : le message raconte l'auteur au lieu de decrire le changement ────────────────
# Motifs ANCRES sur des frontieres de mot. Sans ancrage, « fichier » matchait « hier » —
# mesure faussee avant correction, d'ou les frontieres explicites partout.
if printf '%s' "$corps" | grep -qiE "\bj'(ai|avais|étais|etais)\b|\bje \b"; then
  ajoute "recit a la premiere personne (« j'ai », « je ») — decrire le CHANGEMENT, pas son auteur"
fi
if printf '%s' "$corps" | grep -qiE "\b(ma|mon|mes)\b +(faute|erreur|premier|premiere|hypothese|mesure|verdict|correctif|inquietude|rendement|regle|garde|script|boucle)"; then
  ajoute "possessif renvoyant a l'auteur (« ma faute », « mon correctif »)"
fi
if printf '%s' "$corps" | grep -qiE "\bhier\b|\baujourd'hui\b|\bce matin\b|de la (session|journee|journée)|\b[0-9ivx]+e fois (de|d')"; then
  ajoute "repere de session (« hier », « de la journee », « 4e fois de la session »)"
fi
# ── DESTINATAIRE : le message s'adresse a quelqu'un ou cite un echange prive ────────────
if printf '%s' "$corps" | grep -qiE "\b(demande par|a demande|m'a dit|il a dit|elle a dit|signale par [A-Z])"; then
  ajoute "message adresse a une personne ou citant un echange"
fi
# ── IDENTIFIANTS : rien de personnel ni de machine ──────────────────────────────────────
printf '%s' "$corps" | grep -qE "/home/[a-z][a-z0-9_-]*" && ajoute "chemin machine (/home/<compte>)"
printf '%s' "$corps" | grep -qi "xguatx"                 && ajoute "compte personnel"
# ── ADRESSES : uniquement le domaine du projet ─────────────────────────────────────────
# Les trailers Co-Authored-By sont exclus du corps plus haut : une co-signature est un fait,
# pas une adresse de contact. Basculer en STRICT = retirer le `grep -v` de la ligne `corps`.
if printf '%s' "$corps" | grep -qoE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" \
   && printf '%s' "$corps" | grep -oE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" | grep -qvE "@guatx\.com$"; then
  ajoute "adresse hors @guatx.com"
fi

if [ -n "$fautes" ]; then
  echo "REFUS — ce message ne s'adresse pas au lecteur du code :$fautes" >&2
  echo "" >&2
  echo "Un message de commit dit CE QUI CHANGE et POURQUOI. Ce qui a de la valeur : la mesure" >&2
  echo "(chiffre + date), ce qui a ete REFUTE, la raison d'un choix. Pas le deroulement du" >&2
  echo "travail, pas son auteur. Regle complete : CONTRIBUTING.md." >&2
  exit 1
fi
