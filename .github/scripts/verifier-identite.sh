#!/usr/bin/env bash
# L'IDENTITE CANONIQUE, ECRITE UNE SEULE FOIS, ET VERIFIEE LA OU CA LIE.
# Appele par `.githooks/pre-commit` (boucle de retour locale, contournable) ET par la CI
# sur la plage poussee (non contournable). Un hook seul ne suffit pas : il se contourne
# avec --no-verify et il est absent de tout clone frais, or c'est justement un clone frais
# qui herite de la configuration git GLOBALE de la station.
# Usage : verifier-identite.sh <plage git>   (ex. HEAD~5..HEAD)  ou  --index (avant commit)
set -uo pipefail
CANONIQUE_NOM="guatxlabs"
CANONIQUE_MEL="noreply@guatx.com"

refuse() { printf 'REFUS — identite non canonique.\n  attendu : %s <%s>\n%s\n' \
  "$CANONIQUE_NOM" "$CANONIQUE_MEL" "$1" >&2; exit 1; }

if [ "${1:-}" = "--index" ]; then
  n="$(git config user.name  || true)"; m="$(git config user.email || true)"
  [ "$n" = "$CANONIQUE_NOM" ] && [ "$m" = "$CANONIQUE_MEL" ] || refuse \
"  configure : $n <$m>
  poser LOCALEMENT dans ce clone :
    git config user.name  \"$CANONIQUE_NOM\"
    git config user.email \"$CANONIQUE_MEL\""
  exit 0
fi

plage="${1:?usage: verifier-identite.sh <plage>|--index}"
mauvais="$(git log --format='%h %an <%ae> | %cn <%ce>' "$plage" \
  | grep -v "^[0-9a-f]* $CANONIQUE_NOM <$CANONIQUE_MEL> | $CANONIQUE_NOM <$CANONIQUE_MEL>$" || true)"
[ -z "$mauvais" ] || refuse "  commits fautifs (auteur | committer) :
$mauvais"
