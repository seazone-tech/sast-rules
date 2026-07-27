#!/usr/bin/env bash
# Benchmark EXTERNO do ruleset pr-blocking (SRE-46 / Airbnb 10.2.8).
#
# POR QUE ISSO EXISTE
# A validacao anterior era circular: media as regras contra achados das proprias
# regras. Recall aparecia alto por construcao. Este harness roda o ruleset contra
# aplicacoes vulneraveis de terceiros, escolhidas pela stack real da frota
# (Python 36%, TypeScript 35%, JavaScript 5% -- Java ~0%, por isso o OWASP
# Benchmark, que e Java-only, NAO e usado aqui).
#
# O QUE ELE MEDE, E O QUE NAO MEDE
#   MEDE     recall: o ruleset dispara em vulnerabilidade conhecida de terceiro?
#   NAO MEDE precisao. Nenhum corpus aqui e um negativo limpo. Em particular o
#            `vulpy/good` NAO e "codigo seguro": ele mantem app.run(debug=True),
#            JWT com secret hardcoded e SQL interpolado em libuser.py:61. Contar
#            hits no lado `good` como falso positivo produz numero errado --
#            verificado lendo as linhas. Precisao exige revisao humana dos
#            achados reais da frota; nao ha atalho automatico.
#
# COMO INTERPRETAR
#   Queda no total de `bad` entre versoes = regressao de recall, investigar.
#   Alta no total de `good` = investigar CADA hit lendo a linha antes de chamar
#   de falso positivo.
set -euo pipefail

RULESET="${1:-pr-blocking}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="${BENCH_WORK:-$(mktemp -d)}"

command -v opengrep >/dev/null || { echo "opengrep nao encontrado no PATH" >&2; exit 2; }

# corpora de terceiros, na stack da frota
declare -A CORPORA=(
  [vulpy]=https://github.com/fportantier/vulpy.git
  [dvpwa]=https://github.com/anxolerd/dvpwa.git
  [vflask]=https://github.com/we45/Vulnerable-Flask-App.git
  [dvws]=https://github.com/snoopysecurity/dvws-node.git
  [nodegoat]=https://github.com/OWASP/NodeGoat.git
)

for name in "${!CORPORA[@]}"; do
  [ -d "$WORK/$name" ] || git clone -q --depth 1 "${CORPORA[$name]}" "$WORK/$name"
done

scan() { # <alvo> -> imprime contagem de achados
  # declaracoes separadas: sob `set -u`, $target nao esta visivel nas
  # expansoes do mesmo `local`, e o alvo virava o diretorio inteiro.
  local target="$1"
  local out="$WORK/$(echo "$target" | tr / -).json"
  local rc
  # Exclusoes EXPLICITAS, nao herdadas. O opengrep le `.semgrepignore` do
  # diretorio de trabalho ATUAL (nao do alvo), e a simples existencia desse
  # arquivo SUBSTITUI a lista de ignore default -- que e o que normalmente
  # exclui bundle minificado. Como este repo versiona um `.semgrepignore`
  # (para .pilot/canary/), rodar o benchmark com cwd na raiz do repo fazia
  # jquery-3.2.1.min.js entrar no scan: dvpwa dava 40 achados com cwd=repo e
  # 15 com cwd=/tmp. Mesmo comando, resultado diferente. Sem estas exclusoes
  # o harness reporta regressao fantasma dependendo de onde foi invocado.
  set +e
  opengrep scan --config "$ROOT/$RULESET/" --json --output "$out" -q \
    --exclude=node_modules --exclude=vendor --exclude='*.min.js' \
    --exclude='*.min.css' --exclude='*.bundle.js' \
    "$WORK/$target" >/dev/null 2>&1
  rc=$?
  set -e
  # 0=limpo, 1=achados (so com --error). >=2 OU NEGATIVO (sinal/OOM) = erro.
  # Nao tratar erro como "zero achados" -- foi exatamente esse bug que fez um
  # scan morto por OOM ser reportado como "repo sem vulnerabilidade".
  if [ "$rc" -ge 2 ] || [ "$rc" -lt 0 ]; then
    echo "ERRO(exit=$rc)"; return 1
  fi
  python3 -c "import json,sys; print(len(json.load(open(sys.argv[1])).get('results',[])))" "$out"
}

echo "ruleset: $RULESET"
echo
echo "CODIGO VULNERAVEL (recall -- maior e melhor)"
total=0
for t in vulpy/bad dvpwa vflask dvws nodegoat; do
  n="$(scan "$t")"
  printf "  %-12s %s\n" "$t" "$n"
  [[ "$n" =~ ^[0-9]+$ ]] && total=$((total + n))
done
printf "  %-12s %s\n" "TOTAL" "$total"
echo
echo "vulpy/good -- PARCIALMENTE endurecido, NAO e negativo limpo."
echo "Investigue cada hit lendo a linha; nao presuma falso positivo."
printf "  %-12s %s\n" "vulpy/good" "$(scan vulpy/good)"
echo
echo "Piso de regressao: o SQL injection de vulpy/bad/db.py:19"
echo "(interpolacao %-format dentro de helper, sem taint rastreavel do request)"
echo "deve aparecer. v1.1.0 nao pegava; v1.2.0 pega."
