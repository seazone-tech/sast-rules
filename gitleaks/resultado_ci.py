"""Lê o relatório do gitleaks (gerado com --redact) no CI e decide o check.

- Nível 1 (regra sem etiqueta): anotação de erro na linha e o check reprova.
- Nível 2 (tags = ["suspeita"]): anotação de aviso, o check passa.
- Exceção no .gitleaksignore vale com ou sem o commit (arquivo:regra:linha ou commit:arquivo:regra:linha).
- Mudança no .gitleaksignore/.gitleaks.toml dentro do PR vira aviso (pede revisão humana).
Nunca imprime o valor: só regra, arquivo, linha e commit.

Uso: python3 resultado_ci.py <relatorio.json> [<base>..<head>]
"""
import json
import os
import subprocess
import sys
from pathlib import Path


def _prop(valor: str) -> str:
    return str(valor).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def _msg(valor: str) -> str:
    return str(valor).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _excecoes() -> set:
    arquivo = Path(".gitleaksignore")
    if not arquivo.is_file():
        return set()
    return {l.strip() for l in arquivo.read_text(errors="ignore").splitlines() if l.strip() and not l.lstrip().startswith("#")}


def main() -> int:
    relatorio = Path(sys.argv[1])
    intervalo = sys.argv[2] if len(sys.argv) > 2 else ""
    if not relatorio.is_file():
        print("::error::o gitleaks não gerou o relatório; o check falha por segurança (veja o passo anterior).")
        return 1
    excecoes = _excecoes()
    nivel1, nivel2 = [], []
    for a in json.loads(relatorio.read_text() or "[]") or []:
        if f"{a.get('File')}:{a.get('RuleID')}:{a.get('StartLine')}" in excecoes:
            continue
        (nivel2 if "suspeita" in (a.get("Tags") or []) else nivel1).append(a)
    for a in nivel1:
        print(f"::error file={_prop(a.get('File'))},line={a.get('StartLine')},title={_prop('Segredo (' + a.get('RuleID', '') + ')')}::"
              + _msg(f"{a.get('Description', '').rstrip('.')}. Tire o valor do código (use variável de ambiente/SSM) e troque a chave: "
                     "o commit continua no histórico."))
    for a in nivel2:
        print(f"::warning file={_prop(a.get('File'))},line={a.get('StartLine')},title={_prop('Possível segredo (' + a.get('RuleID', '') + ')')}::"
              + _msg(f"{a.get('Description', '').rstrip('.')}. Confira se é segredo; se não for, registre a exceção com /trava-segredos excecao."))
    if intervalo:
        r = subprocess.run(["git", "diff", "--name-only", intervalo], capture_output=True, text=True)
        mexidos = [n for n in r.stdout.splitlines() if Path(n).name in (".gitleaksignore", ".gitleaks.toml")]
        if mexidos:
            print("::warning::este PR muda a lista de exceções ou as regras de segredo ("
                  + ", ".join(mexidos) + "): precisa de revisão de uma pessoa.")
    resumo = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumo and (nivel1 or nivel2):
        with open(resumo, "a", encoding="utf-8") as f:
            f.write("## Segredos\n\n| nível | regra | arquivo | linha | commit |\n|---|---|---|---|---|\n")
            for nivel, lista in (("barra", nivel1), ("pergunta", nivel2)):
                for a in lista:
                    f.write(f"| {nivel} | {a.get('RuleID')} | `{a.get('File')}` | {a.get('StartLine')} | `{str(a.get('Commit', ''))[:10]}` |\n")
            f.write("\nO valor nunca aparece aqui. Achou segredo? Tire do código **e troque a chave**: apagar não basta.\n"
                    "Falso alarme? `/trava-segredos excecao` no Claude, ou uma linha `arquivo:regra:linha` no `.gitleaksignore` (com motivo, revisado no PR).\n")
    print(f"segredos: {len(nivel1)} barrado(s), {len(nivel2)} suspeita(s)")
    return 1 if nivel1 else 0


if __name__ == "__main__":
    sys.exit(main())
