"""Regera o bloco "CORREÇÃO DO FIM DA CHAVE" do seazone.toml a partir da config padrão do gitleaks.

Por quê: 151 das 222 regras padrão do gitleaks 8.30.1 só reconhecem a chave se ela vier seguida de
aspas, espaço, ";" ou fim de linha. Chave sem aspas seguida de ")", "," ou "}" passava
(ex.: createClient(url, CHAVE)). Este bloco sobrescreve só a regex dessas regras, aceitando também
esses finais; o resto da regra padrão (palavras-chave, entropia, exceções) continua valendo.

Uso, ao subir a versão do gitleaks:
    curl -fsSL https://raw.githubusercontent.com/gitleaks/gitleaks/v<versão>/config/gitleaks.toml -o /tmp/padrao.toml
    python3 gitleaks/atualizar_fim_da_chave.py /tmp/padrao.toml <versão>
Depois copie o seazone.toml para o plugin geral do seazone-skills e rode os testes de lá.
"""
import sys
import tomllib
from pathlib import Path

VELHO = "(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
# Depois da chave pode vir também: ) , } ] (código), & (URL), < > (XML/HTML), | (tabela), # (âncora), * (negrito),
# . ! ? (fim de frase), \ (string escapada), / (caminho de URL), @ e : (usuario:token@host).
NOVO = "(?:[\\x60'\"\\s;,)}\\]&<>|#*.!?\\\\/@:]|$)"
# Entre o nome e o valor: | sozinho (tabela markdown) e ] antes do sinal (os.environ['X'] = ..., config["X"] = ...).
TROCAS = (
    ("(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)", "(?:=|>|:{1,3}=|\\|\\|?|:|=>|\\?=|,)"),
    ("[\\s'\"]{0,3}", "[\\s'\"\\]]{0,4}"),
)
# generic-api-key: ampliar o fim só trouxe ruído (medido em 4.581 commits). jwt: ajustada na seção de ajustes.
FORA = {"generic-api-key", "jwt"}
MARCO = "# ============ CORREÇÃO DO FIM DA CHAVE (gerado) ============"


def main() -> None:
    padrao = tomllib.loads(Path(sys.argv[1]).read_text())
    versao = sys.argv[2] if len(sys.argv) > 2 else "?"
    alvo = Path(__file__).with_name("seazone.toml")
    cabeca = alvo.read_text().rsplit(MARCO, 1)[0]
    linhas = [
        MARCO,
        "# Nas regras padrão, a chave só casava se viesse seguida de aspas, espaço, ; ou fim de linha.",
        f"# Aqui aceitamos também ) , }} ] & < > | # * . ! ? \\ / @ : depois da chave, e | ou ] antes do sinal. Gerado de gitleaks {versao}.",
    ]
    for regra in padrao["rules"]:
        if VELHO in regra.get("regex", "") and regra["id"] not in FORA:
            regex = regra["regex"].replace(VELHO, NOVO)
            for velho, novo in TROCAS:
                regex = regex.replace(velho, novo)
            linhas += ["[[rules]]", f'id = "{regra["id"]}"', "regex = '''" + regex + "'''"]
    alvo.write_text(cabeca + "\n".join(linhas) + "\n")
    print(f"{sum(1 for l in linhas if l == '[[rules]]')} regras com o fim da chave corrigido")


if __name__ == "__main__":
    main()
