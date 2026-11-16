"""Banco das regras chave-curta, chave-de-acesso-curta e senha-ou-codigo-curto, com o gitleaks de verdade.

Rodar: python3 -m unittest discover -s gitleaks

Caso de 12/11/2026 (seazone-skills#1029): numa tabela de processos, "<número> - Chave <8 letras e números>"
passou pela trava. Os valores daqui são inventados e montados na hora (J(...)): se o texto deste arquivo
formasse uma chave, a própria trava barraria este repo.

Sem gitleaks no PATH (ou na variável GITLEAKS), os testes são pulados. O CI (validate-gitleaks.yml) instala o
gitleaks fixado antes de rodar.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REGRAS = Path(__file__).resolve().parent / "seazone.toml"
REGRAS_CURTAS = "chave-curta,chave-de-acesso-curta,senha-ou-codigo-curto"
J = "".join
V = J(["K7Q", "M2R9P"])  # inventado, no formato do caso: 8 caracteres com letras e números

# (id, conteúdo): alguma das três regras TEM que pegar
POSITIVOS = [
    ("tabela-do-caso", f"| 40213/2026 - Chave {V} | SZS |  | Tributário | — | — | número não CNJ (administrativo) |  | legado |\n"),
    ("dois-pontos", f"Chave: {V}\n"),
    ("traco", f"Processo 123/2026 - chave - {V}\n"),
    ("de-acesso", f"Chave de acesso: {V}\n"),
    ("de-consulta", f"chave de consulta {V} (portal da prefeitura)\n"),
    ("tabela-duas-colunas", f"| Chave de consulta | {V} |\n"),
    ("entre-crases", f"a chave `{V}` vence em 2027\n"),
    ("igual", f"chave={V}\n"),
    ("minusculas", f"chave {V.lower()}\n"),
    ("seis", J(["chave 7QM", "2R9\n"])),
    ("dezesseis", J(["chave K7Q", "M2R9PZ4TWB8LN\n"])),
    # entre crases, com maiúscula e número misturados: não é nome de campo
    ("crase-com-maiuscula", J(["Chave: `hT6w", "N2rX`\n"])),
    # "123" no meio de uma chave sorteada não faz dela um molde
    ("molde-no-meio", J(["Chave Q7W1", "23ZK\n"])),
    # "chave de acesso/consulta" já diz o que é: letras e depois números também conta
    ("de-acesso-letras-e-numeros", J(["Chave de acesso: KQTR", "4821\n"])),
    # a senha e o código de acesso continuam como o #18 deixou: senha fraca também é vazamento
    ("senha-fraca", J(["senha: Mar", "ia2024\n"])),
    ("codigo-de-acesso", J(["código de acesso: QTR", "0412\n"])),
]

# (id, conteúdo): nenhuma das três pode pegar
NEGATIVOS = [
    ("pix-email", "Chave PIX: financeiro@seazone.com.br\n"),
    ("pix-cpf", "Chave PIX: 123.456.789-09\n"),
    ("pix-cpf-sem-pontos", "chave pix 12345678909\n"),
    ("pix-cnpj", "Chave PIX - 12.345.678/0001-90\n"),
    ("nfe-44-digitos", "Chave de acesso: 35190512345678000190550010000012341000012345\n"),
    ("nfe-em-blocos", "Chave de acesso 3519 0512 3456 7800 0190 5500 1000 0012 3410 0001 2345\n"),
    ("estrangeira", "a coluna imovel_id é chave estrangeira para imoveis\n"),
    ("primaria", "chave primária composta (imovel_id, data)\n"),
    ("dezessete", J(["chave K7Q", "M2R9PZ4TWB8LNX\n"])),
    ("uuid", "chave 3f2b8c1a-1d2e-4f5a-9b8c-7d6e5f4a3b2c\n"),
    ("codigo-entre-aspas", "{ chave: 'anterior12', longo: '12m anteriores' }\n"),
    ("campo-entre-crases", "não tem chave `expb2b` no mapa\n"),
    ("hash-cortado", "(campo 12924, chave 3fa9c0d1...)\n"),
    ("id-de-chave-do-gcp", "Desativar a chave 1f3b27 da conta de serviço\n"),
    ("commit", "Commits chave: 4e1d9c2 (scheduler)\n"),
    ("codigo-de-imovel", "Retirar a chave QTR0412: na portaria\n"),
    ("nome-tecnico", "criptografado com chave AES256; gere uma chave ed25519 com o ssh-keygen\n"),
    ("id-do-slack", "colapsam na mesma chave=C09KQ7TZ3LM|kubernetes\n"),
    ("molde", "Chave: ABC123\n"),
]


def _gitleaks():
    return os.environ.get("GITLEAKS") or shutil.which("gitleaks")


def _achados(casos):
    """Roda as três regras uma vez sobre todos os casos (um arquivo por caso) e devolve os ids pegos."""
    with tempfile.TemporaryDirectory() as pasta:
        pasta = Path(pasta)
        for cid, conteudo in casos:
            (pasta / f"{cid}.md").write_text(conteudo, encoding="utf-8")
        relatorio = pasta / "relatorio.json"
        subprocess.run([_gitleaks(), "dir", str(pasta), "--config", str(REGRAS),
                        "--enable-rule", REGRAS_CURTAS,
                        "--no-banner", "--log-level", "error", "--exit-code", "0",
                        "--report-format", "json", "--report-path", str(relatorio)], check=True)
        return {Path(a["File"]).stem for a in json.loads(relatorio.read_text(encoding="utf-8"))}


@unittest.skipUnless(_gitleaks(), "gitleaks não instalado")
class ChaveDeAcessoCurta(unittest.TestCase):
    def test_pega_a_chave_curta(self):
        self.assertEqual(sorted(c for c, _ in POSITIVOS if c not in _achados(POSITIVOS)), [])

    def test_nao_pega_texto_comum(self):
        self.assertEqual(sorted(_achados(NEGATIVOS)), [])


if __name__ == "__main__":
    unittest.main()
