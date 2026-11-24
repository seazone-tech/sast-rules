"""Vetores de teste públicos de RFC não são segredo: a trava não pergunta nem barra (caso de 23/11/2026).

Rodar: python3 -m unittest discover -s gitleaks

Em 23/11/2026 o commit de um teste de um repo interno parou numa confirmação da trava de segredos por causa do
exemplo da RFC 6455 (Sec-WebSocket-Key do handshake de exemplo, seção 1.3), que a regra generic-api-key pegou. Os
valores daqui são montados na hora (J(...)): se o texto deste arquivo formasse a linha do caso, a trava de quem não
tem esta regra ainda barraria o próprio repo.

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
J = "".join
RFC6455_CHAVE = J(["dGhlIHNhbXBsZSBu", "b25jZQ=="])  # RFC 6455, 1.3: "the sample nonce" em base64
RFC6455_ACEITE = J(["s3pPLMBiTxaQ9kYG", "zzhZRbK+xOo="])  # RFC 6455, 1.3: o Sec-WebSocket-Accept do exemplo
INVENTADA = J(["Qm9yZGFkb1ZhbG9y", "WHlaMjAyNnE="])  # mesmo formato, valor inventado: tem que continuar pego

POSITIVOS = [("chave-inventada", f'const headers = {{ "Sec-WebSocket-Key": "{INVENTADA}" }};\n')]
NEGATIVOS = [
    ("rfc6455-chave", f'const headers = {{ "Sec-WebSocket-Key": "{RFC6455_CHAVE}" }};\n'),
    ("rfc6455-aceite", f'expect(res.headers["sec-websocket-accept"]).toBe("{RFC6455_ACEITE}");\n'),
]


def _gitleaks():
    return os.environ.get("GITLEAKS") or shutil.which("gitleaks")


def _achados(casos):
    with tempfile.TemporaryDirectory() as pasta:
        pasta = Path(pasta)
        for cid, conteudo in casos:
            (pasta / f"{cid}.test.js").write_text(conteudo, encoding="utf-8")
        relatorio = pasta / "relatorio.json"
        subprocess.run([_gitleaks(), "dir", str(pasta), "--config", str(REGRAS),
                        "--no-banner", "--log-level", "error", "--exit-code", "0",
                        "--report-format", "json", "--report-path", str(relatorio)], check=True)
        return {Path(a["File"]).name.split(".")[0] for a in json.loads(relatorio.read_text(encoding="utf-8"))}


@unittest.skipUnless(_gitleaks(), "gitleaks não instalado")
class VetoresPublicos(unittest.TestCase):
    def test_exemplo_da_rfc6455_nao_e_segredo(self):
        self.assertEqual(sorted(_achados(NEGATIVOS)), [])

    def test_chave_inventada_no_mesmo_formato_segue_pega(self):
        self.assertEqual(sorted(c for c, _ in POSITIVOS if c not in _achados(POSITIVOS)), [])


if __name__ == "__main__":
    unittest.main()
