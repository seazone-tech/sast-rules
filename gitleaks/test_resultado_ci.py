"""Testes do resultado_ci.py (só biblioteca padrão): python3 -m unittest discover -s gitleaks"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "resultado_ci.py"


def rodar(achados, gitleaksignore=None):
    with tempfile.TemporaryDirectory() as pasta:
        pasta = Path(pasta)
        (pasta / "relatorio.json").write_text(json.dumps(achados), encoding="utf-8")
        if gitleaksignore is not None:
            (pasta / ".gitleaksignore").write_text(gitleaksignore, encoding="utf-8")
        return subprocess.run([sys.executable, str(SCRIPT), "relatorio.json"], cwd=pasta, capture_output=True,
                              text=True, env={"PATH": "/usr/bin:/bin"})


ACHADO = {"File": "src/a.py", "RuleID": "chave-sk", "StartLine": 3, "Commit": "abc123", "Tags": [],
          "Description": "Chave do hub"}


class ResultadoCI(unittest.TestCase):
    def test_nivel_1_reprova(self):
        r = rodar([ACHADO])
        self.assertEqual(r.returncode, 1)
        self.assertIn("::error file=src/a.py,line=3", r.stdout)

    def test_suspeita_so_avisa(self):
        r = rodar([{**ACHADO, "Tags": ["suspeita"]}])
        self.assertEqual(r.returncode, 0)
        self.assertIn("::warning", r.stdout)

    def test_excecao_sem_commit_vale(self):
        self.assertEqual(rodar([ACHADO], "# motivo\nsrc/a.py:chave-sk:3\n").returncode, 0)

    def test_excecao_com_commit_vale(self):
        self.assertEqual(rodar([ACHADO], "abc123:src/a.py:chave-sk:3\n").returncode, 0)

    def test_excecao_de_outro_commit_nao_vale(self):
        self.assertEqual(rodar([ACHADO], "fff999:src/a.py:chave-sk:3\n").returncode, 1)


if __name__ == "__main__":
    unittest.main()
