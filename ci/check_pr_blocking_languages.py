#!/usr/bin/env python3
"""Falha se alguma regra de pr-blocking/ declarar linguagem fora do conjunto
esperado.

POR QUE ISTO EXISTE

O caller do gate nos repos da org usa um filtro POSITIVO de caminhos:

    on:
      pull_request:
        paths: ['**/*.py','**/*.js','**/*.ts','**/*.go', ...]

Esse filtro existe porque o GitHub cobra Actions em minutos inteiros por job --
52% dos PRs da frota nao tocam nenhum arquivo dessas linguagens, e rodar o scan
neles gastava ~620 min/mes para encontrar nada por construcao.

"Por construcao" e a parte fragil: hoje as 68 regras de pr-blocking cobrem
apenas python, javascript, typescript e go, entao mudanca em .yml/.json/.md NAO
PODE gerar achado. No dia em que alguem promover para pr-blocking uma regra de
terraform, yaml, dockerfile ou generic, o filtro passa a esconder achados em
silencio -- e ninguem descobre, porque a ausencia de achado e indistinguivel de
codigo limpo.

Um comentario no caller de 481 repos nao segura esse invariante. Este teste
segura: promover regra de outra linguagem quebra o CI aqui, e a mensagem diz
exatamente o que atualizar do outro lado.
"""
import glob
import os
import sys

import yaml

# Linguagens cujas extensoes o filtro de caminho do caller cobre.
PERMITIDAS = {"python", "javascript", "typescript", "go"}

# Mantido em sincronia com o `paths:` do caller (workflow-templates/seazone-sast.yml).
EXTENSOES_DO_CALLER = (
    "py pyi js jsx mjs cjs ts tsx mts cts go"
)


def main() -> int:
    raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    infratores = []
    total = 0
    for caminho in glob.glob(os.path.join(raiz, "pr-blocking", "**", "*.y*ml"), recursive=True):
        try:
            doc = yaml.safe_load(open(caminho)) or {}
        except yaml.YAMLError as exc:
            print(f"::error file={caminho}::YAML invalido: {exc}")
            return 1
        for regra in doc.get("rules", []):
            total += 1
            langs = {str(x).lower() for x in (regra.get("languages") or [])}
            fora = langs - PERMITIDAS
            if fora:
                infratores.append((regra.get("id", "?"), sorted(fora), os.path.relpath(caminho, raiz)))

    print(f"regras em pr-blocking/: {total}")
    print(f"linguagens permitidas: {', '.join(sorted(PERMITIDAS))}")
    if not infratores:
        print("OK -- nenhuma regra fora do conjunto coberto pelo filtro de caminho do caller.")
        return 0

    print()
    print("FALHOU: regra(s) em pr-blocking/ declaram linguagem que o filtro de")
    print("caminho do caller NAO cobre. Se isto for merged, o gate deixara de")
    print("rodar em PRs que tocam essas linguagens, SEM AVISO.")
    print()
    for rid, fora, arq in infratores:
        print(f"  {rid}")
        print(f"    linguagem fora do conjunto: {', '.join(fora)}")
        print(f"    arquivo: {arq}")
    print()
    print("Para resolver, escolha um:")
    print("  a) mover a regra para deep-scan/ (o scanner central nao usa filtro de caminho)")
    print("  b) adicionar as extensoes da linguagem ao `paths:` do caller em TODOS os")
    print("     repos da org, e a PERMITIDAS aqui. Hoje o caller cobre:")
    print(f"     {EXTENSOES_DO_CALLER}")
    print("     Ha ~481 callers; ha um procedimento de push direto com [skip ci] que")
    print("     faz isso sem custo de Actions -- ver o historico de SRE-46.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
