# Benchmark externo do ruleset

## O problema que isto resolve

A validacao anterior do `pr-blocking` era **circular**: o canario de eficacia
media as regras contra fixtures escritas a partir das proprias regras. Recall
aparecia alto por construcao, e nenhum gap podia ser descoberto -- se a regra
nao existia, a fixture correspondente tambem nao.

Rodar o ruleset contra aplicacoes vulneraveis de terceiros achou, na primeira
execucao, um gap que o canario nunca acharia.

## O gap encontrado

`vulpy/bad/db.py:19` -- SQL injection de manual:

```python
c.execute("INSERT INTO users (user, password, failures) VALUES ('%s', '%s', '%d')" % (u, p, 0))
```

O `pr-blocking` v1.1.0 rodou 21 regras de Python nesse arquivo e **nao pegou**.
O gate teria aprovado esse PR.

A causa nao era falta de regra: `formatted-sql-query` e
`sqlalchemy-execute-raw-query` estavam no corpus vendorizado, mas em
`deep-scan-audit/` e `deep-scan/` -- fora do tier que bloqueia. Erro de
curadoria, nao de cobertura.

O `pr-blocking` ja tinha `tainted-sql-string`, que e baseada em taint e exige
caminho rastreavel de uma source do request ate o sink. Aqui `u` e `p` chegam
como parametros de funcao auxiliar, sem source rastreavel -- a regra de taint
nao dispara. Regra baseada em padrao pega; regra baseada em taint nao. **Cobrir
uma CWE exige as duas abordagens, nao uma.**

## Escolha dos corpora

Pela stack real da frota (`seazone-tech`, repos ativos, jul/2026):

| Linguagem  | Repos | %     |
|------------|-------|-------|
| Python     | 297   | 36,0% |
| TypeScript | 290   | 35,2% |
| JavaScript | 43    | 5,2%  |
| Java       | 0     | ~0%   |

Por isso o **OWASP Benchmark nao e usado**: ele e Java-only. Medir recall nele
produziria um numero alto e irrelevante -- exatamente o vicio que este harness
existe para eliminar. Os corpora escolhidos sao Python e JS/TS.

## O que o benchmark mede -- e o que NAO mede

**MEDE recall.** O ruleset dispara em vulnerabilidade conhecida, escrita por
terceiro, sem relacao com as nossas regras.

**NAO MEDE precisao.** Nenhum corpus aqui e um negativo limpo. O `vulpy/good`
em particular **nao e "codigo seguro"** -- e a mesma aplicacao com *algumas*
correcoes. Ele mantem:

- `vulpy.py:53` e `vulpy-ssl.py:29` -- `app.run(debug=True, ...)`
- `libapi.py:24` -- JWT assinado com secret hardcoded
- `libuser.py:61` -- SQL interpolado com `%`, identico ao de `bad/db.py:19`

Consequencia pratica: contar hits no lado `good` como falso positivo da numero
errado. Na primeira analise deste benchmark, `formatted-sql-query` e
`sqlalchemy-execute-raw-query` foram descartadas por "1 FP" que, ao ler a
linha, era vulnerabilidade real -- as duas regras mais valiosas do lote quase
ficaram de fora por isso. Pelo mesmo motivo, `debug-enabled` (4 hits vulneravel
/ 4 seguro) e `jwt-python-hardcoded-secret` (2/2) **nao** sao ruido: disparam
nos dois lados porque o problema esta nos dois lados.

**Precisao exige revisao humana dos achados reais da frota.** Nao ha atalho
automatico, e este harness nao substitui isso.

## Resultado v1.1.0 -> v1.2.0

Mesmas exclusoes, mesmos corpora:

| Corpus     | v1.1.0 | v1.2.0 |
|------------|--------|--------|
| vulpy/bad  | 2      | 14     |
| dvpwa      | 2      | 15     |
| vflask     | 3      | 16     |
| dvws       | 4      | 25     |
| nodegoat   | 4      | 8      |
| **TOTAL**  | **15** | **78** |

O SQL injection de `db.py:19` passou a ser detectado pelas duas regras
promovidas.

## Determinismo: uma armadilha real

O opengrep le `.semgrepignore` do **diretorio de trabalho atual**, nao do
diretorio alvo. E a simples existencia desse arquivo **substitui a lista de
ignore default** -- que e o que normalmente exclui bundle minificado.

Como este repo versiona um `.semgrepignore` (para `.pilot/canary/`), o mesmo
comando dava resultados diferentes conforme o cwd:

```
cwd = raiz do sast-rules  ->  dvpwa: 40 achados  (jquery-3.2.1.min.js entrou)
cwd = /tmp                ->  dvpwa: 15 achados
```

Por isso `run.sh` passa as exclusoes **explicitamente** em vez de herdar. Sem
isso o harness reportaria regressao fantasma dependendo de onde foi invocado.

O mesmo mecanismo vale para o gate de PR: **um repo que criar seu proprio
`.semgrepignore` perde silenciosamente todas as exclusoes default.** Na frota
isso nao esta acontecendo hoje (0 de 5.877 achados em caminho
vendorizado/minificado), mas e um risco a monitorar.

## Como rodar

```bash
opengrep --version          # v1.25.0 na validacao acima
./benchmark/run.sh pr-blocking
```

Clona os corpora em um tmpdir (ou em `$BENCH_WORK`). Interpretacao:

- **Queda no TOTAL** entre versoes = regressao de recall. Investigar.
- **Alta em `vulpy/good`** = investigar CADA hit lendo a linha antes de chamar
  de falso positivo. Ver a secao acima.
