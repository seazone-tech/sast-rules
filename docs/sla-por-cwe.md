# Proposta: amarrar o SLA em CWE, nao na severidade do fornecedor

**Status: proposta.** Nao implementada. Mudar o mapa do SLA e decisao de
produto, nao conserto de bug.

## O problema

O SLA de remediacao de 7/30/90 dias e derivado hoje do campo `severity` das
regras do `opengrep-rules`. Esse campo nao aguenta o peso.

As 573 regras de categoria `security` do corpus vendorizado tem `severity`,
`confidence` e `impact` preenchidos em **100%** dos casos -- cobertura nao e o
problema. O problema e que **os campos se contradizem entre si em 23 regras**:

| Contradicao        | Qtd | Exemplos |
|--------------------|-----|----------|
| `ERROR` + `impact: LOW`  | 22 | `tainted-sql-string`, `disabled-cert-validation`, `jwt-go-none-algorithm`, `grpc-server-insecure-connection`, `string-concat` |
| `INFO` + `impact: HIGH`  | 1  | `express-check-csurf-middleware-usage` |

`tainted-sql-string` e SQL injection marcada com impacto baixo. `INFO` num
middleware de CSRF ausente. Nao ha leitura em que os dois campos estejam certos
ao mesmo tempo, e por isso **a conclusao nao e "usar `impact` em vez de
`severity`"** -- e que nenhum dos dois campos, isolado, sustenta um SLA.

Consequencia concreta: hoje uma SQL injection e uma falha de validacao de
certificado entram no mesmo balde de 7 dias que qualquer outro `ERROR`, e um
CSRF ausente cai em 90 dias por ser `INFO`.

## A proposta

Derivar o balde de SLA da **classe de CWE**, que e taxonomia externa, estavel,
e nao muda quando o fornecedor reclassifica uma regra.

Viabilidade medida: **CWE presente em 479 de 479 regras `security`** (100%).

| Balde | Criterio | CWEs |
|-------|----------|------|
| **7 dias** | execucao/injecao com caminho direto a comprometimento | 89 (SQLi), 78 (command injection), 94/95/96 (code injection, eval, SSTI), 502 (deserializacao), 22 (path traversal), 798/259 (credencial hardcoded), 327 (cripto quebrada), 611 (XXE), 1321 (prototype pollution) |
| **30 dias** | explorável, mas exige interacao ou tem impacto contido | 79 (XSS), 601 (open redirect), 352 (CSRF), 1333 (ReDoS), 532 (exposicao em log), 345/347 (verificacao insuficiente), 384 (session fixation), 614/1004 (flags de cookie), 1236 (CSV injection) |
| **90 dias** | higiene e defesa em profundidade | todo o resto |

## O que isso muda na pratica

Medido sobre os 5.877 achados reais da frota (uniao dos dois prefixos de data
do run de 2026-07-26):

| Balde | Hoje (por `severity`) | Proposto (por CWE) |
|-------|----------------------|--------------------|
| 7 dias  | 958   | 1.182 |
| 30 dias | 3.304 | 1.136 |
| 90 dias | 697   | 2.641 |
| **sem balde** | **918** | **918** |

O balde de 30 dias hoje concentra 56% de tudo, o que o torna informativo de
menos para priorizar. A proposta esvazia o meio e empurra higiene para 90 dias,
mantendo o topo pequeno o suficiente para ser acionavel -- 1.182 achados em
7 dias ainda e muito, e provavelmente exige um corte adicional por
exploitabilidade, mas ao menos o corte passa a ser por classe de vulnerabilidade
em vez de por um campo que se contradiz.

## Buraco que a proposta NAO resolve

**918 achados (15,6%) nao tem CWE resolvivel e hoje nao caem em nenhum balde de
SLA.** Sao as regras `KSV*` do Trivy (config-scan de Kubernetes):

```
  70x KSV118    52x KSV020    52x KSV021    49x KSV003
  49x KSV004    49x KSV012    49x KSV014    49x KSV030
```

O Trivy nao emite CWE nessas regras -- ele usa a taxonomia AVD/KSV propria.
Qualquer mapa de SLA precisa de uma tabela explicita AVD/KSV -> balde, ou esses
achados continuam fora do processo independentemente de o resto ser corrigido.
Nao inventei esse mapeamento aqui porque ele precisa de decisao humana sobre o
que um `securityContext` permissivo vale em dias.

## Ressalva de metodo

Este documento mede **distribuicao**, nao **acerto**. Dizer que o balde de
7 dias esta "melhor" pressupoe que a minha atribuicao CWE -> balde esta certa,
e ela e um julgamento meu, nao um resultado medido. O que esta medido e:
a contradicao interna do metadata do fornecedor (23 regras), a cobertura de CWE
(479/479) e a redistribuicao acima.

Validar se o balde reflete risco real na Seazone exige um revisor humano de
seguranca -- a mesma dependencia que trava a divulgacao de taxa de ruido.
