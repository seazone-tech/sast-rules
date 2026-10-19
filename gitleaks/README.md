# gitleaks/ — regras da trava de segredos da Seazone

`seazone.toml` é a **fonte única** das regras de segredo da Seazone. Ela estende a config padrão do
gitleaks 8.30.1 (`[extend] useDefault = true`).

## Quem usa

- **A trava de segredos no Claude e no git das máquinas** (plugin `geral` do `seazone-skills`). O plugin
  leva uma cópia em `geral/lib/trava_segredos/dados/seazone-gitleaks.toml`, e o CI de lá confere se ela
  está igual a esta.
- **O job `segredos` do SAST reutilizável** (`seazone-tech/.github`, `sast.yml`), que roda nos PRs. O
  `resultado_ci.py` daqui lê o relatório: nível 1 reprova, nível 2 avisa e o valor nunca aparece.

## Níveis

- **Nível 1 (barra):** toda regra sem etiqueta. É o formato de um provedor, uma regra da Seazone ou um arquivo
  proibido pelo nome.
- **Nível 2 (pergunta):** regras com `tags = ["suspeita"]`. São a genérica, JWT que não é do Supabase, `curl`
  com header de autorização, `.har`, `.sqlite`/`.bak` e kubeconfig pelo nome. A trava pergunta à pessoa, e
  o CI só avisa.

## O que esta config faz além da padrão

1. **Supabase:**
   - a chave `anon` passa (é pública, e o Lovable commita ela);
   - a `service_role` barra;
   - `sb_secret_` e `sbp_` têm regra própria.
2. **Formatos da casa e de 2026:**
   - URL de banco com senha e senha escrita à mão;
   - chave `sk-` do hub LiteLLM e token OAuth do Claude Code;
   - Gemini `AQ.`, Cloudflare `cfut_`/`cfat_`/`cfast_` e `ghs_` novo;
   - Coolify, Asaas, Mercado Pago, Pagar.me, Z-API e outros.
3. **Menos falso alarme:**
   - hash de imagem no gitops;
   - nome de variável;
   - campo `"key"` (Pipedrive, i18n);
   - palavras em português com "api" no meio;
   - valores de exemplo óbvios.
4. **Ponto cego do fim da chave:** 149 regras padrão passam a aceitar a chave seguida de `)`, `,`, `}` ou `]`.
   Esse bloco é gerado por `atualizar_fim_da_chave.py`.
5. **Arquivos que nunca vão pro git:** `.claude/settings.local.json`, `.env.local`, `.netrc`, histórico de
   terminal, dump de banco, `.tfstate`, chave SSH e outros.

## Calibração (19/10/2026)

| | regras padrão | seazone.toml |
|---|---|---|
| Banco Seazone (79 segredos + 39 limpos) | 46/79, 7 falsos alarmes | 79/79, 0 falsos alarmes |
| Banco de formatos dos provedores (96 casos) | 55 certos | 96 certos |
| 4.581 commits de 3 meses em 198 repos | 151 barrados (a maioria falso) | 19 barrados (16 vazamentos prováveis) + 36 perguntas |

Os bancos de casos ficam nos testes do plugin (`seazone-skills`, `geral/tests/`).

## Mudar uma regra

1. Edite `seazone.toml` aqui, num PR (o CODEOWNERS pede revisão do SRE).
2. Copie o arquivo para o plugin `geral` do `seazone-skills`. Regere o filtro rápido de lá com
   `PYTHONPATH=geral/lib python3 -m trava_segredos.filtro` e rode os testes (`geral/tests`).

## Subir a versão do gitleaks

```bash
curl -fsSL https://raw.githubusercontent.com/gitleaks/gitleaks/v<versão>/config/gitleaks.toml -o /tmp/padrao.toml
python3 gitleaks/atualizar_fim_da_chave.py /tmp/padrao.toml <versão>
```

Depois, atualize a versão e os sha256 fixados em:

- no plugin: `geral/lib/trava_segredos/gitleaks.py` e `dados/gitleaks-padrao-*.toml.gz`;
- no SAST reutilizável: `seazone-tech/.github`.
