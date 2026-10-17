# Regras para manutenção de `docs/`

Este é um **ponto de entrada ativo** de instruções para o Documentador. A missão inicial de auditoria geral, com instruções completas de 2026-10-15/16, foi integralmente preservada em [HISTORY/PROJECT_HANDOFFS.md](HISTORY/PROJECT_HANDOFFS.md#source-docs-agents-md).

1. Leia [AGENTS.md](../AGENTS.md), [README.md](README.md), [RESEARCH_STATUS.md](RESEARCH_STATUS.md) e, se houver pesquisa em curso, [research/COORDINATION.md](../research/COORDINATION.md).
2. **Cifra é a única investigação aberta.** Movimento `0x035F` e ações `0x0437`/`0x0438`/`0x0AF4` funcionam conforme confirmação do responsável; estudos detalhados encerrados estão em [HISTORY/MOVEMENT_COMPLETE.md](HISTORY/MOVEMENT_COMPLETE.md) e [HISTORY/ACTIONS_COMPLETE.md](HISTORY/ACTIONS_COMPLETE.md).
3. Preserve provas com fonte, data, build, sessão sanitizada, `arquivo:linha`, resultados negativos, limites, hipóteses concorrentes e classificação **OBSERVADO / INFERIDO / HIPÓTESE / NÃO VERIFICADO / REFUTADO**. Relato do responsável e inspeção estática não equivalem a teste live reexecutado.
4. Não reescreva os corpos históricos incorporados entre os marcadores `BEGIN ORIGINAL` e `END ORIGINAL`. Ao arquivar novas fontes, registre o caminho, blob SHA e destino em [README.md](README.md).
5. Não edite a execução, testes de produção, configurações intencionais ou scripts de pesquisa em tarefa puramente documental. Preserve `inject = true` e `inject-call = true` em `relay_capture.conf`.
6. Use [CIPHER_INVESTIGATION.md](CIPHER_INVESTIGATION.md) para o trabalho científico ativo; o histórico de sessões permanece separado dos fatos reproduzidos. Não publique credenciais, GIDs de sessão ou capturas cruas.
7. Valide links e documentação; execute `python3 scripts/validate-research.py`, `python3 scripts/validate-codex.py`, `bash scripts/test-offline.sh` e `git diff --check` quando houver checkout executável. Não interprete teste offline como confirmação no cliente.
8. Comunique: resultado, arquivos, evidência, verificações PASS/FAIL/NOT RUN, riscos e próxima decisão. Nenhum push ou experimento ao vivo decorre automaticamente da documentação.
