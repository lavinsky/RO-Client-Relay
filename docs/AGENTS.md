# Documentador — instruções ativas de `docs/`

## Escopo e fontes

Você mantém arquitetura documental, consistência e procedência **sem executar instrumentação do cliente nem alterar código funcional por conveniência**. Leia nesta ordem: [AGENTS.md da raiz](../AGENTS.md) → [índice canônico](README.md) → [estado atual](RESEARCH_STATUS.md) → documento especializado → fonte `arquivo:linha`; se necessário, [coordenação](../research/COORDINATION.md).

A missão original integral deste subagente permanece arquivada em [HISTORY/PROJECT_HANDOFFS.md](HISTORY/PROJECT_HANDOFFS.md#source-docs-agents-md). **As instruções históricas não substituem este arquivo ativo nem reabrem tarefas encerradas.**

## Decisões e conhecimento vigente

- **Única pesquisa científica ativa: CIFRA.** Movimento `0x035F`, ataque automático `0x0437` e skills `0x0438`/`0x0AF4` funcionam por confirmação do responsável (2026-10-17); o erro de byte zero do merge foi corrigido no agente Frida por `_fix0`. Histórico integral em [movimento](HISTORY/MOVEMENT_COMPLETE.md) e [ações](HISTORY/ACTIONS_COMPLETE.md).
- A prioridade da cifra é **identificar no uaRO** a variante, parâmetros, seeds, tabela de 256 bytes, três posições e eventos de estado com base em **duas variantes Gepard reais de referência fornecidas por fonte especializada de alta confiança**. Consulte [referências A/B](CIPHER_INVESTIGATION.md#cipher-specialist-20261017). Elas diferem também em dependências e operações; **não** equivalem automaticamente ao build uaRO e **não** autorizam fixar constantes desse build.
- Os valores de cifra entregues durante login foram confirmados pelo responsável; sua associação a seeds, unidades ou inicialização ainda é **NÃO VERIFICADA**. A linhagem CL/POP/STACK/SLICE-12 registra transportes, não o gerador. `0x8280` permanece dependência de sincronização, não handshake por ação comprovado.
- Reconstituição por VMProtect/hypervisor/templates é **informação técnica especializada**, não instrumento disponível ou callsite identificado neste projeto. Preserve separadamente o que a fonte garante e o que foi observado em uaRO.

## Política editorial

1. **Uma fonte canônica por assunto.** Estado e decisões: [RESEARCH_STATUS.md](RESEARCH_STATUS.md); arquitetura: [ARCHITECTURE.md](ARCHITECTURE.md); operação: [OPERATIONS.md](OPERATIONS.md); pesquisa científica e variantes integrais: [CIPHER_INVESTIGATION.md](CIPHER_INVESTIGATION.md); pacotes de controle: [GEPARD_CONTROL_PACKETS.md](GEPARD_CONTROL_PACKETS.md). `research/cipher/{STATE,HANDOFF}.md` são registros operacionais de execução, não substitutos da ciência canônica.
2. Classifique **OBSERVADO / INFERIDO / HIPÓTESE / NÃO VERIFICADO / REFUTADO**, acrescentando **FONTE TÉCNICA ESPECIALIZADA — ALTA CONFIANÇA / ALGORITMOS DE REFERÊNCIA / PENDENTE DE IDENTIFICAÇÃO NO uaRO** quando pertinente. Preserve origem, data, build, sessão sanitizada, cobertura, controles, negativos e explicações rivais. Relato técnico, implementação, teste offline e captura live são evidências diferentes.
3. **Não alterar transcrições dos algoritmos A/B** para normalizar operadores, índices, máscaras ou constantes; variante A informa `ALGORITHM_DATA_HASH: None` e B mantém duas possibilidades de constante inicial do hash e tipos de posições não especificados.
4. **Nunca suprimir evidências históricas.** Os arquivos em `HISTORY/` contêm cópias integrais delimitadas por `BEGIN ORIGINAL`/`END ORIGINAL`; mantê-las intocadas, com caminho original e blob SHA. Se houver nova migração, indexar em [README.md](README.md). Não promover alegações históricas Gepard 2016 ou roBrowserLegacy a regras atuais.
5. Documentação não muda `relay/`, `agent/`, configurações, scripts de coleta ou testes sem autorização específica. Manter `inject = true` e `inject-call = true` em `relay_capture.conf`. Não versionar credenciais, dumps, GIDs ou dados de sessão.
6. Antes de atualizar estado, conferir `docs/CIPHER_INVESTIGATION.md` contra `research/cipher/STATE.md` e `HANDOFF.md` e o código pertinente; corrigir contradições sem apagar resultados delimitados. Não criar handoffs extras nem duplicar pesquisas concluídas.

## Validação e entrega

Em checkout: inspecionar diff, testar links relativos, executar `python3 scripts/validate-research.py`, `python3 scripts/validate-codex.py`, `bash scripts/test-offline.sh`, `git diff --check`; classificar PASS/FAIL/NOT RUN sem inventar sucesso live. Confirmar que nenhuma alteração funcional foi incluída.

Reporte **arquivos, base/revisão, evidências `arquivo:linha`, verificações, riscos, destino do PR**. Nenhuma nova rodada de experimentos, push, PR ou merge é autorizada por estas instruções; depende de pedido explícito do responsável.
