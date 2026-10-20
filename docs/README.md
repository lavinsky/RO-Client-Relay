# Documentação técnica — RO-Client-Relay

**Entrada principal de documentação.** Em 2026-10-17, as pesquisas de **movimento `0x035F` e ações `0x0437`/`0x0438`/`0x0AF4` foram encerradas como funcionais** pelo responsável. A **única investigação criptográfica científica ativa é a cifra uaRO/Gepard**; a trilha de engenharia de recuperação do plaintext recebido é distinta e está documentada separadamente. O defeito do ataque automático era a reescrita incorreta do primeiro byte pelo store do scrambler, corrigida em `agent/relay_hook_linux.js:481-534` (não seleção de alvo). [Estado canônico](RESEARCH_STATUS.md).

## Ordem de leitura

Para toda tarefa: [AGENTS.md do projeto](../AGENTS.md) → [Estado e decisões](RESEARCH_STATUS.md) → documento temático → fonte específica (`arquivo:linha`). A pesquisa ativa também lê [research/COORDINATION.md](../research/COORDINATION.md), [research/cipher/STATE.md](../research/cipher/STATE.md) e o [handoff corrente](../research/cipher/HANDOFF.md).

## Auditoria de atualização — 2026-10-20

A comparação recente foi feita contra `origin/main@9ee7ef5`, não contra a `main` local desatualizada. O estado atualizado de recepção, guardas TX/RX, novas sondas, watchdog e configurações está em [RESEARCH_STATUS](RESEARCH_STATUS.md#revisão-do-checkout--2026-10-20), com contratos em [ARCHITECTURE](ARCHITECTURE.md#15-recepção-dinâmica-novos-ids-e-proveniência-revisão-2026-10-20), operação em [OPERATIONS](OPERATIONS.md) e histórico técnico da ring em [DYNAMIC_ACTOR_RING](DYNAMIC_ACTOR_RING.md). A pesquisa de extração de plaintext em `research/recv_cipher/` é **instrumentação experimental separada** da identificação do algoritmo Gepard: esta continua a única investigação criptográfica científica ativa. Testes offline não equivalem à validação live.

## Documentos ativos

| Documento | Função atual | Consultar quando |
|---|---|---|
| [RESEARCH_STATUS.md](RESEARCH_STATUS.md) | Único panorama de estado, decisões, classificação e evidências essenciais | Qualquer tarefa ou subagente |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Fluxos de cliente/Frida/driver/OpenKore; memória, threads, writeback e limites do xKore 0 | Arquitetura, programação e revisão |
| [OPERATIONS.md](OPERATIONS.md) | Configuração, execução, flags, dependências e testes offline | Instalação, operação e diagnóstico |
| [DYNAMIC_ACTOR_RING.md](DYNAMIC_ACTOR_RING.md) | Registro técnico cronológico da descoberta e recuperação do ring de recepção, limites, validação de nomes e novos IDs | Bugs de atores, buffs e proveniência RX |
| [CIPHER_INVESTIGATION.md](CIPHER_INVESTIGATION.md) | Pesquisa científica de cifra **ativa**; inclui integralmente o antigo manual `CIPHER_TOOLS.md` e fingerprint `PROTECTION_FINGERPRINT_DIE.md` | Agente CIFRA, verifier e pesquisa |
| [GEPARD_CONTROL_PACKETS.md](GEPARD_CONTROL_PACKETS.md) | Inventário de protocolo, pacote periódico `0x8280`, distinção entre histórico e build atual | Protocolo, cifra e futuro plugin |
| [AGENTS.md](AGENTS.md) | Regras breves de documentação e preservação de evidências | Documentador |

O `README.md` da raiz mantém a apresentação e instalação inicial. `research/cipher/` mantém scripts, `STATE.md`, `HANDOFF.md` curto e instruções locais; `research/COORDINATION.md` continua coordenando trabalhos ativos.

## Arquivo histórico e proveniência

Os registros **não foram resumidos nem descartados**: o conteúdo original foi copiado integralmente entre `BEGIN ORIGINAL` e `END ORIGINAL`, com caminho de origem, SHA do blob e índice de navegação em cada arquivo. Os originais continuam recuperáveis também no histórico Git. Não interpretar planos, diagnósticos superados ou autorizações datadas como tarefas ainda abertas.

| Arquivo em `docs/HISTORY/` | Conteúdo original preservado | Estado |
|---|---|---|
| [MOVEMENT_COMPLETE.md](HISTORY/MOVEMENT_COMPLETE.md) | Dois estudos longos de `035F`; `AGENTS`, `STATE` e `HANDOFF` de MOVER | Pesquisa concluída |
| [ACTIONS_COMPLETE.md](HISTORY/ACTIONS_COMPLETE.md) | Estudo `0437/0438/0AF4`; cinco handoffs, ensaios e plano de isolamento de ações | Pesquisa concluída |
| [PROJECT_HANDOFFS.md](HISTORY/PROJECT_HANDOFFS.md) | Mandato documental original, rotina Codex, orquestrador, backlog, handoff `ro_ops`, redirecionamentos antigos e histórico cumulativo CIFRA | Governança passada; handoff CIFRA corrente permanece ativo |
| [STATUS_AND_AUDIT.md](HISTORY/STATUS_AND_AUDIT.md) | Panorama anterior, decisões, índice de evidências, auditoria/matriz de migração e redirecionamento `DOCUMENTATION_SOURCES` | Substituído pelo estado canônico atual |
| [ARCHITECTURE_LEGACY.md](HISTORY/ARCHITECTURE_LEGACY.md) | Offsets, ABI, caminhos e experimentos antigos | Referência histórica |
| [GEPARD_LEGACY.md](HISTORY/GEPARD_LEGACY.md) | Modelo Gepard 2016, constantes e hipóteses antigas | Referência histórica |

**Busca por documento antigo:** abra o arquivo histórico temático e escolha no índice o *caminho original*, como `research/action_0437_0438/HANDOFF.md` ou `docs/MOVEMENT_035F_PRECONDITIONS.md`. A seção correspondente contém o texto original e sua procedência, não apenas um resumo.

## Regras de manutenção

- Manter **uma fonte canônica por assunto** e utilizar links em vez de duplicar grandes blocos explicativos.
- Preservar integralmente resultados negativos, registradores, ABI, offsets, scripts, limites e refutações antes de arquivar.
- Separar **OBSERVADO, INFERIDO, HIPÓTESE, NÃO VERIFICADO e REFUTADO**; não elevar relatos ou testes offline a prova live.
- Novos handoffs de cifra devem chegar ao Documentador com evidência `arquivo:linha`, condições de coleta e limitações; incorporar o resultado em `CIPHER_INVESTIGATION.md` e sintetizar a mudança aqui/sobre o status.
- Instruções de agentes, skills, scripts, testes e fixtures **necessários à execução** continuam nos caminhos funcionais; nenhum arquivo funcional foi movido nesta reorganização.
- Validação esperada: `python3 scripts/validate-research.py`, `python3 scripts/validate-codex.py`, `bash scripts/test-offline.sh`, `git diff --check` e checagem de links locais. Esses testes não validam comportamento em cliente real.
