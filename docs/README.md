# Documentação técnica — RO-Client-Relay

**Estado em 2026-10-17:** movimento `0x035F` e ações `0x0437`/`0x0438`/`0x0AF4` **funcionais, pesquisas encerradas** conforme o responsável; **única pesquisa aberta: cifra uaRO/Gepard**. A causa da falha automática era o **primeiro byte regravado pelo scrambler** após o merge do Frida; correção `_fix0` verificada em `agent/relay_hook_linux.js:481-534`. [Fechamento técnico](ACTION_0437_0438_INVESTIGATION.md).

**Fonte canônica de navegação.** Revisão local de 2026-10-15 em
`main@524b0f05fa61872e140f98ace9e503d12356641e`, reconciliada com o pacote de `bdc2a07` e o ensaio de dispatcher de `524b0f0`.
Os estudos especializados permanecem separados e completos, incluindo o fechamento das ações. Históricos sanitizados
ficam em `HISTORY/`; os caminhos anteriores na raiz redirecionam para esta documentação.

## Fluxo mínimo de leitura por agentes

1. [Regras do projeto](../AGENTS.md): autorização, invariantes, testes e limites.
2. [Estado atual](RESEARCH_STATUS.md): o que foi observado/refutado, lacunas e prioridades.
3. Este índice: selecione **apenas** documentos pertinentes à tarefa.
4. Consulte código/fixtures e [índice de evidências](RESEARCH_EVIDENCE_INDEX.md) para testar decisões técnicas. Não use histórico de chat como prova.

## Índice por tarefa e destinatário

| Documento | Finalidade e principais assuntos | Estado | Perfil de consulta / documentos relacionados |
|---|---|---|---|
| [RESEARCH_STATUS.md](RESEARCH_STATUS.md) | Panorama atual: movimento, cifra, controle, hipóteses, refutações, pendências | Novo, revisão 2026-10-15 | Todo agente antes de pesquisa; aponta para quatro estudos |
| [RESEARCH_EVIDENCE_INDEX.md](RESEARCH_EVIDENCE_INDEX.md) | Identificadores/proveniência/limites de evidências | Novo, revisão 2026-10-15 | Pesquisador, auditor, verifier; estudos especializados |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Componentes, threads, caminhos de recepção/escrita, invariantes, demarcação de conhecimento | Novo, revisão 2026-10-15; conferido com contratos locais | Implementer/verifier; [arquitetura legada](HISTORY/ARCHITECTURE_LEGACY.md), código |
| [OPERATIONS.md](OPERATIONS.md) | Requisitos, instalação, execução, config, diagnóstico, testes e segurança | Novo, revisão 2026-10-15; conferido com CLI/config | Operador/verifier; [README da raiz](../README.md), `relay/cli.py` |
| [MOVEMENT_035F_INVESTIGATION.md](MOVEMENT_035F_INVESTIGATION.md) | S1/S2, VM, dispatcher, ABI, offsets, sondas, controles, ensaio nativo original | **FUNCIONAL/ENCERRADO** (2026-10-17); experimentos 2026-10-15 preservados | Subagente de movimento; [pré-condições](MOVEMENT_035F_PRECONDITIONS.md) |
| [MOVEMENT_035F_PRECONDITIONS.md](MOVEMENT_035F_PRECONDITIONS.md) | Contrato natural/nativo, canais independentes, refutação M-H1 na etapa 6.4, ensaio do dispatcher §13 e limites H2/H3 | **FUNCIONAL/ENCERRADO** (2026-10-17); histórico técnico preservado | Subagente de movimento; `research/movement_035f/` |
| [ACTION_0437_0438_INVESTIGATION.md](ACTION_0437_0438_INVESTIGATION.md) | Fechamento do ataque automático `0437` e skills `0438`/`0AF4`; causa byte zero, `_fix0`, histórico ACT-01/02/03 e resultados negativos | **CONCLUÍDO/funcional**, confirmação do responsável 2026-10-17 e código inspecionado | Investigador de ações, verifier, documentador; [controle](GEPARD_CONTROL_PACKETS.md), [cifra](CIPHER_INVESTIGATION.md) |
| [CIPHER_INVESTIGATION.md](CIPHER_INVESTIGATION.md) | Cadeias executadas, assembly, escritores/consumidores, estudos negativos, limites | Existente, continuação dinâmica 2026-10-15 | Subagente de cifra; [pesquisa local](../research/cipher/README.md) |
| [GEPARD_CONTROL_PACKETS.md](GEPARD_CONTROL_PACKETS.md) | IDs/tamanhos conhecidos, hipóteses de handshake e controle, restrições do build 2016; mapa dispatcher code → `035F`/`0437`/`0438` e teste negativo de injeção da perícia (2026-10-16) | Existente; reclassifica histórico explicitamente; `0368` pré-select REFUTADO como solução | Investigador de protocolo; [decisões](RESEARCH_DECISIONS.md) |
| [RESEARCH_DECISIONS.md](RESEARCH_DECISIONS.md) | Decisões aprovadas e hipóteses históricas identificadas como tais | Existente; nota de precedência adicionada pela aplicação | Coordenador; [estado atual](RESEARCH_STATUS.md) |
| [CODEX_WORKFLOW.md](CODEX_WORKFLOW.md) | Delegação, modelos, agentes, validação, medição de uso | Existente, conferido com estrutura de `.codex/` / `.claude/` | Coordenador de agentes; [AGENTS](../AGENTS.md) |
| [DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md) | Matriz de fontes, conflitos, migração, verificações e limites | Novo, revisão 2026-10-15 | Curador/verifier; este índice |

## Fontes adicionais e status

- [CIPHER_TOOLS.md](CIPHER_TOOLS.md): manual integral de formatos, CLI, limites e limpeza;
  consulta por pesquisadores de cifra e operadores. Migrado do README local sem cortes.
- [HISTORY/ARCHITECTURE_LEGACY.md](HISTORY/ARCHITECTURE_LEGACY.md): §§1–13 históricos,
  mapas, ABI, sondas, resultados e cautelas. Consulte para proveniência, com precedência do estado atual.
- [HISTORY/GEPARD_LEGACY.md](HISTORY/GEPARD_LEGACY.md): modelo 2016, constantes, offsets,
  hipóteses antigas e candidatos de perícia. Sanitizado; não é especificação do build atual.
- Inventário recursivo versionado, procedência e mapa por família de código/testes/configuração:
  fundido em [DOCUMENTATION_AUDIT.md §10](DOCUMENTATION_AUDIT.md#10-inventário-de-fontes-da-consolidação-migrado-de-documentation_sourcesmd)
  (2026-10-16). O caminho antigo [DOCUMENTATION_SOURCES.md](DOCUMENTATION_SOURCES.md) é um redirecionamento.
- [README da raiz](../README.md) e [AGENTS.md](../AGENTS.md) continuam como entrada e regras.
- `research/`, `relay/`, `agent/`, `tests/`, `scripts/`, `data/` e configurações continuam nos
  caminhos funcionais. `.agents/`, `.codex/` e `.claude/` mantêm estrutura e espelhos.
- `docs/AGENTS.md` preexistente foi preservado integralmente como instrução da tarefa.

## Atualização de pesquisa (política)

1. Deposite a observação no documento **especializado** com data, build, sessão sanitizada, método, recortes e limitações.
2. Classifique expressamente como **OBSERVADO**, **INFERIDO**, **HIPÓTESE**, **NÃO VERIFICADO** ou **REFUTADO**; mantenha a hipótese rival e uma observação que a distingua.
3. Preserve resultados negativos com método, cobertura, controles, resultados, limites e o que **não** se pode concluir.
4. Atualize o panorama em `RESEARCH_STATUS.md` apenas quando o entendimento global mudar.
5. Inclua nova entrada em `RESEARCH_EVIDENCE_INDEX.md` com referência ao estudo integral.
6. Alterações em `RESEARCH_DECISIONS.md` exigem **decisão real do responsável**, nunca mera preferência do agente.
7. Corrija links relativos, execute `python3 scripts/validate-research.py`, `python3 scripts/validate-codex.py`, `git diff --check` e testes offline pertinentes. Reporte sempre PASS/FAIL/NOT RUN.
8. Não compartilhe tokens, credenciais, endereços de conta, dumps brutos ou conteúdo de artefatos privados. Experimento vivo exige aprovação explícita distinta desta manutenção documental.

**Regra editorial:** os documentos especializados são autocontidos e completos. O estado atual/indexador é curto por ser um mapa; **não** é um resumo substitutivo dos dados, offsets, registradores, experimentos ou refutações contidos nas pesquisas.

## Documento incorporado pelo pull

[PROTECTION_FINGERPRINT_DIE.md](PROTECTION_FINGERPRINT_DIE.md) registra as proteções da
mesma build confirmadas pelo responsável. Consulte antes de atribuir funções a uma VM;
a presença do protetor não demonstra virtualização de um callsite específico.
