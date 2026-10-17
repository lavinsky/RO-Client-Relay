# RO-Client-Relay — instruções para agentes

## Missão e fronteiras

Este projeto integra o **OpenKore externo (Perl, consumidor xKore 1)** ao cliente **uaRO/Gepard** em Linux/Wine/Proton usando relay Python e agente Frida. O OpenKore decide ações e já implementa xKore; **não** recrie lógica de bot ou um backend xKore no relay.

**Objetivo de longo prazo:** OpenKore operando **sem cliente (xKore 0)**. A implementação independente de protocolo, quando houver evidência suficiente, deve ser concebida como integração/plugin **no projeto OpenKore**, não presumida como novo backend deste repositório.

**Estado confirmado pelo responsável em 2026-10-17 (escopo uaRO estudado):** movimento automático `0x035F`, ataque automático `0x0437`, skill em alvo `0x0438` e skill no chão `0x0AF4` estão **funcionais; suas pesquisas específicas foram encerradas**. Não reabrir essas investigações com base em handoffs históricos. O movimento pode usar `--move-dispatch` (destino do consumidor → dispatcher nativo → cliente cifra/envia). Ações podem usar `--action-merge` e carrier natural, inclusive `--synth-input` quando configurado. Essas são **capacidades opt-in**, não presumir que todas as flags estejam ligadas na configuração principal.

**Causa da falha antiga do ataque:** no merge pré-XOR, o store `mov [ecx], bl` do scrambler podia regravar o byte zero usando o original do cliente. A correção `_fix0` no `agent/relay_hook_linux.js` restaura a contribuição do consumidor no hit seguinte. **Seleção/lock de alvo ou sincronização de caminhada não foram a causa final desse defeito.** Isso não revela o gerador de keystream.

## Pesquisa ativa — somente CIFRA

**Única investigação ainda aberta:** identificar, para o uaRO, o algoritmo efetivo de cifra, seus parâmetros e o ciclo de estado/sessão. O XOR final in-place em `gepard+0x18eff2` é conhecido no recorte estudado, **mas geração do keystream, seeds, estado e inicialização/reinicialização continuam não identificados**. O rastreamento histórico CL/POP/STACK/SLICE-12 até candidata `EBP+0x09` demonstra transportes delimitados, não o produtor da cifra.

**Atualização técnica prioritária (2026-10-17):** foram fornecidas por **fonte técnica especializada de alta confiança** duas variantes reais de referência de versões atuais do Gepard, provenientes de **servidores distintos**. Elas partilham uma família estrutural (tabela mutável de 256 bytes, três posições, inicialização com seed/constantes, operações por byte, XOR e dependência do comprimento), mas **diferem também na ordem, índices e dependências**, não apenas em constantes. Exemplos integrais, hashes e ambiguidades em `docs/CIPHER_INVESTIGATION.md#cipher-specialist-20261017`.

**Prioridade do pesquisador:** comparar A/B offline com entradas e seeds sintéticas e semântica de tipos explícita; identificar assinaturas discriminatórias (por exemplo `>>7` × `>>10`, índice das posições, soma × subtração), depois mapear parâmetros, memória, unidade/direção e eventos de inicialização no build uaRO. **Nunca promover constantes/seed dos exemplos a parâmetros do uaRO sem correspondência demonstrada.** A variante A registra hash como `None`; a B inclui rotina de hash com constante inicial ambígua e largura das posições ainda não especificada. Não normalizar as duas versões para uma única função.

**Procedência e método:** a fonte especializada relata seeds/valores de inicialização acessíveis em memória e reconstrução de operações protegidas por VMProtect com hypervisor, entradas/saídas e templates aritméticos/lógicos. Essa descrição **não demonstra que uma função específica já foi localizada no uaRO**, nem que a ferramenta esteja disponível neste repositório. O responsável confirmou valores relacionados à cifra recebidos durante login; **se representam seeds dessa família é hipótese de correspondência**, ainda sem campos identificados. Manter `0x8280` periódico e unidades de sincronização como dependências do protocolo futuro, não preâmbulos obrigatórios de ações.

Leia antes de trabalhar: `docs/README.md` → `docs/RESEARCH_STATUS.md` → `docs/CIPHER_INVESTIGATION.md`; na trilha CIFRA, também `research/COORDINATION.md`, `research/cipher/AGENTS.md`, `research/cipher/STATE.md` e `research/cipher/HANDOFF.md`. Os experimentos completos encerrados estão em `docs/HISTORY/MOVEMENT_COMPLETE.md` e `docs/HISTORY/ACTIONS_COMPLETE.md`, preservados para proveniência, não como backlog ativo.

## Invariantes do relay e das evidências

- Agente: `agent/relay_hook_linux.js`; driver: `relay_capture_linux.py` e `relay/` (`runtime.py`, `protocol.py`, `wire_feed.py`, `writeback.py`). Cliente real monta/cifra/envia; relay fornece quadros XKore `R`/`S`. Preserve ordem, identidade das conexões, concorrência, framing e **nunca fabrique corpos decifrados** quando a cópia verificada faltar.
- `relay_capture.conf` contém deliberadamente **`inject = true` e `inject-call = true`**, apesar de defaults internos do CLI distintos. Não mude sem decisão humana. Não inferir ativação de flags de pesquisa só por existirem no CLI.
- Preservar sanitização de credenciais e tráfego HTTP em `relay/safety.py`. Não versionar `relay/resources/`, binários baixados, dumps, logs, capturas de sessão, tokens, identificadores de contas nem `__pycache__`.
- Distinguir **OBSERVADO**, **INFERIDO**, **HIPÓTESE**, **NÃO VERIFICADO**, **REFUTADO**, além de **informação especializada de alta confiança** e **parâmetros ainda não identificados no uaRO**. Relato do responsável, inspeção de código, verificação do mesmo artefato e reprodução independente são graus de evidência distintos.
- Documentos de `docs/HISTORY/`, Gepard 2016 e roBrowserLegacy preservam contexto histórico; não equivalem automaticamente ao build atual. Registre `arquivo:linha`, versão/build, sessão sanitizada, fronteira de coleta, rival e condições de refutação.
- Testes offline **não** comprovam êxito em cliente vivo. Pesquisa ou operação contra processo/servidor requer escopo e autorização explícitos por rodada; esta documentação, scripts e skills não concedem autorização. Não desligar instrumentação de outros agentes. Uma pesquisa documental não altera operação.

## Divisão de responsabilidades e fluxo

O Documentador é o escritor habitual de `docs/`; CIFRA responde por `research/cipher/` e `tests/test_cipher_research.py`. Consulte `research/COORDINATION.md` antes de transferir ou editar trabalho compartilhado. Atualize primeiro evidência e relatório especializados; depois o estado canônico, sem apagar resultados negativos. Preserve o texto integral de arquivos já arquivados entre marcadores `BEGIN ORIGINAL` e `END ORIGINAL`.

Subagentes: **no máximo dois simultâneos**, se economizarem contexto. `explorer` busca evidência pontual (read-only), `implementer` executa patch delimitado e `verifier` revisa diff/testes independentemente. Modelos e esforços são definidos nos arquivos vigentes `.codex/config.toml` e `.codex/agents/*.toml`, com equivalentes `.claude/agents/`: **não hardcode nomes de modelos em handoffs**. Delegue objetivo, caminhos, evidência, teste de aceitação e limites, normalmente até 150 palavras.

Skills ativas em `.agents/skills/` (espelhadas em `.claude/skills/`): `repo-evidence` para prova `arquivo:linha`, `research-handoff` para entrega delimitada e `ro-ops` (`python3 -m ro_ops`: `discover`, `env-check`, `sample-thread`, `new-artifact`, `scaffold-state`) para rotinas operacionais. `cheat-engine-cli` pode estar disponível em ambiente Claude; **uso de CEServer/memória precisa de autorização própria**. `env-check` não certifica exclusividade da sessão. Se uma skill mencionar documentos removidos na consolidação, prevalecem os caminhos canônicos acima e o histórico em `docs/HISTORY/`.

## Testes, revisão e publicação

1. Inspecione `git status`, `git diff` e a revisão atual antes da edição; não sobreponha mudanças de outros agentes.
2. Rode testes focados e, para regressões offline, `bash scripts/test-offline.sh`; valide documentação com `python3 scripts/validate-research.py` e configuração de agentes com `python3 scripts/validate-codex.py`; confira `git diff --check`. Não inventar formatters ou migrações inexistentes.
3. Registre **PASS / FAIL / NOT RUN** com os comandos e limites. Sucesso offline não atesta cliente/servidor. Não executar cliente, Frida ou CEServer como parte da validação documental.
4. Commits locais somente com escopo/autorização aplicáveis e `git add` de arquivos explícitos. **Push, PR ou merge exigem autorização humana explícita**; criar PR não implica permissão para mesclar.
5. Entrega final: **Resultado | Arquivos alterados | Evidências (`arquivo:linha`) | Verificações (PASS/FAIL/NOT RUN) | Hipóteses/riscos | Commit/PR ou nenhum | Próxima decisão**.
