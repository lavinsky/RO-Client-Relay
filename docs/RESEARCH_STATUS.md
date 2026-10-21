# Estado atual e decisões — RO-Client-Relay

## Atualização incremental do observer — 2026-10-21

**Base:** `origin/main@f311d67` (merge do PR #21). A working tree contém somente a nova trilha **operacional** de observer read-only (`relay/observer.py`, integração em `relay/cli.py`/`wire_feed.py`, helper de restart, testes e documentação). **OBSERVADO NO CÓDIGO/TESTE OFFLINE:** o observer é opt-in por `RO_RELAY_OBSERVER_SOCKET`, espelha apenas frames `R` server→client, exige socket 0600 em diretório 0700 pertencente ao UID, mantém replay de até 32 MiB por epoch/fase e fecha viewer em backpressure. **NÃO VERIFICADO LIVE NESTA REVISÃO:** login→char→map completo até uma UI roBrowser, autenticação da camada externa e reconnect real. Isso não modifica a situação da cifra, movimento, ações ou recuperação de atores consolidada abaixo. [Contrato completo](RO_BROWSER_OBSERVER.md).


## Verificação passiva dos logs de produção — 2026-10-20, 18:37–19:30 BRT

**Procedência e método (OBSERVADO EM LOGS LIVE JÁ EXISTENTES):** análise **somente leitura** de `relay_log.jsonl` (JSONL local) e `../OpenKore-upstream/logs/console.txt`, correlacionando timestamps a partir de 20/10/2026 18:37:05. O cliente `uaRO.exe` estava ativo desde 16:00:46; o processo do relay foi iniciado às 18:37:05 e o OpenKore estava ativo desde 19/10 às 23:58:53. `relay/actors.py` (mtime 18:31:40), `wire_feed.py` (17:15), agente Frida (15:49), `run.sh` (16:42) e INI (19/10) tinham alterações anteriores à inicialização do relay; isso é **compatível com a versão atual em execução**, não uma prova byte a byte do código carregado. A amostra termina em **19:30:47**, e os arquivos continuam crescendo. Não houve reinício, nova instrumentação, input ou comunicação adicional com o servidor nesta auditoria. Nenhum log cru ou nome/ID de ator foi incorporado ao Git.

| Indicador do relay | Total da janela | O que mostra / limite |
|---|---:|---|
| `ACTOR-RECOVERY`: `09FD` | 1.030 recuperados / 6 perdidos | Cópias verificadas em execução; os perdidos não foram sintetizados |
| `ACTOR-RECOVERY`: `09FF` | 1.001 / 15 | Recuperação majoritária, com perdas ainda reais |
| `ACTOR-RECOVERY`: `0983` | 948 / 75 | Maior grupo de misses; requer análise da proveniência e interpretação dos estados |
| `ACTOR-RECOVERY`: `043F` | 241 / 18 | Fluxo presente, mas não comprova semântica dos buffs |
| `ACTOR-RECOVERY`: `0229` | 91 / 1 | Reconstrução do corpo do status, não prova que `opt1/opt2/option` estão sempre corretos |
| **Total de candidatos** | **3.311 recuperados / 115 não recuperados = 3.426** | ~**96,6%** dos candidatos anotados no log desta sessão; não garantia global |
| Motivos dos 115 misses | 103 `correlation-mismatch`, 7 `overwritten-before-verification`, 4 `ring-not-found`, 1 `timeout-no-valid-copy` | Categorias de decisão do software, não causalidade confirmada |
| Outros eventos de diagnóstico | 391 `SENDCALL stale-drop`, 217 `THIS-CONTEXT stale`, 70 `THIS-CONTEXT suspect` | Guardas/descartes observados; não classificar automaticamente como falha fatal nem como sucesso da ação |

**OpenKore-upstream no mesmo intervalo** (classificação passiva por regex de linhas de console, **não** contagem de ações exclusivas): 724 linhas de skills, 346 de ataque, 195 de movimento, 85 de itens/storage e 45 com marcadores de aviso/erro; 0 linhas identificadas por estes padrões como desconexões ou IDs de pacote desconhecidos a partir das 18:37. O log permaneceu ativo às 19:30:47. **INFERIDO:** há continuidade operacional compatível entre relay e consumidor no período; ausência de um padrão textual não exclui falhas não logadas, e sem inspeção semântica detalhada não se afirma que todo buff/status/`sitting` esteja correto.

**Conclusão delimitada:** `09FD/09FF/0983/043F/0229` têm **recuperações confirmadas em registro live** da sessão de 20/10, com FIFO/entrega de plaintext verificado segundo as tags observadas; as falhas registradas impedem concluir 100%. O comportamento de movimento/ataque/skills no OpenKore é observado como **atividade**, não como confirmação instrumental de cada pacote aceito pelo servidor. Os **37 scripts offline** e os validadores documentais passaram separadamente; não misturar as duas classes de evidência.

## Revisão do checkout — 2026-10-20

**Base revisada:** `origin/main@9ee7ef5` (atualizada por fetch); checkout `test/audit-edge-cases-20261018@aa69a6a` antes desta edição, com 47 arquivos rastreados diferentes de main e 22 arquivos novos não rastreados. Os últimos incluem testes, instrumentos da trilha de recepção e `docs/DYNAMIC_ACTOR_RING.md`. Esta contagem é o inventário **antes** das atualizações documentais; não significa 69 alterações aprovadas para PR. `main` local estava desatualizada em relação a `origin/main`. **Nenhuma instrumentação live foi executada nesta auditoria documental.**

| Tema | Classificação / estado em 2026-10-20 | Evidência e limite |
|---|---|---|
| Movimento `035F`, ações `0437/0438/0AF4` | **FUNCIONAIS SEGUNDO RELATO DO RESPONSÁVEL (2026-10-17)** | Mecanismos já consolidados; código mudou posteriormente, **sem revalidação live aqui** |
| Gamescope EIS + uso de item `0439` | **IMPLEMENTADO; configuração local alterada** | `relay_capture.conf` mantém `inject=true`, `inject-call=true`, `gamescope-eis`, `egress-queue=false`, `sendcall-demand=false`; `itemuse-input-key` está agora **F2**, não END; não atribuir a confirmação anterior à mudança F2 |
| Ring RX e recuperação de atores | **IMPLEMENTADO; resultados de campo variáveis** | Descoberta dinâmica por sessão, isolamento de epoch/slot, `ACTOR-RECOVERY`; referências em [arquitetura](ARCHITECTURE.md#15-recepção-dinâmica-novos-ids-e-proveniência-revisão-2026-10-20) e [registro técnico](DYNAMIC_ACTOR_RING.md) |
| Status/buffs `0229`/`043F`/`0983` | **REGRAS/TESTES OFFLINE, sem garantia semântica live** | Somente cópias verificadas; o estado `sitting` incorreto relatado anteriormente não é considerado resolvido |
| RX/TX do scrambler e breakpoints | **OBSERVADO NO CÓDIGO** | Guarda de sobreposição nos rings registrados + telemetria `BP-TELEMETRY`; não prova separação quando o ring RX é desconhecido |
| Sonda `research/recv_cipher/` | **ENGENHARIA EXPERIMENTAL ATIVA, separada da pesquisa da cifra** | Descobre o plaintext produzido pelo próprio cliente, sem identificar algoritmo; [STATE](../research/recv_cipher/STATE.md) contém amostras positivas, negativas, limitações e limpeza |
| Watchdog de SIGCONT / auditoria de sinais | **IMPLEMENTADO, não validado live nesta rodada** | Só observa estados Linux `T/t` e usa um sinal por episódio após 3 s; risco de dessincronizar sessão permanece |
| Cifra independente uaRO/Gepard | **ÚNICA INVESTIGAÇÃO CRIPTOGRÁFICA CIENTÍFICA ABERTA** | Duas variantes especializadas A/B seguem referência; seeds, tabela real, funções e estado do uaRO **NÃO IDENTIFICADOS** |

**Risco adicional OBSERVADO NO CÓDIGO:** `research/recv_cipher/sample_telemetry.py` mantém até 512 frames completos (padrão 16 KiB cada) em RAM, embora seu docstring afirme não armazenar conteúdo. Não há prova de exportação automática neste módulo, mas os frames e qualquer captura derivada são **dados privados de sessão**. `audit_coverage.py` conta somente `09FD/09FF/0229`; cobertura de `043F/0983` não deve ser inferida de seus percentuais. [Inventário e limites](../research/recv_cipher/README.md#inventário-dos-instrumentos-ainda-não-publicados--revisão-estática-2026-10-20).

**Validação offline do checkout anterior às edições:** `bash scripts/test-offline.sh` **PASS (37 scripts)**; `python3 scripts/validate-research.py` **PASS**; `python3 scripts/validate-codex.py` **PASS**; `git diff --check` **PASS**; `bash -n` dos launchers e `node --check` do agente e sondas JS **PASS**; `python3 -m compileall` de fontes próprias **PASS**. Além disso, `research/recv_cipher/test_ring_correlator.py` e `test_audit_write_trace.py` **PASS**. Os testes não estabelecem cobertura total da recepção em jogo.

**OBSERVADO nas amostras já registradas pela trilha de recepção:** em 2026-10-19 a coleta `182943` encontrou 70 `09FF`, 4 `09FD` e 2 `0229`, **0 recuperados**, enquanto `184839` encontrou 221/224 `09FF` e 14/16 `09FD` recuperados. Uma coleta sob escrita rastreada recuperou 7/7, mas não provou proveniência única. **Não calcular percentuais globais** combinando sessões distintas ou concluir 100% a partir de amostras favoráveis. A causa dos misses de alta carga permanece **NÃO VERIFICADA**.

A documentação precedente de 2026-10-17 permanece abaixo como registro cronológico. `docs/AGENTS.md` preserva a política de uma fonte canônica por assunto, distingue evidência de código/teste/live e impede promover hipóteses ao protocolo.


<!-- CIPHER-SPECIALIST-REFERENCES-2026-10-17 -->

**Prioridade especializada da cifra — 2026-10-17:** a investigação da cifra continua a **única pesquisa ativa**. Foram recebidos de fonte técnica especializada de **alta confiança** dois **algoritmos reais de referência Gepard**, de servidores distintos, representativos de **versões atuais**. As variantes não são apenas conjuntos de constantes: diferem em índices, dependências de estado, sinais das operações, deslocamentos de inicialização e tratamento do hash. O modelo concreto de trabalho é tabela mutável de 256 bytes + três posições + seed/constantes + XOR/transformações por byte + comprimento e possível persistência. Ver [estudo e código integral](CIPHER_INVESTIGATION.md#cipher-specialist-20261017).

**Classificação:** conhecimento especializado = **FONTE TÉCNICA ESPECIALIZADA — ALTA CONFIANÇA**; exemplos = **ALGORITMOS DE REFERÊNCIA FORNECIDOS POR ESPECIALISTA**; algoritmo, seed, constantes e unidades atuais do uaRO = **PENDENTE DE IDENTIFICAÇÃO NO uaRO**. A evidência observada STACK/SLICE até candidata `EBP+0x09` permanece válida, mas não gerou keystream. O responsável confirmou valores de cifra no login; serem seeds da família é hipótese de **correspondência**, não de confiabilidade da fonte. VMProtect/hypervisor/templates são conhecimento metodológico recebido, sem identificação de função concreta no build atual.

**Próximos marcos:** vetores sintéticos offline A/B com semântica explícita; assinatura discriminatória de ordem/índice/sinal/shift; identificação de seed vs estado derivado e vínculo login→inicialização; unidades de envio/recepção/sync, continuidade/reset; dependência do `0x8280` para xKore 0. **Nenhuma constante exemplar se torna parâmetro do uaRO sem evidência correspondente.** Não foram realizadas sondas nesta atualização documental.
**Referência:** 2026-10-17 · revisado após a conclusão funcional de movimento e ações, confirmada pelo responsável. Este documento é o **único panorama canônico do trabalho atual**; investigações, decisões e índices anteriores estão preservados integralmente em [HISTORY/STATUS_AND_AUDIT.md](HISTORY/STATUS_AND_AUDIT.md).

## Estado operacional

| Domínio | Situação | Mecanismo / evidência | Próxima pesquisa |
|---|---|---|---|
| Movimento `0x035F` | **CONCLUÍDO / funcional** | OpenKore entrega destino; `--move-dispatch` chama o dispatcher nativo no contexto do cliente, que gera, cifra e envia o movimento; rodadas 06b/08/09 e confirmação do responsável | Nenhuma na trilha de movimento |
| Ataque automático `0x0437` | **CONCLUÍDO / funcional** | `--action-merge` substitui corpo no scrambler; `_fix0` corrige byte zero regravado pelo store | Nenhuma na trilha de ataque |
| Skill automática em alvo `0x0438` | **CONCLUÍDA / funcional** | Carrier natural + merge pré-XOR; correção de byte zero, confirmação do responsável | Nenhuma na trilha de skills |
| Skill automática no chão `0x0AF4` | **CONCLUÍDA / funcional** | Carrier natural + merge pré-XOR; confirmação do responsável | Nenhuma na trilha de skills |
| **Cifra uaRO/Gepard** | **ÚNICA PESQUISA ABERTA** | XOR final local conhecido; geração de keystream, estado, inicialização e evolução entre sessões ainda desconhecidos | Seguir origem dos bytes/operandos e associar estado à inicialização |

A **confirmação funcional** acima foi fornecida pelo responsável; esta consolidação **não executou** cliente nem coletou novos pacotes. O mecanismo `_fix0` está **OBSERVADO NO CÓDIGO** em `agent/relay_hook_linux.js:481-534`. No store `mov [ecx], bl` (`gepard+0x18eff2`), `bl` já carregava o byte original do cliente; após `bodyp.writeByteArray(body)`, o store podia revertê-lo. No hit seguinte o agente corrige `body[0]` com `c0 ^ orig0 ^ our0`. Não confundir essa correção com descoberta do algoritmo criptográfico. [Experimentos e negativos integrais](HISTORY/ACTIONS_COMPLETE.md).

## Decisões vigentes

1. **Somente CIFRA permanece ativa.** Movimento e ações não devem aparecer como pendências de pesquisa; seus históricos completos ficam em [HISTORY/MOVEMENT_COMPLETE.md](HISTORY/MOVEMENT_COMPLETE.md) e [HISTORY/ACTIONS_COMPLETE.md](HISTORY/ACTIONS_COMPLETE.md).
2. **Arquitetura:** OpenKore é o consumidor Perl externo e implementa xKore; RO-Client-Relay permanece intermediário em xKore 1. A meta futura **xKore 0 sem cliente** exige domínio independente do protocolo e pertence conceitualmente a uma integração/plugin **no OpenKore**, não a um novo backend xKore neste repositório.
3. **Configuração:** `relay_capture.conf` mantém intencionalmente `inject = true` e `inject-call = true`. Defaults internos do CLI são diferentes. Não modificar em manutenção documental.
4. **Método científico:** classificar como **OBSERVADO**, **INFERIDO**, **HIPÓTESE**, **NÃO VERIFICADO** ou **REFUTADO**, sempre com origem, build, condição de coleta, limites e rivais; relato do responsável ≠ observação instrumental independente.
5. **Limite operacional:** nada autoriza experimentos live, ferramentas de memória ou envio ao servidor. Preserve ordem de pacotes, identidade das conexões, sanitização e enquadramento XKore `R`/`S`.
6. **Documentação:** manter materiais ativos resumidos e detalhamento científico da cifra em [CIPHER_INVESTIGATION.md](CIPHER_INVESTIGATION.md). Preservar fontes aposentadas literalmente nos arquivos temáticos de [HISTORY/](README.md#arquivo-histórico-e-proveniência).

## Atualização de integração operacional — PR Gamescope EIS (2026-10-17)

- **CONFIRMADO PELO RESPONSÁVEL:** as mudanças e os valores do
  `relay_capture.conf` atual funcionam em sua execução do cliente;
  `inject=true`, `inject-call=true`, `egress-queue=false`,
  `sendcall-demand=false`, `synth-backend=gamescope-eis` e
  `itemuse-input=true` são decisões operacionais mantidas.
- **OBSERVADO NO CÓDIGO:** a interface EIS conecta apenas ao socket
  Gamescope explicitamente configurado, e não faz fallback a
  `ydotool`/KDE; `0x0439` exige tecla síncrona antes de
  `SendPacket`; as tags `THIS-CONTEXT` e
  `RECV-PLAIN-UNAVAILABLE` permitem diagnóstico sem inventar
  decifragem. [Arquitetura](ARCHITECTURE.md#14-integração-operacional-gamescope-eis-2026-10-17).
- **OBSERVADO EM TESTE TÉCNICO ISOLADO:** evento EIS chegou como
  `KeyPress/KeyRelease` a uma aplicação XWayland de teste dentro de
  Gamescope. A revisão documental não reproduziu entrada live no uaRO.
- **NÃO VERIFICADO NESTA RODADA:** causalidade de congelamentos
  anteriores, validade de todos os ponteiros nativos sob transições
  futuras e implementação independente da cifra. Os diagnósticos não
  transformam essas hipóteses em fatos.
- **Portabilidade:** sete scripts de pesquisa histórica de movimento
  corrigiram um caminho absoluto para referência relativa à tabela de
  pacotes; não reabre uma pesquisa encerrada.

Detalhes de instalação, flags e teste estão em [OPERATIONS](OPERATIONS.md#gamescope-eis-e-configuração-operacional-validada).
Esta integração não altera a decisão de manter a **cifra como única
pesquisa científica ativa**.

## Cifra — questões científicas abertas

**OBSERVADO:** a transformação final do corpo `0x035F` inclui XOR in-place byte a byte na instrumentação estudada. A pesquisa de CL/bytes identificou transportes intermediários e candidatos de fonte, incluindo `EBP+0x57` e `EBP+0x09` em rodadas CIFRA STACK-04…SLICE-12, **sem isolar operação geradora**.

**NÃO VERIFICADO:** função `F(entrada, estado anterior, contexto) = (saída, estado seguinte)`, produtor real do keystream, origem de operandos, fronteiras completas de plaintext/ciphertext, estado de sessão, inicialização/reinicialização, ligação inequívoca a valores do login, vetores independentes. A implementação do cliente conhecida em xKore 1 não substitui esses achados para xKore 0.

**Próxima dependência:** retomar `research/cipher/STATE.md` e `research/cipher/HANDOFF.md`, seguir a fonte candidata com contexto de execução verificável e associar o produtor a seu consumidor **na mesma ocorrência/sessão**. Respeitar a exclusividade de DRs e janelas instrumentadas. Referências completas em [CIPHER_INVESTIGATION.md](CIPHER_INVESTIGATION.md) e seu manual incorporado.

## Protocolo e limites de interpretação

- `0x035F` é **cifrado** pelo cliente, não texto claro bruto no wire; `0x0087` observado confirma resposta associada ao destino, não prova geral de chegada.
- `0x0437`, `0x0438` e `0x0AF4` funcionam via carrier+merge, **não** pela via isolada `SendPacket` crua que falhou em experimento anterior.
- A hipótese de **seleção/lock de alvo** como causa do ataque automático é **REFUTADA/SUPERADA**. A hipótese intermediária de alcance/estado de caminhada e a fila FIFO não explicam o bug corrigido do primeiro byte.
- `0x0368` pré-select não foi a solução; o `0x8280` periódico originado pelo Gepard não constitui preâmbulo obrigatório por ação comprovado. Sua estrutura e o vínculo exato com a máquina de estado ainda são dependências de protocolo relevantes à **cifra/xKore 0**, não reabertura de ataques.
- Analogias Gepard 2016 e roBrowserLegacy são históricas, **não** contrato do build atual. Consulte [GEPARD_CONTROL_PACKETS.md](GEPARD_CONTROL_PACKETS.md) e [HISTORY/GEPARD_LEGACY.md](HISTORY/GEPARD_LEGACY.md).

## Evidências essenciais

| ID/fonte | Estado | Onde consultar |
|---|---|---|
| M-11/M-13 e PoC 09 | OBSERVADO nas rodadas documentadas, encerrado funcionalmente | [Arquivo de movimento](HISTORY/MOVEMENT_COMPLETE.md), fontes `research/movement_035f/` incorporadas |
| A-01…03 e fix byte zero | NEGATIVOS históricos + validação final comunicada pelo responsável; fix OBSERVADO no código | [Arquivo de ações](HISTORY/ACTIONS_COMPLETE.md), `agent/relay_hook_linux.js:481-534` |
| C-08…C-10 | OBSERVADO em recortes delimitados, algoritmo NÃO VERIFICADO | [Pesquisa de cifra](CIPHER_INVESTIGATION.md), `research/cipher/STATE.md`, [handoffs originais](HISTORY/PROJECT_HANDOFFS.md#source-research-cipher-handoff-md) |
| P-01 | OBSERVADO/confirmado no fingerprint de arquivos da build; sem provar virtualização de callsites individuais | [Apêndice do fingerprint](CIPHER_INVESTIGATION.md#original-docs-protection-fingerprint-die-md) |
| Relatórios e decisões anteriores | HISTÓRICO integral, não prioridades presentes | [Arquivo de status e auditorias](HISTORY/STATUS_AND_AUDIT.md) |

**Procedência:** o estado de 2026-10-17 incorpora declaração do responsável e implementação já versionada. Novas conclusões sobre cifra exigem build, revisão, método, resultado, alternativa, escopo de refutação e limites de cobertura. Sem resultados live novos nesta reorganização.
