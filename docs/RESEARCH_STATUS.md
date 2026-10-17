# Estado atual e decisões — RO-Client-Relay


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
