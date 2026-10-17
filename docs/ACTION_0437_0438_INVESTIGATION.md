# Ações `0x0437` / `0x0438` / `0x0AF4` — conclusão operacional e histórico

**Estado:** PESQUISA FUNCIONAL ENCERRADA em 2026-10-17 por confirmação expressa do responsável pelo projeto.
**Base de código auditada:** `main@0bddf0d77a5f81dc92c6fa5f5d6d45f1aa237d95`. **Escopo:** build uaRO/Gepard pesquisado; não inferir compatibilidade com outro build/servidor.
**Procedência:** fontes registradas em `research/action_0437_0438/`, inspeção estática do agente Frida e confirmação posterior do responsável. **Nenhum novo teste live foi executado pelo documentador.**

## 1. Conclusão canônica (substitui diagnósticos intermediários)

| Função | Estado atual | Base da conclusão |
|---|---|---|
| Caminhar, pacote `0x035F` | **CONCLUÍDO / FUNCIONAL** | MOVER-20261015-06b, MOVER-20261016-08 e rodada 09 do relay; fechamento funcional confirmado pelo responsável |
| Ataque automático, `0x0437` | **CONCLUÍDO / FUNCIONAL** | Confirmação do responsável; correção de byte no Frida verificada no código |
| Skill automática em alvo, `0x0438` | **CONCLUÍDO / FUNCIONAL** | Confirmação expressa do responsável |
| Skill automática no chão, `0x0AF4` | **CONCLUÍDO / FUNCIONAL** | Confirmação expressa do responsável |
| Algoritmo e estado da cifra | **EM INVESTIGAÇÃO** | A correção do merge não identifica geração, estado, inicialização ou keystream |

**Causalidade corrigida:** a falha do ataque automático **não** era causada por falta de seleção/lock de alvo nem foi resolvida por alterações na política de roteamento/alcance. O primeiro byte do corpo do pacote substituído podia permanecer com o valor derivado do **cliente**, em vez do valor enviado pelo **consumidor OpenKore**, por erro temporal no script do agente Frida. A correção do primeiro byte encerrou o problema funcional, conforme relato do responsável. Não extrapolar esta confirmação para comprovar o algoritmo completo da cifra.

O relato atual é uma **decisão/validação funcional comunicada pelo responsável**; o mecanismo concreto da correção é **OBSERVADO NO CÓDIGO**. Logs adicionais de reprodução pós-fix por família não foram disponibilizados nesta rodada documental. Os registros antigos abaixo permanecem válidos **como história dos experimentos**, não como status operacional.

## 2. O defeito do byte zero no store de scramble

Fontes da implementação atual: `agent/relay_hook_linux.js:481-534`; `relay/writeback.py`; `relay/synth_input.py`.

A rotina de merge encontra o carrier natural que o cliente ia enviar e executa `bodyp.writeByteArray(body)`, gravando no buffer o corpo recebido do OpenKore antes da transformação final. O breakpoint está no store de 1 byte `mov [ecx], bl` do scrambler (`gepard+0x18eff2`). Quando o hit ocorre no primeiro byte, **BL já havia sido carregado a partir do corpo original**; prosseguir a instrução sobrescrevia `body[0]` depois da gravação do merge.

Efeitos descritos no próprio comentário do agente:
- em `0x0437`, byte baixo incorreto do identificador do alvo (GID);
- em `0x0438`, byte baixo incorreto do nível de skill, com emissão de nível diferente daquele enviado pelo consumidor.

### Correção implementada, sem reconstrução da cifra

O ramo `// --- byte0 fix (merge)` guarda `{at, orig0, our0}` em `scr._fix0` ao reconhecer a condição `usedOff === -2`. No **próximo hit** do store de scramble, quando a escrita atrasada do byte zero já ocorreu, aplica:

~~~text
c0 = *(bodyp[0])                # byte corrente após o store do cliente
bodyp[0] = (c0 ^ orig0 ^ our0) & 0xff
~~~

Essa identidade XOR substitui o efeito do primeiro byte original pelo primeiro byte fornecido pelo consumidor, preservando a transformação aplicada naquele instante. O agente limpa `scr._fix0` após consumi-lo. **Não prova** como o keystream é gerado ou reiniciado e não autoriza assumir que todas as etapas criptográficas foram descobertas. A validade depende do contexto e da ordem dos hits descrita no código.

**Classificação:** OBSERVADO na implementação (`agent/relay_hook_linux.js:481-493, 523-534`); efeito funcional das três famílias de ação CONFIRMADO PELO RESPONSÁVEL nesta revisão. Não houve instrumentação nova do documentador.

## 3. Como funcionam os caminhos concluídos

### Movimento `0x035F`

O OpenKore emite o pedido `0x035F` no enquadramento xKore 1. Em `--move-dispatch`, o relay extrai o destino e solicita o dispatcher nativo de movimento (`0x11`, `0xd473b0`, disparo no main-loop `0x4dcba0`). **O próprio cliente gera/cifra/envia** o `0x035F` e o pedido original é descartado, sem cifragem independente pelo relay. Rodada 06b demonstrou origem ponta a ponta, rodada 08 reproduziu após relogin e rodada 09 demonstrou integração via relay/OpenKore. Detalhes, argumentos, ABI e ensaios negativos permanecem em [MOVEMENT_035F_PRECONDITIONS.md](MOVEMENT_035F_PRECONDITIONS.md) ``13.8–13.13 e [MOVEMENT_035F_INVESTIGATION.md](MOVEMENT_035F_INVESTIGATION.md).

### Ataque e skills `0x0437` / `0x0438` / `0x0AF4`

Com `--action-merge`, o relay arma um corpo one-shot correspondente ao pacote do consumidor e necessita que o cliente monte naturalmente um carrier de mesmo ID/tamanho. A entrada `uinput`/`ydotool` (`--synth-input`, opt-in) dispara a ação no cliente; o store do scrambler substitui o corpo pré-XOR. A correção `_fix0` impede a regressão do primeiro byte na sequência executada.

Defaults de teclas configurados no CLI: `0437→INSERT`, `0438→9` (fileira superior) e `0AF4→F2`. Os defaults são do **CLI**, não prova de efeito em outras builds. O suporte está em `relay/cli.py`, `relay/writeback.py`, `relay/synth_input.py` e `agent/relay_hook_linux.js`. Em `0x0438` o corpo leva nível, skill e GID; em `0x0AF4` leva skill e coordenadas. A cifra e o envio continuam por responsabilidade do próprio cliente.

## 4. Reconciliação cronológica: conclusões refutadas e preservadas

| Evidência/etapa | Resultado correto e limite atual |
|---|---|
| ACT-20261016-01, dispatcher nativo de perícia `0x29→0x5a→0x2a` | **NEGATIVO na via testada**: `0x2a` retornou 0, sem `0x0438` na rede e com crash diferido. Isto **não contradiz** o êxito posterior via carrier+merge; são caminhos distintos. |
| Rodada 09b / `0x0368` | **REFUTADO como solução**: seleção/`0x0368` não era a correção necessária. A hipótese de *target lock* como causa raiz do ataque automático está **SUPERADA**. |
| ACT-20261016-02, merge isolado e personagem parado | **OBSERVADO na época**: `0x0437` efetivo com alvo válido; faixa de carrier obsoleta podia causar 0-WROTE; sidecar inicialmente dependia do log sem buffering. |
| ACT-20261016-03, AI automática falhando com `WROTE` | **OBSERVAÇÃO HISTÓRICA** real, mas sua explicação causal (estado de walk/alcance ou fila) foi **SUPERADA** pela correção do byte zero. Não relatar falha como presente. |
| `--egress-queue`, FIFO de quadros `S` | Funcionalidade de ordenação com testes offline; **REFUTADA como correção suficiente** para a falha automática observada. Não é causa do êxito final relatado. |
| `_fix0` no agente Frida + confirmação do responsável | **CONCLUSÃO ATUAL**: as funções automáticas operam; primeiro byte derivado do cliente era a causa da falha específica. |
| `0x8280` | Periodicidade Gepard observada na coleta histórica; não se requer inventar um `0x8280` antes de cada ação. |

Experimentos com GIDs inválidos, proximidade do alvo, XTEST vs. uinput, alocação de DRs e recaptura de `this` após relogin permanecem como **dados históricos importantes**. O fechamento funcional da linha de pesquisa não significa que toda hipótese sobre ABI, relogin, sessão ou controle tenha sido resolvida universalmente.

## 5. Proveniência, código e testes

| Origem | Escopo |
|---|---|
| `research/action_0437_0438/STATE.md` | Codes do dispatcher, SendPacket, testes negativos da via nativa |
| `research/action_0437_0438/HANDOFF.md`, ACT-01/02/03 | Cronologia dos ensaios, condições, validações parciais, diagnósticos superados |
| `research/action_0437_0438/MERGE_SYNTH_STATE.md` | Carrier, range, gatilhos, relogin, automação, hipóteses intermediárias |
| `research/action_0437_0438/HANDOFF_CODEX.md` | Problema de automação **histórico**, não backlog ainda aberto |
| `agent/relay_hook_linux.js:481-534` | Causa e correção `_fix0`, verificadas estaticamente |
| `relay/cli.py`, `relay/writeback.py`, `relay/synth_input.py` | Flags, roteamento, atuador integrado |
| `tests/test_writeback.py` | Casos offline de roteamento/merge/queue; não substituem teste live |

**Testes desta atualização documental:** leitura e revisão estática das fontes remotas. Nenhum teste live de movimento, ataque ou skills foi executado nesta edição; confirmação operacional conforme comunicação do responsável em 2026-10-17. Os validadores de repositório devem ser executados no CI/checkout. Os artefatos originais em `research/` não foram reescritos nem apagados.

## 6. Trabalho restante

**Somente a investigação da cifra é ativa.** Permanecem desconhecidos a geração do keystream, a evolução do estado por sessão, a inicialização/reinicialização e a fronteira completa plaintext/ciphertext, necessários para avaliar xKore 0 sem cliente. Ver [CIPHER_INVESTIGATION.md](CIPHER_INVESTIGATION.md), [CIPHER_TOOLS.md](CIPHER_TOOLS.md) e [RESEARCH_STATUS.md](RESEARCH_STATUS.md).

O encerramento de movimento/ação é **funcional no escopo uaRO atual**, não prova de portabilidade nem resolução dessas dependências criptográficas. Sem implementar backend xKore novo neste repositório. Nenhuma credencial ou captura bruta é reproduzida.
