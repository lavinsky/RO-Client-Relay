# Ações 0x0437, 0x0438 e 0x0AF4 — arquivo integral

> **Pesquisa funcional encerrada.** Ataque e skills automáticos funcionam segundo o responsável (2026-10-17). O defeito resolvido foi o primeiro byte sobrescrito pelo store do scrambler após o merge; o agente atual corrige esse byte com `_fix0` em `agent/relay_hook_linux.js:481-534`. Explicações anteriores sobre seleção/alcance eram intermediárias e foram superadas; não descartar seus logs/resultados.

## Índice de originais

- [`docs/ACTION_0437_0438_INVESTIGATION.md`](#source-docs-action-0437-0438-investigation-md) — blob `4c83b38cbaefbfe9fee6adea0ab93cbeb5953f5a`
- [`research/action_0437_0438/STATE.md`](#source-research-action-0437-0438-state-md) — blob `12aa84120b2a2c565503b4d89096d8682b3bb3cc`
- [`research/action_0437_0438/HANDOFF.md`](#source-research-action-0437-0438-handoff-md) — blob `c25f9d3d0efc28c74f00f7279137367425930a2f`
- [`research/action_0437_0438/HANDOFF_CODEX.md`](#source-research-action-0437-0438-handoff-codex-md) — blob `0956c99d40439bcce9f3d131ea2aa891cbc3336f`
- [`research/action_0437_0438/MERGE_SYNTH_STATE.md`](#source-research-action-0437-0438-merge-synth-state-md) — blob `7005eb5dc0eaf9179d962856329d348fb5d7037c`
- [`research/action_0437_0438/ISOLATION_SPIKE.md`](#source-research-action-0437-0438-isolation-spike-md) — blob `f2778e8702db453c4a999452e9d0094dda6aac6e`

## Método de preservação

Todas as fontes abaixo são reproduzidas **integralmente, sem edição**, inclusive experimentos negativos, propostas e limitações. Referências relativas embutidas nos originais mantêm o contexto histórico e não são links atuais garantidos.

<a id="source-docs-action-0437-0438-investigation-md"></a>

## Fonte original: `docs/ACTION_0437_0438_INVESTIGATION.md`

Commit-base da fonte: `69ea1aa7d119b92c54e22b7d19ed22e515350ebc` · blob: `4c83b38cbaefbfe9fee6adea0ab93cbeb5953f5a` · caracteres: 9458.

<!-- BEGIN ORIGINAL docs/ACTION_0437_0438_INVESTIGATION.md -->
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
<!-- END ORIGINAL docs/ACTION_0437_0438_INVESTIGATION.md -->

<a id="source-research-action-0437-0438-state-md"></a>

## Fonte original: `research/action_0437_0438/STATE.md`

Commit-base da fonte: `69ea1aa7d119b92c54e22b7d19ed22e515350ebc` · blob: `12aa84120b2a2c565503b4d89096d8682b3bb3cc` · caracteres: 6919.

<!-- BEGIN ORIGINAL research/action_0437_0438/STATE.md -->
# STATE — ação/perícia 0x0437 / 0x0438 (método MOVER aplicado)

_Trilha aberta 2026-10-16. Pergunta inicial: qual `code` do dispatcher `0xd473b0` origina 0x0437
(ação) e 0x0438 (perícia), análogo a `code 0x11 → 035f`? Evoluiu para: a ação/perícia podem ser
INJETADAS pela via nativa (como o PoC 035f)? Resposta curta: os codes de origem estão OBSERVADOS, mas
a injeção da perícia pela via nativa NÃO funciona do jeito testado (ver §Testes live)._

Classificação: **OBSERVADO** = medido ao vivo nesta build; **INFERIDO** = deduzido por sequência/cross-check;
**REFUTADO** = testado e negado; **RETIRADO** = afirmação minha anterior que não se sustenta.

---

## 1. Mapa code → pacote (OBSERVADO, ao vivo, read-only, corpos em claro conferindo com `relay/writeback.py`)

Captura com 2 HW exec BP (sem injeção): DR0 no dispatcher `0xd473b0` (lê `code=[esp+8]`, frame nos 13
dwords `[esp+4+4k]`), DR1 na `SendPacket(this,len,buf)` do cliente em **uaRO+0x816640 (VA `0xC16640`)**,
onde o pacote está EM CLARO antes do scrambler do Gepard (`mov [ecx],bl` em `gb+0x18eff2`). Tudo na main.

| ação (usuário) | dispatcher code | pacote CZ | corpo observado (hex) |
|---|---|---|---|
| andar | `0x11` (17) | 0x035f | frame `[0,17,0,X,0,Y,…]` (X,Y no próprio frame) |
| sentar/levantar | `0x1f` (31) | 0x0437 | `3704 <GID próprio> 02/03` (02=senta/03=levanta) |
| **atacar** | `0x28` (40) | **0x0437** | `3704 <GID> 07` (ação 07=ataque, GID≠0) |
| **usar perícia** | `0x2a` (42) | **0x0438** | `3804 0a00 0d00 <GID>` (nível 10, skill `0x0d`=13 Soul Strike) |
| selecionar alvo | `0x0a` (10) | (via 0x0368) | GID do alvo no frame arg3 |

Artefatos: `/tmp/claude-act-20261016-031147-sendpkt/observe.json` (map inicial);
`/tmp/claude-act-20261016-110249-soulstrike2/inject.json` (cast Soul Strike em claro = `3804 0a00 0d00 51c18e06`).
Sonda: `observe_dispatch_codes.py`.

## 2. ABI do dispatcher (OBSERVADO)
- `0x11` (move) carrega **X,Y no próprio frame** e comete sozinho.
- `0x28` (ataque) e `0x2a` (perícia) **NÃO levam args no frame** (`[0,40,0,0,…]` / `[0,42,0,0,…]`): leem
  **alvo/perícia correntes de estado global** montado por passos anteriores.
- Preparação (INFERIDO, por sequência + cross-check): `0x29` frame `[.,41,.,GID,.,13,…]` = seta skill id=13 + GID;
  `0x5a` frame `[.,90,.,10,…]` = seta nível=10; `0x0a` = seleciona alvo (GID). O corpo do 0438 (nível10/skill13)
  casa exatamente com `0x29`(skill13)+`0x5a`(nível10). **Cadeia de cast OBSERVADA: `0x29 → 0x5a → 0x2a`**
  (sem `0x0a` neste cast — o GID já vem embutido no frame do `0x29`; alvo também passou pela via do `0x0368`).

## 3. Caller imediato do dispatcher (OBSERVADO, sólido)
Em TODOS os codes, o retorno imediato na pilha (`[esp]`) é o **shim do Gepard `gepard+0xb2c251`** — o
Gepard relaia a chamada do dispatcher. (O PoC 035f contorna esse shim via `NativeFunction` direta e ainda
funciona, então o shim **não** é o bloqueio.)

## 4. Testes de INJEÇÃO nativa da perícia (ao vivo, autorizados) — resultado NEGATIVO
Método capture+replay: capturar os frames reais da conjuração do usuário e repeti-los via o mecanismo de
disparo do PoC 035f (captura passiva do `this`=ECX + chamada `thiscall` a partir do fire-site de main-loop
`0x4dcba0`). Sonda `inject_soulstrike_live.py`.
- **Rodada 1** (bug meu: replay de superset incluindo movimento `0x11` + code `0x00`): **CRASH** do cliente.
- **Rodada 2** (corrigido: allowlist estrita, cadeia congelada = `[0x29,0x5a,0x2a]`): as 3 chamadas retornaram
  (`0x29`→13, `0x5a`→17, `0x2a`→**0**) sem exceção, MAS **nenhum `0x0438` saiu na rede** (perícia NÃO conjurada)
  e o cliente **crashou de forma deferida** (chegou ao `DONE` aos 90s; caiu depois).
- **Conclusão (OBSERVADO):** disparar `0x29→0x5a→0x2a` do fire-site `0x4dcba0` é **inócuo** (`0x2a`→0, sem egress)
  **e instável**. Diferente do movimento (`0x11` carrega tudo e comete em segurança), o commit da perícia
  depende de estado/contexto que o handler de input natural monta e que esse disparo fora de contexto não tem.

## 5. REFUTADO e RETIRADO
- **REFUTADO (responsável, 2026-10-16):** a hipótese "o `0368` (CZ_REQNAME_BYGID) pré-ação era o bloqueio da
  SendPacket de 0437/0438" é FALSA. **Com ou sem `0368` o SendPacket SEMPRE ocorria**; o problema (ação sem
  efeito) é ANTERIOR ao `0368`, que foi tentativa que NÃO resolveu. Logo: rotear 0437/0438 pela SendPacket crua
  **não executa** a ação. A flag `--target-select` / `0368` em SKIP_IDS segue no código, mas NÃO é solução.
- **RETIRADO (meu erro, 2×):** as cadeias de chamadores obtidas por `Backtracer.FUZZY` e por walk de EBP. Ao
  validar no objdump, quase nenhum endereço é retorno de `call` genuíno (o "folha" `0x944002`/`0x943fda` cai
  dentro de um loop de 0x102 entradas após um `jb`; os "profundos" `0x874a40` [+3 após `call *0x98(eax)`],
  `0x874b32` [prólogo `push ebp;mov ebp,esp`+2], `0x874f0b` [após `mov`], `0x66baea` [prólogo SEH+0xa] não são
  retornos). As funções aqui não mantêm frame de EBP padrão (SEH/FPO) e o shim do Gepard provavelmente usa
  trampolim `ret`/`jmp`, quebrando a disciplina de pilha. **Toda afirmação de cadeia além do shim imediato fica
  RETIRADA**; o split "prepare vs commit" NÃO está provado.

## 6. Em aberto (o que resolver em seguida)
- **Sítio real que dispara o `0x2a`** e a **pré-condição/estado global** que ele lê (o que faz `0x2a` devolver 0
  fora de contexto). O stack-walk não resolve aqui.
- **Método proposto (read-only, ainda não feito):** *validated stack scan* — no BP do dispatcher, varrer a pilha
  e manter **só** os dwords `V` em `.text` do uaRO onde um `call` termina exatamente em `V` (checar bytes
  `V-5==E8` ou `V-6..-2` = `FF /2`), produzindo a cadeia de retornos VERDADEIRA sem depender de EBP. Alternativa:
  desmontar a partir de um frame comprovadamente genuíno; ou instrumentar o próprio shim para logar seu chamador.
- Se achado o sítio/precondição: avaliar injeção ou pela via natural (setar estado + disparar do sítio certo) ou
  por outra entrada. Movimento 035f segue funcionando como referência do padrão.

## 7. Ferramentas desta trilha (todas read-mostly; a de injeção só sob autorização direta)
- `observe_dispatch_codes.py` — map code→pacote (DR0 dispatcher + DR1 SendPacket). Read-only.
- `inject_soulstrike_live.py` — capture+replay da perícia (allowlist estrita; **disparo** — usar só sob OK direto).
- `capture_skill_callers.py` — caller via `Backtracer.FUZZY` (resultado RETIRADO — não confiável aqui).
- `capture_skill_ebp.py` — caller via EBP-walk (resultado RETIRADO — não confiável aqui).
- `debug_inventory.py` — (pré-existente da trilha; não alterado aqui).

## 8. Limpeza / limites
Todas as sondas finalizam com DR desarmado (DONE/stop); nenhuma sonda minha fica ativa. Build uaRO+gepard = MATCH.
Autorização direta do responsável para cada rodada ao vivo (servidor próprio). Não editei `docs/` nem
`relay/`/`agent/` — entrega ao Documentador via `HANDOFF.md`. Nenhum commit feito.
<!-- END ORIGINAL research/action_0437_0438/STATE.md -->

<a id="source-research-action-0437-0438-handoff-md"></a>

## Fonte original: `research/action_0437_0438/HANDOFF.md`

Commit-base da fonte: `69ea1aa7d119b92c54e22b7d19ed22e515350ebc` · blob: `c25f9d3d0efc28c74f00f7279137367425930a2f` · caracteres: 13556.

<!-- BEGIN ORIGINAL research/action_0437_0438/HANDOFF.md -->
# HANDOFF — ação/perícia 0x0437/0x0438 → Documentador

## ID: ACT-20261016-01 (método MOVER aplicado a 0437/0438 + testes de injeção nativa da perícia)
**Revisão base:** commit `6c20733` + sondas novas em `research/action_0437_0438/`.
**Autorização:** direta do responsável, ao vivo, para cada rodada (servidor próprio). Build uaRO+gepard = MATCH.
**Estado completo:** `research/action_0437_0438/STATE.md`. Artefatos privados (não versionar):
`/tmp/claude-act-20261016-031147-sendpkt/observe.json`, `/tmp/claude-act-20261016-110249-soulstrike2/inject.json`,
`/tmp/claude-act-20261016-111154-callers/callers.json`, `/tmp/claude-act-20261016-112037-ebp2/ebp.json`.

### OBSERVADO (ao vivo, read-only salvo §injeção)
- Mapa dispatcher `0xd473b0` → pacote: `0x11`→035f (andar; X,Y no frame); `0x1f`→0437 (sentar/levantar, GID
  próprio); **`0x28`→0437 (ataque, `3704 <GID> 07`)**; **`0x2a`→0438 (perícia, `3804 0a00 0d00 <GID>` =
  nível10/skill13 Soul Strike)**; `0x0a`→seleção de alvo. Fronteira em claro = `SendPacket` em
  uaRO+0x816640 (VA `0xC16640`); scrambler em `gb+0x18eff2`.
- `0x28`/`0x2a` **não levam args no frame** (leem alvo/perícia de estado global). Cadeia de cast observada:
  **`0x29`(skill13+GID) → `0x5a`(nível10) → `0x2a`(dispara)**.
- Caller imediato do dispatcher é SEMPRE o shim do Gepard **`gepard+0xb2c251`** (`[esp]`, todos os codes).

### INFERIDO (sequência + cross-check)
- `0x29` = seta skill id(13)+GID; `0x5a` = seta nível(10); `0x0a` = seleciona alvo. Cadeias: ataque = `0x0a→0x28`;
  perícia = `0x0a?→0x29→0x5a→0x2a`. O corpo do 0438 (nível10/skill13) casa com `0x29`+`0x5a`.

### TESTE DE INJEÇÃO (ao vivo, autorizado) — NEGATIVO
- Replay da cadeia de perícia (`0x29→0x5a→0x2a`) via mecanismo do PoC 035f (captura `this` + chamada thiscall do
  fire-site de main-loop `0x4dcba0`): `0x2a` retorna **0**, **nenhum `0x0438` sai na rede** (perícia NÃO conjurada)
  e o cliente **crasha** (rodada 1 por bug meu com movimento no replay; rodada 2, cadeia mínima limpa, crash
  deferido). CONCLUSÃO: a via nativa disparada de `0x4dcba0` é **inócua e instável** para a perícia — o commit
  depende de estado/contexto do handler de input que esse disparo não tem.

### REFUTADO
- "O `0368` pré-ação era o bloqueio da SendPacket de 0437/0438" — **FALSO** (responsável): o SendPacket sempre
  ocorria com/sem `0368`; o problema (ação sem efeito) é anterior ao `0368`. Rotear 0437/0438 pela SendPacket crua
  **não executa** a ação. → Corrigir qualquer doc que credite o `0368`/`--target-select` como solução de ataque/perícia
  (ver memória `movement-035f-poc-live-works` §ataque/perícia, já marcada como refutada).

### RETIRADO (não publicar como fato)
- Cadeias de chamadores do dispatcher obtidas por `Backtracer.FUZZY` e por EBP-walk: ao validar no objdump,
  os endereços não são retornos de `call` genuínos (frames SEH/FPO + trampolim do Gepard quebram a pilha). Só o
  shim imediato `gepard+0xb2c251` é confiável. O split "prepare vs commit" NÃO está provado.

### EM ABERTO / próxima decisão
- Achar o sítio real de disparo do `0x2a` e a pré-condição que ele lê, via **validated stack scan** (read-only;
  manter só dwords da pilha que são retorno de `call` comprovado no disassembly). Responsável mantém janela ao
  vivo disponível (estabilidade não é problema; pode reabrir o cliente e reconjurar à vontade).

### Sugestão de integração em `docs/` (decisão do Documentador)
- `docs/GEPARD_CONTROL_PACKETS.md`: registrar codes `0x28`/`0x2a`/`0x1f`/`0x0a` e a cadeia de cast.
- `docs/MOVEMENT_035F_PRECONDITIONS.md`: nota de que a via nativa (fire-site `0x4dcba0`) **não** transfere para a
  perícia (OBSERVADO), distinta do movimento.
- Corrigir no índice/‘status’ a REFUTAÇÃO do `0368` como solução.

**Verificações:** `py_compile` de todas as sondas OK; `tests/test_movement_preconditions.py` PASS;
`scripts/validate-research.py` PASS. **Limpeza:** nenhuma sonda ativa; `docs/`/`relay/`/`agent/` não editados;
nenhum commit.

---

## ID: ACT-20261016-02 (merge do scrambler + entrada sintética + anti-freeze no relogin)
**Revisão base:** commit `2a2b0f0` + mudanças no working tree em `relay/`, `agent/`, `tests/` + sondas novas
em `research/action_0437_0438/`. **Autorização:** direta do responsável, ao vivo, por rodada (servidor
próprio). Build uaRO+gepard = MATCH. **Estado completo:** `research/action_0437_0438/MERGE_SYNTH_STATE.md`.

### OBSERVADO (ao vivo)
- **Entrada sintética passa no Gepard** por uinput (`ydotool`/`ydotoold`), **não** por XTEST; precisa da
  janela **focada** (reafirmar `wmctrl -i -a` por tecla) e **hold ~120 ms**. INSERT sintético → sentou.
- **Merge reescreve o buffer de saída real e o servidor aceita ação SEM alvo:** teste isolado
  (`isolated_merge.py`, sem relay/sem consumidor) — corpo LEVANTAR armado → 9/10 WROTE
  `was=…02 -> now=…03`, personagem ficou de pé (confirmado). Carrier vivo em **0x25ba03xx**, match
  `reg=ecx off=-2` no store `gepard+0x18eff2`.
- **Causa do 0-WROTE do relay = faixa (scramble-range) obsoleta:** carrier abaixo do piso fixo
  `0x2632000` (conf `2632000-2730000`); filtro auto do agente rejeitava todo carrier. Correção: faixa
  vazia/larga **pelo CLI** (`--scramble-range ''`), **sem** editar a conf.
- **Freeze no relogin:** `this` da move-dispatch capturado uma vez vira ponteiro para objeto de mapa
  liberado após mapa→login→mapa; firar congela (`queue full` → `connection-terminated`).

### RESOLVIDO (OBSERVADO ao vivo, confirmado pelo responsável)
- **Ação COM alvo (ataque 07) EXECUTA pelo merge.** A conclusão anterior ("não executa") era **viés de
  teste**: armávamos GID inválido (marcador `0xdeadbeef`, GID próprio da geometria de sit, ou alvo morto).
  A/B limpo (`isolated_merge.py`, sem relay): (1) com marcador armado, ler o GID do alvo vivo dos ataques
  naturais do cliente (`was=49c3d70607` = GID `0x06d7c349`; o clobber-marcador mantém o mob vivo na leitura);
  (2) char parado+adjacente ao mesmo mob vivo, armar `49c3d70607`, INSERT sintético → sit reescrito p/
  `49c3d70607` → **mob tomou dano** (responsável: "FUncionou"). Um 0437 de ataque reescrito pelo merge é
  byte-idêntico a um natural; servidor aceita **sse GID for alvo VIVO e char em alcance**. Detalhe:
  `MERGE_SYNTH_STATE.md` §4.

### EM ABERTO (não publicar como resolvido)
- **Perícia 0438 com alvo pelo merge: HIPÓTESE não medida** (testamos ataque 0437, não 0438). Falta uma
  tecla do cliente que emita um 0438 de cast imediato (a tecla "9"/keycode 10 não emitiu). A via **nativa**
  segue inócua p/ perícia (`STATE.md` §§4–6) — não confundir com o merge.

### RETIRADO
- "Sentar bloqueia atacar" (meu) — refutado pela prova LEVANTAR. "Ataque com alvo não executa pelo merge"
  (minha conclusão na revisão anterior) — era GID armado inválido; REFUTADO pelo A/B acima. Leitura de um
  `0x008a` como sucesso de ataque (meu) — era pacote não relacionado.

### IMPLEMENTAÇÃO (working tree; sem commit)
- `--action-merge` (`relay/cli.py:85`): roteia 0437/0438/0af4 do consumidor ao merge do scrambler (OFF por
  padrão; só roteamento). `relay/writeback.py`: `ACTION_MERGE_IDS` + ramo em `_on_inbound_split`.
- **Anti-freeze recapture-on-reconnect:** `relay/relay.py:37-39,73-79` (`on_connect` só em RE-conexão),
  `relay/writeback.py:207-214,107`, `relay/protocol.py:106-124` (`recapture=True`),
  `agent/relay_hook_linux.js:716-726` (zera `this`, re-arma DR2, nunca fira sem `this`).
- `.gitignore`: `research/**/captures/`.

### Sugestão de integração em `docs/` (decisão do Documentador)
- `docs/RESEARCH_STATUS.md` / índice: registrar o merge como via de **ação sem alvo** comprovada e a
  faixa-obsoleta como causa do 0-WROTE; manter a ação **com alvo** como EM ABERTO (não creditar solução).
- `docs/GEPARD_CONTROL_PACKETS.md`: nota de `--action-merge` (roteamento 0437/0438/0af4 ao store
  `gepard+0x18eff2`, pré-XOR).

### EM ABERTO / próxima decisão
- Fiar `--action-merge` para armar o corpo do próprio `0437` do consumidor (`3704 <GID alvo> 07`) e deixar o
  OpenKore pathear em alcance (ataque com alvo já RESOLVIDO no isolado). Testar perícia 0438 (carrier de cast
  imediato). Validar o fix de freeze ao vivo (mapa→login→mapa + andar uma vez). Fase 2: atuador de input no
  relay (flag, default OFF). Prioridade 2: gamescope headless + uinput (`ISOLATION_SPIKE.md`).

**Verificações:** `python3 -m py_compile` OK; `node --check agent/relay_hook_linux.js` → JS OK;
`bash scripts/test-offline.sh` → **ALL PASS (11 scripts)** (inclui move-dispatch e action-merge routing);
`tests/test_writeback.py` +30 linhas. **Ao vivo: NÃO verificado.** **Limpeza:** nenhuma sonda ativa;
nenhum commit.

### RESOLVIDO (2026-10-16, validação ao vivo — responsável: "Funcionou, ele atacou")
- **Cadeia completa do relay (opção 1) hands-free com char PARADO.** Após reiniciar com `-u` (stdout
  unbuffered — era a causa do "só funcionou manualmente": $LOG vazio → `action_trigger` cego), o log cresce
  ao vivo e o trigger dispara o INSERT sozinho. Com char estacionário (`0087 src==dst`), mob adjacente, AI on:
  OpenKore enviou o **próprio** corpo 0437 de ataque `3704 <GIDalvo> 07` (ação 07) → relay armou
  (`scramble body map`) → INSERT sintético → `[scramble] WROTE id=0x0437 was=…02 -> …07`, **`move-dispatch
  fired=0`** (não andou). Ataque confirmado na tela pelo responsável.
- **Raiz da intermitência CONFIRMADA = conflito andar×atacar:** com `--move-dispatch` o char anda
  continuamente e raramente assenta em alcance; o ataque só commita parado+em alcance. É **coordenação do
  OpenKore** (attackAuto/route/attackDistance), não defeito do relay. Próximo: Tarefa #6.
- **CAVEAT métrica:** `0x008a` é actor_action/dano **legado**; o uaRO moderno usa opcode mais novo
  (família `0x02e1`/`0x08c8`), então `008a≈0` mesmo em acerto. Usar a cadeia WROTE + confirmação visual.
- **Nota de ambiente:** OpenKore roda em container podman (`openkore-env`); console `/dev/pts/7` é do conmon,
  então escrita do host (`printf > /dev/pts/7`) **não** chega — só o responsável dirige o console do OpenKore.
- **Launcher:** `research/action_0437_0438/run_action_merge.sh` (`--move-dispatch --action-merge
  --scramble-range ''` + `action_trigger.py` sidecar, relay sob `python -u`).

---

## ID: ACT-20261016-03 (fila de egresso + BLOQUEIO do modo automático)
**Revisão base:** working tree sobre `2a2b0f0` (sem commit). **Autorização:** responsável, ao vivo, por
rodada (servidor próprio). **Estado completo:** `MERGE_SYNTH_STATE.md` §8. **Handoff Codex dedicado:**
`research/action_0437_0438/HANDOFF_CODEX.md`.

### OBSERVADO (ao vivo, 2026-10-16)
- **0437 e 0438 commitam quando o comando é DIGITADO no console do OpenKore** (char assentado). Tecla do
  carrier: 0437→INSERT, **0438→`9` da fileira de cima** (KEY_9=10, NÃO numpad), 0af4→F2.
- **A AI em modo AUTOMÁTICO não ataca nem lança perícia**, apesar de o merge escrever. Log vivo: OpenKore
  **emite** 0437 c/ GID do alvo e o scrambler escreve (22 `WROTE`/26 `inbound`, `was=<GIDpróprio>02` →
  `<GIDalvo>07`), mas os despachos nativos de **035f chegam contínuos** (destinos mudando) e os `WROTE` caem
  **no meio** → char **andando** no instante da reescrita → ação não commita. Manual = char parado = commita.

- **Teste decisivo (CAUSA RAIZ CONFIRMADA):** no manual, atacar mob **fora de alcance** → OpenKore anda e
  ataca → **FALHA** (igual ao auto); só commita quando o comando chega **já EM ALCANCE**. ⇒ a ação commita
  **sse emitida com o char EM ALCANCE e ASSENTADO** (sem rota antes/junto). Console nunca foi exceção. A
  hipótese de seleção/lock de alvo fica **APOSENTADA** como causa.

### INFERIDO
- 035f = "mover até destino" (multi-tile); o auto **roteia até o mob e ataca na transição de chegada**, com
  o cliente ainda em estado de movimento (move-dispatch executando o último 035f) → não commita. Pacear o
  **despacho** (fila) não cria janela parada — serializa **ordem**, não o **efeito** walk×tecla.
- **Fix (p/ Codex, `HANDOFF_CODEX.md` hip. 0):** ao armar ação, fazer o cliente **parar/assentar** (onde o
  OpenKore já o julga em alcance) **antes** da tecla; provável bastar uma vez pra travar o 1º golpe.

### IMPLEMENTAÇÃO (working tree; sem commit)
- **`--egress-queue`** (`relay/cli.py`, `relay/writeback.py:_egress_enqueue`/`_egress_drain`): fila FIFO
  única, serializa só quadros **`S`** (035f/0437/0438), **ignora `R`** (recv espelhado — afogava a FIFO:
  542 drops `typ='R'` antes do filtro). Flags: `--egress-interval-ms` (default **400**), `--egress-action-
  gap-ms` (400), `--egress-max-age-ms` (**800**, dropa pacote velho na fila). `tests/test_writeback.py`:
  casos FIFO + stale-drop + filtro-`R`. **Suíte offline: ALL PASS (11).**
- **`action_trigger.py`**: `--key-0438` default `9`. **`run_action_merge.sh`**: passa `--egress-queue
  --egress-interval-ms 400`, relay sob `python -u`.

### REFUTADO / não reabrir
- Fila não resolve o bloqueio (é **estado do cliente**, não ordem). Via **nativa** de ação (`0x28`/`0x2a`
  do fire-site `0x4dcba0`) continua inócua/instável (ACT-20261016-01). `0368` pré-select NÃO é solução.

### EM ABERTO / próxima decisão (p/ Codex — ver HANDOFF_CODEX.md)
- Fazer o char **assentar** em alcance no instante da ação: (a) pausar o move-dispatch numa janela quando há
  ação armada; (b) coordenar pelo OpenKore (`attackDistance`/`route`, Tarefa #6); (c) gate de "char idle".

**Verificações:** `python3 -m py_compile` OK; `bash scripts/test-offline.sh` → **ALL PASS (11)**;
`node --check agent/relay_hook_linux.js` → JS OK. **Ao vivo:** manual PASS, automático **FALHA** (bloqueio
acima). **Limpeza:** nenhuma sonda ativa; nenhum commit.
<!-- END ORIGINAL research/action_0437_0438/HANDOFF.md -->

<a id="source-research-action-0437-0438-handoff-codex-md"></a>

## Fonte original: `research/action_0437_0438/HANDOFF_CODEX.md`

Commit-base da fonte: `69ea1aa7d119b92c54e22b7d19ed22e515350ebc` · blob: `0956c99d40439bcce9f3d131ea2aa891cbc3336f` · caracteres: 8642.

<!-- BEGIN ORIGINAL research/action_0437_0438/HANDOFF_CODEX.md -->
# HANDOFF → Codex — bot anda+ataca sozinho: resolver o BLOQUEIO do modo automático

**Data:** 2026-10-16. **Autorização:** servidor próprio, ao vivo, por rodada (responsável presente).
Build uaRO+gepard = MATCH. **Sem commit.** Convenção de evidência: `docs/RESEARCH_DECISIONS.md`
(OBSERVADO / INFERIDO / HIPÓTESE / NÃO VERIFICADO / REFUTADO). Estado longo: `MERGE_SYNTH_STATE.md` §8;
histórico: `HANDOFF.md` ACT-20261016-02/03.

## Objetivo
OpenKore deve **andar e atacar/lançar perícia sozinho** no cliente uaRO via relay. Andar já é autônomo
(move-dispatch). Atacar/lançar funciona **manualmente** mas **NÃO** com a AI em automático. Resolver isso.

## O que JÁ funciona (OBSERVADO ao vivo)
- **Mecanismo de ação pelo merge:** OpenKore manda `0437` (`3704 <GID alvo> 07`) / `0438` → o relay
  **arma** o corpo no body-map do scrambler → uma **tecla sintética** (ydotool/uinput, passa no Gepard;
  0437→INSERT, 0438→**`9`** da fileira de cima = KEY_9=10, 0af4→F2) faz o cliente montar um carrier (sit)
  → o store `gepard+0x18eff2` reescreve o corpo pré-XOR (`…02` → `…07`) → **a ação executa**.
- **Com o char PARADO + alvo adjacente:** a cadeia commita **hands-free** (responsável: "Funcionou, ele
  atacou"). **Digitando o comando no console do OpenKore:** 0437 e 0438 funcionam perfeitamente.

## O PROBLEMA (OBSERVADO ao vivo, 2026-10-16) — foco do handoff
A **AI em automático não ataca/lança**, embora o merge escreva. Evidência do log vivo do relay:
- OpenKore **emite** o 0437 com o GID do alvo e o scrambler **escreve** (≈22 `WROTE` / 26 `inbound`;
  carrier `was=<GIDpróprio>02` → `<GIDalvo>07`).
- Mas os despachos nativos de **035f chegam em fluxo contínuo** (destinos mudando a cada poucos ms:
  ex. (158,191)→(155,201)→(152,205)→(162,212)→(166,213)…) e cada `WROTE` cai **no meio** desse fluxo.
- **→ o char está ANDANDO no instante em que o carrier é reescrito → a ação não commita.** No manual o
  char está assentado → commita.

**INFERIDO:** `035f` é "mover até o destino" (multi-tile), não "um passo". Pacear o **despacho** (já feito:
fila FIFO `--egress-queue`, 400ms entre pacotes, +400ms após ação, drop >800ms) **cria janela parada**

**OBSERVADO — refinamento decisivo (responsável, 2026-10-16):** com a AI em automático, se o responsável
**ataca MANUALMENTE pelo cliente** o mesmo monstro que o consumidor quer atacar, **para de atacar e ANDA
PARA LONGE**, então o consumidor **passa a atacar aquele monstro automaticamente** (pela via do merge).
→ **IMPLICAÇÃO (reorienta a causa raiz):** como volta a funcionar mesmo depois de **andar para longe**, o
gate **não é** estar parado/adjacente nem o estado de movimento — é o cliente ter **ADQUIRIDO o alvo**
(seleção/lock de alvo **do lado do cliente**), que o ataque manual estabelece e **persiste**, e que o
`0437` do merge **sozinho NÃO estabelece** (ele leva o GID no pacote ao servidor, mas não seta o estado de
alvo local do cliente). A hipótese do walk-state passa a **secundária**; a primária é **seleção de alvo no
cliente** (provável ligação com o code `0x0a` "selecionar alvo" do dispatcher e/ou o pacote `0368`).

**OBSERVADO — teste decisivo (responsável, 2026-10-16), RESOLVE o paradoxo do console:** no modo manual,
pedir ataque num mob **FORA de alcance** → o OpenKore **anda até o mob e então ataca** → **FALHA** (igual
ao auto). O ataque **só commita quando o comando chega com o char JÁ EM ALCANCE** do mob. → O console
nunca foi exceção: só funcionava quando o comando saía **em alcance**. **CAUSA RAIZ CONFIRMADA:** a ação
commita **sse emitida com o char EM ALCANCE e ASSENTADO** (sem rota imediatamente antes/junto). O auto
falha porque **roteia até o mob e ataca na transição de chegada**, com o cliente ainda em estado de
movimento (move-dispatch executando o último 035f). **A hipótese de seleção/lock de alvo fica APOSENTADA
como causa** (o gate é alcance+assentar, não aquisição de alvo); `C` encaixa: engajou em alcance à mão e o
auto depois reataca também em alcance.

## Hipóteses a testar (ordene por custo; valide OFFLINE antes de ao vivo)
0. **(PRIMÁRIA — CONFIRMADA pelo teste de alcance) Assentar EM ALCANCE antes da ação.** A ação só commita
   com o char **em alcance e parado** no instante do carrier; roteia-e-ataca falha (manual e auto). O fix é
   garantir que, quando um `0437/0438` está armado, o cliente **pare de se mover e assente** (na posição em
   que o OpenKore já o julga em alcance — é ele quem decide emitir o ataque) **antes** da tecla sintética.
   Provável bastar **uma vez**, pra travar o 1º golpe; depois sustenta (ver `C`). Onde mexer:
   - `relay/writeback.py` `_egress_drain` (ponto único serializado): ao despachar uma ação, **suprimir os
     035f enfileirados por uma janela** (segurar/dropar `WALK_ID` enquanto `now < until`) para o char parar;
     considerar emitir um **stop de movimento** no cliente antes do carrier. A tecla sintética **já vive no
     relay** (`--synth-input`, `relay/synth_input.py`, disparada em `_on_inbound_scramble`), então "parar de
     andar" e "apertar a tecla" podem ser casados no mesmo relógio sem processo externo.
   - Desafio: o move-dispatch e o estado de movimento do CLIENTE podem estar **dessincronizados** da posição
     que o OpenKore acha (por isso a ação cai "na transição de chegada"). Medir essa defasagem.
   Refs p/ a implementação: `_on_inbound_split` ramo `WALK_ID`+`md` → `post_move_dispatch`; ramo de ação
   → `_on_inbound_scramble`, que ao armar chama `self.synth.on_armed(pid)` (`relay/synth_input.py`
   `SynthActuator`). "Parar de andar" e "apertar a tecla" podem ser casados nesse ponto, no mesmo relógio.
1. **(complementar) Coordenar pelo OpenKore para parar em alcance (Tarefa #6).**
   `attackDistance`/`attackMaxDistance`/`route_step` p/ o bot **parar junto do mob** e atacar em alcance,
   em vez de rotear reto. Config do consumidor; não é defeito do relay. Testar `config.txt`/`mon_control`.
2. **Gate "char idle".** Condicionar a tecla sintética a um sinal de char parado (ausência de 035f recente
   ou leitura read-only do estado de movimento). Mais caro; só se (0)/(1) não bastarem.

## REFUTADO / não reabrir
- Via **nativa** de ação (`0x28` ataque / `0x2a` perícia disparados do fire-site `0x4dcba0`): inócua e
  instável (retorna 0, sem egress, crash) — `HANDOFF.md` ACT-20261016-01. **Não** tente dispará-la de novo.
- `0368` pré-select como "solução de ataque/perícia": REFUTADO pelo responsável (ação sai com/sem ele).
- **Fila de egresso não resolve** este bloqueio (é estado do cliente, não ordem de despacho).

## Como rodar (ao vivo, servidor próprio)
- Launcher: `./run.sh [--port 27053] [--wid <wid>]` (ou `research/action_0437_0438/run_action_merge.sh`)
  — UM processo: o relay com `--move-dispatch --action-merge --egress-queue --egress-interval-ms 400
  --synth-input --synth-wid <wid> --scramble-range ''` (`python -u`). A tecla (0437→INSERT, 0438→`9`,
  0af4→F2) é disparada pelo módulo `relay/synth_input.py`, não mais pelo sidecar `action_trigger.py`.
  Pré-req: `ydotoold` rodando, janela do cliente focável, gadget na 27053. Pós relogin, **ande uma vez**
  (recaptura passiva do `this`, DR2).
- OpenKore roda em container podman (`openkore-env`); o console (`/dev/pts/7`) é do conmon → **só o
  responsável** dirige o console (host não alcança).
- Evidência no stdout do relay: `[inject] inbound id=0x0437 … scramble body map` (arme), `[scramble] WROTE
  id=0x0437 … was=…02 -> …07` (reescrita), `[inject] 035f -> native dispatch to (x,y)` (walk),
  `[egress] drop …` (fila). `0x008a` (dano) é opcode **legado**; não usar como métrica neste build.

## Teste de aceitação
- OFFLINE: `bash scripts/test-offline.sh` → **ALL PASS (11)** após qualquer mudança em `relay/`/`agent/`;
  `python3 scripts/validate-research.py` PASS. `node --check agent/relay_hook_linux.js`.
- AO VIVO (responsável): com a AI em **automático**, o char **para junto do mob e ataca** (dano na tela),
  de forma repetida, sem comando manual. **Não** relatar sucesso ao vivo a partir de offline.

## Limites / invariantes
- Máx. 2 subagentes. Sem credenciais/contas/**GIDs**/IPs/capturas cruas em docs/commits (use marcador).
- `relay_capture.conf` mantém `inject=true`/`inject-call=true` intocados; `scramble-range` **pode** ser
  sobrescrito no CLI (`--scramble-range ''`). Commit local só após teste, com paths explícitos; sem push.
- Fontes: `agent/relay_hook_linux.js`, `relay/{cli,writeback,relay,protocol,synth_input}.py`,
  `research/action_0437_0438/run_action_merge.sh`. (`action_trigger.py`/`synth_input.py` em research/
  ficaram como ferramenta manual; o disparo de produção é `relay/synth_input.py` via `--synth-input`.)
<!-- END ORIGINAL research/action_0437_0438/HANDOFF_CODEX.md -->

<a id="source-research-action-0437-0438-merge-synth-state-md"></a>

## Fonte original: `research/action_0437_0438/MERGE_SYNTH_STATE.md`

Commit-base da fonte: `69ea1aa7d119b92c54e22b7d19ed22e515350ebc` · blob: `7005eb5dc0eaf9179d962856329d348fb5d7037c` · caracteres: 16350.

<!-- BEGIN ORIGINAL research/action_0437_0438/MERGE_SYNTH_STATE.md -->
# STATE — merge do scrambler + entrada sintética + anti-freeze (trilha de execução de ação)

_Trilha aberta 2026-10-16. Pergunta: uma ação do **consumidor** (OpenKore) — 0x0437 (sentar/levantar,
atacar) ou 0x0438 (perícia) — pode ser **executada no cliente** reescrevendo um carrier natural no
scrambler do Gepard (**merge**, igual ao mapa de corpos do 035f), tendo a **entrada sintética** como
fonte do carrier, no **desktop normal**? E: corrigir o **congelamento no relogin** da via move-dispatch._

_Resposta curta: o merge reescreve o buffer real e o servidor **aceita ação sem alvo** (sentar/levantar)
**E ação com alvo** (ataque 07) — ambos OBSERVADOS ao vivo. A falha anterior do ataque era **viés de teste
(GID armado inválido/obsoleto)**, não falha do mecanismo (§4, RESOLVIDO). A causa do 0-WROTE do relay era a
**faixa (scramble-range) obsoleta** — OBSERVADO/CORRIGIDO. O freeze no relogin foi **diagnosticado e
corrigido** (fix passa offline; **falta** validação ao vivo). Perícia (0438) com alvo pelo merge: HIPÓTESE
não medida._

Classificação: **OBSERVADO** = medido ao vivo nesta build; **INFERIDO** = deduzido por sequência/cross-check;
**HIPÓTESE** = plausível, não medido; **REFUTADO** = testado e negado; **RETIRADO** = afirmação minha
anterior que não se sustenta. Build uaRO+gepard = MATCH. Autorização direta do responsável, ao vivo, por
rodada (servidor próprio). Esta trilha é complementar à injeção nativa de perícia em `STATE.md` §§4–6.

---

## 1. Entrada sintética passa no Gepard (OBSERVADO)
- O Gepard **filtra XTEST** (`xdotool`/Xvfb como *input*) mas aceita eventos de **uinput**
  (`ydotool`/`ydotoold`), que chegam ao Wine como hardware. Sonda: `synth_input.py:1` (cabeçalho e
  contexto), keycodes em `synth_input.py:30`.
- **Duas pré-condições OBSERVADAS para o keystroke pegar:** (a) a janela do uaRO **focada no momento do
  keypress** e (b) **HOLD ~120 ms** (press→sleep→release). O foco **tem de ser reafirmado a cada tecla**
  (`wmctrl -i -a <wid>` antes de cada envio): sem isso `xdotool getactivewindow` vinha vazio e nada
  chegava. Memória: [[synth-input-needs-focus-reassert]], [[synthetic-movement-uaro-hybrid-input]].
- **Prova:** INSERT sintético → personagem **sentou** (confirmado pelo responsável). Efeito colateral: o
  evento uinput é global ao seat0 (atrapalha o uso real); isolamento limpo é o passo 2 (ver
  `ISOLATION_SPIKE.md`).

## 2. O merge reescreve o buffer real; o servidor aceita ação SEM alvo (OBSERVADO, teste isolado)
Sonda independente do relay e do OpenKore: `isolated_merge.py` — DR0 em `gepard+0x18eff2` (store do
scrambler, pré-XOR, in-place), **sem** filtro de faixa; a cada hit varre `eax/ebx/ecx/edx/esi/edi/ebp`
e, se `[reg+off]==0x0437` (`off∈{-2,0}`), grava o corpo armado em `reg+off+2` (`isolated_merge.py:62-82`).
- **Prova 1 (endereço/mecanismo):** corpo-marcador armado, 11 INSERTs focados → **11/11 WROTE**, carrier em
  **0x25ba03xx**, todos `in_old_range=False`. Geometria do match: `reg=ecx, off=-2` (ponteiro no corpo;
  cabeçalho `3704` 2 bytes antes).
- **Prova 2 (ponta-a-ponta, ação sem alvo):** corpo armado = **LEVANTAR** (`0000000003`), 10 INSERTs →
  **9 WROTE** `was=0000000002 -> now=0000000003`, e o personagem **ficou de pé / nunca sentou**
  (confirmado pelo responsável). Logo o rewrite **chega ao buffer de saída real** e o servidor **aceita**
  a ação sem alvo reescrita. Memória: [[merge-0437-works-stale-range-was-bug]].

## 3. A faixa (scramble-range) obsoleta era o 0-WROTE do relay (OBSERVADO; hipótese do responsável CONFIRMADA)
- O carrier vivo fica em **0x25ba03xx**, **abaixo** do piso fixo do relay `0x2632000` (conf:
  `scramble-range 2632000-2730000`). O filtro auto do agente
  (`agent/relay_hook_linux.js` ~L493, `if (scr.lo!==null && (r<scr.lo||r>=scr.hi)) continue`) **rejeitava
  silenciosamente** todo carrier real → nunca escrevia. O 035f seguia funcionando só porque a via
  move-dispatch **contorna** o caminho do scrambler.
- A faixa é **específica de sessão/heap** (relogin/restart a move); valor fixo é a armadilha.
- **Correção:** rodar com faixa **vazia** (`--scramble-range ''` → `scr.lo=null`, match só por id, o mais
  robusto) ou faixa larga, **via CLI**. **Não** editar `scramble-range` em `relay_capture.conf` sem
  decisão humana (a conf mantém `inject`/`inject-call` propositalmente — AGENTS.md; a faixa **não** é parte
  desse invariante protegido e pode ser sobrescrita no CLI). Verificar sucesso no log por
  `[scramble] WROTE id=0x0437` (NÃO "SCRAMBLE hit").

## 4. Ação COM alvo (ataque 07) EXECUTA pelo merge — RESOLVIDO (OBSERVADO 2026-10-16)
**A falha anterior era VIÉS DE TESTE (GID armado inválido), não falha do mecanismo.** Nada no código
regrediu; o merge de ataque sempre funcionou. Prova decisiva (A/B isolado, `isolated_merge.py`, sem relay):
- **Passo 1 — ler o GID real do alvo vivo:** com corpo-marcador armado, o responsável clicou-atacou o mob;
  a sonda logou os ataques naturais do cliente em `was=` = `3704 <GID do alvo LE> 07` (ex.: `49c3d70607`
  = GID `0x06d7c349`, ação 07; 15 hits = alvo vivo e em alcance). A sonda-marcador derruba esses ataques
  (viram `deadbeef`), **mantendo o mob vivo** durante a leitura.
- **Passo 2 — armar o GID vivo + disparar em alcance:** char **parado e adjacente** ao mesmo mob vivo; armei
  `49c3d70607`; INSERT sintético gerou o carrier de sit (que, com alvo selecionado, já vinha
  `was=49c3d70602`) → reescrito para **`49c3d70607`** → **o mob tomou dano / combate iniciou**
  (confirmado pelo responsável).
- **Conclusão (OBSERVADO):** um `0437` de ataque reescrito pelo merge é **byte-idêntico** a um ataque
  natural e o servidor **aceita**, desde que o **GID armado seja um alvo VIVO** e o char esteja **em
  alcance**. "Funcionou antes / não funcionava" = **GID vivo+alcance** vs **GID marcador/próprio/obsoleto**
  (alvo morto, inexistente `0xdeadbeef`, ou GID próprio da geometria de sit). Alvo obsoleto → servidor
  descarta em silêncio → "sentou normal / nada aconteceu".
- **RETIRADO (meu erro):** "sentar bloqueia atacar" (refutado pela Prova 2/LEVANTAR §2); "ataque com alvo não
  executa pelo merge" (a própria conclusão desta seção na revisão anterior — vinha de armar GID inválido);
  leitura de um `0x008a` como sucesso de ataque (pacote não relacionado).
- **Implicação para o relay (`--action-merge`):** em produção o OpenKore fornece o **GID de alvo vivo** (ele
  rastreia os GIDs dos mobs) e **patheia o char em alcance** antes — então a fragilidade de GID obsoleto do
  teste manual **não existe** no fluxo real: o relay arma o corpo do próprio `0437` do consumidor
  (`3704 <GID alvo> 07`), que já traz o GID certo. Ver §6/Passo subsequente.
- **Perícia (0438) com alvo:** NÃO reprovada por este teste (testamos ataque 0437). A via **nativa**
  (fire-site) continua inócua p/ perícia (`STATE.md` §§4–6); se a perícia com alvo segue o mesmo padrão do
  ataque, o merge deve aceitá-la com skill/nível/GID válidos — **HIPÓTESE, ainda não medida** (falta uma
  tecla do cliente que emita um 0438 de cast imediato; a tecla "9"/keycode 10 não emitiu).

## 5. Freeze no relogin — diagnosticado e CORRIGIDO (causa OBSERVADA; fix PASS offline; ao vivo NÃO verificado)
- **Causa (OBSERVADA):** a move-dispatch captura o `this` (ecx) do dispatcher **uma vez** em `0xd473b0` e o
  reutiliza; depois de **mapa→login→mapa** esse ponteiro aponta para um **objeto de mapa já liberado**;
  firar o dispatcher nativo com ele **congela** o cliente — manifesta como `[move-dispatch] dropped
  e=queue full` seguido de `[!] detached: connection-terminated`.
- **Fix (recapture-on-reconnect):**
  - `relay/relay.py:37-39,73-79` — `on_connect` dispara **só em RE-conexão** (`_connected_once` separa o
    primeiro connect dos reconnects); callback nunca mata o loop de conexão.
  - `relay/writeback.py:207-214` (`recapture_move_dispatch`) + fio em `:107`
    (`relay.on_connect = self.recapture_move_dispatch`, só sob `--move-dispatch`).
  - `relay/protocol.py:106-124` — `move_dispatch_msg(recapture=True)`.
  - `agent/relay_hook_linux.js:716-726` — ramo `recapture`: zera `md.thisp`, descarta a fila, desarma o
    fire (DR3), re-arma a **captura passiva** (DR2); **nunca** fira com `this` nulo. Depois o responsável
    **anda uma vez** pós-relogin para recapturar um `this` fresco.
- **Verificação offline:** `python3 -m py_compile` OK; `node --check agent/relay_hook_linux.js` → "JS OK";
  `bash scripts/test-offline.sh` → **ALL PASS (11 scripts)**, incluindo "move-dispatch routing ok" e
  "action-merge routing ok"; `tests/test_writeback.py` +30 linhas. **Ao vivo: NÃO verificado** — por
  AGENTS.md, não se relata sucesso em cliente real a partir de teste offline.

## 6. Implementação entregue nesta fase (resumo)
- **`--action-merge`** (`relay/cli.py:85-88`): roteia 0x0437/0x0438/0x0af4 do consumidor ao **merge** do
  scrambler (mapa de corpos one-shot, como o 035f) em vez da SendPacket do cliente. **OFF por padrão.**
  Só roteamento — o **cliente precisa construir** aquele id (via entrada sintética) para sair. Suporte em
  `relay/writeback.py`: `ACTION_MERGE_IDS` (`:31`) + ramo em `_on_inbound_split` (`~:262`, gated por
  `opts.action_merge` + `_scramble_armed`). Arming do corpo = `_on_inbound_scramble:244` (`payload[2:]` =
  `<GID><ação>` do **consumidor**, chaveado pelo pid). Lado do agente: `relay_hook_linux.js:497` (casa
  qualquer id em `scr.bodies`, off ∈ {-2,0}) + `:519` (escreve o corpo **inteiro**, incl. GID). Tudo coberto
  por `tests/test_writeback.py:223-250` (ALL PASS, 11 scripts).
- **Override de faixa pelo CLI** (§3): `--scramble-range ''` desliga o filtro (id-only match — robusto a
  relogin/restart); conf **não** editada (a conf mantém a faixa obsoleta `2632000-2730000` e `inject`/
  `inject-call`).
- **Launcher `research/action_0437_0438/run_action_merge.sh`** (opção 1 ponta-a-ponta, ANDAR + ATACAR): fia
  os dois processos — relay com **`--move-dispatch`** (035f→dispatch nativo; sem ele o char não anda) +
  `--action-merge --scramble-range ''` (resto da conf: `inject`, `inject-call`, `scramble-bp=18eff2`,
  `reg=auto`, consumidor `127.0.0.1:2350`, dispatcher `0xd473b0`/site `0x4dcba0`, sendpacket `816640`) e
  `action_trigger.py` tailando o stdout (0437→INSERT, 0438→F1, 0af4→F2). Sob `--move-dispatch`,
  `_on_inbound_split` roteia 035f→andar, 0437/0438/0af4→merge, resto→SendPacket. DRs: DR0 scramble, DR1
  sendcall, DR2+DR3 move-dispatch (cheio). `bash -n` OK; `parse_args` confirma `move_dispatch=True`,
  `action_merge=True`, `scramble_range=''`. **Ordem ao vivo:** subir → andar uma vez (captura passiva do
  `this`); pós relogin o relay recaptura sozinho (§5), basta andar de novo. **Falta validar ao vivo.**
- **recapture-on-reconnect** (§5).
- **`.gitignore:12-13`**: `research/**/captures/` — capturas cruas (corpos em claro) **não** versionadas.

## 7. Ferramentas desta fase (todas read-mostly quanto ao repo; efeito ao vivo quando indicado)
- `synth_input.py` — entrada sintética via `ydotool`/uinput (foco + hold 120 ms). Efeito: input real no
  seat0. Uso: `--wid <top-level> key INSERT` (o `--wid` é top-level, **antes** do subcomando).
- `isolated_merge.py` — teste isolado do merge (sem relay/sem consumidor), diagnóstico de faixa. Requer
  DR0 livre (parar o relay). `--pid --port 27053 --body <10 hex> --timeout-ms`.
- `action_trigger.py` — observa o stdout do relay (`[inject] inbound id=0x…  scramble body map`) e dispara
  `synth_input` para gerar o carrier (gatilho rápido do merge). **Não** altera o relay.
- `observe_store_ids.py`, `observe_8280.py` — sondas de observação (store/ids; 0x8280) desta trilha.

## 8. Em aberto / próxima decisão
- **Mecanismo de ação pelo merge: RESOLVIDO e hands-free com char PARADO (OBSERVADO 2026-10-16).** Launcher
  `run_action_merge.sh` (`--move-dispatch --action-merge --egress-queue --scramble-range ''`) + `python -u`
  (stdout unbuffered: o `$LOG` cresce ao vivo e o `action_trigger` enxerga o arme e dispara o INSERT
  sozinho — era o motivo do carrier ter sido manual antes) + `0438→tecla 9` (fileira de cima, KEY_9=10).
  Com o char **estacionário** + alvo adjacente, a cadeia completa commita sozinha: OpenKore manda seu
  próprio 0437 `3704 <GID vivo> 07` → arme → INSERT auto → `WROTE …02→…07` com `move fired=0` → ataque
  executou (responsável: "Funcionou, ele atacou"). **0437 e 0438 também funcionam perfeitamente quando o
  comando é DIGITADO no console do OpenKore.**
- **BLOQUEIO ABERTO — a AI em modo AUTOMÁTICO não ataca/lança (OBSERVADO 2026-10-16).** O comando manual no
  console do consumidor funciona; a AI automática não. Evidência (log vivo pós-fix): o OpenKore **EMITE** o
  0437 de ataque com o GID do alvo e o merge o **escreve** (22 `WROTE` / 26 `inbound`; carrier
  `was=<GIDpróprio>02` → `<GIDalvo>07`), MAS os despachos nativos de 035f chegam em **fluxo contínuo** (destinos
  mudando: (158,191)→(155,201)→(152,205)→(162,212)→(166,213)…) e cada `WROTE` cai **no meio** desse fluxo →
  o char está **andando** quando o carrier é reescrito → a ação não commita.
  - **INFERIDO:** 035f é "mover até o destino" (multi-tile), não "um passo"; pacear o **despacho** (fila
    FIFO 400ms + gap 400ms pós-ação + drop >800ms) **não cria janela parada** — o cliente segue o trajeto
    inteiro entre despachos. A fila serializou a **ordem** mas não o **efeito** do walk nativo contra o
    efeito da tecla sintética. No cliente real/xKore o fluxo único + a máquina de estado do cliente
    interrompem o walk para atacar; aqui o walk nativo e a ação não se coordenam.
  - **HIPÓTESE / próximo teste (p/ Codex):** fazer o char **assentar** em alcance no instante da ação —
    (a) **pausar o move-dispatch** por uma janela quando há ação armada (parar de disparar 035f, deixar o
    char parar, então a tecla); (b) coordenar pelo **OpenKore** (`attackDistance`/`route` p/ parar junto do
    mob — Tarefa #6); (c) condicionar a tecla a um sinal de "char idle". A via **nativa** de ação
    (`0x28`/`0x2a` do fire-site) segue **REFUTADA**/inócua (ACT-20261016-01).
- **OBSERVADO — teste decisivo (2026-10-16), CAUSA RAIZ CONFIRMADA:** no modo manual, atacar um mob **fora
  de alcance** → o OpenKore anda até ele e ataca → **FALHA** (igual ao auto); só **commita quando o comando
  chega com o char JÁ EM ALCANCE**. Logo a ação commita **sse emitida com o char EM ALCANCE e ASSENTADO**
  (sem rota imediatamente antes/junto). O console nunca foi exceção — só funcionava **em alcance**. O auto
  falha porque **roteia até o mob e ataca na transição de chegada** (cliente ainda em estado de movimento,
  move-dispatch executando o último 035f). **A hipótese de seleção/lock de alvo fica APOSENTADA como causa.**
  Observações anteriores encaixam: "atacar à mão em alcance → anda pra longe → auto volta a atacar" = engajou
  em alcance e o auto reataca também em alcance. **FIX (p/ Codex, `HANDOFF_CODEX.md` hip. 0):** ao armar uma
  ação, fazer o cliente **parar e assentar** (onde o OpenKore já o julga em alcance) **antes** da tecla —
  provável bastar uma vez pra travar o 1º golpe.
- **Perícia 0438 com alvo pelo merge:** carrier via tecla 9 funciona **manualmente**; no automático sofre o
  **mesmo** bloqueio de estado-andando.
- **Fila de egresso (`--egress-queue`):** entregue e testada offline; serializa os quadros **`S`** (035f/
  0437/0438), ignora os **`R`** (recv espelhado) — antes eles afogavam a FIFO (542 drops `typ='R'`). Não
  resolve o bloqueio acima (que é de **estado do cliente**, não de ordem de despacho).
- **Validar o fix de freeze ao vivo** (§5): mapa→login→mapa, **andar uma vez** pós-relogin, sem freeze.
- **Fase 2 / Prioridade 2:** atuador sintético **dentro** do relay (flag, default OFF); cliente `gamescope`
  headless + uinput próprio (`ISOLATION_SPIKE.md`).

## 9. Limpeza / limites
- Suíte offline PASS; **nenhuma** alegação de sucesso ao vivo a partir de offline. Sem credenciais/contas/
  IPs/capturas cruas em docs ou commits (nas provas usei GID-marcador `0xdeadbeef`; GIDs reais fora dos
  docs). `inject`/`inject-call` da conf intocados. Cada sonda desarma seu DR em DONE/stop. **Nenhum commit
  feito**: working tree com `relay/{cli,protocol,relay,writeback}.py`, `agent/relay_hook_linux.js`,
  `tests/test_writeback.py`, `.gitignore`, `docs/{GEPARD_CONTROL_PACKETS,RESEARCH_STATUS}.md` alterados;
  scripts novos não rastreados em `research/action_0437_0438/`.
<!-- END ORIGINAL research/action_0437_0438/MERGE_SYNTH_STATE.md -->

<a id="source-research-action-0437-0438-isolation-spike-md"></a>

## Fonte original: `research/action_0437_0438/ISOLATION_SPIKE.md`

Commit-base da fonte: `69ea1aa7d119b92c54e22b7d19ed22e515350ebc` · blob: `f2778e8702db453c4a999452e9d0094dda6aac6e` · caracteres: 6576.

<!-- BEGIN ORIGINAL research/action_0437_0438/ISOLATION_SPIKE.md -->
# Spike de isolamento — input sintético ao cliente escondido (Fase 0)

> **Status:** RUNBOOK (procedimento proposto; **não executado**). Nenhuma mudança de sistema foi
> feita por esta entrega. Os passos abaixo exigem a máquina do responsável, root para `udev`/seat, e
> decisão humana. Classificação dos resultados quando executar: OBSERVADO/INFERIDO/HIPÓTESE.

## Objetivo e critério de sucesso

Um clique/keypress sintético que, **simultaneamente**: (a) chega **só** ao uaRO escondido;
(b) **não** toca o teclado/mouse reais do responsável no seat0; (c) **passa** no filtro do Gepard
(chega ao Wine como evento de hardware, sem a flag "injected").

**Sucesso =** apertar INSERT sintético faz o personagem **sentar** no uaRO isolado enquanto o
responsável usa o PC normalmente no seat0, sem interferência.

## Por que é não-trivial (confirmado neste box)

- O que **passa no Gepard** é input via **uinput (kernel)** → libinput → compositor → Wine
  (parece hardware). **XTEST** é filtrado (`xdotool`/Xvfb). Memória do projeto:
  `synthetic-movement-uaro-hybrid-input`.
- uinput é **global ao seat**: sem roteamento, o evento vai para a janela em foco do seat0 → atrapalha
  o uso real. É exatamente o que o isolamento tem de impedir.
- Inventário deste box (2026-10-16): `gamescope`, `cage`, `Xvfb`, `ydotool/ydotoold`, `xdotool`,
  `libinput`, `evtest`, `loginctl` presentes. **`seatd` NÃO instalado**; **`python-evdev` NÃO
  instalado**; `Xephyr` ausente. Sessão Wayland/KDE (KWin), `/dev/uinput` root (usuário fora do grupo
  `input`). `gamescope` tem backends `drm|sdl|openvr|headless|wayland`.
- **Caminho de input para o headless (técnica, relato 2026-10-16):** o par "gamescope headless +
  input por `/dev/uinput` virtual" é uma técnica **comprovada** — é assim que o **Sunshine** alimenta
  um gamescope headless (teclado/mouse/gamepad virtuais via uinput). **Não usamos o Sunshine**; ele é
  só a prova de que a técnica funciona. **Replicamos** o mesmo: criamos nossos próprios devices
  virtuais uinput (teclado/mouse) e rodamos o uaRO num gamescope `--backend headless` que lê esses
  devices — ver E1. Isso dá input ao compositor escondido sem tocar o seat0.

## Arquitetura alvo

Dispositivo **uinput dedicado** (teclado+mouse virtuais, nome fixo) → roteado a um **seat próprio**
→ **compositor real** (não cliente Wayland aninhado, que herda o foco do pai) lendo **só** esse
dispositivo → uaRO (Wine/Proton) dentro. Frida/relay anexam como hoje. O input sintético é escrito
nesse device; nunca toca o seat0.

## Pré-requisitos (mudanças de sistema — responsável decide)

1. Acesso ao `/dev/uinput` para criar o device (grupo `input` no usuário, ou rodar o criador como
   root). `ydotoold` já cria um uinput próprio quando iniciado.
2. Para o roteamento por seat, uma destas duas vias:
   - **logind** (presente): atribuir o device do bot a um seat via regra `udev`
     `ENV{ID_SEAT}="seat-bot"` + `loginctl attach seat-bot <syspath>`. Limite conhecido: um seat que
     roda *sessão gráfica* precisa de um device master de vídeo; em **GPU única** isso conflita com o
     seat0/KWin. Para **input-only** destinado a um compositor headless/nested, avaliar se o logind
     aceita o seat sem master de vídeo (a verificar no spike).
   - **seatd** (instalar): mais simples para wlroots (`cage`/`gamescope`). Requer instalar o pacote.

## Experimentos (ordem; cada um com gate go/no-go)

### E0 — Device dedicado + verificação de roteamento (sem compositor ainda)
1. Criar o device do bot (via `ydotoold` próprio, ou um criador uinput via `ctypes`/`libevdev` —
   `python-evdev` ausente, então não contar com ele).
2. `sudo libinput list-devices` e `evtest`: achar o device do bot e **confirmar seu `seat`**.
3. Aplicar a regra `udev` de `ID_SEAT=seat-bot` ao device do bot; re-plug/trigger; reconfirmar com
   `loginctl seat-status seat-bot` e `libinput list-devices` que **só** o device do bot está em
   `seat-bot` e os devices reais seguem em `seat0`.
- **Gate:** o device do bot aparece em `seat-bot` e os reais em `seat0`. Se o logind recusar o seat
  sem master de vídeo → instalar `seatd` (via E-alt) ou ir ao fallback VM/2ª máquina.

### E1 — Compositor isolado rodando app trivial
- **Indício (relato responsável, 2026-10-16):** setups de **gamescope headless** recebem input por
  **dispositivos virtuais `/dev/uinput`** (teclado/mouse/gamepad) — técnica comprovada pelo Sunshine.
  Replicamos a técnica com nossos próprios devices; isso **reduz** (não elimina) a incerteza do item
  1: confirmar ao vivo que o headless desta versão lê o device do bot. HIPÓTESE até observar.
- Tentar, em ordem de menor conflito com o seat0:
  1. `gamescope --backend headless` com um app Wine trivial (p.ex. `wine notepad`): confirmar que o
     headless **lê** o device do bot (device uinput próprio criado em E0). Render offscreen já
     satisfaz "fora da visão".
  2. `cage` num VT dedicado (backend DRM) com seat próprio, se E0 via seatd/logind permitir DRM
     secundário. Em GPU única, pode exigir trocar de VT — aceitável só se "fora da visão" e sem tirar
     o display do seat0.
- **Gate:** escrever um keypress no device do bot muda o app trivial no compositor isolado e **nada**
  acontece no seat0 (confirmar olhando o seat0 em uso).

### E2 — uaRO dentro + Gepard aceita o clique
1. Lançar o uaRO (Wine/Proton) dentro do compositor isolado de E1.
2. Anexar o relay/Frida como hoje (`ro-ops discover` para PID/porta).
3. Escrever um **INSERT** sintético no device do bot → o personagem deve **sentar** (0437 GID próprio
   sai e executa). Repetir algumas vezes.
- **Gate (SUCESSO DO SPIKE):** senta no uaRO isolado **e** o seat0 do responsável fica intacto durante
  os disparos. Falha → fallback.

## Fallbacks (se E0/E1 travarem em GPU única)

- **Cliente em VM/2ª máquina** (GPU passthrough ou máquina física separada): isolamento físico
  trivial; o relay/OpenKore falam com ela por rede. Custo de infra; sem conflito de seat.
- **Protótipo aceitando interferência:** uinput global + o uaRO num **desktop virtual KDE** separado,
  disparos em rajadas curtas — só para **provar a cadeia ponta-a-ponta** (Fases 2–3) antes de
  reinvestir no isolamento limpo. Não é a entrega final (atrapalha o uso durante os disparos).

## Saída do spike

Registrar em `research/action_0437_0438/STATE.md` (via skill `research-handoff`): qual via de seat
funcionou, comandos exatos, device/seat observados (`libinput list-devices`, `loginctl`), e se o
Gepard aceitou o clique isolado. Só então o módulo de input do relay (Fase 2) tem um alvo estável
para escrever.
<!-- END ORIGINAL research/action_0437_0438/ISOLATION_SPIKE.md -->
