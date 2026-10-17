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
