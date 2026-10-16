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
