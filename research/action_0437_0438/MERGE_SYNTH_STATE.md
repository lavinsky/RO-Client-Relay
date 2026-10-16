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
