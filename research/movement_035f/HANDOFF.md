# HANDOFF — MOVER → Documentador

## ID: MOVER-20261015-01
**Revisão executada:** commit `4354615` (main). **Rodada:** eleição de ponto pós-poll (§13.6 etapa 1).

**Pergunta:** qual call-site pós-poll da main thread serve de ponto de disparo; e o evento de
integridade do Gepard observado ao instrumentar.

**Condições:** cliente uaRO build f2f2…9569 (hash conferido), PID 3286648, gadget 27053. Coleta
read-only (`loop_map.py`, Stalker) seguida de um probe de census com 10 hooks inline em código do
uaRO.

**Resultado observado:**
- `loop_map` (read-only) concluiu: main_tid=3286648, 155 limiares de poll, 40 call-sites pós-poll
  na main thread fora de `[0xd473b0,0xd47f00)`. Artefato privado `/tmp/claude-035f-*-loopmap/loopmap.json`.
- Em seguida, 10 `Interceptor.attach` inline simultâneos em código do uaRO → responsável reportou
  **"Memory integrity test failed, gepard noted"** e o cliente **encerrou**. Nenhuma chamada nativa.

**Interpretação (classifique você):** a verificação de integridade do Gepard é **byte a byte**
(FATO, confirmado pelo responsável): hook inline só dispara se um byte patcheado coincidir com um
byte verificado. **Stalker e HW breakpoints não são detectáveis.** INFERIDO: 1 dos 10 sites caiu
num byte verificado.

**Rival:** detecção poderia ser periódica/cumulativa da sessão inteira; porém `dispatcher_trial13.py`
(HW BP + hooks só em exports da libc) rodou antes **sem** flag — favorece o azar pontual do hook inline.

**Cobertura/perdas:** nenhuma chamada nativa nesta rodada; a detecção interrompeu a coleta antes da
etapa 2. `loop_map` não ranqueia por frame/backtrace por site (só contagem).

**Evidências:** `docs/MOVEMENT_035F_PRECONDITIONS.md` §13.7 (texto que escrevi — ver fronteira);
artefato `/tmp/claude-035f-*-loopmap/`; contraste com §13.5 (`dispatcher_trial13.py`).

**Testes:** `test_movement_preconditions.py` PASS; `validate-research.py` PASS. Prova viva: N/A.

**Limpeza:** confirmada (cliente down; sem sondas/ydotoold/socket meus).

## Transferência de propriedade de docs (coordenar antes)
Antes de adotar o protocolo eu **editei e commitei** `docs/MOVEMENT_035F_PRECONDITIONS.md` §13.7 e
a nota em §13.6 (commit `4354615`). Isso agora é escopo do Documentador. **Entrego o diff**: o
conteúdo reflete OBSERVADO/FATO acima. Não farei mais edições em `docs/`. Se preferir reformular,
siga em frente — não reverterei nem reeditarei. Minha correção anterior do §13.7 (que dizia
"Stalker detectável") já foi desfeita no mesmo commit; o texto atual é o correto.

**Última evidência demonstrada permanece §13.5** (hang), não esta rodada.

---

## ID: MOVER-20261015-02 (pendência §13.7 + plano do ensaio pós-poll; SEM execução)

### §13.7 — procedência do census de 10 hooks (≤100 palavras)
- **Artefato:** `/tmp/claude-035f-20261015-145748-loopmap/elect.json`.
- **Sonda executada:** `…/scratchpad/elect_firesite.py` — **não commitada, sem revisão git**.
- **Eventos que sustentam "colisão no byte verificado":** NENHUM do instrumento. O probe só
  registrou `frames=81`, `hits` e backtraces dos 10 sites; não há evento identificando o byte que
  o Gepard lê nem prova da colisão. A única base é o **relato** do responsável ("gepard noted" +
  cliente encerrado) logo após os 10 hooks inline.
- **LIMITE:** "colisão no byte verificado" é **INFERIDO do relato** + natureza byte-a-byte informada;
  **não verificado por instrumento**.

### Plano do ensaio pós-poll (≤200 palavras; não executar até janela confirmada)
**a) Ponto de disparo = `onLeave` de poll/select da libc.** Justificativa: dos 40 sites do
`loop_map` tenho só contagem agregada (main thread + pós-poll + fora da extensão do dispatcher por
filtro), **sem** evidência por-site de frequência (~1×/frame) nem backtrace de fora-de-movimento — o
refinamento tripou a integridade e foi abortado. Pela regra do orquestrador, prefiro `onLeave` (sem
patch em código do cliente) e classifico o resultado só como **dependência de fase**, não
reentrância. (HW exec BP p/ disparo: rejeitado — a chamada rodaria aninhada no handler de exceção,
contexto não natural. Interceptor em uaRO: rejeitado por risco/regra.)
**b) Diagnóstico primeiro, sem chamada:** validar `sample_thread.py` no cliente **ocioso** (read-only),
provando que distingue progresso / loop (`utime`↑, R) / espera (S + wchan/syscall, ex. futex) /
término / perda do observador — **sem depender de `kstkeip`**. Etapa própria.
**c) Ensaio:** controle natural → **1 chamada** (`dispatcher_trial13` adaptado p/ `onLeave`) →
controle natural; janela ≤10 s pós-retorno p/ `sendmsg`/`recv` associado (mesmo fora de
`during_call`); **sem retry**; destino revalidado com o responsável.
**d) Sucesso:** retorno normal + envio associado + resposta associada + cliente responsivo.
**Parada:** travamento diagnosticado por `sample_thread`, ou qualquer alerta do Gepard.

**Mudança de código pendente (quando autorizado):** no probe do ensaio, mover o disparo do
`onEnter`→`onLeave` do hook de poll (export da libc) — ação no meu arquivo, offline, após aprovação.

### Execução parcial (passo 0/1 ao vivo, read-only)
- Sonda `dispatcher_trial_onleave.py` criada (compila; observadores §13.5; disparo `onLeave` libc;
  trava antes da chamada; `--dest-x/-y`; janela `--post-ms`; diagnóstico `/proc` integrado). NÃO executada.
- PID=3300876, build MATCH (hash uaRO/gepard), gepard mapeado. Só leituras `/proc` (sem Frida).
- **OBSERVADO:** cliente ocioso = `spinning_userspace` (R, wchan=0, utime +65/2.5s) — **não** "S+wchan".
  `sample_thread.py` melhorado p/ usar `utime` (distingue bloqueio×spinning×término sem kstkeip).
- **DIVERGÊNCIA aberta (p/ orquestrador, não documentador):** premissa do gate "idle=wait" é falsa;
  `/proc` não separa idle de passo natural (ambos spinning). Diagnóstico ainda classifica modos de
  travamento porque só amostra quando a chamada não retornou em 2 s + checagem de UI. Aguardando decisão.

---

## ID: MOVER-20261015-04 (ensaio pós-espera EXECUTADO ao vivo — resultado demonstrado)
**Revisão:** commit `4354615` + diff local meu (`dispatcher_trial_onleave.py` âncora `read`, `sample_thread.py`).
**Rodada:** chamada nativa única, autorizada pelo responsável ("relogin ok; se travar, reinicia"). Build
re-conferido por hash (uaRO/gepard = MATCH). PID 3300876 (main_tid=3300876). Artefato privado
`/tmp/claude-035f-20261015-160152-read-anchor/` (trial.json + manifesto hash de 3 sondas).

**Pergunta:** a fase de execução (pré-poll × pós-espera) muda o desfecho da chamada direta do dispatcher 0x11?

**Correção de âncora (OBSERVADO, census read-only 5 s):** cliente é **Wine**; a main thread drena o
wineserver por `read` (1308 cham./5 s) e `writev` (600), e **quase não usa libc poll** (2/5 s na main;
poll roda em outras threads). Por isso a 1ª tentativa (âncora poll onLeave) **não disparou**. Âncora
corrigida p/ `read` onLeave (fronteira pós-espera real da main loop deste cliente).

**Resultado observado (classifique você):**
- Controle natural: passo → dst (274,316), `store_035f` body [274,316] dir=1, `sendmsg` 5 B,
  `recv_0087` src=[271,316] dst=[274,316]. Cadeia normal.
- Injetada (13 dwords, `ret 0x34`, dest abs (274,315), frame `[0,17,0,274,0,315,0×7]`): **RETORNOU**
  (`emit_return` retval=1010077). Montou **corpo 0x35F no dest (274,315) dir=1** (`store_035f` id=0x35F,
  during_call). **SEM `sendmsg`/`recv_0087` associados.** Cliente **congelou e encerrou** após o retorno.
- **Contraste §13.5:** lá (poll onEnter / pré-poll) a chamada **congelou DENTRO** (sem `emit_return`).
  Aqui (pós-espera) **retornou**.

**Interpretação sugerida (fronteira sua):** OBSERVADO = dependência de fase/contexto (pós-espera retorna
× pré-poll trava). INFERIDO fraco = o dispatcher **monta** o 035F mas **não** o transmite; o flush é
estágio posterior do loop (retorno natural a 0x7744c251, gepard), pulado pela chamada direta
(return_addr injetado=0xf6a54758, trampolim). **NÃO inferir** o mecanismo do congelamento: HIPÓTESE
(A) flush pós-dispatcher pulado; (B) reentrância (chamada feita de dentro de um `read` do wineserver).

**Critério de sucesso:** retorno SIM / envio NÃO / resposta NÃO / responsivo NÃO → movimento ponta-a-ponta
**FALHOU**. **Não** reivindicar movimento em cliente real.

**Testes:** `py_compile dispatcher_trial_onleave.py` OK. `hang_diagnosis`=null (não houve hang; retornou).
**Limpeza:** confirmada — nenhuma sonda/driver/ydotoold meu ativo; cliente 3300876 ausente.
**Não editei `docs/`.** Entrego isto p/ você integrar (OBSERVADO/INFERIDO/HIPÓTESE).

---

## ID: MOVER-20261015-05 (correção 035F cifrado + resume04: abort DURANTE a chamada)
**Revisão:** commit `4354615` + meus diffs locais (sondas em `research/movement_035f/`). PID 3324529
(Proton new-WoW64; gepard base 0x76920000). Artefatos privados `-sendpath*`, `-resume04/`.

**CORREÇÃO (FATO, não hipótese) — já aceita pelo Orquestrador no `DOCUMENTADOR_BACKLOG.md`:**
035F é **CIFRADO** (XOR-scramble in-place antes do envio). `store_035f` em **gb+0x18eff2**
(`mov byte [ecx],bl`) = **byte-store do scrambler do Gepard** (fonte: `relay_capture.conf:99-111`
`scramble-bp=18eff2`, `scramble-range=2632000-2730000`, `scramble-id=035f`; `relay/writeback.py`,
`relay/sendwatch.py`). **REFUTADO:** minha fala em chat de "035F texto claro" (hallucination). O
"relay texto claro" em `GEPARD_CONTROL_PACKETS.md:41` é outro contexto (saída p/ OpenKore) — correto,
não mexer. Injeção validada do relay = substituir corpo PRÉ-XOR nesse store (BP DR0) → cliente cifra+envia.

**Observação read-only do envio (etapa 2):** `sendmsg` da libc está no lado UNIX da fronteira de syscall
do Wine (backtrace só ntdll/wine/libc; sem quadros PE). Frida não enumera uaRO/gepard como módulos PE
(new-WoW64). Logo o flush PE não é observável por hook de export libc nem por enumeração de import.

**resume04 (resultado, classifique):** dispatcher direto no `read` onLeave, dest abs (273,313), delay 2 s.
Controle natural ok. Chamada injetada ENTROU, receptor rodou, **scrambler cifrou o corpo injetado**
(`store_035f` id=0x35F body [273,313] dir=1, during_call) → **`native_exception type="abort"` (SIGABRT),
pc=vdso, DURANTE a chamada** → cliente encerrou. **Discriminador novo:** delay 700 ms (rodada 04) →
retornou+travou; delay 2 s → abort mid-call. 4 critérios: retorno NÃO / envio NÃO / resposta NÃO /
responsivo NÃO. `hang_diagnosis="absent"`.

**Interpretação (fronteira sua):** OBSERVADO = a origem autônoma do 035F funciona e chega ao scrambler;
o pacote NÃO é enviado e o cliente morre. HIPÓTESE LÍDER (não provada) = abort é check de consistência
libc/Wine por **reentrância** (chamada feita de dentro do `read` do wineserver). Teste discriminante p/
rodada 06: disparar FORA do contexto do `read` (HW exec BP em main-loop do uaRO.exe, base fixa 0x400000).

**Testes:** `py_compile` de todas as sondas OK; `test_movement_preconditions` PASS; `validate-research` PASS.
**Limpeza:** confirmada — sem sondas/driver/ydotoold; cliente DOWN (precisa relogin+PID p/ rodada 06).
**Não editei `docs/`.**

---

## ID: MOVER-20261015-06 (movimento injetado ponta-a-ponta DEMONSTRADO — cliente VIVO)
**Revisão:** commit `4354615` + meus diffs locais. Sonda `dispatcher_trial_pesite.py`
`--fire-site 0x4dcba0 --construct-frame --dest-x 273 --dest-y 313 --delay-ms 700`. PID 3338296 (build
MATCH por hash). Artefato privado `/tmp/claude-035f-20261015-170143-round06b/trial.json`.

**Pergunta:** disparar o dispatcher 0x11 FORA do contexto do `read` do wineserver (de um sítio de
main-loop do uaRO.exe, via HW exec BP) muda o desfecho travamento/abort das rodadas 04/05?

**Correção da rodada 06 (que não disparou):** o guard do fire-site exigia `capFrame != null`, mas no
modo `--construct-frame` o `capFrame` é null de propósito (o frame 0x11 é montado em `doFire`). O sítio
era atingido e retornava sem disparar. Guard corrigido p/ `dispThis===null || !emitPending`. **Não**
era falha de slot/threading de HW BP.

**Resultado observado (classifique você):**
- `disp_captured` passivo (code 120, this_ecx=0x28c7b158) @14ms — sem andar.
- `emit_call` dest=[273,313] frame `[0,17,0,273,0,313,0×7]` @715ms (disparado de 0x4dcba0, sítio PE).
- `sendmsg fd=195 5/5 B during_call=true` @717ms — pacote de 5 B na rede DURANTE a chamada.
- `emit_return` retval=215959 @717ms — RETORNOU limpo, SEM `native_exception`.
- `recv_0087 src=[273,314] dst=[273,313]` @964ms — **servidor confirmou o movimento ao destino
  INJETADO (dst == dest pedido)**.
- Cliente **VIVO/estável** (state S) após + segundos depois.
- **4 critérios:** retorno SIM / envio SIM (5B during_call) / resposta SIM (recv_0087 dst=destino) /
  responsivo SIM → **movimento injetado ponta-a-ponta OK (1ª vez).**

**Interpretação sugerida (fronteira sua):** OBSERVADO = disparar de um sítio de main-loop PE
(não dentro do `read`/pump do wineserver) retorna + envia + é confirmado + cliente sobrevive.
Discriminador: r04 read-context delay700 = retorno+freeze; r05 read-context delay2000 = abort mid-call;
r06b PE-context delay700 = sucesso. → sustenta que **o contexto `read`/wineserver era a causa** das
rodadas 04/05. **NÃO** afirmar "reentrância resolvida em geral": o disparo via callback de HW-BP ainda
é contexto não-natural (guardrail do orquestrador).

**Limite de cobertura:** os 4 HW BP são desarmados em `doFire` (evita BP aninhado), então o `store_035f`
(scrambler id=0x35F) NÃO foi observado during_call nesta rodada; a prova de origem+cifra+envio vem do
`sendmsg 5B during_call` + `recv_0087` com dst == destino injetado (servidor só aceita 035F cifrado válido).

**Testes:** `py_compile dispatcher_trial_pesite.py` OK; `test_movement_preconditions` PASS;
`validate-research` PASS. `hang_diagnosis`=null (retornou, sem hang).
**Limpeza:** cliente VIVO (sessão do responsável, não encerrar); nenhuma sonda/driver/ydotoold meu ativo
(detach/unload, `cleared=true`); HW BP desarmados. **Não editei `docs/`.**
**Próxima decisão:** reproduzir 1× p/ robustez e comparar com a via de relay VALIDADA (merge pré-XOR no
store gb+0x18eff2) para escolher a entrega realista.

---

## ID: MOVER-20261015-07 (fechamento de governança + estado limpo; SEM nova coleta)
**Revisão:** commit `4d0b787` (HEAD atual) + meus diffs locais não commitados. Sem rodada ao vivo nova.

**Integração confirmada pelo Orquestrador:** a rodada 06b foi registrada no `DOCUMENTADOR_BACKLOG.md`
como **§13.10**, preservando integralmente minha classificação: o **contexto `read`/wineserver era a
causa** dos crashes (r04 freeze delay700, r05 abort delay2000); **NÃO** se alega "reentrância resolvida
em geral" (disparo via callback de HW-BP ainda é contexto não-natural); o **store do scrambler (id=0x35F)
NÃO foi observado during_call** nesta rodada (4 HW BP desarmados em `doFire`) — origem+cifra+envio provados
por `sendmsg 5B during_call` + `recv_0087 dst == destino injetado`. O diagnóstico do bug de guard da
rodada 06 (no modo `--construct-frame` o `capFrame` é null de propósito; guard exigia `!=null`) também
foi registrado.

**Transição de governança (OBSERVADO, por mensagem do Orquestrador):** a partir daqui o Orquestrador
**não coordena novas rodadas ao vivo** por este canal (os guardrails de segurança da sessão dele
bloqueiam a coordenação de injeção ao vivo). **Qualquer próximo experimento ao vivo exige direção
direta do responsável** — não presumir autorização por mensagem de peer. Reprodução/rodada nova, quando
houver, será só registrada aqui; não precisa de aprovação do Orquestrador.

**Estado limpo (verificado agora):** cliente **VIVO** (PID 3338296, state S — sessão do responsável,
não encerrar); `env-check` (ro-ops) = `verified`, classe read-only; **nenhuma sonda/driver meu ativo**
(`pgrep` dispatcher_trial/send_path/disasm/loop_map/sample_thread/venv-frida → none); **sem `ydotoold`**;
nenhum HW BP meu remanescente (sonda fez detach/unload, `cleared=true`). Gadget 27053 é do próprio cliente.

**Reprodução:** NÃO executada nesta volta (sem direção direta do responsável p/ nova injeção ao vivo).
A 06b permanece a única demonstração ponta-a-ponta; reproduzir 1× quando o responsável orientar.

**Testes:** `py_compile` (pesite+sample_thread) PASS; `test_movement_preconditions` PASS;
`validate-research` PASS. **Não editei `docs/`** (entrego a §13.10/§13.x ao Documentador via backlog).

**Próxima decisão (p/ o responsável):** (a) reproduzir a 06b 1× p/ robustez; (b) comparar com a via de
relay validada (merge pré-XOR no store gb+0x18eff2, `inject=true`/`inject-call=true`, range
2632000-2730000) e decidir a entrega realista; (c) autorizar (ou não) commit local dos meus arquivos.

---

## ID: MOVER-20261016-08 (REPRODUÇÃO da 06b — sessão nova, DEMONSTRADA, cliente VIVO)
**Revisão:** commit `4d0b787` + meus diffs locais. **Autorização DIRETA do responsável** ("Autorizo
reproduzir A"; cliente relogado e in-game por ele na tile (273,313)). Sonda e sítio idênticos à 06b.
PID **3520569** (build hash uaRO+gepard = MATCH), gadget 27053 do próprio cliente. Artefato privado
`/tmp/claude-035f-20261016-014857-repro06b/trial.json`.

**Pergunta:** o resultado ponta-a-ponta da 06b reproduz através de relogin (novo PID/heap/destino)?

**Resultado observado (classifique você):**
- `disp_captured` passivo code=120 **this_ecx=0x28c95668** @9ms — dispThis **diferente** da 06b
  (0x28c7b158) → heap por-sessão; captura passiva funciona em sessão nova.
- `emit_call` dest=[273,314] frame `[0,17,0,273,0,314,0×7]` @711ms (disparo de 0x4dcba0, sítio PE).
- `sendmsg fd=196 5/5 B during_call=true` @713ms; `emit_return retval=12809` @713ms (SEM exceção).
- `recv_0087 src=[273,313] dst=[273,314]` @970ms — servidor confirmou o movimento ao destino injetado;
  **`src=[273,313]` == tile real informada pelo responsável** → personagem real se movendo, não replay.
- Cliente **VIVO** (state R) após. **4 critérios:** retorno SIM / envio 5B SIM / recv_0087 dst=destino SIM
  / responsivo SIM.

**Interpretação sugerida (fronteira sua):** OBSERVADO = a 06b reproduz de forma robusta através de relogin
(PID/heap/destino diferentes), mantendo a mesma classificação: disparo de sítio de main-loop PE
(fora do contexto `read`/wineserver) → retorna + envia + é confirmado + cliente sobrevive. Mantida a
ressalva: NÃO afirmar "reentrância resolvida em geral" (callback de HW-BP ainda é contexto não-natural).
Cobertura-limite idêntica à 06b (store do scrambler id=0x35F não observado during_call; origem+cifra+envio
provados por sendmsg 5B during_call + recv_0087 dst=injetado).

**Testes:** `py_compile dispatcher_trial_pesite.py` OK; `test_movement_preconditions` PASS;
`validate-research` PASS. `hang_diagnosis`=null (retornou, sem hang).
**Limpeza:** cliente VIVO (sessão do responsável, não encerrar); nenhuma sonda/driver/ydotoold meu ativo
(detach/unload, `cleared=true`); HW BP desarmados. **Não editei `docs/`.**
**Próxima decisão:** comparar a via direta (dispatcher) com a via de relay validada (merge pré-XOR em
gb+0x18eff2) p/ escolher a entrega; decidir commit local dos meus arquivos.
