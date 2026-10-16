# STATE — MOVER (movimento 0x035F)

_Atualizado 2026-10-15. Reconciliação pontual na 1ª adoção do protocolo COORDINATION.md._

## Objetivo ativo e próximo experimento único
**ALCANÇADO na rodada 06b e REPRODUZIDO 2026-10-16 (rodada 08)** (ver fim do arquivo): movimento injetado ponta-a-ponta com
`emit_return` + `sendmsg 5B during_call` + `recv_0087 dst=destino injetado` + **cliente VIVO/estável**,
disparando o dispatcher 0x11 a partir de um **sítio de main-loop do uaRO.exe (0x4dcba0, HW exec BP)**,
FORA do contexto do `read` do wineserver. Classificação (guardrail): sustenta que **o contexto
`read`/wineserver era o problema** (rodadas 04/05 travavam/abortavam); NÃO prova "reentrância
resolvida em geral" — o disparo via callback de HW-BP ainda é um contexto não-natural.
**Próxima decisão:** reproduzir 1×, depois comparar com a via de relay validada (merge pré-XOR no
store gb+0x18eff2) para escolher a entrega. Nenhuma coleta nova sem reconfirmar janela.

## Última revisão de código executada
Commit `4354615` (branch main). Diff local nos meus arquivos (não commitado): `sample_thread.py`
(captura `utime`) e `dispatcher_trial_onleave.py` (âncora `--anchor read` p/ cliente Wine). Ver rodada 04.

## Última rodada (reconciliação)
- **Último resultado DEMONSTRADO: rodada 08 = REPRODUÇÃO da 06b (ver fim do arquivo)** — movimento injetado
  ponta-a-ponta (retorno + sendmsg 5B + recv_0087 dst=destino injetado + cliente VIVO), disparado de sítio
  PE 0x4dcba0, agora confirmado em sessão nova (PID/heap/destino diferentes; src do 0087 = tile real).
- **§13.5** (sessão anterior). Chamada nativa 13-dword
  (`ret 0x34`) disparada no `onEnter` de poll (export da libc). Entrou no dispatcher
  (`return_addr`=trampolim Frida), rodou `receptor_0x8a`, **montou corpo 035F no destino
  pedido no trap pré-store**, mas **sem** `emit_return`, **sem** `native_exception`, **sem**
  `sendmsg`/`recv` → **congelou**. Artefato privado: `/tmp/claude-035f-20261015-142841-abi13/`.
- **Rodada desta sessão (sem demonstração de movimento):** etapa 1 de §13.6 (eleição de ponto
  pós-poll). `loop_map.py` (read-only, Stalker) concluiu: main_tid=3286648, 155 limiares de
  poll, 40 call-sites pós-poll na main thread fora da subárvore do dispatcher. Em seguida um
  probe de census com **10 hooks inline simultâneos em código do uaRO** disparou a verificação
  de integridade do Gepard ("gepard noted") e o cliente encerrou. **Nenhuma chamada nativa**
  foi feita nesta rodada. Detalhe em docs §13.7. Artefato: `/tmp/claude-035f-*-loopmap/`.

## Fatos estabelecidos (OBSERVADO/confirmado)
- Dispatcher `0xd473b0` = `__thiscall` normal, `ret 0x34` (13 dwords). Frame natural 0x11 =
  `[0,0x11,0,x,0,y,0,0,0,0,0,0,0]`. (disasm estático §13.1.)
- OBSERVADO (§13.7): 10 `Interceptor.attach` inline simultâneos em código do uaRO → responsável
  reportou "gepard noted" e o cliente encerrou. (Evento = relato; ver limite abaixo.)

## Relato do responsável (NÃO verificado em geral)
- "Verificação de integridade do Gepard é **byte a byte**; hook inline só dispara por colisão de
  byte; **Stalker e HW breakpoints NÃO são detectáveis**." Fonte: relato do responsável (§13.7).
  **Não verificado por instrumento** (o probe não identificou qual byte; ver HANDOFF MOVER-20261015-02).
- **Consequência operacional (mantida):** preferir Stalker/HW BP; **nenhum `Interceptor.attach` em
  código do uaRO/gepard sem justificativa explícita no plano da rodada**. Exports da libc/ntdll permitidos.
- **Desvio de método registrado:** o census de 10 hooks inline NÃO era read-only; não repetir.

## Hipóteses abertas
- Dependência de **contexto/fase de execução** (pré-poll × pós-poll) — não testada vivo ainda.
- Exceção nativa vs bloqueio vs loop durante a chamada — **UNVERIFIED** (observador não cobriu).

## Conclusões RETIRADAS
- "VM sem retorno / imbalance de pilha é a causa" — REFUTADO como mecanismo (§13.2).
- "Inline hooks / Stalker em código do cliente são detectados" — super-generalização minha,
  CORRIGIDA (§13.7): era azar de 1 byte entre 10 hooks.

## Inventário mínimo de sondas (ponto de entrada; sem copiar código)
- **`dispatcher_trial_onleave.py` — SONDA DA RODADA APROVADA (MOVER-20261015-03):** disparo no
  `onLeave` de poll/select da libc, trava antes da chamada, `--dest-x/-y` absoluto, janela pós-retorno
  `--post-ms`, diagnóstico `/proc` integrado (via `sample_thread`) ao ver `emit_call` sem `emit_return`.
  Observadores = §13.5. Compila OK; NÃO executada ao vivo.
- `dispatcher_trial13.py` — chamada 13-dword no `onEnter` de poll; obs. por 3 HW exec BP + hooks libc. (§13.5)
- `dispatcher_trial_ctx.py` — mesma ABI, disparo num `--fire-at` (Interceptor), fases sync/post, `--dest-x/-y`.
- `loop_map.py` — census read-only (Stalker) p/ eleger ponto pós-poll (não usado nesta rodada).
- `sample_thread.py` — diagnóstico independente `/proc/<pid>/task/<tid>/{stat,wchan,syscall}`.
- `native_trial.py`, `observe_path.py`, `dispatcher_trial.py` — anteriores (ABI antiga/observação).

## Autorizações
Servidor próprio do responsável (autorizado). Chamadas nativas e input sintético híbrido
autorizados; relogin aceito se cair. **Exclusividade exige reconfirmação por sessão.** Sem
push/PR autorizado. **Cliente DOWN** → relogin invalida PID/base/heap/fd/posição.

## Limpeza
**Após rodada 08 (reprodução):** cliente **VIVO** (PID 3520569, state R — sessão autorizada do
responsável, não encerrar; o PID 3338296 da 06b já estava morto/relogado antes desta rodada);
**nenhum processo de sonda/driver meu ativo** (sonda finalizou e fez detach/unload, `cleared=true`);
sem `ydotoold` nem socket de input. Gadget 27053 é do próprio cliente (27052 = `reaper`, não meu).
Nenhum HW BP meu permanece (desarmados no fim da sonda). Nenhum recurso próprio ativo.

## Testes
`test_movement_preconditions.py` PASS; `validate-research.py` PASS; `py_compile` das sondas OK.
`scripts/test-offline.sh` NOT RUN (inclui suíte de CIFRA, fora do meu escopo).

## Rodada MOVER-20261015-03 — passo 0/1 ao vivo (read-only, sem instrumentação)
- Relogin feito. **PID=3300876** (state R), build `uaRO`/`gepard` hash = **MATCH**, gepard mapeado. main_tid=3300876.
- **sample_thread (passo 1):** cliente OCIOSO = `spinning_userspace(utime+ 65 ticks/2.5s, R, wchan=0)` —
  **NÃO** é "S+wchan wait" como o plano supunha; é laço de render ocupado. Artefatos `idle_baseline*.json`.
  Melhorei `sample_thread.py` (captura `utime`, independente de kstkeip): distingue **bloqueio**
  (S+wchan, utime estável — autoteste do shell: `wchan=do_wait`), **spinning** (R, utime+),
  **término** (ausente). Ambíguo: idle-loop × hang-spin (ambos spinning) — resolver por utime+ no
  momento do travamento (que só amostramos se a chamada NÃO retornou em 2 s) + responsividade da UI relatada.
- **BLOQUEIO:** gate do orquestrador ("idle=wait; se não distinguir idle de progresso, parar") parte de
  premissa falsa. Escalado (SendMessage) p/ decisão: prosseguir com cobertura de modos de hang
  (bloqueio/spinning/término/perda) OU adicionar PC userspace via cecli/ceserver antes da chamada.
  **Nenhuma chamada nativa até a decisão + confirmação de destino + "no gepard noted".**

## Rodada MOVER-20261015-04 — chamada pós-espera no `read` onLeave (DEMONSTRADA)
Artefato: `/tmp/claude-035f-20261015-160152-read-anchor/` (trial.json + manifesto hash das sondas).
- **Correção de âncora (OBSERVADO, census read-only):** cliente é **Wine**; o loop da main thread drena o
  wineserver via `read`/`writev` (read=1308 cham./5 s na main) e **quase não usa libc poll** (2/5 s na
  main). Por isso a 1ª tentativa (âncora poll onLeave) nunca disparou. Âncora corrigida p/ `read` onLeave.
- **Controle natural (mesma sessão):** passo → dst (274,316); `store_035f` body [274,316] dir=1;
  `sendmsg` 5 B; `recv_0087` src=[271,316] dst=[274,316]. Cadeia normal.
- **Chamada injetada (13 dwords, `ret 0x34`) no `read` onLeave**, dest abs (274,315), frame
  `[0,17,0,274,0,315,0,0,0,0,0,0,0]`, this_ecx=0x28c77600:
  - **`emit_return` retval=1010077 (0xF6A5D)** — a chamada **RETORNOU**. Contraste decisivo com §13.5
    (poll onEnter / pré-poll → congelou DENTRO da chamada, sem retorno). → **sustenta dependência de
    fase/contexto** (pós-espera retorna; pré-poll travou). Classificar SÓ como dependência de fase.
  - montou **corpo 0x35F válido no dest pedido (274,315) dir=1** (`store_035f` id=0x35F, during_call).
    Os outros 6 hits de store = instrução compartilhada p/ dados não-035F (ruído).
  - **SEM `sendmsg` associado, SEM `recv_0087`** → pacote **NÃO transmitido**. Cliente **congelou e
    encerrou** após o retorno (relato do responsável + PID 3300876 ausente).
- **Resultado vs critério de sucesso:** retorno SIM, envio NÃO, resposta NÃO, responsivo NÃO (travou).
  Movimento ponta-a-ponta **FALHOU**. `hang_diagnosis`=null (não houve hang; a chamada retornou).
- **Mecanismo do congelamento: NÃO inferir.** HIPÓTESE (A) o flush do socket ocorre em estágio POSTERIOR
  do loop (pós-retorno do dispatcher ao chamador natural 0x7744c251), pulado pela invocação direta;
  HIPÓTESE (B) reentrância corrompe o contexto do loop (chamada feita de dentro de um `read` do wineserver).
  return_addr natural=0x7744c251 (gepard); injetado=0xf6a54758 (trampolim NativeFunction).
- **Próximo método (não executar sem janela):** em vez de chamar o dispatcher direto, acionar o estágio
  natural que ENFILEIRA+FLUSHA (seguir a cadeia pós-dispatcher a partir de 0x7744c251), OU injetar o
  035F montado pela via de envio natural. Uma tentativa por rodada; sem retry.

## Rodada MOVER-20261015-05 — correção (035F cifrado) + resume04 (abort DURANTE a chamada)
Artefatos: `/tmp/claude-035f-20261015-162749-sendpath/`, `-162956-sendpath-pe/` (observação read-only
do caminho de envio), `/tmp/claude-035f-20261015-163955-resume04/trial.json` (re-run do dispatcher).
- **FATO (corrigido, fonte `relay_capture.conf:99-111` + `relay/writeback.py`/`sendwatch.py`):** 035F é
  **CIFRADO** (XOR-scramble in-place antes do envio). `store_035f` em **gb+0x18eff2** (`mov byte [ecx],bl`)
  = **byte-store do scrambler do Gepard** (`scramble-bp=18eff2`); cliente monta o 035F em
  `2632000-2730000`, cifra byte-a-byte e envia. Minha afirmação em chat de "035F texto claro" =
  **REFUTADA** (hallucination; o 0x5F03 lido num send da libc era pós-scramble/irrelevante).
  O "relay texto claro" em `GEPARD_CONTROL_PACKETS.md:41` é OUTRO contexto (saída p/ OpenKore) e correto.
- **Observação read-only do envio (etapa 2a/2b/2c):** o `sendmsg` da libc fica no lado UNIX da fronteira
  de syscall do Wine (backtrace só ntdll/wine/libc, sem quadros PE). Proton new-WoW64: Frida NÃO vê
  uaRO/gepard como módulos (`findModuleByAddress(0x401000)`=null; sem enumerar imports/exports). Sondas:
  `send_path_probe.py`, `send_path_pe.py` (ws2_32 só aparece como `.so` unix, sem export send), `disasm_postdispatch.py` (não executada; desvio preterido pelo responsável).
- **resume04 (dispatcher direto, âncora `read` onLeave, dest abs (273,313), delay 2000 ms):** controle
  natural ok (passo→(270,313), scrambler body [270,313], sendmsg 5B, recv_0087 src=[273,313] dst=[270,313]).
  Chamada injetada: entrou, receptor, **scrambler cifrou NOSSO corpo injetado** (`store_035f` id=0x35F
  body **[273,313]** dir=1, during_call) → origem funcionou de novo → **`native_exception type="abort"`
  (SIGABRT) DURANTE a chamada** (pc=vdso) → processo encerrou. `hang_diagnosis="absent"` (já ausente).
- **Discriminador novo vs rodada 04:** delay 700 ms → RETORNOU+travou; delay 2000 ms → **abort mid-call**.
  Ambos falham. Critérios: retorno NÃO / envio NÃO / resposta NÃO / responsivo NÃO.
- **HIPÓTESE LÍDER (não provada):** o abort é um check de consistência da libc/Wine disparado por
  REENTRÂNCIA — chamamos lógica PE de dentro do `onLeave` de um `read` da libc (pump do wineserver).
  **Teste discriminante proposto p/ rodada 06:** disparar FORA do contexto do `read` do wineserver
  (p.ex. HW exec BP num sítio de main-loop do uaRO.exe — base fixa 0x400000 — como 0x54aed0 do loop_map,
  ou após o retorno natural ao pump). Se então não abortar/travar → reentrância confirmada.
- **Pendente:** cliente DOWN; precisa relogin + novo PID p/ rodada 06. Destino caminhável a reconfirmar.

## Rodada MOVER-20261015-06b — movimento injetado ponta-a-ponta (DEMONSTRADO, cliente VIVO)
Artefato: `/tmp/claude-035f-20261015-170143-round06b/trial.json`. Sonda `dispatcher_trial_pesite.py`
`--fire-site 0x4dcba0 --construct-frame --dest-x 273 --dest-y 313 --delay-ms 700`. PID=3338296
(build MATCH), gepard mapeado. **Correção de bug (rodada 06 anterior não disparou):** o guard do
fire-site exigia `capFrame != null`, mas no modo `--construct-frame` o `capFrame` é intencionalmente
null (o frame é montado em `doFire`); por isso o sítio era atingido mas retornava sem disparar. Guard
corrigido p/ `dispThis===null || !emitPending`. (Não era slot/threading de HW BP; era o guard.)
- **disp_captured** (passivo, code=120, this_ecx=0x28c7b158) @14ms — dispThis capturado sem andar.
- **fire_site_armed 0x4dcba0** @714ms; **emit_call** dest=[273,313] frame `[0,17,0,273,0,313,0,0,0,0,0,0,0]`
  @715ms — disparo de dentro do HW exec BP no sítio de main-loop PE **0x4dcba0** (NÃO dentro de `read`).
- **transport sendmsg fd=195 bytes 5/5 during_call=true phase=sync** @717ms — pacote de 5 B na rede
  DURANTE a chamada (origem→scramble→envio pelo próprio cliente).
- **emit_return retval=215959** @717ms — chamada **RETORNOU** limpa, SEM `native_exception`.
- **recv_0087 src=[273,314] dst=[273,313] phase=post_return** @964ms — **o servidor confirmou o
  movimento ao destino INJETADO (273,313)**. dst == nosso dest pedido.
- **Cliente VIVO e estável** (state S) após a rodada + segundos depois; gadget 27053 intacto.
- **Critérios de sucesso:** retorno SIM / sendmsg 5B SIM (during_call) / recv_0087 dst=destino SIM /
  responsivo SIM. **Movimento injetado ponta-a-ponta OK pela 1ª vez.**
- **Limite de cobertura (regra de conclusão):** nesta rodada os 4 HW BP são desarmados em `doFire` p/
  evitar falha de BP aninhado, então o `store_035f` (scrambler id=0x35F) NÃO foi observado diretamente
  DURANTE a chamada; a prova de origem+cifra+envio vem do `sendmsg 5B during_call` + `recv_0087` com
  dst == destino injetado (o servidor só aceitaria um 035F cifrado válido). Para observar o store
  during_call seria preciso um disparo que não desarme o slot 2 (tradeoff conhecido).
- **Discriminador consolidado:** read-context (r04 delay700=retorno+freeze; r05 delay2000=abort mid-call)
  × PE-main-loop-context (r06b delay700 = retorno + envio + ack + VIVO). → **o contexto `read`/wineserver
  era a causa do travamento/abort**; classificar SÓ assim (não "reentrância resolvida em geral":
  o callback de HW-BP ainda não é o fluxo natural). `this_ecx=0x28c7b158` é o mesmo da rodada 06.
- **Próxima decisão:** (a) reproduzir 1× p/ robustez; (b) comparar com a via de relay VALIDADA
  (substituir corpo pré-XOR no store gb+0x18eff2, inject=true/inject-call=true, range 2632000-2730000)
  — que também não derruba o cliente — e decidir a entrega realista com o orquestrador/responsável.

## Rodada MOVER-20261016-08 — REPRODUÇÃO da 06b (sessão nova, DEMONSTRADA, cliente VIVO)
Artefato: `/tmp/claude-035f-20261016-014857-repro06b/trial.json`. Autorização direta do responsável
("Autorizo reproduzir A"), cliente relogado e in-game na tile (273,313) informada por ele. Sonda e sítio
idênticos à 06b (`dispatcher_trial_pesite.py --fire-site 0x4dcba0 --construct-frame --delay-ms 700`),
destino **(273,314)** (passo de 1 tile a partir de (273,313)). **PID novo 3520569** (build hash uaRO+gepard
= MATCH), gadget 27053 do próprio cliente (há um 2º gadget em 27052 = processo `reaper`, não-alvo).
- `disp_captured` passivo code=120 **this_ecx=0x28c95668** @9ms — dispThis **diferente** da 06b
  (0x28c7b158) → confirma que é heap por-sessão e a captura passiva funciona em qualquer sessão.
- `emit_call` dest=[273,314] frame `[0,17,0,273,0,314,0×7]` @711ms (disparo de 0x4dcba0).
- `sendmsg fd=196 5/5 B during_call=true` @713ms; `emit_return retval=12809` @713ms (SEM exceção).
- `recv_0087 src=[273,313] dst=[273,314]` @970ms — **servidor confirmou o movimento ao destino injetado;
  o `src=[273,313]` bate EXATAMENTE com a tile real informada pelo responsável** → é o personagem real
  se movendo da posição real, não replay. Cliente **VIVO** (state R) após.
- **4 critérios:** retorno SIM / envio 5B SIM / recv_0087 dst=destino SIM / responsivo SIM.
- **Robustez demonstrada:** o mecanismo repete através de relogin (novo PID, novo heap/dispThis, novo
  destino). Mesma cobertura-limite da 06b (4 HW BP desarmados em `doFire` → store do scrambler id=0x35F
  não observado during_call; origem+cifra+envio provados por sendmsg 5B during_call + recv_0087 dst=injetado).

## Pendência de fronteira
Editei e commitei docs §13.7 **antes** de adotar o protocolo; docs pertencem ao Documentador.
Ver HANDOFF: entregar propriedade; não editar docs compartilhados daqui em diante.
