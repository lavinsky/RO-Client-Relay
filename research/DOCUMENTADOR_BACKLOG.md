# Backlog do Documentador

Fila de integração montada pelo Orquestrador. **Não é documento científico** e não
concede autorização. Ao retomar, leia `research/COORDINATION.md` (§Entrega ao
documentador) e as instruções de `docs/`. Classifique tudo em
OBSERVADO / INFERIDO / HIPÓTESE / NÃO VERIFICADO / REFUTADO. Não transforme relato em
prova. Preserve rodadas anteriores. Atualizado 2026-10-15.

## CORREÇÃO CRÍTICA (2026-10-15, confirmada pelo responsável) — aplicar antes das demais
Entra via MOVER (retratação) + responsável. Reclassifica a leitura do 035F e conecta MOVER↔CIFRA.

- **FATO:** o **035F é CIFRADO** — XOR-scramble byte-a-byte em memória **antes** do envio. Qualquer
  afirmação de que 035F trafega/é montado em "texto claro" é **REFUTADA**. (A retratação do MOVER
  foi sobre uma leitura `0x5F03` num `send` da libc, pós-scramble, irrelevante.) Varra os docs de
  movimento por linguagem que sugira 035F claro e corrija. **Nota:** "relay de texto claro" em
  `GEPARD_CONTROL_PACKETS.md:41` é OUTRO contexto (saída decifrada do relay p/ OpenKore em xKore 1)
  e está **correto** — não confundir.
- **FATO (validado p/ este cliente, `relay_capture.conf:99-111`):** o que as sondas de movimento
  chamam `store_035f` em **gepard+0x18eff2** (`mov byte [ecx],bl`) **é o byte-store in-place do
  scrambler do Gepard** (= `scramble-bp=18eff2`). O cliente monta o 035F em
  `scramble-range=2632000-2730000`, cifra ali byte-a-byte e envia. Isto **liga** o `store_035f` da
  trilha MOVER ao scrambler que a CIFRA investiga — anote a conexão nos dois documentos.
- **VALIDADO (relay, `relay/writeback.py`, `relay/sendwatch.py`):** a injeção de andar pelo relay =
  substituir o corpo **ANTES do XOR nesse store** (BP exec DR0); o cliente então cifra+envia. É o
  caminho correto conhecido para o 035f (merge reativo, `inject=true`/`inject-call=true`).
- **Reenquadramento da rodada 04:** a chamada direta ao dispatcher ORIGINOU um 035F e **chegou ao
  scrambler** (`store_035f` id=0x35F during_call) → movimento de fato injetado, mas **retornou antes
  do estágio natural de envio e travou**. Causa **líder (HIPÓTESE, não provada):** reentrância Wine
  (disparo de dentro de um `read` da libc, no pump do wineserver). Documente como hipótese líder,
  não como mecanismo demonstrado.
- **Direção vigente (responsável, sobrepõe o contrato da rodada 05):** retomar a origem via chamada
  ao dispatcher e **estabilizar o crash**; **não** seguir a via "caminho de envio natural" pura.
  Ajuste a §13 para refletir que a via de envio natural foi preterida por decisão humana.

## 0. Antes de tocar em docs
- `git status` / `git log`. Há **mudanças não commitadas em `docs/`** (CIPHER_INVESTIGATION,
  CIPHER_TOOLS, RESEARCH_EVIDENCE_INDEX, RESEARCH_STATUS) e em `research/cipher/*.py` —
  são edições em andamento (consolidação / CIFRA). **Confirme a propriedade antes de
  sobrescrever**; não reverta diffs alheios. MOVER e CIFRA já entregaram a propriedade dos
  docs ao Documentador (ver HANDOFFs), mas o diff em curso precisa ser conciliado, não descartado.
- Kit `ro-ops` já commitado e pushado (commit `b003b1d`). Não precisa integrar código; ver tarefa 4.

## 1. MOVER — integrar em `docs/MOVEMENT_035F_PRECONDITIONS.md`
Fonte: `research/movement_035f/HANDOFF.md` (IDs 01, 02, 04) e `STATE.md` (rodadas 03, 04).
Rodada 05 (via de envio natural) **está em andamento — aguarde o HANDOFF 05 antes de fechar §13**.

### 1a. §13.8 NOVA (rodada 04) — ainda ausente do doc
O resultado mais recente demonstrado **não está em docs**, só em HANDOFF:04 e STATE.
Integrar como §13.8:
- **OBSERVADO:** cliente é Wine; a main thread drena o wineserver por `read` (~1308/5 s) e
  `writev`, quase não usa libc `poll` (2/5 s). A âncora antiga (`poll` onLeave) não disparava
  por isso. Âncora corrigida p/ `read` onLeave.
- **OBSERVADO:** chamada nativa 13-dword no `read` onLeave, dest (274,315), **RETORNOU**
  (`emit_return` retval=1010077) e montou corpo 0x35F no dest, `during_call`. **SEM**
  `sendmsg`/`recv_0087`. Cliente **congelou e encerrou após o retorno**.
- **Contraste §13.5** (poll onEnter / pré-poll): lá congelava DENTRO, sem retorno.
- **Classificação correta:** dependência de fase/contexto = OBSERVADA (pós-espera retorna ×
  pré-poll trava). Transmissão ausente = OBSERVADA. **O `store_035f` observado = o byte-store do
  scrambler** (ver CORREÇÃO CRÍTICA): a chamada chegou a cifrar o corpo in-place, mas retornou
  antes do estágio natural de envio. **Mecanismo do freeze = HIPÓTESE, líder = reentrância Wine**
  (disparo de dentro de um `read` da libc); flush pulado é alternativa. **NÃO** escrever que
  "anda" nem que o mecanismo está resolvido.
- **Critério ponta-a-ponta:** retorno SIM / envio NÃO / resposta NÃO / responsivo NÃO → FALHOU.
- Evidência: artefato privado `/tmp/claude-035f-20261015-160152-read-anchor/` (não versionar).

### 1a-bis. §13.9 NOVA (rodada 05) — abort mid-call (fonte: HANDOFF:05)
Chamada direta ao dispatcher, âncora `read` onLeave, dest (273,313), **delay 2 s** (autorizada e
assistida pelo responsável). Cliente DOWN depois.
- **4 critérios:** retorno NÃO / envio NÃO / resposta NÃO / responsivo NÃO → FALHOU.
- **Modo de falha = OBSERVADO:** **não** foi freeze — `native_exception type="abort"` (SIGABRT),
  `pc=vdso`, **DURANTE** a chamada. `hang_diagnosis="absent"` (processo já ausente; responsável:
  "o cliente simplesmente fechou").
- A chamada **entrou, rodou o receptor, e o scrambler cifrou o corpo injetado** (`store_035f`
  id=0x35F body [273,313] dir=1, during_call) — origem autônoma do 035F chegou ao scrambler de novo —
  **e então abortou**.
- **Discriminador (OBSERVADO):** delay 700 ms (rodada 04) → RETORNOU+travou; delay 2 s (rodada 05)
  → abort mid-call. **Manifestações diferentes, causa provável a mesma.**
- **Classificação:** reentrância Wine = **HIPÓTESE LÍDER, não provada** (chamada de lógica PE de
  dentro do `onLeave` de um `read` da libc = pump do wineserver → check de consistência libc/Wine →
  abort). Não escrever como mecanismo demonstrado.
- Próxima rodada (06): discriminante = disparar **fora** do contexto do `read` (HW exec BP em sítio
  de main-loop do `uaRO.exe`, base fixa 0x400000). Aguardando relogin.

### 1b. Correções de conclusões fortes já pedidas pelo Orquestrador (verificar se aplicadas)
- **§13.7:** rebaixar "Stalker/HW BP não são detectáveis" de FATO para **RELATO do responsável
  (NÃO VERIFICADO em geral)**; "colisão no byte verificado" = **INFERIDO**, não observado por
  instrumento (o probe não identificou o byte). Alerta/encerramento do Gepard = RELATO.
  (STATE.md do MOVER já foi reclassificado; conferir se o doc acompanha.)
- **§13.5:** "pacote montado" deve ser **"conteúdo compatível observado no trap pré-store"**;
  `onEnter` precede a execução de poll; remover frase de §13.4 contradita por §13.5
  ("faltava só a ABI/pilha correta"). Imbalance de pilha = REFUTADO como causa única, não toda ABI.
- Reconciliar divergência §13.5 (assertiva) × `RESEARCH_STATUS.md` (limites corretos): vale o
  método/cobertura, não a frase mais recente.

## 2. CIFRA — integrar em `docs/CIPHER_INVESTIGATION.md`
Fonte: `research/cipher/HANDOFF.md` (`CIFRA-20261015-CL-01`) e `STATE.md`. CIFRA está sem tokens.
- Carga em `+0x1C7502` define CL; cadeia de cópias até store `+0x1C752B` (13 pontos, ECX estável,
  origem `EBP+0x36`) = OBSERVADO. POP candidato em `+0x1C70DC` = **candidato por decode reverso**,
  prova antes/depois **PENDENTE**.
- XOR local em `+0x2689FB` = OBSERVADO por operandos; **não** identificado como cifra; sem consumidor
  associado. **Retirar** qualquer atribuição automática do XOR ao byte final.
- Direção, pacote, fronteira F, estado, inicialização e vetores independentes = DESCONHECIDOS.
- Conferir as edições já em curso em CIPHER_INVESTIGATION/CIPHER_TOOLS contra esses limites.

## 3. Índice e panorama
- `docs/RESEARCH_EVIDENCE_INDEX.md`: apontar os artefatos privados por rodada (caminhos, não conteúdo).
- `docs/RESEARCH_STATUS.md`: refletir rodada 04 (dependência de fase OBSERVADA; movimento autônomo
  ainda **não** validado) e o estado da cifra. Sem elevar relato a prova.

## 4. Kit `ro-ops` (follow-up do Orquestrador)
Citar o kit em `docs/CODEX_WORKFLOW.md` (e, se couber, `docs/OPERATIONS.md`): CLI read-only
`ro-ops` com 5 subcomandos (`discover`, `new-artifact`, `sample-thread`, `scaffold-state`,
`env-check`), contrato JSON `{cmd,status,data,caveats}` + exit codes 0/10/20/1, skill em
`.agents/skills/ro-ops/`. Deixar explícito que **não autoriza experimento** e que
`env-check` **não** prova exclusividade da janela. Commit `b003b1d`.

## 5. Devolução ao Orquestrador
Por rodada incorporada: ID, links e **no máximo três divergências** que exijam decisão humana.
Não fazer nova reorganização geral. Se faltar evidência, devolver pergunta específica ao autor
(MOVER/CIFRA) e registrar a limitação — não preencher por conta própria.
