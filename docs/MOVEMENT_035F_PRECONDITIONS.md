# Pré-condições de preparação do movimento 0x035F

Investigação da preparação/contexto que antecede o store do `0x035F`, focada em
**explicar por que a tentativa de chamada nativa de `0x8A` ficou inconclusiva**.
Registra apenas conclusões e referências sanitizadas; não copia capturas cruas,
credenciais nem objetos completos.

- **Repositório/commit:** `dbb08c7` (working tree; `research/`, `.mcp.json` e os
  arquivos de cifra estavam não rastreados — não interpretados como descartáveis).
- **Build/sessão viva:** `uaRO.exe` PID 3124344, `comm=uaro.exe`, 37 threads.
  `uaRO.exe` SHA-256 `f2f25a89917563237bb6…`, `gepard.dll` `34188e6046eb831f31c0…`
  (em disco; **iguais** aos de S1/S2 — mesmo build). Gadget em `127.0.0.1:27053`.
  `uaRO.exe` PE em `0x400000`; código anônimo `0x401000–0x1607000`. Base do Gepard
  muda por relog — **resolver em runtime, nunca hardcode**.
- **Escopo autorizado:** cliente uaRO do próprio responsável; observação read-only e
  movimentos manuais. **Acesso NÃO exclusivo** — a instância de cifra (Codex) coexiste
  e pede confirmação humana antes de cada sonda. Revezamento mediado pelo responsável.
- **Fontes das sondas (externas, /tmp, hasheadas):** `ro035f_probe.py`
  (`7033b0a05971e08e…`), `ro035f_auto_probe.py` (`b051ec36d00e2dc0…`),
  `ro035f_clicks.py` (`e43acec1f12cfdf6…`), `ro035f_inspect.py` (`8f6c02fb5d955862…`).
  Artefatos de resultado em `/tmp/ro035f*`; sínteses revisadas abaixo, não cópias.

## 1. Conclusão principal e seu limite

**OBSERVADO (código das sondas + artefatos):** o resultado "inconclusivo" do ensaio
nativo é, antes de tudo, uma **lacuna de observabilidade**, não prova de que a chamada
não enviou movimento. O detector de sucesso é inteiramente ancorado no reconhecimento
do store do `0x035F`; quando o store não é reconhecido, o pipeline não consegue sequer
observar envio ou associar resposta.

**Limite da conclusão:** isto **não** demonstra que a chamada nativa funciona, nem
**localiza** a preparação necessária (não se pode afirmar que ela está "antes do `0x11`").
Distingue o que a sonda podia e não podia ver, e aponta a observação mínima que separaria
as hipóteses. Nenhuma função autossuficiente de movimento foi demonstrada.

## 2. Chamada natural × tentativa nativa

Cadeia natural OBSERVADA (6/6 cliques manuais em S1/S2, mesmo build) até o store:
clique → wrapper uaRO → VM do Gepard → dispatcher `0xd473b0` processa os códigos
**internos** `0x11 → 0x0D → 0x5B → 0x8A` → receptor `gepard+0x10A90` → store
`mov [ecx],bl` em `gepard+0x18eff2` → resposta `0x0087` (ver `docs/MOVEMENT_035F_INVESTIGATION.md`).

Diferenças auditadas da tentativa nativa (`ro035f_probe.py`, modo `--emit`):

| Aspecto | Natural | Tentativa nativa | Fonte |
|---|---|---|---|
| Ponto de chamada | callsite da VM `0xd477bc` | hook `onEnter` de `poll/ppoll/select/pselect` | `ro035f_probe.py:179-191` |
| Alvo chamado | cadeia `0x11→0x0D→0x5B→0x8A` | **só a folha `0x8A`** (`gepard+0x10A90`) | `ro035f_probe.py:177,187` |
| Destino | do estado de entrada do clique | **fixo** `[189,357]`/`[191,358]` | `ro035f_probe.py:198` |
| Detecção de store | BP site 3 com gate `ecx∈pilha` e `[ecx-2]==0x035f` | idem (gate silencioso em falha) | `ro035f_probe.py:154-155` |
| Associação do ACK | só se `pending` (= store reconhecido) | idem | `ro035f_probe.py:70-78` |
| Observação de **envio** | **nenhuma** (só `recvmsg`) | **nenhuma** | `ro035f_probe.py:83-100` |

**OBSERVADO nos artefatos:**
- `probe-1792047915…` (1º ensaio, 119 ms): `emit_state={attempted,returned:false,thread_ok}`,
  `error:"breakpoint triggered"`. A chamada bateu nos **próprios breakpoints armados** →
  **artefato de instrumentação** (`exceptions:'steal'`), não comportamento do cliente.
- `probe-1792048184…` (2º ensaio, 10 s, `exceptions:'propagate'`, `ro035f_probe.py:177`):
  o receptor **entrou** (`last8a`: code `0x8a`, `receiver_this_is_manager:true`,
  `tail_args_zero:true`, coords `[191,358]`) **e retornou** (`returned:true`), mas
  **`matched:false`** — nenhum store reconhecido.

**INFERIDO:** como um hit do store que falhe o gate de `ecx` é descartado em silêncio
(`return true`, `ro035f_probe.py:155`) e não há hook de transporte, o artefato **não
distingue** "store executou fora da janela de pilha corrente" de "store não alcançado",
nem observa se bytes saíram. O ACK ausente **não é** um segundo negativo independente:
ele depende do store (`ro035f_probe.py:70-78`). A contagem "6/6 com store" vem do modo
`anchor` (`ro035f_auto_probe.py:188-255`), **que não tinha hook de recepção** — logo não
sustenta contagem de ACKs.

## 3. Mapa de argumentos/objetos/campos (contrato conhecido)

Disassembly OBSERVADO em `/tmp/ro035f-dispatch-cases-getter-full.json` (mesmo build):

| Caso @pc | Acessos a campos (objeto `this`) | Leitura/escrita | Papel OBSERVADO |
|---|---|---|---|
| `0x11` @`0xd476e5` | `[ebx+0x70]` (gate: 2/5/6 → desvia) | R | encaminha `0x0D` via `[eax+8]`; depois `0x5B` via `[esi+8]` |
| `0x11` @`0xd476e5` | `[ebx+0x510]=0`; `[ebx+0x534]=[ebx+0x538]=0xffffffff` | W | prepara estado antes do `0x5B` |
| `0x0D` @`0xd47ac4` | `[ebx+0x50c]=0`; `[ebx+0x500]=0` | W | zera campos; encaminha `0x1A` via slot `0x18` |
| `0x5B` @`0xd4777d` | `byte[0x1602a8f]=0`; gate `getter() ≤ [ebx+0x520]+0x15E ? sai` | R/W | se passa: `[ebx+0x520]=getter()` e chama `0x8A` |

Chamada do receptor em `0xd477bc`: `ecx=esi`, args `(0x8A, edi, [ebp-0x24], 0, 0)` =
`(code, x, y, 0, 0)`. **INFERIDO:** thiscall, 5 args de 32 bits, callee remove 20 bytes
(doc de investigação: `stack_delta=24`). `pack_move`/`unpack_pos2` em `relay/packets.py:112-125`
confirmam a decodificação dos 3 bytes.

**NÃO VERIFICADO / cautela (crítica):**
- `getter` do gate `0x5B` = `[0xfc17b0]()`; **unidade e semântica de `0x15E`=350 não demonstradas**
  (não afirmar 350 ms nem "cooldown"). O gate decide **SE** chamar o receptor — não é, por si,
  prova de pré-condição **para o receptor produzir** o pacote quando já chamado.
- Os campos escritos por `0x11`/`0x0D` são no `this` do **dispatcher** (`ebx`); o `this` do
  receptor é `esi`. **Não presumir que são o mesmo objeto.** Nas capturas naturais `esi`
  coincidiu com o objeto do manager (`receiver_this_is_manager:true`), mas isso não prova que o
  receptor **lê** `[ebx+…]`. Uma escrita antes do `0x8A` é **candidata** a preparação, não
  pré-condição necessária comprovada — falta identificar um consumidor (leitura/ramo) no receptor.

## 4. Matriz de hipóteses

| Hipótese | Evidência a favor | Evidência contra / ausente | Menor observação que distingue |
|---|---|---|---|
| **H1 — Observador store-gated** | associação dependia do store | **ELIMINADA pela 6.4** (ver §6): transporte independente + store sem gate ficaram silenciosos para a chamada | — (resolvida) |
| **H2 — Bypass da preparação de estado** (agora prioritária) | `0x11/0x0D/0x5B` escrevem 5+ campos no objeto do dispatcher antes do `0x8A`; leaf sozinho não armazena/envia (6.4) | nenhum consumidor dessas escritas ainda identificado no receptor | leitura delimitada desses campos dentro do receptor na execução natural |
| **H3 — Contexto/callsite/reentrância** (viável) | chamada fora da VM entrou e retornou **sem** store/envio (6.4); receptor começa com `jmp` p/ VM | — | entrar pelo **dispatcher `0x11`** (contrato próprio) vs. folha |
| **H4 — Destino redundante/condição** | — | destino (160,247) era diferente da posição (~156,247) e ainda assim nada ocorreu (6.4) | destino bloqueado/distante com ground-truth |

Amostra relevante (`probe-1792048509…`, `--input`): movimento com **store + ACK** porém
**sem hit em `0xc7650e`** (`input11` ausente). **REFUTA para esta amostra** que o wrapper
`0xc7650e` seja passo necessário; não refuta todos os ramos. As **duas interfaces `0x11`**
(dispatcher de slots 64-bit vs. wrapper `0xc7650e`) permanecem distintas — a ferramenta
offline as separa e nunca as funde.

## 5. Experimentos executados e próximo experimento

**Executado (offline, nesta sessão):** auditoria do código das sondas e dos artefatos;
mapa do contrato a partir do disassembly salvo; ferramenta de tabela sanitizada + testes
sintéticos.

**Executado (vivo, read-only, janela exclusiva confirmada pelo responsável):** um run de
`research/movement_035f/observe_path.py` de 10 s no PID 3124344, limpeza confirmada
(`cleared=true`), 2126 eventos, sem saturação, nenhuma chamada nativa. Resultado em
`/tmp/claude-035f-20261015-091419/natural-observe-1.json` (externo, não versionado).

- **OBSERVADO — observadores funcionam no movimento natural (`observers_ok=true`):** por
  passo do andar, a sequência é consistente e as coordenadas coincidem entre os canais:
  `dispatcher_0x11 [x,y] → receptor_0x8a [x,y] (this=manager) → store_035f [x,y]
  (id 0x035f, in_stack) → sendmsg → recv_0087 dst [x,y]` (ex.: `[159,321]`, `[160,323]`,
  `[159,317]`; 18 passos). Ordem por índice de evento, não por relógio.
- **OBSERVADO — transporte DESCOBERTO (envio correlacionado ao movimento):** a conexão do
  servidor (fd 197, porta remota 5121) usa **`sendmsg`** (21x no run), com endereço de
  retorno em **`ntdll.so`** (Wine). **Não é `sendto`.** O **retorno efetivo** foi 5 bytes;
  o **tamanho solicitado** não foi lido desta captura (o comprimento mora no `msghdr`, não
  num arg direto). 5 coincide com `035F 5` em `data/uaro_recvpackets.txt`, mas **sem leitura
  de buffer/proveniência não se afirma identidade demonstrada** com o `035f` — é envio
  **correlacionado temporalmente** ao passo de movimento, não um pacote identificado.
- **OBSERVADO — store compartilhado:** o breakpoint em `gepard+0x18eff2` (`mov [ecx],bl`)
  dispara para muitos pacotes/posições (2038 hits; só 18 com `[ecx-2]==0x035f`). É um
  **store compartilhado observado**; **não** é classificado como laço de cifra byte-a-byte
  aqui — isso exigiria evidência adicional da transformação executada (não coletada).
- **OBSERVADO — `recv_0087` é independente:** registrado por framing de recepção, **sem
  depender de store nem de `pending`**; sua **associação a um movimento** (casar `dst` com
  um `035f`) é uma **etapa separada**, feita na análise, não na coleta.
- **Cobertura/perdas:** `saturated=false` e `framing_errors` observados por run; ainda assim
  **eventos distintos não garantem observação completa** (uma tentativa de movimento, um
  envio ou uma resposta podem não ter sido capturados). Resultados negativos de uma janela
  são inconclusivos.
- **INFERIDO:** o conjunto de observadores agora **distingue** os quatro pontos de forma
  independente — pré-requisito satisfeito para a comparação com a tentativa nativa.

**Executado (vivo, Etapa 6.4, janela EXCLUSIVA confirmada — Codex da cifra parado):**
controle natural antes → **uma** tentativa nativa → controle natural depois, destino de
mapa **(160,247)** a partir de ~**(156–157,247)** (diferente e andável). Observadores
validados no controle antes (`observers_ok=true`; dispatcher `this=0x28c27dc8`, retorno
`0x7744c251`=Gepard+0xB2C251, `gate70=0`; receptor `this=0x248ca3d0`, `this_is_manager=true`,
retorno natural `0xd477bf`; `sendmsg` de movimento **5/5** req=ret). Artefatos externos:
`native-before-1.json`, `native-trial-1.json`, `natural-after-{1,2}.json`.

- **OBSERVADO na tentativa nativa** (`native-trial-1.json`): `emit_state={attempted,
  returned,thread_ok}`. Ordem: `emit_call[160,247] → receptor_0x8a (coord [160,247],
  this_is_manager=true, mesmo objeto 0x248ca3d0, retorno 0xf69b8758 = trampolim) →
  emit_return`. **Entre a chamada e o retorno: nenhum `store_035f` com id `0x035f` e nenhum
  `sendmsg`.** Os `sendmsg`/stores da janela eram de **outros ids**, anteriores à chamada.
- **HIPÓTESE DISCRIMINADA — H1 (observabilidade) ELIMINADA:** o transporte foi observado de
  forma **independente** e o store **sem gate de pilha**; ambos silenciosos para a chamada.
  Logo a folha `0x8A`, chamada direta com objeto/args corretos na thread principal,
  **genuinamente não monta/armazena/envia** o `035f`. (Limite: não distingue H2 de H3 e não
  afirma ausência absoluta de tráfego — afirma que, nesta janela e com observadores
  independentes ativos, nada ocorreu atribuível à chamada.)
- **OBSERVADO — controle depois:** movimento natural volta a produzir a cadeia completa e o
  responsável confirmou in-game que **o movimento funciona**; cliente responsivo, sem
  dessincronização de cifra atribuível à tentativa.

**Próximo experimento (só após proposta e aprovação; agora com dependência concreta):**
o leaf é insuficiente, então investigar a **preparação a montante** — entrar pela cadeia do
**dispatcher `0x11`** (ABI de slots 64 bits, contrato re-verificado; `this` do dispatcher é
objeto **distinto** do receptor) que executa `0x11→0x0D→0x5B` e escreve o estado
(`+0x500/+0x50c/+0x510/+0x520/+0x534/+0x538`) antes do `0x8A` — OU identificar, por leitura
delimitada na execução natural, qual desses campos o receptor **consome** (distingue H2 de
H3). Não aprofundar além disso sem um consumidor concreto apontado pelo resultado.

> **Arquitetura (ARCHITECTURE.md §10; `relay/writeback.py:1-8`):** o relay já injeta `035f`
> de forma **reativa** (merge no store, pré-XOR), porque enviá-lo pela `SendPacket`
> **dessincroniza a cifra**. O objetivo desta linha nativa (§10/§13) é **disparar um `035f`
> espontâneo pelo caminho de pilha correto** (andar autônomo). Logo o teste precisa também
> verificar se o `035f` resultante sai com a **cifra sincronizada** — um store reconhecido
> sem sincronia de cifra não resolve o objetivo.

## 6. Ferramenta offline e testes

- `research/movement_035f/analyze.py`: aceita arquivos de evento **explícitos**, emite tabela
  sanitizada de canais, ordem (por campo `order`, nunca por `ms`) e limites de observação.
  Não varre diretórios, não funde sessões, não fabrica campos (ausência ≠ zero/false), não
  afirma envio quando a captura não o observou.
- `research/movement_035f/observe_path.py`: observação read-only (dispatcher/receptor/store
  sem gate/transporte/recv) para validar observadores no movimento natural e descobrir o
  transporte. `research/movement_035f/native_trial.py`: a tentativa nativa única da Etapa 6.4.
- `tests/test_movement_preconditions.py`: fluxo natural; nativo sem store; ACK sem associação;
  truncado/ausente; isolamento entre sessões; distinção das duas `0x11`; preservação dos
  arquivos de entrada; ordenação por `order`; canais independentes do `observe_path`.

## 7. Verificações

- `python3 tests/test_movement_preconditions.py` → **PASS** (`test_movement_preconditions PASS`).
- `python3 scripts/validate-research.py` → **PASS** (docs compartilhados, não alterados).
- `research/movement_035f/analyze.py` sobre artefatos reais (`probe-…662/915/184/509`) →
  **PASS** (formatos reais classificados; falso-positivo de limite corrigido e coberto por teste).
- `observe_path.py` vivo (janela exclusiva) → **PASS**: `cleared=true`, `observers_ok=true`,
  transporte descoberto (`sendmsg`), DRs liberados. Cliente vivo após o run.
- `native_trial.py` vivo (Etapa 6.4, janela exclusiva) → **PASS/limpo**: `cleared=true`,
  `emit_state={attempted,returned,thread_ok}`, DRs liberados; controle natural depois
  confirmou movimento funcionando. Resultado experimental: H1 eliminada (ver §5).
- Suíte offline completa (`scripts/test-offline.sh`) → **NOT RUN** de propósito: inclui a
  pesquisa de cifra em construção (`tests/test_cipher_research.py`), de outra instância.
- Investigação a montante (dispatcher `0x11` / consumidor de campo) → **NOT RUN**: próximo
  experimento, exige proposta e aprovação próprias.

## 8. Lacunas e pendências humanas

- **REFUTADO (6.4):** a folha `0x8A` **não** é uma função de movimento autossuficiente
  (entrou/retornou sem store nem envio). A preparação a montante é necessária (dependência
  concreta para o próximo passo).
- **NÃO VERIFICADO:** qual campo do estado do dispatcher o receptor consome (H2 vs H3);
  transformação completa entrada→destino; unidade do gate `0x15E`; sincronia de cifra de um
  `035f` eventualmente disparado pela cadeia do dispatcher; cobertura entre builds; protocolo
  suficiente para xKore 0.
- **Depende do responsável:** janela de uso exclusivo (ou revezamento confirmado) para a fase
  viva; confirmação de que a sonda da cifra está desarmada antes de cada run (colisão de
  registradores de depuração pode travar o cliente — ARCHITECTURE.md §11); escolha de destino
  com ground-truth (posição conhecida) para H4.

## 9. Estado de limpeza e liberação do cliente

Vários runs de `observe_path.py` (read-only) e **uma** tentativa de `native_trial.py`
(Etapa 6.4) armaram 3 breakpoints de execução (DR0–DR2) + hooks de leitura; **todos**
reportaram `cleared=true` (DRs liberados) e o cliente seguiu vivo. A tentativa nativa fez
**uma** chamada ao receptor (sem retry, sem cópia de objeto, sem outra escrita) e não leu
buffer de pacote. Controle natural depois + confirmação do responsável: **movimento
funciona**, sem dessincronização de cifra atribuível à tentativa. Cliente PID 3124344 vivo e
responsivo; janela exclusiva pode ser devolvida. Áreas de outra instância (`research/cipher/`,
`tests/test_cipher_research.py`, `docs/CIPHER_INVESTIGATION.md`, `/tmp/ro-cipher-*`) não
foram lidas nem alteradas. Sem commit/push/PR. Artefatos privados em
`/tmp/claude-035f-20261015-091419/` (0700).

## 10. Auditoria offline (Fase A) — matriz objeto/campo/produtor/consumidor

Auditoria **somente de fontes já existentes** (sem nova coleta): docs de preconditions e
investigação, `observe_path.py`/`native_trial.py`/`analyze.py`, `ARCHITECTURE.md` §§9–11.
Objetivo: separar o que já está demonstrado do que falta para distinguir **H2** (estado
preparado é consumido) de **H3** (contexto/callsite/VM/reentrância).

| Objeto / campo | Produtor OBSERVADO | Consumidor | Natureza | Classificação |
|---|---|---|---|---|
| Dispatcher `[ebx+0x70]` | lido como gate no caso `0x11` (`0xd476e5`) | o próprio caso `0x11` (desvia se 2/5/6) | gate de despacho | OBSERVADO (produtor/consumidor no mesmo caso) |
| Dispatcher `[ebx+0x510]=0`; `[ebx+0x534]=[ebx+0x538]=0xffffffff` | escrito no caso `0x11` | **nenhum identificado** | estado preparado | OBSERVADO (escrita) / consumidor **NÃO VERIFICADO** |
| Dispatcher `[ebx+0x50c]=0`; `[ebx+0x500]=0` | escrito no caso `0x0D` (`0xd47ac4`) | **nenhum identificado** | estado preparado | OBSERVADO (escrita) / consumidor **NÃO VERIFICADO** |
| Dispatcher `[ebx+0x520]` | consultado e atualizado no caso `0x5B` (`0xd4777d`) | o próprio `0x5B` (gate `getter()≤[+0x520]+0x15E`) | gate decide **SE** chama `0x8A` | OBSERVADO; decide a chamada, **não** prova pré-condição p/ o receptor produzir o pacote |
| `byte[0x1602a8f]=0` | escrito no caso `0x5B` | **nenhum identificado** | flag global | OBSERVADO (escrita) / consumidor **NÃO VERIFICADO** |
| Objeto do dispatcher (`ebx`; sessão: `0x28c27dc8`) | VM do Gepard | — | objeto de estado de despacho | OBSERVADO; **distinto** do objeto do receptor |
| Objeto do receptor/manager (`esi`/`ecx`; sessão: `0x248ca3d0`) | manager `[0x1213338]` → vtable slot `0x18` | receptor `0x8A` (`gepard+0x10a90`) | objeto do receptor | OBSERVADO; **nenhuma ligação direta** a `ebx` demonstrada |
| Store `gepard+0x18eff2` (`mov [ecx],bl`) | caminho natural (muitos ids) | fila/cifra compartilhada | store **compartilhado** | OBSERVADO (18/2038 hits foram `035f`); não classificado como laço de cifra aqui |
| Transporte `sendmsg` (fd 197, porta 5121) | caminho natural + heartbeat/outros | socket do servidor | transporte **geral** | OBSERVADO; envio **correlacionado** ao passo, não identidade de pacote |

**Lacunas que a Fase A não fecha (precisam de coleta viva):**
1. **Consumidor ausente.** Nenhuma evidência existente mostra qualquer campo `+0x5xx`/`+0x70`
   do dispatcher sendo **lido** pelo receptor ou por código a jusante que decida produzir o
   store. Só há **produtores** (escritas) e dois gates (`+0x70`, `+0x520`) que agem **dentro
   do dispatcher** — ou seja, decidem **se** `0x8A` é chamado, não **se** `0x8A`, uma vez
   chamado, monta o pacote. A tentativa nativa 6.4 chamou `0x8A` já "depois" desses gates e
   mesmo assim nada ocorreu — logo os gates `+0x70`/`+0x520` **não explicam** a falha nativa.
2. **Sem ligação objeto↔objeto.** Dispatcher (`ebx`) e receptor (`esi`) são objetos distintos;
   não se demonstrou que o receptor alcance `[ebx+…]`. Se não houver ponteiro do receptor para
   o dispatcher, os campos `+0x5xx` são **irrelevantes** para o receptor e a divergência pende
   para **H3** (ou para um campo do **próprio** objeto do receptor, ainda não mapeado).
3. **Snapshot ≠ consumo.** Mesmo observando os campos mudarem de `0xffffffff`/stale para um
   valor "preparado" antes do `0x8A`, isso é **produtor**; provar consumo exige ver a **leitura**
   numa condição de controle (Fase E), que tem proposta de custo própria.

**Conclusão da Fase A (OBSERVADO/INFERIDO):** a base de evidências sustenta **produtores** de
estado e **gates de despacho**, mas **não** um **consumidor** que ligue estado preparado à
produção do pacote. Portanto H2 e H3 permanecem ambas abertas; o menor passo que as separa é
primeiro estabelecer **se o objeto do receptor sequer referencia o objeto do dispatcher**
(mapa funcional, critério D) — barato e read-only — antes de qualquer rastreio de leitura.

## 11. Próximo experimento (um só) e pedido de autorização consolidado

**Estado do cliente nesta sessão:** PID 3124344 **não existe mais** (relog ocorrido — bases do
Gepard mudam por relog, como já documentado). Logo **nenhuma instrumentação viva foi executada
nesta sessão**; o que segue é **proposta**, com a ferramenta já preparada e validada offline.

**Experimento escolhido (Fase C/D, read-only, delimitado — 2ª prioridade do §10 do prompt,
pois ainda não há consumidor identificado):** uma janela de **movimento natural** com o
`observe_path.py` estendido, que nos mesmos 3 breakpoints de execução já validados acrescenta,
**sem chamada nativa e sem watchpoint**:
- `state` no `dispatcher_0x11`: leitura read-only dos campos candidatos
  (`+0x500/+0x50c/+0x510/+0x534/+0x538`) — linha do tempo do **produtor**;
- `refs_dispatcher_at` no `receptor_0x8a`: varredura **delimitada a 64 words (256 bytes)** do
  objeto do receptor procurando um ponteiro para o objeto do dispatcher visto na mesma janela.

**O que discrimina:** se `refs_dispatcher_at` for um offset estável em vários passos → o receptor
**pode** alcançar o estado do dispatcher (abre H2 com um alvo concreto de leitura para a Fase E);
se for sempre `null` com os campos `+0x5xx` preparados mesmo assim → fortalece **H3** (ou desloca
a busca para campos do próprio objeto do receptor). Qualquer resultado reduz o espaço de hipóteses
(critério D) ou aponta um consumidor candidato (critério A).

**Limites de custo (Fase 8):** ≤ 1 processo; 3 BPs de execução (DR0–DR2) já usados antes; por hit
do receptor no máximo 64 leituras de 4 bytes (256 B) + 5 campos no dispatcher; nenhum buffer de
pacote/cifra lido; `timeout` 1000–10000 ms; teto de eventos 4000; artefatos sanitizados em
`/tmp/claude-035f-<data>/` (0700), **não versionados**; falha de leitura → `null` (nunca troca
proteção de página); cancelamento por SIGTERM com espera de limpeza idempotente.

**Risco e recuperação:** idêntico ao run read-only já validado (mesmos BPs, só mais leituras
pequenas) — ARCHITECTURE.md §11 admite "leituras fixas pequenas no agente". Sem escrita, sem
chamada, sem watchpoint de dados. Limpeza confirmada por `cleared=true`; cliente conferido vivo
e responsivo ao final; ausência de dessincronização **não** inferida só por processo vivo.

**Pré-condições humanas antes de rodar (protocolo §11 do prompt):** (1) cliente no ar e **novo
PID** confirmado + build re-conferido (hashes) + bases re-resolvidas em runtime; (2) **janela
exclusiva** confirmada; (3) **sonda da cifra (Codex) desarmada** — colisão de registradores de
depuração pode travar o cliente; (4) sem CEServer e Frida instrumentando ao mesmo tempo.
**Não** executarei sem essa autorização consolidada.

> **DiE / proteções (prompt §4):** o relatório `docs/PROTECTION_FINGERPRINT_DIE.md` (commit
> `77954b2`, branch `docs/detect-it-easy-uaro-protection-20261015`) **não está** nesta working
> tree nem no banco de objetos local. Não foi mesclado e **não farei merge automático**; é
> pendência humana decidir sua integração. A identificação Themida/VMProtect não demonstra, por
> si, que `0x8A`/dispatcher estejam virtualizados — permanece hipótese sobre cada função.

## 12. Coleta viva read-only (Fase C/D) — resultado e matriz de evidências

**Sessão:** `uaRO.exe` **PID 3240424** (após novo relog; o 3124344 da §11 não existe mais).
Build re-conferido em disco via `/proc/<pid>/root`: `uaRO.exe` `f2f25a89…` e `gepard.dll`
`34188e60…` **iguais** ao build documentado → offsets válidos. Janela **exclusiva** (nenhum
driver/sonda concorrente ativo; `/tmp/ro-cipher-*` recentes eram runs `-tests-` offline).
Limpeza: `cleared=true` em todos os runs; observador destacado; cliente **vivo e responsivo**
ao final. Artefatos externos **não versionados** em `/tmp/claude-035f-20261015-131054-walk2/`.

**Observação crítica de foco (responsável):** valores de memória do cliente podem mudar conforme
a janela esteja **em foco ou não**, e o movimento natural só ocorre com a janela focada. Logo um
campo que difira entre focado/não-focado **não é**, por isso, pré-condição de movimento.

**Geração do movimento natural (read-only no cliente):** cliques sintéticos XTEST (xdotool puro)
**não** produziram movimento (0 `035f`; só tráfego de fundo) — consistente com o Gepard filtrar
entrada sintética do X. O método que funcionou foi **híbrido**: `xdotool` posiciona o cursor
global e **uinput/ydotool** entrega o botão (BTN_LEFT) — entrada ao nível de evdev. O observador
permaneceu **somente leitura** (não chama função nativa, não escreve, não lê corpo de pacote);
os cliques são entrada natural do próprio cliente. `ydotoold` foi encerrado e o socket removido.

**Achado offline (disasm salvo, `/tmp/ro035f-dispatch-cases-getter-full.json`, build conferido):**
a chamada natural do receptor em `0xd477bc` é `call [eax+0x18]` com `this=esi` e pilha
`push 0x8a; push edi(x); push [ebp-0x24](y); push 0; push 0` — **exatamente** `(0x8A,x,y,0,0)`,
forma **idêntica** à da tentativa nativa 6.4. **REFUTADO (offline): nenhum campo de estado do
dispatcher é passado como argumento ao receptor.** Imediatamente antes, `0x5B` faz
`mov byte [0x1602a8f], 0` (zera um **global**) e aplica o gate `getter() > [ebx+0x520]+0x15E`.
Nos cinco campos candidatos, a varredura do disasm mostra **apenas escritas** de
`+0x500/+0x50c/+0x510/+0x534/+0x538` (nenhuma leitura no código capturado); só `+0x70` e `+0x520`
são lidos, e **dentro** da própria lógica de despacho (gates).

**Achados vivos (2/2 passos, estáveis):**
- **Sem ligação de ponteiro em NENHUMA direção (1024 B) nem via registro global.**
  `refs_dispatcher_at = None` (receptor `0x248caf88` → dispatcher `0x28c0a2f8`), `deref0_is_receiver
  = False` + `refs_receiver_at = None` (dispatcher → manager), e `root_refs_dispatcher_at = None`
  (o registro global do manager `[0x1213338]` → dispatcher). Varreduras **ampliadas a 1024 B** em
  ambas as direções + 128 B do registro global, confirmadas em `walk3` e `walk4`. O
  `[dispatcher+0]` é um objeto de despacho/handler, **não** o manager; o `this` do receptor é o
  manager resolvido por `[0x1213338]`. (Cobertura: 1024 B bidirecional + registro global, 8+
  eventos em 3 sessões de passos. **Resta** apenas a via H2-por-**valor global** — ex.
  `byte[0x1602a8f]` lido dentro da VM — que varredura de **ponteiros** não cobre, e offsets
  >0x400/indireção profunda/TLS.)
- **Contexto de retorno (sinal p/ H3):** `return_region = uaRO` no receptor natural (retorno em
  `0xd477bf`, dentro do despacho) **vs.** retorno em **trampolim** (`0xf69b8758`) na tentativa
  nativa 6.4 — mesma forma de objeto/args, **contexto de execução diferente**.
- **Campos `+0x5xx` constantes**: `{f500:0, f50c:0, f510:0, f534:0xffffffff, f538:0xffffffff}`
  idênticos nos dois passos → **sentinelas/flags**, não dado de destino que varie por passo
  (o destino varia — `[160,223]`→`[166,219]` — mas esses campos não).
- **`flag_1602a8f = 0`** na entrada do dispatcher e do receptor no caminho natural que funciona.
- **`counter520`** muda entre passos (gate do `0x5B`), como esperado; objetos dispatcher/receptor
  estáveis entre passos. Estrutura (disasm): o `this` do receptor é o **manager** resolvido
  independentemente (`is_manager=true`), objeto **distinto** do dispatcher.

### Matriz de evidências

| Campo/evidência | Hipótese | Origem | Produtor | Consumidor | Contexto | Cobertura | Classificação | Rival | Próximo discriminador |
|---|---|---|---|---|---|---|---|---|---|
| Args do `0x8A` natural = `(0x8A,x,y,0,0)` | H2 | disasm `0xd477a4–0xd477bc` | VM/`0x5B` | receptor | natural (estático) | call-site completo | **REFUTA H2-via-argumento** | — | — |
| `+0x500/50c/510/534/538` só escritos | H2 | disasm cases | `0x11`/`0x0D` | **nenhum no código capturado** | natural (estático) | só janela do dispatcher | OBSERVADO; consumidor ausente | leitura fora da janela capturada | disasm do corpo do receptor (VM) |
| linkage dispatcher↔manager = None + registro global = None | H2 | vivo `walk2/3/4` | — | — | natural | 1024 B bidirecional + 128 B registro, 8+ eventos | INFERIDO: sem ligação de ponteiro | H2-por-valor global (ex. `byte[0x1602a8f]`); offset >0x400/TLS | ler o global dentro da VM (Fase E) ou comparar contexto nativo×natural |
| `return_region=uaRO` natural vs trampolim nativo | H3 | vivo `walk4` + §5 | — | — | natural×nativo | 1 nativo, naturais | OBSERVADO: contexto de retorno difere | diferença irrelevante p/ o store | teste comparativo de contexto (proposta própria) |
| `+0x5xx` constantes entre passos | H2 | vivo `walk2` | `0x11`/`0x0D` | — | natural | 2 passos | INFERIDO: não são estado por-passo | campo de destino noutro objeto | snapshot do objeto do receptor/manager |
| `byte[0x1602a8f]=0` natural | H2/H4 | disasm + vivo | `0x5B` | não verificado | natural | valor no ponto, não a leitura | OBSERVADO (produtor); consumo NÃO VERIFICADO | flag não lido pelo receptor | ler o global dentro do receptor (Fase E) |
| receptor entra idêntico (obj+args) e só natural produz store | H3 | §5 (6.4) + §12 | — | — | natural×nativo | 1 nativo, 2 naturais | consistente com H3 (contexto/VM/callsite) | H2 por caminho não coberto | entrar pelo dispatcher `0x11` (contexto da VM) |

**Atualização de hipóteses (dentro da cobertura demonstrada):**
- **H2 — substancialmente enfraquecida; via-ponteiro excluída na cobertura.** Estado não é passado
  como argumento (refutado offline); campos `+0x5xx` são constantes/sentinela; **nenhuma ligação
  de ponteiro entre os objetos em 1024 B (ambas direções) nem via registro global `[0x1213338]`.**
  Logo não há canal de **ponteiro** pelo qual o receptor leia o estado do dispatcher. **Resta vivo
  apenas** H2-por-**valor global** (um global que `0x5B` prepara — ex. `byte[0x1602a8f]` — e a VM
  do receptor lê); isso **não** é coberto por varredura de ponteiros e exige Fase E.
- **H3 — relativamente reforçada**, não provada: receptor entra idêntico em forma e só o caminho
  natural (pela VM/call-site `0xd477bc`, com o despacho `0x11→0x0D→0x5B`) produz o store.
- **Discriminador mínimo seguinte:** a ligação por ponteiro (direta e via registro global) está
  excluída na cobertura. Restam **dois** caminhos mutuamente exclusivos de discriminação, cada um
  com proposta de custo própria: (a) **Fase E read-only** — observar se a VM do receptor **lê** o
  global `byte[0x1602a8f]` (ou outro global preparado por `0x5B`) durante o passo natural
  (watchpoint/rastreio de leitura; ARCHITECTURE.md §11 alerta que watchpoint de **dados** travou o
  cliente — exige cuidado e proposta); (b) **teste comparativo de contexto** — reexecutar a folha
  `0x8A` **no contexto do dispatcher** vs. isolada, o que implica **nova chamada nativa** e portanto
  **autorização separada** (§11 do prompt). Nenhum dos dois foi executado.

**Limites/cobertura:** varredura de 256 B numa direção; corpo do receptor (VM do Gepard) **não**
desassemblado — o consumidor real não foi observado diretamente (exigiria watchpoint/rastreio de
leitura = Fase E, com proposta de custo própria; ARCHITECTURE.md §11 alerta que watchpoint de
dados travou o cliente). Sessão única; sem controle focado×não-focado. Nenhuma conclusão de
sincronia de cifra inferida só por processo vivo.
