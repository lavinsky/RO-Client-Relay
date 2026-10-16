# Pré-condições de preparação do movimento 0x035F

> **Leitura atual (pós-rodada 06b, 2026-10-15):** §§1–12 registram etapas anteriores; §13 cobre os
> ensaios nativos do dispatcher 0x11. O disasm de `uaRO.exe` mostra `0xd473b0` como `__thiscall`
> comum que termina em `ret 0x34` (13 dwords) — "VM que não retorna" está **REFUTADA quanto ao
> mecanismo estático**. A **ABI de 13 dwords ainda travava** quando disparada no `onEnter` de
> `poll/select` / pré-poll (§13.5): a correção de ABI não bastou e o desequilíbrio de 8 bytes **não
> explica sozinho** o resultado, sem refutar que a pilha importe.
>
> **Correção factual (§13.8, FATO, `relay_capture.conf:99-111`):** o `035F` é **CIFRADO** — XOR-scramble
> byte-a-byte em memória **antes** do envio. O `store_035f` em `gepard+0x18eff2` que estas sondas
> observam **é o byte-store in-place do scrambler** (`scramble-bp=18eff2`, `scramble-range=2632000-2730000`,
> `scramble-id=035f`). Qualquer leitura de `035F` como "texto claro" está **REFUTADA**.
>
> **Dependência de fase/contexto — OBSERVADA (§13.9):** disparando no `onLeave` de um `read` do
> wineserver, a chamada 04 **retornou** e chegou ao scrambler, mas congelou após o retorno; a 05
> **abortou durante a chamada** (SIGABRT). Em ambas o scrambler cifrou o corpo injetado, mas não houve
> envio. **Mecanismo do crash = HIPÓTESE, líder = reentrância Wine** (não demonstrada).
>
> **Marco (§13.10, OBSERVADO, cliente vivo):** disparando o dispatcher de um **sítio de main-loop do
> `uaRO.exe` (HW exec BP `0x4dcba0`), fora do contexto do `read`**, a chamada 06b **retornou, enviou 5 B
> (`sendmsg`), recebeu `recv_0087` com dst = destino injetado e manteve o cliente responsivo** — 1ª
> origem autônoma de `035F` ponta-a-ponta. Sustenta que o **contexto read/wineserver era a causa** dos
> crashes 04/05, mas **NÃO** prova "reentrância resolvida em geral" (o callback de HW-BP ainda é
> contexto não-natural); **reproduzida** na rodada 08 através de relogin (§13.12). H2/H3 seguem **não
> isoladas**; exclusões de §12 restritas à cobertura. Lacunas: reprodução (determinismo) e comparação
> delimitada com a via de relay (merge pré-XOR em `gepard+0x18eff2`). Nova execução ao vivo exige
> direção direta do responsável.

> **Procedência histórica:** PIDs, FDs, portas de instrumentação em loopback e caminhos externos abaixo identificam os ensaios originais; não descrevem processos vivos agora nem garantem disponibilidade dos artefatos. Nenhuma captura privada foi aberta nesta consolidação.

Investigação da preparação/contexto que antecede o store do `0x035F`, focada em
**explicar por que a tentativa de chamada nativa de `0x8A` ficou inconclusiva**.
Registra apenas conclusões e referências sanitizadas; não copia capturas cruas,
credenciais nem objetos completos.

**Proteções da build em estudo (identificadas pelo responsável
no Detect It Easy, 2026-10-15):** `uaRO.exe` contém
**Themida/WinLicense 3.XX**; `gepard.dll` contém **VMProtect**.
São os mesmos arquivos usados nas investigações atuais.
A detecção não atribui a VM de nenhuma rotina específica,
nem discrimina H2 (preparação) de H3 (contexto/callsite).
[Registro completo](PROTECTION_FINGERPRINT_DIE.md).

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
| **H2 — Bypass da preparação de estado** (prioritária nessa etapa; atualizada em §12) | `0x11/0x0D/0x5B` escrevem 5+ campos no objeto do dispatcher antes do `0x8A`; leaf sozinho não armazena/envia (6.4) | nenhum consumidor dessas escritas ainda identificado no receptor | leitura delimitada desses campos dentro do receptor na execução natural |
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

> **Arquitetura (docs/HISTORY/ARCHITECTURE_LEGACY.md §10; `relay/writeback.py:1-8`):** o relay já injeta `035f`
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
  registradores de depuração pode travar o cliente — docs/HISTORY/ARCHITECTURE_LEGACY.md §11); escolha de destino
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
investigação, `observe_path.py`/`native_trial.py`/`analyze.py`, `docs/HISTORY/ARCHITECTURE_LEGACY.md` §§9–11.
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
pequenas) — docs/HISTORY/ARCHITECTURE_LEGACY.md §11 admite "leituras fixas pequenas no agente". Sem escrita, sem
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
`push 0x8a; push edi(x); push [ebp-0x24] /* y */; push 0; push 0` — **exatamente** `(0x8A,x,y,0,0)`,
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
  (watchpoint/rastreio de leitura; docs/HISTORY/ARCHITECTURE_LEGACY.md §11 alerta que watchpoint de **dados** travou o
  cliente — exige cuidado e proposta); (b) **teste comparativo de contexto** — reexecutar a folha
  `0x8A` **no contexto do dispatcher** vs. isolada, o que implica **nova chamada nativa** e portanto
  **autorização separada** (§11 do prompt). Nenhum dos dois foi executado.

**Limites/cobertura:** o primeiro ensaio cobriu 256 B numa direção; a extensão `walk3/4` cobriu 1024 B em ambas as direções e 128 B do registro global, conforme acima. O corpo do receptor (VM do Gepard) **não**
desassemblado — o consumidor real não foi observado diretamente (exigiria watchpoint/rastreio de
leitura = Fase E, com proposta de custo própria; docs/HISTORY/ARCHITECTURE_LEGACY.md §11 alerta que watchpoint de
dados travou o cliente). Resultados restritos às janelas/sessão reportadas; sem controle focado×não-focado. Nenhuma conclusão de
sincronia de cifra inferida só por processo vivo.

## 13. Ensaio nativo do dispatcher 0x11 — leitura corrigida: ABI incompleta, não "VM sem retorno"

Experimento autorizado (chamadas nativas + tolerância a queda do cliente). Ferramenta:
`research/movement_035f/dispatcher_trial.py`. Em vez da folha `0x8A` (insuficiente, §5/6.4),
chama o **dispatcher `0xd473b0`** (em `uaRO.exe`, ImageBase 0x400000, base fixa — não ASLR)
com a ABI que então se supunha: `this`=ecx (objeto capturado de um passo natural), pilha
`(u32 0, u64 0x11, u64 x, u64 y, u64 0, u64 0)`. O `this` é de heap (sem âncora global): é
**capturado de um passo natural** e reusado na mesma sessão; a chamada dispara UMA vez no dreno
main-thread, ~após a captura, para `coord_capturada + (4,0)`. Sessões: PIDs 3240424/3266070/3267651
(relogados), build re-conferido (hashes iguais; `sha256(uaRO.exe)=f2f2…9569`).

### 13.1 ABI real do dispatcher (OBSERVADO — disasm estático de `uaRO.exe`, build f2f2…9569)

Desassemblagem estática offline de `uaRO.exe` (seção 0, VA 0x401000, raw 0x800; `objdump -b binary
-mi386`), confrontada com os dumps ao vivo. O dispatcher `0xd473b0` é uma **função nativa comum
`__thiscall`**, não uma VM/threaded-code:

- Prólogo MSVC com SEH e stack cookie: `push ebp; mov ebp,esp; push -1; push 0xf312d5;
  mov eax,fs:0; … ; mov eax,ds:0x122b924; xor eax,ebp; mov [ebp-0x10],eax` (`0xd473b0`–`0xd473d5`).
- `mov ebx,ecx` (`0xd473db`): **`ebx = this`** (thiscall confirmado).
- Lê args em `[ebp+0x8]`, `[ebp+0xc/0x10]` (code 64-bit — `test eax,eax` exige high=0),
  `[ebp+0x14]`=x (edi), `[ebp+0x1c]`=y, e demais dwords até `[ebp+0x38]`.
- Switch por tabela: `cmp edx,0x95; ja default; movzx eax,[edx+0xd47ebc]; jmp [eax*4+0xd47e64]`
  (`0xd47439`–`0xd47440`). **code `0x11` → índice 7 → caso `0xd476e5`.**
- Todos os casos convergem para `jmp 0xd47e46` (epílogo único). Epílogo (`0xd47e46`–`0xd47e61`):
  restaura SEH/`fs:0`, `pop ecx/edi/esi/ebx`, checa cookie (`call 0xdbbbd4`), `mov esp,ebp; pop ebp;`
  **`ret 0x34`**.

> **`ret 0x34` = 52 bytes = 13 dwords de argumentos de pilha, limpos pelo callee (thiscall).**
> A `NativeFunction` usada (`['pointer', u32, u64, u64, u64, u64, u64]`) empilha apenas
> **44 bytes (11 dwords)** de args. **Faltam 8 bytes (2 dwords: `[ebp+0x34]`/`[ebp+0x38]`).**
> Logo, ao executar `ret 0x34`, `esp` retorna **8 bytes acima** do esperado pelo trampolim Frida:
> **desequilíbrio de pilha na volta** — violação de disciplina de pilha, não "VM que não retorna".

**Caso `0x11` (`0xd476e5`):** `push 0×11; push 0xd; push 0; call [eax+0x8]` (sub-rotina `0x0D`);
depois ramifica por `[ebx+0x70]` (∈{2,5,6} → grava `[ebx+0x510]=1`, `[ebx+0x534]=edi(x)`,
`[ebx+0x538]=y`; senão grava `[ebx+0x510]=0`, `[ebx+0x534]=[ebx+0x538]=0xffffffff` e
`push 0×5b; … call [esi+0x8]`). O caso `0x5B` separado (`0xd4777d`) faz
`mov byte ds:0x1602a8f,0; call [0xfc17b0]; cmp eax,[ebx+0x520]+0x15e; jbe epílogo` (porta de taxa)
e só então `push 0x8a; … call [eax+0x18]` (`0xd477bc`) — a folha `0x8A`. Campos
`+0x510/+0x514/+0x520/+0x524/+0x528/+0x52c/+0x530/+0x534/+0x538` são lidos/gravados aqui dentro
(consistente com §12: escritos pelo dispatcher, não passados ao receptor).

### 13.2 Correções à leitura anterior

1. **"Store espontâneo montado/armazenado" → superdimensionado.** O BP do store
   (`gepard+0x18eff2`, `mov [ecx],bl`) é **HW de execução**, dispara **antes** da instrução; o
   handler lê `[ecx..ecx+2]` = **conteúdo do buffer no trap**, incluindo o byte `b0` que esta
   própria store ainda vai sobrescrever (`dispatcher_trial.py:198`). Em disp2 houve UMA leitura
   com `id@[ecx-2]=0x035f` e corpo decodificado `[288,320]` (order 13), **cercada por leituras com
   `id` lixo** (534, 44398, 769, …) — o `mov [ecx],bl` é genérico e é atingido em muitos buffers.
   Portanto: **OBSERVADO** = "conteúdo de buffer compatível com um corpo `035f` para o destino
   pedido, presente no trap do store, durante a chamada"; **NÃO demonstrado** que a escrita se
   concluiu, que o pacote de 5 bytes foi finalizado, nem que seguiu adiante. A prova decisiva
   (sendmsg 5 B no fd do servidor + `recv_0087 dst`) **não ocorreu `during_call`** — ao contrário
   do fluxo natural (order 4→5→6), onde o mesmo trap pré-store traz corpo que o `recv_0087`
   posterior confirma. `destino = capturado+(4,0)` **não é** automaticamente um tile válido/andável.
2. **"Travamento intrínseco da VM / não retorna" → REFUTADO quanto ao mecanismo alegado.** Pela
   §13.1, `0xd473b0` termina em `ret 0x34` normal; `gepard+0xb2c251` é apenas **o endereço do
   chamador** (um thunk Gepard), um alvo de retorno comum — não uma "continuação de VM não
   chamável". A hipótese então levantada — travamento causado pelo **desequilíbrio de pilha de 8
   bytes** — foi **testada e REFUTADA** ao vivo em §13.5 (a chamada com ABI de 13 dwords casando
   `ret 0x34` trava igual). A rajada de stores com id lixo é **artefato de logging** (`inCall`
   emite todo hit do `mov [ecx],bl` genérico), não runaway.
3. **Desarmar HW breakpoints (disp5) exclui só essa fonte.** A chamada seguia dentro de um
   callback `poll/select` via `NativeFunction`, com hooks `Interceptor` (sendmsg/recv) ainda ativos
   (`dispatcher_trial.py:218`). **REFUTADA** apenas a explicação "exclusivamente pelos HW BPs".
   **Reentrância** (chamar de dentro do dreno main-thread) permanece **hipótese aberta**, não
   excluída, e distinta do desequilíbrio de pilha.
4. **Coordenadas corretas validam só o encaminhamento de args, não a ABI inteira.** Preservação de
   registradores (o callee salva/restaura ebx/esi/edi), disciplina de pilha e retorno continuam
   relevantes justamente porque a chamada não concluiu.

**H2 vs H3:** trocar folha→dispatcher muda **preparação e contexto juntos**; o resultado **não
isola H2 de H3** nem comprova necessidade individual de cada uma. O consumo de estado/global pelo
receptor segue **NÃO VERIFICADO**; a cobertura de ponteiros de §12 não é ampliada.

### 13.3 Classificação da falha capturada (disp2 × disp5 — condições DISTINTAS, não combinar)

- **disp2** (`/tmp/claude-035f-…-134442-disp2/`, HW BPs armados durante a chamada): após `emit_call`
  → `receptor_0x8a[288,320]` + rajada de `store_035f` (order 9–16, ~1 ms), **sem `emit_return`,
  sem sendmsg/recv `during_call`**, depois silêncio até TIMEOUT; `cleanup_error: script destroyed`.
- **disp5** (`/tmp/claude-035f-…-135147-disp5/`, TODOS os HW BPs desarmados antes da chamada): após
  `emit_call` **nenhum evento** (observação dos 3 BPs desligada); o hook `sendmsg` seguia armado e
  **não** registrou envio `during_call`; TIMEOUT; `cleanup_error: script destroyed`.

Sem `emit_error` (o `try/catch` com `exceptions:'propagate'` emitiria em exceção JS capturável) e
sem `emit_return`. **Não atribuível a exceção capturada nem a retorno normal.** Distinguir
exceção nativa × loop × bloqueio × término externo **exige coleta adicional** (abaixo); a ausência
de `emit_return` isolada **não** prova "VM". O teste de §13.5 **excluiu** o desequilíbrio de pilha;
sem exceção capturável, resta **bloqueio ou loop**, com **reentrância** como hipótese principal.

### 13.4 Intervenção fundamentada (EXECUTADA em §13.5 — proposta original mantida para registro)

Antes de qualquer nova chamada nativa, **confirmar comigo a janela exclusiva** (cliente relogado +
foco). Intervenção proposta, com a ABI corrigida:

1. Num passo natural de `0x11`, capturar o **frame completo de 13 dwords** (`[esp+4 .. esp+0x34]`)
   além de `this`(ecx) — não só code/x/y.
2. Replicar a chamada como **`__thiscall` com exatamente 13 args u32** (casando `ret 0x34`),
   reusando os 13 dwords naturais e **alterando apenas x (`[ebp+0x14]`) e y (`[ebp+0x1c]`)** para um
   tile comprovadamente adjacente/andável; `this` = objeto natural capturado.
3. **Discriminadores de falha** a instrumentar na mesma rodada: BP no endereço de retorno do
   trampolim (detecta retorno vs. não-retorno), handler de exceção registrando tipo+endereço de
   falha, e um contador para distinguir loop de bloqueio.

**Critério de sucesso (todos):** `emit_return` (retorno normal) · `store_035f` com corpo correto
`during_call` · `sendmsg` de 5 B no fd do servidor `during_call` · `recv_0087` com `dst` = destino ·
**cliente permanece responsivo**. Falha de qualquer item mantém a hipótese de reentrância como
próximo discriminador. **Não repetir a chamada idêntica sem um discriminador novo.**

**Objetivo de andar autônomo (§ legacy):** ainda **não** alcançado de forma limpa. O disasm estático
mostra que `0xd473b0` **tem** um `ret 0x34` normal (§13.1), mas **ao ser chamado o retorno não foi
observado** (§13.5) — não afirmar que "retorna normalmente" nem que "faltava só a ABI correta".
Alternativa conservadora permanece o merge **reativo** no store (§10 do legacy), com a limitação "só
reage a um clique".

**Verificações/limpeza:** eventos em streaming (sobrevivem ao freeze) + escrita incremental;
limpeza de HW breakpoints idempotente e **limitada** (cliente pode travar); artefatos externos
sanitizados (`/tmp/claude-035f-*-disp*/` e disasm em `…-abi2/`, não versionados). `ydotoold`
(uinput) encerrado a cada run. Cliente derrubado nos ensaios de chamada (autorizado; relogin
trivial). **Watchpoint do flag `0x1602a8f` (Fase E) NÃO executado** — não discriminante agora;
hipótese do global permanece aberta, retomável se a evidência apontar para ela.

### 13.5 EXECUTADO (vivo, janela exclusiva confirmada) — ABI de 13 dwords: hang persiste; imbalance não explica sozinho

Ferramenta: `research/movement_035f/dispatcher_trial13.py` (nova; `dispatcher_trial.py` preservado).
`NativeFunction` `__thiscall` com **13 args u32** (= `ret 0x34`), captura do **frame natural
completo de 13 dwords** + `this`, replay alterando só x/y. PID 3284268 (relog), build re-conferido
MATCH; checagem em runtime de `ret 0x34` em `0xd47e61`. Artefato: `/tmp/claude-035f-…-abi13/`.

- **OBSERVADO:** o frame natural de `0x11` é **`[0, 0x11, 0, x, 0, y, 0,0,0,0,0,0,0]`** — os 7
  dwords finais são **zero**. Logo o ensaio anterior (11 dwords) tinha os **valores corretos**; só
  faltavam 8 bytes de pilha. O ensaio atual empilha os 13 (casando `ret 0x34`).
- **OBSERVADO:** a chamada **entrou** no dispatcher (`dispatcher_0x11[278,318]`,
  `return_addr=0xf69ed758` = trampolim Frida, região `other`, `during_call=true`), executou
  `receptor_0x8a[278,318]` e, **no trap pré-store**, o buffer já tinha um corpo `035f` decodificando
  para `[278,318]` — cercado por hits do `mov [ecx],bl` genérico (artefato de `inCall`). **A
  montagem completa do pacote e a transmissão continuam NÃO demonstradas.**
- **OBSERVADO:** **nenhum `emit_return`, nenhum `native_exception` registrado, nenhum
  `sendmsg`/`recv_0087` `during_call`**; o cliente **congelou** (relogin). Assinatura igual a
  disp2/disp5.

**Conclusões (cuidado epistêmico):**
1. A correção de **11→13 dwords não resolveu** o travamento: a falta de 8 bytes **não explica
   sozinha** o resultado. O desequilíbrio de pilha deixa de ser a explicação suficiente; não é uma
   prova de que a pilha é irrelevante, apenas de que corrigi-la não bastou.
2. **Nenhuma exceção foi registrada** pelo nosso handler durante a chamada. Isso **não refuta**
   exceção nativa em geral: o handler pode não ter rodado, ou a falha pode ocorrer fora do seu
   alcance. Fica **NÃO VERIFICADO** se há exceção; o diagnóstico atual não distingue exceção de
   bloqueio/loop (ver §13.6).
3. **OBSERVADO:** um corpo `035f` para o destino pedido aparece no trap pré-store ao entrar pelo
   dispatcher. **NÃO demonstrado:** conclusão da escrita, montagem do pacote de 5 bytes, retorno e
   transmissão.
4. **Correção factual:** a chamada é feita no **`onEnter` de `poll/select`**, ou seja **antes** de
   `poll` executar — a main thread **não** está "parada dentro do poll", está no **limiar** do poll.
   A hipótese correta é **dependência do contexto/fase de execução do laço** (chamar a lógica de
   movimento numa fase do laço onde ela não é esperada); "reentrância no poll" é apenas um caso
   particular ainda **sem evidência direta**.

**Próximo passo:** ver §13.6 (ponto escolhido + diagnóstico de falha) — preparado, não executado.

### 13.6 Próximo experimento, mais discriminante (PREPARADO; exige janela exclusiva + destino validado)

> **Nota de instrumentação (§13.7, 2026-10-15).** `loop_map.py` (Stalker) e o disparo por
> `Interceptor.attach` no `--fire-at` **continuam válidos**. A verificação de integridade do Gepard é
> **byte a byte** (FATO, confirmado pelo responsável; comportamento canônico do relay — ver §13.7):
> um hook inline só a dispara se um byte patcheado coincidir com um byte verificado (azar pontual =
> INFERIDO); `Stalker` e **hardware breakpoints** não são detectáveis por ela. Para um único ponto
> sensível, um HW BP de execução elimina esse risco pontual. Ver §13.7.

Objetivo: **explicar a falha mesmo que não ande.** Uma tentativa por condição, **sem retry
automático**. Ferramentas preparadas (não executadas): `research/movement_035f/loop_map.py`
(read-only) e `research/movement_035f/dispatcher_trial_ctx.py` (chamada parametrizada por ponto).

**(a) Seleção do ponto de disparo — por observação natural (read-only), 1ª etapa da janela.**
Não basta trocar `onEnter`→`onLeave` do poll. `loop_map.py` faz um censo com **Stalker** na main
thread (id == `Process.id`) por uma janela curta entre dois limiares de `poll/select`, e elege um
**call-site estável em `uaRO.exe` (base fixa)** que satisfaça TODOS:
- **thread:** é a main thread (mesmo TID que executa o dispatcher natural);
- **frequência:** recorre ~1×/frame (ordem do laço), medida;
- **contexto:** ocorre **depois** do retorno do poll e **antes** do próximo poll;
- **fora de movimento:** a pilha no momento **não** contém `0xd473b0`/receptor/`0x0D`/`0x5B`;
- **estável:** endereço fixo (uaRO não-ASLR), reusável na mesma sessão.
O endereço eleito é relatado com as evidências acima **antes** de qualquer chamada.

**(b) Chamada — comparável à de §13.5.** Mesma ABI (13 dwords u32, `ret 0x34`), **mesma identidade
de objeto validada** (`m.add(0x58)==1`, receiver == `gb+0x10a90`, `this` natural capturado), mesmos
args (frame natural, trocando só x/y), mesma instrumentação de observação. Disparo via
`Interceptor.attach` **one-shot** no ponto eleito (não no boundary do poll). **Destino = tile
validado com o responsável** (não `capturado+4`).

**(c) Diagnóstico de falha independente do callback JS que faz a chamada.** Como a chamada bloqueia
a própria engine JS na main thread, a amostragem é feita **pelo driver Python** (processo separado),
lendo `/proc/<pid>/task/<main_tid>/{stat,wchan,syscall}` a cada ~30 ms, antes/durante/depois.
Classifica:
- **progredindo:** `state=R`, `syscall`/`wchan` variando no tempo;
- **repetição de PC / loop apertado:** `state=R`, `syscall=running` (userspace) persistente, sem
  `wchan` — opcional: poucas amostras de `$pc` via `gdb -p` para confirmar faixa estreita;
- **espera/bloqueio:** `state=S/D`, `wchan` = `futex`/`poll`/`read`… (espera identificável);
- **exceção/término:** thread/processo `Z` ou ausente;
- **perda do próprio observador:** sessão Frida caiu mas processo vivo e main thread normal.
**Não** concluir deadlock só pelo silêncio dos logs.

**(d) Janela de observação após o retorno (não exigir envio during_call).** O dispatcher pode
**enfileirar** trabalho e retornar antes do transporte. `dispatcher_trial_ctx.py` mantém os hooks de
transporte/`recv` armados por `--post-ms` após `emit_return`, marcando `sync` (during_call) vs
`post_return` (após), com associação independente do `dst` observado ao destino pedido.

**(e) Condições que mudam inevitavelmente entre sessões (registrar sempre):** PID, base do Gepard,
endereço de heap do `this`, fd do socket do servidor, posição/zona do personagem e da janela. Build
re-conferido por hash a cada run.

**Critério de sucesso (todos):** retorno normal observado · transmissão associada ao destino (sync
ou post-return) · resposta correspondente (`recv_0087 dst`) · **cliente responsivo** depois.
**Classificação:** se funcionar no ponto pós-poll → inicialmente **dependência do contexto/fase de
execução**; **reentrância específica no poll ainda exigirá evidência** (p.ex. variar a fase e medir).

**Condições de parada:** uma só chamada; aborta se identidade do objeto mudar antes do disparo;
timeout curto; limpeza idempotente de BPs/hooks; `ydotoold` encerrado; relogin aceito se cair.

### 13.7 Evento de integridade do Gepard (azar pontual de um hook inline) — natureza byte a byte

**OBSERVADO (2026-10-15).** Durante a 1ª etapa de §13.6 (eleição do ponto pós-poll), rodei um probe de
census NOVO, `elect_firesite.py`, que colocou **10 hooks `Interceptor.attach` inline em endereços de
código do `uaRO.exe` de uma só vez**. Logo em seguida o responsável reportou **"Memory integrity test
failed, gepard noted"** e o processo do cliente (PID 3286648) **encerrou**. Nenhuma chamada nativa
chegou a ser disparada. (O probe só registrou `frames`, `hits` e backtraces dos 10 sites; não
identificou **por instrumento** qual byte o Gepard lê.)

**FATO (confirmado pelo responsável; comportamento canônico do relay).** A verificação de integridade
do Gepard é **byte a byte**: lê byte(s) específicos do próprio código do cliente e compara com o
esperado. Um hook inline (`Interceptor.attach`, que reescreve bytes no alvo) só dispara a verificação
**se um dos bytes patcheados coincidir com um byte verificado** — azar num site específico, **não**
uma propriedade de hooks inline em geral. Isto está consolidado no caminho de **produção** do relay:
o merge do 035f usa um **breakpoint de EXECUÇÃO em registrador de depuração (DR0)** sobre o store do
scrambler e roda no cliente do responsável sem disparar o check — ver a função de scramble em
`agent/relay_hook_linux.js:224-233` e `:518`, `relay/writeback.py:4-6`, e `relay_capture.conf:99-111`
(`scramble-bp=18eff2`). Memória do projeto: [[gepard-integrity-check-bytes]].
- **INFERIDO:** com 10 hooks de uma vez, um caiu num byte verificado. O instrumento não identificou o
  byte; a base direta é o relato + a natureza byte-a-byte canônica.
- **`Stalker` NÃO é detectável** por esse check: executa uma **cópia relocada** do código, deixando os
  bytes originais intactos (o checksum do original passa).
- **Hardware breakpoints (DR0–DR3) NÃO alteram byte algum** (footprint zero) e são o mecanismo do
  próprio merge de produção. **Caveat de código:** o comentário em `agent/relay_hook_linux.js:232`
  registra que um registrador de depuração "may be detected" em geral — por isso o uso fica restrito
  ao cliente do responsável; na prática o caminho DR0 do merge não dispara a checagem byte-a-byte.
- O projeto **`gepardbypass`** (GitHub) trata de verificações desse tipo (referência externa).

**Não detectado (contraste).** O ensaio estabelecido `dispatcher_trial13.py` (§13.5) rodou **sem**
flag: observa por `th.setHardwareBreakpoint` (HW BP, sem patch) e só faz `Interceptor.attach` em
**exports da libc** (send/recv/poll) — nunca em código do uaRO/gepard. (A nota
[[no-hw-watch-on-stack-walk-slot]] — crash de um *data watchpoint* num slot de pilha reescrito a cada
frame — é caso específico, NÃO evidência contra HW breakpoints de execução em geral.)

**Correção de uma super-generalização minha.** Cheguei a tratar o evento como "hooks inline / Stalker
em código do cliente são detectados" e a desaprovar o Stalker / forçar só-HW-BP — **errado**, corrigido
pelo responsável. `Interceptor` e `Stalker` seguem utilizáveis em código do cliente; o único risco é um
hook inline cujo byte patcheado seja justamente um verificado.

**Implicação prática (o desenho de §13.6 fica como está):** para um **único ponto sensível/de alto
valor** (p.ex. o `--fire-at` do `dispatcher_trial_ctx.py`), um **HW BP de execução** elimina o risco
pontual sem custo. Para census amplo (`loop_map.py`), `Stalker` é seguro. Não repetir o padrão de
muitos hooks inline simultâneos em código do cliente sem necessidade (maximiza a chance de azar).

**Consequência para §13.5:** o resultado anterior (ABI de 13 dwords ainda trava, disparo no `onEnter`
de poll via export da libc) **mantém-se válido como OBSERVADO** — aquele método não foi detectado.

**Pendências humanas antes do próximo vivo:** relogin do cliente (novo PID); confirmação de que o
evento "noted" não penalizou a conta/servidor do responsável; janela exclusiva; destino validado na
nova posição (o `(278,316)` combinado antes vale só se o personagem ainda estiver em `(274,316)`).

### 13.8 CORREÇÃO: o 035F é CIFRADO; `store_035f` = byte-store do scrambler

**FATO (confirmado pelo responsável; validado por `relay_capture.conf:99-111`).** O 035F é
**cifrado** por um XOR-scramble byte-a-byte em memória **antes** do envio; qualquer leitura de 035F
como "texto claro" está **REFUTADA**. O que as sondas de movimento chamam `store_035f` em
`gepard+0x18eff2` (`mov byte [ecx],bl`) **é o byte-store in-place do scrambler** (= `scramble-bp=18eff2`).
O cliente monta o 035F em `scramble-range=2632000-2730000`, cifra ali e envia. Isso **liga** o
`store_035f` desta investigação ao scrambler estudado em `CIPHER_INVESTIGATION.md`.

**VALIDADO (relay, `relay/writeback.py:4-6`, `relay/sendwatch.py`; função de scramble do agente em
`agent/relay_hook_linux.js:224-233` e `:518`).** A injeção de andar pelo relay = substituir o corpo
**antes do XOR** nesse store (BP exec DR0), deixando o cliente cifrar+enviar — é o caminho
conhecido-correto do merge reativo (`inject=true`/`inject-call=true`). A transformação FINAL do 035F
é um **XOR in-place byte a byte** (FATO/OBSERVADO na implementação do relay); as operações que
**antecedem** o XOR (fluxo de chave, estado, inicialização) continuam essencialmente **DESCONHECIDAS**
(ver `CIPHER_INVESTIGATION.md`).

### 13.9 Rodada 04/05 — dependência de fase de execução (OBSERVADO)

**Correção de âncora (OBSERVADO, census read-only 5 s).** O cliente é **Wine**: a main thread drena
o wineserver por `read` (~1308/5 s) e `writev`, quase não usa libc `poll` (2/5 s). A âncora `poll`
nunca disparava por isso; corrigida para `read` onLeave (fronteira pós-espera real da main loop).

**Rodada 04 (delay 700 ms, `read` onLeave).** A chamada 13-dword **RETORNOU** (`emit_return`
retval=1010077) e chegou ao scrambler (`store_035f` id=0x35F, dest injetado, during_call), mas
**sem** `sendmsg`/`recv_0087` e o cliente **congelou após o retorno**. Contraste com §13.5 (poll
onEnter / pré-poll: congelava DENTRO, sem retorno).

**Rodada 05 (delay 2 s, `read` onLeave).** Modo de falha diferente: `native_exception type="abort"`
(SIGABRT, `pc=vdso`) **durante** a chamada, também após o scrambler cifrar o corpo. Manifestações
distintas (freeze × abort), **causa provável a mesma**.

**Classificação.** Dependência de fase/contexto = OBSERVADA. **Mecanismo do crash = HIPÓTESE,
líder = reentrância Wine** (chamada de lógica PE de dentro do `onLeave` de um `read` = pump do
wineserver); flush pós-dispatcher pulado é alternativa. Não demonstrado como mecanismo.

### 13.10 Rodada 06b — MARCO: origem autônoma ponta-a-ponta (OBSERVADO, cliente vivo)

**Primeira demonstração completa** de um 035F originado autonomamente que retorna, transmite, recebe
resposta do servidor e mantém o cliente vivo. PID 3338296; artefato privado
`/tmp/claude-035f-20261015-170143-round06b/trial.json` (não versionado).

**Disparo.** Dispatcher 0x11 a partir de um **sítio de main-loop do `uaRO.exe`** (HW exec BP em
`0x4dcba0`, base fixa `0x400000`), **fora** do contexto do `read` do wineserver.

**Trace OBSERVADO.** `disp_captured` passivo (code120, `this_ecx=0x28c7b158`) → `emit_call`
dest `[273,313]`, frame `[0,17,0,273,0,313,0×7]` → **`sendmsg` fd195, 5 B, during_call** →
**`emit_return` retval=215959 (sem exceção)** → **`recv_0087` src `[273,314]` dst `[273,313]` =
destino injetado** → cliente state S, vivo/estável.

**4 critérios:** retorno SIM / envio 5 B SIM / `recv_0087` dst=destino SIM / responsivo SIM → **PASSOU.**

**Diagnóstico da 06 (que não disparou):** bug de guard (no modo `--construct-frame` o `capFrame` é
`null` de propósito; o guard exigia `!=null`). Corrigido. **Não** era slot/threading de HW BP.

**Classificação (limite preservado).** Sustenta que **o contexto read/wineserver era a causa** dos
crashes de §13.9 (r04 freeze, r05 abort). **NÃO** se afirma "reentrância resolvida em geral": o
callback de HW-BP ainda é contexto não-natural. **Cobertura/perda:** os BPs foram desarmados em
`doFire`, então o `store_035f` do scrambler **não** foi observado during_call nesta rodada —
origem+cifra+envio ficam provados **funcionalmente** pelo `sendmsg` 5 B + `recv_0087` dst=injetado
(servidor aceitou, cliente seguiu vivo), não pela observação do store.

**Consequência.** Existe agora uma **primitiva nativa de andar autônomo** disparável de um sítio de
main-loop — relevante ao objetivo xKore 0. **Lacunas abertas:** reprodução (determinismo, 1×) e
comparação delimitada com a via de relay (merge pré-XOR em `gepard+0x18eff2`, §13.8). Ambas exigem
direção direta do responsável para nova execução ao vivo.

### 13.11 Rodada 09 — PoC do relay: `035F` do OpenKore → dispatcher nativo (OBSERVADO live, cliente vivo)

**Marco de integração.** A primitiva nativa de §13.10 foi **integrada ao relay/agent de produção** e
dirigida pelo **OpenKore de ponta a ponta**: quando um `035F` (CZ_REQUEST_MOVE) chega do consumidor
pelo enquadramento XKore `S`, o relay **extrai o destino `x,y` e aciona o dispatcher nativo** do
cliente; o próprio cliente monta, cifra e envia seu `035F`, e o servidor responde `0087`. **O relay
não fabrica corpo cifrado nem reencaminha o `035F` original** — ele é dropado (preserva a política de
não forjar corpo decifrado e a identidade da conexão).

**Procedência.** OBSERVADO **uma vez**, live, **2026-10-16**. Build: `uaRO.exe`
`f2f2…9569` (§anchor em `docs/MOVEMENT_035F_PRECONDITIONS.md`), `gepard.dll` base `0x76920000`
(hash em `docs/CIPHER_INVESTIGATION.md`); cliente uaRO PID 3520569 porta 27053 (Wine); OpenKore
`perl openkore.pl` em container podman, XKore 1 porta 2350. Servidor emulador **próprio do
responsável** (escopo autorizado). Mudanças de código em **working tree, não commitadas** no
momento do registro.

**Caminho no código (OBSERVADO — leitura estática do checkout):**
- Roteamento: ramo `WALK_ID` em `relay/writeback.py:243` — `if pid == self.WALK_ID and md:` decodifica
  `payload[2:5]` via `unpack_move` e chama `post_move_dispatch(x, y)`; o `035F` original **não** é
  reenviado (`relay/writeback.py:249`). Sem `--move-dispatch`, o ramo legado de merge pré-XOR
  (`:250`) é preservado.
- Decoder: `relay/packets.py:119` `unpack_move` (inverso de `pack_move:112`; round-trip testado).
- Mensagem Python↔Frida: `relay/protocol.py:106` `move_dispatch_msg`; armar/postar em
  `relay/writeback.py:197,205`.
- Agent: bloco `native-dispatch` com `MD_RECIPES['walk-035f']` (`agent/relay_hook_linux.js:647-752`,
  dispatcher `0xd473b0`, fire-site `0x4dcba0`); captura passiva do `this` + fire-site em `mdTrap`
  (`:435`). Receita validada originalmente pelo MOVER (`research/movement_035f/dispatcher_trial_pesite.py`).

**Orçamento de debug registers (restrição OBSERVADA — x86 = 4 HW BP):** DR0 scramble (`--inject`) ·
DR1 SendPacket (`--inject-call`) · DR2 captura passiva do `this` do dispatcher · DR3 fire-site
`0x4dcba0`. O **`send-watch` precisa ficar OFF** (`--no-send-watch`), senão não há slot livre. HW
**exec** BP em código (não o watchpoint de DADOS no slot de pilha do walk, proibido por memória do
projeto).

**Gotcha corrigido (OBSERVADO offline + confirmado live).** `move_dispatch` **soma** ao
`inject-call`, não o substitui. Na versão inicial os dois eram mutuamente exclusivos no `_arm`
(`if/elif`): sem `--inject-call`, o relay **dropava todo pacote não-`035F`** do consumidor e
`sendcall_rva` nunca era setado, e o OpenKore travava no ciclo "Aguardando…/pronto" sem sincronizar.
Corrigido em `relay/writeback.py:101-107`: sob `move_dispatch`, `sendcall_rva` é setado quando
`inject_call` está on (as demais ações seguem pelo client SendPacket na DR1).

**Invocação que funciona (rodada manualmente pelo responsável):**
`./run.sh --inject --inject-call --move-dispatch --no-send-watch --out <ARQUIVO>` (criar o diretório
de saída antes; `--out` exige **arquivo**, não diretório — `IsADirectoryError` se for pasta).

**Sequência live OBSERVADA.** relay conecta no XKore 2350 (OpenKore para de ciclar) → andar 1× no
cliente captura o `this` do dispatcher (`disp_captured`) → OpenKore emite walk → `035F → native
dispatch to (x,y); original dropped` → cliente monta/cifra o próprio `035F` → `recv_0087 dst =
destino` → **cliente VIVO**. Os 4 critérios de §13.10 (retorno/envio/`recv_0087` dst=destino/
responsivo) = SIM.

**Classificação e limites.** **OBSERVADO** uma vez, dirigido por OpenKore (difere de §13.10, que
disparava de um harness de pesquisa). **NÃO** eleva a cifra a "compreendida": o relay continua sem
conhecer a geração de keystream — só decide o destino e aciona o código nativo (§13.8 segue o
DESCONHECIDO anterior ao XOR). **Lacunas:** reprodução/determinismo em várias sessões; recaptura
obrigatória do `this` por sessão (relogin invalida PID/base/heap); comparação de custo/robustez com
a via de relay (merge pré-XOR) ainda pendente. Verificações offline que acompanham:
`bash scripts/test-offline.sh` ALL PASS; `python3 scripts/validate-research.py` PASS (ver
[RESEARCH_EVIDENCE_INDEX](RESEARCH_EVIDENCE_INDEX.md) M-12).

### 13.12 Rodada 08 — reprodução da 06b através de relogin (OBSERVADO, cliente vivo)

**Fonte:** MOVER-20261016-08 (`research/movement_035f/HANDOFF.md`, `STATE.md`). Revisão `4d0b787` +
diffs locais; autorização direta do responsável; sonda e sítio idênticos à 06b
(`dispatcher_trial_pesite.py`, HW exec BP `0x4dcba0`). Nova sessão: PID 3520569, build MATCH.
Artefato privado `/tmp/claude-035f-20261016-014857-repro06b/trial.json`.

- `disp_captured` passivo code=120, **`this_ecx=0x28c95668`** (≠ `0x28c7b158` da 06b → heap por sessão;
  a captura passiva funciona após relogin).
- `emit_call` dest [273,314], frame `[0,17,0,273,0,314,0×7]` @711 ms → `sendmsg` fd196 5/5 B
  during_call @713 ms → `emit_return retval=12809` sem exceção @713 ms → `recv_0087 src=[273,313]
  dst=[273,314]` @970 ms (src = tile real informada pelo responsável).
- Cliente vivo (state R). **4 critérios = SIM.**

**Classificação:** OBSERVADO — a 06b reproduz com PID/heap/destino diferentes. Mesmos limites da
§13.10: BPs desarmados antes da chamada, store do scrambler não observado during_call; não prova
"reentrância resolvida em geral". A reprodução vale para a **sonda PE**, não para o PoC relay §13.11.
Conferência documental dos dois `trial.json`: [RESEARCH_STATUS M-13](RESEARCH_STATUS.md#m-13--reprodução-08-e-lições-do-contexto-de-disparo).

### 13.13 A primitiva do fire-site não transfere para a perícia (ACT-20261016-01, OBSERVADO)

O mesmo mecanismo (captura passiva do `this` + `thiscall` ao dispatcher `0xd473b0` a partir de
`0x4dcba0`) foi aplicado à cadeia de cast observada `0x29 → 0x5a → 0x2a` (perícia `0438`). Com
allowlist estrita, as três chamadas retornaram (`0x2a`→**0**), **nenhum `0x0438` saiu** e o cliente
**crashou de forma deferida**. Diferença estrutural OBSERVADA: `0x11` carrega X,Y no frame e comete
sozinho; `0x28`/`0x2a` não levam argumentos e leem estado global preparado pelo caminho de input
natural. Logo, o sucesso de §§13.10–13.12 **não** generaliza para ações/perícias; a pré-condição do
`0x2a` segue **NÃO VERIFICADA**. Detalhes e mapa code→pacote em
[GEPARD_CONTROL_PACKETS](GEPARD_CONTROL_PACKETS.md#mapa-dispatcher--pacote-de-ação-act-20261016-01).

---

_Integração §13.8–§13.10 incorporada a partir dos HANDOFFs MOVER-20261015-01..07
(`research/movement_035f/HANDOFF.md`) e do `research/DOCUMENTADOR_BACKLOG.md`. §13.11 registra o PoC
de integração do relay (sessão OrquestradorCLAUDE, 2026-10-16); §13.12 vem de MOVER-20261016-08 e
§13.13 de ACT-20261016-01 (`research/action_0437_0438/`). Fonte viva nos artefatos privados
citados; classificação segundo `docs/AGENTS.md` §3.2._
