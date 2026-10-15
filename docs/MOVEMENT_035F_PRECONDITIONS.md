# Pré-condições de preparação do movimento 0x035F

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
