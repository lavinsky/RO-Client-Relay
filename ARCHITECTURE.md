# Arquitetura: depuração do cliente uaRO

Mapa técnico da ferramenta e das descobertas sobre o cliente uaRO (RO sob Wine/Proton,
32 bits). O objetivo é **observar e depurar** o fluxo de pacotes do cliente: reconstruir o
fluxo em texto claro para um consumidor (p.ex. OpenKore em XKore 1) e, de forma opcional e
voltada a teste num servidor próprio, **reenviar** pacotes vindos do consumidor fazendo o
próprio cliente montá-los e cifrá-los. Tudo aqui é depuração de um cliente que se controla.

Este documento deve bastar para retomar o trabalho noutra conversa: além da arquitetura,
reúne as descobertas de engenharia reversa (endereços, caminhos de envio, o estado da
cifragem) e as pendências.

---

## 1. Visão geral

Dois programas cooperam:

| Programa | Onde roda | Função |
|---|---|---|
| **Agente**, `relay_hook_linux.js` | dentro do processo do jogo, via Frida Gadget | Observa cada leitura/escrita de socket (hooks de `recvmsg`/`sendmsg` da libc). Opcionalmente copia a região de recepção, acompanha a fila de envio, e executa as ações de pesquisa/escrita que o driver pedir. Faz o mínimo dentro do jogo. |
| **Driver**, `relay_capture_linux.py` → pacote `relay/` | processo Python normal, fora do jogo | Recebe os relatos do agente, monta um fluxo ordenado de pacotes em texto claro, preenche os poucos trechos cifrados lendo as cópias já decifradas da memória do cliente (`/proc/<pid>/mem`, somente leitura), e entrega ao consumidor. |

```
 processo do jogo (Wine)                 driver (Python)                       consumidor
 ┌─────────────────────┐  mensagens Frida ┌───────────────────────────────┐ TCP ┌─────────┐
 │ hook recvmsg/sendmsg ├─────────────────►│ Agente → fila de trabalho     │     │ XKore 1 │
 │ cópias da ring       │                  │ worker: Capture.dispatch      ├────►│ :2350   │
 │ acompanha a fila     │◄─────────────────┤ WireFeed / ClientSendFeed     │ R/S │         │
 └─────────────────────┘ ring/sendwatch/   │ thread alimentadora → Relay   │frames└─────────┘
          ▲               scramble/sendcall └───────────────┬───────────────┘
          │        /proc/<pid>/mem (somente leitura)        │
          └─────────────────────────────────────────────────┘
```

Por padrão o driver **não escreve** no jogo e nada do que produz chega ao servidor; o que o
consumidor devolve é lido e descartado. As opções de **escrita** (§6) são o oposto: fazem os
pacotes que o consumidor devolve (quadros XKore "S") saírem pelo cliente. São para um
cliente/servidor que você controla, e ficam desligadas a menos que pedidas.

`relay_capture_linux.py` é só o ponto de entrada; reexporta nomes antigos para os testes.

A ligação é via **Gadget** (`LD_PRELOAD`), não ptrace: dar ptrace num Proton 32 bits derruba
o processo (o handler de SIGSEGV do Wine morre no `%gs` TLS zerado).

---

## 2. O agente (`relay_hook_linux.js`)

Um arquivo só (o Frida carrega um script). Seções, de cima para baixo:

| Seção | O que faz |
|---|---|
| hex | Bytes → hex por tabela; lê o id do pacote dos 2 primeiros bytes. |
| sockets | `peerOf(fd)`: qual servidor (`ip:porta`) e qual conexão (porta local) um socket é. Reconsultado sempre que importa, porque o Wine reusa números de socket entre login/char/mapa. `libcFns`, `iovs`, `hookAll`. |
| ring de recepção | O driver avisa onde está a região de recepção (`{type:'ring'}`). **hook recvmsg**: na entrada manda uma **RINGSNAP** (cópia tirada antes do próximo trecho chegar); na saída manda **RECV** com os bytes e uma cópia de *antes* de o cliente decifrar. |
| acompanhamento da fila | Desligado até o driver pedir (`{type:'sendwatch'}`). Mantém os 4 registradores de depuração sobre a próxima posição da fila; `swTrap` registra cada escrita. Recupera o texto claro de `0437`/`0438`. |
| envio | **hook sendmsg**: manda **SEND**; para envios da fila com o acompanhamento ligado, anexa a janela de escritas `W` e move o acompanhamento para `buf + len`. |
| ponto de parada da cifragem | Desligado até `{type:'scramble'}`. Um **breakpoint de execução** (DR0) sobre o *store* byte a byte da cifragem; enquanto a posição ainda tem o texto claro, o manipulador localiza a posição do pacote (por registrador nomeado, ou `reg:'auto'` casando o id) e, em modo de escrita, **substitui o corpo** — então a própria cifragem do cliente cifra os bytes fornecidos. Modos de leitura: relatório (dry), passeio de pilha (`--send-probe`), captura de argumentos na entrada (`--probe-entry`/`--probe-at`). Corpos por id chegam por `{type:'scramble-set'}`, usados uma vez ou mantidos (`persist`). Compartilha os registradores de depuração com o acompanhamento da fila (um ou outro). |
| chamada de envio (`sendcall`) | Desligado até `{type:'sendcall'}`. Captura `this` do `SendPacket` do cliente uma vez (breakpoint de hardware, sem alterar código), monta um `NativeFunction` e, para cada pacote do consumidor (`{type:'sendcall-emit'}`), chama `SendPacket(this, len, buf)` **na thread do jogo** (drenado a partir dos hooks de recv/send). |
| rastreio (Stalker) | Desligado até `{type:'trace'}`. Segue a thread principal por uma janela curta e registra chamadas (teste de sobrevivência; ou `uaRO→gepard`; ou `uaRO→uaRO`). Para achar a cadeia **viva** de chamadas (o passeio de pilha só dá quadros obsoletos). `codeRanges`/`codeAt` resolvem endereços contra as faixas mapeadas, incluindo o **código anônimo** do uaRO (ver §9). |
| log inicial | Onde `gepard.dll` está carregada; manda **GEPARD** (base) para o driver resolver `gepard+off`. |

Os campos das mensagens estão no docstring de `relay/protocol.py`.

---

## 3. O driver (`relay/`)

### 3.1 Módulos

| Módulo | Conteúdo | Quando |
|---|---|---|
| `protocol` | Tags e campos das mensagens (o contrato com o agente): `ring_msg`, `sendwatch_msg`, `scramble_msg`, `scramble_set_msg`, `sendcall_msg`, `sendcall_emit_msg`, `trace_msg`, `conn_of`. | sempre |
| `agent` | `gadget_ports`, `pick_port`, `pid_of_port`; `Agent` (conecta ao gadget, carrega o JS, repassa/posta mensagens). Único módulo que importa `frida`. | sempre |
| `cli` | Opções, leitura do arquivo de configuração (`relay_capture.conf`), tabela de tamanhos, `main` (trata `SIGTERM` para desligar limpo). | sempre |
| `runtime` | `Capture`: monta os componentes conforme as opções, inicia as threads, roteia cada mensagem (`dispatch`), mantém o acompanhamento da fila apontado, e — na escrita sem ponto de parada fixado — autodescobre a cifragem. | sempre |
| `relay` | `Relay`: enquadramento XKore, (re)conexão, `--feed-dump`. `PacketAligner`: alinhador opcional (consumidor bruto). | com `--relay` |
| `packets` | `load_lengths`, `packet_len`, `WireFilter` (divide o fluxo de cada conexão em pacotes; passa o id de conta; separa 09fd/09ff como itens a preencher). | sempre |
| `actors` | `ActorDecrypt`: acha a ring de recepção e aceita a cópia decifrada de 09fd/09ff só com prova (recente, ou contexto em volta casa); senão descarta. `valid_actor`. | `--decrypt-actors` |
| `wire_feed` | `WireFeed` (enfileira os trechos em ordem de chegada, anexa snapshots, thread alimentadora). `ClientSendFeed` (pacotes cliente→servidor). | sempre |
| `sendwatch` | `SendWatch`, `plaintext_guess`, `packet_at`, `send_queue_range`. | `--send-watch` |
| `moves` | `MoveTracker`, `unpack_pos2`, `pack_move`: decodifica o destino do movimento a partir do `0087` (texto claro) do servidor e registra (`MOVE-CHECK`); `pack_move` monta o corpo de 3 bytes de um `035f`. | sempre |
| `memory` | `/proc/<pid>/maps` (`regions`, `region_at`), `ProcessMemory.read`, `ProcessMemoryWriter`. | com acesso a memória |
| `inject` | `SendInjector`: escrita bruta de pacotes do consumidor na fila de envio, com checagem de limites. Primitivo de escrita; só válido para um cliente **sem cifragem** (ver §6). | escrita bruta |
| `research` | `ActorProbe` (`--probe-actors`), `ActorDiag` (`--actor-diag`). | pesquisa |

### 3.2 Threads

| Thread | Onde | O que faz |
|---|---|---|
| callback Frida | `Agent._message` | Põe cada mensagem numa fila. Nada mais, para o agente nunca esperar. |
| **worker** | `Capture.run_worker` | Uma mensagem por vez, em ordem. `RINGSNAP` → anexa aos trechos da mesma conexão. `RECV` → tokeniza, nota os cifrados, enfileira. `SEND` → redige, roda o acompanhamento, alimenta o quadro "S" (e, autodescobrindo, arma a cifragem a partir do pc recuperado). `GEPARD`/`SCRAMBLE`/`SENDCALL`/`TRACE` registrados. Exceção numa mensagem é impressa, não fatal. |
| **alimentadora** | `WireFeed.run` | Dorme até ter trecho. Enquanto um trecho espera, consulta a cada 5 ms, deixa o `ActorDecrypt` decidir, e alimenta em **ordem estrita de chegada**. |
| conexão do relay | dentro de `Relay` | (Re)conecta ao consumidor a cada segundo; lê o que o consumidor manda (descarta, ou entrega a um manipulador de escrita). |
| thread do jogo (chamada de envio) | `drainSendCall` | `--inject-call`: os pacotes pendentes do consumidor são enviados por `SendPacket` a partir dos hooks de recv/send (na thread do jogo). |

### 3.3 Estado compartilhado e travas

| Estado | Escritores/leitores | Protegido por |
|---|---|---|
| `WireFeed.pending` + `snaps`/`closed` de cada trecho | worker adiciona, alimentadora remove | `WireFeed.cond` |
| local da ring, stats, `fed` do `ActorDecrypt` | worker, alimentadora, thread de busca | `ActorDecrypt.lock`; fora da trava lê-se `base` uma vez |
| `stream` do `ActorDecrypt` | worker escreve, alimentadora lê | substituído numa atribuição |
| socket/contadores do `Relay` | todos os emissores, laço de conexão | `Relay.lock` |
| mapa de corpos da cifragem / captura de `this` | worker posta; o agente roda os manipuladores numa thread só | (lado do agente) |

---

## 4. A jornada de um pacote

**Servidor → cliente (quadro "R"):**
1. O jogo lê do socket; o agente manda `RECV` (+ cópia "de antes" da ring).
2. `WireFeed.on_recv` entrega ao `WireFilter`, que divide em pacotes. Pacotes em texto claro
   saem na hora. Um `09fd`/`09ff` vira item "a preencher".
3. O trecho entra em `pending`. Se tem item a preencher, espera (no máx. `--actor-delay`,
   0,15 s) enquanto o `ActorDecrypt` lê a cópia decifrada do cliente e verifica.
4. A alimentadora manda ao relay, em ordem, com a cópia verificada no lugar — ou sem aquele
   pacote, se não deu para verificar.

**Cliente → servidor (quadro "S"):**
1. O jogo escreve um pacote na fila de envio. Se é ação/perícia, o acompanhamento registra os
   bytes em texto claro sendo escritos e depois a cifragem reescrevendo-os.
2. No `sendmsg` o agente manda `SEND` com a janela registrada e move o acompanhamento.
3. `ClientSendFeed` redige o tráfego de login e o `SendWatch` devolve o texto claro (ou nada).
4. O relay alimenta como quadro "S".

---

## 5. Entendendo a cifragem do cliente

- **Servidor → cliente**: texto claro no fio, exceto os **corpos** de `09fd`/`09ff`
  (actor_moved/actor_exists). O cliente decifra cada trecho na sua **ring de recepção** (um
  bloco de heap); o driver lê a cópia decifrada de lá (verificada por pacote).
- **Cliente → servidor**: `0437` (ação) e `0438` (perícia) são montados na **fila de envio** e
  cifrados **in-place** nessa fila. `035f` (andar) é montado e cifrado na **pilha**, por um
  caminho **separado** (o acompanhamento da fila o descarta de propósito).
- A cifragem tem **estado por conexão**. Reenviar um `035f` pelo caminho da fila dessincroniza
  esse estado (só volta ao relogar) — confirmando que o `035f` tem canal próprio. Ver §10.
- O primitivo de cifragem fica em `gepard.dll`: um laço que escreve byte a byte, instrução
  `88 19` (`mov [ecx], bl`) em **gepard+0x18eff2** (`ecx` = ponteiro do byte destino; o id do
  pacote fica em `ecx-2`). O acompanhamento da fila relata o pc como `gepard+0x18eff4`
  (= store + 2, pois o watchpoint de dados dispara depois da escrita).

---

## 6. Caminhos de escrita (reenvio de pacotes do consumidor)

Três formas de fazer o cliente transmitir os pacotes que o consumidor devolve. Todas para um
cliente/servidor próprio, desligadas por padrão.

1. **Chamar a função de envio do cliente** (`--inject-call`) — espontâneo, não troca nenhum
   pacote do cliente. O driver chama o `SendPacket(this, len, buf)` do próprio cliente, que
   monta, cifra e envia pelo caminho normal. `this` é capturado uma vez com um breakpoint de
   hardware (sem alterar código); a chamada é feita na thread do jogo. **Funciona** para os
   pacotes da fila (`0437`/`0438`). Endereço: `uaRO.exe+0x816640` (ver §9).
2. **Substituir o corpo no ponto de parada da cifragem** (`--inject` + `--scramble-bp`;
   `--inject-persist`) — troca o corpo de um pacote que **o próprio cliente monta**, antes do
   XOR, então a cifragem do cliente cifra os bytes fornecidos. Uma vez por pacote, ou mantido
   (substitui toda ação igual). É o caminho certo quando o cliente inicia a ação (ver §10,
   método 1 para o `035f`).
3. **Escrita bruta na fila** (`inject.SendInjector`, via `memory.ProcessMemoryWriter`) — escreve
   direto na fila. Só vale para um cliente **sem cifragem** (os bytes não passam pela cifragem).

Cuidados: `--feed-send` é desligado automaticamente com `--inject` (senão os envios do próprio
cliente voltariam pelo consumidor e seriam reenviados em laço). `SIGTERM`/Ctrl-C fazem o
desligamento limpo (o `dispose` do agente libera os registradores de depuração; um registrador
de depuração armado sem manipulador derruba o cliente).

---

## 7. Autodescoberta da cifragem

Com `--inject` e sem a localização fixada, o driver se autoconfigura:
1. O acompanhamento da fila (ligado) relata o pc do store da cifragem no primeiro `0437`/`0438`
   (`enc`/`enc_off`). O store em si é uma instrução antes (`SCRAMBLE_STORE_BACK = 2`).
2. O driver desliga o acompanhamento e arma o breakpoint de execução no store com `reg='auto'`:
   o agente **localiza sozinho** o registrador do ponteiro e o deslocamento do id, casando o id
   do pacote.
3. A **faixa** vem do bloco da ring que o `ActorDecrypt` acha (`send_queue_range`).

Para **fixar** e pular a descoberta, defina `scramble-bp`/`-reg`/`-idoff`/`-range` na config.
É preciso **uma ação `0437`/`0438` no cliente** para iniciar a descoberta.

---

## 8. Sondas de pesquisa (somente leitura, exceto onde dito)

Ferramentas para engenharia reversa do caminho de envio, todas de disparo único e com proteção
contra inundação:

- `--send-probe`: no primeiro `0437`/`0438`, captura os registradores e um **passeio de pilha**
  (endereços de retorno resolvidos contra as faixas de código — ver §9). `--probe-ids` escolhe
  os ids (padrão `0437,0438`; use `035f`). `--probe-anyid` captura o primeiro acerto dentro da
  faixa sem exigir id (quando o deslocamento do id é desconhecido). `reg='auto'` localiza o
  ponteiro/id.
- `--probe-entry OFF` / `--probe-at ADDR`: captura de disparo único dos **argumentos de uma
  função na entrada** (registradores + topo da pilha + bytes apontados), opcionalmente filtrada.
- `--trace-test MS` / `--trace-walk MS` / `--trace-internal MS`: **Stalker**. Segue a thread
  principal por MS ms. `test` só conta eventos (sobrevivência); `walk` registra chamadas
  `uaRO→gepard`; `internal` registra `uaRO→uaRO`. Comparar parado vs andando isola o fluxo.

**Lição importante:** o passeio de pilha no store da cifragem pega muitos endereços de retorno
**obsoletos** (a pilha é profunda, cheia de histórico do laço de UI), então não é confiável para
achar o chamador vivo do envio. **O Stalker dá a cadeia viva** e foi o que funcionou. O gepard
**tolera** o Stalker em janelas curtas (teste de sobrevivência confirmado).

---

## 9. Mapa da memória e endereços (sessão de referência)

ASLR varia as **bases** entre execuções, mas nesta máquina elas têm sido constantes; os
**deslocamentos** relativos ao módulo são estáveis. O código do uaRO é **desempacotado em
memória anônima** (não é um módulo com arquivo), por isso o Frida não o resolve por nome — o
agente resolve contra as faixas mapeadas (regiões anônimas de código baixo, `< 0x2000000`).

| Item | Endereço | Observação |
|---|---|---|
| base `gepard.dll` | `0x76940000` | reportado na mensagem GEPARD |
| código do uaRO | anônimo base `0x401000` | desempacotado; `uaRO.exe` com arquivo fica em `0x400000` |
| VM/blob do gepard | anônimo `0x1717000` | glue que chama/é chamado pelo código do uaRO |
| bloco ring de recepção / fila de envio | `0x24dd0000`–`0x24f80000` | onde `0437`/`0438` são cifrados |
| região de pilha da thread principal | ~`0x2632000`–`0x2730000` | onde `035f` é montado/cifrado |
| **store da cifragem** | `gepard+0x18eff2` | `mov [ecx],bl`; `ecx`=destino; id em `ecx-2` (idoff `-2`) |
| **envio da fila (`SendPacket`)** | `uaRO+0x816640` | `thiscall(this, len, buf)`; copia p/ a fila, avança o cursor `this->[8]`; `this` observado `0x15c5a44` (`this->[0]`=base da fila) |
| **envio do `035f` (andar)** | `uaRO+0x9463b0` | `thiscall`, monta o `035f` na pilha, usa um objeto de estado; invocado pela VM do gepard (retorno `gepard+0xb2c251`); chama a API gepard `+0xdbf0`/`+0x10a90` |
| wrapper do envio do walk | `uaRO+0x875400` | chamado por `uaRO+0x873b32`; recebe um **objeto de movimento/posição** (`ecx`) + contexto de mapa, não `(x,y)` crus |
| cadeia do movimento (Stalker) | `uaRO+0x873a80` → `+0x875400`; cluster `+0x679xxx` (animação/por frame); `+0x454xxx` (preparação) | ver §10 |
| thunks da API gepard no envio | `gepard+0xdbf0`, `+0x10a90`, `+0x35ac0` | `jmp` para dentro do gepard |

---

## 10. O caso do `035f` (andar) — situação e método 1

**Descobertas:**
- O `035f` é cifrado na **pilha**, por um caminho próprio (não a fila). Reenviá-lo pela fila
  (`SendPacket`) **dessincroniza** o estado da cifragem (precisa relogar).
- O envio do `035f` sai de `uaRO+0x9463b0`, que **monta o pacote e usa um objeto de estado**
  (`ecx`), e é invocado pela VM do gepard — não é um `enviar(buf,len)` simples.
- Subindo a cadeia (via Stalker, confiável): `uaRO+0x873a80 → +0x875400 → API gepard`.
  `+0x875400` recebe um **objeto de movimento/posição** com a posição já **empacotada**, mais o
  contexto de mapa — não coordenadas `(x,y)` cruas. As coordenadas do clique são empacotadas
  **cedo** (perto do manipulador do clique). Um `andar(x,y)` limpo está mais acima na cadeia e
  exige mais sondas (caminho grande e ofuscado).

**Método 1 (escolhido):** em vez de um `andar(x,y)` espontâneo, usar o caminho 2 (§6) para o
`035f`: quando **o próprio cliente** monta um `035f`, substituir os 3 bytes de destino pelos do
consumidor, no ponto de parada da cifragem (faixa = pilha), antes do XOR. Mantém o canal e o
estado da cifragem idênticos (**sem dessincronizar**). Limitação: o cliente precisa **iniciar**
o andar (não é tão autônomo quanto o `0437`). Usa a maquinaria já existente (§6, caminho 2);
o id fica em `ecx-2`, o corpo (3 bytes = `pack_move(x,y,dir)`) em `ecx`.

---

## 11. Como rodar

Mantenha o stdin aberto (o driver encerra no EOF). Sem opções, lê `relay_capture.conf`:

```sh
tail -f /dev/null | ~/.venv-frida/bin/python relay_capture_linux.py
```

Precedência das opções: padrões embutidos < arquivo de config < linha de comando. `--config`
aponta outro arquivo. Carregar o gadget: opção de inicialização do Steam
`LD_PRELOAD=.../frida-gadget-32.so %command%`.

---

## 12. Testes (offline, sem o cliente)

```sh
for t in test_*.py; do python3 "$t"; done
```

Cobrem `WireFilter`, `ActorDecrypt.settle`, `SendWatch`/`plaintext_guess`, `MoveTracker`,
`SendInjector` + o enquadramento do `Relay`, e o contrato de mensagens da escrita
(`scramble_set_msg`, `scramble_msg`, `_on_inbound_scramble`, `_autodiscover_scramble`).

---

## 13. Pendências e próximos passos

- **Método 1 (em andamento):** substituir as coordenadas de destino do `035f` do próprio cliente
  (§10) — reenvio de andar confiável, sem dessincronizar.
- **`andar(x,y)` espontâneo:** exigiria subir mais na cadeia do clique (`uaRO+0x873a80` e acima)
  até a função que recebe `(x,y)` crus; aberto, várias sondas de distância.
- **Latência (~700 ms)** na chamada de envio (`--inject-call`): a drenagem só ocorre nos hooks de
  recv/send; um ponto de drenagem mais frequente na thread do jogo reduziria.
- O passeio de pilha é pouco confiável (quadros obsoletos); preferir Stalker para mapear.
