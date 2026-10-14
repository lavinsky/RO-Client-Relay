# RO Client Relay

Ferramenta de **depuração** do fluxo de pacotes de um cliente uaRO (RO sob Wine/Proton, 32 bits)
no Linux. Reconstrói o fluxo servidor→cliente em texto claro e o entrega a um consumidor XKore 1
(p.ex. OpenKore). Opcionalmente, para teste num servidor próprio, reenvia pacotes vindos do
consumidor fazendo o próprio cliente montá-los e cifrá-los.

O fluxo servidor→cliente é texto claro no fio, exceto os corpos de alguns pacotes, que o cliente
decifra na própria memória. Um agente Frida observa `recvmsg`/`sendmsg` dentro do processo Wine e
relata o que vê; o driver em Python monta um fluxo ordenado em texto claro, preenchendo os trechos
cifrados com as cópias já decifradas lidas de `/proc/<pid>/mem` (somente leitura).

> **Uso autorizado.** A ferramenta lê (e, opcionalmente, escreve) a memória de um cliente em
> execução, como parte da depuração. Use com um cliente e servidor que você controla ou está
> autorizado a testar.

## Como funciona

**Recepção (servidor → cliente).** O agente copia cada trecho recebido e tira snapshots da região
de recepção. O `WireFilter` separa o fluxo em pacotes por conexão; os corpos cifrados de
`09fd`/`09ff` são preenchidos pelo `ActorDecrypt` a partir da cópia decifrada do cliente,
verificada por pacote (os não verificáveis são descartados, nunca adivinhados). O `WireFeed`
entrega ao consumidor na ordem exata de chegada.

**Envio (cliente → servidor).** O agente observa `sendmsg`. Os pacotes cifrados `0437` (ação) e
`0438` (perícia) são recuperados em texto claro com o acompanhamento da fila e entregues como
quadros "S"; `035f` (andar) e os não recuperados são descartados (as coordenadas do andar vêm do
`0087` em texto claro do servidor). Credenciais são redigidas (`safety.py`).

**Escrita (opcional, para teste em servidor próprio).** Os pacotes que o consumidor devolve podem
sair pelo cliente de duas formas, combináveis por id (ver `ARCHITECTURE.md` §6): substituindo o
corpo de um pacote que o próprio cliente monta no ponto de parada da cifragem (`035f`/andar), e/ou
chamando a função de envio do próprio cliente (`--inject-call`, para `0437`/`0438`).

## Requisitos

- Linux, com o jogo como processo Wine/Proton 32 bits.
- [frida-gadget](https://frida.re/) (32 bits) pré-carregado no cliente.
- Python com `frida` (p.ex. `~/.venv-frida`).
- Acesso de leitura a `/proc/<pid>/mem`.

A ligação é pelo **gadget** (`LD_PRELOAD`), não ptrace: dar ptrace num Proton 32 bits derruba o
processo.

## Setup rápido (nova máquina)

Um script faz o trabalho chato (venv do Python, `frida` fixado, e o **gadget de 32 bits que casa
essa versão** baixado e configurado em `relay/resources/`):

```sh
./setup.sh                 # ou: ./setup.sh /caminho/do/venv
```

Ao terminar, ele imprime a opção de inicialização do Steam, já com o caminho absoluto do gadget:

```
LD_PRELOAD=/.../relay/resources/frida-gadget-32.so %command%
```

Cole isso nas opções de inicialização do jogo no Steam. O gadget escuta numa porta em
`27052–27100`; o driver o encontra pelo nome do processo (padrão `uaRO.exe`). Para rebaixar o
gadget (p.ex. após trocar a versão do frida): `./setup.sh --force-gadget`.

> O gadget (`.so`, ~24 MB) e o OpenKore não são versionados (`relay/resources/`); o `setup.sh`
> baixa o gadget, e o consumidor você instala à parte (abaixo).

## Consumidor (OpenKore)

O consumidor é o OpenKore em **XKore 1**. No `control/config.txt` dele, o que importa para ligar ao
relay (preencha servidor/conta à parte, conforme a comunidade uaRO):

```
master uaRO
server 0
XKore 1
XKore_port 2350            # o relay conecta aqui (= --relay 127.0.0.1:2350)
XKore_listenIp 127.0.0.1
XKore_publicIp 127.0.0.1
```

## Executando

Com o cliente aberto e o consumidor rodando:

```sh
./run.sh                   # sem opções, lê relay_capture.conf; Ctrl-C encerra
./run.sh --no-inject       # ex.: captura só de leitura, ignorando a config
```

`run.sh` segura o stdin aberto e usa o venv (padrão `~/.venv-frida`; `VENV=... ./run.sh` troca).
Equivale a `tail -f /dev/null | ~/.venv-frida/bin/python relay_capture_linux.py`. Precedência das
opções: padrões embutidos < arquivo de config < linha de comando.

## Configuração

`relay_capture.conf` é um INI comentado (seção `[capture]`); as chaves são os nomes longos das
opções. `--config <arquivo>` aponta outro; arquivo ausente usa os padrões embutidos.

## Módulos

O fluxo passa pelo pacote `relay/` nesta ordem:

| Módulo | Papel |
|---|---|
| `protocol` | formatos das mensagens trocadas com o agente (`agent/relay_hook_linux.js`) |
| `agent` | conexão Frida: acha o gadget, carrega o agente, posta mensagens |
| `packets` | tabela de tamanhos + `WireFilter` (separa o fluxo TCP em pacotes) + movimento (`pack_move`, `MoveTracker` do `0087`) |
| `actors` | `ActorDecrypt`: preenche os corpos cifrados de `09fd`/`09ff` da memória do cliente |
| `sendwatch` | recupera o texto claro dos pacotes cifrados de envio |
| `wire_feed` | pipeline padrão: trechos RECV → fluxo ordenado e preenchido |
| `relay` | enquadramento XKore + conexão com o consumidor |
| `writeback` | caminho de escrita: merge (`035f`) + `SendPacket` (`0437`/`0438`) + autodescoberta + rastreio |
| `safety` | redação de credenciais e a checagem de HTTP |
| `console` | log JSONL redigido + linhas de console |
| `memory` | leitura de `/proc/<pid>/mem` (nunca pausa o jogo) |
| `research` | ferramentas de pesquisa (`--probe-actors` / `--actor-diag`) |
| `runtime` | `Capture`: monta os componentes e roteia as mensagens |
| `config` | lê `relay_capture.conf` como defaults |
| `cli` | opções, threads, `main` |

O agente Frida é `agent/relay_hook_linux.js`. Veja `ARCHITECTURE.md` para o mapa completo, as
descobertas de engenharia reversa (endereços, caminhos de envio, estado da cifragem) e as
pendências.

`relay/resources/Gepard-SRC-LGP-master` é o fonte de um build **antigo** do gepard (lado servidor),
usado como referência da cifra e do protocolo (ver `ARCHITECTURE.md` §5.1 e `gepard_investigation.md`
§22). `--scramble-trace N` é a sonda de traço passo-a-passo da cifragem (§8 do ARCHITECTURE).
O estado atual da investigação e o próximo passo concreto estão em `HANDOFF.md`.

## Testes

Testes offline (sem o cliente), contra dados gravados. Cada arquivo roda como script e
imprime `ALL PASS` ao final:

```sh
for t in tests/test_*.py; do python3 "$t" || break; done
```

Um teste por módulo: `test_packets` (tokenização do stream + andar), `test_actors`
(decifra os corpos de ator), `test_relay` / `test_integration` (enquadramento e fluxo
ponta-a-ponta sobre socket), `test_sendwatch` (recupera texto claro dos envios),
`test_writeback` (o caminho de escrita e seu roteamento por id), `test_safety`
(a fronteira de credenciais) e `test_config` (a precedência da config).
