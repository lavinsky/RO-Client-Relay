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
sair pelo cliente de três formas (ver `ARCHITECTURE.md` §6): chamando a função de envio do próprio
cliente (`--inject-call`), substituindo o corpo de um pacote do cliente no ponto de parada da
cifragem, ou escrevendo direto na fila (só para cliente sem cifragem).

## Requisitos

- Linux, com o jogo como processo Wine/Proton 32 bits.
- [frida-gadget](https://frida.re/) (32 bits) pré-carregado no cliente.
- Python com `frida` (p.ex. `~/.venv-frida`).
- Acesso de leitura a `/proc/<pid>/mem`.

A ligação é pelo **gadget** (`LD_PRELOAD`), não ptrace: dar ptrace num Proton 32 bits derruba o
processo.

## Preparação

Pré-carregue o gadget. No Steam, opção de inicialização:

```
LD_PRELOAD=/caminho/para/frida-gadget/frida-gadget-32.so %command%
```

O gadget escuta numa porta em `27052–27100`; o driver o encontra pelo nome do processo (padrão
`uaRO.exe`).

## Executando

Mantenha o stdin aberto (o driver encerra no EOF). Sem opções, lê `relay_capture.conf`:

```sh
tail -f /dev/null | ~/.venv-frida/bin/python relay_capture_linux.py
```

Precedência: padrões embutidos < arquivo de config < linha de comando. Ex.: uma captura só de
leitura, ignorando a config:

```sh
tail -f /dev/null | ~/.venv-frida/bin/python relay_capture_linux.py --no-inject
```

## Configuração

`relay_capture.conf` é um INI comentado (seção `[capture]`); as chaves são os nomes longos das
opções. `--config <arquivo>` aponta outro; arquivo ausente usa os padrões embutidos.

## Módulos

O fluxo passa pelo pacote `relay/` nesta ordem:

| Módulo | Papel |
|---|---|
| `protocol` | formatos das mensagens trocadas com o agente (`relay_hook_linux.js`) |
| `agent` | conexão Frida: acha o gadget, carrega o agente, posta mensagens |
| `packets` | tabela de tamanhos + `WireFilter` (separa o fluxo TCP em pacotes) |
| `actors` | `ActorDecrypt`: preenche os corpos cifrados de `09fd`/`09ff` da memória do cliente |
| `sendwatch` | recupera o texto claro dos pacotes cifrados de envio |
| `wire_feed` | pipeline padrão: trechos RECV → fluxo ordenado e preenchido |
| `relay` | enquadramento XKore + conexão com o consumidor |
| `inject` | escrita bruta de pacotes na fila (clientes sem cifragem) |
| `moves` | decodifica o destino do movimento do `0087` (texto claro) do servidor |
| `safety` | redação de credenciais e a checagem de HTTP |
| `console` | log JSONL redigido + linhas de console |
| `memory` | leitura/escrita de `/proc/<pid>/mem` (nunca pausa o jogo) |
| `research` | ferramentas de pesquisa (`--probe-actors` / `--actor-diag`) |
| `runtime` | `Capture`: monta os componentes e roteia as mensagens |
| `cli` | opções, config, threads |

O agente Frida é `relay_hook_linux.js`. Veja `ARCHITECTURE.md` para o mapa completo, as
descobertas de engenharia reversa (endereços, caminhos de envio, estado da cifragem) e as
pendências.

## Testes

Testes offline (sem o cliente), contra dados gravados:

```sh
for t in test_*.py; do python3 "$t"; done
```
