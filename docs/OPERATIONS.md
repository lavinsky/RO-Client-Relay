# Operação, configuração e validação — RO-Client-Relay

> Revisão documental: **2026-10-15**, `main@524b0f05fa61872e140f98ace9e503d12356641e`. Transcrição dos comandos publicados em [`../README.md`](../README.md), [`../ARCHITECTURE.md`](HISTORY/ARCHITECTURE_LEGACY.md), [`../relay_capture.conf`](../relay_capture.conf). **Não foram executados contra o cliente durante esta revisão.** Uso somente em ambientes com autorização explícita.

## Pré-requisitos e instalação

- Linux com cliente uaRO rodando sob **Wine/Proton 32 bits**.
- **Frida Gadget de 32 bits** carregado no cliente (instalado pelo script do repositório); Python com `frida` em ambiente virtual (exemplo `~/.venv-frida`).
- Acesso somente de leitura a `/proc/<pid>/mem` para observar cópias já decifradas.
- OpenKore instalado **externamente**, usando seu modo xKore 1.

Configuração publicada:

```sh
./setup.sh                   # ou ./setup.sh /caminho/do/venv
# Opção de inicialização Steam indicada pelo script:
# LD_PRELOAD=/caminho/absoluto/relay/resources/frida-gadget-32.so %command%
```

`./setup.sh --force-gadget` força baixar o Gadget compatível com a versão de Frida configurada. O Gadget/recurso gerado em `relay/resources/` não é material a versionar ou editar nesta tarefa. A ligação ocorre por Gadget/`LD_PRELOAD`, **não** via ptrace; a arquitetura histórica registra instabilidade no cliente via ptrace neste ambiente. Não presumir que tal observação valha para todos os Proton/builds.

## OpenKore e enquadramento XKore

Trecho de configuração do **consumidor**, não do relay (preencher informações de servidor/conta somente fora do repositório):

```text
master uaRO
server 0
XKore 1
XKore_port 2350
XKore_listenIp 127.0.0.1
XKore_publicIp 127.0.0.1
```

O relay usa como padrão publicado `127.0.0.1:2350` e quadros `R` (servidor→consumidor) / `S` (cliente→consumidor), mantendo identidade de conexão internamente no pipeline. O frame XKore não possui ID de conexão: contém tipo, comprimento e payload (`relay/relay.py:14`). `relay/relay.py` cuida de reconexão/framing; `relay/protocol.py` define os campos agente-driver. OpenKore é o responsável pela lógica de ações e já contém a implementação xKore.

## Execução

```sh
./run.sh                     # lê relay_capture.conf quando opções não sobrescritas
./run.sh --no-inject         # exemplo: leitura apenas, ignorando escrita da config
# Com stdin mantido aberto, como documentado:
tail -f /dev/null | ~/.venv-frida/bin/python relay_capture_linux.py
# Troca do ambiente virtual:
VENV=/caminho/do/venv ./run.sh
```

A precedência declarada é **defaults internos CLI → `relay_capture.conf` → argumentos CLI**. O arquivo INI usa `[capture]`; `--config ARQUIVO` aponta alternativa. O driver encerra ao receber EOF no stdin; `run.sh` mantém stdin aberto. Encerramento normal por Ctrl-C/SIGTERM, liberando a instrumentação; evitar kill abrupto enquanto registradores de depuração permanecerem armados.

## Flags de pesquisa do CLI (fora da config; exigem autorização para uso live)

Estas flags **não** estão em `relay_capture.conf` (entram pelo CLI; `relay_capture.conf` permanece
inalterado). Uso live contra o cliente exige escopo explicitamente aprovado — validação offline por
padrão.

| Flag | Default | Efeito |
|---|---|---|
| `--move-dispatch` | OFF | Roteia o `035F` (CZ_REQUEST_MOVE) do consumidor para o **dispatcher nativo de movimento do cliente** em vez do merge pré-XOR: o cliente monta/cifra/envia o próprio `035F` e o `035F` original é dropado. Usa **DR2+DR3**; requer `--no-send-watch`. Ref.: [MOVEMENT_035F_PRECONDITIONS §13.11](MOVEMENT_035F_PRECONDITIONS.md). |
| `--move-dispatch-ptr` | `0xd473b0` | Endereço do dispatcher (hex); evita hardcode no agent. |
| `--move-dispatch-site` | `0x4dcba0` | Fire-site de main-loop do `uaRO.exe` (hex). |
| `--target-select` | OFF | Reativa o `0368` (seleção por GID) **antes** de ações com alvo (`0437` ataque / `0438` perícia). **Default OFF** (o cliente já emite o `0368` sozinho). A leitura de que o `0368` pré-ação bloqueava ataque/perícia foi **REFUTADA** pelo responsável em 2026-10-16: o `sendmsg` da ação sai com ou sem `0368`, e a ação continua **sem efeito** via SendPacket crua. Ligar/desligar a flag **não** resolve ataque/perícia (ver [GEPARD_CONTROL_PACKETS](GEPARD_CONTROL_PACKETS.md)). |

**Orçamento de debug registers (x86 = 4 HW BP).** Com `--move-dispatch`, os 4 slots são:
DR0 scramble (`--inject`) · DR1 SendPacket (`--inject-call`) · DR2 captura passiva do `this` do
dispatcher · DR3 fire-site. Por isso **`--no-send-watch` é obrigatório** com `--move-dispatch`
(send-watch usa os mesmos registradores).

**Invocação do PoC de movimento (OBSERVADA funcionando live 2026-10-16, rodada pelo responsável):**

```sh
mkdir -p <dir-saida>
./run.sh --inject --inject-call --move-dispatch --no-send-watch --out <dir-saida>/relay_log.jsonl
```

`--out` exige **arquivo**, não diretório (passar um diretório gera `IsADirectoryError`). O
`--move-dispatch` **soma** ao `--inject-call` (não o substitui): sem `--inject-call`, o relay dropa
pacotes não-`035F` do consumidor e o OpenKore não sincroniza. Sequência: relay conecta no XKore 2350
→ andar 1× no cliente captura o `this` do dispatcher → OpenKore emite walk → `035F → native dispatch`
→ `recv_0087 dst=destino` → cliente vivo.

## Configuração observada no checkout local

| Chave | Valor em `relay_capture.conf` | Interpretação/conferência |
|---|---|---|
| `name` | `uaRO.exe` | Processo-alvo padrão |
| `relay` | `127.0.0.1:2350` | Consumidor xKore 1 |
| `relay-format` | `xkore1` | Enquadramento de quadros |
| `out` | `relay_log.jsonl` | Saída de logs; sensibilidade deve ser conferida antes de publicar |
| `inject` | **`true`** | **Decisão humana, não alterar** |
| `inject-call` | **`true`** | **Decisão humana, não alterar** |
| `inject-persist` | `false` | Merge reativo de uso único; evitar substituição persistente de todos os andares |
| `cast-throttle` | `0.8` | 800 ms no dreno; casts dentro da janela são descartados, sem reenfileirar (arquitetura §11) |
| `scramble-bp` | `18eff2` | Offset relativo à base Gepard validada na sessão; **não endereço universal** |
| `scramble-reg` | `auto` | Identifica registro do ponteiro conforme heurística do agente |
| `scramble-range` | `2632000-2730000` | Faixa de sessão da escrita reativa; **revalidar** em outra sessão |
| `scramble-id` | `035f` | Alvo do merge reativo |

**Não confundir** a config intencional com defaults internos do CLI. Não executar instrumentos de pesquisa ou modificar a configuração funcional para 'corrigir' a documentação.

## Diagnóstico e cuidados

- **Nenhum pacote decifrado fabricado:** para `09fd`/`09ff` sem evidência de cópia válida, o pipeline descarta o item em vez de gerar bytes conjecturais.
- **Sem laços de retorno:** o modo de escrita desativa o feed de send do cliente para evitar duplicação recursiva.
- **Privacidade:** `relay/safety.py` implementa sanitização de credenciais e HTTP; nunca salvar em docs capturas reais, tokens, endpoints privados de conta ou dumps brutos.
- **Identidade da conexão:** reutilização de FD no Wine exige separar conexões/portas, não confundir char/mapa e login.
- **Instrumentação:** registradores DR0/DR1 e acompanhamento de fila podem conflitar; experimentos de pesquisa dependem de janela exclusiva aprovada e limpeza explícita. Evitar varredura grande in-process e watchpoint de dados no slot de pilha de `0x035F`, conforme incidentes históricos.
- **Sequência do `035f`:** `SendPacket` da fila não equivale à montagem natural na pilha; usar essa rota para andar foi associado a dessincronização na sessão documentada. O merge só é disparado após movimento originado pelo cliente.
- **Observações temporais:** `sendmsg` e `recv_0087` precisam ser analisados independentemente do store; comprimento efetivamente enviado não prova conteúdo sem bytes/proveniência observados.
- **Falhas:** distinguir ausência de instrumento, truncamento/perda de eventos, falha de captura, cliente desconectado e falha real do protocolo. Não elevar um timeout local à rejeição de servidor.

## Testes offline e o que comprovam

```sh
python3 scripts/validate-research.py
python3 scripts/validate-codex.py
bash scripts/test-offline.sh
git diff --check
```

`validate-research.py` valida **marcadores e tamanhos tabelados**, não a hipótese criptográfica; `validate-codex.py` valida **estrutura de agentes/configurações**, não disponibilidade de modelos. A suíte `test-offline.sh` roda `tests/test_*.py` sequencialmente; inclui `test_cipher_research.py`, `test_movement_preconditions.py` e os testes operacionais. `test_integration.py` pode usar sockets loopback locais: sua falha por permissão em alguns sandboxes **não** caracteriza falha do cliente. Nenhum teste offline prova envio/recepção aceitos pelo servidor.

**Status desta revisão local:** comandos e resultados efetivamente executados em [DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md). Nenhuma instalação ou coleta viva foi realizada.

## Operação e pesquisa são escopos diferentes

Atualizar documentação não concede autorização para executar o cliente, probes, `Frida`, CEServer, alterar `relay/`/`agent/` ou provocar tráfego de servidor. Para detalhes especializados de experimento offline, consulte `research/cipher/README.md` (instruções locais) e `research/movement_035f/` (fontes), além de [RESEARCH_STATUS](RESEARCH_STATUS.md) e [índice de evidências](RESEARCH_EVIDENCE_INDEX.md).

## Detalhes de instalação e configuração preservados

O Gadget usa a faixa de descoberta `27052–27100`; `setup.sh` cria listener em `127.0.0.1:27052`
com `on_port_conflict=pick-next` e `on_load=resume`. O driver procura o processo `uaRO.exe`.
INI aceita chaves com hífen/underscore e booleanos true/false, yes/no, on/off, 1/0;
arquivo ausente deixa os defaults internos. A localização do arquivo padrão é resolvida
pelo driver; caminhos em comandos deste manual são relativos à raiz.

O cliente deve entrar na sessão desde o início com relay e OpenKore prontos, para que o
consumidor receba login, mapa e nascimento de atores. O crash de consumidor ao entrar no
meio da sessão foi diagnóstico histórico, não prova de ausência de outros defeitos.
Cuidados históricos completos (incluindo espera de ~6 s após SIGTERM, falsos positivos de
`pgrep`, sondas e registradores) em [arquitetura histórica §§8–11](HISTORY/ARCHITECTURE_LEGACY.md).
“Seguro” nesses registros significa apenas sobrevivência no recorte, sem garantia geral.
