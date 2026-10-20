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

## Flags do CLI e valores operacionais do INI

**Status corrigido 2026-10-17:** operação funcional de movimento, ataque automático e skills automáticas de alvo/chão **confirmada pelo responsável**. A falha anterior foi causada pelo primeiro byte sobregravado no agente Frida, corrigido em `agent/relay_hook_linux.js:481-534`; não foi seleção de alvo. Única pesquisa aberta: cifra. A tabela abaixo registra parâmetros de CLI (OFF por padrão onde indicado); **não** instrui teste live.

A tabela descreve os **defaults internos do CLI**, não os valores
efetivos de `relay_capture.conf`; o arquivo operacional contém diversas
dessas flags e prevalece sobre os defaults. Argumentos explícitos do CLI
sobrescrevem ambos. Uso live contra o cliente exige escopo autorizado;
validação de manutenção é offline por padrão.

**Fluxo de identificação (resultado live confirmado em 2026-10-17):** os pacotes de saída
`0368/0369/0193/0094/0360` do consumidor seguem normalmente via `SendPacket`,
sem lista de descarte. A política legada `SKIP_IDS` e a flag temporária
`--noskipids` foram removidas após confirmação de que esse encaminhamento
resolveu o sintoma `[Unknown]` da identificação de monstros.
O `--drop-ids` do fluxo servidor→consumidor e o timeout da FIFO continuam independentes.

| Flag | Default | Efeito |
|---|---|---|
| `--move-dispatch` | OFF | Roteia o `035F` (CZ_REQUEST_MOVE) do consumidor para o **dispatcher nativo de movimento do cliente** em vez do merge pré-XOR: o cliente monta/cifra/envia o próprio `035F` e o `035F` original é dropado. Usa **DR2+DR3**; requer `--no-send-watch`. Ref.: [MOVEMENT_035F_PRECONDITIONS §13.11](HISTORY/MOVEMENT_COMPLETE.md#source-docs-movement-035f-preconditions-md). |
| `--move-dispatch-ptr` | `0xd473b0` | Endereço do dispatcher (hex); evita hardcode no agent. |
| `--move-dispatch-site` | `0x4dcba0` | Fire-site de main-loop do `uaRO.exe` (hex). |
| `--target-select` | OFF | Reativa o `0368` (seleção por GID) **antes** de ações com alvo (`0437` ataque / `0438` perícia). **Default OFF** (o cliente já emite o `0368` sozinho). A leitura de que o `0368` pré-ação bloqueava ataque/perícia foi **REFUTADA** pelo responsável em 2026-10-16: o `sendmsg` da ação sai com ou sem `0368`, e a ação continua **sem efeito** via SendPacket crua. Ligar/desligar a flag **não** resolve ataque/perícia (ver [GEPARD_CONTROL_PACKETS](GEPARD_CONTROL_PACKETS.md)). |
| `--action-merge` | OFF | Arma corpo de `0437/0438/0AF4` do consumidor no store do scrambler, pré-XOR; requer carrier natural correspondente do cliente. Ações automáticas funcionais após `_fix0`. |
| `--synth-input` | OFF | Atuador interno de carriers de ação; a via depende de `--synth-backend`. Na configuração operacional validada está ON. |
| `--synth-backend` | `ydotool` | Seleciona `ydotool`/seat0 legado ou `gamescope-eis` via libei/socket privado; a config operacional validada usa `gamescope-eis`. |
| `--synth-eis-socket` / `--synth-eis-socket-file` | vazios | Indicação direta do socket EIS ou arquivo de localização 0600 criado pelo wrapper; não usar ambos. Erro se não houver EIS no backend selecionado, sem fallback ao KDE. |
| `--itemuse-input` / `--itemuse-input-key` | OFF / `END` | Com `0x0439`, pressiona e solta a tecla sincronicamente *antes* do pedido SendPacket; impede envio se não completar. Config operacional validada: ON / `END`. |
| `--synth-key-0437` / `--synth-key-0438` / `--synth-key-0af4` | `INSERT` / `9` / `F2` | Teclas padrão para produzir o carrier; `9` corresponde à fileira superior. |
| `--synth-debounce-ms` / `--synth-dry` | `500` / OFF | Antirrepetição em milissegundos; modo `dry` registra sem enviar input. |
| `--egress-queue` | OFF | FIFO para quadros de egresso `S` (não `R`); ordenação, **não** causa/correção do defeito de byte zero. |
| `--sendcall-demand` | consulte CLI | Solicitação sob demanda do envio nativo; a configuração validada mantém `false`. Não confundir com `inject-call`, que permanece ligado. |
| `--egress-interval-ms` / `--egress-action-gap-ms` / `--egress-max-age-ms` | `400` / `400` / `800` | Intervalos e descarte de quadro envelhecido na FIFO; não garantem por si só término do movimento. |

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

- **Login sem coordenadas ou entidades:** o default de `--drop-ids` é
  `4754,5395,09fd,09ff` (`relay/cli.py`). Os controles Gepard `4754`/`5395` ficam com
  o cliente; encaminhá-los a uma tabela RO que não reconhece esses IDs faz o OpenKore
  descartar também pacotes seguintes do mesmo bloco, inclusive a resposta de login `0AC4`.
  `debugPacket_exclude` apenas oculta avisos no consumidor, não descarta bytes.
  Uma lista explícita em config/CLI **substitui** os defaults: mantenha `4754,5395`
  nela. `09fd`/`09ff` continuam sendo recuperados quando `ActorDecrypt` verifica a cópia;
  sem verificação, são descartados. Regressão: `tests/test_packets.py` cobre fragmentação,
  preservação de `0AC4`/`02EB` e offsets dos atores cifrados. Após perder o login inicial,
  faça login completo com o relay corrigido ativo para reconstruir o estado do consumidor.
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

**Status desta revisão local:** comandos e resultados efetivamente executados em [DOCUMENTATION_AUDIT.md](HISTORY/STATUS_AND_AUDIT.md#source-docs-documentation-audit-md). Nenhuma instalação ou coleta viva foi realizada.

## Operação e pesquisa são escopos diferentes

Atualizar documentação não concede autorização para executar o cliente, probes, `Frida`, CEServer, alterar `relay/`/`agent/` ou provocar tráfego de servidor. Para detalhes especializados de experimento offline, consulte `research/cipher/README.md` (instruções locais) e `research/movement_035f/` (fontes), além de [RESEARCH_STATUS](RESEARCH_STATUS.md) e [índice de evidências](RESEARCH_STATUS.md#evidências-essenciais).

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

## Input sintético em Gamescope isolado (backend experimental EIS)

O atuador existente mantém **`--synth-backend ydotool` como padrão** (usa seat0,
altera foco do KDE). Para isolar eventos do mouse/teclado do desktop, selecionar
`--synth-backend gamescope-eis` em conjunto com `--synth-input`.
Esse backend usa **libei/EIS**, exige um socket do Gamescope **explicitamente**
selecionado, não usa `wmctrl`, `xdotool`, `ydotool` nem move o foco do host.
Não há fallback para seat0. O suporte libei no Gamescope depende da versão/build.

Exemplo para as opções de inicialização do jogo no Steam (adapte o diretório
do repositório e do Gadget; **não use duas instâncias com o mesmo path file**):

```sh
gamescope --backend wayland -g --force-grab-cursor -W 1280 -H 720 -w 1280 -h 720 -r 60 -- /var/home/bazzite/Documentos/Projetos/RO-Client-Relay/scripts/gamescope-eis-session.sh env LD_PRELOAD=/var/home/bazzite/Documentos/Projetos/RO-Client-Relay/relay/resources/frida-gadget-32.so %command%
```

O wrapper é executado **dentro do Gamescope** e escreve o valor `LIBEI_SOCKET`
num arquivo privado (0600) em `$XDG_RUNTIME_DIR/ro-relay-gamescope-eis.path`.
O arquivo é removido ao encerrar a sessão. Isso não concede acesso ao teclado
principal: apenas publica um nome de socket. Se necessário, defina
`RO_RELAY_EIS_FILE` para criar um arquivo distinto por sessão.

Ao iniciar o relay na **versão que contém este backend**, acrescente
**às flags já utilizadas**:

```sh
--synth-input --synth-backend gamescope-eis \
--synth-eis-socket-file /run/user/1000/ro-relay-gamescope-eis.path
```

Também é possível passar `--synth-eis-socket /run/user/1000/gamescope-N-ei`
diretamente. Não combine as duas opções. `--synth-dry` permite confirmar
mapeamento sem conectar ao socket e sem produzir eventos.

**Critérios de segurança e compatibilidade:** cada comando envia código evdev
para o *seat virtual do Gamescope* (pressão, frame, espera padrão 120 ms,
soltura, frame). A entrega ao **uaRO/Gepard** permanece a ser verificada em
teste autorizado: o fato de o Gamescope aceitar EIS não comprova que a
aplicação reconheça a tecla. Se a sessão Gamescope fechar ou o dispositivo
EIS não estiver disponível, a ação **falha e é registrada**, sem redirecionar
a entrada ao KDE. O cliente deve permanecer em foco **dentro** do Gamescope,
não necessariamente no KDE. Preferência operacional solicitada:
**`--backend wayland -g --force-grab-cursor`** em janela, para capturar teclado
e cursor enquanto o Gamescope estiver ativo e permitir a digitação no jogo.
O funcionamento do login deve ser validado na sessão real; os dois backends
já apresentaram dificuldades com teclado antes desse ajuste. A captura
pode restringir o uso dos periféricos enquanto a janela tiver foco; não
presumir que o EIS resolva a digitação manual. `Super+G` é interceptado
pelo KDE. O relay EIS envia ao Gamescope sem ativar a janela no KDE. Os testes offline de sintaxe/mocks não alteram
o estado do cliente.

## Gamescope EIS e configuração operacional validada

**CONFIRMADO PELO RESPONSÁVEL (2026-10-17):** as alterações e a
configuração presente na pasta original funcionam no ambiente utilizado.
A documentação e os testes offline não constituem uma repetição instrumental
dessa execução. [Arquitetura e limites](ARCHITECTURE.md#14-integração-operacional-gamescope-eis-2026-10-17).

A seção `[capture]` do `relay_capture.conf` validado mantém:

```ini
inject = true
inject-call = true
move-dispatch = true
action-merge = true
egress-queue = false
sendcall-demand = false
map-settle-ms = 1500
synth-input = true
synth-backend = gamescope-eis
synth-eis-socket-file = /run/user/1000/ro-relay-gamescope-eis.path
synth-key-0437 = INSERT
synth-key-0438 = 9
synth-key-0af4 = F2
itemuse-input = true
itemuse-input-key = END
```

`synth-wid` permanece no INI como compatibilidade, porém é **ignorado**
quando `synth-backend = gamescope-eis`. Esta publicação **não recomenda**
substituir os valores validados por defaults internos. `egress-queue=false`
foi preservado; o teste de launcher foi corrigido para verificar apenas seu
contrato de inicialização em vez de impor `true`.

**Sequência:** Steam abre Gamescope Wayland com `-g
--force-grab-cursor`, executa `scripts/gamescope-eis-session.sh` e
passa o Proton/uaRO ao wrapper. Dentro do compositor, `LIBEI_SOCKET`
é publicado num arquivo 0600 em `XDG_RUNTIME_DIR`; o arquivo é removido
ao final da sessão. O relay lê o socket por
`--synth-eis-socket-file`. Para login, usar mouse/teclado com a janela
ativa; depois, o relay pode enviar eventos ao compositor sem ativar o
KDE. A captura física com `-g` e `--force-grab-cursor` pode dificultar
temporariamente a troca de janelas.

**Diagnóstico:** se o arquivo/socket EIS sumir, o envio de tecla
falhará explicitamente, **sem voltar ao ydotool**. `--synth-dry`
testa o mapeamento sem enviar eventos. Eventos `THIS-CONTEXT`
denunciam suspeita de contexto nativo inválido, sem identificar
automaticamente a causa. `RECV-PLAIN-UNAVAILABLE` indica conteúdo
cifrado sem cópia verificada; não representa dados descriptografados.

**Teste e cobertura:** `tests/test_gamescope_eis.py` valida
isolamento do socket, permissões 0600, frame press/release e ausência
de side effect no KDE em `dry`. `tests/test_launcher_gadget_port.py`
verifica a descoberta da porta do Gadget sem impor política de
`egress-queue`. `bash scripts/test-offline.sh` cobre os contratos
offline, não valida transmissão criptográfica ou conformidade do uaRO.
`research/movement_035f/` usa agora caminhos relativos à raiz para
`data/uaro_recvpackets.txt`, sem modificar experimentos concluídos.
