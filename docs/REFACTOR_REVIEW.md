# Revisão da refatoração operacional — 2026-10-17

Base registrada antes dos patches: `004efd4e298cb7d5824e6e9ee0d0cc73f5d38916`.
Branch: `refactor/minimal-low-latency-relay`. O backup não versionado
`agent/relay_hook_linux.js.bak-byte0fix` preexistia e não integra a entrega.
Nenhum cliente, Gadget, uinput, servidor de jogo ou captura de sessão foi executado.

## Evidência inicial e escopo

**OBSERVADO NO CÓDIGO da base:** `run.sh` delegava ao launcher de pesquisa;
o launcher ativava a FIFO com 400 ms entre despachos e após ações. WriteBack
expirava comandos com 800 ms; o atuador suprimia repetições por opcode por 500 ms,
esperava 250 ms após foco e mantinha teclas por 120 ms. O agente descartava casts
por intervalo; `scr.bodies[id]` sobrescrevia comandos do mesmo opcode.

**Verificação antes dos patches:** suíte de 12 scripts PASS numa cópia imutável
`git archive` da base em `/tmp/ro-relay-refactor-base`. A primeira tentativa no
sandbox falhou por proibição de criar sockets locais; a repetição autorizada fora
dele passou. A suíte usa exclusivamente fixtures, mocks e loopback local.
Não havia teste executando o store `_fix0` nem proteção suficiente de sessões.

**Limitações verificadas:** SendPacket isolada não comprova ações no servidor;
carriers dependem de contexto/entrada do cliente; não foi medida a latência real
informada pelo OpenKore. A refatoração não implementa cifra nem xKore 0.

## Antes e depois

| Aspecto | Base | Refatoração |
|---|---|---|
| Inicialização | launcher de pesquisa e pipe para manter stdin | `exec` de Python; `--wait`; uma configuração |
| Egresso | FIFO temporizada, expiração e debounce | prontidão por ACK nativo e liberação da tecla; sem tempo de expiração |
| Corpos de ação | último corpo por opcode | comandos identificados, uso único e sem sobrescrita |
| Ordem entre rotas | despacho em caminhos assíncronos | próximo comando após conclusão local do anterior |
| Sessões | captura parcial e ponteiros podiam sobreviver | epoch, tokens, piso de tokens e geração do socket |
| Reconexão | 1 s após sucesso antes de ler comandos | backoff apenas se a conexão falhar |
| Pesquisa | Stalker/probes no script padrão | extensão JS e funções Python carregadas sob opção explícita |
| Console | corpos e tráfego contínuo | normal conciso; verbose; ANSI condicional; sanitização |
| Captura normal | JSONL com corpos e flush por linha | metadados sanitizados e buffer; flush no fechamento |

Removidos efetivamente: `_egress_enqueue`, `_egress_drain`, `_egress_q`, opções
exclusivas de intervalo/idade, cast throttle, debounce, seleção experimental
`0368` pré-ação, persistência operacional e recaptura substituída pelo reset de
sessão. Removidos o launcher `research/action_0437_0438/run_action_merge.sh` e o
sidecar `action_trigger.py`. Históricos permanecem preservados; suas referências
a caminhos removidos descrevem a revisão histórica.

## Dependências, threads e sincronização

Nenhuma dependência nova. A identidade do socket usa SO_COOKIE de 64 bits, estável entre descritores duplicados e distinto após reutilização de porta; se indisponível, há aviso explícito e fallback de identidade mais fraco por porta local. Peer/cookie são conferidos na entrada e saída de syscalls; divergência omite bytes com aviso. A constante Linux está na [UAPI oficial](https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/socket.h). Esse custo adicional não foi medido no cliente.

Python usa biblioteca padrão; Frida é importada apenas
na conexão ao Gadget. `xdotool` gerencia foco com `windowactivate --sync`;
`ydotool/ydotoold` mantém o mecanismo uinput já utilizado. Falhas são explícitas.
A espera fixa de foco foi eliminada; a duração de tecla de 120 ms permanece por
ter evidência de necessidade no cliente. Sua redução exige rodada autorizada.

| Execução / estado | Proteção e motivo |
|---|---|
| Callback Frida → worker | `queue.Queue`; transferência de eventos em ordem, sem pacing |
| Sessão / comandos | `RLock`, até 64 comandos incluindo o corrente; ACK libera o próximo |
| Atuador | worker próprio, fila limitada; libera tecla antes do próximo corpo; reset invalida eventos |
| Agente | filas limitadas de defesa; token/epoch; native calls na thread capturada; guards de reentrância |
| WireFeed | Condition/deque em ordem; revisão/epoch e feed atômicos sob Relay.lock; espera apenas evidência de atores |
| ActorDecrypt | lock e instância nova por sessão; descoberta antiga não republica contexto atual |
| Relay | RLock para socket/framing e callbacks de sessão; feed nunca ocorre sob o lock de comandos |

A capacidade limita a interface, não a frequência do jogo. Excesso é falha
registrada, sem promessa de transmissão. Não há relógio que libere ou expire
comandos. Uma operação sem evento nativo pode bloquear as seguintes: isso é
head-of-line por prontidão, observável pelos tokens armados, e não confirmação de
aceitação. Desconectar cancela pendências; comandos já executados não são desfeitos.
A fila de eventos Frida e a recepção continuam sem limite novo de memória: descartar
eventos arbitrariamente comprometeria a reconstrução; sobrecarga continua um risco.

No reset, `_fix0` já comprometido é preservado até o hit seguinte na mesma thread:
o store anterior precisa desse reparo mesmo após cancelar comandos futuros.
ACK `consumed` só ocorre depois do reparo quando ele é necessário. O XOR permanece
`c0 ^ orig0 ^ our0`. Um ponteiro de reparo que deixe de ser legível gera falha
explícita; não há prova offline sobre a duração de objetos nativos entre relogins.

## Latência: reprodução e limites

Comandos equivalentes (movimento, melee, alvo nível 10, chão), 20 amostras,
um comando disponibilizado após o despacho anterior. Base usa a implementação
real da FIFO com intervalo de 400 ms; destino e conclusão nativos são simulados
nos dois casos. Não é teste do jogo nem medição de RTT.

```sh
python3 scripts/benchmark-relay.py --repo /tmp/ro-relay-refactor-base --count 20
python3 scripts/benchmark-relay.py --count 20
```

| Despacho sintético local, ms | mediana | p95 | p99 | máximo |
|---|---:|---:|---:|---:|
| Base | 400.072639 | 400.090191 | 400.093237 | 400.093237 |
| Refatoração | 0.000521 | 0.006482 | 0.007084 | 0.007084 |

**OBSERVADO OFFLINE:** a espera configurada desaparece; não foram medidos ganho
real em combate, tempo da cifra isolada ou latência externa. A ativação de janela
e a duração da tecla são medidas separadamente no verbose; atores preservam
poll de 5 ms, espera máxima configurada de 150 ms e margem de evidência de 30 ms.
Esses custos não devem ser confundidos com a FIFO eliminada.

Instrumentação operacional: `monotonic_ns` no recebimento/dispatch/ACK/entrega;
`clock_gettime(CLOCK_MONOTONIC)` opcional no agente em aceitação, chamada nativa,
SEND e RECV. Sem export/ABI disponível, campos são omitidos. Distribuições
limitadas a 2048 amostras por etapa: mediana/p95/p99/máximo e tamanho da janela.
`local_completion_ms` inclui ida/volta Frida; `native_call_ms` e
`agent_schedule_ms` usam diferenças do mesmo relógio do agente. `receive_ready_ms`
inclui agendamento/recuperação de atores e `consumer_send_call_ms` mede a chamada
local de entrega (inclusive tentativa falha). Não existe associação geral de um
SEND cifrado a um token por tamanho; correlação de resposta/rede fica **NÃO
VERIFICADA** quando não há identidade independente. Não atribuir esses tempos a
cifra ou rede externa por subtração especulativa.

Origem dos ~400 ms mostrados pelo OpenKore: **NÃO IDENTIFICADA no consumidor
instalado**, cuja revisão/plugin de medição não foi fornecida. Conferido código
público OpenKore `51de1ddfc4449ae5217f6886de702f87ca934030`:
[serverSend](https://github.com/OpenKore/openkore/blob/51de1ddfc4449ae5217f6886de702f87ca934030/src/Network/XKore.pm#L127)
enquadra cada mensagem em `S`; [received_sync](https://github.com/OpenKore/openkore/blob/51de1ddfc4449ae5217f6886de702f87ca934030/src/Network/Receive.pm#L8437)
atualiza timeout de conexão, sem calcular RTT. Isso não identifica um plugin
local nem comprova que o indicador do usuário mede exclusivamente o relay.

## Cobertura e pendências de revisão

- PASS: suíte-base, novos testes de readiness/capacidade/cancelamento, JS mock
  executando `_fix0`, FIFO de corpos repetidos, skills nível 10, roteamento
  genérico e política anti-duplicação, frames fragmentados/concatenados,
  reconexão, gerações antigas, sessões de mapa e sanitização de console/JSONL.
- PASS: validadores de pesquisa/configuração; sintaxe Python/JS/shell; diff whitespace.
- NOT RUN: cliente uaRO, Gadget, teclas reais, login/seleção/mapa/teleporte/relogin,
  sobrevivência nativa, aceitação das quatro ações, rajadas e RTT ao vivo.

Os testes da FIFO/debounce antigos foram substituídos por propriedades de ordem,
preservação de bytes e ausência de perda por sobrescrita. Não foram apenas
excluídos para obter suíte verde. O caminho genérico preserva bytes e usa
SendPacket; classes fora das quatro ações não ganham confirmação funcional por
isso. Raw permanece observação; injeção exige framing XKore 1.

Arquivos de cifra protegidos e `research/cipher/` devem estar sem diff contra a
base antes do commit. Nenhum artefato externo/credencial entra na entrega.
O fork na mesma conta do original é impossível; o responsável autorizou depois
uma branch exclusiva no próprio repositório, com um único PR Draft e sem push
na main, force-push ou merge.

Inventário da primeira etapa (antes da consolidação de módulos):

- Adicionados: `agent/research_hooks.js`, `relay/commands.py`,
  `scripts/benchmark-relay.py`, `docs/REFACTOR_REVIEW.md`,
  `tests/test_agent_pending.py`, `tests/test_capture_sessions.py`,
  `tests/test_commands.py`, `tests/test_console_modes.py`,
  `tests/test_transport_session.py`.
- Modificados: `README.md`, `run.sh`, `relay_capture.conf`,
  `relay_capture_linux.py`; `relay/__init__.py`, `agent.py`, `cli.py`,
  `console.py`, `protocol.py`, `relay.py`, `research.py`, `runtime.py`,
  `safety.py`, `synth_input.py`, `wire_feed.py`, `writeback.py`;
  `agent/relay_hook_linux.js`; `docs/ARCHITECTURE.md`,
  `docs/OPERATIONS.md`, `docs/GEPARD_CONTROL_PACKETS.md`;
  `tests/test_synth_input.py`, `tests/test_writeback.py`.
- Removidos: os dois arquivos de launcher/sidecar listados acima.

O agente operacional passou de 897 linhas na base para aproximadamente 740, e WriteBack de 376 para cerca de 220 (contagens incluem comentários e não medem complexidade sozinhas).
A redução está no caminho carregado por padrão: sondas e send-watch saíram do
agente operacional e os imports Python de pesquisa são tardios, inclusive na
fachada de compatibilidade. O repositório inteiro ganhou testes e garantias de
sessão; contagem total de linhas não é uma medida de latência ou correção.

Próxima decisão: revisar o Draft e autorizar, separadamente, cada rodada ao vivo.
O primeiro cenário proposto é conexão limpa/login/mapa e uma ação de cada tipo,
com processo relay, cliente já autorizado e OpenKore; parar no primeiro erro,
desconexão inesperada ou desvio de destino. Só executar após aprovação específica
do cenário, comandos, processos e impacto.


## Consolidação posterior — base `0e6e3e7`

**OBSERVADO OFFLINE:** cinco fusões reduzem `relay/` de 18 para 13 arquivos Python,
incluindo `__init__.py`. Não foram criados shims para manter os nomes de módulos
antigos. Símbolos da fachada `relay_capture_linux.py` permanecem disponíveis.

| Arquivos anteriores | Arquivo canônico |
|---|---|
| `config.py` + `cli.py` | `cli.py` |
| `commands.py` + `writeback.py` | `client_dispatch.py` |
| `agent.py` + `protocol.py` | `frida_bridge.py` |
| `actors.py` + `memory.py` | `actor_recovery.py` |
| `packets.py` + `wire_feed.py` | `packet_pipeline.py` |
| `runtime.py` | `capture_runtime.py` |
| `relay.py` | `xkore_transport.py` |
| `console.py` | `event_log.py` |
| `safety.py` | `traffic_safety.py` |
| `sendwatch.py` | `send_recovery.py` |
| `synth_input.py` | `synthetic_input.py` |
| `research.py` | `research_diagnostics.py` |

A fusão do dispatcher troca herança por composição e remove o transporte implícito
de token/epoch por `threading.local`. Os comandos passam explicitamente ao roteador;
posts de controle não herdam metadados de um comando. A ordem de locks e as cercas
de sessão permanecem. As demais fusões mantêm os algoritmos e fronteiras de efeito:
importar funções puras não conecta ao Gadget, não abre sockets nem lê `/proc`.
O Frida continua importado somente no construtor da conexão.

Imports e patches de mocks foram migrados nos testes, benchmark e `ro_ops`.
Documentação operacional e `AGENTS.md` apontam aos nomes atuais. Referências em
históricos e nos arquivos protegidos de cifra permanecem literais e se referem às
revisões que as originaram; não são imports executáveis do núcleo atual.

Verificações da etapa: suíte antes PASS (17 scripts); suíte depois PASS (18 scripts),
incluindo regressões de metadados explícitos/controle independente e importação
dos módulos consolidados sem abrir sockets, processos ou memória do cliente. Não foi
realizada medição nova no cliente. A consolidação não constitui evidência de ganho
de RTT; permanecem as mesmas limitações e exigência de autorização por rodada viva.

Os testes operacionais também receberam nomes alinhados às responsabilidades: `test_cli_config`, `test_client_dispatch_routes`, `test_client_readiness`, `test_actor_recovery`, `test_packet_pipeline`, `test_frida_agent`, `test_event_log_modes`, `test_send_recovery`, `test_synthetic_input`, `test_traffic_safety` e `test_xkore_*`. O benchmark mantém seleção explícita de módulos antigos apenas para reproduzir revisões arquivadas anteriores à consolidação.

A revisão independente do dispatcher composto foi PASS (estática). Uma comparação AST contra `0e6e3e7` confirmou 31 funções/classes idênticas nas quatro fusões mecânicas; o dispatcher foi verificado pelos testes de readiness, roteamento, sessões e controle. `validate-research.py`, `validate-codex.py`, compilação Python, help do launcher e `git diff --check`: PASS.

## Diagnóstico de bloqueio após a refatoração

Base do diagnóstico: `700950a`. O responsável relatou falha de movimento e ações
em uma rodada executada por ele e autorizou leitura **local de metadados** do
log. O agente não iniciou cliente, OpenKore, input sintético nem teste ao vivo.
Nenhum corpo, credencial, ponteiro ou captura bruta integra este registro.

**OBSERVADO nos metadados autorizados:** cinco ACKs de arme `0437`, cinco
liberações de input, quatro escritas e quatro consumos. O último comando armado
não teve escrita nem terminal até a desconexão. Houve 443 recusas por capacidade;
a desconexão cancelou 64 comandos sob controle da pipeline. As estatísticas de
atores continuaram registrando recuperação fresca. Isso não comprova integridade
de toda a recepção, mas não aponta falha de recuperação como origem do bloqueio.

**OBSERVADO no código / reproduzido offline:** uma ação sem terminal mantém
`CommandPipeline.current`. Os comandos seguintes permanecem pendentes, inclusive
`035F` e `0438`, até esgotar a capacidade global. Essa dependência global foi
introduzida na refatoração, não na fusão dos módulos. A suíte anterior passou,
mas não demonstrava disponibilidade quando o carrier não aparece. A ausência
de `wrote` no comando bloqueador não indica falha de `_fix0`: o reparo sucede
uma escrita que não foi observada nessa ocorrência.

**Correção de diagnóstico:** erros de capacidade agora mostram o opcode recusado,
opcode/token bloqueador, etapa, ocupação e tempo local. IDs aparecem em hexadecimal
nos dois modos. A liberação da tecla sem terminal gera uma indicação explícita de
espera; o início do despacho das quatro ações é visível sem dumps. Descrições de
erro usam códigos públicos fixos; texto arbitrário de exceção não vai ao console.
Exceções de despacho persistem somente o tipo, sem sua mensagem potencialmente
sensível. Não houve mudança de sincronização, cancelamento, rotas ou `_fix0`.

**NÃO VERIFICADO / regressão aberta:** por que o cliente não produziu o carrier
correspondente. O log não distingue input não processado, foco incorreto, evento
nativo tardio ou outra condição do cliente. Liberação da tecla não é um evento
negativo de consumo. Não há mecanismo demonstrado para encerrar essa espera sem
tempo arbitrário, cancelamento explícito ou mudança de ordenação. Logo este patch
de observabilidade **não restaura a disponibilidade** e não deve ser apresentado
como correção funcional. O PR permanece Draft, com esse bloqueio conhecido.

Os novos testes reproduzem a falta de consumo, identificam bloqueador e recusas,
verificam que não se fabrica confirmação de envio e exercitam cancelamento
explícito seguido de avanço ordenado. Uma investigação adicional deve observar
foco/input e geração do carrier em uma rodada separadamente autorizada; não
reabrir a pesquisa encerrada de cifra de movimento/ações nem alterar `_fix0`.

Verificações desta etapa: suíte offline completa antes/depois **PASS (18 scripts)**;
readiness e console **PASS (8 casos cada)**; revisão independente do patch **PASS**;
`validate-research.py`, `validate-codex.py` e `git diff --check` **PASS**.
Teste ao vivo executado pelo agente **NOT RUN**. Os arquivos protegidos da cifra,
o agente JS e a configuração permaneceram sem alterações nesta etapa.
