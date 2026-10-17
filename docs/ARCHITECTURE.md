# Arquitetura técnica do RO-Client-Relay

Revisão operacional: 2026-10-17. Base anterior `004efd4`; refatoração validada
somente offline. Auditoria, comparação temporal e limitações em
[REFACTOR_REVIEW](REFACTOR_REVIEW.md). Estado científico em
[RESEARCH_STATUS](RESEARCH_STATUS.md); registros anteriores em
[HISTORY/ARCHITECTURE_LEGACY](HISTORY/ARCHITECTURE_LEGACY.md).

## 1. Responsabilidades

OpenKore externo implementa xKore 1 e decide ações, frequência, ordem, retentativas
e cooldowns. O relay transporta os pacotes e usa o cliente uaRO para operações
nativas de protocolo/cifra. Não contém outro backend xKore nem um bot.
O futuro xKore 0 depende da pesquisa da cifra e de integração no OpenKore.

## 2. Componentes operacionais

| Componente | Responsabilidade |
|---|---|
| `run.sh`, `relay_capture.conf` | launcher único, configuração principal, precedência CLI |
| `relay/cli.py`, `agent.py` | montagem e conexão ao Gadget; extensão de pesquisa só sob opção |
| `relay/relay.py` | socket OpenKore, framing XKore e gerações de conexão |
| `relay/commands.py` | prontidão, ordem entre rotas, capacidade, cancelamento e tempos locais |
| `relay/writeback.py` | roteamento de comandos; sem política de ritmo |
| `relay/synth_input.py` | carrier natural via uinput após ACK de arme; liberação da tecla |
| `relay/runtime.py` | worker de eventos e coordenação de sessão |
| `relay/packets.py`, `wire_feed.py`, `actors.py` | delimitação TCP por conexão e recuperação validada |
| `relay/safety.py`, `console.py` | sanitização, console normal/verbose e log |
| `agent/relay_hook_linux.js` | captura e execução nativas, store de merge e `_fix0` |
| `agent/research_hooks.js`, `relay/research.py` | probes/Stalker/diagnósticos opcionais |

Nenhuma dependência nova. Frida é carregada em runtime; os testes usam mocks.

## 3. Recepção: servidor → cliente → OpenKore

O agente observa `recvmsg` e snapshots da ring antes da próxima sobrescrita.
`WireFilter` remonta pacotes por identidade de conexão (SO_COOKIE quando disponível) e tabela de comprimentos,
fixos ou variáveis. Fluxos desconhecidos mantêm o fallback raw anterior, com aviso;
não se procura arbitrariamente um opcode para realinhar o pipeline padrão.
Tráfego HTTP não é interpretado como Ragnarok e é sanitizado.

`09FD` e `09FF` entram em pendências ordenadas. `ActorDecrypt` só aceita cópias
com evidência de frescor/contexto; sem evidência o corpo é descartado, nunca
fabricado. A política conservadora de recuperação permanece: poll de 5 ms,
espera configurável de 150 ms e margem de 30 ms para evidência fresca. Chunks
claros sem predecessores pendentes saem imediatamente. O desconhecimento da
cifra não foi substituído por suposição de plaintext.

A entrega usa frames `R + uint16_le(tamanho) + payload`. A geração do socket
impede entregar chunks antigos a uma nova conexão OpenKore. O framing XKore
não possui campo de conexão; a identidade permanece interna, por stream.

## 4. Comandos: OpenKore → cliente → servidor

Quadros `S` fragmentados/concatenados no TCP são remontados antes de chamar o
roteador. Cada mensagem XKore válida é preservada em bytes. O contrato de
injeção exige mensagens de pacote XKore 1; raw é observação.

| Classe | Rota | Conclusão local usada para prontidão |
|---|---|---|
| `035F` | dispatcher nativo na thread do cliente | retorno do dispatcher |
| `0437`, `0438`, `0AF4` | corpo one-shot no carrier natural, pré-XOR | corpo consumido, `_fix0` aplicado quando necessário e tecla liberada |
| Demais | SendPacket nativa com contexto capturado | retorno da chamada, sem promessa de envio/aceitação |
| `0368/0369/0193/0094/0360` | omissão observável herdada | cliente já produz esses pedidos; evita duplicação |

Não existe allowlist fechada de quatro pacotes para entrada. O fallback genérico
não demonstra que todos os pacotes têm suporte funcional no servidor. Pacotes
especiais com comprimento inválido falham explicitamente. Não se entrega o
`035F` cru à SendPacket: o cliente monta o movimento no dispatcher funcional.

Cada comando tem token e epoch. Só há um comando nativo operacional corrente;
as pendências limitadas preservam os demais até o evento real de conclusão.
O próximo corpo não é armado enquanto a tecla anterior continua pressionada.
As filas internas do agente são defesa adicional para callers diretos; corpos
consecutivos do mesmo opcode não se substituem. Limite de capacidade produz
falha explícita. Não há intervalo mínimo, expiração por idade, debounce ou
cooldown imposto pelo relay. A duração de tecla necessária é preservada.

Arme, retorno de função, merge e execução local não confirmam aceitação pelo
servidor. `SEND` observado é transporte independente; tamanho sozinho não vincula
ciphertext a um comando. As confirmações funcionais anteriores do responsável
continuam registradas em [ACTIONS_COMPLETE](HISTORY/ACTIONS_COMPLETE.md) e
[MOVEMENT_COMPLETE](HISTORY/MOVEMENT_COMPLETE.md); esta refatoração não as repetiu.

## 5. Sessões e ponteiros

A conexão OpenKore só é publicada após reset. EOF/falha de transporte suspende
comandos, cancela pendências e limpa framing parcial, corpos, input e contextos
nativos. Uma nova conexão incrementa epoch e geração; trabalho antigo não é
reexecutado. O cliente pode manter sua conexão legítima com o servidor.

Uma nova identidade de conexão de mapa invalida contextos e comandos pelo piso
de tokens, preservando o epoch de rede para não perder fragmentos já observados
da nova conexão. Eventos da conexão substituída são rejeitados. ActorDecrypt é
substituído e sua evidência antiga não pode alimentar a instância nova.

Objetos `this` de movimento e SendPacket exigem recaptura passiva após reset.
Não há suposição de validade de ponteiros antigos. Mudanças de objetos nativos
sem alteração observável da conexão continuam dependentes de validação ao vivo.

O `_fix0` já comprometido permanece até o hit seguinte na mesma thread. Sua
identidade XOR não mudou; o ACK é posterior ao reparo. Cancelar um comando
futuro não autoriza deixar o store anterior corrompido. Trabalho já transmitido
não pode ser retroativamente cancelado.

## 6. Concorrência, diagnóstico e pesquisa

Callback Frida apenas transfere eventos a um worker. WireFeed tem alimentadora
própria e Condition; entrada sintética tem worker próprio. Relay protege socket
e framing com RLock; CommandPipeline protege sessão e pendências com RLock.
A ordem é Relay.lock → commands.lock; revisão e entrega de chunks dividem a
mesma cerca de sessão, evitando inversão e entrega tardia após troca de mapa.
Os locks do decifrador protegem evidência, não cadência de jogo.

O console padrão suprime tráfego contínuo e mostra operação/sessão/erros.
`--verbose` acrescenta eventos e tempos. `NO_COLOR`, TTY e `--no-color` controlam
ANSI. Verde é reservado a evidência de wire, nunca a enfileiramento ou função
retornada. Log normal contém metadados; verbose conserva sanitização de login e
HTTP. Corpos de ACKs operacionais são removidos dos dois modos e do JSONL.

Medições monotônicas e distribuições por etapa estão descritas na
[auditoria](REFACTOR_REVIEW.md#latência-reprodução-e-limites). Não há RTT do jogo
medido nesta revisão. A cifra permanece responsabilidade do cliente; somente a
pesquisa especializada pode identificar seu algoritmo/estado. As ferramentas,
algoritmos de referência e arquivos protegidos de cifra permanecem intactos.
