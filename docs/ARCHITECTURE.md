# Arquitetura técnica do RO-Client-Relay

> **Revisão local:** 2026-10-15, `main@524b0f05fa61872e140f98ace9e503d12356641e`. Implementação conferida estaticamente; nenhum experimento vivo repetido. Dados técnicos anteriores preservados em [HISTORY/ARCHITECTURE_LEGACY.md](HISTORY/ARCHITECTURE_LEGACY.md), com ressalvas sobre hipóteses históricas. Estado científico em [RESEARCH_STATUS.md](RESEARCH_STATUS.md).

## 1. Fronteiras de responsabilidade

| Unidade | Responsabilidade | Fonte verificável | Não é sua responsabilidade |
|---|---|---|---|
| OpenKore externo (Perl) | Escolher ações, produzir/consumir pacotes, usar seu próprio xKore 1 | `README.md` da raiz e [decisões](RESEARCH_DECISIONS.md) | O relay **não** deve reimplementar o bot/xKore |
| Driver `relay_capture_linux.py`/`relay/` | Conectar ao Gadget, interpretar eventos, manter ordem e identidade de conexões, reconstruir/validar pacotes, enquadrar XKore, opcionalmente pedir escrita ao cliente | `relay/runtime.py`, `relay/wire_feed.py`, `relay/relay.py`, `relay/writeback.py` | Não tentar cifrar tráfego com algoritmo não demonstrado |
| Agente `agent/relay_hook_linux.js` | Instrumentação Frida in-process sob Wine/Proton; relatar `recvmsg`/`sendmsg`, snapshots e observações opcionais, instalar/remover sondas de execução sob controle | `agent/relay_hook_linux.js`, `relay/protocol.py` | Não deve bloquear o jogo com varreduras extensas de memória |
| Cliente uaRO/Gepard | Produz/cifra pacotes no caminho real e mantém estado operacional de protocolo durante xKore 1 | [arquitetura legada](HISTORY/ARCHITECTURE_LEGACY.md) §§2–10, controles documentados | Não há prova da função F criptográfica para implementação sem cliente |
| Futuro plugin OpenKore | Quando fundamentado, manejar protocolo/sessão no xKore 0 **dentro do projeto OpenKore** | [decisões](RESEARCH_DECISIONS.md) | Não pressupõe backend xKore 0 neste repositório |

```text
 servidor uaRO  ◄──── cliente uaRO (Wine/Proton) ── Frida Gadget ──► driver Python ──► OpenKore xKore 1
      ▲            pacote cifrado conforme cliente       eventos     reconstrução     quadros R/S
      │                                 ◄──────── solicitações instrumentadas ──────┘
      └──────── envio real feito pelo cliente, se opção/ação autorizada estiver habilitada ───────┘
```

A figura é **esquemática**: nunca indica um canal direto de envio da rede pelo driver. O driver comunica-se com o consumidor XKore; o cliente real permanece responsável pelos writes na etapa intermediária.

## 2. Organização do código

| Caminho | Contrato técnico documentado |
|---|---|
| `relay_capture_linux.py` | Ponto de entrada; compatibilidade por reexportação para testes históricos |
| `relay/protocol.py` | Tags/campos de mensagens agente-driver (`ring`, `sendwatch`, `scramble`, `sendcall`, `trace`) e identidade de conexão |
| `relay/agent.py` | Localização/conexão ao Gadget, carregamento do script, encaminhamento de mensagens; único módulo Python que importa `frida` conforme arquitetura legada |
| `relay/config.py` e `relay/cli.py` | Config INI `[capture]`, precedência de defaults, argumentos e ciclo de vida do CLI |
| `relay/runtime.py` | `Capture` instancia pipeline, despacha mensagens, coordena threads/estado |
| `relay/wire_feed.py` | `WireFeed`: ordenação de trechos `RECV`, espera limitada por conteúdo verificado; `ClientSendFeed`: caminho de envio observado |
| `relay/packets.py` | Tamanhos e fragmentação de pacote, `WireFilter`, `pack_move`, `unpack_pos2`, `MoveTracker` |
| `relay/actors.py` | `ActorDecrypt`: ring e aceitação somente de cópias decifradas verificadas (`09fd`/`09ff`) |
| `relay/relay.py` | Frames XKore, conexão/reconexão, alinhamento opcional |
| `relay/writeback.py` | Merge de corpo para `035f`, `SendPacket` para ações da fila, autodescoberta e sondas pertinentes |
| `relay/sendwatch.py` | Acompanhamento das escritas na fila, inferência conservadora de texto claro |
| `relay/memory.py` | Consulta `/proc/<pid>/maps` e acesso **somente leitura** a `/proc/<pid>/mem` |
| `relay/safety.py` e `relay/console.py` | Redação de credenciais, tráfego HTTP e logs de depuração |
| `relay/research.py` | Diagnósticos de atores e verificações especializadas |
| `agent/relay_hook_linux.js` | Instala e remove hooks/snapshots/instrumentação conforme mensagens; observa a própria thread do cliente |
| `data/uaro_recvpackets.txt` | Referência de tamanhos para framing; **não** especifica por si só semântica de sessão |
| `research/cipher/`, `research/movement_035f/` | Ferramentas e análises experimentais, separadas da lógica operacional |

## 3. Recepção: servidor → cliente → quadro `R`

1. O cliente recebe dados em um socket; o agente reporta `RECV` e snapshots correspondentes da ring de recepção **antes** da modificação relevante.
2. `WireFeed.on_recv`/`WireFilter` acumulam segmentos por conexão e aplicam a tabela conhecida para delinear os pacotes; não buscar um ID plausível arbitrário para resincronizar um fluxo inválido.
3. Corpos reconhecidamente claros são encaminhados; `09fd`/`09ff`, cujos corpos exigem acesso às cópias do cliente, criam itens pendentes.
4. A thread alimentadora espera até um limite configurável (documentação original refere padrão `--actor-delay` de 0,15 s), durante o qual `ActorDecrypt` tenta ler/verificar a cópia já decifrada em `/proc/<pid>/mem`.
5. Se a verificação não se sustentar, **não fabricar o corpo decifrado**: descartar o pacote não confirmado; preservar ordem de chegada para os demais.
6. O `Relay` enquadra o fluxo como quadros `R` para o consumidor XKore 1. A identidade da conexão é mantida internamente para tokenização e reconstrução; o frame contém tipo, comprimento e payload, sem campo de ID de conexão (`relay/relay.py:14`).

**Invariantes:** enquadramento com base na tabela correta; delimitação por conexão, em vez de misturar sockets cujos FDs foram reutilizados pelo Wine; ordem global dos trechos recebidos; nenhuma inferência de bytes ausentes; conteúdo HTTP/login tratado por regras de segurança. Fontes: `relay/wire_feed.py`, `relay/packets.py`, `relay/actors.py`, `relay/safety.py` e [arquitetura histórica §4](HISTORY/ARCHITECTURE_LEGACY.md).

## 4. Envio observado: cliente → servidor → quadro `S`

1. O cliente grava o pacote em seu caminho de envio. Para ações da fila, a sonda `sendwatch` pode observar bytes pré-transformação e sua posterior alteração, sem redefinir esses bytes como estado criptográfico.
2. `sendmsg` registra o envio; o agente emite `SEND` com sua identidade de conexão e eventual janela de acompanhamento pertinente.
3. O driver sanitiza login/HTTP e dados sensíveis (`relay/safety.py`), e `ClientSendFeed` transmite somente material que atenda aos requisitos de fidelidade, enquadrado como `S`.
4. No modo de escrita, `--feed-send` é automaticamente desativado com `--inject`, para evitar recirculação de pacotes enviados pelo próprio cliente (fonte: [arquitetura histórica §6](HISTORY/ARCHITECTURE_LEGACY.md)).

**Atenção:** um `sendmsg` cujo retorno coincide com o tamanho de `035F` é evidência de transporte **correlacionado**, não prova de identidade do conteúdo sem buffer/fonte independente ([pré-condições](MOVEMENT_035F_PRECONDITIONS.md) §5).

## 5. Caminhos de escrita e sincronização

| Caminho | Origem e implementação | Classes observadas | Limite essencial |
|---|---|---|---|
| `--inject-call` / `SendPacket(this,len,buf)` | Objeto da rotina capturado por BP de execução DR1; chamada efetiva na thread do jogo | Ações de fila `0437`/`0438`, conforme sessão documentada | `035f` pelo caminho de fila foi associado a **dessincronização** da sessão documentada de 2026-10-13 |
| `--inject` + `--scramble-bp` / merge | Substitui corpo de pacote **já montado pelo próprio cliente**, no store pré-transformação, normalmente com DR0; uso único por padrão | `035f` na pilha, 3 bytes de destino | **Reativo**: requer que o cliente produza naturalmente um `035f`; não sintetiza intenção autônoma |
| Autodescoberta opcional | Watch de escrita em ações de fila para recuperar PC do store, depois migrar a BP de execução para a posição real | `0437`/`0438` conforme fluxo documentado | Endereços/faixas dependem do build; não tratar offsets antigos como universais |

O modo combinado distribui `035f` ao merge e os demais ao `SendPacket`, mantendo canais de debug distintos. `--inject-persist` é inadequado como regra automática para andar porque repetiria o destino em todos os passos naturais. Sem alteração explícita do responsável, preservar **`inject = true` e `inject-call = true` em `relay_capture.conf`**, apesar de defaults internos distintos.

**Cuidado terminológico:** chamar o breakpoint `gepard+0x18eff2` de *store de corpo* não prova que a operação criptográfica é realizada nessa própria instrução. A investigação mais recente encontrou uma cadeia de **cópias de bytes** que antecede o store sem identificar o produtor criptográfico ([CIPHER_INVESTIGATION](CIPHER_INVESTIGATION.md)).

## 6. Threads, concorrência e estado compartilhado

| Execução | Responsabilidade | Proteção/contrato |
|---|---|---|
| Callback Frida (`Agent._message`) | Só enfileirar mensagens; não bloquear o jogo | Fila de trabalho |
| Worker (`Capture.run_worker`) | Despacho sequencial em ordem: `RINGSNAP`, `RECV`, `SEND`, sinalização Gepard/sondas | Mensagens de um pipeline devem preservar identidade/ordem |
| Alimentadora `WireFeed.run` | Aguarda elementos pendentes; consulta periodicamente cópia validada; entrega na ordem | `WireFeed.cond` protege pendências/snapshots |
| Relay | Conexão/reconexão ao consumidor, recepção do retorno `S`, roteamento da escrita | `Relay.lock` e contrato do enquadramento |
| Caminho in-process de escrita | Drenagem na thread do jogo, sem chamada arbitrária do driver como se fosse socket | `NativeFunction`/estado de `sendcall` controlados pelo agente |
| Busca/decifragem | Descoberta de ring e cópias verificadas | `ActorDecrypt.lock`; atualizar stream por substituição de atribuição |

`ActorDecrypt` usa estado compartilhado para região, contadores e trechos; mapa de corpos e objeto `this` capturado são atualizados pelo agente sob seu ciclo de execução. `relay_capture.conf`/CLI distinguem capacidades configuradas e efetivamente exercidas: definir uma flag não comprova que a instrumentação encontrou o callsite.

## 7. Pesquisa de movimento como subsistema separado

**OBSERVADO no build estudado:** dispatcher no código anônimo referenciado ao endereço `0xd473b0`; caminho `0x11 → 0x0D → 0x5B → 0x8A`, com receptor virtual `gepard+0x10A90`; preparação de campos no dispatcher e store compartilhado `gepard+0x18eff2`. No ensaio 6.4 com transporte observado independentemente, chamar só `0x8A` não produziu `035f`/`sendmsg` atribuível. Não é uma API de movimento autônomo demonstrada.

**Não confundir bases:** RVA do PE `uaRO.exe` em `0x400000` versus offsets do código anônimo em `0x401000` (diferença `0x1000`); base da DLL Gepard muda ao relogar. **Não hardcodar absolutos** para outros builds.

**Leitura corrigida de §13 (`888764a`, preservado no pull):** houve conteúdo de buffer compatível com o destino no trap **anterior** ao store, sem prova de escrita concluída, pacote finalizado, envio ou resposta. O dispatcher tem epílogo nativo `ret 0x34` (52 bytes), enquanto a chamada usada empilha 44 bytes: desequilíbrio de 8 bytes na versão inicial. O ensaio posterior de 52 bytes (§13.5, `7a64581`) também travou, refutando nesse recorte a explicação exclusivamente por esses 8 bytes. Reentrância/contexto permanecem hipóteses. Não tratar o endereço de retorno Gepard como prova de VM sem retorno. H2/H3 continuam não isoladas; reentrância permanece hipótese. As exclusões de §12 continuam restritas ao callsite e aos 1024 B bidirecionais/128 B do registro global; TLS, indireções e offsets fora da cobertura não foram excluídos. O gate com constante `0x15E` tem unidade não identificada. Estudos completos: [MOVEMENT_035F_INVESTIGATION](MOVEMENT_035F_INVESTIGATION.md), [MOVEMENT_035F_PRECONDITIONS](MOVEMENT_035F_PRECONDITIONS.md).

## 8. Limites do conhecimento da cifra e dos controles

- `gepard+0x18eff2 mov [ecx],bl` é uma âncora de escrita executada em recortes definidos, mas não uma prova isolada de XOR, estado, tamanho de keystream ou algoritmo.
- `SC_GEPARD_INIT`, `CS_GEPARD_INIT_ACK`, `CS_GEPARD_SYNC` são designações documentadas para **Gepard 2016**, não equivalências automaticamente demonstradas no uaRO atual.
- `0x8280` tamanho 128 na tabela não demonstra direção, heartbeat ou estrutura. O registro apropriado é [GEPARD_CONTROL_PACKETS](GEPARD_CONTROL_PACKETS.md).
- A investigação dinâmica recente identificou escritor de byte `+0x1C752B`, cópias intermediárias e consumidor `+0x18EFF2`; faltam última definição de CL, região de estado, fronteiras P/C e inicialização, inclusive para `xKore 0`.
- A análise dos [históricos Gepard](HISTORY/GEPARD_LEGACY.md) e [arquitetura §§5,9,10](HISTORY/ARCHITECTURE_LEGACY.md) contém hipóteses históricas expressas com maior certeza que a evidência atual suporta. Este documento qualifica tais conclusões sem apagar endereços/recortes antigos.

## 9. Referência de operação e testes

Detalhes operacionais em [OPERATIONS](OPERATIONS.md); conjunto offline `bash scripts/test-offline.sh`, verificadores de documentação em `scripts/validate-research.py` e `scripts/validate-codex.py`; limitações de cobertura explicitadas no [estado atual](RESEARCH_STATUS.md). Não executar cliente, probes dinâmicas, CEServer ou Frida como parte de manutenção documental.

## 10. Preservação e evidência implementacional

O histórico integral da arquitetura foi movido para [HISTORY/ARCHITECTURE_LEGACY.md](HISTORY/ARCHITECTURE_LEGACY.md);
o histórico Gepard sanitizado está em [HISTORY/GEPARD_LEGACY.md](HISTORY/GEPARD_LEGACY.md).
Os caminhos de raiz são redirecionamentos. Mapa e prova de preservação em [DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md).

Âncoras verificáveis na revisão local: `relay/runtime.py:35` (fila), `relay/wire_feed.py:47`
(conexões), `relay/protocol.py:124` (identidade), `relay/relay.py:14` (frame) e
`relay/safety.py:25` (sanitização). Os testes offline validam contratos; não comprovam
segurança ou funcionamento da instrumentação no cliente atual.

## 11. Detalhes de escrita confirmados no código atual

A drenagem não depende só de `recvmsg`/`sendmsg`: o agente também instala hooks nas
exportações disponíveis `poll`, `ppoll`, `select`, `pselect`, `pselect6`
(`agent/relay_hook_linux.js:732`). `drainSendCall` exige a thread do jogo (`:617`).
A afirmação histórica de latência ~700 ms causada exclusivamente pelos hooks de tráfego
não descreve o código atual. Frequência e latência atuais não foram medidas nesta revisão.

`relay/writeback.py:224` extrai GID no offset 6 de `0438` (mínimo 10 bytes) ou no offset 2
de `0437` (mínimo 7, GID não zero). Somente com `--target-select` (default OFF desde 2026-10-16)
envia seleção `0368` antes da ação, e apenas quando o GID muda; cache `_last_select_gid` evita
flood. A remoção do `0368` **não** fez ataque/perícia executarem (REFUTADO, ver
[GEPARD_CONTROL_PACKETS](GEPARD_CONTROL_PACKETS.md)). IDs `0368/0369/0193/0094/0360` recebidos do
consumidor são ignorados nesse caminho (`:23`, `:234`). No dreno do agente, `0438/0af4`
com intervalo desde o último cast menor que `castMs` são descartados, sem reenfileirar (`agent/relay_hook_linux.js:617`).
A configuração de 0,8 s vira 800 ms; isso é política atual de writeback, não descoberta
sobre requisitos criptográficos do servidor. `tests/test_writeback.py:63` cobre seleção,
deduplicação, IDs ignorados e encaminhamento de `cast_ms` por doubles.

## 12. Proteções identificadas no build atual — conteúdo integrado pelo pull

**OBSERVADO e confirmado pelo responsável no DiE (2026-10-15):** `uaRO.exe` é PE32/x86,
protegido por Themida/WinLicense 3.XX; `gepard.dll` usa VMProtect. Foram analisados os
mesmos arquivos usados nas pesquisas atuais. Isso identifica os protetores dos arquivos,
sem atribuir automaticamente funções ou regiões anônimas à virtualização de um deles.
Origem: commit `77954b2`, incorporado em `origin/main@0a29193`.
Relatório completo: [PROTECTION_FINGERPRINT_DIE.md](PROTECTION_FINGERPRINT_DIE.md).
