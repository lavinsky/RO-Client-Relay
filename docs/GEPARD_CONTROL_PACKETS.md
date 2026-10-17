# Registro de pacotes de controle e sessão — Gepard / uaRO


<!-- CIPHER-SPECIALIST-REFERENCES-2026-10-17 -->

## Dependência de login, unidades de cifra e sincronização — atualização 2026-10-17

**FONTE TÉCNICA ESPECIALIZADA — ALTA CONFIANÇA:** variantes reais contemporâneas do Gepard utilizam seed/constantes para inicialização de tabela mutável (256 bytes) e posições de estado, seguidas por atualização por byte. O responsável confirmou que valores relacionados à cifra são entregues ao cliente no login. **Ainda não está identificado** se esses campos são seeds, outros parâmetros ou estado já derivado, nem se há unidade independente para envio, recepção e sincronização no uaRO.

**Limite do `0x8280`:** periodicidade e origem Gepard relatadas/observadas continuam válidas nos recortes históricos; **não** foi demonstrado que o pacote carregue seed, inicialize estado, dispare rekey ou corresponda binariamente ao `0x8285` do código de 2016. Tratar como **dependência de protocolo para investigação da cifra/xKore 0**, sem reabrir a pesquisa funcional de ataque ou postulá-lo preâmbulo por ação.

**Perguntas discriminatórias:** quais valores de login chegam a qual inicializador? Qual sequência e direção de unidade é afetada? Quando uma unidade é criada, evolui ou resetada? Há vinculação entre `0x8280` e estado da unidade criptográfica? Versão, ID, direção, estrutura e capturas sanitizadas devem fundamentar qualquer equivalência.

Documentação detalhada e variantes integrais: [CIPHER_INVESTIGATION.md](CIPHER_INVESTIGATION.md#cipher-specialist-20261017).
**Atualização canônica 2026-10-17:** ataque automático `0437`, skill automática em alvo `0438` e skill automática no chão `0AF4` **FUNCIONAIS** conforme responsável. Defeito real da fase ACT-03: byte 0 do corpo do consumidor era reescrito pelo store do scrambler após merge no Frida; `_fix0` corrigiu. Hipóteses de seleção/alcance como causa raiz estão **SUPERADAS**. Apenas a pesquisa da cifra segue aberta. [Conclusão de ações](HISTORY/ACTIONS_COMPLETE.md#source-docs-action-0437-0438-investigation-md). O texto antigo abaixo mantém negativos e hipóteses como histórico, não falha operacional vigente.

**Objetivo:** reter evidências verificáveis para avaliar futuramente um plugin OpenKore de protocolo/sessão independente do cliente (xKore 0). Este arquivo **não** é uma implementação, especificação final de wire protocol ou prova de compatibilidade entre builds.

## Evidências disponíveis

- **Build servidor 2016 (referência histórica, não verificada no uaRO atual):** a investigação documenta unidades independentes `recv_crypt`, `send_crypt`, `sync_crypt`; inicialização `SC_GEPARD_INIT`; resposta `CS_GEPARD_INIT_ACK`; sincronização periódica `CS_GEPARD_SYNC`. Origem relatada: `docs/HISTORY/GEPARD_LEGACY.md` §3 e `docs/HISTORY/ARCHITECTURE_LEGACY.md` §5.1. O código histórico não está versionado (`relay/resources/` é ignorado).
- **uaRO, tabela de tamanhos:** `data/uaro_recvpackets.txt` contém `8280 128`, `4754 -1`, `5395 -1` e `C392 -1`. A presença na tabela **não demonstra** direção, papel no handshake ou associação exclusiva ao Gepard.
- **uaRO, hipótese de heartbeat:** `docs/HISTORY/GEPARD_LEGACY.md` §3.3 associa `0x8280` ao heartbeat de 128 bytes; no histórico 2016 a nota associa `0x8285` ao nome `CS_GEPARD_SYNC`. A equiparação entre builds é uma **inferência**, ainda não uma especificação validada.
- **Login:** `docs/HISTORY/GEPARD_LEGACY.md` §1 documenta login uaRO via HTTP/token e char server sem camada Gepard. Isso **não identifica o ID ou a sequência exata** do pacote de inicialização/sincronização da cifra na sessão de mapa.

<!-- SESSION-AUDIT-20261017-BEGIN -->
## Auditoria de login, entrada e permanência no mapa — 2026-10-17

**ID:** `GEPARD-SESSION-20261017-01`. Escopo autorizado nesta conversa: observar os
pacotes do cliente desde o login até dez segundos no mapa e investigar os controles
desconhecidos. Não houve injeção, input sintético, suspensão ou breakpoint de hardware.

**Procedência:** uaRO/Wine local; SHA-256 `uaRO.exe` =
`f2f25a89917563237bb6faf60058cc536b7f42469af32fba556842f9f0cb9569`;
`gepard.dll` = `34188e6046eb831f31c0843744c084b56704a765d9e758043a1a1dad6046b08b`.
Base do repositório: `d3baabe`, com instrumentos de pesquisa locais adicionais.
As comparações pertencem a novas conexões/sessões do mesmo processo/build, não a
builds ou contas diferentes. Não transportamos estado criptográfico entre conexões.

**Método reproduzível:** [session_packets.py](../research/cipher/session_packets.py)
reutiliza os observadores `recvmsg`/`sendmsg` do agente, adiciona pilhas limitadas de
chamadas e remonta separadamente cada direção/conexão pela tabela de comprimentos.
O inventário ocorre **antes** do descarte do feed OpenKore; assim, `4754/5395` continuam
visíveis à pesquisa. O início dos dez segundos é o primeiro `007D` do cliente após
`02EB`, não apenas o recebimento da aceitação. A versão final reinicia a janela se
houver pedido de reinício, fechamento do socket de mapa ou nova aceitação de mapa.
O observador adicional de `close` distingue a reutilização da porta local. As
primeiras coletas não possuíam esse observador; não houve erro de enquadramento nelas,
mas isso não constitui prova geral contra reutilização de portas.

**Cobertura e privacidade:** os arquivos `packets.jsonl` guardam ID, tamanho, direção,
porta de serviço, ordem, offset e tempos; não guardam corpos de autenticação, listas
de personagens, identificadores de conta nem texto de chat. Somente corpos dos
quatro controles investigados ficam no `controls.jsonl` **privado** (0700/0600), pois
precisamos compará-los; sua sensibilidade interna ainda não é conhecida. Nenhum
payload, seed, MAC, identificador ou captura crua foi copiado para este documento.
Tráfego auxiliar das portas 3000/6700 é contado como bytes não RO e não decodificado;
esta é uma auditoria de mensagens RO/Gepard observadas no socket, não um PCAP de
todos os protocolos, retransmissões e cabeçalhos TCP/IP.

Artefatos locais não versionados: `/tmp/gepard-session-20261017/`, subdiretórios
`round1`, `round2`, `round3` e `map-only`; `scope-packets.jsonl` retém a sequência do
recorte; `catalog.json` contém formatos/campos declarados e hashes dos parsers;
`summary.json` registra cobertura, erros, perdas, hash do agente executado e limpeza.
A partir da segunda rodada também se preserva o driver executado e seu hash.
As referências históricas abreviadas `socket.cpp`/`socket.hpp` desta auditoria ficam
em `relay/resources/Gepard-SRC-LGP-master/src/common/`; `map/clif.cpp` pertence ao
mesmo diretório `src/`. São fontes locais externas, não regras do build atual.
O parser de declarações [packet_semantics.py](../research/cipher/packet_semantics.py)
resolve herança e condições literais de comprimento sem executar Perl; condições ou
alterações dinâmicas não suportadas ficam explicitamente sem resolução.

### Sequência discriminante observada

Na rodada A, relativa ao primeiro pedido de login: `S:0204 + S:0064` →
`R:4754` (40 B, +244 ms) → `S:C392` (72 B, +256 ms) → repetição de `S:0064` →
`R:0AC4` (autenticação, +493 ms). No serviço de personagens: `S:0065` → preâmbulo
de conta de quatro bytes → `R:082D/006B/08B9` → `S:0187/0066` → `R:0AC5`.
No mapa: `S:0436` → `R:4754` (40 B) junto de mensagens de entrada e
`R:5395` (12 B) → `S:C392` (72 B, 12 ms depois do `4754`) → `S:007D`.
Os tempos observam a entrega dos hooks; mensagens no mesmo recv compartilham tempo,
mas mantêm offsets e ordem. Eles não provam uma cadeia de chamadas do servidor.

**Limite causal:** na entrada do mapa, `0283/02EB` já chegaram no mesmo bloco do
`4754`, antes do envio do `C392`. Portanto, esta captura **não sustenta** a afirmação
de que todos os pacotes RO do mapa ficam bloqueados até o ACK. Já no login, a
resposta `0AC4` veio depois do ACK. Não foi removido/modificado controle no cliente
ou servidor para demonstrar quais mensagens são requisitos de aceitação.

**Condições das rodadas:** A contém seis movimentos, uma ação `0437` e uma skill
de chão `0AF4`; serve para inventariar o fluxo, mas não é repouso. B inclui novas
transições pela seleção e outro login; no seu recorte final houve `00B2` apenas
3,078 s após `007D`, seguido de `0065` em 3,828 s. O resumo antigo de B terminou
pelo relógio e **não comprova dez segundos contínuos no mapa**; a auditoria da
sequência detectou isso e motivou a correção do coletor para a repetição final.
D observa dez segundos no mapa já aberto, sem `035F/0437/0438/0AF4`, e registra
um `8280`. Retorno à seleção e aquecimento anteriores ao primeiro login completo
de B foram separados (69 mensagens), sem apagar o arquivo original.


### Cobertura das rodadas

| Rodada | Pacotes no recorte | Resultado de cobertura |
|---|---:|---|
| A — login completo | 191 (162 R / 29 S) | 10 s após 007D; houve movimento/ações |
| B — login/transições repetidos | 113 (93 R / 20 S) | saída em 3,078 s; não valida estadia contínua de 10 s |
| C — repetição aguardada | 0 incluídos | timeout sem nova entrada; 616 mensagens de espera excluídas do catálogo |
| D — mapa já aberto | 10 (8 R / 2 S) | 10 s adicionais, sem movimento/ataque/skills |

**OBSERVADO:** A/B/D somam 314 mensagens e 69 pares direção/ID: 65 têm declaração
no parser selecionado e quatro são os controles investigados abaixo. Nenhum fluxo
capturado terminou com bytes pendentes ou comprimento desconhecido; não houve
lacunas nos números de sequência capturados nem erro de script. `unload`/`detach`
foram confirmados. Isso descreve a cobertura dos hooks, não prova ausência de
pacotes fora das APIs observadas ou de perda de rede. C foi excluída porque não
registrou nova aceitação/007D; nenhum dado dela substitui o login pedido.

### Catálogo completo dos tipos observados

Contagens por rodada: **A** = login completo inicial; **B** = segundo login (estadia interrompida); **C** = tentativa sem nova entrada (excluída); **D** = observação adicional de dez segundos no mapa. Cada número conta pacotes remontados, não chamadas de socket. `S` = cliente → servidor; `R` = servidor → cliente. Os controles estão detalhados nas fichas abaixo. A referência de parser prova a declaração no OpenKore; não comprova todos os campos do corpo no build uaRO.

| Dir. | ID | Bytes observados | A/B/C/D | Função declarada / interpretação | Fonte |
|---|---|---|---|---|---|
| R | `0x006B` | 202 | 1/2/0/0 | lista e slots de personagens (`received_characters_info`) | `P2:66` |
| R | `0x007F` | 6 | 2/2/0/1 | resposta de sincronização (`received_sync`) | `P2:90` |
| R | `0x0080` | 7 | 7/0/0/0 | remoção/morte de entidade (`actor_died_or_disappeared`) | `P2:91` |
| R | `0x0086` | 16 | 19/0/0/0 | movimento de outra entidade (`actor_display`) | `P2:95` |
| R | `0x0087` | 12 | 6/0/0/0 | confirmação do movimento do jogador (`character_moves`) | `P2:96` |
| R | `0x0088` | 10 | 2/0/0/0 | interrupção de movimento (`actor_movement_interrupted`) | `P2:97` |
| R | `0x008E` | 60 | 1/1/0/0 | eco de chat próprio (`self_chat`) | `P2:100` |
| R | `0x0091` | 22 | 1/1/0/0 | mudança de mapa/posição (`map_change`) | `P2:101` |
| R | `0x009C` | 9 | 4/0/0/0 | direção da entidade (`actor_look_at`) | `P2:108` |
| R | `0x00B0` | 8 | 21/20/0/0 | atributo do personagem (`stat_info`) | `P2:123` |
| R | `0x00B3` | 3 | 0/1/0/0 | resposta de retorno à seleção (`switch_character`) | `P2:125` |
| R | `0x00BD` | 44 | 1/1/0/0 | conjunto de atributos (`stats_info`) | `P2:131` |
| R | `0x00C0` | 7 | 0/1/0/0 | emoticon de entidade (`emoticon`) | `P2:133` |
| R | `0x010F` | 966 | 1/1/0/0 | lista de skills (`skills_list`) | `P2:182` |
| R | `0x013A` | 4 | 2/2/0/0 | alcance de ataque (`attack_range`) | `P2:212` |
| R | `0x0141` | 14 | 12/12/0/0 | atributo base e bônus (`stat_info2`) | `P2:217` |
| R | `0x01C3` | 46 | 1/0/0/0 | anúncio local (`local_broadcast`) | `P2:298` |
| R | `0x01D7` | 15 | 3/3/0/3 | aparência/equipamento do sprite (`sprite_change`) | `P2:313` |
| R | `0x0201` | 68 | 1/1/0/0 | lista de amigos (`friend_list`) | `P2:342` |
| R | `0x0283` | 6 | 1/1/0/0 | identificação de conta (`account_id`) | `P2:404` |
| R | `0x02C1` | 35, 38, 62, 63, 90 | 3/0/0/2 | chat de NPC/canal (`npc_chat`) | `P2:440` |
| R | `0x02EB` | 13 | 1/1/0/0 | aceitação/carregamento do mapa (`map_loaded`) | `P2:468` |
| R | `0x07FD` | 265 | 1/0/0/0 | anúncio de obtenção de item (`special_item_obtain`) | `P2:501` |
| R | `0x082D` | 29 | 1/2/0/0 | lista e slots de personagens (`received_characters_info`) | `P2:525` |
| R | `0x08B9` | 12 | 1/2/0/0 | estado/solicitação de PIN (`login_pin_code_request`) | `P2:540` |
| R | `0x08C8` | 34 | 7/0/0/0 | ação de entidade (`actor_action`) | `P2:542` |
| R | `0x08CA` | 134, 176, 260, 862, 1842, 1870, 2304, 4376 | 8/8/0/0 | catálogo da loja de cash (`cash_shop_list`) | `P2:543` |
| R | `0x0983` | 29 | 3/3/0/0 | estado/efeito ativo da entidade (`actor_status_active`) | `P2:564` |
| R | `0x099B` | 8 | 1/1/0/0 | propriedades do mapa (`map_property3`) | `P2:581` |
| R | `0x09E7` | 3 | 1/1/0/0 | estado de correio não lido (`unread_rodex`) | `P2:603` |
| R | `0x09FD` | 114 | 13/0/0/0 | movimento de entidade (`actor_moved`) | `P1:24` |
| R | `0x09FE` | 107 | 0/0/0/1 | entrada de entidade (`actor_connected`) | `P1:25` |
| R | `0x09FF` | 108 | 8/2/0/0 | entidade existente (`actor_exists`) | `P1:26` |
| R | `0x0A15` | 12 | 1/1/0/0 | pontos de bônus PC Café (`gold_pc_cafe_point`) | `P2:633` |
| R | `0x0A23` | 22 | 1/1/0/0 | lista de conquistas (`achievement_list`) | `P2:640` |
| R | `0x0A30` | 106 | 5/1/0/0 | informações/nome de entidade (`actor_info`) | `P2:647` |
| R | `0x0A3B` | 9 | 1/1/0/1 | efeito visual de equipamento (`hat_effect`) | `P2:654` |
| R | `0x0AC4` | 224 | 1/1/0/0 | resposta de autenticação e servidores (`account_server_info`) | `P2:700` |
| R | `0x0AC5` | 156 | 1/1/0/0 | personagem selecionado e destino do mapa (`received_character_ID_and_Map`) | `P2:701` |
| R | `0x0ACB` | 12 | 4/4/0/0 | atributo do personagem (`stat_info`) | `P2:705` |
| R | `0x0ADE` | 6 | 1/1/0/0 | limite percentual de peso (`overweight_percent`) | `P2:711` |
| R | `0x0AFF` | 212 | 1/1/0/0 | lista de quests (`quest_all_list`) | `P2:724` |
| R | `0x0B08` | 6 | 1/1/0/0 | início da lista de itens (`item_list_start`) | `P2:728` |
| R | `0x0B09` | 991 | 1/1/0/0 | itens empilháveis (`item_list_stackable`) | `P2:729` |
| R | `0x0B0B` | 4 | 1/1/0/0 | fim da lista de itens (`item_list_end`) | `P2:731` |
| R | `0x0B18` | 4 | 1/1/0/0 | resultado de expansão do inventário (`inventory_expansion_result`) | `P2:735` |
| R | `0x0B1A` | 29 | 1/1/0/0 | início de conjuração (`skill_cast`) | `P2:736` |
| R | `0x0B1B` | 2 | 1/1/0/0 | confirmação de carregamento (`load_confirm`) | `P2:737` |
| R | `0x0B20` | 271 | 1/1/0/0 | atalhos (`hotkeys`) | `P2:739` |
| R | `0x0B39` | 617 | 1/1/0/0 | itens não empilháveis (`item_list_nonstackable`) | `P2:744` |
| R | `0x4754` | 40 | 2/2/0/0 | controle investigado; função/campos parcialmente identificados | fichas desta seção |
| R | `0x5395` | 12, 16 | 2/2/0/0 | controle investigado; função/campos parcialmente identificados | fichas desta seção |
| S | `0x0064` | 55 | 2/2/0/0 | pedido de autenticação (`master_login`) | `P5:23` |
| S | `0x0065` | 17 | 1/2/0/0 | login no servidor de personagens (`game_login`) | `P7:41` |
| S | `0x0066` | 3 | 1/1/0/0 | seleção de personagem (`char_login`) | `P7:42` |
| S | `0x007D` | 2 | 2/2/0/0 | confirmação do cliente de carregamento do mapa (`map_loaded`) | `P7:46` |
| S | `0x00B2` | 3 | 0/1/0/0 | pedido de reinício/seleção (`restart`) | `P7:61` |
| S | `0x0187` | 6 | 1/1/0/0 | consulta de bloqueio (`ban_check`) | `P7:130` |
| S | `0x0204` | 18 | 1/1/0/0 | identificação/hash do cliente (`client_hash`) | `P7:162` |
| S | `0x035F` | 5 | 6/0/0/0 | pedido de movimento (`character_move`) | `P4:31` |
| S | `0x0360` | 6 | 2/2/0/1 | sincronização do cliente (`sync`) | `P4:43` |
| S | `0x0368` | 6 | 2/1/0/0 | pedido de informações de entidade (`actor_info_request`) | `P4:24` |
| S | `0x0436` | 23 | 1/1/0/0 | pedido de entrada no mapa (`map_login`) | `P6:25` |
| S | `0x0437` | 7 | 1/0/0/0 | ação de entidade (`actor_action`) | `P4:23` |
| S | `0x0447` | 2 | 1/1/0/0 | pedido de desbloqueio do personagem (`blocking_play_cancel`) | `P7:218` |
| S | `0x08C9` | 2 | 1/1/0/0 | pedido da loja de cash (`request_cashitems`) | `P3:44` |
| S | `0x0AF4` | 11 | 1/0/0/0 | skill no chão (`skill_use_location`) | `P4:44` |
| S | `0x8280` | 128 | 4/2/0/1 | controle investigado; função/campos parcialmente identificados | fichas desta seção |
| S | `0xC392` | 72 | 2/2/0/0 | controle investigado; função/campos parcialmente identificados | fichas desta seção |

Fontes do parser externo (prefixo `relay/resources/openkore-master/src/`; arquivos locais ignorados pelo Git, hashes em `catalog.json:parser_sources`):

- `P1` — `Network/Receive/kRO/RagexeRE_2018_11_21.pm`.
- `P2` — `Network/Receive/kRO/Sakexe_0.pm`.
- `P3` — `Network/Send/kRO/RagexeRE_2012_04_10a.pm`.
- `P4` — `Network/Send/kRO/RagexeRE_2018_04_04b.pm`.
- `P5` — `Network/Send/kRO/RagexeRE_2020_04_01b.pm`.
- `P6` — `Network/Send/kRO/RagexeRE_2021_11_03.pm`.
- `P7` — `Network/Send/kRO/Sakexe_0.pm`.

`01D7` usa o ramo de 15 bytes (`a4 C V2`) da condição literal baseada em `recvpackets`. `09FD`/`09FF` e os envios de ação mantêm corpos opacos nesta auditoria; o nome da função não significa que esta coleta os decifrou.

### `0x4754` — abertura da negociação de segurança (papel INFERIDO)

- **OBSERVADO:** servidor → cliente nos serviços de login e mapa; 40 bytes;
  `u16 id @0`, `u16 comprimento total @2`, 36 bytes de corpo opaco em `@4..39`.
  Cada ocorrência foi seguida por um `C392` na mesma conexão, cerca de 12 ms depois.
  Não apareceu na seleção de personagem desta coleta.
- **INFERIDO:** inicia negociação/estado Gepard por conexão. A sequência de login
  inclui uma segunda tentativa de `0064` depois da resposta, compatível com esse papel.
  Timing e tamanho não identificam a operação criptográfica nem os campos de seed.
- **CÓDIGO HISTÓRICO 2016:** `socket.hpp:127` chama `4753` de `SC_GEPARD_INIT`;
  `socket.cpp:355-384` constrói 36 bytes, com três valores de inicialização de 16 bits,
  hash, tick e parâmetros de servidor/build; `:532-535` transforma parte do pacote.
  A diferença **4754/40 B versus 4753/36 B refuta identidade binária direta**. Não
  aplicar os offsets antigos ao corpo atual. Falta observar qual consumidor atual
  lê/transforma esses 36 bytes e qual inicializador recebe os valores derivados.

### `0xC392` — resposta da negociação (papel INFERIDO)

- **OBSERVADO:** cliente → servidor, 72 bytes, login e mapa, sempre após `4754`
  nos pares capturados. Cabeçalho `u16 id @0`, `u16 comprimento @2`; corpo opaco
  de 68 bytes. A repetição não mostrou um identificador fixo legível no corpo.
- **INFERIDO:** ACK/resposta da negociação, com dependência temporal de `4754`.
  Isso **não prova** se há autenticação criptográfica, fingerprint de máquina,
  algoritmo negociado ou simples confirmação no build atual.
- **CÓDIGO HISTÓRICO 2016:** `socket.hpp:125` usa o mesmo ID para `CS_GEPARD_INIT_ACK`;
  `socket.cpp:478-514` valida comprimento mínimo, transforma corpo, compara hash,
  extrai versão/identificação, MAC e IDs dos pacotes de ação. São campos da referência
  de 2016, **NÃO VERIFICADOS no uaRO atual**; os 72 bytes atuais não foram decifrados.
  Não copiar MACs, fingerprints ou seeds hipotéticos para fixtures/documentação.

### `0x5395` — mensagens de configuração com pelo menos duas formas

| Offset | Tamanho | Forma de 12 bytes: OBSERVADO | Forma de 16 bytes: OBSERVADO |
|---|---:|---|---|
| 0 | 2 | ID `5395` | ID `5395` |
| 2 | 2 | comprimento 12 | comprimento 16 |
| 4 | 4 | campo little-endian = 1 | campo little-endian = 4 |
| 8 | 4 | campo little-endian = 1 | campo opaco variável entre sessões |
| 12 | 4 | ausente | incremento compatível com relógio em milissegundos; origem/eco não verificados |

**OBSERVADO:** servidor → cliente, no mapa. A forma de 12 bytes veio no bloco de
entrada; a de 16 bytes chegou depois. Na comparação auxiliar de cinco amostras por
forma, do diagnóstico anterior e da rodada A, `12 B` manteve o mesmo par `1,1`;
as cinco formas `16 B` tinham valores distintos tanto em `@8` quanto em `@12`.
Essas amostras auxiliares pertencem ao mesmo processo/build, não a cinco builds ou
cinco reproduções independentes. Corpos/valores privados foram preservados somente
nos artefatos locais.

**CÓDIGO HISTÓRICO 2016:** `socket.hpp:129` nomeia o ID como `SC_GEPARD_SETTINGS`.
`map/clif.cpp:60-72` produz exatamente 12 bytes, com `u32 @4 = 1 // LGP` e
`u32 @8 = 1 // mode`. A combinação ID/tamanho/campos da forma curta é compatível
com configuração LGP (**INFERIDO para uaRO**). O efeito visual e o handler atual
ainda não foram observados.

**Teste temporal adicional — OBSERVADO:** seis amostras da forma `4/16 B`, incluindo
A/B e as capturas auxiliares anteriores, cobrem 2.451.850 ms entre recebimentos.
O `u32 little-endian @12` avançou 2.451.847 unidades nesse intervalo. Em todos os
cinco pares adjacentes, a diferença entre incremento e tempo capturado ficou em
até 10 ms. `@8` não acompanhou esse relógio em nenhum desses pares (tolerância
de 2 s). Os valores absolutos não foram publicados. Resultado privado:
`clock-correlation.json` e `field-relations.json`.

| Amostra | Tempo de recebimento desde a primeira (ms) | Incremento de `@12` desde a primeira | Diferença (ms) |
|---|---:|---:|---:|
| 1 | 0 | 0 | 0 |
| 2 | 303289 | 303299 | +10 |
| 3 | 437236 | 437237 | +1 |
| 4 | 721249 | 721251 | +2 |
| 5 | 1813252 | 1813254 | +2 |
| 6 | 2451850 | 2451847 | −3 |

A tabela contém apenas deltas para permitir verificar a correlação; não contém
o valor absoluto do campo ou identificadores das sessões.

**INFERIDO:** `@12` é um campo temporal em milissegundos, e `@4` distingue subtipos.
Isso não distingue tick do servidor, eco de tempo do cliente ou outro relógio
compartilhado. Chamar os dois campos de seeds não é sustentado por essa medição.
Para `@8`, nonce, desafio, parâmetro de sincronização, seed e checksum continuam
**HIPÓTESES**. Modelos simples `rotate(@12) XOR constante`, afim módulo 2³² e
`CRC32(@12) XOR constante` não se ajustaram simultaneamente às seis amostras
(`field8-model-checks.json`); esse negativo não exclui outros cálculos/entradas.

**Relação temporal observada:** em A/B, o `5395` de 16 bytes veio respectivamente
243/247 ms após o último `8280` anterior — ordem compatível com resposta/sinalização
de sincronização. **INFERIDO:** o subtipo 4 participa de temporização/sincronia.
Dois pares e um campo temporal não demonstram causalidade, transformação ou
periodicidade. Para promover `@8` a seed, ainda é preciso ligar sua leitura à
inicialização/evolução de estado; um consumidor sem função criptográfica a refutaria.
Não estender o layout LGP de 12 bytes aos 16 bytes por semelhança de ID.

### `0x8280` — sinalização de sessão, independente de ação imediata no recorte

**OBSERVADO:** cliente → servidor de mapa; 128 bytes por mensagem completa.
Somente os dois bytes de ID são um cabeçalho estabelecido; os 126 bytes restantes
permanecem opacos. Não interpretar `@2` como comprimento variável só porque outros
controles possuem esse campo. Na rodada A houve quatro ocorrências; seus intervalos
foram 1,226 s, 1,251 s e 5,215 s. Na observação D, um `8280` foi transmitido em dez
segundos sem envios de movimento/ataque/skills. Assim, **não é correto descrevê-lo
como pacote observado exclusivamente imediatamente antes de uma ação**. Isso não
estabelece período fixo nem elimina dependências de ações anteriores fora da janela.

**INFERIDO:** sinalização/heartbeat/sincronização Gepard, coerente com o histórico.
Conteúdo, checksum, contador, fingerprint e ligação à cifra continuam **NÃO
VERIFICADOS**. Na referência de 2016, `socket.cpp:411-426` trata `8285` com seis
bytes, quatro deles transformados por `sync_crypt`. **ID e tamanho diferem**;
não aplicar o literal `0xDDCCBBAA` ou esse layout aos 128 bytes atuais.

### Tentativas de identificação e o que elas não demonstram

1. **Referências primárias:** todos os tipos comuns do catálogo têm declaração no
   parser OpenKore selecionado. Os quatro controles não têm handler nesse parser.
   A referência 2016 identifica nomes/papéis candidatos, mas não substitui prova atual.
2. **Comparação estrutural:** tamanho, direção, sequência, layout curto de `5395` e
   variação dos campos da forma longa foram medidos sem alterar tráfego do cliente.
3. **Referências de cifra, offline:** 72 hipóteses limitadas foram testadas para os
   quatro pares `4754→C392` de A/B: variantes literais A, B e 2016; seeds candidatas
   `u16 @4/6/8` ou `u32 @4/8/12` do `4754`; unidade fresca e corpo do ACK em `@4`.
   Com posições assumidas `uint8` na variante B, nenhuma saída sequer continha um
   dos IDs de ação esperados `035F/0437/0438/0AF4`; zero atingiu o critério de três
   IDs distintos. Não foi aplicado um hash sem campo/estrutura justificados.
   Script e resultado privados: `reference_checks.py` e `reference-checks.json`;
   hash do script `79b6cb835b345d2e8dd8b7cb8b10ec8b68c1c5cdab8d0286da31200bcfad738b`.
   **Negativo apenas para essas hipóteses:** não refuta a família, constantes
   desconhecidas, estado prévio ou outro layout do uaRO; não é decifragem válida.
4. **Código/callers atuais:** busca estática no DLL e em 50.118.656 bytes de 14
   regiões executáveis encontrou coincidências de literais, mas nenhum handler
   validado. As pilhas da fronteira libc retornaram endereços Wine não atribuídos
   ao handler Gepard. Não promover coincidência de bytes/disassembly candidato a
   instrução executada, nem chamar essa lacuna de gerador criptográfico recuperado.
   Uma busca adicional por padrões específicos de comparação/escrita de IDs de
   16 bits em 50.184.192 bytes executáveis não encontrou candidato; ausência desses
   padrões não exclui dispatch calculado, outros encodings ou código virtualizado.

**Próximo discriminador:** localizar o consumidor atual de `5395` com campo `4`,
observar a leitura de `@8` e separá-la do relógio candidato em `@12`, ligando destinos
à inicialização de estado ou à temporização. Esse é um
recorte mais específico que tentar impor o layout 2016 ao `4754`. Para `C392`,
comparar a entrada e saída reais da transformação associadas à mesma conexão.
Sem essas leituras/transformações, o catálogo estabelece o fluxo e os papéis
candidatos, mas **não especifica o conteúdo criptográfico completo dos controles**.

### Reprodução e verificação

Coleta autorizada, com PID/porta redescobertos e janela exclusiva confirmada:

```sh
python3 -m ro_ops discover
python3 -m ro_ops new-artifact --dir /tmp/minha-coleta
~/.venv-frida/bin/python research/cipher/session_packets.py \
  --pid PID --port PORTA --out /tmp/minha-coleta \
  --exclusive-confirmed --map-seconds 10 --max-seconds 300
```

O responsável efetua login/seleção manualmente e permanece no mapa até o término.
`--start-now --max-seconds 10` serve apenas para acompanhamento do mapa atual;
não comprova cobertura do login. As flags não concedem autorização por si mesmas.

Testes de fronteiras, privacidade, ciclo de conexão e parser literal:
`python3 tests/test_session_packets.py`, `python3 tests/test_packet_semantics.py`.
Validação adicional: `bash scripts/test-offline.sh`,
`python3 scripts/validate-research.py`, `python3 scripts/validate-codex.py` e
`git diff --check`. Os testes offline não validam cifra nem os nomes inferidos.

<!-- SESSION-AUDIT-20261017-END -->

## Inventário com níveis de evidência

| Mensagem / ID | Direção | Tamanho | Papel proposto | Nível e fonte | Lacunas para xKore 0 |
|---|---|---:|---|---|---|
| `SC_GEPARD_INIT` / ID atual não confirmado | servidor → cliente (no build 2016) | desconhecido no uaRO | estabelecimento de estado de sessão/cifra | **DOCUMENTADO PARA 2016**: investigação §3.1 | ID atual, fase, campos, condições de reinicialização |
| `CS_GEPARD_INIT_ACK` / ID atual não confirmado | cliente → servidor (no build 2016) | desconhecido no uaRO | confirmação de inicialização | **DOCUMENTADO PARA 2016**: investigação §3.2 | ID atual, dependências, conteúdo, transição de estado |
| `0x8280` | cliente → servidor de mapa; origem Gepard documentada no histórico | 128 **OBSERVADO por ID** na auditoria 2026-10-17 | sinalização/heartbeat/sync **INFERIDO**; ocorre também sem ação no recorte | ID, direção e tamanho **OBSERVADOS**; intervalos variáveis, sem período universal estabelecido | conteúdo, transformação, estado e eventual papel de gate **NÃO VERIFICADOS**; ficha atual acima e [histórico abaixo](#0x8280--syncanti-cheat-gepard-origin-periódico-fase-1-observada-papel-de-gate-ainda-hipótese) |
| `0x8285` (build 2016) | cliente → servidor | não estabelecido aqui | heartbeat histórico | **DOCUMENTADO PARA 2016**: investigação §3.3 | não assumir correspondência binária com `0x8280` |
| `0x4754` | servidor → cliente (login e mapa) | 40 observado | abertura da negociação (**INFERIDO**) | sequência com `C392` **OBSERVADA** na auditoria 2026-10-17 acima | corpo de 36 bytes, consumidor, seeds e transformação não identificados |
| `0xC392` | cliente → servidor (login e mapa) | 72 observado | resposta/ACK da negociação (**INFERIDO**) | pares após `4754` **OBSERVADOS**; ACK nomeado apenas na referência 2016 | corpo de 68 bytes e validação atual não decifrados |
| `0x5395` | servidor → cliente de mapa | 12 e 16 observados | configurações/subtipos (**INFERIDO**); 12 B compatível com LGP, tipo 4 compatível com temporização/sincronia | campos `1/1`, tipo `4` e correlação temporal de `@12` **OBSERVADOS**, fichas acima | consumo de `@8`; origem/eco do relógio candidato de `@12` |
| `0x035F`, `0x0437`, `0x0438`, `0x0AF4` | cliente → servidor | consultar fonte do protocolo | pacotes de ação, **não confundir com heartbeat** | **DOCUMENTADOS** em `docs/HISTORY/ARCHITECTURE_LEGACY.md` §§5–6; origem por code do dispatcher `0xd473b0` **OBSERVADA** em 2026-10-16 ([mapa abaixo](#mapa-dispatcher--pacote-de-ação-act-20261016-01)) | comportamento no build atual e requisitos do OpenKore |

## Hipótese separada da evidência

**H-CIPHER-01 — HIPÓTESE HISTÓRICA, NÃO causa ativa da falha corrigida.** O fonte servidor de 2016 sugere decifragem de corpos selecionados antes do parser, com estado de recepção que deve avançar na sequência correta. Conjectura atual: bytes de conteúdo incorretamente decifrados podem fazer o parser/servidor rejeitar `0x0438`; operações de corpo menor, como algumas variantes de `0x0437`, podem parecer funcionar mesmo se a cobertura da cifra estiver incorreta. **Não está provado** que exista validação criptográfica por byte, que o servidor descarte o pacote por esse motivo, ou que a cifra atual seja idêntica à de 2016.

**Evidência que falta:** comparar resultados reproduzíveis de sessões de teste autorizadas e dados sanitizados, separados por versão, ID, comprimento e estado de sessão, para distinguir diferença de corpo, dessincronização, pré-condição de ação e rejeição de parser. Não concluir causalidade apenas pela ausência da animação de perícia.

## `0368` pré-select e ações com alvo (`0437` ataque / `0438` perícia) — achado REFUTADO como solução

**Fechamento posterior:** `0368` não era a causa; ataque e skills automáticos funcionam após o `_fix0` no Frida (`agent/relay_hook_linux.js:481-534`). Os negativos desta seção referem-se à via `SendPacket` crua **testada anteriormente**, não ao carrier+merge hoje funcional.

**Procedência.** Sessão OrquestradorCLAUDE, **2026-10-16** (ORCH-20261016-01b, rodada 09b); build
`uaRO.exe` `f2f2…9569`; servidor emulador **próprio do responsável**. Caminho no relay:
`relay/writeback.py:_on_inbound_sendcall`. **Refutação** pelo responsável no mesmo dia, registrada em
ACT-20261016-01 (fontes originais `research/action_0437_0438/{STATE,HANDOFF}.md`, arquivadas [integralmente](HISTORY/ACTIONS_COMPLETE.md)).

**Leitura original (2026-10-16, rodada 09b — SUPERADA).** A divergência entre sentar (`0437`, GID=0,
funcionava) e ataque/perícia (não tinham efeito) foi atribuída ao `0368` (CZ_REQNAME_BYGID) que o relay
injetava antes de ações com alvo. O `0368` pré-ação passou a ser **gated** por `--target-select`
(default OFF) em `relay/writeback.py` (`target_select`), com flag em `relay/cli.py`.

**REFUTADO (responsável, 2026-10-16):** a hipótese "o `0368` pré-ação era o bloqueio" é **falsa**.
**Com ou sem `0368` o `SendPacket`/`sendmsg` da ação sempre ocorria**; o problema (ação enviada mas
**sem efeito** no servidor) é **anterior** ao `0368`. Consequência: rotear `0437`/`0438` pela
`SendPacket` crua do cliente **não executa** ataque/perícia. A flag `--target-select`
continua opcional, mas não é solução para ataque/perícia. **Resultado posterior
(2026-10-17, confirmação live do responsável):** o filtro legado `SKIP_IDS`
descartava os pedidos `0368` de identificação feitos pelo OpenKore, causando
`[Unknown]` nos nomes de monstros. O filtro e a flag transitória `--noskipids`
foram removidos após o teste bem-sucedido. Isso não valida a hipótese de
pré-select obrigatório para o ataque.

Fatos que permanecem:

- **`0368` (CZ_REQNAME_BYGID):** OBSERVADO como **pedido de nome por GID** emitido pelo cliente ao
  passar o mouse/clicar num alvo — não um "lock de alvo". Também é
  encaminhado quando solicitado pelo consumidor, para identificar entidades.
- **`0437` sentar/levantar (GID=0):** OBSERVADO funcionando via client SendPacket.
- **`0437` ataque (GID≠0) e `0438` perícia via SendPacket crua:** pacote sai, **ação não executa**
  (relato do responsável; mecanismo do servidor NÃO VERIFICADO).
- **Throttle de cast:** `0438` sob `--cast-throttle` (default 0.8 s): um cast por janela, log
  `cast 0x0438 pacejado (rajada evitada)` — política intencional de writeback.

**Relação com H-CIPHER-01:** a explicação alternativa "era o `0368`" foi retirada; H-CIPHER-01
(rejeição por conteúdo/cifra) **volta a ser candidata**, ao lado de pré-condições de estado do
cliente que a via natural monta (ver abaixo). Nenhuma das duas está demonstrada.

**Teste offline:** `tests/test_writeback.py` cobre o roteamento (default sem `0368`; caso
`target_select=True` com dedup por GID). Testa o código, não a execução da ação no servidor.

## Mapa dispatcher → pacote de ação (ACT-20261016-01)

**Procedência.** Trilha `research/action_0437_0438/` (STATE/HANDOFF), **2026-10-16**, base `6c20733`;
build uaRO+gepard = MATCH; autorização direta do responsável por rodada, servidor próprio. Captura
**read-only** com 2 HW exec BP: DR0 no dispatcher `0xd473b0` (lê `code=[esp+8]` e o frame de 13
dwords `[esp+4+4k]`); DR1 na `SendPacket(this,len,buf)` do cliente em **uaRO+0x816640
(VA `0xC16640`)**, onde o corpo ainda está **em claro**, antes do scrambler Gepard
(`mov [ecx],bl` em `gepard+0x18eff2`). Tudo na thread principal. Sonda:
`research/action_0437_0438/observe_dispatch_codes.py`. Artefatos privados (não versionados):
`/tmp/claude-act-20261016-031147-sendpkt/observe.json`,
`/tmp/claude-act-20261016-110249-soulstrike2/inject.json`.

| Ação do usuário | code do dispatcher | Pacote CZ | Corpo em claro observado | Classificação |
|---|---|---|---|---|
| andar | `0x11` (17) | `0x035F` | frame `[0,17,0,X,0,Y,…]` (X,Y no próprio frame) | OBSERVADO |
| sentar/levantar | `0x1f` (31) | `0x0437` | `3704 <GID próprio> 02/03` (02 senta, 03 levanta) | OBSERVADO |
| atacar | `0x28` (40) | `0x0437` | `3704 <GID alvo> 07` (ação 07 = ataque) | OBSERVADO |
| usar perícia | `0x2a` (42) | `0x0438` | `3804 0a00 0d00 <GID>` (nível 10, skill `0x0d` = 13 Soul Strike) | OBSERVADO |
| selecionar alvo | `0x0a` (10) | (via `0x0368`) | GID do alvo no frame arg3 | OBSERVADO |

**ABI (OBSERVADO):** `0x11` carrega X,Y no frame e comete sozinho. `0x28` e `0x2a` **não levam
argumentos no frame** (`[0,40,0,0,…]` / `[0,42,0,0,…]`): leem alvo/perícia de **estado global**
montado por passos anteriores.

**Preparação (INFERIDO por sequência + cross-check):** `0x29` frame `[.,41,.,GID,.,13,…]` = seta skill
13 + GID; `0x5a` frame `[.,90,.,10,…]` = seta nível 10; `0x0a` = seleciona alvo. O corpo do `0438`
(nível 10/skill 13) casa exatamente com `0x29`+`0x5a`. **Cadeia de cast OBSERVADA: `0x29 → 0x5a →
0x2a`**; cadeia de ataque inferida `0x0a → 0x28`.

**Caller imediato (OBSERVADO):** em todos os codes, `[esp]` no dispatcher é o shim do Gepard
**`gepard+0xb2c251`**. O PoC 035F chama o dispatcher direto (sem o shim) e funciona, logo o shim não é
o bloqueio. **RETIRADO:** cadeias de chamadores além do shim obtidas por `Backtracer.FUZZY` e por
EBP-walk (`capture_skill_callers.py`, `capture_skill_ebp.py`) — validadas no objdump, os endereços
(`0x944002`, `0x943fda`, `0x874a40`, `0x874b32`, `0x874f0b`, `0x66baea`) **não** são retornos de
`call` (frames SEH/FPO, provável trampolim `ret`/`jmp` do shim). O split "prepare vs commit" **não**
está provado.

**Injeção nativa da perícia — NEGATIVO (OBSERVADO, ao vivo, autorizado).** Capture+replay da cadeia
de cast pelo mecanismo do PoC 035F (captura passiva do `this`=ECX + `thiscall` a partir do fire-site
de main-loop `0x4dcba0`), sonda `inject_soulstrike_live.py`:

- Rodada 1 (bug do pesquisador: replay de superset incluindo `0x11` e code `0x00`): **crash** do
  cliente. Não interpretar como resultado da cadeia de perícia.
- Rodada 2 (allowlist estrita `[0x29,0x5a,0x2a]`): as 3 chamadas retornaram (`0x29`→13, `0x5a`→17,
  `0x2a`→**0**) sem exceção, **nenhum `0x0438` na rede** (perícia não conjurada) e **crash deferido**
  (sonda chegou ao `DONE` aos 90 s; cliente caiu depois).

**Conclusão (OBSERVADO no recorte):** disparar `0x29→0x5a→0x2a` de `0x4dcba0` é **inócuo** (`0x2a`→0,
sem egress) **e instável**. Ao contrário do `0x11`, o commit da perícia depende de estado/contexto
montado pelo handler de input natural que esse disparo não tem (natureza do estado: **NÃO
VERIFICADA**). **Em aberto:** sítio real que dispara `0x2a` e a pré-condição que ele lê. Método
proposto, não executado: *validated stack scan* (no BP do dispatcher, manter só dwords da pilha `V`
em `.text` do uaRO onde um `call` termina exatamente em `V`: `V-5 == E8` ou `FF /2` em `V-6..V-2`).

**Limite de recursos:** o modo `--move-dispatch` do relay ocupa os quatro DRs; o STATE da trilha
admite sobreposição DR0/DR1 com outras sondas — este experimento **não** valida coexistência de sondas.

## `0x8280` — sync/anti-cheat Gepard-origin, periódico (Fase 1 OBSERVADA; papel de gate ainda HIPÓTESE)

**Procedência.** RELATO do responsável, **2026-10-16**, confirmado ao vivo por ele em logs e teste
(servidor próprio): **um `0x8280` sai IMEDIATAMENTE ANTES de todo `0x0437`/`0x0438`/`0x0AF4`** (e
**não** antes do `0x035F`); comandos do consumidor (OpenKore) também provocam o envio de `0x8280`.
Não reproduzido independentemente por sonda ainda (ver "Teste" abaixo).

**Analogia (NÃO prova para este build).** No fonte Gepard 2016, `CS_GEPARD_SYNC` (`0x8285` lá)
carrega um `control_value` de 4 bytes cifrado por uma unidade **`sync_crypt` separada** das de
recv/send; ao decodificar `0xDDCCBBAA` o servidor faz `sync_tick = gepard_get_tick()`
(`relay/resources/Gepard-SRC-LGP-master/src/common/socket.cpp:411-426`). Em
`relay/resources/Gepard-SRC-LGP-master/src/map/clif.cpp:79-85`, `clif_gepard_process_packet` calcula
`diff_time = gettick() - sync_tick` e, se `> 40000`, chama `clif_authfail_fd` (rejeita/derruba). As
ações (`cs_packet_request_move`/`action_request`/`use_skill_to_id`/`use_skill_to_ground`) são
decifradas com `recv_crypt`. **A equivalência build-2016 × uaRO não está demonstrada** (AGENTS.md §6.2).

**Hipótese de trabalho (não confirmada).** `0x8280` é o sync/anti-cheat do uaRO e **gateia** as ações:
injeção crua de `0437/0438` (REFUTADA em ACT-20261016-01) e disparo do dispatcher fora de contexto
falham por **não** virem acompanhados do `8280` natural. Isso explicaria por que o `INSERT→ataque`
(merge sobre um `0437` que o próprio cliente montou pela entrada natural, **com** o `8280`) **executou**
— ver [MOVEMENT_035F_PRECONDITIONS §13.13](HISTORY/MOVEMENT_COMPLETE.md#source-docs-movement-035f-preconditions-md) e o mapa acima.

**Resultado da Fase 1 (OBSERVADO — build atual, 2026-10-16, pid 3752762, 20 ações; sonda
`research/action_0437_0438/observe_8280.py`, HW exec BP na `SendPacket` uaRO+0x816640 + Interceptor
`sendmsg`):**

- **`0x8280` NÃO é construído pelo cliente.** Em 20 ações (6× `0437`, 10× `0438`, 4× `0AF4`), o
  cliente emitiu em claro na `SendPacket` os ids `0437/0438/0AF4/0360/0368` — e **nenhum `0x8280`**
  (contador `is_sync` = 0). → `0x8280` é **Gepard-origin** (INFERIDO), não um pacote montado pelo
  cliente na via de envio natural.
- **Egress periódico de 128 B.** O `sendmsg` mostra uma escrita de **128 B recorrente (25× em 90 s ≈
  a cada 3,6 s)**, independente do ritmo das ações — candidato ao heartbeat/sync (coerente com o
  tamanho 128 da tabela uaRO). Logo o `0x8280` é **periódico** (timer), **não** um preâmbulo por-ação
  construído pelo cliente. (INFERIDO; conteúdo cifrado não decodificado — a identidade exata
  128B ≡ `0x8280` é NÃO VERIFICADA.)
- **Reconciliação com o RELATO.** O relato "um `0x8280` sai imediatamente antes de toda ação" é
  compatível com uma observação **no fio** (onde o egress periódico de 128 B se intercala com a ação),
  **não** com construção do `8280` pelo cliente — que a sonda refuta. A classificação do RELATO passa
  de HIPÓTESE a **parcialmente reconciliada**: o `8280` existe e é Gepard-side, mas não precede
  causalmente cada ação como pacote do cliente.
- **Consequência para o merge (favorável).** Como o `8280` é do Gepard e não do cliente, o merge
  **não precisa sintetizá-lo**: ao deixar o cliente disparar uma ação **real** (via entrada natural),
  qualquer sync que o Gepard exija ocorre sozinho — exatamente o que o `INSERT→ataque` já mostrava.
- **Buffers das ações (OBSERVADO; insumo para `scramble-range`).** `buf` da `SendPacket` é **estável**
  por id e todos caem **dentro da `scramble-range` do `035F` já configurada** (`0x2632000–0x2730000`):
  `0x0437`→`0x271eb78`, `0x0438`→`0x27218cc`, `0x0AF4`→`0x27218fc` (e `0360`/`0368`→`0x272f37c`).
- **Corpos decodificados (em claro).** `0437` = `3704|GID|07` (ataque); `0438` =
  `3804|nível(2)|skill(2)|GID(4)`; `0AF4` = `f40a|0100|skill(2)|x(2)|y(2)` — **o `0AF4` carrega
  skill+x+y no corpo**, confirmando o desenho "clique fixo + merge reescreve x,y".

**Lacunas específicas da coleta histórica de 2026-10-16 (não são falhas operacionais atuais):** naquela coleta ainda não havia captura individual do store `gepard+0x18eff2` no envio natural de `0438`/`0AF4`; o responsável confirmou as skills automáticas funcionais posteriormente. Permanecem perguntas separadas de protocolo: a identidade binária do egress de 128 B com `0x8280` e a possível variação do `control_value`. Captura crua (gitignored):
`research/action_0437_0438/captures/obs8280_20261016/`.

**Spike de isolamento** para dirigir a ação por input sintético escondido:
[`research/action_0437_0438/ISOLATION_SPIKE.md`](HISTORY/ACTIONS_COMPLETE.md#source-research-action-0437-0438-isolation-spike-md).

## Ficha obrigatória para novas descobertas

- ID/nome proposto; direção e fase (login/char/mapa); versão/build e data;
- Comprimento e se a observação ocorreu em wire, após decifragem ou somente em tabela;
- Relação temporal com inicialização, reconexão ou heartbeat;
- Referência exata `arquivo:linha` ou teste reproduzível **sanitizado**;
- Classificação: OBSERVADO / INFERIDO / HIPÓTESE / NÃO VERIFICADO / REFUTADO;
- Explicação alternativa e teste offline capaz de distinguir interpretações;
- Informação necessária para futura interface de plugin OpenKore, **sem** assumir que o relay implementará xKore 0.

## Limite de arquitetura do futuro plugin

Quando houver protocolo demonstrado, a responsabilidade por inicialização de sessão, mensagens de controle periódicas e estado do protocolo deverá ser especificada como extensão **do OpenKore**. Este repositório permanece responsável pelo relay de texto claro na fase xKore 1. Nenhuma implementação de controle deve preceder evidência suficiente de direção, transições de estado e testes reproduzíveis.

## Fechamento funcional das ações e limite criptográfico — 2026-10-17

**CONFIRMADO PELO RESPONSÁVEL:** ataque automático `0437`, skill de alvo `0438` e de chão `0AF4` estão funcionando. Não há bloqueio pendente da automação por `0368`, lock de alvo ou coordenação de movimento. O primeiro byte do corpo entregue pelo consumidor estava saindo com contribuição do original do cliente por conta da ordem do store byte a byte; o `_fix0` o corrige no hit seguinte (`agent/relay_hook_linux.js:481-534`).

**OBSERVADO NO CÓDIGO:** escrita de corpo pré-XOR e restauração `c0 ^ orig0 ^ our0`. **NÃO VERIFICADO NESTA REVISÃO:** nova captura de rede pós-fix por família e reconstrução do algoritmo criptográfico. A observação de `0x8280` periódico é registro separado; não transformá-lo em preâmbulo obrigatório por ação.

Os experimentos históricos `0368`/`SendPacket` cru, replay de `0x2a` e `0x8280` permanecem preservados com seu escopo original. A interpretação final e matriz de evidências estão em [ACTION_0437_0438_INVESTIGATION](HISTORY/ACTIONS_COMPLETE.md#source-docs-action-0437-0438-investigation-md).
