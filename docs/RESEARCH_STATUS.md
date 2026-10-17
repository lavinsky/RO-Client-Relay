# RO-Client-Relay — estado atual do conhecimento técnico

**Atualização canônica — 2026-10-17 (responsável):** movimento `0x035F`, ataque automático `0x0437` e skills automáticas de alvo `0x0438` e de chão `0x0AF4` estão **FUNCIONAIS / pesquisas encerradas**. A falha do ataque automático era o primeiro byte do corpo reescrito no store do scrambler pelo agente Frida, não a seleção do alvo nem um gate de walk; a correção `_fix0` está em `agent/relay_hook_linux.js:481-534`. **Somente a investigação da cifra permanece ativa**. Ver [ACTION_0437_0438_INVESTIGATION.md](ACTION_0437_0438_INVESTIGATION.md). Resultados antigos abaixo são históricos e não descrevem falha operacional atual.

> **Integração 2026-10-16:** [entregas conferidas e limites](#integração-de-entregas--2026-10-16) atualizam os checkpoints anteriores; relatos, consistência de artefatos e prova independente permanecem distintos.

> **Revisão documental local:** 2026-10-15, `main@524b0f05fa61872e140f98ace9e503d12356641e`. Pacote inicial baseado em `bdc2a07`, reconciliado com `2645fad`, `87245d6` e o ensaio posterior de `524b0f0`. Alterações preexistentes foram preservadas; artefatos privados/ignorados não foram abertos. **Este arquivo é o mapa; os estudos especializados contêm a evidência integral.**

## A. Estado geral — revisão 2026-10-15

**Decisão confirmada:** objetivo final de usar o **OpenKore externo em xKore 0, sem cliente**. A etapa intermediária emprega o xKore 1 já presente no OpenKore, o relay Python/Frida e o cliente uaRO para preparar/cifrar tráfego. Uma implementação independente do protocolo, quando justificada por evidências, pertence ao projeto OpenKore como integração/plugin, e **não** a um backend xKore novo neste repositório. Fonte: [RESEARCH_DECISIONS](RESEARCH_DECISIONS.md), seção *Decisões confirmadas*; [AGENTS.md](../AGENTS.md).

**OBSERVADO na implementação/documentação de operação:** o agente Frida inspeciona `recvmsg`/`sendmsg` sob Wine/Proton; o driver ordena quadros, tenta substituir corpos recebidos somente com cópias decifradas verificadas pelo cliente e oferece tráfego ao consumidor XKore 1 (`R` e `S`). Os caminhos de escrita são distintos: merge reativo no store do `0x035F` e `SendPacket` para ações da fila (`0x0437`/`0x0438`), usando o próprio cliente. A **transformação final** do `0x035F` é um **XOR in-place byte a byte** no store do scrambler (`gepard+0x18eff2`) — **FATO/OBSERVADO na implementação do relay** (`agent/relay_hook_linux.js:224-233`, `:518`; `relay/writeback.py:4-6`; `relay_capture.conf:99-111`); a geração de keystream, o estado e a inicialização **anteriores** ao XOR continuam **DESCONHECIDOS** (ver [CIPHER_INVESTIGATION](CIPHER_INVESTIGATION.md)). `relay_capture.conf` fixa intencionalmente `inject = true` e `inject-call = true`, embora defaults internos do CLI sejam outros. Fontes: [arquitetura](ARCHITECTURE.md), [operações](OPERATIONS.md), `relay/writeback.py`, `relay/wire_feed.py`, `relay/relay.py`, `agent/relay_hook_linux.js`.

**Limitações:** o merge do movimento **pelo relay** é reativo, não inicia por conta própria um passo natural; chamar `0x035F` pela rotina da fila foi associado à dessincronização de cifra na sessão documentada de 2026-10-13. Existe, à parte do relay, uma **primitiva nativa de andar autônomo OBSERVADA uma única vez** (§13.10/M-11) disparada de um sítio de main-loop via HW exec BP — **contexto de disparo não-natural; reproduzida na rodada 08 (nova sessão, M-13) para a sonda PE**; não eleva o relay a inicializador nem prova um mecanismo geral. A cifra atual não foi reconstruída e o comportamento suficiente para xKore 0 permanece desconhecido. Resultados do cliente, ainda que documentados com controles, são específicos do build e da janela indicada em cada evidência.

## B. Linhas de pesquisa — revisão 2026-10-15

| Linha | Estado fundamentado | Fonte detalhada | Próxima dependência |
|---|---|---|---|
| Movimento `0x035F` | **CONCLUÍDO (funcional, confirmação do responsável 2026-10-17)**; cadeia natural e PoC relay registrados nas rodadas 06b/08/09; ensaios negativos antigos preservados | [Investigação](MOVEMENT_035F_INVESTIGATION.md), [Pré-condições](MOVEMENT_035F_PRECONDITIONS.md) | Sem investigação de movimento ativa; detalhes não resolvidos da cifra pertencem à linha CIFRA |
| Ações `0x0437`/`0x0438`/`0x0AF4` | **CONCLUÍDAS (funcionais, confirmação do responsável 2026-10-17)**; bug do byte zero no Frida resolvido por `_fix0`, não por seleção de alvo | [Ações](ACTION_0437_0438_INVESTIGATION.md); `agent/relay_hook_linux.js:481-534` | Nenhuma pesquisa de ação ativa; não confundir histórico ACT-03 com estado atual |
| Cifra atual | **OBSERVADO:** origem imediata de CL até o store, XOR local independente e última escrita com byte associado ao consumidor; **NÃO VERIFICADO:** produção anterior, papel criptográfico, estado/inicialização, fronteira P/C e vetor completo | [Cifra](CIPHER_INVESTIGATION.md) §§ *Retomada após consolidação*, *Nova instância*; C-05–C-07 abaixo | Confirmar `+0x1C70DC pop [edx]` antes/depois e seguir a origem de seu operando |
| Controle de sessão/Gepard | Tabela uaRO contém tamanhos de alguns IDs; modelo `SC_GEPARD_INIT` e `CS_GEPARD_INIT_ACK` é **histórico de 2016**, não especificação do build atual. Papel de `0x8280` é **HIPÓTESE** | [Pacotes de controle](GEPARD_CONTROL_PACKETS.md) | IDs, direção, fase, handshake, reset, cadência, transições no build atual |
| OpenKore/relay | xKore 1 em uso como ponte; rota futura xKore 0 depende de demonstrar protocolo e estados sem o cliente | [Arquitetura](ARCHITECTURE.md); [Decisões](RESEARCH_DECISIONS.md) | Provas da cifra e controles; decisão humana sobre integração futura |
| Instrumentação | `research/movement_035f/` e `research/cipher/` fornecem sondas e análises; fixtures sintéticas não são evidência dinâmica | Documentos especializados e `research/*/README.md` | Nova autorização/coordenação de exclusividade para qualquer experimento vivo |

**Diferenciar códigos internos e rede:** `0x11`, `0x0D`, `0x5B`, `0x8A` referem-se ao despacho interno observado, **não** a IDs de pacote no fio. `0x035F` é ID de pacote de movimento; `0x0087`, resposta observada com destino correspondente, **não prova chegada final** ao destino.

## C. Descobertas e evidências confirmadas — revisão 2026-10-15

### M-01 — despacho natural e ABI

**OBSERVADO no mesmo build em S1/S2:** seis capturas manuais positivas mostraram dispatcher `0x11 → 0x0D → 0x5B` antes do store `0x035F`; cliques alternados adicionais correlacionaram `0x8A`, coordenadas, store e resposta `0x0087`. O receptor virtual do slot `0x18` resolve para `gepard+0x10A90`, com argumentos `(0x8A,x,y,0,0)` em ECX/stack; retorno natural em `0xd477bf`, consistente com thiscall e cinco argumentos de 32 bits. Unidade de observação e limitações: [MOVEMENT_035F_INVESTIGATION](MOVEMENT_035F_INVESTIGATION.md) §§ *S1*, *Replicação S2*, *ABI natural*.

### M-02 — observabilidade do transporte e controle independente

**OBSERVADO em janela posterior:** `observe_path.py` correlacionou dispatcher, receptor, store identificado, `sendmsg` e `recv_0087` com canais independentes. O transporte encontrado foi `sendmsg` (não `sendto`) no escopo observado; a correspondência com `0x035F` exigiria buffer/proveniência independentes, não só retorno de cinco bytes. `0x0087` foi coletado independentemente do gate de store. Eventos foram ordenados pelo índice, não por relógio. [MOVEMENT_035F_PRECONDITIONS](MOVEMENT_035F_PRECONDITIONS.md) §5.

### M-03 — folha `0x8A` insuficiente na tentativa delimitada

**REFUTADO no escopo do ensaio 6.4:** hipótese M-H1 de que a ausência do store/ACK na tentativa nativa fosse **apenas** artefato de observadores dependentes do store. Com detector de store sem gate de pilha, observação independente de `sendmsg`, controle natural antes/depois e entrada/retorno correto no receptor, a chamada isolada não gerou store `0x035F` nem `sendmsg` atribuíveis **naquela janela**. Isso **não** localiza a dependência preparatória, não demonstra ausência absoluta de tráfego e não separa M-H2 de M-H3. [MOVEMENT_035F_PRECONDITIONS](MOVEMENT_035F_PRECONDITIONS.md) §§4–5.

### M-04 — estado a montante é candidato, não dependência comprovada

**OBSERVADO por inspeção do código:** caso `0x11` interage com `+0x70`, `+0x510`, `+0x534`, `+0x538`; caso `0x0D` zera `+0x50c` e `+0x500`; caso `0x5B` compara getter com `+0x520` e constante `0x15E`, escreve `+0x520` e despacha `0x8A`. **NÃO VERIFICADO:** qual campo é consumido pelo receptor, significado do gate ou unidade de `0x15E` (não chamar de 350 ms). `this` do dispatcher difere do `this` receptor; não presumir mesma instância. [MOVEMENT_035F_PRECONDITIONS](MOVEMENT_035F_PRECONDITIONS.md) §3.

### M-07 — reconciliação dos commits posteriores ao pacote

**OBSERVADO nos registros de §12 das pré-condições:** forma dos argumentos natural e nativa
igual a `(0x8A,x,y,0,0)`; nenhum campo do dispatcher passado como argumento no callsite
`0xd477a4–0xd477bc`. Não houve ponteiro entre dispatcher e manager nas varreduras de
1024 B em ambas as direções, nem no recorte de 128 B do registro global `[0x1213338]`;
8+ eventos em três sessões de passos reportadas. Cinco campos `+0x5xx` ficaram constantes
nos dois passos detalhados. Retorno natural `0xd477bf` difere do trampolim nativo.
**INFERIDO:** H2 por ponteiro fica excluída apenas nessa cobertura; H3 ganha força relativa.
Valor global `byte[0x1602a8f]`, TLS, offsets fora do recorte e indireções profundas não foram
excluídos. Nenhuma leitura do global pelo receptor foi demonstrada.

Origem: commits `2645fad`/`87245d6`,
[MOVEMENT_035F_PRECONDITIONS.md §12](MOVEMENT_035F_PRECONDITIONS.md#12-coleta-viva-read-only-fase-cd--resultado-e-matriz-de-evidências).
Critério de refutação de H2 residual: observar ou excluir o consumo em cobertura delimitada;
para H3, demonstrar necessidade do contexto mantendo estado e argumentos comparáveis.
São propostas que exigem nova autorização; nenhuma foi executada nesta consolidação.

### M-08/M-09 — dispatcher: conteúdo no trap e travamento com 11/13 dwords

**Origens:** `524b0f0` (ensaio inicial), `888764a` (auditoria ABI) e `7a64581` (ensaio de
13 dwords, §13.5). As datas/revisões iniciais desta página identificam a primeira consolidação;
esta seção incorpora os resultados posteriores antes da publicação.

**OBSERVADO no registro:** em `disp2`, conteúdo de buffer compatível com corpo `035F` para o
destino pedido no trap de execução **anterior** ao store, sem confirmação de escrita concluída
ou pacote finalizado. `disp5`, sem HW breakpoints ativos, também travou, mas não observou o
mesmo trap: não combinar as condições como se fossem uma única coleta.

**OBSERVADO por disassembly documentado:** epílogo `ret 0x34`, 52 bytes de argumentos;
a chamada inicial empilhava 44 bytes. **Resultado posterior (§13.5):** repetir com 13 dwords
(52 bytes), capturados do frame natural e alterando x/y, ainda produziu congelamento, sem
`emit_return`, `native_exception`, envio ou resposta observados durante a chamada. Houve
conteúdo de movimento correspondente no trap pré-store. O registro descreve isso como
montagem, mas o breakpoint de execução isolado continua sem provar a escrita posterior.

**REFUTADO nesse recorte:** atribuir o travamento exclusivamente aos 8 bytes ausentes na
chamada inicial; a variante de 52 bytes também falhou. **HIPÓTESE:** reentrância no hook
`poll/select`, ou outra dependência de estado/contexto. Ausência de exceção reportada não
exclui globalmente toda falha nativa ou perda de observação. H2/H3 continuam não isoladas.
Até §13.5 **não havia** movimento autônomo funcional demonstrado (resultado superado pela rodada
06b — ver M-11). Detalhes e próxima proposta em
[pré-condições §§13.1–13.5](MOVEMENT_035F_PRECONDITIONS.md).
Nenhuma coleta foi executada por esta tarefa de publicação.

### M-10 — dependência de fase de execução (rodadas 04/05)

**Correção de leitura (§13.8):** o `035F` é **CIFRADO**; o `store_035f` observado em
`gepard+0x18eff2` é o **byte-store in-place do scrambler** (`relay_capture.conf:99-111`). Leituras
de `035F` como "texto claro" estão **REFUTADAS**.

**OBSERVADO (§13.9, cliente Wine):** a main thread drena o wineserver por `read`/`writev`, quase não
usa libc `poll`; a âncora foi corrigida para `read` onLeave. Disparando o dispatcher nesse ponto, a
rodada 04 (delay 700 ms) **retornou** e o scrambler cifrou o corpo injetado, mas o cliente
**congelou após o retorno**, sem `sendmsg`/`recv_0087`. A rodada 05 (delay 2 s) **abortou durante a
chamada** (SIGABRT, `pc=vdso`), também após cifrar o corpo. **Dependência de fase/contexto =
OBSERVADA** (manifestações distintas: freeze × abort). **HIPÓTESE LÍDER (não provada):** reentrância
Wine (chamada de lógica PE de dentro do `onLeave` de um `read` = pump do wineserver). Artefatos
privados por rodada em [RESEARCH_EVIDENCE_INDEX](RESEARCH_EVIDENCE_INDEX.md) M-10.
[Pré-condições §13.9](MOVEMENT_035F_PRECONDITIONS.md). Coleta não executada por esta tarefa documental.

### M-11 — rodada 06b: origem autônoma ponta-a-ponta (MARCO, cliente vivo)

**OBSERVADO (§13.10, uma única vez):** disparando o dispatcher 0x11 de um **sítio de main-loop do
`uaRO.exe`** (HW exec BP `0x4dcba0`, base `0x400000`), **fora** do contexto do `read` do wineserver,
a chamada **retornou** (`emit_return`, sem exceção), **enviou 5 B** (`sendmsg` during_call), recebeu
**`recv_0087` com dst = destino injetado** e o cliente permaneceu **responsivo** — 1ª origem autônoma
de `035F` ponta-a-ponta. **Classificação (limite preservado):** sustenta que o **contexto
read/wineserver era a causa** dos crashes 04/05; **NÃO** eleva a "reentrância resolvida em geral" (o
callback de HW-BP ainda é contexto não-natural). **Cobertura/perda:** os HW BP foram desarmados em
`doFire`, então o `store_035f` do scrambler **não** foi observado during_call; origem+cifra+envio ficam
provados **funcionalmente** pelo `sendmsg` 5 B + `recv_0087` dst=injetado, não pela observação do store.
**Lacunas:** reprodução (determinismo — **atendida para a sonda PE pela rodada 08, ver M-13**) e comparação com a via de relay (merge pré-XOR em
`gepard+0x18eff2`). Nova execução ao vivo exige direção direta do responsável. Artefato privado em
[RESEARCH_EVIDENCE_INDEX](RESEARCH_EVIDENCE_INDEX.md) M-11. [Pré-condições §13.10](MOVEMENT_035F_PRECONDITIONS.md).

### M-12 — rodada 09: PoC do relay, `035F` do OpenKore → dispatcher nativo (MARCO de integração, cliente vivo)

**OBSERVADO (live, 2026-10-16, uma única vez):** a primitiva de M-11 foi **integrada ao relay/agent
de produção** e dirigida pelo **OpenKore de ponta a ponta**. Um `035F` do consumidor (XKore `S`) é
decodificado e roteado para o **dispatcher nativo do cliente** (`0xd473b0`, fire-site `0x4dcba0`);
o cliente monta/cifra o próprio `035F`, o servidor responde `recv_0087 dst = destino` e o cliente
fica **VIVO** (4 critérios de M-11 = SIM). O `035F` original é **dropado** — o relay **não** fabrica
corpo cifrado nem reencaminha. **Orçamento de DR 4/4** (scramble/SendPacket/captura `this`/fire-site);
`send-watch` OFF obrigatório. **Gotcha:** `move_dispatch` soma ao `inject-call`
(`relay/writeback.py:101-107`), não o substitui. **Classificação/limite:** a cifra **não** está
compreendida — o relay só decide o destino e aciona o código nativo (§13.8 segue DESCONHECIDO antes
do XOR); OBSERVADO uma vez, sem reprodução multi-sessão; `this` recapturado por sessão. Mudanças em
**working tree, não commitadas**. [Pré-condições §13.11](MOVEMENT_035F_PRECONDITIONS.md);
[índice M-12](RESEARCH_EVIDENCE_INDEX.md). Achado de pacotes de controle associado (ataque `0437`/
perícia `0438` × seleção `0368`) em [GEPARD_CONTROL_PACKETS](GEPARD_CONTROL_PACKETS.md) —
**posteriormente REFUTADO** como solução (ver A-01).

### C-01 — bytes efetivamente acompanhados, não cifra resolvida

**OBSERVADO:** escritor `gepard+0x1C752B: mov [esi],cl` em ocorrência independente; carga `+0x1B223C: mov al,[eax]`; extensão `+0x1B2252: movzx ecx,al`; store intermediário `+0x1B2255: mov [ebx],ecx` numa posição `EBP+0xA5`; consumidor `+0x18EFEC: mov ebx,[ebx]` até `+0x18EFF2: mov [ecx],bl`. As setas no documento especializado indicam associação de memória medida em rodadas específicas, **não** adjacência de instruções. A origem imediata de CL foi delimitada posteriormente em C-05; geração anterior, estado e identidade/limites do pacote seguem desconhecidos. [CIPHER_INVESTIGATION](CIPHER_INVESTIGATION.md) §§ *Continuação dinâmica*, *Evidências e limites*.

### C-02 — experimento negativo e limites de cobertura

**OBSERVADO:** 26 artefatos de rodadas com seis `matched`, um `byte_producer_confirmed`, quinze `timeout`, dois `unattributed_exception`, um `chain_timeout` e um `code_only`; todos com limpeza reportada. Um timeout entre escritor e consumidor **não comprova** geração antecipada em bloco, e monitoramento por thread não comprova ausência de escritores globais. A ferramenta offline continua retornando `C_INSUFFICIENT`/sem chamada completa. [CIPHER_INVESTIGATION](CIPHER_INVESTIGATION.md) §§ *Rodadas efetivamente executadas* e *Ferramenta offline*.

### C-06 — XOR local observado, sem atribuição à cifra

**OBSERVADO:** `+0x2689FB xor dword ptr [ecx],edx` alterou a posição investigada
conforme seus operandos medidos antes/depois. Houve 17 escritas posteriores, sem
consumidor retido nessa rodada; não atribuir esse XOR ao byte final nem a fluxo ou
estado criptográfico. [Cifra — nova instância](CIPHER_INVESTIGATION.md#nova-instância-e-primeiro-escritor-aritmético-observado).

### C-07 — último escritor candidato ligado ao consumidor

**OBSERVADO:** com teto autorizado de 256, 129 escritas precederam uma cadeia de
13 pontos; o byte da última escrita coincidiu com o carregado/armazenado por CL,
na mesma thread/EBP. **INFERIDO:** única candidata `+0x1C70DC pop dword ptr [edx]`;
confirmação antes/depois preparada, ainda sem acertos vivos. O marco não demonstra
cifra ou produção do operando na pilha. [Cifra — nova instância](CIPHER_INVESTIGATION.md#nova-instância-e-primeiro-escritor-aritmético-observado).

### C-05 — origem imediata de CL demonstrada na retomada

**OBSERVADO em nova janela exclusiva:** `gepard+0x1C7502: mov ecx,[ecx]` carregou uma
dword de uma posição `EBP+0x36`; ECX permaneceu igual pelos pontos executados até
`+0x1C752B: mov [esi],cl`, com byte posterior ao store correspondente. Foram 13 pontos
em 9 ms, sem perda de ordem/contexto e com limpeza confirmada. O endereço de ECX foi
salvo antes da carga; não se inferiu o caminho por disassembly linear.
**NÃO VERIFICADO nesse recorte:** escritor dessa posição, papel criptográfico, estado e identidade
do pacote. A associação posterior de escrita→carga está delimitada em C-07.
[Cifra — retomada após consolidação](CIPHER_INVESTIGATION.md#retomada-após-consolidação--origem-executada-de-cl).

## D. Hipóteses registradas no período exploratório — histórico (movimento encerrado)

As entradas `M-H2/M-H3/M-H4` preservam lacunas explicativas dos ensaios negativos, **não** representam pesquisas atualmente abertas. Em 2026-10-17 somente a cifra permaneceu ativa.

| ID | Status | Favorável | Limite/rival | Experimento discriminatório (planejamento, **não executado aqui**) |
|---|---|---|---|---|
| M-H2 | **HIPÓTESE não isolada** — preparação de estado | Buffer compatível no trap pré-store em §13; folha isolada sem store atribuído em 6.4 | Contexto também mudou; não prova necessidade dos campos. Exclusões de §12 restritas à cobertura; consumo de global não observado | Demonstrar consumo de estado mantendo contexto comparável; proposta própria |
| M-H3 | **PARCIALMENTE SUSTENTADA** — contexto/callsite | Dependência de fase OBSERVADA (§13.9); disparar fora do contexto `read`/wineserver (06b, §13.10) retornou+enviou+manteve o cliente vivo, enquanto no `read` onLeave travava/abortava | Causa exata do crash 04/05 ainda HIPÓTESE (reentrância Wine, não provada); callback de HW-BP é contexto não-natural; 06b reproduzida em 08 (M-13), sem variar fase/ponto; não isola de M-H2 | Reproduzir 06b; variar a fase/ponto e medir; comparar com a via de relay |
| M-H4 | **HIPÓTESE residual** — destino/condição | Resultado negativo pode depender de regras de movimento | Destino alterado em 6.4 e ainda assim não houve store/envio | Escolher destino com ground-truth em experimento autorizado |
| C-H1 | **NÃO VERIFICADO** — região de estado incorreta | Janela EBX histórica não foi demonstrada como estado | Cargas rastreadas são cópias, não evolução de estado | Seguir última definição de CL e efetivas leituras/escritas de estado |
| C-H2 | **NÃO VERIFICADO** — geração antecipada | Há bytes já disponíveis a copiar | Nenhum produtor criptográfico ou fronteira de geração demonstrado | Distinguir operação geradora de transporte de byte |
| C-H3 | **SUSPENSA** — dependência de fronteira/comprimento | Modelo plausível de cipher histórico | Falta vetor contíguo completo e independente | Observar entrada, saída e estados antes/depois sem inferir resets |
| G-H1 | **HIPÓTESE** — `0x8280` como heartbeat | Tamanho 128 em tabela; associação histórica | Direção/papel não comprovados no build atual; `0x8285` é referência 2016 | Verificar fase, direção, estrutura e cadência com evidências do build atual |

## E. Refutações e interpretações superadas — revisão 2026-10-15

- **M-H1 (observabilidade apenas): REFUTADO no ensaio 6.4.** Documentação anterior de movimento, com ACK condicionado ao store, corretamente registrava resultado inconclusivo. A coleta posterior criou observadores independentes e permitiu conclusão mais forte, **restrita à tentativa testada**. [Pré-condições](MOVEMENT_035F_PRECONDITIONS.md) §5.
- **Wrapper `uaRO+0x875400` como discriminador isolado da intenção: REFUTADO nas amostras S1.** As chamadas ocorreram tanto em repouso como em movimento; isso não refuta participação em outros caminhos. [Investigação](MOVEMENT_035F_INVESTIGATION.md) § *S1*.
- **Wrapper `0xc7650e` obrigatório para todo movimento: REFUTADO em uma amostra** com store/ACK sem hit; outros ramos não são excluídos. Distinguir seu `0x11` do `0x11` interno do dispatcher. [Investigação](MOVEMENT_035F_INVESTIGATION.md) § *Origem da preparação*.
- **Registros `EBX` após `+0x18EFEC` como ponteiro original de carga: REFUTADO para o recorte executado.** Após a carga, contém uma dword carregada/estendida. Não inferir identidade de estado da cifra de uma janela alinhada a EBX. [Cifra](CIPHER_INVESTIGATION.md) § *Evidências e limites*.
- **Modelo Gepard 2016, padrões de `ramp`, papéis de `0x8280` e escolha dos IDs de cifra do build atual:** **NÃO VERIFICADOS** por equivalência de build. Textos de raiz às vezes os apresentam categoricamente; preservá-los como **referência histórica ou hipótese**, não fatos atuais. [Inventário de controle](GEPARD_CONTROL_PACKETS.md), [cifra](CIPHER_INVESTIGATION.md) §§ *Evidências auditadas*, *Três famílias*.
- **A suposição de que um store pré-XOR já demonstra a operação criptográfica:** **NÃO SUSTENTADA** pelas observações atuais. O store é compartilhado e os recortes incluem cópias; a geração de keystream/CL não foi observada como tal.

## F. Prioridade corrente e histórico de encerramento — 2026-10-17

1. **ÚNICA PESQUISA ATIVA: CIFRA.** Linhagem de CL recuada por transportes até `EBP+0x57`/`EBP+0x09` (C-10) sem operação geradora demonstrada. Faltam produtor, estado, inicialização, fronteira P/C, vetor independente e vínculo dos valores recebidos no login. Ver [CIPHER_INVESTIGATION](CIPHER_INVESTIGATION.md).
2. **MOVIMENTO `0x035F`: CONCLUÍDO.** Funcional pelo fluxo OpenKore → dispatcher nativo → cliente, confirmado pelo responsável. Preservar resultados negativos anteriores para procedência, sem agendar novos ensaios como investigação prioritária.
3. **AÇÕES `0x0437`, `0x0438`, `0x0AF4`: CONCLUÍDAS.** Ataque automático e skills automáticas de alvo/chão estão funcionais. **Causa da falha antiga:** byte 0 do corpo regravado pelo store do scrambler depois da injeção Frida; corrigido em `agent/relay_hook_linux.js` por `_fix0`. Diagnósticos de seleção/alcance/egress FIFO como raiz são superados. Consulte [Ações](ACTION_0437_0438_INVESTIGATION.md).
4. **Protocolos/controle de sessão:** lacunas de conhecimento são **dependências subordinadas à investigação da cifra / meta futura xKore 0**, e não reabertura das trilhas funcionais encerradas. Nenhuma investigação autônoma adicional está ativa por decisão do responsável.
5. **Restrições:** preservar `inject = true` e `inject-call = true`; resultados desta edição são documentais, sem nova coleta ao vivo nem autorização implícita de atividade de rede. Os detalhes históricos anteriores da seção `D` são hipóteses arquivadas, não backlog vigente.

**Mudança de status:** confirmação expressa do responsável em 2026-10-17 e correção `_fix0` presente no commit-base. O documentador verificou o código, não repetiu experimentos live.


## G. Mapa documental — revisão 2026-10-15

| Pergunta | Leia primeiro | Depois, se necessário |
|---|---|---|
| Situação e prioridades | Este documento | [README da documentação](README.md) |
| Cadeia `0x035F` | [MOVEMENT_035F_INVESTIGATION](MOVEMENT_035F_INVESTIGATION.md) | [Pré-condições](MOVEMENT_035F_PRECONDITIONS.md) e `research/movement_035f/` |
| Ações `0437/0438/0AF4` concluídas | [ACTION_0437_0438_INVESTIGATION](ACTION_0437_0438_INVESTIGATION.md) | `agent/relay_hook_linux.js`, `research/action_0437_0438/HANDOFF.md` |
| Pré-condições/ensaio isolado | [MOVEMENT_035F_PRECONDITIONS](MOVEMENT_035F_PRECONDITIONS.md) | [Investigação](MOVEMENT_035F_INVESTIGATION.md) |
| Dependências de bytes/cifra | [CIPHER_INVESTIGATION](CIPHER_INVESTIGATION.md) | `research/cipher/README.md`, `research/cipher/chain_audit.py` |
| Pacotes de controle | [GEPARD_CONTROL_PACKETS](GEPARD_CONTROL_PACKETS.md) | [Índice de evidências](RESEARCH_EVIDENCE_INDEX.md) |
| Arquitetura/threads | [ARCHITECTURE](ARCHITECTURE.md) | `../ARCHITECTURE.md` (fonte legada detalhada), código |
| Instalar/executar | [OPERATIONS](OPERATIONS.md) | `../README.md`, `../relay_capture.conf`, `../relay/cli.py` |
| Decisões aprovadas | [RESEARCH_DECISIONS](RESEARCH_DECISIONS.md) §1 | [AGENTS](../AGENTS.md) |

**Aviso:** referências acima correspondem à documentação consolidada no checkout; todas as medições dinâmicas vêm dos documentos existentes, não foram repetidas nesta auditoria offline.

## Atualização recebida pelo pull

`origin/main@0a29193` incorporou [PROTECTION_FINGERPRINT_DIE.md](PROTECTION_FINGERPRINT_DIE.md):
Themida/WinLicense 3.XX no executável e VMProtect na DLL, confirmados pelo responsável nos
arquivos da mesma build. Isso não prova virtualização de funções individuais. A correção
local `888764a` foi preservada pelo merge. Metadados iniciais desta página identificam a
etapa anterior de consolidação; esta nota e M-08 registram a integração posterior.

## Integração de entregas — 2026-10-16

**Precedência:** esta seção atualiza os checkpoints anteriores de C-07 e M-11; os
relatos originais e os diffs da rodada 09 foram preservados. Documentador conferiu
somente trechos citados, sem executar cliente/sondas. Propriedade recebida de CIFRA
pelo handoff e de MOVER pela transferência confirmada pelo responsável.

### C-08 — POP-03: cópia associada a CL e ao pós-store

ID incorporado: **CIFRA-20261016-POP-03**, após **CIFRA-20261015-CL-01/WRITER-02**.
O artefato permite recalcular POP antes/depois, ESP+4, EDX estável e associação ao
byte carregado por CL, com pós-store na mesma ocorrência. 15 traps/uma escrita,
13 pontos, sem erros de leitura/ordem reportados. **Erro pós-DONE presente**:
`TypeError: not a function`; origem exata ainda em investigação. Limpeza própria
registrada, sem prova de saúde global. [Detalhes e limitações](CIPHER_INVESTIGATION.md#integração-documental--cifra-20261016-pop-03).
O próximo desconhecido é a origem anterior do operando; o POP já não é só candidato
nessa ocorrência. XOR de C-06 não ligado ao byte final; cifra/estado/vetor não resolvidos.

### M-13 — reprodução 08 e lições do contexto de disparo

IDs conferidos: **MOVER-20261015-06** (06b) e **MOVER-20261016-08** (reprodução).
Nos dois `trial.json` citados no handoff, a sequência inclui `emit_call`,
`sendmsg` solicitado/retornado de 5 bytes durante a chamada, `emit_return` e
`recv_0087` cujo destino coincide com o solicitado. Os dois registros informam
`cleared=true`, RPC de limpeza bem-sucedida, sem saturação/framing errors.
A reprodução usa nova instância/objeto/destino; a nota antiga “uma única vez, não
reproduzida” fica superada para a **sonda PE**, não para o PoC relay da rodada 09.

**Limites de decisão:** os BPs foram desarmados antes da chamada; nenhum store foi
observado durante essas duas chamadas. Envio de 5 bytes e resposta correspondente
sustentam funcionamento no recorte, mas não expõem corpo cifrado, operação XOR ou
estado criptográfico. Responsividade da UI e limpeza de todos os processos são
relatos de MOVER, não medições independentes desses JSON. O contraste com hangs
no contexto `read` sustenta **dependência do contexto/fase**; reentrância específica
não foi isolada. Sucesso nesse contexto não prova que outro seja causa única.

### Rodada 09 e fronteira para CIFRA

O [handoff do integrador](../research/HANDOFF_ORQUESTRADOR_CODEX.md),
**ORCH-20261016-01a**, relata PoC OpenKore/relay; os hunks §13.11/M-12 foram
preservados. As referências citam código, não um artefato vivo reproduzível; a
classificação nesta revisão é **relato do autor**, com implementação examinável,
sem revalidação independente de retorno/envio/resposta/saúde. São quatro DRs
previstos no modo combinado; exclusividade e liberação exigem confirmação atual.
A limpeza de MOVER-08 não libera automaticamente uma execução posterior do relay.
Comentários `writeback`/`scramble` e flags são contrato operacional; a instrução
`mov [ecx],bl` ou o uso de merge não demonstram por si só XOR nem seu gerador.
O relato de XOR final deve permanecer separado das cargas/cópias demonstradas por
CIFRA. Não se integra nova evidência criptográfica a partir de aceitação de movimento.

### Login — valores relacionados à cifra recebidos pelo cliente

Confirmado diretamente pelo responsável em 2026-10-16: no momento do login valores
relacionados à cifra são enviados ao cliente. É conhecimento informado, sem nova
captura independente nesta integração. Campos, pacote/fase exata, papel (seed/chave/
parâmetro), inicialização e vínculo com CL/estado continuam por identificar.
[Procedência e próximo discriminador](CIPHER_INVESTIGATION.md#valores-de-cifra-recebidos-no-login--confirmação-do-responsável).

## Integração de entregas — 2026-10-16 (segunda passada)

**Precedência:** atualiza F.1(d), F.2, M-11/M-12 e a seção "Login" acima. Fontes conferidas apenas
nos trechos citados; nenhuma coleta viva foi executada pelo Documentador.

### A-01 — dispatcher × ataque/perícia (ACT-20261016-01)

**OBSERVADO (read-only, ao vivo):** mapa dispatcher `0xd473b0` → pacote: `0x11`→`035F`,
`0x1f`→`0437` sentar/levantar, `0x28`→`0437` ataque (`3704 <GID> 07`), `0x2a`→`0438` perícia
(`3804 0a00 0d00 <GID>`), `0x0a`→seleção de alvo. Fronteira em claro na `SendPacket` uaRO+0x816640.
`0x28`/`0x2a` não levam argumentos no frame; cadeia de cast observada `0x29 → 0x5a → 0x2a`. Caller
imediato sempre `gepard+0xb2c251` (shim); cadeias de chamadores além dele **RETIRADAS**.

**OBSERVADO (injeção, autorizada):** replay `0x29→0x5a→0x2a` pelo fire-site `0x4dcba0` →
`0x2a` retorna 0, nenhum `0x0438` sai, cliente crasha de forma deferida. A primitiva de movimento
(M-11/M-13) **não transfere** para a perícia.

**REFUTADO (responsável):** "`0368` pré-select bloqueava `0437`/`0438`" — o envio sempre ocorria;
a falta de efeito é anterior. Isso supera a leitura da rodada 09b (M-12). **Em aberto:** sítio real e
pré-condição do `0x2a` (método proposto: *validated stack scan*, read-only).
[Detalhes](GEPARD_CONTROL_PACKETS.md#mapa-dispatcher--pacote-de-ação-act-20261016-01);
[pré-condições §13.13](MOVEMENT_035F_PRECONDITIONS.md).

### C-10 — CIFRA STACK-04 → SLICE-12: linhagem do byte de CL por transportes

IDs conferidos em `research/cipher/HANDOFF.md`: STACK-04, EARLIER-05, SOURCE-06, REPEAT-07,
LINEAGE-08, UPSTREAM-09, SWAP-10, SLICE-11, SLICE-12. **OBSERVADO** (por ocorrência, uma thread,
bytes sob watch): trocas PUSH/PUSH/POP/POP em `+0x1C70D6` (STACK-04, ESI==EDX, transporte redundante),
`+0x13A194..+0x13A19A` (SOURCE-06 `EBP+0x68→+0x36`; REPEAT-07 última troca `EBP+0x57→+0x36`, byte
preservado nas escritas cobertas até CL) e `+0x256883..+0x256889` (UPSTREAM-09/SWAP-10, POP/EAX
pré/pós). **HIPÓTESE** (SLICE-12, plano offline): cinco escritores `+1C70DC→+28E0A7→+13A19A→
+256889→+256809`, chegando à fonte `EBP+0x09`; só o prefixo `+13A194..+13A19A` foi executado na
coleta. **Nenhuma transformação criptográfica** demonstrada; XOR local (C-06) e XOR próximo a
`+0x256889` seguem candidatos sem ligação ao byte final.

**Saúde/limites:** `TypeError: not a function` pós-DONE em várias rodadas; mitigações "callback em
vez de null" e "sem RPC stop redundante" **REFUTADAS**; desarme antes do callback adiado foi seguido
por coletas sem erro, causalidade NÃO VERIFICADA. SLICE-11 foi **invalidada** por perda de
exclusividade (outro agente; relato do responsável) e deixou limpeza pendente restrita àquela
instância. Não fundir ocorrências de instâncias diferentes.
[Detalhes](CIPHER_INVESTIGATION.md#integração-documental--cifra-stack-04--slice-12).

## Histórico de implementação — ações via gatilho natural + merge (2026-10-16; concluídas em 2026-10-17)

**SUPERADO COMO ESTADO ATUAL:** a fase exploratória a seguir antecede `_fix0` e a confirmação funcional posterior. Em 2026-10-17 o responsável confirmou ataque/skills automáticas e atribuiu a falha ao primeiro byte regravado pelo scrambler após o merge; as lacunas abaixo descrevem somente o recorte de 2026-10-16. [Conclusão atual](ACTION_0437_0438_INVESTIGATION.md).

**Decisão (responsável, plan aprovado):** resolver ataque/perícia (`0437`/`0438`/`0AF4`) pelo mesmo
princípio do walk — **não fabricar**; deixar o cliente montar/cifrar/enviar o pacote natural (que já
emite o `0x8280`, ver [GEPARD_CONTROL_PACKETS](GEPARD_CONTROL_PACKETS.md#0x8280--candidato-a-syncanti-cheat-que-precede-as-ações-hipótese-em-teste))
e apenas **reescrever o corpo (GID/skill/coords) pré-XOR** no store do scrambler. Gatilho = **input
sintético híbrido** (uinput, passa no Gepard), com o cliente **isolado** para não atrapalhar o uso
real. Abandonadas para ações: injeção crua por `SendPacket` (REFUTADA, A-01) e disparo do dispatcher
fora de contexto (inócuo/instável, A-01/§13.13).

**Estado por fase:**
- **Fase 2 (roteamento, código) — FEITO, offline:** flag `--action-merge` (default OFF) roteia
  `0437/0438/0AF4` do consumidor para o merge quando há scrambler armado (modo combinado
  `--inject-call`). `relay/cli.py` (`--action-merge`), `relay/writeback.py` (`ACTION_MERGE_IDS`;
  ramo em `_on_inbound_split`), `tests/test_writeback.py` ("action-merge routing ok"). `035F`,
  `--move-dispatch` e `relay_capture.conf` inalterados. Verificado: `test-offline.sh` ALL PASS,
  `node --check` PASS, validadores PASS. **Sem commit.**
- **Fase 1 (caracterização do `8280`) — EXECUTADA ao vivo (2026-10-16, pid 3752762, 20 ações;
  read-only, HW BP + `sendmsg`):** OBSERVADO — o cliente **não** constrói `0x8280` (0 na `SendPacket`
  em 20 ações); há egress **periódico de 128 B** (~a cada 3,6 s) = o `8280` é **Gepard-origin e
  periódico**, não preâmbulo por-ação. Buffers de ação estáveis e **já dentro** da `scramble-range`
  do `035F` (`0x2632000–0x2730000`): `0437`@`0x271eb78`, `0438`@`0x27218cc`, `0AF4`@`0x27218fc`.
  `0AF4` carrega skill+x+y no corpo. **Consequência:** o merge não precisa sintetizar `8280` — basta
  o cliente disparar a ação real. Detalhe e classificação em
  [GEPARD_CONTROL_PACKETS](GEPARD_CONTROL_PACKETS.md) (ficha `0x8280`). Captura crua gitignored em
  `research/action_0437_0438/captures/obs8280_20261016/`.
- **Fase 0 (isolamento) — runbook pronto, spike PENDENTE:**
  `research/action_0437_0438/ISOLATION_SPIKE.md`. Maior risco: GPU única em Wayland/KDE sem `seatd`
  instalado; fallbacks (VM/2ª máquina; protótipo com interferência) documentados.

**Limites:** o merge só reescreve **corpo de mesmo id/tamanho** que o cliente montou → gatilho casado
por família. Não está confirmado ao vivo que `0438/0AF4` passam pelo mesmo store do `035F` (o `0437`
tem indício no `INSERT→ataque`). A cifra **continua não compreendida**; este caminho a contorna.
