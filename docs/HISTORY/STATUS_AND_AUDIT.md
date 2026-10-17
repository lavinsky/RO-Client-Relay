# Histórico integral — estado de pesquisa, decisões, evidências e auditorias

> **Registros congelados com proveniência.** A versão atual e resumida está em [`docs/RESEARCH_STATUS.md`](../RESEARCH_STATUS.md). O bloco original abaixo pertence ao período de investigação anterior; conclusões intermediárias não reabrem movimento e ações.

## Índice de arquivos originais

- [`docs/RESEARCH_STATUS.md`](#source-docs-research-status-md) — blob `c61054f423c47a874724e4e8b7d1f4741bd5085a`
- [`docs/RESEARCH_DECISIONS.md`](#source-docs-research-decisions-md) — blob `2a5e5ddd993fc90d65f175b7fbb8b69e7b051c63`
- [`docs/RESEARCH_EVIDENCE_INDEX.md`](#source-docs-research-evidence-index-md) — blob `b262ffd5193be265469b7741ca8346ec1cc822da`
- [`docs/DOCUMENTATION_AUDIT.md`](#source-docs-documentation-audit-md) — blob `e43c0e1ec601030df304e956c6a8ce505dab0c55`
- [`docs/DOCUMENTATION_SOURCES.md`](#source-docs-documentation-sources-md) — blob `3ca5c0a474fc17f363e2f9fbfe6d1d6fc865b723`

Reprodução literal de cada fonte entre marcadores HTML; nenhuma seção técnica foi omitida.

<a id="source-docs-research-status-md"></a>

## Fonte original: `docs/RESEARCH_STATUS.md`

Commit-base: `45483aaec7ee8546b9e81f5f1e569b83aa8dd911` · blob: `c61054f423c47a874724e4e8b7d1f4741bd5085a` · caracteres: 36763.

<!-- BEGIN ORIGINAL docs/RESEARCH_STATUS.md -->
# RO-Client-Relay — estado atual do conhecimento técnico

**Atualização canônica — 2026-10-17 (responsável):** movimento `0x035F`, ataque automático `0x0437` e skills automáticas de alvo `0x0438` e de chão `0x0AF4` estão **FUNCIONAIS / pesquisas encerradas**. A falha do ataque automático era o primeiro byte do corpo reescrito no store do scrambler pelo agente Frida, não a seleção do alvo nem um gate de walk; a correção `_fix0` está em `agent/relay_hook_linux.js:481-534`. **Somente a investigação da cifra permanece ativa**. Ver [ACTION_0437_0438_INVESTIGATION.md](ACTION_0437_0438_INVESTIGATION.md). Resultados antigos abaixo são históricos e não descrevem falha operacional atual.

> **Integração 2026-10-16:** [entregas conferidas e limites](#integração-de-entregas--2026-10-16) atualizam os checkpoints anteriores; relatos, consistência de artefatos e prova independente permanecem distintos.

> **Revisão documental local:** 2026-10-15, `main@524b0f05fa61872e140f98ace9e503d12356641e`. Pacote inicial baseado em `bdc2a07`, reconciliado com `2645fad`, `87245d6` e o ensaio posterior de `524b0f0`. Alterações preexistentes foram preservadas; artefatos privados/ignorados não foram abertos. **Este arquivo é o mapa; os estudos especializados contêm a evidência integral.**

## A. Estado geral — revisão 2026-10-15

**Decisão confirmada:** objetivo final de usar o **OpenKore externo em xKore 0, sem cliente**. A etapa intermediária emprega o xKore 1 já presente no OpenKore, o relay Python/Frida e o cliente uaRO para preparar/cifrar tráfego. Uma implementação independente do protocolo, quando justificada por evidências, pertence ao projeto OpenKore como integração/plugin, e **não** a um backend xKore novo neste repositório. Fonte: [RESEARCH_DECISIONS](RESEARCH_DECISIONS.md), seção *Decisões confirmadas*; [AGENTS.md](../AGENTS.md).

**OBSERVADO na implementação/documentação de operação:** o agente Frida inspeciona `recvmsg`/`sendmsg` sob Wine/Proton; o driver ordena quadros, tenta substituir corpos recebidos somente com cópias decifradas verificadas pelo cliente e oferece tráfego ao consumidor XKore 1 (`R` e `S`). Os caminhos atuais incluem `--move-dispatch` para o `0x035F` nativo e `--action-merge` + carrier natural para `0x0437`/`0x0438`/`0x0AF4`; `SendPacket` cru das tentativas anteriores permanece como caminho histórico, não mecanismo de sucesso das ações. A **transformação final** do `0x035F` é um **XOR in-place byte a byte** no store do scrambler (`gepard+0x18eff2`) — **FATO/OBSERVADO na implementação do relay** (`agent/relay_hook_linux.js:224-233`, `:518`; `relay/writeback.py:4-6`; `relay_capture.conf:99-111`); a geração de keystream, o estado e a inicialização **anteriores** ao XOR continuam **DESCONHECIDOS** (ver [CIPHER_INVESTIGATION](CIPHER_INVESTIGATION.md)). `relay_capture.conf` fixa intencionalmente `inject = true` e `inject-call = true`, embora defaults internos do CLI sejam outros. Fontes: [arquitetura](ARCHITECTURE.md), [operações](OPERATIONS.md), `relay/writeback.py`, `relay/wire_feed.py`, `relay/relay.py`, `agent/relay_hook_linux.js`.

**Limitações históricas (pré-PoC):** o merge reativo do movimento **pelo relay** não iniciava por conta própria um passo natural; a via posterior `--move-dispatch` concluiu essa integração funcionalmente. chamar `0x035F` pela rotina da fila foi associado à dessincronização de cifra na sessão documentada de 2026-10-13. Existe, à parte do relay, uma **primitiva nativa de andar autônomo OBSERVADA uma única vez** (§13.10/M-11) disparada de um sítio de main-loop via HW exec BP — **contexto de disparo não-natural; reproduzida na rodada 08 (nova sessão, M-13) para a sonda PE**; não eleva o relay a inicializador nem prova um mecanismo geral. A cifra atual não foi reconstruída e o comportamento suficiente para xKore 0 permanece desconhecido. Resultados do cliente, ainda que documentados com controles, são específicos do build e da janela indicada em cada evidência.

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
por família. Aquela coleta não havia confirmado individualmente `0438/0AF4` no store; **o responsável confirmou posteriormente as skills automáticas funcionais** após o fix `_fix0` no Frida. A cifra **continua não compreendida**; este caminho a contorna.
<!-- END ORIGINAL docs/RESEARCH_STATUS.md -->

<a id="source-docs-research-decisions-md"></a>

## Fonte original: `docs/RESEARCH_DECISIONS.md`

Commit-base: `45483aaec7ee8546b9e81f5f1e569b83aa8dd911` · blob: `2a5e5ddd993fc90d65f175b7fbb8b69e7b051c63` · caracteres: 7503.

<!-- BEGIN ORIGINAL docs/RESEARCH_DECISIONS.md -->
# Decisões e hipóteses de pesquisa (2026-10-15)

> **Precedência da evidência:** a seção de coleta abaixo antecede a etapa 6.4 e §§12–13 de [MOVEMENT_035F_PRECONDITIONS.md](MOVEMENT_035F_PRECONDITIONS.md). H1 foi refutada no recorte 6.4; §12 enfraqueceu vias específicas de H2; §13 foi corrigido em `888764a`: buffer compatível no trap pré-store não prova escrita concluída; ABI inicial de 44/52 bytes é incompatível, mas §13.5 (`7a64581`) também travou com 52 bytes; H2/H3 continuam não isoladas. As decisões confirmadas continuam preservadas.

## Decisões confirmadas pelo responsável
- **Final:** usar OpenKore (Perl, externo) em xKore 0, sem cliente oficial.
- **Intermediário:** xKore 1 existente no OpenKore + RO-Client-Relay + cliente uaRO, para encaminhar texto claro e utilizar o cliente como executor do protocolo.
- **Padrões intencionais:** manter `inject = true` e `inject-call = true` em `relay_capture.conf`.
- **Prioridade atual (2026-10-17, responsável):** apenas a investigação da **cifra uaRO/Gepard** permanece aberta. Movimento `0x035F`, ataque automático `0x0437` e skills automáticas `0x0438`/`0x0AF4` estão funcionais, com as pesquisas de movimento/ações encerradas. Ver [ACTION_0437_0438_INVESTIGATION](ACTION_0437_0438_INVESTIGATION.md).
- **Futuro:** documentar os pacotes de controle e requisitos de sessão para avaliar um plugin no OpenKore; referência: `docs/GEPARD_CONTROL_PACKETS.md`.

## Hipóteses históricas de movimento/ação e hipóteses remanescentes da cifra

**Atualização 2026-10-17:** hipóteses de falha do `0438`, seleção de alvo ou falta de alcance como causa da falha automática estão **SUPERADAS**. O defeito identificado pelo responsável foi o byte zero sobregravado pelo store após o merge; a implementação `_fix0` aparece em `agent/relay_hook_linux.js:481-534`. A tabela seguinte conserva a formulação **anterior** como histórico; não é backlog atual.

| Hipótese | Base | Limitação / alternativa |
|---|---|---|
| A intenção de mover aciona uma cadeia de preparação antes do envio de `0x035F` | `docs/HISTORY/ARCHITECTURE_LEGACY.md` §§9–10; analogia com roBrowserLegacy relatada pelo responsável | A analogia não prova equivalência entre implementações |
| A falha de `0x0438` está relacionada à cobertura/estado da cifra | Código servidor Gepard 2016 descrito em `docs/HISTORY/GEPARD_LEGACY.md` §3; comportamento descrito em `docs/HISTORY/ARCHITECTURE_LEGACY.md` §5.1 | Diferentes pré-condições de ação, parser e estado interno também podem explicar falhas. 2026-10-16: "era o `0368` pré-select" **REFUTADO** pelo responsável (pacote sai com/sem `0368`, ação sem efeito); disparo nativo `0x29→0x5a→0x2a` de `0x4dcba0` retornou `0x2a`→0 sem egress e crashou (ACT-20261016-01, [controle](GEPARD_CONTROL_PACKETS.md#mapa-dispatcher--pacote-de-ação-act-20261016-01)) |
| A sincronização do servidor é governada pelos estados de cifragem e mensagens de controle | Modelo do servidor 2016 | IDs, transições e algoritmos do build atual não estão completamente identificados |
| `0x8280` serve como heartbeat uaRO | `docs/HISTORY/GEPARD_LEGACY.md` §3.3; entrada 128 bytes na tabela | Papel/direção e equivalência com `0x8285` histórico pendem de evidência específica |

## Evidência nova de movimento — coleta autorizada em 2026-10-15

Origem/build, método, artefatos e limites: `docs/MOVEMENT_035F_INVESTIGATION.md`.
Cliente uaRO e servidor próprio expressamente autorizados; primeira etapa manual,
seguida de cliques uinput e dois ensaios nativos delimitados. Código do relay/agente
não foi alterado.

- **OBSERVADO:** seis capturas manuais, três por instância do mesmo build, com
  códigos internos `0x11 → 0x0D → 0x5B` antes de `0x035F`. Por código, caso `0x11`
  emite os dois seguintes; `0x5B` tem gate numérico `0x15E` e repassa `0x8A` ao slot
  virtual atual `gepard+0x10A90`. São mensagens internas, não IDs de rede.
- **OBSERVADO na automação:** seis cliques alternados com `0x8A == 0x035F`; três
  controles de cursor sem clique sem correspondência. Duas rodadas adicionais de
  três cliques validaram ECX/objeto, argumentos `(0x8A,x,y,0,0)`, remoção de 20 bytes
  pelo callee e resposta `0x0087` com destino igual. `0x11` do dispatcher também
  recebeu esse destino e teve retorno imediato em Gepard+`0xB2C251`.
- **REFUTADO no recorte:** presença isolada das duas chamadas históricas ao wrapper
  `+0x875400` distingue intenção: ocorreram também em 3/3 controles de repouso.
  Isso não refuta sua participação no fluxo.
- **OBSERVADO / limite:** ensaio nativo revisado entrou em `0x8A` com argumentos
  corretos na thread principal e retornou, sem par store/resposta confirmado em 10 s.
  Não demonstra ausência de tráfego nem rejeição. Rivais: estado preparatório,
  contexto VM/callsite, efeito local ou cobertura da sonda. Nenhuma integração dessa
  chamada ao relay foi autorizada por evidência suficiente; controles UI seguintes passaram.
- **HIPÓTESE/próximo teste:** localizar a produção do destino anterior ao dispatcher
  pelo chamador real na VM em Gepard+`0xB2C251`. A entrada `(0x11,x,y,0,0)` em
  `0xc7650e` é outro candidato; uma amostra teve movimento/ACK sem hit nesse callsite
  antes do store. O elo permanece não confirmado. Os inteiros vêm do estado de entrada;
  inspeção de `0xa797b0` sustenta hit-test de UI no recorte, sem projeção demonstrada.
  Pontos fixos de tela mudaram de destino de mapa entre rodadas; não congelar o par.
- **NÃO VERIFICADO:** transformação completa, requisitos autossuficientes da chamada,
  unidade do gate, cobertura entre builds e protocolo suficiente para xKore 0.

## Fingerprint das proteções (Detect It Easy, 2026-10-15)

- **OBSERVADO E CONFIRMADO PELO RESPONSÁVEL NA BUILD ATUAL:** os
  mesmos arquivos investigados foram submetidos ao DiE.
  `uaRO.exe` usa **Themida/WinLicense 3.XX**; `gepard.dll`
  usa **VMProtect**. O relatório textual completo fornecido
  nesta conversa é do executável; a detecção da DLL foi
  informada separadamente pelo responsável.
- **Limite técnico:** a presença desses protetores não prova quais
  rotinas específicas estão virtualizadas; os sinais heurísticos
  sobre seções/certificado não equivalem à execução de código.
- **Decisão histórica (2026-10-15):** priorizar `0x035F` e origem de `CL`. **Atualização 2026-10-17:** movimento encerrado; cifra/CL é a única pesquisa ativa. Não classificar como VM Themida ou VMProtect um callsite/região sem evidência de fluxo; H2/H3 são lacunas históricas, não investigações de movimento ativas.
- **Proveniência e detalhes:** [`PROTECTION_FINGERPRINT_DIE.md`](PROTECTION_FINGERPRINT_DIE.md).

## Método de atualização
1. Para cada afirmação, classificar: **OBSERVADO**, **INFERIDO**, **HIPÓTESE**, **NÃO VERIFICADO** ou **REFUTADO**.
2. Registrar prova/reprodução e versão. Uma análise histórica não demonstra o comportamento de builds posteriores.
3. Declarar pelo menos uma explicação rival e qual observação poderia refutar a hipótese.
4. Em handoffs, registrar somente conclusões e referências, sem copiar logs brutos nem dados de conta.
5. Resultados que dependam de cliente real/servidor externo devem indicar claramente se não foram reproduzidos em ambiente autorizado.

## Pendências humanas
- Determinar quais pacotes marcam estabelecimento e reinicialização de sessão no **build atual**.
- Decidir em qual repositório/estrutura manter um futuro plugin OpenKore e sua interface.
- Definir um protocolo de medição de economia de tokens: tarefas equivalentes, correção, retrabalho, duração e uso de franquia.
<!-- END ORIGINAL docs/RESEARCH_DECISIONS.md -->

<a id="source-docs-research-evidence-index-md"></a>

## Fonte original: `docs/RESEARCH_EVIDENCE_INDEX.md`

Commit-base: `45483aaec7ee8546b9e81f5f1e569b83aa8dd911` · blob: `b262ffd5193be265469b7741ca8346ec1cc822da` · caracteres: 22397.

<!-- BEGIN ORIGINAL docs/RESEARCH_EVIDENCE_INDEX.md -->
# Índice de evidências técnicas — RO-Client-Relay

**Atualização 2026-10-17:** movimento e ações encerrados funcionalmente; somente cifra é pesquisa aberta. A evidência de código para o defeito do byte zero está em `agent/relay_hook_linux.js:481-534`. Ver [A-02/A-03 abaixo](#a-02a-03--fechamento-de-movimento-e-ações-2026-10-17).

> **Integração 2026-10-16:** [entregas conferidas e limites](#c-08--integração-cifra-20261016-pop-03) atualizam os checkpoints anteriores; relatos, consistência de artefatos e prova independente permanecem distintos.

**Revisão:** 2026-10-15. **Referência:** revisão local `524b0f05fa61872e140f98ace9e503d12356641e`. Os resultados abaixo são **documentados em fontes primárias do repositório**, não verificados de novo em cliente real por esta auditoria. Os artefatos privados citados nos estudos **não acompanham** este índice.

| ID | Estado | Evidência / método original | Build e condições | Documento canônico / código | Limitação principal |
|---|---|---|---|---|---|
| M-01 | **OBSERVADO** | S1/S2: 6/6 capturas positivas, sequência `0x11→0x0D→0x5B→0x8A` até store de `0x035F` | Duas instâncias do mesmo build documentado, sessões distintas | [Investigação §§S1/S2](MOVEMENT_035F_INVESTIGATION.md); `research/movement_035f/` | Capturas até primeiro hit, não cobertura total de movimentos |
| M-02 | **OBSERVADO/INFERIDO** | ABI natural `(0x8A,x,y,0,0)`; ECX manager; ESP compatível com cinco argumentos; resposta `0x0087` correspondente | Mesmo build, cliques alternados e controles | [Investigação §ABI](MOVEMENT_035F_INVESTIGATION.md); `relay/packets.py` | ABI semântica inferida; ACK não prova conclusão do percurso |
| M-03 | **OBSERVADO** | Observadores independentes dispatcher/receptor/store/`sendmsg`/`recv_0087`, ordenação por evento | Run read-only de 10 s na janela controlada | [Pré-condições §5](MOVEMENT_035F_PRECONDITIONS.md); `research/movement_035f/observe_path.py` | `sendmsg` temporalmente correlacionado, bytes não identificados naquele run |
| M-04 | **REFUTADO no recorte** | Ensaio 6.4: `0x8A` isolado entra e retorna, sem store/`sendmsg` atribuível; controles naturais funcionam antes/depois | Mesmo build, objeto/args/thread conferidos, observadores independentes | [Pré-condições §§4–5](MOVEMENT_035F_PRECONDITIONS.md); `research/movement_035f/native_trial.py` | Refuta M-H1 (falha apenas de observabilidade), não distingue M-H2/M-H3; não ausência global |
| M-05 | **OBSERVADO/INFERIDO** | Disassembly dos casos `0x11/0x0D/0x5B`, campos +0x500/+0x50c/+0x510/+0x520/+0x534/+0x538 | Código identificado; distinção dos objetos dispatcher/receptor | [Pré-condições §3](MOVEMENT_035F_PRECONDITIONS.md); [Investigação §Casos internos](MOVEMENT_035F_INVESTIGATION.md) | Consumidor dos campos e unidade de `0x15E` não observados |
| M-06 | **REFUTADO no recorte** | Wrapper `+0x875400` observado em controles de repouso e de movimento; `0xc7650e` faltou em uma amostra positiva | S1 e uma amostra de callsite | [Investigação §§S1/Origem](MOVEMENT_035F_INVESTIGATION.md) | Não elimina esses caminhos de todos os ramos ou funções |
| C-01 | **OBSERVADO** | Breakpoints com operandos preservados verificaram `+0x1B223C → +0x1B2255 → +0x18EFEC..+0x18EFF2` em recortes delimitados | Arquivos de módulos identificados e revalidados em 2026-10-15 | [Cifra §Continuação dinâmica](CIPHER_INVESTIGATION.md); `research/cipher/chain_capture.py` | Não identifica entrada/saída de função criptográfica |
| C-02 | **OBSERVADO independente** | Watchpoint do byte consumido + escritor `+0x1C752B mov [esi],cl` confirmado em rodada isolada | Mesmo build; recortes não fundidos indevidamente | [Cifra §Evidências e limites](CIPHER_INVESTIGATION.md) | Última definição de CL e conexão com recorte consumidor não concluídas numa só rodada |
| C-03 | **OBSERVADO** | 26 rodadas, contagem de matches/timeouts/exceções e limpeza | Capturas reportadas em 2026-10-15, observação por thread | [Cifra §Rodadas](CIPHER_INVESTIGATION.md); `research/cipher/chain_audit.py` | Timeout ≠ ausência global de escrita; alguns observadores incompletos |
| C-04 | **NÃO VERIFICADO** | Auditoria de onze fontes: nenhuma chamada P/C/estado completa; ferramenta retorna `C_INSUFFICIENT` | Escopos variados, não unir sessões por nome/tempo | [Cifra §§Auditoria/Ferramenta](CIPHER_INVESTIGATION.md); `research/cipher/analyze.py` | Sem identidade de F, estado, inicialização, pacote ou cifragem independente |
| C-05 | **OBSERVADO** | Origem de CL: carga de dword em `+0x1C7502`, ECX estável até store `+0x1C752B`; 13 pontos/9 ms e byte posterior conferido | Mesmo build, nova instância descoberta e janela exclusiva; origem `EBP+0x36` nessa ocorrência | [Cifra — retomada](CIPHER_INVESTIGATION.md#retomada-após-consolidação--origem-executada-de-cl); `cl-round-1/chain-capture.json:161` em `/tmp/ro-cipher-20261015T174618Z/` | Não demonstra escritor da origem, operação da cifra ou continuidade com sessões anteriores |
| C-06 | **OBSERVADO** | XOR de dword `+0x2689FB`, operandos e resultado antes/depois conferidos; 17 escritas seguintes | Nova instância, mesma build, janela exclusiva | [Cifra — nova instância](CIPHER_INVESTIGATION.md#nova-instância-e-primeiro-escritor-aritmético-observado); `session2-cl-transform-round-1/chain-capture.json`, evento `DONE.cl_transformation`, na mesma raiz privada de C-05 | Não associado ao consumidor de CL; papel criptográfico desconhecido |
| C-07 | **OBSERVADO / INFERIDO** | 129 escritas, depois 13 pontos de carga→CL→store; última escrita com candidata única `+0x1C70DC pop [edx]`, byte correspondente | Mesma instância de C-06; teto de 256 autorizado; observação em uma thread | [Cifra — nova instância](CIPHER_INVESTIGATION.md#nova-instância-e-primeiro-escritor-aritmético-observado); `session2-cl-writer256-round-1/chain-capture.json`, `DONE.cl_preceding_write` | POP ainda sem prova antes/depois; sem origem do operando, cifra, inicialização ou identidade de pacote |
| G-01 | **OBSERVADO apenas na tabela** | IDs `8280 128`, `4754 -1`, `5395 -1`, `C392 -1` | Tabela do repositório, não captura de sessão | [Controle](GEPARD_CONTROL_PACKETS.md); `data/uaro_recvpackets.txt` | Tamanho tabelado não determina direção, função ou handshake |
| G-02 | **DOCUMENTADO apenas para 2016** | `SC_GEPARD_INIT`, `CS_GEPARD_INIT_ACK`, `CS_GEPARD_SYNC`, estados históricos | Fonte Gepard 2016, não equivalência do uaRO atual | [Controle](GEPARD_CONTROL_PACKETS.md); [investigação histórica](HISTORY/GEPARD_LEGACY.md) | Necessário revalidar IDs/algoritmo/direção no build atual |
| R-01 | **OBSERVADO no código/configuração** | `inject = true`, `inject-call = true`; separar merge stack do `SendPacket` fila; frames XKore | Revisão de código publicada em 2026-10-15 | `relay_capture.conf`; `relay/writeback.py`; [arquitetura](ARCHITECTURE.md) | Verificação estática não prova cliente/servidor funcionando agora |

## Notas de procedência e auditoria

- **Identidade de módulos do estudo:** `uaRO.exe` SHA-256 `f2f25a89917563237bb6faf60058cc536b7f42469af32fba556842f9f0cb9569`; `gepard.dll` SHA-256 `34188e6046eb831f31c0843744c084b56704a765d9e758043a1a1dad6046b08b`. Hashes citados em [CIPHER_INVESTIGATION §Build](CIPHER_INVESTIGATION.md); não provam identidade do estado criptográfico entre sessões.
- **Bases de endereços:** código anônimo uaRO referenciado em `0x401000`, base PE em `0x400000`, bases Gepard variáveis por relog. Offsets de sessão só podem ser interpretados junto às bases e hashes; não são assinatura universal. [MOVEMENT_035F_INVESTIGATION §Convenções](MOVEMENT_035F_INVESTIGATION.md).
- **Artefatos externos:** caminhos em `/tmp/` citados nos estudos apontam para material de execução original; este índice não afirma que continuam disponíveis. Para reproduzir, exigir autorização separada, revalidar build e limites e não copiar dados privados.
- **Independência epistemológica:** códigos `M-H1` e `C-H1` são linhas de pesquisa diferentes; não fundi-los. Ausência de hit não é ausência de evento fora da cobertura observada.

## Evidência incorporada após o pacote inicial

| ID | Status e origem | Recorte e resultado | Limite / refutação |
|---|---|---|---|
| M-07 | OBSERVADO no registro; commits `2645fad`, `87245d6`; `MOVEMENT_035F_PRECONDITIONS.md` §12 | Argumentos iguais; sem ponteiro nos 1024 B bidirecionais + 128 B do registro global, 8+ eventos; contexto de retorno difere | Refuta passagem de campo por argumento nesse callsite e restringe ligação por ponteiro; não exclui valor global/TLS/indireções |
| D-01 | OBSERVADO offline nesta consolidação; `DOCUMENTATION_AUDIT.md` | Manifesto/CRC conferidos; aplicador recusou HEAD divergente sem escrita; reconciliação manual | Não valida resultados vivos nem integridade atual de capturas externas |

Reprodução offline dos contratos: `python3 tests/test_movement_preconditions.py` e
`python3 tests/test_cipher_research.py`. Não reproduzem os experimentos históricos vivos.

## M-08 — ensaio do dispatcher, corrigido após integração

**Origem:** `524b0f0`, corrigido em `888764a`; [pré-condições §13](MOVEMENT_035F_PRECONDITIONS.md).
**OBSERVADO no registro:** buffer compatível no trap pré-store em `disp2`, sem confirmação
de escrita final, pacote completo, retorno normal, envio ou resposta. `disp5` sem HW BPs
é outra condição; não fornece confirmação daquele trap. **OBSERVADO por disassembly:**
`ret 0x34` = 52 bytes; chamada com 44 bytes. **HIPÓTESE então levantada:** desequilíbrio de 8 bytes como causa da falha;
explicação exclusiva superada pelo ensaio M-09 abaixo. Necessidade individual H2/H3 não demonstrada; reentrância segue aberta.
Nova coleta requer proposta própria. Capturas privadas não foram abertas nesta integração.

## P-01 — identificação de proteções recebida na main

**Origem:** `77954b2`, integrado em `origin/main@0a29193`;
[PROTECTION_FINGERPRINT_DIE.md](PROTECTION_FINGERPRINT_DIE.md).
**OBSERVADO e confirmado pelo responsável no DiE:** Themida/WinLicense 3.XX em `uaRO.exe`,
VMProtect em `gepard.dll`, arquivos da mesma build. **NÃO VERIFICADO:** quais funções estão
virtualizadas; não atribuir automaticamente uma região anônima a um protetor.

## M-09 — ABI de 13 dwords também trava

**Origem:** `7a64581`, [pré-condições §13.5](MOVEMENT_035F_PRECONDITIONS.md).
**OBSERVADO no registro:** replay com 13 dwords/52 bytes do frame natural, alterando x/y;
conteúdo de movimento no trap pré-store, sem retorno, exceção reportada ou envio/resposta
observados durante a chamada; cliente congelou. **REFUTADO no recorte:** discrepância de
8 bytes como explicação exclusiva da falha. **HIPÓTESE:** reentrância em `poll/select` ou
outra dependência de contexto/estado. Trap de execução não prova escrita concluída;
ausência de exceção reportada não exclui toda falha fora da cobertura. H2/H3 não isoladas.
A publicação não executou a sonda. Arquivo-fonte incluído no commit `7a64581`.

## M-10 — dependência de fase (rodadas 04/05), âncora `read` do wineserver

**Origem:** HANDOFFs MOVER-20261015-04 e -05 (`research/movement_035f/HANDOFF.md`);
[pré-condições §13.9](MOVEMENT_035F_PRECONDITIONS.md). **Correção associada (§13.8):** o `035F` é
cifrado e o `store_035f` em `gepard+0x18eff2` é o byte-store do scrambler
(`relay_capture.conf:99-111`); leituras de `035F` como "texto claro" estão REFUTADAS.
**OBSERVADO:** cliente Wine, main thread drena o wineserver por `read`/`writev` (poll quase ausente
na main); âncora corrigida para `read` onLeave. Rodada 04 (delay 700 ms) **retornou** e o scrambler
cifrou o corpo injetado, mas o cliente **congelou após o retorno**, sem `sendmsg`/`recv_0087`.
Rodada 05 (delay 2 s) **abortou durante a chamada** (SIGABRT, `pc=vdso`), também após cifrar o corpo.
Dependência de fase/contexto = OBSERVADA; manifestações distintas (freeze × abort). **HIPÓTESE
LÍDER (não provada):** reentrância Wine. **Artefatos privados (caminhos, não conteúdo; não
versionados):** rodada 04 `/tmp/claude-035f-20261015-160152-read-anchor/` (trial.json + manifesto
de 3 sondas); rodada 05 diretório `…-resume04/` na mesma convenção `/tmp/claude-035f-*`.
**Limite:** disparo no `onLeave` de um `read` é contexto não-natural; mecanismo do crash não
demonstrado; `sendmsg` lado-UNIX da fronteira Wine não observável por hook de export libc.

## M-11 — rodada 06b: origem autônoma ponta-a-ponta (MARCO, cliente vivo)

**Origem:** HANDOFF MOVER-20261015-06 (`research/movement_035f/HANDOFF.md`);
[pré-condições §13.10](MOVEMENT_035F_PRECONDITIONS.md). Sonda `dispatcher_trial_pesite.py`
(`--fire-site 0x4dcba0 --construct-frame --dest-x 273 --dest-y 313 --delay-ms 700`). PID 3338296,
build MATCH por hash. **OBSERVADO (uma única vez):** dispatcher 0x11 disparado de um sítio de
main-loop do `uaRO.exe` (HW exec BP `0x4dcba0`, base `0x400000`), fora do contexto do `read` do
wineserver → `emit_call` dest `[273,313]` → `sendmsg` fd195 5 B during_call → `emit_return`
retval=215959 (sem exceção) → `recv_0087` src `[273,314]` dst `[273,313]` (= destino injetado) →
cliente state S, vivo/estável. **4 critérios:** retorno/envio/resposta dst=destino/responsivo = SIM
→ PASSOU. **Diagnóstico da 06 (não disparou):** bug de guard (`capFrame` null de propósito em
`--construct-frame`); corrigido — não era slot/threading de HW BP. **Artefato privado (caminho, não
conteúdo; não versionado):** `/tmp/claude-035f-20261015-170143-round06b/trial.json`.
**Limite:** disparo via callback de HW-BP é contexto não-natural; sustenta que o contexto
read/wineserver causava os crashes 04/05, **não** "reentrância resolvida em geral". Os 4 HW BP foram
desarmados em `doFire`, então o `store_035f` do scrambler **não** foi observado during_call;
origem+cifra+envio provados **funcionalmente** por `sendmsg` 5 B + `recv_0087` dst=injetado.
**Não reproduzida**; comparação com a via de relay (merge pré-XOR em `gepard+0x18eff2`) pendente.

## M-12 — rodada 09: PoC do relay, `035F` do OpenKore → dispatcher nativo (OBSERVADO live, cliente vivo)

**Origem:** sessão OrquestradorCLAUDE, 2026-10-16; plano
`/home/bazzite/.claude/plans/abundant-frolicking-aho.md`. Integração da primitiva de M-11/§13.10 ao
relay/agent de produção, dirigida pelo OpenKore. **Build MATCH por hash:** `uaRO.exe` `f2f2…9569`,
`gepard.dll` base `0x76920000`. PID cliente 3520569 porta 27053 (Wine); OpenKore XKore 1 porta 2350
em container podman. Servidor **próprio do responsável** (escopo autorizado). **Mudanças em working
tree, não commitadas** no registro.
**OBSERVADO (uma única vez, live):** `035F` do consumidor (XKore `S`) decodificado
(`relay/packets.py:119` `unpack_move`), roteado em `relay/writeback.py:243` para o dispatcher nativo
`0xd473b0` (fire-site `0x4dcba0`, `agent/relay_hook_linux.js:647-752` `MD_RECIPES['walk-035f']`), com
o `035F` original **dropado** (`:249`, nada reenviado) → cliente monta/cifra o próprio `035F` →
`recv_0087 dst = destino pedido` → **cliente VIVO**. Os 4 critérios de M-11 = SIM.
**Orçamento de DR (4/4):** DR0 scramble · DR1 SendPacket · DR2 captura passiva do `this` · DR3
fire-site. `send-watch` OFF obrigatório. **Gotcha corrigido:** `move_dispatch` soma ao `inject-call`
(`relay/writeback.py:101-107`); eram exclusivos no `_arm` original → sem `--inject-call` o relay
dropava todo pacote não-`035F` e o OpenKore travava em "Aguardando".
**Invocação (rodada manualmente pelo responsável; classificador de auto-mode bloqueia o assistente):**
`./run.sh --inject --inject-call --move-dispatch --no-send-watch --out <ARQUIVO>`.
**Verificações offline:** `bash scripts/test-offline.sh` ALL PASS (11 scripts); `node --check
agent/relay_hook_linux.js` PASS; `python3 scripts/validate-research.py` PASS; `py_compile` dos `.py`
alterados OK. **Limites:** OBSERVADO uma vez; não reproduzido em várias sessões; `this` recapturado a
cada sessão (relogin invalida PID/base/heap); a cifra **não** é compreendida (o relay só decide o
destino; geração de keystream anterior ao XOR segue DESCONHECIDA, §13.8). Comparação de custo/robustez
com a via de relay (merge pré-XOR em `gepard+0x18eff2`) pendente. [Pré-condições §13.11](MOVEMENT_035F_PRECONDITIONS.md).

## C-08 — integração CIFRA-20261016-POP-03

**Origem:** [HANDOFF CIFRA](../research/cipher/HANDOFF.md), POP-03;
`/tmp/ro-cipher-20261016T061947Z/pop-click-1/capture/chain-capture.json`,
`DONE.cl_producer/cl_origin/cl_preceding_write`. **OBSERVADO NO ARTEFATO:** cópia
POP antes/depois, ESP+4, EDX estável e associação até pós-store de CL na mesma
ocorrência; recálculo local `POP_COPY_CONFIRMED`, `linked_to_cl_load=true`.
15 traps/uma escrita/13 pontos, 43 ms totais/12 ms sequência. Não é uma coleta
independente; nenhuma captura privada foi publicada. `SCRIPT_ERROR` posterior ao
DONE registrado e perguntado ao autor; contadores limpos não significam ausência
global de erros. Limpeza própria em `stimulus-summary.json` (dois flags verdadeiros),
sem prova de saúde global. [Integração completa](CIPHER_INVESTIGATION.md#integração-documental--cifra-20261016-pop-03).
C-07 conserva a etapa de candidato; C-08 demonstra a cópia apenas na nova ocorrência.
Origem anterior, cifra/estado/pacote permanecem desconhecidos.

## M-13 — MOVER-20261016-08: reprodução da sonda 06b

**Fontes:** [HANDOFF MOVER](../research/movement_035f/HANDOFF.md), IDs06/08;
`/tmp/claude-035f-20261015-170143-round06b/trial.json` e
`/tmp/claude-035f-20261016-014857-repro06b/trial.json`, `DONE.events` e flags
externos de limpeza. Conferidos dois pares chamada/retorno e envio 5/5 bytes,
resposta com destino correspondente; zero stores observados durante a chamada.
**OBSERVADO NO ARTEFATO**, não nova execução pelo documentador. UI responsiva é relato
MOVER; mecanismos da cifra e reentrância não demonstrados. Atualiza o estado “não
reproduzida” de M-11; não reproduz automaticamente a integração relay M-12.
[Limites e lições](RESEARCH_STATUS.md#m-13--reprodução-08-e-lições-do-contexto-de-disparo).

## Limites de procedência que mudam decisões

1. **MOVER-01/02, §13.7:** o autor confirmou que nenhum evento identifica o byte
   verificado ou a colisão; alerta/encerramento são relato. A indetectabilidade geral
   de Stalker/HW BP não foi demonstrada por esses recortes. Pergunta de evidência
   encaminhada ao pesquisador via orquestrador; não autoriza nova instrumentação.
2. **§13.8 / ORCH-20261016-01a:** os trechos citados documentam o caminho de merge e
   uma implementação; não medem operandos XOR do cliente ou gerador criptográfico.
   Solicitados artefato/eventos do PoC e evidência da operação, sem rebaixar o relato
   funcional nem promovê-lo a prova independente.
3. **WRITER-02 / POP-03:** erro tardio após DONE comunicado a CIFRA. Cópias e XOR
   local conferidos são preservados com cobertura; causa/impacto tardio e saúde global
   não preenchidos por inferência. Próxima entrega do autor poderá resolver a lacuna.

## C-09 — informação confirmada: valores enviados ao cliente no login

**Fonte:** declaração direta do responsável nesta rodada, 2026-10-16; no login
valores relacionados à cifra são enviados ao cliente. **Confirmação informada**, sem
captura/reprodução independente pelo documentador. Não identifica automaticamente
seed, chave completa, pacote, estado ou derivação. [Registro e limites](CIPHER_INVESTIGATION.md#valores-de-cifra-recebidos-no-login--confirmação-do-responsável).

## C-10 — CIFRA STACK-04 … SLICE-12 (linhagem por transportes)

**Fonte:** [HANDOFF CIFRA](../research/cipher/HANDOFF.md), IDs STACK-04 a SLICE-12; raiz privada
`/tmp/ro-cipher-resume-20261016/` (`prefix-manual-1`, `earlier-pop-manual-256`,
`earlier-prefix-sixth-manual-1`, `repeat-prefix-manual-1`, `lineage-passive-and-1`,
`upstream-eax-manual-1`, `session2-upstream-prefix-manual-1`, `session4-slice-late4-1`).
**OBSERVADO por ocorrência:** trocas PUSH/POP `+0x1C70D6`, `+0x13A194..A`, `+0x256883..9`;
igualdade do byte através das escritas cobertas até CL. **HIPÓTESE:** plano até `EBP+0x09`.
SLICE-11 inválida (exclusividade perdida). Relato do autor, não reexecutado pelo documentador.
[Integração](CIPHER_INVESTIGATION.md#integração-documental--cifra-stack-04--slice-12).

## A-01 — ACT-20261016-01: dispatcher × ataque/perícia

**Fonte:** `research/action_0437_0438/STATE.md`, `HANDOFF.md`; artefatos privados
`/tmp/claude-act-20261016-031147-sendpkt/observe.json`,
`/tmp/claude-act-20261016-110249-soulstrike2/inject.json`. **OBSERVADO:** codes `0x11/0x1f/0x28/0x2a/0x0a`
→ `035F/0437/0437/0438/(0368)`; cadeia de cast `0x29→0x5a→0x2a`; caller imediato `gepard+0xb2c251`.
**OBSERVADO (injeção):** replay da cadeia pelo fire-site `0x4dcba0` → `0x2a`=0, sem egress, crash
deferido. **REFUTADO:** `0368` pré-select como bloqueio. **RETIRADO:** cadeias de caller por
Backtracer/EBP-walk. [Controle](GEPARD_CONTROL_PACKETS.md#mapa-dispatcher--pacote-de-ação-act-20261016-01).
Supera a leitura da rodada 09b citada em M-12.

## A-02/A-03 — fechamento de movimento e ações (2026-10-17)

**CONFIRMADO PELO RESPONSÁVEL:** `0x035F` (movimento), `0x0437` (ataque automático), `0x0438` (skill automática em alvo) e `0x0AF4` (skill automática no chão) funcionam no ambiente pesquisado. Trilhas MOVER e ACT encerradas; cifra permanece a única pesquisa aberta. Registro novo por declaração do responsável, **não por coleta repetida nesta auditoria**.

**OBSERVADO NO CÓDIGO:** `agent/relay_hook_linux.js:481-534` demonstra `_fix0`. `bodyp.writeByteArray(body)` não bastava no primeiro byte quando `bl` já tinha o valor derivado do corpo original: o store `mov [ecx],bl` o sobregravava. No hit seguinte, `c0 ^ orig0 ^ our0` restaura a contribuição do consumidor. Comentário do agente relaciona erro anterior a GID de ataque e nível de skill. Base `main@0bddf0d77a5f81dc92c6fa5f5d6d45f1aa237d95`.

**REFUTADO/SUPERADO como causa do bloqueio automático:** seleção/lock de alvo e diagnóstico de alcance/estado de movimento em ACT-03. **REFUTADO como correção suficiente:** `0368` pré-select, fila FIFO e disparo isolado da perícia pelo fire-site de movimento. Esses últimos continuam resultados negativos válidos **das vias testadas**, não falha das funções finais.

**Fontes:** [estudo de ações](ACTION_0437_0438_INVESTIGATION.md), `research/action_0437_0438/HANDOFF.md` ACT-01/02/03, `research/action_0437_0438/MERGE_SYNTH_STATE.md` (histórico), `research/movement_035f/HANDOFF.md` MOVER-06b/08, [Pré-condições `13](MOVEMENT_035F_PRECONDITIONS.md). **Limite:** sem ensaio live pós-fix pelo documentador; não comprova algoritmo/estado criptográfico nem generaliza a builds distintos.
<!-- END ORIGINAL docs/RESEARCH_EVIDENCE_INDEX.md -->

<a id="source-docs-documentation-audit-md"></a>

## Fonte original: `docs/DOCUMENTATION_AUDIT.md`

Commit-base: `45483aaec7ee8546b9e81f5f1e569b83aa8dd911` · blob: `e43c0e1ec601030df304e956c6a8ce505dab0c55` · caracteres: 30754.

<!-- BEGIN ORIGINAL docs/DOCUMENTATION_AUDIT.md -->
# Auditoria e mapa de migração documental

Revisão local: **2026-10-15**, `main@87245d6491e6e27534ab6ada0b4d2cfe7225e43d`.
Escopo: consolidação documental e validação offline. Nenhum código funcional,
configuração, dado, fixture ou ferramenta de pesquisa foi alterado.

## 1. Preflight e arquivos protegidos

- `AGENTS.md` e `docs/AGENTS.md` lidos antes de editar; especificação recebida em
  `Texto_20colado.txt` e instruções do pacote consultadas.
- `git status --short`: somente dois arquivos não rastreados preexistentes,
  `docs/AGENTS.md` e `research/movement_035f/dispatcher_trial.py`; nenhum arquivo rastreado
  alterado. Branch `main`; HEAD acima. Nenhum checkout/reset/stash executado.
- ZIP `RO-Client-Relay-documentation-20261015.zip`: CRC íntegro; os dez arquivos listados
  no `MANIFEST.json` conferidos por tamanho e SHA-256. Extração isolada em `/tmp`.
- `validate_overlay.py`: PASS, seis documentos propostos. O pacote é ponto de partida,
  não fonte que prevalece sobre o checkout.
- Simulação `tools/apply_documentation.py <checkout>`: **recusa esperada**, HEAD diferente
  de `bdc2a07d982bdd393a22a0828a28bd0511145797`; nenhum arquivo escrito pelo aplicador.
  Não houve bypass do guard. Documentos novos foram reconciliados manualmente.
- `git diff bdc2a07..HEAD --stat`: dois commits posteriores, três arquivos rastreados
  envolvidos: pré-condições (+172 linhas), observador e teste. Dados recentes foram
  incorporados ao panorama sem sobrescrever o estudo especializado.

| Arquivo preexistente protegido | SHA-256 inicial / observação final |
|---|---|
| `docs/AGENTS.md` | `4d6dff77f05a728d2d6101a9b50df818a6d339ad95086525a6d641d5e196b843` |
| `research/movement_035f/dispatcher_trial.py` | Inicial `4c3b507cd0bbccdefd72d1dd08ab3e6d380a9a819368b521e765e1f0d72a5af6`; intermediário observado `64b04edad9a377256b2b229876341fa0f66ad7bdad01d3deb90c109a95ac025b` — alteração concorrente, não editada/restaurada nesta tarefa |

O arquivo não rastreado `dispatcher_trial.py` mudou durante a execução (mtime local
13:49:08); a origem da alteração não foi determinada. Seu hash voltou a mudar na última conferência, confirmando atividade concorrente. Sua integridade final não pode ser
declarada igual à inicial. Não foi sobrescrito nem incluído no escopo desta consolidação.

Recursos externos/ignorados, logs, snapshots e capturas privadas não foram abertos,
editados ou migrados. Não se afirma auditoria de conteúdo privado indisponível.

## 2. Estrutura final e mapa de migração

| Origem | Destino | Conteúdo / justificativa |
|---|---|---|
| `README.md` | [README da raiz](../README.md), [OPERATIONS.md](OPERATIONS.md), [ARCHITECTURE.md](ARCHITECTURE.md) | Entrada breve; requisitos, setup, faixa Gadget, configuração OpenKore, stdin, INI, precedência e testes nos manuais; módulos e fluxos na arquitetura |
| `ARCHITECTURE.md` (410 linhas) | [HISTORY/ARCHITECTURE_LEGACY.md](HISTORY/ARCHITECTURE_LEGACY.md) | Corpo completo, §§1–13, figuras, tabelas, ABI, endereços, sondas, experiências e limites; cabeçalho qualifica alegações superadas. Raiz virou redirecionamento |
| `gepard_investigation.md` (222 linhas) | [HISTORY/GEPARD_LEGACY.md](HISTORY/GEPARD_LEGACY.md) | Corpo completo com sanitização explícita de conta/endpoints, sem corte de assembly/constantes/candidatos. Raiz virou redirecionamento |
| `research/cipher/README.md` (166 linhas) | [CIPHER_TOOLS.md](CIPHER_TOOLS.md) | Manual integral: formatos, limites, privacidade, CLI, mecanismos de coleta, limpeza, doubles e interpretação. README local virou entrada curta |
| Quatro estudos especializados | Mesmos caminhos em `docs/` | Movimento, pré-condições, cifra e controle permanecem independentes; referências atualizadas, sem condensar experimentos |
| `docs/RESEARCH_DECISIONS.md` | Mesmo caminho | Decisões confirmadas preservadas; nota diferencia observação inicial e resultado posterior |
| `docs/CODEX_WORKFLOW.md` | Mesmo caminho | Instruções operacionais e medição preservadas, sem mudar ferramentas/modelos |
| Pacote inicial (seis documentos) | Índice, estado, evidências, arquitetura, operação, esta auditoria | Base reconciliada com HEAD; texto provisório de migração pendente substituído por resultado local |
| Inventário recursivo e código/testes | [§10 desta auditoria](#10-inventário-de-fontes-da-consolidação-migrado-de-documentation_sourcesmd) | Fontes Markdown e hashes de origem, famílias de implementação, testes, histórico Git e limites da inspeção. **Migrado de `DOCUMENTATION_SOURCES.md` (2026-10-16)** |
| `DOCUMENTATION_SOURCES.md` | §10 deste documento | Inventário de fontes fundido nesta auditoria para reduzir dispersão; o caminho antigo vira redirecionamento curto |
| `AGENTS.md` | Raiz | Somente referências documentais atualizadas; decisões/restrições intactas |
| `.agents/`, `.codex/`, `.claude/` | Mesmos caminhos | Configuração, skills, agentes e espelhos preservados |

Não há segunda cópia integral dos documentos migrados na raiz. `HISTORY/` guarda somente
as duas fontes mistas cuja informação técnica exclusiva precisa permanecer contextualizada.
A arquitetura atual usa links para o histórico, não reproduz todos os seus mapas.

## 3. Auditoria de preservação técnica

Comparação automatizada entre `git show HEAD:<origem>` e o corpo migrado:

- Arquitetura: **410/410 linhas preservadas**, removidos somente espaços finais;
  cabeçalho histórico adicionado. Mesmas sequências de caracteres técnicos e ordem.
- Gepard: **222/222 linhas preservadas** após substituir exclusivamente endpoints,
  usuário e as duas representações do identificador de conta por placeholders.
  Sanitização não altera offsets, portas, IDs de pacote, constantes ou assembly.
- Manual da cifra: **166/166 linhas preservadas**, apenas título atualizado e seção
  de localização adicionada. Comandos continuam relativos à raiz.
- Quatro estudos: nenhum experimento ou tabela removido. Pré-condições recebeu nota
  de precedência e correção do rodapé que ainda dizia 256 B após extensões 1024 B/128 B.
  O trecho inicial continua indicando a cobertura original, sem reescrever o resultado antigo.
- `README.md` antigo: explicações de pipeline/módulos já constam da arquitetura;
  requisitos, comandos e opções estão em operações. Alegação geral sobre ptrace foi
  delimitada ao ambiente histórico. Referências inexistentes §§22–23 foram corrigidas.

Elementos conferidos no histórico preservado incluem:

| Família | Elementos preservados / destino |
|---|---|
| Movimento e memória | Bases `0x400000/0x401000`, `+0x816640`, `+0x875400`, `+0x9463b0`, `+0x18eff2`, pilha/ring, DR0/DR1, thiscall → arquitetura histórica §§2,6,8–10 |
| Contrato natural/nativo | `0xd473b0`, `0xd477bc/0xd477bf`, `+0x10A90`, cinco argumentos, slots 64 bits, `+0x70/+0x500/+0x50c/+0x510/+0x520/+0x534/+0x538`, gate `0x15E` → estudos originais |
| Cifra histórica | `gepard_crypt_unit`, pseudocódigo, constantes, ramp/posições, unidades de sessão e resultados negativos → histórico Gepard §§3–4, qualificado como hipótese para uaRO |
| Cifra recente | `+0x1C752B`, `+0x1B223C/+0x1B2252/+0x1B2255`, `+0x18EFEC..+0x18EFF2`, `ESI/CL/EAX/AL/ECX/EBX/EBP/BL`, `EBP+0xA5`, 26 rodadas e limites → cifra original |
| Controle | `0x8280/0x8285/0x4754/0x5395/0xC392`, tamanhos, nomes 2016 e lacunas → controle original e histórico Gepard |
| Perícia não verificada | Diagrama final, `0x14b`, clusters `+0x930xxx..+0x932xxx`, RVAs e candidatos → histórico Gepard final |
| Negativos | Fila inadequada para `035F`, merge persistente, wrapper não discriminatório, nativo sem store/envio, timeouts de cifra, falhas de instrumentação → históricos e estudos mantidos |

Essas comparações comprovam preservação textual sanitizada; não autenticam novamente as
capturas históricas nem tornam seus diagnósticos fatos do build atual.

## 4. Matriz de contradições e resolução

| Assunto | Afirmação anterior | Evidência / formulação canônica |
|---|---|---|
| Observabilidade da chamada nativa | Sem store/ACK não se podia concluir nada sobre envio | Correto para a sonda inicial; etapa 6.4 usa canais independentes e refuta H1 naquele recorte, sem ausência absoluta de tráfego |
| H2/H3 no pacote | H2 prioritária, H3 viável | `2645fad`/`87245d6`, pré-condições §12: sem argumento de estado e sem ponteiro nas regiões examinadas; H2 por valor global continua aberta; H3 relativamente reforçada, não provada |
| Cobertura §12 | Rodapé dizia apenas 256 B unidirecionais | O próprio corpo relata extensões de 1024 B bidirecionais e 128 B do registro global; rodapé agora distingue fases. TLS/indireções/fora do recorte não excluídos |
| Gate e preparação | Campos escritos antes do receptor seriam sua pré-condição demonstrada | Produtor não demonstra consumidor; gates decidem chamar, não demonstram geração de pacote após chamada |
| `0x8280` | Heartbeat igual ao `0x8285` de 2016 | Apenas tamanho tabelado é observável aqui; papel, direção, handshake e equivalência permanecem hipóteses |
| Cifra e estado | Ramp/word-based/posições e XOR final como modelo resolvido | Cargas/cópias/store comprovados em recortes; falta geração de CL, estado consumido, inicialização e vetor P/C completo. `C_INSUFFICIENT` |
| Falha de perícia / flag | Causa exclusivamente sincronia; flag de conta como diagnóstico | Causas não demonstradas; parser, pré-condições, estado e conectividade continuam alternativas. Histórico explicitamente qualificado |
| Dreno SendPacket | Apenas recv/send, latência ~700 ms | Agente atual também hooka `poll/ppoll/select/pselect/pselect6` (`agent/relay_hook_linux.js:732`); latência atual não medida |
| Identidade XKore | Frame preservaria identificador de conexão | Pipeline usa identidade interna (`relay/protocol.py:124`), frame contém tipo+tamanho+payload (`relay/relay.py:14`) |
| Semântica do writeback | Apenas chamar SendPacket e trocar corpo | `relay/writeback.py:224` também seleciona alvo `0368`, deduplica e ignora IDs; agente descarta casts no intervalo (`:617`) |
| Testes históricos PASS vs NOT RUN | Estudos registram resultados diferentes | São execuções/etapas diferentes, com falha ambiental de socket em uma delas. Não apagar registros nem somar como única rodada; validação desta consolidação abaixo |
| §§22–23 e HANDOFF | Referências antigas pareciam destinos existentes | `05fb8d3` reescreveu histórico e `f98e466` removeu handoff. Registrar proveniência e usar §§3–4 atuais; não restaurar material removido com dados privados |
| Recursos Gepard | Arquitetura antiga dizia fonte versionada | `relay/resources/` é externo/ignorado conforme regras atuais; arquivo histórico mantém frase original sob ressalva |

## 5. Verificações desta consolidação

| Comando / verificação | Resultado | Escopo |
|---|---|---|
| ZIP CRC + tamanho/SHA-256 de `MANIFEST.json` | PASS (10 arquivos) | Integridade do pacote recebido |
| `python3 <pacote>/tools/validate_overlay.py` | PASS | Estrutura dos seis documentos iniciais |
| `python3 <pacote>/tools/apply_documentation.py <checkout>` | RECUSA ESPERADA | HEAD divergente; simulação sem escrita |
| Comparação integral das três fontes migradas | PASS | Corpos, ordem, sanitização e linhas preservadas |
| Hashes dos arquivos preexistentes | PARCIAL / alteração concorrente | `docs/AGENTS.md` igual; `dispatcher_trial.py` mudou externamente e foi deixado intacto |
| `python3 scripts/validate-research.py` | PASS | Marcadores/tamanhos, não comprova hipóteses |
| `python3 scripts/validate-codex.py` | PASS | Estrutura/configuração/espelhos, não runtime |
| `bash scripts/test-offline.sh` no sandbox | FAIL ambiental | PermissionError ao criar socket local em integração; testes anteriores passaram |
| `bash scripts/test-offline.sh` fora do sandbox, autorizado | PASS (10 scripts) | Somente suíte offline e sockets locais; saída em `/tmp/ro-doc-offline-tests.txt` |
| `python3 <pacote>/tools/validate_checkout_links.py <checkout>` | PASS | Caminhos relativos existentes; falso positivo da notação de assembly resolvido com comentário explícito para y |
| `git diff --check` | PASS | Espaços do diff rastreado; novos documentos também conferidos |
| Frida/CEServer/cliente/servidores | NOT RUN | Fora do escopo autorizado desta tarefa |
| Commit/push/PR/reescrita | NENHUM | Não autorizado |

## 6. Limites, delegação e próxima decisão

A centralização e a preservação das fontes documentais presentes estão implementadas.
O inventário da [§10 desta auditoria](#10-inventário-de-fontes-da-consolidação-migrado-de-documentation_sourcesmd) registra os documentos
versionados, fontes de contratos e cronologia examinada. A auditoria de implementação foi
estática e dirigida a afirmações documentais, não uma revisão linha a linha de todo o código
ou de cada versão desde a criação do repositório. Fontes privadas/externas indisponíveis
não foram autenticadas nem copiadas. O relatório DiE de outra branch não foi incorporado.

Dois explorers fizeram leituras independentes de arquitetura/operação e pesquisa recente;
somente o coordenador editou arquivos. Foram úteis para localizar a nuance do frame e a
atualização H2/H3; não houve medição comparativa de tokens/tempo/correção suficiente para
alegar economia. Revisões retornaram referências, sem logs completos. Um verifier final apontou PIDs,
FDs, loopback e caminhos históricos como possíveis metadados sensíveis. São referências
preexistentes necessárias à distinção de sessões, sem dados de conta ou conteúdo bruto;
foram mantidas com nota explícita de procedência histórica. Não indicam cliente vivo agora.
A recomendação de removê-las indiscriminadamente não foi adotada por conflitar com a
preservação de proveniência solicitada. A revisão não identificou credenciais nos trechos
examinados e não repetiu a suíte; os resultados acima foram executados pelo coordenador.

Continuam abertas **questões de pesquisa**, não migrações de conteúdo desta árvore:
consumo de valor global vs. contexto no movimento; produtor de CL e cifra completa;
IDs/transições de sessão e futura integração OpenKore. Novos experimentos vivos exigem
proposta/autorização própria. Próxima decisão humana: revisar o diff documental e decidir
se deseja um commit local; nenhum commit é necessário para usar os documentos no checkout.

## 7. Correções da revisão e sincronização solicitada

**HEAD da revisão:** `524b0f05fa61872e140f98ace9e503d12356641e`, posterior à base da
consolidação inicial acima. O commit concorrente incluiu `dispatcher_trial.py` e o
ensaio §13. O fato de ele estar rastreado agora não é alteração funcional desta revisão.

| Achado | Correção aplicada | Limite mantido |
|---|---|---|
| Panorama/arquitetura/índice ainda paravam em §12 | Incorporado M-08 com origem `524b0f0` e referência ao ensaio §13; índices e precedência atualizados | Store no destino pedido, mas sem retorno normal, transmissão ou resposta confirmados |
| §13 declarava H2/H3 necessárias e negava qualquer efeito de instrumentação | Necessidade individual reclassificada como não demonstrada; retorno/continuação e mecanismo do travamento permanecem hipóteses | Desarmar HW breakpoints exclui somente a explicação exclusivamente por esses breakpoints ativos |
| Throttle descrito como descarte ao exceder `castMs` | Corrigido para intervalo desde último cast **menor** que `castMs` | Descarte sem reenfileirar; comportamento do código, não regra criptográfica |

**Sincronização:** `git pull --ff-only --no-rebase` inicialmente bloqueado pelo sandbox
na escrita de `.git/FETCH_HEAD`; repetido fora do sandbox com autorização e concluído:
**Already up to date**. Branch `main` sincronizada com `origin/main`, sem rebase, descarte
de alterações ou mescla de branches de pesquisa. Alterações documentais locais preservadas.
Nenhum commit ou push foi criado por esta tarefa.

Os resultados da seção 5 pertencem à primeira consolidação. As verificações da correção
são registradas abaixo após execução; nenhum experimento vivo foi reexecutado.

| Verificação após as correções | Resultado |
|---|---|
| `python3 scripts/validate-research.py` | PASS — marcadores/tamanhos |
| `python3 scripts/validate-codex.py` | PASS — estrutura/espelhos |
| `python3 <pacote>/tools/validate_checkout_links.py <checkout>` | PASS — caminhos relativos |
| `git diff --check` + espaços dos novos documentos | PASS |
| `bash scripts/test-offline.sh` fora do sandbox, autorizado | PASS — 10 scripts; `/tmp/ro-doc-offline-tests.txt` |
| Inspeção das correções, tokens técnicos e ausência de diff funcional | PASS — três achados resolvidos |
| `git rev-list --left-right --count HEAD...origin/main` | PASS — `0 0` após pull |
| Experimentos vivos | NOT RUN |

**Resultado da revisão:** aprovada documentalmente após corrigir os três achados, dentro
do escopo estático e offline descrito. As hipóteses de pesquisa não se tornam fatos pela
aprovação. Mudanças continuam locais, sem commit/push desta tarefa. Próxima decisão:
versionar a consolidação quando houver autorização explícita para commit.

## 8. Exclusão de branches e integração da main solicitadas pelo responsável

As seis branches remotas explicitamente dispensadas foram excluídas em uma operação
atômica com conferência dos SHAs (`--force-with-lease` por ref). A consulta à API do
GitHub confirmou que somente `main` permanece. Branches locais não foram excluídas.

Antes do pull, os 20 arquivos locais alterados foram copiados para
`/tmp/ro-before-branch-cleanup-yjjwo1g7/` e guardados no stash
`preserve-local-docs-before-requested-pull-20261015`. O backup e o stash foram mantidos.
O pull por merge preservou `888764a` e integrou `origin/main@0a29193`, criando o commit
local de merge `677e51e`. Nenhum commit local foi publicado na main.

A reaplicação da documentação gerou conflito apenas em `ARCHITECTURE.md`: o remoto
acrescentava o resultado DiE ao documento antigo; o local mantinha uma entrada para a
arquitetura centralizada. A resolução conserva a entrada na raiz e integra a adição
à **§12 de `docs/ARCHITECTURE.md`**, com link ao relatório completo. Não se restaurou a
antiga organização. As adições remotas em cifra, pré-condições e decisões foram mantidas.

O panorama/índice local também refletem a correção já feita em `888764a`: trap pré-store
não prova escrita concluída; ABI da chamada de 44 bytes difere de `ret 0x34` (52 bytes).
O relatório DiE agora existe nesta árvore; menções anteriores à sua indisponibilidade
nesta auditoria descrevem a fase anterior ao pull e ficam superadas por esta integração.
Nenhum cliente, Frida, CEServer ou experimento de servidor foi executado nesta tarefa.

## 9. Preparação da publicação autorizada

O responsável autorizou publicar todas as alterações no GitHub. Além da consolidação,
o conjunto inclui o script preexistente `research/movement_035f/dispatcher_trial13.py`,
que captura 13 dwords para ensaio nativo experimental. Publicação do código não autoriza
executá-lo: esta tarefa não fez coleta viva. O script usa verificações de instruções/objeto,
sem conferir automaticamente os hashes dos módulos; sua configuração depende da build
já identificada. Os resultados vivos permanecem no estudo especializado e não são validados
pela suíte offline.

Verificações antes da publicação: suíte offline completa **PASS (10 scripts)**, sintaxe
Python por AST/compile **PASS**, JavaScript embutido por `node --check` **PASS**, validadores
de pesquisa/Codex **PASS**, caminhos Markdown e `git diff --check` **PASS**. A inspeção
estática não identificou credenciais nem capturas cruas nos arquivos novos; offsets e
hashes de build foram mantidos como proveniência. Artefatos ignorados e backups em `/tmp`
ficam fora do commit. O stash de segurança continua preservado.

Durante a preparação, outra sessão concluiu e commitou `7a64581` (script ABI13 e §13.5).
O panorama e o índice incorporam esse resultado: a variante de 52 bytes também travou,
sem retorno/envio observado. A publicação preserva esse commit, sem reproduzir a coleta.
Removida apenas uma linha vazia redundante no EOF do histórico Gepard para atender
`git diff --cached --check`; nenhum dado técnico foi removido.

## 10. Inventário de fontes da consolidação (migrado de DOCUMENTATION_SOURCES.md)

> Migrado de `DOCUMENTATION_SOURCES.md` em 2026-10-16 (consolidação: inventário de fontes incorporado
> a esta auditoria). Revisão de origem: `87245d6491e6e27534ab6ada0b4d2cfe7225e43d`, branch `main`,
> 2026-10-15. Inventário de arquivos rastreados via `git ls-files`; hashes abaixo são do conteúdo
> **antes** da consolidação, obtido por `git show HEAD:caminho`. Não inventaria logs privados ou
> recursos ignorados. Não houve leitura de memória/processo nesta manutenção.

### 10.1 Markdown versionado de origem

| Fonte | Linhas | SHA-256 de origem |
|---|---:|---|
| `.agents/skills/repo-evidence/SKILL.md` | 8 | `b9b81b04e1c3be3b3e3aabe5773e582e0732350f361d922e432bb41dafb5ec36` |
| `.agents/skills/research-handoff/SKILL.md` | 9 | `8d93d4e253ba94a8947f4f478bd7e04516f1b68dc67f9ba78acfbbefac1518d3` |
| `.claude/agents/explorer.md` | 9 | `4db0f165f968322b2940619ecaaefbd09f4b0d83af4eca0250a2c09b557298c1` |
| `.claude/agents/implementer.md` | 11 | `f3d7c2691d32a0a4e62f9a667546adec1b0f049765c5229ef7d7651dff899de2` |
| `.claude/agents/verifier.md` | 10 | `b4fbb3b5e8f1265c14a4528fad0a14286b9915cda4d3c91c4181f0352c26a1fc` |
| `AGENTS.md` | 46 | `632ab023574a3217f4a45860a5a692e91404257e648674e0ef7b69247a9a2873` |
| `ARCHITECTURE.md` | 410 | `ff3a43643bfd975f273336d82839d9082211a3ceccfa65c9fee9cc24be554a17` |
| `README.md` | 144 | `c6712f8cc0fdf87c3ff9b117e29aad44202134c46c64c0b2763ee1e7f987f108` |
| `docs/CIPHER_INVESTIGATION.md` | 344 | `b83abbd7a6b2120466ed5574164f6287c01ff3650d7b17c13f79882653b65d9c` |
| `docs/CODEX_WORKFLOW.md` | 35 | `57db19f342c885884bfc82d8b8f49c49757db6cf6b8286509c9e55e5dd6e8262` |
| `docs/GEPARD_CONTROL_PACKETS.md` | 41 | `f228ebc081e0e0ccd5329f5a0ef32a53219d19ea284d557b639a0b086d0e5005` |
| `docs/MOVEMENT_035F_INVESTIGATION.md` | 417 | `de35ed841b97b2fca4ca46d37a6f86bad8cfcbd1a4cc1ac273bf8ce904069926` |
| `docs/MOVEMENT_035F_PRECONDITIONS.md` | 413 | `f3b36fe8ea758dd44aa89d8be2b5b93d8748b48a720ce25ab9d551c61e24b9c6` |
| `docs/RESEARCH_DECISIONS.md` | 62 | `dc29c59cee12cf0be5a65f758078a30cb900c86b13cc875443dc04873ee9e327` |
| `gepard_investigation.md` | 222 | `1b03bb9734dddd5e635a37aa2fd7e13bbf3c8580564d2ebd15416daf93b3073a` |
| `research/cipher/README.md` | 166 | `f8e83a637c3c8fd2d467b5cd36d5ea91ba5fcc1f1da042cf73c6805cb7f3d7b1` |

Além do inventário versionado, `docs/AGENTS.md` (instruções desta tarefa) e
`research/movement_035f/dispatcher_trial.py` já estavam não rastreados. Não foram editados nesta tarefa; o segundo teve alteração concorrente detectada (ver auditoria);
a presença da ferramenta não demonstra execução nem validação em cliente.

### 10.2 Documentação embutida e destinos por família

| Fontes / cobertura de leitura | Informação / destino |
|---|---|
| `relay_capture_linux.py`, `relay/{protocol,runtime,wire_feed,relay,actors,packets,safety,writeback,cli,config}.py` | Contratos, fila, identidade, framing, sanitização, defaults e escrita → [arquitetura](ARCHITECTURE.md) e [operação](OPERATIONS.md) |
| `agent/relay_hook_linux.js` (hooks, sendcall, dreno e throttle) | DR0/DR1, thread, sondas e chamadas periódicas → arquitetura §§5,6,11; comentários criptográficos não viram prova |
| `relay/{agent,memory,sendwatch,research,console}.py` | Responsabilidades por módulo → arquitetura §2; leitura estática dirigida por símbolos, sem alegação de revisão exaustiva de cada linha |
| `setup.sh`, `run.sh`, `requirements.txt`, `relay_capture.conf` | Venv, Gadget, versão, stdin, configuração e defaults → operação |
| `research/cipher/{core,analyze,chain_audit,chain_capture,inspect_client}.py`, `chain_probe.js`, `chain_probe_test.js` | Contratos de análise/coleta e doubles → [manual integral](CIPHER_TOOLS.md), [cifra](CIPHER_INVESTIGATION.md) |
| `research/movement_035f/{analyze,observe_path,native_trial}.py`, commits `bdc2a07..87245d6` | Independência dos canais, campos e cobertura de ponteiros → [pré-condições](MOVEMENT_035F_PRECONDITIONS.md) §§6,10–12 |
| `tests/test_*.py`, `tests/_boot.py`, fixtures existentes | Contratos offline; cobertura por teste abaixo; fixtures não promovidas a vetores completos da cifra |
| `scripts/{test-offline.sh,validate-research.py,validate-codex.py}` | Critérios reais de PASS e limites → operação/auditoria |
| `data/uaro_recvpackets.txt` | Tamanhos, semântica não inferida → [controle](GEPARD_CONTROL_PACKETS.md) |
| `.agents/skills/*/SKILL.md`, `.codex/{config.toml,agents/*.toml}`, `.claude/agents/*.md`, symlinks `.claude/skills` | Instruções preservadas, validação de espelhos → [workflow](CODEX_WORKFLOW.md) |

O inventário distingue inspeção dos contratos de uma prova do comportamento em produção.
Não afirma auditoria exaustiva linha a linha do código funcional ou de toda revisão histórica.

### 10.3 Testes existentes e informação exclusiva de contrato

| Teste | Conhecimento verificável offline |
|---|---|
| `test_actors.py` | Cópias frescas/contextuais, descarte conservador, socket fechado e cadeia |
| `test_cipher_research.py` | Proveniência, perdas, isolamento, privacidade, formatos, doubles JS e limpeza; não cifra real |
| `test_config.py` | Defaults < INI < CLI, tipos inválidos e chaves desconhecidas |
| `test_integration.py` | Pipeline e escrita sobre sockets **locais**, requer permissão para criá-los |
| `test_movement_preconditions.py` | Canais independentes, ordenação por evento, limite do nativo e campos de linkage |
| `test_packets.py` | Framing, fragmentação, tamanho inválido e codificação de movimento |
| `test_relay.py` | Frames `S` cortados e reconstrução do retorno do consumidor |
| `test_safety.py` | Login/HTTP e sanitização |
| `test_sendwatch.py` | Recuperação conservadora das janelas de escrita |
| `test_writeback.py` | Merge/SendPacket, `0368`, dedup, skip, throttle encaminhado e descoberta idempotente |

### 10.4 Cronologia técnica conferida no Git

- `6a47d5c`: traço de cifra e modelo 2016; é origem histórica, não equivalência atual.
- `05fb8d3`: reescrita do histórico Gepard removeu narrativa antiga. As referências §§22–23
  sobreviveram em textos, mas as seções atuais equivalentes são §§3–4.
- `f98e466`: removeu `HANDOFF.md` e adicionou candidatos de perícia não confiáveis.
  Handoff anterior consultado: sínteses repetidas dos históricos; nomes de scripts externos
  `findunit.py`, `scanunit.py`, `difftrace.py`, `fitf.py` são pistas de método, não ferramentas
  disponíveis no checkout. Não se restauram dados de conta/rede daquele handoff.
- `0feb23a`/`b4724fc`: seleção de alvo, dedup/anti-flood, dreno periódico e paceamento;
  comentários históricos de drenagem exclusiva por tráfego estão superados pelo código.
- `3403a4c`/`5ea043f`: cadeia natural, ABI, controles e ensaios iniciais de movimento.
- `8006373`: ferramentas e continuação da cifra; dependências de bytes não resolvem F.
- `bdc2a07`: pré-condições e ensaio 6.4; base do ZIP recebido.
- `2645fad`, `87245d6`: auditoria produtor/consumidor e extensões de linkage; base da primeira consolidação.

Não houve fetch, merge, restauração de arquivos removidos ou exame de logs privados.
O relatório externo DiE citado nas pré-condições continua indisponível nesta árvore;
não há evidência local suficiente para incorporá-lo como descoberta.

### 10.5 Atualização após revisão do diff

A revisão subsequente usa `524b0f05fa61872e140f98ace9e503d12356641e` como HEAD.
Esse commit rastreou `research/movement_035f/dispatcher_trial.py` e acrescentou o ensaio
§13 às pré-condições. Os hashes da tabela inicial continuam descrevendo a origem em
`87245d6`, não o novo conteúdo. O panorama e o índice foram atualizados para o store
espontâneo sem retorno/envio confirmados; H2/H3 permanecem não isoladas.
`git pull --ff-only --no-rebase` concluiu com "Already up to date"; nenhuma branch de
pesquisa recém-descoberta foi mesclada nesta tarefa. O relatório DiE continua fora
da árvore de trabalho; disponibilidade de uma referência remota não valida seu conteúdo.

### 10.6 Integração posterior solicitada

O pull de `origin/main@0a29193` incorporou o relatório `PROTECTION_FINGERPRINT_DIE.md` e
suas referências; a integração local `677e51e` preserva também `888764a`. A informação DiE
que chegou na arquitetura antiga foi conciliada em `docs/ARCHITECTURE.md` §12. A nota
anterior de relatório fora da árvore refere-se ao momento anterior a esse pull.

### 10.7 Fonte experimental incluída por autorização de publicação

`research/movement_035f/dispatcher_trial13.py`: frame de 13 dwords, verificação do epílogo,
observadores de execução/transporte e registro incremental. A checagem antes de publicar
cobriu sintaxe Python/JS, não execução no cliente. Hashes dos módulos não são conferidos
automaticamente pelo script; parâmetros e endereços pertencem à build documentada.

## 11. Atualização documental de encerramento — 2026-10-17

**Base:** `main@0bddf0d77a5f81dc92c6fa5f5d6d45f1aa237d95`; atualização solicitada expressamente pelo responsável. Mudança somente documental; nenhum arquivo funcional em `relay/`, `agent/`, testes ou configuração alterado neste PR.

| Origem | Destino canônico | Ação e justificativa |
|---|---|---|
| Confirmação atual do responsável + `agent/relay_hook_linux.js:481-534` | [ACTION_0437_0438_INVESTIGATION](ACTION_0437_0438_INVESTIGATION.md) | Corrigir o diagnóstico: byte zero regravado pelo store, restaurado por `_fix0`; ações e movimento encerrados funcionalmente |
| `research/action_0437_0438/{STATE,HANDOFF,MERGE_SYNTH_STATE,HANDOFF_CODEX}.md` | [ACTION_0437_0438_INVESTIGATION](ACTION_0437_0438_INVESTIGATION.md) | Conservar evidências, ABI, cronologia e tentativas negativas; deixar claros limites temporais de ACT-01/02/03 |
| ``docs/MOVEMENT_035F_*`, handoffs MOVER | [MOVEMENT_035F_PRECONDITIONS](MOVEMENT_035F_PRECONDITIONS.md), [RESEARCH_STATUS](RESEARCH_STATUS.md) | Encerrar status funcional sem apagar hipóteses históricas |
| Prioridades/rotas desatualizadas em ``AGENTS.md` e `docs/{README,ARCHITECTURE,OPERATIONS,RESEARCH_DECISIONS,RESEARCH_EVIDENCE_INDEX,GEPARD_CONTROL_PACKETS}.md` | mesmos destinos + novo estudo | Atualizar índice, efeitos operacionais, classificação e prova estática; cifra como única pesquisa ativa |
| `docs/CIPHER_INVESTIGATION.md` | mesmo arquivo | Delimitar cifra como único aberto; `_fix0` não é geração criptográfica |

**Confiabilidade:** conclusão funcional **informada e confirmada pelo responsável**, correção do byte zero **verificada estaticamente** no agente do commit-base. Experimentos live pós-fix **não reexecutados pelo documentador**. Conteúdo de `research/` preservado; conclusões historicamente refutadas identificadas como tal. Não versionar credenciais, GIDs reais, IPs ou capturas brutas.
<!-- END ORIGINAL docs/DOCUMENTATION_AUDIT.md -->

<a id="source-docs-documentation-sources-md"></a>

## Fonte original: `docs/DOCUMENTATION_SOURCES.md`

Commit-base: `45483aaec7ee8546b9e81f5f1e569b83aa8dd911` · blob: `3ca5c0a474fc17f363e2f9fbfe6d1d6fc865b723` · caracteres: 666.

<!-- BEGIN ORIGINAL docs/DOCUMENTATION_SOURCES.md -->
# Inventário de fontes da consolidação — movido

> **Consolidado em 2026-10-16.** Este inventário foi fundido na auditoria documental para reduzir a
> dispersão de documentos. O conteúdo integral (Markdown versionado + hashes de origem, documentação
> embutida por família, testes, cronologia Git e fonte experimental) está agora em:
>
> **[DOCUMENTATION_AUDIT.md §10 — Inventário de fontes da consolidação](DOCUMENTATION_AUDIT.md#10-inventário-de-fontes-da-consolidação-migrado-de-documentation_sourcesmd)**

Nenhum dado foi descartado na migração; ver o mapa de migração em
[DOCUMENTATION_AUDIT.md §2](DOCUMENTATION_AUDIT.md#2-estrutura-final-e-mapa-de-migração).
<!-- END ORIGINAL docs/DOCUMENTATION_SOURCES.md -->
