# RO-Client-Relay — estado atual do conhecimento técnico

> **Revisão documental local:** 2026-10-15, `main@524b0f05fa61872e140f98ace9e503d12356641e`. Pacote inicial baseado em `bdc2a07`, reconciliado com `2645fad`, `87245d6` e o ensaio posterior de `524b0f0`. Alterações preexistentes foram preservadas; artefatos privados/ignorados não foram abertos. **Este arquivo é o mapa; os estudos especializados contêm a evidência integral.**

## A. Estado geral — revisão 2026-10-15

**Decisão confirmada:** objetivo final de usar o **OpenKore externo em xKore 0, sem cliente**. A etapa intermediária emprega o xKore 1 já presente no OpenKore, o relay Python/Frida e o cliente uaRO para preparar/cifrar tráfego. Uma implementação independente do protocolo, quando justificada por evidências, pertence ao projeto OpenKore como integração/plugin, e **não** a um backend xKore novo neste repositório. Fonte: [RESEARCH_DECISIONS](RESEARCH_DECISIONS.md), seção *Decisões confirmadas*; [AGENTS.md](../AGENTS.md).

**OBSERVADO na implementação/documentação de operação:** o agente Frida inspeciona `recvmsg`/`sendmsg` sob Wine/Proton; o driver ordena quadros, tenta substituir corpos recebidos somente com cópias decifradas verificadas pelo cliente e oferece tráfego ao consumidor XKore 1 (`R` e `S`). Os caminhos de escrita são distintos: merge reativo no store do `0x035F` e `SendPacket` para ações da fila (`0x0437`/`0x0438`), usando o próprio cliente. `relay_capture.conf` fixa intencionalmente `inject = true` e `inject-call = true`, embora defaults internos do CLI sejam outros. Fontes: [arquitetura](ARCHITECTURE.md), [operações](OPERATIONS.md), `relay/writeback.py`, `relay/wire_feed.py`, `relay/relay.py`, `agent/relay_hook_linux.js`.

**Limitações:** o merge do movimento é reativo, não inicia por conta própria um passo natural; chamar `0x035F` pela rotina da fila foi associado à dessincronização de cifra na sessão documentada de 2026-10-13. A cifra atual não foi reconstruída e o comportamento suficiente para xKore 0 permanece desconhecido. Resultados do cliente, ainda que documentados com controles, são específicos do build e da janela observada — não foram reproduzidos nesta revisão puramente documental.

## B. Linhas de pesquisa — revisão 2026-10-15

| Linha | Estado fundamentado | Fonte detalhada | Próxima dependência |
|---|---|---|---|
| Movimento `0x035F` | **OBSERVADO:** cadeia natural `0x11 → 0x0D → 0x5B → 0x8A` até store; `0x8A` isolado, com args/objeto/thread conferidos, não gerou store `0x035F` nem `sendmsg` atribuível na janela 6.4, com observadores independentes e controles positivos | [Investigação](MOVEMENT_035F_INVESTIGATION.md); [Pré-condições](MOVEMENT_035F_PRECONDITIONS.md) §5 | §13.5: chamada com 52 bytes também trava; trap pré-store não prova escrita; retorno/envio não confirmados |
| Cifra atual | **OBSERVADO:** cadeia de byte com carga, extensão sem sinal, cópia intermediária e store; **NÃO VERIFICADO:** operação de cifra, produtor de CL, estado/inicialização, fronteira P/C e vetor completo | [Cifra](CIPHER_INVESTIGATION.md) §§ *Continuação dinâmica*, *Evidências* | Última definição executada de CL antes de `gepard+0x1C752B` |
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
Não há movimento autônomo funcional demonstrado. Detalhes e próxima proposta em
[pré-condições §§13.1–13.5](MOVEMENT_035F_PRECONDITIONS.md).
Nenhuma coleta foi executada por esta tarefa de publicação.

### C-01 — bytes efetivamente acompanhados, não cifra resolvida

**OBSERVADO:** escritor `gepard+0x1C752B: mov [esi],cl` em ocorrência independente; carga `+0x1B223C: mov al,[eax]`; extensão `+0x1B2252: movzx ecx,al`; store intermediário `+0x1B2255: mov [ebx],ecx` numa posição `EBP+0xA5`; consumidor `+0x18EFEC: mov ebx,[ebx]` até `+0x18EFF2: mov [ecx],bl`. As setas no documento especializado indicam associação de memória medida em rodadas específicas, **não** adjacência de instruções. A origem de CL, estado da transformação e identidade/limites do pacote seguem desconhecidos. [CIPHER_INVESTIGATION](CIPHER_INVESTIGATION.md) §§ *Continuação dinâmica*, *Evidências e limites*.

### C-02 — experimento negativo e limites de cobertura

**OBSERVADO:** 26 artefatos de rodadas com seis `matched`, um `byte_producer_confirmed`, quinze `timeout`, dois `unattributed_exception`, um `chain_timeout` e um `code_only`; todos com limpeza reportada. Um timeout entre escritor e consumidor **não comprova** geração antecipada em bloco, e monitoramento por thread não comprova ausência de escritores globais. A ferramenta offline continua retornando `C_INSUFFICIENT`/sem chamada completa. [CIPHER_INVESTIGATION](CIPHER_INVESTIGATION.md) §§ *Rodadas efetivamente executadas* e *Ferramenta offline*.

## D. Hipóteses ativas — revisão 2026-10-15

| ID | Status | Favorável | Limite/rival | Experimento discriminatório (planejamento, **não executado aqui**) |
|---|---|---|---|---|
| M-H2 | **HIPÓTESE não isolada** — preparação de estado | Buffer compatível no trap pré-store em §13; folha isolada sem store atribuído em 6.4 | Contexto também mudou; não prova necessidade dos campos. Exclusões de §12 restritas à cobertura; consumo de global não observado | Demonstrar consumo de estado mantendo contexto comparável; proposta própria |
| M-H3 | **HIPÓTESE não isolada** — contexto/callsite/VM | Retornos diferem; ensaio §13 tem ABI incompleta e trava sem retorno normal | Preparação também mudou; causa pode envolver ABI, reentrância ou instrumentação restante | Revalidar frame completo de 52 bytes e comparar contexto sob controle de estado; proposta própria |
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

## F. Pendências e prioridades — revisão 2026-10-15

1. **Movimento:** partir de §13.5 (`7a64581`): a chamada com frame de 52 bytes também travou, enfraquecendo a explicação exclusivamente por discrepância de pilha. Discriminar reentrância/contexto mantendo os argumentos controlados, com observação de retorno, falhas e transporte. Trap pré-store não comprova pacote finalizado. Qualquer ensaio vivo exige autorização própria.
2. **Cifra:** determinar a última definição executada de CL que alcança `gepard+0x1C752B`, sem assumir que desassembly linear antecedente seja fluxo real; depois identificar regiões de estado consumidas/modificadas. Não associar fontes de sessões distintas.
3. **Protocolo:** estabelecer mensagens de inicialização/reinicialização e controle do build atual, com direção, comprimento, sequência, estado e artefatos sanitizados, antes de projetar implementação independente.
4. **Operação:** conservar `inject = true` e `inject-call = true` na configuração; nenhuma alteração funcional ou ação externa sem aprovação humana. Toda sonda viva exige coordenação de exclusividade por colisões nos DRs/handlers.
5. **Curadoria:** conservar a migração sanitizada em `docs/HISTORY/` e o manual em `CIPHER_TOOLS.md`; inventário, proveniência e limites da revisão local em [DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md). Não interpretar os históricos como especificação atual.

**Critério para mudar o status:** nova evidência deve indicar fonte, data, build, sessão sanitizada, observação/método e rival. Atualizar primeiro o documento especializado, depois este mapa, por último o [índice de evidências](RESEARCH_EVIDENCE_INDEX.md).

## G. Mapa documental — revisão 2026-10-15

| Pergunta | Leia primeiro | Depois, se necessário |
|---|---|---|
| Situação e prioridades | Este documento | [README da documentação](README.md) |
| Cadeia `0x035F` | [MOVEMENT_035F_INVESTIGATION](MOVEMENT_035F_INVESTIGATION.md) | [Pré-condições](MOVEMENT_035F_PRECONDITIONS.md) e `research/movement_035f/` |
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
