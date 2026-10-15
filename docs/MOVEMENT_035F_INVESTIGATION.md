# Investigação de preparação do movimento 0x035F

Preparação e coleta autorizada de 2026-10-15. Referência de código: commit
`71c47ff1cbaecd8478ebe98130dddf858e1af02c`, com alteração preexistente em
`gepard_investigation.md` que não foi usada como nova prova dinâmica.
Decisões: `docs/RESEARCH_DECISIONS.md`; protocolo: `docs/GEPARD_CONTROL_PACKETS.md`.
Objetivo imediato: identificar intenção → preparação → montagem de movimento.
Objetivo final: OpenKore em xKore 0; uma função do cliente é etapa intermediária.

## Estado de execução

- **OBSERVADO no código:** auditoria das sondas e opções concluída offline.
- **OBSERVADO nesta sessão:** processo `uaRO.exe`, hashes dos arquivos de módulos
  mapeados e faixas executáveis relevantes, por leitura de metadados `/proc`.
- **OBSERVADO no cliente:** coleta curta via Gadget/Stalker, inspeção limitada de
  código e captura de movimento antes do store por breakpoints de execução.
  Primeira etapa manual; etapa posterior com cliques ydotool/uinput e dois
  ensaios nativos delimitados, descritos separadamente abaixo.
- **OBSERVADO no recorte automatizado:** argumentos de destino iguais em
  `0x11` do dispatcher, `0x8A` e `0x035F`; respostas de movimento `0x0087`.
- **NÃO VERIFICADO:** origem completa da transformação, contrato autossuficiente
  de uma função chamável e protocolo suficiente para xKore 0.
- **Autorizado pelo responsável:** cliente `uaRO.exe` atual e builds subsequentes;
  observar movimentos e injetar ações se necessário; servidor hospedado pelo
  próprio responsável em outra máquina, confirmado nesta conversa.

## Achados reproduzíveis de instrumentação

| Fonte | OBSERVADO no código | Consequência para a investigação |
|---|---|---|
| `agent/relay_hook_linux.js:655–697` | Trace usa a thread cujo ID coincide com `Process.id`, guarda pares de offsets únicos e limita a 8.000 arestas | Preserva a ordem de primeira inserção das arestas únicas, mas perde a sequência completa de chamadas, profundidade e frequência por aresta. Ausência pode ser efeito de thread, faixa, janela ou teto |
| `relay/writeback.py:185–198` | Rastreio usa faixa fixa `0x401000..0x1717000` | Confirmar os mapeamentos do build alvo antes de interpretar offsets |
| `agent/relay_hook_linux.js:386–406` | Resolução de código agrupa arquivos pela base mínima e inclui regiões anônimas executáveis abaixo de `0x2000000`; resultado fica em cache | A resolução das sondas não torna o filtro do trace automaticamente adaptativo |
| `agent/relay_hook_linux.js:305–315` | Gate de entrada examina quatro argumentos na pilha; aceita ponteiro na faixa **OU** conteúdo iniciado por ID permitido | Objeto somente em ECX ou preparação sem pacote pode ficar invisível ao gate; ausência não refuta a cadeia |
| `agent/relay_hook_linux.js:316–327` | Captura de entrada inclui registradores, pequenas leituras apontadas e 12 slots da pilha; desarma após um acerto | Sem gate, primeiro acerto pode pertencer a repouso/UI. Comparar capturas controladas, sem presumir assinatura |
| `relay/safety.py:50–59`; `relay/console.py:99–104` | Sanitização de login/HTTP atua sobre C/P; não faz sanitização recursiva de regmem/stack.mem | Captura de sonda não deve ser promovida diretamente a documento/commit. Extrair somente campos necessários e revisados, sem dados de conta ou bytes crus |

**INFERIDO:** as ferramentas atuais permitem selecionar candidatos, mas não bastam,
isoladamente, para provar a ordem causal completa. Essa conclusão é sobre o contrato
de coleta; não demonstra nenhuma cadeia nova do cliente.

## Ficha de identidade e escopo

Preencher sem credenciais, identificação de conta ou endereços pessoais:

| Campo | Estado |
|---|---|
| Escopo autorizado: cliente, servidor, operações | uaRO.exe atual/subsequentes; observação e eventual injeção; servidor do responsável em outra máquina |
| Hash SHA-256 e versão do uaRO.exe e gepard.dll | Hashes abaixo; versão semântica NÃO VERIFICADA |
| Wine/Proton, Frida/Gadget e arquitetura | Ambos PE Machine 0x14c (i386); Frida 17.23.3 conectou ao Gadget; versão exata Wine/Proton/Gadget NÃO VERIFICADA |
| Identificador local da sessão e instância correta | S1 e S2: processos distintos identificados por uaRO.exe; mapa/repouso e relogin informados pelo responsável |
| Regiões executáveis relevantes e base do código desempacotado | Arquivo uaRO em 0x400000; regiões anônimas executáveis a partir de 0x401000; Gepard em 0x76920000; identidade funcional das regiões NÃO VERIFICADA |
| Thread que executa intenção/preparação/envio | Pontos observados na thread cujo ID coincide com Process.id; origem completa da intenção NÃO VERIFICADA |
| Candidatos históricos resolvidos na instância atual | Prólogos de entrada, chamadas e store conferidos nas duas instâncias; sem prova de função exclusiva de movimento |
| Mapa/condições iniciais de teste | Repouso/cliques próximos; etapa posterior com uma única imagem da janela e pontos A/B. Sem identificação de mapa nem controle de câmera |

Os offsets históricos de `docs/HISTORY/ARCHITECTURE_LEGACY.md` §9 são pistas. A identidade do arquivo
no disco, sozinha, não comprova a identidade/localização do código desempacotado.
Resolver cada alvo na instância atual antes de armar uma sonda.

### Identidade observada dos arquivos mapeados

Leitura de `/proc/<instância>/comm` e `maps`, seguida de hash dos arquivos
indicados por esses mapas (via raiz do processo). Não houve leitura de `mem`.
Campos PE são metadados, não prova de data de compilação ou versão semântica.

| Arquivo | Bytes | SHA-256 | PE timestamp bruto |
|---|---:|---|---:|
| uaRO.exe | 29726720 | `f2f25a89917563237bb6faf60058cc536b7f42469af32fba556842f9f0cb9569` | 1715817600 |
| gepard.dll | 30187512 | `34188e6046eb831f31c0843744c084b56704a765d9e758043a1a1dad6046b08b` | 1786119737 |

O mapa mostra regiões anônimas executáveis `0x401000–0x1607000`,
`0x1607000–0x170f000`, `0x1710000–0x1716000`, `0x1717000–0x1e51000`
e `0x1e51000–0x240a000`, entre outras. São limites observados; nomes e papéis
funcionais dessas regiões continuam hipóteses. A base Gepard difere em
`-0x20000` da referência histórica `0x76940000`; não reutilizar endereços absolutos.

## Perfil de observação conferido offline

Os argumentos abaixo foram passados somente a `relay.cli.parse_args`; nenhum
driver foi iniciado. `Capture.arm_trace` foi chamado com `post` substituído por
impressão local da mensagem, sem Frida nem leitura de processo:

```text
--no-inject --no-inject-call --no-send-watch --no-decrypt-actors
--relay '' --scramble-bp '' --scramble-range '' --trace-test 200
```

Resultado: inject/inject_call/send_watch/decrypt_actors falsos; relay,
scramble_bp e scramble_range vazios; probe_entry/probe_at vazios;
trace_internal/trace_walk zero. Mensagem prevista: `{'type': 'trace', 'ms': 200}`.
Os defaults intencionais de `relay_capture.conf` foram preservados.
Este perfil valida seleção de opções, não sobrevivência ou adequação do build.
Ele também não constitui modo de coleta exclusivamente de TRACE: o agente
continua observando sockets. Não publicar o log geral como evidência sanitizada.

## Matriz de coleta e cobertura pendente

Após identificação e autorização do ambiente, começar pelo teste de sobrevivência
curto. Só então comparar janelas internas de 300–500 ms, três repetições por
condição, repetindo em duas sessões independentes:

| Condição | Questão que ajuda a separar |
|---|---|
| Repouso, mesma duração | UI/tick/tráfego de fundo |
| Clique sem deslocamento | Entrada/seleção versus movimento efetivo |
| Destino válido próximo | Caminho mínimo de preparação/envio |
| Destino válido distante | Dependência de distância/caminho |
| Destino inválido ou bloqueado | Validação/cancelamento versus serialização |

Não presumir que cada condição emite um único pacote ou que caminho distante
implique pathfinding local. Registrar o comportamento observado.

Cada ensaio precisa de rótulo local, sessão/build, condição, duração, opções
efetivas, validação de thread/faixas, arestas normalizadas e resumo do movimento
observado. Um trace com 8.000 arestas é potencialmente truncado; o coletor atual
não emite flag explícita de saturação. Ausência em janela única é inconclusiva.

Selecionar candidatos que se repitam nas condições pertinentes. Sondar entradas
a montante do wrapper histórico, variando uma coordenada por vez. Não usar o
gate por pacote como exigência para a etapa anterior à serialização.

## Critério de avanço

Só considerar demonstrada a preparação quando houver evidência sanitizada de
entrada → mudança de estado/objeto → destino empacotado → montagem de `0x035F`,
com contexto e thread identificados. Um conjunto de arestas não satisfaz esse
critério. Se necessário, especificar instrumentação ordenada mínima em etapa
posterior; nenhuma alteração de código foi feita nesta preparação.

Hipótese: um candidato participa da preparação. Rival: ele somente atualiza
animação/UI ou recebe destino já pronto. Teste: comparar entradas e estado sob
variação controlada de destino e controles negativos. Evidência de posição já
empacotada classifica o candidato como intermediário, não origem decisória.

Chamadas funcionais ficam para ensaio separado, após contrato de argumentos,
objetos, vida útil, thread e estado. Não repetir envio de `035F` pela fila como
atalho. Não usar watchpoint de dados na pilha nem varredura extensa no agente.
Encerrar instrumentação pelo caminho de limpeza, conforme `docs/HISTORY/ARCHITECTURE_LEGACY.md` §11 (cuidados operacionais).

## Verificações desta preparação

- `bash scripts/test-offline.sh`: **PASS**, 8 scripts, após permitir sockets
  locais fora do sandbox. Primeira tentativa: interrompida por PermissionError
  no socket de `test_integration.py`; não foi falha demonstrada do produto.
- Prévia Python de parser + mensagem de trace: **PASS**, sem cliente.
- `python3 scripts/validate-research.py`: **PASS**, consistência básica.
- `python3 scripts/validate-codex.py`: **PASS**, sintaxe/esquema mínimo.
- Verificação Python de espaços finais e fim do novo documento: **PASS**.
  O `git diff --check` geral apontou somente espaços em branco na
  alteração preexistente de `gepard_investigation.md`, preservada nesta etapa.
- Identificação de processo/módulos por metadados: **PASS**, sem bytes de memória
  de sessão, conexão ao Gadget ou ações. Necessitou execução fora do sandbox
  porque a instância do host não era visível no `/proc` isolado.
- Coleta dinâmica: executada após autorização; resultados e limites abaixo.

As conclusões de movimento abaixo se limitam ao build e às condições registrados.
Hipóteses sobre controle de sessão/cifra continuam sem nova comprovação.

## Coleta autorizada e achados do build identificado

### Método e limites de coleta

Primeira etapa: sonda temporária `/tmp/ro035f_probe.py`, fora do código do relay. Ela conectou
ao Gadget por loopback; não instalou hooks de rede, não copiou tráfego e não
chamou funções de ação. Identificação verificou ausência de processos executando
`relay_capture_linux.py`; isso não equivale a inventário de todos os scripts Frida.
SHA-256 final da sonda:
`7033b0a05971e08eb044c47ed76422fef726a39194b70eb67d7e47c584a478db`.
Artefatos locais em `/tmp/ro035f-*.json` são externos e não versionados; os
resultados abaixo são sínteses revisadas, não cópias das capturas.
REA não disponibilizou ferramentas MCP nesta sessão; nenhuma configuração foi
alterada para repará-lo. Estas evidências vêm de Frida/shell, não de REA.

Teste de sobrevivência de 200 ms: evento de conclusão, unfollow e processo vivo.
Isso não comprova por si só responsividade da interface. Nas janelas seguintes,
o responsável confirmou que os movimentos manuais ocorreram normalmente.

O modo global de eventos atingiu capacidade de lote mesmo com fila de 262.144
eventos e drenagem de 10 ms. **INFERIDO:** perda de eventos é possível; resultados
negativos dessas janelas são inconclusivos. O teto de arestas não foi atingido.
Não confundir teto de arestas com capacidade da fila de eventos.

Para descoberta, o modo `direct` usou Stalker transform com callouts somente em
`call` de destino imediato dentro de `0x401000..0x1717000`, sem eventos globais.
Ele não depende dessa fila e não atingiu 8.000 arestas, mas **não cobre chamadas
indiretas, retornos nem chamadas de origem externa ao intervalo**. Guarda pares
únicos, não a sequência completa. Durações de 300/500 ms são solicitadas ao timer;
latência de instrumentação impede assumir frequência real de jogo por esses dados.

Para correlação, o modo `anchor` usou quatro breakpoints de execução somente
leitura, com timeout de 10 s e limpeza explícita: entrada do wrapper, callsite
de um par numérico, entrada do dispatcher e store Gepard. No store, exigiu ponteiro
na janela de pilha corrente e ID `0x035F` imediatamente antes do corpo; leu somente
os três bytes de movimento e reteve coordenadas decodificadas. Não persistiu
corpos crus, registradores completos, credenciais ou objetos arbitrários.

### Convenções de endereços conferidas

| Referência | Base para somar offset | Endereço S1 e S2 |
|---|---|---|
| Wrapper histórico `+0x875400` | código anônimo `0x401000` | `0xc76400` |
| Rotina histórica `+0x873a80` | código anônimo `0x401000` | `0xc74a80` |
| Dispatcher histórico `+0x9463b0` | código anônimo `0x401000` | `0xd473b0` |
| SendPacket RVA `0x816640` | arquivo PE `0x400000` | `0xc16640` |
| Store `gepard+0x18eff2` | Gepard `0x76920000` | `0x76aaeff2`, `mov byte ptr [ecx], bl` |
| Receptor virtual slot `0x18` | Gepard `0x76920000` | `0x76930a90`, `jmp 0x7736c217` |

**OBSERVADO:** misturar as bases do PE e do código anônimo desloca os candidatos
em `0x1000`. Foram conferidas instruções nos dois esquemas; isso não estabelece
assinatura universal para builds futuros.

### S1: repouso e movimento manual

Três controles de 500 ms tiveram 1002, 967 e 972 arestas únicas. Doze janelas de
movimento manual, também de 500 ms, tiveram 730–1005 arestas. As chamadas
`+0x873b2d → +0x875400` e `+0x873ee0 → +0x875400` apareceram em **3/3 controles e
12/12 janelas de movimento**. São offsets de callsite; os retornos são
`+0x873b32` e `+0x873ee5`. **REFUTADO para estas amostras:** presença isolada
dessas chamadas distingue repouso de intenção de movimento. A função pode
participar do movimento e também de processamento periódico ou de outras ações.

Três capturas `anchor` atingiram `0x035F` e registraram limpeza dos quatro
breakpoints, com processo vivo após detach. Em todas, os últimos códigos internos
de despacho foram `0x11 → 0x0D → 0x5B`, seguidos do store 2–3 ms depois.
O par numérico observado antes de `call 0xa797b0` em `0xc76580` mudou entre
amostras e diferiu das coordenadas decodificadas do pacote. **HIPÓTESE:** entrada
em coordenadas de tela passa por transformação/projeção; rival: outro par de
estado ou etapa intermediária. Variação controlada de cursor/câmera e destino
deve distinguir essas explicações. Não chamar o par de coordenada de mapa provada.

### Casos internos de despacho e receptor

Os códigos abaixo são **mensagens internas**, não IDs de pacote de rede.

| Caso em `0xd473b0` | OBSERVADO por instruções do build |
|---|---|
| `0x11`, alvo `0xd476e5` | Emite chamada virtual com `0x0D`; no ramo observado como candidato, testa estado `[this+0x70]`, prepara argumentos e emite `0x5B` em `0xd47757` |
| `0x0D`, alvo `0xd47ac4` | Zera campos `+0x50c/+0x500` e encaminha outro código interno; semântica dos campos NÃO VERIFICADA |
| `0x5B`, alvo `0xd4777d` | Compara retorno de chamada indireta com `[this+0x520]+0x15E`; sai se menor/igual. No caminho restante, atualiza `+0x520` e chama slot virtual `0x18` com mensagem `0x8A` em `0xd477bc` |

O limiar `0x15E` vale 350 numericamente; a unidade e o significado da função
indireta que fornece o valor **não foram identificados**, portanto não afirmar
350 ms nem chamá-lo de cooldown demonstrado.

O getter em `0xa75340` retorna `[ecx+4]` somente se `[ecx+0x58]==1`; caso
contrário retorna zero. Partindo do manager `0x1213338`, o receptor foi resolvido
novamente via objeto/vtable, sem invocar o getter nem reutilizar o objeto antigo.
O slot `0x18` aponta para `gepard+0x10A90`, cuja primeira instrução é um salto.
**OBSERVADO por código/metadados:** esse é o destino virtual atual do repasse de
`0x8A`. A chamada natural foi observada dinamicamente na etapa automatizada;
o tratamento dentro da VM continua incompleto. Não interpretar bytes lineares após o salto como
instruções necessariamente executadas.

### Replicação S2 e critérios ainda abertos

Após relogin informado pelo responsável, o processo anterior deixou de existir;
uma nova instância foi identificada. Hashes dos dois módulos permaneceram iguais,
assim como as instruções conferidas dos candidatos/store. O receptor foi resolvido
novamente. Isso dá duas instâncias do mesmo build, não prova transições ou mensagens
de reinicialização de sessão do protocolo.

Três capturas S2 atingiram `0x035F`, todas com `0x11 → 0x0D → 0x5B` no trecho
imediatamente anterior, 2–3 ms antes da conclusão. Todas informaram limpeza dos
breakpoints e processo vivo. São **6/6 capturas manuais positivas em duas instâncias
do mesmo build**, com destinos decodificados distintos. A sonda para na primeira
correspondência e observa somente a thread escolhida; não representa cobertura
de toda tentativa de movimento. A etapa automatizada seguinte acrescenta controles,
argumentos e respostas do servidor, sem transformar correlação em causalidade completa.

## Automação delimitada e contrato observado em S2

### Entrada e controles

O responsável autorizou ações e confirmou que os cliques funcionaram normalmente.
Um explorer inspecionou **uma única captura somente da janela do jogo**, 1920×996,
no monitor 1920×1200. A imagem não foi versionada nem reutilizada. Os pontos escolhidos
foram A=(900,525) e B=(1020,485), relativos à janela. Geometria e foco foram conferidos
antes de cada ação, além de PID/proprietário, bloqueio de tela e posição do cursor.

`ydotoold` temporário usou `/dev/uinput`, com socket privado; sem alteração de serviço
ou da aceleração do ponteiro. Tanto movimento como botão foram enviados por uinput.
O cursor foi ajustado por feedback até tolerância de um pixel. O ensaio anterior de
warp XWayland com botão uinput deixou coordenadas antigas no estado do jogo; esses
recortes exploratórios não validam correspondência entre cursor e destino.

A rodada pura uinput teve seis cliques alternados: três A produziram (189,357), três B
(191,358), com `0x8A == 0x035F`. Três controles posteriores de 3 s moveram somente o
cursor, sem clique: nenhum `0x8A` nem store correspondente foi observado. São controles
negativos no mesmo processo e condições; não cobrem outros tipos de entrada.

Pontos fixos de tela **não garantem destino fixo de mapa** entre rodadas. No controle
posterior ao ensaio nativo, A produziu (187,356) e B (189,357), mantendo alternância e
correspondência dos argumentos. Câmera, estado do cliente ou outra causa podem explicar
a mudança; a coleta não isolou sua origem. Não usar o primeiro par como constante.

### ABI natural e resposta de movimento

Duas rodadas de três cliques, antes e depois do ensaio nativo, demonstraram:

- Entrada em `gepard+0x10A90`, somente para código `0x8A`, na thread principal.
- ECX igual ao objeto resolvido pelo manager; argumentos de pilha `(0x8A,x,y,0,0)`.
- Par `(x,y)` igual ao `0x11` do dispatcher e ao destino decodificado de `0x035F`.
- Retorno natural em `0xd477bf`; diferença de ESP de 24 bytes em relação à entrada,
  consistente com retorno mais remoção de cinco argumentos de 32 bits pelo callee.
- Resposta `0x0087` de tamanho 12, com destino correspondente. Nas alternâncias,
  origem da resposta seguinte igual ao destino anterior, sustentando continuidade
  do deslocamento entre pedidos. A resposta isolada não comprova chegada ao destino.

**INFERIDO:** convenção thiscall com cinco argumentos de 32 bits. O caller ignora o
retorno; tipo de retorno semântico e todos os requisitos de estado não foram provados.
O `0x11` do dispatcher usa slots de 64 bits para código e coordenadas, com metades altas
zero nas amostras. Seu retorno imediato foi `0x7744c251` (Gepard+`0xB2C251`); não afirmar
uma chamada direta desde o wrapper uaRO até esse dispatcher.

A observação de recepção foi limitada a `recvmsg`/`__recvmsg64`, conexão IPv4 com porta
remota 5121 e identidade fd/porta local. Enquadramento seguiu a tabela canônica por
conexão, com buffer limitado; ID/tamanho desconhecido invalidava o fluxo, sem busca de
resincronização. Persistiu somente origem/destino de `0x0087` correspondente, nunca
corpos crus, endereços de rede, dados de conta ou demais pacotes. Isso é resposta vista
no cliente, não log independente no servidor. Teste offline do parser cobriu fragmentação
e tamanhos variáveis inválidos 2/3; não valida integralmente o protocolo de recepção.

### Ensaio nativo: resultado limitado

Depois da ABI natural, houve dois ensaios de uma chamada cada ao receptor, destino B
já observado, sem clique. O primeiro foi interrompido com `breakpoint triggered`:
objeto/thread conferidos, chamada tentada, sem retorno normal; breakpoints removidos.
**INFERIDO:** conflito com o tratamento padrão de exceções de `NativeFunction`.

A documentação oficial do [Frida, NativeFunction](https://frida.re/docs/javascript-api/#nativefunction)
descreve `steal` como padrão e `propagate` como encaminhamento à aplicação ou ao
`Process.setExceptionHandler`. Após revisão independente, apenas a sonda temporária
passou a `{abi:'thiscall', exceptions:'propagate'}`. Um único novo ensaio entrou com
ECX/argumentos esperados na thread principal e retornou; **não confirmou o par store
`0x035F`/resposta correspondente em 10 s**. Limpeza confirmou remoção dos breakpoints.
Nenhuma nova chamada nativa foi tentada; os três cliques de controle seguintes passaram.

Não concluir que não houve tráfego ou que o servidor rejeitou a ação: o ACK só é
associado depois de um store reconhecido, e o store exige ID/localização na pilha
observada. Rivais: pré-condição preparatória, contexto da VM/callsite, efeito local ou
limite da sonda. Não há função autossuficiente de movimento demonstrada, nem justificativa
para integrar essa chamada ao relay. O resultado mantém a prioridade de investigar antes do `0x11` do dispatcher.

### Origem da preparação: código observado e lacuna

O writer em `0x5fd760` copia campos `+0x20/+0x24` para `+4/+8` do estado de entrada,
condicionado ao byte `+0x3c`, calculando deltas. Watchpoints nos dois campos atuais
registraram 1440 hits em 6 s, com PCs pós-store `0x5fd78c/0x5fd78f`. Isso demonstra
cópia periódica, não a origem do cursor nem chamada a GetCursorPos.

O wrapper `0xc76400`, no ramo `[0x11e40e4]==3`, encaminha os dois inteiros globais
por chamada virtual em `0xc7650e` com `(0x11,x,y,0,0)`. Código `0x11` nesta interface
não deve ser confundido automaticamente com o `0x11` do dispatcher de slots de 64 bits.
O ramo de estado 1 leva a `0xc93cb0`, com limites e divisões em índices; o trecho
inspecionado de `0xa797b0` compara floats com retângulos e retorna objeto. São candidatos
de tratamento de UI, sem projeção de mapa demonstrada. Recortes encerrados no primeiro
retorno não cobrem todos os ramos das funções.

Uma sonda posterior trocou o breakpoint do par de floats pelo callsite `0xc7650e`,
com instrução conferida e coleta na mesma thread. **OBSERVADO em uma amostra:**
`0x11` do dispatcher → `0x8A` → store `0x035F`, coordenadas iguais e resposta `0x0087`,
mas nenhum hit de `0xc7650e` antes do store; limpeza confirmada. O controlador encerrou
com `Input message not confirmed`, corretamente impedindo afirmar o elo pretendido.
É resultado negativo do candidato nessa janela, não falha do movimento. Outras threads,
ramos ou momentos não foram excluídos. O ramo estático de estado 3 não é origem
comprovada do clique normal observado.

## Próxima investigação e critérios de validação

1. Priorizar o chamador real do `0x11` no dispatcher, com retorno observado em
   Gepard+`0xB2C251`. Delimitar instruções e transições VM por janelas ordenadas curtas;
   localizar quem produz o destino de mapa antes dessa chamada. Capturar somente pares
   numéricos, código, thread e endereços de código; não objetos completos. Tratar o ramo
   `0xc7650e` como candidato ainda não confirmado e separar as duas interfaces de `0x11`.
2. Delimitar o trecho VM que transforma entrada em destino antes do retorno imediato
   Gepard+`0xB2C251`. Só afirmar transformação quando entrada controlada, alteração de
   representação e saída de mapa forem observadas na mesma execução, com rival de UI
   separado. Não usar proximidade de arestas ou sequência de primeira inserção como prova.
3. Repetir o contrato em outra sessão com objetos/vtable resolvidos novamente; acrescentar
   clique sem deslocamento, destino bloqueado e distante quando houver cenário conhecido.
   Negativos com fila truncada, thread/faixa incorreta ou enquadramento inválido são inconclusivos.
4. Só propor integração funcional após demonstrar pré-condições, retorno, continuidade de
   sessão e resposta efetiva. Uma função do cliente atende etapa intermediária; xKore 0 ainda
   exige cifra, inicialização/reinicialização e controle de sessão implementáveis no OpenKore.

### Artefatos e revisão

Sondas e resultados são temporários, fora do repositório, em `/tmp/ro035f*`.
As rodadas citadas podem ser conferidas nos seguintes manifestos locais, sem publicar
capturas cruas: `ro035f-automation/pure-uinput-six.json`, `last-hover.json` e
`post-native-ui-three.json`. ABI anterior: `probe-1792047662527246511.json`,
`probe-1792047666174306437.json`, `probe-1792047669827658122.json`. Ensaios nativos:
`probe-1792047915579862459.json` e `probe-1792048184505572733.json`. Candidato de
entrada: `probe-1792048509406653769.json`, no mesmo diretório.
Esses artefatos não são persistência garantida; reprodução exige nova resolução do build
mais os critérios acima. Nenhum script temporário é apresentado como recurso do relay.

Revisões independentes cobriram limites de automação, limpeza, parser e ABI; achados
sobre máscara de falha de limpeza, iovecs e tamanhos inválidos foram corrigidos nas
sondas temporárias antes dos ensaios finais. Máximo de dois subagentes simultâneos.
Não foi medida economia de tokens por tarefa; não há alegação de ganho de eficiência.
Ao final, o daemon uinput temporário foi encerrado por SIGTERM dirigido ao processo
do socket privado. Cliente vivo; nenhum loop de cliques ficou programado.

### Verificações ao encerrar

- `bash scripts/test-offline.sh`: **PASS**, 8 scripts, repetido após a coleta;
  integração usou somente sockets locais fora do sandbox.
- `python3 scripts/validate-research.py`: **PASS**; não prova hipóteses dinâmicas.
- `python3 scripts/validate-codex.py`: **PASS**; não mede modelo/runtime ou tokens.
- `node /tmp/ro035f-ack-parser-test.js`: **PASS**, recorte do parser temporário.
- Revisão independente da síntese contra os artefatos citados: **PASS**.
- Movimento UI/ABI e respostas: **PASS no recorte**. Chamada nativa autossuficiente:
  **NÃO DEMONSTRADA**. Associação do candidato `0xc7650e`: **NÃO CONFIRMADA**.
- Espaços/fim de arquivo dos dois documentos e diff restrito: **PASS**.
  Alterações preexistentes de `gepard_investigation.md` e `.mcp.json` ficaram fora do trabalho.
