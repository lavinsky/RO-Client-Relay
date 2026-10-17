# Investigação da cifra uaRO/Gepard — 2026-10-15

**Estado 2026-10-17:** esta é a **única linha de pesquisa ainda aberta**, por decisão do responsável; movimento `035F` e ações automáticas `0437/0438/0AF4` estão funcionais. O bug de byte zero no merge do Frida foi corrigido por `_fix0` (`agent/relay_hook_linux.js:481-534`), **sem** identificar o produtor de keystream, estado de sessão ou inicialização. Não confundir correção local dos bytes com descoberta do algoritmo. [Conclusão funcional](ACTION_0437_0438_INVESTIGATION.md).

> **Integração 2026-10-16:** [entregas conferidas e limites](#integração-documental--cifra-20261016-pop-03) atualizam os checkpoints anteriores; relatos, consistência de artefatos e prova independente permanecem distintos.

## Resultado e escopo

**Resultado atual: C quanto à cifra, com avanço dinâmico comprovado na cadeia de bytes.**
A continuação dinâmica abaixo confirmou a carga→store, seu escritor intermediário,
a leitura anterior por EAX e um escritor desse byte. Esses recortes são transporte
de dados; a geração de CL e o estado criptográfico continuam desconhecidos.

**Auditoria inicial:** os onze artefatos auditados não contêm uma chamada de transformação completa que
reúna entrada, saída, estado anterior/posterior e contexto identificado. A auditoria
não ajustou algoritmo, não completou bytes ausentes e não produziu um decrypt fictício.
Inicialização, evolução do estado e validação independente continuam não verificadas;
a cifra não está resolvida e xKore 0 não foi implementado.

Pergunta preservada: `(saída, estado seguinte) = F(entrada, estado anterior, contexto)`.
Esta execução investigou exclusivamente o cliente. Não retomou a origem do ANDAR,
projeção de coordenadas, bot ou outro backend xKore. Código servidor 2016 aparece
nas notas consultadas como referência histórica; não foi usado como implementação
do build atual, nem para ajustar constantes. Documentos históricos ficaram intactos.

Commit inicial: `dbb08c73d9b19b615486119255cd2c2a370cd9f8`, branch `main`.
Alteração preexistente: `.mcp.json` não rastreado, preservado. Não houve commit,
push, PR ou publicação externa nesta tarefa. Não foram usados subagentes nem
instaladas dependências. A leitura/inventário inicial terminou em até 20 minutos.

## Build e condições conhecidos

O inventário inicial do sandbox não expôs o cliente. Posteriormente, o responsável
autorizou expressamente uma exceção para inventário do host e coleta passiva limitada.
Isso não autorizou ações provocadas, instalação ou elevação dos testes de integração.

Inventário autorizado: exatamente um `uaRO.exe`, um listener Gadget associado,
nenhum dos drivers conhecidos em execução. Hashes dos módulos mapeados, revalidados
antes da inspeção de código:

| Módulo | Bytes | SHA-256 |
|---|---:|---|
| uaRO.exe | 29726720 | `f2f25a89917563237bb6faf60058cc536b7f42469af32fba556842f9f0cb9569` |
| gepard.dll | 30187512 | `34188e6046eb831f31c0843744c084b56704a765d9e758043a1a1dad6046b08b` |

**Identificação estática confirmada pelo responsável, na mesma
build desta pesquisa (DiE, 2026-10-15):** `uaRO.exe`
protegido por **Themida/WinLicense 3.XX** e `gepard.dll`
protegida por **VMProtect**. Os arquivos analisados são os
atuais, não uma amostra histórica. Isso não revela a origem
de `CL` nem determina se esse trecho é virtualizado.
[Fingerprint e limites](PROTECTION_FINGERPRINT_DIE.md).

Esses hashes também constam da investigação anterior S1/S2. Isso identifica arquivos;
não prova identidade de sessões criptográficas nem inicialização atual. Artefatos sem
build/sessão explícitos permanecem desconhecidos, inclusive quando têm endereços iguais.
Nenhum campo de sessão foi inferido apenas de PID, horário ou nome do arquivo.

Ferramentas existentes: Python 3.14.7, ambiente Frida 17.23.3, Node, objdump 2.46.1,
readelf, strings e gdb. A análise offline usa somente a biblioteca padrão Python.
REA MCP não estava exposto; não houve reparo/configuração/download de analisadores.
`HANDOFF.md` está ausente no commit atual. Foram consultados os quatro documentos
preexistentes de `docs/`, trechos técnicos de arquitetura/investigação e os módulos
de agente, writeback, pacotes e segurança necessários ao contrato de coleta.

## Evidências auditadas e limitações

| Classificação / origem | O que existe | O que não demonstra |
|---|---|---|
| **OBSERVADO no artefato**, captura manual S1/S2 | Coordenadas; ordem de códigos internos; flags de limpeza | Não há bytes P/C ou snapshots de estado; coordenadas não são vetor de cifra |
| **OBSERVADO no artefato**, rodada ABI | Destino correspondente em dispatcher `0x11`, API `0x8A`, `0x035F` e resposta `0x0087` | Não identifica F, estado, inicialização ou função autossuficiente de movimento |
| **OBSERVADO no código**, sonda nativa antiga | O ACK só é associado quando `pending` foi criado pelo store reconhecido | Ausência desse par não demonstra ausência de envio/resposta ou rejeição do servidor |
| **OBSERVADO no artefato**, `/tmp/skill-root-live/events.jsonl` | Dois pacotes de entrada em eventos HIT; stack/registradores não são copiados ao relatório | Falta saída cifrada, estado e build atribuível ao vetor; não alinhar com outro log |
| **OBSERVADO no fixture legado** `sendbp_queue.jsonl` | 40 eventos; 26 saídas de ações com forma válida; quatro janelas de watchpoint elegíveis | Sem P independente, fronteiras da transformação, estado ou build; não é fixture nova desta tarefa |
| **OBSERVADO no recorte do log**, sete ações | Saídas de socket; nenhum P associado | Uma chamada de socket não equivale a chamada de cifra; não prova estado/aceite de transporte |
| **OBSERVADO nesta execução**, código do build identificado | Âncora executável `gepard+0x18eff2`: `mov byte ptr [ecx], bl` | Store não revela por si só a origem do byte ou geração do fluxo |
| **INFERIDO, condicionado ao caminho linear** | Decodificações compatíveis anteriores: `+0x18efec mov ebx,[ebx]`, `+0x18efee add ecx,ebp`, `+0x18eff0 mov ecx,[ecx]` | Execução/dominância não foi traçada; enumeração reversa parou em ambiguidade antes de `+0x18efec` |
| **NÃO VERIFICADO**, janela EBX histórica | O agente alinha o valor de EBX e lê uma janela; não identifica seu uso | Não comprova que seja a região de estado consumida, sobretudo após possível carga em EBX |
| **HIPÓTESE histórica** | Ramp rol8, palavras de 16 bits, incrementos de posições, papel de 0x8280 | Nenhuma dessas alegações foi tratada como axioma ou validada no recorte atual |
| **REFUTADO neste inventário** | A alegação de que os arquivos de coordenadas/ACK, sozinhos, fornecem vetores completos | A ferramenta mostrou ausência dos campos P/C/estado; isso não refuta uma cifra específica |

Os dois snapshots de código confirmam bytes decodificáveis na instância atual.
Não se inferiu que instruções próximas tenham sido executadas em sequência.
Em particular, o predecessor de store observado por decodificação é uma carga de
ponteiro, não evidência de uma instrução XOR. Sem XOR independentemente confirmado,
nem o delta P XOR C pode ser promovido a fluxo criptográfico observado.

## Três famílias de hipóteses

| Família | Previsão / rival | Teste delimitado | Resultado |
|---|---|---|---|
| H1: estado amostrado diferente do consumido | Região efetivamente lida/modificada difere da janela EBX. Rival: região correta, mudança ocorre antes do store | Provar a dependência da região antes de comparar snapshots | **SUSPENSA**: região consumida não identificada; inspeção local é compatível com EBX contendo valor carregado, sem prová-lo dinamicamente |
| H2: geração antecipada em bloco | Mudanças de estado/fluxo precedem vários stores. Rival: geração por byte usa outra região | Seguir o produtor de BL e separar geração de consumo | **SUSPENSA**: falta produtor executado e fronteira de geração; âncora final conferida |
| H3: comprimento/fronteira afeta F | Chamadas ímpares/pares contíguas impõem transições diferentes de concatenação. Rival: perdas, mistura de unidades ou estado inicial diferente | Replay com fronteiras e estados observados, sem resets artificiais | **SUSPENSA**: não há sequência real completa/reservada; nenhum candidato foi ajustado |

As comparações de ramp, adjacência e incrementos no programa são diagnósticos
descritivos disponíveis para snapshots explicitamente identificados. Fixtures
sintéticas exercitam esses cálculos; não são evidência do algoritmo do cliente.

## Experimentos realmente executados — auditoria inicial

1. Leitura/inventário e hashes de preservação; nenhuma sonda histórica foi executada.
   `/tmp/ro035f_probe.py` tem PID/portas/endereço históricos; `auto_probe.py` inclui
   emissão nativa e ACK condicionado ao store; `inspect.py` inclui watchpoints e
   retry de limpeza sem limite. O driver de `/tmp/skill-root-live` inclui substituição
   de driver, espera por stdin e TTL longo; o probe inclui leituras amplas de stack.
   Esses comportamentos não foram reutilizados.
2. Inspeção de até 2 MiB no início e 2 MiB no fim de `relay_log.jsonl`, sem carregar
   seus 53 MB no contexto. As regiões ficaram separadas; os sete envios selecionados
   não foram ligados a P de outros arquivos. Identidade/tamanho das regiões e seus
   hashes estão em artefatos privados; não se atribuiu hash de região ao arquivo todo.
3. Auditoria offline de onze arquivos explicitamente indicados: nenhum erro de leitura,
   zero chamadas completas de cifra. O código não recupera corpos de coordenadas,
   não associa por proximidade temporal e não confunde socket com fronteira de F.
4. Após autorização adicional e testes de ciclo de vida com doubles: uma inspeção
   Gadget de **200 ms**, seguida de outra de **200 ms** dentro do orçamento opcional,
   somente de código. A segunda delimitou até oito predecessores e parou em ambiguidade
   após três decodificações compatíveis. Ambas concluíram e confirmaram limpeza.
5. Nenhuma janela de coleta de vetores/estado, Stalker, breakpoint ou watchpoint novo.
   Não se provocou ação. O produtor de BL e a região de estado ainda não estão
   identificados; uma coleta no consumidor final não satisfaria H1/H2. A posse dos
   slots de debug/handlers existentes não foi auditada; a inspeção não usa esses recursos.

Não houve coleta dependente de login, cliques ou nova sessão do responsável.
Não foi criado coletor de tráfego que pudesse condicionar respostas ao store.
Portanto não há resultados novos sobre envios aceitos, respostas ou bytes no fio.

## Ferramenta offline reproduzível

```bash
umask 077
cipher_out=$(mktemp -d /tmp/ro-cipher-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX)
python3 research/cipher/analyze.py \
  --input research/cipher/fixtures/synthetic_calls.jsonl \
  --out "$cipher_out"
```

Para auditar fontes reais existentes, indicar cada caminho por `--input`; usar outro
diretório privado de saída a cada rodada. Formatos, limites, semântica dos campos e
diagnósticos estão em [CIPHER_TOOLS.md](CIPHER_TOOLS.md). Os únicos bytes/estados colocados
no repositório nesta tarefa são sintéticos e explicitamente rotulados como tal.

Resultados: `inventory.json` e `missing-data.json`, ambos privados. O inventário inclui
hash/proveniência, disponibilidade, exclusões e hipóteses suspensas. Saída padrão
contém somente contagens. Arquivo ausente/malformado retorna diagnóstico e exit 2;
insuficiência válida retorna C e exit 0, não validação da cifra.

## Verificações — auditoria inicial

| Comando / verificação | Resultado |
|---|---|
| `python3 tests/test_cipher_research.py` | **PASS**, 39 testes: tipos/JSON, perdas, truncamento, associação ambígua, isolamento, determinismo, preservação, privacidade, ausência de Frida/rede; doubles de timeout/erro/interrupção/teto/limpeza da inspeção |
| `python3 scripts/validate-research.py` | **PASS**; presença/consistência dos documentos canônicos, não prova dinâmica nem valida este relatório semanticamente |
| `bash scripts/test-offline.sh` | **FAIL ambiental** em `test_integration.py`, PermissionError ao criar socket local; os três scripts anteriores passaram. Não foi pedida elevação para testes |
| `python3 tests/test_packets.py`, `test_relay.py`, `test_safety.py`, `test_sendwatch.py`, `test_writeback.py` | **PASS**, executados separadamente após a interrupção ambiental |
| `git diff --check` restrito + verificação de arquivos novos | **PASS**, incluindo arquivos novos não rastreados por comparação com `/dev/null` |
| Validação de candidato em dados reais reservados | **NOT RUN**: nenhum candidato justificável e nenhum conjunto completo independente; não fabricar inicialização |

Houve um erro inicial no próprio teste: o mesmo nome de arquivo foi usado duas vezes,
e a escrita exclusiva recusou sobrescrever. O teste foi corrigido; não era falha do
produto nem motivo para enfraquecer a preservação de entradas.

## Artefatos privados e limpeza — auditoria inicial

Diretório principal: `/tmp/ro-cipher-20261015T112524Z/`, 0700; arquivos privados 0600.
Contém inventários/hashes, regiões limitadas, relatórios `audit-final/`, resultados de testes,
inventário autorizado e `preflight/`/`code-dependency/`. Os testes usam diretórios próprios
`/tmp/ro-cipher-<data-hora>-tests-*`, também privados. Nenhum conteúdo real é copiado para
fixtures, documentação ou Git. Os artefatos não constituem armazenamento permanente. A auditoria principal mediu
menos de 1 MiB de artefatos; o teto total de 64 MiB não foi atingido. Hashes dos
5.635 arquivos preexistentes protegidos permaneceram iguais; nenhum arquivo
rastreado preexistente aparece modificado no diff.

As duas sessões Gadget próprias foram descarregadas/desanexadas e suas conexões
removidas, com confirmação de limpeza. Nenhum handler, breakpoint, watchpoint, Stalker,
driver, serviço ou loop foi instalado. O cliente não foi encerrado. Não há processo de
coleta desta tarefa em segundo plano. Não foram tocados recursos da investigação anterior.

## Próximo experimento específico — planejamento inicial

Após validar previamente posse/ausência de instrumentação conflitante, observar por
até 500 ms o trecho executado em torno de Gepard+`0x18efec..0x18eff4`, com endereços
resolvidos no build e teto explícito. Confirmar se a carga `mov ebx,[ebx]` alimenta BL
consumido pelo store. Seguir somente o escritor da dword referenciada nessa carga,
para localizar a origem do byte transformado e suas dependências de estado. Parar em
ambiguidade; não desvirtualizar toda a VM nem usar ramp como identidade automática.

Somente quando essas dependências forem demonstradas, obter chamadas naturais com
entrada/saída, estados antes/depois, comprimento e unidade/direção, mais observação
independente do transporte/resposta. Reservar sequências contíguas não usadas no ajuste;
sem estado inicial observado, registrar lacuna em vez de inventá-lo.

## Continuação dinâmica — 2026-10-15

### Resultado novo e proveniência

O responsável confirmou expressamente a exclusividade do cliente, inclusive a saída
da outra investigação, e autorizou separadamente o breakpoint de execução, o watchpoint
de 1 byte e sua mudança para a origem efetivamente lida. A ausência de drivers não
foi usada como prova de exclusividade. Os hashes dos dois módulos continuaram iguais
aos da tabela acima. As instruções e mapeamentos foram revalidados no Gadget; RVAs
continuam condicionados a esse build. A sessão criptográfica, direção e identidade
do pacote das ocorrências retidas permanecem **desconhecidas**.

As novas evidências **não** atribuem os bytes a `0x035F`: houve estímulos manuais de
movimento, mas não se observou uma fronteira independente de pacote/cifra ou transporte.
Não se reconstruiu pacote a partir de coordenadas. Nenhuma ação foi injetada.

Recortes executados e conferidos, com contexto de thread/ESP/EBP e ordem preservados:

```text
+0x1C752B: mov byte ptr [esi], cl       escritor do byte de origem, prova isolada
                 ↓ memória intermediária (associação observada em outra rodada)
+0x1B223C: mov al, byte ptr [eax]       endereço de EAX salvo ANTES da carga
+0x1B223E: mov esi, 0
+0x1B2243: movzx ebx, bx
+0x1B2246: mov esi, 1
+0x1B224B: mov edi, 0x400
+0x1B2250: add ebx, ebp
+0x1B2252: movzx ecx, al
+0x1B2255: mov dword ptr [ebx], ecx     cópia para a posição EBP+0xA5
                 ↓ posição intermediária, com ordem de escrita/leitura observada
+0x18EFEC: mov ebx, dword ptr [ebx]    endereço de EBX salvo ANTES da carga
+0x18EFEE: add ecx, ebp
+0x18EFF0: mov ecx, dword ptr [ecx]
+0x18EFF2: mov byte ptr [ecx], bl
+0x18EFF4: mov edi, ebp                ponto posterior ao store
```

Os dois recortes separados por setas não representam instruções adjacentes nem uma
aresta deduzida de proximidade. A associação escrita→leitura foi medida pelo watchpoint
e pela ocorrência consumidora dentro da mesma captura. A confirmação antes/depois de
`+0x1C752B` foi uma **ocorrência independente**, sem unir seus valores aos de outra rodada.
No trecho contíguo `+0x1B223C..+0x1B2255`, cada instrução indicada foi visitada por
breakpoint rotativo; a igualdade do byte foi conferida até o store final.

### Evidências e limites das conclusões

Origens privadas relativas a `/tmp/ro-cipher-20261015T121900Z/`:

| Classificação | Origem:linha | Conclusão delimitada |
|---|---|---|
| **OBSERVADO** | `breakpoint-round-1/chain-capture.json:92` | Cinco pontos da cadeia original; carga comparada à dword amostrada antes de sobrescrever EBX; BL comparado ao byte posterior ao store; 6 ms entre os pontos; limpeza confirmada |
| **OBSERVADO** | `producer-round-1/chain-capture.json:152` | Antes/depois de `+0x1B2255`: ECX foi copiado para a origem da carga em EBX; dword escrita igual à carregada; nenhuma escrita intermediária observada nessa posição na thread acompanhada; 8 ms |
| **OBSERVADO** | `operand-round-2/chain-capture.json:166` | Entrada em `+0x1B2252` e extensão com zeros de AL para ECX; descarta a decodificação sobreposta começando em `+0x1B2253` como entrada desse trecho nessa ocorrência; 9 ms |
| **OBSERVADO** | `load-round-1/chain-capture.json:272` | Endereço original de EAX preservado; byte lido conferido após a carga e em cada etapa até o store; 13 ms; origem diferente do destino e da posição EBP+0xA5 |
| **OBSERVADO / INFERIDO** | `byte-writer-round-2/chain-capture.json:315` | Watchpoint registrou uma escrita anterior à leitura; byte igual ao consumido; mesmo frame/thread; predecessor único compatível `+0x1C752B mov [esi],cl` ainda era candidato nessa rodada; sequência consumidora 14 ms |
| **OBSERVADO**, independente | `byte-producer-confirm/chain-capture.json:222` | Breakpoints antes/depois de `+0x1C752B`: endereço em ESI e CL preservados, byte posterior igual a CL, contexto estável; 1 ms; não houve associação a leitura posterior nessa captura |
| **INFERIDO** | Mesmas ocorrências | EBP+0xA5 funciona como posição intermediária desse caminho; os passos observados são cargas, extensão com zeros e cópias de um byte já disponível |
| **NÃO VERIFICADO** | Falta evidência anterior a CL | Última definição de CL, operação criptográfica, estado realmente consumido/modificado, inicialização, fronteiras de F, identidade P/C e transporte |
| **REFUTADO no recorte executado** | Cargas e valores anteriores/posteriores | Tratar EBX posterior a `+0x18EFEC` como o ponteiro original da carga: nesse caminho ele já contém a dword zeroestendida; isso não refuta todos os usos históricos de EBX |

A origem lida por EAX e a posição EBP+0xA5 pertenciam a mapeamentos distintos,
anônimos e RWX, separados do mapeamento de ESP. Esse aspecto **não** identifica
estado criptográfico, fluxo, entrada clara ou saída cifrada. A recusa de watchpoints
em regiões que continham ESP foi aplicada a todas as threads enumeradas.

### Rodadas efetivamente executadas

Foram preservados 26 artefatos de rodada, incluindo testes iniciais de até 200 ms
e uma inspeção somente de código. `experiment-summary.json` registra hashes, tamanho,
modo, motivo de parada, tempos, contadores e limpeza por arquivo.

- Cinco janelas Stalker solicitadas de 500 ms: uma teve 426 visitas e 85 cadeias
  completas não retidas pelo filtro de cabeçalho/pilha; as demais tiveram zero
  visitas. Contadores provaram execução no código acompanhado, sem afirmar acerto
  na âncora. Ajustes de coordenação e filtro foram registrados, sem refutar a cadeia.
- Mudança autorizada para um breakpoint de execução rotativo: confirmou a cadeia.
  Depois, um watchpoint de escrita de 1 byte delimitou o escritor da posição lida.
- Duas paradas `unattributed_exception` encerraram e limparam a coleta. A primeira
  versão aceitava somente candidatos `mov`; o diagnóstico limitado encontrou `pop`.
  O reconhecimento foi ampliado somente para essa operação observada; decodificação
  anterior à exceção permaneceu candidata, sem alegar execução de todo predecessor.
- Rodadas seguintes confirmaram o produtor intermediário, `movzx ecx,al`, a carga
  `mov al,[eax]` e a associação ao escritor do byte real. Uma janela passiva vazia
  foi seguida por comparação com movimento, sem aumentar os tetos.
- A tentativa de capturar escritor real e consumidor na mesma sequência terminou
  em `chain_timeout`: a escrita ocorreu, mas a leitura esperada não apareceu nos
  500 ms seguintes. Não se inferiu geração antecipada em bloco só desse timeout.
  A confirmação final isolou o escritor e encerrou após seus dois pontos.

Resultados agregados: seis `matched`, um `byte_producer_confirmed`, quinze `timeout`,
dois `unattributed_exception`, um `chain_timeout` e um `code_only`. Nenhum teto de
eventos/escritas/bytes foi atingido: máximo de 426 visitas Stalker, 132 traps,
18 escritas e 21.068 bytes por captura. As capturas somaram 177.730 bytes.
Todos os 26 artefatos registram limpeza confirmada.

Janelas pedidas e tempos medidos são distintos: timers de 500 ms chegaram a registrar
502 ms até o encerramento, e esperas de 10 s chegaram a 10.011 ms. Não há garantia
de tempo real. Os recortes positivos completos duraram 6–14 ms; o escritor isolado,
1 ms. Esses valores não medem a pausa total do cliente ou custo de cada trap.
Watchpoints observaram somente a thread alvo; escritas de outras threads não foram
monitoradas. Não declarar ausência global de escritores ou de mudanças de estado.

H1 permanece aberta: identificaram-se regiões realmente lidas, mas nenhuma como
estado da cifra. H2 permanece aberta: encontrou-se transporte de byte já disponível,
sem provar geração antecipada de fluxo. H3 permanece suspensa por falta de fronteiras,
comprimentos e sequências completas de transformação. XOR/P XOR C não foi validado.

### Ferramentas, reprodução offline e verificações

Novos arquivos: `chain_capture.py`, `chain_probe.js`, `chain_probe_test.js` e
`chain_audit.py`, em `research/cipher/`. `analyze.py`, README e testes foram ampliados.
A ferramenta offline recalcula igualdades do recorte e mantém observações independentes
separadas; continua retornando C e zero chamadas completas de cifra.

```bash
umask 077
cipher_out=$(mktemp -d /tmp/ro-cipher-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX)
python3 research/cipher/analyze.py \
  --input /tmp/ro-cipher-20261015T121900Z/load-round-1/chain-capture.json \
  --input /tmp/ro-cipher-20261015T121900Z/byte-writer-round-2/chain-capture.json \
  --input /tmp/ro-cipher-20261015T121900Z/byte-producer-confirm/chain-capture.json \
  --out "$cipher_out"
```

`audit-all-dynamic/` auditou os 26 arquivos sem erro; `final-dynamic-audit/` contém
o recorte de três fontes do exemplo. Não existe replay da cifra nem candidato de
decrypt. As sondas evoluíram entre rodadas; hashes de código foram registrados onde
disponíveis. A versão final recebeu endurecimento offline de limites/diagnóstico
após as coletas; isso não constitui uma nova validação ao vivo dessa revisão.

| Comando | Resultado da continuação |
|---|---|
| `python3 tests/test_cipher_research.py` | **PASS**, 48 testes sintéticos/offline; inclui ordem, valores anteriores às cargas, etapas de cópia, limites, isolamento, erro/timeout/desarme, privacidade e preservação |
| `python3 scripts/validate-research.py` | **PASS**, validação documental; não é prova dinâmica |
| `bash scripts/test-offline.sh` | **PASS**, dez scripts, incluindo o teste concorrente de movimento; a falha ambiental da execução inicial não se repetiu neste ambiente |
| `git diff --check` e arquivos novos | **PASS**, escopo da tarefa e 12 arquivos novos por comparação com `/dev/null` |
| Candidato de cifra / estados reais reservados | **NOT RUN**, nenhum candidato ou vetor completo justificável |

### Artefatos, limpeza e próximo experimento

Artefatos novos em `/tmp/ro-cipher-20261015T121900Z/`: diretórios 0700 e arquivos
0600. Não há capturas reais ou estados nas fixtures novas. Os arquivos preexistentes
fora do escopo, inclusive `.mcp.json`, foram preservados. Não houve alteração de
`relay/`, `agent/`, configurações ou OpenKore, nem commit, push ou publicação.
Os recursos próprios foram desarmados antes de remover handlers/descarregar scripts;
sessões e conexões próprias foram liberadas. Nenhum coletor foi deixado em segundo
plano e o cliente não foi encerrado. A exclusividade deve ser coordenada novamente
antes de outra investigação instrumentar a instância.

Próximo experimento específico: determinar a última definição executada de CL antes
de `gepard+0x1C752B`, preservando ESI como endereço de destino. As decodificações locais
anteriores são ambíguas (`+0x1C7525/+0x1C7526` e `+0x1C7529`); não assumir um caminho.
Observar somente o trecho que efetivamente alcança esse escritor, com comparação
antes/depois dos operandos que produzirem CL. Se houver carga, registrar seu endereço
antes da sobrescrita. Só promover uma região a estado criptográfico depois de demonstrar
suas leituras e atualizações na transformação, com fronteiras e inicialização conhecidas.

Relato paralelo recebido ao encerrar as coletas: `docs/MOVEMENT_035F_PRECONDITIONS.md:129`
registra `sendmsg` com retorno efetivo de cinco bytes, mas sem comprimento solicitado
ou buffer capturado nessa rodada. Isso é **OBSERVADO no documento / NÃO REVALIDADO aqui**;
não associa as ocorrências desta pesquisa a `0x035F` nem fornece fronteira da cifra.
Os arquivos de movimento foram preservados. Em uma coleta futura de vetores, essa
descoberta pode orientar observação independente de bytes tentados/aceitos pelo transporte,
após nova coordenação de exclusividade; não foi usada para preencher campos ausentes.

## Retomada após consolidação — origem executada de CL

Referência inicial: `3349b57eb174c487b8359ce6896c8a10a24b9be6`, em 2026-10-15.
O responsável confirmou novamente exclusividade, personagem no mapa e observação
passiva limitada, com movimentos naturais quando solicitado. O cliente atual foi
descoberto novamente: um alvo/listener, hashes iguais aos documentados. Reinícios
do trabalho de movimento invalidam qualquer continuidade presumida com as rodadas
anteriores; nenhum endereço de heap ou estado criptográfico antigo foi reutilizado.

**OBSERVADO — origem imediata de CL:** `cl-round-1/chain-capture.json` em
`/tmp/ro-cipher-20261015T174618Z/` confirmou a sequência abaixo. O arquivo contém
os endereços/valores privados; este documento registra somente instruções e relações.

```text
+0x1C7502 mov ecx, dword ptr [ecx]   endereço original salvo antes da sobrescrita
+0x1C7504 xor ebx, 0x47d61b9
+0x1C750A sub eax, esi
+0x1C750C add esi, ebp
+0x1C750E mov eax, 0xa
+0x1C7513 xor eax, 0x80
+0x1C7518 mov eax, ebx
+0x1C751A mov eax, 0x200
+0x1C751F or eax, 0x1f
+0x1C7524 mov esi, dword ptr [esi]   slot do ponteiro salvo antes da sobrescrita
+0x1C7526 and eax, 4
+0x1C752B mov byte ptr [esi], cl
+0x1C752D                           observação posterior ao store
```

Método: duas inspeções somente de código, limitadas a 64 bytes, com alternativas
de decodificação preservadas; depois breakpoint de execução rotativo por 13 pontos.
Um teste inicial de até 200 ms terminou sem acerto, com limpeza. Na rodada principal,
houve três segundos de preparação e movimentos naturais do responsável; espera de
1.303 ms, sequência de 9 ms, 13 visitas, zero perdas de ordem/contexto e zero erros
de leitura. Armação e limpeza foram confirmadas. Isso é evidência viva; os doubles
e os testes Python apenas verificam a ferramenta offline.

Comparações registradas: a dword anterior à carga coincidiu com ECX posterior;
ECX permaneceu igual em todos os pontos seguintes; a carga do ponteiro de ESI e o
destino do store coincidiram; o byte posterior ao store foi igual a `ECX & 255`.
O endereço de origem correspondeu a `EBP+0x36` nessa ocorrência, em mapeamento
anônimo RWX distinto do que continha ESP. A dword carregada não estava restrita a
um byte. **Não** tratar seus outros bytes como estado criptográfico demonstrado.

**INFERIDO:** a última definição de CL nesse trecho é a carga em `+0x1C7502`;
as instruções seguintes não redefinem ECX e sua estabilidade foi medida, sem
deduzir execução por proximidade. Os XOR em EAX/EBX não demonstram XOR no byte
transportado por CL nem uma operação da cifra. O papel criptográfico, identidade
de pacote, direção, inicialização e fronteira de F continuam **NÃO VERIFICADOS**.
As associações históricas com `+0x1B223C`/`+0x18EFF2` continuam em suas próprias
ocorrências, sem fusão de valores desta retomada com capturas anteriores.

Os avanços de movimento foram incorporados pelo método: `sendmsg` e recepção
possuem canais independentes, mas o retorno de cinco bytes não identifica o pacote;
trap pré-store não prova conclusão de escrita. A repetição com 13 dwords também
congelou, sem excluir toda exceção ou isolar preparação/contexto. Esses ensaios não
foram reutilizados. A presença confirmada de VMProtect/Themida na build não atribui
este trecho a funções virtualizadas nem explica automaticamente os desvios.

Ferramentas atuais: `--mechanism cl-origin`, inspeção `--inspect-cl-origin` e
revalidação de cada instrução. O analisador offline recalcula a carga e a cópia do
byte baixo, sem exportar valores; a classificação da cifra permanece C. O próximo
passo delimitado é observar o escritor do byte baixo da posição efetivamente lida
antes de uma nova carga, com endereço, ordem e contexto preservados na mesma captura.
Novos artefatos ficam no diretório privado acima (0700/0600); nenhuma captura real
foi adicionada aos fixtures ou ao Git. A continuação abaixo distingue os resultados
vivos das mudanças posteriores verificadas somente offline.

### Nova instância e primeiro escritor aritmético observado

Durante a coordenação do watchpoint, o processo da primeira captura terminou. O
responsável confirmou reinício, exclusividade e personagem no mapa. A tentativa
`cl-writer-preflight/` abortou no inventário do host, antes de conectar ou armar
instrumentos. `host-inventory-2.json` registra uma nova instância com os mesmos
hashes de módulos; nenhuma continuidade criptográfica ou endereço antigo foi
presumido. Duas inspeções de código e o teste de 200 ms foram repetidos somente
para revalidar a instrumentação atual.

| Artefato privado na mesma raiz | Observação e cobertura | Limite de interpretação |
|---|---|---|
| `session2-cl-round-1/chain-capture.json` | 13 pontos, 320 ms incluindo espera, sequência de 9 ms; carga e store conferidos; origem novamente `EBP+0x36` | Ocorrência independente da primeira instância |
| `session2-cl-writer-preflight/chain-capture.json` | Em 166 ms, 15 escritas retidas e uma exceção cuja única decodificação predecessora foi `+0x2689FB xor dword ptr [ecx],edx` | A decodificação isolada não prova a instrução executada nem seus operandos anteriores |
| `session2-cl-transform-preflight-2/chain-capture.json` | Teste de 202 ms, sem acertos, armação e desarme confirmados | Timeout sem evidência de ausência global |
| `session2-cl-transform-round-1/chain-capture.json` | Antes/depois do XOR confirmados; 490 ms totais, 28 ms após entrar no trecho; 36 traps e 33 escritas retidas; depois parou em candidata `+0x256B66 add byte ptr [ebx],al` | Não alcançou a carga de CL; 17 escritas posteriores ao XOR impedem atribuir diretamente seu resultado ao consumidor |
| `session2-cl-writer-round-1/chain-capture.json` | Teto de 64 escritas em 397 ms, 63 retidas, sem alcançar a carga; mesmo EBP da origem revalidada | Janela incompleta por limite; não confirma último escritor nem exclui uma carga posterior |
| `session2-cl-writer256-round-1/chain-capture.json` | Após autorização explícita de até 256 escritas: 129 escritas, 142 traps, 13 pontos da cadeia, 349 ms totais e 10 ms de sequência; sem perdas/erros | Última escrita com única candidata `+0x1C70DC pop dword ptr [edx]`, ainda sem execução antes/depois dessa instrução |

**OBSERVADO:** breakpoint de execução antes e depois de `+0x2689FB` preservou ECX
como endereço do operando, EDX e a dword anterior/posterior. O endereço coincidiu
com `EBP+0x36`, offset observado zero dentro do operando; EDX não era zero e houve
mudança do valor. O pós-valor coincidiu com `antes XOR EDX`, mantendo ECX, EDX, ESP,
EBP e thread. Essa é uma transformação local de quatro bytes efetivamente
executada, com escrita na posição investigada. **NÃO VERIFICADO:** que esse XOR
seja cifragem de pacote, geração de fluxo ou atualização de estado criptográfico.
A própria captura contém escritas posteriores, sem uma carga consumidora retida.

A região de código desse XOR era executável anônima. A primeira checagem a recusou
por exigir associação direta ao arquivo; duas inspeções de diagnóstico e aquela
tentativa terminaram antes da armação. A implementação passou a conferir os
cabeçalhos DOS/PE32 e `SizeOfImage` da base identificada, os limites da imagem, a
permissão de execução e a instrução exata. O teste vivo acima ocorreu somente
após essas verificações. Os diagnósticos privados não contêm stack completa.

O inventário de escritores aceita somente famílias já encontradas neste recorte
(`mov`, `pop`, `xor`, `add`), preservando alternativas de decodificação e sem
promovê-las a caminho executado. A prova antes/depois do XOR é separada da
associação com CL no analisador. Todas as tentativas desta subseção terminaram
com limpeza confirmada; não houve chamadas nativas nem alteração do relay.

**OBSERVADO — associação por watchpoint:** na rodada de 256, o byte da última
escrita observada coincidiu com o byte baixo carregado e posteriormente escrito
por CL; thread e EBP coincidiram. O arquivo tem 72.449 bytes, abaixo do teto de
256 KiB. O teto anterior impedia alcançar o consumidor; a ampliação foi autorizada
somente após demonstrar esse impedimento, mantendo 10 s e 1.000 eventos.
**INFERIDO:** `+0x1C70DC pop dword ptr [edx]` é o escritor candidato relevante nessa
ocorrência. **NÃO VERIFICADO:** a transferência antes/depois do POP e a origem
anterior do operando na pilha; a candidata reversa não equivale a execução provada.

Próximo experimento preparado: `--mechanism cl-producer`, com breakpoint antes e
depois do POP, EDX preservado como endereço de destino, somente a dword em ESP como
operando e validação de ESP posterior (`ESP+4`), seguido da carga→CL→store. Sem
watchpoint de stack, sem stack completa, sem chamadas nativas. O teste vivo de
200 ms (`session2-cl-producer-preflight/`) armou/desarmou com sucesso, sem acertos;
as revisões seguintes de diagnóstico ainda só possuem teste offline. Uma inspeção
reversa limitada encontrou alternativas antes do POP; nenhuma virou caminho executado.

A manutenção habitual de `docs/` passa ao Documentador conforme
`research/COORDINATION.md`. Continuação operacional, limites e evidências novas
ficam em `research/cipher/STATE.md` e `research/cipher/HANDOFF.md`; não substituir
este resultado por observações ainda não integradas. A limpeza das rodadas acima
foi confirmada. O checkpoint offline desta transferência é registrado no handoff.

## Transformação final do 035F = XOR in-place byte a byte (registro canônico)

**FATO/OBSERVADO na implementação do relay (decisão do responsável, 2026-10-15).** A transformação
**final** aplicada ao corpo do `035F` antes do envio é um **XOR in-place, byte a byte**, no store do
scrambler do cliente (`gepard+0x18eff2`). O relay já depende desse comportamento: a função de scramble
substitui o corpo do `035F` pelo pacote do consumidor **antes do XOR** e deixa o próprio cliente
cifrar e enviar. Fontes no código: `agent/relay_hook_linux.js:224-233` e a escrita em `:518`
(`bodyp.writeByteArray(body)` — "overwrite plaintext; the in-place XOR encrypts ours");
`relay/writeback.py:4-6` (merge no ponto de cifragem, "antes do XOR em memória, no breakpoint de
execução DR0"); `relay_capture.conf:99-111` (`scramble-bp=18eff2`, `scramble-range=2632000-2730000`,
`scramble-id=035f`). Conecta-se ao `store_035f` da trilha de movimento em
[MOVEMENT_035F_PRECONDITIONS §13.8](MOVEMENT_035F_PRECONDITIONS.md).

**Limite explícito — o que continua DESCONHECIDO.** Saber que a operação final é um XOR byte a byte
**não** resolve a cifra. A função geradora e tudo o que **antecede** o XOR permanecem essencialmente
desconhecidos: **fluxo de chave / keystream**, **estado criptográfico** e sua evolução,
**inicialização / seeds**, direção, identidade e fronteira do pacote, e os vetores independentes. O
XOR observado dinamicamente em `+0x2689FB` (seção *Nova instância*) é uma transformação local de quatro
bytes **não atribuída** a essa cifra final — não confundir cópia/transporte de byte nem um XOR local
com a operação geradora do keystream. A classificação da cifra permanece **C** (não reconstruída).

## Integração documental — CIFRA-20261016-POP-03

**Transferência:** CIFRA liberou os quatro documentos compartilhados no
[HANDOFF](../research/cipher/HANDOFF.md), preservado com CL-01, WRITER-02 e POP-03.
Esta edição acrescenta a rodada; os diffs anteriores e o histórico de candidato POP
continuam preservados. Conferência de artefatos em 2026-10-16; nenhuma coleta nova.

**Pergunta discriminante:** a última escrita candidata de WRITER-02 foi realmente
`gepard+0x1C70DC: pop dword ptr [edx]`, e seu byte chegou à carga de CL na mesma ocorrência?

**OBSERVADO NO ARTEFATO:**
`/tmp/ro-cipher-20261016T061947Z/pop-click-1/capture/chain-capture.json`,
`DONE.cl_producer`, `DONE.cl_preceding_write` e `DONE.cl_origin`. Há pontos antes/depois
do POP: dword de ESP igual ao valor de destino depois, EDX estável, ESP acrescido de 4,
thread/EBP preservados. A carga `+0x1C7502` e os 13 pontos até depois de
`+0x1C752B mov [esi],cl` seguem na mesma ocorrência. As igualdades de cópia, incremento
ESP e byte baixo foram recalculadas sem exportar endereços ou valores privados.
`audit_chain` retorna `POP_COPY_CONFIRMED`, `linked_to_cl_load=true` e
`CL_LOAD_AND_STORE_CONFIRMED`. São verificações de consistência **da mesma captura**,
não repetição independente do experimento ou autenticação externa dos instrumentos.

**Cobertura:** 15 traps, uma escrita observada, 13 pontos de cadeia, 43 ms totais/12 ms
na sequência; contadores `read_errors=0` e `discontinuities=0`, sem teto atingido.
O watchpoint cobre um byte/uma thread: não excluir outros escritores fora da cobertura.
A origem é resolvida no hit atual, não reutilizada como endereço de heap da sessão antiga.
Build/revisão de instrumentos constam do handoff e dos metadados da captura; a revisão
atual do código não é atribuída retroativamente às coletas CL-01/WRITER-02.

**Erro tardio e limpeza:** a ordem registrada é `READY → DONE → SCRIPT_ERROR`, com
`TypeError: not a function` depois do resultado. Isso também aparece no artefato
`session2-cl-writer256-round-1` de WRITER-02. CIFRA confirmou a errata: “zero erros”
descreve os contadores de leitura/ordem, não todos os eventos. A versão executada
registrou apenas a descrição, sem linha/stack; chamada exata e impacto tardio continuam
**NÃO VERIFICADOS**. O resultado local anterior não é descartado automaticamente.
`cleanup_confirmed` e `DONE.cleanup.ok` são verdadeiros; em
`pop-click-1/stimulus-summary.json`, `probe_cleanup_confirmed` e
`input_daemon_cleanup_confirmed` também são verdadeiros. Segundo o esclarecimento de CIFRA, `cleanup_confirmed` é marcado pelo host após
RPC stop, unload e detach sem exceção: é autorrelato do mesmo coletor, separado do
`DONE`. Isso registra limpeza dos recursos próprios; não prova saúde global do processo. CIFRA relatou encerramento do
cliente depois, em outra etapa; causa não atribuída a POP-03 por esta integração.

**Estado científico:** o POP deixou de ser apenas candidato reverso nessa ocorrência;
foi confirmada uma **cópia** e sua associação ao consumidor. O XOR de dword de C-06,
com 17 escritas posteriores, continua sem ligação ao byte final. Origem anterior do
operando da pilha, função criptográfica, pacote, direção, estado e inicialização seguem
**NÃO VERIFICADOS**. O recorte PUSH/POP seguinte é proposta, não resultado incorporado.
A cifra permanece sem vetor completo. A confirmação funcional de movimento em MOVER
não fornece os operandos do gerador nem resolve essa lacuna.

## Integração documental — CIFRA STACK-04 … SLICE-12

**Fonte:** `research/cipher/HANDOFF.md` (IDs CIFRA-20261016-STACK-04 a SLICE-12) e `STATE.md`.
Base HEAD `6c20733` com diffs locais; revisão/digest/hashes de cada execução em
`chain-capture.json`. Raiz privada `/tmp/ro-cipher-resume-20261016/` (não versionada). Cada rodada é
uma ocorrência em uma thread, com um byte por alvo; **não** fundir ocorrências nem instâncias
(sessões 1–4 tiveram PIDs/heaps distintos, inventários `inventory-session{2,3,4}.json`).

| ID | Pergunta | Resultado | Classificação |
|---|---|---|---|
| STACK-04 | PUSH/POP candidatos fornecem o operando de CL? | `+1c70d6 push [esi]; push [edx]; pop [esi]; pop [edx]`, 5 pontos/7 relações; ESI==EDX (valor volta ao mesmo endereço); POP ligado à carga e pós-store CL; 18 traps, 13 pontos CL | OBSERVADO; transporte redundante INFERIDO |
| EARLIER-05 | `+0x13A19A pop [ebx]` fornece o valor consumido? | POP pré/pós confirmado, mas 129 escritas intermediárias impedem atribuição ao consumidor; código apareceu 6× na ocorrência | OBSERVADO local; ligação NÃO VERIFICADA |
| SOURCE-06 | Origem de memória das trocas `+0x13A194–+0x13A19A` | operandos distintos: fonte `EBP+0x68` → destino `EBP+0x36` (fonte em mapa anônimo); 102 escritas posteriores impedem ligação causal | OBSERVADO; transporte INFERIDO |
| REPEAT-07 | Última troca selecionada pela execução | 5 trocas; a última lê `EBP+0x57` → `EBP+0x36`; byte preservado em todas as escritas cobertas até CL | OBSERVADO (igualdade, não causalidade) |
| LINEAGE-08 | Quem escreve `EBP+0x57`? | última escrita da fonte = operando do primeiro PUSH; decode único `+0x256889 pop dword ptr [eax]`; `lineage-manual-1` terminou em `unattributed_exception` com decode `+0x2c042f and byte ptr [edi], dl` | OBSERVADO / escritor candidato INFERIDO |
| UPSTREAM-09 | Confirmar `+0x256889` | POP/EAX pré/pós, ESP+4, cópia para `EBP+0x57` (4 traps, 2 ms); CL não retido por desenho | OBSERVADO local |
| SWAP-10 | Origem do POP/EAX (nova instância) | `+0x256883 push [edi]; push [eax]; pop [edi]; pop [eax]`: fonte `EBP+0x36`, destino `EBP+0x57` | OBSERVADO; ciclo 36→57→36 **não** provado (instâncias distintas) |
| SLICE-11 | Dependências sob dois watchpoints | duas coletas pararam em 502 ms sem CL; terceira (gate no 4º hit) só READY; jogo travou e exclusividade foi comprometida por outro agente (relato do responsável) | **INVÁLIDA** para cifra/causa; limpeza pendente restrita àquela instância |
| SLICE-12 | Plano retrospectivo com gate no 4º hit | 73 traps, 20 escritas em +0x36, 14 em +0x57, 2 trocas, 13 pontos CL; plano de 5 escritores `+1C70DC→+28E0A7→+13A19A→+256889→+256809` até fonte `EBP+0x09`, parado em `FIRST_POP_NOT_OBSERVED` | prefixo `+13A194..+13A19A` OBSERVADO; resto HIPÓTESE |

**Estado científico:** a linhagem do byte de CL foi recuada por **transportes** (cópias via pilha)
`EBP+0x09 →(hipótese) … → EBP+0x57 → EBP+0x36 → CL → +0x1C752B`. Nenhuma das etapas demonstradas é
transformação criptográfica. O XOR local `+0x2689FB` (C-06) e o XOR imediato próximo a `+0x256889`
continuam **candidatos estáticos** sem ligação ao byte final. Keystream, estado, inicialização,
pacote/direção e fronteira F permanecem **DESCONHECIDOS**.

**Saúde do instrumento:** `TypeError: not a function` após DONE em várias rodadas. Trocar handler
`null` por callable e evitar RPC stop redundante **não** suprimiram o erro (mitigações REFUTADAS);
desarmar os watchpoints antes do callback adiado foi seguido por LINEAGE-08/UPSTREAM-09/SWAP-10/
SLICE-12 sem SCRIPT_ERROR, mas causalidade NÃO VERIFICADA e sem validação retroativa.
`runtime_health` global segue UNVERIFIED; limpeza de recursos próprios confirmada pelo coletor
(autorrelato), exceto SLICE-11.

**Ferramentas novas:** `research/cipher/candidate_slice.py` (plano offline, sempre HIPÓTESE, até 32
arestas; para em decode ambíguo, primeiro POP ausente, fonte não observada ou byte divergente);
`research/cipher/debug_inventory.py`; limites de `chain_capture.py`/`chain_probe.js`: 10 s de espera,
500 ms de sequência, 1000 traps, 256 KiB, 256 escritas por alvo, 32 trocas, sem watchpoint de stack.
63 testes próprios em `tests/test_cipher_research.py` (PASS segundo o autor; não validam segurança em
cliente compartilhado).

**Próximo recorte (CIFRA):** observar `EBP+0x09` mantendo ligação ao consumidor, no máximo 4 DRs,
sem ampliar a janela de 500 ms; o seletor do 4º hit é experimental, não invariante.

## Valores de cifra recebidos no login — confirmação do responsável

**Conhecimento confirmado pelo responsável em 2026-10-16:** no momento do login,
valores relacionados à cifra são enviados ao cliente. **Procedência:** declaração
direta nesta rodada documental; não foi feita captura ou reprodução independente
para esta afirmação. A ausência de campos identificados nesta documentação não
nega o recebimento informado.

**NÃO VERIFICADO nesta integração:** ID/direção exata do pacote de protocolo,
fronteira login/char/mapa, layout/tamanhos, se os valores constituem seeds, chaves,
parâmetros ou outra entrada, derivação e ponto em que inicializam/alteram estado.
Não associar automaticamente esses valores ao byte de CL/POP-03 ou ao modelo Gepard
2016. Distinguir envio ao cliente, uso na inicialização e consumo na transformação.
Próxima questão delimitada: qual campo recebido chega a qual consumidor/inicializador,
com build, ordem e sessão identificados? Nenhum login/captura foi executado aqui.
