# Investigação da cifra uaRO/Gepard — 2026-10-15


<!-- CIPHER-SPECIALIST-REFERENCES-2026-10-17 -->

<a id="cipher-specialist-20261017"></a>

## Referências especializadas da família Gepard — prioridade vigente (2026-10-17)

### Procedência e alcance epistemológico

**FONTE TÉCNICA ESPECIALIZADA — ALTA CONFIANÇA.** Foram recebidos dois algoritmos reais de **servidores distintos** e uma descrição técnica de como especialistas reconstruíram rotinas Gepard contemporâneas. Os relatos sobre estrutura, variação por servidor e técnica de análise são conhecimento técnico especializado e devem orientar diretamente a pesquisa, não ser tratados como conjectura genérica.

**ALGORITMOS DE REFERÊNCIA FORNECIDOS POR ESPECIALISTA — A e B.** Os exemplos completos estão reproduzidos literalmente abaixo: constantes, inicialização, índice de tabela, operações, ordem, máscaras e corpo do hash. São **variantes reais de referência**, não implementação validada como idêntica ao uaRO.

**PENDENTE DE IDENTIFICAÇÃO NO uaRO.** Ainda não estão demonstrados, para o build investigado, qual variante/arranjo de operações é empregado, quais constantes e seeds lhe correspondem, como se parametrizam as unidades de envio/recepção/sincronização, quais eventos inicializam ou reinicializam o estado e quais bytes do login alimentam esses campos. Isso delimita a aplicabilidade dos exemplos, **sem diminuir sua confiabilidade como referências**.

As variantes foram informadas como representantes de **versões atuais do Gepard**. Entre servidores, a família conserva semelhança matemática, mas diferenças podem atingir **ordem e dependência de operações**, além de constantes e seeds. A informação especializada afirma que seeds/valores de inicialização ficam acessíveis na memória e que as operações de cifra são protegidas por virtualização **VMProtect**. Um pesquisador especializado teria recuperado operações virtualizadas com instrumentação de **hypervisor**, análise de entradas/saídas e *templates* de operações aritméticas/lógicas (`+`, `-`, `*`, `/`, `%`, `^`); foi relatado um fluxo de ferramenta que identifica essas transformações em cerca de **dois minutos**. Esse tempo é desempenho atribuído à ferramenta especializada, **não prazo ou benchmark reproduzido** neste projeto. A aplicação exata dessas técnicas ao build uaRO, em um ponto de execução específico, continua por localizar.

**Mudança estratégica:** identificar **variante, constantes, seed, estado e eventos de transição** de uma família matemática concretamente descrita é agora a linha prioritária, sem exigir como pressuposto a desvirtualização integral da DLL. A linhagem anterior CL/POP/STACK/SLICE permanece evidência observada de *transporte* e de store final, não evidência de identificação da função geradora.

### Variante A — transcrição integral da referência

O bloco a seguir foi preservado **literalmente**, inclusive o identificador inicial `ngt`, o marcador `ALGORITHM_DATA_HASH: None` e os dois `DATA_HASH_CONST_*`. **Não** deduzir desse par de constantes que uma função hash estivesse ativa: o próprio exemplar indica `None` nesse campo.

````text
ngt
#define SESSION_CONST_1 0xB9028DC4
#define SESSION_CONST_2 0xF1359265

#define ALGO_KEY_1 0x0F
#define ALGO_KEY_2 0x64
#define ALGO_KEY_3 0xBE

#define DATA_HASH_CONST_1 0xBED5C268
#define DATA_HASH_CONST_2 0x3B060DE6


--------------------------------------------------------------------------------
ALGORITHM_DATA_HASH:
--------------------------------------------------------------------------------
None


--------------------------------------------------------------------------------
ALGORITHM_UNIT_INIT:
--------------------------------------------------------------------------------
# Initialize unit keys
for i in range(256):
    valueA = (session_const_1 * seed) & 0xffffffff
    valueB = (session_const_2 * i) & 0xffffffff
    seed = ((valueA + valueB) & 0xffffffff)
    seed &= 0xffffffff
    keys[i] = (seed >> 7) & 0xff
# Initialize unit positions
pos1 = seed % 20
pos2 = seed % 30
pos3 = seed % 50

--------------------------------------------------------------------------------
ALGORITHM_UNIT_ENC_DEC:
--------------------------------------------------------------------------------
for i in range(data_length):
    pos1 = (pos1 + ((keys[pos3] - ALGO_KEY_1) & 0xFF)) & 0xFF
    keys[pos3] = (keys[pos3] ^ pos1) & 0xFF
    pos2 = (pos2 - ((keys[pos3] * ALGO_KEY_2) & 0xFF)) & 0xFF
    keys[pos1] = (keys[pos1] ^ pos2) & 0xFF
    pos2 = (pos2 - ((pos3 * ALGO_KEY_3) & 0xFF)) & 0xFF
    data[i] ^= keys[pos1]
    data[i] &= 0xff
    pos1 = (pos1 ^ ((pos3 + (data_length % 0xFF)) & 0xFF)) & 0xFF
    pos3 = (pos3 + 1) & 0xFF
````

### Variante B — transcrição integral da referência

Preservados os tipos e expressões tal como recebidos. O `#define DATA_HASH_CONST_1` traz **duas alternativas** (`0x6C6FFD4F`, `0xEC6FFD4F`), sem uma escolhida; é um **trecho de referência**, não código C++ autocontido/compilável tal como transcrito. Não escolher implicitamente uma dessas alternativas. A função de hash da Variante B está presente como código de referência, sem comprovação de que corresponda à rotina usada no uaRO.

````cpp
#define ALGO_KEY_1  0x13
#define ALGO_KEY_2  0xA1
#define ALGO_KEY_3  0x58

void gepard_enc_dec( unsigned char* data, std::uint32_t data_size, struct gepard_crypt_unit* unit)
{
    for ( unsigned int i = 0; i < data_size; ++i )
    {
        unit->pos_1 += unit->key[ unit->pos_2 ] - ALGO_KEY_1;
        unit->key[ unit->pos_3 ] ^= unit->pos_1;
        unit->pos_2 += unit->key[ unit->pos_3 ] * ALGO_KEY_2;
        unit->key[ unit->pos_1 ] ^= unit->pos_2;
        unit->pos_2 += unit->pos_1 * ALGO_KEY_3;
        data[ i ] ^= unit->key[ unit->pos_1 ];
        unit->pos_1 ^= unit->pos_2 + (data_size % 0xFF);
        unit->pos_3++;
    }
}

#define SESSION_CONST_1 0xE746213E
#define SESSION_CONST_2 0x68D5E061

void gepard_session_unit( unsigned int seed, struct gepard_crypt_unit* unit, unsigned int SESSION_CONST_1, unsigned int SESSION_CONST_2 )
{
    unsigned int i;

    for ( i = 0; i < 256; ++i )
    {
        unit->key[ i ] = ( ( ( seed = seed * SESSION_CONST_1 + SESSION_CONST_2 * i ) >> 10 ) & 0xFF );
    }

    unit->pos_1 = seed % 20;
    unit->pos_2 = seed % 30;
    unit->pos_3 = seed % 50;
}

#define DATA_HASH_CONST_1 // Any possibility: 0x6C6FFD4F, 0xEC6FFD4F
#define DATA_HASH_CONST_2 0x592926D2

unsigned int gepard_get_data_hash(const unsigned char* data, unsigned int data_size)
{
    unsigned int i, result_hash = DATA_HASH_CONST_1;

    for (i = 0; i < data_size; ++i)
    {
        result_hash = result_hash * DATA_HASH_CONST_2 + data[i];
    }

    return result_hash;
}
````

### Diferenças estruturais que não podem ser normalizadas

| Aspecto | Variante A | Variante B | Consequência investigativa |
|---|---|---|---|
| Geração da tabela `key[0..255]` | `seed=(C1*seed+C2*i)&0xffffffff`, byte `(seed >> 7)&0xff` | atribuição com aritmética de `unsigned int`, byte `(seed >> 10)&0xFF` | Shift e constantes específicos; **não** trocar só constantes |
| Posições iniciais | `seed % 20`, `% 30`, `% 50` | Mesmo conjunto de módulos | Semelhante, mas insuficiente para provar equivalência |
| Atualização de `pos1` | `pos1 += keys[pos3] - K1` | `pos_1 += key[pos_2] - K1` | Dependência de índice **distinta** |
| Primeira mutação de tabela | `keys[pos3] ^= pos1` | `key[pos_3] ^= pos_1` | Mesma forma textual, porém posições/estado anteriores diferem |
| Atualização inicial de `pos2` | **subtrai** `keys[pos3]*K2` | **soma** `key[pos_3]*K2` | Sinal da operação muda |
| Atualização posterior de `pos2` | **subtrai** `pos3*K3` | **soma** `pos_1*K3` | Operando e sinal diferentes |
| Aplicação ao dado | `data[i] ^= keys[pos1]` e máscara de 8 bits | `data[i] ^= unit->key[unit->pos_1]` | XOR em ambas; tipo efetivo de posições em B requer definição da struct |
| Realimentação | `pos1 ^= pos3 + (data_length % 0xFF)` | `pos_1 ^= pos_2 + (data_size % 0xFF)` | Dependência de posição **distinta** |
| Hash | `ALGORITHM_DATA_HASH: None`, apesar de constantes nomeadas | Rotina polinomial com `DATA_HASH_CONST_2=0x592926D2`; `CONST_1` ambígua | Não atribuir hash ativo à A nem escolher hash inicial da B |

O exemplar A explicita máscaras `& 0xFF` para as posições. Na Variante B, a largura/narrowing de `unit->pos_*` depende da declaração de `struct gepard_crypt_unit`, **não fornecida**. Para criar vetores offline fiéis, fixar a semântica de tipos/truncamentos antes de equiparar resultados, registrar versão da interpretação e não reescrever os trechos originais. Valores de seed e corpos de referência devem ser **sintéticos**, sem capturas de sessão reais.

### Modelo-alvo, prioridades e critério de identificação

**Família de trabalho prioritária:** tabela mutável de 256 bytes, três posições de estado, inicialização a partir de seed e constantes, operações por byte, XOR de dados, dependência do comprimento e possível persistência do estado. Separar **constantes do servidor/variante**, **seed por sessão**, **estado derivado**, **unidade/direção (envio, recepção, sincronização)** e **gatilhos de reinicialização**. Nem identidade de unidades nem persistência estão demonstradas para uaRO.

1. **Comparação estrutural offline:** desenvolver vetores de referência para A e B, documentando seed sintética, dados, comprimento (incluindo 0, 1 e limites próximos de 255), resultado, posições e tabela antes/depois, largura aritmética e hipóteses de tipo da Variante B. **Planejamento; não executado nesta revisão.**
2. **Assinaturas discriminatórias no uaRO:** buscar, quando houver janela de pesquisa aprovada, a ordem efetiva de leitura/mutação das três posições e da tabela, a direção das somas/subtrações, o deslocamento na inicialização e a fonte do termo de comprimento. Capturas de CL por transporte não isolam por si tais estruturas.
3. **Parâmetros do login:** está **confirmado pelo responsável** que valores relacionados à cifra chegam ao cliente durante login; a proposta de que sejam seeds específicas desta família é **HIPÓTESE DE CORRESPONDÊNCIA**, não a observação do campo. Exigir ID, direção, fase, layout, sequência e consumo/inicializador, **sem capturar credenciais**.
4. **Estado e ciclo de vida:** observar se a tabela/posições evoluem continuamente por unidade, por direção e por sessão; identificar reset, relogin, negociação e eventos de sincronização. Um valor em memória não prova que é a seed inicial; distinguir a seed de estado já derivado.
5. **Validação entre variantes:** antes de declarar que um algoritmo de referência representa uaRO, confrontar **mais de um vetor independente** e o estado antes/depois, com build e sessão definidos, incluindo comprimentos diferentes, reconexão e controle da direção. Sem isso, classificação **PENDENTE DE IDENTIFICAÇÃO**.
6. **`0x8280`:** conservar análise de sync periódico e unidades separadas de inicialização/sincronização como **dependência da cifra para xKore 0**, sem afirmar que seja preâmbulo obrigatório de ações ou chave da sessão.

**Comparação com `resources/`:** a árvore de arquivos versionados de `main` revisada nesta atualização **não contém uma pasta `resources/`** com código-fonte para esse cotejo. Qualquer fonte presente apenas localmente/ignorada precisará ser fornecida/referenciada antes da análise; não foram inferidos seus conteúdos. Há documentação histórica Gepard 2016 em [HISTORY/GEPARD_LEGACY.md](HISTORY/GEPARD_LEGACY.md), cuja equivalência com o build atual continua não demonstrada.

### Perguntas técnicas ainda discriminatórias

- Há seed independente por unidade criptográfica ou por direção?
- Os valores recebidos no login são seeds, parâmetros de derivação ou estado já inicializado? Qual campo chega a qual rotina consumidora?
- Estado/tabela/posições são contínuos entre pacotes? Quais eventos reinicializam cada unidade?
- A ferramenta especializada reconstrói a sequência/dependências completas ou classifica uma seleção de templates com parâmetros? A descrição disponível favorece reconstrução de função por templates, **sem especificação instrumentada da ferramenta**.
- As rotinas hash/autenticação são usadas, quando, e com quais parâmetros? Em B, qual das duas constantes iniciais possíveis se aplica?
- Qual a declaração da struct e a semântica de truncamento em B? Que diferenças de build/servidor condicionam a variante?

**Mapa de leituras:** [RESEARCH_STATUS.md](RESEARCH_STATUS.md) (prioridade executiva), [research/cipher/STATE.md](../research/cipher/STATE.md) (último recorte executado), [research/cipher/HANDOFF.md](../research/cipher/HANDOFF.md) (próxima tarefa), [GEPARD_CONTROL_PACKETS.md](GEPARD_CONTROL_PACKETS.md) (controle, login, sync). Novos ensaios não foram realizados nesta edição documental. O corpus anterior, inclusive os negativos, segue preservado integralmente nas seções abaixo e nos arquivos históricos.

---
**Estado 2026-10-17:** esta é a **única linha de pesquisa ainda aberta**, por decisão do responsável; movimento `035F` e ações automáticas `0437/0438/0AF4` estão funcionais. O bug de byte zero no merge do Frida foi corrigido por `_fix0` (`agent/relay_hook_linux.js:481-534`), **sem** identificar o produtor de keystream, estado de sessão ou inicialização. Não confundir correção local dos bytes com descoberta do algoritmo. [Conclusão funcional](HISTORY/ACTIONS_COMPLETE.md#source-docs-action-0437-0438-investigation-md).

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
[Fingerprint e limites](CIPHER_INVESTIGATION.md#original-docs-protection-fingerprint-die-md).

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
diagnósticos estão em [CIPHER_TOOLS.md](CIPHER_INVESTIGATION.md#original-docs-cipher-tools-md). Os únicos bytes/estados colocados
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

Relato paralelo recebido ao encerrar as coletas: antigo `docs/MOVEMENT_035F_PRECONDITIONS.md:129` (cópia integral em [HISTORY/MOVEMENT_COMPLETE.md](HISTORY/MOVEMENT_COMPLETE.md#source-docs-movement-035f-preconditions-md))
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
[MOVEMENT_035F_PRECONDITIONS §13.8](HISTORY/MOVEMENT_COMPLETE.md#source-docs-movement-035f-preconditions-md).

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

---

# Manuais técnicos incorporados (2026-10-17)

Os arquivos originais de ferramentas e fingerprint de proteção foram incorporados **integralmente** aqui, com preservação de origem. O estado atual permanece definido nas primeiras seções científicas; conteúdo histórico não prova equivalência entre builds.


<a id="original-docs-cipher-tools-md"></a>

## Apêndice preservado integralmente: `docs/CIPHER_TOOLS.md`

> Fonte original incorporada sem cortes — blob `0021f489ba1be71e412c13680e5364112fd298c8`, base `b35042ef1b84434889cb1eeb602393ec3ddb7be8`. Os links internos desta fonte mantêm a procedência histórica.

<!-- BEGIN ORIGINAL docs/CIPHER_TOOLS.md -->
# Ferramentas de análise e coleta da cifra

Esta ferramenta inventaria dados **já capturados no cliente**. Não implementa
uma cifra uaRO, não adivinha estado inicial, não conecta à rede e não importa
Frida. A inspeção Gadget opcional está separada em `inspect_client.py`.
O coletor de dependências executadas, também opcional, está em `chain_capture.py`.

```bash
umask 077
cipher_out=$(mktemp -d /tmp/ro-cipher-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX)
python3 research/cipher/analyze.py \
  --input research/cipher/fixtures/synthetic_calls.jsonl \
  --out "$cipher_out"
```

Repita `--input ARQUIVO` para cada fonte explícita. Há no máximo 64 arquivos,
4 MiB por arquivo por padrão e 10.000 registros/eventos por arquivo. A opção
`--max-input-bytes` permite um teto explícito de até 64 MiB; `--max-records` reduz
o teto de eventos. Nenhuma busca de arquivos ou associação entre fontes ocorre.

`inventory.json` registra caminho/proveniência, SHA-256, campos disponíveis e
ausentes, exclusões, grupos conhecidos, contagens e três hipóteses. Conteúdo
duplicado é identificado, mantendo as fontes separadas. `missing-data.json`
resume os dados faltantes. Arquivos grandes/ilegíveis/malformados produzem
diagnóstico seguro com erro; se não foi possível ler integralmente, o hash fica
desconhecido. Não há hash fictício de arquivo inteiro a partir de um prefixo.

O diretório deve ser novo ou privado (0700), sem arquivos de saída anteriores.
Os relatórios são criados exclusivamente com 0600; nunca sobrescrevem entradas
ou relatórios. A saída do terminal contém somente contagens e classificação.
Não publique relatórios de entradas reais: caminhos e metadados permanecem privados.

## Formatos realmente usados

- JSON das sondas anteriores: contêiner `events`, metadados `modules`, `coords`,
  `ack0087` e referências de instruções. Coordenadas não viram bytes de pacote.
- JSON/JSONL de eventos `SEND`, `SEND-PLAIN`, `HIT`, `SCRAMBLE` e `CODE_PREFLIGHT`.
  Somente os IDs de ação 035F/0437/0438, com comprimento/header coerentes, entram
  no inventário de bytes. Login/HTTP e outros IDs são excluídos. Um socket pode
  transportar fragmentos ou vários pacotes: o analisador não procura IDs no meio
  do buffer para tentar resincronização.
- JSONL normalizado `ro-cipher-evidence-v1`: cabeçalho e observações tipadas,
  ilustrados integralmente pelo fixture **exclusivamente sintético**.

No formato normalizado, `input_hex`, `output_hex`, `xor_operand_hex` e snapshots
podem faltar explicitamente. `call_index` e `stream_offset` desconhecidos ficam
`null`; `boundary` é `complete` apenas com prova de entrada/saída da transformação.
`complete=false` preserva uma captura parcial sem considerá-la completa.
`session`/`connection` são aliases locais; direção, unidade e época separam fluxos.
Não há associação entre arquivos com aliases/endereços coincidentes.

`state_layout`, quando informado, contém `table_offset`, `table_length` e
`position_offsets`, relativos à região observada. O programa verifica limites;
o chamador precisa demonstrar que a região é o estado consumido. Uma janela
alinhada a EBX não recebe automaticamente esse rótulo.

## Interpretação dos resultados

Um par P/C de mesmo tamanho sempre admite um delta `P XOR C`. Somente um operando
XOR observado independentemente permite conferir essa operação no recorte.
Mesmo assim, isso não demonstra geração do fluxo, inicialização ou recorrência.
Campos `P` de eventos legados e janelas de watchpoint mantêm origem não verificada;
não são alinhados com outros arquivos por tempo ou endereço.

O analisador conta mudanças de estado e continuidade somente dentro do mesmo
fluxo, com fronteiras completas e offsets consecutivos. Um marcador de perda
interrompe conservadoramente todas as associações anteriores no arquivo. Capturas
parciais não sustentam continuidade. Não é preenchido nenhum byte ausente.

Quando há layout explícito, comparações descritivas incluem padrão `rol8(i,2)`,
pares adjacentes alterados e incrementos modulares de 1/33 por byte/palavra
arredondada para baixo/cima. São diagnósticos de alegações históricas, não ajuste
de algoritmo. Padrão de memória ou dois bytes adjacentes mudados não demonstram
identidade de estado nem instruções de 16 bits.

O resultado atual é `C_INSUFFICIENT`; a ferramenta não tem candidato de cifra nem
fallback decrypt. Os testes sintéticos validam o diagnóstico, não a cifra do jogo.

```bash
python3 tests/test_cipher_research.py
```

## Inspeção de código opcional e separada

`inspect_client.py` requer inventário previamente autorizado, com exatamente um
alvo/listener, hashes e mapeamentos. Revalida processo/hashes e resolve a base do
módulo no Gadget. O RVA histórico só é aceito com a instrução esperada executável.
Uma janela de 200 ms lê código por `Instruction.parse`, até oito predecessores
locais, parando em ambiguidade/desvio. Decodificação reversa **não** demonstra
execução ou dominância de instruções.

Essa inspeção não instala handler, breakpoint, Stalker ou hooks de transporte;
não lê stack, objetos, corpos ou estado. Operações Frida têm cancelamento e
limpeza limitados. Os doubles cobrem timeout, erro, interrupção e teto de eventos,
sem provar segurança no cliente. Essa inspeção não coleta vetores criptográficos.

## Continuação dinâmica: dependências de um byte

`chain_capture.py` é um instrumento separado do relay. Exige inventário autorizado,
exatamente um alvo/listener, confirmação humana de exclusividade e hashes compatíveis.
A ausência de um driver não estabelece exclusividade. Não provoca ações nem remove
instrumentação de terceiros. Antes de nova rodada, coordenar a disponibilidade do cliente.

```bash
python3 research/cipher/chain_capture.py --help
```

Frida é importado apenas ao executar a coleta. Usar o ambiente existente com Frida;
`analyze.py` e seus diagnósticos continuam sem Frida, cliente ou rede.

| `--mechanism` | Evidência visada / entradas adicionais |
|---|---|
| `stalker` | Cinco pontos carga→store, thread principal, até 500 ms; contadores de tradução/entrada distinguem falta de cobertura de falta de acerto |
| `breakpoint` | Um breakpoint de execução próprio, rotativo pelas cinco instruções; espera limitada por `--arm-timeout-ms`, sequência até 500 ms |
| `writer` | Um watchpoint de escrita de 1 byte na origem comprovada; `--source-capture` |
| `producer` | Antes/depois de `mov [ebx],ecx`, depois carga→store; acrescentar `--producer-capture` |
| `operand` | Confirmar `movzx ecx,al`; acrescentar `--operand-capture` com a decodificação candidata |
| `load` | Confirmar `mov al,[eax]` e seis instruções contíguas; acrescentar `--load-capture` com o grafo limitado |
| `byte-writer` | Mover o watchpoint para a origem realmente lida por EAX; acrescentar `--value-capture` |
| `byte-producer` | Confirmar antes/depois de `mov [esi],cl`; acrescentar `--byte-producer-capture` |
| `cl-origin` | Confirmar `mov ecx,[ecx]` em `+0x1C7502` e o trecho contíguo até depois de `mov [esi],cl`; exige `--cl-code-input` para cada inspeção de código |
| `cl-writer` | Observar escrita de 1 byte na origem de CL e a carga consumidora na mesma rodada; acrescentar `--cl-source-capture` de um `cl-origin` completo |
| `cl-transform` | Observar antes/depois de `xor dword ptr [ecx],edx`, seguido de carga→CL→store; acrescentar `--cl-writer-capture` com o único predecessor candidato do watchpoint, da mesma instância |
| `cl-producer` | Confirmar `pop dword ptr [edx]` antes/depois e a cadeia consumidora; acrescentar `--cl-writer-capture` completo com essa única candidata de última escrita |

Todos os modos requerem `--inventory ARQUIVO --out DIRETORIO --exclusive-confirmed`.
Modos com breakpoint exigem `--selection any-chain`: não atribuem identidade de pacote.
Os modos posteriores também exigem as entradas das etapas anteriores. São recortes
específicos das instruções observadas neste build, não um tracer genérico ou cifra.
Um endereço observado anteriormente só é usado após validar build, código e mapeamento.
Os modos `cl-origin`/`cl-writer`/`cl-transform`/`cl-producer` usam o inventário atual e inspeções explícitas do
mesmo processo/build, sem depender das capturas das oito etapas antigas. Isso não
estabelece continuidade de sessão criptográfica. Antes de definir CL pela carga,
ECX é salvo como endereço efetivo; ESI também é preservado antes de carregar o
ponteiro de destino. O caminho candidato é revalidado e cada instrução é observada.
Watchpoints são recusados se a região contiver ESP de qualquer thread enumerada ou
se faltar o contexto necessário para essa verificação. Isso não identifica estado criptográfico.

`--inspect-only` lê metadados de código e não arma instrumentos. Seu resultado
`code_only` não é prova de execução. O grafo reverso considera no máximo 32 arestas,
64 bytes e 200 ms, interrompendo ao atingir limites; alternativas não são caminhos executados.
`--inspect-cl-origin` requer `--inspect-only` e examina predecessores de
`+0x1C752B`. `--cl-code-anchor-rva` permite retomar uma fronteira encontrada dentro
dos mesmos 64 bytes anteriores, sem ampliar a região; no máximo quatro arquivos
de código entram por `--cl-code-input`. Capturas conflitantes são rejeitadas.
`cl-writer` recusa regiões de stack, aguarda uma escrita na posição comprovada e
associa somente a próxima carga correspondente na mesma captura. Leituras anteriores
sem escritor observado são contadas separadamente. O watchpoint vê só o byte baixo,
sem demonstrar quem escreveu os outros três bytes da dword ou excluir outras threads.
`cl-transform` revalida cabeçalhos/limites PE, região executável e instrução exata;
uma seção executável anônima só é aceita dentro da imagem identificada. Preserva
ECX como endereço, EDX e quatro bytes do operando antes/depois do XOR. A região do
operando também precisa estar fora dos mapeamentos de ESP enumerados na preparação.
O watchpoint continua limitado a um byte e uma thread. Uma escrita posterior antes
da carga impede atribuir o byte carregado ao XOR observado. Sem associação completa,
o analisador conserva a prova local da operação separada da cadeia consumidora;
um XOR de memória não identifica por si só cifragem, fluxo ou estado criptográfico.
`cl-producer` preserva EDX antes da escrita e lê somente a dword em ESP usada pelo
POP. Confere a cópia, EDX e ESP posterior (`ESP+4`), sem watchpoint de stack. Uma
inspeção limitada de predecessores do escritor permanece separada da prova viva.
`--producer-only`, exclusivo de `byte-producer`, encerra após a escrita confirmada,
sem associá-la a uma leitura posterior. Observações parciais são preservadas separadamente.

Limites: sequência até 500 ms, espera até 10 s, até 1.000 traps/visitas, padrão de 64 escritas
e arquivo até 256 KiB. O evento que alcança o teto interrompe a completude da coleta.
`--cl-write-cap` permite até 256 em modos CL com watchpoint; ampliar o padrão exige
escopo humano confirmado. A possibilidade no CLI não constitui autorização.
Os timers não são de tempo real; os tempos efetivos ficam no artefato. Cada trap retoma
a thread, sem suspendê-la pela duração da janela. A preparação (`--start-delay-ms`, até 5 s)
ocorre antes da armação. Timeout/erro/interrupção desarmam somente os recursos próprios.
O driver faz até três tentativas de desarme e recusa unload/detach explícitos se não
obtiver confirmação; `CLEANUP_PENDING` exige interromper as rodadas e coordenar a limpeza.

`chain-capture.json` é privado: contém os endereços efetivos anteriores às cargas,
valores estritamente necessários, ordem, contexto, mapeamentos e confirmação de limpeza.
Não inclui stack completa, login, corpos de socket ou estado criptográfico identificado.
Não publique esse arquivo. A seleção histórica `movement-header` é somente um filtro;
sua ausência não refuta o caminho e seu acerto não prova uma fronteira de cifra.

Reanálise offline de um artefato explicitamente escolhido:

```bash
python3 research/cipher/analyze.py --input "$captura_privada" --out "$saida_privada_nova"
```

`chain_audit.py` recalcula igualdades e fornece `COPY_CHAIN_CONFIRMED` apenas para
o recorte carga→store admissível. Registra separadamente cópias intermediárias,
extensão com zeros, origem do byte e escritor independente. Não exporta valores de
registradores ou memória. Capturas permanecem separadas por fonte; mesmo endereço,
build ou frame não cria sessão criptográfica nem par P/C. `C_INSUFFICIENT` continua
sendo o resultado quanto à cifra, com direção/sessão desconhecidas e zero chamadas completas.

Os doubles JS exercitam ordem, endereço anterior à carga, isolamento de contexto,
desarme, timeout, erro de armação, cobertura, tetos e as etapas antes/depois.
São exclusivamente sintéticos e não provam segurança no cliente. Node existente é
usado nesses doubles; sem Node, esse teste específico é marcado como skip.

## Localização e escopo operacional

Comandos deste manual são relativos à raiz do repositório. Coleta/inspeção viva exige
autorização e exclusividade próprias; esta migração executa somente testes offline.
Conclusões científicas em [CIPHER_INVESTIGATION.md](CIPHER_INVESTIGATION.md).
<!-- END ORIGINAL docs/CIPHER_TOOLS.md -->


<a id="original-docs-protection-fingerprint-die-md"></a>

## Apêndice preservado integralmente: `docs/PROTECTION_FINGERPRINT_DIE.md`

> Fonte original incorporada sem cortes — blob `d725d96f65e3c811db5d24001e05717d1825fe39`, base `b35042ef1b84434889cb1eeb602393ec3ddb7be8`. Os links internos desta fonte mantêm a procedência histórica.

<!-- BEGIN ORIGINAL docs/PROTECTION_FINGERPRINT_DIE.md -->
# Identificação de proteções — Detect It Easy (15/10/2026)

## Proveniência e build

**OBSERVADO E CONFIRMADO PELO RESPONSÁVEL, no Detect It Easy (DiE):**
os próprios arquivos `uaRO.exe` e `gepard.dll` da **build atual,
utilizada nas investigações de movimento `0x035F` e cifra**, foram
submetidos ao DiE. Esta associação de identidade **foi esclarecida
expressamente pelo responsável**, não se trata de extrapolação de uma
build histórica ou de um cliente diferente.

- **uaRO.exe:** Detecção **Themida/WinLicense 3.XX**; PE32, x86 de 32 bits.
- **gepard.dll:** Detecção **VMProtect**, conforme resultado informado
  pelo responsável sobre o arquivo atual; versão exata do VMProtect
  não especificada no material textual.
- **Nível de evidência:** observação estática feita pelo responsável
  nos binários usados no projeto e resultado reproduzido nesta conversa.
  Não se fez uma segunda execução independente do DiE neste trabalho;
  isso **não coloca em dúvida a identidade da build informada**.
- **Limite técnico:** a detecção de um protetor **não identifica quais
  funções concretas estão virtualizadas**, nem as fronteiras de VM
  ou o código executado em uma região de memória.

Hashes **já documentados** dos arquivos atuais da pesquisa
(`docs/CIPHER_INVESTIGATION.md`; valores não extraídos do próprio
texto do DiE):

| Arquivo | SHA-256 da build pesquisada |
|---|---|
| `uaRO.exe` | `f2f25a89917563237bb6faf60058cc536b7f42469af32fba556842f9f0cb9569` |
| `gepard.dll` | `34188e6046eb831f31c0843744c084b56704a765d9e758043a1a1dad6046b08b` |

O responsável confirmou **a identidade dos arquivos usados no DiE com
os arquivos atuais da pesquisa**. Os hashes são referências de build já
existentes na documentação; não foram medidos novamente nesta alteração.

## Saída DiE fornecida para uaRO.exe

| Grupo | Valor comunicado | Interpretação |
|---|---|---|
| DOS | `MS-DOS [8086, 16-bit]` | Stub DOS normal do formato PE; **não** significa aplicativo 16 bits |
| Imagem | `PE32`, `Windows (Vista) [I386, 32-bit]` | PE32/x86; a etiqueta de SO é informação do DiE, não teste de suporte ao Vista |
| Linker | `Microsoft Linker (6.00.8447)` | Metadado identificado pelo DiE |
| Compilador | `Microsoft Visual C/C++ (19.29.30153) [C++]` | Identificação de compilador, sem atribuição de todas as rotinas |
| Ferramenta | `Microsoft Visual Studio (6.0)` | Outra assinatura detectada; não inferir cronologia a partir de rótulos conflitantes |
| Bibliotecas | Direct3D 9, DirectDraw, MSVC Runtime (dynamic), Miles Sound System, RAD Video Tools | Dependências indicadas |
| Assinatura | `Windows Authenticode (2.0) [PKCS #7]` | Presença da estrutura; não constitui verificação de confiança da assinatura |
| Integridade (heurística) | `Generic (Uncritical)`: `Certificate table overlaps image data`; `Malformed certificate table` | Alerta estrutural do DiE, **não** prova de arquivo malicioso |
| Proteção | `Themida/Winlicense (3.XX, Winlicense)` | Identificação do protetor aplicado ao cliente atual |
| Seções (heurística) | `#11 ".winlice"` RWX; seções incomuns; IAT data directory vazia | Compatível com proteção/empacotamento |
| Packer (heurística) | Seções características do Themida 3.x, nomes repetidos, seção `#12 ".boot"` comprimida, imports recorrentes | Características estáticas da imagem protegida |
| Depuração | Registros CodeView, VC Feature, POGO; seção `#5 ".debug"` | Metadados detectados, não garantia de símbolos úteis |
| Recurso: ícone | Offset `0x00f520c8`, tamanho `0x02e8` | Offset de recurso em arquivo, não breakpoint |
| Recurso: ícone | Offset `0x00f523c0`, tamanho `0x14` | Offset de recurso em arquivo, não RVA de função |
| Recurso: manifesto XML | Offset `0x00f523e4`, tamanho `0x0312` | Offset de recurso em arquivo, não endereço executado |

A detecção do DiE para `uaRO.exe` e `gepard.dll` identifica
**dois protetores diferentes na mesma build**, mas não demonstra que
o componente Themida ou o componente VMProtect tenha virtualizado
cada caminho específico já rastreado.

## Consequências para as duas investigações

### Movimento `0x035F`

**OBSERVADO anteriormente:** no caminho natural aparece o dispatcher
`0x11 → 0x0D → 0x5B → 0x8A`; no ensaio nativo exclusivo o
receptor `0x8A` entrou/retornou e não produziu store `0x035F`
ou envio observado na janela. O resultado do DiE confirma a presença
de Themida no executável e VMProtect na DLL dessa **mesma build**.

**INFERÊNCIA:** agora é especialmente importante não atribuir
regiões de código desempacotado/anônimo, trampolins e callsites a
uma VM específica sem observar a origem de execução. Alternativas
incluem código nativo do cliente, rotina Gepard, stub/protetor
e suporte Wine/Proton. **H2 (preparação) e H3 (contexto/callsite)**
continuam hipóteses distintas; a detecção de proteção, por si só,
não resolve qual delas explica a ausência de `0x035F`.
Ver `MOVEMENT_035F_PRECONDITIONS.md`.

### Cifra

**OBSERVADO anteriormente:** escritor `gepard+0x1C752B`
com `mov [esi],cl` e cadeia parcial de transporte até
`gepard+0x18EFF2`. **OBSERVADO via DiE na build atual:**
a `gepard.dll` possui VMProtect. **AINDA DESCONHECIDO:**
a última definição executada de `CL`, função de keystream,
estado consumido, inicialização e fronteiras da transformação.

A ferramenta de desvirtualização VMProtect de Jonathan Salwan
trabalha com traces completos de funções puras, não com os
snapshots seletivos que já foram coletados. Não transferir
automaticamente a metodologia para código Themida, nem presumir
que o gerador de `CL` esteja virtualizado só pela presença
de VMProtect na DLL. Ver `CIPHER_INVESTIGATION.md`.

## Estado desta edição

**Documentação somente.** Sem execução local de DiE, breakpoints,
instrumentação, extração de código, tráfego de rede, instalação
ou modificação de mecanismos de proteção.

**Próximo registro útil:** preservar a versão do Detect It Easy e,
se conveniente, a saída bruta sanitizada para rastreabilidade.
Isso melhora a proveniência, mas **não é requisito para aceitar
a confirmação já fornecida sobre a build utilizada**.
<!-- END ORIGINAL docs/PROTECTION_FINGERPRINT_DIE.md -->
