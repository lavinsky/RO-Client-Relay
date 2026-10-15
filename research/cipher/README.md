# Análise offline de evidências de cifra

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

Todos os modos requerem `--inventory ARQUIVO --out DIRETORIO --exclusive-confirmed`.
Modos com breakpoint exigem `--selection any-chain`: não atribuem identidade de pacote.
Os modos posteriores também exigem as entradas das etapas anteriores. São recortes
específicos das instruções observadas neste build, não um tracer genérico ou cifra.
Um endereço observado anteriormente só é usado após validar build, código e mapeamento.
Watchpoints são recusados se a região contiver ESP de qualquer thread enumerada ou
se faltar o contexto necessário para essa verificação. Isso não identifica estado criptográfico.

`--inspect-only` lê metadados de código e não arma instrumentos. Seu resultado
`code_only` não é prova de execução. O grafo reverso considera no máximo 32 arestas,
64 bytes e 200 ms, interrompendo ao atingir limites; alternativas não são caminhos executados.
`--producer-only`, exclusivo de `byte-producer`, encerra após a escrita confirmada,
sem associá-la a uma leitura posterior. Observações parciais são preservadas separadamente.

Limites: sequência até 500 ms, espera até 10 s, até 1.000 traps/visitas, até 64 escritas
e arquivo até 256 KiB. O evento que alcança o teto interrompe a completude da coleta.
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
