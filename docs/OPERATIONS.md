# Operação e validação

## Inicialização

O cliente autorizado precisa de Frida Gadget 32 bits sob Wine/Proton, Python com
`frida`, acesso de leitura a `/proc/<pid>/mem` e OpenKore externo em xKore 1.
Instalação existente: `./setup.sh` ou `./setup.sh /caminho/do/venv`; recursos
baixados em `relay/resources/` são externos e não devem ser versionados.

```sh
./run.sh
./run.sh --verbose
./run.sh --no-color
./run.sh --no-inject
VENV=/caminho/do/venv ./run.sh
```

`run.sh` executa diretamente o driver, com `--wait` para aguardar sinais sem
pipe/sidecar ou launcher de pesquisa. Ctrl-C/SIGTERM suspende comandos e remove
a instrumentação. CLI direta continua aceitando stdin como controle de duração.
A precedência é defaults CLI → `relay_capture.conf` → argumentos CLI.
`--config` escolhe outro INI. `--out` exige arquivo, não diretório.

A configuração principal preserva **inject=true e inject-call=true** e ativa
movimento, merge de ações e atuador. `scramble-range` vazio reproduz a faixa
sem restrição usada pelo launcher funcional anterior; não é endereço de sessão.
Dispatcher/fire-site e offset de store continuam específicos do build conhecido.
`--no-inject` desativa o recebimento de comandos para execução.

## Cliente, input e conexão

Configure o OpenKore externamente com `XKore 1`, `XKore_port 2350` e listener
`127.0.0.1`. Não inclua credenciais em arquivos publicados. Inicie o pipeline
antes do login para observar o stream completo. Entrar no meio de uma sessão
não garante contexto de login/mapa ou delimitação inicial completa.

Movimento usa captura passiva de contexto: é necessário andar no cliente para
capturar o `this`. SendPacket também requer um contexto natural. Após relogin,
reconexão do consumidor ou troca da conexão de mapa, os ponteiros são invalidados
e precisam de recaptura; ausência de contexto é erro explícito.

O atuador usa `ydotool/ydotoold` (uinput), com foco via
`xdotool windowactivate --sync`. Esses programas devem estar disponíveis; o
relay não inicia daemon privilegiado. Input afeta o desktop real e só pode ser
executado numa rodada especificamente autorizada. Teclas padrão:

| Pacote | Tecla |
|---|---|
| `0437` | INSERT |
| `0438` | 9 da fileira superior |
| `0AF4` | F2 |

`--synth-wid` define a janela; vazio procura o título conhecido. As opções
`--synth-key-0437`, `--synth-key-0438`, `--synth-key-0af4` mudam as teclas.
`--synth-dry` não gera input; não simula consumo do carrier nem prova ações.
A duração de tecla de 120 ms permanece necessária conforme evidência anterior.
Não há debounce ou espera fixa de foco. Próximo comando aguarda consumo/reparo
e liberação da tecla, em qualquer ordem.

OpenKore desconectado significa ponte suspensa. Não há buffer para executar
comandos de sessão anterior. A reconexão limpa framing, pendências e contexto;
a conexão legítima do cliente com o servidor pode permanecer aberta.

## Console, tempos e falhas

Normal é conciso; verbose detalha pacotes sanitizados e correlações locais.
`NO_COLOR`, saída sem TTY e `--no-color` desabilitam ANSI. Arme/chamada nativa
não aparecem como aceitação do servidor. JSONL normal guarda metadados e usa
buffer de escrita; o encerramento normal fecha o log. Uma queda abrupta pode
perder a cauda ainda em buffer.

`LATENCY` resume mediana, p95, p99 e máximo de até 2048 amostras por etapa.
O verbose discrimina foco e tecla. A recuperação de atores preserva os tempos
de evidência; não foi reduzida para melhorar benchmark. Confira a
[comparação reproduzível](REFACTOR_REVIEW.md#latência-reprodução-e-limites).

Capacidade é 64 comandos incluindo o corrente. Excesso/falha não significa
transmissão. Se o cliente não produzir o carrier, o comando permanece pendente
e bloqueia os seguintes por prontidão; cancelar a sessão limpa esse estado.
O caminho genérico usa SendPacket, sem alegação de cobertura funcional universal.
Omissões anti-duplicação `0368/0369/0193/0094/0360` são registradas. A injeção em
raw é rejeitada: o transporte de comandos precisa dos frames XKore 1.

## Pesquisa e testes

Stalker/probes são carregados somente quando flags de pesquisa forem pedidas;
atores e captura operacional não dependem dessa extensão. Ferramentas de cifra,
referências e históricos permanecem disponíveis. Nenhuma flag autoriza por si
experimento ao vivo. Opções de FIFO, cast throttle, debounce, persistência e
seleção experimental foram eliminadas, com seus testes substituídos por
propriedades do novo contrato.

```sh
bash scripts/test-offline.sh
python3 scripts/validate-research.py
python3 scripts/validate-codex.py
python3 scripts/benchmark-relay.py
```

A suíte inclui sockets exclusivamente locais, mocks de Frida/input e fixtures
sintéticas. Testes offline não demonstram sobrevivência do cliente, aceitação
pelo servidor, RTT ou equivalência funcional ao vivo. O PR permanece Draft até
revisão e rodadas especificamente autorizadas. Detalhes em
[ARCHITECTURE](ARCHITECTURE.md) e [REFACTOR_REVIEW](REFACTOR_REVIEW.md).

## Consolidação dos módulos operacionais

O pacote `relay/` tem 13 arquivos Python (contando `__init__.py`). O mapa completo
está em [ARCHITECTURE](ARCHITECTURE.md#2-componentes-operacionais).
`cli.py` também carrega a configuração INI; `frida_bridge.py` também constrói as
mensagens do agente; `client_dispatch.py` reúne roteamento e prontidão;
`actor_recovery.py` inclui acesso de leitura à memória e `packet_pipeline.py`
reúne framing RO e alimentação ordenada. Os nomes antigos foram removidos;
imports internos, testes e `ro_ops` usam os nomes canônicos novos. A fachada
`relay_capture_linux.py` mantém seus símbolos históricos sem arquivos-shim.
