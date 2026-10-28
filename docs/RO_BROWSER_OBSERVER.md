# Observer read-only para roBrowser / UI externa

**Status em 2026-10-21:** implementação **opt-in** na working tree, ainda não integrada à `main` no momento desta revisão. O observer não substitui o consumidor XKore do OpenKore e não possui caminho de escrita para o cliente ou servidor. A integração da UI/Node é externa a este repositório e **NÃO VERIFICADA aqui**.

## Contrato do relay

- **Ativação:** somente quando `RO_RELAY_OBSERVER_SOCKET` está definido no ambiente do processo do relay (`relay/cli.py`). Sem essa variável, o comportamento existente permanece inalterado.
- **Producer:** `relay/wire_feed.py` espelha apenas bytes **server → client** que já passaram pelo framing/recuperação do pipeline e seriam entregues ao consumidor. Cada publicação usa quadro XKore1 `R + uint16LE(len) + payload`.
- **Sem writeback:** `ClientSendFeed` e os quadros `S` continuam exclusivamente no fluxo normal do OpenKore/relay; o observer não recebe callback de envio nem expõe API para injeção.
- **Fases:** o leitor envia exatamente um byte ao conectar: `L` para login (`6900`), `C` para char (`6121`) ou `M` para map/demais portas de jogo. Essa classificação é específica do layout de portas usado pelo projeto e deve ser revista se o servidor mudar.
- **Epoch:** o primeiro `RECV` de uma nova identidade de conexão real de login chama `begin_session(conn)`, limpa todo o histórico e fecha viewers antigos. Repetições na mesma conexão não reiniciam a epoch.
- **Replay:** histórico por fase, em memória, até **32 MiB totais**. Se ultrapassar o limite, `replay_valid=False` e todo o histórico é descartado; viewers já conectados continuam recebendo o stream live. O relay não oferece replay truncado como se fosse completo.
- **Backpressure:** no máximo dois leitores registrados. Cada um possui fila de 64 frames; fila cheia fecha o viewer inteiro em vez de descartar um frame intermediário e dessincronizar seu parser.
- **Concorrência:** snapshot do histórico e registro do subscriber acontecem sob o mesmo lock, evitando que um frame live ultrapasse os bytes históricos.

## Fronteira de segurança e privacidade

O socket UNIX é criado com modo **0600** dentro de diretório que deve ser **diretório existente, 0700 e pertencente ao UID atual**. Um caminho existente é recusado. Essa barreira é de filesystem; o protocolo do socket não adiciona autenticação própria.

O replay de login pode conter **material sensível recebido do servidor**, inclusive estado/autenticação de sessão. A sanitização de `relay_log.jsonl` não transforma esse stream bruto do observer. Portanto:

- não expor o socket por TCP, HTTP genérico, compartilhamento de arquivos ou diretório de grupo;
- não versionar, gravar em logs ou anexar os frames a issues/PRs;
- uma UI remota deve implementar sua própria autenticação/autorização antes de retransmitir esses bytes;
- permissões de Tailnet ou de um reverse proxy são responsabilidade da camada externa e **não são garantidas pelo relay**;
- o login real precisa ocorrer depois de o observer ser ligado para que um viewer tardio tenha replay completo das três fases. Ligar o observer após login não reconstrói retroativamente o material anterior.

## Ativação local

Exemplo explícito, antes de iniciar o relay:

```bash
runtime="${XDG_RUNTIME_DIR}/visualbt-relay"
mkdir -p -m 700 "$runtime"
export RO_RELAY_OBSERVER_SOCKET="$runtime/feed.sock"
./run.sh
```

Para um relay já iniciado a partir de terminal, o helper opcional
`scripts/restart-relay-in-terminal.sh` realiza uma reinicialização controlada:

1. identifica `relay_capture_linux.py` e exige que seu pai seja exatamente `bash ./run.sh`;
2. confirma que o grupo de processos é próprio do launcher, recusando sinal amplo inesperado;
3. resolve um TTY gravável pertencente ao usuário (override `RO_RELAY_LOG_TTY`, TTY atual, TTY do launcher ou hint privado);
4. envia `SIGINT` ao grupo e espera o relay antigo sair, para não anexar duas instâncias Frida;
5. reinicia `./run.sh` em sessão separada com `RO_RELAY_OBSERVER_SOCKET`, log privado 0600 e forwarding opcional para o TTY escolhido;
6. só declara sucesso quando encontra novo PID e o socket UNIX existe.

`--dry-run` valida apenas identidade/grupo/TTY sem reiniciar. O script **não reinicia OpenKore nem uaRO**. Se não houver relay ativo e verificável, encerra com erro e orienta usar `./run.sh` diretamente.

## Consumo do socket

O protocolo local é deliberadamente mínimo:

```text
connect(AF_UNIX, feed.sock)
send("L" | "C" | "M")    # exatamente uma seleção de fase
recv(...)                 # sequência de frames XKore1 R
```

Qualquer outro byte de fase encerra a conexão sem inscrição. A implementação atual limita-se ao espelho; nomes como `BT_RELAY_OBSERVER_SOCKET`, endpoints HTTP/WebSocket ou `BT_ALLOW_RAW_OBSERVER` pertencem à aplicação de UI externa e **não fazem parte do contrato deste repositório**.

## Evidência e testes

**OBSERVADO EM TESTE OFFLINE:**

- `tests/test_observer.py`: permissões 0600, diretório 0700, propriedade do UID, replay por fase, troca de epoch, invalidação por limite, fase inválida e limpeza do socket.
- `tests/test_edge_wirefeed.py`: integração `WireFeed → PacketObserver` por login/char/map e confirmação de que o caminho client→server não publica no observer.
- `bash -n scripts/restart-relay-in-terminal.sh`: valida sintaxe, não comportamento de reinício.

**NÃO VERIFICADO nesta revisão:** uma sessão nova uaRO→login→char→map atravessando o observer até uma UI roBrowser; autenticação da UI externa; comportamento durante reconnects reais; adequação do limite de 32 MiB para sessões longas; uso simultâneo de duas conexões pela aplicação externa.

Arquitetura geral: [ARCHITECTURE.md](ARCHITECTURE.md). Operação do relay: [OPERATIONS.md](OPERATIONS.md). Estado atual: [RESEARCH_STATUS.md](RESEARCH_STATUS.md).
