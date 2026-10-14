# Handoff — estado da investigação (2026-10-14)

Resumo para futuras conversas. Fala-se **português**; evitar termos adversariais (é depuração de um
cliente **próprio**, em servidor/emulador **próprio e autorizado**). Detalhe completo em
`gepard_investigation.md` (§19–§23) e `ARCHITECTURE.md` (§5–§6, §8, §13).

## O objetivo

Fazer o cliente uaRO transmitir ações (atacar/`0437`, perícia on-target/`0438`, perícia on-ground/
`0af4`, andar/`035f`) que o consumidor (OpenKore via XKore 1) manda de volta, para depurar o cliente.

## O que funciona hoje

- **Captura/feed** (recv decifrado → OpenKore) e **envio reativo**:
  - `035f` (andar): **merge** no breakpoint de execução da cifragem (`--scramble-bp 18eff2`,
    `reg=auto`), uso único. Confiável, não dessincroniza.
  - `0437`/`0438` (ação/perícia): **`--inject-call`** chama a `SendPacket` do cliente
    (`uaRO.exe+0x816640`, `this` capturado no DR1). Sentar/levantar/atacar saem.
  - Modo combinado roteia por id (`writeback._on_inbound_split`). Invocação de referência em
    `ARCHITECTURE.md` §6.

## O problema central ainda aberto

Perícia on-target injetada **não conjura de forma confiável**. Diagnóstico (NÃO é token de validação):

- O fonte de 2016 (`relay/resources/Gepard-SRC-LGP-master`, `src/common/socket.cpp`) mostra que o
  servidor só faz `gepard_enc_dec(corpo, recv_crypt)` e parseia. **Sem validação por-ação.** O `8280`
  é **heartbeat** (constante `0xDDCCBBAA` cifrada), não gate. A ação injetada falha por **SINCRONIA
  de cifra**: o corpo precisa estar cifrado com o `send_crypt` do cliente, na posição certa do stream.
- A cifra é um **stream cipher auto-modificante**. No build atual a tabela começa de um **ramp fixo**
  `key[i]=rol8(i,2)` e as posições caminham linearmente (`0x101`/`0x104` variam). Mas a função
  por-palavra `f` (como a tabela muta) **não foi resolvida**: `gepard+0x18eff2` fica **depois** do
  keystream (é o XOR/store final), então o traço ali não expõe `f`. Ver §23.

## Decisão / próximo passo concreto

**Caminho 1 — chamar a função de perícia do próprio cliente** (dispensa resolver `f`; o cliente
cifra+envia certo, em sincronia). É a extensão natural do `--inject-call`:

1. Achar a função de alto nível de **uso de perícia on-target** `(skillID, nível, GID)` no uaRO
   (análoga à cadeia de movimento `uaRO+0x873a80 → +0x875400 → +0x9463b0`, §9/§10 do ARCHITECTURE).
   Método: **Stalker** (`--trace-internal`, comparar parado vs. uma conjuração manual para isolar as
   arestas) + sondas de entrada (`--probe-at`) nos candidatos; depois chamar por `NativeFunction`
   com o `this` certo, como se faz com a `SendPacket`.
2. Risco a verificar cedo: o gepard pode validar a **cadeia de retorno** ao enviar; uma chamada via
   Stalker/`NativeFunction` com pilha sintética pode ser rejeitada. É o único dealbreaker restante.
   Primeiro passo barato: `--send-probe`/`--trace-internal` numa conjuração **manual** para mapear a
   cadeia real antes de chamar.
3. Alternativa já sugerida pelo usuário (msg 11): implementar parte dessa lógica no **lado do
   consumidor** (plugin do OpenKore).

## Restrições e lições operacionais

- **Nunca** varrer muita memória de dentro do agente (Frida) — travou o cliente. Varredura de memória
  só **externa** (`/proc/<pid>/mem`, não pausa o jogo). Leituras fixas pequenas no agente são ok.
- **Não** pôr watchpoint de dados no slot de pilha do `035f` (travou o cliente). O BP de **execução**
  em `0x18eff2` é seguro (é o merge).
- Parar o driver com **SIGTERM** e **esperar ~6 s** (o `dispose` do agente libera os registradores de
  depuração; matar à força deixa registrador armado sem handler e derruba o cliente).
- `pgrep -f relay_capture` dá falso-positivo (casa o wrapper do shell); conferir com
  `ps -eo args | grep relay_capture_linux | grep -v grep | grep -v zsh`.
- Rodar read-only: `./run.sh --no-inject ...`. Combinado: `./run.sh` (lê `relay_capture.conf`).
  Python com `-u` ao rodar em background. venv: `~/.venv-frida`.

## Infra de pesquisa deixada pronta

- `--scramble-trace N`: traço passo-a-passo da cifragem (snapshot tabela+posições por byte, gated por
  `--scramble-range`, teto `N`, auto-desarma). Seguro. Ver `ARCHITECTURE.md` §8.
- Scripts de análise offline ficam no `scratchpad` da sessão (não versionados): `findunit.py`
  (acha a unidade pelo ramp), `scanunit.py`, `difftrace.py`, `fitf.py`. O método está em §23.

## Sessão de referência (endereços — mudam a cada relog)

- gepard base ~`0x76940000`; store da cifragem `gepard+0x18eff2`.
- `SendPacket` do cliente: `uaRO.exe+0x816640`.
- Unidades de cifra: recv `key[0]=0x3efdd00`, send `key[0]=0x3efddd8` (posições em `key[0]+0x100`).
- Servidor: `51.89.96.177` (char 6121, mapa 5121). Conta AID 2158435 (`0x0020EF63`).
