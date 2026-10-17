# Registro de pacotes de controle e sessão — Gepard / uaRO

**Atualização canônica 2026-10-17:** ataque automático `0437`, skill automática em alvo `0438` e skill automática no chão `0AF4` **FUNCIONAIS** conforme responsável. Defeito real da fase ACT-03: byte 0 do corpo do consumidor era reescrito pelo store do scrambler após merge no Frida; `_fix0` corrigiu. Hipóteses de seleção/alcance como causa raiz estão **SUPERADAS**. Apenas a pesquisa da cifra segue aberta. [Conclusão de ações](ACTION_0437_0438_INVESTIGATION.md). O texto antigo abaixo mantém negativos e hipóteses como histórico, não falha operacional vigente.

**Objetivo:** reter evidências verificáveis para avaliar futuramente um plugin OpenKore de protocolo/sessão independente do cliente (xKore 0). Este arquivo **não** é uma implementação, especificação final de wire protocol ou prova de compatibilidade entre builds.

## Evidências disponíveis

- **Build servidor 2016 (referência histórica, não verificada no uaRO atual):** a investigação documenta unidades independentes `recv_crypt`, `send_crypt`, `sync_crypt`; inicialização `SC_GEPARD_INIT`; resposta `CS_GEPARD_INIT_ACK`; sincronização periódica `CS_GEPARD_SYNC`. Origem relatada: `docs/HISTORY/GEPARD_LEGACY.md` §3 e `docs/HISTORY/ARCHITECTURE_LEGACY.md` §5.1. O código histórico não está versionado (`relay/resources/` é ignorado).
- **uaRO, tabela de tamanhos:** `data/uaro_recvpackets.txt` contém `8280 128`, `4754 -1`, `5395 -1` e `C392 -1`. A presença na tabela **não demonstra** direção, papel no handshake ou associação exclusiva ao Gepard.
- **uaRO, hipótese de heartbeat:** `docs/HISTORY/GEPARD_LEGACY.md` §3.3 associa `0x8280` ao heartbeat de 128 bytes; no histórico 2016 a nota associa `0x8285` ao nome `CS_GEPARD_SYNC`. A equiparação entre builds é uma **inferência**, ainda não uma especificação validada.
- **Login:** `docs/HISTORY/GEPARD_LEGACY.md` §1 documenta login uaRO via HTTP/token e char server sem camada Gepard. Isso **não identifica o ID ou a sequência exata** do pacote de inicialização/sincronização da cifra na sessão de mapa.

## Inventário com níveis de evidência

| Mensagem / ID | Direção | Tamanho | Papel proposto | Nível e fonte | Lacunas para xKore 0 |
|---|---|---:|---|---|---|
| `SC_GEPARD_INIT` / ID atual não confirmado | servidor → cliente (no build 2016) | desconhecido no uaRO | estabelecimento de estado de sessão/cifra | **DOCUMENTADO PARA 2016**: investigação §3.1 | ID atual, fase, campos, condições de reinicialização |
| `CS_GEPARD_INIT_ACK` / ID atual não confirmado | cliente → servidor (no build 2016) | desconhecido no uaRO | confirmação de inicialização | **DOCUMENTADO PARA 2016**: investigação §3.2 | ID atual, dependências, conteúdo, transição de estado |
| `0x8280` | **Gepard → servidor** (não construído pelo cliente, OBSERVADO 2026-10-16) | 128 (tabela uaRO; egress periódico de 128 B observado, ~a cada 3,6 s) | heartbeat/sync Gepard-origin, **periódico** (não preâmbulo por-ação do cliente); papel de **gate** das ações ainda HIPÓTESE ([ficha abaixo](#0x8280--syncanti-cheat-gepard-origin-periódico-fase-1-observada-papel-de-gate-ainda-hipótese)) | **origem e periodicidade OBSERVADAS**; papel de gate **HIPÓTESE** | identidade binária 128B≡`0x8280`; se `control_value` varia; se gateia a ação no servidor |
| `0x8285` (build 2016) | cliente → servidor | não estabelecido aqui | heartbeat histórico | **DOCUMENTADO PARA 2016**: investigação §3.3 | não assumir correspondência binária com `0x8280` |
| `0x4754`, `0x5395`, `0xC392` | não estabelecida | variável (`-1` na tabela) | desconhecido | **LISTADOS** em `data/uaro_recvpackets.txt` | verificar origem e se são realmente pacotes de controle |
| `0x035F`, `0x0437`, `0x0438`, `0x0AF4` | cliente → servidor | consultar fonte do protocolo | pacotes de ação, **não confundir com heartbeat** | **DOCUMENTADOS** em `docs/HISTORY/ARCHITECTURE_LEGACY.md` §§5–6; origem por code do dispatcher `0xd473b0` **OBSERVADA** em 2026-10-16 ([mapa abaixo](#mapa-dispatcher--pacote-de-ação-act-20261016-01)) | comportamento no build atual e requisitos do OpenKore |

## Hipótese separada da evidência

**H-CIPHER-01 — HIPÓTESE HISTÓRICA, NÃO causa ativa da falha corrigida.** O fonte servidor de 2016 sugere decifragem de corpos selecionados antes do parser, com estado de recepção que deve avançar na sequência correta. Conjectura atual: bytes de conteúdo incorretamente decifrados podem fazer o parser/servidor rejeitar `0x0438`; operações de corpo menor, como algumas variantes de `0x0437`, podem parecer funcionar mesmo se a cobertura da cifra estiver incorreta. **Não está provado** que exista validação criptográfica por byte, que o servidor descarte o pacote por esse motivo, ou que a cifra atual seja idêntica à de 2016.

**Evidência que falta:** comparar resultados reproduzíveis de sessões de teste autorizadas e dados sanitizados, separados por versão, ID, comprimento e estado de sessão, para distinguir diferença de corpo, dessincronização, pré-condição de ação e rejeição de parser. Não concluir causalidade apenas pela ausência da animação de perícia.

## `0368` pré-select e ações com alvo (`0437` ataque / `0438` perícia) — achado REFUTADO como solução

**Fechamento posterior:** `0368` não era a causa; ataque e skills automáticos funcionam após o `_fix0` no Frida (`agent/relay_hook_linux.js:481-534`). Os negativos desta seção referem-se à via `SendPacket` crua **testada anteriormente**, não ao carrier+merge hoje funcional.

**Procedência.** Sessão OrquestradorCLAUDE, **2026-10-16** (ORCH-20261016-01b, rodada 09b); build
`uaRO.exe` `f2f2…9569`; servidor emulador **próprio do responsável**. Caminho no relay:
`relay/writeback.py:_on_inbound_sendcall`. **Refutação** pelo responsável no mesmo dia, registrada em
ACT-20261016-01 (`research/action_0437_0438/STATE.md` §5, `HANDOFF.md`).

**Leitura original (2026-10-16, rodada 09b — SUPERADA).** A divergência entre sentar (`0437`, GID=0,
funcionava) e ataque/perícia (não tinham efeito) foi atribuída ao `0368` (CZ_REQNAME_BYGID) que o relay
injetava antes de ações com alvo. O `0368` pré-ação passou a ser **gated** por `--target-select`
(default OFF) em `relay/writeback.py` (`target_select`), com flag em `relay/cli.py`.

**REFUTADO (responsável, 2026-10-16):** a hipótese "o `0368` pré-ação era o bloqueio" é **falsa**.
**Com ou sem `0368` o `SendPacket`/`sendmsg` da ação sempre ocorria**; o problema (ação enviada mas
**sem efeito** no servidor) é **anterior** ao `0368`. Consequência: rotear `0437`/`0438` pela
`SendPacket` crua do cliente **não executa** ataque/perícia. A flag `--target-select` e o `0368` em
`SKIP_IDS` continuam no código (comportamento operacional válido: o cliente já emite o `0368` sozinho
ao passar o mouse/clicar), mas **não** são solução para ataque/perícia.

Fatos que permanecem:

- **`0368` (CZ_REQNAME_BYGID):** OBSERVADO como **pedido de nome por GID** emitido pelo cliente ao
  passar o mouse/clicar num alvo — não um "lock de alvo". Por isso está em `SKIP_IDS`
  (`relay/writeback.py`) no sentido consumidor→servidor.
- **`0437` sentar/levantar (GID=0):** OBSERVADO funcionando via client SendPacket.
- **`0437` ataque (GID≠0) e `0438` perícia via SendPacket crua:** pacote sai, **ação não executa**
  (relato do responsável; mecanismo do servidor NÃO VERIFICADO).
- **Throttle de cast:** `0438` sob `--cast-throttle` (default 0.8 s): um cast por janela, log
  `cast 0x0438 pacejado (rajada evitada)` — política intencional de writeback.

**Relação com H-CIPHER-01:** a explicação alternativa "era o `0368`" foi retirada; H-CIPHER-01
(rejeição por conteúdo/cifra) **volta a ser candidata**, ao lado de pré-condições de estado do
cliente que a via natural monta (ver abaixo). Nenhuma das duas está demonstrada.

**Teste offline:** `tests/test_writeback.py` cobre o roteamento (default sem `0368`; caso
`target_select=True` com dedup por GID). Testa o código, não a execução da ação no servidor.

## Mapa dispatcher → pacote de ação (ACT-20261016-01)

**Procedência.** Trilha `research/action_0437_0438/` (STATE/HANDOFF), **2026-10-16**, base `6c20733`;
build uaRO+gepard = MATCH; autorização direta do responsável por rodada, servidor próprio. Captura
**read-only** com 2 HW exec BP: DR0 no dispatcher `0xd473b0` (lê `code=[esp+8]` e o frame de 13
dwords `[esp+4+4k]`); DR1 na `SendPacket(this,len,buf)` do cliente em **uaRO+0x816640
(VA `0xC16640`)**, onde o corpo ainda está **em claro**, antes do scrambler Gepard
(`mov [ecx],bl` em `gepard+0x18eff2`). Tudo na thread principal. Sonda:
`research/action_0437_0438/observe_dispatch_codes.py`. Artefatos privados (não versionados):
`/tmp/claude-act-20261016-031147-sendpkt/observe.json`,
`/tmp/claude-act-20261016-110249-soulstrike2/inject.json`.

| Ação do usuário | code do dispatcher | Pacote CZ | Corpo em claro observado | Classificação |
|---|---|---|---|---|
| andar | `0x11` (17) | `0x035F` | frame `[0,17,0,X,0,Y,…]` (X,Y no próprio frame) | OBSERVADO |
| sentar/levantar | `0x1f` (31) | `0x0437` | `3704 <GID próprio> 02/03` (02 senta, 03 levanta) | OBSERVADO |
| atacar | `0x28` (40) | `0x0437` | `3704 <GID alvo> 07` (ação 07 = ataque) | OBSERVADO |
| usar perícia | `0x2a` (42) | `0x0438` | `3804 0a00 0d00 <GID>` (nível 10, skill `0x0d` = 13 Soul Strike) | OBSERVADO |
| selecionar alvo | `0x0a` (10) | (via `0x0368`) | GID do alvo no frame arg3 | OBSERVADO |

**ABI (OBSERVADO):** `0x11` carrega X,Y no frame e comete sozinho. `0x28` e `0x2a` **não levam
argumentos no frame** (`[0,40,0,0,…]` / `[0,42,0,0,…]`): leem alvo/perícia de **estado global**
montado por passos anteriores.

**Preparação (INFERIDO por sequência + cross-check):** `0x29` frame `[.,41,.,GID,.,13,…]` = seta skill
13 + GID; `0x5a` frame `[.,90,.,10,…]` = seta nível 10; `0x0a` = seleciona alvo. O corpo do `0438`
(nível 10/skill 13) casa exatamente com `0x29`+`0x5a`. **Cadeia de cast OBSERVADA: `0x29 → 0x5a →
0x2a`**; cadeia de ataque inferida `0x0a → 0x28`.

**Caller imediato (OBSERVADO):** em todos os codes, `[esp]` no dispatcher é o shim do Gepard
**`gepard+0xb2c251`**. O PoC 035F chama o dispatcher direto (sem o shim) e funciona, logo o shim não é
o bloqueio. **RETIRADO:** cadeias de chamadores além do shim obtidas por `Backtracer.FUZZY` e por
EBP-walk (`capture_skill_callers.py`, `capture_skill_ebp.py`) — validadas no objdump, os endereços
(`0x944002`, `0x943fda`, `0x874a40`, `0x874b32`, `0x874f0b`, `0x66baea`) **não** são retornos de
`call` (frames SEH/FPO, provável trampolim `ret`/`jmp` do shim). O split "prepare vs commit" **não**
está provado.

**Injeção nativa da perícia — NEGATIVO (OBSERVADO, ao vivo, autorizado).** Capture+replay da cadeia
de cast pelo mecanismo do PoC 035F (captura passiva do `this`=ECX + `thiscall` a partir do fire-site
de main-loop `0x4dcba0`), sonda `inject_soulstrike_live.py`:

- Rodada 1 (bug do pesquisador: replay de superset incluindo `0x11` e code `0x00`): **crash** do
  cliente. Não interpretar como resultado da cadeia de perícia.
- Rodada 2 (allowlist estrita `[0x29,0x5a,0x2a]`): as 3 chamadas retornaram (`0x29`→13, `0x5a`→17,
  `0x2a`→**0**) sem exceção, **nenhum `0x0438` na rede** (perícia não conjurada) e **crash deferido**
  (sonda chegou ao `DONE` aos 90 s; cliente caiu depois).

**Conclusão (OBSERVADO no recorte):** disparar `0x29→0x5a→0x2a` de `0x4dcba0` é **inócuo** (`0x2a`→0,
sem egress) **e instável**. Ao contrário do `0x11`, o commit da perícia depende de estado/contexto
montado pelo handler de input natural que esse disparo não tem (natureza do estado: **NÃO
VERIFICADA**). **Em aberto:** sítio real que dispara `0x2a` e a pré-condição que ele lê. Método
proposto, não executado: *validated stack scan* (no BP do dispatcher, manter só dwords da pilha `V`
em `.text` do uaRO onde um `call` termina exatamente em `V`: `V-5 == E8` ou `FF /2` em `V-6..V-2`).

**Limite de recursos:** o modo `--move-dispatch` do relay ocupa os quatro DRs; o STATE da trilha
admite sobreposição DR0/DR1 com outras sondas — este experimento **não** valida coexistência de sondas.

## `0x8280` — sync/anti-cheat Gepard-origin, periódico (Fase 1 OBSERVADA; papel de gate ainda HIPÓTESE)

**Procedência.** RELATO do responsável, **2026-10-16**, confirmado ao vivo por ele em logs e teste
(servidor próprio): **um `0x8280` sai IMEDIATAMENTE ANTES de todo `0x0437`/`0x0438`/`0x0AF4`** (e
**não** antes do `0x035F`); comandos do consumidor (OpenKore) também provocam o envio de `0x8280`.
Não reproduzido independentemente por sonda ainda (ver "Teste" abaixo).

**Analogia (NÃO prova para este build).** No fonte Gepard 2016, `CS_GEPARD_SYNC` (`0x8285` lá)
carrega um `control_value` de 4 bytes cifrado por uma unidade **`sync_crypt` separada** das de
recv/send; ao decodificar `0xDDCCBBAA` o servidor faz `sync_tick = gepard_get_tick()`
(`relay/resources/Gepard-SRC-LGP-master/src/common/socket.cpp:411-426`). Em
`relay/resources/Gepard-SRC-LGP-master/src/map/clif.cpp:79-85`, `clif_gepard_process_packet` calcula
`diff_time = gettick() - sync_tick` e, se `> 40000`, chama `clif_authfail_fd` (rejeita/derruba). As
ações (`cs_packet_request_move`/`action_request`/`use_skill_to_id`/`use_skill_to_ground`) são
decifradas com `recv_crypt`. **A equivalência build-2016 × uaRO não está demonstrada** (AGENTS.md §6.2).

**Hipótese de trabalho (não confirmada).** `0x8280` é o sync/anti-cheat do uaRO e **gateia** as ações:
injeção crua de `0437/0438` (REFUTADA em ACT-20261016-01) e disparo do dispatcher fora de contexto
falham por **não** virem acompanhados do `8280` natural. Isso explicaria por que o `INSERT→ataque`
(merge sobre um `0437` que o próprio cliente montou pela entrada natural, **com** o `8280`) **executou**
— ver [MOVEMENT_035F_PRECONDITIONS §13.13](MOVEMENT_035F_PRECONDITIONS.md) e o mapa acima.

**Resultado da Fase 1 (OBSERVADO — build atual, 2026-10-16, pid 3752762, 20 ações; sonda
`research/action_0437_0438/observe_8280.py`, HW exec BP na `SendPacket` uaRO+0x816640 + Interceptor
`sendmsg`):**

- **`0x8280` NÃO é construído pelo cliente.** Em 20 ações (6× `0437`, 10× `0438`, 4× `0AF4`), o
  cliente emitiu em claro na `SendPacket` os ids `0437/0438/0AF4/0360/0368` — e **nenhum `0x8280`**
  (contador `is_sync` = 0). → `0x8280` é **Gepard-origin** (INFERIDO), não um pacote montado pelo
  cliente na via de envio natural.
- **Egress periódico de 128 B.** O `sendmsg` mostra uma escrita de **128 B recorrente (25× em 90 s ≈
  a cada 3,6 s)**, independente do ritmo das ações — candidato ao heartbeat/sync (coerente com o
  tamanho 128 da tabela uaRO). Logo o `0x8280` é **periódico** (timer), **não** um preâmbulo por-ação
  construído pelo cliente. (INFERIDO; conteúdo cifrado não decodificado — a identidade exata
  128B ≡ `0x8280` é NÃO VERIFICADA.)
- **Reconciliação com o RELATO.** O relato "um `0x8280` sai imediatamente antes de toda ação" é
  compatível com uma observação **no fio** (onde o egress periódico de 128 B se intercala com a ação),
  **não** com construção do `8280` pelo cliente — que a sonda refuta. A classificação do RELATO passa
  de HIPÓTESE a **parcialmente reconciliada**: o `8280` existe e é Gepard-side, mas não precede
  causalmente cada ação como pacote do cliente.
- **Consequência para o merge (favorável).** Como o `8280` é do Gepard e não do cliente, o merge
  **não precisa sintetizá-lo**: ao deixar o cliente disparar uma ação **real** (via entrada natural),
  qualquer sync que o Gepard exija ocorre sozinho — exatamente o que o `INSERT→ataque` já mostrava.
- **Buffers das ações (OBSERVADO; insumo para `scramble-range`).** `buf` da `SendPacket` é **estável**
  por id e todos caem **dentro da `scramble-range` do `035F` já configurada** (`0x2632000–0x2730000`):
  `0x0437`→`0x271eb78`, `0x0438`→`0x27218cc`, `0x0AF4`→`0x27218fc` (e `0360`/`0368`→`0x272f37c`).
- **Corpos decodificados (em claro).** `0437` = `3704|GID|07` (ataque); `0438` =
  `3804|nível(2)|skill(2)|GID(4)`; `0AF4` = `f40a|0100|skill(2)|x(2)|y(2)` — **o `0AF4` carrega
  skill+x+y no corpo**, confirmando o desenho "clique fixo + merge reescreve x,y".

**Lacunas específicas da coleta histórica de 2026-10-16 (não são falhas operacionais atuais):** naquela coleta ainda não havia captura individual do store `gepard+0x18eff2` no envio natural de `0438`/`0AF4`; o responsável confirmou as skills automáticas funcionais posteriormente. Permanecem perguntas separadas de protocolo sobre a identidade
binária do egress de 128 B com `0x8280`; se o `control_value` varia. Captura crua (gitignored):
`research/action_0437_0438/captures/obs8280_20261016/`.

**Spike de isolamento** para dirigir a ação por input sintético escondido:
[`research/action_0437_0438/ISOLATION_SPIKE.md`](../research/action_0437_0438/ISOLATION_SPIKE.md).

## Ficha obrigatória para novas descobertas

- ID/nome proposto; direção e fase (login/char/mapa); versão/build e data;
- Comprimento e se a observação ocorreu em wire, após decifragem ou somente em tabela;
- Relação temporal com inicialização, reconexão ou heartbeat;
- Referência exata `arquivo:linha` ou teste reproduzível **sanitizado**;
- Classificação: OBSERVADO / INFERIDO / HIPÓTESE / NÃO VERIFICADO / REFUTADO;
- Explicação alternativa e teste offline capaz de distinguir interpretações;
- Informação necessária para futura interface de plugin OpenKore, **sem** assumir que o relay implementará xKore 0.

## Limite de arquitetura do futuro plugin

Quando houver protocolo demonstrado, a responsabilidade por inicialização de sessão, mensagens de controle periódicas e estado do protocolo deverá ser especificada como extensão **do OpenKore**. Este repositório permanece responsável pelo relay de texto claro na fase xKore 1. Nenhuma implementação de controle deve preceder evidência suficiente de direção, transições de estado e testes reproduzíveis.

## Fechamento funcional das ações e limite criptográfico — 2026-10-17

**CONFIRMADO PELO RESPONSÁVEL:** ataque automático `0437`, skill de alvo `0438` e de chão `0AF4` estão funcionando. Não há bloqueio pendente da automação por `0368`, lock de alvo ou coordenação de movimento. O primeiro byte do corpo entregue pelo consumidor estava saindo com contribuição do original do cliente por conta da ordem do store byte a byte; o `_fix0` o corrige no hit seguinte (`agent/relay_hook_linux.js:481-534`).

**OBSERVADO NO CÓDIGO:** escrita de corpo pré-XOR e restauração `c0 ^ orig0 ^ our0`. **NÃO VERIFICADO NESTA REVISÃO:** nova captura de rede pós-fix por família e reconstrução do algoritmo criptográfico. A observação de `0x8280` periódico é registro separado; não transformá-lo em preâmbulo obrigatório por ação.

Os experimentos históricos `0368`/`SendPacket` cru, replay de `0x2a` e `0x8280` permanecem preservados com seu escopo original. A interpretação final e matriz de evidências estão em [ACTION_0437_0438_INVESTIGATION](ACTION_0437_0438_INVESTIGATION.md).
