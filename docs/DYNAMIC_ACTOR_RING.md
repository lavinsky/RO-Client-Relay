# Dynamic actor receive-ring discovery (2026-10-19)

## Goal
Use only evidence from the current uaRO process/session when choosing the memory
region containing decrypted 09FD, 09FF, and 0229 packets. Previously, the
`.relay_actor_ring` file was loaded at startup if its address was mapped; that
was not proof that the allocation still contained the current receive ring.

## Implementation
`relay/actors.py`: startup no longer reads or writes `.relay_actor_ring`
(the existing file is left untouched and ignored). It starts with
`base = hi = region = None`. Current-session discovery remains through
`quick_discover` (matching current wire bytes outside encrypted spans at ring
`+0x40`) and `discover` (context-verified plaintext). Quick search only
triggers for chunks containing encrypted packets, with a one-second backoff
after each attempt, to limit `/proc/PID/mem` work. After 20 consecutive
unverified actor packets, the selected ring is invalidated in full
(`base`, `hi`, `region`), the discovery rate limit is reset, and future
received packets may discover it again. The TCP stream/chunk chain is
preserved across rediscovery. Counters: `ring-discovered`,
`ring-invalidated`. Reads remain read-only; this does not affect
packet-length tables, native encryption/decryption, injection or the relay
FIFO. Existing snapshots still require provenance and validation.

## Evidence and limits
OBSERVED before change: current run had 0 recovered actors out of 611 encrypted
packets (09FD=210, 09FF=381, 0229=20); a ring address cache was changing
between sessions. The former startup trust in a mapped old address was
unjustified. INFERRED: refusing that trust prevents one important class of
misidentification; dynamic discovery alone does not guarantee higher recovery
under very fast ring overwrites or worker delays.

Offline validation: `python3 tests/test_actor_dynamic_ring.py` and
`bash scripts/test-offline.sh`. No live test; the relay process already
running must be restarted to load these Python changes.

## 2026-10-19 — discovery of isolated encrypted actor packets

The previous quick discovery refused chunks with fewer than 64 clear bytes.
A standalone 0x09FF (108 bytes) or 0x09FD (114 bytes) contributes just 4
clear header bytes, causing repeated discovery misses (42/71 observed encrypted
chunks were below the threshold in a diagnostic sample).

`start_quick_discover` now sends complete, wholly-contained encrypted actor
candidates (relative offset + original wire packet) to `quick_discover`.
For chunks with fewer than 64 clear bytes, the candidate ring's predicted
`base+0x40+offset` slot **must** contain an actually different, plausibly
plaintext packet validated by `ActorDecrypt.copy_ok`, with the unchanged clear
header. Mere 4-byte coincidence or unchanged ciphertext is rejected. The
existing >=64-clear-byte context matcher remains; no packet body is fabricated
and no memory is written. Counters: `ring-quick-actor-verified`.

Offline regression: `tests/test_actor_dynamic_ring.py` includes isolated
09FF and 09FD, and rejects matching headers without plaintext. This still
does not guarantee recovery when the client overwrites the ring earlier than
the delayed read, when ring layout differs, or when the character/NPC encoding
fails `valid_actor`. No live restart/test was done in this change.

## 2026-10-19 — internal mapping search and recovery diagnostics

`quick_discover()` now searches **within** writable mappings (bounded 1 MiB
reads, at most 64 MiB per mapping) for a current-session encrypted actor's
clear header. For each hit it computes `ring_base = header_address - 0x40 -
packet_offset_in_chunk` and verifies the exact candidate slot against the
whole chunk, masking encrypted body bytes. At least one decrypted actor must
pass `copy_ok()` at the predicted location; a matching header alone never
accepts an address. The routine no longer assumes `ring_base == mapping_lo`.
The slower `discover()` also derives the ring base from the verified packet
slot and chunk offset instead of persisting the mapping start.

Read-only metrics, one `ACTOR-RECOVERY` record per encrypted actor packet:
`status`, `reason`, `attempts` (poll count), `snapshots`, `first_valid_ms`,
`elapsed_ms`, `ring_known`, connection identity and packet ID. No packet bytes,
actor names or private network addresses are added to these records. Failure
reasons distinguish `ring-not-found`, `overwritten-before-verification`,
`timeout-no-valid-copy`, `correlation-mismatch` and `no-valid-copy`, as well
as `unclassified` for unforeseen early exits. These are diagnostic categories,
not proof that the underlying race is conclusively identified.

Regressions `tests/test_actor_dynamic_ring.py`: ring within mapping,
full discovery base calculation, isolated 09FD/09FF and false header rejection.
`bash scripts/test-offline.sh` passes 30 scripts. NOT RUN LIVE: restart
`./run.sh` when convenient to activate; compare `ACTOR-RECOVERY` records
before claiming improved NPC visibility.

## 2026-10-19 — slot-read diagnostics and 300ms actor delay

`ACTOR-RECOVERY` additionally records `first_read` and `last_read` for
actual live slot reads (elapsed milliseconds from queue arrival, bytes read,
clear header match, whether `copy_ok` passed, whether bytes differ from the
pre-decrypt image, and whether the sample was accepted as verified evidence).
`candidate_seen` tracks whether a valid copy appeared in the event evidence
set; `usable_snapshots` counts snapshots covering the packet offset;
`next_recv_before_decision` and `preimage_safe` help distinguish races from
correlation/provenance rejection. No actor bodies, GIDs or memory addresses
are logged in these new fields. Missing `first_read`/`last_read` means no
live slot read occurred (e.g. ring discovery or next recv closed evidence).

`actor-delay` is 0.30 seconds in the CLI default and relay_capture.conf.
The extra 150ms may improve late-appearing copies but holds the ordered
feed longer for unresolved chunks (and every following chunk). The existing
settle confirmation adds up to ~30ms beyond this threshold. More polling
increases read work and the queue may grow. A later TCP recv closes the safe
read window regardless of this value, so increasing it does NOT preserve an
overwritten copy nor fix a wrong ring-slot correlation. No live validation
of the change is claimed.

## 2026-10-19 — diagnostic decomposition of actor validation

Each live slot observation (`ACTOR-RECOVERY.first_read` / `last_read`) now has a
`validation` object with *boolean-only* fields: `length_match`, `header_match`,
`body_changed`, `object_type_ok`, `walk_speed_ok`, `name_format_ok`,
`fixed_gid_ok` and `accepted`. The first three are shared checks; for 09FD/09FF,
object type, speed and name use exactly the existing `valid_actor` predicates.
For 0229 only the fixed packet's known checks apply; the unrelated actor fields
are null. The diagnostic function does not alter packet acceptance.

`ACTOR-RECOVERY.evidence_validation` summarizes `observations`, number of
`structurally_valid` evidence copies and `snapshots_usable` at the packet's
calculated slot. These metrics help distinguish an apparently correct header
containing invalid actor fields from valid copies rejected later by evidence
provenance/context. They do NOT show packet bytes, actor names, GIDs, memory
addresses, keys or private data. An invalid body could also be a stale or
wrong-slot copy: metrics alone do not prove partial decryption.

New tests compare the diagnostic `accepted` boolean to the actual `copy_ok`
behavior for valid and invalid 09FF samples and fixed 0229. Live processes
must be restarted before these extra fields appear; existing logs cannot be
retroactively classified at field level.

## 2026-10-19 — remove per-poll diagnostics from timing-sensitive path

The field-by-field `copy_validation()` metrics previously ran at EVERY live
slot polling iteration, repeating parse/allocations and creating diagnostic
dictionaries in the latency-sensitive wire-feed thread. This was not truly
passive instrumentation. The feed now performs only the original `copy_ok`
check during polling and retains its already-recorded live read samples.
On final decision, it computes the detailed validation exactly for the first
and last actual samples. The 300ms limit and packet acceptance criteria are
unchanged. `tests/test_actor_dynamic_ring.py` verifies the preserved first/
last diagnostics; offline suite passes. Improvement to live recovery has NOT
been verified after restart.

Separate observation, before this change was loaded: session beginning
16:46:49 recovered 1/37 actors at 16:47, but later recovered 41/46 at 16:49,
11/12 at 16:50 and 15/15 through 16:51:48, *without a relay restart*. This
means the apparent regression also involves transient state (ring discovery,
connection context, or live client timing), not just static validation rules.
Those causal hypotheses are unverified.

## 2026-10-19 — immobile actors and walk_speed

The lower speed boundary is no longer used to reject `09FD` / `09FF` actors:
`0 <= walk_speed <= 1000` replaces `20 <= walk_speed <= 1000` in both
`valid_actor()` and `copy_validation()`. Speeds of 0 or below 20 can be
legitimate for stationary monsters. Upper bound, packet header, body change,
object type, name, and evidence/provenance rules remain unchanged.
Tests cover 0, 1, 19, 20, 1000 (accepted) and 1001 (rejected).

## 2026-10-19 — allow walk_speed 2000

Repeated rejected 09FF copies had structurally consistent headers, object
types and names with `walk_speed_value=2000`, so `valid_actor()` and diagnostic
`copy_validation()` now accept inclusive `0..2000`. Values 2001 and above
remain rejected. All existing ring timing, correlation, name, type and
provenance checks are retained. Live benefit requires restarting relay.

## 2026-10-19 — reject undecoded actor names

Inspection of the live session found 93/891 accepted 09FD/09FF actor names
containing high bytes (including apparent garbage), including the same actor GID
that later appeared as an unknown attacker. The former rule accepted all bytes
>=0x80. Both `valid_actor()` and `copy_validation()` now require only printable
7-bit ASCII (`0x20..0x7e`) before NUL padding. This intentionally rejects
characters like `§`/`¥` and other high bytes rather than treating them as
decryption evidence. **Tradeoff:** actors with legitimate non-ASCII names
(e.g. accented names) will be rejected until a verified character encoding is
implemented. Correlation and speed rules remain unchanged. Restart required.


## Consolidação do checkout — 2026-10-20 (auditoria documental; logs live existentes analisados)

**Registro live passivo (20/10, 18:37–19:30 BRT):** o relay atualmente executado registrou 1.030/1.036 `09FD`, 1.001/1.016 `09FF`, 948/1.023 `0983`, 241/259 `043F` e 91/92 `0229` recuperados, num total de **3.311/3.426 candidatos (~96,6%)**, com 115 falhas classificadas (103 correlação, 7 sobrescrita antes de verificação, 4 ring não encontrado, 1 timeout). Isso é **OBSERVADO EM LOGS JÁ COLETADOS**, sem emitir pacotes novos; os logs não provam ausência de falsos positivos sem confronto independente de semântica. [Procedência e correlação com o OpenKore](RESEARCH_STATUS.md#verificação-passiva-dos-logs-de-produção--2026-10-20-18371930-brt). Os resultados positivos e negativos históricos abaixo continuam válidos em suas sessões específicas.

**Atualização do código posterior aos parágrafos de 19/10:** a restrição transitória de nomes a ASCII foi substituída por decodificação estrita **CP1252**, permitindo letras/números e caracteres imprimíveis selecionados, inclusive acentos, mas rejeitando controle, padding inválido, limites com espaço e pontos de código não aprovados (`relay/actors.py:11-84`). Isso **não prova** qual codificação o servidor usa. A regra de `walk_speed` continua inclusiva `0..2000`; rejeições são classificadas em `ACTOR-RECOVERY.name_rejection`, sem publicar o nome.

Uma exceção muito restrita para **nome vazio em `09FF`** foi adicionada: `fresh_empty_name_actor()` exige ID/tamanho/cabeçalho conservados, GID não nulo, tipo e velocidade plausíveis e nome NUL integral. O resultado só pode ser aceito por leitura **nova do slot previsto**, pré-imagem segura, mesma base e `ring_epoch`, antes do próximo `recv`; snapshots e busca geral continuam sujeitos ao validador de nome padrão. `tests/test_empty_actor_name.py` cobre nomes vazios, nome com `#`, invalidação de época, corridas de recepção e rejeição de evidência antiga. O ganho ou a segurança end-to-end dessa exceção **NÃO FORAM testados live nesta revisão**.

O pipeline agora marca como cifrados `09FD/09FF` (variáveis), `0229` (15 bytes), `043F` (25 bytes) e `0983` (29 bytes). Para os últimos três só o ID inicial de dois bytes é confiável no wire; validação de plaintext usa o tamanho, ID, corpo modificado, GID não nulo e condições de **proveniência**, não correspondência de GID cifrado/decifrado. `0229` não é promovido com base apenas no slot esperado. Status de `sitting` ou buffs do consumidor **não são considerados semanticamente resolvidos** por esses testes. Testes: `test_0229_provenance.py`, `test_043f_recovery.py`, `test_0983_recovery.py`, `test_validate_0229.py`.

A proteção de ring inclui agora `_ring_mapping_allowed()` (base alinhada em página, região anônima privada gravável, inclusive RWX do Wine, limite da leitura dentro da região) e geração `ring_epoch`. O diagnóstico registra `ring_mapping_rejections`, `ring_mapping_unavailable`, `failure_evidence`, categoria do nome e as validações finais de amostras em `ACTOR-RECOVERY`. O relatório `RECV-BOUNDARY` registra hex de **tráfego real**, limitado ao map server; trate logs como artefatos de sessão privados. Fonte: `relay/actors.py`, `relay/wire_feed.py`, `relay/packets.py`, `relay/runtime.py`.

**Evidência disponível:** amostras documentadas na sonda independente variam de zero recuperação para 70 `09FF`/4 `09FD`/2 `0229` sob carga até 221/224 `09FF` e 14/16 `09FD` em outra janela (ver [STATE](../research/recv_cipher/STATE.md)). São **observações de sessões diferentes**, sem medição causal pareada. A confirmação do responsável sobre movimento/ataque em 17/10 não garante recuperação perfeita de atores no build/sessão atuais. O código e os testes offline passam, porém a condição de recuperação integral permanece **NÃO VERIFICADA**.
