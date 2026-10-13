# Capturer architecture: how the driver and its agent fit together

A plain-language map of the capture tool. It describes what each module does, how data moves
between them, what state they share, and which parts are legacy. For the project's history,
findings and run steps, see `README.md`.

---

## 1. The big picture

Two programs cooperate:

| Program | Runs in | Job |
|---|---|---|
| **Agent**, `relay_hook_linux.js` | the game process, loaded through the Frida gadget | Watches every socket read and write the game makes and reports them. Optionally takes snapshots of the client's receive buffer and watches the send queue. Does as little work as possible inside the game. |
| **Driver**, `relay_capture_linux.py` → package `relay/` | a normal Python process outside the game | Receives the agent's reports, turns them into a clean ordered packet stream, fills in the few obfuscated parts from client memory, and feeds the result to the consumer. |

```
 game process (Wine)                         driver (Python)                         the consumer
 ┌─────────────────────┐   Frida messages   ┌───────────────────────────────┐  TCP  ┌─────────┐
 │ recvmsg/sendmsg hook├───────────────────►│ Agent → work queue            │       │ XKore 1 │
 │ ring snapshots      │                    │ worker: Capture.dispatch      ├──────►│ :2350   │
 │ send-queue watch    │◄───────────────────┤ WireFeed / ClientSendFeed     │ R / S │         │
 └─────────────────────┘ ring/sendwatch/    │ feeder thread → Relay         │frames └─────────┘
                          scramble posts
          ▲                                 └───────────────┬───────────────┘
          │            read-only /proc/<pid>/mem            │
          └─────────────────────────────────────────────────┘
```

By default the driver never writes to the game, and nothing it produces reaches the game server;
everything the consumer sends back to the relay is read and ignored. The opt-in **`--inject`** path
is the exception: the packets the consumer sends back (XKore "S" frames) are made to leave the
client. There are three ways, all for a client/server you control:
- **`--inject-call`** (spontaneous, §8): call the client's own `SendPacket(this, len, buf)` so it
  builds, encrypts and sends our bytes through its normal path — replacing nothing.
- **scramble merge** (hijack, §7): with the scrambler breakpoint armed, each packet's body is
  substituted into the client's send slot *before* the client obfuscates it, so the client's own
  scrambler encrypts the driver-supplied bytes — but it only *replaces* a packet the client itself
  builds.
- **`inject.SendInjector`** (raw, via `memory.ProcessMemoryWriter`): writes straight into the send
  queue. Only valid for an *unencrypted* client (the bytes are never run through the scrambler).

`relay_capture_linux.py` is only the entry point. It re-exports the old names (`ActorDecrypt`,
`WireFilter`, `SendWatch`, `plaintext_guess`, …) so existing tests and `relay_sendbp.py` keep
importing from it.

---

## 2. The agent (`relay_hook_linux.js`)

One file, because Frida loads one script. Sections, top to bottom:

| Section | What it does |
|---|---|
| hex | Bytes → hex text through a 256-entry table; read a packet id from the first two bytes. |
| sockets | `peerOf(fd)`: which server (`ip:port`) and which connection (local port) a socket is. Asked fresh whenever it matters, because Wine reuses socket numbers between the login, char and map servers. `libcFns`, `iovs`, `hookAll`: find and hook libc functions, unpack `msghdr` buffers. |
| recv ring | The driver posts `{type:'ring'}` once it knows where the client's receive ring is. **recvmsg hook**: on entry, re-checks the socket and sends a **RINGSNAP** (ring copy taken before the next chunk can land); on exit, sends **RECV** with the bytes plus a ring copy from *before* the client could deobfuscate them. |
| send watch | Off until the driver posts `{type:'sendwatch'}`. Keeps all 4 debug registers on the next send-queue slot; `swTrap` records each write into a fixed buffer. `rpc.exports.dispose` clears the registers on unload. |
| send | **sendmsg hook**: sends **SEND**; for queue sends while the watch is on, attaches the recorded window `W` and moves the watch to `buf + len`. |
| scramble hook | Off until the driver posts `{type:'scramble'}`. A hardware **execution** breakpoint (DR0) on the scrambler's in-place byte store (`gepard+off`) fires while the slot still holds the plain body. In LIVE mode the handler finds the packet slot — from a named register or stack arg (`sN` = `[esp+4N]`), or, with `reg:'auto'`, by scanning the general registers for one that points at a slot whose id the driver has a body for — and replaces the body, so the client obfuscates and sends the driver-supplied bytes. Bodies are supplied per id by `{type:'scramble-set'}`, used once or kept (`persist`). DRY reports slot/regs/stack and writes nothing. Shares the debug registers with the send watch (one or the other). |
| send-probe / entry-probe | Research modes of the scramble breakpoint (read-only, one-shot). `--send-probe` walks the stack at the scrambler store and reports return addresses (resolved against file-backed PE ranges; Wine's unpacked code is anonymous). `--probe-entry`/`--probe-at` capture a function's registers + stack args at its entry, optionally gated to a 0437/0438 touching the send queue. Used to map the send path. |
| sendcall | Off until the driver posts `{type:'sendcall'}`. Call-based injection: a one-shot hardware breakpoint at `SendPacket` captures `this` (ecx) and builds a `NativeFunction`; then `{type:'sendcall-emit'}` packets are queued and `SendPacket(this, len, buf)` is called on the **game thread** (drained from the recv/send hooks), so the client builds+encrypts+sends them. `dispose` clears it. |
| startup log | Where `gepard.dll` is loaded; sends **GEPARD** (base) so the driver can set `gepard+off`. |

The message fields are written down in one place: the docstring of `relay/protocol.py`.

---

## 3. The driver (`relay/`)

### 3.1 Modules

| Module | Contents | Used when |
|---|---|---|
| `protocol` | Message tags and fields (the agent contract), `ring_msg`, `sendwatch_msg`, `scramble_msg`, `scramble_set_msg`, `sendcall_msg`, `sendcall_emit_msg`, `conn_of`. | always |
| `agent` | `gadget_ports`, `pick_port`, `pid_of_port`; `Agent`: connects to the gadget, loads the JS, forwards messages, posts, unloads. The only module that imports `frida`. | always |
| `cli` | Options, config-file loading (`relay_capture.conf`), length-table loading, building Relay + WireFilter, `main` (SIGTERM → clean shutdown). | always |
| `runtime` | `Capture`: builds the components the options ask for, starts the threads, routes each agent message (`dispatch`), keeps the send watch pointed at the queue, and — for `--inject` with no scrambler location set — auto-discovers it at runtime and arms the merge. | always |
| `relay` | `Relay`: XKore framing, (re)connecting, discarding the consumer's replies, `--feed-dump`. `PacketAligner`: the old boundary aligner (legacy path only). | unless `--relay ""` |
| `packets` | `load_lengths`, `packet_len`, `WireFilter` (splits each connection's stream into packets, passes the bare account ID, drops unwanted ids, hands out 09fd/09ff as obfuscated items). | default |
| `actors` | `ActorDecrypt`: finds the client's receive ring and accepts a deobfuscated 09fd/09ff copy only with proof it's fresh or its surroundings match; otherwise the packet is dropped. `valid_actor`. | default (`--decrypt-actors`) |
| `wire_feed` | `WireFeed`: queues chunks in arrival order, attaches ring snapshots, runs the feeder thread. `ClientSendFeed`: client→server packets. | default (`--wire`) |
| `sendwatch` | `SendWatch`, `plaintext_guess`, `packet_at`, `send_queue_range`. | default (`--send-watch`) |
| `inject` | `SendInjector`: writes the consumer's "S" packets straight into the client send queue, bounds-checked, dry-run by default in the class. A raw memory-write primitive; valid only for an unencrypted client (encrypted ids need the `scramble` or `sendcall` paths). | `--inject` (unencrypted) |
| `moves` | `MoveTracker`, `unpack_pos2`, `pack_move`: decode the walk **destination** from the server's unobfuscated 0087 (ZC_NOTIFY_PLAYERMOVE) and log it (`MOVE-CHECK`); `pack_move` builds a 035f body. Read-only decode, driver-side. | default |
| `safety` | `LOGIN_SOCK`, `is_game_sock`, the single `looks_like_http`, `redact_login`, `client_packet_to_feed`, `sanitize`. | always |
| `console` | `CaptureLog` (sanitized JSONL log + console line), `show`. | always |
| `memory` | `/proc/<pid>/maps` parsing (`regions`, `region_at`), `ProcessMemory.read`, `ProcessMemoryWriter`. Shared by every memory reader/writer. | whenever memory is used |
| `research` | `ActorProbe` (`--probe-actors`), `ActorDiag` (`--actor-diag`). | research only |

### 3.2 Threads

| Thread | Where | What it does |
|---|---|---|
| Frida callback | `Agent._message` | Puts every agent message on one queue. Nothing else, so the agent is never kept waiting. |
| **worker** | `Capture.run_worker` | One message at a time, in agent order. `RINGSNAP` → attaches to waiting chunks of the same connection. `RECV` → tokenizes, notes obfuscated packets, queues the chunk. `SEND` → redacts, runs SendWatch, feeds the `S` frame (and, while auto-discovering, arms the scramble merge from the recovered scrambler pc). `GEPARD` records the gepard.dll base; `SCRAMBLE` is logged. An exception in one message is printed, not fatal. |
| **wire feeder** | `WireFeed.run` | Sleeps until a chunk is queued. While a chunk is held it polls every 5 ms, lets ActorDecrypt settle it, and feeds finished chunks **strictly in arrival order**. Stats every 30 s. |
| relay connect | inside `Relay` | Connects/reconnects to the consumer once a second, reads what the consumer sends (discarded, or handed to an inject handler). |
| game thread (call-inject) | `drainSendCall` | `--inject-call`: pending consumer packets are sent via `SendPacket` from the recv/send hooks (game thread). |
| short helpers | — | ActorDecrypt's quick ring search; research and legacy scans. |

### 3.3 Shared state and its locks

| State | Writers / readers | Protected by |
|---|---|---|
| `WireFeed.pending` + each chunk's `snaps`, `closed` | worker adds/updates, feeder removes | `WireFeed.cond` |
| each chunk's `res`, `ev`, `tfinal` | feeder only | — |
| ActorDecrypt ring location, stats, `fed` | worker, feeder, quick-search thread | `ActorDecrypt.lock`; code outside the lock reads `base` once into a local, since rediscovery can reset it to `None` at any time |
| ActorDecrypt `stream` | worker writes, feeder reads | replaced with one assignment, never mutated in place |
| Relay socket, aligner, counters | all senders, connect loop | `Relay.lock` |
| WireFilter per-connection state | worker only | — |
| scramble `bodies` map / `scSend` capture | worker posts, agent-side (one JS thread) | agent runs handlers on one thread |

---

## 4. One packet's journey (default mode)

**Server → client (an `R` frame):**
1. The game reads from the socket; the agent sends `RECV` (plus a "before" ring copy).
2. `WireFeed.on_recv` gives the bytes to WireFilter, which splits them into packets. Plain packets
   are ready at once. A 09fd/09ff becomes an "obfuscated" item.
3. The chunk goes into `pending`. If it holds an obfuscated packet, it waits (at most
   `--actor-delay`, 0.15 s) while ActorDecrypt reads the client's deobfuscated copy and checks it.
4. The feeder sends the chunk to the relay, in order, with the verified copy in place, or with
   that packet left out if it couldn't be verified.

**Client → server (an `S` frame):**
1. The game writes a packet into its send queue. If it's an action or skill, the agent's watch
   records the plain bytes being written, then the scrambler rewriting it.
2. On `sendmsg` the agent sends `SEND` with the recorded window and moves the watch to the next slot.
3. `ClientSendFeed` redacts login traffic, then SendWatch returns the plain bytes, the unchanged
   bytes (if the packet wasn't obfuscated), or nothing (dropped).
4. The relay feeds it as an `S` frame straight away; `S` frames need no ordering buffer.

---

## 5. Options → which components run

| Option (default) | Turns on |
|---|---|
| (always) | WireFilter + WireFeed (the only recv pipeline; the old `--no-wire` memory path was removed) |
| `--decrypt-actors` (on) | ActorDecrypt |
| `--send-watch` (on), `--send-queue auto` | SendWatch + the agent's send watch |
| `--feed-send` (on) | `S` frames to the consumer |
| `--relay 127.0.0.1:2350` | Relay (`""` = no the consumer feed, and then no ActorDecrypt either) |
| `--inject` (off), `--inject-dry-run` | the write path: consumer "S" packets → client. Through the scramble merge when a breakpoint is armed (discovered or set), else `SendInjector` into the send queue. The shipped `relay_capture.conf` turns this on. `--feed-send` is auto-disabled while it runs. |
| `--inject-persist` (off) | scramble merge: replace **every** matching client action with the consumer's latest packet of that id, instead of one-shot (just the next one). |
| `--scramble-bp OFF` (off, else auto), `--scramble-reg` (`auto`), `--scramble-idoff`, `--scramble-range`, `--scramble-id`, `--inject-walk X,Y` | agent HW **execution** breakpoint on the scrambler store at gepard+OFF: rewrites the slot's plain body before the client scrambles and sends it (a valid obfuscated packet). With `--inject` and OFF left empty, the breakpoint and its register/offset/range are auto-discovered (see §7). `--inject-walk` writes one fixed walk body (DRY otherwise, logging slot+regs). Disables the send watch (shares the debug registers); 1 register. |
| `--inject-call` (off), `--sendpacket-rva`, `--sendpacket-module` | SPONTANEOUS injection (§8): call `SendPacket(this,len,buf)` so the client sends consumer packets through its own path, replacing nothing. |
| `--send-probe`, `--probe-entry OFF`, `--probe-at ADDR` | research probes (read-only, one-shot): map the send path by capturing a stack walk / a function's entry args. |
| `--probe-actors`, `--actor-diag` | research tools |
| `--feed-dump FILE`, `--out FILE` | copies of the feed / sanitized log |
| `--config FILE` (`relay_capture.conf`) | defaults read from this INI; the command line still overrides (built-in defaults < config file < CLI). |

---

## 6. Behaviour changes in the modular rewrite (2026-10-12)

Same options, same messages, same feed. Differences, all fixes:

1. **Agent: ring snapshots after a socket number is reused.** The `recvmsg` entry hook labelled
   the snapshot with the *cached* server of that fd, so after a login→char→map switch it could be
   tagged with the old server. It now re-checks the socket first. Snapshots also carry `conn`,
   and the driver attaches them only to chunks of that same TCP connection.
2. **Driver crash when the ring was rediscovered.** `before()`, `settle()`, the worker's ring-span
   post and ActorDiag read `ActorDecrypt.base` several times; if another thread reset it to `None`
   in between, a `TypeError` killed the worker thread and the capture silently stopped. They now
   read it once.
3. **Torn reads of the context buffer.** `note_chunk` updated the per-connection wire-byte buffer
   in two steps while the feeder read it; it is now replaced in one assignment.
4. **Full memory scans while no ring is known.** Every held chunk ran a scan of all rw memory,
   immediately, on the feeder thread. Now the feeder waits 30 ms first (the copy needs that long
   to land, and the quick search often wins meanwhile), and after a failed scan the next one waits
   at least 1 s.
5. **Zero-length entries in the length table** made the tokenizers loop forever; such ids are now
   treated as unknown. The legacy aligner also no longer loops on a variable-length field < 4.
6. **One HTTP check** (`safety.looks_like_http`) instead of four slightly different byte lists.
7. **Performance:** table-driven hex in the agent; the feeder sleeps when idle instead of waking
   every 5 ms; snapshots are kept only for chunks still waiting on them; one relay write per chunk;
   the context check only scans nearby obfuscated spans.
8. A `--port` whose process can't be found now exits with a message instead of crashing on
   `/proc/None/mem`.

Tests:
- Project tests: `test_actor_decrypt.py` (unchanged) passes. `test_bidir.py` now imports
  `relay.relay` from this folder; before, it read a hard-coded copy of the old file.
  `test_reorder.py` used to test its own copy of the logic and now runs the same scenarios,
  plus one for HTTP, against the real `LegacyPipeline`. `test_send_watch.py` (unchanged,
  reads `sendbp_queue.jsonl`) passes.
- The agent runs inside the Frida 17.23 gadget (ia32, QuickJS) against real loopback TCP.
- WireFilter, PacketAligner and `ActorDecrypt.settle` were checked against the original code on
  the same inputs.
- WireFeed was run end to end against real process memory.

---

## 7. Injection and auto-discovery (2026-10-13)

The write path now makes the **client's own scrambler** encrypt the injected bytes, and it
configures itself.

**The inject merge.** When `--inject` runs with a scrambler breakpoint, a packet the consumer sends
back (`relay.on_inbound` → `Capture._on_inbound_scramble`) is not written into the queue; its body
is handed to the agent keyed by id (`protocol.scramble_set_msg` → `{type:'scramble-set'}`). The next
time the client builds that id, the scramble breakpoint fires while the slot still holds the plain
body and the handler overwrites it, so the client obfuscates and sends the driver-supplied bytes —
a valid packet with the live key, which `SendInjector`'s raw queue write could never be. By default
the body is used once (the client's own actions resume); `--inject-persist` keeps it and replaces
every matching client action of that id. This only *replaces* client-initiated packets; it does not
inject one out of band.

**Auto-discovery (`--inject` with the scrambler location unset).** Three things are found at
runtime so nothing session- or ASLR-specific has to be configured:

1. **The store pc.** The send watch (on by default) reports the scrambler's write pc on the first
   recovered `0437`/`0438` (`enc`/`enc_off`). The store itself is one instruction earlier
   (`SCRAMBLE_STORE_BACK`), where the full plain body is still present.
2. **The pointer register and id offset.** The breakpoint is armed with `reg:'auto'`; at each hit
   the agent scans the general registers for one that points at a slot whose id it has a body for
   (trying a couple of id offsets), so the register and offset need not be known in advance.
3. **The range.** The recv-ring block `ActorDecrypt` already finds (`send_queue_range`), reused to
   keep the breakpoint off unrelated scrambler hits.

`Capture._autodiscover_scramble` does the hand-off: on that first recovered send it disarms the send
watch (freeing the debug registers), then arms the exec breakpoint on the store with `reg:'auto'`,
the recv-ring range, and the configured persistence. **Bootstrap:** perform one in-client `0437`
action after launch so the send watch can locate the scrambler; injection is armed for the session.
Setting `scramble-bp`/`-reg`/`-idoff`/`-range` pins the values and skips discovery.

**Guards.**
- `--feed-send` is auto-disabled while `--inject` runs: feeding the client's own sends to the
  consumer, which echoes them back, would re-inject them in a loop.
- `SIGTERM` is handled like Ctrl-C (`cli.main`), so `pkill` also runs the agent's `dispose()` and
  clears the debug registers; an armed register with no handler would crash the client.

**Config file.** `relay_capture.conf` (annotated INI, `[capture]` section) supplies defaults so the
tool runs with no launch options; `cli.load_config_defaults` folds it into argparse so the command
line still wins (built-in defaults < config file < CLI). The shipped file enables inject with the
scrambler left to auto-discovery.

Tests:
- `test_scramble_merge.py`: the message contract (`scramble_set_msg`, `scramble_msg` `persist`),
  `_on_inbound_scramble` turning an inbound "S" packet into a per-id `scramble-set`, and
  `_autodiscover_scramble` doing the send-watch → scramble hand-off (store = `enc − SCRAMBLE_STORE_BACK`,
  `reg='auto'`, recv-ring range).
- `test_inject.py` (unchanged) still covers `SendInjector` framing, bounds, dry-run and slot
  placement, and `Relay` deframing of inbound "S" frames.
- The agent's `reg='auto'` locate and the whole merge were confirmed live against the real client
  (discovered `store @ gepard+0x18eff2`, located `reg=ecx, idoff=-2`).

---

## 8. Call-based spontaneous injection (2026-10-13)

The scramble merge (§7) can only *replace* a packet the client itself builds. To issue a packet
spontaneously — with nothing replaced — the driver calls the client's own send routine so the
client builds, encrypts and transmits our bytes through its normal path.

**How the send path was mapped.** The obfuscation is a gepard VM, so the stack near the scrambler
is all gepard frames and a plain stack walk gives stale/ambiguous callers. The reliable signal was
the send watch's *write PCs*: a generic `memcpy` (`gepard+0xa0770`, a normal function) copies the
built packet into the send-queue slot. A one-shot entry probe at that `memcpy`, gated to a
0437/0438 copy into the send-queue block, captured its return address — which is the client's own
send routine, **in `uaRO.exe` code that gepard unpacked into anonymous `rwx` memory based at
`0x401000`** (so it is not a file-backed module; probes resolve it via the mapped ranges). Reading
that routine gave:

```
thiscall  SendPacket(this /*ecx*/, int len /*[esp+4]*/, void* buf /*[esp+8]*/)
          memcpy(this->buf + this->cursor, buf, len); this->cursor += len;   (gepard encrypts + flushes after)
```

**`--inject-call`.** The driver tells the agent where `SendPacket` is (`--sendpacket-rva`, default
`0x816640` from the `uaRO.exe` base, resolved by `--sendpacket-module`). The agent captures `this`
once with a one-shot hardware breakpoint at the entry (no code patching, so no anti-tamper trip),
builds a `NativeFunction`, and for each inbound consumer "S" packet (`Capture._on_inbound_sendcall`
→ `sendcall_emit_msg`) queues it and calls `SendPacket(this, len, buf)` from a **game-thread** hook
(`drainSendCall`, off the recv/send hooks) — never the JS/relay thread.

Verified live: `sit`/`stand` from the consumer are sent and the client acts on them with no client
input and nothing replaced.

**Known limits (work in progress):**
- Injecting `035f` (walk) through this queue path desyncs the encrypted send channel (035f uses a
  separate stack-based path, and the obfuscation carries per-connection state); a relog resets it.
  Walks need their own send routine, and/or the call should go one level up through the function
  that manages the per-packet sequence/counter.
- There is a noticeable latency (~700 ms) because the call is drained only from the recv/send
  hooks; a more frequent game-thread drain point is needed.
