# RO Client Relay

A Linux tool that reconstructs a uaRO client's packet stream and feeds it to an
XKore 1 consumer (such as OpenKore), with an optional write path that injects
client→server packets through the client's own encryption.

The server→client stream is cleartext on the wire except for a few packet
bodies; the client decrypts those into its own memory. A Frida agent hooks libc
`recvmsg`/`sendmsg` inside the 32-bit Wine process and reports what it sees; the
Python driver reassembles a clean, ordered packet stream, filling in the
encrypted bodies by reading the client's **decrypted** copies out of
`/proc/<pid>/mem` (read-only). The result is framed as XKore 1 and fed to the
consumer.

> **Authorized use only.** This reads and (optionally) writes the memory of a
> running game client and injects packets. Use it with a client and server you
> own or are explicitly authorized to test. The injection path is intended for
> client-trust testing against your own emulator.

## How it works

**Receive path (default).** The agent hooks `recvmsg`, copies each received
chunk and periodic ring snapshots, and posts them to the driver. `WireFilter`
tokenizes the cleartext stream per TCP connection; the encrypted actor bodies
(`09fd`/`09ff`) are filled in by `ActorDecrypt`, which locates the client's
decrypted recv ring and verifies each copy (unverifiable ones are dropped, never
guessed). `WireFeed` emits packets to the consumer in exact arrival order.

**Send path.** The agent hooks `sendmsg`. Encrypted client→server packets
(`0437` action, `0438` skill) are recovered to plaintext with a hardware
watchpoint on the send queue (`SendWatch`) and fed as XKore `S` frames;
unrecoverable ones and `035f` walks are dropped (walk coordinates are read
instead from the server's cleartext `0087`). Credentials are redacted
(`safety.py`).

**Inject path (opt-in, write).** Packets the consumer sends back are made to leave
the client, either **spontaneously** by calling the client's own `SendPacket`
(`--inject-call`, nothing replaced) or by **hijacking** the client's next matching
packet at the scrambler breakpoint — *before* the client's in-place XOR — so the
client encrypts our bytes with the live key. See [Injection](#injection-write-path).

## Requirements

- Linux, with the game running as a 32-bit Wine/Proton process.
- [frida-gadget](https://frida.re/) (32-bit) preloaded into the client.
- A Python environment with `frida` (e.g. `~/.venv-frida`).
- Read access to `/proc/<pid>/mem` (same user; `ptrace_scope` permitting).

Attach is via the **gadget** (`LD_PRELOAD`), not ptrace: ptrace-attaching a
32-bit Proton process crashes it (the Wine SIGSEGV handler dies on the dead
`%gs` TLS).

## Setup

Preload the gadget into the client. For a Steam title, set the launch option:

```
LD_PRELOAD=/path/to/frida-gadget/frida-gadget-32.so %command%
```

The gadget listens on a port in `27052–27100`; the driver finds it by matching
the process name (default `uaRO.exe`).

## Running

Drive the consumer's XKore 1 listener (default `127.0.0.1:2350`). Hold stdin
open so the driver doesn't EOF:

```sh
tail -f /dev/null | ~/.venv-frida/bin/python relay_capture_linux.py
```

With no options it reads [`relay_capture.conf`](relay_capture.conf). Every
setting is also a command-line flag, and the command line always wins:

```sh
# one read-only capture, ignoring the config's inject setting
tail -f /dev/null | ~/.venv-frida/bin/python relay_capture_linux.py --no-inject
```

Settings precedence: **built-in defaults < config file < command line.**

## Injection (write path)

There are two ways to make the client transmit the consumer's packets (both for a
client/server you own):

- **Spontaneous — `--inject-call`** (no client packet replaced): the driver calls
  the client's own `SendPacket(this, len, buf)` so it builds, encrypts and sends
  each consumer `S` packet through its normal path. `this` is captured once with a
  hardware breakpoint and the call is made on the game thread. `SendPacket` is at
  `--sendpacket-module` + `--sendpacket-rva` (default `uaRO.exe+0x816640`).
  Bootstrap: do one in-client `0437` action so `this` is captured.
  *Known WIP:* `035f` (walk) uses a separate path and desyncs the cipher if sent
  this way (relog resets it); and there's ~700 ms latency. See `ARCHITECTURE.md` §8.
- **Hijack — scramble merge** (replaces the client's next matching packet): the
  consumer's `S` frames are substituted into the client's send slot at the
  scrambler breakpoint, pre-XOR. This needs to know where the scrambler is and how
  it addresses the packet slot — four values that are **auto-discovered at runtime**
  when left unset:

1. the scrambler store pc — from the send watch, on the first encrypted
   `0437`/`0438` you send;
2. the pointer register and id offset — the agent self-locates them by matching
   the packet id at the breakpoint (`reg=auto`);
3. the heap range — the recv-ring block that `ActorDecrypt` finds.

Nothing session- or ASLR-specific has to be configured. **Bootstrap:** after
launching with inject on, perform one in-client `0437` action (e.g. sit) so the
send watch can locate the scrambler; injection is then armed for the session.
To pin the values and skip discovery, set `scramble-bp`/`-reg`/`-idoff`/`-range`
in the config.

`--inject-persist` replaces *every* matching client action with the consumer's
latest packet of that id (vs. one-shot: just the next one). While `--inject` is
on, `--feed-send` is auto-disabled to avoid a re-inject feedback loop.

## Configuration

`relay_capture.conf` is an annotated INI (`[capture]` section); keys are the
long option names. Point at another file with `--config <path>`; a missing file
just uses built-in defaults. See the file's comments for every setting.

## Modules

Data flows through the `relay/` package in this order:

| Module        | Role |
|---------------|------|
| `protocol`    | message shapes shared with the Frida agent (`relay_hook_linux.js`) |
| `agent`       | Frida connection: find the gadget, load the agent, post to it |
| `packets`     | packet-length table + `WireFilter` (splits a TCP stream into packets) |
| `actors`      | `ActorDecrypt`: fills encrypted `09fd`/`09ff` bodies from client memory |
| `sendwatch`   | recovers plaintext of encrypted client→server packets |
| `wire_feed`   | default pipeline: RECV chunks → ordered, filled-in feed |
| `relay`       | XKore framing + connection to the consumer |
| `inject`      | write path: `SendInjector` plants raw packets in the client send queue (unencrypted clients) |
| `moves`       | decode the server's cleartext `0087` move destination |
| `safety`      | credential redaction and the one HTTP check |
| `console`     | sanitized JSONL log + console lines |
| `memory`      | read/write `/proc/<pid>/mem` (never pauses the game) |
| `research`    | `--probe-actors` / `--actor-diag` tools |
| `runtime`     | `Capture`: builds components and routes agent messages |
| `cli`         | options, config loading, wiring, threads |

The Frida agent is `relay_hook_linux.js`. See `ARCHITECTURE.md` for more detail.

## Tests

Offline tests (no client needed) run against recorded fixtures:

```sh
for t in test_*.py; do python3 "$t"; done
```

## Safety notes

- Memory reads are read-only via `/proc/<pid>/mem`; the game is never paused.
- Login/HTTP traffic is redacted before logging or feeding (`safety.py`).
- The injection path writes to the client only when `inject` is enabled, and the
  breakpoint it uses is cleared on a clean shutdown (Ctrl-C or SIGTERM).
