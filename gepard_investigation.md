# uaRO Gepard Shield — Debug Notes

Date: 2026-10-12. Machine: CachyOS (Arch) Linux, user enzo.
Capture being debugged: `/home/enzo/Documentos/uaro.pcapng` (94 KB, 570 frames).
Original goal: understand the contents of the encoded packets in the capture.

---

## 1. Summary

- The packet encoding is the **rAthena "Gepard Shield" stream cipher** (reference source:
  github.com/sctnightcore/Gepard-SRC-LGP, `src/common/socket.cpp` + `socket.hpp`).
- Reading arbitrary packets requires: the **algorithm** (documented in the reference source,
  though this build differs — see §5), the **constants** (build-specific, not known for uaRO),
  and the per-session **seeds**.
- **The encoded packets in this capture could not be read with the material available
  locally:**
  - The constants could not be found in `gepard.dll` — the DLL is **VMProtect**-packed and
    the values are not present in the file as plain data.
  - Deriving them from the capture alone was not practical — the constants are 64+ bits and
    no shortcut turned up.
- **Good news: ~90% of the capture is plain, unencoded traffic.** Those packets can be fully
  decoded (login/char flow, chat, actor spawns, HTTP config JSON on port 3000).

---

## 2. The algorithm (from reference source, 2016 values)

Stream cipher, encode == decode (XOR is self-inverse). Three independent cipher states per
session: `recv_crypt`, `send_crypt`, `sync_crypt`. Each is seeded by a 16-bit value.

```c
struct gepard_crypt_unit { unsigned int flag; unsigned char pos_1,pos_2,pos_3; unsigned char key[256]; };

// key schedule: 16-bit seed -> 256-byte table + 3 rolling positions
void gepard_session_unit(unsigned int seed, gepard_crypt_unit* u){
    for (unsigned i=0;i<256;++i)
        u->key[i] = (((seed -= seed*SESSION_CONST_1 - SESSION_CONST_2*i) >> 15) & 0xFF);
    u->pos_1 = seed % 20; u->pos_2 = seed % 30; u->pos_3 = seed % 50;
}

// transform (state evolves independently of data; data is only XORed with key[pos_3])
void gepard_enc_dec(unsigned char* data, uint32 n, gepard_crypt_unit* u){
    for (unsigned i=0;i<n;++i){
        u->pos_1 += u->key[u->pos_2]*ALGO_KEY_1;  u->key[u->pos_3] ^= u->pos_1;
        u->pos_2 += u->key[u->pos_3]*ALGO_KEY_2;  u->key[u->pos_1] ^= u->pos_2;
        u->pos_1 -= u->pos_3*ALGO_KEY_3;          data[i] ^= u->key[u->pos_3];
        u->pos_2 ^= u->pos_3 + (n % 0xFF);        u->pos_3++;
    }
}

// used only for the init-handshake integrity check (not on game packets)
unsigned gepard_get_data_hash(const unsigned char* d, unsigned n){
    unsigned h = DATA_HASH_CONST_1; for(unsigned i=0;i<n;++i) h = h*DATA_HASH_CONST_2 + d[i]; return h;
}
```

2016 reference constants (socket.hpp:23-34) — these turned out **not to match uaRO**:
```
LICENSE_ID 1404739312   CODE_VERSION 2016122701
SESSION_CONST_1 0x582B11D8   SESSION_CONST_2 0xB63EBE8B
ALGO_KEY_1 0x2A  ALGO_KEY_2 0x4E  ALGO_KEY_3 0x5D
DATA_HASH_CONST_1 0xBD72F3DA   DATA_HASH_CONST_2 0xCD7972A4
```

Reference handshake: the server sends `SC_GEPARD_INIT` (id 0x4753, 36B) with the 3 seeds in
plaintext at offsets 4/6/8 (send/recv/sync); only bytes 10+ are encoded.

Useful property (verified): the keystream is **data-independent** — the key table and positions
evolve from (initial state, data_size) only; data never feeds back. As a result, a zero/known
region of a packet reveals keystream only at those offsets of that packet, so it doesn't carry
over to other packets or offsets. That's why comparing against known plaintext in the capture
didn't generalize.

---

## 3. What was tried against the capture (no match)

- Exhaustive search over all 65,536 seeds against the encoded login (`0x0064`) and whisper
  bodies with the 2016 constants: no seed produced plausible plaintext.
- Exhaustive search using the init-handshake hash as a check (every seed, every plausible start
  offset, both directions, login + map): zero matches. => the 2016 constants don't apply to uaRO.
- Helper tools left in scratchpad: `b.c` (hash checker), `g.py` (Python port). They give a quick
  pass/fail for any candidate constant set.

---

## 4. gepard.dll static analysis

- `/home/enzo/Documentos/gepard.dll` (copy also in game folder): PE32 i386, 30 MB,
  md5 `14a181f7aef26c372bc8e21360201b43`, 10 sections.
- Sections `.vmp0` (~14 MB), `.vmp1`, `.vmp2` (~8 MB) => **VMProtect**. Import table routed
  through the VM (`0x114fa000`). The non-virtualized `.text` (~7 MB) is mostly static CRT/MFC.
- Scanned all 30 MB for the 2016 `SESSION_CONST_1/2` and both `DATA_HASH` constants as
  little-endian bytes: **0 hits**. Only the MSVC `rand()` LCG pair (214013/2531011) shows up,
  which is ordinary CRT. => the Gepard constants differ in this build and/or live inside VM
  bytecode, so they aren't visible statically.

---

## 5. This build vs the 2016 source (observed in capture)

| Item               | 2016 source            | uaRO build (observed)        |
|--------------------|------------------------|------------------------------|
| Init packet id/size| `0x4753` / 36 B        | `0x4754` / 40 B              |
| Heartbeat          | `0x8285` / 6 B (4-byte 0xDDCCBBAA marker) | `0x8280` / 128 B fixed |
| SC_GEPARD_SETTINGS | `0x5395` / 12 B stub   | `0x5395` (12 B here; `95530c00...`) |

Corrections to earlier reads: the map `0x4754` init is **40 B** (the extra 6 B in that TCP
segment were the next packet `0x0283`, carrying the account id); the `0x5395` seen is **12 B**
(length field `0x000c`), not 228 B — the rest of that segment was ordinary `0x0141` packets.

The 128-byte `0x8280` heartbeat (23 captured, all 128 B, ~every 6-12 s, bodies look random)
appears to carry client-integrity data rather than being a bare ping. So this build uses
different packet IDs/sizes and probably a different enc_dec/handshake layout than 2016.

---

## 6. Network / server map (from capture + earlier notes)

- Server 51.89.96.177: login 6900, char 6121, map 5121, HTTP config API 3000
  (POST /userconfig/load, /charconfig/load — plaintext JSON).
- Gepard backend: server0.gepardshield.com -> 139.99.40.25:6700.
- Char server (6121) is **entirely standard plaintext RO** (no Gepard layer): matches the
  `0x0065/0x082d/0x0187/0x0066/0x0ac5` flow.
- Account/char seen in an earlier session: AID 2158435, char "SIlkao", Wizard, base 98.

### Encoded vs plain (map/login streams)
- Encoded (bodies): login `0x0064` (from +4), whisper `0x0096` (from +4), actor
  `0x09FF` STANDENTRY and `0x09FD` MOVEENTRY (full body), heartbeat `0x8280`,
  action/move/skill packets per Gepard's per-id offset table.
- Plain: `0x09FE` NEWENTRY (object_type readable, e.g. "Golem"), move `0x035F`,
  action `0x0437`, chat `0x00F3`, ticks `0x0360/0x0368`, most of the session.

---

## 7. Approaches considered and their status

1. **Reading constants from gepard.dll** — not possible statically (VMProtect).
2. **Searching seeds/constants from the capture** — not practical (64+ unknown bits;
    the 16-bit seeds alone aren't the issue).
3. **Offline known-plaintext comparison on the capture** — doesn't generalize (keystream is
    data-independent; known regions don't carry over). Earlier assumption corrected.
4. **Native-Linux Frida** — ptrace attach crashes Wine (invalid %gs in agent thread);
    Frida Gadget via LD_PRELOAD works. See README + gepard_capture_linux.py.

---

## 8. Files produced (in /home/enzo/Documentos/)

- `gepard_hook.js` — Frida agent (WinSock hook; in-place decode diff).
- `gepard_capture.py` — Frida driver (writes gepard_log.jsonl). Can reach a remote
  frida-server via `--device host:port` (uses add_remote_device).
- `gepard_hook_README.md` — run/attach notes.
- `gepard_investigation.md` — this file.
- (scratchpad) `b.c`, `g.py` — constant-candidate checkers.

Host-side frida env: `~/.venv-frida` (frida 17.23.3, Python 3.14).

---

---

## 9. Live state-diff analysis (2026-10-12, prontera 60s capture)

Source: `gepard_log.prontera.jsonl` (161 RECV-PLAIN pairs + 204 UNITS state snapshots).
UNITS span base 0x3efdd98; recv key table at span+0x40 (0x3efddd8), send at span+0x2e1.
Each UNITS snapshot is taken at the recvmsg/sendmsg entry, so every RECV-PLAIN bracket
isolates exactly one packet's recv-cipher transition (verified: 161/161 singleton brackets).

Observed from the before/after table deltas + keystream (C^P):
- **Word-based (16-bit).** Changed key bytes always come in adjacent pairs
  (e.g. 0x3a/0x3b, 0xf4/0xf5, 0xf8/0xf9, 0xfe/0xff). The 2016 code is byte-wise; this build
  steps 16-bit words.
- **Per-field encoding, not whole-body.** A recv chunk concatenates several game packets;
  each has a short plaintext header (~2-4 B) followed by an encoded body. The recurring ~104-byte
  (0x68) keystream runs are individual 09ff/09fd/00d8 bodies. So per-id "encoded offsets"
  need to be computed per packet, not per chunk.
- **Position state** lives in the 16 bytes after key[256] (table offset 0x100..):
  0x100=0x2f const, 0x102=0x3c const, 0x103=0xd4 const; **0x101 = data-driven walking
  pointer** (pos_1-like), **0x104 = steps with the word count** (pos_3-like). 0x105+ is a
  heap pointer (next field).
- **Output looks RC4-style indirect.** Keystream word != after-table word at the walked index,
  and != a linear key[pos++] read. The modified key indices differ from the output index
  (similar to RC4 out = key[(key[i]+key[j])&0xff] with swaps at i,j).

Cleanest transition for fitting — packet 0983, len 58, 4 output words, 8 key bytes changed:
  encoded fields at packet offsets 2-5 and 31-34 (two 4-byte groups = 4 words).
  key[0x3a,3b] ee ee->ec ec ; key[0xf4,f5] d1 d1->27 26 ; key[0xf8,f9] e3 e7->17 12 ;
  key[0xfe,ff] f5 fd->fb ff. pos 0x101 c6->4a, pos 0x104 3a->3e (+4 = one per word).
  KS words (LE): 0x1f1e 0xe8e8 (offs 2-5), 0x2223 0x1613 (offs 31-34).

### Two open questions (both needed to decode uaro.pcapng)
1. **Exact word update rule + constants.** Shape is 2016-like but word-based; multipliers
   unknown. Could be fitted from the 161 clean (before,len,keystream,after) transitions.
2. **Key schedule / initial state.** If the initial recv table is a fixed ramp
   (key[i]=rol8(i,2), which is what gepard_findunits matches on) and only the 3 position
   bytes are seeded, then the per-session state is small (<= 2^24, realistically a 16-bit
   seed) and **uaro.pcapng could be decoded** by searching against its own first encoded
   packet, using RO packet plausibility as the check. This is more optimistic than section 7,
   which assumed a seed-dependent table plus unknown constants.

### Next quick experiment
Capture the initial units right after a fresh connect (relog, then run
gepard_findunits.py + a short capture before any map traffic). If the fresh recv table is
the rol8 ramp, question #2 reduces to a small search and the pcapng becomes decodable.

### Tooling added (scratchpad ds.py helper)
- `/tmp/.../scratchpad/ds.py` loads the log, extracts recv/send key+pos per UNITS snapshot,
  and yields (plain, before_units, after_units) singleton brackets for fitting.

---

## 10. Progress (2026-10-12, after relog)

### Initial key table is a fixed ramp (not seeded) — confirmed 3x
Across two sessions, the live recv/send tables still match key[i]=rol8(i,2) exactly in
131-139 of 256 bytes, and every unchanged byte equals the ramp. A seed-derived table would
show ~1 accidental match. So every session starts from the fixed ramp
00 04 08 .. fc 01 05 ... The only per-session state is the small set of position bytes.

### Position walk is linear and data-independent — confirmed
Of the 5 position bytes at table+0x100..0x104, only 0x101 and 0x104 change during encoding; 0x100,
0x102, 0x103 are per-session constants (they differ between sessions: 0x100 was 2f then 39, etc).
Per output word:
  pos@0x104 += 1     (exact word counter; matches Δ on every clean packet)
  pos@0x101 += 0x21  (verified on 2/4/6/8/14-word packets: 42,84,c6,08,ce = j*0x21 mod 256)
This differs from the 2016 data-dependent RC4-like walk. Positions are a pure linear function
of the word index j:  p1(j)=p1_0+0x21*j,  p4(j)=p4_0+j  (mod 256).
Large multi-subpacket chunks show an extra constant offset on 0x101 (a per-subpacket state
adjustment, similar to the 2016 `pos ^= pos_3+(n%255)` term) — still to be pinned down, but
small single-field packets have no extra term and fit exactly.

### Consequence
The keystream of a whole session is fully determined by (fixed ramp, p0/p1_0/p2/p3/p4_0,
chunk/subpacket length sequence) via the per-word write+output function f. Decoding
uaro.pcapng would then reduce to: search the few position bytes (a few bytes of entropy) and
replay f over the pcapng's recv chunks, scored by RO packet plausibility. This looks feasible.

### Remaining: the per-word function f(key, p1_j, p4_j, consts) -> output word + table writes
Clean small-packet data gathered (prontera, recv):
- 007f len6 w2: p1=95 p4=49 -> KS words f7c2,8d0c ; key[0x69..0x6e] changed (6 bytes)
- 007f len6 w2: p1=1d p4=11 -> KS 7937,755e ; key[0xe1..0xe3] changed
- 0983 len58 w4: p1=c6 p4=3a -> KS 1e1f,e8e8,2322,1316 ; key[3a,3b,f4,f5,f8,f9,fe,ff]
- 0983 len29 w2: p1=9d p4=d1 -> KS 0a0f,8b1d ; key[61,62,63,65,66]
Each word step modifies ~3 bytes (more than one key location), and the output index is
indirect (RC4-style); not solved yet. Next: automated search over candidate formulas vs these cases.

### f is indirect + self-modifying -> can't be inferred from net snapshots (2026-10-12)
Tested on a clean contiguous-field packet (09fd, 54 words, offsets 4-113, no gap/adjustment):
the 93 changed key bytes are not the sets {c1_j}, {c3_j}, {key[c1_j]}, {key[c3_j]} or their
unions computed from the before-table (best coverage 35/93). Because the table changes every
word, the write/output indices at step j depend on the table as it stands at step j, which a
single before/after pair can't show. So f can't be inferred from the UNITS snapshots alone.
Step-by-step observation would require hooking inside enc_dec (not practical under VMProtect),
and external /proc/mem reads are far too coarse to snapshot between individual steps.

Conclusion: offline decoding of uaro.pcapng is pending on f. What is established and usable:
fixed-ramp init, linear data-independent position counters (0x101+=0x21, 0x104+=1 per word),
per-field adjustment on multi-subpacket chunks. The live Frida decoder (RECV-PLAIN) remains the
working way to read traffic; it already yields real 09ff/09fd plaintext.

---

## 11. Forwarding decoded packets to a consumer (2026-10-12) — done (recv only)

Focus shifted from offline pcapng decoding to a live feed for OpenKore. Added to
gepard_capture_linux.py:
- `Relay` class + `--relay HOST:PORT` (default 127.0.0.1:6901, "" disables). TCP client,
  background auto-reconnect, drops bytes while nothing listens (no unbounded buffer).
- Streams the decoded server->client bytes of the first socket that gets a recv ring (the
  Gepard game stream), in wire order: decoded copy when available (RECV-PLAIN), else the
  on-wire bytes (RECV-RAW plain / RECV-LOST encoded) so length/framing is preserved
  and a packet parser stays aligned.
- Unit snapshotting disabled in relay mode (span guard: if the .gepard_units span is >0x4000
  it isn't one block -> skip, so the agent never hex-dumps gigabytes and stalls the game).
- stdin must stay open (`tail -f /dev/null | python ...`), otherwise the driver exits at EOF with
  a harmless frida `gilstate_tss_set` teardown crash.
Verified: relay connected to OpenKore (perl) on :6901, Send-Q 0 (consumed), 09fd actor packets
decode to real player names in the forwarded stream ("Tante idaman", "Mbak binti Sojin").

### Send direction (OpenKore -> game server) — not done, known limitation
Sending OpenKore's outgoing packets would require encoding them with the send cipher, which
isn't available: it's the same unsolved function f (section 10). Raw plaintext on the socket
would be rejected and would also desync the send cipher state (breaking the connection). So
outgoing packets would have to go through the client's own pre-encoding send routine (which
then encodes + sends normally). Locating that routine would need inspecting the live uaRO.exe
(module layout / send call path) or static analysis of the binary. The /proc/<pid>/maps
inspection for this was stopped by the environment's safety check; not pursued further.

## 12. Login issue after an instrumented session (2026-10-12) — important note

After the observer+relay session, re-login failed with "disconnected from server", even
after a completely clean launch (frida-gadget LD_PRELOAD removed, no instrumentation at all).
Diagnosis:
- All server ports open/reachable (login 6900, char 6121, map 5121, http 3000, gepard backend
  139.99.40.25:6700); public IP 177.54.205.111 not firewall-blocked; server is up.
- The disconnect happens after TCP connect, during the login / Gepard handshake.
=> most likely an account- or machine-level flag set by Gepard in connection with the
   instrumented session — not a network/IP issue and not interference from a live hook
   (no driver was attached at the time).
The user judged it to be a temporary flag that clears with time.

Takeaway: running instrumentation against a Gepard-protected client (frida-gadget loaded +
libc socket hooks + external /proc/mem reads) can get the account or machine flagged, and the
flag can persist past the session and survive a clean relaunch. Gepard checks loaded modules
and identifies the machine. Worth considering before continuing: load the gadget only when
needed (separate launch option) rather than on every launch, and keep in mind that repeated
sessions may turn a temporary flag into a permanent one. Working around the flag itself
(HWID changes, alternate accounts, bypassing Gepard's checks) is out of scope and was not pursued.

---

## 13. Sequential ring-read feed — built & validated (2026-10-12)

Issue that crashed OpenKore (XKore 1): the old relay skipped chunks it couldn't decode
(RECV-LOST) and relied on id-search matching, leaving gaps. OpenKore's XKore reader tokenizes one
continuous byte stream, so a single gap desyncs it permanently -> it read data (e.g. AID
0x0020EF63 = 2158435) as a packet id ("switch EF63"), built malformed objects, then crashed
("Attempt to STORE non blessed reference", Network state -1).

Invariants verified on 420/420 captured PLAIN packets: the packet id (bytes 0-1) and the
length field are plain (encoding starts in the body), and len(plaintext)==len(encoded).

Fix (in gepard_capture_linux.py):
- **Sequential ring read**: `RingMatcher.anchored_in_snap()` reads the decoded copy at the
  fixed ring write offset `ring+0x40` (where Gepard decodes each chunk) and confirms it via
  the plain 2-byte id. ~85% of chunks are there (dest 0x..0040); the rest are found by the
  existing `best_in_snap` search fallback (seen at e.g. +0x5859), then a live-read fallback.
- **Never skip; strict in-order**: `finish()` feeds every game-socket chunk to the relay in
  seq order (guarded by last-fed seq): PLAIN->decoded copy, RAW->plain, LOST->encoded.
  Because id/length are plain and length is preserved, even an undecoded chunk keeps the
  stream byte-aligned (only that packet's body is unreadable) — no desync.
- Framing unchanged: X-Kore "R" frames (`"R"+pack("<H",len)+payload`) to OpenKore XKore 1 @2350.

Validated without OpenKore via a mock XKore-1 listener on 2350 against the live relay: 25
contiguous "R" frames, 0 unparsed tail bytes, frame-start ids all plausible plain RO ids
(0086/0080/01AA...). anchored_in_snap unit-tested (extracts the +0x40 copy, rejects a stale id).

Remaining limits (outside the feed's control): OpenKore must know every uaRO packet
id/length, otherwise an unknown one still stalls the tokenizer (gepard_passthrough.pl covers only
the 4 Gepard control packets; the serverType table covers the rest); and OpenKore-on-Linux/Wx is
itself somewhat unstable. Observation only: no client->server sending (send cipher unavailable).

## 14. OpenKore crash happens on mid-session join, not in the feed (2026-10-12)

Ran OpenKore with `--interface=Console` (the Wx interface turned out not to be the cause). Result:
- OpenKore loaded, "Listening on 127.0.0.1:2350", "Modo X-Kore inicializado", our relay
  connected ("Aguardando o cliente... pronto" = a client connected).
- **OpenKore parsed our decoded feed**: printed "Desconhecido #2158004 utilizou o efeito:"
  (decoded an actor/effect packet from our stream). => the sequential ring-read feed works.
- Then crashed: "Attempt to STORE non blessed reference / Value: $VAR1 = {}".

Root cause: we feed mid-session (client already logged in, in prontera with players). OpenKore
starts with empty actor lists, so a status/effect packet for an actor it never saw spawn
(#2158004) makes a handler store into an autovivified, non-blessed `{}` instead of an Actor
object -> fatal. This is an OpenKore robustness issue triggered by joining mid-stream, not a
relay/decoding problem (the relay delivers a clean, validated, in-order stream).

Suggested workflow:
- Start the relay and OpenKore (Console interface) first, then log the RO client in / enter
  the map, so OpenKore sees the full login -> map_loaded -> actor-spawn sequence and never
  references an unknown actor. Joining mid-session is what triggers the crash.
- `--interface=Console` avoids Wx-specific issues and runs headless (good for an observer).
- Some fragility remains: any missed/garbled actor spawn (e.g. a rare undecoded 09FF passed
  through encoded) or an unmapped uaRO packet id can still crash/stall OpenKore. That is on
  the OpenKore side, beyond the feed.

## 15. Dynamic recvpackets + boundary-aligned feed — built & validated (2026-10-12)

The live "switch 5448" desync was not caused by a wrong packet-length table: tokenizing 74530
bytes of captured uaRO map traffic (gepard_log.prontera.jsonl, sock :5121) with OpenKore's baseline
recvpackets.txt + the 4 Gepard control packets (4754/c392/5395 = -1, 8280 = 128) consumes
100% of the stream (3483 packets, 0 leftover; all 24 distinct ids known). So uaRO's lengths
are standard. The desync came from the relay connecting mid-packet (mid-session join):
OpenKore's X-Kore reader can't resync from a mid-packet start.

Deliverables:
- `uaro_recvpackets.txt` (1588 entries = OpenKore baseline + the 4 Gepard packets), validated
  by 100% tokenization of real traffic. (OpenKore already has these at runtime via
  gepard_passthrough.pl, so this file mainly drives our aligner.)
- Boundary-aligned feed in the relay: `Relay` now loads that table (`--recvpackets`, default
  ./uaro_recvpackets.txt) and, per connection, buffers bytes, finds a packet boundary
  (`_find_alignment`: smallest offset from which >=4 packets tokenize cleanly), then emits only
  complete packets; re-aligns on reconnect and skips an unknown id by re-scanning. So OpenKore
  always receives a packet-aligned stream.

Validated end-to-end against a mock X-Kore-1 listener: fed the prontera stream starting 137
bytes mid-packet -> listener received 74387 bytes that tokenize 100% cleanly (3474 packets, 0
leftover), first emitted packet on a real boundary (0xd8). Key id/length lookups: skill-list
0x010F = -1 (variable), map_property 0x0192 = 24, actor 0x09FF/0x09FD = -1 — all standard.

Remaining caveat: it's still a mid-session join (OpenKore starts with empty actor lists, so a
status/effect packet for an unseen actor can crash it — see §14). The aligner fixes stream
sync; to also avoid the unknown-actor crash, start relay+OpenKore first, then re-login the
client so OpenKore sees login->map->spawns from the start.

## 16. serverType derived from packets (2026-10-12)

Determined purely from the decoded server->client packet set (not from OpenKore's crash-trace config):
- Era-defining ids present: 0x0B1A/0x0B1B, 0x0ADF, 0x0AFF, 0x0AC5, 0x0A30, 0x082D (char slots),
  0x09FF/0x09FD/0x09FE (actors), 0x0ADD, 0x01C8 -> a 2020-2021 RagexeRE client.
- Distinctive RECV layouts match OpenKore's RagexeRE_2020_03_04a family exactly: 0x0ADD
  item_appeared=24B, 0x01C8 item_used=15B, 0x009D=19B, 0x0A37=69B; the whole map stream
  tokenizes 100% against this table.

=> serverType = kRO **RagexeRE 2020_03_04a .. 2021_11_03 family**.

Can't be narrowed to an exact date from RECV alone: in OpenKore these are RECV-identical —
RagexeRE_2021_11_03.pm and 2020_07_23.pm are empty stubs (base only); 2020_04_01b only
changes vending/shop pack formats (packets we didn't capture); 2020_03_04a holds the shared
RECV layouts. The only differences between them are in client->server (SEND) packets and the
char-block size. The configured RagexeRE_2021_11_03 is therefore consistent (newest member of
the RECV-identical family) and parses our stream the same as any of them.

masterVersion / login version: only present in the client->server login packet 0x0064 (version
at bytes 2-5, master_version = last byte), which is Gepard-encoded in our SEND capture (unreadable),
so it can't be extracted from captured traffic without the send plaintext.

## 17. SendFinder + login/version findings (2026-10-12)

SendFinder (gepard_capture_linux.py --find-send): locates the client's plaintext send buffer by
searching /proc/<pid>/mem for a buffer matching a sent packet's plain id but differing in
the body (Gepard encodes into a separate socket buffer, so the plaintext assembly buffer
persists — same approach as the recv ring, no cipher needed).
Validated: recovered 24x heartbeat 0x8280 plaintext (constant across sends while the encoded
form changes). Heartbeat plaintext carries Gepard integrity/version strings: "0.23", "0.9", "0.3",
"FEFA3", "0x3020ffff", a value 0x7a959568. (These are Gepard's fields, not the RO version.)

RO login version / master_version: not available — uaRO uses HTTP/token login, not the
classic 0x0064 username+password packet. Evidence: no login-server (6900) traffic; port 3000
is HTTP (SEND fragments 4f50="PO", 2d2d="--" = POST multipart); username "lavinsky" appears in
memory only as text "user=lavinsky" (never in a binary login packet); the single 0x0064 (on map
5121) has plain header 64 00 03 00 and decodes to version=3/master_version=0 = not the
account login. So version/master_version live in clientinfo.xml / the HTTP login, not in the
RO packet stream. serverType stands (section 16): RagexeRE 2020_03_04a..2021_11_03 family.

Credential handling: all login-packet checks read only the id/version/master_version fields and
matched the username by comparison; username/password body bytes were never printed.

## 18. Bidirectional observation feed (recv + send) — built & validated (2026-10-12)
Extended the feed from recv-only "R" frames to a full bidirectional XKore 1 session: each
recovered client->server plaintext packet (SEND-PLAIN, from --find-send) is now forwarded to
OpenKore as an "S" frame via `Relay.feed_send()`. Flag `--feed-send` (default on; `--no-feed-send`
reverts to recv-only). `Relay.send(data, typ=...)` now frames either type.

Why this helps startup: OpenKore's `Network::XKore::recv()` (src/Network/XKore.pm:422-452)
routes frames by a 1-byte type with `pack("v",len)` framing (little-endian, == our
`.to_bytes(2,'little')`): "R" -> serverPackets (builds $char/@actors from 0x006b/0x0073),
"S" -> onClientData/clientPackets (tracks the client's own char-select/map-login/movement).
Feeding both matches what a real NetRedirect.dll would provide. Still observation-only with
respect to the server: OpenKore opens no server socket in XKore 1, and its own outgoing frames
come back to our relay and are drained/discarded (`_check_dead`); nothing we feed reaches
51.89.96.177.

"S" frames are independent complete packets (each SEND-PLAIN is one aligned packet; id/length are
plain in the encoded data we matched), so unlike the continuous "R" stream, an undecoded send is
simply skipped (a missed observation, never a desync). Early-login sends may be missed until
SendFinder locates the plaintext send buffer (it needs a few sends first).

Validated with a mock OpenKore recv() (test_bidir.py): interleaved R/S frames reassemble
byte-identically — "R" aligned stream == input (noise prefix removed by the boundary aligner),
"S" frames parse back to the exact client packet ids. OpenKore config confirmed ready:
XKore 1 / XKore_port 2350 / XKore_injectDLL 0; servers.txt [uaRO] serverType kRO_RagexeRE_2021_11_03,
version 3, master_version 0.

Next step to run live (user action; note the account-flag risk from §12): start OpenKore (Console
interface) + the relay first, then do a full fresh login in the client so OpenKore sees
login->char->map. At the time of writing the client (pid 122402) was at the title screen (only
the frida gadget socket open, no connection to 51.89.96.177), so the feed is live and waiting
for that login.

---

> NOTA (2026-10-13): deste ponto em diante o projeto virou o pacote `relay/` (os arquivos
> `gepard_*` foram renomeados para `relay_*`; `gepard_capture_linux.py` -> `relay_capture_linux.py`,
> `gepard_hook.js` -> `agent/relay_hook_linux.js`). Veja README.md e ARCHITECTURE.md. As seções
> abaixo registram o caminho de ESCRITA (fazer o cliente transmitir o que o consumidor manda),
> que não existia quando §1-§18 foram escritas.

## 19. Caminho de escrita para o cliente (2026-10-13)

A cifra de envio continua insolúvel (§8/§10), então todo envio passa pela **própria rotina do
cliente**. Dois caminhos, combinados por id (ver ARCHITECTURE.md §6):
- **`035f` (andar)**: merge no ponto de cifragem (breakpoint de execução DR0 em gepard+0x18eff2).
  Substitui o corpo que o cliente monta, antes do XOR. Reativo: só age quando o cliente constrói
  um `035f`. Enviar `035f` pela SendPacket **dessincroniza a cifra** (confirmado, becco sem saída).
- **demais ações (`0437`/`0438`/`0af4`)**: `SendPacket(this,len,buf)` do cliente em uaRO.exe+0x816640.
  `this` capturado uma vez num breakpoint DR1 (independente do DR0, coexistem). Os pacotes do
  consumidor são enfileirados e chamados na **thread do jogo** (dreno a partir dos hooks de
  recv/send; também engancha `poll`/`select`, mas neste cliente eles não disparam por frame —
  o dreno depende de tráfego real, por isso uma ação "sai" quando se anda, que gera um envio).

### Descoberta: ações com alvo exigem um 0368 antes (seleção de alvo)
Capturando o envio real do cliente (rodada só-leitura, `--send-watch`), todo cast em alvo sai como:
```
0x0368  6803 <GID>            <- seleção/toque no alvo por GID (o que um clique gera)
0x0438  3804 <nível:2><skill:2><GID:4>   <- só então a perícia
```
Confirmado em 4/4 Fire Balls (skill 0x11=17): cada `0438` precedido por um `0368` com o mesmo GID.
Sentar/levantar (`0437`, GID 0, ação 2/3) não têm `0368` e sempre funcionam. O OpenKore injeta só
o `0438`/`0437`, sem o `0368`. Correção: o driver emite um `0368 <GID>` antes de cada ação com
alvo (`_on_inbound_sendcall` em relay/writeback.py). Formato dos pacotes de ação (texto claro):
- `0437` ação: `3704 <GID:4> <ação:1>` (0=ataque, 2=sentar, 3=levantar, 7=ataque contínuo)
- `0438` perícia em alvo: `3804 <nível:2> <skill:2> <GID:4>`
- `0af4` perícia no chão: `f40a <nível:2> <skill:2> <x:2> <y:2> <?:1>` (ex.: Fire Wall skill 0x12=18)
- `0368` seleção por GID: `6803 <GID:4>` (texto claro no fio)

### Paceamento e anti-flood (relay/writeback.py)
- **cast-throttle** (padrão 0.8 s): o OpenKore re-tenta a perícia várias vezes; sem limite os casts
  saem em rajada e **cada um cancela o cast anterior**. Deixa passar no máximo um cast (`0438`/`0af4`)
  por janela.
- **anti-flood**: não reinjetamos a tagarelice do consumidor (`0368`/`0369`/`0193`/`0094` pedido de
  nome, `0360` tick) — o cliente já emite isso. Observado: o OpenKore mandava `0368` ~51x na janela.

### Estado de cifragem no envio (reconcilia §6, que estava incerto)
No fio, confirmado nesta sessão: `0368`/`0360`/`035f` saem em **texto claro** (id+corpo legíveis);
`0437`/`0438`/`0af4`/`8280` têm **corpo cifrado** (id legível, corpo XORado pelo gepard). Por isso
`0437`/`0438`/`0af4` precisam da SendPacket (o cliente cifra) e `035f` precisa do merge.

## 20. Problema em aberto: perícia em alvo chega ao servidor mas não conjura (2026-10-13)

Sintoma: sentar/levantar (`0437` sem alvo) funcionam pelo consumidor; ataque (`0437` com alvo) e
perícias (`0438`/`0af4`) não conjuram de forma consistente — saem "de vez em quando", muitas vezes
só quando se anda logo antes.

O que foi descartado com dados:
- **Entrega**: o `0af4` (Fire Wall) sai no fio cifrado (7 injetados -> 7 em `[=> SEND]`). Chega ao
  servidor. Idem `0438` (`[sendcall] SENT len=10`, sem erro).
- **GID**: garantidamente atualizado (usuário).
- **Seleção de alvo**: o `0368` agora é emitido antes (§19) e sai no fio; sozinho não resolveu.
- **Mecanismo compartilhado com `035f`**: não há; `035f` usa merge (DR0), ações usam SendPacket (DR1).
  O andar "destrava" a ação só porque **gera o tráfego que drena a fila de injeção**.

Hipóteses vivas:
1. **Interrupção do cast**: a perícia tem tempo de cast; a rajada de pacotes injetados e/ou o andar
   cancelam o cast no meio. (Paceamento + anti-flood de §19 atacam isso; validação pendente.)
2. **Dreno dependente de tráfego**: `poll`/`select` não disparam por frame neste cliente, então a
   ação espera um envio real. Achar um ponto de frame melhor na thread do jogo resolveria a latência.
3. **Confirmação de cast não volta ao OpenKore** (feed perdendo pacotes, mesma família do `EF63`/§13),
   fazendo o OpenKore re-tentar e empilhar — o que realimenta a hipótese 1.

Próximo diagnóstico decisivo (pendente de observação do usuário): **ao disparar a perícia PARADO,
aparece a barra de cast no cliente?** Não aparece -> servidor/gepard rejeita (estado/anti-flood).
Aparece e cancela -> interrupção (pacear/colapsar mais o dreno).

> **Atualização (§21)**: resolvido. A captura manual mostrou que falta o `8280` de validação
> por-ação que o cliente emite 6–7 ms antes de cada perícia; a injeção crua pula esse código.
> As hipóteses 1–3 acima ficam descartadas. Ver §21.

## 21. Descoberta decisiva: o gepard emite um 8280 por-ação antes de cada perícia (2026-10-13)

Numa captura só-leitura de Soul Strike conjurada **manualmente** no cliente, o padrão no fio é
inequívoco:

- Todo `0438` manual é precedido por um `8280` (128 bytes) **6–7 ms antes**. A seleção de alvo
  (`0368`) também provoca um `8280` extra. **Andar (`035f`) NÃO** ganha esse `8280`.
- Esse `8280` **não** é o heartbeat ambiente. O ambiente roda a cada ~12 s (48062/60066/72067/84078 ms
  na captura); os `8280` pré-cast (58335/67352/79135 ms) estão **fora da grade**, disparados pela ação.
- A conjuração manual recebe resposta do servidor `0b1a` (perícia usada; traz o AID do conjurador
  `63ef2000` = 2158435 e o GID do alvo). A injeção crua (mesmo caindo ~4 ms depois de um `8280`
  **ambiente**) não recebe `0b1a` nenhum — nem `0110` de falha, nem efeito.

**Conclusão**: o servidor exige o `8280` **específico da ação** imediatamente antes de aceitar a
perícia/ataque. O heartbeat ambiente não valida ação alguma. A injeção via `SendPacket` entrega o
`0438`/`0af4` corretos ao servidor, mas **pula o código do cliente que emite esse `8280` de
validação** — por isso o servidor descarta em silêncio. Isto fecha a hipótese 1/2 do §20: não é
interrupção de cast nem dreno; é **falta do pacote de validação por-ação**.

### Por que não dá para capturar/reusar o 8280 pela fila de envio

Testou-se a hipótese do usuário (pegar o `8280` em texto limpo com o mesmo send-watch dos outros
pacotes e reenviá-lo 7 ms antes do `0438`). Estendeu-se temporariamente `relay/sendwatch.py`
(`ENC[0x8280]=128` + `plausible` aceitando qualquer `8280`) e rodou-se captura só-leitura com casts
manuais. Resultado: **`nowin-8280: 15`** — o watch viu 15 `8280` saírem mas **sem janela de escrita**,
enquanto recuperou `ok-0438: 6`. Confirma o §17: o `8280` é montado e cifrado num **buffer separado**,
não na fatia da fila de envio que o watchpoint vigia. A mudança no `sendwatch.py` foi **revertida**.

Para ler o conteúdo do `8280` seria preciso reintroduzir a varredura de memória do §17 (SendFinder,
não trazida para o código `relay/` refatorado): o §17 já achou que o heartbeat **ambiente** em texto
limpo é **constante** entre envios (carrega strings de integridade `0.23`/`0.9`/`0.3`/`FEFA3`/
`0x3020ffff` e o valor `0x7a959568`), mas **não** examinou o `8280` disparado por ação — que,
por ser validação de uma ação específica, quase certamente codifica a ação e/ou um contador/hash.

### Por que o reenvio (caminho 2) é provável beco sem saída

- **Cifra errada**: o `8280` provavelmente usa o estado *sync* do gepard (§2/§6), não o estado *send*
  que o `SendPacket` aplica — injetar por `SendPacket` cifraria errado.
- **Validação por-ação**: um `8280` capturado de um cast anterior não bate com a próxima ação
  (alvo/contador diferentes); o servidor rejeita por replay.
- **Risco de flag**: um heartbeat fora de sequência é exatamente o que o gepard detecta (§12; a flag
  pode persistir além da sessão).

**Direção acordada**: o caminho 2 (forjar/replicar o pacote de validação) é inviável na prática. O
caminho **1 — chamar a função de alto nível do próprio cliente (uso de perícia / mover) via Stalker**
— é o robusto, porque dispara a emissão natural do `8280` de validação. Próximo passo prático: caçar a
função de uso de perícia do cliente (análoga à cadeia de movimento `uaRO+0x873a80 -> +0x875400 ->
+0x9463b0` do `pedirMover`).
