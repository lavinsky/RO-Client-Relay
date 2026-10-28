# Client discovery

The relay must never assume that a Ragnarok client exposes the same static
metadata as the current uaRO build. Client discovery is therefore a layered
process whose result carries both its source and confidence.

## Discovery ladder

1. **Static RTTI / structure discovery**
   - Parse the PE on disk.
   - Recover MSVC RTTI/vtables when present.
   - Locate `CGameMode::SendMsg` from redundant evidence rather than one byte
     signature.
   - This is the preferred path because it is deterministic and entirely
     offline.

2. **Exact known-build profile**
   - If static evidence is unavailable, compare the executable fingerprint
     against `profiles/*.json`.
   - A profile is accepted only for an exact compatible fingerprint.
   - Profiles are not fuzzy guesses and must not silently match another build.

3. **Behavioral passive discovery**
   - Used for stripped, packed or virtualized clients where useful RTTI/CFG
     structure is unavailable on disk.
   - Capture several bounded `uaRO -> uaRO` call-edge windows for each known
     action, plus idle baseline windows.
   - Current recommended labels: `baseline`, `move`, `attack`,
     `skill_target`, `use_item`.
   - Keep edges recurring in repeated runs of the same action, subtract
     idle-stable edges, then rank internal callees shared by several actions.
   - A result is a **candidate ranking**, not a callable dispatcher.

4. **Per-action compatibility adapters**
   - If Themida/VMProtect hides the shared dispatcher behind a VM interpreter,
     or behavioral candidates remain ambiguous, do not invent a dispatcher.
   - Keep the already validated per-action native routes (input/carrier,
     merge, SendPacket, or another profile-defined adapter).
   - Generalization is allowed to degrade gracefully instead of becoming
     unsafe or brittle.

## Promotion rule

No behavioral candidate may be called automatically. Before it becomes a
profile dispatcher, it must be validated passively across multiple actions and
must show a stable client object/calling convention and sane action-dependent
arguments. Idle-only explanations and VM-interpreter entry points are not
sufficient.

## Tooling

`tools/discover_client.py CLIENT.EXE` tries the offline ladder automatically.

The relay also exposes an integrated interactive fallback. Prefer `auto`: it performs the
static/profile preflight first and opens the wizard only when those methods are insufficient.

```text
python3 relay_capture_linux.py --discovery-wizard auto --client-exe /path/to/client.exe
```

To deliberately recollect a known build:

```text
python3 relay_capture_linux.py --discovery-wizard force --client-exe /path/to/client.exe
```

The wizard requests the loaded module range from the Frida agent, then collects three repeated
windows for `baseline`, `move`, `attack`, `skill_target` and `use_item`. Each step is persisted
immediately, so an interrupted session retains completed evidence. The default output is
`research/client_discovery/<sha12>-traces.json`; the candidate ranking is written beside it as
`<sha12>-traces.result.json`.

Useful controls are `--discovery-runs`, `--discovery-trace-ms`,
`--discovery-arm-delay-ms` and `--discovery-out`. The wizard never calls a discovered candidate.

For previously collected traces, provide a JSON trace set directly to the offline tool:

```text
python3 tools/discover_client.py CLIENT.EXE --trace-set traces.json
```

The trace set contains repeated runs, for example:

```json
{
  "baseline": [{"chamadas": ["0x10>u0x20"]}],
  "move": [{"chamadas": ["0x100>u0x500"]}],
  "attack": [{"chamadas": ["0x200>u0x500"]}],
  "skill_target": [{"chamadas": ["0x300>u0x500"]}],
  "use_item": [{"chamadas": ["0x400>u0x500"]}]
}
```

Real collection should use at least three separate windows per label. A single
known action should occur in each action window.

The current uaRO executable still resolves through the first path
(`static-rtti`) at `CGameMode::SendMsg` RVA `0x886740`. The behavioral fallback
exists for other builds and must not weaken the confidence of the working
static result.

## Current uaRO live validation (2026-10-22)

The initial semantic mapping used a short Stalker observation, but a later Stalker research run crashed
the protected client. **Live research on this build must therefore use hardware breakpoints only; do not
use Stalker or research Interceptor hooks.** The existing socket hooks used by the production relay are a
separate, already-established path and were not the cause of this research crash.

Hardware execution breakpoints subsequently confirmed the relevant call boundaries with sub-millisecond
to 1 ms handlers. The switch table and packet builders establish the current semantic IDs:

| semantic action | SendMsg id | packet | evidence |
| --- | ---: | ---: | --- |
| targeted skill | 69 | `0x0438` | live HW breakpoint + static builder; natural high-level caller is case 113 |
| ground skill | 70 | `0x0AF4` | static builder; live confirmation pending |
| attack | 137 | `0x0437` | live correlation + static builder |
| move | 138 | `0x035F` | live HW breakpoint + static builder |
| use item | 27 | `0x0439` | static builder; live confirmation pending |

### Gepard runtime vtable hook

The on-disk `CGameMode` vtable has slot 6 (`+0x18`) pointing to original
`CGameMode::SendMsg` at `uaRO.exe+0x886740`. In the live process the same vtable slot is patched to
`gepard.dll+0x10A90`. A hardware breakpoint on the original function, filtered to message id 69,
captured a return address inside Gepard's `.vmp0`; a second hardware breakpoint on
`gepard+0x10A90` captured the same `SendMsg(69, skill, target, level, 0)` arguments and a natural
uaRO caller in case 113.

This explains the outbound behavior:

- Directly calling original `uaRO+0x886740` is **refuted** as an injection boundary. A movement test
  built the correct `0x035F`, but its body reached the socket as plaintext. RX remained normal and the
  session did not disconnect; the failure was isolated to encrypted outbound processing.
- Directly calling `gepard+0x10A90` is also **refuted** as an injection boundary. It returned normally
  but produced no send, showing that Gepard requires additional natural caller/stack/context.
- The validated movement dispatcher at `uaRO+0x9473B0` remains a valid boundary because it reaches the
  patched virtual slot through the client's natural chain. A hardware breakpoint at the natural move
  callsite captured `SendMsg(138, x, y, 0, 0)`, followed immediately by an encrypted `0x035F`.

`SCRAMBLE` telemetry is also unambiguous: `body` is the client's natural carrier body observed before
replacement; `wrote` is the consumer/OpenKore body written into that slot. Do not use `body` as the
requested OpenKore target when reconstructing an action.

An experimental attempt to synthesize targeted-skill dispatcher state using codes `0x5A -> 0x29 ->
0x2A` did not produce a send and is **not a validated recipe**. It has been removed from the live code.
Future action research should observe natural state with hardware breakpoints instead of reconstructing
internal state by trial.

These action IDs and offsets belong to this fingerprinted build and must not be copied to another client
without discovery/validation.

### Gepard wrapper above `CGameMode::SendMsg`

Live hardware probes established the missing outer boundary for a natural targeted-skill call. At
`CGameMode::SendMsg` entry, the immediate return address was `gepard.dll+0xA23D7A`; the instruction at
`gepard.dll+0xA23D78` is `call eax`, with `eax` equal to the discovered `SendMsg` entry. This is why a
static PE xref search does not expose the caller.

A second read-only probe at that callsite captured a conventional protected-wrapper frame:
`[ebp+4] = gepard+0x9602DB`, followed by `[ebp+8..] = this, id, a2, a3, a4, a5`. The caller bytes at
`gepard+0x9602D6` are a direct `call gepard+0xF07FEF`, followed at the return site by `add esp,0x18`.
The protected wrapper is therefore modeled as `cdecl wrapper(this, sendMsgId, a2, a3, a4, a5)`.

The wrapper entry at `gepard+0xF07FEF` immediately enters heavily protected/virtualized control flow.
A hardware breakpoint placed directly on that entry terminated the client, so the VM entry must not be
used as a live probe point. `gepard+0xA23D78` is the validated passive observation point.

An experimental `--move-dispatch-backend gepard-wrapper` is implemented but remains opt-in. It validates
the callsite instruction, wrapper entry anchors, `eax == SendMsg`, and the exact `CGameMode` vtable before
capturing context or calling anything. The default remains `legacy` until one live movement proves that
entering the wrapper through `NativeFunction` preserves the Gepard outbound transformation.

### Instrumentation crash evidence and guardrails

The 2026-10-22 client crash at 01:28:58 was preserved by systemd as a SIGSEGV core. The faulting
instruction is `pthread_mutex_lock+0x25` in the host 32-bit libc with `gs=0`, so native TLS was invalid
on the faulting secondary thread. The manually recovered return address of that libc call lies inside
`frida-gadget-32.so`. This is strong evidence that the instrumentation/runtime path was involved; it is
not evidence of a server disconnect or RX failure. A later 01:32:39 client exit produced no core and is
kept separate from this SIGSEGV incident.

To reduce instrumentation risk, the relay now enforces one process per Frida Gadget port before
`attach()`. A second relay fails closed instead of sharing the same Gadget. Normal unload explicitly
detaches the Frida session before releasing that lock. Hardware-probe exception handlers also limit
stack resolution to 96 words / 16 executable frames and no longer perform per-frame prologue scans in
exception context. Research must avoid parallel throwaway Frida attachments while the production relay
owns the Gadget.
