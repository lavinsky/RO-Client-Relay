"""Optional 200 ms code-only Gadget preflight. Never installs hooks/breakpoints.

Invoke only after authorized host inventory. No traffic, actions, stack, payload
or state reads. Tests use doubles; they do not establish client safety.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import threading
import sys
sys.dont_write_bytecode = True

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.cipher.core import EvidenceError, json_bytes, open_regular, parse_json, private_write, require
else:
    from .core import EvidenceError, json_bytes, open_regular, parse_json, private_write, require


SOURCE = r"""
'use strict';
if (Process.id !== TARGET_PID || Process.arch !== 'ia32') throw new Error('target mismatch');
let base = null;
Process.enumerateRanges({protection:'---',coalesce:false}).forEach(function(r) {
  if(r.file && /\/gepard\.dll$/i.test(r.file.path) && (base===null || r.base.compare(base)<0)) base=r.base;
});
if(base===null) throw new Error('module unavailable');
const pc=base.add(0x18eff2), range=Process.findRangeByAddress(pc);
if(range===null || range.protection.indexOf('x')<0) throw new Error('anchor not executable');
const store=Instruction.parse(pc);
if(store.toString()!=='mov byte ptr [ecx], bl') throw new Error('anchor instruction changed');
const predecessors=[];
for(let size=2;size<=15;size++) {
  try {
    const candidate=Instruction.parse(pc.sub(size));
    if(candidate.next.equals(pc)) predecessors.push({bytes_before_store:size,instruction:candidate.toString()});
  } catch(_) {}
}
const chain=[];
let cursor=pc,chainEnd='depth_limit';
for(let depth=0;depth<8;depth++) {
  const choices=[];
  for(let size=1;size<=15;size++) {
    try {
      const candidate=Instruction.parse(cursor.sub(size));
      if(candidate.next.equals(cursor)) choices.push(candidate);
    } catch(_) {}
  }
  if(choices.length!==1){chainEnd=choices.length===0?'no_candidate':'ambiguous';break;}
  const candidate=choices[0];
  chain.push({rva:candidate.address.sub(base).toString(),instruction:candidate.toString()});
  cursor=candidate.address;
  if(/^(j|call|ret)/.test(candidate.mnemonic)){chainEnd='control_transfer';break;}
}
send({tag:'CODE_PREFLIGHT',anchor_rva:'0x18eff2',instruction:store.toString(),
      predecessor_decode_candidates:predecessors,
      bounded_predecessor_chain:chain,chain_end:chainEnd,
      warning:'Backward decodes are candidates, not executed control-flow proof.',
      hooks:0,breakpoints:0,traffic_observed:false,state_observed:false});
setTimeout(function(){send({tag:'DONE',requested_ms:200});},200);
"""


def bounded(frida_module, operation, seconds=2):
    cancellable = frida_module.Cancellable()
    timer = threading.Timer(seconds, cancellable.cancel)
    timer.daemon = True
    timer.start()
    try:
        with cancellable:
            return operation()
    finally:
        timer.cancel()
        timer.join(timeout=0.5)


def observe(device, source, bounded_call=lambda operation: operation(), timeout=0.5, cap=2):
    """Owned-script lifecycle, with deterministic bounded cleanup on every exit path."""
    require(0 < timeout <= 1 and 1 <= cap <= 10000, "invalid inspection limits")
    session = script = None
    events = []
    errors = []
    stop = threading.Event()
    reason = "timeout"

    def receive(message, data):
        nonlocal reason
        if len(events) >= cap:
            reason = "event_limit"
            stop.set()
            return
        if message.get("type") == "send" and isinstance(message.get("payload"), dict):
            payload = message["payload"]
            events.append(payload)
            if payload.get("tag") == "DONE":
                reason = "done"
                stop.set()
        else:
            reason = "script_error"
            stop.set()

    try:
        session = bounded_call(lambda: device.attach("Gadget"))
        script = bounded_call(lambda: session.create_script(source))
        script.on("message", receive)
        bounded_call(script.load)
        stop.wait(timeout)
    except (Exception, KeyboardInterrupt) as exc:
        reason = "interrupted" if isinstance(exc, KeyboardInterrupt) else "error"
        errors.append(type(exc).__name__)
    finally:
        if script is not None:
            try:
                bounded_call(script.unload)
            except Exception as exc:
                errors.append("unload:" + type(exc).__name__)
        if session is not None:
            try:
                bounded_call(session.detach)
            except Exception as exc:
                errors.append("detach:" + type(exc).__name__)
    return {"events": events, "reason": reason, "errors": errors,
            "cleanup_confirmed": not any(e.startswith(("unload:", "detach:")) for e in errors),
            "hooks": 0, "breakpoints": 0, "new_state_samples": 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    # No Frida import during offline analysis or tests.
    import frida
    with open_regular(args.inventory) as handle:
        raw = handle.read(65537)
    require(len(raw) <= 65536, "inventory size limit")
    info = parse_json(raw)
    require(info.get("target_count") == 1 and len(info.get("targets", [])) == 1 and
            not info.get("known_drivers") and len(info.get("gadget_ports", [])) == 1,
            "inventory does not authorize unambiguous preflight")
    pid = info["targets"][0]
    port = info["gadget_ports"][0]
    require(type(pid) is int and pid > 0 and type(port) is int and 27052 <= port < 27100,
            "invalid target identity")
    process = Path("/proc") / str(pid)
    require((process / "comm").read_text().strip().lower() == "uaro.exe", "target changed")
    for name in ("uaRO.exe", "gepard.dll"):
        module = info["modules"][name]
        require(Path(module["path"]).name.lower() == name.lower(), "module identity mismatch")
        with open_regular(process / "root" / module["path"].lstrip("/")) as handle:
            require(hashlib.file_digest(handle, "sha256").hexdigest() == module["sha256"],
                    "module hash changed")
    manager = frida.get_device_manager()
    address = "127.0.0.1:" + str(port)
    result = None
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        device = bounded(frida, lambda: manager.add_remote_device(address))
        result = observe(device, SOURCE.replace("TARGET_PID", str(pid)),
                         lambda operation: bounded(frida, operation))
    except (Exception, KeyboardInterrupt) as exc:
        result = {"events": [], "reason": "connection_error", "errors": [type(exc).__name__],
                  "cleanup_confirmed": True, "hooks": 0, "breakpoints": 0, "new_state_samples": 0}
    finally:
        try:
            bounded(frida, lambda: manager.remove_remote_device(address))
        except Exception:
            if result is not None:
                result["cleanup_confirmed"] = False
                result["errors"].append("remote_device_removal_failed")
    private_write(args.out, "code-preflight.json", json_bytes(result))
    print(json.dumps({"reason": result["reason"], "cleanup_confirmed": result["cleanup_confirmed"],
                      "hooks": 0, "breakpoints": 0, "new_state_samples": 0}))
    return 0 if result["reason"] == "done" and result["cleanup_confirmed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
