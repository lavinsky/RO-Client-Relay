"""The sanitized JSONL capture log and the one-line console view of each message."""
import json

from .safety import sanitize


def _pid(v):
    """'0x....' for a numeric packet id, '?' when it is missing."""
    return f'0x{v:04x}' if isinstance(v, int) else '?'


def show(m):
    tag, i = m.get('tag'), m.get('id', '????')
    if tag == 'RECV-PLAIN':
        print(f"[<= PLAIN{'?' if m.get('uncertain') else ' '}] id=0x{i} len={m['len']:<4} @{m.get('dest','?')} C={m['C'][:32]}... P={m['P'][:48]}...")
    elif tag == 'SEND':
        print(f"[=> SEND ] id=0x{i} len={m['len']:<4} {m['C'][:48]}...")
    elif tag == 'SEND-PLAIN':
        enc = f" enc@gepard+{m['enc_off']}" if m.get('enc_off') else ''
        print(f"[=> SEND*] id=0x{i} len={m['len']:<4} @{m.get('src','?')} C={m['C'][:32]}... P={m['P'][:48]}...{enc}")
    elif tag == 'SCRAMBLE':
        if m.get('hit') == 'wrote':
            print(f"[scramble] WROTE id={_pid(m.get('id'))} @{m.get('slot')} was={m.get('body')} -> {m.get('wrote')}")
        elif m.get('hit') == 'dry':
            ptrs = ' '.join(f"{r}={v}" for r, v in (m.get('regs') or {}).items())
            stk = ' '.join(f"s{k}={v}" for k, v in enumerate(m.get('stack') or []))
            ent = m.get('entry')
            ent_s = f"gepard+{ent['off']} ({ent['abs']})" if ent and ent.get('off') else (ent and ent.get('abs')) or '?'
            print(f"[scramble] DRY reg={m.get('reg')} slot={m.get('slot')} id={_pid(m.get('id'))} body={m.get('body')}")
            print(f"           regs: {ptrs}")
            print(f"           stack: {stk}")
            print(f"           nearest prologue (candidate entry): {ent_s}")
        elif m.get('hit') == 'entry':
            rm = m.get('regmem') or {}
            print(f"[entry] args at {m.get('pc')}:")
            print("        regs: " + ' '.join(f"{r}={v}" + (f"->{rm[r]}" if rm.get(r) else '')
                                               for r, v in (m.get('regs') or {}).items()))
            for s in (m.get('stack') or []):
                code = f" [{s['code']}]" if s.get('code') else ''
                mem = f" ->{s['mem']}" if s.get('mem') else ''
                print(f"        [esp+{s.get('off')}] {s.get('val')}{code}{mem}")
        elif m.get('hit') == 'probe':
            ptrs = ' '.join(f"{r}={v}" for r, v in (m.get('regs') or {}).items())
            print(f"[probe] send mapped: id={_pid(m.get('id'))} via {m.get('reg')} (idoff={m.get('idoff')}) slot={m.get('slot')}")
            print(f"        regs: {ptrs}")
            for f in (m.get('frames') or []):
                e = f.get('entry')
                ent = f" entry={e['mod']}+{e['off']}" if e else ''
                print(f"        [{f.get('sp')}] {f.get('mod')}+{f.get('off')} (ret {f.get('ret')}){ent}")
        else:
            print(f"[scramble] (other id={_pid(m.get('id'))} @{m.get('slot')} body={m.get('body')})")
    elif tag == 'SENDCALL':
        hit = m.get('hit')
        if hit == 'ready':
            print(f"[sendcall] captured this={m.get('this')} @ {m.get('pc')} (call-inject armed)")
        elif hit == 'sent':
            print(f"[sendcall] SENT len={m.get('len')} {m.get('data','')[:48]}")
        else:
            print(f"[sendcall] {hit}: {m.get('e')}")
    elif tag == 'TRACE':
        if m.get('erro'):
            print(f"[trace] erro: {m.get('erro')}")
        elif m.get('chamadas') is not None:
            print(f"[trace] {m.get('ms')}ms, {m.get('n')} chamadas uaRO->gepard distintas:")
            for c in (m.get('chamadas') or []):
                print(f"        uaRO+{c.split('>')[0]} -> gepard+{c.split('>')[1]}")
        else:
            print(f"[trace] {m.get('ms')}ms: {m.get('nota')} ({m.get('bytes')} bytes de eventos) - cliente sobreviveu")
    elif tag == 'RECV-WIRE':
        print(f"[<= wire ] id=0x{i} len={m['len']:<4} conn={m.get('conn','?')} {m['C'][:48]}...")
    elif tag == 'RECV-LOST':
        print(f"[<= LOST ] id=0x{i} len={m['len']:<4} (decrypted copy not found) {m['C'][:32]}...")
    elif tag == 'RECV-RAW':
        print(f"[<= raw  ] id=0x{i} len={m['len']:<4} {m['C'][:48]}...")
    elif tag == 'RECV-HTTP':
        print(f"[<= http ] id=0x{i} len={m['len']:<4} (uaRO token/HTTP, not fed to the consumer)")
    elif tag == 'MOVE-CHECK':
        req = m.get('req')
        status = 'OK' if m.get('match') else ('MISMATCH' if req else 'confirmed')   # live: no 035f request
        print(f"[move   ] 0087 dst={tuple(m['dst'])} src={tuple(m['src'])} "
              f"walk-req={tuple(req) if req else '-'} -> {status}")


class CaptureLog:
    """Writes each message, sanitized, as one JSON line, and prints it. Worker thread only."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, 'w', buffering=1)          # line-buffered: survives os._exit on detach

    def write(self, m):
        m.pop('data', None)                            # binary attachments never go to the log
        m.pop('ptr', None)
        sanitize(m)
        self.f.write(json.dumps(m) + '\n')
        show(m)
