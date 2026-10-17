"""The sanitized JSONL capture log and the one-line console view of each message."""
import json
import os
import sys
from copy import deepcopy

from .traffic_safety import sanitize


def _pid(v):
    """'0x....' for a numeric packet id, '?' when it is missing."""
    return f'0x{v:04x}' if isinstance(v, int) else '?'


_mode = 'normal'
_color = False


def configure(opts):
    """Configure human output independently from the sanitized JSONL capture."""
    global _mode, _color
    _mode = getattr(opts, 'console_mode', None) or ('verbose' if getattr(opts, 'verbose', False) else 'normal')
    if _mode not in ('normal', 'verbose'):
        raise ValueError('console_mode must be normal or verbose')
    _color = not getattr(opts, 'no_color', False) and 'NO_COLOR' not in os.environ and sys.stdout.isatty()


def event(message, level='info', verbose=False):
    """Render an operator message; 'wire' means independently confirmed wire output."""
    if verbose and _mode != 'verbose':
        return
    colors = {'info': '', 'stage': '36', 'warning': '33', 'error': '31', 'wire': '32'}
    color = colors.get(level, '')
    text = str(message)
    if _color and color:
        text = f"\033[{color}m{text}\033[0m"
    print(text)


def _metadata(m):
    # ACKs may carry raw bodies: expose only correlation and timing fields.
    fields = ('id', 'token', 'epoch', 'len', 'ms', 'elapsed_ms', 'queue_ms',
              'dispatch_ms', 'wire_ms', 'local_elapsed_ms', 'mono_ms', 'active', 'pending',
              'capacity', 'blocked_id', 'blocked_token', 'blocked_ms', 'dropped', 'cancelled')
    parts = [f'{key}={_pid(m[key]) if key in ("id", "blocked_id") else m[key]}'
             for key in fields if key in m and isinstance(m[key], (int, float, bool))]
    if m.get('blocked_stage') in ('input', 'carrier', 'native'):
        parts.append('blocked_stage=' + m['blocked_stage'])
    return ' '.join(parts)


def show(m):
    m = sanitize(deepcopy(m))
    tag, hit = m.get('tag', '?'), m.get('hit', '')
    if tag in ('SESSION', 'LATENCY', 'COMMAND', 'SENDCALL', 'MOVE-DISPATCH') or (
            tag == 'SCRAMBLE' and hit in ('armed', 'consumed', 'cancelled', 'error')):
        if hit == 'throttled':
            return
        level = ('error' if hit == 'error' or m.get('exception') else
                 'warning' if hit == 'waiting' else 'stage')
        detail = ''
        # Fixed public descriptions: arbitrary exception text may contain secrets.
        reasons = {'COMMAND_CAPACITY': 'capacidade esgotada; comando recusado',
                   'COMMAND_DISCONNECTED': 'OpenKore desconectado; comando recusado',
                   'COMMAND_DISPATCH_FAILED': 'falha no despacho local',
                   'COMMAND_CARRIER_PENDING': 'tecla liberada; aguardando carrier nativo (envio não confirmado)'}
        if tag == 'COMMAND' and m.get('code') in reasons:
            detail = ' ' + reasons[m['code']]
        if tag == 'LATENCY' and m.get('stages'):
            detail = ' ' + json.dumps(m.get('stages', {}), separators=(',', ':'))
        event(f"[{tag}] {hit} {_metadata(m)}{detail}".rstrip(), level)
        return
    if tag in ('WARNING', 'ERROR'):
        known = {'SO_COOKIE_FALLBACK': 'identidade de conexão degradada: SO_COOKIE indisponível',
                 'SOCKET_ID_CHANGED': 'bytes omitidos: identidade do socket mudou durante syscall'}
        detail = known.get(m.get('code'), '')
        event(f"[{tag}] {_metadata(m)} {detail}".rstrip(), tag.lower())
        return
    if _mode == 'normal':
        if tag == 'RECV-LOST':
            event(f"[{tag}] id={m.get('id', '?')} len={m.get('len', '?')}", 'warning')
        return
    _show_verbose(m)


def _show_verbose(m):
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
        elif m.get('hit') == 'trace':
            print(f"[trace#{m.get('n')}] ecx={m.get('ecx')} ebx={m.get('ebx')} db={m.get('db')}")
        elif m.get('hit') == 'trace-done':
            print(f"[trace] concluido ({m.get('n')} passos)")
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
    elif tag == 'MOVE-DISPATCH':
        print(f"[move-dispatch] {m.get('hit')} " + ' '.join(f"{k}={m[k]}" for k in
              ('x', 'y', 'this', 'retval', 'exception', 'e') if m.get(k) is not None))
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
            print(f"[trace] {m.get('ms')}ms, {m.get('n')} chamadas distintas:")
            for c in (m.get('chamadas') or []):
                de, para = c.split('>', 1)
                destino = f"uaRO+{para[1:]}" if para.startswith('u') else f"gepard+{para}"
                print(f"        uaRO+{de} -> {destino}")
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
        self.f = open(path, 'w', buffering=65536)

    def write(self, m):
        m = dict(m)
        m.pop('data', None)                            # binary attachments never go to the log
        m.pop('ptr', None)
        sanitize(m)
        if _mode != 'verbose' and m.get('tag') in ('SEND', 'RECV-WIRE', 'RECV-RAW', 'RECV-HTTP'):
            m = {k: v for k, v in m.items() if k not in ('C', 'P', 'W')}
        self.f.write(json.dumps(m) + '\n')
        show(m)

    def close(self):
        self.f.close()
