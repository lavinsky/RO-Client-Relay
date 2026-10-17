"""Teste de integração ponta-a-ponta do Relay sobre um socket real (simula o consumidor XKore 1).

Sobe um consumidor falso que lê quadros typ+len16+payload como o XKore.pm faz, conecta um Relay a
ele e exercita o fluxo de produção inteiro numa só passagem:
  - stream servidor->cliente com lixo no início (o alinhador precisa achar a borda e descartá-lo),
  - pacotes de tamanho fixo E variável misturados,
  - um id na lista de descarte (sai inteiro, o stream segue alinhado),
  - o stream cortado no meio de um pacote entre dois feeds (remontagem),
  - o caminho de escrita: dois pacotes 'S' cliente->servidor voltam enquadrados.
Determinístico (corpos com semente fixa) para que a comparação de bytes seja estável."""
import random
import socket
import struct
import threading
import time

from _boot import g, DATA

lengths = g.load_lengths(DATA + '/uaro_recvpackets.txt')
RNG = random.Random(1234)                              # corpos estáveis entre execuções

# --- consumidor falso: lê quadros XKore 1 exatamente como o XKore.pm --------------------------
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 0))
srv.listen(1)
port = srv.getsockname()[1]
got = {'R': b'', 'S': b'', 'frames': []}

def consumidor():
    c, _ = srv.accept()
    c.settimeout(0.6)
    buf = b''
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
    except socket.timeout:
        pass
    while len(buf) >= 3:
        t = chr(buf[0]); ln = struct.unpack('<H', buf[1:3])[0]
        if ln > len(buf) - 3:
            break
        msg = buf[3:3 + ln]; buf = buf[3 + ln:]
        got['frames'].append((t, len(msg)))
        if t in got:
            got[t] += msg

threading.Thread(target=consumidor, daemon=True).start()

# --- monta um pacote real a partir da tabela (corpo determinístico) ---------------------------
def mk(pid):
    L = lengths[pid]
    cab = bytes([pid & 0xff, pid >> 8])
    if L == -1:                                        # variável: tamanho total nos bytes 2-3
        corpo = bytes(RNG.randrange(256) for _ in range(14))
        return cab + struct.pack('<H', 4 + len(corpo)) + corpo
    return cab + bytes(RNG.randrange(256) for _ in range(L - 2))

DROP = 0x007f                                          # este id sai inteiro do stream
r = g.Relay('127.0.0.1', port, 'xkore1', lengths=lengths, align=True, drop={DROP})
time.sleep(0.4)                                        # deixa conectar

# stream servidor->cliente: fixos + variável + o id descartado, no meio de outros
ids_servidor = [0x0073, 0x09ff, 0x0087, 0x007f, 0x0091, 0x0a37]
pacotes = {i: mk(i) for i in ids_servidor}
stream = b''.join(pacotes[i] for i in ids_servidor)
esperado_R = b''.join(pacotes[i] for i in ids_servidor if i != DROP)

ruido = b'\x11\x22\x33' + stream                       # 3 bytes de lixo antes da primeira borda
corte = len(ruido) // 2
r.feed(ruido[:corte]); time.sleep(0.05); r.feed(ruido[corte:])   # cortado no meio de um pacote

# caminho de escrita: dois pacotes cliente->servidor voltam como 'S'
ids_envio = [0x0089, 0x0085]
for i in ids_envio:
    r.feed_send(mk(i))

time.sleep(1.2)
srv.close()
time.sleep(0.3)

# --- verificações -----------------------------------------------------------------------------
print('quadros:', got['frames'])
assert got['R'] == esperado_R, (got['R'].hex(), esperado_R.hex())   # lixo descartado, 007f omitido, alinhado
assert pacotes[DROP] not in got['R']                   # o id descartado não aparece no que o consumidor recebeu
print('stream servidor->cliente ok (alinhado, 0x007f descartado, remontado)')

# lado 'S': re-tokeniza os bytes de volta em pacotes inteiros
sbuf = got['S']; vistos = []; pos = 0
while pos + 2 <= len(sbuf):
    pid = sbuf[pos] | sbuf[pos + 1] << 8
    L = lengths.get(pid)
    L = (sbuf[pos + 2] | sbuf[pos + 3] << 8) if L == -1 else L
    vistos.append(pid); pos += L
assert vistos == ids_envio, (vistos, ids_envio)
assert [t for t, _ in got['frames']].count('S') == len(ids_envio)
print('caminho de escrita ok: pacotes S', [hex(i) for i in vistos])
print('ALL PASS')
