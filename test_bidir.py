import os, socket, threading, time, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from relay.relay import Relay
from relay.packets import load_lengths

# load real lengths table
lengths = load_lengths(os.path.join(HERE, "uaro_recvpackets.txt"))

# mock the consumer XKore 1 recv(): parse type+len16+payload frames
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
srv.bind(("127.0.0.1",0)); srv.listen(1); port = srv.getsockname()[1]
got = {"R": b"", "S": b"", "frames": []}
def accept():
    c,_ = srv.accept()
    buf = b""
    c.settimeout(0.6)
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            buf += d
    except socket.timeout: pass
    # parse exactly like XKore.pm recv()
    while buf:
        t = chr(buf[0]); L = struct.unpack("<H", buf[1:3])[0]
        if L > len(buf)-3: break
        msg = buf[3:3+L]; buf = buf[3+L:]
        got["frames"].append((t, len(msg)))
        if t in got: got[t] += msg
threading.Thread(target=accept, daemon=True).start()

r = Relay("127.0.0.1", port, "xkore1", lengths=lengths, align=True)
time.sleep(0.4)  # let it connect

# Build a realistic server->client stream of 3 packets, then feed in 2 chunks (mid-packet split)
# 0x0073 map_loaded(len 11), 0x009d (len19 var? here fixed), use known fixed-len packets.
def pkt(idhex, body):
    return bytes.fromhex(idhex[2:]+idhex[:2]) + body
# pick fixed-length packets from table
import random
def mk(pid):
    L = lengths[pid]
    b = bytes([pid&0xff, pid>>8])
    if L == -1:
        body = bytes(random.randrange(256) for _ in range(10))
        return b + struct.pack("<H", 4+len(body)) + body
    return b + bytes(random.randrange(256) for _ in range(L-2))
# choose some real fixed ids present in table
server_ids = [0x0073, 0x01c8, 0x009d, 0x0a37]
server_ids = [i for i in server_ids if lengths.get(i,0) not in (0,None)]
stream = b"".join(mk(i) for i in server_ids)
# prepend 3 junk bytes to test alignment skip
noisy = b"\x11\x22\x33" + stream
r.feed(noisy[:7]); time.sleep(0.05); r.feed(noisy[7:])  # split mid-stream

# feed two client->server send packets as "S"
send_ids = [0x0089, 0x0085]
send_ids = [i for i in send_ids if lengths.get(i,0) not in (0,None)]
for i in send_ids:
    r.feed_send(mk(i))
time.sleep(1.6)
srv.close()
time.sleep(0.3)

print("frames:", got["frames"])
print("R bytes:", got["R"].hex())
print("expected server stream:", stream.hex())
print("R == aligned stream:", got["R"] == stream)
# S side: parse the S bytes back into packets
sbuf = got["S"]; sp=[]
pos=0
while pos+2<=len(sbuf):
    pid = sbuf[pos]|(sbuf[pos+1]<<8); L=lengths.get(pid)
    if L==-1: L=sbuf[pos+2]|(sbuf[pos+3]<<8)
    sp.append(hex(pid)); pos+=L
print("S packets parsed:", sp, "expected:", [hex(i) for i in send_ids])
print("S ok:", sp==[hex(i) for i in send_ids])
