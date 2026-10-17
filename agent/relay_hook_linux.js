/*
 * relay_hook_linux.js - native-Linux Frida agent (via Frida Gadget) for uaRO under Proton.
 *
 * Hooks Linux libc recvmsg/sendmsg inside the 32-bit wine process - the bottom of
 * every Winsock call - which is the simplest, most stable place to observe the
 * socket traffic under Wine. The client decrypts each received chunk into its recv
 * ring; the driver locates that copy via /proc/pid/mem.
 * Frida 17 API.
 *
 * Nothing heavy runs in here: every hook callback holds the JS lock on the game's
 * thread, so in-process searching froze the client. The hooks only copy bytes out.
 *
 * MESSAGES (full field list: relay/protocol.py)
 *   to driver:   RECV, RINGSNAP, SEND (+ W window when the send watch saw the slot), SENDWATCH-ERR
 *   from driver: {type:'ring', sock, base, span?}   {type:'sendwatch', lo?, hi?, ports?}
 */
'use strict';

if (Process.arch !== 'ia32')
    throw new Error('target is ' + Process.arch + ' (WoW64 mode?) - expected a 32-bit wine process');

// ---- hex ---------------------------------------------------------------------------------------
var HEX = [];
for (var h = 0; h < 256; h++) HEX.push((h < 16 ? '0' : '') + h.toString(16));

function hexOf(u) {
    var parts = new Array(u.length);
    for (var i = 0; i < u.length; i++) parts[i] = HEX[u[i]];
    return parts.join('');
}
function toHex(p, n) { try { return hexOf(new Uint8Array(p.readByteArray(n))); } catch (e) { return null; } }
function pktId(h) { return h && h.length >= 4 ? h.slice(2, 4) + h.slice(0, 2) : '????'; }   // little-endian id

// ---- sockets -----------------------------------------------------------------------------------
var libcGetpeername = new NativeFunction(Module.getGlobalExportByName('getpeername'), 'int', ['int', 'pointer', 'pointer']);
var libcGetsockname = new NativeFunction(Module.getGlobalExportByName('getsockname'), 'int', ['int', 'pointer', 'pointer']);
var libcGetsockopt = null, socketIdentityWarned = false, socketChangedWarned = false;
try {
    var getsockoptAddress = Module.findGlobalExportByName('getsockopt');
    if (getsockoptAddress !== null)
        libcGetsockopt = new NativeFunction(getsockoptAddress, 'int', ['int', 'int', 'int', 'pointer', 'pointer']);
} catch (e) {}
var peerCache = {};     // fd -> "ip:port" of the last query (a hint only: fds get reused)
var connCache = {};     // fd -> Linux socket cookie; duplicate fds share the same TCP identity

// "ip:port" for AF_INET sockets, null otherwise (wineserver/unix sockets). Re-queried on every
// use that matters: the client closes and reopens sockets at each login->char->map switch and
// fds get reused, so a cached label would tag the new connection with the old server (it once
// mislabeled HTTP token uploads as map traffic, dodging the driver's credential redaction).
function peerOf(fd) {
    var sa = Memory.alloc(128), len = Memory.alloc(4);
    var res = null;
    len.writeU32(128);
    if (libcGetpeername(fd, sa, len) === 0 && sa.readU16() === 2) {
        res = [4, 5, 6, 7].map(function (o) { return sa.add(o).readU8(); }).join('.') + ':' + portAt(sa);
        connCache[fd] = socketIdentity(fd, sa, len);
    }
    return (peerCache[fd] = res);
}
// SO_COOKIE (Linux UAPI: SOL_SOCKET=1, SO_COOKIE=57) survives dup() but changes for a new socket.
// Reuse the sockaddr tail for its uint64 result; stringify both halves without Number precision loss.
function socketIdentity(fd, sa, len) {
    if (libcGetsockopt !== null) {
        try {
            var cookie = sa.add(16); len.writeU32(8);
            if (libcGetsockopt(fd, 1, 57, cookie, len) === 0 && len.readU32() === 8)
                return 'cookie:' + cookie.add(4).readU32().toString(16).padStart(8, '0') +
                    cookie.readU32().toString(16).padStart(8, '0');
        } catch (e) {}
    }
    if (!socketIdentityWarned) {
        socketIdentityWarned = true;
        send({tag: 'WARNING', code: 'SO_COOKIE_FALLBACK',
              e: 'SO_COOKIE unavailable; local-port identity is weaker under port reuse'});
    }
    len.writeU32(128);
    // Compatibility fallback: local ports can repeat after close and cannot prove TCP identity.
    return libcGetsockname(fd, sa, len) === 0 ? portAt(sa) : null;
}
// Never label a blocked syscall's bytes with a socket that replaced its original fd.
function sameSocket(peer, conn, currentPeer, currentConn) {
    return peer !== null && peer !== undefined && conn !== null && conn !== undefined &&
        peer === currentPeer && conn === currentConn;
}
function socketUnchanged(call) {
    var currentPeer = peerOf(call.fd), currentConn = connCache[call.fd];
    if (sameSocket(call.peer, call.conn, currentPeer, currentConn)) return true;
    if (!socketChangedWarned) {
        socketChangedWarned = true;
        send({tag: 'WARNING', code: 'SOCKET_ID_CHANGED',
              e: 'socket identity changed during syscall; event discarded'});
    }
    return false;
}
function portAt(sa) { return (sa.add(2).readU8() << 8) | sa.add(3).readU8(); }

// 32-bit wine's ntdll.so imports the time64 entry points (__recvmsg64/__sendmsg64);
// plain recvmsg/sendmsg are a separate export, so hook both when present.
function libcFns(names) {
    var seen = {}, out = [];
    names.forEach(function (n) {
        var a = Module.findGlobalExportByName(n);
        if (a && !seen[a]) { seen[a] = 1; out.push([n, a]); }
    });
    if (!out.length) throw new Error('none of ' + names + ' found in libc');
    return out;
}

// struct msghdr (i386): name, namelen, iov, iovlen, control, controllen, flags -> [[buf, len]]
function iovs(msg, total) {
    var out = [], iov = msg.add(8).readPointer(), n = msg.add(12).readU32(), left = total;
    for (var i = 0; i < n && left > 0; i++) {
        var b = iov.add(i * 8).readPointer(), l = iov.add(i * 8 + 4).readU32(), take = Math.min(l, left);
        if (take > 0) out.push([b, take]);
        left -= take;
    }
    return out;
}

function hookAll(names, callbacks) {
    libcFns(names).forEach(function (f) {
        console.log('[+] hooked ' + f[0] + ' @ ' + f[1]);
        Interceptor.attach(f[1], callbacks);
    });
}

// libc monotonic clock is optional; omit measurements if this ABI/export is unavailable.
var monotonicClock = null;
try {
    var clockAddress = Module.findGlobalExportByName('clock_gettime');
    if (clockAddress !== null) monotonicClock = new NativeFunction(clockAddress, 'int', ['int', 'pointer']);
} catch (e) {}
function monoNow() {
    if (monotonicClock === null) return undefined;
    try {
        var ts = Memory.alloc(Process.pointerSize * 2);
        if (monotonicClock(1, ts) !== 0) return undefined; // CLOCK_MONOTONIC, i386 timespec
        return ts.readU32() * 1000 + ts.add(Process.pointerSize).readU32() / 1000000;
    } catch (e) { return undefined; }
}

var workEpoch = 0, workMinToken = 0, workActive = false, WORK_CAPACITY = 64;
var seq = 0;            // orders RECV / RINGSNAP / SEND events for the driver
var g = null, gepardSent = false;   // gepard.dll base, resolved lazily (it loads only after login)

function getGepard() {              // peBase is hoisted (function declaration below)
    if (g === null) { try { g = peBase('gepard.dll'); } catch (e) {} }
    return g;
}

// ---- recv ring ---------------------------------------------------------------------------------
// The client decrypts each chunk into its recv ring (ring+0x40, or appended after the previous
// chunk when it continues a partial packet); the next chunk overwrites it. Once the driver has
// found the ring it posts {type:'ring'} (optionally with the `span` it needs), and we copy the
// ring at the START of EVERY recvmsg on that socket - also calls that return nothing - so the
// driver always has a copy taken right before the next chunk can land.
var ringBase = {}, ringSpan = {}, lastLen = {};    // keyed by "ip:port"

function onRing(m) {
    ringBase[m.sock] = ptr(m.base);
    if (m.span) ringSpan[m.sock] = m.span;
    recv('ring', onRing);                           // recv() handlers are one-shot: re-arm
}
recv('ring', onRing);

function ringBytes(peer, chunkLen) {                // whole chunk + context, or the span asked for
    return Math.max(ringSpan[peer] || 0, 0x40 + chunkLen + 0x800);
}

hookAll(['__recvmsg64', 'recvmsg'], {
    onEnter: function (args) {
        this.fd = args[0].toInt32(); this.msg = args[1]; this.epoch = workEpoch;
        this.peer = peerOf(this.fd); this.conn = connCache[this.fd];
        var peer = this.peer;
        if (!peer || !ringBase[peer] || !lastLen[peer]) return;
        try {
            send({tag: 'RINGSNAP', epoch: this.epoch, mono_ms: monoNow(), sock: peer, conn: this.conn, base: ringBase[peer].toString(),
                  seq: seq, ts: Date.now()}, ringBase[peer].readByteArray(ringBytes(peer, lastLen[peer])));
        } catch (e) {}
    },
    onLeave: function (ret) {
        var n = ret.toInt32(); if (n <= 0 || !this.peer) return;
        if (!socketUnchanged(this)) return;
        var eventEpoch = this.epoch, eventConn = this.conn, fd = this.fd, peer = this.peer;
        lastLen[peer] = n;
        // ring BEFORE the client can decrypt this chunk (we are still inside its recv): the
        // driver's proof that a copy found later is new, not a stale leftover
        var pre = null;
        if (ringBase[peer]) {
            try { pre = ringBase[peer].readByteArray(ringBytes(peer, n)); } catch (e) {}
        }
        iovs(this.msg, n).forEach(function (v, k) {
            var h = toHex(v[0], v[1]);
            if (!h) return;
            var first = k === 0 && pre !== null;
            send({tag: 'RECV', epoch: eventEpoch, mono_ms: monoNow(), sock: peer, conn: eventConn, len: v[1], id: pktId(h), C: h,
                  ptr: v[0].toString(), seq: seq++, ts: Date.now(),
                  pre: first ? ringBase[peer].toString() : undefined}, first ? pre : null);
        });
        if (scSend !== null) drainSendCall();                       // game thread: safe point to call-inject
    }
});

var sw = null; // Optional send-watch state; helpers exist only in research_hooks.js.

// ---- scramble intercept (opt-in: the driver posts {type:'scramble'}) ---------------------------
// Inject a valid encrypted client->server packet: a hardware EXECUTION breakpoint at the client's
// scrambler entry fires while the slot still holds the full PLAINTEXT (verified: the build->scramble
// window is where the plaintext lives). In the handler we read the slot via a register and, if it
// holds the target id, overwrite the body - so the client's own scrambler encrypts OUR bytes with
// the live key and sends them. Unlike a stack data watchpoint this breakpoint fires only on an
// encrypted send (no flood). DRY mode writes nothing; it just reports the slot bytes and all GP
// registers so the exact entry pc and pointer register can be confirmed first. It uses one debug
// register, so it can't run alongside the full 4-register send watch (use --no-send-watch).
// NOTE: a debug register is exactly what the anti-cheat may detect - this is for a client you own.
function workAck(hit, item, extra) {
    send(Object.assign({tag: 'SCRAMBLE', hit: hit, token: item.token, epoch: item.epoch, id: item.id,
        mono_ms: monoNow(), accepted_mono_ms: item.accepted_mono_ms}, extra || {}));
}
function workFinish(item, hit, extra) {
    workAck(hit, item, extra);
    if (scr !== null && scr.pending.length && !scr._fix0) workAck('armed', scr.pending[0]);
}
function workCurrent(m) {
    return m.epoch === undefined || (workActive && m.epoch === workEpoch &&
        (typeof m.token !== 'number' || m.token >= workMinToken));
}
var researchTrap = null, researchReset = null;
var scr = null;                                 // {pc, reg, id, body(array)|null, dry} or null
var scrThread = null, scrHandler = false;
var scrCall = null;                              // sendcall: {pc} do ponto de captura do `this`, em DR1
var GP = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'];
var SCR_IDOFFS = [-2, 0];                        // reg='auto': try id just before the body pointer, then at it

function scrDisarm() {
    if (scrThread !== null) { try { scrThread.unsetHardwareBreakpoint(0); } catch (e) {} }
}

function scrArm() {
    scrDisarm();
    if (scr === null) return;
    scrThread = Process.enumerateThreads().filter(function (t) { return t.id === Process.id; })[0] || null;
    if (scrThread === null) { send({tag: 'SENDWATCH-ERR', e: 'scramble: main thread not found'}); return; }
    try { scrThread.setHardwareBreakpoint(0, scr.pc); }      // DR0 as an execution breakpoint
    catch (e) { scr = null; send({tag: 'SENDWATCH-ERR', e: 'scramble bp: ' + e.message}); }
}

// sendcall: captura do `this` num slot de debug proprio (DR1), para o merge de 035f (DR0) seguir intacto.
function scrCallDisarm() {
    if (scrThread !== null) { try { scrThread.unsetHardwareBreakpoint(1); } catch (e) {} }
}

function scrCallArm() {
    scrCallDisarm();
    if (scrCall === null) return;
    scrThread = scrThread || Process.enumerateThreads().filter(function (t) { return t.id === Process.id; })[0] || null;
    if (scrThread === null) { send({tag: 'SENDCALL', hit: 'error', e: 'main thread not found'}); return; }
    try { scrThread.setHardwareBreakpoint(1, scrCall.pc); }   // DR1 as an execution breakpoint
    catch (e) { scrCall = null; send({tag: 'SENDCALL', hit: 'error', e: 'bp: ' + e.message}); }
}

function slotFrom(ctx, reg) {                     // the slot pointer: a register, or 'sN' = [esp + 4*N]
    try {
        if (reg.charAt(0) === 's' && reg.length <= 3) {
            var n = parseInt(reg.slice(1), 10);
            if (!isNaN(n)) return ctx.esp.add(4 * n).readPointer();
        }
        return ctx[reg];
    } catch (e) { return null; }
}

function scrTrap(d) {
    if (d.type !== 'breakpoint') return false;
    var ctx = d.context;
    if (md !== null && mdTrap(ctx)) return true;       // native-dispatch (DR2/DR3)
    // sendcall: captura de uso unico do `this` (ecx) na entrada da SendPacket, no DR1 -- independente
    // do merge de 035f (DR0), que segue armado. Depois a SendPacket e chamada por NativeFunction.
    if (scrCall !== null && ctx.pc.equals(scrCall.pc)) {
        if (scrThread !== null && Process.getCurrentThreadId() !== scrThread.id) return false;
        try {
            scSend['this'] = ctx.ecx;
            scSend.tid = Process.getCurrentThreadId();   // a thread em que a SendPacket roda; drenar so nela
            scSend.fn = new NativeFunction(scrCall.pc, 'void', ['pointer', 'int', 'pointer'], 'thiscall');
            send({tag: 'SENDCALL', hit: 'ready', 'this': ctx.ecx.toString(), pc: scrCall.pc.toString(), tid: scSend.tid});
        } catch (e) { send({tag: 'SENDCALL', hit: 'error', e: 'arm: ' + e.message}); }
        scrCall = null; scrCallDisarm();
        return true;
    }
    if (scr === null || !ctx.pc.equals(scr.pc)) return false;
    if (scrThread !== null && Process.getCurrentThreadId() !== scrThread.id) return false;
    if (researchTrap !== null && researchTrap(ctx)) return true;
    // --- byte0 fix (merge) ---------------------------------------------------------------------
    // O store scr.pc (mov [ecx],bl) grava UM byte em bodyp[0] DEPOIS do nosso writeByteArray, com o
    // valor derivado do byte ORIGINAL (bl foi carregado antes do nosso write) -> body[0] revertia:
    // ataque no GID errado (byte baixo do GID) e perícia saindo nível 1 (byte baixo do nível). Como o
    // scrambler é ascendente (body[0] primeiro), corrigimos no hit SEGUINTE (byte1 do mesmo pacote, o
    // store de body[0] já rodou) reescrevendo body[0] pela identidade XOR, sem conhecer o keystream
    // nem assumir onde o XOR é aplicado: final = (valor_atual) ^ original0 ^ nosso0.
    if (scr._fix0 && scr._fix0.tid === Process.getCurrentThreadId()) {
        var f0 = scr._fix0; scr._fix0 = null;
        try {
            var c0 = f0.at.readU8(); f0.at.writeU8((c0 ^ f0.orig0 ^ f0.our0) & 0xff);
            if (f0.item) workFinish(f0.item, 'consumed');
        } catch (e) { if (f0.item) workFinish(f0.item, 'error', {e: 'byte-zero repair: ' + e.message}); }
    }
    // Find the slot pointer + which body to write. Two modes:
    //   fixed  (scr.reg is a register / sN): pointer = that reg, id at pointer+idoff (configured).
    //   auto   (scr.reg === 'auto'): scan GP registers for one that points at a slot whose id is one
    //          we're injecting, trying a couple of id offsets - so reg/idoff need not be known ahead.
    var bodyp = null, pid2 = -1, body = null, oneshot = false, usedReg = scr.reg, usedOff = scr.idoff;
    if (scr.reg === 'auto') {
        var pending = scr.pending[0], haveMap = pending !== undefined;
        if (!haveMap && scr.body === null) return true;              // nothing queued to inject: cheap exit
        var cand = {eax: ctx.eax, ebx: ctx.ebx, ecx: ctx.ecx, edx: ctx.edx, esi: ctx.esi, edi: ctx.edi, ebp: ctx.ebp};
        for (var rn in cand) {
            var r = cand[rn];
            if (!(r instanceof NativePointer) || r.isNull()) continue;
            if (scr.lo !== null && (r.compare(scr.lo) < 0 || r.compare(scr.hi) >= 0)) continue;
            for (var ci = 0; ci < SCR_IDOFFS.length; ci++) {
                var off2 = SCR_IDOFFS[ci], idv;
                try { idv = r.add(off2).readU16(); } catch (e) { continue; }
                if (pending && pending.id === idv) { pid2 = idv; body = pending.body; oneshot = true; }
                else if (scr.body !== null && idv === scr.id) { pid2 = idv; body = scr.body; }
                if (body !== null) { bodyp = r.add(off2 + 2); usedReg = rn; usedOff = off2; break; }
            }
            if (body !== null) break;
        }
        if (body === null) return true;                             // no register points at a slot we inject
    } else {
        var p = slotFrom(ctx, scr.reg);                             // pointer = reg (e.g. ecx = body byte)
        if (!(p instanceof NativePointer)) return true;
        if (scr.lo !== null && (p.compare(scr.lo) < 0 || p.compare(scr.hi) >= 0)) return true;   // range filter
        var idp = p.add(scr.idoff); bodyp = p.add(scr.idoff + 2);   // id at p+idoff; body right after it
        var head;
        try { head = new Uint8Array(idp.readByteArray(2)); } catch (e) { return true; }
        pid2 = head[0] | (head[1] << 8);
        if (scr.pending.length && scr.pending[0].id === pid2) { body = scr.pending[0].body; oneshot = true; }   // consumer packet wins
        else if (scr.body !== null && (scr.id === undefined || pid2 === scr.id)) { body = scr.body; }  // legacy walk
        if (body === null) return true;                             // not a packet we're injecting
    }
    var was = null;
    try { was = toHex(bodyp, body.length); } catch (e) {}
    if (usedOff === -2 && (was === null || was.length < 2)) {
        if (oneshot) workFinish(scr.pending.shift(), 'error', {e: 'original byte unavailable for byte-zero repair'});
        else send({tag: 'SENDWATCH-ERR', e: 'original byte unavailable for byte-zero repair'});
        return true;
    }
    try {
        bodyp.writeByteArray(body);                                 // overwrite plaintext; the in-place XOR encrypts ours
        if (oneshot && !(scr.persist && scr.pending[0].token === undefined)) {
            var consumed = scr.pending.shift();
        }       // Each queued consumer packet is consumed exactly once.
        if (usedOff === -2 && was !== null && was.length >= 2) {    // bodyp==ecx: o store seguinte grava body[0]
            scr._fix0 = {item: consumed, tid: Process.getCurrentThreadId(), at: bodyp, orig0: parseInt(was.slice(0, 2), 16), our0: body[0] & 0xff};
        }
        if (consumed && !scr._fix0) workFinish(consumed, 'consumed');
        send({tag: 'SCRAMBLE', hit: 'wrote', pc: scr.pc.toString(), slot: bodyp.toString(), id: pid2,
              body: was, wrote: hexOf(new Uint8Array(body)), reg: usedReg, idoff: usedOff});
    } catch (e) {
        if (oneshot && scr.pending.length) workFinish(scr.pending.shift(), 'error', {e: 'scramble write: ' + e.message});
        else send({tag: 'SENDWATCH-ERR', e: 'scramble write: ' + e.message});
    }
    return true;
}

function onScramble(m) {
    if ((m.pc !== undefined || m.off !== undefined) && researchTrap === null &&
        (m.entry || m.probe || m.trace || m.dry !== false)) {
        send({tag: 'SENDWATCH-ERR', e: 'research hooks not loaded'});
        recv('scramble', onScramble); return;
    }
    if (m.pc === undefined && m.off === undefined) {
        scr = null; scrDisarm();
    } else {
        var gep = getGepard();
        var pc = (m.off !== undefined && gep !== null) ? gep.add(m.off) : ptr(m.pc);
        scr = {pc: pc, reg: m.reg || 'edi', id: m.id, idoff: m.idoff || 0,
               lo: m.lo !== undefined ? ptr(m.lo) : null, hi: m.hi !== undefined ? ptr(m.hi) : null,
               body: m.body ? Array.from(hexToBytes(m.body)) : null, dry: m.dry !== false,
               persist: !!m.persist,   // --inject merge: keep each body and replace every matching action
               probe: !!m.probe,       // --send-probe: one-shot read-only stack walk of a real send
               entry: !!m.entry,       // --probe-entry: one-shot capture of a function's args at entry
               anyid: !!m.anyid,       // --probe-anyid: capture the first in-range hit regardless of id
               trace: !!m.trace,       // --scramble-trace: snapshot da tabela/posicoes por byte (so envio)
               traceMax: m.traceMax || 400, traceN: 0,
               nprobe: 0,              // in-range misses seen (hard cap -> disarm, never flood)
               ids: (function () { var o = {}; (m.ids || [0x0437, 0x0438]).forEach(function (x) { o[x] = 1; }); return o; })(),
               pending: []};        // ordered plaintext substitutions (pre-XOR)
        if (researchReset !== null) researchReset();
        if (!scrHandler) { scrHandler = true; Process.setExceptionHandler(scrTrap); }
        scrArm();
        console.log('[*] scramble intercept: bp @ ' + pc + ' reg ' + scr.reg +
                    ' id 0x' + ((m.id || 0).toString(16)) + (scr.dry ? ' DRY' : ' LIVE wrote=' + m.body));
    }
    recv('scramble', onScramble);
}
recv('scramble', onScramble);

// --inject merge: the driver forwards each packet the consumer wants to send as {id, body}.
// Only the FIFO head is armed; the next time the scramble BP sees its id in a slot, scrTrap
// writes the body in place of the client's own, one-shot, so the client's XOR encrypts ours.
function onScrambleSet(m) {
    var item = {id: m.id, token: m.token, epoch: m.epoch === undefined ? workEpoch : m.epoch, accepted_mono_ms: monoNow()};
    if (!workCurrent(m)) workAck('error', item, {e: 'stale epoch'});
    else if (scr === null) workAck('error', item, {e: 'scramble BP not armed'});
    else if (m.body === null || m.body === undefined) {
        var wasHead = scr.pending[0];
        scr.pending = scr.pending.filter(function (queued) {
            if (queued.id !== m.id || (m.token !== undefined && queued.token !== m.token)) return true;
            workAck('cancelled', queued); return false;
        });
        if (scr.pending.length && scr.pending[0] !== wasHead && !scr._fix0) workAck('armed', scr.pending[0]);
    }
    else if (scr.pending.length >= WORK_CAPACITY) workAck('error', item, {e: 'pending queue full'});
    else if (!/^(?:[0-9a-fA-F]{2})+$/.test(m.body)) workAck('error', item, {e: 'invalid body hex'});
    else {
        item.body = Array.from(hexToBytes(m.body));
        scr.pending.push(item);
        if (scr.pending.length === 1 && !scr._fix0) workAck('armed', item);
    }
    recv('scramble-set', onScrambleSet);
}
recv('scramble-set', onScrambleSet);

function hexToBytes(h) {
    var out = new Uint8Array(h.length >> 1);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
}

// ---- call-based injection (opt-in: the driver posts {type:'sendcall'}) -------------------------
// Spontaneous send, no client packet replaced: call the client's own SendPacket(this, len, buf)
// so it builds+encrypts+sends our bytes through its normal path. `this` is captured once with a
// one-shot hardware breakpoint at the entry (no code patching). Consumer packets are queued and
// the call is made on the GAME thread (drained from the recv/send hooks), never from the JS thread.
var scSend = null;                              // {pc, fn, this, queue:[[bytes]]}
var scDraining = false;                         // re-entrancy guard
function onSendCall(m) {
    if (m.rva === undefined && m.pc === undefined) {                 // disarm
        scSend = null;
        scrCall = null; scrCallDisarm();
    } else {
        var pc = null;
        if (m.pc !== undefined) pc = ptr(m.pc);
        else { var b = peBase(m.module || 'uaRO.exe'); pc = b !== null ? b.add(m.rva) : null; }
        if (pc === null) {
            send({tag: 'SENDCALL', hit: 'error', e: 'could not resolve ' + (m.module || 'uaRO.exe') + ' base'});
        } else {
            scSend = {pc: pc, fn: null, 'this': null, queue: []};
            scrCall = {pc: pc};                              // DR1, independente do merge de 035f (DR0)
            if (!scrHandler) { scrHandler = true; Process.setExceptionHandler(scrTrap); }
            scrCallArm();
            console.log('[*] sendcall: capturing this @ ' + pc + ' (one-shot, DR1), then call-inject on the game thread');
        }
    }
    recv('sendcall', onSendCall);
}
recv('sendcall', onSendCall);

function onSendEmit(m) {
    if (scSend === null) send({tag: 'SENDCALL', hit: 'error', e: 'emit with no sendcall armed', token: m.token, epoch: m.epoch});
    else if (!workCurrent(m)) send({tag: 'SENDCALL', hit: 'error', e: 'stale epoch', epoch: m.epoch, token: m.token});
    else if (scSend.queue.length >= WORK_CAPACITY) send({tag: 'SENDCALL', hit: 'error', e: 'queue full', epoch: m.epoch, token: m.token});
    else if (!m.data || !/^(?:[0-9a-fA-F]{2}){2,}$/.test(m.data)) send({tag: 'SENDCALL', hit: 'error', e: 'invalid packet hex', token: m.token, epoch: m.epoch});
    else scSend.queue.push({bytes: Array.from(hexToBytes(m.data)), token: m.token, epoch: m.epoch, accepted_mono_ms: monoNow()});
    recv('sendcall-emit', onSendEmit);
}
recv('sendcall-emit', onSendEmit);

function drainSendCall() {                       // only runs on the game thread (SendPacket must)
    if (scDraining || scSend === null || scSend.fn === null || scSend['this'] === null) return;
    if (scSend.queue.length === 0) return;
    if (scSend.tid && Process.getCurrentThreadId() !== scSend.tid) return;   // so na thread que roda a SendPacket
    scDraining = true;
    try {
        var current = scSend;
        while (scSend === current && current.fn !== null && current['this'] !== null && current.queue.length) {
            var queued = current.queue.shift(), pk = queued.bytes;
            if (!workCurrent(queued)) {
                send({tag: 'SENDCALL', hit: 'error', e: 'stale epoch', token: queued.token, epoch: queued.epoch});
                continue;
            }
            try {
                var buf = Memory.alloc(pk.length < 8 ? 8 : pk.length);
                buf.writeByteArray(pk);
                var nativeBegin = monoNow();
                if (scSend !== current || current.fn === null || current['this'] === null || !workCurrent(queued))
                    throw new Error('session reset before native call');
                scSend.fn(scSend['this'], pk.length, buf);           // client builds+encrypts+sends it
                send({tag: 'SENDCALL', hit: 'sent', len: pk.length, token: queued.token, epoch: queued.epoch,
                    accepted_mono_ms: queued.accepted_mono_ms, native_begin_mono_ms: nativeBegin, native_end_mono_ms: monoNow()});
            } catch (e) {
                send({tag: 'SENDCALL', hit: 'error', e: 'call: ' + e.message, token: queued.token, epoch: queued.epoch});
            }
        }
    } finally { scDraining = false; }
}

// ---- native-dispatch (opt-in: {type:'native-dispatch'}) ---------------------------------------
// PoC: em vez de fabricar o corpo do 035f, dispara o DISPATCHER NATIVO de movimento do cliente
// (0xd473b0, thiscall, frame 0x11) a partir de um sitio de main-loop do uaRO.exe (HW exec BP em
// CODIGO, DR2/DR3; sem Interceptor inline). O cliente monta, cifra e envia o proprio 035f.
// Receita validada: research/movement_035f/dispatcher_trial_pesite.py (rodadas 06b/08).
var MD_MGR = ptr('0x1213338'), MD_RET34 = ptr('0xd47e61');
var MD_RECIPES = {
    'walk-035f': {
        dispatcher: 0xd473b0, fireSite: 0x4dcba0,
        buildFrame: function (a) {                      // 13 dwords: f[1]=code 0x11, f[3]=dx, f[5]=dy
            var dx = Math.max(0, Math.min(1023, a.x | 0)), dy = Math.max(0, Math.min(1023, a.y | 0));
            return [0, 0x11, 0, dx >>> 0, 0, dy >>> 0, 0, 0, 0, 0, 0, 0, 0];
        }
    }
};
var md = null;      // {recipe, disp, site, fn, thisp, receiver, queue:[args], th, capArmed, fireArmed, busy}

function mdUnarm(slot) { if (md !== null && md.th !== null) { try { md.th.unsetHardwareBreakpoint(slot); } catch (e) {} } }

function mdReceiverReady() {                    // guarda de prontidao do receptor (rodada 06b)
    try {
        if (MD_MGR.add(0x58).readU32() !== 1) return false;
        var obj = MD_MGR.add(4).readPointer();
        var rcv = obj.readPointer().add(0x18).readPointer();
        return getGepard() !== null && rcv.equals(g.add(0x10a90));
    } catch (e) { return false; }
}

function mdTrap(ctx) {                          // devolve true se tratou o breakpoint
    if (md === null || Process.getCurrentThreadId() !== md.tid) return false;
    if (md.capArmed && ctx.pc.equals(md.disp)) {                   // captura passiva do `this` (construct mode)
        if (md.thisp === null && !md.busy) {
            var lo = ctx.esp.add(8).readU32(), hi = ctx.esp.add(12).readU32();
            if (hi === 0 && lo <= 0x95) {
                md.thisp = ctx.ecx; md.capArmed = false; mdUnarm(2);
                send({tag: 'MOVE-DISPATCH', hit: 'captured', 'this': ctx.ecx.toString(), code: lo});
            }
        }
        return true;
    }
    if (md.fireArmed && ctx.pc.equals(md.site)) {                  // sitio PE do main-loop
        if (Process.getCurrentThreadId() !== md.tid || md.thisp === null || md.queue.length === 0 || md.busy) return true;
        var currentDispatch = md, a = md.queue.shift();
        md.fireArmed = false; mdUnarm(3); md.capArmed = false; mdUnarm(2);   // sem BP aninhado
        var r = {tag: 'MOVE-DISPATCH', hit: a.token === undefined ? 'fired' : 'dispatched', x: a.x, y: a.y, token: a.token, epoch: a.epoch, accepted_mono_ms: a.accepted_mono_ms, 'this': md.thisp.toString()};
        if (!mdReceiverReady()) { r.hit = 'abort'; r.e = 'receiver not ready/changed'; send(r); }
        else {
            try {
                md.busy = true;
                var f = md.recipe.buildFrame(a);
                r.frame = f;
                var dispatchThis = currentDispatch.thisp;
                r.native_begin_mono_ms = monoNow();
                if (md !== currentDispatch || currentDispatch.thisp !== dispatchThis || !workCurrent(a))
                    throw new Error('session reset before native dispatch');
                send({tag: 'MOVE-DISPATCH', hit: 'call', token: a.token, epoch: a.epoch, mono_ms: r.native_begin_mono_ms, x: a.x, y: a.y});
                var rv = md.fn.apply(null, [md.thisp].concat(f));
                r.native_end_mono_ms = monoNow(); r.retval = rv >>> 0; r.exception = null;
            } catch (e) { r.hit = 'error'; r.exception = String(e.message || e); }
            currentDispatch.busy = false;
            send(r);
        }
        if (md === currentDispatch) {
            if (md.thisp === null && !md.capArmed) {
                try { md.th.setHardwareBreakpoint(2, md.disp); md.capArmed = true; }
                catch (e) { send({tag: 'MOVE-DISPATCH', hit: 'error', e: 'capture rearm: ' + e.message}); }
            } else if (md.queue.length) {
                try { md.th.setHardwareBreakpoint(3, md.site); md.fireArmed = true; }
                catch (e) {
                    md.queue.splice(0).forEach(function (item) {
                        send({tag: 'MOVE-DISPATCH', hit: 'error', token: item.token, epoch: item.epoch, e: 'fire rearm: ' + e.message});
                    });
                }
            }
        }
        return true;
    }
    return false;
}

function onNativeDispatch(m) {
    try {
        if (m.disarm) {
            if (md !== null) { mdUnarm(2); mdUnarm(3); }
            md = null;
        } else if (m.recapture) {
            // Reconexao/relogin: o `this` capturado aponta para objeto de mapa JA LIBERADO; firar com
            // ele toca memoria invalida e CONGELA o cliente (fila entope com 'queue full'). Zera o
            // `this`, descarta a fila pendente e re-arma a captura passiva (DR2) para recapturar fresco
            // no proximo dispatch in-client (andar uma vez). Nunca firar (DR3) sem `this` valido.
            if (md !== null && !md.busy) {
                md.thisp = null; md.queue.length = 0;
                if (md.fireArmed) { mdUnarm(3); md.fireArmed = false; }
                if (!md.capArmed) { try { md.th.setHardwareBreakpoint(2, md.disp); md.capArmed = true; } catch (e) {} }
                send({tag: 'MOVE-DISPATCH', hit: 'recapture', e: 'this reset; walk once to re-capture'});
            }
        } else if (m.arm) {
            if (md !== null) { mdUnarm(2); mdUnarm(3); md = null; }
            var rec = MD_RECIPES[m.recipe];
            var base = peBase(m.module || 'uaRO.exe');
            if (!rec || base === null) { send({tag: 'MOVE-DISPATCH', hit: 'error', e: 'recipe/base unresolved'}); }
            else {
                var disp = ptr(m.dispatcher !== undefined ? m.dispatcher : rec.dispatcher);
                var site = ptr(m.site !== undefined ? m.site : rec.fireSite);
                var why = null;
                if (!Process.findRangeByAddress(disp)) why = 'dispatcher unmapped';
                else if (!/ret\s+0x34/.test(Instruction.parse(MD_RET34).toString())) why = 'ret 0x34 anchor mismatch';
                else if (!Process.findRangeByAddress(site)) why = 'fire-site unmapped';
                if (why) send({tag: 'MOVE-DISPATCH', hit: 'error', e: why});
                else {
                    var th = Process.enumerateThreads().filter(function (t) { return t.id === Process.id; })[0];
                    var types = ['pointer']; for (var i = 0; i < 13; i++) types.push('uint32');
                    md = {recipe: rec, disp: disp, site: site, thisp: null, queue: [], th: th || null, tid: Process.id,
                          capArmed: false, fireArmed: false, busy: false,
                          fn: new NativeFunction(disp, 'uint', types, {abi: 'thiscall', exceptions: 'propagate'})};
                    if (!scrHandler) { scrHandler = true; Process.setExceptionHandler(scrTrap); }
                    if (md.th === null) { send({tag: 'MOVE-DISPATCH', hit: 'error', e: 'main thread not found'}); md = null; }
                    else { md.th.setHardwareBreakpoint(2, disp); md.capArmed = true;     // DR2: captura passiva
                           send({tag: 'MOVE-DISPATCH', hit: 'armed', disp: disp.toString(), site: site.toString()}); }
                }
            }
        } else if (m.args && md !== null) {
            if (md.thisp === null) send({tag: 'MOVE-DISPATCH', token: m.token, epoch: m.epoch, hit: 'error', e: 'dispThis not captured yet (walk once in-client)', x: m.args.x, y: m.args.y});
            else if (!workCurrent(m)) send({tag: 'MOVE-DISPATCH', token: m.token, epoch: m.epoch, hit: 'error', e: 'stale epoch'});
            else if (md.queue.length >= WORK_CAPACITY) send({tag: 'MOVE-DISPATCH', token: m.token, epoch: m.epoch, hit: 'error', e: 'queue full'});
            else {
                md.queue.push(Object.assign({}, m.args, {token: m.token, epoch: m.epoch, accepted_mono_ms: monoNow()}));
                if (!md.fireArmed) {
                    try { md.th.setHardwareBreakpoint(3, md.site); md.fireArmed = true; }
                    catch (e) { md.queue.pop(); throw e; }
                }   // DR3: sitio de disparo
                send({tag: 'MOVE-DISPATCH', token: m.token, epoch: m.epoch, hit: 'queued', x: m.args.x, y: m.args.y});
            }
        } else if (m.args) send({tag: 'MOVE-DISPATCH', token: m.token, epoch: m.epoch, hit: 'error', e: 'native-dispatch with no arm'});
    } catch (e) { send({tag: 'MOVE-DISPATCH', token: m.token, epoch: m.epoch, hit: 'error', e: 'native-dispatch: ' + e.message}); }
    recv('native-dispatch', onNativeDispatch);
}
recv('native-dispatch', onNativeDispatch);

// A new connection/session invalidates native object pointers and every queued action.
function onSessionReset(m) {
    var nextEpoch = m.epoch === undefined ? workEpoch + 1 : m.epoch;
    if (nextEpoch !== workEpoch) workMinToken = 0;
    if (typeof m.min_token === 'number') workMinToken = Math.max(workMinToken, m.min_token);
    workEpoch = nextEpoch;
    workActive = m.active === true;
    if (scr !== null) {
        scr.pending.forEach(function (item) { workAck('cancelled', item); });
        scr.pending.length = 0;
        scr.body = null;
        // A committed body still needs its next-hit XOR repair, even across an epoch reset.
        // Preserve _fix0 and its originating thread; no new action uses the old native context.
    }
    if (scSend !== null) {
        scSend.queue.length = 0; scSend.fn = null; scSend['this'] = null; scSend.tid = null;
        scrCall = {pc: scSend.pc}; scrCallArm();
    }
    if (md !== null) {
        md.queue.length = 0; md.thisp = null;
        mdUnarm(3); md.fireArmed = false;
        mdUnarm(2); md.capArmed = false;
        if (!md.busy) {
            try { md.th.setHardwareBreakpoint(2, md.disp); md.capArmed = true; }
            catch (e) { send({tag: 'MOVE-DISPATCH', hit: 'error', e: 'reset capture: ' + e.message}); }
        } // A call already in progress rearms capture on return, without nested breakpoints.
    }
    send({tag: 'SESSION', hit: 'reset', epoch: workEpoch, min_token: workMinToken, active: workActive});
    recv('session-reset', onSessionReset);
}
recv('session-reset', onSessionReset);

// never leave debug registers armed without our handler: the client would die on the next write
rpc.exports = { dispose: function () { sw = null; if (typeof swDisarm === 'function') swDisarm(); scr = null; scrDisarm(); scrCall = null; scrCallDisarm(); scSend = null; if (md !== null) { mdUnarm(2); mdUnarm(3); } md = null; } };

// ---- send --------------------------------------------------------------------------------------
hookAll(['__sendmsg64', 'sendmsg'], {
    onEnter: function (args) {
        this.fd = args[0].toInt32(); this.msg = args[1]; this.epoch = workEpoch;
        this.peer = peerOf(this.fd); this.conn = connCache[this.fd];
    },
    onLeave: function (ret) {
        var n = ret.toInt32(); if (n <= 0 || !this.peer) return;
        if (!socketUnchanged(this)) return;
        var peer = this.peer;
        if (!gepardSent) {                                  // gepard loads after login: report its base once it's up
            var gb = getGepard();
            if (gb !== null) { gepardSent = true; send({tag: 'GEPARD', base: gb.toString()}); }
        }
        var chunks = iovs(this.msg, n), h = chunks.map(function (v) { return toHex(v[0], v[1]) || ''; }).join('');
        var m = {tag: 'SEND', epoch: this.epoch, mono_ms: monoNow(), sock: peer, conn: this.conn, len: n, id: pktId(h), C: h, seq: seq++, ts: Date.now()};
        if (sw !== null && chunks.length && sw.ports.indexOf(parseInt(peer.split(':')[1], 10)) >= 0) {
            var buf = chunks[0][0], tid = Process.getCurrentThreadId();
            if (buf.compare(sw.lo) >= 0 && buf.compare(sw.hi) < 0) {
                var a = swArmed;
                if (a !== null && a.tid === tid && buf.equals(a.slot)) m.W = swWindow(a);
                m.buf = buf.toString();
                var next = buf.add(n);
                setTimeout(function () { swArm(tid, next); }, 0);   // off the game thread's hook
            }
        }
        send(m);
        if (scSend !== null) drainSendCall();                       // game thread: safe point to call-inject
    }
});

// ---- dreno periodico ---------------------------------------------------------------------------
// drainSendCall so roda depois de trafego de socket (recv/send), entao uma acao enfileirada
// (0437/0438) esperava o proximo pacote -- muitas vezes o 035f de um clique de andar. O cliente
// consulta o socket e processa mensagens a cada frame na thread do jogo; drenar a partir dessas
// chamadas frequentes entrega a acao sem precisar de trafego. drainSendCall ja se restringe a
// thread do jogo e sai barato com a fila vazia, entao isto e estritamente aditivo e seguro.
['poll', 'ppoll', 'select', 'pselect', 'pselect6'].forEach(function (name) {
    var a = Module.findGlobalExportByName(name);
    if (a === null) return;
    console.log('[+] dreno periodico em ' + name + ' @ ' + a);
    Interceptor.attach(a, { onEnter: function () {
        if (scSend !== null && scSend.queue.length) drainSendCall();
    }});
});
console.log('[*] no PE code patched');

// ---- startup log: where gepard.dll sits -----------------------------------------------------
function peBase(dllName) {
    var want = '/' + dllName.toLowerCase(), best = null;
    Process.enumerateRanges({protection: '---', coalesce: false}).forEach(function (r) {
        if (!r.file || !r.file.path) return;
        var p = r.file.path.toLowerCase();
        if (p.slice(-want.length) !== want) return;
        if (best === null || r.base.compare(best) < 0) best = r.base;
    });
    if (best === null) return null;
    try { if (best.readU16() !== 0x5a4d) return null; } catch (e) { return null; }   // 'MZ'
    return best;
}

getGepard();
console.log('[*] gepard.dll base: ' + (g === null ? 'not loaded yet (resolved after login)' : g));
if (g !== null) { gepardSent = true; send({tag: 'GEPARD', base: g.toString()}); }  // else reported on the first send
console.log('[*] ready. Log in / enter map to generate traffic.');
