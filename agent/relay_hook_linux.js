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
var peerCache = {};     // fd -> "ip:port" of the last query (a hint only: fds get reused)
var connCache = {};     // fd -> local port = a unique id per TCP connection

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
        len.writeU32(128);
        if (libcGetsockname(fd, sa, len) === 0) connCache[fd] = portAt(sa);
    }
    return (peerCache[fd] = res);
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

// Fail closed: never let the outgoing scramble merge modify a registered RX ring.
// Compare the entire write interval, not just its first byte (including _fix0).
function overlapsRecvRing(at, length) {
    if (!(at instanceof NativePointer) || !Number.isSafeInteger(length) || length < 0) return true;
    if (length === 0) return false;
    try {
        var end = at.add(length);
        if (end.compare(at) <= 0) return true;
        for (var peer in ringBase) {
            if (!Object.prototype.hasOwnProperty.call(ringBase, peer)) continue;
            var base = ringBase[peer];
            if (!(base instanceof NativePointer) || base.isNull()) return true;
            var span = ringBytes(peer, lastLen[peer] || 0);
            var ringEnd = base.add(span);
            if (ringEnd.compare(base) <= 0) return true;
            if (at.compare(ringEnd) < 0 && end.compare(base) > 0) return true;
        }
        return false;
    } catch (e) { return true; }
}

hookAll(['__recvmsg64', 'recvmsg'], {
    onEnter: function (args) {
        this.fd = args[0].toInt32(); this.msg = args[1];
        var hint = peerCache[this.fd];
        if (!hint || !ringBase[hint] || !lastLen[hint]) return;     // not a socket we snapshot: no syscall
        var peer = peerOf(this.fd);                                 // the fd may now be another connection
        if (!peer || !ringBase[peer] || !lastLen[peer]) return;
        try {
            send({tag: 'RINGSNAP', sock: peer, conn: connCache[this.fd], base: ringBase[peer].toString(),
                  seq: seq, ts: Date.now()}, ringBase[peer].readByteArray(ringBytes(peer, lastLen[peer])));
        } catch (e) {}
    },
    onLeave: function (ret) {
        var n = ret.toInt32(); if (n <= 0) return;
        var fd = this.fd, peer = peerOf(fd); if (!peer) return;
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
            send({tag: 'RECV', sock: peer, conn: connCache[fd], len: v[1], id: pktId(h), C: h,
                  ptr: v[0].toString(), seq: seq++, ts: Date.now(),
                  pre: first ? ringBase[peer].toString() : undefined}, first ? pre : null);
        });
        if (scSend !== null) drainSendCall();                       // game thread: safe point to call-inject
    }
});

// ---- send watch (opt-in: the driver posts {type:'sendwatch'}) ----------------------------------
// 0437 action / 0438 skill are built in the client's send queue, back to back (the next packet goes
// at buf + len), and the client encrypts the body IN PLACE before sendmsg. A hardware write watchpoint on
// the next slot (all 4 debug registers = 16 bytes, slots are unaligned) sees the plaintext before the
// encryptor overwrites it. The trap handler only copies pc + the 16 bytes into a preallocated ring:
// a heavier handler (first relay_sendbp.py run) hung the client. The window rides along with the
// SEND and the driver picks the plaintext out (relay_sendbp.py --queue = the same method).
var sw = null;                                  // {lo, hi, ports} while the watch is on
var swArmed = null;                             // {tid, thread, slot, base, words}
var SWREC = 5, SWRING = 32;                     // record = pc + 4 words; ring of the last 32 writes
var swRing = new Uint32Array(SWREC * SWRING), swN = 0, swThread = null, swHandler = false;

function swDisarm() {
    var a = swArmed; if (a === null) return;
    swArmed = null;
    for (var i = 0; i < 4; i++) { try { a.thread.unsetHardwareWatchpoint(i); } catch (e) {} }
}

function swArm(tid, slot) {
    swDisarm();
    if (sw === null) return;
    if (swThread === null || swThread.id !== tid)
        swThread = Process.enumerateThreads().filter(function (t) { return t.id === tid; })[0] || null;
    if (swThread === null) return;
    var base = slot.and(ptr(~3 >>> 0)), words = [base, base.add(4), base.add(8), base.add(12)];
    swN = 0;
    swArmed = {tid: tid, thread: swThread, slot: slot, base: base, words: words};
    try {
        for (var w = 0; w < 4; w++) swThread.setHardwareWatchpoint(w, words[w], 4, 'w');
    } catch (e) { swDisarm(); send({tag: 'SENDWATCH-ERR', e: e.message}); }
}

function swHex(o) {                             // the 16 watched bytes of record o, as hex
    var s = '';
    for (var w = 1; w <= 4; w++) {
        var v = swRing[o + w];
        s += HEX[v & 0xff] + HEX[(v >>> 8) & 0xff] + HEX[(v >>> 16) & 0xff] + HEX[(v >>> 24) & 0xff];
    }
    return s;
}

function swWindow(a) {                          // writes since arming, oldest of the kept ones first
    var keep = Math.min(swN, SWRING), hits = [];
    for (var j = swN - keep; j < swN; j++) {
        var o = (j % SWRING) * SWREC;
        hits.push({pc: '0x' + swRing[o].toString(16), win: swHex(o)});
    }
    return {base: a.base.toString(), n: swN, hits: hits};
}

function swTrap(d) {
    var a = swArmed;
    if (a === null || (d.type !== 'single-step' && d.type !== 'breakpoint')) return false;
    if (Process.getCurrentThreadId() !== a.tid) return false;
    var o = (swN % SWRING) * SWREC;
    swRing[o] = d.context.pc.toUInt32();
    for (var w = 0; w < 4; w++) swRing[o + 1 + w] = a.words[w].readU32();
    swN++;
    return true;                                // data watchpoints trap AFTER the write: just resume
}

function onSendWatch(m) {
    if (m.lo) {
        sw = {lo: ptr(m.lo), hi: ptr(m.hi), ports: m.ports || [5121]};
        if (!swHandler) {                       // registered only once the feature is on
            swHandler = true;
            Process.setExceptionHandler(swTrap);
        }
        console.log('[*] send watch on: queue ' + sw.lo + '-' + sw.hi + ' ports ' + sw.ports);
    } else {
        sw = null; swDisarm();
    }
    recv('sendwatch', onSendWatch);
}
recv('sendwatch', onSendWatch);

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
var scr = null;                                 // {pc, reg, id, body(array)|null, dry} or null
var scrThread = null, scrHandler = false;
var scrCall = null;                              // sendcall: {pc} do ponto de captura do `this`, em DR1
// Session-scoped allocator: never overwrite a slot owned by another hook.
// Hardware API reports whether a candidate slot is actually available.
var hwOwners = {};
var hwProbe = null;                                // one-shot read-only research exec breakpoint
// Bounded breakpoint lifecycle telemetry; no payload, stack, or user data.
var bpStats = {};
function bpEvent(owner, event, extra) {
    var o = {tag:'BP-TELEMETRY', owner:owner, hit:event, ts:Date.now(), generation:sessionGeneration};
    if (extra) Object.keys(extra).forEach(function(k) { o[k] = extra[k]; });
    send(o);
}
function bpHit(owner, durationMs, result) {
    var now = Date.now(), s = bpStats[owner] || (bpStats[owner] = {count:0, last:0, maxMs:0});
    s.count++;
    s.maxMs = Math.max(s.maxMs, durationMs);
    // A rare slow handler is reported immediately; normal hits at most every 5 seconds.
    if (durationMs >= 20 || now - s.last >= 5000) {
        bpEvent(owner, 'hit-summary', {count:s.count, max_ms:s.maxMs, duration_ms:durationMs, result:result});
        s.count = 0; s.maxMs = 0; s.last = now;
    }
}
function hwSet(owner, th, pc) {
    var old = hwOwners[owner];
    if (old) { hwClear(owner); }
    var used = {};
    Object.keys(hwOwners).forEach(function (k) { if (hwOwners[k].th.id === th.id) used[hwOwners[k].slot] = true; });
    var errors = [];
    for (var i = 0; i < 4; i++) {
        if (used[i]) continue;
        try { th.setHardwareBreakpoint(i, pc); hwOwners[owner] = {th: th, slot: i}; bpEvent(owner, 'armed', {slot:i, tid:th.id, pc:pc.toString()}); return i; }
        catch (e) { errors.push(i + ':' + e.message); }
    }
    bpEvent(owner, 'arm-error', {tid:th.id, pc:pc.toString(), reason:errors.join(',')});
    throw new Error('no free hardware breakpoint: ' + errors.join(','));
}
function hwClear(owner) {
    var a = hwOwners[owner]; if (!a) return;
    delete hwOwners[owner];
    try { a.th.unsetHardwareBreakpoint(a.slot); bpEvent(owner, 'disarmed', {slot:a.slot, tid:a.th.id}); }
    catch (e) { bpEvent(owner, 'disarm-error', {slot:a.slot, tid:a.th.id, reason:String(e)}); }
}
var sessionBlockedUntil = 0, sessionGeneration = 0;
// Low-volume lifecycle diagnostics, no speculative memory dereferences.
var thisDiagSeen = {};
function thisDiag(kind, owner, reason, address) {
    var key = sessionGeneration + ':' + owner + ':' + kind + ':' + reason;
    if (thisDiagSeen[key]) return;
    thisDiagSeen[key] = true;
    send({tag:'THIS-CONTEXT',hit:kind,owner:owner,reason:reason,
          address:address ? address.toString() : null,
          generation:sessionGeneration,ts:Date.now()});
}

function sessionReady() { return Date.now() >= sessionBlockedUntil; }
function resetNativeSession(reason, delayMs) {
    if (delayMs === undefined) delayMs = 1500;
    sessionGeneration++;
    thisDiagSeen = {};
    if (scSend !== null && scSend['this'] !== null)
        thisDiag('stale','SendPacket','session transition: '+reason,scSend['this']);
    if (md !== null && md.thisp !== null)
        thisDiag('stale','MoveDispatch','session transition: '+reason,md.thisp);
    if (gd !== null && gd.thisp !== null)
        thisDiag('stale','GepardDispatch','session transition: '+reason,gd.thisp);
    scDemandScheduled = false;
    sessionBlockedUntil = Date.now() + delayMs;
    if (scSend !== null) {
        scSend.queue.length = 0; scSend.fn = null; scSend['this'] = null;
        scSend.tid = null; scSend.awaitRecapture = true;
    }
    scrCall = null; hwClear('sendcall');
    if (hwProbe !== null) {
        if (hwProbe.rearmSession) hwClear('research-probe');
        else { hwProbe = null; hwClear('research-probe'); }
    }
    if (md !== null) {
        md.thisp = null; md.receiver = null; md.queue.length = 0;
        md.capArmed = false; md.fireArmed = false;
        hwClear('move-cap'); hwClear('move-fire');
    }
    if (gd !== null) {
        gd.thisp = null; gd.queue.length = 0; gd.capArmed = false; gd.fireArmed = false;
        hwClear('gepard-cap'); hwClear('gepard-fire');
    }
    var epoch = sessionGeneration;
    send({tag:'NATIVE-SESSION', hit:'invalidated', reason:reason, ts:Date.now(), wait_ms:delayMs, generation:epoch});
    setTimeout(function () {
        if (epoch !== sessionGeneration) return;
        if (scSend !== null) {
            scrCall = {pc: scSend.pc};
            try { scrCallArm(); } catch(e) { send({tag:'SENDCALL',hit:'error',e:'delayed arm: '+e.message}); }
        }
        if (md !== null && md.th !== null) {
            try { hwSet('move-cap', md.th, md.disp); md.capArmed = true; }
            catch(e) { send({tag:'MOVE-DISPATCH',hit:'error',e:'delayed arm: '+e.message}); }
        }
        if (gd !== null && gd.th !== null) {
            try { hwSet('gepard-cap', gd.th, gd.callsite); gd.capArmed = true; }
            catch(e) { send({tag:'GEPARD-DISPATCH',hit:'error',e:'delayed arm: '+e.message}); }
        }
        if (hwProbe !== null && hwProbe.rearmSession) {
            try {
                var pth = Process.enumerateThreads().filter(function(t){return t.id === Process.id;})[0] || null;
                if (pth !== null) { hwProbe.th = pth; hwSet('research-probe', pth, hwProbe.pc);
                    send({tag:'HW-PROBE',hit:'rearmed-session',token:hwProbe.token || null,
                          pc:hwProbe.pc.toString(),tid:pth.id,ts:Date.now()}); }
            } catch(e) { send({tag:'HW-PROBE',hit:'error',e:'session rearm: '+e.message,ts:Date.now()}); }
        }
        send({tag:'NATIVE-SESSION',hit:'recapture-armed',generation:epoch,ts:Date.now()});
    }, delayMs);
}

var GP = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'];
var SCR_IDOFFS = [-2, 0];                        // reg='auto': try id just before the body pointer, then at it

function scrDisarm() { hwClear('scramble'); }
function scrArm() {
    scrDisarm(); if (scr === null) return;
    scrThread = Process.enumerateThreads().filter(function (t) { return t.id === Process.id; })[0] || null;
    if (scrThread === null) { send({tag:'SENDWATCH-ERR',e:'scramble: main thread not found'}); return; }
    try { hwSet('scramble',scrThread,scr.pc); }
    catch(e) { scr=null; send({tag:'SENDWATCH-ERR',e:'scramble bp: '+e.message}); }
}
function scrCallDisarm() { hwClear('sendcall'); }
function scrCallArm() {
    scrCallDisarm();
    if (scrCall === null || !sessionReady()) return;
    scrThread = scrThread || Process.enumerateThreads().filter(function(t){return t.id === Process.id;})[0] || null;
    if (scrThread === null) { send({tag:'SENDCALL',hit:'error',e:'main thread not found'}); return; }
    try { hwSet('sendcall',scrThread,scrCall.pc); }
    catch(e) { send({tag:'SENDCALL',hit:'error',e:'bp: '+e.message}); }
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

var scrEntry;                                    // cached nearest function prologue before the bp pc
function scrPrologue() {
    if (scrEntry !== undefined) return scrEntry;
    scrEntry = null;
    try {
        var span = 0x400, base = scr.pc.sub(span), buf = new Uint8Array(base.readByteArray(span));
        for (var k = buf.length - 3; k >= 0; k--) {        // push ebp; mov ebp,esp  (55 8B EC / 55 89 E5)
            if (buf[k] === 0x55 && ((buf[k + 1] === 0x8b && buf[k + 2] === 0xec) || (buf[k + 1] === 0x89 && buf[k + 2] === 0xe5))) {
                var e = base.add(k);
                scrEntry = {abs: e.toString(), off: g !== null ? '0x' + e.sub(g).toString(16) : null};
                break;
            }
        }
    } catch (e) {}
    return scrEntry;
}

// --send-probe: on the first recognised client send, capture the registers and walk the stack for
// return addresses into mapped modules (resolved to module+offset and the nearest prologue), so the
// driver can pick the client's callable send routine. One-shot and read-only - it never writes.
function safeHead(p, n) {                                            // first n (default 16) bytes at p, hex, or null
    if (!(p instanceof NativePointer) || p.isNull()) return null;
    try { return hexOf(new Uint8Array(p.readByteArray(n || 16))); } catch (e) { return null; }
}

// --probe-entry: one-shot capture of a function's arguments at its entry. On the first hit we dump
// the registers, the top of the stack (incoming args / return address), and the first bytes each of
// those points at, so the driver can see how the packet/slot is passed. Read-only; disarms at once.
function scrProbeEntry(ctx) {
    if (scr.lo !== null) {                                           // gated: a send-packet copy into the queue
        var args = [];                                              // at entry: [esp]=return addr, [esp+4..]=args
        for (var j = 1; j <= 4; j++) { try { args.push(ctx.esp.add(j * 4).readPointer()); } catch (e) { args.push(null); } }
        var inRange = args.some(function (a) { return a && a.compare(scr.lo) >= 0 && a.compare(scr.hi) < 0; });
        var hasId = args.some(function (a) {
            if (!a) return false;
            try { return scr.ids[a.readU16()] === 1; } catch (e) { return false; }
        });
        if (!(inRange || hasId)) return true;                       // not the call we want: keep waiting
    }
    var regs = {}, regmem = {};
    GP.forEach(function (r) { try { regs[r] = ctx[r].toString(); regmem[r] = safeHead(ctx[r]); } catch (e) {} });
    var stack = [], esp = ctx.esp;
    for (var i = 0; i < 12; i++) {                                   // [esp+0]=return addr, [esp+4..]=args (cdecl/stdcall)
        var v;
        try { v = esp.add(i * 4).readPointer(); } catch (e) { break; }
        var c = codeAt(v);
        stack.push({off: '0x' + (i * 4).toString(16), val: v.toString(),
                    code: c ? (c.name + '+0x' + v.sub(c.base).toString(16)) : null, mem: safeHead(v)});
    }
    send({tag: 'SCRAMBLE', hit: 'entry', pc: scr.pc.toString(), regs: regs, regmem: regmem, stack: stack});
    scr = null; scrDisarm();                                         // one-shot
    return true;
}

function scrProbe(ctx) {
    var PROBE_IDS = scr.ids;                                         // the encrypted client send ids to gate on
    var cand = {eax: ctx.eax, ebx: ctx.ebx, ecx: ctx.ecx, edx: ctx.edx, esi: ctx.esi, edi: ctx.edi, ebp: ctx.ebp};
    var slotReg = null, slotPtr = null, slotId = -1, slotOff = null, inRange = null;
    for (var rn in cand) {                                           // confirm a real send: a reg points at a slot id we expect
        var r = cand[rn];
        if (!(r instanceof NativePointer) || r.isNull()) continue;
        if (scr.lo !== null && (r.compare(scr.lo) < 0 || r.compare(scr.hi) >= 0)) continue;   // cheap reject
        if (inRange === null) inRange = {rn: rn, r: r};              // first reg inside the range
        for (var ci = 0; ci < SCR_IDOFFS.length; ci++) {
            var o = SCR_IDOFFS[ci], idv;
            try { idv = r.add(o).readU16(); } catch (e) { continue; }
            if (PROBE_IDS[idv]) { slotReg = rn; slotPtr = r.add(o); slotId = idv; slotOff = o; break; }
        }
        if (slotReg) break;
    }
    if (slotReg === null && scr.anyid && inRange !== null) {         // range is the gate: take the first in-range hit
        slotReg = inRange.rn; slotPtr = inRange.r.add(SCR_IDOFFS[0]); slotOff = SCR_IDOFFS[0];
        try { slotId = inRange.r.add(SCR_IDOFFS[0]).readU16(); } catch (e) { slotId = -1; }
    }
    if (slotReg === null) {                                          // no match yet
        if (inRange !== null && ++scr.nprobe >= 2000) {              // hard cap on in-range work -> disarm, never flood
            send({tag: 'SENDWATCH-ERR', e: 'probe: ' + scr.nprobe + ' in-range hits, no id match; disarming'});
            scr = null; scrDisarm();
        }
        return true;                                                // out-of-range hits are rejected cheaply, not counted
    }
    var regs = {};
    GP.forEach(function (r) { try { regs[r] = ctx[r].toString(); } catch (e) {} });
    var frames = [], esp = ctx.esp;
    for (var i = 0; i < 512 && frames.length < 64; i++) {            // scan the stack for return addresses
        var w;
        try { w = esp.add(i * 4).readPointer(); } catch (e) { break; }
        if (w.isNull()) continue;
        var c = codeAt(w);                                           // file-backed executable range (Wine PE too)
        if (c === null) continue;
        frames.push({sp: '0x' + (i * 4).toString(16), ret: w.toString(), mod: c.name,
                     off: '0x' + w.sub(c.base).toString(16), entry: scrPrologueBefore(w)});
    }
    send({tag: 'SCRAMBLE', hit: 'probe', pc: scr.pc.toString(), reg: slotReg, idoff: slotOff,
          id: slotId, slot: slotPtr.toString(), regs: regs, frames: frames});
    scr = null; scrDisarm();                                         // one-shot
    return true;
}

// Executable, file-backed ranges (Frida's module API misses Wine-loaded PE modules, so resolve
// addresses against the mapped ranges directly, as peBase() does). `base` is the lowest range of
// the same file - a usable module base for RVAs. Cached; recomputed only if a lookup misses.
var CODE_RANGES = null;
// Faixas executaveis para resolver enderecos da pilha. O codigo do uaRO roda em memoria ANONIMA
// (desempacotado pelo gepard, base 0x401000), por isso incluimos faixas anonimas executaveis de
// endereco baixo (< 0x2000000: o uaRO em 0x401000 e o blob do gepard em 0x1717000) alem dos modulos
// .exe/.dll com arquivo; pulamos .grf (dados) e as regioes anonimas altas (pilhas/heaps). Construida
// UMA vez - reconstruir a cada endereco sem correspondencia travava a thread do jogo.
var LIMITE_ANON = ptr('0x2000000');
function codeRanges() {
    if (CODE_RANGES) return CODE_RANGES;
    var grupos = {};
    Process.enumerateRanges({protection: 'r-x', coalesce: false}).forEach(function (r) {
        var cam = (r.file && r.file.path) ? r.file.path : null, chave, nome;
        if (cam) {
            if (!/\.(exe|dll)$/i.test(cam)) return;                  // pular arquivos de dados (.grf, .nls)
            chave = cam; nome = cam.split('/').pop();
        } else {
            if (r.base.compare(LIMITE_ANON) >= 0) return;            // anonimo alto = pilha/heap, nao codigo
            chave = 'anon:' + r.base; nome = 'anon@' + r.base;       // codigo desempacotado (uaRO, VM gepard)
        }
        (grupos[chave] = grupos[chave] || {nome: nome, faixas: []}).faixas.push([r.base, r.base.add(r.size)]);
    });
    var saida = [];
    for (var k in grupos) {
        var g = grupos[k], base = g.faixas[0][0];
        g.faixas.forEach(function (x) { if (x[0].compare(base) < 0) base = x[0]; });
        g.faixas.forEach(function (x) { saida.push({lo: x[0], hi: x[1], name: g.nome, base: base}); });
    }
    return (CODE_RANGES = saida);
}
function codeAt(ptr) {                                               // sem reconstruir: evita o congelamento
    var rs = codeRanges();
    for (var i = 0; i < rs.length; i++) if (ptr.compare(rs[i].lo) >= 0 && ptr.compare(rs[i].hi) < 0) return rs[i];
    return null;
}

function scrPrologueBefore(addr) {                                   // nearest push ebp;mov ebp,esp before addr
    try {
        var c = codeAt(addr);
        if (c === null) return null;
        var span = 0x600, base = addr.sub(span);
        if (base.compare(c.lo) < 0) { base = c.lo; span = addr.sub(c.lo).toInt32(); }
        if (span <= 3) return null;
        var buf = new Uint8Array(base.readByteArray(span));
        for (var k = buf.length - 3; k >= 0; k--) {
            if (buf[k] === 0x55 && ((buf[k + 1] === 0x8b && buf[k + 2] === 0xec) || (buf[k + 1] === 0x89 && buf[k + 2] === 0xe5))) {
                var e = base.add(k);
                return {abs: e.toString(), off: '0x' + e.sub(c.base).toString(16), mod: c.name};
            }
        }
    } catch (e) {}
    return null;
}

function stackCodeFrames(esp, maxWords, maxFrames) {
    // HW breakpoint handlers run in exception context: keep this deliberately cheap.
    // Resolve only executable mappings here; deeper prologue analysis belongs off the hot path.
    var frames = [];
    maxWords = Math.min(maxWords, 96);
    maxFrames = Math.min(maxFrames, 16);
    for (var i = 0; i < maxWords && frames.length < maxFrames; i++) {
        var w;
        try { w = esp.add(i * 4).readPointer(); } catch (e) { break; }
        if (w.isNull()) continue;
        var c = codeAt(w);
        if (c === null) continue;
        frames.push({sp:'0x' + (i * 4).toString(16), ret:w.toString(), mod:c.name,
                     off:'0x' + w.sub(c.base).toString(16)});
    }
    return frames;
}

function hwProbeClear(hit) {
    var p = hwProbe;
    if (p === null) return;
    hwProbe = null;
    hwClear('research-probe');
    if (hit) send({tag:'HW-PROBE',hit:hit,token:p.token || null,pc:p.pc.toString(),ts:Date.now()});
}
function hwProbeTrap(ctx) {
    var p = hwProbe;
    if (p === null || !ctx.pc.equals(p.pc)) return false;
    try {
        if (p.filterIndex !== null) {
            var gate = ctx.esp.add(p.filterIndex * 4).readU32();
            if (gate !== p.filterValue) return true;   // handled, remain armed; minimal hot-path work
        }
        var stack = [];
        for (var i = 0; i < p.stackWords; i++) stack.push(ctx.esp.add(i * 4).readU32());
        var regs = {};
        GP.forEach(function (r) { try { regs[r] = ctx[r].toString(); } catch (e) {} });
        var ebpWords = [];
        try { for (var j = 0; j < 8; j++) ebpWords.push(ctx.ebp.add(j * 4).readU32()); } catch (e) {}
        // Bounded raw EBP chain: no symbol/prologue work in exception context. This lets offline analysis
        // recover exact parent return addresses instead of guessing from unrelated executable-looking words.
        var ebpChain = [], fp = ctx.ebp;
        try {
            for (var depth = 0; depth < 8; depth++) {
                var saved = fp.readPointer(), ret = fp.add(4).readPointer(), argv = [];
                for (var ai = 0; ai < 6; ai++) argv.push(fp.add(8 + ai * 4).readU32());
                ebpChain.push({fp:fp.toString(), saved:saved.toString(), ret:ret.toString(), args:argv});
                if (saved.isNull() || saved.compare(fp) <= 0 || saved.sub(fp).toUInt32() > 0x100000) break;
                fp = saved;
            }
        } catch (e) {}
        var frames = stackCodeFrames(ctx.esp, 512, 64);
        var msg = {tag:'HW-PROBE',hit:'captured',token:p.token || null,pc:ctx.pc.toString(),
                   tid:Process.getCurrentThreadId(),ecx:ctx.ecx.toString(),esp:ctx.esp.toString(),
                   ebp:ctx.ebp.toString(),stack:stack,ebp_words:ebpWords,ebp_chain:ebpChain,
                   regs:regs,frames:frames,ts:Date.now()};
        hwProbe = null; hwClear('research-probe');
        send(msg);
    } catch (e) {
        hwProbe = null; hwClear('research-probe');
        send({tag:'HW-PROBE',hit:'error',token:p.token || null,pc:p.pc.toString(),e:String(e),ts:Date.now()});
    }
    return true;
}
function onHwExecProbe(m) {
    try {
        hwProbeClear(null);
        var base = peBase(m.module || 'uaRO.exe');
        if (base === null) throw new Error('module base unresolved');
        var pc = base.add(Number(m.rva));
        if (!Process.findRangeByAddress(pc)) throw new Error('probe pc unmapped');
        var th = Process.enumerateThreads().filter(function (t) { return t.id === Process.id; })[0] || null;
        if (th === null) throw new Error('main thread not found');
        var words = Math.max(1, Math.min(16, Number(m.stackWords || 8)));
        var timeoutMs = Math.max(100, Math.min(60000, Number(m.timeoutMs || 5000)));
        var token = m.token || null;
        var filterIndex = m.filterIndex === undefined ? null : Math.max(0, Math.min(15, Number(m.filterIndex)));
        var filterValue = m.filterValue === undefined ? null : (Number(m.filterValue) >>> 0);
        hwProbe = {pc:pc,th:th,stackWords:words,token:token,filterIndex:filterIndex,
                   filterValue:filterValue,rearmSession:!!m.rearmSession};
        if (!scrHandler) { scrHandler = true; Process.setExceptionHandler(scrTrap); }
        hwSet('research-probe', th, pc);
        send({tag:'HW-PROBE',hit:'armed',token:token,pc:pc.toString(),tid:th.id,
              stack_words:words,timeout_ms:timeoutMs,ts:Date.now()});
        setTimeout(function () {
            if (hwProbe !== null && hwProbe.pc.equals(pc) && hwProbe.token === token) hwProbeClear('timeout');
        }, timeoutMs);
    } catch (e) {
        hwProbe = null; hwClear('research-probe');
        send({tag:'HW-PROBE',hit:'error',token:m.token || null,e:String(e),ts:Date.now()});
    }
    recv('hw-exec-probe', onHwExecProbe);
}
recv('hw-exec-probe', onHwExecProbe);

function scrTrap(d) {
    if (d.type !== 'breakpoint') return false;
    var started = Date.now(), owner = 'unknown', result = false;
    try {
        var pc = d.context.pc;
        if (md !== null && ((md.capArmed && pc.equals(md.disp)) || (md.fireArmed && pc.equals(md.site))))
            owner = md.capArmed && pc.equals(md.disp) ? 'move-cap' : 'move-fire';
        else if (gd !== null && ((gd.capArmed && pc.equals(gd.callsite)) || (gd.fireArmed && pc.equals(gd.site))))
            owner = gd.capArmed && pc.equals(gd.callsite) ? 'gepard-cap' : 'gepard-fire';
        else if (scrCall !== null && pc.equals(scrCall.pc)) owner = 'sendcall';
        else if (hwProbe !== null && pc.equals(hwProbe.pc)) owner = 'research-probe';
        else if (scr !== null && pc.equals(scr.pc)) owner = 'scramble';
        result = scrTrapCore(d);
        return result;
    } catch (e) {
        bpEvent(owner, 'handler-error', {reason:String(e)});
        throw e;
    } finally {
        if (owner !== 'unknown') bpHit(owner, Date.now() - started, result ? 'handled' : 'unhandled');
    }
}
function scrTrapCore(d) {
    if (d.type !== 'breakpoint') return false;
    var ctx = d.context;
    if (hwProbe !== null && hwProbeTrap(ctx)) return true; // one-shot read-only research BP
    if (gd !== null && gdTrap(ctx)) return true;       // protected wrapper dispatch (DR2/DR3)
    if (md !== null && mdTrap(ctx)) return true;       // native-dispatch (DR2/DR3)
    // sendcall: captura de uso unico do `this` (ecx) na entrada da SendPacket, no DR1 -- independente
    // do merge de 035f (DR0), que segue armado. Depois a SendPacket e chamada por NativeFunction.
    if (scrCall !== null && ctx.pc.equals(scrCall.pc)) {
        try {
            scSend['this'] = ctx.ecx;
            scSend.tid = Process.getCurrentThreadId();   // a thread em que a SendPacket roda; drenar so nela
            scSend.awaitRecapture = false;
            scSend.fn = new NativeFunction(scrCall.pc, 'void', ['pointer', 'int', 'pointer'], 'thiscall');
            send({tag: 'SENDCALL', hit: 'ready', 'this': ctx.ecx.toString(), pc: scrCall.pc.toString(), tid: scSend.tid});
        } catch (e) { send({tag: 'SENDCALL', hit: 'error', e: 'arm: ' + e.message}); }
        scrCall = null; scrCallDisarm();
        return true;
    }
    if (scr === null || !ctx.pc.equals(scr.pc)) return false;
    if (scr.entry) return scrProbeEntry(ctx);                        // --probe-entry: capture args + disarm
    if (scr.probe) return scrProbe(ctx);                             // --send-probe: capture + disarm, no write
    if (scr.trace) {                                                 // TRACE: snapshot por byte, so no fluxo de envio
        if (scr.lo === null) {                                       // trace exige --scramble-range; sem ele, desarma
            scr.trace = false; scrDisarm();
            send({tag: 'SCRAMBLE', hit: 'trace-done', n: scr.traceN, e: 'trace needs --scramble-range'});
            return true;
        }
        var ex = ctx.ecx, bx = ctx.ebx;
        if (!(ex instanceof NativePointer) ||
            ex.compare(scr.lo) < 0 || ex.compare(scr.hi) >= 0) return true;   // so envio (ecx no range)
        if (scr.traceN >= scr.traceMax) { scr.trace = false; scrDisarm(); send({tag: 'SCRAMBLE', hit: 'trace-done', n: scr.traceN}); return true; }
        scr.traceN++;
        var wb = bx.sub(bx.and(0x3ff)), tbl = null, db = null;       // janela 1KB-alinhada ao ebx
        try { tbl = toHex(wb, 0x600); } catch (e) {}
        try { db = toHex(ex, 1); } catch (e) {}
        send({tag: 'SCRAMBLE', hit: 'trace', n: scr.traceN, ecx: ex.toString(), ebx: bx.toString(), win: wb.toString(), db: db, tbl: tbl});
        return true;
    }
    if (scr.dry) {                                                   // DRY: report everything, write nothing
        var regs = {}, stk = [], i;
        GP.forEach(function (r) { try { regs[r] = ctx[r].toString(); } catch (e) {} });
        for (i = 0; i < 6; i++) { try { stk.push(ctx.esp.add(4 * i).readPointer().toString()); } catch (e) { stk.push(null); } }
        var slot = slotFrom(ctx, scr.reg), pid = null, body = null;
        if (slot instanceof NativePointer) {
            try { var h = new Uint8Array(slot.readByteArray(2)); pid = h[0] | (h[1] << 8); body = toHex(slot.add(2), 8); } catch (e) {}
        }
        send({tag: 'SCRAMBLE', hit: 'dry', pc: scr.pc.toString(), reg: scr.reg,
              slot: slot ? slot.toString() : null, id: pid, body: body, regs: regs, stack: stk,
              entry: scrPrologue()});
        return true;
    }
    // --- byte0 fix (merge) ---------------------------------------------------------------------
    // O store scr.pc (mov [ecx],bl) grava UM byte em bodyp[0] DEPOIS do nosso writeByteArray, com o
    // valor derivado do byte ORIGINAL (bl foi carregado antes do nosso write) -> body[0] revertia:
    // ataque no GID errado (byte baixo do GID) e perícia saindo nível 1 (byte baixo do nível). Como o
    // scrambler é ascendente (body[0] primeiro), corrigimos no hit SEGUINTE (byte1 do mesmo pacote, o
    // store de body[0] já rodou) reescrevendo body[0] pela identidade XOR, sem conhecer o keystream
    // nem assumir onde o XOR é aplicado: final = (valor_atual) ^ original0 ^ nosso0.
    if (scr._fix0) {
        var f0 = scr._fix0; scr._fix0 = null;
        if (!overlapsRecvRing(f0.at, 1)) {
            try { var c0 = f0.at.readU8(); f0.at.writeU8((c0 ^ f0.orig0 ^ f0.our0) & 0xff); } catch (e) {}
        } else send({tag: 'SCRAMBLE', hit: 'blocked-rx-ring', phase: 'fix0'});
    }
    // Find the slot pointer + which body to write. Two modes:
    //   fixed  (scr.reg is a register / sN): pointer = that reg, id at pointer+idoff (configured).
    //   auto   (scr.reg === 'auto'): scan GP registers for one that points at a slot whose id is one
    //          we're injecting, trying a couple of id offsets - so reg/idoff need not be known ahead.
    var bodyp = null, pid2 = -1, body = null, oneshot = false, usedReg = scr.reg, usedOff = scr.idoff;
    if (scr.reg === 'auto') {
        var haveMap = false, kk; for (kk in scr.bodies) { haveMap = true; break; }
        if (!haveMap && scr.body === null) return true;              // nothing queued to inject: cheap exit
        var cand = {eax: ctx.eax, ebx: ctx.ebx, ecx: ctx.ecx, edx: ctx.edx, esi: ctx.esi, edi: ctx.edi, ebp: ctx.ebp};
        for (var rn in cand) {
            var r = cand[rn];
            if (!(r instanceof NativePointer) || r.isNull()) continue;
            if (scr.lo !== null && (r.compare(scr.lo) < 0 || r.compare(scr.hi) >= 0)) continue;
            for (var ci = 0; ci < SCR_IDOFFS.length; ci++) {
                var off2 = SCR_IDOFFS[ci], idv;
                try { idv = r.add(off2).readU16(); } catch (e) { continue; }
                if (scr.bodies[idv] !== undefined) { pid2 = idv; body = scr.bodies[idv]; oneshot = true; }
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
        if (scr.bodies[pid2] !== undefined) { body = scr.bodies[pid2]; oneshot = true; }   // consumer packet wins
        else if (scr.body !== null && (scr.id === undefined || pid2 === scr.id)) { body = scr.body; }  // legacy walk
        if (body === null) return true;                             // not a packet we're injecting
    }
    if (overlapsRecvRing(bodyp, body.length)) {
        send({tag: 'SCRAMBLE', hit: 'blocked-rx-ring', id: pid2});
        return true; // preserve one-shot body for a later genuine TX slot
    }
    var was = null;
    try { was = toHex(bodyp, body.length); } catch (e) {}
    try {
        bodyp.writeByteArray(body);                                 // overwrite plaintext; the in-place XOR encrypts ours
        if (oneshot && !scr.persist) delete scr.bodies[pid2];       // one-shot: client's own sends resume; persist: keep replacing
        if (usedOff === -2 && was !== null && was.length >= 2) {    // bodyp==ecx: o store seguinte grava body[0]
            scr._fix0 = {at: bodyp, orig0: parseInt(was.slice(0, 2), 16), our0: body[0] & 0xff};
        }
        send({tag: 'SCRAMBLE', hit: 'wrote', pc: scr.pc.toString(), slot: bodyp.toString(), id: pid2,
              body: was, wrote: hexOf(new Uint8Array(body)), reg: usedReg, idoff: usedOff});
    } catch (e) { send({tag: 'SENDWATCH-ERR', e: 'scramble write: ' + e.message}); }
    return true;
}

function onScramble(m) {
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
               bodies: {}};        // --inject merge: id -> plaintext body to substitute (pre-XOR)
        scrEntry = undefined;                       // recompute the prologue scan for this pc
        if (!scrHandler) { scrHandler = true; Process.setExceptionHandler(scrTrap); }
        scrArm();
        console.log('[*] scramble intercept: bp @ ' + pc + ' reg ' + scr.reg +
                    ' id 0x' + ((m.id || 0).toString(16)) + (scr.dry ? ' DRY' : ' LIVE wrote=' + m.body));
    }
    recv('scramble', onScramble);
}
recv('scramble', onScramble);

// --inject merge: the driver forwards each packet the consumer wants to send as {id, body}.
// We stash the body keyed by id; the next time the scramble BP sees that id in a slot, scrTrap
// writes the body in place of the client's own, one-shot, so the client's XOR encrypts ours.
function onScrambleSet(m) {
    if (scr !== null) {
        if (m.body === null || m.body === undefined) delete scr.bodies[m.id];
        else scr.bodies[m.id] = Array.from(hexToBytes(m.body));
        console.log('[*] scramble body ' + (m.body ? 'armed' : 'cleared') +
                    ' for id 0x' + (m.id | 0).toString(16) + (m.body ? ' (' + (m.body.length >> 1) + 'B)' : ''));
    } else {
        send({tag: 'SENDWATCH-ERR', e: 'scramble-set with no scramble BP armed (need --scramble-bp)'});
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
var scDemand = false, scDemandScheduled = false, scDemandUnavailable = false;
function requestSendCallDrain() {
    if (!sessionReady() || !scDemand || scDemandUnavailable || scDemandScheduled || scSend === null ||
        scSend.fn === null || scSend['this'] === null || !scSend.tid || !scSend.queue.length) return;
    if (typeof Process.runOnThread !== 'function') {
        scDemandUnavailable = true;
        send({tag:'SENDCALL', hit:'demand-disabled', e:'runOnThread unavailable'});
        return;
    }
    scDemandScheduled = true;
    var epoch = sessionGeneration;
    // Experimental: Frida interrupts the captured game thread, even when it is
    // not at a known safe point. The original event-driven drain remains active.
    Process.runOnThread(scSend.tid, function () {
        if (epoch !== sessionGeneration || !sessionReady()) return;
        drainSendCall();
    }).then(function () {
        scDemandScheduled = false;
        // Work arrived while the callback was running: schedule another pass.
        if (epoch === sessionGeneration && scSend !== null && scSend.queue.length) requestSendCallDrain();
    }, function (e) {
        scDemandScheduled = false;
        scDemandUnavailable = true; // fail closed to the existing safe-point drain
        send({tag:'SENDCALL', hit:'demand-disabled', e:String(e)});
    });
}
var scCastMs = 800;                             // janela de paceamento dos casts (0 desliga)
var scLastCast = 0;                             // Date.now() do ultimo cast realmente enviado
var CAST_IDS = {0x0438: 1, 0x0af4: 1};          // pericias com tempo de cast: so uma por janela

function onSendCall(m) {
    if (m.recapture) {
        resetNativeSession(m.reason || 'session transition', m.delayMs);
    } else if (m.rva === undefined && m.pc === undefined) {          // disarm
        scDemand = false;
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
            scDemand = !!m.demand;
            scDemandUnavailable = false;
            scDemandScheduled = false;
            if (m.castMs !== undefined) scCastMs = m.castMs;
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
    if (scSend === null) send({tag: 'SENDCALL', hit: 'error', e: 'emit with no sendcall armed'});
    else if (!sessionReady() || scSend.awaitRecapture) {
        thisDiag('stale','SendPacket','emit before context recapture',scSend['this']);
        send({tag: 'SENDCALL', hit: 'stale-drop', e: 'waiting for a fresh SendPacket object', ts: Date.now()});
    } else if (m.data) {
        var queued = Array.from(hexToBytes(m.data));
        scSend.queue.push(queued);
        requestSendCallDrain();             // opt-in, immediate; old hook drain is fallback
        // Stage 2a: relay's own queue, NOT the encrypted client queue.
        if (queued.length === 8 && queued[0] === 0x39 && queued[1] === 0x04)
            send({tag: 'ITEMUSE-STAGE', stage: 'relay-queue', ts: Date.now(),
                  item_index: queued[2] | (queued[3] << 8), queue_len: scSend.queue.length});
    }
    recv('sendcall-emit', onSendEmit);
}
recv('sendcall-emit', onSendEmit);

function drainSendCall() {                       // only runs on the game thread (SendPacket must)
    if (!sessionReady() || scDraining || scSend === null || scSend.fn === null || scSend['this'] === null) return;
    if (scSend.queue.length === 0) return;
    if (scSend.tid && Process.getCurrentThreadId() !== scSend.tid) {
        thisDiag('suspect','SendPacket','wrong execution thread',scSend['this']);
        return;
    }   // so na thread que roda a SendPacket
    scDraining = true;
    try {
        while (scSend.queue.length) {
            var pk = scSend.queue.shift();
            var id = pk.length >= 2 ? (pk[0] | (pk[1] << 8)) : 0;
            if (scCastMs > 0 && CAST_IDS[id]) {              // pericia com cast: so uma por janela
                var now = Date.now();                        // retentativas enfileiradas drenariam
                if (now - scLastCast < scCastMs) {           // em rajada e uma cancelaria a outra
                    send({tag: 'SENDCALL', hit: 'throttled', len: pk.length, id: id});
                    continue;                                // descarta este cast (nao reenfileira)
                }
                scLastCast = now;
            }
            try {
                var buf = Memory.alloc(pk.length < 8 ? 8 : pk.length);
                buf.writeByteArray(pk);
                if (id === 0x0439 && pk.length === 8)
                    send({tag: 'ITEMUSE-STAGE', stage: 'sendpacket-entry', ts: Date.now(),
                          item_index: buf.add(2).readU16(), tid: Process.getCurrentThreadId()});
                scSend.fn(scSend['this'], pk.length, buf);           // client builds+encrypts+sends it
                // Post-call snapshot is the INPUT buffer, not the native send queue.
                // If the native method copies into its own queue, this snapshot alone
                // cannot observe that allocation or its subsequent transformations.
                if (id === 0x0439 && pk.length === 8) {
                    try {
                        var after = new Uint8Array(buf.readByteArray(8));
                        send({tag: 'ITEMUSE-STAGE', stage: 'sendpacket-return-buffer', ts: Date.now(),
                              item_index: after[2] | (after[3] << 8),
                              changed: after[2] !== pk[2] || after[3] !== pk[3]});
                    } catch (e) {
                        send({tag: 'ITEMUSE-STAGE', stage: 'sendpacket-return-buffer', ts: Date.now(),
                              error: e.message});
                    }
                }
                // Record only non-sensitive metadata for use-item diagnosis: the slot
                // requested BEFORE SendPacket, not the potentially transformed wire slot.
                var sent = {tag: 'SENDCALL', hit: 'sent', len: pk.length, id: id, ts: Date.now()};
                if (id === 0x0439 && pk.length === 8)
                    sent.item_index = pk[2] | (pk[3] << 8);
                send(sent);
            } catch (e) {
                send({tag: 'SENDCALL', hit: 'error', e: 'call: ' + e.message});
            }
        }
    } finally { scDraining = false; }
}

// ---- Gepard SendMsg wrapper dispatch (experimental, opt-in) -----------------------------------
// Live HW probes established a protected cdecl wrapper with six stack arguments:
//   wrapper(CGameMode*this, sendMsgId, a2, a3, a4, a5)
// which later executes `call eax` with eax=CGameMode::SendMsg. Direct SendMsg calls bypassed the
// outbound transform, so this path deliberately enters ABOVE SendMsg. Exact offsets are profile data.
var gd = null;
function gdUnarm(which) { hwClear(which === 'cap' ? 'gepard-cap' : 'gepard-fire'); }
function gdThisValid(p) {
    try {
        if (gd === null || p === null || p.isNull() || !Process.findRangeByAddress(p)) return false;
        return p.readPointer().equals(gd.vtable);
    } catch (e) { return false; }
}
function gdInvalidate(why) {
    if (gd === null) return;
    gd.thisp = null; gd.queue.length = 0;
    gdUnarm('fire'); gd.fireArmed = false;
    if (!gd.capArmed && gd.th !== null) {
        try { if (sessionReady()) { hwSet('gepard-cap', gd.th, gd.callsite); gd.capArmed = true; } }
        catch (e) { send({tag:'GEPARD-DISPATCH',hit:'error',e:'recapture arm: '+e.message}); }
    }
    send({tag:'GEPARD-DISPATCH',hit:'invalidated',e:why});
}
function gdTrusted() {
    if (gd === null || gd.thisp === null) return false;
    if (!gdThisValid(gd.thisp)) {
        thisDiag('invalid','GepardDispatch','CGameMode vtable changed',gd.thisp);
        gdInvalidate('CGameMode context changed');
        return false;
    }
    return true;
}
function gdTrap(ctx) {
    if (gd === null) return false;
    if (gd.capArmed && ctx.pc.equals(gd.callsite)) {
        if (sessionReady() && gd.thisp === null && !gd.busy) {
            var sid = 0xffffffff;
            try { sid = ctx.esp.readU32(); } catch (e) {}
            if (ctx.eax.equals(gd.sendmsg) && sid <= 0x14f && gdThisValid(ctx.ecx)) {
                gd.thisp = ctx.ecx; gd.capArmed = false; gdUnarm('cap');
                send({tag:'GEPARD-DISPATCH',hit:'captured','this':ctx.ecx.toString(),send_msg_id:sid});
            }
        }
        return true;
    }
    if (gd.fireArmed && ctx.pc.equals(gd.site)) {
        if (Process.getCurrentThreadId() !== gd.tid || gd.busy) return true;
        if (!gdTrusted() || gd.queue.length === 0) return true;
        var a = gd.queue.shift();
        gd.fireArmed = false; gdUnarm('fire'); gd.capArmed = false; gdUnarm('cap');
        var x = Math.max(0, Math.min(1023, a.x | 0));
        var y = Math.max(0, Math.min(1023, a.y | 0));
        var out = {tag:'GEPARD-DISPATCH',hit:'fired',x:x,y:y,'this':gd.thisp.toString(),send_msg_id:gd.moveId};
        try {
            gd.busy = true; gd.firesLeft--;
            send({tag:'GEPARD-DISPATCH',hit:'call',x:x,y:y,fires_left:gd.firesLeft});
            out.retval = gd.fn(gd.thisp, gd.moveId, x, y, 0, 0) >>> 0;
            out.exception = null;
            if (gd.firesLeft <= 0) { gd.fireEnabled = false; gd.queue.length = 0; }
        } catch (e) { out.exception = String(e.message || e); }
        gd.busy = false; send(out);
        if (gd.queue.length && gdTrusted()) {
            try { if (sessionReady()) { hwSet('gepard-fire',gd.th,gd.site); gd.fireArmed = true; } } catch (e) {}
        }
        return true;
    }
    return false;
}
function onGepardDispatch(m) {
    try {
        if (m.arm) send({tag:'GEPARD-DISPATCH',hit:'arm-received',module:m.module || null,
                         entry_offset:m.entryOffset,callsite_offset:m.callsiteOffset,
                         safe_point_rva:m.safePointRva,send_msg_rva:m.sendMsgRva});
        if (m.disarm) {
            if (gd !== null) { gdUnarm('cap'); gdUnarm('fire'); }
            gd = null;
        } else if (m.recapture) {
            resetNativeSession('gepard-wrapper recapture', m.delayMs);
        } else if (m.arm) {
            var gb = peBase(m.module || 'gepard.dll'), ub = peBase(m.uaroModule || 'uaRO.exe');
            var have = m.entryOffset !== undefined && m.callsiteOffset !== undefined &&
                       m.safePointRva !== undefined && m.sendMsgRva !== undefined &&
                       m.gameModeVtableRva !== undefined && m.moveSendMsgId !== undefined;
            if (gb === null || ub === null || !have) throw new Error('wrapper/profile unresolved');
            var entry = gb.add(m.entryOffset), callsite = gb.add(m.callsiteOffset);
            var site = ub.add(m.safePointRva), sendmsg = ub.add(m.sendMsgRva), vtable = ub.add(m.gameModeVtableRva);
            var ci = Instruction.parse(callsite).toString();
            var e1 = Instruction.parse(entry), e2 = Instruction.parse(e1.next), e3 = Instruction.parse(e2.next);
            if (ci !== 'call eax') throw new Error('wrapper callsite anchor mismatch: ' + ci);
            if (e1.toString() !== 'push ebp' || e2.toString() !== 'bswap ebp' || e3.toString() !== 'mov ebp, esp')
                throw new Error('wrapper entry anchor mismatch');
            if (!Process.findRangeByAddress(site) || !Process.findRangeByAddress(sendmsg) || !Process.findRangeByAddress(vtable))
                throw new Error('uaRO anchor unmapped');
            var th = Process.enumerateThreads().filter(function(t){return t.id === Process.id;})[0] || null;
            if (th === null) throw new Error('main thread not found');
            gd = {entry:entry,callsite:callsite,site:site,sendmsg:sendmsg,vtable:vtable,moveId:Number(m.moveSendMsgId),
                  th:th,tid:Process.id,thisp:null,queue:[],capArmed:false,fireArmed:false,busy:false,
                  fireEnabled:!!m.fireEnabled, firesLeft:Math.max(0, Number(m.maxFires === undefined ? 1 : m.maxFires)),
                  fn:new NativeFunction(entry,'uint',['pointer','uint32','uint32','uint32','uint32','uint32'],
                                        {abi:'default',exceptions:'propagate'})};
            if (!scrHandler) { scrHandler = true; Process.setExceptionHandler(scrTrap); }
            hwSet('gepard-cap',gd.th,gd.callsite); gd.capArmed = true;
            send({tag:'GEPARD-DISPATCH',hit:'armed',entry:entry.toString(),callsite:callsite.toString(),site:site.toString()});
        } else if (m.args && gd !== null) {
            if (!gd.fireEnabled) send({tag:'GEPARD-DISPATCH',hit:'dropped',e:'capture-only mode'});
            else if (gd.firesLeft <= 0) send({tag:'GEPARD-DISPATCH',hit:'dropped',e:'fire limit exhausted'});
            else if (!sessionReady()) send({tag:'GEPARD-DISPATCH',hit:'dropped',e:'map settle delay'});
            else if (!gdTrusted()) send({tag:'GEPARD-DISPATCH',hit:'dropped',e:'CGameMode context unavailable'});
            else if (gd.queue.length >= 8) send({tag:'GEPARD-DISPATCH',hit:'dropped',e:'queue full'});
            else {
                gd.queue.push({x:Number(m.args.x),y:Number(m.args.y)});
                if (!gd.fireArmed) { hwSet('gepard-fire',gd.th,gd.site); gd.fireArmed = true; }
                send({tag:'GEPARD-DISPATCH',hit:'queued',x:Number(m.args.x),y:Number(m.args.y)});
            }
        } else if (m.args) send({tag:'GEPARD-DISPATCH',hit:'error',e:'dispatch with no arm'});
    } catch (e) { send({tag:'GEPARD-DISPATCH',hit:'error',e:String(e.message || e)}); }
    recv('gepard-dispatch', onGepardDispatch);
}
recv('gepard-dispatch', onGepardDispatch);

// ---- native-dispatch (opt-in: {type:'native-dispatch'}) ---------------------------------------
// PoC: em vez de fabricar o corpo do 035f, dispara o dispatcher nativo do cliente (thiscall,
// frame 0x11) a partir de um safe point da thread do jogo. Enderecos/RVAs pertencem ao perfil
// do build; o agente nao carrega offsets de uaRO fixos. Receita validada historicamente em
// research/movement_035f/dispatcher_trial_pesite.py (rodadas 06b/08).
function mdWalkFrame(a) {                             // 13 dwords: f[1]=code 0x11, f[3]=dx, f[5]=dy
    var dx = Math.max(0, Math.min(1023, a.x | 0)), dy = Math.max(0, Math.min(1023, a.y | 0));
    return [0, 0x11, 0, dx >>> 0, 0, dy >>> 0, 0, 0, 0, 0, 0, 0, 0];
}
var MD_RECIPES = {
    'walk-035f': {kind: 'legacy-frame', buildFrame: mdWalkFrame},
    'walk-player-vtable': {kind: 'player-vtable', buildFrame: mdWalkFrame}
};
var md = null;      // {recipe, disp, site, fn, thisp, receiver, queue:[args], th, capArmed, fireArmed, busy}

function mdUnarm(slot) { hwClear(slot === 2 ? 'move-cap' : 'move-fire'); }

function mdContext() {                          // identidade do objeto receptor nesta sessao
    try {
        if (md === null || md.manager === null) return null;
        if (md.manager.add(0x58).readU32() !== 1) return null;
        var obj = md.manager.add(4).readPointer();
        if (obj.isNull()) return null;
        if (md.receiverVslot === null || md.receiverVslot === undefined) return null;
        var rcv = obj.readPointer().add(md.receiverVslot * Process.pointerSize).readPointer();
        var receiverBase = peBase(md.receiverModule);
        if (receiverBase === null || !rcv.equals(receiverBase.add(md.receiverOffset))) return null;
        return obj;
    } catch (e) { return null; }
}

function mdPlayerHook() {
    try {
        if (md === null || md.thisp === null || md.dispatcherVslot === null || md.dispatcherVslot === undefined)
            return null;
        var hook = md.thisp.readPointer().add(md.dispatcherVslot * Process.pointerSize).readPointer();
        if (hook.isNull() || hook.equals(md.disp)) return null;
        var range = peRange(md.receiverModule);
        if (range === null || hook.compare(range.base) < 0 || hook.compare(range.end) >= 0) return null;
        var mapped = Process.findRangeByAddress(hook);
        if (!mapped || mapped.protection.indexOf('x') < 0) return null;
        return hook;
    } catch (e) { return null; }
}

function mdInvalidate(why) {
    if (md === null) return;
    md.thisp = null;
    md.receiver = null;
    md.queue.length = 0;
    mdUnarm(3); md.fireArmed = false;
    // A captura so e aceita quando o receptor estiver novamente pronto.
    if (!md.capArmed && md.th !== null) {
        try { if (sessionReady()) { hwSet('move-cap',md.th,md.disp); md.capArmed = true; } }
        catch (e) { send({tag: 'MOVE-DISPATCH', hit: 'error', e: 'recapture arm: ' + e.message}); }
    }
    send({tag: 'MOVE-DISPATCH', hit: 'invalidated', e: why});
}

function mdTrusted() {
    var obj = mdContext();
    if (md === null || md.thisp === null || md.receiver === null ||
        obj === null || !obj.equals(md.receiver)) {
        if (md !== null && md.thisp !== null) {
            thisDiag('invalid','MoveDispatch','receiver unavailable or identity changed',md.thisp);
            mdInvalidate('receiver unavailable/changed');
        }
        return false;
    }
    if (md.recipe.kind === 'player-vtable' && mdPlayerHook() === null) {
        thisDiag('invalid','MoveDispatch','CPlayer runtime vtable hook unavailable',md.thisp);
        mdInvalidate('CPlayer vtable hook unavailable/changed');
        return false;
    }
    return true;
}

function mdTrap(ctx) {                          // devolve true se tratou o breakpoint
    if (md === null) return false;
    if (md.capArmed && ctx.pc.equals(md.disp)) {                   // captura passiva do `this` (construct mode)
        if (sessionReady() && md.thisp === null && !md.busy) {
            var lo = ctx.esp.add(8).readU32(), hi = ctx.esp.add(12).readU32();
            var receiver = mdContext();
            if (hi === 0 && lo <= 0x95 && receiver !== null && !ctx.ecx.isNull()) {
                md.thisp = ctx.ecx; md.receiver = receiver;
                md.capArmed = false; mdUnarm(2);
                send({tag: 'MOVE-DISPATCH', hit: 'captured', 'this': ctx.ecx.toString(), code: lo});
            }
        }
        return true;
    }
    if (md.fireArmed && ctx.pc.equals(md.site)) {                  // sitio PE do main-loop
        if (Process.getCurrentThreadId() !== md.tid || md.busy) return true;
        if (!mdTrusted() || md.queue.length === 0) return true;
        var a = md.queue.shift();
        md.fireArmed = false; mdUnarm(3); md.capArmed = false; mdUnarm(2);   // sem BP aninhado
        var r = {tag:'MOVE-DISPATCH',hit:'fired',x:a.x,y:a.y,'this':md.thisp.toString()};
        if (!mdTrusted()) { r.hit = 'abort'; r.e = 'receiver not ready/changed'; send(r); }
        else {
            try {
                md.busy = true;
                var recipe = MD_RECIPES[a._recipe || 'walk-035f'];
                if (!recipe) throw new Error('unknown queued native recipe');
                var f = recipe.buildFrame(a), rv;
                r.frame = f;
                if (recipe.kind === 'player-vtable') {
                    var hook = mdPlayerHook();
                    if (hook === null) throw new Error('CPlayer runtime vtable hook unresolved');
                    if (md.playerFiresLeft <= 0) throw new Error('player-vtable fire limit exhausted');
                    md.playerFiresLeft--;
                    r.backend = 'player-vtable'; r.hook = hook.toString(); r.fires_left = md.playerFiresLeft;
                    send({tag:'MOVE-DISPATCH',hit:'call',backend:'player-vtable',hook:hook.toString(),
                          x:a.x,y:a.y,fires_left:md.playerFiresLeft});
                    var playerFn = new NativeFunction(hook, 'uint', md.callTypes,
                                                      {abi:'thiscall',exceptions:'propagate'});
                    rv = playerFn.apply(null, [md.thisp].concat(f));
                } else {
                    r.backend = 'legacy';
                    send({tag:'MOVE-DISPATCH',hit:'call',backend:'legacy',x:a.x,y:a.y});
                    rv = md.fn.apply(null, [md.thisp].concat(f));
                }
                r.retval = rv >>> 0; r.exception = null;
            } catch (e) { r.exception = String(e.message || e); }
            md.busy = false;
            if (md.recipe.kind === 'player-vtable' && md.playerFiresLeft <= 0) md.queue.length = 0;
            send(r);
        }
        if (md.queue.length && mdTrusted()) { try { if (sessionReady()) { hwSet('move-fire',md.th,md.site); md.fireArmed = true; } } catch (e) {} }
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
            resetNativeSession('move recapture', m.delayMs);
        } else if (m.arm) {
            var rec = MD_RECIPES[m.recipe];
            var base = peBase(m.module || 'uaRO.exe');
            var haveProfile = m.dispatcherRva !== undefined && m.safePointRva !== undefined &&
                              m.managerRva !== undefined && m.retAnchorRva !== undefined &&
                              m.receiverOffset !== undefined && m.receiverVslot !== undefined;
            if (!rec || base === null || !haveProfile) {
                send({tag: 'MOVE-DISPATCH', hit: 'error', e: 'recipe/base/profile unresolved'});
            } else {
                var disp = m.dispatcher !== undefined ? ptr(m.dispatcher) : base.add(m.dispatcherRva);
                var site = m.site !== undefined ? ptr(m.site) : base.add(m.safePointRva);
                var manager = haveProfile ? base.add(m.managerRva) : null;
                var retAnchor = haveProfile ? base.add(m.retAnchorRva) : null;
                var receiverModule = m.receiverModule || 'gepard.dll';
                var receiverOffset = haveProfile ? m.receiverOffset : 0;
                var receiverVslot = haveProfile ? Number(m.receiverVslot) : null;
                var dispatcherVslot = m.dispatcherVslot === undefined ? null : Number(m.dispatcherVslot);
                var receiverBase = peBase(receiverModule);
                var receiverHook = receiverBase === null ? null : receiverBase.add(receiverOffset);
                var why = null;
                if (!Process.findRangeByAddress(disp)) why = 'dispatcher unmapped';
                else if (retAnchor === null || !/ret\s+0x34/.test(Instruction.parse(retAnchor).toString())) why = 'ret 0x34 anchor mismatch';
                else if (!Process.findRangeByAddress(site)) why = 'safe-point unmapped';
                else if (!Process.findRangeByAddress(manager)) why = 'manager unmapped';
                else if (receiverHook === null || !Process.findRangeByAddress(receiverHook)) why = 'receiver hook unmapped';
                else if (rec.kind === 'player-vtable' && dispatcherVslot === null) why = 'profile missing CPlayer dispatcher vslot';
                if (why) send({tag: 'MOVE-DISPATCH', hit: 'error', e: why});
                else {
                    var th = Process.enumerateThreads().filter(function (t) { return t.id === Process.id; })[0];
                    var types = ['pointer']; for (var i = 0; i < 13; i++) types.push('uint32');
                    md = {recipe: rec, disp: disp, site: site, manager: manager, retAnchor: retAnchor,
                          receiverModule: receiverModule, receiverOffset: receiverOffset,
                          receiverVslot: receiverVslot, receiverHook: receiverHook,
                          dispatcherVslot: dispatcherVslot, callTypes: types,
                          playerFiresLeft: rec.kind === 'player-vtable' ?
                              Math.max(0, Number(m.playerMaxFires === undefined ? 1 : m.playerMaxFires)) : null,
                          thisp: null, receiver: null, queue: [], th: th || null, tid: Process.id,
                          capArmed: false, fireArmed: false, busy: false,
                          fn: new NativeFunction(disp, 'uint', types, {abi: 'thiscall', exceptions: 'propagate'})};
                    if (!scrHandler) { scrHandler = true; Process.setExceptionHandler(scrTrap); }
                    if (md.th === null) { send({tag: 'MOVE-DISPATCH', hit: 'error', e: 'main thread not found'}); md = null; }
                    else { hwSet('move-cap',md.th,disp); md.capArmed = true;     // dynamically allocated capture slot
                           send({tag: 'MOVE-DISPATCH', hit: 'armed', disp: disp.toString(), site: site.toString()}); }
                }
            }
        } else if (m.args && md !== null) {
            if (!sessionReady()) { send({tag:'MOVE-DISPATCH',hit:'dropped',e:'map settle delay'}); }
            else
            if (!mdTrusted()) send({tag: 'MOVE-DISPATCH', hit: 'dropped', e: 'dispatcher context untrusted (walk once in-client)', x: m.args.x, y: m.args.y});
            else if (!MD_RECIPES[m.recipe || 'walk-035f']) send({tag:'MOVE-DISPATCH',hit:'error',e:'unknown recipe'});
            else if (md.recipe.kind === 'player-vtable' && md.playerFiresLeft <= 0)
                send({tag:'MOVE-DISPATCH',hit:'dropped',e:'player-vtable fire limit exhausted',x:m.args.x,y:m.args.y});
            else if (md.queue.length >= 8) send({tag: 'MOVE-DISPATCH', hit: 'dropped', e: 'queue full'});
            else {
                m.args._recipe = m.recipe || 'walk-035f';
                md.queue.push(m.args);
                if (!md.fireArmed) { if (sessionReady()) { hwSet('move-fire',md.th,md.site); md.fireArmed = true; } }   // dynamically allocated fire slot
                send({tag: 'MOVE-DISPATCH', hit: 'queued', x: m.args.x, y: m.args.y});
            }
        } else if (m.args) send({tag: 'MOVE-DISPATCH', hit: 'error', e: 'native-dispatch with no arm'});
    } catch (e) { send({tag: 'MOVE-DISPATCH', hit: 'error', e: 'native-dispatch: ' + e.message}); }
    recv('native-dispatch', onNativeDispatch);
}
recv('native-dispatch', onNativeDispatch);

// never leave debug registers armed without our handler: the client would die on the next write
rpc.exports = { dispose: function () { sw = null; swDisarm(); scr = null; scrDisarm(); scrCall = null; scrCallDisarm(); hwProbe = null; hwClear('research-probe'); scSend = null; if (gd !== null) { gdUnarm('cap'); gdUnarm('fire'); } gd = null; if (md !== null) { mdUnarm(2); mdUnarm(3); } md = null; } };

// ---- module metadata / bounded trace -----------------------------------------------------------
function onModuleInfo(m) {
    var name = m.module || 'uaRO.exe', r = peRange(name);
    if (r === null) send({tag: 'MODULE-INFO', token: m.token || null, module: name, erro: 'module not mapped'});
    else send({tag: 'MODULE-INFO', token: m.token || null, module: name,
               base: r.base.toString(), end: r.end.toString(), size: r.end.sub(r.base).toUInt32()});
    recv('module-info', onModuleInfo);
}
recv('module-info', onModuleInfo);

// ---- rastreio com Stalker (opcional: o driver envia {type:'trace'}) ----------------------------
// ARRISCADO em codigo protegido pelo gepard: o Stalker reescreve o codigo executado. Primeiro um
// teste de sobrevivencia curto; se o cliente aguentar, com a faixa do uaRO registramos as chamadas
// do codigo do uaRO para dentro do gepard (a chamada do envio do walk esta entre elas). Janela
// curta e desliga sozinho.
var traceSeen = null;
function onTrace(m) {
    var ms = m.ms || 200, token = m.token || null;
    var th = Process.enumerateThreads().filter(function (t) { return t.id === Process.id; })[0];
    if (!th) { send({tag: 'TRACE', token: token, erro: 'thread principal nao encontrada'}); recv('trace', onTrace); return; }
    var ualo = m.ualo ? ptr(m.ualo) : null, uahi = m.uahi ? ptr(m.uahi) : null;
    var gep = getGepard(), ghi = gep ? gep.add(0x2000000) : null;
    var interno = !!m.interno;                                       // true: registrar uaRO->uaRO
    traceSeen = ualo ? {} : null;
    var nvistos = 0, TETO = 8000;
    var nblocos = 0;
    try {
        Stalker.follow(th.id, {
            events: {call: true},
            onReceive: function (ev) {
                nblocos += ev.byteLength;
                if (traceSeen === null) return;                     // teste de sobrevivencia: so conta
                var es = Stalker.parse(ev, {stringify: false});    // [['call', de, para, prof], ...]
                for (var i = 0; i < es.length; i++) {
                    if (es[i][0] !== 'call') continue;
                    var de = es[i][1], para = es[i][2];
                    if (!(de instanceof NativePointer) || !(para instanceof NativePointer)) continue;
                    if (nvistos >= TETO) continue;                  // teto de memoria
                    if (de.compare(ualo) < 0 || de.compare(uahi) >= 0) continue;   // origem no uaRO
                    var chave = null;
                    if (interno) {                                  // destino tambem no uaRO
                        if (para.compare(ualo) >= 0 && para.compare(uahi) < 0)
                            chave = de.sub(ualo).toString() + '>u' + para.sub(ualo).toString();
                    } else if (gep && para.compare(gep) >= 0 && para.compare(ghi) < 0) {
                        chave = de.sub(ualo).toString() + '>' + para.sub(gep).toString();
                    }
                    if (chave !== null && traceSeen[chave] === undefined) { traceSeen[chave] = 1; nvistos++; }
                }
            }
        });
    } catch (e) { send({tag: 'TRACE', token: token, erro: 'follow: ' + e.message}); recv('trace', onTrace); return; }
    setTimeout(function () {
        try { Stalker.unfollow(th.id); Stalker.flush(); } catch (e) {}
        var msg = {tag: 'TRACE', token: token, ms: ms, bytes: nblocos};
        if (traceSeen !== null) { msg.chamadas = Object.keys(traceSeen); msg.n = msg.chamadas.length; }
        else { msg.nota = 'teste de sobrevivencia ok'; }
        send(msg);
        traceSeen = null;
    }, ms);
    recv('trace', onTrace);
}
recv('trace', onTrace);

// ---- send --------------------------------------------------------------------------------------
hookAll(['__sendmsg64', 'sendmsg'], {
    onEnter: function (args) {
        this.fd = args[0].toInt32(); this.msg = args[1];
    },
    onLeave: function (ret) {
        var n = ret.toInt32(); if (n <= 0) return;
        var peer = peerOf(this.fd); if (!peer) return;
        if (!gepardSent) {                                  // gepard loads after login: report its base once it's up
            var gb = getGepard();
            if (gb !== null) { gepardSent = true; send({tag: 'GEPARD', base: gb.toString()}); }
        }
        var chunks = iovs(this.msg, n), h = chunks.map(function (v) { return toHex(v[0], v[1]) || ''; }).join('');
        var m = {tag: 'SEND', sock: peer, conn: connCache[this.fd], len: n, id: pktId(h), C: h, seq: seq++, ts: Date.now()};
        // Stage 3: actual socket boundary; scan complete 8-byte 0439 records in
        // this buffer only. Do not assume the whole sendmsg is a single packet.
        if (h.length >= 16 && h.slice(0, 4) === '3904') {
            for (var off = 0; off + 16 <= h.length; off += 16) {
                if (h.slice(off, off + 4) !== '3904') break;
                var itemIndex = parseInt(h.slice(off + 6, off + 8) + h.slice(off + 4, off + 6), 16);
                send({tag: 'ITEMUSE-STAGE', stage: 'socket-send', ts: m.ts,
                      item_index: itemIndex, chunk_len: n, byte_offset: off / 2});
            }
        }
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
function peRange(dllName) {
    var want = '/' + dllName.toLowerCase(), lo = null, hi = null;
    Process.enumerateRanges({protection: '---', coalesce: false}).forEach(function (r) {
        if (!r.file || !r.file.path) return;
        var p = r.file.path.toLowerCase();
        if (p.slice(-want.length) !== want) return;
        var end = r.base.add(r.size);
        if (lo === null || r.base.compare(lo) < 0) lo = r.base;
        if (hi === null || end.compare(hi) > 0) hi = end;
    });
    if (lo === null) return null;
    try { if (lo.readU16() !== 0x5a4d) return null; } catch (e) { return null; }   // 'MZ'
    return {base: lo, end: hi};
}
function peBase(dllName) {
    var r = peRange(dllName);
    return r === null ? null : r.base;
}

getGepard();
console.log('[*] gepard.dll base: ' + (g === null ? 'not loaded yet (resolved after login)' : g));
if (g !== null) { gepardSent = true; send({tag: 'GEPARD', base: g.toString()}); }  // else reported on the first send
console.log('[*] ready. Log in / enter map to generate traffic.');
