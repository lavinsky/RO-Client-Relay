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
            try { var v = a.readU16(); return v === 0x0437 || v === 0x0438; } catch (e) { return false; }
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
    var PROBE_IDS = {0x0437: 1, 0x0438: 1};                          // the encrypted client send ids
    var cand = {eax: ctx.eax, ebx: ctx.ebx, ecx: ctx.ecx, edx: ctx.edx, esi: ctx.esi, edi: ctx.edi, ebp: ctx.ebp};
    var slotReg = null, slotPtr = null, slotId = -1, slotOff = null;
    for (var rn in cand) {                                           // confirm a real send: a reg points at a slot id we expect
        var r = cand[rn];
        if (!(r instanceof NativePointer) || r.isNull()) continue;
        if (scr.lo !== null && (r.compare(scr.lo) < 0 || r.compare(scr.hi) >= 0)) continue;
        for (var ci = 0; ci < SCR_IDOFFS.length; ci++) {
            var o = SCR_IDOFFS[ci], idv;
            try { idv = r.add(o).readU16(); } catch (e) { continue; }
            if (PROBE_IDS[idv]) { slotReg = rn; slotPtr = r.add(o); slotId = idv; slotOff = o; break; }
        }
        if (slotReg) break;
    }
    if (slotReg === null) return true;                               // not a send we recognise yet: keep waiting
    var regs = {};
    GP.forEach(function (r) { try { regs[r] = ctx[r].toString(); } catch (e) {} });
    var frames = [], esp = ctx.esp;
    for (var i = 0; i < 4096 && frames.length < 80; i++) {           // scan the stack for return addresses
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
function codeRanges(refresh) {
    if (CODE_RANGES && !refresh) return CODE_RANGES;
    var byPath = {};
    Process.enumerateRanges({protection: 'r-x', coalesce: false}).forEach(function (r) {
        var p = (r.file && r.file.path) ? r.file.path : null;
        if (!p || !/\.(exe|dll)$/i.test(p)) return;                  // PE modules only (skip mapped .grf data archives)
        (byPath[p] = byPath[p] || []).push([r.base, r.base.add(r.size)]);
    });
    var out = [];
    for (var p in byPath) {
        var ranges = byPath[p], base = ranges[0][0], name = p.split('/').pop();
        ranges.forEach(function (x) { if (x[0].compare(base) < 0) base = x[0]; });
        ranges.forEach(function (x) { out.push({lo: x[0], hi: x[1], name: name, base: base}); });
    }
    return (CODE_RANGES = out);
}
function codeAt(ptr) {
    var rs = codeRanges(false);
    for (var i = 0; i < rs.length; i++) if (ptr.compare(rs[i].lo) >= 0 && ptr.compare(rs[i].hi) < 0) return rs[i];
    rs = codeRanges(true);                                           // stale cache? refresh once and retry
    for (var j = 0; j < rs.length; j++) if (ptr.compare(rs[j].lo) >= 0 && ptr.compare(rs[j].hi) < 0) return rs[j];
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

function scrTrap(d) {
    if (scr === null || d.type !== 'breakpoint' || !d.context.pc.equals(scr.pc)) return false;
    var ctx = d.context;
    if (scr.sendcall) {                                              // call-inject: capture `this` (ecx), build fn, disarm
        try {
            scSend['this'] = ctx.ecx;
            scSend.fn = new NativeFunction(scr.pc, 'void', ['pointer', 'int', 'pointer'], 'thiscall');
            send({tag: 'SENDCALL', hit: 'ready', 'this': ctx.ecx.toString(), pc: scr.pc.toString()});
        } catch (e) { send({tag: 'SENDCALL', hit: 'error', e: 'arm: ' + e.message}); }
        scr = null; scrDisarm();
        return true;
    }
    if (scr.entry) return scrProbeEntry(ctx);                        // --probe-entry: capture args + disarm
    if (scr.probe) return scrProbe(ctx);                             // --send-probe: capture + disarm, no write
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
    var was = null;
    try { was = toHex(bodyp, body.length); } catch (e) {}
    try {
        bodyp.writeByteArray(body);                                 // overwrite plaintext; the in-place XOR encrypts ours
        if (oneshot && !scr.persist) delete scr.bodies[pid2];       // one-shot: client's own sends resume; persist: keep replacing
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

function onSendCall(m) {
    if (m.rva === undefined && m.pc === undefined) {                 // disarm
        scSend = null;
        if (scr !== null && scr.sendcall) { scr = null; scrDisarm(); }
    } else {
        var pc = null;
        if (m.pc !== undefined) pc = ptr(m.pc);
        else { var b = peBase(m.module || 'uaRO.exe'); pc = b !== null ? b.add(m.rva) : null; }
        if (pc === null) {
            send({tag: 'SENDCALL', hit: 'error', e: 'could not resolve ' + (m.module || 'uaRO.exe') + ' base'});
        } else {
            scSend = {pc: pc, fn: null, 'this': null, queue: []};
            scr = {pc: pc, reg: 'auto', id: undefined, idoff: 0, lo: null, hi: null, body: null,
                   dry: false, persist: false, probe: false, entry: false, sendcall: true, bodies: {}};
            if (!scrHandler) { scrHandler = true; Process.setExceptionHandler(scrTrap); }
            scrArm();
            console.log('[*] sendcall: capturing this @ ' + pc + ' (one-shot), then call-inject on the game thread');
        }
    }
    recv('sendcall', onSendCall);
}
recv('sendcall', onSendCall);

function onSendEmit(m) {
    if (scSend === null) send({tag: 'SENDCALL', hit: 'error', e: 'emit with no sendcall armed'});
    else if (m.data) scSend.queue.push(Array.from(hexToBytes(m.data)));
    recv('sendcall-emit', onSendEmit);
}
recv('sendcall-emit', onSendEmit);

function drainSendCall() {                       // called from the game thread (recv/send hooks)
    if (scDraining || scSend === null || scSend.fn === null || scSend['this'] === null) return;
    if (scSend.queue.length === 0) return;
    scDraining = true;
    try {
        while (scSend.queue.length) {
            var pk = scSend.queue.shift();
            try {
                var buf = Memory.alloc(pk.length < 8 ? 8 : pk.length);
                buf.writeByteArray(pk);
                scSend.fn(scSend['this'], pk.length, buf);           // client builds+encrypts+sends it
                send({tag: 'SENDCALL', hit: 'sent', len: pk.length, data: hexOf(new Uint8Array(pk))});
            } catch (e) {
                send({tag: 'SENDCALL', hit: 'error', e: 'call: ' + e.message});
            }
        }
    } finally { scDraining = false; }
}

// never leave debug registers armed without our handler: the client would die on the next write
rpc.exports = { dispose: function () { sw = null; swDisarm(); scr = null; scrDisarm(); scSend = null; } };

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
