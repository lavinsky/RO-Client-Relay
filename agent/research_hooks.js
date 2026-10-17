/* Optional helpers, appended by relay.agent.Agent(research=True).
 * Shares core scope; never loaded by the operational default. */
// ---- send watch (opt-in: the driver posts {type:'sendwatch'}) ----------------------------------
// 0437 action / 0438 skill are built in the client's send queue, back to back (the next packet goes
// at buf + len), and the client encrypts the body IN PLACE before sendmsg. A hardware write watchpoint on
// the next slot (all 4 debug registers = 16 bytes, slots are unaligned) sees the plaintext before the
// encryptor overwrites it. The trap handler only copies pc + the 16 bytes into a preallocated ring:
// a heavier handler (first relay_sendbp.py run) hung the client. The window rides along with the
// SEND and the driver picks the plaintext out (relay_sendbp.py --queue = the same method).
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

researchReset = function () { scrEntry = undefined; };
researchTrap = function (ctx) {
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
    return false;
};

// ---- rastreio com Stalker (opcional: o driver envia {type:'trace'}) ----------------------------
// ARRISCADO em codigo protegido pelo gepard: o Stalker reescreve o codigo executado. Primeiro um
// teste de sobrevivencia curto; se o cliente aguentar, com a faixa do uaRO registramos as chamadas
// do codigo do uaRO para dentro do gepard (a chamada do envio do walk esta entre elas). Janela
// curta e desliga sozinho.
var traceSeen = null;
function onTrace(m) {
    var ms = m.ms || 200;
    var th = Process.enumerateThreads().filter(function (t) { return t.id === Process.id; })[0];
    if (!th) { send({tag: 'TRACE', erro: 'thread principal nao encontrada'}); recv('trace', onTrace); return; }
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
    } catch (e) { send({tag: 'TRACE', erro: 'follow: ' + e.message}); recv('trace', onTrace); return; }
    setTimeout(function () {
        try { Stalker.unfollow(th.id); Stalker.flush(); } catch (e) {}
        var msg = {tag: 'TRACE', ms: ms, bytes: nblocos};
        if (traceSeen !== null) { msg.chamadas = Object.keys(traceSeen); msg.n = msg.chamadas.length; }
        else { msg.nota = 'teste de sobrevivencia ok'; }
        send(msg);
        traceSeen = null;
    }, ms);
    recv('trace', onTrace);
}
recv('trace', onTrace);
