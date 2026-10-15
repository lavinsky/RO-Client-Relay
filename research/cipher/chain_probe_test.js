'use strict';
// Synthetic doubles only. No client, Frida or network.
const assert = require('assert');
const {createMachine, createStopper, createRotatingBreakpoint} = require('./chain_probe.js');
function fixture(options = {}) {
    let result = null, stop = null, written = 0x66;
    const reads = [];
    const io = {
        read32: address => { reads.push(address); if (options.readError) throw Error('synthetic');
            if (address === 0x2000) return 0x11223344;
            if (address === 0x3100) return 0x4002; throw Error('unexpected read'); },
        read8: address => { assert.equal(address, 0x4002); return written; },
        selectDestination: () => !options.unselected,
        onStack: address => address >= 0x4000 && address < 0x5000,
        stop: reason => {stop = reason;}, match: row => {result = row;}
    };
    const machine = createMachine(io, {event_cap: options.cap || 1000});
    const contexts = [
        {ebx: 0x2000, ecx: 0x100}, {ebx: 0x11223344, ecx: 0x100},
        {ebx: 0x11223344, ecx: 0x3100}, {ebx: 0x11223344, ecx: 0x4002},
        {ebx: 0x11223344, ecx: 0x4002}
    ].map(c => Object.assign({thread: 7, sp: 0x4800, frame: 0x3000}, c));
    return {machine, contexts, reads, result: () => result, stopped: () => stop,
            write: byte => {written = byte;}};
}
{
    const f = fixture();
    for (let i = 0; i < 5; i++) { if (i === 4) f.write(0x44); f.machine.observe(i, f.contexts[i]); }
    assert.deepEqual(f.reads, [0x2000, 0x3100]);
    const row = f.result();
    assert.equal(row.source_address, 0x2000); assert.equal(row.loaded_value, 0x11223344);
    assert.equal(row.destination, 0x4002); assert.equal(row.destination_after, 0x44);
    assert(row.write_matches && row.load_matches_sample && row.loaded_value_reaches_store);
    assert(!row.source_shares_sp_mapping && !f.machine.incomplete());
    assert.deepEqual(row.sites, [0,1,2,3,4]);
}
{
    const f = fixture(); [0,2,3,4].forEach(i => f.machine.observe(i, f.contexts[i]));
    assert.equal(f.result(), null); assert(f.machine.counts.discontinuities > 0);
}
{
    const f = fixture(); f.contexts[1].thread = 8;
    f.contexts.forEach((c,i) => f.machine.observe(i,c)); assert.equal(f.result(), null);
}
{
    const f = fixture(); f.contexts[1].frame++;
    f.contexts.forEach((c,i) => f.machine.observe(i,c)); assert.equal(f.result(), null);
}
{
    const f = fixture(); f.contexts.forEach((c,i) => f.machine.observe(i,c));
    assert(f.result()); assert.equal(f.result().write_matches, false);
}
{
    const f = fixture({unselected: true}); f.contexts.forEach((c,i) => f.machine.observe(i,c));
    assert.equal(f.result(), null); assert.equal(f.machine.counts.unselected_chains, 1);
}
{
    const f = fixture({cap: 5}); f.contexts.forEach((c,i) => f.machine.observe(i,c));
    assert.equal(f.stopped(), 'event_limit'); assert.equal(f.result(), null);
    assert.equal(f.machine.counts.visits, 5);
}
{
    const f = fixture({readError: true}); f.contexts.forEach((c,i) => f.machine.observe(i,c));
    assert.equal(f.result(), null); assert.equal(f.machine.counts.read_errors, 1);
}
{
    let fail = true, untrace = 0, flush = 0;
    const stopper = createStopper({unfollow: () => {untrace++; if(fail) throw Error('synthetic');},
                                   flush: () => {flush++;}});
    stopper.arm(); assert.equal(stopper.stop().ok, false); assert(stopper.owned());
    fail = false; assert(stopper.stop().ok); assert(!stopper.owned());
    assert.equal(untrace, 2); assert.equal(flush, 1);
    stopper.stop(); assert.equal(untrace, 2);
}
process.stdout.write('CHAIN SYNTHETIC PASS: order, effective source, post-store, isolation, cap, read-error, cleanup\n');

// Exercise the actual RPC/timer wrapper with synthetic Frida doubles, too.
// This proves bounded control flow in the double, not client safety.
const vm = require('vm'), fs = require('fs');
function runtime(failFollow, mechanism = 'stalker', noHit = false, writeCap = 64, producerOnly = false) {
    const messages = [], timers = [], callouts = [];
    let unfollow = 0, flush = 0, handler = null, armed = null, unsets = 0, written = 0x66, watched = false;
    let sourceWord = 0x11223344;
    function pointer(value) {
        return {value, add: n => pointer(value + n), sub: n => pointer(value - (n.value === undefined ? n : n.value)),
            compare: p => Math.sign(value - p.value),
            equals: p => value === p.value, toString: () => '0x' + value.toString(16),
            toUInt32: () => value,
            readU32: () => {if(value === 0x2000) return sourceWord;
                if(value === 0x3100) return 0x4002; throw Error('unexpected synthetic read');},
            readU8: () => written};
    }
    const offsets = [0x18efec, 0x18efee, 0x18eff0, 0x18eff2, 0x18eff4];
    const expected = ['mov ebx, dword ptr [ebx]', 'add ecx, ebp', 'mov ecx, dword ptr [ecx]',
        'mov byte ptr [ecx], bl', 'mov edi, ebp'];
    const instructions = offsets.map((off, i) => ({address: pointer(0x1000 + off),
        next: pointer(0x1000 + off + 2), toString: () => expected[i]}));
    const range = {base: pointer(0x1000), size: 0x200000, protection: 'rwx', file: {path: '/gepard.dll'}};
    const sourceRange = {base: pointer(0x2000), size: 4096, protection: 'rw-'};
    const stackRange = {base: pointer(0x4000), size: 4096, protection: 'rw-'};
    const valueRange = {base: pointer(0x8000), size: 4096, protection: 'rwx'};
    const thread = {id: 7, context: {esp: pointer(0x4800)},
        setHardwareBreakpoint: (slot, address) => {assert.equal(slot, 0); armed = address;
            if (failFollow) throw Error('synthetic arm failure');},
        unsetHardwareBreakpoint: slot => {assert.equal(slot, 0); armed = null; unsets++;},
        setHardwareWatchpoint: (slot, address, size, access) => {
            assert.equal(slot, 1); assert.equal(address.value, mechanism.startsWith('byte-') ? 0x8000 : 0x2000); assert.equal(size, 1);
            assert.equal(access, 'w'); watched = true;},
        unsetHardwareWatchpoint: slot => {assert.equal(slot, 1); watched = false;}};
    const writerInstruction = {address: pointer(0x7000), next: pointer(0x7002), mnemonic: 'mov',
        operands: [{type: 'mem', size: 4, value: {base: 'ebx'}}, {type: 'reg', value: 'ecx'}],
        toString: () => 'mov dword ptr [ebx], ecx'};
    const operandInstruction = {address: pointer(0x6ffd), next: pointer(0x7000), mnemonic: 'movzx',
        toString: () => 'movzx ecx, al'};
    const byteInstruction = {address: pointer(0x9000), next: pointer(0x9002), mnemonic: 'mov',
        operands: [{type: 'mem', size: 1, value: {base: 'esi'}}, {type: 'reg', value: 'cl'}],
        toString: () => 'mov byte ptr [esi], cl'};
    const loadPath = [
        [0x5fe7, 0x5fe9, 'mov al, byte ptr [eax]'], [0x5fe9, 0x5fee, 'mov esi, 0'],
        [0x5fee, 0x5ff1, 'movzx ebx, bx'], [0x5ff1, 0x5ff6, 'mov esi, 1'],
        [0x5ff6, 0x5ffb, 'mov edi, 0x400'], [0x5ffb, 0x5ffd, 'add ebx, ebp']
    ].map(([rva, next_rva, instruction]) => ({rva, next_rva, instruction}));
    const loadInstructions = loadPath.map(n => ({address: pointer(n.rva + 0x1000),
        next: pointer(n.next_rva + 0x1000), mnemonic: n.instruction.split(' ')[0], toString: () => n.instruction}));
    const context = {Process: {id: 7, arch: 'ia32', enumerateThreads: () => [thread],
        getCurrentThreadId: () => 7, setExceptionHandler: callback => {handler = callback;},
        enumerateRanges: () => [range], findRangeByAddress: p => p.value >= 0x2000 && p.value < 0x3000 ? sourceRange :
            p.value >= 0x4000 && p.value < 0x5000 ? stackRange : p.value >= 0x8000 && p.value < 0x9000 ? valueRange : range},
        Instruction: {parse: p => operandInstruction.address.equals(p) ? operandInstruction :
            byteInstruction.address.equals(p) ? byteInstruction :
            writerInstruction.address.equals(p) ? writerInstruction :
            loadInstructions.find(i => i.address.equals(p)) || instructions.find(i => i.address.equals(p))},
        Stalker: {
            follow: (thread, options) => {
                if (failFollow) throw Error('synthetic follow failure');
                let n = 0;
                options.transform({next: () => instructions[n++] || null,
                    keep: () => {}, putCallout: callback => callouts.push(callback)});
            },
            unfollow: () => {unfollow++;}, flush: () => {flush++;}
        }, ptr: pointer, rpc: {exports: {}}, send: value => messages.push(value),
        setTimeout: callback => {timers.push(callback); return timers.length;},
        clearTimeout: () => {}, setImmediate: callback => callback(), Date: {now: () => 1000}};
    vm.runInNewContext(fs.readFileSync(__dirname + '/chain_probe.js', 'utf8')
        .replace('__CONFIG__', JSON.stringify({pid: 7, window_ms: 500, event_cap: 1000,
            bytes_cap: 262144, mechanism, arm_timeout_ms: 10000, selection: 'any-chain', write_cap: writeCap,
            producer_only: producerOnly,
            producer: {rva: 0x6000, next_rva: 0x6002, input_rva: 0x5ffd, instruction: 'mov dword ptr [ebx], ecx'},
            load_path: loadPath,
            value_watch: {address: 0x8000, mapping: {base: '0x8000', size: 4096, protection: 'rwx', file_backed: false}},
            byte_producer: {rva: 0x8000, next_rva: 0x8002},
            source_watch: {address: 0x2000, frame: 0x3000,
                mapping: {base: '0x2000', size: 4096, protection: 'rw-', file_backed: false}}})), context);
    context.rpc.exports.start();
    if (!failFollow && mechanism === 'stalker') {callouts[0](); timers[0]();}
    if (!failFollow && mechanism !== 'stalker') {
        if (noHit) {
            if (noHit === 'unpaired') {
                assert(handler({type: 'breakpoint', context: {pc: armed, eax: pointer(0x8000),
                    ebx: pointer(0x1000), ebp: pointer(0x1000), esp: pointer(0x4800)}}));
            }
            if (noHit === 'unattributed') {
                assert(handler({type: 'single-step', context: {pc: pointer(0xdeadbeef),
                    ebx: pointer(0x2000), ebp: pointer(0x3000)}}));
            }
            timers[0]();
        }
        else {
            const f = fixture();
            const frame = ['load','byte-writer','byte-producer'].includes(mechanism) ? 0x1000 : 0x3000;
            const operandEax = ['load','byte-writer','byte-producer'].includes(mechanism) ? 0x8044 : 0xabcdef44;
            if (mechanism === 'byte-producer') {
                const registers = {esi: pointer(0x8000), ecx: pointer(0xaabbcc44), esp: pointer(0x4800), ebp: pointer(frame)};
                assert(armed.equals(byteInstruction.address));
                assert(handler({type: 'breakpoint', context: {...registers, pc: armed}}));
                assert(armed.equals(byteInstruction.next)); written = 0x44;
                assert(handler({type: 'breakpoint', context: {...registers, pc: armed}}));
            }
            if (mechanism === 'byte-writer') {
                written = 0x44;
                assert(handler({type: 'single-step', context: {pc: pointer(0x7002), ebx: pointer(0x8000), ebp: pointer(frame)}}));
            }
            if (!producerOnly && ['load','byte-writer','byte-producer'].includes(mechanism)) {
                const registers = {ebx: pointer(0x1000), ecx: pointer(0x66), eax: pointer(0x8000),
                    esp: pointer(0x4800), ebp: pointer(frame)};
                written = 0x44;
                loadInstructions.forEach((ins, i) => {
                    assert(armed.equals(ins.address));
                    assert(handler({type: 'breakpoint', context: {...registers, pc: armed}}));
                    if (i === 0) registers.eax = pointer(operandEax);
                    if (i === 5) registers.ebx = pointer(0x2000);
                });
                f.contexts.forEach((c, i) => {c.frame = frame; if (i < 2) c.ecx = 0x2100;});
            }
            if (mechanism === 'writer') {
                written = 0x44;
                assert(watched);
                assert(handler({type: 'single-step', context: {pc: pointer(0x7002), ebx: pointer(0x2000), ebp: pointer(0x3000)}}));
            }
            if (!producerOnly && ['operand', 'load', 'byte-writer', 'byte-producer'].includes(mechanism)) {
                assert(armed.equals(operandInstruction.address));
                assert(handler({type: 'breakpoint', context: {pc: armed, ebx: pointer(0x2000),
                    ecx: pointer(0x66), eax: pointer(operandEax), esp: pointer(0x4800), ebp: pointer(frame)}}));
                f.contexts.forEach((c, i) => {if (i > 0) c.ebx = 0x44;});
            }
            if (!producerOnly && ['producer', 'operand', 'load', 'byte-writer', 'byte-producer'].includes(mechanism)) {
                assert(armed.equals(writerInstruction.address));
                const registers = {pc: armed, ebx: pointer(0x2000), ecx: pointer(['operand','load','byte-writer','byte-producer'].includes(mechanism) ? 0x44 : 0x11223344),
                    eax: pointer(operandEax),
                    esp: pointer(0x4800), ebp: pointer(frame)};
                assert(handler({type: 'breakpoint', context: registers}));
                assert(armed.equals(writerInstruction.next));
                written = 0x44;
                if (['operand','load','byte-writer','byte-producer'].includes(mechanism)) sourceWord = 0x44;
                assert(handler({type: 'breakpoint', context: {...registers, pc: armed}}));
            }
            if (!producerOnly && writeCap > 1) f.contexts.forEach((c, i) => {
                assert(armed.equals(instructions[i].address));
                if (i === 4) written = 0x44;
                const registers = {pc: armed, esp: pointer(c.sp), ebp: pointer(c.frame),
                    ebx: pointer(c.ebx), ecx: pointer(c.ecx)};
                assert(handler({type: 'breakpoint', context: registers}));
            });
        }
    }
    const done = messages.find(m => m.tag === 'DONE');
    assert(done.cleanup.ok);
    if (mechanism === 'stalker') {
        assert.equal(unfollow, 1); assert.equal(flush, 1);
        assert.equal(done.reason, failFollow ? 'follow_error' : 'timeout');
    } else {
        assert.equal(done.reason, failFollow ? 'breakpoint_error' : noHit === 'unattributed' ? 'unattributed_exception' :
            noHit ? 'timeout' : producerOnly ? 'byte_producer_confirmed' : writeCap === 1 ? 'write_limit' : 'matched');
        assert.equal(armed, null); assert.equal(handler, null); assert(unsets >= 1);
        assert(!watched);
        if (!failFollow && !noHit && producerOnly) {
            assert(done.partial_observations.byte_producer.copy_matches);
            assert(done.partial_observations.byte_producer.context_matches);
            assert.equal(done.occurrence, null);
        }
        if (!failFollow && !noHit && !producerOnly && writeCap > 1) {
            assert(done.occurrence.write_matches);
            if (mechanism === 'writer') assert(done.occurrence.loaded_byte_matches_preceding_write);
            if (['producer', 'operand', 'load', 'byte-writer', 'byte-producer'].includes(mechanism)) {
                assert(done.occurrence.producer.copy_matches && done.occurrence.producer.context_matches);
                assert(done.occurrence.producer_is_last_write_before_load);
            }
            if (['operand','load','byte-writer','byte-producer'].includes(mechanism)) assert(done.occurrence.operand.zero_extension_matches && done.occurrence.operand.context_matches);
            if (['load','byte-writer','byte-producer'].includes(mechanism)) {
                assert(done.occurrence.value_load.load_matches && done.occurrence.value_load.eax_stable_after_load);
                assert(done.occurrence.loaded_source_byte_equals_store);
            }
            if (['byte-writer','byte-producer'].includes(mechanism)) assert(done.occurrence.value_matches_preceding_write);
            if (mechanism === 'byte-producer') assert(done.occurrence.byte_producer.copy_matches &&
                done.occurrence.byte_producer.context_matches && done.occurrence.byte_producer_is_last_write_before_read);
        }
    }
    if (!failFollow && mechanism === 'stalker') {
        assert.equal(done.coverage.translated_blocks, 1);
        assert.equal(done.coverage.chain_sites_translated, 5);
        assert(done.coverage.first_block_entered);
    }
    assert(context.rpc.exports.stop().ok);
}
runtime(false); runtime(true);
runtime(false, 'breakpoint'); runtime(true, 'breakpoint'); runtime(false, 'breakpoint', true);
runtime(false, 'writer'); runtime(true, 'writer'); runtime(false, 'writer', true); runtime(false, 'writer', false, 1);
runtime(false, 'writer', 'unattributed');
runtime(false, 'producer'); runtime(true, 'producer'); runtime(false, 'producer', true);
runtime(false, 'operand'); runtime(true, 'operand'); runtime(false, 'operand', true);
runtime(false, 'load'); runtime(true, 'load'); runtime(false, 'load', true);
runtime(false, 'byte-writer'); runtime(true, 'byte-writer'); runtime(false, 'byte-writer', true);
runtime(false, 'byte-writer', 'unpaired');
runtime(false, 'byte-producer'); runtime(true, 'byte-producer'); runtime(false, 'byte-producer', true);
runtime(false, 'byte-producer', false, 64, true);
{
    let fail = true;
    const rotating = createRotatingBreakpoint({set: () => {}, unset: () => {if(fail) throw Error('synthetic');}});
    rotating.arm(0); assert(rotating.owns(0)); assert(!rotating.stop().ok); assert(rotating.owned());
    fail = false; assert(rotating.stop().ok); assert(!rotating.owned());
}
process.stdout.write('CHAIN RUNTIME DOUBLES PASS: timeout, follow-error, coverage, owned cleanup\n');
