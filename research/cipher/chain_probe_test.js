'use strict';
// Synthetic doubles only. No client, Frida or network.
const assert = require('assert');
const {createMachine, createStopper, createRotatingBreakpoint, inspectPredecessorGraph, createClMachine, createStackCopyMachine,decodeSwapCandidate,createSwapDecoder} = require('./chain_probe.js');
{
    function stackFixture(source=0x3000,badSite=null) {
        const memory=new DataView(new ArrayBuffer(0x6000));let reason=null;
        const write=(a,v)=>memory.setUint32(a,v,true),read=a=>memory.getUint32(a,true);
        write(source,0x11223344);write(0x2000,0x55667788);
        const machine=createStackCopyMachine({read32:read,mapping:a=>({base:Math.floor(a/4096)*4096,size:4096}),stop:r=>{reason=r;}});
        const c={thread:7,sp:0x4800,frame:0x1fca,esi:source,edx:0x2000};
        machine.observe(0,c);const input=read(source);write(0x47fc,input);c.sp-=4;
        machine.observe(badSite===1?2:1,c);write(0x47f8,read(0x2000));c.sp-=4;
        machine.observe(2,c);write(source,read(c.sp));c.sp+=4;
        machine.observe(3,c);write(0x2000,read(c.sp));c.sp+=4;
        machine.observe(4,c);return {row:machine.current(),reason};
    }
    for(const source of [0x3000,0x2000,0x2001]) {
        const {row,reason}=stackFixture(source);assert.equal(reason,null);assert(row.complete);
        assert(Object.values(row.comparisons).every(Boolean));assert.equal(row.same_address,source===0x2000);
    }
    const lost=stackFixture(0x3000,1);assert.equal(lost.reason,'stack_prefix_discontinuity');assert(!lost.row.complete);
    const aliasStack=stackFixture(0x47fc);assert(aliasStack.row.complete);
    assert(!aliasStack.row.comparisons.remaining_stack_slot_preserved && !aliasStack.row.comparisons.original_source_reaches_destination);
}
{
    const result = inspectPredecessorGraph({now: () => 0, parse: rva => {
        if (rva === 99) return {rva, next_rva: 100, mnemonic: 'mov'};
        if (rva === 97) return {rva, next_rva: 99, mnemonic: 'jmp'};
        throw Error('synthetic undecodable');
    }}, 100);
    assert.deepEqual(result.nodes.map(n => n.rva), [99, 97]);
    assert(result.code_only && !result.executed_path_proven);
    assert(result.attempts <= 480);
    const capped = inspectPredecessorGraph({now: () => 0,
        parse: rva => ({rva, next_rva: rva + 1, mnemonic: 'mov'})}, 100);
    assert(capped.nodes.length <= 32 && capped.limit_reached);
    let time = 0;
    const timeout = inspectPredecessorGraph({now: () => {time += 201; return time;},
        parse: () => {throw Error('must not decode');}}, 100);
    assert.equal(timeout.attempts, 0);
}
{
    function fixtureCl(cap = 1000, failRead = false) {
        let reason = null, written = 0x66;
        const machine = createClMachine({read32: a => {
            if (failRead) throw Error('synthetic read');
            if (a === 0x2000) return 0x11223344;
            if (a === 0x3100) return 0x4002; throw Error('unexpected read');},
            read8: () => written, mapping: () => ({base: '0x2000', size: 4096}),
            stop: r => {reason = r;}}, {event_cap: cap});
        const contexts = Array.from({length: 13}, (_, i) => ({thread: 7, sp: 0x4800, frame: 0x3000,
            ecx: i === 0 ? 0x2000 : 0x11223344, esi: i <= 9 ? 0x3100 : 0x4002}));
        return {machine, contexts, reason: () => reason, write: () => {written = 0x44;}};
    }
    const good = fixtureCl();
    good.contexts.forEach((c,i) => {if(i === 12) good.write(); good.machine.observe(i,c);});
    const row = good.machine.current();
    assert.equal(row.source_address, 0x2000); assert.equal(row.loaded_value, 0x11223344);
    assert(row.load_matches && row.ecx_stable && row.pointer_load_matches && row.store_matches && row.complete);
    assert.equal(good.reason(), 'cl_origin_observed');
    const wrongThread = fixtureCl(); wrongThread.contexts[1].thread++;
    wrongThread.contexts.forEach((c,i) => wrongThread.machine.observe(i,c));
    assert.equal(wrongThread.reason(), 'cl_discontinuity'); assert(!wrongThread.machine.current().complete);
    const loss = fixtureCl(); [0,2,3].forEach(i => loss.machine.observe(i,loss.contexts[i]));
    assert.equal(loss.reason(), 'cl_discontinuity');
    const cap = fixtureCl(5); cap.contexts.forEach((c,i) => cap.machine.observe(i,c));
    assert.equal(cap.reason(), 'event_limit'); assert(!cap.machine.current().complete);
    const error = fixtureCl(1000,true); error.machine.observe(0,error.contexts[0]);
    assert.equal(error.reason(), 'cl_read_error');
}
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
{
    const code=['push dword ptr [edi]','push dword ptr [eax]','pop dword ptr [edi]'];
    const io={parse:rva=>({instruction:code[(rva-0x100)/2],next_rva:rva+2}),register:n=>n==='edi'?0x2040:0x2000};
    const result=decodeSwapCandidate(io,{rva:0x106,instruction:'pop dword ptr [eax]'});
    assert(result && !result.executed_path_proven && result.source_address===0x2040 && result.first_pop_rva===0x104);
    assert.equal(decodeSwapCandidate(io,{rva:0x106,instruction:'pop dword ptr [esp]'}),null);
    code[1]='push dword ptr [ebx]';assert.equal(decodeSwapCandidate(io,{rva:0x106,instruction:'pop dword ptr [eax]'}),null);
}
{
    let signature='first',parses=0;
    const texts=['push dword ptr [edi]','push dword ptr [eax]','pop dword ptr [edi]'];
    const decoder=createSwapDecoder({fingerprint:()=>signature,parse:rva=>{parses++;return {instruction:texts[(rva-0x100)/2],next_rva:rva+2};},register:(n,c)=>c[n]});
    const final={rva:0x106,instruction:'pop dword ptr [eax]'};
    assert.equal(decoder.decode(final,{edi:0x2040,eax:0x2000}).source_address,0x2040);
    const count=parses;
    assert.equal(decoder.decode(final,{edi:0x2080,eax:0x2000}).source_address,0x2080);assert.equal(parses,count);
    signature='changed';texts[1]='push dword ptr [ebx]';assert.equal(decoder.decode(final,{edi:0x2080,eax:0x2000}),null);assert(parses>count);
}
const vm = require('vm'), fs = require('fs');
function runtime(failFollow, mechanism = 'stalker', noHit = false, writeCap = 64, producerOnly = false, eventCap = 1000, writeKind = 'mov', relative = false, stackPrefix = false, producerRegister = 'edx', producerHit = 1, repeatProducer = false, lineage = false, deferred = false, upstreamOnly = false, third = false) {
    const messages = [], timers = [], callouts = [], immediates=[];
    let consumerArmed=null,sourceWatched=false,extraWatched=false,extraByte=0x99;
    const prefixSourceAddress=lineage?0x200a:0x3200;
    let unfollow = 0, flush = 0, handler = null, armed = null, unsets = 0, written = 0x66, watched = false;
    let sourceWord = 0x11223344;
    let prefixSourceWord=0x55667788,stackOlder=0x55667788,stackNewer=0x11223344;
    const clFrame=relative?(upstreamOnly?0x1fc0:0x1fca):0x3000;
    function pointer(value) {
        return {value, add: n => pointer(value + n), sub: n => pointer(value - (n.value === undefined ? n : n.value)),
            compare: p => Math.sign(value - p.value),
            equals: p => value === p.value, toString: () => '0x' + value.toString(16),
            toUInt32: () => value,
            readU16: () => {if(value===0x1000)return 0x5a4d;if(value===0x1098)return 0x10b;throw Error('unexpected synthetic header');},
            readU32: () => {if(value===0x103c)return 0x80;if(value===0x1080)return 0x4550;if(value===0x10d0)return 0x300000;
                if(value === 0x47fc)return stackOlder;
                if(value === 0x47f8)return stackNewer;
                if(value === prefixSourceAddress)return prefixSourceWord;
                if(value === 0x2000) return sourceWord;
                if(value === 0x3100) return 0x4002; throw Error('unexpected synthetic read');},
            readU8: () => value===0x201a && third ? extraByte : value===prefixSourceAddress && lineage ? prefixSourceWord&255 : written};
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
        setHardwareBreakpoint: (slot, address) => {if(slot===2){consumerArmed=address;return;}assert.equal(slot, 0); armed = address;
            if (failFollow) throw Error('synthetic arm failure');},
        unsetHardwareBreakpoint: slot => {if(slot===2){consumerArmed=null;return;}assert.equal(slot, 0); armed = null; unsets++;},
        setHardwareWatchpoint: (slot, address, size, access) => {
            if(slot===2){assert.equal(address.value,0x201a);assert.equal(size,1);assert.equal(access,'w');extraWatched=true;return;}
            if(slot===3){assert.equal(address.value,0x200a);assert.equal(size,1);assert.equal(access,'w');sourceWatched=true;return;}
            assert.equal(slot, 1); assert.equal(address.value, mechanism.startsWith('byte-') ? 0x8000 : 0x2000); assert.equal(size, 1);
            assert.equal(access, 'w'); watched = true;if(noHit==='watch-arm-error')throw Error('synthetic watch arm failure');},
        unsetHardwareWatchpoint: slot => {if(slot===2){extraWatched=false;return;}if(slot===3){sourceWatched=false;return;}assert.equal(slot, 1); watched = false;}};
    const writerInstruction = {address: pointer(0x7000), next: pointer(0x7002), mnemonic: writeKind,
        operands: [{type: 'mem', size: writeKind === 'add' ? 1 : 4, value: {base: 'ebx'}}, {type: 'reg', value: 'ecx'}],
        toString: () => writeKind === 'add' ? 'add byte ptr [ebx], al' : writeKind+' dword ptr [ebx], ecx'};
    const operandInstruction = {address: pointer(0x6ffd), next: pointer(0x7000), mnemonic: 'movzx',
        toString: () => 'movzx ecx, al'};
    const byteInstruction = {address: pointer(0x9000), next: pointer(0x9002), mnemonic: 'mov',
        operands: [{type: 'mem', size: 1, value: {base: 'esi'}}, {type: 'reg', value: 'cl'}],
        toString: () => 'mov byte ptr [esi], cl'};
    const xorInstruction = {address:pointer(0xb000),next:pointer(0xb002),mnemonic:'xor',
        toString:()=>'xor dword ptr [ecx], edx'};
    const popInstruction = {address:pointer(0xc000),next:pointer(0xc002),mnemonic:'pop',
        toString:()=>'pop dword ptr ['+producerRegister+']'};
    const prefixSourceRegister=producerRegister==='ebx'?'edi':'esi';
    const prefixRows=[[0xaffa,'push dword ptr ['+prefixSourceRegister+']'],[0xaffc,'push dword ptr ['+producerRegister+']'],[0xaffe,'pop dword ptr ['+prefixSourceRegister+']']];
    const prefixPath=prefixRows.map(([rva,instruction])=>({rva,next_rva:rva+2,instruction}));
    const prefixInstructions=prefixPath.map(n=>({address:pointer(n.rva+0x1000),next:pointer(n.next_rva+0x1000),
        mnemonic:n.instruction.split(' ')[0],toString:()=>n.instruction}));
    const loadPath = [
        [0x5fe7, 0x5fe9, 'mov al, byte ptr [eax]'], [0x5fe9, 0x5fee, 'mov esi, 0'],
        [0x5fee, 0x5ff1, 'movzx ebx, bx'], [0x5ff1, 0x5ff6, 'mov esi, 1'],
        [0x5ff6, 0x5ffb, 'mov edi, 0x400'], [0x5ffb, 0x5ffd, 'add ebx, ebp']
    ].map(([rva, next_rva, instruction]) => ({rva, next_rva, instruction}));
    const loadInstructions = loadPath.map(n => ({address: pointer(n.rva + 0x1000),
        next: pointer(n.next_rva + 0x1000), mnemonic: n.instruction.split(' ')[0], toString: () => n.instruction}));
    const clRows = [[0x1c7502,'mov ecx, dword ptr [ecx]'],[0x1c7504,'xor ebx, 0x47d61b9'],
        [0x1c750a,'sub eax, esi'],[0x1c750c,'add esi, ebp'],[0x1c750e,'mov eax, 0xa'],
        [0x1c7513,'xor eax, 0x80'],[0x1c7518,'mov eax, ebx'],[0x1c751a,'mov eax, 0x200'],
        [0x1c751f,'or eax, 0x1f'],[0x1c7524,'mov esi, dword ptr [esi]'],[0x1c7526,'and eax, 4'],
        [0x1c752b,'mov byte ptr [esi], cl'],[0x1c752d,'nop']];
    const clPath = clRows.slice(0,11).map(([rva,instruction],i) => ({rva,instruction,next_rva:clRows[i+1][0]}));
    const clInstructions = clRows.map(([rva,instruction],i) => ({address:pointer(rva+0x1000),
        next:pointer((clRows[i+1] || [rva+1])[0]+0x1000), toString:() => instruction}));
    const context = {Process: {id: 7, arch: 'ia32', enumerateThreads: () => [thread],
        getCurrentThreadId: () => 7, setExceptionHandler: callback => {handler = callback;},
        enumerateRanges: () => [range], findRangeByAddress: p => p.value >= 0x2000 && p.value < 0x3000 ? sourceRange :
            p.value >= 0x4000 && p.value < 0x5000 ? stackRange : p.value >= 0x8000 && p.value < 0x9000 ? valueRange : range},
        Instruction: {parse: p => [operandInstruction, byteInstruction, writerInstruction, xorInstruction, popInstruction, ...prefixInstructions,
            ...clInstructions, ...loadInstructions, ...instructions].find(i => i.address.equals(p))},
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
        clearTimeout: () => {}, setImmediate: callback => {if(deferred)immediates.push(callback);else callback();}, Date: {now: () => 1000}};
    vm.runInNewContext(fs.readFileSync(__dirname + '/chain_probe.js', 'utf8')
        .replace('__CONFIG__', JSON.stringify({pid: 7, window_ms: 500, event_cap: eventCap,
            bytes_cap: 262144, mechanism, arm_timeout_ms: 10000, selection: 'any-chain', write_cap: writeCap,
            producer_only: producerOnly,
            producer: {rva: 0x6000, next_rva: 0x6002, input_rva: 0x5ffd, instruction: 'mov dword ptr [ebx], ecx'},
            load_path: loadPath,
            cl_path: clPath,
            cl_transform:{rva:0xa000,next_rva:0xa002,instruction:'xor dword ptr [ecx], edx'},
            cl_producer:{rva:0xb000,next_rva:0xb002,instruction:'pop dword ptr ['+producerRegister+']',destination_register:producerRegister},
            cl_watch: relative?undefined:{address:0x2000,mapping:{base:'0x2000',size:4096,protection:'rw-',file_backed:false}},
            cl_source_relative:relative?{register:'ebp',offset:upstreamOnly?0x40:0x36,historical_reference_only:true,source_session_reused:false,upstream_operand_reference:upstreamOnly}:undefined,
            cl_stack_prefix:stackPrefix?prefixPath:undefined,
            cl_extra_source:third?{register:'ebp',offset:0x50,runtime_reused:false}:undefined,
            cl_lineage_source:lineage?{register:'ebp',offset:0x40,runtime_reused:false}:undefined,
            cl_stack_source_register:prefixSourceRegister,cl_producer_hit:producerHit,cl_producer_repeat:repeatProducer,
            cl_producer_track_intervening: noHit==='producer-overwrite-retain',cl_upstream_only:upstreamOnly,
            value_watch: {address: 0x8000, mapping: {base: '0x8000', size: 4096, protection: 'rwx', file_backed: false}},
            byte_producer: {rva: 0x8000, next_rva: 0x8002},
            source_watch: {address: 0x2000, frame: 0x3000,
                mapping: {base: '0x2000', size: 4096, protection: 'rw-', file_backed: false}}})), context);
    context.rpc.exports.start();
    if (['cl-origin','cl-writer','cl-transform','cl-producer'].includes(mechanism)) {
        if (!failFollow) {
            if (['wrong-relative','stack-relative','watch-arm-error','producer-overwrite','producer-overwrite-retain'].includes(noHit)) {
                const c={ecx:pointer(0x2000),edx:pointer(noHit==='stack-relative'?0x4800:noHit==='wrong-relative'?0x2004:0x2000),
                    esp:pointer(0x47fc),ebp:pointer(noHit==='stack-relative'?0x47ca:clFrame)};
                assert(handler({type:'breakpoint',context:{...c,pc:armed}}));
                if(noHit==='wrong-relative'){assert(!watched);timers[0]();}
                if(['producer-overwrite','producer-overwrite-retain'].includes(noHit)) {
                    sourceWord=0x55667788;written=sourceWord&255;c.esp=pointer(0x4800);
                    assert(handler({type:'breakpoint',context:{...c,pc:armed}}));
                    written^=1;sourceWord^=1;
                    assert(handler({type:'single-step',context:{pc:writerInstruction.next,ebx:pointer(0x2000),ebp:pointer(clFrame)}}));
                    assert(handler({type:'breakpoint',context:{...c,esi:pointer(0x3100),ecx:pointer(0x2000),pc:armed}}));
                    if(noHit==='producer-overwrite-retain')timers[0]();
                }
            } else if (noHit === 'writeburst') {
                for(let i=0;i<writeCap;i++) assert(handler({type:'single-step',context:{pc:writerInstruction.next,
                    ebx:pointer(0x2000),ebp:pointer(0x3000)}}));
            } else if (noHit) {
                if (noHit === 'unpaired') assert(handler({type:'breakpoint',context:{pc:armed,
                    ecx:pointer(0x2000),esp:pointer(0x4800),ebp:pointer(0x3000),esi:pointer(0x3100)}}));
                timers[0]();
            } else if (eventCap === 1) {
                assert(handler({type:'breakpoint',context:{pc:armed,ecx:pointer(0x2000)}}));
            } else {
                if(stackPrefix) {
                  for(let cycle=0;cycle<(repeatProducer && !third?2:1);cycle++){
                    const c={ecx:pointer(0),edx:pointer(0x2000),esi:pointer(0x3200),esp:pointer(0x4800),ebp:pointer(clFrame)};
                    c[prefixSourceRegister]=pointer(prefixSourceAddress);
                    if(lineage && cycle===1){
                        prefixSourceWord=0xaabbccdd;
                        assert(handler({type:'single-step',context:{pc:writerInstruction.next,ebx:pointer(prefixSourceAddress),ebp:pointer(clFrame)}}));
                    }c[producerRegister]=pointer(0x2000);
                    for(let h=1;cycle===0 && h<producerHit;h++){assert(handler({type:'breakpoint',context:{...c,pc:armed}}));assert(!watched);}
                    assert(handler({type:'breakpoint',context:{...c,pc:armed}}));
                    stackOlder=prefixSourceWord;c.esp=pointer(0x47fc);
                    assert(handler({type:'breakpoint',context:{...c,pc:armed}}));
                    stackNewer=sourceWord;c.esp=pointer(0x47f8);
                    assert(handler({type:'breakpoint',context:{...c,pc:armed}}));
                    prefixSourceWord=stackNewer;c.esp=pointer(0x47fc);
                    assert(handler({type:'breakpoint',context:{...c,pc:armed}}));
                    sourceWord=stackOlder;written=sourceWord&255;c.esp=pointer(0x4800);
                    assert(handler({type:'breakpoint',context:{...c,pc:armed}}));
                  }
                } else if (['cl-transform','cl-producer'].includes(mechanism)) {
                    const pop=mechanism==='cl-producer', ins=pop?popInstruction:xorInstruction;
                    const c = {ebx:pointer(0x2000),ecx:pointer(0x2000),edx:pointer(pop?0x2000:0x01020304),esp:pointer(pop?0x47fc:0x4800),ebp:pointer(clFrame)};
                    assert(armed.equals(ins.address));
                    assert(handler({type:'breakpoint',context:{...c,pc:armed}}));
                    sourceWord=pop?0x55667788:(sourceWord^0x01020304)>>>0; written=sourceWord&255;
                    c.esp=pointer(0x4800);
                    assert(armed.equals(ins.next));
                    assert(handler({type:'breakpoint',context:{...c,pc:armed}}));
                }
                if (mechanism === 'cl-writer') {
                    written = 0x44;
                    assert(handler({type:'single-step',context:{pc:writerInstruction.next,
                        ebx:pointer(0x2000),ebp:pointer(0x3000)}}));
                }
                if(third){extraByte=0x77;assert(handler({type:'single-step',context:{pc:writerInstruction.next,ebx:pointer(0x201a),ebp:pointer(clFrame)}}));}
                if (writeCap > 1 && !upstreamOnly) clInstructions.forEach((ins,i) => {
                const activePc=repeatProducer && !third && i===0?consumerArmed:armed;
                assert(activePc.equals(ins.address));
                if (i === 12) written = sourceWord&255;
                assert(handler({type:'breakpoint',context:{pc:activePc,esp:pointer(0x4800),ebp:pointer(clFrame),
                    ecx:pointer(i === 0 ? 0x2000 : sourceWord),esi:pointer(i <= 9 ? 0x3100 : 0x4002)}}));
                });
            }
        }
        if(deferred){
            assert(armed===null && !watched && !sourceWatched && !extraWatched && consumerArmed===null);
            assert(!messages.some(e=>e.tag==='DONE'));
            immediates.forEach(callback=>callback());
        }
        const end = messages.find(e => e.tag === 'DONE');
        assert.equal(end.reason, upstreamOnly?'upstream_pop_observed':failFollow || ['stack-relative','watch-arm-error'].includes(noHit) ? 'cl_probe_error' :
            noHit==='producer-overwrite'?'transform_overwritten':noHit === 'writeburst' ? 'write_limit' : noHit ? 'timeout' :
            eventCap === 1 ? 'event_limit' : writeCap === 1 ? 'write_limit' : 'cl_origin_observed');
        assert(consumerArmed===null && !sourceWatched && !extraWatched);
        if(third){assert(end.cl_extra_source_write_count===1);assert(end.cl_extra_source_writer_observations[0].byte_after===0x77);}
        if(lineage && !third){
            assert(end.cl_source_writer_observations.length===3);
            assert(end.cl_stack_source.source_lineage.preceding_write.byte_after===end.cl_stack_source.source_lineage.sampled_byte);
        }
        if(repeatProducer)assert(end.cl_producer_occurrences.length===(third?1:2));
        assert(end.cleanup.ok && armed === null && (handler === null || handler({type:'synthetic-unowned'}) === false) && !watched);
        if(upstreamOnly){assert(end.cl_origin===null && end.cl_producer.complete);if(stackPrefix)assert(end.cl_stack_source.complete);}
        if (!failFollow && !noHit && writeCap > 1 && eventCap > 1 && !upstreamOnly) {
            assert(end.cl_origin.complete && end.cl_origin.store_matches);
            if (mechanism === 'cl-writer') assert(end.cl_preceding_write.byte_after === end.cl_origin.store_byte);
            if (mechanism === 'cl-transform') {
                assert(end.cl_transformation.complete && end.cl_transformation.xor_matches && end.cl_transformation.post_context_matches);
                assert(end.cl_preceding_write.order===end.cl_transformation.write_order);
                assert(end.cl_preceding_write.byte_after===end.cl_origin.store_byte);
            }
            if (mechanism==='cl-producer') {
                assert(end.cl_producer.complete && end.cl_producer.copy_matches && end.cl_producer.post_context_matches);
                assert(end.cl_producer.source_address===0x47fc && end.cl_origin.source_sample===end.cl_producer.after);
                if(relative)assert(end.resolved_source.observed_in_current_hit && end.resolved_source.address===0x2000);
                if(stackPrefix)assert(end.cl_stack_source.complete && Object.values(end.cl_stack_source.comparisons).every(Boolean));
            }
        }
        if (noHit === 'unpaired') assert(end.cl_reads_without_writer === 1 && end.cl_origin === null);
        if(noHit==='producer-overwrite')assert(end.cl_producer.complete && end.cl_origin===null);
        if (noHit === 'writeburst') {
            assert(end.writer_counts.writes===writeCap && end.cl_writer_observations.length===writeCap-1);
            assert(JSON.stringify(messages).length<262144);
        }
        assert(context.rpc.exports.stop().ok);
        return;
    }
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
runtime(false, 'cl-origin'); runtime(true, 'cl-origin'); runtime(false, 'cl-origin', true);
runtime(false, 'cl-writer'); runtime(true, 'cl-writer'); runtime(false, 'cl-writer', true);
runtime(false, 'cl-writer', 'unpaired'); runtime(false, 'cl-writer', false, 1);
runtime(false, 'cl-transform');runtime(true, 'cl-transform');runtime(false,'cl-transform',true);
runtime(false, 'cl-transform', false, 1);
runtime(false, 'cl-transform', false, 64, false, 1);
runtime(false, 'cl-writer', false, 64, false, 1000, 'xor');
runtime(false, 'cl-writer', false, 64, false, 1000, 'add');
runtime(false, 'cl-writer', 'writeburst', 256);
runtime(false,'cl-producer','producer-overwrite-retain',64,false,1000,'mov',true);
runtime(false,'cl-producer',false,64,false,1000,'mov',true,false,'ebx');
runtime(false,'cl-producer');runtime(true,'cl-producer');runtime(false,'cl-producer',true);
runtime(false,'cl-producer',false,1);runtime(false,'cl-producer',false,64,false,1);
runtime(false,'cl-producer',false,64,false,1000,'mov',true);
runtime(false,'cl-producer',true,64,false,1000,'mov',true);
runtime(true,'cl-producer',false,64,false,1000,'mov',true);
for(const scenario of ['wrong-relative','stack-relative','watch-arm-error','producer-overwrite'])
    runtime(false,'cl-producer',scenario,64,false,1000,'mov',true);
runtime(false,'cl-producer',false,64,false,1000,'mov',true,true,'eax',1,false,false,true,true);
runtime(false,'cl-producer',false,64,false,1000,'mov',true,false,'ebx',1,false,false,true,true);
runtime(false,'cl-producer',false,64,false,1000,'mov',true,true,'ebx',4,true,true,true,false,true);
runtime(false,'cl-producer',false,64,false,1000,'mov',true,true,'ebx',4,true,true,true);
runtime(false,'cl-producer',false,64,false,1000,'mov',true,true,'ebx',1,true,true,true);
runtime(false,'cl-producer',false,64,false,1000,'mov',true,true,'ebx',1,true,true);
runtime(false,'cl-producer',false,64,false,1000,'mov',true,true,'ebx',1,true);
runtime(false,'cl-producer',false,64,false,1000,'mov',true,true,'ebx',2);
runtime(false,'cl-producer',false,64,false,1000,'mov',true,true);
runtime(false,'cl-producer',true,64,false,1000,'mov',true,true);
runtime(true,'cl-producer',false,64,false,1000,'mov',true,true);
{
    let fail = true;
    const rotating = createRotatingBreakpoint({set: () => {}, unset: () => {if(fail) throw Error('synthetic');}});
    rotating.arm(0); assert(rotating.owns(0)); assert(!rotating.stop().ok); assert(rotating.owned());
    fail = false; assert(rotating.stop().ok); assert(!rotating.owned());
}
process.stdout.write('CHAIN RUNTIME DOUBLES PASS: timeout, follow-error, coverage, owned cleanup\n');
