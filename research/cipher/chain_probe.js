'use strict';

// Pure state machine is exported for Node doubles. No writes to client data.
function createMachine(io, config) {
    let pending = null, sequence = 0, completed = false;
    const counts = {visits: 0, discontinuities: 0, unselected_chains: 0, read_errors: 0};
    function same(a, b) { return a.thread === b.thread && a.sp === b.sp && a.frame === b.frame; }
    function observe(site, c) {
        if (completed) return;
        counts.visits++;
        if (counts.visits >= config.event_cap) { completed = true; io.stop('event_limit'); return; }
        const order = ++sequence;
        try {
            if (site === 0) {
                pending = {stage: 0, context: {thread: c.thread, sp: c.sp, frame: c.frame},
                    base_ecx: c.ecx, source_address: c.ebx, source_sample: io.read32(c.ebx),
                    expected_slot: (c.ecx + c.frame) >>> 0, order: [order], sites: [0]};
                return;
            }
            if (pending === null || !same(pending.context, c) || site !== pending.stage + 1) {
                pending = null; counts.discontinuities++; return;
            }
            pending.order.push(order); pending.sites.push(site); pending.stage = site;
            if (site === 1) {
                pending.loaded_value = c.ebx;
                pending.load_matches_sample = c.ebx === pending.source_sample;
                pending.pre_add_ecx_matches = c.ecx === pending.base_ecx;
            } else if (site === 2) {
                pending.pointer_slot = c.ecx;
                pending.add_matches = c.ecx === pending.expected_slot;
                pending.expected_destination = io.read32(c.ecx);
            } else if (site === 3) {
                pending.destination = c.ecx;
                pending.destination_matches = c.ecx === pending.expected_destination;
                pending.loaded_value_reaches_store = c.ebx === pending.loaded_value;
                pending.store_byte = c.ebx & 255;
                pending.selected = io.selectDestination(c.ecx, c.sp);
                if (pending.selected) pending.destination_before = io.read8(c.ecx);
            } else if (site === 4) {
                if (!pending.selected) { counts.unselected_chains++; pending = null; return; }
                pending.post_context_matches = c.ecx === pending.destination && c.ebx === pending.loaded_value;
                pending.destination_after = io.read8(pending.destination);
                pending.write_matches = pending.destination_after === pending.store_byte;
                pending.source_shares_sp_mapping = io.onStack(pending.source_address, c.sp);
                completed = true;
                io.match(pending);
            }
        } catch (_) { counts.read_errors++; pending = null; }
    }
    return {observe, counts, incomplete: () => pending !== null && pending.stage < 4, stop: () => {completed = true;}};
}

function createStopper(api) {
    let owned = false;
    return {
        arm: () => { owned = true; },
        stop: () => {
            if (!owned) return {ok: true};
            try { api.unfollow(); api.flush(); owned = false; return {ok: true}; }
            catch (_) { return {ok: false}; }
        },
        owned: () => owned
    };
}

function createRotatingBreakpoint(api) {
    let owned = false, site = null;
    return {
        arm: next => {
            if (owned) throw new Error('breakpoint already owned');
            owned = true; site = next; api.set(next);
        },
        stop: () => {
            if (!owned) return {ok: true};
            try {api.unset(); owned = false; site = null; return {ok: true};}
            catch (_) {return {ok: false};}
        },
        owns: candidate => owned && site === candidate,
        owned: () => owned
    };
}

function runGadget(config) {
    if (Process.id !== config.pid || Process.arch !== 'ia32') throw new Error('target mismatch');
    const byteProducerMode = config.mechanism === 'byte-producer';
    const byteWriterMode = config.mechanism === 'byte-writer' || byteProducerMode;
    const loadMode = config.mechanism === 'load' || byteWriterMode;
    const operandMode = config.mechanism === 'operand' || loadMode;
    const producerMode = config.mechanism === 'producer' || operandMode;
    const writerMode = config.mechanism === 'writer' || producerMode;
    const breakpointMode = config.mechanism === 'breakpoint' || writerMode;
    if (!breakpointMode) ['follow', 'unfollow', 'flush'].forEach(name => {
            if (typeof Stalker[name] !== 'function') throw new Error('Stalker API unavailable');
        });
    const thread = Process.enumerateThreads().find(t => t.id === Process.id);
    if (!thread) throw new Error('main thread absent');
    if (breakpointMode && (typeof thread.setHardwareBreakpoint !== 'function' ||
            typeof thread.unsetHardwareBreakpoint !== 'function')) throw new Error('breakpoint API unavailable');
    let base = null;
    Process.enumerateRanges({protection: '---', coalesce: false}).forEach(r => {
        if (r.file && /\/gepard\.dll$/i.test(r.file.path) && (base === null || r.base.compare(base) < 0)) base = r.base;
    });
    if (base === null) throw new Error('module absent');
    const offsets = [0x18efec, 0x18efee, 0x18eff0, 0x18eff2, 0x18eff4];
    const expected = ['mov ebx, dword ptr [ebx]', 'add ecx, ebp', 'mov ecx, dword ptr [ecx]',
                      'mov byte ptr [ecx], bl', 'mov edi, ebp'];
    const sites = {}, instructions = [];
    offsets.forEach((off, i) => {
        const pc = base.add(off), range = Process.findRangeByAddress(pc), ins = Instruction.parse(pc);
        if (!range || range.protection.indexOf('x') < 0 || ins.toString() !== expected[i]) throw new Error('instruction mismatch');
        if (i < 4 && !ins.next.equals(base.add(offsets[i + 1]))) throw new Error('instruction boundary mismatch');
        sites[pc.toString()] = i; instructions.push({rva: '0x' + off.toString(16), instruction: ins.toString()});
    });
    let producerCode = null;
    let byteProducerCode = null;
    if (byteProducerMode) {
        const before = base.add(config.byte_producer.rva), after = base.add(config.byte_producer.next_rva);
        const ins = Instruction.parse(before), range = Process.findRangeByAddress(before);
        if (!range || range.protection.indexOf('x') < 0 || ins.toString() !== 'mov byte ptr [esi], cl' ||
                !ins.next.equals(after)) throw new Error('byte producer changed');
        sites[before.toString()] = -11; sites[after.toString()] = -10;
        byteProducerCode = {predecessors: [], executed_path_proven: false};
        for (let size = 1; size <= 15; size++) {
            try {
                const candidate = Instruction.parse(before.sub(size));
                const range = Process.findRangeByAddress(candidate.address);
                if (range && range.protection.indexOf('x') >= 0 && candidate.next.equals(before))
                    byteProducerCode.predecessors.push({rva: candidate.address.sub(base).toString(), instruction: candidate.toString()});
            } catch (_) {}
        }
    }
    if (producerMode) {
        const before = base.add(config.producer.rva), after = base.add(config.producer.next_rva);
        const range = Process.findRangeByAddress(before), ins = Instruction.parse(before);
        if (!range || range.protection.indexOf('x') < 0 || ins.toString() !== config.producer.instruction ||
                ins.toString() !== 'mov dword ptr [ebx], ecx' || !ins.next.equals(after)) throw new Error('producer changed');
        sites[before.toString()] = -2; sites[after.toString()] = -1;
        if (operandMode) {
            const input = base.add(config.producer.input_rva), inputIns = Instruction.parse(input);
            const inputRange = Process.findRangeByAddress(input);
            if (!inputRange || inputRange.protection.indexOf('x') < 0 || inputIns.toString() !== 'movzx ecx, al' ||
                    !inputIns.next.equals(before)) throw new Error('operand instruction changed');
            sites[input.toString()] = -3;
            if (loadMode) config.load_path.forEach((node, index) => {
                const pc = base.add(node.rva), parsed = Instruction.parse(pc), range = Process.findRangeByAddress(pc);
                if (!range || range.protection.indexOf('x') < 0 || parsed.toString() !== node.instruction ||
                        !parsed.next.equals(base.add(node.next_rva))) throw new Error('load path changed');
                sites[pc.toString()] = -3 - config.load_path.length + index;
            });
        }
        producerCode = {steps: [], end: 'depth_limit', executed_path_proven: false};
        let cursor = operandMode ? base.add(config.producer.input_rva) : before;
        for (let depth = 0; depth < 8; depth++) {
            const choices = [];
            for (let size = 1; size <= 15; size++) {
                try {
                    const candidate = Instruction.parse(cursor.sub(size));
                    const candidateRange = Process.findRangeByAddress(candidate.address);
                    if (candidateRange && candidateRange.protection.indexOf('x') >= 0 && candidate.next.equals(cursor))
                        choices.push({rva: candidate.address.sub(base).toString(), instruction: candidate.toString(), mnemonic: candidate.mnemonic});
                } catch (_) {}
            }
            producerCode.steps.push(choices);
            if (choices.length !== 1) {producerCode.end = 'ambiguous'; break;}
            if (/^(j|call|ret)/.test(choices[0].mnemonic)) {producerCode.end = 'control_transfer'; break;}
            cursor = base.add(parseInt(choices[0].rva, 16));
        }
        if (operandMode && config.inspect_only) {
            const anchor = config.producer.input_rva, queue = [anchor], visited = new Set(), graph = [];
            const codeStarted = Date.now();
            while (queue.length && graph.length < 32 && Date.now() - codeStarted < 200) {
                const target = queue.shift();
                if (visited.has(target)) continue;
                visited.add(target);
                for (let size = 1; size <= 15 && graph.length < 32; size++) {
                    if (anchor - (target - size) > 64) continue;
                    try {
                        const pc = base.add(target - size), candidate = Instruction.parse(pc);
                        const range = Process.findRangeByAddress(pc);
                        if (!range || range.protection.indexOf('x') < 0 || !candidate.next.equals(base.add(target))) continue;
                        graph.push({rva: target - size, next_rva: target, instruction: candidate.toString(),
                            registers_written: candidate.regsWritten || []});
                        if (!/^(j|call|ret)/.test(candidate.mnemonic)) queue.push(target - size);
                    } catch (_) {}
                }
            }
            producerCode.predecessor_graph = graph;
            producerCode.graph_limit_reached = queue.length > 0;
            producerCode.graph_warning = 'Alternative decodes only; no executed edges established.';
        }
    }
    function readable(address, length) {
        const p = ptr(address), range = Process.findRangeByAddress(p);
        if (!range || range.protection.indexOf('r') < 0 || p.add(length).compare(range.base.add(range.size)) > 0) throw new Error('read bound');
        return p;
    }
    function onStack(address, sp) {
        const range = Process.findRangeByAddress(ptr(sp)), p = ptr(address);
        return range !== null && p.compare(range.base) >= 0 && p.add(4).compare(range.base.add(range.size)) <= 0;
    }
    const watched = byteWriterMode ? config.value_watch : config.source_watch;
    if (writerMode) {
        if (typeof thread.setHardwareWatchpoint !== 'function' ||
                typeof thread.unsetHardwareWatchpoint !== 'function') throw new Error('watchpoint API unavailable');
        const address = ptr(watched.address), range = Process.findRangeByAddress(address);
        const prior = watched.mapping;
        if (!range || range.base.toString() !== prior.base || range.size !== prior.size ||
                range.protection !== prior.protection || !!range.file !== prior.file_backed ||
                range.protection.indexOf('w') < 0) throw new Error('source mapping changed');
        Process.enumerateThreads().forEach(t => {
            if (!t.context || !t.context.esp) throw new Error('unknown thread stack');
            if (onStack(watched.address, t.context.esp.toUInt32())) throw new Error('source intersects stack mapping');
        });
    }
    let done = false, closing = false, timer = null, chainTimer = null, started = 0, last = null;
    let firstHit = null, handlerInstalled = false;
    let watchOwned = false, latestWrite = null, linkedWrite = null;
    let producer = null;
    let operand = null;
    let valueLoad = null;
    let latestValueWrite = null, linkedValueWrite = null, firstUnpairedRead = null;
    let unpairedReads = 0;
    let byteProducer = null;
    let unattributed = null;
    const writes = [], writerCounts = {traps: 0, writes: 0, ignored_loads: 0};
    const coverage = {translated_blocks: 0, translated_instructions: 0,
        chain_sites_translated: 0, first_block_entered: false};
    const rotating = createRotatingBreakpoint({
        set: site => thread.setHardwareBreakpoint(0, base.add(site === -11 ? config.byte_producer.rva :
            site === -10 ? config.byte_producer.next_rva : site < -3 ? config.load_path[site + 3 + config.load_path.length].rva :
            site === -3 ? config.producer.input_rva : site === -2 ? config.producer.rva :
            site === -1 ? config.producer.next_rva : offsets[site])),
        unset: () => thread.unsetHardwareBreakpoint(0)
    });
    const stopper = breakpointMode ? {
        arm: () => {},
        stop: () => {
            if (watchOwned) {
                try {thread.unsetHardwareWatchpoint(1); watchOwned = false;}
                catch (_) {return {ok: false};}
            }
            const result = rotating.stop();
            if (!result.ok) return result;
            if (handlerInstalled) {
                try {Process.setExceptionHandler(null); handlerInstalled = false;}
                catch (_) {return {ok: false};}
            }
            return {ok: true};
        }
    } : createStopper({unfollow: () => Stalker.unfollow(thread.id), flush: () => Stalker.flush()});
    function finish(reason) {
        if (done) return;
        done = true; if (timer !== null) clearTimeout(timer);
        if (chainTimer !== null) clearTimeout(chainTimer); machine.stop();
        const cleanup = stopper.stop();
        send({tag: 'DONE', reason, cleanup, elapsed_ms: Date.now() - started,
              counts: machine.counts, coverage, incomplete_occurrence: machine.incomplete(), occurrence: last,
              mechanism: breakpointMode ? 'rotating_execution_breakpoint' : 'stalker',
              chain_elapsed_ms: firstHit === null ? null : Date.now() - firstHit,
              writer_counts: writerCounts, writer_observations: writes,
              unattributed_exception: unattributed,
              value_source_unpaired_reads: unpairedReads, first_unpaired_value_read: firstUnpairedRead,
              partial_observations: {byte_producer: byteProducer, producer, operand, value_load: valueLoad},
              other_thread_writes_observed: false,
              thread_id: thread.id, instructions,
              packet_gate: config.selection === 'any-chain' ? null : '035f at destination-2 in current SP mapping',
              captured_state: false, transport_observed: false});
    }
    function requestFinish(reason) {
        if (done || closing) return;
        closing = true; setImmediate(() => finish(reason));
    }
    const machine = createMachine({
        read32: address => readable(address, 4).readU32(),
        read8: address => readable(address, 1).readU8(),
        onStack,
        selectDestination: (address, sp) => config.selection === 'any-chain' ||
            (onStack(address, sp) && readable(address - 2, 3).readU16() === 0x035f),
        stop: requestFinish,
        match: occurrence => {
            function mapping(address) {
                const range = Process.findRangeByAddress(ptr(address));
                return range === null ? null : {base: range.base.toString(), size: range.size,
                    protection: range.protection, file_backed: !!range.file};
            }
            occurrence.source_mapping = mapping(occurrence.source_address);
            occurrence.destination_mapping = mapping(occurrence.destination);
            if (writerMode) {
                occurrence.preceding_write = linkedWrite;
                occurrence.loaded_byte_matches_preceding_write = linkedWrite !== null &&
                    (occurrence.loaded_value & 255) === linkedWrite.byte_after;
            }
            if (producerMode) {
                occurrence.producer = producer;
                occurrence.producer_is_last_write_before_load = producer !== null && linkedWrite !== null &&
                    producer.write_order === linkedWrite.order;
            }
            if (operandMode) occurrence.operand = operand;
            if (loadMode) {
                occurrence.value_load = valueLoad;
                occurrence.loaded_source_byte_equals_store = valueLoad.sample_byte === occurrence.store_byte;
                occurrence.source_equals_final_destination = valueLoad.source_address === occurrence.destination;
            }
            if (byteWriterMode) {
                occurrence.value_preceding_write = linkedValueWrite;
                occurrence.value_matches_preceding_write = linkedValueWrite !== null &&
                    valueLoad.sample_byte === linkedValueWrite.byte_after;
            }
            if (byteProducerMode) {
                occurrence.byte_producer = byteProducer;
                occurrence.byte_producer_is_last_write_before_read = byteProducer !== null && linkedValueWrite !== null &&
                    linkedValueWrite.order === byteProducer.write_order;
            }
            last = occurrence; requestFinish('matched');
        }
    }, config);
    rpc.exports = {
        start: () => {
            if (started) throw new Error('already started');
            started = Date.now(); stopper.arm();
            timer = setTimeout(() => finish('timeout'), breakpointMode ? config.arm_timeout_ms : config.window_ms);
            try {
                if (breakpointMode) {
                    Process.setExceptionHandler(details => {
                        const site = sites[details.context.pc.toString()];
                        if (Process.getCurrentThreadId() !== thread.id) return false;
                        const ownExecution = details.type === 'breakpoint' && site !== undefined && rotating.owns(site);
                        if (!ownExecution && (!writerMode || !watchOwned ||
                                !['single-step', 'breakpoint'].includes(details.type))) return false;
                        if (done || closing) return true;
                        try {
                            if (Date.now() - started >= config.arm_timeout_ms) {requestFinish('timeout'); return true;}
                            if (writerMode) {
                                writerCounts.traps++;
                                if (writerCounts.traps >= config.event_cap) {requestFinish('event_limit'); return true;}
                            }
                            if (!ownExecution) {
                                const c = details.context, candidates = [], decodes = [];
                                for (let size = 1; size <= 15; size++) {
                                    try {
                                        const ins = Instruction.parse(c.pc.sub(size));
                                        if (!ins.next.equals(c.pc)) continue;
                                        decodes.push({pc: ins.address.toString(), instruction: ins.toString(),
                                            mnemonic: ins.mnemonic, operands: ins.operands});
                                        if (!['mov', 'pop'].includes(ins.mnemonic) || !ins.operands ||
                                                ins.operands.length !== (ins.mnemonic === 'pop' ? 1 : 2) ||
                                                ins.operands[0].type !== 'mem') continue;
                                        const op = ins.operands[0], mem = op.value;
                                        if (![1, 2, 4].includes(op.size) || (mem.segment && !['ds', 'ss'].includes(mem.segment))) continue;
                                        if (ins.mnemonic === 'pop' && mem.base === 'esp') continue;
                                        function reg(name) {
                                            if (!name || name === 'invalid') return 0;
                                            if (!c[name]) throw new Error('unknown operand register');
                                            return c[name].toUInt32();
                                        }
                                        const effective = (reg(mem.base) + reg(mem.index) * (mem.scale || 1) + (mem.disp || 0)) >>> 0;
                                        const address = watched.address;
                                        if (address < effective || address >= effective + op.size) continue;
                                        const range = Process.findRangeByAddress(ins.address);
                                        if (!range || range.protection.indexOf('x') < 0) continue;
                                        candidates.push({pc: ins.address.toString(), instruction: ins.toString(),
                                            gepard_rva: range.file && /\/gepard\.dll$/i.test(range.file.path) ? ins.address.sub(base).toString() : null,
                                            effective_address: effective, write_width: op.size,
                                            mapping: {base: range.base.toString(), size: range.size,
                                                protection: range.protection, file_backed: !!range.file}});
                                    } catch (_) {}
                                }
                                if (candidates.length === 0) {
                                    // Ownership cannot be attributed from a missing predecessor.
                                    // Stop immediately; retain no alleged writer/association.
                                    unattributed = {exception_type: details.type, pc_after: c.pc.toString(),
                                        predecessor_decodes: decodes, predecessor_execution_proven: false};
                                    stopper.stop(); requestFinish('unattributed_exception'); return true;
                                }
                                writerCounts.writes++;
                                if (writerCounts.writes >= config.write_cap) {requestFinish('write_limit'); return true;}
                                const observedWrite = {order: writerCounts.traps, byte_after: readable(watched.address, 1).readU8(),
                                    pc_after: c.pc.toString(), thread: thread.id, frame: c.ebp.toUInt32(),
                                    candidates, predecessor_execution_proven: false};
                                if (byteWriterMode) latestValueWrite = observedWrite;
                                else latestWrite = observedWrite;
                                writes.push(observedWrite);
                                return true;
                            }
                            if (writerMode && site === 0) {
                                if (details.context.ebx.toUInt32() !== config.source_watch.address || latestWrite === null) {
                                    writerCounts.ignored_loads++; return true;
                                }
                                linkedWrite = latestWrite;
                            }
                            if (byteProducerMode && site === -11) {
                                const c = details.context;
                                if (c.esi.toUInt32() !== watched.address) {writerCounts.ignored_loads++; return true;}
                                byteProducer = {rva: config.byte_producer.rva, destination: c.esi.toUInt32(),
                                    ecx_before: c.ecx.toUInt32(), sp: c.esp.toUInt32(), frame: c.ebp.toUInt32(),
                                    thread: thread.id, before: readable(watched.address, 1).readU8()};
                            }
                            if (byteProducerMode && site === -10) {
                                const c = details.context;
                                if (byteProducer === null) throw new Error('byte producer context absent');
                                byteProducer.after = readable(watched.address, 1).readU8();
                                byteProducer.copy_matches = byteProducer.after === (byteProducer.ecx_before & 255);
                                byteProducer.context_matches = c.esi.toUInt32() === byteProducer.destination &&
                                    c.ecx.toUInt32() === byteProducer.ecx_before && c.esp.toUInt32() === byteProducer.sp &&
                                    c.ebp.toUInt32() === byteProducer.frame;
                                byteProducer.write_order = writerCounts.traps;
                                latestValueWrite = {order: writerCounts.traps, byte_after: byteProducer.after,
                                    thread: thread.id, frame: c.ebp.toUInt32(), pc_after: c.pc.toString(),
                                    predecessor_execution_proven: true};
                                writes.push(latestValueWrite); writerCounts.writes++;
                                if (config.producer_only) requestFinish('byte_producer_confirmed');
                            }
                            if (loadMode && site === -3 - config.load_path.length) {
                                const c = details.context;
                                if (byteWriterMode) {
                                    if (c.eax.toUInt32() !== watched.address) {writerCounts.ignored_loads++; return true;}
                                    if (latestValueWrite === null) {
                                        unpairedReads++;
                                        if (firstUnpairedRead === null) firstUnpairedRead = {
                                            byte: readable(watched.address, 1).readU8(), thread: thread.id, frame: c.ebp.toUInt32()};
                                        return true;
                                    }
                                    linkedValueWrite = latestValueWrite;
                                }
                                if ((((c.ebx.toUInt32() & 65535) + c.ebp.toUInt32()) >>> 0) !== config.source_watch.address) {
                                    writerCounts.ignored_loads++; return true;
                                }
                                const address = c.eax.toUInt32(), range = Process.findRangeByAddress(ptr(address));
                                valueLoad = {source_address: address, sample_byte: readable(address, 1).readU8(),
                                    eax_before: address, thread: thread.id, frame: c.ebp.toUInt32(), sp: c.esp.toUInt32(),
                                    sites: [], context_matches: true, eax_stable_after_load: true,
                                    mapping: {base: range.base.toString(), size: range.size, protection: range.protection, file_backed: !!range.file}};
                            }
                            if (loadMode && site <= -3 && site >= -3 - config.load_path.length) {
                                const c = details.context;
                                if (valueLoad === null) throw new Error('byte load context absent');
                                valueLoad.sites.push(site);
                                valueLoad.context_matches = valueLoad.context_matches && valueLoad.frame === c.ebp.toUInt32() && valueLoad.sp === c.esp.toUInt32();
                                if (site === -2 - config.load_path.length) {
                                    valueLoad.eax_after = c.eax.toUInt32();
                                    valueLoad.load_matches = valueLoad.eax_after === (((valueLoad.eax_before & 0xffffff00) | valueLoad.sample_byte) >>> 0);
                                } else if (site > -2 - config.load_path.length) {
                                    valueLoad.eax_stable_after_load = valueLoad.eax_stable_after_load && valueLoad.eax_after === c.eax.toUInt32();
                                }
                            }
                            if (producerMode && site === -2) {
                                const c = details.context;
                                if (c.ebx.toUInt32() !== config.source_watch.address) {
                                    writerCounts.ignored_loads++; return true;
                                }
                                producer = {thread: thread.id, frame: c.ebp.toUInt32(), sp: c.esp.toUInt32(),
                                    destination: c.ebx.toUInt32(), input_register_value: c.ecx.toUInt32(),
                                    before: readable(config.source_watch.address, 4).readU32(),
                                    rva: config.producer.rva, next_rva: config.producer.next_rva};
                                if (operandMode) {
                                    if (operand === null) throw new Error('operand context absent');
                                    operand.zero_extension_matches = c.ecx.toUInt32() === operand.low_byte_before;
                                    operand.context_matches = c.ebx.toUInt32() === operand.destination &&
                                        c.esp.toUInt32() === operand.sp && c.ebp.toUInt32() === operand.frame &&
                                        c.eax.toUInt32() === operand.eax_before;
                                }
                            }
                            if (operandMode && site === -3) {
                                const c = details.context;
                                if (c.ebx.toUInt32() !== config.source_watch.address) {
                                    writerCounts.ignored_loads++; return true;
                                }
                                operand = {rva: config.producer.input_rva, destination: c.ebx.toUInt32(),
                                    sp: c.esp.toUInt32(), frame: c.ebp.toUInt32(), eax_before: c.eax.toUInt32(),
                                    low_byte_before: c.eax.toUInt32() & 255};
                            }
                            if (firstHit === null) {
                                firstHit = Date.now();
                                chainTimer = setTimeout(() => finish('chain_timeout'), config.window_ms);
                            }
                            if (Date.now() - firstHit >= config.window_ms) {requestFinish('chain_timeout'); return true;}
                            const c = details.context;
                            if (site >= 0) machine.observe(site, {thread: Process.getCurrentThreadId(), sp: c.esp.toUInt32(),
                                frame: c.ebp.toUInt32(), ebx: c.ebx.toUInt32(), ecx: c.ecx.toUInt32()});
                            else if (site === -1) {
                                if (producer === null) throw new Error('producer context absent');
                                producer.after = readable(producer.destination, 4).readU32();
                                producer.context_matches = c.esp.toUInt32() === producer.sp && c.ebp.toUInt32() === producer.frame &&
                                    c.ebx.toUInt32() === producer.destination && c.ecx.toUInt32() === producer.input_register_value;
                                producer.copy_matches = producer.after === producer.input_register_value;
                                producer.write_order = writerCounts.traps;
                                latestWrite = {order: writerCounts.traps, byte_after: producer.after & 255,
                                    thread: thread.id, frame: c.ebp.toUInt32(), pc_after: c.pc.toString(),
                                    predecessor_execution_proven: true};
                                if (!byteWriterMode) {writes.push(latestWrite); writerCounts.writes++;}
                            }
                            if (!rotating.stop().ok) {requestFinish('cleanup_error'); return true;}
                            if (!closing && site < 4) rotating.arm(site + 1);
                            else if (!closing) requestFinish('sequence_ended');
                        } catch (_) {requestFinish('breakpoint_error');}
                        return true;
                    });
                    handlerInstalled = true;
                    if (writerMode) {
                        watchOwned = true;
                        thread.setHardwareWatchpoint(1, ptr(watched.address), 1, 'w');
                    }
                    rotating.arm(byteProducerMode ? -11 : loadMode ? -3 - config.load_path.length : operandMode ? -3 : producerMode ? -2 : 0);
                } else Stalker.follow(thread.id, {transform: iterator => {
                    const firstBlock = coverage.translated_blocks++ === 0;
                    let firstInstruction = true;
                    let ins;
                    while ((ins = iterator.next()) !== null) {
                        coverage.translated_instructions++;
                        if (firstBlock && firstInstruction) iterator.putCallout(() => {coverage.first_block_entered = true;});
                        firstInstruction = false;
                        const site = sites[ins.address.toString()];
                        if (site !== undefined) {
                            coverage.chain_sites_translated++;
                            iterator.putCallout(context => {
                            if (done || closing) return;
                            if (Date.now() - started >= config.window_ms) { requestFinish('timeout'); return; }
                            machine.observe(site, {thread: Process.getCurrentThreadId(), sp: context.esp.toUInt32(),
                                frame: context.ebp.toUInt32(), ebx: context.ebx.toUInt32(), ecx: context.ecx.toUInt32()});
                            });
                        }
                        iterator.keep();
                    }
                }});
            } catch (_) { finish(breakpointMode ? 'breakpoint_error' : 'follow_error'); }
            return {started: true};
        },
        stop: () => { closing = true; machine.stop(); if (timer !== null) clearTimeout(timer);
            if (chainTimer !== null) clearTimeout(chainTimer); return stopper.stop(); }
    };
    send({tag: 'READY', pid: Process.id, thread_id: thread.id, instructions,
          producer_code: producerCode,
          byte_producer_code: byteProducerCode,
          window_ms: config.window_ms, event_cap: config.event_cap, bytes_cap: config.bytes_cap});
}

if (typeof module !== 'undefined' && module.exports) module.exports = {createMachine, createStopper, createRotatingBreakpoint};
else runGadget(__CONFIG__);
