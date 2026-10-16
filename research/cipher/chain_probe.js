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

function inspectPredecessorGraph(io, anchor) {
    const queue = [anchor], seen = new Set(), nodes = [], began = io.now();
    let attempts = 0;
    while (queue.length && nodes.length < 32 && io.now() - began < 200) {
        const target = queue.shift();
        if (seen.has(target)) continue;
        seen.add(target);
        for (let size = 1; size <= 15 && nodes.length < 32 && io.now() - began < 200; size++) {
            const rva = target - size;
            if (anchor - rva > 64 || (io.lowerBound !== undefined && rva < io.lowerBound)) continue;
            attempts++;
            try {
                const candidate = io.parse(rva);
                if (candidate.next_rva !== target) continue;
                nodes.push(candidate);
                if (!/^(j|call|ret)/.test(candidate.mnemonic)) queue.push(rva);
            } catch (_) {}
        }
    }
    return {anchor_rva: anchor, nodes, attempts, limit_reached: queue.length > 0,
        executed_path_proven: false, code_only: true};
}

function createClMachine(io, config) {
    let record = null, done = false;
    const counts = {visits: 0, discontinuities: 0, read_errors: 0, unselected_chains: 0};
    function stop(reason) {done = true; io.stop(reason);}
    function observe(site, c) {
        if (done) return;
        if (++counts.visits >= config.event_cap) {stop('event_limit'); return;}
        try {
            if (site === 0) {
                record = {context: {thread: c.thread, sp: c.sp, frame: c.frame}, source_address: c.ecx,
                    source_sample: io.read32(c.ecx), source_mapping: io.mapping(c.ecx),
                    sites: [], ecx_values: [], context_matches: true, ecx_stable: true, complete: false};
            }
            if (record === null || site !== record.sites.length || c.thread !== record.context.thread ||
                    c.sp !== record.context.sp || c.frame !== record.context.frame) {
                counts.discontinuities++; stop('cl_discontinuity'); return;
            }
            record.sites.push(site); record.ecx_values.push(c.ecx);
            if (site === 1) {
                record.loaded_value = c.ecx;
                record.load_matches = c.ecx === record.source_sample;
            }
            if (site > 1) record.ecx_stable = record.ecx_stable && c.ecx === record.loaded_value;
            if (site === 9) {
                record.pointer_slot = c.esi;
                record.pointer_sample = io.read32(c.esi);
            }
            if (site === 10) {
                record.pointer_loaded = c.esi;
                record.pointer_load_matches = c.esi === record.pointer_sample;
            }
            if (site === 11) {
                record.destination = c.esi; record.store_byte = c.ecx & 255;
                record.destination_before = io.read8(c.esi);
                record.destination_matches = c.esi === record.pointer_loaded;
            }
            if (site === 12) {
                record.destination_after = io.read8(record.destination);
                record.store_matches = record.destination_after === record.store_byte;
                record.post_destination_matches = c.esi === record.destination;
                record.complete = true; stop('cl_origin_observed');
            }
        } catch (_) {counts.read_errors++; stop('cl_read_error');}
    }
    return {observe, counts, current: () => record, stopped: () => done, stop: () => {done = true;}};
}

function runClOrigin(config) {
    if (Process.id !== config.pid || Process.arch !== 'ia32') throw new Error('target mismatch');
    const thread = Process.enumerateThreads().find(t => t.id === Process.id);
    if (!thread || typeof thread.setHardwareBreakpoint !== 'function' ||
            typeof thread.unsetHardwareBreakpoint !== 'function') throw new Error('CL thread/API unavailable');
    let base = null;
    Process.enumerateRanges({protection: '---', coalesce: false}).forEach(r => {
        if (r.file && /\/gepard\.dll$/i.test(r.file.path) && (base === null || r.base.compare(base) < 0)) base = r.base;
    });
    if (base === null || !Array.isArray(config.cl_path) || config.cl_path.length !== 11) throw new Error('CL module/path unavailable');
    const path = config.cl_path.slice();
    const store = base.add(0x1c752b), storeIns = Instruction.parse(store);
    if (storeIns.toString() !== 'mov byte ptr [esi], cl') throw new Error('CL store changed');
    path.push({rva: 0x1c752b, next_rva: parseInt(storeIns.next.sub(base).toString(), 16), instruction: storeIns.toString()});
    path.push({rva: path[11].next_rva, instruction: 'post-store observation'});
    const sites = {};
    path.forEach((node, index) => {
        const pc = base.add(node.rva), range = Process.findRangeByAddress(pc), ins = Instruction.parse(pc);
        if (!range || range.protection.indexOf('x') < 0 ||
                (index < 12 && (ins.toString() !== node.instruction || !ins.next.equals(base.add(node.next_rva)) ||
                    /^(j|call|ret)/.test(ins.mnemonic))))
            throw new Error('CL instruction/path mismatch');
        if (index < 12 && node.next_rva !== path[index + 1].rva) throw new Error('CL path is not contiguous');
        sites[pc.toString()] = index;
    });
    function checked(address, size) {
        const p = ptr(address), range = Process.findRangeByAddress(p);
        if (!range || !range.protection.includes('r') || p.add(size).compare(range.base.add(range.size)) > 0)
            throw new Error('CL read bound');
        return p;
    }
    const transformMode = config.mechanism === 'cl-transform';
    const producerMode = config.mechanism === 'cl-producer';
    const operationMode = transformMode || producerMode;
    const operation = transformMode ? config.cl_transform : config.cl_producer;
    const watchMode = config.mechanism === 'cl-writer' || operationMode;
    const stackRanges = [];
    let producerCode = null;
    if (operationMode) {
        const spec = operation, pc = base.add(spec.rva), ins = Instruction.parse(pc);
        const range = Process.findRangeByAddress(pc);
        if (base.readU16() !== 0x5a4d) throw new Error('CL module DOS header changed');
        const peOffset=base.add(0x3c).readU32();
        if (peOffset>1048576 || base.add(peOffset).readU32()!==0x4550 ||
                base.add(peOffset+24).readU16()!==0x10b) throw new Error('CL module PE header changed');
        const imageSize=base.add(peOffset+80).readU32();
        if (imageSize<=0 || imageSize>32*1024*1024 || spec.rva<0 || spec.next_rva>=imageSize)
            throw new Error('CL XOR outside PE image');
        if (!range || !range.protection.includes('x') ||
                (range.file && !/\/gepard\.dll$/i.test(range.file.path)) ||
                ins.toString() !== (producerMode ? 'pop dword ptr [edx]' : 'xor dword ptr [ecx], edx') ||
                !ins.next.equals(base.add(spec.next_rva)))
            throw new Error('CL XOR candidate changed');
        sites[pc.toString()] = -2; sites[ins.next.toString()] = -1;
        if (producerMode) producerCode=inspectPredecessorGraph({now:()=>Date.now(),parse:rva=>{
            const p=base.add(rva),r=Process.findRangeByAddress(p);
            if(!r || !r.protection.includes('x'))throw new Error('producer code not executable');
            const i=Instruction.parse(p);return {rva,next_rva:parseInt(i.next.sub(base).toString(),16),
                mnemonic:i.mnemonic,instruction:i.toString()};
        }},spec.rva);
    }
    if (watchMode) {
        if (typeof thread.setHardwareWatchpoint !== 'function' || typeof thread.unsetHardwareWatchpoint !== 'function')
            throw new Error('CL watchpoint API unavailable');
        const r = Process.findRangeByAddress(ptr(config.cl_watch.address)), old = config.cl_watch.mapping;
        if (!r || !r.protection.includes('w') || r.base.toString() !== old.base || r.size !== old.size ||
                r.protection !== old.protection || !!r.file !== old.file_backed) throw new Error('CL source mapping changed');
        Process.enumerateThreads().forEach(t => {
            if (!t.context || !t.context.esp) throw new Error('CL stack context unknown');
            const stack = Process.findRangeByAddress(t.context.esp), a = ptr(config.cl_watch.address);
            if (!stack || (a.compare(stack.base) >= 0 && a.compare(stack.base.add(stack.size)) < 0))
                throw new Error('CL source may intersect stack');
            stackRanges.push(stack);
        });
    }
    let handler = false, done = false, closing = false, armedAt = null, firstHit = null, timer = null, windowTimer = null;
    let watchOwned = false, lastWrite = null, linkedWrite = null, unattributed = null, transformation = null;
    const writes = [], writerCounts = {traps: 0, writes: 0, ignored_loads: 0};
    let unpairedReads = 0;
    const rotating = createRotatingBreakpoint({set: site => thread.setHardwareBreakpoint(0,
        base.add(site === -2 ? operation.rva : site === -1 ? operation.next_rva : path[site].rva)),
        unset: () => thread.unsetHardwareBreakpoint(0)});
    function stopOwned() {
        if (watchOwned) {
            try {thread.unsetHardwareWatchpoint(1); watchOwned = false;}
            catch (_) {return {ok: false};}
        }
        const state = rotating.stop();
        if (!state.ok) return state;
        if (handler) {
            try {Process.setExceptionHandler(null); handler = false;}
            catch (_) {return {ok: false};}
        }
        return {ok: true};
    }
    function finish(reason) {
        if (done) return;
        done = true; machine.stop();
        if (timer !== null) clearTimeout(timer);
        if (windowTimer !== null) clearTimeout(windowTimer);
        const cleanup = stopOwned();
        send({tag: 'DONE', reason, cleanup, counts: machine.counts, cl_origin: machine.current(),
            writer_counts: writerCounts, cl_preceding_write: linkedWrite, cl_writer_observations: writes,
            cl_reads_without_writer: unpairedReads, unattributed_exception: unattributed,
            cl_transformation: transformMode ? transformation : null, cl_producer: producerMode ? transformation : null,
            other_thread_writes_observed: false,
            occurrence: null, thread_id: thread.id, path,
            elapsed_ms: armedAt === null ? null : Date.now() - armedAt,
            chain_elapsed_ms: firstHit === null ? null : Date.now() - firstHit,
            captured_state: false, transport_observed: false});
    }
    function requestFinish(reason) {if (done || closing) return; closing = true; setImmediate(() => finish(reason));}
    const machine = createClMachine({read32: a => checked(a, 4).readU32(), read8: a => checked(a, 1).readU8(),
        mapping: a => {const r = Process.findRangeByAddress(ptr(a));
            return {base: r.base.toString(), size: r.size, protection: r.protection, file_backed: !!r.file};},
        stop: requestFinish}, config);
    rpc.exports = {
        start: () => {
            if (armedAt !== null) throw new Error('already started');
            armedAt = Date.now(); timer = setTimeout(() => finish('timeout'), config.arm_timeout_ms);
            try {
                Process.setExceptionHandler(details => {
                    const site = sites[details.context.pc.toString()];
                    if (Process.getCurrentThreadId() !== thread.id) return false;
                    const execution = details.type === 'breakpoint' && site !== undefined && rotating.owns(site);
                    if (!execution && (!watchMode || !watchOwned || !['breakpoint','single-step'].includes(details.type))) return false;
                    if (done || closing) return true;
                    try {
                        if (Date.now() - armedAt >= config.arm_timeout_ms) {requestFinish('timeout'); return true;}
                        if (firstHit !== null && Date.now()-firstHit >= config.window_ms) {requestFinish('chain_timeout');return true;}
                        writerCounts.traps++;
                        if (writerCounts.traps >= config.event_cap) {requestFinish('event_limit'); return true;}
                        if (execution && site === -2) {
                            const c = details.context, address = (producerMode ? c.edx : c.ecx).toUInt32(), watched = config.cl_watch.address;
                            if (watched < address || watched >= address + 4) {writerCounts.ignored_loads++; return true;}
                            // Expand only to the four bytes of the instruction's proven operand.
                            const operandRange = Process.findRangeByAddress(ptr(address));
                            if (!operandRange || !operandRange.protection.includes('w')) throw new Error('XOR operand not writable');
                            stackRanges.forEach(stack => {
                                if (ptr(address).compare(stack.base.add(stack.size)) < 0 &&
                                        ptr(address+4).compare(stack.base) > 0) throw new Error('XOR operand intersects stack');
                            });
                            transformation = {rva:operation.rva,next_rva:operation.next_rva,
                                instruction:operation.instruction,address,watched_offset:watched-address,
                                before:checked(address,4).readU32(),
                                context:{thread:thread.id,sp:c.esp.toUInt32(),frame:c.ebp.toUInt32()},
                                before_order:writerCounts.traps,complete:false};
                            if(producerMode) {
                                transformation.source_address=c.esp.toUInt32();
                                transformation.source_sample=checked(c.esp.toUInt32(),4).readU32();
                            } else transformation.operand_edx=c.edx.toUInt32();
                            firstHit = Date.now(); windowTimer = setTimeout(() => finish('chain_timeout'),config.window_ms);
                            if (!rotating.stop().ok) {requestFinish('cleanup_error');return true;}
                            rotating.arm(-1); return true;
                        }
                        if (execution && site === -1) {
                            const c = details.context, t = transformation;
                            if (!t) throw new Error('XOR pre-observation absent');
                            t.after = checked(t.address,4).readU32();t.after_order=writerCounts.traps;
                            t.post_context={thread:thread.id,sp:c.esp.toUInt32(),frame:c.ebp.toUInt32()};
                            t.post_context_matches=(producerMode ? c.edx.toUInt32()===t.address &&
                                c.esp.toUInt32()===((t.context.sp+4)>>>0) : c.ecx.toUInt32()===t.address &&
                                c.edx.toUInt32()===t.operand_edx && c.esp.toUInt32()===t.context.sp) &&
                                c.ebp.toUInt32()===t.context.frame;
                            if(producerMode){t.copy_matches=t.after===t.source_sample;t.edx_after=c.edx.toUInt32();}
                            else t.xor_matches=t.after===((t.before^t.operand_edx)>>>0);
                            t.complete=true;t.write_order=writerCounts.traps;
                            if (++writerCounts.writes>=config.write_cap) {requestFinish('write_limit');return true;}
                            lastWrite={order:writerCounts.traps,byte_after:(t.after>>>(8*t.watched_offset))&255,
                                thread:thread.id,frame:c.ebp.toUInt32(),pc_after:c.pc.toString(),
                                candidates:[{rva:t.rva,instruction:t.instruction,effective_address:t.address,write_width:4}],
                                predecessor_execution_proven:true};
                            writes.push(lastWrite);t.write_order=lastWrite.order;
                            if (!rotating.stop().ok) {requestFinish('cleanup_error');return true;}
                            rotating.arm(0);return true;
                        }
                        if (!execution) {
                            const c = details.context, decodes = [], candidates = [];
                            for (let size = 1; size <= 15; size++) {
                                try {
                                    const ins = Instruction.parse(c.pc.sub(size));
                                    if (!ins.next.equals(c.pc)) continue;
                                    decodes.push({pc:ins.address.toString(),instruction:ins.toString()});
                                    // Only observed writer families; reverse decoding remains a candidate.
                                    if (!['mov','pop','xor','add'].includes(ins.mnemonic) || !ins.operands ||
                                            ins.operands.length !== (ins.mnemonic === 'pop' ? 1 : 2) || ins.operands[0].type !== 'mem') continue;
                                    const op = ins.operands[0], mem = op.value;
                                    if (![1,2,4].includes(op.size) || (mem.segment && !['ds','ss'].includes(mem.segment)) ||
                                            (ins.mnemonic === 'pop' && mem.base === 'esp')) continue;
                                    const reg = name => !name || name === 'invalid' ? 0 : c[name].toUInt32();
                                    const address = (reg(mem.base) + reg(mem.index) * (mem.scale || 1) + (mem.disp || 0)) >>> 0;
                                    if (config.cl_watch.address < address || config.cl_watch.address >= address + op.size) continue;
                                    const r = Process.findRangeByAddress(ins.address);
                                    if (!r || !r.protection.includes('x')) continue;
                                    candidates.push({pc:ins.address.toString(),instruction:ins.toString(),
                                        rva:parseInt(ins.address.sub(base).toString(),16), effective_address:address,write_width:op.size});
                                } catch (_) {}
                            }
                            if (!candidates.length) {
                                unattributed = {pc_after:c.pc.toString(),exception_type:details.type,predecessor_decodes:decodes};
                                stopOwned(); requestFinish('unattributed_exception'); return true;
                            }
                            if (++writerCounts.writes >= config.write_cap) {requestFinish('write_limit'); return true;}
                            lastWrite = {order:writerCounts.traps,byte_after:checked(config.cl_watch.address,1).readU8(),
                                thread:thread.id,frame:c.ebp.toUInt32(),pc_after:c.pc.toString(),candidates,
                                predecessor_execution_proven:false};
                            writes.push(lastWrite); return true;
                        }
                        if (watchMode && site === 0) {
                            if (details.context.ecx.toUInt32() !== config.cl_watch.address) {writerCounts.ignored_loads++; return true;}
                            if (lastWrite === null) {unpairedReads++; return true;}
                            linkedWrite = lastWrite;
                            if (operationMode && (!transformation || linkedWrite.order!==transformation.write_order)) {
                                requestFinish('transform_overwritten');return true;
                            }
                            if (operationMode) transformation.load_order=writerCounts.traps;
                        }
                        if (firstHit === null) {firstHit = Date.now(); windowTimer = setTimeout(() => finish('chain_timeout'), config.window_ms);}
                        if (Date.now() - firstHit >= config.window_ms) {requestFinish('chain_timeout'); return true;}
                        const c = details.context;
                        machine.observe(site, {thread: thread.id, sp: c.esp.toUInt32(), frame: c.ebp.toUInt32(),
                            ecx: c.ecx.toUInt32(), esi: c.esi.toUInt32()});
                        if (!rotating.stop().ok) {requestFinish('cleanup_error'); return true;}
                        if (!closing) rotating.arm(site + 1);
                    } catch (_) {requestFinish('cl_probe_error');}
                    return true;
                });
                handler = true;
                if (watchMode) {watchOwned = true;thread.setHardwareWatchpoint(1,ptr(config.cl_watch.address),1,'w');}
                rotating.arm(operationMode ? -2 : 0);
            } catch (_) {finish('cl_probe_error');}
            return {started: true};
        },
        stop: () => {closing = true; machine.stop(); if (timer !== null) clearTimeout(timer);
            if (windowTimer !== null) clearTimeout(windowTimer); return stopOwned();}
    };
    send({tag: 'READY', thread_id: thread.id, path, mechanism: 'cl-origin',
        producer_code:producerCode,
        window_ms: config.window_ms, event_cap: config.event_cap, bytes_cap: config.bytes_cap});
}

function runGadget(config) {
    if (['cl-origin','cl-writer','cl-transform','cl-producer'].includes(config.mechanism)) return runClOrigin(config);
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
    let clOriginCode = null;
    if (config.inspect_cl_origin) {
        const anchor = base.add(0x1c752b), decoded = Instruction.parse(anchor);
        const range = Process.findRangeByAddress(anchor);
        if (!range || range.protection.indexOf('x') < 0 || decoded.toString() !== 'mov byte ptr [esi], cl')
            throw new Error('CL anchor changed');
        clOriginCode = inspectPredecessorGraph({now: () => Date.now(), lowerBound: 0x1c752b - 64, parse: rva => {
            const pc = base.add(rva), range = Process.findRangeByAddress(pc), ins = Instruction.parse(pc);
            if (!range || range.protection.indexOf('x') < 0) throw new Error('code bound');
            return {rva, next_rva: parseInt(ins.next.sub(base).toString(), 16),
                instruction: ins.toString(), mnemonic: ins.mnemonic, operands: ins.operands};
        }}, config.cl_code_anchor_rva || 0x1c752b);
    }
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
          cl_origin_code: clOriginCode,
          producer_code: producerCode,
          byte_producer_code: byteProducerCode,
          window_ms: config.window_ms, event_cap: config.event_cap, bytes_cap: config.bytes_cap});
}

if (typeof module !== 'undefined' && module.exports) module.exports = {createMachine, createStopper, createRotatingBreakpoint, inspectPredecessorGraph, createClMachine};
else runGadget(__CONFIG__);
