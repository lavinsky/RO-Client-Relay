"""Exclusive-client, bounded Stalker observation of a verified load/store chain.

Captured values stay in a private artifact. Stdout reports readiness/counts only.
Does not inject actions or touch another investigation's resources.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
from datetime import datetime, timezone
sys.dont_write_bytecode = True
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from research.cipher.core import json_bytes, open_regular, parse_json, private_directory, private_write, require
from research.cipher.inspect_client import bounded


def close_owned(script, session, call, needs_stop=True, phase=lambda name: None):
    """Never unload/detach while the owned Stalker remains unconfirmed."""
    state = {'ok': True}
    if script is not None:
        if needs_stop:
            for _ in range(3):
                try:
                    phase('stop_rpc')
                    state = call(lambda: script.exports_sync.stop())
                except Exception:
                    state = {'ok': False}
                if state.get('ok'):
                    break
        if not state.get('ok'):
            return False
        try:
            phase('script_unload')
            call(script.unload)
        except Exception:
            return False
    if session is not None:
        try:
            phase('session_detach')
            call(session.detach)
        except Exception:
            return False
    return True


def bounded_artifact(result, limit=262144):
    """Invalidate an oversized capture instead of truncating a successful occurrence."""
    require(1024 <= limit <= 262144, 'invalid artifact byte limit')
    if len(json_bytes(result)) <= limit:
        return result
    return {'configuration': {key: result['configuration'][key] for key in ('window_ms', 'event_cap', 'bytes_cap')},
            'build': result.get('build'), 'cleanup_confirmed': result['cleanup_confirmed'],
            'capture_invalid_reason': 'byte_limit', 'discarded_events': len(result.get('events', [])),
            'events': [{'tag': 'DONE', 'reason': 'byte_limit', 'cleanup': {'ok': result['cleanup_confirmed']},
                        'counts': dict(visits=0, discontinuities=0, unselected_chains=0, read_errors=0),
                        'occurrence': None}]}


def cl_source_options(source, digest, relocate=False):
    """Separate a historical code-relative selector from reusable runtime data."""
    require(isinstance(source,dict) and isinstance(source.get('context'),dict),'invalid CL reference')
    require(type(source.get('source_address')) is int and type(source['context'].get('frame')) is int,
            'invalid CL reference address')
    if relocate:
        require(source['source_address']-source['context']['frame']==0x36,'unsupported relative CL source')
        return {'cl_source_relative':dict(register='ebp',offset=0x36,historical_reference_only=True,
                    source_session_reused=False,source_digest=digest)}
    require(isinstance(source.get('source_mapping'),dict),'missing CL reference mapping')
    return {'cl_watch':dict(address=source['source_address'],mapping=source['source_mapping'],source_digest=digest)}


def select_pop_candidate(end, rva):
    """Historical observations select code only, never runtime operands."""
    require(type(rva) is int and 0 <= rva < 32*1024*1024, 'invalid POP selector')
    rows = end.get('cl_writer_observations')
    require(isinstance(rows, list) and len(rows) <= 256, 'missing bounded writer list')
    matches = []
    for row in rows:
        candidates = row.get('candidates', [])
        if len(candidates) != 1:
            continue
        code = candidates[0]
        if code.get('rva') == rva:
            require(code.get('instruction') in ('pop dword ptr [edx]', 'pop dword ptr [ebx]',
                    'pop dword ptr [ecx]', 'pop dword ptr [esi]', 'pop dword ptr [edi]',
                    'pop dword ptr [eax]'), 'unsupported POP destination')
            matches.append(row)
    require(len(matches) >= 1, 'POP selector absent or ambiguous decode')
    # Repeated executions are allowed only if they identify identical code edges.
    edges = {(r['candidates'][0]['pc'], r['pc_after'], r['candidates'][0]['instruction']) for r in matches}
    require(len(edges) == 1, 'conflicting POP code edges')
    return matches[-1]


def upstream_pop_reference(reference, rva):
    """Derive a code selector and frame offset from an audited source read."""
    from research.cipher.chain_audit import audit_chain
    audit=audit_chain(reference)
    require(audit.get('source_lineage',{}).get('conclusion')=='BYTE_WRITER_BEFORE_SOURCE_READ_OBSERVED',
            'missing audited upstream source read')
    end=next(e for e in reference['events'] if e.get('tag')=='DONE')
    selected=select_pop_candidate(dict(cl_writer_observations=end['cl_source_writer_observations']),rva)
    decoded=selected['candidates'][0]
    next_rva=rva+int(selected['pc_after'],16)-int(decoded['pc'],16)
    require(rva<next_rva<=rva+15,'invalid upstream POP edge')
    offset=end['cl_source_watch']['offset']
    require(type(offset) is int and 0<=offset<=1024,'invalid upstream frame offset')
    return dict(rva=rva,next_rva=next_rva,instruction=decoded['instruction'],
                destination_register=decoded['instruction'][len('pop dword ptr ['):-1]),offset


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--exclusive-confirmed', action='store_true', required=True)
    parser.add_argument('--window-ms', type=int, default=500)
    parser.add_argument('--event-cap', type=int, default=1000)
    parser.add_argument('--start-delay-ms', type=int, default=0)
    parser.add_argument('--selection', choices=('movement-header', 'any-chain'), default='movement-header')
    parser.add_argument('--mechanism', choices=('stalker', 'breakpoint', 'writer', 'producer', 'operand', 'load', 'byte-writer', 'byte-producer', 'cl-origin', 'cl-writer', 'cl-transform', 'cl-producer'), default='stalker')
    parser.add_argument('--arm-timeout-ms', type=int, default=10000)
    parser.add_argument('--source-capture', type=Path)
    parser.add_argument('--producer-capture', type=Path)
    parser.add_argument('--operand-capture', type=Path)
    parser.add_argument('--load-capture', type=Path)
    parser.add_argument('--value-capture', type=Path)
    parser.add_argument('--byte-producer-capture', type=Path)
    parser.add_argument('--inspect-only', action='store_true', help='code metadata only; do not arm instrumentation')
    parser.add_argument('--inspect-cl-origin', action='store_true', help='inspect bounded candidate predecessors of the CL store')
    parser.add_argument('--cl-code-anchor-rva', type=lambda v: int(v, 0), default=0x1c752b)
    parser.add_argument('--cl-code-input', type=Path, action='append', default=[])
    parser.add_argument('--cl-source-capture', type=Path)
    parser.add_argument('--cl-writer-capture', type=Path, help='same-instance watchpoint evidence for a candidate XOR')
    parser.add_argument('--cl-write-cap', type=int, default=64, help='CL writer limit; increases require a confirmed live scope')
    parser.add_argument('--cl-relocate-source', action='store_true', help='CL producer only: historical code reference; resolve EDX=EBP+0x36 on the current hit')
    parser.add_argument('--announce-armed', action='store_true', help='emit ARMED after start RPC, for a separate bounded input controller')
    parser.add_argument('--cl-stack-prefix-capture', type=Path, help='confirmed POP capture with bounded PUSH/POP candidate code graph')
    parser.add_argument('--cl-producer-rva', type=lambda v: int(v, 0), help='select an earlier observed POP as code reference')
    parser.add_argument('--cl-producer-hit', type=int, default=1, help='bounded matching occurrence selector, not a protocol invariant')
    parser.add_argument('--cl-producer-repeat', action='store_true', help='retain repeated POP/prefix observations until the independent CL breakpoint')
    parser.add_argument('--cl-lineage-capture', type=Path, help='proven stack transport supplying a code-relative source offset; no old runtime data reused')
    parser.add_argument('--cl-upstream-reference', type=Path, help='audited source-writer capture for a standalone upstream POP proof')
    parser.add_argument('--cl-upstream-rva', type=lambda v:int(v,0))
    parser.add_argument('--cl-extra-source-reference', type=Path, help='watch the missing frame byte selected by a hypothetical slice; use CL after the primary-source prefix')
    parser.add_argument('--producer-only', action='store_true', help='stop after verifying the byte writer, without pairing a later read')
    args = parser.parse_args(argv)
    require(1 <= args.window_ms <= 500 and 5 <= args.event_cap <= 1000, 'invalid collection limits')
    require(0 <= args.start_delay_ms <= 5000, 'invalid preparation delay')
    require(1 <= args.arm_timeout_ms <= 10000, 'invalid arming timeout')
    require(args.mechanism == 'stalker' or args.selection == 'any-chain', 'breakpoint requires one-shot selection')
    require(1 <= args.cl_write_cap <= 256 and (args.cl_write_cap == 64 or args.mechanism in ('cl-writer','cl-transform','cl-producer')),
            'invalid CL writer cap')
    require(not args.producer_only or args.mechanism == 'byte-producer', 'producer-only requires byte-producer mechanism')
    require(not args.inspect_cl_origin or args.inspect_only, 'CL code inspection requires inspect-only')
    require(not args.cl_relocate_source or args.mechanism=='cl-producer','relative source requires cl-producer')
    require(args.cl_producer_rva is None or (args.mechanism=='cl-producer' and args.cl_relocate_source),
            'earlier POP requires relative selection')
    require(1 <= args.cl_producer_hit <= 32 and (args.cl_producer_hit==1 or args.cl_relocate_source), 'invalid producer hit selector')
    require(not args.cl_producer_repeat or args.cl_producer_rva is not None,
            'repeat requires explicit producer RVA')
    require(args.cl_lineage_capture is None or (args.cl_producer_repeat and args.cl_stack_prefix_capture is not None),
            'source lineage requires repeated prefix observation')
    require(args.cl_extra_source_reference is None or (args.cl_lineage_capture is not None and args.cl_producer_repeat),
            'extra source requires repeated prefix and primary source')
    require((args.cl_upstream_reference is None)==(args.cl_upstream_rva is None),'upstream reference and RVA must be paired')
    require(args.cl_upstream_reference is None or (args.cl_relocate_source and args.cl_producer_rva is not None and
            not args.cl_producer_repeat and args.cl_producer_hit==1),
            'standalone upstream POP requires relative selection without repeated prefix')
    require(args.cl_stack_prefix_capture is None or (args.mechanism=='cl-producer' and args.cl_relocate_source),
            'stack prefix requires current-hit CL producer selection')
    require(0x1c752b - 64 <= args.cl_code_anchor_rva <= 0x1c752b, 'CL code anchor outside bounded region')
    out = private_directory(args.out)
    with open_regular(args.inventory) as inventory:
        raw = inventory.read(65537)
    require(len(raw) <= 65536, 'inventory size limit')
    info = parse_json(raw)
    require(info.get('exclusive_confirmed_by_user') is True and info.get('target_count') == 1 and
            len(info.get('targets', [])) == 1 and len(info.get('gadget_ports', [])) == 1,
            'exclusive target not established')
    pid, port = info['targets'][0], info['gadget_ports'][0]
    proc = Path('/proc') / str(pid)
    require((proc / 'comm').read_text().strip().lower() == 'uaro.exe', 'target changed')
    if info.get('target_starttime_ticks') is not None:
        require(int((proc/'stat').read_text().rsplit(')',1)[1].split()[19])==info['target_starttime_ticks'],
                'target process lifetime changed')
    for name in ('uaRO.exe', 'gepard.dll'):
        module = info['modules'][name]
        with open_regular(proc / 'root' / module['path'].lstrip('/')) as handle:
            require(hashlib.file_digest(handle, 'sha256').hexdigest() == module['sha256'], 'module changed')
    import frida
    manager = frida.get_device_manager()
    address = '127.0.0.1:' + str(port)
    session = script = None
    events = []
    ready, finished = threading.Event(), threading.Event()
    stopping = threading.Event()
    config = dict(pid=pid, window_ms=args.window_ms, event_cap=args.event_cap, bytes_cap=262144,
                  start_delay_ms=args.start_delay_ms, selection=args.selection,
                  mechanism=args.mechanism, arm_timeout_ms=args.arm_timeout_ms, inspect_only=args.inspect_only,
                  inspect_cl_origin=args.inspect_cl_origin,
                  cl_code_anchor_rva=args.cl_code_anchor_rva,
                  producer_only=args.producer_only)
    config['process_starttime_ticks']=info.get('target_starttime_ticks')
    if args.mechanism in ('cl-origin', 'cl-writer', 'cl-transform', 'cl-producer'):
        require(1 <= len(args.cl_code_input) <= 4, 'CL origin requires bounded code evidence')
        nodes, digests = {}, []
        for code_path in args.cl_code_input:
            with open_regular(code_path) as handle:
                code_raw = handle.read(262145)
            require(len(code_raw) <= 262144, 'CL evidence size limit')
            code = parse_json(code_raw)
            require(code.get('cleanup_confirmed') is True and code.get('build') ==
                    {k: v['sha256'] for k, v in info['modules'].items()}, 'CL code provenance mismatch')
            require(args.cl_relocate_source or code.get('configuration', {}).get('pid') == pid, 'CL code from a different process')
            readies = [e for e in code.get('events', []) if e.get('tag') == 'READY']
            require(len(readies) == 1 and isinstance(readies[0].get('cl_origin_code'), dict), 'missing CL code graph')
            graph = readies[0]['cl_origin_code']
            require(graph.get('code_only') is True and graph.get('executed_path_proven') is False and
                    isinstance(graph.get('nodes'),list) and len(graph['nodes']) <= 32, 'invalid bounded CL graph')
            for node in graph['nodes']:
                require(isinstance(node, dict) and type(node.get('rva')) is int and
                        type(node.get('next_rva')) is int and isinstance(node.get('instruction'), str) and
                        isinstance(node.get('mnemonic'),str) and bool(node['instruction'].split()) and
                        node['instruction'].split()[0] == node['mnemonic'], 'invalid CL code node')
                old = nodes.get(node['rva'])
                require(old is None or (old['instruction'], old['next_rva']) == (node['instruction'], node['next_rva']),
                        'conflicting CL code snapshots')
                nodes[node['rva']] = node
            digests.append(hashlib.sha256(code_raw).hexdigest())
        current, path = 0x1c7502, []
        while current < 0x1c752b and len(path) < 16:
            node = nodes.get(current)
            require(node is not None and current < node['next_rva'] <= 0x1c752b and
                    not node.get('mnemonic', '').startswith(('j', 'call', 'ret')), 'incomplete or branching CL path')
            path.append(dict(rva=current, next_rva=node['next_rva'], instruction=node['instruction']))
            current = node['next_rva']
        require(current == 0x1c752b and len(path) == 11 and
                path[0]['instruction'] == 'mov ecx, dword ptr [ecx]', 'unsupported CL candidate path')
        require([i for i,n in enumerate(path) if n['instruction'] == 'mov esi, dword ptr [esi]'] == [9],
                'CL destination pointer load not identified')
        config['cl_path'] = path
        config['cl_code_digests'] = digests
        if args.mechanism in ('cl-writer', 'cl-transform', 'cl-producer'):
            require(args.cl_source_capture is not None, 'CL writer requires an observed source')
            with open_regular(args.cl_source_capture) as handle:
                source_raw = handle.read(262145)
            require(len(source_raw) <= 262144, 'CL source capture size limit')
            source_capture = parse_json(source_raw)
            require(source_capture.get('cleanup_confirmed') is True and source_capture.get('build') ==
                    {k:v['sha256'] for k,v in info['modules'].items()} and
                    (args.cl_relocate_source or source_capture.get('configuration',{}).get('pid') == pid), 'CL source provenance mismatch')
            endings = [e for e in source_capture.get('events',[]) if e.get('tag') == 'DONE']
            require(len(endings) == 1 and endings[0].get('cleanup',{}).get('ok') is True, 'CL source cleanup unconfirmed')
            require(endings[0].get('reason') == 'cl_origin_observed' and
                    endings[0].get('counts',{}).get('visits') == 13, 'CL source capture incomplete')
            from research.cipher.chain_audit import audit_cl_origin
            source = endings[0].get('cl_origin')
            require(audit_cl_origin(source,endings[0].get('path'))['conclusion'] == 'CL_LOAD_AND_STORE_CONFIRMED',
                    'CL source path not confirmed')
            provenance_watch = dict(address=source['source_address'], mapping=source['source_mapping'],
                                    source_digest=hashlib.sha256(source_raw).hexdigest())
            config.update(cl_source_options(source,provenance_watch['source_digest'],args.cl_relocate_source))
            config['write_cap'] = args.cl_write_cap
            if args.mechanism in ('cl-transform','cl-producer'):
                require(args.cl_writer_capture is not None, 'CL transformation requires writer evidence')
                with open_regular(args.cl_writer_capture) as handle:
                    writer_raw = handle.read(262145)
                require(len(writer_raw) <= 262144, 'CL writer evidence size limit')
                writer_capture = parse_json(writer_raw)
                require(writer_capture.get('cleanup_confirmed') is True and
                        writer_capture.get('build') == source_capture['build'] and
                        writer_capture.get('configuration', {}).get('pid') == source_capture.get('configuration',{}).get('pid') and
                        writer_capture.get('configuration', {}).get('cl_watch') == provenance_watch,
                        'CL writer provenance mismatch')
                ends = [e for e in writer_capture.get('events', []) if e.get('tag') == 'DONE']
                require(len(ends) == 1 and ends[0].get('cleanup', {}).get('ok') is True, 'CL writer cleanup missing')
                if args.mechanism == 'cl-transform':
                    require(ends[0].get('reason') == 'unattributed_exception', 'missing bounded XOR candidate')
                    candidate = ends[0].get('unattributed_exception')
                    require(isinstance(candidate, dict), 'missing CL writer exception')
                    decodes = candidate.get('predecessor_decodes')
                    instruction = 'xor dword ptr [ecx], edx'
                else:
                    require(ends[0].get('reason') == 'cl_origin_observed' and
                            audit_cl_origin(ends[0].get('cl_origin'),ends[0].get('path'))['conclusion'] == 'CL_LOAD_AND_STORE_CONFIRMED',
                            'CL writer consumer not confirmed')
                    candidate = ends[0].get('cl_preceding_write')
                    require(isinstance(candidate,dict) and candidate.get('byte_after') == (ends[0]['cl_origin']['source_sample']&255) and
                            ends[0]['cl_origin']['source_address']==source['source_address'], 'CL writer association missing')
                    decodes = candidate.get('candidates')
                    instruction = 'pop dword ptr [edx]'
                    if args.cl_producer_rva is not None:
                        candidate = select_pop_candidate(ends[0], args.cl_producer_rva)
                        decodes = candidate['candidates']
                        instruction = decodes[0]['instruction']
                require(isinstance(decodes, list) and len(decodes) == 1 and isinstance(decodes[0],dict) and
                        decodes[0].get('instruction') == instruction, 'unsupported or ambiguous CL writer candidate')
                if args.cl_relocate_source:
                    rva=decodes[0].get('rva')
                    require(type(rva) is int and rva==(args.cl_producer_rva if args.cl_producer_rva is not None else 0x1c70dc),
                            'unexpected relative CL producer anchor')
                    next_rva=rva+int(candidate['pc_after'],16)-int(decodes[0]['pc'],16)
                else:
                    base = min(int(r['range'].split('-')[0], 16) for r in info['modules']['gepard.dll']['ranges'])
                    rva, next_rva = int(decodes[0]['pc'], 16)-base, int(candidate['pc_after'], 16)-base
                require(0 <= rva < next_rva < 32*1024*1024 and next_rva-rva <= 15, 'XOR candidate outside image')
                config['cl_transform' if args.mechanism=='cl-transform' else 'cl_producer'] = dict(
                    rva=rva, next_rva=next_rva, instruction=instruction,evidence_digest=hashlib.sha256(writer_raw).hexdigest())
                if args.mechanism=='cl-producer':
                    config['cl_producer']['destination_register'] = instruction[len('pop dword ptr ['):-1]
                    config['cl_producer_track_intervening'] = args.cl_producer_rva is not None
                    config['cl_producer_hit'] = args.cl_producer_hit
                    config['cl_producer_repeat'] = args.cl_producer_repeat
                if args.cl_upstream_reference is not None:
                    with open_regular(args.cl_upstream_reference) as handle:upstream_raw=handle.read(262145)
                    require(len(upstream_raw)<=262144,'upstream reference size limit')
                    upstream=parse_json(upstream_raw)
                    require(upstream.get('build')=={k:v['sha256'] for k,v in info['modules'].items()},'upstream build mismatch')
                    operation,offset=upstream_pop_reference(upstream,args.cl_upstream_rva)
                    digest=hashlib.sha256(upstream_raw).hexdigest()
                    operation['evidence_digest']=digest
                    config['cl_producer']=operation
                    config['cl_source_relative']=dict(register='ebp',offset=offset,historical_reference_only=True,
                        source_session_reused=False,source_digest=digest,upstream_operand_reference=True)
                    config['cl_upstream_only']=True
                    config['cl_producer_track_intervening']=False
                    rva,next_rva,instruction=operation['rva'],operation['next_rva'],operation['instruction']
                if args.cl_stack_prefix_capture is not None:
                    with open_regular(args.cl_stack_prefix_capture) as handle:prefix_raw=handle.read(262145)
                    require(len(prefix_raw)<=262144,'CL prefix evidence size limit')
                    reference=parse_json(prefix_raw)
                    require(reference.get('cleanup_confirmed') is True and reference.get('build')==source_capture['build'],
                            'CL prefix provenance mismatch')
                    from research.cipher.chain_audit import audit_chain
                    prefix_audit=audit_chain(reference)
                    require(prefix_audit.get('cl_producer',{}).get('conclusion')=='POP_COPY_CONFIRMED' and
                            (args.cl_upstream_reference is not None or prefix_audit.get('cl_origin',{}).get('conclusion')=='CL_LOAD_AND_STORE_CONFIRMED'),
                            'CL prefix requires observed POP and consumer; causal linkage is separate')
                    readies=[e for e in reference.get('events',[]) if e.get('tag')=='READY']
                    require(len(readies)==1 and isinstance(readies[0].get('producer_code'),dict),'CL prefix graph missing')
                    graph=readies[0]['producer_code']
                    require(graph.get('code_only') is True and graph.get('executed_path_proven') is False and
                            isinstance(graph.get('nodes'),list) and len(graph['nodes'])<=32,'invalid CL prefix graph')
                    destination=instruction[len('pop dword ptr ['):-1]
                    starts=[n for n in graph['nodes'] if n.get('rva')==rva-6 and
                            n.get('instruction','').startswith('push dword ptr [')]
                    require(len(starts)==1, 'missing or ambiguous first PUSH')
                    source_register=starts[0]['instruction'][len('push dword ptr ['):-1]
                    require(source_register in ('eax','ebx','ecx','edx','esi','edi'), 'unsupported prefix source')
                    chosen=[]
                    for point,text in [(rva-6,f'push dword ptr [{source_register}]'),(rva-4,f'push dword ptr [{destination}]'),
                                       (rva-2,f'pop dword ptr [{source_register}]')]:
                        matches=[n for n in graph['nodes'] if isinstance(n,dict) and n.get('rva')==point and
                                 n.get('instruction')==text and n.get('next_rva')==point+2]
                        require(len(matches)==1,'missing or ambiguous CL prefix candidate')
                        chosen.append(dict(rva=point,next_rva=point+2,instruction=text))
                    config['cl_stack_prefix']=chosen
                    config['cl_stack_source_register']=source_register
                    config['cl_stack_prefix_digest']=hashlib.sha256(prefix_raw).hexdigest()
                    if args.cl_lineage_capture is not None:
                        with open_regular(args.cl_lineage_capture) as handle:lineage_raw=handle.read(262145)
                        require(len(lineage_raw)<=262144,'lineage reference too large')
                        lineage=parse_json(lineage_raw)
                        require(lineage.get('build')==source_capture['build'],'lineage build mismatch')
                        la=audit_chain(lineage)
                        require(la.get('cl_stack_source',{}).get('conclusion')=='STACK_MEMORY_TRANSPORT_CONFIRMED' and
                                la.get('cl_producer',{}).get('byte_preserved_through_observed_writes') is True,
                                'lineage requires observed transport and byte preservation')
                        ls=next(e for e in lineage['events'] if e.get('tag')=='DONE')['cl_stack_source']
                        offset=ls['source_address']-ls['context']['frame']
                        require(0<=offset<=1024 and abs(offset-0x36)>=4,'unsupported source offset or overlapping targets')
                        config['cl_lineage_source']=dict(register='ebp',offset=offset,
                            reference_digest=hashlib.sha256(lineage_raw).hexdigest(),runtime_reused=False)
                        if args.cl_extra_source_reference is not None:
                            with open_regular(args.cl_extra_source_reference) as handle:extra_raw=handle.read(262145)
                            require(len(extra_raw)<=262144,'extra source reference size limit')
                            extra=parse_json(extra_raw)
                            require(extra.get('build')==source_capture['build'],'extra source build mismatch')
                            from research.cipher.candidate_slice import candidate_slice
                            plan=candidate_slice(extra)
                            require(plan.get('stop') in ('FIRST_POP_NOT_OBSERVED','SOURCE_NOT_WATCHED'), 'slice does not identify a missing source')
                            extra_offset=plan.get('next_offset')
                            require(type(extra_offset) is int and 0<=extra_offset<=1024 and
                                    all(abs(extra_offset-existing)>=4 for existing in (0x36,offset)), 'invalid or overlapping extra source')
                            config['cl_extra_source']=dict(register='ebp',offset=extra_offset,runtime_reused=False,
                                reference_digest=hashlib.sha256(extra_raw).hexdigest(),selection='HYPOTHESIS')
    if args.mechanism in ('writer', 'producer', 'operand', 'load', 'byte-writer', 'byte-producer'):
        require(args.source_capture is not None, 'writer requires a proven source capture')
        with open_regular(args.source_capture) as handle:
            source_raw = handle.read(262145)
        require(len(source_raw) <= 262144, 'source capture size limit')
        previous = parse_json(source_raw)
        from research.cipher.chain_audit import audit_chain
        require(audit_chain(previous)['chain_conclusion'] == 'COPY_CHAIN_CONFIRMED', 'source chain not confirmed')
        require(previous['build'] == {k: v['sha256'] for k, v in info['modules'].items()}, 'source build mismatch')
        end = next(e for e in previous['events'] if e.get('tag') == 'DONE')
        row = end['occurrence']
        require(row.get('source_shares_sp_mapping') is False, 'source may be on stack')
        config['source_watch'] = dict(address=row['source_address'], frame=row['context']['frame'],
                                     mapping=row['source_mapping'], source_digest=hashlib.sha256(source_raw).hexdigest())
        config['write_cap'] = 64
        if args.mechanism in ('producer', 'operand', 'load', 'byte-writer', 'byte-producer'):
            require(args.producer_capture is not None, 'producer requires a writer capture')
            with open_regular(args.producer_capture) as handle:
                writer_raw = handle.read(262145)
            require(len(writer_raw) <= 262144, 'writer capture size limit')
            writer_previous = parse_json(writer_raw)
            require(audit_chain(writer_previous)['chain_conclusion'] == 'COPY_CHAIN_CONFIRMED', 'writer chain not confirmed')
            require(writer_previous['build'] == previous['build'], 'writer build mismatch')
            writer_end = next(e for e in writer_previous['events'] if e.get('tag') == 'DONE')
            writer_row = writer_end['occurrence']
            require(writer_row['source_address'] == row['source_address'], 'writer source mismatch')
            writer = writer_row['preceding_write']
            require(len(writer['candidates']) == 1, 'ambiguous producer candidate')
            candidate = writer['candidates'][0]
            require(candidate['instruction'] == 'mov dword ptr [ebx], ecx', 'unsupported producer instruction')
            module_base = min(int(r['range'].split('-')[0], 16) for r in info['modules']['gepard.dll']['ranges'])
            rva, next_rva = int(candidate['pc'], 16) - module_base, int(writer['pc_after'], 16) - module_base
            require(0 <= rva < next_rva < 32 * 1024 * 1024, 'producer outside bounded image')
            config['producer'] = dict(rva=rva, next_rva=next_rva, instruction=candidate['instruction'],
                                      source_digest=hashlib.sha256(writer_raw).hexdigest())
            if args.mechanism in ('operand', 'load', 'byte-writer', 'byte-producer'):
                require(args.operand_capture is not None, 'operand requires candidate code evidence')
                with open_regular(args.operand_capture) as handle:
                    code_raw = handle.read(262145)
                require(len(code_raw) <= 262144, 'operand code size limit')
                code = parse_json(code_raw)
                require(code.get('cleanup_confirmed') is True and code.get('build') == previous['build'], 'operand provenance mismatch')
                ready_code = [e['producer_code'] for e in code['events'] if e.get('tag') == 'READY']
                require(len(ready_code) == 1, 'ambiguous operand metadata')
                choices = [c for c in ready_code[0]['steps'][0] if c.get('instruction') == 'movzx ecx, al']
                require(len(choices) == 1, 'operand candidate missing or ambiguous')
                input_rva = int(choices[0]['rva'], 16)
                require(0 <= input_rva < rva and rva - input_rva <= 15, 'operand outside producer boundary')
                config['producer']['input_rva'] = input_rva
                config['producer']['operand_digest'] = hashlib.sha256(code_raw).hexdigest()
                if args.mechanism in ('load', 'byte-writer', 'byte-producer'):
                    require(args.load_capture is not None, 'load requires bounded predecessor evidence')
                    with open_regular(args.load_capture) as handle:
                        load_raw = handle.read(262145)
                    require(len(load_raw) <= 262144, 'load code size limit')
                    load_code = parse_json(load_raw)
                    require(load_code.get('cleanup_confirmed') is True and load_code.get('build') == previous['build'], 'load provenance mismatch')
                    graph = next(e for e in load_code['events'] if e.get('tag') == 'READY')['producer_code']['predecessor_graph']
                    starts = [n for n in graph if n.get('instruction') == 'mov al, byte ptr [eax]']
                    require(len(starts) == 1, 'missing or ambiguous byte load')
                    nodes = {n['rva']: n for n in graph}
                    current, path = starts[0]['rva'], []
                    allowed = {'mov al, byte ptr [eax]', 'mov esi, 0', 'movzx ebx, bx',
                               'mov esi, 1', 'mov edi, 0x400', 'add ebx, ebp'}
                    while current < input_rva and len(path) < 8:
                        node = nodes.get(current)
                        require(node is not None and node['instruction'] in allowed and
                                current < node['next_rva'] <= input_rva, 'unsupported load path')
                        path.append(node); current = node['next_rva']
                    require(current == input_rva and len(path) == 6, 'incomplete load path')
                    config['load_path'] = path
                    config['load_digest'] = hashlib.sha256(load_raw).hexdigest()
                    if args.mechanism in ('byte-writer', 'byte-producer'):
                        require(args.value_capture is not None, 'byte writer requires observed byte source')
                        with open_regular(args.value_capture) as handle:
                            value_raw = handle.read(262145)
                        require(len(value_raw) <= 262144, 'value capture size limit')
                        value_capture = parse_json(value_raw)
                        require(audit_chain(value_capture)['chain_conclusion'] == 'COPY_CHAIN_CONFIRMED' and
                                value_capture['build'] == previous['build'], 'value capture provenance mismatch')
                        value_row = next(e for e in value_capture['events'] if e.get('tag') == 'DONE')['occurrence']
                        value = value_row['value_load']
                        require(value.get('load_matches') is True and value.get('context_matches') is True and
                                value.get('eax_stable_after_load') is True and value_row.get('loaded_source_byte_equals_store') is True,
                                'byte source path not confirmed')
                        config['value_watch'] = dict(address=value['source_address'], mapping=value['mapping'],
                                                     source_digest=hashlib.sha256(value_raw).hexdigest())
                        if args.mechanism == 'byte-producer':
                            require(args.byte_producer_capture is not None, 'byte producer requires a writer observation')
                            with open_regular(args.byte_producer_capture) as handle:
                                byte_raw = handle.read(262145)
                            require(len(byte_raw) <= 262144, 'byte producer capture size limit')
                            byte_capture = parse_json(byte_raw)
                            require(audit_chain(byte_capture)['chain_conclusion'] == 'COPY_CHAIN_CONFIRMED' and
                                    byte_capture.get('build') == previous['build'], 'byte producer provenance mismatch')
                            byte_row = next(e for e in byte_capture['events'] if e.get('tag') == 'DONE')['occurrence']
                            require(byte_row['value_load']['source_address'] == value['source_address'] and
                                    byte_row.get('value_matches_preceding_write') is True, 'byte writer source mismatch')
                            byte_writer = byte_row['value_preceding_write']
                            require(len(byte_writer['candidates']) == 1, 'ambiguous byte writer')
                            byte_candidate = byte_writer['candidates'][0]
                            require(byte_candidate['instruction'] == 'mov byte ptr [esi], cl', 'unsupported byte producer')
                            rva_byte = int(byte_candidate['pc'], 16) - module_base
                            next_byte = int(byte_writer['pc_after'], 16) - module_base
                            require(0 <= rva_byte < next_byte < 32 * 1024 * 1024, 'byte producer outside image')
                            config['byte_producer'] = dict(rva=rva_byte, next_rva=next_byte,
                                                          source_digest=hashlib.sha256(byte_raw).hexdigest())
    created_utc = datetime.now(timezone.utc).isoformat()
    revision = {'head': 'unknown', 'scope_diff_sha256': 'unknown'}
    try:
        repo = Path(__file__).resolve().parents[2]
        revision['head'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'],cwd=repo,timeout=2).decode().strip()
        diff = subprocess.check_output(['git', 'diff', '--no-ext-diff', '--no-textconv', '--',
            'research/cipher/chain_capture.py','research/cipher/chain_probe.js','research/cipher/chain_audit.py'],
            cwd=repo,timeout=2)
        revision['scope_diff_sha256'] = hashlib.sha256(diff).hexdigest()
    except (OSError,subprocess.SubprocessError):
        pass
    probe_source = Path(__file__).with_name('chain_probe.js').read_bytes()
    tool_hashes = {'chain_probe.js': hashlib.sha256(probe_source).hexdigest(),
                   'chain_capture.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    source = probe_source.decode('utf8').replace('__CONFIG__', json.dumps(config))
    byte_limit_reached = False
    driver_phase='setup'
    def set_phase(name):
        nonlocal driver_phase
        driver_phase=name
    def message(msg, data):
        nonlocal byte_limit_reached
        if msg.get('type') == 'send' and isinstance(msg.get('payload'), dict):
            value = msg['payload']
            if len(json_bytes(events + [value])) > config['bytes_cap']:
                byte_limit_reached = True
                stopping.set(); finished.set(); return
            events.append(value)
            if value.get('tag') == 'READY':
                ready.set()
            if value.get('tag') == 'DONE':
                finished.set()
        else:
            # Keep a bounded private diagnostic, without stack or binary payload.
            events.append({'tag': 'SCRIPT_ERROR', 'description': str(msg.get('description', ''))[:512],
                'file_name':str(msg.get('fileName',''))[:128],
                'line_number':msg.get('lineNumber') if type(msg.get('lineNumber')) is int else None,
                'column_number':msg.get('columnNumber') if type(msg.get('columnNumber')) is int else None})
            events[-1]['javascript_stack'] = str(msg.get('stack', ''))[:2048]
            events[-1]['driver_phase'] = driver_phase
            finished.set()
    def interrupt(*unused):
        stopping.set(); finished.set()
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    cleaned = False
    attempted_start = False
    try:
        device = bounded(frida, lambda: manager.add_remote_device(address))
        session = bounded(frida, lambda: device.attach('Gadget'))
        script = bounded(frida, lambda: session.create_script(source))
        private_write(out,'probe-source.js',source.encode())
        script.on('message', message)
        bounded(frida, script.load)
        require(ready.wait(1) and not finished.is_set(), 'probe not ready')
        print('READY', flush=True)
        if stopping.wait(args.start_delay_ms / 1000):
            raise InterruptedError('cancelled before start')
        if args.inspect_only:
            events.append({'tag': 'DONE', 'reason': 'code_only', 'cleanup': {'ok': True},
                           'counts': dict(visits=0, discontinuities=0, unselected_chains=0, read_errors=0),
                           'occurrence': None})
        else:
            attempted_start = True
            start_result=bounded(frida, lambda: script.exports_sync.start())
            if args.announce_armed:
                require(isinstance(start_result,dict) and start_result.get('started') is True,'probe start not acknowledged')
                print('ARMED',flush=True)
            set_phase('collecting')
            finished.wait(args.arm_timeout_ms / 1000 + 1 if args.mechanism != 'stalker' else 2)
    finally:
        auto_stop_confirmed=any(e.get('tag')=='DONE' and e.get('cleanup',{}).get('ok') is True for e in events)
        rpc_stop_required=attempted_start and not auto_stop_confirmed
        if script is not None or session is not None:
            cleaned = close_owned(script, session, lambda operation: bounded(frida, operation), rpc_stop_required, set_phase)
        if cleaned:
            bounded(frida, lambda: manager.remove_remote_device(address))
        result = {'events': events, 'cleanup_confirmed': cleaned, 'configuration': config,
                  'created_utc': created_utc, 'finished_utc': datetime.now(timezone.utc).isoformat(),
                  'tools_sha256': tool_hashes, 'loaded_script_sha256': hashlib.sha256(source.encode()).hexdigest(),
                  'repository_revision':revision,
                  'rpc_stop_required':rpc_stop_required,'automatic_stop_confirmed':auto_stop_confirmed,
                  'build': {k: v['sha256'] for k, v in info['modules'].items()},
                  'exclusivity': 'user confirmed; no inference from driver absence'}
        if byte_limit_reached:
            result['events'] = [{'tag': 'DONE', 'reason': 'byte_limit', 'cleanup': {'ok': cleaned},
                                 'counts': dict(visits=0, discontinuities=0, unselected_chains=0, read_errors=0),
                                 'occurrence': None}]
        result = bounded_artifact(result)
        private_write(out, 'chain-capture.json', json_bytes(result))
        if not cleaned:
            # No explicit unload/detach after an unconfirmed stop, and no next round.
            # The artifact reports failure; do not claim resource cleanup from exit.
            print('CLEANUP_PENDING', flush=True)
    end = next((v for v in result['events'] if v.get('tag') == 'DONE'), {})
    print(json.dumps({'reason': end.get('reason'), 'counts': end.get('counts'),
                      'matched': end.get('occurrence') is not None,
                      'cl_origin_complete': (end.get('cl_origin') or {}).get('complete'),
                      'script_errors':sum(e.get('tag')=='SCRIPT_ERROR' for e in result['events']),
                      'cleanup_confirmed': cleaned}), flush=True)
    return 0 if cleaned and end and not any(e.get('tag')=='SCRIPT_ERROR' for e in result['events']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
