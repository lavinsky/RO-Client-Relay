"""Validate a load/store observation without exporting its values or calling it a cipher."""
from .core import require


def uint(value, maximum=(1 << 32) - 1):
    require(type(value) is int and 0 <= value <= maximum, 'invalid chain integer')
    return value


def audit_chain(container):
    require(isinstance(container, dict), 'invalid chain container')
    config = container.get('configuration')
    require(isinstance(config, dict), 'invalid chain configuration')
    require(1 <= uint(config.get('window_ms')) <= 500, 'invalid chain window')
    require(5 <= uint(config.get('event_cap')) <= 1000, 'invalid chain event cap')
    require(0 < uint(config.get('bytes_cap')) <= 262144, 'invalid chain byte cap')
    events = container.get('events')
    require(isinstance(events, list) and all(isinstance(e, dict) for e in events), 'invalid chain events')
    endings = [e for e in events if e.get('tag') == 'DONE']
    require(len(endings) == 1, 'missing or ambiguous chain ending')
    end = endings[0]
    counts = end.get('counts')
    require(isinstance(counts, dict), 'missing chain counters')
    for key in ('visits', 'discontinuities', 'unselected_chains', 'read_errors'):
        uint(counts.get(key))
    cleanup = end.get('cleanup')
    require(isinstance(cleanup, dict) and type(cleanup.get('ok')) is bool and
            type(container.get('cleanup_confirmed')) is bool, 'invalid chain cleanup metadata')
    clean = container['cleanup_confirmed'] and cleanup['ok']
    limited = end.get('reason') in ('event_limit', 'write_limit', 'byte_limit') or counts['visits'] >= config['event_cap']
    result = {'observed_site_visits': counts['visits'],
              'complete_unretained_chains': counts['unselected_chains'],
              'cleanup_confirmed': clean, 'capture_limit_reached': limited,
              'retained_chain': False, 'chain_conclusion': 'NO_RETAINED_OCCURRENCE',
              'cipher_conclusion': 'NOT_TESTED', 'direction': 'unknown', 'session': 'unknown',
              'missing': ['producer write', 'proven transformation input/output',
                          'consumed cipher state', 'state transition', 'cipher initialization']}
    writer_counts = end.get('writer_counts')
    if writer_counts is not None:
        require(isinstance(writer_counts, dict), 'invalid writer counters')
        result['writer_counts'] = {k: uint(writer_counts.get(k)) for k in ('traps', 'writes', 'ignored_loads')}
        result['unpaired_value_reads'] = uint(end.get('value_source_unpaired_reads', 0))
        limited = limited or writer_counts['traps'] >= config['event_cap']
        result['capture_limit_reached'] = limited
    partial = end.get('partial_observations')
    if partial is not None:
        require(isinstance(partial, dict), 'invalid partial observations')
        if partial.get('byte_producer') is not None:
            result['independent_byte_writer'] = _byte_writer(partial['byte_producer'], clean and not limited)
    if end.get('cl_transformation') is not None:
        result['cl_transformation'] = audit_cl_transformation(end['cl_transformation'], clean and not limited)
    if end.get('cl_producer') is not None:
        result['cl_producer'] = audit_cl_producer(end['cl_producer'], clean and not limited)
    if end.get('cl_origin') is not None:
        result['cl_origin'] = audit_cl_origin(end['cl_origin'], end.get('path'), clean and not limited)
        require(end['cl_origin']['context']['thread'] == uint(end.get('thread_id')), 'conflicting CL thread')
        preceding = end.get('cl_preceding_write')
        if preceding is not None:
            require(isinstance(preceding, dict), 'invalid CL preceding write')
            for key in ('order','thread','frame','byte_after'):
                uint(preceding.get(key),255 if key == 'byte_after' else (1 << 32)-1)
            result['cl_writer'] = {'byte_matches_loaded_low_byte': preceding['byte_after'] == (end['cl_origin']['source_sample'] & 255),
                'same_thread':preceding['thread'] == end['cl_origin']['context']['thread'],
                'same_frame':preceding['frame'] == end['cl_origin']['context']['frame'],
                'predecessor_execution_proven':preceding.get('predecessor_execution_proven') is True,
                'watched_bytes':1}
            transform = end.get('cl_transformation')
            if transform is not None and transform.get('complete') is True:
                result['cl_transformation']['linked_to_cl_load'] = (
                    result['cl_transformation']['conclusion'] == 'XOR_WRITE_CONFIRMED' and
                    result['cl_origin']['conclusion'] == 'CL_LOAD_AND_STORE_CONFIRMED' and
                    preceding['order'] == transform['write_order'] and
                    uint(transform.get('load_order')) > transform['write_order'] and
                    preceding.get('predecessor_execution_proven') is True and
                    transform['context'] == end['cl_origin']['context'] and
                    end['cl_origin']['source_address'] == transform['address'] + transform['watched_offset'] and
                    preceding['byte_after'] == ((transform['after'] >> (8*transform['watched_offset'])) & 255) and
                    result['cl_writer']['same_thread'] and result['cl_writer']['same_frame'] and
                    result['cl_writer']['byte_matches_loaded_low_byte'])
            producer=end.get('cl_producer')
            if producer is not None and producer.get('complete') is True:
                result['cl_producer']['linked_to_cl_load']=(
                    result['cl_producer']['conclusion']=='POP_COPY_CONFIRMED' and
                    result['cl_origin']['conclusion']=='CL_LOAD_AND_STORE_CONFIRMED' and
                    preceding['order']==producer['write_order'] < uint(producer.get('load_order')) and
                    preceding.get('predecessor_execution_proven') is True and
                    end['cl_origin']['source_address']==producer['address']+producer['watched_offset'] and
                    preceding['byte_after']==((producer['after']>>(8*producer['watched_offset']))&255) and
                    producer['context']['thread']==preceding['thread'] and producer['context']['frame']==preceding['frame'] and
                    result['cl_writer']['same_thread'] and result['cl_writer']['same_frame'] and
                    result['cl_writer']['byte_matches_loaded_low_byte'])
    row = end.get('occurrence')
    if row is None:
        return result
    require(isinstance(row, dict), 'invalid chain occurrence')
    require(row.get('sites') == [0, 1, 2, 3, 4], 'missing or unordered chain sites')
    for n in row['sites']:
        uint(n)
    order = row.get('order')
    require(isinstance(order, list) and len(order) == 5, 'invalid chain ordering')
    for n in order:
        uint(n)
    require(all(b == a + 1 for a, b in zip(order, order[1:])), 'noncontiguous chain order')
    context = row.get('context')
    require(isinstance(context, dict), 'missing chain context')
    for name in ('thread', 'sp', 'frame'):
        uint(context.get(name))
    require(context['thread'] == uint(end.get('thread_id')), 'conflicting chain thread')
    for name in ('source_address', 'source_sample', 'loaded_value', 'base_ecx', 'expected_slot',
                 'pointer_slot', 'expected_destination', 'destination'):
        uint(row.get(name))
    for name in ('store_byte', 'destination_before', 'destination_after'):
        uint(row.get(name), 255)
    checks = {
        'load_matches_sample': row['loaded_value'] == row['source_sample'],
        'add_matches': row['pointer_slot'] == ((row['base_ecx'] + context['frame']) & 0xffffffff),
        'destination_matches': row['destination'] == row['expected_destination'],
        'write_matches': row['destination_after'] == (row['loaded_value'] & 255),
        'low_byte_matches': row['store_byte'] == (row['loaded_value'] & 255),
    }
    for name in ('load_matches_sample', 'pre_add_ecx_matches', 'add_matches', 'destination_matches',
                 'loaded_value_reaches_store', 'post_context_matches', 'write_matches'):
        require(type(row.get(name)) is bool, 'missing chain comparison')
        if name in checks:
            require(row[name] == checks[name], 'conflicting chain comparison')
        else:
            checks[name] = row[name]
    result.update(retained_chain=True, comparisons=checks,
                  source_shares_sp_mapping=row.get('source_shares_sp_mapping'),
                  chain_conclusion=('COPY_CHAIN_CONFIRMED' if all(checks.values()) and clean and not limited
                                    else 'INCOMPLETE_OR_MISMATCHED_CHAIN'))
    producer = row.get('producer')
    if producer is not None:
        require(isinstance(producer, dict), 'invalid producer observation')
        for key in ('before', 'after', 'input_register_value', 'destination', 'thread', 'frame', 'sp', 'write_order', 'rva'):
            uint(producer.get(key))
        copied = producer['after'] == producer['input_register_value']
        require(type(producer.get('copy_matches')) is bool and producer['copy_matches'] == copied,
                'conflicting producer copy')
        require(type(producer.get('context_matches')) is bool, 'missing producer context comparison')
        result['intermediate_writer'] = {
            'rva': hex(producer['rva']), 'copy_matches': copied,
            'context_matches': producer['context_matches'],
            'destination_is_load_source': producer['destination'] == row['source_address'],
            'written_dword_is_loaded_dword': producer['after'] == row['loaded_value'],
            'reported_last_write_before_load': row.get('producer_is_last_write_before_load') is True}
    operand = row.get('operand')
    if operand is not None:
        require(isinstance(operand, dict), 'invalid operand observation')
        for key in ('eax_before', 'low_byte_before', 'rva'):
            uint(operand.get(key))
        require(operand['low_byte_before'] == (operand['eax_before'] & 255), 'conflicting operand low byte')
        result['zero_extension'] = {'rva': hex(operand['rva']),
            'reported_match': operand.get('zero_extension_matches') is True,
            'matches_writer_input': producer is not None and producer['input_register_value'] == operand['low_byte_before']}
    load = row.get('value_load')
    if load is not None:
        require(isinstance(load, dict), 'invalid byte load observation')
        for key in ('source_address', 'eax_before', 'eax_after', 'sample_byte'):
            uint(load.get(key), 255 if key == 'sample_byte' else (1 << 32) - 1)
        loaded = load['eax_after'] == ((load['eax_before'] & 0xffffff00) | load['sample_byte'])
        require(type(load.get('load_matches')) is bool and load['load_matches'] == loaded, 'conflicting byte load')
        result['value_load'] = {'load_matches': loaded,
            'original_address_preserved': load['source_address'] == load['eax_before'],
            'reaches_operand': operand is not None and load['eax_after'] == operand['eax_before'],
            'source_byte_equals_final_store': load['sample_byte'] == row['store_byte'],
            'source_is_final_destination': load['source_address'] == row['destination'],
            'reported_context_match': load.get('context_matches') is True,
            'reported_register_stability': load.get('eax_stable_after_load') is True}
    preceding = row.get('value_preceding_write')
    if preceding is not None:
        require(isinstance(preceding, dict), 'invalid preceding byte write')
        for key in ('byte_after', 'order', 'thread', 'frame'):
            uint(preceding.get(key), 255 if key == 'byte_after' else (1 << 32) - 1)
        result['value_writer'] = {
            'byte_matches_load': load is not None and preceding['byte_after'] == load['sample_byte'],
            'same_thread': preceding['thread'] == context['thread'],
            'predecessor_execution_proven': preceding.get('predecessor_execution_proven') is True,
            'candidate_count': len(preceding.get('candidates', [])) if isinstance(preceding.get('candidates', []), list) else None}
    if row.get('byte_producer') is not None:
        result['byte_writer_in_chain'] = _byte_writer(row['byte_producer'], clean and not limited)
        result['byte_writer_in_chain']['paired_with_later_load'] = row.get('byte_producer_is_last_write_before_read') is True
    return result


def _byte_writer(raw, admissible):
    require(isinstance(raw, dict), 'invalid byte writer observation')
    for key in ('destination', 'ecx_before', 'sp', 'frame', 'thread', 'rva'):
        uint(raw.get(key))
    uint(raw.get('before'), 255)
    missing = [key for key in ('after', 'write_order', 'copy_matches', 'context_matches') if key not in raw]
    if missing:
        return {'rva': hex(raw['rva']), 'independent_copy_confirmed': False,
                'paired_with_later_load': False, 'missing': missing}
    uint(raw['after'], 255)
    uint(raw['write_order'])
    copied = raw['after'] == (raw['ecx_before'] & 255)
    require(type(raw.get('copy_matches')) is bool and raw['copy_matches'] == copied, 'conflicting byte writer copy')
    require(type(raw.get('context_matches')) is bool, 'missing byte writer context')
    return {'rva': hex(raw['rva']), 'copy_matches': copied, 'context_matches': raw['context_matches'],
            'independent_copy_confirmed': copied and raw['context_matches'] and admissible,
            'paired_with_later_load': False}


def audit_cl_producer(raw, admissible=True):
    """Confirm the POP's single stack operand and memory destination; no stack scan."""
    require(isinstance(raw,dict) and type(raw.get('complete')) is bool,'invalid CL POP observation')
    for key in ('rva','next_rva','address','before','source_address','source_sample','before_order'):uint(raw.get(key))
    uint(raw.get('watched_offset'),3)
    require(raw.get('instruction')=='pop dword ptr [edx]' and raw['rva']<raw['next_rva']<=raw['rva']+15,
            'unsupported CL POP instruction')
    require(isinstance(raw.get('context'),dict),'missing POP context')
    for key in ('thread','sp','frame'):uint(raw['context'].get(key))
    require(raw['source_address']==raw['context']['sp'],'POP operand not preserved')
    result={'conclusion':'PARTIAL_POP_OBSERVATION','operation':'pop dword ptr [edx]',
        'rva':hex(raw['rva']),'operand_bytes':4,'watched_bytes':1,'cipher_role':'UNKNOWN',
        'state_identified':False,'linked_to_cl_load':False,'other_thread_writes_observed':False}
    if not raw['complete']:
        result['missing']=['post-instruction memory','post-instruction ESP/EDX']
        return result
    for key in ('after','after_order','write_order','edx_after'):uint(raw.get(key))
    require(isinstance(raw.get('post_context'),dict),'missing POP post-context')
    for key in ('thread','sp','frame'):uint(raw['post_context'].get(key))
    require(raw['before_order']<raw['after_order']==raw['write_order'],'unordered POP observation')
    copied=raw['after']==raw['source_sample']
    context=(raw['post_context']['thread']==raw['context']['thread'] and raw['post_context']['frame']==raw['context']['frame'] and
             raw['post_context']['sp']==((raw['context']['sp']+4)&0xffffffff) and raw['edx_after']==raw['address'])
    require(type(raw.get('copy_matches')) is bool and raw['copy_matches']==copied and
            type(raw.get('post_context_matches')) is bool and raw['post_context_matches']==context,'conflicting POP comparison')
    result.update(copy_matches=copied,context_matches=context,
        conclusion='POP_COPY_CONFIRMED' if admissible and copied and context else 'POP_UNVERIFIED')
    return result


def audit_cl_transformation(raw, admissible=True):
    """A proven local XOR is not automatically packet encryption or cipher state."""
    require(isinstance(raw, dict) and type(raw.get('complete')) is bool, 'invalid CL transformation')
    for key in ('rva', 'next_rva', 'address', 'before', 'operand_edx', 'before_order'):
        uint(raw.get(key))
    require(raw['rva'] < raw['next_rva'] <= raw['rva']+15 and
            raw.get('instruction') == 'xor dword ptr [ecx], edx', 'unsupported CL operation')
    uint(raw.get('watched_offset'),3)
    require(isinstance(raw.get('context'),dict), 'missing CL operation context')
    for key in ('thread','sp','frame'):uint(raw['context'].get(key))
    result = {'conclusion':'PARTIAL_XOR_OBSERVATION','operation':'xor dword ptr [ecx], edx',
              'rva':hex(raw['rva']),'operand_bytes':4,'watched_bytes':1,
              'cipher_role':'UNKNOWN','state_identified':False,'linked_to_cl_load':False,
              'other_thread_writes_observed':False}
    if not raw['complete']:
        result['missing']=['post-instruction operand','executed post-instruction point']
        return result
    for key in ('after','after_order','write_order'):uint(raw.get(key))
    require(raw['before_order'] < raw['after_order'] == raw['write_order'], 'unordered XOR observation')
    expected=raw['after']==(raw['before']^raw['operand_edx'])
    require(type(raw.get('xor_matches')) is bool and raw['xor_matches']==expected and
            type(raw.get('post_context_matches')) is bool, 'conflicting XOR comparison')
    result.update(xor_matches=expected,context_matches=raw['post_context_matches'],
                  conclusion='XOR_WRITE_CONFIRMED' if admissible and expected and raw['post_context_matches'] else 'XOR_UNVERIFIED')
    return result


def audit_cl_origin(raw, path, admissible=True):
    """Recompute the observed ECX load/CL store without exporting captured values."""
    require(isinstance(raw, dict) and isinstance(path, list) and len(path) == 13, 'invalid CL origin/path')
    for node in path:
        require(isinstance(node, dict), 'invalid CL path node')
        uint(node.get('rva'))
    for i,node in enumerate(path[:-1]):
        require(uint(node.get('next_rva')) == path[i+1]['rva'] and node['rva'] < node['next_rva'], 'noncontiguous CL code path')
    require(path[0].get('instruction') == 'mov ecx, dword ptr [ecx]' and
            path[11].get('instruction') == 'mov byte ptr [esi], cl', 'unsupported CL endpoints')
    sites, values = raw.get('sites'), raw.get('ecx_values')
    require(isinstance(sites, list) and isinstance(values, list) and len(sites) == len(values) <= 13,
            'invalid CL visits')
    for site, value in zip(sites, values):
        uint(site); uint(value)
    require(sites == list(range(len(sites))), 'unordered CL visits')
    require(type(raw.get('complete')) is bool and isinstance(raw.get('context'), dict), 'invalid CL completeness/context')
    for key in ('thread', 'sp', 'frame'):
        uint(raw['context'].get(key))
    for key in ('source_address', 'source_sample'):
        uint(raw.get(key))
    require(bool(values) and values[0] == raw['source_address'], 'original ECX address not preserved')
    result = {'conclusion': 'PARTIAL_CL_PATH', 'observed_sites': len(sites), 'cipher_role': 'UNKNOWN',
              'definition_rva': hex(path[0]['rva']), 'store_rva': hex(path[11]['rva']),
              'state_identified': False, 'session': 'unknown', 'direction': 'unknown'}
    if not raw['complete']:
        result['missing'] = ['remaining executed sites', 'completed CL store']
        return result
    require(len(sites) == 13, 'incomplete CL path marked complete')
    for key in ('loaded_value', 'pointer_slot', 'pointer_sample', 'pointer_loaded', 'destination'):
        uint(raw.get(key))
    for key in ('store_byte', 'destination_before', 'destination_after'):
        uint(raw.get(key), 255)
    comparisons = {
        'load_matches': raw['source_sample'] == raw['loaded_value'] == values[1],
        'ecx_stable': all(v == raw['loaded_value'] for v in values[1:]),
        'pointer_load_matches': raw['pointer_loaded'] == raw['pointer_sample'],
        'destination_matches': raw['destination'] == raw['pointer_loaded'],
        'store_matches': raw['destination_after'] == raw['store_byte'] == (raw['loaded_value'] & 255),
    }
    for key, expected in comparisons.items():
        require(type(raw.get(key)) is bool and raw[key] == expected, 'conflicting CL comparison')
    for key in ('context_matches', 'post_destination_matches'):
        require(type(raw.get(key)) is bool, 'missing CL context comparison')
        comparisons[key] = raw[key]
    result.update(comparisons=comparisons,
                  conclusion='CL_LOAD_AND_STORE_CONFIRMED' if admissible and all(comparisons.values()) else 'CL_PATH_UNVERIFIED',
                  operation='dword load followed by low-byte copy')
    return result
