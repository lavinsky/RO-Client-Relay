"""Offline discovery of stable client entry points from PE/MSVC metadata."""
import re

from .pe_static import PEImage, class_vtables, relative_call_present, vtables_for_rtti_name


SENDMSG_RTTI = re.compile(rb'\.\?AV[^\x00]{1,220}SendMsg@CGameMode@@[^\x00]*')


def _first_ret_imm(image, start_va, imm, max_span=0x200000):
    section = image.section_for_va(start_va)
    start = image.va_to_offset(start_va)
    if section is None or start is None:
        return None
    section_end = section.raw_offset + section.raw_size
    end = min(section_end, start + max_span)
    needle = bytes((0xC2, imm & 0xFF, (imm >> 8) & 0xFF))
    hit = image.data.find(needle, start, end)
    return image.offset_to_va(hit) if hit >= 0 else None


def _sendmsg_lambda_vtables(image):
    names = []
    vtables = set()
    for match in SENDMSG_RTTI.finditer(image.data):
        name = match.group(0)
        if name in names:
            continue
        names.append(name)
        for vtable, _methods in vtables_for_rtti_name(image, name):
            vtables.add(vtable)
    return names, sorted(vtables)


def discover_gamemode_sendmsg(executable):
    """Locate CGameMode::SendMsg without executing the client.

    Evidence is deliberately redundant: MSVC RTTI identifies CGameMode, the
    candidate occupies the same virtual slot as CMode, SendMsg-specific lambda
    vtables are referenced inside its body, and the x86 epilogue pops five
    stack arguments (ret 0x14).
    """
    image = executable if isinstance(executable, PEImage) else PEImage(executable)
    game_tables = class_vtables(image, 'CGameMode')
    base_tables = class_vtables(image, 'CMode')
    lambda_names, lambda_vtables = _sendmsg_lambda_vtables(image)

    if not game_tables:
        raise ValueError('CGameMode RTTI/vtable not found')
    if not base_tables:
        raise ValueError('CMode RTTI/vtable not found')
    if not lambda_names or not lambda_vtables:
        raise ValueError('CGameMode::SendMsg lambda RTTI/vtables not found')

    lambda_refs = []
    for vtable in lambda_vtables:
        lambda_refs.extend(
            va for off in image.refs_to_va(vtable)
            if (va := image.offset_to_va(off)) is not None
        )

    candidates = []
    for game_vtable, game_methods in game_tables:
        for slot, start_va in enumerate(game_methods):
            end_ret = _first_ret_imm(image, start_va, 0x14)
            if end_ret is None:
                continue
            end_va = end_ret + 3
            refs = sorted(va for va in lambda_refs if start_va <= va < end_va)
            base_method = None
            base_call = False
            for _base_vtable, base_methods in base_tables:
                if slot < len(base_methods):
                    base_method = base_methods[slot]
                    if relative_call_present(image, start_va, end_va, base_method):
                        base_call = True
                        break
            score = len(refs) * 10 + (20 if base_call else 0)
            candidates.append({
                'va': start_va,
                'rva': start_va - image.image_base,
                'vtable': game_vtable,
                'vslot': slot,
                'end_va': end_va,
                'stack_args': 5,
                'lambda_refs': refs,
                'lambda_ref_count': len(refs),
                'base_virtual': base_method,
                'base_call_present': base_call,
                'score': score,
            })

    if not candidates:
        raise ValueError('no CGameMode virtual method matched ret 0x14')
    best = max(candidates, key=lambda item: item['score'])
    if best['lambda_ref_count'] < 4:
        raise ValueError('best CGameMode candidate lacks enough SendMsg-lambda evidence')

    checks = {
        'cgamemode_rtti': True,
        'cmode_rtti': True,
        'sendmsg_lambda_rtti': len(lambda_names),
        'sendmsg_lambda_vtables': len(lambda_vtables),
        'same_virtual_slot_as_cmode': best['base_virtual'] is not None,
        'base_virtual_call_in_body': best['base_call_present'],
        'ret_0x14': True,
        'lambda_refs_in_body': best['lambda_ref_count'],
    }
    confidence = 'very-high' if best['base_call_present'] and best['lambda_ref_count'] >= 8 else 'high'
    return {
        'image_base': image.image_base,
        'game_mode': {
            'vtable': best['vtable'],
            'send_msg_va': best['va'],
            'send_msg_rva': best['rva'],
            'send_msg_vslot': best['vslot'],
            'stack_args': best['stack_args'],
            'function_end_va': best['end_va'],
        },
        'evidence': checks,
        'confidence': confidence,
    }
