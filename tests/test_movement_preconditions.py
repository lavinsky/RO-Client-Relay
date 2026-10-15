"""Testes offline do analisador de pré-condições de 0x035F (research/movement_035f/analyze.py).

Cobre (Seção 5 do prompt de investigação):
- fluxo natural com eventos suficientes (store + ACK associado);
- entrada/retorno nativos sem store e sem cobertura independente de resposta;
- resposta vista sem associação provada (ACK não vira 'associado' sem store);
- registros truncados e campos ausentes (ausência != zero/false, sem crash);
- isolamento entre sessões (arquivos distintos nunca são fundidos);
- distinção entre as DUAS interfaces 0x11 (dispatcher root11 vs wrapper 0xc7650e input11);
- preservação dos arquivos de entrada (somente leitura).

Independente da suíte da cifra: não importa _boot nem relay/. Rodar com:
    python3 tests/test_movement_preconditions.py
"""
import hashlib
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "research", "movement_035f"))
import analyze  # noqa: E402


def write_json(d, obj):
    p = os.path.join(d, f"cap-{len(os.listdir(d))}.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    return p


def done(**fields):
    ev = {"tag": "DONE"}
    ev.update(fields)
    return {"pid": fields.pop("_pid", 3124344), "gadget_port": 27053, "events": [ev]}


# ---- 1. fluxo natural: store reconhecido + ACK associado --------------------------------
natural = {"pid": 111, "gadget_port": 27053, "target_alive_after": True, "events": [
    {"tag": "READY"},
    {"tag": "DONE", "cleared": True, "matched": True, "args_match": True, "coords": [189, 357],
     "store_order": 5, "store_ms": 120,
     "root11": {"coordinate_candidates": [189, 357], "return_pc": "0x7744c251"},
     "last8a": {"code": 138, "coordinate_candidates": [189, 357], "receiver_this_is_manager": True,
                "tail_args_zero": True},
     "ack0087": {"src": [187, 356], "dst": [189, 357], "ms": 180},
     "trail": [{"site": 1, "order": 2}, {"site": 2, "order": 3}, {"site": 0, "order": 4}]}]}

with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, natural)))
    assert rec["usable"] and rec["clean_cleanup"] is True
    assert rec["channels"]["store_035f"] == "reconhecido"
    assert rec["channels"]["ack_0087"] == "associado"
    assert rec["channels"]["transporte_envio"] == analyze.UNOBS_SEND  # mesmo no caso bom
    assert rec.get("cannot_conclude_no_send") is not True
    assert rec["order_basis"] == "ordem-explicita"

# ---- 2. nativo: entrou e retornou, sem store; sem cobertura de resposta ------------------
native = {"pid": 111, "gadget_port": 27053, "target_alive_after": True, "events": [
    {"tag": "DONE", "cleared": True, "matched": False,
     "emit_state": {"attempted": True, "returned": True, "thread_ok": True},
     "last8a": {"code": 138, "coordinate_candidates": [191, 358], "receiver_this_is_manager": True,
                "tail_args_zero": True},
     "trail": [{"site": 2, "code": 120}, {"site": 1, "screen_candidates": [900, 524]}]}]}

with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, native)))
    assert rec["channels"]["store_035f"] == "nao-reconhecido"
    assert rec["channels"]["ack_0087"] == analyze.UNOBS_ACK
    assert rec["channels"]["transporte_envio"] == analyze.UNOBS_SEND
    assert rec["cannot_conclude_no_send"] is True
    assert any("NAO implica 'nao enviou'" in l for l in rec["limits"])
    # last8a preservado (entrada observada), mas não é store nem envio
    assert rec["channels"]["receptor_0x8a(last8a)"]["coordinate_candidates"] == [191, 358]
    # trilha sem 'order' em todos: ordem de arquivo, nunca por ms
    assert rec["order_basis"] == "ordem-de-arquivo"

# ---- 2b. primeiro ensaio nativo: não retornou (artefato de instrumentação) ---------------
native_bp = {"pid": 111, "gadget_port": 27053, "events": [
    {"tag": "DONE", "cleared": True, "matched": False, "error": "breakpoint triggered",
     "emit_state": {"attempted": True, "returned": False, "thread_ok": True}}]}
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, native_bp)))
    assert any("artefato de instrumentacao" in l for l in rec["limits"])

# 2c. run natural carrega emit_state default (attempted=false): limite NÃO deve disparar
natural_emitdefault = {"pid": 111, "gadget_port": 27053, "events": [
    {"tag": "DONE", "cleared": True, "matched": True, "coords": [1, 2], "ack0087": {"dst": [1, 2]},
     "emit_state": {"attempted": False, "returned": False, "thread_ok": False}}]}
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, natural_emitdefault)))
    assert not any("artefato de instrumentacao" in l for l in rec["limits"])

# ---- 3. resposta sem associação provada: ACK não vira 'associado' sem store --------------
# store reconhecido mas sem ACK -> 'nao-associado' (negativo legítimo, pois store existiu)
no_ack = {"pid": 111, "gadget_port": 27053, "events": [
    {"tag": "DONE", "cleared": True, "matched": True, "coords": [10, 20], "ack0087": None}]}
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, no_ack)))
    assert rec["channels"]["ack_0087"] == "nao-associado"
# store NÃO reconhecido -> ACK é inobservável, jamais 'associado'
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, native)))
    assert rec["channels"]["ack_0087"] == analyze.UNOBS_ACK

# ---- 4. truncado / campos ausentes: ausência != zero/false, sem crash --------------------
truncated = {"gadget_port": 27053, "events": [
    {"tag": "DONE", "cleared": False}]}  # sem matched, sem coords, sem trail, sem pid
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, truncated)))
    assert rec["usable"] is True
    assert rec["session"]["pid"] == analyze.ABSENT         # NÃO vira 0
    assert rec["decoded_dest"] == analyze.ABSENT           # NÃO vira []
    assert rec["channels"]["receptor_0x8a(last8a)"] == analyze.ABSENT
    assert rec["channels"]["store_035f"] == "nao-reconhecido"

# sem DONE nenhum -> não usável, sem inventar
no_done = {"pid": 111, "events": [{"tag": "READY"}, {"tag": "TIMEOUT"}]}
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, no_done)))
    assert rec["usable"] is False and any("sem evento DONE" in l for l in rec["limits"])

# arquivo ilegível não bloqueia o lote
with tempfile.TemporaryDirectory() as d:
    bad = os.path.join(d, "bad.json")
    with open(bad, "w") as f:
        f.write("{nao-json")
    good = write_json(d, natural)
    table = analyze.build_table([bad, good])
    assert len(table) == 2 and table[0]["usable"] is False and table[1]["usable"] is True

# ---- 5. isolamento entre sessões: mesmas coords, pids distintos, nunca fundidos ----------
sess_a = {"pid": 111, "gadget_port": 27053, "events": [
    {"tag": "DONE", "cleared": True, "matched": True, "coords": [189, 357], "ack0087": {"dst": [189, 357]}}]}
sess_b = {"pid": 222, "gadget_port": 27053, "events": [
    {"tag": "DONE", "cleared": True, "matched": True, "coords": [189, 357], "ack0087": {"dst": [189, 357]}}]}
with tempfile.TemporaryDirectory() as d:
    table = analyze.build_table([write_json(d, sess_a), write_json(d, sess_b)])
    assert len(table) == 2
    assert table[0]["session"]["pid"] == 111 and table[1]["session"]["pid"] == 222  # separados

# ---- 6. duas interfaces 0x11 permanecem distintas ----------------------------------------
both11 = {"pid": 111, "gadget_port": 27053, "events": [
    {"tag": "DONE", "cleared": True, "matched": True, "coords": [5, 6],
     "root11": {"coordinate_candidates": [5, 6], "return_pc": "0x7744c251"},
     "input11": {"screen_candidates": [900, 525], "input_state": 3, "virtual_target": "0xabc"}}]}
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, both11)))
    disp = rec["channels"]["dispatcher_0x11(root11)"]
    wrap = rec["channels"]["wrapper_0x11_0xc7650e(input11)"]
    assert disp != wrap and "coordinate_candidates" in disp and "screen_candidates" in wrap
    assert "screen_candidates" not in disp and "coordinate_candidates" not in wrap

# ---- 7. preservação dos arquivos de entrada (somente leitura) ----------------------------
with tempfile.TemporaryDirectory() as d:
    p1, p2 = write_json(d, natural), write_json(d, native)
    before = {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in (p1, p2)}
    analyze.build_table([p1, p2])
    after = {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in (p1, p2)}
    assert before == after, "o analisador alterou um arquivo de entrada"

# ---- 8. ordenação por 'order' explícito ignora 'ms' enganoso -----------------------------
misleading = {"pid": 111, "gadget_port": 27053, "events": [
    {"tag": "DONE", "cleared": True, "matched": False,
     "trail": [{"site": 0, "order": 3, "ms": 1}, {"site": 2, "order": 1, "ms": 9},
               {"site": 1, "order": 2, "ms": 5}]}]}
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, misleading)))
    assert rec["order_basis"] == "ordem-explicita"
    assert [t["order"] for t in rec["trail"]] == [1, 2, 3]   # por order, não por ms

# ---- 9. observe_path.py: canais independentes (dispatcher/receptor/store/transporte/recv) ----
def path_capture(events, pid=3124344, **done):
    ev = {"tag": "DONE", "cleared": True, "events": events, "transport_apis_seen": done.pop(
        "transport_apis_seen", {})}
    ev.update(done)
    return {"pid": pid, "gadget_port": 27053, "events": [{"tag": "READY"}, ev]}


# natural: os três observadores dispararam + transporte descoberto + recv 0087
natural_path = path_capture([
    {"site": "dispatcher_0x11", "order": 1, "coord": [189, 357], "return_region": "gepard"},
    {"site": "receptor_0x8a", "order": 2, "coord": [189, 357], "this_is_manager": True},
    {"site": "store_035f", "order": 3, "id_at_ecx_minus2": 863, "in_current_stack": True,
     "ecx_region": "uaRO", "body": {"coord": [189, 357], "dir": 0}},
    {"site": "transport", "order": 4, "api": "sendto", "fd": 40, "bytes_returned": 5,
     "ret_region": "gepard"},
    {"site": "recv_0087", "order": 5, "src": [187, 356], "dst": [189, 357]},
], transport_apis_seen={"sendto": 1})
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, natural_path)))
    assert rec["shape"] == "path-observation"
    assert rec["observers_ok"] is True
    assert rec["transport_apis_seen"] == {"sendto": 1}
    assert len(rec["channels"]["transport"]) == 1 and rec["channels"]["transport"][0]["api"] == "sendto"
    assert any("correlacao" in n for n in rec["notes"])      # nunca afirma causa

# store fora da pilha ainda conta como 'store executou' (não filtra)
offstack_path = path_capture([
    {"site": "dispatcher_0x11", "order": 1, "coord": [1, 2]},
    {"site": "receptor_0x8a", "order": 2, "coord": [1, 2], "this_is_manager": True},
    {"site": "store_035f", "order": 3, "id_at_ecx_minus2": 863, "in_current_stack": False,
     "ecx_region": "gepard", "body": {"coord": [1, 2], "dir": 0}},
])
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, offstack_path)))
    assert len(rec["channels"]["store_035f"]) == 1          # contado apesar de in_current_stack=False
    assert rec["channels"]["store_035f"][0]["in_current_stack"] is False

# nenhum transporte disparou: resultado de descoberta, não ausência de envio
no_transport_path = path_capture([
    {"site": "dispatcher_0x11", "order": 1, "coord": [1, 2]},
    {"site": "receptor_0x8a", "order": 2, "coord": [1, 2]},
    {"site": "store_035f", "order": 3, "id_at_ecx_minus2": 863, "in_current_stack": True,
     "body": {"coord": [1, 2], "dir": 0}},
])
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, no_transport_path)))
    assert rec["channels"]["transport"] == []
    assert any("NAO ausencia de envio" in n for n in rec["notes"])

# observadores incompletos (ex.: nativo sem store): observers_ok False, store ausente
incomplete_path = path_capture([
    {"site": "receptor_0x8a", "order": 1, "coord": [191, 358], "this_is_manager": True},
    {"site": "transport", "order": 2, "api": "send", "fd": 40, "bytes_returned": 5},
])
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, incomplete_path)))
    assert rec["observers_ok"] is False and rec["channels"]["store_035f"] == []
    assert len(rec["channels"]["transport"]) == 1           # transporte observado independentemente
    assert any("observadores incompletos" in n for n in rec["notes"])

# ---- 10. observe_path.py estendido: snapshot de estado do dispatcher + referência cruzada -----
# Campos aditivos (state no dispatcher, refs_dispatcher_at no receptor) passam intactos pelos
# canais, sem o analisador promovê-los a prova de consumo nem fundir os canais.
state_path = path_capture([
    {"site": "dispatcher_0x11", "order": 1, "coord": [160, 247], "this_ecx": "0x28c27dc8",
     "flag_1602a8f": 1, "deref0_is_receiver": True, "refs_receiver_at": 0,
     "root_refs_dispatcher_at": None,
     "state": {"f500": 0, "f50c": 0, "f510": 0, "f534": 4294967295, "f538": 4294967295}},
    {"site": "receptor_0x8a", "order": 2, "coord": [160, 247], "this_is_manager": True,
     "this_ecx": "0x248ca3d0", "flag_1602a8f": 0, "refs_dispatcher_at": None},
    {"site": "store_035f", "order": 3, "id_at_ecx_minus2": 863, "in_current_stack": True,
     "body": {"coord": [160, 247], "dir": 0}},
])
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, state_path)))
    assert rec["shape"] == "path-observation" and rec["observers_ok"] is True
    disp = rec["channels"]["dispatcher_0x11"][0]
    recep = rec["channels"]["receptor_0x8a"][0]
    # snapshot preservado literalmente (0xffffffff == 4294967295 não vira True/False)
    assert disp["state"]["f534"] == 4294967295 and disp["state"]["f500"] == 0
    # ausência de ligação direta é representada como None, nunca inventada como offset
    assert recep["refs_dispatcher_at"] is None
    # o global cleared-pre-dispatch passa como dado literal nos dois canais (1 no 0x11, 0 no receptor)
    assert disp["flag_1602a8f"] == 1 and recep["flag_1602a8f"] == 0
    # linkage bidirecional + elo indireto passam como dado (sem virar conclusao de consumo)
    assert disp["deref0_is_receiver"] is True and disp["refs_receiver_at"] == 0
    assert disp["root_refs_dispatcher_at"] is None
    # o analisador NÃO adiciona nenhuma conclusão de consumo a partir do snapshot
    assert "consumer" not in rec and "consumidor" not in json.dumps(rec)

# referência cruzada POSITIVA (offset encontrado) também só passa como dado, sem virar causa
state_path_ref = path_capture([
    {"site": "dispatcher_0x11", "order": 1, "coord": [1, 2], "this_ecx": "0xaaaa0000",
     "state": {"f500": 1, "f50c": 0, "f510": 0, "f534": 0, "f538": 0}},
    {"site": "receptor_0x8a", "order": 2, "coord": [1, 2], "this_is_manager": True,
     "this_ecx": "0xbbbb0000", "refs_dispatcher_at": 76},
    {"site": "store_035f", "order": 3, "id_at_ecx_minus2": 863, "in_current_stack": True,
     "body": {"coord": [1, 2], "dir": 0}},
])
with tempfile.TemporaryDirectory() as d:
    rec = analyze.classify(analyze.load_capture(write_json(d, state_path_ref)))
    assert rec["channels"]["receptor_0x8a"][0]["refs_dispatcher_at"] == 76
    assert rec["observers_ok"] is True

print("test_movement_preconditions PASS")
