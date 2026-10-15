#!/usr/bin/env python3
"""Tabela sanitizada de sequência e limites de observação para capturas de 0x035F.

Entrada: caminhos EXPLÍCITOS de arquivos JSON produzidos por ro035f_probe.py /
ro035f_auto_probe.py. Não varre diretórios, não busca novos dados, não fabrica
campos ausentes e não ordena causalmente por timestamp. Cada arquivo é uma sessão
isolada: nunca correlaciona arquivos diferentes só porque coordenada/endereço
coincidem. Nunca afirma evento de saída (envio) quando a captura não o observou.

Uso:  python3 analyze.py captura1.json [captura2.json ...]
"""
import argparse
import json
import sys

ABSENT = "ausente-na-captura"            # campo não registrado — NÃO é zero/false
UNOBS_SEND = "nao-observado-na-captura"  # a sonda não tinha hook de transporte
UNOBS_ACK = "inobservavel-sem-store"     # associação do ACK depende do store reconhecido


def load_capture(path):
    """Lê um JSON de captura. Erro de leitura/parse é devolvido como registro de limite,
    não interrompe o lote (um arquivo ausente/corrompido não bloqueia os demais)."""
    try:
        with open(path, encoding="utf-8") as f:
            return {"source": path, "data": json.load(f), "error": None}
    except (OSError, ValueError) as e:
        return {"source": path, "data": None, "error": str(e)}


def _done_event(data):
    """O evento DONE da captura, ou None. Não inventa um DONE quando ele falta."""
    for ev in (data or {}).get("events", []):
        if isinstance(ev, dict) and ev.get("tag") == "DONE":
            return ev
    return None


def _ordered_trail(done):
    """Trilha preservando a ORDEM EXPLÍCITA (campo 'order') quando presente em todos os
    itens; caso contrário mantém a ordem do arquivo. Nunca reordena por 'ms'/timestamp."""
    trail = done.get("trail")
    if not isinstance(trail, list):
        return [], "sem-trilha"
    if trail and all(isinstance(x, dict) and "order" in x for x in trail):
        return sorted(trail, key=lambda x: x["order"]), "ordem-explicita"
    return list(trail), "ordem-de-arquivo"


def classify(capture):
    """Registro sanitizado de uma captura: canais observados, ordem e limites.

    Mantém as DUAS interfaces 0x11 separadas (dispatcher 'root11' vs wrapper 0xc7650e
    'input11'); nunca as funde. Marca o envio como não-observado e o ACK como
    inobservável-sem-store quando for o caso, para impedir leitura de duplo negativo."""
    if capture["error"] is not None:
        return {"source": capture["source"], "usable": False,
                "limits": [f"arquivo ilegivel: {capture['error']}"]}
    data = capture["data"]
    done = _done_event(data)
    # Capturas de observe_path.py levam a lista de eventos DENTRO do DONE (campo 'events'
    # com itens 'site'); são canais independentes, resumidos à parte.
    if done is not None and isinstance(done.get("events"), list):
        return summarize_path(capture["source"], data, done)
    session = {"pid": data.get("pid", ABSENT), "gadget_port": data.get("gadget_port", ABSENT),
               "mode": data.get("mode", ABSENT)}
    rec = {"source": capture["source"], "session": session, "usable": done is not None,
           "limits": []}
    if done is None:
        rec["limits"].append("sem evento DONE: captura incompleta ou abortada")
        return rec

    # Limpeza / sobrevivência (não confundir com responsividade de interface).
    rec["clean_cleanup"] = bool(done.get("cleared", done.get("unfollowed", False)))
    rec["target_alive_after"] = data.get("target_alive_after", ABSENT)

    store_recognized = bool(done.get("matched", done.get("matched_035f", False)))
    last8a = done.get("last8a")
    root11 = done.get("root11")      # dispatcher 0xd473b0, code 0x11 (slots de 64 bits)
    input11 = done.get("input11")    # wrapper 0xc7650e, code 0x11 (interface DISTINTA)
    ack = done.get("ack0087")

    rec["channels"] = {
        # interfaces 0x11 explicitamente separadas
        "dispatcher_0x11(root11)": _coord_of(root11),
        "wrapper_0x11_0xc7650e(input11)": _screen_of(input11),
        "receptor_0x8a(last8a)": _recep_of(last8a),
        "store_035f": "reconhecido" if store_recognized else "nao-reconhecido",
        "ack_0087": _ack_state(ack, store_recognized),
        "transporte_envio": UNOBS_SEND,   # nenhuma captura ro035f* tinha hook de saída
    }
    rec["decoded_dest"] = done.get("coords", ABSENT)
    rec["args_match"] = done.get("args_match", ABSENT)
    if "emit_state" in done:
        rec["emit_state"] = done["emit_state"]

    trail, basis = _ordered_trail(done)
    rec["order_basis"] = basis
    rec["trail"] = [{"site": t.get("site", ABSENT), "order": t.get("order", ABSENT),
                     "code": t.get("code", ABSENT)} for t in trail]

    # Limites que impedem conclusões inválidas.
    if not store_recognized:
        rec["limits"].append(
            "store 0x035F nao reconhecido: NAO distingue 'store executou fora da janela "
            "de pilha' de 'store nao alcancado' (gate de ecx silencioso).")
        rec["limits"].append(
            "envio nao observado nesta captura: 'sem store/ACK' NAO implica 'nao enviou'.")
        rec["cannot_conclude_no_send"] = True
    if rec["channels"]["ack_0087"] == UNOBS_ACK:
        rec["limits"].append(
            "ACK 0x0087 inobservavel sem store: nao contar como negativo independente.")
    es = done.get("emit_state")
    # Só vale quando houve TENTATIVA de chamada nativa; o emit_state default
    # (attempted=false,returned=false) acompanha toda captura e não é um emit real.
    if isinstance(es, dict) and es.get("attempted") and es.get("returned") is False:
        rec["limits"].append(
            "chamada nativa nao retornou (ex.: 'breakpoint triggered'): artefato de "
            "instrumentacao, nao comportamento do cliente.")
    return rec


def _coord_of(root11):
    if not isinstance(root11, dict):
        return ABSENT
    return {"coordinate_candidates": root11.get("coordinate_candidates", ABSENT),
            "return_pc": root11.get("return_pc", ABSENT)}


def _screen_of(input11):
    if not isinstance(input11, dict):
        return ABSENT
    return {"screen_candidates": input11.get("screen_candidates", ABSENT),
            "input_state": input11.get("input_state", ABSENT),
            "virtual_target": input11.get("virtual_target", ABSENT)}


def _recep_of(last8a):
    if not isinstance(last8a, dict):
        return ABSENT
    return {"code": last8a.get("code", ABSENT),
            "coordinate_candidates": last8a.get("coordinate_candidates", ABSENT),
            "receiver_this_is_manager": last8a.get("receiver_this_is_manager", ABSENT),
            "tail_args_zero": last8a.get("tail_args_zero", ABSENT)}


def _ack_state(ack, store_recognized):
    if not store_recognized:
        return UNOBS_ACK
    if ack is None:
        return "nao-associado"
    if isinstance(ack, dict):
        return "associado"
    return ABSENT


def summarize_path(source, data, done):
    """Resumo de uma captura de observe_path.py: canais INDEPENDENTES, ordem preservada.

    Não infere que um evento de transporte carregue o 0x035F, não condiciona o store à
    janela de pilha, não ordena por 'ms'. Transporte vazio é RESULTADO de descoberta
    (possível syscall crua/API não coberta), não prova de ausência de envio."""
    evs = done.get("events", [])
    buckets = {"dispatcher_0x11": [], "receptor_0x8a": [], "store_035f": [],
               "transport": [], "recv_0087": [], "handler_error": []}
    for e in evs:
        if isinstance(e, dict) and e.get("site") in buckets:
            buckets[e["site"]].append(e)
    rec = {
        "shape": "path-observation",
        "source": source,
        "session": {"pid": data.get("pid", ABSENT), "gadget_port": data.get("gadget_port", ABSENT)},
        "clean_cleanup": bool(done.get("cleared", False)),
        "saturated": done.get("saturated", ABSENT),
        "framing_errors": done.get("framing_errors", ABSENT),
        "transport_apis_seen": done.get("transport_apis_seen", {}),
        "channels": buckets,
        # Observadores validados no movimento natural = os três pontos de execução dispararam.
        "observers_ok": bool(buckets["dispatcher_0x11"] and buckets["receptor_0x8a"]
                             and buckets["store_035f"]),
        "notes": [
            "transporte e store sao canais INDEPENDENTES; proximidade temporal e correlacao, "
            "nao causa (codigo virtualizado; endereco de retorno isolado nao prova a cadeia).",
            "store_035f e contado mesmo com in_current_stack=false (store executou != na pilha).",
        ],
    }
    if not buckets["transport"]:
        rec["notes"].append(
            "nenhum candidato de envio disparou na conexao do servidor: possivel syscall crua "
            "ou API nao coberta (resultado de descoberta, NAO ausencia de envio).")
    if not rec["observers_ok"]:
        miss = [k for k in ("dispatcher_0x11", "receptor_0x8a", "store_035f") if not buckets[k]]
        rec["notes"].append(f"observadores incompletos neste movimento: {', '.join(miss)} sem evento.")
    return rec


def build_table(paths):
    """Uma linha por arquivo, sem fundir sessões diferentes."""
    return [classify(load_capture(p)) for p in paths]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", help="arquivos JSON de captura explicitos")
    ap.add_argument("--json", action="store_true", help="saida JSON em vez de texto")
    a = ap.parse_args(argv)
    table = build_table(a.files)
    if a.json:
        print(json.dumps(table, indent=2, ensure_ascii=False))
        return 0
    for rec in table:
        print(f"== {rec['source']} ==")
        if rec.get("shape") == "path-observation":
            s = rec["session"]
            print(f"   sessao: pid={s['pid']} porta={s['gadget_port']} limpeza={rec['clean_cleanup']} "
                  f"saturado={rec['saturated']} observadores_ok={rec['observers_ok']}")
            for ch, items in rec["channels"].items():
                if items:
                    print(f"   canal {ch}: {len(items)} evento(s)")
            print(f"   transport_apis_seen={rec['transport_apis_seen']}")
            for nt in rec["notes"]:
                print(f"   [nota] {nt}")
            continue
        if not rec.get("usable"):
            for lim in rec["limits"]:
                print(f"   [limite] {lim}")
            continue
        s = rec["session"]
        print(f"   sessao: pid={s['pid']} porta={s['gadget_port']} modo={s['mode']} "
              f"limpeza={rec['clean_cleanup']} vivo_apos={rec['target_alive_after']}")
        for k, v in rec["channels"].items():
            print(f"   canal {k}: {v}")
        print(f"   destino_decodificado={rec['decoded_dest']} args_match={rec['args_match']} "
              f"ordem={rec['order_basis']}")
        for lim in rec["limits"]:
            print(f"   [limite] {lim}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
