#!/usr/bin/env python3
"""Offline inventory: python3 research/cipher/analyze.py --input FILE ... --out DIR.

Only explicitly named files are opened. Reports contain no payloads, states,
register values, account IDs, network addresses or stack contents. No collector,
decrypt fallback, candidate fitting, filesystem search or network access exists.
"""
from collections import Counter, defaultdict
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from research.cipher.core import (Dataset, EvidenceError, MAX_BYTES, MAX_LINE, SCHEMA,
        analyze, hex_bytes, json_bytes, load_dataset, open_regular, parse_json,
        private_directory, private_write, require)
else:
    from .core import (Dataset, EvidenceError, MAX_BYTES, MAX_LINE, SCHEMA, analyze,
        hex_bytes, json_bytes, load_dataset, open_regular, parse_json,
        private_directory, private_write, require)

ACTION_LENGTHS = {0x035F: 5, 0x0437: 7, 0x0438: 10}
from research.cipher.chain_audit import audit_chain


def _packet_id(value):
    if type(value) is int:
        return value if 0 <= value <= 65535 else None
    if isinstance(value, str) and re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,4}", value):
        return int(value, 16)
    return None

ESSENTIAL = ("plaintext", "ciphertext", "call_boundary", "call_order", "direction",
             "cipher_unit", "state_before", "state_after", "build", "session", "context")


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _recorded_build(container):
    modules = container.get("modules")
    if not isinstance(modules, dict):
        return None
    result = {}
    for name, key in (("uaRO.exe", "uaro_sha256"), ("gepard.dll", "gepard_sha256")):
        value = modules.get(name)
        if not isinstance(value, dict) or not _hash(value.get("sha256")):
            return None
        result[key] = value["sha256"]
    return result


def _finite_ints(value, length):
    return isinstance(value, list) and len(value) == length and all(
        type(v) is int and 0 <= v <= 8192 for v in value)


def _inspect_event(record, fields, excluded):
    """Read only documented event fields. No pairing across different records."""
    if not isinstance(record, dict):
        excluded["not_an_event_object"] += 1
        return
    if _finite_ints(record.get("coords"), 2) or _finite_ints(record.get("coordinate_candidates"), 2):
        fields["coordinates"] += 1
    ack = record.get("ack0087")
    if isinstance(ack, dict) and _finite_ints(ack.get("src"), 2) and _finite_ints(ack.get("dst"), 2):
        fields["movement_ack"] += 1
    # No conversion of coordinates, return PCs or ACKs into absent cipher bytes.
    tag = record.get("tag")
    if tag in ("SEND", "SEND-PLAIN"):
        packet_id = _packet_id(record.get("id"))
        if packet_id not in ACTION_LENGTHS:
            excluded["non_allowlisted_or_ambiguous_socket_id"] += 1
            return
        try:
            cipher = hex_bytes(record.get("C"), "client output")
            plain = hex_bytes(record.get("P"), "client input")
        except EvidenceError:
            excluded["malformed_action_bytes"] += 1
            return
        length = ACTION_LENGTHS[packet_id]
        if cipher is None or len(cipher) != length or int.from_bytes(cipher[:2], "little") != packet_id:
            excluded["socket_chunk_not_one_proven_packet"] += 1
            return
        if "len" in record and (type(record["len"]) is not int or record["len"] != length):
            excluded["conflicting_socket_length"] += 1
            return
        fields["ciphertext"] += 1
        fields["direction"] += 1
        fields["socket_order_only"] += 1
        if plain is not None and len(plain) == length and plain[:2] == cipher[:2]:
            fields["plaintext"] += 1
            fields["same_event_byte_pair"] += 1
            excluded["plaintext_origin_not_independently_verified"] += 1
        if isinstance(record.get("win"), dict):
            fields["watch_windows_unverified"] += 1
        excluded["socket_call_is_not_cipher_call"] += 1
    elif tag == "SCRAMBLE" and record.get("hit") == "trace":
        try:
            byte = hex_bytes(record.get("db"), "store byte", 1)
            window = hex_bytes(record.get("tbl"), "unclassified window", 4096)
        except EvidenceError:
            excluded["malformed_store_trace"] += 1
            return
        fields["store_memory_byte"] += byte is not None
        fields["unclassified_memory_window"] += window is not None
        fields["store_result_register_present"] += isinstance(record.get("ebx"), str)
        excluded["memory_window_not_identified_state"] += 1
    elif tag == "HIT" and isinstance(record.get("packet"), dict):
        packet = record["packet"]
        packet_id = _packet_id(packet.get("id"))
        if packet_id in ACTION_LENGTHS:
            try:
                value = hex_bytes(packet.get("hex"), "entry packet")
                if value is not None and len(value) == ACTION_LENGTHS[packet_id] and \
                        int.from_bytes(value[:2], "little") == packet_id:
                    fields["plaintext"] += 1
                    fields["entry_packet_only"] += 1
                    excluded["entry_boundary_not_independently_validated"] += 1
            except EvidenceError:
                excluded["malformed_entry_packet"] += 1
    elif tag == "CODE_PREFLIGHT":
        if record.get("instruction") == "mov byte ptr [ecx], bl":
            fields["final_store_instruction"] += 1
        if record.get("state_observed") is False:
            excluded["code_only_preflight_not_cipher_vector"] += 1
    else:
        excluded["no_direct_cipher_vector"] += 1


def _probe_report(objects, digest, max_records):
    fields, excluded = Counter(), Counter()
    events = 0
    builds = []
    for item in objects:
        if isinstance(item, dict) and isinstance(item.get("events"), list):
            build = _recorded_build(item)
            if build:
                builds.append(build)
                fields["build"] += 1
            if type(item.get("pid")) is int:
                fields["recorded_process_only"] += 1
            require(events + len(item["events"]) <= max_records, "nested event limit exceeded")
            for event in item["events"]:
                events += 1
                _inspect_event(event, fields, excluded)
                # Bounded instruction metadata from the actual inspection format.
                if isinstance(event, dict) and isinstance(event.get("refs"), list):
                    for ref in event["refs"][:64]:
                        if isinstance(ref, dict) and isinstance(ref.get("instructions"), list):
                            for ins in ref["instructions"][:32]:
                                if isinstance(ins, str) and re.fullmatch(
                                        r"0x[0-9a-f]+: mov byte ptr \[ecx\], bl", ins):
                                    fields["final_store_instruction"] += 1
        elif isinstance(item, dict):
            events += 1
            require(events <= max_records, "event limit exceeded")
            _inspect_event(item, fields, excluded)
        else:
            excluded["unsupported_record_shape"] += 1
    return {"result": "C_INSUFFICIENT", "format": "legacy_client_events", "source_digest": digest,
            "events": events, "fields_available": dict(sorted(fields.items())),
            "fields_absent": [name for name in ESSENTIAL if not fields[name]],
            "usable_complete_cipher_calls": 0, "excluded": dict(sorted(excluded.items())),
            "recorded_builds": builds, "session": "unknown",
            "pairing_policy": "same record only; no reconstruction, temporal matching or cross-file joins"}


def inspect_file(path, max_bytes=4 * 1024 * 1024, max_records=10000):
    """Hash the exact bounded input; malformed/large files produce safe diagnostics."""
    path = Path(path)
    result = {"file": path.name, "source_path": str(path.absolute()),
              "sha256": None, "result": "C_INSUFFICIENT"}
    try:
        require(type(max_bytes) is int and 0 < max_bytes <= MAX_BYTES, "invalid byte limit")
        require(type(max_records) is int and 0 < max_records <= 10000, "invalid record limit")
        with open_regular(path) as handle:
            initial = os.fstat(handle.fileno())
            result["source_bytes"] = initial.st_size
            require(initial.st_size <= max_bytes, "input exceeds configured byte limit")
            raw = handle.read(max_bytes + 1)
            final = os.fstat(handle.fileno())
            require(len(raw) <= max_bytes, "input grew beyond byte limit")
            require((initial.st_size, initial.st_mtime_ns) == (final.st_size, final.st_mtime_ns),
                    "input changed during read")
        result["sha256"] = hashlib.sha256(raw).hexdigest()
        stripped = raw.lstrip()
        require(bool(stripped), "empty input")
        # JSON containers and JSONL are distinguished by complete parsing, never eval.
        try:
            obj = parse_json(raw)
        except EvidenceError:
            lines = raw.splitlines(keepends=True)
            require(len(lines) <= max_records + 1, "input record limit exceeded")
            require(all(len(line) <= MAX_LINE and line.endswith(b"\n") for line in lines),
                    "truncated or oversized JSONL line")
            objects = [parse_json(line) for line in lines]
        else:
            objects = obj if isinstance(obj, list) else [obj]
            require(len(objects) <= max_records, "input record limit exceeded")
        if objects and isinstance(objects[0], dict) and objects[0].get("schema") == SCHEMA:
            # Normalized format is deliberately JSONL, including its header.
            data = load_dataset(path, max_bytes, max_records)
            require(result["sha256"] == data.digest, "input changed between validation passes")
            result.update(analyze(data))
            groups = Counter()
            for record in data.records:
                groups[(record["session"], record["direction"], record["unit"], record["epoch"])] += 1
            result["groups"] = [dict(session=k[0], direction=k[1], unit=k[2], epoch=k[3], records=n)
                                for k, n in sorted(groups.items())]
            result["format"] = SCHEMA
            result["usable_complete_cipher_calls"] = sum(
                r["kind"] == "call" and r["complete"] and r["boundary"] == "complete" and
                all(r.get(k) is not None for k in ("input_hex", "output_hex", "state_before_hex",
                                                  "state_after_hex", "call_index", "stream_offset"))
                for r in data.records)
        else:
            result.update(_probe_report(objects, result["sha256"], max_records))
            if len(objects) == 1 and isinstance(objects[0], dict) and 'configuration' in objects[0] \
                    and 'cleanup_confirmed' in objects[0]:
                result['chain_observation'] = audit_chain(objects[0])
                result['format'] = 'bounded_load_store_chain'
                build = objects[0].get('build', {})
                if isinstance(build, dict) and all(_hash(build.get(k)) for k in ('uaRO.exe', 'gepard.dll')):
                    result['recorded_builds'] = [dict(uaro_sha256=build['uaRO.exe'],
                                                    gepard_sha256=build['gepard.dll'])]
                    result['fields_available']['build'] = 1
                    result['fields_absent'] = [x for x in result['fields_absent'] if x != 'build']
        result["source_preserved"] = True
    except (EvidenceError, OSError) as exc:
        result["error"] = str(exc) if isinstance(exc, EvidenceError) else type(exc).__name__
        result["usable_complete_cipher_calls"] = 0
    return result


def diagnose(reports):
    # Exactly three families, with preconditions. No fitting/searching is performed.
    return [
        {"id": "H1", "hypothesis": "sampled memory differs from consumed cipher state",
         "prediction": "a proven state read/write region differs from the EBX-aligned window",
         "rival": "the sampled region is correct but no state write occurs at the final store",
         "test": "compare independently identified state reads/writes with the sampled window",
         "result": "SUSPENDED", "missing": ["identified consumed state", "ordered memory dependencies"]},
        {"id": "H2", "hypothesis": "block generation precedes final byte consumption",
         "prediction": "keystream/state changes precede several final byte stores",
         "rival": "per-byte generation uses a different unobserved state region",
         "test": "observe producer of BL and its state dependencies before the store",
         "result": "SUSPENDED", "missing": ["producer of transformed byte", "generation/consumption boundaries"]},
        {"id": "H3", "hypothesis": "length or call boundary affects transition",
         "prediction": "contiguous odd/even calls constrain different transitions than a concatenated call",
         "rival": "differences arise from missing bytes, direction/unit mix or unrelated initial states",
         "test": "compare complete contiguous calls and observed state before/after without resetting state",
         "result": "SUSPENDED", "missing": ["real contiguous input/output/state vectors", "proven call lengths"]},
    ]


def run(paths, out, max_bytes=4 * 1024 * 1024, max_records=10000):
    require(1 <= len(paths) <= 64, "input count outside bound")
    out = private_directory(out)
    reports = [inspect_file(p, max_bytes, max_records) for p in paths]
    seen = {}
    for index, report in enumerate(reports):
        digest = report.get("sha256")
        if digest is not None:
            if digest in seen:
                report["duplicate_content_of_input"] = seen[digest]
            else:
                seen[digest] = index
    # Sources and local session aliases remain separate, including identical addresses/aliases.
    report = {"schema": "ro-cipher-investigation-v1", "result": "C_INSUFFICIENT",
              "files": reports, "hypotheses": diagnose(reports),
              "cross_file_association": "disabled: provenance/session continuity not established",
              "cipher_candidate": None, "cipher_solved": False,
              "initial_state_fabricated": False, "xkore0_functional": False}
    private_write(out, "inventory.json", json_bytes(report))
    private_write(out, "missing-data.json", json_bytes({"result": report["result"],
        "files": [{"file": r["file"], "missing": r.get("fields_absent", r.get("missing", {})),
                   "error": r.get("error"), "usable_calls": r["usable_complete_cipher_calls"]}
                  for r in reports], "hypotheses": report["hypotheses"]}))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-input-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--max-records", type=int, default=10000)
    args = parser.parse_args(argv)
    try:
        report = run(args.input, args.out, args.max_input_bytes, args.max_records)
    except (EvidenceError, OSError) as exc:
        print(json.dumps({"error": str(exc) if isinstance(exc, EvidenceError) else type(exc).__name__}),
              file=sys.stderr)
        return 2
    errors = sum("error" in r for r in report["files"])
    print(json.dumps({"result": report["result"], "files": len(report["files"]),
                      "invalid_or_unreadable": errors,
                      "usable_complete_cipher_calls": sum(r["usable_complete_cipher_calls"]
                                                          for r in report["files"]),
                      "cipher_candidate": None}))
    return 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
