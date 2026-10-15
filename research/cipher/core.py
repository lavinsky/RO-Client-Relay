"""Bounded evidence validation and falsification, without an assumed uaRO cipher.

Hex/state values stay in memory or caller-selected private artifacts. Public reports
contain counts and missing requirements, never captured bytes or state values.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "ro-cipher-evidence-v1"
MAX_BYTES = 64 * 1024 * 1024
MAX_LINE = 262144
MAX_PAYLOAD = 65536
MAX_STATE = 4096
ALIAS = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
HEX = re.compile(r"(?:[0-9a-fA-F]{2})*\Z")
HEADER_KEYS = {"schema", "kind", "provenance", "build", "dataset"}
RECORD_KEYS = {
    "kind", "index", "session", "connection", "direction", "unit", "epoch",
    "call_index", "stream_offset", "boundary", "length", "input_hex",
    "output_hex", "xor_operand_hex", "state_before_hex", "state_after_hex",
    "state_layout", "source_offset", "input_origin", "output_origin", "complete",
    "reason",
}


class EvidenceError(ValueError):
    """A safe error message: do not interpolate captured values into exceptions."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def integer(value, field: str, maximum: int = (1 << 63) - 1, nullable=False):
    if value is None and nullable:
        return None
    require(type(value) is int and 0 <= value <= maximum, "invalid " + field)
    return value


def hex_bytes(value, field: str, maximum: int = MAX_PAYLOAD):
    if value is None:
        return None
    require(isinstance(value, str) and len(value) <= 2 * maximum and
            HEX.fullmatch(value) is not None, "invalid " + field)
    return bytes.fromhex(value)


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse_json(raw: bytes):
    try:
        return json.loads(raw, object_pairs_hook=_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              EvidenceError("non-finite JSON number")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise EvidenceError("invalid JSON record") from exc


def header(provenance="synthetic", dataset="sample", build=None):
    return {"schema": SCHEMA, "kind": "dataset", "provenance": provenance,
            "dataset": dataset, "build": build}


def validate_header(item):
    require(isinstance(item, dict) and set(item) == HEADER_KEYS, "invalid dataset header")
    require(item["schema"] == SCHEMA and item["kind"] == "dataset", "unsupported schema")
    require(item["provenance"] in ("synthetic", "client"), "invalid provenance")
    require(isinstance(item["dataset"], str) and ALIAS.fullmatch(item["dataset"]) is not None,
            "invalid local dataset alias")
    build = item["build"]
    if build is not None:
        require(isinstance(build, dict) and set(build) == {"uaro_sha256", "gepard_sha256"},
                "invalid build metadata")
        for value in build.values():
            require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
                    "invalid build digest")
    return item


def validate_record(item):
    require(isinstance(item, dict) and not (set(item) - RECORD_KEYS), "unknown observation field")
    for key in ("kind", "index", "session", "connection", "direction", "unit", "epoch"):
        require(key in item, "missing " + key)
    require(item["kind"] in ("call", "packet", "store", "gap"), "invalid observation kind")
    for key in ("session", "connection"):
        require(isinstance(item[key], str) and ALIAS.fullmatch(item[key]) is not None,
                "invalid local " + key + " alias")
    require(item["direction"] in ("send", "recv", "unknown"), "invalid direction")
    require(item["unit"] in ("send", "recv", "sync", "unknown"), "invalid cipher unit")
    for key in ("index", "epoch"):
        integer(item[key], key)
    if item["kind"] == "gap":
        require(set(item) <= {"kind", "index", "session", "connection", "direction", "unit",
                              "epoch", "reason", "source_offset"}, "gap contains payload")
        require(item.get("reason") in ("capture_limit", "source_boundary", "record_loss",
                                        "malformed_record"), "invalid gap reason")
        integer(item.get("source_offset"), "source_offset", nullable=True)
        return item
    for key in ("call_index", "stream_offset", "source_offset"):
        integer(item.get(key), key, nullable=True)
    length = integer(item.get("length"), "length", MAX_PAYLOAD)
    require(item.get("boundary") in ("complete", "unknown"), "invalid call boundary")
    require(type(item.get("complete")) is bool, "missing completeness flag")
    for key in ("input_origin", "output_origin"):
        require(item.get(key) in ("direct", "window_inferred", "post_store_register",
                                   "synthetic", "unavailable"), "invalid byte provenance")
    for key in ("input_hex", "output_hex", "xor_operand_hex"):
        value = hex_bytes(item.get(key), key)
        if value is not None:
            require(len(value) <= length, "payload exceeds declared length")
            if item["complete"]:
                require(len(value) == length, "incomplete payload marked complete")
    before = hex_bytes(item.get("state_before_hex"), "state_before_hex", MAX_STATE)
    after = hex_bytes(item.get("state_after_hex"), "state_after_hex", MAX_STATE)
    if before is not None and after is not None:
        require(len(before) == len(after), "state region size changed")
    layout = item.get("state_layout")
    if layout is not None:
        require(isinstance(layout, dict) and set(layout) == {
            "table_offset", "table_length", "position_offsets"}, "invalid state layout")
        off = integer(layout["table_offset"], "table_offset", MAX_STATE)
        n = integer(layout["table_length"], "table_length", MAX_STATE)
        positions = layout["position_offsets"]
        require(isinstance(positions, list) and len(positions) <= 32, "invalid position offsets")
        for pos in positions:
            integer(pos, "position offset", MAX_STATE - 1)
        require(len(set(positions)) == len(positions), "duplicate position offset")
        for state_value in (before, after):
            if state_value is not None:
                require(off + n <= len(state_value) and all(p < len(state_value) for p in positions),
                        "state layout exceeds observed region")
    return item


def lane(record):
    return tuple(record[k] for k in ("session", "connection", "direction", "unit", "epoch"))


def open_regular(path):
    """Do not block on a FIFO/device, follow a final symlink, or read it before fstat."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "input must be a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


@dataclass(frozen=True)
class Dataset:
    metadata: dict
    records: tuple[dict, ...]
    digest: str


def load_dataset(path, max_bytes=4 * 1024 * 1024, max_records=4096):
    integer(max_bytes, "max_bytes", MAX_BYTES)
    integer(max_records, "max_records", 100000)
    require(max_bytes > 0 and max_records > 0, "limits must be positive")
    path = Path(path)
    require(not path.is_symlink(), "input symlink refused")
    digest = hashlib.sha256()
    records = []
    metadata = None
    total = 0
    with open_regular(path) as handle:
        initial = os.fstat(handle.fileno())
        require(stat.S_ISREG(initial.st_mode), "input must be a regular file")
        require(initial.st_size <= max_bytes, "input byte limit exceeded")
        for raw in iter(lambda: handle.readline(MAX_LINE + 1), b""):
            total += len(raw)
            require(len(raw) <= MAX_LINE and total <= max_bytes, "input byte/line limit exceeded")
            require(raw.endswith(b"\n"), "unterminated JSONL record")
            digest.update(raw)
            item = parse_json(raw)
            if metadata is None:
                metadata = validate_header(item)
            else:
                require(len(records) < max_records, "input record limit exceeded")
                records.append(validate_record(item))
        final = os.fstat(handle.fileno())
        require((initial.st_size, initial.st_mtime_ns) == (final.st_size, final.st_mtime_ns),
                "input changed during read")
    require(metadata is not None, "empty input")
    require(all(a["index"] < b["index"] for a, b in zip(records, records[1:])),
            "observation indices must increase")
    return Dataset(metadata, tuple(records), digest.hexdigest())


def private_directory(path):
    path = Path(path)
    require(not path.is_symlink(), "output directory symlink refused")
    if not path.exists():
        path.mkdir(mode=0o700)
    require(path.is_dir() and stat.S_IMODE(path.stat().st_mode) == 0o700,
            "output directory must have mode 0700")
    return path


def private_write(directory, name: str, content: bytes):
    require(isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,95}", name) is not None,
            "invalid artifact name")
    directory = private_directory(directory)
    path = directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        directory_stat = os.fstat(directory_fd)
        require(stat.S_IMODE(directory_stat.st_mode) == 0o700 and directory_stat.st_uid == os.getuid(),
                "output directory must be private and owned by current user")
        with os.fdopen(os.open(name, flags, 0o600, dir_fd=directory_fd), "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(content)
    finally:
        os.close(directory_fd)
    return path


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def dataset_bytes(metadata, records):
    validate_header(metadata)
    return b"".join((json.dumps(validate_record(r) if i else validate_header(r),
                                sort_keys=True, allow_nan=False) + "\n").encode()
                    for i, r in enumerate([metadata, *records]))


def analyze(data: Dataset):
    """Count evidence, not an inferred algorithm or a guessed initial state."""
    counts = Counter()
    missing = Counter()
    previous = {}
    byte_lengths = Counter()
    position_hypotheses = defaultdict(Counter)
    for record in data.records:
        counts[record["kind"] + "_records"] += 1
        key = lane(record)
        if record["kind"] == "gap":
            # A loss marker may not identify which unit lost data. Conservative:
            # never carry any association through a declared gap in this file.
            previous.clear()
            continue
        byte_lengths[record["length"]] += 1
        values = {k: hex_bytes(record.get(k), k, MAX_STATE if k.startswith("state_") else MAX_PAYLOAD)
                  for k in ("input_hex", "output_hex", "xor_operand_hex", "state_before_hex",
                            "state_after_hex")}
        for key_name, requirement in [("input_hex", "input_bytes"), ("output_hex", "output_bytes"),
                                      ("state_before_hex", "state_before"),
                                      ("state_after_hex", "state_after")]:
            if values[key_name] is None:
                missing[requirement] += 1
        for key_name in ("call_index", "stream_offset"):
            if record.get(key_name) is None:
                missing[key_name] += 1
        if record["boundary"] != "complete" or record["kind"] != "call":
            missing["transformation_call_boundary"] += 1
        if not record["complete"]:
            missing["complete_bytes"] += 1
        for key_name in ("direction", "unit"):
            if record[key_name] == "unknown":
                missing[key_name] += 1
        plain, cipher, operand = (values[k] for k in ("input_hex", "output_hex", "xor_operand_hex"))
        if plain is not None and cipher is not None and len(plain) == len(cipher) == record["length"]:
            counts["complete_byte_pairs"] += 1
            counts["paired_bytes"] += len(plain)
            # P xor C exists for every equal-length pair; it does not prove XOR encryption.
            if operand is not None and len(operand) == len(plain):
                delta = bytes(a ^ b for a, b in zip(plain, cipher))
                counts["xor_operand_matches" if delta == operand else "xor_operand_mismatches"] += 1
            else:
                missing["independently_observed_xor_operand"] += 1
        before, after = values["state_before_hex"], values["state_after_hex"]
        if before is not None and after is not None:
            counts["paired_state_snapshots"] += 1
            counts["changed_state_bytes"] += sum(a != b for a, b in zip(before, after))
            layout = record.get("state_layout")
            if layout is not None:
                lo = layout["table_offset"]
                if layout["table_length"] == 256:
                    ramp = bytes(((i << 2) | (i >> 6)) & 255 for i in range(256))
                    counts["rol8_pattern_comparisons"] += 1
                    counts["rol8_pattern_matches_before"] += sum(
                        a == b for a, b in zip(before[lo:lo + 256], ramp))
                    counts["rol8_pattern_matches_after"] += sum(
                        a == b for a, b in zip(after[lo:lo + 256], ramp))
                changed = {i for i, (a, b) in enumerate(zip(before[lo:lo + layout["table_length"]],
                                                           after[lo:lo + layout["table_length"]])) if a != b}
                counts["changed_table_bytes"] += len(changed)
                counts["adjacent_changed_byte_pairs"] += sum(i % 2 == 0 and i + 1 in changed
                                                              for i in changed)
                # Snapshot adjacency does not establish word-sized instructions or their order.
                for pos in layout["position_offsets"]:
                    delta = (after[pos] - before[pos]) & 255
                    stats = position_hypotheses[str(pos)]
                    stats["observations"] += 1
                    for label, steps in (("byte", record["length"]),
                                         ("floor_word", record["length"] // 2),
                                         ("ceil_word", (record["length"] + 1) // 2)):
                        for increment in (1, 33):
                            stats[label + "_step_" + str(increment) + "_matches"] += (
                                delta == (steps * increment) & 255)
        if (record["kind"] != "call" or record["boundary"] != "complete" or
                not record["complete"] or record["direction"] == "unknown" or
                record["unit"] == "unknown"):
            previous.pop(key, None)
            continue
        prior = previous.get(key)
        if prior is not None:
            if (prior.get("call_index") is not None and record.get("call_index") is not None):
                if record["call_index"] == prior["call_index"] + 1:
                    counts["consecutive_call_links"] += 1
                    offset_matches = False
                    if prior.get("stream_offset") is not None and record.get("stream_offset") is not None:
                        offset_matches = record["stream_offset"] == prior["stream_offset"] + prior["length"]
                        counts["offset_link_matches" if offset_matches else "offset_link_mismatches"] += 1
                    if offset_matches and prior.get("state_after_hex") is not None and record.get("state_before_hex") is not None:
                        counts["state_link_matches" if prior["state_after_hex"].lower() ==
                               record["state_before_hex"].lower() else "state_link_mismatches"] += 1
                else:
                    counts["call_index_discontinuities"] += 1
        previous[key] = record
    if data.metadata["build"] is None:
        missing["identified_client_build"] += 1
    if not data.records:
        missing["observations"] += 1
    # A byte/state record does not establish all arguments consumed by a VM.
    missing["context_dependencies_identified"] += 1
    return {"schema": "ro-cipher-report-v1", "result": "C_INSUFFICIENT",
            "provenance": data.metadata["provenance"], "source_digest": data.digest,
            "counts": dict(sorted(counts.items())), "missing": dict(sorted(missing.items())),
            "byte_lengths": dict(sorted(byte_lengths.items())),
            "position_hypotheses": {k: dict(v) for k, v in sorted(position_hypotheses.items())},
            "claims": {"cipher_solved": False, "xor_delta_proves_cipher": False,
                       "pattern_match_identifies_state": False,
                       "complete_context_identified": False,
                       "initial_state_fabricated": False, "xkore0_functional": False}}
