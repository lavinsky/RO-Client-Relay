"""Read literal OpenKore packet metadata without running Perl or reading payloads.

This is a static subset, not a Perl interpreter: supported sources are packet_list
hash literals, direct literal assignments and %packets copied into packet_list.
Dynamic entries are warned about and omitted (including inherited definitions
which they override). Conditions, runtime mutation and method dispatch are not
resolved; results describe source declarations, not verified uaRO semantics.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import warnings


class SemanticsWarning(UserWarning):
    """Source contains metadata that cannot be resolved statically."""


_STRING = r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\""
_TOKEN = re.compile(rf"\s*(?:(?P<string>{_STRING})|(?P<qw>qw\([^)]*\))|(?P<punct>[\[\],]))", re.S)


def _uncomment(text: str) -> str:
    # Preserve offsets and newlines for source_line, including # inside strings.
    pattern = re.compile(rf"{_STRING}|\#[^\n]*|^=(?:pod|head\w*|begin|for)\b.*?^=cut[^\n]*", re.M | re.S)
    return pattern.sub(lambda m: re.sub(r"[^\n]", " ", m[0]) if m[0].startswith(("#", "=")) else m[0], text)


def _end(text: str, start: int) -> int:
    pairs = {"[": "]", "{": "}", "(": ")"}
    stack = []
    i = start
    while i < len(text):
        quoted = re.match(_STRING, text[i:])
        if quoted:
            i += quoted.end()
            continue
        char = text[i]
        if char in pairs:
            stack.append(pairs[char])
        elif char in "]})":
            if not stack or stack.pop() != char:
                raise ValueError("unbalanced Perl literal")
            if not stack:
                return i + 1
        i += 1
    raise ValueError("unterminated Perl literal")


def _literal(text: str):
    tokens = []
    pos = 0
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match:
            if text[pos:].strip():
                raise ValueError("dynamic expression")
            break
        if match.lastgroup == "string":
            value = match["string"]
            if value[0] == '"' and re.search(r"(?<!\\)[$@]", value):
                raise ValueError("interpolated string")
            # Avoid guessing Perl escape semantics outside this narrow subset.
            if "\\" in value:
                raise ValueError("escaped string")
            tokens.append(value[1:-1])
        elif match.lastgroup == "qw":
            tokens.append(match["qw"][3:-1].split())
        else:
            tokens.append(match["punct"])
        pos = match.end()

    def array(index):
        if tokens[index] != "[":
            raise ValueError("expected array")
        values = []
        index += 1
        while index < len(tokens) and tokens[index] != "]":
            if tokens[index] == "[":
                value, index = array(index)
            else:
                value = tokens[index]
                index += 1
            values.append(value)
            if index < len(tokens) and tokens[index] == ",":
                index += 1
            elif index < len(tokens) and tokens[index] != "]":
                raise ValueError("expected comma")
        if index >= len(tokens):
            raise ValueError("unterminated array")
        return values, index + 1

    values, index = array(0)
    if index != len(tokens) or not 1 <= len(values) <= 3 or not isinstance(values[0], str):
        raise ValueError("unsupported packet entry")
    if len(values) > 1 and not isinstance(values[1], str):
        raise ValueError("unsupported pack")
    fields = values[2] if len(values) == 3 else []
    # [qw(...)] becomes a one-element nested list during tokenization.
    if len(fields) == 1 and isinstance(fields[0], list):
        fields = fields[0]
    if not isinstance(fields, list) or not all(isinstance(field, str) for field in fields):
        raise ValueError("unsupported fields")
    return {"handler": values[0], "pack": values[1] if len(values) > 1 else "", "fields": fields}


def _entry(text, start, packet_id, packet_lengths):
    """Resolve a literal, or one exact length-equality ternary of two literals."""
    if text[start] == "[":
        end = _end(text, start)
        return _literal(text[start:end]), end
    condition = re.match(
        r"\(\s*\$rpackets\s*\{\s*([\"'])([0-9A-Fa-f]{4})\1\s*\}"
        r"\s*\{\s*length\s*\}\s*==\s*(\d+)\s*\)\s*\?\s*",
        text[start:],
    )
    if condition is None or int(condition[2], 16) != packet_id:
        raise ValueError("unsupported condition")
    if packet_lengths is None or packet_id not in packet_lengths:
        raise ValueError("packet length unavailable")
    yes_start = start + condition.end()
    if text[yes_start] != "[":
        raise ValueError("nonliteral true branch")
    yes_end = _end(text, yes_start)
    separator = re.match(r"\s*:\s*", text[yes_end:])
    if separator is None:
        raise ValueError("missing false branch")
    no_start = yes_end + separator.end()
    if text[no_start] != "[":
        raise ValueError("nonliteral false branch")
    no_end = _end(text, no_start)
    yes = _literal(text[yes_start:yes_end])
    no = _literal(text[no_start:no_end])
    length = packet_lengths[packet_id]
    if not isinstance(length, int) or isinstance(length, bool):
        raise ValueError("noninteger packet length")
    return (yes if length == int(condition[3]) else no), no_end


def load_semantics(src_root, class_name, packet_lengths=None) -> dict[int, dict]:
    """Resolve literal declarations, with subclass entries taking precedence.

    src_root is OpenKore's src directory; class_name is a full Perl package name.
    Missing requested classes and inheritance cycles raise errors. Missing base
    modules (for example Perl core Exporter) are warned about and skipped.
    Multiple bases follow Perl's leftmost precedence for inherited entries.
    packet_lengths optionally maps integer IDs to lengths. Only literal
    ($rpackets{'ID'}{length} == N) ? [literal] : [literal] is resolved;
    absent lengths and all other conditions remain warned omissions.
    """
    root = Path(src_root).resolve()
    cache = {}
    active = set()

    def visit(name):
        if not re.fullmatch(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*", name):
            raise ValueError("invalid Perl class name")
        if name in active:
            raise ValueError(f"inheritance cycle: {name}")
        if name in cache:
            return dict(cache[name])
        path = (root / (name.replace("::", "/") + ".pm")).resolve()
        if not path.is_relative_to(root):
            raise ValueError("class path escapes source root")
        text = _uncomment(path.read_text(encoding="utf-8"))
        active.add(name)
        bases = []
        for match in re.finditer(r"\buse\s+base\s+(?:qw\(([^)]*)\)|(['\"])([\w:]+)\2)\s*;", text):
            bases.extend(match[1].split() if match[1] is not None else [match[3]])
        result = {}
        for base in reversed(bases):
            try:
                result.update(visit(base))
            except FileNotFoundError as exc:
                warnings.warn(f"{path}: unresolved base {base}: {exc.filename}", SemanticsWarning, stacklevel=2)
        regions = []
        for match in re.finditer(r"\$self\s*->\s*\{packet_list\}\s*=\s*\{", text):
            start = match.end() - 1
            regions.append((start + 1, _end(text, start) - 1))
        if re.search(r"\$self\s*->\s*\{packet_list\}\s*\{\$_\}\s*=\s*\$packets\{\$_\}", text):
            for match in re.finditer(r"\bmy\s+%packets\s*=\s*\(", text):
                start = match.end() - 1
                regions.append((start + 1, _end(text, start) - 1))
        entries = []
        for start, end in regions:
            for match in re.finditer(r"(['\"])([0-9a-fA-F]{4})\1\s*=>\s*", text[start:end]):
                entries.append((start + match.start(), int(match[2], 16), start + match.end()))
        for match in re.finditer(r"\$self\s*->\s*\{packet_list\}\s*\{\s*(['\"])([0-9a-fA-F]{4})\1\s*\}\s*=\s*", text):
            entries.append((match.start(), int(match[2], 16), match.end()))
        for offset, packet_id, start in sorted(entries):
            line = text.count("\n", 0, offset) + 1
            try:
                metadata, end = _entry(text, start, packet_id, packet_lengths)
                if text[end:].lstrip()[:1] not in (",", ";", ")", "}"):
                    raise ValueError("expression after literal")
            except (ValueError, IndexError):
                result.pop(packet_id, None)
                warnings.warn(f"{path}:{line}: dynamic/unsupported packet {packet_id:04X} omitted", SemanticsWarning, stacklevel=2)
                continue
            metadata.update(source_path=str(path.relative_to(root)), source_line=line)
            result[packet_id] = metadata
        active.remove(name)
        cache[name] = result
        return dict(result)

    return visit(class_name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("src_root")
    parser.add_argument("class_name")
    args = parser.parse_args()
    print(json.dumps({f"{key:04X}": value for key, value in sorted(load_semantics(args.src_root, args.class_name).items())}, indent=2))


if __name__ == "__main__":
    main()
