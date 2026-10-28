"""Build-scoped client profiles and executable fingerprinting.

This module intentionally uses only the Python standard library so profile
verification stays available before Frida or reverse-engineering dependencies
are loaded. Profiles are data: the relay core should not learn build-specific
addresses directly.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct


class ProfileError(ValueError):
    """Invalid profile data or an executable that does not match its profile."""


@dataclass(frozen=True)
class ClientFingerprint:
    sha256: str
    size: int
    machine: int
    pe_timestamp: int
    optional_magic: int
    image_base: int
    size_of_image: int

    @classmethod
    def from_file(cls, path):
        path = Path(path)
        data = path.read_bytes()
        if len(data) < 0x40 or data[:2] != b'MZ':
            raise ProfileError(f'{path}: not a DOS/PE executable')
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b'PE\0\0':
            raise ProfileError(f'{path}: missing PE signature')

        file_header = pe_off + 4
        machine, _sections, pe_timestamp = struct.unpack_from('<HHI', data, file_header)
        optional = file_header + 20
        if optional + 60 > len(data):
            raise ProfileError(f'{path}: truncated PE optional header')
        optional_magic = struct.unpack_from('<H', data, optional)[0]
        if optional_magic == 0x10B:       # PE32
            image_base = struct.unpack_from('<I', data, optional + 28)[0]
        elif optional_magic == 0x20B:     # PE32+
            image_base = struct.unpack_from('<Q', data, optional + 24)[0]
        else:
            raise ProfileError(f'{path}: unsupported PE optional magic 0x{optional_magic:x}')
        size_of_image = struct.unpack_from('<I', data, optional + 56)[0]

        return cls(
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            machine=machine,
            pe_timestamp=pe_timestamp,
            optional_magic=optional_magic,
            image_base=image_base,
            size_of_image=size_of_image,
        )

    def as_dict(self):
        return {
            'sha256': self.sha256,
            'size': self.size,
            'machine': self.machine,
            'pe_timestamp': self.pe_timestamp,
            'optional_magic': self.optional_magic,
            'image_base': self.image_base,
            'size_of_image': self.size_of_image,
        }


@dataclass(frozen=True)
class ClientProfile:
    name: str
    fingerprint: dict
    native: dict
    source: Path | None = None

    @classmethod
    def load(cls, path):
        path = Path(path)
        try:
            raw = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileError(f'{path}: cannot load profile: {exc}') from exc
        if not isinstance(raw, dict) or not isinstance(raw.get('name'), str):
            raise ProfileError(f'{path}: profile requires string field "name"')
        fingerprint = raw.get('fingerprint')
        if not isinstance(fingerprint, dict) or not fingerprint.get('sha256'):
            raise ProfileError(f'{path}: profile requires fingerprint.sha256')
        native = raw.get('native', {})
        if not isinstance(native, dict):
            raise ProfileError(f'{path}: native must be an object')
        return cls(raw['name'], fingerprint, native, path)

    def native_group(self, name):
        group = self.native.get(name, {})
        if not isinstance(group, dict):
            raise ProfileError(f'{self.source or self.name}: native.{name} must be an object')
        return group

    def native_int(self, group, field, default=None):
        value = self.native_group(group).get(field, default)
        if value is None:
            raise ProfileError(f'{self.source or self.name}: missing native.{group}.{field}')
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError as exc:
                raise ProfileError(
                    f'{self.source or self.name}: native.{group}.{field} must be an integer'
                ) from exc
        raise ProfileError(f'{self.source or self.name}: native.{group}.{field} must be an integer')

    def verify_executable(self, executable):
        actual = ClientFingerprint.from_file(executable)
        expected = self.fingerprint
        mismatches = []
        for key, wanted in expected.items():
            if not hasattr(actual, key):
                raise ProfileError(f'{self.source or self.name}: unknown fingerprint field {key!r}')
            got = getattr(actual, key)
            if isinstance(got, int) and isinstance(wanted, str):
                try:
                    wanted = int(wanted, 0)
                except ValueError:
                    pass
            if got != wanted:
                mismatches.append(f'{key}: expected {wanted!r}, got {got!r}')
        if mismatches:
            raise ProfileError(f'{executable}: profile {self.name!r} mismatch: ' + '; '.join(mismatches))
        return actual
