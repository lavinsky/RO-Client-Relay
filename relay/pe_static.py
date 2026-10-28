"""Small PE/MSVC-RTTI helpers used by offline client discovery.

This is intentionally not a general PE parser. It implements only the stable
facts the relay needs for build fingerprinting/discovery and stays dependency
free so it can run on a clean project checkout.
"""
from dataclasses import dataclass
from pathlib import Path
import struct


IMAGE_SCN_MEM_EXECUTE = 0x20000000


@dataclass(frozen=True)
class PESection:
    name: str
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def executable(self):
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)


class PEImage:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if len(self.data) < 0x40 or self.data[:2] != b'MZ':
            raise ValueError(f'{self.path}: not a PE executable')
        self.pe_offset = struct.unpack_from('<I', self.data, 0x3C)[0]
        if self.data[self.pe_offset:self.pe_offset + 4] != b'PE\0\0':
            raise ValueError(f'{self.path}: missing PE signature')

        fh = self.pe_offset + 4
        self.machine, section_count = struct.unpack_from('<HH', self.data, fh)
        optional_size = struct.unpack_from('<H', self.data, fh + 16)[0]
        optional = fh + 20
        self.optional_magic = struct.unpack_from('<H', self.data, optional)[0]
        if self.optional_magic == 0x10B:
            self.image_base = struct.unpack_from('<I', self.data, optional + 28)[0]
        elif self.optional_magic == 0x20B:
            self.image_base = struct.unpack_from('<Q', self.data, optional + 24)[0]
        else:
            raise ValueError(f'{self.path}: unsupported PE optional magic 0x{self.optional_magic:x}')

        section_table = optional + optional_size
        self.sections = []
        for i in range(section_count):
            off = section_table + i * 40
            if off + 40 > len(self.data):
                raise ValueError(f'{self.path}: truncated section table')
            raw_name = self.data[off:off + 8].split(b'\0', 1)[0]
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', self.data, off + 8)
            characteristics = struct.unpack_from('<I', self.data, off + 36)[0]
            self.sections.append(PESection(
                raw_name.decode('ascii', errors='replace').strip(),
                rva, virtual_size, raw_offset, raw_size, characteristics,
            ))

    def section_for_offset(self, offset):
        return next((s for s in self.sections
                     if s.raw_offset <= offset < s.raw_offset + s.raw_size), None)

    def section_for_va(self, va):
        rva = va - self.image_base
        return next((s for s in self.sections
                     if s.rva <= rva < s.rva + max(s.virtual_size, s.raw_size)), None)

    def offset_to_va(self, offset):
        section = self.section_for_offset(offset)
        if section is None:
            return None
        return self.image_base + section.rva + offset - section.raw_offset

    def va_to_offset(self, va):
        section = self.section_for_va(va)
        if section is None:
            return None
        offset = section.raw_offset + (va - self.image_base - section.rva)
        if offset >= section.raw_offset + section.raw_size:
            return None
        return offset

    def is_executable_va(self, va):
        section = self.section_for_va(va)
        return bool(section and section.executable)

    def find_all(self, needle):
        start = 0
        while True:
            start = self.data.find(needle, start)
            if start < 0:
                return
            yield start
            start += 1

    def refs_to_va(self, va):
        if not 0 <= va <= 0xFFFFFFFF:
            return []
        return list(self.find_all(struct.pack('<I', va)))

    def read_u32(self, offset):
        return struct.unpack_from('<I', self.data, offset)[0]

    def executable_vtable(self, vtable_va, limit=256):
        off = self.va_to_offset(vtable_va)
        if off is None:
            return []
        entries = []
        for i in range(limit):
            pos = off + i * 4
            if pos + 4 > len(self.data):
                break
            target = self.read_u32(pos)
            if not self.is_executable_va(target):
                break
            entries.append(target)
        return entries


def _vtable_refs_for_type_descriptor(image, type_descriptor_va):
    """Return (vtable VA, methods) pairs from x86 MSVC RTTI structures."""
    results = []
    for td_ref in image.refs_to_va(type_descriptor_va):
        col_off = td_ref - 12
        if col_off < 0 or col_off + 20 > len(image.data):
            continue
        signature, obj_offset, cd_offset = struct.unpack_from('<III', image.data, col_off)
        if signature not in (0, 1) or obj_offset >= 0x10000 or cd_offset >= 0x10000:
            continue
        col_va = image.offset_to_va(col_off)
        if col_va is None:
            continue
        for col_ref in image.refs_to_va(col_va):
            vtable_va = image.offset_to_va(col_ref)
            if vtable_va is None:
                continue
            vtable_va += 4  # MSVC stores CompleteObjectLocator at vftable[-1].
            methods = image.executable_vtable(vtable_va)
            if methods and (vtable_va, methods) not in results:
                results.append((vtable_va, methods))
    return results


def vtables_for_rtti_name(image, rtti_name):
    """Find x86 MSVC vtables for an exact decorated RTTI type name."""
    needle = rtti_name if isinstance(rtti_name, bytes) else rtti_name.encode('ascii')
    if not needle.endswith(b'\0'):
        needle += b'\0'
    results = []
    for name_off in image.find_all(needle):
        name_va = image.offset_to_va(name_off)
        if name_va is None or name_off < 8:
            continue
        # MSVC x86 TypeDescriptor is {vftable, spare, name[]}.
        td_va = image.offset_to_va(name_off - 8)
        if td_va is None:
            continue
        for entry in _vtable_refs_for_type_descriptor(image, td_va):
            if entry not in results:
                results.append(entry)
    return results


def class_vtables(image, class_name):
    return vtables_for_rtti_name(image, f'.?AV{class_name}@@')


def relative_call_present(image, start_va, end_va, target_va):
    """Conservative scan for x86 E8 rel32 calls inside a validated function span."""
    start = image.va_to_offset(start_va)
    end = image.va_to_offset(end_va - 1)
    if start is None or end is None:
        return False
    end += 1
    data = image.data
    for off in range(start, max(start, end - 4)):
        if data[off] != 0xE8:
            continue
        insn_va = image.offset_to_va(off)
        rel = struct.unpack_from('<i', data, off + 1)[0]
        if insn_va is not None and insn_va + 5 + rel == target_va:
            return True
    return False
