"""Read-only access to the game's memory through /proc/<pid>/mem (never pauses the game)."""
import os

MAX_REGION = 0x4000000                             # scans skip rw regions larger than 64 MiB


def regions(pid, writable=True, max_size=None, paths=None):
    """Yield (lo, hi, path) for each mapping of `pid`. `paths`: allowed path names
    ('' = anonymous), None = any."""
    with open(f'/proc/{pid}/maps') as f:
        for line in f:
            fields = line.split(maxsplit=5)
            lo, hi = (int(x, 16) for x in fields[0].split('-'))
            path = fields[5].strip() if len(fields) > 5 else ''
            if writable and not fields[1].startswith('rw'):
                continue
            if max_size is not None and hi - lo > max_size:
                continue
            if paths is not None and path not in paths:
                continue
            yield lo, hi, path


def region_at(pid, lo):
    """(lo, hi) of the mapping that starts exactly at `lo`, or None."""
    return next(((a, b) for a, b, _ in regions(pid, writable=False) if a == lo), None)


class ProcessMemory:
    def __init__(self, pid):
        self.pid = pid
        self.fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY)

    def read(self, addr, n):
        """Up to n bytes at addr; b'' if unmapped."""
        try:
            return os.pread(self.fd, n, addr)
        except OSError:
            return b''


class ProcessMemoryWriter:
    """Read/write access to the game's memory through /proc/<pid>/mem (never pauses the game).

    The rest of the driver only reads; this is the one writer, used by inject.SendInjector to
    plant a packet in the client's send queue. A single pwrite lands atomically for the lengths
    we write (one packet), so the client never sees a torn slot."""

    def __init__(self, pid):
        self.pid = pid
        self.fd = os.open(f'/proc/{pid}/mem', os.O_RDWR)

    def read(self, addr, n):
        """Up to n bytes at addr; b'' if unmapped."""
        try:
            return os.pread(self.fd, n, addr)
        except OSError:
            return b''

    def write(self, addr, data):
        """Write `data` at addr; bytes written, or 0 if the span isn't writable."""
        try:
            return os.pwrite(self.fd, data, addr)
        except OSError:
            return 0
