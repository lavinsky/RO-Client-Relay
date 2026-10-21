"""Opt-in read-only packet mirror with bounded in-memory login/char/map replay.

The relay keeps its existing XKore1 consumer. The observer listens only on a
0600 UNIX socket, never forwards client-generated commands and never logs raw
login packets. Each viewer selects one connection phase (L/C/M) with one byte.
"""
from collections import deque
import os
import queue
import socket
import stat
import threading


PHASES = {b'L': 'login', b'C': 'char', b'M': 'map'}
MAX_HISTORY = 32 * 1024 * 1024


class PacketObserver:
    FRAME_MAX = 0xFFFF

    @staticmethod
    def frame(payload):
        # Always XKore1 R framing, independent of the main Relay format.
        if not payload:
            return b''
        out = []
        for off in range(0, len(payload), PacketObserver.FRAME_MAX):
            chunk = payload[off:off + PacketObserver.FRAME_MAX]
            out.append(b'R' + len(chunk).to_bytes(2, 'little') + chunk)
        return b''.join(out)

    def __init__(self, pathname):
        self.pathname = pathname
        parent = os.path.dirname(pathname)
        try:
            parent_st = os.stat(parent)
        except OSError as e:
            raise ValueError("observer socket parent is unavailable") from e
        if (not stat.S_ISDIR(parent_st.st_mode) or parent_st.st_uid != os.getuid()
                or parent_st.st_mode & 0o077):
            raise ValueError("observer socket parent must be user-owned private directory (0700)")
        if os.path.lexists(pathname):
            raise FileExistsError("observer socket already exists")
        self.sock = socket.socket(socket.AF_UNIX)
        try:
            self.sock.bind(pathname)
            os.chmod(pathname, stat.S_IRUSR | stat.S_IWUSR)
            bound_st = os.lstat(pathname)
            self._socket_identity = (bound_st.st_dev, bound_st.st_ino)
            self.sock.listen(2)
            self.sock.settimeout(0.5)
        except BaseException:
            self.sock.close()
            raise
        self.closed = False
        self.lock = threading.Lock()
        self.clients = {}  # socket -> (phase, bounded queue)
        self.history = {phase: deque() for phase in PHASES.values()}
        self.history_size = 0
        self.replay_valid = False
        self.session = None
        threading.Thread(target=self._accept, daemon=True, name="observer-accept").start()

    def begin_session(self, connection):
        """An observed real login-server connection starts a new replay epoch."""
        with self.lock:
            if self.closed or self.session == connection:
                return
            self.session = connection
            self.history = {phase: deque() for phase in PHASES.values()}
            self.history_size = 0
            self.replay_valid = True
            # Old browser sessions must restart their parsers at login.
            clients = list(self.clients)
            self.clients.clear()
        for sock in clients:
            sock.close()

    def _accept(self):
        while not self.closed:
            try:
                client, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(client,), daemon=True,
                             name="observer-writer").start()

    def _serve(self, client):
        try:
            client.settimeout(5)
            phase = PHASES.get(client.recv(1))
            if not phase:
                return
            with self.lock:
                if self.closed or len(self.clients) >= 2:
                    return
                work = queue.Queue(maxsize=64)
                self.clients[client] = (phase, work)
                # Snapshot and subscriber insertion are atomic: new packets go
                # into work and cannot overtake historical bytes.
                initial = list(self.history[phase]) if self.replay_valid else []
            client.settimeout(2)
            for frame in initial:
                client.sendall(frame)
            while not self.closed:
                try:
                    frame = work.get(timeout=20)
                except queue.Empty:
                    continue  # remain subscribed during server idle periods
                client.sendall(frame)
        except OSError:
            pass
        finally:
            with self.lock:
                self.clients.pop(client, None)
            client.close()

    def publish(self, frame, phase='map'):
        if not frame or self.closed or phase not in PHASES.values():
            return
        with self.lock:
            if self.closed:
                return
            if self.replay_valid:
                if self.history_size + len(frame) > MAX_HISTORY:
                    # Truncated history could desynchronize a late viewer.
                    self.replay_valid = False
                    self.history = {role: deque() for role in PHASES.values()}
                    self.history_size = 0
                else:
                    self.history[phase].append(frame)
                    self.history_size += len(frame)
            for sock, (role, work) in tuple(self.clients.items()):
                if role != phase:
                    continue
                try:
                    work.put_nowait(frame)
                except queue.Full:
                    # Drop the whole viewer, never a frame in the parser's stream.
                    self.clients.pop(sock, None)
                    sock.close()

    def close(self):
        with self.lock:
            self.closed = True
            clients = list(self.clients)
            self.clients.clear()
            self.history.clear()
            self.history_size = 0
            self.replay_valid = False
            self.session = None
        self.sock.close()
        for sock in clients:
            sock.close()
        try:
            current = os.lstat(self.pathname)
            if (stat.S_ISSOCK(current.st_mode)
                    and (current.st_dev, current.st_ino) == self._socket_identity):
                os.unlink(self.pathname)
        except FileNotFoundError:
            pass
