"""libei sender for a *specific* Gamescope EIS socket (never the KDE seat).

Calls are restricted to one background actuator thread at a time by a lock.
Does not use xdotool, ydotool, KDE focus, portals or /dev/uinput.
"""
import ctypes
import os
import select
import stat
import threading
import time

# libei 1.6+ capability values are bit flags; keyboard == 1 << 2.
_CAP_KEYBOARD = 4


class GamescopeEISError(RuntimeError):
    pass


def resolve_socket(path="", path_file=""):
    """Resolve an explicitly selected Gamescope EIS socket, refusing implicit KDE input."""
    if path and path_file:
        raise GamescopeEISError("provide only one of --synth-eis-socket / --synth-eis-socket-file")
    if path_file:
        try:
            st = os.stat(path_file)
            if st.st_uid != os.getuid() or st.st_mode & 0o077:
                raise GamescopeEISError("EIS path file must be owned by this user and private (0600)")
            with open(path_file, encoding="utf-8") as f:
                path = f.read().strip()
        except OSError as e:
            raise GamescopeEISError("cannot read EIS path file: %s" % e) from e
    if not path:
        raise GamescopeEISError("Gamescope EIS socket not provided; refusing to send to desktop seat")
    if chr(0) in path or chr(10) in path:
        raise GamescopeEISError("invalid EIS socket path")
    if not os.path.isabs(path):
        runtime = os.environ.get("XDG_RUNTIME_DIR")
        if not runtime:
            raise GamescopeEISError("XDG_RUNTIME_DIR missing for relative EIS socket")
        path = os.path.join(runtime, path)
    # Never route to the KDE compositor's own EIS socket, even if a private
    # locator file or a symlink mistakenly points at it. Fail closed.
    if not os.path.basename(os.path.realpath(path)).startswith('gamescope-'):
        raise GamescopeEISError('EIS target is not a Gamescope socket: %s' % path)
    try:
        if not stat.S_ISSOCK(os.stat(path).st_mode):
            raise GamescopeEISError("EIS target is not a Unix socket: %s" % path)
    except OSError as e:
        raise GamescopeEISError("Gamescope EIS socket unavailable: %s" % path) from e
    return path


class _LibEI:
    def __init__(self, library=None):
        if library is None:
            try:
                library = ctypes.CDLL("libei.so.1")
            except OSError as e:
                raise GamescopeEISError("libei.so.1 not installed") from e
        self.lib = library
        P, I, U, B = ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_bool
        def api(name, result, *args):
            fn = getattr(library, name)
            fn.restype, fn.argtypes = result, list(args)
            return fn
        self.new = api("ei_new_sender", P, P)
        self.name = api("ei_configure_name", None, P, ctypes.c_char_p)
        self.setup = api("ei_setup_backend_socket", I, P, ctypes.c_char_p)
        self.fd = api("ei_get_fd", I, P)
        self.dispatch = api("ei_dispatch", None, P)
        self.get_event = api("ei_get_event", P, P)
        self.event_type = api("ei_event_type_to_string", ctypes.c_char_p, I)
        self.ev_kind = api("ei_event_get_type", I, P)
        self.ev_seat = api("ei_event_get_seat", P, P)
        self.ev_device = api("ei_event_get_device", P, P)
        self.ev_unref = api("ei_event_unref", P, P)
        self.bind = api("ei_seat_bind_capabilities", None, P)  # varargs, NULL-terminated
        self.has_cap = api("ei_device_has_capability", B, P, I)
        self.device_ref = api("ei_device_ref", P, P)
        self.device_unref = api("ei_device_unref", P, P)
        self.emulate = api("ei_device_start_emulating", None, P, U)
        self.key = api("ei_device_keyboard_key", None, P, U, B)
        self.now = api("ei_now", ctypes.c_uint64, P)
        self.frame = api("ei_device_frame", None, P, ctypes.c_uint64)
        self.unref = api("ei_unref", P, P)


class GamescopeEIS:
    """Keyboard on one nominated Gamescope socket. No seat0 fallback, ever."""

    def __init__(self, socket="", socket_file="", library=None, connect_timeout=2.0):
        self.socket = socket
        self.socket_file = socket_file
        self.timeout = connect_timeout
        self._library = library
        self.api = None  # libei is loaded only for real sends, not --synth-dry
        self._lock = threading.Lock()
        self.ctx = None
        self.dev = None
        self.ready = False

    def close(self):
        # Called while holding lock or when object no longer used.
        if self.dev:
            self.api.device_unref(self.dev)
            self.dev = None
        if self.ctx:
            self.api.unref(self.ctx)
            self.ctx = None
        self.ready = False

    def _drain_events(self):
        self.api.dispatch(self.ctx)
        while True:
            ev = self.api.get_event(self.ctx)
            if not ev:
                break
            try:
                kind = self.api.event_type(self.api.ev_kind(ev))
                if kind == b"EI_EVENT_DISCONNECT":
                    raise GamescopeEISError("Gamescope EIS disconnected")
                if kind == b"EI_EVENT_SEAT_ADDED":
                    seat = self.api.ev_seat(ev)
                    if seat:
                        self.api.bind(seat, ctypes.c_int(_CAP_KEYBOARD), ctypes.c_void_p(None))
                elif kind == b"EI_EVENT_DEVICE_ADDED":
                    device = self.api.ev_device(ev)
                    if device and self.api.has_cap(device, _CAP_KEYBOARD) and not self.dev:
                        self.dev = self.api.device_ref(device)
                elif kind == b"EI_EVENT_DEVICE_REMOVED":
                    if self.dev == self.api.ev_device(ev):
                        self.api.device_unref(self.dev)
                        self.dev, self.ready = None, False
                elif kind == b"EI_EVENT_DEVICE_PAUSED":
                    if self.dev == self.api.ev_device(ev):
                        self.ready = False
                elif kind == b"EI_EVENT_DEVICE_RESUMED":
                    if self.dev == self.api.ev_device(ev):
                        self.api.emulate(self.dev, 0)
                        self.ready = True
            finally:
                self.api.ev_unref(ev)

    def _connect(self):
        path = resolve_socket(self.socket, self.socket_file)
        if self.api is None:
            self.api = _LibEI(self._library)
        self.ctx = self.api.new(None)
        if not self.ctx:
            raise GamescopeEISError("ei_new_sender failed")
        try:
            self.api.name(self.ctx, b"RO-Client-Relay synth")
            result = self.api.setup(self.ctx, os.fsencode(path))
            if result < 0:
                raise GamescopeEISError("EIS connection refused: error %d" % result)
            fd = self.api.fd(self.ctx)
            if fd < 0:
                raise GamescopeEISError("libei returned invalid descriptor")
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                self._drain_events()
                if self.ready:
                    return
                rem = max(0, deadline - time.monotonic())
                select.select([fd], [], [], min(rem, 0.15))
            raise GamescopeEISError("EIS keyboard device not ready (timeout)")
        except Exception:
            self.close()
            raise

    def send_key(self, keycode, hold_ms=120):
        with self._lock:
            if self.ctx:
                try:
                    self._drain_events()
                except GamescopeEISError:
                    self.close()
            if not self.ready:
                self.close()
                self._connect()
            dev = self.dev
            try:
                # Always try key-up, including if an exception occurs after key-down.
                try:
                    self.api.key(dev, int(keycode), True)
                    self.api.frame(dev, self.api.now(self.ctx))
                    self.api.dispatch(self.ctx)  # flush key-down BEFORE the 120ms hold
                    time.sleep(max(0, hold_ms) / 1000.0)
                finally:
                    self.api.key(dev, int(keycode), False)
                    self.api.frame(dev, self.api.now(self.ctx))
                    self.api.dispatch(self.ctx)  # always flush key-up
                self._drain_events()
                if not self.ready:
                    raise GamescopeEISError("EIS keyboard disconnected during event")
                return 0
            except BaseException:
                # Transport/key failure must not leave a stale 'ready' context
                # reused on the next synthetic action.
                self.close()
                raise
