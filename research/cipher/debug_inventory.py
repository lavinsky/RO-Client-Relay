"""Bounded read-only inventory of Linux x86 debug registers, without Frida.

PTRACE_SEIZE/INTERRUPT briefly stop one thread; no debug register is written.
This cannot inspect a Gadget exception handler or establish human exclusivity.
Seizing changes TracerPid temporarily and may be visible to anti-debug checks.
Client use is suspended after an unexplained exit; prefer cooperative ownership.
"""
import argparse
import ctypes
import os
import platform
from pathlib import Path
import signal
import sys
import time

sys.dont_write_bytecode = True
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from research.cipher.core import json_bytes, private_write, require


class LinuxPtrace:
    """Offsets follow the tracer's native struct user ABI (sys/user.h)."""
    def __init__(self):
        bits = ctypes.sizeof(ctypes.c_void_p)*8
        require(platform.machine().lower() in ('x86_64','amd64','i386','i686'), 'unsupported ptrace ABI')
        self.offset, self.width = (848,8) if bits == 64 else (252,4)
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.ptrace.argtypes = [ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p]
        self.libc.ptrace.restype = ctypes.c_long

    def _call(self, request, pid, address=0, data=0):
        ctypes.set_errno(0)
        value=self.libc.ptrace(request,pid,ctypes.c_void_p(address),ctypes.c_void_p(data))
        error=ctypes.get_errno()
        if value == -1 and error:
            raise OSError(error, os.strerror(error))
        return value

    def seize(self,pid): self._call(0x4206,pid)
    def interrupt(self,pid): self._call(0x4207,pid)
    def wait(self,pid): return os.waitpid(pid,os.WNOHANG|0x40000000)
    def read(self,pid,register): return self._call(3,pid,self.offset+self.width*register)
    def detach(self,pid,resume_signal): self._call(17,pid,0,resume_signal)


def snapshot(pid, backend=None, now=time.monotonic, sleep=time.sleep, timeout=0.1):
    """Doubles test stop/error/detach; they do not prove safety in a client."""
    require(type(pid) is int and pid>0 and 0<timeout<=0.1,'invalid debug inventory limits')
    backend=backend or LinuxPtrace()
    result=dict(status='undetermined',cleanup_confirmed=True,enabled_slots=None,
        register_indices_read=[],debug_registers_changed=False,client_data_read=False,
        handler_ownership='not_determined',coverage='one Linux thread')
    attached=stopped=gone=False
    resume_signal=0
    began=now()

    def wait_stop(deadline):
        nonlocal stopped,gone,resume_signal
        while now()<deadline:
            found,status=backend.wait(pid)
            if found:
                if os.WIFSTOPPED(status):
                    stopped=True
                    own=(status>>16)==128 and os.WSTOPSIG(status)==signal.SIGTRAP
                    resume_signal=0 if own else os.WSTOPSIG(status)
                    return own
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):gone=True;return False
            sleep(0.001)
        return False

    try:
        backend.seize(pid);attached=True
        backend.interrupt(pid)
        if not wait_stop(now()+timeout):
            result['reason']='stop_timeout_or_external_stop'
        else:
            for index in (0,1,2,3,6,7):
                value=backend.read(pid,index)
                result['register_indices_read'].append(index)
                if index==7:result['enabled_slots']=[i for i in range(4) if value&(3<<(2*i))]
            result['status']='occupied' if result['enabled_slots'] else 'free'
    except OSError as error:
        result.update(reason='ptrace_error',errno=error.errno)
    finally:
        if attached and not gone:
            if not stopped:
                try:
                    backend.interrupt(pid);wait_stop(now()+timeout)
                except OSError:
                    pass
            if stopped:
                try:backend.detach(pid,resume_signal)
                except OSError:
                    result['cleanup_confirmed']=False;result['status']='undetermined'
            elif not gone:
                result['cleanup_confirmed']=False;result['status']='undetermined'
        result['elapsed_ms']=round((now()-began)*1000,3)
        result['ptrace_ownership_temporarily_changed']=attached
        result['target_may_observe_tracing']=attached
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid',type=int,required=True)
    parser.add_argument('--starttime-ticks',type=int,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--allow-brief-stop',action='store_true',required=True,
        help='explicit scope must cover ptrace ownership/brief stop; not a passive /proc read')
    args=parser.parse_args()
    process=Path('/proc')/str(args.pid)
    require((process/'comm').read_text().strip().lower()=='uaro.exe','unexpected target')
    require(int((process/'stat').read_text().rsplit(')',1)[1].split()[19])==args.starttime_ticks,'process lifetime changed')
    status=dict(line.split(':',1) for line in (process/'status').read_text().splitlines() if ':' in line)
    require(status['TracerPid'].strip()=='0' and status['State'].strip()[0] not in 'TtZX','target traced/stopped/absent')
    result=snapshot(args.pid)
    private_write(args.out,'debug-inventory.json',json_bytes(result))
    print(json_bytes(result).decode().strip())
    return 0 if result['status']=='free' and result['cleanup_confirmed'] else 10


if __name__=='__main__':
    raise SystemExit(main())
