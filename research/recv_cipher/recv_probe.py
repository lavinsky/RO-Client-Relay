#!/usr/bin/env python3
"""Bounded Frida Gadget receive-callsite observation; no ptrace or production hooks."""
import argparse
import json
import time
from pathlib import Path
import frida
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import threading
from ring_correlator import RingCorrelator
from sample_telemetry import RingSampleTelemetry

JS = r'''
'use strict';
var calls=0, maxCalls=/*MAX_CALLS*/, hooks=[];
var allowedFds=/*FD_ALLOWLIST*/;
var startMs=Date.now(), lastRecvMs=0;
var totalBytes=0, gapsShort=0, gapsLong=0, stackSamples=0;
var fdKinds={};
var payloadSamples=0;
var ringBase=null, ringSnapCount=0;
function locate(addr){
  try { var m=Process.findModuleByAddress(addr); return m ? m.name+'+'+addr.sub(m.base).toString() : addr.toString(); }
  catch(_) { return addr.toString(); }
}
function fdKind(fd){
  // FD numbers only; avoid file-system calls inside a recv hook.
  return 'unclassified';
}
function note(kind, data){ send(Object.assign({kind:kind,ms:Date.now(),tid:Process.getCurrentThreadId()},data)); }
/* WATCH_HELPERS */
/* WRITE_HELPERS */
var recvSequence=0, recvByThread={};
var found=[];
['recvmsg','__recvmsg64','recv','recvfrom'].forEach(function(name){
  try {var f=Module.findGlobalExportByName(name); if(!f || found.some(function(x){return x.equals(f)}))return;found.push(f);
    var hook=Interceptor.attach(f,{onEnter:function(args){this.fd=args[0].toInt32();this.buf=args[1];this.msg=null;this.iov=null;this.iovcnt=0;if(name==='recvmsg'||name==='__recvmsg64'){try{this.msg=args[1];var off=Process.pointerSize===8?16:8;this.iov=this.msg.add(off).readPointer();this.iovcnt=this.msg.add(off+Process.pointerSize).readU32();}catch(_){}}this.retloc=this.returnAddress;this.caller=locate(this.retloc);this.wanted=calls<maxCalls && allowedFds.indexOf(this.fd)>=0;
      if(this.wanted && ringBase!==null && ringSnapCount<maxCalls){
        try {
          var snap=ringBase.readByteArray(16384);ringSnapCount++;
          send({kind:'ring_snapshot',fd:this.fd,ms:Date.now(),base:ringBase.toString(),seq:ringSnapCount},snap);
        }catch(e){ringSnapCount++;note('ring_snapshot_error',{error:String(e).slice(0,180)});}
      }
    },
      onLeave:function(rv){if(!this.wanted || rv.toInt32()<=0)return; calls++; recvSequence++; recvByThread[Process.getCurrentThreadId()]={seq:recvSequence,fd:this.fd,ms:Date.now()};
       var now=Date.now(), gap=lastRecvMs ? now-lastRecvMs : null;lastRecvMs=now;totalBytes+=rv.toInt32();if(gap!==null){if(gap<=50)gapsShort++;else gapsLong++;}
       var payload=null;if(payloadSamples<maxCalls){try{var left=Math.min(rv.toInt32(),4096),out=[];if(this.iov && this.iovcnt>0 && this.iovcnt<=64){for(var j=0;j<this.iovcnt && left>0;j++){var entry=this.iov.add(j*Process.pointerSize*2),b=entry.readPointer(),len=Process.pointerSize===8?entry.add(8).readU64().toNumber():entry.add(4).readU32(),take=Math.min(left,len);if(take<=0)continue;var bytes=new Uint8Array(b.readByteArray(take));for(var k=0;k<bytes.length;k++)out.push(bytes[k]);left-=take;}}else if(name==='recv'||name==='recvfrom'){var bytes=new Uint8Array(this.buf.readByteArray(left));for(var k=0;k<bytes.length;k++)out.push(bytes[k]);}if(out.length){payload=out;payloadSamples++;}}catch(_){}}
       var sample=null;if(stackSamples<8){stackSamples++;try{sample=Thread.backtrace(this.context,Backtracer.ACCURATE).slice(0,10).map(locate);}catch(e){sample=['unavailable'];}}
       if (typeof ringArm === 'function' && ringBase !== null) ringArm(this.fd);
       note('recv', {recv_seq:recvSequence,fn:name,bytes:rv.toInt32(),relative_ms:now-startMs,gap_ms:gap,return_pc:this.caller,return_address:this.retloc.toString(),fd:this.fd,fd_kind:fdKind(this.fd),stack:sample,payload:payload ? payload.map(function(v){return ('0'+v.toString(16)).slice(-2)}).join('') : null});
      }});hooks.push(hook);note('armed',{fn:name,address:f.toString()});
  } catch(e){note('error',{fn:name,error:String(e)});}
});
rpc.exports={setring:function(base){ringBase=ptr(base);if(typeof ringVerified==='function')ringVerified(base);if(typeof writerStart==='function')writerStart();return true;},stop:function(){if(typeof writerStop==='function')writerStop();if(typeof ringDisarm==='function')ringDisarm('cleanup');hooks.forEach(function(h){try{h.detach()}catch(_){}});hooks=[];return{ok:true,calls:calls,total_bytes:totalBytes,gaps_le_50ms:gapsShort,gaps_gt_50ms:gapsLong};}};
'''

def main():
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--seconds',type=float,default=8);p.add_argument('--max-calls',type=int,default=160);p.add_argument('--pid',type=int,required=True);a=p.parse_args()
    if not 1<=a.seconds<=60: raise SystemExit('seconds must be 1..60')
    if not 1<=a.max_calls<=1500: raise SystemExit('max-calls must be 1..1500')
    # Classify sockets from procfs before installing hooks; no ptrace.
    import os
    socket_map={}
    for kind in ('tcp','tcp6','udp','udp6','unix'):
        try:
            lines=Path(f'/proc/{a.pid}/net/{kind}').read_text().splitlines()[1:]
            for line in lines:
                fields=line.split()
                idx=6 if kind=='unix' else 9
                if len(fields)>idx: socket_map[fields[idx]]=kind
        except OSError: pass
    fd_classes={}
    try:
        for fd in os.listdir(f'/proc/{a.pid}/fd'):
            try:
                target=os.readlink(f'/proc/{a.pid}/fd/{fd}')
                if target.startswith('socket:['):
                    inode=target[8:-1]
                    fd_classes[int(fd)]=socket_map.get(inode,'socket-unknown')
            except (OSError,ValueError): pass
    except OSError: pass
    d=frida.get_device_manager().add_remote_device(f'127.0.0.1:{a.port}')
    session=None; script=None; errors=[]
    lock=threading.Lock()
    with a.out.open('x') as f:
        def emit(x):
            with lock:
                f.write(json.dumps(x)+'\n')
                f.flush()
        correlator=RingCorrelator(a.pid,emit,max_candidates=a.max_calls)
        correlator.start()
        emit({'kind':'actor_core_configuration','engine':'relay.actors.ActorDecrypt',
              'policy':'scored-context-plus-expected-slot','production_relay_modified':False})
        sampler=RingSampleTelemetry(a.pid)
        sampler.start()
        try:
            emit({'kind':'fd_inventory','classes':fd_classes})
            session=d.attach('Gadget')
            source=JS.replace('/*MAX_CALLS*/',str(a.max_calls)).replace('/*FD_ALLOWLIST*/',json.dumps([fd for fd,k in fd_classes.items() if k in ('tcp','tcp6')]))
            import os
            watch_enabled=os.environ.get('RECV_WATCH_BP')=='1'
            watch_code=(Path(__file__).with_name('ring_watch.js').read_text() if watch_enabled else '')
            source=source.replace('/* WATCH_HELPERS */',watch_code)
            write_pc=os.environ.get('RECV_WRITE_PC', '').strip()
            write_code=(Path(__file__).with_name('write_trace.js').read_text() if write_pc else '')
            source=source.replace('/* WRITE_HELPERS */', write_code.replace('/*WRITE_ADDRESS*/',json.dumps(write_pc)))
            emit({'kind':'write_hook_configuration','enabled':bool(write_pc),'address_source':'session-verified-address' if write_pc else None})
            emit({'kind':'ring_watch_configuration','enabled':watch_enabled})
            script=session.create_script(source)
            def verified_ring(base):
                sampler.set_base(base)
                try: script.exports_sync.setring(hex(base))
                except Exception as e: emit({'kind':'ring_snapshot_error','error':str(e)[:200]})
            correlator.on_verified=verified_ring
            def message(m,data):
                if m['type']=='send':
                    x=m['payload'];
                    if x.get('kind')=='ring_snapshot':
                        correlator.snapshot(x,data)
                        return
                    if x.get('kind')=='recv':
                        x['fd_kind']=fd_classes.get(x.get('fd'),'unclassified')
                        if x['fd_kind'] not in ('tcp','tcp6'): return
                    emit(x)
                    if x.get('kind')=='recv': correlator.receive(x)
                else: errors.append(str(m)[:300])
            script.on('message',message);script.load()
            time.sleep(a.seconds)
        finally:
            sampling_stats=sampler.stop()
            correlator.stop()
            frames=sampler.take_frames()
            correlator.replay_frames(frames)
            emit({'kind':'ring_1ms_telemetry','interval_ms':1,'stats':sampling_stats,
                  'replay_frames':len(frames),'replay_matched':correlator.stats['replay_matched']})
            if script:
                try:
                    result=script.exports_sync.stop(); emit({'kind':'cleanup','result':result})
                except Exception as e: errors.append('stop:'+str(e))
                try:script.unload()
                except Exception as e:errors.append('unload:'+str(e))
            if session:
                try:session.detach()
                except Exception as e:errors.append('detach:'+str(e))
            if errors:
                emit({'kind':'errors','messages':errors})
    print('Frida recv-callsite observation finished; output:',a.out,'errors:',len(errors))
    if errors: raise SystemExit(2)
if __name__=='__main__':main()
