#!/usr/bin/env python3
"""Bounded Frida Gadget receive-callsite observation; no ptrace or production hooks."""
import argparse
import json
import time
from pathlib import Path
import frida

JS = r'''
'use strict';
var calls=0, maxCalls=80, hooks=[];
function locate(addr){
  try { var m=Process.findModuleByAddress(addr); return m ? m.name+'+'+addr.sub(m.base).toString() : addr.toString(); }
  catch(_) { return addr.toString(); }
}
function note(kind, data){ send(Object.assign({kind:kind,ms:Date.now(),tid:Process.getCurrentThreadId()},data)); }
var found=[];
['recvmsg','__recvmsg64','recv','recvfrom'].forEach(function(name){
  try {var f=Module.findGlobalExportByName(name); if(!f || found.some(function(x){return x.equals(f)}))return;found.push(f);
    var hook=Interceptor.attach(f,{onEnter:function(args){this.fd=args[0].toInt32();this.retloc=this.returnAddress;this.caller=locate(this.retloc);this.wanted=calls<maxCalls && !/libxcb|libwayland|libX11|libpulse|libasound/i.test(this.caller);},
      onLeave:function(rv){if(!this.wanted || rv.toInt32()<=0)return; calls++;
       note('recv', {fn:name,bytes:rv.toInt32(),return_pc:this.caller,return_address:this.retloc.toString()});
      }});hooks.push(hook);note('armed',{fn:name,address:f.toString()});
  } catch(e){note('error',{fn:name,error:String(e)});}
});
rpc.exports={stop:function(){hooks.forEach(function(h){try{h.detach()}catch(_){}});hooks=[];return{ok:true,calls:calls};}};
'''

def main():
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--seconds',type=float,default=8);a=p.parse_args()
    if not 1<=a.seconds<=15: raise SystemExit('seconds must be 1..15')
    d=frida.get_device_manager().add_remote_device(f'127.0.0.1:{a.port}')
    session=None; script=None; errors=[]
    with a.out.open('x') as f:
        try:
            session=d.attach('Gadget')
            script=session.create_script(JS)
            def message(m,data):
                if m['type']=='send':
                    x=m['payload'];f.write(json.dumps(x)+'\n');f.flush()
                else: errors.append(str(m)[:300])
            script.on('message',message);script.load()
            time.sleep(a.seconds)
        finally:
            if script:
                try:
                    result=script.exports_sync.stop(); f.write(json.dumps({'kind':'cleanup','result':result})+'\n');f.flush()
                except Exception as e: errors.append('stop:'+str(e))
                try:script.unload()
                except Exception as e:errors.append('unload:'+str(e))
            if session:
                try:session.detach()
                except Exception as e:errors.append('detach:'+str(e))
            if errors:
                f.write(json.dumps({'kind':'errors','messages':errors})+'\n');f.flush()
    print('Frida recv-callsite observation finished; output:',a.out,'errors:',len(errors))
    if errors: raise SystemExit(2)
if __name__=='__main__':main()
