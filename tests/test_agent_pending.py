"""Offline JS behavior checks for ordered substitutions and session invalidation."""
import pathlib
import subprocess
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

source = pathlib.Path('agent/relay_hook_linux.js').read_text()
# Evaluate actual handler functions in a tiny Frida-free harness.
def function(name):
    start = source.index('function ' + name + '(')
    line_end = source.index('\n', start)
    end = line_end if source[start:line_end].rstrip().endswith('}') else source.index('\n}', start) + 2
    return source[start:end]

js = '''const assert = require('assert');
var events = [], workEpoch = 0, workMinToken = 0, workActive = true, WORK_CAPACITY = 64;
var scr = {pending: [], body: null}, scSend = null, md = null;
function send(m) {events.push(m);} function recv() {} function monoNow() {return 42;}
'''
js += '\n'.join(function(n) for n in ('workAck', 'workFinish', 'workCurrent', 'hexToBytes', 'onScrambleSet', 'onSessionReset', 'scrTrap', 'drainSendCall'))
js += '''
onScrambleSet({id: 0x437, body: '01', token: 'a', epoch: 0});
onScrambleSet({id: 0x437, body: '02', token: 'b', epoch: 0});
assert.deepStrictEqual(scr.pending.map(x => x.body[0]), [1,2]);
assert.deepStrictEqual(events.map(x => x.hit), ['armed']);
for (let i=2; i<64; i++) onScrambleSet({id: 0x437, body: '03'});
onScrambleSet({id: 0x437, body: '04'});
assert.strictEqual(scr.pending.length, 64);
assert.strictEqual(events.at(-1).e, 'pending queue full');
scSend = {queue: [[1]], fn: {}, this: {}, tid: 1, pc: 'pc'};
var captures = 0; function scrCallArm() {captures++;}
onSessionReset({epoch: 1, active: true});
assert.strictEqual(scr.pending.length, 0);
assert.strictEqual(events.filter(x => x.hit === 'cancelled').length, 64);
assert.strictEqual(scSend.this, null); assert.strictEqual(scSend.fn, null);
assert.strictEqual(scSend.queue.length, 0); assert.strictEqual(captures, 1);
onScrambleSet({id: 0x437, body: '05', token: 'stale', epoch: 0});
assert.strictEqual(events.at(-1).e, 'stale epoch');
assert.strictEqual(scr.pending.length, 0);
onSessionReset({epoch:2,active:false});
onScrambleSet({id:0x437,body:'05',epoch:2});
assert.strictEqual(events.at(-1).e,'stale epoch');
assert.strictEqual(scr.pending.length,0);
onSessionReset({epoch:3,active:true,min_token:10});
onScrambleSet({id:0x437,body:'01',token:9,epoch:3});
assert.strictEqual(events.at(-1).hit,'error');
assert.strictEqual(scr.pending.length,0);
onScrambleSet({id:0x437,body:'01',token:10,epoch:3});
assert.strictEqual(events.at(-1).hit,'armed');
assert.strictEqual(scr.pending[0].token,10);
onSessionReset({epoch:3,active:true});
assert.strictEqual(workEpoch,3);
assert.strictEqual(workMinToken,10);
onScrambleSet({id:0x437,body:'01',token:9,epoch:3});
assert.strictEqual(events.at(-1).hit,'error');
assert.strictEqual(scr.pending.length,0);
onScrambleSet({id:1,body:'01',token:'clear',epoch:3});
onScrambleSet({id:2,body:'02',token:'next',epoch:3});
onScrambleSet({id:1,body:null,epoch:3});
assert.strictEqual(scr.pending[0].token,'next');
assert.deepStrictEqual(events.slice(-2).map(x=>x.hit),['cancelled','armed']);
'''
js += r"""
class NativePointer {
    constructor(memory, offset) {this.memory=memory; this.offset=offset;}
    add(n) {return new NativePointer(this.memory, this.offset+n);}
    equals(other) {return this.memory === other.memory && this.offset === other.offset;}
    readByteArray(n) {return this.memory.slice(this.offset,this.offset+n);}
    writeByteArray(bytes) {this.memory.set(bytes,this.offset);}
    readU8() {return this.memory[this.offset];}
    writeU8(v) {this.memory[this.offset]=v;}
    toString() {return String(this.offset);}
}
var tid=7, Process={getCurrentThreadId:()=>tid};
var scrThread={id:7}, scrCall=null, researchTrap=null;
function slotFrom(ctx,reg) {return ctx[reg];}
function hexOf(b) {return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');}
function toHex(p,n) {return hexOf(p.readByteArray(n));}
var mem=new Uint8Array([0x37,0x04,0x11,0x22]);
var pc=new NativePointer(new Uint8Array(1),0), bodyp=new NativePointer(mem,2);
scr={pc,reg:'ecx',idoff:-2,lo:null,body:null,pending:[
 {id:0x437,body:[0x33,0x44],token:'first',epoch:1},
 {id:0x437,body:[0x55,0x66],token:'second',epoch:1}]};
scrTrap({type:'breakpoint',context:{pc,ecx:bodyp}});
assert.strictEqual(scr.pending[0].token,'second');
assert.strictEqual(events.at(-1).hit,'wrote');
assert.strictEqual(events.filter(x=>x.token==='first' && x.hit==='consumed').length,0);
mem[2]=0x91; // Native store has encrypted ORIGINAL byte after the trap returned.
tid=8; scrTrap({type:'breakpoint',context:{pc,ecx:bodyp.add(1)}});
assert.strictEqual(mem[2],0x91); // A different thread cannot run the deferred repair.
tid=7; scrTrap({type:'breakpoint',context:{pc,ecx:bodyp.add(1)}});
assert.strictEqual(mem[2],0x91 ^ 0x11 ^ 0x33);
assert.deepStrictEqual(events.slice(-2).map(x=>x.hit),['consumed','armed']);
assert.strictEqual(scr.pending.length,1);
// A failed write removes only its own head; the following request remains usable.
scr._fix0=null;
scr.pending=[{id:0x437,body:[1,2],token:'fail',epoch:3},
 {id:0x437,body:[3,4],token:'after-fail',epoch:3}];
var failWrite=true, normalWrite=NativePointer.prototype.writeByteArray;
NativePointer.prototype.writeByteArray=function(bytes) {
 if (failWrite) {failWrite=false; throw new Error('mock write failure');}
 normalWrite.call(this,bytes);
};
scrTrap({type:'breakpoint',context:{pc,ecx:bodyp}});
assert.strictEqual(scr.pending[0].token,'after-fail');
assert.deepStrictEqual(events.slice(-2).map(x=>x.hit),['error','armed']);
scrTrap({type:'breakpoint',context:{pc,ecx:bodyp}});
assert.strictEqual(scr.pending.length,0);
mem[2]=0x91;
scrTrap({type:'breakpoint',context:{pc,ecx:bodyp.add(1)}});
assert.strictEqual(events.at(-1).token,'after-fail');
assert.strictEqual(events.at(-1).hit,'consumed');
// Actual skill level 10 and target/ground bodies survive the deferred store repair.
for (const [pid, bytes] of [[0x438,[10,0,0x1c,0,1,2,3,4]],
                          [0xaf4,[10,0,0x1c,0,150,0,187,0,0]]]) {
 mem=new Uint8Array(32);bodyp=new NativePointer(mem,2);
 mem[0]=pid&255;mem[1]=pid>>8;mem[2]=1;
 scr.pending=[{id:pid,body:bytes,token:'level10',epoch:workEpoch}];
 scr._fix0=null;
 scrTrap({type:'breakpoint',context:{pc,ecx:bodyp}});
 assert.deepStrictEqual(Array.from(mem.slice(2,2+bytes.length)),bytes);
 mem[2]=1^0xa5; // native store still used the original level 1
 scrTrap({type:'breakpoint',context:{pc,ecx:bodyp.add(1)}});
 assert.strictEqual(mem[2],10^0xa5);
 assert.strictEqual(events.at(-1).hit,'consumed');
}
// Never perform a merge without the original byte required by _fix0.
var normalRead=NativePointer.prototype.readByteArray;
NativePointer.prototype.readByteArray=function(n) {
 if(this.offset===2) throw new Error('unreadable original');
 return normalRead.call(this,n);
};
mem[0]=0x38;mem[1]=4;mem[2]=1;
scr.pending=[{id:0x438,body:[10,0,28,0,1,2,3,4],token:'unreadable',epoch:workEpoch}];
scrTrap({type:'breakpoint',context:{pc,ecx:bodyp}});
assert.strictEqual(mem[2],1);
assert.strictEqual(scr.pending.length,0);
assert.strictEqual(events.at(-1).hit,'error');
NativePointer.prototype.readByteArray=normalRead;
var scDraining=false, called=[];
var Memory={alloc:()=>({writeByteArray:()=>{}})};
scSend={tid:7,this:{},fn:(_this,len)=>called.push(len),queue:[
 {bytes:[0x38,0x04,1],token:'cast1',epoch:3},
 {bytes:[0x38,0x04,2],token:'cast2',epoch:3}]};
drainSendCall();
assert.deepStrictEqual(called,[3,3]);
assert.deepStrictEqual(events.slice(-2).map(x=>x.token),['cast1','cast2']);
"""
subprocess.run(['node', '-e', js], check=True)
print('PASS: agent FIFO, bounded capacity, epoch reset, native invalidation')

from relay.agent import agent_source
operational = agent_source()
research = agent_source(research=True)
assert 'Stalker.follow' not in operational
assert 'function scrProbe(' not in operational
assert 'function onSendWatch(' not in operational
assert "recv('sendwatch'" not in operational
assert 'Stalker.follow' in research
assert 'function scrProbe(' in research
assert 'function onSendWatch(' in research
assert "recv('sendwatch'" in research
subprocess.run(['node', '--check'], input=research, text=True, check=True)
# Default dispose must not resolve research-only helper names.
dispose = next(line for line in operational.splitlines() if line.startswith('rpc.exports ='))
dispose_js = """const assert = require('assert');
var rpc={},sw=null,scr=null,scrCall=null,scSend=null,md=null,cleared=0;
function scrDisarm() {cleared++;} function scrCallDisarm() {cleared++;}
""" + dispose + "\nrpc.exports.dispose(); assert.strictEqual(cleared,2);"
subprocess.run(['node', '-e', dispose_js], check=True)
extension_js = """const assert = require('assert');
var sw=null,researchTrap=null,researchReset=null,registrations=[];
function ptr(x) {return x;} function recv(name) {registrations.push(name);}
""" + pathlib.Path('agent/research_hooks.js').read_text() + """
assert(registrations.includes('sendwatch'));
assert(registrations.includes('trace'));
onSendWatch({}); assert.strictEqual(sw,null);
"""
subprocess.run(['node', '-e', extension_js], check=True)
print('PASS: default source excludes send-watch/probe/Stalker; dispose needs no research helpers')

identity_js = """const assert = require('assert');
class Ptr {
 constructor(mem,off=0){this.mem=mem;this.off=off;}
 add(n){return new Ptr(this.mem,this.off+n);}
 writeU32(n){new DataView(this.mem).setUint32(this.off,n,true);}
 readU32(){return new DataView(this.mem).getUint32(this.off,true);}
 readU8(){return new DataView(this.mem).getUint8(this.off);}
}
var socketIdentityWarned=false,warnings=[],fallbacks=0;
function send(m){warnings.push(m);}
var cookies={4:[1,0x20000000],5:[1,0x20000000],6:[2,0x20000000]};
var libcGetsockopt=(fd,level,option,value,len)=>{
 assert.strictEqual(level,1);assert.strictEqual(option,57);
 value.writeU32(cookies[fd][0]);value.add(4).writeU32(cookies[fd][1]);len.writeU32(8);return 0;
};
var libcGetsockname=(fd,sa,len)=>{
 fallbacks++;new DataView(sa.mem).setUint8(2,0x12);new DataView(sa.mem).setUint8(3,0x34);return 0;
};
var sa=new Ptr(new ArrayBuffer(128)),len=new Ptr(new ArrayBuffer(4));
""" + function('socketIdentity') + '\n' + function('portAt') + """
const first=socketIdentity(4,sa,len);
assert.strictEqual(first,'cookie:2000000000000001');
assert.strictEqual(socketIdentity(5,sa,len),first); // dup fd, same TCP socket
assert.notStrictEqual(socketIdentity(6,sa,len),first); // same local port, new TCP socket
cookies[4]=[2,0x20000000];
assert.notStrictEqual(socketIdentity(4,sa,len),first); // same fd reused
assert.strictEqual(fallbacks,0);
libcGetsockopt=()=>-1;
assert.strictEqual(socketIdentity(4,sa,len),0x1234);
libcGetsockopt=null;
assert.strictEqual(socketIdentity(5,sa,len),0x1234);
assert.strictEqual(warnings.length,1);
assert.strictEqual(warnings[0].code,'SO_COOKIE_FALLBACK');
"""
subprocess.run(['node','-e',identity_js],check=True)
print('PASS: socket cookies distinguish port/fd reuse and retain duplicate-fd identity; fallback warns once')

guard_js = "const assert=require('assert');\n" + function('sameSocket') + """
assert(sameSocket('peer','cookie:1','peer','cookie:1'));
assert(!sameSocket('peer','cookie:1','peer','cookie:2'));
assert(!sameSocket('peer','cookie:1',null,null));
assert(!sameSocket('peer',null,'peer',null));
assert(!sameSocket(null,null,null,null));
assert(!sameSocket('peer','cookie:1','other','cookie:1'));
"""
subprocess.run(['node','-e',guard_js],check=True)
print('PASS: syscall identity guard accepts stable sockets and rejects replacement/missing identity')
