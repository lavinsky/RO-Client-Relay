// Research-only trace of the previously observed `mov byte ptr [ecx], bl`.
// Installed only after a ring address has been verified by a plaintext match.
// Do not assume an observed writer is the unique writer for any packet.
// Hardware EXECUTE breakpoints, without modifying executable instructions.
var writeTraceRing=null, writeTraceThreads=[], writeTraceInstalled=false;
var writeTraceEvents=[],writeTraceTotal=0,writeTraceDropped=0;
var writeTraceBatch=0,writeTraceMax=30000;
var writeTraceAddress=ptr(/*WRITE_ADDRESS*/);
function writeTraceFlush(){
  if(!writeTraceEvents.length)return;
  send({kind:'write_trace_batch',batch:++writeTraceBatch,events:writeTraceEvents});
  writeTraceEvents=[];
}
function writeTraceException(details){
  if(!writeTraceInstalled || details.type!=='breakpoint' ||
     !details.address.equals(writeTraceAddress))return false;
  var tid=Process.getCurrentThreadId();
  if(!writeTraceThreads.some(function(t){return t.id===tid;}))return false;
  if(writeTraceTotal >= writeTraceMax){writeTraceDropped++;return true;}
  var relative=details.context.ecx.sub(writeTraceRing);
  if(relative.compare(ptr('0x40'))>=0 && relative.compare(ptr('0x4000'))<0){
    var recv=recvByThread[tid]||null;
    writeTraceTotal++;
    writeTraceEvents.push({n:writeTraceTotal,tid:tid,
       offset:relative.toUInt32(),byte:details.context.ebx.toUInt32()&255,
       recv_seq_hint:recv?recv.seq:null,fd_hint:recv?recv.fd:null,
       age_ms:recv?Date.now()-recv.ms:null});
    if(writeTraceEvents.length>=64)writeTraceFlush();
  }
  return true;
}
function writerStart(){
  if(writeTraceInstalled || ringBase===null)return;
  try{
    var range=Process.findRangeByAddress(writeTraceAddress);
    if(!range || range.protection.indexOf('x')<0)throw Error('not_executable');
    var ins=Instruction.parse(writeTraceAddress);
    if(ins.toString()!=='mov byte ptr [ecx], bl')throw Error('unexpected_instruction:'+ins.toString());
    writeTraceRing=ringBase;
    Process.setExceptionHandler(writeTraceException);
    // Execution breakpoint is thread-local: arm every existing thread.
    // Do not claim coverage for threads created after this snapshot.
    Process.enumerateThreads().forEach(function(t){
      try{ t.setHardwareBreakpoint(1,writeTraceAddress); writeTraceThreads.push(t); }
      catch(e){note('write_trace_thread_error',{tid:t.id,reason:String(e).slice(0,100)});}
    });
    writeTraceInstalled=writeTraceThreads.length>0;
    note('write_trace_armed',{mode:'hardware_execute',instruction:ins.toString(),
        thread_count:writeTraceThreads.length,ring:writeTraceRing.toString()});
  }catch(e){note('write_trace_error',{reason:String(e).slice(0,200)});}
}
function writerStop(){
  writeTraceInstalled=false;
  writeTraceThreads.forEach(function(t){try{t.unsetHardwareBreakpoint(1);}catch(_){}});
  writeTraceThreads=[];
  writeTraceFlush();
  note('write_trace_summary',{mode:'hardware_execute',total:writeTraceTotal,
    dropped:writeTraceDropped,batches:writeTraceBatch});
}
