// Injected into the Frida recv probe after plaintext ring verification.
// Hardware watchpoint is per receiving thread, armed only on later 09FD chunks.
var verifiedRing = null, ringWatch = null, ringHandlerReady = false;
var watchWords = new Uint32Array(256); // 64 records (pc, value, ecx, ebx)
var watchCount = 0, watchEpoch = 0;

function ringTrap(details) {
  var w = ringWatch;
  if (!w || (details.type !== 'single-step' && details.type !== 'breakpoint') ||
      Process.getCurrentThreadId() !== w.tid) return false;
  var ix = (watchCount % 64) * 4;
  watchWords[ix] = details.context.pc.toUInt32();
  try {watchWords[ix + 1] = w.addr.readU32();} catch (_) {watchWords[ix + 1] = 0;}
  watchWords[ix + 2] = details.context.ecx.toUInt32();
  watchWords[ix + 3] = details.context.ebx.toUInt32();
  watchCount++;
  return true;
}

function describeWriter(address) {
  var pc = ptr(address);
  var desc = {pc:locate(pc)};
  try {
    var range=Process.findRangeByAddress(pc);
    if(range)desc.range={base:range.base.toString(),size:range.size,protection:range.protection,file:range.file?range.file.path:null};
  } catch(_) {}
  try {desc.next_instruction=Instruction.parse(pc).toString();} catch(_) {}
  try {desc.previous_2=Instruction.parse(pc.sub(2)).toString();} catch(_) {}
  try {desc.previous_4=Instruction.parse(pc.sub(4)).toString();} catch(_) {}
  try {desc.near_bytes=Array.from(new Uint8Array(pc.sub(12).readByteArray(36))).map(function(v){return ('0'+v.toString(16)).slice(-2)}).join('');} catch(_) {}
  return desc;
}
function ringDisarm(reason) {
  var w = ringWatch;
  if (!w) return;
  ringWatch = null;
  try {w.thread.unsetHardwareWatchpoint(0);} catch (_) {}
  var n = Math.min(64, watchCount), events = [];
  for (var j = watchCount - n; j < watchCount; j++) {
    var k = (j % 64) * 4;
    events.push({pc: locate(ptr(watchWords[k])), word: '0x' + watchWords[k + 1].toString(16),
      ecx: '0x' + watchWords[k + 2].toString(16), ebx: '0x' + watchWords[k + 3].toString(16)});
  }
  var pcs=[];
  events.forEach(function(e){if(!pcs.some(function(z){return z.pc===e.pc;}))pcs.push(describeWriter(e.pc));});
  events.forEach(function(e){
    try {var previous=ptr(e.pc).sub(2);
      if(Instruction.parse(previous).toString()==='mov byte ptr [ecx], bl')reportWriterCode(previous);
    } catch (_) {}
  });
  var finalWord = null;
  try {finalWord = '0x' + w.addr.readU32().toString(16);} catch (_) {}
  note('ring_watch', {writers:pcs,reason:reason, fd:w.fd, tid:w.tid,
    address:w.addr.toString(), duration_ms:Date.now()-w.started,
    initial_word:w.initial, final_word:finalWord, total_hits:watchCount, events:events});
}

function ringArm(fd) {
  if (!verifiedRing || ringWatch) return;
  var tid = Process.getCurrentThreadId();
  try {
    var th = Process.enumerateThreads().filter(function(t){return t.id === tid;})[0];
    if (!th) return;
    var addr = verifiedRing.add(0x44); // body bytes 4..7 after ring + 0x40
    th.setHardwareWatchpoint(0, addr, 4, 'w');
    var initialWord = null;
    try {initialWord = '0x' + addr.readU32().toString(16);} catch (_) {}
    ringWatch = {thread:th, tid:tid, addr:addr, fd:fd, started:Date.now(), initial:initialWord};
    watchCount = 0;
    var epoch = ++watchEpoch;
    setTimeout(function(){if(epoch === watchEpoch)ringDisarm('timeout_125ms');},125);
    note('ring_watch_armed',{fd:fd,tid:tid,address:addr.toString()});
  } catch (e) {
    ringDisarm('failed_arm');
    note('ring_watch_error',{message:String(e).slice(0,180)});
  }
}

var writerCodeReported = false;
function reportWriterCode(pc) {
  if (writerCodeReported) return;
  writerCodeReported = true;
  // Resolve the writer from the live watchpoint PC, not a previous session address.
  try {
    var range = Process.findRangeByAddress(pc);
    if (!range || range.protection.indexOf('x') < 0) {
      note('writer_code_error', {reason:'target_not_executable'});return;
    }
    var start = pc.sub(128), code = new Uint8Array(start.readByteArray(256));
    var raw = Array.from(code).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join('');
    var instructions = [];
    // Decode confirmed boundary and forward, never claim arbitrary pre-store byte boundaries.
    var walk = pc;
    for (var i=0;i<36;i++) {
      try {var inst=Instruction.parse(walk);instructions.push({pc:locate(walk),text:inst.toString()});walk=inst.next;}
      catch (_) {break;}
    }
    note('writer_code', {pc:pc.toString(),mapping_base:range.base.toString(),
      region_start:start.toString(),bytes:raw, decoded_forward:instructions});
  } catch(e) {note('writer_code_error',{reason:String(e).slice(0,180)});}
}

function ringVerified(base) {
  verifiedRing = ptr(base);
  if (!ringHandlerReady) {
    Process.setExceptionHandler(ringTrap);
    ringHandlerReady = true;
  }
}
