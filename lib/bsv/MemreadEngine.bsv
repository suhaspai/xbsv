// Copyright (c) 2013 Quanta Research Cambridge, Inc.

// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import Vector::*;
import FIFOF::*;
import FIFO::*;
import GetPut::*;
import Assert::*;
import ClientServer::*;
import BRAM::*;
import BRAMFIFO::*;
import Ratchet::*;
import Connectable::*;

import PortalMemory::*;
import MemTypes::*;
import Pipe::*;
import MemUtils::*;


module mkMemreadEngine(MemreadEngineV#(dataWidth, cmdQDepth, numServers))
   provisos( Mul#(TDiv#(dataWidth, 8), 8, dataWidth)
	    ,Add#(1, a__, numServers)
	    ,Add#(b__, TLog#(numServers), TAdd#(1, TLog#(TMul#(cmdQDepth,numServers))))
	    ,Pipe::FunnelPipesPipelined#(1, numServers,Tuple2#(Bit#(TLog#(numServers)), MemTypes::MemengineCmd), TMin#(2,TLog#(numServers)))
	    ,Pipe::FunnelPipesPipelined#(1, numServers, Tuple2#(Bit#(dataWidth), Bool),TMin#(2, TLog#(numServers)))
	    ,Add#(c__, TLog#(numServers), TLog#(TMul#(cmdQDepth, numServers)))
	    );
   let rv <- mkMemreadEngineBuff(256);
   return rv;
endmodule

module mkMemreadEngineBuff#(Integer bufferSizeBytes) (MemreadEngineV#(dataWidth, cmdQDepth, numServers))
   provisos (Div#(dataWidth,8,dataWidthBytes),
	     Mul#(dataWidthBytes,8,dataWidth),
	     Log#(dataWidthBytes,beatShift),
	     Log#(cmdQDepth,logCmdQDepth),
	     Mul#(cmdQDepth,numServers,cmdBuffSz),
	     Log#(cmdBuffSz, cmdBuffAddrSz),
	     Log#(numServers, serverIdxSz),
	     Add#(1,logCmdQDepth, outCntSz),
	     Add#(1, c__, numServers),
	     Add#(b__, TLog#(numServers), cmdBuffAddrSz),
	     Add#(e__, TLog#(numServers), TAdd#(1, cmdBuffAddrSz)),
	     Add#(a__, serverIdxSz, cmdBuffAddrSz),
	     Min#(2,TLog#(numServers),bpc),
	     FunnelPipesPipelined#(1,numServers,Tuple2#(Bit#(serverIdxSz),MemengineCmd),bpc),
	     FunnelPipesPipelined#(1,numServers,Tuple2#(Bit#(dataWidth),Bool),bpc));
   
   Integer bufferSizeBeats = bufferSizeBytes/valueOf(dataWidthBytes);
   Vector#(numServers, Reg#(Bit#(outCntSz)))     outs1 <- replicateM(mkReg(0));
   Vector#(numServers, Reg#(Bit#(outCntSz)))     outs0 <- replicateM(mkReg(0));
   Vector#(numServers, Ratchet#(16))           buffCap <- replicateM(mkRatchet(fromInteger(bufferSizeBeats)));
   UGBramFifos#(numServers,cmdQDepth,MemengineCmd) cmdBuf <- mkUGBramFifos;
   
   Reg#(Bool) load_in_progress <- mkReg(False);
   FIFO#(Tuple2#(MemengineCmd,Bool))              loadf_b <- mkSizedFIFO(1);
   FIFO#(Tuple2#(Bit#(serverIdxSz),MemengineCmd)) loadf_c <- mkSizedFIFO(1);
   FIFO#(Tuple3#(Bit#(8),Bit#(serverIdxSz),Bool))   workf <- mkSizedFIFO(32); // isthis the right size?
   

   Vector#(numServers, FIFO#(void))              outfs <- replicateM(mkSizedFIFO(1));
   Vector#(numServers, FIFOF#(Tuple2#(Bit#(serverIdxSz), MemengineCmd))) cmds_in <- replicateM(mkSizedFIFOF(1));
   FunnelPipe#(1, numServers, Tuple2#(Bit#(serverIdxSz), MemengineCmd),bpc) cmds_in_funnel <- mkFunnelPipesPipelined(map(toPipeOut,cmds_in));

   FIFOF#(Tuple2#(Bit#(TLog#(numServers)), Tuple2#(Bit#(dataWidth),Bool))) read_data <- mkFIFOF;
   UnFunnelPipe#(1, numServers, Tuple2#(Bit#(dataWidth),Bool),bpc) read_data_unfunnel <- mkUnFunnelPipesPipelined(cons(toPipeOut(read_data),nil));
   Vector#(numServers, FIFOF#(Tuple2#(Bit#(dataWidth),Bool)))  read_data_buffs <- replicateM(mkSizedBRAMFIFOF(bufferSizeBeats));
   Vector#(numServers, PipeIn#(Tuple2#(Bit#(dataWidth),Bool))) foo = map(toPipeIn, read_data_buffs); 
   zipWithM(mkConnection, read_data_unfunnel, foo);
   function PipeOut#(Bit#(dataWidth)) check_out(PipeOut#(Tuple2#(Bit#(dataWidth),Bool)) x, Integer i) = 
      (interface PipeOut;
	  method Bit#(dataWidth) first;
	     return tpl_1(x.first);
	  endmethod
	  method Action deq;
	     x.deq;
	     buffCap[i].increment(1);
	     if (tpl_2(x.first)) 
		outfs[i].enq(?);
	  endmethod
	  method Bool notEmpty = x.notEmpty;
       endinterface);
   Vector#(numServers, PipeOut#(Bit#(dataWidth))) read_data_pipes = zipWith(check_out, map(toPipeOut,read_data_buffs), genVector);
   
   Reg#(Bit#(8))                               respCnt <- mkReg(0);
   Reg#(Bit#(serverIdxSz))                     loadIdx <- mkReg(0);
   let beat_shift = fromInteger(valueOf(beatShift));
   let cmd_q_depth = fromInteger(valueOf(cmdQDepth));

   rule store_cmd;
      match {.idx, .cmd} <- toGet(cmds_in_funnel[0]).get;
      outs1[idx] <= outs1[idx]+1;
      cmdBuf.enq(idx,cmd);
      //$display("store_cmd %d", idx);
   endrule
   
   rule load_ctxt_a (!load_in_progress);
      if (outs1[loadIdx] > 0) begin
	 load_in_progress <= True;
	 cmdBuf.first_req(loadIdx);
      end
      else begin
	 loadIdx <= loadIdx+1;
      end
   endrule

   rule load_ctxt_b;
      let cmd <- cmdBuf.first_resp;
      let cond = buffCap[loadIdx].read() >= unpack(extend(cmd.burstLen>>beat_shift));
      loadf_b.enq(tuple2(cmd,cond));
   endrule

   rule load_ctxt_c;
      load_in_progress <= False;
      loadIdx <= loadIdx+1;
      match {.cmd,.cond} <- toGet(loadf_b).get;
      if  (cond) begin
	 //$display("load_ctxt_b %h %d", cmd.base, idx);
	 buffCap[loadIdx].decrement(unpack(extend(cmd.burstLen>>beat_shift)));
	 loadf_c.enq(tuple2(loadIdx,cmd));
	 if (cmd.len <= extend(cmd.burstLen)) begin
	    outs1[loadIdx] <= outs1[loadIdx]-1;
	    cmdBuf.deq(loadIdx);
	 end
	 else begin
	    let new_cmd = MemengineCmd{pointer:cmd.pointer, base:cmd.base+extend(cmd.burstLen), burstLen:cmd.burstLen, len:cmd.len-extend(cmd.burstLen)};
	    cmdBuf.upd_head(loadIdx,new_cmd);
	 end
      end
   endrule
   
   Vector#(numServers, Server#(MemengineCmd,Bool)) rs;
   for(Integer i = 0; i < valueOf(numServers); i=i+1)
      rs[i] = (interface Server#(MemengineCmd,Bool);
		  interface Put request;
		     method Action put(MemengineCmd c) if (outs0[i] < cmd_q_depth);
			Bit#(32) bsb = fromInteger(bufferSizeBytes);
			if(extend(c.burstLen) > bsb)
			   $display("mkMemreadEngineV::unsupportedBurstLen");
	 		outs0[i] <= outs0[i]+1;
			cmds_in[i].enq(tuple2(fromInteger(i),c));
 		     endmethod
		  endinterface
		  interface Get response;
		     method ActionValue#(Bool) get;
			outfs[i].deq;
	 		outs0[i] <= outs0[i]-1;
			return True;
		     endmethod
		  endinterface
	       endinterface);
   interface readServers = rs;
   interface ObjectReadClient dmaClient;
      interface Get readReq;
	 method ActionValue#(ObjectRequest) get();
	    match {.idx, .cmd} <- toGet(loadf_c).get;
	    Bit#(8) bl = cmd.burstLen;
	    let last = False;
	    if (cmd.len <= extend(bl)) begin
	       last = True;
	       bl = truncate(cmd.len);
	    end
	    workf.enq(tuple3(truncate(bl>>beat_shift), idx, last));
	    //$display("readReq %d, %h %h %h", idx, cmd.base, bl, last);
	    return ObjectRequest { pointer: cmd.pointer, offset: cmd.base, burstLen:bl, tag: 0 };
	 endmethod
      endinterface
      interface Put readData;
	 method Action put(ObjectData#(dataWidth) d);
	    match {.rc, .idx, .last} = workf.first;
	    let new_respCnt = respCnt+1;
	    let l = False;
	    //$display("%h %d", d.data, idx);
	    if (new_respCnt == rc) begin
	       respCnt <= 0;
	       workf.deq;
	       //$display("eob %d", idx);
	       l = last;
	    end
	    else begin
	       respCnt <= new_respCnt;
	    end
	    read_data.enq(tuple2(idx,tuple2(d.data,l)));
	 endmethod
      endinterface
   endinterface 
   interface dataPipes = read_data_pipes;
endmodule


