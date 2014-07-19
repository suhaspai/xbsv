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

import FIFO::*;
import FIFOF::*;
import Vector::*;
import GetPut::*;
import ClientServer::*;

import Pipe::*;
import MemTypes::*;
import MemreadEngine::*;
import Pipe::*;

interface MemreadRequest;
   method Action startRead(Bit#(32) pointer, Bit#(32) numWords, Bit#(32) burstLen, Bit#(32) iterCnt);
endinterface

interface Memread;
   interface MemreadRequest request;
   interface ObjectReadClient#(64) dmaClient;
endinterface

interface MemreadIndication;
   method Action readDone(Bit#(32) mismatchCount);
endinterface

module mkMemread#(MemreadIndication indication) (Memread);

   Reg#(ObjectPointer)   pointer <- mkReg(0);
   Reg#(Bit#(32))       numWords <- mkReg(0);
   Reg#(Bit#(32))       burstLen <- mkReg(0);
   Reg#(Bit#(32))    mismatchCnt <- mkReg(0);
   FIFO#(void)          cf <- mkSizedFIFO(1);
   Reg#(Bit#(32))       iterCnt <- mkReg(0);
   Reg#(Bit#(32))       iterCnts <- mkReg(0);
   Reg#(Bit#(32))        srcGens <- mkReg(0);
   Reg#(Bit#(32)) mismatchCounts <- mkReg(0);
   MemreadEngineV#(64,2,1)        re <- mkMemreadEngine;
   Bit#(ObjectOffsetSize) chunk = extend(numWords)*4;
   
   
      rule start (iterCnts > 0);
	 re.readServers[0].request.put(MemengineCmd{pointer:pointer, base:0, len:truncate(chunk), burstLen:truncate(burstLen*4)});
	 iterCnts <= iterCnts-1;
      endrule
      rule finish;
	 let rv <- re.readServers[0].response.get;
	 mismatchCounts <= 0;
      endrule
      rule check;
	 let v <- toGet(re.dataPipes[0]).get;
	 let expectedV = {srcGens+1,srcGens};
	 let misMatch = v != expectedV;
	 mismatchCounts <= mismatchCounts + (misMatch ? 1 : 0);
	 let new_srcGens = srcGens+2;
	 if (new_srcGens >= truncate(chunk/4))
	    new_srcGens = 0;
	 srcGens <= new_srcGens;
      endrule
   
   rule indicate_finish;
      let mc = mismatchCnt;
      if (iterCnt == 1) begin
	 cf.deq;
	 indication.readDone(mc);
	 mc = 0;
      end
      mismatchCnt <= mc;
      iterCnt <= iterCnt - 1;
   endrule
   
   interface dmaClient = re.dmaClient;
   interface MemreadRequest request;
      method Action startRead(Bit#(32) rp, Bit#(32) nw, Bit#(32) bl, Bit#(32) ic);
	 pointer <= rp;
	 cf.enq(?);
	 numWords  <= nw;
	 burstLen  <= bl;
	 iterCnt <= ic;
	 iterCnts <= ic;
	 mismatchCounts <= 0;
	 srcGens <= 0;
      endmethod
   endinterface
endmodule
