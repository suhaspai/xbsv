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
import GetPut::*;
import ClientServer::*;
import Vector::*;

import MemTypes::*;
import MemreadEngine::*;
import Pipe::*;

interface MemreadRequest;
   method Action startRead(Bit#(32) pointer, Bit#(32) numWords, Bit#(32) burstLen, Bit#(32) iterCnt);
   method Action getStateDbg();   
endinterface

interface Memread;
   interface MemreadRequest request;
   interface ObjectReadClient#(128) dmaClient;
endinterface

interface MemreadIndication;
   method Action started(Bit#(32) numWords);
   method Action reportStateDbg(Bit#(32) streamRdCnt, Bit#(32) mismatchCount);
   method Action readDone(Bit#(32) mismatchCount);
endinterface

module mkMemread#(MemreadIndication indication) (Memread);

   Reg#(ObjectPointer)     pointer <- mkReg(0);
   Reg#(Bit#(32))         numWords <- mkReg(0);
   Reg#(Bit#(32))         burstLen <- mkReg(0);
   Reg#(Bit#(32))          iterCnt <- mkReg(0);
   
   Reg#(Bit#(32))           srcGen <- mkReg(0);
   Reg#(Bit#(32))    mismatchCount <- mkReg(0);
   MemreadEngine#(128,1)        re <- mkMemreadEngine;
   
   rule start (iterCnt > 0);
      iterCnt <= iterCnt-1;
      re.readServers[0].request.put(MemengineCmd{pointer:pointer, base:0, len:numWords, burstLen:truncate(burstLen)});
   endrule
   
   rule finish;
      let rv <- re.readServers[0].response.get;
      if (iterCnt == 0)
	 indication.readDone(mismatchCount);
   endrule
   
   rule check;
      let v <- toGet(re.dataPipes[0]).get;
      let expectedV = {srcGen+3,srcGen+2,srcGen+1,srcGen};
      let misMatch = v != expectedV;
      mismatchCount <= mismatchCount + (misMatch ? 1 : 0);
      if (srcGen+4 == numWords)
	 srcGen <= 0;
      else
	 srcGen <= srcGen+4;
   endrule
   
   interface ObjectReadClient dmaClient = re.dmaClient;
   interface MemreadRequest request;
      method Action startRead(Bit#(32) rp, Bit#(32) nw, Bit#(32) bl, Bit#(32) ic);
	 $display("startRead rdPointer=%d numWords=%h burstLen=%d iterCnt=%d", rp, nw, bl, ic);
	 indication.started(nw);
	 pointer <= rp;
	 numWords  <= nw;
	 burstLen  <= bl;
	 iterCnt <= ic;
	 mismatchCount <= 0;
	 srcGen <= 0;
      endmethod
      method Action getStateDbg();
	 indication.reportStateDbg(iterCnt, mismatchCount);
      endmethod
   endinterface
      
endmodule
