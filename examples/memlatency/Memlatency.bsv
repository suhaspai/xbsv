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

import FIFOF::*;
import FIFO::*;
import ClientServer::*;
import GetPut::*;
import BRAMFIFO::*;

import Pipe::*;
import PortalMemory::*;
import MemTypes::*;
import MemreadEngine::*;
import MemwriteEngine::*;

interface MemlatencyRequest;
   method Action start(Bit#(32) wrPointer, Bit#(32) rdPointer, Bit#(32) burstLen);
endinterface

interface MemlatencyIndication;
   method Action started;
   method Action readDone;
   method Action writeDone;
   method Action readLatency(Bit#(32) l);
   method Action writeLatency(Bit#(32) l);
endinterface

interface Memlatency;
   interface MemlatencyRequest request;
   interface ObjectReadClient#(64) dmaReadClient;
   interface ObjectWriteClient#(64) dmaWriteClient;
endinterface

module mkMemlatency#(MemlatencyIndication indication)(Memlatency);


   MemreadEngine#(64,1)  re <- mkMemreadEngine;
   MemwriteEngine#(64,1) we <- mkMemwriteEngine;
   
   Reg#(Bit#(32))        rdIterCnt <- mkReg(0);
   Reg#(Bit#(32))        wrIterCnt <- mkReg(0);
   Reg#(ObjectPointer)   rdPointer <- mkReg(0);
   Reg#(ObjectPointer)   wrPointer <- mkReg(0);
   Reg#(Bit#(32))         burstLen <- mkReg(0);
   
   Reg#(Bit#(32))           cycles <- mkReg(0);
   Reg#(Bit#(32))          rdStart <- mkReg(0);
   Reg#(Bit#(32))          wrStart <- mkReg(0);
   FIFO#(Bit#(32))       rdLatFifo <- mkSizedBRAMFIFO(16);
   FIFO#(Bit#(32))       wrLatFifo <- mkSizedBRAMFIFO(16);
   
   rule cycle;
      cycles <= cycles+1;
   endrule
   
   rule startRead(rdIterCnt > 0);
      re.readServers[0].request.put(MemengineCmd{pointer:rdPointer, base:0, len:burstLen*4, burstLen:truncate(burstLen*4)});
      rdIterCnt <= rdIterCnt-1;
      rdStart <= cycles;
   endrule

   rule finishRead;
      let rv0 <- re.readServers[0].response.get;
      rdLatFifo.enq(cycles-rdStart);
   endrule
   
   rule readConsume;
      re.dataPipes[0].deq;
   endrule
   
   rule startWrite(wrIterCnt > 0);
      we.writeServers[0].request.put(MemengineCmd{pointer:wrPointer, base:0, len:burstLen*4, burstLen:truncate(burstLen*4)});
      wrIterCnt <= wrIterCnt-1;
      wrStart <= cycles;
   endrule

   rule finishWrite;
      let rv0 <- we.writeServers[0].response.get;
      wrLatFifo.enq(cycles-wrStart);
   endrule
   
   rule writeProduce;
      we.dataPipes[0].enq(1);
   endrule
   
   rule report;
      let wl <- toGet(wrLatFifo).get;
      let rl <- toGet(rdLatFifo).get;
      indication.readLatency(rl);
      indication.writeLatency(wl);
      if(wrIterCnt==0)
	 indication.writeDone;
      if(rdIterCnt==0)
	 indication.readDone;
   endrule

   
   interface MemlatencyRequest request;
   method Action start(Bit#(32) wp, Bit#(32) rp, Bit#(32) bl);
      $display("start wrPointer=%d rdPointer=%d burstLen=%d", wp, rp, bl);
      indication.started;
      // initialized
      wrPointer <= wp;
      rdPointer <= rp;
      rdIterCnt <= 16;
      wrIterCnt <= 16;
      burstLen  <= bl;
   endmethod
   endinterface
   interface ObjectReadClient dmaReadClient = re.dmaClient;
   interface ObjectWriteClient dmaWriteClient = we.dmaClient;
   
endmodule
