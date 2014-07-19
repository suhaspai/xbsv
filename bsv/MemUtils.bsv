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


import BRAM::*;
import FIFO::*;
import Vector::*;
import Gearbox::*;
import FIFOF::*;
import SpecialFIFOs::*;

import GetPut::*;
import MemTypes::*;

interface MemReader#(numeric type dataWidth);
   interface ObjectReadServer #(dataWidth) readServer;
   interface ObjectReadClient#(dataWidth) readClient;
endinterface

module mkMemReader(MemReader#(dataWidth))
   provisos(Div#(dataWidth,8,dataWidthBytes),
	    Mul#(dataWidthBytes,8,dataWidth),
	    Log#(dataWidthBytes,beatShift));

   FIFOF#(ObjectData#(dataWidth))  readBuffer <- mkFIFOF;
   FIFOF#(ObjectRequest)       reqOutstanding <- mkFIFOF;

   interface ObjectReadServer readServer;
      interface Put readReq = toPut(reqOutstanding);
      interface Get readData = toGet(readBuffer);
   endinterface
   interface ObjectReadClient readClient;
      interface Get readReq = toGet(reqOutstanding);
      interface Put readData = toPut(readBuffer);
   endinterface
endmodule


interface MemWriter#(numeric type dataWidth);
   interface ObjectWriteServer#(dataWidth) writeServer;
   interface ObjectWriteClient#(dataWidth) writeClient;
endinterface


module mkMemWriter(MemWriter#(dataWidth))
   provisos(Div#(dataWidth,8,dataWidthBytes),
	    Mul#(dataWidthBytes,8,dataWidth),
	    Log#(dataWidthBytes,beatShift));

   FIFOF#(ObjectData#(dataWidth)) writeBuffer <- mkFIFOF;
   FIFOF#(ObjectRequest)        reqOutstanding <- mkFIFOF;
   FIFOF#(Bit#(6))                        doneTags <- mkFIFOF();

   interface ObjectWriteServer writeServer;
      interface Put writeReq = toPut(reqOutstanding);
      interface Put writeData = toPut(writeBuffer);
      interface Get writeDone = toGet(doneTags);
   endinterface
   interface ObjectWriteClient writeClient;
      interface Get writeReq = toGet(reqOutstanding);
      interface Get writeData = toGet(writeBuffer);
      interface Put writeDone = toPut(doneTags);
   endinterface

endmodule
   

interface UGBramFifos#(numeric type numFifos, numeric type fifoDepth, type a);
   method Action enq(Bit#(TLog#(numFifos)) idx, a v);
   method Action first_req(Bit#(TLog#(numFifos)) idx);
   method ActionValue#(a) first_resp();
   method Action deq(Bit#(TLog#(numFifos)) idx);
   method Action upd_head(Bit#(TLog#(numFifos)) idx, a v);
endinterface


module mkUGBramFifos(UGBramFifos#(numFifos,fifoDepth,a))
   provisos(Mul#(fifoDepth,numFifos,buffSz),
	    Log#(buffSz, buffAddrSz),
	    Add#(a__, TLog#(numFifos), TAdd#(1, buffAddrSz)),
	    Bits#(a,b__));
   
   function Bit#(buffAddrSz) hf(Integer i) = fromInteger(i*valueOf(fifoDepth));
   Vector#(numFifos, Reg#(Bit#(buffAddrSz))) head <- mapM(mkReg, genWith(hf));
   Vector#(numFifos, Reg#(Bit#(buffAddrSz))) tail <- mapM(mkReg, genWith(hf));
   BRAM2Port#(Bit#(buffAddrSz),a)    buff <- mkBRAM2Server(defaultValue);
   let fifo_depth = fromInteger(valueOf(fifoDepth));
      
   method Action enq(Bit#(TLog#(numFifos)) idx, a v);
      buff.portB.request.put(BRAMRequest{write:True, responseOnWrite:False, address:tail[idx], datain:v});
      Bit#(TAdd#(1,buffAddrSz)) nt = extend(tail[idx])+1;
      Bit#(TAdd#(1,buffAddrSz)) li = (extend(idx)+1)*fifo_depth;
      Bit#(TAdd#(1,buffAddrSz)) rs = (extend(idx)+0)*fifo_depth;
      if (nt >= li) 
	 nt = rs;
      tail[idx] <= truncate(nt);
   endmethod

   method Action first_req(Bit#(TLog#(numFifos)) idx);
      buff.portA.request.put(BRAMRequest{write:False, responseOnWrite:False, address:head[idx], datain:?});
   endmethod
   
   method ActionValue#(a) first_resp();
      let v <- buff.portA.response.get;
      return v;
   endmethod

   method Action deq(Bit#(TLog#(numFifos)) idx);
      Bit#(TAdd#(1,buffAddrSz)) nt = extend(head[idx])+1;
      Bit#(TAdd#(1,buffAddrSz)) li = (extend(idx)+1)*fifo_depth;
      Bit#(TAdd#(1,buffAddrSz)) rs = (extend(idx)+0)*fifo_depth;
      if (nt >= li) 
	 nt = rs;
      head[idx] <= truncate(nt);
   endmethod

   method Action upd_head(Bit#(TLog#(numFifos)) idx, a v);
      buff.portA.request.put(BRAMRequest{write:True, responseOnWrite:False, address:head[idx], datain:v});
   endmethod

endmodule

