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

import FIFOF        :: *;
import Vector       :: *;
import GetPut       :: *;
import Connectable  :: *;
import MIMO         :: *;
import PCIE         :: *;
import DefaultValue :: *;

import AxiMasterSlave :: *;

//
// Top interface: PCIe transaction level packets (TLPs)
// Sources interrupt MSIX requests
interface PcieInterruptEngine;
    interface Put#(TLPData#(16))   tlp_in;
    interface Get#(TLPData#(16))   tlp_out;
    interface Axi3Master#(32,32,12) master;
    interface Put#(Tuple2#(Bit#(64),Bit#(32))) interruptRequest;
    interface Reg#(Bit#(12))       bTag;
endinterface

(* synthesize *)
module mkPcieInterruptEngine#(PciId my_id)(PcieInterruptEngine);
    FIFOF#(Tuple2#(Bit#(64),Bit#(32))) interruptRequestFifo <- mkSizedFIFOF(16);
    Reg#(Maybe#(Bit#(32))) interruptSecondHalf <- mkReg(tagged Invalid);
    FIFOF#(TLPData#(16)) tlpOutFifo <- mkSizedFIFOF(8);
    Reg#(TLPTag) tlpTag <- mkReg(0);
    Reg#(Bit#(7)) hitReg <- mkReg(0);

   FIFOF#(Bool) interruptIs64BitFifo <- mkFIFOF();

    rule interruptTlpPrep if (interruptRequestFifo.notEmpty &&& interruptSecondHalf matches tagged Invalid);
       let interruptRequested = True;
       let interruptIs64Bit = False;

       Bit#(64) interruptAddr = tpl_1(interruptRequestFifo.first);
       Bit#(32) interruptData = tpl_2(interruptRequestFifo.first);
       if (interruptAddr == '0) begin
	  // do not write to 0 -- it wedges the host
	  interruptRequested = False;
       end
       else if (interruptAddr[63:32] == '0) begin
	  interruptIs64Bit = True;
       end

       if (!interruptRequested)
	  interruptRequestFifo.deq();
       else
	  interruptIs64BitFifo.enq(interruptIs64Bit);
    endrule

    rule interruptTlpOut if (interruptIs64BitFifo.notEmpty());

       Bool is64bit = interruptIs64BitFifo.first();
       interruptIs64BitFifo.deq();

       TLPData#(16) tlp = defaultValue;
       tlp.sof = True;
       tlp.eof = False;
       tlp.hit = 7'h00;
       tlp.be = 16'hffff;

       Bit#(64) interruptAddr = tpl_1(interruptRequestFifo.first);
       Bit#(32) interruptData = tpl_2(interruptRequestFifo.first);
       if (!is64bit) begin
          TLPMemoryIO3DWHeader hdr_3dw = defaultValue();
          hdr_3dw.format = MEM_WRITE_3DW_DATA;
	  //hdr_3dw.pkttype = MEM_READ_WRITE;
          hdr_3dw.tag = tlpTag;
          hdr_3dw.reqid = my_id;
          hdr_3dw.length = 1;
          hdr_3dw.firstbe = '1;
          hdr_3dw.lastbe = '0;
          hdr_3dw.addr = interruptAddr[31:2];
	  hdr_3dw.data = byteSwap(interruptData);
	  tlp.data = pack(hdr_3dw);
	  tlp.eof = True;
       end
       else begin
	  TLPMemory4DWHeader hdr_4dw = defaultValue;
	  hdr_4dw.format = MEM_WRITE_4DW_DATA;
	  //hdr_4dw.pkttype = MEM_READ_WRITE;
	  hdr_4dw.tag = tlpTag;
	  hdr_4dw.reqid = my_id;
	  hdr_4dw.nosnoop = SNOOPING_REQD;
	  hdr_4dw.addr = interruptAddr[40-1:2];
	  hdr_4dw.length = 1;
	  hdr_4dw.firstbe = 4'hf;
	  hdr_4dw.lastbe = 0;
	  tlp.data = pack(hdr_4dw);

	  interruptSecondHalf <= tagged Valid interruptData;
       end

       if (!is64bit)
	  interruptRequestFifo.deq();
       tlpOutFifo.enq(tlp);
    endrule

    rule interruptTlpDataOut if (interruptSecondHalf matches tagged Valid .interruptData);
       TLPData#(16) tlp = defaultValue;
       tlp.sof = False;
       tlp.eof = True;
       tlp.hit = 7'h00;
       tlp.be = 16'hf000;
       tlp.data[7+8*15:8*12] = byteSwap(interruptData);
       tlpOutFifo.enq(tlp);
       interruptSecondHalf <= tagged Invalid;
       interruptRequestFifo.deq();
    endrule

    interface Put tlp_in;
        method Action put(TLPData#(16) tlp);
	    //$display("PcieInterruptEngine.put tlp=%h", tlp);
	    TLPMemoryIO3DWHeader h = unpack(tlp.data);
	    hitReg <= tlp.hit;
	endmethod
    endinterface: tlp_in
    interface Get tlp_out = toGet(tlpOutFifo);
    interface Put interruptRequest;
       method Action put(Tuple2#(Bit#(64),Bit#(32)) intr);
          interruptRequestFifo.enq(intr);
       endmethod
    endinterface
endmodule: mkPcieInterruptEngine
