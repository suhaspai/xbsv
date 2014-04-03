// Copyright (c) 2014 Quanta Research Cambridge, Inc.

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

import Vector         :: *;
import BRAM           :: *;
import FIFOF          :: *;
import GetPut         :: *;
import PCIE           :: *;
import Connectable    :: *;
import AxiMasterSlave :: *;
import Bscan          :: *;
import BramMux        :: *;
import Clocks         :: *;

typedef 8 TlpTraceAddrSize;
typedef TAdd#(TlpTraceAddrSize,1) TlpTraceAddrSize1;

typedef struct {
    Bit#(32) timestamp;
    Bit#(7) source;   // 4==frombus 8=tobus
    TLPData#(16) tlp; // 153 bits
} TimestampedTlpData deriving (Bits);
typedef SizeOf#(TimestampedTlpData) TimestampedTlpDataSize;
typedef SizeOf#(TLPData#(16)) TlpData16Size;
typedef SizeOf#(TLPCompletionHeader) TLPCompletionHeaderSize;
interface TlpTrace;
   interface Get#(TimestampedTlpData) tlp;
endinterface

// An MSIX table entry, as defined in the PCIe spec
typedef struct {
   Bit#(32) addr_lo;
   Bit#(32) addr_hi;
   Bit#(32) msg_data;
   Bool     masked;
} MSIX_Entry deriving (Bits);

// The control and status registers which are accessible from the PCIe
// bus.
interface AxiControlAndStatusRegs;

   interface Axi3Slave#(32,32,12)  slave;

   interface BRAMServer#(Bit#(6), Bit#(32)) msixBram;

   interface Reg#(Bool)     tlpTracing;
   interface Reg#(Bit#(TlpTraceAddrSize)) tlpTraceLimit;
   interface Reg#(Bit#(TlpTraceAddrSize)) fromPcieTraceBramWrAddr;
   interface Reg#(Bit#(TlpTraceAddrSize))   toPcieTraceBramWrAddr;
   interface BRAMServer#(Bit#(TlpTraceAddrSize), TimestampedTlpData) fromPcieTraceBramPort;
   interface BRAMServer#(Bit#(TlpTraceAddrSize), TimestampedTlpData)   toPcieTraceBramPort;
endinterface: AxiControlAndStatusRegs

typedef struct {
   Bit#(13) waddr;
   Bit#(5) rbc;
   Bool last;
   Bit#(12) id;
   } ReadStage0Values deriving (Bits);
typedef struct {
   Bool last;
   Bool isMsixAccess;
   Bit#(12) id;
   } ReadStage1Values deriving (Bits);

// This module encapsulates all of the logic for instantiating and
// accessing the control and status registers. It defines the
// registers, the address map, and how the registers respond to reads
// and writes.
(* synthesize *)
module mkAxiControlAndStatusRegs#( Bit#(64)  board_content_id
				  , PciId     my_id
				  , UInt#(13) max_read_req_bytes
				  , UInt#(13) max_payload_bytes
				  //, MakeResetIfc portalResetIfc
				  )
   (AxiControlAndStatusRegs);


   // Revision information for this implementation
   Integer major_rev = 2;
   Integer minor_rev = 0;

   BRAM_Configure msix_bram_cfg = defaultValue;
   msix_bram_cfg.memorySize = 64;
   msix_bram_cfg.latency = 1;
   BRAM2Port#(Bit#(6), Bit#(32)) msix_bram <- mkBRAM2Server(msix_bram_cfg);

   // Clocks and Resets
   Clock defaultClock <- exposeCurrentClock();
   Reset defaultReset <- exposeCurrentReset();
   
   // Trace Support
   Reg#(Bool) tlpTracingReg        <- mkReg(False);
   Reg#(Bit#(TlpTraceAddrSize)) tlpTraceLimitReg <- mkReg(0);
   Reg#(Bit#(TAdd#(TlpTraceAddrSize,1))) bramMuxRdAddrReg <- mkReg(0);
   Reg#(Bit#(TlpTraceAddrSize)) fromPcieTraceBramWrAddrReg <- mkReg(0);
   Reg#(Bit#(TlpTraceAddrSize))   toPcieTraceBramWrAddrReg <- mkReg(0);
   Integer memorySize = 2**valueOf(TlpTraceAddrSize);
   // TODO: lift BscanBram to *Top.bsv
`ifdef BSIM
   Clock jtagClock = defaultClock;
   Reset jtagReset = defaultReset;
`else
   Reg#(Bit#(TAdd#(TlpTraceAddrSize,1))) bscanPcieTraceBramWrAddrReg <- mkReg(0);
   BscanBram#(Bit#(TAdd#(TlpTraceAddrSize,1)), TimestampedTlpData) pcieBscanBram <- mkBscanBram(1, bscanPcieTraceBramWrAddrReg);
   Clock jtagClock = pcieBscanBram.jtagClock;
   Reset jtagReset = pcieBscanBram.jtagReset;
`endif

   BRAM_Configure bramCfg = defaultValue;
   bramCfg.memorySize = memorySize;
   bramCfg.latency = 1;
   BRAM2Port#(Bit#(TlpTraceAddrSize), TimestampedTlpData) fromPcieTraceBram <- mkSyncBRAM2Server(bramCfg, defaultClock, defaultReset,
												 jtagClock, jtagReset);
   BRAM2Port#(Bit#(TlpTraceAddrSize), TimestampedTlpData) toPcieTraceBram <- mkSyncBRAM2Server(bramCfg, defaultClock, defaultReset,
											       jtagClock, jtagReset);
   Vector#(2, BRAMServer#(Bit#(TlpTraceAddrSize), TimestampedTlpData)) bramServers;
   bramServers[0] = fromPcieTraceBram.portA;
   bramServers[1] =   toPcieTraceBram.portA;
   BramServerMux#(TAdd#(TlpTraceAddrSize,1), TimestampedTlpData) bramMux <- mkBramServerMux(bramServers);

`ifndef BSIM
   Vector#(2, BRAMServer#(Bit#(TlpTraceAddrSize), TimestampedTlpData)) bscanBramServers;
   bscanBramServers[0] = fromPcieTraceBram.portB;
   bscanBramServers[1] =   toPcieTraceBram.portB;
   BramServerMux#(TAdd#(TlpTraceAddrSize,1), TimestampedTlpData) bscanBramMux <- mkBramServerMux(bscanBramServers, clocked_by jtagClock, reset_by jtagReset);
   mkConnection(pcieBscanBram.bramClient, bscanBramMux.bramServer, clocked_by jtagClock, reset_by jtagReset);
`endif
   
   Reg#(TimestampedTlpData) pcieTraceBramResponse <- mkReg(unpack(0));

   // Function to return a one-word slice of the tlpTraceBramResponse
   function Bit#(32) tlpTraceBramResponseSlice(Reg#(TimestampedTlpData) data, Bit#(3) i);
       Bit#(8) i8 = zeroExtend(i);
       begin
           Bit#(192) v = extend(pack(data));
           return v[31 + (i8*32) : 0 + (i8*32)];
       end
   endfunction

   // Function to read from the CSR address space (using DW address)
   function Bit#(32) rd_csr(UInt#(13) addr);
      case (addr)
         // board identification
         0: return 32'h65756c42; // Blue
         1: return 32'h63657073; // spec
         2: return fromInteger(minor_rev);
         3: return fromInteger(major_rev);
         4: return pack(buildVersion);
         5: return pack(epochTime);
         8: return board_content_id[31:0];
         9: return board_content_id[63:32];
	 
	 768: return extend(bramMuxRdAddrReg);
	 774: return fromInteger(2**valueOf(TAdd#(TlpTraceAddrSize,1)));
	 775: return (tlpTracingReg ? 1 : 0);
	 776: return tlpTraceBramResponseSlice(pcieTraceBramResponse, 0);
	 777: return tlpTraceBramResponseSlice(pcieTraceBramResponse, 1);
	 778: return tlpTraceBramResponseSlice(pcieTraceBramResponse, 2);
	 779: return tlpTraceBramResponseSlice(pcieTraceBramResponse, 3);
	 780: return tlpTraceBramResponseSlice(pcieTraceBramResponse, 4);
	 781: return tlpTraceBramResponseSlice(pcieTraceBramResponse, 5);
	 792: return extend(fromPcieTraceBramWrAddrReg);
	 793: return extend(  toPcieTraceBramWrAddrReg);
	 794: return extend(tlpTraceLimitReg);
	 //795: return portalResetIfc.isAsserted() ? 1 : 0;

         //******************************** start of area referenced from xilinx_x7_pcie_wrapper.v
         // 4-entry MSIx table
	 // 4096 through 4159 is in msix_bram
         // 4-bit MSIx pending bit field
         5120: return '0;                               // PBA structure (low)
         5121: return '0;                               // PBA structure (high)
         //******************************** end of area referenced from xilinx_x7_pcie_wrapper.v
         // unused addresses
         default: return 32'hbad0add0;
      endcase
   endfunction: rd_csr

   // Utility function for managing partial writes
   function t update_dword(t dword_orig, Bit#(4) be, Bit#(32) dword_in) provisos(Bits#(t,32));
      Vector#(4,Bit#(8)) result = unpack(pack(dword_orig));
      Vector#(4,Bit#(8)) vin    = unpack(dword_in);
      for (Integer i = 0; i < 4; i = i + 1)
         if (be[i] != 0) result[i] = vin[i];
      return unpack(pack(result));
   endfunction: update_dword

   // Function to write to the CSR address space (using DW address)
   function Action wr_csr(UInt#(30) addr, Bit#(4) be, Bit#(32) dword);
      action
         case (addr % 8192)
	    775: tlpTracingReg <= (dword != 0) ? True : False;

	    768: begin
		    bramMux.bramServer.request.put(BRAMRequest{ write: False, responseOnWrite: False, address: bramMuxRdAddrReg, datain: unpack(0)});
		    bramMuxRdAddrReg <= bramMuxRdAddrReg + 1;
		    end

	    792: fromPcieTraceBramWrAddrReg <= truncate(dword);
	    793:   toPcieTraceBramWrAddrReg <= truncate(dword);
	    794: tlpTraceLimitReg <= truncate(dword);
	    //795: portalResetIfc.assertReset();

            //******************************** start of area referenced from xilinx_x7_pcie_wrapper.v
            // MSIx table entries
	    // 4096 to 4159 in msix_bram
            //******************************** end of area referenced from xilinx_x7_pcie_wrapper.v
         endcase
      endaction
   endfunction: wr_csr

   // State used to actually service read and write requests

   rule brmMuxResponse;
       let v <- bramMux.bramServer.response.get();
       pcieTraceBramResponse <= v;
   endrule

   FIFOF#(Axi3ReadRequest#(32,12)) req_ar_fifo <- mkFIFOF();
   FIFOF#(Axi3ReadResponse#(32,12)) resp_read_fifo <- mkSizedFIFOF(8);
   FIFOF#(Axi3WriteRequest#(32,12)) req_aw_fifo <- mkFIFOF();
   FIFOF#(Axi3WriteData#(32,12)) resp_write_fifo <- mkSizedFIFOF(8);
   FIFOF#(Axi3WriteResponse#(12)) resp_b_fifo <- mkFIFOF();

   FIFOF#(ReadStage0Values) read_stage0_fifo <- mkFIFOF();
   FIFOF#(ReadStage1Values) read_stage1_fifo <- mkFIFOF();
   FIFOF#(Bit#(32)) v_fifo <- mkFIFOF();

   Reg#(Bool) readIdleReg <- mkReg(True);
   Reg#(Bool) readLastReg <- mkReg(False);
   Reg#(Bit#(5)) readBurstCount <- mkReg(0);
   Reg#(Bit#(30)) readAddr <- mkReg(0);
   rule do_read if (req_ar_fifo.notEmpty());
      Bit#(5) rbc = readBurstCount;
      Bit#(5) nextRbc = rbc - 1;
      Bool last = readLastReg;
      Bool nextLast = (rbc == 1);
      Bit#(30) addr = readAddr;
      Bool isIdle = readIdleReg;
      // FIXME
      Bool nextIdle = nextLast;
      let req = req_ar_fifo.first();
      if (isIdle) begin
	 nextRbc = extend(req.len);
	 nextLast = (nextRbc == 0);
	 nextIdle = False;
	 addr = truncate(req.address);
      end

      read_stage0_fifo.enq(ReadStage0Values { waddr: addr[14:2], last: nextLast, rbc: nextRbc, id: req.id});

      readBurstCount <= nextRbc;
      readAddr <= addr + 4;
      readLastReg <= nextLast;
      readIdleReg <= nextIdle;
      if (last)
	 req_ar_fifo.deq();
   endrule

   rule read_stage_stage0;
      let values = read_stage0_fifo.first();
      read_stage0_fifo.deq();
      let waddr = values.waddr;
      let rbc = values.rbc;
      let last = values.last;
      let id = values.id;
      let v = rd_csr(unpack(waddr));

      Bool isMsixAccess = (waddr >= 4096 && waddr <= 4159);
      read_stage1_fifo.enq(ReadStage1Values { last: last, id: id, isMsixAccess: isMsixAccess });
      if (isMsixAccess) begin
	 // msix register
	 msix_bram.portA.request.put(BRAMRequest { write: False, responseOnWrite: False, address: waddr[5:0], datain: ?});
      end
      else begin
	 $display("AxiCsr do_read waddr=%h len=%d v=%h", waddr, rbc, v);
	 v_fifo.enq(v);
      end

   endrule

   rule read_stage_stage1;
      let values = read_stage1_fifo.first();
      read_stage1_fifo.deq();
      Bit#(32) v;
      if (values.isMsixAccess) begin
	 let entry <- msix_bram.portA.response.get();
	 v = entry;
      end
      else begin
	 v = v_fifo.first();
	 v_fifo.deq();
      end
      resp_read_fifo.enq(Axi3ReadResponse { data: v, resp: 0, last: pack(values.last), id: values.id });
   endrule

   Reg#(Bool) writeIdleReg <- mkReg(True);
   Reg#(Bool) writeLastReg <- mkReg(False);
   Reg#(Bit#(5)) writeBurstCount <- mkReg(0);
   Reg#(Bit#(30)) writeAddr <- mkReg(0);

   rule do_write;
      Bit#(5) wbc = writeBurstCount;
      Bit#(5)  nextWbc = wbc - 1;
      Bool isLast = writeLastReg;
      Bool nextLast = (wbc == 1);
      Bit#(30) addr = writeAddr;
      let req = req_aw_fifo.first();
      let isIdle = writeIdleReg;
      // fixme
      let nextIdle = nextLast;
      if (isIdle) begin
	 nextWbc = extend(req.len);
	 nextLast = (nextWbc == 0);
	 addr = truncate(req.address);
	 nextIdle = False;
      end
      else begin
	  let resp_write = resp_write_fifo.first();
	  resp_write_fifo.deq();

	  Bit#(30) waddr = addr >> 2;
	  if (waddr >= 4096 && waddr <= 4159) begin
	     // msix register
	     msix_bram.portA.request.put(BRAMRequest { write: True, responseOnWrite: False, address: waddr[5:0], datain: resp_write.data});
	  end
	  else begin
	     wr_csr(unpack(addr >> 2), 'hf, resp_write.data);
	  end
	  addr = addr + 4;
      end

      writeIdleReg <= nextIdle;
      writeBurstCount <= nextWbc;
      writeAddr <= addr;
      writeLastReg <= nextLast;
      if (isLast) begin
	 req_aw_fifo.deq();
	 resp_b_fifo.enq(Axi3WriteResponse { resp: 0, id: req.id});
      end
   endrule

   interface Axi3Slave slave;
	interface Put req_ar;
	   method Action put(Axi3ReadRequest#(32,12) req);
	      req_ar_fifo.enq(req);
	   endmethod
	endinterface: req_ar
	interface Get resp_read;
	   method ActionValue#(Axi3ReadResponse#(32,12)) get();
	      let resp = resp_read_fifo.first();
	      resp_read_fifo.deq();
	      return resp;
	   endmethod
	endinterface: resp_read
	interface Put req_aw;
	   method Action put(Axi3WriteRequest#(32,12) req);
	      req_aw_fifo.enq(req);
	   endmethod
	endinterface: req_aw
	interface Put resp_write;
	   method Action put(Axi3WriteData#(32,12) resp);
	      resp_write_fifo.enq(resp);
	   endmethod
	endinterface: resp_write
	interface Get resp_b;
	   method ActionValue#(Axi3WriteResponse#(12)) get();
	      let b = resp_b_fifo.first();
	      resp_b_fifo.deq();
	      return b;
	   endmethod
	endinterface: resp_b
   endinterface: slave

   interface BRAMServer msixBram = msix_bram.portB;

   interface Reg tlpTracing    = tlpTracingReg;
   interface Reg tlpTraceLimit = tlpTraceLimitReg;
   interface Reg fromPcieTraceBramWrAddr = fromPcieTraceBramWrAddrReg;
   interface Reg   toPcieTraceBramWrAddr =   toPcieTraceBramWrAddrReg;
   interface BRAMServer fromPcieTraceBramPort = fromPcieTraceBram.portA;
   interface BRAMServer   toPcieTraceBramPort =   toPcieTraceBram.portA;
endmodule: mkAxiControlAndStatusRegs
