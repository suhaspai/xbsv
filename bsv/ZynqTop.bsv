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

import Clocks :: *;
import Vector            :: *;
import Connectable       :: *;
import ConnectableWithTrace::*;
import Portal            :: *;
import Leds              :: *;
import AxiMasterSlave    :: *;
import XilinxCells       :: *;
import XbsvXilinxCells   :: *;
import PS7LIB::*;
import PPS7LIB::*;
import XADC::*;
import CtrlMux::*;
import AxiMasterSlave    :: *;
import AxiDma            :: *;
import Top               :: *;
import Bscan             :: *;
import HostInterface::*;

`ifdef USES_BSCAN
`define BSCAN_ARG  lbscan.loc[0],
`else
`define BSCAN_ARG
`endif
`ifndef PinType
`define PinType Empty
`endif

typedef `PinType PinType;
typedef `NumberOfMasters NumberOfMasters;

interface I2C_Pins;
   interface Inout#(Bit#(1)) scl;
   interface Inout#(Bit#(1)) sda;
endinterface

(* always_ready, always_enabled *)
interface ZynqTop;
   (* prefix="" *)
   interface ZynqPins zynq;
   (* prefix="GPIO" *)
   interface LEDS             leds;
   (* prefix="XADC" *)
   interface XADC             xadc;
`ifdef USE_I2C0
   (* prefix="I2C0" *)
   interface I2C_Pins         i2c0;
`endif
`ifdef USE_I2C1
   (* prefix="I2C1" *)
   interface I2C_Pins         i2c1;
`endif
   (* prefix="" *)
   interface PinType          pins;
   interface Vector#(4, Clock) deleteme_unused_clock;
   interface Vector#(4, Reset) deleteme_unused_reset;
endinterface

module mkZynqTop(ZynqTop);
   PS7 ps7 <- mkPS7();
   Clock mainclock = ps7.fclkclk[0];
   Reset mainreset = ps7.fclkreset[0];

`ifdef USE_I2C0
   let tscl0 <- mkIOBUF(~ps7.i2c[0].scltn, ps7.i2c[0].sclo, clocked_by mainclock, reset_by mainreset);
   let tsda0 <- mkIOBUF(~ps7.i2c[0].sdatn, ps7.i2c[0].sdao, clocked_by mainclock, reset_by mainreset);
   rule sdai0;
      ps7.i2c[0].sdai(tsda0.o);
      ps7.i2c[0].scli(tscl0.o);
   endrule
`endif

`ifdef USE_I2C1
   let tscl1 <- mkIOBUF(~ps7.i2c[1].scltn, ps7.i2c[1].sclo, clocked_by mainclock, reset_by mainreset);
   let tsda1 <- mkIOBUF(~ps7.i2c[1].sdatn, ps7.i2c[1].sdao, clocked_by mainclock, reset_by mainreset);
   rule sdai1;
      ps7.i2c[1].sdai(tsda1.o);
      ps7.i2c[1].scli(tscl1.o);
   endrule
`endif

   BscanTop bscan <- mkBscanTop(3, clocked_by mainclock, reset_by mainreset); // Use USER3  (JTAG IDCODE address 0x22)
   BscanLocal lbscan <- mkBscanLocal(bscan, clocked_by bscan.tck, reset_by bscan.rst);
`ifdef IMPORT_HOSTIF
   PortalTop#(32, 64, PinType, NumberOfMasters) top <- mkPortalTop(ps7, clocked_by mainclock, reset_by mainreset);
`else
   PortalTop#(32, 64, PinType, NumberOfMasters) top <- mkPortalTop(`BSCAN_ARG clocked_by mainclock, reset_by mainreset);
`endif
   mkConnectionWithTrace(ps7, top, lbscan.loc[1], clocked_by mainclock, reset_by mainreset);

   let intr_mux <- mkInterruptMux(top.interrupt);
   rule send_int_rule;
      ps7.interrupt(pack(intr_mux));
   endrule

   module bufferClock#(Integer i)(Clock); let bc <- mkClockBUFG(clocked_by ps7.fclkclk[i]); return bc; endmodule
   module bufferReset#(Integer i)(Reset); let rc <- mkAsyncReset(2, ps7.fclkreset[i], ps7.fclkclk[0]); return rc; endmodule
   Vector#(4, Clock) unused_clock <- genWithM(bufferClock);
   Vector#(4, Reset) unused_reset <- genWithM(bufferReset);

   interface zynq = ps7.pins;
   interface leds = top.leds;
   interface XADC xadc = top.xadc;
`ifdef USE_I2C0
   interface I2C_Pins i2c0;
      interface Inout scl = tscl0.io;
      interface Inout sda = tsda0.io;
   endinterface
`endif
`ifdef USE_I2C1
   interface I2C_Pins i2c1;
      interface Inout scl = tscl1.io;
      interface Inout sda = tsda1.io;
   endinterface
`endif
   interface pins = top.pins;
   interface deleteme_unused_clock = unused_clock;
   interface deleteme_unused_reset = unused_reset;

endmodule
