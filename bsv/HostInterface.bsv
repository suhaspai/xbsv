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

////////////////////////////// Bsim /////////////////////////////////
`ifdef BsimHostTypeIF

import Vector            :: *;
import AxiMasterSlave    :: *;
import MemTypes          :: *;

`ifndef DataBusWidth
`define DataBusWidth 64
`endif
`ifndef PinType
`define PinType Empty
`endif

typedef `NumberOfMasters NumberOfMasters;
typedef `DataBusWidth DataBusWidth;

// this interface should allow for different master and slave bus paraters;		 
interface BsimHost#(numeric type clientAddrWidth, numeric type clientBusWidth, numeric type clientIdWidth,  
		    numeric type serverAddrWidth, numeric type serverBusWidth, numeric type serverIdWidth,
		    numeric type nSlaves);
   interface MemMaster#(clientAddrWidth, clientBusWidth)  mem_client;
   interface Vector#(nSlaves,Axi3Slave#(serverAddrWidth,  serverBusWidth, serverIdWidth))  axi_servers;
   interface Clock doubleClock;
   interface Reset doubleReset;
endinterface

typedef BsimHost#(32,32,12,40,DataBusWidth,6,NumberOfMasters) HostType;
`endif

////////////////////////////// PciE /////////////////////////////////
`ifdef PcieHostTypeIF

import Vector            :: *;
import GetPut            :: *;
import ClientServer      :: *;
import PCIE               :: *;
import PCIEWRAPPER       :: *;
import PcieCsr           :: *;
import MemSlave          :: *;
import MemTypes          :: *;
import Bscan             :: *;
`ifndef BSIM
import PcieEndpointX7    :: *;
`endif

`ifndef DataBusWidth
`define DataBusWidth 64
`endif
`ifndef PinType
`define PinType Empty
`endif

typedef `DataBusWidth DataBusWidth;
typedef `NumberOfMasters NumberOfMasters;

interface PcieHost#(numeric type dsz, numeric type nSlaves);
   interface Vector#(16,MSIX_Entry)              msixEntry;
   interface MemMaster#(32,32)                   master;
   interface Vector#(nSlaves,MemSlave#(40,dsz))  slave;
   interface Put#(Tuple2#(Bit#(64),Bit#(32)))    interruptRequest;
   interface Client#(TLPData#(16), TLPData#(16)) pci;
   interface BscanTop bscanif;
endinterface

interface PcieHostTop;
   interface Clock tepClock125;
   interface Reset tepReset125;
   interface PcieHost#(DataBusWidth, NumberOfMasters) tpciehost;
`ifndef BSIM
   interface Clock tsys_clk_200mhz;
   interface Clock tsys_clk_200mhz_buf;
   interface Clock tpci_clk_100mhz_buf;
   interface PcieEndpointX7#(PcieLanes) tep7;
`endif
   interface Clock doubleClock;
   interface Reset doubleReset;
endinterface

typedef PcieHostTop HostType;
`endif

////////////////////////////// Zynq /////////////////////////////////
`ifdef ZynqHostTypeIF
import PS7LIB::*;

typedef PS7 HostType;

export PS7LIB::*;
export HostType;
`endif
