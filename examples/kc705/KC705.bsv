import SceMi      :: *;
import SceMiLayer :: *;
import SceMiKintex7PCIEQrc:: *;

// Setup for SCE-MI over PCIE to a Virtex6
import Xilinx       :: *;
import XilinxPCIE   :: *;
import Clocks       :: *;
import DefaultValue :: *;
import Connectable  :: *;
import CommitIfc    :: *;
import TieOff       :: *;
import Memory       :: *;
import GetPut       :: *;
import ClientServer :: *;
import BUtils       :: *;

// We need to get access to the uncontrolled clock and reset to hook up the DDR2
interface MemSceMiLayerIfc;
    interface SceMiLayer scemiLayer;
    interface Clock uclock;
    interface Reset ureset;
endinterface

module buildSceMiQrc#(SceMiModule#(i) mod, SceMiK7PCIEArgs args)
		  (SceMiK7PCIEQrcIfc#(i,lanes))
   provisos(Add#(1,_,lanes), SelectKintex7PCIE#(lanes));

   // record link type parameter for infrastructure linkage tool
   //let param_link_type <- mkSceMiLinkTypeParameter(args.link_type);

   // Dispatch to builder for specific linkage type
   let build = buildSceMiPCIEK7Qrc( args.pci_sys_clk_p, args.pci_sys_clk_n, args.pci_sys_reset, args.ref_clk, args.link_type );

   (* hide *)
   let _m <- liftModule(build);

   return _m;
endmodule

(* synthesize, no_default_clock, no_default_reset *)
module mkBridge #(Clock pci_sys_clk_p, Clock pci_sys_clk_n,
		  Clock sys_clk_p,     Clock sys_clk_n,
		  Clock user_clk_p, Clock user_clk_n,
		  Reset pci_sys_reset_n)
                 (KC705_FPGA_DDR3);

   Clock sys_clk <- mkClockIBUFDS(sys_clk_p, sys_clk_n);
   Clock user_clk <- mkClockIBUFDS(user_clk_p, user_clk_n);

   ClockGenerator7Params clk_params = defaultValue();
   clk_params.clkin1_period     = 5.000;       // 200 MHz reference
   clk_params.clkin_buffer      = False;       // necessary buffer is instanced above
   clk_params.reset_stages      = 0;           // no sync on reset so input clock has pll as only load
   clk_params.clkfbout_mult_f   = 5.000;       // 1000 MHz VCO
   clk_params.clkout0_divide_f  = `SCEMI_CLOCK_PERIOD;
   clk_params.clkout1_divide    = 5;           // ddr3 reference clock (200 MHz)

   ClockGenerator7 clk_gen <- mkClockGenerator7(clk_params, clocked_by sys_clk, reset_by pci_sys_reset_n);

   Clock clk = clk_gen.clkout0;
   Reset rst_n <- mkAsyncReset( 1, pci_sys_reset_n, clk );
   Reset ddr3ref_rst_n <- mkAsyncReset( 1, rst_n, clk_gen.clkout1 );
   
   DDR3_Configure_K7 ddr3_cfg;
   ddr3_cfg.num_reads_in_flight = 2;   // adjust as needed
   ddr3_cfg.fast_train_sim_only = False; // adjust if simulating
   
   DDR3_Controller_K7 ddr3_ctrl <- mkKintex7DDR3Controller(ddr3_cfg, clocked_by clk_gen.clkout1, reset_by ddr3ref_rst_n);

   // ddr3_ctrl.user needs to connect to user logic and should use ddr3clk and ddr3rstn
   Clock ddr3clk = ddr3_ctrl.user.clock;
   Reset ddr3rstn = ddr3_ctrl.user.reset_n;
   
   SceMiK7PCIEArgs pcie_args;
   pcie_args.pci_sys_clk_p = pci_sys_clk_p;
   pcie_args.pci_sys_clk_n = pci_sys_clk_n;
   pcie_args.pci_sys_reset = pci_sys_reset_n;
   pcie_args.ref_clk       = clk_gen.clkout0;
   pcie_args.link_type     = PCIE_KINTEX7;

   SceMiK7PCIEQrcIfc#(MemSceMiLayerIfc, 8) scemi <- buildSceMiQrc(mkMemSceMiLayerWrapper, pcie_args);
   //MemSceMiLayerIfc scemiOrig =  scemi.orig_ifc;
   //let uclock = scemiOrig.uclock;
   //let ureset = scemiOrig.ureset;
   //SceMiLayer scemiLayer = scemiOrig.scemiLayer;
   
   //mkTieOff(scemi.noc_cont);
   
   let uclock = clk;
   let ureset = rst_n;
   SyncFIFOIfc#(MemoryRequest#(32,256)) fMemReq <- mkSyncFIFO(1, uclock, ureset, ddr3clk);
   SyncFIFOIfc#(MemoryResponse#(256))   fMemResp <- mkSyncFIFO(1, ddr3clk, ddr3rstn, uclock);
   
   //mkConnection(scemiLayer.memory.request,  toPut(fMemReq));
   //mkConnection(scemiLayer.memory.response, toGet(fMemResp));

   let memclient = interface Client;
		      interface request  = toGet(fMemReq);
		      interface response = toPut(fMemResp);
		   endinterface;
			 
   mkConnection( memclient, ddr3_ctrl.user, clocked_by ddr3clk, reset_by ddr3rstn );

   ReadOnly#(Bool) _isLinkUp         <- mkNullCrossingWire(noClock, scemi.isLinkUp);
   ReadOnly#(Bool) _isCalibrated     <- mkNullCrossingWire(noClock, ddr3_ctrl.user.init_done);
   
   interface pcie = scemi.pcie;
   interface ddr3 = ddr3_ctrl.ddr3;
   method leds = zeroExtend({ pack(_isCalibrated)
			     ,pack(False)
			     ,pack(False)
			     ,pack(_isLinkUp)
			     });
endmodule: mkBridge

module [SceMiModule] mkMemSceMiLayerWrapper(MemSceMiLayerIfc);

    (*hide*) let _m <- mkSceMiLayer();
    Clock uclk <- sceMiGetUClock;
    Reset urst <- sceMiGetUReset;

    interface scemiLayer = _m;
    interface uclock = uclk;
    interface ureset = urst;
endmodule

instance Connectable#(MemoryClient#(32, 256), DDR3_User_K7);
   module mkConnection#(MemoryClient#(32, 256) client, DDR3_User_K7 ddr3)(Empty);
      rule connect_requests;
	 let request <- client.request.get;
	 Bit#(28) address = truncate(request.address) << 2;
	 Bool     addrhi  = unpack(request.address[0]);
	 Bit#(64) writeen = addrhi ? zeroExtend(request.byteen) << 32 : zeroExtend(request.byteen);
	 Bit#(512) datain = duplicate(request.data);
	 if (request.write) begin
	    ddr3.request(address, writeen, datain);
	 end
	 else begin
	    ddr3.request(address, 0, ?);
	 end
      endrule
      
      rule connect_responses;
	 let response <- ddr3.read_data;
	 Bit#(256) data = truncate(response);
	 client.response.put(unpack(data));
      endrule
   endmodule
endinstance
