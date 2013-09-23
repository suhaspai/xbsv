// Copyright (c) 2008- 2009 Bluespec, Inc.  All rights reserved.
// $Revision$
// $Date$

package SceMiKintex7PCIEQrc;

// PCI-Express for Kintex 7
// FPGAs.

import Clocks       :: *;
import Connectable  :: *;
import TieOff       :: *;
import DefaultValue :: *;
import XilinxPCIE   :: *;
import XilinxCells  :: *;
import BlueNoC      :: *;

import SceMiDefines   :: *;
import SceMiInternals :: *;
import SceMiNoC       :: *;

// Interface wrapper for PCIE
interface SceMiK7PCIEQrcIfc#(type i, numeric type lanes);
   //interface i                orig_ifc;
   interface PCIE_EXP#(lanes) pcie;
   //interface MsgPort#(BPB)    noc_cont;
   (* always_ready *)
   method Bool isLinkUp();
   //(* always_ready *)
   //method Bool isOutOfReset();
   //(* always_ready *)
   //method Bool isClockAdvancing();
endinterface

// Argument structure used for passing in PCIE clocks
typedef struct {
   Clock         pci_sys_clk_p;
   Clock         pci_sys_clk_n;
   Reset         pci_sys_reset;
   Clock         ref_clk;
   SceMiLinkType link_type;
} SceMiK7PCIEArgs;

// This module builds the transactor hierarchy, the clock
// generation logic and the PCIE-to-port logic.
(* no_default_clock, no_default_reset *)
module [Module] buildSceMiPCIEK7Qrc#(
                                   Clock pci_sys_clk_p
                                 , Clock pci_sys_clk_n
                                 , Reset pci_sys_reset
                                 , Clock ref_clk
                                 , SceMiLinkType link_type
                                 )
                                 (SceMiK7PCIEQrcIfc#(i,lanes))
   provisos(Add#(1,_,lanes), SelectKintex7PCIE#(lanes));

   if (valueOf(lanes) != 8)
      errorM("Only 8-lane PCIe is supported on K7.");

   // Buffer clocks and reset before they are used
   Clock sys_clk_buf <- mkClockIBUFDS_GTE2(True, pci_sys_clk_p, pci_sys_clk_n);

   // Instantiate the PCIE endpoint
   PCIExpressK7#(lanes) _ep <- mkPCIExpressEndpointK7( defaultValue
                                                     , clocked_by sys_clk_buf
                                                     , reset_by pci_sys_reset
                                                     );
   mkTieOff(_ep.cfg);
   mkTieOff(_ep.cfg_interrupt);
   mkTieOff(_ep.cfg_err);
   mkTieOff(_ep.pl);

   // note our PCI ID
   PciId my_id = PciId { bus:  _ep.cfg.bus_number()
		       , dev:  _ep.cfg.device_number()
		       , func: _ep.cfg.function_number()
		       };

   // The PCIE endpoint is processing TLPWord#(8)s at 250MHz.  The
   // NoC bridge is accepting TLPWord#(16)s at 125 MHz. The
   // connection between the endpoint and the NoC contains GearBox
   // instances for the TLPWord#(8)@250 <--> TLPWord#(16)@125
   // conversion.

   // The PCIe endpoint exports full (250MHz) and half-speed (125MHz) clocks
   Clock epClock250 = _ep.trn.clk;
   Reset epReset250 <- mkAsyncReset(4, _ep.trn.reset_n, epClock250);
   Clock epClock125 = _ep.trn.clk2;
   Reset epReset125 <- mkAsyncReset(4, _ep.trn.reset_n, epClock125);

   // Extract some status info from the PCIE endpoint. These values are
   // all in the epClock250 domain, so we have to cross them into the
   // epClock125 domain.

   Bool link_is_up = _ep.trn.link_up();
   UInt#(13) max_read_req_bytes_250       = 128 << _ep.cfg.dcommand[14:12];
   UInt#(13) max_payload_bytes_250        = 128 << _ep.cfg.dcommand[7:5];
   UInt#(8)  read_completion_boundary_250 = 64 << _ep.cfg.lcommand[3];
   Bool      msix_enable_250              = (_ep.cfg_interrupt.msixenable() == 1);
   Bool      msix_masked_250              = (_ep.cfg_interrupt.msixfm()     == 1);

   CrossingReg#(UInt#(13)) max_rd_req_cr  <- mkNullCrossingReg(epClock125, 128,   clocked_by epClock250, reset_by epReset250);
   CrossingReg#(UInt#(13)) max_payload_cr <- mkNullCrossingReg(epClock125, 128,   clocked_by epClock250, reset_by epReset250);
   CrossingReg#(UInt#(8))  rcb_cr         <- mkNullCrossingReg(epClock125, 128,   clocked_by epClock250, reset_by epReset250);
   CrossingReg#(Bool)      msix_enable_cr <- mkNullCrossingReg(epClock125, False, clocked_by epClock250, reset_by epReset250);
   CrossingReg#(Bool)      msix_masked_cr <- mkNullCrossingReg(epClock125, True,  clocked_by epClock250, reset_by epReset250);

   Reg#(UInt#(13)) max_read_req_bytes <- mkReg(128,   clocked_by epClock125, reset_by epReset125);
   Reg#(UInt#(13)) max_payload_bytes  <- mkReg(128,   clocked_by epClock125, reset_by epReset125);
   Reg#(Bit#(7))   rcb_mask           <- mkReg(7'h3f, clocked_by epClock125, reset_by epReset125);
   Reg#(Bool)      msix_enable        <- mkReg(False, clocked_by epClock125, reset_by epReset125);
   Reg#(Bool)      msix_masked        <- mkReg(True,  clocked_by epClock125, reset_by epReset125);

   (* fire_when_enabled, no_implicit_conditions *)
   rule cross_config_values;
      max_rd_req_cr  <= max_read_req_bytes_250;
      max_payload_cr <= max_payload_bytes_250;
      rcb_cr         <= read_completion_boundary_250;
      msix_enable_cr <= msix_enable_250;
      msix_masked_cr <= msix_masked_250;
   endrule

   (* fire_when_enabled, no_implicit_conditions *)
   rule register_config_values;
      max_read_req_bytes <= max_rd_req_cr.crossed();
      max_payload_bytes  <= max_payload_cr.crossed();
      rcb_mask           <= (rcb_cr.crossed() == 64) ? 7'h3f : 7'h7f;
      msix_enable        <= msix_enable_cr.crossed();
      msix_masked        <= msix_masked_cr.crossed();
   endrule

   // setup PCIe interrupt for MSI-X
   // this rule executes in the epClock250 domain
   (* fire_when_enabled, no_implicit_conditions *)
   rule intr_ifc_ctl;
      _ep.cfg_interrupt.di('0);      // tied off for MSI-X
      _ep.cfg_interrupt.assrt('0);  // tied off for MSI-X
      _ep.cfg_interrupt.req(0);      // tied off for MSI-X
   endrule: intr_ifc_ctl

   // Build the PCIe-to-NoC bridge
   PCIEtoBNoC#(BPB)  bridge <- mkPCIEtoBNoC_4( 64'h05ce_0006_0008_6847
                                             , my_id
                                             , max_read_req_bytes
                                             , max_payload_bytes
                                             , rcb_mask
                                             , msix_enable
                                             , msix_masked
                                             , False // no MSI, only MSI-X
                                             , clocked_by epClock125, reset_by epReset125
                                             );
   mkConnectionWithClocks(_ep.trn_rx, tpl_2(bridge.tlps), epClock250, epReset250, epClock125, epReset125);
   mkConnectionWithClocks(_ep.trn_tx, tpl_1(bridge.tlps), epClock250, epReset250, epClock125, epReset125);

   // The reference clock is the base SCE-MI clock
   Clock scemiClock = ref_clk;

   // Propagate loss-of-partner as a reset to the SCE-MI
   MakeResetIfc network_status <- mkReset(4, True, scemiClock, clocked_by epClock125, reset_by epReset125);

   (* fire_when_enabled, no_implicit_conditions *)
   rule reset_scemi_if_network_is_inactive if (!bridge.is_activated());
      network_status.assertReset();
   endrule

   Reset scemiReset = network_status.new_rst;

   //mkConnection(_dut.noc_src,bridge.noc);
   mkTieOff(bridge.noc);

   // Pass along the required interface elements
   //interface orig_ifc = _dut.orig_ifc;
   interface pcie     = _ep.pcie;
   //interface noc_cont = _dut.noc_cont;
   method Bool isLinkUp         = link_is_up;
   //method Bool isOutOfReset     = _dut.isOutOfReset;
   //method Bool isClockAdvancing = _dut.isClockAdvancing;
   
endmodule: buildSceMiPCIEK7Qrc

endpackage: SceMiKintex7PCIEQrc