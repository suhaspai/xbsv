// bsv libraries
export Aurora::*;
export mkPortalTop;

import Vector::*;
import FIFO::*;
import Connectable::*;

// portz libraries
import Directory::*;
import CtrlMux::*;
import Portal::*;
import Leds::*;
import MemTypes::*;
import MemPortal::*;

// generated by tool
import AuroraIndicationProxy::*;
import AuroraRequestWrapper::*;

// defined by user
import Aurora::*;
typedef enum {AuroraIndication, AuroraRequest} IfcNames deriving (Eq,Bits);

module mkPortalTop(PortalTop#(addrWidth,64,AuroraPins,0));

   // instantiate user portals
   AuroraIndicationProxy auroraIndicationProxy <- mkAuroraIndicationProxy(AuroraIndication);
   let auroraRequest <- mkAuroraRequest(auroraIndicationProxy.ifc);
   AuroraRequestWrapper auroraRequestWrapper <- mkAuroraRequestWrapper(AuroraRequest,auroraRequest.request);
   
   Vector#(2,StdPortal) portals;
   portals[0] = auroraRequestWrapper.portalIfc;
   portals[1] = auroraIndicationProxy.portalIfc;
   
   // instantiate system directory
   StdDirectory dir <- mkStdDirectory(portals);
   let ctrl_mux <- mkSlaveMux(dir,portals);
   
   interface interrupt = getInterruptVector(portals);
   interface slave = ctrl_mux;
   interface masters = nil;
   interface leds = default_leds;
   interface pins = auroraRequest.pins;

endmodule : mkPortalTop
