// bsv libraries
import Vector::*;
import FIFO::*;
import Connectable::*;

// portz libraries
import Portal::*;
import Directory::*;
import CtrlMux::*;
import Portal::*;
import Leds::*;
import AxiMasterSlave::*;
import MemTypes::*;


// generated by tool
import PipeMulIndicationProxy::*;
import PipeMulRequestWrapper::*;

// defined by user
import PipeMulTB::*;

typedef enum {PipeMulIndication, PipeMulRequest} IfcNames deriving (Eq,Bits);

module mkPortalTop(StdPortalTop#(addrWidth));

   // instantiate user portals
   PipeMulIndicationProxy indProxy <- mkPipeMulIndicationProxy(PipeMulIndication);
   PipeMulTB pmTB <- mkPipeMulTB(indProxy.ifc);
   PipeMulRequestWrapper reqWrapper <- mkPipeMulRequestWrapper(PipeMulRequest,pmTB.ifc);
   
   Vector#(2,StdPortal) portals;
   portals[0] = indProxy.portalIfc;
   portals[1] = reqWrapper.portalIfc; 
   
   // instantiate system directory
   StdDirectory dir <- mkStdDirectory(portals);
   let ctrl_mux <- mkSlaveMux(dir,portals);
   
   interface interrupt = getInterruptVector(portals);
   interface slave = ctrl_mux;
   interface masters = nil;
   interface leds = pmTB.leds;

endmodule : mkPortalTop
