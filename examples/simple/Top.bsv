// bsv libraries
import Vector::*;
import FIFO::*;
import Connectable::*;

// portz libraries
import Directory::*;
import CtrlMux::*;
import Portal::*;
import Leds::*;
import AxiMasterSlave::*;

// generated by tool
import SimpleIndicationProxy::*;
import SimpleRequestWrapper::*;

// defined by user
import Simple::*;

typedef enum {SimpleIndication, SimpleRequest} IfcNames deriving (Eq,Bits);

module mkPortalTop(StdPortalTop#(addrWidth));

   // instantiate user portals
   SimpleIndicationProxy simpleIndicationProxy <- mkSimpleIndicationProxy(SimpleIndication);
   SimpleRequest simpleRequest <- mkSimpleRequest(simpleIndicationProxy.ifc);
   SimpleRequestWrapper simpleRequestWrapper <- mkSimpleRequestWrapper(SimpleRequest,simpleRequest);
   
   Vector#(2,StdPortal) portals;
   portals[0] = simpleRequestWrapper.portalIfc; 
   portals[1] = simpleIndicationProxy.portalIfc;
   let interrupt_mux <- mkInterruptMux(portals);
   
   // instantiate system directory
   StdDirectory dir <- mkStdDirectory(portals);
   let ctrl_mux <- mkAxiSlaveMux(dir,portals);
   
   interface interrupt = interrupt_mux;
   interface ctrl = ctrl_mux;
   interface m_axi = null_axi_master;
   interface leds = default_leds;

endmodule : mkPortalTop

