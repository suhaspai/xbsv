// bsv libraries
import SpecialFIFOs::*;
import Vector::*;
import StmtFSM::*;
import FIFO::*;

// portz libraries
import Leds::*;
import Directory::*;
import CtrlMux::*;
import Portal::*;
import PortalMemory::*;
import MemTypes::*;
import MemServer::*;

// generated by tool
import MemwriteRequestWrapper::*;
import DmaConfigWrapper::*;
import MemwriteIndicationProxy::*;
import DmaIndicationProxy::*;

// defined by user
import Memwrite::*;

typedef enum {DmaIndication, DmaConfig, MemwriteIndication, MemwriteRequest} IfcNames deriving (Eq,Bits);

module mkPortalTop(StdPortalDmaTop#(addrWidth)) 

   provisos(Add#(addrWidth, a__, 52),
	    Add#(b__, addrWidth, 64),
	    Add#(c__, 12, addrWidth),
	    Add#(addrWidth, d__, 44),
	    Add#(e__, c__, 40),
	    Add#(f__, addrWidth, 40));

   MemwriteIndicationProxy memwriteIndicationProxy <- mkMemwriteIndicationProxy(MemwriteIndication);
   Memwrite memwrite <- mkMemwrite(memwriteIndicationProxy.ifc);
   MemwriteRequestWrapper memwriteRequestWrapper <- mkMemwriteRequestWrapper(MemwriteRequest,memwrite.request);

   Vector#(1, ObjectWriteClient#(64)) writeClients = cons(memwrite.dmaClient,nil);
   DmaIndicationProxy dmaIndicationProxy <- mkDmaIndicationProxy(DmaIndication);
   MemServer#(addrWidth,64,1)   dma <- mkMemServerW(dmaIndicationProxy.ifc, writeClients);
   DmaConfigWrapper dmaRequestWrapper <- mkDmaConfigWrapper(DmaConfig ,dma.request);

   
   Vector#(4,StdPortal) portals;
   portals[0] = memwriteRequestWrapper.portalIfc;
   portals[1] = memwriteIndicationProxy.portalIfc; 
   portals[2] = dmaRequestWrapper.portalIfc;
   portals[3] = dmaIndicationProxy.portalIfc; 
   
   StdDirectory dir <- mkStdDirectory(portals);
   let ctrl_mux <- mkSlaveMux(dir,portals);
   
   interface interrupt = getInterruptVector(portals);
   interface slave = ctrl_mux;
   interface masters = dma.masters;
   interface leds = default_leds;
endmodule
