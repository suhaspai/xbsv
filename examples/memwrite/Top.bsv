// bsv libraries
import SpecialFIFOs::*;
import Vector::*;
import StmtFSM::*;
import FIFO::*;

// portz libraries
import AxiMasterSlave::*;
import Directory::*;
import CtrlMux::*;
import Portal::*;
import PortalMemory::*;
import PortalRMemory::*;
import AxiRDMA::*;

// generated by tool
import MemwriteRequestWrapper::*;
import DMARequestWrapper::*;
import MemwriteIndicationProxy::*;
import DMAIndicationProxy::*;

// defined by user
import Memwrite::*;

module mkPortalTop(StdPortalDmaTop#(addrWidth)) provisos (
    Add#(addrWidth, a__, 52),
    Add#(b__, addrWidth, 64),
    Add#(c__, 12, addrWidth),
    Add#(addrWidth, d__, 44));

   DMAIndicationProxy dmaIndicationProxy <- mkDMAIndicationProxy(9);
   DMAWriteBuffer#(64,16) dma_stream_write_chan <- mkDMAWriteBuffer();

   Vector#(0,  DMAReadClient#(64))   readClients = newVector();
   Vector#(1, DMAWriteClient#(64)) writeClients = newVector();
   writeClients[0] = dma_stream_write_chan.dmaClient;
   Integer               numRequests = 8;
   AxiDMAServer#(addrWidth,64)   dma <- mkAxiDMAServer(dmaIndicationProxy.ifc, numRequests, readClients, writeClients);
   DMARequestWrapper dmaRequestWrapper <- mkDMARequestWrapper(1005,dma.request);

   
   MemwriteIndicationProxy memwriteIndicationProxy <- mkMemwriteIndicationProxy(7);
   MemwriteRequest memwriteRequest <- mkMemwriteRequest(memwriteIndicationProxy.ifc, dma_stream_write_chan.dmaServer);
   MemwriteRequestWrapper memwriteRequestWrapper <- mkMemwriteRequestWrapper(1008,memwriteRequest);

   Vector#(4,StdPortal) portals;
   portals[0] = memwriteRequestWrapper.portalIfc;
   portals[1] = memwriteIndicationProxy.portalIfc; 
   portals[2] = dmaRequestWrapper.portalIfc;
   portals[3] = dmaIndicationProxy.portalIfc; 
   
   Directory dir <- mkDirectory(portals);
   Vector#(1,StdPortal) directories;
   directories[0] = dir.portalIfc;
   
   // when constructing ctrl and interrupt muxes, directories must be the first argument
   let ctrl_mux <- mkAxiSlaveMux(directories,portals);
   let interrupt_mux <- mkInterruptMux(portals);
   
   interface interrupt = interrupt_mux;
   interface ctrl = ctrl_mux;
   interface m_axi = replicate(dma.m_axi);
   interface leds = ?;
endmodule
