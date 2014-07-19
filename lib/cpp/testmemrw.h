#ifndef _TESTMEMRW_H_
#define _TESTMEMRW_H_

#include "StdDmaIndication.h"
#include "DmaConfigProxy.h"
#include "GeneratedTypes.h"
#include "MemrwIndicationWrapper.h"
#include "MemrwRequestProxy.h"

sem_t read_done_sem;
sem_t write_done_sem;
PortalAlloc *srcAlloc;
PortalAlloc *dstAlloc;
unsigned int *srcBuffer = 0;
unsigned int *dstBuffer = 0;
#ifdef MMAP_HW
int numWords = 16 << 18;
#else
int numWords = 16 << 10;
#endif
size_t alloc_sz = numWords*sizeof(unsigned int);
bool finished = false;
uint64_t read_cycles;
uint64_t write_cycles;

class MemrwIndication : public MemrwIndicationWrapper
{

public:
  MemrwIndication(unsigned int id) : MemrwIndicationWrapper(id){}

  virtual void started(){
    fprintf(stderr, "started\n");
  }
  virtual void readDone() {
    read_cycles = lap_timer(0);
    sem_post(&read_done_sem);
    fprintf(stderr, "readDone\n");
  }
  virtual void writeDone() {
    write_cycles = lap_timer(0);
    sem_post(&write_done_sem);
    fprintf(stderr, "writeDone\n");
  }
};


// we can use the data synchronization barrier instead of flushing the 
// cache only because the ps7 is configured to run in buffered-write mode
//
// an opc2 of '4' and CRm of 'c10' encodes "CP15DSB, Data Synchronization Barrier 
// operation". this is a legal instruction to execute in non-privileged mode (mdk)
//
// #define DATA_SYNC_BARRIER   __asm __volatile( "MCR p15, 0, %0, c7, c10, 4" ::  "r" (0) );

int runtest(int argc, const char **argv)
{
  MemrwRequestProxy *device = 0;
  DmaConfigProxy *dmap = 0;
  
  MemrwIndication *deviceIndication = 0;
  DmaIndication *dmaIndication = 0;

  if(sem_init(&read_done_sem, 1, 0)){
    fprintf(stderr, "failed to init read_done_sem\n");
    exit(1);
  }
  if(sem_init(&write_done_sem, 1, 0)){
    fprintf(stderr, "failed to init write_done_sem\n");
    exit(1);
  }

  fprintf(stderr, "%s %s\n", __DATE__, __TIME__);

  device = new MemrwRequestProxy(IfcNames_MemrwRequest);
  dmap = new DmaConfigProxy(IfcNames_DmaConfig);
  DmaManager *dma = new DmaManager(dmap);

  deviceIndication = new MemrwIndication(IfcNames_MemrwIndication);
  dmaIndication = new DmaIndication(dma, IfcNames_DmaIndication);

  fprintf(stderr, "Main::allocating memory...\n");

  dma->alloc(alloc_sz, &srcAlloc);
  dma->alloc(alloc_sz, &dstAlloc);

  // for(int i = 0; i < srcAlloc->header.numEntries; i++)
  //   fprintf(stderr, "%lx %lx\n", srcAlloc->entries[i].dma_address, srcAlloc->entries[i].length);
  // for(int i = 0; i < dstAlloc->header.numEntries; i++)
  //   fprintf(stderr, "%lx %lx\n", dstAlloc->entries[i].dma_address, dstAlloc->entries[i].length);

  srcBuffer = (unsigned int *)mmap(0, alloc_sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, srcAlloc->header.fd, 0);
  dstBuffer = (unsigned int *)mmap(0, alloc_sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, dstAlloc->header.fd, 0);

  pthread_t tid;
  fprintf(stderr, "creating exec thread\n");
  if(pthread_create(&tid, NULL,  portalExec, NULL)){
    fprintf(stderr, "error creating exec thread\n");
    exit(1);
  }

  for (int i = 0; i < numWords; i++){
    srcBuffer[i] = i;
    dstBuffer[i] = 0x5a5abeef;
  }

  dma->dCacheFlushInval(srcAlloc, srcBuffer);
  dma->dCacheFlushInval(dstAlloc, dstBuffer);
  fprintf(stderr, "Main::flush and invalidate complete\n");

  unsigned int ref_srcAlloc = dma->reference(srcAlloc);
  unsigned int ref_dstAlloc = dma->reference(dstAlloc);
  
  sleep(1);
  dmap->addrRequest(ref_srcAlloc, 1*sizeof(unsigned int));
  sleep(1);
  dmap->addrRequest(ref_dstAlloc, 2*sizeof(unsigned int));
  sleep(1);
  
  fprintf(stderr, "Main::starting mempcy numWords:%d\n", numWords);
  int burstLen = 16;
#ifdef MMAP_HW
  int iterCnt = 64;
#else
  int iterCnt = 2;
#endif
  start_timer(0);
  device->start(ref_dstAlloc, ref_srcAlloc, numWords, burstLen, iterCnt);
  sem_wait(&read_done_sem);
  sem_wait(&write_done_sem);
  uint64_t hw_cycles = lap_timer(0); 
  uint64_t read_beats = dma->show_mem_stats(ChannelType_Read);
  uint64_t write_beats = dma->show_mem_stats(ChannelType_Write);
  float read_util = (float)read_beats/(float)read_cycles;
  float write_util = (float)write_beats/(float)write_cycles;

  fprintf(stderr, "memory read utilization (beats/cycle): %f\n", read_util);
  fprintf(stderr, "memory write utilization (beats/cycle): %f\n", write_util);

  MonkitFile("perf.monkit")
    .setHwCycles(hw_cycles)
    .setReadBwUtil(read_util)
    .setWriteBwUtil(write_util)
    .writeFile();

}

#endif //_TESTMEMRW_H_
