/*
 *
 * Note: the parameters set in this file and Top.bsv have been chose carefully.  They represent the
 *       minimal resource usage required to achieve maximum memory bandwidth utilization on the kc705
 *       and zedboard platforms.
 *       
 *       dma_read_buff: the zedboard requires at least 5 outstanding read commands to achieve full
 *       memory read bandwidth of 0.89 (40 64-bit beats with a burst-len of 8 beats).  We are unsure 
 *       exactly why, but each time a read request is transmitted, there is a 1-cycle delay in the 
 *       pipelined read responses (which otherwise return 64 bits per cycle).   With a burst length of 8 
 *       beats, this implies an 11% overhead.  The kc705 requires at least 8 outstanding read commands
 *       to achieve full read bandwidth of 1.0 (64 64-bit beats with a burst-len of 8 beats).  The
 *       unbuffered version of this test (memread_nobuff) achieves full throughput simply by permitting
 *       an unlimited number of outstanding read commands.  This is only safe if the application can 
 *       guarantee the availability of buffering to receive read responses.  If you don't know, be safe and
 *       use buffering.
 *        
 */

#ifndef _TESTMEMREAD_H_
#define _TESTMEMREAD_H_

#include "StdDmaIndication.h"
#include "DmaConfigProxy.h"
#include "GeneratedTypes.h" 
#include "MemreadRequestProxy.h"
#include "MemreadIndicationWrapper.h"

sem_t test_sem;


int burstLen = 16;
#ifdef MMAP_HW
int iterCnt = 64;
#else
int iterCnt = 3;
#endif

#ifdef MMAP_HW
int numWords = 0x1240000/4; // make sure to allocate at least one entry of each size
#else
int numWords = 0x124000/4;
#endif

size_t test_sz  = numWords*sizeof(unsigned int);
size_t alloc_sz = test_sz;
int mismatchCount = 0;

void dump(const char *prefix, char *buf, size_t len)
{
    fprintf(stderr, "%s ", prefix);
    for (int i = 0; i < (len > 16 ? 16 : len) ; i++)
	fprintf(stderr, "%02x", (unsigned char)buf[i]);
    fprintf(stderr, "\n");
}

class MemreadIndication : public MemreadIndicationWrapper
{
public:
  unsigned int rDataCnt;
  virtual void readDone(uint32_t v){
    fprintf(stderr, "Memread::readDone(%x)\n", v);
    mismatchCount += v;
    sem_post(&test_sem);
  }
  virtual void started(uint32_t words){
    fprintf(stderr, "Memread::started(%x)\n", words);
  }
  virtual void rData ( uint64_t v ){
    fprintf(stderr, "rData(%08x): ", rDataCnt++);
    dump("", (char*)&v, sizeof(v));
  }
  virtual void reportStateDbg(uint32_t streamRdCnt, uint32_t dataMismatch){
    fprintf(stderr, "Memread::reportStateDbg(%08x, %d)\n", streamRdCnt, dataMismatch);
  }  
  MemreadIndication(int id) : MemreadIndicationWrapper(id){}
};

void runtest(int argc, const char ** argv)
{

  PortalAlloc *srcAlloc;
  unsigned int *srcBuffer = 0;

  MemreadRequestProxy *device = 0;
  DmaConfigProxy *dmap = 0;
  
  MemreadIndication *deviceIndication = 0;
  DmaIndication *dmaIndication = 0;

  fprintf(stderr, "Main::%s %s\n", __DATE__, __TIME__);

  device = new MemreadRequestProxy(IfcNames_MemreadRequest);
  dmap = new DmaConfigProxy(IfcNames_DmaConfig);
  DmaManager *dma = new DmaManager(dmap);

  deviceIndication = new MemreadIndication(IfcNames_MemreadIndication);
  dmaIndication = new DmaIndication(dma, IfcNames_DmaIndication);

  fprintf(stderr, "Main::allocating memory...\n");
  dma->alloc(alloc_sz, &srcAlloc);
  srcBuffer = (unsigned int *)mmap(0, alloc_sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, srcAlloc->header.fd, 0);

  pthread_t tid;
  fprintf(stderr, "Main::creating exec thread\n");
  if(pthread_create(&tid, NULL,  portalExec, NULL)){
   fprintf(stderr, "error creating exec thread\n");
   exit(1);
  }

  for (int i = 0; i < numWords; i++){
    srcBuffer[i] = i;
  }
    
  dma->dCacheFlushInval(srcAlloc, srcBuffer);
  fprintf(stderr, "Main::flush and invalidate complete\n");
  device->getStateDbg();
  fprintf(stderr, "Main::after getStateDbg\n");

  unsigned int ref_srcAlloc = dma->reference(srcAlloc);
  fprintf(stderr, "ref_srcAlloc=%d\n", ref_srcAlloc);

  fprintf(stderr, "Main::starting read %08x\n", numWords);
  start_timer(0);
  device->startRead(ref_srcAlloc, numWords, burstLen, iterCnt);
  sem_wait(&test_sem);
  uint64_t cycles = lap_timer(0);
  uint64_t beats = dma->show_mem_stats(ChannelType_Read);
  float read_util = (float)beats/(float)cycles;
  fprintf(stderr, "   beats: %"PRIx64"\n", beats);
  fprintf(stderr, "numWords: %x\n", numWords);
  fprintf(stderr, "     est: %"PRIx64"\n", (beats*2)/iterCnt);
  fprintf(stderr, "memory read utilization (beats/cycle): %f\n", read_util);

  MonkitFile("perf.monkit")
    .setHwCycles(cycles)
    .setReadBwUtil(read_util)
    .writeFile();
  
}

#endif // _TESTMEMREAD_H_
