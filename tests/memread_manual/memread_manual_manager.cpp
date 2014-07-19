/* Copyright (c) 2014 Quanta Research Cambridge, Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#ifndef __KERNEL__
#include <sys/mman.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/select.h>
#endif

#include "portal.h"
#include "dmaManager.h"
#include "GeneratedTypes.h" 

static int trace_memory;// = 1;

#define MAX_INDARRAY 4
typedef int (*INDFUNC)(PortalInternal *p, unsigned int channel);
static PortalInternal *intarr[MAX_INDARRAY];
static INDFUNC indfn[MAX_INDARRAY];

static sem_t test_sem;
static int burstLen = 16;
#ifdef MMAP_HW
static int numWords = 0x1240000/4; // make sure to allocate at least one entry of each size
#else
static int numWords = 0x124000/4;
#endif
static size_t test_sz  = numWords*sizeof(unsigned int);
static size_t alloc_sz = test_sz;
static DmaManagerPrivate priv;

void DmaConfigProxyStatusputFailed_cb (  struct PortalInternal *p, const uint32_t v )
{
        const char* methodNameStrings[] = {"sglist", "region", "addrRequest", "getStateDbg", "getMemoryTraffic"};
        fprintf(stderr, "putFailed: %s\n", methodNameStrings[v]);
}
void MemreadRequestProxyStatusputFailed_cb (  struct PortalInternal *p, const uint32_t v )
{
        const char* methodNameStrings[] = {"startRead"};
        fprintf(stderr, "putFailed: %s\n", methodNameStrings[v]);
}
void MemreadIndicationWrapperreadDone_cb (  struct PortalInternal *p, const uint32_t mismatchCount )
{
         printf( "Memread_readDone(mismatch = %x)\n", mismatchCount);
         sem_post(&test_sem);
}
void DmaIndicationWrapperconfigResp_cb (  struct PortalInternal *p, const uint32_t pointer, const uint64_t msg )
{
        //fprintf(stderr, "configResp: %x, %"PRIx64"\n", pointer, msg);
        //fprintf(stderr, "configResp %d\n", pointer);
        sem_post(&priv.confSem);
}
void DmaIndicationWrapperaddrResponse_cb (  struct PortalInternal *p, const uint64_t physAddr )
{
        fprintf(stderr, "DmaIndication_addrResponse(physAddr=%"PRIx64")\n", physAddr);
}
void DmaIndicationWrapperbadPointer_cb (  struct PortalInternal *p, const uint32_t pointer )
{
        fprintf(stderr, "DmaIndication_badPointer(pointer=%x)\n", pointer);
}
void DmaIndicationWrapperbadAddrTrans_cb (  struct PortalInternal *p, const uint32_t pointer, const uint64_t offset, const uint64_t barrier )
{
        fprintf(stderr, "DmaIndication_badAddrTrans(pointer=%x, offset=%"PRIx64" barrier=%"PRIx64"\n", pointer, offset, barrier);
}
void DmaIndicationWrapperbadPageSize_cb (  struct PortalInternal *p, const uint32_t pointer, const uint32_t sz )
{
        fprintf(stderr, "DmaIndication_badPageSize(pointer=%x, len=%x)\n", pointer, sz);
}
void DmaIndicationWrapperbadNumberEntries_cb (  struct PortalInternal *p, const uint32_t pointer, const uint32_t sz, const uint32_t idx )
{
        fprintf(stderr, "DmaIndication_badNumberEntries(pointer=%x, len=%x, idx=%x)\n", pointer, sz, idx);
}
void DmaIndicationWrapperbadAddr_cb (  struct PortalInternal *p, const uint32_t pointer, const uint64_t offset, const uint64_t physAddr )
{
        fprintf(stderr, "DmaIndication_badAddr(pointer=%x offset=%"PRIx64" physAddr=%"PRIx64")\n", pointer, offset, physAddr);
}
void DmaIndicationWrapperreportStateDbg_cb (  struct PortalInternal *p, const DmaDbgRec rec )
{
        //fprintf(stderr, "reportStateDbg: {x:%08x y:%08x z:%08x w:%08x}\n", rec.x,rec.y,rec.z,rec.w);
        DmaDbgRec dbgRec = rec;
        fprintf(stderr, "dbgResp: %08x %08x %08x %08x\n", dbgRec.x, dbgRec.y, dbgRec.z, dbgRec.w);
        sem_post(&priv.dbgSem);
}
void DmaIndicationWrapperreportMemoryTraffic_cb (  struct PortalInternal *p, const uint64_t words )
{
        //fprintf(stderr, "reportMemoryTraffic: words=%"PRIx64"\n", words);
        priv.mtCnt = words;
        sem_post(&priv.mtSem);
}
void DmaIndicationWrappertagMismatch_cb (  struct PortalInternal *p, const ChannelType x, const uint32_t a, const uint32_t b )
{
        fprintf(stderr, "tagMismatch: %s %d %d\n", x==ChannelType_Read ? "Read" : "Write", a, b);
}

static void manual_event(void)
{
    for (int i = 0; i < MAX_INDARRAY; i++) {
      PortalInternal *instance = intarr[i];
      volatile unsigned int *map_base = instance->map_base;
      unsigned int queue_status;
      while ((queue_status= READL(instance, &map_base[IND_REG_QUEUE_STATUS]))) {
        unsigned int int_src = READL(instance, &map_base[IND_REG_INTERRUPT_FLAG]);
        unsigned int int_en  = READL(instance, &map_base[IND_REG_INTERRUPT_MASK]);
        unsigned int ind_count  = READL(instance, &map_base[IND_REG_INTERRUPT_COUNT]);
        fprintf(stderr, "(%d:fpga%d) about to receive messages int=%08x en=%08x qs=%08x\n", i, instance->fpga_number, int_src, int_en, queue_status);
        if (indfn[i])
            indfn[i](instance, queue_status-1);
      }
    }
}

#ifndef __KERNEL__ ///////////////////////// userspace version
static void *pthread_worker(void *p)
{
    void *rc = NULL;
    while (1) {
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000;
        manual_event();
        select(0, NULL, NULL, NULL, &timeout);
    }
    return rc;
}
#endif

int main(int argc, const char **argv)
{
  intarr[0] = new PortalInternal(IfcNames_DmaIndication);     // fpga1
  intarr[1] = new PortalInternal(IfcNames_MemreadIndication); // fpga2
  intarr[2] = new PortalInternal(IfcNames_DmaConfig);         // fpga3
  intarr[3] = new PortalInternal(IfcNames_MemreadRequest);    // fpga4
  indfn[0] = DmaIndicationWrapper_handleMessage;
  indfn[1] = MemreadIndicationWrapper_handleMessage;
  indfn[2] = DmaConfigProxyStatus_handleMessage;
  indfn[3] = MemreadRequestProxyStatus_handleMessage;

  PortalAlloc *srcAlloc;
  DmaManager_init(&priv, intarr[2]);
  int rc = DmaManager_alloc(&priv, alloc_sz, &srcAlloc);
  if (rc){
    fprintf(stderr, "portal alloc failed rc=%d\n", rc);
    return rc;
  }

#ifndef __KERNEL__ ///////////////////////// userspace version
  pthread_t tid;
  printf( "Main: creating exec thread\n");
  if(pthread_create(&tid, NULL,  pthread_worker, NULL)){
   printf( "error creating exec thread\n");
   exit(1);
  }
  unsigned int *srcBuffer = (unsigned int *)mmap(0, alloc_sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, srcAlloc->header.fd, 0);
#else   /// kernel version
//??????
#endif ////////////////////////////////

  for (int i = 0; i < numWords; i++)
    srcBuffer[i] = i;

#ifndef __KERNEL__   //////////////// userspace code for flushing dcache for srcAlloc
  DmaManager_dCacheFlushInval(&priv, srcAlloc, srcBuffer);
#else   /// kernel version
//??????
#endif /////////////////////
  unsigned int ref_srcAlloc = DmaManager_reference(&priv, srcAlloc);
  printf( "Main: starting read %08x\n", numWords);
  MemreadRequestProxy_startRead (intarr[3] , ref_srcAlloc, numWords, burstLen, 1);
  sem_wait(&test_sem);
  return 0;
}
