
// Copyright (c) 2013-2014 Quanta Research Cambridge, Inc.

// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "dmaManager.h"
#include "DmaIndicationWrapper.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

static int error_limit = 20;
class DmaIndication : public DmaIndicationWrapper
{
  DmaManager *portalMemory;
  int tag_mismatch_cnt;
 public:
  DmaIndication(DmaManager *pm, unsigned int  id) : DmaIndicationWrapper(id), portalMemory(pm), tag_mismatch_cnt(0) {}
  virtual void configResp(uint32_t pointer, uint64_t msg){
    //fprintf(stderr, "configResp: %x, %"PRIx64"\n", pointer, msg);
    portalMemory->confResp(pointer);
  }
  virtual void addrResponse(uint64_t physAddr){
    fprintf(stderr, "DmaIndication::addrResponse(physAddr=%"PRIx64")\n", physAddr);
  }
  //unused virtual void parefResp(uint32_t pointer){
    //unused fprintf(stderr, "DmaIndication::parefResp(pointer=%x)\n", pointer);
  //unused }
  virtual void badPointer (uint32_t pointer) {
    fprintf(stderr, "DmaIndication::badPointer(pointer=%x)\n", pointer);
  }
  virtual void badPageSize (uint32_t pointer, uint32_t sz) {
    fprintf(stderr, "DmaIndication::badPageSize(pointer=%x, sz=%x)\n", pointer, sz);
  }
  virtual void badNumberEntries (uint32_t pointer, uint32_t sz, uint32_t idx) {
    fprintf(stderr, "DmaIndication::badNumberEntries(pointer=%x, sz=%x, idx=%x)\n", pointer, sz, idx);
  }
  virtual void badAddrTrans (uint32_t pointer, uint64_t offset, uint64_t barrier) {
    fprintf(stderr, "DmaIndication::badAddrTrans(pointer=%x, offset=%"PRIx64" barrier=%"PRIx64"\n", pointer, offset, barrier);
    if (--error_limit < 0)
        exit(-1);
  }
  virtual void badAddr (uint32_t pointer, uint64_t offset , uint64_t physAddr) {
    fprintf(stderr, "DmaIndication::badAddr(pointer=%x offset=%"PRIx64" physAddr=%"PRIx64")\n", pointer, offset, physAddr);
  }
  virtual void reportStateDbg(const DmaDbgRec rec){
    //fprintf(stderr, "reportStateDbg: {x:%08x y:%08x z:%08x w:%08x}\n", rec.x,rec.y,rec.z,rec.w);
    portalMemory->dbgResp(rec);
  }
  virtual void reportMemoryTraffic(uint64_t words){
    //fprintf(stderr, "reportMemoryTraffic: words=%"PRIx64"\n", words);
    portalMemory->mtResp(words);
  }
  virtual void tagMismatch(const ChannelType x, uint32_t a, uint32_t b){
    //if (tag_mismatch_cnt++ < 10)
    fprintf(stderr, "tagMismatch: %s %d %d\n", x==ChannelType_Read ? "Read" : "Write", a, b);
  }
};
