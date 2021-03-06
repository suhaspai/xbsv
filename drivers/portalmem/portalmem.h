
#ifndef __PORTALALLOC_H__
#define __PORTALALLOC_H__

typedef struct PortalAllocHeader {
    size_t size;
    int fd;
    int numEntries;
} PortalAllocHeader;

typedef struct DmaEntry {
  dma_addr_t dma_address;
  unsigned int length; // to match length field in scatterlist.h
} DmaEntry;


typedef struct PortalAlloc {
  PortalAllocHeader header;
  DmaEntry entries[0];
} PortalAlloc;

#define PA_ALLOC _IOWR('B', 10, PortalAlloc)
#define PA_DCACHE_FLUSH_INVAL _IOWR('B', 11, PortalAlloc)
#define PA_DMA_ADDRESSES _IOWR('B', 13, PortalAlloc)

#endif /* __PORTALALLOC_H__ */
