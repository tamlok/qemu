/*
 * QEMU emulation of an Intel IOMMU
 *   (DMA Remapping device)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 * Lots of defines copied from kernel/include/linux/intel-iommu.h:
 *   Copyright (C) 2006-2008 Intel Corporation
 *   Author: Ashok Raj <ashok.raj@intel.com>
 *   Author: Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
 *
 * Copyright (c) 2013 Knut Omang, Oracle <knut.omang@oracle.com>
 *
 */

#ifndef _INTEL_IOMMU_H
#define _INTEL_IOMMU_H
#include "hw/qdev.h"
#include "sysemu/dma.h"

#define TYPE_INTEL_IOMMU_DEVICE "intel-iommu"
#define INTEL_IOMMU_DEVICE(obj) \
     OBJECT_CHECK(IntelIOMMUState, (obj), TYPE_INTEL_IOMMU_DEVICE)

/* DMAR Hardware Unit Definition address (IOMMU unit) set i bios */
#define Q35_HOST_BRIDGE_IOMMU_ADDR 0xfed90000ULL

/*
 * Intel IOMMU register specification per version 1.0 public spec.
 */

#define DMAR_VER_REG    0x0 /* Arch version supported by this IOMMU */
#define DMAR_CAP_REG    0x8 /* Hardware supported capabilities */
#define DMAR_CAP_REG_HI 0xc /* High 32-bit of DMAR_CAP_REG */
#define DMAR_ECAP_REG   0x10    /* Extended capabilities supported */
#define DMAR_ECAP_REG_HI    0X14
#define DMAR_GCMD_REG   0x18    /* Global command register */
#define DMAR_GSTS_REG   0x1c    /* Global status register */
#define DMAR_RTADDR_REG 0x20    /* Root entry table */
#define DMAR_RTADDR_REG_HI  0X24
#define DMAR_CCMD_REG   0x28  /* Context command reg */
#define DMAR_CCMD_REG_HI    0x2c
#define DMAR_FSTS_REG   0x34  /* Fault Status register */
#define DMAR_FECTL_REG  0x38 /* Fault control register */
#define DMAR_FEDATA_REG 0x3c    /* Fault event interrupt data register */
#define DMAR_FEADDR_REG 0x40    /* Fault event interrupt addr register */
#define DMAR_FEUADDR_REG    0x44   /* Upper address register */
#define DMAR_AFLOG_REG  0x58 /* Advanced Fault control */
#define DMAR_AFLOG_REG_HI   0X5c
#define DMAR_PMEN_REG   0x64  /* Enable Protected Memory Region */
#define DMAR_PLMBASE_REG    0x68    /* PMRR Low addr */
#define DMAR_PLMLIMIT_REG 0x6c  /* PMRR low limit */
#define DMAR_PHMBASE_REG 0x70   /* pmrr high base addr */
#define DMAR_PHMBASE_REG_HI 0X74
#define DMAR_PHMLIMIT_REG 0x78  /* pmrr high limit */
#define DMAR_PHMLIMIT_REG_HI 0x7c
#define DMAR_IQH_REG    0x80   /* Invalidation queue head register */
#define DMAR_IQH_REG_HI 0X84
#define DMAR_IQT_REG    0x88   /* Invalidation queue tail register */
#define DMAR_IQT_REG_HI 0X8c
#define DMAR_IQ_SHIFT   4 /* Invalidation queue head/tail shift */
#define DMAR_IQA_REG    0x90   /* Invalidation queue addr register */
#define DMAR_IQA_REG_HI 0x94
#define DMAR_ICS_REG    0x9c   /* Invalidation complete status register */
#define DMAR_IRTA_REG   0xb8    /* Interrupt remapping table addr register */
#define DMAR_IRTA_REG_HI    0xbc

/* From Vt-d 2.2 spec */
#define DMAR_IECTL_REG  0xa0    /* Invalidation event control register */
#define DMAR_IEDATA_REG 0xa4    /* Invalidation event data register */
#define DMAR_IEADDR_REG 0xa8    /* Invalidation event address register */
#define DMAR_IEUADDR_REG 0xac    /* Invalidation event address register */
#define DMAR_PQH_REG    0xc0    /* Page request queue head register */
#define DMAR_PQH_REG_HI 0xc4
#define DMAR_PQT_REG    0xc8    /* Page request queue tail register*/
#define DMAR_PQT_REG_HI     0xcc
#define DMAR_PQA_REG    0xd0    /* Page request queue address register */
#define DMAR_PQA_REG_HI 0xd4
#define DMAR_PRS_REG    0xdc    /* Page request status register */
#define DMAR_PECTL_REG  0xe0    /* Page request event control register */
#define DMAR_PEDATA_REG 0xe4    /* Page request event data register */
#define DMAR_PEADDR_REG 0xe8    /* Page request event address register */
#define DMAR_PEUADDR_REG  0xec  /* Page event upper address register */
#define DMAR_MTRRCAP_REG 0x100  /* MTRR capability register */
#define DMAR_MTRRCAP_REG_HI 0x104
#define DMAR_MTRRDEF_REG 0x108  /* MTRR default type register */
#define DMAR_MTRRDEF_REG_HI 0x10c

/* IOTLB */
#define DMAR_IOTLB_REG_OFFSET 0xf0  /* Offset to the IOTLB registers */
#define DMAR_IVA_REG DMAR_IOTLB_REG_OFFSET  /* Invalidate Address Register */
#define DMAR_IVA_REG_HI (DMAR_IVA_REG + 4)
/* IOTLB Invalidate Register */
#define DMAR_IOTLB_REG (DMAR_IOTLB_REG_OFFSET + 0x8)
#define DMAR_IOTLB_REG_HI (DMAR_IOTLB_REG + 4)

/* FRCD */
#define DMAR_FRCD_REG_OFFSET 0x220 /* Offset to the Fault Recording Registers */
#define DMAR_FRCD_REG_NR 1 /* Num of Fault Recording Registers */

#define DMAR_REG_SIZE   (DMAR_FRCD_REG_OFFSET + 128 * DMAR_FRCD_REG_NR)

#define VTD_PCI_BUS_MAX 256
#define VTD_PCI_SLOT_MAX 32
#define VTD_PCI_FUNC_MAX 8
#define VTD_PCI_SLOT(devfn)         (((devfn) >> 3) & 0x1f)
#define VTD_PCI_FUNC(devfn)         ((devfn) & 0x07)

typedef struct IntelIOMMUState IntelIOMMUState;
typedef struct VTDAddressSpace VTDAddressSpace;

struct VTDAddressSpace {
    int bus_num;
    int devfn;
    AddressSpace as;
    MemoryRegion iommu;
    IntelIOMMUState *iommu_state;
};

/* The iommu (DMAR) device state struct */
struct IntelIOMMUState {
    SysBusDevice busdev;
    MemoryRegion csrmem;
    uint8_t csr[DMAR_REG_SIZE];     /* register values */
    uint8_t wmask[DMAR_REG_SIZE];   /* R/W bytes */
    uint8_t w1cmask[DMAR_REG_SIZE]; /* RW1C(Write 1 to Clear) bytes */
    uint8_t womask[DMAR_REG_SIZE]; /* WO (write only - read returns 0) */
    uint32_t version;

    dma_addr_t root;  /* Current root table pointer */
    bool extended;    /* Type of root table (extended or not) */
    uint16_t iq_head; /* Current invalidation queue head */
    uint16_t iq_tail; /* Current invalidation queue tail */
    dma_addr_t iq;   /* Current invalidation queue (IQ) pointer */
    size_t iq_sz;    /* IQ Size in number of entries */
    bool iq_enable;  /* Set if the IQ is enabled */

    MemoryRegionIOMMUOps iommu_ops;
    VTDAddressSpace **address_spaces[VTD_PCI_BUS_MAX];
};


/* An invalidate descriptor */
typedef struct intel_iommu_inv_desc {
    uint64_t lower;
    uint64_t upper;
} intel_iommu_inv_desc;


/* Invalidate descriptor types */
#define CONTEXT_CACHE_INV_DESC  0x1
#define PASID_CACHE_INV_DESC    0x7
#define IOTLB_INV_DESC          0x2
#define EXT_IOTLB_INV_DESC      0x6
#define DEV_TLB_INV_DESC        0x3
#define EXT_DEV_TLB_INV_DESC    0x8
#define INT_ENTRY_INV_DESC      0x4
#define INV_WAIT_DESC           0x5


/* IOTLB_REG */
#define VTD_TLB_GLOBAL_FLUSH (1ULL << 60) /* Global invalidation */
#define VTD_TLB_DSI_FLUSH (2ULL << 60)  /* Domain-selective invalidation */
#define VTD_TLB_PSI_FLUSH (3ULL << 60)  /* Page-selective invalidation */
#define VTD_TLB_FLUSH_GRANU_MASK (3ULL << 60)
#define VTD_TLB_GLOBAL_FLUSH_A (1ULL << 57)
#define VTD_TLB_DSI_FLUSH_A (2ULL << 57)
#define VTD_TLB_PSI_FLUSH_A (3ULL << 57)
#define VTD_TLB_FLUSH_GRANU_MASK_A (3ULL << 57)
#define VTD_TLB_READ_DRAIN (1ULL << 49)
#define VTD_TLB_WRITE_DRAIN (1ULL << 48)
#define VTD_TLB_DID(id) (((uint64_t)((id) & 0xffffULL)) << 32)
#define VTD_TLB_IVT (1ULL << 63)
#define VTD_TLB_IH_NONLEAF (1ULL << 6)
#define VTD_TLB_MAX_SIZE (0x3f)

/* INVALID_DESC */
#define DMA_CCMD_INVL_GRANU_OFFSET  61
#define DMA_ID_TLB_GLOBAL_FLUSH (((uint64_t)1) << 3)
#define DMA_ID_TLB_DSI_FLUSH    (((uint64_t)2) << 3)
#define DMA_ID_TLB_PSI_FLUSH    (((uint64_t)3) << 3)
#define DMA_ID_TLB_READ_DRAIN   (((uint64_t)1) << 7)
#define DMA_ID_TLB_WRITE_DRAIN  (((uint64_t)1) << 6)
#define DMA_ID_TLB_DID(id)  (((uint64_t)((id & 0xffff) << 16)))
#define DMA_ID_TLB_IH_NONLEAF   (((uint64_t)1) << 6)
#define DMA_ID_TLB_ADDR(addr)   (addr)
#define DMA_ID_TLB_ADDR_MASK(mask)  (mask)

/* PMEN_REG */
#define DMA_PMEN_EPM (((uint32_t)1)<<31)
#define DMA_PMEN_PRS (((uint32_t)1)<<0)

/* GCMD_REG */
#define VTD_GCMD_TE (1UL << 31)
#define VTD_GCMD_SRTP (1UL << 30)
#define VTD_GCMD_SFL (1UL << 29)
#define VTD_GCMD_EAFL (1UL << 28)
#define VTD_GCMD_WBF (1UL << 27)
#define VTD_GCMD_QIE (1UL << 26)
#define VTD_GCMD_IRE (1UL << 25)
#define VTD_GCMD_SIRTP (1UL << 24)
#define VTD_GCMD_CFI (1UL << 23)

/* GSTS_REG */
#define VTD_GSTS_TES (1UL << 31)
#define VTD_GSTS_RTPS (1UL << 30)
#define VTD_GSTS_FLS (1UL << 29)
#define VTD_GSTS_AFLS (1UL << 28)
#define VTD_GSTS_WBFS (1UL << 27)
#define VTD_GSTS_QIES (1UL << 26)
#define VTD_GSTS_IRES (1UL << 25)
#define VTD_GSTS_IRTPS (1UL << 24)
#define VTD_GSTS_CFIS (1UL << 23)

/* CCMD_REG */
#define VTD_CCMD_ICC (1ULL << 63)
#define VTD_CCMD_GLOBAL_INVL (1ULL << 61)
#define VTD_CCMD_DOMAIN_INVL (2ULL << 61)
#define VTD_CCMD_DEVICE_INVL (3ULL << 61)
#define VTD_CCMD_CIRG_MASK (3ULL << 61)
#define VTD_CCMD_GLOBAL_INVL_A (1ULL << 59)
#define VTD_CCMD_DOMAIN_INVL_A (2ULL << 59)
#define VTD_CCMD_DEVICE_INVL_A (3ULL << 59)
#define VTD_CCMD_CAIG_MASK (3ULL << 59)
#define VTD_CCMD_FM(m) (((uint64_t)((m) & 3ULL)) << 32)
#define VTD_CCMD_MASK_NOBIT 0
#define VTD_CCMD_MASK_1BIT 1
#define VTD_CCMD_MASK_2BIT 2
#define VTD_CCMD_MASK_3BIT 3
#define VTD_CCMD_SID(s) (((uint64_t)((s) & 0xffffULL)) << 16)
#define VTD_CCMD_DID(d) ((uint64_t)((d) & 0xffffULL))

/* FECTL_REG */
#define DMA_FECTL_IM (((uint32_t)1) << 31)

/* FSTS_REG */
#define DMA_FSTS_PPF ((uint32_t)2)
#define DMA_FSTS_PFO ((uint32_t)1)
#define DMA_FSTS_IQE (1 << 4)
#define DMA_FSTS_ICE (1 << 5)
#define DMA_FSTS_ITE (1 << 6)
#define dma_fsts_fault_record_index(s) (((s) >> 8) & 0xff)

/* RTADDR_REG */
#define VTD_RTADDR_RTT (1ULL << 11)


/* ECAP_REG */
#define VTD_ECAP_IRO (DMAR_IOTLB_REG_OFFSET << 4)   /* (val >> 4) << 8 */

/* CAP_REG */

/* (val >> 4) << 24 */
#define VTD_CAP_FRO     ((uint64_t)DMAR_FRCD_REG_OFFSET << 20)

#define VTD_CAP_NFR     ((uint64_t)(DMAR_FRCD_REG_NR - 1) << 40)
#define VTD_DOMAIN_ID_SHIFT     16  /* 16-bit domain id for 64K domains */
#define VTD_CAP_ND  (((VTD_DOMAIN_ID_SHIFT - 4) / 2) & 7ULL)
#define VTD_MGAW    39  /* Maximum Guest Address Width */
#define VTD_CAP_MGAW    (((VTD_MGAW - 1) & 0x3fULL) << 16)
/* Supported Adjusted Guest Address Widths */
#define VTD_SAGAW_MASK  (0x1fULL << 8)
#define VTD_SAGAW_39bit (0x2ULL << 8)   /* 39-bit AGAW, 3-level page-table */
#define VTD_SAGAW_48bit (0x4ULL << 8)   /* 48-bit AGAW, 4-level page-table */

/* Register descriptor */
struct vtd_reg_desc {
    uint32_t offset;
    int size;
};
typedef struct vtd_reg_desc vtd_reg_desc;


/* Pagesize of VTD paging structures, including root and context tables */
#define VTD_PAGE_SHIFT      (12)
#define VTD_PAGE_SIZE       (1UL << VTD_PAGE_SHIFT)

#define VTD_PAGE_SHIFT_4K   (12)
#define VTD_PAGE_MASK_4K    (~((1ULL << VTD_PAGE_SHIFT_4K) - 1))
#define VTD_PAGE_SHIFT_2M   (21)
#define VTD_PAGE_MASK_2M    (~((1UL << VTD_PAGE_SHIFT_2M) - 1))
#define VTD_PAGE_SHIFT_1G   (30)
#define VTD_PAGE_MASK_1G    (~((1UL << VTD_PAGE_SHIFT_1G) - 1))

/* Root-Entry
 * 0: Present
 * 1-11: Reserved
 * 12-63: Context-table Pointer
 * 64-127: Reserved
 */
struct vtd_root_entry {
    uint64_t val;
    uint64_t rsvd;
};
typedef struct vtd_root_entry vtd_root_entry;

/* Masks for struct vtd_root_entry */
#define ROOT_ENTRY_P (1ULL << 0)
#define ROOT_ENTRY_CTP  (~0xfffULL)

#define ROOT_ENTRY_NR   (VTD_PAGE_SIZE / sizeof(vtd_root_entry))


/* Context-Entry */
struct vtd_context_entry {
    uint64_t lo;
    uint64_t hi;
};
typedef struct vtd_context_entry vtd_context_entry;

/* Masks for struct vtd_context_entry */
/* lo */
#define CONTEXT_ENTRY_P (1ULL << 0)
#define CONTEXT_ENTRY_FPD   (1ULL << 1) /* Fault Processing Disable */
#define CONTEXT_ENTRY_TT    (3ULL << 2) /* Translation Type */
#define CONTEXT_TT_MULTI_LEVEL  (0)
#define CONTEXT_TT_DEV_IOTLB    (1)
#define CONTEXT_TT_PASS_THROUGH (2)
/* Second Level Page Translation Pointer*/
#define CONTEXT_ENTRY_SLPTPTR   (~0xfffULL)

/* hi */
#define CONTEXT_ENTRY_AW    (7ULL) /* Adjusted guest-address-width */
#define CONTEXT_ENTRY_DID   (0xffffULL << 8)    /* Domain Identifier */


#define CONTEXT_ENTRY_NR    (VTD_PAGE_SIZE / sizeof(vtd_context_entry))


/* Paging Structure common */
#define SL_PT_PAGE_SIZE_MASK   (1ULL << 7)

/* Second Level Paging Structure */
#define SL_PML4_LEVEL 4
#define SL_PDP_LEVEL 3
#define SL_PD_LEVEL 2
#define SL_PT_LEVEL 1

#define SL_PT_ENTRY_NR  512
#define SL_PT_BASE_ADDR_MASK  (~(uint64_t)(VTD_PAGE_SIZE - 1))


#endif
