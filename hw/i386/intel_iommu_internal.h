/*
 * QEMU emulation of an Intel IOMMU (VT-d)
 *   (DMA Remapping device)
 *
 * Copyright (C) 2013 Knut Omang, Oracle <knut.omang@oracle.com>
 * Copyright (C) 2014 Le Tan, <tamlokveer@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * Lots of defines copied from kernel/include/linux/intel-iommu.h:
 *   Copyright (C) 2006-2008 Intel Corporation
 *   Author: Ashok Raj <ashok.raj@intel.com>
 *   Author: Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
 *
 */

#ifndef HW_I386_INTEL_IOMMU_INTERNAL_H
#define HW_I386_INTEL_IOMMU_INTERNAL_H
#include "hw/i386/intel_iommu.h"

/*
 * Intel IOMMU register specification
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
/* NOTICE: If you change the DMAR_FRCD_REG_NR, please remember to change the
 * DMAR_REG_SIZE in include/hw/i386/intel_iommu.h.
 * #define DMAR_REG_SIZE   (DMAR_FRCD_REG_OFFSET + 16 * DMAR_FRCD_REG_NR)
 */
#define DMAR_FRCD_REG_NR 1ULL /* Num of Fault Recording Registers */

#define DMAR_FRCD_REG_0_0    0x220 /* The 0th Fault Recording Register */
#define DMAR_FRCD_REG_0_1    0x224
#define DMAR_FRCD_REG_0_2    0x228
#define DMAR_FRCD_REG_0_3    0x22c

/* Interrupt Address Range */
#define VTD_INTERRUPT_ADDR_FIRST    0xfee00000ULL
#define VTD_INTERRUPT_ADDR_LAST     0xfeefffffULL

/* IOTLB_REG */
#define VTD_TLB_GLOBAL_FLUSH (1ULL << 60) /* Global invalidation */
#define VTD_TLB_DSI_FLUSH (2ULL << 60)  /* Domain-selective invalidation */
#define VTD_TLB_PSI_FLUSH (3ULL << 60)  /* Page-selective invalidation */
#define VTD_TLB_FLUSH_GRANU_MASK (3ULL << 60)
#define VTD_TLB_GLOBAL_FLUSH_A (1ULL << 57)
#define VTD_TLB_DSI_FLUSH_A (2ULL << 57)
#define VTD_TLB_PSI_FLUSH_A (3ULL << 57)
#define VTD_TLB_FLUSH_GRANU_MASK_A (3ULL << 57)
#define VTD_TLB_IVT (1ULL << 63)

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

/* RTADDR_REG */
#define VTD_RTADDR_RTT (1ULL << 11)
#define VTD_RTADDR_ADDR_MASK (VTD_HAW_MASK ^ 0xfffULL)

/* ECAP_REG */
#define VTD_ECAP_IRO (DMAR_IOTLB_REG_OFFSET << 4)  /* (offset >> 4) << 8 */
#define VTD_ECAP_QI  (1ULL << 1)

/* CAP_REG */
#define VTD_CAP_FRO  (DMAR_FRCD_REG_OFFSET << 20) /* (offset >> 4) << 24 */
#define VTD_CAP_NFR  ((DMAR_FRCD_REG_NR - 1) << 40)
#define VTD_DOMAIN_ID_SHIFT     16  /* 16-bit domain id for 64K domains */
#define VTD_CAP_ND  (((VTD_DOMAIN_ID_SHIFT - 4) / 2) & 7ULL)
#define VTD_MGAW    39  /* Maximum Guest Address Width */
#define VTD_CAP_MGAW    (((VTD_MGAW - 1) & 0x3fULL) << 16)

/* Supported Adjusted Guest Address Widths */
#define VTD_CAP_SAGAW_SHIFT (8)
#define VTD_CAP_SAGAW_MASK  (0x1fULL << VTD_CAP_SAGAW_SHIFT)
 /* 39-bit AGAW, 3-level page-table */
#define VTD_CAP_SAGAW_39bit (0x2ULL << VTD_CAP_SAGAW_SHIFT)
 /* 48-bit AGAW, 4-level page-table */
#define VTD_CAP_SAGAW_48bit (0x4ULL << VTD_CAP_SAGAW_SHIFT)
#define VTD_CAP_SAGAW       VTD_CAP_SAGAW_39bit

/* IQT_REG */
#define VTD_IQT_QT(val)     (((val) >> 4) & 0x7fffULL)

/* IQA_REG */
#define VTD_IQA_IQA_MASK    (VTD_HAW_MASK ^ 0xfffULL)
#define VTD_IQA_QS          (0x7ULL)

/* IQH_REG */
#define VTD_IQH_QH_SHIFT    (4)
#define VTD_IQH_QH_MASK     (0x7fff0ULL)

/* ICS_REG */
#define VTD_ICS_IWC         (1UL)

/* IECTL_REG */
#define VTD_IECTL_IM        (1UL << 31)
#define VTD_IECTL_IP        (1UL << 30)

/* FSTS_REG */
#define VTD_FSTS_FRI_MASK  (0xff00)
#define VTD_FSTS_FRI(val)  ((((uint32_t)(val)) << 8) & VTD_FSTS_FRI_MASK)
#define VTD_FSTS_IQE       (1UL << 4)
#define VTD_FSTS_PPF       (1UL << 1)
#define VTD_FSTS_PFO       (1UL)

/* FECTL_REG */
#define VTD_FECTL_IM       (1UL << 31)
#define VTD_FECTL_IP       (1UL << 30)

/* Fault Recording Register */
/* For the high 64-bit of 128-bit */
#define VTD_FRCD_F         (1ULL << 63)
#define VTD_FRCD_T         (1ULL << 62)
#define VTD_FRCD_FR(val)   (((val) & 0xffULL) << 32)
#define VTD_FRCD_SID_MASK   0xffffULL
#define VTD_FRCD_SID(val)  ((val) & VTD_FRCD_SID_MASK)
/* For the low 64-bit of 128-bit */
#define VTD_FRCD_FI(val)   ((val) & (((1ULL << VTD_MGAW) - 1) ^ 0xfffULL))

/* DMA Remapping Fault Conditions */
typedef enum VTDFaultReason {
    /* Reserved for Advanced Fault logging. We use this to represent the case
     * with no fault event.
     */
    VTD_FR_RESERVED = 0,
    VTD_FR_ROOT_ENTRY_P = 1, /* The Present(P) field of root-entry is 0 */
    VTD_FR_CONTEXT_ENTRY_P, /* The Present(P) field of context-entry is 0 */
    VTD_FR_CONTEXT_ENTRY_INV, /* Invalid programming of a context-entry */
    VTD_FR_ADDR_BEYOND_MGAW, /* Input-address above (2^x-1) */
    VTD_FR_WRITE, /* No write permission */
    VTD_FR_READ, /* No read permission */
    /* Fail to access a second-level paging entry (not SL_PML4E) */
    VTD_FR_PAGING_ENTRY_INV,
    VTD_FR_ROOT_TABLE_INV, /* Fail to access a root-entry */
    VTD_FR_CONTEXT_TABLE_INV, /* Fail to access a context-entry */
    /* Non-zero reserved field in a present root-entry */
    VTD_FR_ROOT_ENTRY_RSVD,
    /* Non-zero reserved field in a present context-entry */
    VTD_FR_CONTEXT_ENTRY_RSVD,
    /* Non-zero reserved field in a second-level paging entry with at lease one
     * Read(R) and Write(W) or Execute(E) field is Set.
     */
    VTD_FR_PAGING_ENTRY_RSVD,
    /* Translation request or translated request explicitly blocked dut to the
     * programming of the Translation Type (T) field in the present
     * context-entry.
     */
    VTD_FR_CONTEXT_ENTRY_TT,
    /* This is not a normal fault reason. We use this to indicate some faults
     * that are not referenced by the VT-d specification.
     * Fault event with such reason should not be recorded.
     */
    VTD_FR_RESERVED_ERR,
    /* Guard */
    VTD_FR_MAX,
} VTDFaultReason;


/* Masks for Queued Invalidation Descriptor */
#define VTD_INV_DESC_TYPE  (0xf)
#define VTD_INV_DESC_CC    (0x1) /* Context-cache Invalidate Descriptor */
#define VTD_INV_DESC_IOTLB (0x2)
#define VTD_INV_DESC_WAIT  (0x5) /* Invalidation Wait Descriptor */
#define VTD_INV_DESC_NONE  (0)   /* Not an Invalidate Descriptor */


/* Pagesize of VTD paging structures, including root and context tables */
#define VTD_PAGE_SHIFT      (12)
#define VTD_PAGE_SIZE       (1ULL << VTD_PAGE_SHIFT)

#define VTD_PAGE_SHIFT_4K   (12)
#define VTD_PAGE_MASK_4K    (~((1ULL << VTD_PAGE_SHIFT_4K) - 1))
#define VTD_PAGE_SHIFT_2M   (21)
#define VTD_PAGE_MASK_2M    (~((1ULL << VTD_PAGE_SHIFT_2M) - 1))
#define VTD_PAGE_SHIFT_1G   (30)
#define VTD_PAGE_MASK_1G    (~((1ULL << VTD_PAGE_SHIFT_1G) - 1))

/* Root-Entry
 * 0: Present
 * 1-11: Reserved
 * 12-63: Context-table Pointer
 * 64-127: Reserved
 */
struct VTDRootEntry {
    uint64_t val;
    uint64_t rsvd;
};
typedef struct VTDRootEntry VTDRootEntry;

/* Masks for struct VTDRootEntry */
#define VTD_ROOT_ENTRY_P (1ULL << 0)
#define VTD_ROOT_ENTRY_CTP  (~0xfffULL)

#define VTD_ROOT_ENTRY_NR   (VTD_PAGE_SIZE / sizeof(VTDRootEntry))
#define VTD_ROOT_ENTRY_RSVD (0xffeULL | ~VTD_HAW_MASK)

/* Context-Entry */
struct VTDContextEntry {
    uint64_t lo;
    uint64_t hi;
};
typedef struct VTDContextEntry VTDContextEntry;

/* Masks for struct VTDContextEntry */
/* lo */
#define VTD_CONTEXT_ENTRY_P (1ULL << 0)
#define VTD_CONTEXT_ENTRY_FPD   (1ULL << 1) /* Fault Processing Disable */
#define VTD_CONTEXT_ENTRY_TT    (3ULL << 2) /* Translation Type */
#define VTD_CONTEXT_TT_MULTI_LEVEL  (0)
#define VTD_CONTEXT_TT_DEV_IOTLB    (1)
#define VTD_CONTEXT_TT_PASS_THROUGH (2)
/* Second Level Page Translation Pointer*/
#define VTD_CONTEXT_ENTRY_SLPTPTR   (~0xfffULL)
#define VTD_CONTEXT_ENTRY_RSVD_LO   (0xff0ULL | ~VTD_HAW_MASK)
/* hi */
#define VTD_CONTEXT_ENTRY_AW    (7ULL) /* Adjusted guest-address-width */
#define VTD_CONTEXT_ENTRY_DID   (0xffffULL << 8)    /* Domain Identifier */
#define VTD_CONTEXT_ENTRY_RSVD_HI   (0xffffffffff000080ULL)

#define VTD_CONTEXT_ENTRY_NR    (VTD_PAGE_SIZE / sizeof(VTDContextEntry))


/* Paging Structure common */
#define VTD_SL_PT_PAGE_SIZE_MASK   (1ULL << 7)
#define VTD_SL_LEVEL_BITS   9   /* Bits to decide the offset for each level */

/* Second Level Paging Structure */
#define VTD_SL_PML4_LEVEL   4
#define VTD_SL_PDP_LEVEL    3
#define VTD_SL_PD_LEVEL     2
#define VTD_SL_PT_LEVEL     1
#define VTD_SL_PT_ENTRY_NR  512

/* Masks for Second Level Paging Entry */
#define VTD_SL_RW_MASK              (3ULL)
#define VTD_SL_R                    (1ULL)
#define VTD_SL_W                    (1ULL << 1)
#define VTD_SL_PT_BASE_ADDR_MASK    (~(VTD_PAGE_SIZE - 1) & VTD_HAW_MASK)
#define VTD_SL_IGN_COM    (0xbff0000000000000ULL)

#endif
