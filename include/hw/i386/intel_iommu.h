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
 */

#ifndef INTEL_IOMMU_H
#define INTEL_IOMMU_H
#include "hw/qdev.h"
#include "sysemu/dma.h"

#define TYPE_INTEL_IOMMU_DEVICE "intel-iommu"
#define INTEL_IOMMU_DEVICE(obj) \
     OBJECT_CHECK(IntelIOMMUState, (obj), TYPE_INTEL_IOMMU_DEVICE)

/* DMAR Hardware Unit Definition address (IOMMU unit) */
#define Q35_HOST_BRIDGE_IOMMU_ADDR 0xfed90000ULL

#define VTD_PCI_BUS_MAX 256
#define VTD_PCI_SLOT_MAX 32
#define VTD_PCI_FUNC_MAX 8
#define VTD_PCI_SLOT(devfn)         (((devfn) >> 3) & 0x1f)
#define VTD_PCI_FUNC(devfn)         ((devfn) & 0x07)

#define DMAR_REG_SIZE   0x2a0

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

#endif
