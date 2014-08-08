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

#include "hw/sysbus.h"
#include "exec/address-spaces.h"
#include "intel_iommu_internal.h"


/*#define DEBUG_INTEL_IOMMU*/
#ifdef DEBUG_INTEL_IOMMU
enum {
    DEBUG_GENERAL, DEBUG_CSR, DEBUG_INV, DEBUG_MMU, DEBUG_FLOG,
};
#define VTD_DBGBIT(x)   (1 << DEBUG_##x)
static int vtd_dbgflags = VTD_DBGBIT(GENERAL) | VTD_DBGBIT(CSR) |
                          VTD_DBGBIT(FLOG);

#define VTD_DPRINTF(what, fmt, ...) do { \
    if (vtd_dbgflags & VTD_DBGBIT(what)) { \
        fprintf(stderr, "(vtd)%s: " fmt "\n", __func__, \
                ## __VA_ARGS__); } \
    } while (0)
#else
#define VTD_DPRINTF(what, fmt, ...) do {} while (0)
#endif

static inline void define_quad(IntelIOMMUState *s, hwaddr addr, uint64_t val,
                               uint64_t wmask, uint64_t w1cmask)
{
    stq_le_p(&s->csr[addr], val);
    stq_le_p(&s->wmask[addr], wmask);
    stq_le_p(&s->w1cmask[addr], w1cmask);
}

static inline void define_quad_wo(IntelIOMMUState *s, hwaddr addr,
                                  uint64_t mask)
{
    stq_le_p(&s->womask[addr], mask);
}

static inline void define_long(IntelIOMMUState *s, hwaddr addr, uint32_t val,
                               uint32_t wmask, uint32_t w1cmask)
{
    stl_le_p(&s->csr[addr], val);
    stl_le_p(&s->wmask[addr], wmask);
    stl_le_p(&s->w1cmask[addr], w1cmask);
}

static inline void define_long_wo(IntelIOMMUState *s, hwaddr addr,
                                  uint32_t mask)
{
    stl_le_p(&s->womask[addr], mask);
}

/* "External" get/set operations */
static inline void set_quad(IntelIOMMUState *s, hwaddr addr, uint64_t val)
{
    uint64_t oldval = ldq_le_p(&s->csr[addr]);
    uint64_t wmask = ldq_le_p(&s->wmask[addr]);
    uint64_t w1cmask = ldq_le_p(&s->w1cmask[addr]);
    stq_le_p(&s->csr[addr],
             ((oldval & ~wmask) | (val & wmask)) & ~(w1cmask & val));
}

static inline void set_long(IntelIOMMUState *s, hwaddr addr, uint32_t val)
{
    uint32_t oldval = ldl_le_p(&s->csr[addr]);
    uint32_t wmask = ldl_le_p(&s->wmask[addr]);
    uint32_t w1cmask = ldl_le_p(&s->w1cmask[addr]);
    stl_le_p(&s->csr[addr],
             ((oldval & ~wmask) | (val & wmask)) & ~(w1cmask & val));
}

static inline uint64_t get_quad(IntelIOMMUState *s, hwaddr addr)
{
    uint64_t val = ldq_le_p(&s->csr[addr]);
    uint64_t womask = ldq_le_p(&s->womask[addr]);
    return val & ~womask;
}


static inline uint32_t get_long(IntelIOMMUState *s, hwaddr addr)
{
    uint32_t val = ldl_le_p(&s->csr[addr]);
    uint32_t womask = ldl_le_p(&s->womask[addr]);
    return val & ~womask;
}

/* "Internal" get/set operations */
static inline uint64_t get_quad_raw(IntelIOMMUState *s, hwaddr addr)
{
    return ldq_le_p(&s->csr[addr]);
}

static inline uint32_t get_long_raw(IntelIOMMUState *s, hwaddr addr)
{
    return ldl_le_p(&s->csr[addr]);
}

static inline void set_quad_raw(IntelIOMMUState *s, hwaddr addr, uint64_t val)
{
    stq_le_p(&s->csr[addr], val);
}

static inline uint32_t set_clear_mask_long(IntelIOMMUState *s, hwaddr addr,
                                           uint32_t clear, uint32_t mask)
{
    uint32_t new_val = (ldl_le_p(&s->csr[addr]) & ~clear) | mask;
    stl_le_p(&s->csr[addr], new_val);
    return new_val;
}

static inline uint64_t set_clear_mask_quad(IntelIOMMUState *s, hwaddr addr,
                                           uint64_t clear, uint64_t mask)
{
    uint64_t new_val = (ldq_le_p(&s->csr[addr]) & ~clear) | mask;
    stq_le_p(&s->csr[addr], new_val);
    return new_val;
}

/* Generate an interrupt via MSI */
static void vtd_generate_interrupt(IntelIOMMUState *s)
{
    dma_addr_t addr = get_long_raw(s, DMAR_FEADDR_REG);
    uint32_t data = get_long_raw(s, DMAR_FEDATA_REG);

    VTD_DPRINTF(FLOG, "msi: addr 0x%"PRIx64 " data 0x%"PRIx32, addr, data);
    data = cpu_to_le32(data);
    if (dma_memory_write(&address_space_memory, addr, &data, sizeof(data))) {
        VTD_DPRINTF(GENERAL, "error: fail to generate msi: addr 0x%"PRIx64
                    "data 0x%"PRIx32, addr, le32_to_cpu(data));
    }
}

/* Generate a fault event to software via MSI if conditions are met.
 * Notice that the value of FSTS_REG being passed to it should be the one
 * before update.
 */
static void vtd_generate_fault_event(IntelIOMMUState *s, uint32_t ori_fsts)
{
    /* Check if there are any previously reported interrupt conditions */
    if (ori_fsts & VTD_FSTS_PPF || ori_fsts & VTD_FSTS_PFO ||
        ori_fsts & VTD_FSTS_IQE) {
        VTD_DPRINTF(FLOG, "there are previous interrupt conditions "
                    "to be serviced by software, fault event is not generated "
                    "(FSTS_REG 0x%"PRIx32 ")", ori_fsts);
        return;
    }
    set_clear_mask_long(s, DMAR_FECTL_REG, 0, VTD_FECTL_IP);
    if (get_long_raw(s, DMAR_FECTL_REG) & VTD_FECTL_IM) {
        /* Interrupt Mask */
        VTD_DPRINTF(FLOG, "Interrupt Mask set, fault event is not generated");
    } else {
        /* generate interrupt */
        vtd_generate_interrupt(s);
        set_clear_mask_long(s, DMAR_FECTL_REG, VTD_FECTL_IP, 0);
    }
}

/* Check if the Fault (F) field of the Fault Recording Register referenced by
 * @index is Set.
 */
static inline bool is_frcd_set(IntelIOMMUState *s, uint16_t index)
{
    /* Each reg is 128-bit */
    hwaddr addr = DMAR_FRCD_REG_OFFSET + (((uint64_t)index) << 4);
    addr += 8; /* Access the high 64-bit half */

    assert(index < DMAR_FRCD_REG_NR);

    return get_quad_raw(s, addr) & VTD_FRCD_F;
}

/* Update the PPF field of Fault Status Register.
 * Should be called whenever change the F field of any fault recording
 * registers.
 */
static inline void update_fsts_ppf(IntelIOMMUState *s)
{
    int i;
    uint32_t ppf_mask = 0;

    for (i = 0; i < DMAR_FRCD_REG_NR; i++) {
        if (is_frcd_set(s, i)) {
            ppf_mask = VTD_FSTS_PPF;
            break;
        }
    }
    set_clear_mask_long(s, DMAR_FSTS_REG, VTD_FSTS_PPF, ppf_mask);
    VTD_DPRINTF(FLOG, "set PPF of FSTS_REG to %d", ppf_mask ? 1 : 0);
}

static inline void frcd_set_f(IntelIOMMUState *s, uint16_t index)
{
    /* Each reg is 128-bit */
    hwaddr addr = DMAR_FRCD_REG_OFFSET + (((uint64_t)index) << 4);
    addr += 8; /* Access the high 64-bit half */

    assert(index < DMAR_FRCD_REG_NR);

    set_clear_mask_quad(s, addr, 0, VTD_FRCD_F);
    update_fsts_ppf(s);
}

/* Must not update F field now, should be done later */
static void record_frcd(IntelIOMMUState *s, uint16_t index,
                             uint16_t source_id, hwaddr addr,
                             VTDFaultReason fault, bool is_write)
{
    uint64_t hi = 0, lo;
    hwaddr frcd_reg_addr = DMAR_FRCD_REG_OFFSET + (((uint64_t)index) << 4);

    assert(index < DMAR_FRCD_REG_NR);

    lo = VTD_FRCD_FI(addr);
    hi = VTD_FRCD_SID(source_id) | VTD_FRCD_FR(fault);
    if (!is_write) {
        hi |= VTD_FRCD_T;
    }

    set_quad_raw(s, frcd_reg_addr, lo);
    set_quad_raw(s, frcd_reg_addr + 8, hi);
    VTD_DPRINTF(FLOG, "record to FRCD_REG #%u: hi 0x%"PRIx64 ", lo 0x%"PRIx64,
                index, hi, lo);
}

/* Try to collapse multiple pending faults from the same requester */
static inline bool try_collapse_fault(IntelIOMMUState *s, uint16_t source_id)
{
    int i;
    uint64_t frcd_reg;
    hwaddr addr = DMAR_FRCD_REG_OFFSET + 8; /* The high 64-bit half */

    for (i = 0; i < DMAR_FRCD_REG_NR; i++) {
        frcd_reg = get_quad_raw(s, addr);
        VTD_DPRINTF(FLOG, "frcd_reg #%d 0x%"PRIx64, i, frcd_reg);
        if ((frcd_reg & VTD_FRCD_F) &&
            ((frcd_reg & VTD_FRCD_SID_MASK) == source_id)) {
            return true;
        }
        addr += 16; /* 128-bit for each */
    }

    return false;
}

/* Log and report an DMAR (address translation) fault to software */
static void vtd_report_dmar_fault(IntelIOMMUState *s, uint16_t source_id,
                                  hwaddr addr, VTDFaultReason fault,
                                  bool is_write)
{
    uint32_t fsts_reg = get_long_raw(s, DMAR_FSTS_REG);

    assert(fault < VTD_FR_MAX);

    if (fault == VTD_FR_RESERVED_ERR) {
        /* This is not a normal fault reason case. Drop it. */
        return;
    }

    VTD_DPRINTF(FLOG, "sid 0x%"PRIx16 ", fault %d, addr 0x%"PRIx64
                ", is_write %d", source_id, fault, addr, is_write);

    /* Check PFO field in FSTS_REG */
    if (fsts_reg & VTD_FSTS_PFO) {
        VTD_DPRINTF(FLOG, "new fault is not recorded due to "
                    "Primary Fault Overflow");
        return;
    }

    /* Compression of multiple faults from the same requester */
    if (try_collapse_fault(s, source_id)) {
        VTD_DPRINTF(FLOG, "new fault is not recorded due to "
                    "compression of faults");
        return;
    }

    /* Check next_frcd_reg to see whether it is overflow now */
    if (is_frcd_set(s, s->next_frcd_reg)) {
        VTD_DPRINTF(FLOG, "Primary Fault Overflow and "
                    "new fault is not recorded, set PFO field");
        set_clear_mask_long(s, DMAR_FSTS_REG, 0, VTD_FSTS_PFO);
        return;
    }

    record_frcd(s, s->next_frcd_reg, source_id, addr, fault, is_write);

    if (fsts_reg & VTD_FSTS_PPF) {
        /* There are already one or more pending faults */
        VTD_DPRINTF(FLOG, "there are pending faults already, "
                    "fault event is not generated");
        frcd_set_f(s, s->next_frcd_reg);
        s->next_frcd_reg++;
        if (s->next_frcd_reg == DMAR_FRCD_REG_NR) {
            s->next_frcd_reg = 0;
        }
    } else {
        set_clear_mask_long(s, DMAR_FSTS_REG, VTD_FSTS_FRI_MASK,
                            VTD_FSTS_FRI(s->next_frcd_reg));
        frcd_set_f(s, s->next_frcd_reg); /* It will also set PPF */
        s->next_frcd_reg++;
        if (s->next_frcd_reg == DMAR_FRCD_REG_NR) {
            s->next_frcd_reg = 0;
        }

        /* This case actually cause the PPF to be Set (in frcd_set_f).
         * So generate fault event (interrupt).
         */
         vtd_generate_fault_event(s, fsts_reg);
    }
}


static inline bool root_entry_present(VTDRootEntry *root)
{
    return root->val & VTD_ROOT_ENTRY_P;
}

static int get_root_entry(IntelIOMMUState *s, int index, VTDRootEntry *re)
{
    dma_addr_t addr;

    assert(index >= 0 && index < VTD_ROOT_ENTRY_NR);

    addr = s->root + index * sizeof(*re);

    if (dma_memory_read(&address_space_memory, addr, re, sizeof(*re))) {
        /* FIXME: fault reporting */
        VTD_DPRINTF(GENERAL, "error: fail to access root-entry at 0x%"PRIx64
                    " + %d", s->root, index);
        re->val = 0;
        return -VTD_FR_ROOT_TABLE_INV;
    }

    re->val = le64_to_cpu(re->val);
    return VTD_FR_RESERVED;
}

static inline bool context_entry_present(VTDContextEntry *context)
{
    return context->lo & VTD_CONTEXT_ENTRY_P;
}

static int get_context_entry_from_root(VTDRootEntry *root, int index,
                                        VTDContextEntry *ce)
{
    dma_addr_t addr;

    if (!root_entry_present(root)) {
        ce->lo = 0;
        ce->hi = 0;
        VTD_DPRINTF(GENERAL, "error: root-entry is not present");
        return -VTD_FR_ROOT_ENTRY_P;
    }

    assert(index >= 0 && index < VTD_CONTEXT_ENTRY_NR);

    addr = (root->val & VTD_ROOT_ENTRY_CTP) + index * sizeof(*ce);

    if (dma_memory_read(&address_space_memory, addr, ce, sizeof(*ce))) {
        /* FIXME: fault reporting */
        VTD_DPRINTF(GENERAL, "error: fail to access context-entry at 0x%"PRIx64
                    " + %d", (uint64_t)(root->val & VTD_ROOT_ENTRY_CTP), index);
        ce->lo = 0;
        ce->hi = 0;
        return -VTD_FR_CONTEXT_TABLE_INV;
    }

    ce->lo = le64_to_cpu(ce->lo);
    ce->hi = le64_to_cpu(ce->hi);
    return VTD_FR_RESERVED;
}

static inline dma_addr_t get_slpt_base_from_context(VTDContextEntry *ce)
{
    return ce->lo & VTD_CONTEXT_ENTRY_SLPTPTR;
}

/* The shift of an addr for a certain level of paging structure */
static inline int slpt_level_shift(int level)
{
    return VTD_PAGE_SHIFT_4K + (level - 1) * VTD_SL_LEVEL_BITS;
}

static inline bool slpte_present(uint64_t slpte)
{
    return slpte & 3;
}

/* Calculate the GPA given the base address, the index in the page table and
 * the level of this page table.
 */
static inline uint64_t get_slpt_gpa(uint64_t addr, int index, int level)
{
    return addr + (((uint64_t)index) << slpt_level_shift(level));
}

static inline uint64_t get_slpte_addr(uint64_t slpte)
{
    return slpte & VTD_SL_PT_BASE_ADDR_MASK;
}

/* Whether the pte points to a large page */
static inline bool is_large_pte(uint64_t pte)
{
    return pte & VTD_SL_PT_PAGE_SIZE_MASK;
}

/* Whether the pte indicates the address of the page frame */
static inline bool is_last_slpte(uint64_t slpte, int level)
{
    if (level == VTD_SL_PT_LEVEL) {
        return true;
    }
    if (is_large_pte(slpte)) {
        return true;
    }
    return false;
}

/* Get the content of a spte located in @base_addr[@index] */
static inline uint64_t get_slpte(dma_addr_t base_addr, int index)
{
    uint64_t slpte;

    assert(index >= 0 && index < VTD_SL_PT_ENTRY_NR);

    if (dma_memory_read(&address_space_memory,
                        base_addr + index * sizeof(slpte), &slpte,
                        sizeof(slpte))) {
        /* FIXME: fault reporting */
        slpte = (uint64_t)-1;
        return slpte;
    }

    slpte = le64_to_cpu(slpte);
    return slpte;
}

/* Given a gpa and the level of paging structure, return the offset of current
 * level.
 */
static inline int gpa_level_offset(uint64_t gpa, int level)
{
    return (gpa >> slpt_level_shift(level)) & ((1ULL << VTD_SL_LEVEL_BITS) - 1);
}

/* Get the page-table level that hardware should use for the second-level
 * page-table walk from the Address Width field of context-entry.
 */
static inline int get_level_from_context_entry(VTDContextEntry *ce)
{
    return 2 + (ce->hi & VTD_CONTEXT_ENTRY_AW);
}

/* Given the @gpa, get relevant @slptep. @slpte_level will be the last level
 * of the translation, can be used for deciding the size of large page.
 */
static int gpa_to_slpte(VTDContextEntry *ce, uint64_t gpa,
                        uint64_t *slptep, int *slpte_level)
{
    dma_addr_t addr = get_slpt_base_from_context(ce);
    int level = get_level_from_context_entry(ce);
    int highest_level = level;
    int offset;
    int ret_fr;
    uint64_t slpte;

    while (true) {
        offset = gpa_level_offset(gpa, level);
        slpte = get_slpte(addr, offset);

        if (slpte == (uint64_t)-1) {
            VTD_DPRINTF(GENERAL, "error: fail to access second-level paging "
                        "entry at level %d for gpa 0x%"PRIx64,
                        level, gpa);
            *slpte_level = level;
            *slptep = 0;
            if (highest_level == level) {
                ret_fr = -VTD_FR_RESERVED_ERR;
            } else {
                ret_fr = -VTD_FR_PAGING_ENTRY_INV;
            }
            return ret_fr;
        }
        if (!slpte_present(slpte)) {
            VTD_DPRINTF(GENERAL, "error: level %d slpte 0x%"PRIx64
                        " for gpa 0x%"PRIx64 " is not present",
                        level, slpte, gpa);
            *slptep = 0;
            *slpte_level = level;
            ret_fr = -VTD_FR_RESERVED_ERR;
            return ret_fr;
        }
        if (is_last_slpte(slpte, level)) {
            *slpte_level = level;
            *slptep = slpte;
            return VTD_FR_RESERVED;
        }
        addr = get_slpte_addr(slpte);
        level--;
    }
}

/* Map a device to its corresponding domain (context_entry) */
static inline int dev_to_context_entry(IntelIOMMUState *s, int bus_num,
                                        int devfn, VTDContextEntry *ce)
{
    VTDRootEntry re;
    int ret_fr;

    assert(0 <= bus_num && bus_num < VTD_PCI_BUS_MAX);
    assert(0 <= devfn && devfn < VTD_PCI_SLOT_MAX * VTD_PCI_FUNC_MAX);

    ret_fr = get_root_entry(s, bus_num, &re);
    if (ret_fr) {
        /* FIXME: fault reporting */
        return ret_fr;
    }

    if (!root_entry_present(&re)) {
        /* FIXME: fault reporting */
        VTD_DPRINTF(GENERAL, "error: root-entry #%d is not present", bus_num);
        return -VTD_FR_ROOT_ENTRY_P;
    }

    ret_fr = get_context_entry_from_root(&re, devfn, ce);
    if (ret_fr) {
        /* FIXME: fault reporting */
        return ret_fr;
    }

    if (!context_entry_present(ce)) {
        /* FIXME: fault reporting */
        VTD_DPRINTF(GENERAL,
                    "error: context-entry #%d(bus #%d) is not present", devfn,
                    bus_num);
        return -VTD_FR_CONTEXT_ENTRY_P;
    }

    return VTD_FR_RESERVED;
}

static inline uint16_t make_source_id(int bus_num, int devfn)
{
    return ((bus_num & 0xffUL) << 8) | (devfn & 0xffUL);
}
/* Map dev to context-entry then do a paging-structures walk to do a iommu
 * translation.
 * @bus_num: The bus number
 * @devfn: The devfn, which is the  combined of device and function number
 * @is_write: The access is a write operation
 * @entry: IOMMUTLBEntry that contain the addr to be translated and result
 */
static void iommu_translate(IntelIOMMUState *s, int bus_num, int devfn,
                            hwaddr addr, bool is_write, IOMMUTLBEntry *entry)
{
    VTDContextEntry ce;
    uint64_t slpte;
    int level;
    uint64_t page_mask = VTD_PAGE_MASK_4K;
    uint16_t source_id = make_source_id(bus_num, devfn);
    int ret_fr;

    ret_fr = dev_to_context_entry(s, bus_num, devfn, &ce);
    if (ret_fr) {
        vtd_report_dmar_fault(s, source_id, addr, -ret_fr, is_write);
        return;
    }

    ret_fr = gpa_to_slpte(&ce, addr, &slpte, &level);
    if (ret_fr) {
        vtd_report_dmar_fault(s, source_id, addr, -ret_fr, is_write);
        return;
    }

    if (is_large_pte(slpte)) {
        if (level == VTD_SL_PDP_LEVEL) {
            /* 1-GB page */
            page_mask = VTD_PAGE_MASK_1G;
        } else {
            /* 2-MB page */
            page_mask = VTD_PAGE_MASK_2M;
        }
    }

    entry->iova = addr & page_mask;
    entry->translated_addr = get_slpte_addr(slpte) & page_mask;
    entry->addr_mask = ~page_mask;
    entry->perm = IOMMU_RW;
}

static void vtd_root_table_setup(IntelIOMMUState *s)
{
    s->root = get_quad_raw(s, DMAR_RTADDR_REG);
    s->root_extended = s->root & VTD_RTADDR_RTT;
    s->root &= VTD_RTADDR_ADDR_MASK;

    VTD_DPRINTF(CSR, "root_table addr 0x%"PRIx64 " %s", s->root,
                (s->root_extended ? "(extended)" : ""));
}

/* Context-cache invalidation
 * Returns the Context Actual Invalidation Granularity.
 * @val: the content of the CCMD_REG
 */
static uint64_t vtd_context_cache_invalidate(IntelIOMMUState *s, uint64_t val)
{
    uint64_t caig;
    uint64_t type = val & VTD_CCMD_CIRG_MASK;

    switch (type) {
    case VTD_CCMD_GLOBAL_INVL:
        VTD_DPRINTF(INV, "Global invalidation request");
        caig = VTD_CCMD_GLOBAL_INVL_A;
        break;

    case VTD_CCMD_DOMAIN_INVL:
        VTD_DPRINTF(INV, "Domain-selective invalidation request");
        caig = VTD_CCMD_DOMAIN_INVL_A;
        break;

    case VTD_CCMD_DEVICE_INVL:
        VTD_DPRINTF(INV, "Domain-selective invalidation request");
        caig = VTD_CCMD_DEVICE_INVL_A;
        break;

    default:
        VTD_DPRINTF(GENERAL,
                    "error: wrong context-cache invalidation granularity");
        caig = 0;
    }

    return caig;
}

/* Flush IOTLB
 * Returns the IOTLB Actual Invalidation Granularity.
 * @val: the content of the IOTLB_REG
 */
static uint64_t vtd_iotlb_flush(IntelIOMMUState *s, uint64_t val)
{
    uint64_t iaig;
    uint64_t type = val & VTD_TLB_FLUSH_GRANU_MASK;

    switch (type) {
    case VTD_TLB_GLOBAL_FLUSH:
        VTD_DPRINTF(INV, "Global IOTLB flush");
        iaig = VTD_TLB_GLOBAL_FLUSH_A;
        break;

    case VTD_TLB_DSI_FLUSH:
        VTD_DPRINTF(INV, "Domain-selective IOTLB flush");
        iaig = VTD_TLB_DSI_FLUSH_A;
        break;

    case VTD_TLB_PSI_FLUSH:
        VTD_DPRINTF(INV, "Page-selective-within-domain IOTLB flush");
        iaig = VTD_TLB_PSI_FLUSH_A;
        break;

    default:
        VTD_DPRINTF(GENERAL, "error: wrong iotlb flush granularity");
        iaig = 0;
    }

    return iaig;
}

static inline bool queued_inv_enable_check(IntelIOMMUState *s)
{
    return s->iq_tail == 0;
}

static inline bool queued_inv_disable_check(IntelIOMMUState *s)
{
    return (s->iq_tail == s->iq_head) &&
           (s->iq_last_desc_type == VTD_INV_DESC_WAIT);
}

static void handle_gcmd_qie(IntelIOMMUState *s, bool en)
{
    uint64_t iqa_val = get_quad_raw(s, DMAR_IQA_REG);
    VTD_DPRINTF(INV, "Queued Invalidation Enable %s", (en ? "on" : "off"));

    if (en) {
        if (queued_inv_enable_check(s)) {
            s->iq = iqa_val & VTD_IQA_IQA_MASK;
            /* 2^(x+8) entries */
            s->iq_size = 1UL << ((iqa_val & VTD_IQA_QS) + 8);
            s->qi_enabled = true;
            VTD_DPRINTF(INV, "DMAR_IQA_REG 0x%"PRIx64, iqa_val);
            VTD_DPRINTF(INV, "Invalidation Queue addr 0x%"PRIx64 " size %d",
                        s->iq, s->iq_size);
            /* Ok - report back to driver */
            set_clear_mask_long(s, DMAR_GSTS_REG, 0, VTD_GSTS_QIES);
        } else {
            VTD_DPRINTF(GENERAL, "error: can't enable Queued Invalidation: "
                        "tail %d", s->iq_tail);
        }
    } else {
        if (queued_inv_disable_check(s)) {
            /* disable Queued Invalidation */
            set_quad_raw(s, DMAR_IQH_REG, 0);
            s->iq_head = 0;
            s->qi_enabled = false;
            /* Ok - report back to driver */
            set_clear_mask_long(s, DMAR_GSTS_REG, VTD_GSTS_QIES, 0);
        } else {
            VTD_DPRINTF(GENERAL, "error: can't disable Queued Invalidation: "
                        "head %d, tail %d, last_descriptor %u",
                        s->iq_head, s->iq_tail, s->iq_last_desc_type);
        }
    }
}

/* Set Root Table Pointer */
static void handle_gcmd_srtp(IntelIOMMUState *s)
{
    VTD_DPRINTF(CSR, "set Root Table Pointer");

    vtd_root_table_setup(s);
    /* Ok - report back to driver */
    set_clear_mask_long(s, DMAR_GSTS_REG, 0, VTD_GSTS_RTPS);
}

/* Handle Translation Enable/Disable */
static void handle_gcmd_te(IntelIOMMUState *s, bool en)
{
    VTD_DPRINTF(CSR, "Translation Enable %s", (en ? "on" : "off"));

    if (en) {
        s->dmar_enabled = true;
        /* Ok - report back to driver */
        set_clear_mask_long(s, DMAR_GSTS_REG, 0, VTD_GSTS_TES);
    } else {
        s->dmar_enabled = false;

        /* Clear the index of Fault Recording Register */
        s->next_frcd_reg = 0;
        /* Ok - report back to driver */
        set_clear_mask_long(s, DMAR_GSTS_REG, VTD_GSTS_TES, 0);
    }
}

/* Handle write to Global Command Register */
static void handle_gcmd_write(IntelIOMMUState *s)
{
    uint32_t status = get_long_raw(s, DMAR_GSTS_REG);
    uint32_t val = get_long_raw(s, DMAR_GCMD_REG);
    uint32_t changed = status ^ val;

    VTD_DPRINTF(CSR, "value 0x%x status 0x%x", val, status);
    if (changed & VTD_GCMD_TE) {
        /* Translation enable/disable */
        handle_gcmd_te(s, val & VTD_GCMD_TE);
    } else if (val & VTD_GCMD_SRTP) {
        /* Set/update the root-table pointer */
        handle_gcmd_srtp(s);
    } else if (changed & VTD_GCMD_QIE) {
        /* Queued Invalidation Enable */
        handle_gcmd_qie(s, val & VTD_GCMD_QIE);
    } else {
        VTD_DPRINTF(GENERAL, "error: unhandled gcmd write");
    }
}

/* Handle write to Context Command Register */
static void handle_ccmd_write(IntelIOMMUState *s)
{
    uint64_t ret;
    uint64_t val = get_quad_raw(s, DMAR_CCMD_REG);

    /* Context-cache invalidation request */
    if (val & VTD_CCMD_ICC) {
        ret = vtd_context_cache_invalidate(s, val);

        /* Invalidation completed. Change something to show */
        set_clear_mask_quad(s, DMAR_CCMD_REG, VTD_CCMD_ICC, 0ULL);
        ret = set_clear_mask_quad(s, DMAR_CCMD_REG, VTD_CCMD_CAIG_MASK, ret);
        VTD_DPRINTF(INV, "CCMD_REG write-back val: 0x%"PRIx64, ret);
    }
}

/* Handle write to IOTLB Invalidation Register */
static void handle_iotlb_write(IntelIOMMUState *s)
{
    uint64_t ret;
    uint64_t val = get_quad_raw(s, DMAR_IOTLB_REG);

    /* IOTLB invalidation request */
    if (val & VTD_TLB_IVT) {
        ret = vtd_iotlb_flush(s, val);

        /* Invalidation completed. Change something to show */
        set_clear_mask_quad(s, DMAR_IOTLB_REG, VTD_TLB_IVT, 0ULL);
        ret = set_clear_mask_quad(s, DMAR_IOTLB_REG,
                                  VTD_TLB_FLUSH_GRANU_MASK_A, ret);
        VTD_DPRINTF(INV, "IOTLB_REG write-back val: 0x%"PRIx64, ret);
    }
}

/* Fetch an Invalidation Descriptor from the Invalidation Queue */
static bool get_inv_desc(dma_addr_t base_addr, uint16_t offset,
                         VTDInvDesc *inv_desc)
{
    dma_addr_t addr = base_addr + offset * sizeof(*inv_desc);
    if (dma_memory_read(&address_space_memory, addr, inv_desc,
        sizeof(*inv_desc))) {
        /* FIXME: fault reporting */
        VTD_DPRINTF(GENERAL, "error: fail to fetch Invalidation Descriptor "
                    "base_addr 0x%"PRIx64 " offset %u", base_addr, offset);
        inv_desc->lo = 0;
        inv_desc->hi = 0;

        return false;
    }

    inv_desc->lo = le64_to_cpu(inv_desc->lo);
    inv_desc->hi = le64_to_cpu(inv_desc->hi);
    return true;
}

static void vtd_process_wait_desc(IntelIOMMUState *s, VTDInvDesc *inv_desc)
{
    assert(!(
           (inv_desc->lo & VTD_INV_DESC_WAIT_SW) &&
           (inv_desc->lo & VTD_INV_DESC_WAIT_IF)));
    if (inv_desc->lo & VTD_INV_DESC_WAIT_SW) {
        /* Status Write */
        uint32_t status_data = (uint32_t)(inv_desc->lo >>
                               VTD_INV_DESC_WAIT_DATA_SHIFT);
        /* FIXME: need to be masked with HAW? */
        dma_addr_t status_addr = inv_desc->hi;
        VTD_DPRINTF(INV, "status data 0x%x, status addr 0x%"PRIx64,
                    status_data, status_addr);
        if (dma_memory_write(&address_space_memory, status_addr, &status_data,
                             sizeof(status_data))) {
            /* FIXME: fault reporting */
            VTD_DPRINTF(GENERAL, "error: fail to perform a coherent write");
        }
    } else if (inv_desc->lo & VTD_INV_DESC_WAIT_IF) {
        /* Interrupt flag */
        /* FIXME: not implemented yet */
        VTD_DPRINTF(INV, "Invalidation Wait Descriptor interrupt completion");
    } else {
        /* FIXME: fault reporting */
        VTD_DPRINTF(GENERAL, "error: Invalidation Wait Descriptor error");
    }
}

static inline void vtd_process_inv_desc(IntelIOMMUState *s)
{
    VTDInvDesc inv_desc;

    if (!get_inv_desc(s->iq, s->iq_head, &inv_desc)) {
        return;
    }

    switch (inv_desc.lo & VTD_INV_DESC_TYPE) {
    case VTD_INV_DESC_CC:
        VTD_DPRINTF(INV, "Context-cache Invalidate Descriptor");
        break;

    case VTD_INV_DESC_IOTLB:
        VTD_DPRINTF(INV, "IOTLB Invalidate Descriptor");
        break;

    case VTD_INV_DESC_WAIT:
        VTD_DPRINTF(INV, "Invalidation Wait Descriptor hi 0x%"PRIx64
                    " lo 0x%"PRIx64, inv_desc.hi, inv_desc.lo);
        vtd_process_wait_desc(s, &inv_desc);
        break;

    default:
        /* FIXME: fault reporting */
        VTD_DPRINTF(GENERAL, "error: unhandled Invalidation Descriptor "
                    "hi 0x%"PRIx64 " lo 0x%"PRIx64,
                    inv_desc.hi, inv_desc.lo);
        break;
    }
    s->iq_head++;
    if (s->iq_head == s->iq_size) {
        s->iq_head = 0;
    }
}

/* Handle write to Invalidation Queue Tail Register */
static inline void handle_iqt_write(IntelIOMMUState *s)
{
    uint64_t val = get_quad_raw(s, DMAR_IQT_REG);

    s->iq_tail = VTD_IQT_QT(val);
    VTD_DPRINTF(INV, "New iq tail %d", s->iq_tail);

    if (s->qi_enabled) {
        /* Process Invalidation Queue here */
        while (s->iq_head != s->iq_tail) {
            vtd_process_inv_desc(s);
        }
        set_quad_raw(s, DMAR_IQH_REG,
                     (((uint64_t)(s->iq_head)) << VTD_IQH_QH_SHIFT) &
                     VTD_IQH_QH_MASK);
    }
}

static inline void handle_fsts_write(IntelIOMMUState *s)
{
    uint32_t fsts_reg = get_long_raw(s, DMAR_FSTS_REG);
    uint32_t fectl_reg = get_long_raw(s, DMAR_FECTL_REG);
    uint32_t status_fields = VTD_FSTS_PFO | VTD_FSTS_PPF | VTD_FSTS_IQE;

    if ((fectl_reg & VTD_FECTL_IP) && !(fsts_reg & status_fields)) {
        set_clear_mask_long(s, DMAR_FECTL_REG, VTD_FECTL_IP, 0);
        VTD_DPRINTF(FLOG, "all pending interrupt conditions serviced, clear "
                    "IP field of FSTS_REG");
    }
}

static inline void handle_fectl_write(IntelIOMMUState *s)
{
    uint32_t fectl_reg;
    /* When software clears the IM field, check the IP field. But do we
     * need to compare the old value and the new value to conclude that
     * software clears the IM field? Or just check if the IM field is zero?
     */
    fectl_reg = get_long_raw(s, DMAR_FECTL_REG);
    if ((fectl_reg & VTD_FECTL_IP) && !(fectl_reg & VTD_FECTL_IM)) {
        vtd_generate_interrupt(s);
        set_clear_mask_long(s, DMAR_FECTL_REG, VTD_FECTL_IP, 0);
        VTD_DPRINTF(FLOG, "IM field is cleared, generate "
                    "fault event interrupt");
    }
}

static uint64_t vtd_mem_read(void *opaque, hwaddr addr, unsigned size)
{
    IntelIOMMUState *s = opaque;
    uint64_t val;

    if (addr + size > DMAR_REG_SIZE) {
        VTD_DPRINTF(GENERAL, "error: addr outside region: max 0x%"PRIx64
                    ", got 0x%"PRIx64 " %d",
                    (uint64_t)DMAR_REG_SIZE, addr, size);
        return (uint64_t)-1;
    }

    assert(size == 4 || size == 8);

    switch (addr) {
    /* Root Table Address Register, 64-bit */
    case DMAR_RTADDR_REG:
        if (size == 4) {
            val = s->root & ((1ULL << 32) - 1);
        } else {
            val = s->root;
        }
        break;

    case DMAR_RTADDR_REG_HI:
        assert(size == 4);
        val = s->root >> 32;
        break;

    /* Invalidation Queue Address Register, 64-bit */
    case DMAR_IQA_REG:
        val = s->iq | (get_quad(s, DMAR_IQA_REG) & VTD_IQA_QS);
        if (size == 4) {
            val = val & ((1ULL << 32) - 1);
        }
        break;

    case DMAR_IQA_REG_HI:
        assert(size == 4);
        val = s->iq >> 32;
        break;

    default:
        if (size == 4) {
            val = get_long(s, addr);
        } else {
            val = get_quad(s, addr);
        }
    }

    VTD_DPRINTF(CSR, "addr 0x%"PRIx64 " size %d val 0x%"PRIx64,
                addr, size, val);
    return val;
}

static void vtd_mem_write(void *opaque, hwaddr addr,
                          uint64_t val, unsigned size)
{
    IntelIOMMUState *s = opaque;

    if (addr + size > DMAR_REG_SIZE) {
        VTD_DPRINTF(GENERAL, "error: addr outside region: max 0x%"PRIx64
                    ", got 0x%"PRIx64 " %d",
                    (uint64_t)DMAR_REG_SIZE, addr, size);
        return;
    }

    assert(size == 4 || size == 8);

    /* Val should be written into csr within the handler */
    switch (addr) {
    /* Global Command Register, 32-bit */
    case DMAR_GCMD_REG:
        VTD_DPRINTF(CSR, "DMAR_GCMD_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        set_long(s, addr, val);
        handle_gcmd_write(s);
        break;

    /* Context Command Register, 64-bit */
    case DMAR_CCMD_REG:
        VTD_DPRINTF(CSR, "DMAR_CCMD_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            set_long(s, addr, val);
        } else {
            set_quad(s, addr, val);
            handle_ccmd_write(s);
        }
        break;

    case DMAR_CCMD_REG_HI:
        VTD_DPRINTF(CSR, "DMAR_CCMD_REG_HI write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        set_long(s, addr, val);
        handle_ccmd_write(s);
        break;


    /* IOTLB Invalidation Register, 64-bit */
    case DMAR_IOTLB_REG:
        VTD_DPRINTF(INV, "DMAR_IOTLB_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            set_long(s, addr, val);
        } else {
            set_quad(s, addr, val);
            handle_iotlb_write(s);
        }
        break;

    case DMAR_IOTLB_REG_HI:
        VTD_DPRINTF(INV, "DMAR_IOTLB_REG_HI write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        set_long(s, addr, val);
        handle_iotlb_write(s);
        break;

    /* Fault Status Register, 32-bit */
    case DMAR_FSTS_REG:
        VTD_DPRINTF(FLOG, "DMAR_FSTS_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        set_long(s, addr, val);
        handle_fsts_write(s);
        break;

    /* Fault Event Control Register, 32-bit */
    case DMAR_FECTL_REG:
        VTD_DPRINTF(FLOG, "DMAR_FECTL_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        set_long(s, addr, val);
        handle_fectl_write(s);
        break;

    /* Fault Event Data Register, 32-bit */
    case DMAR_FEDATA_REG:
        VTD_DPRINTF(FLOG, "DMAR_FEDATA_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        set_long(s, addr, val);
        break;

    /* Fault Event Address Register, 32-bit */
    case DMAR_FEADDR_REG:
        VTD_DPRINTF(FLOG, "DMAR_FEADDR_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        set_long(s, addr, val);
        break;

    /* Fault Event Upper Address Register, 32-bit */
    case DMAR_FEUADDR_REG:
        VTD_DPRINTF(FLOG, "DMAR_FEUADDR_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        set_long(s, addr, val);
        break;

    /* Protected Memory Enable Register, 32-bit */
    case DMAR_PMEN_REG:
        VTD_DPRINTF(CSR, "DMAR_PMEN_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        set_long(s, addr, val);
        break;


    /* Root Table Address Register, 64-bit */
    case DMAR_RTADDR_REG:
        VTD_DPRINTF(CSR, "DMAR_RTADDR_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            set_long(s, addr, val);
        } else {
            set_quad(s, addr, val);
        }
        break;

    case DMAR_RTADDR_REG_HI:
        VTD_DPRINTF(CSR, "DMAR_RTADDR_REG_HI write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        set_long(s, addr, val);
        break;

    /* Invalidation Queue Tail Register, 64-bit */
    case DMAR_IQT_REG:
        VTD_DPRINTF(INV, "DMAR_IQT_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            set_long(s, addr, val);
        } else {
            set_quad(s, addr, val);
        }
        handle_iqt_write(s);
        break;

    case DMAR_IQT_REG_HI:
        VTD_DPRINTF(INV, "DMAR_IQT_REG_HI write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        set_long(s, addr, val);
        /* 19:63 of IQT_REG is RsvdZ, do nothing here */
        break;

    /* Invalidation Queue Address Register, 64-bit */
    case DMAR_IQA_REG:
        VTD_DPRINTF(INV, "DMAR_IQA_REG write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            set_long(s, addr, val);
        } else {
            set_quad(s, addr, val);
        }
        break;

    case DMAR_IQA_REG_HI:
        VTD_DPRINTF(INV, "DMAR_IQA_REG_HI write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        set_long(s, addr, val);
        break;

    /* Fault Recording Registers, 128-bit */
    case DMAR_FRCD_REG_0_0:
        VTD_DPRINTF(FLOG, "DMAR_FRCD_REG_0_0 write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            set_long(s, addr, val);
        } else {
            set_quad(s, addr, val);
        }
        break;

    case DMAR_FRCD_REG_0_1:
        VTD_DPRINTF(FLOG, "DMAR_FRCD_REG_0_1 write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        set_long(s, addr, val);
        break;

    case DMAR_FRCD_REG_0_2:
        VTD_DPRINTF(FLOG, "DMAR_FRCD_REG_0_2 write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            set_long(s, addr, val);
        } else {
            set_quad(s, addr, val);
            /* May clear bit 127 (Fault), update PPF */
            update_fsts_ppf(s);
        }
        break;

    case DMAR_FRCD_REG_0_3:
        VTD_DPRINTF(FLOG, "DMAR_FRCD_REG_0_3 write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        assert(size == 4);
        set_long(s, addr, val);
        /* May clear bit 127 (Fault), update PPF */
        update_fsts_ppf(s);
        break;

    default:
        VTD_DPRINTF(GENERAL, "error: unhandled reg write addr 0x%"PRIx64
                    ", size %d, val 0x%"PRIx64, addr, size, val);
        if (size == 4) {
            set_long(s, addr, val);
        } else {
            set_quad(s, addr, val);
        }
    }

}

static IOMMUTLBEntry vtd_iommu_translate(MemoryRegion *iommu, hwaddr addr)
{
    VTDAddressSpace *vtd_as = container_of(iommu, VTDAddressSpace, iommu);
    IntelIOMMUState *s = vtd_as->iommu_state;
    int bus_num = vtd_as->bus_num;
    int devfn = vtd_as->devfn;
    IOMMUTLBEntry ret = {
        .target_as = &address_space_memory,
        .iova = addr,
        .translated_addr = 0,
        .addr_mask = ~(hwaddr)0,
        .perm = IOMMU_NONE,
    };

    if (!s->dmar_enabled) {
        /* DMAR disabled, passthrough, use 4k-page*/
        ret.iova = addr & VTD_PAGE_MASK_4K;
        ret.translated_addr = addr & VTD_PAGE_MASK_4K;
        ret.addr_mask = ~VTD_PAGE_MASK_4K;
        ret.perm = IOMMU_RW;
        return ret;
    }

    iommu_translate(s, bus_num, devfn, addr, false, &ret);

    VTD_DPRINTF(MMU,
                "bus %d slot %d func %d devfn %d gpa %"PRIx64 " hpa %"PRIx64,
                bus_num, VTD_PCI_SLOT(devfn), VTD_PCI_FUNC(devfn), devfn, addr,
                ret.translated_addr);
    return ret;
}

static const VMStateDescription vtd_vmstate = {
    .name = "iommu_intel",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT8_ARRAY(csr, IntelIOMMUState, DMAR_REG_SIZE),
        VMSTATE_END_OF_LIST()
    }
};

static const MemoryRegionOps vtd_mem_ops = {
    .read = vtd_mem_read,
    .write = vtd_mem_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
};

static Property iommu_properties[] = {
    DEFINE_PROP_UINT32("version", IntelIOMMUState, version, 0),
    DEFINE_PROP_END_OF_LIST(),
};

/* Do the real initialization. It will also be called when reset, so pay
 * attention when adding new initialization stuff.
 */
static void do_vtd_init(IntelIOMMUState *s)
{
    memset(s->csr, 0, DMAR_REG_SIZE);
    memset(s->wmask, 0, DMAR_REG_SIZE);
    memset(s->w1cmask, 0, DMAR_REG_SIZE);
    memset(s->womask, 0, DMAR_REG_SIZE);

    s->iommu_ops.translate = vtd_iommu_translate;
    s->root = 0;
    s->root_extended = false;
    s->dmar_enabled = false;
    s->iq_head = 0;
    s->iq_tail = 0;
    s->iq = 0;
    s->iq_size = 0;
    s->qi_enabled = false;
    s->iq_last_desc_type = VTD_INV_DESC_NONE;
    s->next_frcd_reg = 0;

    /* b.0:2 = 6: Number of domains supported: 64K using 16 bit ids
     * b.3   = 0: Advanced fault logging not supported
     * b.4   = 0: Required write buffer flushing not supported
     * b.5   = 0: Protected low memory region not supported
     * b.6   = 0: Protected high memory region not supported
     * b.8:12 = 2: SAGAW(Supported Adjusted Guest Address Widths), 39-bit,
     *             3-level page-table
     * b.16:21 = 38: MGAW(Maximum Guest Address Width) = 39
     * b.22 = 0: ZLR(Zero Length Read) zero length DMA read requests
     *           to write-only pages not supported
     * b.24:33 = 34: FRO(Fault-recording Register offset)
     * b.54 = 0: DWD(Write Draining), draining of write requests not supported
     * b.55 = 0: DRD(Read Draining), draining of read requests not supported
     */
    const uint64_t dmar_cap_reg_value = VTD_CAP_FRO | VTD_CAP_NFR |
                                        VTD_CAP_ND | VTD_CAP_MGAW |
                                        VTD_CAP_SAGAW_39bit;

    /* b.1 = 1: QI(Queued Invalidation support) supported
     * b.2 = 0: DT(Device-TLB support) not supported
     * b.3 = 0: IR(Interrupt Remapping support) not supported
     * b.4 = 0: EIM(Extended Interrupt Mode) not supported
     * b.8:17 = 15: IRO(IOTLB Register Offset)
     * b.20:23 = 0: MHMV(Maximum Handle Mask Value) not valid
     */
    const uint64_t dmar_ecap_reg_value = VTD_ECAP_QI | VTD_ECAP_IRO;

    /* Define registers with default values and bit semantics */
    define_long(s, DMAR_VER_REG, 0x10UL, 0, 0);  /* set MAX = 1, RO */
    define_quad(s, DMAR_CAP_REG, dmar_cap_reg_value, 0, 0);
    define_quad(s, DMAR_ECAP_REG, dmar_ecap_reg_value, 0, 0);
    define_long(s, DMAR_GCMD_REG, 0, 0xff800000UL, 0);
    define_long_wo(s, DMAR_GCMD_REG, 0xff800000UL);
    define_long(s, DMAR_GSTS_REG, 0, 0, 0); /* All bits RO, default 0 */
    define_quad(s, DMAR_RTADDR_REG, 0, 0xfffffffffffff000ULL, 0);
    define_quad(s, DMAR_CCMD_REG, 0, 0xe0000003ffffffffULL, 0);
    define_quad_wo(s, DMAR_CCMD_REG, 0x3ffff0000ULL);

    /* Advanced Fault Logging not supported */
    define_long(s, DMAR_FSTS_REG, 0, 0, 0x11UL);
    define_long(s, DMAR_FECTL_REG, 0x80000000UL, 0x80000000UL, 0);
    define_long(s, DMAR_FEDATA_REG, 0, 0x0000ffffUL, 0); /* 15:0 RW */
    define_long(s, DMAR_FEADDR_REG, 0, 0xfffffffcUL, 0); /* 31:2 RW */

    /* Treated as RsvdZ when EIM in ECAP_REG is not supported
     * define_long(s, DMAR_FEUADDR_REG, 0, 0xffffffffUL, 0);
     */
    define_long(s, DMAR_FEUADDR_REG, 0, 0, 0);

    /* Treated as RsvdZ when AFL in Capability Register is not supported.
     * define_quad(s, DMAR_AFLOG_REG, 0, 0xffffffffffffff00ULL, 0);
     */
    define_quad(s, DMAR_AFLOG_REG, 0, 0, 0);

    /* Treated as RO for implementations that PLMR and PHMR fields reported
     * as Clear in the CAP_REG.
     * define_long(s, DMAR_PMEN_REG, 0, 0x80000000UL, 0);
     */
    define_long(s, DMAR_PMEN_REG, 0, 0, 0);

    /* Bits 18:4 (0x7fff0) is RO, rest is RsvdZ */
    define_quad(s, DMAR_IQH_REG, 0, 0, 0);
    define_quad(s, DMAR_IQT_REG, 0, 0x7fff0ULL, 0);
    define_quad(s, DMAR_IQA_REG, 0, 0xfffffffffffff007ULL, 0);

    /* Bit 0 is RW1CS - rest is RsvdZ */
    define_long(s, DMAR_ICS_REG, 0, 0, 0x1UL);

    /* b.31 is RW, b.30 RO, rest: RsvdZ */
    define_long(s, DMAR_IECTL_REG, 0x80000000UL, 0x80000000UL, 0);

    define_long(s, DMAR_IEDATA_REG, 0, 0xffffffffUL, 0);
    define_long(s, DMAR_IEADDR_REG, 0, 0xfffffffcUL, 0);
    define_long(s, DMAR_IEUADDR_REG, 0, 0xffffffffUL, 0);
    define_quad(s, DMAR_IRTA_REG, 0, 0xfffffffffffff80fULL, 0);
    define_quad(s, DMAR_PQH_REG, 0, 0x7fff0ULL, 0);
    define_quad(s, DMAR_PQT_REG, 0, 0x7fff0ULL, 0);
    define_quad(s, DMAR_PQA_REG, 0, 0xfffffffffffff007ULL, 0);
    define_long(s, DMAR_PRS_REG, 0, 0, 0x1UL);
    define_long(s, DMAR_PECTL_REG, 0x80000000UL, 0x80000000UL, 0);
    define_long(s, DMAR_PEDATA_REG, 0, 0xffffffffUL, 0);
    define_long(s, DMAR_PEADDR_REG, 0, 0xfffffffcUL, 0);
    define_long(s, DMAR_PEUADDR_REG, 0, 0xffffffffUL, 0);

    /* When MTS is not supported in ECAP_REG, these regs are RsvdZ */
    define_long(s, DMAR_MTRRCAP_REG, 0, 0, 0);
    define_long(s, DMAR_MTRRDEF_REG, 0, 0, 0);

    /* IOTLB registers */
    define_quad(s, DMAR_IOTLB_REG, 0, 0Xb003ffff00000000ULL, 0);
    define_quad(s, DMAR_IVA_REG, 0, 0xfffffffffffff07fULL, 0);
    define_quad_wo(s, DMAR_IVA_REG, 0xfffffffffffff07fULL);

    /* Fault Recording Registers, 128-bit */
    define_quad(s, DMAR_FRCD_REG_0_0, 0, 0, 0);
    define_quad(s, DMAR_FRCD_REG_0_2, 0, 0, 0x8000000000000000ULL);
}

/* Reset function of QOM
 * Should not reset address_spaces when reset
 */
static void vtd_reset(DeviceState *dev)
{
    IntelIOMMUState *s = INTEL_IOMMU_DEVICE(dev);

    VTD_DPRINTF(GENERAL, "");
    do_vtd_init(s);
}

/* Initialization function of QOM */
static void vtd_realize(DeviceState *dev, Error **errp)
{
    IntelIOMMUState *s = INTEL_IOMMU_DEVICE(dev);

    VTD_DPRINTF(GENERAL, "");
    memset(s->address_spaces, 0, sizeof(s->address_spaces));
    memory_region_init_io(&s->csrmem, OBJECT(s), &vtd_mem_ops, s,
                          "intel_iommu", DMAR_REG_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->csrmem);
    do_vtd_init(s);
}

static void vtd_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->reset = vtd_reset;
    dc->realize = vtd_realize;
    dc->vmsd = &vtd_vmstate;
    dc->props = iommu_properties;
}

static const TypeInfo vtd_info = {
    .name          = TYPE_INTEL_IOMMU_DEVICE,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(IntelIOMMUState),
    .class_init    = vtd_class_init,
};

static void vtd_register_types(void)
{
    VTD_DPRINTF(GENERAL, "");
    type_register_static(&vtd_info);
}

type_init(vtd_register_types)
