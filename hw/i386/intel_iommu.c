/*
 * QEMU emulation of an Intel IOMMU
 *   (DMA Remapping device)
 *
 * Copyright (c) 2013 Knut Omang, Oracle <knut.omang@oracle.com>
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
 */

#include "hw/sysbus.h"
#include "exec/address-spaces.h"
#include "hw/i386/intel_iommu.h"

#define DEBUG_INTEL_IOMMU
#ifdef DEBUG_INTEL_IOMMU
#define D(fmt, ...) \
    do { fprintf(stderr, "(vtd)%s, %s: " fmt "\n", __FILE__, __func__, \
                 ## __VA_ARGS__); } while (0)
#else
#define D(fmt, ...) \
    do { } while (0)
#endif


#define REG_DESC(_offset, _size) \
    .offset = _offset, \
    .size = _size, \


static const vtd_reg_desc reserved_regs[] = {
    { REG_DESC(0x04, 32) },
    { REG_DESC(0x30, 32) },
    { REG_DESC(0x48, 64) },
    { REG_DESC(0x50, 64) },
    { REG_DESC(0x60, 32) },
    { REG_DESC(0x98, 32) },
    { REG_DESC(0xb0, 64) },
    { REG_DESC(0xd8, 32) },
};

static bool is_reserved(uint32_t offset, int size)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(reserved_regs); ++i) {
        if (reserved_regs[i].offset == offset) {
            if (size > reserved_regs[i].size) {
                D("Access to reserved regs exceeds the size %d",
                  reserved_regs[i].size);
            }
            return true;
        } else {
            return false;
        }
    }
    return false;
}

static inline void define_quad(intel_iommu_state *s, hwaddr addr, uint64_t val,
                        uint64_t wmask, uint64_t w1cmask)
{
    *((uint64_t *)&s->csr[addr]) = val;
    *((uint64_t *)&s->wmask[addr]) = wmask;
    *((uint64_t *)&s->w1cmask[addr]) = w1cmask;
}

static inline void define_quad_wo(intel_iommu_state *s, hwaddr addr,
                                  uint64_t mask)
{
    *((uint64_t *)&s->womask[addr]) = mask;
}

static inline void define_long(intel_iommu_state *s, hwaddr addr, uint32_t val,
                        uint32_t wmask, uint32_t w1cmask)
{
    *((uint32_t *)&s->csr[addr]) = val;
    *((uint32_t *)&s->wmask[addr]) = wmask;
    *((uint32_t *)&s->w1cmask[addr]) = w1cmask;
}

static inline void define_long_wo(intel_iommu_state *s, hwaddr addr,
                                  uint32_t mask)
{
    *((uint32_t *)&s->womask[addr]) = mask;
}

/* "External" get/set operations */
static inline void set_quad(intel_iommu_state *s, hwaddr addr, uint64_t val)
{
    uint64_t oldval = *((uint64_t *)&s->csr[addr]);
    uint64_t wmask = *((uint64_t *)&s->wmask[addr]);
    uint64_t w1cmask = *((uint64_t *)&s->w1cmask[addr]);
    *((uint64_t *)&s->csr[addr]) =
        ((oldval & ~wmask) | (val & wmask)) & ~(w1cmask & val);
}

static inline void set_long(intel_iommu_state *s, hwaddr addr, uint32_t val)
{
    uint32_t oldval = *((uint32_t *)&s->csr[addr]);
    uint32_t wmask = *((uint32_t *)&s->wmask[addr]);
    uint32_t w1cmask = *((uint32_t *)&s->w1cmask[addr]);
    *((uint32_t *)&s->csr[addr]) =
        ((oldval & ~wmask) | (val & wmask)) & ~(w1cmask & val);
}

static inline uint64_t get_quad(intel_iommu_state *s, hwaddr addr)
{
    uint64_t val = *((uint64_t *)&s->csr[addr]);
    uint64_t womask = *((uint64_t *)&s->womask[addr]);
    return val & ~womask;
}


static inline uint32_t get_long(intel_iommu_state *s, hwaddr addr)
{
    uint32_t val = *((uint32_t *)&s->csr[addr]);
    uint32_t womask = *((uint32_t *)&s->womask[addr]);
    return val & ~womask;
}


/* "Internal" get/set operations */
static inline uint64_t __get_quad(intel_iommu_state *s, hwaddr addr)
{
    return *((uint64_t *)&s->csr[addr]);
}

static inline uint32_t __get_long(intel_iommu_state *s, hwaddr addr)
{
    return *((uint32_t *)&s->csr[addr]);
}



/* val = (val & ~clear) | mask */
static inline uint32_t set_mask_long(intel_iommu_state *s, hwaddr addr,
                                     uint32_t clear, uint32_t mask)
{
    uint32_t *ptr = (uint32_t *)&s->csr[addr];
    uint32_t val = (*ptr & ~clear) | mask;
    *ptr = val;
    return val;
}

/* val = (val & ~clear) | mask */
static inline uint64_t set_mask_quad(intel_iommu_state *s, hwaddr addr,
                                     uint64_t clear, uint64_t mask)
{
    uint64_t *ptr = (uint64_t *)&s->csr[addr];
    uint64_t val = (*ptr & ~clear) | mask;
    *ptr = val;
    return val;
}


static inline bool root_entry_present(vtd_root_entry* root)
{
    return (root->val & ROOT_ENTRY_P);
}


static bool get_root_entry(intel_iommu_state *s, int index, vtd_root_entry *re)
{
    dma_addr_t addr;
    if (index >= 0 && index < ROOT_ENTRY_NR) {
        addr = s->root + index * sizeof(*re);
        if (dma_memory_read(&address_space_memory, addr, re, sizeof(*re))) {
            fprintf(stderr, "(vtd) fail to read root table\n");
            return false;
        }
        re->val = le64_to_cpu(re->val);
        return true;
    }

    return false;
}


static inline bool context_entry_present(vtd_context_entry *context)
{
    return (context->lo & CONTEXT_ENTRY_P);
}

static bool get_context_entry_from_root(vtd_root_entry *root, int index,
                                        vtd_context_entry *ce)
{
    dma_addr_t addr;

    if (!root_entry_present(root)) {
        return false;
    }
    if (index >= 0 && index < CONTEXT_ENTRY_NR) {
        addr = (root->val & ROOT_ENTRY_CTP) + index * sizeof(*ce);
        if (dma_memory_read(&address_space_memory, addr, ce, sizeof(*ce))) {
            fprintf(stderr, "(vtd) fail to read context table\n");
            return false;
        }
        ce->lo = le64_to_cpu(ce->lo);
        ce->hi = le64_to_cpu(ce->hi);
        return true;
    }

    return false;
}

static inline dma_addr_t get_slpt_base_from_context(vtd_context_entry *ce)
{
    return (ce->lo & CONTEXT_ENTRY_SLPTPTR);
}

#define SLPT_LEVEL_BITS 9

static inline int slpt_level_shift(int level)
{
    return (VTD_PAGE_SHIFT + (level - 1) * SLPT_LEVEL_BITS);
}

static inline bool slpte_present(uint64_t slpte)
{
    return (slpte & 3);
}

/* Calculate the GPA given the base address, the index in the page table and
 * the level of this page table.
 */
static inline uint64_t get_slpt_gpa(uint64_t addr, int index, int level)
{
    return (addr + (((uint64_t)index) << slpt_level_shift(level)));
}

static inline uint64_t get_slpte_addr(uint64_t slpte)
{
    return (slpte & SL_PT_BASE_ADDR_MASK);
}

/* Whether the pte points to a large page */
static inline bool is_large_pte(uint64_t pte)
{
    return (pte & PT_PAGE_SIZE_MASK);
}

/* Whether the pte indicates the address of the page frame */
static inline bool is_last_slpte(uint64_t slpte, int level)
{
    if (level == SL_PT_LEVEL) {
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
    if (index >= SL_PT_ENTRY_NR) {
        return (uint64_t)-1;
    }
    if (dma_memory_read(&address_space_memory,
                        base_addr + index * sizeof(slpte), &slpte,
                        sizeof(slpte))) {
        fprintf(stderr, "(vtd) fail to read slpte\n");
        return (uint64_t)-1;
    }
    slpte = le64_to_cpu(slpte);
    return slpte;
}


static inline int gfn_level_offset(uint64_t gfn, int level)
{
    uint64_t gpa = gfn << 12;
    return ((gpa >> slpt_level_shift(level)) & ((1ULL << SLPT_LEVEL_BITS) - 1));
}

/*static uint64_t gfn_to_slpte(vtd_context_entry *ce, uint64_t gfn)
{
    dma_addr_t addr = get_slpt_base_from_context(ce);
    int level = SL_PDP_LEVEL;
    int offset;
    uint64_t slpte;


    while (true) {
        offset = gfn_level_offset(gfn, level);
        slpte = get_slpte(addr, offset);
        if (!slpte_present(slpte)) {
            slpte = (uint64_t)-1;
            break;
        }
		if (is_last_slpte(slpte, level)) {
            break;
        }
        addr = get_slpte_addr(slpte);
        level--;
    }
    return slpte;
}*/


/* Iterate a Second Level Page Table */
static void __walk_slpt(dma_addr_t table_addr, int level, uint64_t gpa)
{
    int index;
    uint64_t next_gpa;
    dma_addr_t next_table_addr;
    uint64_t slpte;

    if (level < SL_PT_LEVEL) {
        return;
    }


    for (index = 0; index < SL_PT_ENTRY_NR; ++index) {
        slpte = get_slpte(table_addr, index);
        if (!slpte_present(slpte)) {
            continue;
        }
        D("level %d, index 0x%x, gpa 0x%"PRIx64, level, index, gpa);
        next_gpa = get_slpt_gpa(gpa, index, level);
        next_table_addr = get_slpte_addr(slpte);

        if (is_last_slpte(slpte, level)) {
            D("slpte gpa 0x%"PRIx64 ", hpa 0x%"PRIx64, next_gpa, next_table_addr);
            if (next_gpa != next_table_addr) {
                D("Not 1:1 mapping, slpte 0x%"PRIx64, slpte);
            }
        } else {
            __walk_slpt(next_table_addr, level - 1, next_gpa);
        }
    }
}



static void print_paging_structure_from_context(vtd_context_entry *ce)
{
    dma_addr_t table_addr;

    table_addr = get_slpt_base_from_context(ce);
    __walk_slpt(table_addr, SL_PDP_LEVEL, 0);
}


static void print_root_table(intel_iommu_state *s)
{
    int i;
    int j;
    vtd_root_entry re;
    vtd_context_entry ce;

    for (i = 0; i < ROOT_ENTRY_NR; ++i) {
        if (get_root_entry(s, i, &re) && root_entry_present(&re)) {
            D("root_entry 0x%x: hi 0x%"PRIx64 " low 0x%"PRIx64, i, re.rsvd, re.val);

            for (j = 0; j < CONTEXT_ENTRY_NR; ++j) {
                if (get_context_entry_from_root(&re, j, &ce)
                    && context_entry_present(&ce)) {
                    D("context_entry 0x%x: hi 0x%"PRIx64 " low 0x%"PRIx64,
                      j, ce.hi, ce.lo);
                    D("--------------------------------");
                    print_paging_structure_from_context(&ce);
                }
            }
        }
    }
}




static void iommu_inv_queue_setup(intel_iommu_state *s)
{
    uint64_t tail_val;
    s->iq = *((uint64_t *)&s->csr[DMAR_IQA_REG]);
    s->iq_sz = 0x100 << (s->iq & 0x7);  /* 256 entries per page */
    s->iq &= ~0x7;
    s->iq_enable = true;

    /* Init head pointers */
    tail_val = *((uint64_t *)&s->csr[DMAR_IQT_REG]);
    *((uint64_t *)&s->csr[DMAR_IQH_REG]) = tail_val;
    s->iq_head = s->iq_tail = (tail_val >> 4) & 0x7fff;
    D(" -- address: 0x%lx size 0x%lx", s->iq, s->iq_sz);
}


static void handle_gcmd_qie(intel_iommu_state *s, bool en)
{
    D("Queued Invalidation Enable %s", (en ? "on" : "off"));

    if (en) {
        iommu_inv_queue_setup(s);
    }

    /* Ok - report back to driver */
    set_mask_long(s, DMAR_GSTS_REG, 0, VTD_GSTS_QIES);
}


static void vtd_root_table_setup(intel_iommu_state *s)
{
    s->root = *((uint64_t *)&s->csr[DMAR_RTADDR_REG]);
    s->extended = s->root & VTD_RTADDR_RTT;
    s->root &= ~0xfff;
    D("root_table addr 0x%"PRIx64 " %s", s->root,
      (s->extended ? "(Extended)" : ""));
}

/* Context-cache invalidation
 * Returns the Context Actual Invalidation Granularity.
 * @val: the content of the CCMD_REG
 */
static uint64_t vtd_context_cache_invalidate(intel_iommu_state *s, uint64_t val)
{
    uint64_t caig;
    uint64_t type = val & VTD_CCMD_CIRG_MASK;

    switch (type) {
    case VTD_CCMD_GLOBAL_INVL:
        D("Global invalidation request");
        caig = VTD_CCMD_GLOBAL_INVL_A;
        break;

    case VTD_CCMD_DOMAIN_INVL:
        D("Domain-selective invalidation request");
        caig = VTD_CCMD_DOMAIN_INVL_A;
        break;

    case VTD_CCMD_DEVICE_INVL:
        D("Domain-selective invalidation request");
        caig = VTD_CCMD_DEVICE_INVL_A;
        break;

    default:
        fprintf(stderr, "vtd context-cache invalidation: wrong granularity\n");
        caig = 0;
    }

    return caig;
}


#define status_write(x) (((x) >> 5) & 1)

/* Flush IOTLB
 * Returns the IOTLB Actual Invalidation Granularity.
 * @val: the content of the IOTLB_REG
 */
static uint64_t vtd_iotlb_flush(intel_iommu_state *s, uint64_t val)
{
    uint64_t iaig;
    uint64_t type = val & VTD_TLB_FLUSH_GRANU_MASK;

    switch (type) {
    case VTD_TLB_GLOBAL_FLUSH:
        D("Global IOTLB flush");
        iaig = VTD_TLB_GLOBAL_FLUSH_A;
        break;

    case VTD_TLB_DSI_FLUSH:
        D("Domain-selective IOTLB flush");
        iaig = VTD_TLB_DSI_FLUSH_A;
        break;

    case VTD_TLB_PSI_FLUSH:
        D("Page-selective-within-domain IOTLB flush");
        iaig = VTD_TLB_PSI_FLUSH_A;
        break;

    default:
        fprintf(stderr, "vtd iotlb flush: wrong granularity\n");
        iaig = 0;
    }

    //print_root_table(s);
    return iaig;
}

/*static int handle_invalidate(intel_iommu_state *s, uint16_t i)
{
    intel_iommu_inv_desc entry;
    uint8_t type;
    dma_memory_read(&address_space_memory, s->iq + sizeof(entry) * i, &entry,
                    sizeof(entry));
    type = entry.lower & 0xf;
    D(" Processing invalidate request %d - desc: %016lx.%016lx", i,
      entry.upper, entry.lower);
    switch (type) {
    case CONTEXT_CACHE_INV_DESC:
        D("Context-cache Invalidate");
        break;
    case IOTLB_INV_DESC:
        D("IOTLB Invalidate");
        break;
    case INV_WAIT_DESC:
        D("Invalidate Wait");
        if (status_write(entry.lower)) {
            dma_memory_write(&address_space_memory, entry.upper,
                             (uint8_t *)&entry.lower + 4, 4);
        }
        break;
    default:
        D(" - not impl - ");
    }
    return 0;
}*/


/*static void handle_iqt_write(intel_iommu_state *s, uint64_t val)
{
    s->iq_tail = (val >> 4) & 0x7fff;
    D("Write to IQT_REG new tail = %d", s->iq_tail);

    if (!s->iq_enable) {
        return;
    }

    //Process the invalidation queue
    while (s->iq_head != s->iq_tail) {
        handle_invalidate(s, s->iq_head++);
        if (s->iq_head == s->iq_sz) {
            s->iq_head = 0;
        }
    }
    *((uint64_t *)&s->csr[DMAR_IQH_REG]) = s->iq_head << 4;

    set_quad(s, DMAR_IQT_REG, val);
}*/

/* Set Root Table Pointer */
static void handle_gcmd_srtp(intel_iommu_state *s, bool en)
{
    D("Set Root Table Pointer %s", (en ? "on" : "off"));
    /* if @en is false, that is, clearing this bit, it has no effect. */
    if (en) {
        vtd_root_table_setup(s);
        /* Ok - report back to driver */
        set_mask_long(s, DMAR_GSTS_REG, 0, VTD_GSTS_RTPS);
    }
}


/* Handle Translation Enable/Disable */
static void handle_gcmd_te(intel_iommu_state *s, bool en)
{
    D("Translation Enable %s", (en ? "on" : "off"));

    if (en) {
        /* Ok - report back to driver */
        set_mask_long(s, DMAR_GSTS_REG, 0, VTD_GSTS_TES);
    } else {
        /* Ok - report back to driver */
        set_mask_long(s, DMAR_GSTS_REG, VTD_GSTS_TES, 0);
    }
    //print_root_table(s);
}

/* Handle write to Global Command Register */
static void handle_gcmd_write(intel_iommu_state *s, uint32_t val)
{
    uint32_t oldval = __get_long(s, DMAR_GCMD_REG);
    uint32_t changed = oldval ^ val;
    if (changed & VTD_GCMD_TE) {
        handle_gcmd_te(s, val & VTD_GCMD_TE);
    }
    if (val & VTD_GCMD_SRTP) {
        handle_gcmd_srtp(s, val & VTD_GCMD_SRTP);
    }
    if (changed & VTD_GCMD_SFL) {
        D("Set Fault Log %s", (val & VTD_GCMD_SFL ? "on" : "off"));
    }
    if (changed & VTD_GCMD_EAFL) {
        D("Enable Advanced Fault Logging %s",
          (val & VTD_GCMD_EAFL ? "on" : "off"));
    }
    if (changed & VTD_GCMD_WBF) {
        D("Write Buffer Flush %s", (val & VTD_GCMD_WBF ? "on" : "off"));
    }
    if (changed & VTD_GCMD_QIE) {
        handle_gcmd_qie(s, val & VTD_GCMD_QIE);
    }
    if (changed & VTD_GCMD_SIRTP) {
        D("Interrupt Remapping Enable %s",
          (val & VTD_GCMD_SIRTP ? "on" : "off"));
    }
    if (changed & VTD_GCMD_IRE) {
        D("Set Interrupt Remapping Table Pointer %s",
          (val & VTD_GCMD_IRE ? "on" : "off"));
    }
    if (changed & VTD_GCMD_CFI) {
        D("Compatibility Format Interrupt %s",
          (val & VTD_GCMD_CFI ? "on" : "off"));
    }

    set_long(s, DMAR_GCMD_REG, val);
}

/* Handle write to Context Command Register */
static void handle_ccmd_write(intel_iommu_state *s)
{
    uint64_t ret;
    uint64_t val = __get_quad(s, DMAR_CCMD_REG);

    /* Context-cache invalidation request */
    if (val & VTD_CCMD_ICC) {
        ret = vtd_context_cache_invalidate(s, val);

        /* Invalidation completed. Change something to show */
        set_mask_quad(s, DMAR_CCMD_REG, VTD_CCMD_ICC, 0ULL);
        ret = set_mask_quad(s, DMAR_CCMD_REG, VTD_CCMD_CAIG_MASK, ret);
        D("CCMD_REG write-back val: 0x%"PRIx64, ret);
    }
}

/* Handle write to IOTLB Invalidation Register */
static void handle_iotlb_write(intel_iommu_state *s)
{
    uint64_t ret;
    uint64_t val = __get_quad(s, DMAR_IOTLB_REG);

    /* IOTLB invalidation request */
    if (val & VTD_TLB_IVT) {
        ret = vtd_iotlb_flush(s, val);

        /* Invalidation completed. Change something to show */
        set_mask_quad(s, DMAR_IOTLB_REG, VTD_TLB_IVT, 0ULL);
        ret = set_mask_quad(s, DMAR_IOTLB_REG, VTD_TLB_FLUSH_GRANU_MASK_A, ret);
        D("IOTLB_REG write-back val: 0x%"PRIx64, ret);
    }
}


static uint64_t vtd_mem_read(void *opaque, hwaddr addr, unsigned size)
{
    intel_iommu_state *s = opaque;
    uint64_t val;

    if (addr + size > DMAR_REG_SIZE) {
        D("addr outside region: max 0x%x, got 0x%"PRIx64 " %d", DMAR_REG_SIZE,
          addr, size);
        return (uint64_t)-1;
    }

    assert(size == 4 || size == 8);

    switch (addr) {
    /* Root Table Address Register, 64-bit */
    case DMAR_RTADDR_REG:
        if (size == 4) {
            val = (uint32_t)s->root;
        } else {
            val = s->root;
        }
        break;

    case DMAR_RTADDR_REG_HI:
        assert(size == 4);
        val = s->root >> 32;
        break;

    default:
        if (size == 4) {
            val = get_long(s, addr);
        } else {
            val = get_quad(s, addr);
        }
    }

    D("addr 0x%"PRIx64 " size %d val 0x%"PRIx64, addr, size, val);
    return val;
}

static void vtd_mem_write(void *opaque, hwaddr addr,
                          uint64_t val, unsigned size)
{
    intel_iommu_state *s = opaque;

    if (addr + size > DMAR_REG_SIZE) {
        D("addr outside region: max 0x%x, got 0x%"PRIx64 " %d", DMAR_REG_SIZE,
          addr, size);
        return;
    }

    assert(size == 4 || size == 8);

    if (is_reserved(addr, size)) {
        return;
    }

    /* Val should be written into csr within the handler */
    switch (addr) {
    /* Global Command Register, 32-bit */
    case DMAR_GCMD_REG:
        D("DMAR_GCMD_REG write addr 0x%"PRIx64 ", size %d, val 0x%"PRIx64,
          addr, size, val);
        handle_gcmd_write(s, val);
        break;

    /* Invalidation Queue Tail Register, 64-bit */
/*    case DMAR_IQT_REG:
        if (size == 4) {

        }
        if (size == 4) {
            if (former_size == 0) {
                former_size = size;
                former_value = val;
                goto out;
            } else {
                val = (val << 32) + former_value;
                former_size = 0;
                former_value = 0;
            }
        }
        handle_iqt_write(s, val);
        break;
*/
    /* Context Command Register, 64-bit */
    case DMAR_CCMD_REG:
        D("DMAR_CCMD_REG write addr 0x%"PRIx64 ", size %d, val 0x%"PRIx64,
          addr, size,val);
        if (size == 4) {
            set_long(s, addr, val);
        } else {
            set_quad(s, addr, val);
            handle_ccmd_write(s);
        }
        break;

    case DMAR_CCMD_REG_HI:
        D("DMAR_CCMD_REG_HI write addr 0x%"PRIx64 ", size %d, val 0x%"PRIx64,
          addr, size, val);
        assert(size == 4);
        set_long(s, addr, val);
        handle_ccmd_write(s);
        break;


    /* IOTLB Invalidation Register, 64-bit */
    case DMAR_IOTLB_REG:
        D("DMAR_IOTLB_REG write addr 0x%"PRIx64 ", size %d, val 0x%"PRIx64,
          addr, size, val);
        if (size == 4) {
            set_long(s, addr, val);
        } else {
            set_quad(s, addr, val);
            handle_iotlb_write(s);
        }
        break;

    case DMAR_IOTLB_REG_HI:
        D("DMAR_IOTLB_REG_HI write addr 0x%"PRIx64 ", size %d, val 0x%"PRIx64,
          addr, size, val);
        assert(size == 4);
        set_long(s, addr, val);
        handle_iotlb_write(s);
        break;

    /* Fault Status Register, 32-bit */
    case DMAR_FSTS_REG:
    /* Fault Event Data Register, 32-bit */
    case DMAR_FEDATA_REG:
    /* Fault Event Address Register, 32-bit */
    case DMAR_FEADDR_REG:
    /* Fault Event Upper Address Register, 32-bit */
    case DMAR_FEUADDR_REG:
    /* Fault Event Control Register, 32-bit */
    case DMAR_FECTL_REG:
    /* Protected Memory Enable Register, 32-bit */
    case DMAR_PMEN_REG:
        D("Known reg write addr 0x%"PRIx64 ", size %d, val 0x%"PRIx64,
          addr, size, val);
        set_long(s, addr, val);
        break;


    /* Root Table Address Register, 64-bit */
    case DMAR_RTADDR_REG:
        D("DMAR_RTADDR_REG write addr 0x%"PRIx64 ", size %d, val 0x%"PRIx64,
          addr, size, val);
        if (size == 4) {
            set_long(s, addr, val);
        }else {
            set_quad(s, addr, val);
        }
        break;

    case DMAR_RTADDR_REG_HI:
        D("DMAR_RTADDR_REG_HI write addr 0x%"PRIx64 ", size %d, val 0x%"PRIx64,
          addr, size, val);
        assert(size == 4);
        set_long(s, addr, val);
        break;

    default:
        D("Unhandled reg write addr 0x%"PRIx64 ", size %d, val 0x%"PRIx64,
          addr, size, val);
        if (size == 4) {
            set_long(s, addr, val);
        } else {
            set_quad(s, addr, val);
        }
    }

}


static IOMMUTLBEntry vtd_iommu_translate(MemoryRegion *iommu, hwaddr addr)
{
    intel_iommu_state *s = container_of(iommu, intel_iommu_state, iommu);
    IOMMUTLBEntry ret = {
        .target_as = &address_space_memory,
        .iova = 0,
        .translated_addr = 0,
        .addr_mask = ~(hwaddr)0,
        .perm = IOMMU_NONE,
    };

    if (!(__get_long(s, DMAR_GSTS_REG) & VTD_GSTS_TES)) {
        /* DMAR disabled, passthrough */
        ret.iova = addr & TARGET_PAGE_MASK;
        ret.translated_addr = addr & TARGET_PAGE_MASK;
        ret.addr_mask = ~TARGET_PAGE_MASK;
        ret.perm = IOMMU_RW;
        D("translation passthrough addr 0x%"PRIx64 " target 0x%"PRIx64, addr,
          ret.translated_addr);
        return ret;
    }

    /* TODO: Add translation function */
    ret.iova = addr & TARGET_PAGE_MASK;
    ret.translated_addr = addr & TARGET_PAGE_MASK;
    ret.addr_mask = ~TARGET_PAGE_MASK;
    ret.perm = IOMMU_RW;

    return ret;
}

static const VMStateDescription vtd_vmstate = {
    .name = "iommu_intel",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields      = (VMStateField[]) {
        VMSTATE_UINT8_ARRAY(csr, intel_iommu_state, DMAR_REG_SIZE),
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

static MemoryRegionIOMMUOps vtd_iommu_ops = {
    .translate = vtd_iommu_translate,
};


static Property iommu_properties[] = {
    DEFINE_PROP_UINT32("version", intel_iommu_state, version, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void vtd_reset(DeviceState *d)
{
    /* intel_iommu_state *s = INTEL_IOMMU_DEVICE(d); */
    D(" ");
}

static int vtd_init(SysBusDevice *dev)
{
    intel_iommu_state *s = INTEL_IOMMU_DEVICE(dev);

    memset(s->csr, 0, DMAR_REG_SIZE);
    memset(s->wmask, 0, DMAR_REG_SIZE);
    memset(s->w1cmask, 0, DMAR_REG_SIZE);
    memset(s->womask, 0, DMAR_REG_SIZE);

    memory_region_init_io(&s->csrmem, OBJECT(s), &vtd_mem_ops, s,
                          "intel_iommu", DMAR_REG_SIZE);
    memory_region_init_iommu(&s->iommu, OBJECT(s), &vtd_iommu_ops,
                            "intel_iommu", ram_size);
    address_space_init(&s->iommu_as, &s->iommu, "intel_iommu");
    D(" ");

    /* b.0:2 = 2: Number of domains supported: 256 using 8 bit ids
     * b.3   = 0: No advanced fault logging
     * b.4   = 0: No required write buffer flushing
     * b.5   = 0: Protected low memory region not supported
     * b.6   = 0: Protected high memory region not supported
     * b.8:12 = 2: SAGAW(Supported Adjusted Guest Address Widths), 39-bit,
     *             3-level page-table
     * b.16:21 = 38: MGAW(Maximum Guest Address Width) = 38 + 1
     * b.22 = 1: ZLR(Zero Length Read) supports zero length DMA read requests
     *           to write-only pages
     * b.24:33 = 34: FRO(Fault-recording Register offset)
     * b.54 = 0: DWD(Write Draining), draining of write requests not supported
     * b.55 = 0: DRD(Read Draining), draining of read requests not supported
     */
    const uint64_t dmar_cap_reg_value = 0x00660202ULL | VTD_CAP_FRO
                                        | VTD_CAP_NFR;

    /* b.1 = 0: QI(Queued Invalidation support) not supported
     * b.2 = 0: DT(Device-TLB support)
     * b.3 = 0: IR(Interrupt Remapping support) not supported
     * b.4 = 0: EIM(Extended Interrupt Mode) not supported
     * b.8:17 = 15: IRO(IOTLB Register Offset)
     * b.20:23 = 15: MHMV(Maximum Handle Mask Value)
     */
    const uint64_t dmar_ecap_reg_value = 0xf00000ULL | VTD_ECAP_IRO;

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
    define_long(s, DMAR_FSTS_REG, 0, 0, 0xfdUL);
    define_long(s, DMAR_FECTL_REG, 0x80000000UL, 0x80000000UL, 0);
    define_long(s, DMAR_FEDATA_REG, 0, 0xffffffffUL, 0); /* All bits RW */
    define_long(s, DMAR_FEADDR_REG, 0, 0xfffffffcUL, 0); /* 31:2 RW */
    define_long(s, DMAR_FEUADDR_REG, 0, 0xffffffffUL, 0); /* 31:0 RW */

    define_quad(s, DMAR_AFLOG_REG, 0, 0xffffffffffffff00ULL, 0);

    /* Treated as RO for implementations that PLMR and PHMR fields reported
     * as Clear in the CAP_REG.
     * define_long(s, DMAR_PMEN_REG, 0, 0x80000000UL, 0);
     */
    define_long(s, DMAR_PMEN_REG, 0, 0, 0);

    /* TBD: The definition of these are dynamic:
     * DMAR_PLMBASE_REG, DMAR_PLMLIMIT_REG, DMAR_PHMBASE_REG, DMAR_PHMLIMIT_REG
     */

    /* Bits 18:4 (0x7fff0) is RO, rest is RsvdZ
     * IQH_REG is treated as RsvdZ when not supported in ECAP_REG
     * define_quad(s, DMAR_IQH_REG, 0, 0, 0);
     */
    define_quad(s, DMAR_IQH_REG, 0, 0, 0);

    /* IQT_REG and IQA_REG is treated as RsvdZ when not supported in ECAP_REG
     * define_quad(s, DMAR_IQT_REG, 0, 0x7fff0ULL, 0);
     * define_quad(s, DMAR_IQA_REG, 0, 0xfffffffffffff007ULL, 0);
     */
    define_quad(s, DMAR_IQT_REG, 0, 0, 0);
    define_quad(s, DMAR_IQA_REG, 0, 0, 0);

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

    /* When MTS not supported in ECAP_REG, these regs are RsvdZ */
    define_long(s, DMAR_MTRRCAP_REG, 0, 0, 0);
    define_long(s, DMAR_MTRRDEF_REG, 0, 0, 0);

    /* IOTLB registers */
    define_quad(s, DMAR_IOTLB_REG, 0, 0Xb003ffff00000000ULL, 0);
    define_quad(s, DMAR_IVA_REG, 0, 0xfffffffffffff07fULL, 0);
    define_quad_wo(s, DMAR_IVA_REG, 0xfffffffffffff07fULL);

    return 0;
}

static void iommu_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);

    k->init = vtd_init;
    dc->reset = vtd_reset;
    dc->vmsd = &vtd_vmstate;
    dc->props = iommu_properties;
}

static const TypeInfo iommu_info = {
    .name          = TYPE_INTEL_IOMMU_DEVICE,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(intel_iommu_state),
    .class_init    = iommu_class_init,
};

static void iommu_register_types(void)
{
    D(" ");
    type_register_static(&iommu_info);
}

type_init(iommu_register_types)
