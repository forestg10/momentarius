#ifndef momentarius_utils_h
#define momentarius_utils_h

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <mach/mach.h>
#include "momentarius.h"

extern momentarius_t momentarius;
extern volatile bool stop_write;

#define KADDR_VALID(va) (((va) & 0xffff000000000000) == 0xffff000000000000)
#define GFX_PA_VALID(arg) (((arg) & 0x0000FFFF00000000) == 0x800000000)
#define trunc_page_kernel(address) ((uint64_t)(address) & ~0x3fffULL)

extern int IOSurface_map_withCacheMode(uint64_t pa, uint64_t size, void **uaddr, uint32_t cacheMode);
uint64_t kread64(uint64_t address);
uint32_t kread32(uint64_t address);
uint8_t kread8(uint64_t address);
uint64_t kread_ptr(uint64_t address);
void kwrite64(uint64_t address, uint64_t value);
void kwrite32(uint64_t address, uint32_t value);
void kwrite8(uint64_t address, uint8_t value);
void kreadbuf(uint64_t address, void *buffer, size_t size);
void kwritebuf(uint64_t address, const void *buffer, size_t size);
uint64_t proc_find(pid_t pid);
uint64_t proc_self(void);
uint64_t proc_task(uint64_t proc);
extern uint64_t physread64(uint64_t pa);
extern uint32_t physread32(uint64_t pa);
extern uint64_t kvtophys(uint64_t va);
extern uint64_t phystokv(uint64_t pa);
extern uint64_t vtophys_lvl(uint64_t tte_ttep, uint64_t va, uint64_t *leaf_level, uint64_t *leaf_tte_ttep);
extern uint64_t task_get_ipc_port_kobject(uint64_t task, mach_port_t port);

uint64_t map_phys_data(uint64_t pa, uint32_t size);
uint64_t map_writeback_page(uint64_t pa);
uint64_t map_physread64(uint64_t pa);
uint64_t kalloc_page(void);
uint32_t a64_gen_movk(uint8_t rd, int32_t imm, uint8_t sh);
uint32_t a64_gen_movz(uint8_t rd, int32_t imm, uint8_t sh);
int32_t a64_branch_difference(uint64_t from, uint64_t to);
uint32_t a64_gen_cond_branch(uint64_t from, uint64_t to, uint8_t cond);
uint32_t a64_gen_branch(uint64_t from, uint64_t to);
uint64_t gfx_phystokv(uint64_t pa);
void momentarius_tlb_flush(void);
void gfx_suspend(void);
void gfx_resume(void);

#endif
