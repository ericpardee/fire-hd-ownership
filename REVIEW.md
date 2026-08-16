# Code Review: Kimi K3 CVE-2022-38181 Exploit (trona)

## Verdict: Stop the grind. The selfix approach has a deterministic logic bug, not a race condition.

Over 500 attempts, every single one that reaches the selfix stage produces the identical result: all 25 PGD candidates show `enforce 1`. This is 0-for-199 (attempts that reached selfix). No amount of rebooting will fix this.

---

## The Three Fatal Issues

### Issue 1: PGD leaves are allocated BEFORE jit_free (the freed pages can never become them)

This is the root cause. On r14p0, `kbase_mem_alloc` for non-SAME_VA regions calls `kbase_gpu_mmap` **during the ioctl** (`mali_kbase_mem_linux.c:381`):

```c
} else /* we control the VA */ {
    if (kbase_gpu_mmap(kctx, reg, 0, va_pages, 1) != 0) {  // GPU PTEs set up HERE
        ...
    }
    *gpu_va = reg->start_pfn << PAGE_SHIFT;
}
```

The reserved regions are allocated with `commit_pages = RESERVED_SIZE` and no `BASE_MEM_SAME_VA` flag (`exploit_trona.c:317-323`). So `kbase_gpu_mmap` -> `kbase_mmu_insert_pages` -> `kbase_mmu_alloc_pgd` runs during `reserve_pages()`, which is **before the exploit loop**.

The PGD leaves for the reserved regions are drawn from `kbdev->mem_pool` at that time. The victim's pages haven't been freed yet. They cannot become these PGD leaves.

The `map_reserved()` call (line 559) only does `mmap()`, which goes through `kbase_cpu_mmap` (the `default` case in `kbase_mmap`). It does **not** call `kbase_gpu_mmap` again. No new GPU page tables are created after jit_free.

**The GHSL reference exploit works on Pixel 6 (r36p0+) likely because the driver version has a different code path where GPU page tables for non-SAME_VA regions are deferred to `mmap()` time. On r14p0, they are set up eagerly during `KBASE_IOCTL_MEM_ALLOC`.**

### Issue 2: Cannot read the alias to find the PGD leaf (PROT_NONE only on r14p0)

The GHSL exploit's `find_pgd()` reads the alias to identify which page is a live PGD leaf:

```c
int find_pgd(int freed_idx, int start_pg) {
    uint64_t* this_alias = alias_regions[freed_idx];
    for (int pg = start_pg; pg < SPRAY_PAGES; pg++) {
        for (int i = 0; i < 0x1000/8; i++) {
            uint64_t entry = this_alias[pg * 0x1000/8 + i];
            if ((entry & 0x443) == 0x443) return pg;  // found ATE_L3 entries
        }
    }
}
```

This requires `PROT_READ` on the alias. On r14p0 (trona), the alias only accepts `PROT_NONE` (confirmed in STATE.md). The selfix approach was designed as a workaround: blindly write to all 25 pages and check if selinux_enforcing toggles.

But selfix can't distinguish PGD leaf pages from non-PGD-leaf pages. If none of the 25 freed pages is a PGD leaf (which is the case due to Issue 1), all 25 probes fail. 500 attempts x 25 probes = 12,500 failed writes, every single one guaranteed to fail.

### Issue 3: Missing `fault_pages()` step

The GHSL exploit calls `fault_pages()` after aliasing and before jit_free:

```c
void fault_pages() {
    for (int va = 0; va < SPRAY_NUM; va++) {
        uint8_t* this_va = (uint8_t*)(gpu_va[va]);
        *this_va = 0;                    // fault in spray page
        uint8_t* this_alias = alias_regions[va];
        read += *this_alias;             // fault in alias page
    }
}
```

This ensures all pages are faulted in and GPU PTEs are fully populated. Kimi's exploit skips this step. Without faulting, some alias GPU PTEs may not be populated, meaning GPU writes through the alias may silently fail.

---

## Misleading Diagnostics

The `markers found in reserved backing: 0` and `markers recycled into NEW fd region: 0` diagnostics are **expected** and do NOT indicate a problem. They check the wrong memory pool:

- `kbase_jit_free` frees victim pages to `kctx->mem_pool` (per-context pool)
- The drain fills `kctx->mem_pool` to max (16384 pages = 64MB)
- The freed victim pages overflow to `kbdev->mem_pool` (device pool)
- PGD leaves are allocated from `kbdev->mem_pool` (confirmed: `kbase_mmu_alloc_pgd` at `mali_kbase_mmu.c:871`)
- But reserved region data backing comes from `kctx->mem_pool` (via `kbase_alloc_phy_pages_helper`)
- And new fd region backing also comes from `kctx->mem_pool`

So the markers check allocations from `kctx->mem_pool`, but the freed pages went to `kbdev->mem_pool`. The markers will always be 0 regardless of whether the page reclamation is working.

Pool assignment (from kbase source analysis):

| Resource | Allocated from | Returned to |
|---|---|---|
| PGD/PTE pages (all levels) | `kbdev->mem_pool` | `kbdev->mem_pool` |
| Backing data pages (4KB) | `kctx->mem_pool` | `kctx->mem_pool` |
| `kbase_va_region` struct | kmalloc-128 slab | kmalloc-128 slab |

---

## Other Differences from GHSL Reference

| Aspect | GHSL (Pixel 6, r36p0+) | Kimi (trona, r14p0) |
|---|---|---|
| Context groups | mali_fd=group 0, mali_fd2=group 1 | both fd and fd2 = group 0 |
| Alias CPU protection | PROT_READ | PROT_NONE (driver quirk) |
| fault_pages() | Yes | No |
| PGD leaf discovery | find_pgd (reads alias) | selfix (blind probe) |
| Spray count | 64 | 256 |
| Reserved size | 1024 pages | 768 pages |
| Target for SELinux off | avc_denied (shellcode) | selinux_enforcing (direct write) |
| kbase_va_region size | kmalloc-256 (r36p0+) | kmalloc-128 (r14p0) |

---

## Recommended Fixes (in priority order)

### Fix 1: Delay PGD leaf allocation to after jit_free

**Option A: Make reserved regions SAME_VA**

Change `reserve_pages()` to use `BASE_MEM_SAME_VA`:
```c
ma.in.flags = BASE_MEM_SAME_VA | BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
              BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_WR;
```

For SAME_VA regions on r14p0, `KBASE_IOCTL_MEM_ALLOC` returns a cookie and does NOT call `kbase_gpu_mmap`. The GPU page tables are set up during `mmap()` via `kbasep_reg_mmap` -> `kbase_gpu_mmap` (`mali_kbase_mem_linux.c:1986`). Since `map_reserved()` runs after jit_free, the PGD leaves will be allocated from `kbdev->mem_pool` at that point, and can be the freed victim pages.

Note: `reserve_pages` will store cookies, and `map_reserved` will establish the VA (CPU VA = GPU VA for SAME_VA).

**Option B: Allocate with commit_pages=0, commit after jit_free**

Keep non-SAME_VA but allocate with `commit_pages = 0`. Then after jit_free, call `KBASE_IOCTL_MEM_COMMIT` for each reserved region. The commit triggers `kbase_mmu_insert_pages` which allocates PGD leaves from `kbdev->mem_pool`.

```c
// In reserve_pages:
ma.in.commit_pages = 0;  // VA only, no backing, no GPU PTEs

// After jit_free, before map_reserved:
for (int i = 0; i < nents; i++) {
    struct kbase_ioctl_mem_commit mc = { reserved_va[i], RESERVED_SIZE };
    ioctl(fd, KBASE_IOCTL_MEM_COMMIT, &mc);
}
```

### Fix 2: Find a way to identify the PGD leaf without reading the alias

**Option A: Use a GPU compute job to scan alias pages**

Write a simple GPU compute shader that reads each alias page and writes a flag to a readable buffer if it finds entries matching the 0x443 pattern. This replaces `find_pgd()` with a GPU-based scan.

**Option B: Use the fault-oracle approach (from the "win" mode in exploit_trona.c)**

The existing "win" mode (lines 593-683) uses a fault-oracle: it writes a bogus entry to each candidate, fires a GPU job at the reserved VA, and checks if the job faults. A fault indicates the candidate IS a live PGD leaf. This approach was abandoned because "bogus-entry probing wedges the GPU" (STATE.md), but with Fix 1 in place, it may work better since the freed pages will actually be PGD leaves.

**Option C: Brute-force with the correct target**

With Fix 1 in place, the selfix approach should work because at least one of the 25 freed pages WILL be a PGD leaf. The selfix probe writes the target page address to entry 256, then writes 0 to selinux_enforcing through the redirected VA. If the page is a PGD leaf, the write lands. With 25 pages and ~24 reserved regions, the odds are good that at least one page is a PGD leaf.

### Fix 3: Add fault_pages() equivalent

After aliasing and before jit_free, fault in all pages:
```c
// After alias_sprayed_regions(), before drain:
for (int j = 0; j < SPRAY_NUM; j++) {
    volatile char *p = (volatile char *)gpu_va[j];
    *p = 0;  // fault in first page
    // Can't read alias (PROT_NONE), but the GPU PTEs are set up during kbase_gpu_mmap
}
```

Note: Since the alias is PROT_NONE, we can't fault in the alias pages from the CPU. But `kbase_gpu_mmap` (called during `KBASE_IOCTL_MEM_ALIAS`) inserts all pages eagerly, so the GPU PTEs should be set up regardless.

### Fix 4: Consider TLB invalidation

After modifying a PGD leaf entry through the alias, the GPU's TLB may still hold the old entry. The GHSL exploit uses a separate context (`mali_fd2`) for the reserved regions and write_func, which may cause a TLB flush when the GPU switches address spaces. With both fds in group 0 (same address space), the TLB may not be flushed.

Consider using separate context groups (like the GHSL exploit) or submitting a NULL job to force a TLB flush.

---

## Summary

The grind should be stopped immediately. The selfix approach cannot succeed because:

1. The PGD leaves for the reserved regions are allocated before jit_free (r14p0 eager GPU mapping during alloc)
2. The alias can't be read to find the correct PGD leaf (PROT_NONE on r14p0)
3. Without knowing which page is the PGD leaf, blind probing fails 100% of the time

The fix is to delay PGD leaf allocation to after jit_free (via SAME_VA regions or deferred commit), then the selfix approach should work because the freed pages will actually become PGD leaves.
