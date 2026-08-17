# Fire HD 10 2019 (trona) root project - engineering state

## Device
- Model KFTRWI (trona/maverick), Fire OS 7.3.2.6, kernel 4.4.146 (built 2022-10-21), MediaTek MT8183 (Mali-G72, kbase r14p0, UAPI 11.11).
- This unit: LOT 8S132 = 2021 manufacture => bootrom DL entry is patched shut; no software-only root path. Confirmed live: vol-button BROM entry blocked (boots recovery), preloader crash rejected (0x1d18).

## The bug: CVE-2022-38181 (JIT allocator UAF) - UNPATCHED here
- `kbase_mem_flags_change` accepts BASE_MEM_DONT_NEED on JIT regions (no KBASE_REG_NO_USER_FREE / JIT guard) - verified in the raw kernel binary.
- Confirmed live on device: JIT region made evictable, shrinker frees it under memory pressure while `kctx->jit_alloc[]` dangles. `poc-28663/{jit_trigger,stagec}.c`.
- Reference exploit: ghsl/SecurityExploits/Android/Mali/CVE_2022_38181 (cloned), Man Yue Mo's writeup (github.blog 2023-01-23).

## Driver quirks discovered (r14p0, needed for any UAPI work)
- Context init sequence: VERSION_CHECK with any version, then SET_FLAGS(create_flags=0) which both flips setup_complete and CLEARS SUBMIT_DISABLED. Then mmap(BASE_MEM_MAP_TRACKING_HANDLE) to bind kctx->mm.
- MEM_ALLOC returns "cookie" addresses; the real VA is established by mmap. MEM_ALIAS on 64-bit likewise returns a cookie and only gets *GPU* mappings when the cookie is mmap'd; alias regions have no CPU perms (mmap only accepts PROT_NONE).
- kbase ioctl nr 5 needs the 32-byte (extent) struct. nr 21 alias = 32 bytes. nr 23 flags_change = 24.
- GPU WRITE_VALUE jobs (BASE_JD_REQ_CS) work; job-chain format validated (pack_header).

## Weaponization pieces validated
- exploit_trona.c: full chain builds, finds freed victim region (find_freed_idx), all stable.
- alias_write_test.c: PROT_NONE alias mmap + GPU WRITE_VALUE lands in shared backing = write channel works.

## Remaining work (the grind)
- PGD-leaf discovery without content reads: probe candidates 0..24 by writing leaf entry[256]=<target phys page>|0x443 through the alias (GPU job), then patch via GPU jobs at the redirected reserved VA; validate via /sys/fs/selinux/enforce toggle.
- Kernel phys base assumption: 0x40080000 (LK build, no EFI seed). Offsets from ota_extract/vmlinux.elf (built with vmlinux-to-elf):
  avc_denied +0x2b7734, sel_read_enforce +0x2c228c, init_cred +0x166a918 (from prepare_kernel_cred), commit_creds +0x4b744, selinux_enforcing +0x18908c0.
- Reliability: replacement race crashes ~half the attempts. Reboot-grind via grind.sh.

## Run
./grind.sh poc-28663/exploit_trona   # loops attempts, reboots tablet on failure, logs win_*.log on success

## Reliability + tuning notes (2026-08-14)
- kbase_va_region is 123 bytes -> kmalloc-128 (hottest slab): the replacement race loses to background kernel traffic most attempts. Tuning applied: SPRAY_NUM 256 multi-CPU, drain to push freed pages to kbdev->mem_pool, grinder settles post-boot.
- **Aperture mapped (decisive):** GPU writes work from 0x40400000 upward; 0x40000000-0x40400000 is SMMU/IOMMU BLOCKED (kernel image start). Confirms phys base = 0x40080000.
- **Writable targets:** selinux_enforcing 0x418908c0, init_cred 0x416a918, commit_creds 0x404b744, kbase_ioctl 0x406e1f7c, kbase_mmap 0x406df3bc. BLOCKED (in protected region): avc_denied 0x402b7734, sel_read_enforce 0x402c228c, sel_write_enforce 0x40342318.
- **Endgame design (validated piece by piece):** trigger -> spray 256 multi-cpu -> alias (PROT_NONE) -> drain -> jit_free -> map_reserved -> find reserved PGD leaf -> write selinux_enforcing=0 (writable) -> patch kbase_mmap with commit_creds(&init_cred) shellcode (writable) -> trigger via mmap -> uid 0.
- **Remaining blocker:** replacement-race reliability (crashes ~half of attempts at jit_free, each costs a reboot) + reserved-PGD-leaf discovery without content reads (bogus-entry probing wedges the GPU; use only safe same-target probes like selfix).

## GLM-5.2 review (REVIEW.md) - verdict on my findings
- **Issue 1 CONFIRMED CORRECT in source**: on r14p0, non-SAME_VA regions get `kbase_gpu_mmap` during the MEM_ALLOC ioctl itself (`mali_kbase_mem_linux.c:381`). My reserved regions were non-SAME_VA committed before the loop, so their PGD leaves were built from kbdev->mem_pool BEFORE the victim's pages were freed => could never become those pages. This was the fatal design bug. FIXED: reserve_pages now uses BASE_MEM_SAME_VA (GPU page tables deferred to map_reserved after jit_free).
- Fault-oracle "pgd_idx 24 = leaf" was a FALSE POSITIVE: reserved regions use leaf entries 0-31, so entry-256 is always unused and faults at baseline.
- Marker diagnostics checked the wrong pool (kctx vs kbdev), zeros were expected.
- GLM-5.2 also confirmed 0x443 is a valid ATE_L3 entry for aarch64 MMU; suggested inner-shareable variants if writes fail.

## The remaining hard problem (2026-08-15)
Freed pages become PGD leaves of MANY structures (reserved, alias, spray, jc). The reserved leaf is only ~2 of the victim's 25 alias pages; I cannot identify which without reading the alias (PROT_NONE on r14p0). Every write-based probe (selfix/safefix/event-code) eventually hijacks a wrong-structure leaf, redirects live translations, and panics the kernel -> reboot. This is the ONLY thing between us and root.
- Correct solution (GLM-5.2 Fix 2 Option A): a Mali bifrost GPU compute shader that scans the 25 alias pages for 0x443-pattern entries and reports the reserved leaf. Crash-free because it reads via GPU, no hijack needed. Requires hand-writing a Mali ISA compute job (the hard part).
- Endgame once leaf is known: hijack that ONE leaf -> write selinux_enforcing=0 (0x418908c0, writable) -> patch kbase_mmap (0x406df3bc, writable) with commit_creds(&init_cred) shellcode -> trigger via mmap -> uid 0. All addresses verified.
