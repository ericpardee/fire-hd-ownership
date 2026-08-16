# Handoff: CVE-2022-38181 root exploit for Fire HD 10 2019 (trona)

**For:** GLM-5.2 (fire-hd-glm-5.2 opencode session)
**From:** Kimi K3
**Date:** 2026-08-15
**Goal:** root + SELinux permissive on Eric's Fire HD 10 2019 (KFTRWI, Fire OS 7.3.2.6, kernel 4.4.146, MT8183, Mali-G72, kbase r14p0, UAPI 11.11)

---

## Executive summary

The bug (CVE-2022-38181) is **confirmed exploitable** on this bootrom-locked device, and every primitive and offset is verified. The GHSL alias-hijack weaponization is **blocked by a pool-structure mismatch on r14p0** that has resisted every drain configuration tried. The exact blocker, all evidence, and the concrete next steps are below. Everything needed to finish is in this directory.

---

## 1. What's proven and works (build on these)

| Component | Status | Where |
|---|---|---|
| Bug is live + exploitable (JIT evictable + shrinker free + dangling jit_alloc) | PROVEN | `poc-28663/{jit_trigger,stagec}.c` |
| GPU WRITE_VALUE jobs (BASE_JD_REQ_CS) | PROVEN | `poc-28663/gpu_test.c` |
| Alias write channel (PROT_NONE alias mmap + GPU write lands in shared backing) | PROVEN | `poc-28663/alias_write_test.c` |
| MMU dump parser via `BASE_MEM_MMU_DUMP_HANDLE` (0x1000) — reads full GPU page-table tree CPU-side | PROVEN, correct | `poc-28663/dump_probe.c` |
| DRAM aperture map (kernel image start `0x40000000-0x40400000` is SMMU-blocked; everything above is GPU-writable) | PROVEN | in this doc §4 |
| All kernel offsets from exact vmlinux | PROVEN | `ota_extract/vmlinux.elf` + this doc §5 |
| r14p0 UAPI driver quirks (context init, cookies, alias perms) | PROVEN | `STATE.md` |

---

## 2. THE BLOCKER (the only thing between GLM-5.2 and root)

**On r14p0, the victim's freed pages never become PGD leaves.** The GHSL exploit's core trick — "the reserved PGD leaf is a freed victim page in the alias" — is **false on this driver's two-pool design**:

- The victim's 25 freed backing pages go to **`kctx->mem_pool`** (per-context backing pool) via `kbase_jit_free -> kbase_mem_shrink -> kbase_free_phy_pages_helper(reclaimed=false)`. They become **backing pages** the alias maps.
- The reserved regions' **PGD leaves** come from **`kbdev->mem_pool`** (separate device-wide PGD pool) via `kbase_mmu_alloc_pgd`. They are **different physical pages**, **not in the alias**.

**Definitive dump evidence (with the working parser):** `0 of 30 L3 leaves are victim pages`, and a new backing allocation after `jit_free` doesn't reuse them either (`markers recycled into NEW fd region = 0`). The victim's freed pages are in **neither** pool's drawable free list.

**Most likely explanation (from GLM-5.2's own earlier diagnosis):** if both `kctx->mem_pool` AND `kbdev->mem_pool` are at capacity at `jit_free` time, the victim's pages are freed straight to the **kernel buddy allocator** (bypassing both pools), which is why they vanish from both drawable lists.

---

## 3. What was tried (all failed to deliver victim-to-leaf)

1. **SAME_VA reserved regions** (GLM-5.2 Fix 1): defers GPU page-table creation to `map_reserved` after `jit_free`. Correct and necessary, but alone insufficient — leaves still come from `kbdev->mem_pool`, not the victim's `kctx->mem_pool` pages.
2. **Single drain** (fill `kctx->mem_pool` to max before `jit_free`): victim doesn't spill to `kbdev->mem_pool`. `0 of 29` leaves are victim pages.
3. **GLM-5.2's two-drain** (drain1 fill kctx, drain2 kept to empty kbdev): drain2 re-empties `kctx->mem_pool` after drain1 fills it, so `kctx` isn't full at `jit_free` — victim stays in `kctx->mem_pool` as backing. `0 of 30`.
4. **Corrected drain ordering** (drainA kctx kept → drainB kbdev kept → free drainA to fill kctx): intended to make kctx full + kbdev empty at `jit_free`. Still `0 of 30`.
5. **Blind/fault-oracle leaf probing** (selfix/safefix): crashes the kernel — freed pages become leaves of many structures (reserved, alias, spray, jc); hijacking a wrong-structure leaf redirects live translations and panics. The MMU dump parser avoids this entirely and is the right discovery tool.

---

## 4. Environment and verified facts

**Device:** KFTRWI (trona/maverick), Fire OS 7.3.2.6 (PS7326.3178N), kernel 4.4.146 (built 2022-10-21), MediaTek MT8183, Mali-G72 MP3 (bifrost, JM-era, UAPI 11.11). This unit: LOT 8S132 = 2021 manufacture => bootrom DL entry patched shut; no software-only root path (vol-button BROM blocked, preloader crash rejected 0x1d18, mtk-su patched + `/dev/mtk_cmdq` system-only).

**Aperture (from GPU phys scan):** `0x40000000-0x40400000` blocked (kernel image region, SMMU), `0x40400000+` fully writable. Kernel phys base = `0x40080000`.

**kctx->mem_pool max** = `KBASE_MEM_POOL_MAX_SIZE_KCTX = SZ_64M >> PAGE_SHIFT = 16384` (confirmed `mali_kbase_mem.h:504`). `CONFIG_MALI_2MB_ALLOC` NOT set (all 4KB pool path).

**Pools:** PGD/PTE pages strictly from `kbdev->mem_pool` (`kbase_mmu_alloc_pgd`, `mali_kbase_mmu.c:871`). Backing data pages from `kctx->mem_pool`. `kbase_va_region` struct from kmalloc-128 slab.

**r14p0 UAPI quirks (required for any ioctl work):**
- Context init: `VERSION_CHECK` (any version) → `SET_FLAGS(create_flags=0)` (flips setup_complete AND clears SUBMIT_DISABLED) → `mmap(BASE_MEM_MAP_TRACKING_HANDLE)` to bind `kctx->mm`.
- `MEM_ALLOC` returns "cookie" addresses; real VA established by mmap. nr 5 = 32-byte (extent) struct. nr 21 alias = 32 bytes. nr 23 flags_change = 24.
- Aliases: CPU perms masked off in `kbase_mem_alias` (only `PROT_NONE` mmap accepted). GPU mappings install at the PROT_NONE mmap.
- The MMU dump handle: `mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0x1000)` → buffer = config[3] + recursive table dump (m_pgd = phys|level header + 512 entries per page) + 0xFF end marker. Tree walk: follow `(entry & 3) == 3` entries (table pointers use `entry_set_pte`, PTE type).

---

## 5. Kernel offsets (from `ota_extract/vmlinux.elf`, built with vmlinux-to-elf from Amazon's own OTA `update-kindle-Fire_HD10_9th_Gen-PS7326_user_3178_0025602845316.bin`, matches device build fingerprint exactly)

| Symbol | Image offset | Physical | Writable? |
|---|---|---|---|
| `selinux_enforcing` | `0x18908c0` | `0x418908c0` | YES |
| `init_cred` | `0x166a918` | `0x416a918` | YES |
| `commit_creds` | `0x4b744` | `0x404b744` | YES |
| `kbase_ioctl` | `0x661f7c` | `0x406e1f7c` | YES |
| `kbase_mmap` | `0x65f3bc` | `0x406df3bc` | YES |
| `avc_denied` | `0x2b7734` | `0x402b7734` | NO (SMMU) |
| `sel_read_enforce` | `0x2c228c` | `0x402c228c` | NO (SMMU) |
| `sel_write_enforce` | `0x2c2318` | `0x40342318` | NO (SMMU) |

phys = offset + `0x40080000` (phys base, confirmed by blocked aperture).

---

## 6. The concrete open questions for GLM-5.2

1. **Where do the victim's freed backing pages actually go?** They're in neither pool's drawable list. Is there a path on r14p0 where they're freed straight to the kernel buddy allocator, and can that be prevented?
2. **How do we get the victim's freed pages into `kbdev->mem_pool`** (the PGD pool) so they become reserved leaves the alias covers? Every drain configuration tried has failed to deliver them there.
3. **GLM-5.2's own suggested diagnostic** (from your last message): allocate a 1-page region after `jit_free`, dump MMU, and check if its L3 leaf's physical address is a victim page. Run that first — it isolates whether pool shaping works at all vs whether `map_reserved` is the broken half.
4. **If the GHSL alias-hijack approach is fundamentally dead on r14p0's two-pool design**, what's the alternative primitive? The freed pages ARE still GPU-mapped in the alias (the bug holds) — just not as leaves. (Note: the compute-shader approach does NOT help here — if victim pages never become leaves, the shader finds no PGD entries in the alias.)

---

## 7. Key artifacts (all in this directory)

- `poc-28663/exploit_trona.c` — the full exploit (trigger, spray, alias, drain, jit_free, map_reserved, dumpfind, selfix/safefix/win modes, corrected drain sequence)
- `poc-28663/dump_probe.c` — **working standalone MMU dump parser** (correct tree walk; use this as the discovery tool)
- `poc-28663/mali_trona.h` — r14p0 UAPI header (verified against the kernel binary)
- `ota_extract/vmlinux.elf` — exact kernel with kallsyms (all offsets computed from it)
- `kbase-src/` — r14p0 kbase source (LCM-MTK mirror, matches the build path embedded in the kernel)
- `ghsl/SecurityExploits/Android/Mali/CVE_2022_38181/` — GHSL reference exploit
- `STATE.md` — full engineering log
- `REVIEW.md` — GLM-5.2's earlier code review (Issue 1 confirmed correct)

## Reliability note

The `jit_free` replacement race (kmalloc-128, hottest slab) crashes ~50% of attempts, each costing a reboot. The exploit self-retries 6x per boot and a hang-watchdog `grind.sh` exists. Manageable, but expect many boots once the reclaim works.
