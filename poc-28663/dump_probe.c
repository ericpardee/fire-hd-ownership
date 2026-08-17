/* dump_probe: standalone MMU dump parser test. No exploit, no churn.
 * Opens mali0, inits a context, dumps the GPU page tables via
 * BASE_MEM_MMU_DUMP_HANDLE and prints the table tree structure. */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned long long __u64;

#include "mali_trona.h"

static int fd;

int main(void)
{
	struct kbase_ioctl_version_check vc = { 999, 999 };
	fd = open("/dev/mali0", O_RDWR);
	if (fd < 0) { perror("open"); return 1; }
	if (ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc) < 0) { perror("VC"); return 1; }
	struct kbase_ioctl_set_flags sf = { 0 };
	if (ioctl(fd, KBASE_IOCTL_SET_FLAGS, &sf) < 0) { perror("SF"); return 1; }
	if (mmap(NULL, 0x1000, 0, MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE) == MAP_FAILED) {
		perror("track"); return 1;
	}
	printf("[*] context up (UAPI %d.%d)\n", vc.major, vc.minor);

	/* allocate a few regions to populate the table tree */
	for (int i = 0; i < 4; i++) {
		union kbase_ioctl_mem_alloc ma;
		memset(&ma, 0, sizeof(ma));
		ma.in.flags = BASE_MEM_SAME_VA | BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
			      BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_WR;
		ma.in.va_pages = 64;
		ma.in.commit_pages = 64;
		if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &ma) < 0) { perror("alloc"); return 1; }
		void *r = mmap(NULL, 64 << 12, PROT_READ | PROT_WRITE, MAP_SHARED, fd, ma.out.gpu_va);
		if (r == MAP_FAILED) { printf("    region %d mmap FAILED: %s (cookie=%llx)\n", i, strerror(errno), ma.out.gpu_va); }
		else printf("    region %d va=%p\n", i, r);
	}

	size_t dsize = 8 * 1024 * 1024;
	void *dump = mmap(NULL, dsize, PROT_READ, MAP_SHARED, fd, 0x1000);
	if (dump == MAP_FAILED) { perror("dump mmap"); return 1; }
	printf("[*] dump mapped %zu bytes\n", dsize);

	/* walk block headers: m_pgd = phys|level, then 512 entries */
	__u64 *q = (__u64 *)((char *)dump + 24);
	__u64 *end = (__u64 *)((char *)dump + dsize);
	int b = 0;
	while (q < end && *q != 0xFFULL && b < 40) {
		printf("  blk %2d: m_pgd=0x%llx phys=0x%llx level=%d\n",
		       b, *q, *q & ~0xfULL, (int)(*q & 0xf));
		q = (__u64 *)((char *)q + 8 + 512 * 8);
		b++;
	}

	/* tree walk from L0 root, tracking index path -> VA */
	struct { __u64 va, phys; int level; } stk[512];
	int n = 0;
	__u64 root = *(__u64 *)((char *)dump + 24) & ~0xfULL;
	stk[n++] = (typeof(stk[0])){ 0, root, 0 };
	while (n > 0) {
		typeof(stk[0]) cur = stk[--n];
		__u64 *blk = NULL;
		for (q = (__u64 *)((char *)dump + 24); q < end && *q != 0xFFULL; q = (__u64 *)((char *)q + 8 + 512 * 8)) {
			if (*q == (cur.phys | (__u64)cur.level)) { blk = q; break; }
		}
		if (!blk) { printf("    (no block for phys=0x%llx level=%d)\n", cur.phys, cur.level); continue; }
		__u64 *ents = blk + 1;
		if (cur.level == 3) {
			printf("  L3 leaf va=0x%llx phys=0x%llx (covers va 0x%llx-0x%llx)\n",
			       cur.va, cur.phys, cur.va, cur.va + 0x200000ULL);
			continue;
		}
		int nf = 0;
		for (int i = 0; i < 512; i++) {
			if (ents[i] && nf < 6) printf("      ent[%d] = 0x%llx (type bits %lld)\n", i, ents[i], ents[i] & 3);
			if ((ents[i] & 3) == 3) {
				__u64 shift = 39 - (__u64)cur.level * 9;
				stk[n++] = (typeof(stk[0])){ cur.va | ((__u64)i << shift), ents[i] & ~0xfffULL, cur.level + 1 };
				nf++;
			}
		}
		printf("    level %d phys=0x%llx: followed %d table entries\n", cur.level, cur.phys, nf);
	}
	return 0;
}
