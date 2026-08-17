/* gpu_test: validate GPU WRITE_VALUE job submission on trona r14p0.
 * Writes a magic immediate into a CPU-readable region via the GPU, then
 * reads it back through the CPU mapping.
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdbool.h>

typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned long long __u64;
typedef unsigned char __u8;

#include "mali_trona.h"

struct kbase_ioctl_job_submit { __u64 addr; __u32 nr_atoms; __u32 stride; };
#define KBASE_IOCTL_JOB_SUBMIT _IOW(0x80, 2, struct kbase_ioctl_job_submit)

struct base_dependency { __u8 atom_id; __u8 dependency_type; };
struct base_jd_atom_v2 {
	__u64 jc; __u64 udata[2]; __u64 extres_list;
	__u16 nr_extres; __u16 compat_core_req;
	struct base_dependency pre_dep[2];
	__u8 atom_number, prio, device_nr, padding;
	__u32 core_req;
};
struct base_jd_event_v2 { __u32 event_code; __u8 atom_number; __u8 _pad[3]; __u64 udata[2]; };

#define BASE_JD_REQ_CS 0x2

/* --- job descriptor bits (bifrost JM, from GHSL midgard.h) --- */
static inline uint32_t gen_uint(uint64_t val, int lo, int hi) { return (uint32_t)(val >> lo); }

struct job_header {
	uint32_t exception_status;
	uint32_t first_incomplete_task;
	uint64_t fault_pointer;
	bool is_64b;
	uint32_t type;
	bool barrier;
	bool invalidate_cache;
	bool suppress_prefetch;
	bool enable_texture_mapper;
	bool relax_dependency_1;
	bool relax_dependency_2;
	uint32_t index;
	uint32_t dependency_1;
	uint32_t dependency_2;
	uint64_t next;
};

static void job_header_pack(uint32_t *cl, const struct job_header *v)
{
	cl[0] = v->exception_status;
	cl[1] = v->first_incomplete_task;
	cl[2] = (uint32_t)v->fault_pointer;
	cl[3] = (uint32_t)(v->fault_pointer >> 32);
	cl[4] = (v->is_64b ? 1 : 0) |
		(v->type << 1) |
		(v->barrier ? (1 << 8) : 0) |
		(v->invalidate_cache ? (1 << 9) : 0) |
		(v->suppress_prefetch ? (1 << 11) : 0) |
		(v->enable_texture_mapper ? (1 << 12) : 0) |
		(v->relax_dependency_1 ? (1 << 14) : 0) |
		(v->relax_dependency_2 ? (1 << 15) : 0) |
		(v->index << 16);
	cl[5] = v->dependency_1 | (v->dependency_2 << 16);
	cl[6] = (uint32_t)v->next;
	cl[7] = (uint32_t)(v->next >> 32);
}

struct write_value_payload {
	uint64_t address;
	uint64_t type;
	uint64_t immediate_value;
};

static int fd;

static void *map_gpu_rw(unsigned int pages)
{
	union kbase_ioctl_mem_alloc ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
		      BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_WR;
	ma.in.va_pages = pages;
	ma.in.commit_pages = pages;
	if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &ma) < 0) { perror("MEM_ALLOC"); return NULL; }
	void *r = mmap(NULL, pages << 12, PROT_READ | PROT_WRITE, MAP_SHARED, fd, ma.out.gpu_va);
	if (r == MAP_FAILED) { perror("mmap"); return NULL; }
	return r;
}

static int submit_cs(__u64 jc, __u8 id)
{
	struct base_jd_atom_v2 atom;
	memset(&atom, 0, sizeof(atom));
	atom.jc = jc;
	atom.atom_number = id;
	atom.core_req = BASE_JD_REQ_CS;
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

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	struct kbase_ioctl_version_check vc = { 999, 999 };
	fd = open("/dev/mali0", O_RDWR);
	if (fd < 0) { perror("open"); return 1; }
	ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc);
	struct kbase_ioctl_set_flags sf = { 0 };
	if (ioctl(fd, KBASE_IOCTL_SET_FLAGS, &sf) < 0) { perror("SF"); return 1; }
	void *track = mmap(NULL, 0x1000, 0, MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE);
	if (track == MAP_FAILED) { perror("track"); return 1; }
	printf("[*] init ok\n");

	void *jc_region = map_gpu_rw(1);
	void *target = map_gpu_rw(1);
	if (!jc_region || !target) return 1;
	memset(jc_region, 0, 0x1000);
	*(volatile __u64 *)target = 0;

	struct job_header jh;
	memset(&jh, 0, sizeof(jh));
	jh.is_64b = true;
	jh.type = 2; /* WRITE_VALUE */
	struct write_value_payload pl = {
		.address = (__u64)target,
		.type = 7, /* IMMEDIATE_64 */
		.immediate_value = 0x4141414142424242ULL,
	};
	job_header_pack((uint32_t *)jc_region, &jh);
	memcpy((uint32_t *)jc_region + 8, &pl, sizeof(pl));

	printf("[*] submitting WRITE_VALUE job, jc=%p target=%p\n", jc_region, target);
	if (submit_cs((__u64)jc_region, 1) < 0) { perror("submit"); return 1; }
	int ev = wait_event();
	printf("[*] event = 0x%x\n", ev);
	printf("[*] target content = 0x%llx (expect 0x4141414142424242)\n",
	       *(volatile __u64 *)target);
	return 0;
}
