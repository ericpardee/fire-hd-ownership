/* bisect: which prep step breaks subsequent JOB_SUBMIT for JIT_ALLOC */
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
typedef unsigned char __u8;

#include "mali_trona.h"

struct kbase_ioctl_mem_jit_init { __u64 va_pages; __u8 max_allocations; __u8 trim_level; __u8 padding[6]; };
#define KBASE_IOCTL_MEM_JIT_INIT _IOW(0x80, 14, struct kbase_ioctl_mem_jit_init)

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

struct base_jit_alloc_info {
	__u64 gpu_alloc_addr; __u64 va_pages; __u64 commit_pages; __u64 extent;
	__u8 id, bin_id, max_allocations, flags; __u8 padding[2]; __u16 usage_id;
};

static int fd;

static void try_dump(int id, const char *tag)
{
	struct base_jd_atom_v2 atom;
	memset(&atom, 0, sizeof(atom));
	atom.atom_number = id;
	atom.core_req = 0x201; /* DUMP */
	struct kbase_ioctl_job_submit js = { (__u64)&atom, 1, sizeof(atom) };
	int r = ioctl(fd, KBASE_IOCTL_JOB_SUBMIT, &js);
	printf("    %-28s -> %s\n", tag, r == 0 ? "OK" : strerror(errno));
}

int main(void)
{
	int id = 1;
	struct kbase_ioctl_version_check vc = { 999, 999 };
	fd = open("/dev/mali0", O_RDWR);
	if (fd < 0) { perror("open"); return 1; }
	ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc);
	struct kbase_ioctl_set_flags sf = { 0 };
	if (ioctl(fd, KBASE_IOCTL_SET_FLAGS, &sf) < 0) { perror("SF"); return 1; }
	void *t = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE);
	if (t == MAP_FAILED) { perror("track"); return 1; }
	printf("[*] init ok\n");

	try_dump(id++, "dump after init");

	struct kbase_ioctl_mem_jit_init ji = { 0 };
	ji.va_pages = 0x40000; ji.max_allocations = 8;
	if (ioctl(fd, KBASE_IOCTL_MEM_JIT_INIT, &ji) < 0) { perror("JIT_INIT"); return 1; }
	try_dump(id++, "dump after JIT_INIT");

	union kbase_ioctl_mem_alloc ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.va_pages = ma.in.commit_pages = 1;
	ma.in.flags = BASE_MEM_SAME_VA | BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
		      BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
	if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &ma) < 0) { perror("MEM_ALLOC"); return 1; }
	void *wb = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, ma.out.gpu_va);
	if (wb == MAP_FAILED) { perror("mmap wb"); return 1; }
	try_dump(id++, "dump after MEM_ALLOC+mmap");

	/* now the JIT alloc atom */
	struct base_jit_alloc_info info;
	memset(&info, 0, sizeof(info));
	info.gpu_alloc_addr = (__u64)wb;
	info.va_pages = info.commit_pages = 4096;
	info.id = 1; info.max_allocations = 8;

	struct base_jd_atom_v2 atom;
	memset(&atom, 0, sizeof(atom));
	atom.jc = (__u64)&info;
	atom.nr_extres = 1;
	atom.atom_number = id++;
	atom.core_req = 0x209; /* SOFT_JIT_ALLOC */
	struct kbase_ioctl_job_submit js = { (__u64)&atom, 1, sizeof(atom) };
	int r = ioctl(fd, KBASE_IOCTL_JOB_SUBMIT, &js);
	printf("    %-28s -> %s\n", "SOFT_JIT_ALLOC", r == 0 ? "OK" : strerror(errno));

	sleep(1);
	printf("[*] jit_va = 0x%llx\n", *(__u64 *)wb);
	return 0;
}
