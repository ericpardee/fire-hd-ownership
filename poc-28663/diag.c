/* diagnostic: is the kctx->mm binding sticking? */
#include <stdio.h>
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

int main(void)
{
	struct kbase_ioctl_version_check vc = { .major = 999, .minor = 999 };
	int fd = open("/dev/mali0", O_RDWR);
	if (fd == -1) { perror("open mali0"); return 1; }
	if (ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc) < 0) { perror("VERSION_CHECK"); return 1; }
	printf("[*] UAPI %d.%d\n", vc.major, vc.minor);

	void *t1 = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE);
	printf("[*] track mmap #1: %s (%p)\n", t1 == MAP_FAILED ? strerror(errno) : "OK", t1);

	void *t2 = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE);
	if (t2 == MAP_FAILED)
		printf("[*] track mmap #2: %s  <- EPERM means binding stuck\n", strerror(errno));
	else
		printf("[*] track mmap #2: OK (%p)  <- binding did NOT stick\n", t2);

	union kbase_ioctl_mem_alloc ma;
	memset(&ma, 0, sizeof(ma));
	ma.in.va_pages     = 0x1000; /* 16MB */
	ma.in.commit_pages = 0x1000;
	ma.in.extent       = 0;
	ma.in.flags        = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
			     BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR;
	if (ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &ma) == 0) {
		printf("[+] MEM_ALLOC OK gpu_va=0x%llx\n", ma.out.gpu_va);
		return 0;
	}
	printf("[-] MEM_ALLOC: %s (%d)\n", strerror(errno), errno);
	return 1;
}
