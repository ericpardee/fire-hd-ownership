/* kbase UAPI for trona's driver: VERSION_CHECK reports 11.11.
 * Key difference vs newer UAPI: union kbase_ioctl_mem_alloc has NO extent
 * field yet, so the struct is 24 bytes and the ioctl number matches.
 */
#ifndef MALI_TRONA_H
#define MALI_TRONA_H

#define KBASE_IOCTL_TYPE 0x80

typedef __u32 base_context_create_flags;
typedef __u32 base_mem_alloc_flags;

struct kbase_ioctl_version_check {
	__u16 major;
	__u16 minor;
};

struct kbase_ioctl_set_flags {
	__u32 create_flags;
};

/* 32-byte layout for nr 4 (0xc0208004) */
union kbase_ioctl_mem_alloc {
	struct {
		__u64 va_pages;
		__u64 commit_pages;
		__u64 extent;
		__u64 flags;
	} in;
	struct {
		__u64 flags;
		__u64 gpu_va;
	} out;
};

union kbase_ioctl_mem_alias {
	struct {
		__u64 flags;
		__u64 stride;
		__u64 nents;
		__u64 aliasing_info;
	} in;
	struct {
		__u64 flags;
		__u64 gpu_va;
		__u64 va_pages;
	} out;
};

struct base_mem_handle {
	struct {
		__u64 handle;
	} basep;
};

struct base_mem_aliasing_info {
	struct base_mem_handle handle;
	__u64 offset;
	__u64 length;
};

struct kbase_ioctl_mem_flags_change {
	__u64 gpu_va;
	__u64 flags;
	__u64 mask;
};

#define BASE_MEM_MAP_TRACKING_HANDLE           (3ull  << 12)

#define BASE_MEM_PROT_GPU_RD ((base_mem_alloc_flags)1 << 2)
#define BASE_MEM_PROT_GPU_WR ((base_mem_alloc_flags)1 << 3)
#define BASE_MEM_PROT_CPU_RD ((base_mem_alloc_flags)1 << 0)
#define BASE_MEM_PROT_CPU_WR ((base_mem_alloc_flags)1 << 1)

#define BASE_MEM_SAME_VA ((base_mem_alloc_flags)1 << 13)
#define BASE_MEM_DONT_NEED ((base_mem_alloc_flags)1 << 17)
#define BASE_MEM_COHERENT_SYSTEM ((base_mem_alloc_flags)1 << 10)
#define BASE_MEM_COHERENT_LOCAL ((base_mem_alloc_flags)1 << 11)

#define BASE_MEM_FLAGS_MODIFIABLE \
	(BASE_MEM_DONT_NEED | BASE_MEM_COHERENT_SYSTEM | \
	 BASE_MEM_COHERENT_LOCAL)

#define KBASE_IOCTL_MEM_FLAGS_CHANGE \
	_IOW(KBASE_IOCTL_TYPE, 23, struct kbase_ioctl_mem_flags_change)

#define KBASE_IOCTL_MEM_ALIAS \
	_IOWR(KBASE_IOCTL_TYPE, 21, union kbase_ioctl_mem_alias)

/* nr 5 = MEM_ALLOC (32-byte). Gated on kctx->bound_mm, which is established
 * lazily by mmap'ing BASE_MEM_MAP_TRACKING_HANDLE first. */
#define KBASE_IOCTL_MEM_ALLOC \
	_IOWR(KBASE_IOCTL_TYPE, 5, union kbase_ioctl_mem_alloc)

#define KBASE_IOCTL_SET_FLAGS \
	_IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)

#define KBASE_IOCTL_VERSION_CHECK \
	_IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version_check)

#endif