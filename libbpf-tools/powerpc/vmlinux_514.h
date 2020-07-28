
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef char *va_list;

typedef signed char __s8;

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

typedef struct {
	__u32 u[4];
} __vector128;

typedef __vector128 vector128;

enum {
	false = 0,
	true = 1,
};

typedef long int __kernel_long_t;

typedef long unsigned int __kernel_ulong_t;

typedef int __kernel_pid_t;

typedef unsigned int __kernel_uid32_t;

typedef unsigned int __kernel_gid32_t;

typedef __kernel_ulong_t __kernel_size_t;

typedef __kernel_long_t __kernel_ssize_t;

typedef long long int __kernel_loff_t;

typedef long long int __kernel_time64_t;

typedef __kernel_long_t __kernel_clock_t;

typedef int __kernel_timer_t;

typedef int __kernel_clockid_t;

typedef __u16 __be16;

typedef __u32 __be32;

typedef __u64 __be64;

typedef unsigned int __poll_t;

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

typedef short unsigned int umode_t;

typedef __kernel_pid_t pid_t;

typedef __kernel_clockid_t clockid_t;

typedef _Bool bool;

typedef __kernel_uid32_t uid_t;

typedef __kernel_gid32_t gid_t;

typedef __kernel_loff_t loff_t;

typedef __kernel_size_t size_t;

typedef __kernel_ssize_t ssize_t;

typedef s32 int32_t;

typedef u32 uint32_t;

typedef u64 uint64_t;

typedef u64 sector_t;

typedef u64 blkcnt_t;

typedef unsigned int gfp_t;

typedef unsigned int fmode_t;

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	s64 counter;
} atomic64_t;

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct hlist_node;

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};

struct kernel_symbol {
	long unsigned int value;
	const char *name;
	const char *namespace;
};

struct user_pt_regs {
	long unsigned int gpr[32];
	long unsigned int nip;
	long unsigned int msr;
	long unsigned int orig_gpr3;
	long unsigned int ctr;
	long unsigned int link;
	long unsigned int xer;
	long unsigned int ccr;
	long unsigned int softe;
	long unsigned int trap;
	long unsigned int dar;
	long unsigned int dsisr;
	long unsigned int result;
};

struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			long unsigned int gpr[32];
			long unsigned int nip;
			long unsigned int msr;
			long unsigned int orig_gpr3;
			long unsigned int ctr;
			long unsigned int link;
			long unsigned int xer;
			long unsigned int ccr;
			long unsigned int softe;
			long unsigned int trap;
			long unsigned int dar;
			long unsigned int dsisr;
			long unsigned int result;
		};
	};
	union {
		struct {
			long unsigned int ppr;
			long unsigned int exit_result;
			union {
				long unsigned int kuap;
				long unsigned int amr;
			};
			long unsigned int iamr;
		};
		long unsigned int __pad[4];
	};
};

struct lock_class_key {};

struct fs_context;

struct fs_parameter_spec;

struct dentry;

struct super_block;

struct module;

struct file_system_type {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry * (*mount)(struct file_system_type *, int, const char *, void *);
	void (*kill_sb)(struct super_block *);
	struct module *owner;
	struct file_system_type *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct qspinlock {
	union {
		atomic_t val;
		struct {
			u8 locked;
			u8 pending;
		};
		struct {
			u16 locked_pending;
			u16 tail;
		};
	};
};

typedef struct qspinlock arch_spinlock_t;

struct qrwlock {
	union {
		atomic_t cnts;
		struct {
			u8 wlocked;
			u8 __lstate[3];
		};
	};
	arch_spinlock_t wait_lock;
};

typedef struct qrwlock arch_rwlock_t;

struct lockdep_map {};

struct raw_spinlock {
	arch_spinlock_t raw_lock;
};

typedef struct raw_spinlock raw_spinlock_t;

struct ratelimit_state {
	raw_spinlock_t lock;
	int interval;
	int burst;
	int printed;
	int missed;
	long unsigned int begin;
	long unsigned int flags;
};

struct pi_entry {
	const char *fmt;
	const char *func;
	const char *file;
	unsigned int line;
	const char *level;
	const char *subsys_fmt_prefix;
} __attribute__((packed));

struct jump_entry {
	s32 code;
	s32 target;
	long int key;
};

struct static_key_mod;

struct static_key {
	atomic_t enabled;
	union {
		long unsigned int type;
		struct jump_entry *entries;
		struct static_key_mod *next;
	};
};

typedef void *fl_owner_t;

struct file;

struct kiocb;

struct iov_iter;

struct io_comp_batch;

struct dir_context;

struct poll_table_struct;

struct vm_area_struct;

struct inode;

struct file_lock;

struct page;

struct pipe_inode_info;

struct seq_file;

struct file_operations {
	struct module *owner;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *, struct io_comp_batch *, unsigned int);
	int (*iterate)(struct file *, struct dir_context *);
	int (*iterate_shared)(struct file *, struct dir_context *);
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
	long int (*unlocked_ioctl)(struct file *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*mmap)(struct file *, struct vm_area_struct *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode *, struct file *);
	int (*flush)(struct file *, fl_owner_t);
	int (*release)(struct inode *, struct file *);
	int (*fsync)(struct file *, loff_t, loff_t, int);
	int (*fasync)(int, struct file *, int);
	int (*lock)(struct file *, int, struct file_lock *);
	ssize_t (*sendpage)(struct file *, struct page *, int, size_t, loff_t *, int);
	long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long int, struct file_lock **, void **);
	long int (*fallocate)(struct file *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file *, struct file *);
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *, loff_t, struct file *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
};

struct static_call_key {
	void *func;
};

struct bug_entry {
	int bug_addr_disp;
	int file_disp;
	short unsigned int line;
	short unsigned int flags;
};

typedef __s64 time64_t;

struct __kernel_timespec {
	__kernel_time64_t tv_sec;
	long long int tv_nsec;
};

struct timespec64 {
	time64_t tv_sec;
	long int tv_nsec;
};

enum timespec_type {
	TT_NONE = 0,
	TT_NATIVE = 1,
	TT_COMPAT = 2,
};

typedef s32 old_time32_t;

struct old_timespec32 {
	old_time32_t tv_sec;
	s32 tv_nsec;
};

struct pollfd;

struct restart_block {
	long unsigned int arch_data;
	long int (*fn)(struct restart_block *);
	union {
		struct {
			u32 *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 *uaddr2;
		} futex;
		struct {
			clockid_t clockid;
			enum timespec_type type;
			union {
				struct __kernel_timespec *rmtp;
				struct old_timespec32 *compat_rmtp;
			};
			u64 expires;
		} nanosleep;
		struct {
			struct pollfd *ufds;
			int nfds;
			int has_timeout;
			long unsigned int tv_sec;
			long unsigned int tv_nsec;
		} poll;
	};
};

typedef struct {
	__be64 pte;
} pte_t;

typedef struct {
	__be64 pmd;
} pmd_t;

typedef struct {
	__be64 pud;
} pud_t;

typedef struct {
	__be64 pgd;
} pgd_t;

typedef struct {
	long unsigned int pgprot;
} pgprot_t;

typedef pte_t *pgtable_t;

typedef atomic64_t atomic_long_t;

struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
};

typedef struct spinlock spinlock_t;

struct address_space;

struct page_pool;

struct mm_struct;

struct dev_pagemap;

struct page {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space *mapping;
			long unsigned int index;
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			union {
				long unsigned int dma_addr_upper;
				atomic_long_t pp_frag_count;
			};
		};
		struct {
			long unsigned int compound_head;
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
			unsigned int compound_nr;
		};
		struct {
			long unsigned int _compound_pad_1;
			long unsigned int _compound_pad_2;
			struct list_head deferred_list;
		};
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t pmd_huge_pte;
			long unsigned int _pt_pad_2;
			union {
				struct mm_struct *pt_mm;
				atomic_t pt_frag_refcount;
			};
			spinlock_t ptl;
		};
		struct {
			struct dev_pagemap *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};

struct slb_entry {
	u64 esid;
	u64 vsid;
};

struct subpage_prot_table {
	long unsigned int maxaddr;
	unsigned int **protptrs[512];
	unsigned int *low_prot[4];
};

struct slice_mask {
	u64 low_slices;
	long unsigned int high_slices[64];
};

struct hash_mm_context {
	u16 user_psize;
	unsigned char low_slices_psize[8];
	unsigned char high_slices_psize[2048];
	long unsigned int slb_addr_limit;
	struct slice_mask mask_64k;
	struct slice_mask mask_4k;
	struct slice_mask mask_16m;
	struct slice_mask mask_16g;
	struct subpage_prot_table *spt;
};

typedef long unsigned int mm_context_id_t;

typedef struct {
	union {
		mm_context_id_t id;
		mm_context_id_t extended_id[8];
	};
	atomic_t active_cpus;
	atomic_t copros;
	atomic_t vas_windows;
	struct hash_mm_context *hash_context;
	void *vdso;
	void *pte_frag;
	void *pmd_frag;
	struct list_head iommu_group_mem_list;
	u32 pkey_allocation_map;
	s16 execute_only_pkey;
} mm_context_t;

struct lppaca {
	__be32 desc;
	__be16 size;
	u8 reserved1[3];
	u8 __old_status;
	u8 reserved3[14];
	volatile __be32 dyn_hw_node_id;
	volatile __be32 dyn_hw_proc_id;
	u8 reserved4[56];
	volatile u8 vphn_assoc_counts[8];
	u8 reserved5[32];
	u8 reserved6[48];
	u8 cede_latency_hint;
	u8 ebb_regs_in_use;
	u8 reserved7[6];
	u8 dtl_enable_mask;
	u8 donate_dedicated_cpu;
	u8 fpregs_in_use;
	u8 pmcregs_in_use;
	u8 reserved8[28];
	__be64 wait_state_cycles;
	u8 reserved9[28];
	__be16 slb_count;
	u8 idle;
	u8 vmxregs_in_use;
	volatile __be32 yield_count;
	volatile __be32 dispersion_count;
	volatile __be64 cmo_faults;
	volatile __be64 cmo_fault_time;
	u8 reserved10[104];
	__be32 page_ins;
	u8 reserved11[148];
	volatile __be64 dtl_idx;
	u8 reserved12[96];
};

struct slb_shadow {
	__be32 persistent;
	__be32 buffer_length;
	__be64 reserved;
	struct {
		__be64 esid;
		__be64 vsid;
	} save_area[2];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct cpu_accounting_data {
	long unsigned int utime;
	long unsigned int stime;
	long unsigned int gtime;
	long unsigned int hardirq_time;
	long unsigned int softirq_time;
	long unsigned int steal_time;
	long unsigned int idle_time;
	long unsigned int starttime;
	long unsigned int starttime_user;
};

enum MCE_Version {
	MCE_V1 = 1,
};

enum MCE_Severity {
	MCE_SEV_NO_ERROR = 0,
	MCE_SEV_WARNING = 1,
	MCE_SEV_SEVERE = 2,
	MCE_SEV_FATAL = 3,
};

enum MCE_Disposition {
	MCE_DISPOSITION_RECOVERED = 0,
	MCE_DISPOSITION_NOT_RECOVERED = 1,
};

enum MCE_Initiator {
	MCE_INITIATOR_UNKNOWN = 0,
	MCE_INITIATOR_CPU = 1,
	MCE_INITIATOR_PCI = 2,
	MCE_INITIATOR_ISA = 3,
	MCE_INITIATOR_MEMORY = 4,
	MCE_INITIATOR_POWERMGM = 5,
};

enum MCE_ErrorType {
	MCE_ERROR_TYPE_UNKNOWN = 0,
	MCE_ERROR_TYPE_UE = 1,
	MCE_ERROR_TYPE_SLB = 2,
	MCE_ERROR_TYPE_ERAT = 3,
	MCE_ERROR_TYPE_TLB = 4,
	MCE_ERROR_TYPE_USER = 5,
	MCE_ERROR_TYPE_RA = 6,
	MCE_ERROR_TYPE_LINK = 7,
	MCE_ERROR_TYPE_DCACHE = 8,
	MCE_ERROR_TYPE_ICACHE = 9,
};

enum MCE_ErrorClass {
	MCE_ECLASS_UNKNOWN = 0,
	MCE_ECLASS_HARDWARE = 1,
	MCE_ECLASS_HARD_INDETERMINATE = 2,
	MCE_ECLASS_SOFTWARE = 3,
	MCE_ECLASS_SOFT_INDETERMINATE = 4,
};

enum MCE_UeErrorType {
	MCE_UE_ERROR_INDETERMINATE = 0,
	MCE_UE_ERROR_IFETCH = 1,
	MCE_UE_ERROR_PAGE_TABLE_WALK_IFETCH = 2,
	MCE_UE_ERROR_LOAD_STORE = 3,
	MCE_UE_ERROR_PAGE_TABLE_WALK_LOAD_STORE = 4,
};

enum MCE_SlbErrorType {
	MCE_SLB_ERROR_INDETERMINATE = 0,
	MCE_SLB_ERROR_PARITY = 1,
	MCE_SLB_ERROR_MULTIHIT = 2,
};

enum MCE_EratErrorType {
	MCE_ERAT_ERROR_INDETERMINATE = 0,
	MCE_ERAT_ERROR_PARITY = 1,
	MCE_ERAT_ERROR_MULTIHIT = 2,
};

enum MCE_TlbErrorType {
	MCE_TLB_ERROR_INDETERMINATE = 0,
	MCE_TLB_ERROR_PARITY = 1,
	MCE_TLB_ERROR_MULTIHIT = 2,
};

enum MCE_UserErrorType {
	MCE_USER_ERROR_INDETERMINATE = 0,
	MCE_USER_ERROR_TLBIE = 1,
	MCE_USER_ERROR_SCV = 2,
};

enum MCE_RaErrorType {
	MCE_RA_ERROR_INDETERMINATE = 0,
	MCE_RA_ERROR_IFETCH = 1,
	MCE_RA_ERROR_IFETCH_FOREIGN = 2,
	MCE_RA_ERROR_PAGE_TABLE_WALK_IFETCH = 3,
	MCE_RA_ERROR_PAGE_TABLE_WALK_IFETCH_FOREIGN = 4,
	MCE_RA_ERROR_LOAD = 5,
	MCE_RA_ERROR_STORE = 6,
	MCE_RA_ERROR_PAGE_TABLE_WALK_LOAD_STORE = 7,
	MCE_RA_ERROR_PAGE_TABLE_WALK_LOAD_STORE_FOREIGN = 8,
	MCE_RA_ERROR_LOAD_STORE_FOREIGN = 9,
};

enum MCE_LinkErrorType {
	MCE_LINK_ERROR_INDETERMINATE = 0,
	MCE_LINK_ERROR_IFETCH_TIMEOUT = 1,
	MCE_LINK_ERROR_PAGE_TABLE_WALK_IFETCH_TIMEOUT = 2,
	MCE_LINK_ERROR_LOAD_TIMEOUT = 3,
	MCE_LINK_ERROR_STORE_TIMEOUT = 4,
	MCE_LINK_ERROR_PAGE_TABLE_WALK_LOAD_STORE_TIMEOUT = 5,
};

struct machine_check_event {
	enum MCE_Version version: 8;
	u8 in_use;
	enum MCE_Severity severity: 8;
	enum MCE_Initiator initiator: 8;
	enum MCE_ErrorType error_type: 8;
	enum MCE_ErrorClass error_class: 8;
	enum MCE_Disposition disposition: 8;
	bool sync_error;
	u16 cpu;
	u64 gpr3;
	u64 srr0;
	u64 srr1;
	union {
		struct {
			enum MCE_UeErrorType ue_error_type: 8;
			u8 effective_address_provided;
			u8 physical_address_provided;
			u8 ignore_event;
			u8 reserved_1[4];
			u64 effective_address;
			u64 physical_address;
			u8 reserved_2[8];
		} ue_error;
		struct {
			enum MCE_SlbErrorType slb_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} slb_error;
		struct {
			enum MCE_EratErrorType erat_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} erat_error;
		struct {
			enum MCE_TlbErrorType tlb_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} tlb_error;
		struct {
			enum MCE_UserErrorType user_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} user_error;
		struct {
			enum MCE_RaErrorType ra_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} ra_error;
		struct {
			enum MCE_LinkErrorType link_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} link_error;
	} u;
};

struct mce_info {
	int mce_nest_count;
	struct machine_check_event mce_event[10];
	int mce_queue_count;
	struct machine_check_event mce_event_queue[10];
	int mce_ue_count;
	struct machine_check_event mce_ue_event_queue[10];
};

struct mmiowb_state {
	u16 nesting_count;
	u16 mmiowb_pending;
};

struct dtl_entry;

struct task_struct;

struct rtas_args;

struct paca_struct {
	struct lppaca *lppaca_ptr;
	u16 paca_index;
	u16 lock_token;
	u64 kernel_toc;
	u64 kernelbase;
	u64 kernel_msr;
	void *emergency_sp;
	u64 data_offset;
	s16 hw_cpu_id;
	u8 cpu_start;
	u8 kexec_state;
	struct slb_shadow *slb_shadow_ptr;
	struct dtl_entry *dispatch_log;
	struct dtl_entry *dispatch_log_end;
	u64 dscr_default;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u64 exgen[10];
	u16 vmalloc_sllp;
	u8 slb_cache_ptr;
	u8 stab_rr;
	u32 slb_used_bitmap;
	u32 slb_kern_bitmap;
	u32 slb_cache[8];
	unsigned char mm_ctx_low_slices_psize[8];
	unsigned char mm_ctx_high_slices_psize[2048];
	struct task_struct *__current;
	u64 kstack;
	u64 saved_r1;
	u64 saved_msr;
	u64 exit_save_r1;
	u8 hsrr_valid;
	u8 srr_valid;
	u8 irq_soft_mask;
	u8 irq_happened;
	u8 irq_work_pending;
	u64 sprg_vdso;
	u64 tm_scratch;
	long unsigned int idle_state;
	union {
		struct {
			u8 thread_idle_state;
			u8 subcore_sibling_mask;
		};
		struct {		};
	};
	u64 exnmi[10];
	u64 exmc[10];
	void *nmi_emergency_sp;
	void *mc_emergency_sp;
	u16 in_nmi;
	u16 in_mce;
	u8 hmi_event_available;
	u8 hmi_p9_special_emu;
	u32 hmi_irqs;
	u8 ftrace_enabled;
	struct cpu_accounting_data accounting;
	u64 dtl_ridx;
	struct dtl_entry *dtl_curr;
	long: 64;
	long: 64;
	u64 exrfi[10];
	void *rfi_flush_fallback_area;
	u64 l1d_flush_size;
	struct rtas_args *rtas_args_reentrant;
	u8 *mce_data_buf;
	struct slb_entry *mce_faulty_slbs;
	u16 slb_save_cache_ptr;
	long unsigned int canary;
	struct mmiowb_state mmiowb_state;
	struct mce_info *mce_info;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct thread_info {
	int preempt_count;
	long unsigned int local_flags;
	long unsigned int *livepatch_sp;
	unsigned char slb_preload_nr;
	unsigned char slb_preload_tail;
	u32 slb_preload_esid[16];
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long unsigned int flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct refcount_struct {
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;

struct llist_node {
	struct llist_node *next;
};

struct __call_single_node {
	struct llist_node llist;
	union {
		unsigned int u_flags;
		atomic_t a_flags;
	};
	u16 src;
	u16 dst;
};

struct load_weight {
	long unsigned int weight;
	u32 inv_weight;
};

struct rb_node {
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct util_est {
	unsigned int enqueued;
	unsigned int ewma;
};

struct sched_avg {
	u64 last_update_time;
	u64 load_sum;
	u64 runnable_sum;
	u32 util_sum;
	u32 period_contrib;
	long unsigned int load_avg;
	long unsigned int runnable_avg;
	long unsigned int util_avg;
	struct util_est util_est;
	long unsigned int rh_reserved1;
	long unsigned int rh_reserved2;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct cfs_rq;

struct sched_entity {
	struct load_weight load;
	struct rb_node run_node;
	struct list_head group_node;
	unsigned int on_rq;
	u64 exec_start;
	u64 sum_exec_runtime;
	u64 vruntime;
	u64 prev_sum_exec_runtime;
	u64 nr_migrations;
	int depth;
	struct sched_entity *parent;
	struct cfs_rq *cfs_rq;
	struct cfs_rq *my_q;
	long unsigned int runnable_weight;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_avg avg;
	long unsigned int rh_reserved1;
	long unsigned int rh_reserved2;
	long unsigned int rh_reserved3;
	long unsigned int rh_reserved4;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct sched_rt_entity {
	struct list_head run_list;
	long unsigned int timeout;
	long unsigned int watchdog_stamp;
	unsigned int time_slice;
	short unsigned int on_rq;
	short unsigned int on_list;
	struct sched_rt_entity *back;
	long unsigned int rh_reserved1;
	long unsigned int rh_reserved2;
};

typedef s64 ktime_t;

struct timerqueue_node {
	struct rb_node node;
	ktime_t expires;
};

enum hrtimer_restart {
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART = 1,
};

struct hrtimer_clock_base;

struct hrtimer {
	struct timerqueue_node node;
	ktime_t _softexpires;
	enum hrtimer_restart (*function)(struct hrtimer *);
	struct hrtimer_clock_base *base;
	u8 state;
	u8 is_rel;
	u8 is_soft;
	u8 is_hard;
	long unsigned int rh_reserved1;
	long unsigned int rh_reserved2;
};

struct sched_dl_entity {
	struct rb_node rb_node;
	u64 dl_runtime;
	u64 dl_deadline;
	u64 dl_period;
	u64 dl_bw;
	u64 dl_density;
	s64 runtime;
	u64 deadline;
	unsigned int flags;
	unsigned int dl_throttled: 1;
	unsigned int dl_yielded: 1;
	unsigned int dl_non_contending: 1;
	unsigned int dl_overrun: 1;
	struct hrtimer dl_timer;
	struct hrtimer inactive_timer;
	struct sched_dl_entity *pi_se;
	long unsigned int rh_reserved1;
	long unsigned int rh_reserved2;
	long unsigned int rh_reserved3;
	long unsigned int rh_reserved4;
};

struct sched_statistics {
	u64 wait_start;
	u64 wait_max;
	u64 wait_count;
	u64 wait_sum;
	u64 iowait_count;
	u64 iowait_sum;
	u64 sleep_start;
	u64 sleep_max;
	s64 sum_sleep_runtime;
	u64 block_start;
	u64 block_max;
	s64 sum_block_runtime;
	u64 exec_max;
	u64 slice_max;
	u64 nr_migrations_cold;
	u64 nr_failed_migrations_affine;
	u64 nr_failed_migrations_running;
	u64 nr_failed_migrations_hot;
	u64 nr_forced_migrations;
	u64 nr_wakeups;
	u64 nr_wakeups_sync;
	u64 nr_wakeups_migrate;
	u64 nr_wakeups_local;
	u64 nr_wakeups_remote;
	u64 nr_wakeups_affine;
	u64 nr_wakeups_affine_attempts;
	u64 nr_wakeups_passive;
	u64 nr_wakeups_idle;
	u64 core_forceidle_sum;
	long: 64;
	long: 64;
	long: 64;
};

struct cpumask {
	long unsigned int bits[32];
};

typedef struct cpumask cpumask_t;

union rcu_special {
	struct {
		u8 blocked;
		u8 need_qs;
		u8 exp_hint;
		u8 need_mb;
	} b;
	u32 s;
};

struct sched_info {
	long unsigned int pcount;
	long long unsigned int run_delay;
	long long unsigned int last_arrival;
	long long unsigned int last_queued;
};

struct plist_node {
	int prio;
	struct list_head prio_list;
	struct list_head node_list;
};

struct vmacache {
	u64 seqnum;
	struct vm_area_struct *vmas[4];
};

struct task_rss_stat {
	int events;
	int count[4];
};

struct prev_cputime {
	u64 utime;
	u64 stime;
	raw_spinlock_t lock;
};

struct seqcount {
	unsigned int sequence;
};

typedef struct seqcount seqcount_t;

enum vtime_state {
	VTIME_INACTIVE = 0,
	VTIME_IDLE = 1,
	VTIME_SYS = 2,
	VTIME_USER = 3,
	VTIME_GUEST = 4,
};

struct vtime {
	seqcount_t seqcount;
	long long unsigned int starttime;
	enum vtime_state state;
	unsigned int cpu;
	u64 utime;
	u64 stime;
	u64 gtime;
};

struct rb_root {
	struct rb_node *rb_node;
};

struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};

struct timerqueue_head {
	struct rb_root_cached rb_root;
};

struct posix_cputimer_base {
	u64 nextevt;
	struct timerqueue_head tqhead;
};

struct posix_cputimers {
	struct posix_cputimer_base bases[3];
	unsigned int timers_active;
	unsigned int expiry_active;
};

struct sem_undo_list;

struct sysv_sem {
	struct sem_undo_list *undo_list;
};

struct sysv_shm {
	struct list_head shm_clist;
};

typedef struct {
	long unsigned int sig[1];
} sigset_t;

struct sigpending {
	struct list_head list;
	sigset_t signal;
};

typedef struct {
	uid_t val;
} kuid_t;

struct seccomp_filter;

struct seccomp {
	int mode;
	atomic_t filter_count;
	struct seccomp_filter *filter;
};

struct syscall_user_dispatch {};

struct wake_q_node {
	struct wake_q_node *next;
};

struct task_io_accounting {
	u64 rchar;
	u64 wchar;
	u64 syscr;
	u64 syscw;
	u64 read_bytes;
	u64 write_bytes;
	u64 cancelled_write_bytes;
};

typedef struct {
	long unsigned int bits[4];
} nodemask_t;

struct seqcount_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_spinlock seqcount_spinlock_t;

struct optimistic_spin_queue {
	atomic_t tail;
};

struct mutex {