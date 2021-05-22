
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

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

typedef u64 sector_t;

typedef u64 blkcnt_t;

typedef unsigned int gfp_t;

typedef unsigned int fmode_t;

typedef u64 phys_addr_t;

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

struct kernel_symbol {
	int value_offset;
	int name_offset;
	int namespace_offset;
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

struct io_uring_cmd;

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
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
};

struct static_call_site {
	s32 addr;
	s32 key;
};

struct static_call_mod;

struct static_call_key {
	void *func;
	union {
		long unsigned int type;
		struct static_call_mod *mods;
		struct static_call_site *sites;
	};
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

struct thread_info {
	long unsigned int flags;
	long unsigned int syscall_work;
	u32 status;
	u32 cpu;
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
	struct sched_avg avg;
};

struct sched_rt_entity {
	struct list_head run_list;
	long unsigned int timeout;
	long unsigned int watchdog_stamp;
	unsigned int time_slice;
	short unsigned int on_rq;
	short unsigned int on_list;
	struct sched_rt_entity *back;
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
};

struct uclamp_se {
	unsigned int value: 11;
	unsigned int bucket_id: 3;
	unsigned int active: 1;
	unsigned int user_defined: 1;
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
	long unsigned int bits[128];
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

struct posix_cputimers_work {
	struct callback_head work;
	unsigned int scheduled;
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

struct syscall_user_dispatch {
	char *selector;
	long unsigned int offset;
	long unsigned int len;
	bool on_dispatch;
};

struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
};

typedef struct spinlock spinlock_t;

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
	long unsigned int bits[16];
} nodemask_t;

struct seqcount {
	unsigned int sequence;
};

typedef struct seqcount seqcount_t;

struct seqcount_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_spinlock seqcount_spinlock_t;

typedef atomic64_t atomic_long_t;

struct optimistic_spin_queue {
	atomic_t tail;
};

struct mutex {
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct optimistic_spin_queue osq;
	struct list_head wait_list;
};

struct arch_tlbflush_unmap_batch {
	struct cpumask cpumask;
};

struct tlbflush_unmap_batch {
	struct arch_tlbflush_unmap_batch arch;
	bool flush_required;
	bool writable;
};

struct page_frag {
	struct page *page;
	__u32 offset;
	__u32 size;
};

struct kmap_ctrl {};

struct timer_list {
	struct hlist_node entry;
	long unsigned int expires;
	void (*function)(struct timer_list *);
	u32 flags;
};

struct llist_head {
	struct llist_node *first;
};

struct desc_struct {
	u16 limit0;
	u16 base0;
	u16 base1: 8;
	u16 type: 4;
	u16 s: 1;
	u16 dpl: 2;
	u16 p: 1;
	u16 limit1: 4;
	u16 avl: 1;
	u16 l: 1;
	u16 d: 1;
	u16 g: 1;
	u16 base2: 8;
};

struct fpu_state_perm {
	u64 __state_perm;
	unsigned int __state_size;
	unsigned int __user_state_size;
};

struct fregs_state {
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u32 status;
};

struct fxregs_state {
	u16 cwd;
	u16 swd;
	u16 twd;
	u16 fop;
	union {
		struct {
			u64 rip;
			u64 rdp;
		};
		struct {
			u32 fip;
			u32 fcs;
			u32 foo;
			u32 fos;
		};
	};
	u32 mxcsr;
	u32 mxcsr_mask;
	u32 st_space[32];
	u32 xmm_space[64];
	u32 padding[12];
	union {
		u32 padding1[12];
		u32 sw_reserved[12];
	};
};

struct math_emu_info;

struct swregs_state {
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u8 ftop;
	u8 changed;
	u8 lookahead;
	u8 no_update;
	u8 rm;
	u8 alimit;
	struct math_emu_info *info;
	u32 entry_eip;
};

struct xstate_header {
	u64 xfeatures;
	u64 xcomp_bv;
	u64 reserved[6];
};

struct xregs_state {
	struct fxregs_state i387;
	struct xstate_header header;
	u8 extended_state_area[0];
};

union fpregs_state {
	struct fregs_state fsave;
	struct fxregs_state fxsave;
	struct swregs_state soft;
	struct xregs_state xsave;
	u8 __padding[4096];
};

struct fpstate {
	unsigned int size;
	unsigned int user_size;
	u64 xfeatures;
	u64 user_xfeatures;
	u64 xfd;
	unsigned int is_valloc: 1;
	unsigned int is_guest: 1;
	unsigned int is_confidential: 1;
	unsigned int in_use: 1;
	long: 60;
	long: 64;
	long: 64;
	long: 64;
	union fpregs_state regs;
};

struct fpu {
	unsigned int last_cpu;
	long unsigned int avx512_timestamp;
	struct fpstate *fpstate;
	struct fpstate *__task_fpstate;
	struct fpu_state_perm perm;
	struct fpu_state_perm guest_perm;
	struct fpstate __fpstate;
};

struct perf_event;

struct io_bitmap;

struct thread_struct {
	struct desc_struct tls_array[3];
	long unsigned int sp;
	short unsigned int es;
	short unsigned int ds;
	short unsigned int fsindex;
	short unsigned int gsindex;
	long unsigned int fsbase;
	long unsigned int gsbase;
	struct perf_event *ptrace_bps[4];
	long unsigned int virtual_dr6;
	long unsigned int ptrace_dr7;
	long unsigned int cr2;
	long unsigned int trap_nr;
	long unsigned int error_code;
	struct io_bitmap *io_bitmap;
	long unsigned int iopl_emul;
	unsigned int iopl_warn: 1;
	unsigned int sig_on_uaccess_err: 1;
	u32 pkru;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct fpu fpu;
};

struct sched_class;

struct task_group;

struct rcu_node;

struct mm_struct;

struct pid;

struct completion;

struct cred;

struct key;

struct nameidata;

struct fs_struct;

struct files_struct;

struct io_uring_task;

struct nsproxy;

struct signal_struct;

struct sighand_struct;

struct audit_context;

struct rt_mutex_waiter;

struct bio_list;

struct blk_plug;

struct reclaim_state;

struct backing_dev_info;

struct io_context;

struct capture_control;

struct kernel_siginfo;

typedef struct kernel_siginfo kernel_siginfo_t;

struct css_set;

struct robust_list_head;

struct compat_robust_list_head;

struct futex_pi_state;

struct perf_event_context;

struct mempolicy;

struct numa_group;

struct rseq;

struct task_delay_info;

struct ftrace_ret_stack;

struct mem_cgroup;

struct request_queue;

struct uprobe_task;

struct vm_struct;

struct bpf_local_storage;

struct bpf_run_ctx;

struct task_struct {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	struct rb_node core_node;
	long unsigned int core_cookie;
	unsigned int core_occupation;
	struct task_group *sched_task_group;
	struct uclamp_se uclamp_req[2];
	struct uclamp_se uclamp[2];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_statistics stats;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	bool trc_reader_checked;
	struct list_head trc_holdout_list;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct *mm;
	struct mm_struct *active_mm;
	struct vmacache vmacache;
	struct task_rss_stat rss_stat;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	unsigned int sched_psi_wake_requeue: 1;
	int: 28;
	unsigned int sched_remote_wakeup: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int in_user_fault: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_eventfd_signal: 1;
	unsigned int pasid_activated: 1;
	unsigned int reported_split_lock: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct *real_parent;
	struct task_struct *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	struct posix_cputimers_work posix_cputimers_work;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	long unsigned int last_switch_count;
	long unsigned int last_switch_time;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy *nsproxy;
	struct signal_struct *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	void *journal_info;
	struct bio_list *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info *backing_dev_info;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set *cgroups;
	struct list_head cg_list;
	u32 closid;
	u32 rmid;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context *perf_event_ctxp[2];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	long unsigned int preempt_disable_ip;
	struct mempolicy *mempolicy;
	short int il_prev;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	struct tlbflush_unmap_batch tlb_ubc;
	union {
		refcount_t rcu_users;
		struct callback_head rcu;
	};
	struct pipe_inode_info *splice_pipe;
	struct page_frag task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace;
	long unsigned int trace_recursion;
	struct mem_cgroup *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup *active_memcg;
	struct request_queue *throttle_queue;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	struct kmap_ctrl kmap_ctrl;
	int pagefault_disabled;
	struct task_struct *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct *stack_vm_area;
	refcount_t stack_refcount;
	int patch_state;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	void *mce_vaddr;
	__u64 mce_kflags;
	u64 mce_addr;
	__u64 mce_ripv: 1;
	__u64 mce_whole_page: 1;
	__u64 __mce_reserved: 62;
	struct callback_head mce_kill_me;
	int mce_count;
	struct llist_head kretprobe_instances;
	struct llist_head rethooks;
	struct callback_head l1d_flush_kill;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct thread_struct thread;
};

struct screen_info {
	__u8 orig_x;
	__u8 orig_y;
	__u16 ext_mem_k;
	__u16 orig_video_page;
	__u8 orig_video_mode;
	__u8 orig_video_cols;
	__u8 flags;
	__u8 unused2;
	__u16 orig_video_ega_bx;
	__u16 unused3;
	__u8 orig_video_lines;
	__u8 orig_video_isVGA;
	__u16 orig_video_points;
	__u16 lfb_width;
	__u16 lfb_height;
	__u16 lfb_depth;
	__u32 lfb_base;
	__u32 lfb_size;
	__u16 cl_magic;
	__u16 cl_offset;
	__u16 lfb_linelength;
	__u8 red_size;
	__u8 red_pos;
	__u8 green_size;
	__u8 green_pos;
	__u8 blue_size;
	__u8 blue_pos;
	__u8 rsvd_size;
	__u8 rsvd_pos;
	__u16 vesapm_seg;
	__u16 vesapm_off;
	__u16 pages;
	__u16 vesa_attributes;
	__u32 capabilities;
	__u32 ext_lfb_base;
	__u8 _reserved[2];
} __attribute__((packed));

struct apm_bios_info {
	__u16 version;
	__u16 cseg;
	__u32 offset;
	__u16 cseg_16;
	__u16 dseg;
	__u16 flags;
	__u16 cseg_len;
	__u16 cseg_16_len;
	__u16 dseg_len;
};

struct edd_device_params {
	__u16 length;
	__u16 info_flags;
	__u32 num_default_cylinders;
	__u32 num_default_heads;
	__u32 sectors_per_track;
	__u64 number_of_sectors;
	__u16 bytes_per_sector;
	__u32 dpte_ptr;
	__u16 key;
	__u8 device_path_info_length;
	__u8 reserved2;
	__u16 reserved3;
	__u8 host_bus_type[4];
	__u8 interface_type[8];
	union {
		struct {
			__u16 base_address;
			__u16 reserved1;
			__u32 reserved2;
		} isa;
		struct {
			__u8 bus;
			__u8 slot;
			__u8 function;
			__u8 channel;
			__u32 reserved;
		} pci;
		struct {
			__u64 reserved;
		} ibnd;
		struct {
			__u64 reserved;
		} xprs;
		struct {
			__u64 reserved;
		} htpt;
		struct {
			__u64 reserved;
		} unknown;
	} interface_path;
	union {
		struct {
			__u8 device;
			__u8 reserved1;
			__u16 reserved2;
			__u32 reserved3;
			__u64 reserved4;
		} ata;
		struct {
			__u8 device;
			__u8 lun;
			__u8 reserved1;
			__u8 reserved2;
			__u32 reserved3;
			__u64 reserved4;
		} atapi;
		struct {
			__u16 id;
			__u64 lun;
			__u16 reserved1;
			__u32 reserved2;
		} __attribute__((packed)) scsi;
		struct {
			__u64 serial_number;
			__u64 reserved;
		} usb;
		struct {
			__u64 eui;
			__u64 reserved;
		} i1394;
		struct {
			__u64 wwid;
			__u64 lun;
		} fibre;
		struct {
			__u64 identity_tag;
			__u64 reserved;
		} i2o;
		struct {
			__u32 array_number;
			__u32 reserved1;
			__u64 reserved2;
		} raid;
		struct {
			__u8 device;
			__u8 reserved1;
			__u16 reserved2;
			__u32 reserved3;
			__u64 reserved4;
		} sata;
		struct {
			__u64 reserved1;
			__u64 reserved2;
		} unknown;
	} device_path;
	__u8 reserved4;
	__u8 checksum;
} __attribute__((packed));

struct edd_info {
	__u8 device;
	__u8 version;
	__u16 interface_support;
	__u16 legacy_max_cylinder;
	__u8 legacy_max_head;
	__u8 legacy_sectors_per_track;
	struct edd_device_params params;
} __attribute__((packed));

struct ist_info {
	__u32 signature;
	__u32 command;
	__u32 event;
	__u32 perf_level;
};

struct edid_info {
	unsigned char dummy[128];
};

struct setup_header {
	__u8 setup_sects;
	__u16 root_flags;
	__u32 syssize;
	__u16 ram_size;
	__u16 vid_mode;
	__u16 root_dev;
	__u16 boot_flag;
	__u16 jump;
	__u32 header;
	__u16 version;
	__u32 realmode_swtch;
	__u16 start_sys_seg;
	__u16 kernel_version;
	__u8 type_of_loader;
	__u8 loadflags;
	__u16 setup_move_size;
	__u32 code32_start;
	__u32 ramdisk_image;
	__u32 ramdisk_size;
	__u32 bootsect_kludge;
	__u16 heap_end_ptr;
	__u8 ext_loader_ver;
	__u8 ext_loader_type;
	__u32 cmd_line_ptr;
	__u32 initrd_addr_max;
	__u32 kernel_alignment;
	__u8 relocatable_kernel;
	__u8 min_alignment;
	__u16 xloadflags;
	__u32 cmdline_size;
	__u32 hardware_subarch;
	__u64 hardware_subarch_data;
	__u32 payload_offset;
	__u32 payload_length;
	__u64 setup_data;
	__u64 pref_address;
	__u32 init_size;
	__u32 handover_offset;
	__u32 kernel_info_offset;
} __attribute__((packed));

struct sys_desc_table {
	__u16 length;
	__u8 table[14];
};

struct olpc_ofw_header {
	__u32 ofw_magic;
	__u32 ofw_version;
	__u32 cif_handler;
	__u32 irq_desc_table;
};

struct efi_info {
	__u32 efi_loader_signature;
	__u32 efi_systab;
	__u32 efi_memdesc_size;
	__u32 efi_memdesc_version;
	__u32 efi_memmap;
	__u32 efi_memmap_size;
	__u32 efi_systab_hi;
	__u32 efi_memmap_hi;
};

struct boot_e820_entry {
	__u64 addr;
	__u64 size;
	__u32 type;
} __attribute__((packed));

struct boot_params {
	struct screen_info screen_info;
	struct apm_bios_info apm_bios_info;
	__u8 _pad2[4];
	__u64 tboot_addr;
	struct ist_info ist_info;
	__u64 acpi_rsdp_addr;
	__u8 _pad3[8];
	__u8 hd0_info[16];
	__u8 hd1_info[16];
	struct sys_desc_table sys_desc_table;
	struct olpc_ofw_header olpc_ofw_header;
	__u32 ext_ramdisk_image;
	__u32 ext_ramdisk_size;
	__u32 ext_cmd_line_ptr;
	__u8 _pad4[112];
	__u32 cc_blob_address;
	struct edid_info edid_info;
	struct efi_info efi_info;
	__u32 alt_mem_k;
	__u32 scratch;
	__u8 e820_entries;
	__u8 eddbuf_entries;
	__u8 edd_mbr_sig_buf_entries;
	__u8 kbd_status;
	__u8 secure_boot;
	__u8 _pad5[2];
	__u8 sentinel;
	__u8 _pad6[1];
	struct setup_header hdr;
	__u8 _pad7[36];
	__u32 edd_mbr_sig_buffer[16];
	struct boot_e820_entry e820_table[128];
	__u8 _pad8[48];
	struct edd_info eddbuf[6];
	__u8 _pad9[276];
} __attribute__((packed));

enum x86_hardware_subarch {
	X86_SUBARCH_PC = 0,
	X86_SUBARCH_LGUEST = 1,
	X86_SUBARCH_XEN = 2,
	X86_SUBARCH_INTEL_MID = 3,
	X86_SUBARCH_CE4100 = 4,
	X86_NR_SUBARCHS = 5,
};

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

enum {
	GATE_INTERRUPT = 14,
	GATE_TRAP = 15,
	GATE_CALL = 12,
	GATE_TASK = 5,
};

struct idt_bits {
	u16 ist: 3;
	u16 zero: 5;
	u16 type: 5;
	u16 dpl: 2;
	u16 p: 1;
};

struct idt_data {
	unsigned int vector;
	unsigned int segment;
	struct idt_bits bits;
	const void *addr;
};

struct gate_struct {
	u16 offset_low;
	u16 segment;
	struct idt_bits bits;
	u16 offset_middle;
	u32 offset_high;
	u32 reserved;
};

typedef struct gate_struct gate_desc;

struct desc_ptr {
	short unsigned int size;
	long unsigned int address;
} __attribute__((packed));

typedef long unsigned int pteval_t;

typedef long unsigned int pmdval_t;

typedef long unsigned int pudval_t;

typedef long unsigned int p4dval_t;

typedef long unsigned int pgdval_t;

typedef long unsigned int pgprotval_t;

typedef struct {
	pteval_t pte;
} pte_t;

struct pgprot {
	pgprotval_t pgprot;
};

typedef struct pgprot pgprot_t;

typedef struct {
	pgdval_t pgd;
} pgd_t;

typedef struct {
	p4dval_t p4d;
} p4d_t;

typedef struct {
	pudval_t pud;
} pud_t;

typedef struct {
	pmdval_t pmd;
} pmd_t;

typedef struct page *pgtable_t;

struct address_space;

struct page_pool;

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

struct paravirt_callee_save {
	void *func;
};

struct pv_lazy_ops {
	void (*enter)();
	void (*leave)();
	void (*flush)();
};

struct pv_cpu_ops {
	void (*io_delay)();
	long unsigned int (*get_debugreg)(int);
	void (*set_debugreg)(int, long unsigned int);
	long unsigned int (*read_cr0)();
	void (*write_cr0)(long unsigned int);
	void (*write_cr4)(long unsigned int);
	void (*load_tr_desc)();
	void (*load_gdt)(const struct desc_ptr *);
	void (*load_idt)(const struct desc_ptr *);
	void (*set_ldt)(const void *, unsigned int);
	long unsigned int (*store_tr)();
	void (*load_tls)(struct thread_struct *, unsigned int);
	void (*load_gs_index)(unsigned int);
	void (*write_ldt_entry)(struct desc_struct *, int, const void *);
	void (*write_gdt_entry)(struct desc_struct *, int, const void *, int);
	void (*write_idt_entry)(gate_desc *, int, const gate_desc *);
	void (*alloc_ldt)(struct desc_struct *, unsigned int);
	void (*free_ldt)(struct desc_struct *, unsigned int);
	void (*load_sp0)(long unsigned int);
	void (*invalidate_io_bitmap)();
	void (*update_io_bitmap)();
	void (*wbinvd)();
	void (*cpuid)(unsigned int *, unsigned int *, unsigned int *, unsigned int *);
	u64 (*read_msr)(unsigned int);
	void (*write_msr)(unsigned int, unsigned int, unsigned int);
	u64 (*read_msr_safe)(unsigned int, int *);
	int (*write_msr_safe)(unsigned int, unsigned int, unsigned int);
	u64 (*read_pmc)(int);
	void (*start_context_switch)(struct task_struct *);
	void (*end_context_switch)(struct task_struct *);
};

struct pv_irq_ops {
	struct paravirt_callee_save save_fl;
	struct paravirt_callee_save irq_disable;
	struct paravirt_callee_save irq_enable;
	void (*safe_halt)();
	void (*halt)();
};

struct flush_tlb_info;

struct mmu_gather;

struct pv_mmu_ops {
	void (*flush_tlb_user)();
	void (*flush_tlb_kernel)();
	void (*flush_tlb_one_user)(long unsigned int);
	void (*flush_tlb_multi)(const struct cpumask *, const struct flush_tlb_info *);
	void (*tlb_remove_table)(struct mmu_gather *, void *);
	void (*exit_mmap)(struct mm_struct *);
	void (*notify_page_enc_status_changed)(long unsigned int, int, bool);
	struct paravirt_callee_save read_cr2;
	void (*write_cr2)(long unsigned int);
	long unsigned int (*read_cr3)();
	void (*write_cr3)(long unsigned int);
	void (*activate_mm)(struct mm_struct *, struct mm_struct *);
	void (*dup_mmap)(struct mm_struct *, struct mm_struct *);
	int (*pgd_alloc)(struct mm_struct *);
	void (*pgd_free)(struct mm_struct *, pgd_t *);
	void (*alloc_pte)(struct mm_struct *, long unsigned int);
	void (*alloc_pmd)(struct mm_struct *, long unsigned int);
	void (*alloc_pud)(struct mm_struct *, long unsigned int);
	void (*alloc_p4d)(struct mm_struct *, long unsigned int);
	void (*release_pte)(long unsigned int);
	void (*release_pmd)(long unsigned int);
	void (*release_pud)(long unsigned int);
	void (*release_p4d)(long unsigned int);
	void (*set_pte)(pte_t *, pte_t);
	void (*set_pmd)(pmd_t *, pmd_t);
	pte_t (*ptep_modify_prot_start)(struct vm_area_struct *, long unsigned int, pte_t *);
	void (*ptep_modify_prot_commit)(struct vm_area_struct *, long unsigned int, pte_t *, pte_t);
	struct paravirt_callee_save pte_val;
	struct paravirt_callee_save make_pte;
	struct paravirt_callee_save pgd_val;
	struct paravirt_callee_save make_pgd;
	void (*set_pud)(pud_t *, pud_t);
	struct paravirt_callee_save pmd_val;
	struct paravirt_callee_save make_pmd;
	struct paravirt_callee_save pud_val;
	struct paravirt_callee_save make_pud;
	void (*set_p4d)(p4d_t *, p4d_t);
	struct paravirt_callee_save p4d_val;
	struct paravirt_callee_save make_p4d;
	void (*set_pgd)(pgd_t *, pgd_t);
	struct pv_lazy_ops lazy_mode;
	void (*set_fixmap)(unsigned int, phys_addr_t, pgprot_t);
};

struct flush_tlb_info {
	struct mm_struct *mm;
	long unsigned int start;
	long unsigned int end;
	u64 new_tlb_gen;
	unsigned int initiating_cpu;
	u8 stride_shift;
	u8 freed_tables;
};

struct rw_semaphore {
	atomic_long_t count;
	atomic_long_t owner;
	struct optimistic_spin_queue osq;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
};

struct mm_rss_stat {
	atomic_long_t count[4];
};

struct ldt_struct;

struct vdso_image;

typedef struct {
	u64 ctx_id;
	atomic64_t tlb_gen;
	struct rw_semaphore ldt_usr_sem;
	struct ldt_struct *ldt;
	short unsigned int flags;
	struct mutex lock;
	void *vdso;
	const struct vdso_image *vdso_image;
	atomic_t perf_rdpmc_allowed;
	u16 pkey_allocation_map;
	s16 execute_only_pkey;
} mm_context_t;

struct xol_area;

struct uprobes_state {
	struct xol_area *xol_area;
};

struct work_struct;

typedef void (*work_func_t)(struct work_struct *);

struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
};

struct linux_binfmt;

struct kioctx_table;

struct user_namespace;

struct mmu_notifier_subscriptions;

struct mm_struct {
	struct {
		struct vm_area_struct *mmap;
		struct rb_root mm_rb;
		u64 vmacache_seqnum;
		long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int mmap_compat_base;
		long unsigned int mmap_compat_legacy_base;
		long unsigned int task_size;
		long unsigned int highest_vm_end;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[48];
		struct mm_rss_stat rss_stat;
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct *owner;
		struct user_namespace *user_ns;
		struct file *exe_file;
		struct mmu_notifier_subscriptions *notifier_subscriptions;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		u32 pasid;
		long unsigned int ksm_merging_pages;
	};
	long unsigned int cpu_bitmap[0];
};

struct userfaultfd_ctx;

struct vm_userfaultfd_ctx {
	struct userfaultfd_ctx *ctx;
};

struct anon_vma_name;

struct anon_vma;

struct vm_operations_struct;

struct vm_area_struct {
	long unsigned int vm_start;
	long unsigned int vm_end;
	struct vm_area_struct *vm_next;
	struct vm_area_struct *vm_prev;
	struct rb_node vm_rb;
	long unsigned int rb_subtree_gap;
	struct mm_struct *vm_mm;
	pgprot_t vm_page_prot;
	long unsigned int vm_flags;
	union {
		struct {
			struct rb_node rb;
			long unsigned int rb_subtree_last;
		} shared;
		struct anon_vma_name *anon_name;
	};
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct *vm_ops;
	long unsigned int vm_pgoff;
	struct file *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct pv_lock_ops {
	void (*queued_spin_lock_slowpath)(struct qspinlock *, u32);
	struct paravirt_callee_save queued_spin_unlock;
	void (*wait)(u8 *, u8);
	void (*kick)(int);
	struct paravirt_callee_save vcpu_is_preempted;
};

struct paravirt_patch_template {
	struct pv_cpu_ops cpu;
	struct pv_irq_ops irq;
	struct pv_mmu_ops mmu;
	struct pv_lock_ops lock;
};

struct math_emu_info {
	long int ___orig_eip;
	struct pt_regs *regs;
};

struct tracepoint_func {
	void *func;
	void *data;
	int prio;
};

struct tracepoint {
	const char *name;
	struct static_key key;
	struct static_call_key *static_call_key;
	void *static_call_tramp;
	void *iterator;
	int (*regfunc)();
	void (*unregfunc)();
	struct tracepoint_func *funcs;
};

typedef const int tracepoint_ptr_t;

struct bpf_raw_event_map {
	struct tracepoint *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long: 64;
};

enum {
	UNAME26 = 131072,
	ADDR_NO_RANDOMIZE = 262144,
	FDPIC_FUNCPTRS = 524288,
	MMAP_PAGE_ZERO = 1048576,
	ADDR_COMPAT_LAYOUT = 2097152,
	READ_IMPLIES_EXEC = 4194304,
	ADDR_LIMIT_32BIT = 8388608,
	SHORT_INODE = 16777216,
	WHOLE_SECONDS = 33554432,
	STICKY_TIMEOUTS = 67108864,
	ADDR_LIMIT_3GB = 134217728,
};

enum tlb_infos {
	ENTRIES = 0,
	NR_INFO = 1,
};

enum pcpu_fc {
	PCPU_FC_AUTO = 0,
	PCPU_FC_EMBED = 1,
	PCPU_FC_PAGE = 2,
	PCPU_FC_NR = 3,
};

typedef struct {
	arch_rwlock_t raw_lock;
} rwlock_t;

struct vm_struct {
	struct vm_struct *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

struct wait_queue_head {
	spinlock_t lock;
	struct list_head head;
};

typedef struct wait_queue_head wait_queue_head_t;

struct kobject;

struct attribute;

struct bin_attribute;

struct attribute_group {
	const char *name;
	umode_t (*is_visible)(struct kobject *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject *, struct bin_attribute *, int);
	struct attribute **attrs;
	struct bin_attribute **bin_attrs;
};

struct seqcount_raw_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_raw_spinlock seqcount_raw_spinlock_t;

typedef struct {
	seqcount_spinlock_t seqcount;
	spinlock_t lock;
} seqlock_t;

enum node_states {
	N_POSSIBLE = 0,
	N_ONLINE = 1,
	N_NORMAL_MEMORY = 2,
	N_HIGH_MEMORY = 2,
	N_MEMORY = 3,
	N_CPU = 4,
	N_GENERIC_INITIATOR = 5,
	NR_NODE_STATES = 6,
};

enum {
	MM_FILEPAGES = 0,
	MM_ANONPAGES = 1,
	MM_SWAPENTS = 2,
	MM_SHMEMPAGES = 3,
	NR_MM_COUNTERS = 4,
};

struct kref {
	refcount_t refcount;
};

struct swait_queue_head {
	raw_spinlock_t lock;
	struct list_head task_list;
};

struct completion {
	unsigned int done;
	struct swait_queue_head wait;
};

struct workqueue_struct;

struct delayed_work {
	struct work_struct work;
	struct timer_list timer;
	struct workqueue_struct *wq;
	int cpu;
};

struct rcu_segcblist {
	struct callback_head *head;
	struct callback_head **tails[4];
	long unsigned int gp_seq[4];
	long int len;
	long int seglen[4];
	u8 flags;
};

struct srcu_node;

struct srcu_struct;

struct srcu_data {
	long unsigned int srcu_lock_count[2];
	long unsigned int srcu_unlock_count[2];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t lock;
	struct rcu_segcblist srcu_cblist;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	bool srcu_cblist_invoking;
	struct timer_list delay_work;
	struct work_struct work;
	struct callback_head srcu_barrier_head;
	struct srcu_node *mynode;
	long unsigned int grpmask;
	int cpu;
	struct srcu_struct *ssp;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct srcu_node {
	spinlock_t lock;
	long unsigned int srcu_have_cbs[4];
	long unsigned int srcu_data_have_cbs[4];
	long unsigned int srcu_gp_seq_needed_exp;
	struct srcu_node *srcu_parent;
	int grplo;
	int grphi;
};

struct srcu_struct {
	struct srcu_node *node;
	struct srcu_node *level[4];
	int srcu_size_state;
	struct mutex srcu_cb_mutex;
	spinlock_t lock;
	struct mutex srcu_gp_mutex;
	unsigned int srcu_idx;
	long unsigned int srcu_gp_seq;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	long unsigned int srcu_gp_start;
	long unsigned int srcu_last_gp_end;
	long unsigned int srcu_size_jiffies;
	long unsigned int srcu_n_lock_retries;
	long unsigned int srcu_n_exp_nodelay;
	struct srcu_data *sda;
	bool sda_is_static;
	long unsigned int srcu_barrier_seq;
	struct mutex srcu_barrier_mutex;
	struct completion srcu_barrier_completion;
	atomic_t srcu_barrier_cpu_cnt;
	long unsigned int reschedule_jiffies;
	long unsigned int reschedule_count;
	struct delayed_work work;
	struct lockdep_map dep_map;
};

struct arch_uprobe_task {
	long unsigned int saved_scratch_register;
	unsigned int saved_trap_nr;
	unsigned int saved_tf;
};

enum uprobe_task_state {
	UTASK_RUNNING = 0,
	UTASK_SSTEP = 1,
	UTASK_SSTEP_ACK = 2,
	UTASK_SSTEP_TRAPPED = 3,
};

struct uprobe;

struct return_instance;

struct uprobe_task {
	enum uprobe_task_state state;
	union {
		struct {
			struct arch_uprobe_task autask;
			long unsigned int vaddr;
		};
		struct {
			struct callback_head dup_xol_work;
			long unsigned int dup_xol_addr;
		};
	};
	struct uprobe *active_uprobe;
	long unsigned int xol_vaddr;
	struct return_instance *return_instances;
	unsigned int depth;
};

struct return_instance {
	struct uprobe *uprobe;
	long unsigned int func;
	long unsigned int stack;
	long unsigned int orig_ret_vaddr;
	bool chained;
	struct return_instance *next;
};

struct vdso_image {
	void *data;
	long unsigned int size;
	long unsigned int alt;
	long unsigned int alt_len;
	long unsigned int extable_base;
	long unsigned int extable_len;
	const void *extable;
	long int sym_vvar_start;
	long int sym_vvar_page;
	long int sym_pvclock_page;
	long int sym_hvclock_page;
	long int sym_timens_page;
	long int sym_VDSO32_NOTE_MASK;
	long int sym___kernel_sigreturn;
	long int sym___kernel_rt_sigreturn;
	long int sym___kernel_vsyscall;
	long int sym_int80_landing_pad;
	long int sym_vdso32_sigreturn_landing_pad;
	long int sym_vdso32_rt_sigreturn_landing_pad;
};

struct xarray {
	spinlock_t xa_lock;
	gfp_t xa_flags;
	void *xa_head;
};

typedef u32 errseq_t;

struct address_space_operations;

struct address_space {
	struct inode *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	struct rw_semaphore i_mmap_rwsem;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t private_lock;
	struct list_head private_list;
	void *private_data;
};

struct folio {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space *mapping;
			long unsigned int index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page page;
	};
};

struct vfsmount;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

enum pid_type {
	PIDTYPE_PID = 0,
	PIDTYPE_TGID = 1,
	PIDTYPE_PGID = 2,
	PIDTYPE_SID = 3,
	PIDTYPE_MAX = 4,
};

struct fown_struct {
	rwlock_t lock;
	struct pid *pid;
	enum pid_type pid_type;
	kuid_t uid;
	kuid_t euid;
	int signum;
};

struct file_ra_state {
	long unsigned int start;
	unsigned int size;
	unsigned int async_size;
	unsigned int ra_pages;
	unsigned int mmap_miss;
	loff_t prev_pos;
};

struct file {
	union {
		struct llist_node fu_llist;
		struct callback_head fu_rcuhead;
	} f_u;
	struct path f_path;
	struct inode *f_inode;
	const struct file_operations *f_op;
	spinlock_t f_lock;
	atomic_long_t f_count;
	unsigned int f_flags;
	fmode_t f_mode;
	struct mutex f_pos_lock;
	loff_t f_pos;
	struct fown_struct f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	u64 f_version;
	void *f_security;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct anon_vma_name {
	struct kref kref;
	char name[0];
};

typedef unsigned int vm_fault_t;

enum page_entry_size {
	PE_SIZE_PTE = 0,
	PE_SIZE_PMD = 1,
	PE_SIZE_PUD = 2,
};

struct vm_fault;

struct vm_operations_struct {
	void (*open)(struct vm_area_struct *);
	void (*close)(struct vm_area_struct *);
	int (*may_split)(struct vm_area_struct *, long unsigned int);
	int (*mremap)(struct vm_area_struct *);
	int (*mprotect)(struct vm_area_struct *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault *);
	vm_fault_t (*huge_fault)(struct vm_fault *, enum page_entry_size);
	vm_fault_t (*map_pages)(struct vm_fault *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct *);
	vm_fault_t (*page_mkwrite)(struct vm_fault *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault *);
	int (*access)(struct vm_area_struct *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct *);
	int (*set_policy)(struct vm_area_struct *, struct mempolicy *);
	struct mempolicy * (*get_policy)(struct vm_area_struct *, long unsigned int);
	struct page * (*find_special_page)(struct vm_area_struct *, long unsigned int);
};

enum fault_flag {
	FAULT_FLAG_WRITE = 1,
	FAULT_FLAG_MKWRITE = 2,
	FAULT_FLAG_ALLOW_RETRY = 4,
	FAULT_FLAG_RETRY_NOWAIT = 8,
	FAULT_FLAG_KILLABLE = 16,
	FAULT_FLAG_TRIED = 32,
	FAULT_FLAG_USER = 64,
	FAULT_FLAG_REMOTE = 128,
	FAULT_FLAG_INSTRUCTION = 256,
	FAULT_FLAG_INTERRUPTIBLE = 512,
	FAULT_FLAG_UNSHARE = 1024,
	FAULT_FLAG_ORIG_PTE_VALID = 2048,
};

struct vm_fault {
	const struct {
		struct vm_area_struct *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page *cow_page;
	struct page *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t prealloc_pte;
};

enum migratetype {
	MIGRATE_UNMOVABLE = 0,
	MIGRATE_MOVABLE = 1,
	MIGRATE_RECLAIMABLE = 2,
	MIGRATE_PCPTYPES = 3,
	MIGRATE_HIGHATOMIC = 3,
	MIGRATE_ISOLATE = 4,
	MIGRATE_TYPES = 5,
};

enum numa_stat_item {
	NUMA_HIT = 0,
	NUMA_MISS = 1,
	NUMA_FOREIGN = 2,
	NUMA_INTERLEAVE_HIT = 3,
	NUMA_LOCAL = 4,
	NUMA_OTHER = 5,
	NR_VM_NUMA_EVENT_ITEMS = 6,
};

enum zone_stat_item {
	NR_FREE_PAGES = 0,
	NR_ZONE_LRU_BASE = 1,
	NR_ZONE_INACTIVE_ANON = 1,
	NR_ZONE_ACTIVE_ANON = 2,
	NR_ZONE_INACTIVE_FILE = 3,
	NR_ZONE_ACTIVE_FILE = 4,
	NR_ZONE_UNEVICTABLE = 5,
	NR_ZONE_WRITE_PENDING = 6,
	NR_MLOCK = 7,
	NR_BOUNCE = 8,
	NR_ZSPAGES = 9,
	NR_FREE_CMA_PAGES = 10,
	NR_VM_ZONE_STAT_ITEMS = 11,
};

enum node_stat_item {
	NR_LRU_BASE = 0,
	NR_INACTIVE_ANON = 0,
	NR_ACTIVE_ANON = 1,
	NR_INACTIVE_FILE = 2,
	NR_ACTIVE_FILE = 3,
	NR_UNEVICTABLE = 4,
	NR_SLAB_RECLAIMABLE_B = 5,
	NR_SLAB_UNRECLAIMABLE_B = 6,
	NR_ISOLATED_ANON = 7,
	NR_ISOLATED_FILE = 8,
	WORKINGSET_NODES = 9,
	WORKINGSET_REFAULT_BASE = 10,
	WORKINGSET_REFAULT_ANON = 10,
	WORKINGSET_REFAULT_FILE = 11,
	WORKINGSET_ACTIVATE_BASE = 12,
	WORKINGSET_ACTIVATE_ANON = 12,
	WORKINGSET_ACTIVATE_FILE = 13,
	WORKINGSET_RESTORE_BASE = 14,
	WORKINGSET_RESTORE_ANON = 14,
	WORKINGSET_RESTORE_FILE = 15,
	WORKINGSET_NODERECLAIM = 16,
	NR_ANON_MAPPED = 17,
	NR_FILE_MAPPED = 18,
	NR_FILE_PAGES = 19,
	NR_FILE_DIRTY = 20,
	NR_WRITEBACK = 21,
	NR_WRITEBACK_TEMP = 22,
	NR_SHMEM = 23,
	NR_SHMEM_THPS = 24,
	NR_SHMEM_PMDMAPPED = 25,
	NR_FILE_THPS = 26,
	NR_FILE_PMDMAPPED = 27,
	NR_ANON_THPS = 28,
	NR_VMSCAN_WRITE = 29,
	NR_VMSCAN_IMMEDIATE = 30,
	NR_DIRTIED = 31,
	NR_WRITTEN = 32,
	NR_THROTTLED_WRITTEN = 33,
	NR_KERNEL_MISC_RECLAIMABLE = 34,
	NR_FOLL_PIN_ACQUIRED = 35,
	NR_FOLL_PIN_RELEASED = 36,
	NR_KERNEL_STACK_KB = 37,
	NR_PAGETABLE = 38,
	NR_SWAPCACHE = 39,
	PGPROMOTE_SUCCESS = 40,
	NR_VM_NODE_STAT_ITEMS = 41,
};

enum lru_list {
	LRU_INACTIVE_ANON = 0,
	LRU_ACTIVE_ANON = 1,
	LRU_INACTIVE_FILE = 2,
	LRU_ACTIVE_FILE = 3,
	LRU_UNEVICTABLE = 4,
	NR_LRU_LISTS = 5,
};

enum vmscan_throttle_state {
	VMSCAN_THROTTLE_WRITEBACK = 0,
	VMSCAN_THROTTLE_ISOLATED = 1,
	VMSCAN_THROTTLE_NOPROGRESS = 2,
	VMSCAN_THROTTLE_CONGESTED = 3,
	NR_VMSCAN_THROTTLE = 4,
};

typedef unsigned int isolate_mode_t;

enum zone_watermarks {
	WMARK_MIN = 0,
	WMARK_LOW = 1,
	WMARK_HIGH = 2,
	WMARK_PROMO = 3,
	NR_WMARK = 4,
};

enum {
	ZONELIST_FALLBACK = 0,
	ZONELIST_NOFALLBACK = 1,
	MAX_ZONELISTS = 2,
};

struct shrink_control {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup *memcg;
};

struct shrinker {
	long unsigned int (*count_objects)(struct shrinker *, struct shrink_control *);
	long unsigned int (*scan_objects)(struct shrinker *, struct shrink_control *);
	long int batch;
	int seeks;
	unsigned int flags;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};

struct rlimit {
	__kernel_ulong_t rlim_cur;
	__kernel_ulong_t rlim_max;
};

struct pid_namespace;

struct upid {
	int nr;
	struct pid_namespace *ns;
};

struct pid {
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	struct hlist_head tasks[4];
	struct hlist_head inodes;
	wait_queue_head_t wait_pidfd;
	struct callback_head rcu;
	struct upid numbers[1];
};

typedef struct {
	gid_t val;
} kgid_t;

struct hrtimer_cpu_base;

struct hrtimer_clock_base {
	struct hrtimer_cpu_base *cpu_base;
	unsigned int index;
	clockid_t clockid;
	seqcount_raw_spinlock_t seq;
	struct hrtimer *running;
	struct timerqueue_head active;
	ktime_t (*get_time)();
	ktime_t offset;
};

struct hrtimer_cpu_base {
	raw_spinlock_t lock;
	unsigned int cpu;
	unsigned int active_bases;
	unsigned int clock_was_set_seq;
	unsigned int hres_active: 1;
	unsigned int in_hrtirq: 1;
	unsigned int hang_detected: 1;
	unsigned int softirq_activated: 1;
	unsigned int nr_events;
	short unsigned int nr_retries;
	short unsigned int nr_hangs;
	unsigned int max_hang_time;
	ktime_t expires_next;
	struct hrtimer *next_timer;
	ktime_t softirq_expires_next;
	struct hrtimer *softirq_next_timer;
	struct hrtimer_clock_base clock_base[8];
};

enum hrtimer_base_type {
	HRTIMER_BASE_MONOTONIC = 0,
	HRTIMER_BASE_REALTIME = 1,
	HRTIMER_BASE_BOOTTIME = 2,
	HRTIMER_BASE_TAI = 3,
	HRTIMER_BASE_MONOTONIC_SOFT = 4,
	HRTIMER_BASE_REALTIME_SOFT = 5,
	HRTIMER_BASE_BOOTTIME_SOFT = 6,
	HRTIMER_BASE_TAI_SOFT = 7,
	HRTIMER_MAX_CLOCK_BASES = 8,
};

typedef void __signalfn_t(int);

typedef __signalfn_t *__sighandler_t;

typedef void __restorefn_t();

typedef __restorefn_t *__sigrestore_t;

union sigval {
	int sival_int;
	void *sival_ptr;
};

typedef union sigval sigval_t;

union __sifields {
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
	} _kill;
	struct {
		__kernel_timer_t _tid;
		int _overrun;
		sigval_t _sigval;
		int _sys_private;
	} _timer;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		sigval_t _sigval;
	} _rt;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		int _status;
		__kernel_clock_t _utime;
		__kernel_clock_t _stime;
	} _sigchld;
	struct {
		void *_addr;
		union {
			int _trapno;
			short int _addr_lsb;
			struct {
				char _dummy_bnd[8];
				void *_lower;
				void *_upper;
			} _addr_bnd;
			struct {
				char _dummy_pkey[8];
				__u32 _pkey;
			} _addr_pkey;
			struct {
				long unsigned int _data;
				__u32 _type;
				__u32 _flags;
			} _perf;
		};
	} _sigfault;
	struct {
		long int _band;
		int _fd;
	} _sigpoll;
	struct {
		void *_call_addr;
		int _syscall;
		unsigned int _arch;
	} _sigsys;
};

struct kernel_siginfo {
	struct {
		int si_signo;
		int si_errno;
		int si_code;
		union __sifields _sifields;
	};
};

struct sigaction {
	__sighandler_t sa_handler;
	long unsigned int sa_flags;
	__sigrestore_t sa_restorer;
	sigset_t sa_mask;
};

struct k_sigaction {
	struct sigaction sa;
};

struct cpu_itimer {
	u64 expires;
	u64 incr;
};

struct task_cputime_atomic {
	atomic64_t utime;
	atomic64_t stime;
	atomic64_t sum_exec_runtime;
};

struct thread_group_cputimer {
	struct task_cputime_atomic cputime_atomic;
};

struct pacct_struct {
	int ac_flag;
	long int ac_exitcode;
	long unsigned int ac_mem;
	u64 ac_utime;
	u64 ac_stime;
	long unsigned int ac_minflt;
	long unsigned int ac_majflt;
};

struct core_state;

struct tty_struct;

struct autogroup;

struct taskstats;

struct tty_audit_buf;

struct signal_struct {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	int posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid *pids[4];
	struct pid *tty_old_pgrp;
	int leader;
	struct tty_struct *tty;
	struct autogroup *autogroup;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

enum rseq_cs_flags_bit {
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT = 0,
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT = 1,
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT = 2,
};

struct rseq {
	__u32 cpu_id_start;
	__u32 cpu_id;
	__u64 rseq_cs;
	__u32 flags;
	long: 32;
	long: 64;
};

enum {
	TASK_COMM_LEN = 16,
};

enum uclamp_id {
	UCLAMP_MIN = 0,
	UCLAMP_MAX = 1,
	UCLAMP_CNT = 2,
};

enum perf_event_task_context {
	perf_invalid_context = 4294967295,
	perf_hw_context = 0,
	perf_sw_context = 1,
	perf_nr_task_contexts = 2,
};

struct rq;

struct rq_flags;

struct sched_class {
	int uclamp_enabled;
	void (*enqueue_task)(struct rq *, struct task_struct *, int);
	void (*dequeue_task)(struct rq *, struct task_struct *, int);
	void (*yield_task)(struct rq *);
	bool (*yield_to_task)(struct rq *, struct task_struct *);
	void (*check_preempt_curr)(struct rq *, struct task_struct *, int);
	struct task_struct * (*pick_next_task)(struct rq *);
	void (*put_prev_task)(struct rq *, struct task_struct *);
	void (*set_next_task)(struct rq *, struct task_struct *, bool);
	int (*balance)(struct rq *, struct task_struct *, struct rq_flags *);
	int (*select_task_rq)(struct task_struct *, int, int);
	struct task_struct * (*pick_task)(struct rq *);
	void (*migrate_task_rq)(struct task_struct *, int);
	void (*task_woken)(struct rq *, struct task_struct *);
	void (*set_cpus_allowed)(struct task_struct *, const struct cpumask *, u32);
	void (*rq_online)(struct rq *);
	void (*rq_offline)(struct rq *);
	struct rq * (*find_lock_rq)(struct task_struct *, struct rq *);
	void (*task_tick)(struct rq *, struct task_struct *, int);
	void (*task_fork)(struct task_struct *);
	void (*task_dead)(struct task_struct *);
	void (*switched_from)(struct rq *, struct task_struct *);
	void (*switched_to)(struct rq *, struct task_struct *);
	void (*prio_changed)(struct rq *, struct task_struct *, int);
	unsigned int (*get_rr_interval)(struct rq *, struct task_struct *);
	void (*update_curr)(struct rq *);
	void (*task_change_group)(struct task_struct *, int);
};

struct kernel_cap_struct {
	__u32 cap[2];
};

typedef struct kernel_cap_struct kernel_cap_t;

struct user_struct;

struct ucounts;

struct group_info;

struct cred {
	atomic_t usage;
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
	unsigned int securebits;
	kernel_cap_t cap_inheritable;
	kernel_cap_t cap_permitted;
	kernel_cap_t cap_effective;
	kernel_cap_t cap_bset;
	kernel_cap_t cap_ambient;
	unsigned char jit_keyring;
	struct key *session_keyring;
	struct key *process_keyring;
	struct key *thread_keyring;
	struct key *request_key_auth;
	void *security;
	struct user_struct *user;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct group_info *group_info;
	union {
		int non_rcu;
		struct callback_head rcu;
	};
};

typedef int32_t key_serial_t;

typedef uint32_t key_perm_t;

struct key_type;

struct key_tag;

struct keyring_index_key {
	long unsigned int hash;
	union {
		struct {
			u16 desc_len;
			char desc[6];
		};
		long unsigned int x;
	};
	struct key_type *type;
	struct key_tag *domain_tag;
	const char *description;
};

union key_payload {
	void *rcu_data0;
	void *data[4];
};

struct assoc_array_ptr;

struct assoc_array {
	struct assoc_array_ptr *root;
	long unsigned int nr_leaves_on_tree;
};

struct watch_list;

struct key_user;

struct key_restriction;

struct key {
	refcount_t usage;
	key_serial_t serial;
	union {
		struct list_head graveyard_link;
		struct rb_node serial_node;
	};
	struct watch_list *watchers;
	struct rw_semaphore sem;
	struct key_user *user;
	void *security;
	union {
		time64_t expiry;
		time64_t revoked_at;
	};
	time64_t last_used_at;
	kuid_t uid;
	kgid_t gid;
	key_perm_t perm;
	short unsigned int quotalen;
	short unsigned int datalen;
	short int state;
	long unsigned int flags;
	union {
		struct keyring_index_key index_key;
		struct {
			long unsigned int hash;
			long unsigned int len_desc;
			struct key_type *type;
			struct key_tag *domain_tag;
			char *description;
		};
	};
	union {
		union key_payload payload;
		struct {
			struct list_head name_link;
			struct assoc_array keys;
		};
	};
	struct key_restriction *restrict_link;
};

struct sighand_struct {
	spinlock_t siglock;
	refcount_t count;
	wait_queue_head_t signalfd_wqh;
	struct k_sigaction action[64];
};

struct io_cq;

struct io_context {
	atomic_long_t refcount;
	atomic_t active_ref;
	short unsigned int ioprio;
	spinlock_t lock;
	struct xarray icq_tree;
	struct io_cq *icq_hint;
	struct hlist_head icq_list;
	struct work_struct release_work;
};

enum rseq_event_mask_bits {
	RSEQ_EVENT_PREEMPT_BIT = 0,
	RSEQ_EVENT_SIGNAL_BIT = 1,
	RSEQ_EVENT_MIGRATE_BIT = 2,
};

enum fixed_addresses {
	VSYSCALL_PAGE = 511,
	FIX_DBGP_BASE = 512,
	FIX_EARLYCON_MEM_BASE = 513,
	FIX_APIC_BASE = 514,
	FIX_IO_APIC_BASE_0 = 515,
	FIX_IO_APIC_BASE_END = 642,
	FIX_PARAVIRT_BOOTMAP = 643,
	FIX_APEI_GHES_IRQ = 644,
	FIX_APEI_GHES_NMI = 645,
	__end_of_permanent_fixed_addresses = 646,
	FIX_BTMAP_END = 1024,
	FIX_BTMAP_BEGIN = 1535,
	FIX_TBOOT_BASE = 1536,
	__end_of_fixed_addresses = 1537,
};

struct hlist_bl_node;

struct hlist_bl_head {
	struct hlist_bl_node *first;
};

struct hlist_bl_node {
	struct hlist_bl_node *next;
	struct hlist_bl_node **pprev;
};

struct lockref {
	union {
		__u64 lock_count;
		struct {
			spinlock_t lock;
			int count;
		};
	};
};

struct qstr {
	union {
		struct {
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

struct dentry_operations;

struct dentry {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	unsigned char d_iname[32];
	struct lockref d_lockref;
	const struct dentry_operations *d_op;
	struct super_block *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

struct posix_acl;

struct inode_operations;

struct bdi_writeback;

struct file_lock_context;

struct cdev;

struct fsnotify_mark_connector;

struct fscrypt_info;

struct fsverity_info;

struct inode {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	struct address_space *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations *i_fop;
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context *i_flctx;
	struct address_space i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info *i_pipe;
		struct cdev *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};

struct dentry_operations {
	int (*d_revalidate)(struct dentry *, unsigned int);
	int (*d_weak_revalidate)(struct dentry *, unsigned int);
	int (*d_hash)(const struct dentry *, struct qstr *);
	int (*d_compare)(const struct dentry *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry *);
	int (*d_init)(struct dentry *);
	void (*d_release)(struct dentry *);
	void (*d_prune)(struct dentry *);
	void (*d_iput)(struct dentry *, struct inode *);
	char * (*d_dname)(struct dentry *, char *, int);
	struct vfsmount * (*d_automount)(struct path *);
	int (*d_manage)(const struct path *, bool);
	struct dentry * (*d_real)(struct dentry *, const struct inode *);
	long: 64;
	long: 64;
	long: 64;
};

struct mtd_info;

typedef long long int qsize_t;

struct quota_format_type;

struct mem_dqinfo {
	struct quota_format_type *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops;

struct quota_info {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode *files[3];
	struct mem_dqinfo info[3];
	const struct quota_format_ops *ops[3];
};

struct rcu_sync {
	int gp_state;
	int gp_count;
	wait_queue_head_t gp_wait;
	struct callback_head cb_head;
};

struct rcuwait {
	struct task_struct *task;
};

struct percpu_rw_semaphore {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers {
	int frozen;
	wait_queue_head_t wait_unfrozen;
	struct percpu_rw_semaphore rw_sem[3];
};

typedef struct {
	__u8 b[16];
} uuid_t;

struct list_lru_node;

struct list_lru {
	struct list_lru_node *node;
	struct list_head list;
	int shrinker_id;
	bool memcg_aware;
	struct xarray xa;
};

struct super_operations;

struct dquot_operations;

struct quotactl_ops;

struct export_operations;

struct xattr_handler;

struct fscrypt_operations;

struct fsverity_operations;

struct unicode_map;

struct block_device;

struct super_block {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type *s_type;
	const struct super_operations *s_op;
	const struct dquot_operations *dq_op;
	const struct quotactl_ops *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	void *s_security;
	const struct xattr_handler **s_xattr;
	const struct fscrypt_operations *s_cop;
	struct key *s_master_keys;
	const struct fsverity_operations *s_vop;
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device *s_bdev;
	struct backing_dev_info *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info s_dquot;
	struct sb_writers s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	__u32 s_fsnotify_mask;
	struct fsnotify_mark_connector *s_fsnotify_marks;
	char s_id[32];
	uuid_t s_uuid;
	unsigned int s_max_links;
	fmode_t s_mode;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations *s_d_op;
	struct shrinker s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
	long: 64;
};

struct vfsmount {
	struct dentry *mnt_root;
	struct super_block *mnt_sb;
	int mnt_flags;
	struct user_namespace *mnt_userns;
};

struct kstat {
	u32 result_mask;
	umode_t mode;
	unsigned int nlink;
	uint32_t blksize;
	u64 attributes;
	u64 attributes_mask;
	u64 ino;
	dev_t dev;
	dev_t rdev;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;
	struct timespec64 btime;
	u64 blocks;
	u64 mnt_id;
};

struct list_lru_one {
	struct list_head list;
	long int nr_items;
};

struct list_lru_node {
	spinlock_t lock;
	struct list_lru_one lru;
	long int nr_items;
	long: 64;
	long: 64;
	long: 64;
};

enum migrate_mode {
	MIGRATE_ASYNC = 0,
	MIGRATE_SYNC_LIGHT = 1,
	MIGRATE_SYNC = 2,
	MIGRATE_SYNC_NO_COPY = 3,
};

struct exception_table_entry {
	int insn;
	int fixup;
	int data;
};

struct key_tag {
	struct callback_head rcu;
	refcount_t usage;
	bool removed;
};

typedef int (*request_key_actor_t)(struct key *, void *);

struct key_preparsed_payload;

struct key_match_data;

struct kernel_pkey_params;

struct kernel_pkey_query;

struct key_type {
	const char *name;
	size_t def_datalen;
	unsigned int flags;
	int (*vet_description)(const char *);
	int (*preparse)(struct key_preparsed_payload *);
	void (*free_preparse)(struct key_preparsed_payload *);
	int (*instantiate)(struct key *, struct key_preparsed_payload *);
	int (*update)(struct key *, struct key_preparsed_payload *);
	int (*match_preparse)(struct key_match_data *);
	void (*match_free)(struct key_match_data *);
	void (*revoke)(struct key *);
	void (*destroy)(struct key *);
	void (*describe)(const struct key *, struct seq_file *);
	long int (*read)(const struct key *, char *, size_t);
	request_key_actor_t request_key;
	struct key_restriction * (*lookup_restriction)(const char *);
	int (*asym_query)(const struct kernel_pkey_params *, struct kernel_pkey_query *);
	int (*asym_eds_op)(struct kernel_pkey_params *, const void *, void *);
	int (*asym_verify_signature)(struct kernel_pkey_params *, const void *, const void *);
	struct list_head link;
	struct lock_class_key lock_class;
};

typedef int (*key_restrict_link_func_t)(struct key *, const struct key_type *, const union key_payload *, struct key *);

struct key_restriction {
	key_restrict_link_func_t check;
	struct key *key;
	struct key_type *keytype;
};

struct percpu_counter {
	raw_spinlock_t lock;
	s64 count;
	struct list_head list;
	s32 *counters;
};

struct user_struct {
	refcount_t __count;
	struct percpu_counter epoll_watches;
	long unsigned int unix_inflight;
	atomic_long_t pipe_bufs;
	struct hlist_node uidhash_node;
	kuid_t uid;
	atomic_long_t locked_vm;
	atomic_t nr_watches;
	struct ratelimit_state ratelimit;
};

struct group_info {
	atomic_t usage;
	int ngroups;
	kgid_t gid[0];
};

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

struct delayed_call {
	void (*fn)(void *);
	void *arg;
};

struct kmem_cache;

struct io_cq {
	struct request_queue *q;
	struct io_context *ioc;
	union {
		struct list_head q_node;
		struct kmem_cache *__rcu_icq_cache;
	};
	union {
		struct hlist_node ioc_node;
		struct callback_head __rcu_head;
	};
	unsigned int flags;
};

enum kmalloc_cache_type {
	KMALLOC_NORMAL = 0,
	KMALLOC_CGROUP = 1,
	KMALLOC_RECLAIM = 2,
	KMALLOC_DMA = 3,
	NR_KMALLOC_TYPES = 4,
};

struct wait_page_queue;

struct kiocb {
	struct file *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	struct wait_page_queue *ki_waitq;
};

struct iattr {
	unsigned int ia_valid;
	umode_t ia_mode;
	kuid_t ia_uid;
	kgid_t ia_gid;
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file *ia_file;
};

typedef __kernel_uid32_t projid_t;

typedef struct {
	projid_t val;
} kprojid_t;

enum quota_type {
	USRQUOTA = 0,
	GRPQUOTA = 1,
	PRJQUOTA = 2,
};

struct kqid {
	union {
		kuid_t uid;
		kgid_t gid;
		kprojid_t projid;
	};
	enum quota_type type;
};

struct mem_dqblk {
	qsize_t dqb_bhardlimit;
	qsize_t dqb_bsoftlimit;
	qsize_t dqb_curspace;
	qsize_t dqb_rsvspace;
	qsize_t dqb_ihardlimit;
	qsize_t dqb_isoftlimit;
	qsize_t dqb_curinodes;
	time64_t dqb_btime;
	time64_t dqb_itime;
};

struct dquot {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

enum {
	DQF_ROOT_SQUASH_B = 0,
	DQF_SYS_FILE_B = 16,
	DQF_PRIVATE = 17,
};

struct quota_format_type {
	int qf_fmt_id;
	const struct quota_format_ops *qf_ops;
	struct module *qf_owner;
	struct quota_format_type *qf_next;
};

enum {
	DQST_LOOKUPS = 0,
	DQST_DROPS = 1,
	DQST_READS = 2,
	DQST_WRITES = 3,
	DQST_CACHE_HITS = 4,
	DQST_ALLOC_DQUOTS = 5,
	DQST_FREE_DQUOTS = 6,
	DQST_SYNCS = 7,
	_DQST_DQSTAT_LAST = 8,
};

struct quota_format_ops {
	int (*check_quota_file)(struct super_block *, int);
	int (*read_file_info)(struct super_block *, int);
	int (*write_file_info)(struct super_block *, int);
	int (*free_file_info)(struct super_block *, int);
	int (*read_dqblk)(struct dquot *);
	int (*commit_dqblk)(struct dquot *);
	int (*release_dqblk)(struct dquot *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct dquot_operations {
	int (*write_dquot)(struct dquot *);
	struct dquot * (*alloc_dquot)(struct super_block *, int);
	void (*destroy_dquot)(struct dquot *);
	int (*acquire_dquot)(struct dquot *);
	int (*release_dquot)(struct dquot *);
	int (*mark_dirty)(struct dquot *);
	int (*write_info)(struct super_block *, int);
	qsize_t * (*get_reserved_space)(struct inode *);
	int (*get_projid)(struct inode *, kprojid_t *);
	int (*get_inode_usage)(struct inode *, qsize_t *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct qc_dqblk {
	int d_fieldmask;
	u64 d_spc_hardlimit;
	u64 d_spc_softlimit;
	u64 d_ino_hardlimit;
	u64 d_ino_softlimit;
	u64 d_space;
	u64 d_ino_count;
	s64 d_ino_timer;
	s64 d_spc_timer;
	int d_ino_warns;
	int d_spc_warns;
	u64 d_rt_spc_hardlimit;
	u64 d_rt_spc_softlimit;
	u64 d_rt_space;
	s64 d_rt_spc_timer;
	int d_rt_spc_warns;
};

struct qc_type_state {
	unsigned int flags;
	unsigned int spc_timelimit;
	unsigned int ino_timelimit;
	unsigned int rt_spc_timelimit;
	unsigned int spc_warnlimit;
	unsigned int ino_warnlimit;
	unsigned int rt_spc_warnlimit;
	long long unsigned int ino;
	blkcnt_t blocks;
	blkcnt_t nextents;
};

struct qc_state {
	unsigned int s_incoredqs;
	struct qc_type_state s_state[3];
};

struct qc_info {
	int i_fieldmask;
	unsigned int i_flags;
	unsigned int i_spc_timelimit;
	unsigned int i_ino_timelimit;
	unsigned int i_rt_spc_timelimit;
	unsigned int i_spc_warnlimit;
	unsigned int i_ino_warnlimit;
	unsigned int i_rt_spc_warnlimit;
};

struct quotactl_ops {
	int (*quota_on)(struct super_block *, int, int, const struct path *);
	int (*quota_off)(struct super_block *, int);
	int (*quota_enable)(struct super_block *, unsigned int);
	int (*quota_disable)(struct super_block *, unsigned int);
	int (*quota_sync)(struct super_block *, int);
	int (*set_info)(struct super_block *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block *, struct qc_state *);
	int (*rm_xquota)(struct super_block *, unsigned int);
};

enum module_state {
	MODULE_STATE_LIVE = 0,
	MODULE_STATE_COMING = 1,
	MODULE_STATE_GOING = 2,
	MODULE_STATE_UNFORMED = 3,
};

struct kset;

struct kobj_type;

struct kernfs_node;

struct kobject {
	const char *name;
	struct list_head entry;
	struct kobject *parent;
	struct kset *kset;
	const struct kobj_type *ktype;
	struct kernfs_node *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module_param_attrs;

struct module_kobject {
	struct kobject kobj;
	struct module *mod;
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct latch_tree_node {
	struct rb_node node[2];
};

struct mod_tree_node {
	struct module *mod;
	struct latch_tree_node node;
};

struct module_layout {
	void *base;
	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;
	unsigned int ro_after_init_size;
	struct mod_tree_node mtn;
};

struct mod_arch_specific {};

struct elf64_sym;

typedef struct elf64_sym Elf64_Sym;

struct mod_kallsyms {
	Elf64_Sym *symtab;
	unsigned int num_symtab;
	char *strtab;
	char *typetab;
};

struct module_attribute;

struct kernel_param;

struct module_sect_attrs;

struct module_notes_attrs;

struct trace_event_call;

struct trace_eval_map;

struct klp_modinfo;

struct error_injection_entry;

struct module {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject mkobj;
	struct module_attribute *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool sig_ok;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	struct module_layout core_layout;
	struct module_layout init_layout;
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	int num_static_call_sites;
	struct static_call_site *static_call_sites;
	bool klp;
	bool klp_alive;
	struct klp_modinfo *klp_info;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
	struct error_injection_entry *ei_funcs;
	unsigned int num_ei_funcs;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct writeback_control;

struct readahead_control;

struct swap_info_struct;

struct address_space_operations {
	int (*writepage)(struct page *, struct writeback_control *);
	int (*read_folio)(struct file *, struct folio *);
	int (*writepages)(struct address_space *, struct writeback_control *);
	bool (*dirty_folio)(struct address_space *, struct folio *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file *, struct address_space *, loff_t, unsigned int, struct page **, void **);
	int (*write_end)(struct file *, struct address_space *, loff_t, unsigned int, unsigned int, struct page *, void *);
	sector_t (*bmap)(struct address_space *, sector_t);
	void (*invalidate_folio)(struct folio *, size_t, size_t);
	bool (*release_folio)(struct folio *, gfp_t);
	void (*free_folio)(struct folio *);
	ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *);
	int (*migratepage)(struct address_space *, struct page *, struct page *, enum migrate_mode);
	bool (*isolate_page)(struct page *, isolate_mode_t);
	void (*putback_page)(struct page *);
	int (*launder_folio)(struct folio *);
	bool (*is_partially_uptodate)(struct folio *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio *, bool *, bool *);
	int (*error_remove_page)(struct address_space *, struct page *);
	int (*swap_activate)(struct swap_info_struct *, struct file *, sector_t *);
	void (*swap_deactivate)(struct file *);
	int (*swap_rw)(struct kiocb *, struct iov_iter *);
};

struct fiemap_extent_info;

struct fileattr;

struct inode_operations {
	struct dentry * (*lookup)(struct inode *, struct dentry *, unsigned int);
	const char * (*get_link)(struct dentry *, struct inode *, struct delayed_call *);
	int (*permission)(struct user_namespace *, struct inode *, int);
	struct posix_acl * (*get_acl)(struct inode *, int, bool);
	int (*readlink)(struct dentry *, char *, int);
	int (*create)(struct user_namespace *, struct inode *, struct dentry *, umode_t, bool);
	int (*link)(struct dentry *, struct inode *, struct dentry *);
	int (*unlink)(struct inode *, struct dentry *);
	int (*symlink)(struct user_namespace *, struct inode *, struct dentry *, const char *);
	int (*mkdir)(struct user_namespace *, struct inode *, struct dentry *, umode_t);
	int (*rmdir)(struct inode *, struct dentry *);
	int (*mknod)(struct user_namespace *, struct inode *, struct dentry *, umode_t, dev_t);
	int (*rename)(struct user_namespace *, struct inode *, struct dentry *, struct inode *, struct dentry *, unsigned int);
	int (*setattr)(struct user_namespace *, struct dentry *, struct iattr *);
	int (*getattr)(struct user_namespace *, const struct path *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry *, char *, size_t);
	int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode *, struct timespec64 *, int);
	int (*atomic_open)(struct inode *, struct dentry *, struct file *, unsigned int, umode_t);
	int (*tmpfile)(struct user_namespace *, struct inode *, struct dentry *, umode_t);
	int (*set_acl)(struct user_namespace *, struct inode *, struct posix_acl *, int);
	int (*fileattr_set)(struct user_namespace *, struct dentry *, struct fileattr *);
	int (*fileattr_get)(struct dentry *, struct fileattr *);
	long: 64;
};

struct file_lock_context {
	spinlock_t flc_lock;
	struct list_head flc_flock;
	struct list_head flc_posix;
	struct list_head flc_lease;
};

struct file_lock_operations {
	void (*fl_copy_lock)(struct file_lock *, struct file_lock *);
	void (*fl_release_private)(struct file_lock *);
};

struct nlm_lockowner;

struct nfs_lock_info {
	u32 state;
	struct nlm_lockowner *owner;
	struct list_head list;
};

struct nfs4_lock_state;

struct nfs4_lock_info {
	struct nfs4_lock_state *owner;
};

struct fasync_struct;

struct lock_manager_operations;

struct file_lock {
	struct file_lock *fl_blocker;
	struct list_head fl_list;
	struct hlist_node fl_link;
	struct list_head fl_blocked_requests;
	struct list_head fl_blocked_member;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;
	wait_queue_head_t fl_wait;
	struct file *fl_file;
	loff_t fl_start;
	loff_t fl_end;
	struct fasync_struct *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct file_lock_operations *fl_ops;
	const struct lock_manager_operations *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
	} fl_u;
};

struct lock_manager_operations {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock *);
	int (*lm_grant)(struct file_lock *, int);
	bool (*lm_break)(struct file_lock *);
	int (*lm_change)(struct file_lock *, int, struct list_head *);
	void (*lm_setup)(struct file_lock *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lock *);
	bool (*lm_lock_expirable)(struct file_lock *);
	void (*lm_expire_lock)();
};

struct fasync_struct {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct *fa_next;
	struct file *fa_file;
	struct callback_head fa_rcu;
};

enum {
	SB_UNFROZEN = 0,
	SB_FREEZE_WRITE = 1,
	SB_FREEZE_PAGEFAULT = 2,
	SB_FREEZE_FS = 3,
	SB_FREEZE_COMPLETE = 4,
};

struct kstatfs;

struct super_operations {
	struct inode * (*alloc_inode)(struct super_block *);
	void (*destroy_inode)(struct inode *);
	void (*free_inode)(struct inode *);
	void (*dirty_inode)(struct inode *, int);
	int (*write_inode)(struct inode *, struct writeback_control *);
	int (*drop_inode)(struct inode *);
	void (*evict_inode)(struct inode *);
	void (*put_super)(struct super_block *);
	int (*sync_fs)(struct super_block *, int);
	int (*freeze_super)(struct super_block *);
	int (*freeze_fs)(struct super_block *);
	int (*thaw_super)(struct super_block *);
	int (*unfreeze_fs)(struct super_block *);
	int (*statfs)(struct dentry *, struct kstatfs *);
	int (*remount_fs)(struct super_block *, int *, char *);
	void (*umount_begin)(struct super_block *);
	int (*show_options)(struct seq_file *, struct dentry *);
	int (*show_devname)(struct seq_file *, struct dentry *);
	int (*show_path)(struct seq_file *, struct dentry *);
	int (*show_stats)(struct seq_file *, struct dentry *);
	ssize_t (*quota_read)(struct super_block *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block *, int, const char *, size_t, loff_t);
	struct dquot ** (*get_dquots)(struct inode *);
	long int (*nr_cached_objects)(struct super_block *, struct shrink_control *);
	long int (*free_cached_objects)(struct super_block *, struct shrink_control *);
};

struct iomap;

struct fid;

struct export_operations {
	int (*encode_fh)(struct inode *, __u32 *, int *, struct inode *);
	struct dentry * (*fh_to_dentry)(struct super_block *, struct fid *, int, int);
	struct dentry * (*fh_to_parent)(struct super_block *, struct fid *, int, int);
	int (*get_name)(struct dentry *, char *, struct dentry *);
	struct dentry * (*get_parent)(struct dentry *);
	int (*commit_metadata)(struct inode *);
	int (*get_uuid)(struct super_block *, u8 *, u32 *, u64 *);
	int (*map_blocks)(struct inode *, loff_t, u64, struct iomap *, bool, u32 *);
	int (*commit_blocks)(struct inode *, struct iomap *, int, struct iattr *);
	u64 (*fetch_iversion)(struct inode *);
	long unsigned int flags;
};

struct xattr_handler {
	const char *name;
	const char *prefix;
	int flags;
	bool (*list)(struct dentry *);
	int (*get)(const struct xattr_handler *, struct dentry *, struct inode *, const char *, void *, size_t);
	int (*set)(const struct xattr_handler *, struct user_namespace *, struct dentry *, struct inode *, const char *, const void *, size_t, int);
};

union fscrypt_policy;

struct fscrypt_operations {
	unsigned int flags;
	const char *key_prefix;
	int (*get_context)(struct inode *, void *, size_t);
	int (*set_context)(struct inode *, const void *, size_t, void *);
	const union fscrypt_policy * (*get_dummy_policy)(struct super_block *);
	bool (*empty_dir)(struct inode *);
	bool (*has_stable_inodes)(struct super_block *);
	void (*get_ino_and_lblk_bits)(struct super_block *, int *, int *);
	int (*get_num_devices)(struct super_block *);
	void (*get_devices)(struct super_block *, struct request_queue **);
};

struct fsverity_operations {
	int (*begin_enable_verity)(struct file *);
	int (*end_enable_verity)(struct file *, const void *, size_t, u64);
	int (*get_verity_descriptor)(struct inode *, void *, size_t);
	struct page * (*read_merkle_tree_page)(struct inode *, long unsigned int, long unsigned int);
	int (*write_merkle_tree_block)(struct inode *, const void *, u64, int);
};

typedef int (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);

struct dir_context {
	filldir_t actor;
	loff_t pos;
};

struct p_log;

struct fs_parameter;

struct fs_parse_result;

typedef int fs_param_type(struct p_log *, const struct fs_parameter_spec *, struct fs_parameter *, struct fs_parse_result *);

struct fs_parameter_spec {
	const char *name;
	fs_param_type *type;
	u8 opt;
	short unsigned int flags;
	const void *data;
};

enum compound_dtor_id {
	NULL_COMPOUND_DTOR = 0,
	COMPOUND_PAGE_DTOR = 1,
	HUGETLB_PAGE_DTOR = 2,
	TRANSHUGE_PAGE_DTOR = 3,
	NR_COMPOUND_DTORS = 4,
};

enum vm_event_item {
	PGPGIN = 0,
	PGPGOUT = 1,
	PSWPIN = 2,
	PSWPOUT = 3,
	PGALLOC_DMA = 4,
	PGALLOC_DMA32 = 5,
	PGALLOC_NORMAL = 6,
	PGALLOC_MOVABLE = 7,
	ALLOCSTALL_DMA = 8,
	ALLOCSTALL_DMA32 = 9,
	ALLOCSTALL_NORMAL = 10,
	ALLOCSTALL_MOVABLE = 11,
	PGSCAN_SKIP_DMA = 12,
	PGSCAN_SKIP_DMA32 = 13,
	PGSCAN_SKIP_NORMAL = 14,
	PGSCAN_SKIP_MOVABLE = 15,
	PGFREE = 16,
	PGACTIVATE = 17,
	PGDEACTIVATE = 18,
	PGLAZYFREE = 19,
	PGFAULT = 20,
	PGMAJFAULT = 21,
	PGLAZYFREED = 22,
	PGREFILL = 23,
	PGREUSE = 24,
	PGSTEAL_KSWAPD = 25,
	PGSTEAL_DIRECT = 26,
	PGDEMOTE_KSWAPD = 27,
	PGDEMOTE_DIRECT = 28,
	PGSCAN_KSWAPD = 29,
	PGSCAN_DIRECT = 30,
	PGSCAN_DIRECT_THROTTLE = 31,
	PGSCAN_ANON = 32,
	PGSCAN_FILE = 33,
	PGSTEAL_ANON = 34,
	PGSTEAL_FILE = 35,
	PGSCAN_ZONE_RECLAIM_FAILED = 36,
	PGINODESTEAL = 37,
	SLABS_SCANNED = 38,
	KSWAPD_INODESTEAL = 39,
	KSWAPD_LOW_WMARK_HIT_QUICKLY = 40,
	KSWAPD_HIGH_WMARK_HIT_QUICKLY = 41,
	PAGEOUTRUN = 42,
	PGROTATED = 43,
	DROP_PAGECACHE = 44,
	DROP_SLAB = 45,
	OOM_KILL = 46,
	NUMA_PTE_UPDATES = 47,
	NUMA_HUGE_PTE_UPDATES = 48,
	NUMA_HINT_FAULTS = 49,
	NUMA_HINT_FAULTS_LOCAL = 50,
	NUMA_PAGE_MIGRATE = 51,
	PGMIGRATE_SUCCESS = 52,
	PGMIGRATE_FAIL = 53,
	THP_MIGRATION_SUCCESS = 54,
	THP_MIGRATION_FAIL = 55,
	THP_MIGRATION_SPLIT = 56,
	COMPACTMIGRATE_SCANNED = 57,
	COMPACTFREE_SCANNED = 58,
	COMPACTISOLATED = 59,
	COMPACTSTALL = 60,
	COMPACTFAIL = 61,
	COMPACTSUCCESS = 62,
	KCOMPACTD_WAKE = 63,
	KCOMPACTD_MIGRATE_SCANNED = 64,
	KCOMPACTD_FREE_SCANNED = 65,
	HTLB_BUDDY_PGALLOC = 66,
	HTLB_BUDDY_PGALLOC_FAIL = 67,
	UNEVICTABLE_PGCULLED = 68,
	UNEVICTABLE_PGSCANNED = 69,
	UNEVICTABLE_PGRESCUED = 70,
	UNEVICTABLE_PGMLOCKED = 71,
	UNEVICTABLE_PGMUNLOCKED = 72,
	UNEVICTABLE_PGCLEARED = 73,
	UNEVICTABLE_PGSTRANDED = 74,
	THP_FAULT_ALLOC = 75,
	THP_FAULT_FALLBACK = 76,
	THP_FAULT_FALLBACK_CHARGE = 77,
	THP_COLLAPSE_ALLOC = 78,
	THP_COLLAPSE_ALLOC_FAILED = 79,
	THP_FILE_ALLOC = 80,
	THP_FILE_FALLBACK = 81,
	THP_FILE_FALLBACK_CHARGE = 82,
	THP_FILE_MAPPED = 83,
	THP_SPLIT_PAGE = 84,
	THP_SPLIT_PAGE_FAILED = 85,
	THP_DEFERRED_SPLIT_PAGE = 86,
	THP_SPLIT_PMD = 87,
	THP_SCAN_EXCEED_NONE_PTE = 88,
	THP_SCAN_EXCEED_SWAP_PTE = 89,
	THP_SCAN_EXCEED_SHARED_PTE = 90,
	THP_SPLIT_PUD = 91,
	THP_ZERO_PAGE_ALLOC = 92,
	THP_ZERO_PAGE_ALLOC_FAILED = 93,
	THP_SWPOUT = 94,
	THP_SWPOUT_FALLBACK = 95,
	BALLOON_INFLATE = 96,
	BALLOON_DEFLATE = 97,
	BALLOON_MIGRATE = 98,
	SWAP_RA = 99,
	SWAP_RA_HIT = 100,
	KSM_SWPIN_COPY = 101,
	COW_KSM = 102,
	ZSWPIN = 103,
	ZSWPOUT = 104,
	DIRECT_MAP_LEVEL2_SPLIT = 105,
	DIRECT_MAP_LEVEL3_SPLIT = 106,
	NR_VM_EVENT_ITEMS = 107,
};

struct tlb_context {
	u64 ctx_id;
	u64 tlb_gen;
};

struct tlb_state {
	struct mm_struct *loaded_mm;
	union {
		struct mm_struct *last_user_mm;
		long unsigned int last_user_mm_spec;
	};
	u16 loaded_mm_asid;
	u16 next_asid;
	bool invalidate_other;
	short unsigned int user_pcid_flush_mask;
	long unsigned int cr4;
	struct tlb_context ctxs[6];
};

struct boot_params_to_save {
	unsigned int start;
	unsigned int len;
};

struct kernfs_root;

struct kernfs_elem_dir {
	long unsigned int subdirs;
	struct rb_root children;
	struct kernfs_root *root;
	long unsigned int rev;
};

struct kernfs_elem_symlink {
	struct kernfs_node *target_kn;
};

struct kernfs_ops;

struct kernfs_open_node;

struct kernfs_elem_attr {
	const struct kernfs_ops *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node *notify_next;
};

struct kernfs_iattrs;

struct kernfs_node {
	atomic_t count;
	atomic_t active;
	struct kernfs_node *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink symlink;
		struct kernfs_elem_attr attr;
	};
	void *priv;
	u64 id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
};

struct kernfs_open_file;

struct kernfs_ops {
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	ssize_t (*read)(struct kernfs_open_file *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
	int (*mmap)(struct kernfs_open_file *, struct vm_area_struct *);
};

struct kernfs_open_file {
	struct kernfs_node *kn;
	struct file *file;
	struct seq_file *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct *vm_ops;
};

enum kobj_ns_type {
	KOBJ_NS_TYPE_NONE = 0,
	KOBJ_NS_TYPE_NET = 1,
	KOBJ_NS_TYPES = 2,
};

struct sock;

struct kobj_ns_type_operations {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct attribute {
	const char *name;
	umode_t mode;
};

struct bin_attribute {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space * (*f_mapping)();
	ssize_t (*read)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	ssize_t (*write)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	int (*mmap)(struct file *, struct kobject *, struct bin_attribute *, struct vm_area_struct *);
};

struct sysfs_ops {
	ssize_t (*show)(struct kobject *, struct attribute *, char *);
	ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops;

struct kset {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject kobj;
	const struct kset_uevent_ops *uevent_ops;
};

struct kobj_type {
	void (*release)(struct kobject *);
	const struct sysfs_ops *sysfs_ops;
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations * (*child_ns_type)(struct kobject *);
	const void * (*namespace)(struct kobject *);
	void (*get_ownership)(struct kobject *, kuid_t *, kgid_t *);
};

struct kobj_uevent_env {
	char *argv[3];
	char *envp[64];
	int envp_idx;
	char buf[2048];
	int buflen;
};

struct kset_uevent_ops {
	int (* const filter)(struct kobject *);
	const char * (* const name)(struct kobject *);
	int (* const uevent)(struct kobject *, struct kobj_uevent_env *);
};

enum cpu_idle_type {
	CPU_IDLE = 0,
	CPU_NOT_IDLE = 1,
	CPU_NEWLY_IDLE = 2,
	CPU_MAX_IDLE_TYPES = 3,
};

enum {
	__SD_BALANCE_NEWIDLE = 0,
	__SD_BALANCE_EXEC = 1,
	__SD_BALANCE_FORK = 2,
	__SD_BALANCE_WAKE = 3,
	__SD_WAKE_AFFINE = 4,
	__SD_ASYM_CPUCAPACITY = 5,
	__SD_ASYM_CPUCAPACITY_FULL = 6,
	__SD_SHARE_CPUCAPACITY = 7,
	__SD_SHARE_PKG_RESOURCES = 8,
	__SD_SERIALIZE = 9,
	__SD_ASYM_PACKING = 10,
	__SD_PREFER_SIBLING = 11,
	__SD_OVERLAP = 12,
	__SD_NUMA = 13,
	__SD_FLAG_CNT = 14,
};

typedef __u64 Elf64_Addr;

typedef __u16 Elf64_Half;

typedef __u64 Elf64_Off;

typedef __u32 Elf64_Word;

typedef __u64 Elf64_Xword;

struct elf64_sym {
	Elf64_Word st_name;
	unsigned char st_info;
	unsigned char st_other;
	Elf64_Half st_shndx;
	Elf64_Addr st_value;
	Elf64_Xword st_size;
};

struct elf64_hdr {
	unsigned char e_ident[16];
	Elf64_Half e_type;
	Elf64_Half e_machine;
	Elf64_Word e_version;
	Elf64_Addr e_entry;
	Elf64_Off e_phoff;
	Elf64_Off e_shoff;
	Elf64_Word e_flags;
	Elf64_Half e_ehsize;
	Elf64_Half e_phentsize;
	Elf64_Half e_phnum;
	Elf64_Half e_shentsize;
	Elf64_Half e_shnum;
	Elf64_Half e_shstrndx;
};

typedef struct elf64_hdr Elf64_Ehdr;

struct elf64_shdr {
	Elf64_Word sh_name;
	Elf64_Word sh_type;
	Elf64_Xword sh_flags;
	Elf64_Addr sh_addr;
	Elf64_Off sh_offset;
	Elf64_Xword sh_size;
	Elf64_Word sh_link;
	Elf64_Word sh_info;
	Elf64_Xword sh_addralign;
	Elf64_Xword sh_entsize;
};

typedef struct elf64_shdr Elf64_Shdr;

struct kernel_param_ops {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param *);
	int (*get)(char *, const struct kernel_param *);
	void (*free)(void *);
};

struct kparam_string;

struct kparam_array;

struct kernel_param {
	const char *name;
	struct module *mod;
	const struct kernel_param_ops *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array *arr;
	};
};

struct kparam_string {
	unsigned int maxlen;
	char *string;
};

struct kparam_array {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops *ops;
	void *elem;
};

struct error_injection_entry {
	long unsigned int addr;
	int etype;
};

struct module_attribute {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute *, struct module_kobject *, char *);
	ssize_t (*store)(struct module_attribute *, struct module_kobject *, const char *, size_t);
	void (*setup)(struct module *, const char *);
	int (*test)(struct module *);
	void (*free)(struct module *);
};

struct klp_modinfo {
	Elf64_Ehdr hdr;
	Elf64_Shdr *sechdrs;
	char *secstrings;
	unsigned int symndx;
};

struct x86_guest {
	void (*enc_status_change_prepare)(long unsigned int, int, bool);
	bool (*enc_status_change_finish)(long unsigned int, int, bool);
	bool (*enc_tlb_flush_required)(bool);
	bool (*enc_cache_flush_required)();
};

struct x86_legacy_devices {
	int pnpbios;
};

enum x86_legacy_i8042_state {
	X86_LEGACY_I8042_PLATFORM_ABSENT = 0,
	X86_LEGACY_I8042_FIRMWARE_ABSENT = 1,
	X86_LEGACY_I8042_EXPECTED_PRESENT = 2,
};

struct x86_legacy_features {
	enum x86_legacy_i8042_state i8042;
	int rtc;
	int warm_reset;
	int no_vga;
	int reserve_bios_regions;
	struct x86_legacy_devices devices;
};

struct ghcb;

struct x86_hyper_runtime {
	void (*pin_vcpu)(int);
	void (*sev_es_hcall_prepare)(struct ghcb *, struct pt_regs *);
	bool (*sev_es_hcall_finish)(struct ghcb *, struct pt_regs *);
};

struct x86_platform_ops {
	long unsigned int (*calibrate_cpu)();
	long unsigned int (*calibrate_tsc)();
	void (*get_wallclock)(struct timespec64 *);
	int (*set_wallclock)(const struct timespec64 *);
	void (*iommu_shutdown)();
	bool (*is_untracked_pat_range)(u64, u64);
	void (*nmi_init)();
	unsigned char (*get_nmi_reason)();
	void (*save_sched_clock_state)();
	void (*restore_sched_clock_state)();
	void (*apic_post_init)();
	struct x86_legacy_features legacy;
	void (*set_legacy_features)();
	struct x86_hyper_runtime hyper;
	struct x86_guest guest;
};

typedef __u16 __be16;

typedef __u32 __le32;

typedef __u32 __be32;

typedef __u32 __wsum;

typedef u16 uint16_t;

typedef long unsigned int irq_hw_number_t;

typedef int (*initcall_t)();

typedef int initcall_entry_t;

struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
	int early;
};

struct static_key_true {
	struct static_key key;
};

struct static_key_false {
	struct static_key key;
};

struct _ddebug {
	const char *modname;
	const char *function;
	const char *filename;
	const char *format;
	unsigned int lineno: 18;
	unsigned int flags: 8;
	union {
		struct static_key_true dd_key_true;
		struct static_key_false dd_key_false;
	} key;
};

struct static_call_mod {
	struct static_call_mod *next;
	struct module *mod;
	struct static_call_site *sites;
};

enum system_states {
	SYSTEM_BOOTING = 0,
	SYSTEM_SCHEDULING = 1,
	SYSTEM_FREEING_INITMEM = 2,
	SYSTEM_RUNNING = 3,
	SYSTEM_HALT = 4,
	SYSTEM_POWER_OFF = 5,
	SYSTEM_RESTART = 6,
	SYSTEM_SUSPEND = 7,
};

struct range {
	u64 start;
	u64 end;
};

typedef struct cpumask *cpumask_var_t;

struct seq_operations {
	void * (*start)(struct seq_file *, loff_t *);
	void (*stop)(struct seq_file *, void *);
	void * (*next)(struct seq_file *, void *, loff_t *);
	int (*show)(struct seq_file *, void *);
};

struct fixed_percpu_data {
	char gs_base[40];
	long unsigned int stack_canary;
};

enum perf_event_state {
	PERF_EVENT_STATE_DEAD = 4294967292,
	PERF_EVENT_STATE_EXIT = 4294967293,
	PERF_EVENT_STATE_ERROR = 4294967294,
	PERF_EVENT_STATE_OFF = 4294967295,
	PERF_EVENT_STATE_INACTIVE = 0,
	PERF_EVENT_STATE_ACTIVE = 1,
};

typedef struct {
	atomic_long_t a;
} local_t;

typedef struct {
	local_t a;
} local64_t;

struct perf_event_attr {
	__u32 type;
	__u32 size;
	__u64 config;
	union {
		__u64 sample_period;
		__u64 sample_freq;
	};
	__u64 sample_type;
	__u64 read_format;
	__u64 disabled: 1;
	__u64 inherit: 1;
	__u64 pinned: 1;
	__u64 exclusive: 1;
	__u64 exclude_user: 1;
	__u64 exclude_kernel: 1;
	__u64 exclude_hv: 1;
	__u64 exclude_idle: 1;
	__u64 mmap: 1;
	__u64 comm: 1;
	__u64 freq: 1;
	__u64 inherit_stat: 1;
	__u64 enable_on_exec: 1;
	__u64 task: 1;
	__u64 watermark: 1;
	__u64 precise_ip: 2;
	__u64 mmap_data: 1;
	__u64 sample_id_all: 1;
	__u64 exclude_host: 1;
	__u64 exclude_guest: 1;
	__u64 exclude_callchain_kernel: 1;
	__u64 exclude_callchain_user: 1;
	__u64 mmap2: 1;
	__u64 comm_exec: 1;
	__u64 use_clockid: 1;
	__u64 context_switch: 1;
	__u64 write_backward: 1;
	__u64 namespaces: 1;
	__u64 ksymbol: 1;
	__u64 bpf_event: 1;
	__u64 aux_output: 1;
	__u64 cgroup: 1;
	__u64 text_poke: 1;
	__u64 build_id: 1;
	__u64 inherit_thread: 1;
	__u64 remove_on_exec: 1;
	__u64 sigtrap: 1;
	__u64 __reserved_1: 26;
	union {
		__u32 wakeup_events;
		__u32 wakeup_watermark;
	};
	__u32 bp_type;
	union {
		__u64 bp_addr;
		__u64 kprobe_func;
		__u64 uprobe_path;
		__u64 config1;
	};
	union {
		__u64 bp_len;
		__u64 kprobe_addr;
		__u64 probe_offset;
		__u64 config2;
	};
	__u64 branch_sample_type;
	__u64 sample_regs_user;
	__u32 sample_stack_user;
	__s32 clockid;
	__u64 sample_regs_intr;
	__u32 aux_watermark;
	__u16 sample_max_stack;
	__u16 __reserved_2;
	__u32 aux_sample_size;
	__u32 __reserved_3;
	__u64 sig_data;
};

struct hw_perf_event_extra {
	u64 config;
	unsigned int reg;
	int alloc;
	int idx;
};

struct arch_hw_breakpoint {
	long unsigned int address;
	long unsigned int mask;
	u8 len;
	u8 type;
};

struct hw_perf_event {
	union {
		struct {
			u64 config;
			u64 last_tag;
			long unsigned int config_base;
			long unsigned int event_base;
			int event_base_rdpmc;
			int idx;
			int last_cpu;
			int flags;
			struct hw_perf_event_extra extra_reg;
			struct hw_perf_event_extra branch_reg;
		};
		struct {
			struct hrtimer hrtimer;
		};
		struct {
			struct list_head tp_list;
		};
		struct {
			u64 pwr_acc;
			u64 ptsc;
		};
		struct {
			struct arch_hw_breakpoint info;
			struct list_head bp_list;
		};
		struct {
			u8 iommu_bank;
			u8 iommu_cntr;
			u16 padding;
			u64 conf;
			u64 conf1;
		};
	};
	struct task_struct *target;
	void *addr_filters;
	long unsigned int addr_filters_gen;
	int state;
	local64_t prev_count;
	u64 sample_period;
	union {
		struct {
			u64 last_period;
			local64_t period_left;
		};
		struct {
			u64 saved_metric;
			u64 saved_slots;
		};
	};
	u64 interrupts_seq;
	u64 interrupts;
	u64 freq_time_stamp;
	u64 freq_count_stamp;
};

struct irq_work {
	struct __call_single_node node;
	void (*func)(struct irq_work *);
	struct rcuwait irqwait;
};

struct perf_addr_filters_head {
	struct list_head list;
	raw_spinlock_t lock;
	unsigned int nr_file_filters;
};

struct perf_sample_data;

typedef void (*perf_overflow_handler_t)(struct perf_event *, struct perf_sample_data *, struct pt_regs *);

struct ftrace_ops;

struct ftrace_regs;

typedef void (*ftrace_func_t)(long unsigned int, long unsigned int, struct ftrace_ops *, struct ftrace_regs *);

struct ftrace_hash;

struct ftrace_ops_hash {
	struct ftrace_hash *notrace_hash;
	struct ftrace_hash *filter_hash;
	struct mutex regex_lock;
};

struct ftrace_ops {
	ftrace_func_t func;
	struct ftrace_ops *next;
	long unsigned int flags;
	void *private;
	ftrace_func_t saved_func;
	struct ftrace_ops_hash local_hash;
	struct ftrace_ops_hash *func_hash;
	struct ftrace_ops_hash old_hash;
	long unsigned int trampoline;
	long unsigned int trampoline_size;
	struct list_head list;
};

struct pmu;

struct perf_buffer;

struct perf_addr_filter_range;

struct bpf_prog;

struct event_filter;

struct perf_cgroup;

struct perf_event {
	struct list_head event_entry;
	struct list_head sibling_list;
	struct list_head active_list;
	struct rb_node group_node;
	u64 group_index;
	struct list_head migrate_entry;
	struct hlist_node hlist_entry;
	struct list_head active_entry;
	int nr_siblings;
	int event_caps;
	int group_caps;
	struct perf_event *group_leader;
	struct pmu *pmu;
	void *pmu_private;
	enum perf_event_state state;
	unsigned int attach_state;
	local64_t count;
	atomic64_t child_count;
	u64 total_time_enabled;
	u64 total_time_running;
	u64 tstamp;
	struct perf_event_attr attr;
	u16 header_size;
	u16 id_header_size;
	u16 read_size;
	struct hw_perf_event hw;
	struct perf_event_context *ctx;
	atomic_long_t refcount;
	atomic64_t child_total_time_enabled;
	atomic64_t child_total_time_running;
	struct mutex child_mutex;
	struct list_head child_list;
	struct perf_event *parent;
	int oncpu;
	int cpu;
	struct list_head owner_entry;
	struct task_struct *owner;
	struct mutex mmap_mutex;
	atomic_t mmap_count;
	struct perf_buffer *rb;
	struct list_head rb_entry;
	long unsigned int rcu_batches;
	int rcu_pending;
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
	int pending_wakeup;
	int pending_kill;
	int pending_disable;
	long unsigned int pending_addr;
	struct irq_work pending;
	atomic_t event_limit;
	struct perf_addr_filters_head addr_filters;
	struct perf_addr_filter_range *addr_filter_ranges;
	long unsigned int addr_filters_gen;
	struct perf_event *aux_event;
	void (*destroy)(struct perf_event *);
	struct callback_head callback_head;
	struct pid_namespace *ns;
	u64 id;
	u64 (*clock)();
	perf_overflow_handler_t overflow_handler;
	void *overflow_handler_context;
	perf_overflow_handler_t orig_overflow_handler;
	struct bpf_prog *prog;
	u64 bpf_cookie;
	struct trace_event_call *tp_event;
	struct event_filter *filter;
	struct ftrace_ops ftrace_ops;
	struct perf_cgroup *cgrp;
	void *security;
	struct list_head sb_list;
};

struct uid_gid_extent {
	u32 first;
	u32 lower_first;
	u32 count;
};

struct uid_gid_map {
	u32 nr_extents;
	union {
		struct uid_gid_extent extent[5];
		struct {
			struct uid_gid_extent *forward;
			struct uid_gid_extent *reverse;
		};
	};
};

struct proc_ns_operations;

struct ns_common {
	atomic_long_t stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;
	refcount_t count;
};

struct ctl_table;

struct ctl_table_root;

struct ctl_table_set;

struct ctl_dir;

struct ctl_node;

struct ctl_table_header {
	union {
		struct {
			struct ctl_table *ctl_table;
			int used;
			int count;
			int nreg;
		};
		struct callback_head rcu;
	};
	struct completion *unregistering;
	struct ctl_table *ctl_table_arg;
	struct ctl_table_root *root;
	struct ctl_table_set *set;
	struct ctl_dir *parent;
	struct ctl_node *node;
	struct hlist_head inodes;
};

struct ctl_dir {
	struct ctl_table_header header;
	struct rb_root root;
};

struct ctl_table_set {
	int (*is_seen)(struct ctl_table_set *);
	struct ctl_dir dir;
};

struct user_namespace {
	struct uid_gid_map uid_map;
	struct uid_gid_map gid_map;
	struct uid_gid_map projid_map;
	struct user_namespace *parent;
	int level;
	kuid_t owner;
	kgid_t group;
	struct ns_common ns;
	long unsigned int flags;
	bool parent_could_setfcap;
	struct list_head keyring_name_list;
	struct key *user_keyring_register;
	struct rw_semaphore keyring_sem;
	struct key *persistent_keyring_register;
	struct work_struct work;
	struct ctl_table_set set;
	struct ctl_table_header *sysctls;
	struct ucounts *ucounts;
	long int ucount_max[16];
};

struct pollfd {
	int fd;
	short int events;
	short int revents;
};

struct smp_ops {
	void (*smp_prepare_boot_cpu)();
	void (*smp_prepare_cpus)(unsigned int);
	void (*smp_cpus_done)(unsigned int);
	void (*stop_other_cpus)(int);
	void (*crash_stop_other_cpus)();
	void (*smp_send_reschedule)(int);
	int (*cpu_up)(unsigned int, struct task_struct *);
	int (*cpu_disable)();
	void (*cpu_die)(unsigned int);
	void (*play_dead)();
	void (*send_call_func_ipi)(const struct cpumask *);
	void (*send_call_func_single_ipi)(int);
};

enum refcount_saturation_type {
	REFCOUNT_ADD_NOT_ZERO_OVF = 0,
	REFCOUNT_ADD_OVF = 1,
	REFCOUNT_ADD_UAF = 2,
	REFCOUNT_SUB_UAF = 3,
	REFCOUNT_DEC_LEAK = 4,
};

struct wait_queue_entry;

typedef int (*wait_queue_func_t)(struct wait_queue_entry *, unsigned int, int, void *);

struct wait_queue_entry {
	unsigned int flags;
	void *private;
	wait_queue_func_t func;
	struct list_head entry;
};

typedef struct wait_queue_entry wait_queue_entry_t;

struct rcu_work {
	struct work_struct work;
	struct callback_head rcu;
	struct workqueue_struct *wq;
};

struct notifier_block;

typedef int (*notifier_fn_t)(struct notifier_block *, long unsigned int, void *);

struct notifier_block {
	notifier_fn_t notifier_call;
	struct notifier_block *next;
	int priority;
};

struct blocking_notifier_head {
	struct rw_semaphore rwsem;
	struct notifier_block *head;
};

struct raw_notifier_head {
	struct notifier_block *head;
};

struct ldt_struct {
	struct desc_struct *entries;
	unsigned int nr_entries;
	int slot;
};

enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

struct device;

struct page_pool_params {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device *dev;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
	void (*init_callback)(struct page *, void *);
	void *init_arg;
};

struct pp_alloc_cache {
	u32 count;
	struct page *cache[128];
};

struct ptr_ring {
	int producer;
	spinlock_t producer_lock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	int consumer_head;
	int consumer_tail;
	spinlock_t consumer_lock;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	int size;
	int batch;
	void **queue;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct page_pool {
	struct page_pool_params p;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	u32 pages_state_hold_cnt;
	unsigned int frag_offset;
	struct page *frag_page;
	long int frag_users;
	u32 xdp_mem_id;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct pp_alloc_cache alloc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct ptr_ring ring;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct vmem_altmap {
	long unsigned int base_pfn;
	const long unsigned int end_pfn;
	const long unsigned int reserve;
	long unsigned int free;
	long unsigned int align;
	long unsigned int alloc;
};

struct percpu_ref_data;

struct percpu_ref {
	long unsigned int percpu_count_ptr;
	struct percpu_ref_data *data;
};

enum memory_type {
	MEMORY_DEVICE_PRIVATE = 1,
	MEMORY_DEVICE_FS_DAX = 2,
	MEMORY_DEVICE_GENERIC = 3,
	MEMORY_DEVICE_PCI_P2PDMA = 4,
};

struct dev_pagemap_ops;

struct dev_pagemap {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct range ranges[0];
	};
};

struct anon_vma {
	struct anon_vma *root;
	struct rw_semaphore rwsem;
	atomic_t refcount;
	unsigned int degree;
	struct anon_vma *parent;
	struct rb_root_cached rb_root;
};

struct mempolicy {
	atomic_t refcnt;
	short unsigned int mode;
	short unsigned int flags;
	nodemask_t nodes;
	int home_node;
	union {
		nodemask_t cpuset_mems_allowed;
		nodemask_t user_nodemask;
	} w;
};

struct linux_binprm;

struct coredump_params;

struct linux_binfmt {
	struct list_head lh;
	struct module *module;
	int (*load_binary)(struct linux_binprm *);
	int (*load_shlib)(struct file *);
	int (*core_dump)(struct coredump_params *);
	long unsigned int min_coredump;
};

struct free_area {
	struct list_head free_list[5];
	long unsigned int nr_free;
};

struct zone_padding {
	char x[0];
};

struct pglist_data;

struct lruvec {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct pglist_data *pgdat;
};

struct per_cpu_pages;

struct per_cpu_zonestat;

struct zone {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[5];
	int node;
	struct pglist_data *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int present_early_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	seqlock_t span_seqlock;
	int initialized;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct zone_padding _pad1_;
	struct free_area free_area[11];
	long unsigned int flags;
	spinlock_t lock;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct zone_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	short: 16;
	struct zone_padding _pad3_;
	atomic_long_t vm_stat[11];
	atomic_long_t vm_numa_event[6];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct zoneref {
	struct zone *zone;
	int zone_idx;
};

struct zonelist {
	struct zoneref _zonerefs[5121];
};

enum zone_type {
	ZONE_DMA = 0,
	ZONE_DMA32 = 1,
	ZONE_NORMAL = 2,
	ZONE_MOVABLE = 3,
	ZONE_DEVICE = 4,
	__MAX_NR_ZONES = 5,
};

struct deferred_split {
	spinlock_t split_queue_lock;
	struct list_head split_queue;
	long unsigned int split_queue_len;
};

struct per_cpu_nodestat;

struct pglist_data {
	struct zone node_zones[5];
	struct zonelist node_zonelists[2];
	int nr_zones;
	spinlock_t node_size_lock;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct task_struct *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long unsigned int min_unmapped_pages;
	long unsigned int min_slab_pages;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct zone_padding _pad1_;
	struct deferred_split deferred_split_queue;
	struct lruvec __lruvec;
	long unsigned int flags;
	long: 64;
	struct zone_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[41];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct per_cpu_pages {
	int count;
	int high;
	int batch;
	short int free_factor;
	short int expire;
	struct list_head lists[15];
};

struct per_cpu_zonestat {
	s8 vm_stat_diff[11];
	s8 stat_threshold;
	long unsigned int vm_numa_event[6];
};

struct per_cpu_nodestat {
	s8 stat_threshold;
	s8 vm_node_stat_diff[41];
};

enum irq_domain_bus_token {
	DOMAIN_BUS_ANY = 0,
	DOMAIN_BUS_WIRED = 1,
	DOMAIN_BUS_GENERIC_MSI = 2,
	DOMAIN_BUS_PCI_MSI = 3,
	DOMAIN_BUS_PLATFORM_MSI = 4,
	DOMAIN_BUS_NEXUS = 5,
	DOMAIN_BUS_IPI = 6,
	DOMAIN_BUS_FSL_MC_MSI = 7,
	DOMAIN_BUS_TI_SCI_INTA_MSI = 8,
	DOMAIN_BUS_WAKEUP = 9,
	DOMAIN_BUS_VMD_MSI = 10,
};

struct irq_domain_ops;

struct fwnode_handle;

struct irq_domain_chip_generic;

struct irq_data;

struct irq_domain {
	struct list_head link;
	const char *name;
	const struct irq_domain_ops *ops;
	void *host_data;
	unsigned int flags;
	unsigned int mapcount;
	struct fwnode_handle *fwnode;
	enum irq_domain_bus_token bus_token;
	struct irq_domain_chip_generic *gc;
	struct device *dev;
	struct irq_domain *parent;
	irq_hw_number_t hwirq_max;
	unsigned int revmap_size;
	struct xarray revmap_tree;
	struct mutex revmap_mutex;
	struct irq_data *revmap[0];
};

typedef int proc_handler(struct ctl_table *, int, void *, size_t *, loff_t *);

struct ctl_table_poll;

struct ctl_table {
	const char *procname;
	void *data;
	int maxlen;
	umode_t mode;
	struct ctl_table *child;
	proc_handler *proc_handler;
	struct ctl_table_poll *poll;
	void *extra1;
	void *extra2;
};

struct ctl_table_poll {
	atomic_t event;
	wait_queue_head_t wait;
};

struct ctl_node {
	struct rb_node node;
	struct ctl_table_header *header;
};

struct ctl_table_root {
	struct ctl_table_set default_set;
	struct ctl_table_set * (*lookup)(struct ctl_table_root *);
	void (*set_ownership)(struct ctl_table_header *, struct ctl_table *, kuid_t *, kgid_t *);
	int (*permissions)(struct ctl_table_header *, struct ctl_table *);
};

struct idr {
	struct xarray idr_rt;
	unsigned int idr_base;
	unsigned int idr_next;
};

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};

typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
};

struct trace_event_functions;

struct trace_event {
	struct hlist_node node;
	struct list_head list;
	int type;
	struct trace_event_functions *funcs;
};

struct trace_event_class;

struct bpf_prog_array;

struct trace_event_call {
	struct list_head list;
	struct trace_event_class *class;
	union {
		char *name;
		struct tracepoint *tp;
	};
	struct trace_event event;
	char *print_fmt;
	struct event_filter *filter;
	union {
		void *module;
		atomic_t refcnt;
	};
	void *data;
	int flags;
	int perf_refcount;
	struct hlist_head *perf_events;
	struct bpf_prog_array *prog_array;
	int (*perf_perm)(struct trace_event_call *, struct perf_event *);
};

struct trace_eval_map {
	const char *system;
	const char *eval_string;
	long unsigned int eval_value;
};

struct cgroup;

struct cgroup_subsys;

struct cgroup_subsys_state {
	struct cgroup *cgroup;
	struct cgroup_subsys *ss;
	struct percpu_ref refcnt;
	struct list_head sibling;
	struct list_head children;
	struct list_head rstat_css_node;
	int id;
	unsigned int flags;
	u64 serial_nr;
	atomic_t online_cnt;
	struct work_struct destroy_work;
	struct rcu_work destroy_rwork;
	struct cgroup_subsys_state *parent;
};

struct mem_cgroup_id {
	int id;
	refcount_t ref;
};

struct page_counter {
	atomic_long_t usage;
	long unsigned int min;
	long unsigned int low;
	long unsigned int high;
	long unsigned int max;
	long unsigned int emin;
	atomic_long_t min_usage;
	atomic_long_t children_min_usage;
	long unsigned int elow;
	atomic_long_t low_usage;
	atomic_long_t children_low_usage;
	long unsigned int watermark;
	long unsigned int failcnt;
	struct page_counter *parent;
};

struct vmpressure {
	long unsigned int scanned;
	long unsigned int reclaimed;
	long unsigned int tree_scanned;
	long unsigned int tree_reclaimed;
	spinlock_t sr_lock;
	struct list_head events;
	struct mutex events_lock;
	struct work_struct work;
};

struct cgroup_file {
	struct kernfs_node *kn;
	long unsigned int notified_at;
	struct timer_list notify_timer;
};

struct mem_cgroup_threshold_ary;

struct mem_cgroup_thresholds {
	struct mem_cgroup_threshold_ary *primary;
	struct mem_cgroup_threshold_ary *spare;
};

struct memcg_padding {
	char x[0];
};

struct memcg_vmstats {
	long int state[48];
	long unsigned int events[107];
	long int state_pending[48];
	long unsigned int events_pending[107];
};

struct fprop_global {
	struct percpu_counter events;
	unsigned int period;
	seqcount_t sequence;
};

struct wb_domain {
	spinlock_t lock;
	struct fprop_global completions;
	struct timer_list period_timer;
	long unsigned int period_time;
	long unsigned int dirty_limit_tstamp;
	long unsigned int dirty_limit;
};

struct wb_completion {
	atomic_t cnt;
	wait_queue_head_t *waitq;
};

struct memcg_cgwb_frn {
	u64 bdi_id;
	int memcg_id;
	u64 at;
	struct wb_completion done;
};

struct obj_cgroup;

struct memcg_vmstats_percpu;

struct mem_cgroup_per_node;

struct mem_cgroup {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct page_counter kmem;
	struct page_counter tcpmem;
	struct work_struct high_work;
	long unsigned int zswap_max;
	long unsigned int soft_limit;
	struct vmpressure vmpressure;
	bool oom_group;
	bool oom_lock;
	int under_oom;
	int swappiness;
	int oom_kill_disable;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct mutex thresholds_lock;
	struct mem_cgroup_thresholds thresholds;
	struct mem_cgroup_thresholds memsw_thresholds;
	struct list_head oom_notify;
	long unsigned int move_charge_at_immigrate;
	spinlock_t move_lock;
	long unsigned int move_lock_flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct memcg_padding _pad1_;
	struct memcg_vmstats vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	bool tcpmem_active;
	int tcpmem_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct list_head objcg_list;
	long: 64;
	long: 64;
	struct memcg_padding _pad2_;
	atomic_t moving_account;
	struct task_struct *move_lock_task;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct deferred_split deferred_split_queue;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
};

struct fs_pin;

struct pid_namespace {
	struct idr idr;
	struct callback_head rcu;
	unsigned int pid_allocated;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
	struct fs_pin *bacct;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int reboot;
	struct ns_common ns;
};

struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	atomic_t count;
	atomic_long_t ucount[16];
};

struct rhash_head {
	struct rhash_head *next;
};

struct rhashtable;

struct rhashtable_compare_arg {
	struct rhashtable *ht;
	const void *key;
};

typedef u32 (*rht_hashfn_t)(const void *, u32, u32);

typedef u32 (*rht_obj_hashfn_t)(const void *, u32, u32);

typedef int (*rht_obj_cmpfn_t)(struct rhashtable_compare_arg *, const void *);

struct rhashtable_params {
	u16 nelem_hint;
	u16 key_len;
	u16 key_offset;
	u16 head_offset;
	unsigned int max_size;
	u16 min_size;
	bool automatic_shrinking;
	rht_hashfn_t hashfn;
	rht_obj_hashfn_t obj_hashfn;
	rht_obj_cmpfn_t obj_cmpfn;
};

struct bucket_table;

struct rhashtable {
	struct bucket_table *tbl;
	unsigned int key_len;
	unsigned int max_elems;
	struct rhashtable_params p;
	bool rhlist;
	struct work_struct run_work;
	struct mutex mutex;
	spinlock_t lock;
	atomic_t nelems;
};

struct task_cputime {
	u64 stime;
	u64 utime;
	long long unsigned int sum_exec_runtime;
};

struct uts_namespace;

struct ipc_namespace;

struct mnt_namespace;

struct net;

struct time_namespace;

struct cgroup_namespace;

struct nsproxy {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct bio;

struct bio_list {
	struct bio *head;
	struct bio *tail;
};

struct request;

struct blk_plug {
	struct request *mq_list;
	struct request *cached_rq;
	short unsigned int nr_ios;
	short unsigned int rq_count;
	bool multiple_queues;
	bool has_elevator;
	bool nowait;
	struct list_head cb_list;
};

struct reclaim_state {
	long unsigned int reclaimed_slab;
};

struct fprop_local_percpu {
	struct percpu_counter events;
	unsigned int period;
	raw_spinlock_t lock;
};

enum wb_reason {
	WB_REASON_BACKGROUND = 0,
	WB_REASON_VMSCAN = 1,
	WB_REASON_SYNC = 2,
	WB_REASON_PERIODIC = 3,
	WB_REASON_LAPTOP_TIMER = 4,
	WB_REASON_FS_FREE_SPACE = 5,
	WB_REASON_FORKER_THREAD = 6,
	WB_REASON_FOREIGN_FLUSH = 7,
	WB_REASON_MAX = 8,
};

struct bdi_writeback {
	struct backing_dev_info *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int congested;
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	long unsigned int dirty_sleep;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};

struct backing_dev_info {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	struct bdi_writeback wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device *dev;
	char dev_name[64];
	struct device *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry *debug_dir;
};

struct css_set {
	struct cgroup_subsys_state *subsys[14];
	refcount_t refcount;
	struct css_set *dom_cset;
	struct cgroup *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[14];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_preload_node;
	struct list_head mg_node;
	struct cgroup *mg_src_cgrp;
	struct cgroup *mg_dst_cgrp;
	struct css_set *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};

typedef u32 compat_uptr_t;

struct compat_robust_list {
	compat_uptr_t next;
};

typedef s32 compat_long_t;

struct compat_robust_list_head {
	struct compat_robust_list list;
	compat_long_t futex_offset;
	compat_uptr_t list_op_pending;
};

struct perf_event_groups {
	struct rb_root tree;
	u64 index;
};

struct perf_event_context {
	struct pmu *pmu;
	raw_spinlock_t lock;
	struct mutex mutex;
	struct list_head active_ctx_list;
	struct perf_event_groups pinned_groups;
	struct perf_event_groups flexible_groups;
	struct list_head event_list;
	struct list_head pinned_active;
	struct list_head flexible_active;
	int nr_events;
	int nr_active;
	int nr_user;
	int is_active;
	int nr_stat;
	int nr_freq;
	int rotate_disable;
	int rotate_necessary;
	refcount_t refcount;
	struct task_struct *task;
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	struct perf_event_context *parent_ctx;
	u64 parent_gen;
	u64 generation;
	int pin_count;
	int nr_cgroups;
	void *task_ctx_data;
	struct callback_head callback_head;
};

struct pipe_buffer;

struct watch_queue;

struct pipe_inode_info {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	bool note_loss;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page *tmp_page;
	struct fasync_struct *fasync_readers;
	struct fasync_struct *fasync_writers;
	struct pipe_buffer *bufs;
	struct user_struct *user;
	struct watch_queue *watch_queue;
};

struct task_delay_info {
	raw_spinlock_t lock;
	u64 blkio_start;
	u64 blkio_delay;
	u64 swapin_start;
	u64 swapin_delay;
	u32 blkio_count;
	u32 swapin_count;
	u64 freepages_start;
	u64 freepages_delay;
	u64 thrashing_start;
	u64 thrashing_delay;
	u64 compact_start;
	u64 compact_delay;
	u64 wpcopy_start;
	u64 wpcopy_delay;
	u32 freepages_count;
	u32 thrashing_count;
	u32 compact_count;
	u32 wpcopy_count;
};

struct ftrace_ret_stack {
	long unsigned int ret;
	long unsigned int func;
	long long unsigned int calltime;
	long long unsigned int subtime;
	long unsigned int *retp;
};

struct blk_integrity_profile;

struct blk_integrity {
	const struct blk_integrity_profile *profile;
	unsigned char flags;
	unsigned char tuple_size;
	unsigned char interval_exp;
	unsigned char tag_size;
};

enum rpm_status {
	RPM_INVALID = 4294967295,
	RPM_ACTIVE = 0,
	RPM_RESUMING = 1,
	RPM_SUSPENDED = 2,
	RPM_SUSPENDING = 3,
};

enum blk_bounce {
	BLK_BOUNCE_NONE = 0,
	BLK_BOUNCE_HIGH = 1,
};

enum blk_zoned_model {
	BLK_ZONED_NONE = 0,
	BLK_ZONED_HA = 1,
	BLK_ZONED_HM = 2,
};

struct queue_limits {
	enum blk_bounce bounce;
	long unsigned int seg_boundary_mask;
	long unsigned int virt_boundary_mask;
	unsigned int max_hw_sectors;
	unsigned int max_dev_sectors;
	unsigned int chunk_sectors;
	unsigned int max_sectors;
	unsigned int max_segment_size;
	unsigned int physical_block_size;
	unsigned int logical_block_size;
	unsigned int alignment_offset;
	unsigned int io_min;
	unsigned int io_opt;
	unsigned int max_discard_sectors;
	unsigned int max_hw_discard_sectors;
	unsigned int max_secure_erase_sectors;
	unsigned int max_write_zeroes_sectors;
	unsigned int max_zone_append_sectors;
	unsigned int discard_granularity;
	unsigned int discard_alignment;
	unsigned int zone_write_granularity;
	short unsigned int max_segments;
	short unsigned int max_integrity_segments;
	short unsigned int max_discard_segments;
	unsigned char misaligned;
	unsigned char discard_misaligned;
	unsigned char raid_partial_stripes_expensive;
	enum blk_zoned_model zoned;
};

typedef void *mempool_alloc_t(gfp_t, void *);

typedef void mempool_free_t(void *, void *);

struct mempool_s {
	spinlock_t lock;
	int min_nr;
	int curr_nr;
	void **elements;
	void *pool_data;
	mempool_alloc_t *alloc;
	mempool_free_t *free;
	wait_queue_head_t wait;
};

typedef struct mempool_s mempool_t;

struct bio_alloc_cache;

struct bio_set {
	struct kmem_cache *bio_slab;
	unsigned int front_pad;
	struct bio_alloc_cache *cache;
	mempool_t bio_pool;
	mempool_t bvec_pool;
	mempool_t bio_integrity_pool;
	mempool_t bvec_integrity_pool;
	unsigned int back_pad;
	spinlock_t rescue_lock;
	struct bio_list rescue_list;
	struct work_struct rescue_work;
	struct workqueue_struct *rescue_workqueue;
	struct hlist_node cpuhp_dead;
};

struct elevator_queue;

struct blk_queue_stats;

struct rq_qos;

struct blk_mq_ops;

struct blk_mq_ctx;

struct gendisk;

struct blk_crypto_profile;

struct blk_stat_callback;

struct blk_rq_stat;

struct blk_mq_tags;

struct blkcg_gq;

struct blk_trace;

struct blk_flush_queue;

struct throtl_data;

struct blk_mq_tag_set;

struct blk_independent_access_ranges;

struct request_queue {
	struct request *last_merge;
	struct elevator_queue *elevator;
	struct percpu_ref q_usage_counter;
	struct blk_queue_stats *stats;
	struct rq_qos *rq_qos;
	const struct blk_mq_ops *mq_ops;
	struct blk_mq_ctx *queue_ctx;
	unsigned int queue_depth;
	struct xarray hctx_table;
	unsigned int nr_hw_queues;
	void *queuedata;
	long unsigned int queue_flags;
	atomic_t pm_only;
	int id;
	spinlock_t queue_lock;
	struct gendisk *disk;
	struct kobject kobj;
	struct kobject *mq_kobj;
	struct blk_integrity integrity;
	struct device *dev;
	enum rpm_status rpm_status;
	long unsigned int nr_requests;
	unsigned int dma_pad_mask;
	unsigned int dma_alignment;
	struct blk_crypto_profile *crypto_profile;
	struct kobject *crypto_kobject;
	unsigned int rq_timeout;
	int poll_nsec;
	struct blk_stat_callback *poll_cb;
	struct blk_rq_stat *poll_stat;
	struct timer_list timeout;
	struct work_struct timeout_work;
	atomic_t nr_active_requests_shared_tags;
	struct blk_mq_tags *sched_shared_tags;
	struct list_head icq_list;
	long unsigned int blkcg_pols[1];
	struct blkcg_gq *root_blkg;
	struct list_head blkg_list;
	struct queue_limits limits;
	unsigned int required_elevator_features;
	unsigned int nr_zones;
	long unsigned int *conv_zones_bitmap;
	long unsigned int *seq_zones_wlock;
	unsigned int max_open_zones;
	unsigned int max_active_zones;
	int node;
	struct mutex debugfs_mutex;
	struct blk_trace *blk_trace;
	struct blk_flush_queue *fq;
	struct list_head requeue_list;
	spinlock_t requeue_lock;
	struct delayed_work requeue_work;
	struct mutex sysfs_lock;
	struct mutex sysfs_dir_lock;
	struct list_head unused_hctx_list;
	spinlock_t unused_hctx_lock;
	int mq_freeze_depth;
	struct throtl_data *td;
	struct callback_head callback_head;
	wait_queue_head_t mq_freeze_wq;
	struct mutex mq_freeze_lock;
	int quiesce_depth;
	struct blk_mq_tag_set *tag_set;
	struct list_head tag_set_list;
	struct bio_set bio_split;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct dentry *rqos_debugfs_dir;
	bool mq_sysfs_init_done;
	struct blk_independent_access_ranges *ia_ranges;
	struct srcu_struct srcu[0];
};

struct cgroup_base_stat {
	struct task_cputime cputime;
};

struct psi_group_cpu;

struct psi_group {
	struct mutex avgs_lock;
	struct psi_group_cpu *pcpu;
	u64 avg_total[6];
	u64 avg_last_update;
	u64 avg_next_update;
	struct delayed_work avgs_work;
	u64 total[12];
	long unsigned int avg[18];
	struct task_struct *poll_task;
	struct timer_list poll_timer;
	wait_queue_head_t poll_wait;
	atomic_t poll_wakeup;
	struct mutex trigger_lock;
	struct list_head triggers;
	u32 nr_triggers[6];
	u32 poll_states;
	u64 poll_min_period;
	u64 polling_total[6];
	u64 polling_next_update;
	u64 polling_until;
};

struct cgroup_bpf {
	struct bpf_prog_array *effective[23];
	struct list_head progs[23];
	u32 flags[23];
	struct list_head storages;
	struct bpf_prog_array *inactive;
	struct percpu_ref refcnt;
	struct work_struct release_work;
};

struct cgroup_freezer_state {
	bool freeze;
	int e_freeze;
	int nr_frozen_descendants;
	int nr_frozen_tasks;
};

struct cgroup_root;

struct cgroup_rstat_cpu;

struct cgroup {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	struct kernfs_node *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[14];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[14];
	struct cgroup *dom_cgrp;
	struct cgroup *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group psi;
	struct cgroup_bpf bpf;
	atomic_t congestion_count;
	struct cgroup_freezer_state freezer;
	u64 ancestor_ids[0];
};

struct taskstats {
	__u16 version;
	__u32 ac_exitcode;
	__u8 ac_flag;
	__u8 ac_nice;
	__u64 cpu_count;
	__u64 cpu_delay_total;
	__u64 blkio_count;
	__u64 blkio_delay_total;
	__u64 swapin_count;
	__u64 swapin_delay_total;
	__u64 cpu_run_real_total;
	__u64 cpu_run_virtual_total;
	char ac_comm[32];
	__u8 ac_sched;
	__u8 ac_pad[3];
	int: 32;
	__u32 ac_uid;
	__u32 ac_gid;
	__u32 ac_pid;
	__u32 ac_ppid;
	__u32 ac_btime;
	__u64 ac_etime;
	__u64 ac_utime;
	__u64 ac_stime;
	__u64 ac_minflt;
	__u64 ac_majflt;
	__u64 coremem;
	__u64 virtmem;
	__u64 hiwater_rss;
	__u64 hiwater_vm;
	__u64 read_char;
	__u64 write_char;
	__u64 read_syscalls;
	__u64 write_syscalls;
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 cancelled_write_bytes;
	__u64 nvcsw;
	__u64 nivcsw;
	__u64 ac_utimescaled;
	__u64 ac_stimescaled;
	__u64 cpu_scaled_run_real_total;
	__u64 freepages_count;
	__u64 freepages_delay_total;
	__u64 thrashing_count;
	__u64 thrashing_delay_total;
	__u64 ac_btime64;
	__u64 compact_count;
	__u64 compact_delay_total;
	__u32 ac_tgid;
	__u64 ac_tgetime;
	__u64 ac_exe_dev;
	__u64 ac_exe_inode;
	__u64 wpcopy_count;
	__u64 wpcopy_delay_total;
};

typedef struct {
	__u8 b[16];
} guid_t;

typedef void percpu_ref_func_t(struct percpu_ref *);

struct percpu_ref_data {
	atomic_long_t count;
	percpu_ref_func_t *release;
	percpu_ref_func_t *confirm_switch;
	bool force_atomic: 1;
	bool allow_reinit: 1;
	struct callback_head rcu;
	struct percpu_ref *ref;
};

struct wait_page_queue {
	struct folio *folio;
	int bit_nr;
	wait_queue_entry_t wait;
};

enum writeback_sync_modes {
	WB_SYNC_NONE = 0,
	WB_SYNC_ALL = 1,
};

struct swap_iocb;

struct writeback_control {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_fscache_wb: 1;
	unsigned int no_cgroup_owner: 1;
	unsigned int punt_to_cgroup: 1;
	struct swap_iocb **swap_plug;
	struct bdi_writeback *wb;
	struct inode *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};

struct readahead_control {
	struct file *file;
	struct address_space *mapping;
	struct file_ra_state *ra;
	long unsigned int _index;
	unsigned int _nr_pages;
	unsigned int _batch_count;
};

struct iovec;

struct kvec;

struct bio_vec;

struct iov_iter {
	u8 iter_type;
	bool nofault;
	bool data_source;
	size_t iov_offset;
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec *bvec;
		struct xarray *xarray;
		struct pipe_inode_info *pipe;
	};
	union {
		long unsigned int nr_segs;
		struct {
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};

struct swap_cluster_info {
	spinlock_t lock;
	unsigned int data: 24;
	unsigned int flags: 8;
};

struct swap_cluster_list {
	struct swap_cluster_info head;
	struct swap_cluster_info tail;
};

struct percpu_cluster;

struct swap_info_struct {
	struct percpu_ref users;
	long unsigned int flags;
	short int prio;
	struct plist_node list;
	signed char type;
	unsigned int max;
	unsigned char *swap_map;
	struct swap_cluster_info *cluster_info;
	struct swap_cluster_list free_clusters;
	unsigned int lowest_bit;
	unsigned int highest_bit;
	unsigned int pages;
	unsigned int inuse_pages;
	unsigned int cluster_next;
	unsigned int cluster_nr;
	unsigned int *cluster_next_cpu;
	struct percpu_cluster *percpu_cluster;
	struct rb_root swap_extent_root;
	struct block_device *bdev;
	struct file *swap_file;
	unsigned int old_block_size;
	struct completion comp;
	long unsigned int *frontswap_map;
	atomic_t frontswap_pages;
	spinlock_t lock;
	spinlock_t cont_lock;
	struct work_struct discard_work;
	struct swap_cluster_list discard_clusters;
	struct plist_node avail_lists[0];
};

struct cdev {
	struct kobject kobj;
	struct module *owner;
	const struct file_operations *ops;
	struct list_head list;
	dev_t dev;
	unsigned int count;
};

enum dl_dev_state {
	DL_DEV_NO_DRIVER = 0,
	DL_DEV_PROBING = 1,
	DL_DEV_DRIVER_BOUND = 2,
	DL_DEV_UNBINDING = 3,
};

struct dev_links_info {
	struct list_head suppliers;
	struct list_head consumers;
	struct list_head defer_sync;
	enum dl_dev_state status;
};

struct pm_message {
	int event;
};

typedef struct pm_message pm_message_t;

enum rpm_request {
	RPM_REQ_NONE = 0,
	RPM_REQ_IDLE = 1,
	RPM_REQ_SUSPEND = 2,
	RPM_REQ_AUTOSUSPEND = 3,
	RPM_REQ_RESUME = 4,
};

struct wakeup_source;

struct wake_irq;

struct pm_subsys_data;

struct dev_pm_qos;

struct dev_pm_info {
	pm_message_t power_state;
	unsigned int can_wakeup: 1;
	unsigned int async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	struct list_head entry;
	struct completion completion;
	struct wakeup_source *wakeup;
	bool wakeup_path: 1;
	bool syscore: 1;
	bool no_pm_callbacks: 1;
	unsigned int must_resume: 1;
	unsigned int may_skip_resume: 1;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	unsigned int idle_notification: 1;
	unsigned int request_pending: 1;
	unsigned int deferred_resume: 1;
	unsigned int needs_force_resume: 1;
	unsigned int runtime_auto: 1;
	bool ignore_children: 1;
	unsigned int no_callbacks: 1;
	unsigned int irq_safe: 1;
	unsigned int use_autosuspend: 1;
	unsigned int timer_autosuspends: 1;
	unsigned int memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device *, s32);
	struct dev_pm_qos *qos;
};

struct msi_device_data;

struct dev_msi_info {
	struct irq_domain *domain;
	struct msi_device_data *data;
};

struct dev_archdata {};

enum device_removable {
	DEVICE_REMOVABLE_NOT_SUPPORTED = 0,
	DEVICE_REMOVABLE_UNKNOWN = 1,
	DEVICE_FIXED = 2,
	DEVICE_REMOVABLE = 3,
};

struct device_private;

struct device_type;

struct bus_type;

struct device_driver;

struct dev_pm_domain;

struct em_perf_domain;

struct dev_pin_info;

struct dma_map_ops;

struct bus_dma_region;

struct device_dma_parameters;

struct io_tlb_mem;

struct device_node;

struct class;

struct iommu_group;

struct dev_iommu;

struct device_physical_location;

struct device {
	struct kobject kobj;
	struct device *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type *type;
	struct bus_type *bus;
	struct device_driver *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info power;
	struct dev_pm_domain *pm_domain;
	struct em_perf_domain *em_pd;
	struct dev_pin_info *pins;
	struct dev_msi_info msi;
	const struct dma_map_ops *dma_ops;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle *fwnode;
	int numa_node;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	struct class *class;
	const struct attribute_group **groups;
	void (*release)(struct device *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
};

struct disk_stats;

struct partition_meta_info;

struct block_device {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	bool bd_read_only;
	dev_t bd_dev;
	atomic_t bd_openers;
	struct inode *bd_inode;
	struct super_block *bd_super;
	void *bd_claiming;
	struct device bd_device;
	void *bd_holder;
	int bd_holders;
	bool bd_write_holder;
	struct kobject *bd_holder_dir;
	u8 bd_partno;
	spinlock_t bd_size_lock;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	int bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct super_block *bd_fsfreeze_sb;
	struct partition_meta_info *bd_meta_info;
};

struct io_comp_batch {
	struct request *req_list;
	bool need_ts;
	void (*complete)(struct io_comp_batch *);
};

struct fc_log;

struct p_log {
	const char *prefix;
	struct fc_log *log;
};

enum fs_context_purpose {
	FS_CONTEXT_FOR_MOUNT = 0,
	FS_CONTEXT_FOR_SUBMOUNT = 1,
	FS_CONTEXT_FOR_RECONFIGURE = 2,
};

enum fs_context_phase {
	FS_CONTEXT_CREATE_PARAMS = 0,
	FS_CONTEXT_CREATING = 1,
	FS_CONTEXT_AWAITING_MOUNT = 2,
	FS_CONTEXT_AWAITING_RECONF = 3,
	FS_CONTEXT_RECONF_PARAMS = 4,
	FS_CONTEXT_RECONFIGURING = 5,
	FS_CONTEXT_FAILED = 6,
};

struct fs_context_operations;

struct fs_context {
	const struct fs_context_operations *ops;
	struct mutex uapi_mutex;
	struct file_system_type *fs_type;
	void *fs_private;
	void *sget_key;
	struct dentry *root;
	struct user_namespace *user_ns;
	struct net *net_ns;
	const struct cred *cred;
	struct p_log log;
	const char *source;
	void *security;
	void *s_fs_info;
	unsigned int sb_flags;
	unsigned int sb_flags_mask;
	unsigned int s_iflags;
	unsigned int lsm_flags;
	enum fs_context_purpose purpose: 8;
	enum fs_context_phase phase: 8;
	bool need_free: 1;
	bool global: 1;
	bool oldapi: 1;
};

struct audit_names;

struct filename {
	const char *name;
	const char *uptr;
	int refcnt;
	struct audit_names *aname;
	const char iname[0];
};

typedef u8 blk_status_t;

struct bvec_iter {
	sector_t bi_sector;
	unsigned int bi_size;
	unsigned int bi_idx;
	unsigned int bi_bvec_done;
} __attribute__((packed));

typedef unsigned int blk_qc_t;

typedef void bio_end_io_t(struct bio *);

struct bio_issue {
	u64 value;
};

struct bio_vec {
	struct page *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct bio_crypt_ctx;

struct bio_integrity_payload;

struct bio {
	struct bio *bi_next;
	struct block_device *bi_bdev;
	unsigned int bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	struct bio_crypt_ctx *bi_crypt_context;
	union {
		struct bio_integrity_payload *bi_integrity;
	};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec bi_inline_vecs[0];
};

struct linux_binprm {
	struct vm_area_struct *vma;
	long unsigned int vma_pages;
	struct mm_struct *mm;
	long unsigned int p;
	long unsigned int argmin;
	unsigned int have_execfd: 1;
	unsigned int execfd_creds: 1;
	unsigned int secureexec: 1;
	unsigned int point_of_no_return: 1;
	struct file *executable;
	struct file *interpreter;
	struct file *file;
	struct cred *cred;
	int unsafe;
	unsigned int per_clear;
	int argc;
	int envc;
	const char *filename;
	const char *interp;
	const char *fdpath;
	unsigned int interp_flags;
	int execfd;
	long unsigned int loader;
	long unsigned int exec;
	struct rlimit rlim_stack;
	char buf[256];
};

struct em_perf_state {
	long unsigned int frequency;
	long unsigned int power;
	long unsigned int cost;
	long unsigned int flags;
};

struct em_perf_domain {
	struct em_perf_state *table;
	int nr_perf_states;
	long unsigned int flags;
	long unsigned int cpus[0];
};

struct dev_pm_ops {
	int (*prepare)(struct device *);
	void (*complete)(struct device *);
	int (*suspend)(struct device *);
	int (*resume)(struct device *);
	int (*freeze)(struct device *);
	int (*thaw)(struct device *);
	int (*poweroff)(struct device *);
	int (*restore)(struct device *);
	int (*suspend_late)(struct device *);
	int (*resume_early)(struct device *);
	int (*freeze_late)(struct device *);
	int (*thaw_early)(struct device *);
	int (*poweroff_late)(struct device *);
	int (*restore_early)(struct device *);
	int (*suspend_noirq)(struct device *);
	int (*resume_noirq)(struct device *);
	int (*freeze_noirq)(struct device *);
	int (*thaw_noirq)(struct device *);
	int (*poweroff_noirq)(struct device *);
	int (*restore_noirq)(struct device *);
	int (*runtime_suspend)(struct device *);
	int (*runtime_resume)(struct device *);
	int (*runtime_idle)(struct device *);
};

struct pm_domain_data;

struct pm_subsys_data {
	spinlock_t lock;
	unsigned int refcount;
	unsigned int clock_op_might_sleep;
	struct mutex clock_mutex;
	struct list_head clock_list;
	struct pm_domain_data *domain_data;
};

struct wakeup_source {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
};

struct dev_pm_domain {
	struct dev_pm_ops ops;
	int (*start)(struct device *);
	void (*detach)(struct device *, bool);
	int (*activate)(struct device *);
	void (*sync)(struct device *);
	void (*dismiss)(struct device *);
};

struct iommu_ops;

struct subsys_private;

struct bus_type {
	const char *name;
	const char *dev_name;
	struct device *dev_root;
	const struct attribute_group **bus_groups;
	const struct attribute_group **dev_groups;
	const struct attribute_group **drv_groups;
	int (*match)(struct device *, struct device_driver *);
	int (*uevent)(struct device *, struct kobj_uevent_env *);
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	void (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*online)(struct device *);
	int (*offline)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	int (*num_vf)(struct device *);
	int (*dma_configure)(struct device *);
	void (*dma_cleanup)(struct device *);
	const struct dev_pm_ops *pm;
	const struct iommu_ops *iommu_ops;
	struct subsys_private *p;
	struct lock_class_key lock_key;
	bool need_parent_lock;
};

enum probe_type {
	PROBE_DEFAULT_STRATEGY = 0,
	PROBE_PREFER_ASYNCHRONOUS = 1,
	PROBE_FORCE_SYNCHRONOUS = 2,
};

struct of_device_id;

struct acpi_device_id;

struct driver_private;

struct device_driver {
	const char *name;
	struct bus_type *bus;
	struct module *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	int (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	const struct dev_pm_ops *pm;
	void (*coredump)(struct device *);
	struct driver_private *p;
};

enum iommu_cap {
	IOMMU_CAP_CACHE_COHERENCY = 0,
	IOMMU_CAP_INTR_REMAP = 1,
	IOMMU_CAP_NOEXEC = 2,
	IOMMU_CAP_PRE_BOOT_PROTECTION = 3,
};

enum iommu_dev_features {
	IOMMU_DEV_FEAT_SVA = 0,
	IOMMU_DEV_FEAT_IOPF = 1,
};

struct iommu_domain;

struct iommu_device;

struct of_phandle_args;

struct iommu_sva;

struct iommu_fault_event;

struct iommu_page_response;

struct iommu_domain_ops;

struct iommu_ops {
	bool (*capable)(enum iommu_cap);
	struct iommu_domain * (*domain_alloc)(unsigned int);
	struct iommu_device * (*probe_device)(struct device *);
	void (*release_device)(struct device *);
	void (*probe_finalize)(struct device *);
	struct iommu_group * (*device_group)(struct device *);
	void (*get_resv_regions)(struct device *, struct list_head *);
	void (*put_resv_regions)(struct device *, struct list_head *);
	int (*of_xlate)(struct device *, struct of_phandle_args *);
	bool (*is_attach_deferred)(struct device *);
	bool (*dev_has_feat)(struct device *, enum iommu_dev_features);
	bool (*dev_feat_enabled)(struct device *, enum iommu_dev_features);
	int (*dev_enable_feat)(struct device *, enum iommu_dev_features);
	int (*dev_disable_feat)(struct device *, enum iommu_dev_features);
	struct iommu_sva * (*sva_bind)(struct device *, struct mm_struct *, void *);
	void (*sva_unbind)(struct iommu_sva *);
	u32 (*sva_get_pasid)(struct iommu_sva *);
	int (*page_response)(struct device *, struct iommu_fault_event *, struct iommu_page_response *);
	int (*def_domain_type)(struct device *);
	const struct iommu_domain_ops *default_domain_ops;
	long unsigned int pgsize_bitmap;
	struct module *owner;
};

struct device_type {
	const char *name;
	const struct attribute_group **groups;
	int (*uevent)(struct device *, struct kobj_uevent_env *);
	char * (*devnode)(struct device *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device *);
	const struct dev_pm_ops *pm;
};

struct class {
	const char *name;
	struct module *owner;
	const struct attribute_group **class_groups;
	const struct attribute_group **dev_groups;
	struct kobject *dev_kobj;
	int (*dev_uevent)(struct device *, struct kobj_uevent_env *);
	char * (*devnode)(struct device *, umode_t *);
	void (*class_release)(struct class *);
	void (*dev_release)(struct device *);
	int (*shutdown_pre)(struct device *);
	const struct kobj_ns_type_operations *ns_type;
	const void * (*namespace)(struct device *);
	void (*get_ownership)(struct device *, kuid_t *, kgid_t *);
	const struct dev_pm_ops *pm;
	struct subsys_private *p;
};

struct of_device_id {
	char name[32];
	char type[32];
	char compatible[128];
	const void *data;
};

typedef long unsigned int kernel_ulong_t;

struct acpi_device_id {
	__u8 id[16];
	kernel_ulong_t driver_data;
	__u32 cls;
	__u32 cls_msk;
};

struct device_dma_parameters {
	unsigned int max_segment_size;
	unsigned int min_align_mask;
	long unsigned int segment_boundary_mask;
};

enum device_physical_location_panel {
	DEVICE_PANEL_TOP = 0,
	DEVICE_PANEL_BOTTOM = 1,
	DEVICE_PANEL_LEFT = 2,
	DEVICE_PANEL_RIGHT = 3,
	DEVICE_PANEL_FRONT = 4,
	DEVICE_PANEL_BACK = 5,
	DEVICE_PANEL_UNKNOWN = 6,
};

enum device_physical_location_vertical_position {
	DEVICE_VERT_POS_UPPER = 0,
	DEVICE_VERT_POS_CENTER = 1,
	DEVICE_VERT_POS_LOWER = 2,
};

enum device_physical_location_horizontal_position {
	DEVICE_HORI_POS_LEFT = 0,
	DEVICE_HORI_POS_CENTER = 1,
	DEVICE_HORI_POS_RIGHT = 2,
};

struct device_physical_location {
	enum device_physical_location_panel panel;
	enum device_physical_location_vertical_position vertical_position;
	enum device_physical_location_horizontal_position horizontal_position;
	bool dock;
	bool lid;
};

typedef u64 dma_addr_t;

struct sg_table;

struct scatterlist;

struct dma_map_ops {
	void * (*alloc)(struct device *, size_t, dma_addr_t *, gfp_t, long unsigned int);
	void (*free)(struct device *, size_t, void *, dma_addr_t, long unsigned int);
	struct page * (*alloc_pages)(struct device *, size_t, dma_addr_t *, enum dma_data_direction, gfp_t);
	void (*free_pages)(struct device *, size_t, struct page *, dma_addr_t, enum dma_data_direction);
	struct sg_table * (*alloc_noncontiguous)(struct device *, size_t, enum dma_data_direction, gfp_t, long unsigned int);
	void (*free_noncontiguous)(struct device *, size_t, struct sg_table *, enum dma_data_direction);
	int (*mmap)(struct device *, struct vm_area_struct *, void *, dma_addr_t, size_t, long unsigned int);
	int (*get_sgtable)(struct device *, struct sg_table *, void *, dma_addr_t, size_t, long unsigned int);
	dma_addr_t (*map_page)(struct device *, struct page *, long unsigned int, size_t, enum dma_data_direction, long unsigned int);
	void (*unmap_page)(struct device *, dma_addr_t, size_t, enum dma_data_direction, long unsigned int);
	int (*map_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, long unsigned int);
	void (*unmap_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, long unsigned int);
	dma_addr_t (*map_resource)(struct device *, phys_addr_t, size_t, enum dma_data_direction, long unsigned int);
	void (*unmap_resource)(struct device *, dma_addr_t, size_t, enum dma_data_direction, long unsigned int);
	void (*sync_single_for_cpu)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_single_for_device)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_sg_for_cpu)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*sync_sg_for_device)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*cache_sync)(struct device *, void *, size_t, enum dma_data_direction);
	int (*dma_supported)(struct device *, u64);
	u64 (*get_required_mask)(struct device *);
	size_t (*max_mapping_size)(struct device *);
	long unsigned int (*get_merge_boundary)(struct device *);
};

struct bus_dma_region {
	phys_addr_t cpu_start;
	dma_addr_t dma_start;
	u64 size;
	u64 offset;
};

typedef u32 phandle;

struct fwnode_operations;

struct fwnode_handle {
	struct fwnode_handle *secondary;
	const struct fwnode_operations *ops;
	struct device *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct property;

struct device_node {
	const char *name;
	phandle phandle;
	const char *full_name;
	struct fwnode_handle fwnode;
	struct property *properties;
	struct property *deadprops;
	struct device_node *parent;
	struct device_node *child;
	struct device_node *sibling;
	long unsigned int _flags;
	void *data;
};

enum cpuhp_state {
	CPUHP_INVALID = 4294967295,
	CPUHP_OFFLINE = 0,
	CPUHP_CREATE_THREADS = 1,
	CPUHP_PERF_PREPARE = 2,
	CPUHP_PERF_X86_PREPARE = 3,
	CPUHP_PERF_X86_AMD_UNCORE_PREP = 4,
	CPUHP_PERF_POWER = 5,
	CPUHP_PERF_SUPERH = 6,
	CPUHP_X86_HPET_DEAD = 7,
	CPUHP_X86_APB_DEAD = 8,
	CPUHP_X86_MCE_DEAD = 9,
	CPUHP_VIRT_NET_DEAD = 10,
	CPUHP_SLUB_DEAD = 11,
	CPUHP_DEBUG_OBJ_DEAD = 12,
	CPUHP_MM_WRITEBACK_DEAD = 13,
	CPUHP_MM_DEMOTION_DEAD = 14,
	CPUHP_MM_VMSTAT_DEAD = 15,
	CPUHP_SOFTIRQ_DEAD = 16,
	CPUHP_NET_MVNETA_DEAD = 17,
	CPUHP_CPUIDLE_DEAD = 18,
	CPUHP_ARM64_FPSIMD_DEAD = 19,
	CPUHP_ARM_OMAP_WAKE_DEAD = 20,
	CPUHP_IRQ_POLL_DEAD = 21,
	CPUHP_BLOCK_SOFTIRQ_DEAD = 22,
	CPUHP_BIO_DEAD = 23,
	CPUHP_ACPI_CPUDRV_DEAD = 24,
	CPUHP_S390_PFAULT_DEAD = 25,
	CPUHP_BLK_MQ_DEAD = 26,
	CPUHP_FS_BUFF_DEAD = 27,
	CPUHP_PRINTK_DEAD = 28,
	CPUHP_MM_MEMCQ_DEAD = 29,
	CPUHP_XFS_DEAD = 30,
	CPUHP_PERCPU_CNT_DEAD = 31,
	CPUHP_RADIX_DEAD = 32,
	CPUHP_PAGE_ALLOC = 33,
	CPUHP_NET_DEV_DEAD = 34,
	CPUHP_PCI_XGENE_DEAD = 35,
	CPUHP_IOMMU_IOVA_DEAD = 36,
	CPUHP_LUSTRE_CFS_DEAD = 37,
	CPUHP_AP_ARM_CACHE_B15_RAC_DEAD = 38,
	CPUHP_PADATA_DEAD = 39,
	CPUHP_AP_DTPM_CPU_DEAD = 40,
	CPUHP_RANDOM_PREPARE = 41,
	CPUHP_WORKQUEUE_PREP = 42,
	CPUHP_POWER_NUMA_PREPARE = 43,
	CPUHP_HRTIMERS_PREPARE = 44,
	CPUHP_PROFILE_PREPARE = 45,
	CPUHP_X2APIC_PREPARE = 46,
	CPUHP_SMPCFD_PREPARE = 47,
	CPUHP_RELAY_PREPARE = 48,
	CPUHP_SLAB_PREPARE = 49,
	CPUHP_MD_RAID5_PREPARE = 50,
	CPUHP_RCUTREE_PREP = 51,
	CPUHP_CPUIDLE_COUPLED_PREPARE = 52,
	CPUHP_POWERPC_PMAC_PREPARE = 53,
	CPUHP_POWERPC_MMU_CTX_PREPARE = 54,
	CPUHP_XEN_PREPARE = 55,
	CPUHP_XEN_EVTCHN_PREPARE = 56,
	CPUHP_ARM_SHMOBILE_SCU_PREPARE = 57,
	CPUHP_SH_SH3X_PREPARE = 58,
	CPUHP_NET_FLOW_PREPARE = 59,
	CPUHP_TOPOLOGY_PREPARE = 60,
	CPUHP_NET_IUCV_PREPARE = 61,
	CPUHP_ARM_BL_PREPARE = 62,
	CPUHP_TRACE_RB_PREPARE = 63,
	CPUHP_MM_ZS_PREPARE = 64,
	CPUHP_MM_ZSWP_MEM_PREPARE = 65,
	CPUHP_MM_ZSWP_POOL_PREPARE = 66,
	CPUHP_KVM_PPC_BOOK3S_PREPARE = 67,
	CPUHP_ZCOMP_PREPARE = 68,
	CPUHP_TIMERS_PREPARE = 69,
	CPUHP_MIPS_SOC_PREPARE = 70,
	CPUHP_LOONGARCH_SOC_PREPARE = 71,
	CPUHP_BP_PREPARE_DYN = 72,
	CPUHP_BP_PREPARE_DYN_END = 92,
	CPUHP_BRINGUP_CPU = 93,
	CPUHP_AP_IDLE_DEAD = 94,
	CPUHP_AP_OFFLINE = 95,
	CPUHP_AP_SCHED_STARTING = 96,
	CPUHP_AP_RCUTREE_DYING = 97,
	CPUHP_AP_CPU_PM_STARTING = 98,
	CPUHP_AP_IRQ_GIC_STARTING = 99,
	CPUHP_AP_IRQ_HIP04_STARTING = 100,
	CPUHP_AP_IRQ_APPLE_AIC_STARTING = 101,
	CPUHP_AP_IRQ_ARMADA_XP_STARTING = 102,
	CPUHP_AP_IRQ_BCM2836_STARTING = 103,
	CPUHP_AP_IRQ_MIPS_GIC_STARTING = 104,
	CPUHP_AP_IRQ_RISCV_STARTING = 105,
	CPUHP_AP_IRQ_SIFIVE_PLIC_STARTING = 106,
	CPUHP_AP_ARM_MVEBU_COHERENCY = 107,
	CPUHP_AP_MICROCODE_LOADER = 108,
	CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING = 109,
	CPUHP_AP_PERF_X86_STARTING = 110,
	CPUHP_AP_PERF_X86_AMD_IBS_STARTING = 111,
	CPUHP_AP_PERF_X86_CQM_STARTING = 112,
	CPUHP_AP_PERF_X86_CSTATE_STARTING = 113,
	CPUHP_AP_PERF_XTENSA_STARTING = 114,
	CPUHP_AP_MIPS_OP_LOONGSON3_STARTING = 115,
	CPUHP_AP_ARM_SDEI_STARTING = 116,
	CPUHP_AP_ARM_VFP_STARTING = 117,
	CPUHP_AP_ARM64_DEBUG_MONITORS_STARTING = 118,
	CPUHP_AP_PERF_ARM_HW_BREAKPOINT_STARTING = 119,
	CPUHP_AP_PERF_ARM_ACPI_STARTING = 120,
	CPUHP_AP_PERF_ARM_STARTING = 121,
	CPUHP_AP_PERF_RISCV_STARTING = 122,
	CPUHP_AP_ARM_L2X0_STARTING = 123,
	CPUHP_AP_EXYNOS4_MCT_TIMER_STARTING = 124,
	CPUHP_AP_ARM_ARCH_TIMER_STARTING = 125,
	CPUHP_AP_ARM_GLOBAL_TIMER_STARTING = 126,
	CPUHP_AP_JCORE_TIMER_STARTING = 127,
	CPUHP_AP_ARM_TWD_STARTING = 128,
	CPUHP_AP_QCOM_TIMER_STARTING = 129,
	CPUHP_AP_TEGRA_TIMER_STARTING = 130,
	CPUHP_AP_ARMADA_TIMER_STARTING = 131,
	CPUHP_AP_MARCO_TIMER_STARTING = 132,
	CPUHP_AP_MIPS_GIC_TIMER_STARTING = 133,
	CPUHP_AP_ARC_TIMER_STARTING = 134,
	CPUHP_AP_RISCV_TIMER_STARTING = 135,
	CPUHP_AP_CLINT_TIMER_STARTING = 136,
	CPUHP_AP_CSKY_TIMER_STARTING = 137,
	CPUHP_AP_TI_GP_TIMER_STARTING = 138,
	CPUHP_AP_HYPERV_TIMER_STARTING = 139,
	CPUHP_AP_KVM_STARTING = 140,
	CPUHP_AP_KVM_ARM_VGIC_INIT_STARTING = 141,
	CPUHP_AP_KVM_ARM_VGIC_STARTING = 142,
	CPUHP_AP_KVM_ARM_TIMER_STARTING = 143,
	CPUHP_AP_DUMMY_TIMER_STARTING = 144,
	CPUHP_AP_ARM_XEN_STARTING = 145,
	CPUHP_AP_ARM_CORESIGHT_STARTING = 146,
	CPUHP_AP_ARM_CORESIGHT_CTI_STARTING = 147,
	CPUHP_AP_ARM64_ISNDEP_STARTING = 148,
	CPUHP_AP_SMPCFD_DYING = 149,
	CPUHP_AP_X86_TBOOT_DYING = 150,
	CPUHP_AP_ARM_CACHE_B15_RAC_DYING = 151,
	CPUHP_AP_ONLINE = 152,
	CPUHP_TEARDOWN_CPU = 153,
	CPUHP_AP_ONLINE_IDLE = 154,
	CPUHP_AP_SCHED_WAIT_EMPTY = 155,
	CPUHP_AP_SMPBOOT_THREADS = 156,
	CPUHP_AP_X86_VDSO_VMA_ONLINE = 157,
	CPUHP_AP_IRQ_AFFINITY_ONLINE = 158,
	CPUHP_AP_BLK_MQ_ONLINE = 159,
	CPUHP_AP_ARM_MVEBU_SYNC_CLOCKS = 160,
	CPUHP_AP_X86_INTEL_EPB_ONLINE = 161,
	CPUHP_AP_PERF_ONLINE = 162,
	CPUHP_AP_PERF_X86_ONLINE = 163,
	CPUHP_AP_PERF_X86_UNCORE_ONLINE = 164,
	CPUHP_AP_PERF_X86_AMD_UNCORE_ONLINE = 165,
	CPUHP_AP_PERF_X86_AMD_POWER_ONLINE = 166,
	CPUHP_AP_PERF_X86_RAPL_ONLINE = 167,
	CPUHP_AP_PERF_X86_CQM_ONLINE = 168,
	CPUHP_AP_PERF_X86_CSTATE_ONLINE = 169,
	CPUHP_AP_PERF_X86_IDXD_ONLINE = 170,
	CPUHP_AP_PERF_S390_CF_ONLINE = 171,
	CPUHP_AP_PERF_S390_SF_ONLINE = 172,
	CPUHP_AP_PERF_ARM_CCI_ONLINE = 173,
	CPUHP_AP_PERF_ARM_CCN_ONLINE = 174,
	CPUHP_AP_PERF_ARM_HISI_CPA_ONLINE = 175,
	CPUHP_AP_PERF_ARM_HISI_DDRC_ONLINE = 176,
	CPUHP_AP_PERF_ARM_HISI_HHA_ONLINE = 177,
	CPUHP_AP_PERF_ARM_HISI_L3_ONLINE = 178,
	CPUHP_AP_PERF_ARM_HISI_PA_ONLINE = 179,
	CPUHP_AP_PERF_ARM_HISI_SLLC_ONLINE = 180,
	CPUHP_AP_PERF_ARM_HISI_PCIE_PMU_ONLINE = 181,
	CPUHP_AP_PERF_ARM_L2X0_ONLINE = 182,
	CPUHP_AP_PERF_ARM_QCOM_L2_ONLINE = 183,
	CPUHP_AP_PERF_ARM_QCOM_L3_ONLINE = 184,
	CPUHP_AP_PERF_ARM_APM_XGENE_ONLINE = 185,
	CPUHP_AP_PERF_ARM_CAVIUM_TX2_UNCORE_ONLINE = 186,
	CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE = 187,
	CPUHP_AP_PERF_POWERPC_NEST_IMC_ONLINE = 188,
	CPUHP_AP_PERF_POWERPC_CORE_IMC_ONLINE = 189,
	CPUHP_AP_PERF_POWERPC_THREAD_IMC_ONLINE = 190,
	CPUHP_AP_PERF_POWERPC_TRACE_IMC_ONLINE = 191,
	CPUHP_AP_PERF_POWERPC_HV_24x7_ONLINE = 192,
	CPUHP_AP_PERF_POWERPC_HV_GPCI_ONLINE = 193,
	CPUHP_AP_PERF_CSKY_ONLINE = 194,
	CPUHP_AP_WATCHDOG_ONLINE = 195,
	CPUHP_AP_WORKQUEUE_ONLINE = 196,
	CPUHP_AP_RANDOM_ONLINE = 197,
	CPUHP_AP_RCUTREE_ONLINE = 198,
	CPUHP_AP_BASE_CACHEINFO_ONLINE = 199,
	CPUHP_AP_ONLINE_DYN = 200,
	CPUHP_AP_ONLINE_DYN_END = 230,
	CPUHP_AP_MM_DEMOTION_ONLINE = 231,
	CPUHP_AP_X86_HPET_ONLINE = 232,
	CPUHP_AP_X86_KVM_CLK_ONLINE = 233,
	CPUHP_AP_ACTIVE = 234,
	CPUHP_ONLINE = 235,
};

struct ring_buffer_event {
	u32 type_len: 5;
	u32 time_delta: 27;
	u32 array[0];
};

struct seq_buf {
	char *buffer;
	size_t size;
	size_t len;
	loff_t readpos;
};

struct trace_seq {
	char buffer[4096];
	struct seq_buf seq;
	int full;
};

enum perf_sw_ids {
	PERF_COUNT_SW_CPU_CLOCK = 0,
	PERF_COUNT_SW_TASK_CLOCK = 1,
	PERF_COUNT_SW_PAGE_FAULTS = 2,
	PERF_COUNT_SW_CONTEXT_SWITCHES = 3,
	PERF_COUNT_SW_CPU_MIGRATIONS = 4,
	PERF_COUNT_SW_PAGE_FAULTS_MIN = 5,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6,
	PERF_COUNT_SW_ALIGNMENT_FAULTS = 7,
	PERF_COUNT_SW_EMULATION_FAULTS = 8,
	PERF_COUNT_SW_DUMMY = 9,
	PERF_COUNT_SW_BPF_OUTPUT = 10,
	PERF_COUNT_SW_CGROUP_SWITCHES = 11,
	PERF_COUNT_SW_MAX = 12,
};

union perf_mem_data_src {
	__u64 val;
	struct {
		__u64 mem_op: 5;
		__u64 mem_lvl: 14;
		__u64 mem_snoop: 5;
		__u64 mem_lock: 2;
		__u64 mem_dtlb: 7;
		__u64 mem_lvl_num: 4;
		__u64 mem_remote: 1;
		__u64 mem_snoopx: 2;
		__u64 mem_blk: 3;
		__u64 mem_hops: 3;
		__u64 mem_rsvd: 18;
	};
};

struct perf_branch_entry {
	__u64 from;
	__u64 to;
	__u64 mispred: 1;
	__u64 predicted: 1;
	__u64 in_tx: 1;
	__u64 abort: 1;
	__u64 cycles: 16;
	__u64 type: 4;
	__u64 reserved: 40;
};

union perf_sample_weight {
	__u64 full;
	struct {
		__u32 var1_dw;
		__u16 var2_w;
		__u16 var3_w;
	};
};

struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

struct uts_namespace {
	struct new_utsname name;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
};

struct ref_tracker_dir {};

struct prot_inuse;

struct netns_core {
	struct ctl_table_header *sysctl_hdr;
	int sysctl_somaxconn;
	u8 sysctl_txrehash;
	struct prot_inuse *prot_inuse;
};

struct ipstats_mib;

struct tcp_mib;

struct linux_mib;

struct udp_mib;

struct linux_xfrm_mib;

struct linux_tls_mib;

struct mptcp_mib;

struct icmp_mib;

struct icmpmsg_mib;

struct icmpv6_mib;

struct icmpv6msg_mib;

struct proc_dir_entry;

struct netns_mib {
	struct ipstats_mib *ip_statistics;
	struct ipstats_mib *ipv6_statistics;
	struct tcp_mib *tcp_statistics;
	struct linux_mib *net_statistics;
	struct udp_mib *udp_statistics;
	struct udp_mib *udp_stats_in6;
	struct linux_xfrm_mib *xfrm_statistics;
	struct linux_tls_mib *tls_statistics;
	struct mptcp_mib *mptcp_statistics;
	struct udp_mib *udplite_statistics;
	struct udp_mib *udplite_stats_in6;
	struct icmp_mib *icmp_statistics;
	struct icmpmsg_mib *icmpmsg_statistics;
	struct icmpv6_mib *icmpv6_statistics;
	struct icmpv6msg_mib *icmpv6msg_statistics;
	struct proc_dir_entry *proc_net_devsnmp6;
};

struct netns_packet {
	struct mutex sklist_lock;
	struct hlist_head sklist;
};

struct netns_unix {
	int sysctl_max_dgram_qlen;
	struct ctl_table_header *ctl;
};

struct netns_nexthop {
	struct rb_root rb_root;
	struct hlist_head *devhash;
	unsigned int seq;
	u32 last_id_allocated;
	struct blocking_notifier_head notifier_chain;
};

struct local_ports {
	seqlock_t lock;
	int range[2];
	bool warned;
};

struct ping_group_range {
	seqlock_t lock;
	kgid_t range[2];
};

typedef struct {
	u64 key[2];
} siphash_key_t;

struct inet_timewait_death_row;

struct ipv4_devconf;

struct ip_ra_chain;

struct fib_rules_ops;

struct fib_table;

struct inet_peer_base;

struct fqdir;

struct tcp_congestion_ops;

struct tcp_fastopen_context;

struct fib_notifier_ops;

struct netns_ipv4 {
	struct inet_timewait_death_row *tcp_death_row;
	struct ctl_table_header *forw_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *ipv4_hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *xfrm4_hdr;
	struct ipv4_devconf *devconf_all;
	struct ipv4_devconf *devconf_dflt;
	struct ip_ra_chain *ra_chain;
	struct mutex ra_mutex;
	struct fib_rules_ops *rules_ops;
	struct fib_table *fib_main;
	struct fib_table *fib_default;
	unsigned int fib_rules_require_fldissect;
	bool fib_has_custom_rules;
	bool fib_has_custom_local_routes;
	bool fib_offload_disabled;
	atomic_t fib_num_tclassid_users;
	struct hlist_head *fib_table_hash;
	struct sock *fibnl;
	struct sock *mc_autojoin_sk;
	struct inet_peer_base *peers;
	struct fqdir *fqdir;
	u8 sysctl_icmp_echo_ignore_all;
	u8 sysctl_icmp_echo_enable_probe;
	u8 sysctl_icmp_echo_ignore_broadcasts;
	u8 sysctl_icmp_ignore_bogus_error_responses;
	u8 sysctl_icmp_errors_use_inbound_ifaddr;
	int sysctl_icmp_ratelimit;
	int sysctl_icmp_ratemask;
	u32 ip_rt_min_pmtu;
	int ip_rt_mtu_expires;
	int ip_rt_min_advmss;
	struct local_ports ip_local_ports;
	u8 sysctl_tcp_ecn;
	u8 sysctl_tcp_ecn_fallback;
	u8 sysctl_ip_default_ttl;
	u8 sysctl_ip_no_pmtu_disc;
	u8 sysctl_ip_fwd_use_pmtu;
	u8 sysctl_ip_fwd_update_priority;
	u8 sysctl_ip_nonlocal_bind;
	u8 sysctl_ip_autobind_reuse;
	u8 sysctl_ip_dynaddr;
	u8 sysctl_ip_early_demux;
	u8 sysctl_raw_l3mdev_accept;
	u8 sysctl_tcp_early_demux;
	u8 sysctl_udp_early_demux;
	u8 sysctl_nexthop_compat_mode;
	u8 sysctl_fwmark_reflect;
	u8 sysctl_tcp_fwmark_accept;
	u8 sysctl_tcp_l3mdev_accept;
	u8 sysctl_tcp_mtu_probing;
	int sysctl_tcp_mtu_probe_floor;
	int sysctl_tcp_base_mss;
	int sysctl_tcp_min_snd_mss;
	int sysctl_tcp_probe_threshold;
	u32 sysctl_tcp_probe_interval;
	int sysctl_tcp_keepalive_time;
	int sysctl_tcp_keepalive_intvl;
	u8 sysctl_tcp_keepalive_probes;
	u8 sysctl_tcp_syn_retries;
	u8 sysctl_tcp_synack_retries;
	u8 sysctl_tcp_syncookies;
	u8 sysctl_tcp_migrate_req;
	u8 sysctl_tcp_comp_sack_nr;
	int sysctl_tcp_reordering;
	u8 sysctl_tcp_retries1;
	u8 sysctl_tcp_retries2;
	u8 sysctl_tcp_orphan_retries;
	u8 sysctl_tcp_tw_reuse;
	int sysctl_tcp_fin_timeout;
	unsigned int sysctl_tcp_notsent_lowat;
	u8 sysctl_tcp_sack;
	u8 sysctl_tcp_window_scaling;
	u8 sysctl_tcp_timestamps;
	u8 sysctl_tcp_early_retrans;
	u8 sysctl_tcp_recovery;
	u8 sysctl_tcp_thin_linear_timeouts;
	u8 sysctl_tcp_slow_start_after_idle;
	u8 sysctl_tcp_retrans_collapse;
	u8 sysctl_tcp_stdurg;
	u8 sysctl_tcp_rfc1337;
	u8 sysctl_tcp_abort_on_overflow;
	u8 sysctl_tcp_fack;
	int sysctl_tcp_max_reordering;
	int sysctl_tcp_adv_win_scale;
	u8 sysctl_tcp_dsack;
	u8 sysctl_tcp_app_win;
	u8 sysctl_tcp_frto;
	u8 sysctl_tcp_nometrics_save;
	u8 sysctl_tcp_no_ssthresh_metrics_save;
	u8 sysctl_tcp_moderate_rcvbuf;
	u8 sysctl_tcp_tso_win_divisor;
	u8 sysctl_tcp_workaround_signed_windows;
	int sysctl_tcp_limit_output_bytes;
	int sysctl_tcp_challenge_ack_limit;
	int sysctl_tcp_min_rtt_wlen;
	u8 sysctl_tcp_min_tso_segs;
	u8 sysctl_tcp_tso_rtt_log;
	u8 sysctl_tcp_autocorking;
	u8 sysctl_tcp_reflect_tos;
	int sysctl_tcp_invalid_ratelimit;
	int sysctl_tcp_pacing_ss_ratio;
	int sysctl_tcp_pacing_ca_ratio;
	int sysctl_tcp_wmem[3];
	int sysctl_tcp_rmem[3];
	long unsigned int sysctl_tcp_comp_sack_delay_ns;
	long unsigned int sysctl_tcp_comp_sack_slack_ns;
	int sysctl_max_syn_backlog;
	int sysctl_tcp_fastopen;
	const struct tcp_congestion_ops *tcp_congestion_control;
	struct tcp_fastopen_context *tcp_fastopen_ctx;
	unsigned int sysctl_tcp_fastopen_blackhole_timeout;
	atomic_t tfo_active_disable_times;
	long unsigned int tfo_active_disable_stamp;
	int sysctl_udp_wmem_min;
	int sysctl_udp_rmem_min;
	u8 sysctl_fib_notify_on_flag_change;
	u8 sysctl_udp_l3mdev_accept;
	u8 sysctl_igmp_llm_reports;
	int sysctl_igmp_max_memberships;
	int sysctl_igmp_max_msf;
	int sysctl_igmp_qrv;
	struct ping_group_range ping_group_range;
	atomic_t dev_addr_genid;
	long unsigned int *sysctl_local_reserved_ports;
	int sysctl_ip_prot_sock;
	struct list_head mr_tables;
	struct fib_rules_ops *mr_rules_ops;
	u32 sysctl_fib_multipath_hash_fields;
	u8 sysctl_fib_multipath_use_neigh;
	u8 sysctl_fib_multipath_hash_policy;
	struct fib_notifier_ops *notifier_ops;
	unsigned int fib_seq;
	struct fib_notifier_ops *ipmr_notifier_ops;
	unsigned int ipmr_seq;
	atomic_t rt_genid;
	siphash_key_t ip_id_key;
};

struct dst_entry;

struct net_device;

struct sk_buff;

struct neighbour;

struct dst_ops {
	short unsigned int family;
	unsigned int gc_thresh;
	int (*gc)(struct dst_ops *);
	struct dst_entry * (*check)(struct dst_entry *, __u32);
	unsigned int (*default_advmss)(const struct dst_entry *);
	unsigned int (*mtu)(const struct dst_entry *);
	u32 * (*cow_metrics)(struct dst_entry *, long unsigned int);
	void (*destroy)(struct dst_entry *);
	void (*ifdown)(struct dst_entry *, struct net_device *, int);
	struct dst_entry * (*negative_advice)(struct dst_entry *);
	void (*link_failure)(struct sk_buff *);
	void (*update_pmtu)(struct dst_entry *, struct sock *, struct sk_buff *, u32, bool);
	void (*redirect)(struct dst_entry *, struct sock *, struct sk_buff *);
	int (*local_out)(struct net *, struct sock *, struct sk_buff *);
	struct neighbour * (*neigh_lookup)(const struct dst_entry *, struct sk_buff *, const void *);
	void (*confirm_neigh)(const struct dst_entry *, const void *);
	struct kmem_cache *kmem_cachep;
	struct percpu_counter pcpuc_entries;
	long: 64;
	long: 64;
	long: 64;
};

struct netns_sysctl_ipv6 {
	struct ctl_table_header *hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *icmp_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *xfrm6_hdr;
	int flush_delay;
	int ip6_rt_max_size;
	int ip6_rt_gc_min_interval;
	int ip6_rt_gc_timeout;
	int ip6_rt_gc_interval;
	int ip6_rt_gc_elasticity;
	int ip6_rt_mtu_expires;
	int ip6_rt_min_advmss;
	u32 multipath_hash_fields;
	u8 multipath_hash_policy;
	u8 bindv6only;
	u8 flowlabel_consistency;
	u8 auto_flowlabels;
	int icmpv6_time;
	u8 icmpv6_echo_ignore_all;
	u8 icmpv6_echo_ignore_multicast;
	u8 icmpv6_echo_ignore_anycast;
	long unsigned int icmpv6_ratemask[4];
	long unsigned int *icmpv6_ratemask_ptr;
	u8 anycast_src_echo_reply;
	u8 ip_nonlocal_bind;
	u8 fwmark_reflect;
	u8 flowlabel_state_ranges;
	int idgen_retries;
	int idgen_delay;
	int flowlabel_reflect;
	int max_dst_opts_cnt;
	int max_hbh_opts_cnt;
	int max_dst_opts_len;
	int max_hbh_opts_len;
	int seg6_flowlabel;
	u32 ioam6_id;
	u64 ioam6_id_wide;
	bool skip_notify_on_dev_down;
	u8 fib_notify_on_flag_change;
};

struct ipv6_devconf;

struct fib6_info;

struct rt6_info;

struct rt6_statistics;

struct fib6_table;

struct seg6_pernet_data;

struct ioam6_pernet_data;

struct netns_ipv6 {
	struct dst_ops ip6_dst_ops;
	struct netns_sysctl_ipv6 sysctl;
	struct ipv6_devconf *devconf_all;
	struct ipv6_devconf *devconf_dflt;
	struct inet_peer_base *peers;
	struct fqdir *fqdir;
	struct fib6_info *fib6_null_entry;
	struct rt6_info *ip6_null_entry;
	struct rt6_statistics *rt6_stats;
	struct timer_list ip6_fib_timer;
	struct hlist_head *fib_table_hash;
	struct fib6_table *fib6_main_tbl;
	struct list_head fib6_walkers;
	rwlock_t fib6_walker_lock;
	spinlock_t fib6_gc_lock;
	atomic_t ip6_rt_gc_expire;
	long unsigned int ip6_rt_last_gc;
	unsigned char flowlabel_has_excl;
	bool fib6_has_custom_rules;
	unsigned int fib6_rules_require_fldissect;
	unsigned int fib6_routes_require_src;
	struct rt6_info *ip6_prohibit_entry;
	struct rt6_info *ip6_blk_hole_entry;
	struct fib6_table *fib6_local_tbl;
	struct fib_rules_ops *fib6_rules_ops;
	struct sock *ndisc_sk;
	struct sock *tcp_sk;
	struct sock *igmp_sk;
	struct sock *mc_autojoin_sk;
	struct hlist_head *inet6_addr_lst;
	spinlock_t addrconf_hash_lock;
	struct delayed_work addr_chk_work;
	struct list_head mr6_tables;
	struct fib_rules_ops *mr6_rules_ops;
	atomic_t dev_addr_genid;
	atomic_t fib6_sernum;
	struct seg6_pernet_data *seg6_data;
	struct fib_notifier_ops *notifier_ops;
	struct fib_notifier_ops *ip6mr_notifier_ops;
	unsigned int ipmr_seq;
	struct {
		struct hlist_head head;
		spinlock_t lock;
		u32 seq;
	} ip6addrlbl_table;
	struct ioam6_pernet_data *ioam6_data;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct netns_sysctl_lowpan {
	struct ctl_table_header *frags_hdr;
};

struct netns_ieee802154_lowpan {
	struct netns_sysctl_lowpan sysctl;
	struct fqdir *fqdir;
};

struct sctp_mib;

struct netns_sctp {
	struct sctp_mib *sctp_statistics;
	struct proc_dir_entry *proc_net_sctp;
	struct ctl_table_header *sysctl_header;
	struct sock *ctl_sock;
	struct sock *udp4_sock;
	struct sock *udp6_sock;
	int udp_port;
	int encap_port;
	struct list_head local_addr_list;
	struct list_head addr_waitq;
	struct timer_list addr_wq_timer;
	struct list_head auto_asconf_splist;
	spinlock_t addr_wq_lock;
	spinlock_t local_addr_lock;
	unsigned int rto_initial;
	unsigned int rto_min;
	unsigned int rto_max;
	int rto_alpha;
	int rto_beta;
	int max_burst;
	int cookie_preserve_enable;
	char *sctp_hmac_alg;
	unsigned int valid_cookie_life;
	unsigned int sack_timeout;
	unsigned int hb_interval;
	unsigned int probe_interval;
	int max_retrans_association;
	int max_retrans_path;
	int max_retrans_init;
	int pf_retrans;
	int ps_retrans;
	int pf_enable;
	int pf_expose;
	int sndbuf_policy;
	int rcvbuf_policy;
	int default_auto_asconf;
	int addip_enable;
	int addip_noauth;
	int prsctp_enable;
	int reconf_enable;
	int auth_enable;
	int intl_enable;
	int ecn_enable;
	int scope_policy;
	int rwnd_upd_shift;
	long unsigned int max_autoclose;
};

struct nf_logger;

struct nf_hook_entries;

struct netns_nf {
	struct proc_dir_entry *proc_netfilter;
	const struct nf_logger *nf_loggers[13];
	struct ctl_table_header *nf_log_dir_header;
	struct nf_hook_entries *hooks_ipv4[5];
	struct nf_hook_entries *hooks_ipv6[5];
	struct nf_hook_entries *hooks_arp[3];
	struct nf_hook_entries *hooks_bridge[5];
	struct nf_hook_entries *hooks_decnet[7];
	unsigned int defrag_ipv4_users;
	unsigned int defrag_ipv6_users;
};

struct nf_generic_net {
	unsigned int timeout;
};

struct nf_tcp_net {
	unsigned int timeouts[14];
	u8 tcp_loose;
	u8 tcp_be_liberal;
	u8 tcp_max_retrans;
	u8 tcp_ignore_invalid_rst;
	unsigned int offload_timeout;
};

struct nf_udp_net {
	unsigned int timeouts[2];
	unsigned int offload_timeout;
};

struct nf_icmp_net {
	unsigned int timeout;
};

struct nf_dccp_net {
	u8 dccp_loose;
	unsigned int dccp_timeout[10];
};

struct nf_sctp_net {
	unsigned int timeouts[10];
};

struct nf_gre_net {
	struct list_head keymap_list;
	unsigned int timeouts[2];
};

struct nf_ip_net {
	struct nf_generic_net generic;
	struct nf_tcp_net tcp;
	struct nf_udp_net udp;
	struct nf_icmp_net icmp;
	struct nf_icmp_net icmpv6;
	struct nf_dccp_net dccp;
	struct nf_sctp_net sctp;
	struct nf_gre_net gre;
};

struct ip_conntrack_stat;

struct nf_ct_event_notifier;

struct netns_ct {
	bool ctnetlink_has_listener;
	bool ecache_dwork_pending;
	u8 sysctl_log_invalid;
	u8 sysctl_events;
	u8 sysctl_acct;
	u8 sysctl_auto_assign_helper;
	u8 sysctl_tstamp;
	u8 sysctl_checksum;
	struct ip_conntrack_stat *stat;
	struct nf_ct_event_notifier *nf_conntrack_event_cb;
	struct nf_ip_net nf_ct_proto;
	unsigned int labels_used;
};

struct netns_nftables {
	u8 gencursor;
};

struct sk_buff_list {
	struct sk_buff *next;
	struct sk_buff *prev;
};

struct sk_buff_head {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
		};
		struct sk_buff_list list;
	};
	__u32 qlen;
	spinlock_t lock;
};

struct netns_bpf {
	struct bpf_prog_array *run_array[2];
	struct bpf_prog *progs[2];
	struct list_head links[2];
};

struct xfrm_policy_hash {
	struct hlist_head *table;
	unsigned int hmask;
	u8 dbits4;
	u8 sbits4;
	u8 dbits6;
	u8 sbits6;
};

struct xfrm_policy_hthresh {
	struct work_struct work;
	seqlock_t lock;
	u8 lbits4;
	u8 rbits4;
	u8 lbits6;
	u8 rbits6;
};

struct netns_xfrm {
	struct list_head state_all;
	struct hlist_head *state_bydst;
	struct hlist_head *state_bysrc;
	struct hlist_head *state_byspi;
	struct hlist_head *state_byseq;
	unsigned int state_hmask;
	unsigned int state_num;
	struct work_struct state_hash_work;
	struct list_head policy_all;
	struct hlist_head *policy_byidx;
	unsigned int policy_idx_hmask;
	struct hlist_head policy_inexact[3];
	struct xfrm_policy_hash policy_bydst[3];
	unsigned int policy_count[6];
	struct work_struct policy_hash_work;
	struct xfrm_policy_hthresh policy_hthresh;
	struct list_head inexact_bins;
	struct sock *nlsk;
	struct sock *nlsk_stash;
	u32 sysctl_aevent_etime;
	u32 sysctl_aevent_rseqth;
	int sysctl_larval_drop;
	u32 sysctl_acq_expires;
	u8 policy_default[3];
	struct ctl_table_header *sysctl_hdr;
	long: 64;
	long: 64;
	long: 64;
	struct dst_ops xfrm4_dst_ops;
	struct dst_ops xfrm6_dst_ops;
	spinlock_t xfrm_state_lock;
	seqcount_spinlock_t xfrm_state_hash_generation;
	seqcount_spinlock_t xfrm_policy_hash_generation;
	spinlock_t xfrm_policy_lock;
	struct mutex xfrm_cfg_mutex;
	long: 64;
	long: 64;
};

struct netns_ipvs;

struct mpls_route;

struct netns_mpls {
	int ip_ttl_propagate;
	int default_ttl;
	size_t platform_labels;
	struct mpls_route **platform_label;
	struct ctl_table_header *ctl;
};

struct can_dev_rcv_lists;

struct can_pkg_stats;

struct can_rcv_lists_stats;

struct netns_can {
	struct proc_dir_entry *proc_dir;
	struct proc_dir_entry *pde_stats;
	struct proc_dir_entry *pde_reset_stats;
	struct proc_dir_entry *pde_rcvlist_all;
	struct proc_dir_entry *pde_rcvlist_fil;
	struct proc_dir_entry *pde_rcvlist_inv;
	struct proc_dir_entry *pde_rcvlist_sff;
	struct proc_dir_entry *pde_rcvlist_eff;
	struct proc_dir_entry *pde_rcvlist_err;
	struct proc_dir_entry *bcmproc_dir;
	struct can_dev_rcv_lists *rx_alldev_list;
	spinlock_t rcvlists_lock;
	struct timer_list stattimer;
	struct can_pkg_stats *pkg_stats;
	struct can_rcv_lists_stats *rcv_lists_stats;
	struct hlist_head cgw_list;
};

struct netns_xdp {
	struct mutex lock;
	struct hlist_head list;
};

struct smc_stats;

struct smc_stats_rsn;

struct netns_smc {
	struct smc_stats *smc_stats;
	struct mutex mutex_fback_rsn;
	struct smc_stats_rsn *fback_rsn;
	bool limit_smc_hs;
	struct ctl_table_header *smc_hdr;
	unsigned int sysctl_autocorking_size;
};

struct uevent_sock;

struct net_generic;

struct net {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	atomic_t dev_unreg_count;
	unsigned int dev_base_seq;
	int ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock *rtnl;
	struct sock *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	struct netns_ipv4 ipv4;
	struct netns_ipv6 ipv6;
	struct netns_ieee802154_lowpan ieee802154_lowpan;
	struct netns_sctp sctp;
	struct netns_nf nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct sk_buff_head wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_xfrm xfrm;
	u64 net_cookie;
	struct netns_ipvs *ipvs;
	struct netns_mpls mpls;
	struct netns_can can;
	struct netns_xdp xdp;
	struct sock *crypto_nlsk;
	struct sock *diag_nlsk;
	struct netns_smc smc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct cgroup_namespace {
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct css_set *root_cset;
};

struct nsset {
	unsigned int flags;
	struct nsproxy *nsproxy;
	struct fs_struct *fs;
	const struct cred *cred;
};

struct proc_ns_operations {
	const char *name;
	const char *real_ns_name;
	int type;
	struct ns_common * (*get)(struct task_struct *);
	void (*put)(struct ns_common *);
	int (*install)(struct nsset *, struct ns_common *);
	struct user_namespace * (*owner)(struct ns_common *);
	struct ns_common * (*get_parent)(struct ns_common *);
};

struct perf_cpu_context;

struct perf_output_handle;

struct pmu {
	struct list_head entry;
	struct module *module;
	struct device *dev;
	const struct attribute_group **attr_groups;
	const struct attribute_group **attr_update;
	const char *name;
	int type;
	int capabilities;
	int *pmu_disable_count;
	struct perf_cpu_context *pmu_cpu_context;
	atomic_t exclusive_cnt;
	int task_ctx_nr;
	int hrtimer_interval_ms;
	unsigned int nr_addr_filters;
	void (*pmu_enable)(struct pmu *);
	void (*pmu_disable)(struct pmu *);
	int (*event_init)(struct perf_event *);
	void (*event_mapped)(struct perf_event *, struct mm_struct *);
	void (*event_unmapped)(struct perf_event *, struct mm_struct *);
	int (*add)(struct perf_event *, int);
	void (*del)(struct perf_event *, int);
	void (*start)(struct perf_event *, int);
	void (*stop)(struct perf_event *, int);
	void (*read)(struct perf_event *);
	void (*start_txn)(struct pmu *, unsigned int);
	int (*commit_txn)(struct pmu *);
	void (*cancel_txn)(struct pmu *);
	int (*event_idx)(struct perf_event *);
	void (*sched_task)(struct perf_event_context *, bool);
	struct kmem_cache *task_ctx_cache;
	void (*swap_task_ctx)(struct perf_event_context *, struct perf_event_context *);
	void * (*setup_aux)(struct perf_event *, void **, int, bool);
	void (*free_aux)(void *);
	long int (*snapshot_aux)(struct perf_event *, struct perf_output_handle *, long unsigned int);
	int (*addr_filters_validate)(struct list_head *);
	void (*addr_filters_sync)(struct perf_event *);
	int (*aux_output_match)(struct perf_event *);
	int (*filter_match)(struct perf_event *);
	int (*check_period)(struct perf_event *, u64);
};

struct ftrace_regs {
	struct pt_regs regs;
};

struct iovec {
	void *iov_base;
	__kernel_size_t iov_len;
};

struct kvec {
	void *iov_base;
	size_t iov_len;
};

struct perf_regs {
	__u64 abi;
	struct pt_regs *regs;
};

struct u64_stats_sync {};

struct psi_group_cpu {
	seqcount_t seq;
	unsigned int tasks[5];
	u32 state_mask;
	u32 times[7];
	u64 state_start;
	u32 times_prev[14];
	long: 64;
};

struct cgroup_taskset;

struct cftype;

struct cgroup_subsys {
	struct cgroup_subsys_state * (*css_alloc)(struct cgroup_subsys_state *);
	int (*css_online)(struct cgroup_subsys_state *);
	void (*css_offline)(struct cgroup_subsys_state *);
	void (*css_released)(struct cgroup_subsys_state *);
	void (*css_free)(struct cgroup_subsys_state *);
	void (*css_reset)(struct cgroup_subsys_state *);
	void (*css_rstat_flush)(struct cgroup_subsys_state *, int);
	int (*css_extra_stat_show)(struct seq_file *, struct cgroup_subsys_state *);
	int (*can_attach)(struct cgroup_taskset *);
	void (*cancel_attach)(struct cgroup_taskset *);
	void (*attach)(struct cgroup_taskset *);
	void (*post_attach)();
	int (*can_fork)(struct task_struct *, struct css_set *);
	void (*cancel_fork)(struct task_struct *, struct css_set *);
	void (*fork)(struct task_struct *);
	void (*exit)(struct task_struct *);
	void (*release)(struct task_struct *);
	void (*bind)(struct cgroup_subsys_state *);
	bool early_init: 1;
	bool implicit_on_dfl: 1;
	bool threaded: 1;
	int id;
	const char *name;
	const char *legacy_name;
	struct cgroup_root *root;
	struct idr css_idr;
	struct list_head cfts;
	struct cftype *dfl_cftypes;
	struct cftype *legacy_cftypes;
	unsigned int depends_on;
};

struct cgroup_rstat_cpu {
	struct u64_stats_sync bsync;
	struct cgroup_base_stat bstat;
	struct cgroup_base_stat last_bstat;
	struct cgroup *updated_children;
	struct cgroup *updated_next;
};

struct cgroup_root {
	struct kernfs_root *kf_root;
	unsigned int subsys_mask;
	int hierarchy_id;
	struct cgroup cgrp;
	u64 cgrp_ancestor_id_storage;
	atomic_t nr_cgrps;
	struct list_head root_list;
	unsigned int flags;
	char release_agent_path[4096];
	char name[64];
};

struct cftype {
	char name[64];
	long unsigned int private;
	size_t max_write_len;
	unsigned int flags;
	unsigned int file_offset;
	struct cgroup_subsys *ss;
	struct list_head node;
	struct kernfs_ops *kf_ops;
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	u64 (*read_u64)(struct cgroup_subsys_state *, struct cftype *);
	s64 (*read_s64)(struct cgroup_subsys_state *, struct cftype *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	int (*write_u64)(struct cgroup_subsys_state *, struct cftype *, u64);
	int (*write_s64)(struct cgroup_subsys_state *, struct cftype *, s64);
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
};

struct perf_callchain_entry {
	__u64 nr;
	__u64 ip[0];
};

typedef long unsigned int (*perf_copy_f)(void *, const void *, long unsigned int, long unsigned int);

struct perf_raw_frag {
	union {
		struct perf_raw_frag *next;
		long unsigned int pad;
	};
	perf_copy_f copy;
	void *data;
	u32 size;
} __attribute__((packed));

struct perf_raw_record {
	struct perf_raw_frag frag;
	u32 size;
};

struct perf_branch_stack {
	__u64 nr;
	__u64 hw_idx;
	struct perf_branch_entry entries[0];
};

struct perf_cpu_context {
	struct perf_event_context ctx;
	struct perf_event_context *task_ctx;
	int active_oncpu;
	int exclusive;
	raw_spinlock_t hrtimer_lock;
	struct hrtimer hrtimer;
	ktime_t hrtimer_interval;
	unsigned int hrtimer_active;
	struct perf_cgroup *cgrp;
	struct list_head cgrp_cpuctx_entry;
	struct list_head sched_cb_entry;
	int sched_cb_usage;
	int online;
	int heap_size;
	struct perf_event **heap;
	struct perf_event *heap_default[2];
};

struct perf_output_handle {
	struct perf_event *event;
	struct perf_buffer *rb;
	long unsigned int wakeup;
	long unsigned int size;
	u64 aux_flags;
	union {
		void *addr;
		long unsigned int head;
	};
	int page;
};

struct perf_addr_filter_range {
	long unsigned int start;
	long unsigned int size;
};

struct perf_sample_data {
	u64 addr;
	struct perf_raw_record *raw;
	struct perf_branch_stack *br_stack;
	u64 period;
	union perf_sample_weight weight;
	u64 txn;
	union perf_mem_data_src data_src;
	u64 type;
	u64 ip;
	struct {
		u32 pid;
		u32 tid;
	} tid_entry;
	u64 time;
	u64 id;
	u64 stream_id;
	struct {
		u32 cpu;
		u32 reserved;
	} cpu_entry;
	struct perf_callchain_entry *callchain;
	u64 aux_size;
	struct perf_regs regs_user;
	struct perf_regs regs_intr;
	u64 stack_user_size;
	u64 phys_addr;
	u64 cgroup;
	u64 data_page_size;
	u64 code_page_size;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct perf_cgroup_info;

struct perf_cgroup {
	struct cgroup_subsys_state css;
	struct perf_cgroup_info *info;
};

struct perf_cgroup_info {
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	int active;
};

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_array;

struct tracer;

struct array_buffer;

struct ring_buffer_iter;

struct trace_iterator {
	struct trace_array *tr;
	struct tracer *trace;
	struct array_buffer *array_buffer;
	void *private;
	int cpu_file;
	struct mutex mutex;
	struct ring_buffer_iter **buffer_iter;
	long unsigned int iter_flags;
	void *temp;
	unsigned int temp_size;
	char *fmt;
	unsigned int fmt_size;
	struct trace_seq tmp_seq;
	cpumask_var_t started;
	bool snapshot;
	struct trace_seq seq;
	struct trace_entry *ent;
	long unsigned int lost_events;
	int leftover;
	int ent_size;
	int cpu;
	u64 ts;
	loff_t pos;
	long int idx;
};

enum print_line_t {
	TRACE_TYPE_PARTIAL_LINE = 0,
	TRACE_TYPE_HANDLED = 1,
	TRACE_TYPE_UNHANDLED = 2,
	TRACE_TYPE_NO_CONSUME = 3,
};

typedef enum print_line_t (*trace_print_func)(struct trace_iterator *, int, struct trace_event *);

struct trace_event_functions {
	trace_print_func trace;
	trace_print_func raw;
	trace_print_func hex;
	trace_print_func binary;
};

enum trace_reg {
	TRACE_REG_REGISTER = 0,
	TRACE_REG_UNREGISTER = 1,
	TRACE_REG_PERF_REGISTER = 2,
	TRACE_REG_PERF_UNREGISTER = 3,
	TRACE_REG_PERF_OPEN = 4,
	TRACE_REG_PERF_CLOSE = 5,
	TRACE_REG_PERF_ADD = 6,
	TRACE_REG_PERF_DEL = 7,
};

struct trace_event_fields {
	const char *type;
	union {
		struct {
			const char *name;
			const int size;
			const int align;
			const int is_signed;
			const int filter_type;
		};
		int (*define_fields)(struct trace_event_call *);
	};
};

struct trace_event_class {
	const char *system;
	void *probe;
	void *perf_probe;
	int (*reg)(struct trace_event_call *, enum trace_reg, void *);
	struct trace_event_fields *fields_array;
	struct list_head * (*get_fields)(struct trace_event_call *);
	struct list_head fields;
	int (*raw_init)(struct trace_event_call *);
};

struct trace_buffer;

struct trace_event_file;

struct trace_event_buffer {
	struct trace_buffer *buffer;
	struct ring_buffer_event *event;
	struct trace_event_file *trace_file;
	void *entry;
	unsigned int trace_ctx;
	struct pt_regs *regs;
};

struct trace_subsystem_dir;

struct trace_event_file {
	struct list_head list;
	struct trace_event_call *event_call;
	struct event_filter *filter;
	struct dentry *dir;
	struct trace_array *tr;
	struct trace_subsystem_dir *system;
	struct list_head triggers;
	long unsigned int flags;
	atomic_t sm_ref;
	atomic_t tm_ref;
};

enum {
	TRACE_EVENT_FL_FILTERED_BIT = 0,
	TRACE_EVENT_FL_CAP_ANY_BIT = 1,
	TRACE_EVENT_FL_NO_SET_FILTER_BIT = 2,
	TRACE_EVENT_FL_IGNORE_ENABLE_BIT = 3,
	TRACE_EVENT_FL_TRACEPOINT_BIT = 4,
	TRACE_EVENT_FL_DYNAMIC_BIT = 5,
	TRACE_EVENT_FL_KPROBE_BIT = 6,
	TRACE_EVENT_FL_UPROBE_BIT = 7,
	TRACE_EVENT_FL_EPROBE_BIT = 8,
	TRACE_EVENT_FL_CUSTOM_BIT = 9,
};

enum {
	TRACE_EVENT_FL_FILTERED = 1,
	TRACE_EVENT_FL_CAP_ANY = 2,
	TRACE_EVENT_FL_NO_SET_FILTER = 4,
	TRACE_EVENT_FL_IGNORE_ENABLE = 8,
	TRACE_EVENT_FL_TRACEPOINT = 16,
	TRACE_EVENT_FL_DYNAMIC = 32,
	TRACE_EVENT_FL_KPROBE = 64,
	TRACE_EVENT_FL_UPROBE = 128,
	TRACE_EVENT_FL_EPROBE = 256,
	TRACE_EVENT_FL_CUSTOM = 512,
};

enum {
	EVENT_FILE_FL_ENABLED_BIT = 0,
	EVENT_FILE_FL_RECORDED_CMD_BIT = 1,
	EVENT_FILE_FL_RECORDED_TGID_BIT = 2,
	EVENT_FILE_FL_FILTERED_BIT = 3,
	EVENT_FILE_FL_NO_SET_FILTER_BIT = 4,
	EVENT_FILE_FL_SOFT_MODE_BIT = 5,
	EVENT_FILE_FL_SOFT_DISABLED_BIT = 6,
	EVENT_FILE_FL_TRIGGER_MODE_BIT = 7,
	EVENT_FILE_FL_TRIGGER_COND_BIT = 8,
	EVENT_FILE_FL_PID_FILTER_BIT = 9,
	EVENT_FILE_FL_WAS_ENABLED_BIT = 10,
};

enum {
	EVENT_FILE_FL_ENABLED = 1,
	EVENT_FILE_FL_RECORDED_CMD = 2,
	EVENT_FILE_FL_RECORDED_TGID = 4,
	EVENT_FILE_FL_FILTERED = 8,
	EVENT_FILE_FL_NO_SET_FILTER = 16,
	EVENT_FILE_FL_SOFT_MODE = 32,
	EVENT_FILE_FL_SOFT_DISABLED = 64,
	EVENT_FILE_FL_TRIGGER_MODE = 128,
	EVENT_FILE_FL_TRIGGER_COND = 256,
	EVENT_FILE_FL_PID_FILTER = 512,
	EVENT_FILE_FL_WAS_ENABLED = 1024,
};

enum {
	FILTER_OTHER = 0,
	FILTER_STATIC_STRING = 1,
	FILTER_DYN_STRING = 2,
	FILTER_RDYN_STRING = 3,
	FILTER_PTR_STRING = 4,
	FILTER_TRACE_FN = 5,
	FILTER_COMM = 6,
	FILTER_CPU = 7,
};

enum dev_dma_attr {
	DEV_DMA_NOT_SUPPORTED = 0,
	DEV_DMA_NON_COHERENT = 1,
	DEV_DMA_COHERENT = 2,
};

struct fwnode_reference_args;

struct fwnode_endpoint;

struct fwnode_operations {
	struct fwnode_handle * (*get)(struct fwnode_handle *);
	void (*put)(struct fwnode_handle *);
	bool (*device_is_available)(const struct fwnode_handle *);
	const void * (*device_get_match_data)(const struct fwnode_handle *, const struct device *);
	bool (*device_dma_supported)(const struct fwnode_handle *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle *);
	bool (*property_present)(const struct fwnode_handle *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle *);
	const char * (*get_name_prefix)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_parent)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_next_child_node)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*get_named_child_node)(const struct fwnode_handle *, const char *);
	int (*get_reference_args)(const struct fwnode_handle *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args *);
	struct fwnode_handle * (*graph_get_next_endpoint)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_remote_endpoint)(const struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_port_parent)(struct fwnode_handle *);
	int (*graph_parse_endpoint)(const struct fwnode_handle *, struct fwnode_endpoint *);
	void * (*iomap)(struct fwnode_handle *, int);
	int (*irq_get)(const struct fwnode_handle *, unsigned int);
	int (*add_links)(struct fwnode_handle *);
};

struct fwnode_endpoint {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle *local_fwnode;
};

struct fwnode_reference_args {
	struct fwnode_handle *fwnode;
	unsigned int nargs;
	u64 args[8];
};

struct property {
	char *name;
	int length;
	void *value;
	struct property *next;
};

struct irq_fwspec {
	struct fwnode_handle *fwnode;
	int param_count;
	u32 param[16];
};

struct irq_domain_ops {
	int (*match)(struct irq_domain *, struct device_node *, enum irq_domain_bus_token);
	int (*select)(struct irq_domain *, struct irq_fwspec *, enum irq_domain_bus_token);
	int (*map)(struct irq_domain *, unsigned int, irq_hw_number_t);
	void (*unmap)(struct irq_domain *, unsigned int);
	int (*xlate)(struct irq_domain *, struct device_node *, const u32 *, unsigned int, long unsigned int *, unsigned int *);
	int (*alloc)(struct irq_domain *, unsigned int, unsigned int, void *);
	void (*free)(struct irq_domain *, unsigned int, unsigned int);
	int (*activate)(struct irq_domain *, struct irq_data *, bool);
	void (*deactivate)(struct irq_domain *, struct irq_data *);
	int (*translate)(struct irq_domain *, struct irq_fwspec *, long unsigned int *, unsigned int *);
};

struct xbc_node {
	uint16_t next;
	uint16_t child;
	uint16_t parent;
	uint16_t data;
};

enum wb_stat_item {
	WB_RECLAIMABLE = 0,
	WB_WRITEBACK = 1,
	WB_DIRTIED = 2,
	WB_WRITTEN = 3,
	NR_WB_STAT_ITEMS = 4,
};

struct block_device_operations;

struct timer_rand_state;

struct disk_events;

struct cdrom_device_info;

struct badblocks;

struct gendisk {
	int major;
	int first_minor;
	int minors;
	char disk_name[32];
	short unsigned int events;
	short unsigned int event_flags;
	struct xarray part_tbl;
	struct block_device *part0;
	const struct block_device_operations *fops;
	struct request_queue *queue;
	void *private_data;
	int flags;
	long unsigned int state;
	struct mutex open_mutex;
	unsigned int open_partitions;
	struct backing_dev_info *bdi;
	struct kobject *slave_dir;
	struct list_head slave_bdevs;
	struct timer_rand_state *random;
	atomic_t sync_io;
	struct disk_events *ev;
	struct kobject integrity_kobj;
	struct cdrom_device_info *cdi;
	int node_id;
	struct badblocks *bb;
	struct lockdep_map lockdep_map;
	u64 diskseq;
};

struct partition_meta_info {
	char uuid[37];
	u8 volname[64];
};

struct bio_integrity_payload {
	struct bio *bip_bio;
	struct bvec_iter bip_iter;
	short unsigned int bip_vcnt;
	short unsigned int bip_max_vcnt;
	short unsigned int bip_flags;
	struct bvec_iter bio_iter;
	short: 16;
	struct work_struct bip_work;
	struct bio_vec *bip_vec;
	struct bio_vec bip_inline_vecs[0];
} __attribute__((packed));

struct blk_rq_stat {
	u64 mean;
	u64 min;
	u64 max;
	u32 nr_samples;
	u64 batch;
};

typedef long unsigned int efi_status_t;

typedef u8 efi_bool_t;

typedef u16 efi_char16_t;

typedef guid_t efi_guid_t;

typedef struct {
	u64 signature;
	u32 revision;
	u32 headersize;
	u32 crc32;
	u32 reserved;
} efi_table_hdr_t;

typedef struct {
	u32 type;
	u32 pad;
	u64 phys_addr;
	u64 virt_addr;
	u64 num_pages;
	u64 attribute;
} efi_memory_desc_t;

typedef struct {
	efi_guid_t guid;
	u32 headersize;
	u32 flags;
	u32 imagesize;
} efi_capsule_header_t;

typedef struct {
	u16 year;
	u8 month;
	u8 day;
	u8 hour;
	u8 minute;
	u8 second;
	u8 pad1;
	u32 nanosecond;
	s16 timezone;
	u8 daylight;
	u8 pad2;
} efi_time_t;

typedef struct {
	u32 resolution;
	u32 accuracy;
	u8 sets_to_zero;
} efi_time_cap_t;

typedef struct {
	efi_table_hdr_t hdr;
	u32 get_time;
	u32 set_time;
	u32 get_wakeup_time;
	u32 set_wakeup_time;
	u32 set_virtual_address_map;
	u32 convert_pointer;
	u32 get_variable;
	u32 get_next_variable;
	u32 set_variable;
	u32 get_next_high_mono_count;
	u32 reset_system;
	u32 update_capsule;
	u32 query_capsule_caps;
	u32 query_variable_info;
} efi_runtime_services_32_t;

typedef efi_status_t efi_get_time_t(efi_time_t *, efi_time_cap_t *);

typedef efi_status_t efi_set_time_t(efi_time_t *);

typedef efi_status_t efi_get_wakeup_time_t(efi_bool_t *, efi_bool_t *, efi_time_t *);

typedef efi_status_t efi_set_wakeup_time_t(efi_bool_t, efi_time_t *);

typedef efi_status_t efi_get_variable_t(efi_char16_t *, efi_guid_t *, u32 *, long unsigned int *, void *);

typedef efi_status_t efi_get_next_variable_t(long unsigned int *, efi_char16_t *, efi_guid_t *);

typedef efi_status_t efi_set_variable_t(efi_char16_t *, efi_guid_t *, u32, long unsigned int, void *);

typedef efi_status_t efi_get_next_high_mono_count_t(u32 *);

typedef void efi_reset_system_t(int, efi_status_t, long unsigned int, efi_char16_t *);

typedef efi_status_t efi_query_variable_info_t(u32, u64 *, u64 *, u64 *);

typedef efi_status_t efi_update_capsule_t(efi_capsule_header_t **, long unsigned int, long unsigned int);

typedef efi_status_t efi_query_capsule_caps_t(efi_capsule_header_t **, long unsigned int, u64 *, int *);

typedef union {
	struct {
		efi_table_hdr_t hdr;
		efi_status_t (*get_time)(efi_time_t *, efi_time_cap_t *);
		efi_status_t (*set_time)(efi_time_t *);
		efi_status_t (*get_wakeup_time)(efi_bool_t *, efi_bool_t *, efi_time_t *);
		efi_status_t (*set_wakeup_time)(efi_bool_t, efi_time_t *);
		efi_status_t (*set_virtual_address_map)(long unsigned int, long unsigned int, u32, efi_memory_desc_t *);
		void *convert_pointer;
		efi_status_t (*get_variable)(efi_char16_t *, efi_guid_t *, u32 *, long unsigned int *, void *);
		efi_status_t (*get_next_variable)(long unsigned int *, efi_char16_t *, efi_guid_t *);
		efi_status_t (*set_variable)(efi_char16_t *, efi_guid_t *, u32, long unsigned int, void *);
		efi_status_t (*get_next_high_mono_count)(u32 *);
		void (*reset_system)(int, efi_status_t, long unsigned int, efi_char16_t *);
		efi_status_t (*update_capsule)(efi_capsule_header_t **, long unsigned int, long unsigned int);
		efi_status_t (*query_capsule_caps)(efi_capsule_header_t **, long unsigned int, u64 *, int *);
		efi_status_t (*query_variable_info)(u32, u64 *, u64 *, u64 *);
	};
	efi_runtime_services_32_t mixed_mode;
} efi_runtime_services_t;

struct efi_memory_map {
	phys_addr_t phys_map;
	void *map;
	void *map_end;
	int nr_map;
	long unsigned int desc_version;
	long unsigned int desc_size;
	long unsigned int flags;
};

struct efi {
	const efi_runtime_services_t *runtime;
	unsigned int runtime_version;
	unsigned int runtime_supported_mask;
	long unsigned int acpi;
	long unsigned int acpi20;
	long unsigned int smbios;
	long unsigned int smbios3;
	long unsigned int esrt;
	long unsigned int tpm_log;
	long unsigned int tpm_final_log;
	long unsigned int mokvar_table;
	long unsigned int coco_secret;
	efi_get_time_t *get_time;
	efi_set_time_t *set_time;
	efi_get_wakeup_time_t *get_wakeup_time;
	efi_set_wakeup_time_t *set_wakeup_time;
	efi_get_variable_t *get_variable;
	efi_get_next_variable_t *get_next_variable;
	efi_set_variable_t *set_variable;
	efi_set_variable_t *set_variable_nonblocking;
	efi_query_variable_info_t *query_variable_info;
	efi_query_variable_info_t *query_variable_info_nonblocking;
	efi_update_capsule_t *update_capsule;
	efi_query_capsule_caps_t *query_capsule_caps;
	efi_get_next_high_mono_count_t *get_next_high_mono_count;
	efi_reset_system_t *reset_system;
	struct efi_memory_map memmap;
	long unsigned int flags;
};

enum memcg_stat_item {
	MEMCG_SWAP = 41,
	MEMCG_SOCK = 42,
	MEMCG_PERCPU_B = 43,
	MEMCG_VMALLOC = 44,
	MEMCG_KMEM = 45,
	MEMCG_ZSWAP_B = 46,
	MEMCG_ZSWAPPED = 47,
	MEMCG_NR_STAT = 48,
};

enum memcg_memory_event {
	MEMCG_LOW = 0,
	MEMCG_HIGH = 1,
	MEMCG_MAX = 2,
	MEMCG_OOM = 3,
	MEMCG_OOM_KILL = 4,
	MEMCG_OOM_GROUP_KILL = 5,
	MEMCG_SWAP_HIGH = 6,
	MEMCG_SWAP_MAX = 7,
	MEMCG_SWAP_FAIL = 8,
	MEMCG_NR_MEMORY_EVENTS = 9,
};

enum mem_cgroup_events_target {
	MEM_CGROUP_TARGET_THRESH = 0,
	MEM_CGROUP_TARGET_SOFTLIMIT = 1,
	MEM_CGROUP_NTARGETS = 2,
};

struct memcg_vmstats_percpu {
	long int state[48];
	long unsigned int events[107];
	long int state_prev[48];
	long unsigned int events_prev[107];
	long unsigned int nr_page_events;
	long unsigned int targets[2];
};

struct mem_cgroup_reclaim_iter {
	struct mem_cgroup *position;
	unsigned int generation;
};

struct shrinker_info {
	struct callback_head rcu;
	atomic_long_t *nr_deferred;
	long unsigned int *map;
};

struct lruvec_stats_percpu {
	long int state[41];
	long int state_prev[41];
};

struct lruvec_stats {
	long int state[41];
	long int state_pending[41];
};

struct mem_cgroup_per_node {
	struct lruvec lruvec;
	struct lruvec_stats_percpu *lruvec_stats_percpu;
	struct lruvec_stats lruvec_stats;
	long unsigned int lru_zone_size[25];
	struct mem_cgroup_reclaim_iter iter;
	struct shrinker_info *shrinker_info;
	struct rb_node tree_node;
	long unsigned int usage_in_excess;
	bool on_tree;
	struct mem_cgroup *memcg;
};

struct eventfd_ctx;

struct mem_cgroup_threshold {
	struct eventfd_ctx *eventfd;
	long unsigned int threshold;
};

struct mem_cgroup_threshold_ary {
	int current_threshold;
	unsigned int size;
	struct mem_cgroup_threshold entries[0];
};

struct obj_cgroup {
	struct percpu_ref refcnt;
	struct mem_cgroup *memcg;
	atomic_t nr_charged_bytes;
	union {
		struct list_head list;
		struct callback_head rcu;
	};
};

struct dev_pagemap_ops {
	void (*page_free)(struct page *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault *);
};

struct percpu_cluster {
	struct swap_cluster_info index;
	unsigned int next;
};

enum fs_value_type {
	fs_value_is_undefined = 0,
	fs_value_is_flag = 1,
	fs_value_is_string = 2,
	fs_value_is_blob = 3,
	fs_value_is_filename = 4,
	fs_value_is_file = 5,
};

struct fs_parameter {
	const char *key;
	enum fs_value_type type: 8;
	union {
		char *string;
		void *blob;
		struct filename *name;
		struct file *file;
	};
	size_t size;
	int dirfd;
};

struct fc_log {
	refcount_t usage;
	u8 head;
	u8 tail;
	u8 need_free;
	struct module *owner;
	char *buffer[8];
};

struct fs_context_operations {
	void (*free)(struct fs_context *);
	int (*dup)(struct fs_context *, struct fs_context *);
	int (*parse_param)(struct fs_context *, struct fs_parameter *);
	int (*parse_monolithic)(struct fs_context *, void *);
	int (*get_tree)(struct fs_context *);
	int (*reconfigure)(struct fs_context *);
};

struct fs_parse_result {
	bool negated;
	union {
		bool boolean;
		int int_32;
		unsigned int uint_32;
		u64 uint_64;
	};
};

struct blk_zone {
	__u64 start;
	__u64 len;
	__u64 wp;
	__u8 type;
	__u8 cond;
	__u8 non_seq;
	__u8 reset;
	__u8 resv[4];
	__u64 capacity;
	__u8 reserved[24];
};

struct blk_integrity_iter;

typedef blk_status_t integrity_processing_fn(struct blk_integrity_iter *);

typedef void integrity_prepare_fn(struct request *);

typedef void integrity_complete_fn(struct request *, unsigned int);

struct blk_integrity_profile {
	integrity_processing_fn *generate_fn;
	integrity_processing_fn *verify_fn;
	integrity_prepare_fn *prepare_fn;
	integrity_complete_fn *complete_fn;
	const char *name;
};

typedef int (*report_zones_cb)(struct blk_zone *, unsigned int, void *);

enum blk_unique_id {
	BLK_UID_T10 = 1,
	BLK_UID_EUI64 = 2,
	BLK_UID_NAA = 3,
};

struct hd_geometry;

struct pr_ops;

struct block_device_operations {
	void (*submit_bio)(struct bio *);
	int (*poll_bio)(struct bio *, struct io_comp_batch *, unsigned int);
	int (*open)(struct block_device *, fmode_t);
	void (*release)(struct gendisk *, fmode_t);
	int (*rw_page)(struct block_device *, sector_t, struct page *, unsigned int);
	int (*ioctl)(struct block_device *, fmode_t, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct block_device *, fmode_t, unsigned int, long unsigned int);
	unsigned int (*check_events)(struct gendisk *, unsigned int);
	void (*unlock_native_capacity)(struct gendisk *);
	int (*getgeo)(struct block_device *, struct hd_geometry *);
	int (*set_read_only)(struct block_device *, bool);
	void (*free_disk)(struct gendisk *);
	void (*swap_slot_free_notify)(struct block_device *, long unsigned int);
	int (*report_zones)(struct gendisk *, sector_t, unsigned int, report_zones_cb, void *);
	char * (*devnode)(struct gendisk *, umode_t *);
	int (*get_unique_id)(struct gendisk *, u8 *, enum blk_unique_id);
	struct module *owner;
	const struct pr_ops *pr_ops;
	int (*alternative_gpt_sector)(struct gendisk *, sector_t *);
};

struct blk_independent_access_range {
	struct kobject kobj;
	struct request_queue *queue;
	sector_t sector;
	sector_t nr_sectors;
};

struct blk_independent_access_ranges {
	struct kobject kobj;
	bool sysfs_registered;
	unsigned int nr_ia_ranges;
	struct blk_independent_access_range ia_range[0];
};

enum blk_eh_timer_return {
	BLK_EH_DONE = 0,
	BLK_EH_RESET_TIMER = 1,
};

struct blk_mq_hw_ctx;

struct blk_mq_queue_data;

struct blk_mq_ops {
	blk_status_t (*queue_rq)(struct blk_mq_hw_ctx *, const struct blk_mq_queue_data *);
	void (*commit_rqs)(struct blk_mq_hw_ctx *);
	void (*queue_rqs)(struct request **);
	int (*get_budget)(struct request_queue *);
	void (*put_budget)(struct request_queue *, int);
	void (*set_rq_budget_token)(struct request *, int);
	int (*get_rq_budget_token)(struct request *);
	enum blk_eh_timer_return (*timeout)(struct request *, bool);
	int (*poll)(struct blk_mq_hw_ctx *, struct io_comp_batch *);
	void (*complete)(struct request *);
	int (*init_hctx)(struct blk_mq_hw_ctx *, void *, unsigned int);
	void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	int (*init_request)(struct blk_mq_tag_set *, struct request *, unsigned int, unsigned int);
	void (*exit_request)(struct blk_mq_tag_set *, struct request *, unsigned int);
	void (*cleanup_rq)(struct request *);
	bool (*busy)(struct request_queue *);
	int (*map_queues)(struct blk_mq_tag_set *);
	void (*show_rq)(struct seq_file *, struct request *);
};

enum pr_type {
	PR_WRITE_EXCLUSIVE = 1,
	PR_EXCLUSIVE_ACCESS = 2,
	PR_WRITE_EXCLUSIVE_REG_ONLY = 3,
	PR_EXCLUSIVE_ACCESS_REG_ONLY = 4,
	PR_WRITE_EXCLUSIVE_ALL_REGS = 5,
	PR_EXCLUSIVE_ACCESS_ALL_REGS = 6,
};

struct pr_ops {
	int (*pr_register)(struct block_device *, u64, u64, u32);
	int (*pr_reserve)(struct block_device *, u64, enum pr_type, u32);
	int (*pr_release)(struct block_device *, u64, enum pr_type);
	int (*pr_preempt)(struct block_device *, u64, u64, enum pr_type, bool);
	int (*pr_clear)(struct block_device *, u64);
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

enum flow_dissector_key_id {
	FLOW_DISSECTOR_KEY_CONTROL = 0,
	FLOW_DISSECTOR_KEY_BASIC = 1,
	FLOW_DISSECTOR_KEY_IPV4_ADDRS = 2,
	FLOW_DISSECTOR_KEY_IPV6_ADDRS = 3,
	FLOW_DISSECTOR_KEY_PORTS = 4,
	FLOW_DISSECTOR_KEY_PORTS_RANGE = 5,
	FLOW_DISSECTOR_KEY_ICMP = 6,
	FLOW_DISSECTOR_KEY_ETH_ADDRS = 7,
	FLOW_DISSECTOR_KEY_TIPC = 8,
	FLOW_DISSECTOR_KEY_ARP = 9,
	FLOW_DISSECTOR_KEY_VLAN = 10,
	FLOW_DISSECTOR_KEY_FLOW_LABEL = 11,
	FLOW_DISSECTOR_KEY_GRE_KEYID = 12,
	FLOW_DISSECTOR_KEY_MPLS_ENTROPY = 13,
	FLOW_DISSECTOR_KEY_ENC_KEYID = 14,
	FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS = 15,
	FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS = 16,
	FLOW_DISSECTOR_KEY_ENC_CONTROL = 17,
	FLOW_DISSECTOR_KEY_ENC_PORTS = 18,
	FLOW_DISSECTOR_KEY_MPLS = 19,
	FLOW_DISSECTOR_KEY_TCP = 20,
	FLOW_DISSECTOR_KEY_IP = 21,
	FLOW_DISSECTOR_KEY_CVLAN = 22,
	FLOW_DISSECTOR_KEY_ENC_IP = 23,
	FLOW_DISSECTOR_KEY_ENC_OPTS = 24,
	FLOW_DISSECTOR_KEY_META = 25,
	FLOW_DISSECTOR_KEY_CT = 26,
	FLOW_DISSECTOR_KEY_HASH = 27,
	FLOW_DISSECTOR_KEY_NUM_OF_VLANS = 28,
	FLOW_DISSECTOR_KEY_MAX = 29,
};

typedef unsigned int sk_buff_data_t;

struct skb_ext;

struct sk_buff {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
			union {
				struct net_device *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	union {
		struct sock *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};

enum {
	IPSTATS_MIB_NUM = 0,
	IPSTATS_MIB_INPKTS = 1,
	IPSTATS_MIB_INOCTETS = 2,
	IPSTATS_MIB_INDELIVERS = 3,
	IPSTATS_MIB_OUTFORWDATAGRAMS = 4,
	IPSTATS_MIB_OUTPKTS = 5,
	IPSTATS_MIB_OUTOCTETS = 6,
	IPSTATS_MIB_INHDRERRORS = 7,
	IPSTATS_MIB_INTOOBIGERRORS = 8,
	IPSTATS_MIB_INNOROUTES = 9,
	IPSTATS_MIB_INADDRERRORS = 10,
	IPSTATS_MIB_INUNKNOWNPROTOS = 11,
	IPSTATS_MIB_INTRUNCATEDPKTS = 12,
	IPSTATS_MIB_INDISCARDS = 13,
	IPSTATS_MIB_OUTDISCARDS = 14,
	IPSTATS_MIB_OUTNOROUTES = 15,
	IPSTATS_MIB_REASMTIMEOUT = 16,
	IPSTATS_MIB_REASMREQDS = 17,
	IPSTATS_MIB_REASMOKS = 18,
	IPSTATS_MIB_REASMFAILS = 19,
	IPSTATS_MIB_FRAGOKS = 20,
	IPSTATS_MIB_FRAGFAILS = 21,
	IPSTATS_MIB_FRAGCREATES = 22,
	IPSTATS_MIB_INMCASTPKTS = 23,
	IPSTATS_MIB_OUTMCASTPKTS = 24,
	IPSTATS_MIB_INBCASTPKTS = 25,
	IPSTATS_MIB_OUTBCASTPKTS = 26,
	IPSTATS_MIB_INMCASTOCTETS = 27,
	IPSTATS_MIB_OUTMCASTOCTETS = 28,
	IPSTATS_MIB_INBCASTOCTETS = 29,
	IPSTATS_MIB_OUTBCASTOCTETS = 30,
	IPSTATS_MIB_CSUMERRORS = 31,
	IPSTATS_MIB_NOECTPKTS = 32,
	IPSTATS_MIB_ECT1PKTS = 33,
	IPSTATS_MIB_ECT0PKTS = 34,
	IPSTATS_MIB_CEPKTS = 35,
	IPSTATS_MIB_REASM_OVERLAPS = 36,
	__IPSTATS_MIB_MAX = 37,
};

enum {
	ICMP_MIB_NUM = 0,
	ICMP_MIB_INMSGS = 1,
	ICMP_MIB_INERRORS = 2,
	ICMP_MIB_INDESTUNREACHS = 3,
	ICMP_MIB_INTIMEEXCDS = 4,
	ICMP_MIB_INPARMPROBS = 5,
	ICMP_MIB_INSRCQUENCHS = 6,
	ICMP_MIB_INREDIRECTS = 7,
	ICMP_MIB_INECHOS = 8,
	ICMP_MIB_INECHOREPS = 9,
	ICMP_MIB_INTIMESTAMPS = 10,
	ICMP_MIB_INTIMESTAMPREPS = 11,
	ICMP_MIB_INADDRMASKS = 12,
	ICMP_MIB_INADDRMASKREPS = 13,
	ICMP_MIB_OUTMSGS = 14,
	ICMP_MIB_OUTERRORS = 15,
	ICMP_MIB_OUTDESTUNREACHS = 16,
	ICMP_MIB_OUTTIMEEXCDS = 17,
	ICMP_MIB_OUTPARMPROBS = 18,
	ICMP_MIB_OUTSRCQUENCHS = 19,
	ICMP_MIB_OUTREDIRECTS = 20,
	ICMP_MIB_OUTECHOS = 21,
	ICMP_MIB_OUTECHOREPS = 22,
	ICMP_MIB_OUTTIMESTAMPS = 23,
	ICMP_MIB_OUTTIMESTAMPREPS = 24,
	ICMP_MIB_OUTADDRMASKS = 25,
	ICMP_MIB_OUTADDRMASKREPS = 26,
	ICMP_MIB_CSUMERRORS = 27,
	__ICMP_MIB_MAX = 28,
};

enum {
	ICMP6_MIB_NUM = 0,
	ICMP6_MIB_INMSGS = 1,
	ICMP6_MIB_INERRORS = 2,
	ICMP6_MIB_OUTMSGS = 3,
	ICMP6_MIB_OUTERRORS = 4,
	ICMP6_MIB_CSUMERRORS = 5,
	__ICMP6_MIB_MAX = 6,
};

enum {
	TCP_MIB_NUM = 0,
	TCP_MIB_RTOALGORITHM = 1,
	TCP_MIB_RTOMIN = 2,
	TCP_MIB_RTOMAX = 3,
	TCP_MIB_MAXCONN = 4,
	TCP_MIB_ACTIVEOPENS = 5,
	TCP_MIB_PASSIVEOPENS = 6,
	TCP_MIB_ATTEMPTFAILS = 7,
	TCP_MIB_ESTABRESETS = 8,
	TCP_MIB_CURRESTAB = 9,
	TCP_MIB_INSEGS = 10,
	TCP_MIB_OUTSEGS = 11,
	TCP_MIB_RETRANSSEGS = 12,
	TCP_MIB_INERRS = 13,
	TCP_MIB_OUTRSTS = 14,
	TCP_MIB_CSUMERRORS = 15,
	__TCP_MIB_MAX = 16,
};

enum {
	UDP_MIB_NUM = 0,
	UDP_MIB_INDATAGRAMS = 1,
	UDP_MIB_NOPORTS = 2,
	UDP_MIB_INERRORS = 3,
	UDP_MIB_OUTDATAGRAMS = 4,
	UDP_MIB_RCVBUFERRORS = 5,
	UDP_MIB_SNDBUFERRORS = 6,
	UDP_MIB_CSUMERRORS = 7,
	UDP_MIB_IGNOREDMULTI = 8,
	UDP_MIB_MEMERRORS = 9,
	__UDP_MIB_MAX = 10,
};

enum {
	LINUX_MIB_NUM = 0,
	LINUX_MIB_SYNCOOKIESSENT = 1,
	LINUX_MIB_SYNCOOKIESRECV = 2,
	LINUX_MIB_SYNCOOKIESFAILED = 3,
	LINUX_MIB_EMBRYONICRSTS = 4,
	LINUX_MIB_PRUNECALLED = 5,
	LINUX_MIB_RCVPRUNED = 6,
	LINUX_MIB_OFOPRUNED = 7,
	LINUX_MIB_OUTOFWINDOWICMPS = 8,
	LINUX_MIB_LOCKDROPPEDICMPS = 9,
	LINUX_MIB_ARPFILTER = 10,
	LINUX_MIB_TIMEWAITED = 11,
	LINUX_MIB_TIMEWAITRECYCLED = 12,
	LINUX_MIB_TIMEWAITKILLED = 13,
	LINUX_MIB_PAWSACTIVEREJECTED = 14,
	LINUX_MIB_PAWSESTABREJECTED = 15,
	LINUX_MIB_DELAYEDACKS = 16,
	LINUX_MIB_DELAYEDACKLOCKED = 17,
	LINUX_MIB_DELAYEDACKLOST = 18,
	LINUX_MIB_LISTENOVERFLOWS = 19,
	LINUX_MIB_LISTENDROPS = 20,
	LINUX_MIB_TCPHPHITS = 21,
	LINUX_MIB_TCPPUREACKS = 22,
	LINUX_MIB_TCPHPACKS = 23,
	LINUX_MIB_TCPRENORECOVERY = 24,
	LINUX_MIB_TCPSACKRECOVERY = 25,
	LINUX_MIB_TCPSACKRENEGING = 26,
	LINUX_MIB_TCPSACKREORDER = 27,
	LINUX_MIB_TCPRENOREORDER = 28,
	LINUX_MIB_TCPTSREORDER = 29,
	LINUX_MIB_TCPFULLUNDO = 30,
	LINUX_MIB_TCPPARTIALUNDO = 31,
	LINUX_MIB_TCPDSACKUNDO = 32,
	LINUX_MIB_TCPLOSSUNDO = 33,
	LINUX_MIB_TCPLOSTRETRANSMIT = 34,
	LINUX_MIB_TCPRENOFAILURES = 35,
	LINUX_MIB_TCPSACKFAILURES = 36,
	LINUX_MIB_TCPLOSSFAILURES = 37,
	LINUX_MIB_TCPFASTRETRANS = 38,
	LINUX_MIB_TCPSLOWSTARTRETRANS = 39,
	LINUX_MIB_TCPTIMEOUTS = 40,
	LINUX_MIB_TCPLOSSPROBES = 41,
	LINUX_MIB_TCPLOSSPROBERECOVERY = 42,
	LINUX_MIB_TCPRENORECOVERYFAIL = 43,
	LINUX_MIB_TCPSACKRECOVERYFAIL = 44,
	LINUX_MIB_TCPRCVCOLLAPSED = 45,
	LINUX_MIB_TCPDSACKOLDSENT = 46,
	LINUX_MIB_TCPDSACKOFOSENT = 47,
	LINUX_MIB_TCPDSACKRECV = 48,
	LINUX_MIB_TCPDSACKOFORECV = 49,
	LINUX_MIB_TCPABORTONDATA = 50,
	LINUX_MIB_TCPABORTONCLOSE = 51,
	LINUX_MIB_TCPABORTONMEMORY = 52,
	LINUX_MIB_TCPABORTONTIMEOUT = 53,
	LINUX_MIB_TCPABORTONLINGER = 54,
	LINUX_MIB_TCPABORTFAILED = 55,
	LINUX_MIB_TCPMEMORYPRESSURES = 56,
	LINUX_MIB_TCPMEMORYPRESSURESCHRONO = 57,
	LINUX_MIB_TCPSACKDISCARD = 58,
	LINUX_MIB_TCPDSACKIGNOREDOLD = 59,
	LINUX_MIB_TCPDSACKIGNOREDNOUNDO = 60,
	LINUX_MIB_TCPSPURIOUSRTOS = 61,
	LINUX_MIB_TCPMD5NOTFOUND = 62,
	LINUX_MIB_TCPMD5UNEXPECTED = 63,
	LINUX_MIB_TCPMD5FAILURE = 64,
	LINUX_MIB_SACKSHIFTED = 65,
	LINUX_MIB_SACKMERGED = 66,
	LINUX_MIB_SACKSHIFTFALLBACK = 67,
	LINUX_MIB_TCPBACKLOGDROP = 68,
	LINUX_MIB_PFMEMALLOCDROP = 69,
	LINUX_MIB_TCPMINTTLDROP = 70,
	LINUX_MIB_TCPDEFERACCEPTDROP = 71,
	LINUX_MIB_IPRPFILTER = 72,
	LINUX_MIB_TCPTIMEWAITOVERFLOW = 73,
	LINUX_MIB_TCPREQQFULLDOCOOKIES = 74,
	LINUX_MIB_TCPREQQFULLDROP = 75,
	LINUX_MIB_TCPRETRANSFAIL = 76,
	LINUX_MIB_TCPRCVCOALESCE = 77,
	LINUX_MIB_TCPBACKLOGCOALESCE = 78,
	LINUX_MIB_TCPOFOQUEUE = 79,
	LINUX_MIB_TCPOFODROP = 80,
	LINUX_MIB_TCPOFOMERGE = 81,
	LINUX_MIB_TCPCHALLENGEACK = 82,
	LINUX_MIB_TCPSYNCHALLENGE = 83,
	LINUX_MIB_TCPFASTOPENACTIVE = 84,
	LINUX_MIB_TCPFASTOPENACTIVEFAIL = 85,
	LINUX_MIB_TCPFASTOPENPASSIVE = 86,
	LINUX_MIB_TCPFASTOPENPASSIVEFAIL = 87,
	LINUX_MIB_TCPFASTOPENLISTENOVERFLOW = 88,
	LINUX_MIB_TCPFASTOPENCOOKIEREQD = 89,
	LINUX_MIB_TCPFASTOPENBLACKHOLE = 90,
	LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES = 91,
	LINUX_MIB_BUSYPOLLRXPACKETS = 92,
	LINUX_MIB_TCPAUTOCORKING = 93,
	LINUX_MIB_TCPFROMZEROWINDOWADV = 94,
	LINUX_MIB_TCPTOZEROWINDOWADV = 95,
	LINUX_MIB_TCPWANTZEROWINDOWADV = 96,
	LINUX_MIB_TCPSYNRETRANS = 97,
	LINUX_MIB_TCPORIGDATASENT = 98,
	LINUX_MIB_TCPHYSTARTTRAINDETECT = 99,
	LINUX_MIB_TCPHYSTARTTRAINCWND = 100,
	LINUX_MIB_TCPHYSTARTDELAYDETECT = 101,
	LINUX_MIB_TCPHYSTARTDELAYCWND = 102,
	LINUX_MIB_TCPACKSKIPPEDSYNRECV = 103,
	LINUX_MIB_TCPACKSKIPPEDPAWS = 104,
	LINUX_MIB_TCPACKSKIPPEDSEQ = 105,
	LINUX_MIB_TCPACKSKIPPEDFINWAIT2 = 106,
	LINUX_MIB_TCPACKSKIPPEDTIMEWAIT = 107,
	LINUX_MIB_TCPACKSKIPPEDCHALLENGE = 108,
	LINUX_MIB_TCPWINPROBE = 109,
	LINUX_MIB_TCPKEEPALIVE = 110,
	LINUX_MIB_TCPMTUPFAIL = 111,
	LINUX_MIB_TCPMTUPSUCCESS = 112,
	LINUX_MIB_TCPDELIVERED = 113,
	LINUX_MIB_TCPDELIVEREDCE = 114,
	LINUX_MIB_TCPACKCOMPRESSED = 115,
	LINUX_MIB_TCPZEROWINDOWDROP = 116,
	LINUX_MIB_TCPRCVQDROP = 117,
	LINUX_MIB_TCPWQUEUETOOBIG = 118,
	LINUX_MIB_TCPFASTOPENPASSIVEALTKEY = 119,
	LINUX_MIB_TCPTIMEOUTREHASH = 120,
	LINUX_MIB_TCPDUPLICATEDATAREHASH = 121,
	LINUX_MIB_TCPDSACKRECVSEGS = 122,
	LINUX_MIB_TCPDSACKIGNOREDDUBIOUS = 123,
	LINUX_MIB_TCPMIGRATEREQSUCCESS = 124,
	LINUX_MIB_TCPMIGRATEREQFAILURE = 125,
	__LINUX_MIB_MAX = 126,
};

enum {
	LINUX_MIB_XFRMNUM = 0,
	LINUX_MIB_XFRMINERROR = 1,
	LINUX_MIB_XFRMINBUFFERERROR = 2,
	LINUX_MIB_XFRMINHDRERROR = 3,
	LINUX_MIB_XFRMINNOSTATES = 4,
	LINUX_MIB_XFRMINSTATEPROTOERROR = 5,
	LINUX_MIB_XFRMINSTATEMODEERROR = 6,
	LINUX_MIB_XFRMINSTATESEQERROR = 7,
	LINUX_MIB_XFRMINSTATEEXPIRED = 8,
	LINUX_MIB_XFRMINSTATEMISMATCH = 9,
	LINUX_MIB_XFRMINSTATEINVALID = 10,
	LINUX_MIB_XFRMINTMPLMISMATCH = 11,
	LINUX_MIB_XFRMINNOPOLS = 12,
	LINUX_MIB_XFRMINPOLBLOCK = 13,
	LINUX_MIB_XFRMINPOLERROR = 14,
	LINUX_MIB_XFRMOUTERROR = 15,
	LINUX_MIB_XFRMOUTBUNDLEGENERROR = 16,
	LINUX_MIB_XFRMOUTBUNDLECHECKERROR = 17,
	LINUX_MIB_XFRMOUTNOSTATES = 18,
	LINUX_MIB_XFRMOUTSTATEPROTOERROR = 19,
	LINUX_MIB_XFRMOUTSTATEMODEERROR = 20,
	LINUX_MIB_XFRMOUTSTATESEQERROR = 21,
	LINUX_MIB_XFRMOUTSTATEEXPIRED = 22,
	LINUX_MIB_XFRMOUTPOLBLOCK = 23,
	LINUX_MIB_XFRMOUTPOLDEAD = 24,
	LINUX_MIB_XFRMOUTPOLERROR = 25,
	LINUX_MIB_XFRMFWDHDRERROR = 26,
	LINUX_MIB_XFRMOUTSTATEINVALID = 27,
	LINUX_MIB_XFRMACQUIREERROR = 28,
	__LINUX_MIB_XFRMMAX = 29,
};

enum {
	LINUX_MIB_TLSNUM = 0,
	LINUX_MIB_TLSCURRTXSW = 1,
	LINUX_MIB_TLSCURRRXSW = 2,
	LINUX_MIB_TLSCURRTXDEVICE = 3,
	LINUX_MIB_TLSCURRRXDEVICE = 4,
	LINUX_MIB_TLSTXSW = 5,
	LINUX_MIB_TLSRXSW = 6,
	LINUX_MIB_TLSTXDEVICE = 7,
	LINUX_MIB_TLSRXDEVICE = 8,
	LINUX_MIB_TLSDECRYPTERROR = 9,
	LINUX_MIB_TLSRXDEVICERESYNC = 10,
	__LINUX_MIB_TLSMAX = 11,
};

struct ipstats_mib {
	u64 mibs[37];
	struct u64_stats_sync syncp;
};

struct icmp_mib {
	long unsigned int mibs[28];
};

struct icmpmsg_mib {
	atomic_long_t mibs[512];
};

struct icmpv6_mib {
	long unsigned int mibs[6];
};

struct icmpv6msg_mib {
	atomic_long_t mibs[512];
};

struct tcp_mib {
	long unsigned int mibs[16];
};

struct udp_mib {
	long unsigned int mibs[10];
};

struct linux_mib {
	long unsigned int mibs[126];
};

struct linux_xfrm_mib {
	long unsigned int mibs[29];
};

struct linux_tls_mib {
	long unsigned int mibs[11];
};

struct inet_frags;

struct fqdir {
	long int high_thresh;
	long int low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags *f;
	struct net *net;
	bool dead;
	long: 56;
	long: 64;
	long: 64;
	struct rhashtable rhashtable;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
	long: 64;
	long: 64;
};

struct inet_frag_queue;

struct inet_frags {
	unsigned int qsize;
	void (*constructor)(struct inet_frag_queue *, const void *);
	void (*destructor)(struct inet_frag_queue *);
	void (*frag_expire)(struct timer_list *);
	struct kmem_cache *frags_cachep;
	const char *frags_cache_name;
	struct rhashtable_params rhash_params;
	refcount_t refcnt;
	struct completion completion;
};

struct frag_v4_compare_key {
	__be32 saddr;
	__be32 daddr;
	u32 user;
	u32 vif;
	__be16 id;
	u16 protocol;
};

struct frag_v6_compare_key {
	struct in6_addr saddr;
	struct in6_addr daddr;
	u32 user;
	__be32 id;
	u32 iif;
};

struct inet_frag_queue {
	struct rhash_head node;
	union {
		struct frag_v4_compare_key v4;
		struct frag_v6_compare_key v6;
	} key;
	struct timer_list timer;
	spinlock_t lock;
	refcount_t refcnt;
	struct rb_root rb_fragments;
	struct sk_buff *fragments_tail;
	struct sk_buff *last_run_head;
	ktime_t stamp;
	int len;
	int meat;
	u8 mono_delivery_time;
	__u8 flags;
	u16 max_size;
	struct fqdir *fqdir;
	struct callback_head rcu;
};

struct inet_hashinfo;

struct inet_timewait_death_row {
	refcount_t tw_refcount;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct inet_hashinfo *hashinfo;
	int sysctl_max_tw_buckets;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum tcp_ca_event {
	CA_EVENT_TX_START = 0,
	CA_EVENT_CWND_RESTART = 1,
	CA_EVENT_COMPLETE_CWR = 2,
	CA_EVENT_LOSS = 3,
	CA_EVENT_ECN_NO_CE = 4,
	CA_EVENT_ECN_IS_CE = 5,
};

struct ack_sample;

struct rate_sample;

union tcp_cc_info;

struct tcp_congestion_ops {
	u32 (*ssthresh)(struct sock *);
	void (*cong_avoid)(struct sock *, u32, u32);
	void (*set_state)(struct sock *, u8);
	void (*cwnd_event)(struct sock *, enum tcp_ca_event);
	void (*in_ack_event)(struct sock *, u32);
	void (*pkts_acked)(struct sock *, const struct ack_sample *);
	u32 (*min_tso_segs)(struct sock *);
	void (*cong_control)(struct sock *, const struct rate_sample *);
	u32 (*undo_cwnd)(struct sock *);
	u32 (*sndbuf_expand)(struct sock *);
	size_t (*get_info)(struct sock *, u32, int *, union tcp_cc_info *);
	char name[16];
	struct module *owner;
	struct list_head list;
	u32 key;
	u32 flags;
	void (*init)(struct sock *);
	void (*release)(struct sock *);
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

typedef struct {} netdevice_tracker;

struct xfrm_state;

struct lwtunnel_state;

struct dst_entry {
	struct net_device *dev;
	struct dst_ops *ops;
	long unsigned int _metrics;
	long unsigned int expires;
	struct xfrm_state *xfrm;
	int (*input)(struct sk_buff *);
	int (*output)(struct net *, struct sock *, struct sk_buff *);
	short unsigned int flags;
	short int obsolete;
	short unsigned int header_len;
	short unsigned int trailer_len;
	atomic_t __refcnt;
	int __use;
	long unsigned int lastuse;
	struct lwtunnel_state *lwtstate;
	struct callback_head callback_head;
	short int error;
	short int __pad;
	__u32 tclassid;
	netdevice_tracker dev_tracker;
};

enum nf_inet_hooks {
	NF_INET_PRE_ROUTING = 0,
	NF_INET_LOCAL_IN = 1,
	NF_INET_FORWARD = 2,
	NF_INET_LOCAL_OUT = 3,
	NF_INET_POST_ROUTING = 4,
	NF_INET_NUMHOOKS = 5,
	NF_INET_INGRESS = 5,
};

enum {
	NFPROTO_UNSPEC = 0,
	NFPROTO_INET = 1,
	NFPROTO_IPV4 = 2,
	NFPROTO_ARP = 3,
	NFPROTO_NETDEV = 5,
	NFPROTO_BRIDGE = 7,
	NFPROTO_IPV6 = 10,
	NFPROTO_DECNET = 12,
	NFPROTO_NUMPROTO = 13,
};

enum nf_log_type {
	NF_LOG_TYPE_LOG = 0,
	NF_LOG_TYPE_ULOG = 1,
	NF_LOG_TYPE_MAX = 2,
};

typedef u8 u_int8_t;

struct nf_loginfo;

typedef void nf_logfn(struct net *, u_int8_t, unsigned int, const struct sk_buff *, const struct net_device *, const struct net_device *, const struct nf_loginfo *, const char *);

struct nf_logger {
	char *name;
	enum nf_log_type type;
	nf_logfn *logfn;
	struct module *me;
};

enum tcp_conntrack {
	TCP_CONNTRACK_NONE = 0,
	TCP_CONNTRACK_SYN_SENT = 1,
	TCP_CONNTRACK_SYN_RECV = 2,
	TCP_CONNTRACK_ESTABLISHED = 3,
	TCP_CONNTRACK_FIN_WAIT = 4,
	TCP_CONNTRACK_CLOSE_WAIT = 5,
	TCP_CONNTRACK_LAST_ACK = 6,
	TCP_CONNTRACK_TIME_WAIT = 7,
	TCP_CONNTRACK_CLOSE = 8,
	TCP_CONNTRACK_LISTEN = 9,
	TCP_CONNTRACK_MAX = 10,
	TCP_CONNTRACK_IGNORE = 11,
	TCP_CONNTRACK_RETRANS = 12,
	TCP_CONNTRACK_UNACK = 13,
	TCP_CONNTRACK_TIMEOUT_MAX = 14,
};

enum ct_dccp_states {
	CT_DCCP_NONE = 0,
	CT_DCCP_REQUEST = 1,
	CT_DCCP_RESPOND = 2,
	CT_DCCP_PARTOPEN = 3,
	CT_DCCP_OPEN = 4,
	CT_DCCP_CLOSEREQ = 5,
	CT_DCCP_CLOSING = 6,
	CT_DCCP_TIMEWAIT = 7,
	CT_DCCP_IGNORE = 8,
	CT_DCCP_INVALID = 9,
	__CT_DCCP_MAX = 10,
};

struct ip_conntrack_stat {
	unsigned int found;
	unsigned int invalid;
	unsigned int insert;
	unsigned int insert_failed;
	unsigned int clash_resolve;
	unsigned int drop;
	unsigned int early_drop;
	unsigned int error;
	unsigned int expect_new;
	unsigned int expect_create;
	unsigned int expect_delete;
	unsigned int search_restart;
	unsigned int chaintoolong;
};

enum ip_conntrack_dir {
	IP_CT_DIR_ORIGINAL = 0,
	IP_CT_DIR_REPLY = 1,
	IP_CT_DIR_MAX = 2,
};

enum sctp_conntrack {
	SCTP_CONNTRACK_NONE = 0,
	SCTP_CONNTRACK_CLOSED = 1,
	SCTP_CONNTRACK_COOKIE_WAIT = 2,
	SCTP_CONNTRACK_COOKIE_ECHOED = 3,
	SCTP_CONNTRACK_ESTABLISHED = 4,
	SCTP_CONNTRACK_SHUTDOWN_SENT = 5,
	SCTP_CONNTRACK_SHUTDOWN_RECD = 6,
	SCTP_CONNTRACK_SHUTDOWN_ACK_SENT = 7,
	SCTP_CONNTRACK_HEARTBEAT_SENT = 8,
	SCTP_CONNTRACK_HEARTBEAT_ACKED = 9,
	SCTP_CONNTRACK_MAX = 10,
};

enum udp_conntrack {
	UDP_CT_UNREPLIED = 0,
	UDP_CT_REPLIED = 1,
	UDP_CT_MAX = 2,
};

enum gre_conntrack {
	GRE_CT_UNREPLIED = 0,
	GRE_CT_REPLIED = 1,
	GRE_CT_MAX = 2,
};

enum {
	XFRM_POLICY_IN = 0,
	XFRM_POLICY_OUT = 1,
	XFRM_POLICY_FWD = 2,
	XFRM_POLICY_MASK = 3,
	XFRM_POLICY_MAX = 3,
};

enum netns_bpf_attach_type {
	NETNS_BPF_INVALID = 4294967295,
	NETNS_BPF_FLOW_DISSECTOR = 0,
	NETNS_BPF_SK_LOOKUP = 1,
	MAX_NETNS_BPF_ATTACH_TYPE = 2,
};

struct pipe_buf_operations;

struct pipe_buffer {
	struct page *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations {
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

struct skb_ext {
	refcount_t refcnt;
	u8 offset[4];
	u8 chunks;
	long: 56;
	char data[0];
};

enum skb_ext_id {
	SKB_EXT_BRIDGE_NF = 0,
	SKB_EXT_SEC_PATH = 1,
	TC_SKB_EXT = 2,
	SKB_EXT_MPTCP = 3,
	SKB_EXT_NUM = 4,
};

struct trace_event_raw_initcall_level {
	struct trace_entry ent;
	u32 __data_loc_level;
	char __data[0];
};

struct trace_event_raw_initcall_start {
	struct trace_entry ent;
	initcall_t func;
	char __data[0];
};

struct trace_event_raw_initcall_finish {
	struct trace_entry ent;
	initcall_t func;
	int ret;
	char __data[0];
};

struct trace_event_data_offsets_initcall_level {
	u32 level;
};

struct trace_event_data_offsets_initcall_start {};

struct trace_event_data_offsets_initcall_finish {};

typedef void (*btf_trace_initcall_level)(void *, const char *);

typedef void (*btf_trace_initcall_start)(void *, initcall_t);

typedef void (*btf_trace_initcall_finish)(void *, initcall_t, int);

struct blacklist_entry {
	struct list_head next;
	char *buf;
};

typedef __u32 Elf32_Word;

struct elf32_note {
	Elf32_Word n_namesz;
	Elf32_Word n_descsz;
	Elf32_Word n_type;
};

enum {
	PROC_ROOT_INO = 1,
	PROC_IPC_INIT_INO = 4026531839,
	PROC_UTS_INIT_INO = 4026531838,
	PROC_USER_INIT_INO = 4026531837,
	PROC_PID_INIT_INO = 4026531836,
	PROC_CGROUP_INIT_INO = 4026531835,
	PROC_TIME_INIT_INO = 4026531834,
};

typedef __u16 __le16;

typedef __u64 __be64;

typedef unsigned int slab_flags_t;

enum pageflags {
	PG_locked = 0,
	PG_referenced = 1,
	PG_uptodate = 2,
	PG_dirty = 3,
	PG_lru = 4,
	PG_active = 5,
	PG_workingset = 6,
	PG_waiters = 7,
	PG_error = 8,
	PG_slab = 9,
	PG_owner_priv_1 = 10,
	PG_arch_1 = 11,
	PG_reserved = 12,
	PG_private = 13,
	PG_private_2 = 14,
	PG_writeback = 15,
	PG_head = 16,
	PG_mappedtodisk = 17,
	PG_reclaim = 18,
	PG_swapbacked = 19,
	PG_unevictable = 20,
	PG_mlocked = 21,
	PG_uncached = 22,
	PG_hwpoison = 23,
	PG_young = 24,
	PG_idle = 25,
	PG_arch_2 = 26,
	__NR_PAGEFLAGS = 27,
	PG_readahead = 18,
	PG_anon_exclusive = 17,
	PG_checked = 10,
	PG_swapcache = 10,
	PG_fscache = 14,
	PG_pinned = 10,
	PG_savepinned = 3,
	PG_foreign = 10,
	PG_xen_remapped = 10,
	PG_slob_free = 13,
	PG_double_map = 6,
	PG_has_hwpoisoned = 8,
	PG_isolated = 18,
	PG_reported = 2,
};

typedef __u64 __addrpair;

typedef __u32 __portpair;

typedef struct {
	struct net *net;
} possible_net_t;

struct hlist_nulls_node {
	struct hlist_nulls_node *next;
	struct hlist_nulls_node **pprev;
};

struct proto;

struct sock_common {
	union {
		__addrpair skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		unsigned int skc_hash;
		__u16 skc_u16hashes[2];
	};
	union {
		__portpair skc_portpair;
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
	volatile unsigned char skc_state;
	unsigned char skc_reuse: 4;
	unsigned char skc_reuseport: 1;
	unsigned char skc_ipv6only: 1;
	unsigned char skc_net_refcnt: 1;
	int skc_bound_dev_if;
	union {
		struct hlist_node skc_bind_node;
		struct hlist_node skc_portaddr_node;
	};
	struct proto *skc_prot;
	possible_net_t skc_net;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
	atomic64_t skc_cookie;
	union {
		long unsigned int skc_flags;
		struct sock *skc_listener;
		struct inet_timewait_death_row *skc_tw_dr;
	};
	int skc_dontcopy_begin[0];
	union {
		struct hlist_node skc_node;
		struct hlist_nulls_node skc_nulls_node;
	};
	short unsigned int skc_tx_queue_mapping;
	short unsigned int skc_rx_queue_mapping;
	union {
		int skc_incoming_cpu;
		u32 skc_rcv_wnd;
		u32 skc_tw_rcv_nxt;
	};
	refcount_t skc_refcnt;
	int skc_dontcopy_end[0];
	union {
		u32 skc_rxhash;
		u32 skc_window_clamp;
		u32 skc_tw_snd_nxt;
	};
};

typedef struct {
	spinlock_t slock;
	int owned;
	wait_queue_head_t wq;
} socket_lock_t;

typedef u64 netdev_features_t;

struct sock_cgroup_data {
	struct cgroup *cgroup;
	u32 classid;
	u16 prioidx;
};

typedef struct {} netns_tracker;

struct sk_filter;

struct socket_wq;

struct xfrm_policy;

struct socket;

struct sock_reuseport;

struct sock {
	struct sock_common __sk_common;
	struct dst_entry *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	socket_lock_t sk_lock;
	atomic_t sk_drops;
	int sk_rcvlowat;
	struct sk_buff_head sk_error_queue;
	struct sk_buff_head sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	int sk_forward_alloc;
	u32 sk_reserved_mem;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	struct xfrm_policy *sk_policy[2];
	struct dst_entry *sk_dst_cache;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head sk_write_queue;
	__s32 sk_peek_off;
	int sk_write_pending;
	__u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	long int sk_sndtimeo;
	struct timer_list sk_timer;
	__u32 sk_priority;
	__u32 sk_mark;
	long unsigned int sk_pacing_rate;
	long unsigned int sk_max_pacing_rate;
	struct page_frag sk_frag;
	netdev_features_t sk_route_caps;
	int sk_gso_type;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	__u32 sk_txhash;
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_userlocks: 4;
	u8 sk_pacing_shift;
	u16 sk_type;
	u16 sk_protocol;
	u16 sk_gso_max_segs;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	u8 sk_txrehash;
	u8 sk_prefer_busy_poll;
	u16 sk_busy_poll_budget;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid *sk_peer_pid;
	const struct cred *sk_peer_cred;
	long int sk_rcvtimeo;
	ktime_t sk_stamp;
	u16 sk_tsflags;
	u8 sk_shutdown;
	atomic_t sk_tskey;
	atomic_t sk_zckey;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	struct socket *sk_socket;
	void *sk_user_data;
	void *sk_security;
	struct sock_cgroup_data sk_cgrp_data;
	struct mem_cgroup *sk_memcg;
	void (*sk_state_change)(struct sock *);
	void (*sk_data_ready)(struct sock *);
	void (*sk_write_space)(struct sock *);
	void (*sk_error_report)(struct sock *);
	int (*sk_backlog_rcv)(struct sock *, struct sk_buff *);
	struct sk_buff * (*sk_validate_xmit_skb)(struct sock *, struct net_device *, struct sk_buff *);
	void (*sk_destruct)(struct sock *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
};

struct fs_struct {
	int users;
	spinlock_t lock;
	seqcount_spinlock_t seq;
	int umask;
	int in_exec;
	struct path root;
	struct path pwd;
};

typedef short unsigned int __kernel_sa_family_t;

typedef __kernel_sa_family_t sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	char sa_data[14];
};

struct msghdr {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb *msg_iocb;
};

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
} sync_serial_settings;

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
	unsigned int slot_map;
} te1_settings;

typedef struct {
	short unsigned int encoding;
	short unsigned int parity;
} raw_hdlc_proto;

typedef struct {
	unsigned int t391;
	unsigned int t392;
	unsigned int n391;
	unsigned int n392;
	unsigned int n393;
	short unsigned int lmi;
	short unsigned int dce;
} fr_proto;

typedef struct {
	unsigned int dlci;
} fr_proto_pvc;

typedef struct {
	unsigned int dlci;
	char master[16];
} fr_proto_pvc_info;

typedef struct {
	unsigned int interval;
	unsigned int timeout;
} cisco_proto;

typedef struct {
	short unsigned int dce;
	unsigned int modulo;
	unsigned int window;
	unsigned int t1;
	unsigned int t2;
	unsigned int n2;
} x25_hdlc_proto;

struct ifmap {
	long unsigned int mem_start;
	long unsigned int mem_end;
	short unsigned int base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
};

struct if_settings {
	unsigned int type;
	unsigned int size;
	union {
		raw_hdlc_proto *raw_hdlc;
		cisco_proto *cisco;
		fr_proto *fr;
		fr_proto_pvc *fr_pvc;
		fr_proto_pvc_info *fr_pvc_info;
		x25_hdlc_proto *x25;
		sync_serial_settings *sync;
		te1_settings *te1;
	} ifs_ifsu;
};

struct ifreq {
	union {
		char ifrn_name[16];
	} ifr_ifrn;
	union {
		struct sockaddr ifru_addr;
		struct sockaddr ifru_dstaddr;
		struct sockaddr ifru_broadaddr;
		struct sockaddr ifru_netmask;
		struct sockaddr ifru_hwaddr;
		short int ifru_flags;
		int ifru_ivalue;
		int ifru_mtu;
		struct ifmap ifru_map;
		char ifru_slave[16];
		char ifru_newname[16];
		void *ifru_data;
		struct if_settings ifru_settings;
	} ifr_ifru;
};

struct ld_semaphore {
	atomic_long_t count;
	raw_spinlock_t wait_lock;
	unsigned int wait_readers;
	struct list_head read_wait;
	struct list_head write_wait;
};

typedef unsigned int tcflag_t;

typedef unsigned char cc_t;

typedef unsigned int speed_t;

struct ktermios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_line;
	cc_t c_cc[19];
	speed_t c_ispeed;
	speed_t c_ospeed;
};

struct winsize {
	short unsigned int ws_row;
	short unsigned int ws_col;
	short unsigned int ws_xpixel;
	short unsigned int ws_ypixel;
};

struct tty_driver;

struct tty_operations;

struct tty_ldisc;

struct tty_port;

struct tty_struct {
	int magic;
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;
	struct ld_semaphore ldisc_sem;
	struct tty_ldisc *ldisc;
	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	struct ktermios termios;
	struct ktermios termios_locked;
	char name[64];
	long unsigned int flags;
	int count;
	struct winsize winsize;
	struct {
		spinlock_t lock;
		bool stopped;
		bool tco_stopped;
		long unsigned int unused[0];
	} flow;
	struct {
		spinlock_t lock;
		struct pid *pgrp;
		struct pid *session;
		unsigned char pktstatus;
		bool packet;
		long unsigned int unused[0];
	} ctrl;
	int hw_stopped;
	unsigned int receive_room;
	int flow_change;
	struct tty_struct *link;
	struct fasync_struct *fasync;
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	spinlock_t files_lock;
	struct list_head tty_files;
	int closing;
	unsigned char *write_buf;
	int write_cnt;
	struct work_struct SAK_work;
	struct tty_port *port;
};

struct posix_acl_entry {
	short int e_tag;
	short unsigned int e_perm;
	union {
		kuid_t e_uid;
		kgid_t e_gid;
	};
};

struct posix_acl {
	refcount_t a_refcount;
	struct callback_head a_rcu;
	unsigned int a_count;
	struct posix_acl_entry a_entries[0];
};

struct tty_buffer {
	union {
		struct tty_buffer *next;
		struct llist_node free;
	};
	int used;
	int size;
	int commit;
	int read;
	int flags;
	long unsigned int data[0];
};

struct tty_bufhead {
	struct tty_buffer *head;
	struct work_struct work;
	struct mutex lock;
	atomic_t priority;
	struct tty_buffer sentinel;
	struct llist_head free;
	atomic_t mem_used;
	int mem_limit;
	struct tty_buffer *tail;
};

struct serial_icounter_struct;

struct serial_struct;

struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *, struct file *, int);
	int (*install)(struct tty_driver *, struct tty_struct *);
	void (*remove)(struct tty_driver *, struct tty_struct *);
	int (*open)(struct tty_struct *, struct file *);
	void (*close)(struct tty_struct *, struct file *);
	void (*shutdown)(struct tty_struct *);
	void (*cleanup)(struct tty_struct *);
	int (*write)(struct tty_struct *, const unsigned char *, int);
	int (*put_char)(struct tty_struct *, unsigned char);
	void (*flush_chars)(struct tty_struct *);
	unsigned int (*write_room)(struct tty_struct *);
	unsigned int (*chars_in_buffer)(struct tty_struct *);
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	void (*set_termios)(struct tty_struct *, struct ktermios *);
	void (*throttle)(struct tty_struct *);
	void (*unthrottle)(struct tty_struct *);
	void (*stop)(struct tty_struct *);
	void (*start)(struct tty_struct *);
	void (*hangup)(struct tty_struct *);
	int (*break_ctl)(struct tty_struct *, int);
	void (*flush_buffer)(struct tty_struct *);
	void (*set_ldisc)(struct tty_struct *);
	void (*wait_until_sent)(struct tty_struct *, int);
	void (*send_xchar)(struct tty_struct *, char);
	int (*tiocmget)(struct tty_struct *);
	int (*tiocmset)(struct tty_struct *, unsigned int, unsigned int);
	int (*resize)(struct tty_struct *, struct winsize *);
	int (*get_icount)(struct tty_struct *, struct serial_icounter_struct *);
	int (*get_serial)(struct tty_struct *, struct serial_struct *);
	int (*set_serial)(struct tty_struct *, struct serial_struct *);
	void (*show_fdinfo)(struct tty_struct *, struct seq_file *);
	int (*poll_init)(struct tty_driver *, int, char *);
	int (*poll_get_char)(struct tty_driver *, int);
	void (*poll_put_char)(struct tty_driver *, int, char);
	int (*proc_show)(struct seq_file *, void *);
};

struct tty_driver {
	int magic;
	struct kref kref;
	struct cdev **cdevs;
	struct module *owner;
	const char *driver_name;
	const char *name;
	int name_base;
	int major;
	int minor_start;
	unsigned int num;
	short int type;
	short int subtype;
	struct ktermios init_termios;
	long unsigned int flags;
	struct proc_dir_entry *proc_entry;
	struct tty_driver *other;
	struct tty_struct **ttys;
	struct tty_port **ports;
	struct ktermios **termios;
	void *driver_state;
	const struct tty_operations *ops;
	struct list_head tty_drivers;
};

struct __kfifo {
	unsigned int in;
	unsigned int out;
	unsigned int mask;
	unsigned int esize;
	void *data;
};

struct tty_port_operations;

struct tty_port_client_operations;

struct tty_port {
	struct tty_bufhead buf;
	struct tty_struct *tty;
	struct tty_struct *itty;
	const struct tty_port_operations *ops;
	const struct tty_port_client_operations *client_ops;
	spinlock_t lock;
	int blocked_open;
	int count;
	wait_queue_head_t open_wait;
	wait_queue_head_t delta_msr_wait;
	long unsigned int flags;
	long unsigned int iflags;
	unsigned char console: 1;
	struct mutex mutex;
	struct mutex buf_mutex;
	unsigned char *xmit_buf;
	struct {
		union {
			struct __kfifo kfifo;
			unsigned char *type;
			const unsigned char *const_type;
			char (*rectype)[0];
			unsigned char *ptr;
			const unsigned char *ptr_const;
		};
		unsigned char buf[0];
	} xmit_fifo;
	unsigned int close_delay;
	unsigned int closing_wait;
	int drain_delay;
	struct kref kref;
	void *client_data;
};

struct tty_ldisc_ops {
	char *name;
	int num;
	int (*open)(struct tty_struct *);
	void (*close)(struct tty_struct *);
	void (*flush_buffer)(struct tty_struct *);
	ssize_t (*read)(struct tty_struct *, struct file *, unsigned char *, size_t, void **, long unsigned int);
	ssize_t (*write)(struct tty_struct *, struct file *, const unsigned char *, size_t);
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	void (*set_termios)(struct tty_struct *, struct ktermios *);
	__poll_t (*poll)(struct tty_struct *, struct file *, struct poll_table_struct *);
	void (*hangup)(struct tty_struct *);
	void (*receive_buf)(struct tty_struct *, const unsigned char *, const char *, int);
	void (*write_wakeup)(struct tty_struct *);
	void (*dcd_change)(struct tty_struct *, unsigned int);
	int (*receive_buf2)(struct tty_struct *, const unsigned char *, const char *, int);
	struct module *owner;
};

struct tty_ldisc {
	struct tty_ldisc_ops *ops;
	struct tty_struct *tty;
};

struct scatterlist {
	long unsigned int page_link;
	unsigned int offset;
	unsigned int length;
	dma_addr_t dma_address;
	unsigned int dma_length;
};

struct tty_port_operations {
	int (*carrier_raised)(struct tty_port *);
	void (*dtr_rts)(struct tty_port *, int);
	void (*shutdown)(struct tty_port *);
	int (*activate)(struct tty_port *, struct tty_struct *);
	void (*destruct)(struct tty_port *);
};

struct tty_port_client_operations {
	int (*receive_buf)(struct tty_port *, const unsigned char *, const unsigned char *, size_t);
	void (*write_wakeup)(struct tty_port *);
};

typedef struct {
	local64_t v;
} u64_stats_t;

enum {
	Root_NFS = 255,
	Root_CIFS = 254,
	Root_RAM0 = 1048576,
	Root_RAM1 = 1048577,
	Root_FD0 = 2097152,
	Root_HDA1 = 3145729,
	Root_HDA2 = 3145730,
	Root_SDA1 = 8388609,
	Root_SDA2 = 8388610,
	Root_HDC1 = 23068673,
	Root_SR0 = 11534336,
};

enum {
	IPPROTO_IP = 0,
	IPPROTO_ICMP = 1,
	IPPROTO_IGMP = 2,
	IPPROTO_IPIP = 4,
	IPPROTO_TCP = 6,
	IPPROTO_EGP = 8,
	IPPROTO_PUP = 12,
	IPPROTO_UDP = 17,
	IPPROTO_IDP = 22,
	IPPROTO_TP = 29,
	IPPROTO_DCCP = 33,
	IPPROTO_IPV6 = 41,
	IPPROTO_RSVP = 46,
	IPPROTO_GRE = 47,
	IPPROTO_ESP = 50,
	IPPROTO_AH = 51,
	IPPROTO_MTP = 92,
	IPPROTO_BEETPH = 94,
	IPPROTO_ENCAP = 98,
	IPPROTO_PIM = 103,
	IPPROTO_COMP = 108,
	IPPROTO_SCTP = 132,
	IPPROTO_UDPLITE = 136,
	IPPROTO_MPLS = 137,
	IPPROTO_ETHERNET = 143,
	IPPROTO_RAW = 255,
	IPPROTO_MPTCP = 262,
	IPPROTO_MAX = 263,
};

struct flowi_tunnel {
	__be64 tun_id;
};

struct flowi_common {
	int flowic_oif;
	int flowic_iif;
	int flowic_l3mdev;
	__u32 flowic_mark;
	__u8 flowic_tos;
	__u8 flowic_scope;
	__u8 flowic_proto;
	__u8 flowic_flags;
	__u32 flowic_secid;
	kuid_t flowic_uid;
	struct flowi_tunnel flowic_tun_key;
	__u32 flowic_multipath_hash;
};

union flowi_uli {
	struct {
		__be16 dport;
		__be16 sport;
	} ports;
	struct {
		__u8 type;
		__u8 code;
	} icmpt;
	struct {
		__le16 dport;
		__le16 sport;
	} dnports;
	__be32 gre_key;
	struct {
		__u8 type;
	} mht;
};

struct flowi4 {
	struct flowi_common __fl_common;
	__be32 saddr;
	__be32 daddr;
	union flowi_uli uli;
};

struct flowi6 {
	struct flowi_common __fl_common;
	struct in6_addr daddr;
	struct in6_addr saddr;
	__be32 flowlabel;
	union flowi_uli uli;
	__u32 mp_hash;
};

struct flowidn {
	struct flowi_common __fl_common;
	__le16 daddr;
	__le16 saddr;
	union flowi_uli uli;
};

struct flowi {
	union {
		struct flowi_common __fl_common;
		struct flowi4 ip4;
		struct flowi6 ip6;
		struct flowidn dn;
	} u;
};

struct prot_inuse {
	int all;
	int val[64];
};

struct icmpv6_mib_device {
	atomic_long_t mibs[6];
};

struct icmpv6msg_mib_device {
	atomic_long_t mibs[512];
};

struct fib_rule;

struct fib_lookup_arg;

struct fib_rule_hdr;

struct nlattr;

struct netlink_ext_ack;

struct fib_rules_ops {
	int family;
	struct list_head list;
	int rule_size;
	int addr_size;
	int unresolved_rules;
	int nr_goto_rules;
	unsigned int fib_rules_seq;
	int (*action)(struct fib_rule *, struct flowi *, int, struct fib_lookup_arg *);
	bool (*suppress)(struct fib_rule *, int, struct fib_lookup_arg *);
	int (*match)(struct fib_rule *, struct flowi *, int);
	int (*configure)(struct fib_rule *, struct sk_buff *, struct fib_rule_hdr *, struct nlattr **, struct netlink_ext_ack *);
	int (*delete)(struct fib_rule *);
	int (*compare)(struct fib_rule *, struct fib_rule_hdr *, struct nlattr **);
	int (*fill)(struct fib_rule *, struct sk_buff *, struct fib_rule_hdr *);
	size_t (*nlmsg_payload)(struct fib_rule *);
	void (*flush_cache)(struct fib_rules_ops *);
	int nlgroup;
	struct list_head rules_list;
	struct module *owner;
	struct net *fro_net;
	struct callback_head rcu;
};

struct fib_notifier_ops {
	int family;
	struct list_head list;
	unsigned int (*fib_seq_read)(struct net *);
	int (*fib_dump)(struct net *, struct notifier_block *, struct netlink_ext_ack *);
	struct module *owner;
	struct callback_head rcu;
};

struct net_device_stats {
	long unsigned int rx_packets;
	long unsigned int tx_packets;
	long unsigned int rx_bytes;
	long unsigned int tx_bytes;
	long unsigned int rx_errors;
	long unsigned int tx_errors;
	long unsigned int rx_dropped;
	long unsigned int tx_dropped;
	long unsigned int multicast;
	long unsigned int collisions;
	long unsigned int rx_length_errors;
	long unsigned int rx_over_errors;
	long unsigned int rx_crc_errors;
	long unsigned int rx_frame_errors;
	long unsigned int rx_fifo_errors;
	long unsigned int rx_missed_errors;
	long unsigned int tx_aborted_errors;
	long unsigned int tx_carrier_errors;
	long unsigned int tx_fifo_errors;
	long unsigned int tx_heartbeat_errors;
	long unsigned int tx_window_errors;
	long unsigned int rx_compressed;
	long unsigned int tx_compressed;
};

struct netdev_hw_addr_list {
	struct list_head list;
	int count;
	struct rb_root tree;
};

struct tipc_bearer;

struct dn_dev;

struct mpls_dev;

enum rx_handler_result {
	RX_HANDLER_CONSUMED = 0,
	RX_HANDLER_ANOTHER = 1,
	RX_HANDLER_EXACT = 2,
	RX_HANDLER_PASS = 3,
};

typedef enum rx_handler_result rx_handler_result_t;

typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **);

enum netdev_ml_priv_type {
	ML_PRIV_NONE = 0,
	ML_PRIV_CAN = 1,
};

struct pcpu_dstats;

struct garp_port;

struct mrp_port;

struct netdev_tc_txq {
	u16 count;
	u16 offset;
};

struct macsec_ops;

struct udp_tunnel_nic;

struct bpf_xdp_link;

struct bpf_xdp_entity {
	struct bpf_prog *prog;
	struct bpf_xdp_link *link;
};

struct netdev_name_node;

struct dev_ifalias;

struct net_device_ops;

struct net_device_core_stats;

struct iw_handler_def;

struct iw_public_data;

struct ethtool_ops;

struct l3mdev_ops;

struct ndisc_ops;

struct xfrmdev_ops;

struct tlsdev_ops;

struct header_ops;

struct in_device;

struct inet6_dev;

struct vlan_info;

struct dsa_port;

struct wireless_dev;

struct wpan_dev;

struct netdev_rx_queue;

struct mini_Qdisc;

struct netdev_queue;

struct cpu_rmap;

struct Qdisc;

struct xdp_dev_bulk_queue;

struct xps_dev_maps;

struct netpoll_info;

struct pcpu_lstats;

struct pcpu_sw_netstats;

struct dm_hw_stat_delta;

struct rtnl_link_ops;

struct dcbnl_rtnl_ops;

struct netprio_map;

struct phy_device;

struct sfp_bus;

struct udp_tunnel_nic_info;

struct rtnl_hw_stats64;

struct net_device {
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	long unsigned int state;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct list_head ptype_specific;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	unsigned int flags;
	long long unsigned int priv_flags;
	const struct net_device_ops *netdev_ops;
	int ifindex;
	short unsigned int gflags;
	short unsigned int hard_header_len;
	unsigned int mtu;
	short unsigned int needed_headroom;
	short unsigned int needed_tailroom;
	netdev_features_t features;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	netdev_features_t gso_partial_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct iw_handler_def *wireless_handlers;
	struct iw_public_data *wireless_data;
	const struct ethtool_ops *ethtool_ops;
	const struct l3mdev_ops *l3mdev_ops;
	const struct ndisc_ops *ndisc_ops;
	const struct xfrmdev_ops *xfrmdev_ops;
	const struct tlsdev_ops *tlsdev_ops;
	const struct header_ops *header_ops;
	unsigned char operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	short unsigned int padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct inet6_dev *ip6_ptr;
	struct vlan_info *vlan_info;
	struct dsa_port *dsa_ptr;
	struct tipc_bearer *tipc_ptr;
	void *atalk_ptr;
	struct dn_dev *dn_ptr;
	void *ax25_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	struct mpls_dev *mpls_ptr;
	const unsigned char *dev_addr;
	struct netdev_rx_queue *_rx;
	unsigned int num_rx_queues;
	unsigned int real_num_rx_queues;
	struct bpf_prog *xdp_prog;
	long unsigned int gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	rx_handler_func_t *rx_handler;
	void *rx_handler_data;
	struct mini_Qdisc *miniq_ingress;
	struct netdev_queue *ingress_queue;
	struct nf_hook_entries *nf_hooks_ingress;
	unsigned char broadcast[32];
	struct cpu_rmap *rx_cpu_rmap;
	struct hlist_node index_hlist;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netdev_queue *_tx;
	unsigned int num_tx_queues;
	unsigned int real_num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct xps_dev_maps *xps_maps[2];
	struct mini_Qdisc *miniq_egress;
	struct nf_hook_entries *nf_hooks_egress;
	struct hlist_head qdisc_hash[16];
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	int *pcpu_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	enum {
		NETREG_UNINITIALIZED = 0,
		NETREG_REGISTERED = 1,
		NETREG_UNREGISTERING = 2,
		NETREG_UNREGISTERED = 3,
		NETREG_RELEASED = 4,
		NETREG_DUMMY = 5,
	} reg_state: 8;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED = 0,
		RTNL_LINK_INITIALIZING = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device *);
	struct netpoll_info *npinfo;
	possible_net_t nd_net;
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	struct garp_port *garp_port;
	struct mrp_port *mrp_port;
	struct dm_hw_stat_delta *dm_private;
	struct device dev;
	const struct attribute_group *sysfs_groups[4];
	const struct attribute_group *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	unsigned int gso_max_size;
	unsigned int tso_max_size;
	u16 gso_max_segs;
	u16 tso_max_segs;
	const struct dcbnl_rtnl_ops *dcbnl_ops;
	s16 num_tc;
	struct netdev_tc_txq tc_to_txq[16];
	u8 prio_tc_map[16];
	unsigned int fcoe_ddp_xid;
	struct netprio_map *priomap;
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct macsec_ops *macsec_ops;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct hh_cache {
	unsigned int hh_len;
	seqlock_t hh_lock;
	long unsigned int hh_data[16];
};

struct neigh_table;

struct neigh_parms;

struct neigh_ops;

struct neighbour {
	struct neighbour *next;
	struct neigh_table *tbl;
	struct neigh_parms *parms;
	long unsigned int confirmed;
	long unsigned int updated;
	rwlock_t lock;
	refcount_t refcnt;
	unsigned int arp_queue_len_bytes;
	struct sk_buff_head arp_queue;
	struct timer_list timer;
	long unsigned int used;
	atomic_t probes;
	u8 nud_state;
	u8 type;
	u8 dead;
	u8 protocol;
	u32 flags;
	seqlock_t ha_lock;
	int: 32;
	unsigned char ha[32];
	struct hh_cache hh;
	int (*output)(struct neighbour *, struct sk_buff *);
	const struct neigh_ops *ops;
	struct list_head gc_list;
	struct list_head managed_list;
	struct callback_head rcu;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u8 primary_key[0];
};

struct ipv6_stable_secret {
	bool initialized;
	struct in6_addr secret;
};

struct ipv6_devconf {
	__s32 forwarding;
	__s32 hop_limit;
	__s32 mtu6;
	__s32 accept_ra;
	__s32 accept_redirects;
	__s32 autoconf;
	__s32 dad_transmits;
	__s32 rtr_solicits;
	__s32 rtr_solicit_interval;
	__s32 rtr_solicit_max_interval;
	__s32 rtr_solicit_delay;
	__s32 force_mld_version;
	__s32 mldv1_unsolicited_report_interval;
	__s32 mldv2_unsolicited_report_interval;
	__s32 use_tempaddr;
	__s32 temp_valid_lft;
	__s32 temp_prefered_lft;
	__s32 regen_max_retry;
	__s32 max_desync_factor;
	__s32 max_addresses;
	__s32 accept_ra_defrtr;
	__u32 ra_defrtr_metric;
	__s32 accept_ra_min_hop_limit;
	__s32 accept_ra_pinfo;
	__s32 ignore_routes_with_linkdown;
	__s32 accept_ra_rtr_pref;
	__s32 rtr_probe_interval;
	__s32 accept_ra_rt_info_min_plen;
	__s32 accept_ra_rt_info_max_plen;
	__s32 proxy_ndp;
	__s32 accept_source_route;
	__s32 accept_ra_from_local;
	atomic_t mc_forwarding;
	__s32 disable_ipv6;
	__s32 drop_unicast_in_l2_multicast;
	__s32 accept_dad;
	__s32 force_tllao;
	__s32 ndisc_notify;
	__s32 suppress_frag_ndisc;
	__s32 accept_ra_mtu;
	__s32 drop_unsolicited_na;
	__s32 accept_untracked_na;
	struct ipv6_stable_secret stable_secret;
	__s32 use_oif_addrs_only;
	__s32 keep_addr_on_down;
	__s32 seg6_enabled;
	__s32 seg6_require_hmac;
	__u32 enhanced_dad;
	__u32 addr_gen_mode;
	__s32 disable_policy;
	__s32 ndisc_tclass;
	__s32 rpl_seg_enabled;
	__u32 ioam6_id;
	__u32 ioam6_id_wide;
	__u8 ioam6_enabled;
	__u8 ndisc_evict_nocarrier;
	struct ctl_table_header *sysctl_header;
};

typedef struct {
	union {
		void *kernel;
		void *user;
	};
	bool is_kernel: 1;
} sockptr_t;

typedef enum {
	SS_FREE = 0,
	SS_UNCONNECTED = 1,
	SS_CONNECTING = 2,
	SS_CONNECTED = 3,
	SS_DISCONNECTING = 4,
} socket_state;

struct socket_wq {
	wait_queue_head_t wait;
	struct fasync_struct *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 64;
};

struct proto_ops;

struct socket {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file *file;
	struct sock *sk;
	const struct proto_ops *ops;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq wq;
};

typedef struct {
	size_t written;
	size_t count;
	union {
		char *buf;
		void *data;
	} arg;
	int error;
} read_descriptor_t;

typedef int (*sk_read_actor_t)(read_descriptor_t *, struct sk_buff *, unsigned int, size_t);

typedef int (*skb_read_actor_t)(struct sock *, struct sk_buff *);

struct proto_ops {
	int family;
	struct module *owner;
	int (*release)(struct socket *);
	int (*bind)(struct socket *, struct sockaddr *, int);
	int (*connect)(struct socket *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket *, struct socket *);
	int (*accept)(struct socket *, struct socket *, int, bool);
	int (*getname)(struct socket *, struct sockaddr *, int);
	__poll_t (*poll)(struct file *, struct socket *, struct poll_table_struct *);
	int (*ioctl)(struct socket *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct socket *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket *, void *, bool, bool);
	int (*listen)(struct socket *, int);
	int (*shutdown)(struct socket *, int);
	int (*setsockopt)(struct socket *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file *, struct socket *);
	int (*sendmsg)(struct socket *, struct msghdr *, size_t);
	int (*recvmsg)(struct socket *, struct msghdr *, size_t, int);
	int (*mmap)(struct file *, struct socket *, struct vm_area_struct *);
	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
	ssize_t (*splice_read)(struct socket *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*set_peek_off)(struct sock *, int);
	int (*peek_len)(struct socket *);
	int (*read_sock)(struct sock *, read_descriptor_t *, sk_read_actor_t);
	int (*read_skb)(struct sock *, skb_read_actor_t);
	int (*sendpage_locked)(struct sock *, struct page *, int, size_t, int);
	int (*sendmsg_locked)(struct sock *, struct msghdr *, size_t);
	int (*set_rcvlowat)(struct sock *, int);
};

struct skb_shared_hwtstamps {
	union {
		ktime_t hwtstamp;
		void *netdev_data;
	};
};

enum rpc_display_format_t {
	RPC_DISPLAY_ADDR = 0,
	RPC_DISPLAY_PORT = 1,
	RPC_DISPLAY_PROTO = 2,
	RPC_DISPLAY_HEX_ADDR = 3,
	RPC_DISPLAY_HEX_PORT = 4,
	RPC_DISPLAY_NETID = 5,
	RPC_DISPLAY_MAX = 6,
};

struct dql {
	unsigned int num_queued;
	unsigned int adj_limit;
	unsigned int last_obj_cnt;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	unsigned int limit;
	unsigned int num_completed;
	unsigned int prev_ovlimit;
	unsigned int prev_num_queued;
	unsigned int prev_last_obj_cnt;
	unsigned int lowest_slack;
	long unsigned int slack_start_time;
	unsigned int max_limit;
	unsigned int min_limit;
	unsigned int slack_hold_time;
	long: 32;
	long: 64;
	long: 64;
};

struct ieee_ets {
	__u8 willing;
	__u8 ets_cap;
	__u8 cbs;
	__u8 tc_tx_bw[8];
	__u8 tc_rx_bw[8];
	__u8 tc_tsa[8];
	__u8 prio_tc[8];
	__u8 tc_reco_bw[8];
	__u8 tc_reco_tsa[8];
	__u8 reco_prio_tc[8];
};

struct ieee_maxrate {
	__u64 tc_maxrate[8];
};

struct ieee_qcn {
	__u8 rpg_enable[8];
	__u32 rppp_max_rps[8];
	__u32 rpg_time_reset[8];
	__u32 rpg_byte_reset[8];
	__u32 rpg_threshold[8];
	__u32 rpg_max_rate[8];
	__u32 rpg_ai_rate[8];
	__u32 rpg_hai_rate[8];
	__u32 rpg_gd[8];
	__u32 rpg_min_dec_fac[8];
	__u32 rpg_min_rate[8];
	__u32 cndd_state_machine[8];
};

struct ieee_qcn_stats {
	__u64 rppp_rp_centiseconds[8];
	__u32 rppp_created_rps[8];
};

struct ieee_pfc {
	__u8 pfc_cap;
	__u8 pfc_en;
	__u8 mbc;
	__u16 delay;
	__u64 requests[8];
	__u64 indications[8];
};

struct dcbnl_buffer {
	__u8 prio2buffer[8];
	__u32 buffer_size[8];
	__u32 total_size;
};

struct cee_pg {
	__u8 willing;
	__u8 error;
	__u8 pg_en;
	__u8 tcs_supported;
	__u8 pg_bw[8];
	__u8 prio_pg[8];
};

struct cee_pfc {
	__u8 willing;
	__u8 error;
	__u8 pfc_en;
	__u8 tcs_supported;
};

struct dcb_app {
	__u8 selector;
	__u8 priority;
	__u16 protocol;
};

struct dcb_peer_app_info {
	__u8 willing;
	__u8 error;
};

struct dcbnl_rtnl_ops {
	int (*ieee_getets)(struct net_device *, struct ieee_ets *);
	int (*ieee_setets)(struct net_device *, struct ieee_ets *);
	int (*ieee_getmaxrate)(struct net_device *, struct ieee_maxrate *);
	int (*ieee_setmaxrate)(struct net_device *, struct ieee_maxrate *);
	int (*ieee_getqcn)(struct net_device *, struct ieee_qcn *);
	int (*ieee_setqcn)(struct net_device *, struct ieee_qcn *);
	int (*ieee_getqcnstats)(struct net_device *, struct ieee_qcn_stats *);
	int (*ieee_getpfc)(struct net_device *, struct ieee_pfc *);
	int (*ieee_setpfc)(struct net_device *, struct ieee_pfc *);
	int (*ieee_getapp)(struct net_device *, struct dcb_app *);
	int (*ieee_setapp)(struct net_device *, struct dcb_app *);
	int (*ieee_delapp)(struct net_device *, struct dcb_app *);
	int (*ieee_peer_getets)(struct net_device *, struct ieee_ets *);
	int (*ieee_peer_getpfc)(struct net_device *, struct ieee_pfc *);
	u8 (*getstate)(struct net_device *);
	u8 (*setstate)(struct net_device *, u8);
	void (*getpermhwaddr)(struct net_device *, u8 *);
	void (*setpgtccfgtx)(struct net_device *, int, u8, u8, u8, u8);
	void (*setpgbwgcfgtx)(struct net_device *, int, u8);
	void (*setpgtccfgrx)(struct net_device *, int, u8, u8, u8, u8);
	void (*setpgbwgcfgrx)(struct net_device *, int, u8);
	void (*getpgtccfgtx)(struct net_device *, int, u8 *, u8 *, u8 *, u8 *);
	void (*getpgbwgcfgtx)(struct net_device *, int, u8 *);
	void (*getpgtccfgrx)(struct net_device *, int, u8 *, u8 *, u8 *, u8 *);
	void (*getpgbwgcfgrx)(struct net_device *, int, u8 *);
	void (*setpfccfg)(struct net_device *, int, u8);
	void (*getpfccfg)(struct net_device *, int, u8 *);
	u8 (*setall)(struct net_device *);
	u8 (*getcap)(struct net_device *, int, u8 *);
	int (*getnumtcs)(struct net_device *, int, u8 *);
	int (*setnumtcs)(struct net_device *, int, u8);
	u8 (*getpfcstate)(struct net_device *);
	void (*setpfcstate)(struct net_device *, u8);
	void (*getbcncfg)(struct net_device *, int, u32 *);
	void (*setbcncfg)(struct net_device *, int, u32);
	void (*getbcnrp)(struct net_device *, int, u8 *);
	void (*setbcnrp)(struct net_device *, int, u8);
	int (*setapp)(struct net_device *, u8, u16, u8);
	int (*getapp)(struct net_device *, u8, u16);
	u8 (*getfeatcfg)(struct net_device *, int, u8 *);
	u8 (*setfeatcfg)(struct net_device *, int, u8);
	u8 (*getdcbx)(struct net_device *);
	u8 (*setdcbx)(struct net_device *, u8);
	int (*peer_getappinfo)(struct net_device *, struct dcb_peer_app_info *, u16 *);
	int (*peer_getapptable)(struct net_device *, struct dcb_app *);
	int (*cee_peer_getpg)(struct net_device *, struct cee_pg *);
	int (*cee_peer_getpfc)(struct net_device *, struct cee_pfc *);
	int (*dcbnl_getbuffer)(struct net_device *, struct dcbnl_buffer *);
	int (*dcbnl_setbuffer)(struct net_device *, struct dcbnl_buffer *);
};

struct netprio_map {
	struct callback_head rcu;
	u32 priomap_len;
	u32 priomap[0];
};

struct xdp_mem_info {
	u32 type;
	u32 id;
};

struct xdp_rxq_info {
	struct net_device *dev;
	u32 queue_index;
	u32 reg_state;
	struct xdp_mem_info mem;
	unsigned int napi_id;
	u32 frag_size;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct xdp_txq_info {
	struct net_device *dev;
};

struct xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
	struct xdp_rxq_info *rxq;
	struct xdp_txq_info *txq;
	u32 frame_sz;
	u32 flags;
};

struct xdp_frame {
	void *data;
	u16 len;
	u16 headroom;
	u32 metasize: 8;
	u32 frame_sz: 24;
	struct xdp_mem_info mem;
	struct net_device *dev_rx;
	u32 flags;
};

struct nlmsghdr {
	__u32 nlmsg_len;
	__u16 nlmsg_type;
	__u16 nlmsg_flags;
	__u32 nlmsg_seq;
	__u32 nlmsg_pid;
};

struct nlattr {
	__u16 nla_len;
	__u16 nla_type;
};

struct nla_policy;

struct netlink_ext_ack {
	const char *_msg;
	const struct nlattr *bad_attr;
	const struct nla_policy *policy;
	u8 cookie[20];
	u8 cookie_len;
};

struct netlink_range_validation;

struct netlink_range_validation_signed;

struct nla_policy {
	u8 type;
	u8 validation_type;
	u16 len;
	union {
		const u32 bitfield32_valid;
		const u32 mask;
		const char *reject_message;
		const struct nla_policy *nested_policy;
		struct netlink_range_validation *range;
		struct netlink_range_validation_signed *range_signed;
		struct {
			s16 min;
			s16 max;
		};
		int (*validate)(const struct nlattr *, struct netlink_ext_ack *);
		u16 strict_start_type;
	};
};

struct netlink_callback {
	struct sk_buff *skb;
	const struct nlmsghdr *nlh;
	int (*dump)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	void *data;
	struct module *module;
	struct netlink_ext_ack *extack;
	u16 family;
	u16 answer_flags;
	u32 min_dump_alloc;
	unsigned int prev_seq;
	unsigned int seq;
	bool strict_check;
	union {
		u8 ctx[48];
		long int args[6];
	};
};

struct ndmsg {
	__u8 ndm_family;
	__u8 ndm_pad1;
	__u16 ndm_pad2;
	__s32 ndm_ifindex;
	__u16 ndm_state;
	__u8 ndm_flags;
	__u8 ndm_type;
};

struct rtnl_link_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
	__u64 collisions;
	__u64 rx_length_errors;
	__u64 rx_over_errors;
	__u64 rx_crc_errors;
	__u64 rx_frame_errors;
	__u64 rx_fifo_errors;
	__u64 rx_missed_errors;
	__u64 tx_aborted_errors;
	__u64 tx_carrier_errors;
	__u64 tx_fifo_errors;
	__u64 tx_heartbeat_errors;
	__u64 tx_window_errors;
	__u64 rx_compressed;
	__u64 tx_compressed;
	__u64 rx_nohandler;
	__u64 rx_otherhost_dropped;
};

struct rtnl_hw_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
};

struct ifla_vf_guid {
	__u32 vf;
	__u64 guid;
};

struct ifla_vf_stats {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 broadcast;
	__u64 multicast;
	__u64 rx_dropped;
	__u64 tx_dropped;
};

struct ifla_vf_info {
	__u32 vf;
	__u8 mac[32];
	__u32 vlan;
	__u32 qos;
	__u32 spoofchk;
	__u32 linkstate;
	__u32 min_tx_rate;
	__u32 max_tx_rate;
	__u32 rss_query_en;
	__u32 trusted;
	__be16 vlan_proto;
};

enum netdev_tx {
	__NETDEV_TX_MIN = 2147483648,
	NETDEV_TX_OK = 0,
	NETDEV_TX_BUSY = 16,
};

typedef enum netdev_tx netdev_tx_t;

struct net_device_core_stats {
	long unsigned int rx_dropped;
	long unsigned int tx_dropped;
	long unsigned int rx_nohandler;
	long unsigned int rx_otherhost_dropped;
};

struct header_ops {
	int (*create)(struct sk_buff *, struct net_device *, short unsigned int, const void *, const void *, unsigned int);
	int (*parse)(const struct sk_buff *, unsigned char *);
	int (*cache)(const struct neighbour *, struct hh_cache *, __be16);
	void (*cache_update)(struct hh_cache *, const struct net_device *, const unsigned char *);
	bool (*validate)(const char *, unsigned int);
	__be16 (*parse_protocol)(const struct sk_buff *);
};

enum {
	NAPI_STATE_SCHED = 0,
	NAPI_STATE_MISSED = 1,
	NAPI_STATE_DISABLE = 2,
	NAPI_STATE_NPSVC = 3,
	NAPI_STATE_LISTED = 4,
	NAPI_STATE_NO_BUSY_POLL = 5,
	NAPI_STATE_IN_BUSY_POLL = 6,
	NAPI_STATE_PREFER_BUSY_POLL = 7,
	NAPI_STATE_THREADED = 8,
	NAPI_STATE_SCHED_THREADED = 9,
};

struct xsk_buff_pool;

struct netdev_queue {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct Qdisc *qdisc;
	struct Qdisc *qdisc_sleeping;
	struct kobject kobj;
	int numa_node;
	long unsigned int tx_maxrate;
	atomic_long_t trans_timeout;
	struct net_device *sb_dev;
	struct xsk_buff_pool *pool;
	spinlock_t _xmit_lock;
	int xmit_lock_owner;
	long unsigned int trans_start;
	long unsigned int state;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct dql dql;
};

struct rps_map {
	unsigned int len;
	struct callback_head rcu;
	u16 cpus[0];
};

struct rps_dev_flow {
	u16 cpu;
	u16 filter;
	unsigned int last_qtail;
};

struct rps_dev_flow_table {
	unsigned int mask;
	struct callback_head rcu;
	struct rps_dev_flow flows[0];
};

struct netdev_rx_queue {
	struct xdp_rxq_info xdp_rxq;
	struct rps_map *rps_map;
	struct rps_dev_flow_table *rps_flow_table;
	struct kobject kobj;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct xsk_buff_pool *pool;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum xps_map_type {
	XPS_CPUS = 0,
	XPS_RXQS = 1,
	XPS_MAPS_MAX = 2,
};

struct xps_map {
	unsigned int len;
	unsigned int alloc_len;
	struct callback_head rcu;
	u16 queues[0];
};

struct xps_dev_maps {
	struct callback_head rcu;
	unsigned int nr_ids;
	s16 num_tc;
	struct xps_map *attr_map[0];
};

struct netdev_fcoe_hbainfo {
	char manufacturer[64];
	char serial_number[64];
	char hardware_version[64];
	char driver_version[64];
	char optionrom_version[64];
	char firmware_version[64];
	char model[256];
	char model_description[256];
};

struct netdev_phys_item_id {
	unsigned char id[32];
	unsigned char id_len;
};

enum net_device_path_type {
	DEV_PATH_ETHERNET = 0,
	DEV_PATH_VLAN = 1,
	DEV_PATH_BRIDGE = 2,
	DEV_PATH_PPPOE = 3,
	DEV_PATH_DSA = 4,
	DEV_PATH_MTK_WDMA = 5,
};

struct net_device_path {
	enum net_device_path_type type;
	const struct net_device *dev;
	union {
		struct {
			u16 id;
			__be16 proto;
			u8 h_dest[6];
		} encap;
		struct {
			enum {
				DEV_PATH_BR_VLAN_KEEP = 0,
				DEV_PATH_BR_VLAN_TAG = 1,
				DEV_PATH_BR_VLAN_UNTAG = 2,
				DEV_PATH_BR_VLAN_UNTAG_HW = 3,
			} vlan_mode;
			u16 vlan_id;
			__be16 vlan_proto;
		} bridge;
		struct {
			int port;
			u16 proto;
		} dsa;
		struct {
			u8 wdma_idx;
			u8 queue;
			u16 wcid;
			u8 bss;
		} mtk_wdma;
	};
};

struct net_device_path_ctx {
	const struct net_device *dev;
	u8 daddr[6];
	int num_vlans;
	struct {
		u16 id;
		__be16 proto;
	} vlan[2];
};

enum tc_setup_type {
	TC_SETUP_QDISC_MQPRIO = 0,
	TC_SETUP_CLSU32 = 1,
	TC_SETUP_CLSFLOWER = 2,
	TC_SETUP_CLSMATCHALL = 3,
	TC_SETUP_CLSBPF = 4,
	TC_SETUP_BLOCK = 5,
	TC_SETUP_QDISC_CBS = 6,
	TC_SETUP_QDISC_RED = 7,
	TC_SETUP_QDISC_PRIO = 8,
	TC_SETUP_QDISC_MQ = 9,
	TC_SETUP_QDISC_ETF = 10,
	TC_SETUP_ROOT_QDISC = 11,
	TC_SETUP_QDISC_GRED = 12,
	TC_SETUP_QDISC_TAPRIO = 13,
	TC_SETUP_FT = 14,
	TC_SETUP_QDISC_ETS = 15,
	TC_SETUP_QDISC_TBF = 16,
	TC_SETUP_QDISC_FIFO = 17,
	TC_SETUP_QDISC_HTB = 18,
	TC_SETUP_ACT = 19,
};

enum bpf_netdev_command {
	XDP_SETUP_PROG = 0,
	XDP_SETUP_PROG_HW = 1,
	BPF_OFFLOAD_MAP_ALLOC = 2,
	BPF_OFFLOAD_MAP_FREE = 3,
	XDP_SETUP_XSK_POOL = 4,
};

enum bpf_xdp_mode {
	XDP_MODE_SKB = 0,
	XDP_MODE_DRV = 1,
	XDP_MODE_HW = 2,
	__MAX_XDP_MODE = 3,
};

struct bpf_offloaded_map;

struct netdev_bpf {
	enum bpf_netdev_command command;
	union {
		struct {
			u32 flags;
			struct bpf_prog *prog;
			struct netlink_ext_ack *extack;
		};
		struct {
			struct bpf_offloaded_map *offmap;
		};
		struct {
			struct xsk_buff_pool *pool;
			u16 queue_id;
		} xsk;
	};
};

struct xfrmdev_ops {
	int (*xdo_dev_state_add)(struct xfrm_state *);
	void (*xdo_dev_state_delete)(struct xfrm_state *);
	void (*xdo_dev_state_free)(struct xfrm_state *);
	bool (*xdo_dev_offload_ok)(struct sk_buff *, struct xfrm_state *);
	void (*xdo_dev_state_advance_esn)(struct xfrm_state *);
};

struct dev_ifalias {
	struct callback_head rcuhead;
	char ifalias[0];
};

struct devlink_port;

struct ip_tunnel_parm;

struct net_device_ops {
	int (*ndo_init)(struct net_device *);
	void (*ndo_uninit)(struct net_device *);
	int (*ndo_open)(struct net_device *);
	int (*ndo_stop)(struct net_device *);
	netdev_tx_t (*ndo_start_xmit)(struct sk_buff *, struct net_device *);
	netdev_features_t (*ndo_features_check)(struct sk_buff *, struct net_device *, netdev_features_t);
	u16 (*ndo_select_queue)(struct net_device *, struct sk_buff *, struct net_device *);
	void (*ndo_change_rx_flags)(struct net_device *, int);
	void (*ndo_set_rx_mode)(struct net_device *);
	int (*ndo_set_mac_address)(struct net_device *, void *);
	int (*ndo_validate_addr)(struct net_device *);
	int (*ndo_do_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_eth_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocbond)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocwandev)(struct net_device *, struct if_settings *);
	int (*ndo_siocdevprivate)(struct net_device *, struct ifreq *, void *, int);
	int (*ndo_set_config)(struct net_device *, struct ifmap *);
	int (*ndo_change_mtu)(struct net_device *, int);
	int (*ndo_neigh_setup)(struct net_device *, struct neigh_parms *);
	void (*ndo_tx_timeout)(struct net_device *, unsigned int);
	void (*ndo_get_stats64)(struct net_device *, struct rtnl_link_stats64 *);
	bool (*ndo_has_offload_stats)(const struct net_device *, int);
	int (*ndo_get_offload_stats)(int, const struct net_device *, void *);
	struct net_device_stats * (*ndo_get_stats)(struct net_device *);
	int (*ndo_vlan_rx_add_vid)(struct net_device *, __be16, u16);
	int (*ndo_vlan_rx_kill_vid)(struct net_device *, __be16, u16);
	void (*ndo_poll_controller)(struct net_device *);
	int (*ndo_netpoll_setup)(struct net_device *, struct netpoll_info *);
	void (*ndo_netpoll_cleanup)(struct net_device *);
	int (*ndo_set_vf_mac)(struct net_device *, int, u8 *);
	int (*ndo_set_vf_vlan)(struct net_device *, int, u16, u8, __be16);
	int (*ndo_set_vf_rate)(struct net_device *, int, int, int);
	int (*ndo_set_vf_spoofchk)(struct net_device *, int, bool);
	int (*ndo_set_vf_trust)(struct net_device *, int, bool);
	int (*ndo_get_vf_config)(struct net_device *, int, struct ifla_vf_info *);
	int (*ndo_set_vf_link_state)(struct net_device *, int, int);
	int (*ndo_get_vf_stats)(struct net_device *, int, struct ifla_vf_stats *);
	int (*ndo_set_vf_port)(struct net_device *, int, struct nlattr **);
	int (*ndo_get_vf_port)(struct net_device *, int, struct sk_buff *);
	int (*ndo_get_vf_guid)(struct net_device *, int, struct ifla_vf_guid *, struct ifla_vf_guid *);
	int (*ndo_set_vf_guid)(struct net_device *, int, u64, int);
	int (*ndo_set_vf_rss_query_en)(struct net_device *, int, bool);
	int (*ndo_setup_tc)(struct net_device *, enum tc_setup_type, void *);
	int (*ndo_fcoe_enable)(struct net_device *);
	int (*ndo_fcoe_disable)(struct net_device *);
	int (*ndo_fcoe_ddp_setup)(struct net_device *, u16, struct scatterlist *, unsigned int);
	int (*ndo_fcoe_ddp_done)(struct net_device *, u16);
	int (*ndo_fcoe_ddp_target)(struct net_device *, u16, struct scatterlist *, unsigned int);
	int (*ndo_fcoe_get_hbainfo)(struct net_device *, struct netdev_fcoe_hbainfo *);
	int (*ndo_fcoe_get_wwn)(struct net_device *, u64 *, int);
	int (*ndo_rx_flow_steer)(struct net_device *, const struct sk_buff *, u16, u32);
	int (*ndo_add_slave)(struct net_device *, struct net_device *, struct netlink_ext_ack *);
	int (*ndo_del_slave)(struct net_device *, struct net_device *);
	struct net_device * (*ndo_get_xmit_slave)(struct net_device *, struct sk_buff *, bool);
	struct net_device * (*ndo_sk_get_lower_dev)(struct net_device *, struct sock *);
	netdev_features_t (*ndo_fix_features)(struct net_device *, netdev_features_t);
	int (*ndo_set_features)(struct net_device *, netdev_features_t);
	int (*ndo_neigh_construct)(struct net_device *, struct neighbour *);
	void (*ndo_neigh_destroy)(struct net_device *, struct neighbour *);
	int (*ndo_fdb_add)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16, u16, struct netlink_ext_ack *);
	int (*ndo_fdb_del)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16, struct netlink_ext_ack *);
	int (*ndo_fdb_del_bulk)(struct ndmsg *, struct nlattr **, struct net_device *, u16, struct netlink_ext_ack *);
	int (*ndo_fdb_dump)(struct sk_buff *, struct netlink_callback *, struct net_device *, struct net_device *, int *);
	int (*ndo_fdb_get)(struct sk_buff *, struct nlattr **, struct net_device *, const unsigned char *, u16, u32, u32, struct netlink_ext_ack *);
	int (*ndo_bridge_setlink)(struct net_device *, struct nlmsghdr *, u16, struct netlink_ext_ack *);
	int (*ndo_bridge_getlink)(struct sk_buff *, u32, u32, struct net_device *, u32, int);
	int (*ndo_bridge_dellink)(struct net_device *, struct nlmsghdr *, u16);
	int (*ndo_change_carrier)(struct net_device *, bool);
	int (*ndo_get_phys_port_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_port_parent_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_phys_port_name)(struct net_device *, char *, size_t);
	void * (*ndo_dfwd_add_station)(struct net_device *, struct net_device *);
	void (*ndo_dfwd_del_station)(struct net_device *, void *);
	int (*ndo_set_tx_maxrate)(struct net_device *, int, u32);
	int (*ndo_get_iflink)(const struct net_device *);
	int (*ndo_fill_metadata_dst)(struct net_device *, struct sk_buff *);
	void (*ndo_set_rx_headroom)(struct net_device *, int);
	int (*ndo_bpf)(struct net_device *, struct netdev_bpf *);
	int (*ndo_xdp_xmit)(struct net_device *, int, struct xdp_frame **, u32);
	struct net_device * (*ndo_xdp_get_xmit_slave)(struct net_device *, struct xdp_buff *);
	int (*ndo_xsk_wakeup)(struct net_device *, u32, u32);
	struct devlink_port * (*ndo_get_devlink_port)(struct net_device *);
	int (*ndo_tunnel_ctl)(struct net_device *, struct ip_tunnel_parm *, int);
	struct net_device * (*ndo_get_peer_dev)(struct net_device *);
	int (*ndo_fill_forward_path)(struct net_device_path_ctx *, struct net_device_path *);
	ktime_t (*ndo_get_tstamp)(struct net_device *, const struct skb_shared_hwtstamps *, bool);
};

struct neigh_parms {
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head list;
	int (*neigh_setup)(struct neighbour *);
	struct neigh_table *tbl;
	void *sysctl_table;
	int dead;
	refcount_t refcnt;
	struct callback_head callback_head;
	int reachable_time;
	int data[13];
	long unsigned int data_state[1];
};

struct pcpu_lstats {
	u64_stats_t packets;
	u64_stats_t bytes;
	struct u64_stats_sync syncp;
};

struct pcpu_sw_netstats {
	u64_stats_t rx_packets;
	u64_stats_t rx_bytes;
	u64_stats_t tx_packets;
	u64_stats_t tx_bytes;
	struct u64_stats_sync syncp;
};

struct iw_request_info;

union iwreq_data;

typedef int (*iw_handler)(struct net_device *, struct iw_request_info *, union iwreq_data *, char *);

struct iw_priv_args;

struct iw_statistics;

struct iw_handler_def {
	const iw_handler *standard;
	__u16 num_standard;
	__u16 num_private;
	__u16 num_private_args;
	const iw_handler *private;
	const struct iw_priv_args *private_args;
	struct iw_statistics * (*get_wireless_stats)(struct net_device *);
};

enum ethtool_phys_id_state {
	ETHTOOL_ID_INACTIVE = 0,
	ETHTOOL_ID_ACTIVE = 1,
	ETHTOOL_ID_ON = 2,
	ETHTOOL_ID_OFF = 3,
};

struct ethtool_drvinfo;

struct ethtool_regs;

struct ethtool_wolinfo;

struct ethtool_link_ext_state_info;

struct ethtool_eeprom;

struct ethtool_coalesce;

struct kernel_ethtool_coalesce;

struct ethtool_ringparam;

struct kernel_ethtool_ringparam;

struct ethtool_pause_stats;

struct ethtool_pauseparam;

struct ethtool_test;

struct ethtool_stats;

struct ethtool_rxnfc;

struct ethtool_flash;

struct ethtool_channels;

struct ethtool_dump;

struct ethtool_ts_info;

struct ethtool_modinfo;

struct ethtool_eee;

struct ethtool_tunable;

struct ethtool_link_ksettings;

struct ethtool_fec_stats;

struct ethtool_fecparam;

struct ethtool_module_eeprom;

struct ethtool_eth_phy_stats;

struct ethtool_eth_mac_stats;

struct ethtool_eth_ctrl_stats;

struct ethtool_rmon_stats;

struct ethtool_rmon_hist_range;

struct ethtool_module_power_mode_params;

struct ethtool_ops {
	u32 cap_link_lanes_supported: 1;
	u32 supported_coalesce_params;
	u32 supported_ring_params;
	void (*get_drvinfo)(struct net_device *, struct ethtool_drvinfo *);
	int (*get_regs_len)(struct net_device *);
	void (*get_regs)(struct net_device *, struct ethtool_regs *, void *);
	void (*get_wol)(struct net_device *, struct ethtool_wolinfo *);
	int (*set_wol)(struct net_device *, struct ethtool_wolinfo *);
	u32 (*get_msglevel)(struct net_device *);
	void (*set_msglevel)(struct net_device *, u32);
	int (*nway_reset)(struct net_device *);
	u32 (*get_link)(struct net_device *);
	int (*get_link_ext_state)(struct net_device *, struct ethtool_link_ext_state_info *);
	int (*get_eeprom_len)(struct net_device *);
	int (*get_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*set_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*get_coalesce)(struct net_device *, struct ethtool_coalesce *, struct kernel_ethtool_coalesce *, struct netlink_ext_ack *);
	int (*set_coalesce)(struct net_device *, struct ethtool_coalesce *, struct kernel_ethtool_coalesce *, struct netlink_ext_ack *);
	void (*get_ringparam)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *);
	int (*set_ringparam)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *);
	void (*get_pause_stats)(struct net_device *, struct ethtool_pause_stats *);
	void (*get_pauseparam)(struct net_device *, struct ethtool_pauseparam *);
	int (*set_pauseparam)(struct net_device *, struct ethtool_pauseparam *);
	void (*self_test)(struct net_device *, struct ethtool_test *, u64 *);
	void (*get_strings)(struct net_device *, u32, u8 *);
	int (*set_phys_id)(struct net_device *, enum ethtool_phys_id_state);
	void (*get_ethtool_stats)(struct net_device *, struct ethtool_stats *, u64 *);
	int (*begin)(struct net_device *);
	void (*complete)(struct net_device *);
	u32 (*get_priv_flags)(struct net_device *);
	int (*set_priv_flags)(struct net_device *, u32);
	int (*get_sset_count)(struct net_device *, int);
	int (*get_rxnfc)(struct net_device *, struct ethtool_rxnfc *, u32 *);
	int (*set_rxnfc)(struct net_device *, struct ethtool_rxnfc *);
	int (*flash_device)(struct net_device *, struct ethtool_flash *);
	int (*reset)(struct net_device *, u32 *);
	u32 (*get_rxfh_key_size)(struct net_device *);
	u32 (*get_rxfh_indir_size)(struct net_device *);
	int (*get_rxfh)(struct net_device *, u32 *, u8 *, u8 *);
	int (*set_rxfh)(struct net_device *, const u32 *, const u8 *, const u8);
	int (*get_rxfh_context)(struct net_device *, u32 *, u8 *, u8 *, u32);
	int (*set_rxfh_context)(struct net_device *, const u32 *, const u8 *, const u8, u32 *, bool);
	void (*get_channels)(struct net_device *, struct ethtool_channels *);
	int (*set_channels)(struct net_device *, struct ethtool_channels *);
	int (*get_dump_flag)(struct net_device *, struct ethtool_dump *);
	int (*get_dump_data)(struct net_device *, struct ethtool_dump *, void *);
	int (*set_dump)(struct net_device *, struct ethtool_dump *);
	int (*get_ts_info)(struct net_device *, struct ethtool_ts_info *);
	int (*get_module_info)(struct net_device *, struct ethtool_modinfo *);
	int (*get_module_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*get_eee)(struct net_device *, struct ethtool_eee *);
	int (*set_eee)(struct net_device *, struct ethtool_eee *);
	int (*get_tunable)(struct net_device *, const struct ethtool_tunable *, void *);
	int (*set_tunable)(struct net_device *, const struct ethtool_tunable *, const void *);
	int (*get_per_queue_coalesce)(struct net_device *, u32, struct ethtool_coalesce *);
	int (*set_per_queue_coalesce)(struct net_device *, u32, struct ethtool_coalesce *);
	int (*get_link_ksettings)(struct net_device *, struct ethtool_link_ksettings *);
	int (*set_link_ksettings)(struct net_device *, const struct ethtool_link_ksettings *);
	void (*get_fec_stats)(struct net_device *, struct ethtool_fec_stats *);
	int (*get_fecparam)(struct net_device *, struct ethtool_fecparam *);
	int (*set_fecparam)(struct net_device *, struct ethtool_fecparam *);
	void (*get_ethtool_phy_stats)(struct net_device *, struct ethtool_stats *, u64 *);
	int (*get_phy_tunable)(struct net_device *, const struct ethtool_tunable *, void *);
	int (*set_phy_tunable)(struct net_device *, const struct ethtool_tunable *, const void *);
	int (*get_module_eeprom_by_page)(struct net_device *, const struct ethtool_module_eeprom *, struct netlink_ext_ack *);
	void (*get_eth_phy_stats)(struct net_device *, struct ethtool_eth_phy_stats *);
	void (*get_eth_mac_stats)(struct net_device *, struct ethtool_eth_mac_stats *);
	void (*get_eth_ctrl_stats)(struct net_device *, struct ethtool_eth_ctrl_stats *);
	void (*get_rmon_stats)(struct net_device *, struct ethtool_rmon_stats *, const struct ethtool_rmon_hist_range **);
	int (*get_module_power_mode)(struct net_device *, struct ethtool_module_power_mode_params *, struct netlink_ext_ack *);
	int (*set_module_power_mode)(struct net_device *, const struct ethtool_module_power_mode_params *, struct netlink_ext_ack *);
};

struct l3mdev_ops {
	u32 (*l3mdev_fib_table)(const struct net_device *);
	struct sk_buff * (*l3mdev_l3_rcv)(struct net_device *, struct sk_buff *, u16);
	struct sk_buff * (*l3mdev_l3_out)(struct net_device *, struct sock *, struct sk_buff *, u16);
	struct dst_entry * (*l3mdev_link_scope_lookup)(const struct net_device *, struct flowi6 *);
};

struct nd_opt_hdr;

struct ndisc_options;

struct prefix_info;

struct ndisc_ops {
	int (*is_useropt)(u8);
	int (*parse_options)(const struct net_device *, struct nd_opt_hdr *, struct ndisc_options *);
	void (*update)(const struct net_device *, struct neighbour *, u32, u8, const struct ndisc_options *);
	int (*opt_addr_space)(const struct net_device *, u8, struct neighbour *, u8 *, u8 **);
	void (*fill_addr_option)(const struct net_device *, struct sk_buff *, u8, const u8 *);
	void (*prefix_rcv_add_addr)(struct net *, struct net_device *, const struct prefix_info *, struct inet6_dev *, struct in6_addr *, int, u32, bool, bool, __u32, u32, bool);
};

enum tls_offload_ctx_dir {
	TLS_OFFLOAD_CTX_DIR_RX = 0,
	TLS_OFFLOAD_CTX_DIR_TX = 1,
};

struct tls_crypto_info;

struct tls_context;

struct tlsdev_ops {
	int (*tls_dev_add)(struct net_device *, struct sock *, enum tls_offload_ctx_dir, struct tls_crypto_info *, u32);
	void (*tls_dev_del)(struct net_device *, struct tls_context *, enum tls_offload_ctx_dir);
	int (*tls_dev_resync)(struct net_device *, struct sock *, u32, u8 *, enum tls_offload_ctx_dir);
};

struct ipv6_devstat {
	struct proc_dir_entry *proc_dir_entry;
	struct ipstats_mib *ipv6;
	struct icmpv6_mib_device *icmpv6dev;
	struct icmpv6msg_mib_device *icmpv6msgdev;
};

struct ifmcaddr6;

struct ifacaddr6;

struct inet6_dev {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head addr_list;
	struct ifmcaddr6 *mc_list;
	struct ifmcaddr6 *mc_tomb;
	unsigned char mc_qrv;
	unsigned char mc_gq_running;
	unsigned char mc_ifc_count;
	unsigned char mc_dad_count;
	long unsigned int mc_v1_seen;
	long unsigned int mc_qi;
	long unsigned int mc_qri;
	long unsigned int mc_maxdelay;
	struct delayed_work mc_gq_work;
	struct delayed_work mc_ifc_work;
	struct delayed_work mc_dad_work;
	struct delayed_work mc_query_work;
	struct delayed_work mc_report_work;
	struct sk_buff_head mc_query_queue;
	struct sk_buff_head mc_report_queue;
	spinlock_t mc_query_lock;
	spinlock_t mc_report_lock;
	struct mutex mc_lock;
	struct ifacaddr6 *ac_list;
	rwlock_t lock;
	refcount_t refcnt;
	__u32 if_flags;
	int dead;
	u32 desync_factor;
	struct list_head tempaddr_list;
	struct in6_addr token;
	struct neigh_parms *nd_parms;
	struct ipv6_devconf cnf;
	struct ipv6_devstat stats;
	struct timer_list rs_timer;
	__s32 rs_interval;
	__u8 rs_probes;
	long unsigned int tstamp;
	struct callback_head rcu;
	unsigned int ra_mtu;
};

struct rtnl_link_ops {
	struct list_head list;
	const char *kind;
	size_t priv_size;
	struct net_device * (*alloc)(struct nlattr **, const char *, unsigned char, unsigned int, unsigned int);
	void (*setup)(struct net_device *);
	bool netns_refund;
	unsigned int maxtype;
	const struct nla_policy *policy;
	int (*validate)(struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*newlink)(struct net *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*changelink)(struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	void (*dellink)(struct net_device *, struct list_head *);
	size_t (*get_size)(const struct net_device *);
	int (*fill_info)(struct sk_buff *, const struct net_device *);
	size_t (*get_xstats_size)(const struct net_device *);
	int (*fill_xstats)(struct sk_buff *, const struct net_device *);
	unsigned int (*get_num_tx_queues)();
	unsigned int (*get_num_rx_queues)();
	unsigned int slave_maxtype;
	const struct nla_policy *slave_policy;
	int (*slave_changelink)(struct net_device *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	size_t (*get_slave_size)(const struct net_device *, const struct net_device *);
	int (*fill_slave_info)(struct sk_buff *, const struct net_device *, const struct net_device *);
	struct net * (*get_link_net)(const struct net_device *);
	size_t (*get_linkxstats_size)(const struct net_device *, int);
	int (*fill_linkxstats)(struct sk_buff *, const struct net_device *, int *, int);
};

struct udp_tunnel_nic_table_info {
	unsigned int n_entries;
	unsigned int tunnel_types;
};

struct udp_tunnel_info;

struct udp_tunnel_nic_shared;

struct udp_tunnel_nic_info {
	int (*set_port)(struct net_device *, unsigned int, unsigned int, struct udp_tunnel_info *);
	int (*unset_port)(struct net_device *, unsigned int, unsigned int, struct udp_tunnel_info *);
	int (*sync_table)(struct net_device *, unsigned int);
	struct udp_tunnel_nic_shared *shared;
	unsigned int flags;
	struct udp_tunnel_nic_table_info tables[4];
};

enum {
	NETIF_MSG_DRV_BIT = 0,
	NETIF_MSG_PROBE_BIT = 1,
	NETIF_MSG_LINK_BIT = 2,
	NETIF_MSG_TIMER_BIT = 3,
	NETIF_MSG_IFDOWN_BIT = 4,
	NETIF_MSG_IFUP_BIT = 5,
	NETIF_MSG_RX_ERR_BIT = 6,
	NETIF_MSG_TX_ERR_BIT = 7,
	NETIF_MSG_TX_QUEUED_BIT = 8,
	NETIF_MSG_INTR_BIT = 9,
	NETIF_MSG_TX_DONE_BIT = 10,
	NETIF_MSG_RX_STATUS_BIT = 11,
	NETIF_MSG_PKTDATA_BIT = 12,
	NETIF_MSG_HW_BIT = 13,
	NETIF_MSG_WOL_BIT = 14,
	NETIF_MSG_CLASS_COUNT = 15,
};

enum {
	RTAX_UNSPEC = 0,
	RTAX_LOCK = 1,
	RTAX_MTU = 2,
	RTAX_WINDOW = 3,
	RTAX_RTT = 4,
	RTAX_RTTVAR = 5,
	RTAX_SSTHRESH = 6,
	RTAX_CWND = 7,
	RTAX_ADVMSS = 8,
	RTAX_REORDERING = 9,
	RTAX_HOPLIMIT = 10,
	RTAX_INITCWND = 11,
	RTAX_FEATURES = 12,
	RTAX_RTO_MIN = 13,
	RTAX_INITRWND = 14,
	RTAX_QUICKACK = 15,
	RTAX_CC_ALGO = 16,
	RTAX_FASTOPEN_NO_COOKIE = 17,
	__RTAX_MAX = 18,
};

struct netlink_range_validation {
	u64 min;
	u64 max;
};

struct netlink_range_validation_signed {
	s64 min;
	s64 max;
};

enum {
	NEIGH_VAR_MCAST_PROBES = 0,
	NEIGH_VAR_UCAST_PROBES = 1,
	NEIGH_VAR_APP_PROBES = 2,
	NEIGH_VAR_MCAST_REPROBES = 3,
	NEIGH_VAR_RETRANS_TIME = 4,
	NEIGH_VAR_BASE_REACHABLE_TIME = 5,
	NEIGH_VAR_DELAY_PROBE_TIME = 6,
	NEIGH_VAR_GC_STALETIME = 7,
	NEIGH_VAR_QUEUE_LEN_BYTES = 8,
	NEIGH_VAR_PROXY_QLEN = 9,
	NEIGH_VAR_ANYCAST_DELAY = 10,
	NEIGH_VAR_PROXY_DELAY = 11,
	NEIGH_VAR_LOCKTIME = 12,
	NEIGH_VAR_QUEUE_LEN = 13,
	NEIGH_VAR_RETRANS_TIME_MS = 14,
	NEIGH_VAR_BASE_REACHABLE_TIME_MS = 15,
	NEIGH_VAR_GC_INTERVAL = 16,
	NEIGH_VAR_GC_THRESH1 = 17,
	NEIGH_VAR_GC_THRESH2 = 18,
	NEIGH_VAR_GC_THRESH3 = 19,
	NEIGH_VAR_MAX = 20,
};

struct pneigh_entry;

struct neigh_statistics;

struct neigh_hash_table;

struct neigh_table {
	int family;
	unsigned int entry_size;
	unsigned int key_len;
	__be16 protocol;
	__u32 (*hash)(const void *, const struct net_device *, __u32 *);
	bool (*key_eq)(const struct neighbour *, const void *);
	int (*constructor)(struct neighbour *);
	int (*pconstructor)(struct pneigh_entry *);
	void (*pdestructor)(struct pneigh_entry *);
	void (*proxy_redo)(struct sk_buff *);
	int (*is_multicast)(const void *);
	bool (*allow_add)(const struct net_device *, struct netlink_ext_ack *);
	char *id;
	struct neigh_parms parms;
	struct list_head parms_list;
	int gc_interval;
	int gc_thresh1;
	int gc_thresh2;
	int gc_thresh3;
	long unsigned int last_flush;
	struct delayed_work gc_work;
	struct delayed_work managed_work;
	struct timer_list proxy_timer;
	struct sk_buff_head proxy_queue;
	atomic_t entries;
	atomic_t gc_entries;
	struct list_head gc_list;
	struct list_head managed_list;
	rwlock_t lock;
	long unsigned int last_rand;
	struct neigh_statistics *stats;
	struct neigh_hash_table *nht;
	struct pneigh_entry **phash_buckets;
};

struct neigh_statistics {
	long unsigned int allocs;
	long unsigned int destroys;
	long unsigned int hash_grows;
	long unsigned int res_failed;
	long unsigned int lookups;
	long unsigned int hits;
	long unsigned int rcv_probes_mcast;
	long unsigned int rcv_probes_ucast;
	long unsigned int periodic_gc_runs;
	long unsigned int forced_gc_runs;
	long unsigned int unres_discards;
	long unsigned int table_fulls;
};

struct neigh_ops {
	int family;
	void (*solicit)(struct neighbour *, struct sk_buff *);
	void (*error_report)(struct neighbour *, struct sk_buff *);
	int (*output)(struct neighbour *, struct sk_buff *);
	int (*connected_output)(struct neighbour *, struct sk_buff *);
};

struct pneigh_entry {
	struct pneigh_entry *next;
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u32 flags;
	u8 protocol;
	u8 key[0];
};

struct neigh_hash_table {
	struct neighbour **hash_buckets;
	unsigned int hash_shift;
	__u32 hash_rnd[4];
	struct callback_head rcu;
};

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_FIN_WAIT1 = 4,
	TCP_FIN_WAIT2 = 5,
	TCP_TIME_WAIT = 6,
	TCP_CLOSE = 7,
	TCP_CLOSE_WAIT = 8,
	TCP_LAST_ACK = 9,
	TCP_LISTEN = 10,
	TCP_CLOSING = 11,
	TCP_NEW_SYN_RECV = 12,
	TCP_MAX_STATES = 13,
};

struct fib_rule_hdr {
	__u8 family;
	__u8 dst_len;
	__u8 src_len;
	__u8 tos;
	__u8 table;
	__u8 res1;
	__u8 res2;
	__u8 action;
	__u32 flags;
};

struct fib_rule_port_range {
	__u16 start;
	__u16 end;
};

struct fib_kuid_range {
	kuid_t start;
	kuid_t end;
};

struct fib_rule {
	struct list_head list;
	int iifindex;
	int oifindex;
	u32 mark;
	u32 mark_mask;
	u32 flags;
	u32 table;
	u8 action;
	u8 l3mdev;
	u8 proto;
	u8 ip_proto;
	u32 target;
	__be64 tun_id;
	struct fib_rule *ctarget;
	struct net *fr_net;
	refcount_t refcnt;
	u32 pref;
	int suppress_ifgroup;
	int suppress_prefixlen;
	char iifname[16];
	char oifname[16];
	struct fib_kuid_range uid_range;
	struct fib_rule_port_range sport_range;
	struct fib_rule_port_range dport_range;
	struct callback_head rcu;
};

struct fib_lookup_arg {
	void *lookup_ptr;
	const void *lookup_data;
	void *result;
	struct fib_rule *rule;
	u32 table;
	int flags;
};

struct smc_hashinfo;

struct sk_psock;

struct request_sock_ops;

struct timewait_sock_ops;

struct udp_table;

struct raw_hashinfo;

struct proto {
	void (*close)(struct sock *, long int);
	int (*pre_connect)(struct sock *, struct sockaddr *, int);
	int (*connect)(struct sock *, struct sockaddr *, int);
	int (*disconnect)(struct sock *, int);
	struct sock * (*accept)(struct sock *, int, int *, bool);
	int (*ioctl)(struct sock *, int, long unsigned int);
	int (*init)(struct sock *);
	void (*destroy)(struct sock *);
	void (*shutdown)(struct sock *, int);
	int (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct sock *, int, int, char *, int *);
	void (*keepalive)(struct sock *, int);
	int (*compat_ioctl)(struct sock *, unsigned int, long unsigned int);
	int (*sendmsg)(struct sock *, struct msghdr *, size_t);
	int (*recvmsg)(struct sock *, struct msghdr *, size_t, int, int *);
	int (*sendpage)(struct sock *, struct page *, int, size_t, int);
	int (*bind)(struct sock *, struct sockaddr *, int);
	int (*bind_add)(struct sock *, struct sockaddr *, int);
	int (*backlog_rcv)(struct sock *, struct sk_buff *);
	bool (*bpf_bypass_getsockopt)(int, int);
	void (*release_cb)(struct sock *);
	int (*hash)(struct sock *);
	void (*unhash)(struct sock *);
	void (*rehash)(struct sock *);
	int (*get_port)(struct sock *, short unsigned int);
	void (*put_port)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	unsigned int inuse_idx;
	int (*forward_alloc_get)(const struct sock *);
	bool (*stream_memory_free)(const struct sock *, int);
	bool (*sock_is_readable)(struct sock *);
	void (*enter_memory_pressure)(struct sock *);
	void (*leave_memory_pressure)(struct sock *);
	atomic_long_t *memory_allocated;
	int *per_cpu_fw_alloc;
	struct percpu_counter *sockets_allocated;
	long unsigned int *memory_pressure;
	long int *sysctl_mem;
	int *sysctl_wmem;
	int *sysctl_rmem;
	u32 sysctl_wmem_offset;
	u32 sysctl_rmem_offset;
	int max_header;
	bool no_autobind;
	struct kmem_cache *slab;
	unsigned int obj_size;
	slab_flags_t slab_flags;
	unsigned int useroffset;
	unsigned int usersize;
	unsigned int *orphan_count;
	struct request_sock_ops *rsk_prot;
	struct timewait_sock_ops *twsk_prot;
	union {
		struct inet_hashinfo *hashinfo;
		struct udp_table *udp_table;
		struct raw_hashinfo *raw_hash;
		struct smc_hashinfo *smc_hash;
	} h;
	struct module *owner;
	char name[32];
	struct list_head node;
	int (*diag_destroy)(struct sock *, int);
};

struct request_sock;

struct request_sock_ops {
	int family;
	unsigned int obj_size;
	struct kmem_cache *slab;
	char *slab_name;
	int (*rtx_syn_ack)(const struct sock *, struct request_sock *);
	void (*send_ack)(const struct sock *, struct sk_buff *, struct request_sock *);
	void (*send_reset)(const struct sock *, struct sk_buff *);
	void (*destructor)(struct request_sock *);
	void (*syn_ack_timeout)(const struct request_sock *);
};

struct timewait_sock_ops {
	struct kmem_cache *twsk_slab;
	char *twsk_slab_name;
	unsigned int twsk_obj_size;
	int (*twsk_unique)(struct sock *, struct sock *, void *);
	void (*twsk_destructor)(struct sock *);
};

struct saved_syn;

struct request_sock {
	struct sock_common __req_common;
	struct request_sock *dl_next;
	u16 mss;
	u8 num_retrans;
	u8 syncookie: 1;
	u8 num_timeout: 7;
	u32 ts_recent;
	struct timer_list rsk_timer;
	const struct request_sock_ops *rsk_ops;
	struct sock *sk;
	struct saved_syn *saved_syn;
	u32 secid;
	u32 peer_secid;
	u32 timeout;
};

struct saved_syn {
	u32 mac_hdrlen;
	u32 network_hdrlen;
	u32 tcp_hdrlen;
	u8 data[0];
};

enum tsq_enum {
	TSQ_THROTTLED = 0,
	TSQ_QUEUED = 1,
	TCP_TSQ_DEFERRED = 2,
	TCP_WRITE_TIMER_DEFERRED = 3,
	TCP_DELACK_TIMER_DEFERRED = 4,
	TCP_MTU_REDUCED_DEFERRED = 5,
};

struct ip6_sf_list {
	struct ip6_sf_list *sf_next;
	struct in6_addr sf_addr;
	long unsigned int sf_count[2];
	unsigned char sf_gsresp;
	unsigned char sf_oldin;
	unsigned char sf_crcount;
	struct callback_head rcu;
};

struct ifmcaddr6 {
	struct in6_addr mca_addr;
	struct inet6_dev *idev;
	struct ifmcaddr6 *next;
	struct ip6_sf_list *mca_sources;
	struct ip6_sf_list *mca_tomb;
	unsigned int mca_sfmode;
	unsigned char mca_crcount;
	long unsigned int mca_sfcount[2];
	struct delayed_work mca_work;
	unsigned int mca_flags;
	int mca_users;
	refcount_t mca_refcnt;
	long unsigned int mca_cstamp;
	long unsigned int mca_tstamp;
	struct callback_head rcu;
};

struct ifacaddr6 {
	struct in6_addr aca_addr;
	struct fib6_info *aca_rt;
	struct ifacaddr6 *aca_next;
	struct hlist_node aca_addr_lst;
	int aca_users;
	refcount_t aca_refcnt;
	long unsigned int aca_cstamp;
	long unsigned int aca_tstamp;
	struct callback_head rcu;
};

enum nfs_opnum4 {
	OP_ACCESS = 3,
	OP_CLOSE = 4,
	OP_COMMIT = 5,
	OP_CREATE = 6,
	OP_DELEGPURGE = 7,
	OP_DELEGRETURN = 8,
	OP_GETATTR = 9,
	OP_GETFH = 10,
	OP_LINK = 11,
	OP_LOCK = 12,
	OP_LOCKT = 13,
	OP_LOCKU = 14,
	OP_LOOKUP = 15,
	OP_LOOKUPP = 16,
	OP_NVERIFY = 17,
	OP_OPEN = 18,
	OP_OPENATTR = 19,
	OP_OPEN_CONFIRM = 20,
	OP_OPEN_DOWNGRADE = 21,
	OP_PUTFH = 22,
	OP_PUTPUBFH = 23,
	OP_PUTROOTFH = 24,
	OP_READ = 25,
	OP_READDIR = 26,
	OP_READLINK = 27,
	OP_REMOVE = 28,
	OP_RENAME = 29,
	OP_RENEW = 30,
	OP_RESTOREFH = 31,
	OP_SAVEFH = 32,
	OP_SECINFO = 33,
	OP_SETATTR = 34,
	OP_SETCLIENTID = 35,
	OP_SETCLIENTID_CONFIRM = 36,
	OP_VERIFY = 37,
	OP_WRITE = 38,
	OP_RELEASE_LOCKOWNER = 39,
	OP_BACKCHANNEL_CTL = 40,
	OP_BIND_CONN_TO_SESSION = 41,
	OP_EXCHANGE_ID = 42,
	OP_CREATE_SESSION = 43,
	OP_DESTROY_SESSION = 44,
	OP_FREE_STATEID = 45,
	OP_GET_DIR_DELEGATION = 46,
	OP_GETDEVICEINFO = 47,
	OP_GETDEVICELIST = 48,
	OP_LAYOUTCOMMIT = 49,
	OP_LAYOUTGET = 50,
	OP_LAYOUTRETURN = 51,
	OP_SECINFO_NO_NAME = 52,
	OP_SEQUENCE = 53,
	OP_SET_SSV = 54,
	OP_TEST_STATEID = 55,
	OP_WANT_DELEGATION = 56,
	OP_DESTROY_CLIENTID = 57,
	OP_RECLAIM_COMPLETE = 58,
	OP_ALLOCATE = 59,
	OP_COPY = 60,
	OP_COPY_NOTIFY = 61,
	OP_DEALLOCATE = 62,
	OP_IO_ADVISE = 63,
	OP_LAYOUTERROR = 64,
	OP_LAYOUTSTATS = 65,
	OP_OFFLOAD_CANCEL = 66,
	OP_OFFLOAD_STATUS = 67,
	OP_READ_PLUS = 68,
	OP_SEEK = 69,
	OP_WRITE_SAME = 70,
	OP_CLONE = 71,
	OP_GETXATTR = 72,
	OP_SETXATTR = 73,
	OP_LISTXATTRS = 74,
	OP_REMOVEXATTR = 75,
	OP_ILLEGAL = 10044,
};

enum perf_branch_sample_type_shift {
	PERF_SAMPLE_BRANCH_USER_SHIFT = 0,
	PERF_SAMPLE_BRANCH_KERNEL_SHIFT = 1,
	PERF_SAMPLE_BRANCH_HV_SHIFT = 2,
	PERF_SAMPLE_BRANCH_ANY_SHIFT = 3,
	PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT = 4,
	PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT = 5,
	PERF_SAMPLE_BRANCH_IND_CALL_SHIFT = 6,
	PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT = 7,
	PERF_SAMPLE_BRANCH_IN_TX_SHIFT = 8,
	PERF_SAMPLE_BRANCH_NO_TX_SHIFT = 9,
	PERF_SAMPLE_BRANCH_COND_SHIFT = 10,
	PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT = 11,
	PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT = 12,
	PERF_SAMPLE_BRANCH_CALL_SHIFT = 13,
	PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT = 14,
	PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT = 15,
	PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT = 16,
	PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT = 17,
	PERF_SAMPLE_BRANCH_MAX_SHIFT = 18,
};

enum exception_stack_ordering {
	ESTACK_DF = 0,
	ESTACK_NMI = 1,
	ESTACK_DB = 2,
	ESTACK_MCE = 3,
	ESTACK_VC = 4,
	ESTACK_VC2 = 5,
	N_EXCEPTION_STACKS = 6,
};

enum {
	TSK_TRACE_FL_TRACE_BIT = 0,
	TSK_TRACE_FL_GRAPH_BIT = 1,
};

struct uuidcmp {
	const char *uuid;
	int len;
};

struct subprocess_info {
	struct work_struct work;
	struct completion *complete;
	const char *path;
	char **argv;
	char **envp;
	int wait;
	int retval;
	int (*init)(struct subprocess_info *, struct cred *);
	void (*cleanup)(struct subprocess_info *);
	void *data;
};

typedef phys_addr_t resource_size_t;

struct __va_list_tag {
	unsigned int gp_offset;
	unsigned int fp_offset;
	void *overflow_arg_area;
	void *reg_save_area;
};

typedef __builtin_va_list va_list;

struct resource {
	resource_size_t start;
	resource_size_t end;
	const char *name;
	long unsigned int flags;
	long unsigned int desc;
	struct resource *parent;
	struct resource *sibling;
	struct resource *child;
};

enum umh_disable_depth {
	UMH_ENABLED = 0,
	UMH_FREEZING = 1,
	UMH_DISABLED = 2,
};

typedef u64 async_cookie_t;

typedef void (*async_func_t)(void *, async_cookie_t);

struct async_domain {
	struct list_head pending;
	unsigned int registered: 1;
};

struct hash {
	int ino;
	int minor;
	int major;
	umode_t mode;
	struct hash *next;
	char name[4098];
};

struct dir_entry {
	struct list_head list;
	time64_t mtime;
	char name[0];
};

enum state {
	Start = 0,
	Collect = 1,
	GotHeader = 2,
	SkipIt = 3,
	GotName = 4,
	CopyFile = 5,
	GotSymlink = 6,
	Reset = 7,
};

typedef int (*decompress_fn)(unsigned char *, long int, long int (*)(void *, long unsigned int), long int (*)(void *, long unsigned int), unsigned char *, long int *, void (*)(char *));

enum {
	HI_SOFTIRQ = 0,
	TIMER_SOFTIRQ = 1,
	NET_TX_SOFTIRQ = 2,
	NET_RX_SOFTIRQ = 3,
	BLOCK_SOFTIRQ = 4,
	IRQ_POLL_SOFTIRQ = 5,
	TASKLET_SOFTIRQ = 6,
	SCHED_SOFTIRQ = 7,
	HRTIMER_SOFTIRQ = 8,
	RCU_SOFTIRQ = 9,
	NR_SOFTIRQS = 10,
};

enum ucount_type {
	UCOUNT_USER_NAMESPACES = 0,
	UCOUNT_PID_NAMESPACES = 1,
	UCOUNT_UTS_NAMESPACES = 2,
	UCOUNT_IPC_NAMESPACES = 3,
	UCOUNT_NET_NAMESPACES = 4,
	UCOUNT_MNT_NAMESPACES = 5,
	UCOUNT_CGROUP_NAMESPACES = 6,
	UCOUNT_TIME_NAMESPACES = 7,
	UCOUNT_INOTIFY_INSTANCES = 8,
	UCOUNT_INOTIFY_WATCHES = 9,
	UCOUNT_FANOTIFY_GROUPS = 10,
	UCOUNT_FANOTIFY_MARKS = 11,
	UCOUNT_RLIMIT_NPROC = 12,
	UCOUNT_RLIMIT_MSGQUEUE = 13,
	UCOUNT_RLIMIT_SIGPENDING = 14,
	UCOUNT_RLIMIT_MEMLOCK = 15,
	UCOUNT_COUNTS = 16,
};

enum audit_ntp_type {
	AUDIT_NTP_OFFSET = 0,
	AUDIT_NTP_FREQ = 1,
	AUDIT_NTP_STATUS = 2,
	AUDIT_NTP_TAI = 3,
	AUDIT_NTP_TICK = 4,
	AUDIT_NTP_ADJUST = 5,
	AUDIT_NTP_NVALS = 6,
};

enum cc_attr {
	CC_ATTR_MEM_ENCRYPT = 0,
	CC_ATTR_HOST_MEM_ENCRYPT = 1,
	CC_ATTR_GUEST_MEM_ENCRYPT = 2,
	CC_ATTR_GUEST_STATE_ENCRYPT = 3,
	CC_ATTR_GUEST_UNROLL_STRING_IO = 4,
	CC_ATTR_GUEST_SEV_SNP = 5,
	CC_ATTR_HOTPLUG_DISABLED = 6,
};

enum cc_vendor {
	CC_VENDOR_NONE = 0,
	CC_VENDOR_AMD = 1,
	CC_VENDOR_HYPERV = 2,
	CC_VENDOR_INTEL = 3,
};

typedef long int (*sys_call_ptr_t)(const struct pt_regs *);

struct io_bitmap {
	u64 sequence;
	refcount_t refcnt;
	unsigned int max;
	long unsigned int bitmap[1024];
};

enum {
	EI_ETYPE_NONE = 0,
	EI_ETYPE_NULL = 1,
	EI_ETYPE_ERRNO = 2,
	EI_ETYPE_ERRNO_NULL = 3,
	EI_ETYPE_TRUE = 4,
};

struct device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device *, struct device_attribute *, char *);
	ssize_t (*store)(struct device *, struct device_attribute *, const char *, size_t);
};

struct platform_msi_priv_data;

struct msi_device_data {
	long unsigned int properties;
	struct platform_msi_priv_data *platform_data;
	struct mutex mutex;
	struct xarray __store;
	long unsigned int __iter_idx;
};

typedef struct {
	u16 __softirq_pending;
	u8 kvm_cpu_l1tf_flush_l1d;
	unsigned int __nmi_count;
	unsigned int apic_timer_irqs;
	unsigned int irq_spurious_count;
	unsigned int icr_read_retry_count;
	unsigned int kvm_posted_intr_ipis;
	unsigned int kvm_posted_intr_wakeup_ipis;
	unsigned int kvm_posted_intr_nested_ipis;
	unsigned int x86_platform_ipis;
	unsigned int apic_perf_irqs;
	unsigned int apic_irq_work_irqs;
	unsigned int irq_resched_count;
	unsigned int irq_call_count;
	unsigned int irq_tlb_count;
	unsigned int irq_thermal_count;
	unsigned int irq_threshold_count;
	unsigned int irq_deferred_error_count;
	unsigned int irq_hv_callback_count;
	unsigned int irq_hv_reenlightenment_count;
	unsigned int hyperv_stimer0_count;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
} irq_cpustat_t;

enum irqreturn {
	IRQ_NONE = 0,
	IRQ_HANDLED = 1,
	IRQ_WAKE_THREAD = 2,
};

typedef enum irqreturn irqreturn_t;

typedef irqreturn_t (*irq_handler_t)(int, void *);

struct irqaction {
	irq_handler_t handler;
	void *dev_id;
	void *percpu_dev_id;
	struct irqaction *next;
	irq_handler_t thread_fn;
	struct task_struct *thread;
	struct irqaction *secondary;
	unsigned int irq;
	unsigned int flags;
	long unsigned int thread_flags;
	long unsigned int thread_mask;
	const char *name;
	struct proc_dir_entry *dir;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct irq_affinity_notify {
	unsigned int irq;
	struct kref kref;
	struct work_struct work;
	void (*notify)(struct irq_affinity_notify *, const cpumask_t *);
	void (*release)(struct kref *);
};

struct irq_affinity_desc {
	struct cpumask mask;
	unsigned int is_managed: 1;
};

enum irqchip_irq_state {
	IRQCHIP_STATE_PENDING = 0,
	IRQCHIP_STATE_ACTIVE = 1,
	IRQCHIP_STATE_MASKED = 2,
	IRQCHIP_STATE_LINE_LEVEL = 3,
};

struct syscall_metadata {
	const char *name;
	int syscall_nr;
	int nb_args;
	const char **types;
	const char **args;
	struct list_head enter_fields;
	struct trace_event_call *enter_event;
	struct trace_event_call *exit_event;
};

struct irqentry_state {
	union {
		bool exit_rcu;
		bool lockdep;
	};
};

typedef struct irqentry_state irqentry_state_t;

struct irq_desc;

typedef void (*irq_flow_handler_t)(struct irq_desc *);

struct msi_desc;

struct irq_common_data {
	unsigned int state_use_accessors;
	unsigned int node;
	void *handler_data;
	struct msi_desc *msi_desc;
	cpumask_var_t affinity;
	cpumask_var_t effective_affinity;
};

struct irq_chip;

struct irq_data {
	u32 mask;
	unsigned int irq;
	long unsigned int hwirq;
	struct irq_common_data *common;
	struct irq_chip *chip;
	struct irq_domain *domain;
	struct irq_data *parent_data;
	void *chip_data;
};

struct irq_desc {
	struct irq_common_data irq_common_data;
	struct irq_data irq_data;
	unsigned int *kstat_irqs;
	irq_flow_handler_t handle_irq;
	struct irqaction *action;
	unsigned int status_use_accessors;
	unsigned int core_internal_state__do_not_mess_with_it;
	unsigned int depth;
	unsigned int wake_depth;
	unsigned int tot_count;
	unsigned int irq_count;
	long unsigned int last_unhandled;
	unsigned int irqs_unhandled;
	atomic_t threads_handled;
	int threads_handled_last;
	raw_spinlock_t lock;
	struct cpumask *percpu_enabled;
	const struct cpumask *percpu_affinity;
	const struct cpumask *affinity_hint;
	struct irq_affinity_notify *affinity_notify;
	cpumask_var_t pending_mask;
	long unsigned int threads_oneshot;
	atomic_t threads_active;
	wait_queue_head_t wait_for_threads;
	unsigned int nr_actions;
	unsigned int no_suspend_depth;
	unsigned int cond_suspend_depth;
	unsigned int force_resume_depth;
	struct proc_dir_entry *dir;
	struct callback_head rcu;
	struct kobject kobj;
	struct mutex request_mutex;
	int parent_irq;
	struct module *owner;
	const char *name;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct x86_msi_addr_lo {
	union {
		struct {
			u32 reserved_0: 2;
			u32 dest_mode_logical: 1;
			u32 redirect_hint: 1;
			u32 reserved_1: 1;
			u32 virt_destid_8_14: 7;
			u32 destid_0_7: 8;
			u32 base_address: 12;
		};
		struct {
			u32 dmar_reserved_0: 2;
			u32 dmar_index_15: 1;
			u32 dmar_subhandle_valid: 1;
			u32 dmar_format: 1;
			u32 dmar_index_0_14: 15;
			u32 dmar_base_address: 12;
		};
	};
};

typedef struct x86_msi_addr_lo arch_msi_msg_addr_lo_t;

struct x86_msi_addr_hi {
	u32 reserved: 8;
	u32 destid_8_31: 24;
};

typedef struct x86_msi_addr_hi arch_msi_msg_addr_hi_t;

struct x86_msi_data {
	union {
		struct {
			u32 vector: 8;
			u32 delivery_mode: 3;
			u32 dest_mode_logical: 1;
			u32 reserved: 2;
			u32 active_low: 1;
			u32 is_level: 1;
		};
		u32 dmar_subhandle;
	};
};

typedef struct x86_msi_data arch_msi_msg_data_t;

struct msi_msg {
	union {
		u32 address_lo;
		arch_msi_msg_addr_lo_t arch_addr_lo;
	};
	union {
		u32 address_hi;
		arch_msi_msg_addr_hi_t arch_addr_hi;
	};
	union {
		u32 data;
		arch_msi_msg_data_t arch_data;
	};
};

struct pci_msi_desc {
	union {
		u32 msi_mask;
		u32 msix_ctrl;
	};
	struct {
		u8 is_msix: 1;
		u8 multiple: 3;
		u8 multi_cap: 3;
		u8 can_mask: 1;
		u8 is_64: 1;
		u8 is_virtual: 1;
		unsigned int default_irq;
	} msi_attrib;
	union {
		u8 mask_pos;
		void *mask_base;
	};
};

struct msi_desc {
	unsigned int irq;
	unsigned int nvec_used;
	struct device *dev;
	struct msi_msg msg;
	struct irq_affinity_desc *affinity;
	const void *iommu_cookie;
	struct device_attribute *sysfs_attrs;
	void (*write_msi_msg)(struct msi_desc *, void *);
	void *write_msi_msg_data;
	u16 msi_index;
	struct pci_msi_desc pci;
};

struct irq_chip {
	const char *name;
	unsigned int (*irq_startup)(struct irq_data *);
	void (*irq_shutdown)(struct irq_data *);
	void (*irq_enable)(struct irq_data *);
	void (*irq_disable)(struct irq_data *);
	void (*irq_ack)(struct irq_data *);
	void (*irq_mask)(struct irq_data *);
	void (*irq_mask_ack)(struct irq_data *);
	void (*irq_unmask)(struct irq_data *);
	void (*irq_eoi)(struct irq_data *);
	int (*irq_set_affinity)(struct irq_data *, const struct cpumask *, bool);
	int (*irq_retrigger)(struct irq_data *);
	int (*irq_set_type)(struct irq_data *, unsigned int);
	int (*irq_set_wake)(struct irq_data *, unsigned int);
	void (*irq_bus_lock)(struct irq_data *);
	void (*irq_bus_sync_unlock)(struct irq_data *);
	void (*irq_suspend)(struct irq_data *);
	void (*irq_resume)(struct irq_data *);
	void (*irq_pm_shutdown)(struct irq_data *);
	void (*irq_calc_mask)(struct irq_data *);
	void (*irq_print_chip)(struct irq_data *, struct seq_file *);
	int (*irq_request_resources)(struct irq_data *);
	void (*irq_release_resources)(struct irq_data *);
	void (*irq_compose_msi_msg)(struct irq_data *, struct msi_msg *);
	void (*irq_write_msi_msg)(struct irq_data *, struct msi_msg *);
	int (*irq_get_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool *);
	int (*irq_set_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool);
	int (*irq_set_vcpu_affinity)(struct irq_data *, void *);
	void (*ipi_send_single)(struct irq_data *, unsigned int);
	void (*ipi_send_mask)(struct irq_data *, const struct cpumask *);
	int (*irq_nmi_setup)(struct irq_data *);
	void (*irq_nmi_teardown)(struct irq_data *);
	long unsigned int flags;
};

struct irq_chip_regs {
	long unsigned int enable;
	long unsigned int disable;
	long unsigned int mask;
	long unsigned int ack;
	long unsigned int eoi;
	long unsigned int type;
	long unsigned int polarity;
};

struct irq_chip_type {
	struct irq_chip chip;
	struct irq_chip_regs regs;
	irq_flow_handler_t handler;
	u32 type;
	u32 mask_cache_priv;
	u32 *mask_cache;
};

struct irq_chip_generic {
	raw_spinlock_t lock;
	void *reg_base;
	u32 (*reg_readl)(void *);
	void (*reg_writel)(u32, void *);
	void (*suspend)(struct irq_chip_generic *);
	void (*resume)(struct irq_chip_generic *);
	unsigned int irq_base;
	unsigned int irq_cnt;
	u32 mask_cache;
	u32 type_cache;
	u32 polarity_cache;
	u32 wake_enabled;
	u32 wake_active;
	unsigned int num_ct;
	void *private;
	long unsigned int installed;
	long unsigned int unused;
	struct irq_domain *domain;
	struct list_head list;
	struct irq_chip_type chip_types[0];
};

enum irq_gc_flags {
	IRQ_GC_INIT_MASK_CACHE = 1,
	IRQ_GC_INIT_NESTED_LOCK = 2,
	IRQ_GC_MASK_CACHE_PER_TYPE = 4,
	IRQ_GC_NO_MASK = 8,
	IRQ_GC_BE_IO = 16,
};

struct irq_domain_chip_generic {
	unsigned int irqs_per_chip;
	unsigned int num_chips;
	unsigned int irq_flags_to_clear;
	unsigned int irq_flags_to_set;
	enum irq_gc_flags gc_flags;
	struct irq_chip_generic *gc[0];
};

struct alt_instr {
	s32 instr_offset;
	s32 repl_offset;
	u16 cpuid;
	u8 instrlen;
	u8 replacementlen;
};

struct timens_offset {
	s64 sec;
	u64 nsec;
};

enum vm_fault_reason {
	VM_FAULT_OOM = 1,
	VM_FAULT_SIGBUS = 2,
	VM_FAULT_MAJOR = 4,
	VM_FAULT_WRITE = 8,
	VM_FAULT_HWPOISON = 16,
	VM_FAULT_HWPOISON_LARGE = 32,
	VM_FAULT_SIGSEGV = 64,
	VM_FAULT_NOPAGE = 256,
	VM_FAULT_LOCKED = 512,
	VM_FAULT_RETRY = 1024,
	VM_FAULT_FALLBACK = 2048,
	VM_FAULT_DONE_COW = 4096,
	VM_FAULT_NEEDDSYNC = 8192,
	VM_FAULT_HINDEX_MASK = 983040,
};

struct vm_special_mapping {
	const char *name;
	struct page **pages;
	vm_fault_t (*fault)(const struct vm_special_mapping *, struct vm_area_struct *, struct vm_fault *);
	int (*mremap)(const struct vm_special_mapping *, struct vm_area_struct *);
};

struct timens_offsets {
	struct timespec64 monotonic;
	struct timespec64 boottime;
};

struct time_namespace {
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
	struct timens_offsets offsets;
	struct page *vvar_page;
	bool frozen_offsets;
};

struct pvclock_vcpu_time_info {
	u32 version;
	u32 pad0;
	u64 tsc_timestamp;
	u64 system_time;
	u32 tsc_to_system_mul;
	s8 tsc_shift;
	u8 flags;
	u8 pad[2];
};

struct pvclock_vsyscall_time_info {
	struct pvclock_vcpu_time_info pvti;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum vdso_clock_mode {
	VDSO_CLOCKMODE_NONE = 0,
	VDSO_CLOCKMODE_TSC = 1,
	VDSO_CLOCKMODE_PVCLOCK = 2,
	VDSO_CLOCKMODE_HVCLOCK = 3,
	VDSO_CLOCKMODE_MAX = 4,
	VDSO_CLOCKMODE_TIMENS = 2147483647,
};

struct arch_vdso_data {};

struct vdso_timestamp {
	u64 sec;
	u64 nsec;
};

struct vdso_data {
	u32 seq;
	s32 clock_mode;
	u64 cycle_last;
	u64 mask;
	u32 mult;
	u32 shift;
	union {
		struct vdso_timestamp basetime[12];
		struct timens_offset offset[12];
	};
	s32 tz_minuteswest;
	s32 tz_dsttime;
	u32 hrtimer_res;
	u32 __unused;
	struct arch_vdso_data arch_data;
};

struct ms_hyperv_tsc_page {
	volatile u32 tsc_sequence;
	u32 reserved1;
	volatile u64 tsc_scale;
	volatile s64 tsc_offset;
};

enum {
	TASKSTATS_CMD_UNSPEC = 0,
	TASKSTATS_CMD_GET = 1,
	TASKSTATS_CMD_NEW = 2,
	__TASKSTATS_CMD_MAX = 3,
};

enum cpu_usage_stat {
	CPUTIME_USER = 0,
	CPUTIME_NICE = 1,
	CPUTIME_SYSTEM = 2,
	CPUTIME_SOFTIRQ = 3,
	CPUTIME_IRQ = 4,
	CPUTIME_IDLE = 5,
	CPUTIME_IOWAIT = 6,
	CPUTIME_STEAL = 7,
	CPUTIME_GUEST = 8,
	CPUTIME_GUEST_NICE = 9,
	NR_STATS = 10,
};

enum cgroup_bpf_attach_type {
	CGROUP_BPF_ATTACH_TYPE_INVALID = 4294967295,
	CGROUP_INET_INGRESS = 0,
	CGROUP_INET_EGRESS = 1,
	CGROUP_INET_SOCK_CREATE = 2,
	CGROUP_SOCK_OPS = 3,
	CGROUP_DEVICE = 4,
	CGROUP_INET4_BIND = 5,
	CGROUP_INET6_BIND = 6,
	CGROUP_INET4_CONNECT = 7,
	CGROUP_INET6_CONNECT = 8,
	CGROUP_INET4_POST_BIND = 9,
	CGROUP_INET6_POST_BIND = 10,
	CGROUP_UDP4_SENDMSG = 11,
	CGROUP_UDP6_SENDMSG = 12,
	CGROUP_SYSCTL = 13,
	CGROUP_UDP4_RECVMSG = 14,
	CGROUP_UDP6_RECVMSG = 15,
	CGROUP_GETSOCKOPT = 16,
	CGROUP_SETSOCKOPT = 17,
	CGROUP_INET4_GETPEERNAME = 18,
	CGROUP_INET6_GETPEERNAME = 19,
	CGROUP_INET4_GETSOCKNAME = 20,
	CGROUP_INET6_GETSOCKNAME = 21,
	CGROUP_INET_SOCK_RELEASE = 22,
	MAX_CGROUP_BPF_ATTACH_TYPE = 23,
};

enum psi_task_count {
	NR_IOWAIT = 0,
	NR_MEMSTALL = 1,
	NR_RUNNING = 2,
	NR_ONCPU = 3,
	NR_MEMSTALL_RUNNING = 4,
	NR_PSI_TASK_COUNTS = 5,
};

enum psi_states {
	PSI_IO_SOME = 0,
	PSI_IO_FULL = 1,
	PSI_MEM_SOME = 2,
	PSI_MEM_FULL = 3,
	PSI_CPU_SOME = 4,
	PSI_CPU_FULL = 5,
	PSI_NONIDLE = 6,
	NR_PSI_STATES = 7,
};

enum psi_aggregators {
	PSI_AVGS = 0,
	PSI_POLL = 1,
	NR_PSI_AGGREGATORS = 2,
};

enum cgroup_subsys_id {
	cpuset_cgrp_id = 0,
	cpu_cgrp_id = 1,
	cpuacct_cgrp_id = 2,
	io_cgrp_id = 3,
	memory_cgrp_id = 4,
	devices_cgrp_id = 5,
	freezer_cgrp_id = 6,
	net_cls_cgrp_id = 7,
	perf_event_cgrp_id = 8,
	net_prio_cgrp_id = 9,
	hugetlb_cgrp_id = 10,
	pids_cgrp_id = 11,
	rdma_cgrp_id = 12,
	misc_cgrp_id = 13,
	CGROUP_SUBSYS_COUNT = 14,
};

struct vdso_exception_table_entry {
	int insn;
	int fixup;
};

struct cpuinfo_x86 {
	__u8 x86;
	__u8 x86_vendor;
	__u8 x86_model;
	__u8 x86_stepping;
	int x86_tlbsize;
	__u32 vmx_capability[3];
	__u8 x86_virt_bits;
	__u8 x86_phys_bits;
	__u8 x86_coreid_bits;
	__u8 cu_id;
	__u32 extended_cpuid_level;
	int cpuid_level;
	union {
		__u32 x86_capability[21];
		long unsigned int x86_capability_alignment;
	};
	char x86_vendor_id[16];
	char x86_model_id[64];
	unsigned int x86_cache_size;
	int x86_cache_alignment;
	int x86_cache_max_rmid;
	int x86_cache_occ_scale;
	int x86_cache_mbm_width_offset;
	int x86_power;
	long unsigned int loops_per_jiffy;
	u64 ppin;
	u16 x86_max_cores;
	u16 apicid;
	u16 initial_apicid;
	u16 x86_clflush_size;
	u16 booted_cores;
	u16 phys_proc_id;
	u16 logical_proc_id;
	u16 cpu_core_id;
	u16 cpu_die_id;
	u16 logical_die_id;
	u16 cpu_index;
	bool smt_active;
	u32 microcode;
	u8 x86_cache_bits;
	unsigned int initialized: 1;
};

enum syscall_work_bit {
	SYSCALL_WORK_BIT_SECCOMP = 0,
	SYSCALL_WORK_BIT_SYSCALL_TRACEPOINT = 1,
	SYSCALL_WORK_BIT_SYSCALL_TRACE = 2,
	SYSCALL_WORK_BIT_SYSCALL_EMU = 3,
	SYSCALL_WORK_BIT_SYSCALL_AUDIT = 4,
	SYSCALL_WORK_BIT_SYSCALL_USER_DISPATCH = 5,
	SYSCALL_WORK_BIT_SYSCALL_EXIT_TRAP = 6,
};

enum x86_pf_error_code {
	X86_PF_PROT = 1,
	X86_PF_WRITE = 2,
	X86_PF_USER = 4,
	X86_PF_RSVD = 8,
	X86_PF_INSTR = 16,
	X86_PF_PK = 32,
	X86_PF_SGX = 32768,
};

struct trace_event_raw_emulate_vsyscall {
	struct trace_entry ent;
	int nr;
	char __data[0];
};

struct trace_event_data_offsets_emulate_vsyscall {};

typedef void (*btf_trace_emulate_vsyscall)(void *, int);

enum {
	EMULATE = 0,
	XONLY = 1,
	NONE = 2,
};

enum perf_type_id {
	PERF_TYPE_HARDWARE = 0,
	PERF_TYPE_SOFTWARE = 1,
	PERF_TYPE_TRACEPOINT = 2,
	PERF_TYPE_HW_CACHE = 3,
	PERF_TYPE_RAW = 4,
	PERF_TYPE_BREAKPOINT = 5,
	PERF_TYPE_MAX = 6,
};

enum perf_hw_id {
	PERF_COUNT_HW_CPU_CYCLES = 0,
	PERF_COUNT_HW_INSTRUCTIONS = 1,
	PERF_COUNT_HW_CACHE_REFERENCES = 2,
	PERF_COUNT_HW_CACHE_MISSES = 3,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS = 4,
	PERF_COUNT_HW_BRANCH_MISSES = 5,
	PERF_COUNT_HW_BUS_CYCLES = 6,
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND = 7,
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND = 8,
	PERF_COUNT_HW_REF_CPU_CYCLES = 9,
	PERF_COUNT_HW_MAX = 10,
};

enum perf_hw_cache_id {
	PERF_COUNT_HW_CACHE_L1D = 0,
	PERF_COUNT_HW_CACHE_L1I = 1,
	PERF_COUNT_HW_CACHE_LL = 2,
	PERF_COUNT_HW_CACHE_DTLB = 3,
	PERF_COUNT_HW_CACHE_ITLB = 4,
	PERF_COUNT_HW_CACHE_BPU = 5,
	PERF_COUNT_HW_CACHE_NODE = 6,
	PERF_COUNT_HW_CACHE_MAX = 7,
};

enum perf_hw_cache_op_id {
	PERF_COUNT_HW_CACHE_OP_READ = 0,
	PERF_COUNT_HW_CACHE_OP_WRITE = 1,
	PERF_COUNT_HW_CACHE_OP_PREFETCH = 2,
	PERF_COUNT_HW_CACHE_OP_MAX = 3,
};

enum perf_hw_cache_op_result_id {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS = 0,
	PERF_COUNT_HW_CACHE_RESULT_MISS = 1,
	PERF_COUNT_HW_CACHE_RESULT_MAX = 2,
};

enum perf_event_sample_format {
	PERF_SAMPLE_IP = 1,
	PERF_SAMPLE_TID = 2,
	PERF_SAMPLE_TIME = 4,
	PERF_SAMPLE_ADDR = 8,
	PERF_SAMPLE_READ = 16,
	PERF_SAMPLE_CALLCHAIN = 32,
	PERF_SAMPLE_ID = 64,
	PERF_SAMPLE_CPU = 128,
	PERF_SAMPLE_PERIOD = 256,
	PERF_SAMPLE_STREAM_ID = 512,
	PERF_SAMPLE_RAW = 1024,
	PERF_SAMPLE_BRANCH_STACK = 2048,
	PERF_SAMPLE_REGS_USER = 4096,
	PERF_SAMPLE_STACK_USER = 8192,
	PERF_SAMPLE_WEIGHT = 16384,
	PERF_SAMPLE_DATA_SRC = 32768,
	PERF_SAMPLE_IDENTIFIER = 65536,
	PERF_SAMPLE_TRANSACTION = 131072,
	PERF_SAMPLE_REGS_INTR = 262144,
	PERF_SAMPLE_PHYS_ADDR = 524288,
	PERF_SAMPLE_AUX = 1048576,
	PERF_SAMPLE_CGROUP = 2097152,
	PERF_SAMPLE_DATA_PAGE_SIZE = 4194304,
	PERF_SAMPLE_CODE_PAGE_SIZE = 8388608,
	PERF_SAMPLE_WEIGHT_STRUCT = 16777216,
	PERF_SAMPLE_MAX = 33554432,
	__PERF_SAMPLE_CALLCHAIN_EARLY = 0,
};

enum perf_branch_sample_type {
	PERF_SAMPLE_BRANCH_USER = 1,
	PERF_SAMPLE_BRANCH_KERNEL = 2,
	PERF_SAMPLE_BRANCH_HV = 4,
	PERF_SAMPLE_BRANCH_ANY = 8,
	PERF_SAMPLE_BRANCH_ANY_CALL = 16,
	PERF_SAMPLE_BRANCH_ANY_RETURN = 32,
	PERF_SAMPLE_BRANCH_IND_CALL = 64,
	PERF_SAMPLE_BRANCH_ABORT_TX = 128,
	PERF_SAMPLE_BRANCH_IN_TX = 256,
	PERF_SAMPLE_BRANCH_NO_TX = 512,
	PERF_SAMPLE_BRANCH_COND = 1024,
	PERF_SAMPLE_BRANCH_CALL_STACK = 2048,
	PERF_SAMPLE_BRANCH_IND_JUMP = 4096,
	PERF_SAMPLE_BRANCH_CALL = 8192,
	PERF_SAMPLE_BRANCH_NO_FLAGS = 16384,
	PERF_SAMPLE_BRANCH_NO_CYCLES = 32768,
	PERF_SAMPLE_BRANCH_TYPE_SAVE = 65536,
	PERF_SAMPLE_BRANCH_HW_INDEX = 131072,
	PERF_SAMPLE_BRANCH_MAX = 262144,
};

struct perf_event_mmap_page {
	__u32 version;
	__u32 compat_version;
	__u32 lock;
	__u32 index;
	__s64 offset;
	__u64 time_enabled;
	__u64 time_running;
	union {
		__u64 capabilities;
		struct {
			__u64 cap_bit0: 1;
			__u64 cap_bit0_is_deprecated: 1;
			__u64 cap_user_rdpmc: 1;
			__u64 cap_user_time: 1;
			__u64 cap_user_time_zero: 1;
			__u64 cap_user_time_short: 1;
			__u64 cap_____res: 58;
		};
	};
	__u16 pmc_width;
	__u16 time_shift;
	__u32 time_mult;
	__u64 time_offset;
	__u64 time_zero;
	__u32 size;
	__u32 __reserved_1;
	__u64 time_cycles;
	__u64 time_mask;
	__u8 __reserved[928];
	__u64 data_head;
	__u64 data_tail;
	__u64 data_offset;
	__u64 data_size;
	__u64 aux_head;
	__u64 aux_tail;
	__u64 aux_offset;
	__u64 aux_size;
};

struct pv_info {
	u16 extra_user_64bit_cs;
	const char *name;
};

typedef void (*smp_call_func_t)(void *);

enum apic_delivery_modes {
	APIC_DELIVERY_MODE_FIXED = 0,
	APIC_DELIVERY_MODE_LOWESTPRIO = 1,
	APIC_DELIVERY_MODE_SMI = 2,
	APIC_DELIVERY_MODE_NMI = 4,
	APIC_DELIVERY_MODE_INIT = 5,
	APIC_DELIVERY_MODE_EXTINT = 7,
};

struct physid_mask {
	long unsigned int mask[512];
};

typedef struct physid_mask physid_mask_t;

struct x86_pmu_capability {
	int version;
	int num_counters_gp;
	int num_counters_fixed;
	int bit_width_gp;
	int bit_width_fixed;
	unsigned int events_mask;
	int events_mask_len;
};

struct debug_store {
	u64 bts_buffer_base;
	u64 bts_index;
	u64 bts_absolute_maximum;
	u64 bts_interrupt_threshold;
	u64 pebs_buffer_base;
	u64 pebs_index;
	u64 pebs_absolute_maximum;
	u64 pebs_interrupt_threshold;
	u64 pebs_event_reset[48];
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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum stack_type {
	STACK_TYPE_UNKNOWN = 0,
	STACK_TYPE_TASK = 1,
	STACK_TYPE_IRQ = 2,
	STACK_TYPE_SOFTIRQ = 3,
	STACK_TYPE_ENTRY = 4,
	STACK_TYPE_EXCEPTION = 5,
	STACK_TYPE_EXCEPTION_LAST = 10,
};

struct stack_info {
	enum stack_type type;
	long unsigned int *begin;
	long unsigned int *end;
	long unsigned int *next_sp;
};

struct stack_frame {
	struct stack_frame *next_frame;
	long unsigned int return_address;
};

struct stack_frame_ia32 {
	u32 next_frame;
	u32 return_address;
};

struct perf_guest_switch_msr {
	unsigned int msr;
	u64 host;
	u64 guest;
};

enum perf_event_x86_regs {
	PERF_REG_X86_AX = 0,
	PERF_REG_X86_BX = 1,
	PERF_REG_X86_CX = 2,
	PERF_REG_X86_DX = 3,
	PERF_REG_X86_SI = 4,
	PERF_REG_X86_DI = 5,
	PERF_REG_X86_BP = 6,
	PERF_REG_X86_SP = 7,
	PERF_REG_X86_IP = 8,
	PERF_REG_X86_FLAGS = 9,
	PERF_REG_X86_CS = 10,
	PERF_REG_X86_SS = 11,
	PERF_REG_X86_DS = 12,
	PERF_REG_X86_ES = 13,
	PERF_REG_X86_FS = 14,
	PERF_REG_X86_GS = 15,
	PERF_REG_X86_R8 = 16,
	PERF_REG_X86_R9 = 17,
	PERF_REG_X86_R10 = 18,
	PERF_REG_X86_R11 = 19,
	PERF_REG_X86_R12 = 20,
	PERF_REG_X86_R13 = 21,
	PERF_REG_X86_R14 = 22,
	PERF_REG_X86_R15 = 23,
	PERF_REG_X86_32_MAX = 16,
	PERF_REG_X86_64_MAX = 24,
	PERF_REG_X86_XMM0 = 32,
	PERF_REG_X86_XMM1 = 34,
	PERF_REG_X86_XMM2 = 36,
	PERF_REG_X86_XMM3 = 38,
	PERF_REG_X86_XMM4 = 40,
	PERF_REG_X86_XMM5 = 42,
	PERF_REG_X86_XMM6 = 44,
	PERF_REG_X86_XMM7 = 46,
	PERF_REG_X86_XMM8 = 48,
	PERF_REG_X86_XMM9 = 50,
	PERF_REG_X86_XMM10 = 52,
	PERF_REG_X86_XMM11 = 54,
	PERF_REG_X86_XMM12 = 56,
	PERF_REG_X86_XMM13 = 58,
	PERF_REG_X86_XMM14 = 60,
	PERF_REG_X86_XMM15 = 62,
	PERF_REG_X86_XMM_MAX = 64,
};

struct perf_callchain_entry_ctx {
	struct perf_callchain_entry *entry;
	u32 max_stack;
	u32 nr;
	short int contexts;
	bool contexts_maxed;
};

struct perf_pmu_events_attr {
	struct device_attribute attr;
	u64 id;
	const char *event_str;
};

struct perf_pmu_events_ht_attr {
	struct device_attribute attr;
	u64 id;
	const char *event_str_ht;
	const char *event_str_noht;
};

struct perf_pmu_events_hybrid_attr {
	struct device_attribute attr;
	u64 id;
	const char *event_str;
	u64 pmu_type;
};

struct apic {
	void (*eoi_write)(u32, u32);
	void (*native_eoi_write)(u32, u32);
	void (*write)(u32, u32);
	u32 (*read)(u32);
	void (*wait_icr_idle)();
	u32 (*safe_wait_icr_idle)();
	void (*send_IPI)(int, int);
	void (*send_IPI_mask)(const struct cpumask *, int);
	void (*send_IPI_mask_allbutself)(const struct cpumask *, int);
	void (*send_IPI_allbutself)(int);
	void (*send_IPI_all)(int);
	void (*send_IPI_self)(int);
	u32 disable_esr;
	enum apic_delivery_modes delivery_mode;
	bool dest_mode_logical;
	u32 (*calc_dest_apicid)(unsigned int);
	u64 (*icr_read)();
	void (*icr_write)(u32, u32);
	int (*probe)();
	int (*acpi_madt_oem_check)(char *, char *);
	int (*apic_id_valid)(u32);
	int (*apic_id_registered)();
	bool (*check_apicid_used)(physid_mask_t *, int);
	void (*init_apic_ldr)();
	void (*ioapic_phys_id_map)(physid_mask_t *, physid_mask_t *);
	void (*setup_apic_routing)();
	int (*cpu_present_to_apicid)(int);
	void (*apicid_to_cpu_present)(int, physid_mask_t *);
	int (*check_phys_apicid_present)(int);
	int (*phys_pkg_id)(int, int);
	u32 (*get_apic_id)(long unsigned int);
	u32 (*set_apic_id)(unsigned int);
	int (*wakeup_secondary_cpu)(int, long unsigned int);
	int (*wakeup_secondary_cpu_64)(int, long unsigned int);
	void (*inquire_remote_apic)(int);
	char *name;
};

enum {
	NMI_LOCAL = 0,
	NMI_UNKNOWN = 1,
	NMI_SERR = 2,
	NMI_IO_CHECK = 3,
	NMI_MAX = 4,
};

typedef int (*nmi_handler_t)(unsigned int, struct pt_regs *);

struct nmiaction {
	struct list_head list;
	nmi_handler_t handler;
	u64 max_duration;
	long unsigned int flags;
	const char *name;
};

struct gdt_page {
	struct desc_struct gdt[16];
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
	long: 64;
};

struct cyc2ns_data {
	u32 cyc2ns_mul;
	u32 cyc2ns_shift;
	u64 cyc2ns_offset;
};

struct unwind_state {
	struct stack_info stack_info;
	long unsigned int stack_mask;
	struct task_struct *task;
	int graph_idx;
	struct llist_node *kr_cur;
	bool error;
	bool got_irq;
	long unsigned int *bp;
	long unsigned int *orig_sp;
	long unsigned int ip;
	long unsigned int *next_bp;
	struct pt_regs *regs;
};

enum extra_reg_type {
	EXTRA_REG_NONE = 4294967295,
	EXTRA_REG_RSP_0 = 0,
	EXTRA_REG_RSP_1 = 1,
	EXTRA_REG_LBR = 2,
	EXTRA_REG_LDLAT = 3,
	EXTRA_REG_FE = 4,
	EXTRA_REG_MAX = 5,
};

struct event_constraint {
	union {
		long unsigned int idxmsk[1];
		u64 idxmsk64;
	};
	u64 code;
	u64 cmask;
	int weight;
	int overlap;
	int flags;
	unsigned int size;
};

struct amd_nb {
	int nb_id;
	int refcnt;
	struct perf_event *owners[64];
	struct event_constraint event_constraints[64];
};

struct er_account {
	raw_spinlock_t lock;
	u64 config;
	u64 reg;
	atomic_t ref;
};

struct intel_shared_regs {
	struct er_account regs[5];
	int refcnt;
	unsigned int core_id;
};

enum intel_excl_state_type {
	INTEL_EXCL_UNUSED = 0,
	INTEL_EXCL_SHARED = 1,
	INTEL_EXCL_EXCLUSIVE = 2,
};

struct intel_excl_states {
	enum intel_excl_state_type state[64];
	bool sched_started;
};

struct intel_excl_cntrs {
	raw_spinlock_t lock;
	struct intel_excl_states states[2];
	union {
		u16 has_exclusive[2];
		u32 exclusive_present;
	};
	int refcnt;
	unsigned int core_id;
};

enum {
	X86_PERF_KFREE_SHARED = 0,
	X86_PERF_KFREE_EXCL = 1,
	X86_PERF_KFREE_MAX = 2,
};

struct cpu_hw_events {
	struct perf_event *events[64];
	long unsigned int active_mask[1];
	long unsigned int dirty[1];
	int enabled;
	int n_events;
	int n_added;
	int n_txn;
	int n_txn_pair;
	int n_txn_metric;
	int assign[64];
	u64 tags[64];
	struct perf_event *event_list[64];
	struct event_constraint *event_constraint[64];
	int n_excl;
	unsigned int txn_flags;
	int is_fake;
	struct debug_store *ds;
	void *ds_pebs_vaddr;
	void *ds_bts_vaddr;
	u64 pebs_enabled;
	int n_pebs;
	int n_large_pebs;
	int n_pebs_via_pt;
	int pebs_output;
	u64 pebs_data_cfg;
	u64 active_pebs_data_cfg;
	int pebs_record_size;
	int lbr_users;
	int lbr_pebs_users;
	struct perf_branch_stack lbr_stack;
	struct perf_branch_entry lbr_entries[32];
	union {
		struct er_account *lbr_sel;
		struct er_account *lbr_ctl;
	};
	u64 br_sel;
	void *last_task_ctx;
	int last_log_id;
	int lbr_select;
	void *lbr_xsave;
	u64 intel_ctrl_guest_mask;
	u64 intel_ctrl_host_mask;
	struct perf_guest_switch_msr guest_switch_msrs[64];
	u64 intel_cp_status;
	struct intel_shared_regs *shared_regs;
	struct event_constraint *constraint_list;
	struct intel_excl_cntrs *excl_cntrs;
	int excl_thread_id;
	u64 tfa_shadow;
	int n_metric;
	struct amd_nb *amd_nb;
	int brs_active;
	u64 perf_ctr_virt_mask;
	int n_pair;
	void *kfree_on_online[2];
	struct pmu *pmu;
};

struct extra_reg {
	unsigned int event;
	unsigned int msr;
	u64 config_mask;
	u64 valid_mask;
	int idx;
	bool extra_msr_access;
};

union perf_capabilities {
	struct {
		u64 lbr_format: 6;
		u64 pebs_trap: 1;
		u64 pebs_arch_reg: 1;
		u64 pebs_format: 4;
		u64 smm_freeze: 1;
		u64 full_width_write: 1;
		u64 pebs_baseline: 1;
		u64 perf_metrics: 1;
		u64 pebs_output_pt_available: 1;
		u64 anythread_deprecated: 1;
	};
	u64 capabilities;
};

struct x86_pmu_quirk {
	struct x86_pmu_quirk *next;
	void (*func)();
};

enum {
	x86_lbr_exclusive_lbr = 0,
	x86_lbr_exclusive_bts = 1,
	x86_lbr_exclusive_pt = 2,
	x86_lbr_exclusive_max = 3,
};

struct x86_hybrid_pmu {
	struct pmu pmu;
	const char *name;
	u8 cpu_type;
	cpumask_t supported_cpus;
	union perf_capabilities intel_cap;
	u64 intel_ctrl;
	int max_pebs_events;
	int num_counters;
	int num_counters_fixed;
	struct event_constraint unconstrained;
	u64 hw_cache_event_ids[42];
	u64 hw_cache_extra_regs[42];
	struct event_constraint *event_constraints;
	struct event_constraint *pebs_constraints;
	struct extra_reg *extra_regs;
	unsigned int late_ack: 1;
	unsigned int mid_ack: 1;
	unsigned int enabled_ack: 1;
};

enum hybrid_pmu_type {
	hybrid_big = 64,
	hybrid_small = 32,
	hybrid_big_small = 96,
};

struct x86_pmu {
	const char *name;
	int version;
	int (*handle_irq)(struct pt_regs *);
	void (*disable_all)();
	void (*enable_all)(int);
	void (*enable)(struct perf_event *);
	void (*disable)(struct perf_event *);
	void (*assign)(struct perf_event *, int);
	void (*add)(struct perf_event *);
	void (*del)(struct perf_event *);
	void (*read)(struct perf_event *);
	int (*hw_config)(struct perf_event *);
	int (*schedule_events)(struct cpu_hw_events *, int, int *);
	unsigned int eventsel;
	unsigned int perfctr;
	int (*addr_offset)(int, bool);
	int (*rdpmc_index)(int);
	u64 (*event_map)(int);
	int max_events;
	int num_counters;
	int num_counters_fixed;
	int cntval_bits;
	u64 cntval_mask;
	union {
		long unsigned int events_maskl;
		long unsigned int events_mask[1];
	};
	int events_mask_len;
	int apic;
	u64 max_period;
	struct event_constraint * (*get_event_constraints)(struct cpu_hw_events *, int, struct perf_event *);
	void (*put_event_constraints)(struct cpu_hw_events *, struct perf_event *);
	void (*start_scheduling)(struct cpu_hw_events *);
	void (*commit_scheduling)(struct cpu_hw_events *, int, int);
	void (*stop_scheduling)(struct cpu_hw_events *);
	struct event_constraint *event_constraints;
	struct x86_pmu_quirk *quirks;
	int perfctr_second_write;
	u64 (*limit_period)(struct perf_event *, u64);
	unsigned int late_ack: 1;
	unsigned int mid_ack: 1;
	unsigned int enabled_ack: 1;
	int attr_rdpmc_broken;
	int attr_rdpmc;
	struct attribute **format_attrs;
	ssize_t (*events_sysfs_show)(char *, u64);
	const struct attribute_group **attr_update;
	long unsigned int attr_freeze_on_smi;
	int (*cpu_prepare)(int);
	void (*cpu_starting)(int);
	void (*cpu_dying)(int);
	void (*cpu_dead)(int);
	void (*check_microcode)();
	void (*sched_task)(struct perf_event_context *, bool);
	u64 intel_ctrl;
	union perf_capabilities intel_cap;
	unsigned int bts: 1;
	unsigned int bts_active: 1;
	unsigned int pebs: 1;
	unsigned int pebs_active: 1;
	unsigned int pebs_broken: 1;
	unsigned int pebs_prec_dist: 1;
	unsigned int pebs_no_tlb: 1;
	unsigned int pebs_no_isolation: 1;
	unsigned int pebs_block: 1;
	int pebs_record_size;
	int pebs_buffer_size;
	int max_pebs_events;
	void (*drain_pebs)(struct pt_regs *, struct perf_sample_data *);
	struct event_constraint *pebs_constraints;
	void (*pebs_aliases)(struct perf_event *);
	long unsigned int large_pebs_flags;
	u64 rtm_abort_event;
	unsigned int lbr_tos;
	unsigned int lbr_from;
	unsigned int lbr_to;
	unsigned int lbr_info;
	unsigned int lbr_nr;
	union {
		u64 lbr_sel_mask;
		u64 lbr_ctl_mask;
	};
	union {
		const int *lbr_sel_map;
		int *lbr_ctl_map;
	};
	bool lbr_double_abort;
	bool lbr_pt_coexist;
	unsigned int lbr_has_info: 1;
	unsigned int lbr_has_tsx: 1;
	unsigned int lbr_from_flags: 1;
	unsigned int lbr_to_cycles: 1;
	unsigned int lbr_depth_mask: 8;
	unsigned int lbr_deep_c_reset: 1;
	unsigned int lbr_lip: 1;
	unsigned int lbr_cpl: 1;
	unsigned int lbr_filter: 1;
	unsigned int lbr_call_stack: 1;
	unsigned int lbr_mispred: 1;
	unsigned int lbr_timed_lbr: 1;
	unsigned int lbr_br_type: 1;
	void (*lbr_reset)();
	void (*lbr_read)(struct cpu_hw_events *);
	void (*lbr_save)(void *);
	void (*lbr_restore)(void *);
	atomic_t lbr_exclusive[3];
	int num_topdown_events;
	u64 (*update_topdown_event)(struct perf_event *);
	int (*set_topdown_event_period)(struct perf_event *);
	void (*swap_task_ctx)(struct perf_event_context *, struct perf_event_context *);
	unsigned int amd_nb_constraints: 1;
	u64 perf_ctr_pair_en;
	struct extra_reg *extra_regs;
	unsigned int flags;
	struct perf_guest_switch_msr * (*guest_get_msrs)(int *);
	int (*check_period)(struct perf_event *, u64);
	int (*aux_output_match)(struct perf_event *);
	int (*filter_match)(struct perf_event *);
	int num_hybrid_pmus;
	struct x86_hybrid_pmu *hybrid_pmu;
	u8 (*get_hybrid_cpu_type)();
};

struct sched_state {
	int weight;
	int event;
	int counter;
	int unassigned;
	int nr_gp;
	u64 used;
};

struct perf_sched {
	int max_weight;
	int max_events;
	int max_gp;
	int saved_states;
	struct event_constraint **constraints;
	struct sched_state state;
	struct sched_state saved[2];
};

struct perf_msr {
	u64 msr;
	struct attribute_group *grp;
	bool (*test)(int, void *);
	bool no_check;
	u64 mask;
};

union cpuid_0x80000022_ebx {
	struct {
		unsigned int num_core_pmc: 4;
	} split;
	unsigned int full;
};

struct pci_device_id {
	__u32 vendor;
	__u32 device;
	__u32 subvendor;
	__u32 subdevice;
	__u32 class;
	__u32 class_mask;
	kernel_ulong_t driver_data;
	__u32 override_only;
};

struct pci_bus;

struct hotplug_slot;

struct pci_slot {
	struct pci_bus *bus;
	struct list_head list;
	struct hotplug_slot *hotplug;
	unsigned char number;
	struct kobject kobj;
};

typedef short unsigned int pci_bus_flags_t;

struct pci_dev;

struct pci_ops;

struct pci_bus {
	struct list_head node;
	struct pci_bus *parent;
	struct list_head children;
	struct list_head devices;
	struct pci_dev *self;
	struct list_head slots;
	struct resource *resource[4];
	struct list_head resources;
	struct resource busn_res;
	struct pci_ops *ops;
	void *sysdata;
	struct proc_dir_entry *procdir;
	unsigned char number;
	unsigned char primary;
	unsigned char max_bus_speed;
	unsigned char cur_bus_speed;
	char name[48];
	short unsigned int bridge_ctl;
	pci_bus_flags_t bus_flags;
	struct device *bridge;
	struct device dev;
	struct bin_attribute *legacy_io;
	struct bin_attribute *legacy_mem;
	unsigned int is_added: 1;
	unsigned int unsafe_warn: 1;
};

enum {
	PCI_STD_RESOURCES = 0,
	PCI_STD_RESOURCE_END = 5,
	PCI_ROM_RESOURCE = 6,
	PCI_IOV_RESOURCES = 7,
	PCI_IOV_RESOURCE_END = 12,
	PCI_BRIDGE_RESOURCES = 13,
	PCI_BRIDGE_RESOURCE_END = 16,
	PCI_NUM_RESOURCES = 17,
	DEVICE_COUNT_RESOURCE = 17,
};

typedef int pci_power_t;

typedef unsigned int pci_channel_state_t;

typedef unsigned int pcie_reset_state_t;

typedef short unsigned int pci_dev_flags_t;

struct pci_vpd {
	struct mutex lock;
	unsigned int len;
	u8 cap;
};

struct aer_stats;

struct rcec_ea;

struct pci_driver;

struct pcie_link_state;

struct pci_sriov;

struct pci_dev {
	struct list_head bus_list;
	struct pci_bus *bus;
	struct pci_bus *subordinate;
	void *sysdata;
	struct proc_dir_entry *procent;
	struct pci_slot *slot;
	unsigned int devfn;
	short unsigned int vendor;
	short unsigned int device;
	short unsigned int subsystem_vendor;
	short unsigned int subsystem_device;
	unsigned int class;
	u8 revision;
	u8 hdr_type;
	u16 aer_cap;
	struct aer_stats *aer_stats;
	struct rcec_ea *rcec_ea;
	struct pci_dev *rcec;
	u32 devcap;
	u8 pcie_cap;
	u8 msi_cap;
	u8 msix_cap;
	u8 pcie_mpss: 3;
	u8 rom_base_reg;
	u8 pin;
	u16 pcie_flags_reg;
	long unsigned int *dma_alias_mask;
	struct pci_driver *driver;
	u64 dma_mask;
	struct device_dma_parameters dma_parms;
	pci_power_t current_state;
	unsigned int imm_ready: 1;
	u8 pm_cap;
	unsigned int pme_support: 5;
	unsigned int pme_poll: 1;
	unsigned int d1_support: 1;
	unsigned int d2_support: 1;
	unsigned int no_d1d2: 1;
	unsigned int no_d3cold: 1;
	unsigned int bridge_d3: 1;
	unsigned int d3cold_allowed: 1;
	unsigned int mmio_always_on: 1;
	unsigned int wakeup_prepared: 1;
	unsigned int skip_bus_pm: 1;
	unsigned int ignore_hotplug: 1;
	unsigned int hotplug_user_indicators: 1;
	unsigned int clear_retrain_link: 1;
	unsigned int d3hot_delay;
	unsigned int d3cold_delay;
	struct pcie_link_state *link_state;
	unsigned int ltr_path: 1;
	u16 l1ss;
	unsigned int pasid_no_tlp: 1;
	unsigned int eetlp_prefix_path: 1;
	pci_channel_state_t error_state;
	struct device dev;
	int cfg_size;
	unsigned int irq;
	struct resource resource[17];
	bool match_driver;
	unsigned int transparent: 1;
	unsigned int io_window: 1;
	unsigned int pref_window: 1;
	unsigned int pref_64_window: 1;
	unsigned int multifunction: 1;
	unsigned int is_busmaster: 1;
	unsigned int no_msi: 1;
	unsigned int no_64bit_msi: 1;
	unsigned int block_cfg_access: 1;
	unsigned int broken_parity_status: 1;
	unsigned int irq_reroute_variant: 2;
	unsigned int msi_enabled: 1;
	unsigned int msix_enabled: 1;
	unsigned int ari_enabled: 1;
	unsigned int ats_enabled: 1;
	unsigned int pasid_enabled: 1;
	unsigned int pri_enabled: 1;
	unsigned int is_managed: 1;
	unsigned int is_msi_managed: 1;
	unsigned int needs_freset: 1;
	unsigned int state_saved: 1;
	unsigned int is_physfn: 1;
	unsigned int is_virtfn: 1;
	unsigned int is_hotplug_bridge: 1;
	unsigned int shpc_managed: 1;
	unsigned int is_thunderbolt: 1;
	unsigned int untrusted: 1;
	unsigned int external_facing: 1;
	unsigned int broken_intx_masking: 1;
	unsigned int io_window_1k: 1;
	unsigned int irq_managed: 1;
	unsigned int non_compliant_bars: 1;
	unsigned int is_probed: 1;
	unsigned int link_active_reporting: 1;
	unsigned int no_vf_scan: 1;
	unsigned int no_command_memory: 1;
	unsigned int rom_bar_overlap: 1;
	pci_dev_flags_t dev_flags;
	atomic_t enable_cnt;
	u32 saved_config_space[16];
	struct hlist_head saved_cap_space;
	int rom_attr_enabled;
	struct bin_attribute *res_attr[17];
	struct bin_attribute *res_attr_wc[17];
	unsigned int broken_cmd_compl: 1;
	unsigned int ptm_root: 1;
	unsigned int ptm_enabled: 1;
	u8 ptm_granularity;
	void *msix_base;
	raw_spinlock_t msi_lock;
	struct pci_vpd vpd;
	u16 dpc_cap;
	unsigned int dpc_rp_extensions: 1;
	u8 dpc_rp_log_size;
	union {
		struct pci_sriov *sriov;
		struct pci_dev *physfn;
	};
	u16 ats_cap;
	u8 ats_stu;
	u16 pri_cap;
	u32 pri_reqs_alloc;
	unsigned int pasid_required: 1;
	u16 pasid_cap;
	u16 pasid_features;
	u16 acs_cap;
	phys_addr_t rom;
	size_t romlen;
	const char *driver_override;
	long unsigned int priv_flags;
	u8 reset_methods[7];
};

struct pci_dynids {
	spinlock_t lock;
	struct list_head list;
};

struct pci_error_handlers;

struct pci_driver {
	struct list_head node;
	const char *name;
	const struct pci_device_id *id_table;
	int (*probe)(struct pci_dev *, const struct pci_device_id *);
	void (*remove)(struct pci_dev *);
	int (*suspend)(struct pci_dev *, pm_message_t);
	int (*resume)(struct pci_dev *);
	void (*shutdown)(struct pci_dev *);
	int (*sriov_configure)(struct pci_dev *, int);
	int (*sriov_set_msix_vec_count)(struct pci_dev *, int);
	u32 (*sriov_get_vf_total_msix)(struct pci_dev *);
	const struct pci_error_handlers *err_handler;
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	struct device_driver driver;
	struct pci_dynids dynids;
	bool driver_managed_dma;
};

struct pci_ops {
	int (*add_bus)(struct pci_bus *);
	void (*remove_bus)(struct pci_bus *);
	void * (*map_bus)(struct pci_bus *, unsigned int, int);
	int (*read)(struct pci_bus *, unsigned int, int, int, u32 *);
	int (*write)(struct pci_bus *, unsigned int, int, int, u32);
};

typedef unsigned int pci_ers_result_t;

struct pci_error_handlers {
	pci_ers_result_t (*error_detected)(struct pci_dev *, pci_channel_state_t);
	pci_ers_result_t (*mmio_enabled)(struct pci_dev *);
	pci_ers_result_t (*slot_reset)(struct pci_dev *);
	void (*reset_prepare)(struct pci_dev *);
	void (*reset_done)(struct pci_dev *);
	void (*resume)(struct pci_dev *);
};

struct syscore_ops {
	struct list_head node;
	int (*suspend)();
	void (*resume)();
	void (*shutdown)();
};

union ibs_fetch_ctl {
	__u64 val;
	struct {
		__u64 fetch_maxcnt: 16;
		__u64 fetch_cnt: 16;
		__u64 fetch_lat: 16;
		__u64 fetch_en: 1;
		__u64 fetch_val: 1;
		__u64 fetch_comp: 1;
		__u64 ic_miss: 1;
		__u64 phy_addr_valid: 1;
		__u64 l1tlb_pgsz: 2;
		__u64 l1tlb_miss: 1;
		__u64 l2tlb_miss: 1;
		__u64 rand_en: 1;
		__u64 fetch_l2_miss: 1;
		__u64 reserved: 5;
	};
};

union ibs_op_ctl {
	__u64 val;
	struct {
		__u64 opmaxcnt: 16;
		__u64 reserved0: 1;
		__u64 op_en: 1;
		__u64 op_val: 1;
		__u64 cnt_ctl: 1;
		__u64 opmaxcnt_ext: 7;
		__u64 reserved1: 5;
		__u64 opcurcnt: 27;
		__u64 reserved2: 5;
	};
};

struct perf_ibs_data {
	u32 size;
	union {
		u32 data[0];
		u32 caps;
	};
	u64 regs[8];
};

enum ibs_states {
	IBS_ENABLED = 0,
	IBS_STARTED = 1,
	IBS_STOPPING = 2,
	IBS_STOPPED = 3,
	IBS_MAX_STATES = 4,
};

struct cpu_perf_ibs {
	struct perf_event *event;
	long unsigned int state[1];
};

struct perf_ibs {
	struct pmu pmu;
	unsigned int msr;
	u64 config_mask;
	u64 cnt_mask;
	u64 enable_mask;
	u64 valid_mask;
	u64 max_period;
	long unsigned int offset_mask[1];
	int offset_max;
	unsigned int fetch_count_reset_broken: 1;
	unsigned int fetch_ignore_if_zero_rip: 1;
	struct cpu_perf_ibs *pcpu;
	u64 (*get_count)(u64);
};

typedef void (*exitcall_t)();

struct amd_uncore {
	int id;
	int refcnt;
	int cpu;
	int num_counters;
	int rdpmc_base;
	u32 msr_base;
	cpumask_t *active_mask;
	struct pmu *pmu;
	struct perf_event *events[6];
	struct hlist_node node;
};

struct amd_iommu;

struct perf_amd_iommu {
	struct list_head list;
	struct pmu pmu;
	struct amd_iommu *iommu;
	char name[16];
	u8 max_banks;
	u8 max_counters;
	u64 cntr_assign_mask;
	raw_spinlock_t lock;
};

struct amd_iommu_event_desc {
	struct device_attribute attr;
	const char *event;
};

enum perf_msr_id {
	PERF_MSR_TSC = 0,
	PERF_MSR_APERF = 1,
	PERF_MSR_MPERF = 2,
	PERF_MSR_PPERF = 3,
	PERF_MSR_SMI = 4,
	PERF_MSR_PTSC = 5,
	PERF_MSR_IRPERF = 6,
	PERF_MSR_THERM = 7,
	PERF_MSR_EVENT_MAX = 8,
};

struct x86_cpu_desc {
	u8 x86_family;
	u8 x86_vendor;
	u8 x86_model;
	u8 x86_stepping;
	u32 x86_microcode_rev;
};

union cpuid10_eax {
	struct {
		unsigned int version_id: 8;
		unsigned int num_counters: 8;
		unsigned int bit_width: 8;
		unsigned int mask_length: 8;
	} split;
	unsigned int full;
};

union cpuid10_ebx {
	struct {
		unsigned int no_unhalted_core_cycles: 1;
		unsigned int no_instructions_retired: 1;
		unsigned int no_unhalted_reference_cycles: 1;
		unsigned int no_llc_reference: 1;
		unsigned int no_llc_misses: 1;
		unsigned int no_branch_instruction_retired: 1;
		unsigned int no_branch_misses_retired: 1;
	} split;
	unsigned int full;
};

union cpuid10_edx {
	struct {
		unsigned int num_counters_fixed: 5;
		unsigned int bit_width_fixed: 8;
		unsigned int reserved1: 2;
		unsigned int anythread_deprecated: 1;
		unsigned int reserved2: 16;
	} split;
	unsigned int full;
};

struct perf_pmu_format_hybrid_attr {
	struct device_attribute attr;
	u64 pmu_type;
};

typedef int perf_snapshot_branch_stack_t(struct perf_branch_entry *, unsigned int);

enum {
	LBR_FORMAT_32 = 0,
	LBR_FORMAT_LIP = 1,
	LBR_FORMAT_EIP = 2,
	LBR_FORMAT_EIP_FLAGS = 3,
	LBR_FORMAT_EIP_FLAGS2 = 4,
	LBR_FORMAT_INFO = 5,
	LBR_FORMAT_TIME = 6,
	LBR_FORMAT_INFO2 = 7,
	LBR_FORMAT_MAX_KNOWN = 7,
};

union x86_pmu_config {
	struct {
		u64 event: 8;
		u64 umask: 8;
		u64 usr: 1;
		u64 os: 1;
		u64 edge: 1;
		u64 pc: 1;
		u64 interrupt: 1;
		u64 __reserved1: 1;
		u64 en: 1;
		u64 inv: 1;
		u64 cmask: 8;
		u64 event2: 4;
		u64 __reserved2: 4;
		u64 go: 1;
		u64 ho: 1;
	} bits;
	u64 value;
};

struct bts_ctx {
	struct perf_output_handle handle;
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
	struct debug_store ds_back;
	int state;
	long: 32;
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
	long: 64;
};

enum {
	BTS_STATE_STOPPED = 0,
	BTS_STATE_INACTIVE = 1,
	BTS_STATE_ACTIVE = 2,
};

struct bts_phys {
	struct page *page;
	long unsigned int size;
	long unsigned int offset;
	long unsigned int displacement;
};

struct bts_buffer {
	size_t real_size;
	unsigned int nr_pages;
	unsigned int nr_bufs;
	unsigned int cur_buf;
	bool snapshot;
	local_t data_size;
	local_t head;
	long unsigned int end;
	void **data_pages;
	struct bts_phys buf[0];
};

struct lbr_entry {
	u64 from;
	u64 to;
	u64 info;
};

struct pebs_basic {
	u64 format_size;
	u64 ip;
	u64 applicable_counters;
	u64 tsc;
};

struct pebs_meminfo {
	u64 address;
	u64 aux;
	u64 latency;
	u64 tsx_tuning;
};

struct pebs_gprs {
	u64 flags;
	u64 ip;
	u64 ax;
	u64 cx;
	u64 dx;
	u64 bx;
	u64 sp;
	u64 bp;
	u64 si;
	u64 di;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

struct pebs_xmm {
	u64 xmm[32];
};

struct x86_perf_regs {
	struct pt_regs regs;
	u64 *xmm_regs;
};

typedef unsigned int insn_attr_t;

typedef unsigned char insn_byte_t;

typedef int insn_value_t;

struct insn_field {
	union {
		insn_value_t value;
		insn_byte_t bytes[4];
	};
	unsigned char got;
	unsigned char nbytes;
};

struct insn {
	struct insn_field prefixes;
	struct insn_field rex_prefix;
	struct insn_field vex_prefix;
	struct insn_field opcode;
	struct insn_field modrm;
	struct insn_field sib;
	struct insn_field displacement;
	union {
		struct insn_field immediate;
		struct insn_field moffset1;
		struct insn_field immediate1;
	};
	union {
		struct insn_field moffset2;
		struct insn_field immediate2;
	};
	int emulate_prefix_size;
	insn_attr_t attr;
	unsigned char opnd_bytes;
	unsigned char addr_bytes;
	unsigned char length;
	unsigned char x86_64;
	const insn_byte_t *kaddr;
	const insn_byte_t *end_kaddr;
	const insn_byte_t *next_byte;
};

enum {
	PERF_TXN_ELISION = 1,
	PERF_TXN_TRANSACTION = 2,
	PERF_TXN_SYNC = 4,
	PERF_TXN_ASYNC = 8,
	PERF_TXN_RETRY = 16,
	PERF_TXN_CONFLICT = 32,
	PERF_TXN_CAPACITY_WRITE = 64,
	PERF_TXN_CAPACITY_READ = 128,
	PERF_TXN_MAX = 256,
	PERF_TXN_ABORT_MASK = 0,
	PERF_TXN_ABORT_SHIFT = 32,
};

struct perf_event_header {
	__u32 type;
	__u16 misc;
	__u16 size;
};

union intel_x86_pebs_dse {
	u64 val;
	struct {
		unsigned int ld_dse: 4;
		unsigned int ld_stlb_miss: 1;
		unsigned int ld_locked: 1;
		unsigned int ld_data_blk: 1;
		unsigned int ld_addr_blk: 1;
		unsigned int ld_reserved: 24;
	};
	struct {
		unsigned int st_l1d_hit: 1;
		unsigned int st_reserved1: 3;
		unsigned int st_stlb_miss: 1;
		unsigned int st_locked: 1;
		unsigned int st_reserved2: 26;
	};
	struct {
		unsigned int st_lat_dse: 4;
		unsigned int st_lat_stlb_miss: 1;
		unsigned int st_lat_locked: 1;
		unsigned int ld_reserved3: 26;
	};
};

struct pebs_record_core {
	u64 flags;
	u64 ip;
	u64 ax;
	u64 bx;
	u64 cx;
	u64 dx;
	u64 si;
	u64 di;
	u64 bp;
	u64 sp;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

struct pebs_record_nhm {
	u64 flags;
	u64 ip;
	u64 ax;
	u64 bx;
	u64 cx;
	u64 dx;
	u64 si;
	u64 di;
	u64 bp;
	u64 sp;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 status;
	u64 dla;
	u64 dse;
	u64 lat;
};

union hsw_tsx_tuning {
	struct {
		u32 cycles_last_block: 32;
		u32 hle_abort: 1;
		u32 rtm_abort: 1;
		u32 instruction_abort: 1;
		u32 non_instruction_abort: 1;
		u32 retry: 1;
		u32 data_conflict: 1;
		u32 capacity_writes: 1;
		u32 capacity_reads: 1;
	};
	u64 value;
};

struct pebs_record_skl {
	u64 flags;
	u64 ip;
	u64 ax;
	u64 bx;
	u64 cx;
	u64 dx;
	u64 si;
	u64 di;
	u64 bp;
	u64 sp;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 status;
	u64 dla;
	u64 dse;
	u64 lat;
	u64 real_ip;
	u64 tsx_tuning;
	u64 tsc;
};

struct bts_record {
	u64 from;
	u64 to;
	u64 flags;
};

enum {
	PERF_BR_UNKNOWN = 0,
	PERF_BR_COND = 1,
	PERF_BR_UNCOND = 2,
	PERF_BR_IND = 3,
	PERF_BR_CALL = 4,
	PERF_BR_IND_CALL = 5,
	PERF_BR_RET = 6,
	PERF_BR_SYSCALL = 7,
	PERF_BR_SYSRET = 8,
	PERF_BR_COND_CALL = 9,
	PERF_BR_COND_RET = 10,
	PERF_BR_ERET = 11,
	PERF_BR_IRQ = 12,
	PERF_BR_MAX = 13,
};

enum xfeature {
	XFEATURE_FP = 0,
	XFEATURE_SSE = 1,
	XFEATURE_YMM = 2,
	XFEATURE_BNDREGS = 3,
	XFEATURE_BNDCSR = 4,
	XFEATURE_OPMASK = 5,
	XFEATURE_ZMM_Hi256 = 6,
	XFEATURE_Hi16_ZMM = 7,
	XFEATURE_PT_UNIMPLEMENTED_SO_FAR = 8,
	XFEATURE_PKRU = 9,
	XFEATURE_PASID = 10,
	XFEATURE_RSRVD_COMP_11 = 11,
	XFEATURE_RSRVD_COMP_12 = 12,
	XFEATURE_RSRVD_COMP_13 = 13,
	XFEATURE_RSRVD_COMP_14 = 14,
	XFEATURE_LBR = 15,
	XFEATURE_RSRVD_COMP_16 = 16,
	XFEATURE_XTILE_CFG = 17,
	XFEATURE_XTILE_DATA = 18,
	XFEATURE_MAX = 19,
};

struct arch_lbr_state {
	u64 lbr_ctl;
	u64 lbr_depth;
	u64 ler_from;
	u64 ler_to;
	u64 ler_info;
	struct lbr_entry entries[0];
};

union cpuid28_eax {
	struct {
		unsigned int lbr_depth_mask: 8;
		unsigned int reserved: 22;
		unsigned int lbr_deep_c_reset: 1;
		unsigned int lbr_lip: 1;
	} split;
	unsigned int full;
};

union cpuid28_ebx {
	struct {
		unsigned int lbr_cpl: 1;
		unsigned int lbr_filter: 1;
		unsigned int lbr_call_stack: 1;
	} split;
	unsigned int full;
};

union cpuid28_ecx {
	struct {
		unsigned int lbr_mispred: 1;
		unsigned int lbr_timed_lbr: 1;
		unsigned int lbr_br_type: 1;
	} split;
	unsigned int full;
};

struct x86_pmu_lbr {
	unsigned int nr;
	unsigned int from;
	unsigned int to;
	unsigned int info;
};

struct x86_perf_task_context_opt {
	int lbr_callstack_users;
	int lbr_stack_state;
	int log_id;
};

struct x86_perf_task_context {
	u64 lbr_sel;
	int tos;
	int valid_lbrs;
	struct x86_perf_task_context_opt opt;
	struct lbr_entry lbr[32];
};

struct x86_perf_task_context_arch_lbr {
	struct x86_perf_task_context_opt opt;
	struct lbr_entry entries[0];
};

struct x86_perf_task_context_arch_lbr_xsave {
	struct x86_perf_task_context_opt opt;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	union {
		struct xregs_state xsave;
		struct {
			struct fxregs_state i387;
			struct xstate_header header;
			struct arch_lbr_state lbr;
			long: 64;
			long: 64;
			long: 64;
		};
	};
};

enum {
	X86_BR_NONE = 0,
	X86_BR_USER = 1,
	X86_BR_KERNEL = 2,
	X86_BR_CALL = 4,
	X86_BR_RET = 8,
	X86_BR_SYSCALL = 16,
	X86_BR_SYSRET = 32,
	X86_BR_INT = 64,
	X86_BR_IRET = 128,
	X86_BR_JCC = 256,
	X86_BR_JMP = 512,
	X86_BR_IRQ = 1024,
	X86_BR_IND_CALL = 2048,
	X86_BR_ABORT = 4096,
	X86_BR_IN_TX = 8192,
	X86_BR_NO_TX = 16384,
	X86_BR_ZERO_CALL = 32768,
	X86_BR_CALL_STACK = 65536,
	X86_BR_IND_JMP = 131072,
	X86_BR_TYPE_SAVE = 262144,
};

enum {
	LBR_NONE = 0,
	LBR_VALID = 1,
};

enum {
	ARCH_LBR_BR_TYPE_JCC = 0,
	ARCH_LBR_BR_TYPE_NEAR_IND_JMP = 1,
	ARCH_LBR_BR_TYPE_NEAR_REL_JMP = 2,
	ARCH_LBR_BR_TYPE_NEAR_IND_CALL = 3,
	ARCH_LBR_BR_TYPE_NEAR_REL_CALL = 4,
	ARCH_LBR_BR_TYPE_NEAR_RET = 5,
	ARCH_LBR_BR_TYPE_KNOWN_MAX = 5,
	ARCH_LBR_BR_TYPE_MAP_MAX = 16,
};

enum P4_EVENTS {
	P4_EVENT_TC_DELIVER_MODE = 0,
	P4_EVENT_BPU_FETCH_REQUEST = 1,
	P4_EVENT_ITLB_REFERENCE = 2,
	P4_EVENT_MEMORY_CANCEL = 3,
	P4_EVENT_MEMORY_COMPLETE = 4,
	P4_EVENT_LOAD_PORT_REPLAY = 5,
	P4_EVENT_STORE_PORT_REPLAY = 6,
	P4_EVENT_MOB_LOAD_REPLAY = 7,
	P4_EVENT_PAGE_WALK_TYPE = 8,
	P4_EVENT_BSQ_CACHE_REFERENCE = 9,
	P4_EVENT_IOQ_ALLOCATION = 10,
	P4_EVENT_IOQ_ACTIVE_ENTRIES = 11,
	P4_EVENT_FSB_DATA_ACTIVITY = 12,
	P4_EVENT_BSQ_ALLOCATION = 13,
	P4_EVENT_BSQ_ACTIVE_ENTRIES = 14,
	P4_EVENT_SSE_INPUT_ASSIST = 15,
	P4_EVENT_PACKED_SP_UOP = 16,
	P4_EVENT_PACKED_DP_UOP = 17,
	P4_EVENT_SCALAR_SP_UOP = 18,
	P4_EVENT_SCALAR_DP_UOP = 19,
	P4_EVENT_64BIT_MMX_UOP = 20,
	P4_EVENT_128BIT_MMX_UOP = 21,
	P4_EVENT_X87_FP_UOP = 22,
	P4_EVENT_TC_MISC = 23,
	P4_EVENT_GLOBAL_POWER_EVENTS = 24,
	P4_EVENT_TC_MS_XFER = 25,
	P4_EVENT_UOP_QUEUE_WRITES = 26,
	P4_EVENT_RETIRED_MISPRED_BRANCH_TYPE = 27,
	P4_EVENT_RETIRED_BRANCH_TYPE = 28,
	P4_EVENT_RESOURCE_STALL = 29,
	P4_EVENT_WC_BUFFER = 30,
	P4_EVENT_B2B_CYCLES = 31,
	P4_EVENT_BNR = 32,
	P4_EVENT_SNOOP = 33,
	P4_EVENT_RESPONSE = 34,
	P4_EVENT_FRONT_END_EVENT = 35,
	P4_EVENT_EXECUTION_EVENT = 36,
	P4_EVENT_REPLAY_EVENT = 37,
	P4_EVENT_INSTR_RETIRED = 38,
	P4_EVENT_UOPS_RETIRED = 39,
	P4_EVENT_UOP_TYPE = 40,
	P4_EVENT_BRANCH_RETIRED = 41,
	P4_EVENT_MISPRED_BRANCH_RETIRED = 42,
	P4_EVENT_X87_ASSIST = 43,
	P4_EVENT_MACHINE_CLEAR = 44,
	P4_EVENT_INSTR_COMPLETED = 45,
};

enum P4_EVENT_OPCODES {
	P4_EVENT_TC_DELIVER_MODE_OPCODE = 257,
	P4_EVENT_BPU_FETCH_REQUEST_OPCODE = 768,
	P4_EVENT_ITLB_REFERENCE_OPCODE = 6147,
	P4_EVENT_MEMORY_CANCEL_OPCODE = 517,
	P4_EVENT_MEMORY_COMPLETE_OPCODE = 2050,
	P4_EVENT_LOAD_PORT_REPLAY_OPCODE = 1026,
	P4_EVENT_STORE_PORT_REPLAY_OPCODE = 1282,
	P4_EVENT_MOB_LOAD_REPLAY_OPCODE = 770,
	P4_EVENT_PAGE_WALK_TYPE_OPCODE = 260,
	P4_EVENT_BSQ_CACHE_REFERENCE_OPCODE = 3079,
	P4_EVENT_IOQ_ALLOCATION_OPCODE = 774,
	P4_EVENT_IOQ_ACTIVE_ENTRIES_OPCODE = 6662,
	P4_EVENT_FSB_DATA_ACTIVITY_OPCODE = 5894,
	P4_EVENT_BSQ_ALLOCATION_OPCODE = 1287,
	P4_EVENT_BSQ_ACTIVE_ENTRIES_OPCODE = 1543,
	P4_EVENT_SSE_INPUT_ASSIST_OPCODE = 13313,
	P4_EVENT_PACKED_SP_UOP_OPCODE = 2049,
	P4_EVENT_PACKED_DP_UOP_OPCODE = 3073,
	P4_EVENT_SCALAR_SP_UOP_OPCODE = 2561,
	P4_EVENT_SCALAR_DP_UOP_OPCODE = 3585,
	P4_EVENT_64BIT_MMX_UOP_OPCODE = 513,
	P4_EVENT_128BIT_MMX_UOP_OPCODE = 6657,
	P4_EVENT_X87_FP_UOP_OPCODE = 1025,
	P4_EVENT_TC_MISC_OPCODE = 1537,
	P4_EVENT_GLOBAL_POWER_EVENTS_OPCODE = 4870,
	P4_EVENT_TC_MS_XFER_OPCODE = 1280,
	P4_EVENT_UOP_QUEUE_WRITES_OPCODE = 2304,
	P4_EVENT_RETIRED_MISPRED_BRANCH_TYPE_OPCODE = 1282,
	P4_EVENT_RETIRED_BRANCH_TYPE_OPCODE = 1026,
	P4_EVENT_RESOURCE_STALL_OPCODE = 257,
	P4_EVENT_WC_BUFFER_OPCODE = 1285,
	P4_EVENT_B2B_CYCLES_OPCODE = 5635,
	P4_EVENT_BNR_OPCODE = 2051,
	P4_EVENT_SNOOP_OPCODE = 1539,
	P4_EVENT_RESPONSE_OPCODE = 1027,
	P4_EVENT_FRONT_END_EVENT_OPCODE = 2053,
	P4_EVENT_EXECUTION_EVENT_OPCODE = 3077,
	P4_EVENT_REPLAY_EVENT_OPCODE = 2309,
	P4_EVENT_INSTR_RETIRED_OPCODE = 516,
	P4_EVENT_UOPS_RETIRED_OPCODE = 260,
	P4_EVENT_UOP_TYPE_OPCODE = 514,
	P4_EVENT_BRANCH_RETIRED_OPCODE = 1541,
	P4_EVENT_MISPRED_BRANCH_RETIRED_OPCODE = 772,
	P4_EVENT_X87_ASSIST_OPCODE = 773,
	P4_EVENT_MACHINE_CLEAR_OPCODE = 517,
	P4_EVENT_INSTR_COMPLETED_OPCODE = 1796,
};

enum P4_ESCR_EMASKS {
	P4_EVENT_TC_DELIVER_MODE__DD = 512,
	P4_EVENT_TC_DELIVER_MODE__DB = 1024,
	P4_EVENT_TC_DELIVER_MODE__DI = 2048,
	P4_EVENT_TC_DELIVER_MODE__BD = 4096,
	P4_EVENT_TC_DELIVER_MODE__BB = 8192,
	P4_EVENT_TC_DELIVER_MODE__BI = 16384,
	P4_EVENT_TC_DELIVER_MODE__ID = 32768,
	P4_EVENT_BPU_FETCH_REQUEST__TCMISS = 512,
	P4_EVENT_ITLB_REFERENCE__HIT = 512,
	P4_EVENT_ITLB_REFERENCE__MISS = 1024,
	P4_EVENT_ITLB_REFERENCE__HIT_UK = 2048,
	P4_EVENT_MEMORY_CANCEL__ST_RB_FULL = 2048,
	P4_EVENT_MEMORY_CANCEL__64K_CONF = 4096,
	P4_EVENT_MEMORY_COMPLETE__LSC = 512,
	P4_EVENT_MEMORY_COMPLETE__SSC = 1024,
	P4_EVENT_LOAD_PORT_REPLAY__SPLIT_LD = 1024,
	P4_EVENT_STORE_PORT_REPLAY__SPLIT_ST = 1024,
	P4_EVENT_MOB_LOAD_REPLAY__NO_STA = 1024,
	P4_EVENT_MOB_LOAD_REPLAY__NO_STD = 4096,
	P4_EVENT_MOB_LOAD_REPLAY__PARTIAL_DATA = 8192,
	P4_EVENT_MOB_LOAD_REPLAY__UNALGN_ADDR = 16384,
	P4_EVENT_PAGE_WALK_TYPE__DTMISS = 512,
	P4_EVENT_PAGE_WALK_TYPE__ITMISS = 1024,
	P4_EVENT_BSQ_CACHE_REFERENCE__RD_2ndL_HITS = 512,
	P4_EVENT_BSQ_CACHE_REFERENCE__RD_2ndL_HITE = 1024,
	P4_EVENT_BSQ_CACHE_REFERENCE__RD_2ndL_HITM = 2048,
	P4_EVENT_BSQ_CACHE_REFERENCE__RD_3rdL_HITS = 4096,
	P4_EVENT_BSQ_CACHE_REFERENCE__RD_3rdL_HITE = 8192,
	P4_EVENT_BSQ_CACHE_REFERENCE__RD_3rdL_HITM = 16384,
	P4_EVENT_BSQ_CACHE_REFERENCE__RD_2ndL_MISS = 131072,
	P4_EVENT_BSQ_CACHE_REFERENCE__RD_3rdL_MISS = 262144,
	P4_EVENT_BSQ_CACHE_REFERENCE__WR_2ndL_MISS = 524288,
	P4_EVENT_IOQ_ALLOCATION__DEFAULT = 512,
	P4_EVENT_IOQ_ALLOCATION__ALL_READ = 16384,
	P4_EVENT_IOQ_ALLOCATION__ALL_WRITE = 32768,
	P4_EVENT_IOQ_ALLOCATION__MEM_UC = 65536,
	P4_EVENT_IOQ_ALLOCATION__MEM_WC = 131072,
	P4_EVENT_IOQ_ALLOCATION__MEM_WT = 262144,
	P4_EVENT_IOQ_ALLOCATION__MEM_WP = 524288,
	P4_EVENT_IOQ_ALLOCATION__MEM_WB = 1048576,
	P4_EVENT_IOQ_ALLOCATION__OWN = 4194304,
	P4_EVENT_IOQ_ALLOCATION__OTHER = 8388608,
	P4_EVENT_IOQ_ALLOCATION__PREFETCH = 16777216,
	P4_EVENT_IOQ_ACTIVE_ENTRIES__DEFAULT = 512,
	P4_EVENT_IOQ_ACTIVE_ENTRIES__ALL_READ = 16384,
	P4_EVENT_IOQ_ACTIVE_ENTRIES__ALL_WRITE = 32768,
	P4_EVENT_IOQ_ACTIVE_ENTRIES__MEM_UC = 65536,
	P4_EVENT_IOQ_ACTIVE_ENTRIES__MEM_WC = 131072,
	P4_EVENT_IOQ_ACTIVE_ENTRIES__MEM_WT = 262144,
	P4_EVENT_IOQ_ACTIVE_ENTRIES__MEM_WP = 524288,
	P4_EVENT_IOQ_ACTIVE_ENTRIES__MEM_WB = 1048576,
	P4_EVENT_IOQ_ACTIVE_ENTRIES__OWN = 4194304,
	P4_EVENT_IOQ_ACTIVE_ENTRIES__OTHER = 8388608,
	P4_EVENT_IOQ_ACTIVE_ENTRIES__PREFETCH = 16777216,
	P4_EVENT_FSB_DATA_ACTIVITY__DRDY_DRV = 512,
	P4_EVENT_FSB_DATA_ACTIVITY__DRDY_OWN = 1024,
	P4_EVENT_FSB_DATA_ACTIVITY__DRDY_OTHER = 2048,
	P4_EVENT_FSB_DATA_ACTIVITY__DBSY_DRV = 4096,
	P4_EVENT_FSB_DATA_ACTIVITY__DBSY_OWN = 8192,
	P4_EVENT_FSB_DATA_ACTIVITY__DBSY_OTHER = 16384,
	P4_EVENT_BSQ_ALLOCATION__REQ_TYPE0 = 512,
	P4_EVENT_BSQ_ALLOCATION__REQ_TYPE1 = 1024,
	P4_EVENT_BSQ_ALLOCATION__REQ_LEN0 = 2048,
	P4_EVENT_BSQ_ALLOCATION__REQ_LEN1 = 4096,
	P4_EVENT_BSQ_ALLOCATION__REQ_IO_TYPE = 16384,
	P4_EVENT_BSQ_ALLOCATION__REQ_LOCK_TYPE = 32768,
	P4_EVENT_BSQ_ALLOCATION__REQ_CACHE_TYPE = 65536,
	P4_EVENT_BSQ_ALLOCATION__REQ_SPLIT_TYPE = 131072,
	P4_EVENT_BSQ_ALLOCATION__REQ_DEM_TYPE = 262144,
	P4_EVENT_BSQ_ALLOCATION__REQ_ORD_TYPE = 524288,
	P4_EVENT_BSQ_ALLOCATION__MEM_TYPE0 = 1048576,
	P4_EVENT_BSQ_ALLOCATION__MEM_TYPE1 = 2097152,
	P4_EVENT_BSQ_ALLOCATION__MEM_TYPE2 = 4194304,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__REQ_TYPE0 = 512,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__REQ_TYPE1 = 1024,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__REQ_LEN0 = 2048,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__REQ_LEN1 = 4096,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__REQ_IO_TYPE = 16384,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__REQ_LOCK_TYPE = 32768,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__REQ_CACHE_TYPE = 65536,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__REQ_SPLIT_TYPE = 131072,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__REQ_DEM_TYPE = 262144,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__REQ_ORD_TYPE = 524288,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__MEM_TYPE0 = 1048576,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__MEM_TYPE1 = 2097152,
	P4_EVENT_BSQ_ACTIVE_ENTRIES__MEM_TYPE2 = 4194304,
	P4_EVENT_SSE_INPUT_ASSIST__ALL = 16777216,
	P4_EVENT_PACKED_SP_UOP__ALL = 16777216,
	P4_EVENT_PACKED_DP_UOP__ALL = 16777216,
	P4_EVENT_SCALAR_SP_UOP__ALL = 16777216,
	P4_EVENT_SCALAR_DP_UOP__ALL = 16777216,
	P4_EVENT_64BIT_MMX_UOP__ALL = 16777216,
	P4_EVENT_128BIT_MMX_UOP__ALL = 16777216,
	P4_EVENT_X87_FP_UOP__ALL = 16777216,
	P4_EVENT_TC_MISC__FLUSH = 8192,
	P4_EVENT_GLOBAL_POWER_EVENTS__RUNNING = 512,
	P4_EVENT_TC_MS_XFER__CISC = 512,
	P4_EVENT_UOP_QUEUE_WRITES__FROM_TC_BUILD = 512,
	P4_EVENT_UOP_QUEUE_WRITES__FROM_TC_DELIVER = 1024,
	P4_EVENT_UOP_QUEUE_WRITES__FROM_ROM = 2048,
	P4_EVENT_RETIRED_MISPRED_BRANCH_TYPE__CONDITIONAL = 1024,
	P4_EVENT_RETIRED_MISPRED_BRANCH_TYPE__CALL = 2048,
	P4_EVENT_RETIRED_MISPRED_BRANCH_TYPE__RETURN = 4096,
	P4_EVENT_RETIRED_MISPRED_BRANCH_TYPE__INDIRECT = 8192,
	P4_EVENT_RETIRED_BRANCH_TYPE__CONDITIONAL = 1024,
	P4_EVENT_RETIRED_BRANCH_TYPE__CALL = 2048,
	P4_EVENT_RETIRED_BRANCH_TYPE__RETURN = 4096,
	P4_EVENT_RETIRED_BRANCH_TYPE__INDIRECT = 8192,
	P4_EVENT_RESOURCE_STALL__SBFULL = 16384,
	P4_EVENT_WC_BUFFER__WCB_EVICTS = 512,
	P4_EVENT_WC_BUFFER__WCB_FULL_EVICTS = 1024,
	P4_EVENT_FRONT_END_EVENT__NBOGUS = 512,
	P4_EVENT_FRONT_END_EVENT__BOGUS = 1024,
	P4_EVENT_EXECUTION_EVENT__NBOGUS0 = 512,
	P4_EVENT_EXECUTION_EVENT__NBOGUS1 = 1024,
	P4_EVENT_EXECUTION_EVENT__NBOGUS2 = 2048,
	P4_EVENT_EXECUTION_EVENT__NBOGUS3 = 4096,
	P4_EVENT_EXECUTION_EVENT__BOGUS0 = 8192,
	P4_EVENT_EXECUTION_EVENT__BOGUS1 = 16384,
	P4_EVENT_EXECUTION_EVENT__BOGUS2 = 32768,
	P4_EVENT_EXECUTION_EVENT__BOGUS3 = 65536,
	P4_EVENT_REPLAY_EVENT__NBOGUS = 512,
	P4_EVENT_REPLAY_EVENT__BOGUS = 1024,
	P4_EVENT_INSTR_RETIRED__NBOGUSNTAG = 512,
	P4_EVENT_INSTR_RETIRED__NBOGUSTAG = 1024,
	P4_EVENT_INSTR_RETIRED__BOGUSNTAG = 2048,
	P4_EVENT_INSTR_RETIRED__BOGUSTAG = 4096,
	P4_EVENT_UOPS_RETIRED__NBOGUS = 512,
	P4_EVENT_UOPS_RETIRED__BOGUS = 1024,
	P4_EVENT_UOP_TYPE__TAGLOADS = 1024,
	P4_EVENT_UOP_TYPE__TAGSTORES = 2048,
	P4_EVENT_BRANCH_RETIRED__MMNP = 512,
	P4_EVENT_BRANCH_RETIRED__MMNM = 1024,
	P4_EVENT_BRANCH_RETIRED__MMTP = 2048,
	P4_EVENT_BRANCH_RETIRED__MMTM = 4096,
	P4_EVENT_MISPRED_BRANCH_RETIRED__NBOGUS = 512,
	P4_EVENT_X87_ASSIST__FPSU = 512,
	P4_EVENT_X87_ASSIST__FPSO = 1024,
	P4_EVENT_X87_ASSIST__POAO = 2048,
	P4_EVENT_X87_ASSIST__POAU = 4096,
	P4_EVENT_X87_ASSIST__PREA = 8192,
	P4_EVENT_MACHINE_CLEAR__CLEAR = 512,
	P4_EVENT_MACHINE_CLEAR__MOCLEAR = 1024,
	P4_EVENT_MACHINE_CLEAR__SMCLEAR = 2048,
	P4_EVENT_INSTR_COMPLETED__NBOGUS = 512,
	P4_EVENT_INSTR_COMPLETED__BOGUS = 1024,
};

enum P4_PEBS_METRIC {
	P4_PEBS_METRIC__none = 0,
	P4_PEBS_METRIC__1stl_cache_load_miss_retired = 1,
	P4_PEBS_METRIC__2ndl_cache_load_miss_retired = 2,
	P4_PEBS_METRIC__dtlb_load_miss_retired = 3,
	P4_PEBS_METRIC__dtlb_store_miss_retired = 4,
	P4_PEBS_METRIC__dtlb_all_miss_retired = 5,
	P4_PEBS_METRIC__tagged_mispred_branch = 6,
	P4_PEBS_METRIC__mob_load_replay_retired = 7,
	P4_PEBS_METRIC__split_load_retired = 8,
	P4_PEBS_METRIC__split_store_retired = 9,
	P4_PEBS_METRIC__max = 10,
};

struct p4_event_bind {
	unsigned int opcode;
	unsigned int escr_msr[2];
	unsigned int escr_emask;
	unsigned int shared;
	char cntr[6];
};

struct p4_pebs_bind {
	unsigned int metric_pebs;
	unsigned int metric_vert;
};

struct p4_event_alias {
	u64 original;
	u64 alternative;
};

enum cpuid_regs_idx {
	CPUID_EAX = 0,
	CPUID_EBX = 1,
	CPUID_ECX = 2,
	CPUID_EDX = 3,
};

struct dev_ext_attribute {
	struct device_attribute attr;
	void *var;
};

enum pt_capabilities {
	PT_CAP_max_subleaf = 0,
	PT_CAP_cr3_filtering = 1,
	PT_CAP_psb_cyc = 2,
	PT_CAP_ip_filtering = 3,
	PT_CAP_mtc = 4,
	PT_CAP_ptwrite = 5,
	PT_CAP_power_event_trace = 6,
	PT_CAP_event_trace = 7,
	PT_CAP_tnt_disable = 8,
	PT_CAP_topa_output = 9,
	PT_CAP_topa_multiple_entries = 10,
	PT_CAP_single_range_output = 11,
	PT_CAP_output_subsys = 12,
	PT_CAP_payloads_lip = 13,
	PT_CAP_num_address_ranges = 14,
	PT_CAP_mtc_periods = 15,
	PT_CAP_cycle_thresholds = 16,
	PT_CAP_psb_periods = 17,
};

enum perf_addr_filter_action_t {
	PERF_ADDR_FILTER_ACTION_STOP = 0,
	PERF_ADDR_FILTER_ACTION_START = 1,
	PERF_ADDR_FILTER_ACTION_FILTER = 2,
};

struct perf_addr_filter {
	struct list_head entry;
	struct path path;
	long unsigned int offset;
	long unsigned int size;
	enum perf_addr_filter_action_t action;
};

struct topa_entry {
	u64 end: 1;
	u64 rsvd0: 1;
	u64 intr: 1;
	u64 rsvd1: 1;
	u64 stop: 1;
	u64 rsvd2: 1;
	u64 size: 4;
	u64 rsvd3: 2;
	u64 base: 36;
	u64 rsvd4: 16;
};

struct pt_pmu {
	struct pmu pmu;
	u32 caps[8];
	bool vmx;
	bool branch_en_always_on;
	long unsigned int max_nonturbo_ratio;
	unsigned int tsc_art_num;
	unsigned int tsc_art_den;
};

struct topa;

struct pt_buffer {
	struct list_head tables;
	struct topa *first;
	struct topa *last;
	struct topa *cur;
	unsigned int cur_idx;
	size_t output_off;
	long unsigned int nr_pages;
	local_t data_size;
	local64_t head;
	bool snapshot;
	bool single;
	long int stop_pos;
	long int intr_pos;
	struct topa_entry *stop_te;
	struct topa_entry *intr_te;
	void **data_pages;
};

struct topa {
	struct list_head list;
	u64 offset;
	size_t size;
	int last;
	unsigned int z_count;
};

struct pt_filter {
	long unsigned int msr_a;
	long unsigned int msr_b;
	long unsigned int config;
};

struct pt_filters {
	struct pt_filter filter[4];
	unsigned int nr_filters;
};

struct pt {
	struct perf_output_handle handle;
	struct pt_filters filters;
	int handle_nmi;
	int vmx_on;
	u64 output_base;
	u64 output_mask;
};

struct pt_cap_desc {
	const char *name;
	u32 leaf;
	u8 reg;
	u32 mask;
};

struct pt_address_range {
	long unsigned int msr_a;
	long unsigned int msr_b;
	unsigned int reg_off;
};

struct topa_page {
	struct topa_entry table[507];
	struct topa topa;
};

struct x86_cpu_id {
	__u16 vendor;
	__u16 family;
	__u16 model;
	__u16 steppings;
	__u16 feature;
	kernel_ulong_t driver_data;
};

enum hrtimer_mode {
	HRTIMER_MODE_ABS = 0,
	HRTIMER_MODE_REL = 1,
	HRTIMER_MODE_PINNED = 2,
	HRTIMER_MODE_SOFT = 4,
	HRTIMER_MODE_HARD = 8,
	HRTIMER_MODE_ABS_PINNED = 2,
	HRTIMER_MODE_REL_PINNED = 3,
	HRTIMER_MODE_ABS_SOFT = 4,
	HRTIMER_MODE_REL_SOFT = 5,
	HRTIMER_MODE_ABS_PINNED_SOFT = 6,
	HRTIMER_MODE_REL_PINNED_SOFT = 7,
	HRTIMER_MODE_ABS_HARD = 8,
	HRTIMER_MODE_REL_HARD = 9,
	HRTIMER_MODE_ABS_PINNED_HARD = 10,
	HRTIMER_MODE_REL_PINNED_HARD = 11,
};

struct acpi_device;

struct pci_sysdata {
	int domain;
	int node;
	struct acpi_device *companion;
	void *iommu;
	void *fwnode;
	struct pci_dev *vmd_dev;
};

struct pci_extra_dev {
	struct pci_dev *dev[4];
};

struct intel_uncore_pmu;

struct intel_uncore_ops;

struct uncore_event_desc;

struct freerunning_counters;

struct intel_uncore_topology;

struct intel_uncore_type {
	const char *name;
	int num_counters;
	int num_boxes;
	int perf_ctr_bits;
	int fixed_ctr_bits;
	int num_freerunning_types;
	int type_id;
	unsigned int perf_ctr;
	unsigned int event_ctl;
	unsigned int event_mask;
	unsigned int event_mask_ext;
	unsigned int fixed_ctr;
	unsigned int fixed_ctl;
	unsigned int box_ctl;
	u64 *box_ctls;
	union {
		unsigned int msr_offset;
		unsigned int mmio_offset;
	};
	unsigned int mmio_map_size;
	unsigned int num_shared_regs: 8;
	unsigned int single_fixed: 1;
	unsigned int pair_ctr_ctl: 1;
	union {
		unsigned int *msr_offsets;
		unsigned int *pci_offsets;
		unsigned int *mmio_offsets;
	};
	unsigned int *box_ids;
	struct event_constraint unconstrainted;
	struct event_constraint *constraints;
	struct intel_uncore_pmu *pmus;
	struct intel_uncore_ops *ops;
	struct uncore_event_desc *event_descs;
	struct freerunning_counters *freerunning;
	const struct attribute_group *attr_groups[4];
	const struct attribute_group **attr_update;
	struct pmu *pmu;
	struct intel_uncore_topology *topology;
	int (*get_topology)(struct intel_uncore_type *);
	int (*set_mapping)(struct intel_uncore_type *);
	void (*cleanup_mapping)(struct intel_uncore_type *);
};

struct intel_uncore_box;

struct intel_uncore_pmu {
	struct pmu pmu;
	char name[32];
	int pmu_idx;
	int func_id;
	bool registered;
	atomic_t activeboxes;
	struct intel_uncore_type *type;
	struct intel_uncore_box **boxes;
};

struct intel_uncore_ops {
	void (*init_box)(struct intel_uncore_box *);
	void (*exit_box)(struct intel_uncore_box *);
	void (*disable_box)(struct intel_uncore_box *);
	void (*enable_box)(struct intel_uncore_box *);
	void (*disable_event)(struct intel_uncore_box *, struct perf_event *);
	void (*enable_event)(struct intel_uncore_box *, struct perf_event *);
	u64 (*read_counter)(struct intel_uncore_box *, struct perf_event *);
	int (*hw_config)(struct intel_uncore_box *, struct perf_event *);
	struct event_constraint * (*get_constraint)(struct intel_uncore_box *, struct perf_event *);
	void (*put_constraint)(struct intel_uncore_box *, struct perf_event *);
};

struct uncore_event_desc {
	struct device_attribute attr;
	const char *config;
};

struct freerunning_counters {
	unsigned int counter_base;
	unsigned int counter_offset;
	unsigned int box_offset;
	unsigned int num_counters;
	unsigned int bits;
	unsigned int *box_offsets;
};

struct intel_uncore_topology {
	u64 configuration;
	int segment;
};

struct intel_uncore_extra_reg {
	raw_spinlock_t lock;
	u64 config;
	u64 config1;
	u64 config2;
	atomic_t ref;
};

struct intel_uncore_box {
	int dieid;
	int n_active;
	int n_events;
	int cpu;
	long unsigned int flags;
	atomic_t refcnt;
	struct perf_event *events[10];
	struct perf_event *event_list[10];
	struct event_constraint *event_constraint[10];
	long unsigned int active_mask[1];
	u64 tags[10];
	struct pci_dev *pci_dev;
	struct intel_uncore_pmu *pmu;
	u64 hrtimer_duration;
	struct hrtimer hrtimer;
	struct list_head list;
	struct list_head active_list;
	void *io_addr;
	struct intel_uncore_extra_reg shared_regs[0];
};

struct pci2phy_map {
	struct list_head list;
	int segment;
	int pbus_to_dieid[256];
};

struct intel_uncore_init_fun {
	void (*cpu_init)();
	int (*pci_init)();
	void (*mmio_init)();
	bool use_discovery;
};

enum {
	EXTRA_REG_NHMEX_M_FILTER = 0,
	EXTRA_REG_NHMEX_M_DSP = 1,
	EXTRA_REG_NHMEX_M_ISS = 2,
	EXTRA_REG_NHMEX_M_MAP = 3,
	EXTRA_REG_NHMEX_M_MSC_THR = 4,
	EXTRA_REG_NHMEX_M_PGT = 5,
	EXTRA_REG_NHMEX_M_PLD = 6,
	EXTRA_REG_NHMEX_M_ZDP_CTL_FVC = 7,
};

enum {
	SNB_PCI_UNCORE_IMC = 0,
};

enum perf_snb_uncore_imc_freerunning_types {
	SNB_PCI_UNCORE_IMC_DATA_READS = 0,
	SNB_PCI_UNCORE_IMC_DATA_WRITES = 1,
	SNB_PCI_UNCORE_IMC_GT_REQUESTS = 2,
	SNB_PCI_UNCORE_IMC_IA_REQUESTS = 3,
	SNB_PCI_UNCORE_IMC_IO_REQUESTS = 4,
	SNB_PCI_UNCORE_IMC_FREERUNNING_TYPE_MAX = 5,
};

struct imc_uncore_pci_dev {
	__u32 pci_id;
	struct pci_driver *driver;
};

enum perf_tgl_uncore_imc_freerunning_types {
	TGL_MMIO_UNCORE_IMC_DATA_TOTAL = 0,
	TGL_MMIO_UNCORE_IMC_DATA_READ = 1,
	TGL_MMIO_UNCORE_IMC_DATA_WRITE = 2,
	TGL_MMIO_UNCORE_IMC_FREERUNNING_TYPE_MAX = 3,
};

enum perf_adl_uncore_imc_freerunning_types {
	ADL_MMIO_UNCORE_IMC_DATA_TOTAL = 0,
	ADL_MMIO_UNCORE_IMC_DATA_READ = 1,
	ADL_MMIO_UNCORE_IMC_DATA_WRITE = 2,
	ADL_MMIO_UNCORE_IMC_FREERUNNING_TYPE_MAX = 3,
};

enum uncore_access_type {
	UNCORE_ACCESS_MSR = 0,
	UNCORE_ACCESS_MMIO = 1,
	UNCORE_ACCESS_PCI = 2,
	UNCORE_ACCESS_MAX = 3,
};

enum {
	SNBEP_PCI_QPI_PORT0_FILTER = 0,
	SNBEP_PCI_QPI_PORT1_FILTER = 1,
	BDX_PCI_QPI_PORT2_FILTER = 2,
};

enum {
	SNBEP_PCI_UNCORE_HA = 0,
	SNBEP_PCI_UNCORE_IMC = 1,
	SNBEP_PCI_UNCORE_QPI = 2,
	SNBEP_PCI_UNCORE_R2PCIE = 3,
	SNBEP_PCI_UNCORE_R3QPI = 4,
};

enum {
	IVBEP_PCI_UNCORE_HA = 0,
	IVBEP_PCI_UNCORE_IMC = 1,
	IVBEP_PCI_UNCORE_IRP = 2,
	IVBEP_PCI_UNCORE_QPI = 3,
	IVBEP_PCI_UNCORE_R2PCIE = 4,
	IVBEP_PCI_UNCORE_R3QPI = 5,
};

enum {
	KNL_PCI_UNCORE_MC_UCLK = 0,
	KNL_PCI_UNCORE_MC_DCLK = 1,
	KNL_PCI_UNCORE_EDC_UCLK = 2,
	KNL_PCI_UNCORE_EDC_ECLK = 3,
	KNL_PCI_UNCORE_M2PCIE = 4,
	KNL_PCI_UNCORE_IRP = 5,
};

enum {
	HSWEP_PCI_UNCORE_HA = 0,
	HSWEP_PCI_UNCORE_IMC = 1,
	HSWEP_PCI_UNCORE_IRP = 2,
	HSWEP_PCI_UNCORE_QPI = 3,
	HSWEP_PCI_UNCORE_R2PCIE = 4,
	HSWEP_PCI_UNCORE_R3QPI = 5,
};

enum {
	BDX_PCI_UNCORE_HA = 0,
	BDX_PCI_UNCORE_IMC = 1,
	BDX_PCI_UNCORE_IRP = 2,
	BDX_PCI_UNCORE_QPI = 3,
	BDX_PCI_UNCORE_R2PCIE = 4,
	BDX_PCI_UNCORE_R3QPI = 5,
};

enum perf_uncore_iio_freerunning_type_id {
	SKX_IIO_MSR_IOCLK = 0,
	SKX_IIO_MSR_BW = 1,
	SKX_IIO_MSR_UTIL = 2,
	SKX_IIO_FREERUNNING_TYPE_MAX = 3,
};

enum {
	SKX_PCI_UNCORE_IMC = 0,
	SKX_PCI_UNCORE_M2M = 1,
	SKX_PCI_UNCORE_UPI = 2,
	SKX_PCI_UNCORE_M2PCIE = 3,
	SKX_PCI_UNCORE_M3UPI = 4,
};

enum {
	SNR_QAT_PMON_ID = 0,
	SNR_CBDMA_DMI_PMON_ID = 1,
	SNR_NIS_PMON_ID = 2,
	SNR_DLB_PMON_ID = 3,
	SNR_PCIE_GEN3_PMON_ID = 4,
};

enum perf_uncore_snr_iio_freerunning_type_id {
	SNR_IIO_MSR_IOCLK = 0,
	SNR_IIO_MSR_BW_IN = 1,
	SNR_IIO_FREERUNNING_TYPE_MAX = 2,
};

enum {
	SNR_PCI_UNCORE_M2M = 0,
	SNR_PCI_UNCORE_PCIE3 = 1,
};

enum perf_uncore_snr_imc_freerunning_type_id {
	SNR_IMC_DCLK = 0,
	SNR_IMC_DDR = 1,
	SNR_IMC_FREERUNNING_TYPE_MAX = 2,
};

enum {
	ICX_PCIE1_PMON_ID = 0,
	ICX_PCIE2_PMON_ID = 1,
	ICX_PCIE3_PMON_ID = 2,
	ICX_PCIE4_PMON_ID = 3,
	ICX_PCIE5_PMON_ID = 4,
	ICX_CBDMA_DMI_PMON_ID = 5,
};

enum perf_uncore_icx_iio_freerunning_type_id {
	ICX_IIO_MSR_IOCLK = 0,
	ICX_IIO_MSR_BW_IN = 1,
	ICX_IIO_FREERUNNING_TYPE_MAX = 2,
};

enum {
	ICX_PCI_UNCORE_M2M = 0,
	ICX_PCI_UNCORE_UPI = 1,
	ICX_PCI_UNCORE_M3UPI = 2,
};

enum perf_uncore_icx_imc_freerunning_type_id {
	ICX_IMC_DCLK = 0,
	ICX_IMC_DDR = 1,
	ICX_IMC_DDRT = 2,
	ICX_IMC_FREERUNNING_TYPE_MAX = 3,
};

enum perf_uncore_spr_iio_freerunning_type_id {
	SPR_IIO_MSR_IOCLK = 0,
	SPR_IIO_MSR_BW_IN = 1,
	SPR_IIO_MSR_BW_OUT = 2,
	SPR_IIO_FREERUNNING_TYPE_MAX = 3,
};

enum perf_uncore_spr_imc_freerunning_type_id {
	SPR_IMC_DCLK = 0,
	SPR_IMC_PQ_CYCLES = 1,
	SPR_IMC_FREERUNNING_TYPE_MAX = 2,
};

struct uncore_global_discovery {
	union {
		u64 table1;
		struct {
			u64 type: 8;
			u64 stride: 8;
			u64 max_units: 10;
			u64 __reserved_1: 36;
			u64 access_type: 2;
		};
	};
	u64 ctl;
	union {
		u64 table3;
		struct {
			u64 status_offset: 8;
			u64 num_status: 16;
			u64 __reserved_2: 40;
		};
	};
};

struct uncore_unit_discovery {
	union {
		u64 table1;
		struct {
			u64 num_regs: 8;
			u64 ctl_offset: 8;
			u64 bit_width: 8;
			u64 ctr_offset: 8;
			u64 status_offset: 8;
			u64 __reserved_1: 22;
			u64 access_type: 2;
		};
	};
	u64 ctl;
	union {
		u64 table3;
		struct {
			u64 box_type: 16;
			u64 box_id: 16;
			u64 __reserved_2: 32;
		};
	};
};

struct intel_uncore_discovery_type {
	struct rb_node node;
	enum uncore_access_type access_type;
	u64 box_ctrl;
	u64 *box_ctrl_die;
	u16 type;
	u8 num_counters;
	u8 counter_width;
	u8 ctl_offset;
	u8 ctr_offset;
	u16 num_boxes;
	unsigned int *ids;
	unsigned int *box_offset;
};

typedef s8 int8_t;

typedef u8 uint8_t;

typedef u64 uint64_t;

struct atomic_notifier_head {
	spinlock_t lock;
	struct notifier_block *head;
};

enum xen_domain_type {
	XEN_NATIVE = 0,
	XEN_PV_DOMAIN = 1,
	XEN_HVM_DOMAIN = 2,
};

typedef long unsigned int xen_pfn_t;

typedef long unsigned int xen_ulong_t;

struct arch_shared_info {
	long unsigned int max_pfn;
	xen_pfn_t pfn_to_mfn_frame_list_list;
	long unsigned int nmi_reason;
	long unsigned int p2m_cr3;
	long unsigned int p2m_vaddr;
	long unsigned int p2m_generation;
};

struct arch_vcpu_info {
	long unsigned int cr2;
	long unsigned int pad;
};

struct pvclock_wall_clock {
	u32 version;
	u32 sec;
	u32 nsec;
};

struct vcpu_info {
	uint8_t evtchn_upcall_pending;
	uint8_t evtchn_upcall_mask;
	xen_ulong_t evtchn_pending_sel;
	struct arch_vcpu_info arch;
	struct pvclock_vcpu_time_info time;
};

struct shared_info {
	struct vcpu_info vcpu_info[32];
	xen_ulong_t evtchn_pending[64];
	xen_ulong_t evtchn_mask[64];
	struct pvclock_wall_clock wc;
	uint32_t wc_sec_hi;
	struct arch_shared_info arch;
};

struct start_info {
	char magic[32];
	long unsigned int nr_pages;
	long unsigned int shared_info;
	uint32_t flags;
	xen_pfn_t store_mfn;
	uint32_t store_evtchn;
	union {
		struct {
			xen_pfn_t mfn;
			uint32_t evtchn;
		} domU;
		struct {
			uint32_t info_off;
			uint32_t info_size;
		} dom0;
	} console;
	long unsigned int pt_base;
	long unsigned int nr_pt_frames;
	long unsigned int mfn_list;
	long unsigned int mod_start;
	long unsigned int mod_len;
	int8_t cmd_line[1024];
	long unsigned int first_p2m_pfn;
	long unsigned int nr_p2m_frames;
};

struct sched_shutdown {
	unsigned int reason;
};

struct sched_pin_override {
	int32_t pcpu;
};

struct xen_extraversion {
	char extraversion[16];
};

struct vcpu_register_vcpu_info {
	uint64_t mfn;
	uint32_t offset;
	uint32_t rsvd;
};

struct xmaddr {
	phys_addr_t maddr;
};

typedef struct xmaddr xmaddr_t;

struct xpaddr {
	phys_addr_t paddr;
};

typedef struct xpaddr xpaddr_t;

typedef s16 int16_t;

enum clocksource_ids {
	CSID_GENERIC = 0,
	CSID_ARM_ARCH_COUNTER = 1,
	CSID_MAX = 2,
};

struct clocksource {
	u64 (*read)(struct clocksource *);
	u64 mask;
	u32 mult;
	u32 shift;
	u64 max_idle_ns;
	u32 maxadj;
	u32 uncertainty_margin;
	u64 max_cycles;
	const char *name;
	struct list_head list;
	int rating;
	enum clocksource_ids id;
	enum vdso_clock_mode vdso_clock_mode;
	long unsigned int flags;
	int (*enable)(struct clocksource *);
	void (*disable)(struct clocksource *);
	void (*suspend)(struct clocksource *);
	void (*resume)(struct clocksource *);
	void (*mark_unstable)(struct clocksource *);
	void (*tick_stable)(struct clocksource *);
	struct list_head wd_list;
	u64 cs_last;
	u64 wd_last;
	struct module *owner;
};

struct x86_init_mpparse {
	void (*setup_ioapic_ids)();
	void (*find_smp_config)();
	void (*get_smp_config)(unsigned int);
};

struct x86_init_resources {
	void (*probe_roms)();
	void (*reserve_resources)();
	char * (*memory_setup)();
};

struct x86_init_irqs {
	void (*pre_vector_init)();
	void (*intr_init)();
	void (*intr_mode_select)();
	void (*intr_mode_init)();
	struct irq_domain * (*create_pci_msi_domain)();
};

struct x86_init_oem {
	void (*arch_setup)();
	void (*banner)();
};

struct x86_init_paging {
	void (*pagetable_init)();
};

struct x86_init_timers {
	void (*setup_percpu_clockev)();
	void (*timer_init)();
	void (*wallclock_init)();
};

struct x86_init_iommu {
	int (*iommu_init)();
};

struct x86_init_pci {
	int (*arch_init)();
	int (*init)();
	void (*init_irq)();
	void (*fixup_irqs)();
};

struct x86_hyper_init {
	void (*init_platform)();
	void (*guest_late_init)();
	bool (*x2apic_available)();
	bool (*msi_ext_dest_id)();
	void (*init_mem_mapping)();
	void (*init_after_bootmem)();
};

struct x86_init_acpi {
	void (*set_root_pointer)(u64);
	u64 (*get_root_pointer)();
	void (*reduced_hw_early_init)();
};

struct x86_init_ops {
	struct x86_init_resources resources;
	struct x86_init_mpparse mpparse;
	struct x86_init_irqs irqs;
	struct x86_init_oem oem;
	struct x86_init_paging paging;
	struct x86_init_timers timers;
	struct x86_init_iommu iommu;
	struct x86_init_pci pci;
	struct x86_hyper_init hyper;
	struct x86_init_acpi acpi;
};

struct x86_cpuinit_ops {
	void (*setup_percpu_clockev)();
	void (*early_percpu_clock_init)();
	void (*fixup_cpu_id)(struct cpuinfo_x86 *, int);
};

enum clock_event_state {
	CLOCK_EVT_STATE_DETACHED = 0,
	CLOCK_EVT_STATE_SHUTDOWN = 1,
	CLOCK_EVT_STATE_PERIODIC = 2,
	CLOCK_EVT_STATE_ONESHOT = 3,
	CLOCK_EVT_STATE_ONESHOT_STOPPED = 4,
};

struct clock_event_device {
	void (*event_handler)(struct clock_event_device *);
	int (*set_next_event)(long unsigned int, struct clock_event_device *);
	int (*set_next_ktime)(ktime_t, struct clock_event_device *);
	ktime_t next_event;
	u64 max_delta_ns;
	u64 min_delta_ns;
	u32 mult;
	u32 shift;
	enum clock_event_state state_use_accessors;
	unsigned int features;
	long unsigned int retries;
	int (*set_state_periodic)(struct clock_event_device *);
	int (*set_state_oneshot)(struct clock_event_device *);
	int (*set_state_oneshot_stopped)(struct clock_event_device *);
	int (*set_state_shutdown)(struct clock_event_device *);
	int (*tick_resume)(struct clock_event_device *);
	void (*broadcast)(const struct cpumask *);
	void (*suspend)(struct clock_event_device *);
	void (*resume)(struct clock_event_device *);
	long unsigned int min_delta_ticks;
	long unsigned int max_delta_ticks;
	const char *name;
	int rating;
	int irq;
	int bound_on;
	const struct cpumask *cpumask;
	struct list_head list;
	struct module *owner;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct tk_read_base {
	struct clocksource *clock;
	u64 mask;
	u64 cycle_last;
	u32 mult;
	u32 shift;
	u64 xtime_nsec;
	ktime_t base;
	u64 base_real;
};

struct timekeeper {
	struct tk_read_base tkr_mono;
	struct tk_read_base tkr_raw;
	u64 xtime_sec;
	long unsigned int ktime_sec;
	struct timespec64 wall_to_monotonic;
	ktime_t offs_real;
	ktime_t offs_boot;
	ktime_t offs_tai;
	s32 tai_offset;
	unsigned int clock_was_set_seq;
	u8 cs_was_changed_seq;
	ktime_t next_leap_ktime;
	u64 raw_sec;
	struct timespec64 monotonic_to_boot;
	u64 cycle_interval;
	u64 xtime_interval;
	s64 xtime_remainder;
	u64 raw_interval;
	u64 ntp_tick;
	s64 ntp_error;
	u32 ntp_error_shift;
	u32 ntp_err_mult;
	u32 skip_second_overflow;
};

typedef unsigned char *__guest_handle_uchar;

typedef char *__guest_handle_char;

typedef void *__guest_handle_void;

typedef uint64_t *__guest_handle_uint64_t;

typedef uint32_t *__guest_handle_uint32_t;

struct vcpu_time_info {
	uint32_t version;
	uint32_t pad0;
	uint64_t tsc_timestamp;
	uint64_t system_time;
	uint32_t tsc_to_system_mul;
	int8_t tsc_shift;
	int8_t pad1[3];
};

struct xenpf_settime32 {
	uint32_t secs;
	uint32_t nsecs;
	uint64_t system_time;
};

struct xenpf_settime64 {
	uint64_t secs;
	uint32_t nsecs;
	uint32_t mbz;
	uint64_t system_time;
};

struct xenpf_add_memtype {
	xen_pfn_t mfn;
	uint64_t nr_mfns;
	uint32_t type;
	uint32_t handle;
	uint32_t reg;
};

struct xenpf_del_memtype {
	uint32_t handle;
	uint32_t reg;
};

struct xenpf_read_memtype {
	uint32_t reg;
	xen_pfn_t mfn;
	uint64_t nr_mfns;
	uint32_t type;
};

struct xenpf_microcode_update {
	__guest_handle_void data;
	uint32_t length;
};

struct xenpf_platform_quirk {
	uint32_t quirk_id;
};

struct xenpf_efi_time {
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t min;
	uint8_t sec;
	uint32_t ns;
	int16_t tz;
	uint8_t daylight;
};

struct xenpf_efi_guid {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
};

struct xenpf_efi_runtime_call {
	uint32_t function;
	uint32_t misc;
	xen_ulong_t status;
	union {
		struct {
			struct xenpf_efi_time time;
			uint32_t resolution;
			uint32_t accuracy;
		} get_time;
		struct xenpf_efi_time set_time;
		struct xenpf_efi_time get_wakeup_time;
		struct xenpf_efi_time set_wakeup_time;
		struct {
			__guest_handle_void name;
			xen_ulong_t size;
			__guest_handle_void data;
			struct xenpf_efi_guid vendor_guid;
		} get_variable;
		struct {
			__guest_handle_void name;
			xen_ulong_t size;
			__guest_handle_void data;
			struct xenpf_efi_guid vendor_guid;
		} set_variable;
		struct {
			xen_ulong_t size;
			__guest_handle_void name;
			struct xenpf_efi_guid vendor_guid;
		} get_next_variable_name;
		struct {
			uint32_t attr;
			uint64_t max_store_size;
			uint64_t remain_store_size;
			uint64_t max_size;
		} query_variable_info;
		struct {
			__guest_handle_void capsule_header_array;
			xen_ulong_t capsule_count;
			uint64_t max_capsule_size;
			uint32_t reset_type;
		} query_capsule_capabilities;
		struct {
			__guest_handle_void capsule_header_array;
			xen_ulong_t capsule_count;
			uint64_t sg_list;
		} update_capsule;
	} u;
};

union xenpf_efi_info {
	uint32_t version;
	struct {
		uint64_t addr;
		uint32_t nent;
	} cfg;
	struct {
		uint32_t revision;
		uint32_t bufsz;
		__guest_handle_void name;
	} vendor;
	struct {
		uint64_t addr;
		uint64_t size;
		uint64_t attr;
		uint32_t type;
	} mem;
};

struct xenpf_firmware_info {
	uint32_t type;
	uint32_t index;
	union {
		struct {
			uint8_t device;
			uint8_t version;
			uint16_t interface_support;
			uint16_t legacy_max_cylinder;
			uint8_t legacy_max_head;
			uint8_t legacy_sectors_per_track;
			__guest_handle_void edd_params;
		} disk_info;
		struct {
			uint8_t device;
			uint32_t mbr_signature;
		} disk_mbr_signature;
		struct {
			uint8_t capabilities;
			uint8_t edid_transfer_time;
			__guest_handle_uchar edid;
		} vbeddc_info;
		union xenpf_efi_info efi_info;
		uint8_t kbd_shift_flags;
	} u;
};

struct xenpf_enter_acpi_sleep {
	uint16_t val_a;
	uint16_t val_b;
	uint32_t sleep_state;
	uint32_t flags;
};

struct xenpf_change_freq {
	uint32_t flags;
	uint32_t cpu;
	uint64_t freq;
};

struct xenpf_getidletime {
	__guest_handle_uchar cpumap_bitmap;
	uint32_t cpumap_nr_cpus;
	__guest_handle_uint64_t idletime;
	uint64_t now;
};

struct xen_power_register {
	uint32_t space_id;
	uint32_t bit_width;
	uint32_t bit_offset;
	uint32_t access_size;
	uint64_t address;
};

struct xen_processor_csd {
	uint32_t domain;
	uint32_t coord_type;
	uint32_t num;
};

typedef struct xen_processor_csd *__guest_handle_xen_processor_csd;

struct xen_processor_cx {
	struct xen_power_register reg;
	uint8_t type;
	uint32_t latency;
	uint32_t power;
	uint32_t dpcnt;
	__guest_handle_xen_processor_csd dp;
};

typedef struct xen_processor_cx *__guest_handle_xen_processor_cx;

struct xen_processor_flags {
	uint32_t bm_control: 1;
	uint32_t bm_check: 1;
	uint32_t has_cst: 1;
	uint32_t power_setup_done: 1;
	uint32_t bm_rld_set: 1;
};

struct xen_processor_power {
	uint32_t count;
	struct xen_processor_flags flags;
	__guest_handle_xen_processor_cx states;
};

struct xen_pct_register {
	uint8_t descriptor;
	uint16_t length;
	uint8_t space_id;
	uint8_t bit_width;
	uint8_t bit_offset;
	uint8_t reserved;
	uint64_t address;
};

struct xen_processor_px {
	uint64_t core_frequency;
	uint64_t power;
	uint64_t transition_latency;
	uint64_t bus_master_latency;
	uint64_t control;
	uint64_t status;
};

typedef struct xen_processor_px *__guest_handle_xen_processor_px;

struct xen_psd_package {
	uint64_t num_entries;
	uint64_t revision;
	uint64_t domain;
	uint64_t coord_type;
	uint64_t num_processors;
};

struct xen_processor_performance {
	uint32_t flags;
	uint32_t platform_limit;
	struct xen_pct_register control_register;
	struct xen_pct_register status_register;
	uint32_t state_count;
	__guest_handle_xen_processor_px states;
	struct xen_psd_package domain_info;
	uint32_t shared_type;
};

struct xenpf_set_processor_pminfo {
	uint32_t id;
	uint32_t type;
	union {
		struct xen_processor_power power;
		struct xen_processor_performance perf;
		__guest_handle_uint32_t pdc;
	};
};

struct xenpf_pcpuinfo {
	uint32_t xen_cpuid;
	uint32_t max_present;
	uint32_t flags;
	uint32_t apic_id;
	uint32_t acpi_id;
};

struct xenpf_cpu_ol {
	uint32_t cpuid;
};

struct xenpf_cpu_hotadd {
	uint32_t apic_id;
	uint32_t acpi_id;
	uint32_t pxm;
};

struct xenpf_mem_hotadd {
	uint64_t spfn;
	uint64_t epfn;
	uint32_t pxm;
	uint32_t flags;
};

struct xenpf_core_parking {
	uint32_t type;
	uint32_t idle_nums;
};

struct xenpf_symdata {
	uint32_t namelen;
	uint32_t symnum;
	__guest_handle_char name;
	uint64_t address;
	char type;
};

struct xen_platform_op {
	uint32_t cmd;
	uint32_t interface_version;
	union {
		struct xenpf_settime32 settime32;
		struct xenpf_settime64 settime64;
		struct xenpf_add_memtype add_memtype;
		struct xenpf_del_memtype del_memtype;
		struct xenpf_read_memtype read_memtype;
		struct xenpf_microcode_update microcode;
		struct xenpf_platform_quirk platform_quirk;
		struct xenpf_efi_runtime_call efi_runtime_call;
		struct xenpf_firmware_info firmware_info;
		struct xenpf_enter_acpi_sleep enter_acpi_sleep;
		struct xenpf_change_freq change_freq;
		struct xenpf_getidletime getidletime;
		struct xenpf_set_processor_pminfo set_pminfo;
		struct xenpf_pcpuinfo pcpu_info;
		struct xenpf_cpu_ol cpu_ol;
		struct xenpf_cpu_hotadd cpu_add;
		struct xenpf_mem_hotadd mem_add;
		struct xenpf_core_parking core_parking;
		struct xenpf_symdata symdata;
		uint8_t pad[128];
	} u;
};

struct vcpu_set_singleshot_timer {
	uint64_t timeout_abs_ns;
	uint32_t flags;
};

typedef struct vcpu_time_info *__guest_handle_vcpu_time_info;

struct vcpu_register_time_memory_area {
	union {
		__guest_handle_vcpu_time_info h;
		struct pvclock_vcpu_time_info *v;
		uint64_t p;
	} addr;
};

struct xen_clock_event_device {
	struct clock_event_device evt;
	char name[16];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

typedef uint16_t grant_status_t;

struct grant_frames {
	xen_pfn_t *pfn;
	unsigned int count;
	void *vaddr;
};

struct gnttab_vm_area {
	struct vm_struct *area;
	pte_t **ptes;
	int idx;
};

enum acpi_irq_model_id {
	ACPI_IRQ_MODEL_PIC = 0,
	ACPI_IRQ_MODEL_IOAPIC = 1,
	ACPI_IRQ_MODEL_IOSAPIC = 2,
	ACPI_IRQ_MODEL_PLATFORM = 3,
	ACPI_IRQ_MODEL_GIC = 4,
	ACPI_IRQ_MODEL_COUNT = 5,
};

typedef uint16_t domid_t;

struct xen_add_to_physmap {
	domid_t domid;
	uint16_t size;
	unsigned int space;
	xen_ulong_t idx;
	xen_pfn_t gpfn;
};

struct machine_ops {
	void (*restart)(char *);
	void (*halt)();
	void (*power_off)();
	void (*shutdown)();
	void (*crash_shutdown)(struct pt_regs *);
	void (*emergency_restart)();
};

enum x86_hypervisor_type {
	X86_HYPER_NATIVE = 0,
	X86_HYPER_VMWARE = 1,
	X86_HYPER_MS_HYPERV = 2,
	X86_HYPER_XEN_PV = 3,
	X86_HYPER_XEN_HVM = 4,
	X86_HYPER_KVM = 5,
	X86_HYPER_JAILHOUSE = 6,
	X86_HYPER_ACRN = 7,
};

struct hypervisor_x86 {
	const char *name;
	uint32_t (*detect)();
	enum x86_hypervisor_type type;
	struct x86_hyper_init init;
	struct x86_hyper_runtime runtime;
	bool ignore_nopv;
};

enum e820_type {
	E820_TYPE_RAM = 1,
	E820_TYPE_RESERVED = 2,
	E820_TYPE_ACPI = 3,
	E820_TYPE_NVS = 4,
	E820_TYPE_UNUSABLE = 5,
	E820_TYPE_PMEM = 7,
	E820_TYPE_PRAM = 12,
	E820_TYPE_SOFT_RESERVED = 4026531839,
	E820_TYPE_RESERVED_KERN = 128,
};

struct vmcore_cb {
	bool (*pfn_is_ram)(struct vmcore_cb *, long unsigned int);
	struct list_head next;
};

struct xen_hvm_pagetable_dying {
	domid_t domid;
	__u64 gpa;
};

enum hvmmem_type_t {
	HVMMEM_ram_rw = 0,
	HVMMEM_ram_ro = 1,
	HVMMEM_mmio_dm = 2,
};

struct xen_hvm_get_mem_type {
	domid_t domid;
	uint16_t mem_type;
	uint16_t pad[2];
	uint64_t pfn;
};

struct e820_entry {
	u64 addr;
	u64 size;
	enum e820_type type;
} __attribute__((packed));

struct e820_table {
	__u32 nr_entries;
	struct e820_entry entries[3200];
} __attribute__((packed));

typedef xen_pfn_t *__guest_handle_xen_pfn_t;

typedef long unsigned int xen_callback_t;

struct mmu_update {
	uint64_t ptr;
	uint64_t val;
};

struct xen_memory_region {
	long unsigned int start_pfn;
	long unsigned int n_pfns;
};

struct callback_register {
	uint16_t type;
	uint16_t flags;
	xen_callback_t address;
};

struct xen_memory_reservation {
	__guest_handle_xen_pfn_t extent_start;
	xen_ulong_t nr_extents;
	unsigned int extent_order;
	unsigned int address_bits;
	domid_t domid;
};

struct xen_memory_map {
	unsigned int nr_entries;
	__guest_handle_void buffer;
};

struct x86_apic_ops {
	unsigned int (*io_apic_read)(unsigned int, unsigned int);
	void (*restore)();
};

struct physdev_apic {
	long unsigned int apic_physbase;
	uint32_t reg;
	uint32_t value;
};

typedef long unsigned int uintptr_t;

struct xen_pmu_amd_ctxt {
	uint32_t counters;
	uint32_t ctrls;
	uint64_t regs[0];
};

struct xen_pmu_cntr_pair {
	uint64_t counter;
	uint64_t control;
};

struct xen_pmu_intel_ctxt {
	uint32_t fixed_counters;
	uint32_t arch_counters;
	uint64_t global_ctrl;
	uint64_t global_ovf_ctrl;
	uint64_t global_status;
	uint64_t fixed_ctrl;
	uint64_t ds_area;
	uint64_t pebs_enable;
	uint64_t debugctl;
	uint64_t regs[0];
};

struct xen_pmu_regs {
	uint64_t ip;
	uint64_t sp;
	uint64_t flags;
	uint16_t cs;
	uint16_t ss;
	uint8_t cpl;
	uint8_t pad[3];
};

struct xen_pmu_arch {
	union {
		struct xen_pmu_regs regs;
		uint8_t pad[64];
	} r;
	uint64_t pmu_flags;
	union {
		uint32_t lapic_lvtpc;
		uint64_t pad;
	} l;
	union {
		struct xen_pmu_amd_ctxt amd;
		struct xen_pmu_intel_ctxt intel;
		uint8_t pad[128];
	} c;
};

struct xen_pmu_params {
	struct {
		uint32_t maj;
		uint32_t min;
	} version;
	uint64_t val;
	uint32_t vcpu;
	uint32_t pad;
};

struct xen_pmu_data {
	uint32_t vcpu_id;
	uint32_t pcpu_id;
	domid_t domain_id;
	uint8_t pad[6];
	struct xen_pmu_arch pmu;
};

struct perf_guest_info_callbacks {
	unsigned int (*state)();
	long unsigned int (*get_ip)();
	unsigned int (*handle_intel_pt_intr)();
};

struct xenpmu {
	struct xen_pmu_data *xenpmu_data;
	uint8_t flags;
};

enum pg_level {
	PG_LEVEL_NONE = 0,
	PG_LEVEL_4K = 1,
	PG_LEVEL_2M = 2,
	PG_LEVEL_1G = 3,
	PG_LEVEL_512G = 4,
	PG_LEVEL_NUM = 5,
};

typedef uint32_t grant_ref_t;

typedef uint32_t grant_handle_t;

struct gnttab_map_grant_ref {
	uint64_t host_addr;
	uint32_t flags;
	grant_ref_t ref;
	domid_t dom;
	int16_t status;
	grant_handle_t handle;
	uint64_t dev_bus_addr;
};

struct gnttab_unmap_grant_ref {
	uint64_t host_addr;
	uint64_t dev_bus_addr;
	grant_handle_t handle;
	int16_t status;
};

enum {
	DESC_TSS = 9,
	DESC_LDT = 2,
	DESCTYPE_S = 16,
};

enum paravirt_lazy_mode {
	PARAVIRT_LAZY_NONE = 0,
	PARAVIRT_LAZY_MMU = 1,
	PARAVIRT_LAZY_CPU = 2,
};

struct x86_hw_tss {
	u32 reserved1;
	u64 sp0;
	u64 sp1;
	u64 sp2;
	u64 reserved2;
	u64 ist[7];
	u32 reserved3;
	u32 reserved4;
	u16 reserved5;
	u16 io_bitmap_base;
} __attribute__((packed));

struct x86_io_bitmap {
	u64 prev_sequence;
	unsigned int prev_max;
	long unsigned int bitmap[1025];
	long unsigned int mapall[1025];
};

struct tss_struct {
	struct x86_hw_tss x86_tss;
	struct x86_io_bitmap io_bitmap;
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

struct plist_head {
	struct list_head node_list;
};

enum pm_qos_type {
	PM_QOS_UNITIALIZED = 0,
	PM_QOS_MAX = 1,
	PM_QOS_MIN = 2,
};

struct pm_qos_constraints {
	struct plist_head list;
	s32 target_value;
	s32 default_value;
	s32 no_constraint_value;
	enum pm_qos_type type;
	struct blocking_notifier_head *notifiers;
};

struct freq_constraints {
	struct pm_qos_constraints min_freq;
	struct blocking_notifier_head min_freq_notifiers;
	struct pm_qos_constraints max_freq;
	struct blocking_notifier_head max_freq_notifiers;
};

struct pm_qos_flags {
	struct list_head list;
	s32 effective_flags;
};

struct dev_pm_qos_request;

struct dev_pm_qos {
	struct pm_qos_constraints resume_latency;
	struct pm_qos_constraints latency_tolerance;
	struct freq_constraints freq;
	struct pm_qos_flags flags;
	struct dev_pm_qos_request *resume_latency_req;
	struct dev_pm_qos_request *latency_tolerance_req;
	struct dev_pm_qos_request *flags_req;
};

union text_poke_insn {
	u8 text[5];
	struct {
		u8 opcode;
		s32 disp;
	} __attribute__((packed));
};

typedef long int xen_long_t;

struct trap_info {
	uint8_t vector;
	uint8_t flags;
	uint16_t cs;
	long unsigned int address;
};

struct mmuext_op {
	unsigned int cmd;
	union {
		xen_pfn_t mfn;
		long unsigned int linear_addr;
	} arg1;
	union {
		unsigned int nr_ents;
		void *vcpumask;
		xen_pfn_t src_mfn;
	} arg2;
};

struct multicall_entry {
	xen_ulong_t op;
	xen_long_t result;
	xen_ulong_t args[6];
};

struct dom0_vga_console_info {
	uint8_t video_type;
	union {
		struct {
			uint16_t font_height;
			uint16_t cursor_x;
			uint16_t cursor_y;
			uint16_t rows;
			uint16_t columns;
		} text_mode_3;
		struct {
			uint16_t width;
			uint16_t height;
			uint16_t bytes_per_line;
			uint16_t bits_per_pixel;
			uint32_t lfb_base;
			uint32_t lfb_size;
			uint8_t red_pos;
			uint8_t red_size;
			uint8_t green_pos;
			uint8_t green_size;
			uint8_t blue_pos;
			uint8_t blue_size;
			uint8_t rsvd_pos;
			uint8_t rsvd_size;
			uint32_t gbl_caps;
			uint16_t mode_attrs;
			uint16_t pad;
			uint32_t ext_lfb_base;
		} vesa_lfb;
	} u;
};

struct physdev_set_iopl {
	uint32_t iopl;
};

struct physdev_set_iobitmap {
	uint8_t *bitmap;
	uint32_t nr_ports;
};

struct pm_qos_flags_request {
	struct list_head node;
	s32 flags;
};

enum freq_qos_req_type {
	FREQ_QOS_MIN = 1,
	FREQ_QOS_MAX = 2,
};

struct freq_qos_request {
	enum freq_qos_req_type type;
	struct plist_node pnode;
	struct freq_constraints *qos;
};

enum dev_pm_qos_req_type {
	DEV_PM_QOS_RESUME_LATENCY = 1,
	DEV_PM_QOS_LATENCY_TOLERANCE = 2,
	DEV_PM_QOS_MIN_FREQUENCY = 3,
	DEV_PM_QOS_MAX_FREQUENCY = 4,
	DEV_PM_QOS_FLAGS = 5,
};

struct dev_pm_qos_request {
	enum dev_pm_qos_req_type type;
	union {
		struct plist_node pnode;
		struct pm_qos_flags_request flr;
		struct freq_qos_request freq;
	} data;
	struct device *dev;
};

struct multicall_space {
	struct multicall_entry *mc;
	void *args;
};

struct tls_descs {
	struct desc_struct desc[3];
};

struct trap_array_entry {
	void (*orig)();
	void (*xen)();
	bool ist_okay;
};

struct mmu_gather_batch {
	struct mmu_gather_batch *next;
	unsigned int nr;
	unsigned int max;
	struct page *pages[0];
};

struct mmu_table_batch;

struct mmu_gather {
	struct mm_struct *mm;
	struct mmu_table_batch *batch;
	long unsigned int start;
	long unsigned int end;
	unsigned int fullmm: 1;
	unsigned int need_flush_all: 1;
	unsigned int freed_tables: 1;
	unsigned int cleared_ptes: 1;
	unsigned int cleared_pmds: 1;
	unsigned int cleared_puds: 1;
	unsigned int cleared_p4ds: 1;
	unsigned int vma_exec: 1;
	unsigned int vma_huge: 1;
	unsigned int batch_count;
	struct mmu_gather_batch *active;
	struct mmu_gather_batch local;
	struct page *__pages[8];
};

struct io_tlb_slot;

struct io_tlb_mem {
	phys_addr_t start;
	phys_addr_t end;
	void *vaddr;
	long unsigned int nslabs;
	long unsigned int used;
	unsigned int index;
	spinlock_t lock;
	struct dentry *debugfs;
	bool late_alloc;
	bool force_bounce;
	bool for_alloc;
	struct io_tlb_slot *slots;
};

struct mmu_table_batch {
	struct callback_head rcu;
	unsigned int nr;
	void *tables[0];
};

struct xen_memory_exchange {
	struct xen_memory_reservation in;
	struct xen_memory_reservation out;
	xen_ulong_t nr_exchanged;
};

struct xen_machphys_mapping {
	xen_ulong_t v_start;
	xen_ulong_t v_end;
	xen_ulong_t max_mfn;
};

struct io_tlb_slot {
	phys_addr_t orig_addr;
	size_t alloc_size;
	unsigned int list;
};

enum pt_level {
	PT_PGD = 0,
	PT_P4D = 1,
	PT_PUD = 2,
	PT_PMD = 3,
	PT_PTE = 4,
};

struct remap_data {
	xen_pfn_t *pfn;
	bool contiguous;
	bool no_translate;
	pgprot_t prot;
	struct mmu_update *mmu_update;
};

enum xen_mc_flush_reason {
	XEN_MC_FL_NONE = 0,
	XEN_MC_FL_BATCH = 1,
	XEN_MC_FL_ARGS = 2,
	XEN_MC_FL_CALLBACK = 3,
};

enum xen_mc_extend_args {
	XEN_MC_XE_OK = 0,
	XEN_MC_XE_BAD_OP = 1,
	XEN_MC_XE_NO_SPACE = 2,
};

typedef void (*xen_mc_callback_fn_t)(void *);

struct callback {
	void (*fn)(void *);
	void *data;
};

struct mc_buffer {
	unsigned int mcidx;
	unsigned int argidx;
	unsigned int cbidx;
	struct multicall_entry entries[32];
	unsigned char args[512];
	struct callback callbacks[32];
};

struct hvm_start_info {
	uint32_t magic;
	uint32_t version;
	uint32_t flags;
	uint32_t nr_modules;
	uint64_t modlist_paddr;
	uint64_t cmdline_paddr;
	uint64_t rsdp_paddr;
	uint64_t memmap_paddr;
	uint32_t memmap_entries;
	uint32_t reserved;
};

struct trace_event_raw_xen_mc__batch {
	struct trace_entry ent;
	enum paravirt_lazy_mode mode;
	char __data[0];
};

struct trace_event_raw_xen_mc_entry {
	struct trace_entry ent;
	unsigned int op;
	unsigned int nargs;
	long unsigned int args[6];
	char __data[0];
};

struct trace_event_raw_xen_mc_entry_alloc {
	struct trace_entry ent;
	size_t args;
	char __data[0];
};

struct trace_event_raw_xen_mc_callback {
	struct trace_entry ent;
	xen_mc_callback_fn_t fn;
	void *data;
	char __data[0];
};

struct trace_event_raw_xen_mc_flush_reason {
	struct trace_entry ent;
	enum xen_mc_flush_reason reason;
	char __data[0];
};

struct trace_event_raw_xen_mc_flush {
	struct trace_entry ent;
	unsigned int mcidx;
	unsigned int argidx;
	unsigned int cbidx;
	char __data[0];
};

struct trace_event_raw_xen_mc_extend_args {
	struct trace_entry ent;
	unsigned int op;
	size_t args;
	enum xen_mc_extend_args res;
	char __data[0];
};

struct trace_event_raw_xen_mmu__set_pte {
	struct trace_entry ent;
	pte_t *ptep;
	pteval_t pteval;
	char __data[0];
};

struct trace_event_raw_xen_mmu_set_pmd {
	struct trace_entry ent;
	pmd_t *pmdp;
	pmdval_t pmdval;
	char __data[0];
};

struct trace_event_raw_xen_mmu_set_pud {
	struct trace_entry ent;
	pud_t *pudp;
	pudval_t pudval;
	char __data[0];
};

struct trace_event_raw_xen_mmu_set_p4d {
	struct trace_entry ent;
	p4d_t *p4dp;
	p4d_t *user_p4dp;
	p4dval_t p4dval;
	char __data[0];
};

struct trace_event_raw_xen_mmu_ptep_modify_prot {
	struct trace_entry ent;
	struct mm_struct *mm;
	long unsigned int addr;
	pte_t *ptep;
	pteval_t pteval;
	char __data[0];
};

struct trace_event_raw_xen_mmu_alloc_ptpage {
	struct trace_entry ent;
	struct mm_struct *mm;
	long unsigned int pfn;
	unsigned int level;
	bool pinned;
	char __data[0];
};

struct trace_event_raw_xen_mmu_release_ptpage {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int level;
	bool pinned;
	char __data[0];
};

struct trace_event_raw_xen_mmu_pgd {
	struct trace_entry ent;
	struct mm_struct *mm;
	pgd_t *pgd;
	char __data[0];
};

struct trace_event_raw_xen_mmu_flush_tlb_one_user {
	struct trace_entry ent;
	long unsigned int addr;
	char __data[0];
};

struct trace_event_raw_xen_mmu_flush_tlb_multi {
	struct trace_entry ent;
	unsigned int ncpus;
	struct mm_struct *mm;
	long unsigned int addr;
	long unsigned int end;
	char __data[0];
};

struct trace_event_raw_xen_mmu_write_cr3 {
	struct trace_entry ent;
	bool kernel;
	long unsigned int cr3;
	char __data[0];
};

struct trace_event_raw_xen_cpu_write_ldt_entry {
	struct trace_entry ent;
	struct desc_struct *dt;
	int entrynum;
	u64 desc;
	char __data[0];
};

struct trace_event_raw_xen_cpu_write_idt_entry {
	struct trace_entry ent;
	gate_desc *dt;
	int entrynum;
	char __data[0];
};

struct trace_event_raw_xen_cpu_load_idt {
	struct trace_entry ent;
	long unsigned int addr;
	char __data[0];
};

struct trace_event_raw_xen_cpu_write_gdt_entry {
	struct trace_entry ent;
	u64 desc;
	struct desc_struct *dt;
	int entrynum;
	int type;
	char __data[0];
};

struct trace_event_raw_xen_cpu_set_ldt {
	struct trace_entry ent;
	const void *addr;
	unsigned int entries;
	char __data[0];
};

struct trace_event_data_offsets_xen_mc__batch {};

struct trace_event_data_offsets_xen_mc_entry {};

struct trace_event_data_offsets_xen_mc_entry_alloc {};

struct trace_event_data_offsets_xen_mc_callback {};

struct trace_event_data_offsets_xen_mc_flush_reason {};

struct trace_event_data_offsets_xen_mc_flush {};

struct trace_event_data_offsets_xen_mc_extend_args {};

struct trace_event_data_offsets_xen_mmu__set_pte {};

struct trace_event_data_offsets_xen_mmu_set_pmd {};

struct trace_event_data_offsets_xen_mmu_set_pud {};

struct trace_event_data_offsets_xen_mmu_set_p4d {};

struct trace_event_data_offsets_xen_mmu_ptep_modify_prot {};

struct trace_event_data_offsets_xen_mmu_alloc_ptpage {};

struct trace_event_data_offsets_xen_mmu_release_ptpage {};

struct trace_event_data_offsets_xen_mmu_pgd {};

struct trace_event_data_offsets_xen_mmu_flush_tlb_one_user {};

struct trace_event_data_offsets_xen_mmu_flush_tlb_multi {};

struct trace_event_data_offsets_xen_mmu_write_cr3 {};

struct trace_event_data_offsets_xen_cpu_write_ldt_entry {};

struct trace_event_data_offsets_xen_cpu_write_idt_entry {};

struct trace_event_data_offsets_xen_cpu_load_idt {};

struct trace_event_data_offsets_xen_cpu_write_gdt_entry {};

struct trace_event_data_offsets_xen_cpu_set_ldt {};

typedef void (*btf_trace_xen_mc_batch)(void *, enum paravirt_lazy_mode);

typedef void (*btf_trace_xen_mc_issue)(void *, enum paravirt_lazy_mode);

typedef void (*btf_trace_xen_mc_entry)(void *, struct multicall_entry *, unsigned int);

typedef void (*btf_trace_xen_mc_entry_alloc)(void *, size_t);

typedef void (*btf_trace_xen_mc_callback)(void *, xen_mc_callback_fn_t, void *);

typedef void (*btf_trace_xen_mc_flush_reason)(void *, enum xen_mc_flush_reason);

typedef void (*btf_trace_xen_mc_flush)(void *, unsigned int, unsigned int, unsigned int);

typedef void (*btf_trace_xen_mc_extend_args)(void *, long unsigned int, size_t, enum xen_mc_extend_args);

typedef void (*btf_trace_xen_mmu_set_pte)(void *, pte_t *, pte_t);

typedef void (*btf_trace_xen_mmu_set_pmd)(void *, pmd_t *, pmd_t);

typedef void (*btf_trace_xen_mmu_set_pud)(void *, pud_t *, pud_t);

typedef void (*btf_trace_xen_mmu_set_p4d)(void *, p4d_t *, p4d_t *, p4d_t);

typedef void (*btf_trace_xen_mmu_ptep_modify_prot_start)(void *, struct mm_struct *, long unsigned int, pte_t *, pte_t);

typedef void (*btf_trace_xen_mmu_ptep_modify_prot_commit)(void *, struct mm_struct *, long unsigned int, pte_t *, pte_t);

typedef void (*btf_trace_xen_mmu_alloc_ptpage)(void *, struct mm_struct *, long unsigned int, unsigned int, bool);

typedef void (*btf_trace_xen_mmu_release_ptpage)(void *, long unsigned int, unsigned int, bool);

typedef void (*btf_trace_xen_mmu_pgd_pin)(void *, struct mm_struct *, pgd_t *);

typedef void (*btf_trace_xen_mmu_pgd_unpin)(void *, struct mm_struct *, pgd_t *);

typedef void (*btf_trace_xen_mmu_flush_tlb_one_user)(void *, long unsigned int);

typedef void (*btf_trace_xen_mmu_flush_tlb_multi)(void *, const struct cpumask *, struct mm_struct *, long unsigned int, long unsigned int);

typedef void (*btf_trace_xen_mmu_write_cr3)(void *, bool, long unsigned int);

typedef void (*btf_trace_xen_cpu_write_ldt_entry)(void *, struct desc_struct *, int, u64);

typedef void (*btf_trace_xen_cpu_write_idt_entry)(void *, gate_desc *, int, const gate_desc *);

typedef void (*btf_trace_xen_cpu_load_idt)(void *, const struct desc_ptr *);

typedef void (*btf_trace_xen_cpu_write_gdt_entry)(void *, struct desc_struct *, int, const void *, int);

typedef void (*btf_trace_xen_cpu_set_ldt)(void *, const void *, unsigned int);

enum ipi_vector {
	XEN_RESCHEDULE_VECTOR = 0,
	XEN_CALL_FUNCTION_VECTOR = 1,
	XEN_CALL_FUNCTION_SINGLE_VECTOR = 2,
	XEN_SPIN_UNLOCK_VECTOR = 3,
	XEN_IRQ_WORK_VECTOR = 4,
	XEN_NMI_VECTOR = 5,
	XEN_NR_IPIS = 6,
};

struct xen_common_irq {
	int irq;
	char *name;
};

struct cpu_user_regs {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	union {
		uint64_t rbp;
		uint64_t ebp;
		uint32_t _ebp;
	};
	union {
		uint64_t rbx;
		uint64_t ebx;
		uint32_t _ebx;
	};
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	union {
		uint64_t rax;
		uint64_t eax;
		uint32_t _eax;
	};
	union {
		uint64_t rcx;
		uint64_t ecx;
		uint32_t _ecx;
	};
	union {
		uint64_t rdx;
		uint64_t edx;
		uint32_t _edx;
	};
	union {
		uint64_t rsi;
		uint64_t esi;
		uint32_t _esi;
	};
	union {
		uint64_t rdi;
		uint64_t edi;
		uint32_t _edi;
	};
	uint32_t error_code;
	uint32_t entry_vector;
	union {
		uint64_t rip;
		uint64_t eip;
		uint32_t _eip;
	};
	uint16_t cs;
	uint16_t _pad0[1];
	uint8_t saved_upcall_mask;
	uint8_t _pad1[3];
	union {
		uint64_t rflags;
		uint64_t eflags;
		uint32_t _eflags;
	};
	union {
		uint64_t rsp;
		uint64_t esp;
		uint32_t _esp;
	};
	uint16_t ss;
	uint16_t _pad2[3];
	uint16_t es;
	uint16_t _pad3[3];
	uint16_t ds;
	uint16_t _pad4[3];
	uint16_t fs;
	uint16_t _pad5[3];
	uint16_t gs;
	uint16_t _pad6[3];
};

struct vcpu_guest_context {
	struct {
		char x[512];
	} fpu_ctxt;
	long unsigned int flags;
	struct cpu_user_regs user_regs;
	struct trap_info trap_ctxt[256];
	long unsigned int ldt_base;
	long unsigned int ldt_ents;
	long unsigned int gdt_frames[16];
	long unsigned int gdt_ents;
	long unsigned int kernel_ss;
	long unsigned int kernel_sp;
	long unsigned int ctrlreg[8];
	long unsigned int debugreg[8];
	long unsigned int event_callback_eip;
	long unsigned int failsafe_callback_eip;
	long unsigned int syscall_callback_eip;
	long unsigned int vm_assist;
	uint64_t fs_base;
	uint64_t gs_base_kernel;
	uint64_t gs_base_user;
};

union efi_boot_services;

typedef union efi_boot_services efi_boot_services_t;

typedef struct {
	efi_table_hdr_t hdr;
	u32 fw_vendor;
	u32 fw_revision;
	u32 con_in_handle;
	u32 con_in;
	u32 con_out_handle;
	u32 con_out;
	u32 stderr_handle;
	u32 stderr;
	u32 runtime;
	u32 boottime;
	u32 nr_tables;
	u32 tables;
} efi_system_table_32_t;

union efi_simple_text_input_protocol;

typedef union efi_simple_text_input_protocol efi_simple_text_input_protocol_t;

union efi_simple_text_output_protocol;

typedef union efi_simple_text_output_protocol efi_simple_text_output_protocol_t;

typedef union {
	struct {
		efi_table_hdr_t hdr;
		long unsigned int fw_vendor;
		u32 fw_revision;
		long unsigned int con_in_handle;
		efi_simple_text_input_protocol_t *con_in;
		long unsigned int con_out_handle;
		efi_simple_text_output_protocol_t *con_out;
		long unsigned int stderr_handle;
		long unsigned int stderr;
		efi_runtime_services_t *runtime;
		efi_boot_services_t *boottime;
		long unsigned int nr_tables;
		long unsigned int tables;
	};
	efi_system_table_32_t mixed_mode;
} efi_system_table_t;

enum efi_secureboot_mode {
	efi_secureboot_mode_unset = 0,
	efi_secureboot_mode_unknown = 1,
	efi_secureboot_mode_disabled = 2,
	efi_secureboot_mode_enabled = 3,
};

struct hvm_modlist_entry {
	uint64_t paddr;
	uint64_t size;
	uint64_t cmdline_paddr;
	uint64_t reserved;
};

struct hvm_memmap_table_entry {
	uint64_t addr;
	uint64_t size;
	uint32_t type;
	uint32_t reserved;
};

enum {
	WORK_STRUCT_PENDING_BIT = 0,
	WORK_STRUCT_INACTIVE_BIT = 1,
	WORK_STRUCT_PWQ_BIT = 2,
	WORK_STRUCT_LINKED_BIT = 3,
	WORK_STRUCT_COLOR_SHIFT = 4,
	WORK_STRUCT_COLOR_BITS = 4,
	WORK_STRUCT_PENDING = 1,
	WORK_STRUCT_INACTIVE = 2,
	WORK_STRUCT_PWQ = 4,
	WORK_STRUCT_LINKED = 8,
	WORK_STRUCT_STATIC = 0,
	WORK_NR_COLORS = 16,
	WORK_CPU_UNBOUND = 8192,
	WORK_STRUCT_FLAG_BITS = 8,
	WORK_OFFQ_FLAG_BASE = 4,
	__WORK_OFFQ_CANCELING = 4,
	WORK_OFFQ_CANCELING = 16,
	WORK_OFFQ_FLAG_BITS = 1,
	WORK_OFFQ_POOL_SHIFT = 5,
	WORK_OFFQ_LEFT = 59,
	WORK_OFFQ_POOL_BITS = 31,
	WORK_OFFQ_POOL_NONE = 2147483647,
	WORK_STRUCT_FLAG_MASK = 255,
	WORK_STRUCT_WQ_DATA_MASK = 4294967040,
	WORK_STRUCT_NO_POOL = 4294967264,
	WORK_BUSY_PENDING = 1,
	WORK_BUSY_RUNNING = 2,
	WORKER_DESC_LEN = 24,
};

enum {
	MEMREMAP_WB = 1,
	MEMREMAP_WT = 2,
	MEMREMAP_WC = 4,
	MEMREMAP_ENC = 8,
	MEMREMAP_DEC = 16,
};

union hv_x64_msr_hypercall_contents {
	u64 as_uint64;
	struct {
		u64 enable: 1;
		u64 reserved: 11;
		u64 guest_physical_address: 52;
	};
};

union hv_vp_assist_msr_contents {
	u64 as_uint64;
	struct {
		u64 enable: 1;
		u64 reserved: 11;
		u64 pfn: 52;
	};
};

struct hv_reenlightenment_control {
	__u64 vector: 8;
	__u64 reserved1: 8;
	__u64 enabled: 1;
	__u64 reserved2: 15;
	__u64 target_vp: 32;
};

struct hv_tsc_emulation_control {
	__u64 enabled: 1;
	__u64 reserved: 63;
};

struct hv_tsc_emulation_status {
	__u64 inprogress: 1;
	__u64 reserved: 63;
};

struct hv_nested_enlightenments_control {
	struct {
		__u32 directhypercall: 1;
		__u32 reserved: 31;
	} features;
	struct {
		__u32 reserved;
	} hypercallControls;
};

struct hv_vp_assist_page {
	__u32 apic_assist;
	__u32 reserved1;
	__u64 vtl_control[3];
	struct hv_nested_enlightenments_control nested_control;
	__u8 enlighten_vmentry;
	__u8 reserved2[7];
	__u64 current_nested_vmcs;
};

struct hv_get_partition_id {
	u64 partition_id;
};

union hv_ghcb;

struct ms_hyperv_info {
	u32 features;
	u32 priv_high;
	u32 misc_features;
	u32 hints;
	u32 nested_features;
	u32 max_vp_index;
	u32 max_lp_index;
	u32 isolation_config_a;
	union {
		u32 isolation_config_b;
		struct {
			u32 cvm_type: 4;
			u32 reserved1: 1;
			u32 shared_gpa_boundary_active: 1;
			u32 shared_gpa_boundary_bits: 6;
			u32 reserved2: 20;
		};
	};
	u64 shared_gpa_boundary;
};

enum HV_GENERIC_SET_FORMAT {
	HV_GENERIC_SET_SPARSE_4K = 0,
	HV_GENERIC_SET_ALL = 1,
};

struct hv_vpset {
	u64 format;
	u64 valid_bank_mask;
	u64 bank_contents[0];
};

struct hv_tlb_flush {
	u64 address_space;
	u64 flags;
	u64 processor_mask;
	u64 gva_list[0];
};

struct hv_tlb_flush_ex {
	u64 address_space;
	u64 flags;
	struct hv_vpset hv_vp_set;
	u64 gva_list[0];
};

struct trace_event_raw_hyperv_mmu_flush_tlb_multi {
	struct trace_entry ent;
	unsigned int ncpus;
	struct mm_struct *mm;
	long unsigned int addr;
	long unsigned int end;
	char __data[0];
};

struct trace_event_raw_hyperv_nested_flush_guest_mapping {
	struct trace_entry ent;
	u64 as;
	int ret;
	char __data[0];
};

struct trace_event_raw_hyperv_nested_flush_guest_mapping_range {
	struct trace_entry ent;
	u64 as;
	int ret;
	char __data[0];
};

struct trace_event_raw_hyperv_send_ipi_mask {
	struct trace_entry ent;
	unsigned int ncpus;
	int vector;
	char __data[0];
};

struct trace_event_raw_hyperv_send_ipi_one {
	struct trace_entry ent;
	int cpu;
	int vector;
	char __data[0];
};

struct trace_event_data_offsets_hyperv_mmu_flush_tlb_multi {};

struct trace_event_data_offsets_hyperv_nested_flush_guest_mapping {};

struct trace_event_data_offsets_hyperv_nested_flush_guest_mapping_range {};

struct trace_event_data_offsets_hyperv_send_ipi_mask {};

struct trace_event_data_offsets_hyperv_send_ipi_one {};

typedef void (*btf_trace_hyperv_mmu_flush_tlb_multi)(void *, const struct cpumask *, const struct flush_tlb_info *);

typedef void (*btf_trace_hyperv_nested_flush_guest_mapping)(void *, u64, int);

typedef void (*btf_trace_hyperv_nested_flush_guest_mapping_range)(void *, u64, int);

typedef void (*btf_trace_hyperv_send_ipi_mask)(void *, const struct cpumask *, int);

typedef void (*btf_trace_hyperv_send_ipi_one)(void *, int, int);

struct hv_guest_mapping_flush {
	u64 address_space;
	u64 flags;
};

union hv_gpa_page_range {
	u64 address_space;
	struct {
		u64 additional_pages: 11;
		u64 largepage: 1;
		u64 basepfn: 52;
	} page;
	struct {
		u64 reserved: 12;
		u64 page_size: 1;
		u64 reserved1: 8;
		u64 base_large_pfn: 43;
	};
};

struct hv_guest_mapping_flush_list {
	u64 address_space;
	u64 flags;
	union hv_gpa_page_range gpa_list[510];
};

typedef int (*hyperv_fill_flush_list_func)(struct hv_guest_mapping_flush_list *, void *);

enum {
	IRQCHIP_SET_TYPE_MASKED = 1,
	IRQCHIP_EOI_IF_HANDLED = 2,
	IRQCHIP_MASK_ON_SUSPEND = 4,
	IRQCHIP_ONOFFLINE_ENABLED = 8,
	IRQCHIP_SKIP_SET_WAKE = 16,
	IRQCHIP_ONESHOT_SAFE = 32,
	IRQCHIP_EOI_THREADED = 64,
	IRQCHIP_SUPPORTS_LEVEL_MSI = 128,
	IRQCHIP_SUPPORTS_NMI = 256,
	IRQCHIP_ENABLE_WAKEUP_ON_SUSPEND = 512,
	IRQCHIP_AFFINITY_PRE_STARTUP = 1024,
	IRQCHIP_IMMUTABLE = 2048,
};

enum irq_alloc_type {
	X86_IRQ_ALLOC_TYPE_IOAPIC = 1,
	X86_IRQ_ALLOC_TYPE_HPET = 2,
	X86_IRQ_ALLOC_TYPE_PCI_MSI = 3,
	X86_IRQ_ALLOC_TYPE_PCI_MSIX = 4,
	X86_IRQ_ALLOC_TYPE_DMAR = 5,
	X86_IRQ_ALLOC_TYPE_AMDVI = 6,
	X86_IRQ_ALLOC_TYPE_UV = 7,
};

struct ioapic_alloc_info {
	int pin;
	int node;
	u32 is_level: 1;
	u32 active_low: 1;
	u32 valid: 1;
};

struct uv_alloc_info {
	int limit;
	int blade;
	long unsigned int offset;
	char *name;
};

struct irq_alloc_info {
	enum irq_alloc_type type;
	u32 flags;
	u32 devid;
	irq_hw_number_t hwirq;
	const struct cpumask *mask;
	struct msi_desc *desc;
	void *data;
	union {
		struct ioapic_alloc_info ioapic;
		struct uv_alloc_info uv;
	};
};

struct irq_cfg {
	unsigned int dest_apicid;
	unsigned int vector;
};

enum {
	IRQCHIP_FWNODE_REAL = 0,
	IRQCHIP_FWNODE_NAMED = 1,
	IRQCHIP_FWNODE_NAMED_ID = 2,
};

typedef struct irq_alloc_info msi_alloc_info_t;

struct msi_domain_info;

struct msi_domain_ops {
	irq_hw_number_t (*get_hwirq)(struct msi_domain_info *, msi_alloc_info_t *);
	int (*msi_init)(struct irq_domain *, struct msi_domain_info *, unsigned int, irq_hw_number_t, msi_alloc_info_t *);
	void (*msi_free)(struct irq_domain *, struct msi_domain_info *, unsigned int);
	int (*msi_check)(struct irq_domain *, struct msi_domain_info *, struct device *);
	int (*msi_prepare)(struct irq_domain *, struct device *, int, msi_alloc_info_t *);
	void (*set_desc)(msi_alloc_info_t *, struct msi_desc *);
	int (*domain_alloc_irqs)(struct irq_domain *, struct device *, int);
	void (*domain_free_irqs)(struct irq_domain *, struct device *);
};

struct msi_domain_info {
	u32 flags;
	struct msi_domain_ops *ops;
	struct irq_chip *chip;
	void *chip_data;
	irq_flow_handler_t handler;
	void *handler_data;
	const char *handler_name;
	void *data;
};

enum {
	MSI_FLAG_USE_DEF_DOM_OPS = 1,
	MSI_FLAG_USE_DEF_CHIP_OPS = 2,
	MSI_FLAG_MULTI_PCI_MSI = 4,
	MSI_FLAG_PCI_MSIX = 8,
	MSI_FLAG_ACTIVATE_EARLY = 16,
	MSI_FLAG_MUST_REACTIVATE = 32,
	MSI_FLAG_LEVEL_CAPABLE = 64,
	MSI_FLAG_DEV_SYSFS = 128,
	MSI_FLAG_MSIX_CONTIGUOUS = 256,
	MSI_FLAG_ALLOC_SIMPLE_MSI_DESCS = 512,
	MSI_FLAG_FREE_MSI_DESCS = 1024,
};

enum hv_interrupt_type {
	HV_X64_INTERRUPT_TYPE_FIXED = 0,
	HV_X64_INTERRUPT_TYPE_LOWESTPRIORITY = 1,
	HV_X64_INTERRUPT_TYPE_SMI = 2,
	HV_X64_INTERRUPT_TYPE_REMOTEREAD = 3,
	HV_X64_INTERRUPT_TYPE_NMI = 4,
	HV_X64_INTERRUPT_TYPE_INIT = 5,
	HV_X64_INTERRUPT_TYPE_SIPI = 6,
	HV_X64_INTERRUPT_TYPE_EXTINT = 7,
	HV_X64_INTERRUPT_TYPE_LOCALINT0 = 8,
	HV_X64_INTERRUPT_TYPE_LOCALINT1 = 9,
	HV_X64_INTERRUPT_TYPE_MAXIMUM = 10,
};

union hv_msi_address_register {
	u32 as_uint32;
	struct {
		u32 reserved1: 2;
		u32 destination_mode: 1;
		u32 redirection_hint: 1;
		u32 reserved2: 8;
		u32 destination_id: 8;
		u32 msi_base: 12;
	};
};

union hv_msi_data_register {
	u32 as_uint32;
	struct {
		u32 vector: 8;
		u32 delivery_mode: 3;
		u32 reserved1: 3;
		u32 level_assert: 1;
		u32 trigger_mode: 1;
		u32 reserved2: 16;
	};
};

union hv_msi_entry {
	u64 as_uint64;
	struct {
		union hv_msi_address_register address;
		union hv_msi_data_register data;
	};
};

union hv_ioapic_rte {
	u64 as_uint64;
	struct {
		u32 vector: 8;
		u32 delivery_mode: 3;
		u32 destination_mode: 1;
		u32 delivery_status: 1;
		u32 interrupt_polarity: 1;
		u32 remote_irr: 1;
		u32 trigger_mode: 1;
		u32 interrupt_mask: 1;
		u32 reserved1: 15;
		u32 reserved2: 24;
		u32 destination_id: 8;
	};
	struct {
		u32 low_uint32;
		u32 high_uint32;
	};
};

struct hv_interrupt_entry {
	u32 source;
	u32 reserved1;
	union {
		union hv_msi_entry msi_entry;
		union hv_ioapic_rte ioapic_rte;
	};
};

struct hv_device_interrupt_target {
	u32 vector;
	u32 flags;
	union {
		u64 vp_mask;
		struct hv_vpset vp_set;
	};
};

enum hv_device_type {
	HV_DEVICE_TYPE_LOGICAL = 0,
	HV_DEVICE_TYPE_PCI = 1,
	HV_DEVICE_TYPE_IOAPIC = 2,
	HV_DEVICE_TYPE_ACPI = 3,
};

typedef u16 hv_pci_rid;

typedef u16 hv_pci_segment;

union hv_pci_bdf {
	u16 as_uint16;
	struct {
		u8 function: 3;
		u8 device: 5;
		u8 bus;
	};
};

union hv_pci_bus_range {
	u16 as_uint16;
	struct {
		u8 subordinate_bus;
		u8 secondary_bus;
	};
};

union hv_device_id {
	u64 as_uint64;
	struct {
		u64 reserved0: 62;
		u64 device_type: 2;
	};
	struct {
		u64 id: 62;
		u64 device_type: 2;
	} logical;
	struct {
		union {
			hv_pci_rid rid;
			union hv_pci_bdf bdf;
		};
		hv_pci_segment segment;
		union hv_pci_bus_range shadow_bus_range;
		u16 phantom_function_bits: 2;
		u16 source_shadow: 1;
		u16 rsvdz0: 11;
		u16 device_type: 2;
	} pci;
	struct {
		u8 ioapic_id;
		u8 rsvdz0;
		u16 rsvdz1;
		u16 rsvdz2;
		u16 rsvdz3: 14;
		u16 device_type: 2;
	} ioapic;
	struct {
		u32 input_mapping_base;
		u32 input_mapping_count: 30;
		u32 device_type: 2;
	} acpi;
};

enum hv_interrupt_trigger_mode {
	HV_INTERRUPT_TRIGGER_MODE_EDGE = 0,
	HV_INTERRUPT_TRIGGER_MODE_LEVEL = 1,
};

struct hv_device_interrupt_descriptor {
	u32 interrupt_type;
	u32 trigger_mode;
	u32 vector_count;
	u32 reserved;
	struct hv_device_interrupt_target target;
};

struct hv_input_map_device_interrupt {
	u64 partition_id;
	u64 device_id;
	u64 flags;
	struct hv_interrupt_entry logical_interrupt_entry;
	struct hv_device_interrupt_descriptor interrupt_descriptor;
};

struct hv_output_map_device_interrupt {
	struct hv_interrupt_entry interrupt_entry;
};

struct hv_input_unmap_device_interrupt {
	u64 partition_id;
	u64 device_id;
	struct hv_interrupt_entry interrupt_entry;
};

struct rid_data {
	struct pci_dev *bridge;
	u32 rid;
};

struct ghcb_save_area {
	u8 reserved_1[203];
	u8 cpl;
	u8 reserved_2[116];
	u64 xss;
	u8 reserved_3[24];
	u64 dr7;
	u8 reserved_4[16];
	u64 rip;
	u8 reserved_5[88];
	u64 rsp;
	u8 reserved_6[24];
	u64 rax;
	u8 reserved_7[264];
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u8 reserved_8[8];
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u8 reserved_9[16];
	u64 sw_exit_code;
	u64 sw_exit_info_1;
	u64 sw_exit_info_2;
	u64 sw_scratch;
	u8 reserved_10[56];
	u64 xcr0;
	u8 valid_bitmap[16];
	u64 x87_state_gpa;
};

struct ghcb {
	struct ghcb_save_area save;
	u8 reserved_save[1016];
	u8 shared_buffer[2032];
	u8 reserved_1[10];
	u16 protocol_version;
	u32 ghcb_usage;
};

enum hv_isolation_type {
	HV_ISOLATION_TYPE_NONE = 0,
	HV_ISOLATION_TYPE_VBS = 1,
	HV_ISOLATION_TYPE_SNP = 2,
};

enum hv_mem_host_visibility {
	VMBUS_PAGE_NOT_VISIBLE = 0,
	VMBUS_PAGE_VISIBLE_READ_ONLY = 1,
	VMBUS_PAGE_VISIBLE_READ_WRITE = 3,
};

struct hv_gpa_range_for_visibility {
	u64 partition_id;
	u32 host_visibility: 2;
	u32 reserved0: 30;
	u32 reserved1;
	u64 gpa_page_list[510];
};

enum intercept_words {
	INTERCEPT_CR = 0,
	INTERCEPT_DR = 1,
	INTERCEPT_EXCEPTION = 2,
	INTERCEPT_WORD3 = 3,
	INTERCEPT_WORD4 = 4,
	INTERCEPT_WORD5 = 5,
	MAX_INTERCEPT = 6,
};

struct es_fault_info {
	long unsigned int vector;
	long unsigned int error_code;
	long unsigned int cr2;
};

struct es_em_ctxt {
	struct pt_regs *regs;
	struct insn insn;
	struct es_fault_info fi;
};

union hv_ghcb___2 {
	struct ghcb ghcb;
	struct {
		u64 hypercalldata[509];
		u64 outputgpa;
		union {
			union {
				struct {
					u32 callcode: 16;
					u32 isfast: 1;
					u32 reserved1: 14;
					u32 isnested: 1;
					u32 countofelements: 12;
					u32 reserved2: 4;
					u32 repstartindex: 12;
					u32 reserved3: 4;
				};
				u64 asuint64;
			} hypercallinput;
			union {
				struct {
					u16 callstatus;
					u16 reserved1;
					u32 elementsprocessed: 12;
					u32 reserved2: 20;
				};
				u64 asunit64;
			} hypercalloutput;
		};
		u64 reserved2;
	} hypercall;
};

struct hv_send_ipi {
	u32 vector;
	u32 reserved;
	u64 cpu_mask;
};

struct hv_send_ipi_ex {
	u32 vector;
	u32 reserved;
	struct hv_vpset vp_set;
};

struct hv_deposit_memory {
	u64 partition_id;
	u64 gpa_page_list[0];
};

struct hv_proximity_domain_flags {
	u32 proximity_preferred: 1;
	u32 reserved: 30;
	u32 proximity_info_valid: 1;
};

union hv_proximity_domain_info {
	struct {
		u32 domain_id;
		struct hv_proximity_domain_flags flags;
	};
	u64 as_uint64;
};

struct hv_lp_startup_status {
	u64 hv_status;
	u64 substatus1;
	u64 substatus2;
	u64 substatus3;
	u64 substatus4;
	u64 substatus5;
	u64 substatus6;
};

struct hv_add_logical_processor_in {
	u32 lp_index;
	u32 apic_id;
	union hv_proximity_domain_info proximity_domain_info;
	u64 flags;
};

struct hv_add_logical_processor_out {
	struct hv_lp_startup_status startup_status;
};

enum HV_SUBNODE_TYPE {
	HvSubnodeAny = 0,
	HvSubnodeSocket = 1,
	HvSubnodeAmdNode = 2,
	HvSubnodeL3 = 3,
	HvSubnodeCount = 4,
	HvSubnodeInvalid = 4294967295,
};

struct hv_create_vp {
	u64 partition_id;
	u32 vp_index;
	u8 padding[3];
	u8 subnode_type;
	u64 subnode_id;
	union hv_proximity_domain_info proximity_domain_info;
	u64 flags;
};

struct real_mode_header {
	u32 text_start;
	u32 ro_end;
	u32 trampoline_start;
	u32 trampoline_header;
	u32 sev_es_trampoline_start;
	u32 trampoline_start64;
	u32 trampoline_pgd;
	u32 wakeup_start;
	u32 wakeup_header;
	u32 machine_real_restart_asm;
	u32 machine_real_restart_seg;
};

struct trampoline_header {
	u64 start;
	u64 efer;
	u32 cr4;
	u32 flags;
};

enum show_regs_mode {
	SHOW_REGS_SHORT = 0,
	SHOW_REGS_USER = 1,
	SHOW_REGS_ALL = 2,
};

struct resctrl_pqr_state {
	u32 cur_rmid;
	u32 cur_closid;
	u32 default_rmid;
	u32 default_closid;
};

enum which_selector {
	FS = 0,
	GS = 1,
};

struct sigcontext_64 {
	__u64 r8;
	__u64 r9;
	__u64 r10;
	__u64 r11;
	__u64 r12;
	__u64 r13;
	__u64 r14;
	__u64 r15;
	__u64 di;
	__u64 si;
	__u64 bp;
	__u64 bx;
	__u64 dx;
	__u64 ax;
	__u64 cx;
	__u64 sp;
	__u64 ip;
	__u64 flags;
	__u16 cs;
	__u16 gs;
	__u16 fs;
	__u16 ss;
	__u64 err;
	__u64 trapno;
	__u64 oldmask;
	__u64 cr2;
	__u64 fpstate;
	__u64 reserved1[8];
};

struct sigaltstack {
	void *ss_sp;
	int ss_flags;
	__kernel_size_t ss_size;
};

typedef struct sigaltstack stack_t;

struct siginfo {
	union {
		struct {
			int si_signo;
			int si_errno;
			int si_code;
			union __sifields _sifields;
		};
		int _si_pad[32];
	};
};

struct ksignal {
	struct k_sigaction ka;
	kernel_siginfo_t info;
	int sig;
};

struct __large_struct {
	long unsigned int buf[100];
};

typedef u32 compat_sigset_word;

typedef struct {
	compat_sigset_word sig[2];
} compat_sigset_t;

struct ucontext {
	long unsigned int uc_flags;
	struct ucontext *uc_link;
	stack_t uc_stack;
	struct sigcontext_64 uc_mcontext;
	sigset_t uc_sigmask;
};

struct kernel_vm86_regs {
	struct pt_regs pt;
	short unsigned int es;
	short unsigned int __esh;
	short unsigned int ds;
	short unsigned int __dsh;
	short unsigned int fs;
	short unsigned int __fsh;
	short unsigned int gs;
	short unsigned int __gsh;
};

struct rt_sigframe {
	char *pretcode;
	struct ucontext uc;
	struct siginfo info;
};

typedef struct siginfo siginfo_t;

typedef s32 compat_clock_t;

typedef s32 compat_pid_t;

typedef s32 compat_timer_t;

typedef s32 compat_int_t;

typedef u32 compat_ulong_t;

typedef u32 __compat_uid32_t;

union compat_sigval {
	compat_int_t sival_int;
	compat_uptr_t sival_ptr;
};

typedef union compat_sigval compat_sigval_t;

struct compat_siginfo {
	int si_signo;
	int si_errno;
	int si_code;
	union {
		int _pad[29];
		struct {
			compat_pid_t _pid;
			__compat_uid32_t _uid;
		} _kill;
		struct {
			compat_timer_t _tid;
			int _overrun;
			compat_sigval_t _sigval;
		} _timer;
		struct {
			compat_pid_t _pid;
			__compat_uid32_t _uid;
			compat_sigval_t _sigval;
		} _rt;
		struct {
			compat_pid_t _pid;
			__compat_uid32_t _uid;
			int _status;
			compat_clock_t _utime;
			compat_clock_t _stime;
		} _sigchld;
		struct {
			compat_uptr_t _addr;
			union {
				int _trapno;
				short int _addr_lsb;
				struct {
					char _dummy_bnd[4];
					compat_uptr_t _lower;
					compat_uptr_t _upper;
				} _addr_bnd;
				struct {
					char _dummy_pkey[4];
					u32 _pkey;
				} _addr_pkey;
				struct {
					compat_ulong_t _data;
					u32 _type;
					u32 _flags;
				} _perf;
			};
		} _sigfault;
		struct {
			compat_long_t _band;
			int _fd;
		} _sigpoll;
		struct {
			compat_uptr_t _call_addr;
			int _syscall;
			unsigned int _arch;
		} _sigsys;
	} _sifields;
};

typedef struct compat_siginfo compat_siginfo_t;

enum bug_trap_type {
	BUG_TRAP_TYPE_NONE = 0,
	BUG_TRAP_TYPE_WARN = 1,
	BUG_TRAP_TYPE_BUG = 2,
};

enum insn_mode {
	INSN_MODE_32 = 0,
	INSN_MODE_64 = 1,
	INSN_MODE_KERN = 2,
	INSN_NUM_MODES = 3,
};

typedef u8 kprobe_opcode_t;

struct kprobe;

struct arch_specific_insn {
	kprobe_opcode_t *insn;
	unsigned int boostable: 1;
	unsigned char size;
	union {
		unsigned char opcode;
		struct {
			unsigned char type;
		} jcc;
		struct {
			unsigned char type;
			unsigned char asize;
		} loop;
		struct {
			unsigned char reg;
		} indirect;
	};
	s32 rel32;
	void (*emulate_op)(struct kprobe *, struct pt_regs *);
	int tp_len;
};

typedef int (*kprobe_pre_handler_t)(struct kprobe *, struct pt_regs *);

typedef void (*kprobe_post_handler_t)(struct kprobe *, struct pt_regs *, long unsigned int);

struct kprobe {
	struct hlist_node hlist;
	struct list_head list;
	long unsigned int nmissed;
	kprobe_opcode_t *addr;
	const char *symbol_name;
	unsigned int offset;
	kprobe_pre_handler_t pre_handler;
	kprobe_post_handler_t post_handler;
	kprobe_opcode_t opcode;
	struct arch_specific_insn ainsn;
	u32 flags;
};

enum die_val {
	DIE_OOPS = 1,
	DIE_INT3 = 2,
	DIE_DEBUG = 3,
	DIE_PANIC = 4,
	DIE_NMI = 5,
	DIE_DIE = 6,
	DIE_KERNELDEBUG = 7,
	DIE_TRAP = 8,
	DIE_GPF = 9,
	DIE_CALL = 10,
	DIE_PAGE_FAULT = 11,
	DIE_NMIUNKNOWN = 12,
};

typedef unsigned int ioasid_t;

struct cea_exception_stacks {
	char DF_stack_guard[4096];
	char DF_stack[8192];
	char NMI_stack_guard[4096];
	char NMI_stack[8192];
	char DB_stack_guard[4096];
	char DB_stack[8192];
	char MCE_stack_guard[4096];
	char MCE_stack[8192];
	char VC_stack_guard[4096];
	char VC_stack[8192];
	char VC2_stack_guard[4096];
	char VC2_stack[8192];
	char IST_top_guard[4096];
};

enum kernel_gp_hint {
	GP_NO_HINT = 0,
	GP_NON_CANONICAL = 1,
	GP_CANONICAL = 2,
};

typedef struct irq_desc *vector_irq_t[256];

struct trace_event_raw_x86_irq_vector {
	struct trace_entry ent;
	int vector;
	char __data[0];
};

struct trace_event_raw_vector_config {
	struct trace_entry ent;
	unsigned int irq;
	unsigned int vector;
	unsigned int cpu;
	unsigned int apicdest;
	char __data[0];
};

struct trace_event_raw_vector_mod {
	struct trace_entry ent;
	unsigned int irq;
	unsigned int vector;
	unsigned int cpu;
	unsigned int prev_vector;
	unsigned int prev_cpu;
	char __data[0];
};

struct trace_event_raw_vector_reserve {
	struct trace_entry ent;
	unsigned int irq;
	int ret;
	char __data[0];
};

struct trace_event_raw_vector_alloc {
	struct trace_entry ent;
	unsigned int irq;
	unsigned int vector;
	bool reserved;
	int ret;
	char __data[0];
};

struct trace_event_raw_vector_alloc_managed {
	struct trace_entry ent;
	unsigned int irq;
	unsigned int vector;
	int ret;
	char __data[0];
};

struct trace_event_raw_vector_activate {
	struct trace_entry ent;
	unsigned int irq;
	bool is_managed;
	bool can_reserve;
	bool reserve;
	char __data[0];
};

struct trace_event_raw_vector_teardown {
	struct trace_entry ent;
	unsigned int irq;
	bool is_managed;
	bool has_reserved;
	char __data[0];
};

struct trace_event_raw_vector_setup {
	struct trace_entry ent;
	unsigned int irq;
	bool is_legacy;
	int ret;
	char __data[0];
};

struct trace_event_raw_vector_free_moved {
	struct trace_entry ent;
	unsigned int irq;
	unsigned int cpu;
	unsigned int vector;
	bool is_managed;
	char __data[0];
};

struct trace_event_data_offsets_x86_irq_vector {};

struct trace_event_data_offsets_vector_config {};

struct trace_event_data_offsets_vector_mod {};

struct trace_event_data_offsets_vector_reserve {};

struct trace_event_data_offsets_vector_alloc {};

struct trace_event_data_offsets_vector_alloc_managed {};

struct trace_event_data_offsets_vector_activate {};

struct trace_event_data_offsets_vector_teardown {};

struct trace_event_data_offsets_vector_setup {};

struct trace_event_data_offsets_vector_free_moved {};

typedef void (*btf_trace_local_timer_entry)(void *, int);

typedef void (*btf_trace_local_timer_exit)(void *, int);

typedef void (*btf_trace_spurious_apic_entry)(void *, int);

typedef void (*btf_trace_spurious_apic_exit)(void *, int);

typedef void (*btf_trace_error_apic_entry)(void *, int);

typedef void (*btf_trace_error_apic_exit)(void *, int);

typedef void (*btf_trace_x86_platform_ipi_entry)(void *, int);

typedef void (*btf_trace_x86_platform_ipi_exit)(void *, int);

typedef void (*btf_trace_irq_work_entry)(void *, int);

typedef void (*btf_trace_irq_work_exit)(void *, int);

typedef void (*btf_trace_reschedule_entry)(void *, int);

typedef void (*btf_trace_reschedule_exit)(void *, int);

typedef void (*btf_trace_call_function_entry)(void *, int);

typedef void (*btf_trace_call_function_exit)(void *, int);

typedef void (*btf_trace_call_function_single_entry)(void *, int);

typedef void (*btf_trace_call_function_single_exit)(void *, int);

typedef void (*btf_trace_threshold_apic_entry)(void *, int);

typedef void (*btf_trace_threshold_apic_exit)(void *, int);

typedef void (*btf_trace_deferred_error_apic_entry)(void *, int);

typedef void (*btf_trace_deferred_error_apic_exit)(void *, int);

typedef void (*btf_trace_thermal_apic_entry)(void *, int);

typedef void (*btf_trace_thermal_apic_exit)(void *, int);

typedef void (*btf_trace_vector_config)(void *, unsigned int, unsigned int, unsigned int, unsigned int);

typedef void (*btf_trace_vector_update)(void *, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);

typedef void (*btf_trace_vector_clear)(void *, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);

typedef void (*btf_trace_vector_reserve_managed)(void *, unsigned int, int);

typedef void (*btf_trace_vector_reserve)(void *, unsigned int, int);

typedef void (*btf_trace_vector_alloc)(void *, unsigned int, unsigned int, bool, int);

typedef void (*btf_trace_vector_alloc_managed)(void *, unsigned int, unsigned int, int);

typedef void (*btf_trace_vector_activate)(void *, unsigned int, bool, bool, bool);

typedef void (*btf_trace_vector_deactivate)(void *, unsigned int, bool, bool, bool);

typedef void (*btf_trace_vector_teardown)(void *, unsigned int, bool, bool);

typedef void (*btf_trace_vector_setup)(void *, unsigned int, bool, int);

typedef void (*btf_trace_vector_free_moved)(void *, unsigned int, unsigned int, unsigned int, bool);

struct irq_stack {
	char stack[16384];
};

struct estack_pages {
	u32 offs;
	u16 size;
	u16 type;
};

enum lockdown_reason {
	LOCKDOWN_NONE = 0,
	LOCKDOWN_MODULE_SIGNATURE = 1,
	LOCKDOWN_DEV_MEM = 2,
	LOCKDOWN_EFI_TEST = 3,
	LOCKDOWN_KEXEC = 4,
	LOCKDOWN_HIBERNATION = 5,
	LOCKDOWN_PCI_ACCESS = 6,
	LOCKDOWN_IOPORT = 7,
	LOCKDOWN_MSR = 8,
	LOCKDOWN_ACPI_TABLES = 9,
	LOCKDOWN_PCMCIA_CIS = 10,
	LOCKDOWN_TIOCSSERIAL = 11,
	LOCKDOWN_MODULE_PARAMETERS = 12,
	LOCKDOWN_MMIOTRACE = 13,
	LOCKDOWN_DEBUGFS = 14,
	LOCKDOWN_XMON_WR = 15,
	LOCKDOWN_BPF_WRITE_USER = 16,
	LOCKDOWN_DBG_WRITE_KERNEL = 17,
	LOCKDOWN_INTEGRITY_MAX = 18,
	LOCKDOWN_KCORE = 19,
	LOCKDOWN_KPROBES = 20,
	LOCKDOWN_BPF_READ_KERNEL = 21,
	LOCKDOWN_DBG_READ_KERNEL = 22,
	LOCKDOWN_PERF = 23,
	LOCKDOWN_TRACEFS = 24,
	LOCKDOWN_XMON_RW = 25,
	LOCKDOWN_XFRM_SECRET = 26,
	LOCKDOWN_CONFIDENTIALITY_MAX = 27,
};

enum lockdep_ok {
	LOCKDEP_STILL_OK = 0,
	LOCKDEP_NOW_UNRELIABLE = 1,
};

struct entry_stack {
	char stack[4096];
};

struct trace_event_raw_nmi_handler {
	struct trace_entry ent;
	void *handler;
	s64 delta_ns;
	int handled;
	char __data[0];
};

struct trace_event_data_offsets_nmi_handler {};

typedef void (*btf_trace_nmi_handler)(void *, void *, s64, int);

struct nmi_desc {
	raw_spinlock_t lock;
	struct list_head head;
};

struct nmi_stats {
	unsigned int normal;
	unsigned int unknown;
	unsigned int external;
	unsigned int swallow;
};

enum nmi_states {
	NMI_NOT_RUNNING = 0,
	NMI_EXECUTING = 1,
	NMI_LATCHED = 2,
};

struct user_desc {
	unsigned int entry_number;
	unsigned int base_addr;
	unsigned int limit;
	unsigned int seg_32bit: 1;
	unsigned int contents: 2;
	unsigned int read_exec_only: 1;
	unsigned int limit_in_pages: 1;
	unsigned int seg_not_present: 1;
	unsigned int useable: 1;
	unsigned int lm: 1;
};

struct edd {
	unsigned int mbr_signature[16];
	struct edd_info edd_info[6];
	unsigned char mbr_signature_nr;
	unsigned char edd_info_nr;
};

struct setup_data {
	__u64 next;
	__u32 type;
	__u32 len;
	__u8 data[0];
};

struct setup_indirect {
	__u32 type;
	__u32 reserved;
	__u64 len;
	__u64 addr;
};

enum con_scroll {
	SM_UP = 0,
	SM_DOWN = 1,
};

enum vc_intensity {
	VCI_HALF_BRIGHT = 0,
	VCI_NORMAL = 1,
	VCI_BOLD = 2,
	VCI_MASK = 3,
};

struct vc_data;

struct console_font;

struct consw {
	struct module *owner;
	const char * (*con_startup)();
	void (*con_init)(struct vc_data *, int);
	void (*con_deinit)(struct vc_data *);
	void (*con_clear)(struct vc_data *, int, int, int, int);
	void (*con_putc)(struct vc_data *, int, int, int);
	void (*con_putcs)(struct vc_data *, const short unsigned int *, int, int, int);
	void (*con_cursor)(struct vc_data *, int);
	bool (*con_scroll)(struct vc_data *, unsigned int, unsigned int, enum con_scroll, unsigned int);
	int (*con_switch)(struct vc_data *);
	int (*con_blank)(struct vc_data *, int, int);
	int (*con_font_set)(struct vc_data *, struct console_font *, unsigned int);
	int (*con_font_get)(struct vc_data *, struct console_font *);
	int (*con_font_default)(struct vc_data *, struct console_font *, char *);
	int (*con_resize)(struct vc_data *, unsigned int, unsigned int, unsigned int);
	void (*con_set_palette)(struct vc_data *, const unsigned char *);
	void (*con_scrolldelta)(struct vc_data *, int);
	int (*con_set_origin)(struct vc_data *);
	void (*con_save_screen)(struct vc_data *);
	u8 (*con_build_attr)(struct vc_data *, u8, enum vc_intensity, bool, bool, bool, bool);
	void (*con_invert_region)(struct vc_data *, u16 *, int);
	u16 * (*con_screen_pos)(const struct vc_data *, int);
	long unsigned int (*con_getxy)(struct vc_data *, long unsigned int, int *, int *);
	void (*con_flush_scrollback)(struct vc_data *);
	int (*con_debug_enter)(struct vc_data *);
	int (*con_debug_leave)(struct vc_data *);
};

struct vc_state {
	unsigned int x;
	unsigned int y;
	unsigned char color;
	unsigned char Gx_charset[2];
	unsigned int charset: 1;
	enum vc_intensity intensity;
	bool italic;
	bool underline;
	bool blink;
	bool reverse;
};

struct console_font {
	unsigned int width;
	unsigned int height;
	unsigned int charcount;
	unsigned char *data;
};

struct vt_mode {
	char mode;
	char waitv;
	short int relsig;
	short int acqsig;
	short int frsig;
};

struct uni_pagedir;

struct uni_screen;

struct vc_data {
	struct tty_port port;
	struct vc_state state;
	struct vc_state saved_state;
	short unsigned int vc_num;
	unsigned int vc_cols;
	unsigned int vc_rows;
	unsigned int vc_size_row;
	unsigned int vc_scan_lines;
	unsigned int vc_cell_height;
	long unsigned int vc_origin;
	long unsigned int vc_scr_end;
	long unsigned int vc_visible_origin;
	unsigned int vc_top;
	unsigned int vc_bottom;
	const struct consw *vc_sw;
	short unsigned int *vc_screenbuf;
	unsigned int vc_screenbuf_size;
	unsigned char vc_mode;
	unsigned char vc_attr;
	unsigned char vc_def_color;
	unsigned char vc_ulcolor;
	unsigned char vc_itcolor;
	unsigned char vc_halfcolor;
	unsigned int vc_cursor_type;
	short unsigned int vc_complement_mask;
	short unsigned int vc_s_complement_mask;
	long unsigned int vc_pos;
	short unsigned int vc_hi_font_mask;
	struct console_font vc_font;
	short unsigned int vc_video_erase_char;
	unsigned int vc_state;
	unsigned int vc_npar;
	unsigned int vc_par[16];
	struct vt_mode vt_mode;
	struct pid *vt_pid;
	int vt_newvt;
	wait_queue_head_t paste_wait;
	unsigned int vc_disp_ctrl: 1;
	unsigned int vc_toggle_meta: 1;
	unsigned int vc_decscnm: 1;
	unsigned int vc_decom: 1;
	unsigned int vc_decawm: 1;
	unsigned int vc_deccm: 1;
	unsigned int vc_decim: 1;
	unsigned int vc_priv: 3;
	unsigned int vc_need_wrap: 1;
	unsigned int vc_can_do_color: 1;
	unsigned int vc_report_mouse: 2;
	unsigned char vc_utf: 1;
	unsigned char vc_utf_count;
	int vc_utf_char;
	long unsigned int vc_tab_stop[4];
	unsigned char vc_palette[48];
	short unsigned int *vc_translate;
	unsigned int vc_resize_user;
	unsigned int vc_bell_pitch;
	unsigned int vc_bell_duration;
	short unsigned int vc_cur_blink_ms;
	struct vc_data **vc_display_fg;
	struct uni_pagedir *vc_uni_pagedir;
	struct uni_pagedir **vc_uni_pagedir_loc;
	struct uni_screen *vc_uni_screen;
};

struct sg_table {
	struct scatterlist *sgl;
	unsigned int nents;
	unsigned int orig_nents;
};

enum memblock_flags {
	MEMBLOCK_NONE = 0,
	MEMBLOCK_HOTPLUG = 1,
	MEMBLOCK_MIRROR = 2,
	MEMBLOCK_NOMAP = 4,
	MEMBLOCK_DRIVER_MANAGED = 8,
};

struct memblock_region {
	phys_addr_t base;
	phys_addr_t size;
	enum memblock_flags flags;
	int nid;
};

struct memblock_type {
	long unsigned int cnt;
	long unsigned int max;
	phys_addr_t total_size;
	struct memblock_region *regions;
	char *name;
};

struct memblock {
	bool bottom_up;
	phys_addr_t current_limit;
	struct memblock_type memory;
	struct memblock_type reserved;
};

struct legacy_pic {
	int nr_legacy_irqs;
	struct irq_chip *chip;
	void (*mask)(unsigned int);
	void (*unmask)(unsigned int);
	void (*mask_all)();
	void (*restore_mask)();
	void (*init)(int);
	int (*probe)();
	int (*irq_pending)(unsigned int);
	void (*make_irq)(unsigned int);
};

enum jump_label_type {
	JUMP_LABEL_NOP = 0,
	JUMP_LABEL_JMP = 1,
};

struct jump_label_patch {
	const void *code;
	int size;
};

enum {
	JL_STATE_START = 0,
	JL_STATE_NO_UPDATE = 1,
	JL_STATE_UPDATE = 2,
};

enum psc_op {
	SNP_PAGE_STATE_PRIVATE = 1,
	SNP_PAGE_STATE_SHARED = 2,
};

typedef short unsigned int __kernel_old_uid_t;

typedef short unsigned int __kernel_old_gid_t;

typedef struct {
	int val[2];
} __kernel_fsid_t;

typedef __kernel_old_uid_t old_uid_t;

typedef __kernel_old_gid_t old_gid_t;

struct kernel_clone_args {
	u64 flags;
	int *pidfd;
	int *child_tid;
	int *parent_tid;
	int exit_signal;
	long unsigned int stack;
	long unsigned int stack_size;
	long unsigned int tls;
	pid_t *set_tid;
	size_t set_tid_size;
	int cgroup;
	int io_thread;
	int kthread;
	int idle;
	int (*fn)(void *);
	void *fn_arg;
	struct cgroup *cgrp;
	struct css_set *cset;
};

struct kstatfs {
	long int f_type;
	long int f_bsize;
	u64 f_blocks;
	u64 f_bfree;
	u64 f_bavail;
	u64 f_files;
	u64 f_ffree;
	__kernel_fsid_t f_fsid;
	long int f_namelen;
	long int f_frsize;
	long int f_flags;
	long int f_spare[4];
};

struct stat64 {
	long long unsigned int st_dev;
	unsigned char __pad0[4];
	unsigned int __st_ino;
	unsigned int st_mode;
	unsigned int st_nlink;
	unsigned int st_uid;
	unsigned int st_gid;
	long long unsigned int st_rdev;
	unsigned char __pad3[4];
	long long int st_size;
	unsigned int st_blksize;
	long long int st_blocks;
	unsigned int st_atime;
	unsigned int st_atime_nsec;
	unsigned int st_mtime;
	unsigned int st_mtime_nsec;
	unsigned int st_ctime;
	unsigned int st_ctime_nsec;
	long long unsigned int st_ino;
} __attribute__((packed));

struct mmap_arg_struct32 {
	unsigned int addr;
	unsigned int len;
	unsigned int prot;
	unsigned int flags;
	unsigned int fd;
	unsigned int offset;
};

enum align_flags {
	ALIGN_VA_32 = 1,
	ALIGN_VA_64 = 2,
};

struct va_alignment {
	int flags;
	long unsigned int mask;
	long unsigned int bits;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct vm_unmapped_area_info {
	long unsigned int flags;
	long unsigned int length;
	long unsigned int low_limit;
	long unsigned int high_limit;
	long unsigned int align_mask;
	long unsigned int align_offset;
};

struct kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *, struct kobj_attribute *, char *);
	ssize_t (*store)(struct kobject *, struct kobj_attribute *, const char *, size_t);
};

enum {
	IORES_DESC_NONE = 0,
	IORES_DESC_CRASH_KERNEL = 1,
	IORES_DESC_ACPI_TABLES = 2,
	IORES_DESC_ACPI_NV_STORAGE = 3,
	IORES_DESC_PERSISTENT_MEMORY = 4,
	IORES_DESC_PERSISTENT_MEMORY_LEGACY = 5,
	IORES_DESC_DEVICE_PRIVATE_MEMORY = 6,
	IORES_DESC_RESERVED = 7,
	IORES_DESC_SOFT_RESERVED = 8,
};

struct change_member {
	struct e820_entry *entry;
	long long unsigned int addr;
};

struct iommu_fault_param;

struct iopf_device_param;

struct iommu_fwspec;

struct dev_iommu {
	struct mutex lock;
	struct iommu_fault_param *fault_param;
	struct iopf_device_param *iopf_param;
	struct iommu_fwspec *fwspec;
	struct iommu_device *iommu_dev;
	void *priv;
};

struct of_phandle_args {
	struct device_node *np;
	int args_count;
	uint32_t args[16];
};

struct iommu_fault_unrecoverable {
	__u32 reason;
	__u32 flags;
	__u32 pasid;
	__u32 perm;
	__u64 addr;
	__u64 fetch_addr;
};

struct iommu_fault_page_request {
	__u32 flags;
	__u32 pasid;
	__u32 grpid;
	__u32 perm;
	__u64 addr;
	__u64 private_data[2];
};

struct iommu_fault {
	__u32 type;
	__u32 padding;
	union {
		struct iommu_fault_unrecoverable event;
		struct iommu_fault_page_request prm;
		__u8 padding2[56];
	};
};

struct iommu_page_response {
	__u32 argsz;
	__u32 version;
	__u32 flags;
	__u32 pasid;
	__u32 grpid;
	__u32 code;
};

typedef int (*iommu_fault_handler_t)(struct iommu_domain *, struct device *, long unsigned int, int, void *);

struct iommu_domain_geometry {
	dma_addr_t aperture_start;
	dma_addr_t aperture_end;
	bool force_aperture;
};

struct iommu_dma_cookie;

struct iommu_domain {
	unsigned int type;
	const struct iommu_domain_ops *ops;
	long unsigned int pgsize_bitmap;
	iommu_fault_handler_t handler;
	void *handler_token;
	struct iommu_domain_geometry geometry;
	struct iommu_dma_cookie *iova_cookie;
};

typedef int (*iommu_dev_fault_handler_t)(struct iommu_fault *, void *);

struct iommu_iotlb_gather;

struct iommu_domain_ops {
	int (*attach_dev)(struct iommu_domain *, struct device *);
	void (*detach_dev)(struct iommu_domain *, struct device *);
	int (*map)(struct iommu_domain *, long unsigned int, phys_addr_t, size_t, int, gfp_t);
	int (*map_pages)(struct iommu_domain *, long unsigned int, phys_addr_t, size_t, size_t, int, gfp_t, size_t *);
	size_t (*unmap)(struct iommu_domain *, long unsigned int, size_t, struct iommu_iotlb_gather *);
	size_t (*unmap_pages)(struct iommu_domain *, long unsigned int, size_t, size_t, struct iommu_iotlb_gather *);
	void (*flush_iotlb_all)(struct iommu_domain *);
	void (*iotlb_sync_map)(struct iommu_domain *, long unsigned int, size_t);
	void (*iotlb_sync)(struct iommu_domain *, struct iommu_iotlb_gather *);
	phys_addr_t (*iova_to_phys)(struct iommu_domain *, dma_addr_t);
	bool (*enforce_cache_coherency)(struct iommu_domain *);
	int (*enable_nesting)(struct iommu_domain *);
	int (*set_pgtable_quirks)(struct iommu_domain *, long unsigned int);
	void (*free)(struct iommu_domain *);
};

struct iommu_iotlb_gather {
	long unsigned int start;
	long unsigned int end;
	size_t pgsize;
	struct list_head freelist;
	bool queued;
};

struct iommu_device {
	struct list_head list;
	const struct iommu_ops *ops;
	struct fwnode_handle *fwnode;
	struct device *dev;
};

struct iommu_sva {
	struct device *dev;
};

struct iommu_fault_event {
	struct iommu_fault fault;
	struct list_head list;
};

struct iommu_fault_param {
	iommu_dev_fault_handler_t handler;
	void *data;
	struct list_head faults;
	struct mutex lock;
};

struct iommu_fwspec {
	const struct iommu_ops *ops;
	struct fwnode_handle *iommu_fwnode;
	u32 flags;
	unsigned int num_ids;
	u32 ids[0];
};

enum dmi_field {
	DMI_NONE = 0,
	DMI_BIOS_VENDOR = 1,
	DMI_BIOS_VERSION = 2,
	DMI_BIOS_DATE = 3,
	DMI_BIOS_RELEASE = 4,
	DMI_EC_FIRMWARE_RELEASE = 5,
	DMI_SYS_VENDOR = 6,
	DMI_PRODUCT_NAME = 7,
	DMI_PRODUCT_VERSION = 8,
	DMI_PRODUCT_SERIAL = 9,
	DMI_PRODUCT_UUID = 10,
	DMI_PRODUCT_SKU = 11,
	DMI_PRODUCT_FAMILY = 12,
	DMI_BOARD_VENDOR = 13,
	DMI_BOARD_NAME = 14,
	DMI_BOARD_VERSION = 15,
	DMI_BOARD_SERIAL = 16,
	DMI_BOARD_ASSET_TAG = 17,
	DMI_CHASSIS_VENDOR = 18,
	DMI_CHASSIS_TYPE = 19,
	DMI_CHASSIS_VERSION = 20,
	DMI_CHASSIS_SERIAL = 21,
	DMI_CHASSIS_ASSET_TAG = 22,
	DMI_STRING_MAX = 23,
	DMI_OEM_STRING = 24,
};

enum {
	NONE_FORCE_HPET_RESUME = 0,
	OLD_ICH_FORCE_HPET_RESUME = 1,
	ICH_FORCE_HPET_RESUME = 2,
	VT8237_FORCE_HPET_RESUME = 3,
	NVIDIA_FORCE_HPET_RESUME = 4,
	ATI_FORCE_HPET_RESUME = 5,
};

struct cpu {
	int node_id;
	int hotpluggable;
	struct device dev;
};

struct x86_cpu {
	struct cpu cpu;
};

typedef int (*cmp_func_t)(const void *, const void *);

typedef u8 retpoline_thunk_t[32];

struct paravirt_patch_site {
	u8 *instr;
	u8 type;
	u8 len;
};

struct die_args {
	struct pt_regs *regs;
	const char *str;
	long int err;
	int trapnr;
	int signr;
};

struct tlb_state_shared {
	bool is_lazy;
};

struct smp_alt_module {
	struct module *mod;
	char *name;
	const s32 *locks;
	const s32 *locks_end;
	u8 *text;
	u8 *text_end;
	struct list_head next;
};

typedef struct {
	struct mm_struct *mm;
} temp_mm_state_t;

typedef void text_poke_f(void *, const void *, size_t);

struct text_poke_loc {
	s32 rel_addr;
	s32 disp;
	u8 len;
	u8 opcode;
	const u8 text[5];
	u8 old;
};

struct bp_patching_desc {
	struct text_poke_loc *vec;
	int nr_entries;
	atomic_t refs;
};

enum {
	HW_BREAKPOINT_LEN_1 = 1,
	HW_BREAKPOINT_LEN_2 = 2,
	HW_BREAKPOINT_LEN_3 = 3,
	HW_BREAKPOINT_LEN_4 = 4,
	HW_BREAKPOINT_LEN_5 = 5,
	HW_BREAKPOINT_LEN_6 = 6,
	HW_BREAKPOINT_LEN_7 = 7,
	HW_BREAKPOINT_LEN_8 = 8,
};

enum {
	HW_BREAKPOINT_EMPTY = 0,
	HW_BREAKPOINT_R = 1,
	HW_BREAKPOINT_W = 2,
	HW_BREAKPOINT_RW = 3,
	HW_BREAKPOINT_X = 4,
	HW_BREAKPOINT_INVALID = 7,
};

typedef unsigned int u_int;

typedef long long unsigned int cycles_t;

struct system_counterval_t {
	u64 cycles;
	struct clocksource *cs;
};

typedef struct {
	seqcount_t seqcount;
} seqcount_latch_t;

enum cpufreq_table_sorting {
	CPUFREQ_TABLE_UNSORTED = 0,
	CPUFREQ_TABLE_SORTED_ASCENDING = 1,
	CPUFREQ_TABLE_SORTED_DESCENDING = 2,
};

struct cpufreq_cpuinfo {
	unsigned int max_freq;
	unsigned int min_freq;
	unsigned int transition_latency;
};

struct clk;

struct cpufreq_governor;

struct cpufreq_frequency_table;

struct cpufreq_stats;

struct thermal_cooling_device;

struct cpufreq_policy {
	cpumask_var_t cpus;
	cpumask_var_t related_cpus;
	cpumask_var_t real_cpus;
	unsigned int shared_type;
	unsigned int cpu;
	struct clk *clk;
	struct cpufreq_cpuinfo cpuinfo;
	unsigned int min;
	unsigned int max;
	unsigned int cur;
	unsigned int suspend_freq;
	unsigned int policy;
	unsigned int last_policy;
	struct cpufreq_governor *governor;
	void *governor_data;
	char last_governor[16];
	struct work_struct update;
	struct freq_constraints constraints;
	struct freq_qos_request *min_freq_req;
	struct freq_qos_request *max_freq_req;
	struct cpufreq_frequency_table *freq_table;
	enum cpufreq_table_sorting freq_table_sorted;
	struct list_head policy_list;
	struct kobject kobj;
	struct completion kobj_unregister;
	struct rw_semaphore rwsem;
	bool fast_switch_possible;
	bool fast_switch_enabled;
	bool strict_target;
	bool efficiencies_available;
	unsigned int transition_delay_us;
	bool dvfs_possible_from_any_cpu;
	unsigned int cached_target_freq;
	unsigned int cached_resolved_idx;
	bool transition_ongoing;
	spinlock_t transition_lock;
	wait_queue_head_t transition_wait;
	struct task_struct *transition_task;
	struct cpufreq_stats *stats;
	void *driver_data;
	struct thermal_cooling_device *cdev;
	struct notifier_block nb_min;
	struct notifier_block nb_max;
};

struct cpufreq_governor {
	char name[16];
	int (*init)(struct cpufreq_policy *);
	void (*exit)(struct cpufreq_policy *);
	int (*start)(struct cpufreq_policy *);
	void (*stop)(struct cpufreq_policy *);
	void (*limits)(struct cpufreq_policy *);
	ssize_t (*show_setspeed)(struct cpufreq_policy *, char *);
	int (*store_setspeed)(struct cpufreq_policy *, unsigned int);
	struct list_head governor_list;
	struct module *owner;
	u8 flags;
};

struct cpufreq_frequency_table {
	unsigned int flags;
	unsigned int driver_data;
	unsigned int frequency;
};

struct cpufreq_freqs {
	struct cpufreq_policy *policy;
	unsigned int old;
	unsigned int new;
	u8 flags;
};

struct cyc2ns {
	struct cyc2ns_data data[2];
	seqcount_latch_t seq;
};

struct muldiv {
	u32 multiplier;
	u32 divider;
};

struct freq_desc {
	bool use_msr_plat;
	struct muldiv muldiv[16];
	u32 freqs[16];
	u32 mask;
};

struct dmi_strmatch {
	unsigned char slot: 7;
	unsigned char exact_match: 1;
	char substr[79];
};

struct dmi_system_id {
	int (*callback)(const struct dmi_system_id *);
	const char *ident;
	struct dmi_strmatch matches[4];
	void *driver_data;
};

struct pdev_archdata {};

struct platform_device_id;

struct mfd_cell;

struct platform_device {
	const char *name;
	int id;
	bool id_auto;
	struct device dev;
	u64 platform_dma_mask;
	struct device_dma_parameters dma_parms;
	u32 num_resources;
	struct resource *resource;
	const struct platform_device_id *id_entry;
	const char *driver_override;
	struct mfd_cell *mfd_cell;
	struct pdev_archdata archdata;
};

struct platform_device_id {
	char name[20];
	kernel_ulong_t driver_data;
};

struct rtc_time {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

struct pnp_device_id {
	__u8 id[8];
	kernel_ulong_t driver_data;
};

struct pnp_card_device_id {
	__u8 id[8];
	kernel_ulong_t driver_data;
	struct {
		__u8 id[8];
	} devs[8];
};

struct acpi_table_header {
	char signature[4];
	u32 length;
	u8 revision;
	u8 checksum;
	char oem_id[6];
	char oem_table_id[8];
	u32 oem_revision;
	char asl_compiler_id[4];
	u32 asl_compiler_revision;
};

struct acpi_generic_address {
	u8 space_id;
	u8 bit_width;
	u8 bit_offset;
	u8 access_width;
	u64 address;
} __attribute__((packed));

struct acpi_table_fadt {
	struct acpi_table_header header;
	u32 facs;
	u32 dsdt;
	u8 model;
	u8 preferred_profile;
	u16 sci_interrupt;
	u32 smi_command;
	u8 acpi_enable;
	u8 acpi_disable;
	u8 s4_bios_request;
	u8 pstate_control;
	u32 pm1a_event_block;
	u32 pm1b_event_block;
	u32 pm1a_control_block;
	u32 pm1b_control_block;
	u32 pm2_control_block;
	u32 pm_timer_block;
	u32 gpe0_block;
	u32 gpe1_block;
	u8 pm1_event_length;
	u8 pm1_control_length;
	u8 pm2_control_length;
	u8 pm_timer_length;
	u8 gpe0_block_length;
	u8 gpe1_block_length;
	u8 gpe1_base;
	u8 cst_control;
	u16 c2_latency;
	u16 c3_latency;
	u16 flush_size;
	u16 flush_stride;
	u8 duty_offset;
	u8 duty_width;
	u8 day_alarm;
	u8 month_alarm;
	u8 century;
	u16 boot_flags;
	u8 reserved;
	u32 flags;
	struct acpi_generic_address reset_register;
	u8 reset_value;
	u16 arm_boot_flags;
	u8 minor_revision;
	u64 Xfacs;
	u64 Xdsdt;
	struct acpi_generic_address xpm1a_event_block;
	struct acpi_generic_address xpm1b_event_block;
	struct acpi_generic_address xpm1a_control_block;
	struct acpi_generic_address xpm1b_control_block;
	struct acpi_generic_address xpm2_control_block;
	struct acpi_generic_address xpm_timer_block;
	struct acpi_generic_address xgpe0_block;
	struct acpi_generic_address xgpe1_block;
	struct acpi_generic_address sleep_control;
	struct acpi_generic_address sleep_status;
	u64 hypervisor_id;
} __attribute__((packed));

struct pnp_protocol;

struct pnp_id;

struct pnp_card {
	struct device dev;
	unsigned char number;
	struct list_head global_list;
	struct list_head protocol_list;
	struct list_head devices;
	struct pnp_protocol *protocol;
	struct pnp_id *id;
	char name[50];
	unsigned char pnpver;
	unsigned char productver;
	unsigned int serial;
	unsigned char checksum;
	struct proc_dir_entry *procdir;
};

struct pnp_dev;

struct pnp_protocol {
	struct list_head protocol_list;
	char *name;
	int (*get)(struct pnp_dev *);
	int (*set)(struct pnp_dev *);
	int (*disable)(struct pnp_dev *);
	bool (*can_wakeup)(struct pnp_dev *);
	int (*suspend)(struct pnp_dev *, pm_message_t);
	int (*resume)(struct pnp_dev *);
	unsigned char number;
	struct device dev;
	struct list_head cards;
	struct list_head devices;
};

struct pnp_id {
	char id[8];
	struct pnp_id *next;
};

struct pnp_card_driver;

struct pnp_card_link {
	struct pnp_card *card;
	struct pnp_card_driver *driver;
	void *driver_data;
	pm_message_t pm_state;
};

struct pnp_driver {
	const char *name;
	const struct pnp_device_id *id_table;
	unsigned int flags;
	int (*probe)(struct pnp_dev *, const struct pnp_device_id *);
	void (*remove)(struct pnp_dev *);
	void (*shutdown)(struct pnp_dev *);
	int (*suspend)(struct pnp_dev *, pm_message_t);
	int (*resume)(struct pnp_dev *);
	struct device_driver driver;
};

struct pnp_card_driver {
	struct list_head global_list;
	char *name;
	const struct pnp_card_device_id *id_table;
	unsigned int flags;
	int (*probe)(struct pnp_card_link *, const struct pnp_card_device_id *);
	void (*remove)(struct pnp_card_link *);
	int (*suspend)(struct pnp_card_link *, pm_message_t);
	int (*resume)(struct pnp_card_link *);
	struct pnp_driver link;
};

struct pnp_dev {
	struct device dev;
	u64 dma_mask;
	unsigned int number;
	int status;
	struct list_head global_list;
	struct list_head protocol_list;
	struct list_head card_list;
	struct list_head rdev_list;
	struct pnp_protocol *protocol;
	struct pnp_card *card;
	struct pnp_driver *driver;
	struct pnp_card_link *card_link;
	struct pnp_id *id;
	int active;
	int capabilities;
	unsigned int num_dependent_sets;
	struct list_head resources;
	struct list_head options;
	char name[50];
	int flags;
	struct proc_dir_entry *procent;
	void *data;
};

enum insn_type {
	CALL = 0,
	NOP = 1,
	JMP = 2,
	RET = 3,
};

struct ldttss_desc {
	u16 limit0;
	u16 base0;
	u16 base1: 8;
	u16 type: 5;
	u16 dpl: 2;
	u16 p: 1;
	u16 limit1: 4;
	u16 zero0: 3;
	u16 g: 1;
	u16 base2: 8;
	u32 base3;
	u32 zero1;
};

typedef struct ldttss_desc tss_desc;

enum idle_boot_override {
	IDLE_NO_OVERRIDE = 0,
	IDLE_HALT = 1,
	IDLE_NOMWAIT = 2,
	IDLE_POLL = 3,
};

enum tick_broadcast_mode {
	TICK_BROADCAST_OFF = 0,
	TICK_BROADCAST_ON = 1,
	TICK_BROADCAST_FORCE = 2,
};

enum tick_broadcast_state {
	TICK_BROADCAST_EXIT = 0,
	TICK_BROADCAST_ENTER = 1,
};

struct inactive_task_frame {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bx;
	long unsigned int bp;
	long unsigned int ret_addr;
};

struct fork_frame {
	struct inactive_task_frame frame;
	struct pt_regs regs;
};

struct ssb_state {
	struct ssb_state *shared_state;
	raw_spinlock_t lock;
	unsigned int disable_state;
	long unsigned int local_state;
};

struct fpu_state_config {
	unsigned int max_size;
	unsigned int default_size;
	u64 max_features;
	u64 default_features;
	u64 legacy_features;
};

struct pkru_state {
	u32 pkru;
	u32 pad;
};

struct fpu_guest {
	u64 xfeatures;
	u64 perm;
	u64 xfd_err;
	unsigned int uabi_size;
	struct fpstate *fpstate;
};

struct membuf {
	void *p;
	size_t left;
};

enum xstate_copy_mode {
	XSTATE_COPY_FP = 0,
	XSTATE_COPY_FX = 1,
	XSTATE_COPY_XSAVE = 2,
};

struct trace_event_raw_x86_fpu {
	struct trace_entry ent;
	struct fpu *fpu;
	bool load_fpu;
	u64 xfeatures;
	u64 xcomp_bv;
	char __data[0];
};

struct trace_event_data_offsets_x86_fpu {};

typedef void (*btf_trace_x86_fpu_before_save)(void *, struct fpu *);

typedef void (*btf_trace_x86_fpu_after_save)(void *, struct fpu *);

typedef void (*btf_trace_x86_fpu_before_restore)(void *, struct fpu *);

typedef void (*btf_trace_x86_fpu_after_restore)(void *, struct fpu *);

typedef void (*btf_trace_x86_fpu_regs_activated)(void *, struct fpu *);

typedef void (*btf_trace_x86_fpu_regs_deactivated)(void *, struct fpu *);

typedef void (*btf_trace_x86_fpu_init_state)(void *, struct fpu *);

typedef void (*btf_trace_x86_fpu_dropped)(void *, struct fpu *);

typedef void (*btf_trace_x86_fpu_copy_src)(void *, struct fpu *);

typedef void (*btf_trace_x86_fpu_copy_dst)(void *, struct fpu *);

typedef void (*btf_trace_x86_fpu_xstate_check_failed)(void *, struct fpu *);

struct _fpreg {
	__u16 significand[4];
	__u16 exponent;
};

struct _fpxreg {
	__u16 significand[4];
	__u16 exponent;
	__u16 padding[3];
};

struct user_i387_ia32_struct {
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
};

struct user_regset;

typedef int user_regset_active_fn(struct task_struct *, const struct user_regset *);

typedef int user_regset_get2_fn(struct task_struct *, const struct user_regset *, struct membuf);

typedef int user_regset_set_fn(struct task_struct *, const struct user_regset *, unsigned int, unsigned int, const void *, const void *);

typedef int user_regset_writeback_fn(struct task_struct *, const struct user_regset *, int);

struct user_regset {
	user_regset_get2_fn *regset_get;
	user_regset_set_fn *set;
	user_regset_active_fn *active;
	user_regset_writeback_fn *writeback;
	unsigned int n;
	unsigned int size;
	unsigned int align;
	unsigned int bias;
	unsigned int core_note_type;
};

struct _fpx_sw_bytes {
	__u32 magic1;
	__u32 extended_size;
	__u64 xfeatures;
	__u32 xstate_size;
	__u32 padding[7];
};

struct _xmmreg {
	__u32 element[4];
};

struct _fpstate_32 {
	__u32 cw;
	__u32 sw;
	__u32 tag;
	__u32 ipoff;
	__u32 cssel;
	__u32 dataoff;
	__u32 datasel;
	struct _fpreg _st[8];
	__u16 status;
	__u16 magic;
	__u32 _fxsr_env[6];
	__u32 mxcsr;
	__u32 reserved;
	struct _fpxreg _fxsr_st[8];
	struct _xmmreg _xmm[8];
	union {
		__u32 padding1[44];
		__u32 padding[44];
	};
	union {
		__u32 padding2[12];
		struct _fpx_sw_bytes sw_reserved;
	};
};

struct user_regset_view {
	const char *name;
	const struct user_regset *regsets;
	unsigned int n;
	u32 e_flags;
	u16 e_machine;
	u8 ei_osabi;
};

enum x86_regset {
	REGSET_GENERAL = 0,
	REGSET_FP = 1,
	REGSET_XFP = 2,
	REGSET_IOPERM64 = 2,
	REGSET_XSTATE = 3,
	REGSET_TLS = 4,
	REGSET_IOPERM32 = 5,
};

struct pt_regs_offset {
	const char *name;
	int offset;
};

enum {
	TB_SHUTDOWN_REBOOT = 0,
	TB_SHUTDOWN_S5 = 1,
	TB_SHUTDOWN_S4 = 2,
	TB_SHUTDOWN_S3 = 3,
	TB_SHUTDOWN_HALT = 4,
	TB_SHUTDOWN_WFS = 5,
};

struct tboot_mac_region {
	u64 start;
	u32 size;
} __attribute__((packed));

struct tboot_acpi_generic_address {
	u8 space_id;
	u8 bit_width;
	u8 bit_offset;
	u8 access_width;
	u64 address;
} __attribute__((packed));

struct tboot_acpi_sleep_info {
	struct tboot_acpi_generic_address pm1a_cnt_blk;
	struct tboot_acpi_generic_address pm1b_cnt_blk;
	struct tboot_acpi_generic_address pm1a_evt_blk;
	struct tboot_acpi_generic_address pm1b_evt_blk;
	u16 pm1a_cnt_val;
	u16 pm1b_cnt_val;
	u64 wakeup_vector;
	u32 vector_width;
	u64 kernel_s3_resume_vector;
} __attribute__((packed));

struct tboot {
	u8 uuid[16];
	u32 version;
	u32 log_addr;
	u32 shutdown_entry;
	u32 shutdown_type;
	struct tboot_acpi_sleep_info acpi_sinfo;
	u32 tboot_base;
	u32 tboot_size;
	u8 num_mac_regions;
	struct tboot_mac_region mac_regions[32];
	u8 s3_key[64];
	u8 reserved_align[3];
	u32 num_in_wfs;
} __attribute__((packed));

struct sha1_hash {
	u8 hash[20];
};

struct sinit_mle_data {
	u32 version;
	struct sha1_hash bios_acm_id;
	u32 edx_senter_flags;
	u64 mseg_valid;
	struct sha1_hash sinit_hash;
	struct sha1_hash mle_hash;
	struct sha1_hash stm_hash;
	struct sha1_hash lcp_policy_hash;
	u32 lcp_policy_control;
	u32 rlp_wakeup_addr;
	u32 reserved;
	u32 num_mdrs;
	u32 mdrs_off;
	u32 num_vtd_dmars;
	u32 vtd_dmars_off;
} __attribute__((packed));

typedef bool (*stack_trace_consume_fn)(void *, long unsigned int);

struct stack_frame_user {
	const void *next_fp;
	long unsigned int ret_addr;
};

enum cache_type {
	CACHE_TYPE_NOCACHE = 0,
	CACHE_TYPE_INST = 1,
	CACHE_TYPE_DATA = 2,
	CACHE_TYPE_SEPARATE = 3,
	CACHE_TYPE_UNIFIED = 4,
};

struct cacheinfo {
	unsigned int id;
	enum cache_type type;
	unsigned int level;
	unsigned int coherency_line_size;
	unsigned int number_of_sets;
	unsigned int ways_of_associativity;
	unsigned int physical_line_partition;
	unsigned int size;
	cpumask_t shared_cpu_map;
	unsigned int attributes;
	void *fw_token;
	bool disable_sysfs;
	void *priv;
};

struct cpu_cacheinfo {
	struct cacheinfo *info_list;
	unsigned int num_levels;
	unsigned int num_leaves;
	bool cpu_map_populated;
};

struct amd_l3_cache {
	unsigned int indices;
	u8 subcaches[4];
};

struct threshold_block {
	unsigned int block;
	unsigned int bank;
	unsigned int cpu;
	u32 address;
	u16 interrupt_enable;
	bool interrupt_capable;
	u16 threshold_limit;
	struct kobject kobj;
	struct list_head miscj;
};

struct threshold_bank {
	struct kobject *kobj;
	struct threshold_block *blocks;
	refcount_t cpus;
	unsigned int shared;
};

struct amd_northbridge {
	struct pci_dev *root;
	struct pci_dev *misc;
	struct pci_dev *link;
	struct amd_l3_cache l3_cache;
	struct threshold_bank *bank4;
};

struct _cache_table {
	unsigned char descriptor;
	char cache_type;
	short int size;
};

enum _cache_type {
	CTYPE_NULL = 0,
	CTYPE_DATA = 1,
	CTYPE_INST = 2,
	CTYPE_UNIFIED = 3,
};

union _cpuid4_leaf_eax {
	struct {
		enum _cache_type type: 5;
		unsigned int level: 3;
		unsigned int is_self_initializing: 1;
		unsigned int is_fully_associative: 1;
		unsigned int reserved: 4;
		unsigned int num_threads_sharing: 12;
		unsigned int num_cores_on_die: 6;
	} split;
	u32 full;
};

union _cpuid4_leaf_ebx {
	struct {
		unsigned int coherency_line_size: 12;
		unsigned int physical_line_partition: 10;
		unsigned int ways_of_associativity: 10;
	} split;
	u32 full;
};

union _cpuid4_leaf_ecx {
	struct {
		unsigned int number_of_sets: 32;
	} split;
	u32 full;
};

struct _cpuid4_info_regs {
	union _cpuid4_leaf_eax eax;
	union _cpuid4_leaf_ebx ebx;
	union _cpuid4_leaf_ecx ecx;
	unsigned int id;
	long unsigned int size;
	struct amd_northbridge *nb;
};

union l1_cache {
	struct {
		unsigned int line_size: 8;
		unsigned int lines_per_tag: 8;
		unsigned int assoc: 8;
		unsigned int size_in_kb: 8;
	};
	unsigned int val;
};

union l2_cache {
	struct {
		unsigned int line_size: 8;
		unsigned int lines_per_tag: 4;
		unsigned int assoc: 4;
		unsigned int size_in_kb: 16;
	};
	unsigned int val;
};

union l3_cache {
	struct {
		unsigned int line_size: 8;
		unsigned int lines_per_tag: 4;
		unsigned int assoc: 4;
		unsigned int res: 2;
		unsigned int size_encoded: 14;
	};
	unsigned int val;
};

struct cpuid_bit {
	u16 feature;
	u8 reg;
	u8 bit;
	u32 level;
	u32 sub_leaf;
};

enum cpuid_leafs {
	CPUID_1_EDX = 0,
	CPUID_8000_0001_EDX = 1,
	CPUID_8086_0001_EDX = 2,
	CPUID_LNX_1 = 3,
	CPUID_1_ECX = 4,
	CPUID_C000_0001_EDX = 5,
	CPUID_8000_0001_ECX = 6,
	CPUID_LNX_2 = 7,
	CPUID_LNX_3 = 8,
	CPUID_7_0_EBX = 9,
	CPUID_D_1_EAX = 10,
	CPUID_LNX_4 = 11,
	CPUID_7_1_EAX = 12,
	CPUID_8000_0008_EBX = 13,
	CPUID_6_EAX = 14,
	CPUID_8000_000A_EDX = 15,
	CPUID_7_ECX = 16,
	CPUID_8000_0007_EBX = 17,
	CPUID_7_EDX = 18,
	CPUID_8000_001F_EAX = 19,
};

enum kgdb_bptype {
	BP_BREAKPOINT = 0,
	BP_HARDWARE_BREAKPOINT = 1,
	BP_WRITE_WATCHPOINT = 2,
	BP_READ_WATCHPOINT = 3,
	BP_ACCESS_WATCHPOINT = 4,
	BP_POKE_BREAKPOINT = 5,
};

struct kgdb_arch {
	unsigned char gdb_bpt_instr[1];
	long unsigned int flags;
	int (*set_breakpoint)(long unsigned int, char *);
	int (*remove_breakpoint)(long unsigned int, char *);
	int (*set_hw_breakpoint)(long unsigned int, int, enum kgdb_bptype);
	int (*remove_hw_breakpoint)(long unsigned int, int, enum kgdb_bptype);
	void (*disable_hw_break)(struct pt_regs *);
	void (*remove_all_hw_break)();
	void (*correct_hw_break)();
	void (*enable_nmi)(bool);
};

struct cpu_dev {
	const char *c_vendor;
	const char *c_ident[2];
	void (*c_early_init)(struct cpuinfo_x86 *);
	void (*c_bsp_init)(struct cpuinfo_x86 *);
	void (*c_init)(struct cpuinfo_x86 *);
	void (*c_identify)(struct cpuinfo_x86 *);
	void (*c_detect_tlb)(struct cpuinfo_x86 *);
	int c_x86_vendor;
};

struct ppin_info {
	int feature;
	int msr_ppin_ctl;
	int msr_ppin;
};

struct cpuid_dependent_feature {
	u32 feature;
	u32 level;
};

enum spectre_v2_mitigation {
	SPECTRE_V2_NONE = 0,
	SPECTRE_V2_RETPOLINE = 1,
	SPECTRE_V2_LFENCE = 2,
	SPECTRE_V2_EIBRS = 3,
	SPECTRE_V2_EIBRS_RETPOLINE = 4,
	SPECTRE_V2_EIBRS_LFENCE = 5,
};

enum spectre_v2_user_mitigation {
	SPECTRE_V2_USER_NONE = 0,
	SPECTRE_V2_USER_STRICT = 1,
	SPECTRE_V2_USER_STRICT_PREFERRED = 2,
	SPECTRE_V2_USER_PRCTL = 3,
	SPECTRE_V2_USER_SECCOMP = 4,
};

enum ssb_mitigation {
	SPEC_STORE_BYPASS_NONE = 0,
	SPEC_STORE_BYPASS_DISABLE = 1,
	SPEC_STORE_BYPASS_PRCTL = 2,
	SPEC_STORE_BYPASS_SECCOMP = 3,
};

enum l1tf_mitigations {
	L1TF_MITIGATION_OFF = 0,
	L1TF_MITIGATION_FLUSH_NOWARN = 1,
	L1TF_MITIGATION_FLUSH = 2,
	L1TF_MITIGATION_FLUSH_NOSMT = 3,
	L1TF_MITIGATION_FULL = 4,
	L1TF_MITIGATION_FULL_FORCE = 5,
};

enum mds_mitigations {
	MDS_MITIGATION_OFF = 0,
	MDS_MITIGATION_FULL = 1,
	MDS_MITIGATION_VMWERV = 2,
};

struct bpf_run_ctx {};

enum cpuhp_smt_control {
	CPU_SMT_ENABLED = 0,
	CPU_SMT_DISABLED = 1,
	CPU_SMT_FORCE_DISABLED = 2,
	CPU_SMT_NOT_SUPPORTED = 3,
	CPU_SMT_NOT_IMPLEMENTED = 4,
};

enum btf_kfunc_type {
	BTF_KFUNC_TYPE_CHECK = 0,
	BTF_KFUNC_TYPE_ACQUIRE = 1,
	BTF_KFUNC_TYPE_RELEASE = 2,
	BTF_KFUNC_TYPE_RET_NULL = 3,
	BTF_KFUNC_TYPE_KPTR_ACQUIRE = 4,
	BTF_KFUNC_TYPE_MAX = 5,
};

enum {
	BPF_MAP_VALUE_OFF_MAX = 8,
	BPF_MAP_OFF_ARR_MAX = 10,
};

enum bpf_type_flag {
	PTR_MAYBE_NULL = 256,
	MEM_RDONLY = 512,
	MEM_ALLOC = 1024,
	MEM_USER = 2048,
	MEM_PERCPU = 4096,
	OBJ_RELEASE = 8192,
	PTR_UNTRUSTED = 16384,
	MEM_UNINIT = 32768,
	DYNPTR_TYPE_LOCAL = 65536,
	DYNPTR_TYPE_RINGBUF = 131072,
	MEM_FIXED_SIZE = 262144,
	__BPF_TYPE_FLAG_MAX = 262145,
	__BPF_TYPE_LAST_FLAG = 262144,
};

enum bpf_arg_type {
	ARG_DONTCARE = 0,
	ARG_CONST_MAP_PTR = 1,
	ARG_PTR_TO_MAP_KEY = 2,
	ARG_PTR_TO_MAP_VALUE = 3,
	ARG_PTR_TO_MEM = 4,
	ARG_CONST_SIZE = 5,
	ARG_CONST_SIZE_OR_ZERO = 6,
	ARG_PTR_TO_CTX = 7,
	ARG_ANYTHING = 8,
	ARG_PTR_TO_SPIN_LOCK = 9,
	ARG_PTR_TO_SOCK_COMMON = 10,
	ARG_PTR_TO_INT = 11,
	ARG_PTR_TO_LONG = 12,
	ARG_PTR_TO_SOCKET = 13,
	ARG_PTR_TO_BTF_ID = 14,
	ARG_PTR_TO_ALLOC_MEM = 15,
	ARG_CONST_ALLOC_SIZE_OR_ZERO = 16,
	ARG_PTR_TO_BTF_ID_SOCK_COMMON = 17,
	ARG_PTR_TO_PERCPU_BTF_ID = 18,
	ARG_PTR_TO_FUNC = 19,
	ARG_PTR_TO_STACK = 20,
	ARG_PTR_TO_CONST_STR = 21,
	ARG_PTR_TO_TIMER = 22,
	ARG_PTR_TO_KPTR = 23,
	ARG_PTR_TO_DYNPTR = 24,
	__BPF_ARG_TYPE_MAX = 25,
	ARG_PTR_TO_MAP_VALUE_OR_NULL = 259,
	ARG_PTR_TO_MEM_OR_NULL = 260,
	ARG_PTR_TO_CTX_OR_NULL = 263,
	ARG_PTR_TO_SOCKET_OR_NULL = 269,
	ARG_PTR_TO_ALLOC_MEM_OR_NULL = 271,
	ARG_PTR_TO_STACK_OR_NULL = 276,
	ARG_PTR_TO_BTF_ID_OR_NULL = 270,
	ARG_PTR_TO_UNINIT_MEM = 32772,
	ARG_PTR_TO_FIXED_SIZE_MEM = 262148,
	__BPF_ARG_TYPE_LIMIT = 524287,
};

enum bpf_return_type {
	RET_INTEGER = 0,
	RET_VOID = 1,
	RET_PTR_TO_MAP_VALUE = 2,
	RET_PTR_TO_SOCKET = 3,
	RET_PTR_TO_TCP_SOCK = 4,
	RET_PTR_TO_SOCK_COMMON = 5,
	RET_PTR_TO_ALLOC_MEM = 6,
	RET_PTR_TO_MEM_OR_BTF_ID = 7,
	RET_PTR_TO_BTF_ID = 8,
	__BPF_RET_TYPE_MAX = 9,
	RET_PTR_TO_MAP_VALUE_OR_NULL = 258,
	RET_PTR_TO_SOCKET_OR_NULL = 259,
	RET_PTR_TO_TCP_SOCK_OR_NULL = 260,
	RET_PTR_TO_SOCK_COMMON_OR_NULL = 261,
	RET_PTR_TO_ALLOC_MEM_OR_NULL = 1286,
	RET_PTR_TO_DYNPTR_MEM_OR_NULL = 262,
	RET_PTR_TO_BTF_ID_OR_NULL = 264,
	__BPF_RET_TYPE_LIMIT = 524287,
};

enum bpf_reg_type {
	NOT_INIT = 0,
	SCALAR_VALUE = 1,
	PTR_TO_CTX = 2,
	CONST_PTR_TO_MAP = 3,
	PTR_TO_MAP_VALUE = 4,
	PTR_TO_MAP_KEY = 5,
	PTR_TO_STACK = 6,
	PTR_TO_PACKET_META = 7,
	PTR_TO_PACKET = 8,
	PTR_TO_PACKET_END = 9,
	PTR_TO_FLOW_KEYS = 10,
	PTR_TO_SOCKET = 11,
	PTR_TO_SOCK_COMMON = 12,
	PTR_TO_TCP_SOCK = 13,
	PTR_TO_TP_BUFFER = 14,
	PTR_TO_XDP_SOCK = 15,
	PTR_TO_BTF_ID = 16,
	PTR_TO_MEM = 17,
	PTR_TO_BUF = 18,
	PTR_TO_FUNC = 19,
	__BPF_REG_TYPE_MAX = 20,
	PTR_TO_MAP_VALUE_OR_NULL = 260,
	PTR_TO_SOCKET_OR_NULL = 267,
	PTR_TO_SOCK_COMMON_OR_NULL = 268,
	PTR_TO_TCP_SOCK_OR_NULL = 269,
	PTR_TO_BTF_ID_OR_NULL = 272,
	__BPF_REG_TYPE_LIMIT = 524287,
};

enum bpf_cgroup_storage_type {
	BPF_CGROUP_STORAGE_SHARED = 0,
	BPF_CGROUP_STORAGE_PERCPU = 1,
	__BPF_CGROUP_STORAGE_MAX = 2,
};

enum bpf_tramp_prog_type {
	BPF_TRAMP_FENTRY = 0,
	BPF_TRAMP_FEXIT = 1,
	BPF_TRAMP_MODIFY_RETURN = 2,
	BPF_TRAMP_MAX = 3,
	BPF_TRAMP_REPLACE = 4,
};

enum vmx_l1d_flush_state {
	VMENTER_L1D_FLUSH_AUTO = 0,
	VMENTER_L1D_FLUSH_NEVER = 1,
	VMENTER_L1D_FLUSH_COND = 2,
	VMENTER_L1D_FLUSH_ALWAYS = 3,
	VMENTER_L1D_FLUSH_EPT_DISABLED = 4,
	VMENTER_L1D_FLUSH_NOT_REQUIRED = 5,
};

enum taa_mitigations {
	TAA_MITIGATION_OFF = 0,
	TAA_MITIGATION_UCODE_NEEDED = 1,
	TAA_MITIGATION_VERW = 2,
	TAA_MITIGATION_TSX_DISABLED = 3,
};

enum mmio_mitigations {
	MMIO_MITIGATION_OFF = 0,
	MMIO_MITIGATION_UCODE_NEEDED = 1,
	MMIO_MITIGATION_VERW = 2,
};

enum srbds_mitigations {
	SRBDS_MITIGATION_OFF = 0,
	SRBDS_MITIGATION_UCODE_NEEDED = 1,
	SRBDS_MITIGATION_FULL = 2,
	SRBDS_MITIGATION_TSX_OFF = 3,
	SRBDS_MITIGATION_HYPERVISOR = 4,
};

enum l1d_flush_mitigations {
	L1D_FLUSH_OFF = 0,
	L1D_FLUSH_ON = 1,
};

enum spectre_v1_mitigation {
	SPECTRE_V1_MITIGATION_NONE = 0,
	SPECTRE_V1_MITIGATION_AUTO = 1,
};

enum spectre_v2_mitigation_cmd {
	SPECTRE_V2_CMD_NONE = 0,
	SPECTRE_V2_CMD_AUTO = 1,
	SPECTRE_V2_CMD_FORCE = 2,
	SPECTRE_V2_CMD_RETPOLINE = 3,
	SPECTRE_V2_CMD_RETPOLINE_GENERIC = 4,
	SPECTRE_V2_CMD_RETPOLINE_LFENCE = 5,
	SPECTRE_V2_CMD_EIBRS = 6,
	SPECTRE_V2_CMD_EIBRS_RETPOLINE = 7,
	SPECTRE_V2_CMD_EIBRS_LFENCE = 8,
};

enum spectre_v2_user_cmd {
	SPECTRE_V2_USER_CMD_NONE = 0,
	SPECTRE_V2_USER_CMD_AUTO = 1,
	SPECTRE_V2_USER_CMD_FORCE = 2,
	SPECTRE_V2_USER_CMD_PRCTL = 3,
	SPECTRE_V2_USER_CMD_PRCTL_IBPB = 4,
	SPECTRE_V2_USER_CMD_SECCOMP = 5,
	SPECTRE_V2_USER_CMD_SECCOMP_IBPB = 6,
};

enum ssb_mitigation_cmd {
	SPEC_STORE_BYPASS_CMD_NONE = 0,
	SPEC_STORE_BYPASS_CMD_AUTO = 1,
	SPEC_STORE_BYPASS_CMD_ON = 2,
	SPEC_STORE_BYPASS_CMD_PRCTL = 3,
	SPEC_STORE_BYPASS_CMD_SECCOMP = 4,
};

struct aperfmperf {
	seqcount_t seq;
	long unsigned int last_update;
	u64 acnt;
	u64 mcnt;
	u64 aperf;
	u64 mperf;
};

struct cpuid_dep {
	unsigned int feature;
	unsigned int depends;
};

enum vmx_feature_leafs {
	MISC_FEATURES = 0,
	PRIMARY_CTLS = 1,
	SECONDARY_CTLS = 2,
	NR_VMX_FEATURE_WORDS = 3,
};

struct semaphore {
	raw_spinlock_t lock;
	unsigned int count;
	struct list_head wait_list;
};

struct cpu_signature {
	unsigned int sig;
	unsigned int pf;
	unsigned int rev;
};

struct ucode_cpu_info {
	struct cpu_signature cpu_sig;
	int valid;
	void *mc;
};

struct _tlb_table {
	unsigned char descriptor;
	char tlb_type;
	unsigned int entries;
	char info[128];
};

enum split_lock_detect_state {
	sld_off = 0,
	sld_warn = 1,
	sld_fatal = 2,
	sld_ratelimit = 3,
};

struct sku_microcode {
	u8 model;
	u8 stepping;
	u32 microcode;
};

struct cpuid_regs {
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
};

enum pconfig_target {
	INVALID_TARGET = 0,
	MKTME_TARGET = 1,
	PCONFIG_TARGET_NR = 2,
};

enum {
	PCONFIG_CPUID_SUBLEAF_INVALID = 0,
	PCONFIG_CPUID_SUBLEAF_TARGETID = 1,
};

enum tsx_ctrl_states {
	TSX_CTRL_ENABLE = 0,
	TSX_CTRL_DISABLE = 1,
	TSX_CTRL_RTM_ALWAYS_ABORT = 2,
	TSX_CTRL_NOT_SUPPORTED = 3,
};

enum energy_perf_value_index {
	EPB_INDEX_PERFORMANCE = 0,
	EPB_INDEX_BALANCE_PERFORMANCE = 1,
	EPB_INDEX_NORMAL = 2,
	EPB_INDEX_BALANCE_POWERSAVE = 3,
	EPB_INDEX_POWERSAVE = 4,
};

enum mf_flags {
	MF_COUNT_INCREASED = 1,
	MF_ACTION_REQUIRED = 2,
	MF_MUST_KILL = 4,
	MF_SOFT_OFFLINE = 8,
	MF_UNPOISON = 16,
};

enum task_work_notify_mode {
	TWA_NONE = 0,
	TWA_RESUME = 1,
	TWA_SIGNAL = 2,
	TWA_SIGNAL_NO_IPI = 3,
};

struct mce {
	__u64 status;
	__u64 misc;
	__u64 addr;
	__u64 mcgstatus;
	__u64 ip;
	__u64 tsc;
	__u64 time;
	__u8 cpuvendor;
	__u8 inject_flags;
	__u8 severity;
	__u8 pad;
	__u32 cpuid;
	__u8 cs;
	__u8 bank;
	__u8 cpu;
	__u8 finished;
	__u32 extcpu;
	__u32 socketid;
	__u32 apicid;
	__u64 mcgcap;
	__u64 synd;
	__u64 ipid;
	__u64 ppin;
	__u32 microcode;
	__u64 kflags;
};

enum mce_notifier_prios {
	MCE_PRIO_LOWEST = 0,
	MCE_PRIO_MCELOG = 1,
	MCE_PRIO_EDAC = 2,
	MCE_PRIO_NFIT = 3,
	MCE_PRIO_EXTLOG = 4,
	MCE_PRIO_UC = 5,
	MCE_PRIO_EARLY = 6,
	MCE_PRIO_CEC = 7,
	MCE_PRIO_HIGHEST = 7,
};

typedef long unsigned int mce_banks_t[1];

enum mcp_flags {
	MCP_TIMESTAMP = 1,
	MCP_UC = 2,
	MCP_DONTLOG = 4,
	MCP_QUEUE_LOG = 8,
};

enum severity_level {
	MCE_NO_SEVERITY = 0,
	MCE_DEFERRED_SEVERITY = 1,
	MCE_UCNA_SEVERITY = 1,
	MCE_KEEP_SEVERITY = 2,
	MCE_SOME_SEVERITY = 3,
	MCE_AO_SEVERITY = 4,
	MCE_UC_SEVERITY = 5,
	MCE_AR_SEVERITY = 6,
	MCE_PANIC_SEVERITY = 7,
};

struct mce_evt_llist {
	struct llist_node llnode;
	struct mce mce;
};

struct mca_config {
	__u64 lmce_disabled: 1;
	__u64 disabled: 1;
	__u64 ser: 1;
	__u64 recovery: 1;
	__u64 bios_cmci_threshold: 1;
	__u64 initialized: 1;
	__u64 __reserved: 58;
	bool dont_log_ce;
	bool cmci_disabled;
	bool ignore_ce;
	bool print_all;
	int monarch_timeout;
	int panic_timeout;
	u32 rip_msr;
	s8 bootlog;
};

struct mce_vendor_flags {
	__u64 overflow_recov: 1;
	__u64 succor: 1;
	__u64 smca: 1;
	__u64 amd_threshold: 1;
	__u64 p5: 1;
	__u64 winchip: 1;
	__u64 snb_ifu_quirk: 1;
	__u64 skx_repmov_quirk: 1;
	__u64 __reserved_0: 56;
};

enum mca_msr {
	MCA_CTL = 0,
	MCA_STATUS = 1,
	MCA_ADDR = 2,
	MCA_MISC = 3,
};

struct trace_event_raw_mce_record {
	struct trace_entry ent;
	u64 mcgcap;
	u64 mcgstatus;
	u64 status;
	u64 addr;
	u64 misc;
	u64 synd;
	u64 ipid;
	u64 ip;
	u64 tsc;
	u64 walltime;
	u32 cpu;
	u32 cpuid;
	u32 apicid;
	u32 socketid;
	u8 cs;
	u8 bank;
	u8 cpuvendor;
	char __data[0];
};

struct trace_event_data_offsets_mce_record {};

typedef void (*btf_trace_mce_record)(void *, struct mce *);

struct mce_bank {
	u64 ctl;
	__u64 init: 1;
	__u64 __reserved_1: 63;
};

struct mce_bank_dev {
	struct device_attribute attr;
	char attrname[16];
	u8 bank;
};

enum context {
	IN_KERNEL = 1,
	IN_USER = 2,
	IN_KERNEL_RECOV = 3,
};

enum ser {
	SER_REQUIRED = 1,
	NO_SER = 2,
};

enum exception {
	EXCP_CONTEXT = 1,
	NO_EXCP = 2,
};

struct severity {
	u64 mask;
	u64 result;
	unsigned char sev;
	unsigned char mcgmask;
	unsigned char mcgres;
	unsigned char ser;
	unsigned char context;
	unsigned char excp;
	unsigned char covered;
	unsigned char cpu_model;
	unsigned char cpu_minstepping;
	unsigned char bank_lo;
	unsigned char bank_hi;
	char *msg;
};

struct gen_pool;

typedef long unsigned int (*genpool_algo_t)(long unsigned int *, long unsigned int, long unsigned int, unsigned int, void *, struct gen_pool *, long unsigned int);

struct gen_pool {
	spinlock_t lock;
	struct list_head chunks;
	int min_alloc_order;
	genpool_algo_t algo;
	void *data;
	const char *name;
};

enum {
	CMCI_STORM_NONE = 0,
	CMCI_STORM_ACTIVE = 1,
	CMCI_STORM_SUBSIDED = 2,
};

enum kobject_action {
	KOBJ_ADD = 0,
	KOBJ_REMOVE = 1,
	KOBJ_CHANGE = 2,
	KOBJ_MOVE = 3,
	KOBJ_ONLINE = 4,
	KOBJ_OFFLINE = 5,
	KOBJ_BIND = 6,
	KOBJ_UNBIND = 7,
};

enum smca_bank_types {
	SMCA_LS = 0,
	SMCA_LS_V2 = 1,
	SMCA_IF = 2,
	SMCA_L2_CACHE = 3,
	SMCA_DE = 4,
	SMCA_RESERVED = 5,
	SMCA_EX = 6,
	SMCA_FP = 7,
	SMCA_L3_CACHE = 8,
	SMCA_CS = 9,
	SMCA_CS_V2 = 10,
	SMCA_PIE = 11,
	SMCA_UMC = 12,
	SMCA_UMC_V2 = 13,
	SMCA_PB = 14,
	SMCA_PSP = 15,
	SMCA_PSP_V2 = 16,
	SMCA_SMU = 17,
	SMCA_SMU_V2 = 18,
	SMCA_MP5 = 19,
	SMCA_MPDMA = 20,
	SMCA_NBIO = 21,
	SMCA_PCIE = 22,
	SMCA_PCIE_V2 = 23,
	SMCA_XGMI_PCS = 24,
	SMCA_NBIF = 25,
	SMCA_SHUB = 26,
	SMCA_SATA = 27,
	SMCA_USB = 28,
	SMCA_GMI_PCS = 29,
	SMCA_XGMI_PHY = 30,
	SMCA_WAFL_PHY = 31,
	SMCA_GMI_PHY = 32,
	N_SMCA_BANK_TYPES = 33,
};

struct smca_hwid {
	unsigned int bank_type;
	u32 hwid_mcatype;
};

struct smca_bank {
	const struct smca_hwid *hwid;
	u32 id;
	u8 sysfs_id;
};

struct smca_bank_name {
	const char *name;
	const char *long_name;
};

struct thresh_restart {
	struct threshold_block *b;
	int reset;
	int set_lvt_off;
	int lvt_off;
	u16 old_limit;
};

struct threshold_attr {
	struct attribute attr;
	ssize_t (*show)(struct threshold_block *, char *);
	ssize_t (*store)(struct threshold_block *, const char *, size_t);
};

enum {
	CPER_SEV_RECOVERABLE = 0,
	CPER_SEV_FATAL = 1,
	CPER_SEV_CORRECTED = 2,
	CPER_SEV_INFORMATIONAL = 3,
};

struct cper_record_header {
	char signature[4];
	u16 revision;
	u32 signature_end;
	u16 section_count;
	u32 error_severity;
	u32 validation_bits;
	u32 record_length;
	u64 timestamp;
	guid_t platform_id;
	guid_t partition_id;
	guid_t creator_id;
	guid_t notification_type;
	u64 record_id;
	u32 flags;
	u64 persistence_information;
	u8 reserved[12];
} __attribute__((packed));

struct cper_section_descriptor {
	u32 section_offset;
	u32 section_length;
	u16 revision;
	u8 validation_bits;
	u8 reserved;
	u32 flags;
	guid_t section_type;
	guid_t fru_id;
	u32 section_severity;
	u8 fru_text[20];
};

struct cper_ia_proc_ctx {
	u16 reg_ctx_type;
	u16 reg_arr_size;
	u32 msr_addr;
	u64 mm_reg_addr;
};

struct cper_sec_mem_err {
	u64 validation_bits;
	u64 error_status;
	u64 physical_addr;
	u64 physical_addr_mask;
	u16 node;
	u16 card;
	u16 module;
	u16 bank;
	u16 device;
	u16 row;
	u16 column;
	u16 bit_pos;
	u64 requestor_id;
	u64 responder_id;
	u64 target_id;
	u8 error_type;
	u8 extended;
	u16 rank;
	u16 mem_array_handle;
	u16 mem_dev_handle;
};

enum {
	GHES_SEV_NO = 0,
	GHES_SEV_CORRECTED = 1,
	GHES_SEV_RECOVERABLE = 2,
	GHES_SEV_PANIC = 3,
};

struct cper_mce_record {
	struct cper_record_header hdr;
	struct cper_section_descriptor sec_hdr;
	struct mce mce;
};

struct miscdevice {
	int minor;
	const char *name;
	const struct file_operations *fops;
	struct list_head list;
	struct device *parent;
	struct device *this_device;
	const struct attribute_group **groups;
	const char *nodename;
	umode_t mode;
};

typedef struct poll_table_struct poll_table;

struct mce_log_buffer {
	char signature[12];
	unsigned int len;
	unsigned int next;
	unsigned int flags;
	unsigned int recordlen;
	struct mce entry[0];
};

typedef __u8 mtrr_type;

struct mtrr_ops {
	u32 vendor;
	u32 use_intel_if;
	void (*set)(unsigned int, long unsigned int, long unsigned int, mtrr_type);
	void (*set_all)();
	void (*get)(unsigned int, long unsigned int *, long unsigned int *, mtrr_type *);
	int (*get_free_region)(long unsigned int, long unsigned int, int);
	int (*validate_add_page)(long unsigned int, long unsigned int, unsigned int);
	int (*have_wrcomb)();
};

struct set_mtrr_data {
	long unsigned int smp_base;
	long unsigned int smp_size;
	unsigned int smp_reg;
	mtrr_type smp_type;
};

struct mtrr_value {
	mtrr_type ltype;
	long unsigned int lbase;
	long unsigned int lsize;
};

struct proc_ops {
	unsigned int proc_flags;
	int (*proc_open)(struct inode *, struct file *);
	ssize_t (*proc_read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*proc_read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*proc_write)(struct file *, const char *, size_t, loff_t *);
	loff_t (*proc_lseek)(struct file *, loff_t, int);
	int (*proc_release)(struct inode *, struct file *);
	__poll_t (*proc_poll)(struct file *, struct poll_table_struct *);
	long int (*proc_ioctl)(struct file *, unsigned int, long unsigned int);
	long int (*proc_compat_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*proc_mmap)(struct file *, struct vm_area_struct *);
	long unsigned int (*proc_get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
};

struct mtrr_sentry {
	__u64 base;
	__u32 size;
	__u32 type;
};

struct mtrr_gentry {
	__u64 base;
	__u32 size;
	__u32 regnum;
	__u32 type;
	__u32 _pad;
};

typedef u32 compat_uint_t;

struct mtrr_sentry32 {
	compat_ulong_t base;
	compat_uint_t size;
	compat_uint_t type;
};

struct mtrr_gentry32 {
	compat_ulong_t regnum;
	compat_uint_t base;
	compat_uint_t size;
	compat_uint_t type;
};

struct mtrr_var_range {
	__u32 base_lo;
	__u32 base_hi;
	__u32 mask_lo;
	__u32 mask_hi;
};

struct mtrr_state_type {
	struct mtrr_var_range var_ranges[256];
	mtrr_type fixed_ranges[88];
	unsigned char enabled;
	unsigned char have_fixed;
	mtrr_type def_type;
};

struct fixed_range_block {
	int base_msr;
	int ranges;
};

struct var_mtrr_range_state {
	long unsigned int base_pfn;
	long unsigned int size_pfn;
	mtrr_type type;
};

struct var_mtrr_state {
	long unsigned int range_startk;
	long unsigned int range_sizek;
	long unsigned int chunk_sizek;
	long unsigned int gran_sizek;
	unsigned int reg;
};

struct mtrr_cleanup_result {
	long unsigned int gran_sizek;
	long unsigned int chunk_sizek;
	long unsigned int lose_cover_sizek;
	unsigned int num_reg;
	int bad;
};

struct subsys_interface {
	const char *name;
	struct bus_type *subsys;
	struct list_head node;
	int (*add_dev)(struct device *, struct subsys_interface *);
	void (*remove_dev)(struct device *, struct subsys_interface *);
};

struct property_entry;

struct platform_device_info {
	struct device *parent;
	struct fwnode_handle *fwnode;
	bool of_node_reused;
	const char *name;
	int id;
	const struct resource *res;
	unsigned int num_res;
	const void *data;
	size_t size_data;
	u64 dma_mask;
	const struct property_entry *properties;
};

enum dev_prop_type {
	DEV_PROP_U8 = 0,
	DEV_PROP_U16 = 1,
	DEV_PROP_U32 = 2,
	DEV_PROP_U64 = 3,
	DEV_PROP_STRING = 4,
	DEV_PROP_REF = 5,
};

struct property_entry {
	const char *name;
	size_t length;
	bool is_inline;
	enum dev_prop_type type;
	union {
		const void *pointer;
		union {
			u8 u8_data[8];
			u16 u16_data[4];
			u32 u32_data[2];
			u64 u64_data[1];
			const char *str[1];
		} value;
	};
};

struct cpio_data {
	void *data;
	size_t size;
	char name[18];
};

enum ucode_state {
	UCODE_OK = 0,
	UCODE_NEW = 1,
	UCODE_UPDATED = 2,
	UCODE_NFOUND = 3,
	UCODE_ERROR = 4,
};

struct microcode_ops {
	enum ucode_state (*request_microcode_user)(int, const void *, size_t);
	enum ucode_state (*request_microcode_fw)(int, struct device *, bool);
	void (*microcode_fini_cpu)(int);
	enum ucode_state (*apply_microcode)(int);
	int (*collect_cpu_info)(int, struct cpu_signature *);
};

struct cpu_info_ctx {
	struct cpu_signature *cpu_sig;
	int err;
};

struct firmware {
	size_t size;
	const u8 *data;
	void *priv;
};

struct ucode_patch {
	struct list_head plist;
	void *data;
	u32 patch_id;
	u16 equiv_cpu;
};

struct microcode_header_intel {
	unsigned int hdrver;
	unsigned int rev;
	unsigned int date;
	unsigned int sig;
	unsigned int cksum;
	unsigned int ldrver;
	unsigned int pf;
	unsigned int datasize;
	unsigned int totalsize;
	unsigned int reserved[3];
};

struct microcode_intel {
	struct microcode_header_intel hdr;
	unsigned int bits[0];
};

struct extended_signature {
	unsigned int sig;
	unsigned int pf;
	unsigned int cksum;
};

struct extended_sigtable {
	unsigned int count;
	unsigned int cksum;
	unsigned int reserved[3];
	struct extended_signature sigs[0];
};

struct equiv_cpu_entry {
	u32 installed_cpu;
	u32 fixed_errata_mask;
	u32 fixed_errata_compare;
	u16 equiv_cpu;
	u16 res;
};

struct microcode_header_amd {
	u32 data_code;
	u32 patch_id;
	u16 mc_patch_data_id;
	u8 mc_patch_data_len;
	u8 init_flag;
	u32 mc_patch_data_checksum;
	u32 nb_dev_id;
	u32 sb_dev_id;
	u16 processor_rev_id;
	u8 nb_rev_id;
	u8 sb_rev_id;
	u8 bios_api_rev;
	u8 reserved1[3];
	u32 match_reg[8];
};

struct microcode_amd {
	struct microcode_header_amd hdr;
	unsigned int mpb[0];
};

struct equiv_cpu_table {
	unsigned int num_entries;
	struct equiv_cpu_entry *entry;
};

struct cont_desc {
	struct microcode_amd *mc;
	u32 cpuid_1_eax;
	u32 psize;
	u8 *data;
	size_t size;
};

enum resctrl_conf_type {
	CDP_NONE = 0,
	CDP_CODE = 1,
	CDP_DATA = 2,
};

struct resctrl_staged_config {
	u32 new_ctrl;
	bool have_new_ctrl;
};

struct mbm_state;

struct pseudo_lock_region;

struct rdt_domain {
	struct list_head list;
	int id;
	struct cpumask cpu_mask;
	long unsigned int *rmid_busy_llc;
	struct mbm_state *mbm_total;
	struct mbm_state *mbm_local;
	struct delayed_work mbm_over;
	struct delayed_work cqm_limbo;
	int mbm_work_cpu;
	int cqm_work_cpu;
	struct pseudo_lock_region *plr;
	struct resctrl_staged_config staged_config[3];
};

struct mbm_state {
	u64 chunks;
	u64 prev_msr;
	u64 prev_bw_msr;
	u32 prev_bw;
	u32 delta_bw;
	bool delta_comp;
};

struct resctrl_schema;

struct pseudo_lock_region {
	struct resctrl_schema *s;
	struct rdt_domain *d;
	u32 cbm;
	wait_queue_head_t lock_thread_wq;
	int thread_done;
	int cpu;
	unsigned int line_size;
	unsigned int size;
	void *kmem;
	unsigned int minor;
	struct dentry *debugfs_dir;
	struct list_head pm_reqs;
};

struct resctrl_cache {
	unsigned int cbm_len;
	unsigned int min_cbm_bits;
	unsigned int shareable_bits;
	bool arch_has_sparse_bitmaps;
	bool arch_has_empty_bitmaps;
	bool arch_has_per_cpu_cfg;
};

enum membw_throttle_mode {
	THREAD_THROTTLE_UNDEFINED = 0,
	THREAD_THROTTLE_MAX = 1,
	THREAD_THROTTLE_PER_THREAD = 2,
};

struct resctrl_membw {
	u32 min_bw;
	u32 bw_gran;
	u32 delay_linear;
	bool arch_needs_linear;
	enum membw_throttle_mode throttle_mode;
	bool mba_sc;
	u32 *mb_map;
};

struct rdt_parse_data;

struct rdt_resource {
	int rid;
	bool alloc_enabled;
	bool mon_enabled;
	bool alloc_capable;
	bool mon_capable;
	int num_rmid;
	int cache_level;
	struct resctrl_cache cache;
	struct resctrl_membw membw;
	struct list_head domains;
	char *name;
	int data_width;
	u32 default_ctrl;
	const char *format_str;
	int (*parse_ctrlval)(struct rdt_parse_data *, struct resctrl_schema *, struct rdt_domain *);
	struct list_head evt_list;
	long unsigned int fflags;
	bool cdp_capable;
};

struct rdtgroup;

struct rdt_parse_data {
	struct rdtgroup *rdtgrp;
	char *buf;
};

struct resctrl_schema {
	struct list_head list;
	char name[8];
	enum resctrl_conf_type conf_type;
	struct rdt_resource *res;
	u32 num_closid;
};

enum rdt_group_type {
	RDTCTRL_GROUP = 0,
	RDTMON_GROUP = 1,
	RDT_NUM_GROUP = 2,
};

struct mongroup {
	struct kernfs_node *mon_data_kn;
	struct rdtgroup *parent;
	struct list_head crdtgrp_list;
	u32 rmid;
};

enum rdtgrp_mode {
	RDT_MODE_SHAREABLE = 0,
	RDT_MODE_EXCLUSIVE = 1,
	RDT_MODE_PSEUDO_LOCKSETUP = 2,
	RDT_MODE_PSEUDO_LOCKED = 3,
	RDT_NUM_MODES = 4,
};

struct rdtgroup {
	struct kernfs_node *kn;
	struct list_head rdtgroup_list;
	u32 closid;
	struct cpumask cpu_mask;
	int flags;
	atomic_t waitcount;
	enum rdt_group_type type;
	struct mongroup mon;
	enum rdtgrp_mode mode;
	struct pseudo_lock_region *plr;
};

struct rdt_hw_domain {
	struct rdt_domain d_resctrl;
	u32 *ctrl_val;
	u32 *mbps_val;
};

struct msr_param {
	struct rdt_resource *res;
	u32 low;
	u32 high;
};

struct rdt_hw_resource {
	struct rdt_resource r_resctrl;
	u32 num_closid;
	unsigned int msr_base;
	void (*msr_update)(struct rdt_domain *, struct msr_param *, struct rdt_resource *);
	unsigned int mon_scale;
	unsigned int mbm_width;
	bool cdp_enabled;
};

enum resctrl_res_level {
	RDT_RESOURCE_L3 = 0,
	RDT_RESOURCE_L2 = 1,
	RDT_RESOURCE_MBA = 2,
	RDT_NUM_RESOURCES = 3,
};

union cpuid_0x10_1_eax {
	struct {
		unsigned int cbm_len: 5;
	} split;
	unsigned int full;
};

union cpuid_0x10_3_eax {
	struct {
		unsigned int max_delay: 12;
	} split;
	unsigned int full;
};

union cpuid_0x10_x_edx {
	struct {
		unsigned int cos_max: 16;
	} split;
	unsigned int full;
};

enum {
	RDT_FLAG_CMT = 0,
	RDT_FLAG_MBM_TOTAL = 1,
	RDT_FLAG_MBM_LOCAL = 2,
	RDT_FLAG_L3_CAT = 3,
	RDT_FLAG_L3_CDP = 4,
	RDT_FLAG_L2_CAT = 5,
	RDT_FLAG_L2_CDP = 6,
	RDT_FLAG_MBA = 7,
};

struct rdt_options {
	char *name;
	int flag;
	bool force_off;
	bool force_on;
};

typedef unsigned int uint;

enum kernfs_node_type {
	KERNFS_DIR = 1,
	KERNFS_FILE = 2,
	KERNFS_LINK = 4,
};

enum kernfs_root_flag {
	KERNFS_ROOT_CREATE_DEACTIVATED = 1,
	KERNFS_ROOT_EXTRA_OPEN_PERM_CHECK = 2,
	KERNFS_ROOT_SUPPORT_EXPORTOP = 4,
	KERNFS_ROOT_SUPPORT_USER_XATTR = 8,
};

struct kernfs_syscall_ops {
	int (*show_options)(struct seq_file *, struct kernfs_root *);
	int (*mkdir)(struct kernfs_node *, const char *, umode_t);
	int (*rmdir)(struct kernfs_node *);
	int (*rename)(struct kernfs_node *, struct kernfs_node *, const char *);
	int (*show_path)(struct seq_file *, struct kernfs_node *, struct kernfs_root *);
};

struct kernfs_fs_context {
	struct kernfs_root *root;
	void *ns_tag;
	long unsigned int magic;
	bool new_sb_created;
};

struct rdt_fs_context {
	struct kernfs_fs_context kfc;
	bool enable_cdpl2;
	bool enable_cdpl3;
	bool enable_mba_mbps;
};

struct mon_evt {
	u32 evtid;
	char *name;
	struct list_head list;
};

union mon_data_bits {
	void *priv;
	struct {
		unsigned int rid: 10;
		unsigned int evtid: 8;
		unsigned int domid: 14;
	} u;
};

struct rmid_read {
	struct rdtgroup *rgrp;
	struct rdt_resource *r;
	struct rdt_domain *d;
	int evtid;
	bool first;
	u64 val;
};

struct rftype {
	char *name;
	umode_t mode;
	const struct kernfs_ops *kf_ops;
	long unsigned int flags;
	long unsigned int fflags;
	int (*seq_show)(struct kernfs_open_file *, struct seq_file *, void *);
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
};

enum rdt_param {
	Opt_cdp = 0,
	Opt_cdpl2 = 1,
	Opt_mba_mbps = 2,
	nr__rdt_params = 3,
};

struct rmid_entry {
	u32 rmid;
	int busy;
	struct list_head list;
};

struct mbm_correction_factor_table {
	u32 rmidthreshold;
	u64 cf;
};

struct trace_event_raw_pseudo_lock_mem_latency {
	struct trace_entry ent;
	u32 latency;
	char __data[0];
};

struct trace_event_raw_pseudo_lock_l2 {
	struct trace_entry ent;
	u64 l2_hits;
	u64 l2_miss;
	char __data[0];
};

struct trace_event_raw_pseudo_lock_l3 {
	struct trace_entry ent;
	u64 l3_hits;
	u64 l3_miss;
	char __data[0];
};

struct trace_event_data_offsets_pseudo_lock_mem_latency {};

struct trace_event_data_offsets_pseudo_lock_l2 {};

struct trace_event_data_offsets_pseudo_lock_l3 {};

typedef void (*btf_trace_pseudo_lock_mem_latency)(void *, u32);

typedef void (*btf_trace_pseudo_lock_l2)(void *, u64, u64);

typedef void (*btf_trace_pseudo_lock_l3)(void *, u64, u64);

struct pseudo_lock_pm_req {
	struct list_head list;
	struct dev_pm_qos_request req;
};

struct residency_counts {
	u64 miss_before;
	u64 hits_before;
	u64 miss_after;
	u64 hits_after;
};

enum mmu_notifier_event {
	MMU_NOTIFY_UNMAP = 0,
	MMU_NOTIFY_CLEAR = 1,
	MMU_NOTIFY_PROTECTION_VMA = 2,
	MMU_NOTIFY_PROTECTION_PAGE = 3,
	MMU_NOTIFY_SOFT_DIRTY = 4,
	MMU_NOTIFY_RELEASE = 5,
	MMU_NOTIFY_MIGRATE = 6,
	MMU_NOTIFY_EXCLUSIVE = 7,
};

struct mmu_notifier;

struct mmu_notifier_range;

struct mmu_notifier_ops {
	void (*release)(struct mmu_notifier *, struct mm_struct *);
	int (*clear_flush_young)(struct mmu_notifier *, struct mm_struct *, long unsigned int, long unsigned int);
	int (*clear_young)(struct mmu_notifier *, struct mm_struct *, long unsigned int, long unsigned int);
	int (*test_young)(struct mmu_notifier *, struct mm_struct *, long unsigned int);
	void (*change_pte)(struct mmu_notifier *, struct mm_struct *, long unsigned int, pte_t);
	int (*invalidate_range_start)(struct mmu_notifier *, const struct mmu_notifier_range *);
	void (*invalidate_range_end)(struct mmu_notifier *, const struct mmu_notifier_range *);
	void (*invalidate_range)(struct mmu_notifier *, struct mm_struct *, long unsigned int, long unsigned int);
	struct mmu_notifier * (*alloc_notifier)(struct mm_struct *);
	void (*free_notifier)(struct mmu_notifier *);
};

struct mmu_notifier {
	struct hlist_node hlist;
	const struct mmu_notifier_ops *ops;
	struct mm_struct *mm;
	struct callback_head rcu;
	unsigned int users;
};

struct mmu_notifier_range {
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	long unsigned int start;
	long unsigned int end;
	unsigned int flags;
	enum mmu_notifier_event event;
	void *owner;
};

enum sgx_page_type {
	SGX_PAGE_TYPE_SECS = 0,
	SGX_PAGE_TYPE_TCS = 1,
	SGX_PAGE_TYPE_REG = 2,
	SGX_PAGE_TYPE_VA = 3,
	SGX_PAGE_TYPE_TRIM = 4,
};

struct sgx_encl_page;

struct sgx_epc_page {
	unsigned int section;
	u16 flags;
	u16 poison;
	struct sgx_encl_page *owner;
	struct list_head list;
};

struct sgx_encl;

struct sgx_va_page;

struct sgx_encl_page {
	long unsigned int desc;
	long unsigned int vm_max_prot_bits;
	struct sgx_epc_page *epc_page;
	struct sgx_encl *encl;
	struct sgx_va_page *va_page;
};

struct sgx_encl {
	long unsigned int base;
	long unsigned int size;
	long unsigned int flags;
	unsigned int page_cnt;
	unsigned int secs_child_cnt;
	struct mutex lock;
	struct xarray page_array;
	struct sgx_encl_page secs;
	long unsigned int attributes;
	long unsigned int attributes_mask;
	cpumask_t cpumask;
	struct file *backing;
	struct kref refcount;
	struct list_head va_pages;
	long unsigned int mm_list_version;
	struct list_head mm_list;
	spinlock_t mm_lock;
	struct srcu_struct srcu;
};

struct sgx_va_page {
	struct sgx_epc_page *epc_page;
	long unsigned int slots[8];
	struct list_head list;
};

struct sgx_encl_mm {
	struct sgx_encl *encl;
	struct mm_struct *mm;
	struct list_head list;
	struct mmu_notifier mmu_notifier;
};

enum {
	__PERCPU_REF_ATOMIC = 1,
	__PERCPU_REF_DEAD = 2,
	__PERCPU_REF_ATOMIC_DEAD = 3,
	__PERCPU_REF_FLAG_BITS = 2,
};

typedef unsigned int xa_mark_t;

struct xa_node {
	unsigned char shift;
	unsigned char offset;
	unsigned char count;
	unsigned char nr_values;
	struct xa_node *parent;
	struct xarray *array;
	union {
		struct list_head private_list;
		struct callback_head callback_head;
	};
	void *slots[64];
	union {
		long unsigned int tags[3];
		long unsigned int marks[3];
	};
};

typedef void (*xa_update_node_t)(struct xa_node *);

struct xa_state {
	struct xarray *xa;
	long unsigned int xa_index;
	unsigned char xa_shift;
	unsigned char xa_sibs;
	unsigned char xa_offset;
	unsigned char xa_pad;
	struct xa_node *xa_node;
	struct xa_node *xa_alloc;
	xa_update_node_t xa_update;
	struct list_lru *xa_lru;
};

enum {
	XA_CHECK_SCHED = 4096,
};

enum {
	CSS_NO_REF = 1,
	CSS_ONLINE = 2,
	CSS_RELEASED = 4,
	CSS_VISIBLE = 8,
	CSS_DYING = 16,
};

enum sgx_encls_function {
	ECREATE = 0,
	EADD = 1,
	EINIT = 2,
	EREMOVE = 3,
	EDGBRD = 4,
	EDGBWR = 5,
	EEXTEND = 6,
	ELDU = 8,
	EBLOCK = 9,
	EPA = 10,
	EWB = 11,
	ETRACK = 12,
	EAUG = 13,
	EMODPR = 14,
	EMODT = 15,
};

struct sgx_pageinfo {
	u64 addr;
	u64 contents;
	u64 metadata;
	u64 secs;
};

struct sgx_numa_node {
	struct list_head free_page_list;
	struct list_head sgx_poison_page_list;
	long unsigned int size;
	spinlock_t lock;
};

struct sgx_epc_section {
	long unsigned int phys_addr;
	void *virt_addr;
	struct sgx_epc_page *pages;
	struct sgx_numa_node *node;
};

enum sgx_encl_flags {
	SGX_ENCL_IOCTL = 1,
	SGX_ENCL_DEBUG = 2,
	SGX_ENCL_CREATED = 4,
	SGX_ENCL_INITIALIZED = 8,
};

struct sgx_backing {
	long unsigned int page_index;
	struct page *contents;
	struct page *pcmd;
	long unsigned int pcmd_offset;
};

enum sgx_return_code {
	SGX_NOT_TRACKED = 11,
	SGX_CHILD_PRESENT = 13,
	SGX_INVALID_EINITTOKEN = 16,
	SGX_UNMASKED_EVENT = 128,
};

enum sgx_attribute {
	SGX_ATTR_INIT = 1,
	SGX_ATTR_DEBUG = 2,
	SGX_ATTR_MODE64BIT = 4,
	SGX_ATTR_PROVISIONKEY = 16,
	SGX_ATTR_EINITTOKENKEY = 32,
	SGX_ATTR_KSS = 128,
};

struct sgx_secs {
	u64 size;
	u64 base;
	u32 ssa_frame_size;
	u32 miscselect;
	u8 reserved1[24];
	u64 attributes;
	u64 xfrm;
	u32 mrenclave[8];
	u8 reserved2[32];
	u32 mrsigner[8];
	u8 reserved3[32];
	u32 config_id[16];
	u16 isv_prod_id;
	u16 isv_svn;
	u16 config_svn;
	u8 reserved4[3834];
};

enum sgx_secinfo_flags {
	SGX_SECINFO_R = 1,
	SGX_SECINFO_W = 2,
	SGX_SECINFO_X = 4,
	SGX_SECINFO_SECS = 0,
	SGX_SECINFO_TCS = 256,
	SGX_SECINFO_REG = 512,
	SGX_SECINFO_VA = 768,
	SGX_SECINFO_TRIM = 1024,
};

struct sgx_secinfo {
	u64 flags;
	u8 reserved[56];
};

struct sgx_sigstruct_header {
	u64 header1[2];
	u32 vendor;
	u32 date;
	u64 header2[2];
	u32 swdefined;
	u8 reserved1[84];
};

struct sgx_sigstruct_body {
	u32 miscselect;
	u32 misc_mask;
	u8 reserved2[20];
	u64 attributes;
	u64 xfrm;
	u64 attributes_mask;
	u64 xfrm_mask;
	u8 mrenclave[32];
	u8 reserved3[32];
	u16 isvprodid;
	u16 isvsvn;
} __attribute__((packed));

struct sgx_sigstruct {
	struct sgx_sigstruct_header header;
	u8 modulus[384];
	u32 exponent;
	u8 signature[384];
	struct sgx_sigstruct_body body;
	u8 reserved4[12];
	u8 q1[384];
	u8 q2[384];
} __attribute__((packed));

struct crypto_alg;

struct crypto_tfm {
	u32 crt_flags;
	int node;
	void (*exit)(struct crypto_tfm *);
	struct crypto_alg *__crt_alg;
	void *__crt_ctx[0];
};

struct cipher_alg {
	unsigned int cia_min_keysize;
	unsigned int cia_max_keysize;
	int (*cia_setkey)(struct crypto_tfm *, const u8 *, unsigned int);
	void (*cia_encrypt)(struct crypto_tfm *, u8 *, const u8 *);
	void (*cia_decrypt)(struct crypto_tfm *, u8 *, const u8 *);
};

struct compress_alg {
	int (*coa_compress)(struct crypto_tfm *, const u8 *, unsigned int, u8 *, unsigned int *);
	int (*coa_decompress)(struct crypto_tfm *, const u8 *, unsigned int, u8 *, unsigned int *);
};

struct crypto_istat_aead {
	atomic64_t encrypt_cnt;
	atomic64_t encrypt_tlen;
	atomic64_t decrypt_cnt;
	atomic64_t decrypt_tlen;
	atomic64_t err_cnt;
};

struct crypto_istat_akcipher {
	atomic64_t encrypt_cnt;
	atomic64_t encrypt_tlen;
	atomic64_t decrypt_cnt;
	atomic64_t decrypt_tlen;
	atomic64_t verify_cnt;
	atomic64_t sign_cnt;
	atomic64_t err_cnt;
};

struct crypto_istat_cipher {
	atomic64_t encrypt_cnt;
	atomic64_t encrypt_tlen;
	atomic64_t decrypt_cnt;
	atomic64_t decrypt_tlen;
	atomic64_t err_cnt;
};

struct crypto_istat_compress {
	atomic64_t compress_cnt;
	atomic64_t compress_tlen;
	atomic64_t decompress_cnt;
	atomic64_t decompress_tlen;
	atomic64_t err_cnt;
};

struct crypto_istat_hash {
	atomic64_t hash_cnt;
	atomic64_t hash_tlen;
	atomic64_t err_cnt;
};

struct crypto_istat_kpp {
	atomic64_t setsecret_cnt;
	atomic64_t generate_public_key_cnt;
	atomic64_t compute_shared_secret_cnt;
	atomic64_t err_cnt;
};

struct crypto_istat_rng {
	atomic64_t generate_cnt;
	atomic64_t generate_tlen;
	atomic64_t seed_cnt;
	atomic64_t err_cnt;
};

struct crypto_type;

struct crypto_alg {
	struct list_head cra_list;
	struct list_head cra_users;
	u32 cra_flags;
	unsigned int cra_blocksize;
	unsigned int cra_ctxsize;
	unsigned int cra_alignmask;
	int cra_priority;
	refcount_t cra_refcnt;
	char cra_name[128];
	char cra_driver_name[128];
	const struct crypto_type *cra_type;
	union {
		struct cipher_alg cipher;
		struct compress_alg compress;
	} cra_u;
	int (*cra_init)(struct crypto_tfm *);
	void (*cra_exit)(struct crypto_tfm *);
	void (*cra_destroy)(struct crypto_alg *);
	struct module *cra_module;
	union {
		struct crypto_istat_aead aead;
		struct crypto_istat_akcipher akcipher;
		struct crypto_istat_cipher cipher;
		struct crypto_istat_compress compress;
		struct crypto_istat_hash hash;
		struct crypto_istat_rng rng;
		struct crypto_istat_kpp kpp;
	} stats;
};

struct crypto_instance;

struct crypto_type {
	unsigned int (*ctxsize)(struct crypto_alg *, u32, u32);
	unsigned int (*extsize)(struct crypto_alg *);
	int (*init)(struct crypto_tfm *, u32, u32);
	int (*init_tfm)(struct crypto_tfm *);
	void (*show)(struct seq_file *, struct crypto_alg *);
	int (*report)(struct sk_buff *, struct crypto_alg *);
	void (*free)(struct crypto_instance *);
	unsigned int type;
	unsigned int maskclear;
	unsigned int maskset;
	unsigned int tfmsize;
};

struct crypto_shash;

struct shash_desc {
	struct crypto_shash *tfm;
	void *__ctx[0];
};

struct crypto_shash {
	unsigned int descsize;
	struct crypto_tfm base;
};

enum sgx_page_flags {
	SGX_PAGE_MEASURE = 1,
};

struct sgx_enclave_create {
	__u64 src;
};

struct sgx_enclave_add_pages {
	__u64 src;
	__u64 offset;
	__u64 length;
	__u64 secinfo;
	__u64 flags;
	__u64 count;
};

struct sgx_enclave_init {
	__u64 sigstruct;
};

struct sgx_enclave_provision {
	__u64 fd;
};

struct node {
	struct device dev;
	struct list_head access_list;
	struct work_struct node_work;
	struct list_head cache_attrs;
	struct device *cache_dev;
};

struct sgx_vepc {
	struct xarray page_array;
	struct mutex lock;
};

struct vmware_steal_time {
	union {
		uint64_t clock;
		struct {
			uint32_t clock_low;
			uint32_t clock_high;
		};
	};
	uint64_t reserved[7];
};

struct mpc_intsrc {
	unsigned char type;
	unsigned char irqtype;
	short unsigned int irqflag;
	unsigned char srcbus;
	unsigned char srcbusirq;
	unsigned char dstapic;
	unsigned char dstirq;
};

enum mp_irq_source_types {
	mp_INT = 0,
	mp_NMI = 1,
	mp_SMI = 2,
	mp_ExtINT = 3,
};

enum mp_bustype {
	MP_BUS_ISA = 1,
	MP_BUS_EISA = 2,
	MP_BUS_PCI = 3,
};

typedef u64 acpi_physical_address;

typedef u32 acpi_status;

typedef void *acpi_handle;

typedef u8 acpi_adr_space_type;

struct acpi_subtable_header {
	u8 type;
	u8 length;
};

struct acpi_table_boot {
	struct acpi_table_header header;
	u8 cmos_index;
	u8 reserved[3];
};

struct acpi_cedt_header {
	u8 type;
	u8 reserved;
	u16 length;
};

struct acpi_hmat_structure {
	u16 type;
	u16 reserved;
	u32 length;
};

struct acpi_table_hpet {
	struct acpi_table_header header;
	u32 id;
	struct acpi_generic_address address;
	u8 sequence;
	u16 minimum_tick;
	u8 flags;
} __attribute__((packed));

struct acpi_table_madt {
	struct acpi_table_header header;
	u32 address;
	u32 flags;
};

enum acpi_madt_type {
	ACPI_MADT_TYPE_LOCAL_APIC = 0,
	ACPI_MADT_TYPE_IO_APIC = 1,
	ACPI_MADT_TYPE_INTERRUPT_OVERRIDE = 2,
	ACPI_MADT_TYPE_NMI_SOURCE = 3,
	ACPI_MADT_TYPE_LOCAL_APIC_NMI = 4,
	ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE = 5,
	ACPI_MADT_TYPE_IO_SAPIC = 6,
	ACPI_MADT_TYPE_LOCAL_SAPIC = 7,
	ACPI_MADT_TYPE_INTERRUPT_SOURCE = 8,
	ACPI_MADT_TYPE_LOCAL_X2APIC = 9,
	ACPI_MADT_TYPE_LOCAL_X2APIC_NMI = 10,
	ACPI_MADT_TYPE_GENERIC_INTERRUPT = 11,
	ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR = 12,
	ACPI_MADT_TYPE_GENERIC_MSI_FRAME = 13,
	ACPI_MADT_TYPE_GENERIC_REDISTRIBUTOR = 14,
	ACPI_MADT_TYPE_GENERIC_TRANSLATOR = 15,
	ACPI_MADT_TYPE_MULTIPROC_WAKEUP = 16,
	ACPI_MADT_TYPE_RESERVED = 17,
	ACPI_MADT_TYPE_OEM_RESERVED = 128,
};

struct acpi_madt_local_apic {
	struct acpi_subtable_header header;
	u8 processor_id;
	u8 id;
	u32 lapic_flags;
};

struct acpi_madt_io_apic {
	struct acpi_subtable_header header;
	u8 id;
	u8 reserved;
	u32 address;
	u32 global_irq_base;
};

struct acpi_madt_interrupt_override {
	struct acpi_subtable_header header;
	u8 bus;
	u8 source_irq;
	u32 global_irq;
	u16 inti_flags;
} __attribute__((packed));

struct acpi_madt_nmi_source {
	struct acpi_subtable_header header;
	u16 inti_flags;
	u32 global_irq;
};

struct acpi_madt_local_apic_nmi {
	struct acpi_subtable_header header;
	u8 processor_id;
	u16 inti_flags;
	u8 lint;
} __attribute__((packed));

struct acpi_madt_local_apic_override {
	struct acpi_subtable_header header;
	u16 reserved;
	u64 address;
} __attribute__((packed));

struct acpi_madt_local_sapic {
	struct acpi_subtable_header header;
	u8 processor_id;
	u8 id;
	u8 eid;
	u8 reserved[3];
	u32 lapic_flags;
	u32 uid;
	char uid_string[1];
} __attribute__((packed));

struct acpi_madt_local_x2apic {
	struct acpi_subtable_header header;
	u16 reserved;
	u32 local_apic_id;
	u32 lapic_flags;
	u32 uid;
};

struct acpi_madt_local_x2apic_nmi {
	struct acpi_subtable_header header;
	u16 inti_flags;
	u32 uid;
	u8 lint;
	u8 reserved[3];
};

struct acpi_madt_multiproc_wakeup {
	struct acpi_subtable_header header;
	u16 mailbox_version;
	u32 reserved;
	u64 base_address;
};

struct acpi_madt_multiproc_wakeup_mailbox {
	u16 command;
	u16 reserved;
	u32 apic_id;
	u64 wakeup_vector;
	u8 reserved_os[2032];
	u8 reserved_firmware[2048];
};

struct acpi_prmt_module_header {
	u16 revision;
	u16 length;
};

union acpi_subtable_headers {
	struct acpi_subtable_header common;
	struct acpi_hmat_structure hmat;
	struct acpi_prmt_module_header prmt;
	struct acpi_cedt_header cedt;
};

typedef int (*acpi_tbl_entry_handler)(union acpi_subtable_headers *, const long unsigned int);

typedef int (*acpi_tbl_entry_handler_arg)(union acpi_subtable_headers *, void *, const long unsigned int);

struct acpi_subtable_proc {
	int id;
	acpi_tbl_entry_handler handler;
	acpi_tbl_entry_handler_arg handler_arg;
	void *arg;
	int count;
};

typedef u32 phys_cpuid_t;

struct serial_icounter_struct {
	int cts;
	int dsr;
	int rng;
	int dcd;
	int rx;
	int tx;
	int frame;
	int overrun;
	int parity;
	int brk;
	int buf_overrun;
	int reserved[9];
};

struct serial_struct {
	int type;
	int line;
	unsigned int port;
	int irq;
	int flags;
	int xmit_fifo_size;
	int custom_divisor;
	int baud_base;
	short unsigned int close_delay;
	char io_type;
	char reserved_char[1];
	int hub6;
	short unsigned int closing_wait;
	short unsigned int closing_wait2;
	unsigned char *iomem_base;
	short unsigned int iomem_reg_shift;
	unsigned int port_high;
	long unsigned int iomap_base;
};

enum ioapic_domain_type {
	IOAPIC_DOMAIN_INVALID = 0,
	IOAPIC_DOMAIN_LEGACY = 1,
	IOAPIC_DOMAIN_STRICT = 2,
	IOAPIC_DOMAIN_DYNAMIC = 3,
};

struct ioapic_domain_cfg {
	enum ioapic_domain_type type;
	const struct irq_domain_ops *ops;
	struct device_node *dev;
};

struct wakeup_header {
	u16 video_mode;
	u32 pmode_entry;
	u16 pmode_cs;
	u32 pmode_cr0;
	u32 pmode_cr3;
	u32 pmode_cr4;
	u32 pmode_efer_low;
	u32 pmode_efer_high;
	u64 pmode_gdt;
	u32 pmode_misc_en_low;
	u32 pmode_misc_en_high;
	u32 pmode_behavior;
	u32 realmode_flags;
	u32 real_magic;
	u32 signature;
} __attribute__((packed));

struct acpi_hest_header {
	u16 type;
	u16 source_id;
};

struct acpi_hest_ia_error_bank {
	u8 bank_number;
	u8 clear_status_on_init;
	u8 status_format;
	u8 reserved;
	u32 control_register;
	u64 control_data;
	u32 status_register;
	u32 address_register;
	u32 misc_register;
} __attribute__((packed));

struct acpi_hest_notify {
	u8 type;
	u8 length;
	u16 config_write_enable;
	u32 poll_interval;
	u32 vector;
	u32 polling_threshold_value;
	u32 polling_threshold_window;
	u32 error_threshold_value;
	u32 error_threshold_window;
};

struct acpi_hest_ia_corrected {
	struct acpi_hest_header header;
	u16 reserved1;
	u8 flags;
	u8 enabled;
	u32 records_to_preallocate;
	u32 max_sections_per_record;
	struct acpi_hest_notify notify;
	u8 num_hardware_banks;
	u8 reserved2[3];
};

struct cpc_reg {
	u8 descriptor;
	u16 length;
	u8 space_id;
	u8 bit_width;
	u8 bit_offset;
	u8 access_width;
	u64 address;
} __attribute__((packed));

struct cppc_perf_caps {
	u32 guaranteed_perf;
	u32 highest_perf;
	u32 nominal_perf;
	u32 lowest_perf;
	u32 lowest_nonlinear_perf;
	u32 lowest_freq;
	u32 nominal_freq;
};

struct acpi_power_register {
	u8 descriptor;
	u16 length;
	u8 space_id;
	u8 bit_width;
	u8 bit_offset;
	u8 access_size;
	u64 address;
} __attribute__((packed));

struct acpi_processor_cx {
	u8 valid;
	u8 type;
	u32 address;
	u8 entry_method;
	u8 index;
	u32 latency;
	u8 bm_sts_skip;
	char desc[32];
};

struct acpi_processor_flags {
	u8 power: 1;
	u8 performance: 1;
	u8 throttling: 1;
	u8 limit: 1;
	u8 bm_control: 1;
	u8 bm_check: 1;
	u8 has_cst: 1;
	u8 has_lpi: 1;
	u8 power_setup_done: 1;
	u8 bm_rld_set: 1;
	u8 need_hotplug_init: 1;
};

struct cstate_entry {
	struct {
		unsigned int eax;
		unsigned int ecx;
	} states[8];
};

enum reboot_mode {
	REBOOT_UNDEFINED = 4294967295,
	REBOOT_COLD = 0,
	REBOOT_WARM = 1,
	REBOOT_HARD = 2,
	REBOOT_SOFT = 3,
	REBOOT_GPIO = 4,
};

enum reboot_type {
	BOOT_TRIPLE = 116,
	BOOT_KBD = 107,
	BOOT_BIOS = 98,
	BOOT_ACPI = 97,
	BOOT_EFI = 101,
	BOOT_CF9_FORCE = 112,
	BOOT_CF9_SAFE = 113,
};

typedef void (*nmi_shootdown_cb)(int, struct pt_regs *);

struct intel_early_ops {
	resource_size_t (*stolen_size)(int, int, int);
	resource_size_t (*stolen_base)(int, int, int, resource_size_t);
};

struct chipset {
	u32 vendor;
	u32 device;
	u32 class;
	u32 class_mask;
	u32 flags;
	void (*f)(int, int, int);
};

enum {
	SD_BALANCE_NEWIDLE = 1,
	SD_BALANCE_EXEC = 2,
	SD_BALANCE_FORK = 4,
	SD_BALANCE_WAKE = 8,
	SD_WAKE_AFFINE = 16,
	SD_ASYM_CPUCAPACITY = 32,
	SD_ASYM_CPUCAPACITY_FULL = 64,
	SD_SHARE_CPUCAPACITY = 128,
	SD_SHARE_PKG_RESOURCES = 256,
	SD_SERIALIZE = 512,
	SD_ASYM_PACKING = 1024,
	SD_PREFER_SIBLING = 2048,
	SD_OVERLAP = 4096,
	SD_NUMA = 8192,
};

struct sched_domain_shared {
	atomic_t ref;
	atomic_t nr_busy_cpus;
	int has_idle_cores;
};
