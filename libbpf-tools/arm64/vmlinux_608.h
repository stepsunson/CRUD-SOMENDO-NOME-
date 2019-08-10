
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef signed char __s8;

typedef unsigned char __u8;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

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

typedef __u16 __le16;

typedef __u32 __le32;

typedef unsigned int __poll_t;

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

typedef short unsigned int umode_t;

typedef __kernel_pid_t pid_t;

typedef __kernel_clockid_t clockid_t;

typedef _Bool bool;

typedef __kernel_uid32_t uid_t;

typedef __kernel_gid32_t gid_t;

typedef long unsigned int uintptr_t;

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

struct lock_class_key {};

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

struct kernel_symbol {
	int value_offset;
	int name_offset;
	int namespace_offset;
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

struct static_key_false {
	struct static_key key;
};

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

struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
	int early;
};

typedef atomic64_t atomic_long_t;

struct pi_entry {
	const char *fmt;
	const char *func;
	const char *file;
	unsigned int line;
	const char *level;
	const char *subsys_fmt_prefix;
} __attribute__((packed));

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

struct bug_entry {
	int bug_addr_disp;
	int file_disp;
	short unsigned int line;
	short unsigned int flags;
};

struct static_call_key {
	void *func;
};

struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};

struct user_fpsimd_state {
	__int128 unsigned vregs[32];
	__u32 fpsr;
	__u32 fpcr;
	__u32 __reserved[2];
};

struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			u64 regs[31];
			u64 sp;
			u64 pc;
			u64 pstate;
		};
	};
	u64 orig_x0;
	s32 syscallno;
	u32 unused2;
	u64 sdei_ttbr1;
	u64 pmr_save;
	u64 stackframe[2];
	u64 lockdep_hardirqs;
	u64 exit_rcu;
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
	u64 ttbr0;
	union {
		u64 preempt_count;
		struct {
			u32 count;
			u32 need_resched;
		} preempt;
	};
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
	long unsigned int bits[64];
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

struct syscall_user_dispatch {};

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
	long unsigned int bits[8];
} nodemask_t;

struct seqcount_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_spinlock seqcount_spinlock_t;

struct optimistic_spin_queue {
	atomic_t tail;
};

struct mutex {
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct optimistic_spin_queue osq;
	struct list_head wait_list;
};

struct tlbflush_unmap_batch {};

struct page_frag {
	struct page *page;
	__u32 offset;
	__u32 size;
};

struct latency_record {
	long unsigned int backtrace[12];
	unsigned int count;
	long unsigned int time;
	long unsigned int max;
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

struct cpu_context {
	long unsigned int x19;
	long unsigned int x20;
	long unsigned int x21;
	long unsigned int x22;
	long unsigned int x23;
	long unsigned int x24;
	long unsigned int x25;
	long unsigned int x26;
	long unsigned int x27;
	long unsigned int x28;
	long unsigned int fp;
	long unsigned int sp;
	long unsigned int pc;
};

struct perf_event;

struct debug_info {
	int suspended_step;
	int bps_disabled;
	int wps_disabled;
	struct perf_event *hbp_break[16];
	struct perf_event *hbp_watch[16];
};

struct ptrauth_key {
	long unsigned int lo;
	long unsigned int hi;
};

struct ptrauth_keys_user {
	struct ptrauth_key apia;
	struct ptrauth_key apib;
	struct ptrauth_key apda;
	struct ptrauth_key apdb;
	struct ptrauth_key apga;
};

struct ptrauth_keys_kernel {
	struct ptrauth_key apia;
};

struct thread_struct {
	struct cpu_context cpu_context;
	long: 64;
	struct {
		long unsigned int tp_value;
		long unsigned int tp2_value;
		struct user_fpsimd_state fpsimd_state;
	} uw;
	unsigned int fpsimd_cpu;
	void *sve_state;
	void *za_state;
	unsigned int vl[2];
	unsigned int vl_onexec[2];
	long unsigned int fault_address;
	long unsigned int fault_code;
	struct debug_info debug;
	struct ptrauth_keys_user keys_user;
	struct ptrauth_keys_kernel keys_kernel;
	u64 mte_ctrl;
	u64 sctlr_user;
	u64 svcr;
	u64 tpidr2_el0;
	long: 64;
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

struct kunit;

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
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	struct rb_node core_node;
	long unsigned int core_cookie;
	unsigned int core_occupation;
	struct task_group *sched_task_group;
	long: 64;
	long: 64;
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
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
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
	unsigned int in_user_fault: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_page_owner: 1;
	unsigned int in_eventfd: 1;
	unsigned int pasid_activated: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
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
	struct vtime vtime;
	atomic_t tick_dep_mask;
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
	int latency_record_count;
	struct latency_record latency_record[32];
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	struct kunit *kunit_test;
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
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	struct llist_head kretprobe_instances;
	struct thread_struct thread;
};

typedef u64 pteval_t;

typedef u64 pmdval_t;

typedef u64 pudval_t;

typedef u64 pgdval_t;

typedef struct {
	pteval_t pte;
} pte_t;

typedef struct {
	pmdval_t pmd;
} pmd_t;

typedef struct {
	pudval_t pud;
} pud_t;

typedef struct {
	pgdval_t pgd;
} pgd_t;

typedef struct {
	pteval_t pgprot;
} pgprot_t;

enum pcpu_fc {
	PCPU_FC_AUTO = 0,
	PCPU_FC_EMBED = 1,
	PCPU_FC_PAGE = 2,
	PCPU_FC_NR = 3,
};

enum vec_type {
	ARM64_VEC_SVE = 0,
	ARM64_VEC_SME = 1,
	ARM64_VEC_MAX = 2,
};

typedef struct {
	arch_rwlock_t raw_lock;
} rwlock_t;

struct wait_queue_head {
	spinlock_t lock;
	struct list_head head;
};

typedef struct wait_queue_head wait_queue_head_t;

enum pid_type {
	PIDTYPE_PID = 0,
	PIDTYPE_TGID = 1,
	PIDTYPE_PGID = 2,
	PIDTYPE_SID = 3,
	PIDTYPE_MAX = 4,
};

struct pid_namespace;

struct upid {
	int nr;
	struct pid_namespace *ns;
};

struct xarray {
	spinlock_t xa_lock;
	gfp_t xa_flags;
	void *xa_head;
};

struct idr {
	struct xarray idr_rt;
	unsigned int idr_base;
	unsigned int idr_next;
};

struct proc_ns_operations;

struct ns_common {
	atomic_long_t stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;
	refcount_t count;
};

struct kmem_cache;

struct fs_pin;

struct user_namespace;

struct ucounts;

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

struct work_struct;

typedef void (*work_func_t)(struct work_struct *);

struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
};

struct workqueue_struct;

struct delayed_work {
	struct work_struct work;
	struct timer_list timer;
	struct workqueue_struct *wq;
	int cpu;
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
				struct list_head buddy_list;
				struct list_head pcp_list;
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

struct seqcount_raw_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_raw_spinlock seqcount_raw_spinlock_t;

typedef struct {
	seqcount_spinlock_t seqcount;
	spinlock_t lock;
} seqlock_t;

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

struct rlimit {
	__kernel_ulong_t rlim_cur;
	__kernel_ulong_t rlim_max;
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

enum {
	MM_FILEPAGES = 0,
	MM_ANONPAGES = 1,
	MM_SWAPENTS = 2,
	MM_SHMEMPAGES = 3,
	NR_MM_COUNTERS = 4,
};

struct mm_rss_stat {
	atomic_long_t count[4];
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

struct rw_semaphore {
	atomic_long_t count;
	atomic_long_t owner;
	struct optimistic_spin_queue osq;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
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
	atomic_t tick_dep_mask;
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

enum perf_event_task_context {
	perf_invalid_context = 4294967295,
	perf_hw_context = 0,
	perf_sw_context = 1,
	perf_nr_task_contexts = 2,
};

struct rq;

struct rq_flags;

struct sched_class {
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

typedef struct {
	atomic64_t id;
	void *sigpage;
	refcount_t pinned;
	void *vdso;
	long unsigned int flags;
} mm_context_t;

struct xol_area;

struct uprobes_state {
	struct xol_area *xol_area;
};

struct linux_binfmt;

struct kioctx_table;

struct mmu_notifier_subscriptions;

struct mm_struct {
	struct {
		struct vm_area_struct *mmap;
		struct rb_root mm_rb;
		u64 vmacache_seqnum;
		long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
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
		long unsigned int saved_auxv[46];
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
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		u32 pasid;
		long unsigned int ksm_merging_pages;
	};
	long unsigned int cpu_bitmap[0];
};

struct swait_queue_head {
	raw_spinlock_t lock;
	struct list_head task_list;
};

struct completion {
	unsigned int done;
	struct swait_queue_head wait;
};

struct kernel_cap_struct {
	__u32 cap[2];
};

typedef struct kernel_cap_struct kernel_cap_t;

struct user_struct;

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

struct ftrace_ret_stack {
	long unsigned int ret;
	long unsigned int func;
	long long unsigned int calltime;
	long long unsigned int subtime;
	long unsigned int fp;
	long unsigned int *retp;
};

enum uprobe_task_state {
	UTASK_RUNNING = 0,
	UTASK_SSTEP = 1,
	UTASK_SSTEP_ACK = 2,
	UTASK_SSTEP_TRAPPED = 3,
};

struct arch_uprobe_task {};

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

struct vm_struct {
	struct vm_struct *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page **pages;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

enum rseq_event_mask_bits {
	RSEQ_EVENT_PREEMPT_BIT = 0,
	RSEQ_EVENT_SIGNAL_BIT = 1,
	RSEQ_EVENT_MIGRATE_BIT = 2,
};

struct kref {
	refcount_t refcount;
};

struct step_hook {
	struct list_head node;
	int (*fn)(struct pt_regs *, long unsigned int);
};

struct break_hook {
	struct list_head node;
	int (*fn)(struct pt_regs *, long unsigned int);
	u16 imm;
	u16 mask;
};

enum dbg_active_el {
	DBG_ACTIVE_EL0 = 0,
	DBG_ACTIVE_EL1 = 1,
};

struct return_instance {
	struct uprobe *uprobe;
	long unsigned int func;
	long unsigned int stack;
	long unsigned int orig_ret_vaddr;
	bool chained;
	struct return_instance *next;
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
	MEMORY_DEVICE_COHERENT = 2,
	MEMORY_DEVICE_FS_DAX = 3,
	MEMORY_DEVICE_GENERIC = 4,
	MEMORY_DEVICE_PCI_P2PDMA = 5,
};

struct range {
	u64 start;
	u64 end;
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
		struct llist_node f_llist;
		struct callback_head f_rcuhead;
		unsigned int f_iocb_flags;
	};
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
	MIGRATE_CMA = 4,
	MIGRATE_ISOLATE = 5,
	MIGRATE_TYPES = 6,
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

struct rcu_segcblist {
	struct callback_head *head;
	struct callback_head **tails[4];
	long unsigned int gp_seq[4];
	atomic_long_t len;
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

struct list_lru_node;

struct list_lru {
	struct list_lru_node *node;
	struct list_head list;
	int shrinker_id;
	bool memcg_aware;
	struct xarray xa;
};

struct kernfs_root;

struct kernfs_elem_dir {
	long unsigned int subdirs;
	struct rb_root children;
	struct kernfs_root *root;
	long unsigned int rev;
};

struct kernfs_node;

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

struct seq_operations;

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

struct attribute {
	const char *name;
	umode_t mode;
};

struct kobject;

struct bin_attribute;

struct attribute_group {
	const char *name;
	umode_t (*is_visible)(struct kobject *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject *, struct bin_attribute *, int);
	struct attribute **attrs;
	struct bin_attribute **bin_attrs;
};

struct kset;

struct kobj_type;

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

enum module_state {
	MODULE_STATE_LIVE = 0,
	MODULE_STATE_COMING = 1,
	MODULE_STATE_GOING = 2,
	MODULE_STATE_UNFORMED = 3,
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

struct mod_plt_sec {
	int plt_shndx;
	int plt_num_entries;
	int plt_max_entries;
};

struct plt_entry;

struct mod_arch_specific {
	struct mod_plt_sec core;
	struct mod_plt_sec init;
	struct plt_entry *ftrace_trampolines;
};

struct elf64_sym;

typedef struct elf64_sym Elf64_Sym;

struct mod_kallsyms {
	Elf64_Sym *symtab;
	unsigned int num_symtab;
	char *strtab;
	char *typetab;
};

typedef const int tracepoint_ptr_t;

struct module_attribute;

struct kernel_param;

struct exception_table_entry;

struct module_sect_attrs;

struct module_notes_attrs;

struct bpf_raw_event_map;

struct trace_event_call;

struct trace_eval_map;

struct kunit_suite;

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
	int num_kunit_suites;
	struct kunit_suite **kunit_suites;
	unsigned int printk_index_size;
	struct pi_entry **printk_index_start;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
	struct error_injection_entry *ei_funcs;
	unsigned int num_ei_funcs;
	long: 32;
	long: 64;
};

typedef __u64 Elf64_Addr;

typedef __u16 Elf64_Half;

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

struct shrink_control;

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

struct super_operations;

struct dquot_operations;

struct quotactl_ops;

struct export_operations;

struct xattr_handler;

struct fscrypt_operations;

struct fscrypt_keyring;

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
	struct fscrypt_keyring *s_master_keys;
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

struct shrink_control {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup *memcg;
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
	short int type;
	short int data;
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

typedef struct {
	uid_t val;
} vfsuid_t;

typedef struct {
	gid_t val;
} vfsgid_t;

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
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
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
	int (*migrate_folio)(struct address_space *, struct folio *, struct folio *, enum migrate_mode);
	int (*launder_folio)(struct folio *);
	bool (*is_partially_uptodate)(struct folio *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio *, bool *, bool *);
	int (*error_remove_page)(struct address_space *, struct page *);
	int (*swap_activate)(struct swap_info_struct *, struct file *, sector_t *);
	void (*swap_deactivate)(struct file *);
	int (*swap_rw)(struct kiocb *, struct iov_iter *);
};

struct iovec;

struct kvec;

struct bio_vec;

struct iov_iter {
	u8 iter_type;
	bool nofault;
	bool data_source;
	bool user_backed;
	union {
		size_t iov_offset;
		int last_offset;
	};
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec *bvec;
		struct xarray *xarray;
		struct pipe_inode_info *pipe;
		void *ubuf;
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

struct fid;

struct iomap;

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

struct bpf_raw_event_map {
	struct tracepoint *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long: 64;
};

struct plt_entry {
	__le32 adrp;
	__le32 add;
	__le32 br;
};

struct module_attribute {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute *, struct module_kobject *, char *);
	ssize_t (*store)(struct module_attribute *, struct module_kobject *, const char *, size_t);
	void (*setup)(struct module *, const char *);
	int (*test)(struct module *);
	void (*free)(struct module *);
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
	CPUHP_BP_PREPARE_DYN = 71,
	CPUHP_BP_PREPARE_DYN_END = 91,
	CPUHP_BRINGUP_CPU = 92,
	CPUHP_AP_IDLE_DEAD = 93,
	CPUHP_AP_OFFLINE = 94,
	CPUHP_AP_SCHED_STARTING = 95,
	CPUHP_AP_RCUTREE_DYING = 96,
	CPUHP_AP_CPU_PM_STARTING = 97,
	CPUHP_AP_IRQ_GIC_STARTING = 98,
	CPUHP_AP_IRQ_HIP04_STARTING = 99,
	CPUHP_AP_IRQ_APPLE_AIC_STARTING = 100,
	CPUHP_AP_IRQ_ARMADA_XP_STARTING = 101,
	CPUHP_AP_IRQ_BCM2836_STARTING = 102,
	CPUHP_AP_IRQ_MIPS_GIC_STARTING = 103,
	CPUHP_AP_IRQ_RISCV_STARTING = 104,
	CPUHP_AP_IRQ_LOONGARCH_STARTING = 105,
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
	CPUHP_AP_PERF_ARM_HNS3_PMU_ONLINE = 182,
	CPUHP_AP_PERF_ARM_L2X0_ONLINE = 183,
	CPUHP_AP_PERF_ARM_QCOM_L2_ONLINE = 184,
	CPUHP_AP_PERF_ARM_QCOM_L3_ONLINE = 185,
	CPUHP_AP_PERF_ARM_APM_XGENE_ONLINE = 186,
	CPUHP_AP_PERF_ARM_CAVIUM_TX2_UNCORE_ONLINE = 187,
	CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE = 188,
	CPUHP_AP_PERF_POWERPC_NEST_IMC_ONLINE = 189,
	CPUHP_AP_PERF_POWERPC_CORE_IMC_ONLINE = 190,
	CPUHP_AP_PERF_POWERPC_THREAD_IMC_ONLINE = 191,
	CPUHP_AP_PERF_POWERPC_TRACE_IMC_ONLINE = 192,
	CPUHP_AP_PERF_POWERPC_HV_24x7_ONLINE = 193,
	CPUHP_AP_PERF_POWERPC_HV_GPCI_ONLINE = 194,
	CPUHP_AP_PERF_CSKY_ONLINE = 195,
	CPUHP_AP_WATCHDOG_ONLINE = 196,
	CPUHP_AP_WORKQUEUE_ONLINE = 197,
	CPUHP_AP_RANDOM_ONLINE = 198,
	CPUHP_AP_RCUTREE_ONLINE = 199,
	CPUHP_AP_BASE_CACHEINFO_ONLINE = 200,
	CPUHP_AP_ONLINE_DYN = 201,
	CPUHP_AP_ONLINE_DYN_END = 231,
	CPUHP_AP_MM_DEMOTION_ONLINE = 232,
	CPUHP_AP_X86_HPET_ONLINE = 233,
	CPUHP_AP_X86_KVM_CLK_ONLINE = 234,
	CPUHP_AP_ACTIVE = 235,
	CPUHP_ONLINE = 236,
};

struct seq_operations {
	void * (*start)(struct seq_file *, loff_t *);
	void (*stop)(struct seq_file *, void *);
	void * (*next)(struct seq_file *, void *, loff_t *);
	int (*show)(struct seq_file *, void *);
};

struct dev_pagemap_ops {
	void (*page_free)(struct page *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault *);
	int (*memory_failure)(struct dev_pagemap *, long unsigned int, long unsigned int, int);
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
	PGALLOC_DEVICE = 8,
	ALLOCSTALL_DMA = 9,
	ALLOCSTALL_DMA32 = 10,
	ALLOCSTALL_NORMAL = 11,
	ALLOCSTALL_MOVABLE = 12,
	ALLOCSTALL_DEVICE = 13,
	PGSCAN_SKIP_DMA = 14,
	PGSCAN_SKIP_DMA32 = 15,
	PGSCAN_SKIP_NORMAL = 16,
	PGSCAN_SKIP_MOVABLE = 17,
	PGSCAN_SKIP_DEVICE = 18,
	PGFREE = 19,
	PGACTIVATE = 20,
	PGDEACTIVATE = 21,
	PGLAZYFREE = 22,
	PGFAULT = 23,
	PGMAJFAULT = 24,
	PGLAZYFREED = 25,
	PGREFILL = 26,
	PGREUSE = 27,
	PGSTEAL_KSWAPD = 28,
	PGSTEAL_DIRECT = 29,
	PGDEMOTE_KSWAPD = 30,
	PGDEMOTE_DIRECT = 31,
	PGSCAN_KSWAPD = 32,
	PGSCAN_DIRECT = 33,
	PGSCAN_DIRECT_THROTTLE = 34,
	PGSCAN_ANON = 35,
	PGSCAN_FILE = 36,
	PGSTEAL_ANON = 37,
	PGSTEAL_FILE = 38,
	PGSCAN_ZONE_RECLAIM_FAILED = 39,
	PGINODESTEAL = 40,
	SLABS_SCANNED = 41,
	KSWAPD_INODESTEAL = 42,
	KSWAPD_LOW_WMARK_HIT_QUICKLY = 43,
	KSWAPD_HIGH_WMARK_HIT_QUICKLY = 44,
	PAGEOUTRUN = 45,
	PGROTATED = 46,
	DROP_PAGECACHE = 47,
	DROP_SLAB = 48,
	OOM_KILL = 49,
	NUMA_PTE_UPDATES = 50,
	NUMA_HUGE_PTE_UPDATES = 51,
	NUMA_HINT_FAULTS = 52,
	NUMA_HINT_FAULTS_LOCAL = 53,
	NUMA_PAGE_MIGRATE = 54,
	PGMIGRATE_SUCCESS = 55,
	PGMIGRATE_FAIL = 56,
	THP_MIGRATION_SUCCESS = 57,
	THP_MIGRATION_FAIL = 58,
	THP_MIGRATION_SPLIT = 59,
	COMPACTMIGRATE_SCANNED = 60,
	COMPACTFREE_SCANNED = 61,
	COMPACTISOLATED = 62,
	COMPACTSTALL = 63,
	COMPACTFAIL = 64,
	COMPACTSUCCESS = 65,
	KCOMPACTD_WAKE = 66,
	KCOMPACTD_MIGRATE_SCANNED = 67,
	KCOMPACTD_FREE_SCANNED = 68,
	HTLB_BUDDY_PGALLOC = 69,
	HTLB_BUDDY_PGALLOC_FAIL = 70,
	CMA_ALLOC_SUCCESS = 71,
	CMA_ALLOC_FAIL = 72,
	UNEVICTABLE_PGCULLED = 73,
	UNEVICTABLE_PGSCANNED = 74,
	UNEVICTABLE_PGRESCUED = 75,
	UNEVICTABLE_PGMLOCKED = 76,
	UNEVICTABLE_PGMUNLOCKED = 77,
	UNEVICTABLE_PGCLEARED = 78,
	UNEVICTABLE_PGSTRANDED = 79,
	THP_FAULT_ALLOC = 80,
	THP_FAULT_FALLBACK = 81,
	THP_FAULT_FALLBACK_CHARGE = 82,
	THP_COLLAPSE_ALLOC = 83,
	THP_COLLAPSE_ALLOC_FAILED = 84,
	THP_FILE_ALLOC = 85,
	THP_FILE_FALLBACK = 86,
	THP_FILE_FALLBACK_CHARGE = 87,
	THP_FILE_MAPPED = 88,
	THP_SPLIT_PAGE = 89,
	THP_SPLIT_PAGE_FAILED = 90,
	THP_DEFERRED_SPLIT_PAGE = 91,
	THP_SPLIT_PMD = 92,
	THP_SCAN_EXCEED_NONE_PTE = 93,
	THP_SCAN_EXCEED_SWAP_PTE = 94,
	THP_SCAN_EXCEED_SHARED_PTE = 95,
	THP_ZERO_PAGE_ALLOC = 96,
	THP_ZERO_PAGE_ALLOC_FAILED = 97,
	THP_SWPOUT = 98,
	THP_SWPOUT_FALLBACK = 99,
	BALLOON_INFLATE = 100,
	BALLOON_DEFLATE = 101,
	BALLOON_MIGRATE = 102,
	SWAP_RA = 103,
	SWAP_RA_HIT = 104,
	KSM_SWPIN_COPY = 105,
	COW_KSM = 106,
	ZSWPIN = 107,
	ZSWPOUT = 108,
	NR_VM_EVENT_ITEMS = 109,
};

struct nsset;

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

struct iovec {
	void *iov_base;
	__kernel_size_t iov_len;
};

struct kvec {
	void *iov_base;
	size_t iov_len;
};

struct bio_vec {
	struct page *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

enum {
	TSK_TRACE_FL_TRACE_BIT = 0,
	TSK_TRACE_FL_GRAPH_BIT = 1,
};

struct nmi_ctx {
	u64 hcr;
	unsigned int cnt;
};

struct midr_range {
	u32 model;
	u32 rv_min;
	u32 rv_max;
};

struct arm64_midr_revidr {
	u32 midr_rv;
	u32 revidr_mask;
};

struct arm64_cpu_capabilities {
	const char *desc;
	u16 capability;
	u16 type;
	bool (*matches)(const struct arm64_cpu_capabilities *, int);
	void (*cpu_enable)(const struct arm64_cpu_capabilities *);
	union {
		struct {
			struct midr_range midr_range;
			const struct arm64_midr_revidr * const fixed_revs;
		};
		const struct midr_range *midr_range_list;
		struct {
			u32 sys_reg;
			u8 field_pos;
			u8 field_width;
			u8 min_field_value;
			u8 hwcap_type;
			bool sign;
			long unsigned int hwcap;
		};
	};
	const struct arm64_cpu_capabilities *match_list;
};

struct vl_info {
	enum vec_type type;
	const char *name;
	int min_vl;
	int max_vl;
	int max_virtualisable_vl;
	long unsigned int vq_map[8];
	long unsigned int vq_partial_map[8];
};

struct notifier_block;

typedef int (*notifier_fn_t)(struct notifier_block *, long unsigned int, void *);

struct notifier_block {
	notifier_fn_t notifier_call;
	struct notifier_block *next;
	int priority;
};

struct ctl_table;

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

struct ctl_table_header;

struct ctl_node {
	struct rb_node node;
	struct ctl_table_header *header;
};

struct ctl_table_root;

struct ctl_table_set;

struct ctl_dir;

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

struct ctl_table_root {
	struct ctl_table_set default_set;
	struct ctl_table_set * (*lookup)(struct ctl_table_root *);
	void (*set_ownership)(struct ctl_table_header *, struct ctl_table *, kuid_t *, kgid_t *);
	int (*permissions)(struct ctl_table_header *, struct ctl_table *);
};

enum cpu_pm_event {
	CPU_PM_ENTER = 0,
	CPU_PM_ENTER_FAILED = 1,
	CPU_PM_EXIT = 2,
	CPU_CLUSTER_PM_ENTER = 3,
	CPU_CLUSTER_PM_ENTER_FAILED = 4,
	CPU_CLUSTER_PM_EXIT = 5,
};

struct fpsimd_last_state_struct {
	struct user_fpsimd_state *st;
	void *sve_state;
	void *za_state;
	u64 *svcr;
	unsigned int sve_vl;
	unsigned int sme_vl;
};

struct vl_config {
	int __default_vl;
};

struct static_key_true {
	struct static_key key;
};

enum arm64_hyp_spectre_vector {
	HYP_VECTOR_DIRECT = 0,
	HYP_VECTOR_SPECTRE_DIRECT = 1,
	HYP_VECTOR_INDIRECT = 2,
	HYP_VECTOR_SPECTRE_INDIRECT = 3,
};

typedef void (*bp_hardening_cb_t)();

struct bp_hardening_data {
	enum arm64_hyp_spectre_vector slot;
	bp_hardening_cb_t fn;
};

enum ctx_state {
	CONTEXT_DISABLED = 4294967295,
	CONTEXT_KERNEL = 0,
	CONTEXT_IDLE = 1,
	CONTEXT_USER = 2,
	CONTEXT_GUEST = 3,
	CONTEXT_MAX = 4,
};

struct context_tracking {
	bool active;
	int recursion;
	atomic_t state;
	long int dynticks_nesting;
	long int dynticks_nmi_nesting;
};

enum stack_type {
	STACK_TYPE_UNKNOWN = 0,
	STACK_TYPE_TASK = 1,
	STACK_TYPE_IRQ = 2,
	STACK_TYPE_OVERFLOW = 3,
	STACK_TYPE_SDEI_NORMAL = 4,
	STACK_TYPE_SDEI_CRITICAL = 5,
	STACK_TYPE_HYP = 6,
	__NR_STACK_TYPES = 7,
};

struct stack_info {
	long unsigned int low;
	long unsigned int high;
	enum stack_type type;
};

struct sdei_registered_event;

typedef short int __s16;

typedef __s16 s16;

typedef struct cpumask cpumask_var_t[1];

struct pollfd {
	int fd;
	short int events;
	short int revents;
};

struct arch_hw_breakpoint_ctrl {
	u32 __reserved: 19;
	u32 len: 8;
	u32 type: 2;
	u32 privilege: 2;
	u32 enabled: 1;
};

struct arch_hw_breakpoint {
	u64 address;
	u64 trigger;
	struct arch_hw_breakpoint_ctrl ctrl;
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

enum ftrace_ops_cmd {
	FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_SELF = 0,
	FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_PEER = 1,
	FTRACE_OPS_CMD_DISABLE_SHARE_IPMODIFY_PEER = 2,
};

typedef int (*ftrace_ops_func_t)(struct ftrace_ops *, enum ftrace_ops_cmd);

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
	ftrace_ops_func_t ops_func;
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
	unsigned int pending_wakeup;
	unsigned int pending_kill;
	unsigned int pending_disable;
	unsigned int pending_sigtrap;
	long unsigned int pending_addr;
	struct irq_work pending_irq;
	struct callback_head pending_task;
	unsigned int pending_work;
	atomic_t event_limit;
	struct perf_addr_filters_head addr_filters;
	struct perf_addr_filter_range *addr_filter_ranges;
	long unsigned int addr_filters_gen;
	struct perf_event *aux_event;
	void (*destroy)(struct perf_event *);
	struct callback_head callback_head;
	struct pid_namespace *ns;
	u64 id;
	atomic64_t lost_samples;
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

enum refcount_saturation_type {
	REFCOUNT_ADD_NOT_ZERO_OVF = 0,
	REFCOUNT_ADD_OVF = 1,
	REFCOUNT_ADD_UAF = 2,
	REFCOUNT_SUB_UAF = 3,
	REFCOUNT_DEC_LEAK = 4,
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

struct rcu_work {
	struct work_struct work;
	struct callback_head rcu;
	struct workqueue_struct *wq;
};

struct plist_head {
	struct list_head node_list;
};

struct task_cputime {
	u64 stime;
	u64 utime;
	long long unsigned int sum_exec_runtime;
};

struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	atomic_t count;
	atomic_long_t ucount[16];
};

struct cgroup_subsys_state;

struct cgroup;

struct css_set {
	struct cgroup_subsys_state *subsys[12];
	refcount_t refcount;
	struct css_set *dom_cset;
	struct cgroup *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[12];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup *mg_src_cgrp;
	struct cgroup *mg_dst_cgrp;
	struct css_set *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
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
	local_t nr_pending;
};

struct blocking_notifier_head {
	struct rw_semaphore rwsem;
	struct notifier_block *head;
};

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

struct cgroup_file {
	struct kernfs_node *kn;
	long unsigned int notified_at;
	struct timer_list notify_timer;
};

struct cgroup_base_stat {
	struct task_cputime cputime;
	u64 forceidle_sum;
};

struct bpf_prog_array;

struct cgroup_bpf {
	struct bpf_prog_array *effective[33];
	struct hlist_head progs[33];
	u8 flags[33];
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

struct psi_group;

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
	struct cgroup_subsys_state *subsys[12];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[12];
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
	struct psi_group *psi;
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

struct cdev {
	struct kobject kobj;
	struct module *owner;
	const struct file_operations *ops;
	struct list_head list;
	dev_t dev;
	unsigned int count;
};

typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
};

struct fwnode_operations;

struct device;

struct fwnode_handle {
	struct fwnode_handle *secondary;
	const struct fwnode_operations *ops;
	struct device *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
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

enum rpm_status {
	RPM_INVALID = 4294967295,
	RPM_ACTIVE = 0,
	RPM_RESUMING = 1,
	RPM_SUSPENDED = 2,
	RPM_SUSPENDING = 3,
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

struct irq_domain;

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

struct dma_coherent_mem;

struct cma;

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
	struct dma_coherent_mem *dma_mem;
	struct cma *cma_area;
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
	bool dma_coherent: 1;
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

typedef u32 phandle;

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
	struct kobject kobj;
	long unsigned int _flags;
	void *data;
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
	int (*of_xlate)(struct device *, struct of_phandle_args *);
	bool (*is_attach_deferred)(struct device *);
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

typedef __u32 Elf32_Addr;

typedef __u16 Elf32_Half;

typedef __u32 Elf32_Off;

typedef __u32 Elf32_Word;

struct elf32_hdr {
	unsigned char e_ident[16];
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_version;
	Elf32_Addr e_entry;
	Elf32_Off e_phoff;
	Elf32_Off e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
};

struct arch_elf_state {
	int flags;
};

struct trace_event_functions;

struct trace_event {
	struct hlist_node node;
	struct list_head list;
	int type;
	struct trace_event_functions *funcs;
};

struct trace_event_class;

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

enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

struct sg_table;

struct scatterlist;

struct dma_map_ops {
	unsigned int flags;
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
	size_t (*opt_mapping_size)();
	long unsigned int (*get_merge_boundary)(struct device *);
};

struct bus_dma_region {
	phys_addr_t cpu_start;
	dma_addr_t dma_start;
	u64 size;
	u64 offset;
};

enum reboot_mode {
	REBOOT_UNDEFINED = 4294967295,
	REBOOT_COLD = 0,
	REBOOT_WARM = 1,
	REBOOT_HARD = 2,
	REBOOT_SOFT = 3,
	REBOOT_GPIO = 4,
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

typedef efi_status_t efi_set_virtual_address_map_t(long unsigned int, long unsigned int, u32, efi_memory_desc_t *);

typedef efi_status_t efi_query_variable_info_t(u32, u64 *, u64 *, u64 *);

typedef efi_status_t efi_update_capsule_t(efi_capsule_header_t **, long unsigned int, long unsigned int);

typedef efi_status_t efi_query_capsule_caps_t(efi_capsule_header_t **, long unsigned int, u64 *, int *);

typedef union {
	struct {
		efi_table_hdr_t hdr;
		efi_get_time_t *get_time;
		efi_set_time_t *set_time;
		efi_get_wakeup_time_t *get_wakeup_time;
		efi_set_wakeup_time_t *set_wakeup_time;
		efi_set_virtual_address_map_t *set_virtual_address_map;
		void *convert_pointer;
		efi_get_variable_t *get_variable;
		efi_get_next_variable_t *get_next_variable;
		efi_set_variable_t *set_variable;
		efi_get_next_high_mono_count_t *get_next_high_mono_count;
		efi_reset_system_t *reset_system;
		efi_update_capsule_t *update_capsule;
		efi_query_capsule_caps_t *query_capsule_caps;
		efi_query_variable_info_t *query_variable_info;
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

typedef bool (*stack_trace_consume_fn)(void *, long unsigned int);

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

struct cgroup_namespace {
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct css_set *root_cset;
};

struct property {
	char *name;
	int length;
	void *value;
	struct property *next;
	long unsigned int _flags;
	struct bin_attribute attr;
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

struct ftrace_regs {
	struct pt_regs regs;
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
	long int wait_index;
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

struct wchan_info {
	long unsigned int pc;
	int count;
};

struct sigcontext {
	__u64 fault_address;
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
	long: 64;
	__u8 __reserved[4096];
};

struct _aarch64_ctx {
	__u32 magic;
	__u32 size;
};

struct fpsimd_context {
	struct _aarch64_ctx head;
	__u32 fpsr;
	__u32 fpcr;
	__int128 unsigned vregs[32];
};

struct esr_context {
	struct _aarch64_ctx head;
	__u64 esr;
};

struct extra_context {
	struct _aarch64_ctx head;
	__u64 datap;
	__u32 size;
	__u32 __reserved[3];
};

struct sve_context {
	struct _aarch64_ctx head;
	__u16 vl;
	__u16 flags;
	__u16 __reserved[2];
};

struct za_context {
	struct _aarch64_ctx head;
	__u16 vl;
	__u16 __reserved[3];
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

typedef struct siginfo siginfo_t;

struct ksignal {
	struct k_sigaction ka;
	kernel_siginfo_t info;
	int sig;
};

struct bio;

struct bio_list {
	struct bio *head;
	struct bio *tail;
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
	long unsigned int events[109];
	long int state_pending[48];
	long unsigned int events_pending[109];
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

struct deferred_split {
	spinlock_t split_queue_lock;
	struct list_head split_queue;
	long unsigned int split_queue_len;
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
	long: 64;
	long: 64;
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

struct free_area {
	struct list_head free_list[6];
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
	long unsigned int cma_pages;
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
	struct zone_padding _pad1_;
	struct free_area free_area[13];
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
	struct zoneref _zonerefs[2561];
};

enum zone_type {
	ZONE_DMA = 0,
	ZONE_DMA32 = 1,
	ZONE_NORMAL = 2,
	ZONE_MOVABLE = 3,
	ZONE_DEVICE = 4,
	__MAX_NR_ZONES = 5,
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
	spinlock_t lock;
	int count;
	int high;
	int batch;
	short int free_factor;
	short int expire;
	struct list_head lists[13];
	long: 64;
	long: 64;
	long: 64;
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

struct disk_stats;

struct gendisk;

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

typedef __u32 blk_opf_t;

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

struct blkcg_gq;

struct bio_crypt_ctx;

struct bio_integrity_payload;

struct bio_set;

struct bio {
	struct bio *bi_next;
	struct block_device *bi_bdev;
	blk_opf_t bi_opf;
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

enum {
	EI_ETYPE_NONE = 0,
	EI_ETYPE_NULL = 1,
	EI_ETYPE_ERRNO = 2,
	EI_ETYPE_ERRNO_NULL = 3,
	EI_ETYPE_TRUE = 4,
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

struct memcg_vmstats_percpu {
	long int state[48];
	long unsigned int events[109];
	long int state_prev[48];
	long unsigned int events_prev[109];
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

struct ucontext {
	long unsigned int uc_flags;
	struct ucontext *uc_link;
	stack_t uc_stack;
	sigset_t uc_sigmask;
	__u8 __unused[120];
	long: 64;
	struct sigcontext uc_mcontext;
};

struct rt_sigframe {
	struct siginfo info;
	struct ucontext uc;
};

struct frame_record {
	u64 fp;
	u64 lr;
};

struct rt_sigframe_user_layout {
	struct rt_sigframe *sigframe;
	struct frame_record *next_frame;
	long unsigned int size;
	long unsigned int limit;
	long unsigned int fpsimd_offset;
	long unsigned int esr_offset;
	long unsigned int sve_offset;
	long unsigned int za_offset;
	long unsigned int extra_offset;
	long unsigned int end_offset;
};

struct user_ctxs {
	struct fpsimd_context *fpsimd;
	struct sve_context *sve;
	struct za_context *za;
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
	VM_FAULT_COMPLETED = 16384,
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

enum vdso_abi {
	VDSO_ABI_AA64 = 0,
	VDSO_ABI_AA32 = 1,
};

enum vvar_pages {
	VVAR_DATA_PAGE_OFFSET = 0,
	VVAR_TIMENS_PAGE_OFFSET = 1,
	VVAR_NR_PAGES = 2,
};

struct vdso_abi_info {
	const char *name;
	const char *vdso_code_start;
	const char *vdso_code_end;
	long unsigned int vdso_pages;
	struct vm_special_mapping *dm;
	struct vm_special_mapping *cm;
};

enum aarch32_map {
	AA32_MAP_VECTORS = 0,
	AA32_MAP_SIGPAGE = 1,
	AA32_MAP_VVAR = 2,
	AA32_MAP_VDSO = 3,
};

enum aarch64_map {
	AA64_MAP_VVAR = 0,
	AA64_MAP_VDSO = 1,
};

struct return_address_data {
	unsigned int level;
	void *addr;
};

typedef int (*cmp_func_t)(const void *, const void *);

enum aarch64_insn_imm_type {
	AARCH64_INSN_IMM_ADR = 0,
	AARCH64_INSN_IMM_26 = 1,
	AARCH64_INSN_IMM_19 = 2,
	AARCH64_INSN_IMM_16 = 3,
	AARCH64_INSN_IMM_14 = 4,
	AARCH64_INSN_IMM_12 = 5,
	AARCH64_INSN_IMM_9 = 6,
	AARCH64_INSN_IMM_7 = 7,
	AARCH64_INSN_IMM_6 = 8,
	AARCH64_INSN_IMM_S = 9,
	AARCH64_INSN_IMM_R = 10,
	AARCH64_INSN_IMM_N = 11,
	AARCH64_INSN_IMM_MAX = 12,
};

enum aarch64_insn_register_type {
	AARCH64_INSN_REGTYPE_RT = 0,
	AARCH64_INSN_REGTYPE_RN = 1,
	AARCH64_INSN_REGTYPE_RT2 = 2,
	AARCH64_INSN_REGTYPE_RM = 3,
	AARCH64_INSN_REGTYPE_RD = 4,
	AARCH64_INSN_REGTYPE_RA = 5,
	AARCH64_INSN_REGTYPE_RS = 6,
};

enum lockdep_ok {
	LOCKDEP_STILL_OK = 0,
	LOCKDEP_NOW_UNRELIABLE = 1,
};

enum {
	CAP_HWCAP = 1,
	CAP_COMPAT_HWCAP = 2,
	CAP_COMPAT_HWCAP2 = 3,
};

enum ftr_type {
	FTR_EXACT = 0,
	FTR_LOWER_SAFE = 1,
	FTR_HIGHER_SAFE = 2,
	FTR_HIGHER_OR_ZERO_SAFE = 3,
};

struct arm64_ftr_bits {
	bool sign;
	bool visible;
	bool strict;
	enum ftr_type type;
	u8 shift;
	u8 width;
	s64 safe_val;
};

struct arm64_ftr_override {
	u64 val;
	u64 mask;
};

struct arm64_ftr_reg {
	const char *name;
	u64 strict_mask;
	u64 user_mask;
	u64 sys_val;
	u64 user_val;
	struct arm64_ftr_override *override;
	const struct arm64_ftr_bits *ftr_bits;
};

struct secondary_data {
	struct task_struct *task;
	long int status;
};

enum mitigation_state {
	SPECTRE_UNAFFECTED = 0,
	SPECTRE_MITIGATED = 1,
	SPECTRE_VULNERABLE = 2,
};

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
	PG_hwpoison = 22,
	PG_young = 23,
	PG_idle = 24,
	PG_arch_2 = 25,
	__NR_PAGEFLAGS = 26,
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
	PG_vmemmap_self_hosted = 10,
};

enum fixed_addresses {
	FIX_HOLE = 0,
	FIX_FDT_END = 1,
	FIX_FDT = 1024,
	FIX_EARLYCON_MEM_BASE = 1025,
	FIX_TEXT_POKE0 = 1026,
	FIX_APEI_GHES_IRQ = 1027,
	FIX_APEI_GHES_SEA = 1028,
	FIX_APEI_GHES_SDEI_NORMAL = 1029,
	FIX_APEI_GHES_SDEI_CRITICAL = 1030,
	FIX_ENTRY_TRAMP_TEXT4 = 1031,
	FIX_ENTRY_TRAMP_TEXT3 = 1032,
	FIX_ENTRY_TRAMP_TEXT2 = 1033,
	FIX_ENTRY_TRAMP_TEXT1 = 1034,
	__end_of_permanent_fixed_addresses = 1035,
	FIX_BTMAP_END = 1035,
	FIX_BTMAP_BEGIN = 1482,
	FIX_PTE = 1483,
	FIX_PMD = 1484,
	FIX_PUD = 1485,
	FIX_PGD = 1486,
	__end_of_fixed_addresses = 1487,
};

struct device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device *, struct device_attribute *, char *);
	ssize_t (*store)(struct device *, struct device_attribute *, const char *, size_t);
};

struct cpu {
	int node_id;
	int hotpluggable;
	struct device dev;
};

typedef int (*cpu_stop_fn_t)(void *);

struct cpuinfo_32bit {
	u32 reg_id_dfr0;
	u32 reg_id_dfr1;
	u32 reg_id_isar0;
	u32 reg_id_isar1;
	u32 reg_id_isar2;
	u32 reg_id_isar3;
	u32 reg_id_isar4;
	u32 reg_id_isar5;
	u32 reg_id_isar6;
	u32 reg_id_mmfr0;
	u32 reg_id_mmfr1;
	u32 reg_id_mmfr2;
	u32 reg_id_mmfr3;
	u32 reg_id_mmfr4;
	u32 reg_id_mmfr5;
	u32 reg_id_pfr0;
	u32 reg_id_pfr1;
	u32 reg_id_pfr2;
	u32 reg_mvfr0;
	u32 reg_mvfr1;
	u32 reg_mvfr2;
};

struct cpuinfo_arm64 {
	struct cpu cpu;
	struct kobject kobj;
	u64 reg_ctr;
	u64 reg_cntfrq;
	u64 reg_dczid;
	u64 reg_midr;
	u64 reg_revidr;
	u64 reg_gmid;
	u64 reg_smidr;
	u64 reg_id_aa64dfr0;
	u64 reg_id_aa64dfr1;
	u64 reg_id_aa64isar0;
	u64 reg_id_aa64isar1;
	u64 reg_id_aa64isar2;
	u64 reg_id_aa64mmfr0;
	u64 reg_id_aa64mmfr1;
	u64 reg_id_aa64mmfr2;
	u64 reg_id_aa64pfr0;
	u64 reg_id_aa64pfr1;
	u64 reg_id_aa64zfr0;
	u64 reg_id_aa64smfr0;
	struct cpuinfo_32bit aarch32;
	u64 reg_zcr;
	u64 reg_smcr;
};

enum kvm_mode {
	KVM_MODE_DEFAULT = 0,
	KVM_MODE_PROTECTED = 1,
	KVM_MODE_NONE = 2,
};

enum vcpu_sysreg {
	__INVALID_SYSREG__ = 0,
	MPIDR_EL1 = 1,
	CSSELR_EL1 = 2,
	SCTLR_EL1 = 3,
	ACTLR_EL1 = 4,
	CPACR_EL1 = 5,
	ZCR_EL1 = 6,
	TTBR0_EL1 = 7,
	TTBR1_EL1 = 8,
	TCR_EL1 = 9,
	ESR_EL1 = 10,
	AFSR0_EL1 = 11,
	AFSR1_EL1 = 12,
	FAR_EL1 = 13,
	MAIR_EL1 = 14,
	VBAR_EL1 = 15,
	CONTEXTIDR_EL1 = 16,
	TPIDR_EL0 = 17,
	TPIDRRO_EL0 = 18,
	TPIDR_EL1 = 19,
	AMAIR_EL1 = 20,
	CNTKCTL_EL1 = 21,
	PAR_EL1 = 22,
	MDSCR_EL1 = 23,
	MDCCINT_EL1 = 24,
	OSLSR_EL1 = 25,
	DISR_EL1 = 26,
	PMCR_EL0 = 27,
	PMSELR_EL0 = 28,
	PMEVCNTR0_EL0 = 29,
	PMEVCNTR30_EL0 = 59,
	PMCCNTR_EL0 = 60,
	PMEVTYPER0_EL0 = 61,
	PMEVTYPER30_EL0 = 91,
	PMCCFILTR_EL0 = 92,
	PMCNTENSET_EL0 = 93,
	PMINTENSET_EL1 = 94,
	PMOVSSET_EL0 = 95,
	PMUSERENR_EL0 = 96,
	APIAKEYLO_EL1 = 97,
	APIAKEYHI_EL1 = 98,
	APIBKEYLO_EL1 = 99,
	APIBKEYHI_EL1 = 100,
	APDAKEYLO_EL1 = 101,
	APDAKEYHI_EL1 = 102,
	APDBKEYLO_EL1 = 103,
	APDBKEYHI_EL1 = 104,
	APGAKEYLO_EL1 = 105,
	APGAKEYHI_EL1 = 106,
	ELR_EL1 = 107,
	SP_EL1 = 108,
	SPSR_EL1 = 109,
	CNTVOFF_EL2 = 110,
	CNTV_CVAL_EL0 = 111,
	CNTV_CTL_EL0 = 112,
	CNTP_CVAL_EL0 = 113,
	CNTP_CTL_EL0 = 114,
	RGSR_EL1 = 115,
	GCR_EL1 = 116,
	TFSR_EL1 = 117,
	TFSRE0_EL1 = 118,
	DACR32_EL2 = 119,
	IFSR32_EL2 = 120,
	FPEXC32_EL2 = 121,
	DBGVCR32_EL2 = 122,
	NR_SYS_REGS = 123,
};

struct undef_hook {
	struct list_head node;
	u32 instr_mask;
	u32 instr_val;
	u64 pstate_mask;
	u64 pstate_val;
	int (*fn)(struct pt_regs *, u32);
};

enum arm64_bp_harden_el1_vectors {
	EL1_VECTOR_BHB_LOOP = 0,
	EL1_VECTOR_BHB_FW = 1,
	EL1_VECTOR_BHB_CLEAR_INSN = 2,
	EL1_VECTOR_KPTI = 3,
};

struct __ftr_reg_entry {
	u32 sys_id;
	struct arm64_ftr_reg *reg;
};

typedef void kpti_remap_fn(int, int, phys_addr_t, long unsigned int);

typedef void ttbr_replace_func(phys_addr_t);

struct arm_cpuidle_irq_context {};

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

struct aarch64_insn_patch {
	void **text_addrs;
	u32 *new_insns;
	int insn_cnt;
	atomic_t cpu_count;
};

enum perf_sample_regs_abi {
	PERF_SAMPLE_REGS_ABI_NONE = 0,
	PERF_SAMPLE_REGS_ABI_32 = 1,
	PERF_SAMPLE_REGS_ABI_64 = 2,
};

enum perf_event_arm_regs {
	PERF_REG_ARM64_X0 = 0,
	PERF_REG_ARM64_X1 = 1,
	PERF_REG_ARM64_X2 = 2,
	PERF_REG_ARM64_X3 = 3,
	PERF_REG_ARM64_X4 = 4,
	PERF_REG_ARM64_X5 = 5,
	PERF_REG_ARM64_X6 = 6,
	PERF_REG_ARM64_X7 = 7,
	PERF_REG_ARM64_X8 = 8,
	PERF_REG_ARM64_X9 = 9,
	PERF_REG_ARM64_X10 = 10,
	PERF_REG_ARM64_X11 = 11,
	PERF_REG_ARM64_X12 = 12,
	PERF_REG_ARM64_X13 = 13,
	PERF_REG_ARM64_X14 = 14,
	PERF_REG_ARM64_X15 = 15,
	PERF_REG_ARM64_X16 = 16,
	PERF_REG_ARM64_X17 = 17,
	PERF_REG_ARM64_X18 = 18,
	PERF_REG_ARM64_X19 = 19,
	PERF_REG_ARM64_X20 = 20,
	PERF_REG_ARM64_X21 = 21,
	PERF_REG_ARM64_X22 = 22,
	PERF_REG_ARM64_X23 = 23,
	PERF_REG_ARM64_X24 = 24,
	PERF_REG_ARM64_X25 = 25,
	PERF_REG_ARM64_X26 = 26,
	PERF_REG_ARM64_X27 = 27,
	PERF_REG_ARM64_X28 = 28,
	PERF_REG_ARM64_X29 = 29,
	PERF_REG_ARM64_LR = 30,
	PERF_REG_ARM64_SP = 31,
	PERF_REG_ARM64_PC = 32,
	PERF_REG_ARM64_MAX = 33,
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

typedef int (*pte_fn_t)(pte_t *, long unsigned int, void *);

typedef __u64 __le64;

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

typedef __u64 Elf64_Off;

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

enum key_being_used_for {
	VERIFYING_MODULE_SIGNATURE = 0,
	VERIFYING_FIRMWARE_SIGNATURE = 1,
	VERIFYING_KEXEC_PE_SIGNATURE = 2,
	VERIFYING_KEY_SIGNATURE = 3,
	VERIFYING_KEY_SELF_SIGNATURE = 4,
	VERIFYING_UNSPECIFIED_SIGNATURE = 5,
	NR__KEY_BEING_USED_FOR = 6,
};

struct kimage_arch {
	void *dtb;
	phys_addr_t dtb_mem;
	phys_addr_t kern_reloc;
	phys_addr_t el2_vectors;
	phys_addr_t ttbr0;
	phys_addr_t ttbr1;
	phys_addr_t zero_page;
	long unsigned int phys_offset;
	long unsigned int t0sz;
};

typedef int kexec_probe_t(const char *, long unsigned int);

struct kimage;

typedef void *kexec_load_t(struct kimage *, char *, long unsigned int, char *, long unsigned int, char *, long unsigned int);

typedef int kexec_cleanup_t(void *);

typedef int kexec_verify_sig_t(const char *, long unsigned int);

struct kexec_file_ops {
	kexec_probe_t *probe;
	kexec_load_t *load;
	kexec_cleanup_t *cleanup;
	kexec_verify_sig_t *verify_sig;
};

typedef long unsigned int kimage_entry_t;

struct kexec_segment {
	union {
		void *buf;
		void *kbuf;
	};
	size_t bufsz;
	long unsigned int mem;
	size_t memsz;
};

struct purgatory_info {
	const Elf64_Ehdr *ehdr;
	Elf64_Shdr *sechdrs;
	void *purgatory_buf;
};

struct kimage {
	kimage_entry_t head;
	kimage_entry_t *entry;
	kimage_entry_t *last_entry;
	long unsigned int start;
	struct page *control_code_page;
	struct page *swap_page;
	void *vmcoreinfo_data_copy;
	long unsigned int nr_segments;
	struct kexec_segment segment[16];
	struct list_head control_pages;
	struct list_head dest_pages;
	struct list_head unusable_pages;
	long unsigned int control_page;
	unsigned int type: 1;
	unsigned int preserve_context: 1;
	unsigned int file_mode: 1;
	struct kimage_arch arch;
	void *kernel_buf;
	long unsigned int kernel_buf_len;
	void *initrd_buf;
	long unsigned int initrd_buf_len;
	char *cmdline_buf;
	long unsigned int cmdline_buf_len;
	const struct kexec_file_ops *fops;
	void *image_loader_data;
	struct purgatory_info purgatory_info;
	void *ima_buffer;
	phys_addr_t ima_buffer_addr;
	size_t ima_buffer_size;
	void *elf_headers;
	long unsigned int elf_headers_sz;
	long unsigned int elf_load_addr;
};

struct kexec_buf {
	struct kimage *image;
	void *buffer;
	long unsigned int bufsz;
	long unsigned int mem;
	long unsigned int memsz;
	long unsigned int buf_align;
	long unsigned int buf_min;
	long unsigned int buf_max;
	bool top_down;
};

struct arm64_image_header {
	__le32 code0;
	__le32 code1;
	__le64 text_offset;
	__le64 image_size;
	__le64 flags;
	__le64 res2;
	__le64 res3;
	__le64 res4;
	__le32 magic;
	__le32 res5;
};

typedef long unsigned int irq_hw_number_t;

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
	unsigned int ipi_offset;
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

struct irqaction;

struct irq_affinity_notify;

struct proc_dir_entry;

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
	long: 64;
	long: 64;
};

typedef bool pstate_check_t(long unsigned int);

typedef struct {
	pgd_t pgd;
} p4d_t;

struct wait_queue_entry;

typedef int (*wait_queue_func_t)(struct wait_queue_entry *, unsigned int, int, void *);

struct wait_queue_entry {
	unsigned int flags;
	void *private;
	wait_queue_func_t func;
	struct list_head entry;
};

typedef struct wait_queue_entry wait_queue_entry_t;

typedef u32 probe_opcode_t;

typedef void probes_handler_t(u32, long int, struct pt_regs *);

struct arch_probe_insn {
	probe_opcode_t *insn;
	pstate_check_t *pstate_cc;
	probes_handler_t *handler;
	long unsigned int restore;
};

typedef u32 kprobe_opcode_t;

struct arch_specific_insn {
	struct arch_probe_insn api;
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

struct reclaim_state {
	long unsigned int reclaimed_slab;
};

struct irq_fwspec {
	struct fwnode_handle *fwnode;
	int param_count;
	u32 param[16];
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

struct irq_domain_chip_generic;

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

enum irq_gc_flags {
	IRQ_GC_INIT_MASK_CACHE = 1,
	IRQ_GC_INIT_NESTED_LOCK = 2,
	IRQ_GC_MASK_CACHE_PER_TYPE = 4,
	IRQ_GC_NO_MASK = 8,
	IRQ_GC_BE_IO = 16,
};

struct irq_chip_generic;

struct irq_domain_chip_generic {
	unsigned int irqs_per_chip;
	unsigned int num_chips;
	unsigned int irq_flags_to_clear;
	unsigned int irq_flags_to_set;
	enum irq_gc_flags gc_flags;
	struct irq_chip_generic *gc[0];
};

struct wait_page_queue {
	struct folio *folio;
	int bit_nr;
	wait_queue_entry_t wait;
};

struct readahead_control {
	struct file *file;
	struct address_space *mapping;
	struct file_ra_state *ra;
	long unsigned int _index;
	unsigned int _nr_pages;
	unsigned int _batch_count;
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

enum irqreturn {
	IRQ_NONE = 0,
	IRQ_HANDLED = 1,
	IRQ_WAKE_THREAD = 2,
};

typedef enum irqreturn irqreturn_t;

enum irqchip_irq_state {
	IRQCHIP_STATE_PENDING = 0,
	IRQCHIP_STATE_ACTIVE = 1,
	IRQCHIP_STATE_MASKED = 2,
	IRQCHIP_STATE_LINE_LEVEL = 3,
};

struct msi_msg;

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

struct kprobe;

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

enum wb_stat_item {
	WB_RECLAIMABLE = 0,
	WB_WRITEBACK = 1,
	WB_DIRTIED = 2,
	WB_WRITTEN = 3,
	NR_WB_STAT_ITEMS = 4,
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

struct percpu_cluster {
	struct swap_cluster_info index;
	unsigned int next;
};

struct hstate {
	struct mutex resize_lock;
	int next_nid_to_alloc;
	int next_nid_to_free;
	unsigned int order;
	unsigned int demote_order;
	long unsigned int mask;
	long unsigned int max_huge_pages;
	long unsigned int nr_huge_pages;
	long unsigned int free_huge_pages;
	long unsigned int resv_huge_pages;
	long unsigned int surplus_huge_pages;
	long unsigned int nr_overcommit_huge_pages;
	struct list_head hugepage_activelist;
	struct list_head hugepage_freelists[512];
	unsigned int max_huge_pages_node[512];
	unsigned int nr_huge_pages_node[512];
	unsigned int free_huge_pages_node[512];
	unsigned int surplus_huge_pages_node[512];
	char name[32];
};

struct fault_info {
	int (*fn)(long unsigned int, long unsigned int, struct pt_regs *);
	int sig;
	int code;
	const char *name;
};

typedef __kernel_long_t __kernel_off_t;

typedef __u16 __be16;

typedef __u32 __be32;

typedef __u32 __wsum;

typedef __kernel_off_t off_t;

enum {
	BPF_REG_0 = 0,
	BPF_REG_1 = 1,
	BPF_REG_2 = 2,
	BPF_REG_3 = 3,
	BPF_REG_4 = 4,
	BPF_REG_5 = 5,
	BPF_REG_6 = 6,
	BPF_REG_7 = 7,
	BPF_REG_8 = 8,
	BPF_REG_9 = 9,
	BPF_REG_10 = 10,
	__MAX_BPF_REG = 11,
};

struct bpf_insn {
	__u8 code;
	__u8 dst_reg: 4;
	__u8 src_reg: 4;
	__s16 off;
	__s32 imm;
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC = 0,
	BPF_PROG_TYPE_SOCKET_FILTER = 1,
	BPF_PROG_TYPE_KPROBE = 2,
	BPF_PROG_TYPE_SCHED_CLS = 3,
	BPF_PROG_TYPE_SCHED_ACT = 4,
	BPF_PROG_TYPE_TRACEPOINT = 5,
	BPF_PROG_TYPE_XDP = 6,
	BPF_PROG_TYPE_PERF_EVENT = 7,
	BPF_PROG_TYPE_CGROUP_SKB = 8,
	BPF_PROG_TYPE_CGROUP_SOCK = 9,
	BPF_PROG_TYPE_LWT_IN = 10,
	BPF_PROG_TYPE_LWT_OUT = 11,
	BPF_PROG_TYPE_LWT_XMIT = 12,
	BPF_PROG_TYPE_SOCK_OPS = 13,
	BPF_PROG_TYPE_SK_SKB = 14,
	BPF_PROG_TYPE_CGROUP_DEVICE = 15,
	BPF_PROG_TYPE_SK_MSG = 16,
	BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
	BPF_PROG_TYPE_LWT_SEG6LOCAL = 19,
	BPF_PROG_TYPE_LIRC_MODE2 = 20,
	BPF_PROG_TYPE_SK_REUSEPORT = 21,
	BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
	BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
	BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
	BPF_PROG_TYPE_TRACING = 26,
	BPF_PROG_TYPE_STRUCT_OPS = 27,
	BPF_PROG_TYPE_EXT = 28,
	BPF_PROG_TYPE_LSM = 29,
	BPF_PROG_TYPE_SK_LOOKUP = 30,
	BPF_PROG_TYPE_SYSCALL = 31,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS = 0,
	BPF_CGROUP_INET_EGRESS = 1,
	BPF_CGROUP_INET_SOCK_CREATE = 2,
	BPF_CGROUP_SOCK_OPS = 3,
	BPF_SK_SKB_STREAM_PARSER = 4,
	BPF_SK_SKB_STREAM_VERDICT = 5,
	BPF_CGROUP_DEVICE = 6,
	BPF_SK_MSG_VERDICT = 7,
	BPF_CGROUP_INET4_BIND = 8,
	BPF_CGROUP_INET6_BIND = 9,
	BPF_CGROUP_INET4_CONNECT = 10,
	BPF_CGROUP_INET6_CONNECT = 11,
	BPF_CGROUP_INET4_POST_BIND = 12,
	BPF_CGROUP_INET6_POST_BIND = 13,
	BPF_CGROUP_UDP4_SENDMSG = 14,
	BPF_CGROUP_UDP6_SENDMSG = 15,
	BPF_LIRC_MODE2 = 16,
	BPF_FLOW_DISSECTOR = 17,
	BPF_CGROUP_SYSCTL = 18,
	BPF_CGROUP_UDP4_RECVMSG = 19,
	BPF_CGROUP_UDP6_RECVMSG = 20,
	BPF_CGROUP_GETSOCKOPT = 21,
	BPF_CGROUP_SETSOCKOPT = 22,
	BPF_TRACE_RAW_TP = 23,
	BPF_TRACE_FENTRY = 24,
	BPF_TRACE_FEXIT = 25,
	BPF_MODIFY_RETURN = 26,
	BPF_LSM_MAC = 27,
	BPF_TRACE_ITER = 28,
	BPF_CGROUP_INET4_GETPEERNAME = 29,
	BPF_CGROUP_INET6_GETPEERNAME = 30,
	BPF_CGROUP_INET4_GETSOCKNAME = 31,
	BPF_CGROUP_INET6_GETSOCKNAME = 32,
	BPF_XDP_DEVMAP = 33,
	BPF_CGROUP_INET_SOCK_RELEASE = 34,
	BPF_XDP_CPUMAP = 35,
	BPF_SK_LOOKUP = 36,
	BPF_XDP = 37,
	BPF_SK_SKB_VERDICT = 38,
	BPF_SK_REUSEPORT_SELECT = 39,
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE = 40,
	BPF_PERF_EVENT = 41,
	BPF_TRACE_KPROBE_MULTI = 42,
	BPF_LSM_CGROUP = 43,
	__MAX_BPF_ATTACH_TYPE = 44,
};

enum bpf_link_type {
	BPF_LINK_TYPE_UNSPEC = 0,
	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
	BPF_LINK_TYPE_TRACING = 2,
	BPF_LINK_TYPE_CGROUP = 3,
	BPF_LINK_TYPE_ITER = 4,
	BPF_LINK_TYPE_NETNS = 5,
	BPF_LINK_TYPE_XDP = 6,
	BPF_LINK_TYPE_PERF_EVENT = 7,
	BPF_LINK_TYPE_KPROBE_MULTI = 8,
	BPF_LINK_TYPE_STRUCT_OPS = 9,
	MAX_BPF_LINK_TYPE = 10,
};

union bpf_attr {
	struct {
		__u32 map_type;
		__u32 key_size;
		__u32 value_size;
		__u32 max_entries;
		__u32 map_flags;
		__u32 inner_map_fd;
		__u32 numa_node;
		char map_name[16];
		__u32 map_ifindex;
		__u32 btf_fd;
		__u32 btf_key_type_id;
		__u32 btf_value_type_id;
		__u32 btf_vmlinux_value_type_id;
		__u64 map_extra;
	};
	struct {
		__u32 map_fd;
		__u64 key;
		union {
			__u64 value;
			__u64 next_key;
		};
		__u64 flags;
	};
	struct {
		__u64 in_batch;
		__u64 out_batch;
		__u64 keys;
		__u64 values;
		__u32 count;
		__u32 map_fd;
		__u64 elem_flags;
		__u64 flags;
	} batch;
	struct {
		__u32 prog_type;
		__u32 insn_cnt;
		__u64 insns;
		__u64 license;
		__u32 log_level;
		__u32 log_size;
		__u64 log_buf;
		__u32 kern_version;
		__u32 prog_flags;
		char prog_name[16];
		__u32 prog_ifindex;
		__u32 expected_attach_type;
		__u32 prog_btf_fd;
		__u32 func_info_rec_size;
		__u64 func_info;
		__u32 func_info_cnt;
		__u32 line_info_rec_size;
		__u64 line_info;
		__u32 line_info_cnt;
		__u32 attach_btf_id;
		union {
			__u32 attach_prog_fd;
			__u32 attach_btf_obj_fd;
		};
		__u32 core_relo_cnt;
		__u64 fd_array;
		__u64 core_relos;
		__u32 core_relo_rec_size;
	};
	struct {
		__u64 pathname;
		__u32 bpf_fd;
		__u32 file_flags;
	};
	struct {
		__u32 target_fd;
		__u32 attach_bpf_fd;
		__u32 attach_type;
		__u32 attach_flags;
		__u32 replace_bpf_fd;
	};
	struct {
		__u32 prog_fd;
		__u32 retval;
		__u32 data_size_in;
		__u32 data_size_out;
		__u64 data_in;
		__u64 data_out;
		__u32 repeat;
		__u32 duration;
		__u32 ctx_size_in;
		__u32 ctx_size_out;
		__u64 ctx_in;
		__u64 ctx_out;
		__u32 flags;
		__u32 cpu;
		__u32 batch_size;
	} test;
	struct {
		union {
			__u32 start_id;
			__u32 prog_id;
			__u32 map_id;
			__u32 btf_id;
			__u32 link_id;
		};
		__u32 next_id;
		__u32 open_flags;
	};
	struct {
		__u32 bpf_fd;
		__u32 info_len;
		__u64 info;
	} info;
	struct {
		__u32 target_fd;
		__u32 attach_type;
		__u32 query_flags;
		__u32 attach_flags;
		__u64 prog_ids;
		__u32 prog_cnt;
		__u64 prog_attach_flags;
	} query;
	struct {
		__u64 name;
		__u32 prog_fd;
	} raw_tracepoint;
	struct {
		__u64 btf;
		__u64 btf_log_buf;
		__u32 btf_size;
		__u32 btf_log_size;
		__u32 btf_log_level;
	};
	struct {
		__u32 pid;
		__u32 fd;
		__u32 flags;
		__u32 buf_len;
		__u64 buf;
		__u32 prog_id;
		__u32 fd_type;
		__u64 probe_offset;
		__u64 probe_addr;
	} task_fd_query;
	struct {
		__u32 prog_fd;
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 flags;
		union {
			__u32 target_btf_id;
			struct {
				__u64 iter_info;
				__u32 iter_info_len;
			};
			struct {
				__u64 bpf_cookie;
			} perf_event;
			struct {
				__u32 flags;
				__u32 cnt;
				__u64 syms;
				__u64 addrs;
				__u64 cookies;
			} kprobe_multi;
			struct {
				__u32 target_btf_id;
				__u64 cookie;
			} tracing;
		};
	} link_create;
	struct {
		__u32 link_fd;
		__u32 new_prog_fd;
		__u32 flags;
		__u32 old_prog_fd;
	} link_update;
	struct {
		__u32 link_fd;
	} link_detach;
	struct {
		__u32 type;
	} enable_stats;
	struct {
		__u32 link_fd;
		__u32 flags;
	} iter_create;
	struct {
		__u32 prog_fd;
		__u32 map_fd;
		__u32 flags;
	} prog_bind_map;
};

struct bpf_link_info {
	__u32 type;
	__u32 id;
	__u32 prog_id;
	union {
		struct {
			__u64 tp_name;
			__u32 tp_name_len;
		} raw_tracepoint;
		struct {
			__u32 attach_type;
			__u32 target_obj_id;
			__u32 target_btf_id;
		} tracing;
		struct {
			__u64 cgroup_id;
			__u32 attach_type;
		} cgroup;
		struct {
			__u64 target_name;
			__u32 target_name_len;
			union {
				struct {
					__u32 map_id;
				} map;
			};
		} iter;
		struct {
			__u32 netns_ino;
			__u32 attach_type;
		} netns;
		struct {
			__u32 ifindex;
		} xdp;
	};
};

struct bpf_func_info {
	__u32 insn_off;
	__u32 type_id;
};

struct bpf_line_info {
	__u32 insn_off;
	__u32 file_name_off;
	__u32 line_off;
	__u32 line_col;
};

struct sock_filter {
	__u16 code;
	__u8 jt;
	__u8 jf;
	__u32 k;
};

enum aarch64_insn_hint_cr_op {
	AARCH64_INSN_HINT_NOP = 0,
	AARCH64_INSN_HINT_YIELD = 32,
	AARCH64_INSN_HINT_WFE = 64,
	AARCH64_INSN_HINT_WFI = 96,
	AARCH64_INSN_HINT_SEV = 128,
	AARCH64_INSN_HINT_SEVL = 160,
	AARCH64_INSN_HINT_XPACLRI = 224,
	AARCH64_INSN_HINT_PACIA_1716 = 256,
	AARCH64_INSN_HINT_PACIB_1716 = 320,
	AARCH64_INSN_HINT_AUTIA_1716 = 384,
	AARCH64_INSN_HINT_AUTIB_1716 = 448,
	AARCH64_INSN_HINT_PACIAZ = 768,
	AARCH64_INSN_HINT_PACIASP = 800,
	AARCH64_INSN_HINT_PACIBZ = 832,
	AARCH64_INSN_HINT_PACIBSP = 864,
	AARCH64_INSN_HINT_AUTIAZ = 896,
	AARCH64_INSN_HINT_AUTIASP = 928,
	AARCH64_INSN_HINT_AUTIBZ = 960,
	AARCH64_INSN_HINT_AUTIBSP = 992,
	AARCH64_INSN_HINT_ESB = 512,
	AARCH64_INSN_HINT_PSB = 544,
	AARCH64_INSN_HINT_TSB = 576,
	AARCH64_INSN_HINT_CSDB = 640,
	AARCH64_INSN_HINT_CLEARBHB = 704,
	AARCH64_INSN_HINT_BTI = 1024,
	AARCH64_INSN_HINT_BTIC = 1088,
	AARCH64_INSN_HINT_BTIJ = 1152,
	AARCH64_INSN_HINT_BTIJC = 1216,
};

enum aarch64_insn_register {
	AARCH64_INSN_REG_0 = 0,
	AARCH64_INSN_REG_1 = 1,
	AARCH64_INSN_REG_2 = 2,
	AARCH64_INSN_REG_3 = 3,
	AARCH64_INSN_REG_4 = 4,
	AARCH64_INSN_REG_5 = 5,
	AARCH64_INSN_REG_6 = 6,
	AARCH64_INSN_REG_7 = 7,
	AARCH64_INSN_REG_8 = 8,
	AARCH64_INSN_REG_9 = 9,
	AARCH64_INSN_REG_10 = 10,
	AARCH64_INSN_REG_11 = 11,
	AARCH64_INSN_REG_12 = 12,
	AARCH64_INSN_REG_13 = 13,
	AARCH64_INSN_REG_14 = 14,
	AARCH64_INSN_REG_15 = 15,
	AARCH64_INSN_REG_16 = 16,
	AARCH64_INSN_REG_17 = 17,
	AARCH64_INSN_REG_18 = 18,
	AARCH64_INSN_REG_19 = 19,
	AARCH64_INSN_REG_20 = 20,
	AARCH64_INSN_REG_21 = 21,
	AARCH64_INSN_REG_22 = 22,
	AARCH64_INSN_REG_23 = 23,
	AARCH64_INSN_REG_24 = 24,
	AARCH64_INSN_REG_25 = 25,
	AARCH64_INSN_REG_26 = 26,
	AARCH64_INSN_REG_27 = 27,
	AARCH64_INSN_REG_28 = 28,
	AARCH64_INSN_REG_29 = 29,
	AARCH64_INSN_REG_FP = 29,
	AARCH64_INSN_REG_30 = 30,
	AARCH64_INSN_REG_LR = 30,
	AARCH64_INSN_REG_ZR = 31,
	AARCH64_INSN_REG_SP = 31,
};

enum aarch64_insn_variant {
	AARCH64_INSN_VARIANT_32BIT = 0,
	AARCH64_INSN_VARIANT_64BIT = 1,
};

enum aarch64_insn_condition {
	AARCH64_INSN_COND_EQ = 0,
	AARCH64_INSN_COND_NE = 1,
	AARCH64_INSN_COND_CS = 2,
	AARCH64_INSN_COND_CC = 3,
	AARCH64_INSN_COND_MI = 4,
	AARCH64_INSN_COND_PL = 5,
	AARCH64_INSN_COND_VS = 6,
	AARCH64_INSN_COND_VC = 7,
	AARCH64_INSN_COND_HI = 8,
	AARCH64_INSN_COND_LS = 9,
	AARCH64_INSN_COND_GE = 10,
	AARCH64_INSN_COND_LT = 11,
	AARCH64_INSN_COND_GT = 12,
	AARCH64_INSN_COND_LE = 13,
	AARCH64_INSN_COND_AL = 14,
};

enum aarch64_insn_branch_type {
	AARCH64_INSN_BRANCH_NOLINK = 0,
	AARCH64_INSN_BRANCH_LINK = 1,
	AARCH64_INSN_BRANCH_RETURN = 2,
	AARCH64_INSN_BRANCH_COMP_ZERO = 3,
	AARCH64_INSN_BRANCH_COMP_NONZERO = 4,
};

enum aarch64_insn_size_type {
	AARCH64_INSN_SIZE_8 = 0,
	AARCH64_INSN_SIZE_16 = 1,
	AARCH64_INSN_SIZE_32 = 2,
	AARCH64_INSN_SIZE_64 = 3,
};

enum aarch64_insn_ldst_type {
	AARCH64_INSN_LDST_LOAD_REG_OFFSET = 0,
	AARCH64_INSN_LDST_STORE_REG_OFFSET = 1,
	AARCH64_INSN_LDST_LOAD_IMM_OFFSET = 2,
	AARCH64_INSN_LDST_STORE_IMM_OFFSET = 3,
	AARCH64_INSN_LDST_LOAD_PAIR_PRE_INDEX = 4,
	AARCH64_INSN_LDST_STORE_PAIR_PRE_INDEX = 5,
	AARCH64_INSN_LDST_LOAD_PAIR_POST_INDEX = 6,
	AARCH64_INSN_LDST_STORE_PAIR_POST_INDEX = 7,
	AARCH64_INSN_LDST_LOAD_EX = 8,
	AARCH64_INSN_LDST_LOAD_ACQ_EX = 9,
	AARCH64_INSN_LDST_STORE_EX = 10,
	AARCH64_INSN_LDST_STORE_REL_EX = 11,
};

enum aarch64_insn_adsb_type {
	AARCH64_INSN_ADSB_ADD = 0,
	AARCH64_INSN_ADSB_SUB = 1,
	AARCH64_INSN_ADSB_ADD_SETFLAGS = 2,
	AARCH64_INSN_ADSB_SUB_SETFLAGS = 3,
};

enum aarch64_insn_movewide_type {
	AARCH64_INSN_MOVEWIDE_ZERO = 0,
	AARCH64_INSN_MOVEWIDE_KEEP = 1,
	AARCH64_INSN_MOVEWIDE_INVERSE = 2,
};

enum aarch64_insn_bitfield_type {
	AARCH64_INSN_BITFIELD_MOVE = 0,
	AARCH64_INSN_BITFIELD_MOVE_UNSIGNED = 1,
	AARCH64_INSN_BITFIELD_MOVE_SIGNED = 2,
};

enum aarch64_insn_data1_type {
	AARCH64_INSN_DATA1_REVERSE_16 = 0,
	AARCH64_INSN_DATA1_REVERSE_32 = 1,
	AARCH64_INSN_DATA1_REVERSE_64 = 2,
};

enum aarch64_insn_data2_type {
	AARCH64_INSN_DATA2_UDIV = 0,
	AARCH64_INSN_DATA2_SDIV = 1,
	AARCH64_INSN_DATA2_LSLV = 2,
	AARCH64_INSN_DATA2_LSRV = 3,
	AARCH64_INSN_DATA2_ASRV = 4,
	AARCH64_INSN_DATA2_RORV = 5,
};

enum aarch64_insn_data3_type {
	AARCH64_INSN_DATA3_MADD = 0,
	AARCH64_INSN_DATA3_MSUB = 1,
};

enum aarch64_insn_logic_type {
	AARCH64_INSN_LOGIC_AND = 0,
	AARCH64_INSN_LOGIC_BIC = 1,
	AARCH64_INSN_LOGIC_ORR = 2,
	AARCH64_INSN_LOGIC_ORN = 3,
	AARCH64_INSN_LOGIC_EOR = 4,
	AARCH64_INSN_LOGIC_EON = 5,
	AARCH64_INSN_LOGIC_AND_SETFLAGS = 6,
	AARCH64_INSN_LOGIC_BIC_SETFLAGS = 7,
};

enum aarch64_insn_mem_atomic_op {
	AARCH64_INSN_MEM_ATOMIC_ADD = 0,
	AARCH64_INSN_MEM_ATOMIC_CLR = 1,
	AARCH64_INSN_MEM_ATOMIC_EOR = 2,
	AARCH64_INSN_MEM_ATOMIC_SET = 3,
	AARCH64_INSN_MEM_ATOMIC_SWP = 4,
};

enum aarch64_insn_mem_order_type {
	AARCH64_INSN_MEM_ORDER_NONE = 0,
	AARCH64_INSN_MEM_ORDER_ACQ = 1,
	AARCH64_INSN_MEM_ORDER_REL = 2,
	AARCH64_INSN_MEM_ORDER_ACQREL = 3,
};

enum aarch64_insn_mb_type {
	AARCH64_INSN_MB_SY = 0,
	AARCH64_INSN_MB_ST = 1,
	AARCH64_INSN_MB_LD = 2,
	AARCH64_INSN_MB_ISH = 3,
	AARCH64_INSN_MB_ISHST = 4,
	AARCH64_INSN_MB_ISHLD = 5,
	AARCH64_INSN_MB_NSH = 6,
	AARCH64_INSN_MB_NSHST = 7,
	AARCH64_INSN_MB_NSHLD = 8,
	AARCH64_INSN_MB_OSH = 9,
	AARCH64_INSN_MB_OSHST = 10,
	AARCH64_INSN_MB_OSHLD = 11,
};

enum {
	DUMP_PREFIX_NONE = 0,
	DUMP_PREFIX_ADDRESS = 1,
	DUMP_PREFIX_OFFSET = 2,
};

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

struct page_pool_alloc_stats {
	u64 fast;
	u64 slow;
	u64 slow_high_order;
	u64 empty;
	u64 refill;
	u64 waive;
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

struct page_pool_recycle_stats;

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
	struct page_pool_alloc_stats alloc_stats;
	u32 xdp_mem_id;
	long: 32;
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
	struct page_pool_recycle_stats *recycle_stats;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct bpf_run_ctx {};

struct raw_notifier_head {
	struct notifier_block *head;
};

struct btf_type {
	__u32 name_off;
	__u32 info;
	union {
		__u32 size;
		__u32 type;
	};
};

typedef void (*btf_dtor_kfunc_t)(void *);

typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);

struct bpf_iter_aux_info;

typedef int (*bpf_iter_init_seq_priv_t)(void *, struct bpf_iter_aux_info *);

struct bpf_map;

struct bpf_iter_aux_info {
	struct bpf_map *map;
};

typedef void (*bpf_iter_fini_seq_priv_t)(void *);

struct bpf_iter_seq_info {
	const struct seq_operations *seq_ops;
	bpf_iter_init_seq_priv_t init_seq_private;
	bpf_iter_fini_seq_priv_t fini_seq_private;
	u32 seq_priv_size;
};

struct btf;

struct bpf_prog_aux;

struct bpf_local_storage_map;

struct bpf_verifier_env;

struct bpf_func_state;

struct bpf_map_ops {
	int (*map_alloc_check)(union bpf_attr *);
	struct bpf_map * (*map_alloc)(union bpf_attr *);
	void (*map_release)(struct bpf_map *, struct file *);
	void (*map_free)(struct bpf_map *);
	int (*map_get_next_key)(struct bpf_map *, void *, void *);
	void (*map_release_uref)(struct bpf_map *);
	void * (*map_lookup_elem_sys_only)(struct bpf_map *, void *);
	int (*map_lookup_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_lookup_and_delete_elem)(struct bpf_map *, void *, void *, u64);
	int (*map_lookup_and_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_update_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	void * (*map_lookup_elem)(struct bpf_map *, void *);
	int (*map_update_elem)(struct bpf_map *, void *, void *, u64);
	int (*map_delete_elem)(struct bpf_map *, void *);
	int (*map_push_elem)(struct bpf_map *, void *, u64);
	int (*map_pop_elem)(struct bpf_map *, void *);
	int (*map_peek_elem)(struct bpf_map *, void *);
	void * (*map_lookup_percpu_elem)(struct bpf_map *, void *, u32);
	void * (*map_fd_get_ptr)(struct bpf_map *, struct file *, int);
	void (*map_fd_put_ptr)(void *);
	int (*map_gen_lookup)(struct bpf_map *, struct bpf_insn *);
	u32 (*map_fd_sys_lookup_elem)(void *);
	void (*map_seq_show_elem)(struct bpf_map *, void *, struct seq_file *);
	int (*map_check_btf)(const struct bpf_map *, const struct btf *, const struct btf_type *, const struct btf_type *);
	int (*map_poke_track)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_untrack)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_run)(struct bpf_map *, u32, struct bpf_prog *, struct bpf_prog *);
	int (*map_direct_value_addr)(const struct bpf_map *, u64 *, u32);
	int (*map_direct_value_meta)(const struct bpf_map *, u64, u32 *);
	int (*map_mmap)(struct bpf_map *, struct vm_area_struct *);
	__poll_t (*map_poll)(struct bpf_map *, struct file *, struct poll_table_struct *);
	int (*map_local_storage_charge)(struct bpf_local_storage_map *, void *, u32);
	void (*map_local_storage_uncharge)(struct bpf_local_storage_map *, void *, u32);
	struct bpf_local_storage ** (*map_owner_storage_ptr)(void *);
	int (*map_redirect)(struct bpf_map *, u32, u64);
	bool (*map_meta_equal)(const struct bpf_map *, const struct bpf_map *);
	int (*map_set_for_each_callback_args)(struct bpf_verifier_env *, struct bpf_func_state *, struct bpf_func_state *);
	int (*map_for_each_callback)(struct bpf_map *, bpf_callback_t, void *, u64);
	int *map_btf_id;
	const struct bpf_iter_seq_info *iter_seq_info;
};

struct bpf_map_value_off;

struct bpf_map_off_arr;

struct bpf_map {
	const struct bpf_map_ops *ops;
	struct bpf_map *inner_map_meta;
	void *security;
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u64 map_extra;
	u32 map_flags;
	int spin_lock_off;
	struct bpf_map_value_off *kptr_off_tab;
	int timer_off;
	u32 id;
	int numa_node;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	u32 btf_vmlinux_value_type_id;
	struct btf *btf;
	struct obj_cgroup *objcg;
	char name[16];
	struct bpf_map_off_arr *off_arr;
	atomic64_t refcnt;
	atomic64_t usercnt;
	struct work_struct work;
	struct mutex freeze_mutex;
	atomic64_t writecnt;
	struct {
		spinlock_t lock;
		enum bpf_prog_type type;
		bool jited;
		bool xdp_has_frags;
	} owner;
	bool bypass_spec_v1;
	bool frozen;
	long: 16;
	long: 64;
	long: 64;
	long: 64;
};

struct btf_header {
	__u16 magic;
	__u8 version;
	__u8 flags;
	__u32 hdr_len;
	__u32 type_off;
	__u32 type_len;
	__u32 str_off;
	__u32 str_len;
};

struct btf_kfunc_set_tab;

struct btf_id_dtor_kfunc_tab;

struct btf {
	void *data;
	struct btf_type **types;
	u32 *resolved_ids;
	u32 *resolved_sizes;
	const char *strings;
	void *nohdr_data;
	struct btf_header hdr;
	u32 nr_types;
	u32 types_size;
	u32 data_size;
	refcount_t refcnt;
	u32 id;
	struct callback_head rcu;
	struct btf_kfunc_set_tab *kfunc_set_tab;
	struct btf_id_dtor_kfunc_tab *dtor_kfunc_tab;
	struct btf *base_btf;
	u32 start_id;
	u32 start_str_off;
	char name[56];
	bool kernel_btf;
};

struct bpf_ksym {
	long unsigned int start;
	long unsigned int end;
	char name[128];
	struct list_head lnode;
	struct latch_tree_node tnode;
	bool prog;
};

struct bpf_ctx_arg_aux;

struct bpf_trampoline;

struct bpf_jit_poke_descriptor;

struct bpf_kfunc_desc_tab;

struct bpf_kfunc_btf_tab;

struct bpf_prog_ops;

struct btf_mod_pair;

struct bpf_prog_offload;

struct bpf_func_info_aux;

struct bpf_prog_aux {
	atomic64_t refcnt;
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 max_ctx_offset;
	u32 max_pkt_offset;
	u32 max_tp_access;
	u32 stack_depth;
	u32 id;
	u32 func_cnt;
	u32 func_idx;
	u32 attach_btf_id;
	u32 ctx_arg_info_size;
	u32 max_rdonly_access;
	u32 max_rdwr_access;
	struct btf *attach_btf;
	const struct bpf_ctx_arg_aux *ctx_arg_info;
	struct mutex dst_mutex;
	struct bpf_prog *dst_prog;
	struct bpf_trampoline *dst_trampoline;
	enum bpf_prog_type saved_dst_prog_type;
	enum bpf_attach_type saved_dst_attach_type;
	bool verifier_zext;
	bool offload_requested;
	bool attach_btf_trace;
	bool func_proto_unreliable;
	bool sleepable;
	bool tail_call_reachable;
	bool xdp_has_frags;
	const struct btf_type *attach_func_proto;
	const char *attach_func_name;
	struct bpf_prog **func;
	void *jit_data;
	struct bpf_jit_poke_descriptor *poke_tab;
	struct bpf_kfunc_desc_tab *kfunc_tab;
	struct bpf_kfunc_btf_tab *kfunc_btf_tab;
	u32 size_poke_tab;
	struct bpf_ksym ksym;
	const struct bpf_prog_ops *ops;
	struct bpf_map **used_maps;
	struct mutex used_maps_mutex;
	struct btf_mod_pair *used_btfs;
	struct bpf_prog *prog;
	struct user_struct *user;
	u64 load_time;
	u32 verified_insns;
	int cgroup_atype;
	struct bpf_map *cgroup_storage[2];
	char name[16];
	void *security;
	struct bpf_prog_offload *offload;
	struct btf *btf;
	struct bpf_func_info *func_info;
	struct bpf_func_info_aux *func_info_aux;
	struct bpf_line_info *linfo;
	void **jited_linfo;
	u32 func_info_cnt;
	u32 nr_linfo;
	u32 linfo_idx;
	u32 num_exentries;
	struct exception_table_entry *extable;
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
};

struct bpf_prog_stats;

struct sock_fprog_kern;

struct bpf_prog {
	u16 pages;
	u16 jited: 1;
	u16 jit_requested: 1;
	u16 gpl_compatible: 1;
	u16 cb_access: 1;
	u16 dst_needed: 1;
	u16 blinding_requested: 1;
	u16 blinded: 1;
	u16 is_func: 1;
	u16 kprobe_override: 1;
	u16 has_callchain_buf: 1;
	u16 enforce_expected_attach_type: 1;
	u16 call_get_stack: 1;
	u16 call_get_func_ip: 1;
	u16 tstamp_type_access: 1;
	enum bpf_prog_type type;
	enum bpf_attach_type expected_attach_type;
	u32 len;
	u32 jited_len;
	u8 tag[8];
	struct bpf_prog_stats *stats;
	int *active;
	unsigned int (*bpf_func)(const void *, const struct bpf_insn *);
	struct bpf_prog_aux *aux;
	struct sock_fprog_kern *orig_prog;
	union {
		struct {
			struct {			} __empty_insns;
			struct sock_filter insns[0];
		};
		struct {
			struct {			} __empty_insnsi;
			struct bpf_insn insnsi[0];
		};
	};
};

enum bpf_kptr_type {
	BPF_KPTR_UNREF = 0,
	BPF_KPTR_REF = 1,
};

struct bpf_map_value_off_desc {
	u32 offset;
	enum bpf_kptr_type type;
	struct {
		struct btf *btf;
		struct module *module;
		btf_dtor_kfunc_t dtor;
		u32 btf_id;
	} kptr;
};

struct bpf_map_value_off {
	u32 nr_off;
	struct bpf_map_value_off_desc off[0];
};

struct bpf_map_off_arr {
	u32 cnt;
	u32 field_off[10];
	u8 field_sz[10];
};

struct bpf_offloaded_map;

struct bpf_map_dev_ops {
	int (*map_get_next_key)(struct bpf_offloaded_map *, void *, void *);
	int (*map_lookup_elem)(struct bpf_offloaded_map *, void *, void *);
	int (*map_update_elem)(struct bpf_offloaded_map *, void *, void *, u64);
	int (*map_delete_elem)(struct bpf_offloaded_map *, void *);
};

struct net_device;

struct bpf_offloaded_map {
	struct bpf_map map;
	struct net_device *netdev;
	const struct bpf_map_dev_ops *dev_ops;
	void *dev_priv;
	struct list_head offloads;
	long: 64;
	long: 64;
	long: 64;
};

typedef u64 netdev_features_t;

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

struct mpls_dev;

enum rx_handler_result {
	RX_HANDLER_CONSUMED = 0,
	RX_HANDLER_ANOTHER = 1,
	RX_HANDLER_EXACT = 2,
	RX_HANDLER_PASS = 3,
};

typedef enum rx_handler_result rx_handler_result_t;

struct sk_buff;

typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **);

struct ref_tracker_dir {};

typedef struct {
	struct net *net;
} possible_net_t;

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

typedef struct {} netdevice_tracker;

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

struct mctp_dev;

struct netdev_rx_queue;

struct mini_Qdisc;

struct netdev_queue;

struct nf_hook_entries;

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
	void *ax25_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	struct mpls_dev *mpls_ptr;
	struct mctp_dev *mctp_ptr;
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

struct bpf_prog_ops {
	int (*test_run)(struct bpf_prog *, const union bpf_attr *, union bpf_attr *);
};

struct bpf_offload_dev;

struct bpf_prog_offload {
	struct bpf_prog *prog;
	struct net_device *netdev;
	struct bpf_offload_dev *offdev;
	void *dev_priv;
	struct list_head offloads;
	bool dev_state;
	bool opt_failed;
	void *jited_image;
	u32 jited_len;
};

struct btf_func_model {
	u8 ret_size;
	u8 nr_args;
	u8 arg_size[12];
};

struct bpf_tramp_link;

struct bpf_tramp_links {
	struct bpf_tramp_link *links[38];
	int nr_links;
};

struct bpf_link_ops;

struct bpf_link {
	atomic64_t refcnt;
	u32 id;
	enum bpf_link_type type;
	const struct bpf_link_ops *ops;
	struct bpf_prog *prog;
	struct work_struct work;
};

struct bpf_tramp_link {
	struct bpf_link link;
	struct hlist_node tramp_hlist;
	u64 cookie;
};

enum bpf_tramp_prog_type {
	BPF_TRAMP_FENTRY = 0,
	BPF_TRAMP_FEXIT = 1,
	BPF_TRAMP_MODIFY_RETURN = 2,
	BPF_TRAMP_MAX = 3,
	BPF_TRAMP_REPLACE = 4,
};

struct bpf_tramp_image {
	void *image;
	struct bpf_ksym ksym;
	struct percpu_ref pcref;
	void *ip_after_call;
	void *ip_epilogue;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
};

struct bpf_trampoline {
	struct hlist_node hlist;
	struct ftrace_ops *fops;
	struct mutex mutex;
	refcount_t refcnt;
	u32 flags;
	u64 key;
	struct {
		struct btf_func_model model;
		void *addr;
		bool ftrace_managed;
	} func;
	struct bpf_prog *extension_prog;
	struct hlist_head progs_hlist[3];
	int progs_cnt[3];
	struct bpf_tramp_image *cur_image;
	u64 selector;
	struct module *mod;
};

struct bpf_func_info_aux {
	u16 linkage;
	bool unreliable;
};

struct bpf_jit_poke_descriptor {
	void *tailcall_target;
	void *tailcall_bypass;
	void *bypass_addr;
	void *aux;
	union {
		struct {
			struct bpf_map *map;
			u32 key;
		} tail_call;
	};
	bool tailcall_target_stable;
	u8 adj_off;
	u16 reason;
	u32 insn_idx;
};

struct bpf_ctx_arg_aux {
	u32 offset;
	enum bpf_reg_type reg_type;
	u32 btf_id;
};

struct btf_mod_pair {
	struct btf *btf;
	struct module *module;
};

typedef struct {
	local64_t v;
} u64_stats_t;

struct bpf_prog_stats {
	u64_stats_t cnt;
	u64_stats_t nsecs;
	u64_stats_t misses;
	struct u64_stats_sync syncp;
	long: 64;
};

struct sock_fprog_kern {
	u16 len;
	struct sock_filter *filter;
};

struct bpf_link_ops {
	void (*release)(struct bpf_link *);
	void (*dealloc)(struct bpf_link *);
	int (*detach)(struct bpf_link *);
	int (*update_prog)(struct bpf_link *, struct bpf_prog *, struct bpf_prog *);
	void (*show_fdinfo)(const struct bpf_link *, struct seq_file *);
	int (*fill_link_info)(const struct bpf_link *, struct bpf_link_info *);
};

struct bpf_cgroup_storage;

struct bpf_prog_array_item {
	struct bpf_prog *prog;
	union {
		struct bpf_cgroup_storage *cgroup_storage[2];
		u64 bpf_cookie;
	};
};

struct bpf_prog_array {
	struct callback_head rcu;
	struct bpf_prog_array_item items[0];
};

struct bpf_tramp_run_ctx {
	struct bpf_run_ctx run_ctx;
	u64 bpf_cookie;
	struct bpf_run_ctx *saved_run_ctx;
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
			__u8 scm_io_uring: 1;
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
			__u8 scm_io_uring: 1;
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

enum bpf_text_poke_type {
	BPF_MOD_CALL = 0,
	BPF_MOD_JUMP = 1,
};

typedef short unsigned int __kernel_sa_family_t;

typedef __kernel_sa_family_t sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	char sa_data[14];
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

struct unix_table {
	spinlock_t *locks;
	struct hlist_head *buckets;
};

struct netns_unix {
	struct unix_table table;
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
	u32 tcp_challenge_timestamp;
	u32 tcp_challenge_count;
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

struct netns_nf {
	struct proc_dir_entry *proc_netfilter;
	const struct nf_logger *nf_loggers[13];
	struct ctl_table_header *nf_log_dir_header;
	struct nf_hook_entries *hooks_ipv4[5];
	struct nf_hook_entries *hooks_ipv6[5];
	struct nf_hook_entries *hooks_arp[3];
	struct nf_hook_entries *hooks_bridge[5];
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
	u8 ctnetlink_has_listener;
	bool ecache_dwork_pending;
	u8 sysctl_log_invalid;
	u8 sysctl_events;
	u8 sysctl_acct;
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

struct nf_flow_table_stat;

struct netns_ft {
	struct nf_flow_table_stat *stat;
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

struct netns_mctp {
	struct list_head routes;
	struct mutex bind_lock;
	struct hlist_head binds;
	spinlock_t keys_lock;
	struct hlist_head keys;
	unsigned int default_net;
	struct mutex neigh_lock;
	struct list_head neighbours;
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
	unsigned int sysctl_smcr_buf_type;
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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_ipv6 ipv6;
	struct netns_ieee802154_lowpan ieee802154_lowpan;
	struct netns_sctp sctp;
	struct netns_nf nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct netns_ft ft;
	struct sk_buff_head wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
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
	struct netns_mctp mctp;
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

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct scatterlist {
	long unsigned int page_link;
	unsigned int offset;
	unsigned int length;
	dma_addr_t dma_address;
	unsigned int dma_length;
	unsigned int dma_flags;
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

struct page_pool_recycle_stats {
	u64 cached;
	u64 cache_full;
	u64 ring;
	u64 ring_full;
	u64 released_refcnt;
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

struct skb_shared_hwtstamps {
	union {
		ktime_t hwtstamp;
		void *netdev_data;
	};
};

struct skb_ext {
	refcount_t refcnt;
	u8 offset[4];
	u8 chunks;
	long: 56;
	char data[0];
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
	long unsigned int mibs[13];
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

struct nf_flow_table_stat {
	unsigned int count_wq_add;
	unsigned int count_wq_del;
	unsigned int count_wq_stats;
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

struct tc_stats {
	__u64 bytes;
	__u32 packets;
	__u32 drops;
	__u32 overlimits;
	__u32 bps;
	__u32 pps;
	__u32 qlen;
	__u32 backlog;
};

struct tc_sizespec {
	unsigned char cell_log;
	unsigned char size_log;
	short int cell_align;
	int overhead;
	unsigned int linklayer;
	unsigned int mpu;
	unsigned int mtu;
	unsigned int tsize;
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

struct net_rate_estimator;

struct qdisc_skb_head {
	struct sk_buff *head;
	struct sk_buff *tail;
	__u32 qlen;
	spinlock_t lock;
};

struct gnet_stats_basic_sync {
	u64_stats_t bytes;
	u64_stats_t packets;
	struct u64_stats_sync syncp;
};

struct gnet_stats_queue {
	__u32 qlen;
	__u32 backlog;
	__u32 drops;
	__u32 requeues;
	__u32 overlimits;
};

struct Qdisc_ops;

struct qdisc_size_table;

struct Qdisc {
	int (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **);
	struct sk_buff * (*dequeue)(struct Qdisc *);
	unsigned int flags;
	u32 limit;
	const struct Qdisc_ops *ops;
	struct qdisc_size_table *stab;
	struct hlist_node hash;
	u32 handle;
	u32 parent;
	struct netdev_queue *dev_queue;
	struct net_rate_estimator *rate_est;
	struct gnet_stats_basic_sync *cpu_bstats;
	struct gnet_stats_queue *cpu_qstats;
	int pad;
	refcount_t refcnt;
	long: 64;
	long: 64;
	long: 64;
	struct sk_buff_head gso_skb;
	struct qdisc_skb_head q;
	struct gnet_stats_basic_sync bstats;
	struct gnet_stats_queue qstats;
	long unsigned int state;
	long unsigned int state2;
	struct Qdisc *next_sched;
	struct sk_buff_head skb_bad_txq;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t busylock;
	spinlock_t seqlock;
	struct callback_head rcu;
	netdevice_tracker dev_tracker;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long int privdata[0];
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

struct flowi6;

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

struct tcf_proto;

struct tcf_block;

struct mini_Qdisc {
	struct tcf_proto *filter_list;
	struct tcf_block *block;
	struct gnet_stats_basic_sync *cpu_bstats;
	struct gnet_stats_queue *cpu_qstats;
	long unsigned int rcu_state;
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

struct tcmsg {
	unsigned char tcm_family;
	unsigned char tcm__pad1;
	short unsigned int tcm__pad2;
	int tcm_ifindex;
	__u32 tcm_handle;
	__u32 tcm_parent;
	__u32 tcm_info;
};

struct gnet_dump {
	spinlock_t *lock;
	struct sk_buff *skb;
	struct nlattr *tail;
	int compat_tc_stats;
	int compat_xstats;
	int padattr;
	void *xstats;
	int xstats_len;
	struct tc_stats tc_stats;
};

struct netlink_range_validation {
	u64 min;
	u64 max;
};

struct netlink_range_validation_signed {
	s64 min;
	s64 max;
};

enum flow_action_hw_stats_bit {
	FLOW_ACTION_HW_STATS_IMMEDIATE_BIT = 0,
	FLOW_ACTION_HW_STATS_DELAYED_BIT = 1,
	FLOW_ACTION_HW_STATS_DISABLED_BIT = 2,
	FLOW_ACTION_HW_STATS_NUM_BITS = 3,
};

struct flow_block {
	struct list_head cb_list;
};

typedef int flow_setup_cb_t(enum tc_setup_type, void *, void *);

struct qdisc_size_table {
	struct callback_head rcu;
	struct list_head list;
	struct tc_sizespec szopts;
	int refcnt;
	u16 data[0];
};

struct Qdisc_class_ops;

struct Qdisc_ops {
	struct Qdisc_ops *next;
	const struct Qdisc_class_ops *cl_ops;
	char id[16];
	int priv_size;
	unsigned int static_flags;
	int (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **);
	struct sk_buff * (*dequeue)(struct Qdisc *);
	struct sk_buff * (*peek)(struct Qdisc *);
	int (*init)(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *);
	void (*reset)(struct Qdisc *);
	void (*destroy)(struct Qdisc *);
	int (*change)(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *);
	void (*attach)(struct Qdisc *);
	int (*change_tx_queue_len)(struct Qdisc *, unsigned int);
	void (*change_real_num_tx)(struct Qdisc *, unsigned int);
	int (*dump)(struct Qdisc *, struct sk_buff *);
	int (*dump_stats)(struct Qdisc *, struct gnet_dump *);
	void (*ingress_block_set)(struct Qdisc *, u32);
	void (*egress_block_set)(struct Qdisc *, u32);
	u32 (*ingress_block_get)(struct Qdisc *);
	u32 (*egress_block_get)(struct Qdisc *);
	struct module *owner;
};

struct qdisc_walker;

struct Qdisc_class_ops {
	unsigned int flags;
	struct netdev_queue * (*select_queue)(struct Qdisc *, struct tcmsg *);
	int (*graft)(struct Qdisc *, long unsigned int, struct Qdisc *, struct Qdisc **, struct netlink_ext_ack *);
	struct Qdisc * (*leaf)(struct Qdisc *, long unsigned int);
	void (*qlen_notify)(struct Qdisc *, long unsigned int);
	long unsigned int (*find)(struct Qdisc *, u32);
	int (*change)(struct Qdisc *, u32, u32, struct nlattr **, long unsigned int *, struct netlink_ext_ack *);
	int (*delete)(struct Qdisc *, long unsigned int, struct netlink_ext_ack *);
	void (*walk)(struct Qdisc *, struct qdisc_walker *);
	struct tcf_block * (*tcf_block)(struct Qdisc *, long unsigned int, struct netlink_ext_ack *);
	long unsigned int (*bind_tcf)(struct Qdisc *, long unsigned int, u32);
	void (*unbind_tcf)(struct Qdisc *, long unsigned int);
	int (*dump)(struct Qdisc *, long unsigned int, struct sk_buff *, struct tcmsg *);
	int (*dump_stats)(struct Qdisc *, long unsigned int, struct gnet_dump *);
};

struct tcf_chain;

struct tcf_block {
	struct mutex lock;
	struct list_head chain_list;
	u32 index;
	u32 classid;
	refcount_t refcnt;
	struct net *net;
	struct Qdisc *q;
	struct rw_semaphore cb_lock;
	struct flow_block flow_block;
	struct list_head owner_list;
	bool keep_dst;
	atomic_t offloadcnt;
	unsigned int nooffloaddevcnt;
	unsigned int lockeddevcnt;
	struct {
		struct tcf_chain *chain;
		struct list_head filter_chain_list;
	} chain0;
	struct callback_head rcu;
	struct hlist_head proto_destroy_ht[128];
	struct mutex proto_destroy_lock;
};

struct tcf_result;

struct tcf_proto_ops;

struct tcf_proto {
	struct tcf_proto *next;
	void *root;
	int (*classify)(struct sk_buff *, const struct tcf_proto *, struct tcf_result *);
	__be16 protocol;
	u32 prio;
	void *data;
	const struct tcf_proto_ops *ops;
	struct tcf_chain *chain;
	spinlock_t lock;
	bool deleting;
	refcount_t refcnt;
	struct callback_head rcu;
	struct hlist_node destroy_ht_node;
};

struct tcf_result {
	union {
		struct {
			long unsigned int class;
			u32 classid;
		};
		const struct tcf_proto *goto_tp;
		struct {
			bool ingress;
			struct gnet_stats_queue *qstats;
		};
	};
};

struct tcf_walker;

struct tcf_proto_ops {
	struct list_head head;
	char kind[16];
	int (*classify)(struct sk_buff *, const struct tcf_proto *, struct tcf_result *);
	int (*init)(struct tcf_proto *);
	void (*destroy)(struct tcf_proto *, bool, struct netlink_ext_ack *);
	void * (*get)(struct tcf_proto *, u32);
	void (*put)(struct tcf_proto *, void *);
	int (*change)(struct net *, struct sk_buff *, struct tcf_proto *, long unsigned int, u32, struct nlattr **, void **, u32, struct netlink_ext_ack *);
	int (*delete)(struct tcf_proto *, void *, bool *, bool, struct netlink_ext_ack *);
	bool (*delete_empty)(struct tcf_proto *);
	void (*walk)(struct tcf_proto *, struct tcf_walker *, bool);
	int (*reoffload)(struct tcf_proto *, bool, flow_setup_cb_t *, void *, struct netlink_ext_ack *);
	void (*hw_add)(struct tcf_proto *, void *);
	void (*hw_del)(struct tcf_proto *, void *);
	void (*bind_class)(void *, u32, long unsigned int, void *, long unsigned int);
	void * (*tmplt_create)(struct net *, struct tcf_chain *, struct nlattr **, struct netlink_ext_ack *);
	void (*tmplt_destroy)(void *);
	int (*dump)(struct net *, struct tcf_proto *, void *, struct sk_buff *, struct tcmsg *, bool);
	int (*terse_dump)(struct net *, struct tcf_proto *, void *, struct sk_buff *, struct tcmsg *, bool);
	int (*tmplt_dump)(struct sk_buff *, struct net *, void *);
	struct module *owner;
	int flags;
};

struct tcf_chain {
	struct mutex filter_chain_lock;
	struct tcf_proto *filter_chain;
	struct list_head list;
	struct tcf_block *block;
	u32 index;
	unsigned int refcnt;
	unsigned int action_refcnt;
	bool explicitly_created;
	bool flushing;
	const struct tcf_proto_ops *tmplt_ops;
	void *tmplt_priv;
	struct callback_head rcu;
};

struct bpf_binary_header {
	u32 size;
	int: 32;
	u8 image[0];
};

typedef void (*bpf_jit_fill_hole_t)(void *, unsigned int);

struct jit_ctx {
	const struct bpf_prog *prog;
	int idx;
	int epilogue_offset;
	int *offset;
	int exentry_idx;
	__le32 *image;
	u32 stack_size;
	int fpb_offset;
};

struct bpf_plt {
	u32 insn_ldr;
	u32 insn_br;
	u64 target;
};

struct arm64_jit_data {
	struct bpf_binary_header *header;
	u8 *image;
	struct jit_ctx ctx;
};

struct preempt_notifier;

struct preempt_ops {
	void (*sched_in)(struct preempt_notifier *, int);
	void (*sched_out)(struct preempt_notifier *, struct task_struct *);
};

struct preempt_notifier {
	struct hlist_node link;
	struct preempt_ops *ops;
};

typedef unsigned int xa_mark_t;

struct interval_tree_node {
	struct rb_node rb;
	long unsigned int start;
	long unsigned int last;
	long unsigned int __subtree_last;
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

struct platform_msi_priv_data;

struct msi_device_data {
	long unsigned int properties;
	struct platform_msi_priv_data *platform_data;
	struct mutex mutex;
	struct xarray __store;
	long unsigned int __iter_idx;
};

struct kvm_guest_debug_arch {
	__u64 dbg_bcr[16];
	__u64 dbg_bvr[16];
	__u64 dbg_wcr[16];
	__u64 dbg_wvr[16];
};

struct kvm_debug_exit_arch {
	__u32 hsr;
	__u32 hsr_high;
	__u64 far;
};

struct kvm_sync_regs {
	__u64 device_irq_level;
};

struct kvm_irq_level {
	union {
		__u32 irq;
		__s32 status;
	};
	__u32 level;
};

struct kvm_hyperv_exit {
	__u32 type;
	__u32 pad1;
	union {
		struct {
			__u32 msr;
			__u32 pad2;
			__u64 control;
			__u64 evt_page;
			__u64 msg_page;
		} synic;
		struct {
			__u64 input;
			__u64 result;
			__u64 params[2];
		} hcall;
		struct {
			__u32 msr;
			__u32 pad2;
			__u64 control;
			__u64 status;
			__u64 send_page;
			__u64 recv_page;
			__u64 pending_page;
		} syndbg;
	} u;
};

struct kvm_xen_exit {
	__u32 type;
	union {
		struct {
			__u32 longmode;
			__u32 cpl;
			__u64 input;
			__u64 result;
			__u64 params[6];
		} hcall;
	} u;
};

struct kvm_run {
	__u8 request_interrupt_window;
	__u8 immediate_exit;
	__u8 padding1[6];
	__u32 exit_reason;
	__u8 ready_for_interrupt_injection;
	__u8 if_flag;
	__u16 flags;
	__u64 cr8;
	__u64 apic_base;
	union {
		struct {
			__u64 hardware_exit_reason;
		} hw;
		struct {
			__u64 hardware_entry_failure_reason;
			__u32 cpu;
		} fail_entry;
		struct {
			__u32 exception;
			__u32 error_code;
		} ex;
		struct {
			__u8 direction;
			__u8 size;
			__u16 port;
			__u32 count;
			__u64 data_offset;
		} io;
		struct {
			struct kvm_debug_exit_arch arch;
		} debug;
		struct {
			__u64 phys_addr;
			__u8 data[8];
			__u32 len;
			__u8 is_write;
		} mmio;
		struct {
			__u64 nr;
			__u64 args[6];
			__u64 ret;
			__u32 longmode;
			__u32 pad;
		} hypercall;
		struct {
			__u64 rip;
			__u32 is_write;
			__u32 pad;
		} tpr_access;
		struct {
			__u8 icptcode;
			__u16 ipa;
			__u32 ipb;
		} s390_sieic;
		__u64 s390_reset_flags;
		struct {
			__u64 trans_exc_code;
			__u32 pgm_code;
		} s390_ucontrol;
		struct {
			__u32 dcrn;
			__u32 data;
			__u8 is_write;
		} dcr;
		struct {
			__u32 suberror;
			__u32 ndata;
			__u64 data[16];
		} internal;
		struct {
			__u32 suberror;
			__u32 ndata;
			__u64 flags;
			union {
				struct {
					__u8 insn_size;
					__u8 insn_bytes[15];
				};
			};
		} emulation_failure;
		struct {
			__u64 gprs[32];
		} osi;
		struct {
			__u64 nr;
			__u64 ret;
			__u64 args[9];
		} papr_hcall;
		struct {
			__u16 subchannel_id;
			__u16 subchannel_nr;
			__u32 io_int_parm;
			__u32 io_int_word;
			__u32 ipb;
			__u8 dequeued;
		} s390_tsch;
		struct {
			__u32 epr;
		} epr;
		struct {
			__u32 type;
			__u32 ndata;
			union {
				__u64 data[16];
			};
		} system_event;
		struct {
			__u64 addr;
			__u8 ar;
			__u8 reserved;
			__u8 fc;
			__u8 sel1;
			__u16 sel2;
		} s390_stsi;
		struct {
			__u8 vector;
		} eoi;
		struct kvm_hyperv_exit hyperv;
		struct {
			__u64 esr_iss;
			__u64 fault_ipa;
		} arm_nisv;
		struct {
			__u8 error;
			__u8 pad[7];
			__u32 reason;
			__u32 index;
			__u64 data;
		} msr;
		struct kvm_xen_exit xen;
		struct {
			long unsigned int extension_id;
			long unsigned int function_id;
			long unsigned int args[6];
			long unsigned int ret[2];
		} riscv_sbi;
		struct {
			long unsigned int csr_num;
			long unsigned int new_value;
			long unsigned int write_mask;
			long unsigned int ret_value;
		} riscv_csr;
		struct {
			__u32 flags;
		} notify;
		char padding[256];
	};
	__u64 kvm_valid_regs;
	__u64 kvm_dirty_regs;
	union {
		struct kvm_sync_regs regs;
		char padding[2048];
	} s;
};

struct kvm_coalesced_mmio {
	__u64 phys_addr;
	__u32 len;
	union {
		__u32 pad;
		__u32 pio;
	};
	__u8 data[8];
};

struct kvm_coalesced_mmio_ring {
	__u32 first;
	__u32 last;
	struct kvm_coalesced_mmio coalesced_mmio[0];
};

struct kvm_mp_state {
	__u32 mp_state;
};

struct kvm_device_attr {
	__u32 flags;
	__u32 group;
	__u64 attr;
	__u64 addr;
};

struct kvm_dirty_gfn {
	__u32 flags;
	__u32 slot;
	__u64 offset;
};

struct kvm_stats_desc {
	__u32 flags;
	__s16 exponent;
	__u16 size;
	__u32 offset;
	__u32 bucket_size;
	char name[0];
};

typedef u64 gpa_t;

typedef u64 gfn_t;

struct kvm_arch_memory_slot {};

struct kvm_memory_slot {
	struct hlist_node id_node[2];
	struct interval_tree_node hva_node[2];
	struct rb_node gfn_node[2];
	gfn_t base_gfn;
	long unsigned int npages;
	long unsigned int *dirty_bitmap;
	struct kvm_arch_memory_slot arch;
	long unsigned int userspace_addr;
	u32 flags;
	short int id;
	u16 as_id;
};

struct kvm_mmio_fragment {
	gpa_t gpa;
	void *data;
	unsigned int len;
};

struct kvm_vcpu;

struct kvm_cpu_context {
	struct user_pt_regs regs;
	u64 spsr_abt;
	u64 spsr_und;
	u64 spsr_irq;
	u64 spsr_fiq;
	struct user_fpsimd_state fp_regs;
	u64 sys_regs[123];
	struct kvm_vcpu *__hyp_running_vcpu;
};

struct kvm_vcpu_fault_info {
	u64 esr_el2;
	u64 far_el2;
	u64 hpfar_el2;
	u64 disr_el1;
};

struct vgic_v2_cpu_if {
	u32 vgic_hcr;
	u32 vgic_vmcr;
	u32 vgic_apr;
	u32 vgic_lr[64];
	unsigned int used_lrs;
};

struct its_vm;

struct its_vpe {
	struct page *vpt_page;
	struct its_vm *its_vm;
	atomic_t vlpi_count;
	int irq;
	irq_hw_number_t vpe_db_lpi;
	bool resident;
	bool ready;
	union {
		struct {
			int vpe_proxy_event;
			bool idai;
		};
		struct {
			struct fwnode_handle *fwnode;
			struct irq_domain *sgi_domain;
			struct {
				u8 priority;
				bool enabled;
				bool group;
			} sgi_config[16];
			atomic_t vmapp_count;
		};
	};
	raw_spinlock_t vpe_lock;
	u16 col_idx;
	u16 vpe_id;
	bool pending_last;
};

struct vgic_v3_cpu_if {
	u32 vgic_hcr;
	u32 vgic_vmcr;
	u32 vgic_sre;
	u32 vgic_ap0r[4];
	u32 vgic_ap1r[4];
	u64 vgic_lr[16];
	struct its_vpe its_vpe;
	unsigned int used_lrs;
};

enum vgic_irq_config {
	VGIC_CONFIG_EDGE = 0,
	VGIC_CONFIG_LEVEL = 1,
};

struct irq_ops;

struct vgic_irq {
	raw_spinlock_t irq_lock;
	struct list_head lpi_list;
	struct list_head ap_list;
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu *target_vcpu;
	u32 intid;
	bool line_level;
	bool pending_latch;
	bool active;
	bool enabled;
	bool hw;
	struct kref refcount;
	u32 hwintid;
	unsigned int host_irq;
	union {
		u8 targets;
		u32 mpidr;
	};
	u8 source;
	u8 active_source;
	u8 priority;
	u8 group;
	enum vgic_irq_config config;
	struct irq_ops *ops;
	void *owner;
};

enum iodev_type {
	IODEV_CPUIF = 0,
	IODEV_DIST = 1,
	IODEV_REDIST = 2,
	IODEV_ITS = 3,
};

struct kvm_io_device_ops;

struct kvm_io_device {
	const struct kvm_io_device_ops *ops;
};

struct vgic_its;

struct vgic_register_region;

struct vgic_io_device {
	gpa_t base_addr;
	union {
		struct kvm_vcpu *redist_vcpu;
		struct vgic_its *its;
	};
	const struct vgic_register_region *regions;
	enum iodev_type iodev_type;
	int nr_regions;
	struct kvm_io_device dev;
};

struct vgic_redist_region;

struct vgic_cpu {
	union {
		struct vgic_v2_cpu_if vgic_v2;
		struct vgic_v3_cpu_if vgic_v3;
	};
	struct vgic_irq private_irqs[32];
	raw_spinlock_t ap_list_lock;
	struct list_head ap_list_head;
	struct vgic_io_device rd_iodev;
	struct vgic_redist_region *rdreg;
	u32 rdreg_index;
	atomic_t syncr_busy;
	u64 pendbaser;
	atomic_t ctlr;
	u32 num_pri_bits;
	u32 num_id_bits;
};

struct arch_timer_context {
	struct kvm_vcpu *vcpu;
	struct kvm_irq_level irq;
	struct hrtimer hrtimer;
	bool loaded;
	u32 host_timer_irq;
	u32 host_timer_irq_flags;
};

struct arch_timer_cpu {
	struct arch_timer_context timers[2];
	struct hrtimer bg_timer;
	bool enabled;
};

struct kvm_pmu_events {
	u32 events_host;
	u32 events_guest;
};

struct kvm_pmc {
	u8 idx;
	struct perf_event *perf_event;
};

struct kvm_pmu {
	struct irq_work overflow_work;
	struct kvm_pmu_events events;
	struct kvm_pmc pmc[32];
	long unsigned int chained[1];
	int irq_num;
	bool created;
	bool irq_level;
};

struct kvm_mmu_memory_cache {
	int nobjs;
	gfp_t gfp_zero;
	gfp_t gfp_custom;
	struct kmem_cache *kmem_cache;
	int capacity;
	void **objects;
};

struct vcpu_reset_state {
	long unsigned int pc;
	long unsigned int r0;
	bool be;
	bool reset;
};

struct kvm_s2_mmu;

struct kvm_vcpu_arch {
	struct kvm_cpu_context ctxt;
	void *sve_state;
	unsigned int sve_max_vl;
	u64 svcr;
	struct kvm_s2_mmu *hw_mmu;
	u64 hcr_el2;
	u64 mdcr_el2;
	u64 cptr_el2;
	u64 mdcr_el2_host;
	struct kvm_vcpu_fault_info fault;
	enum {
		FP_STATE_FREE = 0,
		FP_STATE_HOST_OWNED = 1,
		FP_STATE_GUEST_OWNED = 2,
	} fp_state;
	u8 cflags;
	u8 iflags;
	u8 sflags;
	bool pause;
	struct kvm_guest_debug_arch *debug_ptr;
	struct kvm_guest_debug_arch vcpu_debug_state;
	struct kvm_guest_debug_arch external_debug_state;
	struct user_fpsimd_state *host_fpsimd_state;
	struct task_struct *parent_task;
	struct {
		struct kvm_guest_debug_arch regs;
		u64 pmscr_el1;
		u64 trfcr_el1;
	} host_debug_state;
	struct vgic_cpu vgic_cpu;
	struct arch_timer_cpu timer_cpu;
	struct kvm_pmu pmu;
	struct {
		u32 mdscr_el1;
	} guest_debug_preserved;
	struct kvm_mp_state mp_state;
	struct kvm_mmu_memory_cache mmu_page_cache;
	int target;
	long unsigned int features[1];
	u64 vsesr_el2;
	struct vcpu_reset_state reset_state;
	struct {
		u64 last_steal;
		gpa_t base;
	} steal;
};

struct kvm_vcpu_stat_generic {
	u64 halt_successful_poll;
	u64 halt_attempted_poll;
	u64 halt_poll_invalid;
	u64 halt_wakeup;
	u64 halt_poll_success_ns;
	u64 halt_poll_fail_ns;
	u64 halt_wait_ns;
	u64 halt_poll_success_hist[32];
	u64 halt_poll_fail_hist[32];
	u64 halt_wait_hist[32];
	u64 blocking;
};

struct kvm_vcpu_stat {
	struct kvm_vcpu_stat_generic generic;
	u64 hvc_exit_stat;
	u64 wfe_exit_stat;
	u64 wfi_exit_stat;
	u64 mmio_exit_user;
	u64 mmio_exit_kernel;
	u64 signal_exits;
	u64 exits;
};

struct kvm_dirty_ring {
	u32 dirty_index;
	u32 reset_index;
	u32 size;
	u32 soft_limit;
	struct kvm_dirty_gfn *dirty_gfns;
	int index;
};

struct kvm;

struct kvm_vcpu {
	struct kvm *kvm;
	struct preempt_notifier preempt_notifier;
	int cpu;
	int vcpu_id;
	int vcpu_idx;
	int ____srcu_idx;
	int mode;
	u64 requests;
	long unsigned int guest_debug;
	struct mutex mutex;
	struct kvm_run *run;
	struct rcuwait wait;
	struct pid *pid;
	int sigset_active;
	sigset_t sigset;
	unsigned int halt_poll_ns;
	bool valid_wakeup;
	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_cur_fragment;
	int mmio_nr_fragments;
	struct kvm_mmio_fragment mmio_fragments[2];
	struct {
		bool in_spin_loop;
		bool dy_eligible;
	} spin_loop;
	bool preempted;
	bool ready;
	long: 32;
	long: 64;
	struct kvm_vcpu_arch arch;
	struct kvm_vcpu_stat stat;
	char stats_id[48];
	struct kvm_dirty_ring dirty_ring;
	struct kvm_memory_slot *last_used_slot;
	u64 last_used_slot_gen;
	long: 64;
};

struct kvm_vm_stat_generic {
	u64 remote_tlb_flush;
	u64 remote_tlb_flush_requests;
};

struct kvm_io_device_ops {
	int (*read)(struct kvm_vcpu *, struct kvm_io_device *, gpa_t, int, void *);
	int (*write)(struct kvm_vcpu *, struct kvm_io_device *, gpa_t, int, const void *);
	void (*destructor)(struct kvm_io_device *);
};

struct its_vm {
	struct fwnode_handle *fwnode;
	struct irq_domain *domain;
	struct page *vprop_page;
	struct its_vpe **vpes;
	int nr_vpes;
	irq_hw_number_t db_lpi_base;
	long unsigned int *db_bitmap;
	int nr_db_lpis;
	u32 vlpi_count[16];
};

struct irq_ops {
	long unsigned int flags;
	bool (*get_input_level)(int);
};

struct kvm_device;

struct vgic_its {
	gpa_t vgic_its_base;
	bool enabled;
	struct vgic_io_device iodev;
	struct kvm_device *dev;
	u64 baser_device_table;
	u64 baser_coll_table;
	struct mutex cmd_lock;
	u64 cbaser;
	u32 creadr;
	u32 cwriter;
	u32 abi_rev;
	struct mutex its_lock;
	struct list_head device_list;
	struct list_head collection_list;
};

struct vgic_register_region {
	unsigned int reg_offset;
	unsigned int len;
	unsigned int bits_per_irq;
	unsigned int access_flags;
	union {
		long unsigned int (*read)(struct kvm_vcpu *, gpa_t, unsigned int);
		long unsigned int (*its_read)(struct kvm *, struct vgic_its *, gpa_t, unsigned int);
	};
	union {
		void (*write)(struct kvm_vcpu *, gpa_t, unsigned int, long unsigned int);
		void (*its_write)(struct kvm *, struct vgic_its *, gpa_t, unsigned int, long unsigned int);
	};
	long unsigned int (*uaccess_read)(struct kvm_vcpu *, gpa_t, unsigned int);
	union {
		int (*uaccess_write)(struct kvm_vcpu *, gpa_t, unsigned int, long unsigned int);
		int (*uaccess_its_write)(struct kvm *, struct vgic_its *, gpa_t, unsigned int, long unsigned int);
	};
};

struct kvm_device_ops;

struct kvm_device {
	const struct kvm_device_ops *ops;
	struct kvm *kvm;
	void *private;
	struct list_head vm_node;
};

struct vgic_redist_region {
	u32 index;
	gpa_t base;
	u32 count;
	u32 free_index;
	struct list_head list;
};

struct vgic_state_iter;

struct vgic_dist {
	bool in_kernel;
	bool ready;
	bool initialized;
	u32 vgic_model;
	u32 implementation_rev;
	bool v2_groups_user_writable;
	bool msis_require_devid;
	int nr_spis;
	gpa_t vgic_dist_base;
	union {
		gpa_t vgic_cpu_base;
		struct list_head rd_regions;
	};
	bool enabled;
	bool nassgireq;
	struct vgic_irq *spis;
	struct vgic_io_device dist_iodev;
	bool has_its;
	u64 propbaser;
	raw_spinlock_t lpi_list_lock;
	struct list_head lpi_list_head;
	int lpi_list_count;
	struct list_head lpi_translation_cache;
	struct vgic_state_iter *iter;
	struct its_vm its_vm;
};

struct kvm_vmid {
	atomic64_t id;
};

struct kvm_pgtable;

struct kvm_arch;

struct kvm_s2_mmu {
	struct kvm_vmid vmid;
	phys_addr_t pgd_phys;
	struct kvm_pgtable *pgt;
	int *last_vcpu_ran;
	struct kvm_arch *arch;
};

struct kvm_smccc_features {
	long unsigned int std_bmap;
	long unsigned int std_hyp_bmap;
	long unsigned int vendor_hyp_bmap;
};

struct arm_pmu;

struct kvm_arch {
	struct kvm_s2_mmu mmu;
	u64 vtcr;
	struct vgic_dist vgic;
	u32 psci_version;
	long unsigned int flags;
	long unsigned int *pmu_filter;
	struct arm_pmu *arm_pmu;
	cpumask_var_t supported_cpus;
	u8 pfr0_csv2;
	u8 pfr0_csv3;
	struct kvm_smccc_features smccc_feat;
};

struct kvm_vm_stat {
	struct kvm_vm_stat_generic generic;
};

struct kvm_io_range {
	gpa_t addr;
	int len;
	struct kvm_io_device *dev;
};

struct kvm_io_bus {
	int dev_count;
	int ioeventfd_count;
	struct kvm_io_range range[0];
};

struct kvm_memslots {
	u64 generation;
	atomic_long_t last_used_slot;
	struct rb_root_cached hva_tree;
	struct rb_root gfn_tree;
	struct hlist_head id_hash[128];
	int node_idx;
};

struct kvm_irq_routing_table;

struct kvm_stat_data;

struct kvm {
	rwlock_t mmu_lock;
	struct mutex slots_lock;
	struct mutex slots_arch_lock;
	struct mm_struct *mm;
	long unsigned int nr_memslot_pages;
	struct kvm_memslots __memslots[2];
	struct kvm_memslots *memslots[1];
	struct xarray vcpu_array;
	spinlock_t mn_invalidate_lock;
	long unsigned int mn_active_invalidate_count;
	struct rcuwait mn_memslots_update_rcuwait;
	spinlock_t gpc_lock;
	struct list_head gpc_list;
	atomic_t online_vcpus;
	int max_vcpus;
	int created_vcpus;
	int last_boosted_vcpu;
	struct list_head vm_list;
	struct mutex lock;
	struct kvm_io_bus *buses[4];
	struct {
		spinlock_t lock;
		struct list_head items;
		struct list_head resampler_list;
		struct mutex resampler_lock;
	} irqfds;
	struct list_head ioeventfds;
	struct kvm_vm_stat stat;
	struct kvm_arch arch;
	refcount_t users_count;
	struct kvm_coalesced_mmio_ring *coalesced_mmio_ring;
	spinlock_t ring_lock;
	struct list_head coalesced_zones;
	struct mutex irq_lock;
	struct kvm_irq_routing_table *irq_routing;
	struct hlist_head irq_ack_notifier_list;
	struct mmu_notifier mmu_notifier;
	long unsigned int mmu_invalidate_seq;
	long int mmu_invalidate_in_progress;
	long unsigned int mmu_invalidate_range_start;
	long unsigned int mmu_invalidate_range_end;
	struct list_head devices;
	u64 manual_dirty_log_protect;
	struct dentry *debugfs_dentry;
	struct kvm_stat_data **debugfs_stat_data;
	struct srcu_struct srcu;
	struct srcu_struct irq_srcu;
	pid_t userspace_pid;
	unsigned int max_halt_poll_ns;
	u32 dirty_ring_size;
	bool vm_bugged;
	bool vm_dead;
	char stats_id[48];
};

struct kvm_irq_routing_table {
	int chip[988];
	u32 nr_rt_entries;
	struct hlist_head map[0];
};

enum kvm_stat_kind {
	KVM_STAT_VM = 0,
	KVM_STAT_VCPU = 1,
};

struct _kvm_stats_desc;

struct kvm_stat_data {
	struct kvm *kvm;
	const struct _kvm_stats_desc *desc;
	enum kvm_stat_kind kind;
};

struct _kvm_stats_desc {
	struct kvm_stats_desc desc;
	char name[48];
};

struct kvm_device_ops {
	const char *name;
	int (*create)(struct kvm_device *, u32);
	void (*init)(struct kvm_device *);
	void (*destroy)(struct kvm_device *);
	void (*release)(struct kvm_device *);
	int (*set_attr)(struct kvm_device *, struct kvm_device_attr *);
	int (*get_attr)(struct kvm_device *, struct kvm_device_attr *);
	int (*has_attr)(struct kvm_device *, struct kvm_device_attr *);
	long int (*ioctl)(struct kvm_device *, unsigned int, long unsigned int);
	int (*mmap)(struct kvm_device *, struct vm_area_struct *);
};

struct arm_smccc_res {
	long unsigned int a0;
	long unsigned int a1;
	long unsigned int a2;
	long unsigned int a3;
};

enum __kvm_host_smccc_func {
	__KVM_HOST_SMCCC_FUNC___kvm_get_mdcr_el2 = 1,
	__KVM_HOST_SMCCC_FUNC___pkvm_init = 2,
	__KVM_HOST_SMCCC_FUNC___pkvm_create_private_mapping = 3,
	__KVM_HOST_SMCCC_FUNC___pkvm_cpu_set_vector = 4,
	__KVM_HOST_SMCCC_FUNC___kvm_enable_ssbs = 5,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_init_lrs = 6,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_get_gic_config = 7,
	__KVM_HOST_SMCCC_FUNC___pkvm_prot_finalize = 8,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp = 9,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp = 10,
	__KVM_HOST_SMCCC_FUNC___kvm_adjust_pc = 11,
	__KVM_HOST_SMCCC_FUNC___kvm_vcpu_run = 12,
	__KVM_HOST_SMCCC_FUNC___kvm_flush_vm_context = 13,
	__KVM_HOST_SMCCC_FUNC___kvm_tlb_flush_vmid_ipa = 14,
	__KVM_HOST_SMCCC_FUNC___kvm_tlb_flush_vmid = 15,
	__KVM_HOST_SMCCC_FUNC___kvm_flush_cpu_context = 16,
	__KVM_HOST_SMCCC_FUNC___kvm_timer_set_cntvoff = 17,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_read_vmcr = 18,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_write_vmcr = 19,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_save_aprs = 20,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_restore_aprs = 21,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_init_traps = 22,
};

enum kvm_bus {
	KVM_MMIO_BUS = 0,
	KVM_PIO_BUS = 1,
	KVM_VIRTIO_CCW_NOTIFY_BUS = 2,
	KVM_FAST_MMIO_BUS = 3,
	KVM_NR_BUSES = 4,
};

struct cyclecounter {
	u64 (*read)(const struct cyclecounter *);
	u64 mask;
	u32 mult;
	u32 shift;
};

struct timecounter {
	const struct cyclecounter *cc;
	u64 cycle_last;
	u64 nsec;
	u64 mask;
	u64 frac;
};

struct arch_timer_kvm_info {
	struct timecounter timecounter;
	int virtual_irq;
	int physical_irq;
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

struct arch_msi_msg_addr_lo {
	u32 address_lo;
};

typedef struct arch_msi_msg_addr_lo arch_msi_msg_addr_lo_t;

struct arch_msi_msg_addr_hi {
	u32 address_hi;