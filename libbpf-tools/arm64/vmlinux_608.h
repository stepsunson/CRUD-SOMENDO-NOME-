
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
};

typedef struct arch_msi_msg_addr_hi arch_msi_msg_addr_hi_t;

struct arch_msi_msg_data {
	u32 data;
};

typedef struct arch_msi_msg_data arch_msi_msg_data_t;

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

struct irq_affinity_desc;

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

enum {
	IRQD_TRIGGER_MASK = 15,
	IRQD_SETAFFINITY_PENDING = 256,
	IRQD_ACTIVATED = 512,
	IRQD_NO_BALANCING = 1024,
	IRQD_PER_CPU = 2048,
	IRQD_AFFINITY_SET = 4096,
	IRQD_LEVEL = 8192,
	IRQD_WAKEUP_STATE = 16384,
	IRQD_MOVE_PCNTXT = 32768,
	IRQD_IRQ_DISABLED = 65536,
	IRQD_IRQ_MASKED = 131072,
	IRQD_IRQ_INPROGRESS = 262144,
	IRQD_WAKEUP_ARMED = 524288,
	IRQD_FORWARDED_TO_VCPU = 1048576,
	IRQD_AFFINITY_MANAGED = 2097152,
	IRQD_IRQ_STARTED = 4194304,
	IRQD_MANAGED_SHUTDOWN = 8388608,
	IRQD_SINGLE_TARGET = 16777216,
	IRQD_DEFAULT_TRIGGER_SET = 33554432,
	IRQD_CAN_RESERVE = 67108864,
	IRQD_MSI_NOMASK_QUIRK = 134217728,
	IRQD_HANDLE_ENFORCE_IRQCTX = 268435456,
	IRQD_AFFINITY_ON_ACTIVATE = 536870912,
	IRQD_IRQ_ENABLED_ON_SUSPEND = 1073741824,
};

struct irq_affinity_desc {
	struct cpumask mask;
	unsigned int is_managed: 1;
};

enum vgic_type {
	VGIC_V2 = 0,
	VGIC_V3 = 1,
};

struct vgic_global {
	enum vgic_type type;
	phys_addr_t vcpu_base;
	void *vcpu_base_va;
	void *vcpu_hyp_va;
	void *vctrl_base;
	void *vctrl_hyp;
	int nr_lr;
	unsigned int maint_irq;
	int max_gic_vcpus;
	bool can_emulate_gicv2;
	bool has_gicv4;
	bool has_gicv4_1;
	bool no_hw_deactivation;
	struct static_key_false gicv3_cpuif;
	u32 ich_vtr_el2;
};

enum kvm_arch_timers {
	TIMER_PTIMER = 0,
	TIMER_VTIMER = 1,
	NR_KVM_TIMERS = 2,
};

enum kvm_arch_timer_regs {
	TIMER_REG_CNT = 0,
	TIMER_REG_CVAL = 1,
	TIMER_REG_TVAL = 2,
	TIMER_REG_CTL = 3,
};

struct timer_map {
	struct arch_timer_context *direct_vtimer;
	struct arch_timer_context *direct_ptimer;
	struct arch_timer_context *emul_ptimer;
};

enum {
	IRQCHIP_FWNODE_REAL = 0,
	IRQCHIP_FWNODE_NAMED = 1,
	IRQCHIP_FWNODE_NAMED_ID = 2,
};

struct kvm_arm_device_addr {
	__u64 id;
	__u64 addr;
};

enum kvm_device_type {
	KVM_DEV_TYPE_FSL_MPIC_20 = 1,
	KVM_DEV_TYPE_FSL_MPIC_42 = 2,
	KVM_DEV_TYPE_XICS = 3,
	KVM_DEV_TYPE_VFIO = 4,
	KVM_DEV_TYPE_ARM_VGIC_V2 = 5,
	KVM_DEV_TYPE_FLIC = 6,
	KVM_DEV_TYPE_ARM_VGIC_V3 = 7,
	KVM_DEV_TYPE_ARM_VGIC_ITS = 8,
	KVM_DEV_TYPE_XIVE = 9,
	KVM_DEV_TYPE_ARM_PV_TIME = 10,
	KVM_DEV_TYPE_MAX = 11,
};

typedef u64 kvm_pte_t;

enum kvm_pgtable_stage2_flags {
	KVM_PGTABLE_S2_NOFWB = 1,
	KVM_PGTABLE_S2_IDMAP = 2,
};

enum kvm_pgtable_prot {
	KVM_PGTABLE_PROT_X = 1,
	KVM_PGTABLE_PROT_W = 2,
	KVM_PGTABLE_PROT_R = 4,
	KVM_PGTABLE_PROT_DEVICE = 8,
	KVM_PGTABLE_PROT_SW0 = 0,
	KVM_PGTABLE_PROT_SW1 = 0,
	KVM_PGTABLE_PROT_SW2 = 0,
	KVM_PGTABLE_PROT_SW3 = 0,
};

typedef bool (*kvm_pgtable_force_pte_cb_t)(u64, u64, enum kvm_pgtable_prot);

struct kvm_pgtable_mm_ops;

struct kvm_pgtable {
	u32 ia_bits;
	u32 start_level;
	kvm_pte_t *pgd;
	struct kvm_pgtable_mm_ops *mm_ops;
	struct kvm_s2_mmu *mmu;
	enum kvm_pgtable_stage2_flags flags;
	kvm_pgtable_force_pte_cb_t force_pte_cb;
};

struct kvm_pgtable_mm_ops {
	void * (*zalloc_page)(void *);
	void * (*zalloc_pages_exact)(size_t);
	void (*free_pages_exact)(void *, size_t);
	void (*get_page)(void *);
	void (*put_page)(void *);
	int (*page_count)(void *);
	void * (*phys_to_virt)(phys_addr_t);
	phys_addr_t (*virt_to_phys)(void *);
	void (*dcache_clean_inval_poc)(void *, size_t);
	void (*icache_inval_pou)(void *, size_t);
};

struct vgic_reg_attr {
	struct kvm_vcpu *vcpu;
	gpa_t addr;
};

struct kvm_host_data {
	struct kvm_cpu_context host_ctxt;
};

struct kvm_exception_table_entry {
	int insn;
	int fixup;
};

typedef bool (*exit_handler_fn)(struct kvm_vcpu *, u64 *);

struct kvm_nvhe_init_params {
	long unsigned int mair_el2;
	long unsigned int tcr_el2;
	long unsigned int tpidr_el2;
	long unsigned int stack_hyp_va;
	long unsigned int stack_pa;
	phys_addr_t pgd_pa;
	long unsigned int hcr_el2;
	long unsigned int vttbr;
	long unsigned int vtcr;
};

union hyp_spinlock {
	u32 __val;
	struct {
		u16 owner;
		u16 next;
	};
};

typedef union hyp_spinlock hyp_spinlock_t;

struct host_kvm {
	struct kvm_arch arch;
	struct kvm_pgtable pgt;
	struct kvm_pgtable_mm_ops mm_ops;
	hyp_spinlock_t lock;
};

typedef __u64 __be64;

typedef void (*exitcall_t)();

struct crypto_alg;

struct crypto_tfm {
	u32 crt_flags;
	int node;
	void (*exit)(struct crypto_tfm *);
	struct crypto_alg *__crt_alg;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct crypto_template;

struct crypto_spawn;

struct crypto_instance {
	struct crypto_alg alg;
	struct crypto_template *tmpl;
	union {
		struct hlist_node list;
		struct crypto_spawn *spawns;
	};
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	void *__ctx[0];
};

struct crypto_spawn {
	struct list_head list;
	struct crypto_alg *alg;
	union {
		struct crypto_instance *inst;
		struct crypto_spawn *next;
	};
	const struct crypto_type *frontend;
	u32 mask;
	bool dead;
	bool registered;
};

struct rtattr;

struct crypto_template {
	struct list_head list;
	struct hlist_head instances;
	struct module *module;
	int (*create)(struct crypto_template *, struct rtattr **);
	char name[128];
};

struct crypto_shash;

struct shash_desc {
	struct crypto_shash *tfm;
	void *__ctx[0];
};

struct crypto_shash {
	unsigned int descsize;
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
	struct crypto_tfm base;
};

struct shash_alg {
	int (*init)(struct shash_desc *);
	int (*update)(struct shash_desc *, const u8 *, unsigned int);
	int (*final)(struct shash_desc *, u8 *);
	int (*finup)(struct shash_desc *, const u8 *, unsigned int, u8 *);
	int (*digest)(struct shash_desc *, const u8 *, unsigned int, u8 *);
	int (*export)(struct shash_desc *, void *);
	int (*import)(struct shash_desc *, const void *);
	int (*setkey)(struct crypto_shash *, const u8 *, unsigned int);
	int (*init_tfm)(struct crypto_shash *);
	void (*exit_tfm)(struct crypto_shash *);
	unsigned int descsize;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	unsigned int digestsize;
	unsigned int statesize;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct crypto_alg base;
};

struct sha256_state {
	u32 state[8];
	u64 count;
	u8 buf[64];
};

typedef void sha256_block_fn(struct sha256_state *, const u8 *, int);

struct cpu_feature {
	__u16 feature;
};

struct sha256_ce_state {
	struct sha256_state sst;
	u32 finalize;
};

struct poly1305_key {
	union {
		u32 r[5];
		u64 r64[3];
	};
};

struct poly1305_core_key {
	struct poly1305_key key;
	struct poly1305_key precomputed_s;
};

struct poly1305_state {
	union {
		u32 h[5];
		u64 h64[3];
	};
};

struct poly1305_desc_ctx {
	u8 buf[16];
	unsigned int buflen;
	short unsigned int rset;
	bool sset;
	u32 s[4];
	struct poly1305_state h;
	union {
		struct poly1305_key opaque_r[9];
		struct poly1305_core_key core_r;
	};
};

typedef phys_addr_t resource_size_t;

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
	IORES_DESC_CXL = 9,
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

enum {
	REGION_INTERSECTS = 0,
	REGION_DISJOINT = 1,
	REGION_MIXED = 2,
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

struct pseudo_fs_context {
	const struct super_operations *ops;
	const struct xattr_handler **xattr;
	const struct dentry_operations *dops;
	long unsigned int magic;
};

typedef void (*dr_release_t)(struct device *, void *);

typedef int (*dr_match_t)(struct device *, void *, void *);

struct resource_entry {
	struct list_head node;
	struct resource *res;
	resource_size_t offset;
	struct resource __res;
};

struct resource_constraint {
	resource_size_t min;
	resource_size_t max;
	resource_size_t align;
	resource_size_t (*alignf)(void *, const struct resource *, resource_size_t, resource_size_t);
	void *alignf_data;
};

enum {
	MAX_IORES_LEVEL = 5,
};

struct region_devres {
	struct resource *parent;
	resource_size_t start;
	resource_size_t n;
};

typedef unsigned int slab_flags_t;

struct nsset {
	unsigned int flags;
	struct nsproxy *nsproxy;
	struct fs_struct *fs;
	const struct cred *cred;
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

enum {
	PROC_ROOT_INO = 1,
	PROC_IPC_INIT_INO = 4026531839,
	PROC_UTS_INIT_INO = 4026531838,
	PROC_USER_INIT_INO = 4026531837,
	PROC_PID_INIT_INO = 4026531836,
	PROC_CGROUP_INIT_INO = 4026531835,
	PROC_TIME_INIT_INO = 4026531834,
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

typedef long unsigned int old_sigset_t;

struct sigqueue {
	struct list_head list;
	int flags;
	kernel_siginfo_t info;
	struct ucounts *ucounts;
};

enum siginfo_layout {
	SIL_KILL = 0,
	SIL_TIMER = 1,
	SIL_POLL = 2,
	SIL_FAULT = 3,
	SIL_FAULT_TRAPNO = 4,
	SIL_FAULT_MCEERR = 5,
	SIL_FAULT_BNDERR = 6,
	SIL_FAULT_PKUERR = 7,
	SIL_FAULT_PERF_EVENT = 8,
	SIL_CHLD = 9,
	SIL_RT = 10,
	SIL_SYS = 11,
};

struct multiprocess_signals {
	sigset_t signal;
	struct hlist_node node;
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

struct fd {
	struct file *file;
	unsigned int flags;
};

typedef u32 compat_size_t;

typedef s32 compat_clock_t;

typedef s32 compat_pid_t;

typedef s32 compat_timer_t;

typedef s32 compat_int_t;

typedef u32 compat_ulong_t;

typedef u32 compat_old_sigset_t;

typedef u32 __compat_uid32_t;

typedef u32 compat_sigset_word;

struct tty_buffer {
	union {
		struct tty_buffer *next;
		struct llist_node free;
	};
	int used;
	int size;
	int commit;
	int lookahead;
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
	void (*lookahead_buf)(struct tty_struct *, const unsigned char *, const unsigned char *, unsigned int);
	struct module *owner;
};

struct tty_ldisc {
	struct tty_ldisc_ops *ops;
	struct tty_struct *tty;
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
	void (*lookahead_buf)(struct tty_port *, const unsigned char *, const unsigned char *, unsigned int);
	void (*write_wakeup)(struct tty_port *);
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

struct core_vma_metadata;

struct coredump_params {
	const kernel_siginfo_t *siginfo;
	struct pt_regs *regs;
	struct file *file;
	long unsigned int limit;
	long unsigned int mm_flags;
	loff_t written;
	loff_t pos;
	loff_t to_skip;
	int vma_count;
	size_t vma_data_size;
	struct core_vma_metadata *vma_meta;
};

struct core_vma_metadata {
	long unsigned int start;
	long unsigned int end;
	long unsigned int flags;
	long unsigned int dump_size;
	long unsigned int pgoff;
	struct file *file;
};

struct ring_buffer_event {
	u32 type_len: 5;
	u32 time_delta: 27;
	u32 array[0];
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

struct compat_sigaltstack {
	compat_uptr_t ss_sp;
	int ss_flags;
	compat_size_t ss_size;
};

typedef struct compat_sigaltstack compat_stack_t;

typedef struct {
	compat_sigset_word sig[2];
} compat_sigset_t;

struct compat_sigaction {
	compat_uptr_t sa_handler;
	compat_ulong_t sa_flags;
	compat_uptr_t sa_restorer;
	compat_sigset_t sa_mask;
};

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

struct compat_old_sigaction {
	compat_uptr_t sa_handler;
	compat_old_sigset_t sa_mask;
	compat_ulong_t sa_flags;
	compat_uptr_t sa_restorer;
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
	CPUTIME_FORCEIDLE = 10,
	NR_STATS = 11,
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
	CGROUP_LSM_START = 23,
	CGROUP_LSM_END = 32,
	MAX_CGROUP_BPF_ATTACH_TYPE = 33,
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
	pids_cgrp_id = 10,
	misc_cgrp_id = 11,
	CGROUP_SUBSYS_COUNT = 12,
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

enum audit_ntp_type {
	AUDIT_NTP_OFFSET = 0,
	AUDIT_NTP_FREQ = 1,
	AUDIT_NTP_STATUS = 2,
	AUDIT_NTP_TAI = 3,
	AUDIT_NTP_TICK = 4,
	AUDIT_NTP_ADJUST = 5,
	AUDIT_NTP_NVALS = 6,
};

enum {
	TRACE_SIGNAL_DELIVERED = 0,
	TRACE_SIGNAL_IGNORED = 1,
	TRACE_SIGNAL_ALREADY_PENDING = 2,
	TRACE_SIGNAL_OVERFLOW_FAIL = 3,
	TRACE_SIGNAL_LOSE_INFO = 4,
};

struct trace_event_raw_signal_generate {
	struct trace_entry ent;
	int sig;
	int errno;
	int code;
	char comm[16];
	pid_t pid;
	int group;
	int result;
	char __data[0];
};

struct trace_event_raw_signal_deliver {
	struct trace_entry ent;
	int sig;
	int errno;
	int code;
	long unsigned int sa_handler;
	long unsigned int sa_flags;
	char __data[0];
};

struct trace_event_data_offsets_signal_generate {};

struct trace_event_data_offsets_signal_deliver {};

typedef void (*btf_trace_signal_generate)(void *, int, struct kernel_siginfo *, struct task_struct *, int, int);

typedef void (*btf_trace_signal_deliver)(void *, int, struct kernel_siginfo *, struct k_sigaction *);

enum sig_handler {
	HANDLER_CURRENT = 0,
	HANDLER_SIG_DFL = 1,
	HANDLER_EXIT = 2,
};

typedef u64 uint64_t;

typedef void (*rcu_callback_t)(struct callback_head *);

struct pin_cookie {};

enum {
	CSD_FLAG_LOCK = 1,
	IRQ_WORK_PENDING = 1,
	IRQ_WORK_BUSY = 2,
	IRQ_WORK_LAZY = 4,
	IRQ_WORK_HARD_IRQ = 8,
	IRQ_WORK_CLAIMED = 3,
	CSD_TYPE_ASYNC = 0,
	CSD_TYPE_SYNC = 16,
	CSD_TYPE_IRQ_WORK = 32,
	CSD_TYPE_TTWU = 48,
	CSD_FLAG_TYPE_MASK = 240,
};

typedef void (*smp_call_func_t)(void *);

struct __call_single_data {
	struct __call_single_node node;
	smp_call_func_t func;
	void *info;
};

typedef struct __call_single_data call_single_data_t;

typedef int (*task_call_f)(struct task_struct *, void *);

struct wait_bit_key {
	void *flags;
	int bit_nr;
	long unsigned int timeout;
};

struct wait_bit_queue_entry {
	struct wait_bit_key key;
	struct wait_queue_entry wq_entry;
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
	WORK_CPU_UNBOUND = 4096,
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

struct dl_bw {
	raw_spinlock_t lock;
	u64 bw;
	u64 total_bw;
};

struct cpudl_item;

struct cpudl {
	raw_spinlock_t lock;
	int size;
	cpumask_var_t free_cpus;
	struct cpudl_item *elements;
};

struct cpupri_vec {
	atomic_t count;
	cpumask_var_t mask;
};

struct cpupri {
	struct cpupri_vec pri_to_cpu[101];
	int *cpu_to_pri;
};

struct perf_domain;

struct root_domain {
	atomic_t refcount;
	atomic_t rto_count;
	struct callback_head rcu;
	cpumask_var_t span;
	cpumask_var_t online;
	int overload;
	int overutilized;
	cpumask_var_t dlo_mask;
	atomic_t dlo_count;
	struct dl_bw dl_bw;
	struct cpudl cpudl;
	u64 visit_gen;
	struct irq_work rto_push_work;
	raw_spinlock_t rto_lock;
	int rto_loop;
	int rto_cpu;
	atomic_t rto_loop_next;
	atomic_t rto_loop_start;
	cpumask_var_t rto_mask;
	struct cpupri cpupri;
	long unsigned int max_cpu_capacity;
	struct perf_domain *pd;
};

struct cfs_rq {
	struct load_weight load;
	unsigned int nr_running;
	unsigned int h_nr_running;
	unsigned int idle_nr_running;
	unsigned int idle_h_nr_running;
	u64 exec_clock;
	u64 min_vruntime;
	unsigned int forceidle_seq;
	u64 min_vruntime_fi;
	struct rb_root_cached tasks_timeline;
	struct sched_entity *curr;
	struct sched_entity *next;
	struct sched_entity *last;
	struct sched_entity *skip;
	unsigned int nr_spread_over;
	long: 32;
	long: 64;
	struct sched_avg avg;
	struct {
		raw_spinlock_t lock;
		int nr;
		long unsigned int load_avg;
		long unsigned int util_avg;
		long unsigned int runnable_avg;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	} removed;
	long unsigned int tg_load_avg_contrib;
	long int propagate;
	long int prop_runnable_sum;
	long unsigned int h_load;
	u64 last_h_load_update;
	struct sched_entity *h_load_next;
	struct rq *rq;
	int on_list;
	struct list_head leaf_cfs_rq_list;
	struct task_group *tg;
	int idle;
	int runtime_enabled;
	s64 runtime_remaining;
	u64 throttled_pelt_idle;
	u64 throttled_clock;
	u64 throttled_clock_pelt;
	u64 throttled_clock_pelt_time;
	int throttled;
	int throttle_count;
	struct list_head throttled_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct cfs_bandwidth {
	raw_spinlock_t lock;
	ktime_t period;
	u64 quota;
	u64 runtime;
	u64 burst;
	u64 runtime_snap;
	s64 hierarchical_quota;
	u8 idle;
	u8 period_active;
	u8 slack_started;
	struct hrtimer period_timer;
	struct hrtimer slack_timer;
	struct list_head throttled_cfs_rq;
	int nr_periods;
	int nr_throttled;
	int nr_burst;
	u64 throttled_time;
	u64 burst_time;
};

struct task_group {
	struct cgroup_subsys_state css;
	struct sched_entity **se;
	struct cfs_rq **cfs_rq;
	long unsigned int shares;
	int idle;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t load_avg;
	struct callback_head rcu;
	struct list_head list;
	struct task_group *parent;
	struct list_head siblings;
	struct list_head children;
	struct autogroup *autogroup;
	struct cfs_bandwidth cfs_bandwidth;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct io_ring_ctx;

struct io_wq;

struct io_uring_task {
	int cached_refs;
	const struct io_ring_ctx *last;
	struct io_wq *io_wq;
	struct file *registered_rings[16];
	struct xarray xa;
	struct wait_queue_head wait;
	atomic_t in_idle;
	atomic_t inflight_tracked;
	struct percpu_counter inflight;
	long: 64;
	long: 64;
	struct {
		struct llist_head task_list;
		struct callback_head task_work;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	};
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

struct blk_integrity_profile;

struct blk_integrity {
	const struct blk_integrity_profile *profile;
	unsigned char flags;
	unsigned char tuple_size;
	unsigned char interval_exp;
	unsigned char tag_size;
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

struct elevator_queue;

struct blk_queue_stats;

struct rq_qos;

struct blk_mq_ops;

struct blk_mq_ctx;

struct blk_crypto_profile;

struct blk_stat_callback;

struct blk_rq_stat;

struct blk_mq_tags;

struct blk_trace;

struct blk_flush_queue;

struct throtl_data;

struct blk_mq_tag_set;

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
	int node;
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
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct dentry *rqos_debugfs_dir;
	struct mutex debugfs_mutex;
	bool mq_sysfs_init_done;
	struct srcu_struct srcu[0];
};

struct cpu_topology {
	int thread_id;
	int core_id;
	int cluster_id;
	int package_id;
	cpumask_t thread_sibling;
	cpumask_t core_sibling;
	cpumask_t cluster_sibling;
	cpumask_t llc_sibling;
};

enum {
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_READY = 1,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED = 2,
	MEMBARRIER_STATE_GLOBAL_EXPEDITED_READY = 4,
	MEMBARRIER_STATE_GLOBAL_EXPEDITED = 8,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY = 16,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE = 32,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_RSEQ_READY = 64,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_RSEQ = 128,
};

struct autogroup {
	struct kref kref;
	struct task_group *tg;
	struct rw_semaphore lock;
	long unsigned int id;
	int nice;
};

typedef int __kernel_rwf_t;

struct io_comp_batch {
	struct request *req_list;
	bool need_ts;
	void (*complete)(struct io_comp_batch *);
};

struct trace_print_flags {
	long unsigned int mask;
	const char *name;
};

struct ubuf_info;

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
	struct ubuf_info *msg_ubuf;
	int (*sg_from_iter)(struct sock *, struct sk_buff *, struct iov_iter *, size_t);
};

struct mmpin {
	struct user_struct *user;
	unsigned int num_pg;
};

struct ubuf_info {
	void (*callback)(struct sk_buff *, struct ubuf_info *, bool);
	union {
		struct {
			long unsigned int desc;
			void *ctx;
		};
		struct {
			u32 id;
			u16 len;
			u16 zerocopy: 1;
			u32 bytelen;
		};
	};
	refcount_t refcnt;
	u8 flags;
	struct mmpin mmp;
};

struct sched_domain_attr {
	int relax_domain_level;
};

struct sched_domain_shared {
	atomic_t ref;
	atomic_t nr_busy_cpus;
	int has_idle_cores;
	int nr_idle_scan;
};

struct sched_group;

struct sched_domain {
	struct sched_domain *parent;
	struct sched_domain *child;
	struct sched_group *groups;
	long unsigned int min_interval;
	long unsigned int max_interval;
	unsigned int busy_factor;
	unsigned int imbalance_pct;
	unsigned int cache_nice_tries;
	unsigned int imb_numa_nr;
	int nohz_idle;
	int flags;
	int level;
	long unsigned int last_balance;
	unsigned int balance_interval;
	unsigned int nr_balance_failed;
	u64 max_newidle_lb_cost;
	long unsigned int last_decay_max_lb_cost;
	u64 avg_scan_cost;
	unsigned int lb_count[3];
	unsigned int lb_failed[3];
	unsigned int lb_balanced[3];
	unsigned int lb_imbalance[3];
	unsigned int lb_gained[3];
	unsigned int lb_hot_gained[3];
	unsigned int lb_nobusyg[3];
	unsigned int lb_nobusyq[3];
	unsigned int alb_count;
	unsigned int alb_failed;
	unsigned int alb_pushed;
	unsigned int sbe_count;
	unsigned int sbe_balanced;
	unsigned int sbe_pushed;
	unsigned int sbf_count;
	unsigned int sbf_balanced;
	unsigned int sbf_pushed;
	unsigned int ttwu_wake_remote;
	unsigned int ttwu_move_affine;
	unsigned int ttwu_move_balance;
	char *name;
	union {
		void *private;
		struct callback_head rcu;
	};
	struct sched_domain_shared *shared;
	unsigned int span_weight;
	long unsigned int span[0];
};

struct sched_group_capacity;

struct sched_group {
	struct sched_group *next;
	atomic_t ref;
	unsigned int group_weight;
	struct sched_group_capacity *sgc;
	int asym_prefer_cpu;
	int flags;
	long unsigned int cpumask[0];
};

struct sched_group_capacity {
	atomic_t ref;
	long unsigned int capacity;
	long unsigned int min_capacity;
	long unsigned int max_capacity;
	long unsigned int next_update;
	int imbalance;
	int id;
	long unsigned int cpumask[0];
};

struct kernel_cpustat {
	u64 cpustat[11];
};

struct kernel_stat {
	long unsigned int irqs_sum;
	unsigned int softirqs[10];
};

struct kthread_work;

typedef void (*kthread_work_func_t)(struct kthread_work *);

struct kthread_worker;

struct kthread_work {
	struct list_head node;
	kthread_work_func_t func;
	struct kthread_worker *worker;
	int canceling;
};

struct kthread_worker {
	unsigned int flags;
	raw_spinlock_t lock;
	struct list_head work_list;
	struct list_head delayed_work_list;
	struct task_struct *task;
	struct kthread_work *current_work;
};

enum {
	CFTYPE_ONLY_ON_ROOT = 1,
	CFTYPE_NOT_ON_ROOT = 2,
	CFTYPE_NS_DELEGATABLE = 4,
	CFTYPE_NO_PREFIX = 8,
	CFTYPE_WORLD_WRITABLE = 16,
	CFTYPE_DEBUG = 32,
	CFTYPE_PRESSURE = 64,
	__CFTYPE_ONLY_ON_DFL = 65536,
	__CFTYPE_NOT_ON_DFL = 131072,
};

enum hk_type {
	HK_TYPE_TIMER = 0,
	HK_TYPE_RCU = 1,
	HK_TYPE_MISC = 2,
	HK_TYPE_SCHED = 3,
	HK_TYPE_TICK = 4,
	HK_TYPE_DOMAIN = 5,
	HK_TYPE_WQ = 6,
	HK_TYPE_MANAGED_IRQ = 7,
	HK_TYPE_KTHREAD = 8,
	HK_TYPE_MAX = 9,
};

struct block_device_operations;

struct timer_rand_state;

struct disk_events;

struct cdrom_device_info;

struct badblocks;

struct blk_independent_access_ranges;

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
	struct bio_set bio_split;
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
	unsigned int nr_zones;
	unsigned int max_open_zones;
	unsigned int max_active_zones;
	long unsigned int *conv_zones_bitmap;
	long unsigned int *seq_zones_wlock;
	struct cdrom_device_info *cdi;
	int node_id;
	struct badblocks *bb;
	struct lockdep_map lockdep_map;
	u64 diskseq;
	struct blk_independent_access_ranges *ia_ranges;
};

struct partition_meta_info {
	char uuid[37];
	u8 volname[64];
};

enum req_op {
	REQ_OP_READ = 0,
	REQ_OP_WRITE = 1,
	REQ_OP_FLUSH = 2,
	REQ_OP_DISCARD = 3,
	REQ_OP_SECURE_ERASE = 5,
	REQ_OP_WRITE_ZEROES = 9,
	REQ_OP_ZONE_OPEN = 10,
	REQ_OP_ZONE_CLOSE = 11,
	REQ_OP_ZONE_FINISH = 12,
	REQ_OP_ZONE_APPEND = 13,
	REQ_OP_ZONE_RESET = 15,
	REQ_OP_ZONE_RESET_ALL = 17,
	REQ_OP_DRV_IN = 34,
	REQ_OP_DRV_OUT = 35,
	REQ_OP_LAST = 36,
};

struct blk_rq_stat {
	u64 mean;
	u64 min;
	u64 max;
	u32 nr_samples;
	u64 batch;
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
	int (*rw_page)(struct block_device *, sector_t, struct page *, enum req_op);
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
	enum blk_eh_timer_return (*timeout)(struct request *);
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
	FLOW_DISSECTOR_KEY_PPPOE = 29,
	FLOW_DISSECTOR_KEY_MAX = 30,
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
	LINUX_MIB_TLSDECRYPTRETRY = 11,
	LINUX_MIB_TLSRXNOPADVIOL = 12,
	__LINUX_MIB_TLSMAX = 13,
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

enum skb_ext_id {
	SKB_EXT_BRIDGE_NF = 0,
	SKB_EXT_SEC_PATH = 1,
	TC_SKB_EXT = 2,
	SKB_EXT_MPTCP = 3,
	SKB_EXT_NUM = 4,
};

struct wake_q_head {
	struct wake_q_node *first;
	struct wake_q_node **lastp;
};

struct sched_param {
	int sched_priority;
};

struct sched_attr {
	__u32 size;
	__u32 sched_policy;
	__u64 sched_flags;
	__s32 sched_nice;
	__u32 sched_priority;
	__u64 sched_runtime;
	__u64 sched_deadline;
	__u64 sched_period;
	__u32 sched_util_min;
	__u32 sched_util_max;
};

struct trace_event_raw_sched_kthread_stop {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	char __data[0];
};

struct trace_event_raw_sched_kthread_stop_ret {
	struct trace_entry ent;
	int ret;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_queue_work {
	struct trace_entry ent;
	void *work;
	void *function;
	void *worker;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_execute_start {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_execute_end {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_raw_sched_wakeup_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int target_cpu;
	char __data[0];
};

struct trace_event_raw_sched_switch {
	struct trace_entry ent;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long int prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
	char __data[0];
};

struct trace_event_raw_sched_migrate_task {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int orig_cpu;
	int dest_cpu;
	char __data[0];
};

struct trace_event_raw_sched_process_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};

struct trace_event_raw_sched_process_wait {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};

struct trace_event_raw_sched_process_fork {
	struct trace_entry ent;
	char parent_comm[16];
	pid_t parent_pid;
	char child_comm[16];
	pid_t child_pid;
	char __data[0];
};

struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	u32 __data_loc_filename;
	pid_t pid;
	pid_t old_pid;
	char __data[0];
};

struct trace_event_raw_sched_stat_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	u64 delay;
	char __data[0];
};

struct trace_event_raw_sched_stat_runtime {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	u64 runtime;
	u64 vruntime;
	char __data[0];
};

struct trace_event_raw_sched_pi_setprio {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int oldprio;
	int newprio;
	char __data[0];
};

struct trace_event_raw_sched_move_numa {
	struct trace_entry ent;
	pid_t pid;
	pid_t tgid;
	pid_t ngid;
	int src_cpu;
	int src_nid;
	int dst_cpu;
	int dst_nid;
	char __data[0];
};

struct trace_event_raw_sched_numa_pair_template {
	struct trace_entry ent;
	pid_t src_pid;
	pid_t src_tgid;
	pid_t src_ngid;
	int src_cpu;
	int src_nid;
	pid_t dst_pid;
	pid_t dst_tgid;
	pid_t dst_ngid;
	int dst_cpu;
	int dst_nid;
	char __data[0];
};

struct trace_event_raw_sched_wake_idle_without_ipi {
	struct trace_entry ent;
	int cpu;
	char __data[0];
};

struct trace_event_data_offsets_sched_kthread_stop {};

struct trace_event_data_offsets_sched_kthread_stop_ret {};

struct trace_event_data_offsets_sched_kthread_work_queue_work {};

struct trace_event_data_offsets_sched_kthread_work_execute_start {};

struct trace_event_data_offsets_sched_kthread_work_execute_end {};

struct trace_event_data_offsets_sched_wakeup_template {};

struct trace_event_data_offsets_sched_switch {};

struct trace_event_data_offsets_sched_migrate_task {};

struct trace_event_data_offsets_sched_process_template {};

struct trace_event_data_offsets_sched_process_wait {};

struct trace_event_data_offsets_sched_process_fork {};

struct trace_event_data_offsets_sched_process_exec {
	u32 filename;
};

struct trace_event_data_offsets_sched_stat_template {};

struct trace_event_data_offsets_sched_stat_runtime {};

struct trace_event_data_offsets_sched_pi_setprio {};

struct trace_event_data_offsets_sched_move_numa {};

struct trace_event_data_offsets_sched_numa_pair_template {};

struct trace_event_data_offsets_sched_wake_idle_without_ipi {};

typedef void (*btf_trace_sched_kthread_stop)(void *, struct task_struct *);

typedef void (*btf_trace_sched_kthread_stop_ret)(void *, int);

typedef void (*btf_trace_sched_kthread_work_queue_work)(void *, struct kthread_worker *, struct kthread_work *);

typedef void (*btf_trace_sched_kthread_work_execute_start)(void *, struct kthread_work *);

typedef void (*btf_trace_sched_kthread_work_execute_end)(void *, struct kthread_work *, kthread_work_func_t);

typedef void (*btf_trace_sched_waking)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wakeup)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wakeup_new)(void *, struct task_struct *);

typedef void (*btf_trace_sched_switch)(void *, bool, struct task_struct *, struct task_struct *, unsigned int);

typedef void (*btf_trace_sched_migrate_task)(void *, struct task_struct *, int);

typedef void (*btf_trace_sched_process_free)(void *, struct task_struct *);

typedef void (*btf_trace_sched_process_exit)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wait_task)(void *, struct task_struct *);

typedef void (*btf_trace_sched_process_wait)(void *, struct pid *);

typedef void (*btf_trace_sched_process_fork)(void *, struct task_struct *, struct task_struct *);

typedef void (*btf_trace_sched_process_exec)(void *, struct task_struct *, pid_t, struct linux_binprm *);

typedef void (*btf_trace_sched_stat_wait)(void *, struct task_struct *, u64);

typedef void (*btf_trace_sched_stat_sleep)(void *, struct task_struct *, u64);

typedef void (*btf_trace_sched_stat_iowait)(void *, struct task_struct *, u64);

typedef void (*btf_trace_sched_stat_blocked)(void *, struct task_struct *, u64);

typedef void (*btf_trace_sched_stat_runtime)(void *, struct task_struct *, u64, u64);

typedef void (*btf_trace_sched_pi_setprio)(void *, struct task_struct *, struct task_struct *);

typedef void (*btf_trace_sched_move_numa)(void *, struct task_struct *, int, int);

typedef void (*btf_trace_sched_stick_numa)(void *, struct task_struct *, int, struct task_struct *, int);

typedef void (*btf_trace_sched_swap_numa)(void *, struct task_struct *, int, struct task_struct *, int);

typedef void (*btf_trace_sched_wake_idle_without_ipi)(void *, int);

typedef void (*btf_trace_pelt_cfs_tp)(void *, struct cfs_rq *);

typedef void (*btf_trace_pelt_rt_tp)(void *, struct rq *);

struct rt_prio_array {
	long unsigned int bitmap[2];
	struct list_head queue[100];
};

struct rt_rq {
	struct rt_prio_array active;
	unsigned int rt_nr_running;
	unsigned int rr_nr_running;
	struct {
		int curr;
		int next;
	} highest_prio;
	unsigned int rt_nr_migratory;
	unsigned int rt_nr_total;
	int overloaded;
	struct plist_head pushable_tasks;
	int rt_queued;
	int rt_throttled;
	u64 rt_time;
	u64 rt_runtime;
	raw_spinlock_t rt_runtime_lock;
};

struct dl_rq {
	struct rb_root_cached root;
	unsigned int dl_nr_running;
	struct {
		u64 curr;
		u64 next;
	} earliest_dl;
	unsigned int dl_nr_migratory;
	int overloaded;
	struct rb_root_cached pushable_dl_tasks_root;
	u64 running_bw;
	u64 this_bw;
	u64 extra_bw;
	u64 bw_ratio;
};

struct cpu_stop_done;

struct cpu_stop_work {
	struct list_head list;
	cpu_stop_fn_t fn;
	long unsigned int caller;
	void *arg;
	struct cpu_stop_done *done;
};

struct cpuidle_state;

struct rq {
	raw_spinlock_t __lock;
	unsigned int nr_running;
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
	unsigned int numa_migrate_on;
	long unsigned int last_blocked_load_update_tick;
	unsigned int has_blocked_load;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	call_single_data_t nohz_csd;
	unsigned int nohz_tick_stopped;
	atomic_t nohz_flags;
	unsigned int ttwu_pending;
	u64 nr_switches;
	long: 64;
	struct cfs_rq cfs;
	struct rt_rq rt;
	struct dl_rq dl;
	struct list_head leaf_cfs_rq_list;
	struct list_head *tmp_alone_branch;
	unsigned int nr_uninterruptible;
	struct task_struct *curr;
	struct task_struct *idle;
	struct task_struct *stop;
	long unsigned int next_balance;
	struct mm_struct *prev_mm;
	unsigned int clock_update_flags;
	u64 clock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u64 clock_task;
	u64 clock_pelt;
	long unsigned int lost_idle_time;
	u64 clock_pelt_idle;
	u64 clock_idle;
	atomic_t nr_iowait;
	u64 last_seen_need_resched_ns;
	int ticks_without_resched;
	int membarrier_state;
	struct root_domain *rd;
	struct sched_domain *sd;
	long unsigned int cpu_capacity;
	long unsigned int cpu_capacity_orig;
	struct callback_head *balance_callback;
	unsigned char nohz_idle_balance;
	unsigned char idle_balance;
	long unsigned int misfit_task_load;
	int active_balance;
	int push_cpu;
	struct cpu_stop_work active_balance_work;
	int cpu;
	int online;
	struct list_head cfs_tasks;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_avg avg_rt;
	struct sched_avg avg_dl;
	struct sched_avg avg_irq;
	struct sched_avg avg_thermal;
	u64 idle_stamp;
	u64 avg_idle;
	long unsigned int wake_stamp;
	u64 wake_avg_idle;
	u64 max_idle_balance_cost;
	struct rcuwait hotplug_wait;
	u64 prev_irq_time;
	u64 prev_steal_time;
	u64 prev_steal_time_rq;
	long unsigned int calc_load_update;
	long int calc_load_active;
	long: 64;
	call_single_data_t hrtick_csd;
	struct hrtimer hrtick_timer;
	ktime_t hrtick_time;
	struct sched_info rq_sched_info;
	long long unsigned int rq_cpu_time;
	unsigned int yld_count;
	unsigned int sched_count;
	unsigned int sched_goidle;
	unsigned int ttwu_count;
	unsigned int ttwu_local;
	struct cpuidle_state *idle_state;
	unsigned int nr_pinned;
	unsigned int push_busy;
	struct cpu_stop_work push_work;
	struct rq *core;
	struct task_struct *core_pick;
	unsigned int core_enabled;
	unsigned int core_sched_seq;
	struct rb_root core_tree;
	unsigned int core_task_seq;
	unsigned int core_pick_seq;
	long unsigned int core_cookie;
	unsigned int core_forceidle_count;
	unsigned int core_forceidle_seq;
	unsigned int core_forceidle_occupation;
	u64 core_forceidle_start;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

typedef void (*btf_trace_pelt_dl_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_thermal_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_irq_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_se_tp)(void *, struct sched_entity *);

typedef void (*btf_trace_sched_cpu_capacity_tp)(void *, struct rq *);

typedef void (*btf_trace_sched_overutilized_tp)(void *, struct root_domain *, bool);

typedef void (*btf_trace_sched_util_est_cfs_tp)(void *, struct cfs_rq *);

typedef void (*btf_trace_sched_util_est_se_tp)(void *, struct sched_entity *);

typedef void (*btf_trace_sched_update_nr_running_tp)(void *, struct rq *, int);

struct cpudl_item {
	u64 dl;
	int cpu;
	int idx;
};

struct rt_bandwidth {
	raw_spinlock_t rt_runtime_lock;
	ktime_t rt_period;
	u64 rt_runtime;
	struct hrtimer rt_period_timer;
	unsigned int rt_period_active;
};

typedef int (*tg_visitor)(struct task_group *, void *);

struct perf_domain {
	struct em_perf_domain *em_pd;
	struct perf_domain *next;
	struct callback_head rcu;
};

struct rq_flags {
	long unsigned int flags;
	struct pin_cookie cookie;
	unsigned int clock_update_flags;
};

struct sched_entity_stats {
	struct sched_entity se;
	struct sched_statistics stats;
};

enum {
	__SCHED_FEAT_GENTLE_FAIR_SLEEPERS = 0,
	__SCHED_FEAT_START_DEBIT = 1,
	__SCHED_FEAT_NEXT_BUDDY = 2,
	__SCHED_FEAT_LAST_BUDDY = 3,
	__SCHED_FEAT_CACHE_HOT_BUDDY = 4,
	__SCHED_FEAT_WAKEUP_PREEMPTION = 5,
	__SCHED_FEAT_HRTICK = 6,
	__SCHED_FEAT_HRTICK_DL = 7,
	__SCHED_FEAT_DOUBLE_TICK = 8,
	__SCHED_FEAT_NONTASK_CAPACITY = 9,
	__SCHED_FEAT_TTWU_QUEUE = 10,
	__SCHED_FEAT_SIS_PROP = 11,
	__SCHED_FEAT_SIS_UTIL = 12,
	__SCHED_FEAT_WARN_DOUBLE_CLOCK = 13,
	__SCHED_FEAT_RT_PUSH_IPI = 14,
	__SCHED_FEAT_RT_RUNTIME_SHARE = 15,
	__SCHED_FEAT_LB_MIN = 16,
	__SCHED_FEAT_ATTACH_AGE_LOAD = 17,
	__SCHED_FEAT_WA_IDLE = 18,
	__SCHED_FEAT_WA_WEIGHT = 19,
	__SCHED_FEAT_WA_BIAS = 20,
	__SCHED_FEAT_UTIL_EST = 21,
	__SCHED_FEAT_UTIL_EST_FASTUP = 22,
	__SCHED_FEAT_LATENCY_WARN = 23,
	__SCHED_FEAT_ALT_PERIOD = 24,
	__SCHED_FEAT_BASE_SLICE = 25,
	__SCHED_FEAT_NR = 26,
};

struct irqtime {
	u64 total;
	u64 tick_delta;
	u64 irq_start_time;
	struct u64_stats_sync sync;
};

enum cpu_util_type {
	FREQUENCY_UTIL = 0,
	ENERGY_UTIL = 1,
};

enum task_work_notify_mode {
	TWA_NONE = 0,
	TWA_RESUME = 1,
	TWA_SIGNAL = 2,
	TWA_SIGNAL_NO_IPI = 3,
};

struct io_uring_sqe {
	__u8 opcode;
	__u8 flags;
	__u16 ioprio;
	__s32 fd;
	union {
		__u64 off;
		__u64 addr2;
		struct {
			__u32 cmd_op;
			__u32 __pad1;
		};
	};
	union {
		__u64 addr;
		__u64 splice_off_in;
	};
	__u32 len;
	union {
		__kernel_rwf_t rw_flags;
		__u32 fsync_flags;
		__u16 poll_events;
		__u32 poll32_events;
		__u32 sync_range_flags;
		__u32 msg_flags;
		__u32 timeout_flags;
		__u32 accept_flags;
		__u32 cancel_flags;
		__u32 open_flags;
		__u32 statx_flags;
		__u32 fadvise_advice;
		__u32 splice_flags;
		__u32 rename_flags;
		__u32 unlink_flags;
		__u32 hardlink_flags;
		__u32 xattr_flags;
		__u32 msg_ring_flags;
	};
	__u64 user_data;
	union {
		__u16 buf_index;
		__u16 buf_group;
	};
	__u16 personality;
	union {
		__s32 splice_fd_in;
		__u32 file_index;
		struct {
			__u16 addr_len;
			__u16 __pad3[1];
		};
	};
	union {
		struct {
			__u64 addr3;
			__u64 __pad2[1];
		};
		__u8 cmd[0];
	};
};

enum {
	IOSQE_FIXED_FILE_BIT = 0,
	IOSQE_IO_DRAIN_BIT = 1,
	IOSQE_IO_LINK_BIT = 2,
	IOSQE_IO_HARDLINK_BIT = 3,
	IOSQE_ASYNC_BIT = 4,
	IOSQE_BUFFER_SELECT_BIT = 5,
	IOSQE_CQE_SKIP_SUCCESS_BIT = 6,
};

enum io_uring_op {
	IORING_OP_NOP = 0,
	IORING_OP_READV = 1,
	IORING_OP_WRITEV = 2,
	IORING_OP_FSYNC = 3,
	IORING_OP_READ_FIXED = 4,
	IORING_OP_WRITE_FIXED = 5,
	IORING_OP_POLL_ADD = 6,
	IORING_OP_POLL_REMOVE = 7,
	IORING_OP_SYNC_FILE_RANGE = 8,
	IORING_OP_SENDMSG = 9,
	IORING_OP_RECVMSG = 10,
	IORING_OP_TIMEOUT = 11,
	IORING_OP_TIMEOUT_REMOVE = 12,
	IORING_OP_ACCEPT = 13,
	IORING_OP_ASYNC_CANCEL = 14,
	IORING_OP_LINK_TIMEOUT = 15,
	IORING_OP_CONNECT = 16,
	IORING_OP_FALLOCATE = 17,
	IORING_OP_OPENAT = 18,
	IORING_OP_CLOSE = 19,
	IORING_OP_FILES_UPDATE = 20,
	IORING_OP_STATX = 21,
	IORING_OP_READ = 22,
	IORING_OP_WRITE = 23,
	IORING_OP_FADVISE = 24,
	IORING_OP_MADVISE = 25,
	IORING_OP_SEND = 26,
	IORING_OP_RECV = 27,
	IORING_OP_OPENAT2 = 28,
	IORING_OP_EPOLL_CTL = 29,
	IORING_OP_SPLICE = 30,
	IORING_OP_PROVIDE_BUFFERS = 31,
	IORING_OP_REMOVE_BUFFERS = 32,
	IORING_OP_TEE = 33,
	IORING_OP_SHUTDOWN = 34,
	IORING_OP_RENAMEAT = 35,
	IORING_OP_UNLINKAT = 36,
	IORING_OP_MKDIRAT = 37,
	IORING_OP_SYMLINKAT = 38,
	IORING_OP_LINKAT = 39,
	IORING_OP_MSG_RING = 40,
	IORING_OP_FSETXATTR = 41,
	IORING_OP_SETXATTR = 42,
	IORING_OP_FGETXATTR = 43,
	IORING_OP_GETXATTR = 44,
	IORING_OP_SOCKET = 45,
	IORING_OP_URING_CMD = 46,
	IORING_OP_SEND_ZC = 47,
	IORING_OP_LAST = 48,
};

struct io_uring_cqe {
	__u64 user_data;
	__s32 res;
	__u32 flags;
	__u64 big_cqe[0];
};

enum {
	IORING_REGISTER_BUFFERS = 0,
	IORING_UNREGISTER_BUFFERS = 1,
	IORING_REGISTER_FILES = 2,
	IORING_UNREGISTER_FILES = 3,
	IORING_REGISTER_EVENTFD = 4,
	IORING_UNREGISTER_EVENTFD = 5,
	IORING_REGISTER_FILES_UPDATE = 6,
	IORING_REGISTER_EVENTFD_ASYNC = 7,
	IORING_REGISTER_PROBE = 8,
	IORING_REGISTER_PERSONALITY = 9,
	IORING_UNREGISTER_PERSONALITY = 10,
	IORING_REGISTER_RESTRICTIONS = 11,
	IORING_REGISTER_ENABLE_RINGS = 12,
	IORING_REGISTER_FILES2 = 13,
	IORING_REGISTER_FILES_UPDATE2 = 14,
	IORING_REGISTER_BUFFERS2 = 15,
	IORING_REGISTER_BUFFERS_UPDATE = 16,
	IORING_REGISTER_IOWQ_AFF = 17,
	IORING_UNREGISTER_IOWQ_AFF = 18,
	IORING_REGISTER_IOWQ_MAX_WORKERS = 19,
	IORING_REGISTER_RING_FDS = 20,
	IORING_UNREGISTER_RING_FDS = 21,
	IORING_REGISTER_PBUF_RING = 22,
	IORING_UNREGISTER_PBUF_RING = 23,
	IORING_REGISTER_SYNC_CANCEL = 24,
	IORING_REGISTER_FILE_ALLOC_RANGE = 25,
	IORING_REGISTER_LAST = 26,
};

struct io_wq_work_node {
	struct io_wq_work_node *next;
};

struct io_wq_work_list {
	struct io_wq_work_node *first;
	struct io_wq_work_node *last;
};

struct io_wq_work {
	struct io_wq_work_node list;
	unsigned int flags;
	int cancel_seq;
};

struct io_fixed_file {
	long unsigned int file_ptr;
};

struct io_file_table {
	struct io_fixed_file *files;
	long unsigned int *bitmap;
	unsigned int alloc_hint;
};

struct io_hash_bucket {
	spinlock_t lock;
	struct hlist_head list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct io_hash_table {
	struct io_hash_bucket *hbs;
	unsigned int hash_bits;
};

struct io_notif_slot;

struct io_kiocb;

struct io_submit_link {
	struct io_kiocb *head;
	struct io_kiocb *last;
};

struct io_submit_state {
	struct io_wq_work_node free_list;
	struct io_wq_work_list compl_reqs;
	struct io_submit_link link;
	bool plug_started;
	bool need_plug;
	short unsigned int submit_nr;
	struct blk_plug plug;
};

struct io_alloc_cache {
	struct hlist_head list;
	unsigned int nr_cached;
};

struct io_restriction {
	long unsigned int register_op[1];
	long unsigned int sqe_op[1];
	u8 sqe_flags_allowed;
	u8 sqe_flags_required;
	bool registered;
};

struct io_rings;

struct io_rsrc_node;

struct io_mapped_ubuf;

struct io_buffer_list;

struct io_sq_data;

struct io_ev_fd;

struct io_rsrc_data;

struct io_wq_hash;

struct io_ring_ctx {
	struct {
		struct percpu_ref refs;
		struct io_rings *rings;
		unsigned int flags;
		enum task_work_notify_mode notify_method;
		unsigned int compat: 1;
		unsigned int drain_next: 1;
		unsigned int restricted: 1;
		unsigned int off_timeout_used: 1;
		unsigned int drain_active: 1;
		unsigned int drain_disabled: 1;
		unsigned int has_evfd: 1;
		unsigned int syscall_iopoll: 1;
		long: 56;
		long: 64;
		long: 64;
		long: 64;
	};
	struct {
		struct mutex uring_lock;
		u32 *sq_array;
		struct io_uring_sqe *sq_sqes;
		unsigned int cached_sq_head;
		unsigned int sq_entries;
		struct io_rsrc_node *rsrc_node;
		int rsrc_cached_refs;
		atomic_t cancel_seq;
		struct io_file_table file_table;
		unsigned int nr_user_files;
		unsigned int nr_user_bufs;
		struct io_mapped_ubuf **user_bufs;
		struct io_notif_slot *notif_slots;
		unsigned int nr_notif_slots;
		struct io_submit_state submit_state;
		struct io_buffer_list *io_bl;
		struct xarray io_bl_xa;
		struct list_head io_buffers_cache;
		struct io_hash_table cancel_table_locked;
		struct list_head cq_overflow_list;
		struct io_alloc_cache apoll_cache;
		struct io_alloc_cache netmsg_cache;
	};
	struct io_wq_work_list locked_free_list;
	unsigned int locked_free_nr;
	const struct cred *sq_creds;
	struct io_sq_data *sq_data;
	struct wait_queue_head sqo_sq_wait;
	struct list_head sqd_list;
	long unsigned int check_cq;
	unsigned int file_alloc_start;
	unsigned int file_alloc_end;
	struct xarray personalities;
	u32 pers_next;
	long: 32;
	long: 64;
	struct {
		struct io_uring_cqe *cqe_cached;
		struct io_uring_cqe *cqe_sentinel;
		unsigned int cached_cq_tail;
		unsigned int cq_entries;
		struct io_ev_fd *io_ev_fd;
		struct wait_queue_head cq_wait;
		unsigned int cq_extra;
	};
	struct {
		spinlock_t completion_lock;
		struct io_wq_work_list iopoll_list;
		struct io_hash_table cancel_table;
		bool poll_multi_queue;
		struct list_head io_buffers_comp;
	};
	struct {
		spinlock_t timeout_lock;
		atomic_t cq_timeouts;
		struct list_head timeout_list;
		struct list_head ltimeout_list;
		unsigned int cq_last_tm_flush;
		long: 32;
		long: 64;
		long: 64;
	};
	struct io_restriction restrictions;
	struct task_struct *submitter_task;
	struct io_rsrc_node *rsrc_backup_node;
	struct io_mapped_ubuf *dummy_ubuf;
	struct io_rsrc_data *file_data;
	struct io_rsrc_data *buf_data;
	struct delayed_work rsrc_put_work;
	struct llist_head rsrc_put_llist;
	struct list_head rsrc_ref_list;
	spinlock_t rsrc_ref_lock;
	struct list_head io_buffers_pages;
	struct socket *ring_sock;
	struct io_wq_hash *hash_map;
	struct user_struct *user;
	struct mm_struct *mm_account;
	struct llist_head fallback_llist;
	struct delayed_work fallback_work;
	struct work_struct exit_work;
	struct list_head tctx_list;
	struct completion ref_comp;
	u32 iowq_limits[2];
	bool iowq_limits_set;
	struct list_head defer_list;
	unsigned int sq_thread_idle;
	unsigned int evfd_last_cq_tail;
};

struct io_uring {
	u32 head;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u32 tail;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct io_rings {
	struct io_uring sq;
	struct io_uring cq;
	u32 sq_ring_mask;
	u32 cq_ring_mask;
	u32 sq_ring_entries;
	u32 cq_ring_entries;
	u32 sq_dropped;
	atomic_t sq_flags;
	u32 cq_flags;
	u32 cq_overflow;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct io_uring_cqe cqes[0];
};

struct io_cmd_data {
	struct file *file;
	__u8 data[56];
};

struct io_cqe {
	__u64 user_data;
	__s32 res;
	union {
		__u32 flags;
		int fd;
	};
};

typedef void (*io_req_tw_func_t)(struct io_kiocb *, bool *);

struct io_task_work {
	struct llist_node node;
	io_req_tw_func_t func;
};

struct io_buffer;

struct async_poll;

struct io_kiocb {
	union {
		struct file *file;
		struct io_cmd_data cmd;
	};
	u8 opcode;
	u8 iopoll_completed;
	u16 buf_index;
	unsigned int flags;
	struct io_cqe cqe;
	struct io_ring_ctx *ctx;
	struct task_struct *task;
	struct io_rsrc_node *rsrc_node;
	union {
		struct io_mapped_ubuf *imu;
		struct io_buffer *kbuf;
		struct io_buffer_list *buf_list;
	};
	union {
		struct io_wq_work_node comp_list;
		__poll_t apoll_events;
	};
	atomic_t refs;
	atomic_t poll_refs;
	struct io_task_work io_task_work;
	union {
		struct hlist_node hash_node;
		struct {
			u64 extra1;
			u64 extra2;
		};
	};
	struct async_poll *apoll;
	void *async_data;
	struct io_kiocb *link;
	const struct cred *creds;
	struct io_wq_work work;
};

struct io_ev_fd {
	struct eventfd_ctx *cq_ev_fd;
	unsigned int eventfd_async: 1;
	struct callback_head rcu;
};

struct io_wq_hash {
	refcount_t refs;
	long unsigned int map;
	struct wait_queue_head wait;
};

enum {
	REQ_F_FIXED_FILE_BIT = 0,
	REQ_F_IO_DRAIN_BIT = 1,
	REQ_F_LINK_BIT = 2,
	REQ_F_HARDLINK_BIT = 3,
	REQ_F_FORCE_ASYNC_BIT = 4,
	REQ_F_BUFFER_SELECT_BIT = 5,
	REQ_F_CQE_SKIP_BIT = 6,
	REQ_F_FAIL_BIT = 8,
	REQ_F_INFLIGHT_BIT = 9,
	REQ_F_CUR_POS_BIT = 10,
	REQ_F_NOWAIT_BIT = 11,
	REQ_F_LINK_TIMEOUT_BIT = 12,
	REQ_F_NEED_CLEANUP_BIT = 13,
	REQ_F_POLLED_BIT = 14,
	REQ_F_BUFFER_SELECTED_BIT = 15,
	REQ_F_BUFFER_RING_BIT = 16,
	REQ_F_REISSUE_BIT = 17,
	REQ_F_CREDS_BIT = 18,
	REQ_F_REFCOUNT_BIT = 19,
	REQ_F_ARM_LTIMEOUT_BIT = 20,
	REQ_F_ASYNC_DATA_BIT = 21,
	REQ_F_SKIP_LINK_CQES_BIT = 22,
	REQ_F_SINGLE_POLL_BIT = 23,
	REQ_F_DOUBLE_POLL_BIT = 24,
	REQ_F_PARTIAL_IO_BIT = 25,
	REQ_F_CQE32_INIT_BIT = 26,
	REQ_F_APOLL_MULTISHOT_BIT = 27,
	REQ_F_CLEAR_POLLIN_BIT = 28,
	REQ_F_HASH_LOCKED_BIT = 29,
	REQ_F_SUPPORT_NOWAIT_BIT = 30,
	REQ_F_ISREG_BIT = 31,
	__REQ_F_LAST_BIT = 32,
};

struct set_affinity_pending;

struct migration_arg {
	struct task_struct *task;
	int dest_cpu;
	struct set_affinity_pending *pending;
};

struct set_affinity_pending {
	refcount_t refs;
	unsigned int stop_pending;
	struct completion done;
	struct cpu_stop_work stop_work;
	struct migration_arg arg;
};

struct migration_swap_arg {
	struct task_struct *src_task;
	struct task_struct *dst_task;
	int src_cpu;
	int dst_cpu;
};

struct tick_work {
	int cpu;
	atomic_t state;
	struct delayed_work work;
};

enum {
	preempt_dynamic_undefined = 4294967295,
	preempt_dynamic_none = 0,
	preempt_dynamic_voluntary = 1,
	preempt_dynamic_full = 2,
};

struct cfs_schedulable_data {
	struct task_group *tg;
	u64 period;
	u64 quota;
};

enum {
	cpuset = 0,
	possible = 1,
	fail = 2,
};

enum {
	IRQ_TYPE_NONE = 0,
	IRQ_TYPE_EDGE_RISING = 1,
	IRQ_TYPE_EDGE_FALLING = 2,
	IRQ_TYPE_EDGE_BOTH = 3,
	IRQ_TYPE_LEVEL_HIGH = 4,
	IRQ_TYPE_LEVEL_LOW = 8,
	IRQ_TYPE_LEVEL_MASK = 12,
	IRQ_TYPE_SENSE_MASK = 15,
	IRQ_TYPE_DEFAULT = 15,
	IRQ_TYPE_PROBE = 16,
	IRQ_LEVEL = 256,
	IRQ_PER_CPU = 512,
	IRQ_NOPROBE = 1024,
	IRQ_NOREQUEST = 2048,
	IRQ_NOAUTOEN = 4096,
	IRQ_NO_BALANCING = 8192,
	IRQ_MOVE_PCNTXT = 16384,
	IRQ_NESTED_THREAD = 32768,
	IRQ_NOTHREAD = 65536,
	IRQ_PER_CPU_DEVID = 131072,
	IRQ_IS_POLLED = 262144,
	IRQ_DISABLE_UNLAZY = 524288,
	IRQ_HIDDEN = 1048576,
	IRQ_NO_DEBUG = 2097152,
};

enum {
	IRQTF_RUNTHREAD = 0,
	IRQTF_WARNED = 1,
	IRQTF_AFFINITY = 2,
	IRQTF_FORCED_THREAD = 3,
	IRQTF_READY = 4,
};

enum {
	IRQS_AUTODETECT = 1,
	IRQS_SPURIOUS_DISABLED = 2,
	IRQS_POLL_INPROGRESS = 8,
	IRQS_ONESHOT = 32,
	IRQS_REPLAY = 64,
	IRQS_WAITING = 128,
	IRQS_PENDING = 512,
	IRQS_SUSPENDED = 2048,
	IRQS_TIMINGS = 4096,
	IRQS_NMI = 8192,
};

enum {
	_IRQ_DEFAULT_INIT_FLAGS = 0,
	_IRQ_PER_CPU = 512,
	_IRQ_LEVEL = 256,
	_IRQ_NOPROBE = 1024,
	_IRQ_NOREQUEST = 2048,
	_IRQ_NOTHREAD = 65536,
	_IRQ_NOAUTOEN = 4096,
	_IRQ_MOVE_PCNTXT = 16384,
	_IRQ_NO_BALANCING = 8192,
	_IRQ_NESTED_THREAD = 32768,
	_IRQ_PER_CPU_DEVID = 131072,
	_IRQ_IS_POLLED = 262144,
	_IRQ_DISABLE_UNLAZY = 524288,
	_IRQ_HIDDEN = 1048576,
	_IRQ_NO_DEBUG = 2097152,
	_IRQF_MODIFY_MASK = 2096911,
};

struct irq_devres {
	unsigned int irq;
	void *dev_id;
};

struct irq_desc_devres {
	unsigned int from;
	unsigned int cnt;
};

struct irq_generic_chip_devres {
	struct irq_chip_generic *gc;
	u32 msk;
	unsigned int clr;
	unsigned int set;
};

typedef void (*swap_func_t)(void *, void *, int);

struct irq_affinity {
	unsigned int pre_vectors;
	unsigned int post_vectors;
	unsigned int nr_sets;
	unsigned int set_size[4];
	void (*calc_sets)(struct irq_affinity *, unsigned int);
	void *priv;
};

struct node_vectors {
	unsigned int id;
	union {
		unsigned int nvectors;
		unsigned int ncpus;
	};
};

enum {
	GP_IDLE = 0,
	GP_ENTER = 1,
	GP_PASSED = 2,
	GP_EXIT = 3,
	GP_REPLAY = 4,
};

struct rcu_cblist {
	struct callback_head *head;
	struct callback_head **tail;
	long int len;
};

struct io_tlb_area;

struct io_tlb_slot;

struct io_tlb_mem {
	phys_addr_t start;
	phys_addr_t end;
	void *vaddr;
	long unsigned int nslabs;
	long unsigned int used;
	struct dentry *debugfs;
	bool late_alloc;
	bool force_bounce;
	bool for_alloc;
	unsigned int nareas;
	unsigned int area_nslabs;
	struct io_tlb_area *areas;
	struct io_tlb_slot *slots;
};

struct sg_table {
	struct scatterlist *sgl;
	unsigned int nents;
	unsigned int orig_nents;
};

struct dma_sgt_handle {
	struct sg_table sgt;
	struct page **pages;
};

struct dma_devres {
	size_t size;
	void *vaddr;
	dma_addr_t dma_handle;
	long unsigned int attrs;
};

typedef struct {
	seqcount_t seqcount;
} seqcount_latch_t;

struct latch_tree_root {
	seqcount_latch_t seq;
	struct rb_root tree[2];
};

struct latch_tree_ops {
	bool (*less)(struct latch_tree_node *, struct latch_tree_node *);
	int (*comp)(void *, struct latch_tree_node *);
};

struct mod_tree_root {
	struct latch_tree_root root;
	long unsigned int addr_min;
	long unsigned int addr_max;
};

struct __va_list {
	void *__stack;
	void *__gr_top;
	void *__vr_top;
	int __gr_offs;
	int __vr_offs;
};

typedef struct __va_list va_list;

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

enum tick_device_mode {
	TICKDEV_MODE_PERIODIC = 0,
	TICKDEV_MODE_ONESHOT = 1,
};

struct tick_device {
	struct clock_event_device *evtdev;
	enum tick_device_mode mode;
};

enum tick_nohz_mode {
	NOHZ_MODE_INACTIVE = 0,
	NOHZ_MODE_LOWRES = 1,
	NOHZ_MODE_HIGHRES = 2,
};

struct tick_sched {
	struct hrtimer sched_timer;
	long unsigned int check_clocks;
	enum tick_nohz_mode nohz_mode;
	unsigned int inidle: 1;
	unsigned int tick_stopped: 1;
	unsigned int idle_active: 1;
	unsigned int do_timer_last: 1;
	unsigned int got_idle_tick: 1;
	ktime_t last_tick;
	ktime_t next_tick;
	long unsigned int idle_jiffies;
	long unsigned int idle_calls;
	long unsigned int idle_sleeps;
	ktime_t idle_entrytime;
	ktime_t idle_waketime;
	ktime_t idle_exittime;
	ktime_t idle_sleeptime;
	ktime_t iowait_sleeptime;
	long unsigned int last_jiffies;
	u64 timer_expires;
	u64 timer_expires_base;
	u64 next_timer;
	ktime_t idle_expires;
	atomic_t tick_dep_mask;
	long unsigned int last_tick_jiffies;
	unsigned int stalled_jiffies;
};

struct timer_list_iter {
	int cpu;
	bool second_pass;
	u64 now;
};

struct __kernel_old_timeval {
	__kernel_long_t tv_sec;
	__kernel_long_t tv_usec;
};

struct __kernel_old_itimerval {
	struct __kernel_old_timeval it_interval;
	struct __kernel_old_timeval it_value;
};

struct itimerspec64 {
	struct timespec64 it_interval;
	struct timespec64 it_value;
};

struct old_timeval32 {
	old_time32_t tv_sec;
	s32 tv_usec;
};

struct old_itimerval32 {
	struct old_timeval32 it_interval;
	struct old_timeval32 it_value;
};

struct hrtimer_sleeper {
	struct hrtimer timer;
	struct task_struct *task;
};

struct rt_mutex_base;

struct ww_acquire_ctx;

struct rt_mutex_waiter {
	struct rb_node tree_entry;
	struct rb_node pi_tree_entry;
	struct task_struct *task;
	struct rt_mutex_base *lock;
	unsigned int wake_state;
	int prio;
	u64 deadline;
	struct ww_acquire_ctx *ww_ctx;
};

struct robust_list {
	struct robust_list *next;
};

struct robust_list_head {
	struct robust_list list;
	long int futex_offset;
	struct robust_list *list_op_pending;
};

struct rt_mutex_base {
	raw_spinlock_t wait_lock;
	struct rb_root_cached waiters;
	struct task_struct *owner;
};

union futex_key {
	struct {
		u64 i_seq;
		long unsigned int pgoff;
		unsigned int offset;
	} shared;
	struct {
		union {
			struct mm_struct *mm;
			u64 __tmp;
		};
		long unsigned int address;
		unsigned int offset;
	} private;
	struct {
		u64 ptr;
		long unsigned int word;
		unsigned int offset;
	} both;
};

struct futex_pi_state {
	struct list_head list;
	struct rt_mutex_base pi_mutex;
	struct task_struct *owner;
	refcount_t refcount;
	union futex_key key;
};

enum {
	FUTEX_STATE_OK = 0,
	FUTEX_STATE_EXITING = 1,
	FUTEX_STATE_DEAD = 2,
};

struct futex_hash_bucket {
	atomic_t waiters;
	spinlock_t lock;
	struct plist_head chain;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct futex_q {
	struct plist_node list;
	struct task_struct *task;
	spinlock_t *lock_ptr;
	union futex_key key;
	struct futex_pi_state *pi_state;
	struct rt_mutex_waiter *rt_waiter;
	union futex_key *requeue_pi_key;
	u32 bitset;
	atomic_t requeue_state;
};

enum futex_access {
	FUTEX_READ = 0,
	FUTEX_WRITE = 1,
};

struct elf64_phdr {
	Elf64_Word p_type;
	Elf64_Word p_flags;
	Elf64_Off p_offset;
	Elf64_Addr p_vaddr;
	Elf64_Addr p_paddr;
	Elf64_Xword p_filesz;
	Elf64_Xword p_memsz;
	Elf64_Xword p_align;
};

typedef struct elf64_phdr Elf64_Phdr;

typedef u32 note_buf_t[106];

struct crash_mem_range {
	u64 start;
	u64 end;
};

struct crash_mem {
	unsigned int max_nr_ranges;
	unsigned int nr_ranges;
	struct crash_mem_range ranges[0];
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

enum kernel_read_file_id {
	READING_UNKNOWN = 0,
	READING_FIRMWARE = 1,
	READING_MODULE = 2,
	READING_KEXEC_IMAGE = 3,
	READING_KEXEC_INITRAMFS = 4,
	READING_POLICY = 5,
	READING_X509_CERTIFICATE = 6,
	READING_MAX_ID = 7,
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

enum hash_algo {
	HASH_ALGO_MD4 = 0,
	HASH_ALGO_MD5 = 1,
	HASH_ALGO_SHA1 = 2,
	HASH_ALGO_RIPE_MD_160 = 3,
	HASH_ALGO_SHA256 = 4,
	HASH_ALGO_SHA384 = 5,
	HASH_ALGO_SHA512 = 6,
	HASH_ALGO_SHA224 = 7,
	HASH_ALGO_RIPE_MD_128 = 8,
	HASH_ALGO_RIPE_MD_256 = 9,
	HASH_ALGO_RIPE_MD_320 = 10,
	HASH_ALGO_WP_256 = 11,
	HASH_ALGO_WP_384 = 12,
	HASH_ALGO_WP_512 = 13,
	HASH_ALGO_TGR_128 = 14,
	HASH_ALGO_TGR_160 = 15,
	HASH_ALGO_TGR_192 = 16,
	HASH_ALGO_SM3_256 = 17,
	HASH_ALGO_STREEBOG_256 = 18,
	HASH_ALGO_STREEBOG_512 = 19,
	HASH_ALGO__LAST = 20,
};

struct kexec_sha_region {
	long unsigned int start;
	long unsigned int len;
};

enum {
	CSS_NO_REF = 1,
	CSS_ONLINE = 2,
	CSS_RELEASED = 4,
	CSS_VISIBLE = 8,
	CSS_DYING = 16,
};

enum {
	CGRP_NOTIFY_ON_RELEASE = 0,
	CGRP_CPUSET_CLONE_CHILDREN = 1,
	CGRP_FREEZE = 2,
	CGRP_FROZEN = 3,
	CGRP_KILL = 4,
};

struct cgroup_taskset {
	struct list_head src_csets;
	struct list_head dst_csets;
	int nr_tasks;
	int ssid;
	struct list_head *csets;
	struct css_set *cur_cset;
	struct task_struct *cur_task;
};

struct css_task_iter {
	struct cgroup_subsys *ss;
	unsigned int flags;
	struct list_head *cset_pos;
	struct list_head *cset_head;
	struct list_head *tcset_pos;
	struct list_head *tcset_head;
	struct list_head *task_pos;
	struct list_head *cur_tasks_head;
	struct css_set *cur_cset;
	struct css_set *cur_dcset;
	struct task_struct *cur_task;
	struct list_head iters_node;
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

struct fs_struct {
	int users;
	spinlock_t lock;
	seqcount_spinlock_t seq;
	int umask;
	int in_exec;
	struct path root;
	struct path pwd;
};

struct kernel_pkey_query {
	__u32 supported_ops;
	__u32 key_size;
	__u16 max_data_size;
	__u16 max_sig_size;
	__u16 max_enc_size;
	__u16 max_dec_size;
};

enum kernel_pkey_operation {
	kernel_pkey_encrypt = 0,
	kernel_pkey_decrypt = 1,
	kernel_pkey_sign = 2,
	kernel_pkey_verify = 3,
};

struct kernel_pkey_params {
	struct key *key;
	const char *encoding;
	const char *hash_algo;
	char *info;
	__u32 in_len;
	union {
		__u32 out_len;
		__u32 in2_len;
	};
	enum kernel_pkey_operation op: 8;
};

struct key_preparsed_payload {
	const char *orig_description;
	char *description;
	union key_payload payload;
	const void *data;
	size_t datalen;
	size_t quotalen;
	time64_t expiry;
};

struct key_match_data {
	bool (*cmp)(const struct key *, const struct key_match_data *);
	const void *raw_data;
	void *preparsed;
	unsigned int lookup_type;
};

struct idmap_key {
	bool map_up;
	u32 id;
	u32 count;
};

typedef int __kernel_mqd_t;

typedef struct {
	int val[2];
} __kernel_fsid_t;

typedef __kernel_mqd_t mqd_t;

enum audit_state {
	AUDIT_STATE_DISABLED = 0,
	AUDIT_STATE_BUILD = 1,
	AUDIT_STATE_RECORD = 2,
};

struct audit_cap_data {
	kernel_cap_t permitted;
	kernel_cap_t inheritable;
	union {
		unsigned int fE;
		kernel_cap_t effective;
	};
	kernel_cap_t ambient;
	kuid_t rootid;
};

struct audit_names {
	struct list_head list;
	struct filename *name;
	int name_len;
	bool hidden;
	long unsigned int ino;
	dev_t dev;
	umode_t mode;
	kuid_t uid;
	kgid_t gid;
	dev_t rdev;
	u32 osid;
	struct audit_cap_data fcap;
	unsigned int fcap_ver;
	unsigned char type;
	bool should_free;
};

struct mq_attr {
	__kernel_long_t mq_flags;
	__kernel_long_t mq_maxmsg;
	__kernel_long_t mq_msgsize;
	__kernel_long_t mq_curmsgs;
	__kernel_long_t __reserved[4];
};

struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};

struct audit_ntp_val {
	long long int oldval;
	long long int newval;
};

struct audit_ntp_data {
	struct audit_ntp_val vals[6];
};

struct audit_proctitle {
	int len;
	char *value;
};

struct audit_aux_data;

struct __kernel_sockaddr_storage;

struct audit_tree_refs;

struct audit_context {
	int dummy;
	enum {
		AUDIT_CTX_UNUSED = 0,
		AUDIT_CTX_SYSCALL = 1,
		AUDIT_CTX_URING = 2,
	} context;
	enum audit_state state;
	enum audit_state current_state;
	unsigned int serial;
	int major;
	int uring_op;
	struct timespec64 ctime;
	long unsigned int argv[4];
	long int return_code;
	u64 prio;
	int return_valid;
	struct audit_names preallocated_names[5];
	int name_count;
	struct list_head names_list;
	char *filterkey;
	struct path pwd;
	struct audit_aux_data *aux;
	struct audit_aux_data *aux_pids;
	struct __kernel_sockaddr_storage *sockaddr;
	size_t sockaddr_len;
	pid_t pid;
	pid_t ppid;
	kuid_t uid;
	kuid_t euid;
	kuid_t suid;
	kuid_t fsuid;
	kgid_t gid;
	kgid_t egid;
	kgid_t sgid;
	kgid_t fsgid;
	long unsigned int personality;
	int arch;
	pid_t target_pid;
	kuid_t target_auid;
	kuid_t target_uid;
	unsigned int target_sessionid;
	u32 target_sid;
	char target_comm[16];
	struct audit_tree_refs *trees;
	struct audit_tree_refs *first_trees;
	struct list_head killed_trees;
	int tree_count;
	int type;
	union {
		struct {
			int nargs;
			long int args[6];
		} socketcall;
		struct {
			kuid_t uid;
			kgid_t gid;
			umode_t mode;
			u32 osid;
			int has_perm;
			uid_t perm_uid;
			gid_t perm_gid;
			umode_t perm_mode;
			long unsigned int qbytes;
		} ipc;
		struct {
			mqd_t mqdes;
			struct mq_attr mqstat;
		} mq_getsetattr;
		struct {
			mqd_t mqdes;
			int sigev_signo;
		} mq_notify;
		struct {
			mqd_t mqdes;
			size_t msg_len;
			unsigned int msg_prio;
			struct timespec64 abs_timeout;
		} mq_sendrecv;
		struct {
			int oflag;
			umode_t mode;
			struct mq_attr attr;
		} mq_open;
		struct {
			pid_t pid;
			struct audit_cap_data cap;
		} capset;
		struct {
			int fd;
			int flags;
		} mmap;
		struct open_how openat2;
		struct {
			int argc;
		} execve;
		struct {
			char *name;
		} module;
		struct {
			struct audit_ntp_data ntp_data;
			struct timespec64 tk_injoffset;
		} time;
	};
	int fds[2];
	struct audit_proctitle proctitle;
};

typedef struct fsnotify_mark_connector *fsnotify_connp_t;

struct fsnotify_mark_connector {
	spinlock_t lock;
	short unsigned int type;
	short unsigned int flags;
	__kernel_fsid_t fsid;
	union {
		fsnotify_connp_t *obj;
		struct fsnotify_mark_connector *destroy_next;
	};
	struct hlist_head list;
};

enum {
	Audit_equal = 0,
	Audit_not_equal = 1,
	Audit_bitmask = 2,
	Audit_bittest = 3,
	Audit_lt = 4,
	Audit_gt = 5,
	Audit_le = 6,
	Audit_ge = 7,
	Audit_bad = 8,
};

struct audit_field;

struct audit_watch;

struct audit_tree;

struct audit_fsnotify_mark;

struct audit_krule {
	u32 pflags;
	u32 flags;
	u32 listnr;
	u32 action;
	u32 mask[64];
	u32 buflen;
	u32 field_count;
	char *filterkey;
	struct audit_field *fields;
	struct audit_field *arch_f;
	struct audit_field *inode_f;
	struct audit_watch *watch;
	struct audit_tree *tree;
	struct audit_fsnotify_mark *exe;
	struct list_head rlist;
	struct list_head list;
	u64 prio;
};

struct audit_field {
	u32 type;
	union {
		u32 val;
		kuid_t uid;
		kgid_t gid;
		struct {
			char *lsm_str;
			void *lsm_rule;
		};
	};
	u32 op;
};

struct audit_parent;

struct audit_watch {
	refcount_t count;
	dev_t dev;
	char *path;
	long unsigned int ino;
	struct audit_parent *parent;
	struct list_head wlist;
	struct list_head rules;
};

struct __kernel_sockaddr_storage {
	union {
		struct {
			__kernel_sa_family_t ss_family;
			char __data[126];
		};
		void *__align;
	};
};

struct fsnotify_group;

struct fsnotify_iter_info;

struct fsnotify_mark;

struct fsnotify_event;

struct fsnotify_ops {
	int (*handle_event)(struct fsnotify_group *, u32, const void *, int, struct inode *, const struct qstr *, u32, struct fsnotify_iter_info *);
	int (*handle_inode_event)(struct fsnotify_mark *, u32, struct inode *, struct inode *, const struct qstr *, u32);
	void (*free_group_priv)(struct fsnotify_group *);
	void (*freeing_mark)(struct fsnotify_mark *, struct fsnotify_group *);
	void (*free_event)(struct fsnotify_group *, struct fsnotify_event *);
	void (*free_mark)(struct fsnotify_mark *);
};

struct inotify_group_private_data {
	spinlock_t idr_lock;
	struct idr idr;
	struct ucounts *ucounts;
};

struct fanotify_group_private_data {
	struct hlist_head *merge_hash;
	struct list_head access_list;
	wait_queue_head_t access_waitq;
	int flags;
	int f_flags;
	struct ucounts *ucounts;
	mempool_t error_events_pool;
};

struct fsnotify_group {
	const struct fsnotify_ops *ops;
	refcount_t refcnt;
	spinlock_t notification_lock;
	struct list_head notification_list;
	wait_queue_head_t notification_waitq;
	unsigned int q_len;
	unsigned int max_events;
	unsigned int priority;
	bool shutdown;
	int flags;
	unsigned int owner_flags;
	struct mutex mark_mutex;
	atomic_t user_waits;
	struct list_head marks_list;
	struct fasync_struct *fsn_fa;
	struct fsnotify_event *overflow_event;
	struct mem_cgroup *memcg;
	union {
		void *private;
		struct inotify_group_private_data inotify_data;
		struct fanotify_group_private_data fanotify_data;
	};
};

struct fsnotify_iter_info {
	struct fsnotify_mark *marks[5];
	struct fsnotify_group *current_group;
	unsigned int report_mask;
	int srcu_idx;
};

struct fsnotify_mark {
	__u32 mask;
	refcount_t refcnt;
	struct fsnotify_group *group;
	struct list_head g_list;
	spinlock_t lock;
	struct hlist_node obj_list;
	struct fsnotify_mark_connector *connector;
	__u32 ignore_mask;
	unsigned int flags;
};

struct fsnotify_event {
	struct list_head list;
};

enum fsnotify_obj_type {
	FSNOTIFY_OBJ_TYPE_ANY = 4294967295,
	FSNOTIFY_OBJ_TYPE_INODE = 0,
	FSNOTIFY_OBJ_TYPE_VFSMOUNT = 1,
	FSNOTIFY_OBJ_TYPE_SB = 2,
	FSNOTIFY_OBJ_TYPE_COUNT = 3,
	FSNOTIFY_OBJ_TYPE_DETACHED = 3,
};

struct audit_entry {
	struct list_head list;
	struct callback_head rcu;
	struct audit_krule rule;
};

struct audit_parent {
	struct list_head watches;
	struct fsnotify_mark mark;
};

struct audit_buffer;

struct ftrace_hash {
	long unsigned int size_bits;
	struct hlist_head *buckets;
	long unsigned int count;
	long unsigned int flags;
	struct callback_head rcu;
};

struct prog_entry;

struct event_filter {
	struct prog_entry *prog;
	char *filter_string;
};

struct trace_array_cpu;

struct array_buffer {
	struct trace_array *tr;
	struct trace_buffer *buffer;
	struct trace_array_cpu *data;
	u64 time_start;
	int cpu;
};

struct trace_pid_list;

struct trace_options;

struct cond_snapshot;

struct trace_func_repeats;

struct trace_array {
	struct list_head list;
	char *name;
	struct array_buffer array_buffer;
	struct array_buffer max_buffer;
	bool allocated_snapshot;
	long unsigned int max_latency;
	struct dentry *d_max_latency;
	struct work_struct fsnotify_work;
	struct irq_work fsnotify_irqwork;
	struct trace_pid_list *filtered_pids;
	struct trace_pid_list *filtered_no_pids;
	arch_spinlock_t max_lock;
	int buffer_disabled;
	int sys_refcount_enter;
	int sys_refcount_exit;
	struct trace_event_file *enter_syscall_files[451];
	struct trace_event_file *exit_syscall_files[451];
	int stop_count;
	int clock_id;
	int nr_topts;
	bool clear_trace;
	int buffer_percent;
	unsigned int n_err_log_entries;
	struct tracer *current_trace;
	unsigned int trace_flags;
	unsigned char trace_flags_index[32];
	unsigned int flags;
	raw_spinlock_t start_lock;
	struct list_head err_log;
	struct dentry *dir;
	struct dentry *options;
	struct dentry *percpu_dir;
	struct dentry *event_dir;
	struct trace_options *topts;
	struct list_head systems;
	struct list_head events;
	struct trace_event_file *trace_marker_file;
	cpumask_var_t tracing_cpumask;
	int ref;
	int trace_ref;
	struct ftrace_ops *ops;
	struct trace_pid_list *function_pids;
	struct trace_pid_list *function_no_pids;
	struct list_head func_probes;
	struct list_head mod_trace;
	struct list_head mod_notrace;
	int function_enabled;
	int no_filter_buffering_ref;
	struct list_head hist_vars;
	struct cond_snapshot *cond_snapshot;
	struct trace_func_repeats *last_func_repeats;
};

struct tracer_flags;

struct tracer {
	const char *name;
	int (*init)(struct trace_array *);
	void (*reset)(struct trace_array *);
	void (*start)(struct trace_array *);
	void (*stop)(struct trace_array *);
	int (*update_thresh)(struct trace_array *);
	void (*open)(struct trace_iterator *);
	void (*pipe_open)(struct trace_iterator *);
	void (*close)(struct trace_iterator *);
	void (*pipe_close)(struct trace_iterator *);
	ssize_t (*read)(struct trace_iterator *, struct file *, char *, size_t, loff_t *);
	ssize_t (*splice_read)(struct trace_iterator *, struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*print_header)(struct seq_file *);
	enum print_line_t (*print_line)(struct trace_iterator *);
	int (*set_flag)(struct trace_array *, u32, u32, int);
	int (*flag_changed)(struct trace_array *, u32, int);
	struct tracer *next;
	struct tracer_flags *flags;
	int enabled;
	bool print_max;
	bool allow_instances;
	bool use_max_tr;
	bool noboot;
};

struct event_subsystem;

struct trace_subsystem_dir {
	struct list_head list;
	struct event_subsystem *subsystem;
	struct trace_array *tr;
	struct dentry *entry;
	int ref_count;
	int nr_events;
};

union lower_chunk {
	union lower_chunk *next;
	long unsigned int data[256];
};

union upper_chunk {
	union upper_chunk *next;
	union lower_chunk *data[256];
};

struct trace_pid_list {
	raw_spinlock_t lock;
	struct irq_work refill_irqwork;
	union upper_chunk *upper[256];
	union upper_chunk *upper_list;
	union lower_chunk *lower_list;
	int free_upper_chunks;
	int free_lower_chunks;
};

struct trace_array_cpu {
	atomic_t disabled;
	void *buffer_page;
	long unsigned int entries;
	long unsigned int saved_latency;
	long unsigned int critical_start;
	long unsigned int critical_end;
	long unsigned int critical_sequence;
	long unsigned int nice;
	long unsigned int policy;
	long unsigned int rt_priority;
	long unsigned int skipped_entries;
	u64 preempt_timestamp;
	pid_t pid;
	kuid_t uid;
	char comm[16];
	int ftrace_ignore_pid;
	bool ignore_pid;
};

struct trace_option_dentry;

struct trace_options {
	struct tracer *tracer;
	struct trace_option_dentry *topts;
};

struct tracer_opt;

struct trace_option_dentry {
	struct tracer_opt *opt;
	struct tracer_flags *flags;
	struct trace_array *tr;
	struct dentry *entry;
};

typedef bool (*cond_update_fn_t)(struct trace_array *, void *);

struct cond_snapshot {
	void *cond_data;
	cond_update_fn_t update;
};

struct trace_func_repeats {
	long unsigned int ip;
	long unsigned int parent_ip;
	long unsigned int count;
	u64 ts_last_call;
};

struct tracer_opt {
	const char *name;
	u32 bit;
};

struct tracer_flags {
	u32 val;
	struct tracer_opt *opts;
	struct tracer *trace;
};

struct event_subsystem {
	struct list_head list;
	const char *name;
	struct event_filter *filter;
	int ref_count;
};

enum trace_flag_type {
	TRACE_FLAG_IRQS_OFF = 1,
	TRACE_FLAG_IRQS_NOSUPPORT = 2,
	TRACE_FLAG_NEED_RESCHED = 4,
	TRACE_FLAG_HARDIRQ = 8,
	TRACE_FLAG_SOFTIRQ = 16,
	TRACE_FLAG_PREEMPT_RESCHED = 32,
	TRACE_FLAG_NMI = 64,
	TRACE_FLAG_BH_OFF = 128,
};

enum trace_type {
	__TRACE_FIRST_TYPE = 0,
	TRACE_FN = 1,
	TRACE_CTX = 2,
	TRACE_WAKE = 3,
	TRACE_STACK = 4,
	TRACE_PRINT = 5,
	TRACE_BPRINT = 6,
	TRACE_MMIO_RW = 7,
	TRACE_MMIO_MAP = 8,
	TRACE_BRANCH = 9,
	TRACE_GRAPH_RET = 10,
	TRACE_GRAPH_ENT = 11,
	TRACE_USER_STACK = 12,
	TRACE_BLK = 13,
	TRACE_BPUTS = 14,
	TRACE_HWLAT = 15,
	TRACE_OSNOISE = 16,
	TRACE_TIMERLAT = 17,
	TRACE_RAW_DATA = 18,
	TRACE_FUNC_REPEATS = 19,
	__TRACE_LAST_TYPE = 20,
};

struct stack_entry {
	struct trace_entry ent;
	int size;
	long unsigned int caller[8];
};

struct osnoise_entry {
	struct trace_entry ent;
	u64 noise;
	u64 runtime;
	u64 max_sample;
	unsigned int hw_count;
	unsigned int nmi_count;
	unsigned int irq_count;
	unsigned int softirq_count;
	unsigned int thread_count;
};

struct timerlat_entry {
	struct trace_entry ent;
	unsigned int seqnum;
	int context;
	u64 timer_latency;
};

enum trace_iterator_bits {
	TRACE_ITER_PRINT_PARENT_BIT = 0,
	TRACE_ITER_SYM_OFFSET_BIT = 1,
	TRACE_ITER_SYM_ADDR_BIT = 2,
	TRACE_ITER_VERBOSE_BIT = 3,
	TRACE_ITER_RAW_BIT = 4,
	TRACE_ITER_HEX_BIT = 5,
	TRACE_ITER_BIN_BIT = 6,
	TRACE_ITER_BLOCK_BIT = 7,
	TRACE_ITER_PRINTK_BIT = 8,
	TRACE_ITER_ANNOTATE_BIT = 9,
	TRACE_ITER_USERSTACKTRACE_BIT = 10,
	TRACE_ITER_SYM_USEROBJ_BIT = 11,
	TRACE_ITER_PRINTK_MSGONLY_BIT = 12,
	TRACE_ITER_CONTEXT_INFO_BIT = 13,
	TRACE_ITER_LATENCY_FMT_BIT = 14,
	TRACE_ITER_RECORD_CMD_BIT = 15,
	TRACE_ITER_RECORD_TGID_BIT = 16,
	TRACE_ITER_OVERWRITE_BIT = 17,
	TRACE_ITER_STOP_ON_FREE_BIT = 18,
	TRACE_ITER_IRQ_INFO_BIT = 19,
	TRACE_ITER_MARKERS_BIT = 20,
	TRACE_ITER_EVENT_FORK_BIT = 21,
	TRACE_ITER_PAUSE_ON_TRACE_BIT = 22,
	TRACE_ITER_HASH_PTR_BIT = 23,
	TRACE_ITER_FUNCTION_BIT = 24,
	TRACE_ITER_FUNC_FORK_BIT = 25,
	TRACE_ITER_DISPLAY_GRAPH_BIT = 26,
	TRACE_ITER_STACKTRACE_BIT = 27,
	TRACE_ITER_LAST_BIT = 28,
};

struct trace_min_max_param {
	struct mutex *lock;
	u64 *val;
	u64 *min;
	u64 *max;
};

struct trace_event_raw_thread_noise {
	struct trace_entry ent;
	char comm[16];
	u64 start;
	u64 duration;
	pid_t pid;
	char __data[0];
};

struct trace_event_raw_softirq_noise {
	struct trace_entry ent;
	u64 start;
	u64 duration;
	int vector;
	char __data[0];
};

struct trace_event_raw_irq_noise {
	struct trace_entry ent;
	u64 start;
	u64 duration;
	u32 __data_loc_desc;
	int vector;
	char __data[0];
};

struct trace_event_raw_nmi_noise {
	struct trace_entry ent;
	u64 start;
	u64 duration;
	char __data[0];
};

struct trace_event_raw_sample_threshold {
	struct trace_entry ent;
	u64 start;
	u64 duration;
	u64 interference;
	char __data[0];
};

struct trace_event_data_offsets_thread_noise {};

struct trace_event_data_offsets_softirq_noise {};

struct trace_event_data_offsets_irq_noise {
	u32 desc;
};

struct trace_event_data_offsets_nmi_noise {};

struct trace_event_data_offsets_sample_threshold {};

typedef void (*btf_trace_thread_noise)(void *, struct task_struct *, u64, u64);

typedef void (*btf_trace_softirq_noise)(void *, int, u64, u64);

typedef void (*btf_trace_irq_noise)(void *, int, const char *, u64, u64);

typedef void (*btf_trace_nmi_noise)(void *, u64, u64);

typedef void (*btf_trace_sample_threshold)(void *, u64, u64, u64);

struct osnoise_instance {
	struct list_head list;
	struct trace_array *tr;
};

struct osn_nmi {
	u64 count;
	u64 delta_start;
};

struct osn_irq {
	u64 count;
	u64 arrival_time;
	u64 delta_start;
};

struct osn_softirq {
	u64 count;
	u64 arrival_time;
	u64 delta_start;
};

struct osn_thread {
	u64 count;
	u64 arrival_time;
	u64 delta_start;
};

struct osnoise_variables {
	struct task_struct *kthread;
	bool sampling;
	pid_t pid;
	struct osn_nmi nmi;
	struct osn_irq irq;
	struct osn_softirq softirq;
	struct osn_thread thread;
	local_t int_counter;
};

struct timerlat_variables {
	struct task_struct *kthread;
	struct hrtimer timer;
	u64 rel_period;
	u64 abs_period;
	bool tracing_thread;
	u64 count;
};

struct osnoise_sample {
	u64 runtime;
	u64 noise;
	u64 max_sample;
	int hw_count;
	int nmi_count;
	int irq_count;
	int softirq_count;
	int thread_count;
};

struct timerlat_sample {
	u64 timer_latency;
	unsigned int seqnum;
	int context;
};

struct osnoise_data {
	u64 sample_period;
	u64 sample_runtime;
	u64 stop_tracing;
	u64 stop_tracing_total;
	u64 timerlat_period;
	u64 print_stack;
	int timerlat_tracer;
	bool tainted;
};

struct trace_stack {
	int stack_size;
	int nr_entries;
	long unsigned int calls[256];
};

struct ftrace_event_field {
	struct list_head link;
	const char *name;
	const char *type;
	int filter_type;
	int offset;
	int size;
	int is_signed;
};

struct filter_pred;

struct prog_entry {
	int target;
	int when_to_branch;
	struct filter_pred *pred;
};

typedef int (*filter_pred_fn_t)(struct filter_pred *, void *);

struct regex;

typedef int (*regex_match_func)(char *, struct regex *, int);

struct regex {
	char pattern[256];
	int len;
	int field_len;
	regex_match_func match;
};

struct filter_pred {
	filter_pred_fn_t fn;
	u64 val;
	struct regex regex;
	short unsigned int *ops;
	struct ftrace_event_field *field;
	int offset;
	int not;
	int op;
};

enum regex_type {
	MATCH_FULL = 0,
	MATCH_FRONT_ONLY = 1,
	MATCH_MIDDLE_ONLY = 2,
	MATCH_END_ONLY = 3,
	MATCH_GLOB = 4,
	MATCH_INDEX = 5,
};

enum filter_op_ids {
	OP_GLOB = 0,
	OP_NE = 1,
	OP_EQ = 2,
	OP_LE = 3,
	OP_LT = 4,
	OP_GE = 5,
	OP_GT = 6,
	OP_BAND = 7,
	OP_MAX = 8,
};

enum {
	FILT_ERR_NONE = 0,
	FILT_ERR_INVALID_OP = 1,
	FILT_ERR_TOO_MANY_OPEN = 2,
	FILT_ERR_TOO_MANY_CLOSE = 3,
	FILT_ERR_MISSING_QUOTE = 4,
	FILT_ERR_OPERAND_TOO_LONG = 5,
	FILT_ERR_EXPECT_STRING = 6,
	FILT_ERR_EXPECT_DIGIT = 7,
	FILT_ERR_ILLEGAL_FIELD_OP = 8,
	FILT_ERR_FIELD_NOT_FOUND = 9,
	FILT_ERR_ILLEGAL_INTVAL = 10,
	FILT_ERR_BAD_SUBSYS_FILTER = 11,
	FILT_ERR_TOO_MANY_PREDS = 12,
	FILT_ERR_INVALID_FILTER = 13,
	FILT_ERR_IP_FIELD_ONLY = 14,
	FILT_ERR_INVALID_VALUE = 15,
	FILT_ERR_ERRNO = 16,
	FILT_ERR_NO_FILTER = 17,
};

struct filter_parse_error {
	int lasterr;
	int lasterr_pos;
};

typedef int (*parse_pred_fn)(const char *, void *, int, struct filter_parse_error *, struct filter_pred **);

enum {
	INVERT = 1,
	PROCESS_AND = 2,
	PROCESS_OR = 4,
};

struct ustring_buffer {
	char buffer[1024];
};

enum {
	TOO_MANY_CLOSE = 4294967295,
	TOO_MANY_OPEN = 4294967294,
	MISSING_QUOTE = 4294967293,
};

struct filter_list {
	struct list_head list;
	struct event_filter *filter;
};

struct function_filter_data {
	struct ftrace_ops *ops;
	int first_filter;
	int first_notrace;
};

enum pm_qos_req_action {
	PM_QOS_ADD_REQ = 0,
	PM_QOS_UPDATE_REQ = 1,
	PM_QOS_REMOVE_REQ = 2,
};

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

struct trace_event_raw_cpu {
	struct trace_entry ent;
	u32 state;
	u32 cpu_id;
	char __data[0];
};

struct trace_event_raw_cpu_idle_miss {
	struct trace_entry ent;
	u32 cpu_id;
	u32 state;
	bool below;
	char __data[0];
};

struct trace_event_raw_powernv_throttle {
	struct trace_entry ent;
	int chip_id;
	u32 __data_loc_reason;
	int pmax;
	char __data[0];
};

struct trace_event_raw_pstate_sample {
	struct trace_entry ent;
	u32 core_busy;
	u32 scaled_busy;
	u32 from;
	u32 to;
	u64 mperf;
	u64 aperf;
	u64 tsc;
	u32 freq;
	u32 io_boost;
	char __data[0];
};

struct trace_event_raw_cpu_frequency_limits {
	struct trace_entry ent;
	u32 min_freq;
	u32 max_freq;
	u32 cpu_id;
	char __data[0];
};

struct trace_event_raw_device_pm_callback_start {
	struct trace_entry ent;
	u32 __data_loc_device;
	u32 __data_loc_driver;
	u32 __data_loc_parent;
	u32 __data_loc_pm_ops;
	int event;
	char __data[0];
};

struct trace_event_raw_device_pm_callback_end {
	struct trace_entry ent;
	u32 __data_loc_device;
	u32 __data_loc_driver;
	int error;
	char __data[0];
};

struct trace_event_raw_suspend_resume {
	struct trace_entry ent;
	const char *action;
	int val;
	bool start;
	char __data[0];
};

struct trace_event_raw_wakeup_source {
	struct trace_entry ent;
	u32 __data_loc_name;
	u64 state;
	char __data[0];
};

struct trace_event_raw_clock {
	struct trace_entry ent;
	u32 __data_loc_name;
	u64 state;
	u64 cpu_id;
	char __data[0];
};

struct trace_event_raw_power_domain {
	struct trace_entry ent;
	u32 __data_loc_name;
	u64 state;
	u64 cpu_id;
	char __data[0];
};

struct trace_event_raw_cpu_latency_qos_request {
	struct trace_entry ent;
	s32 value;
	char __data[0];
};

struct trace_event_raw_pm_qos_update {
	struct trace_entry ent;
	enum pm_qos_req_action action;
	int prev_value;
	int curr_value;
	char __data[0];
};

struct trace_event_raw_dev_pm_qos_request {
	struct trace_entry ent;
	u32 __data_loc_name;
	enum dev_pm_qos_req_type type;
	s32 new_value;
	char __data[0];
};

struct trace_event_raw_guest_halt_poll_ns {
	struct trace_entry ent;
	bool grow;
	unsigned int new;
	unsigned int old;
	char __data[0];
};

struct trace_event_data_offsets_cpu {};

struct trace_event_data_offsets_cpu_idle_miss {};

struct trace_event_data_offsets_powernv_throttle {
	u32 reason;
};

struct trace_event_data_offsets_pstate_sample {};

struct trace_event_data_offsets_cpu_frequency_limits {};

struct trace_event_data_offsets_device_pm_callback_start {
	u32 device;
	u32 driver;
	u32 parent;
	u32 pm_ops;
};

struct trace_event_data_offsets_device_pm_callback_end {
	u32 device;
	u32 driver;
};

struct trace_event_data_offsets_suspend_resume {};

struct trace_event_data_offsets_wakeup_source {
	u32 name;
};

struct trace_event_data_offsets_clock {
	u32 name;
};

struct trace_event_data_offsets_power_domain {
	u32 name;
};

struct trace_event_data_offsets_cpu_latency_qos_request {};

struct trace_event_data_offsets_pm_qos_update {};

struct trace_event_data_offsets_dev_pm_qos_request {
	u32 name;
};

struct trace_event_data_offsets_guest_halt_poll_ns {};

typedef void (*btf_trace_cpu_idle)(void *, unsigned int, unsigned int);

typedef void (*btf_trace_cpu_idle_miss)(void *, unsigned int, unsigned int, bool);

typedef void (*btf_trace_powernv_throttle)(void *, int, const char *, int);

typedef void (*btf_trace_pstate_sample)(void *, u32, u32, u32, u32, u64, u64, u64, u32, u32);

typedef void (*btf_trace_cpu_frequency)(void *, unsigned int, unsigned int);

typedef void (*btf_trace_cpu_frequency_limits)(void *, struct cpufreq_policy *);

typedef void (*btf_trace_device_pm_callback_start)(void *, struct device *, const char *, int);

typedef void (*btf_trace_device_pm_callback_end)(void *, struct device *, int);

typedef void (*btf_trace_suspend_resume)(void *, const char *, int, bool);

typedef void (*btf_trace_wakeup_source_activate)(void *, const char *, unsigned int);

typedef void (*btf_trace_wakeup_source_deactivate)(void *, const char *, unsigned int);

typedef void (*btf_trace_clock_enable)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_clock_disable)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_clock_set_rate)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_power_domain_target)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_pm_qos_add_request)(void *, s32);

typedef void (*btf_trace_pm_qos_update_request)(void *, s32);

typedef void (*btf_trace_pm_qos_remove_request)(void *, s32);

typedef void (*btf_trace_pm_qos_update_target)(void *, enum pm_qos_req_action, int, int);

typedef void (*btf_trace_pm_qos_update_flags)(void *, enum pm_qos_req_action, int, int);

typedef void (*btf_trace_dev_pm_qos_add_request)(void *, const char *, enum dev_pm_qos_req_type, s32);

typedef void (*btf_trace_dev_pm_qos_update_request)(void *, const char *, enum dev_pm_qos_req_type, s32);

typedef void (*btf_trace_dev_pm_qos_remove_request)(void *, const char *, enum dev_pm_qos_req_type, s32);

typedef void (*btf_trace_guest_halt_poll_ns)(void *, bool, unsigned int, unsigned int);

struct syscore_ops {
	struct list_head node;
	int (*suspend)();
	void (*resume)();
	void (*shutdown)();
};

enum bpf_func_id {
	BPF_FUNC_unspec = 0,
	BPF_FUNC_map_lookup_elem = 1,
	BPF_FUNC_map_update_elem = 2,
	BPF_FUNC_map_delete_elem = 3,
	BPF_FUNC_probe_read = 4,
	BPF_FUNC_ktime_get_ns = 5,
	BPF_FUNC_trace_printk = 6,
	BPF_FUNC_get_prandom_u32 = 7,
	BPF_FUNC_get_smp_processor_id = 8,
	BPF_FUNC_skb_store_bytes = 9,
	BPF_FUNC_l3_csum_replace = 10,
	BPF_FUNC_l4_csum_replace = 11,
	BPF_FUNC_tail_call = 12,
	BPF_FUNC_clone_redirect = 13,
	BPF_FUNC_get_current_pid_tgid = 14,
	BPF_FUNC_get_current_uid_gid = 15,
	BPF_FUNC_get_current_comm = 16,
	BPF_FUNC_get_cgroup_classid = 17,
	BPF_FUNC_skb_vlan_push = 18,
	BPF_FUNC_skb_vlan_pop = 19,
	BPF_FUNC_skb_get_tunnel_key = 20,
	BPF_FUNC_skb_set_tunnel_key = 21,
	BPF_FUNC_perf_event_read = 22,
	BPF_FUNC_redirect = 23,
	BPF_FUNC_get_route_realm = 24,
	BPF_FUNC_perf_event_output = 25,
	BPF_FUNC_skb_load_bytes = 26,
	BPF_FUNC_get_stackid = 27,
	BPF_FUNC_csum_diff = 28,
	BPF_FUNC_skb_get_tunnel_opt = 29,
	BPF_FUNC_skb_set_tunnel_opt = 30,
	BPF_FUNC_skb_change_proto = 31,
	BPF_FUNC_skb_change_type = 32,
	BPF_FUNC_skb_under_cgroup = 33,
	BPF_FUNC_get_hash_recalc = 34,
	BPF_FUNC_get_current_task = 35,
	BPF_FUNC_probe_write_user = 36,
	BPF_FUNC_current_task_under_cgroup = 37,
	BPF_FUNC_skb_change_tail = 38,
	BPF_FUNC_skb_pull_data = 39,
	BPF_FUNC_csum_update = 40,
	BPF_FUNC_set_hash_invalid = 41,
	BPF_FUNC_get_numa_node_id = 42,
	BPF_FUNC_skb_change_head = 43,
	BPF_FUNC_xdp_adjust_head = 44,
	BPF_FUNC_probe_read_str = 45,
	BPF_FUNC_get_socket_cookie = 46,
	BPF_FUNC_get_socket_uid = 47,
	BPF_FUNC_set_hash = 48,
	BPF_FUNC_setsockopt = 49,
	BPF_FUNC_skb_adjust_room = 50,
	BPF_FUNC_redirect_map = 51,
	BPF_FUNC_sk_redirect_map = 52,
	BPF_FUNC_sock_map_update = 53,
	BPF_FUNC_xdp_adjust_meta = 54,
	BPF_FUNC_perf_event_read_value = 55,
	BPF_FUNC_perf_prog_read_value = 56,
	BPF_FUNC_getsockopt = 57,
	BPF_FUNC_override_return = 58,
	BPF_FUNC_sock_ops_cb_flags_set = 59,
	BPF_FUNC_msg_redirect_map = 60,
	BPF_FUNC_msg_apply_bytes = 61,
	BPF_FUNC_msg_cork_bytes = 62,
	BPF_FUNC_msg_pull_data = 63,
	BPF_FUNC_bind = 64,
	BPF_FUNC_xdp_adjust_tail = 65,
	BPF_FUNC_skb_get_xfrm_state = 66,
	BPF_FUNC_get_stack = 67,
	BPF_FUNC_skb_load_bytes_relative = 68,
	BPF_FUNC_fib_lookup = 69,
	BPF_FUNC_sock_hash_update = 70,
	BPF_FUNC_msg_redirect_hash = 71,
	BPF_FUNC_sk_redirect_hash = 72,
	BPF_FUNC_lwt_push_encap = 73,
	BPF_FUNC_lwt_seg6_store_bytes = 74,
	BPF_FUNC_lwt_seg6_adjust_srh = 75,
	BPF_FUNC_lwt_seg6_action = 76,
	BPF_FUNC_rc_repeat = 77,
	BPF_FUNC_rc_keydown = 78,
	BPF_FUNC_skb_cgroup_id = 79,
	BPF_FUNC_get_current_cgroup_id = 80,
	BPF_FUNC_get_local_storage = 81,
	BPF_FUNC_sk_select_reuseport = 82,
	BPF_FUNC_skb_ancestor_cgroup_id = 83,
	BPF_FUNC_sk_lookup_tcp = 84,
	BPF_FUNC_sk_lookup_udp = 85,
	BPF_FUNC_sk_release = 86,
	BPF_FUNC_map_push_elem = 87,
	BPF_FUNC_map_pop_elem = 88,
	BPF_FUNC_map_peek_elem = 89,
	BPF_FUNC_msg_push_data = 90,
	BPF_FUNC_msg_pop_data = 91,
	BPF_FUNC_rc_pointer_rel = 92,
	BPF_FUNC_spin_lock = 93,
	BPF_FUNC_spin_unlock = 94,
	BPF_FUNC_sk_fullsock = 95,
	BPF_FUNC_tcp_sock = 96,
	BPF_FUNC_skb_ecn_set_ce = 97,
	BPF_FUNC_get_listener_sock = 98,
	BPF_FUNC_skc_lookup_tcp = 99,
	BPF_FUNC_tcp_check_syncookie = 100,
	BPF_FUNC_sysctl_get_name = 101,
	BPF_FUNC_sysctl_get_current_value = 102,
	BPF_FUNC_sysctl_get_new_value = 103,
	BPF_FUNC_sysctl_set_new_value = 104,
	BPF_FUNC_strtol = 105,
	BPF_FUNC_strtoul = 106,
	BPF_FUNC_sk_storage_get = 107,
	BPF_FUNC_sk_storage_delete = 108,
	BPF_FUNC_send_signal = 109,
	BPF_FUNC_tcp_gen_syncookie = 110,
	BPF_FUNC_skb_output = 111,
	BPF_FUNC_probe_read_user = 112,
	BPF_FUNC_probe_read_kernel = 113,
	BPF_FUNC_probe_read_user_str = 114,
	BPF_FUNC_probe_read_kernel_str = 115,
	BPF_FUNC_tcp_send_ack = 116,
	BPF_FUNC_send_signal_thread = 117,
	BPF_FUNC_jiffies64 = 118,
	BPF_FUNC_read_branch_records = 119,
	BPF_FUNC_get_ns_current_pid_tgid = 120,
	BPF_FUNC_xdp_output = 121,
	BPF_FUNC_get_netns_cookie = 122,
	BPF_FUNC_get_current_ancestor_cgroup_id = 123,
	BPF_FUNC_sk_assign = 124,
	BPF_FUNC_ktime_get_boot_ns = 125,
	BPF_FUNC_seq_printf = 126,
	BPF_FUNC_seq_write = 127,
	BPF_FUNC_sk_cgroup_id = 128,
	BPF_FUNC_sk_ancestor_cgroup_id = 129,
	BPF_FUNC_ringbuf_output = 130,
	BPF_FUNC_ringbuf_reserve = 131,
	BPF_FUNC_ringbuf_submit = 132,
	BPF_FUNC_ringbuf_discard = 133,
	BPF_FUNC_ringbuf_query = 134,
	BPF_FUNC_csum_level = 135,
	BPF_FUNC_skc_to_tcp6_sock = 136,
	BPF_FUNC_skc_to_tcp_sock = 137,
	BPF_FUNC_skc_to_tcp_timewait_sock = 138,
	BPF_FUNC_skc_to_tcp_request_sock = 139,
	BPF_FUNC_skc_to_udp6_sock = 140,
	BPF_FUNC_get_task_stack = 141,
	BPF_FUNC_load_hdr_opt = 142,
	BPF_FUNC_store_hdr_opt = 143,
	BPF_FUNC_reserve_hdr_opt = 144,
	BPF_FUNC_inode_storage_get = 145,
	BPF_FUNC_inode_storage_delete = 146,
	BPF_FUNC_d_path = 147,
	BPF_FUNC_copy_from_user = 148,
	BPF_FUNC_snprintf_btf = 149,
	BPF_FUNC_seq_printf_btf = 150,
	BPF_FUNC_skb_cgroup_classid = 151,
	BPF_FUNC_redirect_neigh = 152,
	BPF_FUNC_per_cpu_ptr = 153,
	BPF_FUNC_this_cpu_ptr = 154,
	BPF_FUNC_redirect_peer = 155,
	BPF_FUNC_task_storage_get = 156,
	BPF_FUNC_task_storage_delete = 157,
	BPF_FUNC_get_current_task_btf = 158,
	BPF_FUNC_bprm_opts_set = 159,
	BPF_FUNC_ktime_get_coarse_ns = 160,
	BPF_FUNC_ima_inode_hash = 161,
	BPF_FUNC_sock_from_file = 162,
	BPF_FUNC_check_mtu = 163,
	BPF_FUNC_for_each_map_elem = 164,
	BPF_FUNC_snprintf = 165,
	BPF_FUNC_sys_bpf = 166,
	BPF_FUNC_btf_find_by_name_kind = 167,
	BPF_FUNC_sys_close = 168,
	BPF_FUNC_timer_init = 169,
	BPF_FUNC_timer_set_callback = 170,
	BPF_FUNC_timer_start = 171,
	BPF_FUNC_timer_cancel = 172,
	BPF_FUNC_get_func_ip = 173,
	BPF_FUNC_get_attach_cookie = 174,
	BPF_FUNC_task_pt_regs = 175,
	BPF_FUNC_get_branch_snapshot = 176,
	BPF_FUNC_trace_vprintk = 177,
	BPF_FUNC_skc_to_unix_sock = 178,
	BPF_FUNC_kallsyms_lookup_name = 179,
	BPF_FUNC_find_vma = 180,
	BPF_FUNC_loop = 181,
	BPF_FUNC_strncmp = 182,
	BPF_FUNC_get_func_arg = 183,
	BPF_FUNC_get_func_ret = 184,
	BPF_FUNC_get_func_arg_cnt = 185,
	BPF_FUNC_get_retval = 186,
	BPF_FUNC_set_retval = 187,
	BPF_FUNC_xdp_get_buff_len = 188,
	BPF_FUNC_xdp_load_bytes = 189,
	BPF_FUNC_xdp_store_bytes = 190,
	BPF_FUNC_copy_from_user_task = 191,
	BPF_FUNC_skb_set_tstamp = 192,
	BPF_FUNC_ima_file_hash = 193,
	BPF_FUNC_kptr_xchg = 194,
	BPF_FUNC_map_lookup_percpu_elem = 195,
	BPF_FUNC_skc_to_mptcp_sock = 196,
	BPF_FUNC_dynptr_from_mem = 197,
	BPF_FUNC_ringbuf_reserve_dynptr = 198,
	BPF_FUNC_ringbuf_submit_dynptr = 199,
	BPF_FUNC_ringbuf_discard_dynptr = 200,
	BPF_FUNC_dynptr_read = 201,
	BPF_FUNC_dynptr_write = 202,
	BPF_FUNC_dynptr_data = 203,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv4 = 204,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv6 = 205,
	BPF_FUNC_tcp_raw_check_syncookie_ipv4 = 206,
	BPF_FUNC_tcp_raw_check_syncookie_ipv6 = 207,
	__BPF_FUNC_MAX_ID = 208,
};

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP = 1,
	XDP_PASS = 2,
	XDP_TX = 3,
	XDP_REDIRECT = 4,
};

struct rnd_state {
	__u32 s1;
	__u32 s2;
	__u32 s3;
	__u32 s4;
};

struct rhash_lock_head;

struct bucket_table {
	unsigned int size;
	unsigned int nest;
	u32 hash_rnd;
	struct list_head walkers;
	struct callback_head rcu;
	struct bucket_table *future_tbl;
	struct lockdep_map dep_map;
	long: 64;
	struct rhash_lock_head *buckets[0];
};

typedef sockptr_t bpfptr_t;

struct bpf_verifier_log {
	u32 level;
	char kbuf[1024];
	char *ubuf;
	u32 len_used;
	u32 len_total;
};

struct bpf_subprog_info {
	u32 start;
	u32 linfo_idx;
	u16 stack_depth;
	bool has_tail_call;
	bool tail_call_reachable;
	bool has_ld_abs;
	bool is_async_cb;
};

struct bpf_id_pair {
	u32 old;
	u32 cur;
};

struct bpf_verifier_ops;

struct bpf_verifier_stack_elem;

struct bpf_verifier_state;

struct bpf_verifier_state_list;

struct bpf_insn_aux_data;

struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;
	const struct bpf_verifier_ops *ops;
	struct bpf_verifier_stack_elem *head;
	int stack_size;
	bool strict_alignment;
	bool test_state_freq;
	struct bpf_verifier_state *cur_state;
	struct bpf_verifier_state_list **explored_states;
	struct bpf_verifier_state_list *free_list;
	struct bpf_map *used_maps[64];
	struct btf_mod_pair used_btfs[64];
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 id_gen;
	bool explore_alu_limits;
	bool allow_ptr_leaks;
	bool allow_uninit_stack;
	bool allow_ptr_to_map_access;
	bool bpf_capable;
	bool bypass_spec_v1;
	bool bypass_spec_v4;
	bool seen_direct_write;
	struct bpf_insn_aux_data *insn_aux_data;
	const struct bpf_line_info *prev_linfo;
	struct bpf_verifier_log log;
	struct bpf_subprog_info subprog_info[257];
	struct bpf_id_pair idmap_scratch[75];
	struct {
		int *insn_state;
		int *insn_stack;
		int cur_stack;
	} cfg;
	u32 pass_cnt;
	u32 subprog_cnt;
	u32 prev_insn_processed;
	u32 insn_processed;
	u32 prev_jmps_processed;
	u32 jmps_processed;
	u64 verification_time;
	u32 max_states_per_insn;
	u32 total_states;
	u32 peak_states;
	u32 longest_mark_read_walk;
	bpfptr_t fd_array;
	u32 scratched_regs;
	u64 scratched_stack_slots;
	u32 prev_log_len;
	u32 prev_insn_print_len;
	char type_str_buf[64];
};

enum bpf_dynptr_type {
	BPF_DYNPTR_TYPE_INVALID = 0,
	BPF_DYNPTR_TYPE_LOCAL = 1,
	BPF_DYNPTR_TYPE_RINGBUF = 2,
};

struct tnum {
	u64 value;
	u64 mask;
};

enum bpf_reg_liveness {
	REG_LIVE_NONE = 0,
	REG_LIVE_READ32 = 1,
	REG_LIVE_READ64 = 2,
	REG_LIVE_READ = 3,
	REG_LIVE_WRITTEN = 4,
	REG_LIVE_DONE = 8,
};

struct bpf_reg_state {
	enum bpf_reg_type type;
	s32 off;
	union {
		int range;
		struct {
			struct bpf_map *map_ptr;
			u32 map_uid;
		};
		struct {
			struct btf *btf;
			u32 btf_id;
		};
		u32 mem_size;
		struct {
			enum bpf_dynptr_type type;
			bool first_slot;
		} dynptr;
		struct {
			long unsigned int raw1;
			long unsigned int raw2;
		} raw;
		u32 subprogno;
	};
	u32 id;
	u32 ref_obj_id;
	struct tnum var_off;
	s64 smin_value;
	s64 smax_value;
	u64 umin_value;
	u64 umax_value;
	s32 s32_min_value;
	s32 s32_max_value;
	u32 u32_min_value;
	u32 u32_max_value;
	struct bpf_reg_state *parent;
	u32 frameno;
	s32 subreg_def;
	enum bpf_reg_liveness live;
	bool precise;
};

struct bpf_reference_state;

struct bpf_stack_state;

struct bpf_func_state {
	struct bpf_reg_state regs[11];
	int callsite;
	u32 frameno;
	u32 subprogno;
	u32 async_entry_cnt;
	bool in_callback_fn;
	bool in_async_callback_fn;
	int acquired_refs;
	struct bpf_reference_state *refs;
	int allocated_stack;
	struct bpf_stack_state *stack;
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

struct bpf_func_proto {
	u64 (*func)(u64, u64, u64, u64, u64);
	bool gpl_only;
	bool pkt_access;
	enum bpf_return_type ret_type;
	union {
		struct {
			enum bpf_arg_type arg1_type;
			enum bpf_arg_type arg2_type;
			enum bpf_arg_type arg3_type;
			enum bpf_arg_type arg4_type;
			enum bpf_arg_type arg5_type;
		};
		enum bpf_arg_type arg_type[5];
	};
	union {
		struct {
			u32 *arg1_btf_id;
			u32 *arg2_btf_id;
			u32 *arg3_btf_id;
			u32 *arg4_btf_id;
			u32 *arg5_btf_id;
		};
		u32 *arg_btf_id[5];
		struct {
			size_t arg1_size;
			size_t arg2_size;
			size_t arg3_size;
			size_t arg4_size;
			size_t arg5_size;
		};
		size_t arg_size[5];
	};
	int *ret_btf_id;
	bool (*allowed)(const struct bpf_prog *);
};

enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2,
};

struct bpf_insn_access_aux {
	enum bpf_reg_type reg_type;
	union {
		int ctx_field_size;
		struct {
			struct btf *btf;
			u32 btf_id;
		};
	};
	struct bpf_verifier_log *log;
};

struct bpf_verifier_ops {
	const struct bpf_func_proto * (*get_func_proto)(enum bpf_func_id, const struct bpf_prog *);
	bool (*is_valid_access)(int, int, enum bpf_access_type, const struct bpf_prog *, struct bpf_insn_access_aux *);
	int (*gen_prologue)(struct bpf_insn *, bool, const struct bpf_prog *);
	int (*gen_ld_abs)(const struct bpf_insn *, struct bpf_insn *);
	u32 (*convert_ctx_access)(enum bpf_access_type, const struct bpf_insn *, struct bpf_insn *, struct bpf_prog *, u32 *);
	int (*btf_struct_access)(struct bpf_verifier_log *, const struct btf *, const struct btf_type *, int, int, enum bpf_access_type, u32 *, enum bpf_type_flag *);
};

enum bpf_jit_poke_reason {
	BPF_POKE_REASON_TAIL_CALL = 0,
};

typedef long unsigned int (*bpf_ctx_copy_t)(void *, const void *, long unsigned int, long unsigned int);

struct bpf_empty_prog_array {
	struct bpf_prog_array hdr;
	struct bpf_prog *null_prog;
};

enum xdp_mem_type {
	MEM_TYPE_PAGE_SHARED = 0,
	MEM_TYPE_PAGE_ORDER0 = 1,
	MEM_TYPE_PAGE_POOL = 2,
	MEM_TYPE_XSK_BUFF_POOL = 3,
	MEM_TYPE_MAX = 4,
};

struct xdp_cpumap_stats {
	unsigned int redirect;
	unsigned int pass;
	unsigned int drop;
};

struct bpf_stack_state {
	struct bpf_reg_state spilled_ptr;
	u8 slot_type[8];
};

struct bpf_reference_state {
	int id;
	int insn_idx;
	int callback_ref;
};

struct bpf_idx_pair {
	u32 prev_idx;
	u32 idx;
};

struct bpf_verifier_state {
	struct bpf_func_state *frame[8];
	struct bpf_verifier_state *parent;
	u32 branches;
	u32 insn_idx;
	u32 curframe;
	u32 active_spin_lock;
	bool speculative;
	u32 first_insn_idx;
	u32 last_insn_idx;
	struct bpf_idx_pair *jmp_history;
	u32 jmp_history_cnt;
};

struct bpf_verifier_state_list {
	struct bpf_verifier_state state;
	struct bpf_verifier_state_list *next;
	int miss_cnt;
	int hit_cnt;
};

struct bpf_loop_inline_state {
	unsigned int initialized: 1;
	unsigned int fit_for_inline: 1;
	u32 callback_subprogno;
};

struct bpf_insn_aux_data {
	union {
		enum bpf_reg_type ptr_type;
		long unsigned int map_ptr_state;
		s32 call_imm;
		u32 alu_limit;
		struct {
			u32 map_index;
			u32 map_off;
		};
		struct {
			enum bpf_reg_type reg_type;
			union {
				struct {
					struct btf *btf;
					u32 btf_id;
				};
				u32 mem_size;
			};
		} btf_var;
		struct bpf_loop_inline_state loop_inline_state;
	};
	u64 map_key_state;
	int ctx_field_size;
	u32 seen;
	bool sanitize_stack_spill;
	bool zext_dst;
	u8 alu_state;
	unsigned int orig_idx;
	bool prune_point;
};

struct bpf_prog_pack {
	struct list_head list;
	void *ptr;
	long unsigned int bitmap[0];
};

struct bpf_prog_dummy {
	struct bpf_prog prog;
};

typedef u64 (*btf_bpf_user_rnd_u32)();

typedef u64 (*btf_bpf_get_raw_cpu_id)();

struct _bpf_dtab_netdev {
	struct net_device *dev;
};

struct rhash_lock_head {};

struct xdp_mem_allocator {
	struct xdp_mem_info mem;
	union {
		void *allocator;
		struct page_pool *page_pool;
	};
	struct rhash_head node;
	struct callback_head rcu;
};

struct trace_event_raw_xdp_exception {
	struct trace_entry ent;
	int prog_id;
	u32 act;
	int ifindex;
	char __data[0];
};

struct trace_event_raw_xdp_bulk_tx {
	struct trace_entry ent;
	int ifindex;
	u32 act;
	int drops;
	int sent;
	int err;
	char __data[0];
};

struct trace_event_raw_xdp_redirect_template {
	struct trace_entry ent;
	int prog_id;
	u32 act;
	int ifindex;
	int err;
	int to_ifindex;
	u32 map_id;
	int map_index;
	char __data[0];
};

struct trace_event_raw_xdp_cpumap_kthread {
	struct trace_entry ent;
	int map_id;
	u32 act;
	int cpu;
	unsigned int drops;
	unsigned int processed;
	int sched;
	unsigned int xdp_pass;
	unsigned int xdp_drop;
	unsigned int xdp_redirect;
	char __data[0];
};

struct trace_event_raw_xdp_cpumap_enqueue {
	struct trace_entry ent;
	int map_id;
	u32 act;
	int cpu;
	unsigned int drops;
	unsigned int processed;
	int to_cpu;
	char __data[0];
};

struct trace_event_raw_xdp_devmap_xmit {
	struct trace_entry ent;
	int from_ifindex;
	u32 act;
	int to_ifindex;
	int drops;
	int sent;
	int err;
	char __data[0];
};

struct trace_event_raw_mem_disconnect {
	struct trace_entry ent;
	const struct xdp_mem_allocator *xa;
	u32 mem_id;
	u32 mem_type;
	const void *allocator;
	char __data[0];
};

struct trace_event_raw_mem_connect {
	struct trace_entry ent;
	const struct xdp_mem_allocator *xa;
	u32 mem_id;
	u32 mem_type;
	const void *allocator;
	const struct xdp_rxq_info *rxq;
	int ifindex;
	char __data[0];
};

struct trace_event_raw_mem_return_failed {
	struct trace_entry ent;
	const struct page *page;
	u32 mem_id;
	u32 mem_type;
	char __data[0];
};

struct trace_event_data_offsets_xdp_exception {};

struct trace_event_data_offsets_xdp_bulk_tx {};

struct trace_event_data_offsets_xdp_redirect_template {};

struct trace_event_data_offsets_xdp_cpumap_kthread {};

struct trace_event_data_offsets_xdp_cpumap_enqueue {};

struct trace_event_data_offsets_xdp_devmap_xmit {};

struct trace_event_data_offsets_mem_disconnect {};

struct trace_event_data_offsets_mem_connect {};

struct trace_event_data_offsets_mem_return_failed {};

typedef void (*btf_trace_xdp_exception)(void *, const struct net_device *, const struct bpf_prog *, u32);

typedef void (*btf_trace_xdp_bulk_tx)(void *, const struct net_device *, int, int, int);

typedef void (*btf_trace_xdp_redirect)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_redirect_err)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_redirect_map)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_redirect_map_err)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_cpumap_kthread)(void *, int, unsigned int, unsigned int, int, struct xdp_cpumap_stats *);

typedef void (*btf_trace_xdp_cpumap_enqueue)(void *, int, unsigned int, unsigned int, int);

typedef void (*btf_trace_xdp_devmap_xmit)(void *, const struct net_device *, const struct net_device *, int, int, int);

typedef void (*btf_trace_mem_disconnect)(void *, const struct xdp_mem_allocator *);

typedef void (*btf_trace_mem_connect)(void *, const struct xdp_mem_allocator *, const struct xdp_rxq_info *);

typedef void (*btf_trace_mem_return_failed)(void *, const struct xdp_mem_info *, const struct page *);

union bpf_iter_link_info {
	struct {
		__u32 map_fd;
	} map;
};

typedef int (*bpf_iter_attach_target_t)(struct bpf_prog *, union bpf_iter_link_info *, struct bpf_iter_aux_info *);

typedef void (*bpf_iter_detach_target_t)(struct bpf_iter_aux_info *);

typedef void (*bpf_iter_show_fdinfo_t)(const struct bpf_iter_aux_info *, struct seq_file *);

typedef int (*bpf_iter_fill_link_info_t)(const struct bpf_iter_aux_info *, struct bpf_link_info *);

typedef const struct bpf_func_proto * (*bpf_iter_get_func_proto_t)(enum bpf_func_id, const struct bpf_prog *);

struct bpf_iter_reg {
	const char *target;
	bpf_iter_attach_target_t attach_target;
	bpf_iter_detach_target_t detach_target;
	bpf_iter_show_fdinfo_t show_fdinfo;
	bpf_iter_fill_link_info_t fill_link_info;
	bpf_iter_get_func_proto_t get_func_proto;
	u32 ctx_arg_info_size;
	u32 feature;
	struct bpf_ctx_arg_aux ctx_arg_info[2];
	const struct bpf_iter_seq_info *seq_info;
};

struct bpf_iter_meta {
	union {
		struct seq_file *seq;
	};
	u64 session_id;
	u64 seq_num;
};

struct bpf_iter_seq_prog_info {
	u32 prog_id;
};

struct bpf_iter__bpf_prog {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_prog *prog;
	};
};

struct bpf_array_aux {
	struct list_head poke_progs;
	struct bpf_map *map;
	struct mutex poke_mutex;
	struct work_struct work;
};

struct bpf_array {
	struct bpf_map map;
	u32 elem_size;
	u32 index_mask;
	struct bpf_array_aux *aux;
	union {
		char value[0];
		void *ptrs[0];
		void *pptrs[0];
	};
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum {
	BPF_MAP_VALUE_OFF_MAX = 8,
	BPF_MAP_OFF_ARR_MAX = 10,
};

enum bpf_cgroup_storage_type {
	BPF_CGROUP_STORAGE_SHARED = 0,
	BPF_CGROUP_STORAGE_PERCPU = 1,
	__BPF_CGROUP_STORAGE_MAX = 2,
};

typedef void (*bpf_insn_print_t)(void *, const char *, ...);

typedef const char * (*bpf_insn_revmap_call_t)(void *, const struct bpf_insn *);

typedef const char * (*bpf_insn_print_imm_t)(void *, const struct bpf_insn *, __u64);

struct bpf_insn_cbs {
	bpf_insn_print_t cb_print;
	bpf_insn_revmap_call_t cb_call;
	bpf_insn_print_imm_t cb_imm;
	void *private_data;
};

enum {
	BTF_KIND_UNKN = 0,
	BTF_KIND_INT = 1,
	BTF_KIND_PTR = 2,
	BTF_KIND_ARRAY = 3,
	BTF_KIND_STRUCT = 4,
	BTF_KIND_UNION = 5,
	BTF_KIND_ENUM = 6,
	BTF_KIND_FWD = 7,
	BTF_KIND_TYPEDEF = 8,
	BTF_KIND_VOLATILE = 9,
	BTF_KIND_CONST = 10,
	BTF_KIND_RESTRICT = 11,
	BTF_KIND_FUNC = 12,
	BTF_KIND_FUNC_PROTO = 13,
	BTF_KIND_VAR = 14,
	BTF_KIND_DATASEC = 15,
	BTF_KIND_FLOAT = 16,
	BTF_KIND_DECL_TAG = 17,
	BTF_KIND_TYPE_TAG = 18,
	BTF_KIND_ENUM64 = 19,
	NR_BTF_KINDS = 20,
	BTF_KIND_MAX = 19,
};

struct btf_enum {
	__u32 name_off;
	__s32 val;
};

struct btf_array {
	__u32 type;
	__u32 index_type;
	__u32 nelems;
};

struct btf_member {
	__u32 name_off;
	__u32 type;
	__u32 offset;
};

struct btf_param {
	__u32 name_off;
	__u32 type;
};

enum {
	BTF_VAR_STATIC = 0,
	BTF_VAR_GLOBAL_ALLOCATED = 1,
	BTF_VAR_GLOBAL_EXTERN = 2,
};

enum btf_func_linkage {
	BTF_FUNC_STATIC = 0,
	BTF_FUNC_GLOBAL = 1,
	BTF_FUNC_EXTERN = 2,
};

struct btf_var {
	__u32 linkage;
};

struct btf_var_secinfo {
	__u32 type;
	__u32 offset;
	__u32 size;
};

struct btf_decl_tag {
	__s32 component_idx;
};

struct btf_enum64 {
	__u32 name_off;
	__u32 val_lo32;
	__u32 val_hi32;
};

struct bpf_cgroup_storage_key {
	__u64 cgroup_inode_id;
	__u32 attach_type;
};

struct bpf_flow_keys {
	__u16 nhoff;
	__u16 thoff;
	__u16 addr_proto;
	__u8 is_frag;
	__u8 is_first_frag;
	__u8 is_encap;
	__u8 ip_proto;
	__be16 n_proto;
	__be16 sport;
	__be16 dport;
	union {
		struct {
			__be32 ipv4_src;
			__be32 ipv4_dst;
		};
		struct {
			__u32 ipv6_src[4];
			__u32 ipv6_dst[4];
		};
	};
	__u32 flags;
	__be32 flow_label;
};

struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
	__u32 src_ip4;
	__u32 src_ip6[4];
	__u32 src_port;
	__be16 dst_port;
	__u32 dst_ip4;
	__u32 dst_ip6[4];
	__u32 state;
	__s32 rx_queue_mapping;
};

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	union {
		struct bpf_flow_keys *flow_keys;
	};
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	union {
		struct bpf_sock *sk;
	};
	__u32 gso_size;
	__u8 tstamp_type;
	__u64 hwtstamp;
};

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

struct sk_msg_md {
	union {
		void *data;
	};
	union {
		void *data_end;
	};
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 size;
	union {
		struct bpf_sock *sk;
	};
};

struct sk_reuseport_md {
	union {
		void *data;
	};
	union {
		void *data_end;
	};
	__u32 len;
	__u32 eth_protocol;
	__u32 ip_protocol;
	__u32 bind_inany;
	__u32 hash;
	union {
		struct bpf_sock *sk;
	};
	union {
		struct bpf_sock *migrating_sk;
	};
};

struct bpf_btf_info {
	__u64 btf;
	__u32 btf_size;
	__u32 id;
	__u64 name;
	__u32 name_len;
	__u32 kernel_btf;
};

struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 msg_src_ip4;
	__u32 msg_src_ip6[4];
	union {
		struct bpf_sock *sk;
	};
};

struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 args[4];
		__u32 reply;
		__u32 replylong[4];
	};
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 is_fullsock;
	__u32 snd_cwnd;
	__u32 srtt_us;
	__u32 bpf_sock_ops_cb_flags;
	__u32 state;
	__u32 rtt_min;
	__u32 snd_ssthresh;
	__u32 rcv_nxt;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 mss_cache;
	__u32 ecn_flags;
	__u32 rate_delivered;
	__u32 rate_interval_us;
	__u32 packets_out;
	__u32 retrans_out;
	__u32 total_retrans;
	__u32 segs_in;
	__u32 data_segs_in;
	__u32 segs_out;
	__u32 data_segs_out;
	__u32 lost_out;
	__u32 sacked_out;
	__u32 sk_txhash;
	__u64 bytes_received;
	__u64 bytes_acked;
	union {
		struct bpf_sock *sk;
	};
	union {
		void *skb_data;
	};
	union {
		void *skb_data_end;
	};
	__u32 skb_len;
	__u32 skb_tcp_flags;
};

struct bpf_cgroup_dev_ctx {
	__u32 access_type;
	__u32 major;
	__u32 minor;
};

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

struct bpf_sysctl {
	__u32 write;
	__u32 file_pos;
};

struct bpf_sockopt {
	union {
		struct bpf_sock *sk;
	};
	union {
		void *optval;
	};
	union {
		void *optval_end;
	};
	__s32 level;
	__s32 optname;
	__s32 optlen;
	__s32 retval;
};

struct bpf_sk_lookup {
	union {
		union {
			struct bpf_sock *sk;
		};
		__u64 cookie;
	};
	__u32 family;
	__u32 protocol;
	__u32 remote_ip4;
	__u32 remote_ip6[4];
	__be16 remote_port;
	__u32 local_ip4;
	__u32 local_ip6[4];
	__u32 local_port;
	__u32 ingress_ifindex;
};

enum {
	BTF_F_COMPACT = 1,
	BTF_F_NONAME = 2,
	BTF_F_PTR_RAW = 4,
	BTF_F_ZERO = 8,
};

enum bpf_core_relo_kind {
	BPF_CORE_FIELD_BYTE_OFFSET = 0,
	BPF_CORE_FIELD_BYTE_SIZE = 1,
	BPF_CORE_FIELD_EXISTS = 2,
	BPF_CORE_FIELD_SIGNED = 3,
	BPF_CORE_FIELD_LSHIFT_U64 = 4,
	BPF_CORE_FIELD_RSHIFT_U64 = 5,
	BPF_CORE_TYPE_ID_LOCAL = 6,
	BPF_CORE_TYPE_ID_TARGET = 7,
	BPF_CORE_TYPE_EXISTS = 8,
	BPF_CORE_TYPE_SIZE = 9,
	BPF_CORE_ENUMVAL_EXISTS = 10,
	BPF_CORE_ENUMVAL_VALUE = 11,
	BPF_CORE_TYPE_MATCHES = 12,
};

struct bpf_core_relo {
	__u32 insn_off;
	__u32 type_id;
	__u32 access_str_off;
	enum bpf_core_relo_kind kind;
};

typedef struct user_pt_regs bpf_user_pt_regs_t;

struct bpf_perf_event_data {
	bpf_user_pt_regs_t regs;
	__u64 sample_period;
	__u64 addr;
};

typedef struct {} local_lock_t;

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

struct radix_tree_preload {
	local_lock_t lock;
	unsigned int nr;
	struct xa_node *nodes;
};

typedef __u64 __addrpair;

typedef __u32 __portpair;

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

struct sock_cgroup_data {
	struct cgroup *cgroup;
	u32 classid;
	u16 prioidx;
};

typedef struct {} netns_tracker;

struct sk_filter;

struct xfrm_policy;

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

struct btf_id_set8;

struct btf_kfunc_id_set {
	struct module *owner;
	struct btf_id_set8 *set;
};

struct btf_id_set8 {
	u32 cnt;
	u32 flags;
	struct {
		u32 id;
		u32 flags;
	} pairs[0];
};

struct btf_id_dtor_kfunc {
	u32 btf_id;
	u32 kfunc_btf_id;
};

struct bpf_storage_buffer;

struct bpf_cgroup_storage_map;

struct bpf_cgroup_storage {
	union {
		struct bpf_storage_buffer *buf;
		void *percpu_buf;
	};
	struct bpf_cgroup_storage_map *map;
	struct bpf_cgroup_storage_key key;
	struct list_head list_map;
	struct list_head list_cg;
	struct rb_node node;
	struct callback_head rcu;
};

struct bpf_core_ctx {
	struct bpf_verifier_log *log;
	const struct btf *btf;
};

struct sk_reuseport_kern {
	struct sk_buff *skb;
	struct sock *sk;
	struct sock *selected_sk;
	struct sock *migrating_sk;
	void *data_end;
	u32 hash;
	u32 reuseport_id;
	bool bind_inany;
};

struct bpf_flow_dissector {
	struct bpf_flow_keys *flow_keys;
	const struct sk_buff *skb;
	const void *data;
	const void *data_end;
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

struct inet_ehash_bucket;

struct inet_bind_hashbucket;

struct inet_listen_hashbucket;

struct inet_hashinfo {
	struct inet_ehash_bucket *ehash;
	spinlock_t *ehash_locks;
	unsigned int ehash_mask;
	unsigned int ehash_locks_mask;
	struct kmem_cache *bind_bucket_cachep;
	struct inet_bind_hashbucket *bhash;
	unsigned int bhash_size;
	unsigned int lhash2_mask;
	struct inet_listen_hashbucket *lhash2;
};

struct ip_ra_chain {
	struct ip_ra_chain *next;
	struct sock *sk;
	union {
		void (*destructor)(struct sock *);
		struct sock *saved_sk;
	};
	struct callback_head rcu;
};

struct fib_rule;

struct fib_lookup_arg;

struct fib_rule_hdr;

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

struct fib_table {
	struct hlist_node tb_hlist;
	u32 tb_id;
	int tb_num_default;
	struct callback_head rcu;
	long unsigned int *tb_data;
	long unsigned int __data[0];
};

struct inet_peer_base {
	struct rb_root rb_root;
	seqlock_t lock;
	int total;
};

struct tcp_fastopen_context {
	siphash_key_t key[2];
	int num;
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
	__s32 optimistic_dad;
	__s32 use_optimistic;
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

struct hlist_nulls_head {
	struct hlist_nulls_node *first;
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
	int qlen;
	int data[14];
	long unsigned int data_state[1];
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

struct __una_u32 {
	u32 x;
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

struct sk_filter {
	refcount_t refcnt;
	struct callback_head rcu;
	struct bpf_prog *prog;
};

struct bpf_sock_addr_kern {
	struct sock *sk;
	struct sockaddr *uaddr;
	u64 tmp_reg;
	void *t_ctx;
};

struct bpf_sock_ops_kern {
	struct sock *sk;
	union {
		u32 args[4];
		u32 reply;
		u32 replylong[4];
	};
	struct sk_buff *syn_skb;
	struct sk_buff *skb;
	void *skb_data_end;
	u8 op;
	u8 is_fullsock;
	u8 remaining_opt_len;
	u64 temp;
};

struct bpf_sysctl_kern {
	struct ctl_table_header *head;
	struct ctl_table *table;
	void *cur_val;
	size_t cur_len;
	void *new_val;
	size_t new_len;
	int new_updated;
	int write;
	loff_t *ppos;
	u64 tmp_reg;
};

struct bpf_sockopt_kern {
	struct sock *sk;
	u8 *optval;
	u8 *optval_end;
	s32 level;
	s32 optname;
	s32 optlen;
	struct task_struct *current_task;
	u64 tmp_reg;
};

struct bpf_sk_lookup_kern {
	u16 family;
	u16 protocol;
	__be16 sport;
	u16 dport;
	struct {
		__be32 saddr;
		__be32 daddr;
	} v4;
	struct {
		const struct in6_addr *saddr;
		const struct in6_addr *daddr;
	} v6;
	struct sock *selected_sk;
	u32 ingress_ifindex;
	bool no_reuseport;
};

struct btf_id_set {
	u32 cnt;
	u32 ids[0];
};

enum {
	BTF_SOCK_TYPE_INET = 0,
	BTF_SOCK_TYPE_INET_CONN = 1,
	BTF_SOCK_TYPE_INET_REQ = 2,
	BTF_SOCK_TYPE_INET_TW = 3,
	BTF_SOCK_TYPE_REQ = 4,
	BTF_SOCK_TYPE_SOCK = 5,
	BTF_SOCK_TYPE_SOCK_COMMON = 6,
	BTF_SOCK_TYPE_TCP = 7,
	BTF_SOCK_TYPE_TCP_REQ = 8,
	BTF_SOCK_TYPE_TCP_TW = 9,
	BTF_SOCK_TYPE_TCP6 = 10,
	BTF_SOCK_TYPE_UDP = 11,
	BTF_SOCK_TYPE_UDP6 = 12,
	BTF_SOCK_TYPE_UNIX = 13,
	BTF_SOCK_TYPE_MPTCP = 14,
	BTF_SOCK_TYPE_SOCKET = 15,
	MAX_BTF_SOCK_TYPE = 16,
};

enum {
	NEIGH_VAR_MCAST_PROBES = 0,
	NEIGH_VAR_UCAST_PROBES = 1,
	NEIGH_VAR_APP_PROBES = 2,
	NEIGH_VAR_MCAST_REPROBES = 3,
	NEIGH_VAR_RETRANS_TIME = 4,
	NEIGH_VAR_BASE_REACHABLE_TIME = 5,
	NEIGH_VAR_DELAY_PROBE_TIME = 6,
	NEIGH_VAR_INTERVAL_PROBE_TIME_MS = 7,
	NEIGH_VAR_GC_STALETIME = 8,
	NEIGH_VAR_QUEUE_LEN_BYTES = 9,
	NEIGH_VAR_PROXY_QLEN = 10,
	NEIGH_VAR_ANYCAST_DELAY = 11,
	NEIGH_VAR_PROXY_DELAY = 12,
	NEIGH_VAR_LOCKTIME = 13,
	NEIGH_VAR_QUEUE_LEN = 14,
	NEIGH_VAR_RETRANS_TIME_MS = 15,
	NEIGH_VAR_BASE_REACHABLE_TIME_MS = 16,
	NEIGH_VAR_GC_INTERVAL = 17,
	NEIGH_VAR_GC_THRESH1 = 18,
	NEIGH_VAR_GC_THRESH2 = 19,
	NEIGH_VAR_GC_THRESH3 = 20,
	NEIGH_VAR_MAX = 21,
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

struct lwtunnel_state {
	__u16 type;
	__u16 flags;
	__u16 headroom;
	atomic_t refcnt;
	int (*orig_output)(struct net *, struct sock *, struct sk_buff *);
	int (*orig_input)(struct sk_buff *);
	struct callback_head rcu;
	__u8 data[0];
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

struct sock_reuseport {
	struct callback_head rcu;
	u16 max_socks;
	u16 num_socks;
	u16 num_closed_socks;
	unsigned int synq_overflow_ts;
	unsigned int reuseport_id;
	unsigned int bind_inany: 1;
	unsigned int has_conns: 1;
	struct bpf_prog *prog;
	struct sock *socks[0];
};

struct sk_psock_progs {
	struct bpf_prog *msg_parser;
	struct bpf_prog *stream_parser;
	struct bpf_prog *stream_verdict;
	struct bpf_prog *skb_verdict;
};

struct strp_stats {
	long long unsigned int msgs;
	long long unsigned int bytes;
	unsigned int mem_fail;
	unsigned int need_more_hdr;
	unsigned int msg_too_big;
	unsigned int msg_timeouts;
	unsigned int bad_hdr_len;
};

struct strparser;

struct strp_callbacks {
	int (*parse_msg)(struct strparser *, struct sk_buff *);
	void (*rcv_msg)(struct strparser *, struct sk_buff *);
	int (*read_sock_done)(struct strparser *, int);
	void (*abort_parser)(struct strparser *, int);
	void (*lock)(struct strparser *);
	void (*unlock)(struct strparser *);
};

struct strparser {
	struct sock *sk;
	u32 stopped: 1;
	u32 paused: 1;
	u32 aborted: 1;
	u32 interrupted: 1;
	u32 unrecov_intr: 1;
	struct sk_buff **skb_nextp;
	struct sk_buff *skb_head;
	unsigned int need_bytes;
	struct delayed_work msg_timer_work;
	struct work_struct work;
	struct strp_stats stats;
	struct strp_callbacks cb;
};

struct sk_psock_work_state {
	struct sk_buff *skb;
	u32 len;
	u32 off;
};

struct sk_msg;

struct sk_psock {
	struct sock *sk;
	struct sock *sk_redir;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 eval;
	struct sk_msg *cork;
	struct sk_psock_progs progs;
	struct strparser strp;
	struct sk_buff_head ingress_skb;
	struct list_head ingress_msg;
	spinlock_t ingress_lock;
	long unsigned int state;
	struct list_head link;
	spinlock_t link_lock;
	refcount_t refcnt;
	void (*saved_unhash)(struct sock *);
	void (*saved_destroy)(struct sock *);
	void (*saved_close)(struct sock *, long int);
	void (*saved_write_space)(struct sock *);
	void (*saved_data_ready)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	struct proto *sk_proto;
	struct mutex work_mutex;
	struct sk_psock_work_state work_state;
	struct work_struct work;
	struct rcu_work rwork;
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

enum {
	__ND_OPT_PREFIX_INFO_END = 0,
	ND_OPT_SOURCE_LL_ADDR = 1,
	ND_OPT_TARGET_LL_ADDR = 2,
	ND_OPT_PREFIX_INFO = 3,
	ND_OPT_REDIRECT_HDR = 4,
	ND_OPT_MTU = 5,
	ND_OPT_NONCE = 14,
	__ND_OPT_ARRAY_MAX = 15,
	ND_OPT_ROUTE_INFO = 24,
	ND_OPT_RDNSS = 25,
	ND_OPT_DNSSL = 31,
	ND_OPT_6CO = 34,
	ND_OPT_CAPTIVE_PORTAL = 37,
	ND_OPT_PREF64 = 38,
	__ND_OPT_MAX = 39,
};

struct nd_opt_hdr {
	__u8 nd_opt_type;
	__u8 nd_opt_len;
};

struct ndisc_options {
	struct nd_opt_hdr *nd_opt_array[15];
	struct nd_opt_hdr *nd_opts_ri;
	struct nd_opt_hdr *nd_opts_ri_end;
	struct nd_opt_hdr *nd_useropts;
	struct nd_opt_hdr *nd_useropts_end;
	struct nd_opt_hdr *nd_802154_opt_array[3];
};

struct prefix_info {
	__u8 type;
	__u8 length;
	__u8 prefix_len;
	__u8 reserved: 6;
	__u8 autoconf: 1;
	__u8 onlink: 1;
	__be32 valid;
	__be32 prefered;
	__be32 reserved2;
	struct in6_addr prefix;
};

struct inet_ehash_bucket {
	struct hlist_nulls_head chain;
};

struct inet_bind_hashbucket {
	spinlock_t lock;
	struct hlist_head chain;
};

struct inet_listen_hashbucket {
	spinlock_t lock;
	struct hlist_nulls_head nulls_head;
};

struct bpf_storage_buffer {
	struct callback_head rcu;
	char data[0];
};

struct ack_sample {
	u32 pkts_acked;
	s32 rtt_us;
	u32 in_flight;
};

struct rate_sample {
	u64 prior_mstamp;
	u32 prior_delivered;
	u32 prior_delivered_ce;
	s32 delivered;
	s32 delivered_ce;
	long int interval_us;
	u32 snd_interval_us;
	u32 rcv_interval_us;
	long int rtt_us;
	int losses;
	u32 acked_sacked;
	u32 prior_in_flight;
	u32 last_end_seq;
	bool is_app_limited;
	bool is_retrans;
	bool is_ack_delayed;
};

struct sk_msg_sg {
	u32 start;
	u32 curr;
	u32 end;
	u32 size;
	u32 copybreak;
	long unsigned int copy[1];
	struct scatterlist data[19];
};

struct sk_msg {
	struct sk_msg_sg sg;
	void *data;
	void *data_end;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 flags;
	struct sk_buff *skb;
	struct sock *sk_redir;
	struct sock *sk;
	struct list_head list;
};

struct bpf_perf_event_data_kern {
	bpf_user_pt_regs_t *regs;
	struct perf_sample_data *data;
	struct perf_event *event;
};

struct bpf_core_cand {
	const struct btf *btf;
	__u32 id;
};

struct bpf_core_cand_list {
	struct bpf_core_cand *cands;
	int len;
};

struct bpf_core_accessor {
	__u32 type_id;
	__u32 idx;
	const char *name;
};

struct bpf_core_spec {
	const struct btf *btf;
	struct bpf_core_accessor spec[64];
	__u32 root_type_id;
	enum bpf_core_relo_kind relo_kind;
	int len;
	int raw_spec[64];
	int raw_len;
	__u32 bit_offset;
};

struct bpf_core_relo_res {
	__u64 orig_val;
	__u64 new_val;
	bool poison;
	bool validate;
	bool fail_memsz_adjust;
	__u32 orig_sz;
	__u32 orig_type_id;
	__u32 new_sz;
	__u32 new_type_id;
};

enum btf_kfunc_hook {
	BTF_KFUNC_HOOK_XDP = 0,
	BTF_KFUNC_HOOK_TC = 1,
	BTF_KFUNC_HOOK_STRUCT_OPS = 2,
	BTF_KFUNC_HOOK_TRACING = 3,
	BTF_KFUNC_HOOK_SYSCALL = 4,
	BTF_KFUNC_HOOK_MAX = 5,
};

enum {
	BTF_KFUNC_SET_MAX_CNT = 32,
	BTF_DTOR_KFUNC_MAX_CNT = 256,
};

struct btf_kfunc_set_tab {
	struct btf_id_set8 *sets[5];
};

struct btf_id_dtor_kfunc_tab {
	u32 cnt;
	struct btf_id_dtor_kfunc dtors[0];
};

enum verifier_phase {
	CHECK_META = 0,
	CHECK_TYPE = 1,
};

struct resolve_vertex {
	const struct btf_type *t;
	u32 type_id;
	u16 next_member;
};

enum visit_state {
	NOT_VISITED = 0,
	VISITED = 1,
	RESOLVED = 2,
};

enum resolve_mode {
	RESOLVE_TBD = 0,
	RESOLVE_PTR = 1,
	RESOLVE_STRUCT_OR_ARRAY = 2,
};

struct btf_sec_info {
	u32 off;
	u32 len;
};

struct btf_verifier_env {
	struct btf *btf;
	u8 *visit_states;
	struct resolve_vertex stack[32];
	struct bpf_verifier_log log;
	u32 log_type_id;
	u32 top_stack;
	enum verifier_phase phase;
	enum resolve_mode resolve_mode;
};

struct btf_show {
	u64 flags;
	void *target;
	void (*showfn)(struct btf_show *, const char *, va_list);
	const struct btf *btf;
	struct {
		u8 depth;
		u8 depth_to_show;
		u8 depth_check;
		u8 array_member: 1;
		u8 array_terminated: 1;
		u16 array_encoding;
		u32 type_id;
		int status;
		const struct btf_type *type;
		const struct btf_member *member;
		char name[80];
	} state;
	struct {
		u32 size;
		void *head;
		void *data;
		u8 safe[32];
	} obj;
};

struct btf_kind_operations {
	s32 (*check_meta)(struct btf_verifier_env *, const struct btf_type *, u32);
	int (*resolve)(struct btf_verifier_env *, const struct resolve_vertex *);
	int (*check_member)(struct btf_verifier_env *, const struct btf_type *, const struct btf_member *, const struct btf_type *);
	int (*check_kflag_member)(struct btf_verifier_env *, const struct btf_type *, const struct btf_member *, const struct btf_type *);
	void (*log_details)(struct btf_verifier_env *, const struct btf_type *);
	void (*show)(const struct btf *, const struct btf_type *, u32, void *, u8, struct btf_show *);
};

enum btf_field_type {
	BTF_FIELD_SPIN_LOCK = 0,
	BTF_FIELD_TIMER = 1,
	BTF_FIELD_KPTR = 2,
};

enum {
	BTF_FIELD_IGNORE = 0,
	BTF_FIELD_FOUND = 1,
};

struct btf_field_info {
	u32 type_id;
	u32 off;
	enum bpf_kptr_type type;
};

struct bpf_ctx_convert {
	struct __sk_buff BPF_PROG_TYPE_SOCKET_FILTER_prog;
	struct sk_buff BPF_PROG_TYPE_SOCKET_FILTER_kern;
	struct __sk_buff BPF_PROG_TYPE_SCHED_CLS_prog;
	struct sk_buff BPF_PROG_TYPE_SCHED_CLS_kern;
	struct __sk_buff BPF_PROG_TYPE_SCHED_ACT_prog;
	struct sk_buff BPF_PROG_TYPE_SCHED_ACT_kern;
	struct xdp_md BPF_PROG_TYPE_XDP_prog;
	struct xdp_buff BPF_PROG_TYPE_XDP_kern;
	struct __sk_buff BPF_PROG_TYPE_CGROUP_SKB_prog;
	struct sk_buff BPF_PROG_TYPE_CGROUP_SKB_kern;
	struct bpf_sock BPF_PROG_TYPE_CGROUP_SOCK_prog;
	struct sock BPF_PROG_TYPE_CGROUP_SOCK_kern;
	struct bpf_sock_addr BPF_PROG_TYPE_CGROUP_SOCK_ADDR_prog;
	struct bpf_sock_addr_kern BPF_PROG_TYPE_CGROUP_SOCK_ADDR_kern;
	struct __sk_buff BPF_PROG_TYPE_LWT_IN_prog;
	struct sk_buff BPF_PROG_TYPE_LWT_IN_kern;
	struct __sk_buff BPF_PROG_TYPE_LWT_OUT_prog;
	struct sk_buff BPF_PROG_TYPE_LWT_OUT_kern;
	struct __sk_buff BPF_PROG_TYPE_LWT_XMIT_prog;
	struct sk_buff BPF_PROG_TYPE_LWT_XMIT_kern;
	struct __sk_buff BPF_PROG_TYPE_LWT_SEG6LOCAL_prog;
	struct sk_buff BPF_PROG_TYPE_LWT_SEG6LOCAL_kern;
	struct bpf_sock_ops BPF_PROG_TYPE_SOCK_OPS_prog;
	struct bpf_sock_ops_kern BPF_PROG_TYPE_SOCK_OPS_kern;
	struct __sk_buff BPF_PROG_TYPE_SK_SKB_prog;
	struct sk_buff BPF_PROG_TYPE_SK_SKB_kern;
	struct sk_msg_md BPF_PROG_TYPE_SK_MSG_prog;
	struct sk_msg BPF_PROG_TYPE_SK_MSG_kern;
	struct __sk_buff BPF_PROG_TYPE_FLOW_DISSECTOR_prog;
	struct bpf_flow_dissector BPF_PROG_TYPE_FLOW_DISSECTOR_kern;
	bpf_user_pt_regs_t BPF_PROG_TYPE_KPROBE_prog;
	struct pt_regs BPF_PROG_TYPE_KPROBE_kern;
	__u64 BPF_PROG_TYPE_TRACEPOINT_prog;
	u64 BPF_PROG_TYPE_TRACEPOINT_kern;
	struct bpf_perf_event_data BPF_PROG_TYPE_PERF_EVENT_prog;
	struct bpf_perf_event_data_kern BPF_PROG_TYPE_PERF_EVENT_kern;
	struct bpf_raw_tracepoint_args BPF_PROG_TYPE_RAW_TRACEPOINT_prog;
	u64 BPF_PROG_TYPE_RAW_TRACEPOINT_kern;
	struct bpf_raw_tracepoint_args BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE_prog;
	u64 BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE_kern;
	void *BPF_PROG_TYPE_TRACING_prog;
	void *BPF_PROG_TYPE_TRACING_kern;
	struct bpf_cgroup_dev_ctx BPF_PROG_TYPE_CGROUP_DEVICE_prog;
	struct bpf_cgroup_dev_ctx BPF_PROG_TYPE_CGROUP_DEVICE_kern;
	struct bpf_sysctl BPF_PROG_TYPE_CGROUP_SYSCTL_prog;
	struct bpf_sysctl_kern BPF_PROG_TYPE_CGROUP_SYSCTL_kern;
	struct bpf_sockopt BPF_PROG_TYPE_CGROUP_SOCKOPT_prog;
	struct bpf_sockopt_kern BPF_PROG_TYPE_CGROUP_SOCKOPT_kern;
	__u32 BPF_PROG_TYPE_LIRC_MODE2_prog;
	u32 BPF_PROG_TYPE_LIRC_MODE2_kern;
	struct sk_reuseport_md BPF_PROG_TYPE_SK_REUSEPORT_prog;
	struct sk_reuseport_kern BPF_PROG_TYPE_SK_REUSEPORT_kern;
	struct bpf_sk_lookup BPF_PROG_TYPE_SK_LOOKUP_prog;
	struct bpf_sk_lookup_kern BPF_PROG_TYPE_SK_LOOKUP_kern;
	void *BPF_PROG_TYPE_STRUCT_OPS_prog;
	void *BPF_PROG_TYPE_STRUCT_OPS_kern;
	void *BPF_PROG_TYPE_EXT_prog;
	void *BPF_PROG_TYPE_EXT_kern;
	void *BPF_PROG_TYPE_LSM_prog;
	void *BPF_PROG_TYPE_LSM_kern;
	void *BPF_PROG_TYPE_SYSCALL_prog;
	void *BPF_PROG_TYPE_SYSCALL_kern;
};

enum {
	__ctx_convertBPF_PROG_TYPE_SOCKET_FILTER = 0,
	__ctx_convertBPF_PROG_TYPE_SCHED_CLS = 1,
	__ctx_convertBPF_PROG_TYPE_SCHED_ACT = 2,
	__ctx_convertBPF_PROG_TYPE_XDP = 3,
	__ctx_convertBPF_PROG_TYPE_CGROUP_SKB = 4,
	__ctx_convertBPF_PROG_TYPE_CGROUP_SOCK = 5,
	__ctx_convertBPF_PROG_TYPE_CGROUP_SOCK_ADDR = 6,
	__ctx_convertBPF_PROG_TYPE_LWT_IN = 7,
	__ctx_convertBPF_PROG_TYPE_LWT_OUT = 8,
	__ctx_convertBPF_PROG_TYPE_LWT_XMIT = 9,
	__ctx_convertBPF_PROG_TYPE_LWT_SEG6LOCAL = 10,
	__ctx_convertBPF_PROG_TYPE_SOCK_OPS = 11,
	__ctx_convertBPF_PROG_TYPE_SK_SKB = 12,
	__ctx_convertBPF_PROG_TYPE_SK_MSG = 13,
	__ctx_convertBPF_PROG_TYPE_FLOW_DISSECTOR = 14,
	__ctx_convertBPF_PROG_TYPE_KPROBE = 15,
	__ctx_convertBPF_PROG_TYPE_TRACEPOINT = 16,
	__ctx_convertBPF_PROG_TYPE_PERF_EVENT = 17,
	__ctx_convertBPF_PROG_TYPE_RAW_TRACEPOINT = 18,
	__ctx_convertBPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 19,
	__ctx_convertBPF_PROG_TYPE_TRACING = 20,
	__ctx_convertBPF_PROG_TYPE_CGROUP_DEVICE = 21,
	__ctx_convertBPF_PROG_TYPE_CGROUP_SYSCTL = 22,
	__ctx_convertBPF_PROG_TYPE_CGROUP_SOCKOPT = 23,
	__ctx_convertBPF_PROG_TYPE_LIRC_MODE2 = 24,
	__ctx_convertBPF_PROG_TYPE_SK_REUSEPORT = 25,
	__ctx_convertBPF_PROG_TYPE_SK_LOOKUP = 26,
	__ctx_convertBPF_PROG_TYPE_STRUCT_OPS = 27,
	__ctx_convertBPF_PROG_TYPE_EXT = 28,
	__ctx_convertBPF_PROG_TYPE_LSM = 29,
	__ctx_convertBPF_PROG_TYPE_SYSCALL = 30,
	__ctx_convert_unused = 31,
};

enum bpf_struct_walk_result {
	WALK_SCALAR = 0,
	WALK_PTR = 1,
	WALK_STRUCT = 2,
};

struct btf_show_snprintf {
	struct btf_show show;
	int len_left;
	int len;
};

enum {
	BTF_MODULE_F_LIVE = 1,
};

struct btf_module {
	struct list_head list;
	struct module *module;
	struct btf *btf;
	struct bin_attribute *sysfs_attr;
	int flags;
};

typedef u64 (*btf_bpf_btf_find_by_name_kind)(char *, int, u32, int);

struct bpf_cand_cache {
	const char *name;
	u32 name_len;
	u16 kind;
	u16 cnt;
	struct {
		const struct btf *btf;
		u32 id;
	} cands[0];
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

struct perf_event_header {
	__u32 type;
	__u16 misc;
	__u16 size;
};

enum perf_event_type {
	PERF_RECORD_MMAP = 1,
	PERF_RECORD_LOST = 2,
	PERF_RECORD_COMM = 3,
	PERF_RECORD_EXIT = 4,
	PERF_RECORD_THROTTLE = 5,
	PERF_RECORD_UNTHROTTLE = 6,
	PERF_RECORD_FORK = 7,
	PERF_RECORD_READ = 8,
	PERF_RECORD_SAMPLE = 9,
	PERF_RECORD_MMAP2 = 10,
	PERF_RECORD_AUX = 11,
	PERF_RECORD_ITRACE_START = 12,
	PERF_RECORD_LOST_SAMPLES = 13,
	PERF_RECORD_SWITCH = 14,
	PERF_RECORD_SWITCH_CPU_WIDE = 15,
	PERF_RECORD_NAMESPACES = 16,
	PERF_RECORD_KSYMBOL = 17,
	PERF_RECORD_BPF_EVENT = 18,
	PERF_RECORD_CGROUP = 19,
	PERF_RECORD_TEXT_POKE = 20,
	PERF_RECORD_AUX_OUTPUT_HW_ID = 21,
	PERF_RECORD_MAX = 22,
};

struct perf_buffer {
	refcount_t refcount;
	struct callback_head callback_head;
	int nr_pages;
	int overwrite;
	int paused;
	atomic_t poll;
	local_t head;
	unsigned int nest;
	local_t events;
	local_t wakeup;
	local_t lost;
	long int watermark;
	long int aux_watermark;
	spinlock_t event_lock;
	struct list_head event_list;
	atomic_t mmap_count;
	long unsigned int mmap_locked;
	struct user_struct *mmap_user;
	long int aux_head;
	unsigned int aux_nest;
	long int aux_wakeup;
	long unsigned int aux_pgoff;
	int aux_nr_pages;
	int aux_overwrite;
	atomic_t aux_mmap_count;
	long unsigned int aux_mmap_locked;
	void (*free_aux)(void *);
	refcount_t aux_refcount;
	int aux_in_sampling;
	void **aux_pages;
	void *aux_priv;
	struct perf_event_mmap_page *user_page;
	void *data_pages[0];
};

struct mem_section_usage {
	long unsigned int subsection_map[1];
	long unsigned int pageblock_flags[0];
};

struct page_ext;

struct mem_section {
	long unsigned int section_mem_map;
	struct mem_section_usage *usage;
	struct page_ext *page_ext;
	long unsigned int pad;
};

struct page_ext {
	long unsigned int flags;
};

enum {
	SECTION_MARKED_PRESENT_BIT = 0,
	SECTION_HAS_MEM_MAP_BIT = 1,
	SECTION_IS_ONLINE_BIT = 2,
	SECTION_IS_EARLY_BIT = 3,
	SECTION_TAINT_ZONE_DEVICE_BIT = 4,
	SECTION_MAP_LAST_BIT = 5,
};

enum {
	MEMREMAP_WB = 1,
	MEMREMAP_WT = 2,
	MEMREMAP_WC = 4,
	MEMREMAP_ENC = 8,
	MEMREMAP_DEC = 16,
};

struct __key_reference_with_attributes;

typedef struct __key_reference_with_attributes *key_ref_t;

enum blacklist_hash_type {
	BLACKLIST_HASH_X509_TBS = 1,
	BLACKLIST_HASH_BINARY = 2,
};

struct anon_vma {
	struct anon_vma *root;
	struct rw_semaphore rwsem;
	atomic_t refcount;
	long unsigned int num_children;
	long unsigned int num_active_vmas;
	struct anon_vma *parent;
	struct rb_root_cached rb_root;
};

typedef struct pglist_data pg_data_t;

struct compact_control;

struct capture_control {
	struct compact_control *cc;
	struct page *page;
};

struct vm_event_state {
	long unsigned int event[109];
};

enum page_memcg_data_flags {
	MEMCG_DATA_OBJCGS = 1,
	MEMCG_DATA_KMEM = 2,
	__NR_MEMCG_DATA_FLAGS = 4,
};

enum mapping_flags {
	AS_EIO = 0,
	AS_ENOSPC = 1,
	AS_MM_ALL_LOCKS = 2,
	AS_UNEVICTABLE = 3,
	AS_EXITING = 4,
	AS_NO_WRITEBACK_TAGS = 5,
	AS_LARGE_FOLIO_SUPPORT = 6,
};

struct pagevec {
	unsigned char nr;
	bool percpu_pvec_drained;
	struct page *pages[15];
};

struct folio_batch {
	unsigned char nr;
	bool percpu_pvec_drained;
	struct folio *folios[15];
};

struct compact_control {
	struct list_head freepages;
	struct list_head migratepages;
	unsigned int nr_freepages;
	unsigned int nr_migratepages;
	long unsigned int free_pfn;
	long unsigned int migrate_pfn;
	long unsigned int fast_start_pfn;
	struct zone *zone;
	long unsigned int total_migrate_scanned;
	long unsigned int total_free_scanned;
	short unsigned int fast_search_fail;
	short int search_order;
	const gfp_t gfp_mask;
	int order;
	int migratetype;
	const unsigned int alloc_flags;
	const int highest_zoneidx;
	enum migrate_mode mode;
	bool ignore_skip_hint;
	bool no_set_skip_hint;
	bool ignore_block_suitable;
	bool direct_compaction;
	bool proactive_compaction;
	bool whole_zone;
	bool contended;
	bool rescan;
	bool alloc_contig;
};

struct trace_event_raw_mm_lru_insertion {
	struct trace_entry ent;
	struct folio *folio;
	long unsigned int pfn;
	enum lru_list lru;
	long unsigned int flags;
	char __data[0];
};

struct trace_event_raw_mm_lru_activate {
	struct trace_entry ent;
	struct folio *folio;
	long unsigned int pfn;
	char __data[0];
};

struct trace_event_data_offsets_mm_lru_insertion {};

struct trace_event_data_offsets_mm_lru_activate {};

typedef void (*btf_trace_mm_lru_insertion)(void *, struct folio *);

typedef void (*btf_trace_mm_lru_activate)(void *, struct folio *);

struct lru_rotate {
	local_lock_t lock;
	struct folio_batch fbatch;
};

struct cpu_fbatches {
	local_lock_t lock;
	struct folio_batch lru_add;
	struct folio_batch lru_deactivate_file;
	struct folio_batch lru_deactivate;
	struct folio_batch lru_lazyfree;
	struct folio_batch activate;
};

typedef void (*move_fn_t)(struct lruvec *, struct folio *);

struct reciprocal_value {
	u32 m;
	u8 sh1;
	u8 sh2;
};

struct kmem_cache_order_objects {
	unsigned int x;
};

struct kmem_cache_cpu;

struct kmem_cache_node;

struct kmem_cache {
	struct kmem_cache_cpu *cpu_slab;
	slab_flags_t flags;
	long unsigned int min_partial;
	unsigned int size;
	unsigned int object_size;
	struct reciprocal_value reciprocal_size;
	unsigned int offset;
	unsigned int cpu_partial;
	unsigned int cpu_partial_slabs;
	struct kmem_cache_order_objects oo;
	struct kmem_cache_order_objects min;
	gfp_t allocflags;
	int refcount;
	void (*ctor)(void *);
	unsigned int inuse;
	unsigned int align;
	unsigned int red_left_pad;
	const char *name;
	struct list_head list;
	struct kobject kobj;
	long unsigned int random;
	unsigned int remote_node_defrag_ratio;
	unsigned int *random_seq;
	unsigned int useroffset;
	unsigned int usersize;
	struct kmem_cache_node *node[512];
};

enum {
	PROC_ENTRY_PERMANENT = 1,
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

struct slab {
	long unsigned int __page_flags;
	union {
		struct list_head slab_list;
		struct callback_head callback_head;
		struct {
			struct slab *next;
			int slabs;
		};
	};
	struct kmem_cache *slab_cache;
	void *freelist;
	union {
		long unsigned int counters;
		struct {
			unsigned int inuse: 16;
			unsigned int objects: 15;
			unsigned int frozen: 1;
		};
	};
	unsigned int __unused;
	atomic_t __page_refcount;
	long unsigned int memcg_data;
};

struct kmem_cache_cpu {
	void **freelist;
	long unsigned int tid;
	struct slab *slab;
	struct slab *partial;
	local_lock_t lock;
};

struct kmem_cache_node {
	spinlock_t list_lock;
	long unsigned int nr_partial;
	struct list_head partial;
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
};

enum slab_state {
	DOWN = 0,
	PARTIAL = 1,
	PARTIAL_NODE = 2,
	UP = 3,
	FULL = 4,
};

struct kmalloc_info_struct {
	const char *name[4];
	unsigned int size;
};

struct slabinfo {
	long unsigned int active_objs;
	long unsigned int num_objs;
	long unsigned int active_slabs;
	long unsigned int num_slabs;
	long unsigned int shared_avail;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int shared;
	unsigned int objects_per_slab;
	unsigned int cache_order;
};

struct kmem_obj_info {
	void *kp_ptr;
	struct slab *kp_slab;
	void *kp_objp;
	long unsigned int kp_data_offset;
	struct kmem_cache *kp_slab_cache;
	void *kp_ret;
	void *kp_stack[16];
	void *kp_free_stack[16];
};

enum compact_priority {
	COMPACT_PRIO_SYNC_FULL = 0,
	MIN_COMPACT_PRIORITY = 0,
	COMPACT_PRIO_SYNC_LIGHT = 1,
	MIN_COMPACT_COSTLY_PRIORITY = 1,
	DEF_COMPACT_PRIORITY = 1,
	COMPACT_PRIO_ASYNC = 2,
	INIT_COMPACT_PRIORITY = 2,
};

enum compact_result {
	COMPACT_NOT_SUITABLE_ZONE = 0,
	COMPACT_SKIPPED = 1,
	COMPACT_DEFERRED = 2,
	COMPACT_NO_SUITABLE_PAGE = 3,
	COMPACT_CONTINUE = 4,
	COMPACT_COMPLETE = 5,
	COMPACT_PARTIAL_SKIPPED = 6,
	COMPACT_CONTENDED = 7,
	COMPACT_SUCCESS = 8,
};

struct trace_event_raw_kmem_alloc {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	size_t bytes_req;
	size_t bytes_alloc;
	long unsigned int gfp_flags;
	bool accounted;
	char __data[0];
};

struct trace_event_raw_kmem_alloc_node {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	size_t bytes_req;
	size_t bytes_alloc;
	long unsigned int gfp_flags;
	int node;
	bool accounted;
	char __data[0];
};

struct trace_event_raw_kfree {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	char __data[0];
};

struct trace_event_raw_kmem_cache_free {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_mm_page_free {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	char __data[0];
};

struct trace_event_raw_mm_page_free_batched {
	struct trace_entry ent;
	long unsigned int pfn;
	char __data[0];
};

struct trace_event_raw_mm_page_alloc {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	long unsigned int gfp_flags;
	int migratetype;
	char __data[0];
};

struct trace_event_raw_mm_page {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	int migratetype;
	int percpu_refill;
	char __data[0];
};

struct trace_event_raw_mm_page_pcpu_drain {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	int migratetype;
	char __data[0];
};

struct trace_event_raw_mm_page_alloc_extfrag {
	struct trace_entry ent;
	long unsigned int pfn;
	int alloc_order;
	int fallback_order;
	int alloc_migratetype;
	int fallback_migratetype;
	int change_ownership;
	char __data[0];
};

struct trace_event_raw_rss_stat {
	struct trace_entry ent;
	unsigned int mm_id;
	unsigned int curr;
	int member;
	long int size;
	char __data[0];
};

struct trace_event_data_offsets_kmem_alloc {};

struct trace_event_data_offsets_kmem_alloc_node {};

struct trace_event_data_offsets_kfree {};

struct trace_event_data_offsets_kmem_cache_free {
	u32 name;
};

struct trace_event_data_offsets_mm_page_free {};

struct trace_event_data_offsets_mm_page_free_batched {};

struct trace_event_data_offsets_mm_page_alloc {};

struct trace_event_data_offsets_mm_page {};

struct trace_event_data_offsets_mm_page_pcpu_drain {};

struct trace_event_data_offsets_mm_page_alloc_extfrag {};

struct trace_event_data_offsets_rss_stat {};

typedef void (*btf_trace_kmalloc)(void *, long unsigned int, const void *, struct kmem_cache *, size_t, size_t, gfp_t);

typedef void (*btf_trace_kmem_cache_alloc)(void *, long unsigned int, const void *, struct kmem_cache *, size_t, size_t, gfp_t);

typedef void (*btf_trace_kmalloc_node)(void *, long unsigned int, const void *, struct kmem_cache *, size_t, size_t, gfp_t, int);

typedef void (*btf_trace_kmem_cache_alloc_node)(void *, long unsigned int, const void *, struct kmem_cache *, size_t, size_t, gfp_t, int);

typedef void (*btf_trace_kfree)(void *, long unsigned int, const void *);

typedef void (*btf_trace_kmem_cache_free)(void *, long unsigned int, const void *, const char *);

typedef void (*btf_trace_mm_page_free)(void *, struct page *, unsigned int);

typedef void (*btf_trace_mm_page_free_batched)(void *, struct page *);

typedef void (*btf_trace_mm_page_alloc)(void *, struct page *, unsigned int, gfp_t, int);

typedef void (*btf_trace_mm_page_alloc_zone_locked)(void *, struct page *, unsigned int, int, int);

typedef void (*btf_trace_mm_page_pcpu_drain)(void *, struct page *, unsigned int, int);

typedef void (*btf_trace_mm_page_alloc_extfrag)(void *, struct page *, int, int, int, int);

typedef void (*btf_trace_rss_stat)(void *, struct mm_struct *, int, long int);

typedef long unsigned int vm_flags_t;

typedef struct {
	long unsigned int val;
} swp_entry_t;

enum {
	__PERCPU_REF_ATOMIC = 1,
	__PERCPU_REF_DEAD = 2,
	__PERCPU_REF_ATOMIC_DEAD = 3,
	__PERCPU_REF_FLAG_BITS = 2,
};

enum migrate_reason {
	MR_COMPACTION = 0,
	MR_MEMORY_FAILURE = 1,
	MR_MEMORY_HOTPLUG = 2,
	MR_SYSCALL = 3,
	MR_MEMPOLICY_MBIND = 4,
	MR_NUMA_MISPLACED = 5,
	MR_CONTIG_RANGE = 6,
	MR_LONGTERM_PIN = 7,
	MR_DEMOTION = 8,
	MR_TYPES = 9,
};

typedef struct {
	long unsigned int pd;
} hugepd_t;

typedef struct page *new_page_t(struct page *, long unsigned int);

typedef void free_page_t(struct page *, long unsigned int);

struct migration_target_control {
	int nid;
	nodemask_t *nmask;
	gfp_t gfp_mask;
};

struct follow_page_context {
	struct dev_pagemap *pgmap;
	unsigned int page_mask;
};

struct page_vma_mapped_walk {
	long unsigned int pfn;
	long unsigned int nr_pages;
	long unsigned int pgoff;
	struct vm_area_struct *vma;
	long unsigned int address;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned int flags;
};

struct hugepage_subpool {
	spinlock_t lock;
	long int count;
	long int max_hpages;
	long int used_hpages;
	struct hstate *hstate;
	long int min_hpages;
	long int rsv_hpages;
};

struct hugetlbfs_sb_info {
	long int max_inodes;
	long int free_inodes;
	spinlock_t stat_lock;
	struct hstate *hstate;
	struct hugepage_subpool *spool;
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
};

enum xa_lock_type {
	XA_LOCK_IRQ = 1,
	XA_LOCK_BH = 2,
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

struct kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *, struct kobj_attribute *, char *);
	ssize_t (*store)(struct kobject *, struct kobj_attribute *, const char *, size_t);
};

struct vma_swap_readahead {
	short unsigned int win;
	short unsigned int offset;
	short unsigned int nr_pte;
	pte_t *ptes;
};

struct nodemask_scratch {
	nodemask_t mask1;
	nodemask_t mask2;
};

enum {
	MPOL_DEFAULT = 0,
	MPOL_PREFERRED = 1,
	MPOL_BIND = 2,
	MPOL_INTERLEAVE = 3,
	MPOL_LOCAL = 4,
	MPOL_PREFERRED_MANY = 5,
	MPOL_MAX = 6,
};

struct sp_node {
	struct rb_node nd;
	long unsigned int start;
	long unsigned int end;
	struct mempolicy *policy;
};

struct shared_policy {
	struct rb_root root;
	rwlock_t lock;
};

struct mm_walk;

struct mm_walk_ops {
	int (*pgd_entry)(pgd_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*p4d_entry)(p4d_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pud_entry)(pud_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pmd_entry)(pmd_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pte_entry)(pte_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pte_hole)(long unsigned int, long unsigned int, int, struct mm_walk *);
	int (*hugetlb_entry)(pte_t *, long unsigned int, long unsigned int, long unsigned int, struct mm_walk *);
	int (*test_walk)(long unsigned int, long unsigned int, struct mm_walk *);
	int (*pre_vma)(long unsigned int, long unsigned int, struct mm_walk *);
	void (*post_vma)(struct mm_walk *);
};

enum page_walk_action {
	ACTION_SUBTREE = 0,
	ACTION_CONTINUE = 1,
	ACTION_AGAIN = 2,
};

struct mm_walk {
	const struct mm_walk_ops *ops;
	struct mm_struct *mm;
	pgd_t *pgd;
	struct vm_area_struct *vma;
	enum page_walk_action action;
	bool no_vma;
	void *private;
};

struct mmu_table_batch {
	struct callback_head rcu;
	unsigned int nr;
	void *tables[0];
};

struct mmu_gather_batch {
	struct mmu_gather_batch *next;
	unsigned int nr;
	unsigned int max;
	struct page *pages[0];
};

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
	unsigned int vma_pfn: 1;
	unsigned int batch_count;
	struct mmu_gather_batch *active;
	struct mmu_gather_batch local;
	struct page *__pages[8];
};

struct mempolicy_operations {
	int (*create)(struct mempolicy *, const nodemask_t *);
	void (*rebind)(struct mempolicy *, const nodemask_t *);
};

struct queue_pages {
	struct list_head *pagelist;
	long unsigned int flags;
	nodemask_t *nmask;
	long unsigned int start;
	long unsigned int end;
	struct vm_area_struct *first;
};

typedef struct {
	u64 val;
} pfn_t;

enum transparent_hugepage_flag {
	TRANSPARENT_HUGEPAGE_NEVER_DAX = 0,
	TRANSPARENT_HUGEPAGE_FLAG = 1,
	TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG = 2,
	TRANSPARENT_HUGEPAGE_DEFRAG_DIRECT_FLAG = 3,
	TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_FLAG = 4,
	TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_OR_MADV_FLAG = 5,
	TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG = 6,
	TRANSPARENT_HUGEPAGE_DEFRAG_KHUGEPAGED_FLAG = 7,
	TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_FLAG = 8,
};

enum ttu_flags {
	TTU_SPLIT_HUGE_PMD = 4,
	TTU_IGNORE_MLOCK = 8,
	TTU_SYNC = 16,
	TTU_IGNORE_HWPOISON = 32,
	TTU_BATCH_FLUSH = 64,
	TTU_RMAP_LOCKED = 128,
};

typedef int rmap_t;

struct simple_xattrs {
	struct list_head head;
	spinlock_t lock;
};

struct shmem_inode_info {
	spinlock_t lock;
	unsigned int seals;
	long unsigned int flags;
	long unsigned int alloced;
	long unsigned int swapped;
	long unsigned int fallocend;
	struct list_head shrinklist;
	struct list_head swaplist;
	struct shared_policy policy;
	struct simple_xattrs xattrs;
	atomic_t stop_eviction;
	struct timespec64 i_crtime;
	unsigned int fsflags;
	struct inode vfs_inode;
};

struct trace_event_raw_hugepage_set_pmd {
	struct trace_entry ent;
	long unsigned int addr;
	long unsigned int pmd;
	char __data[0];
};

struct trace_event_raw_hugepage_update {
	struct trace_entry ent;
	long unsigned int addr;
	long unsigned int pte;
	long unsigned int clr;
	long unsigned int set;
	char __data[0];
};

struct trace_event_raw_migration_pmd {
	struct trace_entry ent;
	long unsigned int addr;
	long unsigned int pmd;
	char __data[0];
};

struct trace_event_data_offsets_hugepage_set_pmd {};

struct trace_event_data_offsets_hugepage_update {};

struct trace_event_data_offsets_migration_pmd {};

typedef void (*btf_trace_hugepage_set_pmd)(void *, long unsigned int, long unsigned int);

typedef void (*btf_trace_hugepage_update)(void *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);

typedef void (*btf_trace_set_migration_pmd)(void *, long unsigned int, long unsigned int);

typedef void (*btf_trace_remove_migration_pmd)(void *, long unsigned int, long unsigned int);

typedef unsigned int isolate_mode_t;

struct movable_operations {
	bool (*isolate_page)(struct page *, isolate_mode_t);
	int (*migrate_page)(struct page *, struct page *, enum migrate_mode);
	void (*putback_page)(struct page *);
};

struct balloon_dev_info {
	long unsigned int isolated_pages;
	spinlock_t pages_lock;
	struct list_head pages;
	int (*migratepage)(struct balloon_dev_info *, struct page *, struct page *, enum migrate_mode);
};

struct damon_addr_range {
	long unsigned int start;
	long unsigned int end;
};

struct damon_region {
	struct damon_addr_range ar;
	long unsigned int sampling_addr;
	unsigned int nr_accesses;
	struct list_head list;
	unsigned int age;
	unsigned int last_nr_accesses;
};

struct damon_target {
	struct pid *pid;
	unsigned int nr_regions;
	struct list_head regions_list;
	struct list_head list;
};

enum damos_action {
	DAMOS_WILLNEED = 0,
	DAMOS_COLD = 1,
	DAMOS_PAGEOUT = 2,
	DAMOS_HUGEPAGE = 3,
	DAMOS_NOHUGEPAGE = 4,
	DAMOS_LRU_PRIO = 5,
	DAMOS_LRU_DEPRIO = 6,
	DAMOS_STAT = 7,
	NR_DAMOS_ACTIONS = 8,
};

struct damos_quota {
	long unsigned int ms;
	long unsigned int sz;
	long unsigned int reset_interval;
	unsigned int weight_sz;
	unsigned int weight_nr_accesses;
	unsigned int weight_age;
	long unsigned int total_charged_sz;
	long unsigned int total_charged_ns;
	long unsigned int esz;
	long unsigned int charged_sz;
	long unsigned int charged_from;
	struct damon_target *charge_target_from;
	long unsigned int charge_addr_from;
	long unsigned int histogram[100];
	unsigned int min_score;
};

enum damos_wmark_metric {
	DAMOS_WMARK_NONE = 0,
	DAMOS_WMARK_FREE_MEM_RATE = 1,
	NR_DAMOS_WMARK_METRICS = 2,
};

struct damos_watermarks {
	enum damos_wmark_metric metric;
	long unsigned int interval;
	long unsigned int high;
	long unsigned int mid;
	long unsigned int low;
	bool activated;
};

struct damos_stat {
	long unsigned int nr_tried;
	long unsigned int sz_tried;
	long unsigned int nr_applied;
	long unsigned int sz_applied;
	long unsigned int qt_exceeds;
};

struct damos {
	long unsigned int min_sz_region;
	long unsigned int max_sz_region;
	unsigned int min_nr_accesses;
	unsigned int max_nr_accesses;
	unsigned int min_age_region;
	unsigned int max_age_region;
	enum damos_action action;
	struct damos_quota quota;
	struct damos_watermarks wmarks;
	struct damos_stat stat;
	struct list_head list;
};

enum damon_ops_id {
	DAMON_OPS_VADDR = 0,
	DAMON_OPS_FVADDR = 1,
	DAMON_OPS_PADDR = 2,
	NR_DAMON_OPS = 3,
};

struct damon_ctx;

struct damon_operations {
	enum damon_ops_id id;
	void (*init)(struct damon_ctx *);
	void (*update)(struct damon_ctx *);
	void (*prepare_access_checks)(struct damon_ctx *);
	unsigned int (*check_accesses)(struct damon_ctx *);
	void (*reset_aggregated)(struct damon_ctx *);
	int (*get_scheme_score)(struct damon_ctx *, struct damon_target *, struct damon_region *, struct damos *);
	long unsigned int (*apply_scheme)(struct damon_ctx *, struct damon_target *, struct damon_region *, struct damos *);
	bool (*target_valid)(void *);
	void (*cleanup)(struct damon_ctx *);
};

struct damon_callback {
	void *private;
	int (*before_start)(struct damon_ctx *);
	int (*after_wmarks_check)(struct damon_ctx *);
	int (*after_sampling)(struct damon_ctx *);
	int (*after_aggregation)(struct damon_ctx *);
	void (*before_terminate)(struct damon_ctx *);
};

struct damon_ctx {
	long unsigned int sample_interval;
	long unsigned int aggr_interval;
	long unsigned int ops_update_interval;
	struct timespec64 last_aggregation;
	struct timespec64 last_ops_update;
	struct task_struct *kdamond;
	struct mutex kdamond_lock;
	struct damon_operations ops;
	struct damon_callback callback;
	long unsigned int min_nr_regions;
	long unsigned int max_nr_regions;
	struct list_head adaptive_targets;
	struct list_head schemes;
};

struct damon_young_walk_private {
	long unsigned int *page_sz;
	bool young;
};

struct page_reporting_dev_info {
	int (*report)(struct page_reporting_dev_info *, struct scatterlist *, unsigned int);
	struct delayed_work work;
	atomic_t state;
	unsigned int order;
};

enum {
	PAGE_REPORTING_IDLE = 0,
	PAGE_REPORTING_REQUESTED = 1,
	PAGE_REPORTING_ACTIVE = 2,
};

typedef short unsigned int __kernel_old_uid_t;

typedef short unsigned int __kernel_old_gid_t;

typedef __kernel_old_uid_t old_uid_t;

typedef __kernel_old_gid_t old_gid_t;

struct stat {
	long unsigned int st_dev;
	long unsigned int st_ino;
	unsigned int st_mode;
	unsigned int st_nlink;
	unsigned int st_uid;
	unsigned int st_gid;
	long unsigned int st_rdev;
	long unsigned int __pad1;
	long int st_size;
	int st_blksize;
	int __pad2;
	long int st_blocks;
	long int st_atime;
	long unsigned int st_atime_nsec;
	long int st_mtime;
	long unsigned int st_mtime_nsec;
	long int st_ctime;
	long unsigned int st_ctime_nsec;
	unsigned int __unused4;
	unsigned int __unused5;
};

typedef u16 compat_mode_t;

typedef u32 compat_ino_t;

typedef s32 compat_off_t;

typedef u16 compat_ushort_t;

typedef u32 compat_uint_t;

typedef s64 compat_s64;

typedef u64 compat_u64;

typedef u32 compat_dev_t;

typedef u16 __compat_uid16_t;

typedef u16 __compat_gid16_t;

struct compat_stat {
	compat_dev_t st_dev;
	compat_ino_t st_ino;
	compat_mode_t st_mode;
	compat_ushort_t st_nlink;
	__compat_uid16_t st_uid;
	__compat_gid16_t st_gid;
	compat_dev_t st_rdev;
	compat_off_t st_size;
	compat_off_t st_blksize;
	compat_off_t st_blocks;
	old_time32_t st_atime;
	compat_ulong_t st_atime_nsec;
	old_time32_t st_mtime;
	compat_ulong_t st_mtime_nsec;
	old_time32_t st_ctime;
	compat_ulong_t st_ctime_nsec;
	compat_ulong_t __unused4[2];
};

struct stat64 {
	compat_u64 st_dev;
	unsigned char __pad0[4];
	compat_ulong_t __st_ino;
	compat_uint_t st_mode;
	compat_uint_t st_nlink;
	compat_ulong_t st_uid;
	compat_ulong_t st_gid;
	compat_u64 st_rdev;
	unsigned char __pad3[4];
	compat_s64 st_size;
	compat_ulong_t st_blksize;
	compat_u64 st_blocks;
	compat_ulong_t st_atime;
	compat_ulong_t st_atime_nsec;
	compat_ulong_t st_mtime;
	compat_ulong_t st_mtime_nsec;
	compat_ulong_t st_ctime;
	compat_ulong_t st_ctime_nsec;
	compat_u64 st_ino;
};

struct statx_timestamp {
	__s64 tv_sec;
	__u32 tv_nsec;
	__s32 __reserved;
};

struct statx {
	__u32 stx_mask;
	__u32 stx_blksize;
	__u64 stx_attributes;
	__u32 stx_nlink;
	__u32 stx_uid;
	__u32 stx_gid;
	__u16 stx_mode;
	__u16 __spare0[1];
	__u64 stx_ino;
	__u64 stx_size;
	__u64 stx_blocks;
	__u64 stx_attributes_mask;
	struct statx_timestamp stx_atime;
	struct statx_timestamp stx_btime;
	struct statx_timestamp stx_ctime;
	struct statx_timestamp stx_mtime;
	__u32 stx_rdev_major;
	__u32 stx_rdev_minor;
	__u32 stx_dev_major;
	__u32 stx_dev_minor;
	__u64 stx_mnt_id;
	__u64 __spare2;
	__u64 __spare3[12];
};

struct mount;

struct mnt_namespace {
	struct ns_common ns;
	struct mount *root;
	struct list_head list;
	spinlock_t ns_lock;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	u64 seq;
	wait_queue_head_t poll;
	u64 event;
	unsigned int mounts;
	unsigned int pending_mounts;
};

struct fs_pin {
	wait_queue_head_t wait;
	int done;
	struct hlist_node s_list;
	struct hlist_node m_list;
	void (*kill)(struct fs_pin *);
};

struct mnt_pcp;

struct mountpoint;

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct callback_head mnt_rcu;
		struct llist_node mnt_llist;
	};
	struct mnt_pcp *mnt_pcp;
	struct list_head mnt_mounts;
	struct list_head mnt_child;
	struct list_head mnt_instance;
	const char *mnt_devname;
	struct list_head mnt_list;
	struct list_head mnt_expire;
	struct list_head mnt_share;
	struct list_head mnt_slave_list;
	struct list_head mnt_slave;
	struct mount *mnt_master;
	struct mnt_namespace *mnt_ns;
	struct mountpoint *mnt_mp;
	union {
		struct hlist_node mnt_mp_list;
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting;
	struct fsnotify_mark_connector *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
	int mnt_id;
	int mnt_group_id;
	int mnt_expiry_mark;
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
};

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	struct hlist_head m_list;
	int m_count;
};

enum dentry_d_lock_class {
	DENTRY_D_LOCK_NORMAL = 0,
	DENTRY_D_LOCK_NESTED = 1,
};

struct name_snapshot {
	struct qstr name;
	unsigned char inline_name[32];
};

enum lru_status {
	LRU_REMOVED = 0,
	LRU_REMOVED_RETRY = 1,
	LRU_ROTATE = 2,
	LRU_SKIP = 3,
	LRU_RETRY = 4,
};

typedef enum lru_status (*list_lru_walk_cb)(struct list_head *, struct list_lru_one *, spinlock_t *, void *);

struct fscrypt_policy_v1 {
	__u8 version;
	__u8 contents_encryption_mode;
	__u8 filenames_encryption_mode;
	__u8 flags;
	__u8 master_key_descriptor[8];
};

struct fscrypt_policy_v2 {
	__u8 version;
	__u8 contents_encryption_mode;
	__u8 filenames_encryption_mode;
	__u8 flags;
	__u8 __reserved[4];
	__u8 master_key_identifier[16];
};

union fscrypt_policy {
	u8 version;
	struct fscrypt_policy_v1 v1;
	struct fscrypt_policy_v2 v2;
};

enum fsnotify_data_type {
	FSNOTIFY_EVENT_NONE = 0,
	FSNOTIFY_EVENT_PATH = 1,
	FSNOTIFY_EVENT_INODE = 2,
	FSNOTIFY_EVENT_DENTRY = 3,
	FSNOTIFY_EVENT_ERROR = 4,
};

struct dentry_stat_t {
	long int nr_dentry;
	long int nr_unused;
	long int age_limit;
	long int want_pages;
	long int nr_negative;
	long int dummy;
};

struct external_name {
	union {
		atomic_t count;
		struct callback_head head;
	} u;
	unsigned char name[0];
};

enum d_walk_ret {
	D_WALK_CONTINUE = 0,
	D_WALK_QUIT = 1,
	D_WALK_NORETRY = 2,
	D_WALK_SKIP = 3,
};

struct check_mount {
	struct vfsmount *mnt;
	unsigned int mounted;
};

struct select_data {
	struct dentry *start;
	union {
		long int found;
		struct dentry *victim;
	};
	struct list_head dispose;
};

typedef __kernel_rwf_t rwf_t;

struct splice_desc {
	size_t total_len;
	unsigned int len;
	unsigned int flags;
	union {
		void *userptr;
		struct file *file;
		void *data;
	} u;
	loff_t pos;
	loff_t *opos;
	size_t num_spliced;
	bool need_wakeup;
};

struct partial_page {
	unsigned int offset;
	unsigned int len;
	long unsigned int private;
};

struct splice_pipe_desc {
	struct page **pages;
	struct partial_page *partial;
	int nr_pages;
	unsigned int nr_pages_max;
	const struct pipe_buf_operations *ops;
	void (*spd_release)(struct splice_pipe_desc *, unsigned int);
};

typedef int splice_actor(struct pipe_inode_info *, struct pipe_buffer *, struct splice_desc *);

typedef int splice_direct_actor(struct pipe_inode_info *, struct splice_desc *);

struct va_format {
	const char *fmt;
	va_list *va;
};

struct constant_table {
	const char *name;
	int value;
};

enum legacy_fs_param {
	LEGACY_FS_UNSET_PARAMS = 0,
	LEGACY_FS_MONOLITHIC_PARAMS = 1,
	LEGACY_FS_INDIVIDUAL_PARAMS = 2,
};

struct legacy_fs_context {
	char *legacy_data;
	size_t data_size;
	enum legacy_fs_param param_type;
};

enum fsnotify_iter_type {
	FSNOTIFY_ITER_TYPE_INODE = 0,
	FSNOTIFY_ITER_TYPE_VFSMOUNT = 1,
	FSNOTIFY_ITER_TYPE_SB = 2,
	FSNOTIFY_ITER_TYPE_PARENT = 3,
	FSNOTIFY_ITER_TYPE_INODE2 = 4,
	FSNOTIFY_ITER_TYPE_COUNT = 5,
};

struct sysinfo {
	__kernel_long_t uptime;
	__kernel_ulong_t loads[3];
	__kernel_ulong_t totalram;
	__kernel_ulong_t freeram;
	__kernel_ulong_t sharedram;
	__kernel_ulong_t bufferram;
	__kernel_ulong_t totalswap;
	__kernel_ulong_t freeswap;
	__u16 procs;
	__u16 pad;
	__kernel_ulong_t totalhigh;
	__kernel_ulong_t freehigh;
	__u32 mem_unit;
	char _f[0];
};

struct inotify_event {
	__s32 wd;
	__u32 mask;
	__u32 cookie;
	__u32 len;
	char name[0];
};

typedef struct poll_table_struct poll_table;

struct inotify_event_info {
	struct fsnotify_event fse;
	u32 mask;
	int wd;
	u32 sync_cookie;
	int name_len;
	char name[0];
};

struct inotify_inode_mark {
	struct fsnotify_mark fsn_mark;
	int wd;
};

enum {
	XA_CHECK_SCHED = 4096,
};

typedef long unsigned int dax_entry_t;

enum dax_access_mode {
	DAX_ACCESS = 0,
	DAX_RECOVERY_WRITE = 1,
};

struct dax_device;

struct iomap_page_ops;

struct iomap {
	u64 addr;
	loff_t offset;
	u64 length;
	u16 type;
	u16 flags;
	struct block_device *bdev;
	struct dax_device *dax_dev;
	void *inline_data;
	void *private;
	const struct iomap_page_ops *page_ops;
};

struct iomap_page_ops {
	int (*page_prepare)(struct inode *, loff_t, unsigned int);
	void (*page_done)(struct inode *, loff_t, unsigned int, struct page *);
};

struct iomap_ops {
	int (*iomap_begin)(struct inode *, loff_t, loff_t, unsigned int, struct iomap *, struct iomap *);
	int (*iomap_end)(struct inode *, loff_t, loff_t, ssize_t, unsigned int, struct iomap *);
};

struct iomap_iter {
	struct inode *inode;
	loff_t pos;
	u64 len;
	s64 processed;
	unsigned int flags;
	struct iomap iomap;
	struct iomap srcmap;
	void *private;
};

struct trace_event_raw_dax_pmd_fault_class {
	struct trace_entry ent;
	long unsigned int ino;
	long unsigned int vm_start;
	long unsigned int vm_end;
	long unsigned int vm_flags;
	long unsigned int address;
	long unsigned int pgoff;
	long unsigned int max_pgoff;
	dev_t dev;
	unsigned int flags;
	int result;
	char __data[0];
};

struct trace_event_raw_dax_pmd_load_hole_class {
	struct trace_entry ent;
	long unsigned int ino;
	long unsigned int vm_flags;
	long unsigned int address;
	struct page *zero_page;
	void *radix_entry;
	dev_t dev;
	char __data[0];
};

struct trace_event_raw_dax_pmd_insert_mapping_class {
	struct trace_entry ent;
	long unsigned int ino;
	long unsigned int vm_flags;
	long unsigned int address;
	long int length;
	u64 pfn_val;
	void *radix_entry;
	dev_t dev;
	int write;
	char __data[0];
};

struct trace_event_raw_dax_pte_fault_class {
	struct trace_entry ent;
	long unsigned int ino;
	long unsigned int vm_flags;
	long unsigned int address;
	long unsigned int pgoff;
	dev_t dev;
	unsigned int flags;
	int result;
	char __data[0];
};

struct trace_event_raw_dax_insert_mapping {
	struct trace_entry ent;
	long unsigned int ino;
	long unsigned int vm_flags;
	long unsigned int address;
	void *radix_entry;
	dev_t dev;
	int write;
	char __data[0];
};

struct trace_event_raw_dax_writeback_range_class {
	struct trace_entry ent;
	long unsigned int ino;
	long unsigned int start_index;
	long unsigned int end_index;
	dev_t dev;
	char __data[0];
};

struct trace_event_raw_dax_writeback_one {
	struct trace_entry ent;
	long unsigned int ino;
	long unsigned int pgoff;
	long unsigned int pglen;
	dev_t dev;
	char __data[0];
};

struct trace_event_data_offsets_dax_pmd_fault_class {};

struct trace_event_data_offsets_dax_pmd_load_hole_class {};

struct trace_event_data_offsets_dax_pmd_insert_mapping_class {};

struct trace_event_data_offsets_dax_pte_fault_class {};

struct trace_event_data_offsets_dax_insert_mapping {};

struct trace_event_data_offsets_dax_writeback_range_class {};

struct trace_event_data_offsets_dax_writeback_one {};

typedef void (*btf_trace_dax_pmd_fault)(void *, struct inode *, struct vm_fault *, long unsigned int, int);

typedef void (*btf_trace_dax_pmd_fault_done)(void *, struct inode *, struct vm_fault *, long unsigned int, int);

typedef void (*btf_trace_dax_pmd_load_hole)(void *, struct inode *, struct vm_fault *, struct page *, void *);

typedef void (*btf_trace_dax_pmd_load_hole_fallback)(void *, struct inode *, struct vm_fault *, struct page *, void *);

typedef void (*btf_trace_dax_pmd_insert_mapping)(void *, struct inode *, struct vm_fault *, long int, pfn_t, void *);

typedef void (*btf_trace_dax_pte_fault)(void *, struct inode *, struct vm_fault *, int);

typedef void (*btf_trace_dax_pte_fault_done)(void *, struct inode *, struct vm_fault *, int);

typedef void (*btf_trace_dax_load_hole)(void *, struct inode *, struct vm_fault *, int);

typedef void (*btf_trace_dax_insert_pfn_mkwrite_no_entry)(void *, struct inode *, struct vm_fault *, int);

typedef void (*btf_trace_dax_insert_pfn_mkwrite)(void *, struct inode *, struct vm_fault *, int);

typedef void (*btf_trace_dax_insert_mapping)(void *, struct inode *, struct vm_fault *, void *);

typedef void (*btf_trace_dax_writeback_range)(void *, struct inode *, long unsigned int, long unsigned int);

typedef void (*btf_trace_dax_writeback_range_done)(void *, struct inode *, long unsigned int, long unsigned int);

typedef void (*btf_trace_dax_writeback_one)(void *, struct inode *, long unsigned int, long unsigned int);

struct exceptional_entry_key {
	struct xarray *xa;
	long unsigned int entry_start;
};

struct wait_exceptional_entry_queue {
	wait_queue_entry_t wait;
	struct exceptional_entry_key key;
};

enum dax_wake_mode {
	WAKE_ALL = 0,
	WAKE_NEXT = 1,
};

struct fsverity_hash_alg;

struct merkle_tree_params {
	struct fsverity_hash_alg *hash_alg;
	const u8 *hashstate;
	unsigned int digest_size;
	unsigned int block_size;
	unsigned int hashes_per_block;
	unsigned int log_blocksize;
	unsigned int log_arity;
	unsigned int num_levels;
	u64 tree_size;
	long unsigned int level0_blocks;
	u64 level_start[8];
};

struct fsverity_info {
	struct merkle_tree_params tree_params;
	u8 root_hash[64];
	u8 file_digest[64];
	const struct inode *inode;
};

struct crypto_ahash;

struct fsverity_hash_alg {
	struct crypto_ahash *tfm;
	const char *name;
	unsigned int digest_size;
	unsigned int block_size;
	mempool_t req_pool;
};

struct ahash_request;

struct crypto_ahash {
	int (*init)(struct ahash_request *);
	int (*update)(struct ahash_request *);
	int (*final)(struct ahash_request *);
	int (*finup)(struct ahash_request *);
	int (*digest)(struct ahash_request *);
	int (*export)(struct ahash_request *, void *);
	int (*import)(struct ahash_request *, const void *);
	int (*setkey)(struct crypto_ahash *, const u8 *, unsigned int);
	unsigned int reqsize;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct crypto_tfm base;
};

struct crypto_async_request;

typedef void (*crypto_completion_t)(struct crypto_async_request *, int);

struct crypto_async_request {
	struct list_head list;
	crypto_completion_t complete;
	void *data;
	struct crypto_tfm *tfm;
	u32 flags;
};

struct crypto_wait {
	struct completion completion;
	int err;
};

struct hash_alg_common {
	unsigned int digestsize;
	unsigned int statesize;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct crypto_alg base;
};

struct ahash_request {
	struct crypto_async_request base;
	unsigned int nbytes;
	struct scatterlist *src;
	u8 *result;
	void *priv;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	void *__ctx[0];
};

struct fdtable {
	unsigned int max_fds;
	struct file **fd;
	long unsigned int *close_on_exec;
	long unsigned int *open_fds;
	long unsigned int *full_fds_bits;
	struct callback_head rcu;
};

struct files_struct {
	atomic_t count;
	bool resize_in_progress;
	wait_queue_head_t resize_wait;
	struct fdtable *fdt;
	struct fdtable fdtab;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t file_lock;
	unsigned int next_fd;
	long unsigned int close_on_exec_init[1];
	long unsigned int open_fds_init[1];
	long unsigned int full_fds_bits_init[1];
	struct file *fd_array[64];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct srcu_notifier_head {
	struct mutex mutex;
	struct srcu_struct srcu;
	struct notifier_block *head;
};

struct flock {
	short int l_type;
	short int l_whence;
	__kernel_off_t l_start;
	__kernel_off_t l_len;
	__kernel_pid_t l_pid;
};

struct flock64 {
	short int l_type;
	short int l_whence;
	__kernel_loff_t l_start;
	__kernel_loff_t l_len;
	__kernel_pid_t l_pid;
};

struct trace_event_raw_locks_get_lock_context {
	struct trace_entry ent;
	long unsigned int i_ino;
	dev_t s_dev;
	unsigned char type;
	struct file_lock_context *ctx;
	char __data[0];
};

struct trace_event_raw_filelock_lock {
	struct trace_entry ent;
	struct file_lock *fl;
	long unsigned int i_ino;
	dev_t s_dev;
	struct file_lock *fl_blocker;
	fl_owner_t fl_owner;
	unsigned int fl_pid;
	unsigned int fl_flags;
	unsigned char fl_type;
	loff_t fl_start;
	loff_t fl_end;
	int ret;
	char __data[0];
};

struct trace_event_raw_filelock_lease {
	struct trace_entry ent;
	struct file_lock *fl;
	long unsigned int i_ino;
	dev_t s_dev;
	struct file_lock *fl_blocker;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	char __data[0];
};

struct trace_event_raw_generic_add_lease {
	struct trace_entry ent;
	long unsigned int i_ino;
	int wcount;
	int rcount;
	int icount;
	dev_t s_dev;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	char __data[0];
};

struct trace_event_raw_leases_conflict {
	struct trace_entry ent;
	void *lease;
	void *breaker;
	unsigned int l_fl_flags;
	unsigned int b_fl_flags;
	unsigned char l_fl_type;
	unsigned char b_fl_type;
	bool conflict;
	char __data[0];
};

struct trace_event_data_offsets_locks_get_lock_context {};

struct trace_event_data_offsets_filelock_lock {};

struct trace_event_data_offsets_filelock_lease {};

struct trace_event_data_offsets_generic_add_lease {};

struct trace_event_data_offsets_leases_conflict {};

typedef void (*btf_trace_locks_get_lock_context)(void *, struct inode *, int, struct file_lock_context *);

typedef void (*btf_trace_posix_lock_inode)(void *, struct inode *, struct file_lock *, int);

typedef void (*btf_trace_fcntl_setlk)(void *, struct inode *, struct file_lock *, int);

typedef void (*btf_trace_locks_remove_posix)(void *, struct inode *, struct file_lock *, int);

typedef void (*btf_trace_flock_lock_inode)(void *, struct inode *, struct file_lock *, int);

typedef void (*btf_trace_break_lease_noblock)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_break_lease_block)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_break_lease_unblock)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_generic_delete_lease)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_time_out_leases)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_generic_add_lease)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_leases_conflict)(void *, bool, struct file_lock *, struct file_lock *);

struct file_lock_list_struct {
	spinlock_t lock;
	struct hlist_head hlist;
};

enum proc_hidepid {
	HIDEPID_OFF = 0,
	HIDEPID_NO_ACCESS = 1,
	HIDEPID_INVISIBLE = 2,
	HIDEPID_NOT_PTRACEABLE = 4,
};

enum proc_pidonly {
	PROC_PIDONLY_OFF = 0,
	PROC_PIDONLY_ON = 1,
};

struct proc_fs_info {
	struct pid_namespace *pid_ns;
	struct dentry *proc_self;
	struct dentry *proc_thread_self;
	kgid_t pid_gid;
	enum proc_hidepid hide_pid;
	enum proc_pidonly pidonly;
};

struct locks_iterator {
	int li_cpu;
	loff_t li_pos;
};

struct fiemap_extent;

struct fiemap_extent_info {
	unsigned int fi_flags;
	unsigned int fi_extents_mapped;
	unsigned int fi_extents_max;
	struct fiemap_extent *fi_extents_start;
};

struct fiemap_extent {
	__u64 fe_logical;
	__u64 fe_physical;
	__u64 fe_length;
	__u64 fe_reserved64[2];
	__u32 fe_flags;
	__u32 fe_reserved[3];
};

typedef unsigned int uint;

struct fs_disk_quota {
	__s8 d_version;
	__s8 d_flags;
	__u16 d_fieldmask;
	__u32 d_id;
	__u64 d_blk_hardlimit;
	__u64 d_blk_softlimit;
	__u64 d_ino_hardlimit;
	__u64 d_ino_softlimit;
	__u64 d_bcount;
	__u64 d_icount;
	__s32 d_itimer;
	__s32 d_btimer;
	__u16 d_iwarns;
	__u16 d_bwarns;
	__s8 d_itimer_hi;
	__s8 d_btimer_hi;
	__s8 d_rtbtimer_hi;
	__s8 d_padding2;
	__u64 d_rtb_hardlimit;
	__u64 d_rtb_softlimit;
	__u64 d_rtbcount;
	__s32 d_rtbtimer;
	__u16 d_rtbwarns;
	__s16 d_padding3;
	char d_padding4[8];
};

struct fs_qfilestat {
	__u64 qfs_ino;
	__u64 qfs_nblks;
	__u32 qfs_nextents;
};

typedef struct fs_qfilestat fs_qfilestat_t;

struct fs_quota_stat {
	__s8 qs_version;
	__u16 qs_flags;
	__s8 qs_pad;
	fs_qfilestat_t qs_uquota;
	fs_qfilestat_t qs_gquota;
	__u32 qs_incoredqs;
	__s32 qs_btimelimit;
	__s32 qs_itimelimit;
	__s32 qs_rtbtimelimit;
	__u16 qs_bwarnlimit;
	__u16 qs_iwarnlimit;
};

struct fs_qfilestatv {
	__u64 qfs_ino;
	__u64 qfs_nblks;
	__u32 qfs_nextents;
	__u32 qfs_pad;
};

struct fs_quota_statv {
	__s8 qs_version;
	__u8 qs_pad1;
	__u16 qs_flags;
	__u32 qs_incoredqs;
	struct fs_qfilestatv qs_uquota;
	struct fs_qfilestatv qs_gquota;
	struct fs_qfilestatv qs_pquota;
	__s32 qs_btimelimit;
	__s32 qs_itimelimit;
	__s32 qs_rtbtimelimit;
	__u16 qs_bwarnlimit;
	__u16 qs_iwarnlimit;
	__u16 qs_rtbwarnlimit;
	__u16 qs_pad3;
	__u32 qs_pad4;
	__u64 qs_pad2[7];
};

enum {
	QIF_BLIMITS_B = 0,
	QIF_SPACE_B = 1,
	QIF_ILIMITS_B = 2,
	QIF_INODES_B = 3,
	QIF_BTIME_B = 4,
	QIF_ITIME_B = 5,
};

struct if_dqblk {
	__u64 dqb_bhardlimit;
	__u64 dqb_bsoftlimit;
	__u64 dqb_curspace;
	__u64 dqb_ihardlimit;
	__u64 dqb_isoftlimit;
	__u64 dqb_curinodes;
	__u64 dqb_btime;
	__u64 dqb_itime;
	__u32 dqb_valid;
};

struct if_nextdqblk {
	__u64 dqb_bhardlimit;
	__u64 dqb_bsoftlimit;
	__u64 dqb_curspace;
	__u64 dqb_ihardlimit;
	__u64 dqb_isoftlimit;
	__u64 dqb_curinodes;
	__u64 dqb_btime;
	__u64 dqb_itime;
	__u32 dqb_valid;
	__u32 dqb_id;
};

struct if_dqinfo {
	__u64 dqi_bgrace;
	__u64 dqi_igrace;
	__u32 dqi_flags;
	__u32 dqi_valid;
};

typedef __kernel_uid32_t qid_t;

enum {
	_DQUOT_USAGE_ENABLED = 0,
	_DQUOT_LIMITS_ENABLED = 1,
	_DQUOT_SUSPENDED = 2,
	_DQUOT_STATE_FLAGS = 3,
};

struct compat_if_dqblk {
	compat_u64 dqb_bhardlimit;
	compat_u64 dqb_bsoftlimit;
	compat_u64 dqb_curspace;
	compat_u64 dqb_ihardlimit;
	compat_u64 dqb_isoftlimit;
	compat_u64 dqb_curinodes;
	compat_u64 dqb_btime;
	compat_u64 dqb_itime;
	compat_uint_t dqb_valid;
};

typedef __kernel_ulong_t ino_t;

typedef u32 nlink_t;

struct ctl_path {
	const char *procname;
};

typedef int (*proc_write_t)(struct file *, char *, size_t);

struct proc_dir_entry {
	atomic_t in_use;
	refcount_t refcnt;
	struct list_head pde_openers;
	spinlock_t pde_unload_lock;
	struct completion *pde_unload_completion;
	const struct inode_operations *proc_iops;
	union {
		const struct proc_ops *proc_ops;
		const struct file_operations *proc_dir_ops;
	};
	const struct dentry_operations *proc_dops;
	union {
		const struct seq_operations *seq_ops;
		int (*single_show)(struct seq_file *, void *);
	};
	proc_write_t write;
	void *data;
	unsigned int state_size;
	unsigned int low_ino;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	char *name;
	umode_t mode;
	u8 flags;
	u8 namelen;
	char inline_name[0];
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

enum xps_map_type {
	XPS_CPUS = 0,
	XPS_RXQS = 1,
	XPS_MAPS_MAX = 2,
};

enum bpf_xdp_mode {
	XDP_MODE_SKB = 0,
	XDP_MODE_DRV = 1,
	XDP_MODE_HW = 2,
	__MAX_XDP_MODE = 3,
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

union proc_op {
	int (*proc_get_link)(struct dentry *, struct path *);
	int (*proc_show)(struct seq_file *, struct pid_namespace *, struct pid *, struct task_struct *);
	const char *lsm;
};

struct proc_inode {
	struct pid *pid;
	unsigned int fd;
	union proc_op op;
	struct proc_dir_entry *pde;
	struct ctl_table_header *sysctl;
	struct ctl_table *sysctl_entry;
	struct hlist_node sibling_inodes;
	const struct proc_ns_operations *ns_ops;
	struct inode vfs_inode;
};

struct sysctl_alias {
	const char *kernel_param;
	const char *sysctl_param;
};

struct module_version_attribute {
	struct module_attribute mattr;
	const char *module_name;
	const char *version;
};

struct config_group;

struct config_item_type;

struct config_item {
	char *ci_name;
	char ci_namebuf[20];
	struct kref ci_kref;
	struct list_head ci_entry;
	struct config_item *ci_parent;
	struct config_group *ci_group;
	const struct config_item_type *ci_type;
	struct dentry *ci_dentry;
};

struct configfs_subsystem;

struct config_group {
	struct config_item cg_item;
	struct list_head cg_children;
	struct configfs_subsystem *cg_subsys;
	struct list_head default_groups;
	struct list_head group_entry;
};

struct configfs_item_operations;

struct configfs_group_operations;

struct configfs_attribute;

struct configfs_bin_attribute;

struct config_item_type {
	struct module *ct_owner;
	struct configfs_item_operations *ct_item_ops;
	struct configfs_group_operations *ct_group_ops;
	struct configfs_attribute **ct_attrs;
	struct configfs_bin_attribute **ct_bin_attrs;
};

struct configfs_item_operations {
	void (*release)(struct config_item *);
	int (*allow_link)(struct config_item *, struct config_item *);
	void (*drop_link)(struct config_item *, struct config_item *);
};

struct configfs_group_operations {
	struct config_item * (*make_item)(struct config_group *, const char *);
	struct config_group * (*make_group)(struct config_group *, const char *);
	int (*commit_item)(struct config_item *);
	void (*disconnect_notify)(struct config_group *, struct config_item *);
	void (*drop_item)(struct config_group *, struct config_item *);
};

struct configfs_attribute {
	const char *ca_name;
	struct module *ca_owner;
	umode_t ca_mode;
	ssize_t (*show)(struct config_item *, char *);
	ssize_t (*store)(struct config_item *, const char *, size_t);
};

struct configfs_bin_attribute {
	struct configfs_attribute cb_attr;
	void *cb_private;
	size_t cb_max_size;
	ssize_t (*read)(struct config_item *, void *, size_t);
	ssize_t (*write)(struct config_item *, const void *, size_t);
};

struct configfs_subsystem {
	struct config_group su_group;
	struct mutex su_mutex;
};

struct configfs_fragment {
	atomic_t frag_count;
	struct rw_semaphore frag_sem;
	bool frag_dead;
};

struct configfs_dirent {
	atomic_t s_count;
	int s_dependent_count;
	struct list_head s_sibling;
	struct list_head s_children;
	int s_links;
	void *s_element;
	int s_type;
	umode_t s_mode;
	struct dentry *s_dentry;
	struct iattr *s_iattr;
	struct configfs_fragment *s_frag;
};

struct buffer_head;

typedef void bh_end_io_t(struct buffer_head *, int);

struct buffer_head {
	long unsigned int b_state;
	struct buffer_head *b_this_page;
	struct page *b_page;
	sector_t b_blocknr;
	size_t b_size;
	char *b_data;
	struct block_device *b_bdev;
	bh_end_io_t *b_end_io;
	void *b_private;
	struct list_head b_assoc_buffers;
	struct address_space *b_assoc_map;
	atomic_t b_count;
	spinlock_t b_uptodate_lock;
};

struct utf8data;

struct utf8data_table;

struct unicode_map {
	unsigned int version;
	const struct utf8data *ntab[2];
	const struct utf8data_table *tables;
};

enum bh_state_bits {
	BH_Uptodate = 0,
	BH_Dirty = 1,
	BH_Lock = 2,
	BH_Req = 3,
	BH_Mapped = 4,
	BH_New = 5,
	BH_Async_Read = 6,
	BH_Async_Write = 7,
	BH_Delay = 8,
	BH_Boundary = 9,
	BH_Write_EIO = 10,
	BH_Unwritten = 11,
	BH_Quiet = 12,
	BH_Meta = 13,
	BH_Prio = 14,
	BH_Defer_Completion = 15,
	BH_PrivateStart = 16,
};

enum utf8_normalization {
	UTF8_NFDI = 0,
	UTF8_NFDICF = 1,
	UTF8_NMAX = 2,
};

struct utf8data {
	unsigned int maxage;
	unsigned int offset;
};

struct utf8data_table {
	const unsigned int *utf8agetab;
	int utf8agetab_size;
	const struct utf8data *utf8nfdicfdata;
	int utf8nfdicfdata_size;
	const struct utf8data *utf8nfdidata;
	int utf8nfdidata_size;
	const unsigned char *utf8data;
};

typedef unsigned int tid_t;

struct transaction_chp_stats_s {
	long unsigned int cs_chp_time;
	__u32 cs_forced_to_close;
	__u32 cs_written;
	__u32 cs_dropped;
};

struct journal_s;

typedef struct journal_s journal_t;

struct journal_head;

struct transaction_s;

typedef struct transaction_s transaction_t;

struct transaction_s {
	journal_t *t_journal;
	tid_t t_tid;
	enum {
		T_RUNNING = 0,
		T_LOCKED = 1,
		T_SWITCH = 2,
		T_FLUSH = 3,
		T_COMMIT = 4,
		T_COMMIT_DFLUSH = 5,
		T_COMMIT_JFLUSH = 6,
		T_COMMIT_CALLBACK = 7,
		T_FINISHED = 8,
	} t_state;
	long unsigned int t_log_start;
	int t_nr_buffers;
	struct journal_head *t_reserved_list;
	struct journal_head *t_buffers;
	struct journal_head *t_forget;
	struct journal_head *t_checkpoint_list;
	struct journal_head *t_checkpoint_io_list;
	struct journal_head *t_shadow_list;
	struct list_head t_inode_list;
	spinlock_t t_handle_lock;
	long unsigned int t_max_wait;
	long unsigned int t_start;
	long unsigned int t_requested;
	struct transaction_chp_stats_s t_chp_stats;
	atomic_t t_updates;
	atomic_t t_outstanding_credits;
	atomic_t t_outstanding_revokes;
	atomic_t t_handle_count;
	transaction_t *t_cpnext;
	transaction_t *t_cpprev;
	long unsigned int t_expires;
	ktime_t t_start_time;
	unsigned int t_synchronous_commit: 1;
	int t_need_data_flush;
	struct list_head t_private_list;
};

struct jbd2_buffer_trigger_type;

struct journal_head {
	struct buffer_head *b_bh;
	spinlock_t b_state_lock;
	int b_jcount;
	unsigned int b_jlist;
	unsigned int b_modified;
	char *b_frozen_data;
	char *b_committed_data;
	transaction_t *b_transaction;
	transaction_t *b_next_transaction;
	struct journal_head *b_tnext;
	struct journal_head *b_tprev;
	transaction_t *b_cp_transaction;
	struct journal_head *b_cpnext;
	struct journal_head *b_cpprev;
	struct jbd2_buffer_trigger_type *b_triggers;
	struct jbd2_buffer_trigger_type *b_frozen_triggers;
};

struct jbd2_buffer_trigger_type {
	void (*t_frozen)(struct jbd2_buffer_trigger_type *, struct buffer_head *, void *, size_t);
	void (*t_abort)(struct jbd2_buffer_trigger_type *, struct buffer_head *);
};

struct jbd2_journal_handle;

typedef struct jbd2_journal_handle handle_t;

struct jbd2_journal_handle {
	union {
		transaction_t *h_transaction;
		journal_t *h_journal;
	};
	handle_t *h_rsv_handle;
	int h_total_credits;
	int h_revoke_credits;
	int h_revoke_credits_requested;
	int h_ref;
	int h_err;
	unsigned int h_sync: 1;
	unsigned int h_jdata: 1;
	unsigned int h_reserved: 1;
	unsigned int h_aborted: 1;
	unsigned int h_type: 8;
	unsigned int h_line_no: 16;
	long unsigned int h_start_jiffies;
	unsigned int h_requested_credits;
	unsigned int saved_alloc_context;
};

struct transaction_run_stats_s {
	long unsigned int rs_wait;
	long unsigned int rs_request_delay;
	long unsigned int rs_running;
	long unsigned int rs_locked;
	long unsigned int rs_flushing;
	long unsigned int rs_logging;
	__u32 rs_handle_count;
	__u32 rs_blocks;
	__u32 rs_blocks_logged;
};

struct transaction_stats_s {
	long unsigned int ts_tid;
	long unsigned int ts_requested;
	struct transaction_run_stats_s run;
};

enum passtype {
	PASS_SCAN = 0,
	PASS_REVOKE = 1,
	PASS_REPLAY = 2,
};

struct journal_superblock_s;

typedef struct journal_superblock_s journal_superblock_t;

struct jbd2_revoke_table_s;

struct jbd2_inode;

struct journal_s {
	long unsigned int j_flags;
	long unsigned int j_atomic_flags;
	int j_errno;
	struct mutex j_abort_mutex;
	struct buffer_head *j_sb_buffer;
	journal_superblock_t *j_superblock;
	int j_format_version;
	rwlock_t j_state_lock;
	int j_barrier_count;
	struct mutex j_barrier;
	transaction_t *j_running_transaction;
	transaction_t *j_committing_transaction;
	transaction_t *j_checkpoint_transactions;
	wait_queue_head_t j_wait_transaction_locked;
	wait_queue_head_t j_wait_done_commit;
	wait_queue_head_t j_wait_commit;
	wait_queue_head_t j_wait_updates;
	wait_queue_head_t j_wait_reserved;
	wait_queue_head_t j_fc_wait;
	struct mutex j_checkpoint_mutex;
	struct buffer_head *j_chkpt_bhs[64];
	struct shrinker j_shrinker;
	struct percpu_counter j_checkpoint_jh_count;
	transaction_t *j_shrink_transaction;
	long unsigned int j_head;
	long unsigned int j_tail;
	long unsigned int j_free;
	long unsigned int j_first;
	long unsigned int j_last;
	long unsigned int j_fc_first;
	long unsigned int j_fc_off;
	long unsigned int j_fc_last;
	struct block_device *j_dev;
	int j_blocksize;
	long long unsigned int j_blk_offset;
	char j_devname[56];
	struct block_device *j_fs_dev;
	unsigned int j_total_len;
	atomic_t j_reserved_credits;
	spinlock_t j_list_lock;
	struct inode *j_inode;
	tid_t j_tail_sequence;
	tid_t j_transaction_sequence;
	tid_t j_commit_sequence;
	tid_t j_commit_request;
	__u8 j_uuid[16];
	struct task_struct *j_task;
	int j_max_transaction_buffers;
	int j_revoke_records_per_block;
	long unsigned int j_commit_interval;
	struct timer_list j_commit_timer;
	spinlock_t j_revoke_lock;
	struct jbd2_revoke_table_s *j_revoke;
	struct jbd2_revoke_table_s *j_revoke_table[2];
	struct buffer_head **j_wbuf;
	struct buffer_head **j_fc_wbuf;
	int j_wbufsize;
	int j_fc_wbufsize;
	pid_t j_last_sync_writer;
	u64 j_average_commit_time;
	u32 j_min_batch_time;
	u32 j_max_batch_time;
	void (*j_commit_callback)(journal_t *, transaction_t *);
	int (*j_submit_inode_data_buffers)(struct jbd2_inode *);
	int (*j_finish_inode_data_buffers)(struct jbd2_inode *);
	spinlock_t j_history_lock;
	struct proc_dir_entry *j_proc_entry;
	struct transaction_stats_s j_stats;
	unsigned int j_failed_commit;
	void *j_private;
	struct crypto_shash *j_chksum_driver;
	__u32 j_csum_seed;
	void (*j_fc_cleanup_callback)(struct journal_s *, int, tid_t);
	int (*j_fc_replay_callback)(struct journal_s *, struct buffer_head *, enum passtype, int, tid_t);
};

struct journal_header_s {
	__be32 h_magic;
	__be32 h_blocktype;
	__be32 h_sequence;
};

typedef struct journal_header_s journal_header_t;

struct journal_superblock_s {
	journal_header_t s_header;
	__be32 s_blocksize;
	__be32 s_maxlen;
	__be32 s_first;
	__be32 s_sequence;
	__be32 s_start;
	__be32 s_errno;
	__be32 s_feature_compat;
	__be32 s_feature_incompat;
	__be32 s_feature_ro_compat;
	__u8 s_uuid[16];
	__be32 s_nr_users;
	__be32 s_dynsuper;
	__be32 s_max_transaction;
	__be32 s_max_trans_data;
	__u8 s_checksum_type;
	__u8 s_padding2[3];
	__be32 s_num_fc_blks;
	__u32 s_padding[41];
	__be32 s_checksum;
	__u8 s_users[768];
};

enum jbd_state_bits {
	BH_JBD = 16,
	BH_JWrite = 17,
	BH_Freed = 18,
	BH_Revoked = 19,
	BH_RevokeValid = 20,
	BH_JBDDirty = 21,
	BH_JournalHead = 22,
	BH_Shadow = 23,
	BH_Verified = 24,
	BH_JBDPrivateStart = 25,
};

struct jbd2_inode {
	transaction_t *i_transaction;
	transaction_t *i_next_transaction;
	struct list_head i_list;
	struct inode *i_vfs_inode;
	long unsigned int i_flags;
	loff_t i_dirty_start;
	loff_t i_dirty_end;
};

struct bgl_lock {
	spinlock_t lock;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct blockgroup_lock {
	struct bgl_lock locks[128];
};

struct fscrypt_str {
	unsigned char *name;
	u32 len;
};

struct fscrypt_dummy_policy {
	const union fscrypt_policy *policy;
};

typedef int ext4_grpblk_t;

typedef long long unsigned int ext4_fsblk_t;

typedef __u32 ext4_lblk_t;

typedef unsigned int ext4_group_t;

struct ext4_map_blocks {
	ext4_fsblk_t m_pblk;
	ext4_lblk_t m_lblk;
	unsigned int m_len;
	unsigned int m_flags;
};

struct ext4_system_blocks {
	struct rb_root root;
	struct callback_head rcu;
};

struct flex_groups {
	atomic64_t free_clusters;
	atomic_t free_inodes;
	atomic_t used_dirs;
};

enum {
	EXT4_INODE_SECRM = 0,
	EXT4_INODE_UNRM = 1,
	EXT4_INODE_COMPR = 2,
	EXT4_INODE_SYNC = 3,
	EXT4_INODE_IMMUTABLE = 4,
	EXT4_INODE_APPEND = 5,
	EXT4_INODE_NODUMP = 6,
	EXT4_INODE_NOATIME = 7,
	EXT4_INODE_DIRTY = 8,
	EXT4_INODE_COMPRBLK = 9,
	EXT4_INODE_NOCOMPR = 10,
	EXT4_INODE_ENCRYPT = 11,
	EXT4_INODE_INDEX = 12,
	EXT4_INODE_IMAGIC = 13,
	EXT4_INODE_JOURNAL_DATA = 14,
	EXT4_INODE_NOTAIL = 15,
	EXT4_INODE_DIRSYNC = 16,
	EXT4_INODE_TOPDIR = 17,
	EXT4_INODE_HUGE_FILE = 18,
	EXT4_INODE_EXTENTS = 19,
	EXT4_INODE_VERITY = 20,
	EXT4_INODE_EA_INODE = 21,
	EXT4_INODE_DAX = 25,
	EXT4_INODE_INLINE_DATA = 28,
	EXT4_INODE_PROJINHERIT = 29,
	EXT4_INODE_CASEFOLD = 30,
	EXT4_INODE_RESERVED = 31,
};

struct extent_status {
	struct rb_node rb_node;
	ext4_lblk_t es_lblk;
	ext4_lblk_t es_len;
	ext4_fsblk_t es_pblk;
};

struct ext4_es_tree {
	struct rb_root root;
	struct extent_status *cache_es;
};

struct ext4_es_stats {
	long unsigned int es_stats_shrunk;
	struct percpu_counter es_stats_cache_hits;
	struct percpu_counter es_stats_cache_misses;
	u64 es_stats_scan_time;
	u64 es_stats_max_scan_time;
	struct percpu_counter es_stats_all_cnt;
	struct percpu_counter es_stats_shk_cnt;
};

struct ext4_pending_tree {
	struct rb_root root;
};

enum {
	EXT4_FC_REASON_XATTR = 0,
	EXT4_FC_REASON_CROSS_RENAME = 1,
	EXT4_FC_REASON_JOURNAL_FLAG_CHANGE = 2,
	EXT4_FC_REASON_NOMEM = 3,
	EXT4_FC_REASON_SWAP_BOOT = 4,
	EXT4_FC_REASON_RESIZE = 5,
	EXT4_FC_REASON_RENAME_DIR = 6,
	EXT4_FC_REASON_FALLOC_RANGE = 7,
	EXT4_FC_REASON_INODE_JOURNAL_DATA = 8,
	EXT4_FC_REASON_MAX = 9,
};

struct ext4_fc_stats {
	unsigned int fc_ineligible_reason_count[9];
	long unsigned int fc_num_commits;
	long unsigned int fc_ineligible_commits;
	long unsigned int fc_failed_commits;
	long unsigned int fc_skipped_commits;
	long unsigned int fc_numblks;
	u64 s_fc_avg_commit_time;
};

struct ext4_fc_alloc_region {
	ext4_lblk_t lblk;
	ext4_fsblk_t pblk;
	int ino;
	int len;
};

struct ext4_fc_replay_state {
	int fc_replay_num_tags;
	int fc_replay_expected_off;
	int fc_current_pass;
	int fc_cur_tag;
	int fc_crc;
	struct ext4_fc_alloc_region *fc_regions;
	int fc_regions_size;
	int fc_regions_used;
	int fc_regions_valid;
	int *fc_modified_inodes;
	int fc_modified_inodes_used;
	int fc_modified_inodes_size;
};

struct ext4_inode_info {
	__le32 i_data[15];
	__u32 i_dtime;
	ext4_fsblk_t i_file_acl;
	ext4_group_t i_block_group;
	ext4_lblk_t i_dir_start_lookup;
	long unsigned int i_flags;
	struct rw_semaphore xattr_sem;
	union {
		struct list_head i_orphan;
		unsigned int i_orphan_idx;
	};
	struct list_head i_fc_dilist;
	struct list_head i_fc_list;
	ext4_lblk_t i_fc_lblk_start;
	ext4_lblk_t i_fc_lblk_len;
	atomic_t i_fc_updates;
	wait_queue_head_t i_fc_wait;
	struct mutex i_fc_lock;
	loff_t i_disksize;
	struct rw_semaphore i_data_sem;
	struct inode vfs_inode;
	struct jbd2_inode *jinode;
	spinlock_t i_raw_lock;
	struct timespec64 i_crtime;
	atomic_t i_prealloc_active;
	struct list_head i_prealloc_list;
	spinlock_t i_prealloc_lock;
	struct ext4_es_tree i_es_tree;
	rwlock_t i_es_lock;
	struct list_head i_es_list;
	unsigned int i_es_all_nr;
	unsigned int i_es_shk_nr;
	ext4_lblk_t i_es_shrink_lblk;
	ext4_group_t i_last_alloc_group;
	unsigned int i_reserved_data_blocks;
	struct ext4_pending_tree i_pending_tree;
	__u16 i_extra_isize;
	u16 i_inline_off;
	u16 i_inline_size;
	qsize_t i_reserved_quota;
	spinlock_t i_completed_io_lock;
	struct list_head i_rsv_conversion_list;
	struct work_struct i_rsv_conversion_work;
	atomic_t i_unwritten;
	spinlock_t i_block_reservation_lock;
	tid_t i_sync_tid;
	tid_t i_datasync_tid;
	struct dquot *i_dquot[3];
	__u32 i_csum_seed;
	kprojid_t i_projid;
};

struct ext4_super_block {
	__le32 s_inodes_count;
	__le32 s_blocks_count_lo;
	__le32 s_r_blocks_count_lo;
	__le32 s_free_blocks_count_lo;
	__le32 s_free_inodes_count;
	__le32 s_first_data_block;
	__le32 s_log_block_size;
	__le32 s_log_cluster_size;
	__le32 s_blocks_per_group;
	__le32 s_clusters_per_group;
	__le32 s_inodes_per_group;
	__le32 s_mtime;
	__le32 s_wtime;
	__le16 s_mnt_count;
	__le16 s_max_mnt_count;
	__le16 s_magic;
	__le16 s_state;
	__le16 s_errors;
	__le16 s_minor_rev_level;
	__le32 s_lastcheck;
	__le32 s_checkinterval;
	__le32 s_creator_os;
	__le32 s_rev_level;
	__le16 s_def_resuid;
	__le16 s_def_resgid;
	__le32 s_first_ino;
	__le16 s_inode_size;
	__le16 s_block_group_nr;
	__le32 s_feature_compat;
	__le32 s_feature_incompat;
	__le32 s_feature_ro_compat;
	__u8 s_uuid[16];
	char s_volume_name[16];
	char s_last_mounted[64];
	__le32 s_algorithm_usage_bitmap;
	__u8 s_prealloc_blocks;
	__u8 s_prealloc_dir_blocks;
	__le16 s_reserved_gdt_blocks;
	__u8 s_journal_uuid[16];
	__le32 s_journal_inum;
	__le32 s_journal_dev;
	__le32 s_last_orphan;
	__le32 s_hash_seed[4];
	__u8 s_def_hash_version;
	__u8 s_jnl_backup_type;
	__le16 s_desc_size;
	__le32 s_default_mount_opts;
	__le32 s_first_meta_bg;
	__le32 s_mkfs_time;
	__le32 s_jnl_blocks[17];
	__le32 s_blocks_count_hi;
	__le32 s_r_blocks_count_hi;
	__le32 s_free_blocks_count_hi;
	__le16 s_min_extra_isize;
	__le16 s_want_extra_isize;
	__le32 s_flags;
	__le16 s_raid_stride;
	__le16 s_mmp_update_interval;
	__le64 s_mmp_block;
	__le32 s_raid_stripe_width;
	__u8 s_log_groups_per_flex;
	__u8 s_checksum_type;
	__u8 s_encryption_level;
	__u8 s_reserved_pad;
	__le64 s_kbytes_written;
	__le32 s_snapshot_inum;
	__le32 s_snapshot_id;
	__le64 s_snapshot_r_blocks_count;
	__le32 s_snapshot_list;
	__le32 s_error_count;
	__le32 s_first_error_time;
	__le32 s_first_error_ino;
	__le64 s_first_error_block;
	__u8 s_first_error_func[32];
	__le32 s_first_error_line;
	__le32 s_last_error_time;
	__le32 s_last_error_ino;
	__le32 s_last_error_line;
	__le64 s_last_error_block;
	__u8 s_last_error_func[32];
	__u8 s_mount_opts[64];
	__le32 s_usr_quota_inum;
	__le32 s_grp_quota_inum;
	__le32 s_overhead_clusters;
	__le32 s_backup_bgs[2];
	__u8 s_encrypt_algos[4];
	__u8 s_encrypt_pw_salt[16];
	__le32 s_lpf_ino;
	__le32 s_prj_quota_inum;
	__le32 s_checksum_seed;
	__u8 s_wtime_hi;
	__u8 s_mtime_hi;
	__u8 s_mkfs_time_hi;
	__u8 s_lastcheck_hi;
	__u8 s_first_error_time_hi;
	__u8 s_last_error_time_hi;
	__u8 s_first_error_errcode;
	__u8 s_last_error_errcode;
	__le16 s_encoding;
	__le16 s_encoding_flags;
	__le32 s_orphan_file_inum;
	__le32 s_reserved[94];
	__le32 s_checksum;
};

enum ext4_journal_trigger_type {
	EXT4_JTR_ORPHAN_FILE = 0,
	EXT4_JTR_NONE = 1,
};

struct ext4_journal_trigger {
	struct jbd2_buffer_trigger_type tr_triggers;
	struct super_block *sb;
};

struct ext4_orphan_block {
	atomic_t ob_free_entries;
	struct buffer_head *ob_bh;
};

struct ext4_orphan_info {
	int of_blocks;
	__u32 of_csum_seed;
	struct ext4_orphan_block *of_binfo;
};

struct mb_cache;

struct ext4_group_info;

struct ext4_locality_group;

struct ext4_li_request;

struct ext4_sb_info {
	long unsigned int s_desc_size;
	long unsigned int s_inodes_per_block;
	long unsigned int s_blocks_per_group;
	long unsigned int s_clusters_per_group;
	long unsigned int s_inodes_per_group;
	long unsigned int s_itb_per_group;
	long unsigned int s_gdb_count;
	long unsigned int s_desc_per_block;
	ext4_group_t s_groups_count;
	ext4_group_t s_blockfile_groups;
	long unsigned int s_overhead;
	unsigned int s_cluster_ratio;
	unsigned int s_cluster_bits;
	loff_t s_bitmap_maxbytes;
	struct buffer_head *s_sbh;
	struct ext4_super_block *s_es;
	struct buffer_head **s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_opt2;
	long unsigned int s_mount_flags;
	unsigned int s_def_mount_opt;
	ext4_fsblk_t s_sb_block;
	atomic64_t s_resv_clusters;
	kuid_t s_resuid;
	kgid_t s_resgid;
	short unsigned int s_mount_state;
	short unsigned int s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;
	struct percpu_counter s_freeclusters_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyclusters_counter;
	struct percpu_counter s_sra_exceeded_retry_limit;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;
	struct super_block *s_sb;
	struct buffer_head *s_mmp_bh;
	struct journal_s *s_journal;
	long unsigned int s_ext4_flags;
	struct mutex s_orphan_lock;
	struct list_head s_orphan;
	struct ext4_orphan_info s_orphan_info;
	long unsigned int s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct block_device *s_journal_bdev;
	char *s_qf_names[3];
	int s_jquota_fmt;
	unsigned int s_want_extra_isize;
	struct ext4_system_blocks *s_system_blks;
	struct ext4_group_info ***s_group_info;
	struct inode *s_buddy_cache;
	spinlock_t s_md_lock;
	short unsigned int *s_mb_offsets;
	unsigned int *s_mb_maxs;
	unsigned int s_group_info_size;
	unsigned int s_mb_free_pending;
	struct list_head s_freed_data_list;
	struct list_head s_discard_list;
	struct work_struct s_discard_work;
	atomic_t s_retry_alloc_pending;
	struct list_head *s_mb_avg_fragment_size;
	rwlock_t *s_mb_avg_fragment_size_locks;
	struct list_head *s_mb_largest_free_orders;
	rwlock_t *s_mb_largest_free_orders_locks;
	long unsigned int s_stripe;
	unsigned int s_mb_max_linear_groups;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_mb_max_inode_prealloc;
	unsigned int s_max_dir_size_kb;
	long unsigned int s_mb_last_group;
	long unsigned int s_mb_last_start;
	unsigned int s_mb_prefetch;
	unsigned int s_mb_prefetch_limit;
	atomic_t s_bal_reqs;
	atomic_t s_bal_success;
	atomic_t s_bal_allocated;
	atomic_t s_bal_ex_scanned;
	atomic_t s_bal_groups_scanned;
	atomic_t s_bal_goals;
	atomic_t s_bal_breaks;
	atomic_t s_bal_2orders;
	atomic_t s_bal_cr0_bad_suggestions;
	atomic_t s_bal_cr1_bad_suggestions;
	atomic64_t s_bal_cX_groups_considered[4];
	atomic64_t s_bal_cX_hits[4];
	atomic64_t s_bal_cX_failed[4];
	atomic_t s_mb_buddies_generated;
	atomic64_t s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;
	struct ext4_locality_group *s_locality_groups;
	long unsigned int s_sectors_written_start;
	u64 s_kbytes_written;
	unsigned int s_extent_max_zeroout_kb;
	unsigned int s_log_groups_per_flex;
	struct flex_groups **s_flex_groups;
	ext4_group_t s_flex_groups_allocated;
	struct workqueue_struct *rsv_conversion_wq;
	struct timer_list s_err_report;
	struct ext4_li_request *s_li_request;
	unsigned int s_li_wait_mult;
	struct task_struct *s_mmp_tsk;
	long unsigned int s_last_trim_minblks;
	struct crypto_shash *s_chksum_driver;
	__u32 s_csum_seed;
	struct shrinker s_es_shrinker;
	struct list_head s_es_list;
	long int s_es_nr_inode;
	struct ext4_es_stats s_es_stats;
	struct mb_cache *s_ea_block_cache;
	struct mb_cache *s_ea_inode_cache;
	long: 64;
	long: 64;
	spinlock_t s_es_lock;
	struct ext4_journal_trigger s_journal_triggers[1];
	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;
	atomic_t s_warning_count;
	atomic_t s_msg_count;
	struct fscrypt_dummy_policy s_dummy_enc_policy;
	struct percpu_rw_semaphore s_writepages_rwsem;
	struct dax_device *s_daxdev;
	u64 s_dax_part_off;
	errseq_t s_bdev_wb_err;
	spinlock_t s_bdev_wb_lock;
	spinlock_t s_error_lock;
	int s_add_error_count;
	int s_first_error_code;
	__u32 s_first_error_line;
	__u32 s_first_error_ino;
	__u64 s_first_error_block;
	const char *s_first_error_func;
	time64_t s_first_error_time;
	int s_last_error_code;
	__u32 s_last_error_line;
	__u32 s_last_error_ino;
	__u64 s_last_error_block;
	const char *s_last_error_func;
	time64_t s_last_error_time;
	struct work_struct s_error_work;
	atomic_t s_fc_subtid;
	struct list_head s_fc_q[2];
	struct list_head s_fc_dentry_q[2];
	unsigned int s_fc_bytes;
	spinlock_t s_fc_lock;
	struct buffer_head *s_fc_bh;
	struct ext4_fc_stats s_fc_stats;
	tid_t s_fc_ineligible_tid;
	struct ext4_fc_replay_state s_fc_replay_state;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct ext4_group_info {
	long unsigned int bb_state;
	struct rb_root bb_free_root;
	ext4_grpblk_t bb_first_free;
	ext4_grpblk_t bb_free;
	ext4_grpblk_t bb_fragments;
	int bb_avg_fragment_size_order;
	ext4_grpblk_t bb_largest_free_order;
	ext4_group_t bb_group;
	struct list_head bb_prealloc_list;
	struct rw_semaphore alloc_sem;
	struct list_head bb_avg_fragment_size_node;
	struct list_head bb_largest_free_order_node;
	ext4_grpblk_t bb_counters[0];
};

enum ext4_li_mode {
	EXT4_LI_MODE_PREFETCH_BBITMAP = 0,
	EXT4_LI_MODE_ITABLE = 1,
};

struct ext4_li_request {
	struct super_block *lr_super;
	enum ext4_li_mode lr_mode;
	ext4_group_t lr_first_not_zeroed;
	ext4_group_t lr_next_group;
	struct list_head lr_request;
	long unsigned int lr_next_sched;
	long unsigned int lr_timeout;
};

struct ext4_dir_entry_hash {
	__le32 hash;
	__le32 minor_hash;
};

struct ext4_dir_entry_2 {
	__le32 inode;
	__le16 rec_len;
	__u8 name_len;
	__u8 file_type;
	char name[255];
};

struct fname;

struct dir_private_info {
	struct rb_root root;
	struct rb_node *curr_node;
	struct fname *extra_fname;
	loff_t last_pos;
	__u32 curr_hash;
	__u32 curr_minor_hash;
	__u32 next_hash;
};

struct fname {
	__u32 hash;
	__u32 minor_hash;
	struct rb_node rb_hash;
	struct fname *next;
	__u32 inode;
	__u8 name_len;
	__u8 file_type;
	char name[0];
};

struct dx_hash_info {
	u32 hash;
	u32 minor_hash;
	int hash_version;
	u32 *seed;
};

struct fstrim_range {
	__u64 start;
	__u64 len;
	__u64 minlen;
};

enum blk_default_limits {
	BLK_MAX_SEGMENTS = 128,
	BLK_SAFE_MAX_SECTORS = 255,
	BLK_DEF_MAX_SECTORS = 2560,
	BLK_MAX_SEGMENT_SIZE = 65536,
	BLK_SEG_BOUNDARY_MASK = 4294967295,
};

struct ext4_allocation_request {
	struct inode *inode;
	unsigned int len;
	ext4_lblk_t logical;
	ext4_lblk_t lleft;
	ext4_lblk_t lright;
	ext4_fsblk_t goal;
	ext4_fsblk_t pleft;
	ext4_fsblk_t pright;
	unsigned int flags;
};

struct ext4_group_desc {
	__le32 bg_block_bitmap_lo;
	__le32 bg_inode_bitmap_lo;
	__le32 bg_inode_table_lo;
	__le16 bg_free_blocks_count_lo;
	__le16 bg_free_inodes_count_lo;
	__le16 bg_used_dirs_count_lo;
	__le16 bg_flags;
	__le32 bg_exclude_bitmap_lo;
	__le16 bg_block_bitmap_csum_lo;
	__le16 bg_inode_bitmap_csum_lo;
	__le16 bg_itable_unused_lo;
	__le16 bg_checksum;
	__le32 bg_block_bitmap_hi;
	__le32 bg_inode_bitmap_hi;
	__le32 bg_inode_table_hi;
	__le16 bg_free_blocks_count_hi;
	__le16 bg_free_inodes_count_hi;
	__le16 bg_used_dirs_count_hi;
	__le16 bg_itable_unused_hi;
	__le32 bg_exclude_bitmap_hi;
	__le16 bg_block_bitmap_csum_hi;
	__le16 bg_inode_bitmap_csum_hi;
	__u32 bg_reserved;
};

struct ext4_locality_group {
	struct mutex lg_mutex;
	struct list_head lg_prealloc_list[10];
	spinlock_t lg_prealloc_lock;
};

struct ext4_free_data {
	struct list_head efd_list;
	struct rb_node efd_node;
	ext4_group_t efd_group;
	ext4_grpblk_t efd_start_cluster;
	ext4_grpblk_t efd_count;
	tid_t efd_tid;
};

struct ext4_prealloc_space {
	struct list_head pa_inode_list;
	struct list_head pa_group_list;
	union {
		struct list_head pa_tmp_list;
		struct callback_head pa_rcu;
	} u;
	spinlock_t pa_lock;
	atomic_t pa_count;
	unsigned int pa_deleted;
	ext4_fsblk_t pa_pstart;
	ext4_lblk_t pa_lstart;
	ext4_grpblk_t pa_len;
	ext4_grpblk_t pa_free;
	short unsigned int pa_type;
	spinlock_t *pa_obj_lock;
	struct inode *pa_inode;
};

enum {
	MB_INODE_PA = 0,
	MB_GROUP_PA = 1,
};

struct ext4_free_extent {
	ext4_lblk_t fe_logical;
	ext4_grpblk_t fe_start;
	ext4_group_t fe_group;
	ext4_grpblk_t fe_len;
};

struct ext4_allocation_context {
	struct inode *ac_inode;
	struct super_block *ac_sb;
	struct ext4_free_extent ac_o_ex;
	struct ext4_free_extent ac_g_ex;
	struct ext4_free_extent ac_b_ex;
	struct ext4_free_extent ac_f_ex;
	__u32 ac_groups_considered;
	__u32 ac_flags;
	__u16 ac_groups_scanned;
	__u16 ac_groups_linear_remaining;
	__u16 ac_found;
	__u16 ac_tail;
	__u16 ac_buddy;
	__u8 ac_status;
	__u8 ac_criteria;
	__u8 ac_2order;
	__u8 ac_op;
	struct page *ac_bitmap_page;
	struct page *ac_buddy_page;
	struct ext4_prealloc_space *ac_pa;
	struct ext4_locality_group *ac_lg;
};

struct ext4_buddy {
	struct page *bd_buddy_page;
	void *bd_buddy;
	struct page *bd_bitmap_page;
	void *bd_bitmap;
	struct ext4_group_info *bd_info;
	struct super_block *bd_sb;
	__u16 bd_blkbits;
	ext4_group_t bd_group;
};

typedef int (*ext4_mballoc_query_range_fn)(struct super_block *, ext4_group_t, ext4_grpblk_t, ext4_grpblk_t, void *);

struct sg {
	struct ext4_group_info info;
	ext4_grpblk_t counters[18];
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

typedef struct {
	__le16 e_tag;
	__le16 e_perm;
	__le32 e_id;
} ext4_acl_entry;

typedef struct {
	__le32 a_version;
} ext4_acl_header;

struct commit_header {
	__be32 h_magic;
	__be32 h_blocktype;
	__be32 h_sequence;
	unsigned char h_chksum_type;
	unsigned char h_chksum_size;
	unsigned char h_padding[2];
	__be32 h_chksum[8];
	__be64 h_commit_sec;
	__be32 h_commit_nsec;
};

struct journal_block_tag3_s {
	__be32 t_blocknr;
	__be32 t_flags;
	__be32 t_blocknr_high;
	__be32 t_checksum;
};

typedef struct journal_block_tag3_s journal_block_tag3_t;

struct journal_block_tag_s {
	__be32 t_blocknr;
	__be16 t_checksum;
	__be16 t_flags;
	__be32 t_blocknr_high;
};

typedef struct journal_block_tag_s journal_block_tag_t;

struct jbd2_journal_block_tail {
	__be32 t_checksum;
};

struct jbd2_journal_revoke_header_s {
	journal_header_t r_header;
	__be32 r_count;
};

typedef struct jbd2_journal_revoke_header_s jbd2_journal_revoke_header_t;

struct recovery_info {
	tid_t start_transaction;
	tid_t end_transaction;
	int nr_replays;
	int nr_revokes;
	int nr_revoke_hits;
};

struct utf8cursor {
	const struct unicode_map *um;
	enum utf8_normalization n;
	const char *s;
	const char *p;
	const char *ss;
	const char *sp;
	unsigned int len;
	unsigned int slen;
	short int ccc;
	short int nccc;
	unsigned char hangul[12];
};

typedef const unsigned char utf8trie_t;

typedef const unsigned char utf8leaf_t;

typedef unsigned int autofs_wqt_t;

struct autofs_packet_hdr {
	int proto_version;
	int type;
};

struct autofs_packet_expire {
	struct autofs_packet_hdr hdr;
	int len;
	char name[256];
};

enum autofs_notify {
	NFY_NONE = 0,
	NFY_MOUNT = 1,
	NFY_EXPIRE = 2,
};

struct autofs_sb_info;

struct autofs_info {
	struct dentry *dentry;
	int flags;
	struct completion expire_complete;
	struct list_head active;
	struct list_head expiring;
	struct autofs_sb_info *sbi;
	long unsigned int last_used;
	int count;
	kuid_t uid;
	kgid_t gid;
	struct callback_head rcu;
};

struct autofs_wait_queue;

struct autofs_sb_info {
	u32 magic;
	int pipefd;
	struct file *pipe;
	struct pid *oz_pgrp;
	int version;
	int sub_version;
	int min_proto;
	int max_proto;
	unsigned int flags;
	long unsigned int exp_timeout;
	unsigned int type;
	struct super_block *sb;
	struct mutex wq_mutex;
	struct mutex pipe_mutex;
	spinlock_t fs_lock;
	struct autofs_wait_queue *queues;
	spinlock_t lookup_lock;
	struct list_head active_list;
	struct list_head expiring_list;
	struct callback_head rcu;
};

struct autofs_wait_queue {
	wait_queue_head_t queue;
	struct autofs_wait_queue *next;
	autofs_wqt_t wait_queue_token;
	struct qstr name;
	u32 offset;
	u32 dev;
	u64 ino;
	kuid_t uid;
	kgid_t gid;
	pid_t pid;
	pid_t tgid;
	int status;
	unsigned int wait_ctr;
};

struct semaphore {
	raw_spinlock_t lock;
	unsigned int count;
	struct list_head wait_list;
};

struct btrfs_scrub_progress {
	__u64 data_extents_scrubbed;
	__u64 tree_extents_scrubbed;
	__u64 data_bytes_scrubbed;
	__u64 tree_bytes_scrubbed;
	__u64 read_errors;
	__u64 csum_errors;
	__u64 verify_errors;
	__u64 no_csum;
	__u64 csum_discards;
	__u64 super_errors;
	__u64 malloc_errors;
	__u64 uncorrectable_errors;
	__u64 corrected_errors;
	__u64 last_physical;
	__u64 unverified_errors;
};

struct btrfs_disk_key {
	__le64 objectid;
	__u8 type;
	__le64 offset;
} __attribute__((packed));

struct btrfs_key {
	__u64 objectid;
	__u8 type;
	__u64 offset;
} __attribute__((packed));

struct btrfs_dev_item {
	__le64 devid;
	__le64 total_bytes;
	__le64 bytes_used;
	__le32 io_align;
	__le32 io_width;
	__le32 sector_size;
	__le64 type;
	__le64 generation;
	__le64 start_offset;
	__le32 dev_group;
	__u8 seek_speed;
	__u8 bandwidth;
	__u8 uuid[16];
	__u8 fsid[16];
} __attribute__((packed));

struct btrfs_stripe {
	__le64 devid;
	__le64 offset;
	__u8 dev_uuid[16];
};

struct btrfs_chunk {
	__le64 length;
	__le64 owner;
	__le64 stripe_len;
	__le64 type;
	__le32 io_align;
	__le32 io_width;
	__le32 sector_size;
	__le16 num_stripes;
	__le16 sub_stripes;
	struct btrfs_stripe stripe;
};

struct btrfs_extent_item {
	__le64 refs;
	__le64 generation;
	__le64 flags;
};

struct btrfs_tree_block_info {
	struct btrfs_disk_key key;
	__u8 level;
} __attribute__((packed));

struct btrfs_extent_data_ref {
	__le64 root;
	__le64 objectid;
	__le64 offset;
	__le32 count;
} __attribute__((packed));

struct btrfs_shared_data_ref {
	__le32 count;
};

struct btrfs_extent_inline_ref {
	__u8 type;
	__le64 offset;
} __attribute__((packed));

struct btrfs_dev_extent {
	__le64 chunk_tree;
	__le64 chunk_objectid;
	__le64 chunk_offset;
	__le64 length;
	__u8 chunk_tree_uuid[16];
};

struct btrfs_timespec {
	__le64 sec;
	__le32 nsec;
} __attribute__((packed));

struct btrfs_inode_item {
	__le64 generation;
	__le64 transid;
	__le64 size;
	__le64 nbytes;
	__le64 block_group;
	__le32 nlink;
	__le32 uid;
	__le32 gid;
	__le32 mode;
	__le64 rdev;
	__le64 flags;
	__le64 sequence;
	__le64 reserved[4];
	struct btrfs_timespec atime;
	struct btrfs_timespec ctime;
	struct btrfs_timespec mtime;
	struct btrfs_timespec otime;
} __attribute__((packed));

struct btrfs_dir_item {
	struct btrfs_disk_key location;
	__le64 transid;
	__le16 data_len;
	__le16 name_len;
	__u8 type;
} __attribute__((packed));

struct btrfs_root_item {
	struct btrfs_inode_item inode;
	__le64 generation;
	__le64 root_dirid;
	__le64 bytenr;
	__le64 byte_limit;
	__le64 bytes_used;
	__le64 last_snapshot;
	__le64 flags;
	__le32 refs;
	struct btrfs_disk_key drop_progress;
	__u8 drop_level;
	__u8 level;
	__le64 generation_v2;
	__u8 uuid[16];
	__u8 parent_uuid[16];
	__u8 received_uuid[16];
	__le64 ctransid;
	__le64 otransid;
	__le64 stransid;
	__le64 rtransid;
	struct btrfs_timespec ctime;
	struct btrfs_timespec otime;
	struct btrfs_timespec stime;
	struct btrfs_timespec rtime;
	__le64 reserved[8];
} __attribute__((packed));

enum {
	BTRFS_FILE_EXTENT_INLINE = 0,
	BTRFS_FILE_EXTENT_REG = 1,
	BTRFS_FILE_EXTENT_PREALLOC = 2,
	BTRFS_NR_FILE_EXTENT_TYPES = 3,
};

struct btrfs_file_extent_item {
	__le64 generation;
	__le64 ram_bytes;
	__u8 compression;
	__u8 encryption;
	__le16 other_encoding;
	__u8 type;
	__le64 disk_bytenr;
	__le64 disk_num_bytes;
	__le64 offset;
	__le64 num_bytes;
} __attribute__((packed));

struct btrfs_block_group_item {
	__le64 used;
	__le64 chunk_objectid;
	__le64 flags;
};

struct btrfs_fs_info;

struct extent_io_tree {
	struct rb_root state;
	struct btrfs_fs_info *fs_info;
	void *private_data;
	u64 dirty_bytes;
	bool track_uptodate;
	u8 owner;
	spinlock_t lock;
};

struct extent_map_tree {
	struct rb_root_cached map;
	struct list_head modified_extents;
	rwlock_t lock;
};

enum btrfs_rsv_type {
	BTRFS_BLOCK_RSV_GLOBAL = 0,
	BTRFS_BLOCK_RSV_DELALLOC = 1,
	BTRFS_BLOCK_RSV_TRANS = 2,
	BTRFS_BLOCK_RSV_CHUNK = 3,
	BTRFS_BLOCK_RSV_DELOPS = 4,
	BTRFS_BLOCK_RSV_DELREFS = 5,
	BTRFS_BLOCK_RSV_EMPTY = 6,
	BTRFS_BLOCK_RSV_TEMP = 7,
};

struct btrfs_space_info;

struct btrfs_block_rsv {
	u64 size;
	u64 reserved;
	struct btrfs_space_info *space_info;
	spinlock_t lock;
	bool full;
	bool failfast;
	enum btrfs_rsv_type type: 8;
	u64 qgroup_rsv_size;
	u64 qgroup_rsv_reserved;
};

struct btrfs_block_group;

struct btrfs_free_cluster {
	spinlock_t lock;
	spinlock_t refill_lock;
	struct rb_root root;
	u64 max_size;
	u64 window_start;
	bool fragmented;
	struct btrfs_block_group *block_group;
	struct list_head block_group_list;
};

struct btrfs_discard_ctl {
	struct workqueue_struct *discard_workers;
	struct delayed_work work;
	spinlock_t lock;
	struct btrfs_block_group *block_group;
	struct list_head discard_list[3];
	u64 prev_discard;
	u64 prev_discard_time;
	atomic_t discardable_extents;
	atomic64_t discardable_bytes;
	u64 max_discard_size;
	u64 delay_ms;
	u32 iops_limit;
	u32 kbps_limit;
	u64 discard_extent_bytes;
	u64 discard_bitmap_bytes;
	atomic64_t discard_bytes_saved;
};

struct btrfs_work;

typedef void (*btrfs_func_t)(struct btrfs_work *);

struct btrfs_workqueue;

struct btrfs_work {
	btrfs_func_t func;
	btrfs_func_t ordered_func;
	btrfs_func_t ordered_free;
	struct work_struct normal_work;
	struct list_head ordered_list;
	struct btrfs_workqueue *wq;
	long unsigned int flags;
};

struct btrfs_device;

struct btrfs_dev_replace {
	u64 replace_state;
	time64_t time_started;
	time64_t time_stopped;
	atomic64_t num_write_errors;
	atomic64_t num_uncorrectable_read_errors;
	u64 cursor_left;
	u64 committed_cursor_left;
	u64 cursor_left_last_write_of_item;
	u64 cursor_right;
	u64 cont_reading_from_srcdev_mode;
	int is_valid;
	int item_needs_writeback;
	struct btrfs_device *srcdev;
	struct btrfs_device *tgtdev;
	struct mutex lock_finishing_cancel_unmount;
	struct rw_semaphore rwsem;
	struct btrfs_scrub_progress scrub_progress;
	struct percpu_counter bio_counter;
	wait_queue_head_t replace_wait;
};

enum btrfs_exclusive_operation {
	BTRFS_EXCLOP_NONE = 0,
	BTRFS_EXCLOP_BALANCE_PAUSED = 1,
	BTRFS_EXCLOP_BALANCE = 2,
	BTRFS_EXCLOP_DEV_ADD = 3,
	BTRFS_EXCLOP_DEV_REMOVE = 4,
	BTRFS_EXCLOP_DEV_REPLACE = 5,
	BTRFS_EXCLOP_RESIZE = 6,
	BTRFS_EXCLOP_SWAP_ACTIVATE = 7,
};

struct btrfs_commit_stats {
	u64 commit_count;
	u64 max_commit_dur;
	u64 last_commit_dur;
	u64 total_commit_dur;
};

struct btrfs_root;

struct btrfs_transaction;

struct btrfs_super_block;

struct btrfs_stripe_hash_table;

struct btrfs_fs_devices;

struct reloc_control;

struct btrfs_balance_control;

struct btrfs_subpage_info;

struct ulist;

struct btrfs_delayed_root;

struct btrfs_fs_info {
	u8 chunk_tree_uuid[16];
	long unsigned int flags;
	struct btrfs_root *tree_root;
	struct btrfs_root *chunk_root;
	struct btrfs_root *dev_root;
	struct btrfs_root *fs_root;
	struct btrfs_root *quota_root;
	struct btrfs_root *uuid_root;
	struct btrfs_root *data_reloc_root;
	struct btrfs_root *block_group_root;
	struct btrfs_root *log_root_tree;
	rwlock_t global_root_lock;
	struct rb_root global_root_tree;
	spinlock_t fs_roots_radix_lock;
	struct xarray fs_roots_radix;
	rwlock_t block_group_cache_lock;
	struct rb_root_cached block_group_cache_tree;
	atomic64_t free_chunk_space;
	struct extent_io_tree excluded_extents;
	struct extent_map_tree mapping_tree;
	struct btrfs_block_rsv global_block_rsv;
	struct btrfs_block_rsv trans_block_rsv;
	struct btrfs_block_rsv chunk_block_rsv;
	struct btrfs_block_rsv delayed_block_rsv;
	struct btrfs_block_rsv delayed_refs_rsv;
	struct btrfs_block_rsv empty_block_rsv;
	u64 generation;
	u64 last_trans_committed;
	u64 last_reloc_trans;
	u64 avg_delayed_ref_runtime;
	u64 last_trans_log_full_commit;
	long unsigned int mount_opt;
	long unsigned int pending_changes;
	long unsigned int compress_type: 4;
	unsigned int compress_level;
	u32 commit_interval;
	u64 max_inline;
	struct btrfs_transaction *running_transaction;
	wait_queue_head_t transaction_throttle;
	wait_queue_head_t transaction_wait;
	wait_queue_head_t transaction_blocked_wait;
	wait_queue_head_t async_submit_wait;
	spinlock_t super_lock;
	struct btrfs_super_block *super_copy;
	struct btrfs_super_block *super_for_commit;
	struct super_block *sb;
	struct inode *btree_inode;
	struct mutex tree_log_mutex;
	struct mutex transaction_kthread_mutex;
	struct mutex cleaner_mutex;
	struct mutex chunk_mutex;
	struct mutex ro_block_group_mutex;
	struct btrfs_stripe_hash_table *stripe_hash_table;
	struct mutex ordered_operations_mutex;
	struct rw_semaphore commit_root_sem;
	struct rw_semaphore cleanup_work_sem;
	struct rw_semaphore subvol_sem;
	spinlock_t trans_lock;
	struct mutex reloc_mutex;
	struct list_head trans_list;
	struct list_head dead_roots;
	struct list_head caching_block_groups;
	spinlock_t delayed_iput_lock;
	struct list_head delayed_iputs;
	atomic_t nr_delayed_iputs;
	wait_queue_head_t delayed_iputs_wait;
	atomic64_t tree_mod_seq;
	rwlock_t tree_mod_log_lock;
	struct rb_root tree_mod_log;
	struct list_head tree_mod_seq_list;
	atomic_t async_delalloc_pages;
	spinlock_t ordered_root_lock;
	struct list_head ordered_roots;
	struct mutex delalloc_root_mutex;
	spinlock_t delalloc_root_lock;
	struct list_head delalloc_roots;
	struct btrfs_workqueue *workers;
	struct btrfs_workqueue *hipri_workers;
	struct btrfs_workqueue *delalloc_workers;
	struct btrfs_workqueue *flush_workers;
	struct workqueue_struct *endio_workers;
	struct workqueue_struct *endio_meta_workers;
	struct workqueue_struct *endio_raid56_workers;
	struct workqueue_struct *rmw_workers;
	struct workqueue_struct *compressed_write_workers;
	struct btrfs_workqueue *endio_write_workers;
	struct btrfs_workqueue *endio_freespace_worker;
	struct btrfs_workqueue *caching_workers;
	struct btrfs_workqueue *fixup_workers;
	struct btrfs_workqueue *delayed_workers;
	struct task_struct *transaction_kthread;
	struct task_struct *cleaner_kthread;
	u32 thread_pool_size;
	struct kobject *space_info_kobj;
	struct kobject *qgroups_kobj;
	struct percpu_counter dirty_metadata_bytes;
	struct percpu_counter delalloc_bytes;
	struct percpu_counter ordered_bytes;
	s32 dirty_metadata_batch;
	s32 delalloc_batch;
	struct list_head dirty_cowonly_roots;
	struct btrfs_fs_devices *fs_devices;
	struct list_head space_info;
	struct btrfs_space_info *data_sinfo;
	struct reloc_control *reloc_ctl;
	struct btrfs_free_cluster data_alloc_cluster;
	struct btrfs_free_cluster meta_alloc_cluster;
	spinlock_t defrag_inodes_lock;
	struct rb_root defrag_inodes;
	atomic_t defrag_running;
	seqlock_t profiles_lock;
	u64 avail_data_alloc_bits;
	u64 avail_metadata_alloc_bits;
	u64 avail_system_alloc_bits;
	spinlock_t balance_lock;
	struct mutex balance_mutex;
	atomic_t balance_pause_req;
	atomic_t balance_cancel_req;
	struct btrfs_balance_control *balance_ctl;
	wait_queue_head_t balance_wait_q;
	atomic_t reloc_cancel_req;
	u32 data_chunk_allocations;
	u32 metadata_ratio;
	void *bdev_holder;
	struct mutex scrub_lock;
	atomic_t scrubs_running;
	atomic_t scrub_pause_req;
	atomic_t scrubs_paused;
	atomic_t scrub_cancel_req;
	wait_queue_head_t scrub_pause_wait;
	refcount_t scrub_workers_refcnt;
	struct workqueue_struct *scrub_workers;
	struct workqueue_struct *scrub_wr_completion_workers;
	struct workqueue_struct *scrub_parity_workers;
	struct btrfs_subpage_info *subpage_info;
	struct btrfs_discard_ctl discard_ctl;
	u64 qgroup_flags;
	struct rb_root qgroup_tree;
	spinlock_t qgroup_lock;
	struct ulist *qgroup_ulist;
	struct mutex qgroup_ioctl_lock;
	struct list_head dirty_qgroups;
	u64 qgroup_seq;
	struct mutex qgroup_rescan_lock;
	struct btrfs_key qgroup_rescan_progress;
	struct btrfs_workqueue *qgroup_rescan_workers;
	struct completion qgroup_rescan_completion;
	struct btrfs_work qgroup_rescan_work;
	bool qgroup_rescan_running;
	long unsigned int fs_state;
	struct btrfs_delayed_root *delayed_root;
	spinlock_t buffer_lock;
	struct xarray buffer_radix;
	int backup_root_index;
	struct btrfs_dev_replace dev_replace;
	struct semaphore uuid_tree_rescan_sem;
	struct work_struct async_reclaim_work;
	struct work_struct async_data_reclaim_work;
	struct work_struct preempt_reclaim_work;
	struct work_struct reclaim_bgs_work;
	struct list_head reclaim_bgs;
	int bg_reclaim_threshold;
	spinlock_t unused_bgs_lock;
	struct list_head unused_bgs;
	struct mutex unused_bg_unpin_mutex;
	struct mutex reclaim_bgs_lock;
	u32 nodesize;
	u32 sectorsize;
	u32 sectorsize_bits;
	u32 csum_size;
	u32 csums_per_leaf;
	u32 stripesize;
	u64 max_extent_size;
	spinlock_t swapfile_pins_lock;
	struct rb_root swapfile_pins;
	struct crypto_shash *csum_shash;
	enum btrfs_exclusive_operation exclusive_operation;
	u64 zone_size;
	u64 max_zone_append_size;
	struct mutex zoned_meta_io_lock;
	spinlock_t treelog_bg_lock;
	u64 treelog_bg;
	spinlock_t relocation_bg_lock;
	u64 data_reloc_bg;
	struct mutex zoned_data_reloc_io_lock;
	u64 nr_global_roots;
	spinlock_t zone_active_bgs_lock;
	struct list_head zone_active_bgs;
	struct btrfs_commit_stats commit_stats;
};

struct ulist {
	long unsigned int nnodes;
	struct list_head nodes;
	struct rb_root root;
};

enum {
	EXTENT_BUFFER_UPTODATE = 0,
	EXTENT_BUFFER_DIRTY = 1,
	EXTENT_BUFFER_CORRUPT = 2,
	EXTENT_BUFFER_READAHEAD = 3,
	EXTENT_BUFFER_TREE_REF = 4,
	EXTENT_BUFFER_STALE = 5,
	EXTENT_BUFFER_WRITEBACK = 6,
	EXTENT_BUFFER_READ_ERR = 7,
	EXTENT_BUFFER_UNMAPPED = 8,
	EXTENT_BUFFER_IN_TREE = 9,
	EXTENT_BUFFER_WRITE_ERR = 10,
	EXTENT_BUFFER_NO_CHECK = 11,
};

struct extent_buffer {
	u64 start;
	long unsigned int len;
	long unsigned int bflags;
	struct btrfs_fs_info *fs_info;
	spinlock_t refs_lock;
	atomic_t refs;
	atomic_t io_pages;
	int read_mirror;
	struct callback_head callback_head;
	pid_t lock_owner;
	s8 log_index;
	struct rw_semaphore lock;
	struct page *pages[16];
	struct list_head release_list;
};

enum btrfs_lock_nesting {
	BTRFS_NESTING_NORMAL = 0,
	BTRFS_NESTING_COW = 1,
	BTRFS_NESTING_LEFT = 2,
	BTRFS_NESTING_RIGHT = 3,
	BTRFS_NESTING_LEFT_COW = 4,
	BTRFS_NESTING_RIGHT_COW = 5,
	BTRFS_NESTING_SPLIT = 6,
	BTRFS_NESTING_NEW_ROOT = 7,
	BTRFS_NESTING_MAX = 8,
};

struct btrfs_drew_lock {
	atomic_t readers;
	struct percpu_counter writers;
	wait_queue_head_t pending_writers;
	wait_queue_head_t pending_readers;
};

struct btrfs_header {
	u8 csum[32];
	u8 fsid[16];
	__le64 bytenr;
	__le64 flags;
	u8 chunk_tree_uuid[16];
	__le64 generation;
	__le64 owner;
	__le32 nritems;
	u8 level;
} __attribute__((packed));

struct btrfs_root_backup {
	__le64 tree_root;
	__le64 tree_root_gen;
	__le64 chunk_root;
	__le64 chunk_root_gen;
	__le64 extent_root;
	__le64 extent_root_gen;
	__le64 fs_root;
	__le64 fs_root_gen;
	__le64 dev_root;
	__le64 dev_root_gen;
	__le64 csum_root;
	__le64 csum_root_gen;
	__le64 total_bytes;
	__le64 bytes_used;
	__le64 num_devices;
	__le64 unused_64[4];
	u8 tree_root_level;
	u8 chunk_root_level;
	u8 extent_root_level;
	u8 fs_root_level;
	u8 dev_root_level;
	u8 csum_root_level;
	u8 unused_8[10];
};

struct btrfs_super_block {
	u8 csum[32];
	u8 fsid[16];
	__le64 bytenr;
	__le64 flags;
	__le64 magic;
	__le64 generation;
	__le64 root;
	__le64 chunk_root;
	__le64 log_root;
	__le64 __unused_log_root_transid;
	__le64 total_bytes;
	__le64 bytes_used;
	__le64 root_dir_objectid;
	__le64 num_devices;
	__le32 sectorsize;
	__le32 nodesize;
	__le32 __unused_leafsize;
	__le32 stripesize;
	__le32 sys_chunk_array_size;
	__le64 chunk_root_generation;
	__le64 compat_flags;
	__le64 compat_ro_flags;
	__le64 incompat_flags;
	__le16 csum_type;
	u8 root_level;
	u8 chunk_root_level;
	u8 log_root_level;
	struct btrfs_dev_item dev_item;
	char label[256];
	__le64 cache_generation;
	__le64 uuid_tree_generation;
	u8 metadata_uuid[16];
	__le64 block_group_root;
	__le64 block_group_root_generation;
	u8 block_group_root_level;
	u8 reserved8[7];
	__le64 reserved[25];
	u8 sys_chunk_array[2048];
	struct btrfs_root_backup super_roots[4];
	u8 padding[565];
} __attribute__((packed));

struct btrfs_item {
	struct btrfs_disk_key key;
	__le32 offset;
	__le32 size;
} __attribute__((packed));

struct btrfs_key_ptr {
	struct btrfs_disk_key key;
	__le64 blockptr;
	__le64 generation;
} __attribute__((packed));

struct btrfs_qgroup_swapped_blocks {
	spinlock_t lock;
	bool swapped;
	struct rb_root blocks[8];
};

struct btrfs_root {
	struct rb_node rb_node;
	struct extent_buffer *node;
	struct extent_buffer *commit_root;
	struct btrfs_root *log_root;
	struct btrfs_root *reloc_root;
	long unsigned int state;
	struct btrfs_root_item root_item;
	struct btrfs_key root_key;
	struct btrfs_fs_info *fs_info;
	struct extent_io_tree dirty_log_pages;
	struct mutex objectid_mutex;
	spinlock_t accounting_lock;
	int: 32;
	struct btrfs_block_rsv *block_rsv;
	struct mutex log_mutex;
	wait_queue_head_t log_writer_wait;
	wait_queue_head_t log_commit_wait[2];
	struct list_head log_ctxs[2];
	atomic_t log_writers;
	atomic_t log_commit[2];
	atomic_t log_batch;
	int log_transid;
	int log_transid_committed;
	int last_log_commit;
	pid_t log_start_pid;
	u64 last_trans;
	u32 type;
	int: 32;
	u64 free_objectid;
	struct btrfs_key defrag_progress;
	struct btrfs_key defrag_max;
	long: 48;
	struct list_head dirty_list;
	struct list_head root_list;
	spinlock_t log_extents_lock[2];
	struct list_head logged_list[2];
	spinlock_t inode_lock;
	int: 32;
	struct rb_root inode_tree;
	struct xarray delayed_nodes_tree;
	dev_t anon_dev;
	spinlock_t root_item_lock;
	refcount_t refs;
	int: 32;
	struct mutex delalloc_mutex;
	spinlock_t delalloc_lock;
	int: 32;
	struct list_head delalloc_inodes;
	struct list_head delalloc_root;
	u64 nr_delalloc_inodes;
	struct mutex ordered_extent_mutex;
	spinlock_t ordered_extent_lock;
	int: 32;
	struct list_head ordered_extents;
	struct list_head ordered_root;
	u64 nr_ordered_extents;
	struct list_head reloc_dirty_list;
	int send_in_progress;
	int dedupe_in_progress;
	struct btrfs_drew_lock snapshot_lock;
	atomic_t snapshot_force_cow;
	spinlock_t qgroup_meta_rsv_lock;
	u64 qgroup_meta_rsv_pertrans;
	u64 qgroup_meta_rsv_prealloc;
	wait_queue_head_t qgroup_flush_wait;
	atomic_t nr_swapfiles;
	int: 32;
	struct btrfs_qgroup_swapped_blocks swapped_blocks;
	struct extent_io_tree log_csum_range;
} __attribute__((packed));

struct root_name_map {
	u64 id;
	char name[16];
};

enum {
	WQ_UNBOUND = 2,
	WQ_FREEZABLE = 4,
	WQ_MEM_RECLAIM = 8,
	WQ_HIGHPRI = 16,
	WQ_CPU_INTENSIVE = 32,
	WQ_SYSFS = 64,
	WQ_POWER_EFFICIENT = 128,
	__WQ_DRAINING = 65536,
	__WQ_ORDERED = 131072,
	__WQ_LEGACY = 262144,
	__WQ_ORDERED_EXPLICIT = 524288,
	WQ_MAX_ACTIVE = 512,
	WQ_MAX_UNBOUND_PER_CPU = 4,
	WQ_DFL_ACTIVE = 256,
};

struct bvec_iter_all {
	struct bio_vec bv;
	int idx;
	unsigned int done;
};

enum {
	BIO_NO_PAGE_REF = 0,
	BIO_CLONED = 1,
	BIO_BOUNCED = 2,
	BIO_WORKINGSET = 3,
	BIO_QUIET = 4,
	BIO_CHAIN = 5,
	BIO_REFFED = 6,
	BIO_BPS_THROTTLED = 7,
	BIO_TRACE_COMPLETION = 8,
	BIO_CGROUP_ACCT = 9,
	BIO_QOS_THROTTLED = 10,
	BIO_QOS_MERGED = 11,
	BIO_REMAPPED = 12,
	BIO_ZONE_WRITE_LOCKED = 13,
	BIO_FLAG_LAST = 14,
};

enum req_flag_bits {
	__REQ_FAILFAST_DEV = 8,
	__REQ_FAILFAST_TRANSPORT = 9,
	__REQ_FAILFAST_DRIVER = 10,
	__REQ_SYNC = 11,
	__REQ_META = 12,
	__REQ_PRIO = 13,
	__REQ_NOMERGE = 14,
	__REQ_IDLE = 15,
	__REQ_INTEGRITY = 16,
	__REQ_FUA = 17,
	__REQ_PREFLUSH = 18,
	__REQ_RAHEAD = 19,
	__REQ_BACKGROUND = 20,
	__REQ_NOWAIT = 21,
	__REQ_CGROUP_PUNT = 22,
	__REQ_POLLED = 23,
	__REQ_ALLOC_CACHE = 24,
	__REQ_SWAP = 25,
	__REQ_DRV = 26,
	__REQ_NOUNMAP = 27,
	__REQ_NR_BITS = 28,
};

struct btrfs_qgroup_limit {
	__u64 flags;
	__u64 max_rfer;
	__u64 max_excl;
	__u64 rsv_rfer;
	__u64 rsv_excl;
};

struct btrfs_qgroup_inherit {
	__u64 flags;
	__u64 num_qgroups;
	__u64 num_ref_copies;
	__u64 num_excl_copies;
	struct btrfs_qgroup_limit lim;
	__u64 qgroups[0];
};

struct btrfs_balance_args {
	__u64 profiles;
	union {
		__u64 usage;
		struct {
			__u32 usage_min;
			__u32 usage_max;
		};
	};
	__u64 devid;
	__u64 pstart;
	__u64 pend;
	__u64 vstart;
	__u64 vend;
	__u64 target;
	__u64 flags;
	union {
		__u64 limit;
		struct {
			__u32 limit_min;
			__u32 limit_max;
		};
	};
	__u32 stripes_min;
	__u32 stripes_max;
	__u64 unused[6];
};

struct btrfs_balance_progress {
	__u64 expected;
	__u64 considered;
	__u64 completed;
};

enum btrfs_dev_stat_values {
	BTRFS_DEV_STAT_WRITE_ERRS = 0,
	BTRFS_DEV_STAT_READ_ERRS = 1,
	BTRFS_DEV_STAT_FLUSH_ERRS = 2,
	BTRFS_DEV_STAT_CORRUPTION_ERRS = 3,
	BTRFS_DEV_STAT_GENERATION_ERRS = 4,
	BTRFS_DEV_STAT_VALUES_MAX = 5,
};

enum btrfs_csum_type {
	BTRFS_CSUM_TYPE_CRC32 = 0,
	BTRFS_CSUM_TYPE_XXHASH = 1,
	BTRFS_CSUM_TYPE_SHA256 = 2,
	BTRFS_CSUM_TYPE_BLAKE2 = 3,
};

enum {
	IO_TREE_FS_PINNED_EXTENTS = 0,
	IO_TREE_FS_EXCLUDED_EXTENTS = 1,
	IO_TREE_BTREE_INODE_IO = 2,
	IO_TREE_INODE_IO = 3,
	IO_TREE_INODE_IO_FAILURE = 4,
	IO_TREE_RELOC_BLOCKS = 5,
	IO_TREE_TRANS_DIRTY_PAGES = 6,
	IO_TREE_ROOT_DIRTY_LOG_PAGES = 7,
	IO_TREE_INODE_FILE_EXTENT = 8,
	IO_TREE_LOG_CSUM_RANGE = 9,
	IO_TREE_SELFTEST = 10,
	IO_TREE_DEVICE_ALLOC_STATE = 11,
};

struct io_failure_record;

struct extent_state {
	u64 start;
	u64 end;
	struct rb_node rb_node;
	wait_queue_head_t wq;
	refcount_t refs;
	u32 state;
	struct io_failure_record *failrec;
};

struct io_failure_record {
	struct page *page;
	u64 start;
	u64 len;
	u64 logical;
	int this_mirror;
	int failed_mirror;
	int num_copies;
};

enum btrfs_compression_type {
	BTRFS_COMPRESS_NONE = 0,
	BTRFS_COMPRESS_ZLIB = 1,
	BTRFS_COMPRESS_LZO = 2,
	BTRFS_COMPRESS_ZSTD = 3,
	BTRFS_NR_COMPRESS_TYPES = 4,
};

typedef blk_status_t extent_submit_bio_start_t(struct inode *, struct bio *, u64);

struct extent_changeset {
	u64 bytes_changed;
	struct ulist range_changed;
};

struct btrfs_io_context;

struct btrfs_io_stripe {
	struct btrfs_device *dev;
	union {
		u64 physical;
		struct btrfs_io_context *bioc;
	};
};

struct map_lookup {
	u64 type;
	int io_align;
	int io_width;
	u32 stripe_len;
	int num_stripes;
	int sub_stripes;
	int verified_stripes;
	struct btrfs_io_stripe stripes[0];
};

struct btrfs_space_info {
	spinlock_t lock;
	u64 total_bytes;
	u64 bytes_used;
	u64 bytes_pinned;
	u64 bytes_reserved;
	u64 bytes_may_use;
	u64 bytes_readonly;
	u64 active_total_bytes;
	u64 bytes_zone_unusable;
	u64 max_extent_size;
	u64 chunk_size;
	int bg_reclaim_threshold;
	int clamp;
	unsigned int full: 1;
	unsigned int chunk_alloc: 1;
	unsigned int flush: 1;
	unsigned int force_alloc;
	u64 disk_used;
	u64 disk_total;
	u64 flags;
	struct list_head list;
	struct list_head ro_bgs;
	struct list_head priority_tickets;
	struct list_head tickets;
	u64 reclaim_size;
	u64 tickets_id;
	struct rw_semaphore groups_sem;
	struct list_head block_groups[9];
	struct kobject kobj;
	struct kobject *block_group_kobjs[9];
};

enum {
	BTRFS_FS_STATE_ERROR = 0,
	BTRFS_FS_STATE_REMOUNTING = 1,
	BTRFS_FS_STATE_RO = 2,
	BTRFS_FS_STATE_TRANS_ABORTED = 3,
	BTRFS_FS_STATE_DEV_REPLACING = 4,
	BTRFS_FS_STATE_DUMMY_FS_INFO = 5,
	BTRFS_FS_STATE_NO_CSUMS = 6,
	BTRFS_FS_STATE_LOG_CLEANUP_ERROR = 7,
	BTRFS_FS_STATE_COUNT = 8,
};

struct btrfs_path {
	struct extent_buffer *nodes[8];
	int slots[8];
	u8 locks[8];
	u8 reada;
	u8 lowest_level;
	unsigned int search_for_split: 1;
	unsigned int keep_locks: 1;
	unsigned int skip_locking: 1;
	unsigned int search_commit_root: 1;
	unsigned int need_commit_sem: 1;
	unsigned int skip_release_on_error: 1;
	unsigned int search_for_extension: 1;
};

struct rcu_string;

struct btrfs_zoned_device_info;

struct scrub_ctx;

struct btrfs_device {
	struct list_head dev_list;
	struct list_head dev_alloc_list;
	struct list_head post_commit_list;
	struct btrfs_fs_devices *fs_devices;
	struct btrfs_fs_info *fs_info;
	struct rcu_string *name;
	u64 generation;
	struct block_device *bdev;
	struct btrfs_zoned_device_info *zone_info;
	fmode_t mode;
	dev_t devt;
	long unsigned int dev_state;
	blk_status_t last_flush_error;
	u64 devid;
	u64 total_bytes;
	u64 disk_total_bytes;
	u64 bytes_used;
	u32 io_align;
	u32 io_width;
	u64 type;
	u32 sector_size;
	u8 uuid[16];
	u64 commit_total_bytes;
	u64 commit_bytes_used;
	struct bio flush_bio;
	struct completion flush_wait;
	struct scrub_ctx *scrub_ctx;
	int dev_stats_valid;
	atomic_t dev_stats_ccnt;
	atomic_t dev_stat_values[5];
	struct extent_io_tree alloc_state;
	struct completion kobj_unregister;
	struct kobject devid_kobj;
	u64 scrub_speed_max;
};

enum btrfs_discard_state {
	BTRFS_DISCARD_EXTENTS = 0,
	BTRFS_DISCARD_BITMAPS = 1,
	BTRFS_DISCARD_RESET_CURSOR = 2,
};

struct btrfs_io_ctl {
	void *cur;
	void *orig;
	struct page *page;
	struct page **pages;
	struct btrfs_fs_info *fs_info;
	struct inode *inode;
	long unsigned int size;
	int index;
	int num_pages;
	int entries;
	int bitmaps;
};

struct btrfs_full_stripe_locks_tree {
	struct rb_root root;
	struct mutex lock;
};

struct btrfs_caching_control;

struct btrfs_free_space_ctl;

struct btrfs_block_group {
	struct btrfs_fs_info *fs_info;
	struct inode *inode;
	spinlock_t lock;
	u64 start;
	u64 length;
	u64 pinned;
	u64 reserved;
	u64 used;
	u64 delalloc_bytes;
	u64 bytes_super;
	u64 flags;
	u64 cache_generation;
	u64 global_root_id;
	u32 bitmap_high_thresh;
	u32 bitmap_low_thresh;
	struct rw_semaphore data_rwsem;
	long unsigned int full_stripe_len;
	unsigned int ro;
	unsigned int iref: 1;
	unsigned int has_caching_ctl: 1;
	unsigned int removed: 1;
	unsigned int to_copy: 1;
	unsigned int relocating_repair: 1;
	unsigned int chunk_item_inserted: 1;
	unsigned int zone_is_active: 1;
	unsigned int zoned_data_reloc_ongoing: 1;
	int disk_cache_state;
	int cached;
	struct btrfs_caching_control *caching_ctl;
	u64 last_byte_to_unpin;
	struct btrfs_space_info *space_info;
	struct btrfs_free_space_ctl *free_space_ctl;
	struct rb_node cache_node;
	struct list_head list;
	refcount_t refs;
	struct list_head cluster_list;
	struct list_head bg_list;
	struct list_head ro_list;
	atomic_t frozen;
	struct list_head discard_list;
	int discard_index;
	u64 discard_eligible_time;
	u64 discard_cursor;
	enum btrfs_discard_state discard_state;
	struct list_head dirty_list;
	struct list_head io_list;
	struct btrfs_io_ctl io_ctl;
	atomic_t reservations;
	atomic_t nocow_writers;
	struct mutex free_space_lock;
	int needs_free_space;
	bool seq_zone;
	int swap_extents;
	struct btrfs_full_stripe_locks_tree full_stripe_locks_root;
	u64 alloc_offset;
	u64 zone_unusable;
	u64 zone_capacity;
	u64 meta_write_pointer;
	struct map_lookup *physical_map;
	struct list_head active_bg_list;
	struct work_struct zone_finish_work;
	struct extent_buffer *last_eb;
};

enum {
	BTRFS_FS_CLOSING_START = 0,
	BTRFS_FS_CLOSING_DONE = 1,
	BTRFS_FS_LOG_RECOVERING = 2,
	BTRFS_FS_OPEN = 3,
	BTRFS_FS_QUOTA_ENABLED = 4,
	BTRFS_FS_UPDATE_UUID_TREE_GEN = 5,
	BTRFS_FS_CREATING_FREE_SPACE_TREE = 6,
	BTRFS_FS_BTREE_ERR = 7,
	BTRFS_FS_LOG1_ERR = 8,
	BTRFS_FS_LOG2_ERR = 9,
	BTRFS_FS_QUOTA_OVERRIDE = 10,
	BTRFS_FS_FROZEN = 11,
	BTRFS_FS_BALANCE_RUNNING = 12,
	BTRFS_FS_RELOC_RUNNING = 13,
	BTRFS_FS_CLEANER_RUNNING = 14,
	BTRFS_FS_CSUM_IMPL_FAST = 15,
	BTRFS_FS_DISCARD_RUNNING = 16,
	BTRFS_FS_CLEANUP_SPACE_CACHE_V1 = 17,
	BTRFS_FS_FREE_SPACE_TREE_UNTRUSTED = 18,
	BTRFS_FS_TREE_MOD_LOG_USERS = 19,
	BTRFS_FS_COMMIT_TRANS = 20,
	BTRFS_FS_UNFINISHED_DROPS = 21,
	BTRFS_FS_NEED_ZONE_FINISH = 22,
};

enum btrfs_trans_state {
	TRANS_STATE_RUNNING = 0,
	TRANS_STATE_COMMIT_START = 1,
	TRANS_STATE_COMMIT_DOING = 2,
	TRANS_STATE_UNBLOCKED = 3,
	TRANS_STATE_SUPER_COMMITTED = 4,
	TRANS_STATE_COMPLETED = 5,
	TRANS_STATE_MAX = 6,
};

struct btrfs_delayed_ref_root {
	struct rb_root_cached href_root;
	struct rb_root dirty_extent_root;
	spinlock_t lock;
	atomic_t num_entries;
	long unsigned int num_heads;
	long unsigned int num_heads_ready;
	u64 pending_csums;
	long unsigned int flags;
	u64 run_delayed_start;
	u64 qgroup_to_skip;
};

struct btrfs_transaction {
	u64 transid;
	atomic_t num_extwriters;
	atomic_t num_writers;
	refcount_t use_count;
	long unsigned int flags;
	enum btrfs_trans_state state;
	int aborted;
	struct list_head list;
	struct extent_io_tree dirty_pages;
	time64_t start_time;
	wait_queue_head_t writer_wait;
	wait_queue_head_t commit_wait;
	struct list_head pending_snapshots;
	struct list_head dev_update_list;
	struct list_head switch_commits;
	struct list_head dirty_bgs;
	struct list_head io_bgs;
	struct list_head dropped_roots;
	struct extent_io_tree pinned_extents;
	struct mutex cache_write_mutex;
	spinlock_t dirty_bgs_lock;
	struct list_head deleted_bgs;
	spinlock_t dropped_roots_lock;
	struct btrfs_delayed_ref_root delayed_refs;
	struct btrfs_fs_info *fs_info;
	atomic_t pending_ordered;
	wait_queue_head_t pending_wait;
	spinlock_t releasing_ebs_lock;
	struct list_head releasing_ebs;
};

enum btrfs_chunk_allocation_policy {
	BTRFS_CHUNK_ALLOC_REGULAR = 0,
	BTRFS_CHUNK_ALLOC_ZONED = 1,
};

enum btrfs_read_policy {
	BTRFS_READ_POLICY_PID = 0,
	BTRFS_NR_READ_POLICY = 1,
};

struct btrfs_fs_devices {
	u8 fsid[16];
	u8 metadata_uuid[16];
	bool fsid_change;
	struct list_head fs_list;
	u64 num_devices;
	u64 open_devices;
	u64 rw_devices;
	u64 missing_devices;
	u64 total_rw_bytes;
	u64 total_devices;
	u64 latest_generation;
	struct btrfs_device *latest_dev;
	struct mutex device_list_mutex;
	struct list_head devices;
	struct list_head alloc_list;
	struct list_head seed_list;
	bool seeding;
	int opened;
	bool rotating;
	struct btrfs_fs_info *fs_info;
	struct kobject fsid_kobj;
	struct kobject *devices_kobj;
	struct kobject *devinfo_kobj;
	struct completion kobj_unregister;
	enum btrfs_chunk_allocation_policy chunk_alloc_policy;
	enum btrfs_read_policy read_policy;
};

struct btrfs_balance_control {
	struct btrfs_balance_args data;
	struct btrfs_balance_args meta;
	struct btrfs_balance_args sys;
	u64 flags;
	struct btrfs_balance_progress stat;
};

struct btrfs_subpage_info {
	unsigned int bitmap_nr_bits;
	unsigned int total_nr_bits;
	unsigned int uptodate_offset;
	unsigned int error_offset;
	unsigned int dirty_offset;
	unsigned int writeback_offset;
	unsigned int ordered_offset;
	unsigned int checked_offset;
};

struct btrfs_delayed_root {
	spinlock_t lock;
	struct list_head node_list;
	struct list_head prepare_list;
	atomic_t items;
	atomic_t items_seq;
	int nodes;
	wait_queue_head_t wait;
};

enum {
	BTRFS_ROOT_IN_TRANS_SETUP = 0,
	BTRFS_ROOT_SHAREABLE = 1,
	BTRFS_ROOT_TRACK_DIRTY = 2,
	BTRFS_ROOT_IN_RADIX = 3,
	BTRFS_ROOT_ORPHAN_ITEM_INSERTED = 4,
	BTRFS_ROOT_DEFRAG_RUNNING = 5,
	BTRFS_ROOT_FORCE_COW = 6,
	BTRFS_ROOT_MULTI_LOG_TASKS = 7,
	BTRFS_ROOT_DIRTY = 8,
	BTRFS_ROOT_DELETING = 9,
	BTRFS_ROOT_DEAD_RELOC_TREE = 10,
	BTRFS_ROOT_DEAD_TREE = 11,
	BTRFS_ROOT_HAS_LOG_TREE = 12,
	BTRFS_ROOT_QGROUP_FLUSHING = 13,
	BTRFS_ROOT_ORPHAN_CLEANUP = 14,
	BTRFS_ROOT_UNFINISHED_DROP = 15,
	BTRFS_ROOT_RESET_LOCKDEP_CLASS = 16,
};

enum {
	BTRFS_MOUNT_NODATASUM = 1,
	BTRFS_MOUNT_NODATACOW = 2,
	BTRFS_MOUNT_NOBARRIER = 4,
	BTRFS_MOUNT_SSD = 8,
	BTRFS_MOUNT_DEGRADED = 16,
	BTRFS_MOUNT_COMPRESS = 32,
	BTRFS_MOUNT_NOTREELOG = 64,
	BTRFS_MOUNT_FLUSHONCOMMIT = 128,
	BTRFS_MOUNT_SSD_SPREAD = 256,
	BTRFS_MOUNT_NOSSD = 512,
	BTRFS_MOUNT_DISCARD_SYNC = 1024,
	BTRFS_MOUNT_FORCE_COMPRESS = 2048,
	BTRFS_MOUNT_SPACE_CACHE = 4096,
	BTRFS_MOUNT_CLEAR_CACHE = 8192,
	BTRFS_MOUNT_USER_SUBVOL_RM_ALLOWED = 16384,
	BTRFS_MOUNT_ENOSPC_DEBUG = 32768,
	BTRFS_MOUNT_AUTO_DEFRAG = 65536,
	BTRFS_MOUNT_USEBACKUPROOT = 131072,
	BTRFS_MOUNT_SKIP_BALANCE = 262144,
	BTRFS_MOUNT_CHECK_INTEGRITY = 524288,
	BTRFS_MOUNT_CHECK_INTEGRITY_DATA = 1048576,
	BTRFS_MOUNT_PANIC_ON_FATAL_ERROR = 2097152,
	BTRFS_MOUNT_RESCAN_UUID_TREE = 4194304,
	BTRFS_MOUNT_FRAGMENT_DATA = 8388608,
	BTRFS_MOUNT_FRAGMENT_METADATA = 16777216,
	BTRFS_MOUNT_FREE_SPACE_TREE = 33554432,
	BTRFS_MOUNT_NOLOGREPLAY = 67108864,
	BTRFS_MOUNT_REF_VERIFY = 134217728,
	BTRFS_MOUNT_DISCARD_ASYNC = 268435456,
	BTRFS_MOUNT_IGNOREBADROOTS = 536870912,
	BTRFS_MOUNT_IGNOREDATACSUMS = 1073741824,
};

struct btrfs_ordered_inode_tree {
	spinlock_t lock;
	struct rb_root tree;
	struct rb_node *last;
};

enum {
	BTRFS_ORDERED_REGULAR = 0,
	BTRFS_ORDERED_NOCOW = 1,
	BTRFS_ORDERED_PREALLOC = 2,
	BTRFS_ORDERED_COMPRESSED = 3,
	BTRFS_ORDERED_DIRECT = 4,
	BTRFS_ORDERED_IO_DONE = 5,
	BTRFS_ORDERED_COMPLETE = 6,
	BTRFS_ORDERED_IOERR = 7,
	BTRFS_ORDERED_TRUNCATED = 8,
	BTRFS_ORDERED_LOGGED = 9,
	BTRFS_ORDERED_LOGGED_CSUM = 10,
	BTRFS_ORDERED_PENDING = 11,
	BTRFS_ORDERED_ENCODED = 12,
};

struct btrfs_ordered_extent {
	u64 file_offset;
	u64 num_bytes;
	u64 ram_bytes;
	u64 disk_bytenr;
	u64 disk_num_bytes;
	u64 offset;
	u64 bytes_left;
	u64 outstanding_isize;
	u64 truncated_len;
	long unsigned int flags;
	int compress_type;
	int qgroup_rsv;
	refcount_t refs;
	struct inode *inode;
	struct list_head list;
	struct list_head log_list;
	wait_queue_head_t wait;
	struct rb_node rb_node;
	struct list_head root_extent_list;
	struct btrfs_work work;
	struct completion completion;
	struct btrfs_work flush_work;
	struct list_head work_list;
	u64 physical;
	struct block_device *bdev;
};

struct btrfs_delayed_node {
	u64 inode_id;
	u64 bytes_reserved;
	struct btrfs_root *root;
	struct list_head n_list;
	struct list_head p_list;
	struct rb_root_cached ins_root;
	struct rb_root_cached del_root;
	struct mutex mutex;
	struct btrfs_inode_item inode_item;
	refcount_t refs;
	u64 index_cnt;
	long unsigned int flags;
	int count;
	u32 curr_index_batch_size;
	u32 index_item_leaves;
};

enum {
	BTRFS_INODE_FLUSH_ON_CLOSE = 0,
	BTRFS_INODE_DUMMY = 1,
	BTRFS_INODE_IN_DEFRAG = 2,
	BTRFS_INODE_HAS_ASYNC_EXTENT = 3,
	BTRFS_INODE_NEEDS_FULL_SYNC = 4,
	BTRFS_INODE_COPY_EVERYTHING = 5,
	BTRFS_INODE_IN_DELALLOC_LIST = 6,
	BTRFS_INODE_HAS_PROPS = 7,
	BTRFS_INODE_SNAPSHOT_FLUSH = 8,
	BTRFS_INODE_NO_XATTRS = 9,
	BTRFS_INODE_NO_DELALLOC_FLUSH = 10,
	BTRFS_INODE_VERITY_IN_PROGRESS = 11,
};

struct btrfs_inode {
	struct btrfs_root *root;
	struct btrfs_key location;
	spinlock_t lock;
	struct extent_map_tree extent_tree;
	struct extent_io_tree io_tree;
	struct extent_io_tree io_failure_tree;
	struct extent_io_tree file_extent_tree;
	struct mutex log_mutex;
	struct btrfs_ordered_inode_tree ordered_tree;
	struct list_head delalloc_inodes;
	struct rb_node rb_node;
	long unsigned int runtime_flags;
	atomic_t sync_writers;
	u64 generation;
	u64 last_trans;
	u64 logged_trans;
	int last_sub_trans;
	int last_log_commit;
	u64 delalloc_bytes;
	union {
		u64 new_delalloc_bytes;
		u64 last_dir_index_offset;
	};
	u64 defrag_bytes;
	u64 disk_i_size;
	u64 index_cnt;
	u64 dir_index;
	u64 last_unlink_trans;
	u64 last_reflink_trans;
	u64 csum_bytes;
	u32 flags;
	u32 ro_flags;
	unsigned int outstanding_extents;
	struct btrfs_block_rsv block_rsv;
	unsigned int prop_compress;
	unsigned int defrag_compress;
	struct btrfs_delayed_node *delayed_node;
	struct timespec64 i_otime;
	struct list_head delayed_iput;
	struct rw_semaphore i_mmap_lock;
	struct inode vfs_inode;
};

struct btrfs_delayed_ref_node {
	struct rb_node ref_node;
	struct list_head add_list;
	u64 bytenr;
	u64 num_bytes;
	u64 seq;
	refcount_t refs;
	int ref_mod;
	unsigned int action: 8;
	unsigned int type: 8;
	unsigned int is_head: 1;
	unsigned int in_tree: 1;
};

struct btrfs_delayed_extent_op {
	struct btrfs_disk_key key;
	u8 level;
	bool update_key;
	bool update_flags;
	u64 flags_to_set;
};

struct btrfs_delayed_ref_head {
	u64 bytenr;
	u64 num_bytes;
	refcount_t refs;
	struct mutex mutex;
	spinlock_t lock;
	struct rb_root_cached ref_tree;
	struct list_head ref_add_list;
	struct rb_node href_node;
	struct btrfs_delayed_extent_op *extent_op;
	int total_ref_mod;
	int ref_mod;
	unsigned int must_insert_reserved: 1;
	unsigned int is_data: 1;
	unsigned int is_system: 1;
	unsigned int processing: 1;
};

struct btrfs_pending_snapshot;

struct btrfs_trans_handle {
	u64 transid;
	u64 bytes_reserved;
	u64 chunk_bytes_reserved;
	long unsigned int delayed_ref_updates;
	struct btrfs_transaction *transaction;
	struct btrfs_block_rsv *block_rsv;
	struct btrfs_block_rsv *orig_rsv;
	struct btrfs_pending_snapshot *pending_snapshot;
	refcount_t use_count;
	unsigned int type;
	short int aborted;
	bool adding_csums;
	bool allocating_chunk;
	bool removing_chunk;
	bool reloc_reserved;
	bool in_fsync;
	struct btrfs_fs_info *fs_info;
	struct list_head new_bgs;
};

struct btrfs_pending_snapshot {
	struct dentry *dentry;
	struct inode *dir;
	struct btrfs_root *root;
	struct btrfs_root_item *root_item;
	struct btrfs_root *snap;
	struct btrfs_qgroup_inherit *inherit;
	struct btrfs_path *path;
	struct btrfs_block_rsv block_rsv;
	int error;
	dev_t anon_dev;
	bool readonly;
	struct list_head list;
};

enum btrfs_raid_types {
	BTRFS_RAID_SINGLE = 0,
	BTRFS_RAID_RAID0 = 1,
	BTRFS_RAID_RAID1 = 2,
	BTRFS_RAID_DUP = 3,
	BTRFS_RAID_RAID10 = 4,
	BTRFS_RAID_RAID5 = 5,
	BTRFS_RAID_RAID6 = 6,
	BTRFS_RAID_RAID1C3 = 7,
	BTRFS_RAID_RAID1C4 = 8,
	BTRFS_NR_RAID_TYPES = 9,
};

struct rcu_string {
	struct callback_head rcu;
	char str[0];
};

struct btrfs_zoned_device_info {
	u64 zone_size;
	u8 zone_size_shift;
	u64 max_zone_append_size;
	u32 nr_zones;
	unsigned int max_active_zones;
	atomic_t active_zones_left;
	long unsigned int *seq_zones;
	long unsigned int *empty_zones;
	long unsigned int *active_zones;
	struct blk_zone *zone_cache;
	struct blk_zone sb_zones[6];
};

struct btrfs_bio {
	unsigned int mirror_num;
	u64 file_offset;
	struct btrfs_device *device;
	u8 *csum;
	u8 csum_inline[64];
	struct bvec_iter iter;
	struct work_struct end_io_work;
	struct bio bio;
};

struct btrfs_io_context {
	refcount_t refs;
	atomic_t stripes_pending;
	struct btrfs_fs_info *fs_info;
	u64 map_type;
	bio_end_io_t *end_io;
	struct bio *orig_bio;
	void *private;
	atomic_t error;
	int max_errors;
	int num_stripes;
	int mirror_num;
	int num_tgtdevs;
	int *tgtdev_map;
	u64 *raid_map;
	struct btrfs_io_stripe stripes[0];
};

struct btrfs_raid_attr {
	u8 sub_stripes;
	u8 dev_stripes;
	u8 devs_max;
	u8 devs_min;
	u8 tolerated_failures;
	u8 devs_increment;
	u8 ncopies;
	u8 nparity;
	u8 mindev_error;
	const char raid_name[8];
	u64 bg_flag;
};

enum btrfs_map_op {
	BTRFS_MAP_READ = 0,
	BTRFS_MAP_WRITE = 1,
	BTRFS_MAP_DISCARD = 2,
	BTRFS_MAP_GET_READ_MIRRORS = 3,
};

enum btrfs_trim_state {
	BTRFS_TRIM_STATE_UNTRIMMED = 0,
	BTRFS_TRIM_STATE_TRIMMED = 1,
	BTRFS_TRIM_STATE_TRIMMING = 2,
};

struct btrfs_free_space {
	struct rb_node offset_index;
	struct rb_node bytes_index;
	u64 offset;
	u64 bytes;
	u64 max_extent_size;
	long unsigned int *bitmap;
	struct list_head list;
	enum btrfs_trim_state trim_state;
	s32 bitmap_extents;
};

struct btrfs_free_space_op;

struct btrfs_free_space_ctl {
	spinlock_t tree_lock;
	struct rb_root free_space_offset;
	struct rb_root_cached free_space_bytes;
	u64 free_space;
	int extents_thresh;
	int free_extents;
	int total_bitmaps;
	int unit;
	u64 start;
	s32 discardable_extents[2];
	s64 discardable_bytes[2];
	const struct btrfs_free_space_op *op;
	struct btrfs_block_group *block_group;
	struct mutex cache_writeout_mutex;
	struct list_head trimming_ranges;
};

struct btrfs_free_space_op {
	bool (*use_bitmap)(struct btrfs_free_space_ctl *, struct btrfs_free_space *);
};

enum btrfs_qgroup_rsv_type {
	BTRFS_QGROUP_RSV_DATA = 0,
	BTRFS_QGROUP_RSV_META_PERTRANS = 1,
	BTRFS_QGROUP_RSV_META_PREALLOC = 2,
	BTRFS_QGROUP_RSV_LAST = 3,
};

enum btrfs_disk_cache_state {
	BTRFS_DC_WRITTEN = 0,
	BTRFS_DC_ERROR = 1,
	BTRFS_DC_CLEAR = 2,
	BTRFS_DC_SETUP = 3,
};

struct btrfs_caching_control {
	struct list_head list;
	struct mutex mutex;
	wait_queue_head_t wait;
	struct btrfs_work work;
	struct btrfs_block_group *block_group;
	u64 progress;
	refcount_t count;
};

struct async_submit_bio {
	struct inode *inode;
	struct bio *bio;
	extent_submit_bio_start_t *submit_bio_start;
	int mirror_num;
	u64 dio_file_offset;
	struct btrfs_work work;
	blk_status_t status;
};

struct btrfs_workqueue {
	struct workqueue_struct *normal_wq;
	struct btrfs_fs_info *fs_info;
	struct list_head ordered_list;
	spinlock_t list_lock;
	atomic_t pending;
	int limit_active;
	int current_active;
	int thresh;
	unsigned int count;
	spinlock_t thres_lock;
};

enum {
	WORK_DONE_BIT = 0,
	WORK_ORDER_DONE_BIT = 1,
};

typedef int (*list_cmp_func_t)(void *, const struct list_head *, const struct list_head *);

struct btrfs_inode_ref {
	__le64 index;
	__le16 name_len;
} __attribute__((packed));

struct btrfs_inode_extref {
	__le64 parent_objectid;
	__le64 index;
	__le16 name_len;
	__u8 name[0];
} __attribute__((packed));

struct btrfs_dir_log_item {
	__le64 end;
};

enum {
	EXTENT_FLAG_PINNED = 0,
	EXTENT_FLAG_COMPRESSED = 1,
	EXTENT_FLAG_PREALLOC = 2,
	EXTENT_FLAG_LOGGING = 3,
	EXTENT_FLAG_FILLING = 4,
	EXTENT_FLAG_FS_MAPPING = 5,
	EXTENT_FLAG_MERGED = 6,
};

struct extent_map {
	struct rb_node rb_node;
	u64 start;
	u64 len;
	u64 mod_start;
	u64 mod_len;
	u64 orig_start;
	u64 orig_block_len;
	u64 ram_bytes;
	u64 block_start;
	u64 block_len;
	u64 generation;
	long unsigned int flags;
	struct map_lookup *map_lookup;
	refcount_t refs;
	unsigned int compress_type;
	struct list_head list;
};

struct btrfs_drop_extents_args {
	struct btrfs_path *path;
	u64 start;
	u64 end;
	bool drop_cache;
	bool replace_extent;
	u32 extent_item_size;
	u64 drop_end;
	u64 bytes_found;
	bool extent_inserted;
};

struct btrfs_map_token {
	struct extent_buffer *eb;
	char *kaddr;
	long unsigned int offset;
};

struct btrfs_item_batch {
	const struct btrfs_key *keys;
	const u32 *data_sizes;
	u32 total_data_size;
	int nr;
};

struct btrfs_ordered_sum {
	u64 bytenr;
	int len;
	struct list_head list;
	u8 sums[0];
};

enum btrfs_ref_type {
	BTRFS_REF_NOT_SET = 0,
	BTRFS_REF_DATA = 1,
	BTRFS_REF_METADATA = 2,
	BTRFS_REF_LAST = 3,
};

struct btrfs_data_ref {
	u64 owning_root;
	u64 ino;
	u64 offset;
};

struct btrfs_tree_ref {
	int level;
	u64 owning_root;
};

struct btrfs_ref {
	enum btrfs_ref_type type;
	int action;
	bool skip_qgroup;
	u64 bytenr;
	u64 len;
	u64 parent;
	union {
		struct btrfs_data_ref data_ref;
		struct btrfs_tree_ref tree_ref;
	};
};

struct btrfs_log_ctx {
	int log_ret;
	int log_transid;
	bool log_new_dentries;
	bool logging_new_name;
	bool logged_before;
	u64 last_dir_item_offset;
	struct inode *inode;
	struct list_head list;
	struct list_head ordered_extents;
};

struct btrfs_truncate_control {
	struct btrfs_inode *inode;
	u64 new_size;
	u64 extents_found;
	u64 last_size;
	u64 sub_bytes;
	u64 ino;
	u32 min_type;
	bool skip_ref_updates;
	bool clear_extent_range;
};

enum {
	LOG_INODE_ALL = 0,
	LOG_INODE_EXISTS = 1,
	LOG_OTHER_INODE = 2,
	LOG_OTHER_INODE_ALL = 3,
};

enum {
	LOG_WALK_PIN_ONLY = 0,
	LOG_WALK_REPLAY_INODES = 1,
	LOG_WALK_REPLAY_DIR_INDEX = 2,
	LOG_WALK_REPLAY_ALL = 3,
};

struct walk_control {
	int free;
	int pin;
	int stage;
	bool ignore_cur_inode;
	struct btrfs_root *replay_dest;
	struct btrfs_trans_handle *trans;
	int (*process_func)(struct btrfs_root *, struct extent_buffer *, struct walk_control *, u64, int);
};

struct btrfs_ino_list {
	u64 ino;
	u64 parent;
	struct list_head list;
};

struct btrfs_dir_list {
	u64 ino;
	struct list_head list;
};

struct posix_acl_xattr_header {
	__le32 a_version;
};

struct btrfs_stream_header {
	char magic[13];
	__le32 version;
} __attribute__((packed));

struct btrfs_cmd_header {
	__le32 len;
	__le16 cmd;
	__le32 crc;
} __attribute__((packed));

struct btrfs_tlv_header {
	__le16 tlv_type;
	__le16 tlv_len;
};

enum btrfs_send_cmd {
	BTRFS_SEND_C_UNSPEC = 0,
	BTRFS_SEND_C_SUBVOL = 1,
	BTRFS_SEND_C_SNAPSHOT = 2,
	BTRFS_SEND_C_MKFILE = 3,
	BTRFS_SEND_C_MKDIR = 4,
	BTRFS_SEND_C_MKNOD = 5,
	BTRFS_SEND_C_MKFIFO = 6,
	BTRFS_SEND_C_MKSOCK = 7,
	BTRFS_SEND_C_SYMLINK = 8,
	BTRFS_SEND_C_RENAME = 9,
	BTRFS_SEND_C_LINK = 10,
	BTRFS_SEND_C_UNLINK = 11,
	BTRFS_SEND_C_RMDIR = 12,
	BTRFS_SEND_C_SET_XATTR = 13,
	BTRFS_SEND_C_REMOVE_XATTR = 14,
	BTRFS_SEND_C_WRITE = 15,
	BTRFS_SEND_C_CLONE = 16,
	BTRFS_SEND_C_TRUNCATE = 17,
	BTRFS_SEND_C_CHMOD = 18,
	BTRFS_SEND_C_CHOWN = 19,
	BTRFS_SEND_C_UTIMES = 20,
	BTRFS_SEND_C_END = 21,
	BTRFS_SEND_C_UPDATE_EXTENT = 22,
	BTRFS_SEND_C_MAX_V1 = 22,
	BTRFS_SEND_C_FALLOCATE = 23,
	BTRFS_SEND_C_FILEATTR = 24,
	BTRFS_SEND_C_ENCODED_WRITE = 25,
	BTRFS_SEND_C_MAX_V2 = 25,
	BTRFS_SEND_C_MAX = 25,
};

enum {
	BTRFS_SEND_A_UNSPEC = 0,
	BTRFS_SEND_A_UUID = 1,
	BTRFS_SEND_A_CTRANSID = 2,
	BTRFS_SEND_A_INO = 3,
	BTRFS_SEND_A_SIZE = 4,
	BTRFS_SEND_A_MODE = 5,
	BTRFS_SEND_A_UID = 6,
	BTRFS_SEND_A_GID = 7,
	BTRFS_SEND_A_RDEV = 8,
	BTRFS_SEND_A_CTIME = 9,
	BTRFS_SEND_A_MTIME = 10,
	BTRFS_SEND_A_ATIME = 11,
	BTRFS_SEND_A_OTIME = 12,
	BTRFS_SEND_A_XATTR_NAME = 13,
	BTRFS_SEND_A_XATTR_DATA = 14,
	BTRFS_SEND_A_PATH = 15,
	BTRFS_SEND_A_PATH_TO = 16,
	BTRFS_SEND_A_PATH_LINK = 17,
	BTRFS_SEND_A_FILE_OFFSET = 18,
	BTRFS_SEND_A_DATA = 19,
	BTRFS_SEND_A_CLONE_UUID = 20,
	BTRFS_SEND_A_CLONE_CTRANSID = 21,
	BTRFS_SEND_A_CLONE_PATH = 22,
	BTRFS_SEND_A_CLONE_OFFSET = 23,
	BTRFS_SEND_A_CLONE_LEN = 24,
	BTRFS_SEND_A_MAX_V1 = 24,
	BTRFS_SEND_A_FALLOCATE_MODE = 25,
	BTRFS_SEND_A_FILEATTR = 26,
	BTRFS_SEND_A_UNENCODED_FILE_LEN = 27,
	BTRFS_SEND_A_UNENCODED_LEN = 28,
	BTRFS_SEND_A_UNENCODED_OFFSET = 29,
	BTRFS_SEND_A_COMPRESSION = 30,
	BTRFS_SEND_A_ENCRYPTION = 31,
	BTRFS_SEND_A_MAX_V2 = 31,
	BTRFS_SEND_A_MAX = 31,
};

struct btrfs_ioctl_send_args {
	__s64 send_fd;
	__u64 clone_sources_count;
	__u64 *clone_sources;
	__u64 parent_root;
	__u64 flags;
	__u32 version;
	__u8 reserved[28];
};

struct btrfs_root_ref {
	__le64 dirid;
	__le64 sequence;
	__le16 name_len;
} __attribute__((packed));

enum {
	READA_NONE = 0,
	READA_BACK = 1,
	READA_FORWARD = 2,
	READA_FORWARD_ALWAYS = 3,
};

typedef int iterate_extent_inodes_t(u64, u64, u64, void *);

struct fs_path {
	union {
		struct {
			char *start;
			char *end;
			char *buf;
			short unsigned int buf_len: 15;
			short unsigned int reversed: 1;
			char inline_buf[0];
		};
		char pad[256];
	};
};

struct clone_root {
	struct btrfs_root *root;
	u64 ino;
	u64 offset;
	u64 found_refs;
};

struct send_ctx {
	struct file *send_filp;
	loff_t send_off;
	char *send_buf;
	u32 send_size;
	u32 send_max_size;
	bool put_data;
	struct page **send_buf_pages;
	u64 flags;
	u32 proto;
	struct btrfs_root *send_root;
	struct btrfs_root *parent_root;
	struct clone_root *clone_roots;
	int clone_roots_cnt;
	struct btrfs_path *left_path;
	struct btrfs_path *right_path;
	struct btrfs_key *cmp_key;
	u64 last_reloc_trans;
	u64 cur_ino;
	u64 cur_inode_gen;
	u64 cur_inode_size;
	u64 cur_inode_mode;
	u64 cur_inode_rdev;
	u64 cur_inode_last_extent;
	u64 cur_inode_next_write_offset;
	bool cur_inode_new;
	bool cur_inode_new_gen;
	bool cur_inode_deleted;
	bool ignore_cur_inode;
	u64 send_progress;
	struct list_head new_refs;
	struct list_head deleted_refs;
	struct xarray name_cache;
	struct list_head name_cache_list;
	int name_cache_size;
	struct inode *cur_inode;
	struct file_ra_state ra;
	u64 page_cache_clear_start;
	bool clean_page_cache;
	struct rb_root pending_dir_moves;
	struct rb_root waiting_dir_moves;
	struct rb_root orphan_dirs;
	struct rb_root rbtree_new_refs;
	struct rb_root rbtree_deleted_refs;
};

struct pending_dir_move {
	struct rb_node node;
	struct list_head list;
	u64 parent_ino;
	u64 ino;
	u64 gen;
	struct list_head update_refs;
};

struct waiting_dir_move {
	struct rb_node node;
	u64 ino;
	u64 rmdir_ino;
	u64 rmdir_gen;
	bool orphanized;
};

struct orphan_dir_info {
	struct rb_node node;
	u64 ino;
	u64 gen;
	u64 last_dir_index_offset;
};

struct name_cache_entry {
	struct list_head list;
	struct list_head radix_list;
	u64 ino;
	u64 gen;
	u64 parent_ino;
	u64 parent_gen;
	int ret;
	int need_later_update;
	int name_len;
	char name[0];
};

enum btrfs_compare_tree_result {
	BTRFS_COMPARE_TREE_NEW = 0,
	BTRFS_COMPARE_TREE_DELETED = 1,
	BTRFS_COMPARE_TREE_CHANGED = 2,
	BTRFS_COMPARE_TREE_SAME = 3,
};

typedef int (*iterate_inode_ref_t)(int, u64, int, struct fs_path *, void *);

typedef int (*iterate_dir_item_t)(int, struct btrfs_key *, const char *, int, const char *, int, void *);

struct backref_ctx {
	struct send_ctx *sctx;
	u64 found;
	u64 cur_objectid;
	u64 cur_offset;
	u64 extent_len;
	int found_itself;
};

enum inode_state {
	inode_state_no_change = 0,
	inode_state_will_create = 1,
	inode_state_did_create = 2,
	inode_state_will_delete = 3,
	inode_state_did_delete = 4,
};

struct recorded_ref {
	struct list_head list;
	char *name;
	struct fs_path *full_path;
	u64 dir;
	u64 dir_gen;
	int name_len;
	struct rb_node node;
	struct rb_root *root;
};

struct find_xattr_ctx {
	const char *name;
	int name_len;
	int found_idx;
	char *found_data;
	int found_data_len;
};

struct parent_paths_ctx {
	struct list_head *refs;
	struct send_ctx *sctx;
};

enum btrfs_caching_type {
	BTRFS_CACHE_NO = 0,
	BTRFS_CACHE_STARTED = 1,
	BTRFS_CACHE_FINISHED = 2,
	BTRFS_CACHE_ERROR = 3,
};

enum btrfs_reserve_flush_enum {
	BTRFS_RESERVE_NO_FLUSH = 0,
	BTRFS_RESERVE_FLUSH_LIMIT = 1,
	BTRFS_RESERVE_FLUSH_EVICT = 2,
	BTRFS_RESERVE_FLUSH_DATA = 3,
	BTRFS_RESERVE_FLUSH_FREE_SPACE_INODE = 4,
	BTRFS_RESERVE_FLUSH_ALL = 5,
	BTRFS_RESERVE_FLUSH_ALL_STEAL = 6,
};

enum btrfs_chunk_alloc_enum {
	CHUNK_ALLOC_NO_FORCE = 0,
	CHUNK_ALLOC_LIMITED = 1,
	CHUNK_ALLOC_FORCE = 2,
	CHUNK_ALLOC_FORCE_FOR_EXTENT = 3,
};

struct efi_generic_dev_path {
	u8 type;
	u8 sub_type;
	u16 length;
};

typedef u16 ucs2_char_t;

struct efi_variable {
	efi_char16_t VariableName[512];
	efi_guid_t VendorGuid;
	long unsigned int DataSize;
	__u8 Data[1024];
	efi_status_t Status;
	__u32 Attributes;
} __attribute__((packed));

struct efivar_entry {
	struct efi_variable var;
	struct list_head list;
	struct kobject kobj;
};

struct variable_validate {
	efi_guid_t vendor;
	char *name;
	bool (*validate)(efi_char16_t *, int, u8 *, long unsigned int);
};

struct sigevent {
	sigval_t sigev_value;
	int sigev_signo;
	int sigev_notify;
	union {
		int _pad[12];
		int _tid;
		struct {
			void (*_function)(sigval_t);
			void *_attribute;
		} _sigev_thread;
	} _sigev_un;
};

enum inode_i_mutex_lock_class {
	I_MUTEX_NORMAL = 0,
	I_MUTEX_PARENT = 1,
	I_MUTEX_CHILD = 2,
	I_MUTEX_XATTR = 3,
	I_MUTEX_NONDIR2 = 4,
	I_MUTEX_PARENT2 = 5,
};

struct ipc_ids {
	int in_use;
	short unsigned int seq;
	struct rw_semaphore rwsem;
	struct idr ipcs_idr;
	int max_idx;
	int last_idx;
	int next_id;
	struct rhashtable key_ht;
};

struct ipc_namespace {
	struct ipc_ids ids[3];
	int sem_ctls[4];
	int used_sems;
	unsigned int msg_ctlmax;
	unsigned int msg_ctlmnb;
	unsigned int msg_ctlmni;
	atomic_t msg_bytes;
	atomic_t msg_hdrs;
	size_t shm_ctlmax;
	size_t shm_ctlall;
	long unsigned int shm_tot;
	int shm_ctlmni;
	int shm_rmid_forced;
	struct notifier_block ipcns_nb;
	struct vfsmount *mq_mnt;
	unsigned int mq_queues_count;
	unsigned int mq_queues_max;
	unsigned int mq_msg_max;
	unsigned int mq_msgsize_max;
	unsigned int mq_msg_default;
	unsigned int mq_msgsize_default;
	struct ctl_table_set mq_set;
	struct ctl_table_header *mq_sysctls;
	struct ctl_table_set ipc_set;
	struct ctl_table_header *ipc_sysctls;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct llist_node mnt_llist;
	struct ns_common ns;
};

struct compat_sigevent {
	compat_sigval_t sigev_value;
	compat_int_t sigev_signo;
	compat_int_t sigev_notify;
	union {
		compat_int_t _pad[13];
		compat_int_t _tid;
		struct {
			compat_uptr_t _function;
			compat_uptr_t _attribute;
		} _sigev_thread;
	} _sigev_un;
};

struct msg_msgseg;

struct msg_msg {
	struct list_head m_list;
	long int m_type;
	size_t m_ts;
	struct msg_msgseg *next;
	void *security;
};

struct mqueue_fs_context {
	struct ipc_namespace *ipc_ns;
	bool newns;
};

struct posix_msg_tree_node {
	struct rb_node rb_node;
	struct list_head msg_list;
	int priority;
};

struct ext_wait_queue {
	struct task_struct *task;
	struct list_head list;
	struct msg_msg *msg;
	int state;
};

struct mqueue_inode_info {
	spinlock_t lock;
	struct inode vfs_inode;
	wait_queue_head_t wait_q;
	struct rb_root msg_tree;
	struct rb_node *msg_tree_rightmost;
	struct posix_msg_tree_node *node_cache;
	struct mq_attr attr;
	struct sigevent notify;
	struct pid *notify_owner;
	u32 notify_self_exec_id;
	struct user_namespace *notify_user_ns;
	struct ucounts *ucounts;
	struct sock *notify_sock;
	struct sk_buff *notify_cookie;
	struct ext_wait_queue e_wait_q[2];
	long unsigned int qsize;
};

struct compat_mq_attr {
	compat_long_t mq_flags;
	compat_long_t mq_maxmsg;
	compat_long_t mq_msgsize;
	compat_long_t mq_curmsgs;
	compat_long_t __reserved[4];
};

enum tpm_duration {
	TPM_SHORT = 0,
	TPM_MEDIUM = 1,
	TPM_LONG = 2,
	TPM_LONG_LONG = 3,
	TPM_UNDEFINED = 4,
	TPM_NUM_DURATIONS = 4,
};

struct trusted_key_payload {
	struct callback_head rcu;
	unsigned int key_len;
	unsigned int blob_len;
	unsigned char migratable;
	unsigned char old_format;
	unsigned char key[129];
	unsigned char blob[512];
};

struct trusted_key_ops {
	unsigned char migratable;
	int (*init)();
	int (*seal)(struct trusted_key_payload *, char *);
	int (*unseal)(struct trusted_key_payload *, char *);
	int (*get_random)(unsigned char *, size_t);
	void (*exit)();
};

struct trusted_key_source {
	char *name;
	struct trusted_key_ops *ops;
};

struct match_token {
	int token;
	const char *pattern;
};

enum {
	MAX_OPT_ARGS = 3,
};

typedef struct {
	char *from;
	char *to;
} substring_t;

enum {
	Opt_err = 0,
	Opt_new = 1,
	Opt_load = 2,
	Opt_update = 3,
};

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_proto;
};

struct ethtool_drvinfo {
	__u32 cmd;
	char driver[32];
	char version[32];
	char fw_version[32];
	char bus_info[32];
	char erom_version[32];
	char reserved2[12];
	__u32 n_priv_flags;
	__u32 n_stats;
	__u32 testinfo_len;
	__u32 eedump_len;
	__u32 regdump_len;
};

struct ethtool_wolinfo {
	__u32 cmd;
	__u32 supported;
	__u32 wolopts;
	__u8 sopass[6];
};

struct ethtool_tunable {
	__u32 cmd;
	__u32 id;
	__u32 type_id;
	__u32 len;
	void *data[0];
};

struct ethtool_regs {
	__u32 cmd;
	__u32 version;
	__u32 len;
	__u8 data[0];
};

struct ethtool_eeprom {
	__u32 cmd;
	__u32 magic;
	__u32 offset;
	__u32 len;
	__u8 data[0];
};

struct ethtool_eee {
	__u32 cmd;
	__u32 supported;
	__u32 advertised;
	__u32 lp_advertised;
	__u32 eee_active;
	__u32 eee_enabled;
	__u32 tx_lpi_enabled;
	__u32 tx_lpi_timer;
	__u32 reserved[2];
};

struct ethtool_modinfo {
	__u32 cmd;
	__u32 type;
	__u32 eeprom_len;
	__u32 reserved[8];
};

struct ethtool_coalesce {
	__u32 cmd;
	__u32 rx_coalesce_usecs;
	__u32 rx_max_coalesced_frames;
	__u32 rx_coalesce_usecs_irq;
	__u32 rx_max_coalesced_frames_irq;
	__u32 tx_coalesce_usecs;
	__u32 tx_max_coalesced_frames;
	__u32 tx_coalesce_usecs_irq;
	__u32 tx_max_coalesced_frames_irq;
	__u32 stats_block_coalesce_usecs;
	__u32 use_adaptive_rx_coalesce;
	__u32 use_adaptive_tx_coalesce;
	__u32 pkt_rate_low;
	__u32 rx_coalesce_usecs_low;
	__u32 rx_max_coalesced_frames_low;
	__u32 tx_coalesce_usecs_low;
	__u32 tx_max_coalesced_frames_low;
	__u32 pkt_rate_high;
	__u32 rx_coalesce_usecs_high;
	__u32 rx_max_coalesced_frames_high;
	__u32 tx_coalesce_usecs_high;
	__u32 tx_max_coalesced_frames_high;
	__u32 rate_sample_interval;
};

struct ethtool_ringparam {
	__u32 cmd;
	__u32 rx_max_pending;
	__u32 rx_mini_max_pending;
	__u32 rx_jumbo_max_pending;
	__u32 tx_max_pending;
	__u32 rx_pending;
	__u32 rx_mini_pending;
	__u32 rx_jumbo_pending;
	__u32 tx_pending;
};

struct ethtool_channels {
	__u32 cmd;
	__u32 max_rx;
	__u32 max_tx;
	__u32 max_other;
	__u32 max_combined;
	__u32 rx_count;
	__u32 tx_count;
	__u32 other_count;
	__u32 combined_count;
};

struct ethtool_pauseparam {
	__u32 cmd;
	__u32 autoneg;
	__u32 rx_pause;
	__u32 tx_pause;
};

enum ethtool_link_ext_state {
	ETHTOOL_LINK_EXT_STATE_AUTONEG = 0,
	ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE = 1,
	ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH = 2,
	ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY = 3,
	ETHTOOL_LINK_EXT_STATE_NO_CABLE = 4,
	ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE = 5,
	ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE = 6,
	ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE = 7,
	ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED = 8,
	ETHTOOL_LINK_EXT_STATE_OVERHEAT = 9,
	ETHTOOL_LINK_EXT_STATE_MODULE = 10,
};

enum ethtool_link_ext_substate_autoneg {
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NEXT_PAGE_EXCHANGE_FAILED = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE = 4,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_FEC_MISMATCH_DURING_OVERRIDE = 5,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD = 6,
};

enum ethtool_link_ext_substate_link_training {
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_REMOTE_FAULT = 4,
};

enum ethtool_link_ext_substate_link_logical_mismatch {
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED = 4,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED = 5,
};

enum ethtool_link_ext_substate_bad_signal_integrity {
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_REFERENCE_CLOCK_LOST = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_ALOS = 4,
};

enum ethtool_link_ext_substate_cable_issue {
	ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_CI_CABLE_TEST_FAILURE = 2,
};

enum ethtool_link_ext_substate_module {
	ETHTOOL_LINK_EXT_SUBSTATE_MODULE_CMIS_NOT_READY = 1,
};

enum ethtool_module_power_mode_policy {
	ETHTOOL_MODULE_POWER_MODE_POLICY_HIGH = 1,
	ETHTOOL_MODULE_POWER_MODE_POLICY_AUTO = 2,
};

enum ethtool_module_power_mode {
	ETHTOOL_MODULE_POWER_MODE_LOW = 1,
	ETHTOOL_MODULE_POWER_MODE_HIGH = 2,
};

struct ethtool_test {
	__u32 cmd;
	__u32 flags;
	__u32 reserved;
	__u32 len;
	__u64 data[0];
};

struct ethtool_stats {
	__u32 cmd;
	__u32 n_stats;
	__u64 data[0];
};

struct ethtool_tcpip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be16 psrc;
	__be16 pdst;
	__u8 tos;
};

struct ethtool_ah_espip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be32 spi;
	__u8 tos;
};

struct ethtool_usrip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be32 l4_4_bytes;
	__u8 tos;
	__u8 ip_ver;
	__u8 proto;
};

struct ethtool_tcpip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be16 psrc;
	__be16 pdst;
	__u8 tclass;
};

struct ethtool_ah_espip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be32 spi;
	__u8 tclass;
};

struct ethtool_usrip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be32 l4_4_bytes;
	__u8 tclass;
	__u8 l4_proto;
};

union ethtool_flow_union {
	struct ethtool_tcpip4_spec tcp_ip4_spec;
	struct ethtool_tcpip4_spec udp_ip4_spec;
	struct ethtool_tcpip4_spec sctp_ip4_spec;
	struct ethtool_ah_espip4_spec ah_ip4_spec;
	struct ethtool_ah_espip4_spec esp_ip4_spec;
	struct ethtool_usrip4_spec usr_ip4_spec;
	struct ethtool_tcpip6_spec tcp_ip6_spec;
	struct ethtool_tcpip6_spec udp_ip6_spec;
	struct ethtool_tcpip6_spec sctp_ip6_spec;
	struct ethtool_ah_espip6_spec ah_ip6_spec;
	struct ethtool_ah_espip6_spec esp_ip6_spec;
	struct ethtool_usrip6_spec usr_ip6_spec;
	struct ethhdr ether_spec;
	__u8 hdata[52];
};

struct ethtool_flow_ext {
	__u8 padding[2];
	unsigned char h_dest[6];
	__be16 vlan_etype;
	__be16 vlan_tci;
	__be32 data[2];
};

struct ethtool_rx_flow_spec {
	__u32 flow_type;
	union ethtool_flow_union h_u;
	struct ethtool_flow_ext h_ext;
	union ethtool_flow_union m_u;
	struct ethtool_flow_ext m_ext;
	__u64 ring_cookie;
	__u32 location;
};

struct ethtool_rxnfc {
	__u32 cmd;
	__u32 flow_type;
	__u64 data;
	struct ethtool_rx_flow_spec fs;
	union {
		__u32 rule_cnt;
		__u32 rss_context;
	};
	__u32 rule_locs[0];
};

struct ethtool_flash {
	__u32 cmd;
	__u32 region;
	char data[128];
};

struct ethtool_dump {
	__u32 cmd;
	__u32 version;
	__u32 flag;
	__u32 len;
	__u8 data[0];
};

struct ethtool_ts_info {
	__u32 cmd;
	__u32 so_timestamping;
	__s32 phc_index;
	__u32 tx_types;
	__u32 tx_reserved[3];
	__u32 rx_filters;
	__u32 rx_reserved[3];
};

struct ethtool_fecparam {
	__u32 cmd;
	__u32 active_fec;
	__u32 fec;
	__u32 reserved;
};

enum ethtool_link_mode_bit_indices {
	ETHTOOL_LINK_MODE_10baseT_Half_BIT = 0,
	ETHTOOL_LINK_MODE_10baseT_Full_BIT = 1,
	ETHTOOL_LINK_MODE_100baseT_Half_BIT = 2,
	ETHTOOL_LINK_MODE_100baseT_Full_BIT = 3,
	ETHTOOL_LINK_MODE_1000baseT_Half_BIT = 4,
	ETHTOOL_LINK_MODE_1000baseT_Full_BIT = 5,
	ETHTOOL_LINK_MODE_Autoneg_BIT = 6,
	ETHTOOL_LINK_MODE_TP_BIT = 7,
	ETHTOOL_LINK_MODE_AUI_BIT = 8,
	ETHTOOL_LINK_MODE_MII_BIT = 9,
	ETHTOOL_LINK_MODE_FIBRE_BIT = 10,
	ETHTOOL_LINK_MODE_BNC_BIT = 11,
	ETHTOOL_LINK_MODE_10000baseT_Full_BIT = 12,
	ETHTOOL_LINK_MODE_Pause_BIT = 13,
	ETHTOOL_LINK_MODE_Asym_Pause_BIT = 14,
	ETHTOOL_LINK_MODE_2500baseX_Full_BIT = 15,
	ETHTOOL_LINK_MODE_Backplane_BIT = 16,
	ETHTOOL_LINK_MODE_1000baseKX_Full_BIT = 17,
	ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT = 18,
	ETHTOOL_LINK_MODE_10000baseKR_Full_BIT = 19,
	ETHTOOL_LINK_MODE_10000baseR_FEC_BIT = 20,
	ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT = 21,
	ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT = 22,
	ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT = 23,
	ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT = 24,
	ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT = 25,
	ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT = 26,
	ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT = 27,
	ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT = 28,
	ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT = 29,
	ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT = 30,
	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT = 31,
	ETHTOOL_LINK_MODE_25000baseKR_Full_BIT = 32,
	ETHTOOL_LINK_MODE_25000baseSR_Full_BIT = 33,
	ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT = 34,
	ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT = 35,
	ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT = 36,
	ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT = 37,
	ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT = 38,
	ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT = 39,
	ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT = 40,
	ETHTOOL_LINK_MODE_1000baseX_Full_BIT = 41,
	ETHTOOL_LINK_MODE_10000baseCR_Full_BIT = 42,
	ETHTOOL_LINK_MODE_10000baseSR_Full_BIT = 43,
	ETHTOOL_LINK_MODE_10000baseLR_Full_BIT = 44,
	ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT = 45,
	ETHTOOL_LINK_MODE_10000baseER_Full_BIT = 46,
	ETHTOOL_LINK_MODE_2500baseT_Full_BIT = 47,
	ETHTOOL_LINK_MODE_5000baseT_Full_BIT = 48,
	ETHTOOL_LINK_MODE_FEC_NONE_BIT = 49,
	ETHTOOL_LINK_MODE_FEC_RS_BIT = 50,
	ETHTOOL_LINK_MODE_FEC_BASER_BIT = 51,
	ETHTOOL_LINK_MODE_50000baseKR_Full_BIT = 52,
	ETHTOOL_LINK_MODE_50000baseSR_Full_BIT = 53,
	ETHTOOL_LINK_MODE_50000baseCR_Full_BIT = 54,
	ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT = 55,
	ETHTOOL_LINK_MODE_50000baseDR_Full_BIT = 56,
	ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT = 57,
	ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT = 58,
	ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT = 59,
	ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT = 60,
	ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT = 61,
	ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT = 62,
	ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT = 63,
	ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT = 64,
	ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT = 65,
	ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT = 66,
	ETHTOOL_LINK_MODE_100baseT1_Full_BIT = 67,
	ETHTOOL_LINK_MODE_1000baseT1_Full_BIT = 68,
	ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT = 69,
	ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT = 70,
	ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT = 71,
	ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT = 72,
	ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT = 73,
	ETHTOOL_LINK_MODE_FEC_LLRS_BIT = 74,
	ETHTOOL_LINK_MODE_100000baseKR_Full_BIT = 75,
	ETHTOOL_LINK_MODE_100000baseSR_Full_BIT = 76,
	ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT = 77,
	ETHTOOL_LINK_MODE_100000baseCR_Full_BIT = 78,
	ETHTOOL_LINK_MODE_100000baseDR_Full_BIT = 79,
	ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT = 80,
	ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT = 81,
	ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT = 82,
	ETHTOOL_LINK_MODE_200000baseDR2_Full_BIT = 83,
	ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT = 84,
	ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT = 85,
	ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT = 86,
	ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT = 87,
	ETHTOOL_LINK_MODE_400000baseDR4_Full_BIT = 88,
	ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT = 89,
	ETHTOOL_LINK_MODE_100baseFX_Half_BIT = 90,
	ETHTOOL_LINK_MODE_100baseFX_Full_BIT = 91,
	ETHTOOL_LINK_MODE_10baseT1L_Full_BIT = 92,
	__ETHTOOL_LINK_MODE_MASK_NBITS = 93,
};

struct ethtool_link_settings {
	__u32 cmd;
	__u32 speed;
	__u8 duplex;
	__u8 port;
	__u8 phy_address;
	__u8 autoneg;
	__u8 mdio_support;
	__u8 eth_tp_mdix;
	__u8 eth_tp_mdix_ctrl;
	__s8 link_mode_masks_nwords;
	__u8 transceiver;
	__u8 master_slave_cfg;
	__u8 master_slave_state;
	__u8 reserved1[1];
	__u32 reserved[7];
	__u32 link_mode_masks[0];
};

struct kernel_ethtool_ringparam {
	u32 rx_buf_len;
	u8 tcp_data_split;
	u8 tx_push;
	u32 cqe_size;
};

struct ethtool_link_ext_state_info {
	enum ethtool_link_ext_state link_ext_state;
	union {
		enum ethtool_link_ext_substate_autoneg autoneg;
		enum ethtool_link_ext_substate_link_training link_training;
		enum ethtool_link_ext_substate_link_logical_mismatch link_logical_mismatch;
		enum ethtool_link_ext_substate_bad_signal_integrity bad_signal_integrity;
		enum ethtool_link_ext_substate_cable_issue cable_issue;
		enum ethtool_link_ext_substate_module module;
		u32 __link_ext_substate;
	};
};

struct ethtool_link_ksettings {
	struct ethtool_link_settings base;
	struct {
		long unsigned int supported[2];
		long unsigned int advertising[2];
		long unsigned int lp_advertising[2];
	} link_modes;
	u32 lanes;
};

struct kernel_ethtool_coalesce {
	u8 use_cqe_mode_tx;
	u8 use_cqe_mode_rx;
};

struct ethtool_eth_mac_stats {
	u64 FramesTransmittedOK;
	u64 SingleCollisionFrames;
	u64 MultipleCollisionFrames;
	u64 FramesReceivedOK;
	u64 FrameCheckSequenceErrors;
	u64 AlignmentErrors;
	u64 OctetsTransmittedOK;
	u64 FramesWithDeferredXmissions;
	u64 LateCollisions;
	u64 FramesAbortedDueToXSColls;
	u64 FramesLostDueToIntMACXmitError;
	u64 CarrierSenseErrors;
	u64 OctetsReceivedOK;
	u64 FramesLostDueToIntMACRcvError;
	u64 MulticastFramesXmittedOK;
	u64 BroadcastFramesXmittedOK;
	u64 FramesWithExcessiveDeferral;
	u64 MulticastFramesReceivedOK;
	u64 BroadcastFramesReceivedOK;
	u64 InRangeLengthErrors;
	u64 OutOfRangeLengthField;
	u64 FrameTooLongErrors;
};

struct ethtool_eth_phy_stats {
	u64 SymbolErrorDuringCarrier;
};

struct ethtool_eth_ctrl_stats {
	u64 MACControlFramesTransmitted;
	u64 MACControlFramesReceived;
	u64 UnsupportedOpcodesReceived;
};

struct ethtool_pause_stats {
	u64 tx_pause_frames;
	u64 rx_pause_frames;
};

struct ethtool_fec_stat {
	u64 total;
	u64 lanes[8];
};

struct ethtool_fec_stats {
	struct ethtool_fec_stat corrected_blocks;
	struct ethtool_fec_stat uncorrectable_blocks;
	struct ethtool_fec_stat corrected_bits;
};

struct ethtool_rmon_hist_range {
	u16 low;
	u16 high;
};

struct ethtool_rmon_stats {
	u64 undersize_pkts;
	u64 oversize_pkts;
	u64 fragments;
	u64 jabbers;
	u64 hist[10];
	u64 hist_tx[10];
};

struct ethtool_module_eeprom {
	u32 offset;
	u32 length;
	u8 page;
	u8 bank;
	u8 i2c_address;
	u8 *data;
};

struct ethtool_module_power_mode_params {
	enum ethtool_module_power_mode_policy policy;
	enum ethtool_module_power_mode mode;
};

enum ib_uverbs_write_cmds {
	IB_USER_VERBS_CMD_GET_CONTEXT = 0,
	IB_USER_VERBS_CMD_QUERY_DEVICE = 1,
	IB_USER_VERBS_CMD_QUERY_PORT = 2,
	IB_USER_VERBS_CMD_ALLOC_PD = 3,
	IB_USER_VERBS_CMD_DEALLOC_PD = 4,
	IB_USER_VERBS_CMD_CREATE_AH = 5,
	IB_USER_VERBS_CMD_MODIFY_AH = 6,
	IB_USER_VERBS_CMD_QUERY_AH = 7,
	IB_USER_VERBS_CMD_DESTROY_AH = 8,
	IB_USER_VERBS_CMD_REG_MR = 9,
	IB_USER_VERBS_CMD_REG_SMR = 10,
	IB_USER_VERBS_CMD_REREG_MR = 11,
	IB_USER_VERBS_CMD_QUERY_MR = 12,
	IB_USER_VERBS_CMD_DEREG_MR = 13,
	IB_USER_VERBS_CMD_ALLOC_MW = 14,
	IB_USER_VERBS_CMD_BIND_MW = 15,
	IB_USER_VERBS_CMD_DEALLOC_MW = 16,
	IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL = 17,
	IB_USER_VERBS_CMD_CREATE_CQ = 18,
	IB_USER_VERBS_CMD_RESIZE_CQ = 19,
	IB_USER_VERBS_CMD_DESTROY_CQ = 20,
	IB_USER_VERBS_CMD_POLL_CQ = 21,
	IB_USER_VERBS_CMD_PEEK_CQ = 22,
	IB_USER_VERBS_CMD_REQ_NOTIFY_CQ = 23,
	IB_USER_VERBS_CMD_CREATE_QP = 24,
	IB_USER_VERBS_CMD_QUERY_QP = 25,
	IB_USER_VERBS_CMD_MODIFY_QP = 26,
	IB_USER_VERBS_CMD_DESTROY_QP = 27,
	IB_USER_VERBS_CMD_POST_SEND = 28,
	IB_USER_VERBS_CMD_POST_RECV = 29,
	IB_USER_VERBS_CMD_ATTACH_MCAST = 30,
	IB_USER_VERBS_CMD_DETACH_MCAST = 31,
	IB_USER_VERBS_CMD_CREATE_SRQ = 32,
	IB_USER_VERBS_CMD_MODIFY_SRQ = 33,
	IB_USER_VERBS_CMD_QUERY_SRQ = 34,
	IB_USER_VERBS_CMD_DESTROY_SRQ = 35,
	IB_USER_VERBS_CMD_POST_SRQ_RECV = 36,
	IB_USER_VERBS_CMD_OPEN_XRCD = 37,
	IB_USER_VERBS_CMD_CLOSE_XRCD = 38,
	IB_USER_VERBS_CMD_CREATE_XSRQ = 39,
	IB_USER_VERBS_CMD_OPEN_QP = 40,
};

enum ib_uverbs_wc_opcode {
	IB_UVERBS_WC_SEND = 0,
	IB_UVERBS_WC_RDMA_WRITE = 1,
	IB_UVERBS_WC_RDMA_READ = 2,
	IB_UVERBS_WC_COMP_SWAP = 3,
	IB_UVERBS_WC_FETCH_ADD = 4,
	IB_UVERBS_WC_BIND_MW = 5,
	IB_UVERBS_WC_LOCAL_INV = 6,
	IB_UVERBS_WC_TSO = 7,
};

enum ib_uverbs_create_qp_mask {
	IB_UVERBS_CREATE_QP_MASK_IND_TABLE = 1,
};

enum ib_uverbs_wr_opcode {
	IB_UVERBS_WR_RDMA_WRITE = 0,
	IB_UVERBS_WR_RDMA_WRITE_WITH_IMM = 1,
	IB_UVERBS_WR_SEND = 2,
	IB_UVERBS_WR_SEND_WITH_IMM = 3,
	IB_UVERBS_WR_RDMA_READ = 4,
	IB_UVERBS_WR_ATOMIC_CMP_AND_SWP = 5,
	IB_UVERBS_WR_ATOMIC_FETCH_AND_ADD = 6,
	IB_UVERBS_WR_LOCAL_INV = 7,
	IB_UVERBS_WR_BIND_MW = 8,
	IB_UVERBS_WR_SEND_WITH_INV = 9,
	IB_UVERBS_WR_TSO = 10,
	IB_UVERBS_WR_RDMA_READ_WITH_INV = 11,
	IB_UVERBS_WR_MASKED_ATOMIC_CMP_AND_SWP = 12,
	IB_UVERBS_WR_MASKED_ATOMIC_FETCH_AND_ADD = 13,
};

enum ib_uverbs_device_cap_flags {
	IB_UVERBS_DEVICE_RESIZE_MAX_WR = 1,
	IB_UVERBS_DEVICE_BAD_PKEY_CNTR = 2,
	IB_UVERBS_DEVICE_BAD_QKEY_CNTR = 4,
	IB_UVERBS_DEVICE_RAW_MULTI = 8,
	IB_UVERBS_DEVICE_AUTO_PATH_MIG = 16,
	IB_UVERBS_DEVICE_CHANGE_PHY_PORT = 32,
	IB_UVERBS_DEVICE_UD_AV_PORT_ENFORCE = 64,
	IB_UVERBS_DEVICE_CURR_QP_STATE_MOD = 128,
	IB_UVERBS_DEVICE_SHUTDOWN_PORT = 256,
	IB_UVERBS_DEVICE_PORT_ACTIVE_EVENT = 1024,
	IB_UVERBS_DEVICE_SYS_IMAGE_GUID = 2048,
	IB_UVERBS_DEVICE_RC_RNR_NAK_GEN = 4096,
	IB_UVERBS_DEVICE_SRQ_RESIZE = 8192,
	IB_UVERBS_DEVICE_N_NOTIFY_CQ = 16384,
	IB_UVERBS_DEVICE_MEM_WINDOW = 131072,
	IB_UVERBS_DEVICE_UD_IP_CSUM = 262144,
	IB_UVERBS_DEVICE_XRC = 1048576,
	IB_UVERBS_DEVICE_MEM_MGT_EXTENSIONS = 2097152,
	IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2A = 8388608,
	IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2B = 16777216,
	IB_UVERBS_DEVICE_RC_IP_CSUM = 33554432,
	IB_UVERBS_DEVICE_RAW_IP_CSUM = 67108864,
	IB_UVERBS_DEVICE_MANAGED_FLOW_STEERING = 536870912,
	IB_UVERBS_DEVICE_RAW_SCATTER_FCS = 0,
	IB_UVERBS_DEVICE_PCI_WRITE_END_PADDING = 0,
};

enum ib_uverbs_raw_packet_caps {
	IB_UVERBS_RAW_PACKET_CAP_CVLAN_STRIPPING = 1,
	IB_UVERBS_RAW_PACKET_CAP_SCATTER_FCS = 2,
	IB_UVERBS_RAW_PACKET_CAP_IP_CSUM = 4,
	IB_UVERBS_RAW_PACKET_CAP_DELAY_DROP = 8,
};

enum ib_uverbs_access_flags {
	IB_UVERBS_ACCESS_LOCAL_WRITE = 1,
	IB_UVERBS_ACCESS_REMOTE_WRITE = 2,
	IB_UVERBS_ACCESS_REMOTE_READ = 4,
	IB_UVERBS_ACCESS_REMOTE_ATOMIC = 8,
	IB_UVERBS_ACCESS_MW_BIND = 16,
	IB_UVERBS_ACCESS_ZERO_BASED = 32,
	IB_UVERBS_ACCESS_ON_DEMAND = 64,
	IB_UVERBS_ACCESS_HUGETLB = 128,
	IB_UVERBS_ACCESS_RELAXED_ORDERING = 1048576,
	IB_UVERBS_ACCESS_OPTIONAL_RANGE = 1072693248,
};

enum ib_uverbs_srq_type {
	IB_UVERBS_SRQT_BASIC = 0,
	IB_UVERBS_SRQT_XRC = 1,
	IB_UVERBS_SRQT_TM = 2,
};

enum ib_uverbs_wq_type {
	IB_UVERBS_WQT_RQ = 0,
};

enum ib_uverbs_wq_flags {
	IB_UVERBS_WQ_FLAGS_CVLAN_STRIPPING = 1,
	IB_UVERBS_WQ_FLAGS_SCATTER_FCS = 2,
	IB_UVERBS_WQ_FLAGS_DELAY_DROP = 4,
	IB_UVERBS_WQ_FLAGS_PCI_WRITE_END_PADDING = 8,
};

enum ib_uverbs_qp_type {
	IB_UVERBS_QPT_RC = 2,
	IB_UVERBS_QPT_UC = 3,
	IB_UVERBS_QPT_UD = 4,
	IB_UVERBS_QPT_RAW_PACKET = 8,
	IB_UVERBS_QPT_XRC_INI = 9,
	IB_UVERBS_QPT_XRC_TGT = 10,
	IB_UVERBS_QPT_DRIVER = 255,
};

enum ib_uverbs_qp_create_flags {
	IB_UVERBS_QP_CREATE_BLOCK_MULTICAST_LOOPBACK = 2,
	IB_UVERBS_QP_CREATE_SCATTER_FCS = 256,
	IB_UVERBS_QP_CREATE_CVLAN_STRIPPING = 512,
	IB_UVERBS_QP_CREATE_PCI_WRITE_END_PADDING = 2048,
	IB_UVERBS_QP_CREATE_SQ_SIG_ALL = 4096,
};

enum ib_uverbs_gid_type {
	IB_UVERBS_GID_TYPE_IB = 0,
	IB_UVERBS_GID_TYPE_ROCE_V1 = 1,
	IB_UVERBS_GID_TYPE_ROCE_V2 = 2,
};

enum ib_poll_context {
	IB_POLL_SOFTIRQ = 0,
	IB_POLL_WORKQUEUE = 1,
	IB_POLL_UNBOUND_WORKQUEUE = 2,
	IB_POLL_LAST_POOL_TYPE = 2,
	IB_POLL_DIRECT = 3,
};

struct lsm_network_audit {
	int netif;
	const struct sock *sk;
	u16 family;
	__be16 dport;
	__be16 sport;
	union {
		struct {
			__be32 daddr;
			__be32 saddr;
		} v4;
		struct {
			struct in6_addr daddr;
			struct in6_addr saddr;
		} v6;
	} fam;
};

struct lsm_ioctlop_audit {
	struct path path;
	u16 cmd;
};

struct lsm_ibpkey_audit {
	u64 subnet_prefix;
	u16 pkey;
};

struct lsm_ibendport_audit {
	const char *dev_name;
	u8 port;
};

struct selinux_state;

struct selinux_audit_data {
	u32 ssid;
	u32 tsid;
	u16 tclass;
	u32 requested;
	u32 audited;
	u32 denied;
	int result;
	struct selinux_state *state;
};

struct common_audit_data {
	char type;
	union {
		struct path path;
		struct dentry *dentry;
		struct inode *inode;
		struct lsm_network_audit *net;
		int cap;
		int ipc_id;
		struct task_struct *tsk;
		struct {
			key_serial_t key;
			char *key_desc;
		} key_struct;
		char *kmod_name;
		struct lsm_ioctlop_audit *op;
		struct file *file;
		struct lsm_ibpkey_audit *ibpkey;
		struct lsm_ibendport_audit *ibendport;
		int reason;
		const char *anonclass;
	} u;
	union {
		struct selinux_audit_data *selinux_audit_data;
	};
};

enum {
	POLICYDB_CAP_NETPEER = 0,
	POLICYDB_CAP_OPENPERM = 1,
	POLICYDB_CAP_EXTSOCKCLASS = 2,
	POLICYDB_CAP_ALWAYSNETWORK = 3,
	POLICYDB_CAP_CGROUPSECLABEL = 4,
	POLICYDB_CAP_NNP_NOSUID_TRANSITION = 5,
	POLICYDB_CAP_GENFS_SECLABEL_SYMLINKS = 6,
	POLICYDB_CAP_IOCTL_SKIP_CLOEXEC = 7,
	__POLICYDB_CAP_MAX = 8,
};

struct selinux_avc;

struct selinux_policy;

struct selinux_state {
	bool enforcing;
	bool checkreqprot;
	bool initialized;
	bool policycap[8];
	struct page *status_page;
	struct mutex status_lock;
	struct selinux_avc *avc;
	struct selinux_policy *policy;
	struct mutex policy_mutex;
};

struct avc_cache {
	struct hlist_head slots[512];
	spinlock_t slots_lock[512];
	atomic_t lru_hint;
	atomic_t active_nodes;
	u32 latest_notif;
};

struct selinux_avc {
	unsigned int avc_cache_threshold;
	struct avc_cache avc_cache;
};

struct av_decision {
	u32 allowed;
	u32 auditallow;
	u32 auditdeny;
	u32 seqno;
	u32 flags;
};

struct extended_perms_data {
	u32 p[8];
};

struct extended_perms_decision {
	u8 used;
	u8 driver;
	struct extended_perms_data *allowed;
	struct extended_perms_data *auditallow;
	struct extended_perms_data *dontaudit;
};

struct extended_perms {
	u16 len;
	struct extended_perms_data drivers;
};

struct avc_cache_stats {
	unsigned int lookups;
	unsigned int misses;
	unsigned int allocations;
	unsigned int reclaims;
	unsigned int frees;
};

struct security_class_mapping {
	const char *name;
	const char *perms[33];
};

struct trace_event_raw_selinux_audited {
	struct trace_entry ent;
	u32 requested;
	u32 denied;
	u32 audited;
	int result;
	u32 __data_loc_scontext;
	u32 __data_loc_tcontext;
	u32 __data_loc_tclass;
	char __data[0];
};

struct trace_event_data_offsets_selinux_audited {
	u32 scontext;
	u32 tcontext;
	u32 tclass;
};

typedef void (*btf_trace_selinux_audited)(void *, struct selinux_audit_data *, char *, char *, const char *);

struct avc_xperms_node;

struct avc_entry {
	u32 ssid;
	u32 tsid;
	u16 tclass;
	struct av_decision avd;
	struct avc_xperms_node *xp_node;
};

struct avc_xperms_node {
	struct extended_perms xp;
	struct list_head xpd_head;
};

struct avc_node {
	struct avc_entry ae;
	struct hlist_node list;
	struct callback_head rhead;
};

struct avc_xperms_decision_node {
	struct extended_perms_decision xpd;
	struct list_head xpd_list;
};

struct avc_callback_node {
	int (*callback)(u32);
	u32 events;
	struct avc_callback_node *next;
};

struct hashtab_key_params {
	u32 (*hash)(const void *);
	int (*cmp)(const void *, const void *);
};

struct hashtab_node {
	void *key;
	void *datum;
	struct hashtab_node *next;
};

struct hashtab {
	struct hashtab_node **htable;
	u32 size;
	u32 nel;
};

struct symtab {
	struct hashtab table;
	u32 nprim;
};

struct avtab_key {
	u16 source_type;
	u16 target_type;
	u16 target_class;
	u16 specified;
};

struct avtab_extended_perms {
	u8 specified;
	u8 driver;
	struct extended_perms_data perms;
};

struct avtab_datum {
	union {
		u32 data;
		struct avtab_extended_perms *xperms;
	} u;
};

struct avtab_node {
	struct avtab_key key;
	struct avtab_datum datum;
	struct avtab_node *next;
};

struct avtab {
	struct avtab_node **htable;
	u32 nel;
	u32 nslot;
	u32 mask;
};

struct ebitmap_node {
	struct ebitmap_node *next;
	long unsigned int maps[6];
	u32 startbit;
};

struct ebitmap {
	struct ebitmap_node *node;
	u32 highbit;
};

struct mls_level {
	u32 sens;
	struct ebitmap cat;
};

struct mls_range {
	struct mls_level level[2];
};

struct context {
	u32 user;
	u32 role;
	u32 type;
	u32 len;
	struct mls_range range;
	char *str;
};

struct sidtab_str_cache;

struct sidtab_entry {
	u32 sid;
	u32 hash;
	struct context context;
	struct sidtab_str_cache *cache;
	struct hlist_node list;
};

struct sidtab_node_inner;

struct sidtab_node_leaf;

union sidtab_entry_inner {
	struct sidtab_node_inner *ptr_inner;
	struct sidtab_node_leaf *ptr_leaf;
};

struct sidtab_node_inner {
	union sidtab_entry_inner entries[512];
};

struct sidtab_node_leaf {
	struct sidtab_entry entries[39];
};

struct sidtab_isid_entry {
	int set;
	struct sidtab_entry entry;
};

struct sidtab;

struct sidtab_convert_params {
	int (*func)(struct context *, struct context *, void *, gfp_t);
	void *args;
	struct sidtab *target;
};

struct sidtab {
	union sidtab_entry_inner roots[4];
	u32 count;
	struct sidtab_convert_params *convert;
	bool frozen;
	spinlock_t lock;
	u32 cache_free_slots;
	struct list_head cache_lru_list;
	spinlock_t cache_lock;
	struct sidtab_isid_entry isids[27];
	struct hlist_head context_to_sid[512];
};

struct type_set;

struct constraint_expr {
	u32 expr_type;
	u32 attr;
	u32 op;
	struct ebitmap names;
	struct type_set *type_names;
	struct constraint_expr *next;
};

struct type_set {
	struct ebitmap types;
	struct ebitmap negset;
	u32 flags;
};

struct constraint_node {
	u32 permissions;
	struct constraint_expr *expr;
	struct constraint_node *next;
};

struct perm_datum {
	u32 value;
};

struct common_datum {
	u32 value;
	struct symtab permissions;
};

struct class_datum {
	u32 value;
	char *comkey;
	struct common_datum *comdatum;
	struct symtab permissions;
	struct constraint_node *constraints;
	struct constraint_node *validatetrans;
	char default_user;
	char default_role;
	char default_type;
	char default_range;
};

struct role_datum {
	u32 value;
	u32 bounds;
	struct ebitmap dominates;
	struct ebitmap types;
};

struct role_trans_key {
	u32 role;
	u32 type;
	u32 tclass;
};

struct role_trans_datum {
	u32 new_role;
};

struct filename_trans_key {
	u32 ttype;
	u16 tclass;
	const char *name;
};

struct filename_trans_datum {
	struct ebitmap stypes;
	u32 otype;
	struct filename_trans_datum *next;
};

struct role_allow {
	u32 role;
	u32 new_role;
	struct role_allow *next;
};

struct type_datum {
	u32 value;
	u32 bounds;
	unsigned char primary;
	unsigned char attribute;
};

struct user_datum {
	u32 value;
	u32 bounds;
	struct ebitmap roles;
	struct mls_range range;
	struct mls_level dfltlevel;
};

struct level_datum {
	struct mls_level *level;
	unsigned char isalias;
};

struct cat_datum {
	u32 value;
	unsigned char isalias;
};

struct range_trans {
	u32 source_type;
	u32 target_type;
	u32 target_class;
};

struct cond_bool_datum {
	__u32 value;
	int state;
};

struct ocontext {
	union {
		char *name;
		struct {
			u8 protocol;
			u16 low_port;
			u16 high_port;
		} port;
		struct {
			u32 addr;
			u32 mask;
		} node;
		struct {
			u32 addr[4];
			u32 mask[4];
		} node6;
		struct {
			u64 subnet_prefix;
			u16 low_pkey;
			u16 high_pkey;
		} ibpkey;
		struct {
			char *dev_name;
			u8 port;
		} ibendport;
	} u;
	union {
		u32 sclass;
		u32 behavior;
	} v;
	struct context context[2];
	u32 sid[2];
	struct ocontext *next;
};

struct genfs {
	char *fstype;
	struct ocontext *head;
	struct genfs *next;
};

struct cond_node;

struct policydb {
	int mls_enabled;
	struct symtab symtab[8];
	char **sym_val_to_name[8];
	struct class_datum **class_val_to_struct;
	struct role_datum **role_val_to_struct;
	struct user_datum **user_val_to_struct;
	struct type_datum **type_val_to_struct;
	struct avtab te_avtab;
	struct hashtab role_tr;
	struct ebitmap filename_trans_ttypes;
	struct hashtab filename_trans;
	u32 compat_filename_trans_count;
	struct cond_bool_datum **bool_val_to_struct;
	struct avtab te_cond_avtab;
	struct cond_node *cond_list;
	u32 cond_list_len;
	struct role_allow *role_allow;
	struct ocontext *ocontexts[9];
	struct genfs *genfs;
	struct hashtab range_tr;
	struct ebitmap *type_attr_map_array;
	struct ebitmap policycaps;
	struct ebitmap permissive_map;
	size_t len;
	unsigned int policyvers;
	unsigned int reject_unknown: 1;
	unsigned int allow_unknown: 1;
	u16 process_class;
	u32 process_trans_perms;
};

struct cond_expr_node;

struct cond_expr {
	struct cond_expr_node *nodes;
	u32 len;
};

struct cond_av_list {
	struct avtab_node **nodes;
	u32 len;
};

struct cond_node {
	int cur_state;
	struct cond_expr expr;
	struct cond_av_list true_list;
	struct cond_av_list false_list;
};

struct policy_file {
	char *data;
	size_t len;
};

struct policy_data {
	struct policydb *p;
	void *fp;
};

struct cond_expr_node {
	u32 expr_type;
	u32 bool;
};

struct policydb_compat_info {
	int version;
	int sym_num;
	int ocon_num;
};

typedef int __kernel_key_t;

typedef __kernel_key_t key_t;

struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

enum key_need_perm {
	KEY_NEED_UNSPECIFIED = 0,
	KEY_NEED_VIEW = 1,
	KEY_NEED_READ = 2,
	KEY_NEED_WRITE = 3,
	KEY_NEED_SEARCH = 4,
	KEY_NEED_LINK = 5,
	KEY_NEED_SETATTR = 6,
	KEY_NEED_UNLINK = 7,
	KEY_SYSADMIN_OVERRIDE = 8,
	KEY_AUTHTOKEN_OVERRIDE = 9,
	KEY_DEFER_PERM_CHECK = 10,
};

struct kern_ipc_perm {
	spinlock_t lock;
	bool deleted;
	int id;
	key_t key;
	kuid_t uid;
	kgid_t gid;
	kuid_t cuid;
	kgid_t cgid;
	umode_t mode;
	long unsigned int seq;
	void *security;
	struct rhash_head khtnode;
	struct callback_head rcu;
	refcount_t refcount;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct sembuf {
	short unsigned int sem_num;
	short int sem_op;
	short int sem_flg;
};

enum kernel_load_data_id {
	LOADING_UNKNOWN = 0,
	LOADING_FIRMWARE = 1,
	LOADING_MODULE = 2,
	LOADING_KEXEC_IMAGE = 3,
	LOADING_KEXEC_INITRAMFS = 4,
	LOADING_POLICY = 5,
	LOADING_X509_CERTIFICATE = 6,
	LOADING_MAX_ID = 7,
};

struct watch_notification;

struct sctp_association;

struct xfrm_sec_ctx;

struct xfrm_user_sec_ctx;

union security_list_options {
	int (*binder_set_context_mgr)(const struct cred *);
	int (*binder_transaction)(const struct cred *, const struct cred *);
	int (*binder_transfer_binder)(const struct cred *, const struct cred *);
	int (*binder_transfer_file)(const struct cred *, const struct cred *, struct file *);
	int (*ptrace_access_check)(struct task_struct *, unsigned int);
	int (*ptrace_traceme)(struct task_struct *);
	int (*capget)(struct task_struct *, kernel_cap_t *, kernel_cap_t *, kernel_cap_t *);
	int (*capset)(struct cred *, const struct cred *, const kernel_cap_t *, const kernel_cap_t *, const kernel_cap_t *);
	int (*capable)(const struct cred *, struct user_namespace *, int, unsigned int);
	int (*quotactl)(int, int, int, struct super_block *);
	int (*quota_on)(struct dentry *);
	int (*syslog)(int);
	int (*settime)(const struct timespec64 *, const struct timezone *);
	int (*vm_enough_memory)(struct mm_struct *, long int);
	int (*bprm_creds_for_exec)(struct linux_binprm *);
	int (*bprm_creds_from_file)(struct linux_binprm *, struct file *);
	int (*bprm_check_security)(struct linux_binprm *);
	void (*bprm_committing_creds)(struct linux_binprm *);
	void (*bprm_committed_creds)(struct linux_binprm *);
	int (*fs_context_dup)(struct fs_context *, struct fs_context *);
	int (*fs_context_parse_param)(struct fs_context *, struct fs_parameter *);
	int (*sb_alloc_security)(struct super_block *);
	void (*sb_delete)(struct super_block *);
	void (*sb_free_security)(struct super_block *);
	void (*sb_free_mnt_opts)(void *);
	int (*sb_eat_lsm_opts)(char *, void **);
	int (*sb_mnt_opts_compat)(struct super_block *, void *);
	int (*sb_remount)(struct super_block *, void *);
	int (*sb_kern_mount)(struct super_block *);
	int (*sb_show_options)(struct seq_file *, struct super_block *);
	int (*sb_statfs)(struct dentry *);
	int (*sb_mount)(const char *, const struct path *, const char *, long unsigned int, void *);
	int (*sb_umount)(struct vfsmount *, int);
	int (*sb_pivotroot)(const struct path *, const struct path *);
	int (*sb_set_mnt_opts)(struct super_block *, void *, long unsigned int, long unsigned int *);
	int (*sb_clone_mnt_opts)(const struct super_block *, struct super_block *, long unsigned int, long unsigned int *);
	int (*move_mount)(const struct path *, const struct path *);
	int (*dentry_init_security)(struct dentry *, int, const struct qstr *, const char **, void **, u32 *);
	int (*dentry_create_files_as)(struct dentry *, int, struct qstr *, const struct cred *, struct cred *);
	int (*path_unlink)(const struct path *, struct dentry *);
	int (*path_mkdir)(const struct path *, struct dentry *, umode_t);
	int (*path_rmdir)(const struct path *, struct dentry *);
	int (*path_mknod)(const struct path *, struct dentry *, umode_t, unsigned int);
	int (*path_truncate)(const struct path *);
	int (*path_symlink)(const struct path *, struct dentry *, const char *);
	int (*path_link)(struct dentry *, const struct path *, struct dentry *);
	int (*path_rename)(const struct path *, struct dentry *, const struct path *, struct dentry *, unsigned int);
	int (*path_chmod)(const struct path *, umode_t);
	int (*path_chown)(const struct path *, kuid_t, kgid_t);
	int (*path_chroot)(const struct path *);
	int (*path_notify)(const struct path *, u64, unsigned int);
	int (*inode_alloc_security)(struct inode *);
	void (*inode_free_security)(struct inode *);
	int (*inode_init_security)(struct inode *, struct inode *, const struct qstr *, const char **, void **, size_t *);
	int (*inode_init_security_anon)(struct inode *, const struct qstr *, const struct inode *);
	int (*inode_create)(struct inode *, struct dentry *, umode_t);
	int (*inode_link)(struct dentry *, struct inode *, struct dentry *);
	int (*inode_unlink)(struct inode *, struct dentry *);
	int (*inode_symlink)(struct inode *, struct dentry *, const char *);
	int (*inode_mkdir)(struct inode *, struct dentry *, umode_t);
	int (*inode_rmdir)(struct inode *, struct dentry *);
	int (*inode_mknod)(struct inode *, struct dentry *, umode_t, dev_t);
	int (*inode_rename)(struct inode *, struct dentry *, struct inode *, struct dentry *);
	int (*inode_readlink)(struct dentry *);
	int (*inode_follow_link)(struct dentry *, struct inode *, bool);
	int (*inode_permission)(struct inode *, int);
	int (*inode_setattr)(struct dentry *, struct iattr *);
	int (*inode_getattr)(const struct path *);
	int (*inode_setxattr)(struct user_namespace *, struct dentry *, const char *, const void *, size_t, int);
	void (*inode_post_setxattr)(struct dentry *, const char *, const void *, size_t, int);
	int (*inode_getxattr)(struct dentry *, const char *);
	int (*inode_listxattr)(struct dentry *);
	int (*inode_removexattr)(struct user_namespace *, struct dentry *, const char *);
	int (*inode_need_killpriv)(struct dentry *);
	int (*inode_killpriv)(struct user_namespace *, struct dentry *);
	int (*inode_getsecurity)(struct user_namespace *, struct inode *, const char *, void **, bool);
	int (*inode_setsecurity)(struct inode *, const char *, const void *, size_t, int);
	int (*inode_listsecurity)(struct inode *, char *, size_t);
	void (*inode_getsecid)(struct inode *, u32 *);
	int (*inode_copy_up)(struct dentry *, struct cred **);
	int (*inode_copy_up_xattr)(const char *);
	int (*kernfs_init_security)(struct kernfs_node *, struct kernfs_node *);
	int (*file_permission)(struct file *, int);
	int (*file_alloc_security)(struct file *);
	void (*file_free_security)(struct file *);
	int (*file_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*mmap_addr)(long unsigned int);
	int (*mmap_file)(struct file *, long unsigned int, long unsigned int, long unsigned int);
	int (*file_mprotect)(struct vm_area_struct *, long unsigned int, long unsigned int);
	int (*file_lock)(struct file *, unsigned int);
	int (*file_fcntl)(struct file *, unsigned int, long unsigned int);
	void (*file_set_fowner)(struct file *);
	int (*file_send_sigiotask)(struct task_struct *, struct fown_struct *, int);
	int (*file_receive)(struct file *);
	int (*file_open)(struct file *);
	int (*task_alloc)(struct task_struct *, long unsigned int);
	void (*task_free)(struct task_struct *);
	int (*cred_alloc_blank)(struct cred *, gfp_t);
	void (*cred_free)(struct cred *);
	int (*cred_prepare)(struct cred *, const struct cred *, gfp_t);
	void (*cred_transfer)(struct cred *, const struct cred *);
	void (*cred_getsecid)(const struct cred *, u32 *);
	int (*kernel_act_as)(struct cred *, u32);
	int (*kernel_create_files_as)(struct cred *, struct inode *);
	int (*kernel_module_request)(char *);
	int (*kernel_load_data)(enum kernel_load_data_id, bool);
	int (*kernel_post_load_data)(char *, loff_t, enum kernel_load_data_id, char *);
	int (*kernel_read_file)(struct file *, enum kernel_read_file_id, bool);
	int (*kernel_post_read_file)(struct file *, char *, loff_t, enum kernel_read_file_id);
	int (*task_fix_setuid)(struct cred *, const struct cred *, int);
	int (*task_fix_setgid)(struct cred *, const struct cred *, int);
	int (*task_fix_setgroups)(struct cred *, const struct cred *);
	int (*task_setpgid)(struct task_struct *, pid_t);
	int (*task_getpgid)(struct task_struct *);
	int (*task_getsid)(struct task_struct *);
	void (*current_getsecid_subj)(u32 *);
	void (*task_getsecid_obj)(struct task_struct *, u32 *);
	int (*task_setnice)(struct task_struct *, int);
	int (*task_setioprio)(struct task_struct *, int);
	int (*task_getioprio)(struct task_struct *);
	int (*task_prlimit)(const struct cred *, const struct cred *, unsigned int);
	int (*task_setrlimit)(struct task_struct *, unsigned int, struct rlimit *);
	int (*task_setscheduler)(struct task_struct *);
	int (*task_getscheduler)(struct task_struct *);
	int (*task_movememory)(struct task_struct *);
	int (*task_kill)(struct task_struct *, struct kernel_siginfo *, int, const struct cred *);
	int (*task_prctl)(int, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	void (*task_to_inode)(struct task_struct *, struct inode *);
	int (*ipc_permission)(struct kern_ipc_perm *, short int);
	void (*ipc_getsecid)(struct kern_ipc_perm *, u32 *);
	int (*msg_msg_alloc_security)(struct msg_msg *);
	void (*msg_msg_free_security)(struct msg_msg *);
	int (*msg_queue_alloc_security)(struct kern_ipc_perm *);
	void (*msg_queue_free_security)(struct kern_ipc_perm *);
	int (*msg_queue_associate)(struct kern_ipc_perm *, int);
	int (*msg_queue_msgctl)(struct kern_ipc_perm *, int);
	int (*msg_queue_msgsnd)(struct kern_ipc_perm *, struct msg_msg *, int);
	int (*msg_queue_msgrcv)(struct kern_ipc_perm *, struct msg_msg *, struct task_struct *, long int, int);
	int (*shm_alloc_security)(struct kern_ipc_perm *);
	void (*shm_free_security)(struct kern_ipc_perm *);
	int (*shm_associate)(struct kern_ipc_perm *, int);
	int (*shm_shmctl)(struct kern_ipc_perm *, int);
	int (*shm_shmat)(struct kern_ipc_perm *, char *, int);
	int (*sem_alloc_security)(struct kern_ipc_perm *);
	void (*sem_free_security)(struct kern_ipc_perm *);
	int (*sem_associate)(struct kern_ipc_perm *, int);
	int (*sem_semctl)(struct kern_ipc_perm *, int);
	int (*sem_semop)(struct kern_ipc_perm *, struct sembuf *, unsigned int, int);
	int (*netlink_send)(struct sock *, struct sk_buff *);
	void (*d_instantiate)(struct dentry *, struct inode *);
	int (*getprocattr)(struct task_struct *, char *, char **);
	int (*setprocattr)(const char *, void *, size_t);
	int (*ismaclabel)(const char *);
	int (*secid_to_secctx)(u32, char **, u32 *);
	int (*secctx_to_secid)(const char *, u32, u32 *);
	void (*release_secctx)(char *, u32);
	void (*inode_invalidate_secctx)(struct inode *);
	int (*inode_notifysecctx)(struct inode *, void *, u32);
	int (*inode_setsecctx)(struct dentry *, void *, u32);
	int (*inode_getsecctx)(struct inode *, void **, u32 *);
	int (*post_notification)(const struct cred *, const struct cred *, struct watch_notification *);
	int (*watch_key)(struct key *);
	int (*unix_stream_connect)(struct sock *, struct sock *, struct sock *);
	int (*unix_may_send)(struct socket *, struct socket *);
	int (*socket_create)(int, int, int, int);
	int (*socket_post_create)(struct socket *, int, int, int, int);
	int (*socket_socketpair)(struct socket *, struct socket *);
	int (*socket_bind)(struct socket *, struct sockaddr *, int);
	int (*socket_connect)(struct socket *, struct sockaddr *, int);
	int (*socket_listen)(struct socket *, int);
	int (*socket_accept)(struct socket *, struct socket *);
	int (*socket_sendmsg)(struct socket *, struct msghdr *, int);
	int (*socket_recvmsg)(struct socket *, struct msghdr *, int, int);
	int (*socket_getsockname)(struct socket *);
	int (*socket_getpeername)(struct socket *);
	int (*socket_getsockopt)(struct socket *, int, int);
	int (*socket_setsockopt)(struct socket *, int, int);
	int (*socket_shutdown)(struct socket *, int);
	int (*socket_sock_rcv_skb)(struct sock *, struct sk_buff *);
	int (*socket_getpeersec_stream)(struct socket *, char *, int *, unsigned int);
	int (*socket_getpeersec_dgram)(struct socket *, struct sk_buff *, u32 *);
	int (*sk_alloc_security)(struct sock *, int, gfp_t);
	void (*sk_free_security)(struct sock *);
	void (*sk_clone_security)(const struct sock *, struct sock *);
	void (*sk_getsecid)(struct sock *, u32 *);
	void (*sock_graft)(struct sock *, struct socket *);
	int (*inet_conn_request)(const struct sock *, struct sk_buff *, struct request_sock *);
	void (*inet_csk_clone)(struct sock *, const struct request_sock *);
	void (*inet_conn_established)(struct sock *, struct sk_buff *);
	int (*secmark_relabel_packet)(u32);
	void (*secmark_refcount_inc)();
	void (*secmark_refcount_dec)();
	void (*req_classify_flow)(const struct request_sock *, struct flowi_common *);
	int (*tun_dev_alloc_security)(void **);
	void (*tun_dev_free_security)(void *);
	int (*tun_dev_create)();
	int (*tun_dev_attach_queue)(void *);
	int (*tun_dev_attach)(struct sock *, void *);
	int (*tun_dev_open)(void *);
	int (*sctp_assoc_request)(struct sctp_association *, struct sk_buff *);
	int (*sctp_bind_connect)(struct sock *, int, struct sockaddr *, int);
	void (*sctp_sk_clone)(struct sctp_association *, struct sock *, struct sock *);
	int (*sctp_assoc_established)(struct sctp_association *, struct sk_buff *);
	int (*ib_pkey_access)(void *, u64, u16);
	int (*ib_endport_manage_subnet)(void *, const char *, u8);
	int (*ib_alloc_security)(void **);
	void (*ib_free_security)(void *);
	int (*xfrm_policy_alloc_security)(struct xfrm_sec_ctx **, struct xfrm_user_sec_ctx *, gfp_t);
	int (*xfrm_policy_clone_security)(struct xfrm_sec_ctx *, struct xfrm_sec_ctx **);
	void (*xfrm_policy_free_security)(struct xfrm_sec_ctx *);
	int (*xfrm_policy_delete_security)(struct xfrm_sec_ctx *);
	int (*xfrm_state_alloc)(struct xfrm_state *, struct xfrm_user_sec_ctx *);
	int (*xfrm_state_alloc_acquire)(struct xfrm_state *, struct xfrm_sec_ctx *, u32);
	void (*xfrm_state_free_security)(struct xfrm_state *);
	int (*xfrm_state_delete_security)(struct xfrm_state *);
	int (*xfrm_policy_lookup)(struct xfrm_sec_ctx *, u32);
	int (*xfrm_state_pol_flow_match)(struct xfrm_state *, struct xfrm_policy *, const struct flowi_common *);
	int (*xfrm_decode_session)(struct sk_buff *, u32 *, int);
	int (*key_alloc)(struct key *, const struct cred *, long unsigned int);
	void (*key_free)(struct key *);
	int (*key_permission)(key_ref_t, const struct cred *, enum key_need_perm);
	int (*key_getsecurity)(struct key *, char **);
	int (*audit_rule_init)(u32, u32, char *, void **);
	int (*audit_rule_known)(struct audit_krule *);
	int (*audit_rule_match)(u32, u32, u32, void *);
	void (*audit_rule_free)(void *);
	int (*bpf)(int, union bpf_attr *, unsigned int);
	int (*bpf_map)(struct bpf_map *, fmode_t);
	int (*bpf_prog)(struct bpf_prog *);
	int (*bpf_map_alloc_security)(struct bpf_map *);
	void (*bpf_map_free_security)(struct bpf_map *);
	int (*bpf_prog_alloc_security)(struct bpf_prog_aux *);
	void (*bpf_prog_free_security)(struct bpf_prog_aux *);
	int (*locked_down)(enum lockdown_reason);
	int (*lock_kernel_down)(const char *, enum lockdown_reason);
	int (*perf_event_open)(struct perf_event_attr *, int);
	int (*perf_event_alloc)(struct perf_event *);
	void (*perf_event_free)(struct perf_event *);
	int (*perf_event_read)(struct perf_event *);
	int (*perf_event_write)(struct perf_event *);
	int (*uring_override_creds)(const struct cred *);
	int (*uring_sqpoll)();
	int (*uring_cmd)(struct io_uring_cmd *);
};

struct security_hook_heads {
	struct hlist_head binder_set_context_mgr;
	struct hlist_head binder_transaction;
	struct hlist_head binder_transfer_binder;
	struct hlist_head binder_transfer_file;
	struct hlist_head ptrace_access_check;
	struct hlist_head ptrace_traceme;
	struct hlist_head capget;
	struct hlist_head capset;
	struct hlist_head capable;
	struct hlist_head quotactl;
	struct hlist_head quota_on;
	struct hlist_head syslog;
	struct hlist_head settime;
	struct hlist_head vm_enough_memory;
	struct hlist_head bprm_creds_for_exec;
	struct hlist_head bprm_creds_from_file;
	struct hlist_head bprm_check_security;
	struct hlist_head bprm_committing_creds;
	struct hlist_head bprm_committed_creds;
	struct hlist_head fs_context_dup;
	struct hlist_head fs_context_parse_param;
	struct hlist_head sb_alloc_security;
	struct hlist_head sb_delete;
	struct hlist_head sb_free_security;
	struct hlist_head sb_free_mnt_opts;
	struct hlist_head sb_eat_lsm_opts;
	struct hlist_head sb_mnt_opts_compat;
	struct hlist_head sb_remount;
	struct hlist_head sb_kern_mount;
	struct hlist_head sb_show_options;
	struct hlist_head sb_statfs;
	struct hlist_head sb_mount;
	struct hlist_head sb_umount;
	struct hlist_head sb_pivotroot;
	struct hlist_head sb_set_mnt_opts;
	struct hlist_head sb_clone_mnt_opts;
	struct hlist_head move_mount;
	struct hlist_head dentry_init_security;
	struct hlist_head dentry_create_files_as;
	struct hlist_head path_unlink;
	struct hlist_head path_mkdir;
	struct hlist_head path_rmdir;
	struct hlist_head path_mknod;
	struct hlist_head path_truncate;
	struct hlist_head path_symlink;
	struct hlist_head path_link;
	struct hlist_head path_rename;
	struct hlist_head path_chmod;
	struct hlist_head path_chown;
	struct hlist_head path_chroot;
	struct hlist_head path_notify;
	struct hlist_head inode_alloc_security;
	struct hlist_head inode_free_security;
	struct hlist_head inode_init_security;
	struct hlist_head inode_init_security_anon;
	struct hlist_head inode_create;
	struct hlist_head inode_link;
	struct hlist_head inode_unlink;
	struct hlist_head inode_symlink;
	struct hlist_head inode_mkdir;
	struct hlist_head inode_rmdir;
	struct hlist_head inode_mknod;
	struct hlist_head inode_rename;
	struct hlist_head inode_readlink;
	struct hlist_head inode_follow_link;
	struct hlist_head inode_permission;
	struct hlist_head inode_setattr;
	struct hlist_head inode_getattr;
	struct hlist_head inode_setxattr;
	struct hlist_head inode_post_setxattr;
	struct hlist_head inode_getxattr;
	struct hlist_head inode_listxattr;
	struct hlist_head inode_removexattr;
	struct hlist_head inode_need_killpriv;
	struct hlist_head inode_killpriv;
	struct hlist_head inode_getsecurity;
	struct hlist_head inode_setsecurity;
	struct hlist_head inode_listsecurity;
	struct hlist_head inode_getsecid;
	struct hlist_head inode_copy_up;
	struct hlist_head inode_copy_up_xattr;
	struct hlist_head kernfs_init_security;
	struct hlist_head file_permission;
	struct hlist_head file_alloc_security;
	struct hlist_head file_free_security;
	struct hlist_head file_ioctl;
	struct hlist_head mmap_addr;
	struct hlist_head mmap_file;
	struct hlist_head file_mprotect;
	struct hlist_head file_lock;
	struct hlist_head file_fcntl;
	struct hlist_head file_set_fowner;
	struct hlist_head file_send_sigiotask;
	struct hlist_head file_receive;
	struct hlist_head file_open;
	struct hlist_head task_alloc;
	struct hlist_head task_free;
	struct hlist_head cred_alloc_blank;
	struct hlist_head cred_free;
	struct hlist_head cred_prepare;
	struct hlist_head cred_transfer;
	struct hlist_head cred_getsecid;
	struct hlist_head kernel_act_as;
	struct hlist_head kernel_create_files_as;
	struct hlist_head kernel_module_request;
	struct hlist_head kernel_load_data;
	struct hlist_head kernel_post_load_data;
	struct hlist_head kernel_read_file;
	struct hlist_head kernel_post_read_file;
	struct hlist_head task_fix_setuid;
	struct hlist_head task_fix_setgid;
	struct hlist_head task_fix_setgroups;
	struct hlist_head task_setpgid;
	struct hlist_head task_getpgid;
	struct hlist_head task_getsid;
	struct hlist_head current_getsecid_subj;
	struct hlist_head task_getsecid_obj;
	struct hlist_head task_setnice;
	struct hlist_head task_setioprio;
	struct hlist_head task_getioprio;
	struct hlist_head task_prlimit;
	struct hlist_head task_setrlimit;
	struct hlist_head task_setscheduler;
	struct hlist_head task_getscheduler;
	struct hlist_head task_movememory;
	struct hlist_head task_kill;
	struct hlist_head task_prctl;
	struct hlist_head task_to_inode;
	struct hlist_head ipc_permission;
	struct hlist_head ipc_getsecid;
	struct hlist_head msg_msg_alloc_security;
	struct hlist_head msg_msg_free_security;
	struct hlist_head msg_queue_alloc_security;
	struct hlist_head msg_queue_free_security;
	struct hlist_head msg_queue_associate;
	struct hlist_head msg_queue_msgctl;
	struct hlist_head msg_queue_msgsnd;
	struct hlist_head msg_queue_msgrcv;
	struct hlist_head shm_alloc_security;
	struct hlist_head shm_free_security;
	struct hlist_head shm_associate;
	struct hlist_head shm_shmctl;
	struct hlist_head shm_shmat;
	struct hlist_head sem_alloc_security;
	struct hlist_head sem_free_security;
	struct hlist_head sem_associate;
	struct hlist_head sem_semctl;
	struct hlist_head sem_semop;
	struct hlist_head netlink_send;
	struct hlist_head d_instantiate;
	struct hlist_head getprocattr;
	struct hlist_head setprocattr;
	struct hlist_head ismaclabel;
	struct hlist_head secid_to_secctx;
	struct hlist_head secctx_to_secid;
	struct hlist_head release_secctx;
	struct hlist_head inode_invalidate_secctx;
	struct hlist_head inode_notifysecctx;
	struct hlist_head inode_setsecctx;
	struct hlist_head inode_getsecctx;
	struct hlist_head post_notification;
	struct hlist_head watch_key;
	struct hlist_head unix_stream_connect;
	struct hlist_head unix_may_send;
	struct hlist_head socket_create;
	struct hlist_head socket_post_create;
	struct hlist_head socket_socketpair;
	struct hlist_head socket_bind;
	struct hlist_head socket_connect;
	struct hlist_head socket_listen;
	struct hlist_head socket_accept;
	struct hlist_head socket_sendmsg;
	struct hlist_head socket_recvmsg;
	struct hlist_head socket_getsockname;
	struct hlist_head socket_getpeername;
	struct hlist_head socket_getsockopt;
	struct hlist_head socket_setsockopt;
	struct hlist_head socket_shutdown;
	struct hlist_head socket_sock_rcv_skb;
	struct hlist_head socket_getpeersec_stream;
	struct hlist_head socket_getpeersec_dgram;
	struct hlist_head sk_alloc_security;
	struct hlist_head sk_free_security;
	struct hlist_head sk_clone_security;
	struct hlist_head sk_getsecid;
	struct hlist_head sock_graft;
	struct hlist_head inet_conn_request;
	struct hlist_head inet_csk_clone;
	struct hlist_head inet_conn_established;
	struct hlist_head secmark_relabel_packet;
	struct hlist_head secmark_refcount_inc;
	struct hlist_head secmark_refcount_dec;
	struct hlist_head req_classify_flow;
	struct hlist_head tun_dev_alloc_security;
	struct hlist_head tun_dev_free_security;
	struct hlist_head tun_dev_create;
	struct hlist_head tun_dev_attach_queue;
	struct hlist_head tun_dev_attach;
	struct hlist_head tun_dev_open;
	struct hlist_head sctp_assoc_request;
	struct hlist_head sctp_bind_connect;
	struct hlist_head sctp_sk_clone;
	struct hlist_head sctp_assoc_established;
	struct hlist_head ib_pkey_access;
	struct hlist_head ib_endport_manage_subnet;
	struct hlist_head ib_alloc_security;
	struct hlist_head ib_free_security;
	struct hlist_head xfrm_policy_alloc_security;
	struct hlist_head xfrm_policy_clone_security;
	struct hlist_head xfrm_policy_free_security;
	struct hlist_head xfrm_policy_delete_security;
	struct hlist_head xfrm_state_alloc;
	struct hlist_head xfrm_state_alloc_acquire;
	struct hlist_head xfrm_state_free_security;
	struct hlist_head xfrm_state_delete_security;
	struct hlist_head xfrm_policy_lookup;
	struct hlist_head xfrm_state_pol_flow_match;
	struct hlist_head xfrm_decode_session;
	struct hlist_head key_alloc;
	struct hlist_head key_free;
	struct hlist_head key_permission;
	struct hlist_head key_getsecurity;
	struct hlist_head audit_rule_init;
	struct hlist_head audit_rule_known;
	struct hlist_head audit_rule_match;
	struct hlist_head audit_rule_free;
	struct hlist_head bpf;
	struct hlist_head bpf_map;
	struct hlist_head bpf_prog;
	struct hlist_head bpf_map_alloc_security;
	struct hlist_head bpf_map_free_security;
	struct hlist_head bpf_prog_alloc_security;
	struct hlist_head bpf_prog_free_security;
	struct hlist_head locked_down;
	struct hlist_head lock_kernel_down;
	struct hlist_head perf_event_open;
	struct hlist_head perf_event_alloc;
	struct hlist_head perf_event_free;
	struct hlist_head perf_event_read;
	struct hlist_head perf_event_write;
	struct hlist_head uring_override_creds;
	struct hlist_head uring_sqpoll;
	struct hlist_head uring_cmd;
};

struct security_hook_list {
	struct hlist_node list;
	struct hlist_head *head;
	union security_list_options hook;
	const char *lsm;
};

struct lsm_blob_sizes {
	int lbs_cred;
	int lbs_file;
	int lbs_inode;
	int lbs_superblock;
	int lbs_ipc;
	int lbs_msg_msg;
	int lbs_task;
};

enum lsm_order {
	LSM_ORDER_FIRST = 4294967295,
	LSM_ORDER_MUTABLE = 0,
};

struct lsm_info {
	const char *name;
	enum lsm_order order;
	long unsigned int flags;
	int *enabled;
	int (*init)();
	struct lsm_blob_sizes *blobs;
};

struct modsig;

enum integrity_status {
	INTEGRITY_PASS = 0,
	INTEGRITY_PASS_IMMUTABLE = 1,
	INTEGRITY_FAIL = 2,
	INTEGRITY_FAIL_IMMUTABLE = 3,
	INTEGRITY_NOLABEL = 4,
	INTEGRITY_NOXATTRS = 5,
	INTEGRITY_UNKNOWN = 6,
};

struct hwrng {
	const char *name;
	int (*init)(struct hwrng *);
	void (*cleanup)(struct hwrng *);
	int (*data_present)(struct hwrng *, int);
	int (*data_read)(struct hwrng *, u32 *);
	int (*read)(struct hwrng *, void *, size_t, bool);
	long unsigned int priv;
	short unsigned int quality;
	struct list_head list;
	struct kref ref;
	struct completion cleanup_done;
	struct completion dying;
};

typedef void *acpi_handle;

struct tpm_digest {
	u16 alg_id;
	u8 digest[64];
};

struct tpm_bank_info {
	u16 alg_id;
	u16 digest_size;
	u16 crypto_id;
};

struct tpm_chip;

struct tpm_class_ops {
	unsigned int flags;
	const u8 req_complete_mask;
	const u8 req_complete_val;
	bool (*req_canceled)(struct tpm_chip *, u8);
	int (*recv)(struct tpm_chip *, u8 *, size_t);
	int (*send)(struct tpm_chip *, u8 *, size_t);
	void (*cancel)(struct tpm_chip *);
	u8 (*status)(struct tpm_chip *);
	void (*update_timeouts)(struct tpm_chip *, long unsigned int *);
	void (*update_durations)(struct tpm_chip *, long unsigned int *);
	int (*go_idle)(struct tpm_chip *);
	int (*cmd_ready)(struct tpm_chip *);
	int (*request_locality)(struct tpm_chip *, int);
	int (*relinquish_locality)(struct tpm_chip *, int);
	void (*clk_enable)(struct tpm_chip *, bool);
};

struct tpm_bios_log {
	void *bios_event_log;
	void *bios_event_log_end;
};

struct tpm_chip_seqops {
	struct tpm_chip *chip;
	const struct seq_operations *seqops;
};

struct tpm_space {
	u32 context_tbl[3];
	u8 *context_buf;
	u32 session_tbl[3];
	u8 *session_buf;
	u32 buf_size;
};

struct tpm_chip {
	struct device dev;
	struct device devs;
	struct cdev cdev;
	struct cdev cdevs;
	struct rw_semaphore ops_sem;
	const struct tpm_class_ops *ops;
	struct tpm_bios_log log;
	struct tpm_chip_seqops bin_log_seqops;
	struct tpm_chip_seqops ascii_log_seqops;
	unsigned int flags;
	int dev_num;
	long unsigned int is_open;
	char hwrng_name[64];
	struct hwrng hwrng;
	struct mutex tpm_mutex;
	long unsigned int timeout_a;
	long unsigned int timeout_b;
	long unsigned int timeout_c;
	long unsigned int timeout_d;
	bool timeout_adjusted;
	long unsigned int duration[4];
	bool duration_adjusted;
	struct dentry *bios_dir[3];
	const struct attribute_group *groups[8];
	unsigned int groups_cnt;
	u32 nr_allocated_banks;
	struct tpm_bank_info *allocated_banks;
	acpi_handle acpi_dev_handle;
	char ppi_version[4];
	struct tpm_space work_space;
	u32 last_cc;
	u32 nr_commands;
	u32 *cc_attrs_tbl;
	int locality;
};

struct evm_ima_xattr_data {
	u8 type;
	u8 data[0];
};

struct ima_digest_data {
	u8 algo;
	u8 length;
	union {
		struct {
			u8 unused;
			u8 type;
		} sha1;
		struct {
			u8 type;
			u8 algo;
		} ng;
		u8 data[2];
	} xattr;
	u8 digest[0];
};

struct ima_max_digest_data {
	struct ima_digest_data hdr;
	u8 digest[64];
};

struct integrity_iint_cache {
	struct rb_node rb_node;
	struct mutex mutex;
	struct inode *inode;
	u64 version;
	long unsigned int flags;
	long unsigned int measured_pcrs;
	long unsigned int atomic_flags;
	enum integrity_status ima_file_status: 4;
	enum integrity_status ima_mmap_status: 4;
	enum integrity_status ima_bprm_status: 4;
	enum integrity_status ima_read_status: 4;
	enum integrity_status ima_creds_status: 4;
	enum integrity_status evm_status: 4;
	struct ima_digest_data *ima_hash;
};

enum ima_show_type {
	IMA_SHOW_BINARY = 0,
	IMA_SHOW_BINARY_NO_FIELD_LEN = 1,
	IMA_SHOW_BINARY_OLD_STRING_FMT = 2,
	IMA_SHOW_ASCII = 3,
};

struct ima_event_data {
	struct integrity_iint_cache *iint;
	struct file *file;
	const unsigned char *filename;
	struct evm_ima_xattr_data *xattr_value;
	int xattr_len;
	const struct modsig *modsig;
	const char *violation;
	const void *buf;
	int buf_len;
};

struct ima_field_data {
	u8 *data;
	u32 len;
};

struct ima_template_field {
	const char field_id[16];
	int (*field_init)(struct ima_event_data *, struct ima_field_data *);
	void (*field_show)(struct seq_file *, enum ima_show_type, struct ima_field_data *);
};

struct ima_template_desc {
	struct list_head list;
	char *name;
	char *fmt;
	int num_fields;
	const struct ima_template_field **fields;
};

struct ima_template_entry {
	int pcr;
	struct tpm_digest *digests;
	struct ima_template_desc *template_desc;
	u32 template_data_len;
	struct ima_field_data template_data[0];
};

struct ima_h_table {
	atomic_long_t len;
	atomic_long_t violations;
	struct hlist_head queue[1024];
};

enum ima_hooks {
	NONE = 0,
	FILE_CHECK = 1,
	MMAP_CHECK = 2,
	BPRM_CHECK = 3,
	CREDS_CHECK = 4,
	POST_SETATTR = 5,
	MODULE_CHECK = 6,
	FIRMWARE_CHECK = 7,
	KEXEC_KERNEL_CHECK = 8,
	KEXEC_INITRAMFS_CHECK = 9,
	POLICY_CHECK = 10,
	KEXEC_CMDLINE = 11,
	KEY_CHECK = 12,
	CRITICAL_DATA = 13,
	SETXATTR_CHECK = 14,
	MAX_CHECK = 15,
};

struct ima_queue_entry {
	struct hlist_node hnext;
	struct list_head later;
	struct ima_template_entry *entry;
};

struct ima_kexec_hdr {
	u16 version;
	u16 _reserved0;
	u32 _reserved1;
	u64 buffer_size;
	u64 count;
};

struct crypto_cipher {
	struct crypto_tfm base;
};

struct aead_request {
	struct crypto_async_request base;
	unsigned int assoclen;
	unsigned int cryptlen;
	u8 *iv;
	struct scatterlist *src;
	struct scatterlist *dst;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	void *__ctx[0];
};

struct crypto_aead;

struct aead_alg {
	int (*setkey)(struct crypto_aead *, const u8 *, unsigned int);
	int (*setauthsize)(struct crypto_aead *, unsigned int);
	int (*encrypt)(struct aead_request *);
	int (*decrypt)(struct aead_request *);
	int (*init)(struct crypto_aead *);
	void (*exit)(struct crypto_aead *);
	unsigned int ivsize;
	unsigned int maxauthsize;
	unsigned int chunksize;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct crypto_alg base;
};

struct crypto_aead {
	unsigned int authsize;
	unsigned int reqsize;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct crypto_tfm base;
};

struct rtattr {
	short unsigned int rta_len;
	short unsigned int rta_type;
};

struct scatter_walk {
	struct scatterlist *sg;
	unsigned int offset;
};

struct crypto_cipher_spawn {
	struct crypto_spawn base;
};

struct skcipher_request {
	unsigned int cryptlen;
	u8 *iv;
	struct scatterlist *src;
	struct scatterlist *dst;
	struct crypto_async_request base;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	void *__ctx[0];
};

struct crypto_skcipher {
	unsigned int reqsize;
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
	struct crypto_tfm base;
};

struct crypto_sync_skcipher {
	struct crypto_skcipher base;
};

struct skcipher_alg {
	int (*setkey)(struct crypto_skcipher *, const u8 *, unsigned int);
	int (*encrypt)(struct skcipher_request *);
	int (*decrypt)(struct skcipher_request *);
	int (*init)(struct crypto_skcipher *);
	void (*exit)(struct crypto_skcipher *);
	unsigned int min_keysize;
	unsigned int max_keysize;
	unsigned int ivsize;
	unsigned int chunksize;
	unsigned int walksize;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct crypto_alg base;
};

struct skcipher_instance {
	void (*free)(struct skcipher_instance *);
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	union {
		struct {
			char head[128];
			struct crypto_instance base;
		} s;
		struct skcipher_alg alg;
	};
};

struct crypto_skcipher_spawn {
	struct crypto_spawn base;
};

struct skcipher_walk {
	union {
		struct {
			struct page *page;
			long unsigned int offset;
		} phys;
		struct {
			u8 *page;
			void *addr;
		} virt;
	} src;
	union {
		struct {
			struct page *page;
			long unsigned int offset;
		} phys;
		struct {
			u8 *page;
			void *addr;
		} virt;
	} dst;
	struct scatter_walk in;
	unsigned int nbytes;
	struct scatter_walk out;
	unsigned int total;
	struct list_head buffers;
	u8 *page;
	u8 *buffer;
	u8 *oiv;
	void *iv;
	unsigned int ivsize;
	int flags;
	unsigned int blocksize;
	unsigned int stride;
	unsigned int alignmask;
};

struct skcipher_ctx_simple {
	struct crypto_cipher *cipher;
};

enum crypto_attr_type_t {
	CRYPTOCFGA_UNSPEC = 0,
	CRYPTOCFGA_PRIORITY_VAL = 1,
	CRYPTOCFGA_REPORT_LARVAL = 2,
	CRYPTOCFGA_REPORT_HASH = 3,
	CRYPTOCFGA_REPORT_BLKCIPHER = 4,
	CRYPTOCFGA_REPORT_AEAD = 5,
	CRYPTOCFGA_REPORT_COMPRESS = 6,
	CRYPTOCFGA_REPORT_RNG = 7,
	CRYPTOCFGA_REPORT_CIPHER = 8,
	CRYPTOCFGA_REPORT_AKCIPHER = 9,
	CRYPTOCFGA_REPORT_KPP = 10,
	CRYPTOCFGA_REPORT_ACOMP = 11,
	CRYPTOCFGA_STAT_LARVAL = 12,
	CRYPTOCFGA_STAT_HASH = 13,
	CRYPTOCFGA_STAT_BLKCIPHER = 14,
	CRYPTOCFGA_STAT_AEAD = 15,
	CRYPTOCFGA_STAT_COMPRESS = 16,
	CRYPTOCFGA_STAT_RNG = 17,
	CRYPTOCFGA_STAT_CIPHER = 18,
	CRYPTOCFGA_STAT_AKCIPHER = 19,
	CRYPTOCFGA_STAT_KPP = 20,
	CRYPTOCFGA_STAT_ACOMP = 21,
	__CRYPTOCFGA_MAX = 22,
};

struct crypto_report_blkcipher {
	char type[64];
	char geniv[64];
	unsigned int blocksize;
	unsigned int min_keysize;
	unsigned int max_keysize;
	unsigned int ivsize;
};

enum {
	SKCIPHER_WALK_PHYS = 1,
	SKCIPHER_WALK_SLOW = 2,
	SKCIPHER_WALK_COPY = 4,
	SKCIPHER_WALK_DIFF = 8,
	SKCIPHER_WALK_SLEEP = 16,
};

struct skcipher_walk_buffer {
	struct list_head entry;
	struct scatter_walk dst;
	unsigned int len;
	u8 *data;
	u8 buffer[0];
};

struct crypto_comp {
	struct crypto_tfm base;
};

struct crypto_rng;

struct rng_alg {
	int (*generate)(struct crypto_rng *, const u8 *, unsigned int, u8 *, unsigned int);
	int (*seed)(struct crypto_rng *, const u8 *, unsigned int);
	void (*set_ent)(struct crypto_rng *, const u8 *, unsigned int);
	unsigned int seedsize;
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
	struct crypto_alg base;
};

struct crypto_rng {
	struct crypto_tfm base;
};

struct drbg_string {
	const unsigned char *buf;
	size_t len;
	struct list_head list;
};

struct drbg_test_data {
	struct drbg_string *testentropy;
};

struct akcipher_request {
	struct crypto_async_request base;
	struct scatterlist *src;
	struct scatterlist *dst;
	unsigned int src_len;
	unsigned int dst_len;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	void *__ctx[0];
};

struct crypto_akcipher {
	struct crypto_tfm base;
};

struct akcipher_alg {
	int (*sign)(struct akcipher_request *);
	int (*verify)(struct akcipher_request *);
	int (*encrypt)(struct akcipher_request *);
	int (*decrypt)(struct akcipher_request *);
	int (*set_pub_key)(struct crypto_akcipher *, const void *, unsigned int);
	int (*set_priv_key)(struct crypto_akcipher *, const void *, unsigned int);
	unsigned int (*max_size)(struct crypto_akcipher *);
	int (*init)(struct crypto_akcipher *);
	void (*exit)(struct crypto_akcipher *);
	unsigned int reqsize;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct crypto_alg base;
};

struct kpp_request {
	struct crypto_async_request base;
	struct scatterlist *src;
	struct scatterlist *dst;
	unsigned int src_len;
	unsigned int dst_len;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	void *__ctx[0];
};

struct crypto_kpp {
	struct crypto_tfm base;
};

struct kpp_alg {
	int (*set_secret)(struct crypto_kpp *, const void *, unsigned int);
	int (*generate_public_key)(struct kpp_request *);
	int (*compute_shared_secret)(struct kpp_request *);
	unsigned int (*max_size)(struct crypto_kpp *);
	int (*init)(struct crypto_kpp *);
	void (*exit)(struct crypto_kpp *);
	unsigned int reqsize;
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
	struct crypto_alg base;
};

struct acomp_req {
	struct crypto_async_request base;
	struct scatterlist *src;
	struct scatterlist *dst;
	unsigned int slen;
	unsigned int dlen;
	u32 flags;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	void *__ctx[0];
};

struct crypto_acomp {
	int (*compress)(struct acomp_req *);
	int (*decompress)(struct acomp_req *);
	void (*dst_free)(struct scatterlist *);
	unsigned int reqsize;
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
	struct crypto_tfm base;
};

enum OID {
	OID_id_dsa_with_sha1 = 0,
	OID_id_dsa = 1,
	OID_id_ecPublicKey = 2,
	OID_id_prime192v1 = 3,
	OID_id_prime256v1 = 4,
	OID_id_ecdsa_with_sha1 = 5,
	OID_id_ecdsa_with_sha224 = 6,
	OID_id_ecdsa_with_sha256 = 7,
	OID_id_ecdsa_with_sha384 = 8,
	OID_id_ecdsa_with_sha512 = 9,
	OID_rsaEncryption = 10,
	OID_md2WithRSAEncryption = 11,
	OID_md3WithRSAEncryption = 12,
	OID_md4WithRSAEncryption = 13,
	OID_sha1WithRSAEncryption = 14,
	OID_sha256WithRSAEncryption = 15,
	OID_sha384WithRSAEncryption = 16,
	OID_sha512WithRSAEncryption = 17,
	OID_sha224WithRSAEncryption = 18,
	OID_data = 19,
	OID_signed_data = 20,
	OID_email_address = 21,
	OID_contentType = 22,
	OID_messageDigest = 23,
	OID_signingTime = 24,
	OID_smimeCapabilites = 25,
	OID_smimeAuthenticatedAttrs = 26,
	OID_md2 = 27,
	OID_md4 = 28,
	OID_md5 = 29,
	OID_mskrb5 = 30,
	OID_krb5 = 31,
	OID_krb5u2u = 32,
	OID_msIndirectData = 33,
	OID_msStatementType = 34,
	OID_msSpOpusInfo = 35,
	OID_msPeImageDataObjId = 36,
	OID_msIndividualSPKeyPurpose = 37,
	OID_msOutlookExpress = 38,
	OID_ntlmssp = 39,
	OID_spnego = 40,
	OID_IAKerb = 41,
	OID_PKU2U = 42,
	OID_Scram = 43,
	OID_certAuthInfoAccess = 44,
	OID_sha1 = 45,
	OID_id_ansip384r1 = 46,
	OID_sha256 = 47,
	OID_sha384 = 48,
	OID_sha512 = 49,
	OID_sha224 = 50,
	OID_commonName = 51,
	OID_surname = 52,
	OID_countryName = 53,
	OID_locality = 54,
	OID_stateOrProvinceName = 55,
	OID_organizationName = 56,
	OID_organizationUnitName = 57,
	OID_title = 58,
	OID_description = 59,
	OID_name = 60,
	OID_givenName = 61,
	OID_initials = 62,
	OID_generationalQualifier = 63,
	OID_subjectKeyIdentifier = 64,
	OID_keyUsage = 65,
	OID_subjectAltName = 66,
	OID_issuerAltName = 67,
	OID_basicConstraints = 68,
	OID_crlDistributionPoints = 69,
	OID_certPolicies = 70,
	OID_authorityKeyIdentifier = 71,
	OID_extKeyUsage = 72,
	OID_NetlogonMechanism = 73,
	OID_appleLocalKdcSupported = 74,
	OID_gostCPSignA = 75,
	OID_gostCPSignB = 76,
	OID_gostCPSignC = 77,
	OID_gost2012PKey256 = 78,
	OID_gost2012PKey512 = 79,
	OID_gost2012Digest256 = 80,
	OID_gost2012Digest512 = 81,
	OID_gost2012Signature256 = 82,
	OID_gost2012Signature512 = 83,
	OID_gostTC26Sign256A = 84,
	OID_gostTC26Sign256B = 85,
	OID_gostTC26Sign256C = 86,
	OID_gostTC26Sign256D = 87,
	OID_gostTC26Sign512A = 88,
	OID_gostTC26Sign512B = 89,
	OID_gostTC26Sign512C = 90,
	OID_sm2 = 91,
	OID_sm3 = 92,
	OID_SM2_with_SM3 = 93,
	OID_sm3WithRSAEncryption = 94,
	OID_TPMLoadableKey = 95,
	OID_TPMImportableKey = 96,
	OID_TPMSealedData = 97,
	OID__NR = 98,
};

struct hash_testvec {
	const char *key;
	const char *plaintext;
	const char *digest;
	unsigned int psize;
	short unsigned int ksize;
	int setkey_error;
	int digest_error;
	bool fips_skip;
};

struct cipher_testvec {
	const char *key;
	const char *iv;
	const char *iv_out;
	const char *ptext;
	const char *ctext;
	unsigned char wk;
	short unsigned int klen;
	unsigned int len;
	bool fips_skip;
	bool generates_iv;
	int setkey_error;
	int crypt_error;
};

struct aead_testvec {
	const char *key;
	const char *iv;
	const char *ptext;
	const char *assoc;
	const char *ctext;
	unsigned char novrfy;
	unsigned char wk;
	unsigned char klen;
	unsigned int plen;
	unsigned int clen;
	unsigned int alen;
	int setkey_error;
	int setauthsize_error;
	int crypt_error;
};

struct cprng_testvec {
	const char *key;
	const char *dt;
	const char *v;
	const char *result;
	unsigned char klen;
	short unsigned int dtlen;
	short unsigned int vlen;
	short unsigned int rlen;
	short unsigned int loops;
};

struct drbg_testvec {
	const unsigned char *entropy;
	size_t entropylen;
	const unsigned char *entpra;
	const unsigned char *entprb;
	size_t entprlen;
	const unsigned char *addtla;
	const unsigned char *addtlb;
	size_t addtllen;
	const unsigned char *pers;
	size_t perslen;
	const unsigned char *expected;
	size_t expectedlen;
};

struct akcipher_testvec {
	const unsigned char *key;
	const unsigned char *params;
	const unsigned char *m;
	const unsigned char *c;
	unsigned int key_len;
	unsigned int param_len;
	unsigned int m_size;
	unsigned int c_size;
	bool public_key_vec;
	bool siggen_sigver_test;
	enum OID algo;
};

struct kpp_testvec {
	const unsigned char *secret;
	const unsigned char *b_secret;
	const unsigned char *b_public;
	const unsigned char *expected_a_public;
	const unsigned char *expected_ss;
	short unsigned int secret_size;
	short unsigned int b_secret_size;
	short unsigned int b_public_size;
	short unsigned int expected_a_public_size;
	short unsigned int expected_ss_size;
	bool genkey;
};

struct comp_testvec {
	int inlen;
	int outlen;
	char input[512];
	char output[512];
};

struct aead_test_suite {
	const struct aead_testvec *vecs;
	unsigned int count;
	unsigned int einval_allowed: 1;
	unsigned int aad_iv: 1;
};

struct cipher_test_suite {
	const struct cipher_testvec *vecs;
	unsigned int count;
};

struct comp_test_suite {
	struct {
		const struct comp_testvec *vecs;
		unsigned int count;
	} comp;
	struct {
		const struct comp_testvec *vecs;
		unsigned int count;
	} decomp;
};

struct hash_test_suite {
	const struct hash_testvec *vecs;
	unsigned int count;
};

struct cprng_test_suite {
	const struct cprng_testvec *vecs;
	unsigned int count;
};

struct drbg_test_suite {
	const struct drbg_testvec *vecs;
	unsigned int count;
};

struct akcipher_test_suite {
	const struct akcipher_testvec *vecs;
	unsigned int count;
};

struct kpp_test_suite {
	const struct kpp_testvec *vecs;
	unsigned int count;
};

struct alg_test_desc {
	const char *alg;
	const char *generic_driver;
	int (*test)(const struct alg_test_desc *, const char *, u32, u32);
	int fips_allowed;
	union {
		struct aead_test_suite aead;
		struct cipher_test_suite cipher;
		struct comp_test_suite comp;
		struct hash_test_suite hash;
		struct cprng_test_suite cprng;
		struct drbg_test_suite drbg;
		struct akcipher_test_suite akcipher;
		struct kpp_test_suite kpp;
	} suite;
};

enum flush_type {
	FLUSH_TYPE_NONE = 0,
	FLUSH_TYPE_FLUSH = 1,
	FLUSH_TYPE_REIMPORT = 2,
};

enum finalization_type {
	FINALIZATION_TYPE_FINAL = 0,
	FINALIZATION_TYPE_FINUP = 1,
	FINALIZATION_TYPE_DIGEST = 2,
};

enum inplace_mode {
	OUT_OF_PLACE = 0,
	INPLACE_ONE_SGLIST = 1,
	INPLACE_TWO_SGLISTS = 2,
};

struct test_sg_division {
	unsigned int proportion_of_total;
	unsigned int offset;
	bool offset_relative_to_alignmask;
	enum flush_type flush_type;
	bool nosimd;
};

struct testvec_config {
	const char *name;
	enum inplace_mode inplace_mode;
	u32 req_flags;
	struct test_sg_division src_divs[8];
	struct test_sg_division dst_divs[8];
	unsigned int iv_offset;
	unsigned int key_offset;
	bool iv_offset_relative_to_alignmask;
	bool key_offset_relative_to_alignmask;
	enum finalization_type finalization_type;
	bool nosimd;
};

struct test_sglist {
	char *bufs[8];
	struct scatterlist sgl[8];
	struct scatterlist sgl_saved[8];
	struct scatterlist *sgl_ptr;
	unsigned int nents;
};

struct cipher_test_sglists {
	struct test_sglist src;
	struct test_sglist dst;
};

typedef unsigned char Byte;

typedef long unsigned int uLong;

struct internal_state;

struct z_stream_s {
	const Byte *next_in;
	uLong avail_in;
	uLong total_in;
	Byte *next_out;
	uLong avail_out;
	uLong total_out;
	char *msg;
	struct internal_state *state;
	void *workspace;
	int data_type;
	uLong adler;
	uLong reserved;
};

struct internal_state {
	int dummy;
};

typedef struct z_stream_s z_stream;

typedef z_stream *z_streamp;

struct crypto_scomp {
	struct crypto_tfm base;
};

struct scomp_alg {
	void * (*alloc_ctx)(struct crypto_scomp *);
	void (*free_ctx)(struct crypto_scomp *, void *);
	int (*compress)(struct crypto_scomp *, const u8 *, unsigned int, u8 *, unsigned int *, void *);
	int (*decompress)(struct crypto_scomp *, const u8 *, unsigned int, u8 *, unsigned int *, void *);
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct crypto_alg base;
};

struct deflate_ctx {
	struct z_stream_s comp_stream;
	struct z_stream_s decomp_stream;
};

struct lzo_ctx {
	void *lzo_comp_mem;
};

struct sockaddr_alg_new {
	__u16 salg_family;
	__u8 salg_type[14];
	__u32 salg_feat;
	__u32 salg_mask;
	__u8 salg_name[0];
};

struct af_alg_iv {
	__u32 ivlen;
	__u8 iv[0];
};

struct cmsghdr {
	__kernel_size_t cmsg_len;
	int cmsg_level;
	int cmsg_type;
};

enum sock_type {
	SOCK_STREAM = 1,
	SOCK_DGRAM = 2,
	SOCK_RAW = 3,
	SOCK_RDM = 4,
	SOCK_SEQPACKET = 5,
	SOCK_DCCP = 6,
	SOCK_PACKET = 10,
};

struct net_proto_family {
	int family;
	int (*create)(struct net *, struct socket *, int, int);
	struct module *owner;
};

enum {
	SOCK_WAKE_IO = 0,
	SOCK_WAKE_WAITD = 1,
	SOCK_WAKE_SPACE = 2,
	SOCK_WAKE_URG = 3,
};

enum sock_flags {
	SOCK_DEAD = 0,
	SOCK_DONE = 1,
	SOCK_URGINLINE = 2,
	SOCK_KEEPOPEN = 3,
	SOCK_LINGER = 4,
	SOCK_DESTROY = 5,
	SOCK_BROADCAST = 6,
	SOCK_TIMESTAMP = 7,
	SOCK_ZAPPED = 8,
	SOCK_USE_WRITE_QUEUE = 9,
	SOCK_DBG = 10,
	SOCK_RCVTSTAMP = 11,
	SOCK_RCVTSTAMPNS = 12,
	SOCK_LOCALROUTE = 13,
	SOCK_MEMALLOC = 14,
	SOCK_TIMESTAMPING_RX_SOFTWARE = 15,
	SOCK_FASYNC = 16,
	SOCK_RXQ_OVFL = 17,
	SOCK_ZEROCOPY = 18,
	SOCK_WIFI_STATUS = 19,
	SOCK_NOFCS = 20,
	SOCK_FILTER_LOCKED = 21,
	SOCK_SELECT_ERR_QUEUE = 22,
	SOCK_RCU_FREE = 23,
	SOCK_TXTIME = 24,
	SOCK_XDP = 25,
	SOCK_TSTAMP_NEW = 26,
	SOCK_RCVMARK = 27,
};

struct af_alg_type;

struct alg_sock {
	struct sock sk;
	struct sock *parent;
	atomic_t refcnt;
	atomic_t nokey_refcnt;
	const struct af_alg_type *type;
	void *private;
};

struct af_alg_type {
	void * (*bind)(const char *, u32, u32);
	void (*release)(void *);
	int (*setkey)(void *, const u8 *, unsigned int);
	int (*setentropy)(void *, sockptr_t, unsigned int);
	int (*accept)(void *, struct sock *);
	int (*accept_nokey)(void *, struct sock *);
	int (*setauthsize)(void *, unsigned int);
	struct proto_ops *ops;
	struct proto_ops *ops_nokey;
	struct module *owner;
	char name[14];
};

struct af_alg_control {
	struct af_alg_iv *iv;
	int op;
	unsigned int aead_assoclen;
};

struct af_alg_sgl {
	struct scatterlist sg[17];
	struct page *pages[16];
	unsigned int npages;
};

struct af_alg_tsgl {
	struct list_head list;
	unsigned int cur;
	struct scatterlist sg[0];
};

struct af_alg_rsgl {
	struct af_alg_sgl sgl;
	struct list_head list;
	size_t sg_num_bytes;
};

struct af_alg_async_req {
	struct kiocb *iocb;
	struct sock *sk;
	struct af_alg_rsgl first_rsgl;
	struct af_alg_rsgl *last_rsgl;
	struct list_head rsgl_list;
	struct scatterlist *tsgl;
	unsigned int tsgl_entries;
	unsigned int outlen;
	unsigned int areqlen;
	union {
		struct aead_request aead_req;
		struct skcipher_request skcipher_req;
	} cra_u;
};

struct af_alg_ctx {
	struct list_head tsgl_list;
	void *iv;
	size_t aead_assoclen;
	struct crypto_wait wait;
	size_t used;
	atomic_t rcvused;
	bool more;
	bool merge;
	bool enc;
	bool init;
	unsigned int len;
};

struct alg_type_list {
	const struct af_alg_type *type;
	struct list_head list;
};

struct asymmetric_key_id {
	short unsigned int len;
	unsigned char data[0];
};

struct public_key {
	void *key;
	u32 keylen;
	enum OID algo;
	void *params;
	u32 paramlen;
	bool key_is_private;
	const char *id_type;
	const char *pkey_algo;
};

struct public_key_signature {
	struct asymmetric_key_id *auth_ids[3];
	u8 *s;
	u8 *digest;
	u32 s_size;
	u32 digest_size;
	const char *pkey_algo;
	const char *hash_algo;
	const char *encoding;
	const void *data;
	unsigned int data_size;
};

struct x509_certificate {
	struct x509_certificate *next;
	struct x509_certificate *signer;
	struct public_key *pub;
	struct public_key_signature *sig;
	char *issuer;
	char *subject;
	struct asymmetric_key_id *id;
	struct asymmetric_key_id *skid;
	time64_t valid_from;
	time64_t valid_to;
	const void *tbs;
	unsigned int tbs_size;
	unsigned int raw_sig_size;
	const void *raw_sig;
	const void *raw_serial;
	unsigned int raw_serial_size;
	unsigned int raw_issuer_size;
	const void *raw_issuer;
	const void *raw_subject;
	unsigned int raw_subject_size;
	unsigned int raw_skid_size;
	const void *raw_skid;
	unsigned int index;
	bool seen;
	bool verified;
	bool self_signed;
	bool unsupported_sig;
	bool blacklisted;
};

struct pkcs7_signed_info {
	struct pkcs7_signed_info *next;
	struct x509_certificate *signer;
	unsigned int index;
	bool unsupported_crypto;
	bool blacklisted;
	const void *msgdigest;
	unsigned int msgdigest_len;
	unsigned int authattrs_len;
	const void *authattrs;
	long unsigned int aa_set;
	time64_t signing_time;
	struct public_key_signature *sig;
};

struct pkcs7_message {
	struct x509_certificate *certs;
	struct x509_certificate *crl;
	struct pkcs7_signed_info *signed_infos;
	u8 version;
	bool have_authattrs;
	enum OID data_type;
	size_t data_len;
	size_t data_hdrlen;
	const void *data;
};

struct disk_stats {
	u64 nsecs[4];
	long unsigned int sectors[4];
	long unsigned int ios[4];
	long unsigned int merges[4];
	long unsigned int io_ticks;
	local_t in_flight[2];
};

struct blk_crypto_key;

struct bio_crypt_ctx {
	const struct blk_crypto_key *bc_key;
	u64 bc_dun[4];
};

typedef __u32 blk_mq_req_flags_t;

enum stat_group {
	STAT_READ = 0,
	STAT_WRITE = 1,
	STAT_DISCARD = 2,
	STAT_FLUSH = 3,
	NR_STAT_GROUPS = 4,
};

struct sbitmap_word {
	long unsigned int word;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long unsigned int cleared;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct sbitmap {
	unsigned int depth;
	unsigned int shift;
	unsigned int map_nr;
	bool round_robin;
	struct sbitmap_word *map;
	unsigned int *alloc_hint;
};

struct sbq_wait_state {
	atomic_t wait_cnt;
	wait_queue_head_t wait;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct sbitmap_queue {
	struct sbitmap sb;
	unsigned int wake_batch;
	atomic_t wake_index;
	struct sbq_wait_state *ws;
	atomic_t ws_active;
	unsigned int min_shallow_depth;
};

enum {
	DISK_EVENT_MEDIA_CHANGE = 1,
	DISK_EVENT_EJECT_REQUEST = 2,
};

enum {
	DISK_EVENT_FLAG_POLL = 1,
	DISK_EVENT_FLAG_UEVENT = 2,
	DISK_EVENT_FLAG_BLOCK_ON_EXCL_WRITE = 4,
};

typedef __u32 req_flags_t;

enum mq_rq_state {
	MQ_RQ_IDLE = 0,
	MQ_RQ_IN_FLIGHT = 1,
	MQ_RQ_COMPLETE = 2,
};

typedef void rq_end_io_fn(struct request *, blk_status_t);

struct blk_crypto_keyslot;

struct request {
	struct request_queue *q;
	struct blk_mq_ctx *mq_ctx;
	struct blk_mq_hw_ctx *mq_hctx;
	blk_opf_t cmd_flags;
	req_flags_t rq_flags;
	int tag;
	int internal_tag;
	unsigned int timeout;
	unsigned int __data_len;
	sector_t __sector;
	struct bio *bio;
	struct bio *biotail;
	union {
		struct list_head queuelist;
		struct request *rq_next;
	};
	struct block_device *part;
	u64 alloc_time_ns;
	u64 start_time_ns;
	u64 io_start_time_ns;
	short unsigned int wbt_flags;
	short unsigned int stats_sectors;
	short unsigned int nr_phys_segments;
	short unsigned int nr_integrity_segments;
	struct bio_crypt_ctx *crypt_ctx;
	struct blk_crypto_keyslot *crypt_keyslot;
	short unsigned int write_hint;
	short unsigned int ioprio;
	enum mq_rq_state state;
	atomic_t ref;
	long unsigned int deadline;
	union {
		struct hlist_node hash;
		struct llist_node ipi_list;
	};
	union {
		struct rb_node rb_node;
		struct bio_vec special_vec;
		void *completion_data;
	};
	union {
		struct {
			struct io_cq *icq;
			void *priv[2];
		} elv;
		struct {
			unsigned int seq;
			struct list_head list;
			rq_end_io_fn *saved_end_io;
		} flush;
	};
	union {
		struct __call_single_data csd;
		u64 fifo_time;
	};
	rq_end_io_fn *end_io;
	void *end_io_data;
};

struct blk_mq_tags {
	unsigned int nr_tags;
	unsigned int nr_reserved_tags;
	atomic_t active_queues;
	struct sbitmap_queue bitmap_tags;
	struct sbitmap_queue breserved_tags;
	struct request **rqs;
	struct request **static_rqs;
	struct list_head page_list;
	spinlock_t lock;
};

struct blk_flush_queue {
	unsigned int flush_pending_idx: 1;
	unsigned int flush_running_idx: 1;
	blk_status_t rq_status;
	long unsigned int flush_pending_since;
	struct list_head flush_queue[2];
	struct list_head flush_data_in_flight;
	struct request *flush_rq;
	spinlock_t mq_flush_lock;
};

struct blk_mq_queue_map {
	unsigned int *mq_map;
	unsigned int nr_queues;
	unsigned int queue_offset;
};

struct blk_mq_tag_set {
	struct blk_mq_queue_map map[3];
	unsigned int nr_maps;
	const struct blk_mq_ops *ops;
	unsigned int nr_hw_queues;
	unsigned int queue_depth;
	unsigned int reserved_tags;
	unsigned int cmd_size;
	int numa_node;
	unsigned int timeout;
	unsigned int flags;
	void *driver_data;
	struct blk_mq_tags **tags;
	struct blk_mq_tags *shared_tags;
	struct mutex tag_list_lock;
	struct list_head tag_list;
};

struct blk_mq_hw_ctx {
	struct {
		spinlock_t lock;
		struct list_head dispatch;
		long unsigned int state;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	};
	struct delayed_work run_work;
	cpumask_var_t cpumask;
	int next_cpu;
	int next_cpu_batch;
	long unsigned int flags;
	void *sched_data;
	struct request_queue *queue;
	struct blk_flush_queue *fq;
	void *driver_data;
	struct sbitmap ctx_map;
	struct blk_mq_ctx *dispatch_from;
	unsigned int dispatch_busy;
	short unsigned int type;
	short unsigned int nr_ctx;
	struct blk_mq_ctx **ctxs;
	spinlock_t dispatch_wait_lock;
	wait_queue_entry_t dispatch_wait;
	atomic_t wait_index;
	struct blk_mq_tags *tags;
	struct blk_mq_tags *sched_tags;
	long unsigned int queued;
	long unsigned int run;
	unsigned int numa_node;
	unsigned int queue_num;
	atomic_t nr_active;
	struct hlist_node cpuhp_online;
	struct hlist_node cpuhp_dead;
	struct kobject kobj;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct list_head hctx_list;
	long: 64;
	long: 64;
	long: 64;
};

struct blk_mq_queue_data {
	struct request *rq;
	bool last;
};

struct blk_integrity_iter {
	void *prot_buf;
	void *data_buf;
	sector_t seed;
	unsigned int data_size;
	short unsigned int interval;
	unsigned char tuple_size;
	const char *disk_name;
};

enum blk_crypto_mode_num {
	BLK_ENCRYPTION_MODE_INVALID = 0,
	BLK_ENCRYPTION_MODE_AES_256_XTS = 1,
	BLK_ENCRYPTION_MODE_AES_128_CBC_ESSIV = 2,
	BLK_ENCRYPTION_MODE_ADIANTUM = 3,
	BLK_ENCRYPTION_MODE_MAX = 4,
};

struct blk_crypto_config {
	enum blk_crypto_mode_num crypto_mode;
	unsigned int data_unit_size;
	unsigned int dun_bytes;
};

struct blk_crypto_key {
	struct blk_crypto_config crypto_cfg;
	unsigned int data_unit_size_bits;
	unsigned int size;
	u8 raw[64];
};

struct bdev_inode {
	struct block_device bdev;
	struct inode vfs_inode;
};

enum {
	ICQ_EXITED = 4,
	ICQ_DESTROYED = 8,
};

enum {
	IOPRIO_CLASS_NONE = 0,
	IOPRIO_CLASS_RT = 1,
	IOPRIO_CLASS_BE = 2,
	IOPRIO_CLASS_IDLE = 3,
};

struct elevator_type;

struct elevator_queue {
	struct elevator_type *type;
	void *elevator_data;
	struct kobject kobj;
	struct mutex sysfs_lock;
	unsigned int registered: 1;
	struct hlist_head hash[64];
};

struct blk_mq_ctxs;

struct blk_mq_ctx {
	struct {
		spinlock_t lock;
		struct list_head rq_lists[3];
		long: 64;
	};
	unsigned int cpu;
	short unsigned int index_hw[3];
	struct blk_mq_hw_ctx *hctxs[3];
	struct request_queue *queue;
	struct blk_mq_ctxs *ctxs;
	struct kobject kobj;
	long: 64;
};

struct blk_stat_callback {
	struct list_head list;
	struct timer_list timer;
	struct blk_rq_stat *cpu_stat;
	int (*bucket_fn)(const struct request *);
	unsigned int buckets;
	struct blk_rq_stat *stat;
	void (*timer_fn)(struct blk_stat_callback *);
	void *data;
	struct callback_head rcu;
};

enum hctx_type {
	HCTX_TYPE_DEFAULT = 0,
	HCTX_TYPE_READ = 1,
	HCTX_TYPE_POLL = 2,
	HCTX_MAX_TYPES = 3,
};

enum elv_merge {
	ELEVATOR_NO_MERGE = 0,
	ELEVATOR_FRONT_MERGE = 1,
	ELEVATOR_BACK_MERGE = 2,
	ELEVATOR_DISCARD_MERGE = 3,
};

struct blk_mq_alloc_data;

struct elevator_mq_ops {
	int (*init_sched)(struct request_queue *, struct elevator_type *);
	void (*exit_sched)(struct elevator_queue *);
	int (*init_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	void (*depth_updated)(struct blk_mq_hw_ctx *);
	bool (*allow_merge)(struct request_queue *, struct request *, struct bio *);
	bool (*bio_merge)(struct request_queue *, struct bio *, unsigned int);
	int (*request_merge)(struct request_queue *, struct request **, struct bio *);
	void (*request_merged)(struct request_queue *, struct request *, enum elv_merge);
	void (*requests_merged)(struct request_queue *, struct request *, struct request *);
	void (*limit_depth)(blk_opf_t, struct blk_mq_alloc_data *);
	void (*prepare_request)(struct request *);
	void (*finish_request)(struct request *);
	void (*insert_requests)(struct blk_mq_hw_ctx *, struct list_head *, bool);
	struct request * (*dispatch_request)(struct blk_mq_hw_ctx *);
	bool (*has_work)(struct blk_mq_hw_ctx *);
	void (*completed_request)(struct request *, u64);
	void (*requeue_request)(struct request *);
	struct request * (*former_request)(struct request_queue *, struct request *);
	struct request * (*next_request)(struct request_queue *, struct request *);
	void (*init_icq)(struct io_cq *);
	void (*exit_icq)(struct io_cq *);
};

struct elv_fs_entry;

struct blk_mq_debugfs_attr;

struct elevator_type {
	struct kmem_cache *icq_cache;
	struct elevator_mq_ops ops;
	size_t icq_size;
	size_t icq_align;
	struct elv_fs_entry *elevator_attrs;
	const char *elevator_name;
	const char *elevator_alias;
	const unsigned int elevator_features;
	struct module *elevator_owner;
	const struct blk_mq_debugfs_attr *queue_debugfs_attrs;
	const struct blk_mq_debugfs_attr *hctx_debugfs_attrs;
	char icq_cache_name[22];
	struct list_head list;
};

struct blk_mq_alloc_data {
	struct request_queue *q;
	blk_mq_req_flags_t flags;
	unsigned int shallow_depth;
	blk_opf_t cmd_flags;
	req_flags_t rq_flags;
	unsigned int nr_tags;
	struct request **cached_rq;
	struct blk_mq_ctx *ctx;
	struct blk_mq_hw_ctx *hctx;
};

struct elv_fs_entry {
	struct attribute attr;
	ssize_t (*show)(struct elevator_queue *, char *);
	ssize_t (*store)(struct elevator_queue *, const char *, size_t);
};

struct blk_mq_debugfs_attr {
	const char *name;
	umode_t mode;
	int (*show)(void *, struct seq_file *);
	ssize_t (*write)(void *, const char *, size_t, loff_t *);
	const struct seq_operations *seq_ops;
};

struct blk_mq_ctxs {
	struct kobject kobj;
	struct blk_mq_ctx *queue_ctx;
};

struct blk_queue_stats {
	struct list_head callbacks;
	spinlock_t lock;
	int accounting;
};

struct parsed_partitions {
	struct gendisk *disk;
	char name[32];
	struct {
		sector_t from;
		sector_t size;
		int flags;
		bool has_info;
		struct partition_meta_info info;
	} *parts;
	int next;
	int limit;
	bool access_beyond_eod;
	char *pp_buf;
};

typedef struct {
	struct folio *v;
} Sector;

struct lvm_rec {
	char lvm_id[4];
	char reserved4[16];
	__be32 lvmarea_len;
	__be32 vgda_len;
	__be32 vgda_psn[2];
	char reserved36[10];
	__be16 pp_size;
	char reserved46[12];
	__be16 version;
};

struct vgda {
	__be32 secs;
	__be32 usec;
	char reserved8[16];
	__be16 numlvs;
	__be16 maxlvs;
	__be16 pp_size;
	__be16 numpvs;
	__be16 total_vgdas;
	__be16 vgda_size;
};

struct lvd {
	__be16 lv_ix;
	__be16 res2;
	__be16 res4;
	__be16 maxsize;
	__be16 lv_state;
	__be16 mirror;
	__be16 mirror_policy;
	__be16 num_lps;
	__be16 res10[8];
};

struct lvname {
	char name[64];
};

struct ppe {
	__be16 lv_ix;
	short unsigned int res2;
	short unsigned int res4;
	__be16 lp_ix;
	short unsigned int res8[12];
};

struct pvd {
	char reserved0[16];
	__be16 pp_count;
	char reserved18[2];
	__be32 psn_part1;
	char reserved24[8];
	struct ppe ppe[1016];
};

struct lv_info {
	short unsigned int pps_per_lv;
	short unsigned int pps_found;
	unsigned char lv_is_contiguous;
};

enum rq_qos_id {
	RQ_QOS_WBT = 0,
	RQ_QOS_LATENCY = 1,
	RQ_QOS_COST = 2,
	RQ_QOS_IOPRIO = 3,
};

struct rq_qos_ops;

struct rq_qos {
	struct rq_qos_ops *ops;
	struct request_queue *q;
	enum rq_qos_id id;
	struct rq_qos *next;
	struct dentry *debugfs_dir;
};

struct rq_wait {
	wait_queue_head_t wait;
	atomic_t inflight;
};

struct rq_qos_ops {
	void (*throttle)(struct rq_qos *, struct bio *);
	void (*track)(struct rq_qos *, struct request *, struct bio *);
	void (*merge)(struct rq_qos *, struct request *, struct bio *);
	void (*issue)(struct rq_qos *, struct request *);
	void (*requeue)(struct rq_qos *, struct request *);
	void (*done)(struct rq_qos *, struct request *);
	void (*done_bio)(struct rq_qos *, struct bio *);
	void (*cleanup)(struct rq_qos *, struct bio *);
	void (*queue_depth_changed)(struct rq_qos *);
	void (*exit)(struct rq_qos *);
	const struct blk_mq_debugfs_attr *debugfs_attrs;
};

struct rq_depth {
	unsigned int max_depth;
	int scale_step;
	bool scaled_max;
	unsigned int queue_depth;
	unsigned int default_depth;
};

typedef bool acquire_inflight_cb_t(struct rq_wait *, void *);

typedef void cleanup_cb_t(struct rq_wait *, void *);

struct rq_qos_wait_data {
	struct wait_queue_entry wq;
	struct task_struct *task;
	struct rq_wait *rqw;
	acquire_inflight_cb_t *cb;
	void *private_data;
	bool got_token;
};

struct blkg_iostat {
	u64 bytes[3];
	u64 ios[3];
};

struct blkg_iostat_set {
	struct u64_stats_sync sync;
	struct blkg_iostat cur;
	struct blkg_iostat last;
};

struct blkcg;

struct blkg_policy_data;

struct blkcg_gq {
	struct request_queue *q;
	struct list_head q_node;
	struct hlist_node blkcg_node;
	struct blkcg *blkcg;
	struct blkcg_gq *parent;
	struct percpu_ref refcnt;
	bool online;
	struct blkg_iostat_set *iostat_cpu;
	struct blkg_iostat_set iostat;
	struct blkg_policy_data *pd[6];
	spinlock_t async_bio_lock;
	struct bio_list async_bios;
	union {
		struct work_struct async_bio_work;
		struct work_struct free_work;
	};
	atomic_t use_delay;
	atomic64_t delay_nsec;
	atomic64_t delay_start;
	u64 last_delay;
	int last_use;
	struct callback_head callback_head;
};

enum blkg_iostat_type {
	BLKG_IOSTAT_READ = 0,
	BLKG_IOSTAT_WRITE = 1,
	BLKG_IOSTAT_DISCARD = 2,
	BLKG_IOSTAT_NR = 3,
};

struct blkcg_policy_data;

struct blkcg {
	struct cgroup_subsys_state css;
	spinlock_t lock;
	refcount_t online_pin;
	struct xarray blkg_tree;
	struct blkcg_gq *blkg_hint;
	struct hlist_head blkg_list;
	struct blkcg_policy_data *cpd[6];
	struct list_head all_blkcgs_node;
	char fc_app_id[129];
	struct list_head cgwb_list;
};

struct blkg_policy_data {
	struct blkcg_gq *blkg;
	int plid;
};

struct blkcg_policy_data {
	struct blkcg *blkcg;
	int plid;
};

struct rchan;

struct blk_trace {
	int trace_state;
	struct rchan *rchan;
	long unsigned int *sequence;
	unsigned char *msg_data;
	u16 act_mask;
	u64 start_lba;
	u64 end_lba;
	u32 pid;
	u32 dev;
	struct dentry *dir;
	struct list_head running_list;
	atomic_t dropped;
};

struct rchan_buf {
	void *start;
	void *data;
	size_t offset;
	size_t subbufs_produced;
	size_t subbufs_consumed;
	struct rchan *chan;
	wait_queue_head_t read_wait;
	struct irq_work wakeup_work;
	struct dentry *dentry;
	struct kref kref;
	struct page **page_array;
	unsigned int page_count;
	unsigned int finalized;
	size_t *padding;
	size_t prev_padding;
	size_t bytes_consumed;
	size_t early_bytes;
	unsigned int cpu;
	long: 32;
	long: 64;
	long: 64;
};

struct rchan_callbacks;

struct rchan {
	u32 version;
	size_t subbuf_size;
	size_t n_subbufs;
	size_t alloc_size;
	const struct rchan_callbacks *cb;
	struct kref kref;
	void *private_data;
	size_t last_toobig;
	struct rchan_buf **buf;
	int is_global;
	struct list_head list;
	struct dentry *parent;
	int has_base_filename;
	char base_filename[255];
};

struct rchan_callbacks {
	int (*subbuf_start)(struct rchan_buf *, void *, void *, size_t);
	struct dentry * (*create_buf_file)(const char *, struct dentry *, umode_t, struct rchan_buf *, int *);
	int (*remove_buf_file)(struct dentry *);
};

enum blktrace_cat {
	BLK_TC_READ = 1,
	BLK_TC_WRITE = 2,
	BLK_TC_FLUSH = 4,
	BLK_TC_SYNC = 8,
	BLK_TC_SYNCIO = 8,
	BLK_TC_QUEUE = 16,
	BLK_TC_REQUEUE = 32,
	BLK_TC_ISSUE = 64,
	BLK_TC_COMPLETE = 128,
	BLK_TC_FS = 256,
	BLK_TC_PC = 512,
	BLK_TC_NOTIFY = 1024,
	BLK_TC_AHEAD = 2048,
	BLK_TC_META = 4096,
	BLK_TC_DISCARD = 8192,
	BLK_TC_DRV_DATA = 16384,
	BLK_TC_FUA = 32768,
	BLK_TC_END = 32768,
};

typedef struct blkcg_policy_data *blkcg_pol_alloc_cpd_fn(gfp_t);

typedef void blkcg_pol_init_cpd_fn(struct blkcg_policy_data *);

typedef void blkcg_pol_free_cpd_fn(struct blkcg_policy_data *);

typedef void blkcg_pol_bind_cpd_fn(struct blkcg_policy_data *);

typedef struct blkg_policy_data *blkcg_pol_alloc_pd_fn(gfp_t, struct request_queue *, struct blkcg *);

typedef void blkcg_pol_init_pd_fn(struct blkg_policy_data *);

typedef void blkcg_pol_online_pd_fn(struct blkg_policy_data *);

typedef void blkcg_pol_offline_pd_fn(struct blkg_policy_data *);

typedef void blkcg_pol_free_pd_fn(struct blkg_policy_data *);

typedef void blkcg_pol_reset_pd_stats_fn(struct blkg_policy_data *);

typedef void blkcg_pol_stat_pd_fn(struct blkg_policy_data *, struct seq_file *);

struct blkcg_policy {
	int plid;
	struct cftype *dfl_cftypes;
	struct cftype *legacy_cftypes;
	blkcg_pol_alloc_cpd_fn *cpd_alloc_fn;
	blkcg_pol_init_cpd_fn *cpd_init_fn;
	blkcg_pol_free_cpd_fn *cpd_free_fn;
	blkcg_pol_bind_cpd_fn *cpd_bind_fn;
	blkcg_pol_alloc_pd_fn *pd_alloc_fn;
	blkcg_pol_init_pd_fn *pd_init_fn;
	blkcg_pol_online_pd_fn *pd_online_fn;
	blkcg_pol_offline_pd_fn *pd_offline_fn;
	blkcg_pol_free_pd_fn *pd_free_fn;
	blkcg_pol_reset_pd_stats_fn *pd_reset_stats_fn;
	blkcg_pol_stat_pd_fn *pd_stat_fn;
};

struct blkg_rwstat {
	struct percpu_counter cpu_cnt[5];
	atomic64_t aux_cnt[5];
};

struct bfq_entity;

struct bfq_service_tree {
	struct rb_root active;
	struct rb_root idle;
	struct bfq_entity *first_idle;
	struct bfq_entity *last_idle;
	u64 vtime;
	long unsigned int wsum;
};

struct bfq_sched_data;

struct bfq_queue;

struct bfq_entity {
	struct rb_node rb_node;
	bool on_st_or_in_serv;
	u64 start;
	u64 finish;
	struct rb_root *tree;
	u64 min_start;
	int service;
	int budget;
	int allocated;
	int dev_weight;
	int weight;
	int new_weight;
	int orig_weight;
	struct bfq_entity *parent;
	struct bfq_sched_data *my_sched_data;
	struct bfq_sched_data *sched_data;
	int prio_changed;
	bool in_groups_with_pending_reqs;
	struct bfq_queue *last_bfqq_created;
};

struct bfq_sched_data {
	struct bfq_entity *in_service_entity;
	struct bfq_entity *next_in_service;
	struct bfq_service_tree service_tree[3];
	long unsigned int bfq_class_idle_last_service;
};

struct bfq_weight_counter {
	unsigned int weight;
	unsigned int num_active;
	struct rb_node weights_node;
};

struct bfq_ttime {
	u64 last_end_request;
	u64 ttime_total;
	long unsigned int ttime_samples;
	u64 ttime_mean;
};

struct bfq_data;

struct bfq_io_cq;

struct bfq_queue {
	int ref;
	int stable_ref;
	struct bfq_data *bfqd;
	short unsigned int ioprio;
	short unsigned int ioprio_class;
	short unsigned int new_ioprio;
	short unsigned int new_ioprio_class;
	u64 last_serv_time_ns;
	unsigned int inject_limit;
	long unsigned int decrease_time_jif;
	struct bfq_queue *new_bfqq;
	struct rb_node pos_node;
	struct rb_root *pos_root;
	struct rb_root sort_list;
	struct request *next_rq;
	int queued[2];
	int meta_pending;
	struct list_head fifo;
	struct bfq_entity entity;
	struct bfq_weight_counter *weight_counter;
	int max_budget;
	long unsigned int budget_timeout;
	int dispatched;
	long unsigned int flags;
	struct list_head bfqq_list;
	struct bfq_ttime ttime;
	u64 io_start_time;
	u64 tot_idle_time;
	u32 seek_history;
	struct hlist_node burst_list_node;
	sector_t last_request_pos;
	unsigned int requests_within_timer;
	pid_t pid;
	struct bfq_io_cq *bic;
	long unsigned int wr_cur_max_time;
	long unsigned int soft_rt_next_start;
	long unsigned int last_wr_start_finish;
	unsigned int wr_coeff;
	long unsigned int last_idle_bklogged;
	long unsigned int service_from_backlogged;
	long unsigned int service_from_wr;
	long unsigned int wr_start_at_switch_to_srt;
	long unsigned int split_time;
	long unsigned int first_IO_time;
	long unsigned int creation_time;
	u32 max_service_rate;
	struct bfq_queue *waker_bfqq;
	struct bfq_queue *tentative_waker_bfqq;
	unsigned int num_waker_detections;
	u64 waker_detection_started;
	struct hlist_node woken_list_node;
	struct hlist_head woken_list;
};

struct bfq_group;

struct bfq_data {
	struct request_queue *queue;
	struct list_head dispatch;
	struct bfq_group *root_group;
	struct rb_root_cached queue_weights_tree;
	unsigned int num_groups_with_pending_reqs;
	unsigned int busy_queues[3];
	int wr_busy_queues;
	int queued;
	int rq_in_driver;
	bool nonrot_with_queueing;
	int max_rq_in_driver;
	int hw_tag_samples;
	int hw_tag;
	int budgets_assigned;
	struct hrtimer idle_slice_timer;
	struct bfq_queue *in_service_queue;
	sector_t last_position;
	sector_t in_serv_last_pos;
	u64 last_completion;
	struct bfq_queue *last_completed_rq_bfqq;
	struct bfq_queue *last_bfqq_created;
	u64 last_empty_occupied_ns;
	bool wait_dispatch;
	struct request *waited_rq;
	bool rqs_injected;
	u64 first_dispatch;
	u64 last_dispatch;
	ktime_t last_budget_start;
	ktime_t last_idling_start;
	long unsigned int last_idling_start_jiffies;
	int peak_rate_samples;
	u32 sequential_samples;
	u64 tot_sectors_dispatched;
	u32 last_rq_max_size;
	u64 delta_from_first;
	u32 peak_rate;
	int bfq_max_budget;
	struct list_head active_list;
	struct list_head idle_list;
	u64 bfq_fifo_expire[2];
	unsigned int bfq_back_penalty;
	unsigned int bfq_back_max;
	u32 bfq_slice_idle;
	int bfq_user_max_budget;
	unsigned int bfq_timeout;
	bool strict_guarantees;
	long unsigned int last_ins_in_burst;
	long unsigned int bfq_burst_interval;
	int burst_size;
	struct bfq_entity *burst_parent_entity;
	long unsigned int bfq_large_burst_thresh;
	bool large_burst;
	struct hlist_head burst_list;
	bool low_latency;
	unsigned int bfq_wr_coeff;
	unsigned int bfq_wr_max_time;
	unsigned int bfq_wr_rt_max_time;
	unsigned int bfq_wr_min_idle_time;
	long unsigned int bfq_wr_min_inter_arr_async;
	unsigned int bfq_wr_max_softrt_rate;
	u64 rate_dur_prod;
	struct bfq_queue oom_bfqq;
	spinlock_t lock;
	struct bfq_io_cq *bio_bic;
	struct bfq_queue *bio_bfqq;
	unsigned int word_depths[4];
	unsigned int full_depth_shift;
};

struct bfq_io_cq {
	struct io_cq icq;
	struct bfq_queue *bfqq[2];
	int ioprio;
	uint64_t blkcg_serial_nr;
	bool saved_has_short_ttime;
	bool saved_IO_bound;
	u64 saved_io_start_time;
	u64 saved_tot_idle_time;
	bool saved_in_large_burst;
	bool was_in_burst_list;
	unsigned int saved_weight;
	long unsigned int saved_wr_coeff;
	long unsigned int saved_last_wr_start_finish;
	long unsigned int saved_service_from_wr;
	long unsigned int saved_wr_start_at_switch_to_srt;
	unsigned int saved_wr_cur_max_time;
	struct bfq_ttime saved_ttime;
	u64 saved_last_serv_time_ns;
	unsigned int saved_inject_limit;
	long unsigned int saved_decrease_time_jif;
	struct bfq_queue *stable_merge_bfqq;
	bool stably_merged;
	unsigned int requests;
};

struct bfqg_stats {
	struct blkg_rwstat bytes;
	struct blkg_rwstat ios;
};

struct bfq_group {
	struct blkg_policy_data pd;
	char blkg_path[128];
	int ref;
	bool online;
	struct bfq_entity entity;
	struct bfq_sched_data sched_data;
	void *bfqd;
	struct bfq_queue *async_bfqq[16];
	struct bfq_queue *async_idle_bfqq;
	struct bfq_entity *my_entity;
	int active_entities;
	struct rb_root rq_pos_tree;
	struct bfqg_stats stats;
};

enum bfqq_state_flags {
	BFQQF_just_created = 0,
	BFQQF_busy = 1,
	BFQQF_wait_request = 2,
	BFQQF_non_blocking_wait_rq = 3,
	BFQQF_fifo_expire = 4,
	BFQQF_has_short_ttime = 5,
	BFQQF_sync = 6,
	BFQQF_IO_bound = 7,
	BFQQF_in_large_burst = 8,
	BFQQF_softrt_update = 9,
	BFQQF_coop = 10,
	BFQQF_split_coop = 11,
};

enum bfqq_expiration {
	BFQQE_TOO_IDLE = 0,
	BFQQE_BUDGET_TIMEOUT = 1,
	BFQQE_BUDGET_EXHAUSTED = 2,
	BFQQE_NO_MORE_REQUESTS = 3,
	BFQQE_PREEMPTED = 4,
};

enum opal_mbr {
	OPAL_MBR_ENABLE = 0,
	OPAL_MBR_DISABLE = 1,
};

enum opal_mbr_done_flag {
	OPAL_MBR_NOT_DONE = 0,
	OPAL_MBR_DONE = 1,
};

enum opal_user {
	OPAL_ADMIN1 = 0,
	OPAL_USER1 = 1,
	OPAL_USER2 = 2,
	OPAL_USER3 = 3,
	OPAL_USER4 = 4,
	OPAL_USER5 = 5,
	OPAL_USER6 = 6,
	OPAL_USER7 = 7,
	OPAL_USER8 = 8,
	OPAL_USER9 = 9,
};

enum opal_lock_state {
	OPAL_RO = 1,
	OPAL_RW = 2,
	OPAL_LK = 4,
};

struct opal_key {
	__u8 lr;
	__u8 key_len;
	__u8 __align[6];
	__u8 key[256];
};

struct opal_lr_act {
	struct opal_key key;
	__u32 sum;
	__u8 num_lrs;
	__u8 lr[9];
	__u8 align[2];
};

struct opal_session_info {
	__u32 sum;
	__u32 who;
	struct opal_key opal_key;
};

struct opal_user_lr_setup {
	__u64 range_start;
	__u64 range_length;
	__u32 RLE;
	__u32 WLE;
	struct opal_session_info session;
};

struct opal_lock_unlock {
	struct opal_session_info session;
	__u32 l_state;
	__u8 __align[4];
};

struct opal_new_pw {
	struct opal_session_info session;
	struct opal_session_info new_user_pw;
};

struct opal_mbr_data {
	struct opal_key key;
	__u8 enable_disable;
	__u8 __align[7];
};

struct opal_mbr_done {
	struct opal_key key;
	__u8 done_flag;
	__u8 __align[7];
};

struct opal_shadow_mbr {
	struct opal_key key;
	const __u64 data;
	__u64 offset;
	__u64 size;
};

enum opal_table_ops {
	OPAL_READ_TABLE = 0,
	OPAL_WRITE_TABLE = 1,
};

struct opal_read_write_table {
	struct opal_key key;
	const __u64 data;
	const __u8 table_uid[8];
	__u64 offset;
	__u64 size;
	__u64 flags;
	__u64 priv;
};

typedef int sec_send_recv(void *, u16, u8, void *, size_t, bool);

enum {
	TCG_SECP_00 = 0,
	TCG_SECP_01 = 1,
};

enum opal_response_token {
	OPAL_DTA_TOKENID_BYTESTRING = 224,
	OPAL_DTA_TOKENID_SINT = 225,
	OPAL_DTA_TOKENID_UINT = 226,
	OPAL_DTA_TOKENID_TOKEN = 227,
	OPAL_DTA_TOKENID_INVALID = 0,
};

enum opal_uid {
	OPAL_SMUID_UID = 0,
	OPAL_THISSP_UID = 1,
	OPAL_ADMINSP_UID = 2,
	OPAL_LOCKINGSP_UID = 3,
	OPAL_ENTERPRISE_LOCKINGSP_UID = 4,
	OPAL_ANYBODY_UID = 5,
	OPAL_SID_UID = 6,
	OPAL_ADMIN1_UID = 7,
	OPAL_USER1_UID = 8,
	OPAL_USER2_UID = 9,
	OPAL_PSID_UID = 10,
	OPAL_ENTERPRISE_BANDMASTER0_UID = 11,
	OPAL_ENTERPRISE_ERASEMASTER_UID = 12,
	OPAL_TABLE_TABLE = 13,
	OPAL_LOCKINGRANGE_GLOBAL = 14,
	OPAL_LOCKINGRANGE_ACE_RDLOCKED = 15,
	OPAL_LOCKINGRANGE_ACE_WRLOCKED = 16,
	OPAL_MBRCONTROL = 17,
	OPAL_MBR = 18,
	OPAL_AUTHORITY_TABLE = 19,
	OPAL_C_PIN_TABLE = 20,
	OPAL_LOCKING_INFO_TABLE = 21,
	OPAL_ENTERPRISE_LOCKING_INFO_TABLE = 22,
	OPAL_DATASTORE = 23,
	OPAL_C_PIN_MSID = 24,
	OPAL_C_PIN_SID = 25,
	OPAL_C_PIN_ADMIN1 = 26,
	OPAL_HALF_UID_AUTHORITY_OBJ_REF = 27,
	OPAL_HALF_UID_BOOLEAN_ACE = 28,
	OPAL_UID_HEXFF = 29,
};

enum opal_method {
	OPAL_PROPERTIES = 0,
	OPAL_STARTSESSION = 1,
	OPAL_REVERT = 2,
	OPAL_ACTIVATE = 3,
	OPAL_EGET = 4,
	OPAL_ESET = 5,
	OPAL_NEXT = 6,
	OPAL_EAUTHENTICATE = 7,
	OPAL_GETACL = 8,
	OPAL_GENKEY = 9,
	OPAL_REVERTSP = 10,
	OPAL_GET = 11,
	OPAL_SET = 12,
	OPAL_AUTHENTICATE = 13,
	OPAL_RANDOM = 14,
	OPAL_ERASE = 15,
};

enum opal_token {
	OPAL_TRUE = 1,
	OPAL_FALSE = 0,
	OPAL_BOOLEAN_EXPR = 3,
	OPAL_TABLE = 0,
	OPAL_STARTROW = 1,
	OPAL_ENDROW = 2,
	OPAL_STARTCOLUMN = 3,
	OPAL_ENDCOLUMN = 4,
	OPAL_VALUES = 1,
	OPAL_TABLE_UID = 0,
	OPAL_TABLE_NAME = 1,
	OPAL_TABLE_COMMON = 2,
	OPAL_TABLE_TEMPLATE = 3,
	OPAL_TABLE_KIND = 4,
	OPAL_TABLE_COLUMN = 5,
	OPAL_TABLE_COLUMNS = 6,
	OPAL_TABLE_ROWS = 7,
	OPAL_TABLE_ROWS_FREE = 8,
	OPAL_TABLE_ROW_BYTES = 9,
	OPAL_TABLE_LASTID = 10,
	OPAL_TABLE_MIN = 11,
	OPAL_TABLE_MAX = 12,
	OPAL_PIN = 3,
	OPAL_RANGESTART = 3,
	OPAL_RANGELENGTH = 4,
	OPAL_READLOCKENABLED = 5,
	OPAL_WRITELOCKENABLED = 6,
	OPAL_READLOCKED = 7,
	OPAL_WRITELOCKED = 8,
	OPAL_ACTIVEKEY = 10,
	OPAL_LIFECYCLE = 6,
	OPAL_MAXRANGES = 4,
	OPAL_MBRENABLE = 1,
	OPAL_MBRDONE = 2,
	OPAL_HOSTPROPERTIES = 0,
	OPAL_STARTLIST = 240,
	OPAL_ENDLIST = 241,
	OPAL_STARTNAME = 242,
	OPAL_ENDNAME = 243,
	OPAL_CALL = 248,
	OPAL_ENDOFDATA = 249,
	OPAL_ENDOFSESSION = 250,
	OPAL_STARTTRANSACTON = 251,
	OPAL_ENDTRANSACTON = 252,
	OPAL_EMPTYATOM = 255,
	OPAL_WHERE = 0,
};

enum opal_parameter {
	OPAL_SUM_SET_LIST = 393216,
};

struct opal_compacket {
	__be32 reserved0;
	u8 extendedComID[4];
	__be32 outstandingData;
	__be32 minTransfer;
	__be32 length;
};

struct opal_packet {
	__be32 tsn;
	__be32 hsn;
	__be32 seq_number;
	__be16 reserved0;
	__be16 ack_type;
	__be32 acknowledgment;
	__be32 length;
};

struct opal_data_subpacket {
	u8 reserved0[6];
	__be16 kind;
	__be32 length;
};

struct opal_header {
	struct opal_compacket cp;
	struct opal_packet pkt;
	struct opal_data_subpacket subpkt;
};

struct d0_header {
	__be32 length;
	__be32 revision;
	__be32 reserved01;
	__be32 reserved02;
	u8 ignored[32];
};

struct d0_tper_features {
	u8 supported_features;
	u8 reserved01[3];
	__be32 reserved02;
	__be32 reserved03;
};

struct d0_locking_features {
	u8 supported_features;
	u8 reserved01[3];
	__be32 reserved02;
	__be32 reserved03;
};

struct d0_geometry_features {
	u8 header[4];
	u8 reserved01;
	u8 reserved02[7];
	__be32 logical_block_size;
	__be64 alignment_granularity;
	__be64 lowest_aligned_lba;
};

struct d0_opal_v100 {
	__be16 baseComID;
	__be16 numComIDs;
};

struct d0_single_user_mode {
	__be32 num_locking_objects;
	u8 reserved01;
	u8 reserved02;
	__be16 reserved03;
	__be32 reserved04;
};

struct d0_opal_v200 {
	__be16 baseComID;
	__be16 numComIDs;
	u8 range_crossing;
	u8 num_locking_admin_auth[2];
	u8 num_locking_user_auth[2];
	u8 initialPIN;
	u8 revertedPIN;
	u8 reserved01;
	__be32 reserved02;
};

struct d0_features {
	__be16 code;
	u8 r_version;
	u8 length;
	u8 features[0];
};

struct opal_dev;

struct opal_step {
	int (*fn)(struct opal_dev *, void *);
	void *data;
};

enum opal_atom_width {
	OPAL_WIDTH_TINY = 0,
	OPAL_WIDTH_SHORT = 1,
	OPAL_WIDTH_MEDIUM = 2,
	OPAL_WIDTH_LONG = 3,
	OPAL_WIDTH_TOKEN = 4,
};

struct opal_resp_tok {
	const u8 *pos;
	size_t len;
	enum opal_response_token type;
	enum opal_atom_width width;
	union {
		u64 u;
		s64 s;
	} stored;
};

struct parsed_resp {
	int num;
	struct opal_resp_tok toks[64];
};

struct opal_dev {
	bool supported;
	bool mbr_enabled;
	void *data;
	sec_send_recv *send_recv;
	struct mutex dev_lock;
	u16 comid;
	u32 hsn;
	u32 tsn;
	u64 align;
	u64 lowest_lba;
	size_t pos;
	u8 cmd[2048];
	u8 resp[2048];
	struct parsed_resp parsed;
	size_t prev_d_len;
	void *prev_data;
	struct list_head unlk_lst;
};

typedef int cont_fn(struct opal_dev *);

struct opal_suspend_data {
	struct opal_lock_unlock unlk;
	u8 lr;
	struct list_head node;
};

struct io_uring_cmd {
	struct file *file;
	const void *cmd;
	void (*task_work_cb)(struct io_uring_cmd *);
	u32 cmd_op;
	u32 pad;
	u8 pdu[32];
};

enum {
	IOU_OK = 0,
	IOU_ISSUE_SKIP_COMPLETE = 4294966767,
	IOU_STOP_MULTISHOT = 4294967171,
};

enum io_uring_cmd_flags {
	IO_URING_F_COMPLETE_DEFER = 1,
	IO_URING_F_UNLOCKED = 2,
	IO_URING_F_NONBLOCK = 2147483648,
	IO_URING_F_SQE128 = 4,
	IO_URING_F_CQE32 = 8,
	IO_URING_F_IOPOLL = 16,
};

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

struct io_rsrc_node {
	struct percpu_ref refs;
	struct list_head node;
	struct list_head rsrc_list;
	struct io_rsrc_data *rsrc_data;
	struct llist_node llist;
	bool done;
};

struct io_mapped_ubuf {
	u64 ubuf;
	u64 ubuf_end;
	unsigned int nr_bvecs;
	long unsigned int acct_pages;
	struct bio_vec bvec[0];
};

struct io_rsrc_put;

typedef void rsrc_put_fn(struct io_ring_ctx *, struct io_rsrc_put *);

struct io_rsrc_data {
	struct io_ring_ctx *ctx;
	u64 **tags;
	unsigned int nr;
	rsrc_put_fn *do_put;
	atomic_t refs;
	struct completion done;
	bool quiesce;
};

enum {
	REQ_F_FIXED_FILE = 1,
	REQ_F_IO_DRAIN = 2,
	REQ_F_LINK = 4,
	REQ_F_HARDLINK = 8,
	REQ_F_FORCE_ASYNC = 16,
	REQ_F_BUFFER_SELECT = 32,
	REQ_F_CQE_SKIP = 64,
	REQ_F_FAIL = 256,
	REQ_F_INFLIGHT = 512,
	REQ_F_CUR_POS = 1024,
	REQ_F_NOWAIT = 2048,
	REQ_F_LINK_TIMEOUT = 4096,
	REQ_F_NEED_CLEANUP = 8192,
	REQ_F_POLLED = 16384,
	REQ_F_BUFFER_SELECTED = 32768,
	REQ_F_BUFFER_RING = 65536,
	REQ_F_REISSUE = 131072,
	REQ_F_SUPPORT_NOWAIT = 1073741824,
	REQ_F_ISREG = 2147483648,
	REQ_F_CREDS = 262144,
	REQ_F_REFCOUNT = 524288,
	REQ_F_ARM_LTIMEOUT = 1048576,
	REQ_F_ASYNC_DATA = 2097152,
	REQ_F_SKIP_LINK_CQES = 4194304,
	REQ_F_SINGLE_POLL = 8388608,
	REQ_F_DOUBLE_POLL = 16777216,
	REQ_F_PARTIAL_IO = 33554432,
	REQ_F_APOLL_MULTISHOT = 134217728,
	REQ_F_CQE32_INIT = 67108864,
	REQ_F_CLEAR_POLLIN = 268435456,
	REQ_F_HASH_LOCKED = 536870912,
};

struct io_rsrc_put {
	struct list_head list;
	u64 tag;
	union {
		void *rsrc;
		struct file *file;
		struct io_mapped_ubuf *buf;
	};
};

struct io_open {
	struct file *file;
	int dfd;
	u32 file_slot;
	struct filename *filename;
	struct open_how how;
	long unsigned int nofile;
};

struct io_close {
	struct file *file;
	int fd;
	u32 file_slot;
};

struct io_uring_buf {
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 resv;
};

struct io_uring_buf_ring {
	union {
		struct {
			__u64 resv1;
			__u32 resv2;
			__u16 resv3;
			__u16 tail;
		};
		struct io_uring_buf bufs[0];
	};
};

struct io_buffer_list {
	union {
		struct list_head buf_list;
		struct {
			struct page **buf_pages;
			struct io_uring_buf_ring *buf_ring;
		};
	};
	__u16 bgid;
	__u16 buf_nr_pages;
	__u16 nr_entries;
	__u16 head;
	__u16 mask;
};

struct io_buffer {
	struct list_head list;
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 bgid;
};

struct io_poll {
	struct file *file;
	struct wait_queue_head *head;
	__poll_t events;
	struct wait_queue_entry wait;
};

struct io_cache_entry {
	struct hlist_node node;
};

struct async_poll {
	union {
		struct io_poll poll;
		struct io_cache_entry cache;
	};
	struct io_poll *double_poll;
};

struct io_op_def {
	unsigned int needs_file: 1;
	unsigned int plug: 1;
	unsigned int hash_reg_file: 1;
	unsigned int unbound_nonreg_file: 1;
	unsigned int pollin: 1;
	unsigned int pollout: 1;
	unsigned int poll_exclusive: 1;
	unsigned int buffer_select: 1;
	unsigned int not_supported: 1;
	unsigned int audit_skip: 1;
	unsigned int ioprio: 1;
	unsigned int iopoll: 1;
	unsigned int manual_alloc: 1;
	short unsigned int async_size;
	const char *name;
	int (*prep)(struct io_kiocb *, const struct io_uring_sqe *);
	int (*issue)(struct io_kiocb *, unsigned int);
	int (*prep_async)(struct io_kiocb *);
	void (*cleanup)(struct io_kiocb *);
	void (*fail)(struct io_kiocb *);
};

enum {
	IO_APOLL_OK = 0,
	IO_APOLL_ABORTED = 1,
	IO_APOLL_READY = 2,
};

struct io_cancel_data {
	struct io_ring_ctx *ctx;
	union {
		u64 data;
		struct file *file;
	};
	u32 flags;
	int seq;
};

struct io_poll_update {
	struct file *file;
	u64 old_user_data;
	u64 new_user_data;
	__poll_t events;
	bool update_events;
	bool update_user_data;
};

struct io_poll_table {
	struct poll_table_struct pt;
	struct io_kiocb *req;
	int nr_entries;
	int error;
	bool owning;
	__poll_t result_mask;
};

enum {
	IOU_POLL_DONE = 0,
	IOU_POLL_NO_ACTION = 1,
	IOU_POLL_REMOVE_POLL_USE_RES = 2,
};

typedef void (*task_work_func_t)(struct callback_head *);

enum {
	IO_WQ_BOUND = 0,
	IO_WQ_UNBOUND = 1,
};

typedef struct io_wq_work *free_work_fn(struct io_wq_work *);

typedef void io_wq_work_fn(struct io_wq_work *);

struct io_wqe;

struct io_wq {
	long unsigned int state;
	free_work_fn *free_work;
	io_wq_work_fn *do_work;
	struct io_wq_hash *hash;
	atomic_t worker_refs;
	struct completion worker_done;
	struct hlist_node cpuhp_node;
	struct task_struct *task;
	struct io_wqe *wqes[0];
};

enum {
	IO_WQ_WORK_CANCEL = 1,
	IO_WQ_WORK_HASHED = 2,
	IO_WQ_WORK_UNBOUND = 4,
	IO_WQ_WORK_CONCURRENT = 16,
	IO_WQ_HASH_SHIFT = 24,
};

enum io_wq_cancel {
	IO_WQ_CANCEL_OK = 0,
	IO_WQ_CANCEL_RUNNING = 1,
	IO_WQ_CANCEL_NOTFOUND = 2,
};

struct io_wq_data {
	struct io_wq_hash *hash;
	struct task_struct *task;
	io_wq_work_fn *do_work;
	free_work_fn *free_work;
};

typedef bool work_cancel_fn(struct io_wq_work *, void *);

enum {
	IO_WORKER_F_UP = 1,
	IO_WORKER_F_RUNNING = 2,
	IO_WORKER_F_FREE = 4,
	IO_WORKER_F_BOUND = 8,
};

enum {
	IO_WQ_BIT_EXIT = 0,
};

enum {
	IO_ACCT_STALLED_BIT = 0,
};

struct io_worker {
	refcount_t ref;
	unsigned int flags;
	struct hlist_nulls_node nulls_node;
	struct list_head all_list;
	struct task_struct *task;
	struct io_wqe *wqe;
	struct io_wq_work *cur_work;
	struct io_wq_work *next_work;
	raw_spinlock_t lock;
	struct completion ref_done;
	long unsigned int create_state;
	struct callback_head create_work;
	int create_index;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
};

struct io_wqe_acct {
	unsigned int nr_workers;
	unsigned int max_workers;
	int index;
	atomic_t nr_running;
	raw_spinlock_t lock;
	struct io_wq_work_list work_list;
	long unsigned int flags;
};

struct io_wqe {
	raw_spinlock_t lock;
	struct io_wqe_acct acct[2];
	int node;
	struct hlist_nulls_head free_list;
	struct list_head all_list;
	struct wait_queue_entry wait;
	struct io_wq *wq;
	struct io_wq_work *hash_tail[64];
	cpumask_var_t cpu_mask;
};

enum {
	IO_WQ_ACCT_BOUND = 0,
	IO_WQ_ACCT_UNBOUND = 1,
	IO_WQ_ACCT_NR = 2,
};

struct io_cb_cancel_data {
	work_cancel_fn *fn;
	void *data;
	int nr_running;
	int nr_pending;
	bool cancel_all;
};

struct online_data {
	unsigned int cpu;
	bool online;
};

struct once_work {
	struct work_struct work;
	struct static_key_true *key;
	struct module *module;
};

struct rb_augment_callbacks {
	void (*propagate)(struct rb_node *, struct rb_node *);
	void (*copy)(struct rb_node *, struct rb_node *);
	void (*rotate)(struct rb_node *, struct rb_node *);
};

struct assoc_array_ops {
	long unsigned int (*get_key_chunk)(const void *, int);
	long unsigned int (*get_object_key_chunk)(const void *, int);
	bool (*compare_object)(const void *, const void *);
	int (*diff_objects)(const void *, const void *);
	void (*free_object)(void *);
};

struct assoc_array_node {
	struct assoc_array_ptr *back_pointer;
	u8 parent_slot;
	struct assoc_array_ptr *slots[16];
	long unsigned int nr_leaves_on_branch;
};

struct assoc_array_shortcut {
	struct assoc_array_ptr *back_pointer;
	int parent_slot;
	int skip_to_level;
	struct assoc_array_ptr *next_node;
	long unsigned int index_key[0];
};

struct assoc_array_edit {
	struct callback_head rcu;
	struct assoc_array *array;
	const struct assoc_array_ops *ops;
	const struct assoc_array_ops *ops_for_excised_subtree;
	struct assoc_array_ptr *leaf;
	struct assoc_array_ptr **leaf_p;
	struct assoc_array_ptr *dead_leaf;
	struct assoc_array_ptr *new_meta[3];
	struct assoc_array_ptr *excised_meta[1];
	struct assoc_array_ptr *excised_subtree;
	struct assoc_array_ptr **set_backpointers[16];
	struct assoc_array_ptr *set_backpointers_to;
	struct assoc_array_node *adjust_count_on;
	long int adjust_count_by;
	struct {
		struct assoc_array_ptr **ptr;
		struct assoc_array_ptr *to;
	} set[2];
	struct {
		u8 *p;
		u8 to;
	} set_parent_slot[1];
	u8 segment_cache[17];
};

enum assoc_array_walk_status {
	assoc_array_walk_tree_empty = 0,
	assoc_array_walk_found_terminal_node = 1,
	assoc_array_walk_found_wrong_shortcut = 2,
};

struct assoc_array_walk_result {
	struct {
		struct assoc_array_node *node;
		int level;
		int slot;
	} terminal_node;
	struct {
		struct assoc_array_shortcut *shortcut;
		int level;
		int sc_level;
		long unsigned int sc_segments;
		long unsigned int dissimilarity;
	} wrong_shortcut;
};

struct assoc_array_delete_collapse_context {
	struct assoc_array_node *node;
	const void *skip_leaf;
	int slot;
};

enum {
	CRYPTO_MSG_ALG_REQUEST = 0,
	CRYPTO_MSG_ALG_REGISTER = 1,
	CRYPTO_MSG_ALG_LOADED = 2,
};

typedef unsigned int uInt;

typedef struct {
	unsigned char op;
	unsigned char bits;
	short unsigned int val;
} code;

typedef enum {
	CODES = 0,
	LENS = 1,
	DISTS = 2,
} codetype;

typedef enum {
	HEAD = 0,
	FLAGS = 1,
	TIME = 2,
	OS = 3,
	EXLEN = 4,
	EXTRA = 5,
	NAME = 6,
	COMMENT = 7,
	HCRC = 8,
	DICTID = 9,
	DICT = 10,
	TYPE = 11,
	TYPEDO = 12,
	STORED = 13,
	COPY = 14,
	TABLE = 15,
	LENLENS = 16,
	CODELENS = 17,
	LEN = 18,
	LENEXT = 19,
	DIST = 20,
	DISTEXT = 21,
	MATCH = 22,
	LIT = 23,
	CHECK = 24,
	LENGTH = 25,
	DONE = 26,
	BAD = 27,
	MEM = 28,
	SYNC = 29,
} inflate_mode;

struct inflate_state {
	inflate_mode mode;
	int last;
	int wrap;
	int havedict;
	int flags;
	unsigned int dmax;
	long unsigned int check;
	long unsigned int total;
	unsigned int wbits;
	unsigned int wsize;
	unsigned int whave;
	unsigned int write;
	unsigned char *window;
	long unsigned int hold;
	unsigned int bits;
	unsigned int length;
	unsigned int offset;
	unsigned int extra;
	const code *lencode;
	const code *distcode;
	unsigned int lenbits;
	unsigned int distbits;
	unsigned int ncode;
	unsigned int nlen;
	unsigned int ndist;
	unsigned int have;
	code *next;
	short unsigned int lens[320];
	short unsigned int work[288];
	code codes[2048];
};

struct inflate_workspace {
	struct inflate_state inflate_state;
	unsigned char working_window[32768];
};

typedef u8 uint8_t;

typedef uint8_t BYTE;

typedef uint32_t U32;

typedef enum {
	ZSTD_error_no_error = 0,
	ZSTD_error_GENERIC = 1,
	ZSTD_error_prefix_unknown = 10,
	ZSTD_error_version_unsupported = 12,
	ZSTD_error_frameParameter_unsupported = 14,
	ZSTD_error_frameParameter_windowTooLarge = 16,
	ZSTD_error_corruption_detected = 20,
	ZSTD_error_checksum_wrong = 22,
	ZSTD_error_dictionary_corrupted = 30,
	ZSTD_error_dictionary_wrong = 32,
	ZSTD_error_dictionaryCreation_failed = 34,
	ZSTD_error_parameter_unsupported = 40,
	ZSTD_error_parameter_outOfBound = 42,
	ZSTD_error_tableLog_tooLarge = 44,
	ZSTD_error_maxSymbolValue_tooLarge = 46,
	ZSTD_error_maxSymbolValue_tooSmall = 48,
	ZSTD_error_stage_wrong = 60,
	ZSTD_error_init_missing = 62,
	ZSTD_error_memory_allocation = 64,
	ZSTD_error_workSpace_tooSmall = 66,
	ZSTD_error_dstSize_tooSmall = 70,
	ZSTD_error_srcSize_wrong = 72,
	ZSTD_error_dstBuffer_null = 74,
	ZSTD_error_frameIndex_tooLarge = 100,
	ZSTD_error_seekableIO = 102,
	ZSTD_error_dstBuffer_wrong = 104,
	ZSTD_error_srcBuffer_wrong = 105,
	ZSTD_error_maxCode = 120,
} ZSTD_ErrorCode;

typedef ZSTD_ErrorCode ERR_enum;

typedef enum {
	trustInput = 0,
	checkMaxSymbolValue = 1,
} HIST_checkInput_e;

typedef __kernel_long_t __kernel_ptrdiff_t;

typedef __kernel_ptrdiff_t ptrdiff_t;

typedef s16 int16_t;

typedef u16 uint16_t;

typedef uint16_t U16;

typedef int16_t S16;

typedef uint64_t U64;

typedef struct {
	U32 f1c;
	U32 f1d;
	U32 f7b;
	U32 f7c;
} ZSTD_cpuid_t;

typedef unsigned int FSE_CTable;

typedef enum {
	FSE_repeat_none = 0,
	FSE_repeat_check = 1,
	FSE_repeat_valid = 2,
} FSE_repeat;

struct HUF_CElt_s {
	U16 val;
	BYTE nbBits;
};

typedef struct HUF_CElt_s HUF_CElt;

typedef enum {
	HUF_repeat_none = 0,
	HUF_repeat_check = 1,
	HUF_repeat_valid = 2,
} HUF_repeat;

typedef enum {
	ZSTDcs_created = 0,
	ZSTDcs_init = 1,
	ZSTDcs_ongoing = 2,
	ZSTDcs_ending = 3,
} ZSTD_compressionStage_e;

typedef enum {
	ZSTD_f_zstd1 = 0,
	ZSTD_f_zstd1_magicless = 1,
} ZSTD_format_e;

typedef enum {
	ZSTD_fast = 1,
	ZSTD_dfast = 2,
	ZSTD_greedy = 3,
	ZSTD_lazy = 4,
	ZSTD_lazy2 = 5,
	ZSTD_btlazy2 = 6,
	ZSTD_btopt = 7,
	ZSTD_btultra = 8,
	ZSTD_btultra2 = 9,
} ZSTD_strategy;

typedef struct {
	unsigned int windowLog;
	unsigned int chainLog;
	unsigned int hashLog;
	unsigned int searchLog;
	unsigned int minMatch;
	unsigned int targetLength;
	ZSTD_strategy strategy;
} ZSTD_compressionParameters;

typedef struct {
	int contentSizeFlag;
	int checksumFlag;
	int noDictIDFlag;
} ZSTD_frameParameters;

typedef enum {
	ZSTD_dictDefaultAttach = 0,
	ZSTD_dictForceAttach = 1,
	ZSTD_dictForceCopy = 2,
	ZSTD_dictForceLoad = 3,
} ZSTD_dictAttachPref_e;

typedef enum {
	ZSTD_lcm_auto = 0,
	ZSTD_lcm_huffman = 1,
	ZSTD_lcm_uncompressed = 2,
} ZSTD_literalCompressionMode_e;

typedef struct {
	U32 enableLdm;
	U32 hashLog;
	U32 bucketSizeLog;
	U32 minMatchLength;
	U32 hashRateLog;
	U32 windowLog;
} ldmParams_t;

typedef enum {
	ZSTD_bm_buffered = 0,
	ZSTD_bm_stable = 1,
} ZSTD_bufferMode_e;

typedef enum {
	ZSTD_sf_noBlockDelimiters = 0,
	ZSTD_sf_explicitBlockDelimiters = 1,
} ZSTD_sequenceFormat_e;

typedef void * (*ZSTD_allocFunction)(void *, size_t);

typedef void (*ZSTD_freeFunction)(void *, void *);

typedef struct {
	ZSTD_allocFunction customAlloc;
	ZSTD_freeFunction customFree;
	void *opaque;
} ZSTD_customMem;

struct ZSTD_CCtx_params_s {
	ZSTD_format_e format;
	ZSTD_compressionParameters cParams;
	ZSTD_frameParameters fParams;
	int compressionLevel;
	int forceWindow;
	size_t targetCBlockSize;
	int srcSizeHint;
	ZSTD_dictAttachPref_e attachDictPref;
	ZSTD_literalCompressionMode_e literalCompressionMode;
	int nbWorkers;
	size_t jobSize;
	int overlapLog;
	int rsyncable;
	ldmParams_t ldmParams;
	int enableDedicatedDictSearch;
	ZSTD_bufferMode_e inBufferMode;
	ZSTD_bufferMode_e outBufferMode;
	ZSTD_sequenceFormat_e blockDelimiters;
	int validateSequences;
	ZSTD_customMem customMem;
};

typedef struct ZSTD_CCtx_params_s ZSTD_CCtx_params;

typedef enum {
	ZSTD_cwksp_alloc_objects = 0,
	ZSTD_cwksp_alloc_buffers = 1,
	ZSTD_cwksp_alloc_aligned = 2,
} ZSTD_cwksp_alloc_phase_e;

typedef enum {
	ZSTD_cwksp_dynamic_alloc = 0,
	ZSTD_cwksp_static_alloc = 1,
} ZSTD_cwksp_static_alloc_e;

typedef struct {
	void *workspace;
	void *workspaceEnd;
	void *objectEnd;
	void *tableEnd;
	void *tableValidEnd;
	void *allocStart;
	BYTE allocFailed;
	int workspaceOversizedDuration;
	ZSTD_cwksp_alloc_phase_e phase;
	ZSTD_cwksp_static_alloc_e isStatic;
} ZSTD_cwksp;

struct xxh64_state {
	uint64_t total_len;
	uint64_t v1;
	uint64_t v2;
	uint64_t v3;
	uint64_t v4;
	uint64_t mem64[4];
	uint32_t memsize;
};

struct POOL_ctx_s;

typedef struct POOL_ctx_s ZSTD_threadPool;

typedef struct {
	unsigned int offset;
	unsigned int litLength;
	unsigned int matchLength;
	unsigned int rep;
} ZSTD_Sequence;

typedef struct {
	int collectSequences;
	ZSTD_Sequence *seqStart;
	size_t seqIndex;
	size_t maxSequences;
} SeqCollector;

struct seqDef_s;

typedef struct seqDef_s seqDef;

typedef struct {
	seqDef *sequencesStart;
	seqDef *sequences;
	BYTE *litStart;
	BYTE *lit;
	BYTE *llCode;
	BYTE *mlCode;
	BYTE *ofCode;
	size_t maxNbSeq;
	size_t maxNbLit;
	U32 longLengthID;
	U32 longLengthPos;
} seqStore_t;

typedef struct {
	const BYTE *nextSrc;
	const BYTE *base;
	const BYTE *dictBase;
	U32 dictLimit;
	U32 lowLimit;
} ZSTD_window_t;

typedef struct {
	U32 offset;
	U32 checksum;
} ldmEntry_t;

typedef struct {
	const BYTE *split;
	U32 hash;
	U32 checksum;
	ldmEntry_t *bucket;
} ldmMatchCandidate_t;

typedef struct {
	ZSTD_window_t window;
	ldmEntry_t *hashTable;
	U32 loadedDictEnd;
	BYTE *bucketOffsets;
	size_t splitIndices[64];
	ldmMatchCandidate_t matchCandidates[64];
} ldmState_t;

typedef struct {
	U32 offset;
	U32 litLength;
	U32 matchLength;
} rawSeq;

typedef struct {
	rawSeq *seq;
	size_t pos;
	size_t posInSequence;
	size_t size;
	size_t capacity;
} rawSeqStore_t;

typedef struct {
	HUF_CElt CTable[256];
	HUF_repeat repeatMode;
} ZSTD_hufCTables_t;

typedef struct {
	FSE_CTable offcodeCTable[193];
	FSE_CTable matchlengthCTable[363];
	FSE_CTable litlengthCTable[329];
	FSE_repeat offcode_repeatMode;
	FSE_repeat matchlength_repeatMode;
	FSE_repeat litlength_repeatMode;
} ZSTD_fseCTables_t;

typedef struct {
	ZSTD_hufCTables_t huf;
	ZSTD_fseCTables_t fse;
} ZSTD_entropyCTables_t;

typedef struct {
	ZSTD_entropyCTables_t entropy;
	U32 rep[3];
} ZSTD_compressedBlockState_t;

typedef struct {
	U32 off;
	U32 len;
} ZSTD_match_t;

typedef struct {
	int price;
	U32 off;
	U32 mlen;
	U32 litlen;
	U32 rep[3];
} ZSTD_optimal_t;

typedef enum {
	zop_dynamic = 0,
	zop_predef = 1,
} ZSTD_OptPrice_e;

typedef struct {
	unsigned int *litFreq;
	unsigned int *litLengthFreq;
	unsigned int *matchLengthFreq;
	unsigned int *offCodeFreq;
	ZSTD_match_t *matchTable;
	ZSTD_optimal_t *priceTable;
	U32 litSum;
	U32 litLengthSum;
	U32 matchLengthSum;
	U32 offCodeSum;
	U32 litSumBasePrice;
	U32 litLengthSumBasePrice;
	U32 matchLengthSumBasePrice;
	U32 offCodeSumBasePrice;
	ZSTD_OptPrice_e priceType;
	const ZSTD_entropyCTables_t *symbolCosts;
	ZSTD_literalCompressionMode_e literalCompressionMode;
} optState_t;

struct ZSTD_matchState_t;

typedef struct ZSTD_matchState_t ZSTD_matchState_t;

struct ZSTD_matchState_t {
	ZSTD_window_t window;
	U32 loadedDictEnd;
	U32 nextToUpdate;
	U32 hashLog3;
	U32 *hashTable;
	U32 *hashTable3;
	U32 *chainTable;
	int dedicatedDictSearch;
	optState_t opt;
	const ZSTD_matchState_t *dictMatchState;
	ZSTD_compressionParameters cParams;
	const rawSeqStore_t *ldmSeqStore;
};

typedef struct {
	ZSTD_compressedBlockState_t *prevCBlock;
	ZSTD_compressedBlockState_t *nextCBlock;
	ZSTD_matchState_t matchState;
} ZSTD_blockState_t;

typedef enum {
	ZSTDb_not_buffered = 0,
	ZSTDb_buffered = 1,
} ZSTD_buffered_policy_e;

typedef enum {
	zcss_init = 0,
	zcss_load = 1,
	zcss_flush = 2,
} ZSTD_cStreamStage;

struct ZSTD_inBuffer_s {
	const void *src;
	size_t size;
	size_t pos;
};

typedef struct ZSTD_inBuffer_s ZSTD_inBuffer;

typedef enum {
	ZSTD_dct_auto = 0,
	ZSTD_dct_rawContent = 1,
	ZSTD_dct_fullDict = 2,
} ZSTD_dictContentType_e;

struct ZSTD_CDict_s;

typedef struct ZSTD_CDict_s ZSTD_CDict;

typedef struct {
	void *dictBuffer;
	const void *dict;
	size_t dictSize;
	ZSTD_dictContentType_e dictContentType;
	ZSTD_CDict *cdict;
} ZSTD_localDict;

struct ZSTD_prefixDict_s {
	const void *dict;
	size_t dictSize;
	ZSTD_dictContentType_e dictContentType;
};

typedef struct ZSTD_prefixDict_s ZSTD_prefixDict;

struct ZSTD_CCtx_s {
	ZSTD_compressionStage_e stage;
	int cParamsChanged;
	int bmi2;
	ZSTD_CCtx_params requestedParams;
	ZSTD_CCtx_params appliedParams;
	U32 dictID;
	size_t dictContentSize;
	ZSTD_cwksp workspace;
	size_t blockSize;
	long long unsigned int pledgedSrcSizePlusOne;
	long long unsigned int consumedSrcSize;
	long long unsigned int producedCSize;
	struct xxh64_state xxhState;
	ZSTD_customMem customMem;
	ZSTD_threadPool *pool;
	size_t staticSize;
	SeqCollector seqCollector;
	int isFirstBlock;
	int initialized;
	seqStore_t seqStore;
	ldmState_t ldmState;
	rawSeq *ldmSequences;
	size_t maxNbLdmSequences;
	rawSeqStore_t externSeqStore;
	ZSTD_blockState_t blockState;
	U32 *entropyWorkspace;
	ZSTD_buffered_policy_e bufferedPolicy;
	char *inBuff;
	size_t inBuffSize;
	size_t inToCompress;
	size_t inBuffPos;
	size_t inBuffTarget;
	char *outBuff;
	size_t outBuffSize;
	size_t outBuffContentSize;
	size_t outBuffFlushedSize;
	ZSTD_cStreamStage streamStage;
	U32 frameEnded;
	ZSTD_inBuffer expectedInBuffer;
	size_t expectedOutBufferSize;
	ZSTD_localDict localDict;
	const ZSTD_CDict *cdict;
	ZSTD_prefixDict prefixDict;
};

typedef struct ZSTD_CCtx_s ZSTD_CCtx;

typedef enum {
	ZSTD_c_compressionLevel = 100,
	ZSTD_c_windowLog = 101,
	ZSTD_c_hashLog = 102,
	ZSTD_c_chainLog = 103,
	ZSTD_c_searchLog = 104,
	ZSTD_c_minMatch = 105,
	ZSTD_c_targetLength = 106,
	ZSTD_c_strategy = 107,
	ZSTD_c_enableLongDistanceMatching = 160,
	ZSTD_c_ldmHashLog = 161,
	ZSTD_c_ldmMinMatch = 162,
	ZSTD_c_ldmBucketSizeLog = 163,
	ZSTD_c_ldmHashRateLog = 164,
	ZSTD_c_contentSizeFlag = 200,
	ZSTD_c_checksumFlag = 201,
	ZSTD_c_dictIDFlag = 202,
	ZSTD_c_nbWorkers = 400,
	ZSTD_c_jobSize = 401,
	ZSTD_c_overlapLog = 402,
	ZSTD_c_experimentalParam1 = 500,
	ZSTD_c_experimentalParam2 = 10,
	ZSTD_c_experimentalParam3 = 1000,
	ZSTD_c_experimentalParam4 = 1001,
	ZSTD_c_experimentalParam5 = 1002,
	ZSTD_c_experimentalParam6 = 1003,
	ZSTD_c_experimentalParam7 = 1004,
	ZSTD_c_experimentalParam8 = 1005,
	ZSTD_c_experimentalParam9 = 1006,
	ZSTD_c_experimentalParam10 = 1007,
	ZSTD_c_experimentalParam11 = 1008,
	ZSTD_c_experimentalParam12 = 1009,
} ZSTD_cParameter;

typedef struct {
	size_t error;
	int lowerBound;
	int upperBound;
} ZSTD_bounds;

typedef enum {
	ZSTD_reset_session_only = 1,
	ZSTD_reset_parameters = 2,
	ZSTD_reset_session_and_parameters = 3,
} ZSTD_ResetDirective;

struct ZSTD_outBuffer_s {
	void *dst;
	size_t size;
	size_t pos;
};

typedef struct ZSTD_outBuffer_s ZSTD_outBuffer;

typedef ZSTD_CCtx ZSTD_CStream;

typedef enum {
	ZSTD_e_continue = 0,
	ZSTD_e_flush = 1,
	ZSTD_e_end = 2,
} ZSTD_EndDirective;

struct ZSTD_CDict_s {
	const void *dictContent;
	size_t dictContentSize;
	ZSTD_dictContentType_e dictContentType;
	U32 *entropyWorkspace;
	ZSTD_cwksp workspace;
	ZSTD_matchState_t matchState;
	ZSTD_compressedBlockState_t cBlockState;
	ZSTD_customMem customMem;
	U32 dictID;
	int compressionLevel;
};

typedef struct {
	ZSTD_compressionParameters cParams;
	ZSTD_frameParameters fParams;
} ZSTD_parameters;

typedef enum {
	ZSTD_dlm_byCopy = 0,
	ZSTD_dlm_byRef = 1,
} ZSTD_dictLoadMethod_e;

typedef struct {
	long long unsigned int ingested;
	long long unsigned int consumed;
	long long unsigned int produced;
	long long unsigned int flushed;
	unsigned int currentJobID;
	unsigned int nbActiveWorkers;
} ZSTD_frameProgression;

typedef enum {
	set_basic = 0,
	set_rle = 1,
	set_compressed = 2,
	set_repeat = 3,
} symbolEncodingType_e;

typedef enum {
	ZSTD_no_overlap = 0,
	ZSTD_overlap_src_before_dst = 1,
} ZSTD_overlap_e;

struct seqDef_s {
	U32 offset;
	U16 litLength;
	U16 matchLength;
};

typedef enum {
	ZSTD_dtlm_fast = 0,
	ZSTD_dtlm_full = 1,
} ZSTD_dictTableLoadMethod_e;

typedef enum {
	ZSTD_noDict = 0,
	ZSTD_extDict = 1,
	ZSTD_dictMatchState = 2,
	ZSTD_dedicatedDictSearch = 3,
} ZSTD_dictMode_e;

typedef enum {
	ZSTD_cpm_noAttachDict = 0,
	ZSTD_cpm_attachDict = 1,
	ZSTD_cpm_createCDict = 2,
	ZSTD_cpm_unknown = 3,
} ZSTD_cParamMode_e;

typedef size_t (*ZSTD_blockCompressor)(ZSTD_matchState_t *, seqStore_t *, U32 *, const void *, size_t);

struct repcodes_s {
	U32 rep[3];
};

typedef struct repcodes_s repcodes_t;

typedef enum {
	ZSTD_defaultDisallowed = 0,
	ZSTD_defaultAllowed = 1,
} ZSTD_defaultPolicy_e;

typedef enum {
	ZSTDcrp_makeClean = 0,
	ZSTDcrp_leaveDirty = 1,
} ZSTD_compResetPolicy_e;

typedef enum {
	ZSTDirp_continue = 0,
	ZSTDirp_reset = 1,
} ZSTD_indexResetPolicy_e;

typedef enum {
	ZSTD_resetTarget_CDict = 0,
	ZSTD_resetTarget_CCtx = 1,
} ZSTD_resetTarget_e;

enum {
	ZSTDbss_compress = 0,
	ZSTDbss_noCompress = 1,
};

typedef struct {
	U32 idx;
	U32 posInSequence;
	size_t posInSrc;
} ZSTD_sequencePosition;

typedef size_t (*ZSTD_sequenceCopier)(ZSTD_CCtx *, ZSTD_sequencePosition *, const ZSTD_Sequence * const, size_t, const void *, size_t);

enum xz_mode {
	XZ_SINGLE = 0,
	XZ_PREALLOC = 1,
	XZ_DYNALLOC = 2,
};

enum xz_ret {
	XZ_OK = 0,
	XZ_STREAM_END = 1,
	XZ_UNSUPPORTED_CHECK = 2,
	XZ_MEM_ERROR = 3,
	XZ_MEMLIMIT_ERROR = 4,
	XZ_FORMAT_ERROR = 5,
	XZ_OPTIONS_ERROR = 6,
	XZ_DATA_ERROR = 7,
	XZ_BUF_ERROR = 8,
};

struct xz_buf {
	const uint8_t *in;
	size_t in_pos;
	size_t in_size;
	uint8_t *out;
	size_t out_pos;
	size_t out_size;
};

struct xz_dec_microlzma;

struct xz_dec;

typedef __u16 __sum16;

struct sg_splitter {
	struct scatterlist *in_sg0;
	int nents;
	off_t skip_sg0;
	unsigned int length_last_sg;
	struct scatterlist *out_sg;
};

struct ida {
	struct xarray xa;
};

typedef u32 depot_stack_handle_t;

union handle_parts {
	depot_stack_handle_t handle;
	struct {
		u32 slabindex: 21;
		u32 offset: 10;
		u32 valid: 1;
	};
};

struct stack_record {
	struct stack_record *next;
	u32 hash;
	u32 size;
	union handle_parts handle;
	long unsigned int entries[0];
};

struct group_data {
	int limit[21];
	int base[20];
	int permute[258];
	int minLen;
	int maxLen;
};

struct bunzip_data {
	int writeCopies;
	int writePos;
	int writeRunCountdown;
	int writeCount;
	int writeCurrent;
	long int (*fill)(void *, long unsigned int);
	long int inbufCount;
	long int inbufPos;
	unsigned char *inbuf;
	unsigned int inbufBitCount;
	unsigned int inbufBits;
	unsigned int crc32Table[256];
	unsigned int headerCRC;
	unsigned int totalCRC;
	unsigned int writeCRC;
	unsigned int *dbuf;
	unsigned int dbufSize;
	unsigned char selectors[32768];
	struct group_data groups[6];
	int io_error;
	int byteCount[256];
	unsigned char symToByte[256];
	unsigned char mtfSymbol[256];
};

struct rc {
	long int (*fill)(void *, long unsigned int);
	uint8_t *ptr;
	uint8_t *buffer;
	uint8_t *buffer_end;
	long int buffer_size;
	uint32_t code;
	uint32_t range;
	uint32_t bound;
	void (*error)(char *);
};

struct lzma_header {
	uint8_t pos;
	uint32_t dict_size;
	uint64_t dst_size;
} __attribute__((packed));

struct writer {
	uint8_t *buffer;
	uint8_t previous_byte;
	size_t buffer_pos;
	int bufsize;
	size_t global_pos;
	long int (*flush)(void *, long unsigned int);
	struct lzma_header *header;
};

struct cstate {
	int state;
	uint32_t rep0;
	uint32_t rep1;
	uint32_t rep2;
	uint32_t rep3;
};

struct word_at_a_time {
	const long unsigned int one_bits;
	const long unsigned int high_bits;
};

struct minmax_sample {
	u32 t;
	u32 v;
};

struct minmax {
	struct minmax_sample s[3];
};

struct xa_limit {
	u32 max;
	u32 min;
};

typedef int (*of_init_fn_2)(struct device_node *, struct device_node *);

typedef int (*of_irq_init_cb_t)(struct device_node *, struct device_node *);

struct armctrl_ic {
	void *base;
	void *pending[3];
	void *enable[3];
	void *disable[3];
	struct irq_domain *domain;
};

struct gic_quirk {
	const char *desc;
	const char *compatible;
	bool (*init)(void *);
	u32 iidr;
	u32 mask;
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

struct msi_alloc_info {
	struct msi_desc *desc;
	irq_hw_number_t hwirq;
	long unsigned int flags;
	union {
		long unsigned int ul;
		void *ptr;
	} scratchpad[2];
};

typedef struct msi_alloc_info msi_alloc_info_t;

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

struct mbi_range {
	u32 spi_start;
	u32 nr_spis;
	long unsigned int *bm;
};

struct partition_affinity {
	cpumask_t mask;
	void *partition_id;
};

struct partition_desc {
	int nr_parts;
	struct partition_affinity *parts;
	struct irq_domain *domain;
	struct irq_desc *chained_desc;
	long unsigned int *bitmap;
	struct irq_domain_ops ops;
};

struct odmi_data {
	struct resource res;
	void *base;
	unsigned int spi_base;
};

struct platform_device_id {
	char name[20];
	kernel_ulong_t driver_data;
};

struct pdev_archdata {};

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

struct platform_driver {
	int (*probe)(struct platform_device *);
	int (*remove)(struct platform_device *);
	void (*shutdown)(struct platform_device *);
	int (*suspend)(struct platform_device *, pm_message_t);
	int (*resume)(struct platform_device *);
	struct device_driver driver;
	const struct platform_device_id *id_table;
	bool prevent_deferred_probe;
	bool driver_managed_dma;
};

struct meson_gpio_irq_controller;

struct irq_ctl_ops {
	void (*gpio_irq_sel_pin)(struct meson_gpio_irq_controller *, unsigned int, long unsigned int);
	void (*gpio_irq_init)(struct meson_gpio_irq_controller *);
	int (*gpio_irq_set_type)(struct meson_gpio_irq_controller *, unsigned int, u32 *);
};

struct meson_gpio_irq_params;

struct meson_gpio_irq_controller {
	const struct meson_gpio_irq_params *params;
	void *base;
	u32 channel_irqs[64];
	long unsigned int channel_map[1];
	spinlock_t lock;
};

struct meson_gpio_irq_params {
	unsigned int nr_hwirq;
	unsigned int nr_channels;
	bool support_edge_both;
	unsigned int edge_both_offset;
	unsigned int edge_single_offset;
	unsigned int pol_low_offset;
	unsigned int pin_sel_mask;
	struct irq_ctl_ops ops;
};

typedef u64 acpi_io_address;

typedef u32 acpi_object_type;

union acpi_object {
	acpi_object_type type;
	struct {
		acpi_object_type type;
		u64 value;
	} integer;
	struct {
		acpi_object_type type;
		u32 length;
		char *pointer;
	} string;
	struct {
		acpi_object_type type;
		u32 length;
		u8 *pointer;
	} buffer;
	struct {
		acpi_object_type type;
		u32 count;
		union acpi_object *elements;
	} package;
	struct {
		acpi_object_type type;
		acpi_object_type actual_type;
		acpi_handle handle;
	} reference;
	struct {
		acpi_object_type type;
		u32 proc_id;
		acpi_io_address pblk_address;
		u32 pblk_length;
	} processor;
	struct {
		acpi_object_type type;
		u32 system_level;
		u32 resource_order;
	} power_resource;
};

struct acpi_resource_irq {
	u8 descriptor_length;
	u8 triggering;
	u8 polarity;
	u8 shareable;
	u8 wake_capable;
	u8 interrupt_count;
	u8 interrupts[1];
};

struct acpi_resource_dma {
	u8 type;
	u8 bus_master;
	u8 transfer;
	u8 channel_count;
	u8 channels[1];
};

struct acpi_resource_start_dependent {
	u8 descriptor_length;
	u8 compatibility_priority;
	u8 performance_robustness;
};

struct acpi_resource_io {
	u8 io_decode;
	u8 alignment;
	u8 address_length;
	u16 minimum;
	u16 maximum;
} __attribute__((packed));

struct acpi_resource_fixed_io {
	u16 address;
	u8 address_length;
} __attribute__((packed));

struct acpi_resource_fixed_dma {
	u16 request_lines;
	u16 channels;
	u8 width;
} __attribute__((packed));

struct acpi_resource_vendor {
	u16 byte_length;
	u8 byte_data[1];
} __attribute__((packed));

struct acpi_resource_vendor_typed {
	u16 byte_length;
	u8 uuid_subtype;
	u8 uuid[16];
	u8 byte_data[1];
};

struct acpi_resource_end_tag {
	u8 checksum;
};

struct acpi_resource_memory24 {
	u8 write_protect;
	u16 minimum;
	u16 maximum;
	u16 alignment;
	u16 address_length;
} __attribute__((packed));

struct acpi_resource_memory32 {
	u8 write_protect;
	u32 minimum;
	u32 maximum;
	u32 alignment;
	u32 address_length;
} __attribute__((packed));

struct acpi_resource_fixed_memory32 {
	u8 write_protect;
	u32 address;
	u32 address_length;
} __attribute__((packed));

struct acpi_memory_attribute {
	u8 write_protect;
	u8 caching;
	u8 range_type;
	u8 translation;
};

struct acpi_io_attribute {
	u8 range_type;
	u8 translation;
	u8 translation_type;
	u8 reserved1;
};

union acpi_resource_attribute {
	struct acpi_memory_attribute mem;
	struct acpi_io_attribute io;
	u8 type_specific;
};

struct acpi_resource_label {
	u16 string_length;
	char *string_ptr;
} __attribute__((packed));

struct acpi_resource_source {
	u8 index;
	u16 string_length;
	char *string_ptr;
} __attribute__((packed));

struct acpi_address16_attribute {
	u16 granularity;
	u16 minimum;
	u16 maximum;
	u16 translation_offset;
	u16 address_length;
};

struct acpi_address32_attribute {
	u32 granularity;
	u32 minimum;
	u32 maximum;
	u32 translation_offset;
	u32 address_length;
};

struct acpi_address64_attribute {
	u64 granularity;
	u64 minimum;
	u64 maximum;
	u64 translation_offset;
	u64 address_length;
};

struct acpi_resource_address {
	u8 resource_type;
	u8 producer_consumer;
	u8 decode;
	u8 min_address_fixed;
	u8 max_address_fixed;
	union acpi_resource_attribute info;
};

struct acpi_resource_address16 {
	u8 resource_type;
	u8 producer_consumer;
	u8 decode;
	u8 min_address_fixed;
	u8 max_address_fixed;
	union acpi_resource_attribute info;
	struct acpi_address16_attribute address;
	struct acpi_resource_source resource_source;
} __attribute__((packed));

struct acpi_resource_address32 {
	u8 resource_type;
	u8 producer_consumer;
	u8 decode;
	u8 min_address_fixed;
	u8 max_address_fixed;
	union acpi_resource_attribute info;
	struct acpi_address32_attribute address;
	struct acpi_resource_source resource_source;
} __attribute__((packed));

struct acpi_resource_address64 {
	u8 resource_type;
	u8 producer_consumer;
	u8 decode;
	u8 min_address_fixed;
	u8 max_address_fixed;
	union acpi_resource_attribute info;
	struct acpi_address64_attribute address;
	struct acpi_resource_source resource_source;
} __attribute__((packed));

struct acpi_resource_extended_address64 {
	u8 resource_type;
	u8 producer_consumer;
	u8 decode;
	u8 min_address_fixed;
	u8 max_address_fixed;
	union acpi_resource_attribute info;
	u8 revision_ID;
	struct acpi_address64_attribute address;
	u64 type_specific;
} __attribute__((packed));

struct acpi_resource_extended_irq {
	u8 producer_consumer;
	u8 triggering;
	u8 polarity;
	u8 shareable;
	u8 wake_capable;
	u8 interrupt_count;
	struct acpi_resource_source resource_source;
	u32 interrupts[1];
} __attribute__((packed));

struct acpi_resource_generic_register {
	u8 space_id;
	u8 bit_width;
	u8 bit_offset;
	u8 access_size;
	u64 address;
} __attribute__((packed));

struct acpi_resource_gpio {
	u8 revision_id;
	u8 connection_type;
	u8 producer_consumer;
	u8 pin_config;
	u8 shareable;
	u8 wake_capable;
	u8 io_restriction;
	u8 triggering;
	u8 polarity;
	u16 drive_strength;
	u16 debounce_timeout;
	u16 pin_table_length;
	u16 vendor_length;
	struct acpi_resource_source resource_source;
	u16 *pin_table;
	u8 *vendor_data;
} __attribute__((packed));

struct acpi_resource_common_serialbus {
	u8 revision_id;
	u8 type;
	u8 producer_consumer;
	u8 slave_mode;
	u8 connection_sharing;
	u8 type_revision_id;
	u16 type_data_length;
	u16 vendor_length;
	struct acpi_resource_source resource_source;
	u8 *vendor_data;
} __attribute__((packed));

struct acpi_resource_i2c_serialbus {
	u8 revision_id;
	u8 type;
	u8 producer_consumer;
	u8 slave_mode;
	u8 connection_sharing;
	u8 type_revision_id;
	u16 type_data_length;
	u16 vendor_length;
	struct acpi_resource_source resource_source;
	u8 *vendor_data;
	u8 access_mode;
	u16 slave_address;
	u32 connection_speed;
} __attribute__((packed));

struct acpi_resource_spi_serialbus {
	u8 revision_id;
	u8 type;
	u8 producer_consumer;
	u8 slave_mode;
	u8 connection_sharing;
	u8 type_revision_id;
	u16 type_data_length;
	u16 vendor_length;
	struct acpi_resource_source resource_source;
	u8 *vendor_data;
	u8 wire_mode;
	u8 device_polarity;
	u8 data_bit_length;
	u8 clock_phase;
	u8 clock_polarity;
	u16 device_selection;
	u32 connection_speed;
} __attribute__((packed));

struct acpi_resource_uart_serialbus {
	u8 revision_id;
	u8 type;
	u8 producer_consumer;
	u8 slave_mode;
	u8 connection_sharing;
	u8 type_revision_id;
	u16 type_data_length;
	u16 vendor_length;
	struct acpi_resource_source resource_source;
	u8 *vendor_data;
	u8 endian;
	u8 data_bits;
	u8 stop_bits;
	u8 flow_control;
	u8 parity;
	u8 lines_enabled;
	u16 rx_fifo_size;
	u16 tx_fifo_size;
	u32 default_baud_rate;
} __attribute__((packed));

struct acpi_resource_csi2_serialbus {
	u8 revision_id;
	u8 type;
	u8 producer_consumer;
	u8 slave_mode;
	u8 connection_sharing;
	u8 type_revision_id;
	u16 type_data_length;
	u16 vendor_length;
	struct acpi_resource_source resource_source;
	u8 *vendor_data;
	u8 local_port_instance;
	u8 phy_type;
} __attribute__((packed));

struct acpi_resource_pin_function {
	u8 revision_id;
	u8 pin_config;
	u8 shareable;
	u16 function_number;
	u16 pin_table_length;
	u16 vendor_length;
	struct acpi_resource_source resource_source;
	u16 *pin_table;
	u8 *vendor_data;
} __attribute__((packed));

struct acpi_resource_pin_config {
	u8 revision_id;
	u8 producer_consumer;
	u8 shareable;
	u8 pin_config_type;
	u32 pin_config_value;
	u16 pin_table_length;
	u16 vendor_length;
	struct acpi_resource_source resource_source;
	u16 *pin_table;
	u8 *vendor_data;
} __attribute__((packed));

struct acpi_resource_pin_group {
	u8 revision_id;
	u8 producer_consumer;
	u16 pin_table_length;
	u16 vendor_length;
	u16 *pin_table;
	struct acpi_resource_label resource_label;
	u8 *vendor_data;
} __attribute__((packed));

struct acpi_resource_pin_group_function {
	u8 revision_id;
	u8 producer_consumer;
	u8 shareable;
	u16 function_number;
	u16 vendor_length;
	struct acpi_resource_source resource_source;
	struct acpi_resource_label resource_source_label;
	u8 *vendor_data;
} __attribute__((packed));

struct acpi_resource_pin_group_config {
	u8 revision_id;
	u8 producer_consumer;
	u8 shareable;
	u8 pin_config_type;
	u32 pin_config_value;
	u16 vendor_length;
	struct acpi_resource_source resource_source;
	struct acpi_resource_label resource_source_label;
	u8 *vendor_data;
} __attribute__((packed));

union acpi_resource_data {
	struct acpi_resource_irq irq;
	struct acpi_resource_dma dma;
	struct acpi_resource_start_dependent start_dpf;
	struct acpi_resource_io io;
	struct acpi_resource_fixed_io fixed_io;
	struct acpi_resource_fixed_dma fixed_dma;
	struct acpi_resource_vendor vendor;
	struct acpi_resource_vendor_typed vendor_typed;
	struct acpi_resource_end_tag end_tag;
	struct acpi_resource_memory24 memory24;
	struct acpi_resource_memory32 memory32;
	struct acpi_resource_fixed_memory32 fixed_memory32;
	struct acpi_resource_address16 address16;
	struct acpi_resource_address32 address32;
	struct acpi_resource_address64 address64;
	struct acpi_resource_extended_address64 ext_address64;
	struct acpi_resource_extended_irq extended_irq;
	struct acpi_resource_generic_register generic_reg;
	struct acpi_resource_gpio gpio;
	struct acpi_resource_i2c_serialbus i2c_serial_bus;
	struct acpi_resource_spi_serialbus spi_serial_bus;
	struct acpi_resource_uart_serialbus uart_serial_bus;
	struct acpi_resource_csi2_serialbus csi2_serial_bus;
	struct acpi_resource_common_serialbus common_serial_bus;
	struct acpi_resource_pin_function pin_function;
	struct acpi_resource_pin_config pin_config;
	struct acpi_resource_pin_group pin_group;
	struct acpi_resource_pin_group_function pin_group_function;
	struct acpi_resource_pin_group_config pin_group_config;
	struct acpi_resource_address address;
};

struct acpi_resource {
	u32 type;
	u32 length;
	union acpi_resource_data data;
} __attribute__((packed));

struct acpi_device;

struct acpi_hotplug_profile {
	struct kobject kobj;
	int (*scan_dependent)(struct acpi_device *);
	void (*notify_online)(struct acpi_device *);
	bool enabled: 1;
	bool demand_offline: 1;
};

struct acpi_device_status {
	u32 present: 1;
	u32 enabled: 1;
	u32 show_in_ui: 1;
	u32 functional: 1;
	u32 battery_present: 1;
	u32 reserved: 27;
};

struct acpi_device_flags {
	u32 dynamic_status: 1;
	u32 removable: 1;
	u32 ejectable: 1;
	u32 power_manageable: 1;
	u32 match_driver: 1;
	u32 initialized: 1;
	u32 visited: 1;
	u32 hotplug_notify: 1;
	u32 is_dock_station: 1;
	u32 of_compatible_ok: 1;
	u32 coherent_dma: 1;
	u32 cca_seen: 1;
	u32 enumeration_by_parent: 1;
	u32 honor_deps: 1;
	u32 reserved: 18;
};

typedef char acpi_bus_id[8];

struct acpi_pnp_type {
	u32 hardware_id: 1;
	u32 bus_address: 1;
	u32 platform_id: 1;
	u32 reserved: 29;
};

typedef u64 acpi_bus_address;

typedef char acpi_device_name[40];

typedef char acpi_device_class[20];

struct acpi_device_pnp {
	acpi_bus_id bus_id;
	int instance_no;
	struct acpi_pnp_type type;
	acpi_bus_address bus_address;
	char *unique_id;
	struct list_head ids;
	acpi_device_name device_name;
	acpi_device_class device_class;
	union acpi_object *str_obj;
};

struct acpi_device_power_flags {
	u32 explicit_get: 1;
	u32 power_resources: 1;
	u32 inrush_current: 1;
	u32 power_removed: 1;
	u32 ignore_parent: 1;
	u32 dsw_present: 1;
	u32 reserved: 26;
};

struct acpi_device_power_state {
	struct {
		u8 valid: 1;
		u8 explicit_set: 1;
		u8 reserved: 6;
	} flags;
	int power;
	int latency;
	struct list_head resources;
};

struct acpi_device_power {
	int state;
	struct acpi_device_power_flags flags;
	struct acpi_device_power_state states[5];
	u8 state_for_enumeration;
};

struct acpi_device_wakeup_flags {
	u8 valid: 1;
	u8 notifier_present: 1;
};

struct acpi_device_wakeup_context {
	void (*func)(struct acpi_device_wakeup_context *);
	struct device *dev;
};

struct acpi_device_wakeup {
	acpi_handle gpe_device;
	u64 gpe_number;
	u64 sleep_state;
	struct list_head resources;
	struct acpi_device_wakeup_flags flags;
	struct acpi_device_wakeup_context context;
	struct wakeup_source *ws;
	int prepare_count;
	int enable_count;
};

struct acpi_device_perf_flags {
	u8 reserved: 8;
};

struct acpi_device_perf_state;

struct acpi_device_perf {
	int state;
	struct acpi_device_perf_flags flags;
	int state_count;
	struct acpi_device_perf_state *states;
};

struct acpi_device_dir {
	struct proc_dir_entry *entry;
};

struct acpi_device_data {
	const union acpi_object *pointer;
	struct list_head properties;
	const union acpi_object *of_compatible;
	struct list_head subnodes;
};

struct acpi_scan_handler;

struct acpi_hotplug_context;

struct acpi_gpio_mapping;

struct acpi_device {
	u32 pld_crc;
	int device_type;
	acpi_handle handle;
	struct fwnode_handle fwnode;
	struct acpi_device *parent;
	struct list_head wakeup_list;
	struct list_head del_list;
	struct acpi_device_status status;
	struct acpi_device_flags flags;
	struct acpi_device_pnp pnp;
	struct acpi_device_power power;
	struct acpi_device_wakeup wakeup;
	struct acpi_device_perf performance;
	struct acpi_device_dir dir;
	struct acpi_device_data data;
	struct acpi_scan_handler *handler;
	struct acpi_hotplug_context *hp;
	const struct acpi_gpio_mapping *driver_gpios;
	void *driver_data;
	struct device dev;
	unsigned int physical_node_count;
	unsigned int dep_unmet;
	struct list_head physical_node_list;
	struct mutex physical_node_lock;
	void (*remove)(struct acpi_device *);
};

struct acpi_scan_handler {
	const struct acpi_device_id *ids;
	struct list_head list_node;
	bool (*match)(const char *, const struct acpi_device_id **);
	int (*attach)(struct acpi_device *, const struct acpi_device_id *);
	void (*detach)(struct acpi_device *);
	void (*bind)(struct device *);
	void (*unbind)(struct device *);
	struct acpi_hotplug_profile hotplug;
};

struct acpi_hotplug_context {
	struct acpi_device *self;
	int (*notify)(struct acpi_device *, u32);
	void (*uevent)(struct acpi_device *, u32);
	void (*fixup)(struct acpi_device *);
};

struct acpi_device_perf_state {
	struct {
		u8 valid: 1;
		u8 reserved: 7;
	} flags;
	u8 power;
	u8 performance;
	int latency;
};

struct acpi_gpio_params;

struct acpi_gpio_mapping {
	const char *name;
	const struct acpi_gpio_params *data;
	unsigned int size;
	unsigned int quirks;
};

enum {
	LOGIC_PIO_INDIRECT = 0,
	LOGIC_PIO_CPU_MMIO = 1,
};

struct logic_pio_host_ops;

struct logic_pio_hwaddr {
	struct list_head list;
	struct fwnode_handle *fwnode;
	resource_size_t hw_start;
	resource_size_t io_start;
	resource_size_t size;
	long unsigned int flags;
	void *hostdata;
	const struct logic_pio_host_ops *ops;
};

struct logic_pio_host_ops {
	u32 (*in)(void *, long unsigned int, size_t);
	void (*out)(void *, long unsigned int, u32, size_t);
	u32 (*ins)(void *, long unsigned int, void *, size_t, unsigned int);
	void (*outs)(void *, long unsigned int, const void *, size_t, unsigned int);
};

struct acpi_gpio_params {
	unsigned int crs_entry_index;
	unsigned int line_index;
	bool active_low;
};

struct console {
	char name[16];
	void (*write)(struct console *, const char *, unsigned int);
	int (*read)(struct console *, char *, unsigned int);
	struct tty_driver * (*device)(struct console *, int *);
	void (*unblank)();
	int (*setup)(struct console *, char *);
	int (*exit)(struct console *);
	int (*match)(struct console *, char *, int, char *);
	short int flags;
	short int index;
	int cflag;
	uint ispeed;
	uint ospeed;
	u64 seq;
	long unsigned int dropped;
	void *data;
	struct console *next;
};

struct of_dev_auxdata {
	char *compatible;
	resource_size_t phys_addr;
	char *name;
	void *platform_data;
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

typedef unsigned int pci_channel_state_t;

typedef unsigned int pcie_reset_state_t;

typedef short unsigned int pci_dev_flags_t;

typedef short unsigned int pci_bus_flags_t;

typedef unsigned int pci_ers_result_t;

struct circ_buf {
	char *buf;
	int head;
	int tail;
};

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

struct serial_rs485 {
	__u32 flags;
	__u32 delay_rts_before_send;
	__u32 delay_rts_after_send;
	union {
		__u32 padding[5];
		struct {
			__u8 addr_recv;
			__u8 addr_dest;
			__u8 padding0[2];
			__u32 padding1[4];
		};
	};
};

struct serial_iso7816 {
	__u32 flags;
	__u32 tg;
	__u32 sc_fi;
	__u32 sc_di;
	__u32 clk;
	__u32 reserved[5];
};

struct uart_port;

struct uart_ops {
	unsigned int (*tx_empty)(struct uart_port *);
	void (*set_mctrl)(struct uart_port *, unsigned int);
	unsigned int (*get_mctrl)(struct uart_port *);
	void (*stop_tx)(struct uart_port *);
	void (*start_tx)(struct uart_port *);
	void (*throttle)(struct uart_port *);
	void (*unthrottle)(struct uart_port *);
	void (*send_xchar)(struct uart_port *, char);
	void (*stop_rx)(struct uart_port *);
	void (*start_rx)(struct uart_port *);
	void (*enable_ms)(struct uart_port *);
	void (*break_ctl)(struct uart_port *, int);
	int (*startup)(struct uart_port *);
	void (*shutdown)(struct uart_port *);
	void (*flush_buffer)(struct uart_port *);
	void (*set_termios)(struct uart_port *, struct ktermios *, struct ktermios *);
	void (*set_ldisc)(struct uart_port *, struct ktermios *);
	void (*pm)(struct uart_port *, unsigned int, unsigned int);
	const char * (*type)(struct uart_port *);
	void (*release_port)(struct uart_port *);
	int (*request_port)(struct uart_port *);
	void (*config_port)(struct uart_port *, int);
	int (*verify_port)(struct uart_port *, struct serial_struct *);
	int (*ioctl)(struct uart_port *, unsigned int, long unsigned int);
	int (*poll_init)(struct uart_port *);
	void (*poll_put_char)(struct uart_port *, unsigned char);
	int (*poll_get_char)(struct uart_port *);
};

struct uart_icount {
	__u32 cts;
	__u32 dsr;
	__u32 rng;
	__u32 dcd;
	__u32 rx;
	__u32 tx;
	__u32 frame;
	__u32 overrun;
	__u32 parity;
	__u32 brk;
	__u32 buf_overrun;
};

typedef u64 upf_t;

typedef unsigned int upstat_t;

struct uart_state;

struct gpio_desc;

struct uart_port {
	spinlock_t lock;
	long unsigned int iobase;
	unsigned char *membase;
	unsigned int (*serial_in)(struct uart_port *, int);
	void (*serial_out)(struct uart_port *, int, int);
	void (*set_termios)(struct uart_port *, struct ktermios *, struct ktermios *);
	void (*set_ldisc)(struct uart_port *, struct ktermios *);
	unsigned int (*get_mctrl)(struct uart_port *);
	void (*set_mctrl)(struct uart_port *, unsigned int);
	unsigned int (*get_divisor)(struct uart_port *, unsigned int, unsigned int *);
	void (*set_divisor)(struct uart_port *, unsigned int, unsigned int, unsigned int);
	int (*startup)(struct uart_port *);
	void (*shutdown)(struct uart_port *);
	void (*throttle)(struct uart_port *);
	void (*unthrottle)(struct uart_port *);
	int (*handle_irq)(struct uart_port *);
	void (*pm)(struct uart_port *, unsigned int, unsigned int);
	void (*handle_break)(struct uart_port *);
	int (*rs485_config)(struct uart_port *, struct ktermios *, struct serial_rs485 *);
	int (*iso7816_config)(struct uart_port *, struct serial_iso7816 *);
	unsigned int irq;
	long unsigned int irqflags;
	unsigned int uartclk;
	unsigned int fifosize;
	unsigned char x_char;
	unsigned char regshift;
	unsigned char iotype;
	unsigned char quirks;
	unsigned int read_status_mask;
	unsigned int ignore_status_mask;
	struct uart_state *state;
	struct uart_icount icount;
	struct console *cons;
	upf_t flags;
	upstat_t status;
	int hw_stopped;
	unsigned int mctrl;
	unsigned int frame_time;
	unsigned int type;
	const struct uart_ops *ops;
	unsigned int custom_divisor;
	unsigned int line;
	unsigned int minor;
	resource_size_t mapbase;
	resource_size_t mapsize;
	struct device *dev;
	long unsigned int sysrq;
	unsigned int sysrq_ch;
	unsigned char has_sysrq;
	unsigned char sysrq_seq;
	unsigned char hub6;
	unsigned char suspended;
	unsigned char console_reinit;
	const char *name;
	struct attribute_group *attr_group;
	const struct attribute_group **tty_groups;
	struct serial_rs485 rs485;
	struct serial_rs485 rs485_supported;
	struct gpio_desc *rs485_term_gpio;
	struct serial_iso7816 iso7816;
	void *private_data;
};

enum uart_pm_state {
	UART_PM_STATE_ON = 0,
	UART_PM_STATE_OFF = 3,
	UART_PM_STATE_UNDEFINED = 4,
};

struct uart_state {
	struct tty_port port;
	enum uart_pm_state pm_state;
	struct circ_buf xmit;
	atomic_t refcount;
	wait_queue_head_t remove_wait;
	struct uart_port *uart_port;
};

struct plat_serial8250_port {
	long unsigned int iobase;
	void *membase;
	resource_size_t mapbase;
	unsigned int irq;
	long unsigned int irqflags;
	unsigned int uartclk;
	void *private_data;
	unsigned char regshift;
	unsigned char iotype;
	unsigned char hub6;
	unsigned char has_sysrq;
	upf_t flags;
	unsigned int type;
	unsigned int (*serial_in)(struct uart_port *, int);
	void (*serial_out)(struct uart_port *, int, int);
	void (*set_termios)(struct uart_port *, struct ktermios *, struct ktermios *);
	void (*set_ldisc)(struct uart_port *, struct ktermios *);
	unsigned int (*get_mctrl)(struct uart_port *);
	int (*handle_irq)(struct uart_port *);
	void (*pm)(struct uart_port *, unsigned int, unsigned int);
	void (*handle_break)(struct uart_port *);
};

struct lpc_cycle_para {
	unsigned int opflags;
	unsigned int csize;
};

struct hisi_lpc_dev {
	spinlock_t cycle_lock;
	void *membase;
	struct logic_pio_hwaddr *io_host;
};

struct hisi_lpc_acpi_cell {
	const char *hid;
	const char *name;
	void *pdata;
	size_t pdata_size;
};

enum device_link_state {
	DL_STATE_NONE = 4294967295,
	DL_STATE_DORMANT = 0,
	DL_STATE_AVAILABLE = 1,
	DL_STATE_CONSUMER_PROBE = 2,
	DL_STATE_ACTIVE = 3,
	DL_STATE_SUPPLIER_UNBIND = 4,
};

struct device_link {
	struct device *supplier;
	struct list_head s_node;
	struct device *consumer;
	struct list_head c_node;
	struct device link_dev;
	enum device_link_state status;
	u32 flags;
	refcount_t rpm_active;
	struct kref kref;
	struct work_struct rm_work;
	bool supplier_preactivated;
};

struct fsl_mc_command {
	__le64 header;
	__le64 params[7];
};

struct fsl_mc_obj_desc {
	char type[16];
	int id;
	u16 vendor;
	u16 ver_major;
	u16 ver_minor;
	u8 irq_count;
	u8 region_count;
	u32 state;
	char label[16];
	u16 flags;
};

struct fsl_mc_io;

struct fsl_mc_device_irq;

struct fsl_mc_resource;

struct fsl_mc_device {
	struct device dev;
	u64 dma_mask;
	u16 flags;
	u32 icid;
	u16 mc_handle;
	struct fsl_mc_io *mc_io;
	struct fsl_mc_obj_desc obj_desc;
	struct resource *regions;
	struct fsl_mc_device_irq **irqs;
	struct fsl_mc_resource *resource;
	struct device_link *consumer_link;
	const char *driver_override;
};

enum fsl_mc_pool_type {
	FSL_MC_POOL_DPMCP = 0,
	FSL_MC_POOL_DPBP = 1,
	FSL_MC_POOL_DPCON = 2,
	FSL_MC_POOL_IRQ = 3,
	FSL_MC_NUM_POOL_TYPES = 4,
};

struct fsl_mc_resource_pool;

struct fsl_mc_resource {
	enum fsl_mc_pool_type type;
	s32 id;
	void *data;
	struct fsl_mc_resource_pool *parent_pool;
	struct list_head node;
};

struct fsl_mc_bus;

struct fsl_mc_resource_pool {
	enum fsl_mc_pool_type type;
	int max_count;
	int free_count;
	struct mutex mutex;
	struct list_head free_list;
	struct fsl_mc_bus *mc_bus;
};

struct fsl_mc_device_irq {
	unsigned int virq;
	struct fsl_mc_device *mc_dev;
	u8 dev_irq_index;
	struct fsl_mc_resource resource;
};

struct fsl_mc_io {
	struct device *dev;
	u16 flags;
	u32 portal_size;
	phys_addr_t portal_phys_addr;
	void *portal_virt_addr;
	struct fsl_mc_device *dpmcp_dev;
	union {
		struct mutex mutex;
		raw_spinlock_t spinlock;
	};
};

struct mc_cmd_header {
	u8 src_id;
	u8 flags_hw;
	u8 status;
	u8 flags_sw;
	__le16 token;
	__le16 cmd_id;
};

enum mc_cmd_status {
	MC_CMD_STATUS_OK = 0,
	MC_CMD_STATUS_READY = 1,
	MC_CMD_STATUS_AUTH_ERR = 3,
	MC_CMD_STATUS_NO_PRIVILEGE = 4,
	MC_CMD_STATUS_DMA_ERR = 5,
	MC_CMD_STATUS_CONFIG_ERR = 6,
	MC_CMD_STATUS_TIMEOUT = 7,
	MC_CMD_STATUS_NO_RESOURCE = 8,
	MC_CMD_STATUS_NO_MEMORY = 9,
	MC_CMD_STATUS_BUSY = 10,
	MC_CMD_STATUS_UNSUPPORTED_OP = 11,
	MC_CMD_STATUS_INVALID_STATE = 12,
};

struct dpbp_attr {
	int id;
	u16 bpid;
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

struct dprc_attributes {
	int container_id;
	u32 icid;
	int portal_id;
	u64 options;
};

struct dpbp_cmd_open {
	__le32 dpbp_id;
};

struct dpbp_rsp_get_attributes {
	__le16 pad;
	__le16 bpid;
	__le32 id;
	__le16 version_major;
	__le16 version_minor;
};

struct fsl_mc_uapi {
	struct miscdevice misc;
	struct device *device;
	struct mutex mutex;
	u32 local_instance_in_use;
	struct fsl_mc_io *static_mc_io;
};

struct fsl_mc_bus {
	struct fsl_mc_device mc_dev;
	struct fsl_mc_resource_pool resource_pools[4];
	struct fsl_mc_device_irq *irq_resources;
	struct mutex scan_mutex;
	struct dprc_attributes dprc_attr;
	struct fsl_mc_uapi uapi_misc;
	int irq_enabled;
};

struct fsl_mc_device_id {
	__u16 vendor;
	const char obj_type[16];
};

struct fsl_mc_driver {
	struct device_driver driver;
	const struct fsl_mc_device_id *match_id_table;
	int (*probe)(struct fsl_mc_device *);
	int (*remove)(struct fsl_mc_device *);
	void (*shutdown)(struct fsl_mc_device *);
	int (*suspend)(struct fsl_mc_device *, pm_message_t);
	int (*resume)(struct fsl_mc_device *);
	bool driver_managed_dma;
};

struct fsl_mc_child_objs {
	int child_count;
	struct fsl_mc_obj_desc *child_array;
};

struct dpmcp_cmd_open {
	__le32 dpmcp_id;
};

struct pm_domain_data {
	struct list_head list_node;
	struct device *dev;
};

struct reset_control;

struct regmap;

struct qcom_ssc_block_bus_data {
	const char * const *pd_names;
	struct device *pds[2];
	char *reg_mpm_sscaon_config0;
	char *reg_mpm_sscaon_config1;
	struct regmap *halt_map;
	struct clk *xo_clk;
	struct clk *aggre2_clk;
	struct clk *gcc_im_sleep_clk;
	struct clk *aggre2_north_clk;
	struct clk *ssc_xo_clk;
	struct clk *ssc_ahbs_clk;
	struct reset_control *ssc_bcr;
	struct reset_control *ssc_reset;
	u32 ssc_axi_halt;
	int num_pds;
};

struct phy_configure_opts_dp {
	unsigned int link_rate;
	unsigned int lanes;
	unsigned int voltage[4];
	unsigned int pre[4];
	u8 ssc: 1;
	u8 set_rate: 1;
	u8 set_lanes: 1;
	u8 set_voltages: 1;
};

struct phy_configure_opts_lvds {
	unsigned int bits_per_lane_and_dclk_cycle;
	long unsigned int differential_clk_rate;
	unsigned int lanes;
	bool is_slave;
};

struct phy_configure_opts_mipi_dphy {
	unsigned int clk_miss;
	unsigned int clk_post;
	unsigned int clk_pre;
	unsigned int clk_prepare;
	unsigned int clk_settle;
	unsigned int clk_term_en;
	unsigned int clk_trail;
	unsigned int clk_zero;
	unsigned int d_term_en;
	unsigned int eot;
	unsigned int hs_exit;
	unsigned int hs_prepare;
	unsigned int hs_settle;
	unsigned int hs_skip;
	unsigned int hs_trail;
	unsigned int hs_zero;
	unsigned int init;
	unsigned int lpx;
	unsigned int ta_get;
	unsigned int ta_go;
	unsigned int ta_sure;
	unsigned int wakeup;
	long unsigned int hs_clk_rate;
	long unsigned int lp_clk_rate;
	unsigned char lanes;
};

enum phy_mode {
	PHY_MODE_INVALID = 0,
	PHY_MODE_USB_HOST = 1,
	PHY_MODE_USB_HOST_LS = 2,
	PHY_MODE_USB_HOST_FS = 3,
	PHY_MODE_USB_HOST_HS = 4,
	PHY_MODE_USB_HOST_SS = 5,
	PHY_MODE_USB_DEVICE = 6,
	PHY_MODE_USB_DEVICE_LS = 7,
	PHY_MODE_USB_DEVICE_FS = 8,
	PHY_MODE_USB_DEVICE_HS = 9,
	PHY_MODE_USB_DEVICE_SS = 10,
	PHY_MODE_USB_OTG = 11,
	PHY_MODE_UFS_HS_A = 12,
	PHY_MODE_UFS_HS_B = 13,
	PHY_MODE_PCIE = 14,
	PHY_MODE_ETHERNET = 15,
	PHY_MODE_MIPI_DPHY = 16,
	PHY_MODE_SATA = 17,
	PHY_MODE_LVDS = 18,
	PHY_MODE_DP = 19,
};

enum phy_media {
	PHY_MEDIA_DEFAULT = 0,
	PHY_MEDIA_SR = 1,
	PHY_MEDIA_DAC = 2,
};

union phy_configure_opts {
	struct phy_configure_opts_mipi_dphy mipi_dphy;
	struct phy_configure_opts_dp dp;
	struct phy_configure_opts_lvds lvds;
};

struct phy;

struct phy_ops {
	int (*init)(struct phy *);
	int (*exit)(struct phy *);
	int (*power_on)(struct phy *);
	int (*power_off)(struct phy *);
	int (*set_mode)(struct phy *, enum phy_mode, int);
	int (*set_media)(struct phy *, enum phy_media);
	int (*set_speed)(struct phy *, int);
	int (*configure)(struct phy *, union phy_configure_opts *);
	int (*validate)(struct phy *, enum phy_mode, int, union phy_configure_opts *);
	int (*reset)(struct phy *);
	int (*calibrate)(struct phy *);
	void (*release)(struct phy *);
	struct module *owner;
};

struct phy_attrs {
	u32 bus_width;
	u32 max_link_rate;
	enum phy_mode mode;
};

struct regulator;

struct phy {
	struct device dev;
	int id;
	const struct phy_ops *ops;
	struct mutex mutex;
	int init_count;
	int power_count;
	struct phy_attrs attrs;
	struct regulator *pwr;
};

struct phy_provider {
	struct device *dev;
	struct device_node *children;
	struct module *owner;
	struct list_head list;
	struct phy * (*of_xlate)(struct device *, struct of_phandle_args *);
};

struct phy_axg_mipi_pcie_analog_priv {
	struct phy *phy;
	struct regmap *regmap;
	bool dsi_configured;
	bool dsi_enabled;
	bool powered;
	struct phy_configure_opts_mipi_dphy config;
};

struct tegra_p2u_of_data {
	bool one_dir_search;
};

struct tegra_p2u {
	void *base;
	bool skip_sz_protection_en;
	struct tegra_p2u_of_data *of_data;
};

struct pinctrl;

struct pinctrl_state;

struct dev_pin_info {
	struct pinctrl *p;
	struct pinctrl_state *default_state;
	struct pinctrl_state *init_state;
	struct pinctrl_state *sleep_state;
	struct pinctrl_state *idle_state;
};

struct pinctrl {
	struct list_head node;
	struct device *dev;
	struct list_head states;
	struct pinctrl_state *state;
	struct list_head dt_maps;
	struct kref users;
};

struct pinctrl_state {
	struct list_head node;
	const char *name;
	struct list_head settings;
};

struct pinctrl_pin_desc {
	unsigned int number;
	const char *name;
	void *drv_data;
};

struct gpio_chip;

struct pinctrl_gpio_range {
	struct list_head node;
	const char *name;
	unsigned int id;
	unsigned int base;
	unsigned int pin_base;
	unsigned int npins;
	const unsigned int *pins;
	struct gpio_chip *gc;
};

union gpio_irq_fwspec;

struct gpio_irq_chip {
	struct irq_chip *chip;
	struct irq_domain *domain;
	const struct irq_domain_ops *domain_ops;
	struct fwnode_handle *fwnode;
	struct irq_domain *parent_domain;
	int (*child_to_parent_hwirq)(struct gpio_chip *, unsigned int, unsigned int, unsigned int *, unsigned int *);
	int (*populate_parent_alloc_arg)(struct gpio_chip *, union gpio_irq_fwspec *, unsigned int, unsigned int);
	unsigned int (*child_offset_to_irq)(struct gpio_chip *, unsigned int);
	struct irq_domain_ops child_irq_domain_ops;
	irq_flow_handler_t handler;
	unsigned int default_type;
	struct lock_class_key *lock_key;
	struct lock_class_key *request_key;
	irq_flow_handler_t parent_handler;
	union {
		void *parent_handler_data;
		void **parent_handler_data_array;
	};
	unsigned int num_parents;
	unsigned int *parents;
	unsigned int *map;
	bool threaded;
	bool per_parent_data;
	bool initialized;
	int (*init_hw)(struct gpio_chip *);
	void (*init_valid_mask)(struct gpio_chip *, long unsigned int *, unsigned int);
	long unsigned int *valid_mask;
	unsigned int first;
	void (*irq_enable)(struct irq_data *);
	void (*irq_disable)(struct irq_data *);
	void (*irq_unmask)(struct irq_data *);
	void (*irq_mask)(struct irq_data *);
};

struct gpio_device;

struct gpio_chip {
	const char *label;
	struct gpio_device *gpiodev;
	struct device *parent;
	struct fwnode_handle *fwnode;
	struct module *owner;
	int (*request)(struct gpio_chip *, unsigned int);
	void (*free)(struct gpio_chip *, unsigned int);
	int (*get_direction)(struct gpio_chip *, unsigned int);
	int (*direction_input)(struct gpio_chip *, unsigned int);
	int (*direction_output)(struct gpio_chip *, unsigned int, int);
	int (*get)(struct gpio_chip *, unsigned int);
	int (*get_multiple)(struct gpio_chip *, long unsigned int *, long unsigned int *);
	void (*set)(struct gpio_chip *, unsigned int, int);
	void (*set_multiple)(struct gpio_chip *, long unsigned int *, long unsigned int *);
	int (*set_config)(struct gpio_chip *, unsigned int, long unsigned int);
	int (*to_irq)(struct gpio_chip *, unsigned int);
	void (*dbg_show)(struct seq_file *, struct gpio_chip *);
	int (*init_valid_mask)(struct gpio_chip *, long unsigned int *, unsigned int);
	int (*add_pin_ranges)(struct gpio_chip *);
	int (*en_hw_timestamp)(struct gpio_chip *, u32, long unsigned int);
	int (*dis_hw_timestamp)(struct gpio_chip *, u32, long unsigned int);
	int base;
	u16 ngpio;
	u16 offset;
	const char * const *names;
	bool can_sleep;
	long unsigned int (*read_reg)(void *);
	void (*write_reg)(void *, long unsigned int);
	bool be_bits;
	void *reg_dat;
	void *reg_set;
	void *reg_clr;
	void *reg_dir_out;
	void *reg_dir_in;
	bool bgpio_dir_unreadable;
	int bgpio_bits;
	raw_spinlock_t bgpio_lock;
	long unsigned int bgpio_data;
	long unsigned int bgpio_dir;
	struct gpio_irq_chip irq;
	long unsigned int *valid_mask;
	struct device_node *of_node;
	unsigned int of_gpio_n_cells;
	int (*of_xlate)(struct gpio_chip *, const struct of_phandle_args *, u32 *);
	int (*of_gpio_ranges_fallback)(struct gpio_chip *, struct device_node *);
};

struct pinctrl_dev;

struct pinctrl_map;

struct pinctrl_ops {
	int (*get_groups_count)(struct pinctrl_dev *);
	const char * (*get_group_name)(struct pinctrl_dev *, unsigned int);
	int (*get_group_pins)(struct pinctrl_dev *, unsigned int, const unsigned int **, unsigned int *);
	void (*pin_dbg_show)(struct pinctrl_dev *, struct seq_file *, unsigned int);
	int (*dt_node_to_map)(struct pinctrl_dev *, struct device_node *, struct pinctrl_map **, unsigned int *);
	void (*dt_free_map)(struct pinctrl_dev *, struct pinctrl_map *, unsigned int);
};

struct pinctrl_desc;

struct pinctrl_dev {
	struct list_head node;
	struct pinctrl_desc *desc;
	struct xarray pin_desc_tree;
	struct xarray pin_group_tree;
	unsigned int num_groups;
	struct xarray pin_function_tree;
	unsigned int num_functions;
	struct list_head gpio_ranges;
	struct device *dev;
	struct module *owner;
	void *driver_data;
	struct pinctrl *p;
	struct pinctrl_state *hog_default;
	struct pinctrl_state *hog_sleep;
	struct mutex mutex;
	struct dentry *device_root;
};

enum pinctrl_map_type {
	PIN_MAP_TYPE_INVALID = 0,
	PIN_MAP_TYPE_DUMMY_STATE = 1,
	PIN_MAP_TYPE_MUX_GROUP = 2,
	PIN_MAP_TYPE_CONFIGS_PIN = 3,
	PIN_MAP_TYPE_CONFIGS_GROUP = 4,
};

struct pinctrl_map_mux {
	const char *group;
	const char *function;
};

struct pinctrl_map_configs {
	const char *group_or_pin;
	long unsigned int *configs;
	unsigned int num_configs;
};

struct pinctrl_map {
	const char *dev_name;
	const char *name;
	enum pinctrl_map_type type;
	const char *ctrl_dev_name;
	union {
		struct pinctrl_map_mux mux;
		struct pinctrl_map_configs configs;
	} data;
};

struct pinmux_ops;

struct pinconf_ops;

struct pinconf_generic_params;

struct pin_config_item;

struct pinctrl_desc {
	const char *name;
	const struct pinctrl_pin_desc *pins;
	unsigned int npins;
	const struct pinctrl_ops *pctlops;
	const struct pinmux_ops *pmxops;
	const struct pinconf_ops *confops;
	struct module *owner;
	unsigned int num_custom_params;
	const struct pinconf_generic_params *custom_params;
	const struct pin_config_item *custom_conf_items;
	bool link_consumers;
};

struct pinmux_ops {
	int (*request)(struct pinctrl_dev *, unsigned int);
	int (*free)(struct pinctrl_dev *, unsigned int);
	int (*get_functions_count)(struct pinctrl_dev *);
	const char * (*get_function_name)(struct pinctrl_dev *, unsigned int);
	int (*get_function_groups)(struct pinctrl_dev *, unsigned int, const char * const **, unsigned int *);
	int (*set_mux)(struct pinctrl_dev *, unsigned int, unsigned int);
	int (*gpio_request_enable)(struct pinctrl_dev *, struct pinctrl_gpio_range *, unsigned int);
	void (*gpio_disable_free)(struct pinctrl_dev *, struct pinctrl_gpio_range *, unsigned int);
	int (*gpio_set_direction)(struct pinctrl_dev *, struct pinctrl_gpio_range *, unsigned int, bool);
	bool strict;
};

struct pinconf_ops {
	bool is_generic;
	int (*pin_config_get)(struct pinctrl_dev *, unsigned int, long unsigned int *);
	int (*pin_config_set)(struct pinctrl_dev *, unsigned int, long unsigned int *, unsigned int);
	int (*pin_config_group_get)(struct pinctrl_dev *, unsigned int, long unsigned int *);
	int (*pin_config_group_set)(struct pinctrl_dev *, unsigned int, long unsigned int *, unsigned int);
	void (*pin_config_dbg_show)(struct pinctrl_dev *, struct seq_file *, unsigned int);
	void (*pin_config_group_dbg_show)(struct pinctrl_dev *, struct seq_file *, unsigned int);
	void (*pin_config_config_dbg_show)(struct pinctrl_dev *, struct seq_file *, long unsigned int);
};

enum pin_config_param {
	PIN_CONFIG_BIAS_BUS_HOLD = 0,
	PIN_CONFIG_BIAS_DISABLE = 1,
	PIN_CONFIG_BIAS_HIGH_IMPEDANCE = 2,
	PIN_CONFIG_BIAS_PULL_DOWN = 3,
	PIN_CONFIG_BIAS_PULL_PIN_DEFAULT = 4,
	PIN_CONFIG_BIAS_PULL_UP = 5,
	PIN_CONFIG_DRIVE_OPEN_DRAIN = 6,
	PIN_CONFIG_DRIVE_OPEN_SOURCE = 7,
	PIN_CONFIG_DRIVE_PUSH_PULL = 8,
	PIN_CONFIG_DRIVE_STRENGTH = 9,
	PIN_CONFIG_DRIVE_STRENGTH_UA = 10,
	PIN_CONFIG_INPUT_DEBOUNCE = 11,
	PIN_CONFIG_INPUT_ENABLE = 12,
	PIN_CONFIG_INPUT_SCHMITT = 13,
	PIN_CONFIG_INPUT_SCHMITT_ENABLE = 14,
	PIN_CONFIG_MODE_LOW_POWER = 15,
	PIN_CONFIG_MODE_PWM = 16,
	PIN_CONFIG_OUTPUT = 17,
	PIN_CONFIG_OUTPUT_ENABLE = 18,
	PIN_CONFIG_OUTPUT_IMPEDANCE_OHMS = 19,
	PIN_CONFIG_PERSIST_STATE = 20,
	PIN_CONFIG_POWER_SOURCE = 21,
	PIN_CONFIG_SKEW_DELAY = 22,
	PIN_CONFIG_SLEEP_HARDWARE_STATE = 23,
	PIN_CONFIG_SLEW_RATE = 24,
	PIN_CONFIG_END = 127,
	PIN_CONFIG_MAX = 255,
};

struct pinconf_generic_params {
	const char * const property;
	enum pin_config_param param;
	u32 default_value;
};

struct pin_config_item {
	const enum pin_config_param param;
	const char * const display;
	const char * const format;
	bool has_arg;
};

union gpio_irq_fwspec {
	struct irq_fwspec fwspec;
	msi_alloc_info_t msiinfo;
};

enum regcache_type {
	REGCACHE_NONE = 0,
	REGCACHE_RBTREE = 1,
	REGCACHE_COMPRESSED = 2,
	REGCACHE_FLAT = 3,
};

struct reg_default {
	unsigned int reg;
	unsigned int def;
};

enum regmap_endian {
	REGMAP_ENDIAN_DEFAULT = 0,
	REGMAP_ENDIAN_BIG = 1,
	REGMAP_ENDIAN_LITTLE = 2,
	REGMAP_ENDIAN_NATIVE = 3,
};

struct regmap_range {
	unsigned int range_min;
	unsigned int range_max;
};

struct regmap_access_table {
	const struct regmap_range *yes_ranges;
	unsigned int n_yes_ranges;
	const struct regmap_range *no_ranges;
	unsigned int n_no_ranges;
};

typedef void (*regmap_lock)(void *);

typedef void (*regmap_unlock)(void *);

struct regmap_range_cfg;

struct regmap_config {
	const char *name;
	int reg_bits;
	int reg_stride;
	int reg_downshift;
	unsigned int reg_base;
	int pad_bits;
	int val_bits;
	bool (*writeable_reg)(struct device *, unsigned int);
	bool (*readable_reg)(struct device *, unsigned int);
	bool (*volatile_reg)(struct device *, unsigned int);
	bool (*precious_reg)(struct device *, unsigned int);
	bool (*writeable_noinc_reg)(struct device *, unsigned int);
	bool (*readable_noinc_reg)(struct device *, unsigned int);
	bool disable_locking;
	regmap_lock lock;
	regmap_unlock unlock;
	void *lock_arg;
	int (*reg_read)(void *, unsigned int, unsigned int *);
	int (*reg_write)(void *, unsigned int, unsigned int);
	int (*reg_update_bits)(void *, unsigned int, unsigned int, unsigned int);
	int (*read)(void *, const void *, size_t, void *, size_t);
	int (*write)(void *, const void *, size_t);
	size_t max_raw_read;
	size_t max_raw_write;
	bool fast_io;
	unsigned int max_register;
	const struct regmap_access_table *wr_table;
	const struct regmap_access_table *rd_table;
	const struct regmap_access_table *volatile_table;
	const struct regmap_access_table *precious_table;
	const struct regmap_access_table *wr_noinc_table;
	const struct regmap_access_table *rd_noinc_table;
	const struct reg_default *reg_defaults;
	unsigned int num_reg_defaults;
	enum regcache_type cache_type;
	const void *reg_defaults_raw;
	unsigned int num_reg_defaults_raw;
	long unsigned int read_flag_mask;
	long unsigned int write_flag_mask;
	bool zero_flag_mask;
	bool use_single_read;
	bool use_single_write;
	bool use_relaxed_mmio;
	bool can_multi_write;
	enum regmap_endian reg_format_endian;
	enum regmap_endian val_format_endian;
	const struct regmap_range_cfg *ranges;
	unsigned int num_ranges;
	bool use_hwlock;
	bool use_raw_spinlock;
	unsigned int hwlock_id;
	unsigned int hwlock_mode;
	bool can_sleep;
};

struct regmap_range_cfg {
	const char *name;
	unsigned int range_min;
	unsigned int range_max;
	unsigned int selector_reg;
	unsigned int selector_mask;
	int selector_shift;
	unsigned int window_start;
	unsigned int window_len;
};

enum rockchip_pinctrl_type {
	PX30 = 0,
	RV1108 = 1,
	RK2928 = 2,
	RK3066B = 3,
	RK3128 = 4,
	RK3188 = 5,
	RK3288 = 6,
	RK3308 = 7,
	RK3368 = 8,
	RK3399 = 9,
	RK3568 = 10,
	RK3588 = 11,
};

struct rockchip_gpio_regs {
	u32 port_dr;
	u32 port_ddr;
	u32 int_en;
	u32 int_mask;
	u32 int_type;
	u32 int_polarity;
	u32 int_bothedge;
	u32 int_status;
	u32 int_rawstatus;
	u32 debounce;
	u32 dbclk_div_en;
	u32 dbclk_div_con;
	u32 port_eoi;
	u32 ext_port;
	u32 version_id;
};

struct rockchip_iomux {
	int type;
	int offset;
};

enum rockchip_pin_drv_type {
	DRV_TYPE_IO_DEFAULT = 0,
	DRV_TYPE_IO_1V8_OR_3V0 = 1,
	DRV_TYPE_IO_1V8_ONLY = 2,
	DRV_TYPE_IO_1V8_3V0_AUTO = 3,
	DRV_TYPE_IO_3V3_ONLY = 4,
	DRV_TYPE_MAX = 5,
};

enum rockchip_pin_pull_type {
	PULL_TYPE_IO_DEFAULT = 0,
	PULL_TYPE_IO_1V8_ONLY = 1,
	PULL_TYPE_MAX = 2,
};

struct rockchip_drv {
	enum rockchip_pin_drv_type drv_type;
	int offset;
};

struct rockchip_pinctrl;

struct rockchip_pin_bank {
	struct device *dev;
	void *reg_base;
	struct regmap *regmap_pull;
	struct clk *clk;
	struct clk *db_clk;
	int irq;
	u32 saved_masks;
	u32 pin_base;
	u8 nr_pins;
	char *name;
	u8 bank_num;
	struct rockchip_iomux iomux[4];
	struct rockchip_drv drv[4];
	enum rockchip_pin_pull_type pull_type[4];
	bool valid;
	struct device_node *of_node;
	struct rockchip_pinctrl *drvdata;
	struct irq_domain *domain;
	struct gpio_chip gpio_chip;
	struct pinctrl_gpio_range grange;
	raw_spinlock_t slock;
	const struct rockchip_gpio_regs *gpio_regs;
	u32 gpio_type;
	u32 toggle_edge_mode;
	u32 recalced_mask;
	u32 route_mask;
	struct list_head deferred_pins;
	struct mutex deferred_lock;
};

struct rockchip_pin_ctrl;

struct rockchip_pin_group;

struct rockchip_pmx_func;

struct rockchip_pinctrl {
	struct regmap *regmap_base;
	int reg_size;
	struct regmap *regmap_pull;
	struct regmap *regmap_pmu;
	struct device *dev;
	struct rockchip_pin_ctrl *ctrl;
	struct pinctrl_desc pctl;
	struct pinctrl_dev *pctl_dev;
	struct rockchip_pin_group *groups;
	unsigned int ngroups;
	struct rockchip_pmx_func *functions;
	unsigned int nfunctions;
};

struct rockchip_mux_recalced_data {
	u8 num;
	u8 pin;
	u32 reg;
	u8 bit;
	u8 mask;
};

enum rockchip_mux_route_location {
	ROCKCHIP_ROUTE_SAME = 0,
	ROCKCHIP_ROUTE_PMU = 1,
	ROCKCHIP_ROUTE_GRF = 2,
};

struct rockchip_mux_route_data {
	u8 bank_num;
	u8 pin;
	u8 func;
	enum rockchip_mux_route_location route_location;
	u32 route_offset;
	u32 route_val;
};

struct rockchip_pin_ctrl {
	struct rockchip_pin_bank *pin_banks;
	u32 nr_banks;
	u32 nr_pins;
	char *label;
	enum rockchip_pinctrl_type type;
	int grf_mux_offset;
	int pmu_mux_offset;
	int grf_drv_offset;
	int pmu_drv_offset;
	struct rockchip_mux_recalced_data *iomux_recalced;
	u32 niomux_recalced;
	struct rockchip_mux_route_data *iomux_routes;
	u32 niomux_routes;
	int (*pull_calc_reg)(struct rockchip_pin_bank *, int, struct regmap **, int *, u8 *);
	int (*drv_calc_reg)(struct rockchip_pin_bank *, int, struct regmap **, int *, u8 *);
	int (*schmitt_calc_reg)(struct rockchip_pin_bank *, int, struct regmap **, int *, u8 *);
};

struct rockchip_pin_config {
	unsigned int func;
	long unsigned int *configs;
	unsigned int nconfigs;
};

struct rockchip_pin_deferred {
	struct list_head head;
	unsigned int pin;
	enum pin_config_param param;
	u32 arg;
};

struct rockchip_pin_group {
	const char *name;
	unsigned int npins;
	unsigned int *pins;
	struct rockchip_pin_config *data;
};

struct rockchip_pmx_func {
	const char *name;
	const char **groups;
	u8 ngroups;
};

struct imx_pin_mmio {
	unsigned int mux_mode;
	u16 input_reg;
	unsigned int input_val;
	long unsigned int config;
};

struct imx_pin_scu {
	unsigned int mux_mode;
	long unsigned int config;
};

struct imx_pin {
	unsigned int pin;
	union {
		struct imx_pin_mmio mmio;
		struct imx_pin_scu scu;
	} conf;
};

struct imx_pin_reg {
	s16 mux_reg;
	s16 conf_reg;
};

struct imx_cfg_params_decode {
	enum pin_config_param param;
	u32 mask;
	u8 shift;
	bool invert;
};

struct imx_pinctrl_soc_info;

struct imx_pinctrl {
	struct device *dev;
	struct pinctrl_dev *pctl;
	void *base;
	void *input_sel_base;
	const struct imx_pinctrl_soc_info *info;
	struct imx_pin_reg *pin_regs;
	unsigned int group_index;
	struct mutex mutex;
};

struct imx_pinctrl_soc_info {
	const struct pinctrl_pin_desc *pins;
	unsigned int npins;
	unsigned int flags;
	const char *gpr_compatible;
	unsigned int mux_mask;
	u8 mux_shift;
	bool generic_pinconf;
	const struct pinconf_generic_params *custom_params;
	unsigned int num_custom_params;
	const struct imx_cfg_params_decode *decodes;
	unsigned int num_decodes;
	void (*fixup)(long unsigned int *, unsigned int, u32 *);
	int (*gpio_set_direction)(struct pinctrl_dev *, struct pinctrl_gpio_range *, unsigned int, bool);
	int (*imx_pinconf_get)(struct pinctrl_dev *, unsigned int, long unsigned int *);
	int (*imx_pinconf_set)(struct pinctrl_dev *, unsigned int, long unsigned int *, unsigned int);
	void (*imx_pinctrl_parse_pin)(struct imx_pinctrl *, unsigned int *, struct imx_pin *, const __be32 **);
};

enum imx8mn_pads {
	MX8MN_PAD_RESERVE0 = 0,
	MX8MN_PAD_RESERVE1 = 1,
	MX8MN_PAD_RESERVE2 = 2,
	MX8MN_PAD_RESERVE3 = 3,
	MX8MN_PAD_RESERVE4 = 4,
	MX8MN_PAD_RESERVE5 = 5,
	MX8MN_PAD_RESERVE6 = 6,
	MX8MN_PAD_RESERVE7 = 7,
	MX8MN_IOMUXC_BOOT_MODE2 = 8,
	MX8MN_IOMUXC_BOOT_MODE3 = 9,
	MX8MN_IOMUXC_GPIO1_IO00 = 10,
	MX8MN_IOMUXC_GPIO1_IO01 = 11,
	MX8MN_IOMUXC_GPIO1_IO02 = 12,
	MX8MN_IOMUXC_GPIO1_IO03 = 13,
	MX8MN_IOMUXC_GPIO1_IO04 = 14,
	MX8MN_IOMUXC_GPIO1_IO05 = 15,
	MX8MN_IOMUXC_GPIO1_IO06 = 16,
	MX8MN_IOMUXC_GPIO1_IO07 = 17,
	MX8MN_IOMUXC_GPIO1_IO08 = 18,
	MX8MN_IOMUXC_GPIO1_IO09 = 19,
	MX8MN_IOMUXC_GPIO1_IO10 = 20,
	MX8MN_IOMUXC_GPIO1_IO11 = 21,
	MX8MN_IOMUXC_GPIO1_IO12 = 22,
	MX8MN_IOMUXC_GPIO1_IO13 = 23,
	MX8MN_IOMUXC_GPIO1_IO14 = 24,
	MX8MN_IOMUXC_GPIO1_IO15 = 25,
	MX8MN_IOMUXC_ENET_MDC = 26,
	MX8MN_IOMUXC_ENET_MDIO = 27,
	MX8MN_IOMUXC_ENET_TD3 = 28,
	MX8MN_IOMUXC_ENET_TD2 = 29,
	MX8MN_IOMUXC_ENET_TD1 = 30,
	MX8MN_IOMUXC_ENET_TD0 = 31,
	MX8MN_IOMUXC_ENET_TX_CTL = 32,
	MX8MN_IOMUXC_ENET_TXC = 33,
	MX8MN_IOMUXC_ENET_RX_CTL = 34,
	MX8MN_IOMUXC_ENET_RXC = 35,
	MX8MN_IOMUXC_ENET_RD0 = 36,
	MX8MN_IOMUXC_ENET_RD1 = 37,
	MX8MN_IOMUXC_ENET_RD2 = 38,
	MX8MN_IOMUXC_ENET_RD3 = 39,
	MX8MN_IOMUXC_SD1_CLK = 40,
	MX8MN_IOMUXC_SD1_CMD = 41,
	MX8MN_IOMUXC_SD1_DATA0 = 42,
	MX8MN_IOMUXC_SD1_DATA1 = 43,
	MX8MN_IOMUXC_SD1_DATA2 = 44,
	MX8MN_IOMUXC_SD1_DATA3 = 45,
	MX8MN_IOMUXC_SD1_DATA4 = 46,
	MX8MN_IOMUXC_SD1_DATA5 = 47,
	MX8MN_IOMUXC_SD1_DATA6 = 48,
	MX8MN_IOMUXC_SD1_DATA7 = 49,
	MX8MN_IOMUXC_SD1_RESET_B = 50,
	MX8MN_IOMUXC_SD1_STROBE = 51,
	MX8MN_IOMUXC_SD2_CD_B = 52,
	MX8MN_IOMUXC_SD2_CLK = 53,
	MX8MN_IOMUXC_SD2_CMD = 54,
	MX8MN_IOMUXC_SD2_DATA0 = 55,
	MX8MN_IOMUXC_SD2_DATA1 = 56,
	MX8MN_IOMUXC_SD2_DATA2 = 57,
	MX8MN_IOMUXC_SD2_DATA3 = 58,
	MX8MN_IOMUXC_SD2_RESET_B = 59,
	MX8MN_IOMUXC_SD2_WP = 60,
	MX8MN_IOMUXC_NAND_ALE = 61,
	MX8MN_IOMUXC_NAND_CE0 = 62,
	MX8MN_IOMUXC_NAND_CE1 = 63,
	MX8MN_IOMUXC_NAND_CE2 = 64,
	MX8MN_IOMUXC_NAND_CE3 = 65,
	MX8MN_IOMUXC_NAND_CLE = 66,
	MX8MN_IOMUXC_NAND_DATA00 = 67,
	MX8MN_IOMUXC_NAND_DATA01 = 68,
	MX8MN_IOMUXC_NAND_DATA02 = 69,
	MX8MN_IOMUXC_NAND_DATA03 = 70,
	MX8MN_IOMUXC_NAND_DATA04 = 71,
	MX8MN_IOMUXC_NAND_DATA05 = 72,
	MX8MN_IOMUXC_NAND_DATA06 = 73,
	MX8MN_IOMUXC_NAND_DATA07 = 74,
	MX8MN_IOMUXC_NAND_DQS = 75,
	MX8MN_IOMUXC_NAND_RE_B = 76,
	MX8MN_IOMUXC_NAND_READY_B = 77,
	MX8MN_IOMUXC_NAND_WE_B = 78,
	MX8MN_IOMUXC_NAND_WP_B = 79,
	MX8MN_IOMUXC_SAI5_RXFS = 80,
	MX8MN_IOMUXC_SAI5_RXC = 81,
	MX8MN_IOMUXC_SAI5_RXD0 = 82,
	MX8MN_IOMUXC_SAI5_RXD1 = 83,
	MX8MN_IOMUXC_SAI5_RXD2 = 84,
	MX8MN_IOMUXC_SAI5_RXD3 = 85,
	MX8MN_IOMUXC_SAI5_MCLK = 86,
	MX8MN_IOMUXC_SAI1_RXFS = 87,
	MX8MN_IOMUXC_SAI1_RXC = 88,
	MX8MN_IOMUXC_SAI1_RXD0 = 89,
	MX8MN_IOMUXC_SAI1_RXD1 = 90,
	MX8MN_IOMUXC_SAI1_RXD2 = 91,
	MX8MN_IOMUXC_SAI1_RXD3 = 92,
	MX8MN_IOMUXC_SAI1_RXD4 = 93,
	MX8MN_IOMUXC_SAI1_RXD5 = 94,
	MX8MN_IOMUXC_SAI1_RXD6 = 95,
	MX8MN_IOMUXC_SAI1_RXD7 = 96,
	MX8MN_IOMUXC_SAI1_TXFS = 97,
	MX8MN_IOMUXC_SAI1_TXC = 98,
	MX8MN_IOMUXC_SAI1_TXD0 = 99,
	MX8MN_IOMUXC_SAI1_TXD1 = 100,
	MX8MN_IOMUXC_SAI1_TXD2 = 101,
	MX8MN_IOMUXC_SAI1_TXD3 = 102,
	MX8MN_IOMUXC_SAI1_TXD4 = 103,
	MX8MN_IOMUXC_SAI1_TXD5 = 104,
	MX8MN_IOMUXC_SAI1_TXD6 = 105,
	MX8MN_IOMUXC_SAI1_TXD7 = 106,
	MX8MN_IOMUXC_SAI1_MCLK = 107,
	MX8MN_IOMUXC_SAI2_RXFS = 108,
	MX8MN_IOMUXC_SAI2_RXC = 109,
	MX8MN_IOMUXC_SAI2_RXD0 = 110,
	MX8MN_IOMUXC_SAI2_TXFS = 111,
	MX8MN_IOMUXC_SAI2_TXC = 112,
	MX8MN_IOMUXC_SAI2_TXD0 = 113,
	MX8MN_IOMUXC_SAI2_MCLK = 114,
	MX8MN_IOMUXC_SAI3_RXFS = 115,
	MX8MN_IOMUXC_SAI3_RXC = 116,
	MX8MN_IOMUXC_SAI3_RXD = 117,
	MX8MN_IOMUXC_SAI3_TXFS = 118,
	MX8MN_IOMUXC_SAI3_TXC = 119,
	MX8MN_IOMUXC_SAI3_TXD = 120,
	MX8MN_IOMUXC_SAI3_MCLK = 121,
	MX8MN_IOMUXC_SPDIF_TX = 122,
	MX8MN_IOMUXC_SPDIF_RX = 123,
	MX8MN_IOMUXC_SPDIF_EXT_CLK = 124,
	MX8MN_IOMUXC_ECSPI1_SCLK = 125,
	MX8MN_IOMUXC_ECSPI1_MOSI = 126,
	MX8MN_IOMUXC_ECSPI1_MISO = 127,
	MX8MN_IOMUXC_ECSPI1_SS0 = 128,
	MX8MN_IOMUXC_ECSPI2_SCLK = 129,
	MX8MN_IOMUXC_ECSPI2_MOSI = 130,
	MX8MN_IOMUXC_ECSPI2_MISO = 131,
	MX8MN_IOMUXC_ECSPI2_SS0 = 132,
	MX8MN_IOMUXC_I2C1_SCL = 133,
	MX8MN_IOMUXC_I2C1_SDA = 134,
	MX8MN_IOMUXC_I2C2_SCL = 135,
	MX8MN_IOMUXC_I2C2_SDA = 136,
	MX8MN_IOMUXC_I2C3_SCL = 137,
	MX8MN_IOMUXC_I2C3_SDA = 138,
	MX8MN_IOMUXC_I2C4_SCL = 139,
	MX8MN_IOMUXC_I2C4_SDA = 140,
	MX8MN_IOMUXC_UART1_RXD = 141,
	MX8MN_IOMUXC_UART1_TXD = 142,
	MX8MN_IOMUXC_UART2_RXD = 143,
	MX8MN_IOMUXC_UART2_TXD = 144,
	MX8MN_IOMUXC_UART3_RXD = 145,
	MX8MN_IOMUXC_UART3_TXD = 146,
	MX8MN_IOMUXC_UART4_RXD = 147,
	MX8MN_IOMUXC_UART4_TXD = 148,
};

struct meson_pmx_group {
	const char *name;
	const unsigned int *pins;
	unsigned int num_pins;
	const void *data;
};

struct meson_pmx_func {
	const char *name;
	const char * const *groups;
	unsigned int num_groups;
};

struct meson_reg_desc {
	unsigned int reg;
	unsigned int bit;
};

enum meson_reg_type {
	MESON_REG_PULLEN = 0,
	MESON_REG_PULL = 1,
	MESON_REG_DIR = 2,
	MESON_REG_OUT = 3,
	MESON_REG_IN = 4,
	MESON_REG_DS = 5,
	MESON_NUM_REG = 6,
};

struct meson_bank {
	const char *name;
	unsigned int first;
	unsigned int last;
	int irq_first;
	int irq_last;
	struct meson_reg_desc regs[6];
};

struct meson_pinctrl;

struct meson_pinctrl_data {
	const char *name;
	const struct pinctrl_pin_desc *pins;
	struct meson_pmx_group *groups;
	struct meson_pmx_func *funcs;
	unsigned int num_pins;
	unsigned int num_groups;
	unsigned int num_funcs;
	struct meson_bank *banks;
	unsigned int num_banks;
	const struct pinmux_ops *pmx_ops;
	void *pmx_data;
	int (*parse_dt)(struct meson_pinctrl *);
};

struct meson_pinctrl {
	struct device *dev;
	struct pinctrl_dev *pcdev;
	struct pinctrl_desc desc;
	struct meson_pinctrl_data *data;
	struct regmap *reg_mux;
	struct regmap *reg_pullen;
	struct regmap *reg_pull;
	struct regmap *reg_gpio;
	struct regmap *reg_ds;
	struct gpio_chip chip;
	struct device_node *of_node;
};

struct meson8_pmx_data {
	bool is_gpio;
	unsigned int reg;
	unsigned int bit;
};

struct mvebu_mpp_ctrl_data {
	union {
		void *base;
		struct {
			struct regmap *map;
			u32 offset;
		} regmap;
	};
};

struct mvebu_mpp_ctrl {
	const char *name;
	u8 pid;
	u8 npins;
	unsigned int *pins;
	int (*mpp_get)(struct mvebu_mpp_ctrl_data *, unsigned int, long unsigned int *);
	int (*mpp_set)(struct mvebu_mpp_ctrl_data *, unsigned int, long unsigned int);
	int (*mpp_gpio_req)(struct mvebu_mpp_ctrl_data *, unsigned int);
	int (*mpp_gpio_dir)(struct mvebu_mpp_ctrl_data *, unsigned int, bool);
};

struct mvebu_mpp_ctrl_setting {
	u8 val;
	const char *name;
	const char *subname;
	u8 variant;
	u8 flags;
};

struct mvebu_mpp_mode {
	u8 pid;
	struct mvebu_mpp_ctrl_setting *settings;
};

struct mvebu_pinctrl_soc_info {
	u8 variant;
	const struct mvebu_mpp_ctrl *controls;
	struct mvebu_mpp_ctrl_data *control_data;
	int ncontrols;
	struct mvebu_mpp_mode *modes;
	int nmodes;
	struct pinctrl_gpio_range *gpioranges;
	int ngpioranges;
};

enum {
	IRQ_DOMAIN_FLAG_HIERARCHY = 1,
	IRQ_DOMAIN_NAME_ALLOCATED = 2,
	IRQ_DOMAIN_FLAG_IPI_PER_CPU = 4,
	IRQ_DOMAIN_FLAG_IPI_SINGLE = 8,
	IRQ_DOMAIN_FLAG_MSI = 16,
	IRQ_DOMAIN_FLAG_MSI_REMAP = 32,
	IRQ_DOMAIN_MSI_NOMASK_QUIRK = 64,
	IRQ_DOMAIN_FLAG_NO_MAP = 128,
	IRQ_DOMAIN_FLAG_NONCORE = 65536,
};

struct msm_function {
	const char *name;
	const char * const *groups;
	unsigned int ngroups;
};

struct msm_pingroup {
	const char *name;
	const unsigned int *pins;
	unsigned int npins;
	unsigned int *funcs;
	unsigned int nfuncs;
	u32 ctl_reg;
	u32 io_reg;
	u32 intr_cfg_reg;
	u32 intr_status_reg;
	u32 intr_target_reg;
	unsigned int tile: 2;
	unsigned int mux_bit: 5;
	unsigned int pull_bit: 5;
	unsigned int drv_bit: 5;
	unsigned int od_bit: 5;
	unsigned int egpio_enable: 5;
	unsigned int egpio_present: 5;
	unsigned int oe_bit: 5;
	unsigned int in_bit: 5;
	unsigned int out_bit: 5;
	unsigned int intr_enable_bit: 5;
	unsigned int intr_status_bit: 5;
	unsigned int intr_ack_high: 1;
	unsigned int intr_target_bit: 5;
	char: 1;
	unsigned int intr_target_kpss_val: 5;
	unsigned int intr_raw_status_bit: 5;
	unsigned int intr_polarity_bit: 5;
	unsigned int intr_detection_bit: 5;
	unsigned int intr_detection_width: 5;
};

struct msm_gpio_wakeirq_map {
	unsigned int gpio;
	unsigned int wakeirq;
};

struct msm_pinctrl_soc_data {
	const struct pinctrl_pin_desc *pins;
	unsigned int npins;
	const struct msm_function *functions;
	unsigned int nfunctions;
	const struct msm_pingroup *groups;
	unsigned int ngroups;
	unsigned int ngpios;
	bool pull_no_keeper;
	const char * const *tiles;
	unsigned int ntiles;
	const int *reserved_gpios;
	const struct msm_gpio_wakeirq_map *wakeirq_map;
	unsigned int nwakeirq_map;
	bool wakeirq_dual_edge_errata;
	unsigned int gpio_func;
	unsigned int egpio_func;
};

struct msm_pinctrl {
	struct device *dev;
	struct pinctrl_dev *pctrl;
	struct gpio_chip chip;
	struct pinctrl_desc desc;
	struct notifier_block restart_nb;
	int irq;
	bool intr_target_use_scm;
	raw_spinlock_t lock;
	long unsigned int dual_edge_irqs[5];
	long unsigned int enabled_irqs[5];
	long unsigned int skip_wake_irqs[5];
	long unsigned int disabled_for_mux[5];
	long unsigned int ever_gpio[5];
	const struct msm_pinctrl_soc_data *soc;
	void *regs[4];
	u32 phys_base[4];
};

enum sunxi_desc_bias_voltage {
	BIAS_VOLTAGE_NONE = 0,
	BIAS_VOLTAGE_GRP_CONFIG = 1,
	BIAS_VOLTAGE_PIO_POW_MODE_SEL = 2,
	BIAS_VOLTAGE_PIO_POW_MODE_CTL = 3,
};

struct sunxi_desc_function {
	long unsigned int variant;
	const char *name;
	u8 muxval;
	u8 irqbank;
	u8 irqnum;
};

struct sunxi_desc_pin {
	struct pinctrl_pin_desc pin;
	long unsigned int variant;
	struct sunxi_desc_function *functions;
};

struct sunxi_pinctrl_desc {
	const struct sunxi_desc_pin *pins;
	int npins;
	unsigned int pin_base;
	unsigned int irq_banks;
	const unsigned int *irq_bank_map;
	bool irq_read_needs_mux;
	bool disable_strict_mode;
	enum sunxi_desc_bias_voltage io_bias_cfg_variant;
};

struct gpio_device {
	int id;
	struct device dev;
	struct cdev chrdev;
	struct device *mockdev;
	struct module *owner;
	struct gpio_chip *chip;
	struct gpio_desc *descs;
	int base;
	u16 ngpio;
	const char *label;
	void *data;
	struct list_head list;
	struct blocking_notifier_head notifier;
	struct list_head pin_ranges;
};

struct gpio_array;

struct gpio_descs {
	struct gpio_array *info;
	unsigned int ndescs;
	struct gpio_desc *desc[0];
};

struct gpio_array {
	struct gpio_desc **desc;
	unsigned int size;
	struct gpio_chip *chip;
	long unsigned int *get_mask;
	long unsigned int *set_mask;
	long unsigned int invert_mask[0];
};

struct gpio_desc {
	struct gpio_device *gdev;
	long unsigned int flags;
	const char *label;
	const char *name;
	struct device_node *hog;
	unsigned int debounce_period_us;
};

enum gpiod_flags {
	GPIOD_ASIS = 0,
	GPIOD_IN = 1,
	GPIOD_OUT_LOW = 3,
	GPIOD_OUT_HIGH = 7,
	GPIOD_OUT_LOW_OPEN_DRAIN = 11,
	GPIOD_OUT_HIGH_OPEN_DRAIN = 15,
};

struct devres;

struct bgpio_pdata {
	const char *label;
	int base;
	int ngpio;
};

struct i2c_device_id {
	char name[20];
	kernel_ulong_t driver_data;
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

enum dev_prop_type {
	DEV_PROP_U8 = 0,
	DEV_PROP_U16 = 1,
	DEV_PROP_U32 = 2,
	DEV_PROP_U64 = 3,
	DEV_PROP_STRING = 4,
	DEV_PROP_REF = 5,
};

struct property_entry;

struct software_node {
	const char *name;
	const struct software_node *parent;
	const struct property_entry *properties;
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

struct rt_mutex {
	struct rt_mutex_base rtmutex;
};

struct i2c_msg {
	__u16 addr;
	__u16 flags;
	__u16 len;
	__u8 *buf;
};

union i2c_smbus_data {
	__u8 byte;
	__u16 word;
	__u8 block[34];
};

enum i2c_slave_event {
	I2C_SLAVE_READ_REQUESTED = 0,
	I2C_SLAVE_WRITE_REQUESTED = 1,
	I2C_SLAVE_READ_PROCESSED = 2,
	I2C_SLAVE_WRITE_RECEIVED = 3,
	I2C_SLAVE_STOP = 4,
};

struct i2c_client;

typedef int (*i2c_slave_cb_t)(struct i2c_client *, enum i2c_slave_event, u8 *);

struct i2c_adapter;

struct i2c_client {
	short unsigned int flags;
	short unsigned int addr;
	char name[20];
	struct i2c_adapter *adapter;
	struct device dev;
	int init_irq;
	int irq;
	struct list_head detected;
	i2c_slave_cb_t slave_cb;
	void *devres_group_id;
};

enum i2c_alert_protocol {
	I2C_PROTOCOL_SMBUS_ALERT = 0,
	I2C_PROTOCOL_SMBUS_HOST_NOTIFY = 1,
};

struct i2c_board_info;

struct i2c_driver {
	unsigned int class;
	int (*probe)(struct i2c_client *, const struct i2c_device_id *);
	int (*remove)(struct i2c_client *);
	int (*probe_new)(struct i2c_client *);
	void (*shutdown)(struct i2c_client *);
	void (*alert)(struct i2c_client *, enum i2c_alert_protocol, unsigned int);
	int (*command)(struct i2c_client *, unsigned int, void *);
	struct device_driver driver;
	const struct i2c_device_id *id_table;
	int (*detect)(struct i2c_client *, struct i2c_board_info *);
	const short unsigned int *address_list;
	struct list_head clients;
	u32 flags;
};

struct i2c_board_info {
	char type[20];
	short unsigned int flags;
	short unsigned int addr;
	const char *dev_name;
	void *platform_data;
	struct device_node *of_node;
	struct fwnode_handle *fwnode;
	const struct software_node *swnode;
	const struct resource *resources;
	unsigned int num_resources;
	int irq;
};

struct i2c_algorithm;

struct i2c_lock_operations;

struct i2c_bus_recovery_info;

struct i2c_adapter_quirks;

struct i2c_adapter {
	struct module *owner;
	unsigned int class;
	const struct i2c_algorithm *algo;
	void *algo_data;
	const struct i2c_lock_operations *lock_ops;
	struct rt_mutex bus_lock;
	struct rt_mutex mux_lock;
	int timeout;
	int retries;
	struct device dev;
	long unsigned int locked_flags;
	int nr;
	char name[48];
	struct completion dev_released;
	struct mutex userspace_clients_lock;
	struct list_head userspace_clients;
	struct i2c_bus_recovery_info *bus_recovery_info;
	const struct i2c_adapter_quirks *quirks;
	struct irq_domain *host_notify_domain;
	struct regulator *bus_regulator;
};

struct i2c_algorithm {
	int (*master_xfer)(struct i2c_adapter *, struct i2c_msg *, int);
	int (*master_xfer_atomic)(struct i2c_adapter *, struct i2c_msg *, int);
	int (*smbus_xfer)(struct i2c_adapter *, u16, short unsigned int, char, u8, int, union i2c_smbus_data *);
	int (*smbus_xfer_atomic)(struct i2c_adapter *, u16, short unsigned int, char, u8, int, union i2c_smbus_data *);
	u32 (*functionality)(struct i2c_adapter *);
	int (*reg_slave)(struct i2c_client *);
	int (*unreg_slave)(struct i2c_client *);
};

struct i2c_lock_operations {
	void (*lock_bus)(struct i2c_adapter *, unsigned int);
	int (*trylock_bus)(struct i2c_adapter *, unsigned int);
	void (*unlock_bus)(struct i2c_adapter *, unsigned int);
};

struct i2c_bus_recovery_info {
	int (*recover_bus)(struct i2c_adapter *);
	int (*get_scl)(struct i2c_adapter *);
	void (*set_scl)(struct i2c_adapter *, int);
	int (*get_sda)(struct i2c_adapter *);
	void (*set_sda)(struct i2c_adapter *, int);
	int (*get_bus_free)(struct i2c_adapter *);
	void (*prepare_recovery)(struct i2c_adapter *);
	void (*unprepare_recovery)(struct i2c_adapter *);
	struct gpio_desc *scl_gpiod;
	struct gpio_desc *sda_gpiod;
	struct pinctrl *pinctrl;
	struct pinctrl_state *pins_default;
	struct pinctrl_state *pins_gpio;
};

struct i2c_adapter_quirks {
	u64 flags;
	int max_num_msgs;
	u16 max_write_len;
	u16 max_read_len;
	u16 max_comb_1st_msg_len;
	u16 max_comb_2nd_msg_len;
};

struct pca953x_platform_data {
	unsigned int gpio_base;
	u32 invert;
	int irq_base;
	void *context;
	int (*setup)(struct i2c_client *, unsigned int, unsigned int, void *);
	int (*teardown)(struct i2c_client *, unsigned int, unsigned int, void *);
	const char * const *names;
};

struct pca953x_reg_config {
	int direction;
	int output;
	int input;
	int invert;
};

struct pca953x_chip {
	unsigned int gpio_start;
	struct mutex i2c_lock;
	struct regmap *regmap;
	struct mutex irq_lock;
	long unsigned int irq_mask[1];
	long unsigned int irq_stat[1];
	long unsigned int irq_trig_raise[1];
	long unsigned int irq_trig_fall[1];
	atomic_t wakeup_path;
	struct i2c_client *client;
	struct gpio_chip gpio_chip;
	const char * const *names;
	long unsigned int driver_data;
	struct regulator *regulator;
	const struct pca953x_reg_config *regs;
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

enum pwm_polarity {
	PWM_POLARITY_NORMAL = 0,
	PWM_POLARITY_INVERSED = 1,
};

struct pwm_args {
	u64 period;
	enum pwm_polarity polarity;
};

enum {
	PWMF_REQUESTED = 1,
	PWMF_EXPORTED = 2,
};

struct pwm_state {
	u64 period;
	u64 duty_cycle;
	enum pwm_polarity polarity;
	bool enabled;
	bool usage_power;
};

struct pwm_chip;

struct pwm_device {
	const char *label;
	long unsigned int flags;
	unsigned int hwpwm;
	unsigned int pwm;
	struct pwm_chip *chip;
	void *chip_data;
	struct pwm_args args;
	struct pwm_state state;
	struct pwm_state last;
};

struct pwm_ops;

struct pwm_chip {
	struct device *dev;
	const struct pwm_ops *ops;
	int base;
	unsigned int npwm;
	struct pwm_device * (*of_xlate)(struct pwm_chip *, const struct of_phandle_args *);
	unsigned int of_pwm_n_cells;
	struct list_head list;
	struct pwm_device *pwms;
};

struct pwm_capture {
	unsigned int period;
	unsigned int duty_cycle;
};

struct pwm_ops {
	int (*request)(struct pwm_chip *, struct pwm_device *);
	void (*free)(struct pwm_chip *, struct pwm_device *);
	int (*capture)(struct pwm_chip *, struct pwm_device *, struct pwm_capture *, long unsigned int);
	int (*apply)(struct pwm_chip *, struct pwm_device *, const struct pwm_state *);
	void (*get_state)(struct pwm_chip *, struct pwm_device *, struct pwm_state *);
	struct module *owner;
};

struct pwm_export {
	struct device child;
	struct pwm_device *pwm;
	struct mutex lock;
	struct pwm_state suspend;
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
	int domain_nr;
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

typedef int pci_power_t;

struct pci_vpd {
	struct mutex lock;
	unsigned int len;
	u8 cap;
};

struct pci_sriov {
	int pos;
	int nres;
	u32 cap;
	u16 ctrl;
	u16 total_VFs;
	u16 initial_VFs;
	u16 num_VFs;
	u16 offset;
	u16 stride;
	u16 vf_device;
	u32 pgsz;
	u8 link;
	u8 max_VF_buses;
	u16 driver_max_VFs;
	struct pci_dev *dev;
	struct pci_dev *self;
	u32 class;
	u8 hdr_type;
	u16 subsystem_vendor;
	u16 subsystem_device;
	resource_size_t barsz[6];
	bool drivers_autoprobe;
};

struct aer_stats;

struct rcec_ea;

struct pci_driver;

struct pcie_link_state;

struct pci_p2pdma;

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
	u16 ptm_cap;
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
	struct pci_p2pdma *p2pdma;
	u16 acs_cap;
	phys_addr_t rom;
	size_t romlen;
	const char *driver_override;
	long unsigned int priv_flags;
	u8 reset_methods[7];
};

struct rcec_ea {
	u8 nextbusn;
	u8 lastbusn;
	u32 bitmap;
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

struct pci_host_bridge {
	struct device dev;
	struct pci_bus *bus;
	struct pci_ops *ops;
	struct pci_ops *child_ops;
	void *sysdata;
	int busnr;
	int domain_nr;
	struct list_head windows;
	struct list_head dma_ranges;
	u8 (*swizzle_irq)(struct pci_dev *, u8 *);
	int (*map_irq)(const struct pci_dev *, u8, u8);
	void (*release_fn)(struct pci_host_bridge *);
	void *release_data;
	unsigned int ignore_reset_delay: 1;
	unsigned int no_ext_tags: 1;
	unsigned int native_aer: 1;
	unsigned int native_pcie_hotplug: 1;
	unsigned int native_shpc_hotplug: 1;
	unsigned int native_pme: 1;
	unsigned int native_ltr: 1;
	unsigned int native_dpc: 1;
	unsigned int preserve_config: 1;
	unsigned int size_windows: 1;
	unsigned int msi_domain: 1;
	resource_size_t (*align_resource)(struct pci_dev *, const struct resource *, resource_size_t, resource_size_t, resource_size_t);
	long: 64;
	long: 64;
	long unsigned int private[0];
};

struct pci_ops {
	int (*add_bus)(struct pci_bus *);
	void (*remove_bus)(struct pci_bus *);
	void * (*map_bus)(struct pci_bus *, unsigned int, int);
	int (*read)(struct pci_bus *, unsigned int, int, int, u32 *);
	int (*write)(struct pci_bus *, unsigned int, int, int, u32);
};

typedef u64 pci_bus_addr_t;

struct pci_bus_region {
	pci_bus_addr_t start;
	pci_bus_addr_t end;
};

struct pci_error_handlers {
	pci_ers_result_t (*error_detected)(struct pci_dev *, pci_channel_state_t);
	pci_ers_result_t (*mmio_enabled)(struct pci_dev *);
	pci_ers_result_t (*slot_reset)(struct pci_dev *);
	void (*reset_prepare)(struct pci_dev *);
	void (*reset_done)(struct pci_dev *);
	void (*resume)(struct pci_dev *);
};

struct pci_dev_resource {
	struct list_head list;
	struct resource *res;
	struct pci_dev *dev;
	resource_size_t start;
	resource_size_t end;
	resource_size_t add_size;
	resource_size_t min_align;
	long unsigned int flags;
};

enum release_type {
	leaf_only = 0,
	whole_subtree = 1,
};

enum enable_type {
	undefined = 4294967295,
	user_disabled = 0,
	auto_disabled = 1,
	user_enabled = 2,
	auto_enabled = 3,
};

enum {
	CPER_SEV_RECOVERABLE = 0,
	CPER_SEV_FATAL = 1,
	CPER_SEV_CORRECTED = 2,
	CPER_SEV_INFORMATIONAL = 3,
};

enum {
	pci_channel_io_normal = 1,
	pci_channel_io_frozen = 2,
	pci_channel_io_perm_failure = 3,
};

enum pci_bus_flags {
	PCI_BUS_FLAGS_NO_MSI = 1,
	PCI_BUS_FLAGS_NO_MMRBC = 2,
	PCI_BUS_FLAGS_NO_AERSID = 4,
	PCI_BUS_FLAGS_NO_EXTCFG = 8,
};

struct aer_stats {
	u64 dev_cor_errs[16];
	u64 dev_fatal_errs[27];
	u64 dev_nonfatal_errs[27];
	u64 dev_total_cor_errs;
	u64 dev_total_fatal_errs;
	u64 dev_total_nonfatal_errs;
	u64 rootport_total_cor_errs;
	u64 rootport_total_fatal_errs;
	u64 rootport_total_nonfatal_errs;
};

enum pci_ers_result {
	PCI_ERS_RESULT_NONE = 1,
	PCI_ERS_RESULT_CAN_RECOVER = 2,
	PCI_ERS_RESULT_NEED_RESET = 3,
	PCI_ERS_RESULT_DISCONNECT = 4,
	PCI_ERS_RESULT_RECOVERED = 5,
	PCI_ERS_RESULT_NO_AER_DRIVER = 6,
};

struct aer_header_log_regs {
	unsigned int dw0;
	unsigned int dw1;
	unsigned int dw2;
	unsigned int dw3;
};

struct aer_capability_regs {
	u32 header;
	u32 uncor_status;
	u32 uncor_mask;
	u32 uncor_severity;
	u32 cor_status;
	u32 cor_mask;
	u32 cap_control;
	struct aer_header_log_regs header_log;
	u32 root_command;
	u32 root_status;
	u16 cor_err_source;
	u16 uncor_err_source;
};

struct pci_cap_saved_data {
	u16 cap_nr;
	bool cap_extended;
	unsigned int size;
	u32 data[0];
};

struct pci_cap_saved_state {
	struct hlist_node next;
	struct pci_cap_saved_data cap;
};

struct aer_err_info {
	struct pci_dev *dev[5];
	int error_dev_num;
	unsigned int id: 16;
	unsigned int severity: 2;
	unsigned int __pad1: 5;
	unsigned int multi_error_valid: 1;
	unsigned int first_error: 5;
	unsigned int __pad2: 2;
	unsigned int tlp_header_valid: 1;
	unsigned int status;
	unsigned int mask;
	struct aer_header_log_regs tlp;
};

struct pcie_device {
	int irq;
	struct pci_dev *port;
	u32 service;
	void *priv_data;
	struct device device;
};

struct pcie_port_service_driver {
	const char *name;
	int (*probe)(struct pcie_device *);
	void (*remove)(struct pcie_device *);
	int (*suspend)(struct pcie_device *);
	int (*resume_noirq)(struct pcie_device *);
	int (*resume)(struct pcie_device *);
	int (*runtime_suspend)(struct pcie_device *);
	int (*runtime_resume)(struct pcie_device *);
	int (*slot_reset)(struct pcie_device *);
	int port_type;
	u32 service;
	struct device_driver driver;
};

struct aer_err_source {
	unsigned int status;
	unsigned int id;
};

struct aer_rpc {
	struct pci_dev *rpd;
	struct {
		union {
			struct __kfifo kfifo;
			struct aer_err_source *type;
			const struct aer_err_source *const_type;
			char (*rectype)[0];
			struct aer_err_source *ptr;
			const struct aer_err_source *ptr_const;
		};
		struct aer_err_source buf[128];
	} aer_fifo;
};

struct aer_recover_entry {
	u8 bus;
	u8 devfn;
	u16 domain;
	int severity;
	struct aer_capability_regs *regs;
};

struct hotplug_slot_ops;

struct hotplug_slot {
	const struct hotplug_slot_ops *ops;
	struct list_head slot_list;
	struct pci_slot *pci_slot;
	struct module *owner;
	const char *mod_name;
};

struct hotplug_slot_ops {
	int (*enable_slot)(struct hotplug_slot *);
	int (*disable_slot)(struct hotplug_slot *);
	int (*set_attention_status)(struct hotplug_slot *, u8);
	int (*hardware_test)(struct hotplug_slot *, u32);
	int (*get_power_status)(struct hotplug_slot *, u8 *);
	int (*get_attention_status)(struct hotplug_slot *, u8 *);
	int (*get_latch_status)(struct hotplug_slot *, u8 *);
	int (*get_adapter_status)(struct hotplug_slot *, u8 *);
	int (*reset_slot)(struct hotplug_slot *, bool);
};

struct controller {
	struct pcie_device *pcie;
	u32 slot_cap;
	unsigned int inband_presence_disabled: 1;
	u16 slot_ctrl;
	struct mutex ctrl_lock;
	long unsigned int cmd_started;
	unsigned int cmd_busy: 1;
	wait_queue_head_t queue;
	atomic_t pending_events;
	unsigned int notification_enabled: 1;
	unsigned int power_fault_detected;
	struct task_struct *poll_thread;
	u8 state;
	struct mutex state_lock;
	struct delayed_work button_work;
	struct hotplug_slot hotplug_slot;
	struct rw_semaphore reset_lock;
	unsigned int depth;
	unsigned int ist_running;
	int request_result;
	wait_queue_head_t requester;
};

enum pci_p2pdma_map_type {
	PCI_P2PDMA_MAP_UNKNOWN = 0,
	PCI_P2PDMA_MAP_NOT_SUPPORTED = 1,
	PCI_P2PDMA_MAP_BUS_ADDR = 2,
	PCI_P2PDMA_MAP_THRU_HOST_BRIDGE = 3,
};

struct pci_p2pdma_map_state {
	struct dev_pagemap *pgmap;
	int map;
	u64 bus_off;
};

struct gen_pool;

struct pci_p2pdma {
	struct gen_pool *pool;
	bool p2pmem_published;
	struct xarray map_types;
};

typedef long unsigned int (*genpool_algo_t)(long unsigned int *, long unsigned int, long unsigned int, unsigned int, void *, struct gen_pool *, long unsigned int);

struct gen_pool {
	spinlock_t lock;
	struct list_head chunks;
	int min_alloc_order;
	genpool_algo_t algo;
	void *data;
	const char *name;
};

struct pci_p2pdma_pagemap {
	struct dev_pagemap pgmap;
	struct pci_dev *provider;
	u64 bus_offset;
};

struct pci_p2pdma_whitelist_entry {
	short unsigned int vendor;
	short unsigned int device;
	enum {
		REQ_SAME_HOST_BRIDGE = 1,
	} flags;
};

enum pci_barno {
	NO_BAR = 4294967295,
	BAR_0 = 0,
	BAR_1 = 1,
	BAR_2 = 2,
	BAR_3 = 3,
	BAR_4 = 4,
	BAR_5 = 5,
};

struct pci_epf_bar {
	dma_addr_t phys_addr;
	void *addr;
	size_t size;
	enum pci_barno barno;
	int flags;
};

struct cdns_pcie;

struct cdns_pcie_ops {
	int (*start_link)(struct cdns_pcie *);
	void (*stop_link)(struct cdns_pcie *);
	bool (*link_up)(struct cdns_pcie *);
	u64 (*cpu_addr_fixup)(struct cdns_pcie *, u64);
};

struct cdns_pcie {
	void *reg_base;
	struct resource *mem_res;
	struct device *dev;
	bool is_rc;
	int phy_count;
	struct phy **phy;
	struct device_link **link;
	const struct cdns_pcie_ops *ops;
};

struct cdns_pcie_rc {
	struct cdns_pcie pcie;
	struct resource *cfg_res;
	void *cfg_base;
	u32 vendor_id;
	u32 device_id;
	bool avail_ib_bar[3];
	unsigned int quirk_retrain_flag: 1;
	unsigned int quirk_detect_quiet_flag: 1;
};

struct cdns_pcie_epf {
	struct cdns_pcie_epf *epf;
	struct pci_epf_bar *epf_bar[6];
};

struct cdns_pcie_ep {
	struct cdns_pcie pcie;
	u32 max_regions;
	long unsigned int ob_region_map;
	phys_addr_t *ob_addr;
	phys_addr_t irq_phys_addr;
	void *irq_cpu_addr;
	u64 irq_pci_addr;
	u8 irq_pci_fn;
	u8 irq_pending;
	spinlock_t lock;
	struct cdns_pcie_epf *epf;
	unsigned int quirk_detect_quiet_flag: 1;
	unsigned int quirk_disable_flr: 1;
};

enum link_status {
	NO_RECEIVERS_DETECTED = 0,
	LINK_TRAINING_IN_PROGRESS = 1,
	LINK_UP_DL_IN_PROGRESS = 2,
	LINK_UP_DL_COMPLETED = 3,
};

struct j721e_pcie {
	struct cdns_pcie *cdns_pcie;
	struct clk *refclk;
	u32 mode;
	u32 num_lanes;
	void *user_cfg_base;
	void *intd_cfg_base;
	u32 linkdown_irq_regfield;
};

enum j721e_pcie_mode {
	PCI_MODE_RC = 0,
	PCI_MODE_EP = 1,
};

struct j721e_pcie_data {
	enum j721e_pcie_mode mode;
	unsigned int quirk_retrain_flag: 1;
	unsigned int quirk_detect_quiet_flag: 1;
	unsigned int quirk_disable_flr: 1;
	u32 linkdown_irq_regfield;
	unsigned int byte_access_allowed: 1;
};

enum pci_interrupt_pin {
	PCI_INTERRUPT_UNKNOWN = 0,
	PCI_INTERRUPT_INTA = 1,
	PCI_INTERRUPT_INTB = 2,
	PCI_INTERRUPT_INTC = 3,
	PCI_INTERRUPT_INTD = 4,
};

struct xilinx_pcie {
	struct device *dev;
	void *reg_base;
	long unsigned int msi_map[2];
	struct mutex map_lock;
	struct irq_domain *msi_domain;
	struct irq_domain *leg_domain;
	struct list_head resources;
};

struct pci_config_window;

struct pci_ecam_ops {
	unsigned int bus_shift;
	struct pci_ops pci_ops;
	int (*init)(struct pci_config_window *);
};

struct pci_config_window {
	struct resource res;
	struct resource busr;
	unsigned int bus_shift;
	void *priv;
	const struct pci_ecam_ops *ops;
	union {
		void *win;
		void **winp;
	};
	struct device *parent;
};

struct event_map {
	u32 reg_mask;
	u32 event_bit;
};

struct mc_msi {
	struct mutex lock;
	struct irq_domain *msi_domain;
	struct irq_domain *dev_domain;
	u32 num_vectors;
	u64 vector_phy;
	long unsigned int used[1];
};

struct mc_pcie {
	void *axi_base_addr;
	struct device *dev;
	struct irq_domain *intx_domain;
	struct irq_domain *event_domain;
	raw_spinlock_t lock;
	struct mc_msi msi;
};

struct cause {
	const char *sym;
	const char *str;
};

struct atomic_notifier_head {
	spinlock_t lock;
	struct notifier_block *head;
};

struct pci_epf_header {
	u16 vendorid;
	u16 deviceid;
	u8 revid;
	u8 progif_code;
	u8 subclass_code;
	u8 baseclass_code;
	u8 cache_line_size;
	u16 subsys_vendor_id;
	u16 subsys_id;
	enum pci_interrupt_pin interrupt_pin;
};

struct pci_epc_ops;

struct pci_epc_mem;

struct pci_epc {
	struct device dev;
	struct list_head pci_epf;
	const struct pci_epc_ops *ops;
	struct pci_epc_mem **windows;
	struct pci_epc_mem *mem;
	unsigned int num_windows;
	u8 max_functions;
	u8 *max_vfs;
	struct config_group *group;
	struct mutex lock;
	long unsigned int function_num_map;
	struct atomic_notifier_head notifier;
};

enum pci_epc_irq_type {
	PCI_EPC_IRQ_UNKNOWN = 0,
	PCI_EPC_IRQ_LEGACY = 1,
	PCI_EPC_IRQ_MSI = 2,
	PCI_EPC_IRQ_MSIX = 3,
};

struct pci_epc_features;

struct pci_epc_ops {
	int (*write_header)(struct pci_epc *, u8, u8, struct pci_epf_header *);
	int (*set_bar)(struct pci_epc *, u8, u8, struct pci_epf_bar *);
	void (*clear_bar)(struct pci_epc *, u8, u8, struct pci_epf_bar *);
	int (*map_addr)(struct pci_epc *, u8, u8, phys_addr_t, u64, size_t);
	void (*unmap_addr)(struct pci_epc *, u8, u8, phys_addr_t);
	int (*set_msi)(struct pci_epc *, u8, u8, u8);
	int (*get_msi)(struct pci_epc *, u8, u8);
	int (*set_msix)(struct pci_epc *, u8, u8, u16, enum pci_barno, u32);
	int (*get_msix)(struct pci_epc *, u8, u8);
	int (*raise_irq)(struct pci_epc *, u8, u8, enum pci_epc_irq_type, u16);
	int (*map_msi_irq)(struct pci_epc *, u8, u8, phys_addr_t, u8, u32, u32 *, u32 *);
	int (*start)(struct pci_epc *);
	void (*stop)(struct pci_epc *);
	const struct pci_epc_features * (*get_features)(struct pci_epc *, u8, u8);
	struct module *owner;
};

struct pci_epc_features {
	unsigned int linkup_notifier: 1;
	unsigned int core_init_notifier: 1;
	unsigned int msi_capable: 1;
	unsigned int msix_capable: 1;
	u8 reserved_bar;
	u8 bar_fixed_64bit;
	u64 bar_fixed_size[6];
	size_t align;
};

struct pci_epc_mem_window {
	phys_addr_t phys_base;
	size_t size;
	size_t page_size;
};

struct pci_epc_mem {
	struct pci_epc_mem_window window;
	long unsigned int *bitmap;
	int pages;
	struct mutex lock;
};

enum dw_pcie_device_mode {
	DW_PCIE_UNKNOWN_TYPE = 0,
	DW_PCIE_EP_TYPE = 1,
	DW_PCIE_LEG_EP_TYPE = 2,
	DW_PCIE_RC_TYPE = 3,
};

struct dw_pcie_rp;

struct dw_pcie_host_ops {
	int (*host_init)(struct dw_pcie_rp *);
	void (*host_deinit)(struct dw_pcie_rp *);
	int (*msi_host_init)(struct dw_pcie_rp *);
};

struct dw_pcie_rp {
	bool has_msi_ctrl: 1;
	bool cfg0_io_shared: 1;
	u64 cfg0_base;
	void *va_cfg0_base;
	u32 cfg0_size;
	resource_size_t io_base;
	phys_addr_t io_bus_addr;
	u32 io_size;
	int irq;
	const struct dw_pcie_host_ops *ops;
	int msi_irq[8];
	struct irq_domain *irq_domain;
	struct irq_domain *msi_domain;
	dma_addr_t msi_data;
	struct page *msi_page;
	struct irq_chip *msi_irq_chip;
	u32 num_vectors;
	u32 irq_mask[8];
	struct pci_host_bridge *bridge;
	raw_spinlock_t lock;
	long unsigned int msi_irq_in_use[4];
};

struct dw_pcie_ep;

struct dw_pcie_ep_ops {
	void (*ep_init)(struct dw_pcie_ep *);
	int (*raise_irq)(struct dw_pcie_ep *, u8, enum pci_epc_irq_type, u16);
	const struct pci_epc_features * (*get_features)(struct dw_pcie_ep *);
	unsigned int (*func_conf_select)(struct dw_pcie_ep *, u8);
};

struct dw_pcie_ep {
	struct pci_epc *epc;
	struct list_head func_list;
	const struct dw_pcie_ep_ops *ops;
	phys_addr_t phys_base;
	size_t addr_size;
	size_t page_size;
	u8 bar_to_atu[6];
	phys_addr_t *outbound_addr;
	long unsigned int *ib_window_map;
	long unsigned int *ob_window_map;
	void *msi_mem;
	phys_addr_t msi_mem_phys;
	struct pci_epf_bar *epf_bar[6];
};

struct dw_pcie;

struct dw_pcie_ops {
	u64 (*cpu_addr_fixup)(struct dw_pcie *, u64);
	u32 (*read_dbi)(struct dw_pcie *, void *, u32, size_t);
	void (*write_dbi)(struct dw_pcie *, void *, u32, size_t, u32);
	void (*write_dbi2)(struct dw_pcie *, void *, u32, size_t, u32);
	int (*link_up)(struct dw_pcie *);
	int (*start_link)(struct dw_pcie *);
	void (*stop_link)(struct dw_pcie *);
};

struct dw_pcie {
	struct device *dev;
	void *dbi_base;
	void *dbi_base2;
	void *atu_base;
	size_t atu_size;
	u32 num_ib_windows;
	u32 num_ob_windows;
	u32 region_align;
	u64 region_limit;
	struct dw_pcie_rp pp;
	struct dw_pcie_ep ep;
	const struct dw_pcie_ops *ops;
	u32 version;
	u32 type;
	int num_lanes;
	int link_gen;
	u8 n_fts[2];
	bool iatu_unroll_enabled: 1;
};

struct ks_pcie_of_data {
	enum dw_pcie_device_mode mode;
	const struct dw_pcie_host_ops *host_ops;
	const struct dw_pcie_ep_ops *ep_ops;
	u32 version;
};

struct keystone_pcie {
	struct dw_pcie *pci;
	u32 device_id;
	int legacy_host_irqs[4];
	struct device_node *legacy_intc_np;
	int msi_host_irq;
	int num_lanes;
	u32 num_viewport;
	struct phy **phy;
	struct device_link **link;
	struct device_node *msi_intc_np;
	struct irq_domain *legacy_irq_domain;
	struct device_node *np;
	void *va_app_base;
	struct resource app;
	bool is_am6;
};

enum pcie_data_rate {
	PCIE_GEN1 = 0,
	PCIE_GEN2 = 1,
	PCIE_GEN3 = 2,
	PCIE_GEN4 = 3,
};

struct meson_pcie_clk_res {
	struct clk *clk;
	struct clk *port_clk;
	struct clk *general_clk;
};

struct meson_pcie_rc_reset {
	struct reset_control *port;
	struct reset_control *apb;
};

struct meson_pcie {
	struct dw_pcie pci;
	void *cfg_base;
	struct meson_pcie_clk_res clk_res;
	struct meson_pcie_rc_reset mrst;
	struct gpio_desc *reset_gpio;
	struct phy *phy;
};

struct mobiveil_msi {
	struct mutex lock;
	struct irq_domain *msi_domain;
	struct irq_domain *dev_domain;
	phys_addr_t msi_pages_phys;
	int num_of_vectors;
	long unsigned int msi_irq_in_use[1];
};

struct mobiveil_pcie;

struct mobiveil_rp_ops {
	int (*interrupt_init)(struct mobiveil_pcie *);
};

struct mobiveil_root_port {
	void *config_axi_slave_base;
	struct resource *ob_io_res;
	struct mobiveil_rp_ops *ops;
	int irq;
	raw_spinlock_t intx_mask_lock;
	struct irq_domain *intx_domain;
	struct mobiveil_msi msi;
	struct pci_host_bridge *bridge;
};

struct mobiveil_pab_ops;

struct mobiveil_pcie {
	struct platform_device *pdev;
	void *csr_axi_slave_base;
	void *apb_csr_base;
	phys_addr_t pcie_reg_base;
	int apio_wins;
	int ppio_wins;
	int ob_wins_configured;
	int ib_wins_configured;
	const struct mobiveil_pab_ops *ops;
	struct mobiveil_root_port rp;
};

struct mobiveil_pab_ops {
	int (*link_up)(struct mobiveil_pcie *);
};

typedef u32 compat_caddr_t;

struct linux_logo {
	int type;
	unsigned int width;
	unsigned int height;
	unsigned int clutsize;
	const unsigned char *clut;
	const unsigned char *data;
};

struct fb_fix_screeninfo {
	char id[16];
	long unsigned int smem_start;
	__u32 smem_len;
	__u32 type;
	__u32 type_aux;
	__u32 visual;
	__u16 xpanstep;
	__u16 ypanstep;
	__u16 ywrapstep;
	__u32 line_length;
	long unsigned int mmio_start;
	__u32 mmio_len;
	__u32 accel;
	__u16 capabilities;
	__u16 reserved[2];
};

struct fb_bitfield {
	__u32 offset;
	__u32 length;
	__u32 msb_right;
};

struct fb_var_screeninfo {
	__u32 xres;
	__u32 yres;
	__u32 xres_virtual;
	__u32 yres_virtual;
	__u32 xoffset;
	__u32 yoffset;
	__u32 bits_per_pixel;
	__u32 grayscale;
	struct fb_bitfield red;
	struct fb_bitfield green;
	struct fb_bitfield blue;
	struct fb_bitfield transp;
	__u32 nonstd;
	__u32 activate;
	__u32 height;
	__u32 width;
	__u32 accel_flags;
	__u32 pixclock;
	__u32 left_margin;
	__u32 right_margin;
	__u32 upper_margin;
	__u32 lower_margin;
	__u32 hsync_len;
	__u32 vsync_len;
	__u32 sync;
	__u32 vmode;
	__u32 rotate;
	__u32 colorspace;
	__u32 reserved[4];
};

struct fb_cmap {
	__u32 start;
	__u32 len;
	__u16 *red;
	__u16 *green;
	__u16 *blue;
	__u16 *transp;
};

enum {
	FB_BLANK_UNBLANK = 0,
	FB_BLANK_NORMAL = 1,
	FB_BLANK_VSYNC_SUSPEND = 2,
	FB_BLANK_HSYNC_SUSPEND = 3,
	FB_BLANK_POWERDOWN = 4,
};

struct fb_copyarea {
	__u32 dx;
	__u32 dy;
	__u32 width;
	__u32 height;
	__u32 sx;
	__u32 sy;
};

struct fb_fillrect {
	__u32 dx;
	__u32 dy;
	__u32 width;
	__u32 height;
	__u32 color;
	__u32 rop;
};

struct fb_image {
	__u32 dx;
	__u32 dy;
	__u32 width;
	__u32 height;
	__u32 fg_color;
	__u32 bg_color;
	__u8 depth;
	const char *data;
	struct fb_cmap cmap;
};

struct fbcurpos {
	__u16 x;
	__u16 y;
};

struct fb_cursor {
	__u16 set;
	__u16 enable;
	__u16 rop;
	const char *mask;
	struct fbcurpos hot;
	struct fb_image image;
};

enum backlight_type {
	BACKLIGHT_RAW = 1,
	BACKLIGHT_PLATFORM = 2,
	BACKLIGHT_FIRMWARE = 3,
	BACKLIGHT_TYPE_MAX = 4,
};

enum backlight_scale {
	BACKLIGHT_SCALE_UNKNOWN = 0,
	BACKLIGHT_SCALE_LINEAR = 1,
	BACKLIGHT_SCALE_NON_LINEAR = 2,
};

struct backlight_device;

struct fb_info;

struct backlight_ops {
	unsigned int options;
	int (*update_status)(struct backlight_device *);
	int (*get_brightness)(struct backlight_device *);
	int (*check_fb)(struct backlight_device *, struct fb_info *);
};

struct backlight_properties {
	int brightness;
	int max_brightness;
	int power;
	int fb_blank;
	enum backlight_type type;
	unsigned int state;
	enum backlight_scale scale;
};

struct backlight_device {
	struct backlight_properties props;
	struct mutex update_lock;
	struct mutex ops_lock;
	const struct backlight_ops *ops;
	struct notifier_block fb_notif;
	struct list_head entry;
	struct device dev;
	bool fb_bl_on[32];
	int use_count;
};

struct fb_chroma {
	__u32 redx;
	__u32 greenx;
	__u32 bluex;
	__u32 whitex;
	__u32 redy;
	__u32 greeny;
	__u32 bluey;
	__u32 whitey;
};

struct fb_videomode;

struct fb_monspecs {
	struct fb_chroma chroma;
	struct fb_videomode *modedb;
	__u8 manufacturer[4];
	__u8 monitor[14];
	__u8 serial_no[14];
	__u8 ascii[14];
	__u32 modedb_len;
	__u32 model;
	__u32 serial;
	__u32 year;
	__u32 week;
	__u32 hfmin;
	__u32 hfmax;
	__u32 dclkmin;
	__u32 dclkmax;
	__u16 input;
	__u16 dpms;
	__u16 signal;
	__u16 vfmin;
	__u16 vfmax;
	__u16 gamma;
	__u16 gtf: 1;
	__u16 misc;
	__u8 version;
	__u8 revision;
	__u8 max_x;
	__u8 max_y;
};

struct fb_pixmap {
	u8 *addr;
	u32 size;
	u32 offset;
	u32 buf_align;
	u32 scan_align;
	u32 access_align;
	u32 flags;
	u32 blit_x;
	u32 blit_y;
	void (*writeio)(struct fb_info *, void *, void *, unsigned int);
	void (*readio)(struct fb_info *, void *, void *, unsigned int);
};

struct fb_deferred_io_pageref;

struct fb_deferred_io;

struct fb_ops;

struct fb_tile_ops;

struct apertures_struct;

struct fb_info {
	refcount_t count;
	int node;
	int flags;
	int fbcon_rotate_hint;
	struct mutex lock;
	struct mutex mm_lock;
	struct fb_var_screeninfo var;
	struct fb_fix_screeninfo fix;
	struct fb_monspecs monspecs;
	struct fb_pixmap pixmap;
	struct fb_pixmap sprite;
	struct fb_cmap cmap;
	struct list_head modelist;
	struct fb_videomode *mode;
	struct backlight_device *bl_dev;
	struct mutex bl_curve_mutex;
	u8 bl_curve[128];
	struct delayed_work deferred_work;
	long unsigned int npagerefs;
	struct fb_deferred_io_pageref *pagerefs;
	struct fb_deferred_io *fbdefio;
	const struct fb_ops *fbops;
	struct device *device;
	struct device *dev;
	int class_flag;
	struct fb_tile_ops *tileops;
	union {
		char *screen_base;
		char *screen_buffer;
	};
	long unsigned int screen_size;
	void *pseudo_palette;
	u32 state;
	void *fbcon_par;
	void *par;
	struct apertures_struct *apertures;
	bool skip_vt_switch;
};

struct fb_videomode {
	const char *name;
	u32 refresh;
	u32 xres;
	u32 yres;
	u32 pixclock;
	u32 left_margin;
	u32 right_margin;
	u32 upper_margin;
	u32 lower_margin;
	u32 hsync_len;
	u32 vsync_len;
	u32 sync;
	u32 vmode;
	u32 flag;
};

struct fb_cmap_user {
	__u32 start;
	__u32 len;
	__u16 *red;
	__u16 *green;
	__u16 *blue;
	__u16 *transp;
};

struct fb_event {
	struct fb_info *info;
	void *data;
};

struct fb_blit_caps {
	u32 x;
	u32 y;
	u32 len;
	u32 flags;
};

struct fb_deferred_io_pageref {
	struct page *page;
	long unsigned int offset;
	struct list_head list;
};

struct fb_deferred_io {
	long unsigned int delay;
	bool sort_pagereflist;
	struct mutex lock;
	struct list_head pagereflist;
	void (*first_io)(struct fb_info *);
	void (*deferred_io)(struct fb_info *, struct list_head *);
};

struct fb_ops {
	struct module *owner;
	int (*fb_open)(struct fb_info *, int);
	int (*fb_release)(struct fb_info *, int);
	ssize_t (*fb_read)(struct fb_info *, char *, size_t, loff_t *);
	ssize_t (*fb_write)(struct fb_info *, const char *, size_t, loff_t *);
	int (*fb_check_var)(struct fb_var_screeninfo *, struct fb_info *);
	int (*fb_set_par)(struct fb_info *);
	int (*fb_setcolreg)(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, struct fb_info *);
	int (*fb_setcmap)(struct fb_cmap *, struct fb_info *);
	int (*fb_blank)(int, struct fb_info *);
	int (*fb_pan_display)(struct fb_var_screeninfo *, struct fb_info *);
	void (*fb_fillrect)(struct fb_info *, const struct fb_fillrect *);
	void (*fb_copyarea)(struct fb_info *, const struct fb_copyarea *);
	void (*fb_imageblit)(struct fb_info *, const struct fb_image *);
	int (*fb_cursor)(struct fb_info *, struct fb_cursor *);
	int (*fb_sync)(struct fb_info *);
	int (*fb_ioctl)(struct fb_info *, unsigned int, long unsigned int);
	int (*fb_compat_ioctl)(struct fb_info *, unsigned int, long unsigned int);
	int (*fb_mmap)(struct fb_info *, struct vm_area_struct *);
	void (*fb_get_caps)(struct fb_info *, struct fb_blit_caps *, struct fb_var_screeninfo *);
	void (*fb_destroy)(struct fb_info *);
	int (*fb_debug_enter)(struct fb_info *);
	int (*fb_debug_leave)(struct fb_info *);
};

struct fb_tilemap {
	__u32 width;
	__u32 height;
	__u32 depth;
	__u32 length;
	const __u8 *data;
};

struct fb_tilerect {
	__u32 sx;
	__u32 sy;
	__u32 width;
	__u32 height;
	__u32 index;
	__u32 fg;
	__u32 bg;
	__u32 rop;
};

struct fb_tilearea {
	__u32 sx;
	__u32 sy;
	__u32 dx;
	__u32 dy;
	__u32 width;
	__u32 height;
};

struct fb_tileblit {
	__u32 sx;
	__u32 sy;
	__u32 width;
	__u32 height;
	__u32 fg;
	__u32 bg;
	__u32 length;
	__u32 *indices;
};

struct fb_tilecursor {
	__u32 sx;
	__u32 sy;