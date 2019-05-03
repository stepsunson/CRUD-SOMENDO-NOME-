#include <uapi/linux/ptrace.h>

struct str_t {
	u64 pid;
	char str[80];
};

BPF_PERF_OUTPUT(events);

int printret(struct pt_regs *ct