/*author: https://github.com/agentzex
Licensed under the Apache License, Version 2.0 (the "License")

tcp_mon_block.c - uses netlink TC, kernel tracepoints and kprobes to monitor outgoing connections from given PIDs
and block connections to all addresses initiated from them (acting like an in-process firewall), unless they are listed in allow_list
*/

#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <linux/tcp.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>


typedef struct
{
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
    u32 pid;
    u8 tcp_flags;
    char comm[TASK_COMM_LEN];
} full_packet;


typedef struct
{
    u8 state;
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
    u32 pid;
    char comm[TASK_COMM_LEN];
} verbose_event;


typedef struct
{
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
} key_hash;


BPF_HASH(monitored_connections, key_hash, full_packet);
BPF_HASH(allow_list, u32, u32);
BPF_HASH(pid_list, u32, u32);
BPF_PERF_OUTPUT(blocked_events);
BPF_PERF_OUTPUT(verbose_events);


#ifndef tcp_flag_byte
#define tcp_flag_byte(th) (((u_int8_t *)th)[13])
#endif


static bool VERBOSE_OUTPUT = false;


static __always_inline int tcp_header_bound_check(struct tcphdr* tcp, void* data_end)
{
    if ((void *)tcp + sizeof(*tcp) > data_end)
    {
        return -1;
    }

    return 0;
}


static void make_verbose_event(verbose_event *v, u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u32 pid, u8 state)
{
    v->src_ip = src_ip;
    v->src_port = src_port;
    v->dst_ip = dst_ip;
    v->dst_port = dst_port;
    v->pid = pid;
    v->state = state;
    bpf_get_current_comm(&v->comm, sizeof(v->comm));
}


int handle_egress(struct __sk_buff *ctx)
{
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;