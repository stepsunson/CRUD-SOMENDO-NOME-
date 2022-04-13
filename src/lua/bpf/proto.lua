--[[
Copyright 2016 Marek Vavrusa <mvavrusa@cloudflare.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]
local ffi = require('ffi')
local BPF = ffi.typeof('struct bpf')

ffi.cdef [[
struct sk_buff {
	uint32_t len;
	uint32_t pkt_type;
	uint32_t mark;
	uint32_t queue_mapping;
	uint32_t protocol;
	uint32_t vlan_present;
	uint32_t vlan_tci;
	uint32_t vlan_proto;
	uint32_t priority;
	uint32_t ingress_ifindex;
	uint32_t ifindex;
	uint32_t tc_index;
	uint32_t cb[5];
	uint32_t hash;
	uint32_t tc_classid;
	uint32_t data;
	uint32_t data_end;
	uint32_t napi_id;

	/* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
	uint32_t family;
	uint32_t remote_ip4;	/* Stored in network byte order */
	uint32_t local_ip4;	/* Stored in network byte order */
	uint32_t remote_ip6[4];	/* Stored in network byte order */
	uint32_t local_ip6[4];	/* Stored in network byte order */
	uint32_t remote_port;	/* Stored in network byte order */
	uint32_t local_port;	/* stored in host byte order */
	/* ... here. */

	uint32_t data_meta;
};

struct net_off_t {
	uint8_t  ver:4;
} __attribute__((packed));

struct eth_t {
	uint8_t  dst[6];
	uint8_t  src[6];
	uint16_t type;
} __attribute__((packed));

struct dot1q_t {
	uint16_t pri:3;
	uint16_t cfi:1;
	uint16_t vlanid:12;
	uint16_t type;
} __attribute__((packed));

struct arp_t {
	uint16_t htype;
	uint16_t ptype;
	uint8_t  hlen;
	uint8_t  plen;
	uint16_t oper;
	uint8_t  sha[6];
	uint32_t spa;
	uint8_t  tha[6];
	uint32_t tpa;
} __attribute__((packed));

struct ip_t {
	uint8_t  ver:4;
	uint8_t  hlen:4;
	uint8_t  tos;
	uint16_t tlen;
	uint16_t identification;
	uint16_t ffo_unused:1;
	uint16_t df:1;
	uint16_t mf:1;
	uint16_t foffset:13;
	uint8_t  ttl;
	uint8_t  proto;
	uint16_t hchecksum;
	uint32_t src;
	uint32_t dst;
} __attribute__((packed));

struct icmp_t {
	uint8_t  type;
	uint8_t  code;
	uint16_t checksum;
} __attribute__((packed));

struct ip6_t {
	uint32_t ver:4;
	uint32_t priority:8;
	uint32_t flow_label:20;
	uint16_t payload_len;
	uint8_t  next_header;
	uint8_t  hop_limit;
	uint64_t src_hi;
	uint64_t src_lo;
	uint64_t dst_hi;
	uint64_t dst_lo;
} __attribute__((packed));

struct ip6_opt_t {
	uint8_t  next_header;
	uint8_t  ext_len;
	uint8_t  pad[6];
} __attribute__((packed));

struct icmp6_t {
	uint8_t  type;
	uint8_t  code;
	uint16_t checksum;
} __attribute__((packed));

struct udp_t {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t crc;
} __attribute__((packed));

struct tcp_t {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t  offset:4;
	uint8_t  reserved:4;
	uint8_t  flag_cwr:1;
	uint8_t  flag_ece:1;
	uint8_t  flag_urg:1;
	uint8_t  flag_ack:1;
	uint8_t  flag_psh:1;
	uint8_t  flag_rst:1;
	uint8_t  flag_syn:1;
	uint8_t  flag_fin:1;
	uint16_t rcv_wnd;
	uint16_t cksum;
	uint16_t urg_ptr;
} __attribute__((packed));

struct vxlan_t {
	uint32_t rsv1:4;
	uint32_t iflag:1;
	uint32_t rsv2:3;
	uint32_t rsv3:24;
	uint32_t key:24;
	uint32_t rsv4:8;
} __attribute__((packed));
]]


-- Architecture-specific ptrace register layout
local S = require('syscall')
local arch = S.abi.arch
local parm_to_reg = {}
if arch == 'x64' then
	ffi.cdef [[
	struct pt_regs {
		unsigned long r15;
		unsigned long r14;
		unsigned long r13;
		unsigned long r12;
		unsigned long bp;
		unsigned long bx;
		unsigned long r11;
		unsigned long r10;
		unsigned long r9;
		unsigned long r8;
		unsigned long ax;
		unsigned long cx;
		unsigned long dx;
		unsigned long si;
		unsigned long di;
		unsigned long orig_ax;
		unsigned long ip;
		unsigned long cs;
		unsigned long flags;
		unsigned long sp;
		unsigned long ss;
	};]]
	parm_to_reg = {parm1='di', parm2='si', parm3='dx', parm4='cx', parm5='r8', ret='sp', fp='bp'}
else
	ffi.cdef 'struct pt_regs {};'
end
-- Map symbolic registers to architecture ABI
ffi.metatype('struct pt_regs', {
		__index = function (_ --[[t]],k)
			return assert(parm_to_reg[k], 'no such register: '..k)
		end,
})

local M = {}

-- Dissector interface
local function dissector(type, e, dst, src, field)
	local parent = e.V[src].const
	-- Create new dissector variable
	e.vcopy(dst, src)
	-- Compute and materialize new dissector offset from parent
	e.V[dst].const = {off=e.V[src].const.off, __dissector=e.V[src].const.__dissector}
	parent.__dissector[field](e, dst)
	e.V[dst].const.__dissector = type
end
M.dissector = dissector

-- Get current effective offset, load field value at an offset relative to it and
-- add its value to compute next effective offset (e.g. udp_off = ip_off + pkt[ip_off].hlen)
local function next_offset(e, var, type, off, mask,