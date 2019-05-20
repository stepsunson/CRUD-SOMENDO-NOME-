#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP 	6
#define ETH_HLEN 14

struct Key {
	u32 src_ip;               //source ip
	u32 dst_ip;               //destination ip
	unsigned short src_port;  //source port
	unsigned short dst_port;  //destination port
};

struct Leaf {
	int timestamp;            //timestamp in ns
};

//BPF_TABLE(map_type, key_type, leaf_type, table_name, num_entry)
//map <Key, Leaf>
//tracing sessions having same Key(dst_ip, src_ip, dst_port,src_port)
BPF_HASH(sessions, struct Key, struct Leaf, 1024);

/*eBPF program.
  Filter IP and TCP packets, having payload not empty
  and containing "HTTP", "GET", "POST"  as first bytes of payload.
  AND ALL the other packets having same (src_ip,dst_ip,src_port,dst_port)
  this means belonging to the same "session"
  this additional check avoids url truncation, if url is too long
  userspace script, if necessary, reassembles urls split in 2 or more packets.
  if the program is loaded as PROG_TYPE_SOCKET_FILTER
  and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int http_filter(struct __sk_buff *skb) {

	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	//filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DROP;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	//filter TCP packets (ip next protocol = 0x06)
	if (ip->nextp != IP_TCP) {
		goto DROP;
	}

	u32  tcp_header_length = 0;
	u32  ip_header_length = 0;
	u32  payload_offset = 0;
	u32  payload_length = 0;
	struct Key 	key;
	struct Leaf zero = {0};

        //calculate ip header length
        //value to multiply * 4
        //e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
        ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

        //check ip header length against minimum
       