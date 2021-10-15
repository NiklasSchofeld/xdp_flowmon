/* structs and definitions for bpflowmon*/
#ifndef BPFLOWMON_H
	#define BPFLOWMON_H
//#ifndef FLOWMGMT || BPFLOWMON_C
#if !defined(FLOWMGMT) && !defined(BPFLOWMON_C)
#include "vmlinux.h"            //all kernel types
#else
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#endif

#include "protocol_ids.h"       //can't include linux/if_ether, because etthdr definition conflicts with vmlinux.h



/************************************************************************************************************************/
/* structs */

struct protocols {
	int l3;
	int l4;
};
#define MAX_OPTS	40
struct tcp_options_words {
		__u8 option_words[MAX_OPTS];
	};

/* IP4 or IP6 address */
union ip_addr {
	__be32 v4;
	__u8 v6[16];	//similar to ipv6hdr->saddr.in6_u.u6_addr8
};

/* identifier for flows, used as key in map */
struct flow_id {
		union ip_addr	saddr;
		union ip_addr	daddr;
		__be16		sport;	/* "type" */
		__be16		dport;	/* "id" for ICMP Echo request/reply, code otherwise */
		__u8		proto;	/* This position is better for padding. */

} ;//__attribute__((packed));

/* Define the data collected for each flow.
 *	TODO: add support for more statistics.
 *	ISSUE: too many instructions are necessary to parse TCP fields
 */
//copied from tc_flowmon
struct flow_info {
	/* Generic flow information (for all protocols) */
	__u64	first_seen;		/* Epoch of the first packet of this flow (ns). */
	__u64	last_seen;	  	/* Epoch of the last packet seen so far (ns). */
	__u64	jitter;			/* Cumulative delays between packets. */
	__u32	pkts;		    /* Cumulative number of packets. */
	__u32	ifindex;		/* Capture interface. */

	/* IP-related filds and measurements. */
	__u8 	version;		/* Version (4/6) */
	__u8	tos;		   	/* TOS/DSCP (IPv4) or Traffic Class (IPv6). */	
	__u32	fl;				/* Flow label (IPv6). */
	__u32	bytes;		    	/* Cumulative number of bytes. */
	__u16	min_pkt_len;	 	/* Smallest IP packet seen in the flow. */
	__u16	max_pkt_len; 		/* Biggest IP packet seen in the flow. */
	__u16	pkt_size_hist[6];	/* [0]: pkts up to 128 bytes;
					 * [1]: pkts from 128 to 256 bytes;
					 * [2]: pkts from 256 to 512 bytes;
					 * [3]: pkts from 512 to 1024 bytes;
					 * [4]: pkts from 1024 to 1514 bytes;
					 * [5]: pkts over 1514 bytes.
					 */
	__u8	min_ttl;		/* Min TTL (IPv4) or Hop Limit (IPv6). */
	__u8	max_ttl;		/* Max TTL (IPv4) or Hop Limit (IPv6). */
    __u16	pkt_ttl_hist[10];	/* [0]: pkts with TTL=1;
					 * [1]: pkts with TTL>1 and TTL<=5;
					 * [2]: packets with TTL > 5 and <= 32;
					 * [3]: packets with TTL > 32 and <= 64;
					 * [4]: packets with TTL > 64 and <= 96;
					 * [5]: packets with TTL > 96 and <= 128;
					 * [6]: packets with TTL > 128 and <= 160;
					 * [7]: packets with TTL > 160 and <= 192;
					 * [8]: packets with TTL > 192 and <= 224;
					 * [9]: packets with TTL > 224 and <= 255.
					 */

	/* TCP-related fields. */
	__u32	next_seq;			/* Last sequence number seen (used for computing retransmissions. */
	__be16 	last_id;			/* Last ipv4 identification value for last_seq. */
	__u8	cumulative_flags;	/* Cumulative TCP flags seen in all packets so far. */
	__u16	retr_pkts;			/* Total number of retrasmitted packets. */
	__u32	retr_bytes;			/* Total number of retransmitted bytes. */
	__u16	ooo_pkts;			/* Total number of out-of-order packets. */
	__u32	ooo_bytes;			/* Total number of out-of-order bytes. */
	__u32	min_win_bytes;		/* Min TCP Window. */
	__u32	max_win_bytes;		/* Max TCP Window. */
	__u16	mss;				/* TCP Max Segment Size. */
	__u8	wndw_scale;			/* TCP Window Scale. */
	__u8	all_options_parsed;	/* indicator for missing options */

	/* Other NetFlow or IPFIX fields are L7- or mgmt specifics and are not collected through packets. */
} ;

/* according to: https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml */
struct general_opt {
	__u8 type;
	__u8 len;
};
//copied from tc_flowmon:
struct optvalues {
	__u16* mss;
	__u8* wndw_scale;
};

struct tcp_opt_none {
	__u8 type;
};

struct tcp_opt_mss {
	__u8 type;
	__u8 len;
	__u16 data;
};

struct tcp_opt_wndw_scale {
	__u8 type;
	__u8 len;
	__u8 data;
};

struct tcp_opt_sackp {
	__u8 type;
	__u8 len;
};

struct tcp_opt_sack {
	__u8 type;
	__u8 len;
//	__u32 data[8];
};

struct tcp_opt_ts {
	__u8 type;
	__u8 len;
	__u32 data[2];
};


/************************************************************************************************************************/

/* meta data */
struct meta_info {
    //struct header_cursor hdr_crsr_offset;
    __u16 hdr_crsr_offset;  //current header cursor offset (header cursor = data + hdr_crsr_offset)
    __u8 l3_offset;         //l3 header offset (l3 header = data + l3_offset) - possibly obsolete
    __u8 l4_offset;         //l4 header offset (l4 header = data + l4_offset) - possibly obsolete
	__u8 payload_offset;	//start of application layer
    __u64 timestamp;        //timestamp of packet arrival
    __u8 action;            //xdp action to be returned (makes possible to set return code while parsing, but let the parsing end)
} __attribute__((aligned(4)));


/* deep packet inspection */
struct dns_info {
	__u16 pkts;
};

#endif	//BPFLOWMON_H