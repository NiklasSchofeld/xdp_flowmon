//#include "vmlinux.h"          //all kernel types
#include "bpflowmon.h"          //includes also vmlinux.h
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "stringify.h"
#include "bpflowmon_defs.h"

#define PROG(F) SEC("xdp/"__stringify(F))   //from sockex3

/* License must be GPL */
char LICENSE[] SEC("license") = "GPL";

#ifndef memcpy
    #define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#define __DEBUG__
// #define __VERBOSE__
#define __FLOW_TCP_OPTS__ //not working
#define __PERFORM_DPI__

/************************************************************************************************************************/
/* global variables */

int action;
__u64 ts;
__u16 proto_l3;
__u8 proto_l4;
__u16 offset_l3;
__u16 offset_l4;
__u16 offset_l5;
__u16 offset_ip_opts;
struct flow_id flow_id;
struct flow_info flow_info;
struct tcp_options_words tcp_opts;
int pkts = 0;
/************************************************************************************************************************/
/* structs */

/* maps */
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, MAX_FLOWS);
//     __type(key, struct flow_id);
// 	__type(value, struct flow_info);
// } flow_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, MAX_PROGS);
	__type(key, int);
	__type(value, int);
} jmp_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} pkts_map SEC(".maps");


/* entry program */
PROG(START_PROGRAM)
int bpflowmon(struct xdp_md *ctx)
{
    // ts = bpf_ktime_get_ns();

    // proto_l3 = 0;   //init with 0 to avoid conflicts with assignments of previous program runs
    // proto_l4 = 0;   //init with 0 to avoid conflicts with assignments of previous program runs
    // offset_l3 = 0;
    // offset_l4 = 0;
    // offset_l5 = 0;
    // flow_id.saddr.v4 = 0;
    // flow_id.sport = 0;
    // flow_id.daddr.v4 = 0;
    // flow_id.dport = 0;
    // flow_id.proto = 0;

    void *data, *data_end;
    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    int key = 0;
    pkts++;
    
    int *pakete;
    pakete = bpf_map_lookup_elem(&pkts_map, &key);
    if (!pakete)
        return XDP_DROP;
    *pakete = *pakete + 1;
    
    bpf_map_update_elem(&pkts_map, &key, pakete, BPF_ANY);
    
    // return action;
    return XDP_PASS;
}