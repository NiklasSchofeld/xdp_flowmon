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

// int action;
// __u64 ts;
// __u16 proto_l3;
// __u8 proto_l4;
// __u16 offset_l3;
// __u16 offset_l4;
// __u16 offset_l5;
// __u16 offset_ip_opts;
// struct flow_id flow_id;
// struct flow_info flow_info;
// struct tcp_options_words tcp_opts;
int pkts = 0;
struct flow_info flow_info;
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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} pkts_percpu_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct flow_info);
} flow_stats_buffer SEC(".maps");


/*****************************************************************************/
/* test type */
// #define PKTS_TEST
#define FLOWINFO_TEST
/*****************************************************************************/
/* data structure */
// #define ARRAYMAP
#define GLOBVAR
// #define PERCPUARRAYMAP
/*****************************************************************************/


#ifdef PKTS_TEST

#ifdef ARRAYMAP
PROG(START_PROGRAM)
int pkt_array(struct xdp_md *ctx)
{
    void *data, *data_end;
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    int key = 0;
    
    int *pakete;
    pakete = bpf_map_lookup_elem(&pkts_map, &key);
    if (!pakete)
        return XDP_DROP;
    *pakete = *pakete + 1;
    
    bpf_map_update_elem(&pkts_map, &key, pakete, BPF_ANY);

    bpf_tail_call(ctx, &jmp_table, NEXT_PROG_MAP);
    
    return XDP_DROP;
}
#endif

#ifdef PERCPUARRAYMAP
PROG(START_PROGRAM)
int pkt_percpuarray(struct xdp_md *ctx)
{
    void *data, *data_end;
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    int key = 0;
    
    int *pakete;
    pakete = bpf_map_lookup_elem(&pkts_percpu_map, &key);
    if (!pakete)
        return XDP_DROP;
    *pakete = *pakete + 1;
    
    bpf_map_update_elem(&pkts_percpu_map, &key, pakete, BPF_ANY);

    bpf_tail_call(ctx, &jmp_table, NEXT_PROG_MAP);
    
    return XDP_DROP;
}
#endif

#ifdef GLOBVAR
PROG(START_PROGRAM)
int global_var(struct xdp_md *ctx)
{
     void *data, *data_end;
    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    pkts++;

    bpf_tail_call(ctx, &jmp_table, NEXT_PROG_GLOB);
    return XDP_DROP;
}
#endif

PROG(NEXT_PROG_MAP)
int tail_called_map(struct xdp_md *ctx)
{
    int pkt;
    int key = 0;

    int *pakete;
    #ifdef ARRAYMAP
    pakete = bpf_map_lookup_elem(&pkts_map, &key);
    #elif PERCPUARRAYMAP
    pakete = bpf_map_lookup_elem(&pkts_percpu_map, &key);
    #endif
    if (!pakete)
        return XDP_DROP;
    pkt = *pakete;

    if (pkt > 0)
        return XDP_PASS;
    else
        return XDP_DROP;
}

PROG(NEXT_PROG_GLOB)
int tail_called_glob(struct xdp_md *ctx)
{
    int pkt;

    pkt = pkts;

    if (pkt > 0)
        return XDP_PASS;
    else
        return XDP_DROP;
}
#endif

/***********************************************************************************/
/* flow_info test */
#ifdef FLOWINFO_TEST

/* map */
#ifdef ARRAYMAP
PROG(START_PROGRAM)
int info_array(struct xdp_md *ctx)
{
    struct flow_info info = {0};
    int key = 0;
    void *data, *data_end;

    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;
    
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return XDP_ABORTED;
    }

    info.cumulative_flags = 8;
    info.max_pkt_len = 2560;
    info.all_options_parsed = true;
    info.bytes = 61929;
    
    bpf_map_update_elem(&flow_stats_buffer, &key, &info, BPF_ANY);

    bpf_tail_call(ctx, &jmp_table, NEXT_PROG_MAP);
    return XDP_DROP;
}
#endif

/* globvar */
#ifdef GLOBVAR
PROG(START_PROGRAM)
int info_glob(struct xdp_md *ctx)
{
    struct flow_info info = {0};
    int key = 0;
    void *data, *data_end;

    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;
    
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return XDP_ABORTED;
    }

    info.cumulative_flags = 8;
    info.max_pkt_len = 2560;
    info.all_options_parsed = true;
    info.bytes = 61929;
    
    // bpf_map_update_elem(&flow_stats_buffer, &key, &info, BPF_ANY);
    flow_info = info;

    bpf_tail_call(ctx, &jmp_table, NEXT_PROG_MAP);
    return XDP_DROP;
}
#endif

PROG(NEXT_PROG_MAP)
int tail_called_map(struct xdp_md *ctx)
{
    int pkt;
    int key = 0;
    struct flow_info *info;

    #ifdef ARRAYMAP
    info = bpf_map_lookup_elem(&flow_stats_buffer, &key);
    #elif PERCPUARRAYMAP
    info = bpf_map_lookup_elem(&flow_stats_buffer, &key);
    #endif
    if (!info)
        return XDP_ABORTED;

    if (info->max_pkt_len == 2560)
        return XDP_PASS;
    else
        return XDP_DROP;
}

PROG(NEXT_PROG_GLOB)
int tail_called_glob(struct xdp_md *ctx)
{
    struct flow_info info;

    info = flow_info;

    if (flow_info.cumulative_flags == 8)
        return XDP_PASS;
    else
        return XDP_DROP;
}

#endif