//#include "vmlinux.h"          //all kernel types
#include "bpflowmon.h"          //includes also vmlinux.h
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// #include <linux/bpf.h>
#include "stringify.h"
#include "bpflowmon_defs.h"

#define PROG(F) SEC("xdp/"__stringify(F))   //from sockex3

/* License must be GPL */
char LICENSE[] SEC("license") = "GPL";

#ifndef memcpy
    #define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

// #define __DEBUG__
// #define __VERBOSE__
// #define __FLOW_TCP_OPTS__
// #define __PERFORM_DPI__

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

__u32 pkts = 0;
__u32 err_pkts = 0;
/************************************************************************************************************************/
/* structs */

/* maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_id);
	__type(value, struct flow_info);
} flow_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, MAX_PROGS);
	__type(key, int);
	__type(value, int);
} jmp_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
	__type(value, struct flow_id);
} dpi_scratch_buffer SEC(".maps");

#ifdef __PERFORM_DPI__
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_id);
	__type(value, struct dns_info);
} dns_stats SEC(".maps");
#endif

/************************************************************************************************************************/
/* helper functions */

/* Lookup jump table key by the given protocol id. Can be used if more control over the fall-through is desired. */
static __always_inline int get_prog_key_by_proto(__u16 proto)
{
    switch (proto) {
        case ETH_P_802_3:
            return 1;
        default:
            return -1;
    }
}

/* Tail calls the next parser by looking up the assigned key for proto and tail calling the program */
static __always_inline void parse_l3_protocol(struct xdp_md *ctx, __u16 proto)
{
    switch (proto) {
        case ETH_P_802_3:
            bpf_tail_call(ctx, &jmp_table, ETHERNET);
            break;
        case ETH_P_IP:
            bpf_tail_call(ctx, &jmp_table, IP);
            break;
        case ETH_P_IPV6:
            bpf_tail_call(ctx, &jmp_table, IPV6);
            break;
        default:
            break;
    }
    /* fall through */
    bpf_tail_call(ctx, &jmp_table, EXIT);
}

/* Tail calls the next parser by looking up the assigned key for proto and tail calling the program */
static __always_inline void parse_l4_protocol(struct xdp_md *ctx, __u8 proto)
{
    switch (proto) {
        case IPPROTO_ICMP:
            bpf_tail_call(ctx, &jmp_table, ICMP);
            break;
        case IPPROTO_ICMPV6:
            bpf_tail_call(ctx, &jmp_table, ICMPV6);
            break;
        case IPPROTO_TCP:
            bpf_tail_call(ctx, &jmp_table, TCP);
            break;
        case IPPROTO_UDP:
            bpf_tail_call(ctx, &jmp_table, UDP);
            break;
        default:
            break;
    }
    /* fall through */
    bpf_tail_call(ctx, &jmp_table, EXIT);
}

// static __always_inline void parse_next_layer_protocol(struct xdp_md *ctx, __u8 proto)
// {
//     parse_l3_protocol(ctx, proto);
//     parse_l4_protocol(ctx, proto);
// }

/* Finishes parsing by tail calling deep packet inspection or exit program. Returns -1 if it fails */
static __always_inline int finish_parsing(struct xdp_md *ctx)
{
    // bpf_tail_call(ctx, &jmp_table, DEEP_PACKET_INSPECTION);
    bpf_tail_call(ctx, &jmp_table, FLOW_ID_FINISH);           //will be called if userspace didn't set DPI support
    return -1;
}


/************************************************************************************************************************/
/* entry program */
/************************************************************************************************************************/

/* entry program */
PROG(START_PROGRAM)
int bpflowmon(struct xdp_md *ctx)
{
    /******************************D E B U G******************************/
    #ifdef __VERBOSE__
    bpf_printk("--------------------s-t-a-r-t--------------------\n");
    #endif
    #ifdef __VERBOSE__
    //bpf_printk("---BPF DEBUG--- INFO: start\n");
    #endif
    /*********************************************************************/
    ts = bpf_ktime_get_ns();
    action = DEFAULT_XDP_ACTION;
    
    union ip_addr v6 = { 0 };
    struct flow_id id = { 0 };
    proto_l3 = 0;  
    proto_l4 = 0;
    offset_l3 = 0;
    offset_l4 = 0;
    offset_l5 = 0;

    flow_id = id;

    /* tail call first parser */
    bpf_tail_call(ctx, &jmp_table, FIRST_PARSER);   //@TODO use map / global variable to set first_parser from user space to allow other l2 protocols
    bpf_tail_call(ctx, &jmp_table, EXIT);

    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- ERROR: Tail call failed: FIRST_PARSER\n\n");
    #endif   
    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif
    return DEFAULT_XDP_FAIL_ACTION;
}

/************************************************************************************************************************/
/* Layer 2 */
/************************************************************************************************************************/
/* ethernet header parser */

static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == ETH_P_8021Q ||
                  h_proto == ETH_P_8021AD);
}

/* ethhdr parser */
PROG(ETHERNET)
int parse_ethhdr(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting header parsing: ETHERNET\n");
    #endif

    int i;
    void *data, *data_end;
    __u16 proto;
    struct ethhdr *eth;
    struct vlan_hdr *vlh;
    unsigned char macbuf[6];

    #ifdef __VERBOSE__
    char src[7], dst[7];
    #endif
    
    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    // eth = data + offset;
    eth = data;

    /* bounds check - eth */
    if ((void *)(eth + 1) > data_end){
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: Bounds check failed - header + sizeof(etthhdr) > data_end\n");
        #endif
        return DEFAULT_XDP_FAIL_ACTION;
	}

    vlh = (void *) (eth + 1);
    proto = bpf_ntohs(eth->h_proto);
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: layer 3 proto = %d\n", (int) proto);
    #endif

    #pragma unroll
    for (i = 0; i < VLAN_MAX_DEPTH; i++) {  //in case VLAN_MAX_DEPTH iterations are done, and next header is still vlan, the bpf_tail_call(proto) fails, so the fall thorugh can handle that
            #ifdef __VERBOSE__
            bpf_printk("---BPF DEBUG--- INFO: parsing vlan header\n");
            #endif
        if (!proto_is_vlan(proto))
            break;
        if ((void *)(vlh + 1) > data_end) {
            #ifdef __DEBUG__
            bpf_printk("---BPF DEBUG--- ERROR: vlan header\n");
            #endif
            return DEFAULT_XDP_FAIL_ACTION;
        }
        proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);

        vlh++;
    }

    offset_l3 = sizeof(*eth) + i * sizeof(struct vlan_hdr);
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: offset = %d\n", offset_l3);
    #endif

    #ifdef __VERBOSE__
    memcpy(src, eth->h_source, 6);
    memcpy(dst, eth->h_dest, 6);
    src[6] = '\0';
    dst[6] = '\0';

    bpf_printk("---BPF DEBUG--- INFO: src mac = \n");
    for (int i =0; i<6; i++)
        bpf_printk("%x\n", src[i] & 0xff);
    bpf_printk("---BPF DEBUG--- INFO: dst mac = \n");
    for (int i =0; i<6; i++)
        bpf_printk("%x\n", dst[i] & 0xff);
    #endif

    /* set MAC address (change dest and src) */
    macbuf[0] = eth->h_dest[0];
    macbuf[1] = eth->h_dest[1];
    macbuf[2] = eth->h_dest[2];
    macbuf[3] = eth->h_dest[3];
    macbuf[4] = eth->h_dest[4];
    macbuf[5] = eth->h_dest[5];

    eth->h_dest[0] = eth->h_source[0];
    eth->h_dest[1] = eth->h_source[1];
    eth->h_dest[2] = eth->h_source[2];
    eth->h_dest[3] = eth->h_source[3];
    eth->h_dest[4] = eth->h_source[4];
    eth->h_dest[5] = eth->h_source[5];

    eth->h_source[0] = macbuf[0];
    eth->h_source[1] = macbuf[1];
    eth->h_source[2] = macbuf[2];
    eth->h_source[3] = macbuf[3];
    eth->h_source[4] = macbuf[4];
    eth->h_source[5] = macbuf[5];

    proto_l3 = proto;

    #ifdef __VERBOSE__
    long pkt_size = data_end - data;
    bpf_printk("---BPF DEBUG--- INFO: pkt_size = %ld\n", pkt_size);
    #endif

    /* tail call next proto parser */
    parse_l3_protocol(ctx, proto);

    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- INFO: L3 protocol not supported: %d\n", proto);
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif
    return DEFAULT_XDP_FAIL_ACTION;
}

/************************************************************************************************************************/
/* Layer 3 */
/************************************************************************************************************************/

/* IP4 parser */
PROG(IP)
int parse_ip4(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting header parsing: IP\n");
    #endif

    int err, hdrsize, action=0, key=0;
    __u8 proto;
    void *data, *data_end;
    struct iphdr *iph_p;

    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    /* check that offset is not too big (to avoid trouble with the verifier) */
    if (offset_l3 > MAX_OFFSET_ETHERNET)
        return DEFAULT_XDP_FAIL_ACTION;

    /* header */
    iph_p = data + offset_l3;

    /* bounds check - iph */
    if ((void *)(iph_p + 1) > data_end){
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: Bounds check failed - header + sizeof(iph) > data_end\n");
        #endif
        return DEFAULT_XDP_FAIL_ACTION;
	}

    /* proto (to tail call next prog) */
    proto = iph_p->protocol;

    /* header size */
    hdrsize = iph_p->ihl * 4;
    if (hdrsize < sizeof(*iph_p)) {
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: iph sanity check\n");
        #endif
        return DEFAULT_XDP_FAIL_ACTION;
    }

    /* options offset */
    if (hdrsize > 20)
        offset_ip_opts = offset_l3 + 20;

    offset_l4 = offset_l3 + hdrsize;
    
    /**********HEADER PARSING**********/
    flow_id.saddr.v4 = iph_p->saddr;
    flow_id.daddr.v4 = iph_p->daddr;
    flow_id.proto    = proto;
    /*********************************/
    proto_l4 = proto;

    /* tail call next proto parser */
    parse_l4_protocol(ctx, proto);
    bpf_tail_call(ctx, &jmp_table, FLOW_ID_FINISH);

    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- INFO: L4 protocol not supported: %d\n", proto);
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif

    return DEFAULT_XDP_FAIL_ACTION;
}


/* IPv6 parser */
PROG(IPV6)
int parse_ip6(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting header parsing: IPv6\n");
    #endif

    int err, i, key=0;
    __u8 proto;
    void *data, *data_end;
    struct ipv6hdr *ip6h_p;

    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    /* check that offset is not too big (to avoid trouble with the verifier) */
    if (offset_l4 > MAX_OFFSET_ETHERNET)
        return DEFAULT_XDP_FAIL_ACTION;
    
    /* header */
    ip6h_p = data + offset_l4;

    /* bounds check - iph */
    if ((void *)(ip6h_p + 1) > data_end){
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: Bounds check failed - header + sizeof(ip6h) > data_end\n");
        #endif
        return DEFAULT_XDP_FAIL_ACTION;
	}

    proto = ip6h_p->nexthdr;
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: layer 4 proto = %d\n", proto);
    #endif

    offset_l4 = offset_l3 + sizeof(struct ipv6hdr);
    
    /**********HEADER PARSING**********/
    memcpy(flow_id.saddr.v6, ip6h_p->saddr.in6_u.u6_addr8, 16);
    memcpy(flow_id.daddr.v6, ip6h_p->daddr.in6_u.u6_addr8, 16);
    flow_id.proto = proto;
    /*********************************/
    proto_l4 = proto;

    /* tail call next proto parser */
    parse_l4_protocol(ctx, proto);
    bpf_tail_call(ctx, &jmp_table, FLOW_ID_FINISH);

    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- INFO: L4 protocol not supported: %d\n", proto);
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif

    return DEFAULT_XDP_FAIL_ACTION;
}

/************************************************************************************************************************/
/* Layer 4 */
/************************************************************************************************************************/

/* UDP parser */
PROG(UDP)
int parse_udp(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting header parsing: UDP\n");
    #endif

    int err, key=0;
    void *data, *data_end;
    struct udphdr *udph_p;

    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    /* check that offset is not too big (to avoid trouble with the verifier) */
    if (offset_l4 > MAX_OFFSET_ETHERNET)
        return DEFAULT_XDP_FAIL_ACTION;
    
    /* header */
    udph_p = data + offset_l4;

    /* bounds check - udph */
    if ((void *)(udph_p + 1) > data_end){
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: Bounds check failed - header + sizeof(udph) > data_end\n");
        #endif
        return DEFAULT_XDP_FAIL_ACTION;
	}


    /**********HEADER PARSING**********/
    flow_id.sport = udph_p->source;
    flow_id.dport = udph_p->dest;
    /*********************************/

    offset_l5 = offset_l4 + sizeof(*udph_p);

    /* tail cal dpi or exit */
    finish_parsing(ctx);
    
    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- INFO: DPI not supported\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif

    return DEFAULT_XDP_FAIL_ACTION;
}


/* TCP parser */
PROG(TCP)
int parse_tcp(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting header parsing: TCP\n");
    #endif

    int i, err, key=0;
    __u16 offset_options;
    __u8 hdrlen;
    void *data, *data_end;
    struct tcphdr *tcph_p;
    __u32 *options;
    unsigned short options_len;
    struct tcp_options_words opt_wrd = { 0 };

    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    /* check that offset is not too big (to avoid trouble with the verifier) */
    if (offset_l4 > MAX_OFFSET_ETHERNET)
        return DEFAULT_XDP_FAIL_ACTION;
    
    /* header */
    tcph_p = data + offset_l4;

    /* bounds check - tcph */
    if ((void *)(tcph_p + 1) > data_end){
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: Bounds check failed - header + sizeof(tcph) > data_end\n");
        #endif
        return DEFAULT_XDP_FAIL_ACTION;
	}

    /* options */
    hdrlen = tcph_p->doff * 4;
    if (hdrlen > sizeof(struct tcphdr)) {
        options_len = hdrlen - sizeof(struct tcphdr);
        offset_options = offset_l4 + sizeof(struct tcphdr);
        #ifdef __FLOW_TCP_OPTS__
        options = data + offset_options;
        #ifdef __VERBOSE__
        bpf_printk("---BPF DEBUG--- INFO: TCP parsing, options len: %d\n", options_len);
        #endif

        switch(options_len)   //my loop and memcpy tries caused too much verifier complains.
        {
            case 40:
                if ((void *)(options + 10) > data_end) {
                    #ifdef __DEBUG__
                    bpf_printk("---BPF DEBUG--- ERROR: tcp options\n");
                    #endif
                    return DEFAULT_XDP_FAIL_ACTION;
                }
                opt_wrd.option_words[36] = *(options+9);
            case 36:
                if ((void *)(options + 9) > data_end){
                    #ifdef __DEBUG__
                    bpf_printk("---BPF DEBUG--- ERROR: tcp options\n");
                    #endif
                    return DEFAULT_XDP_FAIL_ACTION;
                }
                opt_wrd.option_words[32] = *(options+8);
            case 32:
                if ((void *)(options + 8) > data_end){
                    #ifdef __DEBUG__
                    bpf_printk("---BPF DEBUG--- ERROR: tcp options\n");
                    #endif
                    return DEFAULT_XDP_FAIL_ACTION;
                }
                opt_wrd.option_words[28] = *(options+7);
            case 28:
                if ((void *)(options + 7) > data_end){
                    #ifdef __DEBUG__
                    bpf_printk("---BPF DEBUG--- ERROR: tcp options\n");
                    #endif
                    return DEFAULT_XDP_FAIL_ACTION;
                }
                opt_wrd.option_words[24] = *(options+6);
            case 24:
                if ((void *)(options + 6) > data_end){
                    #ifdef __DEBUG__
                    bpf_printk("---BPF DEBUG--- ERROR: tcp options\n");
                    #endif
                    return DEFAULT_XDP_FAIL_ACTION;
                }
                opt_wrd.option_words[20] = *(options+5);
            case 20:
                if ((void *)(options + 5) > data_end){
                    #ifdef __DEBUG__
                    bpf_printk("---BPF DEBUG--- ERROR: tcp options\n");
                    #endif
                    return DEFAULT_XDP_FAIL_ACTION;
                }
                opt_wrd.option_words[16] = *(options+4);
            case 16:
                if ((void *)(options + 4) > data_end){
                    #ifdef __DEBUG__
                    bpf_printk("---BPF DEBUG--- ERROR: tcp options\n");
                    #endif
                    return DEFAULT_XDP_FAIL_ACTION;
                }
                opt_wrd.option_words[12] = *(options+3);
            case 12:
                if ((void *)(options + 3) > data_end){
                    #ifdef __DEBUG__
                    bpf_printk("---BPF DEBUG--- ERROR: tcp options\n");
                    #endif
                    return DEFAULT_XDP_FAIL_ACTION;
                }
                opt_wrd.option_words[8] = *(options+2);
            case 8:
                if ((void *)(options + 2) > data_end){
                    #ifdef __DEBUG__
                    bpf_printk("---BPF DEBUG--- ERROR: tcp options\n");
                    #endif
                    return DEFAULT_XDP_FAIL_ACTION;
                }
                opt_wrd.option_words[4] = *(options+1);
            case 4:
                if ((void *)(options + 1) > data_end){
                    #ifdef __DEBUG__
                    bpf_printk("---BPF DEBUG--- ERROR: tcp options\n");
                    #endif
                    return DEFAULT_XDP_FAIL_ACTION;
                }
                opt_wrd.option_words[0] = *(options);
                break;
            default:
                break;
        }
        #endif
    }
    // note: (options is a multiple of 4 byte)

    /**********HEADER PARSING**********/
    flow_id.sport = tcph_p->source;
    flow_id.dport = tcph_p->dest;
    #ifdef __FLOW_TCP_OPTS__
    tcp_opts = opt_wrd;
    #endif
    /*********************************/

    offset_l5 = offset_l4 + hdrlen;

    /* tail cal dpi or exit */
    finish_parsing(ctx);

    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- INFO: DPI not supported\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif

    return DEFAULT_XDP_FAIL_ACTION;
}


/* ICMP parser */
PROG(ICMP)
int parse_icmp(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting header parsing: ICMP\n");
    #endif

    int err, hdrsize, key=0;
    __u8 type;
    void *data, *data_end;
    struct icmphdr *icmph_p;

    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    /* check that offset is not too big (to avoid trouble with the verifier) */
    if (offset_l4 > MAX_OFFSET_ETHERNET)
        return DEFAULT_XDP_FAIL_ACTION;
    
    /* header */
    icmph_p = data + offset_l4;

    /* bounds check - icmph */
    if ((void *)(icmph_p + 1) > data_end){
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: Bounds check failed - header + sizeof(icmph) > data_end\n");
        #endif
        return DEFAULT_XDP_FAIL_ACTION;
	}

    /**********HEADER PARSING**********/
    //TODO maybe not suitable for flow monitoring
    if (icmph_p->type == ICMP_ECHOREPLY || icmph_p->type == ICMP_ECHO)
        flow_id.dport = icmph_p->un.echo.id;
    else
        flow_id.dport = icmph_p->code;
    flow_id.sport = icmph_p->type;
    /*********************************/

    /* tail cal dpi or exit */
    finish_parsing(ctx);
    
    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- INFO: DPI not supported\n");
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif
    return DEFAULT_XDP_FAIL_ACTION;
}


/* ICMPv6 parser */
PROG(ICMPV6)
int parse_icmpv6(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting header parsing: ICMPv6\n");
    #endif

    int err, hdrsize, key=0;
    __u8 type;
    void *data, *data_end;
    struct icmp6hdr *icmp6h_p;

    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    /* check that offset is not too big (to avoid trouble with the verifier) */
    if (offset_l4 > MAX_OFFSET_ETHERNET)
        return DEFAULT_XDP_FAIL_ACTION;
    
    /* header */
    icmp6h_p = data + offset_l4;

    /* bounds check - icmp6h */
    if ((void *)(icmp6h_p + 1) > data_end){
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: Bounds check failed - header + sizeof(icmp6h) > data_end\n");
        #endif
        return DEFAULT_XDP_FAIL_ACTION;
	}

    /**********HEADER PARSING**********/
    //TODO maybe not suitable for flow monitoring 
    if (icmp6h_p->icmp6_type == ICMPV6_ECHO_REPLY || icmp6h_p->icmp6_type == ICMPV6_ECHO_REQUEST)
        flow_id.dport = icmp6h_p->icmp6_dataun.u_echo.identifier;
    else
        flow_id.dport = icmp6h_p->icmp6_code;
    flow_id.sport = icmp6h_p->icmp6_type;
    /*********************************/

    /* tail cal dpi or exit */
    finish_parsing(ctx);

    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- ERROR: tail call failed\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif
    return DEFAULT_XDP_FAIL_ACTION;
}

/* Writes header values into flow_info */
//copied from tc_flowmon
static __always_inline int update_frame_stats()
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: first seen: %lu\n", ts);
    #endif
	flow_info.pkts++;
	if( flow_info.first_seen == 0 ) {
		flow_info.first_seen = ts;
		flow_info.jitter = 0;
	}
	else
		flow_info.jitter += ts - flow_info.last_seen;

	flow_info.last_seen = ts;

	return 1;
}

/* update the stats in flow_info with the info from the new header */
//copied from tc_flowmon
static __always_inline void ip4_update_stats(struct iphdr *iph, struct flow_info *stats)
{
    int idx, len;
    __u8 ttl;

    len = bpf_ntohs(iph->tot_len);
    ttl = iph->ttl;

    stats->version  = iph->version;
    stats->tos      = iph->tos;
    stats->bytes   += len;

    if( len < stats->min_pkt_len) 
		stats->min_pkt_len = len;
	if( len > stats->max_pkt_len )
		stats->max_pkt_len = len;
	switch ( len ) {
		case 0 ... 127:
			idx = 0;
			break;
		case 128 ... 255:
			idx = 1;
			break;
		case 256 ... 511:
			idx = 2;
			break;
		case 512 ... 1023:
			idx = 3;
			break;
		case 1024 ... 1513:
			idx = 4;
			break;
		default:
			idx = 5;
	}
	stats->pkt_size_hist[idx]++;

    if( ttl < stats->min_ttl) 
		stats->min_ttl = ttl;
	if( ttl > stats->max_ttl )
		stats->max_ttl = ttl;
	switch ( ttl ) {
		case 1:
			idx = 0;
			break;
		case 2 ... 5:
			idx = 1;
			break;
		case 6 ... 32:
			idx = 2;
			break;
		case 33 ... 64:
			idx = 3;
			break;
		case 65 ... 96:
			idx = 4;
			break;
		case 97 ... 128:
			idx = 5;
			break;
		case 129 ... 160:
			idx = 6;
			break;
		case 161 ... 192:
			idx = 7;
			break;
		case 193 ... 224:
			idx = 8;
			break;
		case 225 ... 255:
			idx = 9;
	}
	stats->pkt_ttl_hist[idx]++;
}

/* update the stats in flow_info with the info from the new header */
//copied from tc_flowmon
static __always_inline void ip6_update_stats(struct ipv6hdr *ip6h, struct flow_info *stats)
{
    int i, idx, len, fl;
    __u8 ttl;

    len = bpf_ntohs(ip6h->payload_len) + 40;
    ttl = ip6h->hop_limit;

    stats->version  = ip6h->version;
    stats->tos      = ip6h->priority;
    stats->bytes   += len;

    for(int i=0; i<3; i++)
    {
        fl &= ip6h->flow_lbl[i];
        if(i < 2)
            fl << 8;
    }
    stats->fl = fl;

    if( len < stats->min_pkt_len) 
		stats->min_pkt_len = len;
	if( len > stats->max_pkt_len )
		stats->max_pkt_len = len;
	switch ( len ) {
		case 0 ... 127:
			idx = 0;
			break;
		case 128 ... 255:
			idx = 1;
			break;
		case 256 ... 511:
			idx = 2;
			break;
		case 512 ... 1023:
			idx = 3;
			break;
		case 1024 ... 1513:
			idx = 4;
			break;
		default:
			idx = 5;
	}
	stats->pkt_size_hist[idx]++;

    if( ttl < stats->min_ttl) 
		stats->min_ttl = ttl;
	if( ttl > stats->max_ttl )
		stats->max_ttl = ttl;
	switch ( ttl ) {
		case 1:
			idx = 0;
			break;
		case 2 ... 5:
			idx = 1;
			break;
		case 6 ... 32:
			idx = 2;
			break;
		case 33 ... 64:
			idx = 3;
			break;
		case 65 ... 96:
			idx = 4;
			break;
		case 97 ... 128:
			idx = 5;
			break;
		case 129 ... 160:
			idx = 6;
			break;
		case 161 ... 192:
			idx = 7;
			break;
		case 193 ... 224:
			idx = 8;
			break;
		case 225 ... 255:
			idx = 9;
	}
	stats->pkt_ttl_hist[idx]++;
}

/* tcp options parser */
//copied from tc_flowmon
//got paranoid of verifier complains about invalid map access and variable stack access, so some if statements could optimized away
#ifdef __FLOW_TCP_OPTS__
static __always_inline int parse_tcpopt(struct tcphdr *tcph, __u8 opt_wrds[MAX_OPTS], struct optvalues value)
{
	short op_tot_len = 0;   //changed to short, so it can be < 0
	unsigned short last_op = 0;
	struct tcp_opt_mss *mss = 0;
	struct tcp_opt_wndw_scale *wndw_scale = 0;
	struct tcp_opt_sackp *sackp = 0;
	struct tcp_opt_sack *sack = 0;
	struct tcp_opt_ts *ts = 0;
    struct general_opt *opt = 0;
	unsigned int offset = 0;
	__u8 type;
    struct tcp_opt_none *opn;

	op_tot_len = (short) ((tcph->doff - 5)*4);
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: options parser tcph len: %d\n", tcph->doff);
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: options parser options_len: %d\n", op_tot_len);
    #endif
	if( op_tot_len <= 0 )
		return -2;

    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: options parser found options\n");
    #endif
	
	 /* loop over options */
	for(unsigned int i=0; i<40; i++)
	{
        #ifdef __VERBOSE__
        bpf_printk("---BPF DEBUG--- INFO: options parser loop: %d\n",i);
        #endif

        if (offset < 0 || offset > MAX_OPTS-1)
            return -1;
        opn = (struct tcp_opt_none *)(&opt_wrds[offset]);
        if ((void*) (opn+1) > (void*) (&opt_wrds[MAX_OPTS-1]) ||
            (void*) opn > (void*) (&opt_wrds[MAX_OPTS-1]) ||
            (void*) opn < (void*) opt_wrds)
            return -1;
        if( opn+1 > &opt_wrds[MAX_OPTS-1])
            return -1;
        type = opn->type;
        
        #ifdef __VERBOSE__
        bpf_printk("---BPF DEBUG--- INFO: options parser loop type: %d\n", type);
        #endif
        switch ( type ) {
            case TCP_OPT_END:
                last_op = 1;
                break;
            case TCP_OPT_NONE:
                offset++;
                op_tot_len--;
                break;
            case TCP_OPT_MSS:
                mss = (struct tcp_opt_mss *)(&opt_wrds[offset]);
                if( mss+1 > &opt_wrds[MAX_OPTS-1])
                    return -1;
                offset+=mss->len;
                if (offset < 0 || offset > MAX_OPTS-1)
                    return -1;
                op_tot_len-=(short) mss->len;
                if( mss+1 > &opt_wrds[MAX_OPTS-1] || mss < &opt_wrds || mss > &opt_wrds[MAX_OPTS-1])
                    return -1;
                *value.mss = bpf_ntohs(mss->data);
                #ifdef __VERBOSE__
                bpf_printk("---BPF DEBUG--- INFO: mss: %d\n", mss->data);
                #endif
                break;
            case TCP_OPT_WNDWS:
                wndw_scale = (struct tcp_opt_wndw_scale *)(&opt_wrds[offset]);
                if( wndw_scale+1 > &opt_wrds[MAX_OPTS-1])
                    return -1;
                offset+=wndw_scale->len;
                if (offset < 0 || offset > MAX_OPTS-1)
                    return -1;
                op_tot_len-=(short) wndw_scale->len;
                if( wndw_scale+1 > &opt_wrds[MAX_OPTS-1])
                    return -1;
                *value.wndw_scale = wndw_scale->data;
                break;
            case TCP_OPT_SACKP:
                sackp = (struct tcp_opt_sackp *)(&opt_wrds[offset]);
                if( sackp+1 > &opt_wrds[MAX_OPTS-1])
                    return -1;
                offset+=sackp->len;
                if (offset < 0 || offset > MAX_OPTS-1)
                    return -1;
                op_tot_len-=(short) sackp->len;
                // No data read for this option
                break;
            case TCP_OPT_SACK:
                sack = (struct tcp_opt_sack *)(&opt_wrds[offset]);
                if( sack+1 > &opt_wrds[MAX_OPTS-1])
                    return -1;
                offset+=sack->len;
                if (offset < 0 || offset > MAX_OPTS-1)
                    return -1;
                op_tot_len-=(short) sack->len;
                // No data read for this option
                break;
            case TCP_OPT_TS:
                ts = (struct tcp_opt_ts *)(&opt_wrds[offset]);
                if( ts+1 > &opt_wrds[MAX_OPTS-1])
                    return -1;
                offset+=ts->len;
                if (offset < 0 || offset > MAX_OPTS-1)
                    return -1;
                op_tot_len-=(short) ts->len;
                // No data read for this option
                break;
            default:
                opt = (struct general_opt *)(&opt_wrds[offset]);    // to also loop over unknown options to find known options behind them
                if( opt+1 > &opt_wrds[MAX_OPTS-1])
                    return op_tot_len;
                offset += opt->len;
                op_tot_len -=(short) opt->len;
                // last_op = 1;
                break;

        }

		if ( last_op || op_tot_len <= 0)
			break;
	}

	return op_tot_len;
}
#endif

//copied from tc_flowmon
static __always_inline void tcp_update_stats(struct tcphdr *tcph, struct flow_info *stats, __u8 opt_wrds[])
{
    __u16 flags;
    __u32 window;
    unsigned int opt_tot_len;
    
    /* flags */
    union tcp_word_hdr *twh = (union tcp_word_hdr *) tcph;
	flags = bpf_ntohl(twh->words[3] & bpf_htonl(0x00FF0000)) >> 16;
	stats->cumulative_flags |= flags;

    /* window */
    window = bpf_ntohs(tcph->window) << stats->wndw_scale;
	if( window < stats->min_win_bytes )
		stats->min_win_bytes = window;
	if( window > stats->max_win_bytes)
		stats->max_win_bytes = window;
    
    /* options */
    #ifdef __FLOW_TCP_OPTS__
    struct optvalues opt_val;
    int op_tot_len = 0;
	opt_val.mss = &stats->mss;
	opt_val.wndw_scale = &stats->wndw_scale;
	op_tot_len = parse_tcpopt(tcph, opt_wrds, opt_val);
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: tcp_update return: %d\n", op_tot_len);
    #endif

	if( op_tot_len > 0 )
		stats->all_options_parsed = 0;
    #endif //__FLOW_TCP_OPTS__
}

/* set ethernet destination and source mac address depending on the destination ip address to forward packets */
static __always_inline int set_ethaddr(struct xdp_md *ctx, int ip_version, void *daddr, int *action)
{
    void *data =     (void *)(unsigned long) ctx->data;
    void *data_end = (void *)(unsigned long) ctx->data_end;
    struct ethhdr *eth = data;

    if ((void*)(eth+1) > data_end)
        return DEFAULT_XDP_FAIL_ACTION;
    
    /* dst mac */
    if (ip_version == 4)
    {
        // switch(*(__be32 *) daddr)
        // {
        //     case 33554442:  //10.0.0.2
        //         eth->h_dest[0] = 0x08;
        //         eth->h_dest[1] = 0x00;
        //         eth->h_dest[2] = 0x27;
        //         eth->h_dest[3] = 0xF4;
        //         eth->h_dest[4] = 0xAE;
        //         eth->h_dest[5] = 0x30;
        //         *action = XDP_TX;
        //         break;
        //     case 50331658:  //10.0.0.3
        //         eth->h_dest[0] = 0x08;
        //         eth->h_dest[1] = 0x00;
        //         eth->h_dest[2] = 0x27;
        //         eth->h_dest[3] = 0x06;
        //         eth->h_dest[4] = 0x47;
        //         eth->h_dest[5] = 0xD9;
        //         *action = XDP_TX;
        //         break;
        //     case 16777226:  //10.0.0.1 (this machine)
        //         *action = XDP_PASS;
        //         break;
        //     default:
        //         break;
        // }
    }
    else if (ip_version == 6)
    {

    }

    // eth->h_dest[0] = 0xB8;
    // eth->h_dest[1] = 0xCE;
    // eth->h_dest[2] = 0xF6;
    // eth->h_dest[3] = 0x04;
    // eth->h_dest[4] = 0x8B;
    // eth->h_dest[5] = 0x70;

    /* src mac */
    //since the test machines are configured to route the traffic via this machine, editing the src is not necessary
    
    return 0;
}

static __always_inline void parse_l3_protocol_info(struct xdp_md *ctx)
{
    switch (proto_l3) {
        // case ETH_P_802_3:
        //     bpf_tail_call(ctx, &jmp_table, ETHERNET);
        //     break;
        case ETH_P_IP:
            bpf_tail_call(ctx, &jmp_table, IP_INFO);
            break;
        case ETH_P_IPV6:
            bpf_tail_call(ctx, &jmp_table, IPV6_INFO);
            break;
        default:
            break;
    }
    /* fall through */
    // bpf_tail_call(ctx, &jmp_table, FALL_THROUGH);   //if a protocol is not set from user space, the fall_through program is called to avoid adding data to the flow_stats map for this packet
    bpf_tail_call(ctx, &jmp_table, EXIT);
}

static __always_inline void parse_l4_protocol_info(struct xdp_md *ctx)
{
    switch (proto_l4) {
        case IPPROTO_ICMP:
            bpf_tail_call(ctx, &jmp_table, FLOW_INFO_FINISH);
            break;
        case IPPROTO_ICMPV6:
            bpf_tail_call(ctx, &jmp_table, FLOW_INFO_FINISH);
            break;
        case IPPROTO_TCP:
            bpf_tail_call(ctx, &jmp_table, TCP_INFO);
            break;
        case IPPROTO_UDP:
            bpf_tail_call(ctx, &jmp_table, FLOW_INFO_FINISH);
            break;
        default:
            break;
    }
    /* fall through */
    // bpf_tail_call(ctx, &jmp_table, FALL_THROUGH);   //if a protocol is not set from user space, the fall_through program is called to avoid adding data to the flow_stats map for this packet
    bpf_tail_call(ctx, &jmp_table, EXIT);
}


static __always_inline void start_info_parsing(struct xdp_md *ctx)
{
    parse_l3_protocol_info(ctx);
}

static __always_inline void finish_info_parsing(struct xdp_md *ctx)
{
    bpf_tail_call(ctx, &jmp_table, FLOW_INFO_FINISH);
}

PROG(IP_INFO)
int parse_ip_info(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting header parsing: IP_INFO\n");
    #endif

    int err, hdrsize, key=0;
    __u16 options_offset;
    void *data, *data_end;
    struct iphdr *iph_p;

    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    /* check that offset is not too big (to avoid trouble with the verifier) */
    if (offset_l3 > MAX_OFFSET_ETHERNET)
        return DEFAULT_XDP_FAIL_ACTION;

    /* header */
    iph_p = data + offset_l3;

    /* bounds check - iph */
    if ((void *)(iph_p + 1) > data_end){
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: Bounds check failed - header + sizeof(iph) > data_end\n");
        #endif
        return DEFAULT_XDP_FAIL_ACTION;
	}
    
    /**********HEADER PARSING**********/
    ip4_update_stats(iph_p, &flow_info);
    /*********************************/

    /* tail call next proto parser */
    parse_l4_protocol_info(ctx);

    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- ERROR: tail call failed\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif

    return DEFAULT_XDP_FAIL_ACTION;
}

PROG(IPV6_INFO)
int parse_ipv6_info(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting header parsing: IPv6_INFO\n");
    #endif

    int err, hdrsize, key=0;
    void *data, *data_end;
    struct ipv6hdr *ipv6h_p;

    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    /* check that offset is not too big (to avoid trouble with the verifier) */
    if (offset_l3 > MAX_OFFSET_ETHERNET)
        return DEFAULT_XDP_FAIL_ACTION;

    /* header */
    ipv6h_p = data + offset_l3;

    /* bounds check - iph */
    if ((void *)(ipv6h_p + 1) > data_end){
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: Bounds check failed - header + sizeof(iph) > data_end\n");
        #endif
        return DEFAULT_XDP_FAIL_ACTION;
	}
    
    /**********HEADER PARSING**********/
    ip6_update_stats(ipv6h_p, &flow_info);
    /*********************************/

    /* tail call next proto parser */
    parse_l4_protocol_info(ctx);

    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- ERROR: tail call failed\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif

    return DEFAULT_XDP_FAIL_ACTION;
}



PROG(TCP_INFO)
int parse_tcp_info(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting header parsing: TCP_INFO\n");
    #endif

    int err, hdrsize, key=0;
    __u16 options_offset;
    void *data, *data_end;
    struct tcphdr *tcph_p;

    /* init data pointers */
    data		= (void*) (unsigned long)ctx->data;
	data_end	= (void*) (unsigned long)ctx->data_end;

    /* check that offset is not too big (to avoid trouble with the verifier) */
    if (offset_l4 > MAX_OFFSET_ETHERNET)
        return DEFAULT_XDP_FAIL_ACTION;

    /* header */
    tcph_p = data + offset_l4;

    /* bounds check - iph */
    if ((void *)(tcph_p + 1) > data_end){
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: Bounds check failed - header + sizeof(iph) > data_end\n");
        #endif
        return DEFAULT_XDP_FAIL_ACTION;
	}
    
    /**********HEADER PARSING**********/
    tcp_update_stats(tcph_p, &flow_info, tcp_opts.option_words);
    /*********************************/

    /* tail call next proto parser */
    bpf_tail_call(ctx, &jmp_table, FLOW_INFO_FINISH);

    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- ERROR: tail call failed\n");
    #endif
    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- ERROR: tail call failed - tcp -> flow_info_finish");
    #endif

    return DEFAULT_XDP_FAIL_ACTION;
}

PROG(FLOW_ID_FINISH)
int flow_id_finish(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    bpf_printk("---BPF DEBUG--- INFO: starting FLOW_ID_FINISH\n");
    #endif

    int key=0, i, ret;
    // bool valid_flow_id;
    struct flow_info *flow_info_p;
    int action = DEFAULT_XDP_ACTION;

    /* get flow_stats from map */
    flow_info_p = bpf_map_lookup_elem(&flow_stats, &flow_id);

    /* check if flow_id is valid */ //this check can fail if attached to loopback device
    // if(!flow_info_p) {
    //     valid_flow_id = false;
    //     if( flow_id.proto != 0 ||
    //         flow_id.sport != 0 ||
    //         flow_id.dport != 0 )
    //     {
    //         for(i=0; i<16; i++)
    //             if(flow_id.saddr.v6[i] != 0 || flow_id.daddr.v6[i] != 0) {
    //                 valid_flow_id = true;
    //                 break;
    //             }
    //     }
    // }

    /* init flow_info if not loaded from map */
    struct flow_info info = {0};
    if(!flow_info_p /*&& valid_flow_id*/) {
        /* fixed flow values */
        info.all_options_parsed = 1;
        info.pkts = 0;
        
        /* min flow values. */
        info.min_pkt_len   = 0xffff;
        info.min_ttl       = 0xff;
        info.min_win_bytes = 0xffff;
        
        flow_info_p = &info;
    }

    if (!flow_info_p) {
        // #ifdef __DEBUG__
        // bpf_printk("---BPF DEBUG--- ERROR: no value for flow_info\n");
        // #endif
        // bpf_tail_call(ctx, &jmp_table, EXIT);
        pkts++;
        return DEFAULT_XDP_FAIL_ACTION;
    }

    flow_info = *flow_info_p;

    start_info_parsing(ctx);

    #ifdef __DEBUG__
    bpf_printk("---BPF DEBUG--- INFO: action = %d\n", action);
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif
    return action;
}


PROG(FLOW_INFO_FINISH)
int flow_info_finish(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    bpf_printk("---BPF DEBUG--- INFO: starting FLOW_INFO_FINISH\n");
    #endif
    int err;
    pkts++;

    update_frame_stats();
    //bpf_fib_lookup()      //TODO should be used for looking up next destination in routing table
    set_ethaddr(ctx, flow_info.version, &flow_id.daddr, &action);
    flow_info.ifindex = ctx->ingress_ifindex;

    /* update flow_stats map */
    err = bpf_map_update_elem(&flow_stats, &flow_id, &flow_info, BPF_ANY);
    if (err) {
        #ifdef __DEBUG__
        bpf_printk("---BPF DEBUG--- ERROR: map update failed: flow_stats: %d\n", err);
        #endif
        err_pkts++;
    }

    bpf_tail_call(ctx, &jmp_table, DEEP_PACKET_INSPECTION);

    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif

    return action;
}

/* exit handles unsupported protocols */
PROG(EXIT)
int exit_prog(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: EXIT\n");
    #endif

    pkts++;

    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif

    return DEFAULT_XDP_PROTO_NOT_SUPPORTED_ACTION;
}




/************************************************************************************************************************/
/* Deep packet inspection */
/************************************************************************************************************************/
/* Deep packet inspection */

#ifdef __PERFORM_DPI__
/* Tail calls the program for DPI depending on the given port */
static __always_inline int perform_dpi_by_port(struct xdp_md *ctx, __be16 port)
{
    switch (bpf_ntohs(port)) {
        case 53:
            bpf_tail_call(ctx, &jmp_table, DNS);
            return -1;
        default:
            return -1;
    }
}

/* Tail calls the program for DPI if sport or dport match a known protocol (calls perform_dpi_by_port() for sport and dport)*/
static __always_inline int perform_dpi_by_ports(struct xdp_md *ctx, __be16 sport, __be16 dport)
{
    int ret = -1;
    ret = perform_dpi_by_port(ctx, sport);
    ret = perform_dpi_by_port(ctx, dport);
    return ret;
}

/* Identify the application layer protocol */
PROG(DEEP_PACKET_INSPECTION)
int deep_packet_inspection_entry(struct xdp_md *ctx)
{
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting DEEP PACKET INSPECTION\n");
    #endif
    
    // int key = 0;
    // struct flow_id *flow_id;

    // flow_id = bpf_map_lookup_elem(&dpi_scratch_buffer, &key);
    // if (!flow_id)
    //     return DEFAULT_XDP_FAIL_ACTION;

    //signature based application layer protocol detection would go here
    perform_dpi_by_ports(ctx, flow_id.sport, flow_id.dport);

    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: layer 5 proto not supported \n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif
    return action;
}

/* DNS DPI */
PROG(DNS)
int inspect_dns(struct xdp_md *ctx)
{    
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: - - - - - - - - - - - - - - - - - - - - -\n");
    #endif
    #ifdef __VERBOSE__
    bpf_printk("---BPF DEBUG--- INFO: starting deep packet inspection: DNS\n");
    #endif

    int key = 0;
    struct dns_info *dns = NULL;
    struct dns_info dns_info = {0};
    // struct flow_id *flow_id;

    // flow_id = bpf_map_lookup_elem(&dpi_scratch_buffer, &key);
    // if (!flow_id)
    //     return DEFAULT_XDP_FAIL_ACTION;
    
    dns = bpf_map_lookup_elem(&dns_stats, &flow_id);
    if (!dns)
        /* init dns_info */
        dns = &dns_info;
    /********PACKET INSPECTION********/
    //TODO inspect packet
    /*********************************/

    bpf_map_update_elem(&dns_stats, &flow_id, dns, BPF_ANY);

    #ifdef __VERBOSE__
    bpf_printk("---------------------e-n-d-e---------------------\n\n");
    #endif
    return action;
}
#endif //PERFORM_DPI