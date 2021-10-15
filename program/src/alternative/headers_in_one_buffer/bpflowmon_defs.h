#ifndef BPFLOWMON_DEFS
    #define BPFLOWMON_DEFS

/* maximum offsets for addition with data pointer */
#define MAX_OFFSET_ETHERNET      30000          //verifier rejects data + offset if offset can be > (2^16)-1

/* default action */
#define DEFAULT_XDP_ACTION 			            2 //pass
#define DEFAULT_XDP_FAIL_ACTION		            0 //aborted
#define DEFAULT_XDP_PROTO_NOT_SUPPORTED_ACTION  2   //pass

/* application limits */
#define MAX_PROGS       255
#define MAX_FLOWS       1024
#define VLAN_MAX_DEPTH  200

/* keys for jump table programs protocols */
#define START_PROGRAM	0
#define EXIT_PROGRAM	1
#define FALL_THROUGH    2
#define DEEP_PACKET_INSPECTION 3
//layer 2
#define ETHERNET    4
//layer 3
#define IP          5
#define IPV6        6
#define ARP         20
//layer 4
#define TCP         7
#define UDP         8
#define ICMP        9
#define ICMPV6      10
//DPI
#define DNS			15

/* layer 2 protocol */
#define FIRST_PARSER ETHERNET


/* TCP options */
#define TCP_OPT_END	0
#define TCP_OPT_NONE	1
#define TCP_OPT_MSS	2
#define TCP_OPT_WNDWS	3
#define TCP_OPT_SACKP	4
#define TCP_OPT_SACK	5
#define TCP_OPT_TS	8


/* Exit return codes */
#define EXIT_OK                  0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL                1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION         2
#define EXIT_FAIL_XDP           30
#define EXIT_FAIL_BPF           40


#endif  //BPFLOWMON_DEFS