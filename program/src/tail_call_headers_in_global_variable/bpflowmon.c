#ifndef BPFLOWMON_C
#define BPFLOWMON_C
#endif
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <linux/limits.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/in.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>

#include "bpflowmon.h"
#include "bpflowmon_defs.h"
#include "flow_mgmt.h"

#include "bpflowmon.skel.h"


int verbose = 1;
static const char *default_map_filename = "/sys/fs/bpf/xdp/globals/flow_stats";
static const char *default_map_basedir = "/sys/fs/bpf/xdp/globals/";

/* long options */
static const struct option long_options[] = {
	{"verbose", 	no_argument,		NULL, 'v'},
	{"quiet",		no_argument,		NULL, 'q'},
	{"help",		no_argument,		NULL, 'h'},
	{"dev",			required_argument,	NULL, 'd'},
	{"protocols",	required_argument,	NULL, 'p'},		//comma seperated values or multiple -p
	{"mode",		required_argument,	NULL, 'm'},		//xdp mode (generic or native)
	{"DPI",			no_argument,		NULL, 'D'},		//decide if dpi should be performed
	{"Output",		required_argument,	NULL, 'O'},		//diretory where to save dumped flows (default: current dir)
	{"Log",			required_argument,	NULL, 'L'},
	{"Map",			required_argument,	NULL, 'M'},		//path to Map
	{"Folder",		required_argument,	NULL, 'F'},		//map folder
	{"interval",	required_argument,	NULL, 'i'},
	{"json",		no_argument,		NULL, 'j'},
	{"test",		required_argument,	NULL, 't'},
	{0, 0, 0, 0}
};

struct option_description {
	struct option option;
	bool required;
	char *description;
};

/* long options with help */
static const struct option_description optdesc[] = {
	{{"verbose", 	no_argument,		NULL, 'v'},	false,	"get information about flow counts [default: verbose]"},
	{{"quiet",		no_argument,		NULL, 'q'},	false,	"get no intormation [default: verbose]"},
	{{"help",		no_argument,		NULL, 'h'},	false,	"print help"},
	{{"dev",		required_argument,	NULL, 'd'},	true,	"<interface>: network devices/interfaces where the XDP BPF program is to be attached. Comma separated values"},
	{{"protocols",	required_argument,	NULL, 'p'}, false,	"<proto>: protocols to be parsed. Comma separated values"},		//comma seperated values or multiple -p
	{{"mode",		required_argument,	NULL, 'm'},	false,	"<xdp-flag>: mode for each interface. Comma separated values in same order as devices [default=skb/generic]"},		//xdp mode (generic or native)
	{{"DPI",		no_argument,		NULL, 'D'},	false,	"decide if deep packet inspection should be performed"},
	{{"Output",		required_argument,	NULL, 'O'},	false,	"<dir>: directory where to save dumped flows. [default to current dir]"},	//diretory where to save dumped flows (default: current dir)
	{{"Log",		required_argument,	NULL, 'L'},	false,	"<file>: log messages to file [default: stdout]"},
	{{"Map",		required_argument,	NULL, 'M'},	false,	"<file>: map for flow_stats that is to be reused (full path) [default: /sys/fs/bpf/xdp/globals/flow_stats"},	//path to Map
	{{"Folder",		required_argument,	NULL, 'F'},	false,	"<dir>:	Folder where the maps are to be saved (full path) [default: /sys/fs/bpf/xdp/globals/"},		//map folder
	{{"interval",	required_argument,	NULL, 'i'}, false,	"<interval>: reporting period in sec [default=1s; 0=print once and exit]"},
	{{"json",		no_argument,		NULL, 'j'},	false,	"encode flow info as json"},
	{{"test",		required_argument,	NULL, 't'},	false,	"<duration> dont start flow management and print pkt count after duration and detach xdp program"},
	{{0, 0, 0, 0}, 0}
};

#define MAX_INTERFACES 8
#define MAX_PATHLEN 512
/* parsed parameters */
struct params {
	int verbose;
	int interfaces[MAX_INTERFACES];
	int xdp_mode[MAX_INTERFACES];	
	bool protocols[MAX_PROGS];
	bool restricted_protos;
	bool map_reuse;
	bool deep_packet_inspection;
	char map_folder_path[MAX_PATHLEN];
	char map_file_path[MAX_PATHLEN];
	char dump_output_path[MAX_PATHLEN];
	char log_output_path[MAX_PATHLEN];
	bool json;
	int interval;
	int test;
	bool test_run;
};

/* set defaults for cfg */
void init_cfg(struct params *cfg)
{
	int i;

	cfg->verbose = verbose;
	for(i=0; i<MAX_INTERFACES; i++){
		cfg->interfaces[i] = 0;						//invalid interface
		cfg->xdp_mode[i] = XDP_FLAGS_SKB_MODE;		//generic mode
	}
	for(i=0; i<MAX_PROGS; i++) {
		cfg->protocols[i] = true;
	}
	cfg->restricted_protos = false;			//all protos are supported
	cfg->map_reuse = false;
	cfg->deep_packet_inspection = false;
	cfg->interval = 1;
	strcpy(cfg->map_folder_path, default_map_basedir);
	strcpy(cfg->map_file_path, default_map_filename);
	strcpy(cfg->dump_output_path, "");
	strcpy(cfg->log_output_path, "");			//stdout
	cfg->json = false;
	cfg->test_run = false;
}

/******************************************************************************************/

/* copied from tc_flowmon */
static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
			       struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return EXIT_FAIL;

        /* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return EXIT_FAIL_BPF;
	}

	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}

/* copied from tc_flowmon */
int check_map_fd(int map_fd)
{
	struct bpf_map_info map_expect = { 0 };
	struct bpf_map_info info = { 0 };

	map_expect.key_size = sizeof(struct flow_id);
	map_expect.value_size = sizeof(struct flow_info);
	map_expect.max_entries = MAX_FLOWS;
	
	return __check_map_fd_info(map_fd, &info, &map_expect);
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

/* Initialize jmp_table by placing all programs at related key */
int init_jmp_table(struct bpf_object *obj, struct params *cfg, int *main_prog_fd)
{
    int prog_fd, jmp_table_fd, key, err;
    struct bpf_program *prog;
    const char *section;
    
	cfg->protocols[FLOW_ID_FINISH] = true;		//must always be used in jump table
	cfg->protocols[EXIT] = true;				//must always be used in jump table
	cfg->protocols[FLOW_INFO_FINISH] = true;	//must always be used in jump table
	// if (cfg->restricted_protos)					//fall through only when certain protocols are set
	// 	cfg->protocols[FALL_THROUGH] = true;
	// else 
	// 	cfg->protocols[FALL_THROUGH] = false;
	if (cfg->deep_packet_inspection)
		cfg->protocols[DEEP_PACKET_INSPECTION] = true;
	else
		cfg->protocols[DEEP_PACKET_INSPECTION] = false;

    jmp_table_fd = bpf_object__find_map_fd_by_name(obj, "jmp_table");
    bpf_object__for_each_program(prog, obj) {
        prog_fd = bpf_program__fd(prog);
        section = bpf_program__section_name(prog);
        
        if (sscanf(section, "xdp/%d", &key) != 1) {
			fprintf(stderr, "ERROR: finding prog failed\n");
			return EXIT_FAIL;
		}

        if (key == START_PROGRAM) {
            *main_prog_fd = prog_fd;		//will be attached to hookpoint
        }
        else {
			if (cfg->protocols[key]) {
				err = bpf_map_update_elem(jmp_table_fd, &key, &prog_fd, BPF_ANY);
				if (err) {
					fprintf(stderr, "ERROR: adding program to jmp_table failed: err(%d)\n", err);
					return err;
				}
			}
        }
    } //end for_each_program
    
    return 0;
}

/* print one option with description */
void print_option(struct option_description *optdesc)
{
	printf("\t-%c\t", optdesc->option.val);
	printf("%s%-20s", "--", optdesc->option.name);
	printf("%s\n", optdesc->description);
}

/* print usage information (print all options with description) */
void usage(const struct option_description optdesc[])
{
	int i;
	
	printf("\n");
	printf("Required options:\n");
	for (i=0; optdesc[i].option.name != 0; ++i)
	{
		if(optdesc[i].required)
			print_option(&optdesc[i]);
	}
	printf("\n");
	printf("Optional options:\n");
	for (i=0; optdesc[i].option.name != 0; ++i)
	{
		if(!optdesc[i].required)
			print_option(&optdesc[i]);
	}
}

/* create shot options string for get_opt function */
char *compose_short_opts(char *shortopts_new, const struct option long_options[], char *short_options)
{
	int i;
	struct option longopt;	

	if(long_options == NULL)
		return short_options;

	i=0;
	while(long_options[i].name != 0)
	{
		longopt = long_options[i];
		if(!longopt.flag)
			strcat(shortopts_new, (char *) &longopt.val);
		if(longopt.has_arg)
			strcat(shortopts_new, ":");
		i++;
	}

	if(short_options != NULL)
		strcat(shortopts_new, short_options);
	// strcat(shortopts_new, "");

	return shortopts_new;
}

/* takes csv and sets the related field in cfg->protocols for each known protocol */
char *add_protocol(char *protos, struct params *cfg)
{
	char *proto = protos;
	
	/* mark that only specific protocols are set */
	if(!cfg->restricted_protos) {
		for(int i=0; i<MAX_PROGS; i++) {
			// if (i != FALL_THROUGH)
				cfg->protocols[i] = false;
		}
		cfg->restricted_protos = true;
	}

	/* for each protocol */	
	proto = strtok(proto, ",");
	while (proto != NULL)
	{
		if (strcmp("TCP", proto) == 0 || strcmp("tcp", proto) == 0) {
			//TCP
			cfg->protocols[TCP] = true;
		} else if (strcmp("UDP", proto) == 0 || strcmp("udp", proto) == 0) {
			//UDP
			cfg->protocols[UDP] = true;
		} else if (strcmp("ICMP", proto) == 0 || strcmp("icmp", proto) == 0 || strcmp("ICMPv4", proto) == 0 || strcmp("icmpv4", proto) == 0 || strcmp("ICMPV4", proto) == 0 || strcmp("icmp4", proto) == 0 || strcmp("ICMP4", proto) == 0 ) {
			//ICMP
			cfg->protocols[ICMP] = true;
		} else if (strcmp("ICMPv6", proto) == 0 || strcmp("ICMPV6", proto) == 0 || strcmp("icmpv6", proto) == 0 || strcmp("ICMP6", proto) == 0 || strcmp("icmp6", proto) == 0) {
			//ICMPv6
			cfg->protocols[ICMPV6] = true;
		} else if (	strcmp("IP", proto) == 0 || strcmp("ip", proto) == 0 || strcmp("IPv4", proto) == 0 || strcmp("ipv4", proto) == 0 || strcmp("IPV4", proto) == 0 || strcmp("IP4", proto) == 0 || strcmp("ip4", proto) == 0) {
			//IP
			cfg->protocols[IP] = true;
		} else if (strcmp("IPv6", proto) == 0 || strcmp("IPV6", proto) == 0 || strcmp("ipv6", proto) == 0 || strcmp("IP6", proto) == 0 || strcmp("ip6", proto) == 0) {
			//IPv6
			cfg->protocols[IPV6] = true;
		} else if (strcmp("ethernet", proto) == 0 || strcmp("eth", proto) == 0 || strcmp("ETHERNET", proto) == 0 || strcmp("ETH", proto) == 0) {
			//ETHERNET
			cfg->protocols[ETHERNET] = true;
		} else if (strcmp("DNS", proto) == 0 || strcmp("dns", proto) == 0) {
			cfg->protocols[DNS] = true;
			cfg->deep_packet_inspection = true;
		} else {
			return proto;
		}
		proto = strtok(NULL, ",");		//next proto from csv
	}

	return NULL;
}

/* parse command line arguments */
void parse_args(int argc, char **argv, const struct option long_options[], struct params *cfg)
{
	int longindex = 0;
	int opt;
	char shortopts[256] = {0};
	int ifcnt = 0, modecnt = 0;	//interface count
	char *proto;

	compose_short_opts(shortopts, long_options, NULL);
	while ((opt = getopt_long(argc, argv, shortopts, long_options, &longindex)) != -1)
	{
		switch(opt)
		{
			case 'v':
				cfg->verbose = 1;
				verbose = 1;
				break;
			case 'q':
				cfg->verbose = 0;
				verbose = 0;
				break;
			case 'd':	//interface/device
				optarg = strtok(optarg, ",");
				while (optarg != NULL)
				{
					if (ifcnt > MAX_INTERFACES-1) {
						fprintf(stderr, "ERROR: --dev too much interfaces\n");	
						goto error;
					}
					cfg->interfaces[ifcnt] = if_nametoindex(optarg);
					if (cfg->interfaces[ifcnt] == 0) {
						fprintf(stderr, "ERROR: --dev can not find interface index for device name: err(%d)\n", errno);
						goto error;
					}
					ifcnt++;
					optarg = strtok(NULL, ",");
				}
				break;
			case 'm':	//xdp flags
				optarg = strtok(optarg,",");
				while (optarg != NULL)
				{
					if (modecnt > MAX_INTERFACES-1) {
						fprintf(stderr, "ERROR: --mode more modes than supported interfaces\n");	
						goto error;
					}
					if (strcmp(optarg, "generic") == 0 || strcmp(optarg, "skb") == 0)
						cfg->xdp_mode[modecnt] = XDP_FLAGS_SKB_MODE;	//generic
					else if (strcmp(optarg, "native") == 0 || strcmp(optarg, "driver") == 0)
						cfg->xdp_mode[modecnt] = XDP_FLAGS_DRV_MODE;	//native / driver
					else if (strcmp(optarg, "hardware") == 0 || strcmp(optarg, "offload") == 0 || strcmp(optarg, "hw") == 0)
						cfg->xdp_mode[modecnt] = XDP_FLAGS_HW_MODE;		//hardware
					else if (atoi(optarg) == XDP_FLAGS_SKB_MODE || atoi(optarg) == XDP_FLAGS_DRV_MODE || atoi(optarg) == XDP_FLAGS_HW_MODE)
						cfg->xdp_mode[modecnt] = atoi(optarg);
					else {
						fprintf(stderr, "ERROR: --mode unknown mode: %s\n", optarg);
						goto error;
					}
					modecnt++;
					optarg = strtok(NULL, ",");
				}
				break;
			case 'p':	//protocols
				proto = add_protocol(optarg, cfg);
				if (proto) {
					fprintf(stderr, "ERROR: --protocols unknown protocol: %s\n", proto);
					goto error;
				}
				break;
			case 'D':
				cfg->deep_packet_inspection = true;
				cfg->protocols[DEEP_PACKET_INSPECTION] = true;
				cfg->protocols[DNS] = true;
				break;
			case 'O':	//output file path
				if(strlen(optarg) + 1 > MAX_PATHLEN) {
					fprintf(stderr, "ERROR: --Output path to long: %s\n", optarg);
					goto error;
				}
				strcpy(cfg->dump_output_path, optarg);
				break;
			case 'L':
				if(strlen(optarg) + 1 > MAX_PATHLEN) {
					fprintf(stderr, "ERROR: --Log path to long: %s\n", optarg);
					goto error;
				}
				strcpy(cfg->log_output_path, optarg);
				break;
			case 'M':	//map file
				if(strlen(optarg) + 1 > MAX_PATHLEN) {
					fprintf(stderr, "ERROR: --Map path to long: %s\n", optarg);
					goto error;
				}
				strcpy(cfg->map_file_path, optarg);
				cfg->map_reuse = true;
				break;
			case 'F':	//map folder
				if(strlen(optarg) + 1 > MAX_PATHLEN) {
					fprintf(stderr, "ERROR: --Folder path to long: %s\n", optarg);
					goto error;
				}
				strcpy(cfg->map_folder_path, optarg);
				break;
			case 'j':
				cfg->json = true;
				break;
			case 'i':
				cfg->interval = atoi(optarg);
				break;
			case 'h':
				usage(optdesc);
				exit(0);
			case 't':
				// if(strcmp(optarg, "run") == 0)
				cfg->test = atoi(optarg);
				if ( 0 == atoi(optarg))
					cfg->test_run = true;
				break;
			error:
			default:
				usage(optdesc);
				exit(EXIT_FAIL_OPTION);
		}
	}

}

__u32 count_pkts(int flow_stats_fd)
{
    struct flow_id key, prev_key;
	struct flow_info value = { 0 };
    __u32 pkts = 0;
    
    while ( bpf_map_get_next_key(flow_stats_fd, &prev_key, &key) == 0 ) {
        if ((bpf_map_lookup_elem(flow_stats_fd, &key, &value)) != 0) {
            fprintf(stderr, "ERR: bpf_map_lookup_elem failed key3:0x%p\n", &key);
			// fprintf(stderr, "ERR: key.saddr: \n", key.saddr);
			// fprintf(stderr, "ERR: key.daddr: \n", key.daddr);
			// fprintf(stderr, "ERR: key.sport: \n", key.sport);
			// fprintf(stderr, "ERR: key.dport: \n", key.dport);
			// fprintf(stderr, "ERR: key.proto: \n", key.proto);
        }
		else {
        	pkts = pkts + value.pkts;
			prev_key = key;
		}
    }
	return pkts;
}

#define MAGIC_BYTES 123

struct ipv4_packet {
		struct ethhdr eth;
		struct iphdr iph;
		struct tcphdr tcp;
} __attribute__ ((__packed__));

int main(int argc, char **argv)
{
	struct bpflowmon_bpf *skel; //skeletton of the .o file
	int main_prog_fd, err=0, i;
    struct bpf_object *obj;
	struct params cfg = {0};
	char map_path[MAX_PATHLEN] = {0};
	//--------------cfg-------------
	int map_fd = -1;
	const char *map_filename = default_map_filename;
	const char *map_basedir = default_map_basedir;
	//--------------cfg-------------

    /* parse command line arguments */
	init_cfg(&cfg);
	parse_args(argc, argv, long_options, &cfg);

	/* Set up libbpf errors and debug info callback */
	if (cfg.verbose > 0)
		libbpf_set_print(libbpf_print_fn);
	else
		libbpf_set_print(NULL);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Open BPF application */
	skel = bpflowmon_bpf__open();
	if (!skel) {
		fprintf(stderr, "ERROR: Failed to open BPF skeleton\n");
		return 1;
	}
	obj = skel->obj;
	
	/* reuse maps */
	if(cfg.map_reuse) {
		map_fd = bpf_obj_get(cfg.map_file_path);
		err = bpf_map__reuse_fd(skel->maps.flow_stats, map_fd);
		if (err) {
			fprintf(stderr, "ERROR: Failed to reuse map: err(%d)\n", err);
			goto cleanup;
		}
	}

	/* Load & verify BPF programs and maps */
	err = bpflowmon_bpf__load(skel);
	if (err) {
		fprintf(stderr, "ERROR: Failed to load and verify BPF skeleton: err(%d)\n", err);
		goto cleanup;
	}
    
	/* check if map folder exists */
	if (access(cfg.map_folder_path, F_OK) == -1) {
		fprintf(stderr, "ERROR: can't access map directory (does it exist?): %s\n", map_basedir);
		goto cleanup;
	}	

	/* unpin old maps previous prog might not have cleaned up */
	struct bpf_map *map = NULL;
	bpf_map__for_each(map, obj)
	{	
		strcpy(map_path, cfg.map_folder_path);
		strcat(map_path, bpf_map__name(map));
		if((cfg.map_reuse && strcmp(bpf_map__name(map), "flow_stats") == 0) ||	//skip flow_stats map when reusing
			strcmp(bpf_map__name(map), bpf_map__name(skel->maps.bss)) == 0)		//skip bss for global variables always
		;	//skip flow_stats map if it is reused	//skip global variables (bss)
		else 
		{	/* unpin existing map */
			bpf_map__unpin(map, map_path);
			if (err && err != -2) {	//ENOENT = no maps found to unpin, that's ok. Above code would check if at least one map is present. I found no shorter solution for that
				fprintf(stderr, "ERROR: can't unpin/unlink maps: err(%d)\n", err);
				goto cleanup;
			}
			/* Pin map */
			err = bpf_map__pin(map, map_path);
			if (err) {
				fprintf(stderr, "ERROR: Failed to pin maps: err(%d)\n", err);
				goto cleanup;
			}
		}
	}//end for each map
	map_fd = bpf_obj_get(cfg.map_file_path);

	/* Init jump table */
    err = init_jmp_table(obj, &cfg, &main_prog_fd);
    if (err) {
        fprintf(stderr, "ERROR: Failed to init jump table: err(%d)\n", err);
        goto cleanup;
    }

	/* Attach xdp program */
	if (!cfg.test_run) {
		for (i=0; i<MAX_INTERFACES; i++)
		{
			if(cfg.interfaces[i]==0)
				break;
			err = bpf_set_link_xdp_fd(cfg.interfaces[i], main_prog_fd, cfg.xdp_mode[i]);     //more control than with libbpf auto attach
			if (err) {
				fprintf(stderr, "ERROR: Failed to attach BPF program: err(%d)\n", err);
				goto cleanup;
			}
		}
		if (i==0) {
			fprintf(stderr, "ERROR: No interface set\n");
			goto cleanup;
		}
	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
	}
	
	
	/* setup test */
	if (cfg.test == 0) {
		struct ipv4_packet pkt_v4 = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_IP),
			
			.iph.ihl = 5,
			.iph.version = 4,
			.iph.daddr = 33554442,
			.iph.saddr = 50331658,
			.iph.protocol = IPPROTO_TCP,
			.iph.tot_len = __bpf_constant_htons(MAGIC_BYTES),
			
			.tcp.source = 80,
			.tcp.dest = 1337,
			.tcp.urg_ptr = 123,
			.tcp.doff = 5,
		};
	
		__u32 size, retval, duration;
		char data_in[sizeof(pkt_v4)];
		char data_out[128];
		struct xdp_md ctx_in, ctx_out;
		int prog_fd;
		memcpy(data_in, &pkt_v4, sizeof(pkt_v4));

		err = bpf_prog_test_run(main_prog_fd, 1000000, &data_in, sizeof(pkt_v4), &data_out, &size, &retval, &duration);
		if (err) {
			printf("test run failed: %d\n", err);
			goto cleanup;
		}

		printf("Successfully ran 1000000 test run.\n");
		printf("average duration: %d ns\n", duration);
		printf("last return value: %d\n", retval);
		
		/* unlink all maps / cleanup*/
		map = NULL;
		bpf_map__for_each(map, obj) {
			bpf_map__unpin(map, bpf_map__get_pin_path(map));
		}
		bpflowmon_bpf__destroy(skel);
		exit(0);
	}


	__u32 pkts=0;
	if (cfg.test > 0) {
		/* wait duration */
		for (i=0; i<cfg.test; i++) {
			sleep(1);
			printf("duration: %d\n", i+1);
		}
		
		/* detach prog */
		for (i=0; i<MAX_INTERFACES; i++)
		{
			if(cfg.interfaces[i]==0)
				break;
			err = bpf_set_link_xdp_fd(cfg.interfaces[i], -1, 0);     //more control than with libbpf auto attach
			if (err) {
				fprintf(stderr, "ERROR: Failed to detach BPF program: err(%d)\n", err);
				goto cleanup;
			}
		}

		/* count pkts */
		// pkts = (int) count_pkts(map_fd);
		pkts = skel->bss->pkts;
		printf("pkts: %d\n", pkts);
		printf("map update error pkts: %d\n", skel->bss->err_pkts);

		/* unlink all maps / cleanup*/
		map = NULL;
		bpf_map__for_each(map, obj) {
			bpf_map__unpin(map, bpf_map__get_pin_path(map));
		}
		bpflowmon_bpf__destroy(skel);
		exit(0);
	}
	else
		flow_poll(map_fd, cfg.interval, cfg.log_output_path, cfg.dump_output_path, cfg.json);

	

/* cleanup */
cleanup:
	usage(optdesc);
	map = NULL;
	bpf_map__for_each(map, obj) {
		bpf_map__unpin(map, bpf_map__get_pin_path(map));
	}
	bpflowmon_bpf__destroy(skel);
	return -err;
}