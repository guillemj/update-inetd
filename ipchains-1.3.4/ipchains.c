/*
 * Author: Paul.Russell@rustcorp.com.au
 *
 * Based on the ipfwadm code by Jos Vos <jos@xos.nl> (see README).
 *
 *	ipchains -- IP firewall administration for kernels with
 * CONFIG_IP_FIREWALL_CHAINS.
 *
 *	See the accompanying manual page ipchains(8) for information
 *	about proper usage of this program.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * History:
 * 1.0: First release
 * 1.0.1: Generic protocols allowed (matching ip_fwtrees.h changes).
 *        Tighter TOS checking (replaced silent kernel TOS mangling).
 *        RETURN target allowed (matching ip_fwtrees.c changes). 
 *        Bug fix for port handling (port ranges broken?).
 *        Bug fix for possible bad return values from delete_entry and
 *         append_entry.
 * 1.0.2: User & marking support.  Removed -a option (interface address).
 * 1.1:   Inverse rule support.
 *        Removal of -k option (ACK).
 *        Moved -b option to userspace (BIDIR).
 *        Removed multiple port support.
 *        Fixed bug in handling of > 8 rules.
 * 1.1.1: Added ICMP code support.
 *        Extra check for multiple DNS resolutions and ! or -b.
 *        Fixed -b code (now swaps address masks as well).
 *        Handle EINVAL from IP_FW_DELETE command.
 * 1.2:   Added wildcard interface support.
 * 1.2.1: Fixed parsing of inverse interfaces (broken in 1.2).
 * 1.2.2: Allow /proc/net/ip_fwnames to contain policy names (so same
 *        across 2.0/2.1 kernels).
 * 1.3:   Added `-o' option for netlink support.
 *        Enumerated exit types.
 *        Added output for delete in verbose mode.
 *        Added -X with no chain name to delete all chains.
 *        Added support for policy counters (kernel change).
 *        Removed old-style (numeric) policy handling.
 *        Fixed masquerade typo so masq works again.
 *        Handle ICMP masq.
 * 1.3.1: Move headers out to kernel_headers for glibc compatibility.
 *        Policies now handed to kernel in string form (kernel change).
 * 1.3.2: Handle generic masq. protocols.
 *        Fixed -S option.
 * 1.3.3: Marks now printed in hex.
 *        kernel_headers.h now works with libc5 again.
 *        Set IP_FW_F_WILDIF for zero-length interface names.
 */

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <netdb.h>
#include <sys/param.h>
#include <pwd.h>
#include <sys/types.h>
#include "kernel_headers.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef	IP_FW_F_REDIR
#define IPFWADM_NO_REDIR
#define IP_FW_F_REDIR		0
#endif	/* ! IP_FW_F_REDIR */

#ifndef	IP_FW_MASQ_TIMEOUTS
#define IPFWADM_NO_TIMEOUT
#define IP_FW_MASQ_TIMEOUTS	0
#endif	/* ! IP_FW_MASQ_TIMEOUTS */

#define IP_VERSION	4
#define IP_OFFSET	0x1FFF

#define CHN_NONE	-1
#define CHN_FWD		0
#define CHN_IN		1
#define CHN_OUT		2
#define CHN_MASQ	3	/* only used for listing masquerading */

#define CMD_NONE		0x0000U
#define CMD_INSERT		0x0001U
#define CMD_DELETE		0x0002U
#define CMD_DELETE_NUM		0x0004U
#define CMD_REPLACE		0x0008U
#define CMD_APPEND		0x0010U
#define CMD_LIST		0x0020U
#define CMD_FLUSH		0x0040U
#define CMD_ZERO		0x0080U
#define CMD_NEW_CHAIN		0x0100u
#define CMD_DELETE_CHAIN	0x0200U
#define CMD_SET_POLICY		0x0400U
#define CMD_MASQERADE		0x0800U
#define CMD_SET_MASQERADE	0x1000U
#define CMD_CHECK		0x2000U
#define NUMBER_OF_CMD	14
static const char cmdflags[] = { 'I', 'D', 'D', 'R', 'A', 'L', 'F', 'Z',
				 'N', 'X', 'P', 'M', 'S', 'C' };

#define OPT_NONE	0x00000U
#define OPT_NUMERIC	0x00001U
#define OPT_SOURCE	0x00002U
#define OPT_DESTINATION	0x00004U
#define OPT_PROTOCOL	0x00008U
#define OPT_JUMP	0x00010U
#define OPT_TCPSYN	0x00020U
#define OPT_BIDIR	0x00040U
#define OPT_VERBOSE	0x00080U
#define OPT_PRINTK	0x00100U
#define OPT_EXPANDED	0x00200U
#define OPT_TOS		0x00400U
#define OPT_VIANAME	0x00800U
#define OPT_FRAGMENT    0x01000U
#define OPT_MARK        0x02000U
#define OPT_SRCPT       0x04000U
#define OPT_DSTPT       0x08000U
#define OPT_NETLINK     0x10000U
#define NUMBER_OF_OPT	17
static const char optflags[] = { 'n', 's', 'd', 'p', 'j', 'y', 'b', 'v', 
				 'l', 'x', 't', 'i', 'f', 'm', 's', 'd', 'o'};

#define FMT_NUMERIC	0x0001
#define FMT_NOCOUNTS	0x0002
#define FMT_KILOMEGAGIGA 0x0004
#define FMT_OPTIONS	0x0008
#define FMT_NOTABLE	0x0010
#define FMT_HEADER	0x0020
#define FMT_NOTARGET	0x0040
#define FMT_VIA		0x0080
#define FMT_NONEWLINE	0x0100
#define FMT_DELTAS	0x0200
#define FMT_TOS		0x0400
#define FMT_MARK        0x0800
#define FMT_NETLINK     0x1000

#define FMT_PRINT_RULE (FMT_NOCOUNTS | FMT_OPTIONS | FMT_TOS | FMT_VIA \
			| FMT_NUMERIC | FMT_NOTABLE | FMT_MARK | FMT_NETLINK)

/* TOS names and values. */
struct TOS_value
{
	unsigned char TOS;
	const char *name;
} TOS_values[] = {
#ifdef NOT_A_GODDAMN_YANK
	{ 0x10, "Minimise Delay" },
	{ 0x08, "Minimise Throughput" },
	{ 0x04, "Maximise Reliability" },
	{ 0x01, "Minimise Cost" },
#else
	{ 0x10, "Minimize Delay" },
	{ 0x08, "Minimize Throughput" },
	{ 0x04, "Maximize Reliability" },
	{ 0x01, "Minimize Cost" },
#endif
	{ 0x00, "Normal Service" },
};

/* Table of legal combinations of commands and options.  If any of the
 * given commands make an option legal, that option is legal (applies to 
 * CMD_LIST and CMD_ZERO only).
 * Key:
 *  +  compulsory
 *  x  illegal
 *     optional
 */

static char commands_v_options[NUMBER_OF_CMD][NUMBER_OF_OPT] = 
/* Well, it's better than "Re: Linux vs FreeBSD" */
{
	/*     -n  -s  -d  -p  -j  -y  -b  -v  -l  -x  -t  -i  -f  -m  -s  -d  -o */
/*INSERT*/    {'x',' ',' ',' ',' ',' ',' ',' ',' ','x',' ',' ',' ',' ',' ',' ',' '},
/*DELETE*/    {'x',' ',' ',' ',' ',' ',' ',' ',' ','x',' ',' ',' ',' ',' ',' ',' '},
/*DELETE_NUM*/{'x','x','x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x'},
/*REPLACE*/   {'x',' ',' ',' ',' ',' ','x',' ',' ','x',' ',' ',' ',' ',' ',' ',' '},
/*APPEND*/    {'x',' ',' ',' ',' ',' ',' ',' ',' ','x',' ',' ',' ',' ',' ',' ',' '},
/*LIST*/      {' ','x','x','x','x','x','x',' ','x',' ','x','x','x','x','x','x','x'},
/*FLUSH*/     {'x','x','x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x'},
/*ZERO*/      {'x','x','x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x'},
/*NEW_CHAIN*/ {'x','x','x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x'},
/*DEL_CHAIN*/ {'x','x','x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x'},
/*SET_POLICY*/{'x','x','x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x'},
/*MASQERADE*/ {'x','x','x','x','x','x','x','x','x','x','x','x','x','x','x','x','x'},
/*SET_MASQ*/  {'x','x','x','x','x','x','x',' ','x','x','x','x','x','x','x','x','x'},
/*CHECK*/     {'x','+','+','+','x',' ',' ',' ','x','x','x','+',' ','x',' ',' ','x'}
};

static int inverse_for_options[NUMBER_OF_OPT] =
{
/* -n */ 0,
/* -s */ IP_FW_INV_SRCIP,
/* -d */ IP_FW_INV_DSTIP,
/* -p */ IP_FW_INV_PROTO,
/* -j */ 0,
/* -y */ IP_FW_INV_SYN,
/* -b */ 0,
/* -v */ 0,
/* -l */ 0,
/* -x */ 0,
/* -t */ 0,
/* -i */ IP_FW_INV_VIA,
/* -f */ IP_FW_INV_FRAG,
/* -m */ 0,
/* -s */ IP_FW_INV_SRCPT,
/* -d */ IP_FW_INV_DSTPT,
/* -o */ 0
};
	
struct masq {
	unsigned long	expires;	/* Expiration timer */
	char proto[20];		/* Which protocol are we talking? */
	struct in_addr	src, dst;	/* Source and destination IP addresses */
	unsigned short	sport, dport;	/* Source and destination ports */
	unsigned short	mport;		/* Masqueraded port */
	__u32		initseq;	/* Add delta from this seq. on */
	short		delta;		/* Delta in sequence numbers */
	short		pdelta;		/* Delta in sequence numbers before last */
};

struct masq_timeout {
	int	tcp_timeout;
	int	tcp_fin_timeout;
	int	udp_timeout;
} timeouts;

static char package_version[] = "ipchains 1.3.4, 19-May-1998";

static const char *program;

static unsigned int nsaddrs, ndaddrs;
static struct in_addr *saddrs, *daddrs;

/* Do we invert the next option? */
static int invert = FALSE;

static int check_inverse(const char option[], int *invert);

/* Parsing functions for command line. */
static struct in_addr *parse_hostnetwork(const char *, unsigned int *);
static void parse_hostnetworkmask(const char *, struct in_addr **,
	struct in_addr *, unsigned int *);
static struct in_addr *parse_mask(char *);
static unsigned short int parse_protocol(const char *);
static const char * parse_policy(const char *);
static void parse_icmp(const char *srcportstring, const char *dstportstring,
		       __u16 *type, __u16* code, int *options, __u16 invflags,
		       int checking);
static void parse_ports(const char *portstring, __u16 *ports, __u16 proto);
static __u16 parse_port(const char *port, unsigned short proto);
static unsigned short parse_mark(char *markstring, __u32 *mark);
static unsigned short parse_outputsize(char *outputstring, __u16 *outputsize);
static unsigned short parse_interface(const char *ifstring, char *vianame);
static void parse_hexbyte(char *, unsigned char *);
static int parse_timeout(char *);
static const char *parse_target(const char *targetname);
static int parse_rulenumber(const char *rule);

/* Various parsing helper functions */
static struct in_addr *host_to_addr(const char *, unsigned int *);
static char *addr_to_host(struct in_addr *);
static struct in_addr *network_to_addr(const char *);
static char *addr_to_network(struct in_addr *);
static char *addr_to_anyname(struct in_addr *);
static struct in_addr *dotted_to_addr(const char *);
static char *addr_to_dotted(struct in_addr *);
static char *mask_to_dotted(struct in_addr *);
static int service_to_port(const char *, unsigned short);
static char *port_to_service(int, unsigned short);
static int string_to_number(const char *, int, int);

/* Check the options based on the tables above */
static void generic_opt_check(int command, int options);
static char opt2char(int option);
static char cmd2char(int option);
static void add_command(int *cmd, const int newcmd, const int othercmds);

/* Check for illegal TOS manipulation */
static void check_tos(unsigned char tosand, unsigned char tosxor);

/* Do the work */
static int insert_entry(const ip_chainlabel chain, 
			const struct ip_fwuser *fw, 
			unsigned int rulenum,
			int verbose, int bidir);
static int replace_entry(const ip_chainlabel chain, 
			 const struct ip_fwuser *fw, 
			 unsigned int rulenum, 
			 int verbose);
static int append_entry(const ip_chainlabel chain, 
			const struct ip_fwuser *fw,
			int verbose, int bidir);
static int delete_entry(const ip_chainlabel chain, 
			const struct ip_fwuser *fw,
			int verbose, int bidir);
static int delete_num_entry(const ip_chainlabel chain, unsigned int rulenum);
static int check_packet(const ip_chainlabel chain, struct ip_fwuser *fw,
			int verbose, int bidir);
static int list_entries(const ip_chainlabel chain, 
			const char *openmode, 
			int verbose, int numeric, int expanded);
static int list_all_entries(int verbose, int numeric, int expanded);
static int flush_entries(const ip_chainlabel chain);
static int zero_entries(const ip_chainlabel chain);
static int new_chain(const ip_chainlabel chain);
static int delete_chain(const ip_chainlabel chain, int verbose);
static int set_policy(const ip_chainlabel chain, const ip_chainlabel policy);
static int list_masq(unsigned int options);

static void print_firewall(FILE *, struct ip_fwuser *, __u64, __u64, int);
static void print_masq(FILE *, struct masq *, int);
static int read_procinfo(FILE *, struct ip_fwchange *, __u64 *, unsigned int);
static int read_masqinfo(FILE *, struct masq *, int);
static struct ip_fwtest *fw_to_fwtest(struct ip_fw *, 
				      const ip_chainlabel chain);
static int do_setsockopt(int, const void *, int);

static void set_option(unsigned int *options, 
		       unsigned int option,
		       __u16 *invflg);
static void inaddrcpy(struct in_addr *, struct in_addr *);
static void *fw_malloc(size_t);
static void *fw_calloc(size_t, size_t);
static void *fw_realloc(void *, size_t);
enum exittype {
	OTHER_PROBLEM = 1,
	PARAMETER_PROBLEM,
	VERSION_PROBLEM
};
static void exit_error(enum exittype, char *, ...)
  __attribute__((noreturn, format(printf,2,3)));
static void exit_tryhelp(int) __attribute__((noreturn));
static void exit_printicmphelp() __attribute__((noreturn));
static void exit_printhelp() __attribute__((noreturn));

struct icmp_names {
	const char *name;
	__u16 type;
	__u16 code_min, code_max;
	int use_code_min_for_testing;
};

const struct icmp_names icmp_codes[] = {
	{ "echo-reply", 0, 0, 0xFFFF, TRUE },
	/* Alias */ { "pong", 0, 0, 0xFFFF, TRUE },

	{ "destination-unreachable", 3, 0, 0xFFFF, FALSE },
	{   "network-unreachable", 3, 0, 0, TRUE },
	{   "host-unreachable", 3, 1, 1, TRUE },
	{   "protocol-unreachable", 3, 2, 2, TRUE },
	{   "port-unreachable", 3, 3, 3, TRUE },
	{   "fragmentation-needed", 3, 4, 4, TRUE },
	{   "source-route-failed", 3, 5, 5, TRUE },
	{   "network-unknown", 3, 6, 6, TRUE },
	{   "host-unknown", 3, 7, 7, TRUE },
	{   "network-prohibited", 3, 9, 9, TRUE },
	{   "host-prohibited", 3, 10, 10, TRUE },
	{   "TOS-network-unreachable", 3, 11, 11, TRUE },
	{   "TOS-host-unreachable", 3, 12, 12, TRUE },
	{   "communication-prohibited", 3, 13, 13, TRUE },
	{   "host-precedence-violation", 3, 14, 14, TRUE },
	{   "precedence-cutoff", 3, 15, 15, TRUE },

	{ "source-quench", 4, 0, 0xFFFF, TRUE },

	{ "redirect", 5, 0, 0xFFFF, FALSE },
	{   "network-redirect", 5, 0, 0, TRUE },
	{   "host-redirect", 5, 1, 1, TRUE },
	{   "TOS-network-redirect", 5, 2, 2, TRUE },
	{   "TOS-host-redirect", 5, 3, 3, TRUE },

	{ "echo-request", 8, 0, 0xFFFF, TRUE },
	/* Alias */ { "ping", 8, 0, 0xFFFF, TRUE },

	{ "router-advertisement", 9, 0, 0xFFFF, TRUE },

	{ "router-solicitation", 10, 0, 0xFFFF, TRUE },

	{ "time-exceeded", 11, 0, 0xFFFF, FALSE },
	/* Alias */ { "ttl-exceeded", 11, 0, 0xFFFF, FALSE },
	{   "ttl-zero-during-transit", 11, 0, 0, TRUE },
	{   "ttl-zero-during-reassembly", 11, 1, 1, TRUE },

	{ "parameter-problem", 12, 0, 0xFFFF, FALSE },
	{   "ip-header-bad", 12, 0, 0, TRUE },
	{   "required-option-missing", 12, 1, 1, TRUE },

	{ "timestamp-request", 13, 0, 0xFFFF, TRUE },

	{ "timestamp-reply", 14, 0, 0xFFFF, TRUE },

	{ "address-mask-request", 17, 0, 0xFFFF, TRUE },

	{ "address-mask-reply", 18, 0, 0xFFFF, TRUE }
};

int
main(int argc, char *argv[])
{
	int c;
	/* By declaring it static, it gets initialised to all 0. */
	static struct ip_fwuser fw;

	const char *chain = NULL;
	const char *jumpto = NULL;
	const char *srcpts = NULL, *dstpts = NULL;
	const char *shostnetworkmask = NULL, *dhostnetworkmask = NULL;
	const char *rport = "0";
	const char *policy = NULL;
	unsigned int rulenum = 0, options = 0, command = 0;
	int ret = 1;

	program = argv[0];

	if (argc > 1 && strcmp(argv[1], "!") == 0) {
		invert = TRUE;
		argc--;
		argv++;
	}
	while ((c = getopt(argc, argv, "A:C:D:R:I:L::F::Z::N:X::P:MS:h::o::p:s:d:j:i:fbvm:nlt:xy-")) != -1) {
		switch (c) {
			/*
			 * Command selection
			 */
		case 'A':
			add_command(&command, CMD_APPEND, CMD_NONE);
			chain = optarg;
			break;

		case 'D':
			add_command(&command, CMD_DELETE, CMD_NONE);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!') {
				rulenum = parse_rulenumber(argv[optind++]);
				command = CMD_DELETE_NUM;
			}
			break;

		case 'C':
			add_command(&command, CMD_CHECK, CMD_NONE);
			chain = optarg;
			break;

		case 'R':
			add_command(&command, CMD_REPLACE, CMD_NONE);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!') {
				rulenum = parse_rulenumber(argv[optind++]);
			}
			else 
				exit_error(PARAMETER_PROBLEM, "-%c requires a rule number",
					   cmd2char(CMD_REPLACE));
			break;

		case 'I':
			add_command(&command, CMD_INSERT, CMD_NONE);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!') {
				rulenum = parse_rulenumber(argv[optind++]);
			}
			else rulenum = 1;
			break;

		case 'L':
			add_command(&command, CMD_LIST, 
				    CMD_ZERO|CMD_MASQERADE);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				 && argv[optind][0] != '!')
				chain = argv[optind++];

			if ((command & CMD_ZERO) && chain)
				exit_error(PARAMETER_PROBLEM, "-%c with -%c does not allow"
					   "chain to be specified",
					   cmd2char(CMD_LIST), 
					   cmd2char(CMD_ZERO));
			break;

		case 'F':
			add_command(&command, CMD_FLUSH, CMD_NONE);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				 && argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'Z':
			add_command(&command, CMD_ZERO, CMD_LIST);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				&& argv[optind][0] != '!')
				chain = argv[optind++];

			if ((command & CMD_LIST) && chain)
				exit_error(PARAMETER_PROBLEM, "-%c with -%c does not allow"
					   "chain to be specified",
					   cmd2char(CMD_LIST), 
					   cmd2char(CMD_ZERO));
			break;

		case 'N':
			add_command(&command, CMD_NEW_CHAIN, CMD_NONE);
			chain = optarg;
			break;

		case 'X':
			add_command(&command, CMD_DELETE_CHAIN, CMD_NONE);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				 && argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'P':
			add_command(&command, CMD_SET_POLICY, CMD_NONE);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!') {
				policy = parse_policy(argv[optind++]);
			}
			else 
				exit_error(PARAMETER_PROBLEM, 
					   "-%c requires a chain and a policy",
					   cmd2char(CMD_SET_POLICY));
			break;

		case 'M':
			add_command(&command, CMD_MASQERADE,
				    CMD_LIST|CMD_SET_MASQERADE);
			break;

		case 'S':
#ifndef	IPFWADM_NO_TIMEOUT
			add_command(&command, CMD_SET_MASQERADE, 
				    CMD_MASQERADE);
			if (optind + 1 < argc 
			    && argv[optind][0] != '!' 
			    && argv[optind][0] != '-' 
			    && argv[optind+1][0] != '!' 
			    && argv[optind+1][0] != '-') {
				timeouts.tcp_timeout =
					HZ * parse_timeout(optarg);
				timeouts.tcp_fin_timeout =
					HZ * parse_timeout(argv[optind++]);
				timeouts.udp_timeout =
					HZ * parse_timeout(argv[optind++]);
			} else
				exit_error(PARAMETER_PROBLEM, "-%c requires 3 timeout values",
					   cmd2char(CMD_SET_MASQERADE));
#else	/* IPFWADM_NO_TIMEOUT */
			exit_error(PARAMETER_PROBLEM, "setting masquerading timeouts "
				   "not supported");
#endif	/* IPFWADM_NO_TIMEOUT */
			break;

		case 'h':
			if ((optarg && strcasecmp(optarg, "icmp") == 0)
			    || (optind < argc 
				&& strcasecmp(argv[optind], "icmp") == 0))
				exit_printicmphelp();
			exit_printhelp();

			/*
			 * Option selection
			 */
		case 'p':
			if (check_inverse(optarg, &invert))
				optind++;				
			set_option(&options, OPT_PROTOCOL, &fw.ipfw.fw_invflg);
			fw.ipfw.fw_proto = parse_protocol(argv[optind-1]);
			if (fw.ipfw.fw_proto == 0
			    && (fw.ipfw.fw_invflg & IP_FW_INV_PROTO))
				exit_error(PARAMETER_PROBLEM, "rule would never match protocol");
			break;

		case 's':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_SOURCE, &fw.ipfw.fw_invflg);
			if (!argv[optind-1])
				exit_error(PARAMETER_PROBLEM, "argument expected after -s");

			shostnetworkmask = argv[optind-1];
			if (check_inverse(argv[optind], &invert))
				optind++;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
			{
				srcpts = argv[optind++];
				set_option(&options, OPT_SRCPT, 
					   &fw.ipfw.fw_invflg);
			}
			break;

		case 'd':
			if (check_inverse(optarg, &invert))
				optind++;				
			set_option(&options, OPT_DESTINATION, 
				   &fw.ipfw.fw_invflg);
			if (!argv[optind-1])
				exit_error(PARAMETER_PROBLEM, "argument expected after -d");

			dhostnetworkmask = argv[optind-1];
			if (check_inverse(argv[optind], &invert))
				optind++;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
			{
				dstpts = argv[optind++];
				set_option(&options, OPT_DSTPT, 
					   &fw.ipfw.fw_invflg);
			}
			break;

		case 'j':
			if (invert)
				exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
			set_option(&options, OPT_JUMP, &fw.ipfw.fw_invflg);
			jumpto = parse_target(optarg);
			if (strcmp(jumpto, IP_FW_LABEL_REDIRECT) == 0
			    && optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				rport = argv[optind++];
			break;

		case 'i':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_VIANAME, &fw.ipfw.fw_invflg);
			fw.ipfw.fw_flg |= parse_interface(argv[optind-1], 
							  fw.ipfw.fw_vianame);
			break;

		case 'f':
			set_option(&options, OPT_FRAGMENT, &fw.ipfw.fw_invflg);
			invert = FALSE;
			fw.ipfw.fw_flg |= IP_FW_F_FRAG;
			break;

		case 'b':
			if (invert)
				exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
			set_option(&options, OPT_BIDIR, &fw.ipfw.fw_invflg);
			break;

		case 'v':
			if (invert)
				exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
			set_option(&options, OPT_VERBOSE, &fw.ipfw.fw_invflg);
			break;

		case 'm':
			if (invert)
				exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
			set_option(&options, OPT_MARK, &fw.ipfw.fw_invflg);
			fw.ipfw.fw_flg |= parse_mark(optarg, &fw.ipfw.fw_mark);
			break;

		case 'n':
			if (invert)
				exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
			set_option(&options, OPT_NUMERIC, &fw.ipfw.fw_invflg);
			break;

		case 'l':
			if (invert)
				exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
			set_option(&options, OPT_PRINTK, &fw.ipfw.fw_invflg);
			fw.ipfw.fw_flg |= IP_FW_F_PRN;
			break;

		case 'o':
			if (invert)
				exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
			set_option(&options, OPT_NETLINK, &fw.ipfw.fw_invflg);
			if (!optarg && optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				optarg = argv[optind++];

			fw.ipfw.fw_flg 
				|= parse_outputsize(optarg, 
						    &fw.ipfw.fw_outputsize);
			break;

		case 't':
			if (invert)
				exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
			set_option(&options, OPT_TOS, &fw.ipfw.fw_invflg);
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!') {
				parse_hexbyte(optarg, &fw.ipfw.fw_tosand);
				parse_hexbyte(argv[optind++], 
					      &fw.ipfw.fw_tosxor);
				check_tos(fw.ipfw.fw_tosand, 
					  fw.ipfw.fw_tosxor);
			} else
				exit_error(PARAMETER_PROBLEM, 
					   "-%c requires 2 hexbyte arguments",
					   opt2char(OPT_TOS));
			break;

		case 'x':
			if (invert)
				exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
			set_option(&options, OPT_EXPANDED, &fw.ipfw.fw_invflg);
			break;

		case 'y':
			set_option(&options, OPT_TCPSYN, &fw.ipfw.fw_invflg);
			fw.ipfw.fw_flg |= IP_FW_F_TCPSYN;
			invert = FALSE;
			break;

		/* A hack -- I like --version */
		case '-':
			if (strcmp(argv[optind], "--version") == 0) {
				printf("%s\n", package_version);
				exit(0);
			}
			exit_error(PARAMETER_PROBLEM, "Unknown option `%s'", argv[optind]);

		case '?':
		default:
			exit_tryhelp(2);
		}

		if (optind + 1 < argc && strcmp(argv[optind], "!") == 0) {
			invert = TRUE;
			optind++;
		}
	}

	if (optind < argc)
		exit_error(PARAMETER_PROBLEM, "unknown arguments found on commandline");
	else if (!command)
		exit_error(PARAMETER_PROBLEM, "no command specified");
	else if (invert)
		exit_error(PARAMETER_PROBLEM, "nothing appropriate following !");

	if ((command & CMD_REPLACE) 
	    || (command & CMD_INSERT) 
	    || (command & CMD_DELETE) 
	    || (command & CMD_APPEND)) {
		if (!(options & OPT_DESTINATION))
			dhostnetworkmask = "0.0.0.0/0";
		if (!(options & OPT_SOURCE))
			shostnetworkmask = "0.0.0.0/0";
	}

	if (shostnetworkmask) {
		parse_hostnetworkmask(shostnetworkmask, &saddrs,
			&(fw.ipfw.fw_smsk), &nsaddrs);
		if (fw.ipfw.fw_proto != IPPROTO_ICMP)
			parse_ports(srcpts, fw.ipfw.fw_spts, fw.ipfw.fw_proto);
	}

	if (dhostnetworkmask) {
		parse_hostnetworkmask(dhostnetworkmask, &daddrs,
			&(fw.ipfw.fw_dmsk), &ndaddrs);
		if (fw.ipfw.fw_proto != IPPROTO_ICMP)
			parse_ports(dstpts, fw.ipfw.fw_dpts, fw.ipfw.fw_proto);
	}

	if (fw.ipfw.fw_proto == IPPROTO_ICMP) {
		parse_icmp(srcpts, dstpts, fw.ipfw.fw_spts, fw.ipfw.fw_dpts,
			   &options, fw.ipfw.fw_invflg, command == CMD_CHECK);
	}

	if ((nsaddrs > 1 || ndaddrs > 1) && 
	    (fw.ipfw.fw_invflg & (IP_FW_INV_SRCIP | IP_FW_INV_DSTIP)))
		exit_error(PARAMETER_PROBLEM, "! not allowed with multiple source or destination IP addresses");

	if ((nsaddrs > 1 || ndaddrs > 1) && (options & OPT_BIDIR))
		exit_error(PARAMETER_PROBLEM, "-b not allowed with multiple source or destination IP addresses");

	if ((fw.ipfw.fw_proto == 0 || (fw.ipfw.fw_invflg & IP_FW_INV_PROTO))
	    && ((options & OPT_SRCPT) || (options & OPT_DSTPT)))
		exit_error(PARAMETER_PROBLEM, "no ports allowed without specific protocol");

	if ((fw.ipfw.fw_proto != IPPROTO_TCP 
	     || (fw.ipfw.fw_invflg & IP_FW_INV_PROTO))
	    && (options & OPT_TCPSYN))
		exit_error(PARAMETER_PROBLEM, "-%c only allowed with TCP protocol",
			   opt2char(OPT_TCPSYN));

	if ((options & OPT_FRAGMENT) && !(fw.ipfw.fw_invflg & IP_FW_INV_FRAG)
	    && ((options & OPT_SRCPT) || (options & OPT_DSTPT)))
		exit_error(PARAMETER_PROBLEM, "no ports allowed with -%c", 
			   opt2char(OPT_FRAGMENT));

	if ((options & OPT_FRAGMENT) && !(fw.ipfw.fw_invflg & IP_FW_INV_FRAG)
	    && (options & OPT_TCPSYN))
		exit_error(PARAMETER_PROBLEM, "-%c not allowed with -%c", 
			   opt2char(OPT_TCPSYN), opt2char(OPT_FRAGMENT));

	if (command == CMD_CHECK 
	    && (fw.ipfw.fw_proto == IPPROTO_TCP 
		|| fw.ipfw.fw_proto == IPPROTO_UDP
		|| fw.ipfw.fw_proto == IPPROTO_ICMP) 
	    && !(options & OPT_FRAGMENT)
	    && (!(options & OPT_SRCPT) 
		|| fw.ipfw.fw_spts[0] != fw.ipfw.fw_spts[1]
		|| !(options & OPT_DSTPT)
		|| fw.ipfw.fw_dpts[0] != fw.ipfw.fw_dpts[1]))
		exit_error(PARAMETER_PROBLEM, "one port required with source/destination "
			   "address for -%c", cmd2char(CMD_CHECK));

	if (command == CMD_CHECK && fw.ipfw.fw_invflg != 0)
		exit_error(PARAMETER_PROBLEM, "! not allowed with -%c", cmd2char(CMD_CHECK));

	if (((fw.ipfw.fw_proto != IPPROTO_TCP && fw.ipfw.fw_proto != IPPROTO_UDP)
	     || (fw.ipfw.fw_invflg & IP_FW_INV_PROTO))
	    && jumpto && strcmp(jumpto, IP_FW_LABEL_REDIRECT) == 0)
		exit_error(PARAMETER_PROBLEM, "redirecting only allowed with TCP or UDP");

	if (jumpto && strcmp(jumpto, IP_FW_LABEL_MASQUERADE) == 0
	    && chain && (strcmp(chain, IP_FW_LABEL_INPUT) == 0
			 || strcmp(chain, IP_FW_LABEL_OUTPUT) == 0))
		exit_error(PARAMETER_PROBLEM, 
			   "masquerading not allowed for input and output chains");

	if (jumpto && strcmp(jumpto, IP_FW_LABEL_REDIRECT) == 0
	    && chain && (strcmp(chain, IP_FW_LABEL_OUTPUT) == 0
			 || strcmp(chain, IP_FW_LABEL_FORWARD) == 0))
		exit_error(PARAMETER_PROBLEM, 
			   "redirect not allowed for output and forward chains");

	/* Allow lazy -S without -M */
	if (command == CMD_SET_MASQERADE)
	    command |= CMD_MASQERADE;
	    
	generic_opt_check(command, options);

	if (chain && strlen(chain) > IP_FW_MAX_LABEL_LENGTH)
		exit_error(PARAMETER_PROBLEM,
			   "chain name `%s' too long (must be under %i chars)",
			   chain, IP_FW_MAX_LABEL_LENGTH);

	if (jumpto && strcmp(jumpto, IP_FW_LABEL_REDIRECT) == 0) {
		fw.ipfw.fw_redirpt = parse_port(rport, fw.ipfw.fw_proto);
	}

	if (!(options & OPT_TOS)) {
		fw.ipfw.fw_tosand = 0xFF;
		fw.ipfw.fw_tosxor = 0x00;
	}

	if (options & OPT_JUMP)
		strcpy(fw.label, jumpto);

	switch (command) {
	case CMD_APPEND:
		ret = append_entry(chain, &fw, options&OPT_VERBOSE, 
				   options&OPT_BIDIR);
		break;
	case CMD_CHECK:
		ret = check_packet(chain, &fw, options&OPT_VERBOSE,
				   options&OPT_BIDIR);
		break;
	case CMD_DELETE:
		ret = delete_entry(chain, &fw, options&OPT_VERBOSE,
				   options&OPT_BIDIR);
		break;
	case CMD_DELETE_NUM:
		ret = delete_num_entry(chain, rulenum);
		break;
	case CMD_REPLACE:
		ret = replace_entry(chain, &fw, rulenum, options&OPT_VERBOSE);
		break;
	case CMD_INSERT:
		ret = insert_entry(chain, &fw, rulenum, options&OPT_VERBOSE,
				   options&OPT_BIDIR);
		break;
	case CMD_LIST|CMD_MASQERADE:
		ret = list_masq(options);
		break;
	case CMD_LIST:
	case CMD_LIST|CMD_ZERO:
		ret = list_entries(chain, (command&CMD_ZERO) ? "r+" : "r",
				   options&OPT_VERBOSE, options&OPT_NUMERIC,
				   options&OPT_EXPANDED);
		break;
	case CMD_FLUSH:
		ret = flush_entries(chain);
		break;
	case CMD_ZERO:
		ret = zero_entries(chain);
		break;
	case CMD_NEW_CHAIN:
		ret = new_chain(chain);
		break;
	case CMD_DELETE_CHAIN:
		ret = delete_chain(chain, options&OPT_VERBOSE);
		break;
	case CMD_MASQERADE|CMD_SET_MASQERADE:
		ret = do_setsockopt(IP_FW_MASQ_TIMEOUTS, 
				    &timeouts, sizeof(timeouts));
		break;
	case CMD_SET_POLICY:
		ret = set_policy(chain, policy);
		break;
	default:
		/* We should never reach this... */
		abort();
		exit_tryhelp(2);
	}
	exit(ret);
}

static int check_inverse(const char option[], int *invert)
{
	if (*invert)
		exit_error(PARAMETER_PROBLEM, "Multiple `!' flags not allowed");

	if (option && strcmp(option, "!") == 0) {
		*invert = TRUE;
		return TRUE;
	}
	return FALSE;
}

/*
 *	All functions starting with "parse" should succeed, otherwise
 *	the program fails. 
 *	Most routines return pointers to static data that may change
 *	between calls to the same or other routines with a few exceptions:
 *	"host_to_addr", "parse_hostnetwork", and "parse_hostnetworkmask"
 *	return global static data.
*/

static struct in_addr *
parse_hostnetwork(const char *name, unsigned int *naddrs)
{
	struct in_addr *addrp, *addrptmp;

	if ((addrptmp = dotted_to_addr(name)) != NULL) {
		addrp = fw_malloc(sizeof(struct in_addr));
		inaddrcpy(addrp, addrptmp);
		*naddrs = 1;
		return addrp;
	} else if ((addrptmp = network_to_addr(name)) != NULL) {
		addrp = fw_malloc(sizeof(struct in_addr));
		inaddrcpy(addrp, addrptmp);
		*naddrs = 1;
		return addrp;
	} else if ((addrp = host_to_addr(name, naddrs)) != NULL) {
		return addrp;
	} else 
		exit_error(PARAMETER_PROBLEM, "host/network `%s' not found", name);
}

static void
parse_hostnetworkmask(const char *name, struct in_addr **addrpp,
		struct in_addr *maskp, unsigned int *naddrs)
{
	struct in_addr *addrp;
	char buf[256];
	char *p;
	int i, j, k, n;

	strncpy(buf, name, sizeof(buf) - 1);
	if ((p = strrchr(buf, '/')) != NULL) {
		*p = '\0';
		addrp = parse_mask(p + 1);
	} else
		addrp = parse_mask(NULL);
	inaddrcpy(maskp, addrp);

	/* if a null mask is given, the name is ignored, like in "any/0" */
	if (maskp->s_addr == 0L)
		strcpy(buf, "0.0.0.0");

	addrp = *addrpp = parse_hostnetwork(buf, naddrs);
	n = *naddrs;
	for (i = 0, j = 0; i < n; i++) {
		addrp[j++].s_addr &= maskp->s_addr;
		for (k = 0; k < j - 1; k++) {
			if (addrp[k].s_addr == addrp[j - 1].s_addr) {
				(*naddrs)--;
				j--;
				break;
			}
		}
	}
}

static struct in_addr *
parse_mask(char *mask)
{
	static struct in_addr maskaddr;
	struct in_addr *addrp;
	int bits;

	if (mask == NULL) {
		/* no mask at all defaults to 32 bits */
		maskaddr.s_addr = 0xFFFFFFFF;
		return &maskaddr;
	} else if ((addrp = dotted_to_addr(mask)) != NULL) {
		/* dotted_to_addr already returns a network byte order addr */
		return addrp;
	} else if ((bits = string_to_number(mask, 0, 32)) == -1) {
		exit_error(PARAMETER_PROBLEM, "invalid mask `%s' specified", mask);
	} else if (bits != 0) {
		maskaddr.s_addr = htonl(0xFFFFFFFF << (32 - bits));
		return &maskaddr;
	} else {
		maskaddr.s_addr = 0L;
		return &maskaddr;
	}
}

static const char *
parse_policy(const char *policy)
{
	if (strcmp(policy, IP_FW_LABEL_ACCEPT) == 0 
	    || strcmp(policy, IP_FW_LABEL_BLOCK) == 0
	    || strcmp(policy, IP_FW_LABEL_REJECT) == 0
	    || strcmp(policy, IP_FW_LABEL_MASQUERADE) == 0)
		return policy;

	exit_error(PARAMETER_PROBLEM, "Invalid policy `%s'.", policy);
}

static unsigned short int
parse_protocol(const char *s)
{
	int proto = string_to_number(s, 0, 65535);

	if (proto != -1) return (unsigned short)proto;

	if (strncmp("all", s, strlen(s)) == 0)
		return 0;
	else if (strncasecmp("tcp", s, strlen(s)) == 0)
		return IPPROTO_TCP;
	else if (strncasecmp("udp", s, strlen(s)) == 0)
		return IPPROTO_UDP;
	else if (strncasecmp("icmp", s, strlen(s)) == 0)
		return IPPROTO_ICMP;
	else {
		exit_error(PARAMETER_PROBLEM, "invalid protocol `%s' specified", s);
	}
}

static void 
parse_icmp(const char *srcportstring, const char *dstportstring,
	   __u16 *type, __u16* code, int *options, __u16 invflags, 
	   int checking)
{
	if (srcportstring) {
		const unsigned int limit 
			= sizeof(icmp_codes)/sizeof(struct icmp_names);
		unsigned int match = limit;
		unsigned int i;

		for (i = 0; i < limit; i++) {
			if (strncasecmp(icmp_codes[i].name, srcportstring,
					strlen(srcportstring)) == 0) {
				if (match != limit)
					exit_error(PARAMETER_PROBLEM, "Ambiguous ICMP `%s' : "
						   "`%s' or `%s'?",
						   srcportstring, 
						   icmp_codes[match].name, 
						   icmp_codes[i].name);
				match = i;
			}
		}
		
		if (match != limit) {
			if (dstportstring)
				exit_error(PARAMETER_PROBLEM, "Can't use ICMP name and destination port together");
			*options |= OPT_DSTPT;
			type[0] = type[1] = icmp_codes[match].type;
			code[0] = icmp_codes[match].code_min;
			code[1] = icmp_codes[match].code_max;
			if (checking) {
				if (icmp_codes[match].use_code_min_for_testing)
					code[1] = code[0];
				else if (code[0] != code[1])
					exit_error(PARAMETER_PROBLEM, "Must specify exact ICMP type for testing");
			}

			/* Inverting won't do what they think it will do. */
			if (invflags & (IP_FW_INV_SRCPT | IP_FW_INV_DSTPT))
				exit_error(PARAMETER_PROBLEM, "Can't invert named ICMP types");

			return;
		}
	}
	parse_ports(srcportstring, type, IPPROTO_ICMP);
	parse_ports(dstportstring, code, IPPROTO_ICMP);
}

static void 
parse_ports(const char *portstring, __u16 *ports, __u16 proto)
{
	char *buffer;
	char *cp;

	if (portstring == NULL) {
		ports[0] = 0;
		ports[1] = 0xFFFF;
		return;
	}

	buffer = strdup(portstring);
	if ((cp = strchr(buffer, ':')) == NULL) {
		ports[0] = ports[1] = parse_port(buffer, proto);
	}
	else {
		*cp = '\0';
		cp++;

		ports[0] = buffer[0] ? parse_port(buffer, proto) : 0;
		ports[1] = cp[0] ? parse_port(cp, proto) : 0xFFFF;
	}
	free(buffer);
}

static unsigned short
parse_mark(char *markstring, __u32 *mark)
{
	char *end, *ptr;
	unsigned long l;

	if (*markstring == '-' || *markstring == '+')
		ptr = markstring+1;
	else ptr = markstring;

	l = strtoul(ptr, &end, 0);

	if (end[0] != '\0' || end == ptr || l > UINT_MAX)
		exit_error(PARAMETER_PROBLEM, "Bad value `%s' for -%c.\n",
			   markstring, opt2char(OPT_MARK));

	/* This gives the effect of subtraction in the kernel */
	if (*markstring == '-') 
		*mark = (__u32)(-(__s32)l);
	else *mark = (__u32)l;

	if (*markstring == '-' || *markstring == '+') 
		return 0;
	else return IP_FW_F_MARKABS;
}

static unsigned short 
parse_outputsize(char *outputstring, __u16 *outputsize)
{
	if (!outputstring) {
		*outputsize = 65535;
	}
	else {
		int i = string_to_number(outputstring, 0, 65535);
		if (i == -1) 
			exit_error(PARAMETER_PROBLEM, "-o argument must be 0-65535, not `%s'",
				   outputstring);
		*outputsize = (__u16)i;
	}
	return IP_FW_F_NETLINK;
}

static unsigned short 
parse_interface(const char *ifstring, char *vianame)
{
	if (strlen(ifstring) > IFNAMSIZ)
		exit_error(PARAMETER_PROBLEM, "interface name `%s' must be shorter than IFNAMSIZ (%i)", 
			   ifstring, IFNAMSIZ);

	strncpy(vianame, ifstring, IFNAMSIZ);
	if (vianame[0] == '\0') 
		return IP_FW_F_WILDIF;
	else if(vianame[strlen(ifstring)-1] == '+') {
		vianame[strlen(ifstring)-1] = '\0';
		return IP_FW_F_WILDIF;
	}
	else return 0;
}

static __u16
parse_port(const char *port, unsigned short proto)
{
	int portnum;

	if (proto != IPPROTO_ICMP 
	    && proto != IPPROTO_TCP 
	    && proto != IPPROTO_UDP)
		exit_error(PARAMETER_PROBLEM, "can only specify ports for icmp, tcp or udp");
	else if ((portnum = string_to_number(port, 0, 65535)) != -1)
		return (unsigned short) portnum;
	else if (proto == IPPROTO_ICMP) {
		/* ICMP types (given as port numbers) must be numeric! */
		exit_error(PARAMETER_PROBLEM, "invalid ICMP type `%s' specified", port);
	} else if ((portnum = service_to_port(port, proto)) != -1)
		return (unsigned short) portnum;
	else {
		exit_error(PARAMETER_PROBLEM, "invalid port/service `%s' specified", port);
	}
}

/* Can't be zero. */
static int
parse_rulenumber(const char *rule)
{
	int rulenum = string_to_number(rule, 1, INT_MAX);
	if (rulenum == -1) exit_error(PARAMETER_PROBLEM, "Invalid rule number `%s'", rule);

	return rulenum;
}

static void
parse_hexbyte(char *s, unsigned char *b)
{
	long number;
	char *end;

	number = strtol(s, &end, 16);
	if (*end == '\0' && end != s) {
		/* we parsed a number, let's see if we want this */
		if (0 <= number && number <= 255)
			*b = (unsigned char) number;
		else {
			exit_error(PARAMETER_PROBLEM, "invalid hexbyte `%s' specified", s);
		}
	} else {
		exit_error(PARAMETER_PROBLEM, "invalid hexbyte `%s' specified", s);
	}
}

static int
parse_timeout(char *s)
{
	int timeout;

	if ((timeout = string_to_number(s, 0, INT_MAX)) != -1)
		return timeout;
	else 
		exit_error(PARAMETER_PROBLEM, "invalid timeout value `%s' specified", s);
}

static const char *
parse_target(const char *targetname)
{
	const char *ptr;
	if (targetname == NULL || strlen(targetname) < 1)
		exit_error(PARAMETER_PROBLEM, "Invalid target name (too short)");

	if (strlen(targetname)+1 > sizeof(ip_chainlabel))
		exit_error(PARAMETER_PROBLEM, "Invalid target name `%s' (%i chars max)",
			   targetname, sizeof(ip_chainlabel)-1);

	for (ptr = targetname; *ptr; ptr++)
		if (isspace(*ptr)) exit_error(PARAMETER_PROBLEM, "Invalid target name `%s'",
					      targetname);

	return targetname;
}

static struct in_addr *
host_to_addr(const char *name, unsigned int *naddr)
{
	struct hostent *host;
	struct in_addr *addr;
	unsigned int i;

	*naddr = 0;
	if ((host = gethostbyname(name)) != NULL) {
		if (host->h_addrtype != AF_INET ||
				host->h_length != sizeof(struct in_addr))
			return (struct in_addr *) NULL;
		while (host->h_addr_list[*naddr] != (char *) NULL)
			(*naddr)++;
		addr = fw_calloc(*naddr, sizeof(struct in_addr));
		for (i = 0; i < *naddr; i++)
			inaddrcpy(&(addr[i]), (struct in_addr *) host->h_addr_list[i]);
		return addr;
	} else
		return (struct in_addr *) NULL;
}

static char *
addr_to_host(struct in_addr *addr)
{
	struct hostent *host;

	if ((host = gethostbyaddr((char *) addr,
			sizeof(struct in_addr), AF_INET)) != NULL)
		return (char *) host->h_name;
	else
		return (char *) NULL;
}

static struct in_addr *
network_to_addr(const char *name)
{
	struct netent *net;
	static struct in_addr addr;

	if ((net = getnetbyname(name)) != NULL) {
		if (net->n_addrtype != AF_INET)
			return (struct in_addr *) NULL;
		addr.s_addr = htonl((unsigned long) net->n_net);
		return &addr;
	} else
		return (struct in_addr *) NULL;
}

static char *
addr_to_network(struct in_addr *addr)
{
	struct netent *net;
 
	if ((net = getnetbyaddr((long) ntohl(addr->s_addr), AF_INET)) != NULL)
		return (char *) net->n_name;
	else
		return (char *) NULL;
}

static char *
addr_to_anyname(struct in_addr *addr)
{
	char *name;

	if ((name = addr_to_host(addr)) != NULL)
		return name;
	else if ((name = addr_to_network(addr)) != NULL)
		return name;
	else
		return addr_to_dotted(addr);
}

static struct in_addr *
dotted_to_addr(const char *dotted)
{
	static struct in_addr addr;
	unsigned char *addrp;
	char *p, *q;
	int onebyte, i;
	char buf[20];

	/* copy dotted string, because we need to modify it */
	strncpy(buf, dotted, sizeof(buf) - 1);
	addrp = (unsigned char *) &(addr.s_addr);

	p = buf;
	for (i = 0; i < 3; i++) {
		if ((q = strchr(p, '.')) == NULL)
			return (struct in_addr *) NULL;
		else {
			*q = '\0';
			if ((onebyte = string_to_number(p, 0, 255)) == -1)
				return (struct in_addr *) NULL;
			else
				addrp[i] = (unsigned char) onebyte;
		}
		p = q + 1;
	}

	/* we've checked 3 bytes, now we check the last one */
	if ((onebyte = string_to_number(p, 0, 255)) == -1)
		return (struct in_addr *) NULL;
	else
		addrp[3] = (unsigned char) onebyte;
		
	return &addr;
}

static char *
addr_to_dotted(struct in_addr *addrp)
{
	static char buf[20];
	unsigned char *bytep;

	bytep = (unsigned char *) &(addrp->s_addr);
	sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
	return buf;
}

static char *
mask_to_dotted(struct in_addr *mask)
{
	int i;
	static char buf[20];
	__u32 maskaddr, bits;

	maskaddr = ntohl(mask->s_addr);

	if (maskaddr == 0xFFFFFFFFL)
		/* we don't want to see "/32" */
		return "";
	else {
		i = 32;
		bits = 0xFFFFFFFEL;
		while (--i >= 0 && maskaddr != bits)
			bits <<= 1;
		if (i >= 0)
			sprintf(buf, "/%d", i);
		else
			/* mask was not a decent combination of 1's and 0's */
			sprintf(buf, "/%s", addr_to_dotted(mask));
		return buf;
	}
}

static int
service_to_port(const char *name, unsigned short proto)
{
	struct servent *service;

	if (proto == IPPROTO_TCP
	    && (service = getservbyname(name, "tcp")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else if (proto == IPPROTO_UDP 
		 && (service = getservbyname(name, "udp")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else
		return -1;
}

static char *
port_to_service(int port, unsigned short proto)
{
	struct servent *service;

	if (proto == IPPROTO_TCP &&
			(service = getservbyport(htons(port), "tcp")) != NULL)
		return service->s_name;
	else if (proto == IPPROTO_UDP &&
			(service = getservbyport(htons(port), "udp")) != NULL)
		return service->s_name;
	else
		return (char *) NULL;
}

static int
string_to_number(const char *s, int min, int max)
{
	int number;
	char *end;

	number = (int)strtol(s, &end, 10);
	if (*end == '\0' && end != s) {
		/* we parsed a number, let's see if we want this */
		if (min <= number && number <= max)
			return number;
		else
			return -1;
	} else
		return -1;
}

static void
swap_info(struct ip_fw *fw, int isicmp)
{
	__u16 tmp;
	__u32 tmpMask;

	/* Swap source and dest masks. */
	tmpMask = fw->fw_smsk.s_addr;
	fw->fw_smsk.s_addr = fw->fw_dmsk.s_addr;
	fw->fw_dmsk.s_addr = tmpMask;

	/* Swap source an dest inverse flags (clear and reset)*/
	tmp = fw->fw_invflg;
	fw->fw_invflg &= ~(IP_FW_INV_SRCIP | IP_FW_INV_DSTIP);
	fw->fw_invflg |= ((tmp & IP_FW_INV_SRCIP ? IP_FW_INV_DSTIP : 0)
			  | (tmp & IP_FW_INV_DSTIP ? IP_FW_INV_SRCIP : 0));

	if (!isicmp) {
		/* Swap source & dest ports */
		tmp = fw->fw_spts[0];
		fw->fw_spts[0] = fw->fw_dpts[0];
		fw->fw_dpts[0] = tmp;

		tmp = fw->fw_spts[1];
		fw->fw_spts[1] = fw->fw_dpts[1];
		fw->fw_dpts[1] = tmp;

		/* Swap src & dst port inverse flags.*/
		tmp = fw->fw_invflg;
		fw->fw_invflg &= ~(IP_FW_INV_SRCPT | IP_FW_INV_DSTPT);

		fw->fw_invflg |= ((tmp & IP_FW_INV_SRCPT ? IP_FW_INV_DSTPT : 0)
				  | (tmp & IP_FW_INV_DSTPT ? IP_FW_INV_SRCPT : 0));
	}
}

static int 
append_entry(const ip_chainlabel chain, 
	     const struct ip_fwuser *fw,
	     int verbose,
	     int bidir)
{
	unsigned int i, j;
	struct ip_fwchange new;
	int ret = 0;

	memcpy(&new.fwc_rule, fw, sizeof(struct ip_fwuser));
	strcpy(new.fwc_label, chain);
	for (i = 0; i < nsaddrs; i++) {
		new.fwc_rule.ipfw.fw_src.s_addr = saddrs[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			new.fwc_rule.ipfw.fw_dst.s_addr = daddrs[j].s_addr;
			if (verbose)
				print_firewall(stdout, &new.fwc_rule, 
					       0, 0, FMT_PRINT_RULE);
			ret |= do_setsockopt(IP_FW_APPEND, &new, sizeof(new));
		}
	}

	if (bidir) {
		swap_info(&new.fwc_rule.ipfw, 
			  new.fwc_rule.ipfw.fw_proto == IPPROTO_ICMP);
		for (i = 0; i < nsaddrs; i++) {
			new.fwc_rule.ipfw.fw_dst.s_addr = saddrs[i].s_addr;
			for (j = 0; j < ndaddrs; j++) {
				new.fwc_rule.ipfw.fw_src.s_addr = daddrs[j].s_addr;
				if (verbose)
					print_firewall(stdout, &new.fwc_rule, 
						       0, 0, FMT_PRINT_RULE);
				ret |= do_setsockopt(IP_FW_APPEND, &new, sizeof(new));
			}
		}
	}

	return ret;
}

static int
replace_entry(const ip_chainlabel chain, 
	      const struct ip_fwuser *fw, 
	      unsigned int rulenum,
	      int verbose)
{
	struct ip_fwnew new;


	if (nsaddrs != 1 || ndaddrs != 1)
		exit_error(PARAMETER_PROBLEM, "Replacement rule does not "
			   "specify a unique address");

	memcpy(&new.fwn_rule, fw, sizeof(struct ip_fwuser));
	strcpy(new.fwn_label, chain);
	new.fwn_rulenum = rulenum;

	new.fwn_rule.ipfw.fw_src.s_addr = saddrs[0].s_addr;
	new.fwn_rule.ipfw.fw_dst.s_addr = daddrs[0].s_addr;
	if (verbose)
		print_firewall(stdout, &new.fwn_rule, 0, 0, FMT_PRINT_RULE);
	return do_setsockopt(IP_FW_REPLACE, &new, sizeof(new));
}

static int
insert_entry(const ip_chainlabel chain, 
	     const struct ip_fwuser *fw, 
	     unsigned int rulenum,
	     int verbose, int bidir)
{
	unsigned int i, j;
	int ret = 0;
	struct ip_fwnew new;

	memcpy(&new.fwn_rule, fw, sizeof(struct ip_fwuser));
	strcpy(new.fwn_label, chain);
	new.fwn_rulenum = rulenum;

	for (i = 0; i < nsaddrs; i++) {
		new.fwn_rule.ipfw.fw_src.s_addr = saddrs[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			new.fwn_rule.ipfw.fw_dst.s_addr = daddrs[j].s_addr;
			if (verbose)
				print_firewall(stdout, &new.fwn_rule, 
					       0, 0, FMT_PRINT_RULE);
			ret |= do_setsockopt(IP_FW_INSERT, &new, sizeof(new));
		}
	}
	if (bidir) {
		swap_info(&new.fwn_rule.ipfw,
			  new.fwn_rule.ipfw.fw_proto == IPPROTO_ICMP);

		for (i = 0; i < nsaddrs; i++) {
			new.fwn_rule.ipfw.fw_dst.s_addr = saddrs[i].s_addr;
			for (j = 0; j < ndaddrs; j++) {
				new.fwn_rule.ipfw.fw_src.s_addr = daddrs[j].s_addr;
				if (verbose)
					print_firewall(stdout, &new.fwn_rule, 
						       0, 0, FMT_PRINT_RULE);
				ret |= do_setsockopt(IP_FW_INSERT, &new, sizeof(new));
			}
		}
	}

	return ret;
}

static int
delete_entry(const ip_chainlabel chain, 
	     const struct ip_fwuser *fw, 
	     int verbose, int bidir)
{
	unsigned int i, j;
	struct ip_fwchange new;
	int ret = 0;

	memcpy(&new.fwc_rule, fw, sizeof(struct ip_fwuser));
	strcpy(new.fwc_label, chain);
	for (i = 0; i < nsaddrs; i++) {
		new.fwc_rule.ipfw.fw_src.s_addr = saddrs[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			new.fwc_rule.ipfw.fw_dst.s_addr = daddrs[j].s_addr;
			if (verbose)
				print_firewall(stdout, &new.fwc_rule, 
					       0, 0, FMT_PRINT_RULE);
			ret |= do_setsockopt(IP_FW_DELETE, &new, sizeof(new));
		}
	}
	if (bidir) {
		swap_info(&new.fwc_rule.ipfw,
			  new.fwc_rule.ipfw.fw_proto == IPPROTO_ICMP);
		for (i = 0; i < nsaddrs; i++) {
			new.fwc_rule.ipfw.fw_dst.s_addr = saddrs[i].s_addr;
			for (j = 0; j < ndaddrs; j++) {
				new.fwc_rule.ipfw.fw_src.s_addr = daddrs[j].s_addr;
				if (verbose)
					print_firewall(stdout, &new.fwc_rule, 
						       0, 0, FMT_PRINT_RULE);
				ret |= do_setsockopt(IP_FW_DELETE, &new, sizeof(new));
			}
		}
	}	
	return ret;
}

static int
delete_num_entry(const ip_chainlabel chain, unsigned int rulenum)
{
	struct ip_fwdelnum fwd;

	fwd.fwd_rulenum = rulenum;
	strcpy(fwd.fwd_label, chain);
	return do_setsockopt(IP_FW_DELETE_NUM, &fwd, sizeof(fwd));
}

static int 
check_packet(const ip_chainlabel chain, 
	     struct ip_fwuser *fw, 
	     int verbose,
	     int bidir)
{
	int ret = 0;
	unsigned int i, j;
	struct ip_fwtest *packet;

	for (i = 0; i < nsaddrs; i++) {
		fw->ipfw.fw_src.s_addr = saddrs[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			fw->ipfw.fw_dst.s_addr = daddrs[j].s_addr;
			if (verbose)
				print_firewall(stdout, fw, 0, 0, 
					       FMT_PRINT_RULE);
			packet = fw_to_fwtest(&fw->ipfw, chain);
			ret |= do_setsockopt(IP_FW_CHECK, packet, 
					     sizeof(struct ip_fwtest));
		}
	}

	if (bidir) {
		swap_info(&fw->ipfw,
			  fw->ipfw.fw_proto == IPPROTO_ICMP);
		for (i = 0; i < nsaddrs; i++) {
			fw->ipfw.fw_dst.s_addr = saddrs[i].s_addr;
			for (j = 0; j < ndaddrs; j++) {
				fw->ipfw.fw_src.s_addr = daddrs[j].s_addr;
				if (verbose)
					print_firewall(stdout, fw, 0, 0,
						       FMT_PRINT_RULE);
				packet = fw_to_fwtest(&fw->ipfw, chain);
				ret |= do_setsockopt(IP_FW_CHECK, packet, 
						     sizeof(struct ip_fwtest));
			}
		}
	}

	return ret;
}

static int
for_each_chain(int (*fn)(const ip_chainlabel))
{
	ip_chainlabel chain;
	ip_chainlabel policy;
	int dummy, ret = 0, nread;
	FILE *fp;

	/* Read names from IP_FW_PROC_CHAIN_NAMES */
	if ((fp = fopen("/proc/net/"IP_FW_PROC_CHAIN_NAMES, "r")) == NULL)
		exit_error(OTHER_PROBLEM, "cannot open file `/proc/net/"
			   IP_FW_PROC_CHAIN_NAMES"'");

	while ((nread = fscanf(fp,"%s %s %i %u %u %u %u", chain, policy, 
			       &dummy, &dummy, &dummy, &dummy, &dummy)) == 7)
		ret |= fn(chain);

	if (nread != -1)
		exit_error(VERSION_PROBLEM, "unexpected input from "
			   "`/proc/net/"IP_FW_PROC_CHAIN_NAMES"'");
	return ret;
}
	
static int 
flush_entries(const ip_chainlabel chain)
{
	if (!chain) return for_each_chain(flush_entries);
	else return do_setsockopt(IP_FW_FLUSH, chain, sizeof(ip_chainlabel));
}

static int 
zero_entries(const ip_chainlabel chain)
{
	if (!chain) return for_each_chain(zero_entries);
	else return do_setsockopt(IP_FW_ZERO, chain, sizeof(ip_chainlabel));
}

static int 
new_chain(const ip_chainlabel chain)
{
	return do_setsockopt(IP_FW_CREATECHAIN, chain, sizeof(ip_chainlabel));
}

static int 
delete_chain(const ip_chainlabel chain, int verbose)
{
	if (!chain) {
		ip_chainlabel *chains = NULL;
		ip_chainlabel policy;
		int dummy, ret = 0, nread;
		unsigned int i, nchains = 0;
		FILE *fp;

		/* Read names from IP_FW_PROC_CHAIN_NAMES */
		if ((fp = fopen("/proc/net/"IP_FW_PROC_CHAIN_NAMES, "r")) 
		    == NULL)
			exit_error(PARAMETER_PROBLEM, "cannot open file `/proc/net/"
				   IP_FW_PROC_CHAIN_NAMES"'");

		chains = malloc(sizeof(ip_chainlabel));
		while ((nread = fscanf(fp,"%s %s %i %u %u %u %u", 
				       chains[nchains], policy, &dummy,
				       &dummy, &dummy, &dummy, &dummy))
		       == 7) {
			/* Don't try to delete builtin chains */
			if (strcmp(policy, "-") == 0)
				chains = realloc(chains, 
						 ++nchains*sizeof(ip_chainlabel));
		}

		
		if (nread != -1)
			exit_error(VERSION_PROBLEM, "unexpected input from "
				   "`/proc/net/"IP_FW_PROC_CHAIN_NAMES"'");

		fclose(fp);
		for (i = 0; i < nchains; i++)
			ret |= delete_chain(chains[i], verbose);

		free(chains);
		return ret;
	}

	if (verbose)
		fprintf(stdout, "Deleting chain `%s'\n", chain);
	return do_setsockopt(IP_FW_DELETECHAIN, chain, sizeof(ip_chainlabel));
}

static int 
set_policy(const ip_chainlabel chain, const ip_chainlabel policy)
{
	struct ip_fwpolicy fwp;

	strcpy(fwp.fwp_policy, policy);
	strcpy(fwp.fwp_label, chain);
	return do_setsockopt(IP_FW_POLICY, &fwp, sizeof(fwp));
}

static int
list_entries(const ip_chainlabel chain, 
	     const char *openmode, 
	     int verbose, int numeric, int expanded)
{
	FILE *fp;
	int i;
	struct ip_fwchange *fwlist;
	__u64 *counterlist;
	int ntotal = 0, nread, format;
	ip_chainlabel ch, policy;
	int refcnt, first = 1;
	unsigned int limit;
	unsigned int pkthi, pktlo, bytehi, bytelo;

	if (!chain) return list_all_entries(verbose, numeric, expanded);

	/* Read policy from IP_FW_PROC_CHAIN_NAMES */
	if ((fp = fopen("/proc/net/"IP_FW_PROC_CHAIN_NAMES, "r")) == NULL)
		exit_error(OTHER_PROBLEM, "cannot open file `/proc/net/"
			   IP_FW_PROC_CHAIN_NAMES"'");

	/* Old-style don't have packet and byte counters */
	while ((i = fscanf(fp,"%s %s %i %u %u %u %u", ch, policy, 
			   &refcnt, &pkthi, &pktlo, &bytehi, &bytelo)) == 7) 
		if (strcmp(ch, chain) == 0) break;

	fclose(fp);
	if (i != -1 && i != 7)
		exit_error(VERSION_PROBLEM, "unexpected input from "
			   "`/proc/net/"IP_FW_PROC_CHAIN_NAMES"'");

	if (strcmp(ch, chain) != 0) 
		exit_error(PARAMETER_PROBLEM, "unknown chain `%s'.", chain);

	if ((fp = fopen("/proc/net/"IP_FW_PROC_CHAINS, openmode)) == NULL)
		exit_error(OTHER_PROBLEM, "cannot open file `/proc/net/"
			   IP_FW_PROC_CHAINS"'");

	limit = 8;
	fwlist = fw_malloc(limit * sizeof(struct ip_fwchange));
	counterlist = fw_malloc(limit * 2 * sizeof(__u64));
	while ((nread = read_procinfo(fp, &(fwlist[ntotal]), 
				      &(counterlist[ntotal*2]), 
				      limit-ntotal)) 
	       == limit-ntotal) {
		ntotal += nread;
		limit *= 2;
		fwlist = fw_realloc(fwlist, limit*sizeof(struct ip_fwchange));
		counterlist = fw_realloc(counterlist, limit * 2*sizeof(__u64));
	}
	ntotal += nread;
	fclose(fp);

	format = FMT_OPTIONS;
	if (!verbose)
		format |= FMT_NOCOUNTS;
	else format |= FMT_TOS | FMT_VIA | FMT_MARK | FMT_NETLINK;

	if (numeric)
		format |= FMT_NUMERIC;

	if (!expanded)
		format |= FMT_KILOMEGAGIGA;

	printf("Chain %s ", chain);
	if (strcmp(policy, "-") == 0) 
		printf("(refcnt = %i):", refcnt);
	else if (!(format & FMT_NOCOUNTS))
		printf("(policy %s: %llu packets, %llu bytes):", 
		       policy, ((__u64)pkthi)<<32 | pktlo, 
		       ((__u64)bytehi)<<32 | bytelo);
	else
		printf("(policy %s):", policy);
	printf("\n");
	for (i = 0; i < ntotal; i++) {
		if (strcmp(fwlist[i].fwc_label, chain) == 0) {
			print_firewall(stdout, &fwlist[i].fwc_rule,
				       counterlist[i*2+1], counterlist[i*2], 
				       (first) ?(format | FMT_HEADER): format);
			first = 0;
		}
	}
	free(fwlist);
	return 0;
}

static int
list_all_entries(int verbose, int numeric, int expanded)
{
	struct chainname {
		ip_chainlabel label;
		ip_chainlabel policy;
		unsigned int refcnt;
		__u64 packets, bytes;
	} *chains = NULL;
	FILE *fp;
	struct ip_fwchange *fwlist;
	__u64 *counterlist;
	unsigned int ntotal = 0, nread, pkthi=0, pktlo=0, bytehi=0, bytelo=0;
	int format, printedrules = 0;
	unsigned int i = 0, nchains, limit, j = 0;

	/* Read policy from IP_FW_PROC_CHAIN_NAMES */
	if ((fp = fopen("/proc/net/"IP_FW_PROC_CHAIN_NAMES, "r")) == NULL)
		exit_error(OTHER_PROBLEM, "cannot open file `/proc/net/"
			   IP_FW_PROC_CHAIN_NAMES"'");

	chains = fw_malloc(sizeof(struct chainname));
	while ((nread = fscanf(fp,"%s %s %i %u %u %u %u", chains[i].label, 
			       chains[i].policy, &chains[i].refcnt,
			       &pkthi, &pktlo, &bytehi, &bytelo)) == 7) {
		chains[i].packets = ((__u64)pkthi)<<32|pktlo;
		chains[i].bytes = ((__u64)bytehi)<<32|bytelo;
		i++;
		chains = fw_realloc(chains, (i+1)*sizeof(struct chainname));
	}

	if (nread != -1)
		exit_error(VERSION_PROBLEM, "unexpected input from "
			   "`/proc/net/"IP_FW_PROC_CHAIN_NAMES"'");
	fclose(fp);
	nchains = i-1;

	if ((fp = fopen("/proc/net/"IP_FW_PROC_CHAINS, "r")) == NULL)
		exit_error(OTHER_PROBLEM, "cannot open file `/proc/net/"
			   IP_FW_PROC_CHAINS"'");

	limit = 8;
	fwlist = fw_malloc(limit * sizeof(struct ip_fwchange));
	counterlist = fw_malloc(limit * 2 * sizeof(__u64));
	while ((nread = read_procinfo(fp, &(fwlist[ntotal]), 
				      &(counterlist[ntotal*2]), limit-ntotal)) 
	       == limit-ntotal) {
		ntotal += nread;
		limit*=2;
		fwlist = fw_realloc(fwlist, 
				    limit*sizeof(struct ip_fwchange));
		counterlist = fw_realloc(counterlist,
					 limit*2*sizeof(__u64));
	}
	ntotal += nread;
	fclose(fp);

	format = FMT_OPTIONS;
	if (!verbose)
		format |= FMT_NOCOUNTS;
	else format |= FMT_TOS | FMT_VIA | FMT_MARK | FMT_NETLINK;

	if (numeric)
		format |= FMT_NUMERIC;

	if (!expanded)
		format |= FMT_KILOMEGAGIGA;

	printf("Chain %s ", chains[j].label);
	if (strcmp(chains[j].policy, "-") == 0) 
		printf("(refcnt = %i):", chains[j].refcnt);
	else if (!(format & FMT_NOCOUNTS))
		printf("(policy %s: %llu packets, %llu bytes):", 
		       chains[j].policy, chains[j].packets, chains[j].bytes);
	else
		printf("(policy %s):", chains[j].policy);
	printf("\n");

	for (i = 0; i < ntotal; i++) {
		while (strcmp(chains[j].label, fwlist[i].fwc_label) != 0){
			j++;
			if (j > nchains) 
				exit_error(VERSION_PROBLEM, 
					   "Unexpected chain `%s'",
					   fwlist[i].fwc_label);
			if (printedrules) printf("\n");
			printf("Chain %s ", chains[j].label);
			if (strcmp(chains[j].policy, "-") == 0) 
				printf("(refcnt = %i):", chains[j].refcnt);
			else if (!(format & FMT_NOCOUNTS))
				printf("(policy %s: %llu packets, %llu bytes):", 
				       chains[j].policy, chains[j].packets, 
				       chains[j].bytes);
			else
				printf("(policy %s):", chains[j].policy);
			printf("\n");
			printedrules = 0;
		}
		print_firewall(stdout, &fwlist[i].fwc_rule,
			       counterlist[i*2+1], counterlist[i*2], 
			       (i) ? format : (format | FMT_HEADER));
		printedrules = 1;
	}
	while (j < nchains) {
		j++;
		if (printedrules) printf("\n");
		printf("Chain %s ", chains[j].label);
		if (strcmp(chains[j].policy, "-") == 0)
			printf("(refcnt = %i):", chains[j].refcnt);
		else if (!(format & FMT_NOCOUNTS))
			printf("(policy %s: %llu packets, %llu bytes):", 
			       chains[j].policy, chains[j].packets, 
			       chains[j].bytes);
		else
			printf("(policy %s):", chains[j].policy);
		printf("\n");
		printedrules = 0;
	}
	free(fwlist);
	free(chains);
	return 0;
}

static int
list_masq(unsigned int options)
{
	FILE *fp;
	int i;
	char buf[256];
	struct masq *mslist;
	int ntotal = 0, nread, format;

	if ((fp = fopen("/proc/net/ip_masquerade", "r")) == NULL)
		exit_error(OTHER_PROBLEM, "cannot open file `/proc/net/ip_masquerade'");

	if (fgets(buf, sizeof(buf), fp) == NULL)
		exit_error(VERSION_PROBLEM, 
			   "unexpected input from `/proc/net/ip_masquerade'");
	fputs("IP masquerading entries\n", stdout);

	mslist = (struct masq *) fw_malloc(16 * sizeof(struct masq));
	while ((nread = read_masqinfo(fp, &(mslist[ntotal]), 16)) == 16) {
		ntotal += nread;
		mslist = (struct masq *) fw_realloc(mslist,
			(ntotal + 16) * sizeof(struct masq));
	}
	ntotal += nread;
	fclose(fp);

	format = 0;

	if (options & OPT_NUMERIC)
		format |= FMT_NUMERIC;

	if (options & OPT_VERBOSE)
		format |= FMT_DELTAS;

	if (ntotal > 0)
		for (i = 0; i < ntotal; i++)
			print_masq(stdout, &(mslist[i]),
				(i) ? format : (format | FMT_HEADER));

	free(mslist);
	return 0;
}

static void
print_port(FILE *fp, int numeric, __u16 port, __u16 proto)
{
	char *service;
	if (numeric || (service = port_to_service(port, proto)) == NULL)
		fprintf(fp, "%u", port);
	else 
		fputs(service, fp);
}

static void
print_firewall(FILE *fp, 
	       struct ip_fwuser *fw, 
	       __u64 bytes, __u64 packets, 
	       int format)
{
	unsigned short flags;
	__u64 cnt, cntkb, cntmb, cntgb;
	char buf[BUFSIZ];
	flags = fw->ipfw.fw_flg;

#define FMT(tab,notab) ((format & FMT_NOTABLE) ? notab : tab)

	if (format & FMT_HEADER) {
		if (!(format & FMT_NOCOUNTS)) {
			if (format & FMT_KILOMEGAGIGA) {
				fprintf(fp, FMT("%5s ","%s "), "pkts");
				fprintf(fp, FMT("%5s ","%s "), "bytes");
			} else {
				fprintf(fp, FMT("%8s ","%s "), "pkts");
				fprintf(fp, FMT("%10s ","%s "), "bytes");
			}
		}
		if (!(format & FMT_NOTARGET)) {
			fprintf(fp, FMT("%-9s ","%s "), "target");
		}
		fputs(" prot ", fp);
		if (format & FMT_OPTIONS)
			fputs("opt    ", fp);
		if (format & FMT_TOS)
			fputs("tosa tosx ", fp);
		if (format & FMT_VIA)
			fprintf(fp, FMT(" %-10s ","%s "), "ifname");
		if (format & FMT_MARK)
			fprintf(fp, FMT("%-10s ","%s "), "mark");
		if (format & FMT_NETLINK)
			fprintf(fp, FMT("%-7s ","%s "), "outsize");
		fprintf(fp, FMT(" %-20s ","%s "), "source");
		fprintf(fp, FMT(" %-20s ","%s "), "destination");
		fputs(" ports\n", fp);
	}

	if (!(format & FMT_NOCOUNTS)) {
		cnt = packets;
		if (format & FMT_KILOMEGAGIGA) {
			if (cnt > 99999) {
				cntkb = (cnt + 500) / 1000;
				if (cntkb > 9999) {
					cntmb = (cnt + 500000) / 1000000;
					if (cntmb > 9999) {
						cntgb = (cntmb + 500) / 1000;
						fprintf(fp, 
							FMT("%4lluG ","%lluG "), 
							cntgb);
					}
					else
						fprintf(fp, FMT("%4lluM ","%lluM "), cntmb);
				} else
					fprintf(fp, FMT("%4lluK ","%lluK "), cntkb);
			} else
				fprintf(fp, FMT("%5llu ","%llu "), cnt);
		} else
			fprintf(fp, FMT("%8llu ","%llu "), cnt);
		cnt = bytes;
		if (format & FMT_KILOMEGAGIGA) {
			if (cnt > 99999) {
				cntkb = (cnt + 500) / 1000;
				if (cntkb > 9999) {
					cntmb = (cnt + 500000) / 1000000;
					if (cntmb > 9999) {
						cntgb = (cntmb + 500) / 1000;
						fprintf(fp, 
							FMT("%4lluG ","%lluG "), 
							cntgb);
					}
					else
						fprintf(fp, FMT("%4lluM ","%lluM "), cntmb);
				} else
					fprintf(fp, FMT("%4lluK ","%lluK "), cntkb);
			} else
				fprintf(fp, FMT("%5llu ","%llu "), cnt);
		} else
			fprintf(fp, FMT("%10llu ","%llu "), cnt);
	}

	if (!(format & FMT_NOTARGET))
		fprintf(fp, FMT("%-9s ", "%s "), fw->label);

	fputc(fw->ipfw.fw_invflg & IP_FW_INV_PROTO ? '!' : ' ', fp);
	switch (fw->ipfw.fw_proto) {
	case IPPROTO_TCP:
		fprintf(fp, FMT("%-5s", "%s "), "tcp");
		break;
	case IPPROTO_UDP:
		fprintf(fp, FMT("%-5s", "%s "), "udp");
		break;
	case IPPROTO_ICMP:
		fprintf(fp, FMT("%-5s", "%s "), "icmp");
		break;
	case 0:
		fprintf(fp, FMT("%-5s", "%s "), "all");
		break;
	default:
		fprintf(fp, FMT("%-5hu", "%hu "), fw->ipfw.fw_proto);
	}

	if (format & FMT_OPTIONS) {
		if (format & FMT_NOTABLE)
			fputs("opt    ", fp);
		fputc((fw->ipfw.fw_invflg & IP_FW_INV_SYN) ? '!' : '-', fp);
		fputc((flags & IP_FW_F_TCPSYN) ? 'y' : '-', fp);
		fputc((fw->ipfw.fw_invflg & IP_FW_INV_FRAG) ? '!' : '-', fp);
		fputc((flags & IP_FW_F_FRAG) ? 'f' : '-', fp);
		fputc((flags & IP_FW_F_PRN) ? 'l' : '-', fp);
		fputc((flags & IP_FW_F_NETLINK) ? 'o' : '-', fp);
		fputc(' ', fp);
	}

	if (format & FMT_TOS) {
		if (format & FMT_NOTABLE)
			fputs("tos ", fp);
		fprintf(fp, "0x%02hX 0x%02hX ",
			(unsigned short) fw->ipfw.fw_tosand,
			(unsigned short) fw->ipfw.fw_tosxor);
	}

	if (format & FMT_VIA) {
		fputc(fw->ipfw.fw_invflg & IP_FW_INV_VIA ? '!' : ' ', fp);
		if (fw->ipfw.fw_flg & IP_FW_F_WILDIF
		    && (fw->ipfw.fw_vianame)[0]) {
			fw->ipfw.fw_vianame[strlen(fw->ipfw.fw_vianame)+1]='\0';
			fw->ipfw.fw_vianame[strlen(fw->ipfw.fw_vianame)]='+';
		}
		fprintf(fp, FMT("%-10.16s ","via %.16s "),
			(fw->ipfw.fw_vianame)[0] ? fw->ipfw.fw_vianame :
				((format & FMT_NUMERIC) ? "*" : "any"));
	}

	if (format & FMT_MARK) {
		if (fw->ipfw.fw_flg & IP_FW_F_MARKABS)
			fprintf(fp, FMT("0x%-10x ","mark 0x%x "),fw->ipfw.fw_mark);
		else if (fw->ipfw.fw_mark == 0)
			fputs(FMT("           ", ""), fp);
		else
			fprintf(fp, FMT("0x%+-10x ","mark 0x%+x "), 
				(int)fw->ipfw.fw_mark);
	}

	if (format & FMT_NETLINK) {
		if ((fw->ipfw.fw_flg & IP_FW_F_NETLINK)
		    && (fw->ipfw.fw_outputsize != 0xFFFF))
			fprintf(fp, FMT("%-7hu ","outsize %hu "),
				fw->ipfw.fw_outputsize);
		else
			fputs(FMT("        ", ""), fp);
	}

	if (format & FMT_NOTABLE)
		fputs("  ", fp);

	fputc(fw->ipfw.fw_invflg & IP_FW_INV_SRCIP ? '!' : ' ', fp);
	if (fw->ipfw.fw_smsk.s_addr == 0L && !(format & FMT_NUMERIC))
		fprintf(fp, FMT("%-20s ","%s "), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			sprintf(buf, "%s", addr_to_dotted(&(fw->ipfw.fw_src)));
		else
			sprintf(buf, "%s", addr_to_anyname(&(fw->ipfw.fw_src)));
		strcat(buf, mask_to_dotted(&(fw->ipfw.fw_smsk)));
		fprintf(fp, FMT("%-20s ","%s "), buf);
	}

	fputc(fw->ipfw.fw_invflg & IP_FW_INV_DSTIP ? '!' : ' ', fp);
	if (fw->ipfw.fw_dmsk.s_addr == 0L && !(format & FMT_NUMERIC))
		fprintf(fp, FMT("%-20s","-> %s"), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			sprintf(buf, "%s", addr_to_dotted(&(fw->ipfw.fw_dst)));
		else
			sprintf(buf, "%s", addr_to_anyname(&(fw->ipfw.fw_dst)));
		strcat(buf, mask_to_dotted(&(fw->ipfw.fw_dmsk)));
		fprintf(fp, FMT("%-20s","-> %s"), buf);
	}

	if (format & FMT_NOTABLE)
		fputs("  ", fp);

	if (fw->ipfw.fw_proto != IPPROTO_TCP
	    && fw->ipfw.fw_proto != IPPROTO_UDP
	    && fw->ipfw.fw_proto != IPPROTO_ICMP) {
		fputs("  n/a", fp);
		if (!(format & FMT_NONEWLINE))
			putc('\n', fp);
		return;
	}

	/* ICMP handled specially. */
	if (fw->ipfw.fw_proto == IPPROTO_ICMP
	    && !(fw->ipfw.fw_invflg & IP_FW_INV_SRCPT)
	    && !(fw->ipfw.fw_invflg & IP_FW_INV_DSTPT)
	    && !(format & FMT_NUMERIC)) {
		unsigned int i;
		for (i = 0; 
		     i < sizeof(icmp_codes)/sizeof(struct icmp_names); 
		     i++) {
			if (icmp_codes[i].type == fw->ipfw.fw_spts[0]
			    && icmp_codes[i].type == fw->ipfw.fw_spts[1]
			    && icmp_codes[i].code_min == fw->ipfw.fw_dpts[0]
			    && icmp_codes[i].code_max == fw->ipfw.fw_dpts[1]) {
				fprintf(fp, "  %s", icmp_codes[i].name);
				if (!(format & FMT_NONEWLINE))
					putc('\n', fp);
				return;
			}
		}
	}

	fputs(fw->ipfw.fw_invflg & IP_FW_INV_SRCPT ? " !" : "  ", fp);
	if (fw->ipfw.fw_spts[0] == 0 && fw->ipfw.fw_spts[1] == 0xFFFF)
		fputs((format & FMT_NUMERIC) ? "*" : "any", fp);
	else if (fw->ipfw.fw_spts[0] == fw->ipfw.fw_spts[1]) {
		print_port(fp, format & FMT_NUMERIC, 
			   fw->ipfw.fw_spts[0], fw->ipfw.fw_proto);
	}
	else {
		print_port(fp, format & FMT_NUMERIC, 
			   fw->ipfw.fw_spts[0], fw->ipfw.fw_proto);
		fputc(':', fp);
		print_port(fp, format & FMT_NUMERIC, 
			   fw->ipfw.fw_spts[1], fw->ipfw.fw_proto);
	}

	fputs(" -> ", fp);

	fputs(fw->ipfw.fw_invflg & IP_FW_INV_DSTPT ? " !" : "  ", fp);
	if (fw->ipfw.fw_dpts[0] == 0 && fw->ipfw.fw_dpts[1] == 0xFFFF)
		fputs((format & FMT_NUMERIC) ? "*" : "any", fp);
	else if (fw->ipfw.fw_dpts[0] == fw->ipfw.fw_dpts[1]) {
		print_port(fp, format & FMT_NUMERIC, 
			   fw->ipfw.fw_dpts[0], fw->ipfw.fw_proto);
	}
	else {
		print_port(fp, format & FMT_NUMERIC, 
			   fw->ipfw.fw_dpts[0], fw->ipfw.fw_proto);
		fputc(':', fp);
		print_port(fp, format & FMT_NUMERIC, 
			   fw->ipfw.fw_dpts[1], fw->ipfw.fw_proto);
	}

	if (strcmp(fw->label, IP_FW_LABEL_REDIRECT) == 0) {
		fputs(FMT(" => ", ""), fp);
		if (fw->ipfw.fw_redirpt == 0)
			fputs((format & FMT_NUMERIC) ? " *" : " any", fp);
		else
			print_port(fp, format & FMT_NUMERIC, 
				   fw->ipfw.fw_redirpt, fw->ipfw.fw_proto);
	}

	if (!(format & FMT_NONEWLINE))
		putc('\n', fp);
}

static void
print_masq(FILE *fp, struct masq *ms, int format)
{
	unsigned long minutes, seconds, sec100s;
	unsigned short proto;
	char *service;

	if (format & FMT_HEADER) {
		fputs("prot ", fp);
		fprintf(fp, "%-8s ", "expire");
		if (format & FMT_DELTAS) {
			fprintf(fp, "%10s delta prevd ", "initseq");
		}
		fprintf(fp, "%-20s ", "source");
		fprintf(fp, "%-20s ", "destination");
		fputs("ports\n", fp);
	}

	fprintf(fp, "%-5s", ms->proto);

	sec100s = ms->expires % HZ;
	seconds = (ms->expires / HZ) % 60;
	minutes = ms->expires / (60 * HZ);

	fprintf(fp, "%02ld:%02ld.%02ld ", minutes, seconds, sec100s);

	if (format & FMT_DELTAS) {
		fprintf(fp, "%10lu %5hd %5hd ", (unsigned long) ms->initseq,
			ms->delta, ms->pdelta);
	}

	if (format & FMT_NUMERIC) {
		fprintf(fp, "%-20s ", addr_to_dotted(&(ms->src)));
		fprintf(fp, "%-20s ", addr_to_dotted(&(ms->dst)));
	} else {
		fprintf(fp, "%-20s ", addr_to_anyname(&(ms->src)));
		fprintf(fp, "%-20s ", addr_to_anyname(&(ms->dst)));
	}

	if (strcmp(ms->proto, "TCP") == 0) proto = IPPROTO_TCP;
	else if (strcmp(ms->proto, "UDP") == 0) proto = IPPROTO_UDP;
	else proto = 0;

	if ((format & FMT_NUMERIC) || !proto)
		fprintf(fp, "%u (%u) -> %u\n", ms->sport, ms->mport, ms->dport);
	else {
		if ((service = port_to_service(ms->sport, proto)) != NULL)
			fprintf(fp, "%s (%u) -> ", service, ms->mport);
		else
			fprintf(fp, "%u (%u) -> ", ms->sport, ms->mport);
		if ((service = port_to_service(ms->dport, proto)) != NULL)
			fprintf(fp, "%s\n", service);
		else
			fprintf(fp, "%u\n", ms->dport);
	}
}

static int
read_procinfo(FILE *fp, 
	      struct ip_fwchange *fwlist, 
	      __u64 *countlist, 
	      unsigned int nfwlist)
{
	int n;
	unsigned int nread;
	struct ip_fwuser *fw;
	unsigned short tosand, tosxor;
	unsigned long temp[4];
	unsigned int tmp1, tmp2, tmp3, tmp4;

	for (nread = 0; nread < nfwlist; nread++) {
		fw = &fwlist[nread].fwc_rule;
/* Hack until we get kernel's %llu working. */
		if ((n = fscanf(fp, 
				"%s "				/* Chain name */
				"%lX/%lX->%lX/%lX "		/* IPs */
				"%s "				/* Interface */
				"%hX %hX "			/* flg & invflg */
				"%hu "				/* Protocol */
				"%u %u %u %u "			/* Counters */
				"%hu-%hu %hu-%hu "		/* Ports */
				"A%hX X%hX "			/* TOS masks */
				"%hX "				/* fw_redir */
				"%u "				/* fw_mark */
				"%hu "			/* output size */
				"%s",				/* Target */
				fwlist[nread].fwc_label,
				&temp[0], &temp[1], &temp[2], &temp[3],
				fw->ipfw.fw_vianame,
				&fw->ipfw.fw_flg, &fw->ipfw.fw_invflg,
				&fw->ipfw.fw_proto,
				&tmp1, &tmp2, &tmp3, &tmp4,
				&fw->ipfw.fw_spts[0], &fw->ipfw.fw_spts[1],
				&fw->ipfw.fw_dpts[0], &fw->ipfw.fw_dpts[1],
				&tosand, &tosxor,
				&fw->ipfw.fw_redirpt,
				&fw->ipfw.fw_mark,
				&fw->ipfw.fw_outputsize,
				fw->label)) == -1)
			return nread;
		else if (n != 23)
			exit_error(VERSION_PROBLEM, 
				   "unexpected input from `/proc/net/"IP_FW_PROC_CHAIN_NAMES"'");

		if (strcmp("-", fw->ipfw.fw_vianame) == 0)
			(fw->ipfw.fw_vianame)[0] = '\0';
		fw->ipfw.fw_tosand = (unsigned char) tosand;
		fw->ipfw.fw_tosxor = (unsigned char) tosxor;

		/* we always keep these addresses in network byte order */
		fw->ipfw.fw_src.s_addr = (__u32) htonl(temp[0]);
		fw->ipfw.fw_dst.s_addr = (__u32) htonl(temp[2]);
		fw->ipfw.fw_smsk.s_addr = (__u32) htonl(temp[1]);
		fw->ipfw.fw_dmsk.s_addr = (__u32) htonl(temp[3]);

		countlist[nread*2] = ((__u64)tmp1)<<32 | tmp2;
		countlist[nread*2+1] = ((__u64)tmp3)<<32 | tmp4;
	}
	return nread;
}

static int
read_masqinfo(FILE *fp, struct masq *mslist, int nmslist)
{
	int n, nread = 0;
	struct masq *ms;
	char buf[256];
	unsigned long temp[3];

	for (nread = 0; nread < nmslist; nread++) {
		ms = &mslist[nread];
		if ((n = fscanf(fp, " %s %lX:%hX %lX:%hX %hX %lX %hd %hd %lu",
				buf, &temp[0], &ms->sport, &temp[1], &ms->dport,
				&ms->mport, &temp[2], &ms->delta,
				&ms->pdelta, &ms->expires)) == -1)
			return nread;
		else if (n != 10)
			exit_error(VERSION_PROBLEM, "unexpected input data");

		strncpy(ms->proto, buf, sizeof(ms->proto));
		ms->proto[sizeof(ms->proto)-1] = '\0';

		/* we always keep these addresses in network byte order */
		ms->src.s_addr = (__u32) htonl(temp[0]);
		ms->dst.s_addr = (__u32) htonl(temp[1]);

		ms->initseq = (__u32) temp[2];
	}
	return nread;
}

static struct ip_fwtest *
fw_to_fwtest(struct ip_fw *fw, const ip_chainlabel chain)
{
	static struct ip_fwtest ipfwt;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;

	strcpy(ipfwt.fwt_label, chain);

	iph = &ipfwt.fwt_packet.fwp_iph;

	iph->version = IP_VERSION;
	iph->ihl = sizeof(struct iphdr) / 4;
	iph->tot_len = sizeof(struct ip_fwpkt);
	iph->frag_off &= htons(~IP_OFFSET);
	iph->protocol = fw->fw_proto;

	iph->saddr = fw->fw_src.s_addr;
	iph->daddr = fw->fw_dst.s_addr;

	strncpy(ipfwt.fwt_packet.fwp_vianame, fw->fw_vianame, IFNAMSIZ);

	if (fw->fw_flg & IP_FW_F_FRAG)
		iph->frag_off |= htons(2); /* = 64 bytes - why not? */

	/* The tcp and udp headers are ignored for fragments, anyway */
	switch (iph->protocol) {
	case IPPROTO_TCP:
		tcph = &ipfwt.fwt_packet.fwp_protoh.fwp_tcph;
		tcph->source = htons(fw->fw_spts[0]);
		tcph->dest = htons(fw->fw_dpts[0]);
		tcph->syn = (fw->fw_flg & IP_FW_F_TCPSYN) ? 1 : 0;
		break;
	case IPPROTO_UDP:
		udph = &ipfwt.fwt_packet.fwp_protoh.fwp_udph;
		udph->source = htons(fw->fw_spts[0]);
		udph->dest = htons(fw->fw_dpts[0]);
		break;
	case IPPROTO_ICMP:
		icmph = &ipfwt.fwt_packet.fwp_protoh.fwp_icmph;
		icmph->type = fw->fw_spts[0];
		icmph->code = fw->fw_dpts[0];
		break;
	}

	return &ipfwt;
}

/* Table of error messages. */
struct errmsg
{
	int iserror; /* If 1, go to stderr. */
	int command; /* 0 = ANY */
	int errnum; /* 0 = OK */
	const char *message;
};

static struct errmsg errmessage[] = { 
	{ 1, 0, ENOENT, "No chain by that name\n" },
	{ 1, IP_FW_DELETECHAIN, ENOTEMPTY, "Chain is not empty\n" },
	{ 0, IP_FW_CHECK, 0, "packet accepted\n" },
	{ 0, IP_FW_CHECK, ECONNRESET, "packet masqueraded\n" },
	{ 0, IP_FW_CHECK, ETIMEDOUT, "packet denied\n" },
	{ 0, IP_FW_CHECK, ECONNREFUSED, "packet rejected\n" },
	{ 0, IP_FW_CHECK, ECONNABORTED, "packet redirected\n" },
	{ 0, IP_FW_CHECK, ELOOP, "packet caught in a loop\n" },
	{ 0, IP_FW_CHECK, ENFILE, "packet passed through chain\n" },
	{ 0, 0, 0, "" },
	/* EINVAL for CHECK probably means bad interface. */
	{ 1, IP_FW_CHECK, EINVAL, 
	  "bad arguments (does that interface exist?)\n" },
	/* EINVAL for DELETE probably means no matching rule */
	{ 1, IP_FW_DELETE, EINVAL,
	  "bad rule (does a matching rule exist in that chain?)\n" },
	/* Kernel caught an error we missed. */
	{ 1, 0, EINVAL, 
	  "If you DON'T have the latest copy of ipchains, then please upgrade.\n"
	  "Otherwise, please EMail `Paul.Russell@rustcorp.com.au' with output from:\n"
	  "`ipchains -L -v',\n"
	  "`ipchains --version',\n"
	  "and the command which caused this error message.\n" },
};

static int
do_setsockopt(int cmd, const void *data, int length)
{
	static int sockfd = -1;
	unsigned int i;
	int ret;

	if (sockfd == -1) {
		if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
			perror("ipchains: socket creation failed");
			exit(1);
		}
	}
	
	ret = setsockopt(sockfd, IPPROTO_IP, cmd, (char *) data, length);
	if (ret == 0) errno = 0;
	for (i = 0; i < sizeof(errmessage)/sizeof(struct errmsg); i++) {
		if ((errmessage[i].command == 0 || errmessage[i].command == cmd)
		    && errmessage[i].errnum == errno) {
			fputs(errmessage[i].message,
			      errmessage[i].iserror ? stderr : stdout);
			break;
		}
	}
	if (i == sizeof(errmessage)/sizeof(struct errmsg)) {
		perror("ipchains: setsockopt failed");
	}

	return ret;
}

static void
set_option(unsigned int *options, unsigned int option, __u16 *invflg)
{
	if (*options & option)
		exit_error(PARAMETER_PROBLEM, "multiple -%c flags not allowed\n", 
			   opt2char(option));
	else *options |= option;

	if (invert) {
		unsigned int i;
		for (i = 0; 1 << i != option; i++);
		if (!inverse_for_options[i])
			exit_error(PARAMETER_PROBLEM, "cannot have ! before -%c\n",
				   opt2char(option));
		*invflg |= inverse_for_options[i];
		invert = FALSE;
	}
}

static void
inaddrcpy(struct in_addr *dst, struct in_addr *src)
{
	/* memcpy(dst, src, sizeof(struct in_addr)); */
	dst->s_addr = src->s_addr;
}

static void *
fw_malloc(size_t size)
{
	void *p;

	if ((p = malloc(size)) == NULL) {
		perror("ipchains: malloc failed");
		exit(1);
	} 
	return p;
}

static void *
fw_calloc(size_t count, size_t size)
{
	void *p;

	if ((p = calloc(count, size)) == NULL) {
		perror("ipchains: calloc failed");
		exit(1);
	} 
	return p;
}

static void *
fw_realloc(void *ptr, size_t size)
{
	void *p;

	if ((p = realloc(ptr, size)) == NULL) {
		perror("ipchains: realloc failed");
		exit(1);
	}
	return p;
}

static void
exit_error(enum exittype status, char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	fprintf(stderr, "%s: ", program);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	if (status == PARAMETER_PROBLEM) exit_tryhelp(status);
	else if (status == VERSION_PROBLEM)
		fprintf(stderr, "Perhaps ipchains or your kernel need to be upgraded.\n");
	exit(status);
}

static void
exit_tryhelp(int status)
{
	fprintf(stderr, "Try `%s -h' for more information.\n", program);
	exit(status);
}

static void
exit_printicmphelp()
{
	unsigned int i;
	printf("%s\n\n"
	       "Valid ICMP Types:",
	       package_version);

	for (i = 0; i < sizeof(icmp_codes)/sizeof(struct icmp_names); i++) {
		if (i && icmp_codes[i].type == icmp_codes[i-1].type) {
			if (icmp_codes[i].code_min == icmp_codes[i-1].code_min
			    && (icmp_codes[i].code_max
				== icmp_codes[i-1].code_max))
				printf(" (%s)", icmp_codes[i].name);
			else
				printf("\n   %s", icmp_codes[i].name);
		}
		else 
			printf("\n%s", icmp_codes[i].name);
	}
	printf("\n");
	exit(0);
}

static void
exit_printhelp()
{
	printf("%s\n\n"
	       "Usage: %s -[ADC] chain rule-specification [options]\n"
	       "       %s -[RI] chain rulenum rule-specification [options]\n"
	       "       %s -D chain rulenum [options]\n"
	       "       %s -[LFZNX] [chain] [options]\n"
	       "       %s -P chain target [options]\n"
	       "       %s -M [ -L | -S ] [options]\n"
	       "       %s -h [icmp] (print this help information, or ICMP list)\n\n",
	       package_version, program, program, program, program, program,
	       program, program);

	printf("Commands:\n"
	       "  -A chain      Append to chain\n"
	       "  -D chain      Delete matching rule from chain\n"
	       "  -D chain rulenum\n"
	       "                Delete rule rulenum (1 = first) from chain\n"
	       "  -I chain [rulenum]\n"
	       "                Insert in chain as rulenum (default = 1 = first)\n"
	       "  -R chain rulenum\n"
	       "                Replace rule rulenum (1 = first) in chain\n"
	       "  -L [chain]    List the rules in a chain (or all chains)\n"
	       "  -F [chain]    Flush (delete all rules) chain or all chains\n"
	       "  -Z [chain]    Zero counters in chain (or all chains)\n"
	       "  -C chain      Test this packet on chain\n"
	       "  -N chain      Create a new user-defined chain\n"
	       "  -X chain      Delete a user-defined chain\n"
	       "  -P chain target\n"
	       "                Change policy on chain to target\n"
	       "  -M -L         List current masqerading connections\n"
	       "  -M -S tcp tcpfin udp\n"
	       "		Set masquerading timeout values\n\n"

	       "Options:\n"
	       "  -b		insert two rules: one with -s & -d reversed\n"
	       "  -p [!] proto	protocol (tcp, udp, icmp, all or a number)\n"
	       "  -s [!] address[/mask] [!] [port ...]\n"
	       "		source specification\n"
	       "  -d [!] address[/mask] [!] [port ...]\n"
	       "		destination specification\n"
	       "  -i [!] name[+]\n"
	       "		network interface name (or wildcard)\n"
	       "  -j target [port]\n"
	       "		target for rule if it matches ([port] for REDIRECT)\n"
               "  -m [+-]mark   number to mark on matching packet\n"
	       "  -n		numeric output of addresses and ports\n"
	       "  -l		turn on kernel logging for matching packets\n"
	       "  -o [maxsize]  output matching packet to netdev\n"
	       "  -t and xor	and/xor masks for TOS field\n"
	       "  -v		verbose mode\n"
	       "  -x		expand numbers (display exact values)\n"
	       "[!] -f		match second or further fragments only\n"
	       "[!] -y		match TCP packets only when SYN set\n");

	exit(0);
}

static void
generic_opt_check(int command, int options)
{
	int i,j,legal=0;

	/* Check that commands are valid with options.  Complicated by the
	 * fact that if an option is legal with *any* command given, it is
	 * legal overall (ie. -z and -l).
	 */
	for (i = 0; i < NUMBER_OF_OPT; i++) {
		legal = 0; /* -1 => illegal, 1 => legal, 0 => undecided. */

		for (j = 0; j < NUMBER_OF_CMD; j++) {
			if (!(command & (1<<j)))
				continue;

			if (!(options & (1<<i))) { 
				if (commands_v_options[j][i] == '+')
					exit_error(PARAMETER_PROBLEM, "Missing compulsory option for this command\n");
			}
			else {
				if (commands_v_options[j][i] != 'x')
					legal = 1;
				else if (legal == 0)
					legal = -1;
			}
		}
		if (legal == -1)
			exit_error(PARAMETER_PROBLEM, "Illegal option with this command\n");
	}
}

static char 
opt2char(int option)
{
	const char *ptr;
	for (ptr = optflags; option > 1; option >>=1, ptr++);

	return *ptr;
}

static char 
cmd2char(int option)
{
	const char *ptr;
	for (ptr = cmdflags; option > 1; option >>=1, ptr++);

	return *ptr;
}

static int
count_tos_bits(unsigned char bitpattern)
{
	int bits;

	for (bits = 0, bitpattern &= 0x0E; bitpattern > 0x00; bitpattern >>= 1)
		bits += bitpattern & 0x01;

	return bits;
}

static void 
check_tos(unsigned char tosand, unsigned char tosxor)
{
	unsigned int i;

	/* The LSB Must Be Untouched (RFC 1349). */
	if (!(tosand & 1) || (tosxor & 1)) 
		exit_error(PARAMETER_PROBLEM, "TOS manipulation cannot alter bit 0 (RFC1349)\n");

	/* Don't create packets with more than 1 TOS bit set, (RFC 1349). */
	/* If it will always create a packet with > 1 TOS bit, it's an
	 * error.  If it MIGHT create a packet with > 1 TOS bit set,
	 * issue a warning to stdout (so the user can filter this out
	 * if they really want this.)
	 */
	if (count_tos_bits((~tosand) & tosxor) > 1)
		exit_error(PARAMETER_PROBLEM, "TOS manipulation cannot set multiple TOS bits "
			   "(RFC1349)\n");

	for (i = 0; i < sizeof(TOS_values)/sizeof(struct TOS_value); i++)
		if (count_tos_bits((TOS_values[i].TOS & tosand) ^ tosxor) > 1)
			printf("Warning: TOS manipulation may set multiple "
			       "TOS bits for %s TOS (0x%02x)\n",
			       TOS_values[i].name, TOS_values[i].TOS);
}

static void 
add_command(int *cmd, const int newcmd, const int othercmds)
{
	if (invert)
		exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
	if (*cmd & (~othercmds))

		exit_error(PARAMETER_PROBLEM, "Can't use -%c with -%c\n", 
			   cmd2char(newcmd), cmd2char(*cmd & (~othercmds)));
	else *cmd |= newcmd;
}
