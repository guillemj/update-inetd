/*
 * ipfw		This file contains an implementation of the command
 *		that maintains the ip firewalling and accounting rules
 *		in the linux kernel. It supports masquerade support, too.
 *
 * Version:	ipfw.c 1.10 (1996-02-18)
 *
 * Author:	Daniel Boulet, Bob Beck
 *
 * Changes:
 *	*	Alan Cox:		Drastically cleaned up
 *	*	Salvador Abreu:		More (major) cleanups and bug 
 *					fixes by <spa@fct.unl.pt>
 *	*	Lutz Pre"sler:		Additional options
 *	*	Alan Cox:		Masquerade client support added
 *					Made to match 1.1.91, and Urgen's 
 *					newer ipfw kernel code.
 *960119 {1.01}	Bernd Eckenfels:	bidir,syn,ack,prn flags, ICMP types
 *					-c option for stats
 *960129 {1.02} Bernd Eckenfels:	long_getopts, -h, -V, usage, -r, 
 *					"list  masq", "zero *"
 *960131 {1.03} Bernd Eckenfels:	dispay policy
 *960201 {1.05} Bernd Eckenfels:	net-features support and new usage,
 *					check iface and flags support, 
 *960203 {1.06} Bernd Eckenfels:	list output reformated, HAVE_FW_APPEND
 *960203 {1.07} Bernd Eckenfels:	"#define" to "#if" for net-features
 *960203 {1.08} Bernd Eckenfels:	try to open raw socket after option
 *					processing (Lutz Pre"sler), 
 *					more net-features
 *960205 {1.09} Bernd Eckenfels:	usage cleanup (gosh, if Jos 
 *					blocking/sending chains are implemented
 *					this is going to be much much much too 
 *					long. Personally I think the Linux 
 *					Kernel has too much Features for 'usage'
 *					authors. "list masquerade" removed.
 *960218 {1.10} Bernd Eckenfels :	netinet/in.h moved
 *
 *
 * Todo:
 *		Code Cleanup, 1.2.x Support
 */

/*
 ********************************************************************************
 *
 * Copyright (c) 1993 Daniel Boulet
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 ********************************************************************************
 *
 *
 *  Linux port (c) 1994 Bob Beck
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 ********************************************************************************
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#define IPFIREWALL
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if.h>
#include <linux/ip_fw.h>

#ifdef IP_FW_INSERT
#error "ARGH! I told you to read the `README' File! See Section `N O T E:'"
#endif

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#define IPVERSION 4

#include "pathnames.h"
#include "version.h"
#include "config.h"
#include "net-locale.h"

#define FEATURE_IPFW
#include "lib/net-features.h"

char *Release = RELEASE,
     *Version = "ipfw 1.10 (1996-02-18)";

typedef enum
{
	IPF_BLOCKING = 0,
	IPF_FORWARDING = 1,
	IPF_ACCOUNTING = 2,
	IPF_MASQUERADE = 3
} ipf_kind;

#define IP_OFFSET       0x1FFF
 
static char *ipf_names[4] = 	{"blocking", "forwarding", "accounting", "masquerading"};
static char *nls_ipf_names[4];
static long ipf_addfunc[4] = 	{IP_FW_ADD_BLK, IP_FW_ADD_FWD, IP_ACCT_ADD, IP_FW_ADD_FWD};
static long ipf_delfunc[4] = 	{IP_FW_DEL_BLK, IP_FW_DEL_FWD, IP_ACCT_DEL, IP_FW_DEL_FWD};
static int lookup = 1;
static int count  = 0;		/* 0=dont display, 2=display */
static int reset  = 0;		/* 0=dont reset, 1=reset after printing */
#if HAVE_FW_APPEND
static int append = 0;		/* 0=guess, 1=append rule */
#endif

void ipf_names_init ()
{
	/* no free for this, should be fixed */
	nls_ipf_names[0] = NLS_CATSAVE (catfd, ipfwSet, ipfw_ipf_blocking, "blocking");
	nls_ipf_names[1] = NLS_CATSAVE (catfd, ipfwSet, ipfw_ipf_fwding, "forwarding");
	nls_ipf_names[2] = NLS_CATSAVE (catfd, ipfwSet, ipfw_ipf_accnting, "accounting");
	nls_ipf_names[3] = NLS_CATSAVE (catfd, ipfwSet, ipfw_ipf_msqrading, "masquerading");
}

static void
version(void)
{
  fprintf(stderr, "%s\n%s\n%s\n",Release,Version,Features);
  NLS_CATCLOSE(catfd)
  exit(-1);
}

void usage()
{
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage1,  "usage:\tipfw [-ndhcVr] [--version] [--help]\n\t     [--numeric] [--count] [--reset] [--debug] [--append]\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage2,  "\tipfw p[olicy]      {b[locking]|f[orwarding]} {accept|deny|reject}\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage3,  "\tipfw [-nrc] l[ist] {b[locking]|f[orwarding]|a[ccounting]}\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage4,  "\tipfw f[lush]       {b[locking]|f[orwarding]|a[ccounting]}\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage5,  "\tipfw {a[dd]|d[el]} {b[locking]|f[orwarding]} {accept|deny|reject} \n\t     Type [iface Addr] from Src to Dst [flags Flags]\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage6,  "\tipfw c[heck]       {b[locking]|f[orwarding]}\n\t     Type [iface Addr] from Src to Dst [flags Flags]\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage7,  "\tipfw {a[dd]|d[el]} a[ccounting]\n\t     Type [iface Addr] from Src to Dst [flags Flags]\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage8, "\tipfw z[ero] {b[locking]|f[orwarding]|a[ccounting]}\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage9, "\tipfw {a[dd]|d[el]} m[asquerade] Type from Src to Dst\n\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage10, "\tType={udp|tcp}:\t\tFlags={bidir|syn|ack|prn} ...\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage11, "\tSrc,Dst={1.2.3.4/24|Host|Netname} [[Port1:Port2] Port3 ... Port10]\n\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage12, "\tType={icmp}:\t\tFlags={bidir,prn}\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage13, "\tSrc={1.2.3.4/24|Host|Netname} [[Type1:Type2] Type3 ... Type10]\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage14, "\tDst={1.2.3.4/24|Host|Netname}\n\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage15, "\tType={all}:\t\tFlags={bidir,prn}\n"));
  fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_usage16, "\tSrc,Dst={1.2.3.4/24|Host|Netname}\n"));
  NLS_CATCLOSE(catfd)
  exit(-1);
}


static char *fmtip(u_long uaddr)
{
	static char tbuf[100];

	sprintf(tbuf, "%d.%d.%d.%d",
	    ((char *) &uaddr)[0] & 0xff,
	    ((char *) &uaddr)[1] & 0xff,
	    ((char *) &uaddr)[2] & 0xff,
	    ((char *) &uaddr)[3] & 0xff);

	return (&tbuf[0]);
}

static void print_ports(int cnt, int range, u_short * ports)
{
	int ix;
	char *pad;

	if (range)
	{
		if (cnt < 2)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_range_set,
			    "ipfw: range flag set but only %d ports\n"), cnt);
			NLS_CATCLOSE(catfd)
			exit(1);
		}
		printf("%d:%d", ports[0], ports[1]);
		ix = 2;
		pad = " ";
	}
	else
	{
		ix = 0;
		pad = "";
	}

	while (ix < cnt)
	{
		printf("%s%d", pad, ports[ix]);
		pad = " ";
		ix += 1;
	}
}

static int do_setsockopt(char *what, int fd, int proto, int cmd, void *data, int datalen, int ok_errno)
{
	char *cmdname;

#define CASE(NAME) case IP_##NAME: cmdname = "IP_" #NAME; break

	switch (cmd)
	{
		CASE(FW_FLUSH_BLK);
		CASE(FW_FLUSH_FWD);
		CASE(FW_CHK_BLK);
		CASE(FW_CHK_FWD);
		CASE(FW_ADD_BLK);
		CASE(FW_ADD_FWD);
		CASE(FW_DEL_BLK);
		CASE(FW_DEL_FWD);
		CASE(FW_POLICY_FWD);
		CASE(FW_POLICY_BLK);
		CASE(ACCT_ADD);
		CASE(ACCT_DEL);
		CASE(ACCT_FLUSH);
		CASE(ACCT_ZERO);
		CASE(FW_ZERO_BLK);
		CASE(FW_ZERO_FWD);
	default:
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_unkn_cmd, "ipfw: "
		    "unknown command (%d) passed to do_setsockopt - bye!\n"), cmd);
		NLS_CATCLOSE(catfd)
		exit(1);
	}

#undef CASE

	if (fd < 0)
	{
		printf("setsockopt(%d, %d, %s, 0x%x, 0x%x)\n",
		    fd, proto, cmdname, (int) data, datalen);
		if (cmd == IP_FW_CHK_BLK || cmd == IP_FW_CHK_FWD)
		{
			struct iphdr *ip = (struct iphdr *) data;
			struct tcphdr *tcp = (struct tcphdr *) &(((int *) ip)[ip->ihl]);
			if (ip->ihl != sizeof(struct iphdr) / sizeof(int))
			{
				fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_ip, "ip header length %d, should be %d\n"),
				    ip->ihl, sizeof(struct iphdr) / sizeof(int));
			}
			if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
			  {
			    NLS_CATCLOSE(catfd)
			      exit(1);
			  }
			printf(NLS_CATGETS(catfd, ipfwSet, ipfw_data_ip, "data = struct iphdr : struct %shdr {\n"),
			    ip->protocol == IPPROTO_TCP ? "tcp" : "udp");
			printf("\tsrc=%s ", fmtip(ip->saddr));
			printf("%d\n", ntohs(tcp->source));
			printf("\tdst=%s  ", fmtip(ip->daddr));
			printf("%d\n", ntohs(tcp->dest));
			printf("}\n");
		}
		else if (cmd == IP_FW_ADD_BLK ||
			    cmd == IP_FW_ADD_FWD ||
		    cmd == IP_ACCT_ADD)
		{
			struct ip_fw *fp = (struct ip_fw *) data;
			int fmt_ports = 0;
			printf(NLS_CATGETS(catfd, ipfwSet, ipfw_data_ipfw, "data = struct ip_fw {\n"));
			if (fp->fw_flg & IP_FW_F_ACCEPT)
			{
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_accept, "\taccept "));
			}
			else if (fp->fw_flg & IP_FW_F_ICMPRPL)
			{
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_reject, "\treject "));
			}
			else
			{
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_deny, "\tdeny "));
			}
			switch (fp->fw_flg & IP_FW_F_KIND)
			{
			case IP_FW_F_ALL:
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_univ, "\tuniversal\n"));
				fmt_ports = 0;
				break;
			case IP_FW_F_TCP:
				printf("tcp\n");
				fmt_ports = 1;
				break;
			case IP_FW_F_UDP:
				printf("udp\n");
				fmt_ports = 1;
				break;
			case IP_FW_F_ICMP:
				printf("icmp\n");
				fmt_ports = 2;
				break;
			}
			printf("\tsrc=%s:", fmtip(fp->fw_src.s_addr));
			printf("%s ", fmtip(fp->fw_smsk.s_addr));
			if (fmt_ports >= 1)
			{
				print_ports(fp->fw_nsp, fp->fw_flg & IP_FW_F_SRNG, &fp->fw_pts[0]);
			}
			else if (fp->fw_flg & (IP_FW_F_SRNG | IP_FW_F_DRNG))
			{
			  NLS_CATCLOSE(catfd)
				exit(1);
			}
			else if (fp->fw_nsp > 0 || fp->fw_ndp > 0)
			{
			    NLS_CATCLOSE(catfd)
				exit(1);
			}
			printf("\n");
			printf("\tdst=%s:", fmtip(fp->fw_dst.s_addr));
			printf("%s ", fmtip(fp->fw_dmsk.s_addr));
			if (fmt_ports == 1)
			{
				print_ports(fp->fw_ndp,
				    fp->fw_flg & IP_FW_F_DRNG,
				    &fp->fw_pts[fp->fw_nsp]);
			}
			printf("\n");
			printf("}\n");
		}
		NLS_CATCLOSE(catfd)
		exit(0);
	}
	else
	{
		if (setsockopt(fd, proto, cmd, data, datalen) < 0)
		{
			char msg[128];

			if (ok_errno)
			{
				return (errno);
			}
			sprintf(msg, "ipfw: setsockopt(%s)", cmdname);
			perror(msg);
			NLS_CATCLOSE(catfd)
			exit(1);
		}
	}
	return (0);
}

void show_parms(char **argv)
{
	while (*argv)
	{
		printf("%s ", *argv++);
	}
}

int get_protocol(char *arg, ipf_kind kind)
{
	if (arg == NULL)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing, "ipfw: missing protocol name\n"));
	}
	else if (strcmp(arg, "tcp") == 0)
	{
		return (IP_FW_F_TCP);
	}
	else if (strcmp(arg, "udp") == 0)
	{
		return (IP_FW_F_UDP);
	}
	else if (strcmp(arg, "icmp") == 0)
	{
		return (IP_FW_F_ICMP);
	}
	else if (strcmp(arg, "all") == 0)
	{
		return (IP_FW_F_ALL);
	}
	else
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_illegal, "illegal protocol name \"%s\"\n"), arg);
	}
	usage();
	return (0);
}

void get_ipaddr(char *arg, struct in_addr *addr, struct in_addr *mask, ipf_kind kind)
{
	char *p, *tbuf;
	int period_cnt, non_digit;
	struct hostent *hptr;

	if (arg == NULL)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_ip, "ipfw: missing ip address\n"));
		usage();
	}
	period_cnt = 0;
	non_digit = 0;
	for (p = arg; *p != '\0' && *p != '/' && *p != ':'; p += 1)
	{
		if (*p == '.')
		{
			if (p > arg && *(p - 1) == '.')
			{
				fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_periods,
							    "ipfw: two periods in a row in ip address (%s)\n"), arg);
				usage();
			}
			period_cnt += 1;
		}
		else if (!isdigit(*p))
		{
			non_digit = 1;
		}
	}

	tbuf = malloc(p - arg + 1);
	strncpy(tbuf, arg, p - arg);
	tbuf[p - arg] = '\0';

	if (non_digit)
	{
		if (!strcmp(tbuf, "anywhere")) {
			addr->s_addr = 0;
			mask->s_addr = 0;
			return;
		}
		hptr = gethostbyname(tbuf);
		if (hptr == NULL)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_unkn_host, "ipfw: unknown host \"%s\"\n"), tbuf);
			NLS_CATCLOSE(catfd);
			exit(1);
		}
		if (hptr->h_length != sizeof(struct in_addr))
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_addr_length,
			    "ipfw: hostentry addr length = %d, expected %d"
			    "(i.e. sizeof(struct in_addr))\n"),
			    hptr->h_length, sizeof(struct in_addr));
			NLS_CATCLOSE(catfd);
			exit(1);
		}
		bcopy(hptr->h_addr, addr, sizeof(struct in_addr));
	}
	else
	{
		if (period_cnt == 3)
		{

			int a1, a2, a3, a4, matched;

			if ((matched = sscanf(tbuf, "%d.%d.%d.%d", &a1, &a2, &a3, &a4))
			    != 4)
			{
				fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_matched,
				    "ipfw: Only %d fields matched in IP address!\n"),
				    matched);
				/* should this exit here? or catch it later? -BB */
			}
			if (a1 > 255 || a2 > 255 || a3 > 255 || a4 > 255)
			{
				fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_too_large,
							    "ipfw: number too large in ip address (%s)\n"), arg);
				usage();			   
			}
			((char *) addr)[0] = a1;
			((char *) addr)[1] = a2;
			((char *) addr)[2] = a3;
			((char *) addr)[3] = a4;

		}
		else if (strcmp(tbuf, "0") == 0)
		{

			((char *) addr)[0] = 0;
			((char *) addr)[1] = 0;
			((char *) addr)[2] = 0;
			((char *) addr)[3] = 0;

		}
		else
		{

			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_inc_format,
						    "ipfw: incorrect ip address format \"%s\" (expected 3 periods)\n"), tbuf);
			usage();
		}
	}

	free(tbuf);

	if (mask == NULL)
	{
		if (*p != '\0')
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_not_allowed,
						    "ipfw: ip netmask not allowed here (%s)\n"), (char *) addr);
			usage();
		}
	}
	else
	{
		if (*p == ':')
		{
			get_ipaddr(p + 1, mask, NULL, kind);
		}
		else if (*p == '/')
		{
			int bits;
			char *end;

			p += 1;
			if (*p == '\0')
			{
				fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_mask,
							    "ipfw: missing mask value (%s)\n"), arg);
				usage();
			}
			else if (!isdigit(*p))
			{
				fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_non_num,
							    "ipfw: non-numeric mask value (%s)\n"), arg);
				usage();
			}
			bits = strtol(p, &end, 10);
			if (*end != '\0')
			{
				fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_junk_mask,
							    "ipfw: junk after mask (%s)\n"), arg);
				usage();
			}
			if (bits < 0 || bits > sizeof(u_long) * 8)
			{
				fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_out_range,
							    "ipfw: mask length value out of range (%s)\n"), arg);
				usage();
			}
			if (bits == 0)
			{	/* left shifts of 32 aren't defined */
				mask->s_addr = 0;
			}
			else
			{
				((char *) mask)[0] = (-1 << (32 - bits)) >> 24;
				((char *) mask)[1] = (-1 << (32 - bits)) >> 16;
				((char *) mask)[2] = (-1 << (32 - bits)) >> 8;
				((char *) mask)[3] = (-1 << (32 - bits)) >> 0;
			}

		}
		else if (*p == '\0')
		{
			mask->s_addr = 0xffffffff;
		}
		else
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_junk_ip,
						    "ipfw: junk after ip address (%s)\n"), arg);
			usage();
		}

		/*
         * Mask off any bits in the address that are zero in the mask.
         * This allows the user to describe a network by specifying
         * any host on the network masked with the network's netmask.
         */
		addr->s_addr &= mask->s_addr;

	}

}

u_short get_one_port(char *arg, ipf_kind kind, const char *proto_name)
{
	int slen = strlen(arg);

	if (slen > 0 && strspn(arg, "0123456789") == slen)
	{
		int port;
		char *end;

		port = strtol(arg, &end, 10);
		if (*end != '\0')
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_illegal_port,
						    "ipfw: illegal port number (%s)\n"), arg);
			usage();
		}
		if (port < 0 || port > 65535 || 
		    (port == 0 && strcmp(proto_name, "icmp")) )
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_portnum_out,
						    "ipfw: port number out of range (%d)\n"), port);
			usage();
		}
		return (port);
	}
	else
	{
		struct servent *sptr;

		sptr = getservbyname(arg, proto_name);

		if (sptr == NULL)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_unkn_service,
						    "ipfw: unknown %s service \"%s\"\n"), proto_name, arg);
			usage();
		}
		return (ntohs(sptr->s_port));
	}
}

int get_ports(char ***argv_ptr, u_short * ports, int min_ports, int max_ports, ipf_kind kind, const char *proto_name)
{
	int ix;
	char *arg;
	int sign;

	ix = 0;
	sign = 1;
	while ((arg = **argv_ptr) != NULL &&
	    strcmp(arg, "from") != 0 &&
	    strcmp(arg, "to") != 0 &&
	    strcmp(arg, "flags") != 0)
	{
		char *p;

		/*
         * Check that we havn't found too many port numbers.
         * We do this here instead of with another condition on the while loop
         * so that the caller can assume that the next parameter is NOT a
         * port number.
         */

		if (ix >= max_ports)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_too_port,
						    "ipfw: too many port numbers "
						    "(max %d, got at least %d, next parm=\"%s\")\n"),
				max_ports, max_ports + 1, arg);
			usage();
		}
		if ((p = strchr(arg, ':')) == NULL)
		{
			ports[ix++] = get_one_port(arg, kind, proto_name);
		}
		else
		{
			if (ix > 0)
			{
				fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_port_ranges,
							    "ipfw: "
							    "port ranges are only allowed for "
							    "the first port value pair (%s)\n"), arg);
				usage();
			}
			if (max_ports > 1)
			{
				char *tbuf;

				tbuf = malloc((p - arg) + 1);
				strncpy(tbuf, arg, p - arg);
				tbuf[p - arg] = '\0';

				ports[ix++] = get_one_port(tbuf, kind, proto_name);
				ports[ix++] = get_one_port(p + 1, kind, proto_name);
				sign = -1;
			}
			else
			{
				fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_no_range,
				    "ipfw: port range not allowed here (%s)\n"), arg);
				usage();
			}
		}

		*argv_ptr += 1;
	}

	if (ix < min_ports)
	{
		if (min_ports == 1)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_port,
						    "ipfw: missing port number%s\n"),
			    max_ports == 1 ? "" : "(s)");
		}
		else
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_nomore_port,
			    "ipfw: not enough port numbers (expected %d, got %d)\n"),
			    min_ports, ix);
		}
		usage();
	}
	return (sign * ix);
}

int get_protoflags(char ***argp, int proto, ipf_kind kind)
{
	int	flags = 0;
	char	**argv = *argp;
	char	*arg;

	if (!*argv || strcmp(*argv, "flags") != 0)
		return 0;
	argv++;
	for (; (arg = *argv) != NULL; argv++)
	{
		if (strcmp(arg, "prn") == 0)
		{
			flags |= IP_FW_F_PRN;
			continue;
		}
		/* bidirection - rule may also match in reverse */
		if (strcmp(arg, "bidir") == 0)
		{
			flags |= IP_FW_F_BIDIR;
			continue;	/* continue - no TCP check */
		}

		/* The following work only for TCP filters */
		if (strcmp(arg, "syn") == 0)
			flags |= IP_FW_F_TCPSYN;
		else 
#if HAVE_FW_TCPACK		
		if (strcmp(arg, "ack") == 0)
			flags |= IP_FW_F_TCPACK;
		else
#endif
			break;

		if (proto != IP_FW_F_TCP)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_badflag,
				"ipfw: \"%s\" flag only applicable to TCP rules\n"), arg);
			usage();
		}
	}

	*argp = argv;
	return flags;
}


void check(ipf_kind kind, int socket_fd, char **argv)
{
	char tbuff[64];
	int protocol, pflags;
	struct ip_fwpkt *packet;
	char *proto_name;

	if (kind == IPF_BLOCKING)
	  NLS_CATBUFF (catfd, ipfwSet, ipfw_check_blocking, "blocking", tbuff, 64);
	else
	  NLS_CATBUFF (catfd, ipfwSet, ipfw_check_forwarding, "forwarding", tbuff, 64);
	
	packet = (struct ip_fwpkt *) malloc (sizeof(struct ip_fwpkt));

	packet->fwp_iph.version = IPVERSION;
	packet->fwp_iph.ihl = sizeof(struct iphdr) / sizeof(int);
	packet->fwp_iph.tot_len = (packet->fwp_iph.ihl<<2)+16;
	packet->fwp_iph.frag_off &= htons(~IP_OFFSET);
	        
	printf(NLS_CATGETS(catfd, ipfwSet, ipfw_check, "check %s "), tbuff);

	show_parms(argv);
	printf("\n");

	proto_name = *argv++;
	protocol = get_protocol(proto_name, kind);
	switch (protocol)
	{
	case IP_FW_F_TCP:
		packet->fwp_iph.protocol = IPPROTO_TCP;
		break;
	case IP_FW_F_UDP:
		packet->fwp_iph.protocol = IPPROTO_UDP;
		break;
	default:
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_only_check,
					    "ipfw: can only check TCP or UDP packets\n"));
		usage();
		break;
	}

	if (*argv == NULL)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_fromi,"ipfw: missing \"from\" or \"iface\" keyword\n"));
		usage();
	}

	if(*argv && strcmp(*argv,"iface")==0)
	{
		argv++;
		if(*argv==NULL)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_iface,
						    "ipfw: missing interface address.\n"));
			usage();
		}
		packet->fwp_via.s_addr=inet_addr(*argv);
		if(packet->fwp_via.s_addr==-1)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_invalid_iface,
						    "Invalid interface address.\n"));
			usage();
		}
		argv++;
	}

	if (*argv == NULL)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_from,"ipfw: missing \"from\" keyword\n"));
		usage();
	}

	if (strcmp(*argv, "from") == 0)
	{
		argv += 1;
		get_ipaddr(*argv++, (struct in_addr *) &packet->fwp_iph.saddr,
		    NULL, kind);
		if (protocol == IP_FW_F_TCP || protocol == IP_FW_F_UDP)
		{
			get_ports(&argv, &packet->fwp_protoh.fwp_tcph.source,
			    1, 1, kind, proto_name);
			packet->fwp_protoh.fwp_tcph.source = htons(packet->fwp_protoh.fwp_tcph.source);
		}
	}
	else
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_expect_from,
		    "ipfw: expected \"from\" keyword, got \"%s\"\n"), *argv);
		usage();
	}

	if (*argv == NULL)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_to, "ipfw: missing \"to\" keyword\n"));
		usage();
	}
	if (strcmp(*argv, "to") == 0)
	{
		argv += 1;
		get_ipaddr(*argv++, (struct in_addr *) &packet->fwp_iph.daddr,
		    NULL, kind);
		if (protocol == IP_FW_F_TCP || protocol == IP_FW_F_UDP)
		{
			get_ports(&argv, &packet->fwp_protoh.fwp_tcph.dest,
			    1, 1, kind, proto_name);
			packet->fwp_protoh.fwp_tcph.dest = htons(packet->fwp_protoh.fwp_tcph.dest);
		}
	}
	else
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_expect_to,
		    "ipfw: expected \"to\" keyword, got \"%s\"\n"), *argv);
		usage();
	}

	pflags = get_protoflags(&argv, protocol, kind) ;

	packet->fwp_protoh.fwp_tcph.syn = (pflags & IP_FW_F_TCPSYN) ? 1 : 0;
#if HAVE_FW_TCPACK
	packet->fwp_protoh.fwp_tcph.ack = (pflags & IP_FW_F_TCPACK) ? 1 : 0;
#endif

	if (*argv == NULL)
	{
		char msg[128];
		
		switch(do_setsockopt(kind == IPF_BLOCKING ? "checkblocking" : "checkforwarding",
			socket_fd, IPPROTO_IP,
			kind == IPF_BLOCKING ? IP_FW_CHK_BLK : IP_FW_CHK_FWD,
			packet,
			sizeof (struct ip_fwpkt),1))
		{
			case 0:
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_paq_accept, "packet accepted by %s firewall\n"),
			    		tbuff);
			    	break;
			case ECONNREFUSED:
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_paq_reject, "packet rejected by %s firewall\n"),
			    		tbuff);
			    	break;
			case ETIMEDOUT:
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_paq_deny, "packet denied by %s firewall\n"),
			    		tbuff);
			    	break;
			default:
				sprintf(msg, "ipfw: setsockopt(%s)", kind == IPF_BLOCKING ? "checkblocking" : "checkforwarding");
				perror(msg);
				NLS_CATCLOSE(catfd)
				exit(1);
		}

		return;
	}
	else
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_extra,
					    "ipfw: extra parameters at end of command ("));
		show_parms(argv);
		fprintf(stderr, ")\n");
		usage();
	}
}

void add(ipf_kind kind, int socket_fd, char **argv)
{
	int protocol, accept_firewall=0, src_range=0, dst_range=0, pflags;
	struct ip_fw firewall;
	char *proto_name;

	printf(NLS_CATGETS(catfd, ipfwSet, ipfw_add, "add %s "), nls_ipf_names[kind]);
	show_parms(argv);
	printf("\n");

	if (kind != IPF_ACCOUNTING && kind != IPF_MASQUERADE)
	{
		if (*argv == NULL)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_acc,
						    "ipfw: missing \"accept\" or \"deny\" keyword\n"));
			usage();
		}
		if (strcmp(*argv, "deny") == 0)
		{
			accept_firewall = 0;
		}
		else if (strcmp(*argv, "accept") == 0)
		{
			accept_firewall = IP_FW_F_ACCEPT;
		}
		else if (strcmp(*argv, "reject") == 0)
			accept_firewall = IP_FW_F_ICMPRPL;
		else
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_expect_acc,
			    "ipfw: expected \"accept\", \"deny\" or \"reject\", got \"%s\"\n"),
			    *argv);
			usage();
		}

		argv += 1;
	}
	else
		accept_firewall = IP_FW_F_ACCEPT;
	if(*argv==NULL)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_proto, "ipfw: missing protocol name.\n"));
		usage();
	}
	proto_name = *argv++;
	protocol = get_protocol(proto_name, kind);
	
	firewall.fw_via.s_addr = 0;
	
	if(*argv && strcmp(*argv,"iface")==0)
	{
		argv++;
		if(*argv==NULL)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_iface,
						    "ipfw: missing interface address.\n"));
			usage();
		}
		firewall.fw_via.s_addr=inet_addr(*argv);
		if(firewall.fw_via.s_addr==-1)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_invalid_iface,
						    "Invalid interface address.\n"));
			usage();
		}
		argv++;
	}
	
	if (*argv == NULL)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_from2,
					    "ipfw: missing \"from\" keyword\n"));
		usage();
	}
	if (strcmp(*argv, "from") == 0)
	{
		argv++;
		get_ipaddr(*argv++, &firewall.fw_src, &firewall.fw_smsk, kind);
		if (protocol == IP_FW_F_TCP || protocol == IP_FW_F_UDP ||
		    protocol == IP_FW_F_ICMP )
		{
			int cnt;
			cnt = get_ports(&argv, &firewall.fw_pts[0], 0, IP_FW_MAX_PORTS,
			    kind, proto_name);
			if (cnt < 0)
			{
				src_range = IP_FW_F_SRNG;
				cnt = -cnt;
			}
			else
			{
				src_range = 0;
			}
			firewall.fw_nsp = cnt;
		}
		else
		{
			firewall.fw_nsp = 0;
			src_range = 0;
		}
	}
	else
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_expect_from2,
					    "ipfw: expected \"from\", got \"%s\"\n"), *argv);
		usage();
	}

	if (*argv == NULL)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_to2, "ipfw: missing \"to\" keyword\n"));
		usage();
	}
	if (strcmp(*argv, "to") == 0)
	{
		argv++;
		get_ipaddr(*argv++, &firewall.fw_dst, &firewall.fw_dmsk, kind);
		if (protocol == IP_FW_F_TCP || protocol == IP_FW_F_UDP)
		{
			int cnt;
			cnt = get_ports(&argv, &firewall.fw_pts[firewall.fw_nsp], 0,
			    IP_FW_MAX_PORTS - firewall.fw_nsp,
			    kind, proto_name);
			if (cnt < 0)
			{
				dst_range = IP_FW_F_DRNG;
				cnt = -cnt;
			}
			else
			{
				dst_range = 0;
			}
			firewall.fw_ndp = cnt;
		}
		else
		{
			firewall.fw_ndp = 0;
			dst_range = 0;
		}
	}
	else
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_expect_to2,
					    "ipfw: expected \"to\", got \"%s\"\n"), *argv);
		usage();
	}

	pflags = get_protoflags(&argv, protocol, kind);

#if HAVE_FW_APPEND
	if (append)
		pflags|=IP_FW_F_APPEND;
#endif
		
	if (*argv == NULL)
	{
		firewall.fw_flg = protocol | accept_firewall | src_range | dst_range | pflags;
#if HAVE_FW_MASQUERADE		
		if (kind == IPF_MASQUERADE)
			firewall.fw_flg |= IP_FW_F_MASQ;
#endif
		(void) do_setsockopt(ipf_names[kind],
		    socket_fd, IPPROTO_IP,
		    ipf_addfunc[kind],
		    &firewall,
		    sizeof(firewall),0);
	}
	else
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_extra2,
					    "ipfw: extra parameters at end of command ("));
		show_parms(argv);
		fprintf(stderr, ")\n");
		usage();
	}
}

void del(ipf_kind kind, int socket_fd, char **argv)
{
	int protocol, accept_firewall=0, src_range=0, dst_range=0, pflags;
	struct ip_fw firewall;
	char *proto_name;

	printf(NLS_CATGETS(catfd, ipfwSet, ipfw_delete, "delete %s "), nls_ipf_names[kind]);
	show_parms(argv);
	printf("\n");

	if (kind != IPF_ACCOUNTING && kind != IPF_MASQUERADE)
	{
		if (*argv == NULL)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_acc2,
						    "ipfw: missing \"accept\" or \"deny\" keyword\n"));
			usage();
		}
		if (strcmp(*argv, "deny") == 0)
		{
			accept_firewall = 0;
		}
		else if (strcmp(*argv, "accept") == 0)
		{
			accept_firewall = IP_FW_F_ACCEPT;
		}
		else if (strcmp(*argv, "reject") == 0)
			accept_firewall = IP_FW_F_ICMPRPL;
		else
		{
			fprintf(stderr, NLS_CATGETS (catfd, ipfwSet, ipfw_expect_acc2,
			    "ipfw: expected \"accept\" or \"deny\", got \"%s\"\n"),
			    *argv);
			usage();
		}

		argv += 1;
	}
	else
		accept_firewall = IP_FW_F_ACCEPT;
	if(*argv==NULL)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_proto2,
					    "ipfw: missing protocol name.\n"));
		usage();
	}
		
	proto_name = *argv++;
	protocol = get_protocol(proto_name, kind);

	firewall.fw_via.s_addr = 0;
	
	if(*argv && strcmp(*argv,"iface")==0)
	{
		argv++;
		if(*argv==NULL)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_iface2,
						    "ipfw: missing interface address.\n"));
			usage();
		}
		firewall.fw_via.s_addr=inet_addr(*argv);
		if(firewall.fw_via.s_addr==-1)
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_invalid_iface2,
						    "Invalid interface address.\n"));
			usage();
		}
		argv++;
	}

	if (*argv == NULL)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_from3,
					    "ipfw: missing \"from\" keyword\n"));
		usage();
	}
	if (strcmp(*argv, "from") == 0)
	{
		argv++;
		get_ipaddr(*argv++, &firewall.fw_src, &firewall.fw_smsk, kind);
		if (protocol == IP_FW_F_TCP || protocol == IP_FW_F_UDP ||
		    protocol == IP_FW_F_ICMP)
		{
			int cnt;
			cnt = get_ports(&argv, &firewall.fw_pts[0], 0, IP_FW_MAX_PORTS,
			    kind, proto_name);
			if (cnt < 0)
			{
				src_range = IP_FW_F_SRNG;
				cnt = -cnt;
			}
			else
			{
				src_range = 0;
			}
			firewall.fw_nsp = cnt;
		}
		else
		{
			firewall.fw_nsp = 0;
			src_range = 0;
		}
	}
	else
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_expect_from3,
					    "ipfw: expected \"from\", got \"%s\"\n"), *argv);
		usage();
	}

	if (*argv == NULL)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_missing_to3, "ipfw: missing \"to\" keyword\n"));
		usage();
	}
	if (strcmp(*argv, "to") == 0)
	{
		argv++;
		get_ipaddr(*argv++, &firewall.fw_dst, &firewall.fw_dmsk, kind);
		if (protocol == IP_FW_F_TCP || protocol == IP_FW_F_UDP)
		{
			int cnt;
			cnt = get_ports(&argv, &firewall.fw_pts[firewall.fw_nsp], 0,
			    IP_FW_MAX_PORTS - firewall.fw_nsp,
			    kind, proto_name);
			if (cnt < 0)
			{
				dst_range = IP_FW_F_DRNG;
				cnt = -cnt;
			}
			else
			{
				dst_range = 0;
			}
			firewall.fw_ndp = cnt;
		}
		else
		{
			firewall.fw_ndp = 0;
			dst_range = 0;
		}
	}
	else
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_expect_to3,
					    "ipfw: expected \"to\", got \"%s\"\n"), *argv);
		usage();
	}

	pflags = get_protoflags(&argv, protocol, kind);

	if (*argv == NULL)
	{
		firewall.fw_flg = protocol | accept_firewall | src_range | dst_range | pflags;
#if HAVE_FW_MASQUERADE
		if (kind == IPF_MASQUERADE)
			firewall.fw_flg |= IP_FW_F_MASQ;
#endif			
		(void) do_setsockopt(ipf_names[kind],
		    socket_fd, IPPROTO_IP,
		    ipf_delfunc[kind],
		    &firewall,
		    sizeof(firewall),0);
	}
	else
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_extra3,
					    "ipfw: extra parameters at end of command ("));
		show_parms(argv);
		fprintf(stderr, ")\n");
		usage();
	}
}

static int count_mask(unsigned long mask)
{
	int ct;
	for (ct = 0; (mask & 0x80000000); ct++)
		mask <<= 1;
	return ct;
}

typedef struct
{
	int acct;
	unsigned long sa, da, sm, dm, iface;
	unsigned int nsp, ndp;
	unsigned long npkt, nbyt;
	unsigned int fw_pts[10];
	int fw_flg;
} fw_rec;

#define MIN(a,b) ((a)<(b)? (a): (b))
#define SRC(x)   ((x)->sa & (x)->sm)
#define DST(x)   ((x)->da & (x)->dm)

static int int_order(const void *L, const void *R)
{
	return (*(unsigned int *) R - *(unsigned int *) L);
}

static int list_order(const void *L, const void *R)
{
	register const fw_rec *l = L;
	register const fw_rec *r = R;

	register int result =
	((r->fw_flg & IP_FW_F_KIND) - (l->fw_flg & IP_FW_F_KIND)) ? :
	(MIN(SRC(r), DST(r)) - MIN(SRC(l), DST(l)));

	if (result == 0 && (l->fw_flg & (IP_FW_F_TCP | IP_FW_F_UDP)))
	{
		unsigned int nlp, lp[10], nrp, rp[10];
		unsigned int i;

		bzero(lp, 10 * sizeof(unsigned int));
		bzero(rp, 10 * sizeof(unsigned int));

		bcopy(l->fw_pts, lp, (nlp = l->nsp + l->ndp) * sizeof(unsigned int));
		bcopy(r->fw_pts, rp, (nrp = r->nsp + r->ndp) * sizeof(unsigned int));

		qsort(lp, nlp, sizeof(unsigned int), int_order);
		qsort(rp, nrp, sizeof(unsigned int), int_order);

		for (i = 0; i < 10; ++i)
			if (lp[i] != rp[i])
				return (lp[i] - rp[i]);
	}
	return result;
}

static char *addr_to_name(unsigned int a, unsigned int m)
{
	static char tbuf[128];
	struct hostent *hptr;
	struct netent *nptr;

	if (m == 0)
		NLS_CATBUFF (catfd, ipfwSet, ipfw_anywhere, "anywhere", tbuf, 128);
	else if (m == 0xffffffff) {
		struct in_addr ia = {htonl(a)};

		if (lookup && (hptr = gethostbyaddr((char *) &ia, sizeof ia, AF_INET)))
			strcpy(tbuf, hptr->h_name);
		else
			sprintf(tbuf, "%s/32", fmtip(htonl(a)));
	} else { /* avoid DNS lookups for networks --okir */
		int mask_len = count_mask(m);

		if (lookup && (nptr = getnetbyaddr(a, AF_INET)))
			sprintf(tbuf, "=%s", nptr->n_name);
		else
			sprintf(tbuf, "%s/%d", fmtip(htonl(a)), mask_len);
	}

	return tbuf;
}

void list_file(char *path, int acct)
{
	FILE *f = fopen(path, reset?"r+":"r");
	int nrecs = 8;
	int nused = 0;
	int policy=-1;
	fw_rec *recs = (void *) malloc(sizeof(fw_rec) * nrecs);
	fw_rec *rec;
	char buf[256],flags[10];
	struct servent *sptr;

	if (f == NULL)
	{
		perror(path);
		NLS_CATCLOSE(catfd)
		exit(1);
	}
	fgets(buf, 255, f);	/* skip title */
	if (!(acct & 1))
		policy=atoi(rindex(buf,' ')+1);
	while (fgets(buf, 255, f))
	{			/* read in the data */
		if (nused >= nrecs)
		{
			nrecs <<= 1;
			recs = (void *) realloc(recs, sizeof(fw_rec) * nrecs);
		}
		rec = &recs[nused++];

		rec->acct = acct & 1;
		sscanf(buf,
		    "%lX/%lX->%lX/%lX %lX %X %u %u %lu %lu %u %u %u %u %u %u %u %u %u %u",
		    &rec->sa, &rec->sm, &rec->da, &rec->dm, &rec->iface,
		    &rec->fw_flg, &rec->nsp, &rec->ndp, &rec->npkt, &rec->nbyt,
		    &rec->fw_pts[0], &rec->fw_pts[1], &rec->fw_pts[2], &rec->fw_pts[3],
		    &rec->fw_pts[4], &rec->fw_pts[5], &rec->fw_pts[6], &rec->fw_pts[7],
		    &rec->fw_pts[8], &rec->fw_pts[9]);
	}
	fclose(f);

	qsort(recs, nused, sizeof(fw_rec), list_order); /* ??? */

	if (nused) { 
		if (acct & 2)
			printf(NLS_CATGETS(catfd, ipfwSet, ipfw_bytes, "  Packets    Bytes  "));

		printf(NLS_CATGETS(catfd, ipfwSet, ipfw_proto, "Type    Proto Flags From                To                  Iface               Ports\n"));
	}
	
	for (rec = recs; nused-- > 0; ++rec)
	{
		unsigned int *pp = &rec->fw_pts[0];

		if (acct & 2) {
			printf("%9lu", rec->npkt);
			if (rec->nbyt > 100 * 1024)
			{
				unsigned long kbyt = (rec->nbyt + 1023) / 1024;
				if (kbyt > 100 * 1024)
				{
					unsigned long mbyt = (kbyt + 1023) / 1024;
					printf(" %7luM ", mbyt);
				}
				else
					printf("  %7luK ", kbyt);
			}
			else
				printf("  %7lu  ", rec->nbyt);
		}
		if (!rec->acct)
		{
			if (rec->fw_flg & IP_FW_F_ACCEPT)
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_list_accept, "accept  "));
			else if (rec->fw_flg & IP_FW_F_ICMPRPL)
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_list_reject, "reject  "));
			else
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_list_deny, "deny    "));
		} else
			printf(NLS_CATGETS(catfd, ipfwSet, ipfw_list_account, "account "));

		switch (rec->fw_flg & IP_FW_F_KIND)
		{
		case IP_FW_F_ALL:
			printf("all   ");
			break;
		case IP_FW_F_TCP:
			printf("tcp   ");
			break;
		case IP_FW_F_UDP:
			printf("udp   ");
			break;
		case IP_FW_F_ICMP:
			printf("icmp  ");
			break;
		}

		flags[0]='\0';
#if HAVE_FW_MASQUERADE
		if (rec->fw_flg & IP_FW_F_MASQ)
			strcat(flags,"M");
#endif
		if (rec->fw_flg & IP_FW_F_TCPSYN)
			strcat(flags,"S");
#if HAVE_FW_TCPACK			
		if (rec->fw_flg & IP_FW_F_TCPACK)
			strcat(flags, "A");
#endif
		if (rec->fw_flg & IP_FW_F_BIDIR)
			strcat(flags, "B");
		if (rec->fw_flg & IP_FW_F_PRN)
			strcat(flags, "P");
		if (!flags[0])
			strcpy(flags,"*");

		printf("%-6.6s",flags);

		printf("%-19.19s ", addr_to_name(rec->sa, rec->sm));
		printf("%-19.19s ", addr_to_name(rec->da, rec->dm));
		
		if (rec->iface)
			printf("%-19.19s", addr_to_name(rec->iface, 0xffffffff));

		if (rec->fw_flg & (IP_FW_F_TCP | IP_FW_F_UDP))
		{
			char *sep = "";
			char *proto;

			if (!rec->iface)
				printf("%-19.19s ", "");
			else
				printf(" ");

			if ((rec->fw_flg & IP_FW_F_KIND) == IP_FW_F_ICMP)
				proto="icmp";
			else
				proto=(rec->fw_flg & IP_FW_F_TCP) ? "tcp" : "udp";
				
			if (rec->nsp == 0)
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_list_any, "any"));
			else
			{
				if (rec->fw_flg & IP_FW_F_SRNG)
				{
					printf("%u-%u", pp[0], pp[1]);
					sep = ",";
					pp += 2;
					rec->nsp -= 2;
				}
				while (rec->nsp-- > 0)
				{
					if (lookup)
						sptr = getservbyport(htons(*pp), proto);
					else
						sptr = NULL;
						
					if (sptr)
						printf("%s%s", sep, sptr->s_name);
					else
						printf("%s%u", sep, *pp);
					++pp;
					sep = ",";
				}
			}

			if ((rec->fw_flg & IP_FW_F_KIND) != IP_FW_F_ICMP) {
			printf(" -> ");

			sep = "";
			if (rec->ndp == 0)
				printf(NLS_CATGETS(catfd, ipfwSet, ipfw_list_any, "any"));
			else
			{
				if (rec->fw_flg & IP_FW_F_DRNG)
				{
					printf("%u-%u", pp[0], pp[1]);
					sep = ",";
					pp += 2;
				}
				while (rec->ndp-- > 0)
				{
					if (lookup)
						sptr = getservbyport(htons(*pp), proto);
					else
						sptr = NULL;
						
					if (sptr)
						printf("%s%s", sep, sptr->s_name);
					else
						printf("%s%u", sep, *pp);
					++pp;
					sep = ",";
				}
			}
			}
		}
		printf("\n");
	}
	endservent();
	switch(policy) {
		case 0:
			printf(NLS_CATGETS(catfd, ipfwSet, ipfw_dp_deny, "Default policy: deny\n"));
			break;
		case IP_FW_F_ACCEPT:
			printf(NLS_CATGETS(catfd, ipfwSet, ipfw_dp_accept, "Default policy: accept\n"));
			break;
		case IP_FW_F_ICMPRPL:
			printf(NLS_CATGETS(catfd, ipfwSet, ipfw_dp_reject, "Default policy: reject\n"));
			break;
	}
}

void list(char **argv)
{
	if (*argv == NULL || !**argv)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_expect_kwds,
					    "blocking, forwarding or accounting keyword expected.\n"));
		NLS_CATCLOSE(catfd)
		exit(1);
	}
	if (strncmp(*argv, "blocking", strlen(*argv)) == 0)
	{
		list_file(_PATH_PROCNET_IP_BLK, count);
		return;
	}
	if (strncmp(*argv, "forwarding", strlen(*argv)) == 0)
	{
		list_file(_PATH_PROCNET_IP_FWD, count);
		return;
	}
	if (strncmp(*argv, "accounting", strlen(*argv)) == 0)
	{
		list_file(_PATH_PROCNET_IP_ACC, count?1:3);
		return;
	}
	fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_found_kwds,
				    "Found '%s': 'blocking', 'forwarding' or 'accounting' keyword expected.\n"), *argv);
	usage();
}

#define MATCH(in,pat) ( in && in[0] && (strncmp(in, pat, strlen(in)) == 0) )

void main(argc, argv)
int argc;
char **argv;
{
	int socket_fd=0,lop,i;
	char *type = NULL, *op = NULL;
  	struct option longopts[]=
  	{
		{"version",	0,	0,	'V'},
		{"numeric",	0,	0,	'n'},
		{"append",	0,	0,	'a'},
		{"counter",	0,	0,	'c'},
		{"debug",	0,	0,	'd'},
		{"help",	0,	0,	'h'},
		{"reset",	0,	0,	'r'},
		{NULL,		0,	0,	0}
	};	

#if NLS
	setlocale (LC_MESSAGES, "");
	catfd = catopen ("nettools", MCLoadBySet);
#endif
	ipf_names_init();
	/* opterr = 0; */
	while ((i = getopt_long(argc, argv, "adncrhV?",longopts, &lop)) != EOF) switch(i) {
	case 'a':
#if HAVE_FW_APPEND
		append = 1;
		break;
#endif
		fprintf(stderr,NLS_CATGETS(catfd, ipfwSet, ipfw_no_support, "ipfw: no support for `%s'. Please recompile with newer Kernel.\n"),"--append");
		NLS_CATCLOSE(catfd)
		exit(1);
	case 'c':
		count = 2;
		break;
		
	case 'd':
		close(socket_fd);
		socket_fd = -1;
		break;

	case 'n':
		lookup = 0;
		break;
	case 'r':
		reset = 1;
		break;

	case 'V':
		version();
	case '?':
	case 'h':
	default:
		usage();
	}
	
	optind--;
	
	argc -= optind;
	argv += optind;
	
	if (argc <= 1)
	{
		usage();
		NLS_CATCLOSE(catfd)
		exit(1);
	}
	if (MATCH(argv[1], "list"))
	{
		type = "list";
		list(&argv[2]);
		NLS_CATCLOSE(catfd);
		exit(0);
	}

	socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	if (socket_fd < 0)
	{
		perror(NLS_CATGETS(catfd, ipfwSet, ipfw_raw_socket, "ipfw: raw socket creation"));
		NLS_CATCLOSE(catfd)
		exit(1);
	}

	if(MATCH(argv[1], "policy"))
	{
		int ptype=0;
		int mode;
		type="policy";
		
		if(MATCH(argv[2],"blocking"))
			ptype=IP_FW_POLICY_BLK;
		else if(MATCH(argv[2], "forwarding"))
			ptype=IP_FW_POLICY_FWD;
		else
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_expect_main_blocking,
						    "ipfw: expected \"blocking\" or \"forwarding\".\n"));
			usage();
		}
		if(MATCH(argv[3], "reject"))
			mode=IP_FW_F_ICMPRPL;
		else if(MATCH(argv[3], "accept"))
			mode=IP_FW_F_ACCEPT;
		else if(MATCH(argv[3], "deny"))
			mode=0;
		else
		{	
			fprintf(stderr,NLS_CATGETS(catfd, ipfwSet, ipfw_expect_main_accept,
						   "ipfw: expected \"accept\", \"deny\" or \"reject\".\n"));
			usage();
		}
		do_setsockopt(argv[2], socket_fd, IPPROTO_IP, ptype, &mode, sizeof(mode),0);
		NLS_CATCLOSE(catfd)
		exit(0);
	}
	else if (MATCH(argv[1], "flush"))
	{
		type="flush";
		
		if (MATCH(argv[2], "accounting"))
		{
			/* Same kludge as above, see above ranting and griping -BB */
			unsigned long fred = 1;
			(void) do_setsockopt(argv[1], socket_fd, IPPROTO_IP, IP_ACCT_FLUSH, &fred, sizeof(unsigned long), 0);

		}
		else if (MATCH(argv[2], "forwarding"))
		{
			/* Same kludge as above, see above ranting and griping -BB */
			unsigned long fred = 1;
			(void) do_setsockopt(argv[1], socket_fd, IPPROTO_IP, IP_FW_FLUSH_FWD, &fred, sizeof(unsigned long), 0);
		}
		else if (MATCH(argv[2], "blocking"))
		{
			/* Same kludge as above, see above ranting and griping -BB */
			unsigned long fred = 1;
			(void) do_setsockopt(argv[1], socket_fd, IPPROTO_IP, IP_FW_FLUSH_BLK, &fred, sizeof(unsigned long), 0);
		}
		else
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_expect_main_accounting,
			    "ipfw: expected \"accounting\", \"blocking\" or \"forwarding\".\n"));
			usage();
		}
	}
	else if (MATCH(argv[1], "check"))
	{
		type="check";
		
		if (MATCH(argv[2], "blocking"))
			check(IPF_BLOCKING, socket_fd, &argv[3]);

		else if (MATCH(argv[2], "forwarding"))
			check(IPF_FORWARDING, socket_fd, &argv[3]);

		else
		{
			fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_illegal_check,
					    "ipfw: illegal `check' keyword: %s\n"),argv[2]);
			usage();
		}
	}
	else
	{
		int is_add = MATCH(argv[1], "add");
		int is_del = MATCH(argv[1], "delete");

		if (is_add)
		{
			type = "add";
			if (MATCH(argv[2], "blocking"))
				add(IPF_BLOCKING, socket_fd, &argv[3]);
			else if (MATCH(argv[2], "forwarding"))
				add(IPF_FORWARDING, socket_fd, &argv[3]);
			else if (MATCH(argv[2], "accounting"))
				add(IPF_ACCOUNTING, socket_fd, &argv[3]);
			else if (MATCH(argv[2], "masquerade")) {
#if HAVE_FW_MASQUERADE				
				add(IPF_MASQUERADE, socket_fd, &argv[3]);
#else
				fprintf(stderr,NLS_CATGETS(catfd, ipfwSet, ipfw_no_support, "ipfw: no support for `%s'. Please recompile with newer Kernel.\n"),"masquerade");
				NLS_CATCLOSE(catfd)
				exit(1);
#endif
			} else
				op = argv[2] ? : NLS_CATSAVE (catfd, ipfwSet, ipfw_main_missing, "(missing)");
		}
		else if (is_del)
		{
			type = "del";
			if (MATCH(argv[2], "blocking"))
				del(IPF_BLOCKING, socket_fd, &argv[3]);
			else if (MATCH(argv[2], "forwarding"))
				del(IPF_FORWARDING, socket_fd, &argv[3]);
			else if (MATCH(argv[2], "accounting"))
				del(IPF_ACCOUNTING, socket_fd, &argv[3]);
			else if (MATCH(argv[2], "masquerade")) {
#if HAVE_FW_MASQUERADE
				del(IPF_MASQUERADE, socket_fd, &argv[3]);
#else
				fprintf(stderr,NLS_CATGETS(catfd, ipfwSet, ipfw_no_support, "ipfw: no support for `%s'. Please recompile with newer Kernel.\n"),"masquerade");
				NLS_CATCLOSE(catfd)
				exit(1);
#endif
			} else
				op = argv[2] ? : NLS_CATSAVE (catfd, ipfwSet, ipfw_main_missing, "(missing)");
		}
		else if (MATCH(argv[1], "zero") || MATCH(argv[1], "zeroaccounting"))
		{
			unsigned long fred = 1;
			type = "zero";
			/* Same kludge as above, see above ranting and griping -BB */
			
			if (MATCH(argv[2], "blocking"))
				(void) do_setsockopt(argv[1], socket_fd, IPPROTO_IP, IP_FW_ZERO_BLK, &fred, sizeof(unsigned long), 0);
			else if (MATCH(argv[2], "forwarding"))
				(void) do_setsockopt(argv[1], socket_fd, IPPROTO_IP, IP_FW_ZERO_FWD, &fred, sizeof(unsigned long), 0);
			else if (MATCH(argv[2], "accounting") || (MATCH(argv[1], "zeroaccounting") && !argv[2]))
				(void) do_setsockopt(argv[1], socket_fd, IPPROTO_IP, IP_ACCT_ZERO, &fred, sizeof(unsigned long), 0);
			else
				op = argv[2] ? : NLS_CATSAVE (catfd, ipfwSet, ipfw_main_missing, "(missing)");
		}
	}
	if (!type)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_unkn_cmd,
					    "ipfw: unknown command `%s'\n\n"), argv[1]);
			usage();
	}
	else if (op)
	{
		fprintf(stderr, NLS_CATGETS(catfd, ipfwSet, ipfw_unkn_kwd,
					    "ipfw: unknown `%s' keyword: `%s'\n"),
		    type, op);
		usage();
	}

	NLS_CATCLOSE(catfd)
	exit(0);
}
