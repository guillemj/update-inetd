/*
 * route        This file contains an implementation of the command
 *              that manages the IP routing table in the kernel.
 *
 * Version:     route 1.94 (1997-09-21)
 *
 * Maintainer:	Bernd 'eckes' Eckenfels, <net-tools@lina.inka.de>
 *
 * Author:      Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 *		(derived from FvK's 'route.c     1.70    01/04/94')
 *
 * Modifications:
 *	 	Johannes Stille:	for Net-2Debugged by 
 *					<johannes@titan.os.open.de>
 *	 	Linus Torvalds:		Misc Changes
 *	 	Alan Cox:		add the new mtu/window stuff
 *	 	Miquel van Smoorenburg:	rt_add and rt_del
 *	 {1.79}	Bernd Eckenfels:	route_info
 *	 {1.80}	Bernd Eckenfels:	reject, metric, irtt, 1.2.x support.
 *	 {1.81}	Bernd Eckenfels:	reject routes need a dummy device
 *960127 {1.82} Bernd Eckenfels:	'mod' and 'dyn' 'reinstate' added
 *960129 {1.83}	Bernd Eckenfels:	resolve and getsock now in lib/, 
 *					REJECT displays '-' as gatway.
 *960202 {1.84} Bernd Eckenfels:	net-features support added
 *960203 {1.85} Bernd Eckenfels:	"#ifdef' in '#if' for net-features
 *					-A  (aftrans) support, get_longopts
 *960206 {1.86} Bernd Eckenfels:	route_init();
 *960218 {1.87} Bernd Eckenfels:	netinet/in.h added
 *960221 {1.88}	Bernd Eckenfels:	aftrans_dfl support
 *960222 {1.90} Bernd Eckenfels:	moved all AF specific code to lib/.
 *960413 {1.91} Bernd Eckenfels:	new RTACTION support+FLAG_CACHE/FIB
 *960426 {1.92} Bernd Eckenfels:	FLAG_SYM/-N support
 *960823 {x.xx} Frank Strauss:  	INET6 stuff
 *
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <linux/param.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <ctype.h>
#include "net-support.h"
#include "config.h"
#include "net-locale.h"
#include "pathnames.h"
#include "version.h"

#define DFLT_AF "inet"

#define FEATURE_ROUTE
#include "lib/net-features.h" /* needs some of the system includes above! */

char	*Release = RELEASE,
	*Version = "route 1.94 (1997-09-21)";

int             opt_n  = 0;	/* numerical output flag	*/
int             opt_v  = 0;	/* debugging output flag	*/
int		opt_e  = 1;	/* 1,2,3=type of routetable	*/
int		opt_fc = 0;	/* routing cache/FIB */
int		opt_h  = 0;	/* help selected		*/
struct aftype   *ap;		/* current address family	*/

static void usage(void)
{
	fprintf(stderr, NLS_CATGETS(catfd, routeSet, route_usage1,
				"Usage: route [-nNvee] [-FC] [Address_families]  List kernel routing tables\n"));
	fprintf(stderr, NLS_CATGETS(catfd, routeSet, route_usage2,
				"       route {-V|--version}                  Display command version and exit.\n"));
	fprintf(stderr, NLS_CATGETS(catfd, routeSet, route_usage3,
				"       route {-h|--help} [Address_family]    Usage Syntax for specified AF.\n"));
	fprintf(stderr, NLS_CATGETS(catfd, routeSet, route_usage4,
				"       route [-v] [-FC] {add|del|flush} ...  Modify routing table for AF.\n\n"));
	fprintf(stderr, NLS_CATGETS(catfd, routeSet, route_usage5,
				"  Address_families: inet,inet6,ddp,ipx,netrom,ax25\n"));
	fprintf(stderr, NLS_CATGETS(catfd, routeSet, route_usage6,
				"        specify AF: -A af1,af2..  or  --af1 --af2  or  af_route\n"));
	NLS_CATCLOSE(catfd)
	exit(E_USAGE);
}


static void version(void)
{
	fprintf(stderr,"%s\n%s\n%s\n",Release,Version,Features);
	NLS_CATCLOSE(catfd)
	exit(E_VERSION);
}


int main(int argc, char **argv)
{
	int i,lop,what=0;
	struct option longopts[]=
	{
		AFTRANS_OPTS,
		{"extend",	0,	0,	'e'},
		{"verbose",	0,	0,	'v'},
		{"version",	0,	0,	'V'},
		{"numeric",	0,	0,	'n'},
		{"symbolic",	0,	0,	'N'},
		{"protocol",	1,	0,	'A'},
		{"cache",	0,	0,	'C'},
		{"fib",		0,	0,	'F'},
		{"help",	0,	0,	'h'},
		{NULL,		0,	0,	0}
	};	
	char **tmp;
	char *progname;
	int options;

#if NLS
	setlocale (LC_MESSAGES, "");
	catfd = catopen ("nettools", MCLoadBySet);
#endif

	getroute_init(); 			/* Set up AF routing support */
	setroute_init();
	afname[0] = '\0';
	progname=argv[0];
	
	/* getopts and -net wont work :-/ */
	for(tmp=argv;*tmp;tmp++) {
		if (!strcmp(*tmp, "-net"))
			strcpy(*tmp, "#net");
		else if (!strcmp(*tmp, "-host"))
			strcpy(*tmp, "#host");
	}
	
	/* Fetch the command-line arguments. */
	while ((i = getopt_long(argc, argv, "A:eCFhnNVv?", longopts, &lop)) != EOF) switch(i) {
		case -1:
			break;
		case 'n':
			opt_n |= FLAG_NUM;
			break;
		case 'N':
			opt_n |= FLAG_SYM;
			break;
		case 'v':
			opt_v |= FLAG_VERBOSE;
			break;
		case 'e':
			opt_e++;
			break;
		case 1:
			if (lop < 0 || lop >= AFTRANS_CNT) {
				EINTERN("route.c","longopts 1 range");
				break;
			}
			if ((i = aftrans_opt(longopts[lop].name))) {
				NLS_CATCLOSE(catfd)
				exit(i);
			}
			break;
		case 'C':
			opt_fc |= FLAG_CACHE;
			break;
		case 'F':
			opt_fc |= FLAG_FIB;
			break;
		case 'A':
			if ((i = aftrans_opt(optarg))) {
				NLS_CATCLOSE(catfd)
				exit(i);
			}
			break;
		case 'V':
			version();
		case 'h':
		case '?':
			opt_h++;
			break;
		default:
			usage();
	}
	
	argv += optind;
	argc -= optind;
	
	if (opt_h) {
		if (!afname[0])
			usage();
		else
			what = RTACTION_HELP;
	} else {	
		if (!afname[0])
			/* this will initialise afname[] */
			aftrans_def("route", progname, DFLT_AF);

		/* Do we have to show the contents of the routing table? */
		if (*argv == NULL) {
			what = RTACTION_SHOW;
		} else {
			if (!strcmp(*argv, "add"))
				what = RTACTION_ADD;
			else if (!strcmp(*argv, "del") || !strcmp(*argv, "delete"))
				what = RTACTION_DEL;
			else if (!strcmp(*argv,"flush"))
				what = RTACTION_FLUSH;
			else 
				usage();
		}
	}

	options = (opt_e & FLAG_EXT) | opt_n | opt_fc | opt_v;
	if (!opt_fc)
		options |= FLAG_FIB;

	if (what == RTACTION_SHOW)
		i = route_info(afname,options);
	else
		i = route_edit(what,afname,options,++argv);

	if (i == E_OPTERR)
		usage();

	NLS_CATCLOSE(catfd)
	return (i);
}
