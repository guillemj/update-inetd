/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1989 The Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

/*
 *			P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 * Bugs -
 *	More statistics could always be gathered.
 *	This program has to run SUID to ROOT to access the ICMP socket.
 */

#include <stdlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>


#define	DEFDATALEN	(64 - 8)	/* default data length */
#define	MAXIPLEN	60
#define	MAXICMPLEN	76
#define	MAXPACKET	(65536 - 60 - 8)/* max packet size */
#define	MAXWAIT		10		/* max seconds to wait for response */
#define	NROUTES		9		/* number of record route slots */

#define	A(bit)		rcvd_tbl[(bit)>>3]	/* identify byte in array */
#define	B(bit)		(1 << ((bit) & 0x07))	/* identify bit in byte */
#define	SET(bit)	(A(bit) |= B(bit))
#define	CLR(bit)	(A(bit) &= (~B(bit)))
#define	TST(bit)	(A(bit) & B(bit))

/* various options */
int options;
#define	F_FLOOD		0x001
#define	F_INTERVAL	0x002
#define	F_NUMERIC	0x004
#define	F_PINGFILLED	0x008
#define	F_QUIET		0x010
#define	F_RROUTE	0x020
#define	F_SO_DEBUG	0x040
#define	F_SO_DONTROUTE	0x080
#define	F_VERBOSE	0x100
#define	F_TIMESTAMP	0x200
#define	F_SOURCEROUTE	0x400

static int ts_type;
static int nroute = 0;
static __u32 route[10];


/* multicast options */
static int moptions;
#define MULTICAST_NOLOOP	0x001
#define MULTICAST_TTL		0x002
#define MULTICAST_IF		0x004

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.  Change 128
 * to 8192 for complete accuracy...
 */
#define	MAX_DUP_CHK	(8 * 128)
int mx_dup_ck = MAX_DUP_CHK;
char rcvd_tbl[MAX_DUP_CHK / 8];

struct sockaddr whereto;	/* who to ping */
int datalen = DEFDATALEN;
int s;				/* socket file descriptor */
u_char outpack[MAXPACKET];
char BSPACE = '\b';		/* characters written for flood */
char DOT = '.';
char *hostname;
int ident;			/* process id to identify our packets */

/* counters */
long npackets;			/* max packets to transmit */
long nreceived;			/* # of packets we got back */
long nrepeats;			/* number of duplicates */
long ntransmitted;		/* sequence # for outbound packets = #sent */
long nchecksum;			/* replies with bad checksum */
long nerrors;			/* icmp errors */
int interval = 1;		/* interval between packets */
int maxwait = MAXWAIT;		/* max time to wait for last packet */

/* timing */
int timing;			/* flag to do timing */
long tmin = LONG_MAX;		/* minimum round trip time */
long tmax;			/* maximum round trip time */
unsigned long tsum;			/* sum of all times, for doing average */

static int broadcast_pings = 0;

static char *pr_addr(__u32);
static void catcher(void);
static void finish(void) __attribute__((noreturn));
static void fill(char *bp, char *patp);
static void pr_options(unsigned char * cp, int hlen);
static void pr_iph(struct iphdr *ip);
static void pr_retip(struct iphdr *ip);
static void usage(void) __attribute__((noreturn));
static void pinger(void);
static int pr_pack(char *buf, int cc, struct sockaddr_in *from);
static u_short in_cksum(u_short *addr, int len);
static void pr_icmph(struct icmphdr *icp);


/*
 * tvsub --
 *	Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static __inline__ void tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

void set_signal(int signo, void (*handler)(void))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = (void (*)(int))handler;
#ifdef SA_INTERRUPT
	sa.sa_flags = SA_INTERRUPT;
#endif
	sigaction(signo, &sa, NULL);
}

static struct {
	struct cmsghdr cm;
	struct in_pktinfo ipi;
} cmsg = { {sizeof(struct cmsghdr) + sizeof(struct in_pktinfo), SOL_IP, IP_PKTINFO},
	   {0, }};
int cmsg_len;

struct sockaddr_in source;
char *device;


int
main(int argc, char **argv)
{
	struct timeval timeout;
	struct hostent *hp;
	struct sockaddr_in *to = NULL;
	int i;
	int ch, fdmask, hold, packlen, preload;
	u_char *datap, *packet;
	char *target, hnamebuf[MAXHOSTNAMELEN];
	u_char ttl, loop;
	int uid = getuid();
	char rspace[3 + 4 * NROUTES + 1];	/* record route space */

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		setuid(uid);
		perror("ping: socket");
		exit(2);
	}
	setuid(uid);

	source.sin_family = AF_INET;

	preload = 0;
	datap = &outpack[8 + sizeof(struct timeval)];
	while ((ch = getopt(argc, argv, "I:LT:Rc:dfh:i:m:l:np:qrs:t:vb")) != EOF)
		switch(ch) {
		case 'b':
		        broadcast_pings = 1;
			if (uid) {
				(void)fprintf(stderr,
				    "ping: %s\n", strerror(EPERM));
				exit(2);
			}
			break;
		case 'c':
			npackets = atoi(optarg);
			if (npackets <= 0) {
				(void)fprintf(stderr,
				    "ping: bad number of packets to transmit.\n");
				exit(2);
			}
			break;
		case 'd':
			options |= F_SO_DEBUG;
			break;
		case 'f':
			if (uid) {
				(void)fprintf(stderr,
				    "ping: %s\n", strerror(EPERM));
				exit(2);
			}
			options |= F_FLOOD;
			setbuf(stdout, (char *)NULL);
			break;
		case 'i':		/* wait between sending packets */
			interval = atoi(optarg);
			if (interval <= 0) {
				(void)fprintf(stderr,
				    "ping: bad timing interval.\n");
				exit(2);
			}
			options |= F_INTERVAL;
			break;
		case 'm':		/* wait for last packet if using -c */
			maxwait = atoi(optarg);
			/* range-check is done after argument processing */
			break;
		case 'l':
			preload = atoi(optarg);
			if (preload < 0) {
				(void)fprintf(stderr,
				    "ping: bad preload value.\n");
				exit(2);
			}
			if (uid) {
				(void)fprintf(stderr,
				    "ping: %s\n", strerror(EPERM));
				exit(2);
			}
			break;
		case 'n':
			options |= F_NUMERIC;
			break;
		case 'p':		/* fill buffer with user pattern */
			options |= F_PINGFILLED;
			fill((char *)datap, optarg);
				break;
		case 'q':
			options |= F_QUIET;
			break;
		case 'R':
			if (options & F_TIMESTAMP) {
			  fprintf(stderr, "Only one of -T or -R may be used\n");
			  exit(2);
			}
			options |= F_RROUTE;
			break;
		case 'T':
			if (options & F_RROUTE) {
			  fprintf(stderr, "Only one of -T or -R may be used\n");
			  exit(2);
			}
			options |= F_TIMESTAMP;
			if (strcmp(optarg, "tsonly") == 0)
			  ts_type = IPOPT_TS_TSONLY;
			else if (strcmp(optarg, "tsandaddr") == 0)
			  ts_type = IPOPT_TS_TSANDADDR;
			else if (strcmp(optarg, "tsprespec") == 0)
			  ts_type = IPOPT_TS_PRESPEC;
			else {
			  fprintf(stderr, "Invalid timestamp type\n");
			  exit(2);
			}
			break;
		case 'r':
			options |= F_SO_DONTROUTE;
			break;
		case 's':		/* size of packet to send */
			datalen = atoi(optarg);
			if (datalen > MAXPACKET) {
				(void)fprintf(stderr,
				    "ping: packet size too large.\n");
				exit(2);
			}
			if (datalen <= 0) {
				(void)fprintf(stderr,
				    "ping: illegal packet size.\n");
				exit(2);
			}
			break;
		case 'v':
			options |= F_VERBOSE;
			break;
		case 'L':
			moptions |= MULTICAST_NOLOOP;
			loop = 0;
			break;
		case 't':
			moptions |= MULTICAST_TTL;
			i = atoi(optarg);
			if (i < 0 || i > 255) {
				printf("ttl %u out of range\n", i);
				exit(2);
			}
			ttl = i;
			break;
		case 'I':
			{
				char dummy;
				int i1, i2, i3, i4;

				if (sscanf(optarg, "%u.%u.%u.%u%c",
					   &i1, &i2, &i3, &i4, &dummy) == 4) {
					__u8 *ptr;
					ptr = (__u8*)&source.sin_addr;
					ptr[0] = i1;
					ptr[1] = i2;
					ptr[2] = i3;
					ptr[3] = i4;
				} else {
					struct ifreq ifr;
				
					memset(&ifr, 0, sizeof(ifr));
					device = optarg;
					strncpy(ifr.ifr_name, optarg, 15);
					if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
						fprintf(stderr, "Unknown iface %s\n", optarg);
						exit(2);
					}
					cmsg.ipi.ipi_ifindex = ifr.ifr_ifindex;
					cmsg_len = sizeof(cmsg);
				}
			}
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	if (maxwait < interval) {
		(void)fprintf(stderr,
			"ping: bad maxwait value (must not be smaller than interval).\n");
		exit(2);
	}
	
	if (argc == 0) 
		usage();
	if (argc > 1) {
	  if (options & F_RROUTE)
	    usage();
	  else if (options & F_TIMESTAMP) {
	    if (ts_type != IPOPT_TS_PRESPEC)
	      usage();
	    if (argc > 5)
	      usage();
	  } else {
		  if (argc > 10)
			  usage();
		  options |= F_SOURCEROUTE;
	  }
	}
	while (argc > 0) {
	  target = *argv;

	  bzero((char *)&whereto, sizeof(struct sockaddr));
	  to = (struct sockaddr_in *)&whereto;
	  to->sin_family = AF_INET;
	  if (inet_aton(target, &to->sin_addr) == 1)
		hostname = target;
	  else {
		hp = gethostbyname(target);
		if (!hp) {
			(void)fprintf(stderr,
			    "ping: unknown host %s\n", target);
			exit(2);
		}
		to->sin_family = hp->h_addrtype;
		bcopy(hp->h_addr, (caddr_t)&to->sin_addr, hp->h_length);
		(void)strncpy(hnamebuf, hp->h_name, sizeof(hnamebuf) - 1);
		hostname = hnamebuf;
	      }
	  if (argc > 1)
	    route[nroute++] = to->sin_addr.s_addr;
	  argc--;
	  argv++;
	}

#ifdef linux
	if (source.sin_addr.s_addr == 0) {
		int alen;
		struct sockaddr_in dst = *to;
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);

		if (probe_fd < 0) {
			perror("socket");
			exit(2);
		}
		if (device) {
			struct ifreq ifr;
			strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
			if (setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == -1)
				perror("WARNING: interface is ignored");
		}
		dst.sin_port = htons(1025);
		if (nroute)
			dst.sin_addr.s_addr = route[0];
		if (connect(probe_fd, (struct sockaddr*)&dst, sizeof(dst)) == -1) {
			if (errno == EACCES) {
				if (broadcast_pings == 0) {
					fprintf(stderr, "Do you want to ping broadcast? Then -b\n");
					exit(2);
				}
				fprintf(stderr, "WARNING: pinging broadcast address\n");
				if (setsockopt(probe_fd, SOL_SOCKET, SO_BROADCAST,
					       &broadcast_pings, sizeof(broadcast_pings)) < 0) {
					perror ("can't set broadcasting");
					exit(2);
				}
				if (connect(probe_fd, (struct sockaddr*)&dst, sizeof(dst)) == -1) {
					perror("connect");
					exit(2);
				}
			} else {
				perror("connect");
				exit(2);
			}
		}
		alen = sizeof(source);
		if (getsockname(probe_fd, (struct sockaddr*)&source, &alen) == -1) {
			perror("getsockname");
			exit(2);
		}
		source.sin_port = 0;
		close(probe_fd);
	} while (0);

	if (bind(s, (struct sockaddr*)&source, sizeof(source)) == -1) {
		perror("bind");
		exit(2);
	}
#endif


#ifdef linux
	if (1) {
		struct icmp_filter filt;
		filt.data = ~((1<<ICMP_DEST_UNREACH)|
			      (1<<ICMP_SOURCE_QUENCH)|
			      (1<<ICMP_TIME_EXCEEDED)|
			      (1<<ICMP_PARAMETERPROB)|
			      (1<<ICMP_REDIRECT)|
			      (1<<ICMP_ECHOREPLY));

                /* Only report errors other than EOPNOTSUPP, since SOL_RAW
                 * was introduced somewhere in 2.1.x, and there's not
                 * equivalent in 2.0.x. Ping works just fine on these
                 * kernels, so there's no point reporting this error.
                 */
		if (setsockopt(s, SOL_RAW, ICMP_FILTER, (char*)&filt, sizeof(filt)) == -1 && errno != EOPNOTSUPP)
			perror("WARNING: setsockopt(ICMP_FILTER)");
	}
#endif

	if (options & F_FLOOD && options & F_INTERVAL) {
		(void)fprintf(stderr,
		    "ping: -f and -i incompatible options.\n");
		exit(2);
	}

	if (datalen >= 8 + sizeof(struct timeval))  /* can we time transfer */
		timing = 1;
	packlen = datalen + MAXIPLEN + MAXICMPLEN;
	if (!(packet = (u_char *)malloc((u_int)packlen))) {
		(void)fprintf(stderr, "ping: out of memory.\n");
		exit(2);
	}
	if (!(options & F_PINGFILLED))
		for (i = 8; i < datalen; ++i)
			*datap++ = i;

	ident = getpid() & 0xFFFF;

	hold = 1;
	if (options & F_SO_DEBUG)
		(void)setsockopt(s, SOL_SOCKET, SO_DEBUG, (char *)&hold,
		    sizeof(hold));
	if (options & F_SO_DONTROUTE)
		(void)setsockopt(s, SOL_SOCKET, SO_DONTROUTE, (char *)&hold,
		    sizeof(hold));

	/* record route option */
	if (options & F_RROUTE) {
	        bzero(rspace, sizeof(rspace));
		rspace[0] = IPOPT_NOP;
		rspace[1+IPOPT_OPTVAL] = IPOPT_RR;
		rspace[1+IPOPT_OLEN] = sizeof(rspace)-1;
		rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
		if (setsockopt(s, IPPROTO_IP, IP_OPTIONS, rspace,
		    sizeof(rspace)) < 0) {
			perror("ping: record route");
			exit(2);
		}
	}
	if (options & F_TIMESTAMP) {
	        bzero(rspace, sizeof(rspace));
		rspace[0] = IPOPT_TIMESTAMP;
		rspace[1] = (ts_type==IPOPT_TS_TSONLY ? 40 : 36);
		rspace[2] = 5;
		rspace[3] = ts_type;
		if (ts_type == IPOPT_TS_PRESPEC) {
			int i;
			rspace[1] = 4+nroute*8;
			for (i=0; i<nroute; i++)
				*(__u32*)&rspace[4+i*8] = route[i];
		}
		if (setsockopt(s, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
			rspace[3] = 2;
			if (setsockopt(s, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
				perror("ping: ts option");
				exit(2);
			}
		}
	}
	if (options & F_SOURCEROUTE) {
	        int i;
	        bzero(rspace, sizeof(rspace));
		rspace[0] = IPOPT_NOOP;
		rspace[1+IPOPT_OPTVAL] = (options & F_SO_DONTROUTE) ? IPOPT_SSRR
			: IPOPT_LSRR;
		rspace[1+IPOPT_OLEN] = 3 + nroute*4;
		rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
		for (i=0; i<nroute; i++)
			*(__u32*)&rspace[4+i*4] = route[i];
		
		if (setsockopt(s, IPPROTO_IP, IP_OPTIONS, rspace, 4 + nroute*4) < 0) {
			perror("ping: record route");
			exit(2);
		}
	}

	/*
	 * When pinging the broadcast address, you can get a lot of answers.
	 * Doing something so evil is useful if you are trying to stress the
	 * ethernet, or just want to fill the arp cache to get some stuff for
	 * /etc/ethers.
	 */
	hold = 48 * 1024;
	(void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&hold,
	    sizeof(hold));

	{
		if (setsockopt(s, SOL_SOCKET, SO_BROADCAST,
							&broadcast_pings, sizeof(broadcast_pings)) < 0) {
			perror ("can't set broadcasting");
			exit(2);
		}
        }

	if (moptions & MULTICAST_NOLOOP) {
		if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP,
							&loop, 1) == -1) {
			perror ("can't disable multicast loopback");
			exit(2);
		}
	}
	if (moptions & MULTICAST_TTL) {
		int ittl = ttl;
		if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,
							&ttl, 1) == -1) {
			perror ("can't set multicast time-to-live");
			exit(2);
		}
		if (setsockopt(s, IPPROTO_IP, IP_TTL,
							&ittl, sizeof(ittl)) == -1) {
			perror ("can't set unicast time-to-live");
			exit(2);
		}
	}

	if (to->sin_family == AF_INET) {
		(void)printf("PING %s (%s) ", hostname,
			     inet_ntoa(*(struct in_addr *)&to->sin_addr.s_addr));
		(void)printf("from %s %s: %d data bytes\n",
			     inet_ntoa(*(struct in_addr *)&source.sin_addr.s_addr),
			     device ?: "",
			     datalen);
	} else
		(void)printf("PING %s: %d data bytes\n", hostname, datalen);

	set_signal(SIGINT, finish);
	set_signal(SIGALRM, catcher);

	while (preload--)		/* fire off them quickies */
		pinger();

	if ((options & F_FLOOD) == 0)
		catcher();		/* start things going */

	for (;;) {
		struct sockaddr_in from;
		register int cc;
		int fromlen;

		if (options & F_FLOOD) {
			pinger();

reselect:
			timeout.tv_sec = 0;
			timeout.tv_usec = 10000;
			fdmask = 1 << s;
			if (select(s + 1, (fd_set *)&fdmask, (fd_set *)NULL,
			    (fd_set *)NULL, &timeout) < 1)
				continue;
		}
		fromlen = sizeof(from);
		if ((cc = recvfrom(s, (char *)packet, packlen, 0,
		    (struct sockaddr *)&from, &fromlen)) < 0) {
			if (errno == EINTR)
				continue;
			perror("ping: recvfrom");
			continue;
		}
		if (pr_pack((char *)packet, cc, &from)) {
			if (options & F_FLOOD)
				goto reselect;
			continue;
		}
		if (npackets && nreceived >= npackets)
			break;
	}
	finish();
	/* NOTREACHED */
}

/*
 * catcher --
 *	This routine causes another PING to be transmitted, and then
 * schedules another SIGALRM for 1 second from now.
 * 
 * bug --
 *	Our sense of time will slowly skew (i.e., packets will not be
 * launched exactly at 1-second intervals).  This does not affect the
 * quality of the delay and loss statistics.
 */
void
catcher()
{
	static struct timeval prev;
	struct timeval now;
	long delta;
	int waittime;

	gettimeofday(&now, NULL);
	delta = now.tv_sec - prev.tv_sec;
	if ((unsigned long)delta > 1)
		delta=1;
	delta = delta*1000 + (now.tv_usec - prev.tv_usec)/1000;
	prev = now;

	if (delta > 500)
		pinger();

	if (!npackets || ntransmitted < npackets)
		alarm((u_int)interval);
	else {
		if (nreceived) {
			waittime = 2 * tmax / 1000;
			if (!waittime)
				waittime = 1;
			if (waittime > maxwait)
				waittime = maxwait;
		} else
			waittime = maxwait;

		set_signal(SIGALRM, finish);
		(void)alarm((u_int)waittime);
	}
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
void pinger()
{
	register struct icmphdr *icp;
	register int cc;
	int i;

	icp = (struct icmphdr *)outpack;
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.sequence = ntransmitted++;
	icp->un.echo.id = ident;			/* ID */

	CLR(icp->un.echo.sequence % mx_dup_ck);

	if (timing)
		(void)gettimeofday((struct timeval *)&outpack[8],
		    (struct timezone *)NULL);

	cc = datalen + 8;			/* skips ICMP portion */

	/* compute ICMP checksum here */
	icp->checksum = in_cksum((u_short *)icp, cc);

        do {
		static struct iovec iov = {outpack, 0};
		static struct msghdr m = { &whereto, sizeof(struct sockaddr),
						   &iov, 1, &cmsg, 0, 0 };
		m.msg_controllen = cmsg_len;
		iov.iov_len = cc;
	
		i = sendmsg(s, &m, 0);
	} while (0);

	if (i < 0 || i != cc)  {
		if (i < 0)
			perror("ping: sendto");
		(void)printf("ping: wrote %s %d chars, ret=%d\n",
		    hostname, cc, i);
	}
	if (!(options & F_QUIET) && options & F_FLOOD)
		(void)write(STDOUT_FILENO, &DOT, 1);
}

/*
 * pr_pack --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
int
pr_pack(char *buf, int cc, struct sockaddr_in *from)
{
	struct icmphdr *icp;
	u_char *cp,*dp;
	struct iphdr *ip;
	struct timeval tv, tp;
	long triptime = 0;
	int hlen, dupflag = 0;
	int csfailed;
	int realdatalen = 0;

	(void)gettimeofday(&tv, (struct timezone *)NULL);

	/* Check the IP header */
	ip = (struct iphdr *)buf;
	hlen = ip->ihl*4;
	if (cc < datalen + 8) {
		if (options & F_VERBOSE)
			(void)fprintf(stderr,
			  "ping: packet too short (%d bytes) from %s\n", cc,
			  inet_ntoa(*(struct in_addr *)&from->sin_addr.s_addr));
		if (cc < hlen + 8)
			return 0;
	}

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmphdr *)(buf + hlen);
	csfailed = in_cksum((u_short *)icp, cc);

	if (icp->type == ICMP_ECHOREPLY) {
		if (icp->un.echo.id != ident)
			return 1;			/* 'Twas not our ECHO */
		++nreceived;
		if (timing) {
			memcpy(&tp, (struct timeval *)(icp + 1), sizeof(tp));
			tvsub(&tv, &tp);
			triptime = tv.tv_sec * 10000 + (tv.tv_usec / 100);
			if (!csfailed) {
				tsum += triptime;
				if (triptime < tmin)
					tmin = triptime;
				if (triptime > tmax)
					tmax = triptime;
			}
		}

		if (csfailed) {
			++nchecksum;
			--nreceived;
		} else if (TST(icp->un.echo.sequence % mx_dup_ck)) {
			++nrepeats;
			--nreceived;
			dupflag = 1;
		} else {
			SET(icp->un.echo.sequence % mx_dup_ck);
		}

		if (options & F_QUIET)
			return 0;

		if (options & F_FLOOD) {
			(void)write(STDOUT_FILENO, &BSPACE, 1);
			if (csfailed)
				(void)write(STDOUT_FILENO, "C", 1);
		} else {
			int i;
			(void)printf("%d bytes from %s: icmp_seq=%u", cc,
			   inet_ntoa(*(struct in_addr *)&from->sin_addr.s_addr),
			   icp->un.echo.sequence);
			(void)printf(" ttl=%d", ip->ttl);
			if (timing)
				(void)printf(" time=%ld.%ld ms", triptime/10,
						triptime%10);
			if (dupflag)
				(void)printf(" (DUP!)");
			if (csfailed)
				(void)printf(" (BAD CHECKSUM!)");
			/* check the data */

			cp = (u_char*)(icp + 1);
			dp = &outpack[8];
			realdatalen = datalen - 8;
			if (timing) {
				cp += sizeof(struct timeval);
				dp += sizeof(struct timeval);
				realdatalen -= sizeof(struct timeval);
			}

			for (i = (datalen - realdatalen); i < datalen; ++i, ++cp, ++dp) {

				if (*cp != *dp) {
					printf("\nwrong data byte #%d should be 0x%x but was 0x%x",
					       i, *dp, *cp);
					cp = (u_char*)(icp + 1);
					for (i = 8; i < datalen; ++i, ++cp) {
						if ((i % 32) == 8)
							(void)printf("\n\t");
						(void)printf("%x ", *cp);
					}
					break;
				}
			}
		}
	} else {
	        switch (icp->type) {
		case ICMP_ECHO:
			return 1;
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
			if (options & F_FLOOD)
				return 1;
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
			{
				struct iphdr * iph = (struct  iphdr *)(&icp[1]);
				struct icmphdr *icp1 = (struct icmphdr*)((unsigned char *)iph + iph->ihl*4);
				int error_pkt;
				if (icp1->type != ICMP_ECHO ||
				    iph->saddr != ip->daddr ||
				    icp1->un.echo.id != ident)
					return 1;
				error_pkt = (icp->type != ICMP_REDIRECT &&
					     icp->type != ICMP_SOURCE_QUENCH);
				nerrors+=error_pkt;
				if (options&F_QUIET)
					return !error_pkt;
				if (options & F_FLOOD) {
					if (error_pkt) {
						(void)write(STDOUT_FILENO, &BSPACE, 1);
						(void)write(STDOUT_FILENO, "E", 1);
					}
					return !error_pkt;
				}
				printf("From %s: ",
				       pr_addr(from->sin_addr.s_addr));
				if (csfailed)
					printf("(BAD CHECKSUM)");
				pr_icmph(icp);
				return !error_pkt;
			}
	        default:
			break;
		}
		if (options & F_FLOOD && !(options & (F_VERBOSE|F_QUIET))) {
			if (!csfailed)
				(void)write(STDOUT_FILENO, "!E", 2);
			else
				(void)write(STDOUT_FILENO, "!EC", 3);
			return 0;
		}
		/* We've got something other than an ECHOREPLY */
		if (!(options & F_VERBOSE))
			return 0;
		(void)printf("From %s: ",
			     pr_addr(from->sin_addr.s_addr));
		if (csfailed) {
			printf("(BAD CHECKSUM)");
			return 0;
		}
		pr_icmph(icp);
		return 0;
	}

	pr_options((u_char *)buf + sizeof(struct iphdr), hlen);
	if (!(options & F_FLOOD)) {
		(void)putchar('\n');
		(void)fflush(stdout);
	}
	return 0;
}

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
u_short in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}


/*
 * finish --
 *	Print out statistics, and give up.
 */
void
finish()
{
	(void)signal(SIGINT, SIG_IGN);
	(void)putchar('\n');
	(void)fflush(stdout);
	(void)printf("--- %s ping statistics ---\n", hostname);
	(void)printf("%ld packets transmitted, ", ntransmitted);
	(void)printf("%ld packets received, ", nreceived);
	if (nrepeats)
		(void)printf("+%ld duplicates, ", nrepeats);
	if (nchecksum)
		(void)printf("+%ld corrupted, ", nchecksum);
	if (nerrors)
		(void)printf("+%ld errors, ", nerrors);
	if (ntransmitted) {
		if (nreceived > ntransmitted)
			(void)printf("-- somebody's printing up packets!");
		else
			(void)printf("%d%% packet loss",
			    (int) (((ntransmitted - nreceived) * 100) /
			    ntransmitted));
        }
	(void)putchar('\n');
	if (nreceived && timing)
		(void)printf("round-trip min/avg/max = %ld.%ld/%lu.%ld/%ld.%ld ms\n",
			tmin/10, tmin%10,
			(tsum / (nreceived + nrepeats))/10,
			(tsum / (nreceived + nrepeats))%10,
			tmax/10, tmax%10);

	if (nreceived==0) exit(1);

	exit(0);
}

#ifdef notdef
static char *ttab[] = {
	"Echo Reply",		/* ip + seq + udata */
	"Dest Unreachable",	/* net, host, proto, port, frag, sr + IP */
	"Source Quench",	/* IP */
	"Redirect",		/* redirect type, gateway, + IP  */
	"Echo",
	"Time Exceeded",	/* transit, frag reassem + IP */
	"Parameter Problem",	/* pointer + IP */
	"Timestamp",		/* id + seq + three timestamps */
	"Timestamp Reply",	/* " */
	"Info Request",		/* id + sq */
	"Info Reply"		/* " */
};
#endif

/*
 * pr_icmph --
 *	Print a descriptive string about an ICMP header.
 */
void pr_icmph(struct icmphdr *icp)
{
	switch(icp->type) {
	case ICMP_ECHOREPLY:
		(void)printf("Echo Reply\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_DEST_UNREACH:
		switch(icp->code) {
		case ICMP_NET_UNREACH:
			(void)printf("Destination Net Unreachable\n");
			break;
		case ICMP_HOST_UNREACH:
			(void)printf("Destination Host Unreachable\n");
			break;
		case ICMP_PROT_UNREACH:
			(void)printf("Destination Protocol Unreachable\n");
			break;
		case ICMP_PORT_UNREACH:
			(void)printf("Destination Port Unreachable\n");
			break;
		case ICMP_FRAG_NEEDED:
			(void)printf("Frag needed and DF set (mtu = %lu)\n",
				     ntohl(icp->un.gateway));
			break;
		case ICMP_SR_FAILED:
			(void)printf("Source Route Failed\n");
			break;
		case ICMP_PKT_FILTERED:
			(void)printf("Packet filtered\n");
			break;
		default:
			(void)printf("Dest Unreachable, Bad Code: %d\n",
			    icp->code);
			break;
		}
		if (!(options & F_VERBOSE))
			break;
		/* Print returned IP header information */
		pr_retip((struct iphdr*)(icp + 1));
		break;
	case ICMP_SOURCE_QUENCH:
		(void)printf("Source Quench\n");
		if (!(options & F_VERBOSE))
			break;
		pr_retip((struct iphdr*)(icp + 1));
		break;
	case ICMP_REDIRECT:
		switch(icp->code) {
		case ICMP_REDIR_NET:
			(void)printf("Redirect Network");
			break;
		case ICMP_REDIR_HOST:
			(void)printf("Redirect Host");
			break;
		case ICMP_REDIR_NETTOS:
			(void)printf("Redirect Type of Service and Network");
			break;
		case ICMP_REDIR_HOSTTOS:
			(void)printf("Redirect Type of Service and Host");
			break;
		default:
			(void)printf("Redirect, Bad Code: %d", icp->code);
			break;
		}
		(void)printf("(New addr: %s)\n", pr_addr(icp->un.gateway));
		if (!(options & F_VERBOSE))
			break;
		pr_retip((struct iphdr*)(icp + 1));
		break;
	case ICMP_ECHO:
		(void)printf("Echo Request\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIME_EXCEEDED:
		switch(icp->code) {
		case ICMP_EXC_TTL:
			(void)printf("Time to live exceeded\n");
			break;
		case ICMP_EXC_FRAGTIME:
			(void)printf("Frag reassembly time exceeded\n");
			break;
		default:
			(void)printf("Time exceeded, Bad Code: %d\n",
			    icp->code);
			break;
		}
		if (!(options & F_VERBOSE))
			break;
		pr_retip((struct iphdr*)(icp + 1));
		break;
	case ICMP_PARAMETERPROB:
		(void)printf("Parameter problem: pointer = %d\n",
			     (int)(ntohl(icp->un.gateway)>>24));
		if (!(options & F_VERBOSE))
			break;
		pr_retip((struct iphdr*)(icp + 1));
		break;
	case ICMP_TIMESTAMP:
		(void)printf("Timestamp\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TIMESTAMPREPLY:
		(void)printf("Timestamp Reply\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_INFO_REQUEST:
		(void)printf("Information Request\n");
		/* XXX ID + Seq */
		break;
	case ICMP_INFO_REPLY:
		(void)printf("Information Reply\n");
		/* XXX ID + Seq */
		break;
#ifdef ICMP_MASKREQ
	case ICMP_MASKREQ:
		(void)printf("Address Mask Request\n");
		break;
#endif
#ifdef ICMP_MASKREPLY
	case ICMP_MASKREPLY:
		(void)printf("Address Mask Reply\n");
		break;
#endif
	default:
		(void)printf("Bad ICMP type: %d\n", icp->type);
	}
}

void pr_options(unsigned char * cp, int hlen)
{
	int i, j;
	int optlen, totlen;
	unsigned char * optptr;
	static int old_rrlen;
	static char old_rr[MAX_IPOPTLEN];

	totlen = hlen-sizeof(struct iphdr);
	optptr = cp;

	while (totlen > 0) {
		if (*optptr == IPOPT_EOL)
			break;
		if (*optptr == IPOPT_NOP) {
			totlen--;
			optptr++;
			printf("\nNOP");
			continue;
		}
		cp = optptr;
		optlen = optptr[1];
		if (optlen < 2 || optlen > totlen)
			break;

		switch (*cp) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			printf("\n%cSRR: ", *cp==IPOPT_SSRR ? 'S' : 'L');
			j = *++cp;
			i = *++cp;
			i -= 4;
			cp++;
			if (j > IPOPT_MINOFF) {
				for (;;) {
					__u32 address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						printf("\t0.0.0.0");
					else
						printf("\t%s", pr_addr(address));
					j -= 4;
					putchar('\n');
					if (j <= IPOPT_MINOFF)
						break;
				}
			}
			break;
		case IPOPT_RR:
			j = *++cp;		/* get length */
			i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= IPOPT_MINOFF;
			if (i <= 0)
				continue;
			if (i == old_rrlen
			    && !bcmp((char *)cp, old_rr, i)
			    && !(options & F_FLOOD)) {
				(void)printf("\t(same route)");
				i = ((i + 3) / 4) * 4;
				cp += i;
				break;
			}
			old_rrlen = i;
			bcopy((char *)cp, old_rr, i);
			(void)printf("\nRR: ");
			cp++;
			for (;;) {
				__u32 address;
				memcpy(&address, cp, 4);
				cp += 4;
				if (address == 0)
					printf("\t0.0.0.0");
				else
					printf("\t%s", pr_addr(address));
				i -= 4;
				putchar('\n');
				if (i <= 0)
					break;
			}
			break;
		case IPOPT_TS:
		{
			int stdtime = 0, nonstdtime = 0;
			__u8 flags;
			j = *++cp;		/* get length */
			i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= 5;
			if (i <= 0)
				continue;
			flags = *++cp;
			(void)printf("\nTS: ");
			cp++;
			for (;;) {
				long l;

				if ((flags&0xF) != IPOPT_TS_TSONLY) {
					__u32 address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						printf("\t0.0.0.0");
					else
						printf("\t%s", pr_addr(address));
					i -= 4;
					if (i <= 0)
						break;
				}
				l = *cp++;
				l = (l<<8) + *cp++;
				l = (l<<8) + *cp++;
				l = (l<<8) + *cp++;

				if  (l & 0x80000000) {
					if (nonstdtime==0)
						printf("\t%ld absolute not-standard", l&0x7fffffff);
					else
						printf("\t%ld not-standard", (l&0x7fffffff) - nonstdtime);
					nonstdtime = l&0x7fffffff;
				} else {
					if (stdtime==0)
						printf("\t%ld absolute", l);
					else
						printf("\t%ld", l - stdtime);
					stdtime = l;
				}
				i -= 4;
				putchar('\n');
				if (i <= 0)
					break;
			}
			if (flags>>4)
				printf("Unrecorded hops: %d\n", flags>>4);
			break;
		}
		default:
			(void)printf("\nunknown option %x", *cp);
			break;
		}
		totlen -= optlen;
		optptr += optlen;
	}
}


/*
 * pr_iph --
 *	Print an IP header with options.
 */
void pr_iph(struct iphdr *ip)
{
	int hlen;
	u_char *cp;

	hlen = ip->ihl << 2;
	cp = (u_char *)ip + 20;		/* point to options */

	printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n");
	printf(" %1x  %1x  %02x %04x %04x",
	       ip->version, ip->ihl, ip->tos, ip->tot_len, ip->id);
	printf("   %1x %04x", ((ip->frag_off) & 0xe000) >> 13,
	       (ip->frag_off) & 0x1fff);
	printf("  %02x  %02x %04x", ip->ttl, ip->protocol, ip->check);
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->saddr));
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->daddr));
	printf("\n");
	pr_options(cp, hlen);
}

/*
 * pr_addr --
 *	Return an ascii host address as a dotted quad and optionally with
 * a hostname.
 */
char *
pr_addr(__u32 addr)
{
	struct hostent *hp;
	static char buf[275]; /* hostname + " (xxx.xxx.xxx.xxx)" + "\0" */

	if ((options & F_NUMERIC) ||
	    !(hp = gethostbyaddr((char *)&addr, 4, AF_INET)))
		snprintf(buf, sizeof(buf), "%s", 
			inet_ntoa(*(struct in_addr *)&addr));
	else
		snprintf(buf, sizeof(buf), "%s (%s)", hp->h_name,
			inet_ntoa(*(struct in_addr *)&addr));
	return(buf);
}

/*
 * pr_retip --
 *	Dump some info on a returned (via ICMP) IP packet.
 */
void pr_retip(struct iphdr *ip)
{
	int hlen;
	u_char *cp;

	pr_iph(ip);
	hlen = ip->ihl << 2;
	cp = (u_char *)ip + hlen;

	if (ip->protocol == 6)
		(void)printf("TCP: from port %u, to port %u (decimal)\n",
		    (*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
	else if (ip->protocol == 17)
		(void)printf("UDP: from port %u, to port %u (decimal)\n",
			(*cp * 256 + *(cp + 1)), (*(cp + 2) * 256 + *(cp + 3)));
}

void fill(char *bp, char *patp)
{
	int ii, jj, kk;
	int pat[16];
	char *cp;

	for (cp = patp; *cp; cp++)
		if (!isxdigit(*cp)) {
			(void)fprintf(stderr,
			    "ping: patterns must be specified as hex digits.\n");
			exit(2);
		}
	ii = sscanf(patp,
	    "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
	    &pat[0], &pat[1], &pat[2], &pat[3], &pat[4], &pat[5], &pat[6],
	    &pat[7], &pat[8], &pat[9], &pat[10], &pat[11], &pat[12],
	    &pat[13], &pat[14], &pat[15]);

	if (ii > 0)
		for (kk = 0; kk <= MAXPACKET - (8 + ii); kk += ii)
			for (jj = 0; jj < ii; ++jj)
				bp[jj + kk] = pat[jj];
	if (!(options & F_QUIET)) {
		(void)printf("PATTERN: 0x");
		for (jj = 0; jj < ii; ++jj)
			(void)printf("%02x", bp[jj] & 0xFF);
		(void)printf("\n");
	}
}

void usage(void)
{
	(void)fprintf(stderr,
	    "usage: ping [-LRdfnqrv] [-c count] [-i wait] [-l preload]\n\t[-p pattern] [-s packetsize] [-t ttl] [-I interface address] host\n");
	exit(2);
}
