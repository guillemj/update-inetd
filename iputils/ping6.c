/*
 *
 *	Modified for AF_INET6 by Pedro Roque
 *
 *	<roque@di.fc.ul.pt>
 *
 *	Original copyright notice included bellow
 */

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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>
/* #include <asm/bitops.h> */
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#define clear_bit(n,addr)  (*(addr) &= ~(1 << (n)))
#define set_bit(n,addr)    (*(addr) |= (1 << (n)))
#define test_bit(n,addr)   (*(addr) & (1 << (n)))

#define ICMPV6_FILTER_WILLPASS(type, filterp) \
	(test_bit(type, filterp) == 0)

#define ICMPV6_FILTER_WILLBLOCK(type, filterp) \
	test_bit(type, filterp)

#define ICMPV6_FILTER_SETPASS(type, filterp) \
	clear_bit(type & 0x1f, &((filterp)->data[type >> 5]))

#define ICMPV6_FILTER_SETBLOCK(type, filterp) \
	set_bit(type & 0x1f, &((filterp)->data[type >> 5]))

#define ICMPV6_FILTER_SETPASSALL(filterp) \
	memset(filterp, 0, sizeof(struct icmp6_filter));

#define ICMPV6_FILTER_SETBLOCKALL(filterp) \
	memset(filterp, 0xFF, sizeof(struct icmp6_filter));


#define MAX_IPOPTLEN	4096
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#define ICMP_MINLEN	28

#define	DEFDATALEN	(64 - 8)	/* default data length */
#define	MAXIPLEN	60
#define	MAXICMPLEN	76
#define	MAXPACKET	(128000)/*(65536 - 60 - 8)*//* max packet size */
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

/* multicast options */
int moptions;
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

struct sockaddr_in6 whereto;	/* who to ping */
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
int interval = 1;		/* interval between packets */

/* timing */
int timing;			/* flag to do timing */
long tmin = LONG_MAX;		/* minimum round trip time */
long tmax;			/* maximum round trip time */
unsigned long tsum;			/* sum of all times, for doing average */

static unsigned char cmsgbuf[4096];
static int cmsglen = 0;

static char * pr_addr(struct in6_addr *addr);
static char * pr_addr_n(struct in6_addr *addr);
static int pr_icmph(struct icmp6hdr *icmph);
static void catcher(int);
static void finish(int) __attribute__((noreturn));
static void usage(void) __attribute((noreturn));
static void pinger(void);
static int pr_pack(char *buf, int cc, struct sockaddr_in6 *from);
static void fill(char *bp, char *patp);

struct sockaddr_in6 source;
char *device;

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

static struct in6_addr in6_anyaddr;
static __inline__ int ipv6_addr_any(struct in6_addr *addr)
{
	return (memcmp(addr, &in6_anyaddr, 16) == 0);
}

size_t inet6_srcrt_space(int type, int segments)
{
	if (type != 0 || segments > 24)
		return 0;

	return (sizeof(struct cmsghdr) + sizeof(struct rt0_hdr) +
		segments * sizeof(struct in6_addr));
}

extern struct cmsghdr *	inet6_srcrt_init(void *bp, int type)
{
	struct cmsghdr *cmsg;

	if (type)
	{
		return NULL;
	}

	memset(bp, 0, sizeof(struct cmsghdr) + sizeof(struct rt0_hdr));
	cmsg = (struct cmsghdr *) bp;

	cmsg->cmsg_len = sizeof(struct cmsghdr) + sizeof(struct rt0_hdr);
	cmsg->cmsg_level = SOL_IPV6;
	cmsg->cmsg_type = IPV6_RTHDR;

	return cmsg;
}

int inet6_srcrt_add(struct cmsghdr *cmsg, const struct in6_addr *addr)
{
	struct rt0_hdr *hdr;
	
	hdr = (struct rt0_hdr *) CMSG_DATA(cmsg);

	cmsg->cmsg_len += sizeof(struct in6_addr);
	hdr->rt_hdr.hdrlen += sizeof(struct in6_addr) / 8;

	memcpy(&hdr->addr[hdr->rt_hdr.segments_left++], addr,
	       sizeof(struct in6_addr));
		
	return 0;
}

struct sockaddr_in6 *to;


int main(int argc, char *argv[])
{
	extern int errno, optind;
	extern char *optarg;
	struct timeval timeout;
	int i;
	int ch, fdmask, hold, packlen, preload;
	u_char *datap, *packet;
	char *target;
	struct sockaddr_in6 firsthop;
	int ttl, loop;
	struct icmp6_filter filter;
	int err, csum_offset, sz_opt;

	if ((s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		setuid(getuid());
		perror("ping6: socket");
		exit(1);
	}

	setuid(getuid());

	source.sin6_family = AF_INET6;
	memset(&firsthop, 0, sizeof(firsthop));
	firsthop.sin6_family = AF_INET6;

	preload = 0;
	datap = &outpack[8 + sizeof(struct timeval)];
	while ((ch = getopt(argc, argv, "I:LRc:dfh:i:l:np:qrs:t:v")) != EOF)
		switch(ch) {
		case 'c':
			npackets = atoi(optarg);
			if (npackets <= 0) {
				(void)fprintf(stderr,
				    "ping6: bad number of packets to transmit.\n");
				exit(1);
			}
			break;
		case 'd':
			options |= F_SO_DEBUG;
			break;
		case 'f':
			if (getuid()) {
				(void)fprintf(stderr,
				    "ping6: %s\n", strerror(EPERM));
				exit(1);
			}
			options |= F_FLOOD;
			setbuf(stdout, (char *)NULL);
			break;
		case 'i':		/* wait between sending packets */
			interval = atoi(optarg);
			if (interval <= 0) {
				(void)fprintf(stderr,
				    "ping6: bad timing interval.\n");
				exit(1);
			}
			options |= F_INTERVAL;
			break;
		case 'l':
			preload = atoi(optarg);
			if (preload < 0) {
				(void)fprintf(stderr,
				    "ping6: bad preload value.\n");
				exit(1);
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
			options |= F_RROUTE;
			break;
		case 'r':
			options |= F_SO_DONTROUTE;
			break;
		case 's':		/* size of packet to send */
			datalen = atoi(optarg);
			if (datalen > MAXPACKET) {
				(void)fprintf(stderr,
				    "ping6: packet size too large.\n");
				exit(1);
			}
			if (datalen <= 0) {
				(void)fprintf(stderr,
				    "ping6: illegal packet size.\n");
				exit(1);
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
				exit(1);
			}
			ttl = i;
			break;
		case 'I':
			moptions |= MULTICAST_IF;
			if (strchr(optarg, ':')) {
				if (inet_pton(AF_INET6, optarg, (char*)&source.sin6_addr) <= 0) {
					fprintf(stderr, "Invalid source address %s\n", optarg);
					exit(1);
				}
			} else {
				struct ifreq ifr;
				struct cmsghdr *cmsg;
				struct in6_pktinfo *ipi;
				
				memset(&ifr, 0, sizeof(ifr));
				strncpy(ifr.ifr_name, optarg, 15);
				if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
					fprintf(stderr, "Unknown iface %s\n", optarg);
					exit(1);
				}
				cmsg = (struct cmsghdr*)cmsgbuf;
				cmsglen += CMSG_SPACE(sizeof(*ipi));
				cmsg->cmsg_len = CMSG_LEN(sizeof(*ipi));
				cmsg->cmsg_level = SOL_IPV6;
				cmsg->cmsg_type = IPV6_PKTINFO;
				
				ipi = (struct in6_pktinfo*)CMSG_DATA(cmsg);
				memset(ipi, 0, sizeof(*ipi));
				ipi->ipi6_ifindex = ifr.ifr_ifindex;
				device = optarg;
			}
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;
	
	while (argc > 1)
	{
		struct cmsghdr *srcrt = NULL;
		struct in6_addr addr;

		if (srcrt == NULL)
		{
			int space;
			
			space = inet6_srcrt_space(IPV6_SRCRT_TYPE_0, argc - 1);

			if (space == 0)
			{
				fprintf(stderr, "srcrt_space failed\n");
			}
			if (space + cmsglen > sizeof(cmsgbuf))
			{
				fprintf(stderr, "no room for options\n");
				exit(1);
			}

			srcrt = (struct cmsghdr*)(cmsgbuf+cmsglen);
			cmsglen += CMSG_ALIGN(space);
			inet6_srcrt_init(srcrt, IPV6_SRCRT_TYPE_0);
		}

		target = *argv;

		if (inet_pton(AF_INET6, target, &addr) <= 0)
		{
			struct hostent *hp;

			hp = gethostbyname2(target, AF_INET6);

			if (hp == NULL)
			{
				fprintf(stderr, "unknown host\n");
				exit(1);
			}

			memcpy(&addr, hp->h_addr_list[0], hp->h_length);
		}

		inet6_srcrt_add(srcrt, &addr);
		if (ipv6_addr_any(&firsthop.sin6_addr))
			memcpy(&firsthop.sin6_addr, &addr, 16);

		argv++;
		argc--;
	}

	if (argc != 1)
		usage();
	target = *argv;

	memset(&whereto, 0, sizeof(struct sockaddr_in6));
	to = &whereto;
	to->sin6_family = AF_INET6;
	to->sin6_port = htons(IPPROTO_ICMPV6);

	if (inet_pton(AF_INET6, target, &to->sin6_addr) <= 0)
	{
		struct hostent *hp;

		hp = gethostbyname2(target, AF_INET6);

		if (hp == NULL)
		{
			fprintf(stderr, "unknown host\n");
			exit(1);
		}
		
		memcpy(&to->sin6_addr, hp->h_addr_list[0],
		       hp->h_length);
	}
	if (ipv6_addr_any(&firsthop.sin6_addr))
		memcpy(&firsthop.sin6_addr, &to->sin6_addr, 16);

	hostname = target;

	if (options & F_FLOOD && options & F_INTERVAL) {
		(void)fprintf(stderr,
		    "ping6: -f and -i incompatible options.\n");
		exit(1);
	}

	if (ipv6_addr_any(&source.sin6_addr)) {
		int alen;
		int probe_fd = socket(AF_INET6, SOCK_DGRAM, 0);

		if (probe_fd < 0) {
			perror("socket");
			exit(1);
		}
		if (device) {
			struct ifreq ifr;
			strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
			if (setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == -1)
				perror("WARNING: interface is ignored");
		}
		firsthop.sin6_port = htons(1025);
		if (connect(probe_fd, (struct sockaddr*)&firsthop, sizeof(firsthop)) == -1) {
			perror("connect");
			exit(1);
		}
		alen = sizeof(source);
		if (getsockname(probe_fd, (struct sockaddr*)&source, &alen) == -1) {
			perror("getsockname");
			exit(1);
		}
		source.sin6_port = 0;
		close(probe_fd);
	}

	if (bind(s, (struct sockaddr*)&source, sizeof(source)) == -1) {
		perror("bind icmp socket");
		exit(1);
	}

	if (datalen >= 8 + sizeof(struct timeval))	/* can we time transfer */
		timing = 1;
	packlen = datalen + MAXIPLEN + MAXICMPLEN;
	if (!(packet = (u_char *)malloc((u_int)packlen))) {
		(void)fprintf(stderr, "ping6: out of memory.\n");
		exit(1);
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

	/*
	 * When pinging the broadcast address, you can get a lot of answers.
	 * Doing something so evil is useful if you are trying to stress the
	 * ethernet, or just want to fill the arp cache to get some stuff for
	 * /etc/ethers.
	 */
	hold = 48 * 1024;
	(void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&hold,
	    sizeof(hold));

	csum_offset = 2;
	sz_opt = sizeof(int);

	err = setsockopt(s, SOL_RAW, IPV6_CHECKSUM, &csum_offset, sz_opt);
	if (err < 0)
	{
		perror("setsockopt(RAW_CHECKSUM)");
		exit(1);
	}

	/*
	 *	select icmp echo reply as icmp type to receive
	 */

	ICMPV6_FILTER_SETBLOCKALL(&filter);

	ICMPV6_FILTER_SETPASS(ICMPV6_DEST_UNREACH, &filter);
	ICMPV6_FILTER_SETPASS(ICMPV6_PKT_TOOBIG, &filter);
	ICMPV6_FILTER_SETPASS(ICMPV6_TIME_EXCEED, &filter);
	ICMPV6_FILTER_SETPASS(ICMPV6_PARAMPROB, &filter);

	ICMPV6_FILTER_SETPASS(ICMPV6_ECHO_REPLY, &filter);

	err = setsockopt(s, SOL_ICMPV6, ICMPV6_FILTER, &filter,
			 sizeof(struct icmp6_filter));

	if (err < 0)
	{
		perror("setsockopt(ICMPV6_FILTER)");
		exit(1);
	}

	if (moptions & MULTICAST_NOLOOP) {
		if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
							&loop, sizeof(loop)) == -1) {
			perror ("can't disable multicast loopback");
			exit(92);
		}
	}
	if (moptions & MULTICAST_TTL) {
		if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
							&ttl, sizeof(ttl)) == -1) {
			perror ("can't set multicast time-to-live");
			exit(93);
		}
		if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
							&ttl, sizeof(ttl)) == -1) {
			perror ("can't set unicast time-to-live");
			exit(93);
		}
	}

	printf("PING %s(%s) ", hostname, pr_addr(&to->sin6_addr));
	if (device || (options&F_NUMERIC)) {
		printf("from %s %s: ",
		       pr_addr_n(&source.sin6_addr), device ? : "");
	}
	printf("%d data bytes\n", datalen);

	(void)signal(SIGINT, finish);
	(void)signal(SIGALRM, catcher);

	while (preload--)		/* fire off them quickies */
		pinger();

	if ((options & F_FLOOD) == 0)
		catcher(0);		/* start things going */

	for (;;) {
		struct sockaddr_in6 from;
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
			perror("ping6: recvfrom");
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
	finish(0);
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
void catcher(int sig)
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

	(void)signal(SIGALRM, catcher);
	if (!npackets || ntransmitted < npackets)
		alarm((u_int)interval);
	else {
		if (nreceived) {
			waittime = 2 * tmax / 1000;
			if (!waittime)
				waittime = 1;
		} else
			waittime = MAXWAIT;
		(void)signal(SIGALRM, finish);
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
void pinger(void)
{
	struct icmp6hdr *icmph;
	register int cc;
	int i;

	icmph = (struct icmp6hdr *)outpack;
	memset(icmph, 0, sizeof(struct icmp6hdr));
	icmph->icmp6_type = ICMPV6_ECHO_REQUEST;
	icmph->icmp6_sequence = ntransmitted++;
	icmph->icmp6_identifier = ident;

	CLR(icmph->icmp6_sequence % mx_dup_ck);

	if (timing)
		(void)gettimeofday((struct timeval *)&outpack[8],
		    (struct timezone *)NULL);

	cc = datalen + 8;			/* skips ICMP portion */

	if (cmsglen == 0)
	{
		i = sendto(s, (char *)outpack, cc, 0,
			   (struct sockaddr *) &whereto,
			   sizeof(struct sockaddr_in6));
	}
	else
	{
		struct msghdr mhdr;
		struct iovec iov;

		iov.iov_len  = cc;
		iov.iov_base = outpack;

		mhdr.msg_name = &whereto;
		mhdr.msg_namelen = sizeof(struct sockaddr_in6);
		mhdr.msg_iov = &iov;
		mhdr.msg_iovlen = 1;
		mhdr.msg_control = cmsgbuf;
		mhdr.msg_controllen = cmsglen;

		i = sendmsg(s, &mhdr, 0);
	}

	if (i < 0 || i != cc)  {
		if (i < 0)
			perror("ping6: sendto");
		(void)printf("ping6: wrote %s %d chars, ret=%d\n",
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
int pr_pack(char *buf, int cc, struct sockaddr_in6 *from)
{
	struct icmp6hdr *icmph;
	u_char *cp,*dp;
	struct timeval tv, *tp;
	long triptime = 0;
	int dupflag = 0;
	int realdatalen = 0;

	(void)gettimeofday(&tv, (struct timezone *)NULL);


	/* Now the ICMP part */

	icmph = (struct icmp6hdr *) buf;

	if (icmph->icmp6_type == ICMPV6_ECHO_REPLY) {
		if (icmph->icmp6_identifier != ident)
			return 1;			/* 'Twas not our ECHO */
		++nreceived;
		if (timing) {

			tp = (struct timeval *)(icmph + 1);

			tvsub(&tv, tp);
			triptime = tv.tv_sec * 10000 + (tv.tv_usec / 100);
			tsum += triptime;
			if (triptime < tmin)
				tmin = triptime;
			if (triptime > tmax)
				tmax = triptime;
		}

		if (TST(icmph->icmp6_sequence % mx_dup_ck)) {
			++nrepeats;
			--nreceived;
			dupflag = 1;
		} else {
			SET(icmph->icmp6_sequence % mx_dup_ck);
			dupflag = 0;
		}

		if (options & F_QUIET)
			return 0;

		if (options & F_FLOOD)
			(void)write(STDOUT_FILENO, &BSPACE, 1);
		else {
			int i;
			(void)printf("%d bytes from %s: icmp_seq=%u", cc,
				     pr_addr(&from->sin6_addr),
				     icmph->icmp6_sequence);

			if (timing)
				(void)printf(" time=%ld.%ld ms", triptime/10,
						triptime%10);
			if (dupflag)
				(void)printf(" (DUP!)");

			/* check the data */
                        cp = ((u_char*)(icmph + 1));
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
					cp = (u_char*)(icmph + 1);
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
		struct ipv6hdr *iph1 = (struct ipv6hdr*)(icmph+1);

		if (memcmp(&iph1->daddr, &to->sin6_addr, 16))
			return 1;

		if (iph1->nexthdr == IPPROTO_ICMPV6) {
			struct icmp6hdr *icmph1 = (struct icmp6hdr *)(iph1+1);
			if (icmph1->icmp6_type != ICMPV6_ECHO_REQUEST ||
			    icmph1->icmp6_identifier != ident)
				return 1;
			if (options & F_FLOOD) {
				(void)write(STDOUT_FILENO, "E", 1);
				return 0;
			}
			(void)printf("From %s: ",
				     pr_addr(&from->sin6_addr));
		} else {
			/* We've got something other than an ECHOREPLY */
			if (!(options & F_VERBOSE))
				return 1;
			(void)printf("From %s: ",
				     pr_addr(&from->sin6_addr));
		}
		pr_icmph(icmph);
	}

	if (!(options & F_FLOOD)) {
		(void)putchar('\n');
		(void)fflush(stdout);
	}
	return 0;
}


int pr_icmph(struct icmp6hdr *icmph)
{
	switch(icmph->icmp6_type) {
	case ICMPV6_DEST_UNREACH:
		printf("Destination unreachable: ");
		switch (icmph->icmp6_code) {
		case ICMPV6_NOROUTE:
			printf("No route");
			break;
		case ICMPV6_ADM_PROHIBITED:
			printf("Administratively prohibited");
			break;
		case ICMPV6_NOT_NEIGHBOUR:
			printf("Not neighbour");
			break;
		case ICMPV6_ADDR_UNREACH:
			printf("Address unreachable");
			break;
		case ICMPV6_PORT_UNREACH:
			printf("Port unreachable");
			break;
		default:	
			printf("Unknown code %d", icmph->icmp6_code);
			break;
		}
		break;
	case ICMPV6_PKT_TOOBIG:
		printf("Packet too big: mtu=%ld", ntohl(icmph->icmp6_hop_limit));
		if (icmph->icmp6_code)
			printf(", code=%d", icmph->icmp6_code);
		break;
	case ICMPV6_TIME_EXCEED:
		printf("Time exceeded: ");
		if (icmph->icmp6_code == ICMPV6_EXC_HOPLIMIT)
			printf("Hop limit");
		else if (icmph->icmp6_code == ICMPV6_EXC_FRAGTIME)
			printf("Defragmentation failure");
		else
			printf("code %d", icmph->icmp6_code);
		break;
	case ICMPV6_PARAMPROB:
		printf("Parameter problem: ");
		if (icmph->icmp6_code == ICMPV6_HDR_FIELD)
			printf("Wrong header field ");
		else if (icmph->icmp6_code == ICMPV6_UNK_NEXTHDR)
			printf("Unknown header ");
		else if (icmph->icmp6_code == ICMPV6_UNK_OPTION)
			printf("Unknown option ");
		else
			printf("code %d ", icmph->icmp6_code);
		printf ("at %ld", ntohl(icmph->icmp6_pointer));
		break;
	case ICMPV6_ECHO_REQUEST:
		printf("Echo request");
		break;
	case ICMPV6_ECHO_REPLY:
		printf("Echo reply");
		break;
	case ICMPV6_MGM_QUERY:
		printf("MLD Query");
		break;
	case ICMPV6_MGM_REPORT:
		printf("MLD Report");
		break;
	case ICMPV6_MGM_REDUCTION:
		printf("MLD Reduction");
		break;
	default:
		printf("unknown icmp type");
		
	}
	return 0;
}

/*
 * finish --
 *	Print out statistics, and give up.
 */
void finish(int sig)
{
	(void)signal(SIGINT, SIG_IGN);
	(void)putchar('\n');
	(void)fflush(stdout);
	(void)printf("--- %s ping6 statistics ---\n", hostname);
	(void)printf("%ld packets transmitted, ", ntransmitted);
	(void)printf("%ld packets received, ", nreceived);
	if (nrepeats)
		(void)printf("+%ld duplicates, ", nrepeats);
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
 * pr_addr --
 *	Return an ascii host address as a dotted quad and optionally with
 * a hostname.
 */
char * pr_addr(struct in6_addr *addr)
{
	static char str[80];
	struct hostent *hp = NULL;

	if (!(options&F_NUMERIC))
		hp = gethostbyaddr((__u8*)addr, sizeof(struct in6_addr), AF_INET6);

	if (hp == NULL)
	{
		inet_ntop(AF_INET6, addr, str, 80);
		return str;
	}

	return hp->h_name;
}

char * pr_addr_n(struct in6_addr *addr)
{
	static char str[80];
	inet_ntop(AF_INET6, addr, str, 80);
	return str;
}

void fill(char *bp, char *patp)
{
	int ii, jj, kk;
	int pat[16];
	char *cp;

	for (cp = patp; *cp; cp++)
		if (!isxdigit(*cp)) {
			fprintf(stderr, "ping6: patterns must be specified as hex digits.\n");
			exit(1);
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
	fprintf(stderr,
		"usage: ping6 [-LRdfnqrv] [-c count] [-i wait] [-l preload]\n\t[-p pattern] [-s packetsize] [-t ttl] [-I interface address] host\n");
	exit(1);
}
