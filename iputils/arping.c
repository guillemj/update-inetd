/*
 * arping.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <sys/uio.h>

#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void usage(void) __attribute__((noreturn));

char *device;
int ifindex;
char *source;
struct in_addr src, dst;
char *target;
int dad, unsolicited, advert;
int quite;
int count=-1;
int timeout;
int unicasting;
int s;

struct sockaddr_ll me;
struct sockaddr_ll he;

struct timeval start, last;

int sent, brd_sent;
int received, brd_recv, req_recv;

#define MS_TDIFF(tv1,tv2) ( ((tv1).tv_sec-(tv2).tv_sec)*1000 + \
			   ((tv1).tv_usec-(tv2).tv_usec)/1000 )

void usage(void)
{
	fprintf(stderr,
		"Usage: arping [-DUA] [-c count] [-w timeout] [-I device] [-s source] destination\n");
	exit(1);
}

void set_signal(int signo, void (*handler)(void))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = (void (*)(int))handler;
	sa.sa_flags = SA_RESTART;
	sigaction(signo, &sa, NULL);
}

int send_pack(int s, struct in_addr src, struct in_addr dst,
	      struct sockaddr_ll *ME, struct sockaddr_ll *HE)
{
	int err;
	struct timeval now;
	unsigned char buf[256];
	struct arphdr *ah = (struct arphdr*)buf;
	unsigned char *p = (unsigned char *)(ah+1);

	ah->ar_hrd = htons(ME->sll_hatype);
	if (ah->ar_hrd == htons(ARPHRD_FDDI))
		ah->ar_hrd = htons(ARPHRD_ETHER);
	ah->ar_pro = htons(ETH_P_IP);
	ah->ar_hln = ME->sll_halen;
	ah->ar_pln = 4;
	ah->ar_op  = advert ? htons(ARPOP_REPLY) : htons(ARPOP_REQUEST);

	memcpy(p, &ME->sll_addr, ah->ar_hln);
	p+=ME->sll_halen;

	memcpy(p, &src, 4);
	p+=4;

	if (advert)
		memcpy(p, &ME->sll_addr, ah->ar_hln);
	else
		memcpy(p, &HE->sll_addr, ah->ar_hln);
	p+=ah->ar_hln;

	memcpy(p, &dst, 4);
	p+=4;

	gettimeofday(&now, NULL);
	err = sendto(s, buf, p-buf, 0, (struct sockaddr*)HE, sizeof(*HE));
	if (err == p-buf) {
		last = now;
		sent++;
		if (!unicasting)
			brd_sent++;
	}
	return err;
}

void finish()
{
	if (!quite) {
		printf("Sent %d probes (%d broadcast(s))\n", sent, brd_sent);
		printf("Received %d response(s)", received);
		if (brd_recv || req_recv) {
			printf(" (");
			if (req_recv)
				printf("%d request(s)", req_recv);
			if (brd_recv)
				printf("%s%d broadcast(s)",
				       req_recv ? ", " : "",
				       brd_recv);
			printf(")");
		}
		printf("\n");
		fflush(stdout);
	}
	exit(dad && received);
}

void catcher()
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	if (start.tv_sec==0)
		start = tv;

	if (count-- == 0 || (timeout && MS_TDIFF(tv,start) > timeout*1000 + 500))
		finish();

	if (last.tv_sec==0 || MS_TDIFF(tv,last) > 500) {
		send_pack(s, src, dst, &me, &he);
		if (count == 0 && unsolicited)
			finish();
	}
	alarm(1);
}

void print_hex(unsigned char *p, int len)
{
	int i;
	for (i=0; i<len; i++) {
		printf("%02X", p[i]);
		if (i != len-1)
			printf(":");
	}
}

int recv_pack(unsigned char *buf, int len, struct sockaddr_ll *FROM)
{
	struct timeval tv;
	struct arphdr *ah = (struct arphdr*)buf;
	unsigned char *p = (unsigned char *)(ah+1);
	struct in_addr src_ip, dst_ip;

	gettimeofday(&tv, NULL);

	/* Filter out wildd packets */
	if (FROM->sll_pkttype != PACKET_HOST &&
	    FROM->sll_pkttype != PACKET_BROADCAST &&
	    FROM->sll_pkttype != PACKET_MULTICAST)
		return 0;

	/* Only these types are recognised */
	if (ah->ar_op != htons(ARPOP_REQUEST) &&
	    ah->ar_op != htons(ARPOP_REPLY))
		return 0;

	/* ARPHRD check and this fucking FDDI hack here :-( */
	if (ah->ar_hrd != htons(FROM->sll_hatype) &&
	    (FROM->sll_hatype != ARPHRD_FDDI || ah->ar_hrd != htons(ARPHRD_ETHER)))
		return 0;

	/* Protocol must be IP. */
	if (ah->ar_pro != htons(ETH_P_IP))
		return 0;
	if (ah->ar_pln != 4)
		return 0;
	if (ah->ar_hln != me.sll_halen)
		return 0;
	if (len < sizeof(*ah) + 2*(4 + ah->ar_hln))
		return 0;
	memcpy(&src_ip, p+ah->ar_hln, 4);
	memcpy(&dst_ip, p+ah->ar_hln+4+ah->ar_hln, 4);
	if (!dad) {
		if (src_ip.s_addr != dst.s_addr)
			return 0;
		if (src.s_addr != dst_ip.s_addr)
			return 0;
		if (memcmp(p+ah->ar_hln+4, &me.sll_addr, ah->ar_hln))
			return 0;
	} else {
		/* DAD packet was:
		   src_ip = 0 (or some src)
		   src_hw = ME
		   dst_ip = tested address
		   dst_hw = <unspec>

		   We fail, if receive request/reply with:
		   src_ip = tested_address
		   src_hw != ME
		   if src_ip in request was not zero, check
		   also that it matches to dst_ip, otherwise
		   dst_ip/dst_hw do not matter.
		 */
		if (src_ip.s_addr != dst.s_addr)
			return 0;
		if (memcmp(p, &me.sll_addr, me.sll_halen) == 0)
			return 0;
		if (src.s_addr && src.s_addr != dst_ip.s_addr)
			return 0;
	}
	if (!quite) {
		int s_printed = 0;
		printf("%s ", FROM->sll_pkttype==PACKET_HOST ? "Unicast" : "Broadcast");
		printf("%s from ", ah->ar_op == htons(ARPOP_REPLY) ? "reply" : "request");
		printf("%s [", inet_ntoa(src_ip));
		print_hex(p, ah->ar_hln);
		printf("] ");
		if (dst_ip.s_addr != src.s_addr) {
			printf("for %s ", inet_ntoa(dst_ip));
			s_printed = 1;
		}
		if (memcmp(p+ah->ar_hln+4, me.sll_addr, ah->ar_hln)) {
			if (!s_printed)
				printf("for ");
			printf("[");
			print_hex(p+ah->ar_hln+4, ah->ar_hln);
			printf("]");
		}
		if (last.tv_sec) {
			long usecs = (tv.tv_sec-last.tv_sec) * 1000000 +
				tv.tv_usec-last.tv_usec;
			long msecs = (usecs+500)/1000;
			usecs -= msecs*1000 - 500;
			printf(" %ld.%03ldms\n", msecs, usecs);
		} else {
			printf(" UNSOLICITED?\n");
		}
		fflush(stdout);
	}
	received++;
	if (FROM->sll_pkttype != PACKET_HOST)
		brd_recv++;
	if (ah->ar_op == htons(ARPOP_REQUEST))
		req_recv++;
	if (dad)
		finish();
	memcpy(he.sll_addr, p, me.sll_halen);
	unicasting=1;
	return 1;
}

int
main(int argc, char **argv)
{
	int ch;
	uid_t uid = getuid();

	if ((s = socket(PF_PACKET, SOCK_DGRAM, 0)) < 0) {
		setuid(uid);
		perror("arping: socket");
		exit(1);
	}
	setuid(uid);

	while ((ch = getopt(argc, argv, "DUAqc:w:s:I:")) != EOF) {
		switch(ch) {
		case 'D':
			dad++;
			break;
		case 'U':
			unsolicited++;
			break;
		case 'A':
			advert++;
			unsolicited++;
			break;
		case 'q':
			quite++;
			break;
		case 'c':
			count = atoi(optarg);
			break;
		case 'w':
			timeout = atoi(optarg);
			break;
		case 'I':
			if (1) {
				struct ifreq ifr;
				memset(&ifr, 0, sizeof(ifr));
				device = optarg;
				strncpy(ifr.ifr_name, optarg, 15);
				if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
					fprintf(stderr, "arping: unknown iface %s\n", optarg);
					exit(1);
				}
				ifindex = ifr.ifr_ifindex;

				if (ioctl(s, SIOCGIFFLAGS, (char*)&ifr)) {
					perror("ioctl(SIOCGIFFLAGS)");
					exit(1);
				}
				if (!(ifr.ifr_flags&IFF_UP)) {
					if (!quite)
						printf("Interface \"%s\" is down\n", device);
					exit(1);
				}
				if (ifr.ifr_flags&(IFF_NOARP|IFF_LOOPBACK)) {
					if (!quite)
						printf("Interface \"%s\" is not ARPable\n", device);
					exit(dad?0:1);
				}
			}
			break;
		case 's':
			source = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc != 1)
		usage();

	target = *argv;

	if (device == NULL) {
		fprintf(stderr, "arping: device (option -I) is required\n");
		usage();
	}

	if (inet_aton(target, &dst) != 1) {
		struct hostent *hp;
		hp = gethostbyname2(target, AF_INET);
		if (!hp) {
			fprintf(stderr, "arping: unknown host %s\n", target);
			exit(1);
		}
		memcpy(&dst, hp->h_addr, 4);
	}

	if (source && inet_aton(source, &src) != 1) {
		fprintf(stderr, "arping: invalid source %s\n", source);
		exit(1);
	}

	if (!dad && unsolicited && src.s_addr == 0)
		src = dst;
	
	if (!dad || src.s_addr) {
		struct sockaddr_in saddr;
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);

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
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		if (src.s_addr) {
			saddr.sin_addr = src;
			if (bind(probe_fd, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
				perror("bind");
				exit(1);
			}
		} else if (!dad) {
			int on = 1;
			int alen = sizeof(saddr);

			saddr.sin_port = htons(1025);
			saddr.sin_addr = dst;

			if (setsockopt(probe_fd, SOL_SOCKET, SO_DONTROUTE, (char*)&on, sizeof(on)) == -1)
				perror("WARNING: setsockopt(SO_DONTROUTE)");
			if (connect(probe_fd, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
				perror("connect");
				exit(1);
			}
			if (getsockname(probe_fd, (struct sockaddr*)&saddr, &alen) == -1) {
				perror("getsockname");
				exit(1);
			}
			src = saddr.sin_addr;
		}
		close(probe_fd);
	};

	me.sll_family = AF_PACKET;
	me.sll_ifindex = ifindex;
	me.sll_protocol = htons(ETH_P_ARP);
	if (bind(s, (struct sockaddr*)&me, sizeof(me)) == -1) {
		perror("bind");
		exit(1);
	}

	if (1) {
		int alen = sizeof(me);
		if (getsockname(s, (struct sockaddr*)&me, &alen) == -1) {
			perror("getsockname");
			exit(1);
		}
	}
	if (me.sll_halen == 0) {
		if (!quite)
			printf("Interface \"%s\" is not ARPable (no ll address)\n", device);
		exit(dad?0:1);
	}

	he = me;
	memset(he.sll_addr, -1, he.sll_halen);

	if (!quite) {
		printf("ARPING %s ", inet_ntoa(dst));
		printf("from %s %s\n",  inet_ntoa(src), device ? : "");
	}

	if (!src.s_addr && !dad) {
		fprintf(stderr, "arping: no source address in not-DAD mode\n");
		exit(1);
	}

	set_signal(SIGINT, finish);
	set_signal(SIGALRM, catcher);

	catcher();

	while(1) {
		sigset_t sset, osset;
		char packet[4096];
		struct sockaddr_ll from;
		int alen = sizeof(from);
		int cc;

		if ((cc = recvfrom(s, packet, sizeof(packet), 0,
				   (struct sockaddr *)&from, &alen)) < 0) {
			perror("arping: recvfrom");
			continue;
		}
		sigemptyset(&sset);
		sigaddset(&sset, SIGALRM);
		sigaddset(&sset, SIGINT);
		sigprocmask(SIG_BLOCK, &sset, &osset);
		recv_pack(packet, cc, &from);
		sigprocmask(SIG_SETMASK, &osset, NULL);
	}
}


