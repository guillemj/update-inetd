/*
 * netstat	This file contains an implementation of the command
 *		that helps in debugging the networking modules.
 *
 * NET-TOOLS	A collection of programs that form the base set of the
 *		NET-3 Networking Distribution for the LINUX operating
 *		system.
 *
 * Version:	netstat 1.26 (1998-03-02)
 *
 * Authors:	Fred Baumgarten, <dc6iq@insu1.etec.uni-karlsruhe.de>
 *		Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 *		Phil Packer, <pep@wicked.demon.co.uk>
 *		Johannes Stille, <johannes@titan.os.open.de>
 *		Bernd Eckenfels, <net-tools@lina.inka.de>
 *		Phil Blundell <philb@gnu.ai.mit.edu>
 *
 * Tuned for NET3 by:
 *		Alan Cox, <A.Cox@swansea.ac.uk>
 *
 *		Copyright (c) 1993  Fred Baumgarten
 *
 * Modified:
 *
 *960116 {1.01} Bernd Eckenfels:	verbose, cleanups
 *960204 {1.10} Bernd Eckenfels:	aftrans, usage, new route_info, 
 *					DLFT_AF
 *960204 {1.11} Bernd Eckenfels:	netlink support
 *960204 {1.12} Bernd Eckenfels:	route_init()
 *960215 {1.13} Bernd Eckenfels:	netlink_print honors HAVE_
 *960217 {1.14} Bernd Eckenfels:	masq_info from Jos Vos and 
 *					ax25_info from Jonathan Naylor.
 *960218 {1.15} Bernd Eckenfels:	ipx_info rewritten, -e for tcp/ipx
 *960220 {1.16} Bernd Eckenfels:	minor output reformats, -a for -x
 *960221 {1.17} Bernd Eckenfels:	route_init->getroute_init
 *960426 {1.18} Bernd Eckenfels:	new RTACTION, SYM/NUM, FIB/CACHE
 *960517 {1.19} Bernd Eckenfels:	usage() spelling fix and --unix inode, 
 *					':' is part of sock_addr for --inet
 *960822 {x.xx} Frank Strauss:          INET6 support
 *
 *970406 {1.33} Philip Copeland		Added snmp reporting support module -s
 *					code provided by Andi Kleen
 *					(relly needs to be kernel hooked but 
 *					this will do in the meantime)
 *					minor header file misplacement tidy up.
 *
 *		This program is free software; you can redistribute it
 *		and/or  modify it under  the terms of  the GNU General
 *		Public  License as  published  by  the  Free  Software
 *		Foundation;  either  version 2 of the License, or  (at
 *		your option) any later version.
 *
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include "net-support.h"
#include "pathnames.h"
#include "version.h"
#include "config.h"
#include "net-locale.h"
#include "sockets.h"
#include "interface.h"

/* prototypes for statistics.c */
void parsesnmp(void);
void inittab(void);

typedef enum {
  SS_FREE = 0,                          /* not allocated                */
  SS_UNCONNECTED,                       /* unconnected to any socket    */
  SS_CONNECTING,                        /* in process of connecting     */
  SS_CONNECTED,                         /* connected to socket          */
  SS_DISCONNECTING                      /* in process of disconnecting  */
} socket_state;

#define SO_ACCEPTCON    (1<<16)         /* performed a listen           */
#define SO_WAITDATA     (1<<17)         /* wait data to read            */
#define SO_NOSPACE      (1<<18)         /* no space to write            */

#define DFLT_AF "inet"

#define FEATURE_NETSTAT
#include "lib/net-features.h"

char *Release   = RELEASE,
     *Version   = "netstat 1.26 (1998-03-02)",
     *Signature = "Fred Baumgarten <dc6iq@insu1.etec.uni-karlsruhe.de> and Alan Cox.";


#define E_READ  -1
#define E_IOCTL -3

int flag_nlp = 0;
int flag_int = 0;
int flag_rou = 0;
int flag_mas = 0;

int flag_all = 0;
int flag_cnt = 0;
int flag_deb = 0;
int flag_not = 0;
int flag_cf  = 0;
int flag_opt = 0;
int flag_raw = 0;
int flag_tcp = 0;
int flag_udp = 0;
int flag_rom = 0;
int flag_exp = 1;
int flag_arg = 0;
int flag_ver = 0;

FILE *procinfo;

#define INFO_GUTS1(file,name,proc)			\
  char buffer[8192];					\
  int lnr = 0;						\
							\
  procinfo = fopen((file), "r");			\
  if (procinfo == NULL) {				\
    if (errno != ENOENT) {				\
      perror((file));					\
      return(-1);					\
    }							\
    if (flag_arg || flag_ver)				\
      ESYSNOT("netstat", (name));			\
    if (flag_arg)					\
      return(1);					\
    else						\
      return(0);					\
  }							\
							\
  do {							\
    if (fgets(buffer, sizeof(buffer), procinfo))	\
      (proc)(lnr++, buffer);				\
  } while (!feof(procinfo));				\
  fclose(procinfo);

#if HAVE_AFINET6
#define INFO_GUTS2(file,proc)				\
  lnr = 0;						\
  procinfo = fopen((file), "r");		       	\
  if (procinfo != NULL) {				\
    fgets(buffer, sizeof(buffer), procinfo);		\
    do {						\
      if (fgets(buffer, sizeof(buffer), procinfo))	\
	(proc)(lnr++, buffer);				\
    } while (!feof(procinfo));				\
    fclose(procinfo);					\
  }
#else
#define INFO_GUTS2(file,proc)
#endif

#define INFO_GUTS3					\
 return(0);						

#define INFO_GUTS6(file,file6,name,proc)		\
 INFO_GUTS1(file,name,proc)				\
 INFO_GUTS2(file6,proc)					\
 INFO_GUTS3

#define INFO_GUTS(file,name,proc)			\
 INFO_GUTS1(file,name,proc)				\
 INFO_GUTS3

#if HAVE_RT_NETLINK && 0
static int
netlink_print(void)
{
  int flag;
#define NL_DEV   1
#define NL_ADDR  2
#define NL_MISC  4
  int fd,ret;
  struct in_rtmsg buf;
  struct aftype *ap;
  struct sockaddr *s;
  
  if ((fd = open(_PATH_DEV_ROUTE, O_RDONLY))<0) {
    if (errno == ENODEV)	
      ESYSNOT("netstat", _PATH_DEV_ROUTE);
    else
      perror(_PATH_DEV_ROUTE);
    return(-1);
  }

  if (flag_ver) {
    printf(NLS_CATGETS(catfd, netstatSet, netstat_nlp_title, "Netlink Kernel Messages"));
    if (flag_cnt)
      printf(NLS_CATGETS(catfd, netstatSet, netstat_nlp_cnt, " (continous)"));
    printf("\n");  	
  }  	
  	
  do {
    if ((ret=read(fd,(char *)&buf,sizeof(buf))) < 0) {
      perror("read "_PATH_DEV_ROUTE);
      return(-1);
    }
    if (ret != sizeof(buf)) {
      EINTERN("netstat.c", "netlink message size mismatch");
      return(-1);
    }
    
	flag=0;
	/* No NLS, keep this parseable */
	switch(buf.rtmsg_type) {
	case RTMSG_NEWROUTE:
	  printf("NEWROUTE\t");
	  flag=NL_DEV|NL_ADDR|NL_MISC;
	  break;
	case RTMSG_DELROUTE:
	  printf("DELROUTE\t");
	  flag=NL_DEV|NL_ADDR|NL_MISC;
	  break;
	case RTMSG_NEWDEVICE:
	  printf("NEWDEVICE\t");
	  flag=NL_DEV|NL_MISC;
	  break;
	case RTMSG_DELDEVICE:
	  printf("DELDEVICE\t");
	  flag=NL_DEV|NL_MISC;
	  break;
	default:
	  printf("UNKNOWN%lx\t",buf.rtmsg_type);
	  flag=NL_DEV|NL_ADDR|NL_MISC;
	  break;
	}
	
	if (flag&NL_ADDR) {
	  s=&buf.rtmsg_dst;
	  ap = get_afntype(s->sa_family);
	  if (ap == NULL) ap = get_afntype(0);
	  
	  printf("%s/%s ",ap->sprint(s, flag_not), ap->name);
	  
	  s=&buf.rtmsg_gateway;
	  ap = get_afntype(s->sa_family);
	  if (ap == NULL) ap = get_afntype(0);
	  
	  printf("%s/%s ",ap->sprint(s, flag_not), ap->name);
	  
	  s=&buf.rtmsg_genmask;
	  ap = get_afntype(s->sa_family);
	  if (ap == NULL) ap = get_afntype(0);
	  
	  printf("%s/%s ",ap->sprint(s, 1), ap->name);
	}
	if (flag&NL_MISC) {
	  printf("0x%x %d ",buf.rtmsg_flags,buf.rtmsg_metric);
	}
	if (flag&NL_DEV) {
	  printf("%s",buf.rtmsg_device);
	}
	printf("\n");
  } while(flag_cnt);
  close(fd);
  return(0);
}
#endif


#if HAVE_AFNETROM
static const char *netrom_state[]=
{
  "LISTENING",
  "CONN SENT",
  "DISC SENT",
  "ESTABLISHED"
};

static int netrom_info(void)
{
  FILE *f;
  char buffer[256],dev[16];
  int st,vs,vr,sendq,recvq;

  f = fopen(_PATH_PROCNET_NR, "r");
  if (f == NULL) {
    if (errno != ENOENT) {
      perror(_PATH_PROCNET_NR);
      return(-1);
    }
    if (flag_arg || flag_ver)
      ESYSNOT("netstat","AF NETROM");
    if (flag_arg)
      return(1);
    else
      return(0);
  }
  
  printf(NLS_CATGETS(catfd, netstatSet, netstat_netrom, "Activate NET/ROM sockets\n"));
  printf(NLS_CATGETS(catfd, netstatSet, netstat_header_netrom, "User       Dest       Source     Device  State        Vr/Vs  Send-Q  Recv-Q\n"));
  fgets(buffer,256,f);
 
  while (fgets(buffer,256,f)) {
    buffer[9]=0;
    buffer[19]=0;
    buffer[29]=0;
    sscanf(buffer+30,"%s %*d/%*d %*d/%*d %d %d %d %*d %*d/%*d %*d/%*d %*d/%*d %*d %*d %d %d",
	   dev,&st,&vs,&vr,&sendq,&recvq);
    printf("%-9s  %-9s  %-9s  %-6s  %-11s  %02d/%02d  %-6d  %-6d\n",
	   buffer,buffer+10,buffer+20,
	   dev,
	   netrom_state[st],
	   vr,vs,sendq,recvq);
  }
  fclose(f);
  return 0;		
}
#endif


#if HAVE_AFINET

enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING   /* now a valid state */
};

static const char *tcp_state[] = {
  "",
  "ESTABLISHED",
  "SYN_SENT",
  "SYN_RECV",
  "FIN_WAIT1",
  "FIN_WAIT2",
  "TIME_WAIT",
  "CLOSE",
  "CLOSE_WAIT",
  "LAST_ACK",
  "LISTEN",
  "CLOSING"
};

static void tcp_do_one(int lnr, const char *line)
{
  unsigned long rxq, txq, time_len, retr;
  int num, local_port, rem_port, d, state, uid, timer_run;
  char rem_addr[128], local_addr[128], timers[64], buffer[1024];
  struct aftype *ap;
  struct passwd *pw;
#if HAVE_AFINET6
  struct sockaddr_in6 localaddr, remaddr;
  char addr6p[16][3], addr6[128];
  extern struct aftype inet6_aftype;
#else
  struct sockaddr_in localaddr, remaddr;
#endif

  if (lnr == 0) 
    return;
  
  num = sscanf(line,
	  "%d: %[0-9A-Fa-f]:%X %[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d\n",
	  &d, local_addr, &local_port, rem_addr, &rem_port, &state,
	  &txq, &rxq, &timer_run, &time_len, &retr, &uid);
  
  if (strlen(local_addr) > 8) {
#if HAVE_AFINET6
    /* Demangle what the kernel gives us */
    sscanf(local_addr, 
	   "%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s",
	   addr6p[0], addr6p[1], addr6p[2], addr6p[3],
	   addr6p[4], addr6p[5], addr6p[6], addr6p[7],
	   addr6p[8], addr6p[9], addr6p[10], addr6p[11],
	   addr6p[12], addr6p[13], addr6p[14], addr6p[15]);
    sprintf(addr6, "%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s",
	    addr6p[3], addr6p[2], addr6p[1], addr6p[0],
	    addr6p[7], addr6p[6], addr6p[5], addr6p[4],
	    addr6p[11], addr6p[10], addr6p[9], addr6p[8],
	    addr6p[15], addr6p[14], addr6p[13], addr6p[12]);
	  inet6_aftype.input(1, addr6, (struct sockaddr *)&localaddr);
	  sscanf(rem_addr, 
		 "%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s%2s",
		 addr6p[0], addr6p[1], addr6p[2], addr6p[3],
		 addr6p[4], addr6p[5], addr6p[6], addr6p[7],
		 addr6p[8], addr6p[9], addr6p[10], addr6p[11],
		 addr6p[12], addr6p[13], addr6p[14], addr6p[15]);
	  sprintf(addr6, "%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s",
		  addr6p[3], addr6p[2], addr6p[1], addr6p[0],
		  addr6p[7], addr6p[6], addr6p[5], addr6p[4],
		  addr6p[11], addr6p[10], addr6p[9], addr6p[8],
		  addr6p[15], addr6p[14], addr6p[13], addr6p[12]);
	  inet6_aftype.input(1, addr6, (struct sockaddr *)&remaddr);
	  localaddr.sin6_family = AF_INET6;
	  remaddr.sin6_family = AF_INET6;
#endif
  } else {
    sscanf(local_addr, "%X",
	   &((struct sockaddr_in *)&localaddr)->sin_addr.s_addr);
    sscanf(rem_addr, "%X",
	   &((struct sockaddr_in *)&remaddr)->sin_addr.s_addr);
    ((struct sockaddr *)&localaddr)->sa_family = AF_INET;
    ((struct sockaddr *)&remaddr)->sa_family = AF_INET;
  }

  if (num < 11) {
    fprintf(stderr, "warning, got bogus tcp line.\n");
    return; 
  }

  if ((ap = get_afntype(((struct sockaddr *)&localaddr)->sa_family)) == NULL) {
    fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_netstat,
				"netstat: unsupported address family %d !\n"),
	    ((struct sockaddr *)&localaddr)->sa_family);
    return;
  }

  if (state == TCP_LISTEN) {
    time_len = 0;
    retr = 0L;
    rxq=0L;
    txq=0L;
  }
	  
  strcpy(local_addr, ap->sprint((struct sockaddr *)&localaddr, flag_not));
  strcpy(rem_addr, ap->sprint((struct sockaddr *)&remaddr, flag_not));
  if (flag_all || rem_port) {
    sprintf(buffer, "%s", get_sname(htons(local_port), "tcp", flag_not));

    if ((strlen(local_addr) + strlen(buffer)) > 22) 
      local_addr[22-strlen(buffer)] = '\0';

    strcat(local_addr, ":");
    strcat(local_addr, buffer);
    sprintf(buffer,  "%s", get_sname(htons(rem_port), "tcp", flag_not));

    if ((strlen(rem_addr) + strlen(buffer)) > 22)
      rem_addr[22-strlen(buffer)] = '\0';
  
    strcat(rem_addr, ":");
    strcat(rem_addr, buffer);
    timers[0] = '\0';

    if (flag_opt) 
      switch (timer_run) {
      case 0:
	sprintf(timers, NLS_CATGETS(catfd, netstatSet, netstat_off,
				    "off (0.00/%ld)"), retr);
	break;
	
      case 1:
	sprintf(timers, NLS_CATGETS(catfd, netstatSet, netstat_on,
				    "on (%2.2f/%ld)"),
		(double)time_len / 100, retr);
	break;
	
      default:
	sprintf(timers, NLS_CATGETS(catfd, netstatSet, netstat_unkn,
				    "unkn-%d (%2.2f/%ld)"),
		timer_run, (double)time_len / 100, retr);
	break;
      }
    printf("tcp   %6ld %6ld %-23s %-23s %-12s",
	   rxq, txq, local_addr, rem_addr, tcp_state[state]);
    
    if (flag_exp > 1) {
      if (!flag_not && ((pw = getpwuid(uid)) != NULL))
	printf("%-10s ", pw->pw_name);
      else
	printf("%-10d ", uid);
    }
    
    if (flag_opt) printf("%s", timers);
    printf("\n");
  }
}

static int
tcp_info(void)
{
  INFO_GUTS6(_PATH_PROCNET_TCP, _PATH_PROCNET_TCP6, "AF INET (tcp)",
	     tcp_do_one);
}

static void udp_do_one(int lnr, const char *line)
{
  char buffer[8192], local_addr[64], rem_addr[64];
  char *udp_state, timer_queued, timers[64], more[512];
  int num, local_port, rem_port, d, state, timer_run;
#if HAVE_AFINET6
  struct sockaddr_in6 localaddr, remaddr;
  char addr6p[8][5];
  char addr6[128];
  extern struct aftype inet6_aftype;
#else
  struct sockaddr_in localaddr, remaddr;
#endif
  struct aftype *ap;
  unsigned long rxq, txq, time_len, retr;

  if (lnr == 0)
    return;

  more[0] = '\0';
  timer_queued = '\0';
  num = sscanf(line,
	 "%d: %[0-9A-Fa-f]:%X %[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %c %s\n",
	 &d, local_addr, &local_port,
	 rem_addr, &rem_port, &state,
	 &txq, &rxq, &timer_run, &time_len, &retr, &timer_queued, more);
	
  if (strlen(local_addr) > 8) {
#if HAVE_AFINET6
    sscanf(local_addr, "%4s%4s%4s%4s%4s%4s%4s%4s",
	   addr6p[0], addr6p[1], addr6p[2], addr6p[3],
	   addr6p[4], addr6p[5], addr6p[6], addr6p[7]);
    sprintf(addr6, "%s:%s:%s:%s:%s:%s:%s:%s",
	    addr6p[0], addr6p[1], addr6p[2], addr6p[3],
	    addr6p[4], addr6p[5], addr6p[6], addr6p[7]);
    inet6_aftype.input(1, addr6, (struct sockaddr *)&localaddr);
    sscanf(rem_addr, "%4s%4s%4s%4s%4s%4s%4s%4s",
	   addr6p[0], addr6p[1], addr6p[2], addr6p[3],
	   addr6p[4], addr6p[5], addr6p[6], addr6p[7]);
    sprintf(addr6, "%s:%s:%s:%s:%s:%s:%s:%s",
	    addr6p[0], addr6p[1], addr6p[2], addr6p[3],
	    addr6p[4], addr6p[5], addr6p[6], addr6p[7]);
    inet6_aftype.input(1, addr6, (struct sockaddr *)&remaddr);
    localaddr.sin6_family = AF_INET6;
    remaddr.sin6_family = AF_INET6;
#endif
  } else {
    sscanf(local_addr, "%X",
	   &((struct sockaddr_in *)&localaddr)->sin_addr.s_addr);
    sscanf(rem_addr, "%X",
	   &((struct sockaddr_in *)&remaddr)->sin_addr.s_addr);
    ((struct sockaddr *)&localaddr)->sa_family = AF_INET;
    ((struct sockaddr *)&remaddr)->sa_family = AF_INET;
  }

  retr = 0L;
  if (!flag_opt) 
    more[0] = '\0';
  
  if (num < 10) {
    fprintf(stderr, "warning, got bogus udp line.\n");
    return;
  }
  
  if ((ap = get_afntype(((struct sockaddr *)&localaddr)->sa_family)) == NULL) {
    fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_netstat,
				"netstat: unsupported address family %d !\n"),
	    ((struct sockaddr *)&localaddr)->sa_family);
    return;
  }
  
  switch (state) {
  case TCP_ESTABLISHED:
    udp_state = "ESTABLISHED";
    break;
    
  case TCP_CLOSE:
    udp_state = "";
    break;
    
  default:
    udp_state = "UNKNOWN";
    break;
  }
  
  strcpy(local_addr, ap->sprint((struct sockaddr *)&localaddr, flag_not));
  strcpy(rem_addr, ap->sprint((struct sockaddr *)&remaddr, flag_not));
#if HAVE_AFINET6
  if (flag_all ||
	    ((localaddr.sin6_family == AF_INET6) &&
	     ((localaddr.sin6_addr.s6_addr32[0])||
	      (localaddr.sin6_addr.s6_addr32[1])||
	      (localaddr.sin6_addr.s6_addr32[2])||
	      (localaddr.sin6_addr.s6_addr32[3]))) ||
      ((localaddr.sin6_family == AF_INET) &&
       ((struct sockaddr_in *)&localaddr)->sin_addr.s_addr)) 
#else
  if (flag_all || localaddr.sin_addr.s_addr) 
#endif
  {
    sprintf(buffer, "%s", get_sname(htons(local_port), "udp", flag_not));
    if ((strlen(local_addr) + strlen(buffer)) > 22) 
      local_addr[22-strlen(buffer)] = '\0';
    
    strcat(local_addr, ":");
    strcat(local_addr, buffer);
    sprintf(buffer, "%s", get_sname(htons(rem_port), "udp", flag_not));
    if ((strlen(rem_addr) + strlen(buffer)) > 22) 
      rem_addr[22-strlen(buffer)] = '\0';
    
    strcat(rem_addr, ":");
    strcat(rem_addr, buffer);
    
    timers[0] = '\0';
    if (flag_opt) switch (timer_run) {
    case 0:
      sprintf(timers, NLS_CATGETS(catfd, netstatSet, netstat_off2,
				  "off (0.00/%ld) %c"),
	      retr, timer_queued);
      break;
      
    case 1:
      sprintf(timers, NLS_CATGETS(catfd, netstatSet, netstat_on2,
				  "on (%2.2f/%ld) %c"),
	      (double)time_len / 100, retr, timer_queued);
      break;
      
    default:
      sprintf(timers, NLS_CATGETS(catfd, netstatSet, netstat_unkn2,
				  "unkn-%d (%2.2f/%ld) %c"),
	      timer_run, (double)time_len / 100,
	      retr, timer_queued);
      break;
    }
    printf("udp   %6ld %6ld %-23s %-23s %-12s",
	   rxq, txq, local_addr, rem_addr, udp_state);
    
    if (flag_exp > 1)
      printf("%-10s ", "");
    
    if (flag_opt) printf("%s", timers);
    printf("\n");
  }
}  

static int
udp_info(void)
{
  INFO_GUTS6(_PATH_PROCNET_UDP, _PATH_PROCNET_UDP6, "AF INET (udp)", 
	     udp_do_one);
}

static void raw_do_one(int lnr, const char *line)
{
  char buffer[8192], local_addr[64], rem_addr[64];
  char *raw_state, timer_queued, timers[64], more[512];
  int num, local_port, rem_port, d, state, timer_run;
#if HAVE_AFINET6
  struct sockaddr_in6 localaddr, remaddr;
  char addr6p[8][5];
  char addr6[128];
  extern struct aftype inet6_aftype;
#else
  struct sockaddr_in localaddr, remaddr;
#endif
  struct aftype *ap;
  unsigned long rxq, txq, time_len, retr;

  if (lnr == 0)
    return;

  more[0] = '\0';
  timer_queued = '\0';
  num = sscanf(line,
          "%d: %[0-9A-Fa-f]:%X %[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %c %s\n",
	   &d, local_addr, &local_port, rem_addr, &rem_port, &state,
	   &txq, &rxq, &timer_run, &time_len, &retr, &timer_queued, more);
  
  if (strlen(local_addr) > 8) {
#if HAVE_AFINET6
    sscanf(local_addr, "%4s%4s%4s%4s%4s%4s%4s%4s",
	   addr6p[0], addr6p[1], addr6p[2], addr6p[3],
	   addr6p[4], addr6p[5], addr6p[6], addr6p[7]);
    sprintf(addr6, "%s:%s:%s:%s:%s:%s:%s:%s",
	    addr6p[0], addr6p[1], addr6p[2], addr6p[3],
	    addr6p[4], addr6p[5], addr6p[6], addr6p[7]);
    inet6_aftype.input(1, addr6, (struct sockaddr *)&localaddr);
    sscanf(rem_addr, "%4s%4s%4s%4s%4s%4s%4s%4s",
	   addr6p[0], addr6p[1], addr6p[2], addr6p[3],
	   addr6p[4], addr6p[5], addr6p[6], addr6p[7]);
    sprintf(addr6, "%s:%s:%s:%s:%s:%s:%s:%s",
	    addr6p[0], addr6p[1], addr6p[2], addr6p[3],
	    addr6p[4], addr6p[5], addr6p[6], addr6p[7]);
    inet6_aftype.input(1, addr6, (struct sockaddr *)&remaddr);
    localaddr.sin6_family = AF_INET6;
    remaddr.sin6_family = AF_INET6;
#endif
  } else {
    sscanf(local_addr, "%X",
	   &((struct sockaddr_in *)&localaddr)->sin_addr.s_addr);
    sscanf(rem_addr, "%X",
	   &((struct sockaddr_in *)&remaddr)->sin_addr.s_addr);
    ((struct sockaddr *)&localaddr)->sa_family = AF_INET;
    ((struct sockaddr *)&remaddr)->sa_family = AF_INET;
  }
#if HAVE_AFINET6
  if ((ap = get_afntype(localaddr.sin6_family)) == NULL) {
    fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_netstat,
				"netstat: unsupported address family %d !\n"),
	    localaddr.sin6_family);
    return;
  }
#else
  if ((ap = get_afntype(localaddr.sin_family)) == NULL) {
    fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_netstat,
				"netstat: unsupported address family %d !\n"),
	    localaddr.sin_family);
    return;
  }
#endif  

  if (!flag_opt) 
    more[0] = '\0';

  if (num < 10) {
    fprintf(stderr, "warning, got bogus raw line.\n");
    return;
  }

  raw_state = "";
  strcpy(local_addr, ap->sprint((struct sockaddr *)&localaddr, flag_not));
  strcpy(rem_addr, ap->sprint((struct sockaddr *)&remaddr, flag_not));
#if HAVE_AFINET6
  if (flag_all ||
      ((localaddr.sin6_family == AF_INET6) &&
       ((localaddr.sin6_addr.s6_addr32[0])||
	(localaddr.sin6_addr.s6_addr32[1])||
	(localaddr.sin6_addr.s6_addr32[2])||
	(localaddr.sin6_addr.s6_addr32[3]))) ||
      ((localaddr.sin6_family == AF_INET) &&
       ((struct sockaddr_in *)&localaddr)->sin_addr.s_addr))
#else
  if (flag_all || localaddr.sin_addr.s_addr) 
#endif
  {
    sprintf(buffer, "%s", get_sname(htons(local_port), "raw", flag_not));
    if ((strlen(local_addr) + strlen(buffer)) > 22) 
      local_addr[22-strlen(buffer)] = '\0';
   
    strcat(local_addr, ":");
    strcat(local_addr, buffer);
    sprintf(buffer, "%s", get_sname(htons(rem_port), "raw", flag_not));
    if ((strlen(rem_addr) + strlen(buffer)) > 22) 
      rem_addr[22-strlen(buffer)] = '\0';
    
    strcat(rem_addr, ":");
    strcat(rem_addr, buffer);
    
    timers[0] = '\0';
    if (flag_opt) switch (timer_run) {
    case 0:
      sprintf(timers, NLS_CATGETS(catfd, netstatSet, netstat_off3,
				  "off (0.00/%ld) %c"),
	      retr, timer_queued);
      break;
      
    case 1:
      sprintf(timers, NLS_CATGETS(catfd, netstatSet, netstat_on3,
				  "on (%2.2f/%ld) %c"),
	      (double)time_len / 100, retr,
	      timer_queued);
	break;
	
    default:
      sprintf(timers, NLS_CATGETS(catfd, netstatSet, netstat_unkn3,
				  "unkn-%d (%2.2f/%ld) %c"),
	      timer_run, (double)time_len / 100,
	      retr, timer_queued);
      break;
    }
      printf("raw   %6ld %6ld %-23s %-23s %-12s",
	     rxq, txq, local_addr, rem_addr, raw_state);
      
      if (flag_exp > 1)
	printf("%-10s ", "");
      
      if (flag_opt) printf("%s", timers);
      printf("\n");
  }
}

static int
raw_info(void)
{
  INFO_GUTS6(_PATH_PROCNET_RAW, _PATH_PROCNET_RAW6, "AF INET (raw)",
	     raw_do_one);
}
#endif


#if HAVE_AFUNIX

#define HAS_INODE 1

static void unix_do_one(int nr, const char *line)
{
  static int has = 0;
  char inode[MAXPATHLEN], path[MAXPATHLEN], ss_flags[32];
  char *ss_proto, *ss_state, *ss_type;
  int num, state, type;
  void *d;
  unsigned long refcnt, proto, flags;

  if (nr == 0) {
    if (strstr(line, "Inode"))
      has |= HAS_INODE;
    return;
  }

  path[0] = '\0';
  inode[0] = '\0';
  num = sscanf(line, "%p: %lX %lX %lX %X %X %s %s",
	       &d, &refcnt, &proto, &flags, &type, &state, inode, path);
  if (num < 6) {
    fprintf(stderr, "warning, got bogus unix line.\n");
    return;
  }

  if (!(has&HAS_INODE)) {
    strcpy(path,inode);
    strcpy(inode,"-");
  }
  if (!flag_all && (state == SS_UNCONNECTED) && (flags & SO_ACCEPTCON))
    return;
  
  switch(proto) {
  case 0:
    ss_proto = "unix";
    break;
    
  default:
    ss_proto = "??";
  }
  
  switch(type) {
  case SOCK_STREAM:
    ss_type = "STREAM";
    break;
    
  case SOCK_DGRAM:
    ss_type = "DGRAM";
    break;
    
  case SOCK_RAW:
    ss_type = "RAW";
    break;
    
  case SOCK_RDM:
    ss_type = "RDM";
    break;
    
  case SOCK_SEQPACKET:
    ss_type = "SEQPACKET";
    break;
    
  default:
    ss_type = "UNKNOWN";
  }
  
  switch(state) {
  case SS_FREE:
    ss_state = "FREE";
    break;
    
  case SS_UNCONNECTED:
    /*
     * Unconnected sockets may be listening
     * for something.
     */
    if (flags & SO_ACCEPTCON) {
      ss_state = "LISTENING";
    } else {
      ss_state = "";
    }
    break;
    
  case SS_CONNECTING:
    ss_state = "CONNECTING";
    break;
    
  case SS_CONNECTED:
    ss_state = "CONNECTED";
    break;
    
  case SS_DISCONNECTING:
    ss_state = "DISCONNECTING";
    break;
    
  default:
    ss_state = "UNKNOWN";
  }
  
  strcpy(ss_flags, "[ ");
  if (flags & SO_ACCEPTCON) strcat(ss_flags, "ACC ");
  if (flags & SO_WAITDATA) strcat(ss_flags, "W ");
  if (flags & SO_NOSPACE) strcat(ss_flags, "N ");
  
  strcat(ss_flags, "]");
  
  printf("%-5s %-6ld %-11s %-10s %-13s %-6s %s\n",
	 ss_proto, refcnt, ss_flags, ss_type, ss_state, inode, path);
}

static int
unix_info(void)
{
  
  printf(NLS_CATGETS(catfd, netstatSet, netstat_unix, "Active UNIX domain sockets ")); /* xxx */
  if (flag_all) printf(NLS_CATGETS(catfd, netstatSet, netstat_servers, "(including servers)")); /* xxx */
           else printf(NLS_CATGETS(catfd, netstatSet, netstat_noservers, "(w/o servers)")); /* xxx */

  printf(NLS_CATGETS(catfd, netstatSet, netstat_header_unix,
		     "\nProto RefCnt Flags       Type       State         I-Node Path\n")); /* xxx */

  {
    INFO_GUTS(_PATH_PROCNET_UNIX, "AF UNIX", unix_do_one);
  }
}
#endif


#if HAVE_AFAX25
static int ax25_info(void)
{
 	FILE *f=fopen(_PATH_PROCNET_AX25, "r");
	char buffer[256],dev[16];
	int st,vs,vr,sendq,recvq;
	static char *ax25_state[5]=
 	{
		"LISTENING",
 		"SABM SENT",
 		"DISC SENT",
		"ESTABLISHED",
		"RECOVERY"
 	};
	if(!(f=fopen(_PATH_PROCNET_AX25, "r")))
	{
		if (errno != ENOENT) {
			perror(_PATH_PROCNET_AX25);
			return(-1);
		}
		if (flag_arg || flag_ver)
			ESYSNOT("netstat","AF AX25");
		if (flag_arg)
			return(1);
		else
			return(0);
  	}
	printf(NLS_CATGETS(catfd, netstatSet, netstat_ax25, "Activate AX.25 sockets\n"));
	printf(NLS_CATGETS(catfd, netstatSet, netstat_header_ax25, "Dest       Source     Device  State        Vr/Vs  Send-Q  Recv-Q\n"));
 	fgets(buffer,256,f);
 	while(fgets(buffer,256,f))
 	{
 		buffer[9]=0;
		buffer[19]=0;
		sscanf(buffer+20,"%s %d %d %d %*d %*d/%*d %*d/%*d %*d/%*d %*d/%*d %*d %*d %d %d",
			dev,&st,&vs,&vr,&sendq,&recvq);
		printf("%-9s  %-9s  %-6s  %-11s  %02d/%02d  %-6d  %-6d\n",
 			buffer,buffer+10,
			dev,
 			ax25_state[st],
			vr,vs,sendq,recvq);
 	}
 	fclose(f);
 	return 0;		
}
#endif


#if HAVE_AFIPX
static int ipx_info(void)
{
	FILE *f;
	char buf[256];
	unsigned long txq,rxq;
	unsigned int state;
	unsigned int uid;
	char *st;
	int nc;
	struct aftype *ap;
	struct passwd *pw;
	char sad[50],dad[50];
	struct sockaddr sa;
	unsigned sport=0,dport=0;
			
	if(!(f=fopen(_PATH_PROCNET_IPX,"r")))
	{
		if (errno != ENOENT) {
			perror(_PATH_PROCNET_IPX);
			return(-1);
		}
		if (flag_arg || flag_ver)
			ESYSNOT("netstat","AF IPX");
		if (flag_arg)
			return(1);
		else
			return(0);
  	}
	printf(NLS_CATGETS(catfd, netstatSet, netstat_header_ipx,
		   "Active IPX sockets\nProto Recv-Q Send-Q Local Address              Foreign Address            State")); /* xxx */
	if (flag_exp>1)
		printf(NLS_CATGETS(catfd, netstatSet, netstat_header_ipx2,
			" User")); /* xxx */
	printf("\n");
	if ((ap = get_afntype(AF_IPX)) == NULL) {
		EINTERN("netstat.c","AF_IPX missing");
		return(-1);
  	}

	fgets(buf,255,f);
	
	while(fgets(buf,255,f)!=NULL)
	{
		sscanf(buf, "%s %s %lX %lX %d %d",
			sad,dad,&txq,&rxq,&state,&uid);
		if ((st = rindex(sad,':'))) {
			*st++ = '\0';
			sscanf(st,"%X",&sport); /* net byt order */
			sport = ntohs(sport);
		} else {
			EINTERN("netstat.c",_PATH_PROCNET_IPX" sport format error");
			return(-1);
		}
		nc = 0;
		if (strcmp(dad,"Not_Connected")!=0) {
			if ((st = rindex(dad,':'))) {
				*st++ = '\0';
				sscanf(st,"%X",&dport); /* net byt order */
				dport = ntohs(dport);
			} else {
				EINTERN("netstat.c",_PATH_PROCNET_IPX" dport format error");
				return(-1);
			}
		} else
			nc = 1;
			
		switch(state)
		{
			case TCP_ESTABLISHED:
				st = "ESTAB";
				break;

			case TCP_CLOSE:
				st = "";
				break;

			default:
				st = "UNK.";
				break;
		}

		/* Fetch and resolve the Source */
		(void)ap->input(4,sad,&sa);
		strcpy(buf, ap->sprint(&sa, flag_not));
		sprintf(sad,"%s:%04X",buf,sport);

		if (!nc) {
			/* Fetch and resolve the Destination */
			(void)ap->input(4,dad,&sa);
			strcpy(buf, ap->sprint(&sa, flag_not));
			sprintf(dad,"%s:%04X",buf,dport);
		} else strcpy(dad,"-");

		printf("IPX   %6ld %6ld %-26s %-26s %-5s", txq, rxq, sad, dad, st);
		if (flag_exp>1) {
			if (!flag_not && ((pw = getpwuid(uid)) != NULL))
				printf(" %-10s", pw->pw_name);
			else
				printf(" %-10d",uid);
		}
		printf("\n");
	}
	fclose(f);
	return 0;
}	
#endif

static void
ife_print(struct interface *ptr)
{
  printf("%-5.5s ", ptr->name);
  printf("%5d %3d ", ptr->mtu, ptr->metric);
  /* If needed, display the interface statistics. */
  printf("%6lu %6lu %6lu %6lu ",
	 ptr->stats.rx_packets, ptr->stats.rx_errors,
	 ptr->stats.rx_dropped, ptr->stats.rx_fifo_errors);
  printf("%6lu %6lu %6lu %6lu ",
	 ptr->stats.tx_packets, ptr->stats.tx_errors,
	 ptr->stats.tx_dropped, ptr->stats.tx_fifo_errors);
  if (ptr->flags == 0) printf(NLS_CATGETS(catfd, netstatSet, netstat_noflags, "[NO FLAGS]"));
  if (ptr->flags & IFF_ALLMULTI) printf("A");
  if (ptr->flags & IFF_BROADCAST) printf("B");
  if (ptr->flags & IFF_DEBUG) printf("D");
  if (ptr->flags & IFF_LOOPBACK) printf("L");
  if (ptr->flags & IFF_PROMISC) printf("M");
  if (ptr->flags & IFF_NOTRAILERS) printf("N");
  if (ptr->flags & IFF_NOARP) printf("O");
  if (ptr->flags & IFF_POINTOPOINT) printf("P");
  if (ptr->flags & IFF_RUNNING) printf("R");
  if (ptr->flags & IFF_UP) printf("U");
  printf("\n");
}

static int
iface_info(void)
{
  struct interface ife;
  char buffer[256];
  FILE *fd;
  
  printf(NLS_CATGETS(catfd, netstatSet, netstat_interface, "Kernel Interface table\n"));
  printf(NLS_CATGETS(catfd, netstatSet, netstat_header_iface,
		     "Iface   MTU Met  RX-OK RX-ERR RX-DRP RX-OVR  TX-OK TX-ERR TX-DRP TX-OVR Flags\n"));
  
  /* Create a channel to the NET kernel. */
  if ((skfd = sockets_open()) < 0) {
    perror("socket");
    NLS_CATCLOSE(catfd)
    exit(1);
  }

  fd = fopen(_PATH_PROCNET_DEV, "r");
  fgets(buffer, 256, fd);	/* chuck first two lines */
  fgets(buffer, 256, fd);
  while (!feof(fd)) {
    char *name = buffer;
    char *sep;
    if (fgets(buffer, 256, fd) == NULL)
      break;
    sep = strrchr(buffer, ':');
    if (sep)
      *sep = 0;
    while (*name == ' ') name++;
    if (if_fetch(name, &ife) < 0) {
      fprintf(stderr, NLS_CATGETS(catfd, ifconfigSet, 
				  ifconfig_unkn, "%s: unknown interface.\n"),
	      name);
      continue;
    }
    
    if (((ife.flags & IFF_UP) == 0) && !flag_all) continue;
    ife_print(&ife);
  }

  fclose(fd);
  close(skfd);

  return 0;
}


static void
version(void) 
{
  printf("%s\n%s\n%s\n%s\n", Release, Version, Signature, Features);
  NLS_CATCLOSE(catfd)
  exit(1);
}


static void
usage(void)
{
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage1,  "usage: netstat [-veenNcCF] [<Af>] -r         netstat {-V|--version|-h|--help}\n"));
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage2,  "       netstat [-vnNcaeo] [<Socket>]\n"));
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage3,  "       netstat { [-veenNac] -i | [-vnNc] -L | [-cnNe] -M }\n\n"));
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage4,  "        -r, --route              display routing table\n")); /* xxx */
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage5,  "        -L, --netlink            display netlink kernel messages\n"));
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage6,  "        -i, --interfaces         display interface table\n"));
#if HAVE_FW_MASQUERADE
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage7,  "        -M, --masquerade         display masqueraded connections\n\n"));
#endif
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage8,  "        -v, --verbose            be verbose\n"));
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage9,  "        -n, --numeric            dont resolve names\n"));
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage10, "        -e, --extend             display other/more informations\n"));
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage11, "        -c, --continuous         continuous listing\n\n"));
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage12, "        -a, --all, --listening   display all\n"));
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage13, "        -o, --timers             display timers\n\n"));
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage14, "<Socket>={-t|--tcp} {-u|--udp} {-w|--raw} {-x|--unix} --ax25 --ipx --netrom\n"));
#if HAVE_AFINET6
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage15, "<Af>= -A {inet|inet6|ipx|netrom|ddp|ax25},... --inet --inet6 --ipx --netrom --ddp --ax25\n"));
#else
  fprintf(stderr, NLS_CATGETS(catfd, netstatSet, netstat_usage15, "<Af>= -A {inet|ipx|netrom|ddp|ax25},... --inet --ipx --netrom --ddp --ax25\n"));
#endif
  NLS_CATCLOSE(catfd)
  exit(1);
}


int main
(int argc, char *argv[])
{
  int i;
  int lop;
  struct option longopts[]=
  {
    AFTRANS_OPTS,
    {"version",		0,	0,	'V'},
    {"interfaces",	0,	0,	'i'},
    {"help",		0,	0,	'h'},
    {"route",		0,	0,	'r'},
    {"netlink",		2,	0,	'L'},
#if HAVE_FW_MASQUERADE
    {"masquerade",	0,	0,	'M'},
#endif
    {"protocol",	1,	0,	'A'},
    {"tcp",		0,	0,	't'},
    {"udp",		0,	0,	'u'},
    {"raw",		0,	0,	'w'},
    {"unix",		0,	0,	'x'},
    {"listening",	0,	0,	'a'},
    {"all",		0,	0,	'a'},
    {"timers",		0,	0,	'o'},
    {"continuous",	0,	0,	'c'},
    {"extend",		0,	0,	'e'},
    {"verbose",		0,	0,	'v'},
    {"statistics",	0,	0,	's'},
    {"numeric",		0,	0,	'n'},
    {"symbolic",	0,	0,	'N'},
    {"cache",		0,	0,	'C'},
    {"fib",		0,	0,	'F'},
    {NULL,		0,	0,	0}
  };
  
#if NLS
  setlocale (LC_MESSAGES, "");
  catfd = catopen ("nettools", MCLoadBySet);
#endif

  getroute_init(); 			/* Set up AF routing support */

  afname[0]='\0';
  while ((i = getopt_long(argc, argv, "MLCFA:acdehinNorstuVv?wx", longopts, &lop)) != EOF) switch(i) {
  case -1:
    break;
  case 1:
    if (lop < 0 || lop >= AFTRANS_CNT) {
      EINTERN("netstat.c","longopts 1 range");
      break;
    }
    if (aftrans_opt(longopts[lop].name)) {
      NLS_CATCLOSE(catfd)
	exit(1);
    }
    break;
  case 'A':
    if (aftrans_opt(optarg)) {
      NLS_CATCLOSE(catfd)
	exit(1);
    }
    break;
  case 'L':
    flag_nlp++;
    break;
  case 'M':
    flag_mas++;
    break;
  case 'a':
    flag_all++;
    break;
  case 'c':
    flag_cnt++;
    break;
    
  case 'd':
    flag_deb++;
    break;
  case 'e':
    flag_exp++;
    break;
  case 'i':
    flag_int++;
    break;
    
  case 'n':
    flag_not|=FLAG_NUM;
    break;
  case 'N':
    flag_not|=FLAG_SYM;
    break;
  case 'C':
    flag_cf|=FLAG_CACHE;
    break;
  case 'F':
    flag_cf|=FLAG_FIB;
    break;
  case 'o':
    flag_opt++;
    break;
  case 'V':
    version();
    /*NOTREACHED*/
  case 'v':
    flag_ver|=FLAG_VERBOSE;
    break;
  case 'r':
    flag_rou++;
    break;
    
  case 't':
    flag_tcp++;
    break;
    
  case 'u':
    flag_udp++;
    break;
  case 'w':
    flag_raw++;
    break;
  case 'x':
    if (aftrans_opt("unix")) {
      NLS_CATCLOSE(catfd)
	exit(1);
    }
    break;
  case '?':
  case 'h':
    usage();
  case 's':
    inittab();
    parsesnmp();
    exit(0);
  }
  
  if (flag_int + flag_rou + flag_nlp + flag_mas > 1)
    usage();
  
  if (flag_inet)
    flag_tcp = flag_udp = flag_raw = 1;
  
  flag_arg = flag_tcp + flag_udp + flag_raw + flag_unx + flag_ipx 
    + flag_ax25 + flag_netrom;
  
  if (flag_nlp) {
#if HAVE_RT_NETLINK && 0
    i=netlink_print();
#else
    ENOSUPP("netstat.c","RT_NETLINK");
    i=-1;
#endif	
    NLS_CATCLOSE(catfd)
      return(i);
  }
  if (flag_mas) {
#if HAVE_FW_MASQUERADE && HAVE_AFINET
#if MORE_THAN_ONE_MASQ_AF
    if (!afname[0])
      strcpy(afname,DFLT_AF);
#endif  
    for(;;) {
      i = ip_masq_info(flag_not, flag_exp);
      if (i || !flag_cnt) break;
      sleep(1);
    }
#else
    ENOSUPP("netstat.c","FW_MASQUERADE");
    i=-1;
#endif
    NLS_CATCLOSE(catfd)
      return(i);
  }
  if (flag_rou) {
    int options=0;
    
    if (!afname[0])
      strcpy(afname,DFLT_AF);
    
    if (flag_exp == 2)
      flag_exp = 1;
    else if (flag_exp == 1)
      flag_exp = 2;
    
    options = (flag_exp & FLAG_EXT) | flag_not | flag_cf | flag_ver ;
    if (!flag_cf)
      options |= FLAG_FIB;
    
    for(;;) {
      i = route_info(afname,options);
      if (i || !flag_cnt) break;
      sleep(1);
    }
    NLS_CATCLOSE(catfd)
      return(i);
  }
  
  if (flag_int) {
    for (;;) {
      i = iface_info();
      if (!flag_cnt || i) break;
      sleep(1);
    }
    NLS_CATCLOSE(catfd)
      return(i);
  }
  
  for (;;) {
    if (!flag_arg || flag_tcp || flag_udp || flag_raw) {
#if HAVE_AFINET
      printf(NLS_CATGETS(catfd, netstatSet, netstat_internet, "Active Internet connections ")); /* xxx */
      if (flag_all) printf(NLS_CATGETS(catfd, netstatSet, netstat_servers, "(including servers)")); /* xxx */
      else printf(NLS_CATGETS(catfd, netstatSet, netstat_noservers, "(w/o servers)")); /* xxx */
      
      printf(NLS_CATGETS(catfd, netstatSet, netstat_header_internet,
			 "\nProto Recv-Q Send-Q Local Address           Foreign Address         State      ")); /* xxx */
      if (flag_exp > 1)
	printf(NLS_CATGETS(catfd, netstatSet, netstat_header_internet2,
			   " User      ")); /* xxx */
      if (flag_opt)
	printf(NLS_CATGETS(catfd, netstatSet, netstat_header_internet3,
			   " Timer")); /* xxx */
      printf("\n");
#else
      if (flag_arg) { 
	i = 1; 
	ENOSUPP("netstat","AF INET"); 
      }
#endif
    }
#if HAVE_AFINET
    if (!flag_arg || flag_tcp) {
      i = tcp_info();
      if (i) {  NLS_CATCLOSE(catfd)  return(i); }
    }
    
    if (!flag_arg || flag_udp) {
      i = udp_info();
      if (i) {  NLS_CATCLOSE(catfd)  return(i); }
    }
    
    if (!flag_arg || flag_raw) {
      i = raw_info();
      if (i) {  NLS_CATCLOSE(catfd)  return(i); }
    }
#endif
    
    if (!flag_arg || flag_unx) {
#if HAVE_AFUNIX
      i = unix_info();
      if (i) {  NLS_CATCLOSE(catfd)  return(i); }
#else
      if (flag_arg)
	{ i=1; ENOSUPP("netstat","AF UNIX"); }
#endif
    }
    
    if(!flag_arg || flag_ipx) {
#if HAVE_AFIPX
      i = ipx_info();
      if(i) {  NLS_CATCLOSE(catfd)  return(i); }
#else
      if (flag_arg)
	{ i=1; ENOSUPP("netstat","AF IPX"); }
#endif
    }
    
    if(!flag_arg || flag_ax25) {
#if HAVE_AFAX25
      i = ax25_info();
      if(i) {  NLS_CATCLOSE(catfd)  return(i); }
#else
      if (flag_arg)
	{ i=1; ENOSUPP("netstat","AF AX25"); }
#endif
    }
    
    if(!flag_arg || flag_netrom) {
#if HAVE_AFNETROM
      i = netrom_info();
      if(i) {  NLS_CATCLOSE(catfd)  return(i); }
#else
      if (flag_arg)
	{ i=1; ENOSUPP("netstat","AF NETROM"); }
#endif
    }
    
    if (!flag_cnt || i) break;
    sleep(1);
  }
  
  NLS_CATCLOSE(catfd)
    return(i);
}
