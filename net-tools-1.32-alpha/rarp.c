/*
 * rarp		This file contains an implementation of the command
 *		that maintains the kernel's RARP cache.  It is derived
 *              from Fred N. van Kempen's arp command.
 *
 * Usage:       rarp -d hostname                      Delete entry
 *		rarp -s hostname ethernet_address     Add entry
 *              rarp -a                               Print entries
 *
 *  Ross D. Martin  <martin@trcsun3.eas.asu.edu>
 * 
 * THIS NEEDS TO BE CLEANED UP COMPLETELY           -eckes
 */
#include <sys/types.h>
#if defined(__GLIBC__)
#define _SOCKETBITS_H
#endif /* __GLIBC__ */
#include <sys/socket.h>
#include <sys/ioctl.h>
#if !defined(__GLIBC__)
#include <netinet/in.h>
#else /* __GLIBC__ */
#include <linux/in.h>
#define _NETINET_IN_H
#endif /* __GLIBC__ */
#include <arpa/inet.h>
#if !defined(__GLIBC__)
#include <net/if.h>
#endif /* __GLIBC__ */
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "net-locale.h"

int sockfd;				/* active socket descriptor	*/

/* Input an Ethernet address and convert to binary. */
unsigned char *in_ether(char *ptr)
{
  static unsigned char buff[6];
  unsigned int temp[6];
  int num;

  num=sscanf(ptr,"%x:%x:%x:%x:%x:%x",
	     &temp[0],&temp[1],&temp[2],&temp[3],&temp[4],&temp[5]);
  if(num!=6)
    {
      fprintf(stderr,NLS_CATGETS(catfd, rarpSet, rarp_invalid, "Invalid Ethernet address: %s\n"), ptr);
    }
  
  for(num=0;num<6;num++)
    buff[num]=temp[num];

  return(buff);
}


/* This structure defines hardware protocols and their handlers. */
struct hwtype {
  char		*name;
  int		type;
  int		hlen;
  unsigned char	*(*input)(char *);
};

struct hwtype hwtypes[] = {
  { "ether",  ARPHRD_ETHER,  6, in_ether  },
#if HAVE_ARPHRD_PRONET /* XXX */
  { "pronet", ARPHRD_PRONET, 2, in_pronet },
#endif
#if HAVE_ARPHRD_AX25 /* XXX */
  { "ax25",   ARPHRD_AX25,  12, in_ax25   },
#endif
  { NULL,     -1,            0, NULL      }
};

struct hwtype *hardware;

/* Check our hardware type table for this type. */
struct hwtype *get_type(char *name)
{
  register struct hwtype *hwp;

  hwp = hwtypes;
  while (hwp->name != NULL) {
	if (!strcmp(hwp->name, name)) return(hwp);
	hwp++;
  }
  return(NULL);
}


/* Check our hardware type table for this type. */
struct hwtype *get_ntype(int type)
{
  register struct hwtype *hwp;

  hwp = hwtypes;
  while (hwp->name != NULL) {
	if (hwp->type == type) return(hwp);
	hwp++;
  }
  return(NULL);
}


/* Delete an entry from the ARP cache. */
int arp_del(char *host)
{
  struct hostent *hp;
  struct arpreq req;
  struct sockaddr_in *si;
  register int i;
  int found;

  /* Resolve the host name. */
  if ((hp = gethostbyname(host)) == NULL) {
	fprintf(stderr, NLS_CATGETS(catfd, rarpSet, rarp_unkn_host, "rarp: %s: unknown host\n"), host);
	return(-1);
  }

  /* The host can have more than one address, so we loop on them. */
  i = -1;
  found = 0;
  while (hp->h_addr_list[++i] != NULL) {
	memset((char *) &req, 0, sizeof(req));
	si = (struct sockaddr_in *) &req.arp_pa;
	si->sin_family = hp->h_addrtype;
	memcpy((char *) &si->sin_addr, hp->h_addr_list[i], hp->h_length);

	/* Call the kernel. */
	if (ioctl(sockfd, SIOCDRARP, &req) < 0) {
		if (errno != ENXIO) {
			perror("SIOCDRARP");
			return(-1);
		} else continue;
	}
	found++;
  }

  if (found == 0) printf(NLS_CATGETS(catfd, rarpSet, rarp_noentry, "No ARP entry for %s\n"), hp->h_name);
  return(0);
}


/* Set an entry in the ARP cache. */
int arp_set(char *host, char *hw_addr)
{
  struct hostent *hp;
  struct arpreq req;
  struct sockaddr_in *si;
  unsigned char *ha;

  /* Resolve the host name. */
  if ((hp = gethostbyname(host)) == NULL) {
	fprintf(stderr, NLS_CATGETS(catfd, rarpSet, rarp_unkn_host, "rarp: %s: unknown host\n"), host);
	return(-1);
  }

  if ((ha = hardware->input(hw_addr)) == NULL) return(-1);

  /* Clear and fill in the request block. */
  memset((char *) &req, 0, sizeof(req));
  si = (struct sockaddr_in *) &req.arp_pa;
  si->sin_family = hp->h_addrtype;
  memcpy((char *) &si->sin_addr, hp->h_addr_list[0], hp->h_length);
  req.arp_ha.sa_family = hardware->type;
  memcpy(req.arp_ha.sa_data, ha, hardware->hlen);

  /* Call the kernel. */
  if (ioctl(sockfd, SIOCSRARP, &req) < 0) {
	perror("SIOCSRARP");
	return(-1);
  }
  return(0);
}


static void usage(void)
{
  fprintf(stderr, NLS_CATGETS(catfd, rarpSet, rarp_usage1,
	  "Usage: rarp -a                   List entries in cache.\n"));
  fprintf(stderr, NLS_CATGETS(catfd, rarpSet, rarp_usage2,
	  "       rarp -d hostname          Delete hostname from cache.\n"));
  fprintf(stderr, NLS_CATGETS(catfd, rarpSet, rarp_usage3,
	  "       rarp -s hostname hw_addr  Add hostname to cache.\n"));
  NLS_CATCLOSE(catfd)
  exit(-1);
}


void main(argc, argv)
int argc;
char **argv;
{
  int result=0;

#if NLS
  setlocale (LC_MESSAGES, "");
  catfd = catopen ("nettools", MCLoadBySet);
#endif

  /* Initialize variables... */
  hardware = get_type("ether");

  argv++;
  argc--;
  if(argc==0)
    usage();

 /* Fetch the command-line arguments. */

  if(argv[0][0]!='-')
    usage();

  if(argv[0][1]=='t')
    {
      if(argc<3)  /* Need -t, type, and then at least one further arg */
	usage();
	  
      hardware = get_type(argv[1]);
      if (hardware->type == -1) 
	{
	  fprintf(stderr, NLS_CATGETS(catfd, rarpSet, rarp_unkn_hw,
		  "rarp: %s: unknown hardware type.\n"), optarg);
	  NLS_CATCLOSE(catfd)
	  exit(-1);
	}
      argv+=2;
      argc-=2;

      if(argv[0][0]!='-')
	usage();
    }

  switch(argv[0][1]) 
    {
    case 'a':
      if(argc!=1)
	usage();
      result=system("cat /proc/net/rarp");  /* This is lazy, but who cares? */
      break;

    case 'd':
      if(argc!=2)
	usage();

      if ((sockfd = socket(AF_INET,SOCK_DGRAM,0)) <0)
	{
	  perror("socket");
	  NLS_CATCLOSE(catfd)
	  exit(-1);
	}

      result = arp_del(argv[1]);

      (void) close(sockfd);
      break;

    case 's':
      if(argc!=3)
	usage();

      if ((sockfd = socket(AF_INET,SOCK_DGRAM,0)) <0)
	{
	  perror("socket");
	  NLS_CATCLOSE(catfd)
	  exit(-1);
	}
      result = arp_set(argv[1],argv[2]);

      (void) close(sockfd);
      break;

    default:
      usage();
  }

  NLS_CATCLOSE(catfd)
  exit(result);
}

