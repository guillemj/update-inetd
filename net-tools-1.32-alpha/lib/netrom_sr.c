#include "config.h"

#if HAVE_AFNETROM
#include <sys/param.h>
#include <sys/types.h>
#if defined(__GLIBC__)
#define _SOCKETBITS_H
#endif /* __GLIBC__ */
#include <sys/socket.h>
#if !defined(__GLIBC__)
#include <netinet/in.h>
#else /* __GLIBC__ */
#include <linux/in.h>
#define _NETINET_IN_H
#endif /* __GLIBC__ */
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <linux/route.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "version.h"
#include "net-support.h"
#include "pathnames.h"
#define  EXTERN
#include "net-locale.h"

#include "net-features.h"

extern     struct aftype   netrom_aftype;

/* static int skfd = -1; */

static int usage(void)
{
  fprintf(stderr,"netrom usage\n");

  return(E_USAGE);
}


int NETROM_rinput(int action, int ext, char **args)
{
  
  fprintf(stderr,"NET/ROM: this needs to be written\n");
  return(0);
}
#endif	/* HAVE_AFNETROM */
