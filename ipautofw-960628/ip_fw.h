/*
 *	IP autofw definitions
 */
 
#ifndef _IP_AUTOFW_H
#define _IP_AUTOFW_H

#include <asm/types.h>

/* if <netinet/ip_fw.h> doesn't include IP_AUTOFW support we'll add it here */
#ifndef IP_FW_AUTOFW
#define IP_FW_AUTOFW		5

#define IP_AUTOFW_ADD		(IP_FW_APPEND | (IP_FW_AUTOFW << IP_FW_SHIFT))
#define IP_AUTOFW_DEL		(IP_FW_DELETE | (IP_FW_AUTOFW << IP_FW_SHIFT))
#define IP_AUTOFW_FLUSH  	(IP_FW_FLUSH  | (IP_FW_AUTOFW << IP_FW_SHIFT))

#define IP_FWD_RANGE 		1
#define IP_FWD_PORT		2
#define IP_FWD_DIRECT		3

#define IP_AUTOFW_ACTIVE	1
#define IP_AUTOFW_USETIME	2
#define IP_AUTOFW_SECURE	4

struct ip_autofw {
	struct ip_autofw * next;
	__u16 type;
	__u16 low;
	__u16 hidden;
	__u16 high;
	__u16 visible;
	__u16 protocol;
	__u32 lastcontact;
	__u32 where;
	__u16 ctlproto;
	__u16 ctlport;
	__u16 flags;
	struct timer_list timer;
};

#endif /* IP_FW_AUTOFW */

#endif /* _IP_AUTOFW_H */
