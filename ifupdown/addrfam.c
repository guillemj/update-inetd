#line 393 "ifupdown.nw"
#include <stdlib.h>
#include "header.h"

#line 2394 "ifupdown.nw"
extern address_family addr_inet;
#line 2522 "ifupdown.nw"
extern address_family addr_inet6;
#line 2543 "ifupdown.nw"
extern address_family addr_ipx;

#line 398 "ifupdown.nw"
address_family *addr_fams[] = {
	
#line 2398 "ifupdown.nw"
&addr_inet, 
#line 2526 "ifupdown.nw"
&addr_inet6,
#line 2547 "ifupdown.nw"
&addr_ipx,
#line 400 "ifupdown.nw"
	NULL
};
