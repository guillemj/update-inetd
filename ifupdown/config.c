#line 961 "ifupdown.nw"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#line 971 "ifupdown.nw"
#include "header.h"
#line 1110 "ifupdown.nw"
#include <errno.h>
#line 1242 "ifupdown.nw"
#include <ctype.h>
#line 1087 "ifupdown.nw"
static int get_line(char **result, size_t *result_len, FILE *f);
#line 1311 "ifupdown.nw"
static char *next_word(char *buf, char *word, int maxlen);
#line 1444 "ifupdown.nw"
static address_family *get_address_family(address_family *af[], char *name);
#line 1479 "ifupdown.nw"
static method *get_method(address_family *af, char *name);
#line 1557 "ifupdown.nw"
static int duplicate_if(interface_defn *ifa, interface_defn *ifb);
#line 1035 "ifupdown.nw"
interface_defn *read_interfaces(char *filename) {
	
#line 1060 "ifupdown.nw"
FILE *f;
#line 1094 "ifupdown.nw"
char *buf = NULL;
size_t buf_len = 0;
#line 1292 "ifupdown.nw"
char scheme[80] = "*";
interface_defn *currif = NULL;
#line 1302 "ifupdown.nw"
char firstword[80];
char *rest;
#line 1037 "ifupdown.nw"
	interface_defn *ifaces = NULL;

	
#line 1064 "ifupdown.nw"
f = fopen(filename, "r");
if ( f == NULL ) return NULL;

#line 1041 "ifupdown.nw"
	while (
#line 1102 "ifupdown.nw"
get_line(&buf,&buf_len,f)
#line 1041 "ifupdown.nw"
                                             ) {
		
#line 1336 "ifupdown.nw"
rest = next_word(buf, firstword, 80);
if (rest == NULL) continue; /* blank line */

if (strcmp(firstword, "scheme") == 0) {
	
#line 1355 "ifupdown.nw"
rest = next_word(rest, scheme, 80);
if (!rest) {
	
#line 1640 "ifupdown.nw"
fprintf(stderr, "%s: scheme name missing\n", filename);
return NULL;
#line 1358 "ifupdown.nw"
}
#line 1341 "ifupdown.nw"
} else if (strcmp(firstword, "iface") == 0) {
	
#line 1366 "ifupdown.nw"
{
	
#line 1400 "ifupdown.nw"
char iface_name[80];
char address_family_name[80];
char method_name[80];

#line 1369 "ifupdown.nw"
	
#line 1388 "ifupdown.nw"
currif = malloc(sizeof(interface_defn));
if (!currif) {
	
#line 1635 "ifupdown.nw"
perror(filename);
return NULL;
#line 1391 "ifupdown.nw"
}

#line 1371 "ifupdown.nw"
	
#line 1406 "ifupdown.nw"
rest = next_word(rest, iface_name, 80);
rest = next_word(rest, address_family_name, 80);
rest = next_word(rest, method_name, 80);

if (rest == NULL) {
	
#line 1645 "ifupdown.nw"
fprintf(stderr, "%s: too few parameters for iface line\n", filename);
return NULL;
#line 1412 "ifupdown.nw"
}

if (rest[0] != '\0') {
	
#line 1650 "ifupdown.nw"
fprintf(stderr, "%s: too many parameters for iface line\n", filename);
return NULL;
#line 1416 "ifupdown.nw"
}

#line 1373 "ifupdown.nw"
	
#line 1423 "ifupdown.nw"
currif->iface = strdup(iface_name);
if (!currif->iface) {
	
#line 1635 "ifupdown.nw"
perror(filename);
return NULL;
#line 1426 "ifupdown.nw"
}    
#line 1374 "ifupdown.nw"
	
#line 1430 "ifupdown.nw"
currif->scheme = strdup(scheme);
if (!currif->scheme) {
	
#line 1635 "ifupdown.nw"
perror(filename);
return NULL;
#line 1433 "ifupdown.nw"
}
#line 1375 "ifupdown.nw"
	
#line 1448 "ifupdown.nw"
currif->address_family = get_address_family(addr_fams, address_family_name);
if (!currif->address_family) {
	
#line 1655 "ifupdown.nw"
fprintf(stderr, "%s: unknown address type\n", filename);
return NULL;
#line 1451 "ifupdown.nw"
}
#line 1376 "ifupdown.nw"
	
#line 1483 "ifupdown.nw"
currif->method = get_method(currif->address_family, method_name);
if (!currif->method) {
	
#line 1660 "ifupdown.nw"
fprintf(stderr, "%s: unknown method\n", filename);
return NULL;
#line 1486 "ifupdown.nw"
	return NULL; /* FIXME */
}
#line 1377 "ifupdown.nw"
	
#line 1506 "ifupdown.nw"
currif->automatic = 1;
currif->max_options = 0;
currif->n_options = 0;
currif->option = NULL;

#line 1379 "ifupdown.nw"
	
#line 1522 "ifupdown.nw"
currif->next = NULL;

if (ifaces == NULL) {
	ifaces = currif;
} else {
	interface_defn *checkif;
	checkif = ifaces; 
	for(;;) {
		if (duplicate_if(checkif, currif)) {
			
#line 1665 "ifupdown.nw"
fprintf(stderr, "%s: duplicate interface\n", filename);
return NULL;
#line 1532 "ifupdown.nw"
		}
		if (!checkif->next) break;
		checkif = checkif->next;
	}

	checkif->next = currif;
}
#line 1380 "ifupdown.nw"
}
#line 1343 "ifupdown.nw"
} else {
	
#line 1578 "ifupdown.nw"
if (!currif) {
	
#line 1670 "ifupdown.nw"
fprintf(stderr, "%s: option without interface\n", filename);
return NULL;
#line 1580 "ifupdown.nw"
} else {
	if (strcmp(firstword,"noauto") == 0) {
		currif->automatic = 0;
	} else {
		
#line 1594 "ifupdown.nw"
if (currif->n_options >= currif->max_options) {
	
#line 1616 "ifupdown.nw"
{
	variable *opt;
	currif->max_options = currif->max_options + 10;
	opt = realloc(currif->option, sizeof(variable) * currif->max_options);
	if (opt == NULL) {
		
#line 1635 "ifupdown.nw"
perror(filename);
return NULL;
#line 1622 "ifupdown.nw"
	}
	currif->option = opt;
}
#line 1596 "ifupdown.nw"
}

currif->option[currif->n_options].name = strdup(firstword);
currif->option[currif->n_options].value = strdup(rest);

if (!currif->option[currif->n_options].name) {
	
#line 1635 "ifupdown.nw"
perror(filename);
return NULL;
#line 1603 "ifupdown.nw"
}

if (!currif->option[currif->n_options].value) {
	
#line 1635 "ifupdown.nw"
perror(filename);
return NULL;
#line 1607 "ifupdown.nw"
}

currif->n_options++;	
#line 1585 "ifupdown.nw"
	}
}
#line 1345 "ifupdown.nw"
}
#line 1043 "ifupdown.nw"
	}
	if (
#line 1114 "ifupdown.nw"
errno != 0
#line 1044 "ifupdown.nw"
                                           ) {
		
#line 1635 "ifupdown.nw"
perror(filename);
return NULL;
#line 1046 "ifupdown.nw"
	}

	
#line 1069 "ifupdown.nw"
fclose(f);

#line 1050 "ifupdown.nw"
	return ifaces;
}
#line 1127 "ifupdown.nw"
static int get_line(char **result, size_t *result_len, FILE *f) {
	
#line 1152 "ifupdown.nw"
size_t pos;
#line 1129 "ifupdown.nw"
	
	do {
		
#line 1159 "ifupdown.nw"
pos = 0;
#line 1132 "ifupdown.nw"
		
#line 1170 "ifupdown.nw"
do {
	
#line 1189 "ifupdown.nw"
if (*result_len - pos < 10) {
	char *newstr = realloc(*result, *result_len * 2 + 80);
	if (newstr == NULL) {
		return 0;
	}
	*result = newstr;
	*result_len = *result_len * 2 + 80;
}
#line 1172 "ifupdown.nw"
	
#line 1218 "ifupdown.nw"
if (!fgets(*result + pos, *result_len - pos, f)) {
	if (errno == 0 && pos == 0) return 0;
	if (errno != 0) return 0;
}
pos += strlen(*result + pos);
#line 1173 "ifupdown.nw"
} while(
#line 1209 "ifupdown.nw"
pos == *result_len - 1 && (*result)[pos-1] != '\n'
#line 1173 "ifupdown.nw"
                                   );

#line 1230 "ifupdown.nw"
if (pos != 0 && (*result)[pos-1] == '\n') {
	(*result)[--pos] = '\0';
}

#line 1177 "ifupdown.nw"
assert( (*result)[pos] == '\0' );
#line 1133 "ifupdown.nw"
		
#line 1246 "ifupdown.nw"
{ 
	int first = 0; 
	while (isspace((*result)[first]) && (*result)[first]) {
		first++;
	}

	memmove(*result, *result + first, pos - first + 1);
	pos -= first;
}
#line 1134 "ifupdown.nw"
	} while (
#line 1270 "ifupdown.nw"
(*result)[0] == '#'
#line 1134 "ifupdown.nw"
                               );

	while (
#line 1274 "ifupdown.nw"
(*result)[pos-1] == '\\'
#line 1136 "ifupdown.nw"
                               ) {
		
#line 1278 "ifupdown.nw"
(*result)[--pos] = '\0';
#line 1138 "ifupdown.nw"
		
#line 1170 "ifupdown.nw"
do {
	
#line 1189 "ifupdown.nw"
if (*result_len - pos < 10) {
	char *newstr = realloc(*result, *result_len * 2 + 80);
	if (newstr == NULL) {
		return 0;
	}
	*result = newstr;
	*result_len = *result_len * 2 + 80;
}
#line 1172 "ifupdown.nw"
	
#line 1218 "ifupdown.nw"
if (!fgets(*result + pos, *result_len - pos, f)) {
	if (errno == 0 && pos == 0) return 0;
	if (errno != 0) return 0;
}
pos += strlen(*result + pos);
#line 1173 "ifupdown.nw"
} while(
#line 1209 "ifupdown.nw"
pos == *result_len - 1 && (*result)[pos-1] != '\n'
#line 1173 "ifupdown.nw"
                                   );

#line 1230 "ifupdown.nw"
if (pos != 0 && (*result)[pos-1] == '\n') {
	(*result)[--pos] = '\0';
}

#line 1177 "ifupdown.nw"
assert( (*result)[pos] == '\0' );
#line 1139 "ifupdown.nw"
	}

	
#line 1258 "ifupdown.nw"
while (isspace((*result)[pos-1])) { /* remove trailing whitespace */
	pos--;
}
(*result)[pos] = '\0';

#line 1143 "ifupdown.nw"
	return 1;
}
#line 1315 "ifupdown.nw"
static char *next_word(char *buf, char *word, int maxlen) {
	if (!buf) return NULL;
	if (!*buf) return NULL;

	while(!isspace(*buf) && *buf) {
		if (maxlen-- > 1) *word++ = *buf;
		buf++;
	}
	if (maxlen > 0) *word = '\0';

	while(isspace(*buf) && *buf) buf++;

	return buf;
}
#line 1460 "ifupdown.nw"
static address_family *get_address_family(address_family *af[], char *name) {
	int i;
	for (i = 0; af[i]; i++) {
		if (strcmp(af[i]->name, name) == 0) {
			return af[i];
		}
	}
	return NULL;
}
#line 1491 "ifupdown.nw"
static method *get_method(address_family *af, char *name) {
	int i;
	for (i = 0; i < af->n_methods; i++) {
		if (strcmp(af->method[i].name, name) == 0) {
			return &af->method[i];
		}
	}
	return NULL;
}
#line 1561 "ifupdown.nw"
static int duplicate_if(interface_defn *ifa, interface_defn *ifb) {
	if (strcmp(ifa->scheme, ifb->scheme) != 0) return 0;
	if (strcmp(ifa->iface, ifb->iface) != 0) return 0;
	if (ifa->address_family != ifb->address_family) return 0;
	return 1;
}
