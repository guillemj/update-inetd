#line 1686 "ifupdown.nw"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "header.h"
#line 1923 "ifupdown.nw"
#include <errno.h>
#line 1750 "ifupdown.nw"
static char *parse(char *command, interface_defn *ifd);
#line 1797 "ifupdown.nw"
void addstr(char **buf, size_t *len, size_t *pos, char *str, size_t strlen);
#line 2004 "ifupdown.nw"
int strncmpz(char *l, char *r, size_t llen);
#line 2021 "ifupdown.nw"
char *get_var(char *id, size_t idlen, interface_defn *ifd);
#line 1706 "ifupdown.nw"
int execute(char *command, interface_defn *ifd, execfn *exec) { 
	char *out;
	int ret;

	out = parse(command, ifd);
	if (!out) { return 0; }

	ret = exec(out);
  
	free(out);
	return ret;
}
#line 1754 "ifupdown.nw"
static char *parse(char *command, interface_defn *ifd) {
	
#line 1779 "ifupdown.nw"
char *result = NULL;
size_t pos = 0, len = 0;
#line 1873 "ifupdown.nw"
size_t old_pos[MAX_OPT_DEPTH] = {0};
int okay[MAX_OPT_DEPTH] = {1};
int opt_depth = 1;

#line 1757 "ifupdown.nw"
	while(*command) {
		switch(*command) {
			
#line 1827 "ifupdown.nw"
default:
	addstr(&result, &len, &pos, command, 1);
	command++;
	break;
#line 1840 "ifupdown.nw"
case '\\':
	if (command[1]) {
		addstr(&result, &len, &pos, command+1, 1);
		command += 2;
	} else {
		addstr(&result, &len, &pos, command, 1);
		command++;
	}
	break;
#line 1888 "ifupdown.nw"
case '[':
	if (command[1] == '[' && opt_depth < MAX_OPT_DEPTH) {
		old_pos[opt_depth] = pos;
		okay[opt_depth] = 1;
		opt_depth++;
		command += 2;
	} else {
		addstr(&result, &len, &pos, "[", 1);
		command++;
	}
	break;
#line 1902 "ifupdown.nw"
case ']':
	if (command[1] == ']' && opt_depth > 1) {
		opt_depth--;
		if (!okay[opt_depth]) {
			pos = old_pos[opt_depth];
			result[pos] = '\0';
		}
		command += 2;
	} else {
		addstr(&result, &len, &pos, "]", 1);
		command++;
	}
	break;
#line 1957 "ifupdown.nw"
case '%':
{
	
#line 1982 "ifupdown.nw"
char *nextpercent;
#line 1960 "ifupdown.nw"
	char *varvalue;

	
#line 1986 "ifupdown.nw"
command++;
nextpercent = strchr(command, '%');
if (!nextpercent) {
	errno = EUNBALPER;
	free(result);
	return NULL;
}

#line 1964 "ifupdown.nw"
	
#line 2045 "ifupdown.nw"
varvalue = get_var(command, nextpercent - command, ifd);

#line 1966 "ifupdown.nw"
	if (varvalue) {
		addstr(&result, &len, &pos, varvalue, strlen(varvalue));
	} else {
		okay[opt_depth - 1] = 0;
	}

	
#line 1996 "ifupdown.nw"
command = nextpercent + 1;
#line 1973 "ifupdown.nw"
	
	break;
}
#line 1760 "ifupdown.nw"
		}
	}

	
#line 1932 "ifupdown.nw"
if (opt_depth > 1) {
	errno = EUNBALBRACK;
	free(result);
	return NULL;
}

if (!okay[0]) {
	errno = EUNDEFVAR;
	free(result);
	return NULL;
}

#line 1765 "ifupdown.nw"
	
#line 1786 "ifupdown.nw"
return result;
#line 1766 "ifupdown.nw"
}
#line 1801 "ifupdown.nw"
void addstr(char **buf, size_t *len, size_t *pos, char *str, size_t strlen) {
	assert(*len >= *pos);
	assert(*len == 0 || (*buf)[*pos] == '\0');

	if (*pos + strlen >= *len) {
		char *newbuf;
		newbuf = realloc(*buf, *len * 2 + strlen + 1);
		if (!newbuf) {
			perror("realloc");
			exit(1); /* a little ugly */
		}
		*buf = newbuf;
		*len = *len * 2 + strlen + 1;
	}
	
	while (strlen-- >= 1) {
		(*buf)[(*pos)++] = *str;
		str++;
	}
	(*buf)[*pos] = '\0';
}
#line 2008 "ifupdown.nw"
int strncmpz(char *l, char *r, size_t llen) {
	int i = strncmp(l, r, llen);
	if (i == 0)
		return -r[llen];
	else
		return i;
}
#line 2025 "ifupdown.nw"
char *get_var(char *id, size_t idlen, interface_defn *ifd) {
	int i;

	if (strncmpz(id, "iface", idlen) == 0) {
		return ifd->iface;
	} else {
		for (i = 0; i < ifd->n_options; i++) {
			if (strncmpz(id, ifd->option[i].name, idlen) == 0) {
				return ifd->option[i].value;
			}
		}
	}

	return NULL;
}
