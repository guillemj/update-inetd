#line 2064 "ifupdown.nw"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>

#include "header.h"
#line 2292 "ifupdown.nw"
#include <fnmatch.h>

#line 2076 "ifupdown.nw"
static int check(char *str);
#line 2086 "ifupdown.nw"
static int doit(char *str);
#line 2097 "ifupdown.nw"
static int printit(char *str);
#line 2109 "ifupdown.nw"
static int execute_all(interface_defn *ifd, int(*exec)(char*), char *opt);
#line 2127 "ifupdown.nw"
static int up(interface_defn *iface, int (*exec)(char*));
#line 2131 "ifupdown.nw"
static int up(interface_defn *iface, int (*exec)(char*));
#line 2145 "ifupdown.nw"
static int down(interface_defn *iface, int (*exec)(char*));
#line 2080 "ifupdown.nw"
static int check(char *str) {
	return str != NULL;
}
#line 2090 "ifupdown.nw"
static int doit(char *str) {
	if (system(str) == 0) return 1;
	else                  return 0;
}
#line 2101 "ifupdown.nw"
static int printit(char *str) {
	printf("  %s\n", str); fflush(stdout);
	return 1;
}
#line 2113 "ifupdown.nw"
static int execute_all(interface_defn *ifd, int(*exec)(char*), char *opt) {
	int i;
	for (i = 0; i < ifd->n_options; i++) {
		if (strcmp(ifd->option[i].name, opt) == 0) {
			if (!exec(ifd->option[i].value)) {
				return 0;
			}
		}
	}
	return 1;
}
#line 2135 "ifupdown.nw"
static int up(interface_defn *iface, int (*exec)(char*)) {
	if (!execute_all(iface,exec,"pre-up")) return 0;
	if (!iface->method->up(iface,exec)) return 0;
	if (!execute_all(iface,exec,"up")) return 0;

	return 1;
}
#line 2149 "ifupdown.nw"
static int down(interface_defn *iface, int (*exec)(char*)) {
	if (!execute_all(iface,exec,"down")) return 0;
	if (!iface->method->down(iface,exec)) return 0;
	if (!execute_all(iface,exec,"post-down")) return 0;

	return 1;
}
#line 2224 "ifupdown.nw"
static void usage(void) {
	fprintf(stderr, "Use --help for help\n");
	exit(1);
}
#line 2231 "ifupdown.nw"
static void help(char *execname) {
	printf("Usage: %s -anvsh -i<file> <ifaces...>\n\n", execname);
	printf("\t-a --all\t\tde/configure all interfaces automatically\n");
	printf("\t-s --scheme SCHEME\tuse SCHEME as scheme\n");
	printf("\t-h --help\t\tthis help\n");
	printf("\t-i --interfaces FILE\tuse FILE for interface definitions\n");
	printf("\t-n --no-act\t\tprint out what would happen, but don't do it\n");
	printf("\t-v --verbose\t\tprint out what would happen before doing it\n");
	exit(0);
}

#line 2159 "ifupdown.nw"
int main(int argc, char **argv) {
	int i;

	char *interfaces = "/etc/network/interfaces";
  
	interface_defn *ifaces = NULL;
	interface_defn *currif = NULL;

	
#line 2184 "ifupdown.nw"
int (*cmds)(interface_defn *, int (*exec)(char*)) = NULL;
char *command;
#line 2207 "ifupdown.nw"
struct option long_opts[] = {
	{"scheme",     required_argument, NULL, 's'},
	{"help",       no_argument,       NULL, 'h'},
	{"verbose",    no_argument,       NULL, 'v'},
	{"all",        no_argument,       NULL, 'a'},
	{"interfaces", required_argument, NULL, 'i'},
	{"no-act",     no_argument,       NULL, 'n'},
	{0,0,0,0}
};

int do_all = 0;
int no_act = 0;
int verbose = 0;
char *real_scheme = "*";

#line 2169 "ifupdown.nw"
	
#line 2189 "ifupdown.nw"
command = strrchr(argv[0],'/');
if (command == NULL) {
	command = argv[0];
} else {
	command++;
}

if (strcmp(command, "ifup")==0) {
	cmds = up;
} else if (strcmp(command, "ifdown")==0) {
	cmds = down;
} else {
	fprintf(stderr,"This command should be called as ifup or ifdown\n");
	exit(1);
}
#line 2170 "ifupdown.nw"
	
#line 2244 "ifupdown.nw"
for (;;) {
	int c;
	c = getopt_long(argc, argv, "s:i:hvna", long_opts, NULL);
	if (c == EOF) break;

	switch(c) {
		case 's':
			real_scheme = strdup(optarg);
			break;
		case 'i':
			interfaces = strdup(optarg);
			break;
		case 'h':
			help(argv[0]);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'a':
			do_all = 1;
			break;
		case 'n':
			no_act = 1;
			break;
		default:
			usage();
			break;
	}
}

if (argc - optind == 0 && !do_all) {
	usage();
}

if (argc - optind > 0 && do_all) {
	usage();
}

#line 2172 "ifupdown.nw"
	ifaces = read_interfaces(interfaces);
	if ( !ifaces ) {
		exit(1);
	}

	
#line 2284 "ifupdown.nw"
if (do_all) {
	
#line 2316 "ifupdown.nw"
for (currif = ifaces; currif; currif = currif->next) {
	if (!currif->automatic 
		|| fnmatch(currif->scheme, real_scheme, 0) != 0) 
	{
		continue;
	}

	
#line 2328 "ifupdown.nw"
if ( !cmds(currif,check) ) {
	printf("Don't seem to be have all the variables for %s.\n", currif->iface);
} else {
	if (no_act || verbose) {
		cmds(currif,printit);
	}
	if (!no_act) {
		cmds(currif,doit);
	}
}
#line 2324 "ifupdown.nw"
}
#line 2286 "ifupdown.nw"
} else {
	
#line 2296 "ifupdown.nw"
for (i = optind; i < argc; i++) {
	int okay;
	okay = 0;
	for (currif = ifaces; currif; currif = currif->next) {
		if (strcmp(argv[i],currif->iface) == 0 
			&& fnmatch(currif->scheme, real_scheme, 0) == 0) 
		{
			okay = 1;
			
#line 2328 "ifupdown.nw"
if ( !cmds(currif,check) ) {
	printf("Don't seem to be have all the variables for %s.\n", currif->iface);
} else {
	if (no_act || verbose) {
		cmds(currif,printit);
	}
	if (!no_act) {
		cmds(currif,doit);
	}
}
#line 2305 "ifupdown.nw"
			/* break; */
		}
	}
	if (!okay) {
		fprintf(stderr, "Ignoring unknown interface %s.\n",
			argv[i]);
	}
}
#line 2288 "ifupdown.nw"
}
#line 2178 "ifupdown.nw"
  
	return 0;
}
