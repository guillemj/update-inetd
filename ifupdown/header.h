#line 73 "ifupdown.nw"
#ifndef HEADER_H
#define HEADER_H

#line 335 "ifupdown.nw"
typedef struct address_family address_family;
#line 368 "ifupdown.nw"
typedef struct method method;
#line 990 "ifupdown.nw"
typedef struct interface_defn interface_defn;
#line 1015 "ifupdown.nw"
typedef struct variable variable;
#line 384 "ifupdown.nw"
typedef int (execfn)(char *command);
typedef int (command_set)(interface_defn *ifd, execfn *e);
#line 339 "ifupdown.nw"
struct address_family {
	char *name;
	int n_methods;
	method *method;
};
#line 372 "ifupdown.nw"
struct method {
	char *name;
	command_set *up, *down;
};
#line 994 "ifupdown.nw"
struct interface_defn {
	interface_defn *next;

	char *iface;
	char *scheme;
	address_family *address_family;
	method *method;

	int automatic;

	int max_options;
	int n_options;
	variable *option;
};
#line 1019 "ifupdown.nw"
struct variable {
	char *name;
	char *value;
};
#line 1869 "ifupdown.nw"
#define MAX_OPT_DEPTH 10
#line 1927 "ifupdown.nw"
#define EUNBALBRACK 10001
#define EUNDEFVAR   10002
#line 1952 "ifupdown.nw"
#define MAX_VARNAME   32
#define EUNBALPER   10000
#line 351 "ifupdown.nw"
extern address_family *addr_fams[];
#line 1031 "ifupdown.nw"
interface_defn *read_interfaces(char *filename);
#line 1699 "ifupdown.nw"
int execute(char *command, interface_defn *ifd, execfn *exec);

#line 82 "ifupdown.nw"
#endif /* HEADER_H */
