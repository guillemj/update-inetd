.PRECIOUS: %.o %_sh.o

ifndef $(KSRC)
KSRC :=/usr
endif

SBIN := $(DESTDIR)/usr/sbin
REALLIBDIR := /usr/lib/ipmasqadm
LIBDIR := $(BASEDIR)$(REALLIBDIR)
MANDIR := $(DESTDIR)/usr/share/man
CC := gcc 
CFLAGS += -Wall -O2 -I $(KSRC)/include -I../include $(XCFLAGS) -fPIC -DLIBDIR=\"$(REALLIBDIR)\"

SH_CFLAGS := $(CFLAGS) -fPIC
LIBMASQ := ip_masq
LDLIBS := $(XLDFLAGS) -ldl -l$(LIBMASQ)
LDFLAGS := -L../lib
SH_LDFLAGS := $(LDFLAGS)
SH_LDLIBS := $(LDLIBS)
