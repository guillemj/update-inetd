all: ping

include ../MCONFIG
include ../MRULES

ifneq ($(USE_GLIBC),1)
CFLAGS += -D_GNU_SOURCE
endif

ping:	ping.o
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

install: ping
	install -s -o root -m$(SUIDMODE) ping $(INSTALLROOT)$(ROOTBINDIR)
	install -m$(MANMODE) ping.8 $(INSTALLROOT)$(MANDIR)/man8

clean:
	rm -f *.o ping

