# Makefile for ipchains-scripts
# Suggested by Brian Finley.

ifndef BINDIR
BINDIR:=$(BASEDIR)/sbin/
endif
ifndef MANDIR
MANDIR:=$(BASEDIR)/usr/share/man/man8/
endif

all:
	true

default:
	@echo Use \`make install\' to install scripts in $(BINDIR),
	@echo and man pages in $(MANDIR).
	@echo Override these by setting \$$BINDIR and \$$MANDIR.
	@exit 1

install:
	cp ipchains-restore ipchains-save ipfwadm-wrapper $(BINDIR)
	cp *.8 $(MANDIR)

clean:
	true
