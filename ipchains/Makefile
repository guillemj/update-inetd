#
#	Makefile for the ipchain package: ripped straight from ipfwadm.
#	(C) Paul Russell 1998 All rights reserved.
#       EMail complaints to ipchains@wantree.com.au.
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; either version 2 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

CC	= gcc
COPTS   = -g -O2
CFLAGS	= -Wall -Wunused $(COPTS)
SBIN	= $(BASEDIR)/sbin
MANDIR	= $(BASEDIR)/usr/share/man
INSTALL = install
TEX	= latex

all:		ipchains ipfw.4 ipchains.8

ipchains:	libipfwc/libipfwc.a libipfwc/libipfwc.h ipchains.c libipfwc/ipfwc_kernel_headers.h
	$(CC) $(CFLAGS) -o ipchains ipchains.c libipfwc/libipfwc.a

install:	ipchains ipfw.4 ipchains.8
#	@-mv $(SBIN)/ipchains $(SBIN)/ipchains.old
	$(INSTALL) -m 0755 -o root -g root ipchains $(SBIN)/
	$(INSTALL) -m 0644 -o root -g root ipfw.4 $(MANDIR)/man4/ipfw_chains.4
	$(INSTALL) -m 0644 -o root -g root ipchains.8 $(MANDIR)/man8/
	$(INSTALL) -m 0644 -o root -g root HOWTO.txt $(BASEDIR)/usr/share/doc/netbase/ipchains-HOWTO.txt
	$(INSTALL) -m 0644 -o root -g root ipchains-quickref.ps $(BASEDIR)/usr/share/doc/netbase/ipchains-quickref.ps

uninstall:
	-rm -f $(SBIN)/ipchains $(MANDIR)/man4/ipfw.4 $(MANDIR)/man8/ipchains.8
	@-mv $(SBIN)/ipchains.old $(SBIN)/ipchains && echo Restored old ipchains from $(SBIN)/ipchains.old...

libipfwc/libipfwc.a:
	cd libipfwc/ && $(MAKE) libipfwc.a

distclean: clean
	rm -f HOWTO.txt

subclean:
	cd libipfwc/ && $(MAKE) clean

clean: subclean
	rm -f ipchains *.o core `ls HOWTO* | grep -v HOWTO.sgml | grep -v HOWTO.txt` *~
