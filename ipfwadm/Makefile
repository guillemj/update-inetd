#
#	$Id: Makefile,v 1.3 1996/06/17 10:29:53 jos Exp $
#
#
#	Makefile for the ipfwadm package
#
#
#	Copyright (c) 1996 by X/OS Experts in Open Systems BV.
#	All rights reserved.
#
#	Author: Jos Vos <jos@xos.nl>
#
#		X/OS Experts in Open Systems BV
#		Kruislaan 419
#		NL-1098 VA  Amsterdam
#		The Netherlands
#
#		E-mail: info@xos.nl
#		WWW:    http://www.xos.nl/
#
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
COPTS   = -O2 -I../debian
CFLAGS	= -Wall $(COPTS)
SBIN	= $(BASEDIR)/sbin
MANDIR	= $(BASEDIR)/usr/share/man
INSTALL = install

all:		ipfwadm ipfw.4 ipfwadm.8

ipfwadm:	ipfwadm.c
	$(CC) $(CFLAGS) -o ipfwadm ipfwadm.c

install:	ipfwadm ipfw.4 ipfwadm.8
#	-mv $(SBIN)/ipfwadm $(SBIN)/ipfwadm.old
	$(INSTALL) -m 0755 -o root -g root -s ipfwadm $(SBIN)/
	$(INSTALL) -m 0644 -o root -g root ipfw.4 $(MANDIR)/man4/
	$(INSTALL) -m 0644 -o root -g root ipfwadm.8 $(MANDIR)/man8/

clean:
	rm -f ipfwadm *.o core

ipfw.4:

ipfwadm.8:

