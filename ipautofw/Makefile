CC	= gcc
CFLAGS	= -Wall -O2 -I../debian -I/usr/src/linux/include
SBIN	= $(BASEDIR)/usr/sbin

all:		ipautofw

ipautofw: ipautofw-2.0.0.c
	$(CC) $(CFLAGS) -o ipautofw ipautofw-2.0.0.c

install:	ipautofw
#	-mv $(SBIN)/ipautofw $(SBIN)/ipautofw.old
	install -o root -g root -m 0755 ipautofw $(SBIN)/ipautofw
	install -o root -g root -m 0644 README $(BASEDIR)/usr/share/doc/netbase/ipautofw.txt

clean:
	rm -f *.o ipautofw core

install-kernel:
	cp ipautofw-2.0.0.diff /usr/src
	cd /usr/src/linux
	patch -p1 < ../ipautofw-2.0.0.diff

archive:
	cd ../.. && tar -cf - ipautofw/ | gzip -9 > /root/scootdir/rlynch.ftp/ipautofw-`date +%y%m%d`.tar.gz

