SBIN   = $(BASEDIR)/sbin
MANDIR = $(BASEDIR)/usr/man
INSTALL = install

all:

install:
	$(INSTALL) -m 0755 -o root -g root ipchains-save $(SBIN)/
	$(INSTALL) -m 0755 -o root -g root ipchains-restore $(SBIN)/
	$(INSTALL) -m 0755 -o root -g root ipfwadm-wrapper $(SBIN)/
	$(INSTALL) -m 0644 -o root -g root ipfwadm-wrapper.8 $(MANDIR)/man8/
	$(INSTALL) -m 0644 -o root -g root ipchains-restore.8 $(MANDIR)/man8/
	$(INSTALL) -m 0644 -o root -g root ipchains-save.8 $(MANDIR)/man8/

clean:

