Template: netbase/upgrade-note/radius-ports-pre-3.05
Type: note
Description: Important hint for users of radius software
 The official port numbers of the radius service have been changed
 from 1645 and 1646 to 1812 and 1813. If you use the radius service
 please make sure that the client and server software both use the
 same port numbers.
Description-ru: ������ ��������� ��� ������������� radius
 ����������� ������ ������ ������� radius ���� �������� � 1645 � 1646 ��
 1812 � 1813. ���� �� ����������� radius, �� ��������������, ��� � ����������,
 � ��������� ����������� ����������� ���������� ���������� ������ ������.

Template: netbase/upgrade-note/portmap-restart-pre-3.11-2
Type: note
Description: The old portmapper is still running.
 The old portmapper is still running. This will cause problems, mainly that
 "/etc/init.d/portmap stop" won't actually do anything. To fix this, I'm
 going to try to forcibly stop portmap, and then restart it.
Description-ru: ������ portmapper �������� ����������. 
 ������ portmapper �������� ����������. ��� ����� �������� � ���������,
 � �������� ��-�� ����, ��� "/etc/init.d/portmap stop" � ����������������
 �� ����� ���-���� ������. ����� ��� ���������, ����� �������������
 ������� portmap � ����� ������������� ���.

Template: netbase/upgrade-note/init.d-split-pre-3.16-1
Type: note
Description: /etc/init.d/netbase has been split.
 /etc/init.d/netbase is no longer required or used.
 .
 /etc/init.d/portmap (provided by the portmap package) now handles
 stopping and starting the portmapper, /etc/init.d/inetd (provided by
 the netkit-inetd package) handles stopping and starting inetd, and
 /etc/init.d/networking handles spoof protection.
Description-ru: /etc/init.d/netbase ��� ��������.
 /etc/init.d/netbase ������ �� ��������� � �� ������������.
 .
 �������� � ���������� portmapper`� ������ ���������� /etc/init.d/portmap
 (������������ � ������ portmap), /etc/init.d/inetd (������������ � ������
 netkit-inetd) ����������� ��������� � ������ inetd, �
 /etc/init.d/networking ���������� ������� �� �������� �������.

Template: netbase/upgrade-note/etc-network-interfaces-pre-3.17-1
Type: note
Description: /etc/init.d/network superceded by /etc/network/interfaces
 /etc/init.d/network is no longer directly supported. You may, of course,
 continue using it to setup your networking, however new Debian installs
 will use the ifup/ifdown commands to configure network interfaces based
 on the settings in /etc/network/interfaces.
 .
 If you do convert to using /etc/network/interfaces in place of
 /etc/init.d/network you will probably want to remove /etc/init.d/network
 and the /etc/rcS.d/S40network symlink. These will not be touched by
 netbase or other Debian packages in future.
 .
 Note that the old default /etc/init.d/network used to add a route for the
 loopback interface. This is no longer necessary for 2.2.x series kernels,
 and will result in a (non-fatal) SIOCADDRT error message at bootup.
Description-ru: /etc/init.d/network ������� ������ /etc/network/interfaces
 /etc/init.d/network ������ �� �������������� ��������. �������, �� ������,
 ���������� �� ������������ ��� ��������� ����� ����, ������ ����� �����������
 Debian ����� ������������ ��� ��������� ������� ����������� �������
 ifup/ifdown, ������� ������ ��������� �� ����� /etc/network/interfaces.
 .
 ���� �� ����������� �������������� ��� ���������� /etc/network/interfaces
 ������ /etc/init.d/network, �� �������� �� �������� ������� ����
 /etc/init.d/network � ������������� ����� /etc/rcS.d/S40network. ��� ��������
 �� ����� ��������������� ������� netbase ��� ������� �������� Debian � �������.
 .
 �������� ��������, �� ��, ��� ������ ���� /etc/init.d/network ������������ ���
 ���������� �������� ��� ���������� loopback. ��� ����� �� ��������� ��� ����
 ����� 2.2.x, � ����� ��������� � ������ ��������� � (�����������) ������ SIOCADDRT.

Template: netbase/ipv6-hosts
Type: boolean
Default: true
Description: Would you like IPv6 addresses added to /etc/hosts?
 Sooner or later, Debian will include out-of-the box support
 for IPv6 (see http://www.ipv6.org/). As such, you might like
 to start playing with this, and seeing what things break as
 we try to add support for IPv6.
Description-ru: �� ������ �� �������� ������ IPv6 � ���� /etc/hosts?
 ������ ��� �����, �� Debian ����� �������� ��������� "�� �������"
 ��������� IPv6 (��. http://www.ipv6.org/). � ����� � ���� ��� ��������
 ��������� ��� ������ ���������� � ����������, ��� � ��� ���������, ���� 
 �������� ��������� IPv6.

Template: netbase/spoofprot
Type: note
Description: Spoof protection for pre-2.2 kernels
 If you are running a pre-2.2 series kernel, IP spoof 
 protection cannot be enabled without special configuration,
 found in /etc/network/spoof-protect and provided by answering
 the following questions. 
 .
 For 2.2.x and later kernels, this information will be determined
 automatically at boot time, so you don't need to enter anything here
 unless you also use pre-2.2 kernels.
Description-ru: ������ �� �������� IP ������� ��� ���� ������ �� 2.2
 ���� �� ����������� ����� ������ �� 2.2, �� ������ �� �������� IP ������� 
 �� ����� ���� �������� ��� ����������� ���������, ����������� � �����
 /etc/network/spoof-protect � ��������������� ����� ������ �� ���������
 ����� �������.
 .
 ��� ���� 2.2 � ����� ������� ��� ���������� ������������ �������������
 ��� �������� �������, ��� ��� ��� ������ �� ����� ������ ����������, ����
 ������ �� �� ����������� ���� ������ �� 2.2.

Template: netbase/spoofprot/pre-2.2-ip
Type: string
Default: 127.0.0.1/8
Description: What IP addresses (or address ranges) should be considered local?
 IP addresses and ranges should be listed in any order, and separated by 
 spaces. Addresses should be specified as a dotted quad, while ranges should
 be specified in CIDR-style. So the class C network 192.168.42.0-192.168.42.255
 would be specified as 192.168.42.0/24.
Description-ru: ����� IP ������ (��� �������� ������������) ������ ��������� ����������?
 IP ������ � ������������ ������ ����������� � ����� ������� � ����������� ���������.
 ������������ ���� ������� � �������� �������, ������������ ������� ����������� �
 CIDR-�����. ��� ���� ������ C 192.168.42.0-192.168.42.255 ������ ���� ������� ���
 192.168.42.0/24.

Template: netbase/spoofprot/pre-2.2-interfaces
Type: string
Default: eth0 eth1 ppp0
Description: What remote interfaces does this host have?
Description-ru: ����� ��������� ���������� ������ ����� ���� ����?
