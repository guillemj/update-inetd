#!/bin/sh
#
# start/stop networking daemons.

test -f /sbin/portmap || exit 0

spoofprotect () {
    # This is the best method: turn on Source Address Verification and get
    # spoof protection on all current and future interfaces.
    if [ -e /proc/sys/net/ipv4/conf/all/rp_filter ]; then
	echo -n "Setting up IP spoofing protection..."
	for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
	    echo 1 > $f
	done
	echo "done."
    # rules for linux 2.0.x and 2.1.x (x < 102) kernels
    elif [ -e /proc/net/ip_input ]; then
        echo -n "Setting up IP spoofing protection..."
	# delete and readd entry (this way we don't get duplicate entries)

	# deny incoming packets pretending to be from 127.0.0.1
        ipfwadm -I -d deny -o -P all -S 127.0.0.0/8 -W eth0 -D 0/0 2>/dev/null || true
        ipfwadm -I -d deny -o -P all -S 127.0.0.0/8 -W eth1 -D 0/0 2>/dev/null || true
        ipfwadm -I -i deny -o -P all -S 127.0.0.0/8 -W eth0 -D 0/0 >/dev/null
        ipfwadm -I -i deny -o -P all -S 127.0.0.0/8 -W eth1 -D 0/0 >/dev/null

	# deny incoming packets pretending to be from our own system.
	# set your own IP address below (or use `hostname -i` to set it).
#	my_ip=192.168.14.1
#	ipfwadm -I -d deny -o -P all -S $my_ip -W eth0 -D 0/0 2>/dev/null || true
#	ipfwadm -I -d deny -o -P all -S $my_ip -W eth1 -D 0/0 2>/dev/null || true
#	ipfwadm -I -a deny -o -P all -S $my_ip -W eth0 -D 0/0 >/dev/null
#	ipfwadm -I -a deny -o -P all -S $my_ip -W eth1 -D 0/0 >/dev/null
	echo "done."
    # rules for linux 2.1.x (x > 101) kernels
    elif [ -e /proc/net/ip_fwchains ]; then
        echo -n "Setting up IP spoofing protection..."
	ipchains -D input -j DENY -l -s 127.0.0.0/8 -i ! lo 2>/dev/null || true
	ipchains -A input -j DENY -l -s 127.0.0.0/8 -i ! lo

	# deny incoming packets pretending to be from our own system.
	# set your own IP address below (or use `hostname -i` to set it).
#	my_ip=192.168.14.1
#	ipchains -D input -j DENY -l -s $my_ip -i ! lo 2>/dev/null || true
#	ipchains -A input -j DENY -l -s $my_ip -i ! lo
	echo "done."
    fi
}


case "$1" in
    start)
	spoofprotect
	echo -n "Starting base networking daemons:"
	echo -n " portmap" ; start-stop-daemon --start --quiet --exec /sbin/portmap
	echo -n " inetd" ; start-stop-daemon --start --quiet --exec /usr/sbin/inetd
	echo "."
	;;
    stop)
	start-stop-daemon --stop --quiet --oknodo --pidfile /var/run/inetd.pid --exec /usr/sbin/inetd
	start-stop-daemon --stop --quiet --oknodo --exec /sbin/portmap
	;;
    reload)
	start-stop-daemon --stop --quiet --oknodo --pidfile /var/run/inetd.pid --signal 1 --exec /usr/sbin/inetd
	;;
    restart)
	start-stop-daemon --stop --quiet --oknodo --pidfile /var/run/inetd.pid --exec /usr/sbin/inetd
	pmap_dump >/var/run/portmap.state
	start-stop-daemon --stop --quiet --oknodo --exec /sbin/portmap
	start-stop-daemon --start --quiet --exec /sbin/portmap
	if [ -f /var/run/portmap.upgrade-state ]; then
	  pmap_set </var/run/portmap.upgrade-state
	elif [ -f /var/run/portmap.state ]; then
	  pmap_set </var/run/portmap.state
	fi
	rm -f /var/run/portmap.upgrade-state /var/run/portmap.state
	start-stop-daemon --start --quiet --exec /usr/sbin/inetd
	;;
    *)
	echo "Usage: /etc/init.d/netbase {start|stop|reload|restart}"
	exit 1
	;;
esac

exit 0

