#!/bin/sh
#
# Start networking daemons.

test -f /usr/sbin/portmap || exit 0

case "$1" in
  start)
	echo -n "Starting base networking daemons:"
	echo -n " portmap" ; start-stop-daemon --start --quiet --exec /usr/sbin/portmap
	echo -n " inetd" ; start-stop-daemon --start --quiet --exec /usr/sbin/inetd
	echo "."
	;;
  stop)
	start-stop-daemon --stop --quiet --oknodo --pidfile /var/run/inetd.pid --exec /usr/sbin/inetd
	start-stop-daemon --stop --quiet --oknodo --exec /usr/sbin/portmap
	killall -9 slattach 2>/dev/null || exit 0
	;;
  reload)
	start-stop-daemon --stop --quiet --oknodo --pidfile /var/run/inetd.pid --signal 1 --exec /usr/sbin/inetd
	;;
  restart)
	start-stop-daemon --stop --quiet --oknodo --pidfile /var/run/inetd.pid --exec /usr/sbin/inetd
	pmap_dump >/var/run/portmap.state
	start-stop-daemon --stop --quiet --oknodo --exec /usr/sbin/portmap
	start-stop-daemon --start --quiet --exec /usr/sbin/portmap
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

