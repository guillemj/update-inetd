#!/bin/sh
#
# start/stop inetd super server.

if ! [ -x /usr/sbin/inetd ]; then
	exit 0
fi

checkportmap () {
    if grep -v "^ *#" /etc/inetd.conf | grep 'rpc/' >/dev/null; then
        if ! /usr/bin/rpcinfo -u localhost portmapper >/dev/null 2>/dev/null
        then
            echo
            echo "WARNING: portmapper inactive - RPC services unavailable!"
            echo "         (Commenting out the rpc services in inetd.conf will"
	    echo "         disable this message)"
            echo
        fi
    fi
} 

case "$1" in
    start)
        checkportmap
	echo -n "Starting internet superserver:"
	echo -n " inetd" ; start-stop-daemon --start --quiet --pidfile /var/run/inetd.pid --exec /usr/sbin/inetd
	echo "."
	;;
    stop)
	echo -n "Stopping internet superserver:"
	echo -n " inetd" ; start-stop-daemon --stop --quiet --oknodo --pidfile /var/run/inetd.pid --exec /usr/sbin/inetd
	echo "."
	;;
    reload)
	echo -n "Reloading internet superserver:"
	echo -n " inetd"
	start-stop-daemon --stop --quiet --oknodo --pidfile /var/run/inetd.pid --signal 1 --exec /usr/sbin/inetd
	echo "."
	;;
    force-reload)
	$0 reload
	;;
    restart)
	echo -n "Restarting internet superserver:"
	echo -n " inetd"
	start-stop-daemon --stop --quiet --oknodo --pidfile /var/run/inetd.pid --exec /usr/sbin/inetd
	checkportmap
	start-stop-daemon --start --quiet --pidfile /var/run/inetd.pid --exec /usr/sbin/inetd
	echo "."
	;;
    *)
	echo "Usage: /etc/init.d/inetd {start|stop|reload|restart}"
	exit 1
	;;
esac

exit 0

