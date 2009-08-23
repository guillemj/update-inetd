#!/usr/bin/python

# basic command-line testing of update-inetd(8)
# Copyright (C) 2009 Serafeim Zanikolas <serzan@hellug.gr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


from commands import getstatusoutput
from tempfile import mktemp
import unittest
import os
import sys

quiet = False

inetd_conf =\
"""
# /etc/inetd.conf:  see inetd(8) for further informations.
#
# Internet superserver configuration database
#
#
# Lines starting with "#:LABEL:" or "#<off>#" should not
# be changed unless you know what you are doing!
#
# If you want to disable an entry so it isn't touched during
# package updates just comment it out with a single '#' character.
#
# Packages should modify this file by using update-inetd(8)
#
# <service_name> <sock_type> <proto> <flags> <user> <server_path> <args>
#
#:INTERNAL: Internal services
#discard		stream	tcp	nowait	root	internal
#discard		dgram	udp	wait	root	internal
#<off># daytime		stream	tcp	nowait	root	internal
time		stream	tcp	nowait	root	internal
#time2		stream	tcp	nowait	root	internal

#:STANDARD: These are standard services.

#:BSD: Shell, login, exec and talk are BSD protocols.

#:MAIL: Mail, news and uucp services.

#:INFO: Info services

#:BOOT: TFTP service is provided primarily for booting.  Most sites
#       run this only on machines acting as "boot servers."

#:RPC: RPC based services

#:HAM-RADIO: amateur-radio services

#:OTHER: Other services
"""

conffile = mktemp()
cmdline = "perl -I. update-inetd --file %s --verbose" % conffile
cmdline = "./update-inetd --file %s --verbose" % conffile

def run(cmd):
    if not quiet:
        print 'running "%s"' % cmd
    status, output = getstatusoutput(cmd)
    if status != 0:
        raise AssertionError("the command '%s' failed" % cmd)
    return output

class UpdateInetdTest(unittest.TestCase):
    """
    Try 2 test cases per mode: one that is actually effective (eg, adds,
    modifies or removes a line) and one that isn't (because the matching entry
    is commented out with '#'). Test success by matching expected messages in
    verbose mode, and patterns in the supplied inetd.conf.
    """
    def setUp(self):
        try:
            f = open(conffile, "w")
            f.write(inetd_conf)
            f.close()
        except IOError:
            sys.stderr.write("failed to create tempfile %s\n" % conffile)
            sys.exit(1)
    def grep(self, string, output):
        if string not in output:
            raise AssertionError("Expected string \"%s\"\n was not found in update-inet's output:\n%s"
                    % (string, output))
    def testEffectiveEnable(self):
        # TODO: this fails for discard presumably because there are 2 discard
        # entries (one with #<#off#> and another with #
        srv = "daytime"
        output = run("%s --enable %s" % (cmdline, srv))
        self.grep("Processing service `%s' ... enabled" % srv, output)
        self.grep("Number of service entries enabled: 1", output)
        run("grep -q '^%s\t' %s" % (srv, conffile))
    def testIneffectiveEnable(self):
        srv = "time2"
        output = run("%s --enable %s" % (cmdline, srv))
        self.grep("No service entries were enabled", output)
        run("grep -q '^#%s\t' %s" % (srv, conffile))
    def testEffectiveDisable(self):
        pass
    def testIneffectiveDisable(self):
        pass
    def testEffectiveAdd(self):
        pass
    def testIneffectiveAdd(self):
        pass
    def testEffectiveRemove(self):
        pass
    def testIneffectiveRemove(self):
        pass

if __name__ == "__main__":
    run("chmod 755 update-inetd")
    # set this env var so that DebianNet.pm won't actually run invoke-rc.d
    os.environ["UPDATE_INETD_FAKE_IT"] = "."
    try:
        unittest.main()
    except Exception, e:
        print e
    finally:
        os.path.exists(conffile) and os.remove(conffile)
