#!/usr/bin/perl
#
# basic command-line testing of update-inetd(8)
#
# Copyright © 2009 Serafeim Zanikolas <serzan@hellug.gr>
# Copyright © 2018 Guillem Jover <guillem@debian.org>
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
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

use strict;
use warnings;

use File::stat;
use File::Copy;
use File::Temp qw(tempfile);
use IPC::Cmd qw(run_forked);
use Test::More tests => 160;

my $GREP_NO_MATCH_EXIT_STATUS = 1;

my $DISABLED_PREFIX = '#<off># ';

# We expect this string to appear in update-inetd's stdout (in verbose mode)
# every time it starts, restarts, or sends SIGHUP to (x)inetd.
my $INETD_WAKEUP_STRING = 'About to ';

my $INETD_CONF = <<"CONF";
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
${DISABLED_PREFIX}daytime		stream	tcp	nowait	root	internal
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
CONF

sub run
{
    my ($cmd, $opts) = @_;

    $opts->{ok_exit_status} //= 0;

    note("running '@{$cmd}'");

    my $ret = run_forked($cmd);

    chomp $ret->{merged};
    ok($ret->{exit_code} == $opts->{ok_exit_status},
       "command '@{$cmd}', exit status $ret->{exit_code} (expected $opts->{ok_exit_status}) " .
       "output: <<<$ret->{merged}>>>");

    return $ret->{merged};
}

my $orig_conffile;
my $conffile;

sub fcomparator
{
    my ($f1, $f2) = @_;

    my $tmp = File::Temp->new(UNLINK => 0);
    run([ "sort $f1 >$tmp; mv $tmp $f1" ]);
    run([ "sort $f2 >$tmp; mv $tmp $f2" ]);
    return run([ 'comm', '-3', '--nocheck-order', $f1, $f2 ]);
}

# Serializes a subset of POSIX stat values.
sub stat_serializer
{
    my $filename = shift;

    my $st = stat $filename or die "cannot stat file $filename: $!\n";

    return $st->ctime . " " . $st->mtime . " " . $st->size;
}

# Try 2 test cases per mode: one that is actually effective (eg, adds,
# modifies or removes a line) and one that isn't (because the matching entry
# is commented out with '#'). Test success by matching expected messages in
# verbose mode, and patterns in the supplied inetd.conf.
sub setUp
{
    open my $fh, '>', $conffile or die "cannot create $conffile: $!\n";
    print { $fh } "$INETD_CONF" or die "cannot write to $conffile: $!\n";
    close $fh or die "cannot write to $conffile: $!\n";
    copy($conffile, $orig_conffile)
        or die "cannot copy $conffile to $orig_conffile: $!\n";
}

# The given string must appear n times in output.
sub assertOutputMatches
{
    my ($string, $output, $n) = @_;

    $n //= 1;

    my $nmatches = scalar grep { m/\Q$string\E/ } split /\n/, $output;
    ok($nmatches == $n,
       "string '$string' appears $nmatches time(s) (expected $n) in " .
       "update-inet's output <<<$output>>>");
}

sub assertConffileMissing
{
    ok(! -e $conffile, "conffile $conffile is missing");
}

# The given pattern must appear exactly n times in the conffile.
sub assertConffileMatches
{
    my ($pattern, $n, $ok_exit_status) = @_;

    $n //= 1;
    $ok_exit_status //= 0;

    ok(-e $conffile, "conffile $conffile exists");
    my $output = run([ 'grep', '-c', "'$pattern'", $conffile ],
                     { ok_exit_status => $ok_exit_status });
    is($output, "$n", "conffile $conffile matches pattern $n times");
}

# orig and modified conffiles must differ in exactly nlines.
sub assertConffileDiffs
{
    my $nlines_diff = shift;

    my $output = fcomparator($orig_conffile, $conffile);
    my $actual_nlines_diff = scalar split /\n/, $output;

    if ($nlines_diff == 0 && $output eq '') {
        pass("no conffile diff <<<$output>>>");
        return;
    }
    ok($actual_nlines_diff == $nlines_diff,
       "original and modified conffiles, $actual_nlines_diff actual diff lines, " .
       "$nlines_diff expected diff lines:\n<<<$output>>>");
}

# Test that no stale file is left behind.
sub assertNoTempFile
{
    my $output = shift;

    # Output should have a line: "Using tempfile $new_inetdcf"
    my ($tmpfilename) = $output =~ m/^Using tempfile (.*)$/m;

    ok(length $tmpfilename,
       "extracted temp filename from output; output: <<<$output>>>");
    ok(defined $tmpfilename && ! -e $tmpfilename,
       "no stale temp file '$tmpfilename' left behind; output: <<<$output>>>");
}

sub update_inetd
{
    my ($mode, $srv, $other_opts, $run_opts) = @_;

    $other_opts //= [];

    return run([ 'update-inetd', '--file', "$conffile", '--verbose',
                 "--$mode", $srv, @{$other_opts} ], $run_opts);
}

sub testMissingConfig
{
    my $srv = "pop-3";
    my $srv_entry = "$srv\t\tstream\ttcp\tnowait\troot\t/usr/sbin/tcpd\t" .
                    "/usr/sbin/in.pop3d";
    my $output;

    # add
    $output = update_inetd("add", "'$srv_entry'");
    assertOutputMatches("warning: cannot add service, $conffile does not exist",
                        $output);
    assertConffileMissing();

    # disable
    $output = update_inetd("disable", $srv);
    assertOutputMatches("No service entries were disabled", $output);
    assertConffileMissing();

    # enable
    $output = update_inetd("enable", $srv);
    assertOutputMatches("warning: cannot enable service, $conffile does not exist",
                        $output);
    assertConffileMissing();

    # remove
    $output = update_inetd("remove", "'$srv'");
    assertOutputMatches("No service entries were removed", $output);
    assertConffileMissing();
}

sub testEffectiveEnable
{
    setUp();

    my $srv = "daytime";
    my $output = update_inetd("enable", $srv);

    assertOutputMatches("Processing service '$srv' ... enabled", $output);
    assertOutputMatches("Number of service entries enabled: 1", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output);
    assertConffileMatches("^$srv\t");
    assertConffileDiffs(2);
    assertNoTempFile($output);
}

sub testIneffectiveEnable
{
    setUp();

    my $srv = "time2";
    my $conffile_stat_before = stat_serializer($conffile);
    my $output = update_inetd("enable", $srv);
    my $conffile_stat_after = stat_serializer($conffile);

    is($conffile_stat_before, $conffile_stat_after, "ineffective enable");
    assertOutputMatches("No service entries were enabled", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output, 0);
    assertConffileMatches("^#$srv\t");
    assertConffileDiffs(0);
    assertNoTempFile($output);
}

sub testEffectiveDisable
{
    setUp();

    my $srv = "time";
    my $output = update_inetd("disable", $srv);

    assertOutputMatches("Processing service '$srv' ... disabled", $output);
    assertOutputMatches("Number of service entries disabled: 1", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output);
    assertConffileMatches("^$DISABLED_PREFIX$srv\t");
    assertConffileDiffs(2);
    assertNoTempFile($output);
}

sub testIneffectiveDisable
{
    setUp();

    my $srv = "time2";
    my $conffile_stat_before = stat_serializer($conffile);
    my $output = update_inetd("disable", $srv);
    my $conffile_stat_after = stat_serializer($conffile);

    is($conffile_stat_before, $conffile_stat_after, "ineffective disable");
    assertOutputMatches("No service entries were disabled", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output, 0);
    assertConffileMatches("^#$srv\t");
    assertConffileDiffs(0);
    assertNoTempFile($output);
}

sub testEffectiveAdd
{
    setUp();

    my $srv = "pop-3";
    my $srv_entry = "$srv\t\tstream\ttcp\tnowait\troot\t/usr/sbin/tcpd\t" .
                    "/usr/sbin/in.pop3d";
    my $output = update_inetd("add", "'$srv_entry'");

    assertOutputMatches("Processing service '$srv' ... added", $output);
    assertOutputMatches("New service(s) added", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output);
    assertConffileMatches("^$srv\t");
    assertConffileDiffs(1);
    assertNoTempFile($output);
    assertOutputMatches("Number of currently enabled services: 1", $output);
}

sub testIneffectiveAdd
{
    setUp();

    my $srv = "time2";
    my $srv_entry = "$srv\t\tstream\ttcp\tnowait\troot\t/usr/sbin/tcpd\t" .
                    "/usr/sbin/in.pop3d";
    my $conffile_stat_before = stat_serializer($conffile);
    my $output = update_inetd("add", "'$srv_entry'");
    my $conffile_stat_after = stat_serializer($conffile);

    is($conffile_stat_before, $conffile_stat_after, "ineffective add");
    assertOutputMatches("Processing service '$srv' ... not enabled", $output);
    assertOutputMatches("No service(s) added", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output, 0);
    assertConffileMatches("^#$srv\t");
    assertConffileDiffs(0);
    #assertNoTempFile($output) # doesn't create a temp file
}

sub testEffectiveRemove
{
    setUp();

    my $srv = "time";
    my $output = update_inetd("remove", "'$srv'");

    assertOutputMatches("Removing line: '$srv\t", $output);
    assertOutputMatches("Number of service entries removed: 1", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output);
    assertConffileMatches("^$srv\t", 0, $GREP_NO_MATCH_EXIT_STATUS);
    assertConffileDiffs(1);
    assertNoTempFile($output);
}

sub testIneffectiveRemove
{
    setUp();

    my $srv = "time2";
    my $conffile_stat_before = stat_serializer($conffile);
    my $output = update_inetd("remove", "'$srv'");
    my $conffile_stat_after = stat_serializer($conffile);

    is($conffile_stat_before, $conffile_stat_after, "ineffective remove");
    assertOutputMatches("No service entries were removed", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output, 0);
    assertConffileDiffs(0);
    assertNoTempFile($output);
}

sub testAddDisableEnableRemove
{
    setUp();

    my $srv = "pop-3";
    my $srv_entry = "$srv\t\tstream\ttcp\tnowait\troot\t/usr/sbin/tcpd\t" .
                    "/usr/sbin/in.pop3d";
    my $output;

    # add
    $output = update_inetd("add", "'$srv_entry'");
    assertOutputMatches("Processing service '$srv' ... added", $output);
    assertOutputMatches("New service(s) added", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output);
    assertConffileMatches("^$srv\t");
    assertConffileDiffs(1);
    assertOutputMatches("Number of currently enabled services: 1", $output);

    # disable
    $output = update_inetd("disable", $srv);
    assertOutputMatches("Processing service '$srv' ... disabled", $output);
    assertOutputMatches("Number of service entries disabled: 1", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output);
    assertConffileMatches("^$DISABLED_PREFIX$srv\t");
    # assertConffileDiff calls compares against the original conffile
    # (before the "add" operation)
    assertConffileDiffs(1);

    # enable
    $output = update_inetd("enable", $srv);
    assertOutputMatches("Processing service '$srv' ... enabled", $output);
    assertOutputMatches("Number of service entries enabled: 1", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output);
    assertConffileMatches("^$srv\t");
    assertConffileDiffs(1);

    # remove
    $output = update_inetd("remove", "'$srv'");
    assertOutputMatches("Removing line: '$srv\t", $output);
    assertOutputMatches("Number of service entries removed: 1", $output);
    assertOutputMatches($INETD_WAKEUP_STRING, $output);
    assertConffileMatches("^$srv\t", 0, $GREP_NO_MATCH_EXIT_STATUS);
    assertConffileDiffs(0);

    #
    assertNoTempFile($output);
}

#
# Main
#

chmod 0755, 'update-inetd';

# Set this envvar so that DebianNet.pm will not actually run update_inetd-rc.d.
$ENV{UPDATE_INETD_FAKE_IT} = '.';
$ENV{UPDATE_INETD_NOXINETD} = '.';

# If testing the installed code, set PATH to include sbin directories,
# otherwise set current dir first in PERLLIB (last by default) and PATH,
# so that we test the local code.
if (exists $ENV{UPDATE_INETD_INSTALLCHECK}) {
    $ENV{PATH} = "/usr/sbin:/sbin:$ENV{PATH}";
} else {
    $ENV{PERL5LIB} = 'lib';
    $ENV{PATH} = ".:$ENV{PATH}";
}

# Test cases.
$conffile = '/nonexistent';

testMissingConfig();

$orig_conffile = File::Temp->new(SUFFIX => '.orig');
$conffile = File::Temp->new(SUFFIX => '.modified');

testEffectiveEnable();
testIneffectiveEnable();
testEffectiveDisable();
testIneffectiveDisable();
testEffectiveAdd();
testIneffectiveAdd();
testEffectiveRemove();
testIneffectiveRemove();
testAddDisableEnableRemove();
