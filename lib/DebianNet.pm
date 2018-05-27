# Copyright © 1995, 1996 Peter Tobias <tobias@et-inf.fho-emden.de>
# Copyright © 1995, 1996 Ian Jackson <iwj10@cus.cam.ac.uk>
# Copyright © 2009-2012 Serafeim Zanikolas <sez@debian.org>
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

=encoding utf8

=head1 NAME

DebianNet - create, remove, enable or disable entry in /etc/inetd.

=head1 DESCRIPTION

You can use the functions in B<DebianNet> to to add, remove, enable or
disable entries in the F</etc/inetd.conf> file. After the F</etc/inetd.conf>
file has been changed, a B<SIGHUP> signal will be sent to the inetd
process to make sure that inetd will use the new F</etc/inetd.conf> file.
The functions can also be used to add entries that are commented out by
default. They will be treated like normal entries. That also means that
if you already have an entry that is commented out you can't add an entry
for the same service without removing the old one first.

The B<DebianNet> functions treat entries that are commented out by a
single 'B<#>' character as entries that have been commented out by a
user. It will not change such entries.

For shell scripts you can also use the B<update-inetd> command. See
B<update-inetd>(8) for further information.

=cut

package DebianNet;

use 5.6.1;
use strict;
use warnings;

our $VERSION = '1.13';

use Carp;
use Debconf::Client::ConfModule ();

BEGIN {
    eval 'use File::Temp qw/ tempfile /';
    if ($@) {
        # If perl-base and perl-modules are out of sync, fall back to the
        # external 'tempfile' command.  In this case we don't bother trying
        # to mangle the template we're given into something that tempfile
        # can understand.
        *tempfile = sub {
            open my $tempfile_fh, '-|', 'tempfile'
                or die "error running tempfile: $!\n";
            chomp (my $tempfile_name = <$tempfile_fh>);
            unless (length $tempfile_name) {
                die "tempfile did not return a temporary file name\n";
            }
            unless (close $tempfile_fh) {
                if ($!) {
                    die "error closing tempfile pipe: $!\n";
                } else {
                    die "tempfile returned exit status $?\n";
                }
            }
            open my $fh, '+<', $tempfile_name
                or die "error opening temporary file $tempfile_name: $!\n";
            return ($fh, $tempfile_name);
        };
    }

    eval 'use File::Copy qw/ move /';
    if ($@) {
        # If perl-base and perl-modules are out of sync, fall back to the
        # external 'mv' command.
        *move = sub {
            my ($from, $to) = @_;
            return system('mv', $from, $to) == 0;
        };
    }
}

=head1 VARIABLES

=over 4

=item $DebianNet::INETD_CONF

Contains a scalar filename to use as the inetd config file (e.g. for
testing purposes).

Defaults to F</etc/inetd.conf>.

=cut

our $INETD_CONF = '/etc/inetd.conf';

=item $DebianNet::SEP

Contains the entry comment characters. This is only necessary if you have
to deal with two (or more) services of the same name.

Defaults to "B<#E<lt>offE<gt># >" as the comment characters.

=cut

our $SEP = '#<off># ';

=item $DebianNet::MULTI

Contains a boolean that decides whether to disable/remove more than one
entry at a time. If you try to remove more than one entry at a time without
using this option the program will show a warning and will ask the user
whether to continue.

Defaults to false.

=cut

our $MULTI;

=item $DebianNet::VERBOSE

Contains a boolean to select whether to explain verbosely what is being
done.

Defaults to false.

=cut

our $VERBOSE;

=back

=cut

our $INETD_WAKEUP_CALLED = 0;

# Backwards compatibility aliases.
## no critic (Variables::ProhibitPackageVars)
our $version;
*version = \$VERSION;
our $verbose;
*verbose = \$VERBOSE;
our $inetdcf;
*inetdcf = \$INETD_CONF;
our $sep;
*sep = \$SEP;
our $multi;
*multi = \$MULTI;
our $called_wakeup_inetd;
*called_wakeup_inetd = \$INETD_WAKEUP_CALLED;
## use critic

=head1 FUNCTIONS

=over 4

=cut

sub _debconf_init
{
    Debconf::Client::ConfModule->import(':all');
}

=item $rc = DebianNet::add_service($newentry, $group)

Add $newentry to the group $group of the F</etc/inetd.conf> file. If the
entry already exist it will be enabled (it will also detect entries with
different program options). Using $group is optional (the default group
is the group OTHER). If the group does not exist the entry will be placed
at the end of the file.

Returns 1 on success, and -1 on failure. This function might call B<exit>()
due to debconf prompt answers.

=cut

sub add_service {
    my ($newentry, $group) = @_;
    my ($service, $searchentry, @inetd, $inetdconf, $found, $success);

    unless (defined($newentry)) { return(-1) };
    chomp($newentry);
    if (defined $group) {
        chomp($group);
    } else {
        $group = 'OTHER';
    }
    $group =~ tr/a-z/A-Z/;
    $newentry =~ s/\\t/\t/g;
    ($service = $newentry) =~ s/(\W*\w+)\s+.*/$1/;
    (my $sservice = $service) =~ s/^#([A-Za-z].*)/$1/;
    ($searchentry = $newentry) =~ s/^$SEP//;
    $searchentry =~ s/^#([A-Za-z].*)/$1/;

    # strip parameter from entry (e.g. -s /tftpboot)
    # example:          service dgram udp     wait    root    /tcpd /prg   -s /tftpboot";
    $searchentry =~ s/^(\w\S+\W+\w+\W+\w\S+\W+\w\S+\W+\w\S+\W+\S+\W+\S+).*/$1/;
    $searchentry =~ s/[ \t]+/ /g;
    $searchentry =~ s/ /\\s+/g;
    $searchentry =~ s{\\s\+/\S+\\s\+/\S+}{\\s\+\\S\+\\s\+\\S\+}g;

    if (open my $inetdconf_fh, '<', $INETD_CONF) {
        @inetd = <$inetdconf_fh>;
        close $inetdconf_fh;
        if (grep(m/^$SEP$sservice\s+/, @inetd)) {
            &enable_service($sservice);
        } elsif (grep(m/^$sservice\s+/,@inetd)) {
            _debconf_init();

            if (grep(m/^$sservice\s+/,@inetd) > 1) {
                set('update-inetd/ask-several-entries', 'true');
                fset('update-inetd/ask-several-entries', 'seen', 'false');
                settitle('update-inetd/title');
                subst('update-inetd/ask-several-entries', 'service', $sservice);
                subst('update-inetd/ask-several-entries', 'sservice', $sservice);
                subst('update-inetd/ask-several-entries', 'inetdcf', $INETD_CONF);
                input('high', 'update-inetd/ask-several-entries');
                my @ret = go();
                if ($ret[0] == 0) {
                    @ret = get('update-inetd/ask-several-entries');
                    exit(1) if ($ret[1] !~ m/true/i);
                }
            } elsif (!grep(m{^#?.*$searchentry.*}, @inetd)) {
                set('update-inetd/ask-entry-present', 'true');
                fset('update-inetd/ask-entry-present', 'seen', 'false');
                settitle('update-inetd/title');
                subst('update-inetd/ask-entry-present', 'service', $sservice);
                subst('update-inetd/ask-entry-present', 'newentry', $newentry);
                subst('update-inetd/ask-entry-present', 'sservice', $sservice);
                subst('update-inetd/ask-entry-present', 'inetdcf', $INETD_CONF);
                my $lookslike = (grep(m/^$sservice\s+/,@inetd))[0];
                $lookslike =~ s/\n//g;
                subst('update-inetd/ask-entry-present', 'lookslike', $lookslike);
                input('high', 'update-inetd/ask-entry-present');
                my @ret = go();
                if ($ret[0] == 0) {
                    @ret = get('update-inetd/ask-entry-present');
                    exit(1) if ($ret[1] !~ m/true/i);
                }
            }
        } elsif (grep(m/^#\s*$sservice\s+/, @inetd) >= 1 or
          (($service =~ s/^#//) and grep(m/^$service\s+/, @inetd)>=1)) {
            printv("Processing service \`$service' ... not enabled" .
                   " (entry is commented out by user)\n");
        } else {
            &printv("Processing service \`$sservice' ... added\n");
            $inetdconf=1;
        }
        if ($inetdconf) {
            my $init_svc_count = &scan_entries();
            &printv("Number of currently enabled services: $init_svc_count\n");
            my ($icwrite_fh, $new_inetdcf) = tempfile('/tmp/inetdcfXXXXX', UNLINK => 0);
            unless (defined $icwrite_fh) {
                die "Error creating temporary file: $!\n";
            }
            &printv("Using tempfile $new_inetdcf\n");
            open my $icread_fh, '<', $INETD_CONF
                or die "cannot open $INETD_CONF: $!\n";
            while (<$icread_fh>) {
                chomp;
                if (/^#:$group:/) {
                    $found = 1;
                };
                if ($found and not m/[a-zA-Z#]/) {
                    print { $icwrite_fh } "$newentry\n"
                        or die "Error writing to $new_inetdcf: $!\n";
                    $found = 0;
                    $success = 1;
                }
                print { $icwrite_fh } "$_\n";
            }
            close $icread_fh;
            unless ($success) {
                print { $icwrite_fh } "$newentry\n"
                    or die "Error writing to $new_inetdcf: $!\n";
                $success = 1;
            }
            close($icwrite_fh) || die "Error closing $new_inetdcf: $!\n";

            if ($success) {
                move($new_inetdcf, $INETD_CONF) ||
                    die "Error installing $new_inetdcf to $INETD_CONF: $!\n";
                chmod 0644, $INETD_CONF;
                &wakeup_inetd(0,$init_svc_count);
                &printv("New service(s) added\n");
            } else {
                &printv("No service(s) added\n");
                unlink($new_inetdcf)
                    || die "Error removing $new_inetdcf: $!\n";
            }
        } else {
            &printv("No service(s) added\n");
        }
    }

    return(1);
}

=item $rc = DebianNet::remove_service($entry)

Remove $entry from F</etc/inetd.conf>. You can use a regular expression
to remove the entry.

Returns 1 on success, and -1 on failure.

=cut

sub remove_service {
    my($service, $pattern) = @_;
    chomp($service);
    my $nlines_removed = 0;
    if ($service eq '') {
         carp('DebianNet::remove_service called with empty argument');
         return(-1);
    }
    unless (defined($pattern)) { $pattern = ''; }

    if (((&scan_entries($service, $pattern) > 1) or (&scan_entries("$SEP$service", $pattern) > 1))
        and (not defined $MULTI)) {
        _debconf_init();

        set('update-inetd/ask-remove-entries', 'false');
        fset('update-inetd/ask-remove-entries', 'seen', 'false');
        settitle('update-inetd/title');
        subst('update-inetd/ask-remove-entries', 'service', $service);
        subst('update-inetd/ask-remove-entries', 'inetdcf', $INETD_CONF);
        input('high', 'update-inetd/ask-remove-entries');
        my @ret = go();
        if ($ret[0] == 0) {
            @ret = get('update-inetd/ask-remove-entries');
            return(1) if ($ret[1] =~ /false/i);
        }
    }

    my ($icwrite_fh, $new_inetdcf) = tempfile('/tmp/inetdcfXXXXX', UNLINK => 0);
    unless (defined $icwrite_fh) {
        die "Error creating temporary file: $!\n";
    }
    &printv("Using tempfile $new_inetdcf\n");
    open my $icread_fh, '<', $INETD_CONF
        or die "cannot open $INETD_CONF: $!\n";
    RLOOP: while (<$icread_fh>) {
        chomp;
        if (not((/^$service\s+/ or /^$SEP$service\s+/) and /$pattern/)) {
            print { $icwrite_fh } "$_\n";
        } else {
            &printv("Removing line: \`$_'\n");
            $nlines_removed += 1;
        }
    }
    close $icread_fh;
    close $icwrite_fh;

    if ($nlines_removed > 0) {
        move($new_inetdcf, $INETD_CONF) ||
            die "Error installing $new_inetdcf to $INETD_CONF: $!\n";
        chmod 0644, $INETD_CONF;
        wakeup_inetd(1);
        &printv("Number of service entries removed: $nlines_removed\n");
    } else {
        &printv("No service entries were removed\n");
        unlink($new_inetdcf) || die "Error removing $new_inetdcf: $!\n";
    }

    return(1);
}

=item $rc = DebianNet::disable_service($service, $pattern)

Disable $service (e.g. "I<ftp>") in F</etc/inetd.conf>. Using $pattern is
optional (see enable_service()).

Returns 1 on success, and -1 on failure.

=cut

sub disable_service {
    my($service, $pattern) = @_;
    unless (defined($service)) { return(-1) };
    unless (defined($pattern)) { $pattern = ''; }
    chomp($service);
    my $nlines_disabled = 0;

    if ((&scan_entries($service, $pattern) > 1) and (not defined $MULTI)) {
        _debconf_init();

        set('update-inetd/ask-disable-entries', 'false');
        fset('update-inetd/ask-disable-entries', 'seen', 'false');
        settitle('update-inetd/title');
        subst('update-inetd/ask-disable-entries', 'service', $service);
        subst('update-inetd/ask-disable-entries', 'inetdcf', $INETD_CONF);
        input('high', 'update-inetd/ask-disable-entries');
        my @ret = go();
        if ($ret[0] == 0) {
            @ret = get('update-inetd/ask-disable-entries');
            return(1) if ($ret[1] =~ /false/i);
        }
    }

    my ($icwrite_fh, $new_inetdcf) = tempfile('/tmp/inetdcfXXXXX', UNLINK => 0);
    unless (defined $icwrite_fh) {
        die "Error creating temporary file: $!\n";
    }
    &printv("Using tempfile $new_inetdcf\n");
    open my $icread_fh, '<', $INETD_CONF
        or die "cannot open $INETD_CONF: $!\n";
    DLOOP: while (<$icread_fh>) {
      chomp;
      if (/^$service\s+\w+\s+/ and /$pattern/) {
          &printv("Processing service \`$service' ... disabled\n");
          $_ =~ s/^(.+)$/$SEP$1/;
          $nlines_disabled += 1;
      }
      print { $icwrite_fh } "$_\n";
    }
    close $icread_fh;
    close($icwrite_fh) || die "Error closing $new_inetdcf: $!\n";

    if ($nlines_disabled > 0) {
        move($new_inetdcf, $INETD_CONF) ||
            die "Error installing new $INETD_CONF: $!\n";
        chmod 0644, $INETD_CONF;
        wakeup_inetd(1);
        &printv("Number of service entries disabled: $nlines_disabled\n");
    } else {
        &printv("No service entries were disabled\n");
        unlink($new_inetdcf) || die "Error removing $new_inetdcf: $!\n";
    }

    return(1);
}

=item $rc = DebianNet::enable_service($service, $pattern)

Enable $service (e.g. "I<ftp>") in F</etc/inetd.conf>. Using $pattern is
optional. It can be used to select a service. You only need this option
if you have two (or more) services of the same name.

An example: you have three I<ftp> entries in the F</etc/inetd.conf> file
(all disabled by default) and you want to enable the entry which uses the
I<vsftpd> daemon. To do this, use the pattern "I<vsftpd>" (or any other
regular expression that matches this entry).

Returns 1 on success, and -1 on failure.

=cut

sub enable_service {
    my($service, $pattern) = @_;
    unless (defined($service)) { return(-1) };
    unless (defined($pattern)) { $pattern = ''; }
    my $init_svc_count = &scan_entries();
    my $nlines_enabled = 0;
    chomp($service);
    my ($icwrite_fh, $new_inetdcf) = tempfile('/tmp/inetdXXXXX', UNLINK => 0);
    unless (defined $icwrite_fh) {
        die "Error creating temporary file: $!\n";
    }
    &printv("Using tempfile $new_inetdcf\n");
    open my $icread_fh, '<', $INETD_CONF
        or die "cannot open $INETD_CONF: $!\n";
    while (<$icread_fh>) {
      chomp;
      if (/^$SEP$service\s+\w+\s+/ and /$pattern/) {
          &printv("Processing service \`$service' ... enabled\n");
          $_ =~ s/^$SEP//;
          $nlines_enabled += 1;
      }
      print { $icwrite_fh } "$_\n";
    }
    close $icread_fh;
    close($icwrite_fh) || die "Error closing $new_inetdcf: $!\n";

    if ($nlines_enabled > 0) {
        move($new_inetdcf, $INETD_CONF) ||
            die "Error installing $new_inetdcf to $INETD_CONF: $!\n";
        chmod 0644, $INETD_CONF;
        &wakeup_inetd(0,$init_svc_count);
        &printv("Number of service entries enabled: $nlines_enabled\n");
    } else {
        &printv("No service entries were enabled\n");
        unlink($new_inetdcf) || die "Error removing $new_inetdcf: $!\n";
    }

    return(1);
}

sub wakeup_inetd {
    my($removal,$init_svc_count) = @_;
    my($pid);
    my($action);

    $INETD_WAKEUP_CALLED = 1;

    if ($removal) {
        $action = 'force-reload';
    } elsif ( defined($init_svc_count) and $init_svc_count == 0 ) {
        $action = 'start';
    } else {
        $action = 'restart';
    }

    my $fake_invocation = defined $ENV{UPDATE_INETD_FAKE_IT};
    if (open my $pid_fh, '<', '/var/run/inetd.pid') {
        $pid = <$pid_fh>;
        chomp($pid);
        if (open my $cmd_fh, '<', sprintf('/proc/%d/stat', $pid)) {
            $_ = <$cmd_fh>;
            if (m/^\d+ \((rl|inetutils-)?inetd\)/) {
                &printv("About to send SIGHUP to inetd (pid: $pid)\n");
                unless ($fake_invocation) {
                    kill(1,$pid);
                }
            } else {
                warn "/var/run/inetd.pid does not have a valid pid!\n";
                warn "Please investigate and restart inetd manually.\n";
            }
            close $cmd_fh;
        }
        close $pid_fh;
    } else {
        $_ = glob '/etc/init.d/*inetd';
        if (m/\/etc\/init\.d\/(.*inetd)/ or $fake_invocation) {
            &printv("About to $action inetd via invoke-rc.d\n");
            my $service = $1;
            unless ($fake_invocation) {
                 # If we were called by a shell script that also uses
                 # debconf, the pipe to the debconf frontend is fd 3 as
                 # well as fd 1 (stdout).  Ensure that fd 3 is not
                 # inherited by invoke-rc.d and inetd, as that will
                 # cause debconf to hang (bug #589487).  Don't let them
                 # confuse debconf via stdout either.
                 system("invoke-rc.d $service $action >/dev/null 3>&-");
            }
        }
    }
    return(1);
}

sub scan_entries {
    my ($service, $pattern) = @_;
    unless (defined($service)) { $service = '[^#\s]+'; }
    unless (defined($pattern)) { $pattern = ''; }
    my $counter = 0;

    open my $icread_fh, '<', $INETD_CONF
        or die "cannot open $INETD_CONF: $!\n";
    SLOOP: while (<$icread_fh>) {
        $counter++ if (/^$service\s+/ and /$pattern/);
    }
    close $icread_fh;
    return($counter);
}

sub printv {
    warn @_ if defined $VERBOSE;
}

1;

=back

=head1 CHANGES

=head2 Version 1.13

New variables: $VERSION, $VERBOSE, $MULTI, $SEP, $INETD_CONF.

Deprecated variables: $version, $verbose, $multi, $sep, $inetdcf.

=cut
