# DebianNet.pm: a perl module to add entries to the /etc/inetd.conf file
#
# Copyright (C) 1995, 1996 Peter Tobias <tobias@et-inf.fho-emden.de>
#                          Ian Jackson <iwj10@cus.cam.ac.uk>
#
#
# DebianNet::add_service($newentry, $group);
# DebianNet::disable_service($service, $pattern);
# DebianNet::enable_service($service, $pattern);
# DebianNet::remove_service($entry);
#

package DebianNet;

require 5.000;

use Debconf::Client::ConfModule ':all';

$inetdcf="/etc/inetd.conf";
$sep = "#<off># ";
$version = "1.12";

sub add_service {
    local($newentry, $group) = @_;
    local($service, $searchentry, @inetd, $inetdconf, $found, $success);
    unless (defined($newentry)) { return(-1) };
    chomp($newentry);
    if (defined $group) {
        chomp($group);
    } else {
        $group = "OTHER";
    }
    $group =~ tr/a-z/A-Z/;
    $newentry =~ s/\\t/\t/g;
    ($service = $newentry) =~ s/(\W*\w+)\s+.*/$1/;
    ($sservice = $service) =~ s/^#([A-Za-z].*)/$1/;
    ($searchentry = $newentry) =~ s/^$sep//;
    $searchentry =~ s/^#([A-Za-z].*)/$1/;

    # strip parameter from entry (e.g. -s /tftpboot)
    # example:          service dgram udp     wait    root    /tcpd /prg   -s /tftpboot";
    $searchentry =~ s/^(\w\S+\W+\w+\W+\w\S+\W+\w\S+\W+\w\S+\W+\S+\W+\S+).*/$1/;
    $searchentry =~ s/[ \t]+/ /g;
    $searchentry =~ s/ /\\s+/g;
    $searchentry =~ s@\\s\+/\S+\\s\+/\S+@\\s\+\\S\+\\s\+\\S\+@g;

    if (open(INETDCONF,"$inetdcf")) {
        @inetd=<INETDCONF>;
        close(INETDCONF);
        if (grep(m/^$sep$sservice\s+/,@inetd)) {
            &enable_service($sservice);
        } else {
            if (grep(m/^$sservice\s+/,@inetd)) {
                if (grep(m/^$sservice\s+/,@inetd) > 1) {
		    set("update-inetd/ask-several-entries", "true");
		    fset("update-inetd/ask-several-entries", "seen", "false");
		    settitle("update-inetd/title");
		    subst("update-inetd/ask-several-entries", "service", "$sservice");
		    subst("update-inetd/ask-several-entries", "sservice", "$sservice");
		    subst("update-inetd/ask-several-entries", "inetdcf", "$inetdcf");
		    input("high", "update-inetd/ask-several-entries");
		    @ret = go();
		    if ($ret[0] == 0) {
		        @ret = get("update-inetd/ask-several-entries");
			exit(1) if ($ret[1] !~ m/true/i);
		    }
                } elsif (!grep(m:^#?.*$searchentry.*:, @inetd)) {
		    set("update-inetd/ask-entry-present", "true");
		    fset("update-inetd/ask-entry-present", "seen", "false");
		    settitle("update-inetd/title");
		    subst("update-inetd/ask-entry-present", "service", "$sservice");
		    subst("update-inetd/ask-entry-present", "newentry", "$newentry");
		    subst("update-inetd/ask-entry-present", "sservice", "$sservice");
		    subst("update-inetd/ask-entry-present", "inetdcf", "$inetdcf");
		    my $lookslike = (grep(m/^$sservice\s+/,@inetd))[0];
		    $lookslike =~ s/\n//g;
		    subst("update-inetd/ask-entry-present", "lookslike", "$lookslike");
		    input("high", "update-inetd/ask-entry-present");
		    @ret = go();
		    if ($ret[0] == 0) {
		        @ret = get("update-inetd/ask-entry-present");
			exit(1) if ($ret[1] !~ m/true/i);
		    }
                }
            } elsif (grep(m/^#\s*$sservice\s+/, @inetd) >= 1 or
              (($service =~ s/^#//) and grep(m/^$service\s+/, @inetd)>=1)) {
                &printv("Processing service \`$service' ... not changed\n");
            } else {
                &printv("Processing service \`$sservice' ... added\n");
                $inetdconf=1;
            }
        }
        if ($inetdconf) {
            open(ICWRITE, ">$inetdcf.new") || die "Error creating new $inetdcf: $!\n";
            open(ICREAD, "$inetdcf");
            while(<ICREAD>) {
                chomp;
                if (/^#:$group:/) {
                    $found = 1;
                };
                if ($found and !(/[a-zA-Z#]/)) {
                    print (ICWRITE "$newentry\n") || die "Error writing new $inetdcf: $!\n";
                    $found = 0;
                    $success = 1;
                }
                print ICWRITE "$_\n";
            }
            close(ICREAD);
            unless ($success) {
                print (ICWRITE "$newentry\n") || die "Error writing new $inetdcf: $!\n";
            }
            close(ICWRITE) || die "Error closing new inetd.conf: $!\n";

            rename("$inetdcf.new","$inetdcf") ||
                die "Error installing new $inetdcf: $!\n";
            chmod(0644, "$inetdcf");

            &wakeup_inetd;
        }
    }

    return(1);
}

sub remove_service {
    my($service) = @_;
    unless(defined($service)) { return(-1) };
    chomp($service);
    if($service eq "") {
         print STDERR "DebianNet::remove_service called with empty argument\n";
         return(-1);
    }

    if ((&scan_entries("$service") > 1) and (not defined($multi))) {
	set("update-inetd/ask-remove-entries", "false");
	fset("update-inetd/ask-remove-entries", "seen", "false");
        settitle("update-inetd/title");
	subst("update-inetd/ask-remove-entries", "service", "$service");
	subst("update-inetd/ask-remove-entries", "inetdcf", "$inetdcf");
	input("high", "update-inetd/ask-remove-entries");
	@ret = go();
	if ($ret[0] == 0) {
	    @ret = get("update-inetd/ask-remove-entries");
	    return(1) if ($ret[1] =~ /false/i);
        }
    }

    open(ICWRITE, ">$inetdcf.new") || die "Error creating $inetdcf.new";
    open(ICREAD, "$inetdcf");
    RLOOP: while(<ICREAD>) {
        chomp;
        unless (/^$service\s+/) {
            print ICWRITE "$_\n";
        } else {
            &printv("Removing line: \`$_'\n");
        }
    }
    close(ICREAD);
    close(ICWRITE);

    rename("$inetdcf.new", "$inetdcf") ||
        die "Error installing new $inetdcf: $!\n";
    chmod(0644, "$inetdcf");

    wakeup_inetd(1);
    return(1);
}

sub disable_service {
    my($service, $pattern) = @_;
    unless (defined($service)) { return(-1) };
    unless (defined($pattern)) { $pattern = ''; }
    chomp($service);

    if ((&scan_entries("$service", $pattern) > 1) and (not defined($multi))) {
	set("update-inetd/ask-disable-entries", "false");
	fset("update-inetd/ask-disable-entries", "seen", "false");
        settitle("update-inetd/title");
	subst("update-inetd/ask-disable-entries", "service", "$service");
	subst("update-inetd/ask-disable-entries", "inetdcf", "$inetdcf");
	input("high", "update-inetd/ask-disable-entries");
	@ret = go();
	if ($ret[0] == 0) {
	    @ret = get("update-inetd/ask-disable-entries");
	    return(1) if ($ret[1] =~ /false/i);
        }
    }

    open(ICWRITE, ">$inetdcf.new") || die "Error creating new $inetdcf: $!\n";
    open(ICREAD, "$inetdcf");
    DLOOP: while(<ICREAD>) {
      chomp;
      if (/^$service\s+\w+\s+/ and /$pattern/) {
          &printv("Processing service \`$service' ... disabled\n");
          $_ =~ s/^(.+)$/$sep$1/;
      }
      print ICWRITE "$_\n";
    }
    close(ICREAD);
    close(ICWRITE) || die "Error closing new inetd.conf: $!\n";

    rename("$inetdcf.new","$inetdcf") ||
        die "Error installing new $inetdcf: $!\n";
    chmod(0644, "$inetdcf");

    wakeup_inetd(1);
    return(1);
}

sub enable_service {
    my($service, $pattern) = @_;
    unless (defined($service)) { return(-1) };
    unless (defined($pattern)) { $pattern = ''; }
    chomp($service);
    open(ICWRITE, ">$inetdcf.new") || die "Error creating new $inetdcf: $!\n";
    open(ICREAD, "$inetdcf");
    while(<ICREAD>) {
      chomp;
      if (/^$sep$service\s+\w+\s+/ and /$pattern/) {
          &printv("Processing service \`$service' ... enabled\n");
          $_ =~ s/^$sep//;
      }
      print ICWRITE "$_\n";
    }
    close(ICREAD);
    close(ICWRITE) || die "Error closing new inetd.conf: $!\n";

    rename("$inetdcf.new","$inetdcf") ||
        die "Error installing new $inetdcf: $!\n";
    chmod(0644, "$inetdcf");

    &wakeup_inetd;
    return(1);
}

sub wakeup_inetd {
    my($removal) = @_;
    my($pid);
    my($action);

    if ($removal) {
        $action = 'force-reload';
    } else {
        $action = 'restart';
    }

    if (open(P,"/var/run/inetd.pid")) {
        $pid=<P>;
        if (open(C,sprintf("/proc/%d/stat",$pid))) {
            $_=<C>;
            if (m/^\d+ \(inetd\)/) { kill(1,$pid); }
            close(C);
        }
        close(P);
    } else {
        $_ = glob "/etc/init.d/*inetd";
        if (m/\/etc\/init\.d\/(.*inetd)/) {
            my $service = $1;
            system("invoke-rc.d $service $action >/dev/null");
        }
    }
    return(1);
}

sub scan_entries {
    my ($service, $pattern) = @_;
    unless (defined($pattern)) { $pattern = ''; }
    my $counter = 0;

    open(ICREAD, "$inetdcf");
    SLOOP: while (<ICREAD>) {
        $counter++ if (/^$service\s+/ and /$pattern/);
    }
    close(ICREAD);
    return($counter);
}

sub printv {
    print STDERR @_ if (defined($verbose));
}

1;

