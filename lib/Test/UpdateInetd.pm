# Copyright © 2015, 2018 Guillem Jover <guillem@debian.org>
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

package Test::UpdateInetd;

use strict;
use warnings;

our $VERSION = '0.00';
our @EXPORT_OK = qw(
    all_perl_files
    all_perl_modules
    test_needs_author
    test_needs_module
    test_needs_command
);
our %EXPORT_TAGS = (
    needs => [ qw(
        test_needs_author
        test_needs_module
        test_needs_command
    ) ],
    paths => [ qw(
        all_perl_files
        all_perl_modules
    ) ],
);

use Exporter qw(import);
use IPC::Cmd qw(can_run);
use Test::More;

sub all_perl_modules
{
    return qw(lib/DebianNet.pm);
}

sub all_perl_files
{
    return (qw(update-inetd), all_perl_modules());
}

sub test_needs_author
{
    if (not $ENV{AUTHOR_TESTING}) {
        plan skip_all => 'developer test';
    }
}

sub test_needs_module
{
    my ($module, @imports) = @_;
    my ($package) = caller;

    require version;
    my $version = '';
    if (@imports >= 1 and version::is_lax($imports[0])) {
        $version = shift @imports;
    }

    eval qq{
        package $package;
        use $module $version \@imports;
        1;
    } or do {
        plan skip_all => "requires module $module $version";
    }
}

sub test_needs_command
{
    my $command = shift;

    if (not can_run($command)) {
        plan skip_all => "requires command $command";
    }
}

1;
