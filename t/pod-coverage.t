#!/usr/bin/perl
#
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

use Test::More;
use Test::UpdateInetd qw(:needs);

test_needs_author();
test_needs_module('Test::Pod::Coverage');

my @module_files =  Test::UpdateInetd::all_perl_modules();
my @modules = map { s{lib/}{}; s/\.pm$//; s{/}{::}gr } @module_files;

plan tests => scalar @modules;

foreach my $module (@modules) {
    pod_coverage_ok($module);
}
