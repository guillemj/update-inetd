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

test_needs_module('Test::Strict');

eval '$Test::Strict::TEST_WARNINGS = 1';

my @files = Test::UpdateInetd::all_perl_files();

plan tests => scalar @files * 2;

for my $file (@files) {
    strict_ok($file);
    warnings_ok($file);
}
