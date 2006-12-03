#!/usr/bin/perl
#
# $Id: nf-arphijack.pl,v 1.1 2006/11/30 17:55:06 gomor Exp $
#

our $VERSION = '1.00';

use Getopt::Std;
my %opts;
getopts('g:t:', \%opts);

die("Usage: $0\n".
    "\n".
    "   -g  gateway IP address\n".
    "   -t  target victim IP address\n".
    "") unless $opts{g} && $opts{t};

__END__

=head1 NAME

nf-arphijack - Net::Frame ARP Hi-Jack tool

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
