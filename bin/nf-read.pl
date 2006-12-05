#!/usr/bin/perl
#
# $Id: nf-read.pl,v 1.2 2006/12/05 20:45:39 gomor Exp $
#
use strict;
use warnings;

our $VERSION = '1.00';

use Getopt::Std;
my %opts;
getopts('f:F:', \%opts);

my $oDump;

die("Usage: $0\n".
    "\n".
    "   -f  file to read\n".
    "   -F  pcap filter to use\n".
    "") unless $opts{f};

use Net::Frame::Dump::Offline;
use Net::Frame::Simple;

$oDump = Net::Frame::Dump::Offline->new(file => $opts{f});
$oDump->filter($opts{F}) if $opts{F};

$oDump->start;

my $count = 0;
while (my $h = $oDump->next) {
   my $f = Net::Frame::Simple->newFromDump($h);
   my $len = length($h->{raw});
   my $ts  = $h->{timestamp};
   print 'o Frame number: '.$count++." (length: $len, timestamp: $ts)\n";
   print $f->print."\n";
}

END { $oDump && $oDump->isRunning && $oDump->stop }

__END__

=head1 NAME

nf-read - Net::Frame Read tool

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
