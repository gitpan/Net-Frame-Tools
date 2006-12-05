#!/usr/bin/perl
#
# $Id: nf-sniff.pl,v 1.3 2006/12/05 20:45:39 gomor Exp $
#
use strict;
use warnings;

our $VERSION = '1.00';

use Getopt::Std;
my %opts;
getopts('F:i:w:', \%opts);

my $oDump;

die("Usage: $0\n".
    "\n".
    "   -i  network interface to sniff on\n".
    "   -F  pcap filter to use\n".
    "   -w  write to file\n".
    "") unless $opts{i};

use Net::Frame::Dump::Online;
use Net::Frame::Simple;

$oDump = Net::Frame::Dump::Online->new(dev => $opts{i});
$oDump->filter($opts{F}) if $opts{F};
if ($opts{w}) {
   $oDump->file($opts{w});
   $oDump->unlinkOnStop(0);
}

$oDump->start;

my $count = 0;
while (1) {
   if (my $h = $oDump->next) {
      my $f   = Net::Frame::Simple->newFromDump($h);
      my $len = length($h->{raw});
      my $ts  = $h->{timestamp};
      print 'o Frame number: '.$count++." (length: $len, timestamp: $ts)\n";
      print $f->print."\n";
   }
}

END { $oDump && $oDump->isRunning && $oDump->stop }

__END__

=head1 NAME

nf-sniff - Net::Frame Sniff tool

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
