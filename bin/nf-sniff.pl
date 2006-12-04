#!/usr/bin/perl
#
# $Id: nf-sniff.pl,v 1.2 2006/12/04 21:20:53 gomor Exp $
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

use Net::Frame::Dump qw(:consts);
use Net::Frame::Simple;

$oDump = Net::Frame::Dump->new(
   dev  => $opts{i},
   mode => NP_DUMP_MODE_ONLINE,
);
$oDump->filter($opts{F}) if $opts{F};
if ($opts{w}) {
   $oDump->file($opts{w});
   $oDump->unlinkOnClean(0);
}

$oDump->start;

my $count = 0;
while (1) {
   if (my $h = $oDump->next) {
      my $f = Net::Frame::Simple->new(
         raw        => $h->{raw},
         firstLayer => $h->{firstLayer},
         timestamp  => $h->{timestamp},
      );
      my $len = length($h->{raw});
      print 'o Frame number: '.$count++." (length: $len)\n";
      print $f->print."\n";
   }
}

$oDump->stop;
$oDump->clean;

END {
   if ($oDump && $oDump->isRunning) {
      $oDump->stop;
      $oDump->clean;
   }
}

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
