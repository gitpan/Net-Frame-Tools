#!/usr/bin/perl
#
# $Id: nf-sniff.pl,v 1.1 2006/11/30 17:55:06 gomor Exp $
#
use strict;
use warnings;

our $VERSION = '1.00';

use Getopt::Std;
my %opts;
getopts('F:i:', \%opts);

die("Usage: $0\n".
    "\n".
    "   -i  network interface to sniff on\n".
    "   -F  pcap filter to use\n".
    "") unless $opts{i};

use Net::Frame::Dump qw(:consts);
use Net::Frame::Simple;

my $d = Net::Frame::Dump->new(
   dev  => $opts{i},
   mode => NP_DUMP_MODE_ONLINE,
);
$d->filter($opts{F}) if $opts{F};

$d->start;

my $count = 0;
while (1) {
   if (my $h = $d->next) {
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

$d->stop;
$d->clean;

END {
   if ($d && $d->isRunning) {
      $d->stop;
      $d->clean;
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
