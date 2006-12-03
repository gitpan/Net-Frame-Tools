#!/usr/bin/perl
#
# $Id: nf-read.pl,v 1.1 2006/11/30 17:55:06 gomor Exp $
#
use strict;
use warnings;

our $VERSION = '1.00';

use Getopt::Std;
my %opts;
getopts('f:F:', \%opts);

die("Usage: $0\n".
    "\n".
    "   -f  file to read\n".
    "   -F  pcap filter to use\n".
    "") unless $opts{f};

use Net::Frame::Dump qw(:consts);
use Net::Frame::Simple;

my $d = Net::Frame::Dump->new(
   dev  => 'non',
   file => $opts{f},
   mode => NP_DUMP_MODE_OFFLINE,
);
$d->filter($opts{F}) if $opts{F};

$d->start;
my $count = 0;
while (my $h = $d->next) {
   my $f = Net::Frame::Simple->new(
      raw        => $h->{raw},
      firstLayer => $h->{firstLayer},
      timestamp  => $h->{timestamp},
   );
   my $len = length($h->{raw});
   print 'o Frame number: '.$count++." (length: $len)\n";
   print $f->print."\n";
}

$d->stop;
$d->clean;

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
