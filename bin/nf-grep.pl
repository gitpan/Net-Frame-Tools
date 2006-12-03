#!/usr/bin/perl
#
# $Id: nf-grep.pl,v 1.2 2006/12/03 16:47:03 gomor Exp $
#
use strict;
use warnings;

our $VERSION = '1.00';

use Getopt::Std;
my %opts;
getopts('f:F:e:i:', \%opts);

die("Usage: $0\n".
    "\n".
    "   -i  network interface to sniff on\n".
    "   -e  regex, will be applied on application layer (for TCP and UDP)\n".
    "   -f  file to read\n".
    "   -F  pcap filter to use\n".
    "") unless $opts{i} && $opts{e};

use Net::Frame::Dump qw(:consts);
use Net::Frame::Simple;

my $d;
if ($opts{f}) {
   $d = Net::Frame::Dump->new(
      dev  => 'none',
      file => $opts{f},
      mode => NP_DUMP_MODE_OFFLINE,
   );
}
else {
   $d = Net::Frame::Dump->new(
      dev  => $opts{i},
      mode => NP_DUMP_MODE_ONLINE,
   );
}
$d->filter($opts{F}) if $opts{F};

$d->start;

my $count = 0;
if ($opts{f}) {
   while (my $h = $d->next) {
      analyzeNext($h, $count);
      $count++;
   }
}
else {
   while (1) {
      if (my $h = $d->next) {
         analyzeNext($h, $count);
         $count++;
      }
   }
}

$d->stop;
$d->clean;

sub analyzeNext {
   my ($h, $c) = @_;
   my $f = Net::Frame::Simple->new(
      raw        => $h->{raw},
      firstLayer => $h->{firstLayer},
      timestamp  => $h->{timestamp},
   );
   my $l;
   if (($l = $f->ref->{TCP}) || ($l = $f->ref->{UDP})) {
      if (my $payload = $l->payload) {
         if ($payload =~ /$opts{e}/) {
            chomp($payload);
            print 'o Frame number: '.$count."\n";
            print $payload."\n";
         }
      }
   }
}

END {
   if ($d && $d->isRunning) {
      $d->stop;
      $d->clean;
   }
}

__END__

=head1 NAME

nf-grep - Net::Frame Grep tool

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
