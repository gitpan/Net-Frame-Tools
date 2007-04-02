#!/usr/bin/perl
#
# $Id: nf-grep.pl,v 1.4 2007/04/02 16:46:49 gomor Exp $
#
use strict;
use warnings;

our $VERSION = '1.00';

use Getopt::Std;
my %opts;
getopts('f:F:e:i:', \%opts);

my $oDump;

die("Usage: $0\n".
    "\n".
    "   -i  network interface to sniff on\n".
    "   -e  regex, will be applied on application layer (for TCP and UDP)\n".
    "   -f  file to read\n".
    "   -F  pcap filter to use\n".
    "") unless $opts{i} && $opts{e};

use Net::Frame::Dump::Online;
use Net::Frame::Dump::Offline;
use Net::Frame::Simple;

if ($opts{f}) {
   $oDump = Net::Frame::Dump::Offline->new(file => $opts{f});
}
else {
   $oDump = Net::Frame::Dump::Online->new(dev  => $opts{i});
}
$oDump->filter($opts{F}) if $opts{F};

$oDump->start;

my $count = 0;
if ($opts{f}) {
   while (my $h = $oDump->next) {
      analyzeNext($h, $count);
      $count++;
   }
}
else {
   while (1) {
      if (my $h = $oDump->next) {
         analyzeNext($h, $count);
         $count++;
      }
   }
}

$oDump->stop;

sub analyzeNext {
   my ($h, $c) = @_;
   my $f = Net::Frame::Simple->newFromDump($h);
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

END { $oDump && $oDump->isRunning && $oDump->stop }

__END__

=head1 NAME

nf-grep - Net::Frame Grep tool

=head1 SYNOPSIS

   # nf-grep.pl -i eth0 -e 'TEST'
   o Frame number: 95
   TEST

=head1 DESCRIPTION

This tool implements the classical network grep (ngrep) command.

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006-2007, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
