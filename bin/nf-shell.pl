#!/usr/bin/perl
#
# $Id: nf-shell.pl,v 1.1 2006/12/03 16:39:29 gomor Exp $
#
package Net::Frame::Shell;
use strict;
use warnings;

our $VERSION = '1.00';

my @subList = qw(
   F sr sd sd2 sd3 sniff dsniff read
);

my @layerList = qw(
   ETH RAW SLL NULL ARP IPv4 IPv6 TCP UDP VLAN ICMPv4 PPPoE PPP PPPLCP LLC CDP
   STP OSPF IGMPv4
);

use Net::Frame::Device;
use Net::Frame::Simple;
use Net::Frame::Dump qw(:consts);
use Net::Write::Layer2;
use Net::Write::Layer3;
use Data::Dumper;
use Term::ReadLine;

my $Device = Net::Frame::Device->new;
my $Dump;

{
   no strict 'refs';
   for my $l (@layerList) {
      *$l = sub {
         (my $module = "Net::Frame::$l") =~ s/::/\//g;
         require $module.'.pm';
         my $r = "Net::Frame::$l"->new(@_);
         $r->pack;
         $r;
      };
   }
}

sub F {
   my @layers = @_;
   Net::Frame::Simple->new(
      firstLayer => $layers[0]->layer,
      layers     => \@layers,
   );
}

sub sr {
   do { print "Nothing to send\n"; return } unless $_[0];

   my $d = Net::Write::Layer2->new(dev => $Device->dev);
   $d->open;
   $d->send(shift());
   $d->close;
}

sub sd {
   do { print "Nothing to send\n"; return } unless $_[0];

   return sd2(@_) if $_[0]->getLayer('ETH') || $_[0]->getLayer('RAW'); # XXX
   return sd3(@_) if $_[0]->l3;
}

sub sd2 {
   my ($f) = @_;

   do { print "Nothing to send\n"; return } unless $f;

   my $d = Net::Write::Layer2->new(dev => $Device->dev);
   $d->open;
   $d->send($f->raw);
   $d->close;
}

sub sd3 {
   my ($f) = @_;

   do { print "Nothing to send\n"; return } unless $f;

   do { print "We can only send IPv4 frames at layer 3\n"; return }
      if (! $f->getLayer('IPv4') || $f->getLayer('ETH')); # XXX, RAW, ...

   my $ip  = $f->getLayer('IPv4');
   my $dst = $ip->dst;

   my $d = Net::Write::Layer3->new(dev => $Device->dev, dst => $dst);
   $d->open;
   $d->send($f->raw);
   $d->close;
}

sub sniff {
   my ($filter) = @_;
   $Dump = Net::Frame::Dump->new(dev => $Device->dev);
   $Dump->filter($filter) if $filter;
   $Dump->start;
   while (1) {
      if (my $h = $Dump->next) {
         my $f = Net::Frame::Simple->new(
            firstLayer => $h->{firstLayer},
            raw        => $h->{raw},
            timestamp  => $h->{timestamp},
         );
         print $f->print."\n";
      }
   }
}

sub dsniff {
   my ($filter) = @_;
   $Dump = Net::Frame::Dump->new(dev => $Device->dev);
   $Dump->filter($filter) if $filter;
   $Dump->start;
   while (1) {
      if (my $h = $Dump->next) {
         my $f = Net::Frame::Simple->new(
            firstLayer => $h->{firstLayer},
            raw        => $h->{raw},
            timestamp  => $h->{timestamp},
         );
         my $ip = $f->getLayer('IPv4');
         next unless $ip;
         my $l;
         if (($l = $f->getLayer('UDP')) || ($l = $f->getLayer('TCP'))) {
            my $data = $l->payload;
            next unless $data =~ /^user\s+|^pass\s+/i;
            print $ip->src.':'.$ip->dst.'> '.$data."\n";
         }
      }
   }
}

sub read {
   my ($file) = @_;
   do { print "Please specify a pcap file to read\n"; return } unless $file;

   $Dump = Net::Packet::Dump->new(
      file => $file,
      mode => NP_DUMP_MODE_OFFLINE,
   );
   $Dump->start;

   my $n = 0;
   while (my $h = $Dump->next) {
      ++$n;
      my $f = Net::Frame::Simple->new(
         firstLayer => $h->{firstLayer},
         raw        => $h->{raw},
         timestamp  => $h->{timestamp},
      );
      my $len = length($h->{raw});
      print 'Frame number: '.$n." (length: $len)\n";
      print $f->print."\n";
   }

   $Dump->stop;
   $Dump->clean;
}

sub nfShell {
   my $prompt = 'nf-shell> ';
   my $name   = 'NF-Shell';
   my $term   = Term::ReadLine->new($name);
   $term->ornaments(0);

   $term->Attribs->{completion_function} = sub {
      ( @subList, @layerList )
   };

   {
      no strict;

      while (my $line = $term->readline($prompt)) {
         $line =~ s/s*read/Net::Frame::Shell::read/;
         eval($line);
         warn($@) if $@;
         print "\n";
      }
   }

   print "\n";
}

END {
   if ($Dump && $Dump->isRunning) {
      $Dump->stop;
      $Dump->clean;
   }
}

1;

package main;

Net::Frame::Shell::nfShell();

1;

__END__

=head1 NAME

nf-shell - Net::Frame Shell tool

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
